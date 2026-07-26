//! 安全存储的**契约测试**。
//!
//! 这里的核心是 [`contract_suite`]：一套与后端无关的断言。它对内存 fake 跑一遍，
//! 如果当前机器上真的有可用的系统凭据库，就**再对系统凭据库跑一遍**。
//! 两个后端共用同一套断言，是「fake 的行为等于真实后端的行为」这句话唯一可信的形式。
//!
//! 系统凭据库那一遍使用带随机后缀的工作区标识，跑完删除自己写下的每一条，
//! 避免污染开发者的钥匙串。
//!
//! 容器 / CI 里通常没有 Secret Service。那不是失败——但**必须**表现为
//! `PlatformError::SecureStoreUnavailable`，既不能 panic，也不能悄悄退化成
//! 明文文件或进程内内存。`system_store_is_either_usable_or_explicitly_unavailable`
//! 就是钉住这一点的。

use envsync_platform::secure_store::{
    open_system_store, SecureKey, SecurePurpose, SecureStore, SERVICE_NAME,
};
use envsync_platform::{InMemorySecureStore, PlatformError};

/// 契约测试用的工作区标识。
///
/// 每次调用都生成新的随机 UUID：跑在真实钥匙串上时，这保证本次运行绝不会读到或
/// 覆盖上一次运行（或开发者本人）的条目。
fn fresh_workspace() -> envsync_domain::WorkspaceId {
    envsync_domain::WorkspaceId::generate()
}

/// 构造一个确定性的设备标识。
fn device(tag: &[u8]) -> envsync_domain::DeviceId {
    envsync_domain::DeviceId::derive(tag)
}

// ---------------------------------------------------------------------------
// 契约本体
// ---------------------------------------------------------------------------

/// 对任意 [`SecureStore`] 实现执行全套契约断言。
///
/// 所有写入都落在 `workspace` 这个一次性工作区下，函数返回前会清理干净。
fn contract_suite(store: &dyn SecureStore, workspace: envsync_domain::WorkspaceId) {
    let label = store.describe();

    // 记录所有写过的坐标，最后统一清理。即使断言失败提前 panic，
    // 也只会残留在一次性工作区里，不会影响下次运行。
    let mut written: Vec<SecureKey> = Vec::new();
    let mut track = |key: SecureKey| {
        written.push(key.clone());
        key
    };

    // --- put/get 往返 ---
    let data_key = track(SecureKey::workspace_scoped(
        workspace,
        SecurePurpose::WorkspaceDataKey,
    ));
    store
        .put(&data_key, b"round-trip-value")
        .unwrap_or_else(|e| panic!("[{label}] put 失败：{e}"));
    let read = store
        .get(&data_key)
        .unwrap_or_else(|e| panic!("[{label}] get 失败：{e}"))
        .unwrap_or_else(|| panic!("[{label}] 刚写入的条目读不到"));
    assert_eq!(read.expose(), b"round-trip-value", "[{label}] 往返值不一致");
    assert_eq!(read.len(), b"round-trip-value".len());
    assert!(!read.is_empty());

    // --- 覆盖写：第二次 put 生效 ---
    store
        .put(&data_key, b"second-value")
        .unwrap_or_else(|e| panic!("[{label}] 覆盖写失败：{e}"));
    assert_eq!(
        store.get(&data_key).unwrap().unwrap().expose(),
        b"second-value",
        "[{label}] 覆盖写没有生效"
    );

    // --- not-found 返回 Ok(None)，而不是错误 ---
    // 这条极其重要：如果「读不到」被当成错误、或者「出错」被当成「不存在」，
    // 上层就会误判成「还没初始化」并生成一把新密钥覆盖旧的。
    let missing = SecureKey::workspace_scoped(workspace, SecurePurpose::RecoveryIdentity);
    match store.get(&missing) {
        Ok(None) => {}
        Ok(Some(_)) => panic!("[{label}] 未写入的坐标却读到了值"),
        Err(error) => panic!("[{label}] 未写入的坐标返回了错误而非 Ok(None)：{error}"),
    }

    // --- delete 的返回值语义 ---
    assert!(
        !store.delete(&missing).unwrap(),
        "[{label}] 删除不存在的条目应返回 false"
    );
    assert!(
        store.delete(&data_key).unwrap(),
        "[{label}] 删除已存在的条目应返回 true"
    );
    assert!(
        store.get(&data_key).unwrap().is_none(),
        "[{label}] 删除后仍能读到值"
    );
    assert!(
        !store.delete(&data_key).unwrap(),
        "[{label}] 重复删除应返回 false"
    );

    // --- 不同 workspace / device / purpose 互不干扰 ---
    let other_workspace = fresh_workspace();
    let dev_a = device(b"device-a");
    let dev_b = device(b"device-b");

    let cases: Vec<(SecureKey, &[u8])> = vec![
        (
            SecureKey::device_scoped(workspace, dev_a, SecurePurpose::DeviceSigningKey),
            b"ws1-devA-sign",
        ),
        (
            SecureKey::device_scoped(workspace, dev_b, SecurePurpose::DeviceSigningKey),
            b"ws1-devB-sign",
        ),
        (
            SecureKey::device_scoped(workspace, dev_a, SecurePurpose::DeviceKemKey),
            b"ws1-devA-kem",
        ),
        (
            SecureKey::device_scoped(other_workspace, dev_a, SecurePurpose::DeviceSigningKey),
            b"ws2-devA-sign",
        ),
        (
            SecureKey::workspace_scoped(workspace, SecurePurpose::Checkpoint),
            b"ws1-checkpoint",
        ),
    ];
    for (key, value) in &cases {
        store.put(&track(key.clone()), value).unwrap();
    }
    for (key, value) in &cases {
        assert_eq!(
            store.get(key).unwrap().unwrap().expose(),
            *value,
            "[{label}] 坐标 {} 串味了",
            key.purpose
        );
    }
    // 删掉其中一条，其余必须不受影响。
    assert!(store.delete(&cases[0].0).unwrap());
    assert!(store.get(&cases[0].0).unwrap().is_none());
    for (key, value) in &cases[1..] {
        assert_eq!(
            store.get(key).unwrap().unwrap().expose(),
            *value,
            "[{label}] 删除一条后影响到了别的坐标"
        );
    }

    // --- 二进制值：含 NUL、非 UTF-8、高位字节 ---
    let binary: Vec<u8> = vec![
        0x00, 0xff, 0xfe, 0x00, 0x80, 0xc0, 0x41, 0x00, 0xed, 0xa0, 0xa0, 0x7f, 0x00,
    ];
    assert!(
        String::from_utf8(binary.clone()).is_err(),
        "测试数据本身必须是非法 UTF-8，否则这条断言没意义"
    );
    let binary_key = track(SecureKey::device_scoped(
        workspace,
        dev_b,
        SecurePurpose::DeviceKemKey,
    ));
    store.put(&binary_key, &binary).unwrap();
    assert_eq!(
        store.get(&binary_key).unwrap().unwrap().expose(),
        binary.as_slice(),
        "[{label}] 二进制值没有原样往返"
    );

    // --- 空值：明确**拒绝** ---
    // 理由见 `SecureStore::put` 的文档：零长度凭据在各平台上的行为不一致，
    // 接受它会让「写过空值」与「从未写入」无法区分。
    let empty_key = SecureKey::workspace_scoped(other_workspace, SecurePurpose::Checkpoint);
    let error = store
        .put(&empty_key, b"")
        .expect_err(&format!("[{label}] 空值必须被拒绝"));
    assert_eq!(error.code(), "platform.secure_store_invalid_value");
    assert!(
        store.get(&empty_key).unwrap().is_none(),
        "[{label}] 被拒绝的空值不应该留下任何条目"
    );

    // --- 清理 ---
    for key in &written {
        let _ = store.delete(key);
    }
    for key in &written {
        assert!(
            store.get(key).unwrap().is_none(),
            "[{label}] 清理后仍有残留条目"
        );
    }
}

// ---------------------------------------------------------------------------
// 后端 1：内存 fake（始终运行）
// ---------------------------------------------------------------------------

#[test]
fn in_memory_fake_satisfies_contract() {
    let store = InMemorySecureStore::new();
    contract_suite(&store, fresh_workspace());
    assert!(store.is_empty(), "契约跑完后 fake 里不应有残留");
}

#[test]
fn in_memory_fake_declares_itself_non_system() {
    let store = InMemorySecureStore::new();
    let descriptor = store.describe();
    assert!(
        !descriptor.is_system_store,
        "内存 fake 绝不能自称系统存储，否则上层无法拦截它进入生产路径"
    );
    assert_eq!(descriptor.backend, "in-memory-fake");
}

// ---------------------------------------------------------------------------
// 后端 2：系统凭据库（可用时才运行）
// ---------------------------------------------------------------------------

#[test]
fn system_store_is_either_usable_or_explicitly_unavailable() {
    match open_system_store() {
        Ok(store) => {
            let descriptor = store.describe();
            assert!(
                descriptor.is_system_store,
                "open_system_store 只能返回系统托管的实现，实际返回 {descriptor}"
            );
            assert_ne!(
                descriptor.backend, "in-memory-fake",
                "open_system_store 绝不能返回内存 fake"
            );
            // 真实凭据库可用：对它跑同一套契约。
            contract_suite(store.as_ref(), fresh_workspace());
        }
        Err(error) => {
            // 容器 / CI 里的预期路径：必须是明确的「不可用」，
            // 不能是别的错误，更不能是 panic 或静默降级。
            assert_eq!(
                error.code(),
                "platform.secure_store_unavailable",
                "没有系统凭据库时必须报 SecureStoreUnavailable，实际是：{error}"
            );
            assert!(
                matches!(error, PlatformError::SecureStoreUnavailable { .. }),
                "错误码与变体必须一致"
            );
        }
    }
}

#[test]
fn open_system_store_returns_quickly_without_a_credential_store() {
    // Linux 上没有 DBus 会话时，DBus 的按需激活默认要等 25 秒。
    // 平台层必须在此之前给出结论，否则 CLI 启动路径会假死。
    let started = std::time::Instant::now();
    let _ = open_system_store();
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "open_system_store 耗时 {elapsed:?}，超过了可接受的上限"
    );
}

// ---------------------------------------------------------------------------
// 命名契约
// ---------------------------------------------------------------------------

#[test]
fn account_name_format_is_frozen() {
    // 这些是 golden 字符串。account 名称是持久化契约：改了它，
    // 已有设备就再也找不到自己写下的密钥，表现为「密钥凭空消失」。
    // 如果这个测试失败了，正确的做法是改回代码，而不是改这里的期望值。
    let workspace = envsync_domain::WorkspaceId::from_uuid(
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8".parse().unwrap(),
    );
    let dev =
        envsync_domain::DeviceId::from_digest(envsync_domain::Digest32::from_bytes([0xab; 32]));

    assert_eq!(SERVICE_NAME, "envsync");

    let scoped = SecureKey::workspace_scoped(workspace, SecurePurpose::WorkspaceDataKey);
    assert_eq!(
        scoped.account_name(),
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8/-/workspace-data-key"
    );
    assert_eq!(scoped.service_name(), "envsync");

    let bound = SecureKey::device_scoped(workspace, dev, SecurePurpose::DeviceSigningKey);
    assert_eq!(
        bound.account_name(),
        concat!(
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8/",
            "abababababababababababababababababababababababababababababababab/",
            "device-signing-key"
        )
    );

    // 用途标记逐条钉住。
    let tokens: Vec<&str> = SecurePurpose::ALL.iter().map(|p| p.as_str()).collect();
    assert_eq!(
        tokens,
        vec![
            "device-signing-key",
            "device-kem-key",
            "workspace-data-key",
            "checkpoint",
            "recovery-identity",
        ]
    );
}

#[test]
fn account_name_never_contains_the_value() {
    let store = InMemorySecureStore::new();
    let workspace = fresh_workspace();
    let key = SecureKey::device_scoped(
        workspace,
        device(b"naming"),
        SecurePurpose::DeviceSigningKey,
    );
    store.put(&key, b"SUPER-SECRET-PAYLOAD").unwrap();

    for name in store.account_names() {
        assert!(
            !name.contains("SUPER-SECRET-PAYLOAD"),
            "account 名称里出现了 value：{name}"
        );
        // 名称里应当只有公开标识。
        assert!(name.starts_with(&format!("{workspace}/")));
        assert!(name.ends_with("/device-signing-key"));
    }
    let _ = store.delete(&key);
}

// ---------------------------------------------------------------------------
// Canary：秘密绝不能出现在任何诊断输出里
// ---------------------------------------------------------------------------

/// 一个绝不会被别的东西偶然产生的哨兵串。
const CANARY: &str = "CANARY-c4f1e2d3-do-not-log-this-secret";

#[test]
fn canary_never_leaks_through_descriptors_or_errors() {
    let mut renderings: Vec<String> = Vec::new();

    // 1) 用 canary 作为 value 跑一遍常规操作，收集沿途的一切诊断输出。
    let store = InMemorySecureStore::new();
    let workspace = fresh_workspace();
    let key = SecureKey::workspace_scoped(workspace, SecurePurpose::WorkspaceDataKey);

    renderings.push(store.describe().to_string());
    renderings.push(format!("{:?}", store.describe()));

    if let Err(error) = store.put(&key, CANARY.as_bytes()) {
        renderings.extend(render_error(&error));
    }
    if let Err(error) = store.get(&key) {
        renderings.extend(render_error(&error));
    }
    if let Err(error) = store.delete(&key) {
        renderings.extend(render_error(&error));
    }
    // 空值拒绝路径也要检查：它是唯一一条 fake 上必然产生错误的路径。
    if let Err(error) = store.put(&key, b"") {
        renderings.extend(render_error(&error));
    }
    renderings.extend(store.account_names());

    // 2) 系统凭据库：可用就走一遍同样的操作，不可用就检查那条错误本身。
    match open_system_store() {
        Ok(system) => {
            renderings.push(system.describe().to_string());
            renderings.push(format!("{:?}", system.describe()));
            let system_key =
                SecureKey::workspace_scoped(fresh_workspace(), SecurePurpose::Checkpoint);
            if let Err(error) = system.put(&system_key, CANARY.as_bytes()) {
                renderings.extend(render_error(&error));
            }
            if let Err(error) = system.get(&system_key) {
                renderings.extend(render_error(&error));
            }
            if let Err(error) = system.delete(&system_key) {
                renderings.extend(render_error(&error));
            }
        }
        Err(error) => renderings.extend(render_error(&error)),
    }

    // 3) 最关键的一步：直接把「后端错误里就带着 canary」这种最坏情况喂给真实的
    //    错误映射函数。上面两步只能证明「这次没泄露」，这一步才能证明
    //    「即使后端把秘密拼进错误消息，映射结果也不会带出来」。
    //    它覆盖 keyring 的每个错误变体，包括直接携带原始字节的 BadEncoding。
    let mapped = envsync_platform::secure_store::map_leaky_backend_errors_for_test(
        SecurePurpose::DeviceSigningKey,
        CANARY,
    );
    for error in &mapped {
        renderings.extend(render_error(error));
    }

    for text in &renderings {
        assert!(!text.contains(CANARY), "canary 泄漏到了诊断输出里：{text}");
    }
}

#[test]
fn mapped_backend_errors_carry_purpose_but_not_the_account_name() {
    let mapped = envsync_platform::secure_store::map_leaky_backend_errors_for_test(
        SecurePurpose::DeviceSigningKey,
        CANARY,
    );
    if mapped.is_empty() {
        // 本平台没有 keyring 后端，这条断言无从谈起。
        return;
    }

    let workspace = fresh_workspace();
    let dev = device(b"leak-check");
    let account =
        SecureKey::device_scoped(workspace, dev, SecurePurpose::DeviceSigningKey).account_name();

    for error in &mapped {
        for text in render_error(error) {
            assert!(
                text.contains("device-signing-key"),
                "错误里应当保留用途，便于诊断：{text}"
            );
            assert!(
                !text.contains(&account),
                "错误里出现了完整 account 名：{text}"
            );
            assert!(
                !text.contains(&workspace.to_string()),
                "错误里出现了工作区标识：{text}"
            );
            assert!(
                !text.contains(&dev.to_hex()),
                "错误里出现了设备标识：{text}"
            );
        }
        assert!(
            error.code().starts_with("platform.secure_store_"),
            "安全存储错误必须有稳定的 secure_store 前缀错误码"
        );
    }
}

#[test]
fn secure_store_error_codes_are_stable() {
    // 错误码是 CLI JSON 契约的一部分，只能新增不能改名。
    let mapped = envsync_platform::secure_store::map_leaky_backend_errors_for_test(
        SecurePurpose::Checkpoint,
        "irrelevant",
    );
    let mut codes: Vec<&str> = mapped.iter().map(|e| e.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    for code in codes {
        assert!(
            [
                "platform.secure_store_denied",
                "platform.secure_store_locked",
                "platform.secure_store_backend",
            ]
            .contains(&code),
            "出现了预期之外的错误码：{code}"
        );
    }

    // 空值拒绝与不可用这两条路径的错误码单独钉住。
    let store = InMemorySecureStore::new();
    let key = SecureKey::workspace_scoped(fresh_workspace(), SecurePurpose::Checkpoint);
    assert_eq!(
        store.put(&key, b"").unwrap_err().code(),
        "platform.secure_store_invalid_value"
    );
    if let Err(error) = open_system_store() {
        assert_eq!(error.code(), "platform.secure_store_unavailable");
    }
}

/// 把一个错误渲染成「所有可能被日志或 JSON 打印出来的形式」。
///
/// 包含 `Display`、`Debug` 与整条 `source()` 链——canary 检查必须覆盖全部三者，
/// 因为实践中三种都会被写进日志。
fn render_error(error: &PlatformError) -> Vec<String> {
    use std::error::Error as _;

    let mut out = vec![error.to_string(), format!("{error:?}")];
    let mut source = error.source();
    while let Some(inner) = source {
        out.push(inner.to_string());
        out.push(format!("{inner:?}"));
        source = inner.source();
    }
    out
}
