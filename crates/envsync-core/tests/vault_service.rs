//! M2 任务 8 步骤 1：Vault application service 的验收测试。
//!
//! 关注五件事：
//!
//! 1. **create / set / get / list / delete 的完整往返**，包括重开进程之后仍然成立。
//! 2. **`list` 只返回元数据**：类型上就拿不到值。
//! 3. **后端上没有明文**：逐字节遍历后端目录里的**每一个文件**找 canary。这不是
//!    「解码之后没找到」，是「磁盘上根本没有这串字节」。
//! 4. **跨纪元读写**：撤销设备把纪元推到 n+1 之后，旧对象仍然读得出来，并且会被
//!    lazy rewrap 到新纪元。
//! 5. **输入来源受限**：[`SecretInput`] 只能从 stdin / 环境变量名 / 隐藏输入构造。

mod vault_support;

use envsync_core::vault::{HiddenPrompt, SecretInput};
use envsync_core::CoreResult;
use envsync_domain::cbor::CborCodec;
use envsync_domain::id::ResourceId;
use envsync_domain::membership::MemberRole;
use envsync_domain::object::ObjectKind;
use vault_support::{assert_no_plaintext, contains, err, sid, Fixture};
use zeroize::Zeroizing;

/// 一串绝不该出现在任何输出或任何后端文件里的字节。
///
/// 刻意不含换行、不含空格，且长得不像任何编码产物：一旦它出现在某个文件里，那就是
/// 明文泄露，没有第二种解释。
const CANARY: &[u8] = b"CANARY-e8f4c1a90b7d2356-PLAINTEXT";

/// 构造一次秘密输入。走的是真实的 stdin 路径（`from_reader`），不是什么测试专用后门。
fn input(value: &[u8]) -> SecretInput {
    SecretInput::from_reader(&mut &value[..]).expect("构造秘密输入")
}

#[test]
fn create_set_get_list_delete_round_trip() {
    let fixture = Fixture::new();
    let laptop = fixture.device("laptop");
    laptop.init_device().expect("建立设备身份");

    let mut vault = laptop.open().expect("打开服务");
    assert!(!vault.is_initialized());
    vault.create().expect("创建工作区");
    assert!(vault.is_initialized());
    assert_eq!(vault.membership().expect("成员状态").len(), 1);

    let token = sid("ci/npm-token");
    vault.set(&token, input(CANARY)).expect("写入秘密");
    assert_eq!(vault.get(&token).expect("读取").expose(), CANARY);

    let listed = vault.list().expect("列出");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, token);
    assert_eq!(listed[0].epoch, 1);

    // 覆盖写：值变了，条数不变。
    vault.set(&token, input(b"second-value")).expect("覆盖写");
    assert_eq!(vault.get(&token).expect("读取").expose(), b"second-value");
    assert_eq!(vault.list().expect("列出").len(), 1);

    assert!(vault.delete(&token).expect("删除"));
    assert!(!vault.delete(&token).expect("重复删除"), "删除应当是幂等的");
    assert!(vault.list().expect("列出").is_empty());
    let error = err(vault.get(&token));
    assert_eq!(error.code(), "vault.secret_not_found");
}

#[test]
fn state_survives_reopening_the_service() {
    let fixture = Fixture::new();
    let laptop = fixture.device("laptop");
    laptop.init_device().expect("建立设备身份");

    {
        let mut vault = laptop.open().expect("打开服务");
        vault.create().expect("创建工作区");
        vault
            .set(&sid("ci/npm-token"), input(CANARY))
            .expect("写入秘密");
    }
    // 新进程：所有状态都从后端 + 安全存储重建。
    let vault = laptop.open().expect("重新打开");
    assert!(vault.is_initialized());
    assert_eq!(
        vault.get(&sid("ci/npm-token")).expect("读取").expose(),
        CANARY
    );
    assert_eq!(vault.list().expect("列出").len(), 1);
}

#[test]
fn list_returns_metadata_only() {
    let fixture = Fixture::new();
    let laptop = fixture.device("laptop");
    laptop.init_device().expect("建立设备身份");
    let mut vault = laptop.open().expect("打开服务");
    vault.create().expect("创建工作区");

    let token = sid("ci/npm-token");
    vault
        .set_with_references(
            &token,
            input(CANARY),
            vec![
                ResourceId::parse("shell/zsh/main").expect("资源"),
                ResourceId::parse("git/config").expect("资源"),
            ],
        )
        .expect("写入秘密");

    let listed = vault.list().expect("列出");
    let entry = &listed[0];
    assert_eq!(entry.id, token);
    assert_eq!(entry.epoch, 1);
    assert!(entry.updated_at_unix_ms > 0);
    assert_eq!(
        entry
            .referenced_by
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["git/config", "shell/zsh/main"]
    );

    // `SecretMetadata` 的 `Debug` 是元数据的完整可见表面；值不在其中。
    let rendered = format!("{listed:?}");
    assert!(
        !rendered.contains("CANARY"),
        "list 的输出里不得出现秘密值：{rendered}"
    );

    // 覆盖写不该丢掉引用关系——引用由配置决定，`vault set` 只换值。
    vault.set(&token, input(b"rotated")).expect("覆盖写");
    assert_eq!(vault.list().expect("列出")[0].referenced_by.len(), 2);
}

#[test]
fn a_full_byte_scan_of_the_backend_never_finds_the_plaintext() {
    let fixture = Fixture::new();
    let laptop = fixture.device("laptop");
    laptop.init_device().expect("建立设备身份");
    let mut vault = laptop.open().expect("打开服务");
    vault.create().expect("创建工作区");

    for (id, value) in [
        ("ci/npm-token", CANARY.to_vec()),
        ("ci/other", b"CANARY-e8f4c1a90b7d2356-PLAINTEXT-2".to_vec()),
        // 空白与二进制内容也不能以任何形式落盘。
        ("app/binary", vec![0u8, 1, 2, 3, 0xff, 0xfe]),
    ] {
        vault.set(&sid(id), input(&value)).expect("写入秘密");
    }
    // 读一遍：确认「能读出来」与「盘上没有明文」同时成立。
    assert_eq!(
        vault.get(&sid("ci/npm-token")).expect("读取").expose(),
        CANARY
    );

    // 后端目录里的每一个文件、每一个字节。
    assert_no_plaintext(&fixture.backend_dir(), CANARY);
    assert_no_plaintext(
        &fixture.backend_dir(),
        b"CANARY-e8f4c1a90b7d2356-PLAINTEXT-2",
    );

    // 本地草稿库（对象缓存）同样不该有明文——它缓存的是密封后的字节。
    assert_no_plaintext(&laptop.state_dir, CANARY);

    // 反过来确认这条断言不是空转：逻辑标识**应当**能在后端里找到（索引里有它）。
    let found = vault_support::all_files(&fixture.backend_dir())
        .iter()
        .any(|(_, bytes)| contains(bytes, b"ci/npm-token"));
    assert!(found, "逻辑标识本来就是公开元数据，应当出现在索引对象里");
}

#[test]
fn the_snapshot_only_ever_references_sealed_objects() {
    let fixture = Fixture::new();
    let laptop = fixture.device("laptop");
    laptop.init_device().expect("建立设备身份");
    let mut vault = laptop.open().expect("打开服务");
    vault.create().expect("创建工作区");
    vault
        .set(&sid("ci/npm-token"), input(CANARY))
        .expect("写入秘密");

    // 索引里每条秘密引用指向的都必须是 `SealedSecret` 种类的对象。
    for entry in &vault.index().secrets {
        assert_eq!(entry.object.kind, ObjectKind::SealedSecret);
    }
    // 而索引本身是一个普通 Blob：任何只会扫 Blob 的工具看到的就只有这些标识。
    let index_bytes = vault.index().to_canonical_vec();
    assert!(!contains(&index_bytes, CANARY));
}

#[test]
fn secrets_written_before_a_rotation_stay_readable_and_get_rewrapped() {
    let fixture = Fixture::new();
    let laptop = fixture.device("laptop");
    let desktop = fixture.device("desktop");
    laptop.init_device().expect("建立设备身份");
    let desktop_key = desktop.init_device().expect("建立设备身份");

    let mut vault = laptop.open().expect("打开服务");
    vault.create().expect("创建工作区");
    let token = sid("ci/npm-token");
    vault.set(&token, input(CANARY)).expect("写入秘密");
    assert_eq!(vault.list().expect("列出")[0].epoch, 1);

    // 加一台设备再撤销它，纪元 1 -> 2。
    envsync_core::device_admin::invite(
        &mut vault,
        desktop_key.public(),
        MemberRole::Member,
        envsync_core::device_admin::INVITATION_DEFAULT_TTL_MS,
    )
    .expect("邀请设备");
    let outcome = vault
        .revoke_device(desktop_key.device_id())
        .expect("撤销设备");
    assert_eq!(outcome.from_epoch, 1);
    assert_eq!(outcome.to_epoch, 2);
    assert_eq!(vault.membership().expect("成员状态").epoch, 2);

    // 旧纪元的对象仍然读得出来（密钥环保留了旧密钥），并且已经被重加密到新纪元。
    assert_eq!(vault.get(&token).expect("读取").expose(), CANARY);
    assert_eq!(
        vault.list().expect("列出")[0].epoch,
        2,
        "轮换完成后旧对象应当已经重加密到新纪元"
    );

    // 新写入用的是新纪元。
    vault.set(&sid("ci/new"), input(b"after")).expect("写入");
    assert_eq!(
        vault
            .list()
            .expect("列出")
            .iter()
            .find(|item| item.id.as_str() == "ci/new")
            .expect("存在")
            .epoch,
        2
    );
    assert_no_plaintext(&fixture.backend_dir(), CANARY);
}

#[test]
fn reading_an_old_epoch_object_rewraps_it_lazily() {
    let fixture = Fixture::new();
    let laptop = fixture.device("laptop");
    let desktop = fixture.device("desktop");
    laptop.init_device().expect("建立设备身份");
    let desktop_key = desktop.init_device().expect("建立设备身份");

    let mut vault = laptop.open().expect("打开服务");
    vault.create().expect("创建工作区");
    let token = sid("ci/npm-token");
    vault.set(&token, input(CANARY)).expect("写入秘密");

    envsync_core::device_admin::invite(
        &mut vault,
        desktop_key.public(),
        MemberRole::Member,
        envsync_core::device_admin::INVITATION_DEFAULT_TTL_MS,
    )
    .expect("邀请设备");
    // 中断在 rewrap 之前：新头已发布，旧对象还停在纪元 1。
    vault
        .revoke_device_until(
            desktop_key.device_id(),
            Some(envsync_storage::RotationStage::Rewrapping),
        )
        .expect("撤销设备（中断）");

    let mut vault = laptop.open().expect("重新打开");
    assert_eq!(vault.list().expect("列出")[0].epoch, 1, "还没有重加密");

    // 一次读取就触发 lazy rewrap；索引更新推迟到 flush。
    assert_eq!(vault.get(&token).expect("读取").expose(), CANARY);
    assert_eq!(vault.flush_rewraps().expect("落盘"), 1);
    assert_eq!(vault.list().expect("列出")[0].epoch, 2);
    // 幂等：没有待更新项时不做任何后端写入。
    assert_eq!(vault.flush_rewraps().expect("再次落盘"), 0);
}

#[test]
fn secret_input_can_only_come_from_stdin_env_or_a_hidden_prompt() {
    // 环境变量：参数是**名**，不是值。
    // SAFETY 注：单元测试进程内设置环境变量；本测试不与其他读取该变量的测试并发。
    std::env::set_var("ENVSYNC_TEST_CANARY_VALUE", "CANARY-from-env");
    let from_env = SecretInput::from_env_var("ENVSYNC_TEST_CANARY_VALUE").expect("读取环境变量");
    assert_eq!(from_env.len(), "CANARY-from-env".len());
    std::env::remove_var("ENVSYNC_TEST_CANARY_VALUE");

    let missing = err(SecretInput::from_env_var("ENVSYNC_TEST_CANARY_VALUE"));
    assert_eq!(missing.code(), "vault.env_var_missing");

    // 隐藏输入：由界面层注入实现，核心层只认这个 trait。
    struct FakePrompt(&'static [u8]);
    impl HiddenPrompt for FakePrompt {
        fn read_hidden(&mut self, _label: &str) -> CoreResult<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(self.0.to_vec()))
        }
    }
    let mut prompt = FakePrompt(CANARY);
    let hidden = SecretInput::from_hidden_prompt(&mut prompt, "口令").expect("隐藏输入");
    assert_eq!(hidden.len(), CANARY.len());

    // stdin：空输入被拒绝，而不是写进一条空秘密。
    assert_eq!(
        err(SecretInput::from_reader(&mut &b""[..])).code(),
        "vault.empty_value"
    );
}

#[test]
fn writing_requires_membership_and_an_initialized_workspace() {
    let fixture = Fixture::new();
    let laptop = fixture.device("laptop");
    laptop.init_device().expect("建立设备身份");
    let mut vault = laptop.open().expect("打开服务");

    // 还没 create：读写都必须失败，而不是凭空建一个工作区。
    assert_eq!(
        err(vault.set(&sid("ci/x"), input(b"v"))).code(),
        "vault.not_initialized"
    );
    assert_eq!(vault.list().expect("列出").len(), 0);

    vault.create().expect("创建工作区");
    assert_eq!(
        vault.create().unwrap_err().code(),
        "vault.already_initialized"
    );
}

#[test]
fn opening_without_a_device_identity_fails_safely() {
    let fixture = Fixture::new();
    let laptop = fixture.device("laptop");
    // 刻意不调用 init_device。
    let error = err(laptop.open());
    assert_eq!(error.code(), "vault.device_identity_missing");
}

#[test]
fn every_publish_advances_the_anti_rollback_checkpoint() {
    let fixture = Fixture::new();
    let laptop = fixture.device("laptop");
    laptop.init_device().expect("建立设备身份");
    let mut vault = laptop.open().expect("打开服务");

    vault.create().expect("创建工作区");
    let after_create = vault.checkpoint().expect("检查点").expect("已建立");
    assert_eq!(after_create.revision, 1);
    assert_eq!(after_create.key_epoch, 1);
    assert_eq!(after_create.membership_sequence, 0);

    vault.set(&sid("ci/x"), input(b"v")).expect("写入");
    let after_set = vault.checkpoint().expect("检查点").expect("已建立");
    assert!(after_set.revision > after_create.revision);
    assert_eq!(after_set.membership_digest, after_create.membership_digest);
}
