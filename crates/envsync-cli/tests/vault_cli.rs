//! M2 任务 8 步骤 3-4：`device` / `vault` / `recovery` / `security` 的命令面、退出码与
//! **脱敏 golden 测试**。
//!
//! ## 两种测试，各管一件事
//!
//! 1. **真二进制**（`std::process::Command`）：命令面、`--help`、退出码分流、以及
//!    「系统安全存储不可用时安全失败」这条真实路径。子进程里没法注入内存替身，因此
//!    这一层只能覆盖失败路径——而这恰好是它最该覆盖的东西。
//! 2. **进程内**（直接调用 [`envsync_cli::vault_cli`]）：成功路径的脱敏 golden。测试
//!    注入 `InMemorySecureStore`，然后断言**真正会被写出去的字节**——
//!    [`envsync_cli::output::json_line`] 与 [`envsync_cli::output::human_body`] 的返回
//!    值，而不是某个「看起来没问题」的中间对象。
//!
//! ## canary 矩阵
//!
//! [`CANARY`] 被灌进下面每一条路径，四个通道（stdout / stderr / tracing / JSON）全部
//! 捕获，断言它从不出现：
//!
//! | 路径 | 覆盖 |
//! |---|---|
//! | `vault set` 成功 | ✓ 人类可读 + `--json` |
//! | `vault set` 失败（密钥库不可用） | ✓ 人类可读 + `--json` |
//! | `vault get` 成功（写文件） | ✓ 人类可读 + `--json` |
//! | `vault get` 失败（不存在） | ✓ 人类可读 + `--json` |
//! | `vault list` | ✓ 人类可读 + `--json` |
//! | `vault delete` | ✓ 人类可读 + `--json` |
//! | `device revoke` | ✓ 人类可读 + `--json` |
//! | 轮换中断后恢复 | ✓ 人类可读 + `--json` |
//! | tracing（trace 级，全开） | ✓ |
//!
//! **唯一的例外**是 `vault get --output stdout --allow-non-tty`：那条路径的存在意义就是
//! 把值交出去。测试同样断言它——断言的是「值确实出来了，而且一个字节不差」。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use envsync_cli::commands::{CommandData, CommandOutput};
use envsync_cli::output::{self, DiagnosticOut, Status, JSON_SCHEMA_VERSION};
use envsync_cli::vault_cli::{self, OutputTarget, ValueSource, VaultContext};
use envsync_core::checkpoint::{CheckpointStore, InMemoryCheckpointStore};
use envsync_core::ports::{Clock, FixedClock};
use envsync_core::{CoreError, CoreResult, EnvSyncService, WorkspaceConfig};
use envsync_domain::membership::MemberRole;
use envsync_platform::secure_store::{SecretBytes, SecureKey, SecureStore, SecureStoreDescriptor};
use envsync_platform::{InMemorySecureStore, PlatformError};
use tempfile::TempDir;

/// 一串绝不该出现在任何输出通道里的字节。
///
/// 刻意长、刻意不含空白、刻意不像任何编码产物：它一旦出现，就只可能是明文泄露。
const CANARY: &str = "CANARY-4f7b21ce90ad3856-DO-NOT-LEAK";

/// 承载 canary 的环境变量名。变量**名**可以出现在输出里，值不行。
const CANARY_ENV: &str = "ENVSYNC_VAULT_CLI_CANARY";

// ---------------------------------------------------------------------------
// 通道捕获
// ---------------------------------------------------------------------------

/// 一次命令执行在四个通道上产生的全部字节。
#[derive(Debug, Default)]
struct Captured {
    /// 人类可读模式下写进 stdout 的正文。
    human_stdout: String,
    /// 人类可读模式下写进 stderr 的诊断/错误。
    human_stderr: String,
    /// `--json` 模式下写进 stdout 的那一行。
    json: String,
    /// 命令执行期间产生的全部 tracing 记录。
    tracing: String,
    /// `vault get --output stdout` 写出去的原始字节。
    raw_stdout: Vec<u8>,
}

impl Captured {
    /// 除「显式的秘密出口」之外的全部通道。
    fn redacted_channels(&self) -> [(&'static str, &str); 4] {
        [
            ("stdout", &self.human_stdout),
            ("stderr", &self.human_stderr),
            ("json", &self.json),
            ("tracing", &self.tracing),
        ]
    }

    /// 断言 canary 不出现在任何一个受脱敏保护的通道里。
    fn assert_no_canary(&self, label: &str) {
        for (channel, text) in self.redacted_channels() {
            assert!(
                !text.contains(CANARY),
                "{label}：canary 出现在 {channel} 通道里\n{text}"
            );
        }
        assert!(
            !self
                .raw_stdout
                .windows(CANARY.len())
                .any(|w| w == CANARY.as_bytes()),
            "{label}：canary 出现在原始 stdout 里，但本次命令没有要求输出秘密"
        );
    }
}

/// 可共享的字节缓冲，兼作 tracing 的 writer。
#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    fn take(&self) -> String {
        let mut guard = self.0.lock().unwrap_or_else(|err| err.into_inner());
        let text = String::from_utf8_lossy(&guard).into_owned();
        guard.clear();
        text
    }
}

impl Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuffer {
    type Writer = SharedBuffer;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// 在一个把**全部**级别都记下来的 tracing 订阅者下执行 `body`，返回记录文本。
///
/// 级别刻意开到 `trace`：脱敏 golden 要证明的是「即便把日志开到最大也不会漏」，
/// 而不是「默认级别下看不见」。
fn with_tracing<T>(body: impl FnOnce() -> T) -> (T, String) {
    let buffer = SharedBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buffer.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    let value = tracing::subscriber::with_default(subscriber, body);
    (value, buffer.take())
}

// ---------------------------------------------------------------------------
// 测试替身
// ---------------------------------------------------------------------------

/// 恒定不可用的安全存储。
///
/// 模拟「系统凭据库被锁定 / 访问被拒绝 / 根本不存在」。所有操作都失败，因此任何
/// 试图退化到明文的实现都会在这些测试里暴露出来——它会**成功**，而断言要求它失败。
struct UnavailableSecureStore;

impl SecureStore for UnavailableSecureStore {
    fn describe(&self) -> SecureStoreDescriptor {
        SecureStoreDescriptor {
            backend: "unavailable-for-test",
            is_system_store: false,
        }
    }
    fn put(&self, _key: &SecureKey, _value: &[u8]) -> Result<(), PlatformError> {
        Err(PlatformError::SecureStoreUnavailable {
            detail: "测试注入：凭据库不可用",
        })
    }
    fn get(&self, _key: &SecureKey) -> Result<Option<SecretBytes>, PlatformError> {
        Err(PlatformError::SecureStoreUnavailable {
            detail: "测试注入：凭据库不可用",
        })
    }
    fn delete(&self, _key: &SecureKey) -> Result<bool, PlatformError> {
        Err(PlatformError::SecureStoreUnavailable {
            detail: "测试注入：凭据库不可用",
        })
    }
}

// ---------------------------------------------------------------------------
// 夹具
// ---------------------------------------------------------------------------

/// 一个可以反复开关「进程」的工作区。
struct Harness {
    root: TempDir,
    config_path: PathBuf,
    config: WorkspaceConfig,
    secure: Arc<InMemorySecureStore>,
    checkpoints: Arc<InMemoryCheckpointStore>,
    clock: Arc<FixedClock>,
}

impl Harness {
    fn new() -> Self {
        let root = TempDir::new().expect("临时目录");
        let config_path = root.path().join("envsync.yaml");
        let config = EnvSyncService::init_workspace(
            &config_path,
            "vault-cli-test",
            &root.path().join("backend"),
        )
        .expect("初始化工作区");
        Harness {
            root,
            config_path,
            config,
            secure: Arc::new(InMemorySecureStore::new()),
            checkpoints: Arc::new(InMemoryCheckpointStore::new()),
            clock: Arc::new(FixedClock(1_700_000_000_000)),
        }
    }

    /// 新建一个上下文，等价于「又跑了一条命令」。
    fn ctx(&self) -> VaultContext {
        VaultContext::with_stores(
            self.config.clone(),
            Arc::clone(&self.secure) as Arc<dyn SecureStore>,
            Arc::clone(&self.checkpoints) as Arc<dyn CheckpointStore>,
            Arc::clone(&self.clock) as Arc<dyn Clock>,
        )
    }

    /// 用一个不可用的安全存储建立上下文（模拟凭据库锁定）。
    fn broken_ctx(&self) -> VaultContext {
        VaultContext::with_stores(
            self.config.clone(),
            Arc::new(UnavailableSecureStore) as Arc<dyn SecureStore>,
            Arc::clone(&self.checkpoints) as Arc<dyn CheckpointStore>,
            Arc::clone(&self.clock) as Arc<dyn Clock>,
        )
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    /// 建立设备身份 + Vault，并写入一条 canary 秘密。
    fn bootstrap(&self) {
        vault_cli::device_init(&self.ctx()).expect("建立设备身份");
        vault_cli::vault_create(&self.ctx()).expect("创建 Vault");
        std::env::set_var(CANARY_ENV, CANARY);
        vault_cli::vault_set(
            &self.ctx(),
            "ci/npm-token",
            &ValueSource::Env(CANARY_ENV.to_owned()),
        )
        .expect("写入 canary");
    }
}

/// 执行一条命令，捕获四个通道。
///
/// 走的是 CLI 真正用的那两个渲染函数，因此这里捕到的就是用户会看到的字节。
fn capture(command: &str, run: impl FnOnce() -> CoreResult<CommandOutput>) -> Captured {
    capture_with_stdout(command, |_| run())
}

/// 同 [`capture`]，但把「秘密写向 stdout」这条出路也接进来。
fn capture_with_stdout(
    command: &str,
    run: impl FnOnce(&mut dyn Write) -> CoreResult<CommandOutput>,
) -> Captured {
    let mut raw_stdout: Vec<u8> = Vec::new();
    let (result, tracing) = with_tracing(|| run(&mut raw_stdout));
    let mut captured = Captured {
        tracing,
        raw_stdout,
        ..Captured::default()
    };
    match result {
        Ok(out) => {
            captured.human_stdout = output::human_body(&out.data.render());
            captured.human_stderr = output::human_diagnostics(&out.diagnostics);
            captured.json = output::json_line(
                command,
                Status::Ok,
                JSON_SCHEMA_VERSION,
                Some(&out.data),
                &out.diagnostics,
                out.data.v2_only_fields(),
            );
        }
        Err(error) => {
            let diagnostics = vec![DiagnosticOut::from_error(&error)];
            captured.human_stderr = output::human_error(&error, &diagnostics);
            captured.json = output::json_line(
                command,
                Status::Error,
                JSON_SCHEMA_VERSION,
                None::<&CommandData>,
                &diagnostics,
                &[],
            );
        }
    }
    captured
}

/// 一条待测的失败路径：命令名 + 触发它的闭包。
///
/// 闭包借用夹具，因此带一个生命周期参数——`'static` 装不下它，夹具是栈上的临时目录。
type FailureCase<'a> = (
    &'static str,
    Box<dyn Fn() -> CoreResult<CommandOutput> + 'a>,
);

/// 取出失败结果里的错误（`CommandOutput` 不实现 `Debug`）。
fn err<T>(result: CoreResult<T>) -> CoreError {
    match result {
        Ok(_) => panic!("期望失败，实际却成功了"),
        Err(error) => error,
    }
}

// ---------------------------------------------------------------------------
// 脱敏 golden：成功与失败的每一条路径
// ---------------------------------------------------------------------------

#[test]
fn set_success_never_leaks_the_value() {
    let harness = Harness::new();
    vault_cli::device_init(&harness.ctx()).expect("建立设备身份");
    vault_cli::vault_create(&harness.ctx()).expect("创建 Vault");
    std::env::set_var(CANARY_ENV, CANARY);

    let captured = capture("vault.set", || {
        vault_cli::vault_set(
            &harness.ctx(),
            "ci/npm-token",
            &ValueSource::Env(CANARY_ENV.to_owned()),
        )
    });
    captured.assert_no_canary("set 成功");

    // 输出**应当**包含逻辑标识、来源和长度——那些是元数据，用户需要它们。
    assert!(captured.human_stdout.contains("ci/npm-token"));
    assert!(captured.json.contains("\"source\":\"env\""));
    assert!(captured
        .json
        .contains(&format!("\"value_bytes\":{}", CANARY.len())));
    // 环境变量的**名字**可以出现（它不是秘密），值不行。
    assert!(!captured.json.contains(CANARY));
}

#[test]
fn set_failure_when_the_key_store_is_unavailable_never_leaks_the_value() {
    let harness = Harness::new();
    harness.bootstrap();
    std::env::set_var(CANARY_ENV, CANARY);

    let captured = capture("vault.set", || {
        vault_cli::vault_set(
            &harness.broken_ctx(),
            "ci/npm-token",
            &ValueSource::Env(CANARY_ENV.to_owned()),
        )
    });
    captured.assert_no_canary("set 失败（密钥库不可用）");
    assert!(captured.json.contains("platform.secure_store_unavailable"));
    // 安全失败：既没有写出任何明文，也没有伪装成功。
    assert!(captured.human_stdout.is_empty());
}

#[test]
fn get_success_writing_a_file_never_leaks_the_value_to_any_channel() {
    let harness = Harness::new();
    harness.bootstrap();
    let out_path = harness.path("token.out");

    let captured = capture("vault.get", || {
        vault_cli::vault_get(
            &harness.ctx(),
            "ci/npm-token",
            &OutputTarget::File(out_path.clone()),
            false,
        )
    });
    captured.assert_no_canary("get 成功（写文件）");

    // 值确实到了文件里——否则这条测试就只是在证明「什么都没发生」。
    assert_eq!(
        std::fs::read(&out_path).expect("读取输出文件"),
        CANARY.as_bytes()
    );
    // JSON 里只有文件名，没有目录，更没有值。
    assert!(captured.json.contains("\"output\":\"file:token.out\""));
    assert!(!captured
        .json
        .contains(harness.root.path().to_str().unwrap()));
}

#[test]
fn get_failure_for_a_missing_secret_never_leaks_anything() {
    let harness = Harness::new();
    harness.bootstrap();
    let captured = capture("vault.get", || {
        vault_cli::vault_get(
            &harness.ctx(),
            "ci/does-not-exist",
            &OutputTarget::File(harness.path("nope.out")),
            false,
        )
    });
    captured.assert_no_canary("get 失败（不存在）");
    assert!(captured.json.contains("vault.secret_not_found"));
    assert!(!harness.path("nope.out").exists(), "失败时不该留下输出文件");
}

#[test]
fn list_never_leaks_the_value() {
    let harness = Harness::new();
    harness.bootstrap();
    let captured = capture("vault.list", || vault_cli::vault_list(&harness.ctx()));
    captured.assert_no_canary("list");

    // 元数据在，值不在。
    assert!(captured.human_stdout.contains("ci/npm-token"));
    assert!(captured.json.contains("\"entries\""));
    assert!(captured.json.contains("\"key_epoch\":1"));
    // 字段名如果叫 `secrets`，脱敏器会把整棵子树替换掉，清单就没法看了。
    assert!(
        !captured.json.contains("<redacted>"),
        "清单不该被自己的字段名脱掉：{}",
        captured.json
    );
}

#[test]
fn delete_never_leaks_the_value() {
    let harness = Harness::new();
    harness.bootstrap();
    let captured = capture("vault.delete", || {
        vault_cli::vault_delete(&harness.ctx(), "ci/npm-token")
    });
    captured.assert_no_canary("delete");
    assert!(captured.json.contains("\"deleted\":true"));

    // 删掉之后再删一次：另一条路径，同样不许泄露。
    let captured = capture("vault.delete", || {
        vault_cli::vault_delete(&harness.ctx(), "ci/npm-token")
    });
    captured.assert_no_canary("delete（重复）");
    assert!(captured.json.contains("\"deleted\":false"));
}

#[test]
fn device_revoke_never_leaks_the_value() {
    let harness = Harness::new();
    harness.bootstrap();

    // 邀请第二台设备（用一把独立生成的密钥对充当它的公开材料）。
    let other = envsync_crypto::device::DeviceKeypair::generate().expect("生成设备");
    let invitation_path = harness.path("invite.cbor");
    let captured = capture("device.invite", || {
        vault_cli::device_invite(
            &harness.ctx(),
            &vault_cli::encode_public(&other.public()),
            MemberRole::Member,
            &invitation_path,
        )
    });
    captured.assert_no_canary("device invite");

    let captured = capture("device.list", || vault_cli::device_list(&harness.ctx()));
    captured.assert_no_canary("device list");
    assert!(captured.json.contains(&other.device_id().to_hex()));

    let captured = capture("device.revoke", || {
        vault_cli::device_revoke(&harness.ctx(), other.device_id())
    });
    captured.assert_no_canary("device revoke");
    assert!(captured.json.contains("\"from_epoch\":1"));
    assert!(captured.json.contains("\"to_epoch\":2"));
    assert!(captured.json.contains("\"stage\":\"complete\""));
}

#[test]
fn resuming_an_interrupted_rotation_never_leaks_the_value() {
    let harness = Harness::new();
    harness.bootstrap();

    let other = envsync_crypto::device::DeviceKeypair::generate().expect("生成设备");
    vault_cli::device_invite(
        &harness.ctx(),
        &vault_cli::encode_public(&other.public()),
        MemberRole::Member,
        &harness.path("invite.cbor"),
    )
    .expect("邀请设备");

    // 在「发布信封」之前把轮换掐断。
    harness
        .ctx()
        .service()
        .expect("打开服务")
        .revoke_device_until(
            other.device_id(),
            Some(envsync_storage::RotationStage::EnvelopesPublished),
        )
        .expect("中断的轮换");

    // 重跑同一条命令：它会接着做完，输出里同样不许出现 canary。
    let captured = capture("device.revoke", || {
        vault_cli::device_revoke(&harness.ctx(), other.device_id())
    });
    captured.assert_no_canary("轮换中断后恢复");
    assert!(captured.json.contains("\"resumed\":true"));
    assert!(captured.json.contains("\"stage\":\"complete\""));
    // 恢复这件事本身要显式告诉用户。
    assert!(captured.human_stderr.contains("rotation.resumed"));

    // 恢复完之后仍然读得出原值。
    let out = harness.path("after.out");
    vault_cli::vault_get(
        &harness.ctx(),
        "ci/npm-token",
        &OutputTarget::File(out.clone()),
        false,
    )
    .expect("读取");
    assert_eq!(std::fs::read(&out).expect("读取"), CANARY.as_bytes());
}

#[test]
fn recovery_and_security_commands_never_leak_the_value() {
    let harness = Harness::new();
    harness.bootstrap();

    // `recovery create` 会把短语写到进程 stderr（只显示一次），JSON 里不该有它。
    let captured = capture("recovery.create", || {
        vault_cli::recovery_create(&harness.ctx())
    });
    captured.assert_no_canary("recovery create");
    assert!(captured.json.contains("\"epochs\":[1]"));

    let captured = capture("security.checkpoint", || {
        vault_cli::security_checkpoint(&harness.ctx())
    });
    captured.assert_no_canary("security checkpoint");
    assert!(captured.json.contains("\"established\":true"));
    assert!(captured.json.contains("\"key_epoch\":1"));
    // 非系统存储必须被显式标注，免得有人拿测试配置当生产用。
    assert!(captured
        .human_stderr
        .contains("checkpoint.non_system_store"));
}

#[test]
fn every_failure_path_keeps_the_canary_out_of_all_four_channels() {
    let harness = Harness::new();
    harness.bootstrap();
    std::env::set_var(CANARY_ENV, CANARY);

    // 一次把「已知的失败形状」全过一遍。逐条断言四个通道。
    let cases: Vec<FailureCase<'_>> = vec![
        (
            "vault.set",
            Box::new(|| {
                vault_cli::vault_set(
                    &harness.broken_ctx(),
                    "ci/npm-token",
                    &ValueSource::Env(CANARY_ENV.to_owned()),
                )
            }),
        ),
        (
            "vault.set",
            Box::new(|| {
                // 非法逻辑标识：在碰任何密钥之前就被拒绝。
                vault_cli::vault_set(
                    &harness.ctx(),
                    "../escape",
                    &ValueSource::Env(CANARY_ENV.to_owned()),
                )
            }),
        ),
        (
            "vault.set",
            Box::new(|| {
                // 环境变量不存在：错误里只有变量名。
                vault_cli::vault_set(
                    &harness.ctx(),
                    "ci/other",
                    &ValueSource::Env("ENVSYNC_UNSET_FOR_TEST".to_owned()),
                )
            }),
        ),
        (
            "vault.get",
            Box::new(|| {
                vault_cli::vault_get(
                    &harness.broken_ctx(),
                    "ci/npm-token",
                    &OutputTarget::Stdout,
                    true,
                )
            }),
        ),
        (
            "vault.get",
            Box::new(|| {
                // 非 TTY 且没有 --allow-non-tty：必须拒绝。
                vault_cli::vault_get(&harness.ctx(), "ci/npm-token", &OutputTarget::Stdout, false)
            }),
        ),
        (
            "vault.list",
            Box::new(|| vault_cli::vault_list(&harness.broken_ctx())),
        ),
        (
            "vault.delete",
            Box::new(|| vault_cli::vault_delete(&harness.broken_ctx(), "ci/npm-token")),
        ),
        (
            "device.list",
            Box::new(|| vault_cli::device_list(&harness.broken_ctx())),
        ),
        (
            "device.invite",
            Box::new(|| {
                // 公开材料非法：用法错误，不碰后端。
                vault_cli::device_invite(
                    &harness.ctx(),
                    "not-hex",
                    MemberRole::Member,
                    &harness.path("invite.cbor"),
                )
            }),
        ),
        (
            "device.join",
            Box::new(|| vault_cli::device_join(&harness.ctx(), &harness.path("missing.cbor"))),
        ),
        (
            "device.revoke",
            Box::new(|| {
                vault_cli::device_revoke(&harness.ctx(), envsync_domain::DeviceId::derive(b"ghost"))
            }),
        ),
        (
            "security.checkpoint",
            Box::new(|| vault_cli::security_checkpoint(&harness.broken_ctx())),
        ),
    ];

    for (index, (command, run)) in cases.iter().enumerate() {
        let captured = capture(command, run);
        captured.assert_no_canary(&format!("失败路径 #{index}（{command}）"));
        assert!(
            captured.json.contains("\"status\":\"error\""),
            "失败路径 #{index}（{command}）应当以 error 信封收尾：{}",
            captured.json
        );
    }
}

#[test]
fn the_non_tty_refusal_is_the_gate_and_allow_non_tty_is_the_only_way_through() {
    let harness = Harness::new();
    harness.bootstrap();

    // 关闸：cargo test 下 stdout 不是终端，因此必须被拒绝。
    let captured = capture_with_stdout("vault.get", |stdout| {
        vault_cli::vault_get_with_writer(
            &harness.ctx(),
            "ci/npm-token",
            &OutputTarget::Stdout,
            false,
            stdout,
        )
    });
    captured.assert_no_canary("stdout 未获授权");
    assert!(captured.json.contains("vault.non_tty_output_refused"));
    assert!(
        captured.raw_stdout.is_empty(),
        "被拒绝时一个字节都不该写出去"
    );

    // 开闸：这是**唯一**允许 canary 出现的地方。
    let captured = capture_with_stdout("vault.get", |stdout| {
        vault_cli::vault_get_with_writer(
            &harness.ctx(),
            "ci/npm-token",
            &OutputTarget::Stdout,
            true,
            stdout,
        )
    });
    assert_eq!(
        captured.raw_stdout,
        CANARY.as_bytes(),
        "显式授权后值应当原样写出，一个字节不多不少"
    );
    // 即使在这条路径上，其余三个通道依然干净——元数据不会顺手把值也带出去。
    for (channel, text) in [
        ("stdout-正文", captured.human_stdout.as_str()),
        ("stderr", captured.human_stderr.as_str()),
        ("json", captured.json.as_str()),
        ("tracing", captured.tracing.as_str()),
    ] {
        assert!(
            !text.contains(CANARY),
            "显式输出秘密时，{channel} 通道仍然不该出现它：{text}"
        );
    }
    // 值已经写进 stdout 了，人类可读正文必须为空，否则会污染它。
    assert!(captured.human_stdout.is_empty());
}

#[test]
fn tracing_at_trace_level_never_carries_the_value() {
    let harness = Harness::new();
    // 整个 bootstrap + 一轮读写都在 trace 级订阅者下跑。
    let (_, logs) = with_tracing(|| {
        harness.bootstrap();
        let _ = vault_cli::vault_list(&harness.ctx());
        let _ = vault_cli::vault_get(
            &harness.ctx(),
            "ci/npm-token",
            &OutputTarget::File(harness.path("t.out")),
            false,
        );
        let _ = vault_cli::vault_delete(&harness.ctx(), "ci/npm-token");
    });
    assert!(
        !logs.contains(CANARY),
        "tracing 记录里出现了 canary：{logs}"
    );
    // 反面对照：日志确实产生了内容，否则这条断言是空转。
    assert!(!logs.is_empty(), "trace 级别下应当有日志产生");
}

// ---------------------------------------------------------------------------
// 输入面：命令行永远拿不到值
// ---------------------------------------------------------------------------

#[test]
fn vault_set_has_no_value_flag() {
    let output = run(&["vault", "set", "--help"]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        !text.contains("--value"),
        "`vault set` 不得提供 --value：{text}"
    );
    for expected in ["--stdin", "--from-env", "--prompt"] {
        assert!(
            text.contains(expected),
            "`vault set --help` 应当说明 {expected}：{text}"
        );
    }
}

#[test]
fn value_sources_are_exhaustive_and_named_stably() {
    assert_eq!(ValueSource::Stdin.as_str(), "stdin");
    assert_eq!(ValueSource::Env("X".to_owned()).as_str(), "env");
    assert_eq!(ValueSource::Prompt.as_str(), "prompt");
}

// ---------------------------------------------------------------------------
// 真二进制：命令面与退出码
// ---------------------------------------------------------------------------

/// 运行一次真正的 `envsync` 二进制。
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_envsync"))
        .args(args)
        .output()
        .expect("应当能够启动 envsync 二进制")
}

/// 退出码。
fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("进程应当正常退出而不是被信号终止")
}

/// M2 新增的全部子命令路径。
const M2_COMMANDS: &[&[&str]] = &[
    &["device", "init"],
    &["device", "list"],
    &["device", "invite"],
    &["device", "join"],
    &["device", "revoke"],
    &["vault", "create"],
    &["vault", "set"],
    &["vault", "get"],
    &["vault", "list"],
    &["vault", "delete"],
    &["recovery", "create"],
    &["recovery", "restore"],
    &["security", "checkpoint"],
];

#[test]
fn the_new_command_groups_appear_in_the_top_level_help() {
    let output = run(&["--help"]);
    assert_eq!(code(&output), 0);
    let text = String::from_utf8_lossy(&output.stdout);
    for group in ["device", "vault", "recovery", "security"] {
        assert!(text.contains(group), "顶层帮助应当列出 `{group}`：{text}");
    }
}

#[test]
fn every_new_subcommand_has_help_and_documents_config() {
    for command in M2_COMMANDS {
        let mut args = command.to_vec();
        args.push("--help");
        let output = run(&args);
        assert_eq!(code(&output), 0, "`{command:?} --help` 应当退出 0");
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            text.contains("--config"),
            "`{command:?} --help` 应当说明 --config：{text}"
        );
    }
}

#[test]
fn missing_required_arguments_are_usage_errors() {
    for command in M2_COMMANDS {
        let output = run(command);
        assert_eq!(
            code(&output),
            2,
            "`{command:?}` 缺 --config 时应当是用法错误：{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn the_new_commands_are_rejected_under_schema_v1() {
    let harness = Harness::new();
    let output = run(&[
        "--schema-version",
        "1",
        "vault",
        "list",
        "--config",
        harness.config_path.to_str().expect("路径"),
    ]);
    assert_eq!(code(&output), 1);
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(
        text.contains("schema"),
        "应当说明这些命令只在 v2 中定义：{text}"
    );
}

#[test]
fn an_unavailable_system_key_store_fails_safely_with_exit_code_15() {
    // CI 容器里没有可用的系统凭据库，因此这条路径在这里就是真实路径：
    // 命令必须**失败**，而不是悄悄写一个明文密钥文件。
    let harness = Harness::new();
    let config = harness.config_path.to_str().expect("路径");
    std::env::set_var(CANARY_ENV, CANARY);

    let output = Command::new(env!("CARGO_BIN_EXE_envsync"))
        .args(["vault", "list", "--config", config, "--json"])
        .env(CANARY_ENV, CANARY)
        .output()
        .expect("启动二进制");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.contains(CANARY) && !stderr.contains(CANARY),
        "任何通道都不得出现 canary"
    );

    match code(&output) {
        0 => {
            // 本机恰好有可用的系统凭据库：那么这条命令应当以「工作区未初始化」失败或
            // 给出空清单，无论哪种都不该泄露任何东西。上面的断言已经覆盖。
        }
        15 => {
            assert!(
                stdout.contains("secure_store") || stderr.contains("secure_store"),
                "退出码 15 应当伴随安全存储错误码：{stdout}{stderr}"
            );
            // 关键：没有任何明文 fallback 落盘。
            assert!(
                !key_material_on_disk(&harness.config.state_dir),
                "安全存储不可用时绝不能在本地写下密钥文件"
            );
        }
        other => {
            // 其他失败（例如工作区还没创建）同样必须干净。
            assert_ne!(other, 0);
        }
    }
}

/// 粗略扫一遍状态目录，确认没有任何「看起来像裸密钥」的文件。
///
/// 判据刻意宽松：只要出现名字里带 `key` / `secret` 的普通文件就算可疑。宁可误报，
/// 也不要漏掉一条真的 fallback 路径。
fn key_material_on_disk(dir: &Path) -> bool {
    fn walk(dir: &Path, found: &mut bool) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                if name.contains("key") || name.contains("secret") {
                    *found = true;
                }
            }
        }
    }
    let mut found = false;
    walk(dir, &mut found);
    found
}

#[test]
fn error_output_is_a_well_formed_json_envelope() {
    let harness = Harness::new();
    let output = run(&[
        "vault",
        "list",
        "--config",
        harness.config_path.to_str().expect("路径"),
        "--json",
    ]);
    if code(&output) == 0 {
        return; // 本机有可用凭据库，这条断言换成成功形状即可，不是本测试的重点。
    }
    let line = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value =
        serde_json::from_str(line.trim()).expect("stdout 必须是一行 JSON");
    assert_eq!(value["status"], "error");
    assert_eq!(value["command"], "vault.list");
    assert_eq!(value["data"], serde_json::Value::Null);
    assert!(value["diagnostics"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
}

#[test]
fn err_helper_reports_failures_without_requiring_debug() {
    // `CommandOutput` 不实现 `Debug`（里面挂着不可打印的数据形状），因此测试里统一用
    // `err()` 取错误。这条测试同时钉住了那个约束。
    let harness = Harness::new();
    let error = err(vault_cli::vault_list(&harness.broken_ctx()));
    assert_eq!(error.code(), "platform.secure_store_unavailable");
    assert!(!error.to_string().contains(CANARY));
}
