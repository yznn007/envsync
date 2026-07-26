//! M2 任务 10 步骤 1：**端到端攻击矩阵**（计划文档里的 `tests/e2e/vault_multi_device.rs`）。
//!
//! 计划文档列了九项攻击，本文件逐项落成一个（或一组）测试函数，每个函数上方的注释
//! 写明它对应矩阵的哪一项。
//!
//! | 攻击矩阵 | 测试函数 |
//! |---|---|
//! | 1 后端读权限 | [`backend_leak_exposes_metadata_but_never_a_single_plaintext_byte`] |
//! | 2 ciphertext 篡改 | [`flipping_one_ciphertext_byte_is_caught_by_content_addressing`]、[`a_consistent_forgery_is_caught_by_aead_authentication`] |
//! | 3 替换 envelope | [`substituting_another_devices_envelope_fails_authentication_without_panicking`] |
//! | 4 撤销设备 | [`revocation_advances_the_epoch_and_locks_the_revoked_device_out`] |
//! | 5 旧 head | [`rolling_the_backend_back_to_an_old_head`] |
//! | 6 错误恢复口令 | [`every_wrong_recovery_phrase_yields_the_very_same_authentication_error`] |
//! | 7 进程中断轮换 | [`interrupting_a_rotation_at_every_stage_recovers_idempotently`]、[`a_lying_rotation_journal_can_never_publish_a_head`] |
//! | 8 日志 canary | [`the_real_binary_never_echoes_the_canary_on_any_subcommand`]、[`the_real_binary_full_flow_never_surfaces_the_vault_canary`]、[`no_in_process_command_channel_ever_carries_the_canary`]、[`the_only_deliberate_outlet_is_vault_get_stdout`] |
//! | 9 跨 workspace 重放 | [`cross_workspace_replay_of_every_object_kind_is_rejected`] |
//!
//! # 为什么这一套是「真进程 + 库级」的混合体，而 `git_multi_device.rs` 不是
//!
//! M0/M1 的两套 E2E 全程只用 `std::process::Command` 驱动真二进制。M2 做不到，原因是
//! 一条硬性的产品约束：[`envsync_cli::vault_cli::VaultContext::open`] **只认**
//! [`envsync_platform::secure_store::open_system_store`]，拿不到系统凭据库就以退出码
//! 15 失败，没有任何回退分支。容器与 CI 上没有 DBus 会话总线，于是真二进制的
//! `device` / `vault` / `recovery` / `security` **每一条子命令都停在第一行**：
//!
//! ```text
//! $ envsync vault create --config ./envsync.yaml --json
//! {"command":"vault.create","data":null,"diagnostics":[{"code":"platform.secure_store_unavailable",...
//! $ echo $?
//! 15
//! ```
//!
//! 而进程边界上**没有**任何注入口（`with_stores` 挂在 `test-support` feature 下，生产
//! 二进制里根本不存在这个符号）。因此本文件的分工是：
//!
//! * **真二进制**负责它唯一能负责的那一层——命令面、`--json` 信封、退出码，以及
//!   「安全存储不可用时安全失败」这条真实路径（攻击 8 的进程侧）；
//! * **进程内**（直接调用 `envsync_cli::vault_cli::*` 的命令函数，注入
//!   `InMemorySecureStore` + `InMemoryCheckpointStore`）负责其余八项。每条命令都新开一个
//!   [`VaultContext`]，等价于「又跑了一条命令」：服务不跨命令缓存状态，安全存储与检查点
//!   像真实凭据库一样跨「进程」存活。
//!
//! 攻击本身（篡改字节、替换信封、伪造索引、回滚后端、伪造 journal）一律直接对**后端
//! 目录**和**轮换 journal**下手，走的是 [`envsync_backend::Backend`] 与文件系统，
//! 不经过任何被测代码路径——攻击者本来就不受 EnvSync 的 API 约束。
//!
//! # 断言的粒度
//!
//! 「输出里没有那个子串」这种断言太容易蒙对。所以：
//!
//! * canary 用**逐字节窗口扫描**在后端每个文件的每个偏移上找，并且每次都配一条
//!   **正向对照**（逻辑标识必须能找到），否则扫描就成了空转；
//! * 失败断言到 [`envsync_core::CoreError::code`] 这个稳定错误码，不看错误文本；
//! * 真进程断言到退出码整数；
//! * 「本地文件零变更」断言的是整棵目录树的**逐字节指纹**，不是文件数量。
//!
//! # 本套件钉住的「当前行为」（与计划文档措辞有出入的地方）
//!
//! 下面几条不是断言写松了，而是**实现现在就是这样**。测试按实际行为写，并在这里
//! 逐条记下来，免得日后有人把它们当成测试 bug 顺手「修」掉：
//!
//! 1. **读路径完全不查反回滚检查点。** [`envsync_core::vault::VaultService::reload`]
//!    只验成员链，不调 `check_advance`；检查点只在
//!    `VaultService::publish` 里推进。因此后端被回退之后，`vault get` / `vault list` /
//!    `device list` 会安静地返回旧状态（已撤销设备重新出现在成员名单里），只有下一次
//!    **写**才会撞上检查点。见 [`rolling_the_backend_back_to_an_old_head`]。
//! 2. **检查点判定在 CAS 之后。** 同一条路径上，被骗的客户端会先把新头 CAS 上去、
//!    再发现自己被回滚了，于是后端的 revision 已经被推进了一格。
//! 3. **快照签名从不被验证。** `publish_snapshot_signature` 会写一个
//!    `ObjectKind::SnapshotSignature` 对象，但全仓库没有任何地方读它——
//!    `SNAPSHOT_SIGNATURE_DOMAIN` 只出现在签名侧。因此本文件里的 [`republish_head`]
//!    连伪造签名都不需要。
//! 4. **成员链自身的 `workspace` 字段不与本地工作区比对。**
//!    `verify_membership_chain` 只保证「链内各事件的 workspace 与 genesis 一致」，
//!    `reload` 只检查*索引*的 workspace。于是一整条外来链可以被读进来，
//!    见 [`cross_workspace_replay_of_every_object_kind_is_rejected`] 的第 3b 段。
//! 5. **`device revoke` 的最后一步是主动重加密，不是 lazy rewrap。** 撤销一结束，
//!    索引里已经没有任何旧纪元条目，见
//!    [`revocation_advances_the_epoch_and_locks_the_revoked_device_out`]。
//! 6. **后端层错误码没有层前缀**：是 `corruption` / `cas_conflict`，而不是
//!    `backend.corruption`；其余每一层都有前缀。
//! 7. **一次普通 `envsync sync` 会静默抹掉整个 Vault。** 普通同步与 Vault 共用同一条
//!    工作区 Ref，而 M0/M1 的发布路径自己构造头快照，`metadata` 里只写
//!    `device_name` / `format`，**不会把上一个头的
//!    [`VAULT_INDEX_METADATA_KEY`] 带过来**。于是 `sync` 一跑完，头快照上的 Vault
//!    索引指针就没了：`vault get` 变成 `vault.secret_not_found`，而 `vault list`
//!    **照常以 `status: ok` 返回一个空 Vault，一条诊断都不给**。密封对象本身还在后端
//!    上（内容寻址、不可变），丢的只是那个指针——但从用户视角看，跑一条例行 `sync`
//!    就让整个 Vault 消失了。见
//!    [`the_real_binary_full_flow_never_surfaces_the_vault_canary`] 的最后一段。

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use envsync_backend::{Backend, LocalBackend};
use envsync_cli::commands::{CommandData, CommandOutput};
use envsync_cli::output::{self, DiagnosticOut, Status, JSON_SCHEMA_VERSION};
use envsync_cli::vault_cli::{self, OutputTarget, ValueSource, VaultContext};
use envsync_core::checkpoint::{CheckpointStore, InMemoryCheckpointStore};
use envsync_core::device_admin;
use envsync_core::ports::Clock;
use envsync_core::vault::{SecretInput, VaultIndex, VaultService, VAULT_INDEX_METADATA_KEY};
use envsync_core::{CoreError, CoreResult, WorkspaceConfig};
use envsync_crypto::device::{DeviceKeypair, DevicePublic};
use envsync_crypto::envelope::KeyEnvelope;
use envsync_crypto::recovery::{Argon2Params, RecoveryPackage, RecoveryPhrase};
use envsync_crypto::sealed::{SealedSecret, SecretId};
use envsync_crypto::suite::{KeyEpoch, Plaintext};
use envsync_crypto::CryptoError;
use envsync_domain::cbor::CborCodec;
use envsync_domain::id::{DeviceId, WorkspaceId};
use envsync_domain::membership::MemberRole;
use envsync_domain::object::{ObjectId, ObjectKind};
use envsync_domain::snapshot::{SnapshotBody, WorkspaceRef};
use envsync_domain::{DesiredDisposition, FileMode};
use envsync_e2e::{arg, envsync_binary, resource, Device, E2eWorld};
use envsync_platform::secure_store::{SecureKey, SecurePurpose, SecureStore};
use envsync_platform::InMemorySecureStore;
use envsync_storage::{RotationJournal, RotationStage};
use serde_json::Value;

// ---------------------------------------------------------------------------
// 固定数据
// ---------------------------------------------------------------------------

/// 一串绝不该出现在任何输出通道、也绝不该出现在后端任何一个字节位置上的标记。
///
/// 刻意长、刻意不含空白、刻意不像任何编码产物：它一旦出现，就只可能是明文泄露。
const CANARY: &str = "CANARY-8b41d0e7a95c236f-E2E-DO-NOT-LEAK";

/// 第二个 canary：撤销之后写入的新秘密用它，用来区分「读到了新值」和「读到了旧值」。
const CANARY_AFTER_ROTATION: &str = "CANARY-27ce9f4b60a1d8e3-EPOCH-TWO-ONLY";

/// 承载 canary 的环境变量名。变量**名**可以出现在输出里，值不行。
const CANARY_ENV: &str = "ENVSYNC_E2E_VAULT_MULTI_DEVICE_CANARY";

/// 主秘密的逻辑标识。它是**公开**元数据：后端上找得到它才说明扫描没有空转。
const SECRET: &str = "ci/npm-token";

/// 撤销之后才写入的秘密。
const SECRET_AFTER_ROTATION: &str = "ci/deploy-key";

/// 一个**普通（非秘密）资源**的标识：走 M0/M1 的同步路径，不进 Vault。
const PUBLIC_RESOURCE: &str = "git/config";

/// 那个普通资源的内容。
///
/// 攻击矩阵第 1 项要求把边界的**另一侧**也断言出来：M2 封起来的只有 Vault 秘密，
/// 普通资源在后端上仍然是明文 Blob。这串字节必须在后端上逐字节找得到——它一身兼两职：
///
/// * **证明扫描没有空转**：能看见「内容」，而不只是能看见对象名这类元数据；
/// * **如实反映 M2 的威胁边界**：拿到后端读权限的人读得到你所有普通配置，
///   别把「Vault 是加密的」误当成「EnvSync 把一切都加密了」。
const PUBLIC_BODY: &str = "[user]\n\tname = PUBLIC-3f9c81ae5d2b4706-VISIBLE-ON-BACKEND\n";

/// 一次性把 canary 放进环境变量，并返回变量名。
///
/// 用 [`OnceLock`] 而不是每个测试各设一次：`set_var` 是进程级的，并行测试各写各的会
/// 互相踩。`get_or_init` 保证初始化只跑一次，且所有调用方都在它之后才读到变量名。
fn canary_env_var() -> &'static str {
    static READY: OnceLock<&'static str> = OnceLock::new();
    READY.get_or_init(|| {
        std::env::set_var(CANARY_ENV, CANARY);
        CANARY_ENV
    })
}

// ---------------------------------------------------------------------------
// 时钟
// ---------------------------------------------------------------------------

/// 单调前进的假时钟：每次读取 +1 毫秒。
///
/// 既保证「同一次操作里的多个时间戳」互不相同（快照标识覆盖 `created_at_unix_ms`，
/// 撞了就会出现两个内容不同却同标识的快照），又完全可复现。
#[derive(Debug)]
struct TickingClock(AtomicU64);

impl TickingClock {
    fn new(start: u64) -> Self {
        TickingClock(AtomicU64::new(start))
    }
}

impl Clock for TickingClock {
    fn now_unix_ms(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// 世界与设备
// ---------------------------------------------------------------------------

/// 一个隔离的世界：一个临时目录 + 一个共享的 Local Backend + 若干设备。
///
/// 每个测试各持一个，彼此没有任何共享状态，因此可以并行执行。
struct World {
    inner: E2eWorld,
}

impl World {
    /// 建立世界。
    fn new() -> Self {
        World {
            inner: E2eWorld::new(),
        }
    }

    /// 第一台设备：真正跑一次 `envsync init`（真二进制），由它决定 `workspace_id`。
    fn primary(&self, name: &str) -> VaultDevice {
        VaultDevice::wrap(self.inner.primary(name), self.inner.path().to_path_buf())
    }

    /// 后续设备：同一个后端、同一个 `workspace_id`，但本地状态完全独立。
    fn secondary(&self, primary: &VaultDevice, name: &str) -> VaultDevice {
        VaultDevice::wrap(
            self.inner.secondary(&primary.cli, name),
            self.inner.path().to_path_buf(),
        )
    }

    /// 共享后端目录。
    fn backend_dir(&self) -> PathBuf {
        self.inner.backend()
    }

    /// 直接打开共享后端——**攻击者视角**，不经过任何被测代码路径。
    fn backend(&self) -> LocalBackend {
        LocalBackend::open(self.backend_dir()).expect("应当能打开后端")
    }

    /// 世界根目录（放邀请文件、备份副本这类临时产物）。
    fn path(&self) -> &Path {
        self.inner.path()
    }
}

/// 一台设备：真二进制用的配置文件 + 本机独有的安全存储、检查点存储与时钟。
///
/// `secure` / `checkpoints` 跨「命令」存活，正是真实凭据库与真实检查点的形状；
/// [`VaultDevice::ctx`] 每次新建一个上下文，等价于「又跑了一条命令」。
struct VaultDevice {
    cli: Device,
    root: PathBuf,
    secure: Arc<InMemorySecureStore>,
    checkpoints: Arc<InMemoryCheckpointStore>,
    clock: Arc<TickingClock>,
}

impl VaultDevice {
    fn wrap(cli: Device, root: PathBuf) -> Self {
        VaultDevice {
            cli,
            root,
            secure: Arc::new(InMemorySecureStore::new()),
            checkpoints: Arc::new(InMemoryCheckpointStore::new()),
            clock: Arc::new(TickingClock::new(1_700_000_000_000)),
        }
    }

    /// 设备名。
    fn name(&self) -> &str {
        self.cli.name()
    }

    /// 工作区配置（每次从磁盘读回，和真命令一样）。
    fn config(&self) -> WorkspaceConfig {
        self.cli.config()
    }

    /// 工作区标识。
    fn workspace(&self) -> WorkspaceId {
        self.config().workspace_id
    }

    /// 本机 Vault 状态目录（草稿库 + 轮换 journal）。
    fn vault_dir(&self) -> PathBuf {
        self.config().vault_dir()
    }

    /// 新建一个命令上下文。
    fn ctx(&self) -> VaultContext {
        VaultContext::with_stores(
            self.config(),
            Arc::clone(&self.secure) as Arc<dyn SecureStore>,
            Arc::clone(&self.checkpoints) as Arc<dyn CheckpointStore>,
            Arc::clone(&self.clock) as Arc<dyn Clock>,
        )
    }

    /// 打开一个服务实例，断言成功。
    fn service(&self) -> VaultService {
        self.try_service()
            .unwrap_or_else(|error| panic!("{}：应当能打开 Vault 服务：{error}", self.name()))
    }

    /// 打开一个服务实例，不断言。
    fn try_service(&self) -> CoreResult<VaultService> {
        self.ctx().service()
    }

    /// `envsync device init`：在安全存储里建立本设备身份。
    fn device_init(&self) -> DeviceKeypair {
        vault_cli::device_init(&self.ctx()).expect("device init 应当成功");
        self.keypair()
    }

    /// 从安全存储读回本设备身份。
    fn keypair(&self) -> DeviceKeypair {
        device_admin::load_device(self.secure.as_ref(), self.workspace())
            .expect("安全存储可读")
            .expect("本设备应当已有身份")
    }

    /// 本设备标识。
    fn device_id(&self) -> DeviceId {
        self.keypair().device_id()
    }

    /// 本设备公开材料。
    fn device_public(&self) -> DevicePublic {
        self.keypair().public()
    }

    /// `envsync vault create`。
    fn vault_create(&self) {
        vault_cli::vault_create(&self.ctx()).expect("vault create 应当成功");
    }

    /// 声明一个普通（非秘密）资源，但不同步。
    fn declare_public_resource(&self) {
        self.cli.set_resources(vec![resource(
            PUBLIC_RESOURCE,
            ".gitconfig",
            FileMode::FullFile,
            DesiredDisposition::Managed,
        )]);
        self.cli.write_home(".gitconfig", PUBLIC_BODY);
    }

    /// 声明并用**真二进制**（`capture` + `plan` + `sync`）把那个普通资源同步到后端。
    ///
    /// 走的是 M0/M1 的路径，与 Vault 毫无关系：它在后端上留下的是一个**明文** Blob。
    fn publish_public_resource(&self) {
        self.declare_public_resource();
        assert!(
            self.cli.capture().changed,
            "{}：首次捕获普通资源应当产生新草稿",
            self.name()
        );
        let sync = self.cli.converge();
        assert_eq!(sync.outcome, "completed", "{}", self.name());
        assert!(
            sync.published,
            "{}：普通资源必须真的发布到后端，否则后面的可见性断言是空转",
            self.name()
        );
    }

    /// 写一条秘密。
    ///
    /// 走核心层的 [`VaultService::set`] 而不是 `vault_cli::vault_set`：后者的取值来源
    /// 只有 stdin / 环境变量 / 隐藏输入三条，在一个多线程测试进程里反复改环境变量是
    /// 竞态。`vault set` 这条命令本身由攻击 8 覆盖。
    fn put_secret(&self, id: &str, value: &[u8]) {
        let mut service = self.service();
        service
            .set(&secret_id(id), input(value))
            .unwrap_or_else(|error| panic!("{}：写入 `{id}` 应当成功：{error}", self.name()));
    }

    /// 读一条秘密，返回明文字节。
    fn read_secret(&self, id: &str) -> CoreResult<Vec<u8>> {
        let service = self.try_service()?;
        Ok(service.get(&secret_id(id))?.expose().to_vec())
    }

    /// `envsync vault get --output <文件>`（真正的命令函数）。
    fn get_secret_to_file(&self, id: &str, path: &Path) -> CoreResult<CommandOutput> {
        vault_cli::vault_get(
            &self.ctx(),
            id,
            &OutputTarget::File(path.to_path_buf()),
            false,
        )
    }

    /// 邀请另一台设备，并让它加入。走的是 `device invite` + `device join` 两条真命令，
    /// 中间经过一份真实的邀请文件。
    fn invite_and_join(&self, newcomer: &VaultDevice, role: MemberRole) {
        let file = self.invite(newcomer, role);
        vault_cli::device_join(&newcomer.ctx(), &file)
            .unwrap_or_else(|error| panic!("{} 加入工作区应当成功：{error}", newcomer.name()));
    }

    /// 只邀请，不加入；返回邀请文件路径。
    fn invite(&self, newcomer: &VaultDevice, role: MemberRole) -> PathBuf {
        newcomer.device_init();
        let file = self.root.join(format!("{}.invitation", newcomer.name()));
        vault_cli::device_invite(
            &self.ctx(),
            &vault_cli::encode_public(&newcomer.device_public()),
            role,
            &file,
        )
        .unwrap_or_else(|error| panic!("邀请 {} 应当成功：{error}", newcomer.name()));
        file
    }

    /// `envsync device revoke`。
    fn revoke(&self, subject: DeviceId) -> CoreResult<CommandOutput> {
        vault_cli::device_revoke(&self.ctx(), subject)
    }

    /// 当前已验证的密钥纪元。
    fn epoch(&self) -> u64 {
        self.service().membership().expect("成员状态").epoch
    }

    /// 本机轮换 journal。
    fn rotation_journal(&self) -> RotationJournal {
        RotationJournal::open(self.vault_dir().join("rotation.db")).expect("应当能打开轮换 journal")
    }
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

/// 构造逻辑秘密标识。
fn secret_id(text: &str) -> SecretId {
    SecretId::parse(text).expect("测试用秘密标识必须合法")
}

/// 构造一次秘密输入。
fn input(value: &[u8]) -> SecretInput {
    SecretInput::from_reader(&mut &value[..]).expect("构造秘密输入")
}

/// 恢复包在安全存储里的坐标。
fn recovery_identity_key(workspace: WorkspaceId) -> SecureKey {
    SecureKey::workspace_scoped(workspace, SecurePurpose::RecoveryIdentity)
}

/// 一条待测的命令路径：命令名 + 触发它的闭包。
///
/// 闭包借用夹具，因此带一个生命周期参数——`'static` 装不下它，夹具是栈上的临时目录。
type CommandCase<'a> = (
    &'static str,
    Box<dyn Fn() -> CoreResult<CommandOutput> + 'a>,
);

/// 取出失败结果里的错误。
///
/// 不能用 `unwrap_err`：它要求 `T: Debug`，而 `Plaintext`、`SecretInput`、`VaultService`
/// 与 `CommandOutput` 都**刻意不实现** `Debug`。
fn err<T>(result: CoreResult<T>) -> CoreError {
    match result {
        Ok(_) => panic!("期望失败，实际却成功了"),
        Err(error) => error,
    }
}

/// 断言失败结果带着某个稳定错误码，并返回那个错误。
fn expect_code<T>(result: CoreResult<T>, code: &str, context: &str) -> CoreError {
    let error = err(result);
    assert_eq!(
        error.code(),
        code,
        "{context}：期望错误码 `{code}`，实际 `{}`（{error}）",
        error.code()
    );
    error
}

/// 递归读出目录下**所有文件**的完整字节。
fn all_files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    collect_files(dir, &mut out);
    out.sort_by(|left, right| left.0.cmp(&right.0));
    out
}

fn collect_files(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => collect_files(&path, out),
            Ok(_) => {
                if let Ok(bytes) = std::fs::read(&path) {
                    out.push((path, bytes));
                }
            }
            Err(_) => {}
        }
    }
}

/// 朴素子串搜索：在**每一个字节偏移**上比对。数据量是测试规模，可读性优先。
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// 断言 `needle` 不出现在目录下任何一个文件的任何一个字节位置。
///
/// 顺带断言目录非空——否则这条断言就成了空转。
fn assert_absent_from_every_byte(dir: &Path, needle: &[u8], label: &str) {
    let files = all_files(dir);
    assert!(
        !files.is_empty(),
        "{label}：目录 {} 是空的，这条断言就成了空转",
        dir.display()
    );
    for (path, bytes) in &files {
        assert!(
            !contains_bytes(bytes, needle),
            "{label}：文件 {} 的 {} 个字节里出现了 canary 明文",
            path.display(),
            bytes.len()
        );
    }
}

/// 断言 `needle` **确实**出现在目录下某个文件里（扫描的正向对照）。
fn assert_present_in_some_file(dir: &Path, needle: &[u8], label: &str) -> PathBuf {
    for (path, bytes) in all_files(dir) {
        if contains_bytes(&bytes, needle) {
            return path;
        }
    }
    panic!(
        "{label}：目录 {} 下找不到 {:?}——正向对照失败，说明扫描根本没覆盖到该数据",
        dir.display(),
        String::from_utf8_lossy(needle)
    );
}

/// 整棵目录树的逐字节指纹：路径 → 完整内容。
fn tree_fingerprint(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    all_files(dir).into_iter().collect()
}

/// 粗略扫一遍目录，确认没有任何「看起来像裸密钥」的文件。
///
/// 判据刻意宽松：只要出现名字里带 `key` / `secret` 的普通文件就算可疑。宁可误报，
/// 也不要漏掉一条真的明文 fallback 路径。EnvSync 在本地状态目录里只放
/// `journal.db` / `draft.db` / `rotation.db`，因此正常情况下恒为 `false`。
fn key_material_on_disk(dir: &Path) -> bool {
    all_files(dir).iter().any(|(path, _)| {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        name.contains("key") || name.contains("secret")
    })
}

/// 把整棵目录树复制一份（攻击者留存的「旧后端」）。
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("应当能创建目标目录");
    for entry in std::fs::read_dir(from).expect("应当能读源目录").flatten() {
        let target = to.join(entry.file_name());
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => copy_tree(&entry.path(), &target),
            Ok(_) => {
                std::fs::copy(entry.path(), &target).expect("应当能复制文件");
            }
            Err(_) => {}
        }
    }
}

/// 用一份旧副本**整体覆盖**后端目录，模拟「后端被回退到旧 revision」。
fn restore_tree(backup: &Path, target: &Path) {
    std::fs::remove_dir_all(target).expect("应当能清空后端目录");
    copy_tree(backup, target);
}

// ---------------------------------------------------------------------------
// 攻击者对后端的直接操作
// ---------------------------------------------------------------------------

/// 对象在后端目录里的绝对路径：`objects/<hex 前两位>/<其余>.<种类>`。
fn object_file(backend_dir: &Path, id: ObjectId) -> PathBuf {
    let (shard, rest) = id.storage_segments();
    backend_dir
        .join("objects")
        .join(shard)
        .join(format!("{rest}.{}", id.kind.as_str()))
}

/// 后端当前 Ref。
fn head_ref(backend: &LocalBackend, workspace: WorkspaceId) -> WorkspaceRef {
    backend.get_ref(workspace).expect("后端应当已有 Ref")
}

/// 后端当前头快照。
fn head_snapshot(backend: &LocalBackend, workspace: WorkspaceId) -> SnapshotBody {
    let head = head_ref(backend, workspace).head.expect("应当已有头快照");
    SnapshotBody::from_canonical_slice(
        &backend
            .get_object(ObjectId::from(head))
            .expect("应当能读头快照"),
    )
    .expect("头快照应当可解码")
}

/// 后端当前索引。
fn head_index(backend: &LocalBackend, workspace: WorkspaceId) -> VaultIndex {
    let body = head_snapshot(backend, workspace);
    let raw = body
        .metadata
        .get(VAULT_INDEX_METADATA_KEY)
        .expect("头快照应当带 vault 索引");
    let id = raw.parse::<ObjectId>().expect("索引对象标识应当可解析");
    VaultIndex::from_canonical_slice(&backend.get_object(id).expect("应当能读索引"))
        .expect("索引应当可解码")
}

/// **攻击者**用一份自己构造的索引重写工作区的头：写索引对象 → 写新快照 → CAS 推进 Ref。
///
/// 刻意**不**发布快照签名对象：EnvSync 在读路径上从不校验它（见本文件末尾的实现缺陷
/// 记录），因此攻击者也没有伪造它的动机。
fn republish_head(
    backend: &LocalBackend,
    workspace: WorkspaceId,
    author: DeviceId,
    index: &VaultIndex,
) {
    let index_bytes = index.to_canonical_vec();
    let index_id = ObjectId::for_bytes(ObjectKind::Blob, &index_bytes);
    backend
        .put_object(index_id, &index_bytes)
        .expect("应当能写索引对象");

    let current = head_ref(backend, workspace);
    let previous = head_snapshot(backend, workspace);
    let mut metadata = previous.metadata.clone();
    metadata.insert(VAULT_INDEX_METADATA_KEY.to_owned(), index_id.to_string());

    let body = SnapshotBody::new(
        workspace,
        current.head.into_iter().collect(),
        previous.state_root,
        author,
        previous.created_at_unix_ms + 1,
        metadata,
    )
    .expect("应当能构造快照");
    let snapshot = body.id();
    backend
        .put_object(ObjectId::from(snapshot), &body.to_canonical_vec())
        .expect("应当能写快照对象");
    backend
        .compare_and_swap_ref(workspace, current.revision, &current.advance(snapshot))
        .expect("攻击者应当能推进 Ref");
}

/// 断言「头引用到的每一个对象都真的在后端上」。
///
/// 轮换的核心不变量——**新头绝不引用尚未发布的信封**——就是它。断言的是后端目录里
/// 有没有那个文件，而不是代码里有没有那个检查。
fn assert_head_references_only_published_objects(backend: &LocalBackend, workspace: WorkspaceId) {
    let index = head_index(backend, workspace);
    let mut checked = 0usize;
    for id in index
        .membership
        .iter()
        .chain(index.envelopes.iter())
        .chain(index.recovery.iter())
        .copied()
        .chain(index.secrets.iter().map(|entry| entry.object))
    {
        assert!(
            backend.has_object(id).expect("后端可查"),
            "头索引引用了后端上不存在的对象 {id}"
        );
        checked += 1;
    }
    assert!(checked > 0, "索引里一个对象引用都没有，断言成了空转");
}

// ---------------------------------------------------------------------------
// 通道捕获（进程内）
// ---------------------------------------------------------------------------

/// 一次命令执行在四个通道上产生的全部字节。
#[derive(Debug, Default)]
struct Channels {
    /// 人类可读模式写进 stdout 的正文。
    stdout: String,
    /// 人类可读模式写进 stderr 的诊断或错误。
    stderr: String,
    /// `--json` 模式写进 stdout 的那一行。
    json: String,
    /// 命令执行期间产生的全部 tracing 记录（级别开到 trace）。
    tracing: String,
    /// `vault get --output stdout` 写出去的原始字节。
    raw_stdout: Vec<u8>,
}

impl Channels {
    /// 断言 canary 不出现在任何一个受脱敏保护的通道里。
    fn assert_no_canary(&self, label: &str) {
        for (channel, text) in [
            ("stdout", &self.stdout),
            ("stderr", &self.stderr),
            ("json", &self.json),
            ("tracing", &self.tracing),
        ] {
            assert!(
                !text.contains(CANARY),
                "{label}：canary 出现在 {channel} 通道里\n{text}"
            );
        }
        assert!(
            !contains_bytes(&self.raw_stdout, CANARY.as_bytes()),
            "{label}：canary 出现在原始 stdout 里，但本次命令并没有要求输出秘密"
        );
    }

    /// `--json` 信封。
    fn envelope(&self) -> Value {
        serde_json::from_str(&self.json).expect("JSON 信封应当可解析")
    }
}

/// 可共享的字节缓冲，兼作 tracing 的 writer。
#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    fn take(&self) -> String {
        let mut guard = self.0.lock().unwrap_or_else(|error| error.into_inner());
        let text = String::from_utf8_lossy(&guard).into_owned();
        guard.clear();
        text
    }
}

impl std::io::Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
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

/// 在一个把**全部**级别都记下来的 tracing 订阅者下执行 `body`。
///
/// 级别刻意开到 `trace`：要证明的是「即便把日志开到最大也不会漏」。
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

/// 执行一条命令函数，捕获四个通道。
///
/// 渲染走的是 CLI 真正用的那几个函数，因此捕到的就是用户会看到的字节。
fn capture(command: &str, run: impl FnOnce() -> CoreResult<CommandOutput>) -> Channels {
    capture_with_stdout(command, |_| run())
}

/// 同 [`capture`]，但把「秘密写向 stdout」这条唯一的出路也接进来。
fn capture_with_stdout(
    command: &str,
    run: impl FnOnce(&mut dyn std::io::Write) -> CoreResult<CommandOutput>,
) -> Channels {
    let mut raw_stdout: Vec<u8> = Vec::new();
    let (result, tracing) = with_tracing(|| run(&mut raw_stdout));
    let mut channels = Channels {
        tracing,
        raw_stdout,
        ..Channels::default()
    };
    match result {
        Ok(out) => {
            channels.stdout = output::human_body(&out.data.render());
            channels.stderr = output::human_diagnostics(&out.diagnostics);
            channels.json = output::json_line(
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
            channels.stderr = output::human_error(&error, &diagnostics);
            channels.json = output::json_line(
                command,
                Status::Error,
                JSON_SCHEMA_VERSION,
                None::<&CommandData>,
                &diagnostics,
                &[],
            );
        }
    }
    channels
}

// ---------------------------------------------------------------------------
// 真二进制调用（可喂 stdin）
// ---------------------------------------------------------------------------

/// 一次真二进制调用的结果。
#[derive(Debug)]
struct RawRun {
    argv: Vec<String>,
    code: i32,
    stdout: String,
    stderr: String,
}

impl RawRun {
    fn expect_code(&self, expected: i32) -> &Self {
        assert_eq!(
            self.code, expected,
            "envsync {:?} 应当以退出码 {expected} 结束，实际 {}\nstdout: {}\nstderr: {}",
            self.argv, self.code, self.stdout, self.stderr
        );
        self
    }

    fn assert_no_canary(&self, label: &str) -> &Self {
        for (channel, text) in [("stdout", &self.stdout), ("stderr", &self.stderr)] {
            assert!(
                !text.contains(CANARY),
                "{label}：canary 出现在真二进制的 {channel} 里\nargv: {:?}\n{text}",
                self.argv
            );
        }
        self
    }

    /// 输出里是否出现了某个稳定错误码（人类可读走 stderr，`--json` 走 stdout）。
    fn reports(&self, code: &str) -> bool {
        self.stdout.contains(code) || self.stderr.contains(code)
    }
}

/// 启动真二进制，往 stdin 里喂 `stdin`，捕获 stdout 与 stderr。
///
/// `-vvv` 把 tracing 级别顶到 trace 并写进 stderr——「日志开到最大也不漏」这条断言
/// 在真进程里就是靠它成立的。
fn run_binary_with_stdin(args: &[String], stdin: &[u8]) -> RawRun {
    let mut argv = args.to_vec();
    argv.push("-vvv".to_owned());
    let mut child = Command::new(envsync_binary())
        .args(&argv)
        .env(canary_env_var(), CANARY)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("应当能够启动 envsync 二进制");
    if let Some(mut pipe) = child.stdin.take() {
        // 子进程完全可能在读之前就退出（`--help`、参数错误、退出码 15），
        // 此时 `write_all` 得到的是 EPIPE——那是预期内的，不是测试失败。
        let _ = pipe.write_all(stdin);
    }
    let output = child.wait_with_output().expect("子进程应当能够结束");
    RawRun {
        code: output
            .status
            .code()
            .unwrap_or_else(|| panic!("envsync {argv:?} 应当正常退出而不是被信号终止")),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        argv,
    }
}

/// 本机是否有可用的系统凭据库。
///
/// 用真二进制探一次 `device list`——它是纯读命令，无论探测结果如何都不会在任何平台上
/// 留下任何凭据。CI 容器与无 DBus 会话的 Linux 上返回 `false`（退出码 15），
/// 开发者的 macOS / Windows 上返回 `true`。
///
/// 存在的理由：本套件必须在两种机器上都是**绿的**，而且在有真凭据库的机器上
/// **绝不能往用户的钥匙串里写东西**。
fn system_store_available(config: &str) -> bool {
    let run = run_binary_with_stdin(
        &[
            "device".to_owned(),
            "list".to_owned(),
            "--config".to_owned(),
            config.to_owned(),
            "--json".to_owned(),
        ],
        b"",
    );
    !(run.code == 15 && run.reports("platform.secure_store_unavailable"))
}

// ===========================================================================
// 攻击矩阵 1：后端读权限
// ===========================================================================

/// **攻击矩阵第 1 项：攻击者拿到整个后端目录的读权限。**
///
/// 断言三件事，缺一不可：
///
/// * 后端**每个文件的每个字节**上都找不到 Vault 的 canary 明文；
/// * Vault 秘密的逻辑标识（`ci/npm-token`）**能**找到——它是公开元数据；
/// * 普通（非秘密）资源的**内容**（[`PUBLIC_BODY`]）也**能**找到。
///
/// 后两条是这条测试的命门。只断言「找不到 canary」太容易蒙对——扫错了目录、扫了个空
/// 目录、needle 拼错，都会让它变绿。正向对照把「扫描确实看得见元数据、也确实看得见
/// 内容」钉死之后，第一条断言才有分量。
///
/// 第三条同时是 M2 威胁边界的如实陈述：**M2 只把 Vault 秘密封起来**。拿到后端读权限的
/// 人照样能逐字节读出你所有普通配置文件，只是读不到 Vault 里的东西。
///
/// 顺带把本机的 Vault 状态目录（草稿库缓存的就是后端对象）也扫一遍：那份缓存同样只该
/// 有密文。
#[test]
fn backend_leak_exposes_metadata_but_never_a_single_plaintext_byte() {
    let world = World::new();
    let alpha = world.primary("alpha");

    // 先用真二进制把一个**普通资源**同步上去：它在后端上是明文 Blob。
    alpha.publish_public_resource();

    alpha.device_init();
    alpha.vault_create();
    alpha.put_secret(SECRET, CANARY.as_bytes());

    // 再加一台设备、一份恢复包、一次撤销：让后端上出现全部五种对象（成员事件、信封、
    // 密封秘密、索引/恢复包、快照），而不是只扫一个 happy path。
    let beta = world.secondary(&alpha, "beta");
    alpha.invite_and_join(&beta, MemberRole::Member);
    device_admin::create_recovery(&mut alpha.service()).expect("生成恢复包");
    alpha.revoke(beta.device_id()).expect("撤销 beta");

    let backend_dir = world.backend_dir();
    let files = all_files(&backend_dir);
    assert!(
        files.len() >= 8,
        "后端上只有 {} 个文件，样本太小，扫描不足以说明问题",
        files.len()
    );

    // 反面：Vault 明文一个字节都不在。
    assert_absent_from_every_byte(&backend_dir, CANARY.as_bytes(), "后端全量扫描");

    // 正面对照之一：Vault 秘密的逻辑标识是公开元数据，必须找得到。
    let hit = assert_present_in_some_file(&backend_dir, SECRET.as_bytes(), "后端全量扫描");
    assert!(
        hit.starts_with(&backend_dir),
        "正向对照命中的文件应当在后端目录内：{}",
        hit.display()
    );

    // 正面对照之二，也是 M2 的边界本身：普通资源的**内容**在后端上明文可见。
    let public_hit =
        assert_present_in_some_file(&backend_dir, PUBLIC_BODY.as_bytes(), "普通资源内容");
    assert!(
        public_hit.starts_with(&backend_dir),
        "普通资源的明文必须在后端目录内：{}",
        public_hit.display()
    );
    // 而且是**整段逐字节**都在，不是碰巧撞上了某个前缀。
    let public_bytes = std::fs::read(&public_hit).expect("命中的对象文件可读");
    assert!(
        contains_bytes(&public_bytes, PUBLIC_BODY.as_bytes()),
        "普通资源的内容必须逐字节完整出现在 {}",
        public_hit.display()
    );
    // 反过来，装着 canary 的那个密封对象绝不是这一个。
    assert!(
        !contains_bytes(&public_bytes, CANARY.as_bytes()),
        "普通资源对象里不该有 Vault 的 canary"
    );

    // 本机缓存同样只有密文。
    assert_absent_from_every_byte(&alpha.vault_dir(), CANARY.as_bytes(), "本机草稿库扫描");

    // 而秘密确实是可读的——否则「后端没有明文」可以靠「根本没写进去」蒙混过关。
    assert_eq!(
        alpha.read_secret(SECRET).expect("alpha 应当读得到"),
        CANARY.as_bytes()
    );
}

// ===========================================================================
// 攻击矩阵 2：ciphertext 篡改
// ===========================================================================

/// **攻击矩阵第 2 项（第一种构造）：直接翻转密封对象文件里的一个字节。**
///
/// 内容寻址在 AEAD 之前就把它拦下了：后端重算摘要发现不符，直接拒绝返回内容。
/// 断言 `vault get` 失败、不产生输出文件、错误里没有 canary。
#[test]
fn flipping_one_ciphertext_byte_is_caught_by_content_addressing() {
    let world = World::new();
    let alpha = world.primary("alpha");
    alpha.device_init();
    alpha.vault_create();
    alpha.put_secret(SECRET, CANARY.as_bytes());

    // 用第二台设备当受害者：它的本地草稿库里还没有这个密封对象，因此一定会回后端读。
    let beta = world.secondary(&alpha, "beta");
    alpha.invite_and_join(&beta, MemberRole::Member);
    assert_eq!(
        beta.read_secret(SECRET).expect("篡改前 beta 读得到"),
        CANARY.as_bytes(),
        "篡改前必须能读通，否则后面的失败断言毫无意义"
    );
    // 上一步把对象缓存进了 beta 的草稿库；清掉它，让 beta 重新回后端读。
    std::fs::remove_dir_all(beta.vault_dir()).expect("应当能清空 beta 的本地缓存");

    let backend = world.backend();
    let workspace = alpha.workspace();
    let entry = head_index(&backend, workspace)
        .find(&secret_id(SECRET))
        .expect("索引里应当有这条秘密")
        .clone();
    let path = object_file(&world.backend_dir(), entry.object);
    let original = std::fs::read(&path).expect("应当能读密封对象");
    let mut tampered = original.clone();
    // 最后一个字节落在 AEAD tag 里；翻转它是最小的一次改动。
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    std::fs::write(&path, &tampered).expect("应当能写回密封对象");

    // 确认改动确实只有一个字节。
    assert_eq!(original.len(), tampered.len());
    assert_eq!(
        original
            .iter()
            .zip(tampered.iter())
            .filter(|(left, right)| left != right)
            .count(),
        1,
        "本次篡改必须精确到一个字节"
    );

    let out = beta.cli.home_path("stolen.txt");
    let channels = capture("vault.get", || beta.get_secret_to_file(SECRET, &out));
    channels.assert_no_canary("篡改密文后的 vault get");

    let envelope = channels.envelope();
    assert_eq!(envelope["status"], "error");
    assert_eq!(envelope["data"], Value::Null, "失败时 data 必须是 null");
    // 注意错误码是不带层前缀的 `corruption`：后端层的码没有 `backend.` 前缀，
    // 而其余每一层（`vault.` / `checkpoint.` / `membership.` / `platform.` /
    // `rotation.` / `crypto.`）都有。这条断言把当前契约钉住，见最终报告。
    assert_eq!(
        envelope["diagnostics"][0]["code"], "corruption",
        "整份信封：{}",
        channels.json
    );
    assert!(!out.exists(), "失败的 get 不得留下任何输出文件");

    // 直接调用一次核心层，把错误码钉死。
    expect_code(
        beta.read_secret(SECRET),
        "corruption",
        "翻转一个字节之后的读取",
    );
}

/// **攻击矩阵第 2 项（第二种构造）：篡改密文并把索引指过去，让摘要自洽。**
///
/// 这一次内容寻址帮不上忙——攻击者重算了对象标识、重写了索引、重发了头。挡住它的是
/// AEAD 认证本身，得到的是统一的「认证失败」，而且**一个明文字节都没有交出去**。
#[test]
fn a_consistent_forgery_is_caught_by_aead_authentication() {
    let world = World::new();
    let alpha = world.primary("alpha");
    alpha.device_init();
    alpha.vault_create();
    alpha.put_secret(SECRET, CANARY.as_bytes());

    let beta = world.secondary(&alpha, "beta");
    alpha.invite_and_join(&beta, MemberRole::Member);
    std::fs::remove_dir_all(beta.vault_dir()).expect("应当能清空 beta 的本地缓存");

    let backend = world.backend();
    let workspace = alpha.workspace();
    let mut index = head_index(&backend, workspace);
    let position = index
        .secrets
        .iter()
        .position(|entry| entry.id.as_str() == SECRET)
        .expect("索引里应当有这条秘密");

    // 攻击者：翻转密文的一个字节，重新计算对象标识，写成一个**自洽**的新对象。
    let original = backend
        .get_object(index.secrets[position].object)
        .expect("应当能读密封对象");
    let sealed = SealedSecret::from_canonical_slice(&original).expect("密封对象可解码");
    let mut ciphertext = sealed.ciphertext().to_vec();
    ciphertext[0] ^= 0x80;
    let forged = SealedSecret::from_parts_for_tests(sealed.header().clone(), ciphertext);
    let forged_bytes = forged.to_canonical_vec();
    let forged_id = ObjectId::for_bytes(ObjectKind::SealedSecret, &forged_bytes);
    backend
        .put_object(forged_id, &forged_bytes)
        .expect("应当能写伪造对象");
    index.secrets[position].object = forged_id;
    republish_head(&backend, workspace, alpha.device_id(), &index);

    // 伪造对象本身是「合法」的：内容寻址层放行了它。
    assert!(
        backend.get_object(forged_id).is_ok(),
        "伪造对象必须能通过摘要校验，否则这条测试测的还是内容寻址"
    );

    let out = beta.cli.home_path("stolen.txt");
    let channels = capture("vault.get", || beta.get_secret_to_file(SECRET, &out));
    channels.assert_no_canary("自洽伪造后的 vault get");

    let envelope = channels.envelope();
    assert_eq!(envelope["status"], "error");
    assert_eq!(envelope["data"], Value::Null);
    assert_eq!(
        envelope["diagnostics"][0]["code"], "crypto.failed",
        "整份信封：{}",
        channels.json
    );
    assert!(!out.exists(), "失败的 get 不得留下任何输出文件");

    let error = expect_code(beta.read_secret(SECRET), "crypto.failed", "自洽伪造");
    assert_eq!(
        error.to_string(),
        CryptoError::Authentication.to_string(),
        "必须是统一的认证失败，不能泄露是密文、tag 还是 AAD 出的问题"
    );
}

// ===========================================================================
// 攻击矩阵 3：替换 envelope
// ===========================================================================

/// **攻击矩阵第 3 项：把发给某台设备的信封替换成发给另一台设备的那一份。**
///
/// 两种替换法都要试：
///
/// * **粗暴替换**——索引里只留下 beta 的信封。gamma 找不到写着自己名字的信封，
///   得到 `vault.data_key_missing`；
/// * **精细替换**——伪造一份「收件人写 gamma、密文用 beta 那份」的信封。gamma 会真的
///   去解它，HPKE 的 `info` 绑定了收件设备，于是得到统一的**认证失败**。
///
/// 关键断言是「认证失败而不是 panic」：整个过程只经过返回 `Result` 的调用，一次 panic
/// 会让测试直接失败。
#[test]
fn substituting_another_devices_envelope_fails_authentication_without_panicking() {
    let world = World::new();
    let alpha = world.primary("alpha");
    alpha.device_init();
    alpha.vault_create();
    alpha.put_secret(SECRET, CANARY.as_bytes());

    let beta = world.secondary(&alpha, "beta");
    alpha.invite_and_join(&beta, MemberRole::Member);

    // gamma 被邀请但还没 join——join 正是需要打开信封的那一步。
    let gamma = world.secondary(&alpha, "gamma");
    let invitation = alpha.invite(&gamma, MemberRole::Member);

    let backend = world.backend();
    let workspace = alpha.workspace();
    let index = head_index(&backend, workspace);
    let epoch = KeyEpoch::new(index.epoch);

    // 找出 beta 与 gamma 各自的信封。
    let mut beta_envelope = None;
    let mut gamma_envelope = None;
    for id in &index.envelopes {
        let envelope =
            KeyEnvelope::from_canonical_slice(&backend.get_object(*id).expect("应当能读信封"))
                .expect("信封应当可解码");
        if envelope.recipient() == beta.device_id() {
            beta_envelope = Some(envelope);
        } else if envelope.recipient() == gamma.device_id() {
            gamma_envelope = Some(*id);
        }
    }
    let beta_envelope = beta_envelope.expect("beta 应当有一份信封");
    let gamma_envelope = gamma_envelope.expect("gamma 应当有一份信封");

    // --- 粗暴替换：索引里把 gamma 的信封换成 beta 的 ---------------------------
    let mut swapped = index.clone();
    swapped.envelopes.retain(|id| *id != gamma_envelope);
    republish_head(&backend, workspace, alpha.device_id(), &swapped);

    expect_code(
        vault_cli::device_join(&gamma.ctx(), &invitation),
        "vault.data_key_missing",
        "gamma 的信封被摘掉之后 join",
    );

    // --- 精细替换：收件人写 gamma，密文用 beta 的 -----------------------------
    let forged = KeyEnvelope::from_parts_for_tests(
        beta_envelope.version(),
        beta_envelope.suite(),
        beta_envelope.workspace(),
        gamma.device_id(),
        epoch,
        *beta_envelope.enc(),
        beta_envelope.ciphertext().to_vec(),
    );
    let forged_bytes = forged.to_canonical_vec();
    let forged_id = ObjectId::for_bytes(ObjectKind::KeyEnvelope, &forged_bytes);
    backend
        .put_object(forged_id, &forged_bytes)
        .expect("应当能写伪造信封");
    let mut spoofed = head_index(&backend, workspace);
    spoofed.envelopes.push(forged_id);
    republish_head(&backend, workspace, alpha.device_id(), &spoofed);

    let channels = capture("device.join", || {
        vault_cli::device_join(&gamma.ctx(), &invitation)
    });
    channels.assert_no_canary("信封被替换后的 device join");
    let error = expect_code(
        vault_cli::device_join(&gamma.ctx(), &invitation),
        "crypto.failed",
        "gamma 打开一份写着自己名字、内容却是 beta 的信封",
    );
    assert_eq!(
        error.to_string(),
        CryptoError::Authentication.to_string(),
        "必须是统一的认证失败"
    );

    // 失败没有留下半个身份：gamma 仍然拿不到任何数据密钥，也读不到任何秘密。
    expect_code(
        gamma.read_secret(SECRET),
        "vault.data_key_missing",
        "信封替换失败之后 gamma 读秘密",
    );
    // 而 beta 完全不受影响——攻击只砸了它自己想冒充的那台设备。
    assert_eq!(
        beta.read_secret(SECRET).expect("beta 仍然读得到"),
        CANARY.as_bytes()
    );
}

// ===========================================================================
// 攻击矩阵 4：撤销设备
// ===========================================================================

/// **攻击矩阵第 4 项：alpha 撤销 beta → 纪元 +1 → alpha 能读新秘密、beta 不能。**
///
/// 与计划文档措辞的一处**实际差异**（已在最终报告中记录）：计划设想「beta 仍能通过
/// `vault get` 读到撤销前的旧对象，直到 lazy rewrap 发生」。实现里 `device revoke` 的
/// 最后一个阶段会**主动**把全部旧纪元秘密重加密到新纪元并更新索引，因此撤销一结束，
/// 索引里就已经没有任何 beta 解得开的条目了。
///
/// 旧密封对象本身仍然躺在后端上（内容寻址、不可变），beta 手里也还留着旧纪元的密钥，
/// 所以它**仍然能解开那个旧对象**——撤销给的是前向保密，不是追溯保密。这一点这里
/// 逐字节断言出来，免得被「beta 读不到了」这句话糊过去。
#[test]
fn revocation_advances_the_epoch_and_locks_the_revoked_device_out() {
    let world = World::new();
    let alpha = world.primary("alpha");
    alpha.device_init();
    alpha.vault_create();
    alpha.put_secret(SECRET, CANARY.as_bytes());

    let beta = world.secondary(&alpha, "beta");
    alpha.invite_and_join(&beta, MemberRole::Member);
    assert_eq!(alpha.epoch(), 1);
    assert_eq!(
        beta.read_secret(SECRET).expect("撤销前 beta 读得到"),
        CANARY.as_bytes()
    );

    // 撤销前记下旧密封对象——撤销之后索引会指向新对象，但旧的还在后端上。
    let backend = world.backend();
    let workspace = alpha.workspace();
    let old_object = head_index(&backend, workspace)
        .find(&secret_id(SECRET))
        .expect("索引里应当有这条秘密")
        .object;

    // --- 撤销 -----------------------------------------------------------------
    let out = alpha.revoke(beta.device_id()).expect("撤销应当成功");
    let envelope = serde_json::from_str::<Value>(&output::json_line(
        "device.revoke",
        Status::Ok,
        JSON_SCHEMA_VERSION,
        Some(&out.data),
        &out.diagnostics,
        out.data.v2_only_fields(),
    ))
    .expect("JSON 可解析");
    assert_eq!(envelope["data"]["from_epoch"], 1);
    assert_eq!(envelope["data"]["to_epoch"], 2);
    assert_eq!(envelope["data"]["stage"], "complete");
    assert_eq!(envelope["data"]["envelopes"], 1, "新信封只发给剩下的 alpha");
    assert_eq!(envelope["data"]["resumed"], false);

    assert_eq!(alpha.epoch(), 2, "撤销必须把纪元推到 2");
    assert_eq!(
        alpha.service().membership().expect("成员状态").len(),
        1,
        "撤销之后只剩 alpha 一台设备"
    );

    // --- alpha 能读新秘密 -----------------------------------------------------
    alpha.put_secret(SECRET_AFTER_ROTATION, CANARY_AFTER_ROTATION.as_bytes());
    assert_eq!(
        alpha
            .read_secret(SECRET_AFTER_ROTATION)
            .expect("alpha 可读"),
        CANARY_AFTER_ROTATION.as_bytes()
    );
    assert_eq!(
        alpha.read_secret(SECRET).expect("alpha 仍读得到老秘密"),
        CANARY.as_bytes()
    );

    // --- beta 读不到新秘密，也写不了任何东西 -----------------------------------
    expect_code(
        beta.read_secret(SECRET_AFTER_ROTATION),
        "vault.data_key_missing",
        "被撤销的 beta 读新纪元秘密",
    );
    let mut beta_service = beta.service();
    expect_code(
        beta_service.set(&secret_id("ci/anything"), input(b"nope")),
        "vault.not_a_member",
        "被撤销的 beta 写秘密",
    );
    // 也拿不到新纪元的信封（新信封根本没发给它）。
    expect_code(
        beta.service().adopt_envelope(),
        "vault.data_key_missing",
        "被撤销的 beta 索要新纪元信封",
    );

    // --- 实际语义：索引已被主动重加密，但旧对象仍可被旧密钥解开 -----------------
    let rewrapped = head_index(&backend, workspace)
        .find(&secret_id(SECRET))
        .expect("索引里仍应有这条秘密")
        .clone();
    assert_eq!(rewrapped.epoch, 2, "revoke 的最后一步已经把旧秘密重加密了");
    assert_ne!(rewrapped.object, old_object);
    expect_code(
        beta.read_secret(SECRET),
        "vault.data_key_missing",
        "撤销之后 beta 通过索引读旧秘密",
    );

    // 但后端上那个旧对象还在，beta 手里的旧纪元密钥仍然能解开它。
    let old_bytes = backend.get_object(old_object).expect("旧对象仍在后端上");
    let old_sealed = SealedSecret::from_canonical_slice(&old_bytes).expect("可解码");
    let ring = beta.service().load_keyring().expect("beta 仍持有密钥环");
    let plaintext = envsync_crypto::sealed::open(
        ring.key(KeyEpoch::new(1)).expect("beta 仍有纪元 1 的密钥"),
        &old_sealed,
    )
    .expect("旧对象仍可被旧密钥解开");
    assert_eq!(
        plaintext.expose(),
        CANARY.as_bytes(),
        "撤销是前向保密，不是追溯保密：已经发出去的密文收不回来"
    );
}

// ===========================================================================
// 攻击矩阵 5：旧 head
// ===========================================================================

/// **攻击矩阵第 5 项：后端被整体回退到旧 revision / 旧 membership head / 旧 key epoch。**
///
/// 攻击构造是最彻底的一种：把整个后端目录换成撤销**之前**的一份副本，于是 revision、
/// 成员链头与密钥纪元三条线同时倒退。
///
/// 断言的是**实际行为**，与计划文档的措辞有出入（见最终报告）：
///
/// * 写路径确实会被拦下，错误是 `checkpoint.*` 系列且
///   [`CoreError::is_rollback_attack`] 为真（CLI 映射到退出码 14）；
/// * 但拦截发生在 **CAS 之后**，后端的 Ref 已经被推进了一格；
/// * 读路径（`vault get` / `vault list` / `device list`）**完全不查检查点**，会安静地
///   返回回滚后的旧状态；
/// * 本地文件（授权根 + 配置文件）逐字节零变更。
#[test]
fn rolling_the_backend_back_to_an_old_head() {
    let world = World::new();
    let alpha = world.primary("alpha");
    alpha.device_init();
    alpha.vault_create();
    alpha.put_secret(SECRET, CANARY.as_bytes());

    let beta = world.secondary(&alpha, "beta");
    alpha.invite_and_join(&beta, MemberRole::Member);

    // 攻击者在这一刻留下后端的完整副本。
    let backup = world.path().join("backend-before-revocation");
    copy_tree(&world.backend_dir(), &backup);
    let old = {
        let backend = world.backend();
        let reference = head_ref(&backend, alpha.workspace());
        let state = alpha.service().membership().expect("成员状态").clone();
        (reference.revision, state.sequence, state.epoch)
    };

    // 正常运转：撤销 beta，并写入一条只有新纪元才有的秘密。
    alpha.revoke(beta.device_id()).expect("撤销应当成功");
    alpha.put_secret(SECRET_AFTER_ROTATION, CANARY_AFTER_ROTATION.as_bytes());
    let new = {
        let backend = world.backend();
        let reference = head_ref(&backend, alpha.workspace());
        let state = alpha.service().membership().expect("成员状态").clone();
        (reference.revision, state.sequence, state.epoch)
    };
    assert!(new.0 > old.0 && new.1 > old.1 && new.2 > old.2);

    let checkpoint = alpha
        .service()
        .checkpoint()
        .expect("检查点可读")
        .expect("撤销之后必须有检查点");
    assert_eq!(checkpoint.revision, new.0);
    assert_eq!(checkpoint.key_epoch, new.2);

    // --- 攻击：把后端整体换回旧副本 -------------------------------------------
    let home_before = tree_fingerprint(alpha.cli.home());
    let config_before = std::fs::read(alpha.cli.config_path()).expect("配置可读");
    restore_tree(&backup, &world.backend_dir());
    assert_eq!(
        head_ref(&world.backend(), alpha.workspace()).revision,
        old.0,
        "后端确实被回退了"
    );

    // --- 读路径：**没有**被拦下（实现缺陷，见报告） ----------------------------
    let stale = alpha.service();
    assert_eq!(
        stale.membership().expect("成员状态").epoch,
        old.2,
        "回滚后的读路径直接采信了旧纪元"
    );
    assert!(
        stale
            .membership()
            .expect("成员状态")
            .contains(&beta.device_id()),
        "回滚后的读路径把已撤销的 beta 又当成了成员"
    );
    assert_eq!(
        alpha.read_secret(SECRET).expect("旧秘密仍可读"),
        CANARY.as_bytes()
    );
    // 新纪元里写的那条秘密凭空消失了，而且没有任何回滚告警。
    expect_code(
        alpha.read_secret(SECRET_AFTER_ROTATION),
        "vault.secret_not_found",
        "回滚之后读新纪元的秘密",
    );
    let listed = capture("vault.list", || vault_cli::vault_list(&alpha.ctx()));
    assert!(
        !listed.json.contains(SECRET_AFTER_ROTATION),
        "回滚后的 vault list 安静地少了一条秘密：{}",
        listed.json
    );

    // --- 写路径：被检查点拦下 -------------------------------------------------
    let mut service = alpha.service();
    let error = err(service.set(&secret_id("ci/after-rollback"), input(b"blocked")));
    assert!(
        error.is_rollback_attack(),
        "回滚必须被判定为攻击（CLI 退出码 14），实际错误码 `{}`：{error}",
        error.code()
    );
    assert!(
        error.code().starts_with("checkpoint."),
        "期望 checkpoint.* 错误码，实际 `{}`",
        error.code()
    );
    assert_eq!(error.code(), "checkpoint.revision_rollback");

    // --- 退出码必须是 14 -------------------------------------------------------
    //
    // 这里没法直接断言那个整数：`envsync_cli::cli::exit_code_for` 与常量
    // `EXIT_ROLLBACK_ATTACK` 都是私有项，而真二进制在本容器里**根本走不到这条路径**
    // ——Vault 的写入要先拿到系统凭据库，没有 DBus 会话时它停在退出码 15。
    //
    // 于是改为把 `exit_code_for` 的**判定链本身**钉死。那是一条 if / else if 链，
    // 顺序是：
    //
    //   1. is_cas_conflict          → 10
    //   2. is_stale_plan | PlanNotFound → 11
    //   3. is_policy_block          → 12
    //   4. is_conflicted            → 13
    //   5. is_rollback_attack       → 14   ← 这里
    //
    // 「前四个判定全假 + 第五个为真」与「这个错误映射到 14」是等价命题，后面的分支
    // 再也轮不到。因此下面六条断言合起来就是「退出码 14」，而且不依赖任何文本。
    assert!(!error.is_cas_conflict(), "不得先被 10 号分支截胡");
    assert!(!error.is_stale_plan(), "不得先被 11 号分支截胡");
    assert!(
        !matches!(error, CoreError::PlanNotFound(_)),
        "不得先被 11 号分支截胡"
    );
    assert!(!error.is_policy_block(), "不得先被 12 号分支截胡");
    assert!(!error.is_conflicted(), "不得先被 13 号分支截胡");
    assert!(
        error.is_rollback_attack(),
        "回滚必须命中 14 号分支，实际错误码 `{}`：{error}",
        error.code()
    );

    // 检查点自身没有被降下来。
    let after = alpha
        .service()
        .checkpoint()
        .expect("检查点可读")
        .expect("检查点仍在");
    assert_eq!(after.revision, checkpoint.revision);
    assert_eq!(after.key_epoch, checkpoint.key_epoch);
    assert_eq!(after.membership_sequence, checkpoint.membership_sequence);

    // 拦截发生在 CAS **之后**：后端的 Ref 已经被这次失败的写推进了一格。
    assert_eq!(
        head_ref(&world.backend(), alpha.workspace()).revision,
        old.0 + 1,
        "反回滚检查点在 CAS 之后才判定，被骗的客户端已经先改写了后端"
    );

    // --- 本地文件零变更 -------------------------------------------------------
    assert_eq!(
        tree_fingerprint(alpha.cli.home()),
        home_before,
        "整个回滚攻击期间授权根必须逐字节不变"
    );
    assert_eq!(
        std::fs::read(alpha.cli.config_path()).expect("配置可读"),
        config_before,
        "配置文件必须逐字节不变"
    );
}

// ===========================================================================
// 攻击矩阵 6：错误恢复口令
// ===========================================================================

/// **攻击矩阵第 6 项：`recovery restore` 用错误口令。**
///
/// 三个格式完全合法、只是内容不对的短语，外加一个「短语对但恢复包被换过」的场景，
/// 必须给出**逐字节相同**的错误：同一个错误码、同一句错误文本。攻击者从中区分不出
/// 「口令错了」还是「包被改了」，也区分不出自己猜的短语哪一位对了。
///
/// 非空转的保证：正确短语在同一个夹具上必须成功。
#[test]
fn every_wrong_recovery_phrase_yields_the_very_same_authentication_error() {
    let world = World::new();
    let alpha = world.primary("alpha");
    alpha.device_init();
    alpha.vault_create();
    alpha.put_secret(SECRET, CANARY.as_bytes());

    // 用核心层拿到那句正确短语：CLI 的 `recovery create` 只把它打到 stderr 一次，
    // 进程内拿不回来（这正是它的设计目的）。
    let mut outcome = device_admin::create_recovery(&mut alpha.service()).expect("生成恢复包");
    let correct = outcome.phrase.display_once().expect("短语只能展示一次");
    let correct = correct.to_string();
    assert!(!correct.is_empty());

    // 三句格式合法、内容不对的短语。
    let wrong: Vec<String> = (0..3)
        .map(|_| {
            let mut phrase = RecoveryPhrase::generate().expect("生成短语");
            phrase.display_once().expect("展示").to_string()
        })
        .collect();
    assert!(
        wrong.iter().all(|candidate| candidate != &correct),
        "随机生成的对照短语不该正好等于真短语"
    );

    let service = alpha.service();
    let mut seen: Vec<(String, String)> = Vec::new();
    for candidate in &wrong {
        let error = err(device_admin::restore_recovery(&service, candidate));
        seen.push((error.code().to_owned(), error.to_string()));
    }

    // 再加一条：短语正确、但安全存储里的恢复包被换成了另一个工作区的那一份。
    let other = World::new();
    let stranger = other.primary("stranger");
    stranger.device_init();
    stranger.vault_create();
    let mut foreign = device_admin::create_recovery(&mut stranger.service()).expect("生成恢复包");
    let _ = foreign.phrase.display_once().expect("展示");
    let foreign_package = stranger
        .secure
        .get(&recovery_identity_key(stranger.workspace()))
        .expect("可读")
        .expect("恢复包应当在安全存储里");
    alpha
        .secure
        .put(
            &recovery_identity_key(alpha.workspace()),
            foreign_package.expose(),
        )
        .expect("攻击者替换恢复包");
    let error = err(device_admin::restore_recovery(&service, &correct));
    seen.push((error.code().to_owned(), error.to_string()));

    // 全部四条路径的错误必须完全一样。
    let first = seen[0].clone();
    assert_eq!(first.0, "crypto.failed");
    assert_eq!(first.1, CryptoError::Authentication.to_string());
    for (code, message) in &seen {
        assert_eq!(
            (code.as_str(), message.as_str()),
            (first.0.as_str(), first.1.as_str()),
            "四条失败路径必须给出完全一致的错误，否则就是一个可用的 oracle：{seen:?}"
        );
        assert!(!message.contains(CANARY));
        assert!(!message.contains(&correct), "错误里绝不能回显任何短语");
    }
    for candidate in &wrong {
        assert!(
            !first.1.contains(candidate),
            "错误里绝不能回显用户输入的短语"
        );
    }

    // 失败没有副作用：密钥环没被覆盖，秘密照样读得到。
    assert_eq!(
        alpha.read_secret(SECRET).expect("失败的恢复不得破坏密钥环"),
        CANARY.as_bytes()
    );

    // 非空转对照：把真恢复包放回去，正确短语必须成功。
    let ring = service.load_keyring().expect("密钥环可读");
    let genuine = RecoveryPackage::create(
        &RecoveryPhrase::parse(&correct).expect("短语可解析"),
        Argon2Params::recommended(),
        &Plaintext::from_slice(&ring.to_secret_bytes()),
    )
    .expect("重新封装恢复包");
    alpha
        .secure
        .put(
            &recovery_identity_key(alpha.workspace()),
            &genuine.to_canonical_vec(),
        )
        .expect("放回真恢复包");
    let epochs =
        device_admin::restore_recovery(&alpha.service(), &correct).expect("正确短语必须成功");
    assert_eq!(epochs, vec![1]);
}

// ===========================================================================
// 攻击矩阵 7：进程中断轮换
// ===========================================================================

/// **攻击矩阵第 7 项：在轮换的每个阶段中断，下次启动幂等恢复。**
///
/// 「中断」用 [`VaultService::revoke_device_until`] 制造——它的文档写得很清楚：等价于
/// 「在进入这个阶段之前把进程杀掉」，journal 与后端留下的状态与真崩溃完全一致。之后
/// 丢掉服务实例（= 进程死掉），重新走一次 `device revoke`（= 用户重跑同一条命令）。
///
/// 每个阶段都断言：
///
/// * 恢复之后终态一致：纪元 2、阶段 `complete`、`resumed == true`；
/// * **新头绝不引用尚未发布的信封**——中断当时与恢复之后都逐个回后端确认头引用的每个
///   对象都在；
/// * 在信封发布之前中断时，后端上的纪元必须**仍然是 1**（新头压根没发出去）。
#[test]
fn interrupting_a_rotation_at_every_stage_recovers_idempotently() {
    for stop_before in [
        RotationStage::EnvelopesPublished,
        RotationStage::HeadPublished,
        RotationStage::Rewrapping,
        RotationStage::Complete,
    ] {
        let world = World::new();
        let alpha = world.primary("alpha");
        alpha.device_init();
        alpha.vault_create();
        alpha.put_secret(SECRET, CANARY.as_bytes());

        let beta = world.secondary(&alpha, "beta");
        alpha.invite_and_join(&beta, MemberRole::Member);
        let doomed = world.secondary(&alpha, "doomed");
        alpha.invite_and_join(&doomed, MemberRole::Member);

        let backend = world.backend();
        let workspace = alpha.workspace();
        let label = stop_before.as_str();

        // --- 中断 -------------------------------------------------------------
        {
            let mut service = alpha.service();
            let outcome = service
                .revoke_device_until(doomed.device_id(), Some(stop_before))
                .unwrap_or_else(|error| panic!("在 {label} 之前中断应当成功：{error}"));
            assert_ne!(
                outcome.stage,
                RotationStage::Complete,
                "{label}：这次调用不该跑完"
            );
            assert!(!outcome.resumed);
        }

        // 中断当时：头引用到的每个对象都必须已经在后端上。
        assert_head_references_only_published_objects(&backend, workspace);
        let published_epoch = head_index(&backend, workspace).epoch;
        if stop_before == RotationStage::EnvelopesPublished
            || stop_before == RotationStage::HeadPublished
        {
            assert_eq!(
                published_epoch, 1,
                "{label}：信封还没发布/新头还没发布时，后端纪元必须仍然是 1"
            );
        } else {
            assert_eq!(published_epoch, 2, "{label}：新头已经发布，纪元应当是 2");
        }
        // journal 记录的阶段就是我们停下的地方。
        let record = alpha
            .rotation_journal()
            .get(workspace)
            .expect("journal 可读")
            .expect("应当留有一条未完成记录");
        assert_ne!(record.stage, RotationStage::Complete, "{label}");

        // --- 进程重启后重跑同一条命令 ------------------------------------------
        let out = alpha
            .revoke(doomed.device_id())
            .unwrap_or_else(|error| panic!("{label}：恢复应当成功：{error}"));
        let envelope = serde_json::from_str::<Value>(&output::json_line(
            "device.revoke",
            Status::Ok,
            JSON_SCHEMA_VERSION,
            Some(&out.data),
            &out.diagnostics,
            out.data.v2_only_fields(),
        ))
        .expect("JSON 可解析");
        assert_eq!(envelope["data"]["stage"], "complete", "{label}");
        assert_eq!(envelope["data"]["to_epoch"], 2, "{label}");
        assert_eq!(
            envelope["data"]["resumed"], true,
            "{label}：必须是「接着做完」而不是「重新开始」"
        );
        assert!(
            out.diagnostics
                .iter()
                .any(|diagnostic| diagnostic.render().contains("rotation.resumed")),
            "{label}：恢复必须留下一条诊断"
        );

        // --- 终态与一次跑完完全一致 --------------------------------------------
        assert_eq!(alpha.epoch(), 2, "{label}");
        assert_head_references_only_published_objects(&backend, workspace);
        let final_index = head_index(&backend, workspace);
        assert_eq!(final_index.epoch, 2, "{label}");
        assert_eq!(
            final_index.envelopes.len(),
            2,
            "{label}：alpha 与 beta 各一份"
        );
        assert!(
            final_index.secrets.iter().all(|entry| entry.epoch == 2),
            "{label}：轮换完成后不该再有停留在旧纪元的秘密"
        );
        assert_eq!(
            alpha.read_secret(SECRET).expect("alpha 可读"),
            CANARY.as_bytes(),
            "{label}"
        );
        // 被撤销的设备读不到；剩下的成员在取回新信封之后照常工作。
        expect_code(
            doomed.read_secret(SECRET),
            "vault.data_key_missing",
            &format!("{label}：被撤销设备读秘密"),
        );
        beta.service()
            .adopt_envelope()
            .expect("beta 取回新纪元密钥");
        assert_eq!(
            beta.read_secret(SECRET).expect("beta 可读"),
            CANARY.as_bytes(),
            "{label}"
        );

        // 幂等：再跑一次不改变任何东西。
        let revision = head_ref(&backend, workspace).revision;
        expect_code(
            alpha.revoke(doomed.device_id()),
            "vault.not_a_member_device",
            &format!("{label}：重复撤销"),
        );
        assert_eq!(head_ref(&backend, workspace).revision, revision, "{label}");
    }
}

/// **攻击矩阵第 7 项（负面构造）：轮换 journal 撒谎，声称信封已发布。**
///
/// 直接改写本机 journal，把 `envelopes` 换成一个格式合法、后端上却根本不存在的对象
/// 标识。状态机必须**信后端不信 journal**：拒绝前进，并且后端上的头一动不动。
#[test]
fn a_lying_rotation_journal_can_never_publish_a_head() {
    let world = World::new();
    let alpha = world.primary("alpha");
    alpha.device_init();
    alpha.vault_create();
    alpha.put_secret(SECRET, CANARY.as_bytes());
    let doomed = world.secondary(&alpha, "doomed");
    alpha.invite_and_join(&doomed, MemberRole::Member);

    let backend = world.backend();
    let workspace = alpha.workspace();

    // 停在「信封已发布」这一步。
    {
        let mut service = alpha.service();
        service
            .revoke_device_until(doomed.device_id(), Some(RotationStage::HeadPublished))
            .expect("中断应当成功");
    }
    let before = head_ref(&backend, workspace);
    let epoch_before = head_index(&backend, workspace).epoch;

    // 攻击：把 journal 里的信封换成一个从未发布过的对象。
    let journal = alpha.rotation_journal();
    let mut record = journal
        .get(workspace)
        .expect("journal 可读")
        .expect("应当有未完成记录");
    assert_eq!(record.stage, RotationStage::EnvelopesPublished);
    let phantom = ObjectId::for_bytes(
        ObjectKind::KeyEnvelope,
        b"this envelope was never published",
    );
    assert!(
        !backend.has_object(phantom).expect("后端可查"),
        "构造出来的幻影对象不该真的存在"
    );
    record.envelopes = vec![phantom.to_string()];
    journal.upsert(&record).expect("应当能改写 journal");

    // 恢复必须中止，而不是硬着头皮发新头。
    expect_code(
        alpha.revoke(doomed.device_id()),
        "rotation.envelopes_missing",
        "journal 说信封发过了、后端说没有",
    );

    // 后端一个字节都没动。
    let after = head_ref(&backend, workspace);
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.head, before.head);
    assert_eq!(head_index(&backend, workspace).epoch, epoch_before);
    assert_head_references_only_published_objects(&backend, workspace);
}

// ===========================================================================
// 攻击矩阵 8：日志 canary
// ===========================================================================

/// **攻击矩阵第 8 项（进程侧）：真二进制的每一条子命令都不得回显 canary。**
///
/// canary 同时从两条入口进程：环境变量与 stdin。`-vvv` 把 tracing 顶到 trace 级并写进
/// stderr，因此这里捕获的 stdout + stderr 覆盖了进程的全部输出通道。
///
/// 在没有系统凭据库的机器（CI 容器、无 DBus 会话的 Linux）上，这些命令都会停在
/// `VaultContext::open`，以退出码 15 失败——这本身也是要验的性质：
/// **安全存储不可用时安全失败，绝不写明文 fallback。** 在开发者的 macOS / Windows 上
/// 凭据库是可用的，它们改为停在「本设备尚未注册身份」，同样必须干净地失败。
///
/// # 为什么名单里没有 `device init`
///
/// 它是这四组命令里**唯一**一条在拿到凭据库之后会立刻往里写东西的命令。在真凭据库
/// 可用的机器上跑它，等于往开发者的钥匙串里塞测试数据并留在那儿。因此它只在探测到
/// 「本机没有系统凭据库」时才进名单（那时它必然失败，什么也写不进去），
/// `device init` 的成功路径由进程内那条测试覆盖。
#[test]
fn the_real_binary_never_echoes_the_canary_on_any_subcommand() {
    let world = World::new();
    let alpha = world.primary("alpha");
    let config = alpha
        .cli
        .config_path()
        .to_str()
        .expect("路径是 UTF-8")
        .to_owned();
    let out_file = alpha
        .cli
        .home_path("out.bin")
        .to_str()
        .expect("路径是 UTF-8")
        .to_owned();
    let invitation = alpha
        .cli
        .home_path("invitation.bin")
        .to_str()
        .expect("路径是 UTF-8")
        .to_owned();
    std::fs::write(&invitation, b"not a real invitation").expect("应当能写文件");
    let store_available = system_store_available(&config);

    let device_public = "ab".repeat(64);
    let device_id = "cd".repeat(32);
    let mut subcommands: Vec<Vec<&str>> = vec![
        vec!["device", "list"],
        vec![
            "device",
            "invite",
            "--device-public",
            &device_public,
            "--output",
            &out_file,
        ],
        vec!["device", "join", "--invitation", &invitation],
        vec!["device", "revoke", "--device", &device_id],
        vec!["vault", "create"],
        vec!["vault", "set", SECRET],
        vec!["vault", "set", SECRET, "--from-env", CANARY_ENV],
        vec!["vault", "get", SECRET, "--output", &out_file],
        vec!["vault", "get", SECRET, "--output", "stdout"],
        vec![
            "vault",
            "get",
            SECRET,
            "--output",
            "stdout",
            "--allow-non-tty",
        ],
        vec!["vault", "list"],
        vec!["vault", "delete", SECRET],
        vec!["recovery", "create"],
        vec!["recovery", "restore"],
        vec!["security", "checkpoint"],
    ];
    if !store_available {
        subcommands.push(vec!["device", "init"]);
    }

    for subcommand in &subcommands {
        for json in [false, true] {
            let mut argv: Vec<String> = subcommand.iter().map(|item| (*item).to_owned()).collect();
            argv.extend(["--config".to_owned(), config.clone()]);
            if json {
                argv.push("--json".to_owned());
            }
            // canary 走 stdin（`vault set --stdin` 与 `recovery restore` 都从这里读）。
            let run = run_binary_with_stdin(&argv, CANARY.as_bytes());
            run.assert_no_canary("真二进制子命令");
            if store_available {
                // 有凭据库：命令改为停在「本设备尚未注册身份」，但仍然必须失败。
                assert_ne!(
                    run.code, 0,
                    "没有设备身份的工作区上这些命令不该成功\nargv: {:?}\nstdout: {}\nstderr: {}",
                    run.argv, run.stdout, run.stderr
                );
            } else {
                run.expect_code(15);
                assert!(
                    run.reports("platform.secure_store_unavailable"),
                    "安全存储不可用必须以稳定错误码上报\nargv: {:?}\nstdout: {}\nstderr: {}",
                    run.argv,
                    run.stdout,
                    run.stderr
                );
            }
            // 绝不写明文 fallback：失败的命令不得留下任何输出文件。
            assert!(
                !Path::new(&out_file).exists(),
                "失败的命令不得留下输出文件：{:?}",
                run.argv
            );
            // 也不得在本地状态目录里写下任何看起来像裸密钥的文件。
            assert!(
                !key_material_on_disk(alpha.cli.state_dir()),
                "失败的命令不得留下任何密钥文件：{:?}",
                run.argv
            );
        }
    }

    // 帮助文本也过一遍：它会被贴进 issue、CI 日志和文档。
    for group in ["device", "vault", "recovery", "security"] {
        let run =
            run_binary_with_stdin(&[group.to_owned(), "--help".to_owned()], CANARY.as_bytes());
        run.assert_no_canary("子命令帮助").expect_code(0);
    }
    // `vault set` 刻意没有 `--value`：命令行参数会进 shell history 与 `ps aux`。
    let help = run_binary_with_stdin(
        &["vault".to_owned(), "set".to_owned(), "--help".to_owned()],
        b"",
    );
    help.expect_code(0);
    assert!(
        !help.stdout.contains("--value"),
        "`vault set` 绝不能长出一个 `--value` 参数：\n{}",
        help.stdout
    );
}

/// **攻击矩阵第 8 项（完整流程）：canary 就在 Vault 里，真二进制跑完整条流程。**
///
/// 计划文档点名的流程是 `init` / `capture` / `plan` / `sync` / `status` /
/// `vault set` / `vault list` / `device list` / `security checkpoint`，这里一条不落。
/// 人类可读与 `--json` 各来一遍，`-vvv` 把 tracing 顶到 trace 级并写进 stderr，因此
/// 捕获的 stdout + stderr 覆盖了进程的全部输出通道。
///
/// 与上面那条测试的分工：那条把每个 M2 子命令**单独**打一遍，验的是「失败也不泄露」；
/// 这条验的是**成功路径**。`init` / `capture` / `plan` / `sync` / `status` 都**不需要**
/// 系统凭据库，因此在任何机器上都真正跑得通——而它们读写的正是那个后端：装着 canary
/// 的密封对象就躺在里面，`capture` 遍历后端对象、`plan` 算差异、`sync` 发布新快照、
/// `status` 把整个工作区状态打印出来。「成功路径也一个 canary 字节都不吐」这条性质，
/// 只有在这一层验得到。
///
/// 四条 M2 命令在没有凭据库的机器上停在退出码 15（成功路径由进程内那条测试覆盖）；
/// 无论停在哪一步，同样不得吐出 canary。
#[test]
fn the_real_binary_full_flow_never_surfaces_the_vault_canary() {
    let world = World::new();
    let alpha = world.primary("alpha");

    // canary 进 Vault。真二进制在本容器里拿不到系统凭据库，这一步只能进程内做；
    // 但它写进后端的密封对象是**真的**，下面真二进制读到的就是它。
    alpha.device_init();
    alpha.vault_create();
    alpha.put_secret(SECRET, CANARY.as_bytes());
    alpha.declare_public_resource();

    // 非空转前提：后端上确实有一个装着 canary 的密封对象，整条流程都在它上面跑。
    let backend = world.backend();
    let sealed = head_index(&backend, alpha.workspace())
        .find(&secret_id(SECRET))
        .expect("后端索引里必须有这条秘密")
        .object;
    assert!(
        backend.has_object(sealed).expect("后端可查"),
        "密封对象必须真的在后端上"
    );

    let config = alpha
        .cli
        .config_path()
        .to_str()
        .expect("路径是 UTF-8")
        .to_owned();
    let step = |args: &[&str], json: bool| -> RawRun {
        let mut argv: Vec<String> = args.iter().map(|item| (*item).to_owned()).collect();
        argv.extend(["--config".to_owned(), config.clone()]);
        if json {
            argv.push("--json".to_owned());
        }
        run_binary_with_stdin(&argv, CANARY.as_bytes())
    };

    // --- init -----------------------------------------------------------------
    // 各用一套全新的配置与后端：`init` 不能在同一个路径上跑第二次，而且这一步也不该
    // 去动上面那个已经装好 Vault 的世界。
    for (index, json) in [(0usize, false), (1usize, true)] {
        let fresh_config = world.path().join(format!("fresh-{index}/envsync.yaml"));
        let fresh_backend = world.path().join(format!("fresh-backend-{index}"));
        std::fs::create_dir_all(&fresh_backend).expect("应当能建后端目录");
        let mut argv = vec![
            "init".to_owned(),
            "--config".to_owned(),
            arg(&fresh_config),
            "--backend-path".to_owned(),
            arg(&fresh_backend),
            "--device-name".to_owned(),
            "fresh".to_owned(),
        ];
        if json {
            argv.push("--json".to_owned());
        }
        run_binary_with_stdin(&argv, CANARY.as_bytes())
            .expect_code(0)
            .assert_no_canary("init");
    }

    // --- capture / plan / sync / status：真正跑通的成功路径 ---------------------
    // 局部变量刻意不叫 `capture`：那会遮住本文件的通道捕获函数 [`capture`]。
    let captured = step(&["capture"], true);
    captured.expect_code(0).assert_no_canary("capture");
    let capture_json =
        serde_json::from_str::<Value>(&captured.stdout).expect("capture 的 stdout 是一行 JSON");
    assert_eq!(
        capture_json["data"]["changed"], true,
        "首次捕获必须产生新草稿，否则后面的 sync 是空转：{}",
        captured.stdout
    );

    let plan = step(&["plan"], true);
    plan.expect_code(0).assert_no_canary("plan");
    let plan_json =
        serde_json::from_str::<Value>(&plan.stdout).expect("plan 的 stdout 是一行 JSON");
    assert_eq!(plan_json["data"]["blocked"], false);
    // 非空转：这份计划必须真的会推进后端。
    //
    // 断言的是 revision 而不是 `action_count`：本机那个 `.gitconfig` 的内容与刚捕获的
    // 草稿完全一致，所以**本地**一个动作都不用做（`action_count == 0`），但这一趟仍然
    // 要把新快照发布上去。「会不会推进后端」才是这里要的性质。
    let base_revision = plan_json["data"]["base_revision"]
        .as_u64()
        .expect("base_revision 是整数");
    let next_revision = plan_json["data"]["next_revision"]
        .as_u64()
        .expect("next_revision 是整数");
    assert!(
        next_revision > base_revision,
        "计划必须会推进后端 revision：{}",
        plan.stdout
    );
    // Vault 的那几次发布就在同一条 Ref 上，因此基线 revision 必然已经被推过了。
    assert!(
        base_revision >= 1,
        "普通同步与 Vault 共用同一条 Ref，基线 revision 应当已经被 Vault 推进过：{}",
        plan.stdout
    );
    let plan_id = plan_json["data"]["plan"]
        .as_str()
        .expect("计划标识是字符串")
        .to_owned();

    let sync = step(&["sync", "--plan", &plan_id], true);
    sync.expect_code(0).assert_no_canary("sync");
    let sync_json =
        serde_json::from_str::<Value>(&sync.stdout).expect("sync 的 stdout 是一行 JSON");
    assert_eq!(sync_json["data"]["outcome"], "completed");
    assert_eq!(
        sync_json["data"]["published"], true,
        "同步必须真的向后端发布，否则这一整趟是空转：{}",
        sync.stdout
    );

    step(&["status"], true)
        .expect_code(0)
        .assert_no_canary("status");

    // 人类可读模式再走一遍（这三条都是可重复跑的读命令）。
    for args in [vec!["capture"], vec!["plan"], vec!["status"]] {
        step(&args, false)
            .expect_code(0)
            .assert_no_canary("人类可读流程");
    }

    // 非空转对照：这一整趟确实把普通资源的明文发布到了后端……
    assert_present_in_some_file(
        &world.backend_dir(),
        PUBLIC_BODY.as_bytes(),
        "完整流程之后的后端",
    );
    // ……而 canary 在整个后端上仍然一个字节都没有。
    assert_absent_from_every_byte(
        &world.backend_dir(),
        CANARY.as_bytes(),
        "完整流程之后的后端",
    );
    // 本机状态目录同样没有留下任何看起来像裸密钥的文件。
    assert!(
        !key_material_on_disk(alpha.cli.state_dir()),
        "完整流程不得在本地状态目录里留下密钥文件"
    );

    // --- 互操作：普通同步与 Vault 共用同一条 Ref ------------------------------
    //
    // `sync` 刚刚在这条 Ref 上发布了一个新快照。M0/M1 的发布路径与 Vault 的发布路径
    // 各自构造快照，于是问题来了：普通同步会不会把头快照上的 Vault 索引元数据顺手
    // 抹掉？
    //
    // 会。这是一个实现缺陷；按约定**不改实现**，测试钉住当前行为，详见最终报告与
    // 文件头「本套件钉住的当前行为」第 7 条。
    //
    // 成因：M0/M1 的发布路径自己构造头快照，`metadata` 只放 `device_name` / `format`，
    // 不会把上一个头的 `envsync.vault.index` 带过来。于是一次普通 `sync` 之后：
    //
    // * 头快照上的 Vault 索引指针没了；
    // * `vault get` 变成 `vault.secret_not_found`；
    // * `vault list` **照常成功**，只是报告一个空 Vault——没有任何错误或诊断。
    //
    // 数据本身没丢（密封对象是内容寻址的，还在后端上），丢的是那个指针。但从用户视角
    // 看，跑一条例行 `envsync sync` 会让整个 Vault 静默消失。
    let head_meta = head_snapshot(&backend, alpha.workspace()).metadata;
    assert!(
        !head_meta.contains_key(VAULT_INDEX_METADATA_KEY),
        "当前行为：普通同步会丢掉 Vault 索引元数据；实际 metadata = {:?}",
        head_meta.keys().collect::<Vec<_>>()
    );
    expect_code(
        alpha.read_secret(SECRET),
        "vault.secret_not_found",
        "普通同步抹掉 Vault 索引之后读秘密",
    );
    // 而 `vault list` 连一句警告都没有，只是报告一个空 Vault。
    let listed = capture("vault.list", || vault_cli::vault_list(&alpha.ctx()));
    assert_eq!(
        listed.envelope()["status"],
        "ok",
        "当前行为：Vault 被抹掉之后 list 仍然成功：{}",
        listed.json
    );
    assert_eq!(
        listed.envelope()["data"]["entries"],
        Value::Array(vec![]),
        "当前行为：list 报告一个空 Vault：{}",
        listed.json
    );
    assert_eq!(
        listed.envelope()["diagnostics"],
        Value::Array(vec![]),
        "当前行为：连一条诊断都没有——用户看不出 Vault 刚刚被自己的 sync 抹掉了：{}",
        listed.json
    );

    // 数据本身没有被销毁：那个密封对象还在后端上，而且仍然只有密文。
    assert!(
        backend.has_object(sealed).expect("后端可查"),
        "密封对象是内容寻址的，不该被这次同步删掉"
    );
    assert_absent_from_every_byte(
        &world.backend_dir(),
        CANARY.as_bytes(),
        "Vault 索引被抹掉之后的后端",
    );

    // --- 四条 M2 命令 ----------------------------------------------------------
    let store_available = system_store_available(&config);
    for args in [
        vec!["vault", "set", SECRET],
        vec!["vault", "list"],
        vec!["device", "list"],
        vec!["security", "checkpoint"],
    ] {
        for json in [false, true] {
            let run = step(&args, json);
            run.assert_no_canary("完整流程里的 M2 子命令");
            if store_available {
                // 有真凭据库的机器上，本设备身份是写在**内存**替身里的，系统凭据库里
                // 没有——命令改为停在「本设备尚未注册身份」，但仍然必须失败。
                assert_ne!(
                    run.code, 0,
                    "系统凭据库里没有本设备身份，这些命令不该成功\nargv: {:?}\nstdout: {}\nstderr: {}",
                    run.argv, run.stdout, run.stderr
                );
            } else {
                run.expect_code(15);
                assert!(
                    run.reports("platform.secure_store_unavailable"),
                    "安全存储不可用必须以稳定错误码上报\nargv: {:?}\nstdout: {}\nstderr: {}",
                    run.argv,
                    run.stdout,
                    run.stderr
                );
            }
        }
    }
}

/// **攻击矩阵第 8 项（进程内）：成功路径与失败路径的每一个通道都不得出现 canary。**
///
/// 真二进制在没有系统凭据库的机器上到不了成功路径，因此这一层用注入的内存安全存储把
/// `device` / `vault` / `recovery` / `security` 四组命令的成功与失败**全部跑通**，
/// 捕获 stdout / stderr / `--json` / tracing 四个通道。
#[test]
fn no_in_process_command_channel_ever_carries_the_canary() {
    let world = World::new();
    let alpha = world.primary("alpha");
    alpha.device_init();
    alpha.vault_create();

    // canary 从环境变量进 vault——走的是真正的 `vault set` 命令函数。
    let source = ValueSource::Env(canary_env_var().to_owned());
    let set = capture("vault.set", || {
        vault_cli::vault_set(&alpha.ctx(), SECRET, &source)
    });
    set.assert_no_canary("vault set 成功");
    assert!(
        set.json
            .contains(&format!("\"value_bytes\":{}", CANARY.len())),
        "长度是元数据，应当出现：{}",
        set.json
    );
    // 契约里只留下「来源类别」，连变量**名**都不回显——名字虽然不是秘密，
    // 但它常常泄露组织内部的命名习惯。
    assert!(
        set.json.contains("\"source\":\"env\""),
        "来源类别应当出现：{}",
        set.json
    );
    assert!(
        !set.json.contains(CANARY_ENV),
        "环境变量名也没有进入契约：{}",
        set.json
    );

    let beta = world.secondary(&alpha, "beta");
    beta.device_init();
    let invitation_file = world.path().join("beta.invitation");
    let beta_public = vault_cli::encode_public(&beta.device_public());
    let out_file = alpha.cli.home_path("token.out");

    // 成功路径。
    let successes: Vec<CommandCase<'_>> = vec![
        (
            "device.init",
            Box::new(|| vault_cli::device_init(&alpha.ctx())),
        ),
        (
            "device.list",
            Box::new(|| vault_cli::device_list(&alpha.ctx())),
        ),
        (
            "device.invite",
            Box::new(|| {
                vault_cli::device_invite(
                    &alpha.ctx(),
                    &beta_public,
                    MemberRole::Member,
                    &invitation_file,
                )
            }),
        ),
        (
            "device.join",
            Box::new(|| vault_cli::device_join(&beta.ctx(), &invitation_file)),
        ),
        (
            "vault.list",
            Box::new(|| vault_cli::vault_list(&alpha.ctx())),
        ),
        (
            "vault.get",
            Box::new(|| alpha.get_secret_to_file(SECRET, &out_file)),
        ),
        (
            "recovery.create",
            Box::new(|| vault_cli::recovery_create(&alpha.ctx())),
        ),
        (
            "security.checkpoint",
            Box::new(|| vault_cli::security_checkpoint(&alpha.ctx())),
        ),
        ("device.revoke", Box::new(|| alpha.revoke(beta.device_id()))),
        (
            "vault.delete",
            Box::new(|| vault_cli::vault_delete(&alpha.ctx(), SECRET)),
        ),
    ];
    for (command, run) in successes {
        let channels = capture(command, run);
        channels.assert_no_canary(&format!("{command} 成功"));
        assert_eq!(
            channels.envelope()["status"],
            "ok",
            "{command} 应当成功：{}",
            channels.json
        );
    }
    // `vault get` 的值确实到了文件里——否则这一整轮断言就只是在证明「什么都没发生」。
    assert_eq!(
        std::fs::read(&out_file).expect("输出文件可读"),
        CANARY.as_bytes()
    );

    // 失败路径。
    let missing = alpha.cli.home_path("never-written.out");
    let failures: Vec<CommandCase<'_>> = vec![
        (
            "vault.get",
            Box::new(|| alpha.get_secret_to_file("ci/does-not-exist", &missing)),
        ),
        (
            "vault.create",
            Box::new(|| vault_cli::vault_create(&alpha.ctx())),
        ),
        (
            "device.join",
            Box::new(|| vault_cli::device_join(&alpha.ctx(), &invitation_file)),
        ),
        ("device.revoke", Box::new(|| alpha.revoke(beta.device_id()))),
        (
            "recovery.restore",
            Box::new(|| {
                // `recovery_restore` 从进程 stdin 读，这里改用等价的核心层入口，
                // 断言的仍然是它渲染出来的那份错误。
                device_admin::restore_recovery(&alpha.service(), "wrong-phrase")
                    .map(|_| unreachable!("错误短语不可能成功"))
            }),
        ),
    ];
    for (command, run) in failures {
        let channels = capture(command, run);
        channels.assert_no_canary(&format!("{command} 失败"));
        let envelope = channels.envelope();
        assert_eq!(
            envelope["status"], "error",
            "{command} 应当失败：{}",
            channels.json
        );
        assert_eq!(envelope["data"], Value::Null);
        assert!(channels.stdout.is_empty(), "{command}：失败不得写 stdout");
    }
    assert!(!missing.exists(), "失败的 get 不得留下输出文件");
}

/// **攻击矩阵第 8 项的唯一例外：`vault get --output stdout --allow-non-tty`。**
///
/// 这条路径的存在意义就是把值交出去，因此断言的是「值确实一个字节不差地出来了，
/// 而且只从这一条路出来」。
#[test]
fn the_only_deliberate_outlet_is_vault_get_stdout() {
    let world = World::new();
    let alpha = world.primary("alpha");
    alpha.device_init();
    alpha.vault_create();
    alpha.put_secret(SECRET, CANARY.as_bytes());

    let channels = capture_with_stdout("vault.get", |stdout| {
        vault_cli::vault_get_with_writer(&alpha.ctx(), SECRET, &OutputTarget::Stdout, true, stdout)
    });

    // 值确实出来了，逐字节相同，没有多一个换行。
    assert_eq!(channels.raw_stdout, CANARY.as_bytes());
    // 其余每一个通道仍然干净。
    for (name, text) in [
        ("stdout", &channels.stdout),
        ("stderr", &channels.stderr),
        ("json", &channels.json),
        ("tracing", &channels.tracing),
    ] {
        assert!(
            !text.contains(CANARY),
            "值只能走原始 stdout，{name} 通道里不该有它：{text}"
        );
    }
    // `--output stdout` 时人类可读正文必须是空的，否则会污染那串字节。
    assert!(channels.stdout.is_empty());
    assert_eq!(channels.envelope()["data"]["output"], "stdout");
    assert_eq!(channels.envelope()["data"]["value_bytes"], CANARY.len());

    // 反面：没有 `--allow-non-tty` 且 stdout 不是终端时必须拒绝，且一个字节都不写。
    let refused = capture_with_stdout("vault.get", |stdout| {
        vault_cli::vault_get_with_writer(&alpha.ctx(), SECRET, &OutputTarget::Stdout, false, stdout)
    });
    refused.assert_no_canary("未授权的 stdout 输出");
    assert_eq!(
        refused.envelope()["diagnostics"][0]["code"],
        "vault.non_tty_output_refused"
    );
    assert!(refused.raw_stdout.is_empty());
}

// ===========================================================================
// 攻击矩阵 9：跨 workspace 重放
// ===========================================================================

/// **攻击矩阵第 9 项：把工作区 A 的成员事件 / 信封 / 密封对象 / 邀请塞进工作区 B。**
///
/// 四种对象各一段，全部必须被拒绝。其中「成员事件」一段记录的是**实际行为**，与
/// 直觉有出入：`reload` 并不校验成员链自身的 `workspace` 字段是否等于本地工作区，
/// 因此一条完整的外来链会被当成合法链读进来（详见最终报告）。真正把它挡住的是
/// 「本设备不在那条链上」这一层——所有写操作都被拒绝。
#[test]
fn cross_workspace_replay_of_every_object_kind_is_rejected() {
    // 工作区 A：受害者。
    let victim_world = World::new();
    let victim = victim_world.primary("victim");
    victim.device_init();
    victim.vault_create();
    victim.put_secret(SECRET, CANARY.as_bytes());

    // 工作区 B：攻击者控制的另一个工作区，秘密的逻辑标识刻意取成一样的。
    let other_world = World::new();
    let attacker = other_world.primary("attacker");
    attacker.device_init();
    attacker.vault_create();
    attacker.put_secret(SECRET, b"attacker-controlled-value");
    let accomplice = other_world.secondary(&attacker, "accomplice");
    attacker.invite_and_join(&accomplice, MemberRole::Member);

    let victim_backend = victim_world.backend();
    let victim_ws = victim.workspace();
    let attacker_backend = other_world.backend();
    let attacker_ws = attacker.workspace();
    let foreign_index = head_index(&attacker_backend, attacker_ws);

    // --- 1. 密封对象 -----------------------------------------------------------
    let foreign_sealed_id = foreign_index
        .find(&secret_id(SECRET))
        .expect("对方索引里有同名秘密")
        .object;
    let foreign_sealed_bytes = attacker_backend
        .get_object(foreign_sealed_id)
        .expect("可读对方对象");
    victim_backend
        .put_object(foreign_sealed_id, &foreign_sealed_bytes)
        .expect("攻击者把外来对象塞进受害者后端");
    let mut spliced = head_index(&victim_backend, victim_ws);
    let position = spliced
        .secrets
        .iter()
        .position(|entry| entry.id.as_str() == SECRET)
        .expect("受害者索引里有这条秘密");
    let genuine_sealed_id = spliced.secrets[position].object;
    spliced.secrets[position].object = foreign_sealed_id;
    republish_head(&victim_backend, victim_ws, victim.device_id(), &spliced);
    std::fs::remove_dir_all(victim.vault_dir()).expect("清掉本地缓存，强制回后端读");

    expect_code(
        victim.read_secret(SECRET),
        "vault.index_inconsistent",
        "跨工作区重放密封对象",
    );
    // 纵深防御：就算 header 检查不存在，AAD 也绑死了工作区，密钥根本解不开。
    let foreign_sealed = SealedSecret::from_canonical_slice(&foreign_sealed_bytes).expect("可解码");
    assert_eq!(foreign_sealed.workspace(), attacker_ws);
    let ring = victim.service().load_keyring().expect("密钥环可读");
    // 不能用 `expect_err`：它要求 `T: Debug`，而 `Plaintext` **刻意不实现** `Debug`。
    let error =
        match envsync_crypto::sealed::open(ring.current_key().expect("当前密钥"), &foreign_sealed)
        {
            Ok(_) => panic!("外来密文不可能被本工作区的密钥解开"),
            Err(error) => error,
        };
    assert_eq!(error.to_string(), CryptoError::Authentication.to_string());

    // 把索引指回受害者自己那个对象，后面几段各测各的。
    let mut repaired = head_index(&victim_backend, victim_ws);
    repaired.secrets[position].object = genuine_sealed_id;
    republish_head(&victim_backend, victim_ws, victim.device_id(), &repaired);
    assert_eq!(
        victim.read_secret(SECRET).expect("修好之后照常可读"),
        CANARY.as_bytes()
    );

    // --- 2. 信封 ---------------------------------------------------------------
    let foreign_envelope_id = *foreign_index
        .envelopes
        .first()
        .expect("对方索引里有信封对象");
    let foreign_envelope_bytes = attacker_backend
        .get_object(foreign_envelope_id)
        .expect("可读对方信封");
    victim_backend
        .put_object(foreign_envelope_id, &foreign_envelope_bytes)
        .expect("塞进受害者后端");
    let mut with_foreign_envelope = head_index(&victim_backend, victim_ws);
    with_foreign_envelope.envelopes = vec![foreign_envelope_id];
    republish_head(
        &victim_backend,
        victim_ws,
        victim.device_id(),
        &with_foreign_envelope,
    );

    // 受害者手里已经有密钥环，因此这里换一台**全新**设备来走 `adopt_envelope`。
    let newcomer = victim_world.secondary(&victim, "newcomer");
    newcomer.device_init();
    expect_code(
        newcomer.service().adopt_envelope(),
        "vault.data_key_missing",
        "跨工作区重放信封",
    );
    let foreign_envelope =
        KeyEnvelope::from_canonical_slice(&foreign_envelope_bytes).expect("可解码");
    assert_eq!(foreign_envelope.workspace(), attacker_ws);
    assert_ne!(foreign_envelope.recipient(), newcomer.device_id());

    // --- 3. 成员事件 -----------------------------------------------------------
    for id in &foreign_index.membership {
        let bytes = attacker_backend.get_object(*id).expect("可读对方成员事件");
        victim_backend
            .put_object(*id, &bytes)
            .expect("塞进受害者后端");
    }
    // 3a. 把外来事件**追加**到受害者自己的链后面：链校验必须拒绝。
    let mut appended = head_index(&victim_backend, victim_ws);
    appended.membership.extend(foreign_index.membership.clone());
    republish_head(&victim_backend, victim_ws, victim.device_id(), &appended);
    let error = err(victim.try_service());
    assert!(
        error.code().starts_with("membership."),
        "追加外来成员事件必须被链校验拒绝，实际错误码 `{}`：{error}",
        error.code()
    );
    assert_eq!(error.code(), "membership.workspace_mismatch");

    // 3b. 把整条链**整体换成**外来链：链本身自洽，于是被读了进来（实现缺陷，见报告），
    //     但本设备不在那条链上，任何写操作都被拒绝。
    let mut replaced = head_index(&victim_backend, victim_ws);
    replaced.membership = foreign_index.membership.clone();
    replaced.epoch = foreign_index.epoch;
    replaced.envelopes = foreign_index.envelopes.clone();
    replaced.secrets.clear();
    republish_head(&victim_backend, victim_ws, victim.device_id(), &replaced);

    let hijacked = victim.service();
    assert!(
        !hijacked
            .membership()
            .expect("成员状态")
            .contains(&victim.device_id()),
        "整条链被换掉之后，本设备当然不在成员里"
    );
    let mut hijacked = victim.service();
    expect_code(
        hijacked.set(&secret_id("ci/anything"), input(b"nope")),
        "vault.not_a_member",
        "外来成员链上写秘密",
    );
    expect_code(
        vault_cli::device_invite(
            &victim.ctx(),
            &vault_cli::encode_public(&newcomer.device_public()),
            MemberRole::Member,
            &victim_world.path().join("hijacked.invitation"),
        ),
        "vault.admin_required",
        "外来成员链上发邀请",
    );

    // --- 4. 邀请对象 -----------------------------------------------------------
    let stranger = victim_world.secondary(&victim, "stranger");
    let foreign_invitation = attacker.invite(&stranger, MemberRole::Member);
    expect_code(
        vault_cli::device_join(&stranger.ctx(), &foreign_invitation),
        "vault.invitation_invalid",
        "跨工作区重放邀请",
    );
}
