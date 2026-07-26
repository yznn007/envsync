//! `device` / `vault` / `recovery` / `security` 四组命令的实现与对外 JSON 形状。
//!
//! ## 秘密值只有一条出路
//!
//! 本模块产出的**所有** [`crate::commands::CommandData`] 都只含元数据：逻辑标识、纪元、
//! 时间戳、对象标识、字节长度。秘密值唯一能离开进程的方式是
//! [`vault_get`] 把它写进 `--output` 指定的文件，或者在显式的
//! `--output stdout --allow-non-tty`（或真 TTY 确认）下写进 stdout。
//!
//! 这条约束不是靠自觉维持的：`tests/vault_cli.rs` 会把一个 canary 灌进每一条成功与
//! 失败路径，捕获 stdout / stderr / tracing / JSON 四个通道，断言 canary 从不出现。
//!
//! ## 输入同样只有三条入口
//!
//! `vault set` **没有** `--value` 参数。值来自 `--stdin`（默认）、`--from-env <NAME>`
//! （读该环境变量，参数是**名**不是值），或交互式隐藏输入。命令行参数会进入 shell
//! history、`ps aux` 与 CI 日志，因此它不是一个可用的输入通道。
//!
//! ## 安全存储不可用时安全失败
//!
//! [`VaultContext::open`] 只认
//! [`envsync_platform::secure_store::open_system_store`]。拿不到系统凭据库时命令以
//! 退出码 15 失败，**绝不**写任何明文 fallback。测试注入入口
//! [`VaultContext::with_stores`] 挂在 `test-support` feature 下，生产构建里根本不存在。

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use zeroize::Zeroizing;

use envsync_core::checkpoint::{CheckpointStore, SecureCheckpointStore};
use envsync_core::device_admin::{self, DeviceInvitation, INVITATION_DEFAULT_TTL_MS};
use envsync_core::ports::{Clock, SystemClock};
use envsync_core::vault::{self, HiddenPrompt, SecretInput, VaultDeps, VaultError, VaultService};
use envsync_core::{CoreError, CoreResult, WorkspaceConfig};
use envsync_crypto::device::DevicePublic;
use envsync_crypto::sealed::SecretId;
use envsync_crypto::suite::{ED25519_PUBLIC_LEN, X25519_LEN};
use envsync_domain::cbor::CborCodec;
use envsync_domain::id::DeviceId;
use envsync_domain::membership::MemberRole;
use envsync_platform::secure_store::SecureStore;

use crate::commands::{CommandData, CommandOutput};
use crate::output::DiagnosticOut;

// ---------------------------------------------------------------------------
// 上下文
// ---------------------------------------------------------------------------

/// 一次 Vault 命令的执行环境。
///
/// 它持有「打开服务需要的一切」，但**不**持有服务本身：每条命令自己打开一个新的
/// [`VaultService`]，从后端重新读一遍状态。命令之间不共享缓存，因为两条命令之间别的
/// 设备可能已经改过后端了。
pub struct VaultContext {
    config: WorkspaceConfig,
    secure: Arc<dyn SecureStore>,
    checkpoints: Arc<dyn CheckpointStore>,
    clock: Arc<dyn Clock>,
}

impl VaultContext {
    /// 生产入口：读配置，打开**系统**安全存储。
    ///
    /// # 错误
    ///
    /// 系统凭据库不可用（不存在、被锁定、访问被拒绝）时返回对应的
    /// [`envsync_platform::PlatformError`]，CLI 把它映射成退出码 15。这里**没有**
    /// 任何回退分支：写明文密钥文件比读不到密钥危险得多。
    pub fn open(config_path: &Path) -> CoreResult<Self> {
        let config = WorkspaceConfig::load(config_path)?;
        let secure: Arc<dyn SecureStore> =
            Arc::from(envsync_platform::secure_store::open_system_store()?);
        let checkpoints: Arc<dyn CheckpointStore> =
            Arc::new(SecureCheckpointStore::new(Arc::clone(&secure)));
        Ok(VaultContext {
            config,
            secure,
            checkpoints,
            clock: Arc::new(SystemClock),
        })
    }

    /// 仅测试可用：注入自定义的安全存储与检查点存储。
    ///
    /// 挂在 `test-support` feature 下，因此**生产构建里这个函数不存在**——
    /// 「测试替身跑进生产二进制」是编译期不可能，而不是靠 review 拦住。
    #[cfg(feature = "test-support")]
    pub fn with_stores(
        config: WorkspaceConfig,
        secure: Arc<dyn SecureStore>,
        checkpoints: Arc<dyn CheckpointStore>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        VaultContext {
            config,
            secure,
            checkpoints,
            clock,
        }
    }

    /// 工作区配置。
    pub fn config(&self) -> &WorkspaceConfig {
        &self.config
    }

    /// 安全存储句柄。
    pub fn secure(&self) -> &dyn SecureStore {
        self.secure.as_ref()
    }

    /// 组装打开服务所需的依赖。
    pub fn deps(&self) -> CoreResult<VaultDeps> {
        Ok(VaultDeps {
            workspace: self.config.workspace_id,
            backend: vault::open_backend(&self.config.backend)?,
            secure: Arc::clone(&self.secure),
            checkpoints: Arc::clone(&self.checkpoints),
            clock: Arc::clone(&self.clock),
        })
    }

    /// 打开一个新的服务实例。
    ///
    /// 每条命令都自己开一个：两条命令之间别的设备可能已经改过后端了，缓存跨命令复用
    /// 只会让「我看到的」和「后端上的」悄悄分叉。
    pub fn service(&self) -> CoreResult<VaultService> {
        VaultService::open(self.deps()?, &self.config.vault_dir())
    }
}

// ---------------------------------------------------------------------------
// 输入来源
// ---------------------------------------------------------------------------

/// `vault set` 的取值来源。
///
/// 三个变体穷尽了允许的入口。**没有**「命令行直接给值」这一项，而且这个枚举里也没有
/// 任何地方能塞进一个 `String` 值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueSource {
    /// 从 stdin 读取（默认）。
    Stdin,
    /// 读取指定**名字**的环境变量。
    Env(String),
    /// 交互式隐藏输入。
    Prompt,
}

impl ValueSource {
    /// 稳定的机器可读名称，进入 JSON 契约。
    pub fn as_str(&self) -> &'static str {
        match self {
            ValueSource::Stdin => "stdin",
            ValueSource::Env(_) => "env",
            ValueSource::Prompt => "prompt",
        }
    }

    /// 按来源读取一次秘密值。
    fn read(&self) -> CoreResult<SecretInput> {
        match self {
            ValueSource::Stdin => SecretInput::from_stdin(),
            ValueSource::Env(name) => SecretInput::from_env_var(name),
            ValueSource::Prompt => {
                SecretInput::from_hidden_prompt(&mut TerminalHiddenPrompt, "请输入秘密值")
            }
        }
    }
}

/// 终端隐藏输入。
///
/// # 实现取舍
///
/// 关闭回显需要平台专用的 termios / Console API，而 EnvSync 刻意不为此引入一个终端库
/// （多一个依赖就多一份供应链风险，而这个功能只有一行用途）。因此 Unix 上借助
/// `stty -echo` 完成，其余平台**直接拒绝**并提示改用 `--stdin` / `--from-env`。
///
/// 拒绝而不是「退化成明文回显」：用户以为自己在隐藏输入、屏幕上却出现了口令，比明确
/// 报错糟糕得多。
pub struct TerminalHiddenPrompt;

impl HiddenPrompt for TerminalHiddenPrompt {
    fn read_hidden(&mut self, label: &str) -> CoreResult<Zeroizing<Vec<u8>>> {
        if !std::io::stdin().is_terminal() {
            return Err(VaultError::HiddenInputUnavailable.into());
        }
        let _guard = EchoGuard::disable()?;
        eprint!("{label}：");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        let read = std::io::stdin()
            .read_line(&mut line)
            .map_err(|error| envsync_platform::PlatformError::io("读取隐藏输入", &error));
        eprintln!();
        read?;
        let bytes = Zeroizing::new(line.trim_end_matches(['\r', '\n']).as_bytes().to_vec());
        // `line` 里还留着一份明文副本；`String` 不会自动清零，必须显式擦掉再放手。
        zeroize::Zeroize::zeroize(&mut line);
        Ok(bytes)
    }
}

/// 在作用域内关闭终端回显，`Drop` 时恢复。
///
/// `Drop` 而不是「读完手动恢复」：读取路径上任何一个 `?` 提前返回都必须让终端回到可用
/// 状态，否则用户会留下一个打字看不见的 shell。
struct EchoGuard;

impl EchoGuard {
    #[cfg(unix)]
    fn disable() -> CoreResult<Self> {
        stty(&["-echo"])?;
        Ok(EchoGuard)
    }

    #[cfg(not(unix))]
    fn disable() -> CoreResult<Self> {
        Err(VaultError::HiddenInputUnavailable.into())
    }
}

#[cfg(unix)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        // 恢复失败已经无处上报了；至少不要 panic 在 Drop 里。
        let _ = stty(&["echo"]);
    }
}

/// 调用 `stty`，把 stdin 原样传下去（它需要控制终端）。
#[cfg(unix)]
fn stty(args: &[&str]) -> CoreResult<()> {
    let status = std::process::Command::new("stty")
        .args(args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|_| CoreError::from(VaultError::HiddenInputUnavailable))?;
    if status.success() {
        Ok(())
    } else {
        Err(VaultError::HiddenInputUnavailable.into())
    }
}

// ---------------------------------------------------------------------------
// 输出目标
// ---------------------------------------------------------------------------

/// `vault get` 的输出目标。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputTarget {
    /// 写进一个文件。
    File(PathBuf),
    /// 写进 stdout。
    Stdout,
}

/// `--output` 中代表 stdout 的字面量。
pub const STDOUT_LITERAL: &str = "stdout";

impl OutputTarget {
    /// 由 `--output` 的取值解析。`stdout` 是保留字面量，其余一律当文件路径。
    pub fn parse(raw: &str) -> Self {
        if raw == STDOUT_LITERAL {
            OutputTarget::Stdout
        } else {
            OutputTarget::File(PathBuf::from(raw))
        }
    }

    /// 进入 JSON 契约的稳定描述。**不含**秘密值，文件目标只给文件名。
    fn describe(&self) -> String {
        match self {
            OutputTarget::Stdout => STDOUT_LITERAL.to_owned(),
            OutputTarget::File(path) => format!(
                "file:{}",
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "-".to_owned())
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// device
// ---------------------------------------------------------------------------

/// `device init` 的数据。
#[derive(Debug, Serialize)]
pub struct DeviceInitData {
    /// 工作区标识。
    pub workspace: String,
    /// 本设备标识。
    pub device: String,
    /// 本设备公开材料（128 位小写十六进制：X25519 公钥 || Ed25519 公钥）。
    ///
    /// 这是**公开**材料，交给管理员去 `device invite` 用。
    pub device_public: String,
    /// 本次是否新建了身份；已存在时为 `false`（不覆盖）。
    pub created: bool,
    /// 安全存储后端标识，例如 `macos-keychain`。
    pub store_backend: String,
}

impl DeviceInitData {
    fn render(&self) -> String {
        let head = if self.created {
            "已生成本设备身份"
        } else {
            "本设备已有身份，未做改动"
        };
        format!(
            "{head}\n  工作区：{}\n  设备：{}\n  安全存储：{}\n  公开材料（交给管理员执行 \
             `envsync device invite --device-public <...>`）：\n    {}",
            self.workspace, self.device, self.store_backend, self.device_public
        )
    }
}

/// 生成（或读回）本设备在该工作区的身份。
pub fn device_init(ctx: &VaultContext) -> CoreResult<CommandOutput> {
    let (keypair, created) = device_admin::init_device(ctx.secure(), ctx.config().workspace_id)?;
    Ok(CommandOutput::plain(CommandData::DeviceInit(
        DeviceInitData {
            workspace: ctx.config().workspace_id.to_string(),
            device: keypair.device_id().to_hex(),
            device_public: encode_public(&keypair.public()),
            created,
            store_backend: ctx.secure().describe().backend.to_owned(),
        },
    )))
}

/// 设备清单里的一行。
#[derive(Debug, Serialize)]
pub struct DeviceRowData {
    /// 设备标识。
    pub device: String,
    /// 角色：`admin` 或 `member`。
    pub role: &'static str,
    /// 加入时所在的成员链位置。
    pub added_at_sequence: u64,
    /// 是否为本机。
    pub is_self: bool,
    /// 是否持有当前纪元的数据密钥信封。
    pub has_current_envelope: bool,
}

/// `device list` 的数据。
#[derive(Debug, Serialize)]
pub struct DeviceListData {
    /// 工作区标识。
    pub workspace: String,
    /// 当前密钥纪元。
    pub key_epoch: u64,
    /// 已验证的成员链位置。
    pub membership_sequence: u64,
    /// 设备清单。
    pub devices: Vec<DeviceRowData>,
}

impl DeviceListData {
    fn render(&self) -> String {
        let mut text = format!(
            "工作区 {} 共有 {} 台设备（密钥纪元 {}，成员链 sequence {}）",
            self.workspace,
            self.devices.len(),
            self.key_epoch,
            self.membership_sequence
        );
        for device in &self.devices {
            text.push_str(&format!(
                "\n  {mark} {id}（{role}，加入于 sequence {seq}）{envelope}",
                mark = if device.is_self { "*" } else { "-" },
                id = device.device,
                role = device.role,
                seq = device.added_at_sequence,
                envelope = if device.has_current_envelope {
                    ""
                } else {
                    "  [!] 缺少当前纪元的信封"
                },
            ));
        }
        text
    }
}

/// 列出工作区当前的成员设备。
pub fn device_list(ctx: &VaultContext) -> CoreResult<CommandOutput> {
    let service = ctx.service()?;
    let state = service.membership()?;
    let devices = device_admin::list_devices(&service)?;
    Ok(CommandOutput::plain(CommandData::DeviceList(
        DeviceListData {
            workspace: ctx.config().workspace_id.to_string(),
            key_epoch: state.epoch,
            membership_sequence: state.sequence,
            devices: devices
                .iter()
                .map(|device| DeviceRowData {
                    device: device.device.to_hex(),
                    role: device.role.as_str(),
                    added_at_sequence: device.added_at_sequence,
                    is_self: device.is_self,
                    has_current_envelope: device.has_current_envelope,
                })
                .collect(),
        },
    )))
}

/// `device invite` 的数据。
#[derive(Debug, Serialize)]
pub struct DeviceInviteData {
    /// 工作区标识。
    pub workspace: String,
    /// 被邀请的设备。
    pub subject: String,
    /// 被授予的角色。
    pub role: &'static str,
    /// 过期时刻（Unix 毫秒）。
    pub expires_at_unix_ms: u64,
    /// 邀请文件路径（文件名部分）。
    pub invitation_file: String,
    /// 邀请对象标识。
    pub invitation: String,
}

impl DeviceInviteData {
    fn render(&self) -> String {
        format!(
            "已邀请设备 {subject}（{role}）\n  邀请文件：{file}\n  过期时刻：{expires} ms\n  \
             下一步：把该文件交给对方，在对方机器上运行 `envsync device join --invitation <文件>`。\n  \
             邀请里不含任何私有材料，可以走普通渠道传递。",
            subject = self.subject,
            role = self.role,
            file = self.invitation_file,
            expires = self.expires_at_unix_ms,
        )
    }
}

/// 邀请一台设备，并把邀请对象写进 `output` 指定的文件。
pub fn device_invite(
    ctx: &VaultContext,
    device_public: &str,
    role: MemberRole,
    output: &Path,
) -> CoreResult<CommandOutput> {
    let public = decode_public(device_public)?;
    let mut service = ctx.service()?;
    let invitation = device_admin::invite(&mut service, public, role, INVITATION_DEFAULT_TTL_MS)?;
    let bytes = invitation.to_canonical_vec();
    std::fs::write(output, &bytes)
        .map_err(|error| envsync_platform::PlatformError::io("写入邀请文件", &error))?;
    Ok(CommandOutput::plain(CommandData::DeviceInvite(
        DeviceInviteData {
            workspace: ctx.config().workspace_id.to_string(),
            subject: invitation.subject.to_hex(),
            role: invitation.role.as_str(),
            expires_at_unix_ms: invitation.expires_at_unix_ms,
            invitation_file: file_label(output),
            invitation: invitation.object_id().to_string(),
        },
    )))
}

/// `device join` 的数据。
#[derive(Debug, Serialize)]
pub struct DeviceJoinData {
    /// 工作区标识。
    pub workspace: String,
    /// 本设备标识。
    pub device: String,
    /// 加入时接受的后端 revision。
    pub revision: u64,
    /// 当前密钥纪元。
    pub key_epoch: u64,
    /// 工作区里已有的秘密条数。
    pub entry_count: usize,
}

impl DeviceJoinData {
    fn render(&self) -> String {
        format!(
            "已加入工作区 {workspace}\n  设备：{device}\n  已建立反回滚检查点：revision \
             {revision}，密钥纪元 {epoch}\n  可见秘密：{count} 条（用 `envsync vault list` 查看）",
            workspace = self.workspace,
            device = self.device,
            revision = self.revision,
            epoch = self.key_epoch,
            count = self.entry_count,
        )
    }
}

/// 用一份邀请加入工作区。
pub fn device_join(ctx: &VaultContext, invitation_path: &Path) -> CoreResult<CommandOutput> {
    let bytes = std::fs::read(invitation_path)
        .map_err(|error| envsync_platform::PlatformError::io("读取邀请文件", &error))?;
    let invitation = DeviceInvitation::from_canonical_slice(&bytes)?;
    let service = device_admin::join(ctx.deps()?, &ctx.config().vault_dir(), &invitation)?;
    let state = service.membership()?;
    Ok(CommandOutput::plain(CommandData::DeviceJoin(
        DeviceJoinData {
            workspace: ctx.config().workspace_id.to_string(),
            device: service.device_id().to_hex(),
            revision: service.head().revision,
            key_epoch: state.epoch,
            entry_count: service.index().secrets.len(),
        },
    )))
}

/// `device revoke` 的数据。
#[derive(Debug, Serialize)]
pub struct DeviceRevokeData {
    /// 工作区标识。
    pub workspace: String,
    /// 被撤销的设备。
    pub revoked: String,
    /// 轮换前的纪元。
    pub from_epoch: u64,
    /// 轮换后的纪元。
    pub to_epoch: u64,
    /// 轮换停下时的阶段；正常完成为 `complete`。
    pub stage: &'static str,
    /// 收到新信封的设备数量。
    pub envelopes: usize,
    /// 仍停留在旧纪元、等待 lazy rewrap 的秘密条数。
    ///
    /// 撤销**不**重加密旧对象：它们会在下一次被读到时用新纪元密钥重新密封。这个数字
    /// 因此是一份进度提示，不是待办事项——这些秘密现在就能正常读写。
    pub pending_rewrap: usize,
    /// 本次是否在恢复一次先前被中断的轮换。
    pub resumed: bool,
}

impl DeviceRevokeData {
    fn render(&self) -> String {
        let head = if self.resumed {
            "已恢复并完成先前被中断的密钥轮换"
        } else {
            "已撤销设备并轮换工作区密钥"
        };
        format!(
            "{head}\n  被撤销设备：{revoked}\n  密钥纪元：{from} → {to}\n  新信封：{envelopes} 份\n  \
             待 lazy rewrap：{pending} 条（读取时自动重加密，无需处理）\n  轮换阶段：{stage}",
            revoked = self.revoked,
            from = self.from_epoch,
            to = self.to_epoch,
            envelopes = self.envelopes,
            pending = self.pending_rewrap,
            stage = self.stage,
        )
    }
}

/// 撤销一台设备并轮换密钥。
pub fn device_revoke(ctx: &VaultContext, device: DeviceId) -> CoreResult<CommandOutput> {
    let mut service = ctx.service()?;
    let outcome = service.revoke_device(device)?;
    let mut diagnostics = Vec::new();
    if outcome.resumed {
        diagnostics.push(DiagnosticOut::info(
            "rotation.resumed",
            "本次命令接着完成了先前被中断的轮换，而不是重新开始。".to_owned(),
        ));
    }
    Ok(CommandOutput {
        data: CommandData::DeviceRevoke(DeviceRevokeData {
            workspace: ctx.config().workspace_id.to_string(),
            revoked: outcome.revoked.to_hex(),
            from_epoch: outcome.from_epoch,
            to_epoch: outcome.to_epoch,
            stage: outcome.stage.as_str(),
            envelopes: outcome.envelopes,
            pending_rewrap: outcome.pending_rewrap,
            resumed: outcome.resumed,
        }),
        diagnostics,
    })
}

// ---------------------------------------------------------------------------
// vault
// ---------------------------------------------------------------------------

/// `vault create` 的数据。
#[derive(Debug, Serialize)]
pub struct VaultCreateData {
    /// 工作区标识。
    pub workspace: String,
    /// 创建者设备（唯一管理员）。
    pub device: String,
    /// 初始密钥纪元。
    pub key_epoch: u64,
}

impl VaultCreateData {
    fn render(&self) -> String {
        format!(
            "已创建 Vault\n  工作区：{}\n  管理员设备：{}\n  密钥纪元：{}\n  \
             下一步：`envsync recovery create` 生成恢复短语并抄写保存。",
            self.workspace, self.device, self.key_epoch
        )
    }
}

/// 建立工作区数据密钥与 genesis 成员事件。
pub fn vault_create(ctx: &VaultContext) -> CoreResult<CommandOutput> {
    let mut service = ctx.service()?;
    service.create()?;
    Ok(CommandOutput {
        data: CommandData::VaultCreate(VaultCreateData {
            workspace: ctx.config().workspace_id.to_string(),
            device: service.device_id().to_hex(),
            key_epoch: service.membership()?.epoch,
        }),
        diagnostics: vec![DiagnosticOut::warning(
            "vault.no_recovery_yet",
            "还没有恢复短语：这台设备一旦丢失，工作区内容将无法恢复。请尽快运行 \
             `envsync recovery create`。"
                .to_owned(),
        )],
    })
}

/// `vault set` 的数据。
///
/// **没有值**：只有逻辑标识、来源、纪元和字节长度。长度是元数据，不是秘密。
#[derive(Debug, Serialize)]
pub struct VaultSetData {
    /// 逻辑标识。
    pub id: String,
    /// 取值来源：`stdin` / `env` / `prompt`。
    pub source: &'static str,
    /// 写入时使用的密钥纪元。
    pub key_epoch: u64,
    /// 值的字节长度。
    pub value_bytes: usize,
}

impl VaultSetData {
    fn render(&self) -> String {
        format!(
            "已写入 {id}\n  来源：{source}\n  密钥纪元：{epoch}\n  长度：{bytes} 字节",
            id = self.id,
            source = self.source,
            epoch = self.key_epoch,
            bytes = self.value_bytes,
        )
    }
}

/// 写入一条秘密。
pub fn vault_set(ctx: &VaultContext, id: &str, source: &ValueSource) -> CoreResult<CommandOutput> {
    let id = SecretId::parse(id)?;
    // 先读值再打开服务？不：**先打开服务**。安全存储不可用时应当在读取秘密之前就失败，
    // 免得把一份明文读进内存却无处安放。
    let mut service = ctx.service()?;
    let input = source.read()?;
    let value_bytes = input.len();
    service.set(&id, input)?;
    Ok(CommandOutput::plain(CommandData::VaultSet(VaultSetData {
        id: id.as_str().to_owned(),
        source: source.as_str(),
        key_epoch: service
            .index()
            .find(&id)
            .map(|entry| entry.epoch)
            .unwrap_or_default(),
        value_bytes,
    })))
}

/// `vault get` 的数据。
///
/// **没有值**：值走的是 `--output`，不是 JSON 契约。
#[derive(Debug, Serialize)]
pub struct VaultGetData {
    /// 逻辑标识。
    pub id: String,
    /// 该对象的密钥纪元。
    pub key_epoch: u64,
    /// 输出去向：`stdout` 或 `file:<文件名>`。
    pub output: String,
    /// 值的字节长度。
    pub value_bytes: usize,
}

impl VaultGetData {
    fn render(&self) -> String {
        if self.output == STDOUT_LITERAL {
            // 值已经原样写进 stdout 了；这里再打印任何东西都会污染它。
            String::new()
        } else {
            format!(
                "已读取 {id}\n  写入：{output}\n  密钥纪元：{epoch}\n  长度：{bytes} 字节",
                id = self.id,
                output = self.output,
                epoch = self.key_epoch,
                bytes = self.value_bytes,
            )
        }
    }
}

/// 读取一条秘密并写到指定去向。
///
/// `--output stdout` 需要 stdout 是终端，或者显式的 `--allow-non-tty`。理由：管道与
/// 重定向的另一头很可能是日志、CI 产物或者某个人的剪贴板历史，而那是秘密最常见的
/// 泄露方式。
pub fn vault_get(
    ctx: &VaultContext,
    id: &str,
    output: &OutputTarget,
    allow_non_tty: bool,
) -> CoreResult<CommandOutput> {
    let mut stdout = std::io::stdout().lock();
    vault_get_with_writer(ctx, id, output, allow_non_tty, &mut stdout)
}

/// 同 [`vault_get`]，但把「stdout」这条出路显式参数化。
///
/// 存在的理由只有一个：脱敏 golden 测试必须能拿到**真正写出去的那串字节**，才能证明
/// 「秘密只从这一条路出去」。把 stdout 藏在函数内部的话，那条断言就只能靠子进程，
/// 而子进程里没法注入内存安全存储。
pub fn vault_get_with_writer(
    ctx: &VaultContext,
    id: &str,
    output: &OutputTarget,
    allow_non_tty: bool,
    stdout: &mut dyn Write,
) -> CoreResult<CommandOutput> {
    let id = SecretId::parse(id)?;
    let service = ctx.service()?;
    if matches!(output, OutputTarget::Stdout) && !allow_non_tty && !std::io::stdout().is_terminal()
    {
        return Err(VaultError::NonTtyOutputRefused.into());
    }
    let epoch = service
        .index()
        .find(&id)
        .map(|entry| entry.epoch)
        .unwrap_or_default();
    let plaintext = service.get(&id)?;
    let value_bytes = plaintext.len();

    match output {
        OutputTarget::Stdout => stdout
            .write_all(plaintext.expose())
            .and_then(|()| stdout.flush())
            .map_err(|error| envsync_platform::PlatformError::io("写入 stdout", &error))?,
        OutputTarget::File(path) => write_secret_file(path, plaintext.expose())?,
    }
    Ok(CommandOutput::plain(CommandData::VaultGet(VaultGetData {
        id: id.as_str().to_owned(),
        key_epoch: epoch,
        output: output.describe(),
        value_bytes,
    })))
}

/// 把秘密写进文件，并尽力收紧权限。
///
/// Unix 上先以 `0600` 创建再写入——先创建后 `chmod` 会留下一个短暂的窗口，那段时间里
/// 文件是 `0644`，同机的其他用户读得到。
fn write_secret_file(path: &Path, bytes: &[u8]) -> CoreResult<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| envsync_platform::PlatformError::io("创建输出文件", &error))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| envsync_platform::PlatformError::io("写入输出文件", &error))?;
    Ok(())
}

/// 清单里的一行。
///
/// 字段名刻意避开 `secret` / `token` 一类词根：[`crate::output::redact_json`] 按键名
/// 工作，叫 `secrets` 会让整棵子树被替换成 `<redacted>`，清单就没法看了。
#[derive(Debug, Serialize)]
pub struct VaultEntryData {
    /// 逻辑标识。
    pub id: String,
    /// 该对象的密钥纪元。
    pub key_epoch: u64,
    /// 最近一次写入时刻（Unix 毫秒）。
    pub updated_at_unix_ms: u64,
    /// 引用它的资源。
    pub referenced_by: Vec<String>,
}

/// `vault list` 的数据。
#[derive(Debug, Serialize)]
pub struct VaultListData {
    /// 工作区标识。
    pub workspace: String,
    /// 当前密钥纪元。
    pub key_epoch: u64,
    /// 条目清单（**只有元数据**）。
    pub entries: Vec<VaultEntryData>,
    /// 头快照上的 Vault 索引指针是否不见了。
    ///
    /// 为 `true` 时 `entries` 一定是空的，但那是「读不到」而不是「没有」。见
    /// [`envsync_core::vault::VaultService::vault_index_missing`]。
    pub index_missing: bool,
}

impl VaultListData {
    fn render(&self) -> String {
        if self.index_missing {
            return format!(
                "工作区 {} 的头快照上**没有** Vault 索引指针，但本机确实加入过这个 Vault。\n  \
                 这不是「Vault 是空的」——是那个指针不见了。密封对象本身是内容寻址的，\
                 多半仍在后端上。\n  \
                 请先用 `envsync security checkpoint` 确认信任根，再从另一台仍然正常的设备\
                 重新发布一次 Vault（任意一条 `vault set` / `vault delete` 都会重建指针）。",
                self.workspace
            );
        }
        if self.entries.is_empty() {
            return format!("工作区 {} 里还没有任何秘密。", self.workspace);
        }
        let mut text = format!(
            "工作区 {} 共有 {} 条秘密（当前密钥纪元 {}）",
            self.workspace,
            self.entries.len(),
            self.key_epoch
        );
        for entry in &self.entries {
            text.push_str(&format!(
                "\n  - {id}  纪元 {epoch}  更新于 {at} ms{refs}",
                id = entry.id,
                epoch = entry.key_epoch,
                at = entry.updated_at_unix_ms,
                refs = if entry.referenced_by.is_empty() {
                    String::new()
                } else {
                    format!("  被引用：{}", entry.referenced_by.join("、"))
                },
            ));
        }
        text
    }
}

/// 列出全部秘密的元数据。
///
/// # 「空 Vault」与「Vault 不见了」必须区分开
///
/// 头快照上的 Vault 索引指针一旦丢失（历史上一次普通 `envsync sync` 就会造成，见
/// [`envsync_core::vault::WORKSPACE_METADATA_PREFIX`]；后端也可以单独把它拿掉），本命令
/// 读到的就是一个空索引。安静地返回 `status: ok` + 空清单是最坏的做法：用户会以为自己
/// 的秘密从来没写进去过。
///
/// 因此这里加一条 `blocking` 级诊断 `vault.index_missing`——本机的密钥环或反回滚检查点
/// 证明这台设备**确实加入过**这个 Vault，那么「一条秘密都没有」就不是一个可信的答案。
pub fn vault_list(ctx: &VaultContext) -> CoreResult<CommandOutput> {
    let service = ctx.service()?;
    let entries = service.list()?;
    let index_missing = service.vault_index_missing()?;
    let mut diagnostics = Vec::new();
    if index_missing {
        diagnostics.push(DiagnosticOut::blocking(
            "vault.index_missing",
            "当前头快照上没有 Vault 索引指针，但本机确实加入过这个 Vault：这是「读不到」\
             而不是「里面是空的」。请勿据此认为秘密已丢失——密封对象是内容寻址的，多半\
             仍在后端上。从另一台正常设备重新发布一次 Vault 即可重建指针。"
                .to_owned(),
        ));
    }
    Ok(CommandOutput {
        data: CommandData::VaultList(VaultListData {
            workspace: ctx.config().workspace_id.to_string(),
            key_epoch: service.index().epoch,
            entries: entries
                .iter()
                .map(|entry| VaultEntryData {
                    id: entry.id.as_str().to_owned(),
                    key_epoch: entry.epoch,
                    updated_at_unix_ms: entry.updated_at_unix_ms,
                    referenced_by: entry
                        .referenced_by
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
                })
                .collect(),
            index_missing,
        }),
        diagnostics,
    })
}

/// `vault delete` 的数据。
#[derive(Debug, Serialize)]
pub struct VaultDeleteData {
    /// 逻辑标识。
    pub id: String,
    /// 是否真的删掉了东西；本来就不存在时为 `false`。
    pub deleted: bool,
}

impl VaultDeleteData {
    fn render(&self) -> String {
        if self.deleted {
            format!(
                "已从索引中删除 {}\n  注意：后端上的密封对象是不可变的，删除只是取消引用；\
                 已经拿到旧快照的设备仍然能读到它。",
                self.id
            )
        } else {
            format!("{} 本来就不存在，未做改动。", self.id)
        }
    }
}

/// 删除一条秘密。
pub fn vault_delete(ctx: &VaultContext, id: &str) -> CoreResult<CommandOutput> {
    let id = SecretId::parse(id)?;
    let mut service = ctx.service()?;
    let deleted = service.delete(&id)?;
    Ok(CommandOutput::plain(CommandData::VaultDelete(
        VaultDeleteData {
            id: id.as_str().to_owned(),
            deleted,
        },
    )))
}

// ---------------------------------------------------------------------------
// recovery
// ---------------------------------------------------------------------------

/// `recovery create` 的数据。
///
/// **恢复短语不在这里**，也永远不会进 JSON：它只被写到 stderr 一次，见
/// [`recovery_create`]。
#[derive(Debug, Serialize)]
pub struct RecoveryCreateData {
    /// 工作区标识。
    pub workspace: String,
    /// 恢复包对象标识。
    pub package: String,
    /// 恢复包覆盖的密钥纪元。
    pub epochs: Vec<u64>,
}

impl RecoveryCreateData {
    fn render(&self) -> String {
        format!(
            "已生成恢复包\n  工作区：{}\n  恢复包对象：{}\n  覆盖纪元：{:?}\n  \
             恢复短语已在上方显示，且**只显示这一次**。",
            self.workspace, self.package, self.epochs
        )
    }
}

/// 生成恢复短语与恢复包。
///
/// 短语走 **stderr**，不走 stdout 也不进 JSON：`--json` 的契约是 stdout 只有一行 JSON，
/// 而把一句「请抄写下来」的提示塞进机器可读输出既没用又危险（它会被日志收走）。
pub fn recovery_create(ctx: &VaultContext) -> CoreResult<CommandOutput> {
    let mut service = ctx.service()?;
    let mut outcome = device_admin::create_recovery(&mut service)?;
    let phrase = outcome.phrase.display_once()?;

    eprintln!("──────────────────────────────────────────────────────────");
    eprintln!("恢复短语（只显示这一次，请立刻抄写到离线的安全位置）：");
    eprintln!();
    eprintln!("    {}", phrase.as_str());
    eprintln!();
    eprintln!("* 抄完请核对一遍；短语带校验位，抄错会在恢复时被发现。");
    eprintln!("* 不要截图、不要存进密码管理器以外的任何地方、不要发消息给自己。");
    eprintln!("* 持有它的人可以解开本工作区的全部秘密。");
    eprintln!("──────────────────────────────────────────────────────────");
    drop(phrase);

    Ok(CommandOutput::plain(CommandData::RecoveryCreate(
        RecoveryCreateData {
            workspace: ctx.config().workspace_id.to_string(),
            package: outcome.package.to_string(),
            epochs: outcome.epochs,
        },
    )))
}

/// `recovery restore` 的数据。
#[derive(Debug, Serialize)]
pub struct RecoveryRestoreData {
    /// 工作区标识。
    pub workspace: String,
    /// 已恢复的密钥纪元。
    pub epochs: Vec<u64>,
}

impl RecoveryRestoreData {
    fn render(&self) -> String {
        format!(
            "已用恢复短语还原工作区密钥环\n  工作区：{}\n  恢复纪元：{:?}",
            self.workspace, self.epochs
        )
    }
}

/// 用恢复短语还原密钥环。短语从 stdin 读入，绝不作为命令行参数。
pub fn recovery_restore(ctx: &VaultContext) -> CoreResult<CommandOutput> {
    let service = ctx.service()?;
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .map_err(|error| envsync_platform::PlatformError::io("读取恢复短语", &error))?;
    let phrase = Zeroizing::new(raw);
    let epochs = device_admin::restore_recovery(&service, phrase.trim())?;
    Ok(CommandOutput::plain(CommandData::RecoveryRestore(
        RecoveryRestoreData {
            workspace: ctx.config().workspace_id.to_string(),
            epochs,
        },
    )))
}

// ---------------------------------------------------------------------------
// security
// ---------------------------------------------------------------------------

/// `security checkpoint` 的数据。
#[derive(Debug, Serialize)]
pub struct SecurityCheckpointData {
    /// 工作区标识。
    pub workspace: String,
    /// 是否已经建立信任根。
    pub established: bool,
    /// 已接受的最高后端 revision。
    pub revision: u64,
    /// 该 revision 对应的快照。
    pub snapshot: Option<String>,
    /// 已验证的成员链头摘要。
    pub membership_digest: Option<String>,
    /// 该链头所在的 sequence。
    pub membership_sequence: u64,
    /// 已知的最高密钥纪元。
    pub key_epoch: u64,
    /// 本机更新检查点的时刻（Unix 毫秒）。
    pub updated_at_unix_ms: u64,
    /// 权威副本所在的安全存储后端。
    pub store_backend: String,
    /// 该后端是否由操作系统托管。为 `false` 说明这不是生产配置。
    pub store_is_system: bool,
}

impl SecurityCheckpointData {
    fn render(&self) -> String {
        if !self.established {
            return format!(
                "工作区 {} 还没有反回滚检查点。\n  这意味着本设备会接受后端给出的任意状态；\
                 请先 `envsync vault create` 或 `envsync device join`。",
                self.workspace
            );
        }
        format!(
            "工作区 {workspace} 的反回滚检查点\n  revision：{revision}\n  快照：{snapshot}\n  \
             成员链头：{digest}（sequence {sequence}）\n  密钥纪元：{epoch}\n  \
             更新于：{at} ms\n  权威副本：{backend}（{kind}）",
            workspace = self.workspace,
            revision = self.revision,
            snapshot = self.snapshot.as_deref().unwrap_or("（无）"),
            digest = self.membership_digest.as_deref().unwrap_or("（无）"),
            sequence = self.membership_sequence,
            epoch = self.key_epoch,
            at = self.updated_at_unix_ms,
            backend = self.store_backend,
            kind = if self.store_is_system {
                "系统存储"
            } else {
                "非系统存储"
            },
        )
    }
}

/// 显示当前反回滚检查点。
pub fn security_checkpoint(ctx: &VaultContext) -> CoreResult<CommandOutput> {
    let service = ctx.service()?;
    let checkpoint = service.checkpoint()?;
    let descriptor = ctx.secure().describe();
    let mut diagnostics = Vec::new();
    if !descriptor.is_system_store {
        diagnostics.push(DiagnosticOut::warning(
            "checkpoint.non_system_store",
            format!(
                "检查点的权威副本落在非系统存储 `{}` 上；这不是生产配置。",
                descriptor.backend
            ),
        ));
    }
    let data = match checkpoint {
        Some(checkpoint) => SecurityCheckpointData {
            workspace: checkpoint.workspace.to_string(),
            established: true,
            revision: checkpoint.revision,
            snapshot: Some(checkpoint.snapshot.to_hex()),
            membership_digest: Some(checkpoint.membership_digest.to_hex()),
            membership_sequence: checkpoint.membership_sequence,
            key_epoch: checkpoint.key_epoch,
            updated_at_unix_ms: checkpoint.updated_at_unix_ms,
            store_backend: descriptor.backend.to_owned(),
            store_is_system: descriptor.is_system_store,
        },
        None => {
            diagnostics.push(DiagnosticOut::warning(
                "checkpoint.not_established",
                "本设备还没有信任根，无法检测后端回滚。".to_owned(),
            ));
            SecurityCheckpointData {
                workspace: ctx.config().workspace_id.to_string(),
                established: false,
                revision: 0,
                snapshot: None,
                membership_digest: None,
                membership_sequence: 0,
                key_epoch: 0,
                updated_at_unix_ms: 0,
                store_backend: descriptor.backend.to_owned(),
                store_is_system: descriptor.is_system_store,
            }
        }
    };
    Ok(CommandOutput {
        data: CommandData::SecurityCheckpoint(data),
        diagnostics,
    })
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

/// 把设备公开材料编成 128 个小写十六进制字符。
pub fn encode_public(public: &DevicePublic) -> String {
    let mut out = String::with_capacity((X25519_LEN + ED25519_PUBLIC_LEN) * 2);
    for byte in public.x25519.iter().chain(public.ed25519.iter()) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// 解析 128 个十六进制字符形式的设备公开材料。
pub fn decode_public(text: &str) -> CoreResult<DevicePublic> {
    let text = text.trim();
    let expected = (X25519_LEN + ED25519_PUBLIC_LEN) * 2;
    if text.len() != expected || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CoreError::Domain(format!(
            "设备公开材料必须是 {expected} 个十六进制字符"
        )));
    }
    let mut bytes = [0u8; X25519_LEN + ED25519_PUBLIC_LEN];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| CoreError::Domain("设备公开材料含非十六进制字符".to_owned()))?;
    }
    let mut x25519 = [0u8; X25519_LEN];
    let mut ed25519 = [0u8; ED25519_PUBLIC_LEN];
    x25519.copy_from_slice(&bytes[..X25519_LEN]);
    ed25519.copy_from_slice(&bytes[X25519_LEN..]);
    let public = DevicePublic { x25519, ed25519 };
    public.validate()?;
    Ok(public)
}

/// 路径的展示形式：只给文件名，**绝不**回显绝对路径。
fn file_label(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "-".to_owned())
}

/// 把 [`CommandData`] 中属于本模块的形状渲染成人类可读文本。
pub(crate) fn render(data: &CommandData) -> Option<String> {
    Some(match data {
        CommandData::DeviceInit(data) => data.render(),
        CommandData::DeviceList(data) => data.render(),
        CommandData::DeviceInvite(data) => data.render(),
        CommandData::DeviceJoin(data) => data.render(),
        CommandData::DeviceRevoke(data) => data.render(),
        CommandData::VaultCreate(data) => data.render(),
        CommandData::VaultSet(data) => data.render(),
        CommandData::VaultGet(data) => data.render(),
        CommandData::VaultList(data) => data.render(),
        CommandData::VaultDelete(data) => data.render(),
        CommandData::RecoveryCreate(data) => data.render(),
        CommandData::RecoveryRestore(data) => data.render(),
        CommandData::SecurityCheckpoint(data) => data.render(),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_public_round_trips_through_hex() {
        let keypair = envsync_crypto::device::DeviceKeypair::generate().expect("生成设备");
        let text = encode_public(&keypair.public());
        assert_eq!(text.len(), 128);
        assert_eq!(decode_public(&text).expect("解析"), keypair.public());
    }

    #[test]
    fn malformed_device_public_is_rejected() {
        for bad in ["", "zz", &"0".repeat(127), &"g".repeat(128)] {
            assert!(decode_public(bad).is_err(), "`{bad}` 应当被拒绝");
        }
    }

    #[test]
    fn output_target_parses_the_stdout_literal() {
        assert_eq!(OutputTarget::parse("stdout"), OutputTarget::Stdout);
        assert_eq!(
            OutputTarget::parse("/tmp/token.txt"),
            OutputTarget::File(PathBuf::from("/tmp/token.txt"))
        );
        // 描述里只出现文件名，绝不出现目录。
        assert_eq!(
            OutputTarget::parse("/very/secret/dir/token.txt").describe(),
            "file:token.txt"
        );
    }

    #[test]
    fn value_source_names_are_stable() {
        assert_eq!(ValueSource::Stdin.as_str(), "stdin");
        assert_eq!(ValueSource::Env("GITHUB_TOKEN".to_owned()).as_str(), "env");
        assert_eq!(ValueSource::Prompt.as_str(), "prompt");
    }

    #[test]
    fn json_field_names_survive_the_redactor() {
        // 清单字段叫 `entries` 而不是 `secrets`：后者会被脱敏器整棵替换掉。
        assert!(!crate::output::is_sensitive_key("entries"));
        assert!(!crate::output::is_sensitive_key("value_bytes"));
        assert!(!crate::output::is_sensitive_key("key_epoch"));
        assert!(!crate::output::is_sensitive_key("device_public"));
        // 反面对照：这些名字如果被用上，值就会消失。
        assert!(crate::output::is_sensitive_key("secrets"));
        assert!(crate::output::is_sensitive_key("token"));
    }
}
