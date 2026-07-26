//! 命令行界面：参数定义、子命令派发与退出码映射。
//!
//! 所有安全决策都在 [`envsync_core`]；本模块只做三件事——解析参数、调用服务、把结果
//! 交给 [`crate::output`] 渲染。

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand};
use envsync_core::CoreError;
use envsync_domain::{ConflictId, OperationId, PlanId, ResolutionChoice};

use envsync_domain::membership::MemberRole;

use crate::commands::{self, CommandData, CommandOutput};
use crate::output::{self, DiagnosticOut, Status, JSON_SCHEMA_VERSION, MIN_JSON_SCHEMA_VERSION};
use crate::vault_cli::{self, OutputTarget, ValueSource, VaultContext};

/// 一般错误。
const EXIT_ERROR: u8 = 1;
/// 后端 CAS 冲突。
const EXIT_CAS_CONFLICT: u8 = 10;
/// 计划失效或不存在。
const EXIT_STALE_PLAN: u8 = 11;
/// 策略阻塞。
const EXIT_POLICY_BLOCK: u8 = 12;
/// 存在未解决的合并冲突。
const EXIT_CONFLICTED: u8 = 13;
/// 检测到后端回滚或分叉（M2）。
const EXIT_ROLLBACK_ATTACK: u8 = 14;
/// 系统安全存储不可用/被锁定/被拒绝（M2）。
const EXIT_SECURE_STORE: u8 = 15;
/// 已发布但本地未收敛。
const EXIT_PARTIAL_CONVERGENCE: u8 = 20;

/// EnvSync 命令行。
#[derive(Debug, Parser)]
#[command(
    name = "envsync",
    version,
    about = "EnvSync：可审计、可回滚的开发环境同步",
    long_about = "EnvSync 把开发环境中被显式声明的文件，安全地在多台设备之间同步。\n\
                  所有写入都必须先出现在一份不可变的计划里，应用过程记录在本地操作日志中，\n\
                  失败时按逆序回滚。\n\n\
                  典型流程：init → capture → plan → sync → status。",
    propagate_version = true
)]
struct Cli {
    /// 要执行的子命令。
    #[command(subcommand)]
    command: Command,

    /// 以单行 JSON 输出结果；日志与诊断一律写 stderr。
    #[arg(long, global = true)]
    json: bool,

    /// JSON 契约版本：2（默认，含 M1 新字段）或 1（M0 字段集合）。
    ///
    /// 其他取值一律以用法错误（退出码 2）拒绝，绝不静默按某个版本输出。
    #[arg(
        long,
        global = true,
        value_name = "VERSION",
        default_value_t = JSON_SCHEMA_VERSION,
        value_parser = clap::value_parser!(u32).range(MIN_JSON_SCHEMA_VERSION as i64..=JSON_SCHEMA_VERSION as i64),
    )]
    schema_version: u32,

    /// 提高日志级别，可重复：-v 为 info，-vv 为 debug，-vvv 为 trace。
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
}

/// 子命令。
#[derive(Debug, Subcommand)]
enum Command {
    /// 初始化工作区：生成配置文件、后端目录与本地状态目录。
    Init(InitArgs),
    /// 观察本机现状并生成快照草稿（不写后端）。
    Capture(CommonArgs),
    /// 由配置、目标快照与本机观察生成不可变计划。
    Plan(CommonArgs),
    /// 应用指定计划：发布到后端并让本机收敛。
    Sync(SyncArgs),
    /// 汇总工作区状态。
    Status(CommonArgs),
    /// 按收据逆序回滚一次操作。
    Rollback(RollbackArgs),
    /// 只读体检：报告问题但绝不修改。
    Doctor(CommonArgs),
    /// 显式触发崩溃恢复（`sync` 启动时也会自动运行）。
    Recover(CommonArgs),
    /// 读取远端引用与头快照，把可达对象拉进本地草稿库。
    Fetch(CommonArgs),
    /// 合并本地草稿头与远端头；有冲突时只登记冲突，不改任何文件。
    Merge(CommonArgs),
    /// 查看与裁决合并冲突。
    Conflicts(ConflictsArgs),
    /// 查看设备 Profile 相关信息。
    Profile(ProfileArgs),
    /// 查看内建适配器，或让它们为本设备生成资源配置。
    Adapters(AdaptersArgs),
    /// 管理本工作区的设备身份与成员关系（M2）。
    Device(DeviceArgs),
    /// 端到端加密的秘密存取（M2）。
    Vault(VaultArgs),
    /// 工作区恢复短语与恢复包（M2）。
    Recovery(RecoveryArgs),
    /// 安全状态查看（M2）。
    Security(SecurityArgs),
}

impl Command {
    /// JSON 契约里的 `command` 字段。
    fn name(&self) -> &'static str {
        match self {
            Command::Init(_) => "init",
            Command::Capture(_) => "capture",
            Command::Plan(_) => "plan",
            Command::Sync(_) => "sync",
            Command::Status(_) => "status",
            Command::Rollback(_) => "rollback",
            Command::Doctor(_) => "doctor",
            Command::Recover(_) => "recover",
            Command::Fetch(_) => "fetch",
            Command::Merge(_) => "merge",
            Command::Conflicts(args) => match args.command {
                ConflictsCommand::List(_) => "conflicts.list",
                ConflictsCommand::Show(_) => "conflicts.show",
                ConflictsCommand::Resolve(_) => "conflicts.resolve",
            },
            Command::Profile(args) => match args.command {
                ProfileCommand::Explain(_) => "profile.explain",
            },
            Command::Adapters(args) => match args.command {
                AdaptersCommand::List(_) => "adapters.list",
                AdaptersCommand::Discover(_) => "adapters.discover",
            },
            Command::Device(args) => match args.command {
                DeviceCommand::Init(_) => "device.init",
                DeviceCommand::List(_) => "device.list",
                DeviceCommand::Invite(_) => "device.invite",
                DeviceCommand::Join(_) => "device.join",
                DeviceCommand::Revoke(_) => "device.revoke",
            },
            Command::Vault(args) => match args.command {
                VaultCommand::Create(_) => "vault.create",
                VaultCommand::Set(_) => "vault.set",
                VaultCommand::Get(_) => "vault.get",
                VaultCommand::List(_) => "vault.list",
                VaultCommand::Delete(_) => "vault.delete",
            },
            Command::Recovery(args) => match args.command {
                RecoveryCommand::Create(_) => "recovery.create",
                RecoveryCommand::Restore(_) => "recovery.restore",
            },
            Command::Security(args) => match args.command {
                SecurityCommand::Checkpoint(_) => "security.checkpoint",
            },
        }
    }

    /// 该命令是否只存在于 schema v2。
    ///
    /// v1 里没有它们的形状，因此以 `--schema-version 1` 调用时必须**报错**，
    /// 而不是输出一个 v1 读者无法解释的信封。
    fn requires_v2(&self) -> bool {
        matches!(
            self,
            Command::Fetch(_)
                | Command::Merge(_)
                | Command::Conflicts(_)
                | Command::Profile(_)
                | Command::Adapters(_)
                | Command::Device(_)
                | Command::Vault(_)
                | Command::Recovery(_)
                | Command::Security(_)
        )
    }
}

/// `adapters` 的参数。
#[derive(Debug, Args)]
struct AdaptersArgs {
    /// 要执行的子命令。
    #[command(subcommand)]
    command: AdaptersCommand,
}

/// `adapters` 的子命令。
#[derive(Debug, Subcommand)]
enum AdaptersCommand {
    /// 列出内建适配器及其目标资源，默认只列适用于本设备的。
    List(AdaptersListArgs),
    /// 对本设备运行一次发现，输出可直接粘贴进配置的 `resources:` 片段。
    Discover(CommonArgs),
}

/// `adapters list` 的参数。
#[derive(Debug, Args)]
struct AdaptersListArgs {
    /// 工作区配置文件路径（YAML）。
    #[arg(long, value_name = "PATH")]
    config: PathBuf,

    /// 列出全部适配器与资源，不按本设备 Profile 与资源选择器过滤。
    #[arg(long)]
    all: bool,
}

/// `conflicts` 的参数。
#[derive(Debug, Args)]
struct ConflictsArgs {
    /// 要执行的子命令。
    #[command(subcommand)]
    command: ConflictsCommand,
}

/// `conflicts` 的子命令。
#[derive(Debug, Subcommand)]
enum ConflictsCommand {
    /// 列出未解决的冲突。
    List(CommonArgs),
    /// 查看单个冲突的详情（三侧摘要与结构性诊断，不含文件正文）。
    Show(ConflictShowArgs),
    /// 裁决一个冲突：采用本地、远端或人工合并后的内容。
    Resolve(ConflictResolveArgs),
}

/// `conflicts show` 的参数。
#[derive(Debug, Args)]
struct ConflictShowArgs {
    /// 工作区配置文件路径（YAML）。
    #[arg(long, value_name = "PATH")]
    config: PathBuf,

    /// 冲突标识，由 `envsync merge` 或 `envsync conflicts list` 输出。
    #[arg(long, value_name = "CONFLICT-ID")]
    conflict: ConflictId,
}

/// `conflicts resolve` 的参数。
///
/// 三种裁决互斥：要么采用一侧，要么给出人工合并后的文件。
#[derive(Debug, Args)]
struct ConflictResolveArgs {
    /// 工作区配置文件路径（YAML）。
    #[arg(long, value_name = "PATH")]
    config: PathBuf,

    /// 要裁决的冲突标识。
    #[arg(long, value_name = "CONFLICT-ID")]
    conflict: ConflictId,

    /// 采用本地一侧的内容。
    #[arg(long, group = "choice")]
    ours: bool,

    /// 采用远端一侧的内容。
    #[arg(long, group = "choice")]
    theirs: bool,

    /// 采用该文件的内容（人工合并结果），会被存成新的 Blob。
    #[arg(long, value_name = "PATH", group = "choice")]
    file: Option<PathBuf>,

    /// 确认删除该资源；这是唯一能让资源消失的裁决。
    #[arg(long, group = "choice")]
    delete: bool,
}

impl ConflictResolveArgs {
    /// 由互斥开关得到裁决方式。
    ///
    /// clap 的 `group` 已经保证至多一个开关出现；一个都没有时必须报用法错误，
    /// 而不是替用户挑一个默认值。
    fn choice(&self) -> Result<ResolutionChoice, clap::Error> {
        if self.ours {
            Ok(ResolutionChoice::Ours)
        } else if self.theirs {
            Ok(ResolutionChoice::Theirs)
        } else if self.file.is_some() {
            Ok(ResolutionChoice::Manual)
        } else if self.delete {
            Ok(ResolutionChoice::Delete)
        } else {
            Err(Cli::command().error(
                clap::error::ErrorKind::MissingRequiredArgument,
                "必须给出裁决方式之一：--ours、--theirs、--file <PATH> 或 --delete",
            ))
        }
    }
}

/// `profile` 的参数。
#[derive(Debug, Args)]
struct ProfileArgs {
    /// 要执行的子命令。
    #[command(subcommand)]
    command: ProfileCommand,
}

/// `profile` 的子命令。
#[derive(Debug, Subcommand)]
enum ProfileCommand {
    /// 解释本设备 Profile 与每个资源的投影结论。
    Explain(CommonArgs),
}

/// 只需要配置文件路径的命令。
#[derive(Debug, Args)]
struct CommonArgs {
    /// 工作区配置文件路径（YAML）。
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
}

/// `init` 的参数。
#[derive(Debug, Args)]
struct InitArgs {
    /// 要生成的配置文件路径；已存在时报错而不覆盖。
    #[arg(long, value_name = "PATH")]
    config: PathBuf,

    /// 设备显示名；省略时取 ENVSYNC_DEVICE_NAME / HOSTNAME / COMPUTERNAME。
    #[arg(long, value_name = "NAME")]
    device_name: Option<String>,

    /// 本地后端目录路径；不存在时创建。
    #[arg(long, value_name = "PATH")]
    backend_path: PathBuf,

    /// 用内建适配器发现本设备上该管理的资源，并写进生成的配置。
    ///
    /// 不加时生成空的 resources 列表，由你自己决定管什么；
    /// 加了之后可以用 `envsync adapters discover` 随时复核这份清单。
    #[arg(long)]
    discover: bool,
}

/// `sync` 的参数。
#[derive(Debug, Args)]
struct SyncArgs {
    /// 工作区配置文件路径（YAML）。
    #[arg(long, value_name = "PATH")]
    config: PathBuf,

    /// 要应用的计划标识，由 `envsync plan` 输出。
    #[arg(long, value_name = "PLAN-ID")]
    plan: PlanId,
}

// ---------------------------------------------------------------------------
// M2：device / vault / recovery / security
// ---------------------------------------------------------------------------

/// `device` 的参数。
#[derive(Debug, Args)]
struct DeviceArgs {
    /// 要执行的子命令。
    #[command(subcommand)]
    command: DeviceCommand,
}

/// `device` 的子命令。
#[derive(Debug, Subcommand)]
enum DeviceCommand {
    /// 在系统安全存储里生成本设备身份，并打印可交给管理员的公开材料。
    Init(CommonArgs),
    /// 列出工作区当前的成员设备及其角色。
    List(CommonArgs),
    /// 邀请一台设备加入：链上追加成员、发一份数据密钥信封，并产出邀请文件。
    Invite(DeviceInviteArgs),
    /// 用一份邀请加入工作区，并建立本机的反回滚检查点。
    Join(DeviceJoinArgs),
    /// 撤销一台设备并轮换工作区数据密钥；中断过的轮换会被接着做完。
    Revoke(DeviceRevokeArgs),
}

/// `device invite` 的参数。
#[derive(Debug, Args)]
struct DeviceInviteArgs {
    /// 工作区配置文件路径（YAML）。
    #[arg(long, value_name = "PATH")]
    config: PathBuf,

    /// 被邀请设备的公开材料：128 个十六进制字符，由对方的 `envsync device init` 打印。
    ///
    /// 这是**公钥**，不是秘密，可以放心写在命令行里。
    #[arg(long, value_name = "HEX")]
    device_public: String,

    /// 授予的角色。
    #[arg(long, value_name = "ROLE", default_value = "member",
          value_parser = ["member", "admin"])]
    role: String,

    /// 邀请文件的写出路径。
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
}

/// `device join` 的参数。
#[derive(Debug, Args)]
struct DeviceJoinArgs {
    /// 工作区配置文件路径（YAML）。
    #[arg(long, value_name = "PATH")]
    config: PathBuf,

    /// 管理员给出的邀请文件。
    #[arg(long, value_name = "PATH")]
    invitation: PathBuf,
}

/// `device revoke` 的参数。
#[derive(Debug, Args)]
struct DeviceRevokeArgs {
    /// 工作区配置文件路径（YAML）。
    #[arg(long, value_name = "PATH")]
    config: PathBuf,

    /// 要撤销的设备标识，由 `envsync device list` 输出。
    #[arg(long, value_name = "DEVICE-ID")]
    device: String,
}

/// `vault` 的参数。
#[derive(Debug, Args)]
struct VaultArgs {
    /// 要执行的子命令。
    #[command(subcommand)]
    command: VaultCommand,
}

/// `vault` 的子命令。
#[derive(Debug, Subcommand)]
enum VaultCommand {
    /// 建立工作区数据密钥与 genesis 成员事件；本设备成为唯一管理员。
    Create(CommonArgs),
    /// 写入一条秘密。值来自 stdin、环境变量名或交互式隐藏输入。
    Set(VaultSetArgs),
    /// 读取一条秘密并写到指定去向。
    Get(VaultGetArgs),
    /// 列出全部秘密的**元数据**（不含任何值）。
    List(CommonArgs),
    /// 从索引中删除一条秘密。
    Delete(VaultDeleteArgs),
}

/// `vault set` 的参数。
///
/// **刻意没有 `--value`。** 命令行参数会进入 shell history、`ps aux` 输出与 CI 日志，
/// 那是秘密最常见的泄露方式。三种来源互斥，默认 `--stdin`。
#[derive(Debug, Args)]
struct VaultSetArgs {
    /// 秘密的逻辑标识，例如 `ci/npm-token`。
    #[arg(value_name = "SECRET-ID")]
    id: String,

    /// 工作区配置文件路径（YAML）。
    #[arg(long, value_name = "PATH")]
    config: PathBuf,

    /// 从 stdin 读取值（默认）。会去掉至多一个结尾换行。
    #[arg(long, group = "source")]
    stdin: bool,

    /// 读取该名字的环境变量的值。参数是变量**名**，不是值。
    #[arg(long, value_name = "NAME", group = "source")]
    from_env: Option<String>,

    /// 交互式隐藏输入（需要终端）。
    #[arg(long, group = "source")]
    prompt: bool,
}

impl VaultSetArgs {
    /// 由互斥开关得到取值来源；一个都没给时默认 stdin。
    fn source(&self) -> ValueSource {
        if let Some(name) = &self.from_env {
            ValueSource::Env(name.clone())
        } else if self.prompt {
            ValueSource::Prompt
        } else {
            ValueSource::Stdin
        }
    }
}

/// `vault get` 的参数。
#[derive(Debug, Args)]
struct VaultGetArgs {
    /// 秘密的逻辑标识。
    #[arg(value_name = "SECRET-ID")]
    id: String,

    /// 工作区配置文件路径（YAML）。
    #[arg(long, value_name = "PATH")]
    config: PathBuf,

    /// 输出去向：文件路径，或字面量 `stdout`。
    ///
    /// 文件会以 `0600` 创建（Unix）。写 stdout 需要终端，或显式 `--allow-non-tty`。
    #[arg(long, value_name = "PATH|stdout")]
    output: String,

    /// 允许把秘密写进非终端的 stdout（管道、重定向）。
    ///
    /// 只在你确实知道另一头是什么时才用它：管道的另一端常常是日志或 CI 产物。
    #[arg(long)]
    allow_non_tty: bool,
}

/// `vault delete` 的参数。
#[derive(Debug, Args)]
struct VaultDeleteArgs {
    /// 秘密的逻辑标识。
    #[arg(value_name = "SECRET-ID")]
    id: String,

    /// 工作区配置文件路径（YAML）。
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
}

/// `recovery` 的参数。
#[derive(Debug, Args)]
struct RecoveryArgs {
    /// 要执行的子命令。
    #[command(subcommand)]
    command: RecoveryCommand,
}

/// `recovery` 的子命令。
#[derive(Debug, Subcommand)]
enum RecoveryCommand {
    /// 生成恢复短语与恢复包；短语只显示一次，请立刻抄写。
    Create(CommonArgs),
    /// 用恢复短语还原工作区密钥环。短语从 stdin 读入。
    Restore(CommonArgs),
}

/// `security` 的参数。
#[derive(Debug, Args)]
struct SecurityArgs {
    /// 要执行的子命令。
    #[command(subcommand)]
    command: SecurityCommand,
}

/// `security` 的子命令。
#[derive(Debug, Subcommand)]
enum SecurityCommand {
    /// 显示当前反回滚检查点：revision、快照、成员链头摘要与密钥纪元。
    Checkpoint(CommonArgs),
}

/// 解析角色短名。clap 的 `value_parser` 已经限定了取值，这里只做映射。
fn parse_role(raw: &str) -> MemberRole {
    MemberRole::parse(raw).unwrap_or(MemberRole::Member)
}

/// 解析设备标识，失败时给出用法错误（退出码 2）。
fn parse_device(raw: &str) -> Result<envsync_domain::DeviceId, CoreError> {
    raw.parse::<envsync_domain::DeviceId>()
        .map_err(|error| CoreError::Domain(format!("设备标识非法：{error}")))
}

/// `rollback` 的参数。
#[derive(Debug, Args)]
struct RollbackArgs {
    /// 工作区配置文件路径（YAML）。
    #[arg(long, value_name = "PATH")]
    config: PathBuf,

    /// 要回滚的操作标识，由 `envsync status` 或 `envsync doctor` 输出。
    #[arg(long, value_name = "OPERATION-ID")]
    operation: OperationId,
}

/// 解析参数、执行命令并返回进程退出码。
///
/// 参数解析失败时 clap 自己退出，用法错误固定为退出码 2。
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    let command = cli.command.name();
    match dispatch(&cli.command, cli.schema_version) {
        Ok(output) => {
            emit_success(command, cli.json, cli.schema_version, &output);
            ExitCode::SUCCESS
        }
        Err(error) => {
            let diagnostics = vec![DiagnosticOut::from_error(&error)];
            emit_failure(command, cli.json, cli.schema_version, &error, &diagnostics);
            ExitCode::from(exit_code_for(&error))
        }
    }
}

/// 把子命令分派到 [`crate::commands`]。
fn dispatch(command: &Command, schema_version: u32) -> Result<CommandOutput, CoreError> {
    if command.requires_v2() && schema_version < JSON_SCHEMA_VERSION {
        return Err(CoreError::ManualInterventionRequired(format!(
            "命令 `{}` 只在 JSON schema v{JSON_SCHEMA_VERSION} 中定义；请去掉 `--schema-version {schema_version}`",
            command.name()
        )));
    }
    match command {
        Command::Init(args) => commands::init(
            &args.config,
            args.device_name.as_deref(),
            &args.backend_path,
            args.discover,
        ),
        Command::Capture(args) => commands::capture(&args.config),
        Command::Plan(args) => commands::plan(&args.config),
        Command::Sync(args) => commands::sync(&args.config, args.plan),
        Command::Status(args) => commands::status(&args.config),
        Command::Rollback(args) => commands::rollback(&args.config, args.operation),
        Command::Doctor(args) => commands::doctor(&args.config),
        Command::Recover(args) => commands::recover(&args.config),
        Command::Fetch(args) => commands::fetch(&args.config),
        Command::Merge(args) => commands::merge(&args.config),
        Command::Conflicts(args) => match &args.command {
            ConflictsCommand::List(args) => commands::conflicts_list(&args.config),
            ConflictsCommand::Show(args) => commands::conflicts_show(&args.config, args.conflict),
            ConflictsCommand::Resolve(args) => {
                // 裁决方式缺失是用法错误：交给 clap 退出（退出码 2）。
                let choice = args.choice().unwrap_or_else(|error| error.exit());
                commands::conflicts_resolve(
                    &args.config,
                    args.conflict,
                    choice,
                    args.file.as_deref(),
                )
            }
        },
        Command::Profile(args) => match &args.command {
            ProfileCommand::Explain(args) => commands::profile_explain(&args.config),
        },
        Command::Adapters(args) => match &args.command {
            AdaptersCommand::List(args) => commands::adapters_list(&args.config, args.all),
            AdaptersCommand::Discover(args) => commands::adapters_discover(&args.config),
        },
        Command::Device(args) => match &args.command {
            DeviceCommand::Init(args) => vault_cli::device_init(&VaultContext::open(&args.config)?),
            DeviceCommand::List(args) => vault_cli::device_list(&VaultContext::open(&args.config)?),
            DeviceCommand::Invite(args) => vault_cli::device_invite(
                &VaultContext::open(&args.config)?,
                &args.device_public,
                parse_role(&args.role),
                &args.output,
            ),
            DeviceCommand::Join(args) => {
                vault_cli::device_join(&VaultContext::open(&args.config)?, &args.invitation)
            }
            DeviceCommand::Revoke(args) => vault_cli::device_revoke(
                &VaultContext::open(&args.config)?,
                parse_device(&args.device)?,
            ),
        },
        Command::Vault(args) => match &args.command {
            VaultCommand::Create(args) => {
                vault_cli::vault_create(&VaultContext::open(&args.config)?)
            }
            VaultCommand::Set(args) => {
                vault_cli::vault_set(&VaultContext::open(&args.config)?, &args.id, &args.source())
            }
            VaultCommand::Get(args) => vault_cli::vault_get(
                &VaultContext::open(&args.config)?,
                &args.id,
                &OutputTarget::parse(&args.output),
                args.allow_non_tty,
            ),
            VaultCommand::List(args) => vault_cli::vault_list(&VaultContext::open(&args.config)?),
            VaultCommand::Delete(args) => {
                vault_cli::vault_delete(&VaultContext::open(&args.config)?, &args.id)
            }
        },
        Command::Recovery(args) => match &args.command {
            RecoveryCommand::Create(args) => {
                vault_cli::recovery_create(&VaultContext::open(&args.config)?)
            }
            RecoveryCommand::Restore(args) => {
                vault_cli::recovery_restore(&VaultContext::open(&args.config)?)
            }
        },
        Command::Security(args) => match &args.command {
            SecurityCommand::Checkpoint(args) => {
                vault_cli::security_checkpoint(&VaultContext::open(&args.config)?)
            }
        },
    }
}

/// 输出成功结果。
fn emit_success(command: &str, json: bool, schema_version: u32, output: &CommandOutput) {
    if json {
        output::print_json(
            command,
            Status::Ok,
            schema_version,
            Some(&output.data),
            &output.diagnostics,
            output.data.v2_only_fields(),
        );
    } else {
        output::print_human(&output.data.render(), &output.diagnostics);
    }
}

/// 输出失败结果。
///
/// `--json` 时信封照样写 stdout（`status` 为 `error`、`data` 为 `null`），这样调用方
/// 无论成功失败都只需要解析同一个位置的同一种形状。
fn emit_failure(
    command: &str,
    json: bool,
    schema_version: u32,
    error: &CoreError,
    diagnostics: &[DiagnosticOut],
) {
    if json {
        output::print_json(
            command,
            Status::Error,
            schema_version,
            None::<&CommandData>,
            diagnostics,
            &[],
        );
    } else {
        output::print_human_error(error, &[]);
    }
}

/// 由核心层错误派生退出码。
///
/// `PlanNotFound` 与 `StalePlan` 共用退出码 11：对调用方来说两者的补救动作完全一样
/// ——重新 `plan` 再 `sync`，用两个码只会让脚本多写一个分支。
fn exit_code_for(error: &CoreError) -> u8 {
    if error.is_cas_conflict() {
        EXIT_CAS_CONFLICT
    } else if error.is_stale_plan() || matches!(error, CoreError::PlanNotFound(_)) {
        EXIT_STALE_PLAN
    } else if error.is_policy_block() {
        EXIT_POLICY_BLOCK
    } else if error.is_conflicted() {
        EXIT_CONFLICTED
    } else if error.is_rollback_attack() {
        EXIT_ROLLBACK_ATTACK
    } else if error.is_secure_store_unavailable() {
        EXIT_SECURE_STORE
    } else if error.is_partial_convergence() {
        EXIT_PARTIAL_CONVERGENCE
    } else {
        EXIT_ERROR
    }
}

/// 初始化日志。
///
/// **writer 固定为 stderr**：`--json` 的契约是「stdout 只有一行 JSON」，任何写进
/// stdout 的日志都会把它破坏掉。因此这里不区分模式，一律写 stderr。
fn init_tracing(verbose: u8) {
    let default_level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));
    // 重复初始化（例如测试进程内多次调用）不应该 panic，因此忽略错误。
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn every_subcommand_has_a_stable_name() {
        let names: Vec<String> = Cli::command()
            .get_subcommands()
            .map(|sub| sub.get_name().to_owned())
            .collect();
        assert_eq!(
            names,
            [
                "init",
                "capture",
                "plan",
                "sync",
                "status",
                "rollback",
                "doctor",
                "recover",
                "fetch",
                "merge",
                "conflicts",
                "profile",
                "adapters",
                "device",
                "vault",
                "recovery",
                "security"
            ]
        );
    }

    #[test]
    fn exit_codes_are_derived_from_error_kind() {
        let stale = CoreError::StalePlan {
            submitted: PlanId::of(b"a"),
            current: PlanId::of(b"b"),
        };
        assert_eq!(exit_code_for(&stale), EXIT_STALE_PLAN);
        assert_eq!(
            exit_code_for(&CoreError::PlanNotFound(PlanId::of(b"a"))),
            EXIT_STALE_PLAN
        );
        assert_eq!(
            exit_code_for(&CoreError::PlanBlocked {
                count: 1,
                first: "x".to_owned()
            }),
            EXIT_POLICY_BLOCK
        );
        assert_eq!(
            exit_code_for(&CoreError::PublishedNotConverged {
                operation: "op".to_owned(),
                detail: "d".to_owned()
            }),
            EXIT_PARTIAL_CONVERGENCE
        );
        assert_eq!(
            exit_code_for(&CoreError::Backend(
                envsync_backend::BackendError::CasConflict {
                    expected: 0,
                    observed: 1
                }
            )),
            EXIT_CAS_CONFLICT
        );
        assert_eq!(
            exit_code_for(&CoreError::Conflicted { count: 2 }),
            EXIT_CONFLICTED
        );
        assert_eq!(
            exit_code_for(&CoreError::Invariant("boom".to_owned())),
            EXIT_ERROR
        );
    }
}
