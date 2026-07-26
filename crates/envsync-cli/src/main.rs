#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

//! # envsync
//!
//! EnvSync 的命令行界面：解析参数、调用 [`envsync_core::EnvSyncService`]、把结果
//! 渲染成人类可读文本或单行 JSON，并把核心层错误映射成稳定的退出码。
//!
//! ## 退出码
//!
//! | 码 | 含义 |
//! |---|---|
//! | 0 | 成功 |
//! | 1 | 一般错误 |
//! | 2 | 用法错误（缺参数、参数非法），由 clap 产生 |
//! | 10 | 后端 CAS 冲突，别的设备先发布了 |
//! | 11 | 计划失效或不存在，需要重新 `plan` |
//! | 12 | 策略阻塞，计划里有阻塞诊断 |
//! | 13 | 存在未解决的合并冲突；本地文件与远端 Ref 都没有被改动 |
//! | 20 | 已发布但本地未收敛，需要 `recover` 或 `rollback` |
//!
//! 退出码只由 [`envsync_core::CoreError`] 的判定方法派生，不看错误文本，因此错误
//! 信息可以随时改写而不破坏脚本。

mod commands;
mod output;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand};
use envsync_core::CoreError;
use envsync_domain::{ConflictId, OperationId, PlanId, ResolutionChoice};

use crate::commands::{CommandData, CommandOutput};
use crate::output::{DiagnosticOut, Status, JSON_SCHEMA_VERSION, MIN_JSON_SCHEMA_VERSION};

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

fn main() -> ExitCode {
    // 参数解析失败时 clap 自己退出，用法错误固定为退出码 2。
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
                "adapters"
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
