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
//! | 20 | 已发布但本地未收敛，需要 `recover` 或 `rollback` |
//!
//! 退出码只由 [`envsync_core::CoreError`] 的判定方法派生，不看错误文本，因此错误
//! 信息可以随时改写而不破坏脚本。

mod commands;
mod output;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use envsync_core::CoreError;
use envsync_domain::{OperationId, PlanId};

use crate::commands::{CommandData, CommandOutput};
use crate::output::{DiagnosticOut, Status};

/// 一般错误。
const EXIT_ERROR: u8 = 1;
/// 后端 CAS 冲突。
const EXIT_CAS_CONFLICT: u8 = 10;
/// 计划失效或不存在。
const EXIT_STALE_PLAN: u8 = 11;
/// 策略阻塞。
const EXIT_POLICY_BLOCK: u8 = 12;
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
        }
    }
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
    match dispatch(&cli.command) {
        Ok(output) => {
            emit_success(command, cli.json, &output);
            ExitCode::SUCCESS
        }
        Err(error) => {
            let diagnostics = vec![DiagnosticOut::from_error(&error)];
            emit_failure(command, cli.json, &error, &diagnostics);
            ExitCode::from(exit_code_for(&error))
        }
    }
}

/// 把子命令分派到 [`crate::commands`]。
fn dispatch(command: &Command) -> Result<CommandOutput, CoreError> {
    match command {
        Command::Init(args) => commands::init(
            &args.config,
            args.device_name.as_deref(),
            &args.backend_path,
        ),
        Command::Capture(args) => commands::capture(&args.config),
        Command::Plan(args) => commands::plan(&args.config),
        Command::Sync(args) => commands::sync(&args.config, args.plan),
        Command::Status(args) => commands::status(&args.config),
        Command::Rollback(args) => commands::rollback(&args.config, args.operation),
        Command::Doctor(args) => commands::doctor(&args.config),
        Command::Recover(args) => commands::recover(&args.config),
    }
}

/// 输出成功结果。
fn emit_success(command: &str, json: bool, output: &CommandOutput) {
    if json {
        output::print_json(command, Status::Ok, Some(&output.data), &output.diagnostics);
    } else {
        output::print_human(&output.data.render(), &output.diagnostics);
    }
}

/// 输出失败结果。
///
/// `--json` 时信封照样写 stdout（`status` 为 `error`、`data` 为 `null`），这样调用方
/// 无论成功失败都只需要解析同一个位置的同一种形状。
fn emit_failure(command: &str, json: bool, error: &CoreError, diagnostics: &[DiagnosticOut]) {
    if json {
        output::print_json(command, Status::Error, None::<&CommandData>, diagnostics);
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
            ["init", "capture", "plan", "sync", "status", "rollback", "doctor", "recover"]
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
            exit_code_for(&CoreError::Invariant("boom".to_owned())),
            EXIT_ERROR
        );
    }
}
