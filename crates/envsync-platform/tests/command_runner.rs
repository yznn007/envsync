//! 能力约束命令执行器的验收测试。
//!
//! 覆盖 M3 计划 Task 2 的全部要求：allowlist 的通过/拒绝形态、shell 字符串被拒、
//! 相对可执行文件被拒、额外参数被拒、未声明的 env / cwd 被拒、stdin 不继承、
//! 超时终止、输出超限截断、注入秘密在输出中被脱敏，以及收据字段。
//!
//! ## 平台与工具可用性
//!
//! 这些测试要真的把进程跑起来，用的是 POSIX 基础工具（`echo`、`cat`、`env`、`sleep`、
//! `yes`、`sh`）。因此整个测试模块用 `#[cfg(unix)]` 编译：Windows 上没有这些程序，
//! 编译进去只会得到必然失败的测试。
//!
//! 即使在 Unix 上，工具的位置也不固定（`/bin` 与 `/usr/bin` 在不同发行版上互为符号
//! 链接），所以每个测试先用 [`tool`] 做一次运行期探测；探测不到就打印一行说明后
//! **提前返回**而不是失败——最小容器镜像里缺 `yes` 是环境问题，不是被测代码的问题。

#![cfg(unix)]

use std::path::PathBuf;
use std::time::Duration;

use envsync_platform::capability::AuthorizedRoot;
use envsync_platform::command::{
    ArgPattern, CommandRunner, CommandSpec, CommandTemplate, CwdPolicy, SecretEnvValue,
    MAX_OUTPUT_LIMIT, RECEIPT_HEAD_LINES, RECEIPT_TAIL_LINES,
};
use envsync_platform::PlatformError;

// ---------------------------------------------------------------------------
// 工具探测
// ---------------------------------------------------------------------------

/// 在常见位置查找一个系统工具，找不到返回 `None`。
///
/// 相当于 `which`，但不依赖 `PATH`（本测试里 `PATH` 本身不可信）也不启动子进程。
fn tool(name: &str) -> Option<PathBuf> {
    for dir in ["/bin", "/usr/bin", "/usr/local/bin"] {
        let candidate = PathBuf::from(dir).join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// 探测不到工具时打印说明并跳过。
macro_rules! require_tool {
    ($name:expr) => {
        match tool($name) {
            Some(path) => path,
            None => {
                eprintln!("跳过：本机没有 {}，无法构造该用例", $name);
                return;
            }
        }
    };
}

/// 注册好一个模板的执行器。
fn runner_with(template: CommandTemplate) -> CommandRunner {
    let mut runner = CommandRunner::new();
    runner.register(template).expect("注册成功");
    runner
}

/// `echo hello` 的模板：一个字面量位置。
fn echo_template() -> CommandTemplate {
    CommandTemplate::new(
        "test.echo",
        "test-adapter",
        "echo",
        vec![ArgPattern::literal("hello")],
    )
}

// ---------------------------------------------------------------------------
// 注册期 allowlist
// ---------------------------------------------------------------------------

#[test]
fn duplicate_template_ids_are_rejected() {
    let mut runner = CommandRunner::new();
    runner.register(echo_template()).expect("首次注册成功");
    let error = runner
        .register(echo_template())
        .expect_err("重复注册必须失败");
    assert_eq!(error.code(), "platform.command_template_duplicate");
    assert_eq!(runner.len(), 1);
}

#[test]
fn registering_a_shell_is_rejected() {
    let mut runner = CommandRunner::new();
    // 典型的 shell 字符串形态：`sh -c "<任意命令>"`。模板层面就被拒。
    let error = runner
        .register(CommandTemplate::new(
            "test.shell",
            "test-adapter",
            "sh",
            vec![ArgPattern::literal("-c"), ArgPattern::token("script")],
        ))
        .expect_err("注册 shell 必须失败");
    assert_eq!(error.code(), "platform.command_shell_rejected");
    assert!(runner.is_empty());

    for shell in ["bash", "zsh", "pwsh", "cmd.exe", "busybox"] {
        assert!(
            runner
                .register(CommandTemplate::new(
                    "test.shell2",
                    "test-adapter",
                    shell,
                    vec![],
                ))
                .is_err(),
            "{shell} 必须被拒"
        );
    }
}

#[test]
fn registering_an_executable_with_a_directory_is_rejected() {
    let mut runner = CommandRunner::new();
    let error = runner
        .register(CommandTemplate::new(
            "test.path",
            "test-adapter",
            "/bin/echo",
            vec![],
        ))
        .expect_err("模板里的可执行文件名不能带目录");
    assert_eq!(error.code(), "platform.command_executable_rejected");
}

// ---------------------------------------------------------------------------
// 执行期 allowlist
// ---------------------------------------------------------------------------

#[test]
fn an_allowlisted_command_runs_and_reports_its_output() {
    let echo = require_tool!("echo");
    let runner = runner_with(echo_template());
    let outcome = runner
        .run(&CommandSpec::new("test.echo", echo).arg("hello"))
        .expect("执行成功");
    assert!(outcome.success());
    assert_eq!(outcome.exit_code, Some(0));
    assert_eq!(outcome.stdout.trim_end(), "hello");
    assert!(outcome.stderr.is_empty());
    assert!(!outcome.truncated);
}

#[test]
fn an_unregistered_template_is_rejected() {
    let echo = require_tool!("echo");
    let runner = CommandRunner::new();
    let error = runner
        .run(&CommandSpec::new("test.echo", echo).arg("hello"))
        .expect_err("未注册模板必须失败");
    assert_eq!(error.code(), "platform.command_template_unknown");
}

#[test]
fn a_relative_executable_is_rejected() {
    let runner = runner_with(echo_template());
    let error = runner
        .run(&CommandSpec::new("test.echo", PathBuf::from("echo")).arg("hello"))
        .expect_err("相对可执行文件必须失败");
    assert_eq!(error.code(), "platform.command_executable_rejected");

    let error = runner
        .run(&CommandSpec::new("test.echo", PathBuf::from("./echo")).arg("hello"))
        .expect_err("相对可执行文件必须失败");
    assert_eq!(error.code(), "platform.command_executable_rejected");
}

#[test]
fn an_executable_path_with_parent_segments_is_rejected() {
    let runner = runner_with(echo_template());
    let error = runner
        .run(&CommandSpec::new("test.echo", PathBuf::from("/bin/../bin/echo")).arg("hello"))
        .expect_err("`..` 必须失败");
    assert_eq!(error.code(), "platform.command_executable_rejected");
}

#[test]
fn an_executable_that_does_not_match_the_template_is_rejected() {
    let cat = require_tool!("cat");
    let runner = runner_with(echo_template());
    // 模板说 `echo`，实参给 `cat`：文件名对不上。
    let error = runner
        .run(&CommandSpec::new("test.echo", cat).arg("hello"))
        .expect_err("可执行文件身份不符必须失败");
    assert_eq!(error.code(), "platform.command_executable_rejected");
}

#[test]
fn running_a_shell_is_rejected_even_if_a_template_somehow_names_it() {
    let sh = require_tool!("sh");
    // 模板名是 `sh` 的注册路径已经被堵死，这里换一条路：模板叫别的名字，
    // 但实参指向 shell。`reject_shell` 在执行期再挡一次。
    let runner = runner_with(CommandTemplate::new(
        "test.notshell",
        "test-adapter",
        "definitely-not-a-shell",
        vec![],
    ));
    let error = runner
        .run(&CommandSpec::new("test.notshell", sh))
        .expect_err("执行 shell 必须失败");
    assert_eq!(error.code(), "platform.command_shell_rejected");
}

#[test]
fn extra_arguments_are_rejected() {
    let echo = require_tool!("echo");
    let runner = runner_with(echo_template());
    let error = runner
        .run(
            &CommandSpec::new("test.echo", echo.clone())
                .arg("hello")
                .arg("; rm -rf /"),
        )
        .expect_err("多余参数必须失败");
    assert_eq!(error.code(), "platform.command_arg_rejected");

    // 少给参数同样被拒。
    let error = runner
        .run(&CommandSpec::new("test.echo", echo))
        .expect_err("缺参数必须失败");
    assert_eq!(error.code(), "platform.command_arg_rejected");
}

#[test]
fn an_argument_that_differs_from_the_template_literal_is_rejected() {
    let echo = require_tool!("echo");
    let runner = runner_with(echo_template());
    let error = runner
        .run(&CommandSpec::new("test.echo", echo).arg("goodbye"))
        .expect_err("字面量不符必须失败");
    assert_eq!(error.code(), "platform.command_arg_rejected");
}

#[test]
fn placeholder_values_reject_shell_strings_and_option_injection() {
    let echo = require_tool!("echo");
    let runner = runner_with(CommandTemplate::new(
        "test.echo-token",
        "test-adapter",
        "echo",
        vec![ArgPattern::token("word")],
    ));

    // 合法 Token 放行。
    let outcome = runner
        .run(&CommandSpec::new("test.echo-token", echo.clone()).arg("ripgrep"))
        .expect("合法 Token 应当通过");
    assert_eq!(outcome.stdout.trim_end(), "ripgrep");

    // 把整条命令塞进一个参数里（典型的 shell 字符串形态）：一律拒。
    for hostile in [
        "rg; rm -rf /",
        "rg && curl http://evil",
        "$(whoami)",
        "`id`",
        "--force",
        "a b",
    ] {
        let result = runner.run(&CommandSpec::new("test.echo-token", echo.clone()).arg(hostile));
        match result {
            Err(error) => assert_eq!(
                error.code(),
                "platform.command_arg_rejected",
                "`{hostile}` 应当以参数校验失败被拒"
            ),
            Ok(outcome) => panic!("`{hostile}` 必须被拒，却执行了：{outcome:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// 环境变量
// ---------------------------------------------------------------------------

#[test]
fn undeclared_environment_variables_are_rejected() {
    let env = require_tool!("env");
    let runner = runner_with(CommandTemplate::new(
        "test.env",
        "test-adapter",
        "env",
        vec![],
    ));

    let error = runner
        .run(&CommandSpec::new("test.env", env.clone()).allow_env("HOME"))
        .expect_err("未声明的透传变量必须失败");
    assert_eq!(error.code(), "platform.command_env_rejected");

    let error = runner
        .run(&CommandSpec::new("test.env", env).inject_env("TOKEN", SecretEnvValue::new("secret")))
        .expect_err("未声明的注入变量必须失败");
    assert_eq!(error.code(), "platform.command_env_rejected");
}

#[test]
fn the_child_environment_is_cleared_except_for_declared_names() {
    let env = require_tool!("env");
    // 刻意**不**调用 `std::env::set_var`：测试进程是多线程的，改进程环境会和
    // 执行器自己的 `var_os` 读取赛跑。改用当前环境里已经存在的变量做断言。
    let Some(path) = std::env::var_os("PATH").and_then(|value| value.into_string().ok()) else {
        eprintln!("跳过：本机环境里没有 PATH");
        return;
    };
    let undeclared = std::env::vars().find(|(name, value)| {
        name != "PATH" && !value.is_empty() && !value.contains('\n') && value.len() > 3
    });

    let runner = runner_with(
        CommandTemplate::new("test.env", "test-adapter", "env", vec![]).allow_env("PATH"),
    );
    let outcome = runner
        .run(&CommandSpec::new("test.env", env).allow_env("PATH"))
        .expect("执行成功");

    assert!(outcome.success());
    assert!(
        outcome.stdout.contains(&format!("PATH={path}")),
        "声明过的变量应当透传"
    );
    if let Some((name, value)) = undeclared {
        assert!(
            !outcome.stdout.contains(&format!("{name}={value}")),
            "未声明的变量 {name} 绝不能进入子进程"
        );
    }
    // 固定 locale：解析器不能受本机语言环境影响。
    assert!(outcome.stdout.contains("LC_ALL=C"));
}

// ---------------------------------------------------------------------------
// 工作目录
// ---------------------------------------------------------------------------

#[test]
fn an_undeclared_working_directory_is_rejected() {
    let echo = require_tool!("echo");
    let runner = runner_with(echo_template());
    let error = runner
        .run(
            &CommandSpec::new("test.echo", echo)
                .arg("hello")
                .cwd(PathBuf::from("/tmp")),
        )
        .expect_err("模板未声明 cwd 时必须失败");
    assert_eq!(error.code(), "platform.command_cwd_rejected");
}

#[test]
fn a_working_directory_outside_every_authorized_root_is_rejected() {
    let echo = require_tool!("echo");
    let root = tempfile::tempdir().expect("临时目录");
    let outside = tempfile::tempdir().expect("临时目录");

    let mut runner = CommandRunner::new();
    runner
        .register(echo_template().with_cwd(CwdPolicy::WithinAuthorizedRoots))
        .expect("注册成功");
    runner
        .authorize_cwd_root(&AuthorizedRoot::open("work", root.path()).expect("打开授权根"))
        .expect("授权成功");

    // 授权根之内：放行。
    let inside = root.path().join("nested");
    std::fs::create_dir(&inside).expect("建目录");
    assert!(runner
        .run(
            &CommandSpec::new("test.echo", echo.clone())
                .arg("hello")
                .cwd(inside)
        )
        .is_ok());

    // 授权根之外：拒绝。
    let error = runner
        .run(
            &CommandSpec::new("test.echo", echo)
                .arg("hello")
                .cwd(outside.path().to_path_buf()),
        )
        .expect_err("越界 cwd 必须失败");
    assert_eq!(error.code(), "platform.command_cwd_rejected");
}

// ---------------------------------------------------------------------------
// stdin / 超时 / 输出上限
// ---------------------------------------------------------------------------

#[test]
fn stdin_is_not_inherited_and_reads_hit_eof_immediately() {
    let cat = require_tool!("cat");
    let runner = runner_with(CommandTemplate::new(
        "test.cat",
        "test-adapter",
        "cat",
        vec![],
    ));
    // `cat` 不带参数就是读 stdin。stdin 若被继承，这里会一直阻塞到超时；
    // 用一个很短的超时把「阻塞」与「立刻 EOF」区分开。
    let outcome = runner
        .run(&CommandSpec::new("test.cat", cat).timeout(Duration::from_secs(5)))
        .expect("stdin 为 null 时 cat 应当立刻 EOF 并退出");
    assert!(
        outcome.success(),
        "退出码应为 0，实际 {:?}",
        outcome.exit_code
    );
    assert!(outcome.stdout.is_empty(), "stdin 是 null，不该有任何输出");
}

#[test]
fn a_command_that_outlives_its_timeout_is_killed() {
    let sleep = require_tool!("sleep");
    let runner = runner_with(CommandTemplate::new(
        "test.sleep",
        "test-adapter",
        "sleep",
        vec![ArgPattern::literal("30")],
    ));
    let started = std::time::Instant::now();
    let error = runner
        .run(
            &CommandSpec::new("test.sleep", sleep)
                .arg("30")
                .timeout(Duration::from_millis(300)),
        )
        .expect_err("超时必须失败");
    assert_eq!(error.code(), "platform.command_timeout");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "必须在超时后立刻终止，而不是等命令自己跑完"
    );
}

#[test]
fn output_beyond_the_limit_stops_the_process_and_marks_truncation() {
    let yes = require_tool!("yes");
    let runner = runner_with(CommandTemplate::new(
        "test.yes",
        "test-adapter",
        "yes",
        vec![],
    ));
    let limit = 64 * 1024;
    let outcome = runner
        .run(
            &CommandSpec::new("test.yes", yes)
                .output_limits(limit, limit)
                // 超时设得远大于预期：真正终止进程的应当是输出上限而不是超时。
                .timeout(Duration::from_secs(30)),
        )
        .expect("输出超限返回 Ok，并标记 truncated");
    assert!(outcome.truncated, "必须标记为已截断");
    assert!(
        outcome.killed_for_output(),
        "必须能识别出是因输出超限被终止"
    );
    assert_eq!(outcome.exit_code, None, "被我们杀掉的进程不该有退出码");
    assert!(
        outcome.stdout.len() <= limit,
        "捕获量必须受上限约束，实际 {} 字节",
        outcome.stdout.len()
    );
}

#[test]
fn output_limits_above_the_hard_cap_are_rejected() {
    let echo = require_tool!("echo");
    let runner = runner_with(echo_template());
    let error = runner
        .run(
            &CommandSpec::new("test.echo", echo)
                .arg("hello")
                .output_limits(MAX_OUTPUT_LIMIT + 1, MAX_OUTPUT_LIMIT),
        )
        .expect_err("超过硬上限必须失败");
    assert_eq!(error.code(), "platform.command_spec_invalid");
}

#[test]
fn a_timeout_longer_than_the_template_allows_is_rejected() {
    let echo = require_tool!("echo");
    let runner = runner_with(echo_template().with_max_timeout(Duration::from_secs(5)));
    let error = runner
        .run(
            &CommandSpec::new("test.echo", echo)
                .arg("hello")
                .timeout(Duration::from_secs(600)),
        )
        .expect_err("超过模板上限的超时必须失败");
    assert_eq!(error.code(), "platform.command_spec_invalid");
}

// ---------------------------------------------------------------------------
// 脱敏
// ---------------------------------------------------------------------------

/// 注入的 canary：既是「秘密」，又足够独特，出现在任何输出里都一定是泄露。
const CANARY: &str = "envsync-canary-9f3a1c7d5e2b4086";

#[test]
fn injected_secrets_are_redacted_from_captured_output() {
    let env = require_tool!("env");
    let runner = runner_with(
        CommandTemplate::new("test.env", "test-adapter", "env", vec![])
            .allow_env_inject("ENVSYNC_TEST_TOKEN"),
    );
    let outcome = runner
        .run(
            &CommandSpec::new("test.env", env)
                .inject_env("ENVSYNC_TEST_TOKEN", SecretEnvValue::new(CANARY)),
        )
        .expect("执行成功");

    assert!(outcome.success());
    // `env` 会把注入的变量原样打出来——这正是脱敏必须生效的地方。
    assert!(
        outcome.stdout.contains("ENVSYNC_TEST_TOKEN=<redacted>"),
        "秘密取值必须被替换：{}",
        outcome.stdout
    );
    assert!(
        !outcome.stdout.contains(CANARY),
        "canary 绝不能出现在捕获输出里"
    );
    assert!(!outcome.stderr.contains(CANARY));

    // 收据同样不含 canary。
    let receipt = outcome.receipt();
    let rendered = format!("{receipt:?}");
    assert!(!rendered.contains(CANARY), "收据里绝不能出现 canary");
}

#[test]
fn secrets_are_redacted_from_stderr_too() {
    // 需要一个「往 stderr 写东西」的程序。`env` 只写 stdout，而 shell 被禁止执行，
    // 所以用 `cat` 读一个不存在的文件：它会把文件名回显进 stderr。
    let cat = require_tool!("cat");
    let runner = runner_with(
        CommandTemplate::new(
            "test.cat-missing",
            "test-adapter",
            "cat",
            vec![ArgPattern::absolute_path("path")],
        )
        .allow_env_inject("ENVSYNC_TEST_TOKEN"),
    );
    // 把 canary 放进文件名：`cat` 会在报错信息里回显它，于是 stderr 里出现秘密。
    let missing = format!("/nonexistent/{CANARY}");
    let outcome = runner
        .run(
            &CommandSpec::new("test.cat-missing", cat)
                .arg(&missing)
                .inject_env("ENVSYNC_TEST_TOKEN", SecretEnvValue::new(CANARY)),
        )
        .expect("执行成功（命令自身失败，但执行本身没问题）");
    assert!(!outcome.success(), "cat 读不存在的文件应当非零退出");
    assert!(
        !outcome.stderr.contains(CANARY),
        "stderr 也必须脱敏：{}",
        outcome.stderr
    );
    assert!(outcome.stderr.contains("<redacted>"));
}

// ---------------------------------------------------------------------------
// 收据
// ---------------------------------------------------------------------------

#[test]
fn the_receipt_records_adapter_template_exit_code_and_timing() {
    let echo = require_tool!("echo");
    let runner = runner_with(echo_template());
    let outcome = runner
        .run(&CommandSpec::new("test.echo", echo).arg("hello"))
        .expect("执行成功");
    let receipt = outcome.receipt();

    assert_eq!(receipt.adapter, "test-adapter");
    assert_eq!(receipt.template_id, "test.echo");
    assert_eq!(receipt.exit_code, Some(0));
    assert!(!receipt.truncated);
    assert!(receipt.started_at_unix_ms > 0);
    assert!(receipt.finished_at_unix_ms >= receipt.started_at_unix_ms);
    assert_eq!(receipt.stdout.line_count, 1);
    assert_eq!(receipt.stdout.head, vec!["hello".to_owned()]);
    assert_eq!(receipt.stdout.omitted_lines, 0);
    assert_eq!(receipt.stderr.line_count, 0);
}

#[test]
fn the_receipt_keeps_only_head_and_tail_of_long_output() {
    let yes = require_tool!("yes");
    let runner = runner_with(CommandTemplate::new(
        "test.yes",
        "test-adapter",
        "yes",
        vec![],
    ));
    let outcome = runner
        .run(
            &CommandSpec::new("test.yes", yes)
                .output_limits(32 * 1024, 32 * 1024)
                .timeout(Duration::from_secs(30)),
        )
        .expect("执行成功");
    let receipt = outcome.receipt();

    assert!(receipt.truncated);
    // 完整输出有上万行，收据里只留头尾。
    assert!(receipt.stdout.line_count > RECEIPT_HEAD_LINES + RECEIPT_TAIL_LINES);
    assert_eq!(receipt.stdout.head.len(), RECEIPT_HEAD_LINES);
    assert_eq!(receipt.stdout.tail.len(), RECEIPT_TAIL_LINES);
    assert!(receipt.stdout.omitted_lines > 0);
    assert_eq!(
        receipt.stdout.head.len() + receipt.stdout.tail.len() + receipt.stdout.omitted_lines,
        receipt.stdout.line_count
    );
}

#[test]
fn a_failing_command_still_produces_a_receipt() {
    let cat = require_tool!("cat");
    let runner = runner_with(CommandTemplate::new(
        "test.cat-missing",
        "test-adapter",
        "cat",
        vec![ArgPattern::absolute_path("path")],
    ));
    let outcome = runner
        .run(&CommandSpec::new("test.cat-missing", cat).arg("/nonexistent/envsync-missing-file"))
        .expect("执行本身成功");
    assert!(!outcome.success());
    assert!(outcome.exit_code.is_some(), "正常退出的进程必须有退出码");
    let receipt = outcome.receipt();
    assert_eq!(receipt.exit_code, outcome.exit_code);
    assert!(receipt.stderr.line_count >= 1);
}

/// [`PlatformError`] 的命令类变体必须有各自稳定的错误码。
#[test]
fn command_error_codes_are_distinct() {
    let errors = [
        PlatformError::CommandTemplateUnknown {
            template_id: "x".to_owned(),
        },
        PlatformError::CommandTemplateDuplicate { template_id: "x" },
        PlatformError::CommandExecutableRejected { reason: "x" },
        PlatformError::CommandShellRejected {
            name: "sh".to_owned(),
        },
        PlatformError::CommandArgRejected {
            index: 0,
            reason: "x",
        },
        PlatformError::CommandEnvRejected {
            name: "X".to_owned(),
            reason: "x",
        },
        PlatformError::CommandCwdRejected { reason: "x" },
        PlatformError::CommandSpecInvalid { reason: "x" },
        PlatformError::CommandTimeout {
            template_id: "x",
            timeout_ms: 1,
        },
    ];
    let mut codes: Vec<&str> = errors.iter().map(PlatformError::code).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), errors.len());

    // 错误信息不得泄露路径或取值。
    for error in &errors {
        let text = error.to_string();
        assert!(!text.contains('/'), "错误信息不得包含路径：{text}");
    }
}
