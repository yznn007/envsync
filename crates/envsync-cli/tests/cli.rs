//! CLI 集成测试：命令面、JSON 契约与退出码。
//!
//! 全部测试都通过 `std::process::Command` 调用真正的二进制，而不是直接调库——退出码、
//! stdout/stderr 分流、clap 的用法错误处理都只在真进程里才成立。

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

use envsync_core::{ResourceConfig, WorkspaceConfig};
use envsync_domain::{DesiredDisposition, FileMode, ResourceId, ResourcePolicy};
use serde_json::Value;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// 测试脚手架
// ---------------------------------------------------------------------------

/// 构造一个指向被测二进制的命令。
fn envsync() -> Command {
    Command::new(env!("CARGO_BIN_EXE_envsync"))
}

/// 运行一次命令并取回结果。
fn run(args: &[&str]) -> Output {
    envsync()
        .args(args)
        .output()
        .expect("应当能够启动 envsync 二进制")
}

/// 退出码；被信号杀死时直接失败。
fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("进程应当正常退出而不是被信号终止")
}

/// stdout 的 UTF-8 文本。
fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout 应当是 UTF-8")
}

/// stderr 的 UTF-8 文本。
fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr 应当是 UTF-8")
}

/// 断言 stdout **只有一行** JSON 并解析它。
///
/// 这是 `--json` 最重要的契约：任何多写一行的日志都会让 `| jq` 失败。
fn json_of(output: &Output) -> Value {
    let text = stdout_of(output);
    let trimmed = text.trim();
    assert_eq!(
        trimmed.lines().count(),
        1,
        "stdout 必须只有一行 JSON，实际是：{text:?}（stderr：{:?}）",
        stderr_of(output)
    );
    assert!(
        trimmed.starts_with('{'),
        "stdout 必须以 `{{` 开头，实际是：{trimmed:?}"
    );
    serde_json::from_str(trimmed).expect("stdout 必须是合法 JSON")
}

/// 取出对象的键集合（`serde_json` 的 Map 是有序的，因此结果稳定）。
fn keys(value: &Value) -> Vec<String> {
    value
        .as_object()
        .expect("应当是 JSON 对象")
        .keys()
        .cloned()
        .collect()
}

/// 一个隔离的工作区：配置、后端、被管理的 home 目录都在同一个临时目录下。
struct Workspace {
    root: TempDir,
}

impl Workspace {
    /// 创建临时目录并跑一次 `init`。
    fn new() -> Self {
        let workspace = Workspace {
            root: TempDir::new().expect("应当能创建临时目录"),
        };
        std::fs::create_dir_all(workspace.home()).expect("应当能创建 home 目录");
        let output = run(&[
            "init",
            "--config",
            &path_arg(&workspace.config()),
            "--backend-path",
            &path_arg(&workspace.backend()),
            "--device-name",
            "laptop",
            "--json",
        ]);
        assert_eq!(code(&output), 0, "init 应当成功：{}", stderr_of(&output));
        workspace
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.path().join(relative)
    }

    fn config(&self) -> PathBuf {
        self.path("ws/envsync.yaml")
    }

    fn home(&self) -> PathBuf {
        self.path("home")
    }

    fn backend(&self) -> PathBuf {
        self.path("backend")
    }

    /// 往配置里追加一个 Full File 资源，并把 `home` 根指向本工作区的 home 目录。
    fn add_resource(&self, id: &str, target: &str) {
        let mut config = WorkspaceConfig::load(&self.config()).expect("配置应当可读");
        config.roots.insert("home".to_owned(), self.home());
        config.resources.push(ResourceConfig {
            id: ResourceId::parse(id).expect("资源标识应当合法"),
            root: "home".to_owned(),
            target: target.to_owned(),
            mode: FileMode::FullFile,
            disposition: DesiredDisposition::Managed,
            policy: ResourcePolicy::default(),
            comment_prefix: "# ".to_owned(),
            // M1 新增：默认是「全局资源、无设备覆盖」。
            selector: None,
            device_overrides: std::collections::BTreeMap::new(),
        });
        self.write_config(&config);
    }

    /// 覆盖写配置文件。
    fn write_config(&self, config: &WorkspaceConfig) {
        std::fs::write(self.config(), config.to_yaml().expect("配置应当可序列化"))
            .expect("应当能写配置文件");
    }

    /// 往 home 目录里写一个文件。
    fn write_home(&self, relative: &str, content: &str) {
        let path = self.home().join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("应当能创建父目录");
        }
        std::fs::write(path, content).expect("应当能写文件");
    }

    /// 读回 home 目录里的文件。
    fn read_home(&self, relative: &str) -> String {
        std::fs::read_to_string(self.home().join(relative)).expect("应当能读文件")
    }

    /// 以 `--json` 运行一个针对本工作区的子命令。
    fn json_command(&self, args: &[&str]) -> Output {
        let config = path_arg(&self.config());
        let mut all: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        all.extend(["--config".to_owned(), config, "--json".to_owned()]);
        envsync()
            .args(&all)
            .output()
            .expect("应当能够启动 envsync 二进制")
    }

    /// 跑一次 `capture`，返回快照标识。
    fn capture(&self) -> String {
        let output = self.json_command(&["capture"]);
        assert_eq!(code(&output), 0, "capture 应当成功：{}", stderr_of(&output));
        json_of(&output)["data"]["snapshot"]
            .as_str()
            .expect("snapshot 是字符串")
            .to_owned()
    }

    /// 跑一次 `plan`，返回计划标识。
    fn plan(&self) -> String {
        let output = self.json_command(&["plan"]);
        assert_eq!(code(&output), 0, "plan 应当成功：{}", stderr_of(&output));
        json_of(&output)["data"]["plan"]
            .as_str()
            .expect("plan 是字符串")
            .to_owned()
    }
}

/// 路径转命令行参数。
fn path_arg(path: &Path) -> String {
    path.to_str().expect("测试路径应当是 UTF-8").to_owned()
}

// ---------------------------------------------------------------------------
// 帮助文本与用法错误
// ---------------------------------------------------------------------------

/// 全部子命令，顺序与 `--help` 中一致。
const SUBCOMMANDS: [&str; 8] = [
    "init", "capture", "plan", "sync", "status", "rollback", "doctor", "recover",
];

#[test]
fn top_level_help_exits_zero() {
    let output = run(&["--help"]);
    assert_eq!(code(&output), 0);
    let text = stdout_of(&output);
    for name in SUBCOMMANDS {
        assert!(text.contains(name), "顶层帮助应当列出 `{name}`：{text}");
    }
}

#[test]
fn every_subcommand_has_help() {
    for name in SUBCOMMANDS {
        let output = run(&[name, "--help"]);
        assert_eq!(code(&output), 0, "`{name} --help` 应当退出 0");
        let text = stdout_of(&output);
        assert!(
            text.contains("--config"),
            "`{name} --help` 应当说明 --config：{text}"
        );
        assert!(
            text.contains("--json"),
            "`{name} --help` 应当说明 --json：{text}"
        );
    }
}

#[test]
fn missing_required_arguments_exit_two() {
    // 缺 --config。
    for name in SUBCOMMANDS {
        let output = run(&[name]);
        assert_eq!(
            code(&output),
            2,
            "`{name}` 缺少必需参数时应当退出 2：{}",
            stderr_of(&output)
        );
    }

    // 缺子命令专属的必需参数。
    assert_eq!(code(&run(&["init", "--config", "x.yaml"])), 2);
    assert_eq!(code(&run(&["sync", "--config", "x.yaml"])), 2);
    assert_eq!(code(&run(&["rollback", "--config", "x.yaml"])), 2);

    // 参数值非法同样是用法错误。
    assert_eq!(
        code(&run(&["sync", "--config", "x.yaml", "--plan", "不是摘要"])),
        2
    );
    assert_eq!(
        code(&run(&[
            "rollback",
            "--config",
            "x.yaml",
            "--operation",
            "not-a-uuid"
        ])),
        2
    );

    // 未知子命令与未知参数。
    assert_eq!(code(&run(&["nope", "--config", "x.yaml"])), 2);
    assert_eq!(code(&run(&["status", "--config", "x.yaml", "--nope"])), 2);
}

// ---------------------------------------------------------------------------
// 完整流程
// ---------------------------------------------------------------------------

#[test]
fn full_workflow_init_capture_plan_sync_status() {
    let workspace = Workspace::new();
    workspace.add_resource("shell/zsh/main", ".zshrc");
    workspace.write_home(".zshrc", "export EDITOR=nvim\n");

    // capture：生成快照草稿，不碰后端。
    let capture = workspace.json_command(&["capture"]);
    assert_eq!(code(&capture), 0, "{}", stderr_of(&capture));
    let capture_json = json_of(&capture);
    assert_eq!(capture_json["command"], "capture");
    assert_eq!(capture_json["status"], "ok");
    assert_eq!(capture_json["data"]["changed"], true);
    let snapshot = capture_json["data"]["snapshot"]
        .as_str()
        .expect("snapshot 是字符串")
        .to_owned();
    assert_eq!(snapshot.len(), 64, "快照标识是 64 位十六进制");

    // 本地漂移：文件被改动，计划应当把它改回去。
    workspace.write_home(".zshrc", "export EDITOR=vim\n");

    let plan = workspace.json_command(&["plan"]);
    assert_eq!(code(&plan), 0, "{}", stderr_of(&plan));
    let plan_json = json_of(&plan);
    assert_eq!(plan_json["data"]["action_count"], 1);
    assert_eq!(plan_json["data"]["blocked"], false);
    assert_eq!(plan_json["data"]["base_revision"], 0);
    assert_eq!(plan_json["data"]["next_revision"], 1);
    assert_eq!(plan_json["data"]["target_snapshot"], snapshot.as_str());
    let action = &plan_json["data"]["actions"][0];
    assert_eq!(action["resource"], "shell/zsh/main");
    assert_eq!(action["kind"], "replace_file");
    assert_eq!(action["target"], "home:.zshrc");
    let plan_id = plan_json["data"]["plan"]
        .as_str()
        .expect("plan 是字符串")
        .to_owned();

    // sync：发布到后端并让本机收敛。
    let sync = workspace.json_command(&["sync", "--plan", &plan_id]);
    assert_eq!(code(&sync), 0, "sync 应当成功：{}", stderr_of(&sync));
    let sync_json = json_of(&sync);
    assert_eq!(sync_json["command"], "sync");
    assert_eq!(sync_json["status"], "ok");
    assert_eq!(sync_json["data"]["outcome"], "completed");
    assert_eq!(sync_json["data"]["applied"], 1);
    assert_eq!(sync_json["data"]["published"], true);
    assert!(sync_json["data"]["operation"].is_string());
    assert_eq!(
        workspace.read_home(".zshrc"),
        "export EDITOR=nvim\n",
        "本机文件应当被改回快照内容"
    );

    // status：收敛之后应当是 clean。
    let status = workspace.json_command(&["status"]);
    assert_eq!(code(&status), 0, "{}", stderr_of(&status));
    let status_json = json_of(&status);
    assert_eq!(status_json["data"]["state"], "clean");
    assert_eq!(status_json["data"]["revision"], 1);
    assert_eq!(status_json["data"]["head"], snapshot.as_str());
    assert!(status_json["data"]["draft_head"].is_null());
    assert_eq!(status_json["data"]["pending_actions"], 0);
    assert_eq!(status_json["data"]["resources"][0]["needs_action"], false);
    assert!(status_json["data"]["unfinished"]
        .as_array()
        .expect("unfinished 是数组")
        .is_empty());

    // doctor：只读体检应当全绿。
    let doctor = workspace.json_command(&["doctor"]);
    assert_eq!(code(&doctor), 0, "{}", stderr_of(&doctor));
    assert_eq!(json_of(&doctor)["data"]["healthy"], true);

    // recover：没有未完成操作时是幂等空转。
    let recover = workspace.json_command(&["recover"]);
    assert_eq!(code(&recover), 0, "{}", stderr_of(&recover));
    assert_eq!(json_of(&recover)["data"]["handled"], 0);
}

// ---------------------------------------------------------------------------
// JSON 契约
// ---------------------------------------------------------------------------

#[test]
fn status_json_shape_is_locked() {
    let workspace = Workspace::new();
    workspace.add_resource("shell/zsh/main", ".zshrc");
    workspace.write_home(".zshrc", "export EDITOR=nvim\n");
    workspace.capture();

    let output = workspace.json_command(&["status"]);
    assert_eq!(code(&output), 0, "{}", stderr_of(&output));
    let value = json_of(&output);

    // 信封：字段集合固定，改动必须是有意识的 schema 变更。
    assert_eq!(
        keys(&value),
        ["command", "data", "diagnostics", "schema_version", "status"]
    );
    // M1 起默认输出 schema v2；v1 形状由 `--schema-version 1` 显式请求（见 m1_cli.rs）。
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["command"], "status");
    assert_eq!(value["status"], "ok");

    // data：字段集合固定。
    assert_eq!(
        keys(&value["data"]),
        [
            "backend_kind",
            // 后端不可达时的降级作答标记（schema v2 新增）：为 false 时
            // revision/head 是本地记录的上次已知状态，而不是远端此刻的内容。
            "backend_reachable",
            "device",
            "draft_head",
            "head",
            // 这份「上次已知状态」有多旧；后端可达时为 null（schema v2 新增）。
            "last_known_revision_at_unix_ms",
            // M1（schema v2）新增；v1 形状里没有它，见 m1_cli.rs 的 golden 测试。
            "open_conflicts",
            "pending_actions",
            "resources",
            "revision",
            "state",
            "unfinished",
            "workspace",
        ]
    );

    // 逐资源条目：字段集合固定。
    assert_eq!(
        keys(&value["data"]["resources"][0]),
        ["disposition", "needs_action", "observed", "resource"]
    );

    // 取值的取值域也锁住，避免枚举被悄悄改名。
    assert_eq!(value["data"]["backend_kind"], "local");
    assert_eq!(value["data"]["state"], "drifted");
    assert_eq!(value["data"]["resources"][0]["observed"], "present");
    assert_eq!(value["data"]["resources"][0]["disposition"], "managed");
}

#[test]
fn diagnostics_have_a_fixed_shape() {
    let workspace = Workspace::new();
    // 目标文件不存在：capture 会留下一条 warning 级诊断。
    workspace.add_resource("shell/zsh/main", ".zshrc");

    let output = workspace.json_command(&["capture"]);
    assert_eq!(code(&output), 0, "{}", stderr_of(&output));
    let value = json_of(&output);

    let diagnostics = value["diagnostics"]
        .as_array()
        .expect("diagnostics 是数组")
        .clone();
    assert!(!diagnostics.is_empty(), "缺文件时应当有诊断");
    assert_eq!(
        keys(&diagnostics[0]),
        ["code", "message", "resource", "severity"]
    );
    assert_eq!(diagnostics[0]["severity"], "warning");
    assert_eq!(diagnostics[0]["resource"], "shell/zsh/main");
}

#[test]
fn failure_envelope_keeps_the_same_shape() {
    let workspace = Workspace::new();
    let missing_plan = "0".repeat(64);

    let output = workspace.json_command(&["sync", "--plan", &missing_plan]);
    assert_ne!(code(&output), 0);
    let value = json_of(&output);

    assert_eq!(
        keys(&value),
        ["command", "data", "diagnostics", "schema_version", "status"]
    );
    assert_eq!(value["status"], "error");
    assert!(value["data"].is_null(), "失败时 data 必须是 null");
    let diagnostics = value["diagnostics"].as_array().expect("diagnostics 是数组");
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0]["severity"], "blocking");
    assert!(
        diagnostics[0]["code"].is_string(),
        "失败诊断必须带稳定错误码"
    );
}

#[test]
fn logs_never_pollute_json_stdout() {
    let workspace = Workspace::new();
    workspace.add_resource("shell/zsh/main", ".zshrc");
    workspace.write_home(".zshrc", "export EDITOR=nvim\n");

    // `-vvv` 打开 trace 级日志；stdout 仍然只能有一行 JSON。
    let output = envsync()
        .args([
            "-vvv",
            "--json",
            "capture",
            "--config",
            &path_arg(&workspace.config()),
        ])
        .output()
        .expect("应当能够启动 envsync 二进制");
    assert_eq!(code(&output), 0, "{}", stderr_of(&output));
    json_of(&output);
}

#[test]
fn global_flags_work_before_and_after_the_subcommand() {
    let workspace = Workspace::new();
    let config = path_arg(&workspace.config());

    let before = envsync()
        .args(["--json", "status", "--config", &config])
        .output()
        .expect("应当能够启动 envsync 二进制");
    let after = envsync()
        .args(["status", "--config", &config, "--json"])
        .output()
        .expect("应当能够启动 envsync 二进制");

    assert_eq!(code(&before), 0, "{}", stderr_of(&before));
    assert_eq!(code(&after), 0, "{}", stderr_of(&after));
    assert_eq!(json_of(&before)["command"], json_of(&after)["command"]);
}

#[test]
fn human_output_goes_to_stdout_and_errors_to_stderr() {
    let workspace = Workspace::new();
    workspace.add_resource("shell/zsh/main", ".zshrc");
    workspace.write_home(".zshrc", "export EDITOR=nvim\n");

    let ok = run(&["capture", "--config", &path_arg(&workspace.config())]);
    assert_eq!(code(&ok), 0, "{}", stderr_of(&ok));
    assert!(
        stdout_of(&ok).contains("快照"),
        "人类可读输出应当写 stdout：{:?}",
        stdout_of(&ok)
    );

    let failed = run(&[
        "sync",
        "--config",
        &path_arg(&workspace.config()),
        "--plan",
        &"0".repeat(64),
    ]);
    assert_ne!(code(&failed), 0);
    assert!(
        stdout_of(&failed).is_empty(),
        "失败时 stdout 必须为空：{:?}",
        stdout_of(&failed)
    );
    assert!(
        stderr_of(&failed).contains("错误码："),
        "失败说明应当写 stderr：{:?}",
        stderr_of(&failed)
    );
}

// ---------------------------------------------------------------------------
// 退出码
// ---------------------------------------------------------------------------

#[test]
fn unknown_plan_id_exits_11() {
    let workspace = Workspace::new();
    workspace.add_resource("shell/zsh/main", ".zshrc");
    workspace.write_home(".zshrc", "export EDITOR=nvim\n");
    workspace.capture();

    let output = workspace.json_command(&["sync", "--plan", &"a".repeat(64)]);
    assert_eq!(
        code(&output),
        11,
        "不存在的计划标识应当退出 11：{}",
        stderr_of(&output)
    );
    assert_eq!(json_of(&output)["diagnostics"][0]["code"], "plan.not_found");
}

#[test]
fn stale_plan_exits_11() {
    let workspace = Workspace::new();
    workspace.add_resource("shell/zsh/main", ".zshrc");
    workspace.write_home(".zshrc", "export EDITOR=nvim\n");
    workspace.capture();
    workspace.write_home(".zshrc", "export EDITOR=vim\n");
    let plan_id = workspace.plan();

    // 生成计划之后文件又被外部改了一次：重新计划的结果不同，计划失效。
    workspace.write_home(".zshrc", "export EDITOR=emacs\n");

    let output = workspace.json_command(&["sync", "--plan", &plan_id]);
    assert_eq!(
        code(&output),
        11,
        "计划失效应当退出 11：{}",
        stderr_of(&output)
    );
    assert_eq!(json_of(&output)["diagnostics"][0]["code"], "plan.stale");
    assert_eq!(
        workspace.read_home(".zshrc"),
        "export EDITOR=emacs\n",
        "计划失效时不得写入任何文件"
    );
}

#[test]
fn blocking_diagnostic_exits_12() {
    let workspace = Workspace::new();
    workspace.add_resource("shell/zsh/main", ".zshrc");
    workspace.write_home(".zshrc", "export EDITOR=nvim\n");
    workspace.capture();

    // 把目标做成目录：观察结果变为 unreadable，计划里出现阻塞诊断。
    std::fs::remove_file(workspace.home().join(".zshrc")).expect("应当能删除文件");
    std::fs::create_dir(workspace.home().join(".zshrc")).expect("应当能创建目录");

    let plan = workspace.json_command(&["plan"]);
    assert_eq!(code(&plan), 0, "{}", stderr_of(&plan));
    let plan_json = json_of(&plan);
    assert_eq!(plan_json["data"]["blocked"], true);
    assert_eq!(plan_json["data"]["action_count"], 0);
    assert_eq!(plan_json["diagnostics"][0]["severity"], "blocking");
    let plan_id = plan_json["data"]["plan"]
        .as_str()
        .expect("plan 是字符串")
        .to_owned();

    let output = workspace.json_command(&["sync", "--plan", &plan_id]);
    assert_eq!(
        code(&output),
        12,
        "策略阻塞应当退出 12：{}",
        stderr_of(&output)
    );
    assert_eq!(json_of(&output)["diagnostics"][0]["code"], "plan.blocked");
}

#[test]
fn cas_conflict_exits_10() {
    // 两台「设备」共享同一个后端与同一个 workspace_id，各自持有一份在同一 revision 上
    // 生成的计划。谁先拿到后端锁谁赢，另一台必须以 CAS 冲突失败，且一个字节都不写。
    let first = Workspace::new();
    first.add_resource("shell/zsh/main", ".zshrc");
    first.write_home(".zshrc", "第一台设备\n");

    let second = TempDir::new().expect("应当能创建临时目录");
    let second_home = second.path().join("home");
    let second_config_path = second.path().join("envsync.yaml");
    std::fs::create_dir_all(&second_home).expect("应当能创建 home 目录");
    std::fs::write(second_home.join(".zshrc"), "第二台设备\n").expect("应当能写文件");

    let mut second_config = WorkspaceConfig::load(&first.config()).expect("配置应当可读");
    second_config.device.name = "desktop".to_owned();
    second_config.device.seed_hex = "b".repeat(64);
    second_config.state_dir = second.path().join(".envsync");
    second_config
        .roots
        .insert("home".to_owned(), second_home.clone());
    std::fs::write(
        &second_config_path,
        second_config.to_yaml().expect("配置应当可序列化"),
    )
    .expect("应当能写配置文件");

    let workspace_id = second_config.workspace_id.to_string();
    let second_config_arg = path_arg(&second_config_path);

    // 两台设备各自 capture + plan，此时后端 revision 都还是 0。
    first.capture();
    let first_plan = first.plan();

    let capture = run(&["capture", "--config", &second_config_arg, "--json"]);
    assert_eq!(code(&capture), 0, "{}", stderr_of(&capture));
    let plan = run(&["plan", "--config", &second_config_arg, "--json"]);
    assert_eq!(code(&plan), 0, "{}", stderr_of(&plan));
    let second_plan = json_of(&plan)["data"]["plan"]
        .as_str()
        .expect("plan 是字符串")
        .to_owned();

    // 先占住后端的 per-workspace 锁，让两个 sync 都停在 CAS 之前——这样它们的重新
    // 计划都发生在 revision 0 上，谁输谁赢由锁决定，而不是由启动顺序决定。
    let objects_dir = first.backend().join("objects");
    let lock_path = first
        .backend()
        .join("locks")
        .join(format!("{workspace_id}.lock"));
    std::fs::create_dir_all(lock_path.parent().expect("锁目录有父目录")).expect("应当能创建锁目录");
    std::fs::write(&lock_path, "held by test\n").expect("应当能写锁文件");

    let first_child = spawn_sync(&path_arg(&first.config()), &first_plan);
    wait_for_objects(&objects_dir, 4);
    let second_child = spawn_sync(&second_config_arg, &second_plan);
    wait_for_objects(&objects_dir, 8);

    std::fs::remove_file(&lock_path).expect("应当能释放锁");

    let first_output = first_child.wait_with_output().expect("第一台设备应当退出");
    let second_output = second_child.wait_with_output().expect("第二台设备应当退出");

    let mut codes = [code(&first_output), code(&second_output)];
    codes.sort_unstable();
    assert_eq!(
        codes,
        [0, 10],
        "恰好一台设备成功，另一台以 CAS 冲突退出\n第一台 stdout：{}\n第一台 stderr：{}\n第二台 stdout：{}\n第二台 stderr：{}",
        stdout_of(&first_output),
        stderr_of(&first_output),
        stdout_of(&second_output),
        stderr_of(&second_output),
    );

    let loser = if code(&first_output) == 10 {
        &first_output
    } else {
        &second_output
    };
    assert_eq!(
        json_of(loser)["diagnostics"][0]["code"],
        "backend.cas_conflict"
    );
}

/// 后台启动一次 `sync`。
fn spawn_sync(config: &str, plan: &str) -> Child {
    envsync()
        .args(["sync", "--config", config, "--plan", plan, "--json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("应当能够启动 envsync 二进制")
}

/// 等待后端对象库里至少出现 `expected` 个对象。
///
/// 对象上传发生在 CAS 之前，因此「对象已到齐」就意味着该进程已经完成重新计划、
/// 正卡在锁上等待发布。
fn wait_for_objects(objects_dir: &Path, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if count_files(objects_dir) >= expected {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "等待后端对象超时：期望至少 {expected} 个，实际 {}",
        count_files(objects_dir)
    );
}

/// 递归统计目录下的文件数量。
fn count_files(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut total = 0;
    for entry in entries.flatten() {
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => total += count_files(&entry.path()),
            Ok(_) => total += 1,
            Err(_) => {}
        }
    }
    total
}

// ---------------------------------------------------------------------------
// 其他命令
// ---------------------------------------------------------------------------

#[test]
fn init_refuses_to_overwrite_an_existing_workspace() {
    let workspace = Workspace::new();
    let output = run(&[
        "init",
        "--config",
        &path_arg(&workspace.config()),
        "--backend-path",
        &path_arg(&workspace.backend()),
        "--json",
    ]);
    assert_eq!(code(&output), 1, "重复 init 应当以一般错误退出");
    let value = json_of(&output);
    assert_eq!(value["status"], "error");
    assert_eq!(
        value["diagnostics"][0]["code"], "recovery.manual_required",
        "重复 init 应当带稳定错误码"
    );
}

#[test]
fn missing_config_file_is_reported_with_a_stable_code() {
    let output = run(&["status", "--config", "/definitely/not/here.yaml", "--json"]);
    assert_eq!(code(&output), 1);
    assert_eq!(json_of(&output)["diagnostics"][0]["code"], "config.io");
}

#[test]
fn rollback_restores_the_previous_content() {
    let workspace = Workspace::new();
    workspace.add_resource("shell/zsh/main", ".zshrc");
    workspace.write_home(".zshrc", "export EDITOR=nvim\n");
    workspace.capture();
    workspace.write_home(".zshrc", "export EDITOR=vim\n");
    let plan_id = workspace.plan();

    let sync = workspace.json_command(&["sync", "--plan", &plan_id]);
    assert_eq!(code(&sync), 0, "{}", stderr_of(&sync));
    let operation = json_of(&sync)["data"]["operation"]
        .as_str()
        .expect("operation 是字符串")
        .to_owned();
    assert_eq!(workspace.read_home(".zshrc"), "export EDITOR=nvim\n");

    let rollback = workspace.json_command(&["rollback", "--operation", &operation]);
    assert_eq!(code(&rollback), 0, "{}", stderr_of(&rollback));
    let value = json_of(&rollback);
    assert_eq!(value["data"]["handled"], 1);
    assert_eq!(value["data"]["operations"][0]["after"], "rolled_back");
    assert_eq!(
        workspace.read_home(".zshrc"),
        "export EDITOR=vim\n",
        "回滚应当恢复应用前的内容"
    );
}

#[test]
fn doctor_json_shape_is_locked() {
    let workspace = Workspace::new();
    workspace.add_resource("shell/zsh/main", ".zshrc");
    workspace.write_home(".zshrc", "export EDITOR=nvim\n");

    let output = workspace.json_command(&["doctor"]);
    assert_eq!(code(&output), 0, "doctor 只报告，本身应当成功");
    let value = json_of(&output);
    assert_eq!(
        keys(&value["data"]),
        ["findings", "healthy", "recovery"],
        "doctor 的字段集合是对外契约"
    );
    assert_eq!(
        keys(&value["data"]["findings"][0]),
        ["check", "detail", "ok"]
    );
    assert_eq!(value["data"]["healthy"], true);
    assert!(value["data"]["recovery"]
        .as_array()
        .expect("recovery 是数组")
        .is_empty());
}
