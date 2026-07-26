//! M1 CLI 验收：新命令的帮助与 JSON 形状、冲突退出码、schema v1/v2 golden。
//!
//! 与 `cli.rs` 一样，全部测试都通过 `std::process::Command` 调用真正的二进制：
//! 退出码、stdout/stderr 分流与 clap 的用法错误只在真进程里才成立。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use envsync_core::{ResourceConfig, WorkspaceConfig};
use envsync_domain::{DesiredDisposition, FileMode, ResourceId, ResourcePolicy, StructuredFormat};
use serde_json::Value;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// 脚手架
// ---------------------------------------------------------------------------

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_envsync"))
        .args(args)
        .output()
        .expect("应当能够启动 envsync 二进制")
}

fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("进程应当正常退出而不是被信号终止")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout 应当是 UTF-8")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr 应当是 UTF-8")
}

/// 断言 stdout 只有一行 JSON 并解析它。
fn json_of(output: &Output) -> Value {
    let text = stdout_of(output);
    let trimmed = text.trim();
    assert_eq!(
        trimmed.lines().count(),
        1,
        "stdout 必须只有一行 JSON，实际是：{text:?}（stderr：{:?}）",
        stderr_of(output)
    );
    serde_json::from_str(trimmed).expect("stdout 必须是合法 JSON")
}

fn keys(value: &Value) -> Vec<String> {
    value
        .as_object()
        .expect("应当是 JSON 对象")
        .keys()
        .cloned()
        .collect()
}

fn path_arg(path: &Path) -> String {
    path.to_str().expect("测试路径应当是 UTF-8").to_owned()
}

/// 一个共享后端 + 两台设备的世界。
struct World {
    root: TempDir,
}

impl World {
    fn new() -> Self {
        World {
            root: TempDir::new().expect("应当能创建临时目录"),
        }
    }

    fn backend(&self) -> PathBuf {
        self.root.path().join("backend")
    }

    /// 初始化一台设备；第二台设备复用第一台的工作区标识与后端。
    fn device(&self, name: &str, share_with: Option<&Device>) -> Device {
        let home = self.root.path().join(name).join("home");
        let config = self.root.path().join(name).join("envsync.yaml");
        std::fs::create_dir_all(&home).expect("应当能创建 home 目录");

        let output = run(&[
            "init",
            "--config",
            &path_arg(&config),
            "--backend-path",
            &path_arg(&self.backend()),
            "--device-name",
            name,
            "--json",
        ]);
        assert_eq!(code(&output), 0, "init 应当成功：{}", stderr_of(&output));

        let device = Device { home, config };
        let mut loaded = device.config();
        loaded.roots.insert("home".to_owned(), device.home.clone());
        if let Some(first) = share_with {
            // 同一个工作区的第二台设备：工作区标识必须一致，设备种子必须不同。
            loaded.workspace_id = first.config().workspace_id;
        }
        loaded.resources = vec![
            resource("shell/zsh/main", ".zshrc", None),
            resource(
                "git/config",
                ".gitconfig",
                Some(StructuredFormat::GitConfig),
            ),
        ];
        device.write_config(&loaded);
        device
    }
}

fn resource(id: &str, target: &str, format: Option<StructuredFormat>) -> ResourceConfig {
    ResourceConfig {
        id: ResourceId::parse(id).expect("资源标识应当合法"),
        root: "home".to_owned(),
        target: target.to_owned(),
        mode: FileMode::FullFile,
        disposition: DesiredDisposition::Managed,
        policy: ResourcePolicy {
            structured_format: format,
            ..ResourcePolicy::default()
        },
        comment_prefix: "# ".to_owned(),
        selector: None,
        device_overrides: BTreeMap::new(),
    }
}

struct Device {
    home: PathBuf,
    config: PathBuf,
}

impl Device {
    fn config(&self) -> WorkspaceConfig {
        WorkspaceConfig::load(&self.config).expect("配置应当可读")
    }

    fn write_config(&self, config: &WorkspaceConfig) {
        std::fs::write(&self.config, config.to_yaml().expect("配置应当可序列化"))
            .expect("应当能写配置文件");
    }

    fn write(&self, target: &str, content: &str) {
        std::fs::write(self.home.join(target), content).expect("应当能写入 home 文件");
    }

    fn read(&self, target: &str) -> String {
        std::fs::read_to_string(self.home.join(target)).expect("应当能读取 home 文件")
    }

    /// 运行一条命令（自动补上 `--config` 与 `--json`）。
    fn json(&self, args: &[&str]) -> Output {
        let config = path_arg(&self.config);
        let mut full: Vec<&str> = args.to_vec();
        full.extend_from_slice(&["--config", &config, "--json"]);
        run(&full)
    }

    /// capture → plan → sync 的完整一轮。
    fn capture_plan_sync(&self) {
        let capture = self.json(&["capture"]);
        assert_eq!(code(&capture), 0, "{}", stderr_of(&capture));
        self.plan_sync();
    }

    fn plan_sync(&self) {
        let plan = self.json(&["plan"]);
        assert_eq!(code(&plan), 0, "{}", stderr_of(&plan));
        let plan_id = json_of(&plan)["data"]["plan"]
            .as_str()
            .expect("plan 输出里应当有计划标识")
            .to_owned();
        let sync = self.json(&["sync", "--plan", &plan_id]);
        assert_eq!(code(&sync), 0, "{}", stderr_of(&sync));
    }
}

/// 把两台设备推进到「同一个 git config key 上双方改动不同」的状态。
fn world_with_conflict() -> (World, Device, Device) {
    let world = World::new();
    let alice = world.device("alice", None);
    let bob = world.device("bob", Some(&alice));

    alice.write(".zshrc", "export EDITOR=nvim\n");
    alice.write(".gitconfig", "[user]\n\temail = base@example.com\n");
    alice.capture_plan_sync();

    assert_eq!(code(&bob.json(&["fetch"])), 0);
    bob.plan_sync();

    // B 先捕获（父快照仍是共同 base），A 随后发布，两条历史真正分叉。
    bob.write(".gitconfig", "[user]\n\temail = bob@example.com\n");
    assert_eq!(code(&bob.json(&["capture"])), 0);

    alice.write(".gitconfig", "[user]\n\temail = alice@example.com\n");
    alice.capture_plan_sync();

    (world, alice, bob)
}

// ---------------------------------------------------------------------------
// 命令面：--help
// ---------------------------------------------------------------------------

#[test]
fn new_commands_expose_help() {
    for args in [
        vec!["fetch", "--help"],
        vec!["merge", "--help"],
        vec!["conflicts", "--help"],
        vec!["conflicts", "list", "--help"],
        vec!["conflicts", "show", "--help"],
        vec!["conflicts", "resolve", "--help"],
        vec!["profile", "--help"],
        vec!["profile", "explain", "--help"],
    ] {
        let output = run(&args);
        assert_eq!(code(&output), 0, "`{args:?}` 的帮助应当成功");
        assert!(
            !stdout_of(&output).trim().is_empty(),
            "`{args:?}` 应当输出帮助文本"
        );
    }
}

#[test]
fn conflicts_resolve_help_lists_all_choices() {
    let help = stdout_of(&run(&["conflicts", "resolve", "--help"]));
    for flag in ["--ours", "--theirs", "--file", "--delete"] {
        assert!(help.contains(flag), "帮助里应当出现 `{flag}`");
    }
}

#[test]
fn conflicts_resolve_without_a_choice_is_a_usage_error() {
    let world = World::new();
    let alice = world.device("alice", None);
    let output = run(&[
        "conflicts",
        "resolve",
        "--config",
        &path_arg(&alice.config),
        "--conflict",
        &"0".repeat(64),
    ]);
    assert_eq!(code(&output), 2, "缺少裁决方式是用法错误");
}

// ---------------------------------------------------------------------------
// JSON 形状
// ---------------------------------------------------------------------------

#[test]
fn fetch_and_profile_and_conflicts_have_stable_json_shapes() {
    let world = World::new();
    let alice = world.device("alice", None);
    alice.write(".zshrc", "export EDITOR=nvim\n");
    alice.write(".gitconfig", "[user]\n\temail = a@example.com\n");
    alice.capture_plan_sync();

    let fetch = alice.json(&["fetch"]);
    assert_eq!(code(&fetch), 0, "{}", stderr_of(&fetch));
    let value = json_of(&fetch);
    assert_eq!(value["command"], "fetch");
    assert_eq!(value["schema_version"], 2);
    assert_eq!(
        keys(&value["data"]),
        ["head", "objects", "revision", "up_to_date"]
    );

    let merge = alice.json(&["merge"]);
    assert_eq!(code(&merge), 0, "{}", stderr_of(&merge));
    let value = json_of(&merge);
    assert_eq!(
        keys(&value["data"]),
        [
            "base",
            "conflicts",
            "local",
            "merged",
            "outcome",
            "remote",
            "resources",
            "state_root",
        ]
    );

    let profile = alice.json(&["profile", "explain"]);
    assert_eq!(code(&profile), 0, "{}", stderr_of(&profile));
    let value = json_of(&profile);
    assert_eq!(value["command"], "profile.explain");
    assert_eq!(
        keys(&value["data"]),
        [
            "arch",
            "capabilities",
            "device",
            "device_view",
            "hostname",
            "os",
            "resources",
            "state_root",
            "tags",
        ]
    );
    assert_eq!(
        keys(&value["data"]["resources"][0]),
        ["detail", "included", "kind", "resource"]
    );
    assert_eq!(
        value["data"]["resources"][0]["kind"], "selected_by_global",
        "没有选择器的资源是全局资源"
    );

    let conflicts = alice.json(&["conflicts", "list"]);
    assert_eq!(code(&conflicts), 0, "{}", stderr_of(&conflicts));
    let value = json_of(&conflicts);
    assert_eq!(value["command"], "conflicts.list");
    assert_eq!(keys(&value["data"]), ["conflicts", "open"]);
    assert_eq!(value["data"]["open"], 0);
}

// ---------------------------------------------------------------------------
// 冲突路径：退出码 13
// ---------------------------------------------------------------------------

#[test]
fn conflicted_sync_exits_13_and_changes_nothing() {
    let (_world, _alice, bob) = world_with_conflict();

    assert_eq!(code(&bob.json(&["fetch"])), 0);
    let merge = bob.json(&["merge"]);
    assert_eq!(code(&merge), 0, "merge 本身成功返回：{}", stderr_of(&merge));
    let merged = json_of(&merge);
    assert_eq!(merged["data"]["outcome"], "conflicted");
    assert!(merged["data"]["merged"].is_null(), "冲突时不生成快照");
    let conflict = merged["data"]["conflicts"][0]
        .as_str()
        .expect("应当登记了一个冲突")
        .to_owned();

    // 列表与详情都能看到它。
    let listed = bob.json(&["conflicts", "list"]);
    assert_eq!(json_of(&listed)["data"]["open"], 1);
    let shown = bob.json(&["conflicts", "show", "--conflict", &conflict]);
    assert_eq!(code(&shown), 0, "{}", stderr_of(&shown));
    let detail = json_of(&shown);
    assert_eq!(detail["data"]["resource"], "git/config");
    assert_eq!(detail["data"]["state"], "open");

    // 存在冲突时 sync 必须退出 13，且什么都不动。
    let before = bob.read(".gitconfig");
    let sync = bob.json(&["sync", "--plan", &"0".repeat(64)]);
    assert_eq!(code(&sync), 13, "冲突路径必须是退出码 13");
    let value = json_of(&sync);
    assert_eq!(value["status"], "error");
    assert!(value["data"].is_null());
    assert_eq!(value["diagnostics"][0]["code"], "sync.conflicted");
    assert_eq!(bob.read(".gitconfig"), before, "本地文件不得被改动");

    // status 也应当把工作区标成 conflicted。
    let status = bob.json(&["status"]);
    assert_eq!(json_of(&status)["data"]["state"], "conflicted");
    assert_eq!(json_of(&status)["data"]["open_conflicts"], 1);

    // 裁决之后可以重新合并并同步完成。
    let resolved = bob.json(&["conflicts", "resolve", "--conflict", &conflict, "--theirs"]);
    assert_eq!(code(&resolved), 0, "{}", stderr_of(&resolved));
    assert_eq!(
        keys(&json_of(&resolved)["data"]),
        ["choice", "conflict", "resolved_blob"]
    );

    let merge = bob.json(&["merge"]);
    assert_eq!(code(&merge), 0, "{}", stderr_of(&merge));
    assert_eq!(json_of(&merge)["data"]["outcome"], "merged");
    bob.plan_sync();
    assert!(bob.read(".gitconfig").contains("alice@example.com"));
}

// ---------------------------------------------------------------------------
// schema v1 / v2 golden
// ---------------------------------------------------------------------------

#[test]
fn schema_v2_is_the_default_and_v1_drops_new_fields() {
    let world = World::new();
    let alice = world.device("alice", None);
    alice.write(".zshrc", "export EDITOR=nvim\n");
    alice.write(".gitconfig", "[user]\n\temail = a@example.com\n");
    assert_eq!(code(&alice.json(&["capture"])), 0);

    let config = path_arg(&alice.config);

    // v2（默认）：status 带 open_conflicts，plan 带 device_view。
    let v2_status = json_of(&run(&["status", "--config", &config, "--json"]));
    assert_eq!(v2_status["schema_version"], 2);
    assert_eq!(
        keys(&v2_status["data"]),
        [
            "backend_kind",
            "backend_reachable",
            "device",
            "draft_head",
            "head",
            "last_known_revision_at_unix_ms",
            "open_conflicts",
            "pending_actions",
            "resources",
            "revision",
            "state",
            "unfinished",
            "workspace",
        ]
    );

    let v2_plan = json_of(&run(&["plan", "--config", &config, "--json"]));
    assert_eq!(
        keys(&v2_plan["data"]),
        [
            "action_count",
            "actions",
            "base_revision",
            "blocked",
            "device_view",
            "next_revision",
            "plan",
            "target_snapshot",
        ]
    );

    // v1：字段集合退回 M0 的形状。
    let v1_status = json_of(&run(&[
        "status",
        "--config",
        &config,
        "--json",
        "--schema-version",
        "1",
    ]));
    assert_eq!(v1_status["schema_version"], 1);
    assert_eq!(
        keys(&v1_status["data"]),
        [
            "backend_kind",
            "device",
            "draft_head",
            "head",
            "pending_actions",
            "resources",
            "revision",
            "state",
            "unfinished",
            "workspace",
        ]
    );

    let v1_plan = json_of(&run(&[
        "plan",
        "--config",
        &config,
        "--json",
        "--schema-version",
        "1",
    ]));
    assert_eq!(
        keys(&v1_plan["data"]),
        [
            "action_count",
            "actions",
            "base_revision",
            "blocked",
            "next_revision",
            "plan",
            "target_snapshot",
        ]
    );

    // 信封本身在两个版本里形状一致。
    for value in [&v1_status, &v2_status] {
        assert_eq!(
            keys(value),
            ["command", "data", "diagnostics", "schema_version", "status"]
        );
    }
}

#[test]
fn unknown_schema_version_is_a_usage_error() {
    let world = World::new();
    let alice = world.device("alice", None);
    for bad in ["0", "3", "99", "abc"] {
        let output = run(&[
            "status",
            "--config",
            &path_arg(&alice.config),
            "--json",
            "--schema-version",
            bad,
        ]);
        assert_eq!(code(&output), 2, "未知输出版本 `{bad}` 必须是用法错误");
        assert!(
            stdout_of(&output).trim().is_empty(),
            "用法错误不得往 stdout 写 JSON"
        );
    }
}

#[test]
fn v2_only_commands_refuse_schema_v1() {
    let world = World::new();
    let alice = world.device("alice", None);
    let config = path_arg(&alice.config);
    for command in [
        vec!["fetch"],
        vec!["merge"],
        vec!["conflicts", "list"],
        vec!["profile", "explain"],
    ] {
        let mut args = command.clone();
        args.extend_from_slice(&["--config", &config, "--json", "--schema-version", "1"]);
        let output = run(&args);
        assert_ne!(code(&output), 0, "`{command:?}` 在 v1 下必须报错");
        let value = json_of(&output);
        assert_eq!(value["status"], "error");
        assert_eq!(value["schema_version"], 1);
    }
}

// ---------------------------------------------------------------------------
// adapters：让 `envsync-adapters` 真正有消费者
//
// 在此之前，`envsync-adapters` 是一个完整实现、有跨平台 fixture 覆盖、却**没有任何
// 调用方**的库：全仓库除 workspace 成员声明之外没人引用它，用户只能照着文档手抄资源表。
// 下面这组测试钉死的是「它现在真的被用上了」这件事——尤其是 `discover` 的产物必须能被
// 配置解析器读回来，否则这条命令等于给了用户一段假的配置。
// ---------------------------------------------------------------------------

/// 只跑一次 `init`、不改资源列表的干净设备。
///
/// `World::device` 会把资源覆盖成固定两条；`adapters discover` 要验的恰恰是「不预设
/// 任何资源时，适配器给出什么」，因此这里另起一个更朴素的脚手架。
fn bare_device(world: &World, name: &str, extra_init_args: &[&str]) -> (Device, Value) {
    let home = world.root.path().join(name).join("home");
    let config = world.root.path().join(name).join("envsync.yaml");
    std::fs::create_dir_all(&home).expect("应当能创建 home 目录");

    let config_arg = path_arg(&config);
    let backend_arg = path_arg(&world.backend());
    let mut args = vec![
        "init",
        "--config",
        &config_arg,
        "--backend-path",
        &backend_arg,
        "--device-name",
        name,
        "--json",
    ];
    args.extend_from_slice(extra_init_args);
    let output = run(&args);
    assert_eq!(code(&output), 0, "init 应当成功：{}", stderr_of(&output));
    let init_json = json_of(&output);

    // 把授权根指向本测试自己的 home，避免碰到跑测试那台机器的真实主目录。
    let device = Device { home, config };
    let mut loaded = device.config();
    loaded.roots.insert("home".to_owned(), device.home.clone());
    device.write_config(&loaded);
    (device, init_json)
}

#[test]
fn adapters_commands_expose_help() {
    for args in [
        vec!["adapters", "--help"],
        vec!["adapters", "list", "--help"],
        vec!["adapters", "discover", "--help"],
    ] {
        let output = run(&args);
        assert_eq!(code(&output), 0, "`{args:?}` 的帮助应当成功");
        assert!(
            !stdout_of(&output).trim().is_empty(),
            "`{args:?}` 应当输出帮助文本"
        );
    }
}

#[test]
fn adapters_list_reports_builtin_adapters_and_filters_by_profile() {
    let world = World::new();
    let (device, _) = bare_device(&world, "alice", &[]);

    let output = device.json(&["adapters", "list"]);
    assert_eq!(code(&output), 0, "{}", stderr_of(&output));
    let data = json_of(&output)["data"].clone();

    assert_eq!(
        keys(&data),
        ["adapters", "all", "arch", "count", "os"],
        "adapters list 的字段集合是对外契约"
    );
    assert_eq!(data["all"], false);
    let adapters = data["adapters"].as_array().expect("adapters 是数组");
    assert!(!adapters.is_empty(), "至少应当列出一个适配器：{data}");
    assert_eq!(data["count"], adapters.len());

    // 过滤掉的是「本设备用不上的」：默认 Profile 没有 pwsh 能力，
    // 因此 PowerShell 适配器不该出现在默认清单里，但 `--all` 里必须有。
    let ids: Vec<&str> = adapters
        .iter()
        .map(|adapter| adapter["id"].as_str().expect("id 是字符串"))
        .collect();
    assert!(ids.contains(&"builtin.vcs.git"), "{ids:?}");
    assert!(
        !ids.contains(&"builtin.shell.powershell"),
        "缺少 pwsh 能力时不该列出 PowerShell 适配器：{ids:?}"
    );
    for adapter in adapters {
        assert_eq!(adapter["applies"], true, "默认清单里的都必须适用本设备");
        assert_eq!(
            keys(adapter),
            [
                "applies",
                "default_mode",
                "display_name",
                "id",
                "required_capabilities",
                "resources",
                "supported_os",
                "version",
            ]
        );
    }

    // 每条资源都带上「目标资源」的完整坐标。
    let git = adapters
        .iter()
        .find(|adapter| adapter["id"] == "builtin.vcs.git")
        .expect("应当有 Git 适配器");
    let user = git["resources"]
        .as_array()
        .expect("resources 是数组")
        .iter()
        .find(|resource| resource["resource"] == "vcs/git/user")
        .unwrap_or_else(|| panic!("Git 适配器应当管理 vcs/git/user：{git}"));
    assert_eq!(user["root"], "home");
    assert_eq!(user["target"], ".gitconfig");
    assert_eq!(user["mode"], "structured_merge");
    assert_eq!(user["disposition"], "managed");
    assert_eq!(user["structured_format"], "git_config");

    // `--all` 不按 Profile 过滤。
    let all = device.json(&["adapters", "list", "--all"]);
    assert_eq!(code(&all), 0, "{}", stderr_of(&all));
    let all_data = json_of(&all)["data"].clone();
    assert_eq!(all_data["all"], true);
    let all_ids: Vec<&str> = all_data["adapters"]
        .as_array()
        .expect("adapters 是数组")
        .iter()
        .map(|adapter| adapter["id"].as_str().expect("id 是字符串"))
        .collect();
    assert!(
        all_ids.contains(&"builtin.shell.powershell"),
        "`--all` 必须列出全部适配器：{all_ids:?}"
    );
    assert!(all_ids.len() > ids.len());
}

#[test]
fn adapters_discover_emits_a_pasteable_resources_snippet() {
    let world = World::new();
    let (device, _) = bare_device(&world, "alice", &[]);

    let output = device.json(&["adapters", "discover"]);
    assert_eq!(code(&output), 0, "{}", stderr_of(&output));
    let data = json_of(&output)["data"].clone();
    assert_eq!(keys(&data), ["count", "device", "resources", "yaml"]);

    let count = data["count"].as_u64().expect("count 是整数");
    assert!(count > 0, "默认配置声明了 home 根，应当发现到资源：{data}");

    // 关键断言：产出的片段**真的能被配置解析器读回来**。把它粘进一份最小配置里，
    // 用真正的 `WorkspaceConfig::parse_yaml` 解析——「可直接粘贴」不是一句形容词。
    let snippet = data["yaml"].as_str().expect("yaml 是字符串");
    assert!(snippet.starts_with("resources:"), "{snippet}");

    let mut config = device.config();
    let text = config.to_yaml().expect("配置可序列化");
    // 原配置的 resources 是空的（`init` 不带 `--discover`），因此直接追加即可。
    assert!(!text.contains("resources:"), "前提：初始配置没有资源列表");
    let pasted = format!("{text}\n{snippet}");
    let base_dir = device.config.parent().expect("配置有父目录");
    let parsed = WorkspaceConfig::parse_yaml(&pasted, base_dir)
        .expect("discover 产出的片段必须能被配置解析器读回来");
    assert_eq!(parsed.resources.len() as u64, count);

    // 粘贴之后 CLI 也认：写回文件，`plan` 能跑起来（不再报 unknown_root 之类的错）。
    config.resources = parsed.resources.clone();
    device.write_config(&config);
    let capture = device.json(&["capture"]);
    assert_eq!(
        code(&capture),
        0,
        "粘贴后的配置必须能被真实命令使用：{}",
        stderr_of(&capture)
    );

    // 片段里绝不能出现脱敏占位符——那会让粘贴回去的 YAML 解析不了。
    assert!(!snippet.contains("<redacted>"), "{snippet}");

    // 内建适配器绝不产出 tombstone。
    for resource in data["resources"].as_array().expect("resources 是数组") {
        assert_ne!(
            resource["disposition"], "ensure_absent",
            "内建适配器绝不产出删除意图：{resource}"
        );
    }
}

#[test]
fn init_with_discover_writes_the_discovered_resources_into_the_config() {
    let world = World::new();

    // 不带 `--discover`：资源列表保持为空，由用户自己决定管什么。
    let (plain, plain_json) = bare_device(&world, "plain", &[]);
    assert_eq!(plain_json["data"]["discovered_resources"], 0);
    assert!(plain.config().resources.is_empty());

    // 带 `--discover`：初始化就把发现结果写进配置。
    let (discovered, discovered_json) = bare_device(&world, "discovered", &["--discover"]);
    let count = discovered_json["data"]["discovered_resources"]
        .as_u64()
        .expect("discovered_resources 是整数");
    assert!(count > 0, "应当发现到资源：{discovered_json}");

    // 写进去的资源必须能被解析回来，而且与 `adapters discover` 的结论一致。
    let config = discovered.config();
    assert_eq!(config.resources.len() as u64, count);
    let listed = discovered.json(&["adapters", "discover"]);
    assert_eq!(code(&listed), 0, "{}", stderr_of(&listed));
    let expected: Vec<String> = json_of(&listed)["data"]["resources"]
        .as_array()
        .expect("resources 是数组")
        .iter()
        .map(|resource| {
            resource["resource"]
                .as_str()
                .expect("resource 是字符串")
                .to_owned()
        })
        .collect();
    let actual: Vec<String> = config
        .resources
        .iter()
        .map(|resource| resource.id.to_string())
        .collect();
    assert_eq!(actual, expected);

    // 其中确实包含一条 `structured_merge`——这条模式在缺口修复前会被配置层直接拒绝，
    // 因此它同时也是「配置层已经接受 structured_merge」的回归测试。
    assert!(
        config
            .resources
            .iter()
            .any(|resource| resource.mode == FileMode::StructuredMerge),
        "Git 配置应当以 structured_merge 写入：{actual:?}"
    );

    // 初始化之后立刻可用。
    let capture = discovered.json(&["capture"]);
    assert_eq!(code(&capture), 0, "{}", stderr_of(&capture));
}
