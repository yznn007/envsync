//! 工作区配置的解析与校验测试。
//!
//! 覆盖策略：**每一条校验规则至少一个用例**，并且断言的是稳定的错误码
//! （`ConfigError::code`）而不是错误文本，这样以后改中文措辞不会误伤测试。
//!
//! 另有三类“防腐”测试：
//!
//! * `examples/workspace.yaml` 必须能被真实解析——保证示例永不过期；
//! * `scaffold` -> `to_yaml` -> `parse_yaml` 往返一致——保证 `envsync init` 写出的
//!   文件一定能被自己读回来；
//! * 相对路径解析——保证配置语义与进程 cwd 无关。

use std::path::{Path, PathBuf};

use envsync_core::config::{
    BackendConfig, ConfigError, DeviceConfig, ResourceConfig, WorkspaceConfig, CONFIG_VERSION,
};
use envsync_domain::{
    BlobId, DesiredDisposition, FileMode, LineEnding, ResourceEntry, ResourceId, StructuredFormat,
    WorkspaceId,
};

/// 一个合法的 64 位小写十六进制设备种子。
const SEED: &str = "3a7f1c92b4de5068a1cf23947db6e50f8c41a2937be05d6c1f83a4b72e90cd15";

/// 示例配置的解析基准目录（不需要真实存在：解析纯粹是文本操作）。
const EXAMPLE_BASE: &str = "/tmp/envsync-example";

fn base_dir() -> PathBuf {
    PathBuf::from("/tmp/envsync-test")
}

/// 组装一份最小合法配置，`extra` 追加在末尾（用于插入 resources 等片段）。
fn yaml_with(extra: &str) -> String {
    format!(
        "version: 1\n\
         workspace_id: \"0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\"\n\
         device:\n\
         \x20 name: workstation\n\
         \x20 seed_hex: \"{SEED}\"\n\
         backend:\n\
         \x20 kind: local\n\
         \x20 path: \"/srv/backend\"\n\
         roots:\n\
         \x20 home: \"/home/example\"\n\
         {extra}"
    )
}

/// 组装一份只含单个资源的配置，`resource` 是该资源的 YAML 片段（不含前导 `- `）。
fn yaml_with_resource(resource: &str) -> String {
    let indented = resource
        .lines()
        .map(|line| format!("    {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    yaml_with(&format!("resources:\n  -\n{indented}\n"))
}

fn parse(text: &str) -> Result<WorkspaceConfig, ConfigError> {
    WorkspaceConfig::parse_yaml(text, &base_dir())
}

// ---------------------------------------------------------------------------
// 规则 1：version 必须落在 [MIN_CONFIG_VERSION, CONFIG_VERSION] 内，绝不静默降级
//
// M1 起支持读取版本 1 与 2（见下方的迁移测试）；范围之外一律拒绝。
// ---------------------------------------------------------------------------

#[test]
fn rule01_unsupported_version_is_rejected() {
    for bad in ["0", "3", "99"] {
        let text = yaml_with("").replace("version: 1", &format!("version: {bad}"));
        let error = parse(&text).expect_err("版本不匹配必须报错");
        assert_eq!(error.code(), "config.unsupported_version");
        match error {
            ConfigError::UnsupportedVersion { found, supported } => {
                assert_eq!(found.to_string(), bad);
                assert_eq!(supported, CONFIG_VERSION);
            }
            other => panic!("错误类型不符：{other:?}"),
        }
    }
}

#[test]
fn rule01_version_error_wins_over_field_errors() {
    // 版本未知时，后续字段的语义本就未知：必须先报版本错误，而不是一堆字段错误。
    let text = "version: 7\nworkspace_id: \"not-a-uuid\"\n";
    assert_eq!(
        parse(text).expect_err("必须报错").code(),
        "config.unsupported_version"
    );
}

// ---------------------------------------------------------------------------
// 迁移：v1 文档仍可读，读进来即升级为当前版本
// ---------------------------------------------------------------------------

#[test]
fn migration_v1_document_is_read_with_default_m1_fields() {
    // 一份地道的 v1 文档：没有 profile、没有 selector、没有 device_overrides。
    let config = parse(&yaml_with_resource(
        "id: shell/zsh/main\nroot: home\ntarget: .zshrc\nmode: full_file\ndisposition: managed\n",
    ))
    .expect("v1 文档必须仍然可读");

    assert_eq!(config.version, CONFIG_VERSION, "读入后即为当前版本");
    assert_eq!(config.profile, envsync_core::DeviceProfileConfig::default());
    let resource = &config.resources[0];
    assert!(resource.selector.is_none(), "v1 没有选择器，默认全局资源");
    assert!(resource.device_overrides.is_empty());
}

#[test]
fn migration_v1_document_rejects_m1_only_fields() {
    // 在 v1 文档里写 M1 字段必须报错：忽略它会让用户以为选择器已经生效。
    let text = yaml_with("profile:\n  tags: [work]\n");
    let error = parse(&text).expect_err("v1 文档不得混入 v2 字段");
    assert_eq!(error.code(), "config.field_requires_version");
}

#[test]
fn migration_v1_round_trips_into_v2() {
    let v1 = parse(&yaml_with_resource(
        "id: shell/zsh/main\nroot: home\ntarget: .zshrc\nmode: full_file\ndisposition: managed\n",
    ))
    .expect("v1 文档必须仍然可读");

    let yaml = v1.to_yaml().expect("序列化应当成功");
    assert!(yaml.contains(&format!("version: {CONFIG_VERSION}")));
    let v2 = WorkspaceConfig::parse_yaml(&yaml, &base_dir()).expect("升级后的文档必须可读");
    assert_eq!(v1, v2, "迁移必须是无损的");
}

#[test]
fn v2_selector_and_device_overrides_round_trip() {
    let device = envsync_domain::DeviceId::derive(b"laptop").to_hex();
    let text = yaml_with_resource(&format!(
        "id: shell/pwsh/main\n\
         root: home\n\
         target: profile.ps1\n\
         mode: full_file\n\
         disposition: managed\n\
         selector:\n\
         \x20 all:\n\
         \x20   - os: windows\n\
         \x20   - capability: pwsh\n\
         device_overrides:\n\
         \x20 {device}:\n\
         \x20   disposition: unmanaged\n\
         \x20   target: other.ps1\n"
    ))
    .replace("version: 1", "version: 2");

    let config = parse(&text).expect("v2 文档必须可读");
    let resource = &config.resources[0];
    assert!(resource.selector.is_some(), "选择器应当被解析出来");
    let overrides = resource
        .device_overrides
        .get(&device)
        .expect("应当有针对本设备的覆盖");
    assert_eq!(
        overrides.disposition,
        Some(envsync_domain::DesiredDisposition::Unmanaged)
    );
    assert_eq!(overrides.target.as_deref(), Some("other.ps1"));

    // 套用覆盖后得到本设备实际使用的资源配置。
    let resolved = resource.resolved_for(envsync_domain::DeviceId::derive(b"laptop"));
    assert_eq!(resolved.target, "other.ps1");

    // 往返稳定。
    let yaml = config.to_yaml().expect("序列化应当成功");
    assert_eq!(
        WorkspaceConfig::parse_yaml(&yaml, &base_dir()).expect("往返后必须可读"),
        config
    );
}

#[test]
fn v2_git_backend_is_parsed_and_rejects_credentials_in_url() {
    let text = yaml_with("")
        .replace("version: 1", "version: 2")
        .replace(
            "backend:\n  kind: local\n  path: \"/srv/backend\"",
            "backend:\n  kind: git\n  remote_url: \"ssh://git@example.invalid/envsync.git\"\n  auth:\n    kind: ssh-agent",
        );
    let config = parse(&text).expect("git 后端配置应当可读");
    let envsync_core::BackendConfig::Git {
        remote_url,
        branch,
        cache_dir,
        ..
    } = &config.backend
    else {
        panic!("应当解析为 Git 变体")
    };
    assert_eq!(remote_url, "ssh://git@example.invalid/envsync.git");
    assert_eq!(branch, "envsync", "省略 branch 时取默认分支");
    assert_eq!(cache_dir, &config.state_dir.join("git-cache"));

    // URL 里内嵌凭据必须在配置边界就被挡下。
    let with_password = text.replace(
        "ssh://git@example.invalid/envsync.git",
        "https://user:hunter2@example.invalid/envsync.git",
    );
    assert_eq!(
        parse(&with_password)
            .expect_err("带凭据的 URL 必须被拒绝")
            .code(),
        "config.invalid_backend"
    );
}

// ---------------------------------------------------------------------------
// 规则 2：未知字段一律拒绝，并带出字段名
// ---------------------------------------------------------------------------

#[test]
fn rule02_unknown_top_level_field_is_rejected() {
    let error = parse(&yaml_with("mystery: 1\n")).expect_err("未知字段必须报错");
    assert_eq!(error.code(), "config.unknown_field");
    match error {
        ConfigError::UnknownField { field } => assert_eq!(field, "mystery"),
        other => panic!("错误类型不符：{other:?}"),
    }
}

#[test]
fn rule02_unknown_nested_field_is_rejected() {
    // 嵌套结构同样拒绝：把 `comment_prefix` 拼错成 `comment_prefixx` 是真实会发生的错误，
    // 若被忽略，用户会以为自定义前缀生效了，而实际上文件正在用 "# " 被改写。
    let error = parse(&yaml_with_resource(
        "id: shell/zsh/main\n\
         root: home\n\
         target: .zshrc\n\
         mode: managed_block\n\
         disposition: managed\n\
         comment_prefixx: \"-- \"\n",
    ))
    .expect_err("未知字段必须报错");
    assert_eq!(error.code(), "config.unknown_field");
    match error {
        ConfigError::UnknownField { field } => assert_eq!(field, "comment_prefixx"),
        other => panic!("错误类型不符：{other:?}"),
    }
}

#[test]
fn rule02_unknown_policy_field_is_rejected() {
    let error = parse(&yaml_with_resource(
        "id: shell/zsh/main\n\
         root: home\n\
         target: .zshrc\n\
         mode: managed_block\n\
         disposition: managed\n\
         policy:\n\
         \x20 max_byte: 10\n",
    ))
    .expect_err("未知字段必须报错");
    assert_eq!(error.code(), "config.unknown_field");
    match error {
        ConfigError::UnknownField { field } => assert_eq!(field, "max_byte"),
        other => panic!("错误类型不符：{other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 规则 3：重复 ResourceId
// ---------------------------------------------------------------------------

#[test]
fn rule03_duplicate_resource_id_is_rejected() {
    let text = yaml_with(
        "resources:\n\
         \x20 - id: shell/zsh/main\n\
         \x20   root: home\n\
         \x20   target: .zshrc\n\
         \x20   mode: managed_block\n\
         \x20   disposition: managed\n\
         \x20 - id: shell/zsh/main\n\
         \x20   root: home\n\
         \x20   target: .zprofile\n\
         \x20   mode: full_file\n\
         \x20   disposition: managed\n",
    );
    let error = parse(&text).expect_err("重复资源必须报错");
    assert_eq!(error.code(), "config.duplicate_resource");
    match error {
        ConfigError::DuplicateResource { id } => assert_eq!(id, "shell/zsh/main"),
        other => panic!("错误类型不符：{other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 规则 4：未声明的授权根别名
// ---------------------------------------------------------------------------

#[test]
fn rule04_unknown_root_alias_is_rejected() {
    let error = parse(&yaml_with_resource(
        "id: shell/zsh/main\n\
         root: elsewhere\n\
         target: .zshrc\n\
         mode: managed_block\n\
         disposition: managed\n",
    ))
    .expect_err("未知根别名必须报错");
    assert_eq!(error.code(), "config.unknown_root");
    match error {
        ConfigError::UnknownRoot { alias, resource } => {
            assert_eq!(alias, "elsewhere");
            assert_eq!(resource.as_deref(), Some("shell/zsh/main"));
        }
        other => panic!("错误类型不符：{other:?}"),
    }
}

#[test]
fn rule04_root_path_lookup_reports_unknown_alias() {
    let config = parse(&yaml_with("")).expect("配置合法");
    assert_eq!(
        config.root_path("home").unwrap(),
        Path::new("/home/example")
    );
    let error = config.root_path("nope").expect_err("未知别名必须报错");
    assert_eq!(error.code(), "config.unknown_root");
    // 直接查询根时没有资源上下文，错误信息里也就不该出现资源提示。
    assert!(!error.to_string().contains("资源"), "{error}");
}

// ---------------------------------------------------------------------------
// 规则 5：target 必须通过 RelativeTarget::parse
// ---------------------------------------------------------------------------

#[test]
fn rule05_invalid_targets_are_rejected() {
    // 覆盖平台层文本校验的每一类拒绝理由。
    let bad_targets = [
        "\"/etc/passwd\"",      // 绝对路径
        "\"../../etc/passwd\"", // 包含 ..
        "\"./.zshrc\"",         // 包含 .
        "\"a//b\"",             // 空段
        "\"\"",                 // 空文本
        "\"C:/Users/x\"",       // 盘符
        "\"//server/share/x\"", // UNC
        "\"a\\\\b\"",           // 反斜杠
        "\"NUL.txt\"",          // Windows 保留设备名
        "\"trailing \"",        // 段以空格结尾
        "\"\\u0000\"",          // NUL 字节
        "\"ctrl\\u0007char\"",  // 其他控制字符
    ];
    for target in bad_targets {
        let result = parse(&yaml_with_resource(&format!(
            "id: shell/zsh/main\n\
             root: home\n\
             target: {target}\n\
             mode: managed_block\n\
             disposition: managed\n"
        )));
        match result {
            Ok(config) => panic!(
                "target {target} 本应被拒绝，却解析成了 {:?}",
                config.resources
            ),
            Err(error) => assert_eq!(error.code(), "config.invalid_target", "target {target}"),
        }
    }
}

#[test]
fn rule05_nested_target_is_accepted() {
    let config = parse(&yaml_with_resource(
        "id: git/config/global\n\
         root: home\n\
         target: .config/git/config\n\
         mode: full_file\n\
         disposition: managed\n",
    ))
    .expect("合法目标必须被接受");
    let target = config.resources[0].action_target();
    assert_eq!(target.root, "home");
    assert_eq!(target.segments, vec![".config", "git", "config"]);
    assert_eq!(target.display_path(), "home:.config/git/config");
}

// ---------------------------------------------------------------------------
// 规则 6：授权根必须是绝对路径
// ---------------------------------------------------------------------------

#[test]
fn rule06_relative_root_without_absolute_base_is_rejected() {
    // 相对根会被相对 base_dir 解析；base_dir 本身是相对路径时无法得到绝对根，必须报错。
    let text = yaml_with("").replace("\"/home/example\"", "\"relative/root\"");
    let error = WorkspaceConfig::parse_yaml(&text, Path::new("relative/base"))
        .expect_err("无法解析成绝对路径的根必须报错");
    assert_eq!(error.code(), "config.root_not_absolute");
    match error {
        ConfigError::RootNotAbsolute { alias } => assert_eq!(alias, "home"),
        other => panic!("错误类型不符：{other:?}"),
    }
}

#[test]
fn rule06_relative_root_resolves_against_absolute_base() {
    let text = yaml_with("").replace("\"/home/example\"", "\"sandbox/home\"");
    let config = WorkspaceConfig::parse_yaml(&text, Path::new("/opt/cfg")).expect("配置合法");
    assert_eq!(
        config.root_path("home").unwrap(),
        Path::new("/opt/cfg/sandbox/home")
    );
}

// ---------------------------------------------------------------------------
// 规则 7：roots 不能为空；resources 允许为空
// ---------------------------------------------------------------------------

#[test]
fn rule07_empty_roots_is_rejected() {
    let text = yaml_with("").replace("  home: \"/home/example\"\n", "");
    let error = parse(&text).expect_err("没有授权根必须报错");
    assert_eq!(error.code(), "config.no_roots");
}

#[test]
fn rule07_empty_resources_is_allowed() {
    // 空工作区是合法状态：`envsync init` 之后、添加第一个资源之前就是这样。
    let config = parse(&yaml_with("resources: []\n")).expect("空资源列表合法");
    assert!(config.resources.is_empty());
    let config = parse(&yaml_with("")).expect("省略 resources 同样合法");
    assert!(config.resources.is_empty());
}

// ---------------------------------------------------------------------------
// 规则 8：structured_merge / generated_include
// ---------------------------------------------------------------------------

#[test]
fn rule08_structured_merge_without_format_is_rejected() {
    let error = parse(&yaml_with_resource(
        "id: editor/vscode/settings\n\
         root: home\n\
         target: .config/Code/User/settings.json\n\
         mode: structured_merge\n\
         disposition: managed\n",
    ))
    .expect_err("缺少结构化格式必须报错");
    assert_eq!(error.code(), "config.structured_without_format");
}

#[test]
fn rule08_structured_merge_with_format_is_rejected_in_m0() {
    // 配置写全了也仍然拒绝：M0 还没实现语义合并，静默降级成整文件覆盖会毁掉用户数据。
    let error = parse(&yaml_with_resource(
        "id: editor/vscode/settings\n\
         root: home\n\
         target: .config/Code/User/settings.json\n\
         mode: structured_merge\n\
         disposition: managed\n\
         policy:\n\
         \x20 structured_format: json\n",
    ))
    .expect_err("M0 不支持 structured_merge");
    assert_eq!(error.code(), "config.mode_not_supported");
    match error {
        ConfigError::ModeNotSupportedInM0 { mode, .. } => assert_eq!(mode, "structured_merge"),
        other => panic!("错误类型不符：{other:?}"),
    }
}

#[test]
fn rule08_generated_include_is_rejected_in_m0() {
    let error = parse(&yaml_with_resource(
        "id: shell/zsh/generated\n\
         root: home\n\
         target: .config/envsync/zsh.zsh\n\
         mode: generated_include\n\
         disposition: managed\n",
    ))
    .expect_err("M0 不支持 generated_include");
    assert_eq!(error.code(), "config.mode_not_supported");
    match error {
        ConfigError::ModeNotSupportedInM0 { mode, .. } => assert_eq!(mode, "generated_include"),
        other => panic!("错误类型不符：{other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 规则 9：disposition 与 mode 的组合一致性交给领域层
// ---------------------------------------------------------------------------

#[test]
fn rule09_disposition_combinations_are_accepted_by_config_layer() {
    for disposition in ["managed", "ensure_absent", "unmanaged"] {
        for mode in ["full_file", "managed_block"] {
            let config = parse(&yaml_with_resource(&format!(
                "id: shell/zsh/main\n\
                 root: home\n\
                 target: .zshrc\n\
                 mode: {mode}\n\
                 disposition: {disposition}\n"
            )))
            .unwrap_or_else(|error| panic!("{disposition}/{mode} 应被接受：{error}"));
            assert_eq!(config.resources.len(), 1);
        }
    }
}

#[test]
fn rule09_blob_consistency_is_domain_level() {
    // 配置层没有 blob，因此“managed 却没有内容”只可能在构造 State Root 时被发现。
    let config = parse(&yaml_with_resource(
        "id: shell/zsh/main\n\
         root: home\n\
         target: .zshrc\n\
         mode: managed_block\n\
         disposition: managed\n",
    ))
    .expect("配置层接受");
    let resource = &config.resources[0];

    let entry = ResourceEntry {
        resource: resource.id.clone(),
        disposition: resource.disposition,
        blob: None,
        mode: resource.mode,
        policy: resource.policy.clone(),
    };
    assert!(
        entry.validate().is_err(),
        "managed 缺少 blob 应由领域层拒绝"
    );

    let entry = ResourceEntry {
        blob: Some(BlobId::of(b"export EDITOR=nvim\n")),
        ..entry
    };
    entry.validate().expect("补上 blob 后领域层应接受");
}

// ---------------------------------------------------------------------------
// 规则 10：device.seed_hex
// ---------------------------------------------------------------------------

#[test]
fn rule10_invalid_device_seed_is_rejected() {
    let cases = [
        "deadbeef",                                                           // 太短
        "3A7F1C92B4DE5068A1CF23947DB6E50F8C41A2937BE05D6C1F83A4B72E90CD15",   // 大写
        "zz7f1c92b4de5068a1cf23947db6e50f8c41a2937be05d6c1f83a4b72e90cd15",   // 非十六进制
        "3a7f1c92b4de5068a1cf23947db6e50f8c41a2937be05d6c1f83a4b72e90cd1500", // 太长
    ];
    for seed in cases {
        let text = yaml_with("").replace(SEED, seed);
        let error = parse(&text).unwrap_err();
        assert_eq!(error.code(), "config.invalid_device_seed", "种子 {seed}");
    }
}

#[test]
fn rule10_device_id_is_derived_from_seed() {
    let config = parse(&yaml_with("")).expect("配置合法");
    let expected = DeviceConfig {
        name: "workstation".to_owned(),
        seed_hex: SEED.to_owned(),
    }
    .device_id();
    assert_eq!(config.device.device_id(), expected);

    // 种子变一个比特，DeviceId 就必须变（ADR-0002 的核心性质）。
    let other_seed = format!("0{}", &SEED[1..]);
    let other = DeviceConfig {
        name: "workstation".to_owned(),
        seed_hex: other_seed,
    };
    assert_ne!(other.device_id(), expected);
}

// ---------------------------------------------------------------------------
// 规则 11：workspace_id 必须是合法 UUID
// ---------------------------------------------------------------------------

#[test]
fn rule11_invalid_workspace_id_is_rejected() {
    for bad in ["not-a-uuid", "0f1e2d3c", ""] {
        let text = yaml_with("").replace("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", bad);
        let error = parse(&text).unwrap_err();
        assert_eq!(error.code(), "config.invalid_workspace_id", "值 {bad}");
    }
}

// ---------------------------------------------------------------------------
// 规则 12：YAML 语法错误带行列信息
// ---------------------------------------------------------------------------

#[test]
fn rule12_yaml_syntax_error_reports_location() {
    let text = "version: 1\ndevice: [unclosed\n";
    let error = parse(text).expect_err("语法错误必须报错");
    assert_eq!(error.code(), "config.yaml");
    match error {
        ConfigError::Yaml { line, column, .. } => {
            assert!(line > 0, "行号应可用");
            assert!(column > 0, "列号应可用");
        }
        other => panic!("错误类型不符：{other:?}"),
    }
}

#[test]
fn rule12_type_mismatch_is_reported_as_yaml_error() {
    let text = yaml_with("").replace("roots:", "roots: 42\nignored:");
    let error = parse(&text).expect_err("类型不符必须报错");
    assert_eq!(error.code(), "config.yaml");
}

// ---------------------------------------------------------------------------
// 规则 13：I/O 错误不泄露绝对路径
// ---------------------------------------------------------------------------

#[test]
fn rule13_io_error_does_not_leak_absolute_path() {
    let dir = tempfile::tempdir().expect("创建临时目录");
    let missing = dir.path().join("workspace.yaml");
    let error = WorkspaceConfig::load(&missing).expect_err("文件不存在必须报错");
    assert_eq!(error.code(), "config.io");

    let message = error.to_string();
    assert!(
        message.contains("workspace.yaml"),
        "应给出文件名：{message}"
    );
    let parent = dir.path().to_string_lossy().into_owned();
    assert!(
        !message.contains(&parent),
        "错误信息不得包含绝对路径：{message}"
    );
}

#[test]
fn rule13_load_uses_config_directory_as_base() {
    let dir = tempfile::tempdir().expect("创建临时目录");
    let path = dir.path().join("workspace.yaml");
    std::fs::write(&path, yaml_with("state_dir: state\n")).expect("写入配置");

    let config = WorkspaceConfig::load(&path).expect("配置合法");
    assert_eq!(config.state_dir, dir.path().join("state"));
}

// ---------------------------------------------------------------------------
// 规则 14：相对路径相对 base_dir 解析
// ---------------------------------------------------------------------------

#[test]
fn rule14_relative_paths_resolve_against_base_dir() {
    let text = yaml_with("state_dir: .envsync\n")
        .replace("\"/srv/backend\"", "\"backend\"")
        .replace("\"/home/example\"", "\"home\"");
    let config = WorkspaceConfig::parse_yaml(&text, Path::new("/tmp/x")).expect("配置合法");

    assert_eq!(config.state_dir, PathBuf::from("/tmp/x/.envsync"));
    assert_eq!(config.root_path("home").unwrap(), Path::new("/tmp/x/home"));
    let BackendConfig::Local { path } = &config.backend else {
        panic!("本地后端配置应当解析为 Local 变体")
    };
    assert_eq!(path, Path::new("/tmp/x/backend"));
}

#[test]
fn rule14_absolute_paths_are_kept_as_is() {
    let config = WorkspaceConfig::parse_yaml(
        &yaml_with("state_dir: /var/lib/envsync\n"),
        Path::new("/tmp/x"),
    )
    .expect("配置合法");
    assert_eq!(config.state_dir, PathBuf::from("/var/lib/envsync"));
    let BackendConfig::Local { path } = &config.backend else {
        panic!("本地后端配置应当解析为 Local 变体")
    };
    assert_eq!(path, Path::new("/srv/backend"));
}

#[test]
fn state_dir_defaults_to_dot_envsync_and_derives_subpaths() {
    let config =
        WorkspaceConfig::parse_yaml(&yaml_with(""), Path::new("/tmp/x")).expect("配置合法");
    assert_eq!(config.state_dir, PathBuf::from("/tmp/x/.envsync"));
    assert_eq!(
        config.journal_path(),
        PathBuf::from("/tmp/x/.envsync/journal.db")
    );
    assert_eq!(config.draft_dir(), PathBuf::from("/tmp/x/.envsync/draft"));
    assert_eq!(
        config.backup_root(),
        PathBuf::from("/tmp/x/.envsync/backups")
    );
}

// ---------------------------------------------------------------------------
// 示例文件：必须永远可解析
// ---------------------------------------------------------------------------

#[test]
fn example_workspace_yaml_parses() {
    let text = include_str!("../../../examples/workspace.yaml");
    let config = WorkspaceConfig::parse_yaml(text, Path::new(EXAMPLE_BASE))
        .expect("examples/workspace.yaml 必须始终可解析");

    assert_eq!(config.version, CONFIG_VERSION);
    assert_eq!(
        config.state_dir,
        PathBuf::from("/tmp/envsync-example/.envsync")
    );
    assert!(config.roots.contains_key("home"));

    // 两种模式都被示例覆盖到。
    let modes: Vec<FileMode> = config.resources.iter().map(|r| r.mode).collect();
    assert!(modes.contains(&FileMode::FullFile));
    assert!(modes.contains(&FileMode::ManagedBlock));

    let zsh = config
        .resource(&ResourceId::parse("shell/zsh/main").unwrap())
        .expect("示例应包含 shell/zsh/main");
    assert_eq!(zsh.target, ".zshrc");
    assert_eq!(zsh.comment_prefix, "# ");
    assert_eq!(zsh.policy.unix_mode, Some(0o644));
    assert_eq!(zsh.policy.line_ending, LineEnding::Preserve);
    assert!(!zsh.policy.secret);

    // 示例里绝不能出现真实用户路径或疑似凭据的内容。
    assert!(text.contains("/home/YOUR_USER"));
    for forbidden in ["token", "password", "secret_key", "/home/claude", "/root/"] {
        assert!(
            !text.to_ascii_lowercase().contains(forbidden),
            "示例不得包含 {forbidden}"
        );
    }
}

#[test]
fn example_resource_without_policy_uses_defaults() {
    let text = include_str!("../../../examples/workspace.yaml");
    let config = WorkspaceConfig::parse_yaml(text, Path::new(EXAMPLE_BASE)).expect("示例可解析");
    let git = config
        .resource(&ResourceId::parse("git/config/global").unwrap())
        .expect("示例应包含 git/config/global");
    assert_eq!(git.mode, FileMode::FullFile);
    assert_eq!(git.disposition, DesiredDisposition::Managed);
    assert_eq!(git.policy, envsync_domain::ResourcePolicy::default());
    assert_eq!(git.comment_prefix, "# ");
    assert_eq!(git.policy.structured_format, None::<StructuredFormat>);
}

// ---------------------------------------------------------------------------
// scaffold / to_yaml 往返
// ---------------------------------------------------------------------------

#[test]
fn scaffold_round_trips_through_yaml() {
    let base = base_dir();
    let scaffolded = WorkspaceConfig::scaffold(
        WorkspaceId::generate(),
        "workstation",
        Path::new("backend"),
        &base,
    );

    let yaml = scaffolded.to_yaml().expect("序列化成功");
    let reparsed = WorkspaceConfig::parse_yaml(&yaml, &base).expect("生成的配置必须能被读回");
    assert_eq!(reparsed, scaffolded);

    // 换一个 base_dir 也应得到同样结果：序列化写出的是解析后的绝对路径。
    let elsewhere =
        WorkspaceConfig::parse_yaml(&yaml, Path::new("/somewhere/else")).expect("仍可解析");
    assert_eq!(elsewhere, scaffolded);
}

#[test]
fn scaffold_produces_valid_minimal_config() {
    let base = base_dir();
    let config = WorkspaceConfig::scaffold(
        WorkspaceId::generate(),
        "laptop",
        Path::new("/srv/backend"),
        &base,
    );
    assert_eq!(config.version, CONFIG_VERSION);
    assert_eq!(config.device.name, "laptop");
    assert_eq!(config.device.seed_hex.len(), 64);
    assert!(config.resources.is_empty(), "空工作区是合法的初始状态");
    assert_eq!(config.state_dir, base.join(".envsync"));
    assert!(config.root_path("home").is_ok());
    let BackendConfig::Local { path } = &config.backend else {
        panic!("本地后端配置应当解析为 Local 变体")
    };
    assert_eq!(path, Path::new("/srv/backend"));
}

#[test]
fn round_trip_preserves_resources_and_policy() {
    let base = base_dir();
    let text = yaml_with_resource(
        "id: shell/zsh/main\n\
         root: home\n\
         target: .zshrc\n\
         mode: managed_block\n\
         disposition: managed\n\
         comment_prefix: \"-- \"\n\
         policy:\n\
         \x20 max_bytes: 4096\n\
         \x20 line_ending: lf\n\
         \x20 unix_mode: \"0600\"\n\
         \x20 secret: true\n",
    );
    let config = WorkspaceConfig::parse_yaml(&text, &base).expect("配置合法");
    let yaml = config.to_yaml().expect("序列化成功");
    let reparsed = WorkspaceConfig::parse_yaml(&yaml, &base).expect("往返解析成功");
    assert_eq!(reparsed, config);

    let resource: &ResourceConfig = &reparsed.resources[0];
    assert_eq!(resource.comment_prefix, "-- ");
    assert_eq!(resource.policy.max_bytes, 4096);
    assert_eq!(resource.policy.line_ending, LineEnding::Lf);
    assert_eq!(resource.policy.unix_mode, Some(0o600));
    assert!(resource.policy.secret);
}

// ---------------------------------------------------------------------------
// unix_mode 的两种写法
// ---------------------------------------------------------------------------

#[test]
fn unix_mode_accepts_octal_string_and_decimal_integer() {
    let make = |value: &str| {
        parse(&yaml_with_resource(&format!(
            "id: shell/zsh/main\n\
             root: home\n\
             target: .zshrc\n\
             mode: full_file\n\
             disposition: managed\n\
             policy:\n\
             \x20 unix_mode: {value}\n"
        )))
        .unwrap_or_else(|error| panic!("unix_mode {value} 应被接受：{error}"))
        .resources[0]
            .policy
            .unix_mode
    };

    assert_eq!(make("\"0644\""), Some(0o644));
    assert_eq!(make("420"), Some(0o644));
    assert_eq!(make("\"0644\""), make("420"));
    assert_eq!(make("\"0o644\""), Some(0o644));
}

#[test]
fn unix_mode_rejects_out_of_range_and_garbage() {
    let try_parse = |value: &str| {
        parse(&yaml_with_resource(&format!(
            "id: shell/zsh/main\n\
             root: home\n\
             target: .zshrc\n\
             mode: full_file\n\
             disposition: managed\n\
             policy:\n\
             \x20 unix_mode: {value}\n"
        )))
    };

    // 超出权限位范围。
    assert_eq!(
        try_parse("99999").unwrap_err().code(),
        "config.invalid_unix_mode"
    );
    // 负数。
    assert_eq!(
        try_parse("-1").unwrap_err().code(),
        "config.invalid_unix_mode"
    );
    // 八进制里不存在的数字。
    assert_eq!(
        try_parse("\"0999\"").unwrap_err().code(),
        "config.invalid_unix_mode"
    );
}

// ---------------------------------------------------------------------------
// 其他公开 API
// ---------------------------------------------------------------------------

#[test]
fn invalid_resource_id_is_rejected() {
    let error = parse(&yaml_with_resource(
        "id: \"shell//zsh\"\n\
         root: home\n\
         target: .zshrc\n\
         mode: full_file\n\
         disposition: managed\n",
    ))
    .expect_err("非法资源标识必须报错");
    assert_eq!(error.code(), "config.invalid_resource_id");
}

#[test]
fn unknown_backend_kind_is_rejected() {
    let text = yaml_with("").replace("kind: local", "kind: s3");
    let error = parse(&text).expect_err("未知后端种类必须报错");
    assert_eq!(error.code(), "config.unknown_backend_kind");
}

#[test]
fn resource_lookup_returns_none_for_missing_id() {
    let config = parse(&yaml_with("")).expect("配置合法");
    assert!(config
        .resource(&ResourceId::parse("nothing/here").unwrap())
        .is_none());
}
