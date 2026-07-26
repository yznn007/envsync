//! 内建适配器的契约测试与 fixture 矩阵。
//!
//! 测试分两层：
//!
//! * **契约测试**：对注册表里的**每一个**适配器统一验证同一组性质（ID 稳定唯一、
//!   版本、平台声明、确定性、capture/render 往返）。新增适配器时不需要新增测试，
//!   直接被覆盖。
//! * **fixture 矩阵**：表格驱动地穷举 macOS / Linux / Windows、LF / CRLF、非 ASCII
//!   主目录前缀、文件不存在、以及权限不足（`Unreadable` 观察态）几个维度。

use std::collections::BTreeMap;

use envsync_adapters::file::{FileAdapter, FileSpec};
use envsync_adapters::{
    git_config, shell, wezterm, Adapter, AdapterContext, AdapterError, AdapterRegistry,
    DiscoveredResource, RenderedFile, ROOT_HOME, ROOT_SYSTEM,
};
use envsync_core::render::detect_line_ending;
use envsync_domain::profile::{Arch, DeviceProfile, Os};
use envsync_domain::resource::{DesiredDisposition, FileMode, LineEnding, ObservedState};

// ---------------------------------------------------------------------------
// 公共夹具
// ---------------------------------------------------------------------------

/// 构造一个带 `pwsh` 能力的设备 Profile。
fn profile_with_pwsh(os: Os) -> DeviceProfile {
    DeviceProfile::new(os, Arch::Aarch64).with_capability(shell::CAPABILITY_PWSH)
}

/// 构造授权根映射。`system` 为 `None` 时不注册系统根。
fn roots(home: &str, system: Option<&str>) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert(ROOT_HOME.to_owned(), home.to_owned());
    if let Some(system) = system {
        map.insert(ROOT_SYSTEM.to_owned(), system.to_owned());
    }
    map
}

/// 把字节里的换行统一成 `eol`。
fn normalize_eol(bytes: &[u8], eol: &str) -> Vec<u8> {
    let text = std::str::from_utf8(bytes).expect("测试内容是 UTF-8");
    text.replace("\r\n", "\n").replace('\n', eol).into_bytes()
}

/// 为一条资源构造一份合理的受管内容。
///
/// 结构化资源必须给出合法的 git config，否则 capture 会（正确地）拒绝；其余资源用
/// 一行注释，它在 shell 与 Lua 里都是合法语法。
fn sample_desired(resource: &DiscoveredResource, eol: &str) -> Vec<u8> {
    if resource.mode == FileMode::StructuredMerge {
        format!("[user]{eol}\temail = dev@example.com{eol}").into_bytes()
    } else {
        format!("{}envsync sample{eol}", resource.comment_prefix).into_bytes()
    }
}

/// 为一条资源构造一份「用户自己写的」现有文件内容。
fn sample_existing(resource: &DiscoveredResource, eol: &str) -> Vec<u8> {
    if resource.mode == FileMode::StructuredMerge {
        format!("[core]{eol}\tautocrlf = input{eol}").into_bytes()
    } else {
        format!("{}用户自己的一行{eol}", resource.comment_prefix).into_bytes()
    }
}

/// 全部内建适配器 ID 的期望集合。
const EXPECTED_IDS: &[&str] = &[
    "builtin.shell.bash",
    "builtin.shell.powershell",
    "builtin.shell.zsh",
    "builtin.terminal.wezterm",
    "builtin.vcs.git",
];

// ---------------------------------------------------------------------------
// 契约测试
// ---------------------------------------------------------------------------

#[test]
fn builtin_ids_are_stable_and_unique() {
    let registry = AdapterRegistry::builtin();
    let ids = registry.ids();
    assert_eq!(
        ids, EXPECTED_IDS,
        "内建适配器 ID 集合是对外契约，不得随意改动"
    );

    let mut unique = ids.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), ids.len(), "ID 必须互不相同");

    for id in &ids {
        assert!(registry.get(id).is_some(), "{id} 必须可以按 ID 取回");
    }
    assert!(registry.get("builtin.does.not.exist").is_none());
}

#[test]
fn descriptors_are_wellformed() {
    let registry = AdapterRegistry::builtin();
    for adapter in registry.adapters() {
        let descriptor = adapter.descriptor();
        assert!(
            descriptor.id.starts_with("builtin."),
            "内建适配器 ID 必须带 builtin. 前缀：{}",
            descriptor.id
        );
        assert!(descriptor.version >= 1, "{} 的版本必须 >= 1", descriptor.id);
        assert!(
            !descriptor.supported_os.is_empty(),
            "{} 必须声明至少一个支持平台",
            descriptor.id
        );
        assert!(
            !descriptor.display_name.is_empty(),
            "{} 缺少展示名",
            descriptor.id
        );
        for capability in descriptor.required_capabilities {
            assert!(
                !capability.trim().is_empty(),
                "{} 声明了空能力名",
                descriptor.id
            );
        }
    }
}

/// 遍历「每个适配器 × 每条资源」，统一验证确定性与 capture/render 往返。
#[test]
fn capture_and_render_are_deterministic_and_round_trip() {
    let registry = AdapterRegistry::builtin();
    // 用一个同时具备全部条件的 Profile，尽量让每个适配器都产出资源。
    for os in [Os::MacOs, Os::Linux, Os::Windows] {
        let profile = profile_with_pwsh(os).with_tag(git_config::TAG_XDG_GIT);
        let roots = roots("", Some("etc"));
        let ctx = AdapterContext::new(&profile, &roots, "");

        for adapter in registry.adapters() {
            for resource in adapter.discover(&ctx).expect("发现不应失败") {
                let desired = sample_desired(&resource, "\n");

                if resource.disposition == DesiredDisposition::Unmanaged {
                    // 观察态资源：既不采集内容也不渲染。
                    assert_eq!(
                        adapter.capture(&resource.id, &desired).expect("capture"),
                        None,
                        "{} 是观察态资源，不应采集内容",
                        resource.id
                    );
                    let error = adapter
                        .render(&resource.id, None, &desired)
                        .expect_err("观察态资源不得渲染");
                    assert_eq!(error.code(), "adapter.observe_only");
                    continue;
                }

                // 确定性：连调两次结果必须逐字节相同。
                let first = adapter
                    .render(&resource.id, None, &desired)
                    .expect("render");
                let second = adapter
                    .render(&resource.id, None, &desired)
                    .expect("render");
                assert_eq!(first, second, "{} 的 render 必须确定", resource.id);

                let bytes = first.bytes().expect("文件不存在时必然产生写入").to_vec();
                let captured_once = adapter.capture(&resource.id, &bytes).expect("capture");
                let captured_twice = adapter.capture(&resource.id, &bytes).expect("capture");
                assert_eq!(
                    captured_once, captured_twice,
                    "{} 的 capture 必须确定",
                    resource.id
                );

                // 往返：render(existing=None) 的结果能被 capture 还原成受管内容。
                assert_eq!(
                    captured_once.as_deref(),
                    Some(desired.as_slice()),
                    "{} 的 capture 未能还原受管内容",
                    resource.id
                );

                // 幂等：对已经处于期望状态的文件再渲染一次不产生写入。
                assert_eq!(
                    adapter
                        .render(&resource.id, Some(&bytes), &desired)
                        .expect("render"),
                    RenderedFile::Unchanged,
                    "{} 的 render 必须幂等",
                    resource.id
                );
                // verify 与 render 语义一致。
                adapter
                    .verify(&resource.id, &bytes, &desired)
                    .expect("verify 应当通过");
                let tampered = [bytes.as_slice(), b"\n# drift\n"].concat();
                if resource.mode != FileMode::ManagedBlock {
                    // Managed Block 允许块外内容变化，这里只对整份接管的模式断言漂移可检出。
                    let error = adapter
                        .verify(&resource.id, &tampered, &desired)
                        .expect_err("内容漂移必须被 verify 检出");
                    assert_eq!(error.code(), "adapter.verify_failed");
                }
            }
        }
    }
}

#[test]
fn unknown_resource_is_rejected_by_every_adapter() {
    let registry = AdapterRegistry::builtin();
    let alien = envsync_domain::id::ResourceId::parse("does/not/exist").expect("合法标识");
    for adapter in registry.adapters() {
        let error = adapter
            .capture(&alien, b"x")
            .expect_err("陌生资源必须被拒绝");
        assert_eq!(error.code(), "adapter.unknown_resource");
        let error = adapter
            .render(&alien, None, b"x")
            .expect_err("陌生资源必须被拒绝");
        assert_eq!(error.code(), "adapter.unknown_resource");
    }
}

#[test]
fn registry_rejects_duplicate_ids() {
    let mut registry = AdapterRegistry::new();
    registry
        .register(Box::new(shell::zsh_adapter()))
        .expect("首次注册成功");
    let error = registry
        .register(Box::new(shell::zsh_adapter()))
        .expect_err("重复 ID 必须被拒绝");
    assert_eq!(error.code(), "adapter.duplicate_id");
    assert!(matches!(error, AdapterError::DuplicateAdapterId(id) if id == "builtin.shell.zsh"));
    assert_eq!(registry.ids(), vec!["builtin.shell.zsh"]);
}

/// 适配器拿不到 Backend / Journal / 文件系统。
///
/// **类型层面的证据**：下面这行穷尽式解构会在 [`AdapterContext`] 新增任何字段时编译
/// 失败。因此「上下文里只有 Profile、授权根前缀映射和主目录前缀」这一约束是被编译器
/// 强制的，而不是靠约定——一个 `Backend` 或 `Journal` 字段无法悄悄混进来。
#[test]
fn adapter_context_exposes_only_scoped_fields() {
    let profile = profile_with_pwsh(Os::Linux);
    let root_map = roots("", None);
    let ctx = AdapterContext::new(&profile, &root_map, "");

    let AdapterContext {
        profile: seen_profile,
        roots: seen_roots,
        home_relative: seen_home,
    } = ctx;

    assert_eq!(seen_profile.os, Os::Linux);
    assert_eq!(seen_roots.len(), 1);
    assert_eq!(seen_home, "");

    // 前缀查表：home 缺失时退回 home_relative，其他根缺失时返回 None。
    let empty: BTreeMap<String, String> = BTreeMap::new();
    let fallback = AdapterContext::new(&profile, &empty, "Users/用户");
    assert_eq!(fallback.prefix(ROOT_HOME), Some("Users/用户"));
    assert_eq!(fallback.prefix(ROOT_SYSTEM), None);
}

#[test]
fn discover_never_produces_ensure_absent() {
    let registry = AdapterRegistry::builtin();
    for os in [Os::MacOs, Os::Linux, Os::Windows] {
        let profile = profile_with_pwsh(os).with_tag(git_config::TAG_XDG_GIT);
        let root_map = roots("", Some("etc"));
        let ctx = AdapterContext::new(&profile, &root_map, "");
        for resource in registry.discover_all(&ctx) {
            assert_ne!(
                resource.disposition,
                DesiredDisposition::EnsureAbsent,
                "{} 不得由适配器推断出删除意图",
                resource.id
            );
        }
    }
}

// ---------------------------------------------------------------------------
// fixture 矩阵
// ---------------------------------------------------------------------------

/// 现有文件的观察形态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Existing {
    /// 文件不存在。
    Missing,
    /// 文件存在且可读。
    Present,
    /// 文件存在但读不出来（权限不足）。
    Unreadable,
}

/// 一行 fixture。
#[derive(Debug, Clone, Copy)]
struct Fixture {
    name: &'static str,
    os: Os,
    /// 主目录相对授权根的前缀。
    home: &'static str,
    /// 现有文件与期望内容使用的换行。
    eol: &'static str,
    existing: Existing,
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        name: "macos/lf/文件不存在",
        os: Os::MacOs,
        home: "Users/dev",
        eol: "\n",
        existing: Existing::Missing,
    },
    Fixture {
        name: "macos/lf/非ASCII用户名",
        os: Os::MacOs,
        home: "Users/用户",
        eol: "\n",
        existing: Existing::Present,
    },
    Fixture {
        name: "linux/lf/普通用户",
        os: Os::Linux,
        home: "home/dev",
        eol: "\n",
        existing: Existing::Present,
    },
    Fixture {
        name: "linux/crlf/非ASCII用户名",
        os: Os::Linux,
        home: "home/üser",
        eol: "\r\n",
        existing: Existing::Present,
    },
    Fixture {
        name: "linux/lf/权限不足",
        os: Os::Linux,
        home: "home/dev",
        eol: "\n",
        existing: Existing::Unreadable,
    },
    Fixture {
        name: "windows/crlf/文件不存在",
        os: Os::Windows,
        home: "Users/用户",
        eol: "\r\n",
        existing: Existing::Missing,
    },
    Fixture {
        name: "windows/crlf/普通用户",
        os: Os::Windows,
        home: "Users/dev",
        eol: "\r\n",
        existing: Existing::Present,
    },
    Fixture {
        name: "windows/lf/权限不足",
        os: Os::Windows,
        home: "Users/dev",
        eol: "\n",
        existing: Existing::Unreadable,
    },
];

/// 某个操作系统上期望被发现的资源标识。
fn expected_ids(os: Os) -> Vec<&'static str> {
    let mut ids = vec![
        "terminal/wezterm/include",
        "terminal/wezterm/module",
        "vcs/git/system",
        "vcs/git/user",
    ];
    match os {
        Os::Windows => ids.push("shell/powershell/profile-windows"),
        Os::MacOs | Os::Linux => {
            ids.extend([
                "shell/bash/bash_profile",
                "shell/bash/bashrc",
                "shell/powershell/profile-xdg",
                "shell/zsh/zshenv",
                "shell/zsh/zshrc",
            ]);
        }
    }
    ids.sort_unstable();
    ids
}

#[test]
fn fixture_matrix_covers_os_eol_unicode_and_missing_or_unreadable_files() {
    let registry = AdapterRegistry::builtin();

    for fixture in FIXTURES {
        let profile = profile_with_pwsh(fixture.os);
        let root_map = roots(fixture.home, Some("etc"));
        let ctx = AdapterContext::new(&profile, &root_map, fixture.home);
        let discovered = registry.discover_all(&ctx);

        // 1) 平台过滤：每个 OS 上应该发现的资源集合是固定的。
        let mut ids: Vec<&str> = discovered
            .iter()
            .map(|resource| resource.id.as_str())
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, expected_ids(fixture.os), "fixture {}", fixture.name);

        for resource in &discovered {
            // 2) 目标一律是相对路径，并带上主目录前缀（含非 ASCII 段）。
            assert!(
                !resource.target.starts_with('/') && !resource.target.contains('\\'),
                "fixture {}：{} 的目标必须是相对路径",
                fixture.name,
                resource.id
            );
            if resource.root == ROOT_HOME {
                assert!(
                    resource.target.starts_with(fixture.home),
                    "fixture {}：{} 的目标缺少主目录前缀 {}",
                    fixture.name,
                    resource.id,
                    fixture.home
                );
            }
        }

        // 3) 逐个适配器验证内容处理；selector 在这里显式求值，与注册表的过滤一致。
        for adapter in registry.adapters() {
            if !adapter.descriptor().applies_to(&profile) {
                continue;
            }
            let owned = adapter.discover(&ctx).expect("发现成功");
            for resource in owned.iter().filter(|resource| {
                resource
                    .selector
                    .as_ref()
                    .is_none_or(|selector| selector.matches(&profile))
            }) {
                if resource.disposition == DesiredDisposition::Unmanaged {
                    continue;
                }

                let desired = sample_desired(resource, fixture.eol);
                match fixture.existing {
                    // 3a) 权限不足：观察态不可写，宿主不会走到渲染这一步。
                    Existing::Unreadable => {
                        let state = ObservedState::Unreadable {
                            reason: "权限不足".to_owned(),
                        };
                        assert!(
                            !state.is_writable(),
                            "fixture {}：Unreadable 不得被当作可写",
                            fixture.name
                        );
                        assert!(state.present().is_none());
                        assert!(state.content_digest().is_none());
                    }
                    Existing::Missing | Existing::Present => {
                        let existing = match fixture.existing {
                            Existing::Present => Some(sample_existing(resource, fixture.eol)),
                            _ => None,
                        };
                        let rendered = adapter
                            .render(&resource.id, existing.as_deref(), &desired)
                            .unwrap_or_else(|error| {
                                panic!("fixture {}：{} 渲染失败 {error}", fixture.name, resource.id)
                            });
                        let bytes = rendered.bytes().expect("必然产生写入").to_vec();

                        // 4) 换行：Managed Block 沿用现有文件风格，文件不存在时用 LF。
                        let dominant = detect_line_ending(existing.as_deref());
                        let expected_inner = match resource.mode {
                            FileMode::ManagedBlock => normalize_eol(
                                &desired,
                                if dominant == LineEnding::Crlf {
                                    "\r\n"
                                } else {
                                    "\n"
                                },
                            ),
                            _ => desired.clone(),
                        };
                        assert_eq!(
                            adapter
                                .capture(&resource.id, &bytes)
                                .expect("capture")
                                .as_deref(),
                            Some(expected_inner.as_slice()),
                            "fixture {}：{} 的换行处理不符预期",
                            fixture.name,
                            resource.id
                        );

                        // 5) Managed Block 必须逐字保留块外内容。
                        if let (FileMode::ManagedBlock, Some(existing)) =
                            (resource.mode, existing.as_deref())
                        {
                            let text = String::from_utf8(bytes.clone()).expect("UTF-8");
                            let existing_text = std::str::from_utf8(existing).expect("UTF-8");
                            assert!(
                                text.starts_with(existing_text),
                                "fixture {}：{} 丢失了块外内容",
                                fixture.name,
                                resource.id
                            );
                        }

                        // 6) 幂等。
                        assert_eq!(
                            adapter
                                .render(&resource.id, Some(&bytes), &desired)
                                .expect("render"),
                            RenderedFile::Unchanged,
                            "fixture {}：{} 渲染不幂等",
                            fixture.name,
                            resource.id
                        );
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 单个适配器的专项断言
// ---------------------------------------------------------------------------

#[test]
fn wezterm_generated_include_is_two_resources() {
    let adapter = wezterm::wezterm_adapter();
    let profile = DeviceProfile::new(Os::Linux, Arch::X86_64);
    let root_map = roots("", None);
    let ctx = AdapterContext::new(&profile, &root_map, "");
    let discovered = adapter.discover(&ctx).expect("发现成功");

    assert_eq!(discovered.len(), 2, "Generated Include 由两个资源组合而成");
    assert_eq!(
        adapter.descriptor().default_mode,
        FileMode::GeneratedInclude,
        "描述符对外仍然自述为 Generated Include"
    );

    let module = discovered
        .iter()
        .find(|resource| resource.id.as_str() == wezterm::MODULE_RESOURCE)
        .expect("生成文件资源");
    assert_eq!(module.mode, FileMode::FullFile);
    assert_eq!(module.target, ".config/wezterm/envsync.lua");

    let include = discovered
        .iter()
        .find(|resource| resource.id.as_str() == wezterm::INCLUDE_RESOURCE)
        .expect("注入块资源");
    assert_eq!(include.mode, FileMode::ManagedBlock);
    assert_eq!(include.target, ".wezterm.lua");
    assert_eq!(include.comment_prefix, wezterm::LUA_COMMENT_PREFIX);

    // include 语句必须指向生成文件，且不含本机绝对路径。
    let snippet = wezterm::include_snippet();
    assert!(snippet.contains("envsync"));
    assert!(
        snippet.contains("home_dir"),
        "路径必须由 wezterm 运行期拼出"
    );
    assert!(
        !snippet.contains("/home/"),
        "include 语句不得包含本机绝对路径"
    );
    assert!(!snippet.contains("C:"), "include 语句不得包含盘符");
}

#[test]
fn wezterm_include_block_preserves_surrounding_content_verbatim() {
    let adapter = wezterm::wezterm_adapter();
    let resource = envsync_domain::id::ResourceId::parse(wezterm::INCLUDE_RESOURCE).expect("标识");

    let head = "local wezterm = require(\"wezterm\")\nlocal config = {}\n";
    let tail = "config.font_size = 13.0\nreturn config\n";
    let existing = format!("{head}{tail}");

    let rendered = adapter
        .render(
            &resource,
            Some(existing.as_bytes()),
            wezterm::include_snippet().as_bytes(),
        )
        .expect("渲染成功");
    let text = String::from_utf8(rendered.bytes().expect("有写入").to_vec()).expect("UTF-8");

    // 块外内容逐字保留：原文件仍是结果的前缀。
    assert!(text.starts_with(&existing), "块外内容必须逐字保留");
    assert!(text.contains("-- >>> envsync:terminal/wezterm/include"));
    assert!(text.contains("-- <<< envsync:terminal/wezterm/include"));

    // 移除受管块后应当逐字回到原文件。
    let stripped =
        envsync_core::render::remove_managed_block(text.as_bytes(), &resource).expect("移除成功");
    assert_eq!(
        String::from_utf8(stripped.expect("存在受管块")).expect("UTF-8"),
        existing,
        "移除受管块后必须逐字还原用户文件"
    );
}

#[test]
fn system_git_config_is_observed_but_never_written() {
    let adapter = git_config::git_adapter();
    let profile = DeviceProfile::new(Os::Linux, Arch::X86_64);
    let root_map = roots("", Some("etc"));
    let ctx = AdapterContext::new(&profile, &root_map, "");

    let system = adapter
        .discover(&ctx)
        .expect("发现成功")
        .into_iter()
        .find(|resource| resource.id.as_str() == git_config::SYSTEM_RESOURCE)
        .expect("系统级 git 配置应当被发现");

    assert_eq!(system.root, ROOT_SYSTEM);
    assert_eq!(system.target, "etc/gitconfig");
    assert_eq!(
        system.disposition,
        DesiredDisposition::Unmanaged,
        "系统级 git 配置的处置恒为 Unmanaged"
    );

    // 只观察：不采集内容。
    assert_eq!(
        adapter
            .capture(&system.id, b"[core]\n\tautocrlf = input\n")
            .expect("capture"),
        None
    );
    // 只观察：不渲染，也就不可能产生写入动作。
    let error = adapter
        .render(&system.id, None, b"[user]\n\temail = x@y.z\n")
        .expect_err("系统级配置不得渲染");
    assert_eq!(error.code(), "adapter.observe_only");
}

#[test]
fn system_git_config_is_skipped_without_system_root() {
    let adapter = git_config::git_adapter();
    let profile = DeviceProfile::new(Os::Linux, Arch::X86_64);
    let root_map = roots("", None);
    let ctx = AdapterContext::new(&profile, &root_map, "");
    let ids: Vec<String> = adapter
        .discover(&ctx)
        .expect("发现成功")
        .into_iter()
        .map(|resource| resource.id.to_string())
        .collect();
    assert!(
        !ids.iter().any(|id| id == git_config::SYSTEM_RESOURCE),
        "未授权系统根时不得产出系统级资源"
    );
}

#[test]
fn user_git_config_uses_structured_merge_and_validates_syntax() {
    let adapter = git_config::git_adapter();
    let resource = envsync_domain::id::ResourceId::parse(git_config::USER_RESOURCE).expect("标识");

    let valid = b"[user]\n\temail = dev@example.com\n\tname = Dev\n";
    assert_eq!(
        adapter.capture(&resource, valid).expect("capture"),
        Some(valid.to_vec())
    );

    // 语法损坏的内容必须在 capture 阶段就被拒绝，避免同步给其他设备。
    let broken = b"[user\n\temail = dev@example.com\n";
    let error = adapter
        .capture(&resource, broken)
        .expect_err("非法 git config 必须被拒绝");
    assert_eq!(error.code(), "adapter.structured");

    // 渲染同样会校验期望内容。
    let error = adapter
        .render(&resource, None, broken)
        .expect_err("非法 git config 不得写盘");
    assert_eq!(error.code(), "adapter.structured");
}

#[test]
fn xdg_git_config_requires_opt_in_tag() {
    let registry = AdapterRegistry::builtin();
    let root_map = roots("", None);

    let plain = DeviceProfile::new(Os::Linux, Arch::X86_64);
    let ctx = AdapterContext::new(&plain, &root_map, "");
    assert!(
        !registry
            .discover_all(&ctx)
            .iter()
            .any(|resource| resource.id.as_str() == git_config::USER_XDG_RESOURCE),
        "未打标签时不得下发 XDG 布局的 git 配置"
    );

    let tagged = DeviceProfile::new(Os::Linux, Arch::X86_64).with_tag(git_config::TAG_XDG_GIT);
    let ctx = AdapterContext::new(&tagged, &root_map, "");
    let xdg = registry
        .discover_all(&ctx)
        .into_iter()
        .find(|resource| resource.id.as_str() == git_config::USER_XDG_RESOURCE)
        .expect("打上标签后应当下发");
    assert_eq!(xdg.target, ".config/git/config");
}

#[test]
fn powershell_is_not_discovered_without_pwsh_capability() {
    let registry = AdapterRegistry::builtin();
    let root_map = roots("", None);

    for os in [Os::MacOs, Os::Linux, Os::Windows] {
        let without = DeviceProfile::new(os, Arch::X86_64);
        let ctx = AdapterContext::new(&without, &root_map, "");
        assert!(
            !registry
                .discover_all(&ctx)
                .iter()
                .any(|resource| resource.id.as_str().starts_with("shell/powershell/")),
            "{os:?}：缺少 pwsh 能力时不得下发 PowerShell profile"
        );

        let with = profile_with_pwsh(os);
        let ctx = AdapterContext::new(&with, &root_map, "");
        let found: Vec<String> = registry
            .discover_all(&ctx)
            .into_iter()
            .filter(|resource| resource.id.as_str().starts_with("shell/powershell/"))
            .map(|resource| resource.target)
            .collect();
        let expected = match os {
            Os::Windows => "Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
            _ => ".config/powershell/Microsoft.PowerShell_profile.ps1",
        };
        assert_eq!(found, vec![expected.to_owned()], "{os:?} 的 profile 路径");
    }
}

#[test]
fn shell_adapters_are_absent_on_windows() {
    let registry = AdapterRegistry::builtin();
    let root_map = roots("", None);
    let profile = profile_with_pwsh(Os::Windows);
    let ctx = AdapterContext::new(&profile, &root_map, "");
    let ids: Vec<String> = registry
        .discover_all(&ctx)
        .into_iter()
        .map(|resource| resource.id.to_string())
        .collect();
    assert!(!ids.iter().any(|id| id.starts_with("shell/bash/")));
    assert!(!ids.iter().any(|id| id.starts_with("shell/zsh/")));
}

#[test]
fn invalid_target_is_rejected_instead_of_escaping_the_root() {
    // 主目录前缀是宿主提供的输入，含 `..` 时必须被平台层的相对目标校验拦下。
    let adapter = shell::zsh_adapter();
    let profile = DeviceProfile::new(Os::Linux, Arch::X86_64);
    let root_map = roots("home/../../etc", None);
    let ctx = AdapterContext::new(&profile, &root_map, "");
    let error = adapter.discover(&ctx).expect_err("逃逸前缀必须被拒绝");
    assert_eq!(error.code(), "adapter.invalid_target");
}

#[test]
fn registry_skips_failing_adapters_instead_of_aborting_discovery() {
    // 一个适配器因为前缀非法而失败时，其余适配器的资源仍然应当被发现。
    let registry = AdapterRegistry::builtin();
    let profile = DeviceProfile::new(Os::Linux, Arch::X86_64);
    let mut root_map = roots("home/dev", Some("etc/.."));
    root_map.insert(ROOT_SYSTEM.to_owned(), "etc/..".to_owned());
    let ctx = AdapterContext::new(&profile, &root_map, "home/dev");
    let discovered = registry.discover_all(&ctx);
    assert!(
        discovered
            .iter()
            .any(|resource| resource.id.as_str() == "shell/zsh/zshrc"),
        "单个适配器失败不应中断整体发现"
    );
    assert!(
        !discovered
            .iter()
            .any(|resource| resource.id.as_str().starts_with("vcs/git/")),
        "git 适配器因非法系统根前缀而整体跳过"
    );
}

#[test]
fn custom_adapter_can_be_registered_from_within_the_crate() {
    // 注册表接受任意 `Adapter`，但 `Adapter` 是 sealed 的：外部 crate 无法实现它。
    // 因此这里只能复用本 crate 暴露的 `FileAdapter`。
    static DESCRIPTOR: envsync_adapters::AdapterDescriptor = envsync_adapters::AdapterDescriptor {
        id: "builtin.test.custom",
        version: 7,
        display_name: "测试适配器",
        supported_os: &[Os::Linux],
        required_capabilities: &[],
        default_mode: FileMode::FullFile,
    };
    let adapter = FileAdapter::new(
        &DESCRIPTOR,
        vec![FileSpec::new(
            "test/custom/file",
            ROOT_HOME,
            &["custom.conf"],
            FileMode::FullFile,
        )],
    );

    let mut registry = AdapterRegistry::new();
    registry.register(Box::new(adapter)).expect("注册成功");
    assert_eq!(registry.ids(), vec!["builtin.test.custom"]);

    let profile = DeviceProfile::new(Os::Linux, Arch::X86_64);
    let root_map = roots("home/dev", None);
    let ctx = AdapterContext::new(&profile, &root_map, "home/dev");
    let discovered = registry.discover_all(&ctx);
    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].target, "home/dev/custom.conf");
}

// ---------------------------------------------------------------------------
// 性质测试
// ---------------------------------------------------------------------------

proptest::proptest! {
    /// 对任意受管内容，Managed Block 的 render 都必须幂等且能被 capture 还原。
    #[test]
    fn managed_block_round_trips_for_arbitrary_content(
        lines in proptest::collection::vec("[a-zA-Z0-9 =_-]{0,40}", 0..8),
        preamble in "[a-zA-Z0-9 =_-]{0,40}",
    ) {
        let adapter = shell::zsh_adapter();
        let resource = envsync_domain::id::ResourceId::parse("shell/zsh/zshrc").expect("标识");
        let desired: String = lines
            .iter()
            .map(|line| format!("{line}\n"))
            .collect();
        let existing = format!("{preamble}\n");

        let rendered = adapter
            .render(&resource, Some(existing.as_bytes()), desired.as_bytes())
            .expect("渲染成功");
        let bytes = rendered.bytes().expect("必然产生写入").to_vec();

        // 块外内容逐字保留。
        proptest::prop_assert!(bytes.starts_with(existing.as_bytes()));
        // capture 还原受管内容（空内容渲染成空块，capture 得到空字节串）。
        let captured = adapter.capture(&resource, &bytes).expect("capture");
        proptest::prop_assert_eq!(captured.as_deref(), Some(desired.as_bytes()));
        // 幂等。
        proptest::prop_assert_eq!(
            adapter.render(&resource, Some(&bytes), desired.as_bytes()).expect("render"),
            RenderedFile::Unchanged
        );
    }
}
