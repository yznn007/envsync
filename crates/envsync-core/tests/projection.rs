//! Profile 投影的规则测试。
//!
//! 覆盖设计文档 §3.2 的四条要求：
//!
//! 1. 优先级固定为 全局资源 < selector < device-id 覆盖 < 安全 policy；
//! 2. 能力缺失只产生诊断，**绝不**产生 tombstone；
//! 3. 投影是确定的纯函数：输入乱序不改变结果，重复投影结果不变；
//! 4. 投影只能收窄或转换，绝不新增 Workspace 中不存在的 ResourceId。

use std::collections::{BTreeMap, BTreeSet};

use envsync_core::projection::{
    project_workspace, project_workspace_with_rules, EntryOverride, ProjectionError,
    ProjectionPolicy, ProjectionRules, ResourceRule,
};
use envsync_domain::{
    Arch, BlobId, DesiredDisposition, DeviceId, DeviceProfile, FileMode, Os, Predicate,
    ProjectionNoteKind, ResourceEntry, ResourceId, ResourcePolicy, Selector, StateRoot,
};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// 脚手架
// ---------------------------------------------------------------------------

fn resource(name: &str) -> ResourceId {
    ResourceId::parse(name).expect("资源标识应当合法")
}

fn managed(name: &str) -> ResourceEntry {
    ResourceEntry {
        resource: resource(name),
        disposition: DesiredDisposition::Managed,
        blob: Some(BlobId::of(name.as_bytes())),
        mode: FileMode::FullFile,
        policy: ResourcePolicy::default(),
    }
}

fn state(entries: impl IntoIterator<Item = ResourceEntry>) -> StateRoot {
    StateRoot::from_entries(entries).expect("State Root 应当合法")
}

fn device(seed: &[u8]) -> DeviceId {
    DeviceId::derive(seed)
}

fn linux_profile() -> DeviceProfile {
    DeviceProfile::new(Os::Linux, Arch::X86_64)
        .with_tag("work")
        .with_device(device(b"laptop"))
}

/// 只允许给定能力的策略。
fn policy_with(capabilities: &[&str]) -> ProjectionPolicy {
    ProjectionPolicy {
        denied: BTreeSet::new(),
        capabilities: capabilities.iter().map(|item| (*item).to_owned()).collect(),
    }
}

fn rules(items: impl IntoIterator<Item = (ResourceId, ResourceRule)>) -> ProjectionRules {
    ProjectionRules {
        resources: items.into_iter().collect(),
    }
}

fn selector_rule(selector: Selector) -> ResourceRule {
    ResourceRule {
        selector: Some(selector),
        device_overrides: BTreeMap::new(),
    }
}

// ---------------------------------------------------------------------------
// 规则 1：全局资源
// ---------------------------------------------------------------------------

#[test]
fn global_resources_reach_every_device() {
    let workspace = state([managed("shell/zsh/main"), managed("git/config")]);
    let view = project_workspace(&workspace, &linux_profile(), &ProjectionPolicy::default())
        .expect("投影应当成功");

    assert_eq!(view.state.len(), 2);
    for note in &view.notes {
        assert_eq!(note.kind, ProjectionNoteKind::SelectedByGlobal);
    }
}

// ---------------------------------------------------------------------------
// 规则 2：selector 命中与未命中
// ---------------------------------------------------------------------------

#[test]
fn selector_hit_selects_and_miss_excludes() {
    let workspace = state([managed("shell/zsh/main"), managed("shell/pwsh/main")]);
    let rules = rules([
        (
            resource("shell/zsh/main"),
            selector_rule(Selector::all([Predicate::Os(Os::Linux)])),
        ),
        (
            resource("shell/pwsh/main"),
            selector_rule(Selector::all([Predicate::Os(Os::Windows)])),
        ),
    ]);

    let view = project_workspace_with_rules(
        &workspace,
        &linux_profile(),
        &ProjectionPolicy::default(),
        &rules,
    )
    .expect("投影应当成功");

    assert!(view.state.get(&resource("shell/zsh/main")).is_some());
    assert!(view.state.get(&resource("shell/pwsh/main")).is_none());
    assert_eq!(
        view.note(&resource("shell/zsh/main")).map(|note| note.kind),
        Some(ProjectionNoteKind::SelectedBySelector)
    );
    assert_eq!(
        view.note(&resource("shell/pwsh/main"))
            .map(|note| note.kind),
        Some(ProjectionNoteKind::ExcludedBySelector)
    );
}

#[test]
fn selector_missing_tag_excludes_without_tombstone() {
    let workspace = state([managed("shell/zsh/main")]);
    let rules = rules([(
        resource("shell/zsh/main"),
        selector_rule(Selector::all([Predicate::Tag("server".into())])),
    )]);

    let view = project_workspace_with_rules(
        &workspace,
        &linux_profile(),
        &ProjectionPolicy::default(),
        &rules,
    )
    .expect("投影应当成功");

    // 未命中只是「不下发」，绝不能变成「删掉它」。
    assert!(view.state.is_empty());
    assert!(view
        .state
        .entries
        .values()
        .all(|entry| entry.disposition != DesiredDisposition::EnsureAbsent));
}

// ---------------------------------------------------------------------------
// 规则 3：device-id 覆盖优先于 selector
// ---------------------------------------------------------------------------

#[test]
fn device_override_beats_selector_and_rewrites_disposition() {
    let workspace = state([managed("shell/zsh/main")]);
    let mut device_overrides = BTreeMap::new();
    device_overrides.insert(
        device(b"laptop"),
        EntryOverride {
            disposition: Some(DesiredDisposition::Unmanaged),
        },
    );
    // 选择器明确排除本设备，但 device-id 覆盖的优先级更高。
    let rules = rules([(
        resource("shell/zsh/main"),
        ResourceRule {
            selector: Some(Selector::all([Predicate::Os(Os::Windows)])),
            device_overrides,
        },
    )]);

    let view = project_workspace_with_rules(
        &workspace,
        &linux_profile(),
        &ProjectionPolicy::default(),
        &rules,
    )
    .expect("投影应当成功");

    let entry = view
        .state
        .get(&resource("shell/zsh/main"))
        .expect("device-id 覆盖应当把资源纳入视图");
    assert_eq!(entry.disposition, DesiredDisposition::Unmanaged);
    // 非 managed 的条目不能带内容，否则 State Root 自身就不合法。
    assert!(entry.blob.is_none());
    assert_eq!(
        view.note(&resource("shell/zsh/main")).map(|note| note.kind),
        Some(ProjectionNoteKind::OverriddenByDevice)
    );
}

#[test]
fn device_override_for_another_device_is_ignored() {
    let workspace = state([managed("shell/zsh/main")]);
    let mut device_overrides = BTreeMap::new();
    device_overrides.insert(
        device(b"desktop"),
        EntryOverride {
            disposition: Some(DesiredDisposition::Unmanaged),
        },
    );
    let rules = rules([(
        resource("shell/zsh/main"),
        ResourceRule {
            selector: None,
            device_overrides,
        },
    )]);

    let view = project_workspace_with_rules(
        &workspace,
        &linux_profile(),
        &ProjectionPolicy::default(),
        &rules,
    )
    .expect("投影应当成功");

    assert_eq!(
        view.state
            .get(&resource("shell/zsh/main"))
            .map(|entry| entry.disposition),
        Some(DesiredDisposition::Managed)
    );
    assert_eq!(
        view.note(&resource("shell/zsh/main")).map(|note| note.kind),
        Some(ProjectionNoteKind::SelectedByGlobal)
    );
}

#[test]
fn override_to_managed_without_content_is_rejected() {
    let entry = ResourceEntry {
        resource: resource("shell/zsh/main"),
        disposition: DesiredDisposition::Unmanaged,
        blob: None,
        mode: FileMode::FullFile,
        policy: ResourcePolicy::default(),
    };
    let workspace = state([entry]);
    let mut device_overrides = BTreeMap::new();
    device_overrides.insert(
        device(b"laptop"),
        EntryOverride {
            disposition: Some(DesiredDisposition::Managed),
        },
    );
    let rules = rules([(
        resource("shell/zsh/main"),
        ResourceRule {
            selector: None,
            device_overrides,
        },
    )]);

    let error = project_workspace_with_rules(
        &workspace,
        &linux_profile(),
        &ProjectionPolicy::default(),
        &rules,
    )
    .expect_err("无法满足的覆盖必须报错而不是被静默丢弃");
    assert!(matches!(
        error,
        ProjectionError::UnsatisfiableOverride { .. }
    ));
    assert_eq!(error.code(), "projection.unsatisfiable_override");
}

// ---------------------------------------------------------------------------
// 规则 4：能力缺失只产生诊断
// ---------------------------------------------------------------------------

#[test]
fn missing_capability_reports_unsupported_and_never_deletes() {
    let workspace = state([managed("shell/pwsh/main")]);
    let rules = rules([(
        resource("shell/pwsh/main"),
        selector_rule(Selector::all([
            Predicate::Os(Os::Linux),
            Predicate::Capability("pwsh".into()),
        ])),
    )]);

    let view =
        project_workspace_with_rules(&workspace, &linux_profile(), &policy_with(&[]), &rules)
            .expect("投影应当成功");

    assert!(view.state.is_empty(), "缺少能力时资源不下发");
    let note = view
        .note(&resource("shell/pwsh/main"))
        .expect("应当有一条诊断");
    assert_eq!(note.kind, ProjectionNoteKind::UnsupportedCapability);
    assert!(note.detail.contains("pwsh"));
}

#[test]
fn capability_must_be_allowed_by_policy_not_just_declared_by_profile() {
    let workspace = state([managed("shell/pwsh/main")]);
    let rules = rules([(
        resource("shell/pwsh/main"),
        selector_rule(Selector::all([Predicate::Capability("pwsh".into())])),
    )]);
    // Profile 自述有 pwsh，但策略不认：策略是更高一层，结果必须是「不下发」。
    let profile = linux_profile().with_capability("pwsh");

    let denied_by_policy =
        project_workspace_with_rules(&workspace, &profile, &policy_with(&[]), &rules)
            .expect("投影应当成功");
    assert!(denied_by_policy.state.is_empty());
    assert_eq!(
        denied_by_policy
            .note(&resource("shell/pwsh/main"))
            .map(|note| note.kind),
        Some(ProjectionNoteKind::UnsupportedCapability)
    );

    let allowed =
        project_workspace_with_rules(&workspace, &profile, &policy_with(&["pwsh"]), &rules)
            .expect("投影应当成功");
    assert_eq!(allowed.state.len(), 1);
}

// ---------------------------------------------------------------------------
// 规则 5：安全 policy 不可被绕过
// ---------------------------------------------------------------------------

#[test]
fn policy_deny_cannot_be_bypassed_by_any_selector_or_override() {
    let workspace = state([managed("secrets/aws")]);
    let mut device_overrides = BTreeMap::new();
    device_overrides.insert(
        device(b"laptop"),
        EntryOverride {
            disposition: Some(DesiredDisposition::Managed),
        },
    );
    let policy = ProjectionPolicy {
        denied: [resource("secrets/aws")].into_iter().collect(),
        capabilities: BTreeSet::new(),
    };

    // 三种「最宽松」的写法轮番上阵：全局资源、恒真选择器、device-id 覆盖。
    let attempts = [
        ResourceRule::default(),
        selector_rule(Selector::All(vec![])),
        ResourceRule {
            selector: Some(Selector::All(vec![])),
            device_overrides,
        },
    ];

    for rule in attempts {
        let view = project_workspace_with_rules(
            &workspace,
            &linux_profile(),
            &policy,
            &rules([(resource("secrets/aws"), rule)]),
        )
        .expect("投影应当成功");

        assert!(
            view.state.is_empty(),
            "被策略拒绝的资源绝不能出现在设备视图里"
        );
        assert_eq!(
            view.note(&resource("secrets/aws")).map(|note| note.kind),
            Some(ProjectionNoteKind::ExcludedByPolicy)
        );
    }
}

// ---------------------------------------------------------------------------
// 规则 6：确定性
// ---------------------------------------------------------------------------

#[test]
fn shuffled_input_yields_the_same_view_id_and_order() {
    let entries = [
        managed("shell/zsh/main"),
        managed("git/config"),
        managed("term/wezterm"),
    ];
    let mut reversed: Vec<ResourceEntry> = entries.to_vec();
    reversed.reverse();

    let straight = project_workspace(
        &state(entries.clone()),
        &linux_profile(),
        &ProjectionPolicy::default(),
    )
    .expect("投影应当成功");
    let shuffled = project_workspace(
        &state(reversed),
        &linux_profile(),
        &ProjectionPolicy::default(),
    )
    .expect("投影应当成功");

    assert_eq!(straight.id(), shuffled.id());
    assert_eq!(
        straight
            .state
            .entries
            .keys()
            .cloned()
            .collect::<Vec<ResourceId>>(),
        shuffled
            .state
            .entries
            .keys()
            .cloned()
            .collect::<Vec<ResourceId>>()
    );
    assert_eq!(straight.notes, shuffled.notes);
}

// ---------------------------------------------------------------------------
// property tests
// ---------------------------------------------------------------------------

/// 生成一组资源名（去重后构造 State Root）。
fn resource_names() -> impl Strategy<Value = Vec<String>> {
    proptest::collection::vec(
        proptest::sample::select(vec![
            "shell/zsh/main",
            "shell/bash/main",
            "shell/pwsh/main",
            "git/config",
            "term/wezterm",
            "secrets/aws",
        ]),
        0..6,
    )
    .prop_map(|names| {
        let unique: BTreeSet<String> = names.into_iter().map(str::to_owned).collect();
        unique.into_iter().collect()
    })
}

/// 生成一个选择器（含恒真、恒假与能力谓词三类）。
fn any_selector() -> impl Strategy<Value = Selector> {
    proptest::sample::select(vec![
        Selector::All(vec![]),
        Selector::Any(vec![]),
        Selector::all([Predicate::Os(Os::Linux)]),
        Selector::all([Predicate::Os(Os::Windows)]),
        Selector::all([Predicate::Tag("work".into())]),
        Selector::all([Predicate::Capability("pwsh".into())]),
        Selector::negate(Selector::is(Predicate::Tag("work".into()))),
    ])
}

proptest! {
    /// 投影是纯函数：同样的输入必然给出同样的视图与诊断。
    #[test]
    fn projection_is_deterministic(names in resource_names(), selector in any_selector()) {
        let workspace = state(names.iter().map(|name| managed(name)));
        let rule_set = rules(names.iter().map(|name| (resource(name), selector_rule(selector.clone()))));

        let first = project_workspace_with_rules(
            &workspace, &linux_profile(), &policy_with(&["pwsh"]), &rule_set,
        ).expect("投影应当成功");
        let second = project_workspace_with_rules(
            &workspace, &linux_profile(), &policy_with(&["pwsh"]), &rule_set,
        ).expect("投影应当成功");

        prop_assert_eq!(first.id(), second.id());
        prop_assert_eq!(first.notes, second.notes);
    }

    /// 投影是幂等的：把视图再投影一次，结果不变。
    #[test]
    fn projection_is_idempotent(names in resource_names()) {
        let workspace = state(names.iter().map(|name| managed(name)));
        let policy = ProjectionPolicy {
            denied: [resource("secrets/aws")].into_iter().collect(),
            capabilities: BTreeSet::new(),
        };

        let once = project_workspace(&workspace, &linux_profile(), &policy)
            .expect("投影应当成功");
        let twice = project_workspace(&once.state, &linux_profile(), &policy)
            .expect("投影应当成功");

        prop_assert_eq!(once.id(), twice.id());
    }

    /// 投影绝不新增 Workspace 中不存在的 ResourceId。
    #[test]
    fn projection_never_invents_resources(
        names in resource_names(),
        selector in any_selector(),
    ) {
        let workspace = state(names.iter().map(|name| managed(name)));
        let rule_set = rules(names.iter().map(|name| {
            let mut device_overrides = BTreeMap::new();
            device_overrides.insert(
                device(b"laptop"),
                EntryOverride { disposition: Some(DesiredDisposition::EnsureAbsent) },
            );
            (resource(name), ResourceRule { selector: Some(selector.clone()), device_overrides })
        }));

        let view = project_workspace_with_rules(
            &workspace, &linux_profile(), &policy_with(&["pwsh"]), &rule_set,
        ).expect("投影应当成功");

        for key in view.state.entries.keys() {
            prop_assert!(workspace.entries.contains_key(key), "投影凭空造出了资源 {}", key);
        }
        for note in &view.notes {
            prop_assert!(workspace.entries.contains_key(&note.resource));
        }
        prop_assert!(view.state.len() <= workspace.len(), "投影只能收窄，不能扩张");
    }
}
