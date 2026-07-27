//! 包期望状态模型的验收测试。
//!
//! 覆盖五组性质：
//!
//! 1. **规范化规则由包管理器决定**——每条规则一个测试；
//! 2. **身份相等性**——来源参与身份，文本形式可无损往返；
//! 3. **版本策略**——四种策略与已安装版本的比较判定；
//! 4. **确定性**——乱序输入同一摘要，冲突 intent 必须报错；
//! 5. **§6 的硬约束**——观察缺失只生成 install，观察到的额外包永不生成 uninstall。

use envsync_domain::cbor::CborCodec;
use envsync_domain::package::{
    InstalledPackage, NameCase, PackageAction, PackageActionKind, PackageDisposition,
    PackageIdentity, PackageIntent, PackageIntentError, PackageIntentSet, PackageManagerId,
    PackageObservation, PackageObservationSet, PackageState, SeparatorRule, VersionPolicy,
    VersionVerdict,
};
use envsync_domain::{Risk, RollbackCapability};

// ---------------------------------------------------------------------------
// 公共夹具
// ---------------------------------------------------------------------------

fn id(text: &str) -> PackageIdentity {
    PackageIdentity::parse(text).unwrap_or_else(|err| panic!("身份 `{text}` 应当合法：{err}"))
}

fn manager(text: &str) -> PackageManagerId {
    PackageManagerId::parse(text).expect("管理器标识合法")
}

/// 构造一个 brew 观察集合。
fn brew_observations(entries: &[(&str, Option<&str>)]) -> PackageObservationSet {
    let mut set = PackageObservationSet::new(manager("brew"), 1_700_000_000_000);
    for (text, version) in entries {
        set.insert(PackageObservation::installed(id(text), *version))
            .expect("观察结果属于同一个管理器");
    }
    set
}

// ---------------------------------------------------------------------------
// 1. 规范化规则：每条规则一个测试
// ---------------------------------------------------------------------------

#[test]
fn brew_names_are_case_insensitive() {
    assert_eq!(id("brew:Ripgrep"), id("brew:ripgrep"));
    assert_eq!(id("brew:RIPGREP").name, "ripgrep");
    assert_eq!(manager("brew").rules().case, NameCase::Fold);
}

#[test]
fn cargo_names_follow_crates_io_rules() {
    // crates.io：小写，且 `-` 与 `_` 等价。
    assert_eq!(id("cargo:Cargo_Edit"), id("cargo:cargo-edit"));
    assert_eq!(id("cargo:cargo_edit").name, "cargo-edit");
    assert_eq!(
        manager("cargo").rules().separators,
        SeparatorRule::HyphenUnderscore
    );
}

#[test]
fn npm_rejects_uppercase_instead_of_folding_it() {
    // npm 的规则不是「不区分大小写」，而是「新包名必须全小写」。折叠会把两个不同的
    // 历史包合成一个，因此这里必须**拒绝**而不是改写。
    assert_eq!(manager("npm").rules().case, NameCase::RejectUppercase);
    assert!(matches!(
        PackageIdentity::parse("npm:Express"),
        Err(PackageIntentError::NameMustBeLowercase { .. })
    ));
    // scope 同样必须全小写。
    assert!(matches!(
        PackageIdentity::parse("npm:@Scope/pkg"),
        Err(PackageIntentError::NameMustBeLowercase { .. })
    ));
    // 合法的 scope 形态原样保留。
    let scoped = id("npm:@scope/pkg");
    assert_eq!(scoped.name, "@scope/pkg");
    assert_eq!(scoped.source, None);
}

#[test]
fn winget_package_identifier_is_case_insensitive() {
    assert_eq!(
        id("winget:Microsoft.PowerToys"),
        id("winget:microsoft.powertoys")
    );
    assert_eq!(id("winget:Microsoft.PowerToys").name, "microsoft.powertoys");
}

#[test]
fn apt_names_are_case_sensitive() {
    assert_ne!(id("apt:libFoo"), id("apt:libfoo"));
    assert_eq!(id("apt:libFoo").name, "libFoo");
    assert_eq!(manager("apt").rules().case, NameCase::Preserve);
}

#[test]
fn unknown_manager_defaults_to_the_conservative_rules() {
    // 折叠是危险方向（会把两个不同的包合并），所以未登记的管理器一律不折叠。
    assert_ne!(id("mystery:Foo"), id("mystery:foo"));
    assert_eq!(manager("mystery").rules().case, NameCase::Preserve);
}

#[test]
fn version_cannot_be_smuggled_into_the_package_name() {
    // `foo@1.2` 会让版本策略形同虚设。
    assert!(matches!(
        PackageIdentity::parse("brew:ripgrep@14"),
        Err(PackageIntentError::InvalidScope(_))
    ));
    // 不允许 scope 的管理器，包名里也不能有 `/`——那是 tap，属于 source。
    assert!(matches!(
        PackageIdentity::new(manager("brew"), "core/ripgrep", None),
        Err(PackageIntentError::NameSlashNotAllowed { .. })
    ));
}

// ---------------------------------------------------------------------------
// 2. 身份相等性
// ---------------------------------------------------------------------------

#[test]
fn different_taps_are_different_packages() {
    let core = id("brew:homebrew/core/ripgrep");
    let custom = id("brew:acme/tools/ripgrep");
    let untapped = id("brew:ripgrep");
    assert_ne!(core, custom, "不同 tap 的同名包必须是不同的包");
    assert_ne!(core, untapped, "带 tap 与不带 tap 必须是不同的包");
    assert_eq!(core.source.as_deref(), Some("homebrew/core"));
    assert_eq!(core.name, "ripgrep");
}

#[test]
fn different_buckets_are_different_packages() {
    let main = id("scoop:main/neovim");
    let extras = id("scoop:extras/neovim");
    assert_ne!(main, extras);
    assert_eq!(main.source.as_deref(), Some("main"));
}

#[test]
fn text_form_round_trips_for_every_shape() {
    for text in [
        "brew:ripgrep",
        "brew:homebrew/core/ripgrep",
        "scoop:extras/neovim",
        "cargo:ripgrep",
        "npm:@scope/pkg",
        "npm:registry.example/@scope/pkg",
        "npm:express",
        "apt:libFoo",
        "winget:microsoft.powertoys",
    ] {
        let parsed = id(text);
        assert_eq!(
            parsed.to_string().parse::<PackageIdentity>().unwrap(),
            parsed,
            "`{text}` 的文本形式必须可无损往返"
        );
    }
}

#[test]
fn identity_ordering_is_total_and_deterministic() {
    let mut forward = vec![
        id("brew:ripgrep"),
        id("apt:zsh"),
        id("brew:homebrew/core/ripgrep"),
        id("cargo:ripgrep"),
    ];
    let mut backward: Vec<PackageIdentity> = forward.iter().rev().cloned().collect();
    forward.sort();
    backward.sort();
    assert_eq!(forward, backward, "排序结果不得依赖输入顺序");
}

#[test]
fn malformed_identity_text_is_rejected_without_panicking() {
    assert!(matches!(
        PackageIdentity::parse("ripgrep"),
        Err(PackageIntentError::MissingManagerSeparator)
    ));
    assert!(matches!(
        PackageIdentity::parse("brew:"),
        Err(PackageIntentError::EmptyName)
    ));
    assert!(matches!(
        PackageIdentity::parse("brew: ripgrep"),
        Err(PackageIntentError::NameCharset(' '))
    ));
    assert!(matches!(
        PackageIdentity::parse("brew:/ripgrep"),
        Err(PackageIntentError::EmptySource)
    ));
}

// ---------------------------------------------------------------------------
// 3. 版本策略
// ---------------------------------------------------------------------------

#[test]
fn present_is_satisfied_by_any_installed_version() {
    assert_eq!(
        VersionPolicy::Present.verdict("0.0.1"),
        VersionVerdict::Satisfied
    );
    assert_eq!(
        VersionPolicy::Present.verdict("不是 semver"),
        VersionVerdict::Satisfied
    );
}

#[test]
fn exact_compares_literally_then_semantically() {
    let policy = VersionPolicy::exact("1.2.3").unwrap();
    assert_eq!(policy.verdict("1.2.3"), VersionVerdict::Satisfied);
    // build metadata 不参与 semver 相等比较。
    assert_eq!(policy.verdict("1.2.3+build.7"), VersionVerdict::Satisfied);
    assert_eq!(policy.verdict("1.2.2"), VersionVerdict::NeedsUpgrade);
    assert_eq!(policy.verdict("2.0.0"), VersionVerdict::NeedsDowngrade);
    // 非 semver：确定要改，但方向不明——必须报出来而不是猜。
    assert_eq!(
        policy.verdict("1:2.3-4ubuntu1"),
        VersionVerdict::NeedsChange
    );
}

#[test]
fn compatible_uses_semver_ranges() {
    let policy = VersionPolicy::compatible("^1.2").unwrap();
    assert_eq!(policy.verdict("1.2.0"), VersionVerdict::Satisfied);
    assert_eq!(policy.verdict("1.9.9"), VersionVerdict::Satisfied);
    assert_eq!(policy.verdict("1.1.0"), VersionVerdict::NeedsUpgrade);
    assert_eq!(policy.verdict("2.0.0"), VersionVerdict::NeedsDowngrade);
    // 已安装版本不是 semver：区间语义无从谈起。
    assert_eq!(policy.verdict("stable"), VersionVerdict::Undecidable);
}

#[test]
fn latest_needs_information_the_domain_layer_does_not_have() {
    // 「是不是最新」必须向包管理器查询，纯函数层只能诚实地说不知道。
    assert_eq!(
        VersionPolicy::Latest.verdict("1.0.0"),
        VersionVerdict::Undecidable
    );
}

#[test]
fn invalid_version_input_is_rejected() {
    assert!(matches!(
        VersionPolicy::exact(""),
        Err(PackageIntentError::EmptyVersion)
    ));
    assert!(matches!(
        VersionPolicy::exact("1.2.3 || rm -rf"),
        Err(PackageIntentError::VersionCharset(' '))
    ));
    assert!(matches!(
        VersionPolicy::compatible("绝对不是区间"),
        Err(PackageIntentError::InvalidVersionReq(_))
    ));
}

// ---------------------------------------------------------------------------
// 4. 确定性与冲突
// ---------------------------------------------------------------------------

#[test]
fn state_digest_is_independent_of_input_order() {
    let intents = [
        PackageIntent::new(id("brew:ripgrep")),
        PackageIntent::new(id("cargo:cargo-edit"))
            .with_version(VersionPolicy::compatible("^0.12").unwrap()),
        PackageIntent::new(id("npm:@scope/pkg")).optional(),
        PackageIntent::new(id("apt:zsh")).with_disposition(PackageDisposition::EnsureAbsent),
    ];
    let forward = PackageIntentSet::from_intents(intents.iter().cloned()).unwrap();
    let backward = PackageIntentSet::from_intents(intents.iter().rev().cloned()).unwrap();
    assert_eq!(forward, backward);
    assert_eq!(forward.state_digest(), backward.state_digest());
    assert_eq!(forward.canonical_bytes(), backward.canonical_bytes());
}

#[test]
fn state_digest_changes_with_every_bound_field() {
    let base = PackageIntentSet::from_intents([PackageIntent::new(id("brew:ripgrep"))]).unwrap();

    let other_version = PackageIntentSet::from_intents([
        PackageIntent::new(id("brew:ripgrep")).with_version(VersionPolicy::Latest)
    ])
    .unwrap();
    assert_ne!(base.state_digest(), other_version.state_digest());

    let other_optional =
        PackageIntentSet::from_intents([PackageIntent::new(id("brew:ripgrep")).optional()])
            .unwrap();
    assert_ne!(base.state_digest(), other_optional.state_digest());

    let other_source =
        PackageIntentSet::from_intents([PackageIntent::new(id("brew:acme/tools/ripgrep"))])
            .unwrap();
    assert_ne!(
        base.state_digest(),
        other_source.state_digest(),
        "来源参与身份，也必须参与摘要"
    );

    let other_manager =
        PackageIntentSet::from_intents([PackageIntent::new(id("cargo:ripgrep"))]).unwrap();
    assert_ne!(base.state_digest(), other_manager.state_digest());
}

#[test]
fn duplicate_identity_with_different_policy_is_a_conflict() {
    let mut set = PackageIntentSet::new();
    set.insert(PackageIntent::new(id("brew:ripgrep"))).unwrap();

    let err = set
        .insert(
            PackageIntent::new(id("brew:Ripgrep")) // 规范化后是同一个包
                .with_version(VersionPolicy::exact("14.0.0").unwrap()),
        )
        .expect_err("同一身份上的不同期望必须报冲突");
    match &err {
        PackageIntentError::ConflictingIntent {
            identity,
            existing,
            incoming,
        } => {
            assert_eq!(identity, "brew:ripgrep");
            assert!(existing.contains("present"), "诊断要说明已有的是什么");
            assert!(incoming.contains("exact:14.0.0"), "诊断要说明新来的是什么");
        }
        other => panic!("期望 ConflictingIntent，实际 {other:?}"),
    }
    assert_eq!(err.code(), "package.conflicting_intent");

    // 完全相同的 intent 重复声明是幂等的：两份配置说了同一件事，没有歧义。
    set.insert(PackageIntent::new(id("brew:ripgrep"))).unwrap();
    assert_eq!(set.len(), 1);
}

#[test]
fn intent_set_round_trips_through_canonical_cbor() {
    let set = PackageIntentSet::from_intents([
        PackageIntent::new(id("brew:homebrew/core/ripgrep"))
            .with_version(VersionPolicy::exact("14.1.0").unwrap()),
        PackageIntent::new(id("cargo:cargo-edit"))
            .with_version(VersionPolicy::compatible(">=0.12, <0.14").unwrap()),
        PackageIntent::new(id("npm:@scope/pkg")).optional(),
        PackageIntent::new(id("apt:zsh")).with_disposition(PackageDisposition::EnsureAbsent),
        PackageIntent::new(id("winget:microsoft.powertoys"))
            .with_disposition(PackageDisposition::Unmanaged),
    ])
    .unwrap();

    let bytes = set.to_canonical_vec();
    let decoded = PackageIntentSet::from_canonical_slice(&bytes).expect("解码成功");
    assert_eq!(decoded, set);
    assert_eq!(decoded.state_digest(), set.state_digest());
    assert_eq!(decoded.to_canonical_vec(), bytes, "编码必须逐字节稳定");
}

#[test]
fn observation_set_round_trips_through_canonical_cbor() {
    let mut set = brew_observations(&[("brew:ripgrep", Some("14.1.0")), ("brew:fd", None)]);
    set.insert(PackageObservation::new(
        id("brew:jq"),
        PackageState::Unreadable {
            reason: "输出无法解析".into(),
        },
    ))
    .unwrap();

    let bytes = set.to_canonical_vec();
    let decoded = PackageObservationSet::from_canonical_slice(&bytes).expect("解码成功");
    assert_eq!(decoded, set);
}

#[test]
fn action_round_trips_through_canonical_cbor() {
    let action = PackageAction::new(
        id("brew:homebrew/core/ripgrep"),
        PackageActionKind::Upgrade,
        Some("14.0.0".into()),
        VersionPolicy::exact("14.1.0").unwrap(),
    );
    let bytes = action.to_canonical_vec();
    assert_eq!(PackageAction::from_canonical_slice(&bytes).unwrap(), action);
}

// ---------------------------------------------------------------------------
// 5. §6 硬约束：默认与安全默认值
// ---------------------------------------------------------------------------

#[test]
fn defaults_are_managed_and_present() {
    let intent = PackageIntent::new(id("brew:ripgrep"));
    assert_eq!(intent.disposition, PackageDisposition::Managed);
    assert_eq!(intent.version, VersionPolicy::Present);
    assert!(!intent.optional);
    assert_eq!(PackageDisposition::default(), PackageDisposition::Managed);
    assert_eq!(VersionPolicy::default(), VersionPolicy::Present);
}

#[test]
fn only_ensure_absent_permits_removal() {
    // 任何人想新增「隐式卸载」之类的处置，都必须先改这里，从而被迫面对 §6 的约束。
    let all = [
        PackageDisposition::Managed,
        PackageDisposition::EnsureAbsent,
        PackageDisposition::Unmanaged,
    ];
    let permitting: Vec<&str> = all
        .iter()
        .filter(|disposition| disposition.permits_removal())
        .map(|disposition| disposition.as_str())
        .collect();
    assert_eq!(permitting, vec!["ensure_absent"]);
}

#[test]
fn missing_package_yields_install_only() {
    let desired = PackageIntentSet::from_intents([
        PackageIntent::new(id("brew:ripgrep")),
        PackageIntent::new(id("brew:fd")),
    ])
    .unwrap();
    // `fd` 已装、`ripgrep` 没装。
    let observed = brew_observations(&[("brew:fd", Some("9.0.0"))]);

    let actions = desired.derive_actions(&observed).unwrap();
    assert_eq!(actions.len(), 1, "只应为缺失的包生成一个动作");
    assert_eq!(actions[0].kind, PackageActionKind::Install);
    assert_eq!(actions[0].identity, id("brew:ripgrep"));
    assert_eq!(actions[0].from_version, None);
    assert_eq!(actions[0].risk, Risk::Low);
    assert_eq!(actions[0].rollback, RollbackCapability::Compensating);
    assert!(!actions[0].requires_confirmation());
}

#[test]
fn observed_extra_packages_never_yield_uninstall() {
    // 这是 §6 的硬约束：本机装了一堆 EnvSync 不认识的包，同步**不得**碰它们。
    let desired = PackageIntentSet::from_intents([PackageIntent::new(id("brew:ripgrep"))]).unwrap();
    let observed = brew_observations(&[
        ("brew:ripgrep", Some("14.1.0")),
        ("brew:some-personal-tool", Some("1.0.0")),
        ("brew:another-extra", None),
    ]);

    let actions = desired.derive_actions(&observed).unwrap();
    assert!(
        actions.is_empty(),
        "期望已满足且额外包不参与收敛，实际生成了 {actions:?}"
    );

    // 即使期望集合完全为空，也不会产生任何卸载。
    let empty = PackageIntentSet::new();
    assert!(empty.derive_actions(&observed).unwrap().is_empty());
}

#[test]
fn uninstall_requires_an_explicit_tombstone() {
    let observed = brew_observations(&[("brew:ripgrep", Some("14.1.0"))]);

    // Unmanaged：只记录存在性，不产生动作。
    let unmanaged = PackageIntentSet::from_intents([
        PackageIntent::new(id("brew:ripgrep")).with_disposition(PackageDisposition::Unmanaged)
    ])
    .unwrap();
    assert!(unmanaged.derive_actions(&observed).unwrap().is_empty());

    // EnsureAbsent：唯一能产生卸载的处置。
    let tombstone =
        PackageIntentSet::from_intents([PackageIntent::new(id("brew:ripgrep"))
            .with_disposition(PackageDisposition::EnsureAbsent)])
        .unwrap();
    let actions = tombstone.derive_actions(&observed).unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].kind, PackageActionKind::Uninstall);
    assert_eq!(actions[0].from_version.as_deref(), Some("14.1.0"));
    assert_eq!(actions[0].risk, Risk::High, "卸载是高风险动作");
    assert!(actions[0].requires_confirmation());

    // 包本来就没装：tombstone 不产生动作（幂等）。
    let nothing = PackageObservationSet::new(manager("brew"), 0);
    assert!(tombstone.derive_actions(&nothing).unwrap().is_empty());
}

#[test]
fn inconclusive_observations_never_yield_actions() {
    let desired = PackageIntentSet::from_intents([
        PackageIntent::new(id("brew:ripgrep")),
        PackageIntent::new(id("brew:fd")).with_disposition(PackageDisposition::EnsureAbsent),
    ])
    .unwrap();

    let mut observed = PackageObservationSet::new(manager("brew"), 0);
    observed
        .insert(PackageObservation::new(
            id("brew:ripgrep"),
            PackageState::Unreadable {
                reason: "brew list 退出码非零".into(),
            },
        ))
        .unwrap();
    observed
        .insert(PackageObservation::new(
            id("brew:fd"),
            PackageState::Unsupported {
                reason: "该平台没有这个 formula".into(),
            },
        ))
        .unwrap();

    assert!(
        observed
            .get(&id("brew:ripgrep"))
            .map(|observation| !observation.state.is_conclusive())
            .unwrap_or_default(),
        "Unreadable 必须是不确定状态"
    );
    assert!(
        desired.derive_actions(&observed).unwrap().is_empty(),
        "读不出来 ≠ 没装，更 ≠ 该卸载"
    );
}

#[test]
fn version_drift_yields_upgrade_or_downgrade() {
    let desired = PackageIntentSet::from_intents([
        PackageIntent::new(id("brew:ripgrep"))
            .with_version(VersionPolicy::exact("14.1.0").unwrap()),
        PackageIntent::new(id("brew:fd")).with_version(VersionPolicy::exact("9.0.0").unwrap()),
    ])
    .unwrap();
    let observed = brew_observations(&[
        ("brew:ripgrep", Some("14.0.0")),
        ("brew:fd", Some("10.0.0")),
    ]);

    let actions = desired.derive_actions(&observed).unwrap();
    let kinds: Vec<(&str, PackageActionKind)> = actions
        .iter()
        .map(|action| (action.identity.name.as_str(), action.kind))
        .collect();
    assert_eq!(
        kinds,
        vec![
            ("fd", PackageActionKind::Downgrade),
            ("ripgrep", PackageActionKind::Upgrade),
        ]
    );
    // 降级是高风险且必须确认；升级不是。
    let downgrade = &actions[0];
    assert_eq!(downgrade.risk, Risk::High);
    assert!(downgrade.requires_confirmation());
    assert!(!actions[1].requires_confirmation());
}

#[test]
fn undecidable_version_blocks_instead_of_guessing() {
    let desired = PackageIntentSet::from_intents([PackageIntent::new(id("brew:ripgrep"))
        .with_version(VersionPolicy::compatible("^14").unwrap())])
    .unwrap();
    // 已安装版本不是合法 semver：区间语义无从谈起。
    let observed = brew_observations(&[("brew:ripgrep", Some("stable"))]);

    let err = desired
        .derive_actions(&observed)
        .expect_err("无法判定时必须阻塞");
    assert!(matches!(err, PackageIntentError::UndecidableVersion { .. }));
    assert_eq!(err.code(), "package.undecidable_version");

    // 管理器根本不报告版本，同样无法满足 Exact。
    let no_version = brew_observations(&[("brew:ripgrep", None)]);
    assert!(matches!(
        desired.derive_actions(&no_version),
        Err(PackageIntentError::UndecidableVersion { .. })
    ));
}

#[test]
fn latest_defers_to_the_adapter_when_already_installed() {
    let desired = PackageIntentSet::from_intents([
        PackageIntent::new(id("brew:ripgrep")).with_version(VersionPolicy::Latest)
    ])
    .unwrap();

    // 已安装：纯函数层不知道有没有更新版本，交给适配器，不产生动作也不报错。
    let installed = brew_observations(&[("brew:ripgrep", Some("14.0.0"))]);
    assert!(desired.derive_actions(&installed).unwrap().is_empty());

    // 没装：无论什么版本策略都只需要安装。
    let missing = PackageObservationSet::new(manager("brew"), 0);
    let actions = desired.derive_actions(&missing).unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].kind, PackageActionKind::Install);
    assert_eq!(actions[0].to_version, VersionPolicy::Latest);
}

#[test]
fn same_name_from_another_source_is_a_source_change_not_a_second_install() {
    let desired =
        PackageIntentSet::from_intents([PackageIntent::new(id("brew:acme/tools/ripgrep"))])
            .unwrap();
    // 同名包已经从另一个 tap 装着。
    let observed = brew_observations(&[("brew:homebrew/core/ripgrep", Some("14.0.0"))]);

    let actions = desired.derive_actions(&observed).unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].kind, PackageActionKind::ChangeSource);
    assert_eq!(actions[0].from_version.as_deref(), Some("14.0.0"));
    assert_eq!(actions[0].risk, Risk::High, "换源是高风险动作");
    assert!(actions[0].requires_confirmation());
}

#[test]
fn intents_for_other_managers_are_skipped() {
    let desired = PackageIntentSet::from_intents([
        PackageIntent::new(id("brew:ripgrep")),
        PackageIntent::new(id("cargo:ripgrep")),
    ])
    .unwrap();
    let observed = PackageObservationSet::new(manager("brew"), 0);

    let actions = desired.derive_actions(&observed).unwrap();
    assert_eq!(actions.len(), 1, "一次收敛只处理一个包管理器");
    assert_eq!(actions[0].identity.manager, manager("brew"));
}

#[test]
fn dependency_installed_packages_are_still_observed() {
    // 依赖自动引入的包会被观察到（`explicit == false`），它满足「已安装」，
    // 因此不会重复安装；但采集侧不会把它变成 intent。
    let desired = PackageIntentSet::from_intents([PackageIntent::new(id("brew:libgit2"))]).unwrap();
    let mut observed = PackageObservationSet::new(manager("brew"), 0);
    observed
        .insert(PackageObservation::new(
            id("brew:libgit2"),
            PackageState::Installed(InstalledPackage {
                version: Some("1.8.0".into()),
                explicit: false,
            }),
        ))
        .unwrap();

    assert!(desired.derive_actions(&observed).unwrap().is_empty());
    assert!(
        !observed
            .get(&id("brew:libgit2"))
            .unwrap()
            .state
            .installed()
            .unwrap()
            .explicit
    );
}
