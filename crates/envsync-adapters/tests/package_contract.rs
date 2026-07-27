//! 包适配器契约测试。
//!
//! 全部用 [`FakePackageManager`] 驱动：CI 上没有 Homebrew、没有 Scoop、也没有 apt，
//! 而契约恰恰是「所有适配器都必须遵守」的那部分，因此用内存替身来钉住它最合适——
//! 既不依赖真实包管理器，也不会改动跑测试的机器。
//!
//! 覆盖计划 Task 3 Step 2 列出的全部场景：install、upgrade、already satisfied、
//! unsupported version、显式 uninstall、partial failure、verify drift，以及回滚能力
//! `None` / `Compensating` / `Exact` 三态。

use envsync_adapters::packages::{
    FakePackageManager, PackageAdapter, PackageAdapterError, PackageAdapterRegistry,
    PackageManagerDescriptor, VerifyResult, FAKE_EXACT_DESCRIPTOR, FAKE_SYSTEM_DESCRIPTOR,
    FAKE_USER_DESCRIPTOR,
};
use envsync_adapters::{ApplyContext, ObserveContext};
use envsync_domain::package::{
    PackageAction, PackageActionKind, PackageDisposition, PackageIdentity, PackageIntent,
    PackageObservationSet, PackageState, VersionPolicy,
};
use envsync_domain::profile::{Arch, DeviceProfile, Os};
use envsync_domain::{OperationId, Risk, RollbackCapability};

// ---------------------------------------------------------------------------
// 公共夹具
// ---------------------------------------------------------------------------

const OBSERVED_AT: u64 = 1_700_000_000_000;

fn profile(os: Os) -> DeviceProfile {
    DeviceProfile::new(os, Arch::Aarch64)
}

fn id(text: &str) -> PackageIdentity {
    PackageIdentity::parse(text).expect("身份合法")
}

fn intent(text: &str) -> PackageIntent {
    PackageIntent::new(id(text))
}

/// 观察 + 计划一步到位。
fn observe_and_plan(
    manager: &FakePackageManager,
    profile: &DeviceProfile,
    desired: &[PackageIntent],
) -> Result<(PackageObservationSet, Vec<PackageAction>), PackageAdapterError> {
    let ctx = ObserveContext::new(profile, OBSERVED_AT);
    let observed = manager.observe(&ctx)?;
    let actions = manager.plan(desired, &observed)?;
    Ok((observed, actions))
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

#[test]
fn missing_package_yields_install_and_apply_installs_it() {
    let profile = profile(Os::MacOs);
    let manager = FakePackageManager::new(&FAKE_USER_DESCRIPTOR)
        .with_available("fakeuser:ripgrep", &["13.0.0", "14.1.0"]);

    let (_, actions) = observe_and_plan(&manager, &profile, &[intent("fakeuser:ripgrep")]).unwrap();
    assert_eq!(actions.len(), 1);
    let action = &actions[0];
    assert_eq!(action.kind, PackageActionKind::Install);
    assert_eq!(action.risk, Risk::Low);
    assert!(!action.elevation_required);
    assert!(!action.requires_confirmation(), "普通安装不需要确认");

    let ctx = ApplyContext::new(
        ObserveContext::new(&profile, OBSERVED_AT),
        OperationId::generate(),
    );
    let receipt = manager.apply(action, &ctx).expect("安装成功");
    assert_eq!(receipt.adapter, FAKE_USER_DESCRIPTOR.id);
    assert_eq!(receipt.before_version, None);
    assert_eq!(receipt.after_version.as_deref(), Some("14.1.0"));
    assert_eq!(receipt.rollback, RollbackCapability::Compensating);
    assert!(receipt.finished_at_unix_ms > receipt.started_at_unix_ms);
    assert!(manager.is_installed("fakeuser:ripgrep"));

    // 应用后 verify 必须通过。
    let observe = ObserveContext::new(&profile, OBSERVED_AT + 1);
    assert_eq!(
        manager.verify(action, &observe).unwrap(),
        VerifyResult::Match
    );

    // 再计划一次：期望已满足，不产生动作（幂等）。
    let (_, again) = observe_and_plan(&manager, &profile, &[intent("fakeuser:ripgrep")]).unwrap();
    assert!(again.is_empty());
}

#[test]
fn plan_is_deterministic() {
    let profile = profile(Os::MacOs);
    let manager = FakePackageManager::new(&FAKE_USER_DESCRIPTOR)
        .with_installed("fakeuser:fd", Some("9.0.0"))
        .with_available("fakeuser:ripgrep", &["14.1.0"]);
    let desired = [
        intent("fakeuser:ripgrep"),
        intent("fakeuser:jq"),
        intent("fakeuser:fd").with_disposition(PackageDisposition::EnsureAbsent),
    ];

    let (_, first) = observe_and_plan(&manager, &profile, &desired).unwrap();
    let reordered = [desired[2].clone(), desired[0].clone(), desired[1].clone()];
    let (_, second) = observe_and_plan(&manager, &profile, &reordered).unwrap();
    assert_eq!(first, second, "计划必须与输入顺序无关");

    // 卸载排在最前，其余按包身份升序。
    let order: Vec<(String, PackageActionKind)> = first
        .iter()
        .map(|action| (action.identity.to_string(), action.kind))
        .collect();
    assert_eq!(
        order,
        vec![
            ("fakeuser:fd".to_owned(), PackageActionKind::Uninstall),
            ("fakeuser:jq".to_owned(), PackageActionKind::Install),
            ("fakeuser:ripgrep".to_owned(), PackageActionKind::Install),
        ]
    );
}

// ---------------------------------------------------------------------------
// upgrade / already satisfied
// ---------------------------------------------------------------------------

#[test]
fn outdated_package_yields_upgrade() {
    let profile = profile(Os::Linux);
    let manager = FakePackageManager::new(&FAKE_USER_DESCRIPTOR)
        .with_installed("fakeuser:ripgrep", Some("13.0.0"))
        .with_available("fakeuser:ripgrep", &["13.0.0", "14.1.0"]);

    let desired =
        [intent("fakeuser:ripgrep").with_version(VersionPolicy::exact("14.1.0").unwrap())];
    let (_, actions) = observe_and_plan(&manager, &profile, &desired).unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].kind, PackageActionKind::Upgrade);
    assert_eq!(actions[0].from_version.as_deref(), Some("13.0.0"));
    assert_eq!(actions[0].risk, Risk::Medium, "升级是中等风险");
    assert!(!actions[0].requires_confirmation());

    let ctx = ApplyContext::new(
        ObserveContext::new(&profile, OBSERVED_AT),
        OperationId::generate(),
    );
    let receipt = manager.apply(&actions[0], &ctx).unwrap();
    assert_eq!(receipt.before_version.as_deref(), Some("13.0.0"));
    assert_eq!(receipt.after_version.as_deref(), Some("14.1.0"));
    assert_eq!(
        manager.installed_version("fakeuser:ripgrep").as_deref(),
        Some("14.1.0")
    );
}

#[test]
fn latest_is_resolved_by_the_adapter_not_by_the_domain() {
    // 「已安装的是不是最新」需要查询源，纯函数层判定不了；适配器用目录补足。
    let profile = profile(Os::Linux);
    let manager = FakePackageManager::new(&FAKE_USER_DESCRIPTOR)
        .with_installed("fakeuser:ripgrep", Some("13.0.0"))
        .with_available("fakeuser:ripgrep", &["13.0.0", "14.1.0"]);

    let desired = [intent("fakeuser:ripgrep").with_version(VersionPolicy::Latest)];
    let (_, actions) = observe_and_plan(&manager, &profile, &desired).unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].kind, PackageActionKind::Upgrade);
    assert_eq!(actions[0].to_version, VersionPolicy::Latest);

    // 已经是最新：不再产生动作。
    let newest = FakePackageManager::new(&FAKE_USER_DESCRIPTOR)
        .with_installed("fakeuser:ripgrep", Some("14.1.0"))
        .with_available("fakeuser:ripgrep", &["13.0.0", "14.1.0"]);
    let (_, none) = observe_and_plan(&newest, &profile, &desired).unwrap();
    assert!(none.is_empty());
}

#[test]
fn already_satisfied_yields_no_action() {
    let profile = profile(Os::Linux);
    let manager = FakePackageManager::new(&FAKE_USER_DESCRIPTOR)
        .with_installed("fakeuser:ripgrep", Some("14.1.0"))
        .with_available("fakeuser:ripgrep", &["14.1.0"]);

    for policy in [
        VersionPolicy::Present,
        VersionPolicy::exact("14.1.0").unwrap(),
        VersionPolicy::compatible("^14").unwrap(),
    ] {
        let desired = [intent("fakeuser:ripgrep").with_version(policy.clone())];
        let (_, actions) = observe_and_plan(&manager, &profile, &desired).unwrap();
        assert!(actions.is_empty(), "策略 {policy} 已满足，不该产生动作");
    }
}

// ---------------------------------------------------------------------------
// unsupported version / package not found
// ---------------------------------------------------------------------------

#[test]
fn unsupported_version_blocks_instead_of_installing_something_else() {
    let profile = profile(Os::Linux);
    let manager = FakePackageManager::new(&FAKE_USER_DESCRIPTOR)
        .with_available("fakeuser:ripgrep", &["13.0.0", "14.1.0"]);

    let desired =
        [intent("fakeuser:ripgrep").with_version(VersionPolicy::exact("99.0.0").unwrap())];
    let err =
        observe_and_plan(&manager, &profile, &desired).expect_err("源里没有这个版本时必须阻塞");
    match &err {
        PackageAdapterError::UnsupportedVersion {
            identity, policy, ..
        } => {
            assert_eq!(identity, "fakeuser:ripgrep");
            assert_eq!(policy, "exact:99.0.0");
        }
        other => panic!("期望 UnsupportedVersion，实际 {other:?}"),
    }
    assert_eq!(err.code(), "package_adapter.unsupported_version");
    assert!(
        !manager.is_installed("fakeuser:ripgrep"),
        "阻塞时不得留下任何副作用"
    );

    // 语义区间同样如此。
    let ranged =
        [intent("fakeuser:ripgrep").with_version(VersionPolicy::compatible("^20").unwrap())];
    assert!(matches!(
        observe_and_plan(&manager, &profile, &ranged),
        Err(PackageAdapterError::UnsupportedVersion { .. })
    ));
}

#[test]
fn package_missing_from_source_is_reported_as_not_found() {
    let profile = profile(Os::Linux);
    let manager =
        FakePackageManager::new(&FAKE_USER_DESCRIPTOR).with_available("fakeuser:nope", &[]);

    let err = observe_and_plan(&manager, &profile, &[intent("fakeuser:nope")]).unwrap_err();
    assert!(matches!(err, PackageAdapterError::PackageNotFound { .. }));
    assert_eq!(err.code(), "package_adapter.package_not_found");
}

#[test]
fn undecidable_installed_version_blocks_the_plan() {
    let profile = profile(Os::Linux);
    // 已安装版本不是合法 semver，而策略是 semver 区间。
    let manager = FakePackageManager::new(&FAKE_USER_DESCRIPTOR)
        .with_installed("fakeuser:ripgrep", Some("nightly"));
    let desired =
        [intent("fakeuser:ripgrep").with_version(VersionPolicy::compatible("^14").unwrap())];

    let err = observe_and_plan(&manager, &profile, &desired).unwrap_err();
    assert!(matches!(err, PackageAdapterError::Intent(_)));
    assert_eq!(err.code(), "package_adapter.invalid_intent");
}

// ---------------------------------------------------------------------------
// 显式卸载与「额外包」
// ---------------------------------------------------------------------------

#[test]
fn explicit_tombstone_yields_high_risk_uninstall_that_needs_confirmation() {
    let profile = profile(Os::Linux);
    let manager = FakePackageManager::new(&FAKE_USER_DESCRIPTOR)
        .with_installed("fakeuser:ripgrep", Some("14.1.0"));

    let desired = [intent("fakeuser:ripgrep").with_disposition(PackageDisposition::EnsureAbsent)];
    let (_, actions) = observe_and_plan(&manager, &profile, &desired).unwrap();
    assert_eq!(actions.len(), 1);
    let action = &actions[0];
    assert_eq!(action.kind, PackageActionKind::Uninstall);
    assert_eq!(action.risk, Risk::High);
    assert!(action.requires_confirmation());

    // 未确认时适配器自己就会拒绝——纵深防御，不依赖核心层。
    let unconfirmed = ApplyContext::new(
        ObserveContext::new(&profile, OBSERVED_AT),
        OperationId::generate(),
    );
    let err = manager.apply(action, &unconfirmed).unwrap_err();
    assert!(matches!(
        err,
        PackageAdapterError::ConfirmationRequired { .. }
    ));
    assert!(
        manager.is_installed("fakeuser:ripgrep"),
        "被拒绝的动作不得产生副作用"
    );

    // 确认之后才真正卸载。
    let confirmed = unconfirmed.confirmed();
    let receipt = manager.apply(action, &confirmed).unwrap();
    assert_eq!(receipt.before_version.as_deref(), Some("14.1.0"));
    assert_eq!(receipt.after_version, None);
    assert!(!manager.is_installed("fakeuser:ripgrep"));

    let observe = ObserveContext::new(&profile, OBSERVED_AT + 1);
    assert_eq!(
        manager.verify(action, &observe).unwrap(),
        VerifyResult::Match
    );
}

#[test]
fn extra_installed_packages_are_never_uninstalled() {
    let profile = profile(Os::Linux);
    let manager = FakePackageManager::new(&FAKE_USER_DESCRIPTOR)
        .with_installed("fakeuser:ripgrep", Some("14.1.0"))
        .with_installed("fakeuser:personal-tool", Some("1.0.0"))
        .with_dependency("fakeuser:libfoo", Some("2.0.0"));

    // 期望里只有 ripgrep，本机多出两个包。
    let (observed, actions) =
        observe_and_plan(&manager, &profile, &[intent("fakeuser:ripgrep")]).unwrap();
    assert_eq!(observed.len(), 3, "观察结果必须完整");
    assert!(actions.is_empty(), "多出来的包不得被卸载，实际 {actions:?}");

    // 期望为空同样不产生任何动作。
    let (_, nothing) = observe_and_plan(&manager, &profile, &[]).unwrap();
    assert!(nothing.is_empty());
}

#[test]
fn unreadable_packages_never_look_absent() {
    let profile = profile(Os::Linux);
    let manager = FakePackageManager::new(&FAKE_USER_DESCRIPTOR)
        .with_unreadable("fakeuser:ripgrep", "输出格式无法解析");

    let (observed, actions) =
        observe_and_plan(&manager, &profile, &[intent("fakeuser:ripgrep")]).unwrap();
    assert!(matches!(
        observed.state_of(&id("fakeuser:ripgrep")),
        PackageState::Unreadable { .. }
    ));
    assert!(actions.is_empty(), "读不出来 ≠ 没装，不得生成安装动作");
}

// ---------------------------------------------------------------------------
// partial failure
// ---------------------------------------------------------------------------

#[test]
fn partial_failure_keeps_earlier_receipts_and_stops_at_the_failing_action() {
    let profile = profile(Os::Linux);
    let manager = FakePackageManager::new(&FAKE_USER_DESCRIPTOR)
        .with_available("fakeuser:aaa", &["1.0.0"])
        .with_available("fakeuser:bbb", &["2.0.0"])
        .with_available("fakeuser:ccc", &["3.0.0"])
        .failing("fakeuser:bbb", "磁盘空间不足");

    let desired = [
        intent("fakeuser:aaa"),
        intent("fakeuser:bbb"),
        intent("fakeuser:ccc"),
    ];
    let (_, actions) = observe_and_plan(&manager, &profile, &desired).unwrap();
    assert_eq!(actions.len(), 3);

    let ctx = ApplyContext::new(
        ObserveContext::new(&profile, OBSERVED_AT),
        OperationId::generate(),
    );
    let mut receipts = Vec::new();
    let mut failure = None;
    for action in &actions {
        match manager.apply(action, &ctx) {
            Ok(receipt) => receipts.push(receipt),
            Err(err) => {
                failure = Some(err);
                break;
            }
        }
    }

    let failure = failure.expect("第二个动作必须失败");
    assert!(matches!(failure, PackageAdapterError::ManagerFailed { .. }));
    assert_eq!(receipts.len(), 1, "失败之前的收据必须完整保留");
    assert_eq!(receipts[0].identity, id("fakeuser:aaa"));

    // 已成功的动作生效，失败的与其后的都没有发生。
    assert!(manager.is_installed("fakeuser:aaa"));
    assert!(!manager.is_installed("fakeuser:bbb"));
    assert!(!manager.is_installed("fakeuser:ccc"));
    assert_eq!(manager.applied_actions().len(), 1);
}

// ---------------------------------------------------------------------------
// verify drift
// ---------------------------------------------------------------------------

#[test]
fn verify_detects_drift() {
    let profile = profile(Os::Linux);
    let manager = FakePackageManager::new(&FAKE_USER_DESCRIPTOR)
        .with_available("fakeuser:ripgrep", &["14.1.0"])
        .drifting("fakeuser:ripgrep", "installed 13.0.0");

    let (_, actions) = observe_and_plan(&manager, &profile, &[intent("fakeuser:ripgrep")]).unwrap();
    let ctx = ApplyContext::new(
        ObserveContext::new(&profile, OBSERVED_AT),
        OperationId::generate(),
    );
    manager.apply(&actions[0], &ctx).expect("命令自称成功");

    let observe = ObserveContext::new(&profile, OBSERVED_AT + 1);
    match manager.verify(&actions[0], &observe).unwrap() {
        VerifyResult::Drift { expected, actual } => {
            assert!(expected.starts_with("installed"));
            assert_eq!(actual, "installed 13.0.0");
        }
        other => panic!("期望检测到漂移，实际 {other:?}"),
    }
}

#[test]
fn verify_reports_unknown_rather_than_success_when_it_cannot_tell() {
    let profile = profile(Os::Linux);
    let manager = FakePackageManager::new(&FAKE_USER_DESCRIPTOR)
        .with_installed("fakeuser:ripgrep", Some("14.1.0"))
        .with_unreadable("fakeuser:ripgrep", "管理器读不出状态");

    let action = PackageAction::new(
        id("fakeuser:ripgrep"),
        PackageActionKind::Install,
        None,
        VersionPolicy::Present,
    );
    let observe = ObserveContext::new(&profile, OBSERVED_AT);
    let result = manager.verify(&action, &observe).unwrap();
    assert!(matches!(result, VerifyResult::Unknown { .. }));
    assert!(!result.is_match(), "「不知道」绝不等于「通过」");
}

// ---------------------------------------------------------------------------
// 回滚能力三态与系统级适配器
// ---------------------------------------------------------------------------

#[test]
fn rollback_capability_is_reported_honestly_for_all_three_states() {
    let cases: [(&'static PackageManagerDescriptor, Os, RollbackCapability); 3] = [
        (
            &FAKE_USER_DESCRIPTOR,
            Os::MacOs,
            RollbackCapability::Compensating,
        ),
        (&FAKE_EXACT_DESCRIPTOR, Os::MacOs, RollbackCapability::Exact),
        (&FAKE_SYSTEM_DESCRIPTOR, Os::Linux, RollbackCapability::None),
    ];

    let mut seen = Vec::new();
    for (descriptor, os, expected) in cases {
        let profile = profile(os);
        let package = format!("{}:ripgrep", descriptor.manager);
        let manager = FakePackageManager::new(descriptor).with_available(&package, &["1.0.0"]);

        let desired = [PackageIntent::new(id(&package))];
        let (_, actions) = observe_and_plan(&manager, &profile, &desired).unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(
            actions[0].rollback, expected,
            "适配器 {} 的回滚能力必须如实标注",
            descriptor.id
        );

        let mut ctx = ApplyContext::new(
            ObserveContext::new(&profile, OBSERVED_AT),
            OperationId::generate(),
        );
        if descriptor.system_scope {
            ctx = ctx.confirmed().elevated();
        }
        let receipt = manager.apply(&actions[0], &ctx).unwrap();
        assert_eq!(receipt.rollback, expected, "收据必须复述同一个能力");
        seen.push(expected);
    }

    assert_eq!(
        seen,
        vec![
            RollbackCapability::Compensating,
            RollbackCapability::Exact,
            RollbackCapability::None
        ],
        "三态都要被覆盖到"
    );
}

#[test]
fn system_scope_actions_are_high_risk_and_require_elevation() {
    let profile = profile(Os::Linux);
    let manager =
        FakePackageManager::new(&FAKE_SYSTEM_DESCRIPTOR).with_available("fakesystem:zsh", &["5.9"]);

    let (_, actions) = observe_and_plan(&manager, &profile, &[intent("fakesystem:zsh")]).unwrap();
    let action = &actions[0];
    assert_eq!(action.kind, PackageActionKind::Install);
    assert_eq!(action.risk, Risk::High, "系统级安装也是高风险");
    assert!(action.elevation_required);
    assert!(action.requires_confirmation());

    // 只确认、不提权：仍然被拒绝。
    let ctx = ApplyContext::new(
        ObserveContext::new(&profile, OBSERVED_AT),
        OperationId::generate(),
    )
    .confirmed();
    assert!(matches!(
        manager.apply(action, &ctx).unwrap_err(),
        PackageAdapterError::ElevationRequired { .. }
    ));
    assert!(!manager.is_installed("fakesystem:zsh"));

    // 两者齐备才执行。
    assert!(manager.apply(action, &ctx.elevated()).is_ok());
    assert!(manager.is_installed("fakesystem:zsh"));
}

#[test]
fn adapter_refuses_packages_from_another_manager() {
    let profile = profile(Os::Linux);
    let manager = FakePackageManager::new(&FAKE_USER_DESCRIPTOR);
    let foreign = PackageAction::new(
        id("fakeexact:ripgrep"),
        PackageActionKind::Install,
        None,
        VersionPolicy::Present,
    );

    let ctx = ApplyContext::new(
        ObserveContext::new(&profile, OBSERVED_AT),
        OperationId::generate(),
    );
    assert!(matches!(
        manager.apply(&foreign, &ctx).unwrap_err(),
        PackageAdapterError::ManagerMismatch { .. }
    ));
    assert!(matches!(
        manager
            .verify(&foreign, &ObserveContext::new(&profile, OBSERVED_AT))
            .unwrap_err(),
        PackageAdapterError::ManagerMismatch { .. }
    ));
}

#[test]
fn unavailable_manager_fails_observation_instead_of_reporting_everything_absent() {
    let profile = profile(Os::Linux);
    let manager = FakePackageManager::new(&FAKE_USER_DESCRIPTOR)
        .with_installed("fakeuser:ripgrep", Some("14.1.0"))
        .unavailable("没有探测到可执行文件");

    let ctx = ObserveContext::new(&profile, OBSERVED_AT);
    let err = manager.observe(&ctx).unwrap_err();
    assert!(matches!(
        err,
        PackageAdapterError::ManagerUnavailable { .. }
    ));
    assert_eq!(err.code(), "package_adapter.manager_unavailable");
}

#[test]
fn adapter_is_skipped_on_unsupported_operating_systems() {
    // 系统级 fake 只支持 Linux。
    let macos = profile(Os::MacOs);
    assert!(!FAKE_SYSTEM_DESCRIPTOR.applies_to(&macos));
    let manager = FakePackageManager::new(&FAKE_SYSTEM_DESCRIPTOR);
    assert!(matches!(
        manager.observe(&ObserveContext::new(&macos, OBSERVED_AT)),
        Err(PackageAdapterError::ManagerUnavailable { .. })
    ));
}

// ---------------------------------------------------------------------------
// 与核心层安全闸门的衔接
// ---------------------------------------------------------------------------

#[test]
fn actions_flow_through_the_core_gates_into_the_adapter() {
    use std::collections::BTreeMap;

    use envsync_adapters::packages::AdapterMutator;
    use envsync_core::packages::{
        apply_packages, Confirmation, ConfirmedPlan, InMemoryPackagePlanStore, PackageMutator,
        PackagePlan, PackagePlanStore, PlannedPackageAction,
    };
    use envsync_policy::PolicySet;

    let device = profile(Os::Linux);
    let manager = FakePackageManager::new(&FAKE_USER_DESCRIPTOR)
        .with_installed("fakeuser:ripgrep", Some("13.0.0"))
        .with_available("fakeuser:ripgrep", &["13.0.0", "14.1.0"])
        .with_available("fakeuser:fd", &["9.0.0"]);

    // 适配器负责「能做什么」。
    let desired = [
        intent("fakeuser:ripgrep").with_version(VersionPolicy::exact("14.1.0").unwrap()),
        intent("fakeuser:fd"),
    ];
    let (_, actions) = observe_and_plan(&manager, &device, &desired).unwrap();
    assert_eq!(actions.len(), 2);

    // 核心层负责「准不准做」：计划必须先被保存。
    let mut store = InMemoryPackagePlanStore::new();
    let plan_id = store
        .save(PackagePlan::new(
            actions
                .iter()
                .cloned()
                .map(|action| PlannedPackageAction::new(FAKE_USER_DESCRIPTOR.id, action)),
            OBSERVED_AT,
        ))
        .unwrap();

    let policy = PolicySet::builtin_defaults();
    let confirmed =
        ConfirmedPlan::load_and_confirm(&store, plan_id, &policy, &device, Confirmation::AssumeYes)
            .unwrap();
    assert_eq!(confirmed.len(), 2);

    // 桥接把授权凭据翻译成 ApplyContext，动作最终落到适配器上。
    let observe = ObserveContext::new(&device, OBSERVED_AT);
    let bridge = AdapterMutator::new(&manager, observe, OperationId::generate());
    let mut registry: BTreeMap<String, &dyn PackageMutator> = BTreeMap::new();
    registry.insert(FAKE_USER_DESCRIPTOR.id.to_owned(), &bridge);

    let outcome = apply_packages(plan_id, confirmed, &policy, &device, &registry).unwrap();
    assert_eq!(outcome.applied_count(), 2);
    assert!(
        outcome
            .receipts
            .iter()
            .all(|receipt| receipt.rollback == RollbackCapability::Compensating),
        "回滚能力必须原样传到核心层收据里"
    );
    assert_eq!(
        manager.installed_version("fakeuser:ripgrep").as_deref(),
        Some("14.1.0")
    );
    assert!(manager.is_installed("fakeuser:fd"));
}

#[test]
fn drift_detected_by_the_adapter_fails_the_core_apply() {
    use std::collections::BTreeMap;

    use envsync_adapters::packages::AdapterMutator;
    use envsync_core::packages::{
        apply_packages, Confirmation, ConfirmedPlan, InMemoryPackagePlanStore, PackageError,
        PackageMutator, PackagePlan, PackagePlanStore, PlannedPackageAction,
    };
    use envsync_policy::PolicySet;

    let device = profile(Os::Linux);
    let manager = FakePackageManager::new(&FAKE_USER_DESCRIPTOR)
        .with_available("fakeuser:ripgrep", &["14.1.0"])
        .drifting("fakeuser:ripgrep", "installed 13.0.0");

    let (_, actions) = observe_and_plan(&manager, &device, &[intent("fakeuser:ripgrep")]).unwrap();
    let mut store = InMemoryPackagePlanStore::new();
    let plan_id = store
        .save(PackagePlan::new(
            actions
                .iter()
                .cloned()
                .map(|action| PlannedPackageAction::new(FAKE_USER_DESCRIPTOR.id, action)),
            OBSERVED_AT,
        ))
        .unwrap();

    let policy = PolicySet::builtin_defaults();
    let confirmed =
        ConfirmedPlan::load_and_confirm(&store, plan_id, &policy, &device, Confirmation::AssumeYes)
            .unwrap();

    let observe = ObserveContext::new(&device, OBSERVED_AT);
    let bridge = AdapterMutator::new(&manager, observe, OperationId::generate());
    let mut registry: BTreeMap<String, &dyn PackageMutator> = BTreeMap::new();
    registry.insert(FAKE_USER_DESCRIPTOR.id.to_owned(), &bridge);

    let err = apply_packages(plan_id, confirmed, &policy, &device, &registry).unwrap_err();
    assert!(matches!(err, PackageError::VerifyFailed { .. }));
}

// ---------------------------------------------------------------------------
// 注册表契约
// ---------------------------------------------------------------------------

#[test]
fn registry_contract_holds_for_every_registered_adapter() {
    let mut registry = PackageAdapterRegistry::new();
    for descriptor in [
        &FAKE_USER_DESCRIPTOR,
        &FAKE_EXACT_DESCRIPTOR,
        &FAKE_SYSTEM_DESCRIPTOR,
    ] {
        registry
            .register(Box::new(FakePackageManager::new(descriptor)))
            .expect("ID 与管理器都不重复");
    }

    assert_eq!(registry.len(), 3);
    let ids = registry.ids();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "注册表遍历顺序必须确定");

    for adapter in registry.adapters() {
        let descriptor = adapter.descriptor();
        assert!(!descriptor.id.is_empty());
        assert!(!descriptor.display_name.is_empty());
        assert!(!descriptor.supported_os.is_empty());
        // 管理器文本必须能解析成强类型标识（`manager_id` 的 panic 前提在此排除）。
        assert_eq!(descriptor.manager_id().as_str(), descriptor.manager);
        // 系统级适配器必须落在内建策略认得的前缀下。
        assert_eq!(
            descriptor.system_scope,
            descriptor.id.starts_with("builtin.pkg.system.")
        );
    }

    // 只有 Linux 设备才看得到系统级 fake。
    let linux = profile(Os::Linux);
    let macos = profile(Os::MacOs);
    assert_eq!(registry.applicable(&linux).count(), 3);
    assert_eq!(registry.applicable(&macos).count(), 2);
}
