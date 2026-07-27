//! 包计划的安全规则验收测试。
//!
//! 这里验证的是「准不准做」，不是「做得对不对」：动作怎么变成命令由适配器负责，
//! 本文件只钉住四道闸门——
//!
//! 1. 动作只能来自一份**已保存**的计划；
//! 2. 每个动作都要过策略，[`Decision::Deny`] 一律中止；
//! 3. 破坏性 / 需提权 / 高风险动作要用户逐条确认；
//! 4. 确认与执行之间策略变严时，执行期复检必须拦住。
//!
//! 以及设计文档 §6 的两条硬约束：缺失包产生 install，观察到的额外包**永远**不产生
//! uninstall。

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use envsync_core::packages::{
    apply_packages, evaluate_plan, ActionAuthorization, ActionConfirmer, Confirmation,
    ConfirmedPlan, InMemoryPackagePlanStore, PackageActionReceipt, PackageDecision, PackageError,
    PackageMutator, PackagePlan, PackagePlanStore, PlannedPackageAction,
};
use envsync_domain::package::{
    PackageAction, PackageActionKind, PackageDisposition, PackageIdentity, PackageIntent,
    PackageIntentSet, PackageManagerId, PackageObservation, PackageObservationSet, VersionPolicy,
};
use envsync_domain::{Arch, DeviceProfile, Os, PlanId, Risk, RollbackCapability};
use envsync_policy::{
    Decision, PolicySet, BUILTIN_ELEVATION_DENIED, BUILTIN_PACKAGE_DOWNGRADE,
    BUILTIN_PACKAGE_UNINSTALL, BUILTIN_SYSTEM_PACKAGE_WRITE,
};

// ---------------------------------------------------------------------------
// 公共夹具
// ---------------------------------------------------------------------------

const USER_ADAPTER: &str = "fake.pkg.user";
const SYSTEM_ADAPTER: &str = "builtin.pkg.system.fake";

fn profile() -> DeviceProfile {
    DeviceProfile::new(Os::Linux, Arch::Aarch64)
}

fn id(text: &str) -> PackageIdentity {
    PackageIdentity::parse(text).expect("身份合法")
}

fn manager(text: &str) -> PackageManagerId {
    PackageManagerId::parse(text).expect("管理器标识合法")
}

fn action(text: &str, kind: PackageActionKind) -> PackageAction {
    PackageAction::new(
        id(text),
        kind,
        match kind {
            PackageActionKind::Install => None,
            _ => Some("1.0.0".to_owned()),
        },
        VersionPolicy::Present,
    )
}

/// 保存一份计划并返回 `(store, plan_id)`。
fn saved(entries: Vec<PlannedPackageAction>) -> (InMemoryPackagePlanStore, PlanId) {
    let mut store = InMemoryPackagePlanStore::new();
    let id = store
        .save(PackagePlan::new(entries, 1_700_000_000_000))
        .expect("保存成功");
    (store, id)
}

/// 一条用户策略。
fn user_policy(yaml: &str) -> PolicySet {
    let user = PolicySet::parse_yaml(yaml, "user.yaml").expect("策略合法");
    PolicySet::merge(vec![PolicySet::builtin_defaults(), user]).expect("合并成功")
}

/// 永远说「不」的确认器。
struct AlwaysDecline;
impl ActionConfirmer for AlwaysDecline {
    fn confirm(&self, _decision: &PackageDecision) -> bool {
        false
    }
}

/// 永远说「好」的确认器，并记录看到的解释。
#[derive(Default)]
struct AlwaysApprove {
    seen: Mutex<Vec<String>>,
}
impl ActionConfirmer for AlwaysApprove {
    fn confirm(&self, decision: &PackageDecision) -> bool {
        self.seen
            .lock()
            .expect("锁可用")
            .push(decision.outcome.explanation.clone());
        true
    }
}

/// 记录下来的一次执行。
#[derive(Debug, Clone, PartialEq, Eq)]
struct AppliedRecord {
    action: PackageAction,
    confirmed: bool,
    elevation_granted: bool,
}

/// 共享的执行日志，测试与执行器各持一份句柄。
#[derive(Debug, Clone, Default)]
struct Recorder(Arc<Mutex<Vec<AppliedRecord>>>);

impl Recorder {
    fn records(&self) -> Vec<AppliedRecord> {
        self.0.lock().expect("锁可用").clone()
    }

    fn actions(&self) -> Vec<PackageAction> {
        self.records()
            .into_iter()
            .map(|record| record.action)
            .collect()
    }
}

/// 内存执行器：只记录，不真的动系统。
#[derive(Debug)]
struct RecordingMutator {
    adapter: String,
    recorder: Recorder,
    fail_on: Option<PackageIdentity>,
    drift_on: Option<PackageIdentity>,
}

impl RecordingMutator {
    fn new(adapter: &str, recorder: Recorder) -> Self {
        RecordingMutator {
            adapter: adapter.to_owned(),
            recorder,
            fail_on: None,
            drift_on: None,
        }
    }

    fn failing(mut self, identity: &str) -> Self {
        self.fail_on = Some(id(identity));
        self
    }

    fn drifting(mut self, identity: &str) -> Self {
        self.drift_on = Some(id(identity));
        self
    }
}

impl PackageMutator for RecordingMutator {
    fn adapter_id(&self) -> &str {
        &self.adapter
    }

    fn apply(
        &self,
        action: &PackageAction,
        authorization: ActionAuthorization,
    ) -> Result<PackageActionReceipt, PackageError> {
        if self.fail_on.as_ref() == Some(&action.identity) {
            return Err(PackageError::Executor {
                adapter: self.adapter.clone(),
                identity: action.identity.to_string(),
                kind: action.kind.as_str(),
                code: "package_adapter.manager_failed".to_owned(),
                detail: "磁盘空间不足".to_owned(),
            });
        }
        self.recorder.0.lock().expect("锁可用").push(AppliedRecord {
            action: action.clone(),
            confirmed: authorization.confirmed(),
            elevation_granted: authorization.elevation_granted(),
        });
        Ok(PackageActionReceipt {
            adapter: self.adapter.clone(),
            identity: action.identity.clone(),
            kind: action.kind,
            before_version: action.from_version.clone(),
            after_version: match action.kind {
                PackageActionKind::Uninstall => None,
                _ => Some("2.0.0".to_owned()),
            },
            rollback: action.rollback,
            started_at_unix_ms: 10,
            finished_at_unix_ms: 20,
        })
    }

    fn verify(&self, action: &PackageAction) -> Result<(), PackageError> {
        if self.drift_on.as_ref() == Some(&action.identity) {
            return Err(PackageError::VerifyFailed {
                identity: action.identity.to_string(),
                kind: action.kind.as_str(),
                expected: "installed 2.0.0".to_owned(),
                actual: "installed 1.0.0".to_owned(),
            });
        }
        Ok(())
    }
}

/// 构造只含一个执行器的注册表。
fn registry(mutator: RecordingMutator) -> BTreeMap<String, Box<dyn PackageMutator>> {
    let mut map: BTreeMap<String, Box<dyn PackageMutator>> = BTreeMap::new();
    map.insert(mutator.adapter.clone(), Box::new(mutator));
    map
}

// ---------------------------------------------------------------------------
// §6 硬约束：缺失包 install，额外包绝不 uninstall
// ---------------------------------------------------------------------------

#[test]
fn missing_package_yields_install_all_the_way_through_apply() {
    let desired = PackageIntentSet::from_intents([
        PackageIntent::new(id("fakeuser:ripgrep")),
        PackageIntent::new(id("fakeuser:fd")),
    ])
    .unwrap();
    let mut observed = PackageObservationSet::new(manager("fakeuser"), 0);
    observed
        .insert(PackageObservation::installed(
            id("fakeuser:fd"),
            Some("9.0.0"),
        ))
        .unwrap();

    let actions = desired.derive_actions(&observed).unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].kind, PackageActionKind::Install);

    let (store, plan_id) = saved(
        actions
            .into_iter()
            .map(|action| PlannedPackageAction::new(USER_ADAPTER, action))
            .collect(),
    );
    let policy = PolicySet::builtin_defaults();
    let device = profile();

    // 普通安装：策略直接放行，也不需要确认。
    let decisions = evaluate_plan(&policy, &store.load(plan_id).unwrap().unwrap(), &device);
    assert_eq!(decisions[0].outcome.decision, Decision::Allow);
    assert!(!decisions[0].requires_confirmation());

    let recorder = Recorder::default();
    let registry = registry(RecordingMutator::new(USER_ADAPTER, recorder.clone()));
    let confirmed = ConfirmedPlan::load_and_confirm(
        &store,
        plan_id,
        &policy,
        &device,
        // 连 `--yes` 都不需要：低风险动作没有确认问题要回答。
        Confirmation::Interactive(&AlwaysDecline),
    )
    .unwrap();
    assert_eq!(confirmed.len(), 1);
    assert!(confirmed.declined().is_empty());

    let outcome = apply_packages(plan_id, confirmed, &policy, &device, &registry).unwrap();
    assert_eq!(outcome.applied_count(), 1);
    assert_eq!(outcome.receipts[0].kind, PackageActionKind::Install);
    assert_eq!(recorder.actions().len(), 1);
}

#[test]
fn observed_extra_packages_never_reach_the_plan() {
    // 本机装了三个包，期望里只声明了一个：不得产生任何卸载。
    let desired =
        PackageIntentSet::from_intents([PackageIntent::new(id("fakeuser:ripgrep"))]).unwrap();
    let mut observed = PackageObservationSet::new(manager("fakeuser"), 0);
    for (package, version) in [
        ("fakeuser:ripgrep", "14.1.0"),
        ("fakeuser:personal-tool", "1.0.0"),
        ("fakeuser:another-extra", "0.1.0"),
    ] {
        observed
            .insert(PackageObservation::installed(id(package), Some(version)))
            .unwrap();
    }

    let actions = desired.derive_actions(&observed).unwrap();
    assert!(actions.is_empty(), "额外包不得产生动作，实际 {actions:?}");

    let (store, plan_id) = saved(Vec::new());
    let policy = PolicySet::builtin_defaults();
    let device = profile();
    let confirmed =
        ConfirmedPlan::load_and_confirm(&store, plan_id, &policy, &device, Confirmation::AssumeYes)
            .unwrap();
    assert!(confirmed.is_empty());

    let recorder = Recorder::default();
    let registry = registry(RecordingMutator::new(USER_ADAPTER, recorder.clone()));
    let outcome = apply_packages(plan_id, confirmed, &policy, &device, &registry).unwrap();
    assert_eq!(outcome.applied_count(), 0);
    assert!(recorder.records().is_empty(), "不该有任何动作被执行");
}

// ---------------------------------------------------------------------------
// 策略拦截：uninstall
// ---------------------------------------------------------------------------

#[test]
fn uninstall_requires_confirmation_by_builtin_policy() {
    let (store, plan_id) = saved(vec![PlannedPackageAction::new(
        USER_ADAPTER,
        action("fakeuser:ripgrep", PackageActionKind::Uninstall),
    )]);
    let policy = PolicySet::builtin_defaults();
    let device = profile();

    let decisions = evaluate_plan(&policy, &store.load(plan_id).unwrap().unwrap(), &device);
    assert_eq!(decisions[0].outcome.decision, Decision::RequireConfirmation);
    assert!(decisions[0]
        .outcome
        .matched_rule_ids()
        .contains(&BUILTIN_PACKAGE_UNINSTALL));

    // 用户拒绝：动作被丢弃，其余流程照常（丢弃永远是安全方向）。
    let declined = ConfirmedPlan::load_and_confirm(
        &store,
        plan_id,
        &policy,
        &device,
        Confirmation::Interactive(&AlwaysDecline),
    )
    .unwrap();
    assert!(declined.is_empty());
    assert_eq!(declined.declined().len(), 1);

    let recorder = Recorder::default();
    let registry = registry(RecordingMutator::new(USER_ADAPTER, recorder.clone()));
    let outcome = apply_packages(plan_id, declined, &policy, &device, &registry).unwrap();
    assert_eq!(outcome.applied_count(), 0);
    assert_eq!(outcome.declined.len(), 1);
    assert!(recorder.records().is_empty());

    // 用户同意：真的执行，且确认器看得到完整解释。
    let approver = AlwaysApprove::default();
    let approved = ConfirmedPlan::load_and_confirm(
        &store,
        plan_id,
        &policy,
        &device,
        Confirmation::Interactive(&approver),
    )
    .unwrap();
    assert_eq!(approved.len(), 1);
    assert!(approver.seen.lock().unwrap()[0].contains(BUILTIN_PACKAGE_UNINSTALL));

    let outcome = apply_packages(plan_id, approved, &policy, &device, &registry).unwrap();
    assert_eq!(outcome.applied_count(), 1);
    assert!(recorder.records()[0].confirmed);
}

#[test]
fn policy_can_deny_uninstall_outright() {
    let policy = user_policy(
        "version: 1\n\
         rules:\n  \
           - id: local.no-uninstall\n    \
             priority: 100\n    \
             decision: deny\n    \
             reason: 本机禁止由同步流程卸载包\n    \
             match:\n      \
               resource_kind: package\n      \
               operation: uninstall\n",
    );
    let (store, plan_id) = saved(vec![PlannedPackageAction::new(
        USER_ADAPTER,
        action("fakeuser:ripgrep", PackageActionKind::Uninstall),
    )]);
    let device = profile();

    let err =
        ConfirmedPlan::load_and_confirm(&store, plan_id, &policy, &device, Confirmation::AssumeYes)
            .expect_err("被拒绝的动作不得进入已确认计划");
    match &err {
        PackageError::PolicyDenied {
            adapter,
            identity,
            kind,
            explanation,
        } => {
            assert_eq!(adapter, USER_ADAPTER);
            assert_eq!(identity, "fakeuser:ripgrep");
            assert_eq!(*kind, "uninstall");
            assert!(
                explanation.contains("local.no-uninstall"),
                "解释里必须写明是哪条规则拦下的"
            );
        }
        other => panic!("期望 PolicyDenied，实际 {other:?}"),
    }
    assert_eq!(err.code(), "packages.policy_denied");
}

// ---------------------------------------------------------------------------
// 策略拦截：downgrade
// ---------------------------------------------------------------------------

#[test]
fn downgrade_requires_confirmation_and_can_be_denied() {
    let (store, plan_id) = saved(vec![PlannedPackageAction::new(
        USER_ADAPTER,
        action("fakeuser:ripgrep", PackageActionKind::Downgrade),
    )]);
    let device = profile();

    let builtin = PolicySet::builtin_defaults();
    let decisions = evaluate_plan(&builtin, &store.load(plan_id).unwrap().unwrap(), &device);
    assert_eq!(decisions[0].outcome.decision, Decision::RequireConfirmation);
    assert!(decisions[0]
        .outcome
        .matched_rule_ids()
        .contains(&BUILTIN_PACKAGE_DOWNGRADE));
    assert_eq!(decisions[0].action.risk, Risk::High, "降级恒为高风险");

    let denying = user_policy(
        "version: 1\n\
         rules:\n  \
           - id: local.no-downgrade\n    \
             decision: deny\n    \
             match:\n      \
               resource_kind: package\n      \
               operation: downgrade\n",
    );
    assert!(matches!(
        ConfirmedPlan::load_and_confirm(
            &store,
            plan_id,
            &denying,
            &device,
            Confirmation::AssumeYes
        ),
        Err(PackageError::PolicyDenied { .. })
    ));
}

// ---------------------------------------------------------------------------
// 策略拦截：system scope 与 elevation
// ---------------------------------------------------------------------------

#[test]
fn system_scope_package_writes_are_denied_by_default() {
    // 适配器 ID 落在 `builtin.pkg.system.` 前缀下，内建策略据此拦截一切写操作。
    let mut install = action("fakesystem:zsh", PackageActionKind::Install);
    install.risk = Risk::High;
    install.rollback = RollbackCapability::None;
    let (store, plan_id) = saved(vec![PlannedPackageAction::new(SYSTEM_ADAPTER, install)]);
    let device = profile();
    let policy = PolicySet::builtin_defaults();

    let decisions = evaluate_plan(&policy, &store.load(plan_id).unwrap().unwrap(), &device);
    assert_eq!(decisions[0].outcome.decision, Decision::Deny);
    assert!(decisions[0]
        .outcome
        .matched_rule_ids()
        .contains(&BUILTIN_SYSTEM_PACKAGE_WRITE));

    let err =
        ConfirmedPlan::load_and_confirm(&store, plan_id, &policy, &device, Confirmation::AssumeYes)
            .unwrap_err();
    assert!(matches!(err, PackageError::PolicyDenied { .. }));
}

#[test]
fn elevation_required_actions_are_denied_by_default() {
    let mut install = action("fakesystem:zsh", PackageActionKind::Install);
    install.elevation_required = true;
    install.risk = Risk::High;
    // 刻意用一个**非**系统前缀的适配器 ID，确保拦下它的是提权规则本身。
    let (store, plan_id) = saved(vec![PlannedPackageAction::new(
        "fake.pkg.needs-elevation",
        install,
    )]);
    let device = profile();
    let policy = PolicySet::builtin_defaults();

    let decisions = evaluate_plan(&policy, &store.load(plan_id).unwrap().unwrap(), &device);
    assert_eq!(decisions[0].outcome.decision, Decision::Deny);
    assert!(decisions[0]
        .outcome
        .matched_rule_ids()
        .contains(&BUILTIN_ELEVATION_DENIED));
    assert!(matches!(
        ConfirmedPlan::load_and_confirm(&store, plan_id, &policy, &device, Confirmation::AssumeYes),
        Err(PackageError::PolicyDenied { .. })
    ));
}

#[test]
fn elevation_is_granted_only_after_the_builtin_deny_is_explicitly_relaxed() {
    let mut install = action("fakesystem:zsh", PackageActionKind::Install);
    install.elevation_required = true;
    install.risk = Risk::High;
    let (store, plan_id) = saved(vec![PlannedPackageAction::new(
        "fake.pkg.needs-elevation",
        install,
    )]);
    let device = profile();

    // 唯一的放宽途径是指名道姓地重新声明那条内建规则——这会留在 diff 与审计里。
    let relaxed = user_policy(&format!(
        "version: 1\n\
         rules:\n  \
           - id: {BUILTIN_ELEVATION_DENIED}\n    \
             decision: require_confirmation\n    \
             match:\n      \
               elevation_required: true\n"
    ));

    let recorder = Recorder::default();
    let registry = registry(RecordingMutator::new(
        "fake.pkg.needs-elevation",
        recorder.clone(),
    ));
    let confirmed = ConfirmedPlan::load_and_confirm(
        &store,
        plan_id,
        &relaxed,
        &device,
        Confirmation::AssumeYes,
    )
    .expect("放宽之后才可能通过");
    apply_packages(plan_id, confirmed, &relaxed, &device, &registry).unwrap();

    let record = &recorder.records()[0];
    assert!(record.confirmed);
    assert!(
        record.elevation_granted,
        "提权授权只在策略放行且用户确认之后才派发"
    );
}

// ---------------------------------------------------------------------------
// `--yes` 的边界
// ---------------------------------------------------------------------------

#[test]
fn assume_yes_only_accepts_a_saved_plan_id() {
    let store = InMemoryPackagePlanStore::new();
    let err = ConfirmedPlan::load_and_confirm(
        &store,
        PlanId::of("从未保存过的计划".as_bytes()),
        &PolicySet::builtin_defaults(),
        &profile(),
        Confirmation::AssumeYes,
    )
    .expect_err("凭空捏造的计划标识必须被拒绝");
    assert!(matches!(err, PackageError::UnknownPlan(_)));
    assert_eq!(err.code(), "packages.unknown_plan");
}

#[test]
fn assume_yes_cannot_bypass_a_deny_decision() {
    let policy = user_policy(
        "version: 1\n\
         rules:\n  \
           - id: local.no-package-writes\n    \
             decision: deny\n    \
             match:\n      \
               resource_kind: package\n",
    );
    let device = profile();

    for kind in [
        PackageActionKind::Install,
        PackageActionKind::Upgrade,
        PackageActionKind::Downgrade,
        PackageActionKind::Uninstall,
        PackageActionKind::ChangeSource,
    ] {
        let (store, plan_id) = saved(vec![PlannedPackageAction::new(
            USER_ADAPTER,
            action("fakeuser:ripgrep", kind),
        )]);
        let err = ConfirmedPlan::load_and_confirm(
            &store,
            plan_id,
            &policy,
            &device,
            Confirmation::AssumeYes,
        )
        .unwrap_err();
        assert!(
            matches!(err, PackageError::PolicyDenied { .. }),
            "{kind:?} 必须被策略拒绝，实际 {err:?}"
        );
    }
}

#[test]
fn apply_rechecks_policy_between_confirmation_and_execution() {
    let (store, plan_id) = saved(vec![PlannedPackageAction::new(
        USER_ADAPTER,
        action("fakeuser:ripgrep", PackageActionKind::Uninstall),
    )]);
    let device = profile();

    // 确认时策略只要求确认。
    let permissive = PolicySet::builtin_defaults();
    let confirmed = ConfirmedPlan::load_and_confirm(
        &store,
        plan_id,
        &permissive,
        &device,
        Confirmation::AssumeYes,
    )
    .unwrap();
    assert_eq!(confirmed.len(), 1);

    // 执行时同步下来一份更严的策略：必须中止。
    let stricter = user_policy(
        "version: 1\n\
         rules:\n  \
           - id: local.no-uninstall\n    \
             decision: deny\n    \
             match:\n      \
               operation: uninstall\n",
    );
    let recorder = Recorder::default();
    let registry = registry(RecordingMutator::new(USER_ADAPTER, recorder.clone()));
    let err = apply_packages(plan_id, confirmed, &stricter, &device, &registry).unwrap_err();
    assert!(matches!(err, PackageError::PolicyDenied { .. }));
    assert!(
        recorder.records().is_empty(),
        "执行期复检必须在动手之前拦住"
    );
}

// ---------------------------------------------------------------------------
// 计划绑定与执行失败
// ---------------------------------------------------------------------------

#[test]
fn applying_a_different_plan_id_than_the_confirmed_one_is_rejected() {
    let (store, plan_id) = saved(vec![PlannedPackageAction::new(
        USER_ADAPTER,
        action("fakeuser:ripgrep", PackageActionKind::Install),
    )]);
    let policy = PolicySet::builtin_defaults();
    let device = profile();
    let confirmed =
        ConfirmedPlan::load_and_confirm(&store, plan_id, &policy, &device, Confirmation::AssumeYes)
            .unwrap();

    let recorder = Recorder::default();
    let registry = registry(RecordingMutator::new(USER_ADAPTER, recorder.clone()));
    let err = apply_packages(
        PlanId::of("另一份计划".as_bytes()),
        confirmed,
        &policy,
        &device,
        &registry,
    )
    .unwrap_err();
    assert!(matches!(err, PackageError::PlanMismatch { .. }));
    assert!(recorder.records().is_empty());
}

#[test]
fn unknown_adapter_in_the_plan_is_rejected_before_execution() {
    let (store, plan_id) = saved(vec![PlannedPackageAction::new(
        "fake.pkg.not-registered",
        action("fakeuser:ripgrep", PackageActionKind::Install),
    )]);
    let policy = PolicySet::builtin_defaults();
    let device = profile();
    let confirmed =
        ConfirmedPlan::load_and_confirm(&store, plan_id, &policy, &device, Confirmation::AssumeYes)
            .unwrap();

    let registry = registry(RecordingMutator::new(USER_ADAPTER, Recorder::default()));
    let err = apply_packages(plan_id, confirmed, &policy, &device, &registry).unwrap_err();
    assert!(matches!(err, PackageError::UnknownAdapter { .. }));
}

#[test]
fn execution_failure_stops_the_run() {
    let (store, plan_id) = saved(vec![
        PlannedPackageAction::new(
            USER_ADAPTER,
            action("fakeuser:aaa", PackageActionKind::Install),
        ),
        PlannedPackageAction::new(
            USER_ADAPTER,
            action("fakeuser:bbb", PackageActionKind::Install),
        ),
        PlannedPackageAction::new(
            USER_ADAPTER,
            action("fakeuser:ccc", PackageActionKind::Install),
        ),
    ]);
    let policy = PolicySet::builtin_defaults();
    let device = profile();
    let confirmed =
        ConfirmedPlan::load_and_confirm(&store, plan_id, &policy, &device, Confirmation::AssumeYes)
            .unwrap();

    let recorder = Recorder::default();
    let registry =
        registry(RecordingMutator::new(USER_ADAPTER, recorder.clone()).failing("fakeuser:bbb"));
    let err = apply_packages(plan_id, confirmed, &policy, &device, &registry).unwrap_err();
    assert!(matches!(err, PackageError::Executor { .. }));
    assert_eq!(err.code(), "packages.executor");

    // 第一个动作已经发生，第三个没有：失败即停。
    let applied: Vec<String> = recorder
        .actions()
        .iter()
        .map(|action| action.identity.to_string())
        .collect();
    assert_eq!(applied, vec!["fakeuser:aaa".to_owned()]);
}

#[test]
fn verify_drift_after_apply_is_reported() {
    let (store, plan_id) = saved(vec![PlannedPackageAction::new(
        USER_ADAPTER,
        action("fakeuser:ripgrep", PackageActionKind::Install),
    )]);
    let policy = PolicySet::builtin_defaults();
    let device = profile();
    let confirmed =
        ConfirmedPlan::load_and_confirm(&store, plan_id, &policy, &device, Confirmation::AssumeYes)
            .unwrap();

    let registry = registry(
        RecordingMutator::new(USER_ADAPTER, Recorder::default()).drifting("fakeuser:ripgrep"),
    );
    let err = apply_packages(plan_id, confirmed, &policy, &device, &registry).unwrap_err();
    assert!(matches!(err, PackageError::VerifyFailed { .. }));
    assert_eq!(err.code(), "packages.verify_failed");
}

// ---------------------------------------------------------------------------
// 回滚能力如实进入收据
// ---------------------------------------------------------------------------

#[test]
fn rollback_capability_reaches_the_receipt_unchanged() {
    for capability in [
        RollbackCapability::Exact,
        RollbackCapability::Compensating,
        RollbackCapability::None,
    ] {
        let mut install = action("fakeuser:ripgrep", PackageActionKind::Install);
        install.rollback = capability;
        let (store, plan_id) = saved(vec![PlannedPackageAction::new(USER_ADAPTER, install)]);
        let policy = PolicySet::builtin_defaults();
        let device = profile();
        let confirmed = ConfirmedPlan::load_and_confirm(
            &store,
            plan_id,
            &policy,
            &device,
            Confirmation::AssumeYes,
        )
        .unwrap();
        let registry = registry(RecordingMutator::new(USER_ADAPTER, Recorder::default()));
        let outcome = apply_packages(plan_id, confirmed, &policy, &device, &registry).unwrap();

        assert_eq!(outcome.receipts[0].rollback, capability);
        let irreversible = outcome.irreversible().count();
        assert_eq!(
            irreversible,
            usize::from(capability == RollbackCapability::None),
            "无法回滚的动作必须能被恢复流程一眼看出来"
        );
    }
}

#[test]
fn plan_is_deterministic_and_unmanaged_intents_stay_out_of_it() {
    let desired = PackageIntentSet::from_intents([
        PackageIntent::new(id("fakeuser:ripgrep")),
        PackageIntent::new(id("fakeuser:legacy")).with_disposition(PackageDisposition::Unmanaged),
    ])
    .unwrap();
    let observed = PackageObservationSet::new(manager("fakeuser"), 0);
    let actions = desired.derive_actions(&observed).unwrap();
    assert_eq!(actions.len(), 1, "unmanaged 的包不参与收敛");

    let entries: Vec<PlannedPackageAction> = actions
        .into_iter()
        .map(|action| PlannedPackageAction::new(USER_ADAPTER, action))
        .collect();
    let forward = PackagePlan::new(entries.clone(), 1);
    let backward = PackagePlan::new(entries.into_iter().rev(), 999);
    assert_eq!(forward.id(), backward.id(), "计划标识与顺序、时刻都无关");
}
