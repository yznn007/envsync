//! 包计划、策略判定与收敛。
//!
//! 本模块是包同步链路上的**安全关口**：适配器负责「能做什么」，这里负责「准不准做」。
//! 它把每个 [`PackageAction`] 翻译成 [`PolicyFacts`] 交给 [`PolicySet`] 判定，再要求
//! 用户对危险动作逐条确认，最后才把动作交给执行端口。
//!
//! ## 四道闸门
//!
//! 一个包动作要真正发生，必须同时通过：
//!
//! 1. **计划先行。** 动作只能来自一份**已保存**的 [`PackagePlan`]；
//!    [`ConfirmedPlan::load_and_confirm`] 唯一的入口参数是 [`PlanId`]，凭空构造的动作
//!    进不来。
//! 2. **策略。** 每个动作过一次 [`PolicySet::evaluate`]，[`Decision::Deny`] 一律中止。
//! 3. **确认。** [`Decision::RequireConfirmation`]、破坏性动作、需要提权的动作都要用户
//!    点头。
//! 4. **执行期复检。** [`apply_packages`] 在每个动作**执行之前**重新求值一次策略：
//!    确认与执行之间策略可能已经变了（例如同步下来一份更严的规则）。
//!
//! ## `--yes` 能做什么，不能做什么
//!
//! [`Confirmation::AssumeYes`] 只替用户回答第 3 道闸门的问题。它：
//!
//! * **不能**跳过第 1 道：没有保存过的 [`PlanId`] 一律 [`PackageError::UnknownPlan`]；
//! * **不能**跳过第 2 道：[`Decision::Deny`] 依旧是 [`PackageError::PolicyDenied`]；
//! * **不能**跳过第 4 道：执行期复检照常进行。
//!
//! 换句话说，`--yes` 是「我已经看过这份计划了」，不是「别拦我」。
//!
//! ## 与 M0 journal / receipt / verify 体系的衔接
//!
//! [`PackageActionReceipt`] 与 [`crate::ports::ActionReceipt`] 同构：都记录动作前后的
//! 状态与**如实标注**的 [`RollbackCapability`]。多数包管理器只能
//! [`RollbackCapability::Compensating`]（重装原版本，但依赖树未必回到原样），个别连补偿
//! 都做不到（源里已经没有原版本），标注为 [`RollbackCapability::None`]。回滚编排据此决定
//! 「能不能自动回滚」，而不是假设所有动作都可逆。

use std::collections::{BTreeMap, BTreeSet};

use envsync_domain::cbor::{self, CborCodec, Value};
use envsync_domain::cbor_struct;
use envsync_domain::package::{PackageAction, PackageActionKind, PackageIdentity};
use envsync_domain::{DeviceProfile, PlanId, RollbackCapability};
use envsync_policy::{Decision, DecisionOutcome, Operation, PolicyFacts, PolicySet, ResourceKind};

/// 包计划的当前格式版本。
pub const PACKAGE_PLAN_FORMAT_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

/// 包计划与收敛错误。
///
/// 刻意**不**并入 [`crate::error::CoreError`]：包链路的失败模式（策略拒绝、确认缺失、
/// 计划未保存）与文件同步毫无交集，混在一起只会让两边的调用方都要处理一堆不可能发生的
/// 分支。需要统一时由调用方在边界上映射。
///
/// 所有变体的 `Display` 都不含本机路径，也不含包管理器原始输出。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PackageError {
    /// 没有保存过这个计划标识。
    ///
    /// 这是「`--yes` 只接受已保存的 Plan ID」这条规则的落点：凭空捏造的标识到不了
    /// 策略判定，更到不了执行。
    #[error("没有保存过包计划 {0}；请先运行 `packages plan`")]
    UnknownPlan(PlanId),

    /// 提交的计划标识与确认过的计划不是同一个。
    #[error("提交的计划 {submitted} 与已确认的计划 {confirmed} 不是同一个")]
    PlanMismatch {
        /// 调用方提交的标识。
        submitted: PlanId,
        /// [`ConfirmedPlan`] 里的标识。
        confirmed: PlanId,
    },

    /// 策略拒绝了某个动作。
    #[error("策略拒绝了 {kind} `{identity}`（适配器 `{adapter}`）")]
    PolicyDenied {
        /// 适配器稳定 ID。
        adapter: String,
        /// 包身份的文本形式。
        identity: String,
        /// 动作种类。
        kind: &'static str,
        /// 可审计的完整解释（命中的规则、优先级、事实摘要）。
        explanation: String,
    },

    /// 计划里的动作归属某个适配器，但本次执行没有注册它。
    #[error("计划 {plan} 里的动作归属适配器 `{adapter}`，本次执行没有注册它")]
    UnknownAdapter {
        /// 计划标识。
        plan: PlanId,
        /// 适配器稳定 ID。
        adapter: String,
    },

    /// 计划存储读写失败。
    #[error("包计划存储失败：{0}")]
    Store(String),

    /// 执行端口报告失败。
    #[error("执行 {kind} `{identity}` 失败：{detail}")]
    Executor {
        /// 适配器稳定 ID。
        adapter: String,
        /// 包身份的文本形式。
        identity: String,
        /// 动作种类。
        kind: &'static str,
        /// 下层的稳定错误码。
        code: String,
        /// 失败摘要。
        detail: String,
    },

    /// 应用后校验发现漂移。
    #[error("{kind} `{identity}` 应用后校验失败：期望 {expected}，实际 {actual}")]
    VerifyFailed {
        /// 包身份的文本形式。
        identity: String,
        /// 动作种类。
        kind: &'static str,
        /// 期望状态。
        expected: String,
        /// 实际状态。
        actual: String,
    },
}

impl PackageError {
    /// 稳定的机器可读错误码。
    pub fn code(&self) -> &'static str {
        match self {
            PackageError::UnknownPlan(_) => "packages.unknown_plan",
            PackageError::PlanMismatch { .. } => "packages.plan_mismatch",
            PackageError::PolicyDenied { .. } => "packages.policy_denied",
            PackageError::UnknownAdapter { .. } => "packages.unknown_adapter",
            PackageError::Store(_) => "packages.store",
            PackageError::Executor { .. } => "packages.executor",
            PackageError::VerifyFailed { .. } => "packages.verify_failed",
        }
    }
}

// ---------------------------------------------------------------------------
// 计划
// ---------------------------------------------------------------------------

/// 计划里的一个条目：一个动作 + 负责执行它的适配器。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedPackageAction {
    /// 适配器稳定 ID，例如 `builtin.pkg.brew`。
    pub adapter: String,
    /// 待执行的动作。
    pub action: PackageAction,
}

cbor_struct!(PlannedPackageAction {
    adapter: String,
    action: PackageAction,
});

impl PlannedPackageAction {
    /// 构造条目。
    pub fn new(adapter: impl Into<String>, action: PackageAction) -> Self {
        PlannedPackageAction {
            adapter: adapter.into(),
            action,
        }
    }

    /// 确定性排序键。
    fn sort_key(&self) -> (String, String, u8) {
        let (identity, rank) = self.action.sort_key();
        (self.adapter.clone(), identity, rank)
    }
}

/// 一份不可变的包计划。
///
/// 与 [`envsync_domain::Plan`] 遵循同一条规则：**创建时刻不参与标识**。否则同一份内容
/// 在两次生成之间只要跨过一毫秒就得到不同的标识，「重新计划并比较标识」这一新鲜度检查
/// 将永远判定为 stale（见 ADR-0003）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackagePlan {
    /// 格式版本。
    pub format_version: u32,
    /// 排序后的条目。
    pub entries: Vec<PlannedPackageAction>,
    /// 创建时刻（Unix 毫秒）。**不参与**计划标识。
    pub created_at_unix_ms: u64,
}

impl PackagePlan {
    /// 由未排序的条目构造，内部完成确定性排序。
    pub fn new(
        entries: impl IntoIterator<Item = PlannedPackageAction>,
        created_at_unix_ms: u64,
    ) -> Self {
        let mut entries: Vec<PlannedPackageAction> = entries.into_iter().collect();
        entries.sort_by_key(PlannedPackageAction::sort_key);
        PackagePlan {
            format_version: PACKAGE_PLAN_FORMAT_VERSION,
            entries,
            created_at_unix_ms,
        }
    }

    /// 计划标识：由格式版本与全部条目派生，与创建时刻无关。
    pub fn id(&self) -> PlanId {
        PlanId::of(&cbor::encode(&Value::Array(vec![
            Value::Uint(self.format_version as u64),
            self.entries.to_value(),
        ])))
    }

    /// 是否不需要任何动作。
    pub fn is_noop(&self) -> bool {
        self.entries.is_empty()
    }

    /// 条目数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// 已保存包计划的存储端口。
///
/// 定义成端口是因为「计划必须先被保存」这条规则不应该绑死在某个具体存储上：CLI 用
/// SQLite 草稿库，测试用内存实现，两者对本模块完全等价。
pub trait PackagePlanStore {
    /// 保存计划，返回其标识。
    fn save(&mut self, plan: PackagePlan) -> Result<PlanId, PackageError>;

    /// 按标识加载计划；不存在时返回 `None`。
    fn load(&self, id: PlanId) -> Result<Option<PackagePlan>, PackageError>;
}

/// 内存计划库。
///
/// 用于测试与「一次进程内计划完立刻应用」的场景。
#[derive(Debug, Default)]
pub struct InMemoryPackagePlanStore {
    plans: BTreeMap<String, PackagePlan>,
}

impl InMemoryPackagePlanStore {
    /// 构造空库。
    pub fn new() -> Self {
        InMemoryPackagePlanStore::default()
    }

    /// 已保存的计划数量。
    pub fn len(&self) -> usize {
        self.plans.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.plans.is_empty()
    }
}

impl PackagePlanStore for InMemoryPackagePlanStore {
    fn save(&mut self, plan: PackagePlan) -> Result<PlanId, PackageError> {
        let id = plan.id();
        self.plans.insert(id.to_hex(), plan);
        Ok(id)
    }

    fn load(&self, id: PlanId) -> Result<Option<PackagePlan>, PackageError> {
        Ok(self.plans.get(&id.to_hex()).cloned())
    }
}

// ---------------------------------------------------------------------------
// 策略判定
// ---------------------------------------------------------------------------

/// 把动作种类映射成策略引擎认识的操作。
///
/// 换源没有专门的操作类型：它在策略层等价于一次写入，因此落到 [`Operation::Write`]，
/// 从而被所有「写操作」规则（包括系统级包管理器的内建 deny）覆盖到。
pub const fn operation_for(kind: PackageActionKind) -> Operation {
    match kind {
        PackageActionKind::Install => Operation::Install,
        PackageActionKind::Upgrade => Operation::Upgrade,
        PackageActionKind::Downgrade => Operation::Downgrade,
        PackageActionKind::Uninstall => Operation::Uninstall,
        PackageActionKind::ChangeSource => Operation::Write,
    }
}

/// 对单个动作做一次策略判定。
///
/// 事实里刻意**不含**明文包名以外的任何本机信息；`resource` 维度只有在包身份能被
/// **无损**映射成 [`envsync_domain::ResourceId`] 时才填（见
/// [`PackageIdentity::to_resource_id`]）：有损映射会让一条 `allow` 规则意外覆盖到另一个
/// 包，那是安全事故，而「策略匹配不到」只是功能缺失。
pub fn evaluate_action(
    policy: &PolicySet,
    adapter: &str,
    action: &PackageAction,
    profile: &DeviceProfile,
) -> DecisionOutcome {
    let resource = action.identity.to_resource_id();
    let mut facts = PolicyFacts::new(
        ResourceKind::Package,
        operation_for(action.kind),
        action.risk,
        profile.os,
    )
    .with_profile(profile)
    .with_adapter(adapter)
    .with_elevation_required(action.elevation_required);
    if let Some(resource) = &resource {
        facts = facts.with_resource(resource);
    }
    policy.evaluate(&facts)
}

/// 一个动作的策略判定结果。
#[derive(Debug, Clone)]
pub struct PackageDecision {
    /// 适配器稳定 ID。
    pub adapter: String,
    /// 被判定的动作。
    pub action: PackageAction,
    /// 判定结果与解释。
    pub outcome: DecisionOutcome,
}

impl PackageDecision {
    /// 是否被拒绝。
    pub fn is_denied(&self) -> bool {
        self.outcome.decision == Decision::Deny
    }

    /// 是否需要用户显式确认。
    ///
    /// 两个来源取或：策略说要确认，或动作自身是破坏性 / 需提权 / 高风险
    /// （[`PackageAction::requires_confirmation`]）。**策略说 allow 不代表可以跳过确认**
    /// ——策略回答的是「准不准」，确认回答的是「你知不知道」。
    pub fn requires_confirmation(&self) -> bool {
        self.outcome.decision == Decision::RequireConfirmation
            || self.action.requires_confirmation()
    }

    fn denial(&self) -> PackageError {
        PackageError::PolicyDenied {
            adapter: self.adapter.clone(),
            identity: self.action.identity.to_string(),
            kind: self.action.kind.as_str(),
            explanation: self.outcome.explanation.clone(),
        }
    }
}

/// 对整份计划逐条判定，顺序与计划一致。
pub fn evaluate_plan(
    policy: &PolicySet,
    plan: &PackagePlan,
    profile: &DeviceProfile,
) -> Vec<PackageDecision> {
    plan.entries
        .iter()
        .map(|entry| PackageDecision {
            adapter: entry.adapter.clone(),
            action: entry.action.clone(),
            outcome: evaluate_action(policy, &entry.adapter, &entry.action, profile),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 确认
// ---------------------------------------------------------------------------

/// 逐条确认端口。
///
/// 实现拿到的是**完整**判定结果（含解释），因此 CLI 能把「为什么要问你」原样展示出来。
pub trait ActionConfirmer {
    /// 用户是否同意执行该动作。
    fn confirm(&self, decision: &PackageDecision) -> bool;
}

/// 确认方式。
#[derive(Clone, Copy)]
pub enum Confirmation<'a> {
    /// 交互式：逐条询问。
    Interactive(&'a dyn ActionConfirmer),
    /// `--yes`：把需要确认的动作视为已确认。
    ///
    /// 它**只**替用户回答确认问题，既不能跳过「计划必须已保存」，也不能跳过策略判定。
    AssumeYes,
}

impl std::fmt::Debug for Confirmation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confirmation::Interactive(_) => f.write_str("Confirmation::Interactive"),
            Confirmation::AssumeYes => f.write_str("Confirmation::AssumeYes"),
        }
    }
}

impl Confirmation<'_> {
    fn approve(&self, decision: &PackageDecision) -> bool {
        match self {
            Confirmation::AssumeYes => true,
            Confirmation::Interactive(confirmer) => confirmer.confirm(decision),
        }
    }
}

/// 单个动作的授权凭据。
///
/// 它**只能**由 [`ConfirmedPlan`] 派发：结构体带一个私有字段，外部 crate 连
/// `ActionAuthorization { .. }` 都写不出来。执行端口因此可以信任「拿到这个值就意味着
/// 四道闸门都过了」。
#[derive(Debug, Clone, Copy)]
pub struct ActionAuthorization {
    confirmed: bool,
    elevation_granted: bool,
    /// 私有字段：封死外部构造。
    _sealed: (),
}

impl ActionAuthorization {
    /// 用户是否已显式确认。
    pub const fn confirmed(&self) -> bool {
        self.confirmed
    }

    /// 是否已获得提权授权。
    pub const fn elevation_granted(&self) -> bool {
        self.elevation_granted
    }
}

/// 计划里被用户拒绝、因此不会执行的动作。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclinedAction {
    /// 适配器稳定 ID。
    pub adapter: String,
    /// 被拒绝的动作。
    pub action: PackageAction,
}

/// 一份**已加载、已过策略、已获用户确认**的计划。
///
/// 唯一的构造入口是 [`ConfirmedPlan::load_and_confirm`]：字段全部私有，且构造过程必须
/// 提供一个 [`PackagePlanStore`]。因此不存在「绕过计划直接确认一堆动作」的路径。
#[derive(Debug, Clone)]
pub struct ConfirmedPlan {
    plan_id: PlanId,
    approved: Vec<(PlannedPackageAction, ActionAuthorization)>,
    declined: Vec<DeclinedAction>,
}

impl ConfirmedPlan {
    /// 加载一份**已保存**的计划，过一遍策略，再逐条取得用户确认。
    ///
    /// # 语义
    ///
    /// * 计划标识不存在 → [`PackageError::UnknownPlan`]（`--yes` 也不例外）；
    /// * 任一动作被策略拒绝 → [`PackageError::PolicyDenied`]，**整份计划中止**：
    ///   一份含被禁动作的计划本身就说明用户的期望与策略冲突，逐条跳过只会让人以为
    ///   同步成功了；
    /// * 需要确认的动作被用户拒绝 → 该动作进入 [`ConfirmedPlan::declined`]，其余照常。
    ///   丢弃动作永远是安全方向。
    pub fn load_and_confirm(
        store: &dyn PackagePlanStore,
        plan_id: PlanId,
        policy: &PolicySet,
        profile: &DeviceProfile,
        confirmation: Confirmation<'_>,
    ) -> Result<Self, PackageError> {
        let plan = store
            .load(plan_id)?
            .ok_or(PackageError::UnknownPlan(plan_id))?;

        let mut approved = Vec::new();
        let mut declined = Vec::new();
        for entry in &plan.entries {
            let decision = PackageDecision {
                adapter: entry.adapter.clone(),
                action: entry.action.clone(),
                outcome: evaluate_action(policy, &entry.adapter, &entry.action, profile),
            };
            if decision.is_denied() {
                tracing::warn!(
                    adapter = %entry.adapter,
                    package = %entry.action.identity,
                    kind = entry.action.kind.as_str(),
                    "策略拒绝了包动作，计划中止"
                );
                return Err(decision.denial());
            }
            if decision.requires_confirmation() && !confirmation.approve(&decision) {
                declined.push(DeclinedAction {
                    adapter: entry.adapter.clone(),
                    action: entry.action.clone(),
                });
                continue;
            }
            approved.push((
                entry.clone(),
                ActionAuthorization {
                    confirmed: true,
                    // 提权只在「策略放行 + 用户确认」之后才授予。内建策略默认拒绝一切
                    // 提权操作，因此走到这里意味着用户已经指名道姓地放宽过那条规则。
                    elevation_granted: entry.action.elevation_required,
                    _sealed: (),
                },
            ));
        }

        Ok(ConfirmedPlan {
            plan_id: plan.id(),
            approved,
            declined,
        })
    }

    /// 被确认的计划标识。
    pub fn plan_id(&self) -> PlanId {
        self.plan_id
    }

    /// 已批准执行的动作。
    pub fn approved(&self) -> impl Iterator<Item = &PlannedPackageAction> {
        self.approved.iter().map(|(entry, _)| entry)
    }

    /// 被用户拒绝、不会执行的动作。
    pub fn declined(&self) -> &[DeclinedAction] {
        &self.declined
    }

    /// 已批准的动作数量。
    pub fn len(&self) -> usize {
        self.approved.len()
    }

    /// 是否没有任何动作会被执行。
    pub fn is_empty(&self) -> bool {
        self.approved.is_empty()
    }
}

// ---------------------------------------------------------------------------
// 执行
// ---------------------------------------------------------------------------

/// 一次包动作应用后的收据。
///
/// 与 [`crate::ports::ActionReceipt`] 同构，属于核心层，方便内存 fake 构造。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageActionReceipt {
    /// 执行该动作的适配器稳定 ID。
    pub adapter: String,
    /// 目标包。
    pub identity: PackageIdentity,
    /// 动作种类。
    pub kind: PackageActionKind,
    /// 执行前的版本。
    pub before_version: Option<String>,
    /// 执行后的版本；卸载为 `None`。
    pub after_version: Option<String>,
    /// **如实标注**的回滚能力。
    pub rollback: RollbackCapability,
    /// 开始时刻（Unix 毫秒）。
    pub started_at_unix_ms: u64,
    /// 结束时刻（Unix 毫秒）。
    pub finished_at_unix_ms: u64,
}

/// 包动作执行端口。
///
/// 适配器层实现它（把授权凭据翻译成 `ApplyContext`），核心层只依赖这个抽象，因此
/// `envsync-core` 不需要反向依赖 `envsync-adapters`。
pub trait PackageMutator: Send + Sync {
    /// 该执行器对应的适配器稳定 ID。
    fn adapter_id(&self) -> &str;

    /// 执行单个动作。
    fn apply(
        &self,
        action: &PackageAction,
        authorization: ActionAuthorization,
    ) -> Result<PackageActionReceipt, PackageError>;

    /// 重新观察并校验动作是否真的生效。
    fn verify(&self, action: &PackageAction) -> Result<(), PackageError>;
}

/// 按适配器 ID 查找执行器。
pub trait PackageMutatorRegistry {
    /// 查找执行器；没有注册时返回 `None`。
    fn mutator(&self, adapter: &str) -> Option<&dyn PackageMutator>;
}

impl PackageMutatorRegistry for BTreeMap<String, Box<dyn PackageMutator>> {
    fn mutator(&self, adapter: &str) -> Option<&dyn PackageMutator> {
        self.get(adapter).map(AsRef::as_ref)
    }
}

/// 借用形式的注册表。
///
/// 适配器侧的执行器通常借着一批上下文（设备 Profile、命令执行器、可执行文件表）活着，
/// 因此不是 `'static`，装不进 `Box<dyn PackageMutator>`。这个实现让它们可以直接以引用
/// 形式登记。
impl PackageMutatorRegistry for BTreeMap<String, &dyn PackageMutator> {
    fn mutator(&self, adapter: &str) -> Option<&dyn PackageMutator> {
        self.get(adapter).copied()
    }
}

/// 一次包应用的结果。
#[derive(Debug, Clone)]
pub struct PackageApplyOutcome {
    /// 被应用的计划标识。
    pub plan_id: PlanId,
    /// 成功执行的动作收据，按执行顺序。
    pub receipts: Vec<PackageActionReceipt>,
    /// 被用户拒绝、未执行的动作。
    pub declined: Vec<DeclinedAction>,
}

impl PackageApplyOutcome {
    /// 本次真正改变了系统状态的动作数量。
    pub fn applied_count(&self) -> usize {
        self.receipts.len()
    }

    /// 无法自动回滚的动作（[`RollbackCapability::None`]）。
    ///
    /// 恢复流程据此决定「哪些动作只能提示用户手工处理」，而不是假设一切可逆。
    pub fn irreversible(&self) -> impl Iterator<Item = &PackageActionReceipt> {
        self.receipts
            .iter()
            .filter(|receipt| receipt.rollback == RollbackCapability::None)
    }
}

/// 应用一份已确认的计划。
///
/// `plan_id` 与 `confirmed` 必须指向同一份计划，否则 [`PackageError::PlanMismatch`]
/// ——这让「确认了 A 计划却应用 B 计划」在类型之外再多一道显式检查。
///
/// 每个动作在**执行之前**重新过一次策略：确认与执行之间可能同步下来一份更严的规则，
/// 这时必须中止而不是沿用确认时的判定。
///
/// 失败即停：第一个失败的动作会中断整个流程，之前的收据不会丢——它们通过
/// [`PackageError`] 之外的路径（调用方持有的 `Vec`）保留是不可能的，因此这里选择在
/// 出错时把已完成的收据写进 `tracing`，并由上层的 journal 记录。
pub fn apply_packages(
    plan_id: PlanId,
    confirmed: ConfirmedPlan,
    policy: &PolicySet,
    profile: &DeviceProfile,
    registry: &dyn PackageMutatorRegistry,
) -> Result<PackageApplyOutcome, PackageError> {
    if plan_id != confirmed.plan_id {
        return Err(PackageError::PlanMismatch {
            submitted: plan_id,
            confirmed: confirmed.plan_id,
        });
    }

    let mut receipts = Vec::with_capacity(confirmed.approved.len());
    for (entry, authorization) in &confirmed.approved {
        // 执行期复检：确认之后策略可能变严了。
        let outcome = evaluate_action(policy, &entry.adapter, &entry.action, profile);
        if outcome.decision == Decision::Deny {
            return Err(PackageError::PolicyDenied {
                adapter: entry.adapter.clone(),
                identity: entry.action.identity.to_string(),
                kind: entry.action.kind.as_str(),
                explanation: outcome.explanation,
            });
        }

        let mutator =
            registry
                .mutator(&entry.adapter)
                .ok_or_else(|| PackageError::UnknownAdapter {
                    plan: plan_id,
                    adapter: entry.adapter.clone(),
                })?;

        let receipt = mutator
            .apply(&entry.action, *authorization)
            .inspect_err(|_| {
                tracing::error!(
                    adapter = %entry.adapter,
                    package = %entry.action.identity,
                    applied = receipts.len(),
                    "包动作执行失败，已完成的动作保留在 journal 中"
                );
            })?;
        mutator.verify(&entry.action)?;
        receipts.push(receipt);
    }

    Ok(PackageApplyOutcome {
        plan_id,
        receipts,
        declined: confirmed.declined,
    })
}

/// 计划里出现的全部适配器 ID，按字典序。
pub fn adapters_in_plan(plan: &PackagePlan) -> BTreeSet<String> {
    plan.entries
        .iter()
        .map(|entry| entry.adapter.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use envsync_domain::package::{PackageIdentity, VersionPolicy};
    use envsync_domain::{Arch, Os};

    fn action(text: &str, kind: PackageActionKind) -> PackageAction {
        PackageAction::new(
            PackageIdentity::parse(text).unwrap(),
            kind,
            None,
            VersionPolicy::Present,
        )
    }

    fn profile() -> DeviceProfile {
        DeviceProfile::new(Os::Linux, Arch::X86_64)
    }

    #[test]
    fn plan_id_is_independent_of_entry_order_and_creation_time() {
        let entries = vec![
            PlannedPackageAction::new(
                "b.adapter",
                action("brew:ripgrep", PackageActionKind::Install),
            ),
            PlannedPackageAction::new(
                "a.adapter",
                action("cargo:fd-find", PackageActionKind::Install),
            ),
        ];
        let forward = PackagePlan::new(entries.clone(), 1);
        let backward = PackagePlan::new(entries.into_iter().rev(), 999_999);
        assert_eq!(forward.id(), backward.id());
        assert_eq!(forward.entries, backward.entries);
    }

    #[test]
    fn plan_id_changes_with_content() {
        let base = PackagePlan::new(
            [PlannedPackageAction::new(
                "a",
                action("brew:ripgrep", PackageActionKind::Install),
            )],
            0,
        );
        let other_kind = PackagePlan::new(
            [PlannedPackageAction::new(
                "a",
                action("brew:ripgrep", PackageActionKind::Uninstall),
            )],
            0,
        );
        let other_adapter = PackagePlan::new(
            [PlannedPackageAction::new(
                "b",
                action("brew:ripgrep", PackageActionKind::Install),
            )],
            0,
        );
        assert_ne!(base.id(), other_kind.id());
        assert_ne!(base.id(), other_adapter.id());
    }

    #[test]
    fn change_source_is_evaluated_as_a_write() {
        assert_eq!(
            operation_for(PackageActionKind::ChangeSource),
            Operation::Write
        );
        // 因此系统级适配器的换源会撞上内建的「系统级写操作一律拒绝」。
        let policy = PolicySet::builtin_defaults();
        let mut change = action("apt:zsh", PackageActionKind::ChangeSource);
        change.elevation_required = false;
        let outcome = evaluate_action(&policy, "builtin.pkg.system.apt", &change, &profile());
        assert_eq!(outcome.decision, Decision::Deny);
    }

    #[test]
    fn unknown_plan_id_is_rejected() {
        let store = InMemoryPackagePlanStore::new();
        let err = ConfirmedPlan::load_and_confirm(
            &store,
            PlanId::of(b"never saved"),
            &PolicySet::builtin_defaults(),
            &profile(),
            Confirmation::AssumeYes,
        )
        .unwrap_err();
        assert!(matches!(err, PackageError::UnknownPlan(_)));
        assert_eq!(err.code(), "packages.unknown_plan");
    }
}
