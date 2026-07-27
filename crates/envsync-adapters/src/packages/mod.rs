//! 包管理器适配器契约。
//!
//! 一个包适配器回答四个问题：
//!
//! 1. **这台设备上这个包管理器现在装了什么**（[`PackageAdapter::observe`]）；
//! 2. **给定期望状态与观察结果，应该做什么**（[`PackageAdapter::plan`]）；
//! 3. **怎么把一个动作真正做掉**（[`PackageAdapter::apply`]）；
//! 4. **做完之后世界是不是真的变成了期望的样子**（[`PackageAdapter::verify`]）。
//!
//! # 同步而非 async
//!
//! 契约是**同步**的，见 ADR-0004：`async fn` in trait 至今不是 dyn-compatible，而包同步
//! 事务本质上是串行的（逐个动作 apply → verify → receipt），异步化只会换来一层
//! `Pin<Box<dyn Future>>` 和到处都是的 `spawn_blocking`。
//!
//! # 适配器不持有权限
//!
//! 适配器自己**不能**执行任何命令：它拿到的 [`ObserveContext`] 里只有设备 Profile、
//! 一个受限的 `envsync_platform::command::CommandRunner` 和能力探测得到的可执行文件
//! 绝对路径。命令必须先在 runner 里注册模板，执行时逐位比对 argv；适配器无法绕过这层
//! 检查，也无法自己拼一条 shell 命令。
//!
//! # 类型放在哪里，为什么
//!
//! | 类型 | 位置 | 原因 |
//! |---|---|---|
//! | [`PackageIdentity`]、[`PackageIntent`]、[`PackageAction`]、[`PackageObservationSet`] | `envsync-domain` | 与 `plan::Action`、`resource::Observation` 完全同层：不可变、可编码、无执行手段。核心层要在**不依赖适配器**的前提下把它们送进策略引擎。 |
//! | [`PackageManagerDescriptor`]、[`PackageAdapter`]、[`PackageReceipt`] | 本模块 | 它们描述「谁来做、用什么能力做、做完留下什么凭据」，天然属于适配器层。 |
//!
//! # 安全默认值
//!
//! [`plan_from_intents`] 是所有适配器共用的推导入口，它把设计文档 §6 的硬约束实现**一次**：
//! 观察缺失只生成 install，观察到的额外包永远不生成 uninstall，只有显式 tombstone 能卸载，
//! 版本无法判定时阻塞而不是静默安装别的版本。适配器只在其上叠加自己的管理器知识
//! （例如 `Latest` 需要查询最新版本），不重写这些规则。

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use envsync_domain::package::{
    PackageAction, PackageActionKind, PackageIdentity, PackageIntent, PackageIntentError,
    PackageIntentSet, PackageManagerId, PackageObservationSet,
};
use envsync_domain::profile::{DeviceProfile, Os};
use envsync_domain::{OperationId, Risk, RollbackCapability};
use envsync_platform::command::{CommandReceipt, CommandRunner};

use envsync_core::packages::{ActionAuthorization, PackageActionReceipt, PackageError};

pub mod fake;

pub use fake::{
    FakePackageManager, FAKE_EXACT_DESCRIPTOR, FAKE_SYSTEM_DESCRIPTOR, FAKE_USER_DESCRIPTOR,
};

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

/// 包适配器层错误。
///
/// 与文件适配器的 [`crate::AdapterError`] 分开：包适配器的失败模式（管理器不在场、
/// 版本满足不了、需要提权、需要确认）与文件适配器毫无交集，混在一个枚举里只会让两边
/// 的调用方都要处理一堆不可能发生的分支。
///
/// 所有变体的 `Display` 都不含本机绝对路径，也不含包管理器的原始输出。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PackageAdapterError {
    /// 注册表中已存在同名适配器。
    #[error("包适配器 ID `{0}` 已注册")]
    DuplicateAdapterId(&'static str),

    /// 期望状态自身不合法，或无法与观察结果比较。
    #[error(transparent)]
    Intent(#[from] PackageIntentError),

    /// 该包不属于本适配器管理的包管理器。
    #[error("包 `{identity}` 不属于适配器 `{adapter}`")]
    ManagerMismatch {
        /// 适配器稳定 ID。
        adapter: &'static str,
        /// 出问题的包身份（文本形式）。
        identity: String,
    },

    /// 包管理器在本机不可用（没装、没探测到可执行文件、平台不支持）。
    #[error("包管理器 `{adapter}` 在本机不可用：{reason}")]
    ManagerUnavailable {
        /// 适配器稳定 ID。
        adapter: &'static str,
        /// 原因。
        reason: String,
    },

    /// 包管理器版本不受支持：输出格式无法可靠解析。
    ///
    /// 设计文档要求「命令版本不兼容时返回 `UnsupportedManagerVersion`，不能基于人类
    /// 输出猜测」。
    #[error("包管理器 `{adapter}` 的版本 `{found}` 不受支持，拒绝猜测其输出格式")]
    UnsupportedManagerVersion {
        /// 适配器稳定 ID。
        adapter: &'static str,
        /// 探测到的版本。
        found: String,
    },

    /// 源里不存在这个包。
    #[error("包 `{identity}` 在适配器 `{adapter}` 的来源里不存在")]
    PackageNotFound {
        /// 适配器稳定 ID。
        adapter: &'static str,
        /// 出问题的包身份（文本形式）。
        identity: String,
    },

    /// 版本策略在该管理器上无法满足。
    ///
    /// **必须阻塞**：静默安装一个别的版本等于让版本策略形同虚设。
    #[error("包 `{identity}` 无法满足版本策略 {policy}：{reason}")]
    UnsupportedVersion {
        /// 出问题的包身份（文本形式）。
        identity: String,
        /// 版本策略的文本形式。
        policy: String,
        /// 具体原因（例如「源里只有 1.0.0 与 2.0.0」）。
        reason: String,
    },

    /// 动作需要用户显式确认，但上下文里没有确认。
    #[error("动作 {kind} `{identity}` 需要显式确认")]
    ConfirmationRequired {
        /// 出问题的包身份（文本形式）。
        identity: String,
        /// 动作种类。
        kind: &'static str,
    },

    /// 动作需要提权，但上下文没有获得平台 elevation broker 的授权。
    #[error("动作 {kind} `{identity}` 需要提权，但本次执行未获授权")]
    ElevationRequired {
        /// 出问题的包身份（文本形式）。
        identity: String,
        /// 动作种类。
        kind: &'static str,
    },

    /// 命令执行失败（超时、被拒绝、模板不匹配）。
    #[error(transparent)]
    Command(#[from] envsync_platform::PlatformError),

    /// 包管理器本身报告了失败。
    #[error("包管理器执行 {kind} `{identity}` 失败：{detail}")]
    ManagerFailed {
        /// 出问题的包身份（文本形式）。
        identity: String,
        /// 动作种类。
        kind: &'static str,
        /// 失败摘要（不含原始输出正文）。
        detail: String,
    },
}

impl PackageAdapterError {
    /// 稳定错误码，用于日志与跨版本比对；展示文案可以改，错误码不可以。
    pub fn code(&self) -> &'static str {
        match self {
            PackageAdapterError::DuplicateAdapterId(_) => "package_adapter.duplicate_id",
            PackageAdapterError::Intent(_) => "package_adapter.invalid_intent",
            PackageAdapterError::ManagerMismatch { .. } => "package_adapter.manager_mismatch",
            PackageAdapterError::ManagerUnavailable { .. } => "package_adapter.manager_unavailable",
            PackageAdapterError::UnsupportedManagerVersion { .. } => {
                "package_adapter.unsupported_manager_version"
            }
            PackageAdapterError::PackageNotFound { .. } => "package_adapter.package_not_found",
            PackageAdapterError::UnsupportedVersion { .. } => "package_adapter.unsupported_version",
            PackageAdapterError::ConfirmationRequired { .. } => {
                "package_adapter.confirmation_required"
            }
            PackageAdapterError::ElevationRequired { .. } => "package_adapter.elevation_required",
            PackageAdapterError::Command(_) => "package_adapter.command",
            PackageAdapterError::ManagerFailed { .. } => "package_adapter.manager_failed",
        }
    }
}

// ---------------------------------------------------------------------------
// 描述符
// ---------------------------------------------------------------------------

/// 包管理器适配器自述。
///
/// 全部字段都是 `'static`：描述符是编译期常量，因此注册表可以在不构造任何设备上下文的
/// 情况下枚举与过滤适配器。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageManagerDescriptor {
    /// 适配器稳定 ID，例如 `builtin.pkg.brew`。**跨版本不得更改**。
    ///
    /// 系统级包管理器必须注册在 `builtin.pkg.system.` 前缀下：内建策略用这个前缀
    /// 拦住所有系统级写操作（见 `envsync_policy::BUILTIN_SYSTEM_PACKAGE_PREFIX`）。
    pub id: &'static str,
    /// [`PackageManagerId`] 的文本形式，例如 `brew`。
    ///
    /// 它决定包名的规范化规则，因此**必须**与 [`PackageIdentity::manager`] 一致。
    pub manager: &'static str,
    /// 展示名。
    pub display_name: &'static str,
    /// 支持的操作系统；空列表意味着该适配器永远不会被选中。
    pub supported_os: &'static [Os],
    /// 所需能力；设备 Profile 必须具备**全部**能力，适配器才会参与观察。
    pub required_capabilities: &'static [&'static str],
    /// 是否需要系统级权限。
    ///
    /// 为 `true` 时，本适配器产出的每个动作都被标记为高风险且需要提权
    /// （见 [`PackageManagerDescriptor::decorate`]），从而必然撞上内建策略。
    pub system_scope: bool,
    /// 该管理器的回滚能力，**如实标注**。
    ///
    /// 多数包管理器只能 [`RollbackCapability::Compensating`]（重新安装原版本，但依赖树
    /// 未必回到原样）；个别管理器连补偿都做不到（例如源里已经没有原版本），标注为
    /// [`RollbackCapability::None`]。
    pub rollback: RollbackCapability,
}

impl PackageManagerDescriptor {
    /// 该适配器是否适用于给定设备。
    pub fn applies_to(&self, profile: &DeviceProfile) -> bool {
        self.supported_os.contains(&profile.os)
            && self
                .required_capabilities
                .iter()
                .all(|capability| profile.has_capability(capability))
    }

    /// 解析出强类型的包管理器标识。
    ///
    /// # Panics
    ///
    /// `manager` 是编译期常量，不合法即为编程错误。`packages::tests::descriptors_are_wellformed`
    /// 与契约测试会对每个注册的适配器检查这一点。
    pub fn manager_id(&self) -> PackageManagerId {
        PackageManagerId::parse(self.manager).expect("descriptor.manager 必须是合法的包管理器标识")
    }

    /// 用管理器知识修饰一个动作：**只能调严，不能放松**。
    ///
    /// * 回滚能力如实取自描述符；
    /// * 系统级管理器的动作一律标记为需要提权且风险为 [`Risk::High`]；
    /// * 风险不得低于 [`PackageActionKind::baseline_risk`]（卸载 / 降级 / 换源恒为
    ///   [`Risk::High`]）。
    #[must_use]
    pub fn decorate(&self, mut action: PackageAction) -> PackageAction {
        action.rollback = self.rollback;
        action.elevation_required = self.system_scope;
        let baseline = action.kind.baseline_risk();
        let system = if self.system_scope {
            Risk::High
        } else {
            Risk::Low
        };
        action.risk = action.risk.max(baseline).max(system);
        action
    }
}

// ---------------------------------------------------------------------------
// 上下文
// ---------------------------------------------------------------------------

/// 一个可以被借用的空可执行文件表，供 [`ObserveContext::new`] 使用。
fn empty_executables() -> &'static BTreeMap<String, PathBuf> {
    static EMPTY: OnceLock<BTreeMap<String, PathBuf>> = OnceLock::new();
    EMPTY.get_or_init(BTreeMap::new)
}

/// 观察阶段可见的**全部**上下文。
///
/// 字段集合本身就是一条安全约束：这里没有 Backend、没有 Journal、没有文件系统句柄。
/// 适配器唯一能对外界产生影响的手段是 [`ObserveContext::runner`]，而它只接受已注册的
/// 命令模板。
#[derive(Debug, Clone, Copy)]
pub struct ObserveContext<'a> {
    /// 本设备 Profile。
    pub profile: &'a DeviceProfile,
    /// 受限命令执行器；`None` 表示本次观察**不允许**执行任何外部命令
    /// （离线预演、为另一台设备做计划）。
    pub runner: Option<&'a CommandRunner>,
    /// 能力探测得到的可执行文件**绝对路径**，按包管理器文本标识索引。
    ///
    /// 适配器不得自己拼路径，也不得依赖 `PATH` 查找：那等于把「执行哪个二进制」
    /// 交给环境变量决定。
    pub executables: &'a BTreeMap<String, PathBuf>,
    /// 观察时刻（Unix 毫秒），由宿主注入，保证结果可复现。
    pub observed_at_unix_ms: u64,
}

impl<'a> ObserveContext<'a> {
    /// 构造一个「不允许执行命令」的观察上下文。
    pub fn new(profile: &'a DeviceProfile, observed_at_unix_ms: u64) -> Self {
        ObserveContext {
            profile,
            runner: None,
            executables: empty_executables(),
            observed_at_unix_ms,
        }
    }

    /// 挂上命令执行器。
    #[must_use]
    pub fn with_runner(mut self, runner: &'a CommandRunner) -> Self {
        self.runner = Some(runner);
        self
    }

    /// 挂上能力探测得到的可执行文件表。
    #[must_use]
    pub fn with_executables(mut self, executables: &'a BTreeMap<String, PathBuf>) -> Self {
        self.executables = executables;
        self
    }

    /// 查询某个包管理器的可执行文件绝对路径。
    pub fn executable(&self, manager: &str) -> Option<&PathBuf> {
        self.executables.get(manager)
    }
}

/// 应用阶段的上下文：观察上下文 + 本次操作的授权。
///
/// [`ApplyContext::confirmed`] 与 [`ApplyContext::elevation_granted`] 是**授权凭据的投影**，
/// 不是开关：它们由核心层的 `ConfirmedPlan`（已保存计划 + 用户确认 + 策略判定）派生。
/// 适配器再自查一次属于纵深防御——即便有人绕过核心层直接调用适配器，破坏性动作也不会
/// 在没有确认的情况下发生。
#[derive(Debug, Clone, Copy)]
pub struct ApplyContext<'a> {
    /// 观察上下文（同一批能力与执行器）。
    pub base: ObserveContext<'a>,
    /// 关联的本地操作标识，用于 journal 与 receipt。
    pub operation: OperationId,
    /// 该动作是否已获得用户显式确认。
    pub confirmed: bool,
    /// 该动作是否已获得平台 elevation broker 的提权授权。
    pub elevation_granted: bool,
}

impl<'a> ApplyContext<'a> {
    /// 构造一个既未确认也未授权提权的上下文。
    pub fn new(base: ObserveContext<'a>, operation: OperationId) -> Self {
        ApplyContext {
            base,
            operation,
            confirmed: false,
            elevation_granted: false,
        }
    }

    /// 标记为已确认。
    #[must_use]
    pub fn confirmed(mut self) -> Self {
        self.confirmed = true;
        self
    }

    /// 标记为已获得提权授权。
    #[must_use]
    pub fn elevated(mut self) -> Self {
        self.elevation_granted = true;
        self
    }

    /// 逐条检查动作所需的授权是否到位。
    ///
    /// 适配器实现应当在 [`PackageAdapter::apply`] 的最开头调用它。
    pub fn authorize(&self, action: &PackageAction) -> Result<(), PackageAdapterError> {
        if action.requires_confirmation() && !self.confirmed {
            return Err(PackageAdapterError::ConfirmationRequired {
                identity: action.identity.to_string(),
                kind: action.kind.as_str(),
            });
        }
        if action.elevation_required && !self.elevation_granted {
            return Err(PackageAdapterError::ElevationRequired {
                identity: action.identity.to_string(),
                kind: action.kind.as_str(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 收据与校验
// ---------------------------------------------------------------------------

/// 一个包动作执行后的收据。
///
/// 它是这次执行**唯一**的留痕来源：进 journal、进 `envsync status`、进事后审计。
/// 结构上不可能携带秘密——[`CommandReceipt`] 里没有环境变量，输出只有已脱敏的摘要。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageReceipt {
    /// 执行该动作的适配器稳定 ID。
    pub adapter: &'static str,
    /// 目标包。
    pub identity: PackageIdentity,
    /// 动作种类。
    pub kind: PackageActionKind,
    /// 执行前的版本。
    pub before_version: Option<String>,
    /// 执行后的版本；卸载为 `None`。
    pub after_version: Option<String>,
    /// 该动作**实际**具备的回滚能力，如实标注。
    pub rollback: RollbackCapability,
    /// 本次执行调用的全部命令收据，按调用顺序。
    pub commands: Vec<CommandReceipt>,
    /// 开始时刻（Unix 毫秒）。
    pub started_at_unix_ms: u64,
    /// 结束时刻（Unix 毫秒）。
    pub finished_at_unix_ms: u64,
}

/// [`PackageAdapter::verify`] 的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    /// 观察结果与动作的期望一致。
    Match,
    /// 检测到漂移：世界不是动作声称的样子。
    Drift {
        /// 期望的状态描述。
        expected: String,
        /// 实际观察到的状态描述。
        actual: String,
    },
    /// 无法判定（管理器读不出来）。
    ///
    /// **不等于通过**：调用方必须把它当作失败对待，只是失败原因是「不知道」而不是
    /// 「不对」。
    Unknown {
        /// 无法判定的原因。
        reason: String,
    },
}

impl VerifyResult {
    /// 是否确定通过。
    pub const fn is_match(&self) -> bool {
        matches!(self, VerifyResult::Match)
    }
}

// ---------------------------------------------------------------------------
// 契约
// ---------------------------------------------------------------------------

/// 包管理器适配器契约。
///
/// 实现必须满足三条性质：
///
/// 1. **[`PackageAdapter::plan`] 是纯函数且确定性。** 相同的期望与观察必须产生逐项相同
///    的动作序列——计划阶段与应用阶段会各算一次，两次不同就意味着预演结果不可信。
/// 2. **[`PackageAdapter::apply`] 幂等。** 对已经满足的动作重复执行不得报错。
/// 3. **[`PackageAdapter::apply`] 先授权后动手。** 实现的第一句应当是
///    [`ApplyContext::authorize`]。
pub trait PackageAdapter: Send + Sync {
    /// 适配器自述。
    fn descriptor(&self) -> &'static PackageManagerDescriptor;

    /// 观察这个包管理器当前装了什么。
    ///
    /// 返回的集合是**完整**列表：不在集合里的包按
    /// [`envsync_domain::package::PackageState::Absent`] 处理。读不出来的包必须显式写入
    /// [`envsync_domain::package::PackageState::Unreadable`]，绝不能留空——留空会被
    /// 当成「没装」。
    fn observe(
        &self,
        ctx: &ObserveContext<'_>,
    ) -> Result<PackageObservationSet, PackageAdapterError>;

    /// 由期望状态与观察结果推导动作。
    ///
    /// 实现应当以 [`plan_from_intents`] 为基础，只叠加自己的管理器知识。
    fn plan(
        &self,
        desired: &[PackageIntent],
        observed: &PackageObservationSet,
    ) -> Result<Vec<PackageAction>, PackageAdapterError>;

    /// 执行单个动作。
    fn apply(
        &self,
        action: &PackageAction,
        ctx: &ApplyContext<'_>,
    ) -> Result<PackageReceipt, PackageAdapterError>;

    /// 重新观察并校验动作是否真的生效。
    fn verify(
        &self,
        action: &PackageAction,
        ctx: &ObserveContext<'_>,
    ) -> Result<VerifyResult, PackageAdapterError>;
}

/// 所有适配器共用的动作推导入口。
///
/// 它把设计文档 §6 的安全语义实现**一次**：
///
/// * 观察缺失只生成 install；
/// * 观察到的额外包**永远**不生成 uninstall；
/// * 只有显式 tombstone 能生成 uninstall；
/// * 状态不确定（`Unsupported` / `Unreadable`）时不产生任何动作；
/// * 版本无法判定时返回错误而不是猜一个方向。
///
/// 随后用 [`PackageManagerDescriptor::decorate`] 补上管理器相关的风险、提权与回滚标注。
///
/// `desired` 里属于其他包管理器的 intent 会被跳过；同一身份上互相冲突的 intent 直接报错。
pub fn plan_from_intents(
    descriptor: &PackageManagerDescriptor,
    desired: &[PackageIntent],
    observed: &PackageObservationSet,
) -> Result<Vec<PackageAction>, PackageAdapterError> {
    let manager = descriptor.manager_id();
    if observed.manager() != &manager {
        return Err(PackageAdapterError::ManagerUnavailable {
            adapter: descriptor.id,
            reason: format!(
                "观察结果属于 `{}`，与适配器声明的 `{manager}` 不符",
                observed.manager()
            ),
        });
    }
    let intents = PackageIntentSet::from_intents(desired.iter().cloned())?;
    let actions = intents.derive_actions(observed)?;
    Ok(actions
        .into_iter()
        .map(|action| descriptor.decorate(action))
        .collect())
}

// ---------------------------------------------------------------------------
// 与核心层执行端口的桥接
// ---------------------------------------------------------------------------

/// 把一个 [`PackageAdapter`] 接到核心层的
/// [`envsync_core::packages::PackageMutator`] 端口上。
///
/// 这是两半唯一的汇合点，方向是**适配器依赖核心**：核心层只认识
/// [`envsync_domain::package::PackageAction`] 与端口 trait，因此
/// `envsync-core` 不必反向依赖 `envsync-adapters`。
///
/// 桥接只做三件事：
///
/// 1. 把 [`ActionAuthorization`] 翻译成 [`ApplyContext`] 上的确认与提权标记
///    ——授权凭据只能由核心层的 `ConfirmedPlan` 派发，适配器拿到的是它的投影；
/// 2. 把 [`PackageReceipt`] 降解成核心层的收据（丢掉命令细节，保留回滚能力）；
/// 3. 把 [`VerifyResult::Drift`] 与 [`VerifyResult::Unknown`] **都**映射成失败：
///    「不知道有没有生效」绝不等于「生效了」。
pub struct AdapterMutator<'a> {
    adapter: &'a dyn PackageAdapter,
    ctx: ObserveContext<'a>,
    operation: OperationId,
}

impl<'a> AdapterMutator<'a> {
    /// 构造桥接。
    pub fn new(
        adapter: &'a dyn PackageAdapter,
        ctx: ObserveContext<'a>,
        operation: OperationId,
    ) -> Self {
        AdapterMutator {
            adapter,
            ctx,
            operation,
        }
    }

    fn executor_error(&self, action: &PackageAction, err: PackageAdapterError) -> PackageError {
        PackageError::Executor {
            adapter: self.adapter.descriptor().id.to_owned(),
            identity: action.identity.to_string(),
            kind: action.kind.as_str(),
            code: err.code().to_owned(),
            detail: err.to_string(),
        }
    }
}

impl envsync_core::packages::PackageMutator for AdapterMutator<'_> {
    fn adapter_id(&self) -> &str {
        self.adapter.descriptor().id
    }

    fn apply(
        &self,
        action: &PackageAction,
        authorization: ActionAuthorization,
    ) -> Result<PackageActionReceipt, PackageError> {
        let mut ctx = ApplyContext::new(self.ctx, self.operation);
        ctx.confirmed = authorization.confirmed();
        ctx.elevation_granted = authorization.elevation_granted();

        let receipt = self
            .adapter
            .apply(action, &ctx)
            .map_err(|err| self.executor_error(action, err))?;
        Ok(PackageActionReceipt {
            adapter: receipt.adapter.to_owned(),
            identity: receipt.identity,
            kind: receipt.kind,
            before_version: receipt.before_version,
            after_version: receipt.after_version,
            rollback: receipt.rollback,
            started_at_unix_ms: receipt.started_at_unix_ms,
            finished_at_unix_ms: receipt.finished_at_unix_ms,
        })
    }

    fn verify(&self, action: &PackageAction) -> Result<(), PackageError> {
        match self
            .adapter
            .verify(action, &self.ctx)
            .map_err(|err| self.executor_error(action, err))?
        {
            VerifyResult::Match => Ok(()),
            VerifyResult::Drift { expected, actual } => Err(PackageError::VerifyFailed {
                identity: action.identity.to_string(),
                kind: action.kind.as_str(),
                expected,
                actual,
            }),
            // 「无法判定」必须当作失败：把它当成通过，等于用沉默冒充证据。
            VerifyResult::Unknown { reason } => Err(PackageError::VerifyFailed {
                identity: action.identity.to_string(),
                kind: action.kind.as_str(),
                expected: action.to_version.to_string(),
                actual: format!("无法判定：{reason}"),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// 注册表
// ---------------------------------------------------------------------------

/// 包适配器注册表。
///
/// 按稳定 ID 索引，**拒绝重复 ID**，也**拒绝两个适配器管同一个包管理器**：那会让
/// 「谁来收敛这个包」变成不确定行为。
#[derive(Default)]
pub struct PackageAdapterRegistry {
    adapters: BTreeMap<&'static str, Box<dyn PackageAdapter>>,
}

impl std::fmt::Debug for PackageAdapterRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PackageAdapterRegistry")
            .field("ids", &self.ids())
            .finish()
    }
}

impl PackageAdapterRegistry {
    /// 空注册表。
    pub fn new() -> Self {
        PackageAdapterRegistry::default()
    }

    /// 注册一个适配器。
    pub fn register(
        &mut self,
        adapter: Box<dyn PackageAdapter>,
    ) -> Result<(), PackageAdapterError> {
        let descriptor = adapter.descriptor();
        if self.adapters.contains_key(descriptor.id) {
            return Err(PackageAdapterError::DuplicateAdapterId(descriptor.id));
        }
        if let Some(existing) = self.by_manager(descriptor.manager) {
            return Err(PackageAdapterError::DuplicateAdapterId(
                existing.descriptor().id,
            ));
        }
        self.adapters.insert(descriptor.id, adapter);
        Ok(())
    }

    /// 按适配器 ID 查找。
    pub fn get(&self, id: &str) -> Option<&dyn PackageAdapter> {
        self.adapters.get(id).map(AsRef::as_ref)
    }

    /// 按包管理器文本标识查找。
    pub fn by_manager(&self, manager: &str) -> Option<&dyn PackageAdapter> {
        self.adapters
            .values()
            .find(|adapter| adapter.descriptor().manager == manager)
            .map(AsRef::as_ref)
    }

    /// 全部已注册 ID，按字典序。
    pub fn ids(&self) -> Vec<&'static str> {
        self.adapters.keys().copied().collect()
    }

    /// 已注册适配器的迭代视图，顺序与 [`PackageAdapterRegistry::ids`] 一致。
    pub fn adapters(&self) -> impl Iterator<Item = &dyn PackageAdapter> {
        self.adapters.values().map(AsRef::as_ref)
    }

    /// 适用于给定设备的适配器。
    pub fn applicable<'a>(
        &'a self,
        profile: &'a DeviceProfile,
    ) -> impl Iterator<Item = &'a dyn PackageAdapter> {
        self.adapters
            .values()
            .map(AsRef::as_ref)
            .filter(move |adapter| adapter.descriptor().applies_to(profile))
    }

    /// 条目数。
    pub fn len(&self) -> usize {
        self.adapters.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.adapters.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envsync_domain::package::{PackageAction, VersionPolicy};

    #[test]
    fn descriptors_are_wellformed() {
        for descriptor in [
            &FAKE_USER_DESCRIPTOR,
            &FAKE_EXACT_DESCRIPTOR,
            &FAKE_SYSTEM_DESCRIPTOR,
        ] {
            assert!(!descriptor.id.is_empty());
            assert!(!descriptor.supported_os.is_empty());
            // `manager_id` 会 panic 的前提在这里被排除。
            assert_eq!(descriptor.manager_id().as_str(), descriptor.manager);
            if descriptor.system_scope {
                assert!(
                    descriptor.id.starts_with("builtin.pkg.system."),
                    "系统级适配器必须注册在 builtin.pkg.system. 前缀下，否则内建策略拦不住它"
                );
            }
        }
    }

    #[test]
    fn decorate_only_tightens() {
        let identity = PackageIdentity::parse("fakeuser:ripgrep").unwrap();
        let install = PackageAction::new(
            identity.clone(),
            PackageActionKind::Install,
            None,
            VersionPolicy::Present,
        );

        let user = FAKE_USER_DESCRIPTOR.decorate(install.clone());
        assert_eq!(user.risk, Risk::Low);
        assert!(!user.elevation_required);
        assert_eq!(user.rollback, RollbackCapability::Compensating);

        let system = FAKE_SYSTEM_DESCRIPTOR.decorate(install);
        assert_eq!(system.risk, Risk::High, "系统级包管理器的动作恒为高风险");
        assert!(system.elevation_required);
        assert_eq!(system.rollback, RollbackCapability::None);

        // 卸载的基线风险是 High，用户级管理器也不能把它降下来。
        let uninstall = PackageAction::new(
            identity,
            PackageActionKind::Uninstall,
            Some("1.0.0".into()),
            VersionPolicy::Present,
        );
        assert_eq!(FAKE_USER_DESCRIPTOR.decorate(uninstall).risk, Risk::High);
    }

    #[test]
    fn registry_rejects_duplicate_id_and_duplicate_manager() {
        let mut registry = PackageAdapterRegistry::new();
        registry
            .register(Box::new(FakePackageManager::new(&FAKE_USER_DESCRIPTOR)))
            .unwrap();
        assert!(matches!(
            registry.register(Box::new(FakePackageManager::new(&FAKE_USER_DESCRIPTOR))),
            Err(PackageAdapterError::DuplicateAdapterId(_))
        ));
        assert_eq!(registry.len(), 1);
        assert!(registry.by_manager(FAKE_USER_DESCRIPTOR.manager).is_some());
    }
}
