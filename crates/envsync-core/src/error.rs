//! 核心层统一错误类型。
//!
//! 每个变体都有稳定的机器可读 [`CoreError::code`]，CLI 直接把它写进 JSON 契约的
//! `diagnostics[].code`，退出码也由它派生。错误信息**不得**包含秘密内容或绝对路径：
//! 下层的 `PlatformError` 已经在结构上保证了这一点，核心层只要不把路径拼回去即可。

use envsync_domain::{PlanId, ResourceId};

/// 核心层错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CoreError {
    /// 后端错误（含 CAS 冲突）。
    #[error(transparent)]
    Backend(#[from] envsync_backend::BackendError),

    /// 平台层错误（路径越权、读写失败、观察陈旧）。
    #[error(transparent)]
    Platform(#[from] envsync_platform::PlatformError),

    /// 操作日志错误。
    #[error(transparent)]
    Journal(#[from] envsync_storage::JournalError),

    /// 草稿库错误。
    #[error(transparent)]
    Draft(#[from] envsync_storage::DraftError),

    /// 冲突索引错误。
    #[error(transparent)]
    ConflictStore(#[from] envsync_storage::ConflictError),

    /// 密钥轮换 journal 错误（M2）。
    #[error(transparent)]
    RotationStore(#[from] envsync_storage::RotationStoreError),

    /// 密码学层错误（M2）。
    ///
    /// 它的 `Display` 只描述结构，绝不携带明文或密钥材料；见
    /// [`envsync_crypto::CryptoError`] 的文档。
    #[error(transparent)]
    Crypto(#[from] envsync_crypto::CryptoError),

    /// 成员链验证或编排失败（M2）。
    #[error(transparent)]
    Membership(#[from] crate::membership::MembershipError),

    /// 反回滚检查点错误（M2）。
    ///
    /// [`crate::checkpoint::CheckpointError::is_rollback_attack`] 为 `true` 时表示
    /// **检测到一次回滚攻击**，调用方必须中止而不是重试。
    #[error(transparent)]
    Checkpoint(#[from] crate::checkpoint::CheckpointError),

    /// Vault 操作失败（M2）。
    #[error(transparent)]
    Vault(#[from] crate::vault::VaultError),

    /// 密钥轮换编排失败（M2）。
    #[error(transparent)]
    Rotation(#[from] crate::rotation::RotationError),

    /// 三方合并失败（解析、超限或渲染校验不通过）。
    #[error("三方合并失败：{0}")]
    Merge(#[source] crate::merge::MergeError),

    /// 投影失败。
    #[error(transparent)]
    Projection(#[from] crate::projection::ProjectionError),

    /// 存在未解决的合并冲突，本次同步拒绝继续。
    ///
    /// 出现它时**本地文件与远端 Ref 都没有被改动**。CLI 把它映射成退出码 13。
    #[error("存在 {count} 个未解决的合并冲突；请先运行 `envsync conflicts resolve`")]
    Conflicted {
        /// 未解决的冲突数量。
        count: usize,
    },

    /// 编解码错误。
    #[error(transparent)]
    Codec(#[from] envsync_domain::CborError),

    /// 配置不合法。
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),

    /// 渲染失败。
    #[error(transparent)]
    Render(#[from] crate::render::RenderError),

    /// 领域对象自身不合法。
    #[error("领域约束被违反：{0}")]
    Domain(String),

    /// 提交的计划已失效：重新观察后生成的计划与之不一致。
    #[error("计划 {submitted} 已失效；在当前条件下应为 {current}")]
    StalePlan {
        /// 用户提交的计划标识。
        submitted: PlanId,
        /// 重新计算得到的计划标识。
        current: PlanId,
    },

    /// 计划包含阻塞诊断，禁止应用。
    #[error("计划被 {count} 条阻塞诊断拦截：{first}")]
    PlanBlocked {
        /// 阻塞诊断数量。
        count: usize,
        /// 第一条阻塞诊断的说明。
        first: String,
    },

    /// 已发布到后端但本地未收敛，必须恢复或显式回滚。
    #[error("已发布但本地未收敛（operation {operation}）：{detail}")]
    PublishedNotConverged {
        /// 操作标识。
        operation: String,
        /// 诊断说明。
        detail: String,
    },

    /// 回滚被拒绝或失败。
    #[error("回滚失败：{0}")]
    Rollback(String),

    /// 恢复流程需要人工介入。
    #[error("需要人工处理：{0}")]
    ManualInterventionRequired(String),

    /// 配置中没有该资源。
    #[error("配置中没有资源 `{0}`")]
    UnknownResource(ResourceId),

    /// 找不到计划。
    #[error("找不到计划 {0}")]
    PlanNotFound(PlanId),

    /// 找不到操作。
    #[error("找不到操作 {0}")]
    OperationNotFound(String),

    /// 引用了不存在的对象。
    #[error("引用了缺失的对象：{0}")]
    MissingObject(String),

    /// 内部不变量被破坏——出现即说明实现有 bug。
    #[error("内部不变量被破坏：{0}")]
    Invariant(String),
}

impl CoreError {
    /// 稳定的机器可读错误码。
    pub fn code(&self) -> &'static str {
        match self {
            CoreError::Backend(err) => err.code(),
            CoreError::Platform(err) => err.code(),
            CoreError::Journal(err) => err.code(),
            CoreError::Draft(err) => err.code(),
            CoreError::ConflictStore(err) => err.code(),
            CoreError::RotationStore(err) => err.code(),
            CoreError::Crypto(_) => "crypto.failed",
            CoreError::Membership(err) => err.code(),
            CoreError::Checkpoint(err) => err.code(),
            CoreError::Vault(err) => err.code(),
            CoreError::Rotation(err) => err.code(),
            CoreError::Merge(err) => err.code(),
            CoreError::Projection(err) => err.code(),
            CoreError::Conflicted { .. } => "sync.conflicted",
            CoreError::Config(err) => err.code(),
            CoreError::Render(err) => err.code(),
            CoreError::Codec(_) => "codec.invalid",
            CoreError::Domain(_) => "domain.invalid",
            CoreError::StalePlan { .. } => "plan.stale",
            CoreError::PlanBlocked { .. } => "plan.blocked",
            CoreError::PublishedNotConverged { .. } => "sync.published_not_converged",
            CoreError::Rollback(_) => "rollback.failed",
            CoreError::ManualInterventionRequired(_) => "recovery.manual_required",
            CoreError::UnknownResource(_) => "resource.unknown",
            CoreError::PlanNotFound(_) => "plan.not_found",
            CoreError::OperationNotFound(_) => "operation.not_found",
            CoreError::MissingObject(_) => "object.missing",
            CoreError::Invariant(_) => "internal.invariant",
        }
    }

    /// 是否为后端 CAS 冲突（CLI 退出码 10）。
    pub fn is_cas_conflict(&self) -> bool {
        matches!(
            self,
            CoreError::Backend(envsync_backend::BackendError::CasConflict { .. })
        )
    }

    /// 是否为计划失效（CLI 退出码 11）。
    pub fn is_stale_plan(&self) -> bool {
        matches!(self, CoreError::StalePlan { .. })
    }

    /// 是否为策略阻塞（CLI 退出码 12）。
    pub fn is_policy_block(&self) -> bool {
        matches!(self, CoreError::PlanBlocked { .. })
    }

    /// 是否为部分收敛（CLI 退出码 20）。
    pub fn is_partial_convergence(&self) -> bool {
        matches!(self, CoreError::PublishedNotConverged { .. })
    }

    /// 是否为未解决的合并冲突（CLI 退出码 13）。
    pub fn is_conflicted(&self) -> bool {
        matches!(self, CoreError::Conflicted { .. })
    }

    /// 是否为「检测到后端回滚/分叉」这一类必须中止的安全事件（CLI 退出码 14）。
    ///
    /// 存储故障不算：那是本机问题，修复后可以继续。
    pub fn is_rollback_attack(&self) -> bool {
        matches!(self, CoreError::Checkpoint(err) if err.is_rollback_attack())
    }

    /// 是否为「系统安全存储不可用/被锁定/被拒绝」（CLI 退出码 15）。
    ///
    /// 这一类失败**绝不**回退到明文存储：调用方唯一正确的反应是提示用户解锁凭据库或
    /// 授予访问权限，然后重试。
    pub fn is_secure_store_unavailable(&self) -> bool {
        matches!(
            self,
            CoreError::Platform(
                envsync_platform::PlatformError::SecureStoreUnavailable { .. }
                    | envsync_platform::PlatformError::SecureStoreLocked { .. }
                    | envsync_platform::PlatformError::SecureStoreDenied { .. }
                    | envsync_platform::PlatformError::SecureStoreBackend { .. }
            )
        )
    }
}

/// 核心层结果别名。
pub type CoreResult<T> = Result<T, CoreError>;
