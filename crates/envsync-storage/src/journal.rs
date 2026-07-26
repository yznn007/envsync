//! SQLite 操作日志。
//!
//! 每一次会写入用户文件的同步事务都必须先在这里登记。journal 回答三个问题：
//!
//! 1. **当前进行到哪一步**——[`OperationState`] 状态机；
//! 2. **计划里有哪些动作、每个动作做到什么程度**——`actions` 表；
//! 3. **已经动过的文件怎么还原**——`receipts` 表中的备份路径与前后摘要。
//!
//! ## 状态机
//!
//! ```text
//! planned -> preflighted -> published -> applying -> verified -> completed
//!                                     \-> published_not_converged
//! planned|preflighted -> aborted
//! applying|published_not_converged -> rolling_back -> rolled_back
//! ```
//!
//! 状态机由 **Rust 层**强制（见 [`OperationState::can_transition_to`]）：数据库只把
//! 状态当作一个字符串列。非法迁移返回 [`JournalError::IllegalTransition`]，
//! 绝不 panic——恢复流程会在各种奇怪的历史状态上调用这些方法，把不一致变成崩溃
//! 只会让用户更难恢复。
//!
//! ## 与 platform crate 的边界
//!
//! 本模块**不依赖** `envsync-platform`。收据里的备份位置是一个普通 [`String`]，
//! 摘要以十六进制文本存放。谁把它解释成真实路径是平台层的事。

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use envsync_domain::id::{Digest32, OperationId, PlanId, ResourceId, SnapshotId, WorkspaceId};
use envsync_domain::plan::{Action, ActionKind, ActionTarget, Plan, RollbackCapability};
use envsync_domain::unix_millis_now;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};

use crate::migrations::{self, StorageDiagnostics, SCHEMA_VERSION};

/// 操作日志错误。
///
/// 所有变体都只描述结构性问题，不携带文件内容，可以安全地写进日志与 CLI 输出。
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// 底层 SQLite 错误。
    #[error("SQLite 错误：{0}")]
    Sqlite(#[from] rusqlite::Error),
    /// 创建数据库目录失败。
    #[error("无法准备数据库目录：{0}")]
    Io(#[from] std::io::Error),
    /// 动作目标的 JSON 编解码失败。
    #[error("动作目标编解码失败：{0}")]
    Json(#[from] serde_json::Error),
    /// 数据库 schema 版本高于本程序支持的版本。
    #[error("数据库 schema 版本 {found} 高于本版本支持的 {supported}，拒绝打开")]
    SchemaTooNew {
        /// 数据库中记录的版本。
        found: u32,
        /// 本程序支持的版本。
        supported: u32,
    },
    /// 连接 PRAGMA 未能生效。
    #[error("PRAGMA `{pragma}` 未生效：期望 {expected}，实际 {actual}")]
    PragmaRejected {
        /// PRAGMA 名称。
        pragma: &'static str,
        /// 期望值。
        expected: String,
        /// 实际值。
        actual: String,
    },
    /// 非法状态迁移。
    #[error("非法状态迁移：{from} -> {to}")]
    IllegalTransition {
        /// 当前状态。
        from: OperationState,
        /// 试图迁移到的状态。
        to: OperationState,
    },
    /// 操作不存在。
    #[error("操作 {0} 不存在")]
    UnknownOperation(OperationId),
    /// 动作不存在。
    #[error("操作 {operation} 中不存在序号为 {ordinal} 的动作")]
    UnknownAction {
        /// 所属操作。
        operation: OperationId,
        /// 动作序号。
        ordinal: u32,
    },
    /// 同一操作中出现了重复的（资源, 动作种类）组合。
    #[error("操作中资源 `{resource}` 的 `{kind}` 动作重复")]
    DuplicateAction {
        /// 重复的资源标识。
        resource: String,
        /// 重复的动作种类。
        kind: String,
    },
    /// 收据记录的资源与动作登记的资源不一致。
    #[error("序号 {ordinal} 的收据资源 `{receipt}` 与动作资源 `{action}` 不一致")]
    ReceiptResourceMismatch {
        /// 动作序号。
        ordinal: u32,
        /// 收据中的资源。
        receipt: String,
        /// 动作中的资源。
        action: String,
    },
    /// 状态在读取与写入之间被其他连接改动。
    #[error("操作 {0} 的状态在更新过程中被并发修改")]
    ConcurrentModification(OperationId),
    /// revision 超出 SQLite 有符号 64 位整数范围。
    #[error("revision {0} 超出 SQLite 整数范围")]
    RevisionOutOfRange(u64),
    /// 数据库中存在无法解释的值。
    #[error("journal 数据损坏：{0}")]
    Corrupt(String),
}

impl JournalError {
    /// 稳定的机器可读错误码，用于 CLI 的 JSON 契约与退出码判定。
    ///
    /// 这些字符串属于对外契约的一部分，只能新增、不能重命名。
    pub fn code(&self) -> &'static str {
        match self {
            JournalError::Sqlite { .. } => "storage.sqlite",
            JournalError::Io { .. } => "storage.io",
            JournalError::Json { .. } => "storage.json",
            JournalError::SchemaTooNew { .. } => "storage.schema_too_new",
            JournalError::PragmaRejected { .. } => "storage.pragma_rejected",
            JournalError::IllegalTransition { .. } => "storage.illegal_transition",
            JournalError::UnknownOperation { .. } => "storage.unknown_operation",
            JournalError::UnknownAction { .. } => "storage.unknown_action",
            JournalError::DuplicateAction { .. } => "storage.duplicate_action",
            JournalError::ReceiptResourceMismatch { .. } => "storage.receipt_resource_mismatch",
            JournalError::ConcurrentModification { .. } => "storage.concurrent_modification",
            JournalError::RevisionOutOfRange { .. } => "storage.revision_out_of_range",
            JournalError::Corrupt { .. } => "storage.corrupt",
        }
    }
}

/// 操作状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    /// 计划已登记，尚未做任何检查。
    Planned,
    /// preflight 全部通过，临时文件已就绪。
    Preflighted,
    /// 后端 Ref 已通过 CAS 更新。
    Published,
    /// 正在把动作应用到本地文件。
    Applying,
    /// 全部动作已应用并通过校验。
    Verified,
    /// 事务成功结束。
    Completed,
    /// 已发布但本地未收敛：后端头已前进，本地文件没跟上。
    ///
    /// 这不是普通失败，必须由后续恢复或显式回滚处理。
    PublishedNotConverged,
    /// 在产生任何本地写入之前放弃。
    Aborted,
    /// 正在按收据逆序回滚。
    RollingBack,
    /// 回滚完成。
    RolledBack,
}

impl OperationState {
    /// 全部状态，顺序稳定，便于穷举测试与 UI 展示。
    pub const ALL: [OperationState; 10] = [
        OperationState::Planned,
        OperationState::Preflighted,
        OperationState::Published,
        OperationState::Applying,
        OperationState::Verified,
        OperationState::Completed,
        OperationState::PublishedNotConverged,
        OperationState::Aborted,
        OperationState::RollingBack,
        OperationState::RolledBack,
    ];

    /// 数据库与 JSON 中使用的稳定文本表示。
    pub const fn as_str(self) -> &'static str {
        match self {
            OperationState::Planned => "planned",
            OperationState::Preflighted => "preflighted",
            OperationState::Published => "published",
            OperationState::Applying => "applying",
            OperationState::Verified => "verified",
            OperationState::Completed => "completed",
            OperationState::PublishedNotConverged => "published_not_converged",
            OperationState::Aborted => "aborted",
            OperationState::RollingBack => "rolling_back",
            OperationState::RolledBack => "rolled_back",
        }
    }

    /// 由文本表示解析；未知取值返回 `None`。
    pub fn parse(text: &str) -> Option<Self> {
        OperationState::ALL
            .into_iter()
            .find(|state| state.as_str() == text)
    }

    /// 是否为终态：终态的操作不再需要恢复。
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            OperationState::Completed | OperationState::Aborted | OperationState::RolledBack
        )
    }

    /// 判断迁移是否合法。
    ///
    /// 注意这里**不允许**自迁移：把同一状态重复写入通常意味着调用方丢失了上下文，
    /// 与其静默接受，不如让它显式失败。
    pub const fn can_transition_to(self, to: OperationState) -> bool {
        use OperationState::*;
        matches!(
            (self, to),
            (Planned, Preflighted)
                | (Preflighted, Published)
                | (Published, Applying)
                | (Published, PublishedNotConverged)
                | (Applying, Verified)
                | (Verified, Completed)
                | (Planned | Preflighted, Aborted)
                | (Applying | PublishedNotConverged, RollingBack)
                // 显式回滚一个已完成的操作：CLI 的 `envsync rollback --operation <id>`
                // 走这条边。计划文档的状态机只考虑了失败路径上的回滚，但「反悔一次
                // 成功的同步」同样必须留下完整审计记录，而不是绕过日志直接改文件。
                | (Completed, RollingBack)
                | (RollingBack, RolledBack)
                // 恢复流程重新收敛：从「已发布未收敛」回到逐动作应用。
                | (PublishedNotConverged, Applying)
                // 应用途中发现人工冲突（目标既不等于原摘要也不等于应用后摘要）时，
                // 停在 published_not_converged 等待人工处理。
                | (Applying, PublishedNotConverged)
                // 回滚本身失败时，操作必须停在 published_not_converged：后端已经
                // 声称该快照是当前头，而本地既没收敛也没回滚干净，只能等恢复流程
                // 或人工处理。绝不允许降级成普通失败终态。
                | (RollingBack, PublishedNotConverged)
        )
    }

    /// 当前状态允许迁移到的全部状态。
    pub fn successors(self) -> Vec<OperationState> {
        OperationState::ALL
            .into_iter()
            .filter(|to| self.can_transition_to(*to))
            .collect()
    }
}

impl fmt::Display for OperationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 单个动作的执行进度。
///
/// 与 [`OperationState`] 不同，动作状态**不构成受约束的状态机**：恢复流程需要
/// 根据现场观察把动作直接置为任意进度，强加迁移规则只会妨碍恢复。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionState {
    /// 已登记，尚未处理。
    Pending,
    /// 临时文件已就绪，尚未替换目标。
    Staged,
    /// 已写入目标并留下收据。
    Applied,
    /// 已重新观察并核对摘要。
    Verified,
    /// 应用或校验失败。
    Failed,
    /// 已按收据还原。
    RolledBack,
}

impl ActionState {
    /// 全部动作状态。
    pub const ALL: [ActionState; 6] = [
        ActionState::Pending,
        ActionState::Staged,
        ActionState::Applied,
        ActionState::Verified,
        ActionState::Failed,
        ActionState::RolledBack,
    ];

    /// 数据库与 JSON 中使用的稳定文本表示。
    pub const fn as_str(self) -> &'static str {
        match self {
            ActionState::Pending => "pending",
            ActionState::Staged => "staged",
            ActionState::Applied => "applied",
            ActionState::Verified => "verified",
            ActionState::Failed => "failed",
            ActionState::RolledBack => "rolled_back",
        }
    }

    /// 由文本表示解析；未知取值返回 `None`。
    pub fn parse(text: &str) -> Option<Self> {
        ActionState::ALL
            .into_iter()
            .find(|state| state.as_str() == text)
    }
}

impl fmt::Display for ActionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 机器可读的错误记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDetail {
    /// 稳定错误码，例如 `apply.rename_failed`。
    pub code: String,
    /// 人类可读说明；不得包含秘密内容。
    pub message: String,
}

impl ErrorDetail {
    /// 构造错误记录。
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        ErrorDetail {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// 一条操作记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRecord {
    /// 操作标识。
    pub operation: OperationId,
    /// 关联计划。
    pub plan: PlanId,
    /// 目标快照。
    pub snapshot: SnapshotId,
    /// 所属工作区。
    pub workspace: WorkspaceId,
    /// 计划生成时后端 Ref 的 revision。
    pub revision: u64,
    /// 当前状态。
    pub state: OperationState,
    /// 登记时刻（Unix 毫秒）。
    pub created_at_unix_ms: u64,
    /// 最后一次状态更新时刻（Unix 毫秒）。
    pub updated_at_unix_ms: u64,
    /// 失败原因。
    pub error: Option<ErrorDetail>,
}

/// 一条动作记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRecord {
    /// 所属操作。
    pub operation: OperationId,
    /// 在计划中的应用顺序；回滚按其逆序进行。
    pub ordinal: u32,
    /// 关联资源。
    pub resource: ResourceId,
    /// 写入目标（授权根别名 + 相对分段）。
    pub target: ActionTarget,
    /// 动作种类。
    pub kind: ActionKind,
    /// 当前进度。
    pub state: ActionState,
    /// 应用前目标应有的摘要；`None` 表示目标应当不存在。
    pub expected_before: Option<Digest32>,
    /// 应用后目标应有的摘要；`None` 表示删除。
    pub expected_after: Option<Digest32>,
    /// 失败原因。
    pub error: Option<ErrorDetail>,
}

/// 回滚收据：动作真正改动文件后留下的还原证据。
///
/// 字段刻意全部是原始类型：`backup_path` 只是字符串，摘要是领域层的
/// [`Digest32`]（持久化为小写十六进制文本）。storage crate 不引入任何平台路径类型。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// 对应动作的序号。
    pub ordinal: u32,
    /// 对应动作的资源，写入时会与动作登记的资源核对。
    pub resource: ResourceId,
    /// 备份文件位置；目标原本不存在时为 `None`。
    pub backup_path: Option<String>,
    /// 应用前目标的内容摘要；目标原本不存在时为 `None`。
    pub original_digest: Option<Digest32>,
    /// 应用后目标的内容摘要；删除动作为 `None`。
    pub applied_digest: Option<Digest32>,
    /// 该动作可提供的回滚保证。
    pub guarantee: RollbackCapability,
}

/// 已持久化的收据。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptRecord {
    /// 所属操作。
    pub operation: OperationId,
    /// 收据内容。
    pub receipt: Receipt,
    /// 写入时刻（Unix 毫秒）。
    pub created_at_unix_ms: u64,
}

/// 操作日志。
///
/// 内部持有一个独占的 SQLite 连接，因此不是 `Sync`；需要并发时请为每个线程各开一个
/// [`Journal`]，`busy_timeout` 会处理写锁竞争。
pub struct Journal {
    connection: Connection,
    path: PathBuf,
}

impl fmt::Debug for Journal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Journal").field("path", &self.path).finish()
    }
}

const OPERATION_COLUMNS: &str = "operation_id, plan_id, snapshot_id, workspace_id, revision, \
                                 state, created_at_unix_ms, updated_at_unix_ms, error_code, \
                                 error_message";

const ACTION_COLUMNS: &str = "operation_id, ordinal, resource_id, target, kind, state, \
                              expected_before_digest, expected_after_digest, error_code, \
                              error_message";

const RECEIPT_COLUMNS: &str = "operation_id, ordinal, resource_id, backup_path, original_digest, \
                               applied_digest, guarantee, created_at_unix_ms";

impl Journal {
    /// 打开（必要时创建）指定路径上的操作日志。
    ///
    /// 重复打开同一路径不会出错：迁移幂等，PRAGMA 逐连接重设。
    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        let connection = migrations::open_database(&path)?;
        Ok(Journal { connection, path })
    }

    /// 数据库文件路径。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 连接层诊断（PRAGMA 与 schema 版本）。
    pub fn diagnostics(&self) -> Result<StorageDiagnostics, JournalError> {
        migrations::read_diagnostics(&self.connection)
    }

    /// 数据库中记录的 schema 版本。
    pub fn schema_version(&self) -> Result<u32, JournalError> {
        Ok(migrations::read_schema_version(&self.connection)?.unwrap_or(SCHEMA_VERSION))
    }

    /// 登记一次新操作：写入 operations 行与**全部** actions 行。
    ///
    /// 两者在同一个事务里完成，任何一步失败都整体回滚——不允许出现“操作已登记但动作
    /// 只写了一半”的 journal，否则恢复算法会以为剩下的动作根本不存在。
    pub fn begin(&mut self, plan: &Plan) -> Result<OperationRecord, JournalError> {
        self.begin_with_id(OperationId::generate(), plan)
    }

    /// 以指定操作标识登记新操作，便于测试与幂等重放。
    pub fn begin_with_id(
        &mut self,
        operation: OperationId,
        plan: &Plan,
    ) -> Result<OperationRecord, JournalError> {
        let revision = i64::try_from(plan.base_revision)
            .map_err(|_| JournalError::RevisionOutOfRange(plan.base_revision))?;
        let now = now_millis();
        let now_sql = to_sql_millis(now);

        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO operations (operation_id, plan_id, snapshot_id, workspace_id, revision, \
             state, created_at_unix_ms, updated_at_unix_ms, error_code, error_message) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL)",
            params![
                operation.to_string(),
                plan.id().to_string(),
                plan.target_snapshot.to_string(),
                plan.workspace.to_string(),
                revision,
                OperationState::Planned.as_str(),
                now_sql,
                now_sql,
            ],
        )?;

        for (index, action) in plan.actions.iter().enumerate() {
            let ordinal = u32::try_from(index)
                .map_err(|_| JournalError::Corrupt("计划动作数量超出 u32 范围".to_owned()))?;
            transaction
                .execute(
                    "INSERT INTO actions (operation_id, ordinal, resource_id, target, kind, \
                     state, expected_before_digest, expected_after_digest, error_code, \
                     error_message) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL)",
                    params![
                        operation.to_string(),
                        ordinal,
                        action.resource.as_str(),
                        serde_json::to_string(&action.target)?,
                        action_kind_as_str(action.kind),
                        ActionState::Pending.as_str(),
                        action.expected_before.map(|digest| digest.to_hex()),
                        action.expected_after.map(|digest| digest.to_hex()),
                    ],
                )
                .map_err(|error| map_action_conflict(error, action))?;
        }
        transaction.commit()?;

        tracing::debug!(
            operation = %operation,
            actions = plan.actions.len(),
            "已登记同步操作"
        );

        Ok(OperationRecord {
            operation,
            plan: plan.id(),
            snapshot: plan.target_snapshot,
            workspace: plan.workspace,
            revision: plan.base_revision,
            state: OperationState::Planned,
            created_at_unix_ms: now,
            updated_at_unix_ms: now,
            error: None,
        })
    }

    /// 迁移到新状态；非法迁移返回 [`JournalError::IllegalTransition`]。
    pub fn transition(
        &self,
        operation: OperationId,
        to: OperationState,
    ) -> Result<OperationRecord, JournalError> {
        self.transition_inner(operation, to, None)
    }

    /// 带失败原因地迁移到新状态。
    pub fn transition_failed(
        &self,
        operation: OperationId,
        to: OperationState,
        error: &ErrorDetail,
    ) -> Result<OperationRecord, JournalError> {
        self.transition_inner(operation, to, Some(error))
    }

    fn transition_inner(
        &self,
        operation: OperationId,
        to: OperationState,
        error: Option<&ErrorDetail>,
    ) -> Result<OperationRecord, JournalError> {
        let from = self
            .operation_state(operation)?
            .ok_or(JournalError::UnknownOperation(operation))?;
        if !from.can_transition_to(to) {
            return Err(JournalError::IllegalTransition { from, to });
        }
        let now = to_sql_millis(now_millis());
        // `WHERE ... AND state = from` 让更新对并发写入保持原子：状态在读取之后被别的
        // 连接改动时受影响行数为 0，此时宁可报错也不能覆盖别人的迁移结果。
        let affected = match error {
            None => self.connection.execute(
                "UPDATE operations SET state = ?1, updated_at_unix_ms = ?2 \
                 WHERE operation_id = ?3 AND state = ?4",
                params![to.as_str(), now, operation.to_string(), from.as_str()],
            )?,
            Some(detail) => self.connection.execute(
                "UPDATE operations SET state = ?1, updated_at_unix_ms = ?2, error_code = ?3, \
                 error_message = ?4 WHERE operation_id = ?5 AND state = ?6",
                params![
                    to.as_str(),
                    now,
                    detail.code,
                    detail.message,
                    operation.to_string(),
                    from.as_str()
                ],
            )?,
        };
        if affected != 1 {
            return Err(JournalError::ConcurrentModification(operation));
        }
        tracing::debug!(operation = %operation, %from, %to, "操作状态已迁移");
        self.operation(operation)?
            .ok_or(JournalError::UnknownOperation(operation))
    }

    /// 记录失败原因但**不**改变状态。
    pub fn record_error(
        &self,
        operation: OperationId,
        error: &ErrorDetail,
    ) -> Result<(), JournalError> {
        let affected = self.connection.execute(
            "UPDATE operations SET error_code = ?1, error_message = ?2, updated_at_unix_ms = ?3 \
             WHERE operation_id = ?4",
            params![
                error.code,
                error.message,
                to_sql_millis(now_millis()),
                operation.to_string()
            ],
        )?;
        if affected != 1 {
            return Err(JournalError::UnknownOperation(operation));
        }
        Ok(())
    }

    /// 更新单个动作的进度。
    pub fn set_action_state(
        &self,
        operation: OperationId,
        ordinal: u32,
        state: ActionState,
    ) -> Result<(), JournalError> {
        let affected = self.connection.execute(
            "UPDATE actions SET state = ?1 WHERE operation_id = ?2 AND ordinal = ?3",
            params![state.as_str(), operation.to_string(), ordinal],
        )?;
        if affected != 1 {
            return Err(JournalError::UnknownAction { operation, ordinal });
        }
        Ok(())
    }

    /// 记录动作失败原因，并把动作置为 [`ActionState::Failed`]。
    pub fn record_action_error(
        &self,
        operation: OperationId,
        ordinal: u32,
        error: &ErrorDetail,
    ) -> Result<(), JournalError> {
        let affected = self.connection.execute(
            "UPDATE actions SET state = ?1, error_code = ?2, error_message = ?3 \
             WHERE operation_id = ?4 AND ordinal = ?5",
            params![
                ActionState::Failed.as_str(),
                error.code,
                error.message,
                operation.to_string(),
                ordinal
            ],
        )?;
        if affected != 1 {
            return Err(JournalError::UnknownAction { operation, ordinal });
        }
        Ok(())
    }

    /// 保存回滚收据，并在**同一个事务**里把对应动作置为 [`ActionState::Applied`]。
    ///
    /// 两者必须原子：只写收据不改动作状态，恢复时会重复应用；只改状态不写收据，
    /// 恢复时找不到备份，等于永久丢失还原能力。
    ///
    /// 重复写入同一序号的收据是幂等的（覆盖），恢复流程可以安全重放。
    pub fn record_receipt(
        &mut self,
        operation: OperationId,
        receipt: &Receipt,
    ) -> Result<(), JournalError> {
        let now = to_sql_millis(now_millis());
        let transaction = self.connection.transaction()?;

        let action_resource: Option<String> = transaction
            .query_row(
                "SELECT resource_id FROM actions WHERE operation_id = ?1 AND ordinal = ?2",
                params![operation.to_string(), receipt.ordinal],
                |row| row.get(0),
            )
            .optional()?;
        let action_resource = action_resource.ok_or(JournalError::UnknownAction {
            operation,
            ordinal: receipt.ordinal,
        })?;
        if action_resource != receipt.resource.as_str() {
            return Err(JournalError::ReceiptResourceMismatch {
                ordinal: receipt.ordinal,
                receipt: receipt.resource.to_string(),
                action: action_resource,
            });
        }

        transaction.execute(
            "UPDATE actions SET state = ?1 WHERE operation_id = ?2 AND ordinal = ?3",
            params![
                ActionState::Applied.as_str(),
                operation.to_string(),
                receipt.ordinal
            ],
        )?;
        transaction.execute(
            "INSERT INTO receipts (operation_id, ordinal, resource_id, backup_path, \
             original_digest, applied_digest, guarantee, created_at_unix_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
             ON CONFLICT (operation_id, ordinal) DO UPDATE SET \
             resource_id = excluded.resource_id, backup_path = excluded.backup_path, \
             original_digest = excluded.original_digest, \
             applied_digest = excluded.applied_digest, guarantee = excluded.guarantee, \
             created_at_unix_ms = excluded.created_at_unix_ms",
            params![
                operation.to_string(),
                receipt.ordinal,
                receipt.resource.as_str(),
                receipt.backup_path,
                receipt.original_digest.map(|digest| digest.to_hex()),
                receipt.applied_digest.map(|digest| digest.to_hex()),
                rollback_capability_as_str(receipt.guarantee),
                now,
            ],
        )?;
        transaction.commit()?;
        tracing::debug!(operation = %operation, ordinal = receipt.ordinal, "已保存回滚收据");
        Ok(())
    }

    /// 读取单个操作。
    pub fn operation(
        &self,
        operation: OperationId,
    ) -> Result<Option<OperationRecord>, JournalError> {
        let raw: Option<RawOperation> = self
            .connection
            .query_row(
                &format!("SELECT {OPERATION_COLUMNS} FROM operations WHERE operation_id = ?1"),
                params![operation.to_string()],
                RawOperation::from_row,
            )
            .optional()?;
        raw.map(RawOperation::into_record).transpose()
    }

    /// 读取单个操作的当前状态。
    pub fn operation_state(
        &self,
        operation: OperationId,
    ) -> Result<Option<OperationState>, JournalError> {
        let raw: Option<String> = self
            .connection
            .query_row(
                "SELECT state FROM operations WHERE operation_id = ?1",
                params![operation.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        raw.map(|text| {
            OperationState::parse(&text)
                .ok_or_else(|| JournalError::Corrupt(format!("未知的操作状态 `{text}`")))
        })
        .transpose()
    }

    /// 列出所有**未完成**操作：状态不在 `{completed, aborted, rolled_back}` 中。
    ///
    /// 这是崩溃恢复的入口：重开数据库后先跑它，再逐个决定继续、回滚还是报告冲突。
    pub fn list_unfinished(&self) -> Result<Vec<OperationRecord>, JournalError> {
        let terminal = OperationState::ALL
            .into_iter()
            .filter(|state| state.is_terminal())
            .map(|state| format!("'{}'", state.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT {OPERATION_COLUMNS} FROM operations WHERE state NOT IN ({terminal}) \
             ORDER BY created_at_unix_ms, operation_id"
        );
        self.query_operations(&sql, [])
    }

    /// 列出处于指定状态的操作。
    pub fn list_by_state(
        &self,
        state: OperationState,
    ) -> Result<Vec<OperationRecord>, JournalError> {
        let sql = format!(
            "SELECT {OPERATION_COLUMNS} FROM operations WHERE state = ?1 \
             ORDER BY created_at_unix_ms, operation_id"
        );
        self.query_operations(&sql, params![state.as_str()])
    }

    fn query_operations<P: rusqlite::Params>(
        &self,
        sql: &str,
        params: P,
    ) -> Result<Vec<OperationRecord>, JournalError> {
        let mut statement = self.connection.prepare(sql)?;
        let rows = statement.query_map(params, RawOperation::from_row)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?.into_record()?);
        }
        Ok(records)
    }

    /// 按序号升序读取操作的全部动作。
    pub fn actions(&self, operation: OperationId) -> Result<Vec<ActionRecord>, JournalError> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {ACTION_COLUMNS} FROM actions WHERE operation_id = ?1 ORDER BY ordinal"
        ))?;
        let rows = statement.query_map(params![operation.to_string()], RawAction::from_row)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?.into_record()?);
        }
        Ok(records)
    }

    /// 按序号升序读取操作的全部收据。回滚时应逆序消费。
    pub fn receipts(&self, operation: OperationId) -> Result<Vec<ReceiptRecord>, JournalError> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {RECEIPT_COLUMNS} FROM receipts WHERE operation_id = ?1 ORDER BY ordinal"
        ))?;
        let rows = statement.query_map(params![operation.to_string()], RawReceipt::from_row)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?.into_record()?);
        }
        Ok(records)
    }

    /// 删除一条操作及其全部动作与收据（依赖外键级联）。
    ///
    /// 仅用于保留策略清理历史；返回是否真的删掉了一行。
    pub fn prune_operation(&self, operation: OperationId) -> Result<bool, JournalError> {
        let affected = self.connection.execute(
            "DELETE FROM operations WHERE operation_id = ?1",
            params![operation.to_string()],
        )?;
        Ok(affected == 1)
    }
}

/// 当前 Unix 毫秒。
fn now_millis() -> u64 {
    unix_millis_now()
}

/// 毫秒时间戳转 SQLite 整数；超出范围时饱和，绝不 panic。
fn to_sql_millis(millis: u64) -> i64 {
    i64::try_from(millis).unwrap_or(i64::MAX)
}

/// 把动作插入时的唯一约束冲突翻译成可读错误。
fn map_action_conflict(error: rusqlite::Error, action: &Action) -> JournalError {
    if let rusqlite::Error::SqliteFailure(inner, _) = &error {
        if inner.code == rusqlite::ErrorCode::ConstraintViolation {
            return JournalError::DuplicateAction {
                resource: action.resource.to_string(),
                kind: action_kind_as_str(action.kind).to_owned(),
            };
        }
    }
    JournalError::Sqlite(error)
}

/// 动作种类的稳定文本表示。
fn action_kind_as_str(kind: ActionKind) -> &'static str {
    match kind {
        ActionKind::DeleteFile => "delete_file",
        ActionKind::CreateFile => "create_file",
        ActionKind::ReplaceFile => "replace_file",
        ActionKind::UpdateManagedBlock => "update_managed_block",
    }
}

/// 由文本还原动作种类。
fn action_kind_from_str(text: &str) -> Option<ActionKind> {
    Some(match text {
        "delete_file" => ActionKind::DeleteFile,
        "create_file" => ActionKind::CreateFile,
        "replace_file" => ActionKind::ReplaceFile,
        "update_managed_block" => ActionKind::UpdateManagedBlock,
        _ => return None,
    })
}

/// 回滚能力的稳定文本表示。
fn rollback_capability_as_str(capability: RollbackCapability) -> &'static str {
    match capability {
        RollbackCapability::Exact => "exact",
        RollbackCapability::Compensating => "compensating",
        RollbackCapability::None => "none",
    }
}

/// 由文本还原回滚能力。
fn rollback_capability_from_str(text: &str) -> Option<RollbackCapability> {
    Some(match text {
        "exact" => RollbackCapability::Exact,
        "compensating" => RollbackCapability::Compensating,
        "none" => RollbackCapability::None,
        _ => return None,
    })
}

/// 解析数据库中的文本字段，失败一律归为 [`JournalError::Corrupt`]。
fn parse_field<T>(text: &str, field: &'static str) -> Result<T, JournalError>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    text.parse::<T>()
        .map_err(|error| JournalError::Corrupt(format!("字段 `{field}` 无法解析：{error}")))
}

/// 解析可选的十六进制摘要字段。
fn parse_optional_digest(
    text: Option<String>,
    field: &'static str,
) -> Result<Option<Digest32>, JournalError> {
    text.map(|raw| parse_field::<Digest32>(&raw, field))
        .transpose()
}

/// 把两列错误信息合并成 [`ErrorDetail`]。
fn error_detail(code: Option<String>, message: Option<String>) -> Option<ErrorDetail> {
    code.map(|code| ErrorDetail {
        code,
        message: message.unwrap_or_default(),
    })
}

/// 把 SQLite 中的毫秒时间戳还原成 `u64`。
fn from_sql_millis(value: i64, field: &'static str) -> Result<u64, JournalError> {
    u64::try_from(value)
        .map_err(|_| JournalError::Corrupt(format!("字段 `{field}` 是负数时间戳：{value}")))
}

/// operations 行的原始形态。
struct RawOperation {
    operation: String,
    plan: String,
    snapshot: String,
    workspace: String,
    revision: i64,
    state: String,
    created_at: i64,
    updated_at: i64,
    error_code: Option<String>,
    error_message: Option<String>,
}

impl RawOperation {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(RawOperation {
            operation: row.get(0)?,
            plan: row.get(1)?,
            snapshot: row.get(2)?,
            workspace: row.get(3)?,
            revision: row.get(4)?,
            state: row.get(5)?,
            created_at: row.get(6)?,
            updated_at: row.get(7)?,
            error_code: row.get(8)?,
            error_message: row.get(9)?,
        })
    }

    fn into_record(self) -> Result<OperationRecord, JournalError> {
        Ok(OperationRecord {
            operation: parse_field(&self.operation, "operation_id")?,
            plan: parse_field(&self.plan, "plan_id")?,
            snapshot: parse_field(&self.snapshot, "snapshot_id")?,
            workspace: parse_field(&self.workspace, "workspace_id")?,
            revision: u64::try_from(self.revision).map_err(|_| {
                JournalError::Corrupt(format!("字段 `revision` 是负数：{}", self.revision))
            })?,
            state: OperationState::parse(&self.state)
                .ok_or_else(|| JournalError::Corrupt(format!("未知的操作状态 `{}`", self.state)))?,
            created_at_unix_ms: from_sql_millis(self.created_at, "created_at_unix_ms")?,
            updated_at_unix_ms: from_sql_millis(self.updated_at, "updated_at_unix_ms")?,
            error: error_detail(self.error_code, self.error_message),
        })
    }
}

/// actions 行的原始形态。
struct RawAction {
    operation: String,
    ordinal: i64,
    resource: String,
    target: String,
    kind: String,
    state: String,
    expected_before: Option<String>,
    expected_after: Option<String>,
    error_code: Option<String>,
    error_message: Option<String>,
}

impl RawAction {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(RawAction {
            operation: row.get(0)?,
            ordinal: row.get(1)?,
            resource: row.get(2)?,
            target: row.get(3)?,
            kind: row.get(4)?,
            state: row.get(5)?,
            expected_before: row.get(6)?,
            expected_after: row.get(7)?,
            error_code: row.get(8)?,
            error_message: row.get(9)?,
        })
    }

    fn into_record(self) -> Result<ActionRecord, JournalError> {
        Ok(ActionRecord {
            operation: parse_field(&self.operation, "operation_id")?,
            ordinal: u32::try_from(self.ordinal).map_err(|_| {
                JournalError::Corrupt(format!("字段 `ordinal` 超出范围：{}", self.ordinal))
            })?,
            resource: parse_field(&self.resource, "resource_id")?,
            target: serde_json::from_str(&self.target)?,
            kind: action_kind_from_str(&self.kind)
                .ok_or_else(|| JournalError::Corrupt(format!("未知的动作种类 `{}`", self.kind)))?,
            state: ActionState::parse(&self.state)
                .ok_or_else(|| JournalError::Corrupt(format!("未知的动作状态 `{}`", self.state)))?,
            expected_before: parse_optional_digest(self.expected_before, "expected_before_digest")?,
            expected_after: parse_optional_digest(self.expected_after, "expected_after_digest")?,
            error: error_detail(self.error_code, self.error_message),
        })
    }
}

/// receipts 行的原始形态。
struct RawReceipt {
    operation: String,
    ordinal: i64,
    resource: String,
    backup_path: Option<String>,
    original_digest: Option<String>,
    applied_digest: Option<String>,
    guarantee: String,
    created_at: i64,
}

impl RawReceipt {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(RawReceipt {
            operation: row.get(0)?,
            ordinal: row.get(1)?,
            resource: row.get(2)?,
            backup_path: row.get(3)?,
            original_digest: row.get(4)?,
            applied_digest: row.get(5)?,
            guarantee: row.get(6)?,
            created_at: row.get(7)?,
        })
    }

    fn into_record(self) -> Result<ReceiptRecord, JournalError> {
        Ok(ReceiptRecord {
            operation: parse_field(&self.operation, "operation_id")?,
            receipt: Receipt {
                ordinal: u32::try_from(self.ordinal).map_err(|_| {
                    JournalError::Corrupt(format!("字段 `ordinal` 超出范围：{}", self.ordinal))
                })?,
                resource: parse_field(&self.resource, "resource_id")?,
                backup_path: self.backup_path,
                original_digest: parse_optional_digest(self.original_digest, "original_digest")?,
                applied_digest: parse_optional_digest(self.applied_digest, "applied_digest")?,
                guarantee: rollback_capability_from_str(&self.guarantee).ok_or_else(|| {
                    JournalError::Corrupt(format!("未知的回滚能力 `{}`", self.guarantee))
                })?,
            },
            created_at_unix_ms: from_sql_millis(self.created_at, "created_at_unix_ms")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_text_round_trips() {
        for state in OperationState::ALL {
            assert_eq!(OperationState::parse(state.as_str()), Some(state));
        }
        for state in ActionState::ALL {
            assert_eq!(ActionState::parse(state.as_str()), Some(state));
        }
        assert_eq!(OperationState::parse("nope"), None);
        assert_eq!(ActionState::parse("nope"), None);
    }

    #[test]
    fn terminal_states_have_no_successors() {
        for state in OperationState::ALL {
            if state.is_terminal() {
                assert!(state.successors().is_empty(), "{state} 不应有后继状态");
            }
        }
    }

    #[test]
    fn no_state_can_transition_to_itself() {
        for state in OperationState::ALL {
            assert!(!state.can_transition_to(state), "{state} 不应允许自迁移");
        }
    }
}
