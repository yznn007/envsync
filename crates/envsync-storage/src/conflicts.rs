//! 合并冲突的本地索引与状态。
//!
//! [`envsync_domain::object::Conflict`] 是**内容寻址的不可变对象**：它描述“发生了
//! 什么冲突”，由 canonical CBOR 决定标识，可以放进草稿库或 Backend。而“这个冲突
//! 在本机处于什么状态、用户怎么决定的”是**可变的本地事实**，属于关系表。
//!
//! 因此这里的分工是：
//!
//! * `conflicts` 表只存*索引与状态*——工作区、资源、种类、三个 Blob 指针、当前状态
//!   和解决结果；
//! * 诊断正文（`Conflict::diagnostics`）**不入库**：它是不可变对象的一部分，复制一份
//!   进关系表就会出现两个可能不一致的事实来源。需要正文时按 [`ConflictId`] 去取对象。
//!
//! ## 状态机
//!
//! ```text
//! open -> resolved     用户做出决定
//! open -> superseded   该冲突已被新的合并结果取代
//! ```
//!
//! 终态不会回到 `open`：冲突标识就是内容摘要，同样的冲突再次出现时它**还是同一行**；
//! 内容不同的冲突则是另一个标识、另一行。也正因如此，[`ConflictStore::record`] 天然
//! 幂等，而且**绝不会**把一个已经解决的冲突重新打开。
//!
//! ## 解决方案必须指向存在的 Blob
//!
//! [`ConflictStore::resolve`] 在写入前会去 `objects` 表确认结果 Blob 确实存在。这道
//! 检查必须发生在动用户文件之前：如果等到收敛阶段才发现内容取不到，届时文件可能
//! 已经被改写，只能走回滚。

use std::path::{Path, PathBuf};

use envsync_domain::id::{BlobId, ConflictId, ResourceId, WorkspaceId};
use envsync_domain::object::{Conflict, ConflictKind, ObjectId, ObjectKind};
use envsync_domain::profile::{ConflictResolution, ProfileError, ResolutionChoice};
use envsync_domain::unix_millis_now;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};

use crate::journal::JournalError;
use crate::migrations::{self, StorageDiagnostics};

/// 冲突存储错误。
///
/// 所有变体都只描述结构性问题，不携带资源内容，可以安全写进日志与 CLI 输出。
#[derive(Debug, thiserror::Error)]
pub enum ConflictError {
    /// 底层 SQLite 错误。
    #[error("SQLite 错误：{0}")]
    Sqlite(#[from] rusqlite::Error),
    /// 打开数据库或迁移 schema 失败。
    #[error(transparent)]
    Storage(#[from] JournalError),
    /// 解决方案本身不合法（形状不自洽或引用了不存在的 Blob）。
    #[error("冲突解决方案非法：{0}")]
    InvalidResolution(#[from] ProfileError),
    /// 冲突不存在。
    #[error("冲突 {0} 不存在")]
    UnknownConflict(String),
    /// 解决方案指向的冲突与被操作的冲突不是同一个。
    #[error("解决方案针对冲突 {resolution}，与被操作的 {target} 不一致")]
    ConflictMismatch {
        /// 解决方案中记录的冲突。
        resolution: String,
        /// 实际被操作的冲突。
        target: String,
    },
    /// 冲突已处于终态，不能再次解决。
    #[error("冲突 {conflict} 已处于 `{state}` 状态，不能重复解决")]
    NotOpen {
        /// 冲突标识。
        conflict: String,
        /// 当前状态。
        state: &'static str,
    },
    /// 数据库中存在无法解释的值。
    #[error("冲突索引数据损坏：{0}")]
    Corrupt(String),
}

impl ConflictError {
    /// 稳定的机器可读错误码，用于 CLI 的 JSON 契约与退出码判定。
    ///
    /// 这些字符串属于对外契约的一部分，只能新增、不能重命名。
    pub fn code(&self) -> &'static str {
        match self {
            ConflictError::Sqlite { .. } => "conflict.sqlite",
            ConflictError::Storage { .. } => "conflict.storage",
            ConflictError::InvalidResolution { .. } => "conflict.invalid_resolution",
            ConflictError::UnknownConflict { .. } => "conflict.unknown",
            ConflictError::ConflictMismatch { .. } => "conflict.mismatch",
            ConflictError::NotOpen { .. } => "conflict.not_open",
            ConflictError::Corrupt { .. } => "conflict.corrupt",
        }
    }
}

/// 冲突在本机的处理状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictState {
    /// 等待用户决定。
    Open,
    /// 用户已经给出解决方案。
    Resolved,
    /// 已被新的合并结果取代，无需处理。
    Superseded,
}

impl ConflictState {
    /// 稳定的短名称，与数据库中的取值一一对应。
    pub const fn as_str(self) -> &'static str {
        match self {
            ConflictState::Open => "open",
            ConflictState::Resolved => "resolved",
            ConflictState::Superseded => "superseded",
        }
    }

    /// 由短名称解析；未知取值返回 `None`。
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "open" => ConflictState::Open,
            "resolved" => ConflictState::Resolved,
            "superseded" => ConflictState::Superseded,
            _ => return None,
        })
    }

    /// 是否为终态。
    pub const fn is_terminal(self) -> bool {
        !matches!(self, ConflictState::Open)
    }
}

/// 冲突在本机的一行索引记录。
///
/// 刻意**不含**诊断正文：那是内容寻址对象的一部分，见模块文档。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictRecord {
    /// 冲突标识（即冲突对象的内容摘要）。
    pub conflict: ConflictId,
    /// 所属工作区。
    pub workspace: WorkspaceId,
    /// 发生冲突的资源。
    pub resource: ResourceId,
    /// 冲突种类。
    pub kind: ConflictKind,
    /// 合并基版本的 Blob。
    pub base: Option<BlobId>,
    /// 本地一侧的 Blob。
    pub ours: Option<BlobId>,
    /// 远端一侧的 Blob。
    pub theirs: Option<BlobId>,
    /// 当前状态。
    pub state: ConflictState,
    /// 解决方式；未解决时为 `None`。
    pub choice: Option<ResolutionChoice>,
    /// 解决后的内容；`Delete` 或未解决时为 `None`。
    pub resolved_blob: Option<BlobId>,
    /// 登记时间（Unix 毫秒）。
    pub created_at_unix_ms: i64,
    /// 解决时间（Unix 毫秒）；未解决时为 `None`。
    pub resolved_at_unix_ms: Option<i64>,
}

/// 冲突种类与数据库文本之间的映射。
///
/// 刻意手写而不是复用 serde：这些字符串是**持久化契约**，必须与序列化格式的演进
/// 解耦——改动 serde 属性不应该悄悄改变已经落库的数据。
const fn kind_to_str(kind: ConflictKind) -> &'static str {
    match kind {
        ConflictKind::TextOverlap => "text_overlap",
        ConflictKind::DeleteModify => "delete_modify",
        ConflictKind::StructuredKey => "structured_key",
        ConflictKind::BinaryBoth => "binary_both",
        ConflictKind::IncompatiblePolicy => "incompatible_policy",
    }
}

/// [`kind_to_str`] 的逆映射。
fn kind_from_str(text: &str) -> Option<ConflictKind> {
    Some(match text {
        "text_overlap" => ConflictKind::TextOverlap,
        "delete_modify" => ConflictKind::DeleteModify,
        "structured_key" => ConflictKind::StructuredKey,
        "binary_both" => ConflictKind::BinaryBoth,
        "incompatible_policy" => ConflictKind::IncompatiblePolicy,
        _ => return None,
    })
}

/// 冲突索引存储。
///
/// 与 [`crate::journal::Journal`]、[`crate::draft::DraftStore`] 共用同一套 schema，
/// 因此可以指向同一个数据库文件；三者的表互不重叠，同时打开互不干扰。
#[derive(Debug)]
pub struct ConflictStore {
    connection: Connection,
    path: PathBuf,
}

impl ConflictStore {
    /// 打开（必要时创建）冲突索引所在的数据库文件。
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ConflictError> {
        let path = path.as_ref().to_path_buf();
        let connection = migrations::open_database(&path)?;
        Ok(ConflictStore { connection, path })
    }

    /// 数据库文件路径。
    pub fn database_path(&self) -> &Path {
        &self.path
    }

    /// 连接层诊断（PRAGMA 与 schema 版本）。
    pub fn diagnostics(&self) -> Result<StorageDiagnostics, ConflictError> {
        Ok(migrations::read_diagnostics(&self.connection)?)
    }

    /// 登记一个冲突，返回它的标识。
    ///
    /// 冲突是内容寻址的，因此重复登记同一个冲突是**幂等**的：已存在的行不会被改动，
    /// 尤其**不会**把已解决的冲突重新打开。
    pub fn record(
        &self,
        workspace: WorkspaceId,
        conflict: &Conflict,
    ) -> Result<ConflictId, ConflictError> {
        self.record_at(workspace, conflict, clamp_millis(unix_millis_now()))
    }

    /// 与 [`ConflictStore::record`] 相同，但由调用方给出登记时间。
    ///
    /// 领域层不依赖时钟；需要确定性的场景（测试、重放）用这个版本注入固定时间。
    pub fn record_at(
        &self,
        workspace: WorkspaceId,
        conflict: &Conflict,
        recorded_at_unix_ms: i64,
    ) -> Result<ConflictId, ConflictError> {
        let id = conflict.id();
        self.connection.execute(
            "INSERT INTO conflicts (
                 conflict_id, workspace_id, resource_id, kind,
                 base_blob, ours_blob, theirs_blob,
                 state, resolution_choice, resolved_blob,
                 created_at_unix_ms, resolved_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'open', NULL, NULL, ?8, NULL)
             ON CONFLICT (conflict_id) DO NOTHING",
            params![
                id.to_hex(),
                workspace.to_string(),
                conflict.resource.as_str(),
                kind_to_str(conflict.kind),
                conflict.base.map(|blob| blob.to_hex()),
                conflict.ours.map(|blob| blob.to_hex()),
                conflict.theirs.map(|blob| blob.to_hex()),
                recorded_at_unix_ms,
            ],
        )?;
        tracing::debug!(conflict = %id, resource = %conflict.resource, "已登记合并冲突");
        Ok(id)
    }

    /// 读取一条冲突索引；不存在返回 `None`。
    pub fn get(&self, conflict: ConflictId) -> Result<Option<ConflictRecord>, ConflictError> {
        self.connection
            .query_row(
                "SELECT conflict_id, workspace_id, resource_id, kind,
                        base_blob, ours_blob, theirs_blob,
                        state, resolution_choice, resolved_blob,
                        created_at_unix_ms, resolved_at_unix_ms
                 FROM conflicts WHERE conflict_id = ?1",
                params![conflict.to_hex()],
                row_to_record,
            )
            .optional()?
            .transpose()
    }

    /// 列出某个工作区中全部未解决的冲突，按登记时间、标识升序。
    pub fn list_open(&self, workspace: WorkspaceId) -> Result<Vec<ConflictRecord>, ConflictError> {
        let mut statement = self.connection.prepare(
            "SELECT conflict_id, workspace_id, resource_id, kind,
                    base_blob, ours_blob, theirs_blob,
                    state, resolution_choice, resolved_blob,
                    created_at_unix_ms, resolved_at_unix_ms
             FROM conflicts
             WHERE workspace_id = ?1 AND state = 'open'
             ORDER BY created_at_unix_ms, conflict_id",
        )?;
        let rows = statement.query_map(params![workspace.to_string()], row_to_record)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// 当前状态；冲突不存在时返回 `None`。
    pub fn state(&self, conflict: ConflictId) -> Result<Option<ConflictState>, ConflictError> {
        let raw: Option<String> = self
            .connection
            .query_row(
                "SELECT state FROM conflicts WHERE conflict_id = ?1",
                params![conflict.to_hex()],
                |row| row.get(0),
            )
            .optional()?;
        raw.map(|text| {
            ConflictState::parse(&text)
                .ok_or_else(|| ConflictError::Corrupt(format!("未知的冲突状态 `{text}`")))
        })
        .transpose()
    }

    /// 记录用户对冲突的解决方案。
    ///
    /// 会依次校验：
    ///
    /// 1. 解决方案针对的确实是这个冲突；
    /// 2. 冲突存在且仍处于 `open`；
    /// 3. 解决方案形状自洽（`Delete` 不带 Blob，其余方式必须带）；
    /// 4. 结果 Blob **确实存在**于本地对象表——否则收敛阶段会拿不到内容，
    ///    而那时用户文件可能已经被动过。
    pub fn resolve(
        &self,
        conflict: ConflictId,
        resolution: &ConflictResolution,
    ) -> Result<(), ConflictError> {
        if resolution.conflict != conflict {
            return Err(ConflictError::ConflictMismatch {
                resolution: resolution.conflict.to_hex(),
                target: conflict.to_hex(),
            });
        }
        match self.state(conflict)? {
            None => return Err(ConflictError::UnknownConflict(conflict.to_hex())),
            Some(state) if state.is_terminal() => {
                return Err(ConflictError::NotOpen {
                    conflict: conflict.to_hex(),
                    state: state.as_str(),
                })
            }
            Some(_) => {}
        }

        // 先把“Blob 是否存在”这一 I/O 结果算出来，再交给领域层做纯函数校验：
        // 领域层不做 I/O，存在性只能由持有存储的这一层注入。
        let known = match resolution.resolved_blob {
            Some(blob) if self.has_blob(blob)? => Some(blob),
            _ => None,
        };
        resolution.validate(&|blob| known == Some(blob))?;

        let affected = self.connection.execute(
            "UPDATE conflicts
             SET state = 'resolved',
                 resolution_choice = ?2,
                 resolved_blob = ?3,
                 resolved_at_unix_ms = ?4
             WHERE conflict_id = ?1 AND state = 'open'",
            params![
                conflict.to_hex(),
                resolution.choice.as_str(),
                resolution.resolved_blob.map(|blob| blob.to_hex()),
                clamp_millis(resolution.resolved_at_unix_ms),
            ],
        )?;
        if affected == 0 {
            // 读到 open 与写入之间被其他连接抢先解决了。
            return Err(ConflictError::NotOpen {
                conflict: conflict.to_hex(),
                state: ConflictState::Resolved.as_str(),
            });
        }
        tracing::debug!(
            conflict = %conflict,
            choice = resolution.choice.as_str(),
            "已记录冲突解决方案"
        );
        Ok(())
    }

    /// 把一个未解决的冲突标记为已被取代。
    ///
    /// 用于“重新合并后旧冲突不再适用”的场景：它不是用户的决定，因此不写解决方式。
    pub fn supersede(&self, conflict: ConflictId) -> Result<(), ConflictError> {
        match self.state(conflict)? {
            None => return Err(ConflictError::UnknownConflict(conflict.to_hex())),
            Some(state) if state.is_terminal() => {
                return Err(ConflictError::NotOpen {
                    conflict: conflict.to_hex(),
                    state: state.as_str(),
                })
            }
            Some(_) => {}
        }
        self.connection.execute(
            "UPDATE conflicts SET state = 'superseded'
             WHERE conflict_id = ?1 AND state = 'open'",
            params![conflict.to_hex()],
        )?;
        Ok(())
    }

    /// 本地对象表中是否已存在该 Blob。
    fn has_blob(&self, blob: BlobId) -> Result<bool, ConflictError> {
        let object = ObjectId {
            kind: ObjectKind::Blob,
            digest: blob.digest(),
        };
        let found: Option<i64> = self
            .connection
            .query_row(
                "SELECT 1 FROM objects WHERE object_id = ?1",
                params![object.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }
}

/// 把 Unix 毫秒钳制到 SQLite 有符号 64 位整数范围。
///
/// 时间戳来自时钟或调用方，理论上可能超出 `i64`；宁可保存一个饱和值，也不要因为
/// 一个时间戳把整条冲突记录丢掉。
fn clamp_millis(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// 把一行结果映射为 [`ConflictRecord`]。
///
/// 外层 `Result` 属于 rusqlite（列读取失败），内层属于本 crate（取值无法解释）：
/// 二者分开可以让 `query_map` 的错误传播保持原样。
fn row_to_record(row: &Row<'_>) -> rusqlite::Result<Result<ConflictRecord, ConflictError>> {
    let conflict_id: String = row.get(0)?;
    let workspace_id: String = row.get(1)?;
    let resource_id: String = row.get(2)?;
    let kind: String = row.get(3)?;
    let base: Option<String> = row.get(4)?;
    let ours: Option<String> = row.get(5)?;
    let theirs: Option<String> = row.get(6)?;
    let state: String = row.get(7)?;
    let choice: Option<String> = row.get(8)?;
    let resolved_blob: Option<String> = row.get(9)?;
    let created_at_unix_ms: i64 = row.get(10)?;
    let resolved_at_unix_ms: Option<i64> = row.get(11)?;

    Ok((|| {
        let parse_blob =
            |raw: Option<String>, column: &str| -> Result<Option<BlobId>, ConflictError> {
                raw.map(|text| {
                    text.parse::<BlobId>().map_err(|error| {
                        ConflictError::Corrupt(format!(
                            "列 `{column}` 中的 Blob `{text}` 非法：{error}"
                        ))
                    })
                })
                .transpose()
            };

        Ok(ConflictRecord {
            conflict: conflict_id.parse::<ConflictId>().map_err(|error| {
                ConflictError::Corrupt(format!("冲突标识 `{conflict_id}` 非法：{error}"))
            })?,
            workspace: workspace_id.parse::<WorkspaceId>().map_err(|error| {
                ConflictError::Corrupt(format!("工作区标识 `{workspace_id}` 非法：{error}"))
            })?,
            resource: ResourceId::parse(&resource_id).map_err(|error| {
                ConflictError::Corrupt(format!("资源标识 `{resource_id}` 非法：{error}"))
            })?,
            kind: kind_from_str(&kind)
                .ok_or_else(|| ConflictError::Corrupt(format!("未知的冲突种类 `{kind}`")))?,
            base: parse_blob(base, "base_blob")?,
            ours: parse_blob(ours, "ours_blob")?,
            theirs: parse_blob(theirs, "theirs_blob")?,
            state: ConflictState::parse(&state)
                .ok_or_else(|| ConflictError::Corrupt(format!("未知的冲突状态 `{state}`")))?,
            choice: choice
                .map(|text| {
                    ResolutionChoice::parse(&text)
                        .ok_or_else(|| ConflictError::Corrupt(format!("未知的解决方式 `{text}`")))
                })
                .transpose()?,
            resolved_blob: parse_blob(resolved_blob, "resolved_blob")?,
            created_at_unix_ms,
            resolved_at_unix_ms,
        })
    })())
}
