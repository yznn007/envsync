//! 反回滚检查点的**审计副本**。
//!
//! # 这不是权威副本
//!
//! 检查点的权威副本保存在**系统安全存储**（macOS Keychain / Windows Credential
//! Manager / Linux Secret Service，见 M2 任务 6）。这张表只是审计副本，让
//! `envsync doctor`、事后排查与支持流程能看到「本机认为自己到哪儿了」。
//!
//! 两份不一致时**以安全存储为准并告警**：这个 SQLite 文件躺在用户目录里，任何本地
//! 进程都能改写；把它当权威等于把反回滚保护拱手让人。尤其**不能**出现「SQLite 里的
//! 检查点更旧，于是把安全存储里的降下来」这种逻辑——那是一条免费的回滚通道。
//!
//! # 判定逻辑不在这里
//!
//! 本模块只负责存取，**不做任何单调性判定**。判定是
//! `envsync_core::checkpoint::check_advance` 这一个纯函数；散落到每个存储实现里只会
//! 产生互不一致的安全边界。因此 [`CheckpointAudit::upsert`] 是无条件覆盖写。

use std::path::{Path, PathBuf};

use envsync_domain::id::{Digest32, SnapshotId, WorkspaceId};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};

use crate::journal::JournalError;
use crate::migrations::{self, StorageDiagnostics};

/// 检查点存储错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CheckpointStoreError {
    /// 底层 SQLite 错误。
    #[error("SQLite 错误：{0}")]
    Sqlite(#[from] rusqlite::Error),
    /// 打开数据库或迁移 schema 失败。
    #[error(transparent)]
    Storage(#[from] JournalError),
    /// 数值超出 SQLite 有符号 64 位整数范围。
    #[error("字段 `{field}` 的值 {value} 超出 SQLite 整数范围")]
    OutOfRange {
        /// 字段名（静态字符串，不来自输入）。
        field: &'static str,
        /// 越界数值。
        value: u64,
    },
    /// 数据库中存在无法解释的值。
    #[error("检查点数据损坏：{0}")]
    Corrupt(String),
}

impl CheckpointStoreError {
    /// 稳定的机器可读错误码，用于 CLI 的 JSON 契约。
    ///
    /// 这些字符串属于对外契约的一部分，只能新增、不能重命名。
    pub fn code(&self) -> &'static str {
        match self {
            CheckpointStoreError::Sqlite { .. } => "checkpoint_store.sqlite",
            CheckpointStoreError::Storage { .. } => "checkpoint_store.storage",
            CheckpointStoreError::OutOfRange { .. } => "checkpoint_store.out_of_range",
            CheckpointStoreError::Corrupt { .. } => "checkpoint_store.corrupt",
        }
    }
}

/// 一行检查点记录。
///
/// 字段与 `envsync_core::checkpoint::Checkpoint` 一一对应；存储层不依赖 core，
/// 因此这里独立声明一次，由 core 侧做转换。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointRecord {
    /// 工作区标识。
    pub workspace: WorkspaceId,
    /// 已接受的最高后端 revision。
    pub revision: u64,
    /// 该 revision 对应的快照。
    pub snapshot: SnapshotId,
    /// 已验证的成员链头摘要。
    pub membership_digest: Digest32,
    /// 已验证的成员链头所在的 sequence。摘要之间没有顺序，判定回滚要靠它。
    pub membership_sequence: u64,
    /// 已知的最高密钥纪元。
    pub key_epoch: u64,
    /// 本机更新该检查点的时刻（Unix 毫秒）。
    pub updated_at_unix_ms: u64,
}

/// 检查点审计表。
///
/// 与 [`crate::journal::Journal`] 等共用同一套 schema，可以指向同一个数据库文件。
#[derive(Debug)]
pub struct CheckpointAudit {
    connection: Connection,
    path: PathBuf,
}

impl CheckpointAudit {
    /// 打开（必要时创建）审计副本所在的数据库文件。
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CheckpointStoreError> {
        let path = path.as_ref().to_path_buf();
        let connection = migrations::open_database(&path)?;
        Ok(CheckpointAudit { connection, path })
    }

    /// 数据库文件路径。
    pub fn database_path(&self) -> &Path {
        &self.path
    }

    /// 连接层诊断（PRAGMA 与 schema 版本）。
    pub fn diagnostics(&self) -> Result<StorageDiagnostics, CheckpointStoreError> {
        Ok(migrations::read_diagnostics(&self.connection)?)
    }

    /// 无条件写入（覆盖）一个工作区的检查点。
    ///
    /// **不做**任何单调性判定，见模块文档。调用方必须先经过
    /// `envsync_core::checkpoint::check_advance`。
    pub fn upsert(&self, record: &CheckpointRecord) -> Result<(), CheckpointStoreError> {
        self.connection.execute(
            "INSERT INTO checkpoints (
                 workspace_id, revision, snapshot_id, membership_digest,
                 membership_sequence, key_epoch, updated_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (workspace_id) DO UPDATE SET
                 revision = excluded.revision,
                 snapshot_id = excluded.snapshot_id,
                 membership_digest = excluded.membership_digest,
                 membership_sequence = excluded.membership_sequence,
                 key_epoch = excluded.key_epoch,
                 updated_at_unix_ms = excluded.updated_at_unix_ms",
            params![
                record.workspace.to_string(),
                to_i64("revision", record.revision)?,
                record.snapshot.to_hex(),
                record.membership_digest.to_hex(),
                to_i64("membership_sequence", record.membership_sequence)?,
                to_i64("key_epoch", record.key_epoch)?,
                to_i64("updated_at_unix_ms", record.updated_at_unix_ms)?,
            ],
        )?;
        Ok(())
    }

    /// 读取某个工作区的检查点；不存在返回 `None`。
    pub fn get(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Option<CheckpointRecord>, CheckpointStoreError> {
        self.connection
            .query_row(
                "SELECT workspace_id, revision, snapshot_id, membership_digest,
                        membership_sequence, key_epoch, updated_at_unix_ms
                 FROM checkpoints WHERE workspace_id = ?1",
                params![workspace.to_string()],
                row_to_record,
            )
            .optional()?
            .transpose()
    }

    /// 列出全部检查点，按工作区标识升序。
    pub fn list(&self) -> Result<Vec<CheckpointRecord>, CheckpointStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT workspace_id, revision, snapshot_id, membership_digest,
                    membership_sequence, key_epoch, updated_at_unix_ms
             FROM checkpoints ORDER BY workspace_id",
        )?;
        let rows = statement.query_map([], row_to_record)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// 删除某个工作区的检查点，**重置信任根**。
    ///
    /// # 危险
    ///
    /// 删掉之后本机会接受后端给出的任意状态，包括一份精心构造的旧快照。它只允许出现
    /// 在显式的灾难恢复流程里，并且必须与安全存储中的权威副本一起重置——只删审计副本
    /// 没有任何安全意义，只删权威副本则会留下自相矛盾的本地状态。
    pub fn delete(&self, workspace: WorkspaceId) -> Result<(), CheckpointStoreError> {
        self.connection.execute(
            "DELETE FROM checkpoints WHERE workspace_id = ?1",
            params![workspace.to_string()],
        )?;
        tracing::warn!(
            workspace = %workspace,
            "反回滚检查点（审计副本）已被删除：必须同时重置安全存储中的权威副本"
        );
        Ok(())
    }
}

/// 把 `u64` 转成 SQLite 的有符号 64 位整数，越界时报错而不是静默钳制。
///
/// 这些字段全部参与反回滚判定，一旦被钳制就再也无法比较大小；宁可写入失败。
fn to_i64(field: &'static str, value: u64) -> Result<i64, CheckpointStoreError> {
    i64::try_from(value).map_err(|_| CheckpointStoreError::OutOfRange { field, value })
}

/// 把一行结果映射为 [`CheckpointRecord`]。
fn row_to_record(
    row: &Row<'_>,
) -> rusqlite::Result<Result<CheckpointRecord, CheckpointStoreError>> {
    let workspace: String = row.get(0)?;
    let revision: i64 = row.get(1)?;
    let snapshot: String = row.get(2)?;
    let membership_digest: String = row.get(3)?;
    let membership_sequence: i64 = row.get(4)?;
    let key_epoch: i64 = row.get(5)?;
    let updated_at_unix_ms: i64 = row.get(6)?;

    Ok((|| {
        Ok(CheckpointRecord {
            workspace: workspace.parse::<WorkspaceId>().map_err(|error| {
                CheckpointStoreError::Corrupt(format!("工作区标识 `{workspace}` 非法：{error}"))
            })?,
            revision: from_i64("revision", revision)?,
            snapshot: snapshot.parse::<SnapshotId>().map_err(|error| {
                CheckpointStoreError::Corrupt(format!("快照标识 `{snapshot}` 非法：{error}"))
            })?,
            membership_digest: membership_digest.parse::<Digest32>().map_err(|error| {
                CheckpointStoreError::Corrupt(format!(
                    "成员链头摘要 `{membership_digest}` 非法：{error}"
                ))
            })?,
            membership_sequence: from_i64("membership_sequence", membership_sequence)?,
            key_epoch: from_i64("key_epoch", key_epoch)?,
            updated_at_unix_ms: from_i64("updated_at_unix_ms", updated_at_unix_ms)?,
        })
    })())
}

fn from_i64(column: &'static str, value: i64) -> Result<u64, CheckpointStoreError> {
    u64::try_from(value)
        .map_err(|_| CheckpointStoreError::Corrupt(format!("列 `{column}` 是负数：{value}")))
}
