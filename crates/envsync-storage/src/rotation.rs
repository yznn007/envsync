//! 密钥轮换 journal：让被中断的轮换可以**幂等恢复**。
//!
//! 撤销一台设备会把工作区的密钥纪元从 `n` 推到 `n+1`，这需要四个互相依赖的副作用：
//!
//! ```text
//! prepared → envelopes_published → head_published → rewrapping → complete
//! ```
//!
//! 进程可能在任何两步之间被杀死。本模块只负责**记住做到哪儿了**；判定与副作用都在
//! `envsync_core::rotation` 里，理由与 [`crate::checkpoints`] 相同——判定散落到存储
//! 实现里只会产生互不一致的安全边界。
//!
//! # 阶段顺序是安全约束
//!
//! `envelopes_published` **必须**早于 `head_published`。新头一旦发布，工作区的纪元就
//! 是 `n+1` 了；此时信封若还没发布，剩余设备拿不到新纪元的数据密钥，而这个状态是后端
//! 上的既成事实，重试也无法自愈。反过来「信封发布了、新头还没发」完全安全：多出来的
//! 信封只是几个没人引用的不可变对象，下次恢复原样复用。
//!
//! # 为什么要记 `event_created_at_unix_ms`
//!
//! 成员事件的签名覆盖创建时刻。若恢复时用「当前时间」重新构造事件，就会签出一条字节
//! 不同、摘要也不同的事件——链头随之改变，先前发布的对象全部失效。把时刻固定在
//! journal 里，重放才能得到**字节完全相同**的事件，从而让「重复发布」退化成一次幂等
//! 的对象写入。

use std::path::{Path, PathBuf};

use envsync_domain::id::{DeviceId, WorkspaceId};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};

use crate::journal::JournalError;
use crate::migrations::{self, StorageDiagnostics};

/// 轮换 journal 的错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RotationStoreError {
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
    #[error("轮换记录损坏：{0}")]
    Corrupt(String),
}

impl RotationStoreError {
    /// 稳定的机器可读错误码，用于 CLI 的 JSON 契约。
    ///
    /// 这些字符串属于对外契约的一部分，只能新增、不能重命名。
    pub fn code(&self) -> &'static str {
        match self {
            RotationStoreError::Sqlite { .. } => "rotation_store.sqlite",
            RotationStoreError::Storage { .. } => "rotation_store.storage",
            RotationStoreError::OutOfRange { .. } => "rotation_store.out_of_range",
            RotationStoreError::Corrupt { .. } => "rotation_store.corrupt",
        }
    }
}

/// 轮换所处的阶段。
///
/// 变体顺序即推进顺序，[`Ord`] 因此可以直接用来比较「谁更靠后」。字符串形式是持久化
/// 契约（写进 SQLite 的 `stage` 列并被 `CHECK` 约束限定），**只能新增、不能重命名**。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStage {
    /// 已生成新纪元的数据密钥并写入安全存储，后端上还什么都没有。
    Prepared,
    /// 每个剩余设备的信封都已写进后端。
    EnvelopesPublished,
    /// 推进纪元的成员事件与新快照头都已发布。
    HeadPublished,
    /// 正在把旧纪元的秘密逐条重加密。
    Rewrapping,
    /// 轮换完成。
    Complete,
}

impl RotationStage {
    /// 全部阶段，按推进顺序排列。
    pub const ALL: [RotationStage; 5] = [
        RotationStage::Prepared,
        RotationStage::EnvelopesPublished,
        RotationStage::HeadPublished,
        RotationStage::Rewrapping,
        RotationStage::Complete,
    ];

    /// 稳定的持久化短名。
    pub const fn as_str(self) -> &'static str {
        match self {
            RotationStage::Prepared => "prepared",
            RotationStage::EnvelopesPublished => "envelopes_published",
            RotationStage::HeadPublished => "head_published",
            RotationStage::Rewrapping => "rewrapping",
            RotationStage::Complete => "complete",
        }
    }

    /// 由短名解析；未知取值返回 `None`（调用方必须拒绝，绝不静默当成某个阶段）。
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "prepared" => RotationStage::Prepared,
            "envelopes_published" => RotationStage::EnvelopesPublished,
            "head_published" => RotationStage::HeadPublished,
            "rewrapping" => RotationStage::Rewrapping,
            "complete" => RotationStage::Complete,
            _ => return None,
        })
    }

    /// 推进顺序中的下一个阶段；[`RotationStage::Complete`] 没有下一个。
    pub fn next(self) -> Option<Self> {
        match self {
            RotationStage::Prepared => Some(RotationStage::EnvelopesPublished),
            RotationStage::EnvelopesPublished => Some(RotationStage::HeadPublished),
            RotationStage::HeadPublished => Some(RotationStage::Rewrapping),
            RotationStage::Rewrapping => Some(RotationStage::Complete),
            RotationStage::Complete => None,
        }
    }

    /// 新头是否已经发布到后端。
    ///
    /// 「新头是否已存在」是判断能否安全重放的关键：未发布之前，后端上不能出现任何指向
    /// 新纪元的引用。
    pub fn head_is_published(self) -> bool {
        self >= RotationStage::HeadPublished
    }

    /// 是否已经结束。
    pub fn is_terminal(self) -> bool {
        matches!(self, RotationStage::Complete)
    }
}

impl std::fmt::Display for RotationStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 一次轮换的完整记录。
///
/// 这里**没有任何私有材料**：新纪元的数据密钥在系统安全存储里，本表只记录「哪个纪元、
/// 发给谁、发到哪一步」。因此这张表即使被完整读走，也不会泄露任何秘密。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationRecord {
    /// 工作区标识。
    pub workspace: WorkspaceId,
    /// 轮换前的密钥纪元。
    pub from_epoch: u64,
    /// 轮换后的密钥纪元，恒为 `from_epoch + 1`。
    pub to_epoch: u64,
    /// 被撤销的设备。
    pub revoked_device: DeviceId,
    /// 当前阶段。
    pub stage: RotationStage,
    /// 剩余 active 设备，即新信封的收件人。
    pub recipients: Vec<DeviceId>,
    /// 已写进后端的信封对象标识（`kind/digest` 文本形式）。
    pub envelopes: Vec<String>,
    /// 尚未用新密钥重加密的秘密逻辑标识。
    pub pending_rewrap: Vec<String>,
    /// 撤销事件的创建时刻；固定它才能让重放签出字节相同的事件。
    pub event_created_at_unix_ms: u64,
    /// 轮换发起时刻（Unix 毫秒）。
    pub started_at_unix_ms: u64,
    /// 最近一次推进时刻（Unix 毫秒）。
    pub updated_at_unix_ms: u64,
}

/// 轮换 journal。
///
/// 与 [`crate::journal::Journal`] 等共用同一套 schema，可以指向同一个数据库文件。
#[derive(Debug)]
pub struct RotationJournal {
    connection: Connection,
    path: PathBuf,
}

impl RotationJournal {
    /// 打开（必要时创建）journal 所在的数据库文件。
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RotationStoreError> {
        let path = path.as_ref().to_path_buf();
        let connection = migrations::open_database(&path)?;
        Ok(RotationJournal { connection, path })
    }

    /// 数据库文件路径。
    pub fn database_path(&self) -> &Path {
        &self.path
    }

    /// 连接层诊断（PRAGMA 与 schema 版本）。
    pub fn diagnostics(&self) -> Result<StorageDiagnostics, RotationStoreError> {
        Ok(migrations::read_diagnostics(&self.connection)?)
    }

    /// 无条件写入（覆盖）一个工作区的轮换记录。
    ///
    /// **不做**任何阶段合法性判定：那是 `envsync_core::rotation` 的职责。这里做的只是
    /// 「把当前进度落盘」这一件事，并且必须在对应的副作用**完成之后**调用——顺序反过来
    /// 会让 journal 声称某一步已经做完，而后端上其实什么都没有。
    pub fn upsert(&self, record: &RotationRecord) -> Result<(), RotationStoreError> {
        self.connection.execute(
            "INSERT INTO rotations (
                 workspace_id, from_epoch, to_epoch, revoked_device, stage,
                 recipients, envelopes, pending_rewrap,
                 event_created_at_unix_ms, started_at_unix_ms, updated_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT (workspace_id) DO UPDATE SET
                 from_epoch = excluded.from_epoch,
                 to_epoch = excluded.to_epoch,
                 revoked_device = excluded.revoked_device,
                 stage = excluded.stage,
                 recipients = excluded.recipients,
                 envelopes = excluded.envelopes,
                 pending_rewrap = excluded.pending_rewrap,
                 event_created_at_unix_ms = excluded.event_created_at_unix_ms,
                 started_at_unix_ms = excluded.started_at_unix_ms,
                 updated_at_unix_ms = excluded.updated_at_unix_ms",
            params![
                record.workspace.to_string(),
                to_i64("from_epoch", record.from_epoch)?,
                to_i64("to_epoch", record.to_epoch)?,
                record.revoked_device.to_hex(),
                record.stage.as_str(),
                encode_list(&device_hexes(&record.recipients))?,
                encode_list(&record.envelopes)?,
                encode_list(&record.pending_rewrap)?,
                to_i64("event_created_at_unix_ms", record.event_created_at_unix_ms)?,
                to_i64("started_at_unix_ms", record.started_at_unix_ms)?,
                to_i64("updated_at_unix_ms", record.updated_at_unix_ms)?,
            ],
        )?;
        Ok(())
    }

    /// 读取某个工作区的轮换记录；从未轮换过时返回 `None`。
    pub fn get(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Option<RotationRecord>, RotationStoreError> {
        self.connection
            .query_row(
                "SELECT workspace_id, from_epoch, to_epoch, revoked_device, stage,
                        recipients, envelopes, pending_rewrap,
                        event_created_at_unix_ms, started_at_unix_ms, updated_at_unix_ms
                 FROM rotations WHERE workspace_id = ?1",
                params![workspace.to_string()],
                row_to_record,
            )
            .optional()?
            .transpose()
    }

    /// 读取尚未完成的轮换记录。
    ///
    /// 这是恢复流程的入口：任何需要用到新纪元的操作都应当先问一句「上一次轮换做完了
    /// 吗」，而不是假设它做完了。
    pub fn get_unfinished(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Option<RotationRecord>, RotationStoreError> {
        Ok(self
            .get(workspace)?
            .filter(|record| !record.stage.is_terminal()))
    }

    /// 列出全部轮换记录，按工作区标识升序。
    pub fn list(&self) -> Result<Vec<RotationRecord>, RotationStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT workspace_id, from_epoch, to_epoch, revoked_device, stage,
                    recipients, envelopes, pending_rewrap,
                    event_created_at_unix_ms, started_at_unix_ms, updated_at_unix_ms
             FROM rotations ORDER BY workspace_id",
        )?;
        let rows = statement.query_map([], row_to_record)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// 删除某个工作区的轮换记录。
    ///
    /// 只应该在灾难恢复里出现：删掉之后本机就再也不知道上一次轮换做到哪儿了，只能靠
    /// 后端上的对象反推。
    pub fn delete(&self, workspace: WorkspaceId) -> Result<(), RotationStoreError> {
        self.connection.execute(
            "DELETE FROM rotations WHERE workspace_id = ?1",
            params![workspace.to_string()],
        )?;
        tracing::warn!(
            workspace = %workspace,
            "密钥轮换 journal 已被删除：中断的轮换将无法按记录恢复"
        );
        Ok(())
    }
}

/// 设备标识的十六进制形式列表。
fn device_hexes(devices: &[DeviceId]) -> Vec<String> {
    devices.iter().map(|device| device.to_hex()).collect()
}

/// 把字符串列表编成 JSON 文本。
///
/// 用 JSON 而不是逗号拼接：设备标识和对象标识都是受控字符集，但「受控」是当下的实现
/// 细节，把它变成分隔符协议的前提会在将来某次格式扩展时安静地崩塌。
fn encode_list(items: &[String]) -> Result<String, RotationStoreError> {
    serde_json::to_string(items)
        .map_err(|error| RotationStoreError::Corrupt(format!("列表无法编码：{error}")))
}

/// 从 JSON 文本还原字符串列表。
fn decode_list(column: &'static str, text: &str) -> Result<Vec<String>, RotationStoreError> {
    serde_json::from_str(text)
        .map_err(|error| RotationStoreError::Corrupt(format!("列 `{column}` 非法：{error}")))
}

/// 把 `u64` 转成 SQLite 的有符号 64 位整数，越界时报错而不是静默钳制。
fn to_i64(field: &'static str, value: u64) -> Result<i64, RotationStoreError> {
    i64::try_from(value).map_err(|_| RotationStoreError::OutOfRange { field, value })
}

fn from_i64(column: &'static str, value: i64) -> Result<u64, RotationStoreError> {
    u64::try_from(value)
        .map_err(|_| RotationStoreError::Corrupt(format!("列 `{column}` 是负数：{value}")))
}

/// 把一行结果映射为 [`RotationRecord`]。
fn row_to_record(row: &Row<'_>) -> rusqlite::Result<Result<RotationRecord, RotationStoreError>> {
    let workspace: String = row.get(0)?;
    let from_epoch: i64 = row.get(1)?;
    let to_epoch: i64 = row.get(2)?;
    let revoked_device: String = row.get(3)?;
    let stage: String = row.get(4)?;
    let recipients: String = row.get(5)?;
    let envelopes: String = row.get(6)?;
    let pending_rewrap: String = row.get(7)?;
    let event_created_at_unix_ms: i64 = row.get(8)?;
    let started_at_unix_ms: i64 = row.get(9)?;
    let updated_at_unix_ms: i64 = row.get(10)?;

    Ok((|| {
        let recipients = decode_list("recipients", &recipients)?
            .into_iter()
            .map(|hex| {
                hex.parse::<DeviceId>().map_err(|error| {
                    RotationStoreError::Corrupt(format!("设备标识 `{hex}` 非法：{error}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RotationRecord {
            workspace: workspace.parse::<WorkspaceId>().map_err(|error| {
                RotationStoreError::Corrupt(format!("工作区标识 `{workspace}` 非法：{error}"))
            })?,
            from_epoch: from_i64("from_epoch", from_epoch)?,
            to_epoch: from_i64("to_epoch", to_epoch)?,
            revoked_device: revoked_device.parse::<DeviceId>().map_err(|error| {
                RotationStoreError::Corrupt(format!("设备标识 `{revoked_device}` 非法：{error}"))
            })?,
            stage: RotationStage::parse(&stage)
                .ok_or_else(|| RotationStoreError::Corrupt(format!("轮换阶段 `{stage}` 未知")))?,
            recipients,
            envelopes: decode_list("envelopes", &envelopes)?,
            pending_rewrap: decode_list("pending_rewrap", &pending_rewrap)?,
            event_created_at_unix_ms: from_i64(
                "event_created_at_unix_ms",
                event_created_at_unix_ms,
            )?,
            started_at_unix_ms: from_i64("started_at_unix_ms", started_at_unix_ms)?,
            updated_at_unix_ms: from_i64("updated_at_unix_ms", updated_at_unix_ms)?,
        })
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(workspace: WorkspaceId) -> RotationRecord {
        RotationRecord {
            workspace,
            from_epoch: 1,
            to_epoch: 2,
            revoked_device: DeviceId::derive(b"revoked"),
            stage: RotationStage::Prepared,
            recipients: vec![DeviceId::derive(b"a"), DeviceId::derive(b"b")],
            envelopes: Vec::new(),
            pending_rewrap: vec!["ci/npm-token".to_owned()],
            event_created_at_unix_ms: 1_700_000_000_000,
            started_at_unix_ms: 1_700_000_000_000,
            updated_at_unix_ms: 1_700_000_000_000,
        }
    }

    fn journal() -> (tempfile::TempDir, RotationJournal) {
        let dir = tempfile::tempdir().expect("临时目录");
        let journal = RotationJournal::open(dir.path().join("rotation.db")).expect("打开 journal");
        (dir, journal)
    }

    #[test]
    fn stage_names_round_trip_and_are_ordered() {
        for stage in RotationStage::ALL {
            assert_eq!(RotationStage::parse(stage.as_str()), Some(stage));
        }
        assert_eq!(RotationStage::parse("unknown"), None);
        // 顺序即安全约束：信封必须早于新头。
        assert!(RotationStage::EnvelopesPublished < RotationStage::HeadPublished);
        assert!(!RotationStage::EnvelopesPublished.head_is_published());
        assert!(RotationStage::HeadPublished.head_is_published());
        assert!(RotationStage::Complete.is_terminal());
        assert_eq!(RotationStage::Complete.next(), None);
    }

    #[test]
    fn record_round_trips_through_sqlite() {
        let (_dir, journal) = journal();
        let workspace = WorkspaceId::generate();
        assert_eq!(journal.get(workspace).unwrap(), None);

        let mut first = record(workspace);
        journal.upsert(&first).unwrap();
        assert_eq!(journal.get(workspace).unwrap(), Some(first.clone()));
        assert_eq!(
            journal.get_unfinished(workspace).unwrap(),
            Some(first.clone())
        );

        first.stage = RotationStage::Complete;
        first.envelopes = vec!["envelope/aa".to_owned()];
        first.pending_rewrap.clear();
        journal.upsert(&first).unwrap();
        assert_eq!(journal.get(workspace).unwrap(), Some(first));
        // 已完成的轮换不再算「未完成」。
        assert_eq!(journal.get_unfinished(workspace).unwrap(), None);
        assert_eq!(journal.list().unwrap().len(), 1);

        journal.delete(workspace).unwrap();
        assert_eq!(journal.get(workspace).unwrap(), None);
    }

    #[test]
    fn unknown_stage_is_rejected_instead_of_guessed() {
        let (_dir, journal) = journal();
        let workspace = WorkspaceId::generate();
        journal.upsert(&record(workspace)).unwrap();
        journal
            .connection
            .execute(
                "UPDATE rotations SET stage = 'complete' WHERE workspace_id = ?1",
                params![workspace.to_string()],
            )
            .expect("CHECK 约束允许的取值");
        // 数据库的 CHECK 约束本身就拒绝未知阶段，这里确认它确实在生效。
        let error = journal.connection.execute(
            "UPDATE rotations SET stage = 'bogus' WHERE workspace_id = ?1",
            params![workspace.to_string()],
        );
        assert!(error.is_err(), "未知阶段必须被 CHECK 约束拒绝");
    }
}
