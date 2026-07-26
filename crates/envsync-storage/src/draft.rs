//! 本地草稿对象存储。
//!
//! `capture` 会产生 Blob、State Root 和 Snapshot。这些对象在用户真正决定发布之前
//! **不应该**进入 Backend：Backend 是共享的内容寻址存储，一旦写进去就是不可变的，
//! 未发布的试验性内容会永久留在那里，还会被其他设备的 GC 与审计看到。
//!
//! 因此草稿先落在本地：与 journal 同一个 SQLite schema 中的 `objects`、`plans` 和
//! `draft_meta` 三张表。发布时才把缺失对象上传到 Backend 并执行 CAS。
//!
//! ## 完整性
//!
//! 草稿库同样是内容寻址的，因此两端都校验：
//!
//! * [`DraftStore::put`] 校验字节确实产生给定的 [`ObjectId`]，不符直接拒绝写入；
//! * [`DraftStore::get`] 读出后**重新**计算摘要，不符返回
//!   [`DraftError::Corruption`] 而不是把脏数据交出去。
//!
//! 这样即使数据库文件被外部工具改坏或磁盘位翻转，损坏也不会静默传播到用户文件。

use std::path::{Path, PathBuf};

use envsync_domain::cbor::{CborCodec, CborError};
use envsync_domain::id::{PlanId, SnapshotId};
use envsync_domain::object::ObjectId;
use envsync_domain::plan::Plan;
use rusqlite::{params, Connection, OptionalExtension};

use crate::journal::JournalError;
use crate::migrations::{self, StorageDiagnostics};

/// 草稿库在给定目录下使用的数据库文件名。
pub const DATABASE_FILE_NAME: &str = "draft.db";

/// `draft_meta` 中记录本地草稿头的键名。
const HEAD_DRAFT_KEY: &str = "head_draft";

/// 草稿存储错误。
#[derive(Debug, thiserror::Error)]
pub enum DraftError {
    /// 底层 SQLite 错误。
    #[error("SQLite 错误：{0}")]
    Sqlite(#[from] rusqlite::Error),
    /// 打开数据库或迁移 schema 失败。
    #[error(transparent)]
    Storage(#[from] JournalError),
    /// canonical CBOR 编解码失败。
    #[error("CBOR 编解码失败：{0}")]
    Cbor(#[from] CborError),
    /// 写入时给定的标识与内容不符。
    #[error("对象 {object} 的内容与标识不符，拒绝写入")]
    DigestMismatch {
        /// 被拒绝的对象标识。
        object: String,
    },
    /// 读取时发现存储内容已损坏。
    #[error("对象 {object} 在草稿库中已损坏：重新计算的摘要与标识不符")]
    Corruption {
        /// 损坏的对象标识。
        object: String,
    },
    /// 数据库中存在无法解释的值。
    #[error("草稿库数据损坏：{0}")]
    Corrupt(String),
}

impl DraftError {
    /// 稳定的机器可读错误码，用于 CLI 的 JSON 契约与退出码判定。
    ///
    /// 这些字符串属于对外契约的一部分，只能新增、不能重命名。
    pub fn code(&self) -> &'static str {
        match self {
            DraftError::Sqlite { .. } => "draft.sqlite",
            DraftError::Storage { .. } => "draft.storage",
            DraftError::Cbor { .. } => "draft.cbor",
            DraftError::DigestMismatch { .. } => "draft.digest_mismatch",
            DraftError::Corruption { .. } => "draft.corruption",
            DraftError::Corrupt { .. } => "draft.corrupt",
        }
    }
}

/// 本地草稿对象存储。
///
/// 与 [`crate::journal::Journal`] 共用同一套 schema，因此可以指向同一个数据库文件；
/// 两者的表互不重叠，同时打开互不干扰。
#[derive(Debug)]
pub struct DraftStore {
    connection: Connection,
    path: PathBuf,
}

impl DraftStore {
    /// 在给定目录下打开（必要时创建）草稿库。
    ///
    /// 目录不存在时会被创建；数据库文件名见 [`DATABASE_FILE_NAME`]。
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, DraftError> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir).map_err(JournalError::from)?;
        DraftStore::open_database(dir.join(DATABASE_FILE_NAME))
    }

    /// 直接打开指定的数据库文件。
    pub fn open_database(path: impl AsRef<Path>) -> Result<Self, DraftError> {
        let path = path.as_ref().to_path_buf();
        let connection = migrations::open_database(&path)?;
        Ok(DraftStore { connection, path })
    }

    /// 数据库文件路径。
    pub fn database_path(&self) -> &Path {
        &self.path
    }

    /// 连接层诊断（PRAGMA 与 schema 版本）。
    pub fn diagnostics(&self) -> Result<StorageDiagnostics, DraftError> {
        Ok(migrations::read_diagnostics(&self.connection)?)
    }

    /// 写入一个草稿对象。
    ///
    /// 先校验 `bytes` 确实产生 `id`，不符返回 [`DraftError::DigestMismatch`]。
    /// 内容寻址意味着同一标识永远对应同一内容，因此重复写入是幂等的。
    pub fn put(&self, id: ObjectId, bytes: &[u8]) -> Result<(), DraftError> {
        if !id.verifies(bytes) {
            return Err(DraftError::DigestMismatch {
                object: id.to_string(),
            });
        }
        // 用 REPLACE 而不是 IGNORE：若已有行因外部改动而损坏，写入应当把它修复。
        self.connection.execute(
            "INSERT INTO objects (object_id, bytes) VALUES (?1, ?2) \
             ON CONFLICT (object_id) DO UPDATE SET bytes = excluded.bytes",
            params![id.to_string(), bytes],
        )?;
        tracing::debug!(object = %id, size = bytes.len(), "已写入草稿对象");
        Ok(())
    }

    /// 读取一个草稿对象；不存在返回 `None`。
    ///
    /// 读出后重新校验摘要，损坏时返回 [`DraftError::Corruption`]。
    pub fn get(&self, id: ObjectId) -> Result<Option<Vec<u8>>, DraftError> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT bytes FROM objects WHERE object_id = ?1",
                params![id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        match bytes {
            None => Ok(None),
            Some(bytes) if id.verifies(&bytes) => Ok(Some(bytes)),
            Some(_) => Err(DraftError::Corruption {
                object: id.to_string(),
            }),
        }
    }

    /// 判断对象是否存在（不校验内容）。
    pub fn has(&self, id: ObjectId) -> Result<bool, DraftError> {
        let found: Option<i64> = self
            .connection
            .query_row(
                "SELECT 1 FROM objects WHERE object_id = ?1",
                params![id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// 列出全部草稿对象标识，按文本表示升序。
    pub fn list(&self) -> Result<Vec<ObjectId>, DraftError> {
        let mut statement = self
            .connection
            .prepare("SELECT object_id FROM objects ORDER BY object_id")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::new();
        for row in rows {
            let text = row?;
            let id = text.parse::<ObjectId>().map_err(|error| {
                DraftError::Corrupt(format!("无法解析对象标识 `{text}`：{error}"))
            })?;
            ids.push(id);
        }
        Ok(ids)
    }

    /// 保存一个草稿计划，返回其标识。
    ///
    /// 计划以 canonical CBOR 存放，键为 [`PlanId`]；同一计划重复保存是幂等的。
    pub fn put_plan(&self, plan: &Plan) -> Result<PlanId, DraftError> {
        let id = plan.id();
        let bytes = plan.to_canonical_vec();
        self.connection.execute(
            "INSERT INTO plans (plan_id, bytes) VALUES (?1, ?2) \
             ON CONFLICT (plan_id) DO UPDATE SET bytes = excluded.bytes",
            params![id.to_string(), bytes],
        )?;
        tracing::debug!(plan = %id, actions = plan.actions.len(), "已保存草稿计划");
        Ok(id)
    }

    /// 读取草稿计划；不存在返回 `None`。
    ///
    /// 解码后重新计算计划标识，不符返回 [`DraftError::Corruption`]。
    pub fn get_plan(&self, id: PlanId) -> Result<Option<Plan>, DraftError> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT bytes FROM plans WHERE plan_id = ?1",
                params![id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        let plan = Plan::from_canonical_slice(&bytes)?;
        if plan.id() != id {
            return Err(DraftError::Corruption {
                object: id.to_string(),
            });
        }
        Ok(Some(plan))
    }

    /// 列出全部草稿计划标识，按文本表示升序。
    pub fn list_plans(&self) -> Result<Vec<PlanId>, DraftError> {
        let mut statement = self
            .connection
            .prepare("SELECT plan_id FROM plans ORDER BY plan_id")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::new();
        for row in rows {
            let text = row?;
            let id = text.parse::<PlanId>().map_err(|error| {
                DraftError::Corrupt(format!("无法解析计划标识 `{text}`：{error}"))
            })?;
            ids.push(id);
        }
        Ok(ids)
    }

    /// 设置本地草稿头快照。
    ///
    /// 草稿头**不是**工作区 Ref：它只表示“本机最近一次 capture 得到的快照”，
    /// 在发布之前对其他设备完全不可见。
    pub fn set_head_draft(&self, snapshot: SnapshotId) -> Result<(), DraftError> {
        self.connection.execute(
            "INSERT INTO draft_meta (key, value) VALUES (?1, ?2) \
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![HEAD_DRAFT_KEY, snapshot.to_string()],
        )?;
        Ok(())
    }

    /// 读取本地草稿头快照；从未设置过时返回 `None`。
    pub fn head_draft(&self) -> Result<Option<SnapshotId>, DraftError> {
        let raw: Option<String> = self
            .connection
            .query_row(
                "SELECT value FROM draft_meta WHERE key = ?1",
                params![HEAD_DRAFT_KEY],
                |row| row.get(0),
            )
            .optional()?;
        raw.map(|text| {
            text.parse::<SnapshotId>()
                .map_err(|error| DraftError::Corrupt(format!("无法解析草稿头 `{text}`：{error}")))
        })
        .transpose()
    }

    /// 清除本地草稿头。
    pub fn clear_head_draft(&self) -> Result<(), DraftError> {
        self.connection.execute(
            "DELETE FROM draft_meta WHERE key = ?1",
            params![HEAD_DRAFT_KEY],
        )?;
        Ok(())
    }
}
