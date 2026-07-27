//! Agent Bundle 的本地隔离状态与文件清单。
//!
//! 与 [`crate::checkpoints`]、[`crate::rotation`] 的分工完全一致：**本模块不做判定**。
//! 状态机是否允许某次迁移、批准是否覆盖新版本、签名是否有效，全部在
//! `envsync_core::bundles` 里；这里只负责把结论落盘并原样读回。
//!
//! # 为什么记录里没有 Bundle 的内容
//!
//! Bundle 的文件躺在不可执行的 quarantine 根下，由 `envsync_core::bundles` 写入。
//! 数据库里只有「本机对这个 Bundle 的信任决定」：状态、批准过的能力集、发布者公钥、
//! 阻断原因，以及一份文件路径到摘要的清单。因此这张表即使被完整读走也不泄露秘密
//! ——`publisher_key` 是公钥，能力名是标识，`blocked_reason` 只放结构化描述。
//!
//! # 批准记录的是四元组，不是一个布尔值
//!
//! [`BundleRecord::approved_capabilities`] 存的是**批准当时** manifest 声明的能力集。
//! Bundle 升级后 manifest 摘要必然变化，新版本可能多声明几项能力；只记「已批准」这
//! 一个布尔值的话，新增能力会随升级静默生效。存下当时的集合，升级时才能算出差集并
//! 要求重新审核（判定在 `envsync_core::bundles::review_update`）。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use envsync_domain::agent_bundle::{BundleId, BundleState};
use envsync_domain::id::Digest32;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};

use crate::journal::JournalError;
use crate::migrations::{self, StorageDiagnostics};

/// Bundle 存储错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BundleStoreError {
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
    #[error("Bundle 记录损坏：{0}")]
    Corrupt(String),
}

impl BundleStoreError {
    /// 稳定的机器可读错误码，用于 CLI 的 JSON 契约。
    ///
    /// 这些字符串属于对外契约的一部分，只能新增、不能重命名。
    pub fn code(&self) -> &'static str {
        match self {
            BundleStoreError::Sqlite { .. } => "bundle_store.sqlite",
            BundleStoreError::Storage { .. } => "bundle_store.storage",
            BundleStoreError::OutOfRange { .. } => "bundle_store.out_of_range",
            BundleStoreError::Corrupt { .. } => "bundle_store.corrupt",
        }
    }
}

/// 一个 Bundle 在本机的完整信任记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleRecord {
    /// Bundle 标识。
    pub bundle: BundleId,
    /// 当前记录对应的 Bundle 版本（semver 文本）。
    pub version: String,
    /// canonical manifest 的域分隔摘要。
    pub manifest_digest: Digest32,
    /// 发布者 Ed25519 公钥。
    pub publisher_key: [u8; 32],
    /// 隔离状态。
    pub state: BundleState,
    /// 批准当时 manifest 声明的能力集合。
    pub approved_capabilities: BTreeSet<String>,
    /// 批准时刻（Unix 毫秒）；从未批准时为 `None`。
    pub approved_at_unix_ms: Option<u64>,
    /// 阻断原因；未被阻断时为 `None`。
    pub blocked_reason: Option<String>,
    /// 最近一次写入时刻（Unix 毫秒）。
    pub updated_at_unix_ms: u64,
}

impl BundleRecord {
    /// 构造一条刚下载、尚未校验的记录。
    pub fn downloaded(
        bundle: BundleId,
        version: impl Into<String>,
        manifest_digest: Digest32,
        publisher_key: [u8; 32],
        now_unix_ms: u64,
    ) -> Self {
        BundleRecord {
            bundle,
            version: version.into(),
            manifest_digest,
            publisher_key,
            state: BundleState::Downloaded,
            approved_capabilities: BTreeSet::new(),
            approved_at_unix_ms: None,
            blocked_reason: None,
            updated_at_unix_ms: now_unix_ms,
        }
    }

    /// 该记录是否已经在影响 AI 工具的行为。
    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }
}

/// Bundle 存储。
///
/// 与 [`crate::journal::Journal`] 等共用同一套 schema，可以指向同一个数据库文件。
#[derive(Debug)]
pub struct BundleStore {
    connection: Connection,
    path: PathBuf,
}

impl BundleStore {
    /// 打开（必要时创建）存储所在的数据库文件。
    pub fn open(path: impl AsRef<Path>) -> Result<Self, BundleStoreError> {
        let path = path.as_ref().to_path_buf();
        let connection = migrations::open_database(&path)?;
        Ok(BundleStore { connection, path })
    }

    /// 数据库文件路径。
    pub fn database_path(&self) -> &Path {
        &self.path
    }

    /// 连接层诊断（PRAGMA 与 schema 版本）。
    pub fn diagnostics(&self) -> Result<StorageDiagnostics, BundleStoreError> {
        Ok(migrations::read_diagnostics(&self.connection)?)
    }

    /// 写入（覆盖）一个 Bundle 的记录与文件清单。
    ///
    /// 记录与清单在**同一个事务**里更新：两者分开写会留下「状态说是新版本、清单还是
    /// 旧版本」的中间态，而完整性校验恰恰要靠清单，读到中间态会给出错误的结论。
    ///
    /// **不做**任何状态合法性判定：那是 `envsync_core::bundles` 的职责。
    pub fn upsert(
        &mut self,
        record: &BundleRecord,
        files: &BTreeMap<String, Digest32>,
    ) -> Result<(), BundleStoreError> {
        let capabilities = encode_set(&record.approved_capabilities)?;
        let approved_at = match record.approved_at_unix_ms {
            Some(value) => Some(to_i64("approved_at", value)?),
            None => None,
        };
        let updated_at = to_i64("updated_at_unix_ms", record.updated_at_unix_ms)?;

        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO bundles (
                 bundle_id, version, manifest_digest, publisher_key, state,
                 approved_capabilities, approved_at, blocked_reason, updated_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (bundle_id) DO UPDATE SET
                 version = excluded.version,
                 manifest_digest = excluded.manifest_digest,
                 publisher_key = excluded.publisher_key,
                 state = excluded.state,
                 approved_capabilities = excluded.approved_capabilities,
                 approved_at = excluded.approved_at,
                 blocked_reason = excluded.blocked_reason,
                 updated_at_unix_ms = excluded.updated_at_unix_ms",
            params![
                record.bundle.as_str(),
                record.version,
                record.manifest_digest.to_hex(),
                hex32(&record.publisher_key),
                record.state.as_str(),
                capabilities,
                approved_at,
                record.blocked_reason,
                updated_at,
            ],
        )?;
        // 先删后插：清单是**全量替换**语义。逐条 upsert 会让旧版本里存在、新版本里
        // 已删除的文件留在表里，完整性校验随之把「多出来的文件」当成正常内容。
        transaction.execute(
            "DELETE FROM bundle_files WHERE bundle_id = ?1",
            params![record.bundle.as_str()],
        )?;
        {
            let mut statement = transaction.prepare(
                "INSERT INTO bundle_files (bundle_id, path, digest) VALUES (?1, ?2, ?3)",
            )?;
            for (path, digest) in files {
                statement.execute(params![record.bundle.as_str(), path, digest.to_hex()])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// 读取一个 Bundle 的记录；从未见过时返回 `None`。
    pub fn get(&self, bundle: &BundleId) -> Result<Option<BundleRecord>, BundleStoreError> {
        self.connection
            .query_row(
                "SELECT bundle_id, version, manifest_digest, publisher_key, state,
                        approved_capabilities, approved_at, blocked_reason, updated_at_unix_ms
                 FROM bundles WHERE bundle_id = ?1",
                params![bundle.as_str()],
                row_to_record,
            )
            .optional()?
            .transpose()
    }

    /// 读取一个 Bundle 的文件清单，按路径升序。
    pub fn files(&self, bundle: &BundleId) -> Result<BTreeMap<String, Digest32>, BundleStoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT path, digest FROM bundle_files WHERE bundle_id = ?1 ORDER BY path")?;
        let rows = statement.query_map(params![bundle.as_str()], |row| {
            let path: String = row.get(0)?;
            let digest: String = row.get(1)?;
            Ok((path, digest))
        })?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (path, digest) = row?;
            out.insert(path, parse_digest("digest", &digest)?);
        }
        Ok(out)
    }

    /// 列出全部记录，按 Bundle 标识升序。
    pub fn list(&self) -> Result<Vec<BundleRecord>, BundleStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT bundle_id, version, manifest_digest, publisher_key, state,
                    approved_capabilities, approved_at, blocked_reason, updated_at_unix_ms
             FROM bundles ORDER BY bundle_id",
        )?;
        let rows = statement.query_map([], row_to_record)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// 列出处于某个状态的全部记录，按 Bundle 标识升序。
    ///
    /// 这是「哪些 Bundle 正在生效」这个审计问题的直接答案。
    pub fn list_by_state(&self, state: BundleState) -> Result<Vec<BundleRecord>, BundleStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT bundle_id, version, manifest_digest, publisher_key, state,
                    approved_capabilities, approved_at, blocked_reason, updated_at_unix_ms
             FROM bundles WHERE state = ?1 ORDER BY bundle_id",
        )?;
        let rows = statement.query_map(params![state.as_str()], row_to_record)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// 列出某个发布者签过的全部 Bundle。
    ///
    /// 撤销一把发布者密钥时需要一次性找出全部受影响项——遗漏一个就等于撤销没生效。
    pub fn list_by_publisher(
        &self,
        publisher_key: &[u8; 32],
    ) -> Result<Vec<BundleRecord>, BundleStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT bundle_id, version, manifest_digest, publisher_key, state,
                    approved_capabilities, approved_at, blocked_reason, updated_at_unix_ms
             FROM bundles WHERE publisher_key = ?1 ORDER BY bundle_id",
        )?;
        let rows = statement.query_map(params![hex32(publisher_key)], row_to_record)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// 删除一个 Bundle 的记录与文件清单。
    ///
    /// 只应该在用户明确要求「彻底忘掉这个 Bundle」时出现：删掉之后本机就不再记得它
    /// 曾被撤销过，同一份内容重新出现时会当作全新 Bundle 走一遍流程。
    pub fn delete(&self, bundle: &BundleId) -> Result<bool, BundleStoreError> {
        let removed = self.connection.execute(
            "DELETE FROM bundles WHERE bundle_id = ?1",
            params![bundle.as_str()],
        )?;
        if removed > 0 {
            tracing::warn!(
                bundle = bundle.as_str(),
                "Bundle 记录已删除：本机不再记得它的隔离历史"
            );
        }
        Ok(removed > 0)
    }
}

/// 把字符串集合编成 JSON 数组文本。
fn encode_set(items: &BTreeSet<String>) -> Result<String, BundleStoreError> {
    serde_json::to_string(items)
        .map_err(|error| BundleStoreError::Corrupt(format!("能力集合无法编码：{error}")))
}

/// 从 JSON 数组文本还原字符串集合。
fn decode_set(column: &'static str, text: &str) -> Result<BTreeSet<String>, BundleStoreError> {
    serde_json::from_str(text)
        .map_err(|error| BundleStoreError::Corrupt(format!("列 `{column}` 非法：{error}")))
}

/// 32 字节的小写十六进制表示。
fn hex32(bytes: &[u8; 32]) -> String {
    Digest32::from_bytes(*bytes).to_hex()
}

/// 解析 64 位小写十六进制摘要。
fn parse_digest(column: &'static str, text: &str) -> Result<Digest32, BundleStoreError> {
    text.parse::<Digest32>()
        .map_err(|error| BundleStoreError::Corrupt(format!("列 `{column}` 非法：{error}")))
}

/// 把 `u64` 转成 SQLite 的有符号 64 位整数，越界时报错而不是静默钳制。
fn to_i64(field: &'static str, value: u64) -> Result<i64, BundleStoreError> {
    i64::try_from(value).map_err(|_| BundleStoreError::OutOfRange { field, value })
}

fn from_i64(column: &'static str, value: i64) -> Result<u64, BundleStoreError> {
    u64::try_from(value)
        .map_err(|_| BundleStoreError::Corrupt(format!("列 `{column}` 是负数：{value}")))
}

/// 把一行结果映射为 [`BundleRecord`]。
fn row_to_record(row: &Row<'_>) -> rusqlite::Result<Result<BundleRecord, BundleStoreError>> {
    let bundle_id: String = row.get(0)?;
    let version: String = row.get(1)?;
    let manifest_digest: String = row.get(2)?;
    let publisher_key: String = row.get(3)?;
    let state: String = row.get(4)?;
    let approved_capabilities: String = row.get(5)?;
    let approved_at: Option<i64> = row.get(6)?;
    let blocked_reason: Option<String> = row.get(7)?;
    let updated_at_unix_ms: i64 = row.get(8)?;

    Ok((|| {
        let approved_at_unix_ms = match approved_at {
            Some(value) => Some(from_i64("approved_at", value)?),
            None => None,
        };
        Ok(BundleRecord {
            bundle: BundleId::parse(&bundle_id).map_err(|error| {
                BundleStoreError::Corrupt(format!("Bundle 标识 `{bundle_id}` 非法：{error}"))
            })?,
            version,
            manifest_digest: parse_digest("manifest_digest", &manifest_digest)?,
            publisher_key: *parse_digest("publisher_key", &publisher_key)?.as_bytes(),
            state: BundleState::parse(&state)
                .ok_or_else(|| BundleStoreError::Corrupt(format!("Bundle 状态 `{state}` 未知")))?,
            approved_capabilities: decode_set("approved_capabilities", &approved_capabilities)?,
            approved_at_unix_ms,
            blocked_reason,
            updated_at_unix_ms: from_i64("updated_at_unix_ms", updated_at_unix_ms)?,
        })
    })())
}
