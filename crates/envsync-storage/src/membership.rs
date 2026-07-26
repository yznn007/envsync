//! 已验证成员链的本地索引与链头。
//!
//! ## 分工
//!
//! [`envsync_domain::membership::MembershipEvent`] 是**内容寻址的不可变对象**，完整
//! 的 canonical CBOR 存在 Backend 里（`ObjectKind::MembershipEvent`）。这里的两张表
//! 只保存「本机已经验证到哪儿了」这个**本地事实**：
//!
//! * `membership_events`：已验证事件的索引（位置、摘要、对象标识、动作与主体）；
//! * `membership_head`：每个工作区一行的已验证链头。
//!
//! 事件正文与签名刻意**不**落库：复制一份进关系表就会出现两个可能不一致的事实来源，
//! 而且会让人误以为可以「查表验签」。需要正文时按 `object_id` 去 Backend 取。
//!
//! ## 只写已验证的事件
//!
//! [`MembershipIndex::append_verified`] 的名字就是它的契约：调用方**必须**先用
//! `envsync_core::membership::verify_membership_chain` 验证过整条链，才允许写入。
//! 这一层再加一道结构性防线——写入必须是对当前链头的合法延伸：
//!
//! ```text
//! 没有链头  → 只接受 sequence 0 的 genesis
//! 有链头    → 只接受 sequence = head.sequence + 1 且 previous = head.digest 的事件
//! ```
//!
//! 插入事件行与更新链头在**同一个事务**里完成，不存在「事件写进去了、链头没动」的
//! 中间态。
//!
//! ## 这不是信任根
//!
//! 信任根（genesis 摘要与反回滚检查点）的权威副本在系统安全存储，见
//! `envsync_core::checkpoint`。这张表和 `checkpoints` 一样只是审计副本。

use std::path::{Path, PathBuf};

use envsync_domain::cbor::CborCodec;
use envsync_domain::id::{DeviceId, Digest32, WorkspaceId};
use envsync_domain::membership::MembershipEvent;
use envsync_domain::object::{ObjectId, ObjectKind};
use envsync_domain::unix_millis_now;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};

use crate::journal::JournalError;
use crate::migrations::{self, StorageDiagnostics};

/// 成员索引错误。
///
/// 所有变体都只描述结构性问题，不携带密钥材料或事件正文，可以安全写进日志。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MembershipStoreError {
    /// 底层 SQLite 错误。
    #[error("SQLite 错误：{0}")]
    Sqlite(#[from] rusqlite::Error),
    /// 打开数据库或迁移 schema 失败。
    #[error(transparent)]
    Storage(#[from] JournalError),
    /// 待写入的事件不是当前链头的合法延伸。
    #[error("事件 sequence {found} 不是当前链头（sequence {head}）的下一条")]
    NotSuccessor {
        /// 当前链头位置；尚无链头时为 `None`。
        head: SequenceDisplay,
        /// 待写入事件的位置。
        found: u64,
    },
    /// 待写入事件的 `previous` 与当前链头摘要不符。
    #[error("事件 sequence {sequence} 的 previous 摘要与当前链头不符")]
    ChainBroken {
        /// 待写入事件的位置。
        sequence: u64,
    },
    /// 事件本身结构非法。
    #[error("成员事件结构非法：{0}")]
    MalformedEvent(#[from] envsync_domain::membership::MembershipEventError),
    /// 数值超出 SQLite 有符号 64 位整数范围。
    #[error("字段 `{field}` 的值 {value} 超出 SQLite 整数范围")]
    OutOfRange {
        /// 字段名（静态字符串，不来自输入）。
        field: &'static str,
        /// 越界数值。
        value: u64,
    },
    /// 数据库中存在无法解释的值。
    #[error("成员索引数据损坏：{0}")]
    Corrupt(String),
}

impl MembershipStoreError {
    /// 稳定的机器可读错误码，用于 CLI 的 JSON 契约。
    ///
    /// 这些字符串属于对外契约的一部分，只能新增、不能重命名。
    pub fn code(&self) -> &'static str {
        match self {
            MembershipStoreError::Sqlite { .. } => "membership_store.sqlite",
            MembershipStoreError::Storage { .. } => "membership_store.storage",
            MembershipStoreError::NotSuccessor { .. } => "membership_store.not_successor",
            MembershipStoreError::ChainBroken { .. } => "membership_store.chain_broken",
            MembershipStoreError::MalformedEvent { .. } => "membership_store.malformed_event",
            MembershipStoreError::OutOfRange { .. } => "membership_store.out_of_range",
            MembershipStoreError::Corrupt { .. } => "membership_store.corrupt",
        }
    }
}

/// 「当前链头位置」的可显示包装：`None` 渲染成 `<空>`。
///
/// 单独造这个类型是为了让 [`MembershipStoreError`] 的 `#[error(...)]` 模板保持简单，
/// 同时避免在错误里塞一个 `Option<u64>` 之后被迫写 `{:?}`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequenceDisplay(pub Option<u64>);

impl std::fmt::Display for SequenceDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(value) => write!(f, "{value}"),
            None => f.write_str("<空>"),
        }
    }
}

/// 已验证链头。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipHead {
    /// 工作区标识。
    pub workspace: WorkspaceId,
    /// 链头摘要。
    pub digest: Digest32,
    /// 链头所在的 sequence。
    pub sequence: u64,
    /// 链头生效时的密钥纪元。
    pub epoch: u64,
    /// 本机完成验证的时刻（Unix 毫秒）。
    pub verified_at_unix_ms: i64,
}

/// 一条已验证事件的索引记录。
///
/// 刻意**不含**事件正文与签名，见模块文档。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipEventRecord {
    /// 工作区标识。
    pub workspace: WorkspaceId,
    /// 链上位置。
    pub sequence: u64,
    /// 事件摘要。
    pub digest: Digest32,
    /// 事件正文在 Backend 中的对象标识。
    pub object: ObjectId,
    /// 事件生效后的密钥纪元。
    pub epoch: u64,
    /// 签发设备。
    pub actor: DeviceId,
    /// 动作短名（`genesis` / `add_member` / `promote` / `revoke`）。
    pub action_kind: String,
    /// 动作作用的设备。
    pub subject: DeviceId,
    /// 事件创建时刻（Unix 毫秒）。
    pub created_at_unix_ms: i64,
}

/// 成员链的本地索引。
///
/// 与 [`crate::journal::Journal`]、[`crate::draft::DraftStore`]、
/// [`crate::conflicts::ConflictStore`] 共用同一套 schema，因此可以指向同一个数据库
/// 文件；它们的表互不重叠，同时打开互不干扰。
#[derive(Debug)]
pub struct MembershipIndex {
    connection: Connection,
    path: PathBuf,
}

impl MembershipIndex {
    /// 打开（必要时创建）成员索引所在的数据库文件。
    pub fn open(path: impl AsRef<Path>) -> Result<Self, MembershipStoreError> {
        let path = path.as_ref().to_path_buf();
        let connection = migrations::open_database(&path)?;
        Ok(MembershipIndex { connection, path })
    }

    /// 数据库文件路径。
    pub fn database_path(&self) -> &Path {
        &self.path
    }

    /// 连接层诊断（PRAGMA 与 schema 版本）。
    pub fn diagnostics(&self) -> Result<StorageDiagnostics, MembershipStoreError> {
        Ok(migrations::read_diagnostics(&self.connection)?)
    }

    /// 登记一条**已经通过链验证**的事件，并把链头推进到它。
    ///
    /// # 契约
    ///
    /// 调用方必须先用 `envsync_core::membership::verify_membership_chain` 验证过整条
    /// 链。本方法只做结构性防线：事件必须是当前链头的合法延伸（sequence 连续且
    /// `previous` 指向当前链头），否则返回
    /// [`MembershipStoreError::NotSuccessor`] 或 [`MembershipStoreError::ChainBroken`]。
    ///
    /// 插入事件行与更新链头在同一个事务里完成。重复登记**同一条**事件是幂等的
    /// （摘要与位置都相同时直接返回），这让「发布后崩溃、重启后重放」不需要特判。
    pub fn append_verified(
        &self,
        workspace: WorkspaceId,
        event: &MembershipEvent,
    ) -> Result<Digest32, MembershipStoreError> {
        self.append_verified_at(workspace, event, clamp_millis(unix_millis_now()))
    }

    /// 与 [`MembershipIndex::append_verified`] 相同，但由调用方给出验证时间。
    ///
    /// 存储层不依赖时钟；需要确定性的场景（测试、重放）用这个版本注入固定时间。
    pub fn append_verified_at(
        &self,
        workspace: WorkspaceId,
        event: &MembershipEvent,
        verified_at_unix_ms: i64,
    ) -> Result<Digest32, MembershipStoreError> {
        event.validate()?;
        let digest = event.digest();
        let head = self.head(workspace)?;

        // 幂等：完全相同的事件重复登记直接返回，不改动任何行。
        if let Some(current) = &head {
            if current.sequence == event.sequence && current.digest == digest {
                return Ok(digest);
            }
        }

        let expected = head.map_or(0, |current| current.sequence + 1);
        if event.sequence != expected {
            return Err(MembershipStoreError::NotSuccessor {
                head: SequenceDisplay(head.map(|current| current.sequence)),
                found: event.sequence,
            });
        }
        if event.previous != head.map(|current| current.digest) {
            return Err(MembershipStoreError::ChainBroken {
                sequence: event.sequence,
            });
        }

        let object = ObjectId::for_bytes(ObjectKind::MembershipEvent, &event.to_canonical_vec());
        let sequence = to_i64("sequence", event.sequence)?;
        let epoch = to_i64("epoch", event.epoch)?;
        let created_at = to_i64("created_at_unix_ms", event.created_at_unix_ms)?;

        // 事件行与链头必须原子地一起前进：守卫在提交前被丢弃时自动 ROLLBACK，
        // 因此下面任何一个 `?` 都会让数据库原封不动。
        let transaction = self.connection.unchecked_transaction()?;
        transaction.execute(
            "INSERT INTO membership_events (
                 workspace_id, sequence, event_digest, object_id, epoch,
                 actor, action_kind, subject, created_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                workspace.to_string(),
                sequence,
                digest.to_hex(),
                object.to_string(),
                epoch,
                event.actor.to_hex(),
                event.action.kind(),
                event.action.subject().to_hex(),
                created_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO membership_head (
                 workspace_id, head_digest, sequence, epoch, verified_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (workspace_id) DO UPDATE SET
                 head_digest = excluded.head_digest,
                 sequence = excluded.sequence,
                 epoch = excluded.epoch,
                 verified_at_unix_ms = excluded.verified_at_unix_ms",
            params![
                workspace.to_string(),
                digest.to_hex(),
                sequence,
                epoch,
                verified_at_unix_ms,
            ],
        )?;
        transaction.commit()?;
        tracing::debug!(
            workspace = %workspace,
            sequence = event.sequence,
            action = event.action.kind(),
            "已登记成员事件并推进链头"
        );
        Ok(digest)
    }

    /// 读取已验证链头；从未登记过时返回 `None`。
    pub fn head(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Option<MembershipHead>, MembershipStoreError> {
        self.connection
            .query_row(
                "SELECT workspace_id, head_digest, sequence, epoch, verified_at_unix_ms
                 FROM membership_head WHERE workspace_id = ?1",
                params![workspace.to_string()],
                row_to_head,
            )
            .optional()?
            .transpose()
    }

    /// 列出某个工作区已登记的全部事件索引，按 sequence 升序。
    pub fn events(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Vec<MembershipEventRecord>, MembershipStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT workspace_id, sequence, event_digest, object_id, epoch,
                    actor, action_kind, subject, created_at_unix_ms
             FROM membership_events
             WHERE workspace_id = ?1
             ORDER BY sequence",
        )?;
        let rows = statement.query_map(params![workspace.to_string()], row_to_event)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// 清空某个工作区的成员索引与链头，**重置信任根**。
    ///
    /// # 危险
    ///
    /// 调用之后，本机不再记得自己验证过哪条链，会接受后端给出的**任意** genesis，
    /// 包括攻击者构造的、把自己设为管理员的那一条。
    ///
    /// 它只允许出现在显式的灾难恢复流程里（用户持恢复短语重新建立身份，见 M2 任务 7），
    /// 并且必须：
    ///
    /// 1. 要求用户交互确认；
    /// 2. 与 `envsync_core::checkpoint::CheckpointStore::reset` 一起调用——只重置一半
    ///    会留下自相矛盾的本地状态；
    /// 3. 在下一次同步时用管理员签名的 invitation 或恢复包重新建立信任根。
    ///
    /// 普通的同步失败、冲突、网络错误、验证失败**都不是**调用它的理由。验证失败恰恰
    /// 说明有人在攻击，这时重置信任根等于直接投降。
    pub fn reset_trust_root(&self, workspace: WorkspaceId) -> Result<(), MembershipStoreError> {
        let transaction = self.connection.unchecked_transaction()?;
        transaction.execute(
            "DELETE FROM membership_events WHERE workspace_id = ?1",
            params![workspace.to_string()],
        )?;
        transaction.execute(
            "DELETE FROM membership_head WHERE workspace_id = ?1",
            params![workspace.to_string()],
        )?;
        transaction.commit()?;
        tracing::warn!(
            workspace = %workspace,
            "成员链信任根已被重置：下一次同步会接受任意 genesis，必须由恢复流程重新背书"
        );
        Ok(())
    }
}

/// 把 `u64` 转成 SQLite 的有符号 64 位整数，越界时报错而不是静默钳制。
///
/// sequence / epoch / 时间戳一旦被钳制就再也无法比较大小，而它们恰恰是反回滚判定的
/// 依据；宁可写入失败，也不能保存一个「看起来正常」的错值。
fn to_i64(field: &'static str, value: u64) -> Result<i64, MembershipStoreError> {
    i64::try_from(value).map_err(|_| MembershipStoreError::OutOfRange { field, value })
}

/// 把 Unix 毫秒钳制到 SQLite 整数范围（仅用于「本机记录时间」这类非判定字段）。
fn clamp_millis(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// 把一行结果映射为 [`MembershipHead`]。
fn row_to_head(row: &Row<'_>) -> rusqlite::Result<Result<MembershipHead, MembershipStoreError>> {
    let workspace: String = row.get(0)?;
    let digest: String = row.get(1)?;
    let sequence: i64 = row.get(2)?;
    let epoch: i64 = row.get(3)?;
    let verified_at_unix_ms: i64 = row.get(4)?;

    Ok((|| {
        Ok(MembershipHead {
            workspace: parse_workspace(&workspace)?,
            digest: parse_digest(&digest, "head_digest")?,
            sequence: from_i64("sequence", sequence)?,
            epoch: from_i64("epoch", epoch)?,
            verified_at_unix_ms,
        })
    })())
}

/// 把一行结果映射为 [`MembershipEventRecord`]。
fn row_to_event(
    row: &Row<'_>,
) -> rusqlite::Result<Result<MembershipEventRecord, MembershipStoreError>> {
    let workspace: String = row.get(0)?;
    let sequence: i64 = row.get(1)?;
    let digest: String = row.get(2)?;
    let object: String = row.get(3)?;
    let epoch: i64 = row.get(4)?;
    let actor: String = row.get(5)?;
    let action_kind: String = row.get(6)?;
    let subject: String = row.get(7)?;
    let created_at_unix_ms: i64 = row.get(8)?;

    Ok((|| {
        Ok(MembershipEventRecord {
            workspace: parse_workspace(&workspace)?,
            sequence: from_i64("sequence", sequence)?,
            digest: parse_digest(&digest, "event_digest")?,
            object: object.parse::<ObjectId>().map_err(|error| {
                MembershipStoreError::Corrupt(format!("对象标识 `{object}` 非法：{error}"))
            })?,
            epoch: from_i64("epoch", epoch)?,
            actor: parse_device(&actor, "actor")?,
            action_kind,
            subject: parse_device(&subject, "subject")?,
            created_at_unix_ms,
        })
    })())
}

fn parse_workspace(text: &str) -> Result<WorkspaceId, MembershipStoreError> {
    text.parse::<WorkspaceId>().map_err(|error| {
        MembershipStoreError::Corrupt(format!("工作区标识 `{text}` 非法：{error}"))
    })
}

fn parse_digest(text: &str, column: &str) -> Result<Digest32, MembershipStoreError> {
    text.parse::<Digest32>().map_err(|error| {
        MembershipStoreError::Corrupt(format!("列 `{column}` 中的摘要 `{text}` 非法：{error}"))
    })
}

fn parse_device(text: &str, column: &str) -> Result<DeviceId, MembershipStoreError> {
    text.parse::<DeviceId>().map_err(|error| {
        MembershipStoreError::Corrupt(format!("列 `{column}` 中的设备 `{text}` 非法：{error}"))
    })
}

fn from_i64(column: &'static str, value: i64) -> Result<u64, MembershipStoreError> {
    u64::try_from(value)
        .map_err(|_| MembershipStoreError::Corrupt(format!("列 `{column}` 是负数：{value}")))
}
