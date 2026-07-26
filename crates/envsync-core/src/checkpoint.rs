//! 反回滚检查点：阻止后端把设备拉回旧状态。
//!
//! 后端在 EnvSync 的威胁模型里是**不被信任**的：它可以少给数据、给旧数据、给自相
//! 矛盾的数据。CAS 只能保证「同一个后端上 revision 单调前进」，无法阻止后端对某一台
//! 设备单独回放一份旧快照——那台设备会以为自己是最新的，从而：
//!
//! * 用旧的 State Root 覆盖掉别人刚同步上去的配置；
//! * 用**撤销发生之前**的成员链头继续给已撤销设备发信封；
//! * 用旧的密钥纪元继续加密，让已撤销设备仍能解密新秘密。
//!
//! 检查点就是设备**自己记住的高水位线**。接受任何一个新的后端头之前，先用
//! [`check_advance`] 判定它是否真的是前进；只有显式的 [`CheckpointStore::reset`]
//! （灾难恢复）能重置信任根。
//!
//! ## 权威副本在系统安全存储
//!
//! **权威副本保存在系统安全存储**（macOS Keychain / Windows Credential Manager /
//! Linux Secret Service，见 M2 任务 6）；SQLite 里的那一份（[`SqliteCheckpointStore`]）
//! 只是**审计副本**，方便 `envsync doctor` 与事后排查。两者不一致时**以安全存储为准
//! 并告警**：SQLite 文件躺在用户目录里，任何本地进程都能改写它；安全存储至少要求
//! 用户账户已解锁且授予了访问权限。绝不能出现「SQLite 里的检查点更旧，于是把安全
//! 存储里的降下来」这种逻辑——那等于给攻击者提供了一条免费的回滚通道。
//!
//! ## 「旧 membership head」为什么需要一个 sequence
//!
//! 摘要之间没有顺序：只拿到两个 `membership_digest`，本地无法判断哪个更新，也无法
//! 判断新的那个是不是从旧的那个延伸出来的。因此 [`Checkpoint`] 在设计给定的字段之外
//! **额外记录 `membership_sequence`**——即已验证链头在链上的位置。有了它，规则就完全
//! 可判定：
//!
//! ```text
//! candidate.membership_sequence <  current.membership_sequence            -> 阻塞（旧 head）
//! candidate.membership_sequence == current.membership_sequence
//!     且 membership_digest 不等                                          -> 阻塞（链分叉）
//! candidate.membership_sequence >  current.membership_sequence            -> 放行
//! ```
//!
//! 最后一条之所以敢放行，是因为**链延续性由
//! [`crate::membership::verify_membership_chain`] 负责**：调用方必须先从已信任的
//! genesis 完整回放到 `candidate.membership_digest`，验证通过才允许把它塞进
//! `candidate`。检查点只做单调性判定，不重复做链验证——两处各自负责一件事，比一个
//! 什么都做的大函数更容易审计。
//!
//! ## 推进顺序
//!
//! ```text
//! 1. 拉取后端头 → 2. 验证成员链 → 3. check_advance → 4. 应用到本地
//!                                                   → 5. 事务提交
//!                                                   → 6. 才推进 checkpoint
//! ```
//!
//! 第 6 步必须在第 5 步之后。反过来的话，进程在两步之间崩溃就会留下「检查点说我已经
//! 到 12 了，本地其实还在 11」的状态，而 11 的数据再也无法被接受。

use std::collections::BTreeMap;
use std::sync::Mutex;

use envsync_domain::id::{Digest32, SnapshotId, WorkspaceId};
use envsync_storage::checkpoints::{CheckpointAudit, CheckpointRecord, CheckpointStoreError};

/// 一个工作区的反回滚检查点。
///
/// 它回答的是同一个问题的四个侧面：「我见过的最新状态是什么」。四个维度都必须单调，
/// 任何一个回退都说明对面在骗人。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    /// 工作区标识。
    pub workspace: WorkspaceId,
    /// 已接受的最高后端 revision。
    pub revision: u64,
    /// 该 revision 对应的快照。
    pub snapshot: SnapshotId,
    /// 已验证的成员链头摘要。
    pub membership_digest: Digest32,
    /// 已验证的成员链头所在的 sequence；摘要之间没有顺序，判定回滚要靠它。
    pub membership_sequence: u64,
    /// 已知的最高密钥纪元。
    pub key_epoch: u64,
    /// 本机更新该检查点的时刻（Unix 毫秒）。仅供审计，**不参与**任何判定——
    /// 时间来自本机时钟，攻击者影响不了它，它也证明不了任何事。
    pub updated_at_unix_ms: u64,
}

/// 检查点错误。
///
/// 所有「阻塞」变体都表示**检测到一次回滚攻击或后端自相矛盾**，调用方必须中止本次
/// 同步，而不是重试。
///
/// 与本 crate 其他错误一致，它只实现 `Debug` + `Error`：底层的 `rusqlite::Error`
/// 无法比较，把整个类型降级成可比较的字符串只会丢掉 source 链。断言请用 `matches!`
/// 或 [`CheckpointError::code`]。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CheckpointError {
    /// 候选检查点属于另一个工作区。
    #[error("检查点属于另一个工作区")]
    WorkspaceMismatch,

    /// 后端给出的 revision 比已接受的更低。
    #[error("检测到回滚：已接受 revision {current}，后端却给出 {candidate}")]
    RevisionRollback {
        /// 当前已接受的 revision。
        current: u64,
        /// 后端给出的 revision。
        candidate: u64,
    },

    /// 同一个 revision 上出现了不同的快照。
    #[error("检测到分叉：revision {revision} 上出现了与已接受快照不同的快照")]
    SnapshotForked {
        /// 出问题的 revision。
        revision: u64,
    },

    /// 同一个 revision、同一个快照，其余字段却不一致。
    #[error("检查点自相矛盾：revision {revision} 的快照相同，但成员链头或密钥纪元不同")]
    Diverged {
        /// 出问题的 revision。
        revision: u64,
    },

    /// 成员链头比已验证的更旧。
    #[error("检测到成员链回滚：已验证到 sequence {current}，后端却给出 sequence {candidate}")]
    MembershipRollback {
        /// 当前已验证的链头位置。
        current: u64,
        /// 后端给出的链头位置。
        candidate: u64,
    },

    /// 同一个 sequence 上出现了不同的成员链头。
    #[error("检测到成员链分叉：sequence {sequence} 上出现了不同的链头摘要")]
    MembershipForked {
        /// 出问题的链头位置。
        sequence: u64,
    },

    /// 密钥纪元回退。
    #[error("检测到密钥纪元回滚：已知 {current}，后端却给出 {candidate}")]
    KeyEpochRollback {
        /// 当前已知的纪元。
        current: u64,
        /// 后端给出的纪元。
        candidate: u64,
    },

    /// 底层存储失败。
    #[error(transparent)]
    Storage(#[from] CheckpointStoreError),

    /// 内存实现的互斥锁被毒化（持锁线程 panic 过）。
    #[error("检查点存储不可用：内部锁已被毒化")]
    Poisoned,
}

impl CheckpointError {
    /// 稳定的机器可读错误码，用于 CLI 的 JSON 契约。
    pub fn code(&self) -> &'static str {
        match self {
            CheckpointError::WorkspaceMismatch => "checkpoint.workspace_mismatch",
            CheckpointError::RevisionRollback { .. } => "checkpoint.revision_rollback",
            CheckpointError::SnapshotForked { .. } => "checkpoint.snapshot_forked",
            CheckpointError::Diverged { .. } => "checkpoint.diverged",
            CheckpointError::MembershipRollback { .. } => "checkpoint.membership_rollback",
            CheckpointError::MembershipForked { .. } => "checkpoint.membership_forked",
            CheckpointError::KeyEpochRollback { .. } => "checkpoint.key_epoch_rollback",
            CheckpointError::Storage(error) => error.code(),
            CheckpointError::Poisoned => "checkpoint.poisoned",
        }
    }

    /// 是否为「检测到回滚/分叉」这一类必须中止的安全事件。
    ///
    /// 存储故障和锁毒化不属于此类：那是本机问题，重试或修复后可以继续。
    pub fn is_rollback_attack(&self) -> bool {
        matches!(
            self,
            CheckpointError::RevisionRollback { .. }
                | CheckpointError::SnapshotForked { .. }
                | CheckpointError::Diverged { .. }
                | CheckpointError::MembershipRollback { .. }
                | CheckpointError::MembershipForked { .. }
                | CheckpointError::KeyEpochRollback { .. }
        )
    }
}

/// 检查点的持久化抽象。
///
/// **权威实现应当由系统安全存储提供**（M2 任务 6 的 `SecureStore`）。本 crate 只定义
/// 契约，并提供两个非权威实现：[`InMemoryCheckpointStore`]（测试）与
/// [`SqliteCheckpointStore`]（审计副本）。
///
/// 实现**不应该**在 [`CheckpointStore::save`] 里自行做单调性判定：判定规则是
/// [`check_advance`] 这一个纯函数，散落到每个实现里只会产生不一致的安全边界。需要
/// 「先判定再保存」时请用 [`advance`]。
pub trait CheckpointStore {
    /// 读取某个工作区的检查点；从未建立过时返回 `None`。
    fn load(&self, workspace: WorkspaceId) -> Result<Option<Checkpoint>, CheckpointError>;

    /// 无条件写入检查点。
    fn save(&self, checkpoint: &Checkpoint) -> Result<(), CheckpointError>;

    /// 删除检查点，**重置信任根**。
    ///
    /// # 危险
    ///
    /// 调用之后，本设备会接受后端给出的**任意**状态，包括一份精心构造的旧快照。它只
    /// 允许出现在显式的灾难恢复流程里（用户持恢复短语重新建立身份），并且必须要求
    /// 用户交互确认。普通的同步失败、冲突、网络错误**都不是**调用它的理由。
    fn reset(&self, workspace: WorkspaceId) -> Result<(), CheckpointError>;
}

/// 在接受一个新的后端头之前调用：判定 `candidate` 是否是 `current` 的合法前进。
///
/// `current` 为 `None` 表示本设备**还没有信任根**（首次加入工作区）。此时一律放行，
/// 由调用方负责先验证管理员签名的 invitation——检查点无法凭空判断第一份状态的真伪。
///
/// # 判定规则
///
/// | 情况 | 结果 |
/// |---|---|
/// | 工作区不同 | [`CheckpointError::WorkspaceMismatch`] |
/// | `revision` 变小 | [`CheckpointError::RevisionRollback`] |
/// | `membership_sequence` 变小 | [`CheckpointError::MembershipRollback`] |
/// | `membership_sequence` 相同但摘要不同 | [`CheckpointError::MembershipForked`] |
/// | `key_epoch` 变小 | [`CheckpointError::KeyEpochRollback`] |
/// | `revision` 相同但快照不同 | [`CheckpointError::SnapshotForked`] |
/// | `revision` 与快照都相同但其余字段不同 | [`CheckpointError::Diverged`] |
/// | 完全相同 | `Ok`（幂等重放同一个头是允许的） |
///
/// # 示例
///
/// ```
/// use envsync_core::checkpoint::{check_advance, Checkpoint, CheckpointError};
/// use envsync_domain::id::{Digest32, SnapshotId, WorkspaceId};
///
/// let workspace = WorkspaceId::generate();
/// let accepted = Checkpoint {
///     workspace,
///     revision: 12,
///     snapshot: SnapshotId::of(b"head-12"),
///     membership_digest: Digest32::domain_hash("test", b"members"),
///     membership_sequence: 3,
///     key_epoch: 2,
///     updated_at_unix_ms: 1_700_000_000_000,
/// };
///
/// let rolled_back = Checkpoint { revision: 11, ..accepted };
/// assert!(matches!(
///     check_advance(Some(&accepted), &rolled_back),
///     Err(CheckpointError::RevisionRollback { current: 12, candidate: 11 })
/// ));
/// ```
pub fn check_advance(
    current: Option<&Checkpoint>,
    candidate: &Checkpoint,
) -> Result<(), CheckpointError> {
    // 没有信任根：首次建立，由调用方用管理员签名的 invitation 背书。
    let Some(current) = current else {
        return Ok(());
    };
    if current.workspace != candidate.workspace {
        return Err(CheckpointError::WorkspaceMismatch);
    }
    if candidate.revision < current.revision {
        return Err(CheckpointError::RevisionRollback {
            current: current.revision,
            candidate: candidate.revision,
        });
    }
    if candidate.membership_sequence < current.membership_sequence {
        return Err(CheckpointError::MembershipRollback {
            current: current.membership_sequence,
            candidate: candidate.membership_sequence,
        });
    }
    if candidate.membership_sequence == current.membership_sequence
        && candidate.membership_digest != current.membership_digest
    {
        return Err(CheckpointError::MembershipForked {
            sequence: current.membership_sequence,
        });
    }
    if candidate.key_epoch < current.key_epoch {
        return Err(CheckpointError::KeyEpochRollback {
            current: current.key_epoch,
            candidate: candidate.key_epoch,
        });
    }
    if candidate.revision == current.revision {
        // 同一个 revision 必须对应同一个快照——不同快照意味着后端在同一个位置给了
        // 两份互不相容的历史。
        if candidate.snapshot != current.snapshot {
            return Err(CheckpointError::SnapshotForked {
                revision: current.revision,
            });
        }
        if candidate.membership_digest != current.membership_digest
            || candidate.key_epoch != current.key_epoch
        {
            return Err(CheckpointError::Diverged {
                revision: current.revision,
            });
        }
    }
    Ok(())
}

/// 先用 [`check_advance`] 判定，再写入存储。
///
/// 这是推进检查点的**唯一**推荐入口：把「判定」和「保存」绑在一起，调用点就不可能
/// 漏掉判定。注意它必须在本地事务提交**之后**调用，见模块文档的推进顺序。
pub fn advance<S>(store: &S, candidate: &Checkpoint) -> Result<(), CheckpointError>
where
    S: CheckpointStore + ?Sized,
{
    let current = store.load(candidate.workspace)?;
    check_advance(current.as_ref(), candidate)?;
    store.save(candidate)
}

/// 进程内的检查点实现，供测试与 dry-run 使用。
///
/// **不要**在生产路径上使用：它随进程消失，等于每次启动都重置信任根。
#[derive(Debug, Default)]
pub struct InMemoryCheckpointStore {
    entries: Mutex<BTreeMap<WorkspaceId, Checkpoint>>,
}

impl InMemoryCheckpointStore {
    /// 建立一个空存储。
    pub fn new() -> Self {
        InMemoryCheckpointStore::default()
    }

    /// 当前保存的工作区数量。
    pub fn len(&self) -> Result<usize, CheckpointError> {
        Ok(self
            .entries
            .lock()
            .map_err(|_| CheckpointError::Poisoned)?
            .len())
    }

    /// 是否为空。
    pub fn is_empty(&self) -> Result<bool, CheckpointError> {
        Ok(self.len()? == 0)
    }
}

impl CheckpointStore for InMemoryCheckpointStore {
    fn load(&self, workspace: WorkspaceId) -> Result<Option<Checkpoint>, CheckpointError> {
        Ok(self
            .entries
            .lock()
            .map_err(|_| CheckpointError::Poisoned)?
            .get(&workspace)
            .copied())
    }

    fn save(&self, checkpoint: &Checkpoint) -> Result<(), CheckpointError> {
        self.entries
            .lock()
            .map_err(|_| CheckpointError::Poisoned)?
            .insert(checkpoint.workspace, *checkpoint);
        Ok(())
    }

    fn reset(&self, workspace: WorkspaceId) -> Result<(), CheckpointError> {
        self.entries
            .lock()
            .map_err(|_| CheckpointError::Poisoned)?
            .remove(&workspace);
        Ok(())
    }
}

/// 系统安全存储中的**权威副本**。
///
/// 这是生产路径应当使用的实现：条目落在操作系统托管的凭据库里
/// （[`SecurePurpose::Checkpoint`]），由用户登录态保护。
/// [`SqliteCheckpointStore`] 只是审计副本，两者不一致时以本实现为准。
///
/// # 编码
///
/// 值是一段 canonical CBOR 数组
/// `[format_version, workspace, revision, snapshot, membership_digest,
///   membership_sequence, key_epoch, updated_at_unix_ms]`。
/// 里面**没有任何密钥材料**——检查点全部是公开元数据；把它放进安全存储不是为了保密，
/// 而是为了**完整性**：安全存储至少要求用户账户已解锁且授予了访问权限，而
/// `~/.envsync` 下的文件任何本地进程都能改写。
///
/// # 读不到 ≠ 没有
///
/// [`SecureStore::get`] 的 `Err`（凭据库锁定、访问被拒绝）会原样上抛，**绝不**被当成
/// 「还没有检查点」。把两者混为一谈等于给攻击者一条免费的回滚通道：锁住凭据库就能让
/// 设备接受任意旧状态。
pub struct SecureCheckpointStore {
    secure: std::sync::Arc<dyn envsync_platform::secure_store::SecureStore>,
}

/// 检查点在安全存储中的编码版本。
pub const CHECKPOINT_RECORD_VERSION: u32 = 1;

impl SecureCheckpointStore {
    /// 由一个已打开的安全存储构造。
    pub fn new(secure: std::sync::Arc<dyn envsync_platform::secure_store::SecureStore>) -> Self {
        SecureCheckpointStore { secure }
    }

    /// 某个工作区的检查点坐标。
    fn key(workspace: WorkspaceId) -> envsync_platform::secure_store::SecureKey {
        envsync_platform::secure_store::SecureKey::workspace_scoped(
            workspace,
            envsync_platform::secure_store::SecurePurpose::Checkpoint,
        )
    }

    /// 编码为 canonical CBOR。
    fn encode(checkpoint: &Checkpoint) -> Vec<u8> {
        use envsync_domain::cbor::{encode, CborCodec, Value};
        encode(&Value::Array(vec![
            Value::Uint(CHECKPOINT_RECORD_VERSION as u64),
            checkpoint.workspace.to_value(),
            Value::Uint(checkpoint.revision),
            checkpoint.snapshot.to_value(),
            checkpoint.membership_digest.to_value(),
            Value::Uint(checkpoint.membership_sequence),
            Value::Uint(checkpoint.key_epoch),
            Value::Uint(checkpoint.updated_at_unix_ms),
        ]))
    }

    /// 从 canonical CBOR 还原。
    fn decode(bytes: &[u8]) -> Result<Checkpoint, CheckpointError> {
        use envsync_domain::cbor::{decode_canonical, CborCodec};
        let malformed = |detail: &str| {
            CheckpointError::Storage(CheckpointStoreError::Corrupt(detail.to_owned()))
        };
        let value = decode_canonical(bytes).map_err(|_| malformed("检查点不是 canonical CBOR"))?;
        let items = value.as_array().map_err(|_| malformed("检查点不是数组"))?;
        if items.len() != 8 {
            return Err(malformed("检查点字段数量不符"));
        }
        let version = u32::from_value(&items[0]).map_err(|_| malformed("版本号非法"))?;
        if version != CHECKPOINT_RECORD_VERSION {
            return Err(malformed("检查点编码版本不受支持"));
        }
        Ok(Checkpoint {
            workspace: WorkspaceId::from_value(&items[1])
                .map_err(|_| malformed("工作区标识非法"))?,
            revision: items[2].as_uint().map_err(|_| malformed("revision 非法"))?,
            snapshot: SnapshotId::from_value(&items[3]).map_err(|_| malformed("快照标识非法"))?,
            membership_digest: Digest32::from_value(&items[4])
                .map_err(|_| malformed("成员链头摘要非法"))?,
            membership_sequence: items[5]
                .as_uint()
                .map_err(|_| malformed("membership_sequence 非法"))?,
            key_epoch: items[6]
                .as_uint()
                .map_err(|_| malformed("key_epoch 非法"))?,
            updated_at_unix_ms: items[7]
                .as_uint()
                .map_err(|_| malformed("updated_at_unix_ms 非法"))?,
        })
    }

    /// 底层安全存储的自述信息，供 `envsync doctor` 判断这是不是真的系统存储。
    pub fn describe(&self) -> envsync_platform::secure_store::SecureStoreDescriptor {
        self.secure.describe()
    }
}

impl std::fmt::Debug for SecureCheckpointStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureCheckpointStore")
            .field("backend", &self.secure.describe().backend)
            .finish()
    }
}

impl CheckpointStore for SecureCheckpointStore {
    fn load(&self, workspace: WorkspaceId) -> Result<Option<Checkpoint>, CheckpointError> {
        match self.secure.get(&Self::key(workspace)).map_err(|error| {
            CheckpointError::Storage(CheckpointStoreError::Corrupt(error.code().to_owned()))
        })? {
            Some(bytes) => Ok(Some(Self::decode(bytes.expose())?)),
            None => Ok(None),
        }
    }

    fn save(&self, checkpoint: &Checkpoint) -> Result<(), CheckpointError> {
        self.secure
            .put(&Self::key(checkpoint.workspace), &Self::encode(checkpoint))
            .map_err(|error| {
                CheckpointError::Storage(CheckpointStoreError::Corrupt(error.code().to_owned()))
            })
    }

    fn reset(&self, workspace: WorkspaceId) -> Result<(), CheckpointError> {
        self.secure.delete(&Self::key(workspace)).map_err(|error| {
            CheckpointError::Storage(CheckpointStoreError::Corrupt(error.code().to_owned()))
        })?;
        tracing::warn!(
            workspace = %workspace,
            "反回滚检查点（权威副本）已被删除：本设备将接受后端给出的任意状态"
        );
        Ok(())
    }
}

/// SQLite 中的**审计副本**。
///
/// # 这不是权威副本
///
/// 权威副本在系统安全存储；这一份只是为了让 `envsync doctor`、事后排查和支持流程能
/// 看到「本机认为自己到哪儿了」。两份不一致时**以安全存储为准并告警**——SQLite 文件
/// 对任何本地进程都是可写的，把它当权威等于把反回滚保护交给攻击者。
#[derive(Debug)]
pub struct SqliteCheckpointStore {
    audit: CheckpointAudit,
}

impl SqliteCheckpointStore {
    /// 打开（必要时创建）审计副本所在的数据库。
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, CheckpointError> {
        Ok(SqliteCheckpointStore {
            audit: CheckpointAudit::open(path)?,
        })
    }

    /// 由已打开的存储句柄构造。
    pub fn from_audit(audit: CheckpointAudit) -> Self {
        SqliteCheckpointStore { audit }
    }

    /// 底层审计表句柄。
    pub fn audit(&self) -> &CheckpointAudit {
        &self.audit
    }
}

impl CheckpointStore for SqliteCheckpointStore {
    fn load(&self, workspace: WorkspaceId) -> Result<Option<Checkpoint>, CheckpointError> {
        Ok(self.audit.get(workspace)?.map(|record| Checkpoint {
            workspace: record.workspace,
            revision: record.revision,
            snapshot: record.snapshot,
            membership_digest: record.membership_digest,
            membership_sequence: record.membership_sequence,
            key_epoch: record.key_epoch,
            updated_at_unix_ms: record.updated_at_unix_ms,
        }))
    }

    fn save(&self, checkpoint: &Checkpoint) -> Result<(), CheckpointError> {
        self.audit.upsert(&CheckpointRecord {
            workspace: checkpoint.workspace,
            revision: checkpoint.revision,
            snapshot: checkpoint.snapshot,
            membership_digest: checkpoint.membership_digest,
            membership_sequence: checkpoint.membership_sequence,
            key_epoch: checkpoint.key_epoch,
            updated_at_unix_ms: checkpoint.updated_at_unix_ms,
        })?;
        Ok(())
    }

    fn reset(&self, workspace: WorkspaceId) -> Result<(), CheckpointError> {
        self.audit.delete(workspace)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint(workspace: WorkspaceId) -> Checkpoint {
        Checkpoint {
            workspace,
            revision: 12,
            snapshot: SnapshotId::of(b"head-12"),
            membership_digest: Digest32::domain_hash("test:members", b"3"),
            membership_sequence: 3,
            key_epoch: 2,
            updated_at_unix_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn first_checkpoint_is_always_accepted() {
        let candidate = checkpoint(WorkspaceId::generate());
        assert!(check_advance(None, &candidate).is_ok());
    }

    #[test]
    fn identical_head_is_idempotent() {
        let current = checkpoint(WorkspaceId::generate());
        assert!(check_advance(Some(&current), &current).is_ok());
    }

    #[test]
    fn cross_workspace_checkpoint_is_rejected() {
        let current = checkpoint(WorkspaceId::generate());
        let other = checkpoint(WorkspaceId::generate());
        assert!(matches!(
            check_advance(Some(&current), &other),
            Err(CheckpointError::WorkspaceMismatch)
        ));
    }

    #[test]
    fn in_memory_store_round_trips_and_resets() {
        let workspace = WorkspaceId::generate();
        let store = InMemoryCheckpointStore::new();
        assert_eq!(store.load(workspace).unwrap(), None);
        assert!(store.is_empty().unwrap());

        let first = checkpoint(workspace);
        advance(&store, &first).unwrap();
        assert_eq!(store.load(workspace).unwrap(), Some(first));
        assert_eq!(store.len().unwrap(), 1);

        // 回滚被 `advance` 拦下，存储内容不变。
        let rolled_back = Checkpoint {
            revision: 11,
            ..first
        };
        assert!(advance(&store, &rolled_back)
            .unwrap_err()
            .is_rollback_attack());
        assert_eq!(store.load(workspace).unwrap(), Some(first));

        // 只有显式 reset 能重置信任根。
        store.reset(workspace).unwrap();
        assert_eq!(store.load(workspace).unwrap(), None);
        advance(&store, &rolled_back).unwrap();
        assert_eq!(store.load(workspace).unwrap(), Some(rolled_back));
    }

    #[test]
    fn storage_errors_are_not_rollback_attacks() {
        assert!(!CheckpointError::Poisoned.is_rollback_attack());
        assert_eq!(CheckpointError::Poisoned.code(), "checkpoint.poisoned");
    }
}
