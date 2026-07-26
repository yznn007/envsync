//! 快照与工作区引用。
//!
//! 一次发布产生一个 [`SnapshotBody`]，其标识**只覆盖主体**，签名作为独立对象存放。
//! 这样同一快照被不同设备签名时，快照标识保持不变，跨设备比较才有意义。
//!
//! [`WorkspaceRef`] 是工作区的当前头，只能通过 CAS（compare-and-swap）单调前进。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::cbor::{CborCodec, CborError, Value};
use crate::cbor_struct;
use crate::id::{DeviceId, SnapshotId, StateRootId, WorkspaceId};

/// 快照主体的当前格式版本。
pub const SNAPSHOT_FORMAT_VERSION: u32 = 1;
/// 工作区引用的当前格式版本。
pub const REF_FORMAT_VERSION: u32 = 1;
/// 单个快照允许的父快照数量上限。
pub const MAX_PARENTS: usize = 8;
/// 快照元数据的键值数量上限。
pub const MAX_METADATA_ENTRIES: usize = 64;

/// 快照校验错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotError {
    /// 父快照数量超限。
    #[error("父快照数量 {0} 超过上限 {MAX_PARENTS}")]
    TooManyParents(usize),
    /// 父快照列表未排序或存在重复。
    #[error("父快照列表必须按升序排列且不重复")]
    UnsortedParents,
    /// 元数据条目过多。
    #[error("元数据条目数量 {0} 超过上限 {MAX_METADATA_ENTRIES}")]
    TooManyMetadataEntries(usize),
    /// 元数据键为空。
    #[error("元数据键不能为空")]
    EmptyMetadataKey,
    /// 引用 revision 未前进。
    #[error("Ref revision 必须单调递增：当前 {current}，尝试写入 {next}")]
    NonMonotonicRevision {
        /// 当前 revision。
        current: u64,
        /// 尝试写入的 revision。
        next: u64,
    },
    /// revision 0 必须对应空头。
    #[error("revision 0 的 Ref 不能携带快照头")]
    InitialRevisionWithHead,
    /// 非 0 revision 必须携带快照头。
    #[error("revision {0} 的 Ref 必须携带快照头")]
    NonInitialRevisionWithoutHead(u64),
}

/// 快照主体。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotBody {
    /// 格式版本。
    pub format_version: u32,
    /// 所属工作区。
    pub workspace: WorkspaceId,
    /// 父快照，按升序排列且不重复；首个快照为空列表。
    pub parents: Vec<SnapshotId>,
    /// 本次快照的 State Root。
    pub state_root: StateRootId,
    /// 作者设备。
    pub author_device: DeviceId,
    /// 创建时刻（Unix 毫秒）。
    pub created_at_unix_ms: u64,
    /// 自由元数据；键值均为文本，编码时按键排序，因此插入顺序不影响快照标识。
    pub metadata: BTreeMap<String, String>,
}

impl SnapshotBody {
    /// 构造并校验快照主体。
    pub fn new(
        workspace: WorkspaceId,
        mut parents: Vec<SnapshotId>,
        state_root: StateRootId,
        author_device: DeviceId,
        created_at_unix_ms: u64,
        metadata: BTreeMap<String, String>,
    ) -> Result<Self, SnapshotError> {
        parents.sort();
        parents.dedup();
        let body = SnapshotBody {
            format_version: SNAPSHOT_FORMAT_VERSION,
            workspace,
            parents,
            state_root,
            author_device,
            created_at_unix_ms,
            metadata,
        };
        body.validate()?;
        Ok(body)
    }

    /// 校验结构约束。
    pub fn validate(&self) -> Result<(), SnapshotError> {
        if self.parents.len() > MAX_PARENTS {
            return Err(SnapshotError::TooManyParents(self.parents.len()));
        }
        if self.parents.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(SnapshotError::UnsortedParents);
        }
        if self.metadata.len() > MAX_METADATA_ENTRIES {
            return Err(SnapshotError::TooManyMetadataEntries(self.metadata.len()));
        }
        if self.metadata.keys().any(|key| key.is_empty()) {
            return Err(SnapshotError::EmptyMetadataKey);
        }
        Ok(())
    }

    /// 快照标识，只覆盖主体。
    pub fn id(&self) -> SnapshotId {
        SnapshotId::of(&self.to_canonical_vec())
    }
}

impl CborCodec for SnapshotBody {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Uint(self.format_version as u64),
            self.workspace.to_value(),
            self.parents.to_value(),
            self.state_root.to_value(),
            self.author_device.to_value(),
            Value::Uint(self.created_at_unix_ms),
            self.metadata.to_value(),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        if items.len() != 7 {
            return Err(CborError::ArityMismatch);
        }
        let format_version = u32::from_value(&items[0])?;
        if format_version != SNAPSHOT_FORMAT_VERSION {
            return Err(CborError::UnsupportedFormatVersion {
                found: format_version,
                supported: SNAPSHOT_FORMAT_VERSION,
            });
        }
        let body = SnapshotBody {
            format_version,
            workspace: WorkspaceId::from_value(&items[1])?,
            parents: Vec::<SnapshotId>::from_value(&items[2])?,
            state_root: StateRootId::from_value(&items[3])?,
            author_device: DeviceId::from_value(&items[4])?,
            created_at_unix_ms: u64::from_value(&items[5])?,
            metadata: BTreeMap::<String, String>::from_value(&items[6])?,
        };
        body.validate()
            .map_err(|err| CborError::InvalidValue(err.to_string()))?;
        Ok(body)
    }
}

/// 快照签名对象。
///
/// M0 不做密码学签名，`algorithm` 为 `"none"` 且 `signature` 为空；M2 起使用
/// Ed25519 并强制校验。字段布局提前固定，避免后续 schema 破坏性变更。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSignature {
    /// 格式版本。
    pub format_version: u32,
    /// 被签名的快照。
    pub snapshot: SnapshotId,
    /// 签名设备。
    pub device: DeviceId,
    /// 算法标识，例如 `none` 或 `ed25519`。
    pub algorithm: String,
    /// 签名字节。
    pub signature: Vec<u8>,
}

cbor_struct!(SnapshotSignature {
    format_version: u32,
    snapshot: SnapshotId,
    device: DeviceId,
    algorithm: String,
    signature: Vec<u8>,
});

impl SnapshotSignature {
    /// 构造 M0 使用的“未签名”占位对象。
    pub fn unsigned(snapshot: SnapshotId, device: DeviceId) -> Self {
        SnapshotSignature {
            format_version: SNAPSHOT_FORMAT_VERSION,
            snapshot,
            device,
            algorithm: "none".to_owned(),
            signature: Vec::new(),
        }
    }

    /// 是否携带真实的密码学签名。
    pub fn is_cryptographic(&self) -> bool {
        self.algorithm != "none" && !self.signature.is_empty()
    }
}

/// 工作区引用：当前头与单调 revision。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRef {
    /// 格式版本。
    pub format_version: u32,
    /// 工作区标识。
    pub workspace: WorkspaceId,
    /// 单调递增的 revision；`0` 表示尚未发布任何快照。
    pub revision: u64,
    /// 当前头快照；`revision == 0` 时为 `None`。
    pub head: Option<SnapshotId>,
}

impl WorkspaceRef {
    /// 构造初始引用（revision 0，无头）。
    pub fn initial(workspace: WorkspaceId) -> Self {
        WorkspaceRef {
            format_version: REF_FORMAT_VERSION,
            workspace,
            revision: 0,
            head: None,
        }
    }

    /// 校验结构约束。
    pub fn validate(&self) -> Result<(), SnapshotError> {
        match (self.revision, &self.head) {
            (0, Some(_)) => Err(SnapshotError::InitialRevisionWithHead),
            (revision, None) if revision > 0 => {
                Err(SnapshotError::NonInitialRevisionWithoutHead(revision))
            }
            _ => Ok(()),
        }
    }

    /// 生成指向新头的下一个引用。
    pub fn advance(&self, head: SnapshotId) -> WorkspaceRef {
        WorkspaceRef {
            format_version: REF_FORMAT_VERSION,
            workspace: self.workspace,
            revision: self.revision + 1,
            head: Some(head),
        }
    }

    /// 校验 `next` 是否是 `self` 的合法后继。
    ///
    /// 该检查是反回滚保护的基础：revision 必须**严格**递增。
    pub fn check_successor(&self, next: &WorkspaceRef) -> Result<(), SnapshotError> {
        next.validate()?;
        if next.revision <= self.revision {
            return Err(SnapshotError::NonMonotonicRevision {
                current: self.revision,
                next: next.revision,
            });
        }
        Ok(())
    }
}

impl CborCodec for WorkspaceRef {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Uint(self.format_version as u64),
            self.workspace.to_value(),
            Value::Uint(self.revision),
            self.head.to_value(),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        if items.len() != 4 {
            return Err(CborError::ArityMismatch);
        }
        let format_version = u32::from_value(&items[0])?;
        if format_version != REF_FORMAT_VERSION {
            return Err(CborError::UnsupportedFormatVersion {
                found: format_version,
                supported: REF_FORMAT_VERSION,
            });
        }
        let reference = WorkspaceRef {
            format_version,
            workspace: WorkspaceId::from_value(&items[1])?,
            revision: u64::from_value(&items[2])?,
            head: Option::<SnapshotId>::from_value(&items[3])?,
        };
        reference
            .validate()
            .map_err(|err| CborError::InvalidValue(err.to_string()))?;
        Ok(reference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::StateRootId;

    fn body(metadata: BTreeMap<String, String>) -> SnapshotBody {
        SnapshotBody::new(
            WorkspaceId::from_uuid(uuid::Uuid::nil()),
            vec![],
            StateRootId::of(b"state"),
            DeviceId::derive(b"device"),
            1_700_000_000_000,
            metadata,
        )
        .expect("构造成功")
    }

    #[test]
    fn snapshot_id_is_independent_of_metadata_insertion_order() {
        let mut forward = BTreeMap::new();
        forward.insert("a".to_owned(), "1".to_owned());
        forward.insert("z".to_owned(), "2".to_owned());
        let mut backward = BTreeMap::new();
        backward.insert("z".to_owned(), "2".to_owned());
        backward.insert("a".to_owned(), "1".to_owned());
        assert_eq!(body(forward).id(), body(backward).id());
    }

    #[test]
    fn snapshot_id_changes_with_state_root() {
        let base = body(BTreeMap::new());
        let mut changed = base.clone();
        changed.state_root = StateRootId::of(b"other");
        assert_ne!(base.id(), changed.id());
    }

    #[test]
    fn snapshot_id_covers_body_only_not_signature() {
        let body = body(BTreeMap::new());
        let id = body.id();
        let signature_a = SnapshotSignature::unsigned(id, DeviceId::derive(b"a"));
        let signature_b = SnapshotSignature::unsigned(id, DeviceId::derive(b"b"));
        // 不同设备签名同一快照，快照标识保持一致。
        assert_eq!(signature_a.snapshot, signature_b.snapshot);
        assert_eq!(body.id(), id);
        assert!(!signature_a.is_cryptographic());
    }

    #[test]
    fn snapshot_rejects_unsorted_or_duplicate_parents() {
        let mut body = body(BTreeMap::new());
        let first = SnapshotId::of(b"1");
        let second = SnapshotId::of(b"2");
        let (low, high) = if first < second {
            (first, second)
        } else {
            (second, first)
        };
        body.parents = vec![high, low];
        assert_eq!(body.validate(), Err(SnapshotError::UnsortedParents));
        body.parents = vec![low, low];
        assert_eq!(body.validate(), Err(SnapshotError::UnsortedParents));
    }

    #[test]
    fn snapshot_new_normalises_parent_order() {
        let first = SnapshotId::of(b"1");
        let second = SnapshotId::of(b"2");
        let forward = SnapshotBody::new(
            WorkspaceId::from_uuid(uuid::Uuid::nil()),
            vec![first, second],
            StateRootId::of(b"state"),
            DeviceId::derive(b"device"),
            0,
            BTreeMap::new(),
        )
        .unwrap();
        let backward = SnapshotBody::new(
            WorkspaceId::from_uuid(uuid::Uuid::nil()),
            vec![second, first],
            StateRootId::of(b"state"),
            DeviceId::derive(b"device"),
            0,
            BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(forward.id(), backward.id());
    }

    #[test]
    fn snapshot_rejects_unknown_format_version() {
        let body = body(BTreeMap::new());
        let mut value = body.to_value();
        if let Value::Array(items) = &mut value {
            items[0] = Value::Uint(7);
        }
        assert_eq!(
            SnapshotBody::from_canonical_slice(&crate::cbor::encode(&value)),
            Err(CborError::UnsupportedFormatVersion {
                found: 7,
                supported: 1
            })
        );
    }

    #[test]
    fn workspace_ref_enforces_monotonic_revisions() {
        let workspace = WorkspaceId::generate();
        let initial = WorkspaceRef::initial(workspace);
        assert_eq!(initial.revision, 0);
        assert!(initial.head.is_none());

        let next = initial.advance(SnapshotId::of(b"head"));
        assert_eq!(next.revision, 1);
        initial.check_successor(&next).expect("1 是 0 的合法后继");

        // 回滚到更低或相同 revision 必须被拒绝。
        assert_eq!(
            next.check_successor(&initial),
            Err(SnapshotError::NonMonotonicRevision {
                current: 1,
                next: 0
            })
        );
        assert_eq!(
            next.check_successor(&next),
            Err(SnapshotError::NonMonotonicRevision {
                current: 1,
                next: 1
            })
        );
    }

    #[test]
    fn workspace_ref_rejects_inconsistent_head_and_revision() {
        let workspace = WorkspaceId::generate();
        let bogus = WorkspaceRef {
            format_version: REF_FORMAT_VERSION,
            workspace,
            revision: 0,
            head: Some(SnapshotId::of(b"head")),
        };
        assert_eq!(
            bogus.validate(),
            Err(SnapshotError::InitialRevisionWithHead)
        );

        let headless = WorkspaceRef {
            format_version: REF_FORMAT_VERSION,
            workspace,
            revision: 3,
            head: None,
        };
        assert_eq!(
            headless.validate(),
            Err(SnapshotError::NonInitialRevisionWithoutHead(3))
        );
    }

    #[test]
    fn workspace_ref_round_trips() {
        let reference =
            WorkspaceRef::initial(WorkspaceId::generate()).advance(SnapshotId::of(b"head"));
        let bytes = reference.to_canonical_vec();
        assert_eq!(
            WorkspaceRef::from_canonical_slice(&bytes).unwrap(),
            reference
        );
    }
}
