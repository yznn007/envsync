//! 内容寻址对象。
//!
//! 后端只存储**不可变**对象，键即内容摘要。为避免不同种类的对象因字节相同而互相
//! 冒充，每种对象使用独立的哈希域分隔标签（见 [`ObjectKind::domain`]）。

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::cbor::{CborCodec, CborError, Value};
use crate::cbor_struct;
use crate::id::{BlobId, ConflictId, Digest32, IdError, ResourceId, SnapshotId, StateRootId};
use crate::resource::{ResourceEntry, ResourceEntryError};

/// State Root 的当前格式版本。
///
/// 任何字段增删都必须提升该版本号；解码时遇到未知版本一律拒绝，绝不静默降级。
pub const STATE_ROOT_FORMAT_VERSION: u32 = 1;

/// 对象种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    /// 资源内容。
    Blob,
    /// 资源条目集合。
    StateRoot,
    /// 快照主体。
    Snapshot,
    /// 快照签名。
    SnapshotSignature,
    /// 合并冲突对象。
    Conflict,
    /// 设备成员事件（M2）。
    MembershipEvent,
    /// 设备密钥信封（M2）。
    KeyEnvelope,
    /// 密封秘密对象（M2）。
    SealedSecret,
}

impl ObjectKind {
    /// 该种类使用的哈希域分隔标签。
    pub const fn domain(self) -> &'static str {
        match self {
            ObjectKind::Blob => "envsync:blob:v1",
            ObjectKind::StateRoot => "envsync:state:v1",
            ObjectKind::Snapshot => "envsync:snapshot:v1",
            ObjectKind::SnapshotSignature => "envsync:snapshot-signature:v1",
            ObjectKind::Conflict => "envsync:conflict:v1",
            ObjectKind::MembershipEvent => "envsync:membership-event:v1",
            ObjectKind::KeyEnvelope => "envsync:key-envelope:v1",
            ObjectKind::SealedSecret => "envsync:sealed-secret:v1",
        }
    }

    /// 稳定的短名称，用于文本表示与诊断。
    pub const fn as_str(self) -> &'static str {
        match self {
            ObjectKind::Blob => "blob",
            ObjectKind::StateRoot => "state",
            ObjectKind::Snapshot => "snapshot",
            ObjectKind::SnapshotSignature => "signature",
            ObjectKind::Conflict => "conflict",
            ObjectKind::MembershipEvent => "membership",
            ObjectKind::KeyEnvelope => "envelope",
            ObjectKind::SealedSecret => "secret",
        }
    }

    /// 由短名称解析。
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "blob" => ObjectKind::Blob,
            "state" => ObjectKind::StateRoot,
            "snapshot" => ObjectKind::Snapshot,
            "signature" => ObjectKind::SnapshotSignature,
            "conflict" => ObjectKind::Conflict,
            "membership" => ObjectKind::MembershipEvent,
            "envelope" => ObjectKind::KeyEnvelope,
            "secret" => ObjectKind::SealedSecret,
            _ => return None,
        })
    }
}

/// 后端使用的统一对象标识：种类 + 内容摘要。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectId {
    /// 对象种类。
    pub kind: ObjectKind,
    /// 内容摘要（已包含域分隔）。
    pub digest: Digest32,
}

/// 对象标识解析错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ObjectIdError {
    /// 缺少 `种类/摘要` 分隔符。
    #[error("对象标识必须形如 `kind/digest`")]
    Malformed,
    /// 种类未知。
    #[error("未知的对象种类 `{0}`")]
    UnknownKind(String),
    /// 摘要非法。
    #[error(transparent)]
    Digest(#[from] IdError),
}

impl ObjectId {
    /// 由内容字节计算对象标识。
    pub fn for_bytes(kind: ObjectKind, bytes: &[u8]) -> Self {
        ObjectId {
            kind,
            digest: Digest32::domain_hash(kind.domain(), bytes),
        }
    }

    /// 校验给定字节是否确实产生该标识。
    pub fn verifies(&self, bytes: &[u8]) -> bool {
        Digest32::domain_hash(self.kind.domain(), bytes) == self.digest
    }

    /// 摘要的十六进制表示。
    pub fn hex(&self) -> String {
        self.digest.to_hex()
    }

    /// 在后端中的相对存储路径分段：`objects/<前两位>/<其余>`。
    pub fn storage_segments(&self) -> (String, String) {
        let hex = self.digest.to_hex();
        (hex[..2].to_owned(), hex[2..].to_owned())
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.kind.as_str(), self.digest)
    }
}

impl FromStr for ObjectId {
    type Err = ObjectIdError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (kind, digest) = text.split_once('/').ok_or(ObjectIdError::Malformed)?;
        let kind =
            ObjectKind::parse(kind).ok_or_else(|| ObjectIdError::UnknownKind(kind.to_owned()))?;
        Ok(ObjectId {
            kind,
            digest: digest.parse()?,
        })
    }
}

impl From<BlobId> for ObjectId {
    fn from(value: BlobId) -> Self {
        ObjectId {
            kind: ObjectKind::Blob,
            digest: value.digest(),
        }
    }
}

impl From<StateRootId> for ObjectId {
    fn from(value: StateRootId) -> Self {
        ObjectId {
            kind: ObjectKind::StateRoot,
            digest: value.digest(),
        }
    }
}

impl From<SnapshotId> for ObjectId {
    fn from(value: SnapshotId) -> Self {
        ObjectId {
            kind: ObjectKind::Snapshot,
            digest: value.digest(),
        }
    }
}

impl From<ConflictId> for ObjectId {
    fn from(value: ConflictId) -> Self {
        ObjectId {
            kind: ObjectKind::Conflict,
            digest: value.digest(),
        }
    }
}

/// 资源内容对象。
///
/// Blob 是**裸字节**，不经过 CBOR 包装：这样任何工具都能直接读出文件内容，也避免
/// 二进制内容在编码层被再次转义。
#[derive(Clone, PartialEq, Eq)]
pub struct Blob {
    bytes: Vec<u8>,
    id: BlobId,
}

impl Blob {
    /// 由字节构造并计算标识。
    pub fn new(bytes: Vec<u8>) -> Self {
        let id = BlobId::of(&bytes);
        Blob { bytes, id }
    }

    /// 内容标识。
    pub fn id(&self) -> BlobId {
        self.id
    }

    /// 内容字节。
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// 消费自身取回字节。
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// 字节数。
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// 是否为空内容。
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for Blob {
    /// 只输出标识和长度，绝不输出内容——Blob 可能承载敏感配置。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blob({}, {} bytes)", self.id.short(), self.bytes.len())
    }
}

/// State Root：某一时刻工作区中全部资源条目的确定性集合。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateRoot {
    /// 格式版本。
    pub format_version: u32,
    /// `ResourceId -> ResourceEntry`，按资源标识排序。
    pub entries: BTreeMap<ResourceId, ResourceEntry>,
}

/// State Root 构造错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StateRootError {
    /// 条目自身不合法。
    #[error(transparent)]
    Entry(#[from] ResourceEntryError),
    /// map 的键与条目内记录的资源标识不一致。
    #[error("State Root 键 `{key}` 与条目资源 `{entry}` 不一致")]
    KeyMismatch {
        /// map 中的键。
        key: ResourceId,
        /// 条目自身记录的资源标识。
        entry: ResourceId,
    },
}

impl StateRoot {
    /// 由条目集合构造，插入顺序不影响结果。
    pub fn from_entries(
        entries: impl IntoIterator<Item = ResourceEntry>,
    ) -> Result<Self, StateRootError> {
        let mut map = BTreeMap::new();
        for entry in entries {
            entry.validate()?;
            map.insert(entry.resource.clone(), entry);
        }
        Ok(StateRoot {
            format_version: STATE_ROOT_FORMAT_VERSION,
            entries: map,
        })
    }

    /// 空 State Root。
    pub fn empty() -> Self {
        StateRoot {
            format_version: STATE_ROOT_FORMAT_VERSION,
            entries: BTreeMap::new(),
        }
    }

    /// 校验全部条目及键一致性。
    pub fn validate(&self) -> Result<(), StateRootError> {
        for (key, entry) in &self.entries {
            entry.validate()?;
            if key != &entry.resource {
                return Err(StateRootError::KeyMismatch {
                    key: key.clone(),
                    entry: entry.resource.clone(),
                });
            }
        }
        Ok(())
    }

    /// 内容标识，由 canonical 编码派生。
    pub fn id(&self) -> StateRootId {
        StateRootId::of(&self.to_canonical_vec())
    }

    /// 条目数量。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 查找条目。
    pub fn get(&self, resource: &ResourceId) -> Option<&ResourceEntry> {
        self.entries.get(resource)
    }
}

impl CborCodec for StateRoot {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Uint(self.format_version as u64),
            self.entries.to_value(),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        if items.len() != 2 {
            return Err(CborError::ArityMismatch);
        }
        let format_version = u32::from_value(&items[0])?;
        if format_version != STATE_ROOT_FORMAT_VERSION {
            return Err(CborError::UnsupportedFormatVersion {
                found: format_version,
                supported: STATE_ROOT_FORMAT_VERSION,
            });
        }
        let entries = BTreeMap::<ResourceId, ResourceEntry>::from_value(&items[1])?;
        let state = StateRoot {
            format_version,
            entries,
        };
        state
            .validate()
            .map_err(|err| CborError::InvalidValue(err.to_string()))?;
        Ok(state)
    }
}

/// 冲突种类（M1 起使用，M0 只定义 schema）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    /// 双方修改了同一文本区域。
    TextOverlap,
    /// 一方删除、另一方修改。
    DeleteModify,
    /// 结构化数据的同一键被双方修改为不同值。
    StructuredKey,
    /// 二进制内容双方均修改。
    BinaryBoth,
    /// 双方对同一资源使用了不兼容的模式或策略。
    IncompatiblePolicy,
}

crate::cbor_unit_enum!(ConflictKind {
    ConflictKind::TextOverlap => "text_overlap",
    ConflictKind::DeleteModify => "delete_modify",
    ConflictKind::StructuredKey => "structured_key",
    ConflictKind::BinaryBoth => "binary_both",
    ConflictKind::IncompatiblePolicy => "incompatible_policy",
});

/// 合并冲突对象。
///
/// 冲突 marker **绝不写入用户文件**，只以该对象形式保存，由用户显式解决。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflict {
    /// 格式版本。
    pub format_version: u32,
    /// 发生冲突的资源。
    pub resource: ResourceId,
    /// 冲突种类。
    pub kind: ConflictKind,
    /// 合并基版本的 Blob；双方均为新增时为 `None`。
    pub base: Option<BlobId>,
    /// 本地一侧的 Blob；本地删除时为 `None`。
    pub ours: Option<BlobId>,
    /// 远端一侧的 Blob；远端删除时为 `None`。
    pub theirs: Option<BlobId>,
    /// 人类可读诊断（例如冲突的 JSON Pointer 或行区间），不含文件内容。
    pub diagnostics: Vec<String>,
}

cbor_struct!(Conflict {
    format_version: u32,
    resource: ResourceId,
    kind: ConflictKind,
    base: Option<BlobId>,
    ours: Option<BlobId>,
    theirs: Option<BlobId>,
    diagnostics: Vec<String>,
});

/// 冲突对象的当前格式版本。
pub const CONFLICT_FORMAT_VERSION: u32 = 1;

impl Conflict {
    /// 内容标识。
    pub fn id(&self) -> ConflictId {
        ConflictId::of(&self.to_canonical_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::ResourceId;
    use crate::resource::{DesiredDisposition, FileMode, ResourcePolicy};

    fn entry(name: &str, content: &[u8]) -> ResourceEntry {
        ResourceEntry {
            resource: ResourceId::parse(name).unwrap(),
            disposition: DesiredDisposition::Managed,
            blob: Some(BlobId::of(content)),
            mode: FileMode::FullFile,
            policy: ResourcePolicy::default(),
        }
    }

    #[test]
    fn identical_bytes_always_produce_identical_blob_id() {
        let a = Blob::new(b"hello world".to_vec());
        let b = Blob::new(b"hello world".to_vec());
        assert_eq!(a.id(), b.id());
        assert_ne!(a.id(), Blob::new(b"hello worl".to_vec()).id());
    }

    #[test]
    fn blob_debug_never_leaks_content() {
        let blob = Blob::new(b"super-secret-token".to_vec());
        let rendered = format!("{blob:?}");
        assert!(
            !rendered.contains("secret"),
            "Blob 的 Debug 输出泄露了内容：{rendered}"
        );
        assert!(rendered.contains("18 bytes"));
    }

    #[test]
    fn state_root_id_is_independent_of_insertion_order() {
        let forward = StateRoot::from_entries([
            entry("shell/zsh/main", b"a"),
            entry("git/config", b"b"),
            entry("terminal/wezterm", b"c"),
        ])
        .unwrap();
        let backward = StateRoot::from_entries([
            entry("terminal/wezterm", b"c"),
            entry("git/config", b"b"),
            entry("shell/zsh/main", b"a"),
        ])
        .unwrap();
        assert_eq!(forward.id(), backward.id());
        assert_eq!(forward.to_canonical_vec(), backward.to_canonical_vec());
    }

    #[test]
    fn state_root_id_changes_with_content() {
        let base = StateRoot::from_entries([entry("shell/zsh/main", b"a")]).unwrap();
        let changed = StateRoot::from_entries([entry("shell/zsh/main", b"b")]).unwrap();
        assert_ne!(base.id(), changed.id());
    }

    #[test]
    fn state_root_rejects_unknown_format_version() {
        let state = StateRoot::from_entries([entry("shell/zsh/main", b"a")]).unwrap();
        let mut value = state.to_value();
        if let Value::Array(items) = &mut value {
            items[0] = Value::Uint(99);
        }
        let bytes = crate::cbor::encode(&value);
        assert_eq!(
            StateRoot::from_canonical_slice(&bytes),
            Err(CborError::UnsupportedFormatVersion {
                found: 99,
                supported: 1
            })
        );
    }

    #[test]
    fn state_root_round_trips_and_rejects_non_canonical_bytes() {
        let state = StateRoot::from_entries([entry("shell/zsh/main", b"a")]).unwrap();
        let bytes = state.to_canonical_vec();
        assert_eq!(StateRoot::from_canonical_slice(&bytes).unwrap(), state);

        // 在末尾追加垃圾字节后必须被拒绝。
        let mut corrupted = bytes.clone();
        corrupted.push(0x00);
        assert!(StateRoot::from_canonical_slice(&corrupted).is_err());
    }

    #[test]
    fn object_id_verifies_content_and_separates_kinds() {
        let bytes = b"payload".as_slice();
        let blob = ObjectId::for_bytes(ObjectKind::Blob, bytes);
        let state = ObjectId::for_bytes(ObjectKind::StateRoot, bytes);
        assert_ne!(blob.digest, state.digest, "不同种类必须有不同摘要");
        assert!(blob.verifies(bytes));
        assert!(!blob.verifies(b"payload!"));
    }

    #[test]
    fn object_id_text_round_trip() {
        let id = ObjectId::for_bytes(ObjectKind::Snapshot, b"x");
        let text = id.to_string();
        assert!(text.starts_with("snapshot/"));
        assert_eq!(text.parse::<ObjectId>().unwrap(), id);
        assert_eq!(
            "nope/".parse::<ObjectId>(),
            Err(ObjectIdError::UnknownKind("nope".into()))
        );
        assert_eq!("nodelim".parse::<ObjectId>(), Err(ObjectIdError::Malformed));
    }

    #[test]
    fn object_id_from_blob_id_matches_direct_construction() {
        let bytes = b"content".as_slice();
        assert_eq!(
            ObjectId::from(BlobId::of(bytes)),
            ObjectId::for_bytes(ObjectKind::Blob, bytes)
        );
    }

    #[test]
    fn conflict_round_trips() {
        let conflict = Conflict {
            format_version: CONFLICT_FORMAT_VERSION,
            resource: ResourceId::parse("git/config").unwrap(),
            kind: ConflictKind::StructuredKey,
            base: Some(BlobId::of(b"base")),
            ours: Some(BlobId::of(b"ours")),
            theirs: None,
            diagnostics: vec!["/user/email".into()],
        };
        let bytes = conflict.to_canonical_vec();
        assert_eq!(Conflict::from_canonical_slice(&bytes).unwrap(), conflict);
        assert_eq!(
            conflict.id(),
            Conflict::from_canonical_slice(&bytes).unwrap().id()
        );
    }
}
