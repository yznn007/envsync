//! Vault 索引的纯线格式模型。
//!
//! 此模块只定义可持久化的公开引用关系：Vault Index、成员事件对象、设备密钥信封、
//! 密封秘密对象和恢复包。它不读取后端、不访问系统安全存储，也不持有任何私钥；因此
//! `envsync-core` 与密封 Gist backend 可以复用同一份 canonical CBOR schema。

use envsync_domain::cbor::{CborCodec, CborError, Value};
use envsync_domain::{ObjectId, ResourceId, WorkspaceId};

use crate::sealed::SecretId;

/// 索引对象的格式版本。字段增删都必须提升它。
pub const VAULT_INDEX_FORMAT_VERSION: u32 = 1;

/// 快照 metadata 中指向 Vault Index 对象的键名。
///
/// 这是持久化契约：改名会让已发布的快照看起来没有 Vault。值是 `ObjectId` 的文本形式，
/// 但该对象本身（含 Secret ID）在 Gist Bundle 中必须保持密封。
pub const VAULT_INDEX_METADATA_KEY: &str = "envsync.vault.index";

/// 一个工作区允许保存的秘密条数上限。
///
/// 上限存在的意义不是性能，而是**在做任何解码之前**就能拒绝一个恶意构造的巨大索引。
pub const MAX_SECRETS: usize = 4096;

/// 索引里的一条秘密引用。
///
/// **这里没有值**：只有逻辑标识、密封对象标识、加密时的纪元和引用它的资源。尽管这些
/// 字段可被普通对象后端存储，Gist Bundle 会把整条记录留在其 AEAD 密封 payload 内。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    /// 逻辑标识。
    pub id: SecretId,
    /// 密封对象在后端中的标识。
    pub object: ObjectId,
    /// 密封时使用的数据密钥纪元。
    pub epoch: u64,
    /// 最近一次写入时刻（Unix 毫秒）。
    pub updated_at_unix_ms: u64,
    /// 引用该秘密的资源，按资源标识排序。
    pub referenced_by: Vec<ResourceId>,
}

impl CborCodec for SecretRef {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Text(self.id.as_str().to_owned()),
            Value::Text(self.object.to_string()),
            Value::Uint(self.epoch),
            Value::Uint(self.updated_at_unix_ms),
            self.referenced_by.to_value(),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        if items.len() != 5 {
            return Err(CborError::ArityMismatch);
        }
        Ok(SecretRef {
            id: SecretId::parse(items[0].as_text()?)
                .map_err(|error| CborError::InvalidValue(error.to_string()))?,
            object: items[1]
                .as_text()?
                .parse::<ObjectId>()
                .map_err(|error| CborError::InvalidValue(error.to_string()))?,
            epoch: items[2].as_uint()?,
            updated_at_unix_ms: items[3].as_uint()?,
            referenced_by: Vec::<ResourceId>::from_value(&items[4])?,
        })
    }
}

/// Vault 索引对象：一次发布中“后端上有什么”的完整清单。
///
/// 它是快照与秘密之间的唯一桥梁：快照 metadata 里放它的对象标识，它里面放
/// [`SecretRef`]、成员事件对象和当前纪元的信封对象。它本身不包含私钥或秘密值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultIndex {
    /// 格式版本。
    pub format_version: u32,
    /// 所属工作区。
    pub workspace: WorkspaceId,
    /// 当前密钥纪元。
    pub epoch: u64,
    /// 成员事件对象，按 sequence 升序；第一项一定是 genesis。
    pub membership: Vec<ObjectId>,
    /// 当前纪元的设备信封对象。
    pub envelopes: Vec<ObjectId>,
    /// 秘密引用，按逻辑标识升序。
    pub secrets: Vec<SecretRef>,
    /// 恢复包对象；尚未创建恢复短语时为 `None`。
    pub recovery: Option<ObjectId>,
}

impl VaultIndex {
    /// 建立一个空索引。
    pub fn empty(workspace: WorkspaceId, epoch: u64) -> Self {
        VaultIndex {
            format_version: VAULT_INDEX_FORMAT_VERSION,
            workspace,
            epoch,
            membership: Vec::new(),
            envelopes: Vec::new(),
            secrets: Vec::new(),
            recovery: None,
        }
    }

    /// 按逻辑标识查找一条秘密引用。
    pub fn find(&self, id: &SecretId) -> Option<&SecretRef> {
        self.secrets.iter().find(|entry| &entry.id == id)
    }

    /// 插入或替换一条秘密引用，并保持按逻辑标识升序。
    pub fn upsert(&mut self, entry: SecretRef) {
        match self.secrets.iter().position(|item| item.id == entry.id) {
            Some(index) => self.secrets[index] = entry,
            None => {
                self.secrets.push(entry);
                self.secrets
                    .sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
            }
        }
    }

    /// 移除一条秘密引用，返回是否真的移除了。
    pub fn remove(&mut self, id: &SecretId) -> bool {
        let Some(index) = self.secrets.iter().position(|item| &item.id == id) else {
            return false;
        };
        self.secrets.remove(index);
        true
    }

    /// 返回 Index 直接引用的全部对象。
    ///
    /// 返回顺序是成员事件、当前纪元信封、密封秘密、恢复包；调用方若需要稳定存储顺序，
    /// 应按 [`ObjectId`] 再排序。该列表故意不含 Index 自身。
    pub fn referenced_objects(&self) -> Vec<ObjectId> {
        let mut objects = Vec::with_capacity(
            self.membership.len()
                + self.envelopes.len()
                + self.secrets.len()
                + usize::from(self.recovery.is_some()),
        );
        objects.extend(self.membership.iter().copied());
        objects.extend(self.envelopes.iter().copied());
        objects.extend(self.secrets.iter().map(|secret| secret.object));
        objects.extend(self.recovery);
        objects
    }
}

impl CborCodec for VaultIndex {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Uint(self.format_version as u64),
            self.workspace.to_value(),
            Value::Uint(self.epoch),
            Value::Array(
                self.membership
                    .iter()
                    .map(|id| Value::Text(id.to_string()))
                    .collect(),
            ),
            Value::Array(
                self.envelopes
                    .iter()
                    .map(|id| Value::Text(id.to_string()))
                    .collect(),
            ),
            self.secrets.to_value(),
            match self.recovery {
                Some(id) => Value::Text(id.to_string()),
                None => Value::Null,
            },
        ])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        if items.len() != 7 {
            return Err(CborError::ArityMismatch);
        }
        let format_version = u32::from_value(&items[0])?;
        if format_version != VAULT_INDEX_FORMAT_VERSION {
            return Err(CborError::UnsupportedFormatVersion {
                found: format_version,
                supported: VAULT_INDEX_FORMAT_VERSION,
            });
        }
        let secrets = Vec::<SecretRef>::from_value(&items[5])?;
        if secrets.len() > MAX_SECRETS {
            return Err(CborError::InvalidValue(format!(
                "秘密数量 {} 超过上限 {MAX_SECRETS}",
                secrets.len()
            )));
        }
        Ok(VaultIndex {
            format_version,
            workspace: WorkspaceId::from_value(&items[1])?,
            epoch: items[2].as_uint()?,
            membership: object_list(&items[3])?,
            envelopes: object_list(&items[4])?,
            secrets,
            recovery: match &items[6] {
                Value::Null => None,
                other => Some(
                    other
                        .as_text()?
                        .parse::<ObjectId>()
                        .map_err(|error| CborError::InvalidValue(error.to_string()))?,
                ),
            },
        })
    }
}

fn object_list(value: &Value) -> Result<Vec<ObjectId>, CborError> {
    value
        .as_array()?
        .iter()
        .map(|item| {
            item.as_text()?
                .parse::<ObjectId>()
                .map_err(|error| CborError::InvalidValue(error.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use envsync_domain::cbor::{encode, CborCodec, Value};
    use envsync_domain::{ObjectId, ObjectKind, ResourceId, WorkspaceId};

    use super::{SecretRef, VaultIndex};
    use crate::sealed::SecretId;

    #[test]
    fn vault_index_round_trips_through_canonical_cbor() {
        let workspace = WorkspaceId::generate();
        let mut index = VaultIndex::empty(workspace, 3);
        index
            .membership
            .push(ObjectId::for_bytes(ObjectKind::MembershipEvent, b"genesis"));
        index
            .envelopes
            .push(ObjectId::for_bytes(ObjectKind::KeyEnvelope, b"envelope"));
        index.upsert(SecretRef {
            id: SecretId::parse("ci/npm-token").expect("标识"),
            object: ObjectId::for_bytes(ObjectKind::SealedSecret, b"sealed"),
            epoch: 3,
            updated_at_unix_ms: 1_700_000_000_000,
            referenced_by: vec![ResourceId::parse("shell/zsh/main").expect("资源")],
        });
        index.recovery = Some(ObjectId::for_bytes(ObjectKind::Blob, b"recovery"));

        let bytes = index.to_canonical_vec();
        assert_eq!(
            VaultIndex::from_canonical_slice(&bytes).expect("还原"),
            index
        );
    }

    #[test]
    fn vault_index_keeps_secrets_sorted_and_supports_removal() {
        let mut index = VaultIndex::empty(WorkspaceId::generate(), 1);
        for id in ["z/last", "a/first", "m/middle"] {
            index.upsert(SecretRef {
                id: SecretId::parse(id).expect("标识"),
                object: ObjectId::for_bytes(ObjectKind::SealedSecret, id.as_bytes()),
                epoch: 1,
                updated_at_unix_ms: 0,
                referenced_by: Vec::new(),
            });
        }
        let ids: Vec<&str> = index.secrets.iter().map(|item| item.id.as_str()).collect();
        assert_eq!(ids, ["a/first", "m/middle", "z/last"]);

        let target = SecretId::parse("m/middle").expect("标识");
        assert!(index.remove(&target));
        assert!(!index.remove(&target));
        assert_eq!(index.secrets.len(), 2);
    }

    #[test]
    fn vault_index_rejects_an_unknown_format_version() {
        let index = VaultIndex::empty(WorkspaceId::generate(), 1);
        let mut value = index.to_value();
        if let Value::Array(items) = &mut value {
            items[0] = Value::Uint(99);
        }
        let bytes = encode(&value);
        assert!(VaultIndex::from_canonical_slice(&bytes).is_err());
    }

    #[test]
    fn referenced_objects_excludes_index_and_preserves_all_dependencies() {
        let mut index = VaultIndex::empty(WorkspaceId::generate(), 1);
        let membership = ObjectId::for_bytes(ObjectKind::MembershipEvent, b"member");
        let envelope = ObjectId::for_bytes(ObjectKind::KeyEnvelope, b"envelope");
        let secret = ObjectId::for_bytes(ObjectKind::SealedSecret, b"secret");
        let recovery = ObjectId::for_bytes(ObjectKind::Blob, b"recovery");
        index.membership.push(membership);
        index.envelopes.push(envelope);
        index.upsert(SecretRef {
            id: SecretId::parse("ci/token").expect("标识"),
            object: secret,
            epoch: 1,
            updated_at_unix_ms: 0,
            referenced_by: Vec::new(),
        });
        index.recovery = Some(recovery);

        assert_eq!(
            index.referenced_objects(),
            vec![membership, envelope, secret, recovery]
        );
    }
}
