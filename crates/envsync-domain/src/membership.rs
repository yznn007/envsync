//! 设备成员事件链的领域模型。
//!
//! 一个工作区的成员关系不是一张可以被后端随意改写的表，而是一条**签名事件链**：
//!
//! ```text
//! genesis (seq 0, previous = None)
//!    └─ e1 (seq 1, previous = digest(genesis))
//!         └─ e2 (seq 2, previous = digest(e1))
//!              └─ ...
//! ```
//!
//! 每个事件由一台**当前有效的管理员设备**签名，签名覆盖除签名字段之外的全部内容
//! （见 [`MembershipEvent::signing_payload`]）。设备只接受从**自己已经信任的
//! genesis** 延伸出来的链，因此后端即使完全被攻击者控制，也只能做「不给数据」，
//! 无法伪造成员变更。
//!
//! ## 本模块的边界
//!
//! 领域层**不依赖 `envsync-crypto`**：这里只定义结构、编码与摘要规则，把公钥当作
//! 不透明的 64 字节（[`DevicePublicBytes`]）保存。验签、授权判定和链回放都在
//! `envsync-core` 的 `membership` 模块里完成，那里才允许依赖密码学实现。
//!
//! ## 三条结构不变量
//!
//! 1. **sequence 0 当且仅当 `previous` 为 `None`，并且动作必须是
//!    [`MembershipAction::Genesis`]。** 见 [`MembershipEvent::validate`]。
//! 2. **事件摘要覆盖整个事件（含签名）。** 因此换一枚签名就是另一个事件，无法在
//!    保持链接不变的前提下替换签名。
//! 3. **[`MembershipState`] 只包含当前有效成员。** 被撤销的设备直接从
//!    [`MembershipState::members`] 中移除，不留「已撤销」的软状态，避免调用方误用。

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::cbor::{CborCodec, CborError, Value};
use crate::id::{DeviceId, Digest32, WorkspaceId};

/// 成员事件的当前格式版本。
pub const MEMBERSHIP_EVENT_FORMAT_VERSION: u32 = 1;

/// 一条成员链允许回放的最大事件数（含 genesis）。
///
/// 验证器是纯函数，但仍然要防「超长链」这种资源耗尽输入：先做数量限制，再做逐事件
/// 的曲线运算。4096 条事件足以覆盖任何真实团队的设备增删历史。
pub const MAX_MEMBERSHIP_EVENTS: usize = 4096;

/// 设备公开材料的字节长度：`X25519 公钥(32) || Ed25519 公钥(32)`。
pub const DEVICE_PUBLIC_LEN: usize = 64;

/// genesis 事件必须使用的密钥纪元。
pub const GENESIS_EPOCH: u64 = 1;

/// 事件摘要使用的哈希域分隔标签。
pub const MEMBERSHIP_EVENT_DIGEST_DOMAIN: &str = "envsync:membership-event-digest:v1";

/// 成员事件的结构性错误。
///
/// 这些是**不需要密码学就能判定**的问题；验签与授权失败属于 `envsync-core` 的
/// `MembershipError`。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MembershipEventError {
    /// 格式版本未知。
    #[error("未知的成员事件格式版本 {found}，本实现支持 {supported}")]
    UnsupportedFormatVersion {
        /// 输入中的版本号。
        found: u32,
        /// 本实现支持的版本号。
        supported: u32,
    },
    /// genesis 事件必须是 sequence 0 且不带 `previous`。
    #[error("genesis 事件必须是 sequence 0 且不携带 previous")]
    MalformedGenesis,
    /// 非 genesis 事件必须携带 `previous`。
    #[error("sequence {0} 的事件必须携带 previous 摘要")]
    MissingPrevious(u64),
    /// sequence 0 上出现了非 Genesis 动作。
    #[error("sequence 0 只能承载 Genesis 动作")]
    NonGenesisAtZero,
    /// 签名字段长度不符。
    #[error("签名长度不符：期望 {expected} 字节，实际 {found} 字节")]
    SignatureLength {
        /// 期望长度。
        expected: usize,
        /// 实际长度。
        found: usize,
    },
    /// 主体设备标识与公钥派生结果不一致。
    #[error("主体设备标识与其公钥派生结果不一致")]
    SubjectKeyMismatch,
    /// 设备公开材料的文本表示非法。
    #[error("设备公开材料必须是 {expected} 个小写十六进制字符")]
    PublicKeyMalformed {
        /// 期望的字符数。
        expected: usize,
    },
}

/// 设备公开材料的原始字节：`X25519 公钥 || Ed25519 公钥`。
///
/// 领域层刻意只保存字节而不解析曲线点：解析属于密码学层的职责，放在这里会让
/// `envsync-domain` 被迫依赖 `envsync-crypto`。合法性检查由 `envsync-core` 在验签时
/// 一并完成。
///
/// 文本表示是 128 个小写十六进制字符，`serde` 也走同一条路径，保证一份公钥在 JSON、
/// CBOR 和日志里的写法唯一。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DevicePublicBytes([u8; DEVICE_PUBLIC_LEN]);

impl DevicePublicBytes {
    /// 由完整的 64 字节构造。
    pub const fn from_bytes(bytes: [u8; DEVICE_PUBLIC_LEN]) -> Self {
        DevicePublicBytes(bytes)
    }

    /// 由两把公钥拼接构造。
    pub fn from_parts(x25519: [u8; 32], ed25519: [u8; 32]) -> Self {
        let mut bytes = [0u8; DEVICE_PUBLIC_LEN];
        bytes[..32].copy_from_slice(&x25519);
        bytes[32..].copy_from_slice(&ed25519);
        DevicePublicBytes(bytes)
    }

    /// 由切片构造，长度不符时返回 `None`。
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        <[u8; DEVICE_PUBLIC_LEN]>::try_from(bytes)
            .ok()
            .map(DevicePublicBytes)
    }

    /// 完整字节。
    pub const fn as_bytes(&self) -> &[u8; DEVICE_PUBLIC_LEN] {
        &self.0
    }

    /// X25519 公钥（HPKE 收件密钥）。
    pub fn x25519(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.0[..32]);
        out
    }

    /// Ed25519 公钥（验签密钥）。
    pub fn ed25519(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.0[32..]);
        out
    }

    /// 由公开材料派生设备标识。
    ///
    /// 与 [`crate::id::DeviceId::derive`] 使用同一条派生规则，因此改动任意一把公钥的
    /// 任意一位都会改变结果——攻击者无法在保持 `DeviceId` 不变的前提下换掉其中一把
    /// 密钥（例如把信封重定向到自己控制的 X25519 私钥）。
    pub fn device_id(&self) -> DeviceId {
        DeviceId::derive(&self.0)
    }

    /// 128 个小写十六进制字符。
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(DEVICE_PUBLIC_LEN * 2);
        for byte in self.0 {
            out.push(char::from_digit((byte >> 4) as u32, 16).expect("半字节始终有效"));
            out.push(char::from_digit((byte & 0x0f) as u32, 16).expect("半字节始终有效"));
        }
        out
    }

    /// 从十六进制文本解析；拒绝大写，保证同一份公钥只有一种文本表示。
    pub fn parse_hex(text: &str) -> Option<Self> {
        if text.len() != DEVICE_PUBLIC_LEN * 2 {
            return None;
        }
        let mut bytes = [0u8; DEVICE_PUBLIC_LEN];
        for (index, chunk) in text.as_bytes().chunks_exact(2).enumerate() {
            if chunk[0].is_ascii_uppercase() || chunk[1].is_ascii_uppercase() {
                return None;
            }
            let hi = (chunk[0] as char).to_digit(16)?;
            let lo = (chunk[1] as char).to_digit(16)?;
            bytes[index] = ((hi << 4) | lo) as u8;
        }
        Some(DevicePublicBytes(bytes))
    }
}

impl fmt::Debug for DevicePublicBytes {
    /// 公钥是公开材料，但完整回显对日志没有价值；只显示派生出的设备短标识。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DevicePublicBytes({})", self.device_id().short())
    }
}

impl fmt::Display for DevicePublicBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl From<DevicePublicBytes> for String {
    fn from(value: DevicePublicBytes) -> Self {
        value.to_hex()
    }
}

impl TryFrom<String> for DevicePublicBytes {
    type Error = MembershipEventError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        DevicePublicBytes::parse_hex(&value).ok_or(MembershipEventError::PublicKeyMalformed {
            expected: DEVICE_PUBLIC_LEN * 2,
        })
    }
}

impl CborCodec for DevicePublicBytes {
    fn to_value(&self) -> Value {
        Value::Bytes(self.0.to_vec())
    }
    fn from_value(value: &Value) -> Result<Self, CborError> {
        Ok(DevicePublicBytes(<[u8; DEVICE_PUBLIC_LEN]>::from_value(
            value,
        )?))
    }
}

/// 成员角色。
///
/// 只有两级：[`MemberRole::Admin`] 可以变更成员关系，[`MemberRole::Member`] 只能读写
/// 秘密内容。刻意不做更细的权限矩阵——角色越多，授权判定的攻击面越大。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberRole {
    /// 管理员：可以添加成员、提升成员、撤销设备。
    Admin,
    /// 普通成员：不能变更成员关系。
    Member,
}

impl MemberRole {
    /// 稳定的短名称，用于持久化与诊断。
    pub const fn as_str(self) -> &'static str {
        match self {
            MemberRole::Admin => "admin",
            MemberRole::Member => "member",
        }
    }

    /// 由短名称解析；未知取值返回 `None`。
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "admin" => MemberRole::Admin,
            "member" => MemberRole::Member,
            _ => return None,
        })
    }

    /// 是否有权变更成员关系。
    pub const fn can_administer(self) -> bool {
        matches!(self, MemberRole::Admin)
    }
}

crate::cbor_unit_enum!(MemberRole {
    MemberRole::Admin => "admin",
    MemberRole::Member => "member",
});

/// 成员事件承载的动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipAction {
    /// 创建工作区并把签名者本身登记为唯一管理员。整条链上只允许出现一次。
    Genesis {
        /// 被登记的设备。
        subject: DeviceId,
        /// 该设备的公开材料。
        public: DevicePublicBytes,
    },
    /// 添加一台新设备。
    AddMember {
        /// 被添加的设备。
        subject: DeviceId,
        /// 该设备的公开材料。
        public: DevicePublicBytes,
        /// 初始角色。
        role: MemberRole,
    },
    /// 把一个普通成员提升为管理员。
    Promote {
        /// 被提升的设备。
        subject: DeviceId,
    },
    /// 撤销一台设备。撤销必须同时推进密钥纪元，见 `envsync-core` 的链验证器。
    Revoke {
        /// 被撤销的设备。
        subject: DeviceId,
    },
}

impl MembershipAction {
    /// 稳定的动作短名，用于持久化索引与诊断。
    pub const fn kind(&self) -> &'static str {
        match self {
            MembershipAction::Genesis { .. } => "genesis",
            MembershipAction::AddMember { .. } => "add_member",
            MembershipAction::Promote { .. } => "promote",
            MembershipAction::Revoke { .. } => "revoke",
        }
    }

    /// 动作作用的设备。
    pub const fn subject(&self) -> DeviceId {
        match self {
            MembershipAction::Genesis { subject, .. }
            | MembershipAction::AddMember { subject, .. }
            | MembershipAction::Promote { subject }
            | MembershipAction::Revoke { subject } => *subject,
        }
    }

    /// 动作携带的公开材料；`Promote` 与 `Revoke` 不携带。
    pub const fn public(&self) -> Option<DevicePublicBytes> {
        match self {
            MembershipAction::Genesis { public, .. }
            | MembershipAction::AddMember { public, .. } => Some(*public),
            MembershipAction::Promote { .. } | MembershipAction::Revoke { .. } => None,
        }
    }

    /// 是否为撤销动作（撤销是唯一允许推进密钥纪元的动作）。
    pub const fn is_revoke(&self) -> bool {
        matches!(self, MembershipAction::Revoke { .. })
    }

    /// 若动作携带公开材料，校验主体标识确实由该公钥派生。
    pub fn validate(&self) -> Result<(), MembershipEventError> {
        if let Some(public) = self.public() {
            if public.device_id() != self.subject() {
                return Err(MembershipEventError::SubjectKeyMismatch);
            }
        }
        Ok(())
    }
}

impl CborCodec for MembershipAction {
    fn to_value(&self) -> Value {
        // 判别式是文本而不是整数：整数判别式在人工排查线格式时毫无意义，而文本判别式
        // 的字节顺序也天然稳定。
        match self {
            MembershipAction::Genesis { subject, public } => Value::Array(vec![
                Value::Text("genesis".to_owned()),
                subject.to_value(),
                public.to_value(),
            ]),
            MembershipAction::AddMember {
                subject,
                public,
                role,
            } => Value::Array(vec![
                Value::Text("add_member".to_owned()),
                subject.to_value(),
                public.to_value(),
                role.to_value(),
            ]),
            MembershipAction::Promote { subject } => {
                Value::Array(vec![Value::Text("promote".to_owned()), subject.to_value()])
            }
            MembershipAction::Revoke { subject } => {
                Value::Array(vec![Value::Text("revoke".to_owned()), subject.to_value()])
            }
        }
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        let tag = items
            .first()
            .ok_or(CborError::ArityMismatch)?
            .as_text()?
            .to_owned();
        let expect = |wanted: usize| -> Result<(), CborError> {
            if items.len() == wanted {
                Ok(())
            } else {
                Err(CborError::ArityMismatch)
            }
        };
        match tag.as_str() {
            "genesis" => {
                expect(3)?;
                Ok(MembershipAction::Genesis {
                    subject: DeviceId::from_value(&items[1])?,
                    public: DevicePublicBytes::from_value(&items[2])?,
                })
            }
            "add_member" => {
                expect(4)?;
                Ok(MembershipAction::AddMember {
                    subject: DeviceId::from_value(&items[1])?,
                    public: DevicePublicBytes::from_value(&items[2])?,
                    role: MemberRole::from_value(&items[3])?,
                })
            }
            "promote" => {
                expect(2)?;
                Ok(MembershipAction::Promote {
                    subject: DeviceId::from_value(&items[1])?,
                })
            }
            "revoke" => {
                expect(2)?;
                Ok(MembershipAction::Revoke {
                    subject: DeviceId::from_value(&items[1])?,
                })
            }
            other => Err(CborError::UnknownVariant(other.to_owned())),
        }
    }
}

/// 一条成员事件。
///
/// 字段顺序即 canonical CBOR 的数组顺序，任何增删都必须提升
/// [`MEMBERSHIP_EVENT_FORMAT_VERSION`]。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipEvent {
    /// 格式版本。
    pub format_version: u32,
    /// 所属工作区；同时被签名覆盖，跨工作区重放会验签失败。
    pub workspace: WorkspaceId,
    /// 链上位置，从 0（genesis）开始连续递增。
    pub sequence: u64,
    /// 前一事件的 canonical 摘要；genesis 为 `None`。
    pub previous: Option<Digest32>,
    /// 本事件生效后的密钥纪元。
    pub epoch: u64,
    /// 签发该事件的设备。
    pub actor: DeviceId,
    /// 事件动作。
    pub action: MembershipAction,
    /// 创建时刻（Unix 毫秒）。
    pub created_at_unix_ms: u64,
    /// `actor` 对 [`MembershipEvent::signing_payload`] 的 Ed25519 签名。
    pub signature: Vec<u8>,
}

impl MembershipEvent {
    /// 待签的 canonical 字节：**除签名之外**的全部字段。
    ///
    /// 之所以单独构造而不是「整个事件去掉最后一项」，是为了让「到底签了什么」可以
    /// 被独立复现——任何人拿到事件都能重新算出这串字节并自行验签。
    pub fn signing_payload(&self) -> Vec<u8> {
        crate::cbor::encode(&Value::Array(vec![
            Value::Uint(self.format_version as u64),
            self.workspace.to_value(),
            Value::Uint(self.sequence),
            self.previous.to_value(),
            Value::Uint(self.epoch),
            self.actor.to_value(),
            self.action.to_value(),
            Value::Uint(self.created_at_unix_ms),
        ]))
    }

    /// 事件摘要，覆盖**整个事件（含签名）**。
    ///
    /// 后继事件的 `previous` 指向的就是它。把签名纳入摘要意味着「换一枚签名」等价于
    /// 「换一个事件」：攻击者无法在保持链接不变的情况下替换签名。
    pub fn digest(&self) -> Digest32 {
        Digest32::domain_hash(MEMBERSHIP_EVENT_DIGEST_DOMAIN, &self.to_canonical_vec())
    }

    /// 是否为 genesis 事件。
    pub fn is_genesis(&self) -> bool {
        self.sequence == 0 && matches!(self.action, MembershipAction::Genesis { .. })
    }

    /// 结构性校验（不含任何密码学运算）。
    pub fn validate(&self) -> Result<(), MembershipEventError> {
        if self.format_version != MEMBERSHIP_EVENT_FORMAT_VERSION {
            return Err(MembershipEventError::UnsupportedFormatVersion {
                found: self.format_version,
                supported: MEMBERSHIP_EVENT_FORMAT_VERSION,
            });
        }
        match (self.sequence, &self.previous) {
            (0, Some(_)) => return Err(MembershipEventError::MalformedGenesis),
            (0, None) => {
                if !matches!(self.action, MembershipAction::Genesis { .. }) {
                    return Err(MembershipEventError::NonGenesisAtZero);
                }
            }
            (sequence, None) => return Err(MembershipEventError::MissingPrevious(sequence)),
            (_, Some(_)) => {}
        }
        if self.signature.len() != crate::membership::SIGNATURE_LEN {
            return Err(MembershipEventError::SignatureLength {
                expected: crate::membership::SIGNATURE_LEN,
                found: self.signature.len(),
            });
        }
        self.action.validate()
    }
}

/// Ed25519 签名的字节长度。
///
/// 领域层不依赖 `envsync-crypto`，因此这里独立声明一次；两处不一致会被
/// `envsync-core` 的测试立刻发现。
pub const SIGNATURE_LEN: usize = 64;

impl CborCodec for MembershipEvent {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Uint(self.format_version as u64),
            self.workspace.to_value(),
            Value::Uint(self.sequence),
            self.previous.to_value(),
            Value::Uint(self.epoch),
            self.actor.to_value(),
            self.action.to_value(),
            Value::Uint(self.created_at_unix_ms),
            Value::Bytes(self.signature.clone()),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        if items.len() != 9 {
            return Err(CborError::ArityMismatch);
        }
        let format_version = u32::from_value(&items[0])?;
        if format_version != MEMBERSHIP_EVENT_FORMAT_VERSION {
            return Err(CborError::UnsupportedFormatVersion {
                found: format_version,
                supported: MEMBERSHIP_EVENT_FORMAT_VERSION,
            });
        }
        let event = MembershipEvent {
            format_version,
            workspace: WorkspaceId::from_value(&items[1])?,
            sequence: u64::from_value(&items[2])?,
            previous: Option::<Digest32>::from_value(&items[3])?,
            epoch: u64::from_value(&items[4])?,
            actor: DeviceId::from_value(&items[5])?,
            action: MembershipAction::from_value(&items[6])?,
            created_at_unix_ms: u64::from_value(&items[7])?,
            signature: Vec::<u8>::from_value(&items[8])?,
        };
        event
            .validate()
            .map_err(|error| CborError::InvalidValue(error.to_string()))?;
        Ok(event)
    }
}

/// 一条成员记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRecord {
    /// 设备标识。
    pub device: DeviceId,
    /// 设备公开材料。
    pub public: DevicePublicBytes,
    /// 当前角色。
    pub role: MemberRole,
    /// 该设备被加入时所在的 sequence。
    pub added_at_sequence: u64,
}

crate::cbor_struct!(MemberRecord {
    device: DeviceId,
    public: DevicePublicBytes,
    role: MemberRole,
    added_at_sequence: u64,
});

/// 回放整条成员链之后得到的状态。
///
/// **只包含当前有效成员**：被撤销的设备直接从 [`MembershipState::members`] 中消失。
/// 「谁曾经被撤销过」属于历史，需要时回放事件即可，不在状态里保留软删除标记——
/// 那种标记非常容易被调用方误当作「仍然是成员」。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipState {
    /// 当前有效成员，按设备标识排序。
    pub members: BTreeMap<DeviceId, MemberRecord>,
    /// 当前密钥纪元。
    pub epoch: u64,
    /// 已验证的链头摘要。
    pub head: Digest32,
    /// 链头所在的 sequence。
    pub sequence: u64,
}

impl MembershipState {
    /// 查询一台设备的成员记录。
    pub fn member(&self, device: &DeviceId) -> Option<&MemberRecord> {
        self.members.get(device)
    }

    /// 该设备当前是否为有效成员。
    pub fn contains(&self, device: &DeviceId) -> bool {
        self.members.contains_key(device)
    }

    /// 该设备当前是否为管理员。
    pub fn is_admin(&self, device: &DeviceId) -> bool {
        self.members
            .get(device)
            .is_some_and(|record| record.role.can_administer())
    }

    /// 当前管理员数量。链的不变量保证它**永远 >= 1**。
    pub fn admin_count(&self) -> usize {
        self.members
            .values()
            .filter(|record| record.role.can_administer())
            .count()
    }

    /// 当前有效成员数量。
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// 成员集合是否为空。链的不变量保证它**永远为 false**。
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public(seed: u8) -> DevicePublicBytes {
        DevicePublicBytes::from_parts([seed; 32], [seed ^ 0xff; 32])
    }

    fn genesis(signature: Vec<u8>) -> MembershipEvent {
        let public = public(1);
        MembershipEvent {
            format_version: MEMBERSHIP_EVENT_FORMAT_VERSION,
            workspace: WorkspaceId::from_uuid(uuid::Uuid::nil()),
            sequence: 0,
            previous: None,
            epoch: GENESIS_EPOCH,
            actor: public.device_id(),
            action: MembershipAction::Genesis {
                subject: public.device_id(),
                public,
            },
            created_at_unix_ms: 1_700_000_000_000,
            signature,
        }
    }

    #[test]
    fn device_public_bytes_round_trips_through_hex_and_cbor() {
        let value = public(7);
        assert_eq!(DevicePublicBytes::parse_hex(&value.to_hex()), Some(value));
        assert_eq!(
            DevicePublicBytes::from_canonical_slice(&value.to_canonical_vec()).unwrap(),
            value
        );
        // 大写十六进制被拒绝，保证文本表示唯一。
        assert_eq!(
            DevicePublicBytes::parse_hex(&value.to_hex().to_uppercase()),
            None
        );
    }

    #[test]
    fn device_id_changes_with_any_public_key_bit() {
        let base = public(3);
        let mut flipped = *base.as_bytes();
        flipped[0] ^= 0x01;
        assert_ne!(
            DevicePublicBytes::from_bytes(flipped).device_id(),
            base.device_id()
        );
        let mut flipped = *base.as_bytes();
        flipped[63] ^= 0x80;
        assert_ne!(
            DevicePublicBytes::from_bytes(flipped).device_id(),
            base.device_id()
        );
    }

    #[test]
    fn signing_payload_excludes_the_signature() {
        let a = genesis(vec![1u8; SIGNATURE_LEN]);
        let b = genesis(vec![2u8; SIGNATURE_LEN]);
        assert_eq!(a.signing_payload(), b.signing_payload());
        // 但摘要覆盖签名，因此两者是不同的事件。
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn event_round_trips_through_canonical_cbor() {
        let event = genesis(vec![9u8; SIGNATURE_LEN]);
        let bytes = event.to_canonical_vec();
        assert_eq!(
            MembershipEvent::from_canonical_slice(&bytes).unwrap(),
            event
        );
    }

    #[test]
    fn event_rejects_unknown_format_version() {
        let event = genesis(vec![0u8; SIGNATURE_LEN]);
        let mut value = event.to_value();
        if let Value::Array(items) = &mut value {
            items[0] = Value::Uint(42);
        }
        assert_eq!(
            MembershipEvent::from_canonical_slice(&crate::cbor::encode(&value)),
            Err(CborError::UnsupportedFormatVersion {
                found: 42,
                supported: MEMBERSHIP_EVENT_FORMAT_VERSION,
            })
        );
    }

    #[test]
    fn genesis_shape_is_enforced() {
        let mut event = genesis(vec![0u8; SIGNATURE_LEN]);
        event.previous = Some(Digest32::ZERO);
        assert_eq!(
            event.validate(),
            Err(MembershipEventError::MalformedGenesis)
        );

        let mut event = genesis(vec![0u8; SIGNATURE_LEN]);
        event.sequence = 1;
        assert_eq!(
            event.validate(),
            Err(MembershipEventError::MissingPrevious(1))
        );

        let mut event = genesis(vec![0u8; SIGNATURE_LEN]);
        event.action = MembershipAction::Revoke {
            subject: public(1).device_id(),
        };
        assert_eq!(
            event.validate(),
            Err(MembershipEventError::NonGenesisAtZero)
        );
    }

    #[test]
    fn subject_must_match_its_public_key() {
        let mut event = genesis(vec![0u8; SIGNATURE_LEN]);
        event.action = MembershipAction::Genesis {
            subject: public(2).device_id(),
            public: public(1),
        };
        assert_eq!(
            event.validate(),
            Err(MembershipEventError::SubjectKeyMismatch)
        );
    }

    #[test]
    fn signature_length_is_enforced() {
        let event = genesis(vec![0u8; 8]);
        assert_eq!(
            event.validate(),
            Err(MembershipEventError::SignatureLength {
                expected: SIGNATURE_LEN,
                found: 8,
            })
        );
    }

    #[test]
    fn action_kind_and_subject_are_stable() {
        let device = public(5).device_id();
        assert_eq!(
            MembershipAction::Promote { subject: device }.kind(),
            "promote"
        );
        assert_eq!(
            MembershipAction::Revoke { subject: device }.subject(),
            device
        );
        assert!(MembershipAction::Revoke { subject: device }.is_revoke());
        assert!(!MembershipAction::Promote { subject: device }.is_revoke());
    }

    #[test]
    fn action_round_trips_for_every_variant() {
        let public = public(4);
        for action in [
            MembershipAction::Genesis {
                subject: public.device_id(),
                public,
            },
            MembershipAction::AddMember {
                subject: public.device_id(),
                public,
                role: MemberRole::Member,
            },
            MembershipAction::Promote {
                subject: public.device_id(),
            },
            MembershipAction::Revoke {
                subject: public.device_id(),
            },
        ] {
            let bytes = action.to_canonical_vec();
            assert_eq!(
                MembershipAction::from_canonical_slice(&bytes).unwrap(),
                action
            );
        }
        assert!(matches!(
            MembershipAction::from_value(&Value::Array(vec![Value::Text("nope".into())])),
            Err(CborError::UnknownVariant(_))
        ));
    }

    #[test]
    fn role_parses_and_round_trips() {
        assert_eq!(MemberRole::parse("admin"), Some(MemberRole::Admin));
        assert_eq!(MemberRole::parse("root"), None);
        assert!(MemberRole::Admin.can_administer());
        assert!(!MemberRole::Member.can_administer());
        let bytes = MemberRole::Member.to_canonical_vec();
        assert_eq!(
            MemberRole::from_canonical_slice(&bytes).unwrap(),
            MemberRole::Member
        );
    }
}
