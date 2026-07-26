//! 强类型标识符。
//!
//! EnvSync 中出现的标识符分为三类：
//!
//! * **随机标识**：[`WorkspaceId`]、[`OperationId`]，由 UUIDv4 生成；
//! * **派生标识**：[`DeviceId`]，由设备公钥（M2 之前为设备种子）经域分隔哈希派生；
//! * **内容标识**：[`BlobId`]、[`StateRootId`]、[`SnapshotId`]、[`PlanId`]、
//!   [`ConflictId`]，由对象的 canonical 编码经域分隔 BLAKE3 派生。
//!
//! 所有标识符都实现 `Display` / `FromStr`，解析失败返回错误而**绝不 panic**。

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cbor::{CborCodec, CborError, Value};

/// 标识符解析错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    /// 十六进制摘要长度不是 64 个字符。
    #[error("摘要必须是 64 个十六进制字符，实际 {0} 个")]
    DigestLength(usize),
    /// 十六进制串包含非法字符。
    #[error("摘要包含非十六进制字符")]
    DigestCharset,
    /// UUID 解析失败。
    #[error("UUID 格式非法")]
    Uuid,
    /// 资源标识为空。
    #[error("ResourceId 不能为空")]
    ResourceIdEmpty,
    /// 资源标识包含空段（连续或首尾的 `/`）。
    #[error("ResourceId 不能包含空段")]
    ResourceIdEmptySegment,
    /// 资源标识包含 `.` 或 `..` 段。
    #[error("ResourceId 不能包含 `.` 或 `..` 段")]
    ResourceIdDotSegment,
    /// 资源标识包含非法字符（例如反斜杠、空白、控制字符或 NUL）。
    #[error("ResourceId 段包含非法字符 `{0}`")]
    ResourceIdCharset(char),
    /// 资源标识超长。
    #[error("ResourceId 超过长度上限：{0} 字节 > {max} 字节", max = ResourceId::MAX_LEN)]
    ResourceIdTooLong(usize),
    /// 资源标识段数超限。
    #[error("ResourceId 段数超过上限 {max}", max = ResourceId::MAX_SEGMENTS)]
    ResourceIdTooManySegments,
}

/// 32 字节摘要，所有内容寻址标识符的公共载体。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest32([u8; 32]);

impl Digest32 {
    /// 由原始字节构造。
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Digest32(bytes)
    }

    /// 取出原始字节。
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 全零摘要，仅用于表示“尚未计算”的占位场景。
    pub const ZERO: Digest32 = Digest32([0u8; 32]);

    /// 以域分隔标签计算 BLAKE3 摘要。
    ///
    /// 域分隔保证不同种类的对象即使字节内容相同，摘要也不同，从而杜绝跨类型混淆。
    pub fn domain_hash(domain: &str, payload: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain.as_bytes());
        hasher.update(&[0x00]); // 分隔符，避免 domain 与 payload 边界歧义
        hasher.update(&(payload.len() as u64).to_be_bytes());
        hasher.update(payload);
        Digest32(*hasher.finalize().as_bytes())
    }

    /// 十六进制表示（小写，64 字符）。
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push(char::from_digit((byte >> 4) as u32, 16).expect("半字节始终有效"));
            out.push(char::from_digit((byte & 0x0f) as u32, 16).expect("半字节始终有效"));
        }
        out
    }

    /// 用于日志和 UI 的短表示（前 12 位十六进制）。
    pub fn short(self) -> String {
        self.to_hex()[..12].to_owned()
    }
}

impl FromStr for Digest32 {
    type Err = IdError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.len() != 64 {
            return Err(IdError::DigestLength(text.len()));
        }
        let mut bytes = [0u8; 32];
        let raw = text.as_bytes();
        for (index, chunk) in raw.chunks_exact(2).enumerate() {
            let hi = (chunk[0] as char)
                .to_digit(16)
                .ok_or(IdError::DigestCharset)?;
            let lo = (chunk[1] as char)
                .to_digit(16)
                .ok_or(IdError::DigestCharset)?;
            // 拒绝大写十六进制，保证同一摘要只有一种文本表示。
            if chunk[0].is_ascii_uppercase() || chunk[1].is_ascii_uppercase() {
                return Err(IdError::DigestCharset);
            }
            bytes[index] = ((hi << 4) | lo) as u8;
        }
        Ok(Digest32(bytes))
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest32({})", self.short())
    }
}

impl From<Digest32> for String {
    fn from(value: Digest32) -> Self {
        value.to_hex()
    }
}

impl TryFrom<String> for Digest32 {
    type Error = IdError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl CborCodec for Digest32 {
    fn to_value(&self) -> Value {
        Value::Bytes(self.0.to_vec())
    }
    fn from_value(value: &Value) -> Result<Self, CborError> {
        Ok(Digest32(<[u8; 32]>::from_value(value)?))
    }
}

/// 生成内容寻址标识符的 newtype。
macro_rules! digest_id {
    ($(#[$meta:meta])* $name:ident, $domain:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Digest32);

        impl $name {
            /// 该标识符使用的哈希域分隔标签。
            pub const DOMAIN: &'static str = $domain;

            /// 由对象的 canonical 编码字节派生标识符。
            pub fn of(payload: &[u8]) -> Self {
                $name(Digest32::domain_hash($domain, payload))
            }

            /// 由已有摘要构造（用于反序列化和测试）。
            pub const fn from_digest(digest: Digest32) -> Self {
                $name(digest)
            }

            /// 取出内部摘要。
            pub const fn digest(&self) -> Digest32 {
                self.0
            }

            /// 十六进制表示。
            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }

            /// 短表示，用于日志与人类可读输出。
            pub fn short(&self) -> String {
                self.0.short()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0.short())
            }
        }

        impl FromStr for $name {
            type Err = IdError;
            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Ok($name(text.parse()?))
            }
        }

        impl CborCodec for $name {
            fn to_value(&self) -> Value {
                self.0.to_value()
            }
            fn from_value(value: &Value) -> Result<Self, CborError> {
                Ok($name(Digest32::from_value(value)?))
            }
        }
    };
}

digest_id!(
    /// 内容寻址的 Blob 标识。
    BlobId,
    "envsync:blob:v1"
);
digest_id!(
    /// 内容寻址的 State Root 标识。
    StateRootId,
    "envsync:state:v1"
);
digest_id!(
    /// 内容寻址的 Snapshot 标识，只覆盖 Snapshot Body，不含签名。
    SnapshotId,
    "envsync:snapshot:v1"
);
digest_id!(
    /// 计划标识，由计划的完整绑定内容派生。
    PlanId,
    "envsync:plan:v1"
);
digest_id!(
    /// 冲突对象标识。
    ConflictId,
    "envsync:conflict:v1"
);
digest_id!(
    /// 设备标识，由设备公钥（M2 起）或设备种子（M2 之前）派生。
    DeviceId,
    "envsync:device:v1"
);

/// 工作区标识，随机生成且在整个生命周期内不变。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkspaceId(Uuid);

impl WorkspaceId {
    /// 生成新的随机工作区标识。
    pub fn generate() -> Self {
        WorkspaceId(Uuid::new_v4())
    }

    /// 由 UUID 构造。
    pub const fn from_uuid(uuid: Uuid) -> Self {
        WorkspaceId(uuid)
    }

    /// 取出 UUID。
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl fmt::Display for WorkspaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for WorkspaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WorkspaceId({})", self.0)
    }
}

impl FromStr for WorkspaceId {
    type Err = IdError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(text)
            .map(WorkspaceId)
            .map_err(|_| IdError::Uuid)
    }
}

impl CborCodec for WorkspaceId {
    fn to_value(&self) -> Value {
        Value::Bytes(self.0.as_bytes().to_vec())
    }
    fn from_value(value: &Value) -> Result<Self, CborError> {
        Ok(WorkspaceId(Uuid::from_bytes(<[u8; 16]>::from_value(
            value,
        )?)))
    }
}

/// 本地操作标识，用于关联 journal、备份目录和收据。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OperationId(Uuid);

impl OperationId {
    /// 生成新的随机操作标识。
    pub fn generate() -> Self {
        OperationId(Uuid::new_v4())
    }

    /// 由 UUID 构造。
    pub const fn from_uuid(uuid: Uuid) -> Self {
        OperationId(uuid)
    }

    /// 适合作为文件名的简洁表示（无连字符）。
    pub fn to_filename(self) -> String {
        self.0.simple().to_string()
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OperationId({})", self.0)
    }
}

impl FromStr for OperationId {
    type Err = IdError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(text)
            .map(OperationId)
            .map_err(|_| IdError::Uuid)
    }
}

impl DeviceId {
    /// 由设备的公开材料派生标识。
    ///
    /// M2 之前传入随机设备种子；M2 起传入 `X25519 公钥 || Ed25519 公钥`，因此修改
    /// 任意一个公钥都会改变 `DeviceId`。
    pub fn derive(public_material: &[u8]) -> Self {
        DeviceId::of(public_material)
    }
}

/// 资源标识：由 `/` 分隔的稳定逻辑路径，例如 `shell/zsh/main`。
///
/// 它**不是**文件系统路径：资源标识只表达“同步什么资源”，具体落到哪个文件由设备上的
/// 授权根与相对目标决定。因此这里严格拒绝一切可能被误当作路径的形式。
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ResourceId(String);

impl ResourceId {
    /// 允许的最大总长度（字节）。
    pub const MAX_LEN: usize = 512;
    /// 允许的最大段数。
    pub const MAX_SEGMENTS: usize = 16;

    /// 解析并校验资源标识。
    pub fn parse(text: &str) -> Result<Self, IdError> {
        if text.is_empty() {
            return Err(IdError::ResourceIdEmpty);
        }
        if text.len() > Self::MAX_LEN {
            return Err(IdError::ResourceIdTooLong(text.len()));
        }
        let segments: Vec<&str> = text.split('/').collect();
        if segments.len() > Self::MAX_SEGMENTS {
            return Err(IdError::ResourceIdTooManySegments);
        }
        for segment in &segments {
            if segment.is_empty() {
                return Err(IdError::ResourceIdEmptySegment);
            }
            if *segment == "." || *segment == ".." {
                return Err(IdError::ResourceIdDotSegment);
            }
            for ch in segment.chars() {
                let allowed = ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '+');
                if !allowed {
                    return Err(IdError::ResourceIdCharset(ch));
                }
            }
        }
        Ok(ResourceId(text.to_owned()))
    }

    /// 文本表示。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 分段视图。
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }

    /// 适合作为文件名的表示（`/` 替换为 `__`），用于备份目录布局。
    pub fn to_filename(&self) -> String {
        self.0.replace('/', "__")
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ResourceId({})", self.0)
    }
}

impl FromStr for ResourceId {
    type Err = IdError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        ResourceId::parse(text)
    }
}

impl TryFrom<String> for ResourceId {
    type Error = IdError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        ResourceId::parse(&value)
    }
}

impl From<ResourceId> for String {
    fn from(value: ResourceId) -> Self {
        value.0
    }
}

impl CborCodec for ResourceId {
    fn to_value(&self) -> Value {
        Value::Text(self.0.clone())
    }
    fn from_value(value: &Value) -> Result<Self, CborError> {
        ResourceId::parse(value.as_text()?).map_err(|err| CborError::InvalidValue(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_domain_separation_changes_id() {
        let payload = b"same bytes";
        assert_ne!(
            BlobId::of(payload).digest(),
            StateRootId::of(payload).digest()
        );
        assert_ne!(
            SnapshotId::of(payload).digest(),
            PlanId::of(payload).digest()
        );
    }

    #[test]
    fn digest_hex_round_trip() {
        let id = BlobId::of(b"hello");
        let text = id.to_hex();
        assert_eq!(text.len(), 64);
        assert_eq!(text.parse::<BlobId>().unwrap(), id);
    }

    #[test]
    fn digest_parse_rejects_bad_input_without_panicking() {
        assert_eq!("".parse::<BlobId>(), Err(IdError::DigestLength(0)));
        assert_eq!(
            "zz".repeat(32).parse::<BlobId>(),
            Err(IdError::DigestCharset)
        );
        // 大写十六进制被拒绝，保证文本表示唯一。
        let upper = BlobId::of(b"x").to_hex().to_uppercase();
        assert_eq!(upper.parse::<BlobId>(), Err(IdError::DigestCharset));
    }

    #[test]
    fn resource_id_accepts_well_formed_path() {
        let id = ResourceId::parse("shell/zsh/main").unwrap();
        assert_eq!(id.as_str(), "shell/zsh/main");
        assert_eq!(
            id.segments().collect::<Vec<_>>(),
            vec!["shell", "zsh", "main"]
        );
        assert_eq!(id.to_filename(), "shell__zsh__main");
    }

    #[test]
    fn resource_id_rejects_path_like_forms() {
        assert_eq!(ResourceId::parse(""), Err(IdError::ResourceIdEmpty));
        assert_eq!(
            ResourceId::parse("a//b"),
            Err(IdError::ResourceIdEmptySegment)
        );
        assert_eq!(
            ResourceId::parse("/abs"),
            Err(IdError::ResourceIdEmptySegment)
        );
        assert_eq!(
            ResourceId::parse("a/"),
            Err(IdError::ResourceIdEmptySegment)
        );
        assert_eq!(
            ResourceId::parse("a/./b"),
            Err(IdError::ResourceIdDotSegment)
        );
        assert_eq!(
            ResourceId::parse("a/../b"),
            Err(IdError::ResourceIdDotSegment)
        );
        assert_eq!(ResourceId::parse(".."), Err(IdError::ResourceIdDotSegment));
        assert_eq!(
            ResourceId::parse("a\\b"),
            Err(IdError::ResourceIdCharset('\\'))
        );
        assert_eq!(
            ResourceId::parse("C:/x"),
            Err(IdError::ResourceIdCharset(':'))
        );
        assert_eq!(
            ResourceId::parse("a\0b"),
            Err(IdError::ResourceIdCharset('\0'))
        );
        assert_eq!(
            ResourceId::parse("a b"),
            Err(IdError::ResourceIdCharset(' '))
        );
        assert!(matches!(
            ResourceId::parse(&"x".repeat(ResourceId::MAX_LEN + 1)),
            Err(IdError::ResourceIdTooLong(_))
        ));
        let deep = vec!["a"; ResourceId::MAX_SEGMENTS + 1].join("/");
        assert_eq!(
            ResourceId::parse(&deep),
            Err(IdError::ResourceIdTooManySegments)
        );
    }

    #[test]
    fn workspace_id_round_trips_through_cbor_and_text() {
        let id = WorkspaceId::generate();
        assert_eq!(id.to_string().parse::<WorkspaceId>().unwrap(), id);
        let bytes = id.to_canonical_vec();
        assert_eq!(WorkspaceId::from_canonical_slice(&bytes).unwrap(), id);
    }

    #[test]
    fn device_id_changes_with_any_public_key_bit() {
        let base = DeviceId::derive(b"x25519-pk||ed25519-pk");
        let flipped = DeviceId::derive(b"x25519-pk||ed25519-pK");
        assert_ne!(base, flipped);
    }

    #[test]
    fn resource_id_cbor_rejects_invalid_text() {
        let bad = Value::Text("../escape".into());
        assert!(matches!(
            ResourceId::from_value(&bad),
            Err(CborError::InvalidValue(_))
        ));
    }
}
