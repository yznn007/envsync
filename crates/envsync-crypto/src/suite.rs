//! 算法套件、格式版本、密钥纪元与敏感类型。
//!
//! M2 只有**一套**算法组合，并且它的名字被写进每一个线格式对象里：
//!
//! ```text
//! ESV1_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519
//!  │    │       │           │                 └─ 签名：Ed25519
//!  │    │       │           └─ AEAD：ChaCha20-Poly1305（256-bit key，96-bit nonce）
//!  │    │       └─ KDF：HKDF-SHA256
//!  │    └─ KEM：X25519（DHKEM，RFC 9180 §4.1）
//!  └─ EnvSync suite 版本 1
//! ```
//!
//! 「只有一套」是刻意的：没有协商就没有降级攻击。解析器遇到任何其他名字都返回
//! [`CryptoError::UnsupportedSuite`]，遇到任何其他格式版本都返回
//! [`CryptoError::UnsupportedFormatVersion`]。

use envsync_domain::cbor::{CborCodec, CborError, Value};
use envsync_domain::cbor_unit_enum;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::CryptoError;

/// 对称密钥长度（ChaCha20-Poly1305，256 bit）。
pub const KEY_LEN: usize = 32;
/// AEAD nonce 长度（96 bit）。
pub const NONCE_LEN: usize = 12;
/// AEAD 认证标签长度（128 bit）。
pub const TAG_LEN: usize = 16;
/// X25519 公钥 / 私钥 / 共享秘密长度。
pub const X25519_LEN: usize = 32;
/// Ed25519 公钥长度。
pub const ED25519_PUBLIC_LEN: usize = 32;
/// Ed25519 签名长度。
pub const SIGNATURE_LEN: usize = 64;

/// 单条秘密明文的长度上限（1 MiB）。
///
/// Vault 存的是配置类秘密（token、密钥、连接串），不是文件。设上限的目的是让恶意或
/// 损坏的输入在做任何分配之前就被拒绝。
pub const MAX_PLAINTEXT_LEN: usize = 1024 * 1024;

/// M2 唯一的算法套件。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CryptoSuite {
    /// `ESV1_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519`。
    Esv1,
}

impl CryptoSuite {
    /// [`CryptoSuite::Esv1`] 的线格式名称。
    pub const ESV1_NAME: &'static str = "ESV1_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519";

    /// 解析套件名；任何未知名称都被拒绝。
    pub fn parse(name: &str) -> Result<Self, CryptoError> {
        match name {
            Self::ESV1_NAME => Ok(CryptoSuite::Esv1),
            _ => Err(CryptoError::UnsupportedSuite),
        }
    }

    /// 线格式名称。
    pub const fn as_str(self) -> &'static str {
        match self {
            CryptoSuite::Esv1 => Self::ESV1_NAME,
        }
    }
}

cbor_unit_enum!(CryptoSuite {
    CryptoSuite::Esv1 => "ESV1_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519",
});

impl core::fmt::Display for CryptoSuite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 密封对象的格式版本。
///
/// 与 [`CryptoSuite`] 一样，未知版本一律拒绝：格式演进必须是显式的读写双方升级，
/// 而不是「尽力而为地解析」。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SealedFormatVersion(u32);

impl SealedFormatVersion {
    /// 当前（也是唯一）支持的版本。
    pub const V1: SealedFormatVersion = SealedFormatVersion(1);

    /// 校验并构造版本号。
    pub fn parse(raw: u32) -> Result<Self, CryptoError> {
        if raw == Self::V1.0 {
            Ok(Self::V1)
        } else {
            Err(CryptoError::UnsupportedFormatVersion {
                found: raw,
                supported: Self::V1.0,
            })
        }
    }

    /// 版本号数值。
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl CborCodec for SealedFormatVersion {
    fn to_value(&self) -> Value {
        Value::Uint(self.0 as u64)
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let raw = u32::from_value(value)?;
        SealedFormatVersion::parse(raw).map_err(|_| CborError::UnsupportedFormatVersion {
            found: raw,
            supported: SealedFormatVersion::V1.0,
        })
    }
}

/// 工作区数据密钥的纪元号。
///
/// 撤销设备时纪元 `n -> n+1`，新秘密只用新纪元的密钥。纪元号进入 sealed object 的
/// AAD 与设备信封的 info 串，因此把纪元号改小（回滚攻击）会直接导致认证失败。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyEpoch(u64);

impl KeyEpoch {
    /// 工作区创建时的初始纪元。
    pub const INITIAL: KeyEpoch = KeyEpoch(1);

    /// 由数值构造。
    pub const fn new(value: u64) -> Self {
        KeyEpoch(value)
    }

    /// 纪元数值。
    pub const fn get(self) -> u64 {
        self.0
    }

    /// 下一个纪元；溢出时返回 `None`（不做环绕）。
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(KeyEpoch)
    }
}

impl CborCodec for KeyEpoch {
    fn to_value(&self) -> Value {
        Value::Uint(self.0)
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        Ok(KeyEpoch(value.as_uint()?))
    }
}

impl core::fmt::Display for KeyEpoch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// 32 字节对称数据密钥。
///
/// **刻意不实现** `Debug`、`Display`、[`CborCodec`] 与任何序列化 trait：想把它写进
/// 日志或磁盘，只能显式调用 [`DataKey::expose_bytes`]，而那是一个在 review 中一眼可见
/// 的调用点。`Drop` 时清零。
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DataKey([u8; KEY_LEN]);

impl DataKey {
    /// 从 [`rand_core::OsRng`] 生成新的数据密钥。
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; KEY_LEN];
        crate::fill_random(&mut bytes)?;
        Ok(DataKey(bytes))
    }

    /// 由已有字节构造（用于从信封或恢复包中还原）。
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        DataKey(bytes)
    }

    /// 由切片构造，长度不符时报错。
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        let array = <[u8; KEY_LEN]>::try_from(bytes).map_err(|_| CryptoError::InvalidLength {
            field: "data_key",
            expected: KEY_LEN,
            found: bytes.len(),
        })?;
        Ok(DataKey(array))
    }

    /// 取出原始字节。
    ///
    /// 调用点即是「密钥离开类型保护」的边界，请只在马上要喂给密码学原语时使用。
    pub fn expose_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl ConstantTimeEq for DataKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for DataKey {
    /// 常量时间比较，避免用比较耗时区分前缀。
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for DataKey {}

/// 秘密明文包装。
///
/// 与 [`DataKey`] 相同的约束：不可打印、不可序列化、`Drop` 时清零。
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Plaintext(Vec<u8>);

impl Plaintext {
    /// 由字节向量构造（不复制）。
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Plaintext(bytes)
    }

    /// 由切片构造。
    pub fn from_slice(bytes: &[u8]) -> Self {
        Plaintext(bytes.to_vec())
    }

    /// 取出明文字节。请只在真正要把值交给使用者时调用。
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// 明文长度。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 明文是否为空。空值是合法的秘密值。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl ConstantTimeEq for Plaintext {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        if self.0.len() != other.0.len() {
            return subtle::Choice::from(0u8);
        }
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Plaintext {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Plaintext {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_round_trips_through_name_and_cbor() {
        let suite = CryptoSuite::parse(CryptoSuite::ESV1_NAME).unwrap();
        assert_eq!(suite, CryptoSuite::Esv1);
        let bytes = suite.to_canonical_vec();
        assert_eq!(CryptoSuite::from_canonical_slice(&bytes).unwrap(), suite);
    }

    #[test]
    fn unknown_suite_is_rejected() {
        assert_eq!(
            CryptoSuite::parse("ESV1_P256_HKDF_SHA256_AES128GCM_ECDSA"),
            Err(CryptoError::UnsupportedSuite)
        );
    }

    #[test]
    fn unknown_format_version_is_rejected() {
        assert!(SealedFormatVersion::parse(1).is_ok());
        assert_eq!(
            SealedFormatVersion::parse(2),
            Err(CryptoError::UnsupportedFormatVersion {
                found: 2,
                supported: 1,
            })
        );
    }

    #[test]
    fn data_key_compares_in_constant_time() {
        let a = DataKey::from_bytes([7u8; KEY_LEN]);
        let b = DataKey::from_bytes([7u8; KEY_LEN]);
        let c = DataKey::from_bytes([8u8; KEY_LEN]);
        // `DataKey` 不实现 Debug，因此这里不能用 assert_eq!——这本身就是约束生效的证据。
        assert!(a == b);
        assert!(a != c);
    }

    #[test]
    fn key_epoch_does_not_wrap() {
        assert_eq!(KeyEpoch::new(1).next(), Some(KeyEpoch::new(2)));
        assert_eq!(KeyEpoch::new(u64::MAX).next(), None);
    }
}
