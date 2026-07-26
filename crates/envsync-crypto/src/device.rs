//! 设备身份：双密钥、派生 [`DeviceId`] 与域分隔签名。
//!
//! 每台设备持有**两把**私钥，职责严格分离：
//!
//! * **X25519**：只用于 HPKE 设备信封（接收工作区数据密钥），见 [`crate::envelope`]；
//! * **Ed25519**：只用于签名（成员事件、快照、信封对象）。
//!
//! [`DeviceId`] 由两把公钥的域分隔摘要派生（ADR-0002）：
//!
//! ```text
//! DeviceId = BLAKE3_domain("envsync:device:v1", x25519_pk || ed25519_pk)
//! ```
//!
//! 因此**改动任意一把公钥都会改变 `DeviceId`**，攻击者无法在保持设备标识不变的前提下
//! 替换其中一把密钥（例如把信封重定向到自己控制的 X25519 私钥）。
//!
//! ## 签名的待签结构
//!
//! 签名从不直接覆盖调用者给的字节，而是覆盖一个 canonical CBOR 数组：
//!
//! ```text
//! signing_input = canonical_cbor([
//!     "envsync:device-signature:v1",   // 域前缀，隔离其他协议的签名
//!     1,                               // 签名格式版本
//!     "ESV1_...",                      // 算法套件名
//!     domain,                          // 调用方给的用途标签，例如 "membership-event"
//!     workspace_id (16 字节),           // 绑定工作区，阻断跨工作区重放
//!     BLAKE3_domain("envsync:device-signature-payload:v1", payload),
//! ])
//! ```
//!
//! 由此得到四条性质：跨工作区重放失败、改 payload 失败、换 signer 失败、
//! 用非 canonical 编码的等价结构失败（canonical 编码是**重新计算**出来的，
//! 不是从输入里读出来的）。

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use envsync_domain::cbor::{decode_canonical, encode, CborCodec, CborError, Value};
use envsync_domain::id::{Digest32, WorkspaceId};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use envsync_domain::id::DeviceId;

use crate::suite::{CryptoSuite, ED25519_PUBLIC_LEN, SIGNATURE_LEN, X25519_LEN};
use crate::CryptoError;

/// 待签结构的域前缀。
pub const SIGNATURE_DOMAIN_PREFIX: &str = "envsync:device-signature:v1";
/// payload 摘要的域标签。
pub const SIGNATURE_PAYLOAD_DOMAIN: &str = "envsync:device-signature-payload:v1";
/// 签名格式版本。
pub const SIGNATURE_FORMAT_VERSION: u32 = 1;
/// 用途标签（`domain` 参数）的最大长度。
pub const MAX_DOMAIN_LABEL_LEN: usize = 64;
/// 待签 payload 的最大长度（16 MiB）；超过则在做任何哈希前拒绝。
pub const MAX_SIGNED_PAYLOAD_LEN: usize = 16 * 1024 * 1024;

/// 设备的公开材料。
///
/// 这是可以自由发布、写日志、进快照的部分；实现 [`CborCodec`] 与 `Debug`。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DevicePublic {
    /// X25519 公钥，用于接收 HPKE 设备信封。
    pub x25519: [u8; X25519_LEN],
    /// Ed25519 公钥，用于验证该设备的签名。
    pub ed25519: [u8; ED25519_PUBLIC_LEN],
}

impl DevicePublic {
    /// 两把公钥的拼接，即 [`DeviceId`] 的派生输入。
    pub fn device_id_input(&self) -> [u8; X25519_LEN + ED25519_PUBLIC_LEN] {
        let mut input = [0u8; X25519_LEN + ED25519_PUBLIC_LEN];
        input[..X25519_LEN].copy_from_slice(&self.x25519);
        input[X25519_LEN..].copy_from_slice(&self.ed25519);
        input
    }

    /// 派生设备标识。改动任意一把公钥的任意一位都会改变结果。
    pub fn device_id(&self) -> DeviceId {
        DeviceId::derive(&self.device_id_input())
    }

    /// 校验两把公钥都是合法的曲线点。
    ///
    /// Ed25519 公钥用 [`VerifyingKey::from_bytes`] 做解压缩校验；X25519 公钥是任意
    /// 32 字节都合法（RFC 7748），其小阶点风险在 DH 之后用「非贡献性」检查覆盖，
    /// 见 [`crate::envelope`]。
    pub fn validate(&self) -> Result<(), CryptoError> {
        VerifyingKey::from_bytes(&self.ed25519).map_err(|_| CryptoError::InvalidPublicKey)?;
        Ok(())
    }
}

impl CborCodec for DevicePublic {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Bytes(self.x25519.to_vec()),
            Value::Bytes(self.ed25519.to_vec()),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        if items.len() != 2 {
            return Err(CborError::ArityMismatch);
        }
        Ok(DevicePublic {
            x25519: <[u8; X25519_LEN]>::from_value(&items[0])?,
            ed25519: <[u8; ED25519_PUBLIC_LEN]>::from_value(&items[1])?,
        })
    }
}

/// Ed25519 签名，带显式格式版本。
///
/// 版本号放在**签名对象**里（而不是只放在待签内容里），是为了让 `verify` 能在做任何
/// 密码学运算之前就拒绝未知版本。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    version: u32,
    bytes: [u8; SIGNATURE_LEN],
}

impl Signature {
    /// 由原始签名字节构造当前版本的签名对象。
    pub const fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Signature {
            version: SIGNATURE_FORMAT_VERSION,
            bytes,
        }
    }

    /// 签名格式版本。
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// 原始 64 字节签名。
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.bytes
    }
}

impl core::fmt::Debug for Signature {
    /// 只显示版本与短摘要——签名本身是公开材料，但完整回显对日志毫无价值。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Signature(v{}, {})",
            self.version,
            Digest32::domain_hash("envsync:signature-fingerprint:v1", &self.bytes).short()
        )
    }
}

impl CborCodec for Signature {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Uint(self.version as u64),
            Value::Bytes(self.bytes.to_vec()),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        if items.len() != 2 {
            return Err(CborError::ArityMismatch);
        }
        let version = u32::from_value(&items[0])?;
        if version != SIGNATURE_FORMAT_VERSION {
            return Err(CborError::UnsupportedFormatVersion {
                found: version,
                supported: SIGNATURE_FORMAT_VERSION,
            });
        }
        Ok(Signature {
            version,
            bytes: <[u8; SIGNATURE_LEN]>::from_value(&items[1])?,
        })
    }
}

/// 设备密钥对：X25519（HPKE）+ Ed25519（签名）。
///
/// **刻意不实现** `Debug`、`Display`、`Clone` 与任何序列化 trait。持久化只能通过
/// [`DeviceKeypair::export_secret_bytes`]，并且必须写进系统安全存储（见 M2 任务 6）。
/// `Drop` 时两把私钥都会被清零。
#[derive(ZeroizeOnDrop)]
pub struct DeviceKeypair {
    x25519_secret: X25519Secret,
    ed25519_secret: SigningKey,
    #[zeroize(skip)]
    public: DevicePublic,
}

impl DeviceKeypair {
    /// 从 [`rand_core::OsRng`] 生成一台新设备的两把私钥。
    pub fn generate() -> Result<Self, CryptoError> {
        let mut x25519_seed = [0u8; X25519_LEN];
        let mut ed25519_seed = [0u8; 32];
        crate::fill_random(&mut x25519_seed)?;
        crate::fill_random(&mut ed25519_seed)?;
        let keypair = Self::from_seeds(x25519_seed, ed25519_seed);
        // 种子已经被拷贝进私钥，本地副本立即清零。
        x25519_seed.zeroize();
        ed25519_seed.zeroize();
        Ok(keypair)
    }

    fn from_seeds(x25519_seed: [u8; X25519_LEN], ed25519_seed: [u8; 32]) -> Self {
        let x25519_secret = X25519Secret::from(x25519_seed);
        let ed25519_secret = SigningKey::from_bytes(&ed25519_seed);
        let public = DevicePublic {
            x25519: X25519Public::from(&x25519_secret).to_bytes(),
            ed25519: ed25519_secret.verifying_key().to_bytes(),
        };
        DeviceKeypair {
            x25519_secret,
            ed25519_secret,
            public,
        }
    }

    /// 由已有私钥字节还原（从系统安全存储读回时使用）。
    pub fn from_secret_bytes(
        x25519_secret: [u8; X25519_LEN],
        ed25519_secret: [u8; 32],
    ) -> Result<Self, CryptoError> {
        Ok(Self::from_seeds(x25519_secret, ed25519_secret))
    }

    /// 导出两把私钥的原始字节，**只允许**交给系统安全存储。
    ///
    /// 返回值在 `Drop` 时清零。
    pub fn export_secret_bytes(&self) -> zeroize::Zeroizing<[u8; X25519_LEN + 32]> {
        let mut out = [0u8; X25519_LEN + 32];
        out[..X25519_LEN].copy_from_slice(&self.x25519_secret.to_bytes());
        out[X25519_LEN..].copy_from_slice(&self.ed25519_secret.to_bytes());
        zeroize::Zeroizing::new(out)
    }

    /// 设备的公开材料。
    pub fn public(&self) -> DevicePublic {
        self.public
    }

    /// 设备标识。
    pub fn device_id(&self) -> DeviceId {
        self.public.device_id()
    }

    /// 供 [`crate::envelope`] 做 X25519 DH，不对外暴露私钥字节。
    pub(crate) fn x25519_secret(&self) -> &X25519Secret {
        &self.x25519_secret
    }

    /// 对 `payload` 产生一枚绑定 `domain` 与 `workspace` 的签名。
    ///
    /// 实际被 Ed25519 覆盖的是 [`signing_input`] 返回的 canonical CBOR 字节，
    /// 而不是 `payload` 本身。
    pub fn sign(
        &self,
        domain: &str,
        workspace: WorkspaceId,
        payload: &[u8],
    ) -> Result<Signature, CryptoError> {
        let input = signing_input(domain, workspace, payload)?;
        Ok(Signature::from_bytes(
            self.ed25519_secret.sign(&input).to_bytes(),
        ))
    }

    /// 仅供测试：直接对任意字节签名，用来构造「非 canonical 待签内容」这类攻击向量。
    #[cfg(feature = "test-vectors")]
    pub fn sign_raw_for_tests(&self, message: &[u8]) -> Signature {
        Signature::from_bytes(self.ed25519_secret.sign(message).to_bytes())
    }
}

/// 构造待签的 canonical CBOR 字节串。
///
/// 公开这个函数是为了可审计性：任何人都能独立复现「到底签了什么」。返回值一定是
/// canonical 编码，因此不存在「同一逻辑内容的两种签名输入」。
pub fn signing_input(
    domain: &str,
    workspace: WorkspaceId,
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    validate_domain_label(domain)?;
    if payload.len() > MAX_SIGNED_PAYLOAD_LEN {
        return Err(CryptoError::PlaintextTooLarge {
            limit: MAX_SIGNED_PAYLOAD_LEN,
        });
    }
    let digest = Digest32::domain_hash(SIGNATURE_PAYLOAD_DOMAIN, payload);
    Ok(encode(&Value::Array(vec![
        Value::Text(SIGNATURE_DOMAIN_PREFIX.to_owned()),
        Value::Uint(SIGNATURE_FORMAT_VERSION as u64),
        Value::Text(CryptoSuite::Esv1.as_str().to_owned()),
        Value::Text(domain.to_owned()),
        workspace.to_value(),
        Value::Bytes(digest.as_bytes().to_vec()),
    ])))
}

/// 验证签名。
///
/// 顺序刻意固定为「结构 → 版本 → 长度 → 密码学」：便宜的检查先做，昂贵的曲线运算最后
/// 做，并且所有失败都只返回粗粒度的分类错误，不泄露任何密钥材料。
pub fn verify(
    public: &DevicePublic,
    domain: &str,
    workspace: WorkspaceId,
    payload: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    if signature.version != SIGNATURE_FORMAT_VERSION {
        return Err(CryptoError::UnsupportedFormatVersion {
            found: signature.version,
            supported: SIGNATURE_FORMAT_VERSION,
        });
    }
    let input = signing_input(domain, workspace, payload)?;
    let verifying =
        VerifyingKey::from_bytes(&public.ed25519).map_err(|_| CryptoError::InvalidPublicKey)?;
    let parsed = ed25519_dalek::Signature::from_bytes(&signature.bytes);
    // `verify_strict` 额外拒绝小阶公钥与带扭转分量的签名，避免同一条消息存在多枚
    // 都「合法」的签名（签名可塑性）。
    verifying
        .verify_strict(&input, &parsed)
        .map_err(|_| CryptoError::SignatureInvalid)?;
    Ok(())
}

/// 校验用途标签：非空、不超长、只含可打印 ASCII。
///
/// 收紧字符集是为了让域标签在任何日志/终端里都不产生控制字符注入。
fn validate_domain_label(domain: &str) -> Result<(), CryptoError> {
    if domain.is_empty() || domain.len() > MAX_DOMAIN_LABEL_LEN {
        return Err(CryptoError::DomainLabelInvalid);
    }
    if !domain
        .bytes()
        .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(CryptoError::DomainLabelInvalid);
    }
    Ok(())
}

/// 断言 [`signing_input`] 的输出确实是 canonical CBOR（纵深防御用的自检）。
pub fn signing_input_is_canonical(input: &[u8]) -> bool {
    decode_canonical(input).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_covers_both_public_keys() {
        let keypair = DeviceKeypair::generate().unwrap();
        let mut public = keypair.public();
        let base = public.device_id();

        public.x25519[0] ^= 0x01;
        assert_ne!(public.device_id(), base);

        let mut public = keypair.public();
        public.ed25519[31] ^= 0x80;
        assert_ne!(public.device_id(), base);
    }

    #[test]
    fn signing_input_is_canonical_cbor() {
        let workspace = WorkspaceId::generate();
        let input = signing_input("membership-event", workspace, b"payload").unwrap();
        assert!(signing_input_is_canonical(&input));
    }

    #[test]
    fn domain_label_is_validated() {
        let workspace = WorkspaceId::generate();
        assert_eq!(
            signing_input("", workspace, b"x").unwrap_err(),
            CryptoError::DomainLabelInvalid
        );
        assert_eq!(
            signing_input("bad\nlabel", workspace, b"x").unwrap_err(),
            CryptoError::DomainLabelInvalid
        );
        assert_eq!(
            signing_input(&"x".repeat(MAX_DOMAIN_LABEL_LEN + 1), workspace, b"x").unwrap_err(),
            CryptoError::DomainLabelInvalid
        );
    }

    #[test]
    fn secret_bytes_round_trip() {
        let keypair = DeviceKeypair::generate().unwrap();
        let exported = keypair.export_secret_bytes();
        let x = <[u8; X25519_LEN]>::try_from(&exported[..X25519_LEN]).unwrap();
        let ed = <[u8; 32]>::try_from(&exported[X25519_LEN..]).unwrap();
        let restored = DeviceKeypair::from_secret_bytes(x, ed).unwrap();
        assert_eq!(restored.public(), keypair.public());
    }
}
