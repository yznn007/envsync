//! 密封秘密对象：工作区数据密钥 + ChaCha20-Poly1305。
//!
//! ## 线格式
//!
//! ```text
//! SealedSecret = canonical_cbor([
//!     version,      // uint，SealedFormatVersion
//!     suite,        // text，算法套件名
//!     workspace_id, // bytes(16)
//!     secret_id,    // text，逻辑标识
//!     key_epoch,    // uint
//!     nonce,        // bytes(12)
//!     ciphertext,   // bytes，含 16 字节 Poly1305 tag
//! ])
//! ```
//!
//! **AAD = 除 `ciphertext` 外的 canonical header**，即
//! `canonical_cbor([version, suite, workspace_id, secret_id, key_epoch, nonce])`。
//! 于是版本、套件、工作区、秘密标识、纪元、nonce 六项中任何一位被改动，解密都会失败：
//! 把一条秘密的密文挪到另一个工作区、另一个逻辑名、另一个纪元下都不成立。
//!
//! ## 为什么 `SecretId` 是逻辑标识
//!
//! [`SecretId`] 是**用户给的名字**（`ci/npm-token`），**绝不**由明文摘要生成。如果用
//! 明文摘要当标识，两条值相同的秘密就会有相同标识，后端仅凭标识就能判断
//! 「A 项目的 token 和 B 项目的 token 是同一个」——这是明确要避免的相等性泄露。
//!
//! ## nonce
//!
//! [`seal`] 每次调用都从 [`rand_core::OsRng`] 取 96-bit 随机 nonce，**不接受调用者
//! 传入**。随机 nonce 在同一密钥下的碰撞概率是 2^-48 量级（生日界），配合每次撤销都
//! 轮换纪元密钥，实际风险可忽略。

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use envsync_domain::cbor::{CborCodec, CborError, Value};
use envsync_domain::id::WorkspaceId;
use zeroize::Zeroize;

use crate::suite::{
    CryptoSuite, DataKey, KeyEpoch, Plaintext, SealedFormatVersion, MAX_PLAINTEXT_LEN, NONCE_LEN,
    TAG_LEN,
};
use crate::CryptoError;

/// 秘密的逻辑标识。
///
/// 命名规则刻意收紧：由 `/` 分隔的段，每段只允许 ASCII 字母数字与 `-`、`_`、`.`。
/// 这样它可以安全地出现在文件名、URL、日志与 CBOR 文本串里，且不含控制字符。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretId(String);

impl SecretId {
    /// 允许的最大长度（字节）。
    pub const MAX_LEN: usize = 128;

    /// 解析并校验逻辑标识。
    pub fn parse(text: &str) -> Result<Self, CryptoError> {
        if text.is_empty() {
            return Err(CryptoError::SecretIdInvalid {
                reason: "不能为空"
            });
        }
        if text.len() > Self::MAX_LEN {
            return Err(CryptoError::SecretIdInvalid {
                reason: "超过长度上限",
            });
        }
        for segment in text.split('/') {
            if segment.is_empty() {
                return Err(CryptoError::SecretIdInvalid {
                    reason: "不能包含空段",
                });
            }
            if segment == "." || segment == ".." {
                return Err(CryptoError::SecretIdInvalid {
                    reason: "不能包含 `.` 或 `..` 段",
                });
            }
            if !segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            {
                return Err(CryptoError::SecretIdInvalid {
                    reason: "段包含非法字符",
                });
            }
        }
        Ok(SecretId(text.to_owned()))
    }

    /// 文本表示。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for SecretId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl CborCodec for SecretId {
    fn to_value(&self) -> Value {
        Value::Text(self.0.clone())
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        SecretId::parse(value.as_text()?).map_err(|err| CborError::InvalidValue(err.to_string()))
    }
}

/// 密封对象的 header：即 AEAD 的 AAD。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedHeader {
    /// 格式版本。
    pub version: SealedFormatVersion,
    /// 算法套件。
    pub suite: CryptoSuite,
    /// 所属工作区。
    pub workspace: WorkspaceId,
    /// 逻辑秘密标识。
    pub secret: SecretId,
    /// 加密所用数据密钥的纪元。
    pub epoch: KeyEpoch,
    /// 96-bit 随机 nonce。
    pub nonce: [u8; NONCE_LEN],
}

impl CborCodec for SealedHeader {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            self.version.to_value(),
            self.suite.to_value(),
            self.workspace.to_value(),
            self.secret.to_value(),
            self.epoch.to_value(),
            Value::Bytes(self.nonce.to_vec()),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        if items.len() != 6 {
            return Err(CborError::ArityMismatch);
        }
        Ok(SealedHeader {
            version: SealedFormatVersion::from_value(&items[0])?,
            suite: CryptoSuite::from_value(&items[1])?,
            workspace: WorkspaceId::from_value(&items[2])?,
            secret: SecretId::from_value(&items[3])?,
            epoch: KeyEpoch::from_value(&items[4])?,
            nonce: <[u8; NONCE_LEN]>::from_value(&items[5])?,
        })
    }
}

/// 密封后的秘密对象。密文与 header 都是公开材料，可以自由持久化。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedSecret {
    header: SealedHeader,
    ciphertext: Vec<u8>,
}

impl SealedSecret {
    /// header 视图（即 AAD 的逻辑内容）。
    pub fn header(&self) -> &SealedHeader {
        &self.header
    }

    /// 格式版本。
    pub fn version(&self) -> SealedFormatVersion {
        self.header.version
    }

    /// 算法套件。
    pub fn suite(&self) -> CryptoSuite {
        self.header.suite
    }

    /// 所属工作区。
    pub fn workspace(&self) -> WorkspaceId {
        self.header.workspace
    }

    /// 逻辑秘密标识。
    pub fn secret(&self) -> &SecretId {
        &self.header.secret
    }

    /// 数据密钥纪元。
    pub fn epoch(&self) -> KeyEpoch {
        self.header.epoch
    }

    /// nonce。
    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.header.nonce
    }

    /// 密文（含认证标签）。
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// AEAD 使用的 AAD 字节，即 canonical 编码的 header。
    pub fn aad(&self) -> Vec<u8> {
        self.header.to_canonical_vec()
    }

    /// 仅供测试：由任意组件拼装对象，用来构造篡改向量。
    #[cfg(feature = "test-vectors")]
    pub fn from_parts_for_tests(header: SealedHeader, ciphertext: Vec<u8>) -> Self {
        SealedSecret { header, ciphertext }
    }
}

impl CborCodec for SealedSecret {
    fn to_value(&self) -> Value {
        let Value::Array(mut fields) = self.header.to_value() else {
            unreachable!("SealedHeader 始终编码为数组")
        };
        fields.push(Value::Bytes(self.ciphertext.clone()));
        Value::Array(fields)
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        if items.len() != 7 {
            return Err(CborError::ArityMismatch);
        }
        let header = SealedHeader::from_value(&Value::Array(items[..6].to_vec()))?;
        let ciphertext = items[6].as_bytes()?.to_vec();
        if ciphertext.len() < TAG_LEN || ciphertext.len() > MAX_PLAINTEXT_LEN + TAG_LEN {
            return Err(CborError::InvalidValue("密文长度超出允许范围".to_owned()));
        }
        Ok(SealedSecret { header, ciphertext })
    }
}

/// 用数据密钥密封一条秘密。
///
/// nonce 由内部从 [`rand_core::OsRng`] 生成；明文超过 [`MAX_PLAINTEXT_LEN`] 时拒绝。
pub fn seal(
    key: &DataKey,
    workspace: WorkspaceId,
    secret: &SecretId,
    epoch: KeyEpoch,
    plaintext: &Plaintext,
) -> Result<SealedSecret, CryptoError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    crate::fill_random(&mut nonce_bytes)?;
    seal_with_nonce(key, workspace, secret, epoch, plaintext, nonce_bytes)
}

/// 仅供测试：用固定 nonce 密封，产生可断言的确定性向量。
///
/// **生产 API 绝不接受调用者传入 nonce**——nonce 复用会直接摧毁 ChaCha20-Poly1305 的
/// 安全性，所以这个入口只在 `test-vectors` feature 下存在。
#[cfg(feature = "test-vectors")]
pub fn seal_with_nonce_for_tests(
    key: &DataKey,
    workspace: WorkspaceId,
    secret: &SecretId,
    epoch: KeyEpoch,
    plaintext: &Plaintext,
    nonce: [u8; NONCE_LEN],
) -> Result<SealedSecret, CryptoError> {
    seal_with_nonce(key, workspace, secret, epoch, plaintext, nonce)
}

fn seal_with_nonce(
    key: &DataKey,
    workspace: WorkspaceId,
    secret: &SecretId,
    epoch: KeyEpoch,
    plaintext: &Plaintext,
    nonce_bytes: [u8; NONCE_LEN],
) -> Result<SealedSecret, CryptoError> {
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(CryptoError::PlaintextTooLarge {
            limit: MAX_PLAINTEXT_LEN,
        });
    }

    let header = SealedHeader {
        version: SealedFormatVersion::V1,
        suite: CryptoSuite::Esv1,
        workspace,
        secret: secret.clone(),
        epoch,
        nonce: nonce_bytes,
    };
    let aad = header.to_canonical_vec();

    let cipher = ChaCha20Poly1305::new_from_slice(key.expose_bytes())
        .map_err(|_| CryptoError::KeyDerivation)?;
    let mut buffer = plaintext.expose().to_vec();
    let result = cipher.encrypt_in_place(Nonce::from_slice(&nonce_bytes), &aad, &mut buffer);
    if result.is_err() {
        // 失败时 buffer 里仍是明文副本，必须清零后再放弃。
        buffer.zeroize();
        return Err(CryptoError::Authentication);
    }

    Ok(SealedSecret {
        header,
        ciphertext: buffer,
    })
}

/// 打开密封对象。
///
/// 检查顺序：版本 → 套件 → 长度 → 密码学。所有失败都归一到
/// [`CryptoError::Authentication`]，不区分「密钥不对」「AAD 不对」「tag 不对」。
pub fn open(key: &DataKey, sealed: &SealedSecret) -> Result<Plaintext, CryptoError> {
    if sealed.header.version != SealedFormatVersion::V1 {
        return Err(CryptoError::UnsupportedFormatVersion {
            found: sealed.header.version.get(),
            supported: SealedFormatVersion::V1.get(),
        });
    }
    if sealed.header.suite != CryptoSuite::Esv1 {
        return Err(CryptoError::UnsupportedSuite);
    }
    if sealed.ciphertext.len() < TAG_LEN {
        return Err(CryptoError::InvalidLength {
            field: "ciphertext",
            expected: TAG_LEN,
            found: sealed.ciphertext.len(),
        });
    }
    if sealed.ciphertext.len() > MAX_PLAINTEXT_LEN + TAG_LEN {
        return Err(CryptoError::CiphertextTooLarge {
            limit: MAX_PLAINTEXT_LEN + TAG_LEN,
        });
    }

    let aad = sealed.aad();
    let cipher = ChaCha20Poly1305::new_from_slice(key.expose_bytes())
        .map_err(|_| CryptoError::KeyDerivation)?;
    let mut buffer = sealed.ciphertext.clone();
    match cipher.decrypt_in_place(Nonce::from_slice(&sealed.header.nonce), &aad, &mut buffer) {
        Ok(()) => Ok(Plaintext::from_vec(buffer)),
        Err(_) => {
            // 认证失败时缓冲区可能含有部分解密结果，消费前先清零。
            buffer.zeroize();
            Err(CryptoError::Authentication)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_id_rejects_path_like_forms() {
        assert!(SecretId::parse("ci/npm-token").is_ok());
        assert!(SecretId::parse("").is_err());
        assert!(SecretId::parse("a//b").is_err());
        assert!(SecretId::parse("../escape").is_err());
        assert!(SecretId::parse("a b").is_err());
        assert!(SecretId::parse(&"x".repeat(SecretId::MAX_LEN + 1)).is_err());
    }

    #[test]
    fn aad_is_header_without_ciphertext() {
        let key = DataKey::from_bytes([1u8; 32]); // 仅供测试的固定密钥
        let workspace = WorkspaceId::generate();
        let secret = SecretId::parse("test/value").unwrap();
        let sealed = seal(
            &key,
            workspace,
            &secret,
            KeyEpoch::INITIAL,
            &Plaintext::from_slice(b"v"),
        )
        .unwrap();
        assert_eq!(sealed.aad(), sealed.header().to_canonical_vec());
        // header 是 6 元数组，完整对象是 7 元数组。
        assert_ne!(sealed.aad(), sealed.to_canonical_vec());
    }
}
