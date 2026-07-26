//! HPKE 设备信封：把工作区数据密钥分发给单台设备。
//!
//! 每个 active 设备一个信封，内容是 [`DataKey`] 与它所属的 [`KeyEpoch`]。信封本体是
//! 公开材料，可以随快照一起放在不受信任的后端上。
//!
//! # 构造：RFC 9180 base 模式
//!
//! 本模块不发明 KEM，而是按 [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180)
//! §4.1（DHKEM(X25519, HKDF-SHA256)）与 §5.1（`mode_base` key schedule）逐步实现，
//! 底层原语分别来自 `x25519-dalek`（DH）、`hkdf` + `sha2`（HKDF-SHA256）与
//! `chacha20poly1305`（AEAD）。算法标识：
//!
//! | 项 | 值 |
//! |---|---|
//! | `kem_id` | `0x0020`（DHKEM(X25519, HKDF-SHA256)） |
//! | `kdf_id` | `0x0001`（HKDF-SHA256） |
//! | `aead_id` | `0x0003`（ChaCha20-Poly1305） |
//! | `mode` | `0x00`（base，无 PSK、无发送方认证） |
//!
//! ## 完整密钥派生链
//!
//! 记 `LabeledExtract(salt, label, ikm) = HKDF-Extract(salt, "HPKE-v1" || suite_id || label || ikm)`，
//! `LabeledExpand(prk, label, info, L) = HKDF-Expand(prk, I2OSP(L,2) || "HPKE-v1" || suite_id || label || info, L)`。
//!
//! **第一步：DHKEM 封装**（`suite_id = "KEM" || I2OSP(0x0020, 2)`，共 5 字节）
//!
//! | # | 输出 | 计算 | 长度 |
//! |---|---|---|---|
//! | 1 | `(esk, enc)` | X25519 临时密钥对，`esk` 取自 `OsRng`，`enc = X25519(esk, 9)` | 32 |
//! | 2 | `dh` | `X25519(esk, pkR)`，随后检查非全零（贡献性） | 32 |
//! | 3 | `kem_context` | `enc || pkR` | 64 |
//! | 4 | `eae_prk` | `LabeledExtract(salt = "", label = "eae_prk", ikm = dh)` | 32 |
//! | 5 | `shared_secret` | `LabeledExpand(eae_prk, "shared_secret", kem_context, 32)` | 32 |
//!
//! **第二步：base 模式 key schedule**
//! （`suite_id = "HPKE" || I2OSP(0x0020,2) || I2OSP(0x0001,2) || I2OSP(0x0003,2)`，共 10 字节）
//!
//! | # | 输出 | 计算 | 长度 |
//! |---|---|---|---|
//! | 6 | `psk_id_hash` | `LabeledExtract("", "psk_id_hash", "")` | 32 |
//! | 7 | `info_hash` | `LabeledExtract("", "info_hash", info)` | 32 |
//! | 8 | `key_schedule_context` | `0x00 || psk_id_hash || info_hash` | 65 |
//! | 9 | `secret` | `LabeledExtract(salt = shared_secret, "secret", ikm = "")` | 32 |
//! | 10 | `key` | `LabeledExpand(secret, "key", key_schedule_context, 32)` | 32 |
//! | 11 | `base_nonce` | `LabeledExpand(secret, "base_nonce", key_schedule_context, 12)` | 12 |
//!
//! 单次封装（`seq = 0`）因此 `nonce = base_nonce`。导出接口（`exporter_secret`）在 M2
//! 用不到，故未派生。
//!
//! **第三步：AEAD**
//!
//! ```text
//! ciphertext = ChaCha20Poly1305-Seal(key, base_nonce, aad, data_key)
//! ```
//!
//! ## `info` 与 `aad` 的绑定内容
//!
//! ```text
//! info = canonical_cbor([
//!     "envsync:key-envelope:v1",   // 域标签
//!     1,                           // 信封格式版本
//!     "ESV1_...",                  // 套件名
//!     workspace_id  (bytes 16),
//!     recipient     (bytes 32，DeviceId 摘要 = H(x25519_pk || ed25519_pk))
//!     epoch         (uint),
//! ])
//!
//! aad = canonical_cbor([1, suite, workspace_id, recipient, epoch, enc])
//! ```
//!
//! `info` 把工作区、收件设备与纪元烙进 AEAD 密钥本身；`aad` 额外把 `enc` 绑定进认证
//! 标签。结论：
//!
//! * **只有目标设备能打开**——`shared_secret` 需要 `skR`；
//! * **交换两台设备的信封失败**——`pkR` 进入 `kem_context`，且 `recipient` 进入 `info`；
//! * **降级 epoch 失败**——`epoch` 同时在 `info` 和 `aad` 里；
//! * **跨工作区重放失败**——`workspace_id` 同时在 `info` 和 `aad` 里。
//!
//! ## 使用顺序
//!
//! 信封对象本身应当由管理员设备签名后上传；**成员链验证必须先于打开信封**，否则攻击者
//! 可以用一个自己生成的数据密钥替换信封，把后续写入的秘密引导到它控制的密钥上。本
//! 模块只负责密码学部分，链验证在 `envsync-core`。

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use envsync_domain::cbor::{encode, CborCodec, CborError, Value};
use envsync_domain::id::{DeviceId, Digest32, WorkspaceId};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::{Zeroize, Zeroizing};

use crate::device::{DeviceKeypair, DevicePublic};
use crate::suite::{
    CryptoSuite, DataKey, KeyEpoch, SealedFormatVersion, KEY_LEN, NONCE_LEN, TAG_LEN, X25519_LEN,
};
use crate::CryptoError;

/// 信封 `info` 串的域标签。
pub const ENVELOPE_INFO_DOMAIN: &str = "envsync:key-envelope:v1";

/// HPKE `kem_id`：DHKEM(X25519, HKDF-SHA256)。
const KEM_ID: u16 = 0x0020;
/// HPKE `kdf_id`：HKDF-SHA256。
const KDF_ID: u16 = 0x0001;
/// HPKE `aead_id`：ChaCha20-Poly1305。
const AEAD_ID: u16 = 0x0003;
/// HPKE `mode_base`。
const MODE_BASE: u8 = 0x00;
/// RFC 9180 的版本前缀。
const HPKE_VERSION_LABEL: &[u8] = b"HPKE-v1";

/// 信封密文长度：32 字节数据密钥 + 16 字节 tag。
pub const ENVELOPE_CIPHERTEXT_LEN: usize = KEY_LEN + TAG_LEN;

/// 分发给单台设备的数据密钥信封。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEnvelope {
    version: SealedFormatVersion,
    suite: CryptoSuite,
    workspace: WorkspaceId,
    recipient: DeviceId,
    epoch: KeyEpoch,
    enc: [u8; X25519_LEN],
    ciphertext: Vec<u8>,
}

impl KeyEnvelope {
    /// 格式版本。
    pub fn version(&self) -> SealedFormatVersion {
        self.version
    }

    /// 算法套件。
    pub fn suite(&self) -> CryptoSuite {
        self.suite
    }

    /// 所属工作区。
    pub fn workspace(&self) -> WorkspaceId {
        self.workspace
    }

    /// 收件设备标识。
    pub fn recipient(&self) -> DeviceId {
        self.recipient
    }

    /// 信封内数据密钥的纪元。
    pub fn epoch(&self) -> KeyEpoch {
        self.epoch
    }

    /// DHKEM 封装出的临时公钥 `enc`。
    pub fn enc(&self) -> &[u8; X25519_LEN] {
        &self.enc
    }

    /// 密文（含认证标签）。
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// AEAD 使用的 AAD。
    pub fn aad(&self) -> Vec<u8> {
        encode(&Value::Array(vec![
            self.version.to_value(),
            self.suite.to_value(),
            self.workspace.to_value(),
            self.recipient.to_value(),
            self.epoch.to_value(),
            Value::Bytes(self.enc.to_vec()),
        ]))
    }

    /// HPKE `info` 串。
    pub fn info(&self) -> Vec<u8> {
        envelope_info(self.version, self.workspace, self.recipient, self.epoch)
    }

    /// 仅供测试：由任意组件拼装信封，用来构造篡改与降级向量。
    #[cfg(feature = "test-vectors")]
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_for_tests(
        version: SealedFormatVersion,
        suite: CryptoSuite,
        workspace: WorkspaceId,
        recipient: DeviceId,
        epoch: KeyEpoch,
        enc: [u8; X25519_LEN],
        ciphertext: Vec<u8>,
    ) -> Self {
        KeyEnvelope {
            version,
            suite,
            workspace,
            recipient,
            epoch,
            enc,
            ciphertext,
        }
    }
}

impl CborCodec for KeyEnvelope {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            self.version.to_value(),
            self.suite.to_value(),
            self.workspace.to_value(),
            self.recipient.to_value(),
            self.epoch.to_value(),
            Value::Bytes(self.enc.to_vec()),
            Value::Bytes(self.ciphertext.clone()),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        if items.len() != 7 {
            return Err(CborError::ArityMismatch);
        }
        let ciphertext = items[6].as_bytes()?.to_vec();
        if ciphertext.len() != ENVELOPE_CIPHERTEXT_LEN {
            return Err(CborError::LengthMismatch {
                expected: ENVELOPE_CIPHERTEXT_LEN,
            });
        }
        Ok(KeyEnvelope {
            version: SealedFormatVersion::from_value(&items[0])?,
            suite: CryptoSuite::from_value(&items[1])?,
            workspace: WorkspaceId::from_value(&items[2])?,
            recipient: DeviceId::from_value(&items[3])?,
            epoch: KeyEpoch::from_value(&items[4])?,
            enc: <[u8; X25519_LEN]>::from_value(&items[5])?,
            ciphertext,
        })
    }
}

/// 构造 HPKE `info` 串。公开以便审计与独立复现。
pub fn envelope_info(
    version: SealedFormatVersion,
    workspace: WorkspaceId,
    recipient: DeviceId,
    epoch: KeyEpoch,
) -> Vec<u8> {
    encode(&Value::Array(vec![
        Value::Text(ENVELOPE_INFO_DOMAIN.to_owned()),
        version.to_value(),
        Value::Text(CryptoSuite::Esv1.as_str().to_owned()),
        workspace.to_value(),
        recipient.to_value(),
        epoch.to_value(),
    ]))
}

/// 为目标设备封装一份工作区数据密钥。
///
/// 临时密钥（`esk`）与全部随机性都来自 [`rand_core::OsRng`]；调用者不能注入 nonce
/// 或临时密钥。
pub fn seal_envelope(
    recipient: &DevicePublic,
    workspace: WorkspaceId,
    epoch: KeyEpoch,
    data_key: &DataKey,
) -> Result<KeyEnvelope, CryptoError> {
    let mut esk_seed = [0u8; X25519_LEN];
    crate::fill_random(&mut esk_seed)?;
    let envelope = seal_envelope_with_ephemeral(recipient, workspace, epoch, data_key, esk_seed);
    esk_seed.zeroize();
    envelope
}

/// 仅供测试：用固定临时私钥封装，产生可断言的确定性向量。
///
/// 生产 API 的临时密钥只来自 [`rand_core::OsRng`]；固定临时密钥会让同一收件人的两个
/// 信封复用同一对 AEAD key/nonce，因此这个入口只在 `test-vectors` feature 下存在。
#[cfg(feature = "test-vectors")]
pub fn seal_envelope_with_ephemeral_for_tests(
    recipient: &DevicePublic,
    workspace: WorkspaceId,
    epoch: KeyEpoch,
    data_key: &DataKey,
    ephemeral_secret: [u8; X25519_LEN],
) -> Result<KeyEnvelope, CryptoError> {
    seal_envelope_with_ephemeral(recipient, workspace, epoch, data_key, ephemeral_secret)
}

fn seal_envelope_with_ephemeral(
    recipient: &DevicePublic,
    workspace: WorkspaceId,
    epoch: KeyEpoch,
    data_key: &DataKey,
    esk_seed: [u8; X25519_LEN],
) -> Result<KeyEnvelope, CryptoError> {
    recipient.validate()?;
    let recipient_id = recipient.device_id();
    let pk_r = X25519Public::from(recipient.x25519);

    // 步骤 1-2：临时密钥对与 DH。
    // `StaticSecret` 在 `zeroize` feature 下 Drop 即清零。
    let esk = X25519Secret::from(esk_seed);
    let enc = X25519Public::from(&esk).to_bytes();
    let dh = esk.diffie_hellman(&pk_r);
    if !dh.was_contributory() {
        return Err(CryptoError::NonContributoryKeyExchange);
    }

    // 步骤 3-5：DHKEM。
    let shared_secret = dhkem_shared_secret(dh.as_bytes(), &enc, &pk_r.to_bytes())?;

    // 步骤 6-11：key schedule。
    let info = envelope_info(SealedFormatVersion::V1, workspace, recipient_id, epoch);
    let HpkeContext { key, base_nonce } = key_schedule(&shared_secret, &info)?;

    let mut envelope = KeyEnvelope {
        version: SealedFormatVersion::V1,
        suite: CryptoSuite::Esv1,
        workspace,
        recipient: recipient_id,
        epoch,
        enc,
        ciphertext: Vec::new(),
    };
    let aad = envelope.aad();

    let cipher =
        ChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| CryptoError::KeyDerivation)?;
    let mut buffer = data_key.expose_bytes().to_vec();
    let result = cipher.encrypt_in_place(Nonce::from_slice(&base_nonce[..]), &aad, &mut buffer);
    if result.is_err() {
        buffer.zeroize();
        return Err(CryptoError::Authentication);
    }
    envelope.ciphertext = buffer;
    Ok(envelope)
}

/// 用设备私钥打开信封，取回工作区数据密钥。
///
/// 检查顺序：版本 → 套件 → 收件人 → 长度 → 密码学。
pub fn open_envelope(
    recipient: &DeviceKeypair,
    envelope: &KeyEnvelope,
) -> Result<DataKey, CryptoError> {
    if envelope.version != SealedFormatVersion::V1 {
        return Err(CryptoError::UnsupportedFormatVersion {
            found: envelope.version.get(),
            supported: SealedFormatVersion::V1.get(),
        });
    }
    if envelope.suite != CryptoSuite::Esv1 {
        return Err(CryptoError::UnsupportedSuite);
    }
    if envelope.recipient != recipient.device_id() {
        return Err(CryptoError::RecipientMismatch);
    }
    if envelope.ciphertext.len() != ENVELOPE_CIPHERTEXT_LEN {
        return Err(CryptoError::InvalidLength {
            field: "envelope_ciphertext",
            expected: ENVELOPE_CIPHERTEXT_LEN,
            found: envelope.ciphertext.len(),
        });
    }

    let pk_r = recipient.public().x25519;
    let enc_public = X25519Public::from(envelope.enc);
    let dh = recipient.x25519_secret().diffie_hellman(&enc_public);
    if !dh.was_contributory() {
        return Err(CryptoError::NonContributoryKeyExchange);
    }

    let shared_secret = dhkem_shared_secret(dh.as_bytes(), &envelope.enc, &pk_r)?;
    let info = envelope.info();
    let HpkeContext { key, base_nonce } = key_schedule(&shared_secret, &info)?;
    let aad = envelope.aad();

    let cipher =
        ChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| CryptoError::KeyDerivation)?;
    let mut buffer = envelope.ciphertext.clone();
    match cipher.decrypt_in_place(Nonce::from_slice(&base_nonce[..]), &aad, &mut buffer) {
        Ok(()) => {
            let key = DataKey::from_slice(&buffer);
            buffer.zeroize();
            key
        }
        Err(_) => {
            buffer.zeroize();
            Err(CryptoError::Authentication)
        }
    }
}

/// `suite_id` for DHKEM：`"KEM" || I2OSP(kem_id, 2)`。
fn kem_suite_id() -> [u8; 5] {
    let mut out = [0u8; 5];
    out[..3].copy_from_slice(b"KEM");
    out[3..].copy_from_slice(&KEM_ID.to_be_bytes());
    out
}

/// `suite_id` for HPKE：`"HPKE" || I2OSP(kem_id,2) || I2OSP(kdf_id,2) || I2OSP(aead_id,2)`。
fn hpke_suite_id() -> [u8; 10] {
    let mut out = [0u8; 10];
    out[..4].copy_from_slice(b"HPKE");
    out[4..6].copy_from_slice(&KEM_ID.to_be_bytes());
    out[6..8].copy_from_slice(&KDF_ID.to_be_bytes());
    out[8..].copy_from_slice(&AEAD_ID.to_be_bytes());
    out
}

/// RFC 9180 §4 的 `LabeledExtract`。
fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut labeled_ikm = Zeroizing::new(Vec::with_capacity(
        HPKE_VERSION_LABEL.len() + suite_id.len() + label.len() + ikm.len(),
    ));
    labeled_ikm.extend_from_slice(HPKE_VERSION_LABEL);
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled_ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(prk.as_slice());
    Zeroizing::new(out)
}

/// RFC 9180 §4 的 `LabeledExpand`。
fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let length = u16::try_from(out.len()).map_err(|_| CryptoError::KeyDerivation)?;
    let mut labeled_info = Zeroizing::new(Vec::with_capacity(
        2 + HPKE_VERSION_LABEL.len() + suite_id.len() + label.len() + info.len(),
    ));
    labeled_info.extend_from_slice(&length.to_be_bytes());
    labeled_info.extend_from_slice(HPKE_VERSION_LABEL);
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| CryptoError::KeyDerivation)?
        .expand(&labeled_info, out)
        .map_err(|_| CryptoError::KeyDerivation)
}

/// DHKEM(X25519, HKDF-SHA256) 的 `shared_secret`（派生链步骤 3-5）。
fn dhkem_shared_secret(
    dh: &[u8; 32],
    enc: &[u8; X25519_LEN],
    pk_r: &[u8; X25519_LEN],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let suite_id = kem_suite_id();
    let mut kem_context = [0u8; 2 * X25519_LEN];
    kem_context[..X25519_LEN].copy_from_slice(enc);
    kem_context[X25519_LEN..].copy_from_slice(pk_r);

    let eae_prk = labeled_extract(&suite_id, b"", b"eae_prk", dh);
    let mut shared_secret = Zeroizing::new([0u8; 32]);
    labeled_expand(
        &suite_id,
        &eae_prk[..],
        b"shared_secret",
        &kem_context,
        &mut shared_secret[..],
    )?;
    Ok(shared_secret)
}

/// base 模式 key schedule 的输出：AEAD 密钥与基础 nonce。
struct HpkeContext {
    key: Zeroizing<[u8; KEY_LEN]>,
    base_nonce: Zeroizing<[u8; NONCE_LEN]>,
}

/// RFC 9180 §5.1 `mode_base` 的 key schedule（派生链步骤 6-11）。
fn key_schedule(shared_secret: &[u8; 32], info: &[u8]) -> Result<HpkeContext, CryptoError> {
    let suite_id = hpke_suite_id();
    let psk_id_hash = labeled_extract(&suite_id, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(&suite_id, b"", b"info_hash", info);

    let mut key_schedule_context = [0u8; 1 + 32 + 32];
    key_schedule_context[0] = MODE_BASE;
    key_schedule_context[1..33].copy_from_slice(&psk_id_hash[..]);
    key_schedule_context[33..].copy_from_slice(&info_hash[..]);

    let secret = labeled_extract(&suite_id, shared_secret, b"secret", b"");

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    labeled_expand(
        &suite_id,
        &secret[..],
        b"key",
        &key_schedule_context,
        &mut key[..],
    )?;

    let mut base_nonce = Zeroizing::new([0u8; NONCE_LEN]);
    labeled_expand(
        &suite_id,
        &secret[..],
        b"base_nonce",
        &key_schedule_context,
        &mut base_nonce[..],
    )?;

    Ok(HpkeContext { key, base_nonce })
}

/// 信封的公开指纹，用于日志与审计（不泄露任何密钥材料）。
pub fn envelope_fingerprint(envelope: &KeyEnvelope) -> Digest32 {
    Digest32::domain_hash(
        "envsync:key-envelope-fingerprint:v1",
        &envelope.to_canonical_vec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_ids_match_rfc9180_identifiers() {
        assert_eq!(kem_suite_id(), *b"KEM\x00\x20");
        assert_eq!(hpke_suite_id(), *b"HPKE\x00\x20\x00\x01\x00\x03");
    }

    #[test]
    fn key_schedule_is_deterministic_and_info_bound() {
        let shared = [9u8; 32]; // 仅供测试的固定共享秘密
        let a = key_schedule(&shared, b"info-a").unwrap();
        let b = key_schedule(&shared, b"info-a").unwrap();
        assert_eq!(&a.key[..], &b.key[..]);
        assert_eq!(&a.base_nonce[..], &b.base_nonce[..]);

        let c = key_schedule(&shared, b"info-b").unwrap();
        assert_ne!(&a.key[..], &c.key[..]);
    }
}
