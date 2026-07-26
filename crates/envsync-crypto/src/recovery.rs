//! Argon2id 恢复包与带校验的恢复短语。
//!
//! 恢复流程解决的是「所有设备都丢了」这一场景：用户手上只有一串离线抄写的短语，凭它
//! 解开一个存放在后端的加密包，包里是重建工作区访问权所需的恢复材料。
//!
//! ## 恢复短语编码
//!
//! ```text
//! entropy   = 16 字节（128 bit）系统随机数
//! checksum  = BLAKE3_domain("envsync:recovery-phrase:v1", entropy)[0..4]
//! payload   = entropy || checksum                       // 20 字节 = 160 bit
//! phrase    = Base32-Crockford(payload)                 // 恰好 32 个符号，无填充
//! 展示形式   = 8 组 × 4 符号，用 `-` 分隔
//! ```
//!
//! 选 Crockford 字母表（`0123456789ABCDEFGHJKMNPQRSTVWXYZ`，剔除 `I`/`L`/`O`/`U`）是
//! 为了抄写不易混淆；解析时接受小写并按 Crockford 规则把 `O` 归一到 `0`、`I`/`L` 归一
//! 到 `1`。160 bit 恰好是 32 个 5-bit 组，因此**不存在填充位**，编码是双射的。
//! 32-bit 校验和意味着任何单字符录入错误都会被发现（漏检概率 2^-32），
//! `tests/recovery_package.rs` 用穷举所有单字符替换来验证这一点。
//!
//! ## 恢复包
//!
//! ```text
//! RecoveryPackage = canonical_cbor([
//!     version, suite, memory_kib, time_cost, parallelism, salt(16), nonce(12), ciphertext
//! ])
//!
//! kek_raw = Argon2id(password = entropy(16), salt = salt(16), params, out_len = 32)
//! kek     = HKDF-SHA256-Expand(
//!               HKDF-SHA256-Extract(salt = "envsync:recovery-kek:v1", ikm = kek_raw),
//!               info = canonical_header,   // 版本/套件/参数/salt/nonce
//!               32)
//! ciphertext = ChaCha20Poly1305-Seal(kek, nonce, aad = canonical_header, payload)
//! ```
//!
//! Argon2id 的输出再过一次 HKDF，是为了把**格式版本、套件与全部 KDF 参数**绑进最终
//! 密钥：即便有人改写包里记录的参数，派生出的密钥也会不同，解密直接失败。
//!
//! ## 参数边界
//!
//! | 方向 | 规则 |
//! |---|---|
//! | 创建 | `memory >= 64 MiB`、`time >= 3`、`parallelism >= 1`，低于下限**拒绝创建** |
//! | 读取 | 允许比下限更高的参数，但 `memory <= 2 GiB`、`time <= 32`、`parallelism <= 16` |
//!
//! 上限的作用是拒绝「畸形包」：攻击者把 `memory` 写成 `u32::MAX` 时，本实现在做任何
//! 分配之前就返回 [`CryptoError::KdfParametersTooLarge`]，而不是尝试申请 4 TiB 内存。
//!
//! ## 错误归一
//!
//! 口令错误、密文被改、tag 被改、参数在合法区间内被改——全部返回同一个
//! [`CryptoError::Authentication`]，不给攻击者可用的区分 oracle。

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use envsync_domain::cbor::{encode, CborCodec, CborError, Value};
use envsync_domain::id::Digest32;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::suite::{
    CryptoSuite, Plaintext, SealedFormatVersion, KEY_LEN, MAX_PLAINTEXT_LEN, NONCE_LEN, TAG_LEN,
};
use crate::CryptoError;

/// 恢复短语熵的字节数（128 bit）。
pub const RECOVERY_ENTROPY_LEN: usize = 16;
/// 恢复短语校验和的字节数（32 bit）。
pub const RECOVERY_CHECKSUM_LEN: usize = 4;
/// 恢复短语的符号数（`(16 + 4) * 8 / 5`）。
pub const RECOVERY_PHRASE_SYMBOLS: usize = 32;
/// 展示时每组的符号数。
pub const RECOVERY_PHRASE_GROUP: usize = 4;
/// 恢复短语校验和的域标签。
pub const RECOVERY_PHRASE_DOMAIN: &str = "envsync:recovery-phrase:v1";
/// 恢复 KEK 的 HKDF salt。
pub const RECOVERY_KEK_DOMAIN: &[u8] = b"envsync:recovery-kek:v1";
/// 恢复包 salt 的字节数。
pub const RECOVERY_SALT_LEN: usize = 16;

/// Base32-Crockford 字母表（剔除易混淆的 `I`、`L`、`O`、`U`）。
const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

// ---------------------------------------------------------------------------
// 恢复短语
// ---------------------------------------------------------------------------

/// 128-bit 恢复短语。
///
/// **刻意不实现** `Debug`、`Display`、[`CborCodec`] 与序列化；`Drop` 时清零。
/// 唯一的展示入口是 [`RecoveryPhrase::display_once`]，并且它一辈子只成功一次
/// ——「只展示一次」被写进了类型的状态里，而不是写在文档里靠人记住。
///
/// 同样刻意不实现 `Clone`：否则「先克隆再展示两次」就能绕过上面这条约束。
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryPhrase {
    entropy: [u8; RECOVERY_ENTROPY_LEN],
    revealed: bool,
}

impl RecoveryPhrase {
    /// 从 [`rand_core::OsRng`] 生成 128-bit 熵。
    pub fn generate() -> Result<Self, CryptoError> {
        let mut entropy = [0u8; RECOVERY_ENTROPY_LEN];
        crate::fill_random(&mut entropy)?;
        Ok(RecoveryPhrase {
            entropy,
            revealed: false,
        })
    }

    /// 解析用户抄回来的短语；校验位不匹配时报错。
    ///
    /// 接受大小写混排、任意位置的 `-` 与空白，并按 Crockford 规则归一 `O`→`0`、
    /// `I`/`L`→`1`。
    pub fn parse(text: &str) -> Result<Self, CryptoError> {
        let mut symbols = Vec::with_capacity(RECOVERY_PHRASE_SYMBOLS);
        for ch in text.chars() {
            if ch == '-' || ch.is_whitespace() {
                continue;
            }
            symbols.push(crockford_value(ch).ok_or(CryptoError::RecoveryPhraseMalformed)?);
            if symbols.len() > RECOVERY_PHRASE_SYMBOLS {
                return Err(CryptoError::RecoveryPhraseMalformed);
            }
        }
        if symbols.len() != RECOVERY_PHRASE_SYMBOLS {
            return Err(CryptoError::RecoveryPhraseMalformed);
        }

        let mut payload = Zeroizing::new([0u8; RECOVERY_ENTROPY_LEN + RECOVERY_CHECKSUM_LEN]);
        let mut accumulator: u16 = 0;
        let mut bits = 0u32;
        let mut index = 0usize;
        for symbol in symbols {
            accumulator = (accumulator << 5) | symbol as u16;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                payload[index] = (accumulator >> bits) as u8;
                index += 1;
            }
        }
        debug_assert_eq!(index, payload.len());
        debug_assert_eq!(bits, 0);

        let mut entropy = [0u8; RECOVERY_ENTROPY_LEN];
        entropy.copy_from_slice(&payload[..RECOVERY_ENTROPY_LEN]);
        let expected = phrase_checksum(&entropy);
        // 校验位是完整性检查而非认证标签，按位比较即可（无秘密可供计时区分）。
        if payload[RECOVERY_ENTROPY_LEN..] != expected {
            entropy.zeroize();
            return Err(CryptoError::RecoveryPhraseChecksum);
        }
        Ok(RecoveryPhrase {
            entropy,
            revealed: false,
        })
    }

    /// 展示短语，**只成功一次**。第二次调用返回
    /// [`CryptoError::RecoveryPhraseAlreadyRevealed`]。
    ///
    /// 返回值是 [`Zeroizing<String>`]，离开作用域即清零。
    pub fn display_once(&mut self) -> Result<Zeroizing<String>, CryptoError> {
        if self.revealed {
            return Err(CryptoError::RecoveryPhraseAlreadyRevealed);
        }
        self.revealed = true;
        Ok(self.render())
    }

    /// 是否已经展示过。
    pub fn is_revealed(&self) -> bool {
        self.revealed
    }

    fn render(&self) -> Zeroizing<String> {
        let mut payload = Zeroizing::new([0u8; RECOVERY_ENTROPY_LEN + RECOVERY_CHECKSUM_LEN]);
        payload[..RECOVERY_ENTROPY_LEN].copy_from_slice(&self.entropy);
        payload[RECOVERY_ENTROPY_LEN..].copy_from_slice(&phrase_checksum(&self.entropy));

        let mut out = String::with_capacity(
            RECOVERY_PHRASE_SYMBOLS + RECOVERY_PHRASE_SYMBOLS / RECOVERY_PHRASE_GROUP,
        );
        let mut accumulator: u16 = 0;
        let mut bits = 0u32;
        let mut emitted = 0usize;
        for byte in payload.iter() {
            accumulator = (accumulator << 8) | *byte as u16;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                let symbol = ((accumulator >> bits) & 0x1f) as usize;
                if emitted != 0 && emitted % RECOVERY_PHRASE_GROUP == 0 {
                    out.push('-');
                }
                out.push(CROCKFORD_ALPHABET[symbol] as char);
                emitted += 1;
            }
        }
        debug_assert_eq!(bits, 0);
        debug_assert_eq!(emitted, RECOVERY_PHRASE_SYMBOLS);
        Zeroizing::new(out)
    }

    /// 作为 KDF 口令使用的字节：直接用 128-bit 熵，避免依赖文本归一化规则。
    fn password_bytes(&self) -> &[u8; RECOVERY_ENTROPY_LEN] {
        &self.entropy
    }

    /// 仅供测试：由固定熵构造短语，用于确定性向量。
    #[cfg(feature = "test-vectors")]
    pub fn from_entropy_for_tests(entropy: [u8; RECOVERY_ENTROPY_LEN]) -> Self {
        RecoveryPhrase {
            entropy,
            revealed: false,
        }
    }

    /// 仅供测试：渲染短语但不消耗「只展示一次」的额度。
    #[cfg(feature = "test-vectors")]
    pub fn render_for_tests(&self) -> Zeroizing<String> {
        self.render()
    }
}

fn phrase_checksum(entropy: &[u8; RECOVERY_ENTROPY_LEN]) -> [u8; RECOVERY_CHECKSUM_LEN] {
    let digest = Digest32::domain_hash(RECOVERY_PHRASE_DOMAIN, entropy);
    let mut out = [0u8; RECOVERY_CHECKSUM_LEN];
    out.copy_from_slice(&digest.as_bytes()[..RECOVERY_CHECKSUM_LEN]);
    out
}

/// Crockford 解码：接受大小写，并归一 `O`→`0`、`I`/`L`→`1`。
fn crockford_value(ch: char) -> Option<u8> {
    let upper = ch.to_ascii_uppercase();
    match upper {
        'O' => return Some(0),
        'I' | 'L' => return Some(1),
        _ => {}
    }
    CROCKFORD_ALPHABET
        .iter()
        .position(|&c| c == upper as u8)
        .map(|index| index as u8)
}

// ---------------------------------------------------------------------------
// Argon2id 参数
// ---------------------------------------------------------------------------

/// 已校验的 Argon2id 参数。
///
/// 构造函数是唯一入口，因此**不可能**存在一个越界的 `Argon2Params` 值。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
}

impl Argon2Params {
    /// 项目安全下限：内存 64 MiB。
    pub const MIN_MEMORY_KIB: u32 = 64 * 1024;
    /// 项目安全下限：迭代 3 次。
    pub const MIN_TIME_COST: u32 = 3;
    /// 项目安全下限：并行度 1。
    pub const MIN_PARALLELISM: u32 = 1;
    /// 本机资源上限：内存 2 GiB。
    pub const MAX_MEMORY_KIB: u32 = 2 * 1024 * 1024;
    /// 本机资源上限：迭代 32 次。
    pub const MAX_TIME_COST: u32 = 32;
    /// 本机资源上限：并行度 16。
    pub const MAX_PARALLELISM: u32 = 16;

    /// 校验并构造参数。低于下限或高于上限都会被拒绝。
    pub fn new(memory_kib: u32, time_cost: u32, parallelism: u32) -> Result<Self, CryptoError> {
        if memory_kib > Self::MAX_MEMORY_KIB
            || time_cost > Self::MAX_TIME_COST
            || parallelism > Self::MAX_PARALLELISM
        {
            return Err(CryptoError::KdfParametersTooLarge {
                max_memory_kib: Self::MAX_MEMORY_KIB,
                max_time: Self::MAX_TIME_COST,
                max_parallelism: Self::MAX_PARALLELISM,
            });
        }
        if memory_kib < Self::MIN_MEMORY_KIB
            || time_cost < Self::MIN_TIME_COST
            || parallelism < Self::MIN_PARALLELISM
        {
            return Err(CryptoError::KdfParametersTooWeak {
                min_memory_kib: Self::MIN_MEMORY_KIB,
                min_time: Self::MIN_TIME_COST,
                min_parallelism: Self::MIN_PARALLELISM,
            });
        }
        Ok(Argon2Params {
            memory_kib,
            time_cost,
            parallelism,
        })
    }

    /// 项目推荐参数：正好等于安全下限（64 MiB / 3 次 / 1 线程）。
    ///
    /// 下限即默认值是刻意的：它是「任何一台还能跑 EnvSync 的机器都扛得住」的取值。
    /// 桌面端可以在设置里调高。
    pub fn recommended() -> Self {
        Argon2Params {
            memory_kib: Self::MIN_MEMORY_KIB,
            time_cost: Self::MIN_TIME_COST,
            parallelism: Self::MIN_PARALLELISM,
        }
    }

    /// 内存开销（KiB）。
    pub const fn memory_kib(self) -> u32 {
        self.memory_kib
    }

    /// 迭代次数。
    pub const fn time_cost(self) -> u32 {
        self.time_cost
    }

    /// 并行度。
    pub const fn parallelism(self) -> u32 {
        self.parallelism
    }

    fn to_argon2(self) -> Result<Argon2<'static>, CryptoError> {
        let params = Params::new(
            self.memory_kib,
            self.time_cost,
            self.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|_| CryptoError::KeyDerivation)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

// ---------------------------------------------------------------------------
// 恢复包
// ---------------------------------------------------------------------------

/// 恢复包的 header，同时是 AEAD 的 AAD 与 HKDF 的 info。
#[derive(Clone, Debug, PartialEq, Eq)]
struct RecoveryHeader {
    version: SealedFormatVersion,
    suite: CryptoSuite,
    params: Argon2Params,
    salt: [u8; RECOVERY_SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

impl RecoveryHeader {
    fn to_bytes(&self) -> Vec<u8> {
        encode(&Value::Array(vec![
            self.version.to_value(),
            self.suite.to_value(),
            Value::Uint(self.params.memory_kib as u64),
            Value::Uint(self.params.time_cost as u64),
            Value::Uint(self.params.parallelism as u64),
            Value::Bytes(self.salt.to_vec()),
            Value::Bytes(self.nonce.to_vec()),
        ]))
    }
}

/// 加密后的恢复包。
///
/// header（版本、套件、KDF 参数、salt、nonce）与密文都是公开材料，可以放在不受信任的
/// 后端上。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryPackage {
    header: RecoveryHeader,
    ciphertext: Vec<u8>,
}

impl RecoveryPackage {
    /// 格式版本。
    pub fn version(&self) -> SealedFormatVersion {
        self.header.version
    }

    /// 算法套件。
    pub fn suite(&self) -> CryptoSuite {
        self.header.suite
    }

    /// Argon2id 参数。
    pub fn params(&self) -> Argon2Params {
        self.header.params
    }

    /// Argon2id salt。
    pub fn salt(&self) -> &[u8; RECOVERY_SALT_LEN] {
        &self.header.salt
    }

    /// AEAD nonce。
    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.header.nonce
    }

    /// 密文（含认证标签）。
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// AEAD 使用的 AAD，即 canonical 编码的 header。
    pub fn aad(&self) -> Vec<u8> {
        self.header.to_bytes()
    }

    /// 用恢复短语加密恢复材料。
    ///
    /// salt 与 nonce 都在内部从 [`rand_core::OsRng`] 生成，调用者不能注入。
    pub fn create(
        phrase: &RecoveryPhrase,
        params: Argon2Params,
        payload: &Plaintext,
    ) -> Result<Self, CryptoError> {
        if payload.len() > MAX_PLAINTEXT_LEN {
            return Err(CryptoError::PlaintextTooLarge {
                limit: MAX_PLAINTEXT_LEN,
            });
        }
        let mut salt = [0u8; RECOVERY_SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        crate::fill_random(&mut salt)?;
        crate::fill_random(&mut nonce)?;
        Self::create_with(phrase, params, payload, salt, nonce)
    }

    /// 仅供测试：用固定 salt 与 nonce 创建，产生可断言的确定性向量。
    #[cfg(feature = "test-vectors")]
    pub fn create_with_salt_nonce_for_tests(
        phrase: &RecoveryPhrase,
        params: Argon2Params,
        payload: &Plaintext,
        salt: [u8; RECOVERY_SALT_LEN],
        nonce: [u8; NONCE_LEN],
    ) -> Result<Self, CryptoError> {
        Self::create_with(phrase, params, payload, salt, nonce)
    }

    fn create_with(
        phrase: &RecoveryPhrase,
        params: Argon2Params,
        payload: &Plaintext,
        salt: [u8; RECOVERY_SALT_LEN],
        nonce: [u8; NONCE_LEN],
    ) -> Result<Self, CryptoError> {
        if payload.len() > MAX_PLAINTEXT_LEN {
            return Err(CryptoError::PlaintextTooLarge {
                limit: MAX_PLAINTEXT_LEN,
            });
        }
        let header = RecoveryHeader {
            version: SealedFormatVersion::V1,
            suite: CryptoSuite::Esv1,
            params,
            salt,
            nonce,
        };
        let aad = header.to_bytes();
        let kek = derive_kek(phrase, &header, &aad)?;

        let cipher =
            ChaCha20Poly1305::new_from_slice(&kek[..]).map_err(|_| CryptoError::KeyDerivation)?;
        let mut buffer = payload.expose().to_vec();
        if cipher
            .encrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut buffer)
            .is_err()
        {
            buffer.zeroize();
            return Err(CryptoError::Authentication);
        }
        Ok(RecoveryPackage {
            header,
            ciphertext: buffer,
        })
    }

    /// 用恢复短语解开恢复包。
    ///
    /// 无论是口令不对、密文被改还是参数被改（只要仍在合法区间内），都返回同一个
    /// [`CryptoError::Authentication`]。
    pub fn open(&self, phrase: &RecoveryPhrase) -> Result<Plaintext, CryptoError> {
        if self.header.version != SealedFormatVersion::V1 {
            return Err(CryptoError::UnsupportedFormatVersion {
                found: self.header.version.get(),
                supported: SealedFormatVersion::V1.get(),
            });
        }
        if self.header.suite != CryptoSuite::Esv1 {
            return Err(CryptoError::UnsupportedSuite);
        }
        if self.ciphertext.len() < TAG_LEN {
            return Err(CryptoError::InvalidLength {
                field: "recovery_ciphertext",
                expected: TAG_LEN,
                found: self.ciphertext.len(),
            });
        }
        if self.ciphertext.len() > MAX_PLAINTEXT_LEN + TAG_LEN {
            return Err(CryptoError::CiphertextTooLarge {
                limit: MAX_PLAINTEXT_LEN + TAG_LEN,
            });
        }

        let aad = self.header.to_bytes();
        let kek = derive_kek(phrase, &self.header, &aad)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(&kek[..]).map_err(|_| CryptoError::KeyDerivation)?;
        let mut buffer = self.ciphertext.clone();
        match cipher.decrypt_in_place(Nonce::from_slice(&self.header.nonce), &aad, &mut buffer) {
            Ok(()) => Ok(Plaintext::from_vec(buffer)),
            Err(_) => {
                buffer.zeroize();
                Err(CryptoError::Authentication)
            }
        }
    }

    /// 仅供测试：用给定 salt/nonce 与任意密文拼装恢复包，用于篡改向量。
    #[cfg(feature = "test-vectors")]
    pub fn from_parts_for_tests(
        params: Argon2Params,
        salt: [u8; RECOVERY_SALT_LEN],
        nonce: [u8; NONCE_LEN],
        ciphertext: Vec<u8>,
    ) -> Self {
        RecoveryPackage {
            header: RecoveryHeader {
                version: SealedFormatVersion::V1,
                suite: CryptoSuite::Esv1,
                params,
                salt,
                nonce,
            },
            ciphertext,
        }
    }
}

impl CborCodec for RecoveryPackage {
    fn to_value(&self) -> Value {
        let header = &self.header;
        Value::Array(vec![
            header.version.to_value(),
            header.suite.to_value(),
            Value::Uint(header.params.memory_kib as u64),
            Value::Uint(header.params.time_cost as u64),
            Value::Uint(header.params.parallelism as u64),
            Value::Bytes(header.salt.to_vec()),
            Value::Bytes(header.nonce.to_vec()),
            Value::Bytes(self.ciphertext.clone()),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        if items.len() != 8 {
            return Err(CborError::ArityMismatch);
        }
        let version = SealedFormatVersion::from_value(&items[0])?;
        let suite = CryptoSuite::from_value(&items[1])?;
        let memory_kib = u32::from_value(&items[2])?;
        let time_cost = u32::from_value(&items[3])?;
        let parallelism = u32::from_value(&items[4])?;
        // 参数校验发生在**解码期**：畸形包在任何 Argon2 分配之前就被拒绝。
        let params = Argon2Params::new(memory_kib, time_cost, parallelism)
            .map_err(|err| CborError::InvalidValue(err.to_string()))?;
        let salt = <[u8; RECOVERY_SALT_LEN]>::from_value(&items[5])?;
        let nonce = <[u8; NONCE_LEN]>::from_value(&items[6])?;
        let ciphertext = items[7].as_bytes()?.to_vec();
        if ciphertext.len() < TAG_LEN || ciphertext.len() > MAX_PLAINTEXT_LEN + TAG_LEN {
            return Err(CborError::InvalidValue("密文长度超出允许范围".to_owned()));
        }
        Ok(RecoveryPackage {
            header: RecoveryHeader {
                version,
                suite,
                params,
                salt,
                nonce,
            },
            ciphertext,
        })
    }
}

/// Argon2id → HKDF-SHA256 的 KEK 派生。
fn derive_kek(
    phrase: &RecoveryPhrase,
    header: &RecoveryHeader,
    header_bytes: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let argon2 = header.params.to_argon2()?;
    let mut kek_raw = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(phrase.password_bytes(), &header.salt, &mut kek_raw[..])
        .map_err(|_| CryptoError::KeyDerivation)?;

    let hkdf = Hkdf::<Sha256>::new(Some(RECOVERY_KEK_DOMAIN), &kek_raw[..]);
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(header_bytes, &mut kek[..])
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(kek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phrase_encoding_round_trips() {
        let phrase = RecoveryPhrase::from_entropy_for_tests([0xA5; RECOVERY_ENTROPY_LEN]);
        let text = phrase.render_for_tests();
        assert_eq!(text.chars().filter(|c| *c != '-').count(), 32);
        let parsed = RecoveryPhrase::parse(&text).unwrap();
        assert_eq!(parsed.password_bytes(), phrase.password_bytes());
    }

    #[test]
    fn phrase_accepts_lowercase_and_crockford_aliases() {
        let phrase = RecoveryPhrase::from_entropy_for_tests([0x11; RECOVERY_ENTROPY_LEN]);
        let text = phrase.render_for_tests();
        let lower = text.to_lowercase();
        assert_eq!(
            RecoveryPhrase::parse(&lower).unwrap().password_bytes(),
            phrase.password_bytes()
        );
        let aliased = text.replace('0', "O").replace('1', "I");
        assert_eq!(
            RecoveryPhrase::parse(&aliased).unwrap().password_bytes(),
            phrase.password_bytes()
        );
    }

    #[test]
    fn phrase_display_only_once() {
        let mut phrase = RecoveryPhrase::generate().unwrap();
        assert!(!phrase.is_revealed());
        assert!(phrase.display_once().is_ok());
        assert!(phrase.is_revealed());
        assert_eq!(
            phrase.display_once().unwrap_err(),
            CryptoError::RecoveryPhraseAlreadyRevealed
        );
    }

    #[test]
    fn parameter_floor_and_ceiling_are_enforced() {
        assert!(Argon2Params::new(64 * 1024, 3, 1).is_ok());
        assert!(matches!(
            Argon2Params::new(64 * 1024 - 1, 3, 1),
            Err(CryptoError::KdfParametersTooWeak { .. })
        ));
        assert!(matches!(
            Argon2Params::new(64 * 1024, 2, 1),
            Err(CryptoError::KdfParametersTooWeak { .. })
        ));
        assert!(matches!(
            Argon2Params::new(u32::MAX, 3, 1),
            Err(CryptoError::KdfParametersTooLarge { .. })
        ));
        assert!(matches!(
            Argon2Params::new(64 * 1024, u32::MAX, 1),
            Err(CryptoError::KdfParametersTooLarge { .. })
        ));
    }
}
