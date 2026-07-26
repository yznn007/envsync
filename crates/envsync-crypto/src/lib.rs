//! # envsync-crypto
//!
//! EnvSync 的**密码学层**：固定一套算法、固定一套线格式，并把「秘密永远不进日志」
//! 这条规则写进类型系统。本 crate 不做任何 I/O，也不自研密码学原语——所有原语都来自
//! RustCrypto / dalek 生态（Ed25519、X25519、HKDF-SHA256、ChaCha20-Poly1305、
//! Argon2id）。
//!
//! ## 模块地图
//!
//! | 模块 | 职责 |
//! |---|---|
//! | [`suite`] | 唯一 M2 算法套件、格式版本、密钥纪元与敏感类型（[`suite::DataKey`]、[`suite::Plaintext`]） |
//! | [`device`] | 设备身份：X25519 + Ed25519 双密钥、[`envsync_domain::id::DeviceId`] 派生、域分隔签名 |
//! | [`sealed`] | 密封秘密对象：AEAD + canonical header 作为 AAD |
//! | [`envelope`] | RFC 9180 base 模式设备信封：把工作区数据密钥分发给单个设备 |
//! | [`recovery`] | Argon2id 恢复包与带校验的恢复短语 |
//!
//! ## 三条不可动摇的规则
//!
//! 1. **敏感类型不可打印、不可序列化、Drop 时清零。** [`suite::DataKey`]、
//!    [`suite::Plaintext`]、[`device::DeviceKeypair`]、[`recovery::RecoveryPhrase`]
//!    都不实现 `Debug` / `Display` / [`envsync_domain::cbor::CborCodec`]；公开材料
//!    （公钥、签名、密文）才实现。
//! 2. **nonce 由生产 API 内部生成，绝不接受调用者传入。** 固定 key/nonce 的确定性
//!    构造只在 `test-vectors` feature 下开放。
//! 3. **错误只描述结构，不携带密钥材料或明文。** 见 [`CryptoError`] 与
//!    `tests/vectors.rs` 中的 canary 测试。
//!
//! ## 密钥层级
//!
//! ```text
//! 恢复短语（128-bit 熵）
//!   └─ Argon2id ──▶ 恢复 KEK ──▶ RecoveryPackage 密文（含工作区恢复材料）
//!
//! 工作区数据密钥 DataKey（32 字节随机）
//!   ├─ ChaCha20-Poly1305 ──▶ SealedSecret（每条秘密一个随机 nonce）
//!   └─ 每设备 HPKE base 模式 ──▶ KeyEnvelope（收件设备用 X25519 私钥打开）
//!
//! 设备 Ed25519 私钥 ──▶ 域分隔签名（覆盖 domain / 版本 / workspace / payload 摘要）
//! ```
//!
//! 完整的信封密钥派生链（每一步的 salt、info 与长度）见 [`envelope`] 模块文档。
//!
//! ## 示例
//!
//! ```
//! use envsync_crypto::device::DeviceKeypair;
//! use envsync_crypto::envelope::{open_envelope, seal_envelope};
//! use envsync_crypto::sealed::{open, seal, SecretId};
//! use envsync_crypto::suite::{DataKey, KeyEpoch, Plaintext};
//! use envsync_domain::id::WorkspaceId;
//!
//! let workspace = WorkspaceId::generate();
//! let epoch = KeyEpoch::new(1);
//! let data_key = DataKey::generate()?;
//! let secret = SecretId::parse("ci/npm-token")?;
//!
//! // 1) 用工作区数据密钥密封一条秘密。
//! let sealed = seal(
//!     &data_key,
//!     workspace,
//!     &secret,
//!     epoch,
//!     &Plaintext::from_slice(b"only-a-test-value"),
//! )?;
//!
//! // 2) 把数据密钥用 HPKE 信封分发给某台设备。
//! let device = DeviceKeypair::generate()?;
//! let envelope = seal_envelope(&device.public(), workspace, epoch, &data_key)?;
//!
//! // 3) 设备打开信封后即可解密秘密。
//! let recovered = open_envelope(&device, &envelope)?;
//! let plaintext = open(&recovered, &sealed)?;
//! assert_eq!(plaintext.expose(), b"only-a-test-value");
//! # Ok::<(), envsync_crypto::CryptoError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod device;
pub mod envelope;
pub mod recovery;
pub mod sealed;
pub mod suite;

use envsync_domain::cbor::CborError;

/// 密码学层的统一错误类型。
///
/// **安全约束：** 所有变体只携带「类型、版本号、长度、静态字段名」这类结构信息。
/// 任何变体都不得携带明文、密钥材料、口令或恢复短语——`tests/vectors.rs` 里的 canary
/// 测试会遍历 `Debug`、`Display` 与 [`std::error::Error::source`] 链做断言。
///
/// 另一条刻意的设计：一切「解不开」的情况——密钥不对、口令不对、密文被改、AAD 被改、
/// 参数被改——都归一到 [`CryptoError::Authentication`]，不给攻击者区分失败原因的
/// oracle。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// 算法套件名未知或不被本实现支持。
    #[error("不支持的算法套件")]
    UnsupportedSuite,

    /// 对象格式版本未知；必须拒绝而不是静默降级。
    #[error("未知的对象格式版本 {found}，本实现支持 {supported}")]
    UnsupportedFormatVersion {
        /// 输入中出现的版本号。
        found: u32,
        /// 本实现支持的版本号。
        supported: u32,
    },

    /// 统一的认证失败：密钥、口令、密文、tag、nonce 或 AAD 中任意一项不匹配。
    #[error("认证失败")]
    Authentication,

    /// 签名验证失败（签名本身非法、被篡改，或由非预期设备产生）。
    #[error("签名验证失败")]
    SignatureInvalid,

    /// 信封的收件设备与本设备不符。
    #[error("信封的收件设备不是本设备")]
    RecipientMismatch,

    /// 公钥不是曲线上的合法点，或落在小子群里。
    #[error("公钥非法")]
    InvalidPublicKey,

    /// X25519 交换得到全零共享秘密（对端使用了小阶点）。
    #[error("密钥交换结果非贡献性")]
    NonContributoryKeyExchange,

    /// 定长字段长度不符。
    #[error("字段 `{field}` 长度不符：期望 {expected} 字节，实际 {found} 字节")]
    InvalidLength {
        /// 字段名（静态字符串，绝不来自输入）。
        field: &'static str,
        /// 期望长度。
        expected: usize,
        /// 实际长度。
        found: usize,
    },

    /// 明文超过 [`suite::MAX_PLAINTEXT_LEN`]。
    #[error("明文超过上限 {limit} 字节")]
    PlaintextTooLarge {
        /// 允许的上限。
        limit: usize,
    },

    /// 密文超过「明文上限 + tag」，在做任何密码学运算前就拒绝。
    #[error("密文超过上限 {limit} 字节")]
    CiphertextTooLarge {
        /// 允许的上限。
        limit: usize,
    },

    /// 签名域标签非法（空、超长或含非可打印 ASCII）。
    #[error("签名域标签非法")]
    DomainLabelInvalid,

    /// 逻辑秘密标识不满足命名约束。
    #[error("SecretId 非法：{reason}")]
    SecretIdInvalid {
        /// 静态原因说明，绝不回显输入内容。
        reason: &'static str,
    },

    /// Argon2id 参数低于项目安全下限，拒绝创建。
    #[error(
        "Argon2id 参数低于安全下限（memory >= {min_memory_kib} KiB, time >= {min_time}, parallelism >= {min_parallelism}）"
    )]
    KdfParametersTooWeak {
        /// 内存下限（KiB）。
        min_memory_kib: u32,
        /// 迭代次数下限。
        min_time: u32,
        /// 并行度下限。
        min_parallelism: u32,
    },

    /// Argon2id 参数超过本机资源上限；拒绝而不是尝试分配。
    #[error(
        "Argon2id 参数超过资源上限（memory <= {max_memory_kib} KiB, time <= {max_time}, parallelism <= {max_parallelism}）"
    )]
    KdfParametersTooLarge {
        /// 内存上限（KiB）。
        max_memory_kib: u32,
        /// 迭代次数上限。
        max_time: u32,
        /// 并行度上限。
        max_parallelism: u32,
    },

    /// 密钥派生函数内部失败（参数组合被底层实现拒绝）。
    #[error("密钥派生失败")]
    KeyDerivation,

    /// 恢复短语的字符集、长度或分组不合法。
    #[error("恢复短语格式非法")]
    RecoveryPhraseMalformed,

    /// 恢复短语校验位不匹配（存在录入错误）。
    #[error("恢复短语校验位不匹配")]
    RecoveryPhraseChecksum,

    /// 恢复短语已经展示过一次，不允许再次展示。
    #[error("恢复短语只能展示一次")]
    RecoveryPhraseAlreadyRevealed,

    /// canonical CBOR 编解码失败。
    #[error("编码错误：{0}")]
    Encoding(#[from] CborError),

    /// 操作系统随机数源不可用。
    #[error("系统随机数源不可用")]
    Rng,
}

/// 从 [`rand_core::OsRng`] 填充随机字节，失败时返回 [`CryptoError::Rng`]。
///
/// 全 crate 只有这一个随机数入口，便于审计「所有随机数都来自 OsRng」。
pub(crate) fn fill_random(buffer: &mut [u8]) -> Result<(), CryptoError> {
    use rand_core::RngCore;
    rand_core::OsRng
        .try_fill_bytes(buffer)
        .map_err(|_| CryptoError::Rng)
}
