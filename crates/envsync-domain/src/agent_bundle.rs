//! Agent Bundle：manifest、发布者签名与隔离状态机的**纯领域模型**。
//!
//! Agent Bundle 是设计文档 §7 意义上的**主动内容**：它携带 Agent 定义、Skill、提示
//! 规则、MCP 配置和工具权限模板，一旦启用就会立刻影响 AI 工具的行为。因此它与普通
//! 配置文件走的是两条完全不同的路径——普通文件默认允许同步，Bundle 默认隔离。
//!
//! 本模块只定义**数据与约束**，不做任何 I/O：
//!
//! * [`BundleId`]：反向域名风格的稳定标识；
//! * [`BundleManifest`]：Bundle 自述的全部内容与声明；
//! * [`BundleSignature`]：发布者对 manifest 与全部文件摘要的签名；
//! * [`BundleState`]：`downloaded → inspected → approved → enabled` 隔离状态机。
//!
//! 验签本身在 `envsync-core` 里用 `envsync-crypto` 完成：领域层不依赖密码学实现，
//! 只负责**定义被签的字节到底是什么**（见 [`BundleManifest::signing_payload`]）。
//!
//! # manifest 是不可信输入
//!
//! manifest 由 Bundle 的作者书写，可能来自任何人。它的每一个字段都会被用来决定
//! 「往磁盘的哪个位置写什么」，因此 [`BundleManifest::validate`] 的拒绝清单本身就是
//! 一份威胁模型：
//!
//! | 拒绝项 | 攻击 |
//! |---|---|
//! | 路径穿越（`..`、绝对路径、盘符、UNC） | 写到 quarantine 根之外 |
//! | 反斜杠与 `:` | Windows 上的分隔符/盘符/数据流歧义 |
//! | 大小写重复路径 | 在大小写不敏感的文件系统上，后写的条目静默覆盖先写的 |
//! | 总大小超过 [`MAX_BUNDLE_TOTAL_BYTES`] | 解包时的磁盘耗尽 |
//! | 非 semver 版本 | 版本比较退化成字符串比较，降级检测失效 |
//! | 非 `secret://` 形式的 `secret_refs` | 明文 Token 被写进 Bundle 并随快照扩散 |
//!
//! 载荷（真正解出来的文件）另有一道 [`BundleManifest::check_payload`]：symlink 条目、
//! 未在 `files` 中声明的文件、摘要不符与大小不符都在那里被拒绝。两道校验分开是因为
//! 它们的输入不同——前者只看 manifest，后者需要已经落地的条目清单。
//!
//! # 示例
//!
//! ```
//! use std::collections::{BTreeMap, BTreeSet};
//! use envsync_domain::agent_bundle::{
//!     BundleId, BundleManifest, BUNDLE_MANIFEST_FORMAT_VERSION,
//! };
//! use envsync_domain::id::Digest32;
//!
//! let manifest = BundleManifest {
//!     format_version: BUNDLE_MANIFEST_FORMAT_VERSION,
//!     id: BundleId::parse("com.example.my-agent")?,
//!     version: "1.2.3".to_owned(),
//!     publisher_key: [7u8; 32],
//!     files: BTreeMap::from([(
//!         "agents/main.md".to_owned(),
//!         Digest32::domain_hash("test", b"hello"),
//!     )]),
//!     entrypoints: BTreeMap::from([("agent".to_owned(), "agents/main.md".to_owned())]),
//!     declared_capabilities: BTreeSet::from(["fs.read".to_owned()]),
//!     secret_refs: BTreeSet::from(["secret://github/token".to_owned()]),
//!     target_tools: BTreeSet::from(["claude".to_owned()]),
//!     min_envsync_version: "0.1.0".to_owned(),
//!     total_bytes: 5,
//! };
//! manifest.validate()?;
//!
//! // 摘要覆盖 manifest 的每一个字段，包括全部文件摘要。
//! assert_ne!(manifest.manifest_digest(), manifest.files_digest());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::cbor::{CborCodec, CborError, Value};
use crate::id::Digest32;

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

/// manifest 的当前格式版本；未知版本一律拒绝，绝不静默降级。
pub const BUNDLE_MANIFEST_FORMAT_VERSION: u32 = 1;

/// 签名对象的当前格式版本。
pub const BUNDLE_SIGNATURE_FORMAT_VERSION: u32 = 1;

/// 一个 Bundle 解包后允许占用的最大总字节数（10 MiB）。
///
/// 上限刻意定得很小：Bundle 装的是提示词、Skill 文本与配置，不是二进制发行物。
/// 需要更大体积的东西应当走包管理器，而不是伪装成 Agent 配置绕过包策略。
pub const MAX_BUNDLE_TOTAL_BYTES: u64 = 10 * 1024 * 1024;

/// manifest 中允许声明的最大文件条数。
pub const MAX_BUNDLE_FILES: usize = 4_096;

/// 单条相对路径允许的最大字节长度。
pub const MAX_BUNDLE_PATH_LEN: usize = 512;

/// 单条路径允许的最大分段数。
pub const MAX_BUNDLE_PATH_SEGMENTS: usize = 32;

/// [`BundleId`] 允许的最大字节长度。
pub const MAX_BUNDLE_ID_LEN: usize = 128;

/// 版本文本允许的最大字节长度。
pub const MAX_BUNDLE_VERSION_LEN: usize = 64;

/// 单条能力名允许的最大字节长度。
pub const MAX_CAPABILITY_LEN: usize = 64;

/// 声明能力、SecretRef、entrypoint、目标工具各自的条数上限。
pub const MAX_BUNDLE_SET_ENTRIES: usize = 256;

/// SecretRef 唯一被接受的前缀。
///
/// 只允许 `secret://<逻辑标识>`：设计文档 §7 要求 Bundle「不得内嵌明文 Token，只能
/// 引用 Vault 中的逻辑 Secret ID」。固定前缀让「这是引用还是值」在**语法层面**就能
/// 判定，而不必依赖任何启发式。
pub const SECRET_REF_SCHEME: &str = "secret://";

/// manifest 摘要的域标签。
pub const BUNDLE_MANIFEST_DIGEST_DOMAIN: &str = "envsync:bundle-manifest:v1";

/// 文件摘要集合的域标签。
pub const BUNDLE_FILES_DIGEST_DOMAIN: &str = "envsync:bundle-files:v1";

/// 单个 Bundle 文件内容摘要的域标签。
pub const BUNDLE_FILE_DIGEST_DOMAIN: &str = "envsync:bundle-file:v1";

/// 待签结构的域前缀。
pub const BUNDLE_SIGNING_PAYLOAD_DOMAIN: &str = "envsync:bundle-signing-payload:v1";

/// 已知的目标工具标识。
///
/// 这是一个**封闭集合**：manifest 声称支持一个本实现不认识的工具时，我们无法判断
/// 渲染结果会落到哪里，因此拒绝而不是忽略。
pub const KNOWN_TARGET_TOOLS: &[&str] = &["claude", "codex", "opencode"];

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

/// manifest 与载荷校验错误。
///
/// 所有变体的 `Display` 输出只描述**结构问题**：字段名、上限与被截断的取值片段。
/// 它们不含秘密值，可以直接写进日志与 CLI 诊断。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BundleManifestError {
    /// 格式版本不是本实现支持的版本。
    #[error("不支持的 Bundle manifest 格式版本 {found}，本实现只接受 {supported}")]
    UnsupportedFormatVersion {
        /// 输入中的版本号。
        found: u32,
        /// 本实现支持的版本号。
        supported: u32,
    },

    /// [`BundleId`] 非法。
    #[error("Bundle 标识 `{id}` 非法：{reason}")]
    InvalidBundleId {
        /// 被截断的取值。
        id: String,
        /// 具体原因。
        reason: &'static str,
    },

    /// 版本文本不是合法 semver。
    #[error("字段 `{field}` 的取值 `{value}` 不是合法 semver")]
    InvalidSemver {
        /// 字段名。
        field: &'static str,
        /// 被截断的取值。
        value: String,
    },

    /// 发布者公钥为全零。
    #[error("发布者公钥不能是全零")]
    EmptyPublisherKey,

    /// 相对路径非法（穿越、绝对路径、盘符、UNC、控制字符等）。
    #[error("文件路径 `{path}` 非法：{reason}")]
    InvalidPath {
        /// 被截断的路径。
        path: String,
        /// 具体原因。
        reason: &'static str,
    },

    /// 两条路径在大小写不敏感的文件系统上会互相覆盖。
    #[error("文件路径 `{first}` 与 `{second}` 在大小写不敏感的文件系统上重复")]
    DuplicatePath {
        /// 先出现的路径。
        first: String,
        /// 后出现的路径。
        second: String,
    },

    /// 载荷里出现了 symlink（或其他非普通文件）条目。
    #[error("条目 `{path}` 的类型是 {kind}，Bundle 只允许普通文件")]
    NonRegularEntry {
        /// 被截断的路径。
        path: String,
        /// 实际类型。
        kind: &'static str,
    },

    /// 载荷里出现了 manifest 未声明的文件。
    #[error("条目 `{path}` 未在 manifest 的 `files` 中声明")]
    UndeclaredFile {
        /// 被截断的路径。
        path: String,
    },

    /// manifest 声明了载荷里不存在的文件。
    #[error("manifest 声明的文件 `{path}` 在载荷中缺失")]
    MissingFile {
        /// 被截断的路径。
        path: String,
    },

    /// 载荷中某个文件的摘要与 manifest 不符。
    #[error("文件 `{path}` 的内容摘要与 manifest 不符")]
    DigestMismatch {
        /// 被截断的路径。
        path: String,
    },

    /// 条目数、集合条数或路径分段数超限。
    #[error("`{field}` 的条数 {actual} 超过上限 {limit}")]
    TooManyEntries {
        /// 字段名。
        field: &'static str,
        /// 实际条数。
        actual: usize,
        /// 允许的上限。
        limit: usize,
    },

    /// 必填集合为空。
    #[error("`{field}` 不能为空")]
    EmptyField {
        /// 字段名。
        field: &'static str,
    },

    /// 声明的总字节数超过 [`MAX_BUNDLE_TOTAL_BYTES`]。
    #[error("Bundle 总大小 {actual} 字节超过上限 {limit} 字节")]
    TooLarge {
        /// 实际字节数。
        actual: u64,
        /// 允许的上限。
        limit: u64,
    },

    /// 载荷实际总大小与 manifest 声明不符。
    #[error("载荷实际总大小 {actual} 字节与 manifest 声明的 {declared} 字节不符")]
    SizeMismatch {
        /// 实际字节数。
        actual: u64,
        /// manifest 声明的字节数。
        declared: u64,
    },

    /// entrypoint 指向了未声明的文件。
    #[error("entrypoint `{name}` 指向未声明的文件 `{target}`")]
    DanglingEntrypoint {
        /// 被截断的 entrypoint 名。
        name: String,
        /// 被截断的目标路径。
        target: String,
    },

    /// 能力名、entrypoint 名等标识的字符集非法。
    #[error("`{field}` 中的取值 `{value}` 非法：{reason}")]
    InvalidIdentifier {
        /// 字段名。
        field: &'static str,
        /// 被截断的取值。
        value: String,
        /// 具体原因。
        reason: &'static str,
    },

    /// `secret_refs` 里出现了非 `secret://` 形式的取值。
    #[error("`secret_refs` 中的取值 `{value}` 不是 `secret://<id>` 形式的引用")]
    SecretRefNotAReference {
        /// 被截断的取值。
        value: String,
    },

    /// `secret_refs` 里出现了看起来像真实凭据的取值。
    #[error("`secret_refs` 中的取值看起来是一枚真实凭据而不是逻辑标识；Bundle 绝不能内嵌明文")]
    SecretRefLooksLikeCredential,

    /// 目标工具不在 [`KNOWN_TARGET_TOOLS`] 内。
    #[error("目标工具 `{tool}` 未知，本实现只认识 {known:?}")]
    UnknownTargetTool {
        /// 被截断的取值。
        tool: String,
        /// 已知工具列表。
        known: &'static [&'static str],
    },

    /// 签名对象与 manifest 不匹配。
    #[error("签名对象与 manifest 不匹配：{detail}")]
    SignatureMismatch {
        /// 具体不匹配的部分。
        detail: &'static str,
    },
}

impl BundleManifestError {
    /// 稳定的机器可读错误码，供 `--json` 输出与测试断言使用。
    ///
    /// 错误码是 API 的一部分：新增变体可以增加新码，已有码不改名。
    pub fn code(&self) -> &'static str {
        match self {
            BundleManifestError::UnsupportedFormatVersion { .. } => "bundle.unsupported_version",
            BundleManifestError::InvalidBundleId { .. } => "bundle.invalid_id",
            BundleManifestError::InvalidSemver { .. } => "bundle.invalid_semver",
            BundleManifestError::EmptyPublisherKey => "bundle.empty_publisher_key",
            BundleManifestError::InvalidPath { .. } => "bundle.invalid_path",
            BundleManifestError::DuplicatePath { .. } => "bundle.duplicate_path",
            BundleManifestError::NonRegularEntry { .. } => "bundle.non_regular_entry",
            BundleManifestError::UndeclaredFile { .. } => "bundle.undeclared_file",
            BundleManifestError::MissingFile { .. } => "bundle.missing_file",
            BundleManifestError::DigestMismatch { .. } => "bundle.digest_mismatch",
            BundleManifestError::TooManyEntries { .. } => "bundle.too_many_entries",
            BundleManifestError::EmptyField { .. } => "bundle.empty_field",
            BundleManifestError::TooLarge { .. } => "bundle.too_large",
            BundleManifestError::SizeMismatch { .. } => "bundle.size_mismatch",
            BundleManifestError::DanglingEntrypoint { .. } => "bundle.dangling_entrypoint",
            BundleManifestError::InvalidIdentifier { .. } => "bundle.invalid_identifier",
            BundleManifestError::SecretRefNotAReference { .. } => "bundle.secret_ref_not_reference",
            BundleManifestError::SecretRefLooksLikeCredential => "bundle.secret_ref_credential",
            BundleManifestError::UnknownTargetTool { .. } => "bundle.unknown_target_tool",
            BundleManifestError::SignatureMismatch { .. } => "bundle.signature_mismatch",
        }
    }
}

/// 把不可信输入截断到适合放进错误信息的长度，并抹掉控制字符。
///
/// 错误信息会进日志和终端；未经处理的输入可以用控制字符伪造日志行。
fn truncate_for_error(text: &str) -> String {
    const LIMIT: usize = 64;
    let cleaned: String = text
        .chars()
        .map(|ch| if ch.is_control() { '\u{fffd}' } else { ch })
        .collect();
    if cleaned.chars().count() <= LIMIT {
        return cleaned;
    }
    let head: String = cleaned.chars().take(LIMIT).collect();
    format!("{head}…")
}

// ---------------------------------------------------------------------------
// BundleId
// ---------------------------------------------------------------------------

/// Bundle 的稳定标识，反向域名风格，例如 `com.example.my-agent`。
///
/// 字符集刻意收得极窄（ASCII 小写字母、数字、`-`，以 `.` 分段，至少两段）：
///
/// * 标识会被拼进文件路径（quarantine 目录名）、日志行与 SQL 参数，允许大写会在
///   大小写不敏感的文件系统上产生两个「不同」的 Bundle 抢同一个目录；
/// * 至少两段保证它看起来就是一个域名，避免与工具名、能力名混淆。
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BundleId(String);

impl BundleId {
    /// 解析并校验标识。
    pub fn parse(text: &str) -> Result<Self, BundleManifestError> {
        if text.is_empty() {
            return Err(BundleManifestError::InvalidBundleId {
                id: String::new(),
                reason: "不能为空",
            });
        }
        if text.len() > MAX_BUNDLE_ID_LEN {
            return Err(BundleManifestError::InvalidBundleId {
                id: truncate_for_error(text),
                reason: "超过长度上限",
            });
        }
        let labels: Vec<&str> = text.split('.').collect();
        if labels.len() < 2 {
            return Err(BundleManifestError::InvalidBundleId {
                id: truncate_for_error(text),
                reason: "必须是反向域名风格，至少两段",
            });
        }
        for label in labels {
            if label.is_empty() {
                return Err(BundleManifestError::InvalidBundleId {
                    id: truncate_for_error(text),
                    reason: "不能包含空段",
                });
            }
            if !label.starts_with(|ch: char| ch.is_ascii_lowercase()) {
                return Err(BundleManifestError::InvalidBundleId {
                    id: truncate_for_error(text),
                    reason: "每段必须以 ASCII 小写字母开头",
                });
            }
            if label.ends_with('-') {
                return Err(BundleManifestError::InvalidBundleId {
                    id: truncate_for_error(text),
                    reason: "段不能以 `-` 结尾",
                });
            }
            if !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err(BundleManifestError::InvalidBundleId {
                    id: truncate_for_error(text),
                    reason: "只允许 ASCII 小写字母、数字与 `-`",
                });
            }
        }
        Ok(BundleId(text.to_owned()))
    }

    /// 文本表示。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 可安全用作单级目录名的表示。
    ///
    /// 由于字符集已经排除了 `/`、`\`、`:` 与一切控制字符，这里直接返回标识本身：
    /// 它在任何平台上都是一个合法的单级目录名。
    pub fn to_directory_name(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BundleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for BundleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BundleId({})", self.0)
    }
}

impl FromStr for BundleId {
    type Err = BundleManifestError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        BundleId::parse(text)
    }
}

impl TryFrom<String> for BundleId {
    type Error = BundleManifestError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        BundleId::parse(&value)
    }
}

impl From<BundleId> for String {
    fn from(value: BundleId) -> Self {
        value.0
    }
}

impl CborCodec for BundleId {
    fn to_value(&self) -> Value {
        Value::Text(self.0.clone())
    }
    fn from_value(value: &Value) -> Result<Self, CborError> {
        BundleId::parse(value.as_text()?).map_err(|err| CborError::InvalidValue(err.to_string()))
    }
}

// ---------------------------------------------------------------------------
// 校验辅助
// ---------------------------------------------------------------------------

/// 校验一条 semver 文本。
///
/// 刻意**不引入 semver crate**：这里只需要「是不是合法 semver」这一个判断，而多一个
/// 依赖就多一份供应链面。实现严格按 semver 2.0.0：`major.minor.patch`，三段都是无
/// 前导零的十进制数；可选 `-prerelease` 与 `+build`，各由 `.` 分段，段非空且只含
/// `[0-9A-Za-z-]`，其中纯数字段不得有前导零。
pub fn is_semver(text: &str) -> bool {
    if text.is_empty() || text.len() > MAX_BUNDLE_VERSION_LEN {
        return false;
    }
    // 先切 build，再切 prerelease：`+` 之后的内容里允许出现 `-`。
    let (without_build, build) = match text.split_once('+') {
        Some((head, build)) => (head, Some(build)),
        None => (text, None),
    };
    if let Some(build) = build {
        if !is_dot_separated_identifiers(build, false) {
            return false;
        }
    }
    let (core, prerelease) = match without_build.split_once('-') {
        Some((head, pre)) => (head, Some(pre)),
        None => (without_build, None),
    };
    if let Some(pre) = prerelease {
        if !is_dot_separated_identifiers(pre, true) {
            return false;
        }
    }
    let mut parts = core.split('.');
    let (Some(major), Some(minor), Some(patch), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    [major, minor, patch].iter().all(|part| is_numeric_id(part))
}

/// 无前导零的十进制数字段。
fn is_numeric_id(part: &str) -> bool {
    if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    part == "0" || !part.starts_with('0')
}

/// `.` 分段的 semver 标识串；`reject_numeric_leading_zero` 对 prerelease 生效。
fn is_dot_separated_identifiers(text: &str, reject_numeric_leading_zero: bool) -> bool {
    if text.is_empty() {
        return false;
    }
    text.split('.').all(|segment| {
        if segment.is_empty() {
            return false;
        }
        if !segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return false;
        }
        if reject_numeric_leading_zero && segment.bytes().all(|byte| byte.is_ascii_digit()) {
            return is_numeric_id(segment);
        }
        true
    })
}

/// 计算一个 Bundle 文件内容的摘要。
///
/// 域分隔标签把它与 Blob 标识、快照标识彻底隔开：即便两处字节完全相同，摘要也不同，
/// 因此不可能出现「拿一个 Blob 冒充 Bundle 文件」这类跨类型混淆。
pub fn bundle_file_digest(bytes: &[u8]) -> Digest32 {
    Digest32::domain_hash(BUNDLE_FILE_DIGEST_DOMAIN, bytes)
}

/// 一条 Bundle 内相对路径的合法性。
///
/// 这是 Bundle 安全性最薄的一层皮：它决定「解包时会往哪里写」。因此这里不做任何
/// 规范化尝试（规范化本身就是漏洞温床），只做**拒绝**。
pub fn validate_bundle_path(path: &str) -> Result<(), BundleManifestError> {
    let reject = |reason: &'static str| {
        Err(BundleManifestError::InvalidPath {
            path: truncate_for_error(path),
            reason,
        })
    };
    if path.is_empty() {
        return reject("不能为空");
    }
    if path.len() > MAX_BUNDLE_PATH_LEN {
        return reject("超过长度上限");
    }
    if path.chars().any(char::is_control) {
        return reject("不能包含控制字符");
    }
    // 反斜杠一律拒绝：它既是 Windows 的路径分隔符，也是 UNC 前缀 `\\server\share`
    // 的第一个字符。允许它就等于允许两套互不相同的路径语义同时存在。
    if path.contains('\\') {
        return reject("不能包含反斜杠（Windows 分隔符 / UNC 前缀）");
    }
    // 冒号同时覆盖盘符（`C:/x`）与 NTFS 交换数据流（`a.txt:hidden`）。
    if path.contains(':') {
        return reject("不能包含冒号（盘符 / NTFS 数据流）");
    }
    if path.starts_with('/') {
        return reject("必须是相对路径");
    }
    if path.starts_with('~') {
        return reject("不能以 `~` 开头");
    }
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() > MAX_BUNDLE_PATH_SEGMENTS {
        return reject("分段数超过上限");
    }
    for segment in segments {
        if segment.is_empty() {
            return reject("不能包含空段（`//` 或结尾 `/`）");
        }
        if segment == "." || segment == ".." {
            return reject("不能包含 `.` 或 `..` 段");
        }
        if segment.ends_with(' ') || segment.ends_with('.') {
            // Windows 会静默剥掉结尾空格与句点，`a.txt.` 与 `a.txt` 因此指向同一个文件。
            return reject("段不能以空格或 `.` 结尾");
        }
    }
    Ok(())
}

/// 受限标识字符集：ASCII 字母数字与 `.`、`-`、`_`，可用 `/` 或 `:` 分段。
fn validate_identifier(
    field: &'static str,
    value: &str,
    allow_separators: bool,
) -> Result<(), BundleManifestError> {
    let invalid = |reason: &'static str| {
        Err(BundleManifestError::InvalidIdentifier {
            field,
            value: truncate_for_error(value),
            reason,
        })
    };
    if value.is_empty() {
        return invalid("不能为空");
    }
    if value.len() > MAX_CAPABILITY_LEN {
        return invalid("超过长度上限");
    }
    for ch in value.chars() {
        let separator = allow_separators && matches!(ch, '.' | ':' | '/');
        let ordinary = ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.');
        if !(separator || ordinary) {
            return invalid("只允许 ASCII 字母、数字与 `-`、`_`、`.`（能力名另允许 `:`、`/`）");
        }
    }
    Ok(())
}

/// 已知的凭据前缀。
///
/// 这份清单**不是**安全边界（它必然不完整），而是一条早失败的诊断：真正的边界是
/// `secret://` 前缀这条语法规则。清单存在的意义是把「作者手滑把 token 粘进来了」
/// 变成一句人话，而不是一句「格式不对」。
const CREDENTIAL_PREFIXES: &[&str] = &[
    "-----BEGIN",
    "AIza",
    "AKIA",
    "ASIA",
    "dop_v1_",
    "eyJ", // 未加密 JWT 的 base64 头
    "ghp_",
    "gho_",
    "ghr_",
    "ghs_",
    "ghu_",
    "github_pat_",
    "glpat-",
    "npm_",
    "pk_live_",
    "sk-",
    "sk_live_",
    "xoxa-",
    "xoxb-",
    "xoxp-",
    "ya29.",
];

/// 一个取值是否「看起来是一枚真实凭据」。
///
/// 判据有二，命中任意一条即为真：
///
/// 1. 命中 [`CREDENTIAL_PREFIXES`] 中的已知前缀；
/// 2. 长度不小于 24、字符集落在 base64/base64url 内，且同时含大写、小写与数字
///    ——这是随机密钥材料的典型形状，而人写的逻辑标识几乎不会同时满足这三条。
pub fn looks_like_credential(value: &str) -> bool {
    if CREDENTIAL_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix))
    {
        return true;
    }
    if value.len() < 24 {
        return false;
    }
    let base64ish = value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
    });
    if !base64ish {
        return false;
    }
    let has_upper = value.bytes().any(|byte| byte.is_ascii_uppercase());
    let has_lower = value.bytes().any(|byte| byte.is_ascii_lowercase());
    let has_digit = value.bytes().any(|byte| byte.is_ascii_digit());
    has_upper && has_lower && has_digit
}

/// 校验一条 `secret://<id>` 引用。
///
/// `<id>` 的规则与 `envsync_crypto::sealed::SecretId` 一致：`/` 分段，每段只含 ASCII
/// 字母数字与 `-`、`_`、`.`，不含空段与 `.`/`..` 段。领域层不依赖 crypto crate，
/// 因此这里重述规则；两处若出现分歧，Vault 侧的解析会拒绝，不会静默接受。
pub fn validate_secret_reference(value: &str) -> Result<&str, BundleManifestError> {
    let Some(id) = value.strip_prefix(SECRET_REF_SCHEME) else {
        // 没有前缀时先判断它是不是一枚真凭据，给出更准确的诊断。
        if looks_like_credential(value) {
            return Err(BundleManifestError::SecretRefLooksLikeCredential);
        }
        return Err(BundleManifestError::SecretRefNotAReference {
            value: truncate_for_error(value),
        });
    };
    if id.is_empty() || id.len() > 128 {
        return Err(BundleManifestError::SecretRefNotAReference {
            value: truncate_for_error(value),
        });
    }
    for segment in id.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(BundleManifestError::SecretRefNotAReference {
                value: truncate_for_error(value),
            });
        }
        if !segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(BundleManifestError::SecretRefNotAReference {
                value: truncate_for_error(value),
            });
        }
    }
    // 语法过关也不够：`secret://ghp_xxxxxxxx` 同样是把明文塞进了 Bundle。
    if looks_like_credential(id) {
        return Err(BundleManifestError::SecretRefLooksLikeCredential);
    }
    Ok(id)
}

// ---------------------------------------------------------------------------
// 载荷条目
// ---------------------------------------------------------------------------

/// 载荷中一个条目的类型。
///
/// `Symlink` 单独成一个变体而不是被归入「其他」，是因为它是 Bundle 场景下唯一真正
/// 危险的类型：一条指向 `~/.ssh/authorized_keys` 的链接会让「往 quarantine 里写文件」
/// 变成「往用户家目录里写文件」。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleEntryKind {
    /// 普通文件；唯一被接受的类型。
    File,
    /// 符号链接。
    Symlink,
    /// 目录条目。
    Directory,
    /// 设备节点、FIFO、socket 等。
    Other,
}

impl BundleEntryKind {
    /// 稳定短名，用于诊断。
    pub const fn as_str(self) -> &'static str {
        match self {
            BundleEntryKind::File => "file",
            BundleEntryKind::Symlink => "symlink",
            BundleEntryKind::Directory => "directory",
            BundleEntryKind::Other => "other",
        }
    }
}

/// 载荷中的一个条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleFileEntry {
    /// 相对 Bundle 根的路径。
    pub path: String,
    /// 条目类型。
    pub kind: BundleEntryKind,
    /// 内容摘要（仅对 [`BundleEntryKind::File`] 有意义）。
    pub digest: Digest32,
    /// 内容字节数。
    pub bytes: u64,
}

// ---------------------------------------------------------------------------
// manifest
// ---------------------------------------------------------------------------

/// Bundle 的自述清单。
///
/// 它是 Bundle 里**唯一被签名覆盖**的结构，也是策略判定与用户审核的全部输入。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleManifest {
    /// 格式版本，必须等于 [`BUNDLE_MANIFEST_FORMAT_VERSION`]。
    pub format_version: u32,
    /// Bundle 标识。
    pub id: BundleId,
    /// Bundle 版本，semver 文本。
    pub version: String,
    /// 发布者的 Ed25519 公钥。
    pub publisher_key: [u8; 32],
    /// 相对路径 -> 内容摘要。
    pub files: BTreeMap<String, Digest32>,
    /// 入口点名 -> `files` 中的相对路径。
    pub entrypoints: BTreeMap<String, String>,
    /// Bundle 自述需要的能力。
    ///
    /// 「自述」是关键词：它不是本机事实，正因为是自述才必须过策略与用户审核。
    pub declared_capabilities: BTreeSet<String>,
    /// Bundle 引用的秘密，只能是 `secret://<id>` 形式的**逻辑标识**。
    pub secret_refs: BTreeSet<String>,
    /// 目标工具标识，取值必须在 [`KNOWN_TARGET_TOOLS`] 内。
    pub target_tools: BTreeSet<String>,
    /// 能加载本 Bundle 的最低 EnvSync 版本，semver 文本。
    pub min_envsync_version: String,
    /// 全部文件的字节数之和。
    pub total_bytes: u64,
}

impl BundleManifest {
    /// 校验 manifest 自身。
    ///
    /// 只看 manifest，不看载荷：载荷校验见 [`BundleManifest::check_payload`]。
    /// 顺序按「便宜的先做」排列，但每一条都会执行到——不存在「前面的检查顺带覆盖了
    /// 后面」的隐式依赖。
    pub fn validate(&self) -> Result<(), BundleManifestError> {
        if self.format_version != BUNDLE_MANIFEST_FORMAT_VERSION {
            return Err(BundleManifestError::UnsupportedFormatVersion {
                found: self.format_version,
                supported: BUNDLE_MANIFEST_FORMAT_VERSION,
            });
        }
        if !is_semver(&self.version) {
            return Err(BundleManifestError::InvalidSemver {
                field: "version",
                value: truncate_for_error(&self.version),
            });
        }
        if !is_semver(&self.min_envsync_version) {
            return Err(BundleManifestError::InvalidSemver {
                field: "min_envsync_version",
                value: truncate_for_error(&self.min_envsync_version),
            });
        }
        if self.publisher_key == [0u8; 32] {
            return Err(BundleManifestError::EmptyPublisherKey);
        }
        if self.total_bytes > MAX_BUNDLE_TOTAL_BYTES {
            return Err(BundleManifestError::TooLarge {
                actual: self.total_bytes,
                limit: MAX_BUNDLE_TOTAL_BYTES,
            });
        }
        self.validate_files()?;
        self.validate_entrypoints()?;
        self.validate_capabilities()?;
        self.validate_secret_refs()?;
        self.validate_target_tools()?;
        Ok(())
    }

    /// 校验 `files`：条数、路径合法性与大小写重复。
    fn validate_files(&self) -> Result<(), BundleManifestError> {
        if self.files.is_empty() {
            return Err(BundleManifestError::EmptyField { field: "files" });
        }
        if self.files.len() > MAX_BUNDLE_FILES {
            return Err(BundleManifestError::TooManyEntries {
                field: "files",
                actual: self.files.len(),
                limit: MAX_BUNDLE_FILES,
            });
        }
        // `BTreeMap` 的键天然互不相同，但「互不相同」只在 Rust 的字节比较意义上成立。
        // macOS（APFS 默认）与 Windows 的文件系统是大小写不敏感的：`Agent.md` 与
        // `agent.md` 会落到同一个文件，后写的静默覆盖先写的——摘要校验随之失效。
        let mut folded: BTreeMap<String, &str> = BTreeMap::new();
        for path in self.files.keys() {
            validate_bundle_path(path)?;
            let key = path.to_ascii_lowercase();
            if let Some(first) = folded.insert(key, path.as_str()) {
                return Err(BundleManifestError::DuplicatePath {
                    first: truncate_for_error(first),
                    second: truncate_for_error(path),
                });
            }
        }
        Ok(())
    }

    /// 校验 `entrypoints`：名称字符集与「目标必须已声明」。
    fn validate_entrypoints(&self) -> Result<(), BundleManifestError> {
        if self.entrypoints.len() > MAX_BUNDLE_SET_ENTRIES {
            return Err(BundleManifestError::TooManyEntries {
                field: "entrypoints",
                actual: self.entrypoints.len(),
                limit: MAX_BUNDLE_SET_ENTRIES,
            });
        }
        for (name, target) in &self.entrypoints {
            validate_identifier("entrypoints", name, false)?;
            if !self.files.contains_key(target) {
                return Err(BundleManifestError::DanglingEntrypoint {
                    name: truncate_for_error(name),
                    target: truncate_for_error(target),
                });
            }
        }
        Ok(())
    }

    /// 校验 `declared_capabilities`。
    fn validate_capabilities(&self) -> Result<(), BundleManifestError> {
        if self.declared_capabilities.len() > MAX_BUNDLE_SET_ENTRIES {
            return Err(BundleManifestError::TooManyEntries {
                field: "declared_capabilities",
                actual: self.declared_capabilities.len(),
                limit: MAX_BUNDLE_SET_ENTRIES,
            });
        }
        for capability in &self.declared_capabilities {
            validate_identifier("declared_capabilities", capability, true)?;
        }
        Ok(())
    }

    /// 校验 `secret_refs`。
    fn validate_secret_refs(&self) -> Result<(), BundleManifestError> {
        if self.secret_refs.len() > MAX_BUNDLE_SET_ENTRIES {
            return Err(BundleManifestError::TooManyEntries {
                field: "secret_refs",
                actual: self.secret_refs.len(),
                limit: MAX_BUNDLE_SET_ENTRIES,
            });
        }
        for value in &self.secret_refs {
            validate_secret_reference(value)?;
        }
        Ok(())
    }

    /// 校验 `target_tools`。
    fn validate_target_tools(&self) -> Result<(), BundleManifestError> {
        if self.target_tools.is_empty() {
            return Err(BundleManifestError::EmptyField {
                field: "target_tools",
            });
        }
        for tool in &self.target_tools {
            if !KNOWN_TARGET_TOOLS.contains(&tool.as_str()) {
                return Err(BundleManifestError::UnknownTargetTool {
                    tool: truncate_for_error(tool),
                    known: KNOWN_TARGET_TOOLS,
                });
            }
        }
        Ok(())
    }

    /// 校验实际载荷与 manifest 是否一致。
    ///
    /// 拒绝：非普通文件（symlink / 目录 / 设备节点）、未声明的文件、声明但缺失的
    /// 文件、摘要不符、实际总大小与 `total_bytes` 不符或超过上限。
    ///
    /// **必须在 [`BundleManifest::validate`] 通过之后调用**：本方法假设 `files` 中
    /// 的路径已经过合法性检查。
    pub fn check_payload(&self, entries: &[BundleFileEntry]) -> Result<(), BundleManifestError> {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut total: u64 = 0;
        for entry in entries {
            if entry.kind != BundleEntryKind::File {
                return Err(BundleManifestError::NonRegularEntry {
                    path: truncate_for_error(&entry.path),
                    kind: entry.kind.as_str(),
                });
            }
            let Some(declared) = self.files.get(&entry.path) else {
                return Err(BundleManifestError::UndeclaredFile {
                    path: truncate_for_error(&entry.path),
                });
            };
            if *declared != entry.digest {
                return Err(BundleManifestError::DigestMismatch {
                    path: truncate_for_error(&entry.path),
                });
            }
            if !seen.insert(entry.path.as_str()) {
                return Err(BundleManifestError::DuplicatePath {
                    first: truncate_for_error(&entry.path),
                    second: truncate_for_error(&entry.path),
                });
            }
            total = total.saturating_add(entry.bytes);
        }
        for path in self.files.keys() {
            if !seen.contains(path.as_str()) {
                return Err(BundleManifestError::MissingFile {
                    path: truncate_for_error(path),
                });
            }
        }
        if total > MAX_BUNDLE_TOTAL_BYTES {
            return Err(BundleManifestError::TooLarge {
                actual: total,
                limit: MAX_BUNDLE_TOTAL_BYTES,
            });
        }
        if total != self.total_bytes {
            return Err(BundleManifestError::SizeMismatch {
                actual: total,
                declared: self.total_bytes,
            });
        }
        Ok(())
    }

    /// 全部文件摘要的域分隔摘要。
    ///
    /// 它单独存在（而不是只依赖 [`BundleManifest::manifest_digest`]）是为了让
    /// 「签名覆盖了全部 file digest」这件事在 [`BundleManifest::signing_payload`]
    /// 里**显式可见**，而不是隐含在「manifest 里恰好有个 files 字段」这一事实中。
    pub fn files_digest(&self) -> Digest32 {
        let value = Value::map_from(
            self.files
                .iter()
                .map(|(path, digest)| (Value::Text(path.clone()), digest.to_value())),
        )
        .expect("BTreeMap 的键互不相同");
        Digest32::domain_hash(BUNDLE_FILES_DIGEST_DOMAIN, &crate::cbor::encode(&value))
    }

    /// canonical manifest 的域分隔摘要。
    pub fn manifest_digest(&self) -> Digest32 {
        Digest32::domain_hash(BUNDLE_MANIFEST_DIGEST_DOMAIN, &self.to_canonical_vec())
    }

    /// 发布者签名实际覆盖的字节。
    ///
    /// ```text
    /// signing_payload = canonical_cbor([
    ///     "envsync:bundle-signing-payload:v1",
    ///     1,                       // 签名格式版本
    ///     bundle id,
    ///     bundle version,
    ///     manifest_digest,         // 覆盖 manifest 的每一个字段
    ///     files_digest,            // 显式覆盖全部 file digest
    /// ])
    /// ```
    ///
    /// 由此得到三条性质：改任意一个 manifest 字段（含任意一条文件摘要）都会让签名
    /// 失配；把 A Bundle 的签名挪到 B Bundle 上会失配；换一个版本号重放同一枚签名
    /// 也会失配。
    pub fn signing_payload(&self) -> Vec<u8> {
        crate::cbor::encode(&Value::Array(vec![
            Value::Text(BUNDLE_SIGNING_PAYLOAD_DOMAIN.to_owned()),
            Value::Uint(BUNDLE_SIGNATURE_FORMAT_VERSION as u64),
            Value::Text(self.id.as_str().to_owned()),
            Value::Text(self.version.clone()),
            Value::Bytes(self.manifest_digest().as_bytes().to_vec()),
            Value::Bytes(self.files_digest().as_bytes().to_vec()),
        ]))
    }
}

impl CborCodec for BundleManifest {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Uint(self.format_version as u64),
            self.id.to_value(),
            Value::Text(self.version.clone()),
            Value::Bytes(self.publisher_key.to_vec()),
            self.files.to_value(),
            self.entrypoints.to_value(),
            string_set_to_value(&self.declared_capabilities),
            string_set_to_value(&self.secret_refs),
            string_set_to_value(&self.target_tools),
            Value::Text(self.min_envsync_version.clone()),
            Value::Uint(self.total_bytes),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        if items.len() != 11 {
            return Err(CborError::ArityMismatch);
        }
        let format_version = u32::from_value(&items[0])?;
        if format_version != BUNDLE_MANIFEST_FORMAT_VERSION {
            return Err(CborError::UnsupportedFormatVersion {
                found: format_version,
                supported: BUNDLE_MANIFEST_FORMAT_VERSION,
            });
        }
        Ok(BundleManifest {
            format_version,
            id: BundleId::from_value(&items[1])?,
            version: String::from_value(&items[2])?,
            publisher_key: <[u8; 32]>::from_value(&items[3])?,
            files: BTreeMap::from_value(&items[4])?,
            entrypoints: BTreeMap::from_value(&items[5])?,
            declared_capabilities: string_set_from_value(&items[6])?,
            secret_refs: string_set_from_value(&items[7])?,
            target_tools: string_set_from_value(&items[8])?,
            min_envsync_version: String::from_value(&items[9])?,
            total_bytes: u64::from_value(&items[10])?,
        })
    }
}

/// 把字符串集合编成 CBOR 数组（已按 [`BTreeSet`] 的顺序排序）。
fn string_set_to_value(set: &BTreeSet<String>) -> Value {
    Value::Array(set.iter().map(|item| Value::Text(item.clone())).collect())
}

/// 从 CBOR 数组还原字符串集合，**拒绝重复项与乱序**。
///
/// 乱序也要拒绝：集合的 canonical 编码必须唯一，否则同一份逻辑内容会有多种字节表示，
/// 签名就不再是「对内容」的签名，而是「对某一种写法」的签名。
fn string_set_from_value(value: &Value) -> Result<BTreeSet<String>, CborError> {
    let items = value.as_array()?;
    let mut out = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for item in items {
        let text = item.as_text()?;
        if let Some(prev) = previous {
            if prev >= text {
                return Err(CborError::NotCanonical);
            }
        }
        previous = Some(text);
        out.insert(text.to_owned());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// 签名
// ---------------------------------------------------------------------------

/// 发布者对一个 Bundle 的签名。
///
/// 本结构只是**载体**：它不做任何密码学运算。验签在 `envsync_core::bundles` 里用
/// `envsync_crypto` 完成，本 crate 不引入密码学依赖。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSignature {
    /// 格式版本，必须等于 [`BUNDLE_SIGNATURE_FORMAT_VERSION`]。
    pub format_version: u32,
    /// 被签名的 Bundle。
    pub bundle: BundleId,
    /// 被签名的 manifest 摘要。
    pub manifest_digest: Digest32,
    /// 原始签名字节（Ed25519：64 字节）。
    pub signature: Vec<u8>,
}

impl BundleSignature {
    /// Ed25519 签名的字节长度。
    pub const SIGNATURE_LEN: usize = 64;

    /// 校验签名对象自身的形状，并确认它声称覆盖的正是 `manifest`。
    ///
    /// 这是**验签之前**的廉价检查：版本、长度、Bundle 标识与 manifest 摘要都对上了，
    /// 才值得去做曲线运算。它不能替代验签，但能让「签名对象来自另一个 Bundle」这类
    /// 错误在密码学之前就被挡掉。
    pub fn check_shape(&self, manifest: &BundleManifest) -> Result<(), BundleManifestError> {
        if self.format_version != BUNDLE_SIGNATURE_FORMAT_VERSION {
            return Err(BundleManifestError::UnsupportedFormatVersion {
                found: self.format_version,
                supported: BUNDLE_SIGNATURE_FORMAT_VERSION,
            });
        }
        if self.signature.len() != Self::SIGNATURE_LEN {
            return Err(BundleManifestError::SignatureMismatch {
                detail: "签名字节长度不是 64",
            });
        }
        if self.bundle != manifest.id {
            return Err(BundleManifestError::SignatureMismatch {
                detail: "签名对象指向另一个 Bundle",
            });
        }
        if self.manifest_digest != manifest.manifest_digest() {
            return Err(BundleManifestError::SignatureMismatch {
                detail: "manifest 摘要与签名对象不符",
            });
        }
        Ok(())
    }
}

impl CborCodec for BundleSignature {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Uint(self.format_version as u64),
            self.bundle.to_value(),
            self.manifest_digest.to_value(),
            Value::Bytes(self.signature.clone()),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        if items.len() != 4 {
            return Err(CborError::ArityMismatch);
        }
        let format_version = u32::from_value(&items[0])?;
        if format_version != BUNDLE_SIGNATURE_FORMAT_VERSION {
            return Err(CborError::UnsupportedFormatVersion {
                found: format_version,
                supported: BUNDLE_SIGNATURE_FORMAT_VERSION,
            });
        }
        Ok(BundleSignature {
            format_version,
            bundle: BundleId::from_value(&items[1])?,
            manifest_digest: Digest32::from_value(&items[2])?,
            signature: Vec::<u8>::from_value(&items[3])?,
        })
    }
}

// ---------------------------------------------------------------------------
// 隔离状态机
// ---------------------------------------------------------------------------

/// Bundle 在本机的隔离状态。
///
/// ```text
/// downloaded ──▶ inspected ──▶ approved ──▶ enabled
///      │              │            │           │
///      └──────────────┴────────────┴───────────┴──▶ blocked ──▶ revoked
/// ```
///
/// 三条规则：
///
/// 1. **前进只能逐级。** 不存在 `downloaded → enabled` 的捷径：每一级都对应一件必须
///    发生过的事（解包并校验载荷 / 验签并展示 diff 与声明能力 / 用户确认）。
/// 2. **降级永远可用。** 任何状态都能进 `blocked` 或 `revoked`。这是安全动作，不需要
///    任何前置条件——发现问题时能立刻停下来，比停得优雅重要。
/// 3. **`revoked` 是吸收态。** 撤销之后没有回头路：要重新启用必须重新下载，从而重新
///    走一遍完整的验签与审核流程。
///
/// 字符串形式是持久化契约（写进 SQLite 的 `state` 列并被 `CHECK` 约束限定），
/// **只能新增、不能重命名**。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleState {
    /// 已下载到 quarantine 根，内容尚未校验。
    Downloaded,
    /// 载荷已校验、签名已验证，等待用户审核。
    Inspected,
    /// 用户已批准某个 `(摘要, 能力集, Profile, signer)` 四元组。
    Approved,
    /// 已渲染到目标工具并生效。
    Enabled,
    /// 因签名、内容或策略问题被阻断。
    Blocked,
    /// 已撤销；吸收态。
    Revoked,
}

impl BundleState {
    /// 全部状态，按上面的图排列。
    pub const ALL: [BundleState; 6] = [
        BundleState::Downloaded,
        BundleState::Inspected,
        BundleState::Approved,
        BundleState::Enabled,
        BundleState::Blocked,
        BundleState::Revoked,
    ];

    /// 稳定的持久化短名。
    pub const fn as_str(self) -> &'static str {
        match self {
            BundleState::Downloaded => "downloaded",
            BundleState::Inspected => "inspected",
            BundleState::Approved => "approved",
            BundleState::Enabled => "enabled",
            BundleState::Blocked => "blocked",
            BundleState::Revoked => "revoked",
        }
    }

    /// 由短名解析；未知取值返回 `None`（调用方必须拒绝，绝不静默当成某个状态）。
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "downloaded" => BundleState::Downloaded,
            "inspected" => BundleState::Inspected,
            "approved" => BundleState::Approved,
            "enabled" => BundleState::Enabled,
            "blocked" => BundleState::Blocked,
            "revoked" => BundleState::Revoked,
            _ => return None,
        })
    }

    /// 该状态下 Bundle 的内容是否已经在影响 AI 工具的行为。
    pub const fn is_active(self) -> bool {
        matches!(self, BundleState::Enabled)
    }

    /// 是否为吸收态（没有任何出边）。
    pub const fn is_terminal(self) -> bool {
        matches!(self, BundleState::Revoked)
    }

    /// 是否为「降级」目标（安全动作）。
    pub const fn is_downgrade(self) -> bool {
        matches!(self, BundleState::Blocked | BundleState::Revoked)
    }

    /// 前进方向上的下一个状态；`enabled` 及两个降级态没有下一个。
    pub const fn next(self) -> Option<Self> {
        match self {
            BundleState::Downloaded => Some(BundleState::Inspected),
            BundleState::Inspected => Some(BundleState::Approved),
            BundleState::Approved => Some(BundleState::Enabled),
            BundleState::Enabled | BundleState::Blocked | BundleState::Revoked => None,
        }
    }

    /// 从当前状态迁移到 `next` 是否合法。
    ///
    /// 自迁移一律为 `false`：幂等由调用方在更高层判断，状态机本身不承认「原地不动」
    /// 是一次迁移，否则「已经启用了」和「刚刚启用成功」在审计日志里无法区分。
    pub fn can_transition_to(self, next: BundleState) -> bool {
        if self == next || self.is_terminal() {
            return false;
        }
        if next.is_downgrade() {
            // 任何状态都能被阻断或撤销。
            return true;
        }
        // 前进方向只允许逐级，且 blocked 不能直接回到流程里：必须重新下载。
        self.next() == Some(next)
    }

    /// 迁移到 `next` 所对应的策略操作。
    ///
    /// 全部返回「启用」：隔离状态机的每一步都是「让这份主动内容离生效更近一步」，
    /// 因此它们共享同一条策略维度。区分具体是哪一步由调用方记录在解释里。
    pub const fn policy_operation_is_enable(self) -> bool {
        true
    }
}

impl fmt::Display for BundleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

crate::cbor_unit_enum!(BundleState {
    BundleState::Downloaded => "downloaded",
    BundleState::Inspected => "inspected",
    BundleState::Approved => "approved",
    BundleState::Enabled => "enabled",
    BundleState::Blocked => "blocked",
    BundleState::Revoked => "revoked",
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_accepts_and_rejects() {
        for good in [
            "0.0.0",
            "1.2.3",
            "1.2.3-alpha.1",
            "1.2.3+build.5",
            "10.20.30",
        ] {
            assert!(is_semver(good), "{good} 应当合法");
        }
        for bad in [
            "1.2", "1.2.3.4", "01.2.3", "v1.2.3", "1.2.3-", "1.2.3-01", "",
        ] {
            assert!(!is_semver(bad), "{bad} 应当非法");
        }
    }

    #[test]
    fn state_machine_forward_edges_are_single_step() {
        assert!(BundleState::Downloaded.can_transition_to(BundleState::Inspected));
        assert!(!BundleState::Downloaded.can_transition_to(BundleState::Enabled));
        assert!(!BundleState::Blocked.can_transition_to(BundleState::Approved));
        assert!(!BundleState::Revoked.can_transition_to(BundleState::Blocked));
    }

    #[test]
    fn every_state_can_be_blocked_or_revoked() {
        for state in BundleState::ALL {
            if state.is_terminal() {
                continue;
            }
            if state != BundleState::Blocked {
                assert!(state.can_transition_to(BundleState::Blocked), "{state}");
            }
            assert!(state.can_transition_to(BundleState::Revoked), "{state}");
        }
    }

    #[test]
    fn credential_heuristic_flags_obvious_tokens() {
        assert!(looks_like_credential("ghp_0123456789abcdefghij"));
        assert!(looks_like_credential("AKIAIOSFODNN7EXAMPLE"));
        assert!(looks_like_credential("Zm9vYmFyQmF6MTIzNDU2Nzg5MA=="));
        assert!(!looks_like_credential("github/token"));
        assert!(!looks_like_credential("ci/npm-token"));
    }
}
