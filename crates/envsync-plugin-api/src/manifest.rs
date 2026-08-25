//! 插件 manifest 的严格纯数据模型。
//!
//! 本模块只验证不可信 JSON 的结构、有限集合和资源声明；它不作任何信任决定、密码学
//! 验签或 I/O。Host 必须在获得 [`PluginManifest`] 后独立处理发布者信任和签名验证。

use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

const MAX_ID_BYTES: usize = 128;
const MAX_ENTRYPOINT_BYTES: usize = 512;
const MIN_RUNTIME_MS: u32 = 100;
const MAX_RUNTIME_MS: u32 = 30_000;
const MIN_MEMORY_BYTES: u64 = 1024 * 1024;
const MAX_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
const MIN_OUTPUT_BYTES: u64 = 1024;

/// 单个 RPC JSON body 可占用的最大字节数。
///
/// 它属于 API 契约，以便后续 RPC 实现与 Host 使用相同的帧上限。
pub const MAX_RPC_FRAME_BYTES: usize = 8 * 1024 * 1024;

const MAX_OUTPUT_BYTES: u64 = MAX_RPC_FRAME_BYTES as u64;

/// Host 当前支持的插件 API 版本。
pub const HOST_PLUGIN_API_VERSIONS: [semver::Version; 2] =
    [semver::Version::new(1, 0, 0), semver::Version::new(1, 1, 0)];

/// 已验证的插件 manifest。
///
/// 此值仅表示 manifest 的声明符合协议，不表示发布者、签名或任何 capability 已获信任。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginManifest {
    id: PluginId,
    version: semver::Version,
    publisher: Publisher,
    api: semver::VersionReq,
    entrypoint: PluginEntrypoint,
    targets: BTreeSet<PluginTarget>,
    capabilities: BTreeSet<PluginCapability>,
    limits: ResourceLimits,
    signature: PluginSignature,
}

impl PluginManifest {
    /// 从 JSON 值构造并校验 manifest。
    ///
    /// JSON 仅会先进入本模块的私有原始结构；公开值对象中的文本字段都经过逐项校验。
    pub fn from_json_value(value: serde_json::Value) -> Result<Self, PluginManifestError> {
        let raw: RawManifest =
            serde_json::from_value(value).map_err(|_| PluginManifestError::InvalidManifest)?;
        Self::try_from(raw)
    }

    /// 返回已经校验的插件标识。
    pub fn id(&self) -> &PluginId {
        &self.id
    }

    /// 返回插件的语义版本。
    pub fn version(&self) -> &semver::Version {
        &self.version
    }

    /// 返回已经校验的发布者声明。
    pub fn publisher(&self) -> &Publisher {
        &self.publisher
    }

    /// 返回兼容性已验证的 API 版本请求。
    pub fn api(&self) -> &semver::VersionReq {
        &self.api
    }

    /// 返回已校验、相对 Unix 风格的入口点。
    pub fn entrypoint(&self) -> &PluginEntrypoint {
        &self.entrypoint
    }

    /// 返回非空且去重的目标平台集合。
    pub fn targets(&self) -> &BTreeSet<PluginTarget> {
        &self.targets
    }

    /// 返回非空且去重的 capability 声明集合。
    pub fn capabilities(&self) -> &BTreeSet<PluginCapability> {
        &self.capabilities
    }

    /// 返回已校验的资源上限声明。
    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    /// 返回形状已校验但尚未获得信任的签名声明。
    pub fn signature(&self) -> &PluginSignature {
        &self.signature
    }

    /// 返回用于 Host 签名校验的确定性无签名 JSON payload。
    ///
    /// 该 payload 刻意排除 `signature` 字段；本 crate 不对它执行密码学验签。
    pub fn signing_payload(&self) -> Result<Vec<u8>, PluginManifestError> {
        let unsigned = UnsignedManifest {
            id: self.id.as_str(),
            version: self.version.to_string(),
            publisher: UnsignedPublisher {
                id: &self.publisher.id,
                public_key: URL_SAFE_NO_PAD.encode(self.publisher.public_key),
            },
            api: self.api.to_string(),
            entrypoint: self.entrypoint.as_str(),
            targets: canonical_wire_values(self.targets.iter().map(|target| target.as_str())),
            capabilities: canonical_wire_values(
                self.capabilities
                    .iter()
                    .map(|capability| capability.as_str()),
            ),
            limits: UnsignedResourceLimits {
                max_runtime_ms: self.limits.max_runtime_ms,
                max_memory_bytes: self.limits.max_memory_bytes,
                max_output_bytes: self.limits.max_output_bytes,
            },
        };

        serde_json::to_vec(&unsigned).map_err(|_| PluginManifestError::InvalidSignature)
    }
}

impl TryFrom<RawManifest> for PluginManifest {
    type Error = PluginManifestError;

    fn try_from(raw: RawManifest) -> Result<Self, Self::Error> {
        let id = PluginId::parse(&raw.id)?;
        let version =
            semver::Version::parse(&raw.version).map_err(|_| PluginManifestError::InvalidSemver)?;
        let publisher = Publisher::try_from(raw.publisher)?;
        let api =
            semver::VersionReq::parse(&raw.api).map_err(|_| PluginManifestError::InvalidSemver)?;
        if !HOST_PLUGIN_API_VERSIONS
            .iter()
            .any(|host_version| api.matches(host_version))
        {
            return Err(PluginManifestError::IncompatibleApi);
        }

        let entrypoint = PluginEntrypoint::parse(&raw.entrypoint)?;
        let targets = parse_targets(raw.targets)?;
        let capabilities = parse_capabilities(raw.capabilities)?;
        let limits = ResourceLimits::try_from(raw.limits)?;
        let signature = PluginSignature::try_from(raw.signature)?;

        Ok(Self {
            id,
            version,
            publisher,
            api,
            entrypoint,
            targets,
            capabilities,
            limits,
            signature,
        })
    }
}

/// 同一安装批次中已验证 manifest 的索引。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginCatalog {
    by_id: BTreeMap<PluginId, PluginManifest>,
}

impl PluginCatalog {
    /// 从 manifest 集合建立目录，并拒绝重复的规范化插件标识。
    pub fn new(manifests: Vec<PluginManifest>) -> Result<Self, PluginManifestError> {
        let mut by_id = BTreeMap::new();
        for manifest in manifests {
            if by_id.insert(manifest.id.clone(), manifest).is_some() {
                return Err(PluginManifestError::DuplicateId);
            }
        }
        Ok(Self { by_id })
    }

    /// 按已校验的插件标识取得 manifest。
    pub fn get(&self, id: &PluginId) -> Option<&PluginManifest> {
        self.by_id.get(id)
    }

    /// 返回目录中的 manifest 数量。
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// 指示目录是否为空。
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

/// 已校验的小写反向域名式插件标识。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PluginId(String);

impl PluginId {
    /// 解析小写 ASCII、点分段且最长 128 字节的反向域名式标识。
    pub fn parse(value: &str) -> Result<Self, PluginManifestError> {
        if value.is_empty()
            || value.len() > MAX_ID_BYTES
            || !value.is_ascii()
            || value.split('.').count() < 2
        {
            return Err(PluginManifestError::InvalidId);
        }

        for segment in value.split('.') {
            if segment.is_empty()
                || segment.starts_with('-')
                || segment.ends_with('-')
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err(PluginManifestError::InvalidId);
            }
        }

        Ok(Self(value.to_owned()))
    }

    /// 返回规范化的字符串标识。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for PluginId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// 发布者的声明标识及形状已校验的 Ed25519 公钥。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publisher {
    /// 已校验的小写反向域名式发布者标识。
    pub id: String,
    /// 长度恰为 32 字节的 Ed25519 公钥；并不表示该发布者已获信任。
    pub public_key: [u8; 32],
}

impl TryFrom<RawPublisher> for Publisher {
    type Error = PluginManifestError;

    fn try_from(raw: RawPublisher) -> Result<Self, Self::Error> {
        let id = PluginId::parse(&raw.id)?.0;
        let public_key = decode_fixed::<32>(&raw.public_key)?;
        Ok(Self { id, public_key })
    }
}

/// 已校验的相对 Unix 风格插件入口点。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PluginEntrypoint(String);

impl PluginEntrypoint {
    /// 解析最大 512 字节、由普通段以 `/` 连接的相对路径。
    pub fn parse(value: &str) -> Result<Self, PluginManifestError> {
        if value.is_empty()
            || value.len() > MAX_ENTRYPOINT_BYTES
            || value.starts_with('/')
            || value.contains(['\\', '\0', ':'])
        {
            return Err(PluginManifestError::InvalidEntrypoint);
        }

        for segment in value.split('/') {
            if segment.is_empty() || matches!(segment, "." | "..") {
                return Err(PluginManifestError::InvalidEntrypoint);
            }
        }

        Ok(Self(value.to_owned()))
    }

    /// 返回规范化的相对路径文本。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for PluginEntrypoint {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// 形状已校验但尚未验证的插件签名声明。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginSignature {
    /// 签名算法；当前只支持 Ed25519 的编码形状。
    pub algorithm: SignatureAlgorithm,
    /// 长度恰为 64 字节的签名字节；不代表签名可信或有效。
    pub value: [u8; 64],
}

impl TryFrom<RawSignature> for PluginSignature {
    type Error = PluginManifestError;

    fn try_from(raw: RawSignature) -> Result<Self, Self::Error> {
        let algorithm = match raw.algorithm.as_str() {
            "ed25519" => SignatureAlgorithm::Ed25519,
            _ => return Err(PluginManifestError::InvalidSignature),
        };
        let value = decode_fixed::<64>(&raw.value)?;
        Ok(Self { algorithm, value })
    }
}

/// manifest 支持的签名算法标识。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatureAlgorithm {
    /// Ed25519 的 64 字节签名格式。
    Ed25519,
}

/// manifest 支持的目标平台。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PluginTarget {
    /// macOS 原生插件。
    Macos,
    /// Windows 原生插件。
    Windows,
    /// Linux 原生插件。
    Linux,
    /// WASI Preview 2 插件。
    WasiP2,
}

impl PluginTarget {
    fn parse(value: &str) -> Result<Self, PluginManifestError> {
        match value {
            "macos" => Ok(Self::Macos),
            "windows" => Ok(Self::Windows),
            "linux" => Ok(Self::Linux),
            "wasi-p2" => Ok(Self::WasiP2),
            _ => Err(PluginManifestError::InvalidTarget),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::WasiP2 => "wasi-p2",
        }
    }
}

/// manifest 中可声明的受限 capability。
///
/// 这些值仅是未可信声明，绝不授予 Host 权限。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PluginCapability {
    /// 声明插件可提供 observation。
    Observe,
    /// 声明插件可渲染数据。
    Render,
    /// 声明插件可提出命令计划。
    PlanCommand,
    /// 声明插件可验证状态。
    Verify,
}

impl PluginCapability {
    fn parse(value: &str) -> Result<Self, PluginManifestError> {
        match value {
            "observe" => Ok(Self::Observe),
            "render" => Ok(Self::Render),
            "plan-command" => Ok(Self::PlanCommand),
            "verify" => Ok(Self::Verify),
            _ => Err(PluginManifestError::UnknownCapability),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Render => "render",
            Self::PlanCommand => "plan-command",
            Self::Verify => "verify",
        }
    }
}

/// manifest 声明的固定资源请求上限。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    /// 请求的最大运行时间，范围为 100 至 30,000 毫秒。
    pub max_runtime_ms: u32,
    /// 请求的最大内存，范围为 1 MiB 至 256 MiB。
    pub max_memory_bytes: u64,
    /// 请求的最大输出，范围为 1 KiB 至 8 MiB。
    pub max_output_bytes: u64,
}

impl TryFrom<RawResourceLimits> for ResourceLimits {
    type Error = PluginManifestError;

    fn try_from(raw: RawResourceLimits) -> Result<Self, Self::Error> {
        let max_runtime_ms =
            u32::try_from(raw.max_runtime_ms).map_err(|_| PluginManifestError::InvalidLimit)?;
        let limits = Self {
            max_runtime_ms,
            max_memory_bytes: raw.max_memory_bytes,
            max_output_bytes: raw.max_output_bytes,
        };
        if !(MIN_RUNTIME_MS..=MAX_RUNTIME_MS).contains(&limits.max_runtime_ms)
            || !(MIN_MEMORY_BYTES..=MAX_MEMORY_BYTES).contains(&limits.max_memory_bytes)
            || !(MIN_OUTPUT_BYTES..=MAX_OUTPUT_BYTES).contains(&limits.max_output_bytes)
        {
            return Err(PluginManifestError::InvalidLimit);
        }
        Ok(limits)
    }
}

/// manifest 校验失败的稳定错误码。
///
/// 所有变体均不携带原始输入，因而其 `Display` 和 `Debug` 不会泄漏完整 JSON、签名字节、
/// 绝对路径或其他未可信文本。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PluginManifestError {
    /// manifest JSON 的字段、类型或封闭结构不符合协议。
    #[error("插件 manifest 结构无效")]
    InvalidManifest,
    /// 插件或发布者标识不符合小写反向域名格式。
    #[error("插件或发布者标识格式无效")]
    InvalidId,
    /// manifest 版本或 API 版本请求不是有效的语义版本。
    #[error("manifest 版本或 API 版本请求格式无效")]
    InvalidSemver,
    /// 入口点不是安全的相对 Unix 风格路径。
    #[error("插件入口点必须是安全的相对路径")]
    InvalidEntrypoint,
    /// 一个安装批次包含多个相同的规范化插件标识。
    #[error("插件目录包含重复的插件标识")]
    DuplicateId,
    /// capability 不属于协议支持的封闭集合，或 capability 集合为空/重复。
    #[error("插件 capability 无效、为空或重复")]
    UnknownCapability,
    /// API 请求不匹配 Host 支持的任何版本。
    #[error("插件 API 版本与 Host 不兼容")]
    IncompatibleApi,
    /// 资源限制为空、溢出或超出固定范围。
    #[error("插件资源限制超出允许范围")]
    InvalidLimit,
    /// 公钥或签名的编码、算法或长度无效。
    #[error("发布者公钥或插件签名格式无效")]
    InvalidSignature,
    /// 目标平台不受支持，或目标集合为空/重复。
    #[error("插件目标平台无效、为空或重复")]
    InvalidTarget,
}

impl PluginManifestError {
    /// 返回可供跨版本调用方依赖的稳定机器错误码。
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidManifest => "plugin.manifest.invalid_manifest",
            Self::InvalidId => "plugin.manifest.invalid_id",
            Self::InvalidSemver => "plugin.manifest.invalid_semver",
            Self::InvalidEntrypoint => "plugin.manifest.invalid_entrypoint",
            Self::DuplicateId => "plugin.manifest.duplicate_id",
            Self::UnknownCapability => "plugin.manifest.unknown_capability",
            Self::IncompatibleApi => "plugin.manifest.incompatible_api",
            Self::InvalidLimit => "plugin.manifest.invalid_limit",
            Self::InvalidSignature => "plugin.manifest.invalid_signature",
            Self::InvalidTarget => "plugin.manifest.invalid_target",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    id: String,
    version: String,
    publisher: RawPublisher,
    api: String,
    entrypoint: String,
    targets: Vec<String>,
    capabilities: Vec<String>,
    limits: RawResourceLimits,
    signature: RawSignature,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPublisher {
    id: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResourceLimits {
    max_runtime_ms: u64,
    max_memory_bytes: u64,
    max_output_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignature {
    algorithm: String,
    value: String,
}

#[derive(Serialize)]
struct UnsignedManifest<'a> {
    id: &'a str,
    version: String,
    publisher: UnsignedPublisher<'a>,
    api: String,
    entrypoint: &'a str,
    targets: Vec<&'static str>,
    capabilities: Vec<&'static str>,
    limits: UnsignedResourceLimits,
}

#[derive(Serialize)]
struct UnsignedPublisher<'a> {
    id: &'a str,
    public_key: String,
}

#[derive(Serialize)]
struct UnsignedResourceLimits {
    max_runtime_ms: u32,
    max_memory_bytes: u64,
    max_output_bytes: u64,
}

fn parse_targets(values: Vec<String>) -> Result<BTreeSet<PluginTarget>, PluginManifestError> {
    if values.is_empty() {
        return Err(PluginManifestError::InvalidTarget);
    }

    let mut targets = BTreeSet::new();
    for value in values {
        let target = PluginTarget::parse(&value)?;
        if !targets.insert(target) {
            return Err(PluginManifestError::InvalidTarget);
        }
    }
    Ok(targets)
}

fn parse_capabilities(
    values: Vec<String>,
) -> Result<BTreeSet<PluginCapability>, PluginManifestError> {
    if values.is_empty() {
        return Err(PluginManifestError::UnknownCapability);
    }

    let mut capabilities = BTreeSet::new();
    for value in values {
        let capability = PluginCapability::parse(&value)?;
        if !capabilities.insert(capability) {
            return Err(PluginManifestError::UnknownCapability);
        }
    }
    Ok(capabilities)
}

fn canonical_wire_values(values: impl IntoIterator<Item = &'static str>) -> Vec<&'static str> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort_unstable();
    values
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], PluginManifestError> {
    if value.len() != base64url_unpadded_len(N) {
        return Err(PluginManifestError::InvalidSignature);
    }

    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| PluginManifestError::InvalidSignature)?;
    decoded
        .try_into()
        .map_err(|_| PluginManifestError::InvalidSignature)
}

const fn base64url_unpadded_len(byte_len: usize) -> usize {
    (byte_len / 3) * 4
        + match byte_len % 3 {
            0 => 0,
            1 => 2,
            _ => 3,
        }
}
