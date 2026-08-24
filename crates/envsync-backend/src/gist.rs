//! 受限的 GitHub Gist 后端边界。
//!
//! 本模块只持有经过校验的 API 基址和 Vault 提供的 token。真正的 HTTP 读写与 CAS
//! 协议由后续任务实现；在此之前，所有操作在完成本地 Bundle 校验后稳定地返回
//! [`GistError::code`] 为 `gist.not_implemented` 的错误。

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use envsync_crypto::sealed::SecretId;
use envsync_crypto::suite::Plaintext;
use envsync_domain::WorkspaceId;
use reqwest::redirect::Policy;
use reqwest::Url;
use zeroize::Zeroizing;

use crate::gist_bundle::{self, GistBundleHeader};
use crate::BackendDescriptor;

const GITHUB_API_BASE: &str = "https://api.github.com/";
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_TOKEN_LEN: usize = 4096;

/// 一个经过语法校验的 Gist 标识。
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GistId(String);

impl GistId {
    /// 解析 GitHub API 接受的 Gist 标识。
    pub fn parse(text: &str) -> Result<Self, GistError> {
        if !(1..=128).contains(&text.len())
            || !text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(GistError::invalid_gist_id());
        }
        Ok(Self(text.to_owned()))
    }

    /// 返回标识文本，用于上层的安全持久化。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GistId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// 从 Vault 明文构造的 Gist 认证材料。
pub struct GistCredentials {
    secret_ref: SecretId,
    token: Zeroizing<String>,
}

impl GistCredentials {
    /// 只接受 Vault 解封后的 token 明文，并在内存中以可清零字符串保存。
    pub fn from_vault(secret_ref: SecretId, plaintext: Plaintext) -> Result<Self, GistError> {
        let bytes = plaintext.expose();
        if bytes.is_empty() || bytes.len() > MAX_TOKEN_LEN {
            return Err(GistError::invalid_credentials());
        }
        let token = std::str::from_utf8(bytes).map_err(|_| GistError::invalid_credentials())?;
        if token.chars().any(char::is_control) {
            return Err(GistError::invalid_credentials());
        }

        Ok(Self {
            secret_ref,
            token: Zeroizing::new(token.to_owned()),
        })
    }
}

impl fmt::Debug for GistCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GistCredentials")
            .field("secret_ref", &"<redacted>")
            .field("token", &"<redacted>")
            .finish()
    }
}

/// 一次 Gist 读取所得的公开 Bundle 元数据与私有 ETag。
#[derive(Clone)]
pub struct GistRevision {
    gist_id: GistId,
    header: GistBundleHeader,
    etag: String,
}

impl GistRevision {
    /// 返回此 revision 所属的 Gist 标识。
    pub fn gist_id(&self) -> &GistId {
        &self.gist_id
    }

    /// 返回 Bundle 的未验证公开 header。
    pub fn header(&self) -> &GistBundleHeader {
        &self.header
    }
}

impl fmt::Debug for GistRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GistRevision")
            .field("gist_id", &"<redacted>")
            .field("header", &self.header)
            .field("etag", &"<redacted>")
            .finish()
    }
}

/// Gist 中的一条完整密封 Bundle 记录。
pub struct GistBundleRecord {
    encoded: String,
    revision: GistRevision,
}

impl GistBundleRecord {
    /// 返回密封 Bundle 的编码文本。
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    /// 返回此记录对应的 Gist revision。
    pub fn revision(&self) -> &GistRevision {
        &self.revision
    }
}

impl fmt::Debug for GistBundleRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GistBundleRecord(<untrusted>)")
            .field("workspace", &self.revision.header.workspace)
            .field("revision", &self.revision.header.revision)
            .field("head", &self.revision.header.head)
            .field("epoch", &self.revision.header.epoch)
            .field("encoded_len", &self.encoded.len())
            .finish()
    }
}

/// Gist 后端的稳定错误。
pub struct GistError {
    kind: GistErrorKind,
}

#[derive(Clone, Copy)]
enum GistErrorKind {
    InvalidApiBase,
    InvalidCredentials,
    InvalidGistId,
    InvalidBundle(&'static str),
    WorkspaceMismatch,
    RevisionNotNext,
    NotImplemented,
}

impl GistError {
    fn invalid_api_base() -> Self {
        Self {
            kind: GistErrorKind::InvalidApiBase,
        }
    }

    fn invalid_credentials() -> Self {
        Self {
            kind: GistErrorKind::InvalidCredentials,
        }
    }

    fn invalid_gist_id() -> Self {
        Self {
            kind: GistErrorKind::InvalidGistId,
        }
    }

    fn invalid_bundle(bundle_code: &'static str) -> Self {
        Self {
            kind: GistErrorKind::InvalidBundle(bundle_code),
        }
    }

    fn workspace_mismatch() -> Self {
        Self {
            kind: GistErrorKind::WorkspaceMismatch,
        }
    }

    fn revision_not_next() -> Self {
        Self {
            kind: GistErrorKind::RevisionNotNext,
        }
    }

    fn not_implemented() -> Self {
        Self {
            kind: GistErrorKind::NotImplemented,
        }
    }

    /// 返回稳定的机器可读错误码。
    pub fn code(&self) -> &'static str {
        match self.kind {
            GistErrorKind::InvalidApiBase => "gist.invalid_api_base",
            GistErrorKind::InvalidCredentials => "gist.invalid_credentials",
            GistErrorKind::InvalidGistId => "gist.invalid_gist_id",
            GistErrorKind::InvalidBundle("gist_bundle.encoded_too_large") => {
                "gist.bundle_too_large"
            }
            GistErrorKind::InvalidBundle(_) => "gist.invalid_bundle",
            GistErrorKind::WorkspaceMismatch => "gist.workspace_mismatch",
            GistErrorKind::RevisionNotNext => "gist.revision_not_next",
            GistErrorKind::NotImplemented => "gist.not_implemented",
        }
    }
}

impl fmt::Display for GistError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            GistErrorKind::InvalidApiBase => "Gist API 基址不符合安全约束",
            GistErrorKind::InvalidCredentials => "Gist 凭据无效",
            GistErrorKind::InvalidGistId => "Gist 标识无效",
            GistErrorKind::InvalidBundle(_) => "Gist Bundle 无效",
            GistErrorKind::WorkspaceMismatch => "Gist Bundle 工作区不匹配",
            GistErrorKind::RevisionNotNext => "Gist Bundle revision 必须恰好递增 1",
            GistErrorKind::NotImplemented => "Gist HTTP 操作尚未实现",
        };
        formatter.write_str(message)
    }
}

impl fmt::Debug for GistError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GistError")
            .field("code", &self.code())
            .finish()
    }
}

impl std::error::Error for GistError {}

/// GitHub Gist 后端。
pub struct GistBackend {
    api_base: Url,
    client: reqwest::blocking::Client,
}

impl GistBackend {
    /// 使用固定 GitHub 公共 API 与 30 秒请求超时构造后端。
    pub fn github() -> Result<Self, GistError> {
        Self::with_api_base(GITHUB_API_BASE, DEFAULT_REQUEST_TIMEOUT)
    }

    /// 使用经安全约束校验的 GitHub 或 GitHub Enterprise API 基址构造后端。
    pub fn with_api_base(
        base_url: impl AsRef<str>,
        request_timeout: Duration,
    ) -> Result<Self, GistError> {
        let api_base = validate_api_base(base_url.as_ref())?;
        let client = reqwest::blocking::Client::builder()
            .timeout(request_timeout)
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .map_err(|_| GistError::invalid_api_base())?;
        Ok(Self { api_base, client })
    }

    /// 返回此后端的能力声明。
    pub fn descriptor(&self) -> BackendDescriptor {
        BackendDescriptor {
            kind: "gist",
            supports_strong_cas: false,
        }
    }

    /// 创建一个非公开 Gist；当前仅执行本地 Bundle 校验。
    pub fn create(
        &self,
        credentials: &GistCredentials,
        encoded: &str,
    ) -> Result<GistBundleRecord, GistError> {
        let header = inspect(encoded)?;
        let _ = (
            self.api_base.as_str(),
            &self.client,
            credentials.secret_ref.as_str(),
            credentials.token.as_str(),
            header,
        );
        Err(GistError::not_implemented())
    }

    /// 读取工作区的 Gist Bundle；当前不会发出网络请求。
    pub fn read(
        &self,
        credentials: &GistCredentials,
        gist: &GistId,
        workspace: WorkspaceId,
    ) -> Result<GistBundleRecord, GistError> {
        let _ = (
            self.api_base.as_str(),
            &self.client,
            credentials.secret_ref.as_str(),
            credentials.token.as_str(),
            gist,
            workspace,
        );
        Err(GistError::not_implemented())
    }

    /// 以 ETag 为条件发布下一 revision；当前仅执行本地 Bundle 校验。
    pub fn compare_and_swap(
        &self,
        credentials: &GistCredentials,
        expected: &GistRevision,
        encoded: &str,
    ) -> Result<GistBundleRecord, GistError> {
        let candidate = inspect(encoded)?;
        let _ = (
            self.api_base.as_str(),
            &self.client,
            credentials.secret_ref.as_str(),
            credentials.token.as_str(),
            expected.etag.as_str(),
        );
        if candidate.workspace != expected.header.workspace {
            return Err(GistError::workspace_mismatch());
        }
        if expected
            .header
            .revision
            .checked_add(1)
            .is_none_or(|revision| candidate.revision != revision)
        {
            return Err(GistError::revision_not_next());
        }
        Err(GistError::not_implemented())
    }
}

impl fmt::Debug for GistBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GistBackend")
            .field("api_base", &"<redacted>")
            .finish()
    }
}

fn inspect(encoded: &str) -> Result<GistBundleHeader, GistError> {
    gist_bundle::inspect(encoded).map_err(|error| GistError::invalid_bundle(error.code()))
}

fn validate_api_base(text: &str) -> Result<Url, GistError> {
    let url = Url::parse(text).map_err(|_| GistError::invalid_api_base())?;
    if !url.has_authority()
        || !url.path().starts_with('/')
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(GistError::invalid_api_base());
    }
    match url.scheme() {
        "https" => Ok(url),
        "http" if is_loopback_host(&url) => Ok(url),
        _ => Err(GistError::invalid_api_base()),
    }
}

fn is_loopback_host(url: &Url) -> bool {
    url.host_str()
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::{GistBackend, GistBundleRecord, GistCredentials, GistId, GistRevision};
    use crate::gist_bundle::GistBundleHeader;
    use envsync_crypto::device::DeviceKeypair;
    use envsync_crypto::sealed::SecretId;
    use envsync_crypto::suite::{KeyEpoch, Plaintext};
    use envsync_domain::WorkspaceId;

    #[test]
    fn github_uses_the_gist_backend_descriptor() {
        let backend = GistBackend::github().expect("固定 GitHub API 地址必须可构造");

        assert_eq!(backend.descriptor().kind, "gist");
        assert!(!backend.descriptor().supports_strong_cas);
    }

    #[test]
    fn credentials_reject_unsafe_tokens_and_redact_all_sensitive_values() {
        let secret = SecretId::parse("private/gist-token").expect("合法 Vault 引用");
        let token = "token-should-not-appear";
        let credentials =
            GistCredentials::from_vault(secret, Plaintext::from_slice(token.as_bytes()))
                .expect("合法 token");
        let debug = format!("{credentials:?}");
        assert!(!debug.contains(token));
        assert!(!debug.contains("private/gist-token"));
        assert!(debug.contains("<redacted>"));

        for plaintext in [
            Plaintext::from_slice(b""),
            Plaintext::from_slice(&[0xff]),
            Plaintext::from_slice(b"has\ncontrol"),
            Plaintext::from_vec(vec![b'x'; 4097]),
        ] {
            let error = GistCredentials::from_vault(
                SecretId::parse("private/gist-token").expect("合法 Vault 引用"),
                plaintext,
            )
            .expect_err("不安全 token 必须被拒绝");
            assert_eq!(error.code(), "gist.invalid_credentials");
        }
    }

    #[test]
    fn gist_id_has_a_narrow_syntax_and_never_debugs_its_value() {
        let identifier = GistId::parse("public-ish_123").expect("允许的 Gist ID");
        assert_eq!(identifier.as_str(), "public-ish_123");
        assert_eq!(format!("{identifier:?}"), "<redacted>");

        for invalid in ["", "contains/slash", "space id", "x!", &"x".repeat(129)] {
            let error = GistId::parse(invalid).expect_err("非法 Gist ID 必须被拒绝");
            assert_eq!(error.code(), "gist.invalid_gist_id");
        }
    }

    #[test]
    fn api_base_refuses_unsafe_urls_without_echoing_them() {
        let unsafe_url = "http://token@example.test/private?secret=token#fragment";
        let error = GistBackend::with_api_base(unsafe_url, std::time::Duration::from_secs(1))
            .expect_err("非 loopback HTTP、userinfo、query 与 fragment 均必须拒绝");
        assert_eq!(error.code(), "gist.invalid_api_base");
        assert!(!error.to_string().contains("token"));
        assert!(!format!("{error:?}").contains("token"));

        GistBackend::with_api_base(
            "http://127.0.0.1:8080/api/",
            std::time::Duration::from_secs(1),
        )
        .expect("loopback HTTP 仅供测试与本地 mock 使用");
    }

    #[test]
    fn bundle_record_debug_shows_only_allowed_header_fields_and_length() {
        let workspace = WorkspaceId::generate();
        let signer = DeviceKeypair::generate().expect("生成测试设备");
        let record = GistBundleRecord {
            encoded: "encoded-bundle-must-not-appear".to_owned(),
            revision: GistRevision {
                gist_id: GistId::parse("gist-id-must-not-appear").expect("合法 Gist ID"),
                header: GistBundleHeader {
                    workspace,
                    revision: 7,
                    head: None,
                    epoch: KeyEpoch::INITIAL,
                    signer: signer.device_id(),
                    object_count: 2,
                },
                etag: "etag-must-not-appear".to_owned(),
            },
        };

        let debug = format!("{record:?}");
        assert!(debug.contains("workspace"));
        assert!(debug.contains("revision"));
        assert!(debug.contains("head"));
        assert!(debug.contains("epoch"));
        assert!(debug.contains("encoded_len"));
        assert!(!debug.contains("encoded-bundle-must-not-appear"));
        assert!(!debug.contains("gist-id-must-not-appear"));
        assert!(!debug.contains("etag-must-not-appear"));
    }

    #[test]
    fn create_inspects_its_bundle_before_returning_not_implemented() {
        let backend =
            GistBackend::with_api_base("http://127.0.0.1:8080/", std::time::Duration::from_secs(1))
                .expect("本地 API 基址合法");
        let credentials = GistCredentials::from_vault(
            SecretId::parse("private/gist-token").expect("合法 Vault 引用"),
            Plaintext::from_slice(b"valid-token"),
        )
        .expect("合法 token");
        let encoded = "invalid-bundle-must-not-appear";

        let error = backend
            .create(&credentials, encoded)
            .expect_err("非法 Bundle 必须早于 HTTP 占位错误被拒绝");
        assert_eq!(error.code(), "gist.invalid_bundle");
        assert!(!error.to_string().contains(encoded));
        assert!(!format!("{error:?}").contains(encoded));
    }
}
