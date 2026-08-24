//! 受限的 GitHub Gist 后端边界。
//!
//! 本模块只持有经过校验的 API 基址和 Vault 提供的 token。它实现 Gist 的创建和读取
//! 边界；弱 CAS 协议仍由后续任务实现。

use std::fmt;
use std::io::Read;
use std::net::IpAddr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use envsync_crypto::sealed::SecretId;
use envsync_crypto::suite::Plaintext;
use envsync_domain::WorkspaceId;
use reqwest::header::{self, HeaderMap};
use reqwest::redirect::Policy;
use reqwest::{StatusCode, Url};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::gist_bundle::{self, gist_bundle_filename, GistBundleHeader, MAX_ENCODED_BUNDLE_LEN};
use crate::BackendDescriptor;

const GITHUB_API_BASE: &str = "https://api.github.com/";
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_TOKEN_LEN: usize = 4096;
const MAX_RESPONSE_LEN: usize = MAX_ENCODED_BUNDLE_LEN + 128 * 1024;
const MAX_ETAG_LEN: usize = 1024;
const MAX_REQUEST_ID_LEN: usize = 256;
const MAX_RETRY_DELAY: Duration = Duration::from_secs(60);
const GIST_ACCEPT: &str = "application/vnd.github+json";
const GITHUB_API_VERSION: &str = "2022-11-28";
const GIST_DESCRIPTION: &str = "EnvSync encrypted workspace bundle";

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
        let _secret_ref = &self.secret_ref;
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
    etag: Option<String>,
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
    operation: &'static str,
    status: Option<u16>,
    observed_revision: Option<u64>,
    request_id: Option<String>,
}

#[derive(Clone)]
enum GistErrorKind {
    InvalidApiBase,
    InvalidCredentials,
    InvalidGistId,
    InvalidBundle(&'static str),
    WorkspaceMismatch,
    RevisionNotNext,
    UnconfirmedRevision,
    CasConflict { expected_revision: u64 },
    UpdateOutcomeUnknown,
    Authentication,
    Forbidden,
    NotFound,
    RateLimited,
    Timeout,
    Transport,
    HttpStatus,
    ResponseTooLarge,
    InvalidResponse,
    MissingEtag,
    InvalidRawUrl,
}

impl GistError {
    fn local(kind: GistErrorKind) -> Self {
        Self {
            kind,
            operation: "local",
            status: None,
            observed_revision: None,
            request_id: None,
        }
    }

    fn response(
        kind: GistErrorKind,
        operation: &'static str,
        status: Option<StatusCode>,
        request_id: Option<String>,
    ) -> Self {
        Self {
            kind,
            operation,
            status: status.map(|status| status.as_u16()),
            observed_revision: None,
            request_id,
        }
    }

    fn invalid_api_base() -> Self {
        Self::local(GistErrorKind::InvalidApiBase)
    }

    fn invalid_credentials() -> Self {
        Self::local(GistErrorKind::InvalidCredentials)
    }

    fn invalid_gist_id() -> Self {
        Self::local(GistErrorKind::InvalidGistId)
    }

    fn invalid_bundle(bundle_code: &'static str) -> Self {
        Self::local(GistErrorKind::InvalidBundle(bundle_code))
    }

    fn workspace_mismatch() -> Self {
        Self::local(GistErrorKind::WorkspaceMismatch)
    }

    fn revision_not_next() -> Self {
        Self::local(GistErrorKind::RevisionNotNext)
    }

    fn unconfirmed_revision() -> Self {
        Self::local(GistErrorKind::UnconfirmedRevision)
    }

    fn cas_conflict(expected: &GistRevision, observed: &GistRevision) -> Self {
        Self {
            kind: GistErrorKind::CasConflict {
                expected_revision: expected.header.revision,
            },
            operation: "compare_and_swap",
            status: None,
            observed_revision: Some(observed.header.revision),
            request_id: None,
        }
    }

    fn update_outcome_unknown() -> Self {
        Self {
            kind: GistErrorKind::UpdateOutcomeUnknown,
            operation: "compare_and_swap",
            status: None,
            observed_revision: None,
            request_id: None,
        }
    }

    fn rate_limited(
        operation: &'static str,
        status: StatusCode,
        request_id: Option<String>,
    ) -> Self {
        Self::response(
            GistErrorKind::RateLimited,
            operation,
            Some(status),
            request_id,
        )
    }

    fn invalid_response(
        operation: &'static str,
        status: Option<StatusCode>,
        request_id: Option<String>,
    ) -> Self {
        Self::response(
            GistErrorKind::InvalidResponse,
            operation,
            status,
            request_id,
        )
    }

    fn response_too_large(
        operation: &'static str,
        status: Option<StatusCode>,
        request_id: Option<String>,
    ) -> Self {
        Self::response(
            GistErrorKind::ResponseTooLarge,
            operation,
            status,
            request_id,
        )
    }

    fn missing_etag(
        operation: &'static str,
        status: StatusCode,
        request_id: Option<String>,
    ) -> Self {
        Self::response(
            GistErrorKind::MissingEtag,
            operation,
            Some(status),
            request_id,
        )
    }

    fn invalid_raw_url(
        operation: &'static str,
        status: StatusCode,
        request_id: Option<String>,
    ) -> Self {
        Self::response(
            GistErrorKind::InvalidRawUrl,
            operation,
            Some(status),
            request_id,
        )
    }

    fn request_error(operation: &'static str, error: &reqwest::Error) -> Self {
        let kind = if error.is_timeout() {
            GistErrorKind::Timeout
        } else {
            GistErrorKind::Transport
        };
        Self::response(kind, operation, None, None)
    }

    fn body_error(
        operation: &'static str,
        status: StatusCode,
        request_id: Option<String>,
        error: &std::io::Error,
    ) -> Self {
        let kind = if error.kind() == std::io::ErrorKind::TimedOut {
            GistErrorKind::Timeout
        } else {
            GistErrorKind::Transport
        };
        Self::response(kind, operation, Some(status), request_id)
    }

    fn status_error(
        operation: &'static str,
        status: StatusCode,
        headers: &HeaderMap,
        request_id: Option<String>,
    ) -> Self {
        let kind = match status {
            StatusCode::UNAUTHORIZED => GistErrorKind::Authentication,
            StatusCode::FORBIDDEN if is_rate_limited(headers) => GistErrorKind::RateLimited,
            StatusCode::FORBIDDEN => GistErrorKind::Forbidden,
            StatusCode::NOT_FOUND => GistErrorKind::NotFound,
            StatusCode::TOO_MANY_REQUESTS => GistErrorKind::RateLimited,
            _ => GistErrorKind::HttpStatus,
        };
        Self::response(kind, operation, Some(status), request_id)
    }

    /// 返回稳定的机器可读错误码。
    pub fn code(&self) -> &'static str {
        match &self.kind {
            GistErrorKind::InvalidApiBase => "gist.invalid_api_base",
            GistErrorKind::InvalidCredentials => "gist.invalid_credentials",
            GistErrorKind::InvalidGistId => "gist.invalid_gist_id",
            GistErrorKind::InvalidBundle(bundle_code)
                if *bundle_code == "gist_bundle.encoded_too_large" =>
            {
                "gist.bundle_too_large"
            }
            GistErrorKind::InvalidBundle(_) => "gist.invalid_bundle",
            GistErrorKind::WorkspaceMismatch => "gist.workspace_mismatch",
            GistErrorKind::RevisionNotNext => "gist.revision_not_next",
            GistErrorKind::UnconfirmedRevision => "gist.unconfirmed_revision",
            GistErrorKind::CasConflict { .. } => "gist.cas_conflict",
            GistErrorKind::UpdateOutcomeUnknown => "gist.update_outcome_unknown",
            GistErrorKind::Authentication => "gist.authentication",
            GistErrorKind::Forbidden => "gist.forbidden",
            GistErrorKind::NotFound => "gist.not_found",
            GistErrorKind::RateLimited => "gist.rate_limited",
            GistErrorKind::Timeout => "gist.timeout",
            GistErrorKind::Transport => "gist.transport",
            GistErrorKind::HttpStatus => "gist.http_status",
            GistErrorKind::ResponseTooLarge => "gist.response_too_large",
            GistErrorKind::InvalidResponse => "gist.invalid_response",
            GistErrorKind::MissingEtag => "gist.missing_etag",
            GistErrorKind::InvalidRawUrl => "gist.invalid_raw_url",
        }
    }
}

impl fmt::Display for GistError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match &self.kind {
            GistErrorKind::InvalidApiBase => "Gist API 基址不符合安全约束",
            GistErrorKind::InvalidCredentials => "Gist 凭据无效",
            GistErrorKind::InvalidGistId => "Gist 标识无效",
            GistErrorKind::InvalidBundle(_) => "Gist Bundle 无效",
            GistErrorKind::WorkspaceMismatch => "Gist Bundle 工作区不匹配",
            GistErrorKind::RevisionNotNext => "Gist Bundle revision 必须恰好递增 1",
            GistErrorKind::UnconfirmedRevision => "Gist revision 尚未通过读取确认",
            GistErrorKind::CasConflict { .. } => "Gist CAS 冲突",
            GistErrorKind::UpdateOutcomeUnknown => "Gist 更新结果未知",
            GistErrorKind::Authentication => "Gist 认证失败",
            GistErrorKind::Forbidden => "Gist 访问被拒绝",
            GistErrorKind::NotFound => "Gist 不存在",
            GistErrorKind::RateLimited => "Gist 请求受限",
            GistErrorKind::Timeout => "Gist 请求超时",
            GistErrorKind::Transport => "Gist 传输失败",
            GistErrorKind::HttpStatus => "Gist HTTP 状态异常",
            GistErrorKind::ResponseTooLarge => "Gist 响应超过大小上限",
            GistErrorKind::InvalidResponse => "Gist 响应格式无效",
            GistErrorKind::MissingEtag => "Gist 响应缺少 ETag",
            GistErrorKind::InvalidRawUrl => "Gist raw URL 不符合安全约束",
        };
        formatter.write_str(message)
    }
}

impl fmt::Debug for GistError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // HTTP metadata is intentionally retained for future control flow but never rendered:
        // it is remote-controlled and must not become a logging side channel.
        let expected_revision = match &self.kind {
            GistErrorKind::CasConflict { expected_revision } => Some(*expected_revision),
            _ => None,
        };
        let _metadata = (
            self.operation,
            self.status,
            expected_revision,
            self.observed_revision,
            &self.request_id,
        );
        formatter
            .debug_struct("GistError")
            .field("code", &self.code())
            .finish()
    }
}

impl std::error::Error for GistError {}

trait Sleeper: Send + Sync {
    fn sleep(&self, duration: Duration);
}

struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep(&self, duration: Duration) {
        thread::sleep(duration);
    }
}

/// GitHub Gist 后端。
pub struct GistBackend {
    api_base: Url,
    client: reqwest::blocking::Client,
    sleeper: Arc<dyn Sleeper>,
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
        Ok(Self {
            api_base,
            client,
            sleeper: Arc::new(ThreadSleeper),
        })
    }

    /// 返回此后端的能力声明。
    pub fn descriptor(&self) -> BackendDescriptor {
        BackendDescriptor {
            kind: "gist",
            supports_strong_cas: false,
        }
    }

    /// 创建一个 secret（`public: false`）Gist，并返回服务端分配的 Gist 标识。
    pub fn create(
        &self,
        credentials: &GistCredentials,
        encoded: &str,
    ) -> Result<GistBundleRecord, GistError> {
        let header = inspect(encoded)?;
        let filename = gist_bundle_filename(header.workspace);
        let body = json!({
            "description": GIST_DESCRIPTION,
            "public": false,
            "files": { filename: { "content": encoded } },
        });
        let url = self.api_url(&["gists"])?;
        let response = self
            .api_request(self.client.post(url), credentials)
            .json(&body)
            .send()
            .map_err(|error| GistError::request_error("create", &error))?;
        let (status, request_id) = response_context(&response);
        if !status.is_success() {
            return Err(GistError::status_error(
                "create",
                status,
                response.headers(),
                request_id,
            ));
        }
        let bytes = read_bounded_response(response, "create", status, request_id.clone())?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| GistError::invalid_response("create", Some(status), request_id.clone()))?;
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .and_then(|id| GistId::parse(id).ok())
            .ok_or_else(|| GistError::invalid_response("create", Some(status), request_id))?;

        Ok(GistBundleRecord {
            encoded: encoded.to_owned(),
            revision: GistRevision {
                gist_id: id,
                header,
                etag: None,
            },
        })
    }

    /// 读取工作区的 Gist Bundle，并保存服务端 authoritative ETag。
    pub fn read(
        &self,
        credentials: &GistCredentials,
        gist: &GistId,
        workspace: WorkspaceId,
    ) -> Result<GistBundleRecord, GistError> {
        self.read_api(credentials, gist, workspace, "read", true)
    }

    fn read_api(
        &self,
        credentials: &GistCredentials,
        gist: &GistId,
        workspace: WorkspaceId,
        operation: &'static str,
        retry_rate_limit: bool,
    ) -> Result<GistBundleRecord, GistError> {
        let mut retried = false;
        loop {
            let url = self.api_url(&["gists", gist.as_str()])?;
            let response = self
                .api_request(self.client.get(url), credentials)
                .send()
                .map_err(|error| GistError::request_error(operation, &error))?;
            let (status, request_id) = response_context(&response);
            if !status.is_success() {
                let rate_limited = is_read_rate_limited(status, response.headers());
                let retry_delay = (rate_limited && retry_rate_limit && !retried)
                    .then(|| bounded_retry_delay(response.headers()))
                    .flatten();
                if rate_limited {
                    if let Some(delay) = retry_delay {
                        drop(response);
                        self.sleep_for_rate_limit_retry(delay);
                        retried = true;
                        continue;
                    }
                    let error = GistError::rate_limited(operation, status, request_id);
                    drop(response);
                    return Err(error);
                }
                let error =
                    GistError::status_error(operation, status, response.headers(), request_id);
                drop(response);
                return Err(error);
            }

            return self
                .parse_gist_response(response, operation, status, request_id, gist, workspace);
        }
    }

    fn parse_gist_response(
        &self,
        response: reqwest::blocking::Response,
        operation: &'static str,
        status: StatusCode,
        request_id: Option<String>,
        gist: &GistId,
        workspace: WorkspaceId,
    ) -> Result<GistBundleRecord, GistError> {
        let etag = validated_etag(response.headers());
        let bytes = read_bounded_response(response, operation, status, request_id.clone())?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
            GistError::invalid_response(operation, Some(status), request_id.clone())
        })?;
        let filename = gist_bundle_filename(workspace);
        let file = value
            .get("files")
            .and_then(Value::as_object)
            .and_then(|files| files.get(&filename))
            .and_then(Value::as_object)
            .ok_or_else(|| {
                GistError::invalid_response(operation, Some(status), request_id.clone())
            })?;
        let truncated = file
            .get("truncated")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                GistError::invalid_response(operation, Some(status), request_id.clone())
            })?;
        let etag =
            etag.ok_or_else(|| GistError::missing_etag(operation, status, request_id.clone()))?;
        let encoded = if truncated {
            let raw_url = file
                .get("raw_url")
                .and_then(Value::as_str)
                .and_then(|raw_url| self.validate_raw_url(raw_url).ok())
                .ok_or_else(|| GistError::invalid_raw_url(operation, status, request_id.clone()))?;
            self.read_raw(&raw_url)?
        } else {
            file.get("content")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    GistError::invalid_response(operation, Some(status), request_id.clone())
                })?
        };
        if encoded.len() > MAX_ENCODED_BUNDLE_LEN {
            return Err(GistError::response_too_large(
                operation,
                Some(status),
                request_id,
            ));
        }
        let header = inspect(&encoded)?;
        if header.workspace != workspace {
            return Err(GistError::workspace_mismatch());
        }

        Ok(GistBundleRecord {
            encoded,
            revision: GistRevision {
                gist_id: gist.clone(),
                header,
                etag: Some(etag),
            },
        })
    }

    /// 以 ETag 为条件发布下一 revision，并以后读的完整候选 bytes 判定结果。
    pub fn compare_and_swap(
        &self,
        credentials: &GistCredentials,
        expected: &GistRevision,
        encoded: &str,
    ) -> Result<GistBundleRecord, GistError> {
        let candidate = inspect(encoded)?;
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
        let expected_etag = expected
            .etag
            .as_deref()
            .ok_or_else(GistError::unconfirmed_revision)?;

        let filename = gist_bundle_filename(candidate.workspace);
        let body = json!({
            "files": { filename: { "content": encoded } },
        });
        let url = self.api_url(&["gists", expected.gist_id.as_str()])?;
        let response = match self
            .api_request(self.client.patch(url), credentials)
            .header(header::IF_MATCH, expected_etag)
            .json(&body)
            .send()
        {
            Ok(response) => response,
            Err(_) => return self.verify_after_patch(credentials, expected, encoded),
        };
        let (status, request_id) = response_context(&response);
        if status.is_success()
            || status == StatusCode::PRECONDITION_FAILED
            || status.is_server_error()
        {
            drop(response);
            return self.verify_after_patch(credentials, expected, encoded);
        }
        let error =
            GistError::status_error("compare_and_swap", status, response.headers(), request_id);
        drop(response);
        Err(error)
    }

    fn verify_after_patch(
        &self,
        credentials: &GistCredentials,
        expected: &GistRevision,
        candidate: &str,
    ) -> Result<GistBundleRecord, GistError> {
        let observed = match self.read_api(
            credentials,
            &expected.gist_id,
            expected.header.workspace,
            "verify",
            false,
        ) {
            Ok(record) => record,
            Err(_) => return Err(GistError::update_outcome_unknown()),
        };
        if observed.encoded.as_bytes() == candidate.as_bytes() {
            Ok(observed)
        } else {
            Err(GistError::cas_conflict(expected, observed.revision()))
        }
    }

    fn sleep_for_rate_limit_retry(&self, delay: Duration) {
        self.sleeper.sleep(delay);
    }

    fn api_url(&self, segments: &[&str]) -> Result<Url, GistError> {
        let mut url = self.api_base.clone();
        let mut path = url
            .path_segments_mut()
            .map_err(|_| GistError::invalid_api_base())?;
        for segment in segments {
            path.push(segment);
        }
        drop(path);
        Ok(url)
    }

    fn api_request(
        &self,
        request: reqwest::blocking::RequestBuilder,
        credentials: &GistCredentials,
    ) -> reqwest::blocking::RequestBuilder {
        request
            .header(header::ACCEPT, GIST_ACCEPT)
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
            .header(header::USER_AGENT, "envsync")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", credentials.token.as_str()),
            )
    }

    fn validate_raw_url(&self, text: &str) -> Result<Url, GistError> {
        let raw_url = Url::parse(text).map_err(|_| GistError::invalid_api_base())?;
        if !raw_url.has_authority()
            || !raw_url.username().is_empty()
            || raw_url.password().is_some()
            || raw_url.query().is_some()
            || raw_url.fragment().is_some()
        {
            return Err(GistError::invalid_api_base());
        }
        let api_origin = self.api_base.origin();
        let github_raw_origin = Url::parse("https://gist.githubusercontent.com/")
            .expect("固定 GitHub raw Gist URL 必须有效")
            .origin();
        let is_public_github_api = self.api_base.as_str() == GITHUB_API_BASE;
        let is_allowed_origin = if is_public_github_api {
            raw_url.origin() == github_raw_origin
        } else {
            raw_url.origin() == api_origin
        };
        if !is_allowed_origin {
            return Err(GistError::invalid_api_base());
        }
        Ok(raw_url)
    }

    fn read_raw(&self, raw_url: &Url) -> Result<String, GistError> {
        let response = self
            .client
            .get(raw_url.clone())
            .send()
            .map_err(|error| GistError::request_error("read_raw", &error))?;
        let (status, request_id) = response_context(&response);
        if !status.is_success() {
            return Err(GistError::status_error(
                "read_raw",
                status,
                response.headers(),
                request_id,
            ));
        }
        let bytes = read_bounded_response(response, "read_raw", status, request_id.clone())?;
        String::from_utf8(bytes)
            .map_err(|_| GistError::invalid_response("read_raw", Some(status), request_id))
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

fn response_context(response: &reqwest::blocking::Response) -> (StatusCode, Option<String>) {
    let request_id = response
        .headers()
        .get("X-GitHub-Request-Id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= MAX_REQUEST_ID_LEN
                && value.bytes().all(|byte| byte.is_ascii_graphic())
        })
        .map(str::to_owned);
    tracing::debug!(github_request_id = ?request_id);
    (response.status(), request_id)
}

fn read_bounded_response(
    response: reqwest::blocking::Response,
    operation: &'static str,
    status: StatusCode,
    request_id: Option<String>,
) -> Result<Vec<u8>, GistError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_LEN as u64)
    {
        return Err(GistError::response_too_large(
            operation,
            Some(status),
            request_id,
        ));
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_LEN as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| GistError::body_error(operation, status, request_id.clone(), &error))?;
    if bytes.len() > MAX_RESPONSE_LEN {
        return Err(GistError::response_too_large(
            operation,
            Some(status),
            request_id,
        ));
    }
    Ok(bytes)
}

fn validated_etag(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= MAX_ETAG_LEN)
        .map(str::to_owned)
}

fn is_rate_limited(headers: &HeaderMap) -> bool {
    headers
        .get("X-RateLimit-Remaining")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .is_some_and(|remaining| remaining == 0)
        || headers.contains_key(header::RETRY_AFTER)
}

fn is_read_rate_limited(status: StatusCode, headers: &HeaderMap) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || is_rate_limited(headers)
}

fn bounded_retry_delay(headers: &HeaderMap) -> Option<Duration> {
    if let Some(value) = headers.get(header::RETRY_AFTER) {
        return parse_retry_after(value.to_str().ok()?);
    }
    let reset_at = headers
        .get("X-RateLimit-Reset")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    bounded_delay(Duration::from_secs(reset_at.saturating_sub(now)))
}

fn parse_retry_after(value: &str) -> Option<Duration> {
    let seconds = value.trim().parse::<u64>().ok()?;
    bounded_delay(Duration::from_secs(seconds))
}

fn bounded_delay(delay: Duration) -> Option<Duration> {
    (delay <= MAX_RETRY_DELAY).then_some(delay)
}

fn validate_api_base(text: &str) -> Result<Url, GistError> {
    let url = Url::parse(text).map_err(|_| GistError::invalid_api_base())?;
    if !url.has_authority()
        || !url.path().starts_with('/')
        || !url.path().ends_with('/')
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
    use reqwest::header::{self, HeaderMap};
    use reqwest::Url;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[derive(Default)]
    struct RecordingSleeper {
        durations: Mutex<Vec<Duration>>,
    }

    impl super::Sleeper for RecordingSleeper {
        fn sleep(&self, duration: Duration) {
            self.durations
                .lock()
                .expect("记录 sleeper duration")
                .push(duration);
        }
    }

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
    fn api_base_requires_trailing_slash_for_path_segments() {
        let https_without_trailing_slash = "https://gist.example.test/api";
        let error = GistBackend::with_api_base(
            https_without_trailing_slash,
            std::time::Duration::from_secs(1),
        )
        .expect_err("HTTPS 路径必须以斜杠结尾");
        assert_eq!(error.code(), "gist.invalid_api_base");
        assert!(!error.to_string().contains(https_without_trailing_slash));
        assert!(!format!("{error:?}").contains(https_without_trailing_slash));

        let loopback_without_trailing_slash = "http://127.0.0.1:8080/api";
        let error = GistBackend::with_api_base(
            loopback_without_trailing_slash,
            std::time::Duration::from_secs(1),
        )
        .expect_err("回环 HTTP 路径必须以斜杠结尾");
        assert_eq!(error.code(), "gist.invalid_api_base");
        assert!(!error.to_string().contains(loopback_without_trailing_slash));
        assert!(!format!("{error:?}").contains(loopback_without_trailing_slash));

        GistBackend::with_api_base(
            "http://127.0.0.1:8080/api/",
            std::time::Duration::from_secs(1),
        )
        .expect("loopback HTTP 仅供测试与本地 mock 使用");
    }

    #[test]
    fn api_base_refuses_unsafe_urls_without_echoing_them() {
        let unsafe_url = "http://token@example.test/private?secret=token#fragment";
        let error = GistBackend::with_api_base(unsafe_url, std::time::Duration::from_secs(1))
            .expect_err("非 loopback HTTP、userinfo、query 与 fragment 均必须拒绝");
        assert_eq!(error.code(), "gist.invalid_api_base");
        assert!(!error.to_string().contains(unsafe_url));
        assert!(!format!("{error:?}").contains(unsafe_url));
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
                etag: Some("etag-must-not-appear".to_owned()),
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
    fn backend_debug_redacts_the_controlled_api_base() {
        let backend = GistBackend {
            api_base: Url::parse("https://gist.example.test/api/").expect("合法 API 基址"),
            client: reqwest::blocking::Client::builder()
                .build()
                .expect("测试客户端"),
            sleeper: Arc::new(super::ThreadSleeper),
        };

        let debug = format!("{backend:?}");
        assert!(debug.contains("GistBackend"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("gist.example.test"));
        assert!(!debug.contains("/api/"));
    }

    #[test]
    fn rate_limit_retry_uses_injected_sleeper() {
        let sleeper = Arc::new(RecordingSleeper::default());
        let backend = GistBackend {
            api_base: Url::parse("https://gist.example.test/api/").expect("合法 API 基址"),
            client: reqwest::blocking::Client::builder()
                .build()
                .expect("测试客户端"),
            sleeper: sleeper.clone(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(header::RETRY_AFTER, header::HeaderValue::from_static("7"));

        let delay = super::bounded_retry_delay(&headers).expect("Retry-After 必须可解析");
        backend.sleep_for_rate_limit_retry(delay);

        assert_eq!(
            sleeper
                .durations
                .lock()
                .expect("读取 sleeper 记录")
                .as_slice(),
            &[Duration::from_secs(7)]
        );
    }

    #[test]
    fn rate_limit_retry_prefers_retry_after_and_rejects_unbounded_delay() {
        let sleeper = Arc::new(RecordingSleeper::default());
        let backend = GistBackend {
            api_base: Url::parse("https://gist.example.test/api/").expect("合法 API 基址"),
            client: reqwest::blocking::Client::builder()
                .build()
                .expect("测试客户端"),
            sleeper: sleeper.clone(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(header::RETRY_AFTER, header::HeaderValue::from_static("7"));
        headers.insert("X-RateLimit-Reset", header::HeaderValue::from_static("0"));

        let delay = super::bounded_retry_delay(&headers).expect("非零 Retry-After 必须可解析");
        backend.sleep_for_rate_limit_retry(delay);

        headers.insert(header::RETRY_AFTER, header::HeaderValue::from_static("61"));
        assert!(
            super::bounded_retry_delay(&headers).is_none(),
            "超过 60 秒的 Retry-After 不得退避重试"
        );
        assert_eq!(
            sleeper
                .durations
                .lock()
                .expect("读取 sleeper 记录")
                .as_slice(),
            &[Duration::from_secs(7)],
            "Retry-After 必须优先于 Reset，且解析出的非零 duration 必须被 fake 记录"
        );
    }

    #[test]
    fn rate_limit_remaining_accepts_only_trimmed_numeric_zero() {
        for value in ["0", "00", " \t0 "] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "X-RateLimit-Remaining",
                header::HeaderValue::from_bytes(value.as_bytes()).expect("合法测试 header"),
            );
            assert!(super::is_rate_limited(&headers), "{value:?} 必须视为零配额");
        }

        for value in ["1", "01", "zero", "0x0", ""] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "X-RateLimit-Remaining",
                header::HeaderValue::from_bytes(value.as_bytes()).expect("合法测试 header"),
            );
            assert!(
                !super::is_rate_limited(&headers),
                "{value:?} 不得视为零配额"
            );
        }
    }

    #[test]
    fn create_rejects_invalid_bundle_before_http_and_redacts_it() {
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
