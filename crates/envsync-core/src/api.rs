//! 桌面与其他宿主共用的版本化应用服务响应信封。
//!
//! 这里的泛型被 [`ViewData`] 密封：调用方只能把本 crate 定义的脱敏 View 放进响应，
//! 不能意外把领域对象、文件内容或秘密原样序列化到界面层。

use envsync_domain::OperationId;
use serde::{Deserialize, Deserializer, Serialize};

use crate::view::ViewDiagnostic;

/// 应用服务 JSON 契约的当前版本。
pub const APPLICATION_SERVICE_SCHEMA_VERSION: u32 = 1;

/// 一次应用服务调用的相关标识。
///
/// 标识由宿主生成并回显给调用方，用于把界面错误、事件和诊断关联到同一次请求；它不承载
/// 用户路径、资源内容或秘密。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ApiRequestId(String);

impl ApiRequestId {
    /// 解析一个宿主提供的请求标识。
    ///
    /// 只接受 1 到 128 个 ASCII 字母、数字、连字符、下划线或点，避免把任意文本带入
    /// API 回显路径。
    pub fn parse(value: impl Into<String>) -> Result<Self, ApiRequestIdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ApiRequestIdError::Empty);
        }
        if value.len() > 128 {
            return Err(ApiRequestIdError::TooLong);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(ApiRequestIdError::InvalidCharacter);
        }
        Ok(ApiRequestId(value))
    }

    /// 取得请求标识的稳定文本。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ApiRequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        ApiRequestId::parse(value).map_err(serde::de::Error::custom)
    }
}

/// 请求标识不符合 API 契约时的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApiRequestIdError {
    /// 标识为空。
    #[error("请求标识不能为空")]
    Empty,
    /// 标识超过长度上限。
    #[error("请求标识超过 128 个字节")]
    TooLong,
    /// 标识包含未允许的字符。
    #[error("请求标识包含未允许的字符")]
    InvalidCharacter,
}

/// 请求信封中的 schema 版本不受当前 application service 支持。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApiSchemaVersionError {
    /// 收到的版本不是当前稳定版本。
    #[error("不支持的 application service schema 版本 {received}")]
    Unsupported {
        /// 调用方发送的版本号。
        received: u32,
    },
}

/// 应用服务调用的终态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiStatus {
    /// 调用成功，`data` 有值。
    Ok,
    /// 调用失败，`data` 为 `null`，`diagnostics` 至少包含一条稳定错误码。
    Error,
}

/// 构造错误响应时违反统一信封不变量的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApiResponseError {
    /// 失败响应缺少稳定机器可读的诊断。
    #[error("错误响应至少需要一条诊断")]
    MissingDiagnostic,
}

/// 可被放入 [`ApiResponse`] 的脱敏视图。
///
/// 这是密封 trait，保证响应数据只能来自本 crate 审核过的 View 类型。
pub trait ViewData: private::Sealed + Serialize {}

pub(crate) mod private {
    /// 密封 [`super::ViewData`] 的内部标记。
    pub trait Sealed {}
}

/// 版本化应用服务请求。
///
/// 请求负载由具体 command 定义；其版本与请求标识始终位于统一信封中，避免宿主根据
/// 隐式字段猜测协议版本。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiRequest<T: Serialize> {
    schema_version: u32,
    request_id: ApiRequestId,
    data: T,
}

impl<T: Serialize> ApiRequest<T> {
    /// 以当前 schema 版本创建请求。
    pub fn new(request_id: ApiRequestId, data: T) -> Self {
        ApiRequest {
            schema_version: APPLICATION_SERVICE_SCHEMA_VERSION,
            request_id,
            data,
        }
    }

    /// 返回请求所使用的 schema 版本。
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// 返回关联请求标识。
    pub fn request_id(&self) -> &ApiRequestId {
        &self.request_id
    }

    /// 返回命令负载。
    pub fn data(&self) -> &T {
        &self.data
    }

    /// 验证调用方使用的是当前稳定 schema。
    ///
    /// 该检查与反序列化分离，使命令层仍能回显已验证的请求标识和返回脱敏错误信封。
    pub fn validate_schema(&self) -> Result<(), ApiSchemaVersionError> {
        if self.schema_version == APPLICATION_SERVICE_SCHEMA_VERSION {
            Ok(())
        } else {
            Err(ApiSchemaVersionError::Unsupported {
                received: self.schema_version,
            })
        }
    }
}

/// `operation.cancel` 命令的受限负载。
///
/// 取消只引用已经分配给受控 worker 的操作标识；它不接受路径、命令行或任意内容。实际
/// 取消语义由应用服务在 journal 安全边界内判断，不能由 UI 直接终止文件事务。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelOperationRequest {
    operation_id: OperationId,
}

impl CancelOperationRequest {
    /// 为已登记的操作创建取消请求。
    pub const fn new(operation_id: OperationId) -> Self {
        CancelOperationRequest { operation_id }
    }

    /// 返回待取消的操作标识。
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }
}

/// 版本化、可脱敏的应用服务响应。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiResponse<T: ViewData> {
    schema_version: u32,
    request_id: ApiRequestId,
    status: ApiStatus,
    data: Option<T>,
    diagnostics: Vec<ViewDiagnostic>,
}

impl<T: ViewData> ApiResponse<T> {
    /// 创建成功响应。
    pub fn ok(request_id: ApiRequestId, data: T, diagnostics: Vec<ViewDiagnostic>) -> Self {
        ApiResponse {
            schema_version: APPLICATION_SERVICE_SCHEMA_VERSION,
            request_id,
            status: ApiStatus::Ok,
            data: Some(data),
            diagnostics,
        }
    }

    /// 创建失败响应。
    ///
    /// 错误响应不会携带数据，并且至少需要一条稳定诊断码；宿主可据此显示本地化说明
    /// 并关联 request ID，而无需接收原始错误文本。
    pub fn error(
        request_id: ApiRequestId,
        diagnostics: Vec<ViewDiagnostic>,
    ) -> Result<Self, ApiResponseError> {
        if diagnostics.is_empty() {
            return Err(ApiResponseError::MissingDiagnostic);
        }
        Ok(ApiResponse {
            schema_version: APPLICATION_SERVICE_SCHEMA_VERSION,
            request_id,
            status: ApiStatus::Error,
            data: None,
            diagnostics,
        })
    }

    /// 返回响应所遵循的 schema 版本。
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// 返回关联请求标识。
    pub fn request_id(&self) -> &ApiRequestId {
        &self.request_id
    }

    /// 返回调用终态。
    pub const fn status(&self) -> ApiStatus {
        self.status
    }

    /// 返回成功数据；失败响应始终返回 `None`。
    pub fn data(&self) -> Option<&T> {
        self.data.as_ref()
    }

    /// 返回脱敏诊断。
    pub fn diagnostics(&self) -> &[ViewDiagnostic] {
        &self.diagnostics
    }
}

/// 一条版本化的应用服务事件。
///
/// 长操作以此信封推送状态更新。`sequence` 只在同一 `request_id` 内单调递增，消费者可用
/// 它去重并在事件间出现空洞时重新查询 [`ApiResponse`]。操作更新的 `data` 必须使用审核
/// 过的 View（例如 [`crate::view::ApplyView`] 或 [`crate::view::OperationView`]），从而不
/// 泄露 journal 错误正文、文件内容或秘密。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiEvent<T: ViewData> {
    schema_version: u32,
    request_id: ApiRequestId,
    sequence: u64,
    status: ApiStatus,
    data: Option<T>,
    diagnostics: Vec<ViewDiagnostic>,
}

impl<T: ViewData> ApiEvent<T> {
    /// 创建成功事件。
    pub fn ok(
        request_id: ApiRequestId,
        sequence: u64,
        data: T,
        diagnostics: Vec<ViewDiagnostic>,
    ) -> Self {
        ApiEvent {
            schema_version: APPLICATION_SERVICE_SCHEMA_VERSION,
            request_id,
            sequence,
            status: ApiStatus::Ok,
            data: Some(data),
            diagnostics,
        }
    }

    /// 创建失败事件；失败事件必须保留至少一条稳定诊断码。
    pub fn error(
        request_id: ApiRequestId,
        sequence: u64,
        diagnostics: Vec<ViewDiagnostic>,
    ) -> Result<Self, ApiResponseError> {
        if diagnostics.is_empty() {
            return Err(ApiResponseError::MissingDiagnostic);
        }
        Ok(ApiEvent {
            schema_version: APPLICATION_SERVICE_SCHEMA_VERSION,
            request_id,
            sequence,
            status: ApiStatus::Error,
            data: None,
            diagnostics,
        })
    }

    /// 返回事件所遵循的 schema 版本。
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// 返回关联请求标识。
    pub fn request_id(&self) -> &ApiRequestId {
        &self.request_id
    }

    /// 返回同一请求内的单调事件序号。
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// 返回事件终态。
    pub const fn status(&self) -> ApiStatus {
        self.status
    }

    /// 返回事件数据；失败事件始终返回 `None`。
    pub fn data(&self) -> Option<&T> {
        self.data.as_ref()
    }

    /// 返回脱敏诊断。
    pub fn diagnostics(&self) -> &[ViewDiagnostic] {
        &self.diagnostics
    }
}
