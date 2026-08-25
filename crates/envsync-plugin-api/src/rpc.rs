//! 插件进程边界上的版本化 JSON-RPC 协议。
//!
//! 本模块只处理消息形状、协议版本、请求 ID、方法集合和长度前缀帧；它不启动进程、
//! 不读取文件或环境变量，也不解释 `params`、`result` 或 `error.data` 中的权限语义。

use std::io::{Read, Write};

use serde::Serialize;
use serde_json::{Map, Value};

/// 单个 RPC JSON body 可占用的最大字节数。
pub const MAX_RPC_FRAME_BYTES: usize = crate::manifest::MAX_RPC_FRAME_BYTES;

/// 当前支持的 JSON-RPC schema major。
pub const SUPPORTED_SCHEMA_MAJOR: u16 = 1;
/// 当前支持的最小 JSON-RPC schema minor。
pub const MIN_SUPPORTED_SCHEMA_MINOR: u16 = 0;
/// 当前支持的最大 JSON-RPC schema minor。
pub const MAX_SUPPORTED_SCHEMA_MINOR: u16 = 1;

/// JSON-RPC envelope 中的 schema version。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SchemaVersion {
    /// 协议 major；不兼容变更必须提升此字段。
    pub major: u16,
    /// 协议 minor；兼容扩展必须提升此字段。
    pub minor: u16,
}

impl SchemaVersion {
    /// 构造一个 schema version；是否受支持由 [`SchemaVersion::validate_supported`] 判断。
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// 确认版本属于当前 Host 支持的封闭集合。
    pub fn validate_supported(self) -> Result<Self, PluginRpcError> {
        if self.major == SUPPORTED_SCHEMA_MAJOR
            && (MIN_SUPPORTED_SCHEMA_MINOR..=MAX_SUPPORTED_SCHEMA_MINOR).contains(&self.minor)
        {
            Ok(self)
        } else {
            Err(PluginRpcError::UnsupportedVersion)
        }
    }
}

/// 已校验的 JSON-RPC request ID。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RequestId(String);

impl RequestId {
    /// 解析 1..=64 字节、仅含 ASCII 字母数字、`-` 与 `_` 的 request ID。
    pub fn parse(value: &str) -> Result<Self, PluginRpcError> {
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(PluginRpcError::InvalidRequest);
        }

        Ok(Self(value.to_owned()))
    }

    /// 返回已校验的 ID 文本。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for RequestId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// 插件协议支持的封闭 request method 集合。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginMethod {
    /// 生命周期初始化请求。
    Initialize,
    /// 描述插件能力与展示信息。
    Describe,
    /// 观察外部状态的请求。
    Observe,
    /// 渲染已验证数据的请求。
    Render,
    /// 提出命令计划的请求。
    PlanCommand,
    /// 验证状态或计划结果的请求。
    Verify,
    /// 生命周期关闭请求。
    Shutdown,
}

impl PluginMethod {
    /// 从 wire-format method 字符串解析封闭枚举。
    pub fn parse(value: &str) -> Result<Self, PluginRpcError> {
        match value {
            "initialize" => Ok(Self::Initialize),
            "describe" => Ok(Self::Describe),
            "observe" => Ok(Self::Observe),
            "render" => Ok(Self::Render),
            "plan-command" => Ok(Self::PlanCommand),
            "verify" => Ok(Self::Verify),
            "shutdown" => Ok(Self::Shutdown),
            _ => Err(PluginRpcError::UnknownMethod),
        }
    }

    /// 返回 wire-format method 字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initialize => "initialize",
            Self::Describe => "describe",
            Self::Observe => "observe",
            Self::Render => "render",
            Self::PlanCommand => "plan-command",
            Self::Verify => "verify",
            Self::Shutdown => "shutdown",
        }
    }
}

/// 已校验 envelope 的 JSON-RPC request。
#[derive(Debug, Clone, PartialEq)]
pub struct RpcRequest {
    schema_version: SchemaVersion,
    id: RequestId,
    method: PluginMethod,
    params: Value,
}

impl RpcRequest {
    /// 从已校验 ID、封闭 method 和未解释的 params 构造 request。
    pub fn new(
        schema_version: SchemaVersion,
        id: RequestId,
        method: PluginMethod,
        params: Value,
    ) -> Result<Self, PluginRpcError> {
        schema_version.validate_supported()?;
        Ok(Self {
            schema_version,
            id,
            method,
            params,
        })
    }

    /// 返回 request 的 schema version。
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// 返回已校验的 request ID。
    pub const fn id(&self) -> &RequestId {
        &self.id
    }

    /// 返回封闭协议 method。
    pub const fn method(&self) -> PluginMethod {
        self.method
    }

    /// 返回未解释的 params JSON。
    pub const fn params(&self) -> &Value {
        &self.params
    }
}

/// 已校验 envelope 的 JSON-RPC response。
#[derive(Debug, Clone, PartialEq)]
pub struct RpcResponse {
    schema_version: SchemaVersion,
    id: RequestId,
    result: Result<Value, RpcErrorObject>,
}

impl RpcResponse {
    /// 构造成功 response；`result` 保持未解释 JSON。
    pub fn success(
        schema_version: SchemaVersion,
        id: RequestId,
        result: Value,
    ) -> Result<Self, PluginRpcError> {
        schema_version.validate_supported()?;
        Ok(Self {
            schema_version,
            id,
            result: Ok(result),
        })
    }

    /// 构造错误 response；`error` 是将发送给对端的 RPC payload，不是本 crate 的解析错误。
    pub fn error(
        schema_version: SchemaVersion,
        id: RequestId,
        error: RpcErrorObject,
    ) -> Result<Self, PluginRpcError> {
        schema_version.validate_supported()?;
        Ok(Self {
            schema_version,
            id,
            result: Err(error),
        })
    }

    /// 返回 response 的 schema version。
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// 返回已校验的 request ID。
    pub const fn id(&self) -> &RequestId {
        &self.id
    }

    /// 返回 response 的 success result 或 error object。
    pub fn result(&self) -> Result<&Value, &RpcErrorObject> {
        self.result.as_ref()
    }
}

/// 已校验 envelope 的 JSON-RPC message。
#[derive(Debug, Clone, PartialEq)]
pub enum RpcMessage {
    /// 带 method 与 params 的 request。
    Request(RpcRequest),
    /// 带 result 或 error 的 response。
    Response(RpcResponse),
}

impl RpcMessage {
    /// 构造 request message。
    pub fn new_request(
        schema_version: SchemaVersion,
        id: RequestId,
        method: PluginMethod,
        params: Value,
    ) -> Result<Self, PluginRpcError> {
        Ok(Self::Request(RpcRequest::new(
            schema_version,
            id,
            method,
            params,
        )?))
    }

    /// 构造 success response message。
    pub fn new_success_response(
        schema_version: SchemaVersion,
        id: RequestId,
        result: Value,
    ) -> Result<Self, PluginRpcError> {
        Ok(Self::Response(RpcResponse::success(
            schema_version,
            id,
            result,
        )?))
    }

    /// 构造 error response message。
    pub fn new_error_response(
        schema_version: SchemaVersion,
        id: RequestId,
        error: RpcErrorObject,
    ) -> Result<Self, PluginRpcError> {
        Ok(Self::Response(RpcResponse::error(
            schema_version,
            id,
            error,
        )?))
    }

    /// 从 UTF-8 JSON payload 解析 RPC message。
    pub fn from_json_slice(json: &[u8]) -> Result<Self, PluginRpcError> {
        if json.len() > MAX_RPC_FRAME_BYTES {
            return Err(PluginRpcError::FrameTooLarge);
        }

        let json = std::str::from_utf8(json).map_err(|_| PluginRpcError::InvalidUtf8)?;
        let value = serde_json::from_str(json).map_err(|_| PluginRpcError::InvalidJson)?;
        Self::from_json_value(value)
    }

    /// 从 JSON value 解析 RPC message。
    pub fn from_json_value(value: Value) -> Result<Self, PluginRpcError> {
        let object = match value {
            Value::Object(object) => object,
            Value::Array(_) => return Err(PluginRpcError::InvalidRequest),
            _ => return Err(PluginRpcError::InvalidRequest),
        };

        parse_message_object(object)
    }

    /// 返回 message 的 schema version。
    pub const fn schema_version(&self) -> SchemaVersion {
        match self {
            Self::Request(request) => request.schema_version(),
            Self::Response(response) => response.schema_version(),
        }
    }

    /// 若 message 是 request，则返回 request。
    pub const fn request(&self) -> Option<&RpcRequest> {
        match self {
            Self::Request(request) => Some(request),
            Self::Response(_) => None,
        }
    }

    /// 若 message 是 response，则返回 response。
    pub const fn response(&self) -> Option<&RpcResponse> {
        match self {
            Self::Request(_) => None,
            Self::Response(response) => Some(response),
        }
    }

    fn to_json_vec(&self) -> Result<Vec<u8>, PluginRpcError> {
        match self {
            Self::Request(request) => serde_json::to_vec(&WireRequest {
                jsonrpc: "2.0",
                schema_version: request.schema_version,
                id: &request.id,
                method: request.method.as_str(),
                params: &request.params,
            }),
            Self::Response(response) => match &response.result {
                Ok(result) => serde_json::to_vec(&WireSuccessResponse {
                    jsonrpc: "2.0",
                    schema_version: response.schema_version,
                    id: &response.id,
                    result,
                }),
                Err(error) => serde_json::to_vec(&WireErrorResponse {
                    jsonrpc: "2.0",
                    schema_version: response.schema_version,
                    id: &response.id,
                    error,
                }),
            },
        }
        .map_err(|_| PluginRpcError::InvalidJson)
    }
}

/// JSON-RPC error object。
///
/// 该对象可能来自不可信插件响应，`code`、`message` 与 `data` 都是协议 payload。调用方
/// 若要记录或展示这些字段，必须按自己的信任边界做脱敏；本 crate 的 [`PluginRpcError`]
/// 则只表示本地解析/帧错误，永不携带这些未可信字段。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RpcErrorObject {
    /// 稳定机器错误码。
    pub code: String,
    /// 面向调用方的简短错误说明。
    pub message: String,
    /// 可选的结构化错误数据；本 crate 不解释其语义。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcErrorObject {
    /// 构造将作为 JSON-RPC payload 传输的 error object。
    pub fn new(code: impl Into<String>, message: impl Into<String>, data: Option<Value>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            data,
        }
    }
}

/// RPC 协议解析、校验或 frame I/O 失败的稳定错误分类。
///
/// 所有变体均不携带原始 payload、路径或底层 I/O 文本，因而 `Display` 与 `Debug` 不会回显
/// 未可信输入。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PluginRpcError {
    /// frame payload 宣称长度或序列化后长度超过协议上限。
    #[error("RPC frame 超出最大长度")]
    FrameTooLarge,
    /// frame 前缀或 payload 在读满前结束。
    #[error("RPC frame 不完整")]
    TruncatedFrame,
    /// frame 长度前缀与实际 slice 长度不一致。
    #[error("RPC frame 长度不匹配")]
    LengthMismatch,
    /// payload 不是合法 UTF-8。
    #[error("RPC payload 不是合法 UTF-8")]
    InvalidUtf8,
    /// payload 不是合法 JSON。
    #[error("RPC payload 不是合法 JSON")]
    InvalidJson,
    /// request envelope 或 request ID 形状无效。
    #[error("RPC request 格式无效")]
    InvalidRequest,
    /// schema version 不属于当前支持集合。
    #[error("RPC schema version 不受支持")]
    UnsupportedVersion,
    /// request method 不属于协议封闭集合。
    #[error("RPC method 不受支持")]
    UnknownMethod,
    /// response envelope、result/error 或 error object 形状无效。
    #[error("RPC response 格式无效")]
    InvalidResponse,
    /// 非 EOF 的底层 I/O 失败。
    #[error("RPC I/O 失败")]
    Io,
}

impl PluginRpcError {
    /// 返回可供跨版本调用方依赖的稳定机器错误码。
    pub const fn code(self) -> &'static str {
        match self {
            Self::FrameTooLarge => "plugin.rpc.frame_too_large",
            Self::TruncatedFrame => "plugin.rpc.truncated_frame",
            Self::LengthMismatch => "plugin.rpc.length_mismatch",
            Self::InvalidUtf8 => "plugin.rpc.invalid_utf8",
            Self::InvalidJson => "plugin.rpc.invalid_json",
            Self::InvalidRequest => "plugin.rpc.invalid_request",
            Self::UnsupportedVersion => "plugin.rpc.unsupported_version",
            Self::UnknownMethod => "plugin.rpc.unknown_method",
            Self::InvalidResponse => "plugin.rpc.invalid_response",
            Self::Io => "plugin.rpc.io_error",
        }
    }
}

/// 将 RPC message 编码为 4 字节大端长度前缀加 JSON payload 的 frame。
pub fn encode_frame(message: &RpcMessage) -> Result<Vec<u8>, PluginRpcError> {
    let payload = message.to_json_vec()?;
    if payload.len() > MAX_RPC_FRAME_BYTES {
        return Err(PluginRpcError::FrameTooLarge);
    }

    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// 从完整 frame slice 解码 RPC message，并拒绝任何尾随 bytes。
pub fn decode_frame(frame: &[u8]) -> Result<RpcMessage, PluginRpcError> {
    let prefix = frame.get(..4).ok_or(PluginRpcError::TruncatedFrame)?;
    let declared_len = u32::from_be_bytes(
        prefix
            .try_into()
            .map_err(|_| PluginRpcError::TruncatedFrame)?,
    ) as usize;

    if declared_len > MAX_RPC_FRAME_BYTES {
        return Err(PluginRpcError::FrameTooLarge);
    }

    let expected_len = 4 + declared_len;
    match frame.len().cmp(&expected_len) {
        std::cmp::Ordering::Less => Err(PluginRpcError::TruncatedFrame),
        std::cmp::Ordering::Greater => Err(PluginRpcError::LengthMismatch),
        std::cmp::Ordering::Equal => RpcMessage::from_json_slice(&frame[4..]),
    }
}

/// 从 reader 读取一个完整 frame，并在分配 payload 前拒绝超长声明。
pub fn read_frame<R: Read>(reader: &mut R) -> Result<RpcMessage, PluginRpcError> {
    read_frame_with_limit(reader, MAX_RPC_FRAME_BYTES)
}

/// 从 reader 读取一个完整 frame，并在分配 payload 前同时执行协议与调用方上限。
///
/// max_payload_bytes 只能进一步收紧 MAX_RPC_FRAME_BYTES，适合 Host 将每个会话的资源配额
/// 传入协议层，避免插件用长度前缀触发超过 Host 预算的分配。
pub fn read_frame_with_limit<R: Read>(
    reader: &mut R,
    max_payload_bytes: usize,
) -> Result<RpcMessage, PluginRpcError> {
    read_frame_with_limit_and_reservation(reader, max_payload_bytes, |_| true)
}

/// 从 reader 读取一个完整 frame，并在分配 payload 前预留整个 frame 的外部资源预算。
///
/// `reserve_frame_bytes` 接收包含 4 字节长度前缀在内的完整 frame 大小。它必须原子地
/// 预留该预算；返回 `false` 时，函数会在分配或读取 payload 前以
/// [`PluginRpcError::FrameTooLarge`] 失败。适合多个 I/O 管道共享单个输出配额的 Host。
pub fn read_frame_with_limit_and_reservation<R: Read>(
    reader: &mut R,
    max_payload_bytes: usize,
    reserve_frame_bytes: impl FnOnce(usize) -> bool,
) -> Result<RpcMessage, PluginRpcError> {
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix).map_err(map_read_error)?;

    let declared_len = u32::from_be_bytes(prefix) as usize;
    if declared_len > max_payload_bytes.min(MAX_RPC_FRAME_BYTES) {
        return Err(PluginRpcError::FrameTooLarge);
    }
    let frame_bytes = declared_len
        .checked_add(prefix.len())
        .ok_or(PluginRpcError::FrameTooLarge)?;
    if !reserve_frame_bytes(frame_bytes) {
        return Err(PluginRpcError::FrameTooLarge);
    }

    let mut payload = vec![0_u8; declared_len];
    reader.read_exact(&mut payload).map_err(map_read_error)?;
    RpcMessage::from_json_slice(&payload)
}

/// 向 writer 写入一个完整 frame。
pub fn write_frame<W: Write>(writer: &mut W, message: &RpcMessage) -> Result<(), PluginRpcError> {
    let frame = encode_frame(message)?;
    writer.write_all(&frame).map_err(|_| PluginRpcError::Io)
}

/// 在 Host 已按 request ID 关联 initialize response 后解析所选 schema version。
pub fn parse_initialize_result(result: &Value) -> Result<SchemaVersion, PluginRpcError> {
    let object = result.as_object().ok_or(PluginRpcError::InvalidResponse)?;
    let version = object
        .get("selected_schema_version")
        .ok_or(PluginRpcError::InvalidResponse)?;
    parse_schema_version(version, PluginRpcError::InvalidResponse)
}

#[derive(Serialize)]
struct WireRequest<'a> {
    jsonrpc: &'static str,
    schema_version: SchemaVersion,
    id: &'a RequestId,
    method: &'static str,
    params: &'a Value,
}

#[derive(Serialize)]
struct WireSuccessResponse<'a> {
    jsonrpc: &'static str,
    schema_version: SchemaVersion,
    id: &'a RequestId,
    result: &'a Value,
}

#[derive(Serialize)]
struct WireErrorResponse<'a> {
    jsonrpc: &'static str,
    schema_version: SchemaVersion,
    id: &'a RequestId,
    error: &'a RpcErrorObject,
}

fn parse_message_object(mut object: Map<String, Value>) -> Result<RpcMessage, PluginRpcError> {
    let has_method = object.contains_key("method");
    let has_params = object.contains_key("params");
    let has_result = object.contains_key("result");
    let has_error = object.contains_key("error");

    if has_method {
        if has_result || has_error || !has_params {
            return Err(PluginRpcError::InvalidRequest);
        }
        parse_request(object)
    } else {
        if has_params {
            return Err(PluginRpcError::InvalidResponse);
        }
        if has_result == has_error {
            return Err(PluginRpcError::InvalidResponse);
        }
        parse_response(&mut object)
    }
}

fn parse_request(mut object: Map<String, Value>) -> Result<RpcMessage, PluginRpcError> {
    let schema_version = parse_envelope_schema_version(&object, PluginRpcError::InvalidRequest)?;
    let id = parse_envelope_id(&object, PluginRpcError::InvalidRequest)?;
    let method = parse_method(&object)?;
    let params = object
        .remove("params")
        .ok_or(PluginRpcError::InvalidRequest)?;

    Ok(RpcMessage::Request(RpcRequest {
        schema_version,
        id,
        method,
        params,
    }))
}

fn parse_response(object: &mut Map<String, Value>) -> Result<RpcMessage, PluginRpcError> {
    let schema_version = parse_envelope_schema_version(object, PluginRpcError::InvalidResponse)?;
    let id = parse_envelope_id(object, PluginRpcError::InvalidResponse)?;
    let result = if let Some(result) = object.remove("result") {
        Ok(result)
    } else {
        let error = object
            .remove("error")
            .ok_or(PluginRpcError::InvalidResponse)?;
        Err(parse_error_object(error)?)
    };

    Ok(RpcMessage::Response(RpcResponse {
        schema_version,
        id,
        result,
    }))
}

fn parse_envelope_schema_version(
    object: &Map<String, Value>,
    shape_error: PluginRpcError,
) -> Result<SchemaVersion, PluginRpcError> {
    parse_jsonrpc(object, shape_error)?;
    let version = object.get("schema_version").ok_or(shape_error)?;
    parse_schema_version(version, shape_error)
}

fn parse_jsonrpc(
    object: &Map<String, Value>,
    shape_error: PluginRpcError,
) -> Result<(), PluginRpcError> {
    match object.get("jsonrpc").and_then(Value::as_str) {
        Some("2.0") => Ok(()),
        _ => Err(shape_error),
    }
}

fn parse_envelope_id(
    object: &Map<String, Value>,
    shape_error: PluginRpcError,
) -> Result<RequestId, PluginRpcError> {
    match object.get("id").and_then(Value::as_str) {
        Some(id) => RequestId::parse(id).map_err(|_| shape_error),
        None => Err(shape_error),
    }
}

fn parse_method(object: &Map<String, Value>) -> Result<PluginMethod, PluginRpcError> {
    match object.get("method").and_then(Value::as_str) {
        Some(method) => PluginMethod::parse(method),
        None => Err(PluginRpcError::InvalidRequest),
    }
}

fn parse_schema_version(
    value: &Value,
    shape_error: PluginRpcError,
) -> Result<SchemaVersion, PluginRpcError> {
    let object = value.as_object().ok_or(shape_error)?;
    let major = parse_u16_field(object, "major", shape_error)?;
    let minor = parse_u16_field(object, "minor", shape_error)?;
    SchemaVersion::new(major, minor).validate_supported()
}

fn parse_u16_field(
    object: &Map<String, Value>,
    field: &str,
    shape_error: PluginRpcError,
) -> Result<u16, PluginRpcError> {
    let value = object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(shape_error)?;
    u16::try_from(value).map_err(|_| shape_error)
}

fn parse_error_object(value: Value) -> Result<RpcErrorObject, PluginRpcError> {
    let mut object = match value {
        Value::Object(object) => object,
        _ => return Err(PluginRpcError::InvalidResponse),
    };
    let code = remove_string(&mut object, "code")?;
    let message = remove_string(&mut object, "message")?;
    let data = object.remove("data");

    Ok(RpcErrorObject {
        code,
        message,
        data,
    })
}

fn remove_string(object: &mut Map<String, Value>, field: &str) -> Result<String, PluginRpcError> {
    match object.remove(field) {
        Some(Value::String(value)) => Ok(value),
        _ => Err(PluginRpcError::InvalidResponse),
    }
}

fn map_read_error(error: std::io::Error) -> PluginRpcError {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        PluginRpcError::TruncatedFrame
    } else {
        PluginRpcError::Io
    }
}
