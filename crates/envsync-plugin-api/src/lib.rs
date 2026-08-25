//! # envsync-plugin-api
//!
//! EnvSync 插件 manifest 的纯数据契约。它校验不可信 JSON 的结构与边界，但不执行
//! I/O、信任决策或密码学验签。

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

/// 严格校验插件 manifest 的纯数据模型。
pub mod manifest;
/// 版本化 JSON-RPC frame 与消息模型。
pub mod rpc;

pub use manifest::{
    PluginArtifactDigest, PluginCapability, PluginCatalog, PluginEntrypoint, PluginId,
    PluginManifest, PluginManifestError, PluginSignature, PluginTarget, Publisher, ResourceLimits,
    SignatureAlgorithm, HOST_PLUGIN_API_VERSIONS,
};
pub use rpc::{
    decode_frame, encode_frame, parse_initialize_result, read_frame, read_frame_with_limit,
    read_frame_with_limit_and_reservation, write_frame, PluginMethod, PluginRpcError, RequestId,
    RpcErrorObject, RpcMessage, RpcRequest, RpcResponse, SchemaVersion, MAX_RPC_FRAME_BYTES,
    MAX_SUPPORTED_SCHEMA_MINOR, MIN_SUPPORTED_SCHEMA_MINOR, SUPPORTED_SCHEMA_MAJOR,
};
