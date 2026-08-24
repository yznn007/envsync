//! # envsync-plugin-api
//!
//! EnvSync 插件 manifest 的纯数据契约。它校验不可信 JSON 的结构与边界，但不执行
//! I/O、信任决策或密码学验签。

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

/// 严格校验插件 manifest 的纯数据模型。
pub mod manifest;

pub use manifest::{
    PluginCapability, PluginCatalog, PluginEntrypoint, PluginId, PluginManifest,
    PluginManifestError, PluginSignature, PluginTarget, Publisher, ResourceLimits,
    SignatureAlgorithm, HOST_PLUGIN_API_VERSIONS,
};
