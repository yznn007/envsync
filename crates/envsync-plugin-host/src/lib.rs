//! EnvSync 插件 Host 的隔离、验签、审批与撤销边界。

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

/// test-only runner 的受控进程与 RPC session。
#[cfg(feature = "test-support")]
pub mod process;
/// 插件制品的 quarantine、信任和生命周期状态机。
pub mod quarantine;

#[cfg(feature = "test-support")]
pub use process::PluginSession;
pub use quarantine::{
    ApprovalGap, HostError, PluginApproval, PluginArtifact, PluginAuditEvent, PluginHost,
    PluginRecord, PluginState, RevocationOutcome, PLUGIN_SIGNATURE_DOMAIN,
};
