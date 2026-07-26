#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

//! # envsync-core
//!
//! EnvSync 的核心编排层：把领域模型、后端、平台能力和本地存储组装成一条可审计、
//! 可回滚的同步事务。
//!
//! ## 模块地图
//!
//! | 模块 | 职责 |
//! |---|---|
//! | [`config`] | 工作区配置 schema、解析与校验 |
//! | [`render`] | Full File / Managed Block 纯函数渲染 |
//! | [`planner`] | 由配置 + 目标状态 + 观察结果生成不可变计划 |
//! | [`apply`] | 事务化应用引擎（preflight → publish → apply → verify → journal） |
//! | [`recovery`] | 崩溃恢复与显式回滚 |
//! | [`service`] | CLI 与桌面端共用的应用服务门面 |
//! | [`ports`] | 时钟、观察、文件变更三个端口抽象及其平台实现 |
//! | [`error`] | 带稳定错误码的统一错误类型 |
//!
//! ## 分层原则
//!
//! **所有依赖当前文件内容的判断都发生在计划阶段**，并被 `expected_before` 摘要绑定；
//! 应用阶段只做「把这些字节写到那个位置」。这条分工让「计划生成后文件被外部修改」
//! 这一竞态可以被摘要比对完整捕获，而不需要在写入路径上再放一份业务逻辑。

pub mod apply;
pub mod config;
pub mod error;
pub mod planner;
pub mod ports;
pub mod recovery;
pub mod render;
pub mod service;

pub use apply::{ApplyEngine, ApplyOutcome};
pub use config::{BackendConfig, ConfigError, DeviceConfig, ResourceConfig, WorkspaceConfig};
pub use error::{CoreError, CoreResult};
pub use planner::{build_plan, BlobSource, PlanOutcome, PlanRequest};
pub use ports::{ActionReceipt, Clock, FileMutator, FixedClock, Observer, SystemClock};
pub use recovery::{
    PlanSource, RecoveryDiagnosis, RecoveryEngine, RecoveryReport, RecoverySuggestion,
};
pub use render::{render, RenderError, RenderInput, RenderedChange};
pub use service::{
    CaptureOutcome, DoctorFinding, DoctorReport, EnvSyncService, ResourceStatus, StatusReport,
    WorkspaceState,
};
