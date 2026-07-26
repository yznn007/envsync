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
//! | [`render`] | Full File / Managed Block / Structured Merge 的纯函数渲染 |
//! | [`planner`] | 由配置 + 目标状态 + 观察结果生成不可变计划 |
//! | [`apply`] | 事务化应用引擎（preflight → publish → apply → verify → journal） |
//! | [`membership`] | 设备成员签名链的纯函数验证器与编排 API（M2） |
//! | [`checkpoint`] | 反回滚检查点：单调性判定与信任根（M2） |
//! | [`vault`] | Vault application service：端到端加密的秘密存取（M2） |
//! | [`device_admin`] | 设备身份、邀请、加入、清单与工作区恢复（M2） |
//! | [`rotation`] | 撤销设备后的可恢复密钥轮换编排（M2） |
//! | [`mod@merge`] | 文本与结构化三方合并，只产出干净结果或显式 Conflict |
//! | [`projection`] | Workspace 到 DeviceView 的纯函数投影 |
//! | [`sync`] | fetch、合并基、三方合并与冲突裁决的编排 |
//! | [`recovery`] | 崩溃恢复与显式回滚 |
//! | [`last_known`] | 「上次成功读到的后端 Ref」的本地留存，供后端不可达时降级作答 |
//! | [`offline`] | 后端联系不上时的占位实现：服务照常打开，只有真正需要远端的调用才失败 |
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
pub mod checkpoint;
pub mod config;
pub mod device_admin;
pub mod error;
pub mod last_known;
pub mod membership;
pub mod merge;
pub mod offline;
pub mod planner;
pub mod ports;
pub mod projection;
pub mod recovery;
pub mod render;
pub mod rotation;
pub mod service;
pub mod sync;
pub mod vault;

pub use apply::{ApplyEngine, ApplyOutcome};
pub use checkpoint::{
    advance as advance_checkpoint, check_advance, Checkpoint, CheckpointError, CheckpointStore,
    InMemoryCheckpointStore, SecureCheckpointStore, SqliteCheckpointStore,
};
pub use config::{
    BackendConfig, ConfigError, DeviceConfig, DeviceProfileConfig, ResourceConfig,
    ResourceOverride, WorkspaceConfig,
};
pub use device_admin::{
    create_recovery, forget_device, init_device, invite, join, list_devices, load_device,
    restore_recovery, DeviceInvitation, DeviceSummary, RecoveryOutcome, INVITATION_DEFAULT_TTL_MS,
    INVITATION_SIGNATURE_DOMAIN,
};
pub use error::{CoreError, CoreResult};
pub use last_known::{
    is_backend_error_unreachable, is_backend_unreachable, LastKnownRef, LastKnownRefStore,
    LAST_KNOWN_REF_FILE,
};
pub use membership::{
    append as append_membership_event, create_genesis, membership_object_id, public_bytes,
    verify_membership_chain, MembershipError, VerifiedHead, MEMBERSHIP_SIGNATURE_DOMAIN,
};
pub use merge::{
    merge, merge_structured, merge_structured_with, merge_text, IniPolicy, MergeError, MergeInput,
    MergeOptions, MergeProvenance, MergeResult, MultiValuePolicy, MAX_INPUT_BYTES, MAX_NODES,
    MAX_PARSE_DEPTH,
};
pub use offline::UnreachableBackend;
pub use planner::{build_plan, BlobSource, PlanOutcome, PlanRequest};
pub use ports::{ActionReceipt, Clock, FileMutator, FixedClock, Observer, SystemClock};
pub use projection::{
    project_workspace, project_workspace_with_rules, DeviceView, EntryOverride, ProjectionError,
    ProjectionPolicy, ProjectionRules, ResourceRule,
};
pub use recovery::{
    PlanSource, RecoveryDiagnosis, RecoveryEngine, RecoveryReport, RecoverySuggestion,
};
pub use render::{render, RenderError, RenderInput, RenderedChange};
pub use rotation::{drive as drive_rotation, RotationError, RotationOutcome, RotationSteps};
pub use service::{
    CaptureOutcome, DoctorFinding, DoctorReport, EnvSyncService, ProfileExplanation,
    ResourceStatus, StatusReport, WorkspaceState,
};
pub use sync::{ConflictDetail, FetchOutcome, MergeContext, MergeKind, MergeOutcome};
pub use vault::{
    HiddenPrompt, KeyRing, SecretInput, SecretMetadata, SecretRef, VaultDeps, VaultError,
    VaultIndex, VaultService, VAULT_INDEX_METADATA_KEY,
};
