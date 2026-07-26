//! # envsync-domain
//!
//! EnvSync 的**纯领域模型**：不做任何 I/O，不依赖运行时，只定义类型、约束和确定性
//! 编码规则。所有需要读写文件、网络或数据库的能力都通过上层 crate 注入。
//!
//! ## 模块地图
//!
//! | 模块 | 职责 |
//! |---|---|
//! | [`cbor`] | 严格 canonical CBOR 编解码，保证确定性与非 canonical 拒绝 |
//! | [`id`] | 强类型标识符：随机 ID、派生 ID 与内容寻址 ID |
//! | [`membership`] | 设备成员签名事件链：角色、动作、事件与回放后的成员状态 |
//! | [`resource`] | 观察状态、期望处置、资源条目与写入策略 |
//! | [`object`] | 内容寻址对象：Blob、State Root、Conflict |
//! | [`profile`] | 设备 Profile、封闭选择器 AST、投影诊断与冲突解决方案 |
//! | [`snapshot`] | 快照主体、签名与工作区引用 |
//! | [`plan`] | 绑定观察结果的不可变计划 |
//!
//! ## 三条不可动摇的不变量
//!
//! 1. **对象不可变，Ref 只能通过 CAS 前进。** 见 [`snapshot::WorkspaceRef::check_successor`]。
//! 2. **观察缺失不等于删除意图。** 只有 [`resource::DesiredDisposition::EnsureAbsent`]
//!    能产生删除动作，[`resource::ObservedState`] 的五个变体没有一个可以被推断为删除。
//! 3. **相同输入产生相同标识。** 所有内容寻址标识都基于 canonical CBOR 与域分隔
//!    BLAKE3；见 [`cbor`] 与 [`id::Digest32::domain_hash`]。
//!
//! ## 示例
//!
//! ```
//! use envsync_domain::cbor::CborCodec;
//! use envsync_domain::id::{BlobId, ResourceId};
//! use envsync_domain::object::StateRoot;
//! use envsync_domain::resource::{
//!     DesiredDisposition, FileMode, ResourceEntry, ResourcePolicy,
//! };
//!
//! let entry = ResourceEntry {
//!     resource: ResourceId::parse("shell/zsh/main")?,
//!     disposition: DesiredDisposition::Managed,
//!     blob: Some(BlobId::of(b"export EDITOR=nvim\n")),
//!     mode: FileMode::ManagedBlock,
//!     policy: ResourcePolicy::default(),
//! };
//!
//! // 插入顺序不影响 State Root 标识。
//! let state = StateRoot::from_entries([entry.clone()])?;
//! assert_eq!(state.id(), StateRoot::from_entries([entry])?.id());
//!
//! // canonical 编码可无损往返。
//! let bytes = state.to_canonical_vec();
//! assert_eq!(StateRoot::from_canonical_slice(&bytes)?, state);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod cbor;
pub mod id;
pub mod membership;
pub mod object;
pub mod plan;
pub mod profile;
pub mod resource;
pub mod snapshot;

pub use cbor::{CborCodec, CborError};
pub use id::{
    BlobId, ConflictId, DeviceId, Digest32, IdError, OperationId, PlanId, ResourceId, SnapshotId,
    StateRootId, WorkspaceId,
};
pub use membership::{
    DevicePublicBytes, MemberRecord, MemberRole, MembershipAction, MembershipEvent,
    MembershipEventError, MembershipState, DEVICE_PUBLIC_LEN, GENESIS_EPOCH, MAX_MEMBERSHIP_EVENTS,
    MEMBERSHIP_EVENT_FORMAT_VERSION,
};
pub use object::{
    Blob, Conflict, ConflictKind, ObjectId, ObjectKind, StateRoot, StateRootError,
    CONFLICT_FORMAT_VERSION, STATE_ROOT_FORMAT_VERSION,
};
pub use plan::{
    Action, ActionKind, ActionTarget, BackupPolicy, Diagnostic, Plan, Risk, RollbackCapability,
    Severity, VerifyRule, PLAN_FORMAT_VERSION,
};
pub use profile::{
    Arch, ConflictResolution, DeviceProfile, Os, Predicate, ProfileError, ProjectionNote,
    ProjectionNoteKind, ResolutionChoice, Selector, MAX_PROFILE_ENTRIES, MAX_PROFILE_VALUE_LEN,
    MAX_SELECTOR_DEPTH, MAX_SELECTOR_NODES, PROFILE_FORMAT_VERSION, PROJECTION_NOTE_FORMAT_VERSION,
    RESOLUTION_FORMAT_VERSION, SELECTOR_FORMAT_VERSION,
};
pub use resource::{
    DesiredDisposition, FileMode, LineEnding, Observation, ObservedState, PermissionSummary,
    PresentFile, ResourceEntry, ResourceEntryError, ResourcePolicy, StructuredFormat,
};
pub use snapshot::{
    SnapshotBody, SnapshotError, SnapshotSignature, WorkspaceRef, REF_FORMAT_VERSION,
    SIGNATURE_FORMAT_VERSION, SNAPSHOT_FORMAT_VERSION,
};

/// 返回当前 Unix 毫秒时间戳。
///
/// 领域层本身不依赖时钟；该函数只是给上层提供一个统一实现，测试中应注入固定时钟。
pub fn unix_millis_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}
