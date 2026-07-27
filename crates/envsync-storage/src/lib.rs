//! # envsync-storage
//!
//! EnvSync 的**本地**持久化层：SQLite 操作日志与本地草稿对象存储。
//!
//! ## 模块地图
//!
//! | 模块 | 职责 |
//! |---|---|
//! | [`journal`] | 操作日志：状态机、动作进度与回滚收据 |
//! | [`draft`] | 本地草稿对象：未发布的 Blob/State Root/Snapshot 与计划 |
//! | [`conflicts`] | 合并冲突的本地索引与状态 |
//! | [`membership`] | 已验证成员事件的本地索引与链头（M2） |
//! | [`checkpoints`] | 反回滚检查点的**审计副本**；权威副本在系统安全存储（M2） |
//! | [`rotation`] | 密钥轮换 journal：让被中断的轮换可以幂等恢复（M2） |
//! | [`bundles`] | Agent Bundle 的隔离状态与文件清单（M3） |
//! | [`migrations`] | 数据库打开、PRAGMA 与 schema 迁移 |
//!
//! ## 三条不变量
//!
//! 1. **journal 是崩溃恢复的事实来源。** 因此连接使用 `synchronous=FULL`：
//!    每次提交都 fsync，用性能换“记录不会丢”。
//! 2. **状态机由 Rust 强制。** 数据库只把状态当字符串存；非法迁移返回
//!    [`journal::JournalError::IllegalTransition`]，绝不 panic。
//! 3. **不依赖平台层。** 收据里的备份位置只是 [`String`]，摘要是十六进制文本；
//!    本 crate 不引入任何文件系统能力类型。
//!
//! ## 示例
//!
//! ```no_run
//! use envsync_storage::journal::{Journal, OperationState};
//!
//! let journal = Journal::open("/tmp/envsync/journal.db")?;
//! // 重开数据库后先处理未完成操作，再做任何新的同步。
//! for record in journal.list_unfinished()? {
//!     assert!(!record.state.is_terminal());
//! }
//! # Ok::<(), envsync_storage::journal::JournalError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod bundles;
pub mod checkpoints;
pub mod conflicts;
pub mod draft;
pub mod journal;
pub mod membership;
pub mod migrations;
pub mod rotation;

pub use bundles::{BundleRecord, BundleStore, BundleStoreError};
pub use checkpoints::{CheckpointAudit, CheckpointRecord, CheckpointStoreError};
pub use conflicts::{ConflictError, ConflictRecord, ConflictState, ConflictStore};
pub use draft::{DraftError, DraftStore, DATABASE_FILE_NAME};
pub use journal::{
    ActionRecord, ActionState, ErrorDetail, Journal, JournalError, OperationRecord, OperationState,
    Receipt, ReceiptRecord,
};
pub use membership::{
    MembershipEventRecord, MembershipHead, MembershipIndex, MembershipStoreError,
};
pub use migrations::{StorageDiagnostics, SCHEMA_VERSION};
pub use rotation::{RotationJournal, RotationRecord, RotationStage, RotationStoreError};
