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

pub mod conflicts;
pub mod draft;
pub mod journal;
pub mod migrations;

pub use conflicts::{ConflictError, ConflictRecord, ConflictState, ConflictStore};
pub use draft::{DraftError, DraftStore, DATABASE_FILE_NAME};
pub use journal::{
    ActionRecord, ActionState, ErrorDetail, Journal, JournalError, OperationRecord, OperationState,
    Receipt, ReceiptRecord,
};
pub use migrations::{StorageDiagnostics, SCHEMA_VERSION};
