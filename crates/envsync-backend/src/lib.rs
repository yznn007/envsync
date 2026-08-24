//! # envsync-backend
//!
//! EnvSync 的**后端端口**：把「不可变对象存储 + 单调 Ref 的 CAS 发布」抽象成一个
//! 同步 trait，并提供本地目录实现 [`LocalBackend`]。
//!
//! ## 为什么是同步的
//!
//! 见 `docs/decisions/2026-07-26-synchronous-backend-trait.md`：同步签名让
//! [`Backend`] 天然 dyn 兼容（应用服务在运行期按配置选择实现），而同步事务本身是
//! 串行的，异步化没有并发收益却会污染整条依赖链。
//!
//! ## 后端必须保证的三件事
//!
//! 1. **对象不可变且内容寻址。** [`Backend::put_object`] 幂等；写入前和读出后都要
//!    用 `ObjectId::verifies` 校验摘要，损坏对象**绝不**返回内容。
//! 2. **Ref 只能通过 CAS 前进。** [`Backend::compare_and_swap_ref`] 必须在
//!    `expected_revision` 与实际不符时失败，且 revision 严格递增。
//! 3. **不泄露本机信息。** 所有 [`BackendError`] 的展示文本只包含相对于后端根的路径
//!    或对象标识，绝不包含绝对路径。
//!
//! ## 示例
//!
//! ```
//! use envsync_backend::{Backend, LocalBackend};
//! use envsync_domain::{ObjectId, ObjectKind, SnapshotId, WorkspaceId, WorkspaceRef};
//!
//! let dir = tempfile::tempdir()?;
//! let backend = LocalBackend::open(dir.path())?;
//!
//! // 对象写入是幂等的。
//! let bytes = b"export EDITOR=nvim\n";
//! let id = ObjectId::for_bytes(ObjectKind::Blob, bytes);
//! backend.put_object(id, bytes)?;
//! backend.put_object(id, bytes)?;
//! assert_eq!(backend.get_object(id)?, bytes.as_slice());
//!
//! // Ref 首次发布只接受 expected_revision == 0。
//! let workspace = WorkspaceId::generate();
//! let next = WorkspaceRef::initial(workspace).advance(SnapshotId::of(b"snapshot"));
//! backend.compare_and_swap_ref(workspace, 0, &next)?;
//! assert_eq!(backend.get_ref(workspace)?.revision, 1);
//!
//! // 重放同一次发布会被 CAS 拦下。
//! let err = backend.compare_and_swap_ref(workspace, 0, &next).unwrap_err();
//! assert_eq!(err.code(), "backend.cas_conflict");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod gist_bundle;
pub mod git;
pub mod git_auth;
pub mod local;

pub use git::{GitBackend, GitConfig};
pub use git_auth::GitAuth;
pub use local::LocalBackend;

use envsync_domain::{CborError, ObjectId, WorkspaceId, WorkspaceRef};

/// 后端自述信息，供诊断输出和能力协商使用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendDescriptor {
    /// 后端种类的稳定短名称，例如 `local`。
    pub kind: &'static str,
    /// 是否提供**强** CAS：并发发布时至多一方成功，且失败方能读到真实的
    /// observed revision。
    ///
    /// 只做「读—改—写」而没有原子性保证的后端（例如最终一致的对象存储）必须返回
    /// `false`，上层据此拒绝多设备写入。
    pub supports_strong_cas: bool,
}

/// 后端操作错误。
///
/// 每个变体都有稳定的机器可读 [`BackendError::code`]；展示文本只使用相对路径或对象
/// 标识，不包含绝对路径。
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// Ref 的 CAS 前置条件不成立：期望的 revision 与后端实际值不符。
    #[error("CAS 冲突：期望 revision {expected}，后端实际为 {observed}")]
    CasConflict {
        /// 调用方声称的 revision。
        expected: u64,
        /// 后端读到的真实 revision（Ref 不存在时为 `0`）。
        observed: u64,
    },

    /// 对象不存在。
    #[error("对象不存在：{0}")]
    ObjectNotFound(ObjectId),

    /// 内容寻址被破坏：字节与对象标识不一致。
    #[error("对象 {id} 内容损坏：{detail}")]
    Corruption {
        /// 受影响的对象标识。
        id: ObjectId,
        /// 人类可读的原因说明，不含绝对路径。
        detail: String,
    },

    /// 工作区 Ref 不存在（尚未发布过任何快照）。
    #[error("工作区 {0} 尚无 Ref")]
    RefNotFound(WorkspaceId),

    /// Ref 内容非法：结构校验失败、工作区不匹配或 revision 未严格递增。
    #[error("工作区 {workspace} 的 Ref 非法：{detail}")]
    InvalidRef {
        /// 受影响的工作区。
        workspace: WorkspaceId,
        /// 原因说明。
        detail: String,
    },

    /// 底层 I/O 失败。
    #[error("I/O 失败（{context}）：{source}")]
    Io {
        /// 相对于后端根的路径或操作描述，**不含**绝对路径。
        context: String,
        /// 原始 I/O 错误。
        #[source]
        source: std::io::Error,
    },

    /// canonical CBOR 编解码失败。
    #[error("CBOR 编解码失败：{0}")]
    Codec(#[from] CborError),

    /// 无法获取工作区锁（其他持有者长时间未释放，或锁目录不可写）。
    #[error("工作区 {workspace} 被锁定：{detail}")]
    Locked {
        /// 受影响的工作区。
        workspace: WorkspaceId,
        /// 原因说明。
        detail: String,
    },

    /// 后端布局或能力不被支持。
    #[error("不支持：{0}")]
    Unsupported(&'static str),

    /// 调用方传入的对象前缀非法（含路径分隔符、点段或非十六进制字符）。
    #[error("非法的对象前缀 `{prefix}`：{detail}")]
    InvalidPrefix {
        /// 被拒绝的前缀，原样回显便于调用方定位。
        prefix: String,
        /// 拒绝原因。
        detail: String,
    },

    /// 后端根目录的格式标记与本实现不匹配。
    #[error("后端格式标记不匹配：期望 `{expected}`，实际 `{found}`")]
    FormatMismatch {
        /// 本实现要求的标记（已转义）。
        expected: String,
        /// 目录中读到的标记（已转义并截断）。
        found: String,
    },
}

impl BackendError {
    /// 稳定的机器可读错误码。
    ///
    /// 该字符串会写入 journal、CLI 的 JSON 输出和遥测，**不得**随展示文本一起改动。
    ///
    /// # 层前缀
    ///
    /// 每一个错误码都带 `backend.` 前缀，与 `platform.*` / `storage.*` / `config.*` /
    /// `vault.*` / `checkpoint.*` 保持一致。前缀不是装饰：调用方（CLI 的 JSON 契约、
    /// 日志检索、告警规则）经常只拿到一个字符串，`corruption` 这种裸名字既看不出是哪
    /// 一层报的，也随时可能和别的层撞名——`unsupported` 就同时是
    /// [`envsync_domain::ObservedState`] 的一个状态名。
    ///
    /// M2 起统一加上前缀，这是一次**对外契约变更**：断言旧码的调用方需要同步更新。
    pub fn code(&self) -> &'static str {
        match self {
            BackendError::CasConflict { .. } => "backend.cas_conflict",
            BackendError::ObjectNotFound(_) => "backend.object_not_found",
            BackendError::Corruption { .. } => "backend.corruption",
            BackendError::RefNotFound(_) => "backend.ref_not_found",
            BackendError::InvalidRef { .. } => "backend.invalid_ref",
            BackendError::Io { .. } => "backend.io",
            BackendError::Codec(_) => "backend.codec",
            BackendError::Locked { .. } => "backend.locked",
            BackendError::Unsupported(_) => "backend.unsupported",
            BackendError::InvalidPrefix { .. } => "backend.invalid_prefix",
            BackendError::FormatMismatch { .. } => "backend.format_mismatch",
        }
    }

    /// 构造 [`BackendError::Io`]；`context` 必须是相对于后端根的路径或操作描述。
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        BackendError::Io {
            context: context.into(),
            source,
        }
    }
}

/// 后端端口：不可变对象存储 + 单调 Ref 的 CAS 发布。
///
/// 实现必须是 `Send + Sync`，以便应用服务以 `Arc<dyn Backend>` 形式共享。所有方法都是
/// 同步的；需要网络 I/O 的实现使用阻塞客户端，由调用方决定是否放进工作线程。
pub trait Backend: Send + Sync {
    /// 返回后端自述信息。
    fn describe(&self) -> BackendDescriptor;

    /// 读取工作区当前 Ref。
    ///
    /// 只读取该工作区自己的 Ref 记录，**绝不**通过列目录推导工作区头：残留文件、
    /// 并发写入或他人的对象都不能影响这个结果。
    ///
    /// # 错误
    ///
    /// 工作区从未发布过快照时返回 [`BackendError::RefNotFound`]。
    fn get_ref(&self, workspace: WorkspaceId) -> Result<WorkspaceRef, BackendError>;

    /// 以 CAS 方式发布新的工作区 Ref。
    ///
    /// 语义：当且仅当后端当前 revision 等于 `expected_revision` 时，把 Ref 原子替换为
    /// `next`。Ref 尚不存在时实际 revision 视为 `0`，因此首次发布只接受
    /// `expected_revision == 0`。
    ///
    /// # 错误
    ///
    /// * [`BackendError::CasConflict`]：期望 revision 与实际不符，错误中带回实际值；
    /// * [`BackendError::InvalidRef`]：`next` 结构非法、工作区不匹配或 revision 未严格递增；
    /// * [`BackendError::Locked`]：无法在有界时间内获得工作区锁。
    fn compare_and_swap_ref(
        &self,
        workspace: WorkspaceId,
        expected_revision: u64,
        next: &WorkspaceRef,
    ) -> Result<(), BackendError>;

    /// 读取对象内容。
    ///
    /// 实现必须重算摘要；不一致时返回 [`BackendError::Corruption`] 而**绝不**返回内容。
    fn get_object(&self, id: ObjectId) -> Result<Vec<u8>, BackendError>;

    /// 写入对象，**幂等**。
    ///
    /// 同一标识重复写入相同内容必须成功且不报错；`bytes` 与 `id` 不匹配，或后端已存在
    /// 同标识但不同内容的对象时，返回 [`BackendError::Corruption`]。
    fn put_object(&self, id: ObjectId, bytes: &[u8]) -> Result<(), BackendError>;

    /// 判断对象是否存在。
    ///
    /// 只检查存在性，不校验内容；需要保证内容完整请使用 [`Backend::get_object`]。
    fn has_object(&self, id: ObjectId) -> Result<bool, BackendError>;

    /// 按摘要十六进制前缀列出对象，**仅用于维护**（GC、体检、修复）。
    ///
    /// 同步路径禁止依赖该方法：列目录的结果会被并发写入和残留文件影响，不能用来推导
    /// 任何领域状态。`prefix` 必须是小写十六进制串，含 `/`、`.`、`..` 或其他字符时返回
    /// [`BackendError::InvalidPrefix`]。
    fn list_objects(&self, prefix: &str) -> Result<Vec<ObjectId>, BackendError>;
}
