//! # envsync-platform
//!
//! EnvSync 的**平台层**：唯一被允许触碰用户文件系统的 crate。
//!
//! 上层（core、cli）只描述“在哪个授权根的哪个相对目标上做什么”，真实路径解析、
//! 符号链接拒绝、原子替换、备份与回滚全部在这里完成。这样做的目的只有一个：把
//! “可能写坏用户文件”的代码收敛到一个可以被完整审计的模块里。
//!
//! ## 模块地图
//!
//! | 模块 | 职责 |
//! |---|---|
//! | [`capability`] | 授权根、相对目标校验、逐段 no-follow 路径解析 |
//! | [`reader`] | 能力约束读取，产出 [`envsync_domain::Observation`] |
//! | [`writer`] | 安全写入、备份、删除与回滚收据 |
//!
//! ## 三条硬约束
//!
//! 1. **绝不越权。** 所有文件操作都通过 [`cap_std::fs::Dir`] 的相对操作完成，
//!    路径分段逐段做 no-follow 检查；中间目录或最终文件是符号链接一律拒绝。
//! 2. **绝不把失败伪装成缺失。** 权限错误、I/O 错误、超限都返回明确错误或
//!    [`envsync_domain::ObservedState::Unreadable`]，永远不会变成 `Absent`——
//!    因为 `Absent` 在计划层意味着“可以放心创建”。
//! 3. **绝不在错误信息里泄露绝对路径。** 诊断只包含授权根别名与相对分段，
//!    I/O 细节只保留 [`std::io::ErrorKind`] 与 OS 错误码。
//!
//! ## 示例
//!
//! ```no_run
//! use envsync_domain::{ResourceId, ResourcePolicy};
//! use envsync_platform::capability::{AuthorizedRoot, RelativeTarget};
//! use envsync_platform::reader::FileReader;
//!
//! let root = AuthorizedRoot::open("home", std::path::Path::new("/tmp/authorized"))?;
//! let target = RelativeTarget::parse(".config/envsync/demo.toml")?;
//! let resource = ResourceId::parse("demo/config")?;
//! let observation = FileReader::observe(
//!     &root,
//!     &target,
//!     &resource,
//!     &ResourcePolicy::default(),
//!     envsync_domain::unix_millis_now(),
//! );
//! println!("{}", observation.state.kind());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

use std::io;

use envsync_domain::Digest32;

pub mod capability;
pub mod reader;
pub mod writer;

pub use capability::{AuthorizedRoot, RelativeTarget, ResolvedPath, RootRegistry, TargetError};
pub use reader::{FileReader, ReadOutcome, FILE_CONTENT_DOMAIN};
pub use writer::{
    DeleteRequest, FaultInjection, Receipt, SafeWriter, WriteRequest, TEMP_FILE_PREFIX,
};

/// 平台层错误。
///
/// 所有变体的 `Display` 输出都保证**不含绝对路径**：只出现授权根别名、相对分段、
/// 摘要短表示和错误类别。上层可以直接把它写进日志或 JSON 诊断而不泄露本机布局。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PlatformError {
    /// 引用了未注册的授权根别名。
    #[error("未注册的授权根别名 `{alias}`")]
    UnknownRoot {
        /// 被引用的别名。
        alias: String,
    },

    /// 授权根本身无法打开（不存在、无权限等）。
    #[error("授权根 `{alias}` 不可用：{detail}")]
    RootUnavailable {
        /// 授权根别名。
        alias: String,
        /// 不含路径的失败描述。
        detail: String,
    },

    /// 授权根存在但不是目录。
    #[error("授权根 `{alias}` 不是目录")]
    RootNotDirectory {
        /// 授权根别名。
        alias: String,
    },

    /// 相对目标本身不合法。
    #[error("相对目标非法：{0}")]
    InvalidTarget(#[from] TargetError),

    /// 路径解析过程中遇到符号链接。
    #[error("授权根 `{alias}` 下的第 {index} 段 `{segment}` 是符号链接，已拒绝穿越")]
    SymlinkRejected {
        /// 授权根别名。
        alias: String,
        /// 出问题的分段序号（从 0 开始）。
        index: usize,
        /// 出问题的分段名。
        segment: String,
    },

    /// 中间分段存在但不是目录，无法继续解析。
    #[error("授权根 `{alias}` 下的段 `{segment}` 不是目录，无法继续解析")]
    NotADirectory {
        /// 授权根别名。
        alias: String,
        /// 出问题的分段名。
        segment: String,
    },

    /// 目标存在但不是普通文件。
    #[error("目标不是普通文件（{kind}）")]
    NotAFile {
        /// 实际类型描述，例如 `directory`。
        kind: &'static str,
    },

    /// 目标超过大小上限。**绝不截断**，一律报错。
    #[error("目标大小 {actual} 字节超过上限 {limit} 字节；拒绝截断读写")]
    TooLarge {
        /// 策略上限。
        limit: u64,
        /// 实际大小。
        actual: u64,
    },

    /// 底层 I/O 失败。
    #[error("{operation}失败：{detail}")]
    Io {
        /// 正在执行的操作（中文短语，便于诊断）。
        operation: &'static str,
        /// 机器可读的错误类别。
        kind: io::ErrorKind,
        /// 不含路径的错误描述。
        detail: String,
    },

    /// 写入前重新观察的结果与计划绑定的观察不一致。
    #[error(
        "写入前观察已过期：期望 {}，实际 {}",
        digest_label(.expected),
        digest_label(.actual)
    )]
    StaleObservation {
        /// 计划绑定的摘要；`None` 表示期望目标不存在。
        expected: Option<Digest32>,
        /// 实际观察到的摘要；`None` 表示目标不存在。
        actual: Option<Digest32>,
    },

    /// 应用后的验证失败。
    #[error(
        "验证失败：期望 {}，实际 {}",
        digest_label(.expected),
        digest_label(.actual)
    )]
    VerificationFailed {
        /// 期望摘要；`None` 表示期望不存在。
        expected: Option<Digest32>,
        /// 实际摘要；`None` 表示不存在。
        actual: Option<Digest32>,
    },

    /// 拒绝回滚，以免覆盖用户在此期间的新修改或写入损坏的备份。
    #[error("拒绝回滚：{reason}")]
    RollbackRefused {
        /// 拒绝原因（不含绝对路径）。
        reason: String,
    },

    /// 测试专用的故障注入点被触发。
    #[error("注入故障：{stage}")]
    FaultInjected {
        /// 被注入故障的阶段名。
        stage: &'static str,
    },
}

impl PlatformError {
    /// 稳定的机器可读错误码，用于 CLI 的 JSON 契约与退出码判定。
    ///
    /// 这些字符串属于对外契约的一部分，只能新增、不能重命名。
    pub fn code(&self) -> &'static str {
        match self {
            PlatformError::UnknownRoot { .. } => "platform.unknown_root",
            PlatformError::RootUnavailable { .. } => "platform.root_unavailable",
            PlatformError::RootNotDirectory { .. } => "platform.root_not_directory",
            PlatformError::InvalidTarget { .. } => "platform.invalid_target",
            PlatformError::SymlinkRejected { .. } => "platform.symlink_rejected",
            PlatformError::NotADirectory { .. } => "platform.not_a_directory",
            PlatformError::NotAFile { .. } => "platform.not_a_file",
            PlatformError::TooLarge { .. } => "platform.too_large",
            PlatformError::Io { .. } => "platform.io",
            PlatformError::StaleObservation { .. } => "platform.stale_observation",
            PlatformError::VerificationFailed { .. } => "platform.verification_failed",
            PlatformError::RollbackRefused { .. } => "platform.rollback_refused",
            PlatformError::FaultInjected { .. } => "platform.fault_injected",
        }
    }
}

impl PlatformError {
    /// 由 [`std::io::Error`] 构造，只保留不泄露路径的信息。
    ///
    /// 故意**不**使用 `io::Error` 的 `Display`：某些来源会把路径拼进消息里。
    pub fn io(operation: &'static str, error: &io::Error) -> Self {
        PlatformError::Io {
            operation,
            kind: error.kind(),
            detail: describe_io(error),
        }
    }

    /// 底层 I/O 错误类别；非 I/O 错误返回 `None`。
    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            PlatformError::Io { kind, .. } => Some(*kind),
            _ => None,
        }
    }

    /// 是否表示“目标确定不存在”。
    pub fn is_not_found(&self) -> bool {
        self.io_kind() == Some(io::ErrorKind::NotFound)
    }
}

/// 生成不含路径的 I/O 错误描述。
fn describe_io(error: &io::Error) -> String {
    match error.raw_os_error() {
        Some(code) => format!("{:?}（os error {code}）", error.kind()),
        None => format!("{:?}", error.kind()),
    }
}

/// 摘要的诊断标签；`None` 渲染为 `absent`。
fn digest_label(digest: &Option<Digest32>) -> String {
    match digest {
        Some(value) => value.short(),
        None => "absent".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_errors_never_carry_paths() {
        let raw = io::Error::new(
            io::ErrorKind::PermissionDenied,
            "/home/alice/.zshrc: denied",
        );
        let mapped = PlatformError::io("读取目标", &raw);
        let text = mapped.to_string();
        assert!(!text.contains('/'), "错误信息不得包含路径：{text}");
        assert_eq!(mapped.io_kind(), Some(io::ErrorKind::PermissionDenied));
    }

    #[test]
    fn digest_label_renders_absent_for_none() {
        assert_eq!(digest_label(&None), "absent");
        let digest = Digest32::domain_hash("test", b"x");
        assert_eq!(digest_label(&Some(digest)), digest.short());
    }
}
