//! Windows 后端：凭据管理器（Credential Manager）。
//!
//! 存取逻辑在 [`super`] 里统一实现，本模块只负责命名、可用性探测与失败分类标记。
//!
//! ## 为什么这里不做主动探测
//!
//! Credential Manager 由 LSASS 提供，随登录会话存在，没有「服务未启动」这种中间
//! 状态；失败要么是权限问题，要么是凭据本身的问题，两者都在真实操作时立即返回。
//! 因此 [`probe`] 恒定成功，与 [`super::macos`] 同理。
//!
//! ## 已知平台限制
//!
//! `CredWrite` 的 blob 上限是 `CRED_MAX_CREDENTIAL_BLOB_SIZE`（2560 字节）。
//! 超限时 `keyring` 会返回 `TooLong`，本层映射为
//! [`crate::PlatformError::SecureStoreBackend`]。EnvSync 存进来的都是密钥与
//! 检查点（数百字节量级），正常不会触碰这个上限；这里记录下来是为了让将来
//! 想往安全存储里塞大对象的人先看到这段话。

use crate::PlatformError;

/// 编译期断言：`keyring` 的默认后端确实是凭据管理器。
///
/// `keyring::default` 是对平台后端模块的 re-export。一旦 `windows-native` feature
/// 被关掉，它会**静默**指向 `keyring::mock`——那是个进程内的假存储，会把密钥丢在
/// 内存里还报告成功。`mock` 里没有 `WinCredential`，因此那种配置在这一行就编译失败。
const _: Option<&keyring::default::WinCredential> = None;

/// 后端标识，进入 [`super::SecureStoreDescriptor`]。
pub(super) const BACKEND: &str = "windows-credential-manager";

/// 判定「访问被明确拒绝」的标记词（小写匹配）。
///
/// 覆盖 `ERROR_ACCESS_DENIED`(5) 与 `ERROR_NO_SUCH_LOGON_SESSION`(1312) 等。
/// 匹配到的原文不会进入错误消息。
pub(super) const DENIAL_MARKERS: &[&str] = &[
    "os error 5",
    "access is denied",
    "1312",
    "no such logon session",
];

/// 判定「凭据库不可访问」的标记词（小写匹配）。
///
/// Windows 没有与 macOS 「钥匙串锁定」完全对应的状态，这里覆盖
/// `ERROR_NOT_READY`(21) 之类的暂时不可用。
pub(super) const LOCK_MARKERS: &[&str] = &["os error 21", "device is not ready"];

/// 探测凭据管理器是否可用；在 Windows 上恒定成功，理由见模块文档。
pub(super) fn probe() -> Result<(), PlatformError> {
    Ok(())
}
