//! macOS 后端：登录钥匙串（Keychain）。
//!
//! 存取逻辑在 [`super`] 里统一实现，本模块只负责命名、可用性探测与失败分类标记。
//!
//! ## 为什么这里不做主动探测
//!
//! Keychain 是系统组件，只要进程跑在 macOS 上就一定存在，不存在「服务没起」这种
//! 状态。反过来，主动探测还有害：读取钥匙串可能弹出解锁或授权对话框，而用户可能
//! 需要几十秒才作出选择。若在探测上设超时，就会把「用户还在看对话框」误判成
//! 「Keychain 不可用」，进而让上层以为需要重新生成密钥——这比慢得多的后果严重。
//!
//! 因此 macOS 上 [`probe`] 恒定成功，锁定与拒绝在**真实操作**发生时才报告，
//! 分别映射为 [`crate::PlatformError::SecureStoreLocked`] 与
//! [`crate::PlatformError::SecureStoreDenied`]。

use crate::PlatformError;

/// 编译期断言：`keyring` 的默认后端确实是 Keychain。
///
/// `keyring::default` 是对平台后端模块的 re-export。一旦 `apple-native` feature
/// 被关掉，它会**静默**指向 `keyring::mock`——那是个进程内的假存储，会把密钥丢在
/// 内存里还报告成功。`mock` 里没有 `MacCredential`，因此那种配置在这一行就编译失败。
const _: Option<&keyring::default::MacCredential> = None;

/// 后端标识，进入 [`super::SecureStoreDescriptor`]。
pub(super) const BACKEND: &str = "macos-keychain";

/// 判定「访问被明确拒绝」的标记词（小写匹配）。
///
/// 覆盖常见的 OSStatus：`errSecUserCanceled`（-128，用户在授权框上点了拒绝）、
/// `errSecAuthFailed`（-25293）。匹配到的原文不会进入错误消息。
pub(super) const DENIAL_MARKERS: &[&str] = &[
    "-25293",
    "-128",
    "usercanceled",
    "user canceled",
    "authfailed",
    "authentication failed",
];

/// 判定「钥匙串锁定」的标记词（小写匹配）。
///
/// 覆盖 `errSecInteractionNotAllowed`（-25308，钥匙串已锁且不允许弹窗）
/// 与 `errSecInteractionRequired`（-25315）。
pub(super) const LOCK_MARKERS: &[&str] = &[
    "-25308",
    "-25315",
    "interaction is not allowed",
    "interactionnotallowed",
    "keychain is locked",
];

/// 探测 Keychain 是否可用；在 macOS 上恒定成功，理由见模块文档。
pub(super) fn probe() -> Result<(), PlatformError> {
    Ok(())
}
