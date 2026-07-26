//! Linux 后端：freedesktop Secret Service（GNOME Keyring / KWallet 等实现）。
//!
//! 存取逻辑在 [`super`] 里统一实现，本模块只负责命名、可用性探测与失败分类标记。
//!
//! ## 为什么 Linux 必须主动探测
//!
//! macOS 与 Windows 的凭据库随系统存在；Linux 的 Secret Service 是一个**可选的**
//! DBus 服务。在容器、CI、SSH 无会话登录等环境里它经常不存在，而 DBus 在这种情况下
//! 的失败方式很不友好：如果会话总线在但服务没起，DBus 会尝试**按需激活**服务，
//! 默认要等 25 秒才超时。EnvSync 的 CLI 不能在启动路径上挂 25 秒。
//!
//! 因此这里做两级探测：
//!
//! 1. **零成本前置检查**：没有会话总线地址就直接判定不可用，连线程都不用起；
//! 2. **带超时的只读探测**：在独立线程里读一个不存在的探测条目，
//!    [`PROBE_TIMEOUT`] 内没有结论就判定不可用。
//!
//! 超时后探测线程可能仍阻塞在 DBus 上；我们**故意**不去 join 它。它不持有任何
//! 秘密，也不会写入任何东西（只读），进程退出时随之消失。用「泄漏一个只读线程」
//! 换「CLI 不会假死」是划算的。

use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use crate::PlatformError;

/// 编译期断言：`keyring` 的默认后端确实是 Secret Service。
///
/// `keyring::default` 是对平台后端模块的 re-export。一旦 `sync-secret-service`
/// feature 被关掉，它会**静默**指向 `keyring::mock`——那是个进程内的假存储，
/// 会把密钥丢在内存里还报告成功，正是本模块要禁止的降级。`mock` 里没有
/// `SsCredential`，所以那种配置在这一行就编译失败，而不是运行时才出问题。
const _: Option<&keyring::default::SsCredential> = None;

/// 后端标识，进入 [`super::SecureStoreDescriptor`]。
pub(super) const BACKEND: &str = "linux-secret-service";

/// Secret Service 可用性探测的超时。
///
/// 取值权衡：本地 GNOME Keyring 的一次只读查询通常在几十毫秒内返回；
/// 3 秒足够覆盖冷启动的解锁协商，又远小于 DBus 默认的 25 秒激活超时。
pub(super) const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// 判定「访问被明确拒绝」的标记词（小写匹配）。
///
/// 匹配到的原文不会进入错误消息，只用于挑选类别。
pub(super) const DENIAL_MARKERS: &[&str] = &[
    "accessdenied",
    "access denied",
    "prompt dismissed",
    "dismissed by user",
    "not authorized",
];

/// 判定「凭据库锁定」的标记词（小写匹配）。
pub(super) const LOCK_MARKERS: &[&str] = &["is locked", "locked collection", "islocked"];

/// 探测 Secret Service 是否可用。
pub(super) fn probe() -> Result<(), PlatformError> {
    if !session_bus_present() {
        return Err(PlatformError::SecureStoreUnavailable {
            detail: "未检测到 DBus 会话总线，Secret Service 不可达",
        });
    }

    let (sender, receiver) = mpsc::channel();
    std::thread::Builder::new()
        .name("envsync-secret-service-probe".to_owned())
        .spawn(move || {
            // 只读探测：读一个必然不存在的条目。`NoEntry` 恰恰证明服务活着并且答复了。
            let reachable = match keyring::Entry::new(super::SERVICE_NAME, super::PROBE_ACCOUNT) {
                Ok(entry) => matches!(entry.get_secret(), Ok(_) | Err(keyring::Error::NoEntry)),
                Err(_) => false,
            };
            // 主线程可能已经超时走人，发送失败是预期内的。
            let _ = sender.send(reachable);
        })
        .map_err(|_| PlatformError::SecureStoreUnavailable {
            detail: "无法启动 Secret Service 探测线程",
        })?;

    match receiver.recv_timeout(PROBE_TIMEOUT) {
        Ok(true) => Ok(()),
        Ok(false) => Err(PlatformError::SecureStoreUnavailable {
            detail: "Secret Service 拒绝了探测请求或未正常应答",
        }),
        Err(RecvTimeoutError::Timeout) => Err(PlatformError::SecureStoreUnavailable {
            detail: "Secret Service 探测超时",
        }),
        Err(RecvTimeoutError::Disconnected) => Err(PlatformError::SecureStoreUnavailable {
            detail: "Secret Service 探测线程异常退出",
        }),
    }
}

/// 零成本前置检查：会话总线是否存在。
///
/// 优先看 `DBUS_SESSION_BUS_ADDRESS`；某些会话（如 systemd 用户实例）不导出它，
/// 但会在 `$XDG_RUNTIME_DIR/bus` 放一个 socket，因此两者取或。
fn session_bus_present() -> bool {
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some_and(|value| !value.is_empty()) {
        return true;
    }
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(dir) if !dir.is_empty() => std::path::Path::new(&dir).join("bus").exists(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_timeout_is_shorter_than_dbus_activation_timeout() {
        // DBus 默认的服务激活超时是 25 秒；我们必须明显短于它。
        assert!(PROBE_TIMEOUT < Duration::from_secs(25));
    }

    #[test]
    fn probe_never_panics_regardless_of_environment() {
        // 容器里通常没有会话总线，这里只要求「有结论且不 panic」。
        let outcome = probe();
        if let Err(error) = outcome {
            assert_eq!(error.code(), "platform.secure_store_unavailable");
        }
    }
}
