//! 系统安全存储抽象：macOS Keychain、Windows Credential Manager、Linux Secret Service。
//!
//! 设备私钥、工作区数据密钥与反回滚检查点必须落在**操作系统托管**的凭据库里，
//! 由用户登录态保护。本模块是 EnvSync 访问这些凭据库的唯一入口。
//!
//! ## 三条硬约束
//!
//! 1. **绝不退化到明文文件。** 没有可用的系统凭据库时 [`open_system_store`] 返回
//!    [`PlatformError::SecureStoreUnavailable`]，由上层决定是提示用户还是终止操作。
//!    M2 里**没有**「找不到 Keychain 就写 `~/.envsync/keys` 」这条路径。
//! 2. **绝不把 secret value 写进名字。** service / account 名称只由
//!    workspace、device 与 [`SecurePurpose`] 拼成，见 [`SecureKey::account_name`]。
//! 3. **绝不把 secret value 写进错误。** 本模块产生的所有 [`PlatformError`] 变体
//!    只携带 `&'static str`（用途、操作、失败类别），后端返回的原始错误文本
//!    **不会**被转载，也不会挂进 `source()` 链——因为它可能包含被查询的凭据内容。
//!
//! ## 为什么只有一个实现，却仍然分平台文件
//!
//! `keyring` 3.x 的 [`keyring::Entry`] 已经做完了跨平台抽象：
//! `Entry::new(service, user)` + `set_secret` / `get_secret` / `delete_credential`
//! 在三个平台上是同一套 API。因此这里**只有一个** `SystemSecureStore` 实现，
//! 平台模块（[`macos`]、[`windows`]、[`linux`]）不重复实现存取逻辑，只承担三件事：
//!
//! * **后端名称**：写进 [`SecureStoreDescriptor`]，让诊断能说清凭据落在哪里；
//! * **可用性探测**：Linux 上需要主动探测 DBus 会话总线并设超时，macOS / Windows 上
//!   凭据库随系统存在，不需要探测（见各模块注释）；
//! * **编译期后端断言**：`keyring` 在目标平台的 native feature 未开启时会**静默**
//!   退回到进程内的 `keyring::mock` 后端。那等于把密钥存在内存里还假装成功，
//!   正是约束 1 要禁止的事。每个平台模块都 `use` 了对应的 `keyring::<backend>`
//!   模块，一旦 feature 掉了就编译失败，而不是运行时静默降级。
//!
//! 非上述三个平台（例如 FreeBSD）不构造任何 keyring 后端，[`open_system_store`]
//! 直接返回 [`PlatformError::SecureStoreUnavailable`]。

use std::fmt;

use envsync_domain::{DeviceId, WorkspaceId};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::PlatformError;

#[cfg(any(feature = "test-support", test))]
pub mod fake;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
use linux as backend;
#[cfg(target_os = "macos")]
use macos as backend;
#[cfg(target_os = "windows")]
use windows as backend;

/// 所有 EnvSync 凭据共用的 service 名称。
///
/// 这是**持久化契约**：改动它会让已有设备读不到自己的密钥，等同于数据丢失。
pub const SERVICE_NAME: &str = "envsync";

/// account 名称中代表「非设备绑定」的占位段。
///
/// 同样是持久化契约，不可更改。
pub const DEVICE_PLACEHOLDER: &str = "-";

/// 可用性探测使用的 account 名称。
///
/// 刻意与真实条目的命名空间同形（`<workspace>/<device>/<purpose>`），但 workspace
/// 段是不可能出现的 `-`，因此永远不会与真实条目冲突。
#[cfg(target_os = "linux")]
const PROBE_ACCOUNT: &str = "-/-/availability-probe";

/// 安全存储中一条记录的用途。
///
/// 用途的字符串形式（[`SecurePurpose::as_str`]）会进入 account 名称，属于持久化契约：
/// **只能新增，不能重命名**。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecurePurpose {
    /// 本设备的 Ed25519 签名私钥。
    DeviceSigningKey,
    /// 本设备的 X25519 KEM 私钥。
    DeviceKemKey,
    /// 工作区数据密钥（当前纪元）。
    WorkspaceDataKey,
    /// 反回滚检查点。
    Checkpoint,
    /// 恢复身份（由恢复口令派生的密钥材料）。
    RecoveryIdentity,
}

impl SecurePurpose {
    /// 全部用途，按声明顺序排列。便于测试遍历与清理逻辑。
    pub const ALL: [SecurePurpose; 5] = [
        SecurePurpose::DeviceSigningKey,
        SecurePurpose::DeviceKemKey,
        SecurePurpose::WorkspaceDataKey,
        SecurePurpose::Checkpoint,
        SecurePurpose::RecoveryIdentity,
    ];

    /// 用途的稳定字符串形式，用于 account 名称与诊断。
    pub const fn as_str(self) -> &'static str {
        match self {
            SecurePurpose::DeviceSigningKey => "device-signing-key",
            SecurePurpose::DeviceKemKey => "device-kem-key",
            SecurePurpose::WorkspaceDataKey => "workspace-data-key",
            SecurePurpose::Checkpoint => "checkpoint",
            SecurePurpose::RecoveryIdentity => "recovery-identity",
        }
    }
}

impl fmt::Display for SecurePurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 安全存储中一条记录的逻辑坐标。
///
/// 它只描述「哪个工作区、哪台设备、什么用途」，**不含**任何 secret value；
/// [`SecureKey::account_name`] 的输出会被原样交给操作系统凭据库，因此在很多平台上
/// 是可被其他进程枚举的元数据。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecureKey {
    /// 所属工作区。
    pub workspace: WorkspaceId,
    /// 绑定的设备；`None` 表示该条目属于整个工作区而非某台设备。
    pub device: Option<DeviceId>,
    /// 记录用途。
    pub purpose: SecurePurpose,
}

impl SecureKey {
    /// 构造一条设备绑定的坐标。
    pub fn device_scoped(workspace: WorkspaceId, device: DeviceId, purpose: SecurePurpose) -> Self {
        SecureKey {
            workspace,
            device: Some(device),
            purpose,
        }
    }

    /// 构造一条工作区级（不绑定设备）的坐标。
    pub fn workspace_scoped(workspace: WorkspaceId, purpose: SecurePurpose) -> Self {
        SecureKey {
            workspace,
            device: None,
            purpose,
        }
    }

    /// 凭据库中的 service 名称，恒为 [`SERVICE_NAME`]。
    pub const fn service_name(&self) -> &'static str {
        SERVICE_NAME
    }

    /// 凭据库中的 account 名称：`<workspace-uuid>/<device-id-hex 或 '-'>/<purpose>`。
    ///
    /// **这是持久化契约。** 格式一旦改变，已有设备就再也找不到自己写下的条目，
    /// 表现为「密钥凭空消失」。契约测试里有一条 golden 字符串专门钉住它。
    ///
    /// 名称里出现的都是公开标识：工作区 UUID、设备指纹与用途名，**绝不含 value**。
    pub fn account_name(&self) -> String {
        let device = match &self.device {
            Some(id) => id.to_hex(),
            None => DEVICE_PLACEHOLDER.to_owned(),
        };
        format!("{}/{}/{}", self.workspace, device, self.purpose.as_str())
    }
}

/// 从安全存储读出的字节。
///
/// 与 `envsync_crypto::Plaintext` 同一套约束：**刻意不实现** `Debug`、`Display` 与
/// 任何序列化 trait，`Drop` 时清零。想把它写进日志只能显式调用 [`SecretBytes::expose`]，
/// 而那是一个 review 时一眼可见的调用点。
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// 由字节向量构造（不复制）。
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        SecretBytes(bytes)
    }

    /// 由切片构造。
    pub fn from_slice(bytes: &[u8]) -> Self {
        SecretBytes(bytes.to_vec())
    }

    /// 取出原始字节。请只在马上要把值交给使用者时调用。
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// 字节长度。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 是否为空。
    ///
    /// 正常情况下恒为 `false`：[`SecureStore::put`] 拒绝空值，见
    /// [`PlatformError::SecureStoreInvalidValue`]。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// 安全存储后端的自描述信息。
///
/// 只包含后端名称与「是否为真实系统存储」两个字段，天然不可能携带 secret value。
/// `is_system_store == false` 意味着这是测试用的内存 fake，上层如果在生产路径上
/// 看到它应当立即失败。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SecureStoreDescriptor {
    /// 后端标识，例如 `macos-keychain`、`linux-secret-service`、`in-memory-fake`。
    pub backend: &'static str,
    /// 是否由操作系统托管。内存 fake 为 `false`。
    pub is_system_store: bool,
}

impl fmt::Display for SecureStoreDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = if self.is_system_store {
            "系统存储"
        } else {
            "非系统存储"
        };
        write!(f, "{}（{kind}）", self.backend)
    }
}

/// 安全存储的读写接口。
///
/// 实现必须是 `Send + Sync`：同一个进程里可能有多个线程同时访问凭据库。
pub trait SecureStore: Send + Sync {
    /// 后端自描述信息。
    fn describe(&self) -> SecureStoreDescriptor;

    /// 写入或覆盖 `key` 对应的值。
    ///
    /// 空值被拒绝（[`PlatformError::SecureStoreInvalidValue`]）：不同平台对
    /// 零长度凭据的处理不一致，接受它会让「写过空值」与「从未写入」在某些后端上
    /// 无法区分，而这个区别在密钥管理里是致命的。
    fn put(&self, key: &SecureKey, value: &[u8]) -> Result<(), PlatformError>;

    /// 读取 `key` 对应的值；条目不存在返回 `Ok(None)`。
    ///
    /// **「不存在」和「读不到」必须区分**：凭据库锁定、访问被拒绝一律返回 `Err`，
    /// 绝不伪装成 `Ok(None)`——否则上层会把「读不到密钥」误判成「还没初始化」，
    /// 进而生成一把新密钥并覆盖旧的。
    fn get(&self, key: &SecureKey) -> Result<Option<SecretBytes>, PlatformError>;

    /// 删除 `key` 对应的条目。返回是否真的删掉了东西。
    fn delete(&self, key: &SecureKey) -> Result<bool, PlatformError>;
}

/// 打开当前平台的系统安全存储。
///
/// 成功时返回的实现一定由操作系统托管（`describe().is_system_store == true`）。
/// 没有可用实现时返回 [`PlatformError::SecureStoreUnavailable`]——**绝不**回退到
/// 明文文件，也绝不回退到进程内内存。
///
/// Linux 上会先做一次带超时的 Secret Service 探测（见 [`linux`] 模块），
/// 因此在无 DBus 会话的容器 / CI 里这个函数会**快速返回错误**而不是长时间阻塞。
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn open_system_store() -> Result<Box<dyn SecureStore>, PlatformError> {
    backend::probe()?;
    Ok(Box::new(SystemSecureStore {
        descriptor: SecureStoreDescriptor {
            backend: backend::BACKEND,
            is_system_store: true,
        },
    }))
}

/// 打开当前平台的系统安全存储。
///
/// 本平台没有受支持的系统凭据库，恒定返回
/// [`PlatformError::SecureStoreUnavailable`]。
///
/// 之所以显式写死而不是让 `keyring` 兜底：`keyring` 在未知平台上会**静默**使用
/// 进程内的 `mock` 后端，那会让「密钥已安全保存」变成一句谎话。
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
pub fn open_system_store() -> Result<Box<dyn SecureStore>, PlatformError> {
    Err(PlatformError::SecureStoreUnavailable {
        detail: "当前平台没有受支持的系统凭据库",
    })
}

/// 基于 [`keyring::Entry`] 的系统凭据库实现。
///
/// 不持有任何连接或缓存：每次操作都新建 `Entry`，让平台后端自己管理会话。
/// 这样也避免了「进程长期持有一个已解锁的凭据库句柄」这种扩大攻击面的写法。
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
struct SystemSecureStore {
    descriptor: SecureStoreDescriptor,
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
impl SystemSecureStore {
    /// 构造某个坐标对应的 keyring 条目。
    fn entry(&self, key: &SecureKey) -> Result<keyring::Entry, PlatformError> {
        keyring::Entry::new(SERVICE_NAME, &key.account_name())
            .map_err(|error| map_keyring_error(key.purpose, "打开条目", &error))
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
impl SecureStore for SystemSecureStore {
    fn describe(&self) -> SecureStoreDescriptor {
        self.descriptor
    }

    fn put(&self, key: &SecureKey, value: &[u8]) -> Result<(), PlatformError> {
        reject_empty(key.purpose, value)?;
        self.entry(key)?
            .set_secret(value)
            .map_err(|error| map_keyring_error(key.purpose, "写入", &error))
    }

    fn get(&self, key: &SecureKey) -> Result<Option<SecretBytes>, PlatformError> {
        match self.entry(key)?.get_secret() {
            Ok(bytes) => Ok(Some(SecretBytes::from_vec(bytes))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(map_keyring_error(key.purpose, "读取", &error)),
        }
    }

    fn delete(&self, key: &SecureKey) -> Result<bool, PlatformError> {
        match self.entry(key)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(error) => Err(map_keyring_error(key.purpose, "删除", &error)),
        }
    }
}

/// 拒绝空值。
fn reject_empty(purpose: SecurePurpose, value: &[u8]) -> Result<(), PlatformError> {
    if value.is_empty() {
        return Err(PlatformError::SecureStoreInvalidValue {
            purpose: purpose.as_str(),
            reason: "空值不是有意义的秘密，且部分后端无法把它与「条目不存在」区分",
        });
    }
    Ok(())
}

/// 把 `keyring` 的错误翻译成平台层错误。
///
/// **这是防泄露的关键位置。** 后端错误的 `Display` 可能包含被查询的凭据内容
/// （最典型的是 [`keyring::Error::BadEncoding`]，它直接携带原始字节），
/// 因此这里只读取原文用于**分类**，产出的 [`PlatformError`] 全部由 `&'static str`
/// 构成，也不把原错误挂进 `source()` 链。
///
/// `keyring::Error::NoEntry` 不会走到这里：它在调用点被翻译成 `Ok(None)` / `Ok(false)`。
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn map_keyring_error(
    purpose: SecurePurpose,
    operation: &'static str,
    error: &keyring::Error,
) -> PlatformError {
    let purpose = purpose.as_str();
    match error {
        // 平台明说「拿不到凭据库」。keyring 文档指出这通常是凭据库被锁定，
        // 但也可能是访问规则拒绝，因此再用平台标记做一次细分。
        keyring::Error::NoStorageAccess(_) => match classify(error) {
            Some(Classification::Denied) => PlatformError::SecureStoreDenied { purpose },
            _ => PlatformError::SecureStoreLocked { purpose },
        },
        keyring::Error::PlatformFailure(_) => match classify(error) {
            Some(Classification::Denied) => PlatformError::SecureStoreDenied { purpose },
            Some(Classification::Locked) => PlatformError::SecureStoreLocked { purpose },
            None => PlatformError::SecureStoreBackend {
                purpose,
                operation,
                class: "平台故障",
            },
        },
        // 只用 `get_secret`（字节接口）时不该出现；真出现了也**绝不**转载它携带的字节。
        keyring::Error::BadEncoding(_) => PlatformError::SecureStoreBackend {
            purpose,
            operation,
            class: "凭据编码非法",
        },
        keyring::Error::TooLong(_, _) => PlatformError::SecureStoreBackend {
            purpose,
            operation,
            class: "属性超出平台长度上限",
        },
        keyring::Error::Invalid(_, _) => PlatformError::SecureStoreBackend {
            purpose,
            operation,
            class: "属性非法",
        },
        keyring::Error::Ambiguous(_) => PlatformError::SecureStoreBackend {
            purpose,
            operation,
            class: "同一坐标匹配到多条凭据",
        },
        keyring::Error::NoEntry => PlatformError::SecureStoreBackend {
            purpose,
            operation,
            class: "条目不存在",
        },
        _ => PlatformError::SecureStoreBackend {
            purpose,
            operation,
            class: "未知后端错误",
        },
    }
}

/// 平台标记细分出来的失败类别。
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Classification {
    /// 访问被明确拒绝（用户取消授权、ACL 拒绝）。
    Denied,
    /// 凭据库处于锁定状态且无法交互解锁。
    Locked,
}

/// 用平台模块提供的标记词对后端错误做**尽力而为**的细分。
///
/// 匹配到的原文**不会**被带进返回值，只用来选一个 `&'static str` 类别。
/// 匹配不上就返回 `None`，调用方退回到通用的 `SecureStoreBackend`——
/// 也就是说这个启发式只会让诊断更精确，永远不会让错误消失。
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn classify(error: &keyring::Error) -> Option<Classification> {
    let text = error_chain_text(error);
    if backend::DENIAL_MARKERS.iter().any(|m| text.contains(m)) {
        return Some(Classification::Denied);
    }
    if backend::LOCK_MARKERS.iter().any(|m| text.contains(m)) {
        return Some(Classification::Locked);
    }
    None
}

/// 收集错误链的小写文本，**仅用于分类**，绝不进入返回值。
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn error_chain_text(error: &keyring::Error) -> String {
    use std::error::Error as _;

    let mut text = error.to_string();
    let mut source = error.source();
    // 链长设上限，避免恶意实现构造超长 / 自引用链。
    for _ in 0..8 {
        match source {
            Some(inner) => {
                text.push(' ');
                text.push_str(&inner.to_string());
                source = inner.source();
            }
            None => break,
        }
    }
    text.to_lowercase()
}

/// 仅测试可用：把一批「携带敏感文本的后端错误」喂给真实的错误映射函数。
///
/// 契约测试用它来证明——不是断言、是证明——即便后端把 secret value 拼进了错误消息，
/// 映射出来的 [`PlatformError`] 的 `Display`、`Debug` 与 `source()` 链里也不会有它。
/// 这条路径覆盖了 `keyring` 的每一个错误变体，包括直接携带原始字节的
/// [`keyring::Error::BadEncoding`]。
#[cfg(all(
    any(feature = "test-support", test),
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
pub fn map_leaky_backend_errors_for_test(
    purpose: SecurePurpose,
    leaky: &str,
) -> Vec<PlatformError> {
    let boxed = || -> Box<dyn std::error::Error + Send + Sync> {
        Box::new(std::io::Error::other(leaky.to_owned()))
    };
    let cases = [
        keyring::Error::PlatformFailure(boxed()),
        keyring::Error::NoStorageAccess(boxed()),
        keyring::Error::BadEncoding(leaky.as_bytes().to_vec()),
        keyring::Error::TooLong(leaky.to_owned(), 42),
        keyring::Error::Invalid(leaky.to_owned(), leaky.to_owned()),
        keyring::Error::Ambiguous(Vec::new()),
        keyring::Error::NoEntry,
    ];
    cases[..]
        .iter()
        .map(|error| map_keyring_error(purpose, "写入", error))
        .collect()
}

/// 仅测试可用：非受支持平台上没有 keyring 后端，返回空列表。
#[cfg(all(
    any(feature = "test-support", test),
    not(any(target_os = "macos", target_os = "windows", target_os = "linux"))
))]
pub fn map_leaky_backend_errors_for_test(
    _purpose: SecurePurpose,
    _leaky: &str,
) -> Vec<PlatformError> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nil_workspace() -> WorkspaceId {
        WorkspaceId::from_uuid(uuid::Uuid::nil())
    }

    #[test]
    fn account_name_is_stable() {
        let key = SecureKey::workspace_scoped(nil_workspace(), SecurePurpose::WorkspaceDataKey);
        assert_eq!(
            key.account_name(),
            "00000000-0000-0000-0000-000000000000/-/workspace-data-key"
        );
        assert_eq!(key.service_name(), "envsync");
    }

    #[test]
    fn purpose_tokens_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for purpose in SecurePurpose::ALL {
            assert!(seen.insert(purpose.as_str()), "用途标记重复：{purpose}");
        }
    }

    #[test]
    fn descriptor_display_mentions_backend_kind() {
        let descriptor = SecureStoreDescriptor {
            backend: "in-memory-fake",
            is_system_store: false,
        };
        assert_eq!(descriptor.to_string(), "in-memory-fake（非系统存储）");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn probe_account_cannot_collide_with_real_keys() {
        // 真实 account 的首段一定是 UUID，不可能是 `-`。
        assert!(PROBE_ACCOUNT.starts_with("-/"));
    }
}
