//! 内存 fake：仅供测试，**生产构建不可选**。
//!
//! 这个模块整体挂在 `#[cfg(any(feature = "test-support", test))]` 下。
//! `test-support` 不是默认 feature，也不被任何生产依赖打开；`Cargo.toml` 的
//! `[dev-dependencies]` 里有一条对本 crate 自身的引用来打开它，效果是：
//!
//! * `cargo build` / 下游生产构建 → feature 关闭，[`InMemorySecureStore`] 根本不存在；
//! * `cargo test` / `cargo clippy --all-targets` → feature 打开，测试能用它。
//!
//! 这样「测试替身泄漏到生产」不是靠约定，而是**编译期不可能**。
//!
//! 另外 [`InMemorySecureStore::describe`] 的 `is_system_store` 恒为 `false`：
//! 即使有人绕过 feature 把它塞进生产路径，上层也能一眼识别并拒绝。

use std::collections::BTreeMap;
use std::sync::Mutex;

use zeroize::{Zeroize, Zeroizing};

use super::{SecretBytes, SecureKey, SecureStore, SecureStoreDescriptor};
use crate::PlatformError;

/// 内存中的安全存储替身。
///
/// 行为与真实后端保持一致的部分：覆盖写、`Ok(None)` 表示不存在、`delete` 返回
/// 是否真的删掉了东西、拒绝空值。不一致的部分只有一条：它不持久化，也不受
/// 操作系统保护——所以它永远不该出现在生产构建里。
///
/// 值以 [`Zeroizing`] 保存，因此覆盖、删除与 `Drop` 都会清零内存；
/// [`Drop`] 里另有一次显式清零，让「值不会留在堆上」这件事在代码里可见。
///
/// # 示例
///
/// ```
/// use envsync_platform::secure_store::{SecureKey, SecurePurpose, SecureStore};
/// use envsync_platform::InMemorySecureStore;
/// use envsync_domain::WorkspaceId;
///
/// let store = InMemorySecureStore::new();
/// let key = SecureKey::workspace_scoped(WorkspaceId::generate(), SecurePurpose::WorkspaceDataKey);
/// store.put(&key, b"k")?;
/// assert_eq!(store.get(&key)?.unwrap().expose(), b"k");
/// assert!(store.delete(&key)?);
/// assert!(store.get(&key)?.is_none());
/// # Ok::<(), envsync_platform::PlatformError>(())
/// ```
#[derive(Default)]
pub struct InMemorySecureStore {
    /// account 名称 -> 值。用 `BTreeMap` 让遍历顺序确定，便于测试。
    entries: Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>,
}

impl InMemorySecureStore {
    /// 创建一个空的内存存储。
    pub fn new() -> Self {
        InMemorySecureStore::default()
    }

    /// 当前条目数。
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// 是否没有任何条目。
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// 已存在的 account 名称，按字典序。
    ///
    /// 只返回**名称**，不返回值：测试可以断言命名布局而不必碰到秘密。
    pub fn account_names(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }

    /// 取锁。
    ///
    /// 刻意不对中毒的锁 panic：测试替身在一个线程 panic 之后仍应可用，
    /// 否则一个失败会级联成一堆看不懂的次生失败。
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Zeroizing<Vec<u8>>>> {
        self.entries.lock().unwrap_or_else(|err| err.into_inner())
    }
}

impl SecureStore for InMemorySecureStore {
    fn describe(&self) -> SecureStoreDescriptor {
        SecureStoreDescriptor {
            backend: "in-memory-fake",
            is_system_store: false,
        }
    }

    fn put(&self, key: &SecureKey, value: &[u8]) -> Result<(), PlatformError> {
        super::reject_empty(key.purpose, value)?;
        // 插入会丢弃旧的 `Zeroizing`，旧值随之清零。
        self.lock()
            .insert(key.account_name(), Zeroizing::new(value.to_vec()));
        Ok(())
    }

    fn get(&self, key: &SecureKey) -> Result<Option<SecretBytes>, PlatformError> {
        Ok(self
            .lock()
            .get(&key.account_name())
            .map(|value| SecretBytes::from_slice(value)))
    }

    fn delete(&self, key: &SecureKey) -> Result<bool, PlatformError> {
        // `remove` 返回的 `Zeroizing` 在这里被丢弃，值随之清零。
        Ok(self.lock().remove(&key.account_name()).is_some())
    }
}

impl Drop for InMemorySecureStore {
    fn drop(&mut self) {
        let mut entries = self.lock();
        for value in entries.values_mut() {
            value.zeroize();
        }
        entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_store::SecurePurpose;
    use envsync_domain::WorkspaceId;

    #[test]
    fn describe_marks_itself_as_non_system_store() {
        let store = InMemorySecureStore::new();
        assert!(!store.describe().is_system_store);
        assert_eq!(store.describe().backend, "in-memory-fake");
    }

    #[test]
    fn empty_value_is_rejected() {
        let store = InMemorySecureStore::new();
        let key =
            SecureKey::workspace_scoped(WorkspaceId::generate(), SecurePurpose::WorkspaceDataKey);
        let error = store.put(&key, b"").unwrap_err();
        assert_eq!(error.code(), "platform.secure_store_invalid_value");
        assert!(store.is_empty());
    }

    #[test]
    fn account_names_expose_layout_without_values() {
        let store = InMemorySecureStore::new();
        let workspace = WorkspaceId::generate();
        for purpose in SecurePurpose::ALL {
            store
                .put(&SecureKey::workspace_scoped(workspace, purpose), b"v")
                .unwrap();
        }
        let names = store.account_names();
        assert_eq!(names.len(), SecurePurpose::ALL.len());
        let prefix = format!("{workspace}/-/");
        // 名字里只有工作区、设备占位与用途；值 `v` 不在其中。
        assert!(names.iter().all(|name| name.starts_with(&prefix)));
    }
}
