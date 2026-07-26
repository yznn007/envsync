//! M2 Vault / 轮换测试的共用脚手架。
//!
//! 三条约定：
//!
//! 1. **安全存储用 `InMemorySecureStore`。** 生产路径走
//!    `envsync_platform::secure_store::open_system_store`，但 CI 上没有可用的系统凭据库，
//!    而「有没有凭据库」不是这些测试要验证的东西（那是 `secure_store_contract.rs` 的活）。
//! 2. **时钟单调且可复现。** 快照标识覆盖 `created_at_unix_ms`；用真实时钟会让「同样的
//!    操作是否产生同样的对象」变成一个不可复现的问题。
//! 3. **每台设备一个 [`Workbench`]，共享同一个后端目录。** 这正是多设备场景的真实形状：
//!    后端是唯一的公共媒介，本地状态（安全存储、检查点、草稿库）各自独立。

#![allow(dead_code)]
// 说明：本模块会被多个测试二进制各自完整编译一遍，任何一个二进制用不到的条目都会触发
// `dead_code`。这是共享 test support 模块的固有现象，不是真的死代码。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use envsync_backend::LocalBackend;
use envsync_core::checkpoint::{CheckpointStore, InMemoryCheckpointStore};
use envsync_core::ports::Clock;
use envsync_core::vault::{VaultDeps, VaultService};
use envsync_core::{device_admin, CoreResult};
use envsync_crypto::device::DeviceKeypair;
use envsync_crypto::sealed::SecretId;
use envsync_domain::id::WorkspaceId;
use envsync_platform::secure_store::SecureStore;
use envsync_platform::InMemorySecureStore;

/// 单调前进的假时钟。
///
/// 每次读取 +1 毫秒：既保证「同一次操作里的多个时间戳」互不相同（快照标识因此不会
/// 意外碰撞），又完全可复现。
#[derive(Debug)]
pub struct TickingClock(AtomicU64);

impl TickingClock {
    pub fn new(start: u64) -> Self {
        TickingClock(AtomicU64::new(start))
    }
}

impl Clock for TickingClock {
    fn now_unix_ms(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst)
    }
}

/// 一台设备的完整本地环境。
pub struct Workbench {
    pub workspace: WorkspaceId,
    pub backend_dir: PathBuf,
    pub state_dir: PathBuf,
    pub secure: Arc<InMemorySecureStore>,
    pub checkpoints: Arc<InMemoryCheckpointStore>,
    pub clock: Arc<TickingClock>,
}

impl Workbench {
    /// 在安全存储里建立本设备身份（幂等）。
    pub fn init_device(&self) -> CoreResult<DeviceKeypair> {
        let (keypair, _) = device_admin::init_device(self.secure.as_ref(), self.workspace)?;
        Ok(keypair)
    }

    /// 组装依赖。每次都新开一个后端句柄，模拟「一次命令一个进程」。
    pub fn deps(&self) -> VaultDeps {
        VaultDeps {
            workspace: self.workspace,
            backend: Arc::new(LocalBackend::open(self.backend_dir.clone()).expect("打开后端")),
            secure: Arc::clone(&self.secure) as Arc<dyn SecureStore>,
            checkpoints: Arc::clone(&self.checkpoints) as Arc<dyn CheckpointStore>,
            clock: Arc::clone(&self.clock) as Arc<dyn Clock>,
        }
    }

    /// 打开一个新的服务实例。
    ///
    /// 「重新打开」在这些测试里很重要：它模拟的是「进程重启之后再来一次」，
    /// 也正是幂等恢复必须成立的那个场景。
    pub fn open(&self) -> CoreResult<VaultService> {
        VaultService::open(self.deps(), &self.state_dir)
    }
}

/// 一个工作区 + 一份后端 + 若干设备环境。
pub struct Fixture {
    pub workspace: WorkspaceId,
    root: tempfile::TempDir,
}

impl Default for Fixture {
    fn default() -> Self {
        Fixture::new()
    }
}

impl Fixture {
    pub fn new() -> Self {
        let root = tempfile::tempdir().expect("临时目录");
        std::fs::create_dir_all(root.path().join("backend")).expect("创建后端目录");
        std::fs::create_dir_all(root.path().join("state")).expect("创建状态目录");
        Fixture {
            workspace: WorkspaceId::generate(),
            root,
        }
    }

    pub fn backend_dir(&self) -> PathBuf {
        self.root.path().join("backend")
    }

    /// 建立一台设备的本地环境。
    pub fn device(&self, name: &str) -> Workbench {
        let state_dir = self.root.path().join("state").join(name);
        std::fs::create_dir_all(&state_dir).expect("创建状态目录");
        Workbench {
            workspace: self.workspace,
            backend_dir: self.backend_dir(),
            state_dir,
            secure: Arc::new(InMemorySecureStore::new()),
            checkpoints: Arc::new(InMemoryCheckpointStore::new()),
            clock: Arc::new(TickingClock::new(1_700_000_000_000)),
        }
    }
}

/// 构造一个测试用逻辑秘密标识。
pub fn sid(text: &str) -> SecretId {
    SecretId::parse(text).expect("测试用秘密标识必须合法")
}

/// 取出失败结果里的错误。
///
/// 不能直接用 `unwrap_err`：它要求 `T: Debug`，而 `Plaintext`、`SecretInput`、
/// `VaultService` 都**刻意不实现** `Debug`。换句话说，这个辅助函数的存在本身就是那条
/// 约束仍然成立的证据——哪天有人给它们加上 `Debug`，这里就可以被删掉了。
pub fn err<T>(result: CoreResult<T>) -> envsync_core::CoreError {
    match result {
        Ok(_) => panic!("期望失败，实际却成功了"),
        Err(error) => error,
    }
}

/// 递归收集某个目录下**所有文件**的字节。
///
/// 这是「普通 Blob 扫描不得发现 plaintext」那条测试的取证手段：不看格式、不解码、
/// 不区分对象种类，就是把磁盘上的每一个字节都拿出来找 canary。
pub fn all_files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    collect(dir, &mut out);
    out
}

fn collect(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if let Ok(bytes) = std::fs::read(&path) {
            out.push((path, bytes));
        }
    }
}

/// 断言 `needle` 不出现在目录下任何一个文件的任何一个字节位置。
pub fn assert_no_plaintext(dir: &Path, needle: &[u8]) {
    let files = all_files(dir);
    assert!(
        !files.is_empty(),
        "目录 {} 是空的，这条断言就成了空转",
        dir.display()
    );
    for (path, bytes) in &files {
        assert!(
            !contains(bytes, needle),
            "文件 {} 里出现了明文 canary",
            path.display()
        );
    }
}

/// 朴素子串搜索。数据量是测试规模，可读性比性能重要。
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
