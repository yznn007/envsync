//! 已注册工作区的进程内状态。
//!
//! 此模块只保存由 Rust 注册过的配置、串行执行锁和后台 operation 的取消令牌。
//! `EnvSyncService` 自身并不承诺可跨线程共享（例如某些系统凭据库实现必须保留在调用
//! 线程），因此每个 command 或后台 worker 都在持有工作区锁时就地打开、使用并销毁
//! service；WebView 不能把任意配置路径或后端连接塞进状态层。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use envsync_core::{ApplyCancellation, CoreResult, EnvSyncService, WorkspaceConfig};
use envsync_domain::{OperationId, WorkspaceId};

/// 桌面状态操作失败时的稳定原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopStateError {
    /// 试图重复注册同一个工作区。
    AlreadyRegistered,
    /// 调用方引用了未注册工作区。
    UnknownWorkspace,
    /// 同一 operation ID 已被一个后台 worker 占用。
    OperationAlreadyActive,
    /// operation 不存在、已经结束，或不属于请求中的工作区。
    OperationNotActive,
    /// 进程内锁已因其他线程 panic 而不可再安全使用。
    Unavailable,
}

impl DesktopStateError {
    /// 返回可交给 UI 本地化的稳定错误码。
    pub const fn code(self) -> &'static str {
        match self {
            DesktopStateError::AlreadyRegistered => "desktop.workspace_already_registered",
            DesktopStateError::UnknownWorkspace => "desktop.workspace_not_registered",
            DesktopStateError::OperationAlreadyActive => "desktop.operation_already_active",
            DesktopStateError::OperationNotActive => "operation.not_cancellable",
            DesktopStateError::Unavailable => "desktop.workspace_unavailable",
        }
    }
}

/// 一个已注册工作区的线程安全描述符。
struct WorkspaceRegistration {
    config: WorkspaceConfig,
    execution_lock: Mutex<()>,
}

/// 由后台 worker 和 core 共同使用的取消令牌。
///
/// 令牌从“可取消”原子地转换为“已请求取消”或“安全窗口已关闭”。UI 可以请求取消，但不能
/// 重新启用一个 operation。core 只在 journal 的可中止边界读取它，因此该状态绝不直接
/// 中断文件写入线程。
#[derive(Debug, Clone)]
pub(crate) struct CancellationToken {
    state: Arc<AtomicU8>,
}

impl Default for CancellationToken {
    fn default() -> Self {
        CancellationToken {
            state: Arc::new(AtomicU8::new(Self::OPEN)),
        }
    }
}

impl CancellationToken {
    const OPEN: u8 = 0;
    const REQUESTED: u8 = 1;
    const CLOSED: u8 = 2;

    /// 记录一次不可逆的取消请求。
    ///
    /// 只有取消窗口仍开放或已经被本次请求占用时返回 `true`；一旦 core 已关闭窗口，调用方
    /// 必须明确报告不可取消，而不是让 UI 误以为发布会被阻止。
    fn request_cancel(&self) -> bool {
        loop {
            match self.state.load(Ordering::Acquire) {
                Self::OPEN => {
                    if self
                        .state
                        .compare_exchange(
                            Self::OPEN,
                            Self::REQUESTED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                Self::REQUESTED => return true,
                Self::CLOSED => return false,
                _ => return false,
            }
        }
    }
}

impl ApplyCancellation for CancellationToken {
    fn is_cancelled(&self) -> bool {
        self.state.load(Ordering::Acquire) == Self::REQUESTED
    }

    fn close_cancellation_window(&self) -> bool {
        self.state
            .compare_exchange(
                Self::OPEN,
                Self::CLOSED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

/// 一个仍由后台 worker 持有的 operation。
struct ActiveBackgroundOperation {
    workspace: WorkspaceId,
    cancellation: CancellationToken,
}

/// 后台 operation 注册表。
///
/// 该表只追踪存活 worker，不替代持久 journal。worker 完成后条目会被删除，但 core 的
/// operation 记录仍保留给 History/Recovery 页面；因此对已发布或已结束 operation 的取消
/// 会明确返回“不可取消”，而不是假装线程仍能被安全打断。
#[derive(Default)]
struct OperationRegistry {
    active: Mutex<BTreeMap<OperationId, ActiveBackgroundOperation>>,
}

impl OperationRegistry {
    fn begin(
        &self,
        workspace: WorkspaceId,
        operation: OperationId,
    ) -> Result<CancellationToken, DesktopStateError> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| DesktopStateError::Unavailable)?;
        if active.contains_key(&operation) {
            return Err(DesktopStateError::OperationAlreadyActive);
        }
        let cancellation = CancellationToken::default();
        active.insert(
            operation,
            ActiveBackgroundOperation {
                workspace,
                cancellation: cancellation.clone(),
            },
        );
        Ok(cancellation)
    }

    fn request_cancel(
        &self,
        workspace: WorkspaceId,
        operation: OperationId,
    ) -> Result<(), DesktopStateError> {
        let active = self
            .active
            .lock()
            .map_err(|_| DesktopStateError::Unavailable)?;
        let Some(entry) = active.get(&operation) else {
            return Err(DesktopStateError::OperationNotActive);
        };
        if entry.workspace != workspace {
            return Err(DesktopStateError::OperationNotActive);
        }
        if entry.cancellation.request_cancel() {
            Ok(())
        } else {
            Err(DesktopStateError::OperationNotActive)
        }
    }

    fn finish(&self, operation: OperationId) {
        // 若 mutex 已 poisoned，宁可保留 active 标记以阻止进程退出，也不能在未知状态下
        // 把正在运行的 journaled operation 当作已结束。
        if let Ok(mut active) = self.active.lock() {
            active.remove(&operation);
        }
    }

    fn has_active_operations(&self) -> bool {
        // 同样以保守策略处理 poisoned mutex：窗口关闭和进程退出必须继续被阻止。
        self.active
            .lock()
            .map(|active| !active.is_empty())
            .unwrap_or(true)
    }
}

/// Tauri 进程的受限状态。
///
/// 工作区以其强类型 ID 索引，而不是以路径、URL 或用户输入的任意字符串索引。
#[derive(Default)]
pub struct DesktopState {
    workspaces: Mutex<BTreeMap<WorkspaceId, Arc<WorkspaceRegistration>>>,
    /// 同步 command（例如 rollback）持有的短生命周期操作计数。
    active_operations: AtomicUsize,
    /// 长操作的后台 worker 与取消令牌。
    background_operations: Arc<OperationRegistry>,
}

impl DesktopState {
    /// 注册一个已经由 Rust 校验过的工作区配置。
    pub fn register(&self, config: WorkspaceConfig) -> Result<WorkspaceId, DesktopStateError> {
        let workspace = config.workspace_id;
        let mut workspaces = self
            .workspaces
            .lock()
            .map_err(|_| DesktopStateError::Unavailable)?;
        if workspaces.contains_key(&workspace) {
            return Err(DesktopStateError::AlreadyRegistered);
        }
        workspaces.insert(
            workspace,
            Arc::new(WorkspaceRegistration {
                config,
                execution_lock: Mutex::new(()),
            }),
        );
        Ok(workspace)
    }

    /// 在已注册工作区的串行安全边界内打开并使用 application service。
    ///
    /// 持锁期间 service 的生命周期局限在调用线程，因此不会把平台凭据句柄或 SQLite
    /// 连接错误地跨线程共享；同一 workspace 的变更则始终串行。
    pub fn with_service<T>(
        &self,
        workspace: WorkspaceId,
        operation: impl FnOnce(&mut EnvSyncService) -> CoreResult<T>,
    ) -> Result<CoreResult<T>, DesktopStateError> {
        let registration = self.registration(workspace)?;
        with_registered_service(&registration, operation)
    }

    /// 启动一个自持的后台 operation。
    ///
    /// 返回的 lease 同时持有工作区注册信息与取消令牌；把它移动到 worker 后，即使 Tauri
    /// command 已返回，窗口生命周期仍能看见该 operation 并阻止进程退出。
    pub(crate) fn start_background_operation(
        &self,
        workspace: WorkspaceId,
        operation: OperationId,
    ) -> Result<BackgroundOperation, DesktopStateError> {
        let registration = self.registration(workspace)?;
        let cancellation = self.background_operations.begin(workspace, operation)?;
        Ok(BackgroundOperation {
            registration,
            registry: Arc::clone(&self.background_operations),
            operation,
            cancellation,
        })
    }

    /// 请求取消仍由后台 worker 持有的 operation。
    ///
    /// 此方法不取得 workspace 的执行锁：这样 worker 正在运行时，取消请求仍可及时写入
    /// 原子令牌。真正是否能取消由 core 在 journal 安全边界决定。
    pub(crate) fn request_cancel(
        &self,
        workspace: WorkspaceId,
        operation: OperationId,
    ) -> Result<(), DesktopStateError> {
        self.registration(workspace)?;
        self.background_operations
            .request_cancel(workspace, operation)
    }

    /// 验证 workspace 已由 Rust 注册。
    pub fn contains(&self, workspace: WorkspaceId) -> Result<bool, DesktopStateError> {
        let workspaces = self
            .workspaces
            .lock()
            .map_err(|_| DesktopStateError::Unavailable)?;
        Ok(workspaces.contains_key(&workspace))
    }

    /// 标记一个 journaled operation 正在同步 command 中执行。
    pub(crate) fn begin_operation(&self) -> ActiveOperationGuard<'_> {
        self.active_operations.fetch_add(1, Ordering::AcqRel);
        ActiveOperationGuard { state: self }
    }

    /// 是否存在不能被进程退出中断的 operation。
    pub(crate) fn has_active_operations(&self) -> bool {
        self.active_operations.load(Ordering::Acquire) != 0
            || self.background_operations.has_active_operations()
    }

    fn registration(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Arc<WorkspaceRegistration>, DesktopStateError> {
        let workspaces = self
            .workspaces
            .lock()
            .map_err(|_| DesktopStateError::Unavailable)?;
        workspaces
            .get(&workspace)
            .cloned()
            .ok_or(DesktopStateError::UnknownWorkspace)
    }
}

/// 一个自持的后台 worker lease。
///
/// 只要它还活着，operation 就可被取消，窗口也不能安全退出。`Drop` 负责无论成功、失败
/// 或线程 panic 都把 operation 从活动表移除。
pub(crate) struct BackgroundOperation {
    registration: Arc<WorkspaceRegistration>,
    registry: Arc<OperationRegistry>,
    operation: OperationId,
    cancellation: CancellationToken,
}

impl BackgroundOperation {
    /// 在本 worker 所属工作区的串行边界内打开 application service。
    pub(crate) fn with_service<T>(
        &self,
        work: impl FnOnce(&mut EnvSyncService, &CancellationToken) -> CoreResult<T>,
    ) -> Result<CoreResult<T>, DesktopStateError> {
        with_registered_service(&self.registration, |service| {
            work(service, &self.cancellation)
        })
    }
}

impl Drop for BackgroundOperation {
    fn drop(&mut self) {
        self.registry.finish(self.operation);
    }
}

/// 在单个已注册工作区的互斥边界内执行 service 调用。
fn with_registered_service<T>(
    registration: &WorkspaceRegistration,
    operation: impl FnOnce(&mut EnvSyncService) -> CoreResult<T>,
) -> Result<CoreResult<T>, DesktopStateError> {
    let _guard = registration
        .execution_lock
        .lock()
        .map_err(|_| DesktopStateError::Unavailable)?;
    let mut service = match EnvSyncService::open(registration.config.clone()) {
        Ok(service) => service,
        Err(error) => return Ok(Err(error)),
    };
    Ok(operation(&mut service))
}

/// 保证 activity 计数会在 command 返回时撤销。
pub(crate) struct ActiveOperationGuard<'a> {
    state: &'a DesktopState,
}

impl Drop for ActiveOperationGuard<'_> {
    fn drop(&mut self) {
        self.state.active_operations.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use envsync_core::ApplyCancellation;
    use envsync_domain::{OperationId, WorkspaceId};

    use super::{DesktopState, DesktopStateError, OperationRegistry};

    #[test]
    fn active_operation_guard_keeps_exit_gate_open_until_completion() {
        let state = DesktopState::default();
        assert!(!state.has_active_operations());
        let guard = state.begin_operation();
        assert!(state.has_active_operations());
        drop(guard);
        assert!(!state.has_active_operations());
    }

    #[test]
    fn background_operation_can_be_cancelled_without_its_execution_lock() {
        let registry = OperationRegistry::default();
        let workspace = WorkspaceId::generate();
        let operation = OperationId::generate();
        let cancellation = registry.begin(workspace, operation).expect("登记后台操作");

        assert!(registry.has_active_operations());
        registry
            .request_cancel(workspace, operation)
            .expect("取消请求不应等待 worker 锁");
        assert!(cancellation.is_cancelled());

        registry.finish(operation);
        assert!(!registry.has_active_operations());

        let closed_operation = OperationId::generate();
        let closed = registry
            .begin(workspace, closed_operation)
            .expect("登记第二个后台操作");
        assert!(closed.close_cancellation_window());
        assert_eq!(
            registry.request_cancel(workspace, closed_operation),
            Err(DesktopStateError::OperationNotActive),
            "不可逆边界关闭后不得把取消伪装成已接受"
        );
    }
}
