//! M0 验收测试（任务 7 / 10 / 11 / 13）共用的夹具与内存 fake。
//!
//! 这里只放**没有任何 I/O 副作用**的构造器，以及三个端口（[`Observer`]、
//! [`FileMutator`]、[`BlobSource`]）的内存实现。真实文件系统与真实后端由
//! `file_sync_service.rs` 和 `recovery.rs` 自己用 tempdir 搭建。
//!
//! 一个额外的小工具是 [`StateProbe`]：它在同一个 journal 数据库上再开一个只读连接，
//! 让测试可以在「事务进行到某一步」的瞬间采样操作状态，从而断言状态**序列**而不是
//! 只断言终态。
#![allow(dead_code)]
// 说明：本模块会被 4 个测试二进制各自完整编译一遍，任何一个二进制用不到的条目都会
// 触发 `dead_code`。这是共享 test support 模块的固有现象，不是真的死代码。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use envsync_backend::{Backend, BackendDescriptor, BackendError};
use envsync_core::config::{
    BackendConfig, DeviceConfig, ResourceConfig, WorkspaceConfig, CONFIG_VERSION,
    DEFAULT_COMMENT_PREFIX,
};
use envsync_core::error::{CoreError, CoreResult};
use envsync_core::planner::BlobSource;
use envsync_core::ports::{ActionReceipt, FileMutator, Observer};
use envsync_core::recovery::PlanSource;
use envsync_domain::{
    Action, ActionKind, ActionTarget, BackupPolicy, BlobId, DesiredDisposition, DeviceId, Digest32,
    FileMode, ObjectId, Observation, ObservedState, OperationId, PermissionSummary, Plan, PlanId,
    PresentFile, ResourceEntry, ResourceId, ResourcePolicy, Risk, RollbackCapability, SnapshotId,
    StateRoot, VerifyRule, WorkspaceId, WorkspaceRef,
};
use envsync_storage::{Journal, OperationState};

// ---------------------------------------------------------------------------
// 固定常量：所有测试共用，保证输出确定
// ---------------------------------------------------------------------------

/// 一个合法的 64 位小写十六进制设备种子（设备 A）。
pub const SEED_A: &str = "3a7f1c92b4de5068a1cf23947db6e50f8c41a2937be05d6c1f83a4b72e90cd15";
/// 另一个合法设备种子（设备 B，用于模拟第二台设备）。
pub const SEED_B: &str = "9c02e5471ab38df6205e94c7130a6b8fe2d47a95c60b381fe74a2d5093bc1607";
/// 固定工作区标识，保证跨运行可复现。
pub const WORKSPACE_UUID: &str = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
/// 固定时钟读数。
pub const FIXED_NOW: u64 = 1_700_000_000_000;

/// 构造资源标识；测试里的标识必须合法。
pub fn rid(text: &str) -> ResourceId {
    ResourceId::parse(text).expect("测试用资源标识必须合法")
}

/// 固定工作区标识。
pub fn workspace_id() -> WorkspaceId {
    WORKSPACE_UUID
        .parse::<WorkspaceId>()
        .expect("测试用工作区标识必须合法")
}

/// 固定设备标识。
pub fn device_id() -> DeviceId {
    DeviceId::derive(b"envsync-acceptance-test-device")
}

/// 文件内容摘要，与平台层使用同一域标签。
pub fn digest_of(bytes: &[u8]) -> Digest32 {
    envsync_core::planner::content_digest(bytes)
}

// ---------------------------------------------------------------------------
// 配置与领域对象构造器
// ---------------------------------------------------------------------------

/// 构造单个资源配置（授权根固定为 `home`）。
pub fn resource_config(
    id: &str,
    target: &str,
    mode: FileMode,
    disposition: DesiredDisposition,
) -> ResourceConfig {
    ResourceConfig {
        id: rid(id),
        root: "home".to_owned(),
        target: target.to_owned(),
        mode,
        disposition,
        policy: ResourcePolicy::default(),
        comment_prefix: DEFAULT_COMMENT_PREFIX.to_owned(),
        // M1 新增：默认是「全局资源、无设备覆盖」。
        selector: None,
        device_overrides: BTreeMap::new(),
    }
}

/// 构造一份完整工作区配置。所有路径都由调用方给出，本函数不创建任何目录。
pub fn workspace_config(
    device_name: &str,
    seed_hex: &str,
    backend_path: &Path,
    state_dir: &Path,
    home_root: &Path,
    resources: Vec<ResourceConfig>,
) -> WorkspaceConfig {
    let mut roots = BTreeMap::new();
    roots.insert("home".to_owned(), home_root.to_path_buf());
    WorkspaceConfig {
        version: CONFIG_VERSION,
        workspace_id: workspace_id(),
        device: DeviceConfig {
            name: device_name.to_owned(),
            seed_hex: seed_hex.to_owned(),
        },
        backend: BackendConfig::Local {
            path: backend_path.to_path_buf(),
        },
        state_dir: state_dir.to_path_buf(),
        roots,
        // M1 新增：不声明标签与能力的最小 Profile。
        profile: envsync_core::DeviceProfileConfig::default(),
        resources,
    }
}

/// 构造 State Root 中的一条资源条目。
pub fn entry(
    id: &str,
    disposition: DesiredDisposition,
    blob: Option<BlobId>,
    mode: FileMode,
) -> ResourceEntry {
    ResourceEntry {
        resource: rid(id),
        disposition,
        blob,
        mode,
        policy: ResourcePolicy::default(),
    }
}

/// 由条目集合构造 State Root。
pub fn state_root(entries: Vec<ResourceEntry>) -> StateRoot {
    StateRoot::from_entries(entries).expect("测试用 State Root 必须合法")
}

/// 授权根 `home` 下的动作目标。
pub fn target(path: &str) -> ActionTarget {
    ActionTarget {
        root: "home".to_owned(),
        segments: path.split('/').map(str::to_owned).collect(),
    }
}

/// 构造一个写入类动作。
pub fn write_action(
    resource: &str,
    path: &str,
    before: Option<Digest32>,
    after: Digest32,
    content: BlobId,
) -> Action {
    Action {
        resource: rid(resource),
        kind: if before.is_some() {
            ActionKind::ReplaceFile
        } else {
            ActionKind::CreateFile
        },
        target: target(path),
        expected_before: before,
        expected_after: Some(after),
        content: Some(content),
        risk: if before.is_some() {
            Risk::Medium
        } else {
            Risk::Low
        },
        backup: if before.is_some() {
            BackupPolicy::Required
        } else {
            BackupPolicy::NotApplicable
        },
        rollback: RollbackCapability::Exact,
        unix_mode: None,
        secret: false,
        verify: VerifyRule::ExpectDigest(after),
    }
}

/// 构造一个删除动作。
pub fn delete_action(resource: &str, path: &str, before: Digest32) -> Action {
    Action {
        resource: rid(resource),
        kind: ActionKind::DeleteFile,
        target: target(path),
        expected_before: Some(before),
        expected_after: None,
        content: None,
        risk: Risk::High,
        backup: BackupPolicy::Required,
        rollback: RollbackCapability::Exact,
        unix_mode: None,
        secret: false,
        verify: VerifyRule::ExpectAbsent,
    }
}

/// 由动作构造计划；`publish` 决定 `next_ref` 是否前进（即是否需要 CAS）。
pub fn plan_of(actions: Vec<Action>, base_revision: u64, publish: bool) -> Plan {
    plan_of_with(actions, vec![], base_revision, publish)
}

/// 同 [`plan_of`]，但允许附加诊断。
pub fn plan_of_with(
    actions: Vec<Action>,
    diagnostics: Vec<envsync_domain::Diagnostic>,
    base_revision: u64,
    publish: bool,
) -> Plan {
    let workspace = workspace_id();
    let snapshot = SnapshotId::of(b"acceptance-snapshot");
    let base_ref = WorkspaceRef {
        format_version: envsync_domain::REF_FORMAT_VERSION,
        workspace,
        revision: base_revision,
        head: if base_revision == 0 {
            None
        } else {
            Some(SnapshotId::of(b"previous-snapshot"))
        },
    };
    let next_ref = if publish {
        base_ref.advance(snapshot)
    } else {
        base_ref.clone()
    };
    Plan::new(
        workspace,
        device_id(),
        snapshot,
        base_revision,
        next_ref,
        vec![],
        actions,
        diagnostics,
        FIXED_NOW,
    )
}

// ---------------------------------------------------------------------------
// 内存 Observer
// ---------------------------------------------------------------------------

/// 内存观察器：完全不接触真实文件系统。
///
/// 目标以 [`ActionTarget::display_path`] 作为键，因此同一个资源的观察、读取和摘要
/// 查询三条路径看到的是同一份内容——这正是真实 `PlatformObserver` 的性质。
#[derive(Default)]
pub struct FakeObserver {
    files: Mutex<BTreeMap<String, Vec<u8>>>,
    forced: Mutex<BTreeMap<String, ObservedState>>,
}

impl FakeObserver {
    /// 构造空观察器（所有目标都是 `Absent`）。
    pub fn new() -> Self {
        FakeObserver::default()
    }

    /// 放置一个「存在且可读」的目标。
    pub fn set_file(&self, target: &ActionTarget, bytes: &[u8]) {
        self.files
            .lock()
            .unwrap()
            .insert(target.display_path(), bytes.to_vec());
    }

    /// 移除目标，使其变为 `Absent`。
    pub fn remove_file(&self, target: &ActionTarget) {
        self.files.lock().unwrap().remove(&target.display_path());
    }

    /// 强制某个目标的观察状态（用于注入 `Unreadable` / `Unsupported` / `Excluded`）。
    pub fn force_state(&self, target: &ActionTarget, state: ObservedState) {
        self.forced
            .lock()
            .unwrap()
            .insert(target.display_path(), state);
    }

    /// 构建器风格：放置文件后返回自身。
    pub fn with_file(self, target: &ActionTarget, bytes: &[u8]) -> Self {
        self.set_file(target, bytes);
        self
    }

    /// 构建器风格：强制状态后返回自身。
    pub fn with_state(self, target: &ActionTarget, state: ObservedState) -> Self {
        self.force_state(target, state);
        self
    }

    fn bytes_of(&self, target: &ActionTarget) -> Option<Vec<u8>> {
        self.files
            .lock()
            .unwrap()
            .get(&target.display_path())
            .cloned()
    }
}

impl Observer for FakeObserver {
    fn observe(
        &self,
        resource: &ResourceId,
        target: &ActionTarget,
        _policy: &ResourcePolicy,
    ) -> Observation {
        if let Some(state) = self.forced.lock().unwrap().get(&target.display_path()) {
            return Observation::new(resource.clone(), state.clone(), FIXED_NOW);
        }
        let state = match self.bytes_of(target) {
            Some(bytes) => ObservedState::Present(PresentFile {
                content_digest: digest_of(&bytes),
                size: bytes.len() as u64,
                mtime_unix_ms: None,
                permissions: PermissionSummary {
                    readonly: false,
                    unix_mode: Some(0o644),
                },
                managed_digest: None,
            }),
            None => ObservedState::Absent,
        };
        Observation::new(resource.clone(), state, FIXED_NOW)
    }

    fn read(&self, target: &ActionTarget, _policy: &ResourcePolicy) -> CoreResult<Vec<u8>> {
        self.bytes_of(target).ok_or_else(|| {
            CoreError::Platform(envsync_platform::PlatformError::io(
                "读取目标文件",
                &std::io::Error::new(std::io::ErrorKind::NotFound, "内存 fake：目标不存在"),
            ))
        })
    }

    fn current_digest(
        &self,
        target: &ActionTarget,
        _policy: &ResourcePolicy,
    ) -> CoreResult<Option<Digest32>> {
        Ok(self.bytes_of(target).map(|bytes| digest_of(&bytes)))
    }
}

// ---------------------------------------------------------------------------
// 内存 BlobSource / PlanSource
// ---------------------------------------------------------------------------

/// 内存 Blob 源。
#[derive(Default)]
pub struct FakeBlobs(Mutex<BTreeMap<BlobId, Vec<u8>>>);

impl FakeBlobs {
    /// 构造空 Blob 源。
    pub fn new() -> Self {
        FakeBlobs::default()
    }

    /// 写入内容并返回其标识。
    pub fn insert(&self, bytes: &[u8]) -> BlobId {
        let id = BlobId::of(bytes);
        self.0.lock().unwrap().insert(id, bytes.to_vec());
        id
    }
}

impl BlobSource for FakeBlobs {
    fn blob(&self, id: BlobId) -> CoreResult<Vec<u8>> {
        self.0
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or_else(|| CoreError::MissingObject(format!("Blob {}", id.short())))
    }
}

/// 内存计划源，供恢复引擎取回原始计划。
#[derive(Default)]
pub struct FakePlans(Mutex<BTreeMap<PlanId, Plan>>);

impl FakePlans {
    /// 构造空计划源。
    pub fn new() -> Self {
        FakePlans::default()
    }

    /// 保存计划。
    pub fn insert(&self, plan: &Plan) {
        self.0.lock().unwrap().insert(plan.id(), plan.clone());
    }
}

impl PlanSource for FakePlans {
    fn plan(&self, id: PlanId) -> CoreResult<Option<Plan>> {
        Ok(self.0.lock().unwrap().get(&id).cloned())
    }
}

// ---------------------------------------------------------------------------
// 状态探针：在事务中途采样操作状态
// ---------------------------------------------------------------------------

/// 在同一个 journal 数据库上另开一条连接，用于在事务进行到某一步时采样状态。
pub struct StateProbe {
    journal: Mutex<Journal>,
    samples: Mutex<Vec<(String, OperationState)>>,
}

impl StateProbe {
    /// 在给定数据库文件上打开探针。
    pub fn open(path: &Path) -> Arc<Self> {
        Arc::new(StateProbe {
            journal: Mutex::new(Journal::open(path).expect("打开探针连接")),
            samples: Mutex::new(Vec::new()),
        })
    }

    /// 采样当前唯一未完成操作的状态。
    pub fn sample(&self, label: &str) {
        let journal = self.journal.lock().unwrap();
        if let Ok(records) = journal.list_unfinished() {
            if let Some(record) = records.first() {
                self.samples
                    .lock()
                    .unwrap()
                    .push((label.to_owned(), record.state));
            }
        }
    }

    /// 全部采样点。
    pub fn samples(&self) -> Vec<(String, OperationState)> {
        self.samples.lock().unwrap().clone()
    }

    /// 某个采样点上观察到的状态。
    pub fn state_at(&self, label: &str) -> Option<OperationState> {
        self.samples()
            .into_iter()
            .find(|(name, _)| name == label)
            .map(|(_, state)| state)
    }
}

// ---------------------------------------------------------------------------
// 可采样的后端包装
// ---------------------------------------------------------------------------

/// 包装任意后端，在 CAS 发生的瞬间采样 journal 状态。
pub struct ProbingBackend<'a> {
    inner: &'a dyn Backend,
    probe: Arc<StateProbe>,
}

impl<'a> ProbingBackend<'a> {
    /// 包装后端。
    pub fn new(inner: &'a dyn Backend, probe: Arc<StateProbe>) -> Self {
        ProbingBackend { inner, probe }
    }
}

impl Backend for ProbingBackend<'_> {
    fn describe(&self) -> BackendDescriptor {
        self.inner.describe()
    }

    fn get_ref(&self, workspace: WorkspaceId) -> Result<WorkspaceRef, BackendError> {
        self.inner.get_ref(workspace)
    }

    fn compare_and_swap_ref(
        &self,
        workspace: WorkspaceId,
        expected_revision: u64,
        next: &WorkspaceRef,
    ) -> Result<(), BackendError> {
        // CAS 之前的瞬间：此时应当刚刚完成 preflight，本地一个字节都还没动。
        self.probe.sample("cas");
        self.inner
            .compare_and_swap_ref(workspace, expected_revision, next)
    }

    fn get_object(&self, id: ObjectId) -> Result<Vec<u8>, BackendError> {
        self.inner.get_object(id)
    }

    fn put_object(&self, id: ObjectId, bytes: &[u8]) -> Result<(), BackendError> {
        self.inner.put_object(id, bytes)
    }

    fn has_object(&self, id: ObjectId) -> Result<bool, BackendError> {
        self.inner.has_object(id)
    }

    fn list_objects(&self, prefix: &str) -> Result<Vec<ObjectId>, BackendError> {
        self.inner.list_objects(prefix)
    }
}

// ---------------------------------------------------------------------------
// 内存 FileMutator
// ---------------------------------------------------------------------------

/// 变更器收到的一次调用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutatorCall {
    /// 预检。
    Preflight(String),
    /// 应用。
    Apply(String),
    /// 验证。
    Verify(String),
    /// 回滚。
    Rollback(String),
    /// 清理暂存文件。
    Cleanup(String),
}

impl MutatorCall {
    /// 该调用涉及的资源标识文本。
    pub fn resource(&self) -> &str {
        match self {
            MutatorCall::Preflight(id)
            | MutatorCall::Apply(id)
            | MutatorCall::Verify(id)
            | MutatorCall::Rollback(id)
            | MutatorCall::Cleanup(id) => id,
        }
    }
}

/// 内存文件变更器：精确记录调用顺序，并可在任意资源上注入失败。
#[derive(Default)]
pub struct FakeMutator {
    calls: Mutex<Vec<MutatorCall>>,
    fail_preflight: BTreeSet<String>,
    fail_apply: BTreeSet<String>,
    fail_verify: BTreeSet<String>,
    fail_rollback: BTreeSet<String>,
    staged_per_action: usize,
    probe: Option<Arc<StateProbe>>,
}

impl FakeMutator {
    /// 构造一个全部成功的变更器。
    pub fn new() -> Self {
        FakeMutator::default()
    }

    /// 让指定资源的 preflight 失败。
    pub fn fail_preflight(mut self, resource: &str) -> Self {
        self.fail_preflight.insert(resource.to_owned());
        self
    }

    /// 让指定资源的 apply 失败。
    pub fn fail_apply(mut self, resource: &str) -> Self {
        self.fail_apply.insert(resource.to_owned());
        self
    }

    /// 让指定资源的 verify 失败。
    pub fn fail_verify(mut self, resource: &str) -> Self {
        self.fail_verify.insert(resource.to_owned());
        self
    }

    /// 让指定资源的 rollback 失败。
    pub fn fail_rollback(mut self, resource: &str) -> Self {
        self.fail_rollback.insert(resource.to_owned());
        self
    }

    /// 设置每个动作「清理暂存文件」时报告的数量。
    pub fn staged_per_action(mut self, count: usize) -> Self {
        self.staged_per_action = count;
        self
    }

    /// 绑定状态探针。
    pub fn with_probe(mut self, probe: Arc<StateProbe>) -> Self {
        self.probe = Some(probe);
        self
    }

    /// 全部调用记录。
    pub fn calls(&self) -> Vec<MutatorCall> {
        self.calls.lock().unwrap().clone()
    }

    /// 某一类调用涉及的资源序列。
    pub fn sequence_of(&self, pick: fn(&MutatorCall) -> bool) -> Vec<String> {
        self.calls()
            .iter()
            .filter(|call| pick(call))
            .map(|call| call.resource().to_owned())
            .collect()
    }

    /// `apply` 的调用次数。
    pub fn apply_count(&self) -> usize {
        self.sequence_of(|call| matches!(call, MutatorCall::Apply(_)))
            .len()
    }

    /// `apply` 的资源顺序。
    pub fn applied(&self) -> Vec<String> {
        self.sequence_of(|call| matches!(call, MutatorCall::Apply(_)))
    }

    /// `rollback` 的资源顺序。
    pub fn rolled_back(&self) -> Vec<String> {
        self.sequence_of(|call| matches!(call, MutatorCall::Rollback(_)))
    }

    /// `cleanup_staged` 的资源顺序。
    pub fn cleaned(&self) -> Vec<String> {
        self.sequence_of(|call| matches!(call, MutatorCall::Cleanup(_)))
    }

    fn record(&self, call: MutatorCall) {
        self.calls.lock().unwrap().push(call);
    }
}

/// 注入「应用失败」时使用的阶段名。
pub const FAKE_APPLY_STAGE: &str = "fake_apply";

/// 注入的「应用失败」错误文本；测试据此断言 journal 里保留了应用侧原因。
pub const FAKE_APPLY_FAILURE: &str = "注入故障：fake_apply";

/// 注入的「回滚失败」错误文本；测试据此断言 journal 里保留了回滚侧原因。
pub const FAKE_ROLLBACK_FAILURE: &str = "fake_rollback：无法还原";

impl FileMutator for FakeMutator {
    fn preflight(&self, action: &Action) -> CoreResult<()> {
        self.record(MutatorCall::Preflight(action.resource.to_string()));
        if let Some(probe) = &self.probe {
            probe.sample(&format!("preflight:{}", action.resource));
        }
        if self.fail_preflight.contains(action.resource.as_str()) {
            return Err(CoreError::Platform(
                envsync_platform::PlatformError::StaleObservation {
                    expected: action.expected_before,
                    actual: None,
                },
            ));
        }
        Ok(())
    }

    fn apply(
        &self,
        _operation: OperationId,
        action: &Action,
        _content: Option<&[u8]>,
    ) -> CoreResult<ActionReceipt> {
        self.record(MutatorCall::Apply(action.resource.to_string()));
        if let Some(probe) = &self.probe {
            probe.sample(&format!("apply:{}", action.resource));
        }
        if self.fail_apply.contains(action.resource.as_str()) {
            return Err(CoreError::Platform(
                envsync_platform::PlatformError::FaultInjected {
                    stage: FAKE_APPLY_STAGE,
                },
            ));
        }
        Ok(ActionReceipt {
            resource: action.resource.clone(),
            backup_path: action
                .expected_before
                .map(|digest| PathBuf::from(format!("/fake/backup/{}", digest.short()))),
            original_digest: action.expected_before,
            applied_digest: action.expected_after,
            guarantee: RollbackCapability::Exact,
        })
    }

    fn verify(&self, action: &Action) -> CoreResult<()> {
        self.record(MutatorCall::Verify(action.resource.to_string()));
        if let Some(probe) = &self.probe {
            probe.sample(&format!("verify:{}", action.resource));
        }
        if self.fail_verify.contains(action.resource.as_str()) {
            return Err(CoreError::Platform(
                envsync_platform::PlatformError::VerificationFailed {
                    expected: action.expected_after,
                    actual: None,
                },
            ));
        }
        Ok(())
    }

    fn rollback(&self, action: &Action, _receipt: &ActionReceipt) -> CoreResult<()> {
        self.record(MutatorCall::Rollback(action.resource.to_string()));
        if self.fail_rollback.contains(action.resource.as_str()) {
            return Err(CoreError::Rollback(format!(
                "{FAKE_ROLLBACK_FAILURE}（{}）",
                action.resource
            )));
        }
        Ok(())
    }

    fn cleanup_staged(&self, _operation: OperationId, action: &Action) -> CoreResult<usize> {
        self.record(MutatorCall::Cleanup(action.resource.to_string()));
        Ok(self.staged_per_action)
    }
}

// ---------------------------------------------------------------------------
// journal 断言小工具
// ---------------------------------------------------------------------------

/// 读取某个操作的当前状态；不存在时 panic。
pub fn state_of(journal: &Journal, operation: OperationId) -> OperationState {
    journal
        .operation(operation)
        .expect("读取操作记录")
        .expect("操作应当存在")
        .state
}

/// 读取某个操作记录的错误信息文本。
pub fn error_message_of(journal: &Journal, operation: OperationId) -> String {
    journal
        .operation(operation)
        .expect("读取操作记录")
        .expect("操作应当存在")
        .error
        .map(|detail| format!("[{}] {}", detail.code, detail.message))
        .unwrap_or_default()
}

/// 数据库中是否**一条操作记录都没有**。
pub fn journal_is_empty(journal: &Journal) -> bool {
    OperationState::ALL
        .into_iter()
        .all(|state| journal.list_by_state(state).expect("按状态查询").is_empty())
}
