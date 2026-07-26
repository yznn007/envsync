//! M0 应用服务。
//!
//! 这是 CLI 与桌面端共用的**唯一**入口：所有安全决策（计划、策略、日志、回滚）都在
//! 这里完成，界面层只负责展示和收集意图。
//!
//! 关键流程：
//!
//! ```text
//! init     创建配置、后端目录与本地状态目录
//! capture  观察本机 → 生成 Blob/StateRoot/Snapshot → 存入草稿库（不碰后端）
//! plan     读后端 Ref + 草稿头 + 本机观察 → 生成不可变计划（含渲染产物）
//! sync     自动恢复 → 校验计划新鲜度 → 上传对象 → CAS 发布 → 逐动作应用 → 验证
//! status   区分 clean / drifted / conflicted / published_not_converged；
//!          后端不可达时降级为本地上次已知状态并显式标注（backend_unreachable）
//! rollback 依据收据逆序还原
//! doctor   只读体检，绝不修改
//! ```
//!
//! **草稿库不污染后端**：capture 产生的对象先落本地，只有在 `sync` 发布时才上传。

use std::cell::OnceCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use envsync_backend::{Backend, BackendError, GitBackend, GitConfig, LocalBackend};
use envsync_domain::{
    Blob, BlobId, CborCodec, Conflict, ConflictId, ConflictResolution, DesiredDisposition,
    DeviceId, DeviceProfile, FileMode, ObjectId, ObjectKind, Observation, ObservedState,
    OperationId, Plan, PlanId, ProjectionNote, ResolutionChoice, ResourceEntry, ResourceId,
    SnapshotBody, SnapshotId, SnapshotSignature, StateRoot, StateRootId, WorkspaceId, WorkspaceRef,
};
use envsync_platform::{AuthorizedRoot, RelativeTarget, RootRegistry, SafeWriter};
use envsync_storage::{ConflictRecord, ConflictStore, DraftStore, Journal, OperationState};

use crate::apply::{ApplyEngine, ApplyOutcome};
use crate::checkpoint::{CheckpointStore, SecureCheckpointStore};
use crate::config::{BackendConfig, WorkspaceConfig};
use crate::error::{CoreError, CoreResult};
use crate::last_known::{is_backend_unreachable, LastKnownRef, LastKnownRefStore};
use crate::offline::UnreachableBackend;
use crate::planner::{self, BlobSource, PlanRequest};
use crate::ports::platform::{PlatformMutator, PlatformObserver};
use crate::ports::{Clock, FileMutator, Observer, SystemClock};
use crate::projection::{self, DeviceView, ProjectionPolicy, ProjectionRules};
use crate::recovery::{PlanSource, RecoveryDiagnosis, RecoveryEngine, RecoveryReport};
use crate::render;
use crate::sync::{self, ConflictDetail, FetchOutcome, MergeContext, MergeOutcome};

/// capture 的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureOutcome {
    /// 生成（或复用）的快照标识。
    pub snapshot: SnapshotId,
    /// 该快照的 State Root。
    pub state_root: StateRootId,
    /// 相对后端当前头是否发生变化。
    pub changed: bool,
    /// 捕获过程中的诊断。
    pub diagnostics: Vec<envsync_domain::Diagnostic>,
}

/// 工作区整体状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceState {
    /// 本机与目标快照一致，且没有未完成操作。
    Clean,
    /// 存在需要应用的变更。
    Drifted,
    /// 存在需要人工解决的冲突（M1 起使用）。
    Conflicted,
    /// 已发布但本地未收敛。
    PublishedNotConverged,
    /// 后端联系不上，报告的是本地记录的**上次已知状态**。
    ///
    /// 它压过其余全部判定，包括 `clean`。理由：把「远端连不上」说成「已收敛」会让用户
    /// 以为自己的改动已经同步出去，这比直接报错危险得多——错误至少会被看见。
    BackendUnreachable,
}

impl WorkspaceState {
    /// 稳定的机器可读名称。
    pub fn as_str(self) -> &'static str {
        match self {
            WorkspaceState::Clean => "clean",
            WorkspaceState::Drifted => "drifted",
            WorkspaceState::Conflicted => "conflicted",
            WorkspaceState::PublishedNotConverged => "published_not_converged",
            WorkspaceState::BackendUnreachable => "backend_unreachable",
        }
    }
}

/// 单个资源的状态摘要。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceStatus {
    /// 资源标识。
    pub resource: ResourceId,
    /// 观察状态名。
    pub observed: &'static str,
    /// 期望处置。
    pub disposition: Option<DesiredDisposition>,
    /// 是否需要写入。
    pub needs_action: bool,
}

/// `status` 的完整报告。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReport {
    /// 工作区标识。
    pub workspace: WorkspaceId,
    /// 本设备标识。
    pub device: DeviceId,
    /// 后端自述。
    pub backend_kind: &'static str,
    /// 后端是否可达。
    ///
    /// 为 `false` 时，[`StatusReport::revision`] 与 [`StatusReport::head`] 来自本地记录的
    /// **上次已知**后端 Ref，而不是刚刚读到的远端状态；此时
    /// [`StatusReport::state`] 恒为 [`WorkspaceState::BackendUnreachable`]。
    pub backend_reachable: bool,
    /// 上次成功读到后端 Ref 的本机时刻（Unix 毫秒）。
    ///
    /// 只在降级作答时有值：它回答「这份状态有多旧」。后端可达时为 `None`——数字就是
    /// 此刻读到的，不需要一个时间戳来限定它。
    pub last_known_revision_at_unix_ms: Option<u64>,
    /// 后端当前 revision；后端不可达时是上次已知的 revision。
    pub revision: u64,
    /// 后端当前头；后端不可达时是上次已知的头。
    pub head: Option<SnapshotId>,
    /// 本地草稿头。
    pub draft_head: Option<SnapshotId>,
    /// 整体状态。
    pub state: WorkspaceState,
    /// 逐资源状态。
    pub resources: Vec<ResourceStatus>,
    /// 未完成操作。
    pub unfinished: Vec<(OperationId, OperationState)>,
    /// 待应用动作数量。
    pub pending_actions: usize,
    /// 未解决的合并冲突数量。
    pub open_conflicts: usize,
    /// 诊断。
    pub diagnostics: Vec<envsync_domain::Diagnostic>,
}

/// `doctor` 的报告条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorFinding {
    /// 检查项名称。
    pub check: String,
    /// 是否通过。
    pub ok: bool,
    /// 说明。
    pub detail: String,
}

/// `doctor` 的完整报告。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    /// 逐项检查结果。
    pub findings: Vec<DoctorFinding>,
    /// 恢复诊断（只读）。
    pub recovery: Vec<RecoveryDiagnosis>,
}

impl DoctorReport {
    /// 是否全部通过。
    pub fn is_healthy(&self) -> bool {
        self.findings.iter().all(|f| f.ok)
            && self
                .recovery
                .iter()
                .all(|d| d.suggestion == crate::recovery::RecoverySuggestion::Nothing)
    }
}

/// 组合 Blob 来源：先查草稿库，再查后端。
struct CompositeBlobs<'a> {
    drafts: &'a DraftStore,
    backend: &'a dyn Backend,
}

impl BlobSource for CompositeBlobs<'_> {
    fn blob(&self, id: BlobId) -> CoreResult<Vec<u8>> {
        if let Some(bytes) = self.drafts.get(ObjectId::from(id))? {
            return Ok(bytes);
        }
        match self.backend.get_object(ObjectId::from(id)) {
            Ok(bytes) => Ok(bytes),
            Err(BackendError::ObjectNotFound(_)) => {
                Err(CoreError::MissingObject(format!("Blob {}", id.short())))
            }
            Err(err) => Err(err.into()),
        }
    }
}

impl PlanSource for DraftStore {
    fn plan(&self, id: PlanId) -> CoreResult<Option<Plan>> {
        Ok(self.get_plan(id)?)
    }
}

/// `profile explain` 的报告：本设备 Profile 与每个资源的投影结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileExplanation {
    /// 本设备 Profile。
    pub profile: DeviceProfile,
    /// 被投影的完整状态；工作区还没有任何快照时为 `None`。
    pub state_root: Option<StateRootId>,
    /// 投影结果的标识。
    pub device_view: StateRootId,
    /// 逐资源的投影结论。
    pub notes: Vec<ProjectionNote>,
}

/// 应用服务。
pub struct EnvSyncService {
    config: WorkspaceConfig,
    backend: Box<dyn Backend>,
    observer: Box<dyn Observer>,
    mutator: Box<dyn FileMutator>,
    journal: Journal,
    drafts: DraftStore,
    conflicts: ConflictStore,
    clock: Arc<dyn Clock>,
    /// 上次成功读到的后端 Ref；后端不可达时用于降级作答。
    last_known: LastKnownRefStore,
    /// 打开后端时就已经联系不上的说明；后端正常时为 `None`。
    ///
    /// 它只用于 `doctor` 的 finding 文案：Git 后端在 `open` 阶段就会 fetch，那一步的
    /// 失败原因比之后任何一次调用都更贴近根因。
    offline_detail: Option<String>,
    /// 反回滚检查点的权威副本，**惰性**打开。
    ///
    /// 惰性有两个理由。其一，M0/M1 的工作区根本没有检查点，为它们去敲一次系统凭据库
    /// 既没用又可能弹出授权对话框。其二，检查点只在头快照**确实带着 Vault**时才有意义，
    /// 而那件事要读完远端头才知道。
    ///
    /// `OnceCell` 里的 `None` 表示「试过了，这台机器上没有可用的系统凭据库」——此时
    /// 读路径不做反回滚校验，只留下一条警告。这是刻意的降级：M0/M1 的用户不该因为
    /// 容器里没有 DBus 会话就连 `status` 都跑不出来。
    checkpoints: OnceCell<Option<Arc<dyn CheckpointStore>>>,
}

impl EnvSyncService {
    /// 用系统时钟打开服务。
    pub fn open(config: WorkspaceConfig) -> CoreResult<Self> {
        Self::open_with_clock(config, Arc::new(SystemClock))
    }

    /// 用指定时钟打开服务（测试注入固定时钟以获得确定性输出）。
    pub fn open_with_clock(config: WorkspaceConfig, clock: Arc<dyn Clock>) -> CoreResult<Self> {
        Self::open_with(config, clock, None)
    }

    /// 用指定时钟与**指定检查点存储**打开服务。
    ///
    /// `checkpoints` 为 `None` 时按需惰性打开系统安全存储里的权威副本（生产路径）；
    /// 给一个 `Some` 等于「本进程就用这一份」，测试用它注入
    /// [`crate::checkpoint::InMemoryCheckpointStore`]，从而在没有系统凭据库的机器上也能
    /// 验证反回滚行为。
    pub fn open_with(
        config: WorkspaceConfig,
        clock: Arc<dyn Clock>,
        checkpoints: Option<Arc<dyn CheckpointStore>>,
    ) -> CoreResult<Self> {
        let cell = OnceCell::new();
        if let Some(store) = checkpoints {
            let _ = cell.set(Some(store));
        }
        Self::open_inner(config, clock, cell)
    }

    fn open_inner(
        config: WorkspaceConfig,
        clock: Arc<dyn Clock>,
        checkpoints: OnceCell<Option<Arc<dyn CheckpointStore>>>,
    ) -> CoreResult<Self> {
        std::fs::create_dir_all(&config.state_dir)
            .map_err(|err| envsync_platform::PlatformError::io("创建状态目录", &err))?;

        // 打开后端。**联系不上远端不应该让整个进程无话可说**：Git 后端在 `open` 里就会
        // fetch 一次，那一步失败时本机的 journal、草稿库与 cache clone 全都完好，用户却
        // 连一句 `status` 都跑不出来。因此这里把「够不着」降级成
        // `UnreachableBackend`——服务照常打开，只有真正需要远端的调用才失败（详见
        // `crate::offline`）。格式不符、Ref 损坏等**够得着但内容坏了**的错误仍然直接抛出。
        let mut offline_detail = None;
        let backend: Box<dyn Backend> = match &config.backend {
            BackendConfig::Local { path } => Box::new(LocalBackend::open(path.clone())?),
            BackendConfig::Git {
                remote_url,
                branch,
                cache_dir,
                auth,
            } => {
                let git_config =
                    GitConfig::new(remote_url.clone(), cache_dir.clone(), auth.clone())
                        .with_branch(branch.clone());
                match GitBackend::open(git_config) {
                    Ok(backend) => Box::new(backend),
                    Err(error) if crate::last_known::is_backend_error_unreachable(&error) => {
                        let placeholder = UnreachableBackend::new("git", &error);
                        tracing::warn!(
                            detail = %placeholder.detail(),
                            "打开 Git 后端失败：联系不上远端，本次将只使用本地已知状态"
                        );
                        offline_detail = Some(placeholder.detail());
                        Box::new(placeholder)
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        };

        let mut registry = RootRegistry::new();
        for (alias, path) in &config.roots {
            registry.insert(AuthorizedRoot::open(alias.clone(), path)?);
        }
        let roots = Arc::new(registry);

        let observer = Box::new(PlatformObserver::new(
            Arc::clone(&roots),
            Arc::clone(&clock),
        ));
        let mutator = Box::new(PlatformMutator::new(
            roots,
            SafeWriter::new(config.backup_root()),
        ));

        let journal = Journal::open(config.journal_path())?;
        let drafts = DraftStore::open(config.draft_dir())?;
        // 与草稿库同库：解决冲突时要在 `objects` 表里确认结果 Blob 存在。
        let conflicts = ConflictStore::open(config.conflict_db_path())?;
        let last_known = LastKnownRefStore::new(&config.state_dir);

        Ok(EnvSyncService {
            config,
            backend,
            observer,
            mutator,
            journal,
            drafts,
            conflicts,
            clock,
            last_known,
            offline_detail,
            checkpoints,
        })
    }

    /// 初始化一个新工作区：生成配置文件、后端目录与状态目录。
    ///
    /// 已存在同名配置文件时报错而不是覆盖——初始化绝不能悄悄丢掉已有工作区。
    pub fn init_workspace(
        config_path: &Path,
        device_name: &str,
        backend_path: &Path,
    ) -> CoreResult<WorkspaceConfig> {
        if config_path.exists() {
            return Err(CoreError::ManualInterventionRequired(format!(
                "配置文件 `{}` 已存在；初始化不会覆盖已有工作区",
                file_label(config_path)
            )));
        }
        let base_dir = config_path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(base_dir)
            .map_err(|err| envsync_platform::PlatformError::io("创建配置目录", &err))?;
        std::fs::create_dir_all(backend_path)
            .map_err(|err| envsync_platform::PlatformError::io("创建后端目录", &err))?;

        let config =
            WorkspaceConfig::scaffold(WorkspaceId::generate(), device_name, backend_path, base_dir);
        let yaml = config.to_yaml()?;
        std::fs::write(config_path, yaml)
            .map_err(|err| envsync_platform::PlatformError::io("写入配置文件", &err))?;

        // 提前建立后端布局与状态目录，让 `init` 之后的任何命令都能直接工作。
        LocalBackend::open(backend_path.to_path_buf())?;
        std::fs::create_dir_all(&config.state_dir)
            .map_err(|err| envsync_platform::PlatformError::io("创建状态目录", &err))?;
        Ok(config)
    }

    /// 只读访问配置。
    pub fn config(&self) -> &WorkspaceConfig {
        &self.config
    }

    /// 只读访问草稿库。
    pub fn drafts(&self) -> &DraftStore {
        &self.drafts
    }

    /// 只读访问操作日志。
    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    // ---- capture -------------------------------------------------------------

    /// 观察本机现状并生成一份快照草稿。
    ///
    /// **不更新后端 Ref**，也不上传任何对象：草稿只存在于本地，直到 `sync` 发布。
    pub fn capture(&mut self) -> CoreResult<CaptureOutcome> {
        let base_ref = self.current_ref()?;
        let base_state = match base_ref.head {
            Some(head) => self.load_state_root_of(head)?,
            None => StateRoot::empty(),
        };

        let mut entries: Vec<ResourceEntry> = Vec::new();
        let mut diagnostics = Vec::new();
        let mut blobs: Vec<Blob> = Vec::new();

        for resource_config in &self.config.resources {
            let target = resource_config.action_target();
            let policy = &resource_config.policy;
            let observation = self.observer.observe(&resource_config.id, &target, policy);

            match resource_config.disposition {
                DesiredDisposition::Unmanaged => {
                    entries.push(ResourceEntry {
                        resource: resource_config.id.clone(),
                        disposition: DesiredDisposition::Unmanaged,
                        blob: None,
                        mode: resource_config.mode,
                        policy: policy.clone(),
                    });
                }
                DesiredDisposition::EnsureAbsent => {
                    entries.push(ResourceEntry {
                        resource: resource_config.id.clone(),
                        disposition: DesiredDisposition::EnsureAbsent,
                        blob: None,
                        mode: resource_config.mode,
                        policy: policy.clone(),
                    });
                }
                DesiredDisposition::Managed => {
                    let captured =
                        self.capture_managed(resource_config, &observation, &mut diagnostics)?;
                    match captured {
                        Some(blob) => {
                            entries.push(ResourceEntry {
                                resource: resource_config.id.clone(),
                                disposition: DesiredDisposition::Managed,
                                blob: Some(blob.id()),
                                mode: resource_config.mode,
                                policy: policy.clone(),
                            });
                            blobs.push(blob);
                        }
                        None => {
                            // 本机读不到内容时**沿用上一版快照**中的条目。
                            // 「观察不到」绝不等于「删掉它」。
                            if let Some(previous) = base_state.get(&resource_config.id) {
                                entries.push(previous.clone());
                                diagnostics.push(envsync_domain::Diagnostic::warning(
                                    "capture.reused_previous",
                                    Some(resource_config.id.clone()),
                                    "本机当前读不到该资源，沿用上一版快照中的内容。",
                                ));
                            } else {
                                diagnostics.push(envsync_domain::Diagnostic::warning(
                                    "capture.skipped",
                                    Some(resource_config.id.clone()),
                                    "本机没有该资源且历史快照中也没有，本次捕获跳过。",
                                ));
                            }
                        }
                    }
                }
            }
        }

        let state =
            StateRoot::from_entries(entries).map_err(|err| CoreError::Domain(err.to_string()))?;
        let state_bytes = state.to_canonical_vec();
        let state_id = state.id();

        // 快照内容未变时不生成新快照：重复 capture 必须是幂等的。
        if base_state.id() == state_id {
            if let Some(head) = base_ref.head {
                self.drafts.clear_head_draft()?;
                return Ok(CaptureOutcome {
                    snapshot: head,
                    state_root: state_id,
                    changed: false,
                    diagnostics,
                });
            }
        }

        for blob in &blobs {
            self.drafts.put(ObjectId::from(blob.id()), blob.bytes())?;
        }
        self.drafts.put(ObjectId::from(state_id), &state_bytes)?;

        // **工作区级元数据必须被继承。** 快照的 metadata 里混着两类东西：本次 capture
        // 自己的事实（`device_name` / `format`），和整个工作区的事实（M2 起是 Vault
        // 索引指针与它的背书）。后者不属于这一次发布，因此这里以父快照的工作区级键为
        // 起点，只覆盖本次真正要改的键。
        //
        // 不这么做的后果不是「少一条元数据」，而是**一次普通 `envsync sync` 静默抹掉
        // 整个 Vault**：头快照上的索引指针没了，`vault get` 报 `vault.secret_not_found`，
        // 而 `vault list` 照常以 `status: ok` 返回一个空清单，用户完全看不出发生了什么。
        let mut metadata = match base_ref.head {
            Some(head) => {
                let bytes = self.read_object(ObjectId::from(head))?;
                let parent = SnapshotBody::from_canonical_slice(&bytes)?;
                crate::vault::inherited_workspace_metadata(&parent.metadata)
            }
            None => BTreeMap::new(),
        };
        metadata.insert("device_name".to_owned(), self.config.device.name.clone());
        metadata.insert("format".to_owned(), "envsync/m0".to_owned());

        let body = SnapshotBody::new(
            self.config.workspace_id,
            base_ref.head.into_iter().collect(),
            state_id,
            self.config.device.device_id(),
            self.clock.now_unix_ms(),
            metadata,
        )
        .map_err(|err| CoreError::Domain(err.to_string()))?;
        let body_bytes = body.to_canonical_vec();
        let snapshot_id = body.id();
        self.drafts.put(ObjectId::from(snapshot_id), &body_bytes)?;

        let signature = SnapshotSignature::unsigned(snapshot_id, self.config.device.device_id());
        let signature_bytes = signature.to_canonical_vec();
        self.drafts.put(
            ObjectId::for_bytes(ObjectKind::SnapshotSignature, &signature_bytes),
            &signature_bytes,
        )?;

        self.drafts.set_head_draft(snapshot_id)?;

        Ok(CaptureOutcome {
            snapshot: snapshot_id,
            state_root: state_id,
            changed: true,
            diagnostics,
        })
    }

    /// 捕获单个 managed 资源的内容。
    fn capture_managed(
        &self,
        resource_config: &crate::config::ResourceConfig,
        observation: &Observation,
        diagnostics: &mut Vec<envsync_domain::Diagnostic>,
    ) -> CoreResult<Option<Blob>> {
        let target = resource_config.action_target();
        let policy = &resource_config.policy;

        match &observation.state {
            ObservedState::Present(_) => {}
            ObservedState::Absent => return Ok(None),
            other => {
                diagnostics.push(envsync_domain::Diagnostic::warning(
                    match other {
                        ObservedState::Unreadable { .. } => "capture.unreadable",
                        ObservedState::Unsupported { .. } => "capture.unsupported",
                        _ => "capture.excluded",
                    },
                    Some(resource_config.id.clone()),
                    format!("捕获跳过：观察状态为 {}", other.kind()),
                ));
                return Ok(None);
            }
        }

        let bytes = self.observer.read(&target, policy)?;
        let content = match resource_config.mode {
            // Structured Merge 的受管内容就是整份文件：结构化只影响**合并**时怎么比较，
            // 不影响捕获时抽哪些字节（见 `crate::render` 的模块级文档）。
            FileMode::FullFile | FileMode::StructuredMerge => bytes,
            FileMode::ManagedBlock => {
                match render::extract_managed_block(&bytes, &resource_config.id)? {
                    Some(block) => block,
                    None => {
                        diagnostics.push(envsync_domain::Diagnostic::info(
                            "capture.no_managed_block",
                            Some(resource_config.id.clone()),
                            "目标文件中还没有该资源的受管区块，本次捕获跳过。",
                        ));
                        return Ok(None);
                    }
                }
            }
            mode => {
                return Err(CoreError::Render(
                    crate::render::RenderError::UnsupportedMode { mode },
                ))
            }
        };
        Ok(Some(Blob::new(content)))
    }

    // ---- plan ----------------------------------------------------------------

    /// 生成计划并保存到草稿库。
    ///
    /// 目标状态**先经 Profile 投影**再交给计划器：Snapshot 始终是全量期望状态，
    /// 而本机只收敛它在这台设备上的投影。
    pub fn build_plan(&mut self) -> CoreResult<Plan> {
        let base_ref = self.current_ref()?;
        self.build_plan_from(&base_ref)
    }

    /// 以给定的后端引用为基准生成计划。
    ///
    /// 拆出来只为一件事：[`EnvSyncService::status`] 在后端不可达时要能基于**上次已知**的
    /// Ref 把「本机还差哪些动作」算出来。除它之外的调用方都应当用
    /// [`EnvSyncService::build_plan`]——那里的 `base_ref` 是刚从远端读到的真实值。
    ///
    /// 用降级 Ref 生成的计划只用于展示：[`EnvSyncService::apply_plan`] 会重新读远端、
    /// 重新计划并比对计划标识，因此一份基于陈旧 revision 的计划不可能被误应用。
    fn build_plan_from(&mut self, base_ref: &WorkspaceRef) -> CoreResult<Plan> {
        let base_ref = base_ref.clone();
        let draft_head = self.drafts.head_draft()?;
        let target_snapshot = draft_head.or(base_ref.head).ok_or_else(|| {
            CoreError::ManualInterventionRequired(
                "工作区尚无任何快照，请先运行 `envsync capture`".to_owned(),
            )
        })?;
        let full_state = self.load_state_root_of(target_snapshot)?;
        let view = self.project(&full_state)?;
        let target_state = view.state;

        let next_ref = if base_ref.head == Some(target_snapshot) {
            // 目标已经是后端当前头：本次只需要本地收敛，不再做一次 CAS。
            base_ref.clone()
        } else {
            base_ref.advance(target_snapshot)
        };

        // device-id 覆盖里的 `target` 只改变本机落地位置，因此在这里套用，绝不
        // 回写进共享 Snapshot。
        let device_config = self.config.for_device(self.config.device.device_id());
        let request = PlanRequest {
            config: &device_config,
            target_state: &target_state,
            target_snapshot,
            base_ref: &base_ref,
            next_ref,
        };

        let blobs = CompositeBlobs {
            drafts: &self.drafts,
            backend: self.backend.as_ref(),
        };
        let outcome = planner::build_plan(
            &request,
            self.observer.as_ref(),
            &blobs,
            self.clock.as_ref(),
        )?;

        for (id, bytes) in &outcome.rendered {
            self.drafts.put(ObjectId::from(*id), bytes)?;
        }
        self.drafts.put_plan(&outcome.plan)?;
        Ok(outcome.plan)
    }

    // ---- sync ----------------------------------------------------------------

    /// 应用指定计划。
    ///
    /// 启动时自动运行恢复流程（M0 任务 13 的要求），随后校验计划新鲜度：重新生成的
    /// 计划标识必须与提交的一致，否则返回 [`CoreError::StalePlan`]。
    pub fn apply_plan(&mut self, plan_id: PlanId) -> CoreResult<ApplyOutcome> {
        // 未解决的冲突一票否决，而且必须排在最前面：此后的任何一步都会动本地文件
        // 或远端 Ref，而「有冲突时两者都不变」是 M1 的硬性承诺。
        let open = self.conflicts_list()?;
        if !open.is_empty() {
            return Err(CoreError::Conflicted { count: open.len() });
        }

        let recovery_reports = self.recover()?;
        for report in &recovery_reports {
            tracing::info!(
                operation = %report.operation,
                before = %report.before,
                after = %report.after,
                "同步前自动恢复"
            );
        }

        let submitted = self
            .drafts
            .get_plan(plan_id)?
            .ok_or(CoreError::PlanNotFound(plan_id))?;

        // 重新观察并重新计划；标识不一致即判定失效。
        let current = self.build_plan()?;
        if current.id() != plan_id {
            return Err(CoreError::StalePlan {
                submitted: plan_id,
                current: current.id(),
            });
        }

        if planner::requires_publish(&submitted) {
            self.upload_snapshot_closure(submitted.target_snapshot)?;
        }

        let EnvSyncService {
            backend,
            mutator,
            journal,
            drafts,
            ..
        } = self;
        let blobs = CompositeBlobs {
            drafts,
            backend: backend.as_ref(),
        };
        let mut engine = ApplyEngine::new(backend.as_ref(), mutator.as_ref(), journal, &blobs);
        let outcome = engine.apply(&current)?;

        if matches!(outcome, ApplyOutcome::Completed { .. }) {
            self.drafts.clear_head_draft()?;
        }
        Ok(outcome)
    }

    /// 把目标快照可达的全部对象上传到后端。
    ///
    /// 必须在 CAS 之前完成：Ref 一旦指向某个快照，其他设备就可能立刻来读，
    /// 缺对象的头是不可接受的。
    fn upload_snapshot_closure(&self, snapshot: SnapshotId) -> CoreResult<()> {
        let body_bytes = self.read_object(ObjectId::from(snapshot))?;
        let body = SnapshotBody::from_canonical_slice(&body_bytes)?;
        let state_bytes = self.read_object(ObjectId::from(body.state_root))?;
        let state = StateRoot::from_canonical_slice(&state_bytes)?;

        for entry in state.entries.values() {
            if let Some(blob) = entry.blob {
                let bytes = self.read_object(ObjectId::from(blob))?;
                self.backend.put_object(ObjectId::from(blob), &bytes)?;
            }
        }
        self.backend
            .put_object(ObjectId::from(body.state_root), &state_bytes)?;
        self.backend
            .put_object(ObjectId::from(snapshot), &body_bytes)?;

        let signature = SnapshotSignature::unsigned(snapshot, self.config.device.device_id());
        let signature_bytes = signature.to_canonical_vec();
        self.backend.put_object(
            ObjectId::for_bytes(ObjectKind::SnapshotSignature, &signature_bytes),
            &signature_bytes,
        )?;
        Ok(())
    }

    // ---- fetch / merge / 冲突 / profile ----------------------------------------

    /// 读取远端 Ref 与头快照，把可达对象拉进本地草稿库。
    ///
    /// 只复制对象：不改 Ref、不生成快照、不碰任何用户文件。
    pub fn fetch(&mut self) -> CoreResult<FetchOutcome> {
        let reference = self.current_ref()?;
        let context = self.merge_context();
        sync::fetch(&context, reference.head, reference.revision)
    }

    /// 合并本地草稿头与远端头。
    ///
    /// 干净合并会生成 `parents = [local, remote]` 的合并快照并设为草稿头；出现冲突
    /// 时只把冲突写进冲突索引，**不**生成快照，也不动任何用户文件。
    pub fn merge_states(&mut self) -> CoreResult<MergeOutcome> {
        let reference = self.current_ref()?;
        let local = self.drafts.head_draft()?;
        let context = self.merge_context();
        sync::merge_states(&context, local, reference.head)
    }

    /// 列出本工作区尚未解决的冲突。
    pub fn conflicts_list(&self) -> CoreResult<Vec<ConflictRecord>> {
        Ok(self.conflicts.list_open(self.config.workspace_id)?)
    }

    /// 查看单个冲突的索引记录与不可变冲突对象。
    pub fn conflicts_show(&self, conflict: ConflictId) -> CoreResult<ConflictDetail> {
        let record = self
            .conflicts
            .get(conflict)?
            .ok_or_else(|| CoreError::OperationNotFound(format!("冲突 {}", conflict.short())))?;
        let bytes = self.read_object(ObjectId::from(conflict))?;
        Ok(ConflictDetail {
            record,
            conflict: Conflict::from_canonical_slice(&bytes)?,
        })
    }

    /// 记录用户对冲突的裁决。
    ///
    /// * `Ours` / `Theirs`：采用对应一侧的内容；
    /// * `Manual`：采用 `content` 给出的字节（由 CLI 从 `--file` 读入）；
    /// * `Delete`：确认删除该资源——这是**唯一**能让资源消失的裁决。
    ///
    /// 选定的内容一律以新 Blob 的形式写进草稿库，因此后续重新合并时一定取得到；
    /// 冲突索引在写入前也会再确认一次该 Blob 存在。
    pub fn conflicts_resolve(
        &mut self,
        conflict: ConflictId,
        choice: ResolutionChoice,
        content: Option<&[u8]>,
    ) -> CoreResult<ConflictResolution> {
        let detail = self.conflicts_show(conflict)?;
        let blob = match choice {
            ResolutionChoice::Ours => Some(self.side_blob(&detail, detail.record.ours, "ours")?),
            ResolutionChoice::Theirs => {
                Some(self.side_blob(&detail, detail.record.theirs, "theirs")?)
            }
            ResolutionChoice::Manual => {
                let bytes = content.ok_or_else(|| {
                    CoreError::ManualInterventionRequired(
                        "manual 裁决必须提供内容（CLI 的 `--file`）".to_owned(),
                    )
                })?;
                let blob = Blob::new(bytes.to_vec());
                self.drafts.put(ObjectId::from(blob.id()), blob.bytes())?;
                Some(blob.id())
            }
            ResolutionChoice::Delete => {
                if content.is_some() {
                    return Err(CoreError::ManualInterventionRequired(
                        "delete 裁决不能同时提供内容".to_owned(),
                    ));
                }
                None
            }
        };

        let resolution = match blob {
            Some(blob) => {
                ConflictResolution::with_blob(conflict, choice, blob, self.clock.now_unix_ms())
            }
            None => ConflictResolution::delete(conflict, self.clock.now_unix_ms()),
        };
        self.conflicts.resolve(conflict, &resolution)?;
        Ok(resolution)
    }

    /// 取某一侧的 Blob，并保证它确实存在于本地草稿库。
    fn side_blob(
        &self,
        detail: &ConflictDetail,
        side: Option<BlobId>,
        label: &'static str,
    ) -> CoreResult<BlobId> {
        let blob = side.ok_or_else(|| {
            CoreError::ManualInterventionRequired(format!(
                "冲突 {} 的 {label} 一侧是删除，请改用 --file 或 delete 裁决",
                detail.record.conflict.short()
            ))
        })?;
        let bytes = self.read_object(ObjectId::from(blob))?;
        self.drafts.put(ObjectId::from(blob), &bytes)?;
        Ok(blob)
    }

    /// 解释本设备的 Profile 与每个资源的投影结论。
    pub fn profile_explain(&mut self) -> CoreResult<ProfileExplanation> {
        let base_ref = self.current_ref()?;
        let target = self.drafts.head_draft()?.or(base_ref.head);
        let full_state = match target {
            Some(snapshot) => self.load_state_root_of(snapshot)?,
            None => StateRoot::empty(),
        };
        let view = self.project(&full_state)?;
        Ok(ProfileExplanation {
            profile: self.config.device_profile(),
            state_root: target.map(|_| full_state.id()),
            device_view: view.id(),
            notes: view.notes,
        })
    }

    /// 按本设备 Profile、安全策略与配置规则投影一份状态。
    pub fn project(&self, state: &StateRoot) -> CoreResult<DeviceView> {
        let rules = ProjectionRules::from_config(&self.config)?;
        let policy = ProjectionPolicy::from_config(&self.config);
        Ok(projection::project_workspace_with_rules(
            state,
            &self.config.device_profile(),
            &policy,
            &rules,
        )?)
    }

    /// 组装合并所需的协作者。
    fn merge_context(&self) -> MergeContext<'_> {
        MergeContext {
            workspace: self.config.workspace_id,
            device: self.config.device.device_id(),
            device_name: &self.config.device.name,
            drafts: &self.drafts,
            backend: self.backend.as_ref(),
            conflicts: &self.conflicts,
            clock: self.clock.as_ref(),
        }
    }

    // ---- status / doctor -----------------------------------------------------

    /// 汇总当前状态。
    ///
    /// # 后端不可达时的降级
    ///
    /// 读不到远端 Ref 且原因是**网络/IO 不可达**时，本方法不再失败，而是改用本地记录的
    /// 上次已知 Ref 继续作答，并在报告上把这件事说清楚：
    /// [`StatusReport::backend_reachable`] 为 `false`、
    /// [`StatusReport::last_known_revision_at_unix_ms`] 给出这份状态有多旧、
    /// [`StatusReport::state`] 恒为 [`WorkspaceState::BackendUnreachable`]。
    ///
    /// **绝不会**在这种情况下报 `clean`：把「远端连不上」说成「已收敛」会让用户以为改动
    /// 已经同步出去了。内容损坏一类「够得着但坏了」的错误仍然照常失败。
    pub fn status(&mut self) -> CoreResult<StatusReport> {
        let (base_ref, degraded) = self.current_ref_or_last_known()?;
        let backend_reachable = degraded.is_none();
        let last_known_revision_at_unix_ms =
            degraded.as_ref().map(|record| record.observed_at_unix_ms);
        let draft_head = self.drafts.head_draft()?;
        let unfinished: Vec<(OperationId, OperationState)> = self
            .journal
            .list_unfinished()?
            .into_iter()
            .map(|record| (record.operation, record.state))
            .collect();

        let target_snapshot = draft_head.or(base_ref.head);
        let target_state = match target_snapshot {
            Some(snapshot) => self.load_state_root_of(snapshot)?,
            None => StateRoot::empty(),
        };

        let mut resources = Vec::new();
        let mut diagnostics = Vec::new();
        let mut pending = 0usize;

        if target_snapshot.is_some() {
            // 降级时用上次已知的 Ref 作基准；`build_plan` 会去读远端，这里读不到。
            match self.build_plan_from(&base_ref) {
                Ok(plan) => {
                    pending = plan.actions.len();
                    diagnostics.extend(plan.diagnostics.iter().cloned());
                    for observation in &plan.observations {
                        let needs_action = plan
                            .actions
                            .iter()
                            .any(|action| action.resource == observation.resource);
                        resources.push(ResourceStatus {
                            resource: observation.resource.clone(),
                            observed: observation.state.kind(),
                            disposition: target_state
                                .get(&observation.resource)
                                .map(|entry| entry.disposition),
                            needs_action,
                        });
                    }
                }
                // 后端可达时计划失败仍然是硬错误。只有在降级路径上才容忍：本地草稿库里
                // 可能缺少某个只在远端有的对象，而「读不到远端」正是我们此刻的处境。
                // 少一份逐资源明细好过整份报告消失——不可达这条结论本身已经拿到了。
                Err(error) if !backend_reachable => {
                    tracing::warn!(%error, "后端不可达时无法重新计划，报告将不含逐资源明细");
                    diagnostics.push(envsync_domain::Diagnostic::warning(
                        "status.plan_unavailable",
                        None,
                        "后端不可达且本地缺少必要对象，本次报告不含逐资源明细。",
                    ));
                }
                Err(error) => return Err(error),
            }
        }

        let open_conflicts = self.conflicts_list()?.len();

        let state = if !backend_reachable {
            // 压过其余一切判定：读不到远端时，任何「已收敛」的结论都是没有依据的。
            WorkspaceState::BackendUnreachable
        } else if unfinished
            .iter()
            .any(|(_, s)| *s == OperationState::PublishedNotConverged)
        {
            WorkspaceState::PublishedNotConverged
        // 两种情况都需要人工裁决：未解决的合并冲突，或计划里的阻塞诊断。
        } else if open_conflicts > 0
            || diagnostics
                .iter()
                .any(|d| d.severity == envsync_domain::Severity::Blocking)
        {
            WorkspaceState::Conflicted
        } else if pending > 0 || draft_head.is_some() {
            WorkspaceState::Drifted
        } else {
            WorkspaceState::Clean
        };

        if !backend_reachable {
            diagnostics.push(envsync_domain::Diagnostic::warning(
                "backend.unreachable",
                None,
                "后端不可达：以下是本地记录的上次已知状态，不代表远端当前内容。",
            ));
        }

        Ok(StatusReport {
            workspace: self.config.workspace_id,
            device: self.config.device.device_id(),
            backend_kind: self.backend.describe().kind,
            backend_reachable,
            last_known_revision_at_unix_ms,
            revision: base_ref.revision,
            head: base_ref.head,
            draft_head,
            state,
            resources,
            unfinished,
            pending_actions: pending,
            open_conflicts,
            diagnostics,
        })
    }

    /// 只读体检：报告问题但**绝不修复**。
    pub fn doctor(&mut self) -> CoreResult<DoctorReport> {
        let mut findings = Vec::new();

        // 1) 授权根可访问性
        for (alias, path) in &self.config.roots {
            let ok = AuthorizedRoot::open(alias.clone(), path).is_ok();
            findings.push(DoctorFinding {
                check: format!("授权根 `{alias}`"),
                ok,
                detail: if ok {
                    "可访问".into()
                } else {
                    "无法打开或不是目录".into()
                },
            });
        }

        // 2) 资源目标合法性
        for resource in &self.config.resources {
            let ok = RelativeTarget::parse(&resource.target).is_ok();
            findings.push(DoctorFinding {
                check: format!("资源 `{}` 的目标路径", resource.id),
                ok,
                detail: if ok {
                    "合法".into()
                } else {
                    "非法或越权".into()
                },
            });
        }

        // 3) 后端可达性
        //
        // 不可达是一条 `ok: false` 的 finding，**不是**让 `doctor` 失败的理由：体检的价值
        // 恰恰在于「网络断了也能把本机情况说清楚」。命令仍以退出码 0 结束，调用方读
        // `healthy` 字段而不是退出码——这条契约在 M0 就已经确立。
        match self.current_ref() {
            Ok(reference) => findings.push(DoctorFinding {
                check: "后端可达性".into(),
                ok: true,
                detail: format!("可读取 Ref（revision {}）", reference.revision),
            }),
            Err(error) if is_backend_unreachable(&error) => {
                // 打开后端时就失败的话，那一步的原因比这次调用更贴近根因。
                let reason = self
                    .offline_detail
                    .clone()
                    .unwrap_or_else(|| error.to_string());
                let last_known = self.last_known.load(self.config.workspace_id);
                let known = match &last_known {
                    Some(record) => format!(
                        "；上次已知 revision {}（本机时刻 {} ms）",
                        record.reference.revision, record.observed_at_unix_ms
                    ),
                    None => "；本地没有上次已知状态可用".to_owned(),
                };
                findings.push(DoctorFinding {
                    check: "后端可达性".into(),
                    ok: false,
                    detail: format!("联系不上后端：{reason}{known}"),
                });
            }
            Err(error) => findings.push(DoctorFinding {
                check: "后端可达性".into(),
                ok: false,
                detail: format!("无法读取 Ref：{error}"),
            }),
        }

        // 4) 存储 schema
        let schema = self.journal.schema_version()?;
        findings.push(DoctorFinding {
            check: "操作日志 schema".into(),
            ok: schema == envsync_storage::SCHEMA_VERSION,
            detail: format!("版本 {schema}，期望 {}", envsync_storage::SCHEMA_VERSION),
        });

        // 5) 恢复诊断（只读）
        let EnvSyncService {
            journal,
            drafts,
            backend,
            observer,
            mutator,
            ..
        } = self;
        let blobs = CompositeBlobs {
            drafts,
            backend: backend.as_ref(),
        };
        let engine = RecoveryEngine::new(
            journal,
            drafts as &DraftStore,
            &blobs,
            observer.as_ref(),
            mutator.as_ref(),
        );
        let recovery = engine.diagnose()?;

        Ok(DoctorReport { findings, recovery })
    }

    // ---- 恢复与回滚 ------------------------------------------------------------

    /// 运行崩溃恢复。
    pub fn recover(&mut self) -> CoreResult<Vec<RecoveryReport>> {
        let EnvSyncService {
            journal,
            drafts,
            backend,
            observer,
            mutator,
            ..
        } = self;
        let blobs = CompositeBlobs {
            drafts,
            backend: backend.as_ref(),
        };
        let plans: &DraftStore = drafts;
        let mut engine =
            RecoveryEngine::new(journal, plans, &blobs, observer.as_ref(), mutator.as_ref());
        engine.recover_all()
    }

    /// 显式回滚一次操作。
    pub fn rollback(&mut self, operation: OperationId) -> CoreResult<RecoveryReport> {
        let EnvSyncService {
            journal,
            drafts,
            backend,
            observer,
            mutator,
            ..
        } = self;
        let blobs = CompositeBlobs {
            drafts,
            backend: backend.as_ref(),
        };
        let plans: &DraftStore = drafts;
        let mut engine =
            RecoveryEngine::new(journal, plans, &blobs, observer.as_ref(), mutator.as_ref());
        engine.rollback_operation(operation)
    }

    // ---- 内部工具 --------------------------------------------------------------

    /// 读取后端引用；从未发布过时返回初始引用。
    ///
    /// **每次成功读到都会更新本地的「上次已知 Ref」记录**，供后端不可达时降级作答。
    /// 记录失败只写一条警告：一个诊断用的缓存不该有能力让真实操作失败。
    ///
    /// 本方法**不会**降级。所有会改动远端或依赖真实 revision 的路径（`capture`、`plan`、
    /// `sync`、`fetch`、`merge`）都走它：拿一份缓存的 revision 去做 CAS，等于把反回滚
    /// 保护交给一个可能已经过期好几天的数字。需要降级的只有只读诊断，见
    /// [`EnvSyncService::current_ref_or_last_known`]。
    fn current_ref(&self) -> CoreResult<WorkspaceRef> {
        let reference = match self.backend.get_ref(self.config.workspace_id) {
            Ok(reference) => reference,
            Err(BackendError::RefNotFound(_)) => WorkspaceRef::initial(self.config.workspace_id),
            Err(err) => return Err(err.into()),
        };
        // 反回滚校验排在「记录上次已知 Ref」**之前**：一份被回退的 Ref 不该被写进本机
        // 的降级缓存，否则下一次后端不可达时，我们会把攻击者给的旧状态当成「上次看到的
        // 真实状态」报出去。
        self.guard_against_rollback(&reference)?;
        // `RefNotFound` 也算「联系上了」：它是一个确定的答案（这个工作区还没发布过），
        // 记下来同样有意义。
        if let Err(error) = self.last_known.record(&reference, self.clock.now_unix_ms()) {
            tracing::warn!(%error, "记录上次已知 Ref 失败，不影响本次操作");
        }
        Ok(reference)
    }

    /// 远端头相对本机反回滚检查点的**只读**校验。
    ///
    /// M0/M1 的读路径过去完全不查检查点，于是后端被回退之后 `status` 会安静地报告旧
    /// 状态。这里补上：一旦倒退或分叉就返回 [`CoreError::Checkpoint`]
    /// （`is_rollback_attack()` 为真，CLI 退出码 14），而且**不推进**检查点——推进只发生
    /// 在一次成功的 Vault 发布之后。
    ///
    /// 三种情况直接放行，都不是「校验通过」而是「无从校验」：
    ///
    /// * Ref 还没有头（工作区从未发布过）；
    /// * 头快照上没有 Vault 索引（M0/M1 工作区，本来就没有检查点）；
    /// * 本机拿不到系统凭据库（检查点的权威副本在里面）。
    ///
    /// 读不到头快照对象时同样放行并只记一条 debug：紧随其后的 `load_state_root_of`
    /// 会用同一个对象再失败一次，在那里报错比在这里报错更贴近根因。
    fn guard_against_rollback(&self, reference: &WorkspaceRef) -> CoreResult<()> {
        let Some(head) = reference.head else {
            return Ok(());
        };
        let bytes = match self.read_object(ObjectId::from(head)) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::debug!(%error, "读不到远端头快照，本次跳过反回滚校验");
                return Ok(());
            }
        };
        let body = SnapshotBody::from_canonical_slice(&bytes)?;
        let Some(observed) =
            crate::vault::inspect_vault_head(self.config.workspace_id, &body, &mut |id| {
                self.read_object(id)
            })?
        else {
            return Ok(());
        };
        let Some(store) = self.checkpoint_store() else {
            tracing::warn!(
                "本机没有可用的系统安全存储，本次无法做反回滚校验；\
                 请解锁凭据库后重试，或改用 `envsync security checkpoint` 确认信任根"
            );
            return Ok(());
        };
        crate::checkpoint::guard(
            store.as_ref(),
            &observed.checkpoint(self.config.workspace_id, reference),
        )?;
        Ok(())
    }

    /// 惰性取得检查点存储；系统凭据库不可用时返回 `None`（只在第一次尝试时告警）。
    fn checkpoint_store(&self) -> Option<&Arc<dyn CheckpointStore>> {
        self.checkpoints
            .get_or_init(
                || match envsync_platform::secure_store::open_system_store() {
                    Ok(secure) => {
                        let secure: Arc<dyn envsync_platform::secure_store::SecureStore> =
                            Arc::from(secure);
                        Some(Arc::new(SecureCheckpointStore::new(secure))
                            as Arc<dyn CheckpointStore>)
                    }
                    Err(error) => {
                        tracing::warn!(
                            code = error.code(),
                            "系统安全存储不可用，反回滚校验将被跳过"
                        );
                        None
                    }
                },
            )
            .as_ref()
    }

    /// 读取后端引用，读不到时降级为本地记录的**上次已知** Ref。
    ///
    /// 返回值的第二项为 `None` 表示后端可达（第一项就是刚读到的真实 Ref）；为
    /// `Some(record)` 表示后端联系不上，第一项是上次已知的 Ref。
    ///
    /// 降级只在**网络/IO 不可达**时发生（判据见
    /// [`crate::last_known::is_backend_unreachable`]）：内容损坏、格式不符这类「够得着
    /// 但坏了」的错误一律原样抛出——用一份旧缓存把事故盖住，比直接报错糟得多。
    ///
    /// 本地也没有上次已知记录时（例如这台设备从来没联系上过远端），同样把原始错误抛
    /// 出去：没有可报告的状态时，沉默地假装一切正常是最坏的选择。
    fn current_ref_or_last_known(&self) -> CoreResult<(WorkspaceRef, Option<LastKnownRef>)> {
        match self.current_ref() {
            Ok(reference) => Ok((reference, None)),
            Err(error) if is_backend_unreachable(&error) => {
                match self.last_known.load(self.config.workspace_id) {
                    Some(record) => {
                        tracing::warn!(
                            revision = record.reference.revision,
                            "后端不可达，降级为本地记录的上次已知 Ref"
                        );
                        Ok((record.reference.clone(), Some(record)))
                    }
                    None => {
                        tracing::warn!("后端不可达，且本地没有上次已知 Ref 可用");
                        Err(error)
                    }
                }
            }
            Err(error) => Err(error),
        }
    }

    /// 先查草稿库再查后端读取对象。
    fn read_object(&self, id: ObjectId) -> CoreResult<Vec<u8>> {
        if let Some(bytes) = self.drafts.get(id)? {
            return Ok(bytes);
        }
        match self.backend.get_object(id) {
            Ok(bytes) => Ok(bytes),
            Err(BackendError::ObjectNotFound(_)) => Err(CoreError::MissingObject(id.to_string())),
            Err(err) => Err(err.into()),
        }
    }

    fn load_state_root_of(&self, snapshot: SnapshotId) -> CoreResult<StateRoot> {
        let body_bytes = self.read_object(ObjectId::from(snapshot))?;
        let body = SnapshotBody::from_canonical_slice(&body_bytes)?;
        let state_bytes = self.read_object(ObjectId::from(body.state_root))?;
        Ok(StateRoot::from_canonical_slice(&state_bytes)?)
    }
}

/// 只保留文件名用于错误信息，避免泄露绝对路径。
fn file_label(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "配置文件".to_owned())
}

/// 便于外部构造备份根路径。
pub fn backup_root_of(state_dir: &Path) -> PathBuf {
    state_dir.join("backups")
}
