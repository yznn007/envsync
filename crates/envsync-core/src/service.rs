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
//! status   区分 clean / drifted / conflicted / published_not_converged
//! rollback 依据收据逆序还原
//! doctor   只读体检，绝不修改
//! ```
//!
//! **草稿库不污染后端**：capture 产生的对象先落本地，只有在 `sync` 发布时才上传。

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
use crate::config::{BackendConfig, WorkspaceConfig};
use crate::error::{CoreError, CoreResult};
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
}

impl WorkspaceState {
    /// 稳定的机器可读名称。
    pub fn as_str(self) -> &'static str {
        match self {
            WorkspaceState::Clean => "clean",
            WorkspaceState::Drifted => "drifted",
            WorkspaceState::Conflicted => "conflicted",
            WorkspaceState::PublishedNotConverged => "published_not_converged",
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
    /// 后端当前 revision。
    pub revision: u64,
    /// 后端当前头。
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
}

impl EnvSyncService {
    /// 用系统时钟打开服务。
    pub fn open(config: WorkspaceConfig) -> CoreResult<Self> {
        Self::open_with_clock(config, Arc::new(SystemClock))
    }

    /// 用指定时钟打开服务（测试注入固定时钟以获得确定性输出）。
    pub fn open_with_clock(config: WorkspaceConfig, clock: Arc<dyn Clock>) -> CoreResult<Self> {
        std::fs::create_dir_all(&config.state_dir)
            .map_err(|err| envsync_platform::PlatformError::io("创建状态目录", &err))?;

        let backend: Box<dyn Backend> = match &config.backend {
            BackendConfig::Local { path } => Box::new(LocalBackend::open(path.clone())?),
            BackendConfig::Git {
                remote_url,
                branch,
                cache_dir,
                auth,
            } => Box::new(GitBackend::open(
                GitConfig::new(remote_url.clone(), cache_dir.clone(), auth.clone())
                    .with_branch(branch.clone()),
            )?),
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

        Ok(EnvSyncService {
            config,
            backend,
            observer,
            mutator,
            journal,
            drafts,
            conflicts,
            clock,
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

        let mut metadata = BTreeMap::new();
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
            FileMode::FullFile => bytes,
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
    pub fn status(&mut self) -> CoreResult<StatusReport> {
        let base_ref = self.current_ref()?;
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
            let plan = self.build_plan()?;
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

        let open_conflicts = self.conflicts_list()?.len();

        let state = if unfinished
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

        Ok(StatusReport {
            workspace: self.config.workspace_id,
            device: self.config.device.device_id(),
            backend_kind: self.backend.describe().kind,
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
        let backend_ok = self.current_ref().is_ok();
        findings.push(DoctorFinding {
            check: "后端可达性".into(),
            ok: backend_ok,
            detail: if backend_ok {
                "可读取 Ref".into()
            } else {
                "无法读取 Ref".into()
            },
        });

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
    fn current_ref(&self) -> CoreResult<WorkspaceRef> {
        match self.backend.get_ref(self.config.workspace_id) {
            Ok(reference) => Ok(reference),
            Err(BackendError::RefNotFound(_)) => {
                Ok(WorkspaceRef::initial(self.config.workspace_id))
            }
            Err(err) => Err(err.into()),
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
