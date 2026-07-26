//! 计划生成。
//!
//! 计划器是一个**近似纯函数**：给定配置、目标 State Root、后端引用和一组观察结果，
//! 它产出同一份计划。唯一的外部输入是 [`Observer`]（读取本机现状）和 [`BlobSource`]
//! （读取期望内容），两者都以 trait 注入，因此可以完全在内存中测试。
//!
//! 计划器承担了 EnvSync 全部「要不要动、动什么」的判断，[`crate::apply`] 只负责
//! 「按计划照做」。这条分工是安全性的关键：所有依赖当前文件内容的逻辑（Managed Block
//! 渲染尤其如此）都发生在计划阶段，并被 `expected_before` 摘要绑定；应用阶段只写入
//! 已经算好的字节。

use envsync_domain::{
    Action, ActionKind, BackupPolicy, BlobId, Diagnostic, Digest32, FileMode, Observation,
    ObservedState, Plan, ResourceEntry, ResourcePolicy, Risk, RollbackCapability, SnapshotId,
    StateRoot, VerifyRule, WorkspaceRef,
};

use crate::config::{ResourceConfig, WorkspaceConfig};
use crate::error::{CoreError, CoreResult};
use crate::ports::{Clock, Observer};
use crate::render::{self, RenderInput, RenderedChange};

/// 期望内容的来源：先查本地草稿，再查后端。
pub trait BlobSource {
    /// 读取 Blob 内容。
    fn blob(&self, id: BlobId) -> CoreResult<Vec<u8>>;
}

/// 计划生成请求。
pub struct PlanRequest<'a> {
    /// 工作区配置。
    pub config: &'a WorkspaceConfig,
    /// 目标状态。
    pub target_state: &'a StateRoot,
    /// 目标快照标识。
    pub target_snapshot: SnapshotId,
    /// 生成计划时读到的后端引用。
    pub base_ref: &'a WorkspaceRef,
    /// 应用时将 CAS 写入的引用；与 `base_ref` 相同则表示无需发布。
    pub next_ref: WorkspaceRef,
}

/// 计划生成结果。
///
/// `rendered` 是计划阶段渲染出的完整文件内容，必须在计划保存时一并写入草稿库，
/// 否则应用阶段将找不到 `Action::content` 指向的 Blob。
pub struct PlanOutcome {
    /// 生成的计划。
    pub plan: Plan,
    /// 渲染产物：`(BlobId, 完整文件字节)`。
    pub rendered: Vec<(BlobId, Vec<u8>)>,
}

/// 判断计划是否需要向后端发布新引用。
///
/// `next_ref.revision == base_revision` 表示目标快照已经是后端当前头，本次同步只需要
/// 把本地收敛过去，不应再做一次 CAS。
pub fn requires_publish(plan: &Plan) -> bool {
    plan.next_ref.revision != plan.base_revision
}

/// 生成计划。
pub fn build_plan(
    request: &PlanRequest<'_>,
    observer: &dyn Observer,
    blobs: &dyn BlobSource,
    clock: &dyn Clock,
) -> CoreResult<PlanOutcome> {
    let mut observations: Vec<Observation> = Vec::new();
    let mut actions: Vec<Action> = Vec::new();
    let mut diagnostics: Vec<Diagnostic> = Vec::new();
    let mut rendered: Vec<(BlobId, Vec<u8>)> = Vec::new();

    for resource_config in &request.config.resources {
        let target = resource_config.action_target();
        let policy = &resource_config.policy;
        let observation = observer.observe(&resource_config.id, &target, policy);

        let entry = request.target_state.get(&resource_config.id);
        plan_one_resource(
            request,
            resource_config,
            entry,
            &observation,
            observer,
            blobs,
            &mut actions,
            &mut diagnostics,
            &mut rendered,
        )?;

        observations.push(observation);
    }

    // 目标状态里有、但本机配置中没有声明的资源：不静默丢弃，而是留一条诊断。
    for resource in request.target_state.entries.keys() {
        if request.config.resource(resource).is_none() {
            diagnostics.push(Diagnostic::warning(
                "resource.not_configured",
                Some(resource.clone()),
                "快照包含该资源，但本设备配置未声明它；本次同步将忽略。",
            ));
        }
    }

    let plan = Plan::new(
        request.config.workspace_id,
        request.config.device.device_id(),
        request.target_snapshot,
        request.base_ref.revision,
        request.next_ref.clone(),
        observations,
        actions,
        diagnostics,
        clock.now_unix_ms(),
    );

    Ok(PlanOutcome { plan, rendered })
}

/// 为单个资源生成动作与诊断。
#[allow(clippy::too_many_arguments)]
fn plan_one_resource(
    request: &PlanRequest<'_>,
    resource_config: &ResourceConfig,
    entry: Option<&ResourceEntry>,
    observation: &Observation,
    observer: &dyn Observer,
    blobs: &dyn BlobSource,
    actions: &mut Vec<Action>,
    diagnostics: &mut Vec<Diagnostic>,
    rendered: &mut Vec<(BlobId, Vec<u8>)>,
) -> CoreResult<()> {
    let resource = &resource_config.id;
    let target = resource_config.action_target();
    let policy = &resource_config.policy;

    let Some(entry) = entry else {
        // 配置声明了资源，但目标快照里没有：这不是删除意图。
        diagnostics.push(Diagnostic::info(
            "resource.not_in_snapshot",
            Some(resource.clone()),
            "目标快照未包含该资源，本次同步不做任何处理。",
        ));
        return Ok(());
    };

    use envsync_domain::DesiredDisposition as Disposition;
    match entry.disposition {
        // 不归 EnvSync 管理：只记录观察，绝不产生动作。
        Disposition::Unmanaged => Ok(()),

        Disposition::Managed => {
            if let Some(diag) = blocking_for_unwritable(observation) {
                diagnostics.push(diag);
                return Ok(());
            }
            let blob_id = entry.blob.ok_or_else(|| {
                CoreError::Invariant(format!("资源 {resource} 为 managed 但缺少内容 Blob"))
            })?;
            let desired = blobs.blob(blob_id)?;

            let existing = match observation.state.present() {
                Some(_) => Some(observer.read(&target, policy)?),
                None => None,
            };

            let change = render::render(&RenderInput {
                resource,
                existing: existing.as_deref(),
                desired: &desired,
                mode: entry.mode,
                policy,
                comment_prefix: &resource_config.comment_prefix,
            })?;

            let RenderedChange::Write(bytes) = change else {
                // 已经符合期望，无需写入。
                return Ok(());
            };

            let after = envsync_platform::FileReader::content_digest(&bytes);
            let before = observation.state.content_digest();
            let blob = BlobId::of(&bytes);
            rendered.push((blob, bytes));

            let kind = match (before.is_some(), entry.mode) {
                (false, _) => ActionKind::CreateFile,
                (true, FileMode::ManagedBlock) => ActionKind::UpdateManagedBlock,
                (true, _) => ActionKind::ReplaceFile,
            };

            actions.push(Action {
                resource: resource.clone(),
                kind,
                target,
                expected_before: before,
                expected_after: Some(after),
                content: Some(blob),
                risk: write_risk(kind, policy),
                backup: if before.is_some() {
                    BackupPolicy::Required
                } else {
                    BackupPolicy::NotApplicable
                },
                rollback: RollbackCapability::Exact,
                unix_mode: policy.unix_mode,
                secret: policy.secret,
                verify: VerifyRule::ExpectDigest(after),
            });
            Ok(())
        }

        Disposition::EnsureAbsent => {
            match &observation.state {
                // 已经不存在：显式删除是幂等的，无需动作。
                ObservedState::Absent => return Ok(()),
                state if !state.is_writable() => {
                    if let Some(diag) = blocking_for_unwritable(observation) {
                        diagnostics.push(diag);
                    }
                    return Ok(());
                }
                _ => {}
            }
            let before = observation.state.content_digest();

            if entry.mode == FileMode::ManagedBlock {
                // Managed Block 的 tombstone 只移除受管区块，块外内容属于用户，必须保留。
                let existing = observer.read(&target, policy)?;
                let Some(remaining) = render::remove_managed_block(&existing, resource)? else {
                    // 文件里本来就没有这个块。
                    return Ok(());
                };
                let after = envsync_platform::FileReader::content_digest(&remaining);
                let blob = BlobId::of(&remaining);
                rendered.push((blob, remaining));
                actions.push(Action {
                    resource: resource.clone(),
                    kind: ActionKind::UpdateManagedBlock,
                    target,
                    expected_before: before,
                    expected_after: Some(after),
                    content: Some(blob),
                    risk: Risk::High,
                    backup: BackupPolicy::Required,
                    rollback: RollbackCapability::Exact,
                    unix_mode: policy.unix_mode,
                    secret: policy.secret,
                    verify: VerifyRule::ExpectDigest(after),
                });
            } else {
                actions.push(Action {
                    resource: resource.clone(),
                    kind: ActionKind::DeleteFile,
                    target,
                    expected_before: before,
                    expected_after: None,
                    content: None,
                    risk: Risk::High,
                    backup: BackupPolicy::Required,
                    rollback: RollbackCapability::Exact,
                    unix_mode: None,
                    secret: policy.secret,
                    verify: VerifyRule::ExpectAbsent,
                });
            }
            let _ = request;
            Ok(())
        }
    }
}

/// 写入类动作的风险评级。
fn write_risk(kind: ActionKind, policy: &ResourcePolicy) -> Risk {
    if policy.secret {
        // 秘密资源的任何写入都是高风险：一旦写错，泄露或失效的代价远高于普通配置。
        return Risk::High;
    }
    match kind {
        ActionKind::CreateFile => Risk::Low,
        ActionKind::ReplaceFile | ActionKind::UpdateManagedBlock => Risk::Medium,
        ActionKind::DeleteFile => Risk::High,
    }
}

/// 为不可写的观察状态生成阻塞诊断。
///
/// 三种状态都**不产生任何写入**：
///
/// * `Unreadable`：我们不知道文件当前内容，覆盖会造成不可恢复的数据丢失；
/// * `Unsupported`：适配器无法保证语义（M1 起由 Profile 投影在计划前剔除）；
/// * `Excluded`：策略明确排除。
fn blocking_for_unwritable(observation: &Observation) -> Option<Diagnostic> {
    let (code, reason) = match &observation.state {
        ObservedState::Unreadable { reason } => ("resource.unreadable", reason),
        ObservedState::Unsupported { reason } => ("resource.unsupported", reason),
        ObservedState::Excluded { reason } => ("resource.excluded", reason),
        _ => return None,
    };
    Some(Diagnostic::blocking(
        code,
        Some(observation.resource.clone()),
        reason.clone(),
    ))
}

/// 计算一段字节的内容摘要，与平台层保持同一域标签。
pub fn content_digest(bytes: &[u8]) -> Digest32 {
    envsync_platform::FileReader::content_digest(bytes)
}
