//! 应用服务面向桌面端的脱敏 View 类型。
//!
//! View 只包含 UI 决策所需的稳定元数据；不会包含 Blob 内容、秘密明文、绝对路径或任意
//! 诊断文本。错误文案由宿主按稳定诊断码本地化，避免把外部输入重新带到 UI 输出面。

use envsync_domain::{
    Action, ActionKind, BackupPolicy, ConflictKind, DesiredDisposition, DeviceId, Diagnostic, Plan,
    ResolutionChoice, Risk, RollbackCapability, Severity, WorkspaceId,
};
use envsync_storage::{ConflictRecord, OperationRecord};
use serde::Serialize;

use crate::api::{private, ViewData};
use crate::service::{ResourceStatus, StatusReport};

/// 一个工作区的无内容摘要。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkspaceSummary {
    /// 工作区标识。
    pub id: String,
    /// 当前设备标识。
    pub device_id: String,
    /// 后端类别，而非后端 URL、路径或凭据。
    pub backend_kind: String,
}

impl WorkspaceSummary {
    /// 以已审核过的元数据构造工作区摘要。
    pub fn from_status_parts(workspace: WorkspaceId, device: DeviceId, backend_kind: &str) -> Self {
        WorkspaceSummary {
            id: workspace.to_string(),
            device_id: device.to_string(),
            backend_kind: backend_kind.to_owned(),
        }
    }
}

/// 单个资源的状态摘要。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResourceStatusView {
    /// 稳定资源标识。
    pub resource: String,
    /// 观察状态的稳定名称。
    pub observed: String,
    /// 期望处置；没有目标条目时为 `null`。
    pub disposition: Option<String>,
    /// 是否需要计划动作。
    pub needs_action: bool,
}

/// 未收敛操作的最小摘要。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationStatusView {
    /// 操作标识。
    pub operation: String,
    /// 操作状态的稳定名称。
    pub state: String,
}

/// `status` 对应的桌面 View。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusView {
    /// 工作区与设备的无内容摘要。
    pub workspace: WorkspaceSummary,
    /// 工作区状态的稳定名称。
    pub state: String,
    /// 当前读到的后端是否可达。
    pub backend_reachable: bool,
    /// 后端不可达时，本机最后一次成功读取 Ref 的时刻。
    pub last_known_revision_at_unix_ms: Option<u64>,
    /// 当前或上次已知的后端 revision。
    pub revision: u64,
    /// 当前或上次已知的后端头快照标识。
    pub head: Option<String>,
    /// 本地草稿头快照标识。
    pub draft_head: Option<String>,
    /// 逐资源状态。
    pub resources: Vec<ResourceStatusView>,
    /// 未完成操作。
    pub unfinished_operations: Vec<OperationStatusView>,
    /// 待应用动作数。
    pub pending_actions: usize,
    /// 未解决冲突数。
    pub open_conflicts: usize,
}

impl StatusView {
    /// 从核心层状态报告构造安全的桌面 View。
    pub fn from_report(report: &StatusReport) -> Self {
        StatusView {
            workspace: WorkspaceSummary::from_status_parts(
                report.workspace,
                report.device,
                report.backend_kind,
            ),
            state: report.state.as_str().to_owned(),
            backend_reachable: report.backend_reachable,
            last_known_revision_at_unix_ms: report.last_known_revision_at_unix_ms,
            revision: report.revision,
            head: report.head.map(|id| id.to_string()),
            draft_head: report.draft_head.map(|id| id.to_string()),
            resources: report
                .resources
                .iter()
                .map(ResourceStatusView::from)
                .collect(),
            unfinished_operations: report
                .unfinished
                .iter()
                .map(|(operation, state)| OperationStatusView {
                    operation: operation.to_string(),
                    state: state.as_str().to_owned(),
                })
                .collect(),
            pending_actions: report.pending_actions,
            open_conflicts: report.open_conflicts,
        }
    }
}

impl From<&ResourceStatus> for ResourceStatusView {
    fn from(status: &ResourceStatus) -> Self {
        ResourceStatusView {
            resource: status.resource.to_string(),
            observed: status.observed.to_owned(),
            disposition: status.disposition.map(disposition_name).map(str::to_owned),
            needs_action: status.needs_action,
        }
    }
}

/// 可安全交给 UI 的诊断。
///
/// 核心诊断正文即使按约定应当脱敏，也可能间接来自外部输入。View API 因而只暴露稳定
/// 的严重级别、错误码和资源标识；UI 根据错误码选择本地化的文案。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ViewDiagnostic {
    /// `info`、`warning` 或 `blocking`。
    pub severity: String,
    /// 稳定机器可读诊断码。
    pub code: String,
    /// 关联资源；没有关联资源时为 `null`。
    pub resource: Option<String>,
}

impl From<&Diagnostic> for ViewDiagnostic {
    fn from(diagnostic: &Diagnostic) -> Self {
        ViewDiagnostic {
            severity: severity_name(diagnostic.severity).to_owned(),
            code: diagnostic.code.clone(),
            resource: diagnostic.resource.as_ref().map(ToString::to_string),
        }
    }
}

/// 不可变同步计划的脱敏摘要。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanView {
    /// 计划标识。
    pub id: String,
    /// 所属工作区标识。
    pub workspace: String,
    /// 生成计划的设备标识。
    pub device_id: String,
    /// 目标快照标识。
    pub target_snapshot: String,
    /// 计划绑定的后端基线 revision。
    pub base_revision: u64,
    /// 成功发布后将达到的 revision。
    pub next_revision: u64,
    /// 待审核动作；不包含任何文件正文或 Blob 标识。
    pub actions: Vec<PlanActionView>,
}

impl PlanView {
    /// 从核心计划构造可审核但不含内容的 View。
    pub fn from_plan(plan: &Plan) -> Self {
        PlanView {
            id: plan.id().to_string(),
            workspace: plan.workspace.to_string(),
            device_id: plan.device.to_string(),
            target_snapshot: plan.target_snapshot.to_string(),
            base_revision: plan.base_revision,
            next_revision: plan.next_ref.revision,
            actions: plan.actions.iter().map(PlanActionView::from).collect(),
        }
    }
}

/// 计划中一个动作的脱敏审核信息。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanActionView {
    /// 关联资源标识。
    pub resource: String,
    /// 动作种类的稳定名称。
    pub kind: String,
    /// 授权根别名与相对路径，不是本机绝对路径。
    pub target: String,
    /// 风险等级的稳定名称。
    pub risk: String,
    /// 备份策略的稳定名称。
    pub backup: String,
    /// 回滚能力的稳定名称。
    pub rollback: String,
    /// 是否涉及敏感资源。
    pub sensitive: bool,
}

impl From<&Action> for PlanActionView {
    fn from(action: &Action) -> Self {
        PlanActionView {
            resource: action.resource.to_string(),
            kind: action_kind_name(action.kind).to_owned(),
            target: action.target.display_path(),
            risk: risk_name(action.risk).to_owned(),
            backup: backup_name(action.backup).to_owned(),
            rollback: rollback_name(action.rollback).to_owned(),
            sensitive: action.secret,
        }
    }
}

/// 一项文件变化的无内容摘要。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffView {
    /// 关联资源标识。
    pub resource: String,
    /// `added`、`removed` 或 `modified`。
    pub kind: String,
    /// 是否属于敏感资源。
    pub sensitive: bool,
    /// 变更前摘要；敏感资源始终为 `null`。
    pub before_digest: Option<String>,
    /// 变更后摘要；敏感资源始终为 `null`。
    pub after_digest: Option<String>,
}

impl DiffView {
    /// 从计划动作构造差异摘要。
    ///
    /// 敏感资源不会暴露摘要或正文，只保留“发生了变更”的事实。
    pub fn from_action(action: &Action) -> Self {
        let (before_digest, after_digest) = if action.secret {
            (None, None)
        } else {
            (
                action.expected_before.map(|digest| digest.to_string()),
                action.expected_after.map(|digest| digest.to_string()),
            )
        };
        DiffView {
            resource: action.resource.to_string(),
            kind: diff_kind_name(action.kind).to_owned(),
            sensitive: action.secret,
            before_digest,
            after_digest,
        }
    }
}

/// 合并冲突的无内容摘要。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConflictView {
    /// 冲突标识。
    pub id: String,
    /// 所属工作区标识。
    pub workspace: String,
    /// 关联资源标识。
    pub resource: String,
    /// 冲突种类的稳定名称。
    pub kind: String,
    /// 冲突状态的稳定名称。
    pub state: String,
    /// 已选解决方式；尚未解决时为 `null`。
    pub choice: Option<String>,
    /// 冲突登记时刻。
    pub created_at_unix_ms: i64,
    /// 解决时刻；尚未解决时为 `null`。
    pub resolved_at_unix_ms: Option<i64>,
}

impl ConflictView {
    /// 从本地冲突索引记录构造 View。
    pub fn from_record(record: &ConflictRecord) -> Self {
        ConflictView {
            id: record.conflict.to_string(),
            workspace: record.workspace.to_string(),
            resource: record.resource.to_string(),
            kind: conflict_kind_name(record.kind).to_owned(),
            state: record.state.as_str().to_owned(),
            choice: record.choice.map(resolution_choice_name).map(str::to_owned),
            created_at_unix_ms: record.created_at_unix_ms,
            resolved_at_unix_ms: record.resolved_at_unix_ms,
        }
    }
}

/// 一次 journal 操作的无内容摘要。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationView {
    /// 操作标识。
    pub operation: String,
    /// 关联计划标识。
    pub plan: String,
    /// 目标快照标识。
    pub snapshot: String,
    /// 所属工作区标识。
    pub workspace: String,
    /// 关联 revision。
    pub revision: u64,
    /// 操作状态的稳定名称。
    pub state: String,
    /// 操作创建时刻。
    pub created_at_unix_ms: u64,
    /// 最后一次状态变化时刻。
    pub updated_at_unix_ms: u64,
    /// 稳定错误码；不传递可能含外部输入的错误正文。
    pub error_code: Option<String>,
}

impl OperationView {
    /// 从 journal 记录构造 View。
    pub fn from_record(record: &OperationRecord) -> Self {
        OperationView {
            operation: record.operation.to_string(),
            plan: record.plan.to_string(),
            snapshot: record.snapshot.to_string(),
            workspace: record.workspace.to_string(),
            revision: record.revision,
            state: record.state.as_str().to_owned(),
            created_at_unix_ms: record.created_at_unix_ms,
            updated_at_unix_ms: record.updated_at_unix_ms,
            error_code: record.error.as_ref().map(|error| error.code.clone()),
        }
    }
}

impl private::Sealed for WorkspaceSummary {}
impl private::Sealed for StatusView {}
impl private::Sealed for PlanView {}
impl private::Sealed for DiffView {}
impl private::Sealed for ConflictView {}
impl private::Sealed for OperationView {}
impl ViewData for WorkspaceSummary {}
impl ViewData for StatusView {}
impl ViewData for PlanView {}
impl ViewData for DiffView {}
impl ViewData for ConflictView {}
impl ViewData for OperationView {}

fn disposition_name(disposition: DesiredDisposition) -> &'static str {
    match disposition {
        DesiredDisposition::Managed => "managed",
        DesiredDisposition::EnsureAbsent => "ensure_absent",
        DesiredDisposition::Unmanaged => "unmanaged",
    }
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Blocking => "blocking",
    }
}

fn action_kind_name(kind: ActionKind) -> &'static str {
    match kind {
        ActionKind::DeleteFile => "delete_file",
        ActionKind::CreateFile => "create_file",
        ActionKind::ReplaceFile => "replace_file",
        ActionKind::UpdateManagedBlock => "update_managed_block",
    }
}

fn diff_kind_name(kind: ActionKind) -> &'static str {
    match kind {
        ActionKind::CreateFile => "added",
        ActionKind::DeleteFile => "removed",
        ActionKind::ReplaceFile | ActionKind::UpdateManagedBlock => "modified",
    }
}

fn risk_name(risk: Risk) -> &'static str {
    match risk {
        Risk::Low => "low",
        Risk::Medium => "medium",
        Risk::High => "high",
    }
}

fn backup_name(backup: BackupPolicy) -> &'static str {
    match backup {
        BackupPolicy::Required => "required",
        BackupPolicy::NotApplicable => "not_applicable",
    }
}

fn rollback_name(rollback: RollbackCapability) -> &'static str {
    match rollback {
        RollbackCapability::Exact => "exact",
        RollbackCapability::Compensating => "compensating",
        RollbackCapability::None => "none",
    }
}

fn conflict_kind_name(kind: ConflictKind) -> &'static str {
    match kind {
        ConflictKind::TextOverlap => "text_overlap",
        ConflictKind::DeleteModify => "delete_modify",
        ConflictKind::StructuredKey => "structured_key",
        ConflictKind::BinaryBoth => "binary_both",
        ConflictKind::IncompatiblePolicy => "incompatible_policy",
    }
}

fn resolution_choice_name(choice: ResolutionChoice) -> &'static str {
    match choice {
        ResolutionChoice::Ours => "ours",
        ResolutionChoice::Theirs => "theirs",
        ResolutionChoice::Manual => "manual",
        ResolutionChoice::Delete => "delete",
    }
}
