//! 应用服务面向桌面端的脱敏 View 类型。
//!
//! View 只包含 UI 决策所需的稳定元数据；不会包含 Blob 内容、秘密明文、绝对路径或任意
//! 诊断文本。错误文案由宿主按稳定诊断码本地化，避免把外部输入重新带到 UI 输出面。

use envsync_domain::{
    Action, ActionKind, BackupPolicy, ConflictKind, ConflictResolution, DesiredDisposition,
    DeviceId, Diagnostic, FileMode, OperationId, Plan, ResolutionChoice, Risk, RollbackCapability,
    Severity, StructuredFormat, WorkspaceId,
};
use envsync_storage::{
    ActionRecord, ConflictRecord, OperationRecord, OperationState, ReceiptRecord,
};
use serde::Serialize;

use crate::api::{private, ViewData};
use crate::config::ResourceConfig;
use crate::service::{ResourceStatus, StatusReport};
use crate::sync::ConflictDetail;

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

/// 原生层已授权目录的无路径能力摘要。
///
/// `token` 只在当前桌面进程中引用 Rust 保存的目录能力，不能反推出路径；`label` 也是
/// 原生层生成的通用显示名而不是目录文本。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RootCapabilityView {
    /// 不透明的根能力标识。
    pub token: String,
    /// 不含路径的安全显示标签。
    pub label: String,
}

impl RootCapabilityView {
    /// 构造已经由原生层验证过的根能力摘要。
    pub fn new(token: impl Into<String>, label: impl Into<String>) -> Self {
        RootCapabilityView {
            token: token.into(),
            label: label.into(),
        }
    }
}

/// 首次使用或打开工作区后交给 UI 的安全注册摘要。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkspaceRegistrationView {
    /// 已注册工作区的公开摘要。
    pub workspace: WorkspaceSummary,
    /// 本次工作区关联的原生根能力。
    pub root: RootCapabilityView,
}

impl WorkspaceRegistrationView {
    /// 组合已审核的工作区与根能力 View。
    pub const fn new(workspace: WorkspaceSummary, root: RootCapabilityView) -> Self {
        WorkspaceRegistrationView { workspace, root }
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
    /// 可显示的差异类别；只描述渲染策略，不包含任何文件正文。
    ///
    /// 取值为 `secret`、`text`、`structured`、`managed_block`、`binary` 或
    /// `content_summary`。宿主不得根据该字段尝试读取任意路径或 Blob。
    pub presentation: String,
    /// 非敏感一侧的已知内容大小；删除前内容没有安全可得的大小时为 `null`。
    pub content_bytes: Option<usize>,
    /// 内容过大时 UI 必须继续保持摘要模式，不能为了展示而请求正文。
    pub preview_truncated: bool,
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
            presentation: if action.secret {
                "secret".to_owned()
            } else {
                "content_summary".to_owned()
            },
            content_bytes: None,
            preview_truncated: action.secret,
            before_digest,
            after_digest,
        }
    }

    /// 加入经 core 判定的显示类别和大小摘要。
    ///
    /// 这仍不携带正文：宿主只能根据它选择“文本 / 结构化 / 二进制 / 受管区块”的说明。
    pub fn with_presentation(
        mut self,
        presentation: &'static str,
        content_bytes: Option<usize>,
        preview_truncated: bool,
    ) -> Self {
        if !self.sensitive {
            self.presentation = presentation.to_owned();
            self.content_bytes = content_bytes;
            self.preview_truncated = preview_truncated;
        }
        self
    }
}

/// 一个已保存 Plan 的无内容差异列表。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffListView {
    /// 被审核的不可变计划标识。
    pub plan: String,
    /// 逐动作的差异摘要。
    pub diffs: Vec<DiffView>,
}

impl DiffListView {
    /// 用已保存计划及其安全差异摘要构造列表。
    pub fn new(plan: &Plan, diffs: Vec<DiffView>) -> Self {
        DiffListView {
            plan: plan.id().to_string(),
            diffs,
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

/// 一个工作区的开放冲突列表。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConflictListView {
    /// 所属工作区标识。
    pub workspace: String,
    /// 仅含无内容摘要的开放冲突。
    pub conflicts: Vec<ConflictView>,
}

impl ConflictListView {
    /// 从本地冲突索引记录构造脱敏列表。
    pub fn from_records(workspace: WorkspaceId, records: &[ConflictRecord]) -> Self {
        ConflictListView {
            workspace: workspace.to_string(),
            conflicts: records.iter().map(ConflictView::from_record).collect(),
        }
    }
}

/// 单个冲突的可裁决元数据。
///
/// 与 [`ConflictView`] 一样，这个 View 不返回任何一侧的 Blob、正文或原始诊断。手动裁决
/// 只在资源明确标记为非秘密文本时开放，内容仍会在 core 中按资源策略重新校验。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConflictDetailView {
    /// 已脱敏的冲突摘要。
    pub conflict: ConflictView,
    /// 资源模式：`full_file`、`managed_block`、`structured_merge` 或 `generated_include`。
    pub mode: String,
    /// 结构化资源的格式；其他资源为 `null`。
    pub structured_format: Option<String>,
    /// 本地一侧是否存在可采用的内容；这不是 Blob 标识。
    pub ours_available: bool,
    /// 远端一侧是否存在可采用的内容；这不是 Blob 标识。
    pub theirs_available: bool,
    /// 是否可以提交手动文本裁决。
    pub manual_allowed: bool,
    /// 手动文本裁决允许的最大字节数；不允许时为 `0`。
    pub manual_max_bytes: u64,
}

impl ConflictDetailView {
    /// 从冲突索引、不可变冲突对象与本机资源策略构造安全裁决元数据。
    pub fn from_detail(
        detail: &ConflictDetail,
        resource: &ResourceConfig,
        manual_limit: u64,
    ) -> Self {
        let manual_allowed = !resource.policy.secret
            && matches!(
                resource.mode,
                FileMode::FullFile | FileMode::ManagedBlock | FileMode::StructuredMerge
            )
            && !matches!(detail.conflict.kind, ConflictKind::BinaryBoth);
        ConflictDetailView {
            conflict: ConflictView::from_record(&detail.record),
            mode: file_mode_name(resource.mode).to_owned(),
            structured_format: resource
                .policy
                .structured_format
                .map(structured_format_name)
                .map(str::to_owned),
            ours_available: detail.conflict.ours.is_some(),
            theirs_available: detail.conflict.theirs.is_some(),
            manual_allowed,
            manual_max_bytes: if manual_allowed { manual_limit } else { 0 },
        }
    }
}

/// 提交冲突裁决后的安全回执。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConflictResolutionView {
    /// 已裁决的冲突标识。
    pub conflict: String,
    /// 固定为 `resolved`；不暗示同步已经完成。
    pub state: String,
    /// 使用的裁决方式。
    pub choice: String,
    /// 裁决写入本地索引的时刻。
    pub resolved_at_unix_ms: u64,
}

impl From<&ConflictResolution> for ConflictResolutionView {
    fn from(resolution: &ConflictResolution) -> Self {
        ConflictResolutionView {
            conflict: resolution.conflict.to_string(),
            state: "resolved".to_owned(),
            choice: resolution_choice_name(resolution.choice).to_owned(),
            resolved_at_unix_ms: resolution.resolved_at_unix_ms,
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

/// 一个工作区的 journal 操作历史。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationHistoryView {
    /// 所属工作区标识。
    pub workspace: String,
    /// 按最近更新时间倒序排列的操作摘要。
    pub operations: Vec<OperationView>,
}

impl OperationHistoryView {
    /// 从已排序的 journal 操作记录构造历史列表。
    pub fn from_records(workspace: WorkspaceId, records: &[OperationRecord]) -> Self {
        OperationHistoryView {
            workspace: workspace.to_string(),
            operations: records.iter().map(OperationView::from_record).collect(),
        }
    }
}

/// history 中单个动作的无路径、无内容执行进度。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationActionView {
    /// 动作在原计划中的稳定序号。
    pub ordinal: u32,
    /// 关联资源。
    pub resource: String,
    /// 原动作种类。
    pub kind: String,
    /// 授权根别名与相对路径。
    pub target: String,
    /// 动作状态。
    pub state: String,
    /// 稳定错误码；不会输出原始错误信息。
    pub error_code: Option<String>,
}

impl From<&ActionRecord> for OperationActionView {
    fn from(action: &ActionRecord) -> Self {
        OperationActionView {
            ordinal: action.ordinal,
            resource: action.resource.to_string(),
            kind: action_kind_name(action.kind).to_owned(),
            target: action.target.display_path(),
            state: action.state.as_str().to_owned(),
            error_code: action.error.as_ref().map(|error| error.code.clone()),
        }
    }
}

/// 不泄漏备份位置或摘要的回滚收据摘要。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationReceiptView {
    /// 对应的原计划动作序号。
    pub ordinal: u32,
    /// 关联资源。
    pub resource: String,
    /// 可提供的回滚保证。
    pub guarantee: String,
    /// 收据持久化时刻。
    pub created_at_unix_ms: u64,
}

impl From<&ReceiptRecord> for OperationReceiptView {
    fn from(receipt: &ReceiptRecord) -> Self {
        OperationReceiptView {
            ordinal: receipt.receipt.ordinal,
            resource: receipt.receipt.resource.to_string(),
            guarantee: rollback_name(receipt.receipt.guarantee).to_owned(),
            created_at_unix_ms: receipt.created_at_unix_ms,
        }
    }
}

/// 单次历史操作的安全详情。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationDetailView {
    /// 操作状态与关联计划。
    pub operation: OperationView,
    /// 逐动作执行状态。
    pub actions: Vec<OperationActionView>,
    /// 已实际持久化的回滚收据摘要。
    pub receipts: Vec<OperationReceiptView>,
    /// 是否可以申请一次新的逆向计划审核。
    pub rollback_available: bool,
}

impl OperationDetailView {
    /// 从 journal 记录构造详情；只要 recovery 支持该状态，就允许申请 rollback review。
    pub fn from_records(
        operation: &OperationRecord,
        actions: &[ActionRecord],
        receipts: &[ReceiptRecord],
    ) -> Self {
        OperationDetailView {
            operation: OperationView::from_record(operation),
            actions: actions.iter().map(OperationActionView::from).collect(),
            receipts: receipts.iter().map(OperationReceiptView::from).collect(),
            rollback_available: rollback_state_supported(operation.state) && !receipts.is_empty(),
        }
    }
}

/// 逆向计划中一项需要逐项确认的动作摘要。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RollbackActionView {
    /// 对应的原计划动作序号；提交确认时使用该序号，不传文件路径。
    pub ordinal: u32,
    /// 关联资源。
    pub resource: String,
    /// 原目标的安全显示名。
    pub target: String,
    /// 原动作种类；逆向写入细节只在 core/recovery 内部决定。
    pub original_kind: String,
    /// 收据声称的回滚保证。
    pub guarantee: String,
}

/// 回滚执行前必须重新审核的逆向计划摘要。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RollbackReviewView {
    /// 进程内一次性审核 token；不能反推出路径或内容。
    pub review_token: String,
    /// 将被恢复的 operation。
    pub operation: OperationView,
    /// 仅包含已有回滚收据的逆向动作，按执行顺序倒序排列。
    pub actions: Vec<RollbackActionView>,
    /// 固定为 `true`：每一项都要由 UI 明确确认后才能请求执行。
    pub requires_individual_confirmation: bool,
}

impl RollbackReviewView {
    /// 从 journal 记录生成尚未分配 token 的逆向计划摘要。
    pub fn from_records(
        operation: &OperationRecord,
        actions: &[ActionRecord],
        receipts: &[ReceiptRecord],
    ) -> Option<Self> {
        if !rollback_state_supported(operation.state) || receipts.is_empty() {
            return None;
        }
        let mut inverse_actions = Vec::new();
        for receipt in receipts.iter().rev() {
            let action = actions
                .iter()
                .find(|action| action.ordinal == receipt.receipt.ordinal)?;
            inverse_actions.push(RollbackActionView {
                ordinal: action.ordinal,
                resource: action.resource.to_string(),
                target: action.target.display_path(),
                original_kind: action_kind_name(action.kind).to_owned(),
                guarantee: rollback_name(receipt.receipt.guarantee).to_owned(),
            });
        }
        Some(RollbackReviewView {
            review_token: String::new(),
            operation: OperationView::from_record(operation),
            actions: inverse_actions,
            requires_individual_confirmation: true,
        })
    }

    /// 将 Rust 进程状态发放的一次性审核 token 绑定到响应。
    pub fn with_review_token(mut self, review_token: String) -> Self {
        self.review_token = review_token;
        self
    }
}

/// 已接受后台 apply 请求的脱敏摘要。
///
/// operation ID 在 worker 创建时就分配，但 journal 只有在 core 完成新鲜度检查后才会出现
/// 对应记录。因此 UI 应把 `queued` 视为“已接受、等待安全执行”的暂态，并订阅 operation
/// 事件取得最终 [`ApplyView`] 或失败诊断。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplyStartView {
    /// 后台 worker 预先分配的 operation 标识。
    pub operation: String,
    /// 当前固定为 `queued`。
    pub state: String,
}

impl ApplyStartView {
    /// 构造已排入后台 worker 的 apply 摘要。
    pub fn queued(operation: OperationId) -> Self {
        ApplyStartView {
            operation: operation.to_string(),
            state: "queued".to_owned(),
        }
    }
}

/// 已接受取消请求的脱敏摘要。
///
/// `requested` 仅表示令牌已送达后台 worker；core 会在 journal 的安全边界决定是否实际
/// 中止。若 operation 已越过发布边界或已经结束，command 会返回稳定错误响应而非本 View。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CancellationView {
    /// 被请求取消的 operation 标识。
    pub operation: String,
    /// 当前固定为 `requested`。
    pub state: String,
}

impl CancellationView {
    /// 构造已送达 worker 的取消请求摘要。
    pub fn requested(operation: OperationId) -> Self {
        CancellationView {
            operation: operation.to_string(),
            state: "requested".to_owned(),
        }
    }
}

/// 提交 Plan 后的脱敏结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplyView {
    /// `no_op` 或 `completed`。
    pub outcome: String,
    /// 已登记操作的摘要；无动作时为 `null`。
    pub operation: Option<OperationView>,
    /// 本次实际应用的动作数量。
    pub applied_actions: usize,
    /// 是否向后端发布新 revision。
    pub published: bool,
}

impl ApplyView {
    /// 构造无需登记 operation 的空计划结果。
    pub fn no_op() -> Self {
        ApplyView {
            outcome: "no_op".to_owned(),
            operation: None,
            applied_actions: 0,
            published: false,
        }
    }

    /// 从已完成 operation 的 journal 记录构造结果。
    pub fn completed(record: &OperationRecord, applied_actions: usize, published: bool) -> Self {
        ApplyView {
            outcome: "completed".to_owned(),
            operation: Some(OperationView::from_record(record)),
            applied_actions,
            published,
        }
    }
}

impl private::Sealed for WorkspaceSummary {}
impl private::Sealed for RootCapabilityView {}
impl private::Sealed for WorkspaceRegistrationView {}
impl private::Sealed for StatusView {}
impl private::Sealed for PlanView {}
impl private::Sealed for DiffView {}
impl private::Sealed for DiffListView {}
impl private::Sealed for ConflictView {}
impl private::Sealed for ConflictListView {}
impl private::Sealed for ConflictDetailView {}
impl private::Sealed for ConflictResolutionView {}
impl private::Sealed for OperationView {}
impl private::Sealed for OperationHistoryView {}
impl private::Sealed for OperationDetailView {}
impl private::Sealed for RollbackReviewView {}
impl private::Sealed for ApplyStartView {}
impl private::Sealed for CancellationView {}
impl private::Sealed for ApplyView {}
impl ViewData for WorkspaceSummary {}
impl ViewData for RootCapabilityView {}
impl ViewData for WorkspaceRegistrationView {}
impl ViewData for StatusView {}
impl ViewData for PlanView {}
impl ViewData for DiffView {}
impl ViewData for DiffListView {}
impl ViewData for ConflictView {}
impl ViewData for ConflictListView {}
impl ViewData for ConflictDetailView {}
impl ViewData for ConflictResolutionView {}
impl ViewData for OperationView {}
impl ViewData for OperationHistoryView {}
impl ViewData for OperationDetailView {}
impl ViewData for RollbackReviewView {}
impl ViewData for ApplyStartView {}
impl ViewData for CancellationView {}
impl ViewData for ApplyView {}

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

fn file_mode_name(mode: FileMode) -> &'static str {
    match mode {
        FileMode::FullFile => "full_file",
        FileMode::ManagedBlock => "managed_block",
        FileMode::StructuredMerge => "structured_merge",
        FileMode::GeneratedInclude => "generated_include",
    }
}

fn structured_format_name(format: StructuredFormat) -> &'static str {
    match format {
        StructuredFormat::Json => "json",
        StructuredFormat::Yaml => "yaml",
        StructuredFormat::Toml => "toml",
        StructuredFormat::Ini => "ini",
        StructuredFormat::GitConfig => "git_config",
    }
}

fn rollback_state_supported(state: OperationState) -> bool {
    matches!(
        state,
        OperationState::Completed
            | OperationState::Applying
            | OperationState::PublishedNotConverged
            | OperationState::RollingBack
    )
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
