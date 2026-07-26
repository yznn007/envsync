//! 子命令实现与对外 JSON 数据结构。
//!
//! 本模块是 CLI 与 [`envsync_core::EnvSyncService`] 之间**唯一**的胶水层：所有安全
//! 决策（计划、策略、日志、回滚）都在核心层完成，这里只做三件事——把配置读进来、
//! 调用服务、把结果翻译成对外契约。
//!
//! `data` 的每个形状都是具名的 `Serialize` 结构体，而不是临时拼出来的
//! `serde_json::json!`：字段名是对外承诺，写错时应当编译失败，改动时应当被 golden
//! test 抓住。

use std::path::{Path, PathBuf};

use serde::Serialize;

use envsync_core::{
    ApplyOutcome, CoreResult, DoctorReport, EnvSyncService, RecoveryDiagnosis, RecoveryReport,
    RecoverySuggestion, StatusReport, WorkspaceConfig,
};
use envsync_domain::{
    ActionKind, BackupPolicy, DesiredDisposition, OperationId, PlanId, Risk, RollbackCapability,
};

use crate::output::DiagnosticOut;

/// 一次命令执行的完整结果。
pub struct CommandOutput {
    /// 命令专属数据，进入 JSON 契约的 `data`。
    pub data: CommandData,
    /// 本次执行产生的诊断，进入 JSON 契约的 `diagnostics`。
    pub diagnostics: Vec<DiagnosticOut>,
}

impl CommandOutput {
    /// 构造一个没有诊断的结果。
    fn plain(data: CommandData) -> Self {
        CommandOutput {
            data,
            diagnostics: Vec::new(),
        }
    }
}

/// 所有命令的 `data` 形状。
///
/// `untagged` 让 JSON 里直接出现内层结构体，不额外包一层变体名——命令名已经在信封的
/// `command` 字段里了，重复一次只会让契约更啰嗦。
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum CommandData {
    /// `init` 的数据。
    Init(InitData),
    /// `capture` 的数据。
    Capture(CaptureData),
    /// `plan` 的数据。
    Plan(PlanData),
    /// `sync` 的数据。
    Sync(SyncData),
    /// `status` 的数据。
    Status(StatusData),
    /// `doctor` 的数据。
    Doctor(DoctorData),
    /// `rollback` 与 `recover` 的数据。
    Recovery(RecoveryData),
}

impl CommandData {
    /// 人类可读渲染。
    pub fn render(&self) -> String {
        match self {
            CommandData::Init(data) => data.render(),
            CommandData::Capture(data) => data.render(),
            CommandData::Plan(data) => data.render(),
            CommandData::Sync(data) => data.render(),
            CommandData::Status(data) => data.render(),
            CommandData::Doctor(data) => data.render(),
            CommandData::Recovery(data) => data.render(),
        }
    }
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

/// `init` 的数据。
#[derive(Debug, Serialize)]
pub struct InitData {
    /// 新工作区标识。
    pub workspace: String,
    /// 设备显示名。
    pub device_name: String,
    /// 由设备种子派生的设备标识。
    pub device: String,
    /// 配置文件路径。
    pub config_path: String,
    /// 后端种类，M0 恒为 `local`。
    pub backend_kind: String,
    /// 本地状态目录（journal / 草稿 / 备份）。
    pub state_dir: String,
}

impl InitData {
    fn render(&self) -> String {
        [
            format!("已初始化工作区 {}", self.workspace),
            format!("  设备：{}（{}）", self.device_name, self.device),
            format!("  配置：{}", self.config_path),
            format!("  后端：{}", self.backend_kind),
            format!("  状态目录：{}", self.state_dir),
            "下一步：编辑配置里的 resources，然后运行 `envsync capture`。".to_owned(),
        ]
        .join("\n")
    }
}

/// 初始化工作区。
pub fn init(
    config_path: &Path,
    device_name: Option<&str>,
    backend_path: &Path,
) -> CoreResult<CommandOutput> {
    let device_name = device_name
        .map(str::to_owned)
        .unwrap_or_else(default_device_name);
    let config = EnvSyncService::init_workspace(config_path, &device_name, backend_path)?;

    let envsync_core::BackendConfig::Local { .. } = &config.backend;
    Ok(CommandOutput::plain(CommandData::Init(InitData {
        workspace: config.workspace_id.to_string(),
        device_name: config.device.name.clone(),
        device: config.device.device_id().to_hex(),
        config_path: display_path(config_path),
        backend_kind: "local".to_owned(),
        state_dir: display_path(&config.state_dir),
    })))
}

/// 未显式指定时的设备名。
///
/// 只看环境变量，不引入额外依赖去问系统主机名——设备名仅供人类辨认，取不到时用一个
/// 稳定的占位值比让 `init` 失败要好。
fn default_device_name() -> String {
    for key in ["ENVSYNC_DEVICE_NAME", "HOSTNAME", "COMPUTERNAME"] {
        if let Some(value) = std::env::var_os(key) {
            let value = value.to_string_lossy().trim().to_owned();
            if !value.is_empty() {
                return value;
            }
        }
    }
    "envsync-device".to_owned()
}

// ---------------------------------------------------------------------------
// capture
// ---------------------------------------------------------------------------

/// `capture` 的数据。
#[derive(Debug, Serialize)]
pub struct CaptureData {
    /// 生成（或复用）的快照标识。
    pub snapshot: String,
    /// 该快照的 State Root 标识。
    pub state_root: String,
    /// 相对后端当前头是否发生变化；`false` 表示本次捕获是幂等空转。
    pub changed: bool,
}

impl CaptureData {
    fn render(&self) -> String {
        let head = if self.changed {
            "已生成新的快照草稿"
        } else {
            "本机内容与后端当前头一致，未生成新草稿"
        };
        format!(
            "{head}\n  快照：{}\n  State Root：{}",
            self.snapshot, self.state_root
        )
    }
}

/// 观察本机现状并生成快照草稿。
pub fn capture(config_path: &Path) -> CoreResult<CommandOutput> {
    let mut service = open(config_path)?;
    let outcome = service.capture()?;
    Ok(CommandOutput {
        data: CommandData::Capture(CaptureData {
            snapshot: outcome.snapshot.to_hex(),
            state_root: outcome.state_root.to_hex(),
            changed: outcome.changed,
        }),
        diagnostics: outcome
            .diagnostics
            .iter()
            .map(DiagnosticOut::from)
            .collect(),
    })
}

// ---------------------------------------------------------------------------
// plan
// ---------------------------------------------------------------------------

/// 计划中的一个动作。
#[derive(Debug, Serialize)]
pub struct PlanActionData {
    /// 关联资源。
    pub resource: String,
    /// 动作种类。
    pub kind: ActionKind,
    /// 写入目标，形如 `home:.zshrc`；**绝不**是绝对路径。
    pub target: String,
    /// 风险等级。
    pub risk: Risk,
    /// 备份策略。
    pub backup: BackupPolicy,
    /// 回滚能力。
    pub rollback: RollbackCapability,
    /// 是否涉及秘密资源。
    ///
    /// 字段名刻意避开 `secret` 一词：脱敏器按键名工作，叫 `secret` 会把这个布尔值
    /// 本身也脱掉。
    pub sensitive: bool,
}

/// `plan` 的数据。
#[derive(Debug, Serialize)]
pub struct PlanData {
    /// 计划标识，`sync --plan` 的入参。
    pub plan: String,
    /// 目标快照。
    pub target_snapshot: String,
    /// 生成计划时后端 Ref 的 revision。
    pub base_revision: u64,
    /// 应用后 Ref 将前进到的 revision。
    pub next_revision: u64,
    /// 动作数量。
    pub action_count: usize,
    /// 是否存在阻塞诊断；为 `true` 时 `sync` 会以退出码 12 拒绝应用。
    pub blocked: bool,
    /// 动作明细。
    pub actions: Vec<PlanActionData>,
}

impl PlanData {
    fn render(&self) -> String {
        let mut text = [
            format!("计划 {}", self.plan),
            format!("  目标快照：{}", self.target_snapshot),
            format!(
                "  Ref revision：{} → {}",
                self.base_revision, self.next_revision
            ),
            format!("  动作：{} 个", self.action_count),
        ]
        .join("\n");
        for action in &self.actions {
            text.push_str(&format!(
                "\n    - {resource}：{kind} → {target}（风险 {risk:?}）",
                resource = action.resource,
                kind = kind_label(action.kind),
                target = action.target,
                risk = action.risk,
            ));
        }
        if self.blocked {
            text.push_str("\n  存在阻塞诊断，本计划不可应用。");
        }
        text
    }
}

/// 动作种类的中文标签。
fn kind_label(kind: ActionKind) -> &'static str {
    match kind {
        ActionKind::DeleteFile => "删除文件",
        ActionKind::CreateFile => "创建文件",
        ActionKind::ReplaceFile => "整体替换",
        ActionKind::UpdateManagedBlock => "更新受管区块",
    }
}

/// 生成计划。
pub fn plan(config_path: &Path) -> CoreResult<CommandOutput> {
    let mut service = open(config_path)?;
    let plan = service.build_plan()?;
    let data = PlanData {
        plan: plan.id().to_hex(),
        target_snapshot: plan.target_snapshot.to_hex(),
        base_revision: plan.base_revision,
        next_revision: plan.next_ref.revision,
        action_count: plan.actions.len(),
        blocked: plan.is_blocked(),
        actions: plan
            .actions
            .iter()
            .map(|action| PlanActionData {
                resource: action.resource.to_string(),
                kind: action.kind,
                target: action.target.display_path(),
                risk: action.risk,
                backup: action.backup,
                rollback: action.rollback,
                sensitive: action.secret,
            })
            .collect(),
    };
    Ok(CommandOutput {
        data: CommandData::Plan(data),
        diagnostics: plan.diagnostics.iter().map(DiagnosticOut::from).collect(),
    })
}

// ---------------------------------------------------------------------------
// sync
// ---------------------------------------------------------------------------

/// `sync` 的数据。
#[derive(Debug, Serialize)]
pub struct SyncData {
    /// 结果：`no_op`（无事可做）或 `completed`（已应用并验证）。
    pub outcome: &'static str,
    /// 本次操作标识；`no_op` 时为 `null`。
    pub operation: Option<String>,
    /// 已应用的动作数量。
    pub applied: usize,
    /// 是否向后端发布了新引用。
    pub published: bool,
}

impl SyncData {
    fn render(&self) -> String {
        match self.operation.as_deref() {
            None => "无事可做：本机已与目标快照一致。".to_owned(),
            Some(operation) => format!(
                "同步完成\n  操作：{operation}\n  已应用动作：{applied}\n  后端发布：{published}",
                applied = self.applied,
                published = if self.published { "是" } else { "否" },
            ),
        }
    }
}

/// 应用指定计划。
pub fn sync(config_path: &Path, plan: PlanId) -> CoreResult<CommandOutput> {
    let mut service = open(config_path)?;
    let data = match service.apply_plan(plan)? {
        ApplyOutcome::NoOp => SyncData {
            outcome: "no_op",
            operation: None,
            applied: 0,
            published: false,
        },
        ApplyOutcome::Completed {
            operation,
            applied,
            published,
        } => SyncData {
            outcome: "completed",
            operation: Some(operation.to_string()),
            applied,
            published,
        },
    };
    Ok(CommandOutput::plain(CommandData::Sync(data)))
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

/// 单个资源的状态。
#[derive(Debug, Serialize)]
pub struct ResourceStatusData {
    /// 资源标识。
    pub resource: String,
    /// 观察状态：`present` / `absent` / `unreadable` / `unsupported` / `excluded`。
    pub observed: &'static str,
    /// 目标快照中的期望处置；快照里没有该资源时为 `null`。
    pub disposition: Option<DesiredDisposition>,
    /// 是否需要写入。
    pub needs_action: bool,
}

/// 一条未完成操作。
#[derive(Debug, Serialize)]
pub struct UnfinishedOperationData {
    /// 操作标识。
    pub operation: String,
    /// 操作当前状态。
    pub state: &'static str,
}

/// `status` 的数据。
#[derive(Debug, Serialize)]
pub struct StatusData {
    /// 工作区标识。
    pub workspace: String,
    /// 本设备标识。
    pub device: String,
    /// 后端种类。
    pub backend_kind: String,
    /// 后端当前 revision。
    pub revision: u64,
    /// 后端当前头；从未发布过时为 `null`。
    pub head: Option<String>,
    /// 本地草稿头；没有未发布草稿时为 `null`。
    pub draft_head: Option<String>,
    /// 整体状态：`clean` / `drifted` / `conflicted` / `published_not_converged`。
    pub state: &'static str,
    /// 待应用动作数量。
    pub pending_actions: usize,
    /// 逐资源状态。
    pub resources: Vec<ResourceStatusData>,
    /// 未完成操作。
    pub unfinished: Vec<UnfinishedOperationData>,
}

impl StatusData {
    fn render(&self) -> String {
        let mut text = [
            format!("工作区 {}（{}）", self.workspace, state_label(self.state)),
            format!("  设备：{}", self.device),
            format!("  后端：{}，revision {}", self.backend_kind, self.revision),
            format!("  当前头：{}", self.head.as_deref().unwrap_or("（无）")),
            format!(
                "  草稿头：{}",
                self.draft_head.as_deref().unwrap_or("（无）")
            ),
            format!("  待应用动作：{}", self.pending_actions),
        ]
        .join("\n");
        for resource in &self.resources {
            text.push_str(&format!(
                "\n    - {resource}：观察 {observed}{mark}",
                resource = resource.resource,
                observed = resource.observed,
                mark = if resource.needs_action {
                    "，需要写入"
                } else {
                    ""
                },
            ));
        }
        for unfinished in &self.unfinished {
            text.push_str(&format!(
                "\n    ! 未完成操作 {}：{}",
                unfinished.operation, unfinished.state
            ));
        }
        text
    }
}

/// 工作区状态的中文标签。
fn state_label(state: &str) -> String {
    let label = match state {
        "clean" => "已收敛",
        "drifted" => "存在待应用变更",
        "conflicted" => "存在冲突",
        "published_not_converged" => "已发布但本地未收敛",
        _ => "未知",
    };
    format!("{state}／{label}")
}

/// 汇总工作区状态。
pub fn status(config_path: &Path) -> CoreResult<CommandOutput> {
    let mut service = open(config_path)?;
    let report: StatusReport = service.status()?;
    let data = StatusData {
        workspace: report.workspace.to_string(),
        device: report.device.to_hex(),
        backend_kind: report.backend_kind.to_owned(),
        revision: report.revision,
        head: report.head.map(|id| id.to_hex()),
        draft_head: report.draft_head.map(|id| id.to_hex()),
        state: report.state.as_str(),
        pending_actions: report.pending_actions,
        resources: report
            .resources
            .iter()
            .map(|resource| ResourceStatusData {
                resource: resource.resource.to_string(),
                observed: resource.observed,
                disposition: resource.disposition,
                needs_action: resource.needs_action,
            })
            .collect(),
        unfinished: report
            .unfinished
            .iter()
            .map(|(operation, state)| UnfinishedOperationData {
                operation: operation.to_string(),
                state: state.as_str(),
            })
            .collect(),
    };
    Ok(CommandOutput {
        data: CommandData::Status(data),
        diagnostics: report.diagnostics.iter().map(DiagnosticOut::from).collect(),
    })
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

/// 一条体检结论。
#[derive(Debug, Serialize)]
pub struct DoctorFindingData {
    /// 检查项名称。
    pub check: String,
    /// 是否通过。
    pub ok: bool,
    /// 说明。
    pub detail: String,
}

/// 一条恢复诊断。
#[derive(Debug, Serialize)]
pub struct RecoveryDiagnosisData {
    /// 操作标识。
    pub operation: String,
    /// 操作当前状态。
    pub state: &'static str,
    /// 建议处理方式：`nothing` / `abort_staged` / `reconverge` / `continue_rollback` / `manual`。
    pub suggestion: &'static str,
    /// 待处理动作数量；与数量无关的建议为 `null`。
    pub pending: Option<usize>,
    /// 需要人工处理时的原因。
    pub reason: Option<String>,
    /// 补充说明。
    pub notes: Vec<String>,
}

/// `doctor` 的数据。
#[derive(Debug, Serialize)]
pub struct DoctorData {
    /// 是否全部健康。
    ///
    /// `doctor` 只报告不修复，因此即使不健康，命令本身仍以退出码 0 结束；调用方应当
    /// 读这个字段而不是退出码来判断。
    pub healthy: bool,
    /// 逐项检查结果。
    pub findings: Vec<DoctorFindingData>,
    /// 恢复诊断（只读）。
    pub recovery: Vec<RecoveryDiagnosisData>,
}

impl DoctorData {
    fn render(&self) -> String {
        let mut text = format!(
            "体检结果：{}",
            if self.healthy {
                "全部通过"
            } else {
                "存在问题"
            }
        );
        for finding in &self.findings {
            text.push_str(&format!(
                "\n  {mark} {check}：{detail}",
                mark = if finding.ok { "✓" } else { "✗" },
                check = finding.check,
                detail = finding.detail,
            ));
        }
        for diagnosis in &self.recovery {
            text.push_str(&format!(
                "\n  ! 操作 {operation}（{state}）建议：{suggestion}",
                operation = diagnosis.operation,
                state = diagnosis.state,
                suggestion = diagnosis.suggestion,
            ));
        }
        text
    }
}

/// 只读体检。
pub fn doctor(config_path: &Path) -> CoreResult<CommandOutput> {
    let mut service = open(config_path)?;
    let report: DoctorReport = service.doctor()?;
    let data = DoctorData {
        healthy: report.is_healthy(),
        findings: report
            .findings
            .iter()
            .map(|finding| DoctorFindingData {
                check: finding.check.clone(),
                ok: finding.ok,
                detail: finding.detail.clone(),
            })
            .collect(),
        recovery: report.recovery.iter().map(diagnosis_data).collect(),
    };
    Ok(CommandOutput::plain(CommandData::Doctor(data)))
}

/// 把核心层的恢复诊断翻译成对外结构。
fn diagnosis_data(diagnosis: &RecoveryDiagnosis) -> RecoveryDiagnosisData {
    let (suggestion, pending, reason) = match &diagnosis.suggestion {
        RecoverySuggestion::Nothing => ("nothing", None, None),
        RecoverySuggestion::AbortStaged => ("abort_staged", None, None),
        RecoverySuggestion::Reconverge { pending } => ("reconverge", Some(*pending), None),
        RecoverySuggestion::ContinueRollback { pending } => {
            ("continue_rollback", Some(*pending), None)
        }
        RecoverySuggestion::Manual { reason } => ("manual", None, Some(reason.clone())),
    };
    RecoveryDiagnosisData {
        operation: diagnosis.operation.to_string(),
        state: diagnosis.state.as_str(),
        suggestion,
        pending,
        reason,
        notes: diagnosis.notes.clone(),
    }
}

// ---------------------------------------------------------------------------
// rollback / recover
// ---------------------------------------------------------------------------

/// 一次恢复或回滚的执行结果。
#[derive(Debug, Serialize)]
pub struct RecoveryReportData {
    /// 操作标识。
    pub operation: String,
    /// 处理前状态。
    pub before: &'static str,
    /// 处理后状态。
    pub after: &'static str,
    /// 执行摘要。
    pub notes: Vec<String>,
}

/// `rollback` 与 `recover` 的数据。
#[derive(Debug, Serialize)]
pub struct RecoveryData {
    /// 本次处理的操作数量。
    pub handled: usize,
    /// 逐个操作的处理结果。
    pub operations: Vec<RecoveryReportData>,
}

impl RecoveryData {
    fn render(&self) -> String {
        if self.operations.is_empty() {
            return "没有需要处理的操作。".to_owned();
        }
        let mut text = format!("已处理 {} 个操作", self.handled);
        for report in &self.operations {
            text.push_str(&format!(
                "\n  - {operation}：{before} → {after}",
                operation = report.operation,
                before = report.before,
                after = report.after,
            ));
            for note in &report.notes {
                text.push_str(&format!("\n    {note}"));
            }
        }
        text
    }
}

/// 显式回滚一次操作。
pub fn rollback(config_path: &Path, operation: OperationId) -> CoreResult<CommandOutput> {
    let mut service = open(config_path)?;
    let report = service.rollback(operation)?;
    Ok(CommandOutput::plain(CommandData::Recovery(RecoveryData {
        handled: 1,
        operations: vec![report_data(&report)],
    })))
}

/// 显式触发崩溃恢复。
pub fn recover(config_path: &Path) -> CoreResult<CommandOutput> {
    let mut service = open(config_path)?;
    let reports = service.recover()?;
    Ok(CommandOutput::plain(CommandData::Recovery(RecoveryData {
        handled: reports.len(),
        operations: reports.iter().map(report_data).collect(),
    })))
}

/// 把核心层的恢复报告翻译成对外结构。
fn report_data(report: &RecoveryReport) -> RecoveryReportData {
    RecoveryReportData {
        operation: report.operation.to_string(),
        before: report.before.as_str(),
        after: report.after.as_str(),
        notes: report.notes.clone(),
    }
}

// ---------------------------------------------------------------------------
// 公共工具
// ---------------------------------------------------------------------------

/// 读取配置并打开服务。
fn open(config_path: &Path) -> CoreResult<EnvSyncService> {
    let config = WorkspaceConfig::load(config_path)?;
    EnvSyncService::open(config)
}

/// 路径的展示形式。
///
/// 非 UTF-8 路径按有损方式转换：输出是给人看的，不应该因为一个奇怪的文件名就失败。
fn display_path(path: &Path) -> String {
    PathBuf::from(path).to_string_lossy().into_owned()
}
