//! 子命令实现与对外 JSON 数据结构。
//!
//! 本模块是 CLI 与 [`envsync_core::EnvSyncService`] 之间**唯一**的胶水层：所有安全
//! 决策（计划、策略、日志、回滚）都在核心层完成，这里只做三件事——把配置读进来、
//! 调用服务、把结果翻译成对外契约。
//!
//! `data` 的每个形状都是具名的 `Serialize` 结构体，而不是临时拼出来的
//! `serde_json::json!`：字段名是对外承诺，写错时应当编译失败，改动时应当被 golden
//! test 抓住。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use envsync_adapters::{AdapterContext, AdapterRegistry, DiscoveredResource, ROOT_SYSTEM};
use envsync_core::{
    ApplyOutcome, CoreError, CoreResult, DoctorReport, EnvSyncService, RecoveryDiagnosis,
    RecoveryReport, RecoverySuggestion, ResourceConfig, StatusReport, WorkspaceConfig,
};
use envsync_domain::{
    ActionKind, BackupPolicy, ConflictId, ConflictKind, DesiredDisposition, DeviceProfile,
    FileMode, OperationId, PlanId, ProjectionNoteKind, ResolutionChoice, Risk, RollbackCapability,
    Selector, StructuredFormat,
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
    /// `fetch` 的数据（schema v2 起）。
    Fetch(FetchData),
    /// `merge` 的数据（schema v2 起）。
    Merge(MergeData),
    /// `conflicts list` 的数据（schema v2 起）。
    ConflictList(ConflictListData),
    /// `conflicts show` 的数据（schema v2 起）。
    ConflictShow(ConflictShowData),
    /// `conflicts resolve` 的数据（schema v2 起）。
    ConflictResolve(ConflictResolveData),
    /// `profile explain` 的数据（schema v2 起）。
    ProfileExplain(ProfileExplainData),
    /// `adapters list` 的数据（schema v2 起）。
    AdapterList(AdapterListData),
    /// `adapters discover` 的数据（schema v2 起）。
    AdapterDiscover(AdapterDiscoverData),
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
            CommandData::Fetch(data) => data.render(),
            CommandData::Merge(data) => data.render(),
            CommandData::ConflictList(data) => data.render(),
            CommandData::ConflictShow(data) => data.render(),
            CommandData::ConflictResolve(data) => data.render(),
            CommandData::ProfileExplain(data) => data.render(),
            CommandData::AdapterList(data) => data.render(),
            CommandData::AdapterDiscover(data) => data.render(),
        }
    }

    /// 本形状中**只在 schema v2 存在**的字段。
    ///
    /// `--schema-version 1` 时它们会被从 `data` 里剔除，从而精确还原 v1 的字段集合。
    /// 只在 v2 才有的整条命令不走这里：它们在派发阶段就被拒绝。
    pub fn v2_only_fields(&self) -> &'static [&'static str] {
        match self {
            CommandData::Status(_) => &[
                "open_conflicts",
                "backend_reachable",
                "last_known_revision_at_unix_ms",
            ],
            CommandData::Init(_) => &["discovered_resources"],
            CommandData::Plan(_) => &["device_view"],
            _ => &[],
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
    /// 后端种类；`init` 生成的工作区恒为 `local`。
    pub backend_kind: String,
    /// 本地状态目录（journal / 草稿 / 备份）。
    pub state_dir: String,
    /// 由内建适配器自动写进配置的资源数量（schema v2 起）。
    ///
    /// 没有加 `--discover` 时恒为 `0`：初始化默认生成**空**资源列表，由用户自己决定
    /// 管什么。
    pub discovered_resources: usize,
}

impl InitData {
    fn render(&self) -> String {
        let next = if self.discovered_resources > 0 {
            format!(
                "已自动写入 {} 个由内建适配器发现的资源。\n\
                 下一步：`envsync adapters discover` 可复核这份清单，确认无误后运行 \
                 `envsync capture`。",
                self.discovered_resources
            )
        } else {
            "下一步：编辑配置里的 resources（`envsync adapters discover` 可生成一份建议），\
             然后运行 `envsync capture`。"
                .to_owned()
        };
        [
            format!("已初始化工作区 {}", self.workspace),
            format!("  设备：{}（{}）", self.device_name, self.device),
            format!("  配置：{}", self.config_path),
            format!("  后端：{}", self.backend_kind),
            format!("  状态目录：{}", self.state_dir),
            next,
        ]
        .join("\n")
    }
}

/// 初始化工作区。
///
/// `discover` 为 `true` 时，在生成配置之后立刻跑一次适配器发现，把结果写回同一个配置
/// 文件。发现是纯计算，不读用户文件也不联网，因此这一步不会因为「机器上还没有 `.zshrc`」
/// 而失败——它声明的是「这台设备上**应该**管哪些文件」，实际存不存在由 `capture` 观察。
pub fn init(
    config_path: &Path,
    device_name: Option<&str>,
    backend_path: &Path,
    discover: bool,
) -> CoreResult<CommandOutput> {
    let device_name = device_name
        .map(str::to_owned)
        .unwrap_or_else(default_device_name);
    let mut config = EnvSyncService::init_workspace(config_path, &device_name, backend_path)?;

    let mut diagnostics = Vec::new();
    if discover {
        let (discovered, _) = discover_resources(&config);
        config.resources = to_resource_configs(&discovered);
        // 重写刚刚生成的那个文件。这里**不是**覆盖用户的已有工作区：`init_workspace`
        // 已经确认过配置文件原本不存在，这个文件是本命令自己在几行之前写下的。
        std::fs::write(config_path, config.to_yaml()?).map_err(|error| {
            // 只回显文件名与错误类别，绝不把绝对路径写进诊断。
            envsync_platform_error(config_path, &error)
        })?;
        if config.resources.is_empty() {
            diagnostics.push(DiagnosticOut::warning(
                "adapters.nothing_discovered",
                "没有发现任何可管理的资源，配置里的 resources 仍然是空的。".to_owned(),
            ));
        }
        diagnostics.extend(system_root_note(&config));
    }

    Ok(CommandOutput {
        data: CommandData::Init(InitData {
            workspace: config.workspace_id.to_string(),
            device_name: config.device.name.clone(),
            device: config.device.device_id().to_hex(),
            config_path: display_path(config_path),
            backend_kind: config.backend.kind().to_owned(),
            state_dir: display_path(&config.state_dir),
            discovered_resources: config.resources.len(),
        }),
        diagnostics,
    })
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
    /// 本设备视图（投影后的目标状态）标识（schema v2 起）。
    pub device_view: String,
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
    // 计划针对的是**投影后**的目标状态；把视图标识一并输出，便于跨设备比对
    // 「同一个快照在不同设备上应当收敛到什么」。
    let device_view = service.profile_explain()?.device_view;
    let data = PlanData {
        plan: plan.id().to_hex(),
        target_snapshot: plan.target_snapshot.to_hex(),
        base_revision: plan.base_revision,
        next_revision: plan.next_ref.revision,
        action_count: plan.actions.len(),
        blocked: plan.is_blocked(),
        device_view: device_view.to_hex(),
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
    /// 后端是否可达（schema v2 起）。
    ///
    /// 为 `false` 时 `revision` / `head` / `resources` 反映的是本地记录的**上次已知**
    /// 状态，而不是远端此刻的内容。
    pub backend_reachable: bool,
    /// 上次成功读到后端 Ref 的本机时刻，Unix 毫秒（schema v2 起）。
    ///
    /// 只在 `backend_reachable` 为 `false` 时有值：它回答「这份状态有多旧」。
    pub last_known_revision_at_unix_ms: Option<u64>,
    /// 后端当前 revision；后端不可达时是上次已知的 revision。
    pub revision: u64,
    /// 后端当前头；从未发布过时为 `null`。后端不可达时是上次已知的头。
    pub head: Option<String>,
    /// 本地草稿头；没有未发布草稿时为 `null`。
    pub draft_head: Option<String>,
    /// 整体状态：`clean` / `drifted` / `conflicted` / `published_not_converged` /
    /// `backend_unreachable`。
    pub state: &'static str,
    /// 待应用动作数量。
    pub pending_actions: usize,
    /// 未解决的合并冲突数量（schema v2 起）。
    pub open_conflicts: usize,
    /// 逐资源状态。
    pub resources: Vec<ResourceStatusData>,
    /// 未完成操作。
    pub unfinished: Vec<UnfinishedOperationData>,
}

impl StatusData {
    fn render(&self) -> String {
        let backend_line = if self.backend_reachable {
            format!("  后端：{}，revision {}", self.backend_kind, self.revision)
        } else {
            // 不可达时把「这是旧数据」写在最显眼的位置，避免读者顺手把 revision 当现状。
            format!(
                "  后端：{}，不可达；以下为上次已知状态（revision {}{}）",
                self.backend_kind,
                self.revision,
                match self.last_known_revision_at_unix_ms {
                    Some(at) => format!("，本机时刻 {at} ms"),
                    None => String::new(),
                }
            )
        };
        let mut text = [
            format!("工作区 {}（{}）", self.workspace, state_label(self.state)),
            format!("  设备：{}", self.device),
            backend_line,
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
        "backend_unreachable" => "后端不可达，显示的是上次已知状态",
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
        backend_reachable: report.backend_reachable,
        last_known_revision_at_unix_ms: report.last_known_revision_at_unix_ms,
        revision: report.revision,
        head: report.head.map(|id| id.to_hex()),
        draft_head: report.draft_head.map(|id| id.to_hex()),
        state: report.state.as_str(),
        pending_actions: report.pending_actions,
        open_conflicts: report.open_conflicts,
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
// fetch
// ---------------------------------------------------------------------------

/// `fetch` 的数据。
#[derive(Debug, Serialize)]
pub struct FetchData {
    /// 远端当前 revision。
    pub revision: u64,
    /// 远端当前头；从未发布过时为 `null`。
    pub head: Option<String>,
    /// 本次拉进本地草稿库的对象数量。
    pub objects: usize,
    /// 本地是否已拥有远端头的全部可达对象。
    pub up_to_date: bool,
}

impl FetchData {
    fn render(&self) -> String {
        format!(
            "已读取远端引用\n  revision：{}\n  远端头：{}\n  新增对象：{}",
            self.revision,
            self.head.as_deref().unwrap_or("（无）"),
            self.objects,
        )
    }
}

/// 读取远端引用并拉取可达对象。
pub fn fetch(config_path: &Path) -> CoreResult<CommandOutput> {
    let mut service = open(config_path)?;
    let outcome = service.fetch()?;
    Ok(CommandOutput::plain(CommandData::Fetch(FetchData {
        revision: outcome.revision,
        head: outcome.head.map(|id| id.to_hex()),
        objects: outcome.objects,
        up_to_date: outcome.up_to_date,
    })))
}

// ---------------------------------------------------------------------------
// merge
// ---------------------------------------------------------------------------

/// `merge` 的数据。
#[derive(Debug, Serialize)]
pub struct MergeData {
    /// 结论：`already_up_to_date` / `fast_forward` / `merged` / `conflicted`。
    pub outcome: &'static str,
    /// 本地草稿头。
    pub local: Option<String>,
    /// 远端头。
    pub remote: Option<String>,
    /// 合并基。
    pub base: Option<String>,
    /// 合并后的目标快照；冲突时为 `null`。
    pub merged: Option<String>,
    /// 合并后的 State Root；冲突时为 `null`。
    pub state_root: Option<String>,
    /// 参与合并的资源数量。
    pub resources: usize,
    /// 本次登记的冲突标识。
    pub conflicts: Vec<String>,
}

impl MergeData {
    fn render(&self) -> String {
        let mut text = [
            format!("合并结论：{}", merge_label(self.outcome)),
            format!("  本地：{}", self.local.as_deref().unwrap_or("（无）")),
            format!("  远端：{}", self.remote.as_deref().unwrap_or("（无）")),
            format!("  合并基：{}", self.base.as_deref().unwrap_or("（无）")),
        ]
        .join("\n");
        if let Some(merged) = &self.merged {
            text.push_str(&format!("\n  合并快照：{merged}"));
        }
        for conflict in &self.conflicts {
            text.push_str(&format!("\n    ! 冲突 {conflict}"));
        }
        if !self.conflicts.is_empty() {
            text.push_str(
                "\n  存在未解决冲突：本地文件与远端引用都没有被改动；\
                 请用 `envsync conflicts resolve` 裁决后重新 merge。",
            );
        }
        text
    }
}

/// 合并结论的中文标签。
fn merge_label(outcome: &str) -> String {
    let label = match outcome {
        "already_up_to_date" => "已是最新",
        "fast_forward" => "快进到远端",
        "merged" => "已三方合并",
        "conflicted" => "存在冲突",
        _ => "未知",
    };
    format!("{outcome}／{label}")
}

/// 合并本地草稿头与远端头。
pub fn merge(config_path: &Path) -> CoreResult<CommandOutput> {
    let mut service = open(config_path)?;
    let outcome = service.merge_states()?;
    Ok(CommandOutput::plain(CommandData::Merge(MergeData {
        outcome: outcome.kind.as_str(),
        local: outcome.local.map(|id| id.to_hex()),
        remote: outcome.remote.map(|id| id.to_hex()),
        base: outcome.base.map(|id| id.to_hex()),
        merged: outcome.merged.map(|id| id.to_hex()),
        state_root: outcome.state_root.map(|id| id.to_hex()),
        resources: outcome.resources,
        conflicts: outcome.conflicts.iter().map(|id| id.to_hex()).collect(),
    })))
}

// ---------------------------------------------------------------------------
// conflicts
// ---------------------------------------------------------------------------

/// 冲突列表中的一条。
#[derive(Debug, Serialize)]
pub struct ConflictSummaryData {
    /// 冲突标识。
    pub conflict: String,
    /// 发生冲突的资源。
    pub resource: String,
    /// 冲突种类。
    pub kind: &'static str,
    /// 当前状态。
    pub state: &'static str,
}

/// `conflicts list` 的数据。
#[derive(Debug, Serialize)]
pub struct ConflictListData {
    /// 未解决冲突数量。
    pub open: usize,
    /// 逐条冲突。
    pub conflicts: Vec<ConflictSummaryData>,
}

impl ConflictListData {
    fn render(&self) -> String {
        if self.conflicts.is_empty() {
            return "没有未解决的冲突。".to_owned();
        }
        let mut text = format!("未解决冲突：{} 个", self.open);
        for conflict in &self.conflicts {
            text.push_str(&format!(
                "\n  - {conflict}（{resource}，{kind}）",
                conflict = conflict.conflict,
                resource = conflict.resource,
                kind = conflict.kind,
            ));
        }
        text
    }
}

/// `conflicts show` 的数据。
#[derive(Debug, Serialize)]
pub struct ConflictShowData {
    /// 冲突标识。
    pub conflict: String,
    /// 发生冲突的资源。
    pub resource: String,
    /// 冲突种类。
    pub kind: &'static str,
    /// 当前状态。
    pub state: &'static str,
    /// 合并基一侧的内容标识。
    pub base: Option<String>,
    /// 本地一侧的内容标识。
    pub ours: Option<String>,
    /// 远端一侧的内容标识。
    pub theirs: Option<String>,
    /// 结构性诊断（键路径或行区间），**不含**文件正文。
    pub diagnostics: Vec<String>,
}

impl ConflictShowData {
    fn render(&self) -> String {
        let mut text = [
            format!("冲突 {}", self.conflict),
            format!("  资源：{}", self.resource),
            format!("  种类：{}", self.kind),
            format!("  状态：{}", self.state),
            format!("  base：{}", self.base.as_deref().unwrap_or("（无）")),
            format!("  ours：{}", self.ours.as_deref().unwrap_or("（无）")),
            format!("  theirs：{}", self.theirs.as_deref().unwrap_or("（无）")),
        ]
        .join("\n");
        for diagnostic in &self.diagnostics {
            text.push_str(&format!("\n    · {diagnostic}"));
        }
        text
    }
}

/// `conflicts resolve` 的数据。
#[derive(Debug, Serialize)]
pub struct ConflictResolveData {
    /// 被裁决的冲突。
    pub conflict: String,
    /// 裁决方式：`ours` / `theirs` / `manual` / `delete`。
    pub choice: &'static str,
    /// 裁决结果对应的 Blob；`delete` 时为 `null`。
    pub resolved_blob: Option<String>,
}

impl ConflictResolveData {
    fn render(&self) -> String {
        format!(
            "冲突 {conflict} 已裁决为 {choice}\n  结果内容：{blob}\n下一步：重新运行 `envsync merge`。",
            conflict = self.conflict,
            choice = self.choice,
            blob = self.resolved_blob.as_deref().unwrap_or("（删除）"),
        )
    }
}

/// 冲突种类的稳定短名。
fn conflict_kind_name(kind: ConflictKind) -> &'static str {
    match kind {
        ConflictKind::TextOverlap => "text_overlap",
        ConflictKind::DeleteModify => "delete_modify",
        ConflictKind::StructuredKey => "structured_key",
        ConflictKind::BinaryBoth => "binary_both",
        ConflictKind::IncompatiblePolicy => "incompatible_policy",
    }
}

/// 列出未解决的冲突。
pub fn conflicts_list(config_path: &Path) -> CoreResult<CommandOutput> {
    let service = open(config_path)?;
    let records = service.conflicts_list()?;
    Ok(CommandOutput::plain(CommandData::ConflictList(
        ConflictListData {
            open: records.len(),
            conflicts: records
                .iter()
                .map(|record| ConflictSummaryData {
                    conflict: record.conflict.to_hex(),
                    resource: record.resource.to_string(),
                    kind: conflict_kind_name(record.kind),
                    state: record.state.as_str(),
                })
                .collect(),
        },
    )))
}

/// 查看单个冲突。
pub fn conflicts_show(config_path: &Path, conflict: ConflictId) -> CoreResult<CommandOutput> {
    let service = open(config_path)?;
    let detail = service.conflicts_show(conflict)?;
    Ok(CommandOutput::plain(CommandData::ConflictShow(
        ConflictShowData {
            conflict: detail.record.conflict.to_hex(),
            resource: detail.record.resource.to_string(),
            kind: conflict_kind_name(detail.record.kind),
            state: detail.record.state.as_str(),
            base: detail.conflict.base.map(|id| id.to_hex()),
            ours: detail.conflict.ours.map(|id| id.to_hex()),
            theirs: detail.conflict.theirs.map(|id| id.to_hex()),
            diagnostics: detail.conflict.diagnostics.clone(),
        },
    )))
}

/// 裁决一个冲突。
///
/// `content_path` 只对 `manual` 有意义：读入的字节会被存成新的 Blob。
pub fn conflicts_resolve(
    config_path: &Path,
    conflict: ConflictId,
    choice: ResolutionChoice,
    content_path: Option<&Path>,
) -> CoreResult<CommandOutput> {
    let mut service = open(config_path)?;
    let content = match content_path {
        Some(path) => Some(std::fs::read(path).map_err(|error| {
            // 只回显文件名：诊断里不出现绝对路径。
            envsync_platform_error(path, &error)
        })?),
        None => None,
    };
    let resolution = service.conflicts_resolve(conflict, choice, content.as_deref())?;
    Ok(CommandOutput::plain(CommandData::ConflictResolve(
        ConflictResolveData {
            conflict: resolution.conflict.to_hex(),
            choice: resolution.choice.as_str(),
            resolved_blob: resolution.resolved_blob.map(|id| id.to_hex()),
        },
    )))
}

/// 读取裁决内容失败时的错误；只保留文件名与错误类别。
fn envsync_platform_error(path: &Path, error: &std::io::Error) -> CoreError {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "裁决内容文件".to_owned());
    CoreError::ManualInterventionRequired(format!("读取 `{name}` 失败：{}", error.kind()))
}

// ---------------------------------------------------------------------------
// profile
// ---------------------------------------------------------------------------

/// 单个资源的投影结论。
#[derive(Debug, Serialize)]
pub struct ProjectionNoteData {
    /// 资源标识。
    pub resource: String,
    /// 结论种类。
    pub kind: &'static str,
    /// 是否出现在本设备视图里。
    pub included: bool,
    /// 人类可读说明。
    pub detail: String,
}

/// `profile explain` 的数据。
#[derive(Debug, Serialize)]
pub struct ProfileExplainData {
    /// 操作系统（编译期探测，不可由配置声明）。
    pub os: &'static str,
    /// 处理器架构（编译期探测）。
    pub arch: &'static str,
    /// 主机名；未声明时为 `null`。
    pub hostname: Option<String>,
    /// 设备标识。
    pub device: String,
    /// 设备标签。
    pub tags: Vec<String>,
    /// 可用能力。
    pub capabilities: Vec<String>,
    /// 被投影的完整状态；工作区尚无快照时为 `null`。
    pub state_root: Option<String>,
    /// 投影结果的标识。
    pub device_view: String,
    /// 逐资源结论。
    pub resources: Vec<ProjectionNoteData>,
}

impl ProfileExplainData {
    fn render(&self) -> String {
        let mut text = [
            format!("设备 Profile（{}）", self.device),
            format!("  平台：{} / {}", self.os, self.arch),
            format!(
                "  主机名：{}",
                self.hostname.as_deref().unwrap_or("（未声明）")
            ),
            format!("  标签：{}", join_or_dash(&self.tags)),
            format!("  能力：{}", join_or_dash(&self.capabilities)),
            format!("  设备视图：{}", self.device_view),
        ]
        .join("\n");
        for note in &self.resources {
            text.push_str(&format!(
                "\n    {mark} {resource}：{kind}——{detail}",
                mark = if note.included { "✓" } else { "·" },
                resource = note.resource,
                kind = note.kind,
                detail = note.detail,
            ));
        }
        text
    }
}

fn join_or_dash(items: &[String]) -> String {
    if items.is_empty() {
        "（无）".to_owned()
    } else {
        items.join("、")
    }
}

/// 投影结论种类的稳定短名，以及它是否代表「已下发」。
fn note_kind_name(kind: ProjectionNoteKind) -> (&'static str, bool) {
    match kind {
        ProjectionNoteKind::SelectedByGlobal => ("selected_by_global", true),
        ProjectionNoteKind::SelectedBySelector => ("selected_by_selector", true),
        ProjectionNoteKind::OverriddenByDevice => ("overridden_by_device", true),
        ProjectionNoteKind::ExcludedBySelector => ("excluded_by_selector", false),
        ProjectionNoteKind::ExcludedByPolicy => ("excluded_by_policy", false),
        ProjectionNoteKind::UnsupportedCapability => ("unsupported_capability", false),
    }
}

/// 解释本设备的 Profile 与投影结论。
pub fn profile_explain(config_path: &Path) -> CoreResult<CommandOutput> {
    let mut service = open(config_path)?;
    let report = service.profile_explain()?;
    let data = ProfileExplainData {
        os: report.profile.os.as_str(),
        arch: report.profile.arch.as_str(),
        hostname: report.profile.hostname.clone(),
        device: report
            .profile
            .device
            .map(|id| id.to_hex())
            .unwrap_or_default(),
        tags: report.profile.tags.iter().cloned().collect(),
        capabilities: report.profile.capabilities.iter().cloned().collect(),
        state_root: report.state_root.map(|id| id.to_hex()),
        device_view: report.device_view.to_hex(),
        resources: report
            .notes
            .iter()
            .map(|note| {
                let (kind, included) = note_kind_name(note.kind);
                ProjectionNoteData {
                    resource: note.resource.to_string(),
                    kind,
                    included,
                    detail: note.detail.clone(),
                }
            })
            .collect(),
    };
    Ok(CommandOutput::plain(CommandData::ProfileExplain(data)))
}

// ---------------------------------------------------------------------------
// adapters
//
// 这两条命令是 `envsync-adapters` 的**消费者**：在此之前那个 crate 虽然完整实现并有
// 跨平台 fixture 覆盖，却没有任何调用方，用户只能照着文档手抄资源表。
//
// 分工保持不变：适配器只做纯计算（给定 Profile 与授权根前缀，算出「应该管哪些文件」），
// 真正的读写仍然由配置驱动。因此 `discover` 的产物是**一段可粘贴的配置**，而不是一条
// 绕过配置直接生效的旁路——用户始终看得到、改得动、审阅得了自己在同步什么。
// ---------------------------------------------------------------------------

/// 由配置推导适配器可见的「授权根别名 -> 相对前缀」表。
///
/// 前缀一律是空串：EnvSync 的授权根**就是**配置里那个绝对路径，适配器的资源路径本来
/// 就相对它。`AdapterContext` 之所以留了这个前缀，是为了容纳「授权根是主目录的上一层」
/// 这类布局；本 CLI 不使用那种布局。
///
/// 只放**配置里真实声明过**的别名：凭空补一个 `system` 会让 `discover` 产出一条指向
/// 未授权目录的资源，而用户根本没同意过写那里。
fn adapter_roots(config: &WorkspaceConfig) -> BTreeMap<String, String> {
    config
        .roots
        .keys()
        .map(|alias| (alias.clone(), String::new()))
        .collect()
}

/// 文件管理模式的稳定短名，与配置里的写法一致（照抄即可）。
fn mode_name(mode: FileMode) -> &'static str {
    match mode {
        FileMode::FullFile => "full_file",
        FileMode::ManagedBlock => "managed_block",
        FileMode::StructuredMerge => "structured_merge",
        FileMode::GeneratedInclude => "generated_include",
    }
}

/// 期望处置的稳定短名，与配置里的写法一致。
fn disposition_name(disposition: DesiredDisposition) -> &'static str {
    match disposition {
        DesiredDisposition::Managed => "managed",
        DesiredDisposition::EnsureAbsent => "ensure_absent",
        DesiredDisposition::Unmanaged => "unmanaged",
    }
}

/// 适配器发现出的一条资源。
#[derive(Debug, Serialize)]
pub struct AdapterResourceData {
    /// 资源标识。
    pub resource: String,
    /// 授权根别名。
    pub root: String,
    /// 相对该授权根的目标路径。
    pub target: String,
    /// 文件管理模式。
    pub mode: FileMode,
    /// 期望处置。内建适配器只会产出 `managed` 或 `unmanaged`，绝不产出 `ensure_absent`。
    pub disposition: DesiredDisposition,
    /// 结构化合并格式；不适用时为 `null`。
    pub structured_format: Option<StructuredFormat>,
    /// 该资源的选择器在本设备上是否命中；无选择器时恒为 `true`。
    pub selected: bool,
}

impl AdapterResourceData {
    fn from_discovered(discovered: &DiscoveredResource, profile: &DeviceProfile) -> Self {
        AdapterResourceData {
            resource: discovered.id.to_string(),
            root: discovered.root.clone(),
            target: discovered.target.clone(),
            mode: discovered.mode,
            disposition: discovered.disposition,
            structured_format: discovered.policy.structured_format,
            selected: selector_matches(discovered.selector.as_ref(), profile),
        }
    }
}

/// 求值资源级选择器；与 `AdapterRegistry::discover_all` 用同一条规则。
///
/// 先 `validate` 再 `matches`：选择器虽然来自内建适配器（可信），但这是 `Selector` 的
/// 使用契约，校验失败时保守判为「不匹配」。
fn selector_matches(selector: Option<&Selector>, profile: &DeviceProfile) -> bool {
    match selector {
        None => true,
        Some(selector) => selector.validate().is_ok() && selector.matches(profile),
    }
}

/// 一个内建适配器的自述与它在本设备上的资源。
#[derive(Debug, Serialize)]
pub struct AdapterData {
    /// 稳定 ID，跨版本不变。
    pub id: String,
    /// 展示名。
    pub display_name: String,
    /// 适配器版本。
    pub version: u32,
    /// 支持的操作系统。
    pub supported_os: Vec<String>,
    /// 所需能力；设备 Profile 必须**全部**具备，适配器才会参与发现。
    pub required_capabilities: Vec<String>,
    /// 主要文件管理模式，仅用于展示与诊断。
    pub default_mode: FileMode,
    /// 本适配器是否适用于当前设备（操作系统在支持列表内 ∧ 所需能力全部具备）。
    pub applies: bool,
    /// 该适配器在当前授权根下的目标资源。
    pub resources: Vec<AdapterResourceData>,
}

/// `adapters list` 的数据。
#[derive(Debug, Serialize)]
pub struct AdapterListData {
    /// 是否列出了全部适配器（`--all`），而不是只列适用于本设备的。
    pub all: bool,
    /// 本设备的操作系统。
    pub os: &'static str,
    /// 本设备的处理器架构。
    pub arch: &'static str,
    /// 列出的适配器数量。
    pub count: usize,
    /// 逐个适配器。
    pub adapters: Vec<AdapterData>,
}

impl AdapterListData {
    fn render(&self) -> String {
        let mut text = format!(
            "内建适配器：{} 个（{}；本设备 {} / {}）",
            self.count,
            if self.all {
                "全部"
            } else {
                "已按本设备 Profile 过滤，`--all` 可看全部"
            },
            self.os,
            self.arch,
        );
        for adapter in &self.adapters {
            text.push_str(&format!(
                "\n  {mark} {id} v{version}（{name}）",
                mark = if adapter.applies { "✓" } else { "·" },
                id = adapter.id,
                version = adapter.version,
                name = adapter.display_name,
            ));
            text.push_str(&format!(
                "\n      平台：{}；能力：{}；默认模式：{}",
                join_or_dash(&adapter.supported_os),
                join_or_dash(&adapter.required_capabilities),
                mode_name(adapter.default_mode),
            ));
            for resource in &adapter.resources {
                text.push_str(&format!(
                    "\n      {mark} {resource} → {root}:{target}（{mode}／{disposition}）",
                    mark = if resource.selected { "-" } else { "·" },
                    resource = resource.resource,
                    root = resource.root,
                    target = resource.target,
                    mode = mode_name(resource.mode),
                    disposition = disposition_name(resource.disposition),
                ));
            }
        }
        text
    }
}

/// `adapters discover` 的数据。
#[derive(Debug, Serialize)]
pub struct AdapterDiscoverData {
    /// 本设备标识。
    pub device: String,
    /// 发现到的资源数量。
    pub count: usize,
    /// 逐条资源。
    pub resources: Vec<AdapterResourceData>,
    /// 可直接粘贴进配置的 `resources:` YAML 片段。
    ///
    /// 它由与 `WorkspaceConfig::to_yaml` **同一套**线格式类型序列化，因此粘贴之后一定
    /// 能被解析回来。
    pub yaml: String,
}

impl AdapterDiscoverData {
    fn render(&self) -> String {
        if self.count == 0 {
            return "没有发现任何可管理的资源。\n\
                    常见原因：本设备的 Profile 没有命中任何适配器，或配置里声明的授权根\
                    不含 `home`。"
                .to_owned();
        }
        format!(
            "发现 {} 个可管理的资源（设备 {}）。\n\
             把下面这段粘贴进配置文件的顶层即可：\n\n{}",
            self.count, self.device, self.yaml,
        )
    }
}

/// 在当前设备上运行一次适配器发现。
///
/// 返回「发现结果 + 本设备 Profile」。发现是**纯计算**：不读用户文件、不联网，因此
/// 即使后端不可达也能正常工作。
fn discover_resources(config: &WorkspaceConfig) -> (Vec<DiscoveredResource>, DeviceProfile) {
    let profile = config.device_profile();
    let roots = adapter_roots(config);
    let context = AdapterContext::new(&profile, &roots, "");
    let registry = AdapterRegistry::builtin();
    let mut discovered = registry.discover_all(&context);
    // `AdapterContext::prefix` 对缺失的 `home` 会退回 `home_relative`，因此即使配置里
    // 没声明 `home` 也会产出主目录资源。这里再筛一道：配置没授权的根，不该出现在建议
    // 里——照抄下去只会得到一条 `config.unknown_root`。
    discovered.retain(|resource| config.roots.contains_key(&resource.root));
    (discovered, profile)
}

/// 把发现结果转成配置层的资源声明。
///
/// 两者字段一一对应，因此这里没有任何「猜测」：适配器已经决定了标识、根、目标、模式、
/// 处置与策略。`device_overrides` 留空——按设备改写落地位置是用户的决定，不是适配器的。
fn to_resource_configs(discovered: &[DiscoveredResource]) -> Vec<ResourceConfig> {
    discovered
        .iter()
        .map(|item| ResourceConfig {
            id: item.id.clone(),
            root: item.root.clone(),
            target: item.target.clone(),
            mode: item.mode,
            disposition: item.disposition,
            policy: item.policy.clone(),
            comment_prefix: item.comment_prefix.clone(),
            selector: item.selector.clone(),
            device_overrides: BTreeMap::new(),
        })
        .collect()
}

/// 没有声明 `system` 授权根时的说明性诊断。
///
/// 这不是错误：不授权 `system` 是**推荐**配置（见 docs/adapters.md）。但如果不说一声，
/// 用户会以为清单漏了系统级 Git 配置。
fn system_root_note(config: &WorkspaceConfig) -> Option<DiagnosticOut> {
    if config.roots.contains_key(ROOT_SYSTEM) {
        return None;
    }
    Some(DiagnosticOut::info(
        "adapters.system_root_not_declared",
        format!(
            "配置未声明 `{ROOT_SYSTEM}` 授权根，系统级配置（只观察、绝不写入）未列出；\
             这是推荐配置，见 docs/adapters.md。"
        ),
    ))
}

/// 列出内建适配器。
pub fn adapters_list(config_path: &Path, all: bool) -> CoreResult<CommandOutput> {
    let config = WorkspaceConfig::load(config_path)?;
    let profile = config.device_profile();
    let roots = adapter_roots(&config);
    let context = AdapterContext::new(&profile, &roots, "");
    let registry = AdapterRegistry::builtin();

    let mut adapters = Vec::new();
    for adapter in registry.adapters() {
        let descriptor = adapter.descriptor();
        let applies = descriptor.applies_to(&profile);
        if !applies && !all {
            continue;
        }
        // 单个适配器出错不该让整条命令失败——与 `discover_all` 的处理保持一致。
        let discovered = adapter.discover(&context).unwrap_or_default();
        let resources: Vec<AdapterResourceData> = discovered
            .iter()
            .filter(|resource| config.roots.contains_key(&resource.root))
            .map(|resource| AdapterResourceData::from_discovered(resource, &profile))
            // 不带 `--all` 时只列本设备真正会用到的资源。
            .filter(|resource| all || resource.selected)
            .collect();
        adapters.push(AdapterData {
            id: descriptor.id.to_owned(),
            display_name: descriptor.display_name.to_owned(),
            version: descriptor.version,
            supported_os: descriptor
                .supported_os
                .iter()
                .map(|os| os.as_str().to_owned())
                .collect(),
            required_capabilities: descriptor
                .required_capabilities
                .iter()
                .map(|capability| (*capability).to_owned())
                .collect(),
            default_mode: descriptor.default_mode,
            applies,
            resources,
        });
    }

    Ok(CommandOutput {
        data: CommandData::AdapterList(AdapterListData {
            all,
            os: profile.os.as_str(),
            arch: profile.arch.as_str(),
            count: adapters.len(),
            adapters,
        }),
        diagnostics: system_root_note(&config).into_iter().collect(),
    })
}

/// 对当前设备运行适配器发现，产出可粘贴的配置片段。
pub fn adapters_discover(config_path: &Path) -> CoreResult<CommandOutput> {
    let config = WorkspaceConfig::load(config_path)?;
    let (discovered, profile) = discover_resources(&config);
    let resources = to_resource_configs(&discovered);
    let yaml = WorkspaceConfig::resources_to_yaml(&resources)?;

    Ok(CommandOutput {
        data: CommandData::AdapterDiscover(AdapterDiscoverData {
            device: profile.device.map(|id| id.to_hex()).unwrap_or_default(),
            count: discovered.len(),
            resources: discovered
                .iter()
                .map(|resource| AdapterResourceData::from_discovered(resource, &profile))
                .collect(),
            yaml,
        }),
        diagnostics: system_root_note(&config).into_iter().collect(),
    })
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
