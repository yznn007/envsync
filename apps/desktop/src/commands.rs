//! Tauri command 的窄 application-service 边界。
//!
//! 所有 command 都只接收 API v1 信封、强类型 ID 与已注册 workspace；本模块没有任意
//! 路径、shell、HTTP 或 Vault 明文入口。失败一律映射成脱敏的 [`ApiResponse`]。

use std::path::{Path, PathBuf};
use std::thread;

use envsync_backend::git::DEFAULT_BRANCH;
use envsync_backend::git_auth::validate_remote_url;
use envsync_backend::GitAuth;
use envsync_core::{
    ApiEvent, ApiRequest, ApiRequestId, ApiResponse, ApplyCancellation, ApplyOutcome,
    ApplyStartView, ApplyView, CancellationView, ConflictDetailView, ConflictListView,
    ConflictResolutionView, CoreError, CoreResult, DeviceListView, DeviceRevocationView,
    DiffListView, EnvSyncService, OperationDetailView, OperationHistoryView, OperationView,
    PlanView, RollbackReviewView, RootCapabilityView, StatusView, VaultMetadataView, ViewData,
    ViewDiagnostic, WorkspaceConfig, WorkspaceRegistrationView, WorkspaceSummary,
};
use envsync_domain::{ConflictId, OperationId, PlanId, ResolutionChoice, WorkspaceId};
use envsync_platform::AuthorizedRoot;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::{DialogExt, FilePath};

use crate::state::{DesktopState, DesktopStateError};

/// 后台 operation 进度使用的唯一事件名。
pub const OPERATION_EVENT: &str = "envsync://operation";

/// 经安全审查后可由桌面 UI 调用的 command 名称。
///
/// 此列表也会写入 Tauri build manifest；新增 command 必须先添加安全测试、明确输入 View
/// 和最小 capability，不能通过插件自动扩展。
pub const ALLOWED_COMMANDS: [&str; 19] = [
    "onboarding_select_root",
    "onboarding_create_workspace",
    "onboarding_open_workspace",
    "workspace_status",
    "workspace_plan",
    "plan_diff",
    "workspace_apply",
    "conflict_list",
    "conflict_show",
    "conflict_resolve",
    "operation_history",
    "operation_detail",
    "operation_rollback_review",
    "operation_rollback",
    "vault_metadata",
    "device_list",
    "device_revoke",
    "bundle_review",
    "operation_cancel",
];

/// 判断 command 是否位于静态白名单中。
pub fn is_allowed_command(command: &str) -> bool {
    ALLOWED_COMMANDS.contains(&command)
}

/// 无负载的原生目录选择请求。
///
/// 目录路径由 native dialog 产生；该结构刻意没有任何路径、URL 或初始目录字段。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectRootRequest {}

/// 首次创建时可选的后端种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingBackendKind {
    /// 本机私有目录后端。
    Local,
    /// 使用无明文凭据认证方式的 Git 后端。
    Git,
}

/// Git 首次创建中允许的无明文认证方式。
///
/// 不接收密码或 token。`token-secret-ref` 必须先经 Vault 流程创建引用，不能在首次页
/// 粘贴秘密；该流程由 Vault 页面负责。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GitOnboardingAuthKind {
    /// 私钥仍由系统 ssh-agent 保管。
    SshAgent,
    /// 系统或 Git credential helper 在需要时提供凭据。
    CredentialHelper,
}

impl GitOnboardingAuthKind {
    fn into_auth(self) -> GitAuth {
        match self {
            GitOnboardingAuthKind::SshAgent => GitAuth::SshAgent,
            GitOnboardingAuthKind::CredentialHelper => GitAuth::CredentialHelper,
        }
    }
}

/// 创建一个新工作区的受限意图。
///
/// `root_capability_token` 不是路径：它必须已由 [`onboarding_select_root`] 在本进程的
/// [`DesktopState`] 中登记。WebView 无法通过它指定任意目录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateWorkspaceRequest {
    /// 后端类型。
    pub backend_kind: OnboardingBackendKind,
    /// 本设备显示名称；命令层会限制长度并拒绝控制字符。
    pub device_profile: String,
    /// 原生登记的、无路径语义的根能力 token。
    pub root_capability_token: String,
    /// Git 远端地址；仅当 `backend_kind=git` 时需要。
    pub remote_url: Option<String>,
    /// Git 无明文认证方式；仅当 `backend_kind=git` 时需要。
    pub git_auth: Option<GitOnboardingAuthKind>,
}

/// 无负载的已有工作区打开请求。
///
/// 配置文件和全部授权根都由原生对话框选择，不能由 WebView 传入。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenWorkspaceRequest {}

/// 仅引用已注册工作区的 command 负载。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRequest {
    /// 桌面 state 中已经登记的工作区标识。
    pub workspace_id: WorkspaceId,
}

/// 请求构建新 Plan 的负载。
pub type PlanRequest = WorkspaceRequest;

/// 请求应用已审核 Plan 的负载。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyPlanRequest {
    /// 已注册工作区标识。
    pub workspace_id: WorkspaceId,
    /// 已由 core 保存并将再次校验新鲜度的计划标识。
    pub plan_id: PlanId,
}

/// 请求读取某个已保存计划的无内容差异摘要。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanDiffRequest {
    /// 已注册工作区标识。
    pub workspace_id: WorkspaceId,
    /// 已保存、由 UI 正在审核的计划标识。
    pub plan_id: PlanId,
}

/// 请求回滚或取消已登记操作的负载。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRequest {
    /// 已注册工作区标识。
    pub workspace_id: WorkspaceId,
    /// 已登记操作标识。
    pub operation_id: OperationId,
}

/// 请求查看单个冲突的负载。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictRequest {
    /// 已注册工作区标识。
    pub workspace_id: WorkspaceId,
    /// 已登记冲突标识。
    pub conflict_id: ConflictId,
}

/// 提交一个受限冲突裁决。
///
/// `manual_content` 只在 `choice=manual` 时可出现。Rust core 会再次检查资源是否非秘密、
/// 是否为文本以及结构化格式/字节上限；WebView 无法凭此字段提交路径或 Blob 标识。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictResolutionRequest {
    /// 已注册工作区标识。
    pub workspace_id: WorkspaceId,
    /// 已登记冲突标识。
    pub conflict_id: ConflictId,
    /// `ours`、`theirs`、`manual` 或 `delete`。
    pub choice: ResolutionChoice,
    /// 临时手动文本；绝不写入 Pinia、日志或 response。
    pub manual_content: Option<String>,
}

/// 请求生成某次 operation 的逆向计划审核。
pub type RollbackReviewRequest = OperationRequest;

/// 执行已经逐项审核过的逆向计划。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackExecutionRequest {
    /// 已注册工作区标识。
    pub workspace_id: WorkspaceId,
    /// 将被回滚的 operation。
    pub operation_id: OperationId,
    /// Rust 进程发放的一次性审核 token。
    pub review_token: String,
    /// 必须与审核响应中所有 inverse action 的序号一一对应。
    pub confirmations: Vec<u32>,
}

/// 撤销设备的受限意图。
///
/// 前端只能引用成员链中已有的设备标识，并在本地输入完全匹配的公开 ID 作为防误触
/// 确认。core 仍会强制管理员、成员关系和轮换规则。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevokeRequest {
    /// 已注册工作区。
    pub workspace_id: WorkspaceId,
    /// 待撤销设备的公开标识。
    pub device_id: envsync_domain::DeviceId,
    /// 必须与 `device_id` 完全一致的公开文本确认。
    pub confirmation: String,
}

/// 让用户通过系统目录选择器授予一个目录能力。
///
/// 此 command 在 async worker 上调用 blocking dialog（Tauri 官方建议的用法）；完成后只
/// 返回不透明 token 和固定标签，不会把选择路径、URI 或目录名序列化进 IPC。
#[tauri::command]
pub async fn onboarding_select_root(
    app: AppHandle,
    request: ApiRequest<SelectRootRequest>,
) -> ApiResponse<RootCapabilityView> {
    let state = app.state::<DesktopState>();
    // 所有失败都编码为版本化 ApiResponse，绝不进入 Tauri 的字符串错误通道，保持 UI 的
    // 脱敏错误契约。
    onboarding_select_root_impl(&app, state.inner(), request)
}

fn onboarding_select_root_impl(
    app: &AppHandle,
    state: &DesktopState,
    request: ApiRequest<SelectRootRequest>,
) -> ApiResponse<RootCapabilityView> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    let selected_path = match picked_path(
        app.dialog()
            .file()
            .set_title("选择 EnvSync 授权根")
            .blocking_pick_folder(),
        "desktop.root_selection_cancelled",
    ) {
        Ok(path) => path,
        Err(code) => return error_response(request_id, code),
    };
    match state.register_root_capability(&selected_path) {
        Ok(root) => ApiResponse::ok(request_id, root, Vec::new()),
        Err(error) => state_error(request_id, error),
    }
}

/// 使用已由 native dialog 登记的根能力创建一个 Local 或 Git 工作区。
///
/// 配置、后端 cache 与状态目录永远由宿主的 app-data 目录派生；UI 既不能指定这些路径，
/// 也不能获知它们。Git 只接受 URL 与无明文认证方式，URL 会在写配置前重新校验。
#[tauri::command]
pub fn onboarding_create_workspace(
    app: AppHandle,
    state: State<'_, DesktopState>,
    request: ApiRequest<CreateWorkspaceRequest>,
) -> ApiResponse<WorkspaceRegistrationView> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    let device_name = match validated_device_profile(&request.data().device_profile) {
        Ok(name) => name,
        Err(code) => return error_response(request_id, code),
    };
    let (root, root_path) = match state
        .inner()
        .root_capability(&request.data().root_capability_token)
    {
        Ok(capability) => capability,
        Err(error) => return state_error(request_id, error),
    };
    let app_data_dir = match app.path().app_data_dir() {
        Ok(path) => path,
        Err(_) => return error_response(request_id, "desktop.onboarding_storage_unavailable"),
    };
    let (config_path, backend_path) = workspace_storage_paths(&app_data_dir, &root.token);
    let git_cache_dir = config_path
        .parent()
        .expect("工作区配置路径始终带父目录")
        .join(".envsync")
        .join("git-cache");
    let backend = match onboarding_backend(request.data(), &backend_path, &git_cache_dir) {
        Ok(backend) => backend,
        Err(OnboardingFailure::Code(code)) => return error_response(request_id, code),
        Err(OnboardingFailure::Core(error)) => {
            return command_error(request_id, CommandFailure::Core(error));
        }
        Err(OnboardingFailure::State(error)) => return state_error(request_id, error),
    };
    let config = match EnvSyncService::init_workspace_with_root_and_backend(
        &config_path,
        &device_name,
        backend,
        &root_path,
    ) {
        Ok(config) => config,
        Err(error) => return command_error(request_id, CommandFailure::Core(error)),
    };
    if let Err(error) = EnvSyncService::open(config.clone()) {
        return command_error(request_id, CommandFailure::Core(error));
    }
    let workspace = workspace_summary(&config);
    match state.inner().register(config) {
        Ok(_) => ApiResponse::ok(
            request_id,
            WorkspaceRegistrationView::new(workspace, root),
            Vec::new(),
        ),
        Err(error) => state_error(request_id, error),
    }
}

/// 原生打开一个已有工作区，并重新确认配置所声明的每一个授权根。
///
/// 选择配置文件本身不等于授予其中任意路径权限：每个根都必须在 native dialog 中再次选中
/// 并匹配 canonical 路径，才会注册到桌面 state。
#[tauri::command]
pub async fn onboarding_open_workspace(
    app: AppHandle,
    request: ApiRequest<OpenWorkspaceRequest>,
) -> ApiResponse<WorkspaceRegistrationView> {
    let state = app.state::<DesktopState>();
    onboarding_open_workspace_impl(&app, state.inner(), request)
}

fn onboarding_open_workspace_impl(
    app: &AppHandle,
    state: &DesktopState,
    request: ApiRequest<OpenWorkspaceRequest>,
) -> ApiResponse<WorkspaceRegistrationView> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    let config_path = match picked_path(
        app.dialog()
            .file()
            .set_title("选择 EnvSync 工作区配置")
            .add_filter("EnvSync 工作区", &["yaml", "yml"])
            .blocking_pick_file(),
        "desktop.workspace_selection_cancelled",
    ) {
        Ok(path) => path,
        Err(code) => return error_response(request_id, code),
    };
    let config = match WorkspaceConfig::load(&config_path) {
        Ok(config) => config,
        Err(error) => return command_error(request_id, CommandFailure::Core(error.into())),
    };
    let roots = match confirm_workspace_roots(app, state, &config) {
        Ok(roots) => roots,
        Err(OnboardingFailure::Code(code)) => return error_response(request_id, code),
        Err(OnboardingFailure::State(error)) => return state_error(request_id, error),
        Err(OnboardingFailure::Core(error)) => {
            return command_error(request_id, CommandFailure::Core(error));
        }
    };
    if let Err(error) = EnvSyncService::open(config.clone()) {
        discard_root_capabilities(state, &roots.all);
        return command_error(request_id, CommandFailure::Core(error));
    }
    let workspace = workspace_summary(&config);
    match state.register(config) {
        Ok(_) => ApiResponse::ok(
            request_id,
            WorkspaceRegistrationView::new(workspace, roots.primary),
            Vec::new(),
        ),
        Err(error) => {
            discard_root_capabilities(state, &roots.all);
            state_error(request_id, error)
        }
    }
}

/// 查询当前工作区状态。
#[tauri::command]
pub fn workspace_status(
    state: State<'_, DesktopState>,
    request: ApiRequest<WorkspaceRequest>,
) -> ApiResponse<StatusView> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    match call_service(state.inner(), request.data().workspace_id, |service| {
        service.status()
    }) {
        Ok(report) => ApiResponse::ok(
            request_id,
            StatusView::from_report(&report),
            report
                .diagnostics
                .iter()
                .map(ViewDiagnostic::from)
                .collect(),
        ),
        Err(error) => command_error(request_id, error),
    }
}

/// 生成并保存可审核 Plan。
#[tauri::command]
pub fn workspace_plan(
    state: State<'_, DesktopState>,
    request: ApiRequest<PlanRequest>,
) -> ApiResponse<PlanView> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    match call_service(state.inner(), request.data().workspace_id, |service| {
        service.build_plan()
    }) {
        Ok(plan) => ApiResponse::ok(
            request_id,
            PlanView::from_plan(&plan),
            plan.diagnostics.iter().map(ViewDiagnostic::from).collect(),
        ),
        Err(error) => command_error(request_id, error),
    }
}

/// 读取已保存 Plan 的无内容差异摘要。
///
/// UI 只能按当前 `plan_id` 请求，无法以路径、Blob ID 或“最新状态”替代它。Plan 失效后
/// 必须重新生成并重新审核；此 command 本身绝不会帮 UI 修补旧计划。
#[tauri::command]
pub fn plan_diff(
    state: State<'_, DesktopState>,
    request: ApiRequest<PlanDiffRequest>,
) -> ApiResponse<DiffListView> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    match call_service(state.inner(), request.data().workspace_id, |service| {
        service.plan_diffs(request.data().plan_id)
    }) {
        Ok(view) => ApiResponse::ok(request_id, view, Vec::new()),
        Err(error) => command_error(request_id, error),
    }
}

/// 应用一个已保存的 Plan。
///
/// core 会在写入前重新观察并检查 Plan ID；桌面层不会也不能自行绕过该新鲜度检查。
#[tauri::command]
pub fn workspace_apply(
    app: AppHandle,
    state: State<'_, DesktopState>,
    request: ApiRequest<ApplyPlanRequest>,
) -> ApiResponse<ApplyStartView> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    let workspace = request.data().workspace_id;
    let plan_id = request.data().plan_id;
    let operation = OperationId::generate();
    let worker = match state
        .inner()
        .start_background_operation(workspace, operation)
    {
        Ok(worker) => worker,
        Err(error) => return state_error(request_id, error),
    };
    let worker_request_id = request_id.clone();
    let spawn = thread::Builder::new()
        .name("envsync-apply".to_owned())
        .spawn(move || {
            let event = match worker.with_service(|service, cancellation| {
                apply_in_background(service, plan_id, operation, cancellation)
            }) {
                Ok(Ok(view)) => ApiEvent::ok(worker_request_id.clone(), 1, view, Vec::new()),
                Ok(Err(error)) => {
                    apply_error_event(worker_request_id.clone(), CommandFailure::Core(error))
                }
                Err(error) => {
                    apply_error_event(worker_request_id.clone(), CommandFailure::State(error))
                }
            };
            emit_event(&app, event);
        });

    match spawn {
        Ok(_) => ApiResponse::ok(request_id, ApplyStartView::queued(operation), Vec::new()),
        Err(_) => error_response(request_id, "desktop.worker_start_failed"),
    }
}

/// 列出当前工作区所有开放冲突。
#[tauri::command]
pub fn conflict_list(
    state: State<'_, DesktopState>,
    request: ApiRequest<WorkspaceRequest>,
) -> ApiResponse<ConflictListView> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    let workspace = request.data().workspace_id;
    match call_service(state.inner(), workspace, |service| service.conflicts_list()) {
        Ok(records) => ApiResponse::ok(
            request_id,
            ConflictListView::from_records(workspace, &records),
            Vec::new(),
        ),
        Err(error) => command_error(request_id, error),
    }
}

/// 读取单个冲突的无内容裁决元数据。
#[tauri::command]
pub fn conflict_show(
    state: State<'_, DesktopState>,
    request: ApiRequest<ConflictRequest>,
) -> ApiResponse<ConflictDetailView> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    match call_service(state.inner(), request.data().workspace_id, |service| {
        service.conflict_detail_view(request.data().conflict_id)
    }) {
        Ok(view) => ApiResponse::ok(request_id, view, Vec::new()),
        Err(error) => command_error(request_id, error),
    }
}

/// 保存一个冲突裁决，但不执行同步、不触碰用户文件。
///
/// 对于 `manual`，内容只在这个调用栈内暂存。core 会拒绝秘密、二进制、结构化解析失败或
/// 超限内容；响应也不会回显用户提交的任何正文。
#[tauri::command]
pub fn conflict_resolve(
    state: State<'_, DesktopState>,
    request: ApiRequest<ConflictResolutionRequest>,
) -> ApiResponse<ConflictResolutionView> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    let workspace = request.data().workspace_id;
    let conflict = request.data().conflict_id;
    let choice = request.data().choice;
    let manual_content = request.data().manual_content.as_deref();
    match call_service(state.inner(), workspace, |service| {
        service.conflicts_resolve_for_desktop(conflict, choice, manual_content)
    }) {
        Ok(view) => ApiResponse::ok(request_id, view, Vec::new()),
        Err(error) => command_error(request_id, error),
    }
}

/// 列出当前工作区的 journal 历史。
#[tauri::command]
pub fn operation_history(
    state: State<'_, DesktopState>,
    request: ApiRequest<WorkspaceRequest>,
) -> ApiResponse<OperationHistoryView> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    match call_service(state.inner(), request.data().workspace_id, |service| {
        service.operation_history_view()
    }) {
        Ok(view) => ApiResponse::ok(request_id, view, Vec::new()),
        Err(error) => command_error(request_id, error),
    }
}

/// 查看单个历史操作的状态机、动作进度与收据摘要。
#[tauri::command]
pub fn operation_detail(
    state: State<'_, DesktopState>,
    request: ApiRequest<OperationRequest>,
) -> ApiResponse<OperationDetailView> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    match call_service(state.inner(), request.data().workspace_id, |service| {
        service.operation_detail_view(request.data().operation_id)
    }) {
        Ok(view) => ApiResponse::ok(request_id, view, Vec::new()),
        Err(error) => command_error(request_id, error),
    }
}

/// 生成一次回滚前必须查看的逆向计划审核。
#[tauri::command]
pub fn operation_rollback_review(
    state: State<'_, DesktopState>,
    request: ApiRequest<RollbackReviewRequest>,
) -> ApiResponse<RollbackReviewView> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    let workspace = request.data().workspace_id;
    let operation = request.data().operation_id;
    let review = match call_service(state.inner(), workspace, |service| {
        service.rollback_review_view(operation)
    }) {
        Ok(review) => review,
        Err(error) => return command_error(request_id, error),
    };
    let token = match state.inner().issue_rollback_review(
        workspace,
        operation,
        review.actions.iter().map(|action| action.ordinal),
    ) {
        Ok(token) => token,
        Err(error) => return state_error(request_id, error),
    };
    ApiResponse::ok(request_id, review.with_review_token(token), Vec::new())
}

/// 为已经审核的逆向计划请求回滚。
///
/// `review_token` 必须由 `operation_rollback_review` 在当前进程发放，且全部动作序号必须被
/// 单独确认。token 校验通过即被消费；若回滚因现场摘要变化等原因失败，用户必须重新生成
/// 逆向计划，而不能重放旧审核。
#[tauri::command]
pub fn operation_rollback(
    app: AppHandle,
    state: State<'_, DesktopState>,
    request: ApiRequest<RollbackExecutionRequest>,
) -> ApiResponse<OperationView> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    let workspace = request.data().workspace_id;
    let operation_id = request.data().operation_id;
    if let Err(error) = state.inner().consume_rollback_review(
        workspace,
        operation_id,
        &request.data().review_token,
        &request.data().confirmations,
    ) {
        return state_error(request_id, error);
    }
    let _operation_guard = state.inner().begin_operation();
    match call_service(state.inner(), workspace, |service| {
        let report = service.rollback(operation_id)?;
        let record = service
            .journal()
            .operation(report.operation)?
            .ok_or_else(|| CoreError::OperationNotFound(report.operation.to_string()))?;
        Ok(OperationView::from_record(&record))
    }) {
        Ok(view) => {
            emit_event(
                &app,
                ApiEvent::ok(request_id.clone(), 1, view.clone(), Vec::new()),
            );
            ApiResponse::ok(request_id, view, Vec::new())
        }
        Err(error) => command_error(request_id, error),
    }
}

/// 请求取消一个仍在执行的 operation。
///
/// 此 command 不等待 workspace 的执行锁，因此可以在后台 worker 正在运行时立即把请求
/// 送到取消令牌。它只确认请求被接收；core 随后会在 journal 的安全边界决定是否中止。
#[tauri::command]
pub fn operation_cancel(
    state: State<'_, DesktopState>,
    request: ApiRequest<OperationRequest>,
) -> ApiResponse<CancellationView> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    let operation_id = request.data().operation_id;
    match state
        .inner()
        .request_cancel(request.data().workspace_id, operation_id)
    {
        Ok(()) => ApiResponse::ok(
            request_id,
            CancellationView::requested(operation_id),
            Vec::new(),
        ),
        Err(error) => state_error(request_id, error),
    }
}

/// 返回 Vault metadata-only 清单。
///
/// 服务层每次都从系统安全存储与当前后端重新打开 Vault；WebView 得到的仅是 Secret ID、
/// 更新时间与引用资源，不能借此读取、复制或默认显示秘密值。
#[tauri::command]
pub fn vault_metadata(
    state: State<'_, DesktopState>,
    request: ApiRequest<WorkspaceRequest>,
) -> ApiResponse<VaultMetadataView> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    match call_service(state.inner(), request.data().workspace_id, |service| {
        service.vault_metadata_view()
    }) {
        Ok(view) => ApiResponse::ok(request_id, view, Vec::new()),
        Err(error) => command_error(request_id, error),
    }
}

/// 列出已经过成员链验证的设备元数据。
///
/// 不传输设备私钥、公开材料、邀请内容或恢复短语；这些要么从系统安全存储读取，要么仍
/// 留在受控的后端/CLI 流程中。
#[tauri::command]
pub fn device_list(
    state: State<'_, DesktopState>,
    request: ApiRequest<WorkspaceRequest>,
) -> ApiResponse<DeviceListView> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    match call_service(state.inner(), request.data().workspace_id, |service| {
        service.device_list_view()
    }) {
        Ok(view) => ApiResponse::ok(request_id, view, Vec::new()),
        Err(error) => command_error(request_id, error),
    }
}

/// 撤销指定设备并触发 core 管理的密钥轮换。
///
/// 文本确认只防止误触；是否可执行始终由 core 重新验证。当前设备不能撤销自己，且任意
/// 已撤销设备都必须经新的管理员邀请重新授权，不能用旧身份恢复访问。
#[tauri::command]
pub fn device_revoke(
    state: State<'_, DesktopState>,
    request: ApiRequest<DeviceRevokeRequest>,
) -> ApiResponse<DeviceRevocationView> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    let data = request.data();
    if data.confirmation != data.device_id.to_string() {
        return error_response(request_id, "device.revoke_confirmation_required");
    }
    let workspace = data.workspace_id;
    let device = data.device_id;
    let _operation_guard = state.inner().begin_operation();
    match call_service(state.inner(), workspace, |service| {
        service.revoke_device_for_desktop(device)
    }) {
        Ok(view) => ApiResponse::ok(request_id, view, Vec::new()),
        Err(error) => command_error(request_id, error),
    }
}

/// 返回 Bundle review endpoint 的受控未配置状态。
///
/// M3 的 quarantine/review 流程会在后续 UI 任务中接入；这里故意没有任何执行或文件读取
/// 入口。
#[tauri::command]
pub fn bundle_review(
    state: State<'_, DesktopState>,
    request: ApiRequest<WorkspaceRequest>,
) -> ApiResponse<WorkspaceSummary> {
    checked_unavailable(state.inner(), request, "desktop.bundle_review_unavailable")
}

/// 首次使用流程中由 native dialog 或受控状态层产生的失败。
enum OnboardingFailure {
    /// 没有任何用户路径语义的稳定本地错误码。
    Code(&'static str),
    /// 进程内状态边界失败。
    State(DesktopStateError),
    /// core 或平台层拒绝了受原生确认的配置。
    Core(CoreError),
}

/// 多根工作区经过原生逐一确认后的能力集合。
struct ConfirmedRoots {
    /// UI 用于显示“已授权”的主根：优先 `home`，否则是第一个已确认根。
    primary: RootCapabilityView,
    /// 失败时必须一并撤销的所有临时 capability。
    all: Vec<RootCapabilityView>,
}

/// 把 dialog 的内部路径对象转为仅供 Rust 使用的 `PathBuf`。
///
/// URL 不能转为本地文件路径、或用户关闭 dialog 时都只返回稳定代码；绝不序列化原始
/// 选择结果或错误文本。
fn picked_path(
    selection: Option<FilePath>,
    cancelled_code: &'static str,
) -> Result<PathBuf, &'static str> {
    selection
        .ok_or(cancelled_code)?
        .into_path()
        .map_err(|_| "desktop.native_path_unavailable")
}

/// 确保设备显示名可安全写入配置且不成为任意文本回显通道。
fn validated_device_profile(value: &str) -> Result<String, &'static str> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 80 || value.chars().any(char::is_control) {
        return Err("desktop.invalid_device_profile");
    }
    Ok(value.to_owned())
}

/// 派生桌面应用私有的配置与 Local backend 位置。
///
/// capability token 已由 state 校验为随机 UUID 样式，不能包含路径分隔符；这里不接受任意
/// UI 字符串，因此所有新建工作区都被限制在 app-data 根内。
fn workspace_storage_paths(app_data_dir: &Path, root_token: &str) -> (PathBuf, PathBuf) {
    let workspace_dir = app_data_dir.join("workspaces").join(root_token);
    (
        workspace_dir.join("workspace.yaml"),
        workspace_dir.join("backend"),
    )
}

/// 将首次使用页的后端意图收敛成 core 的封闭配置类型。
///
/// Local 拒绝 Git 字段，Git 则要求一个无用户信息的远端 URL 和允许的认证方式；这样恶意
/// WebView 即使构造混合负载，也无法让未审核字段被静默忽略。
fn onboarding_backend(
    request: &CreateWorkspaceRequest,
    local_backend_path: &Path,
    git_cache_dir: &Path,
) -> Result<envsync_core::BackendConfig, OnboardingFailure> {
    match request.backend_kind {
        OnboardingBackendKind::Local => {
            if request.remote_url.is_some() || request.git_auth.is_some() {
                return Err(OnboardingFailure::Code(
                    "desktop.invalid_backend_configuration",
                ));
            }
            Ok(envsync_core::BackendConfig::Local {
                path: local_backend_path.to_path_buf(),
            })
        }
        OnboardingBackendKind::Git => {
            let remote_url = request
                .remote_url
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty() && value.len() <= 2_048)
                .ok_or(OnboardingFailure::Code("desktop.git_remote_required"))?;
            if remote_url.chars().any(char::is_control) {
                return Err(OnboardingFailure::Code(
                    "desktop.invalid_backend_configuration",
                ));
            }
            validate_remote_url(remote_url)
                .map_err(CoreError::from)
                .map_err(OnboardingFailure::Core)?;
            let auth = request
                .git_auth
                .ok_or(OnboardingFailure::Code("desktop.git_auth_required"))?
                .into_auth();
            Ok(envsync_core::BackendConfig::Git {
                remote_url: remote_url.to_owned(),
                branch: DEFAULT_BRANCH.to_owned(),
                cache_dir: git_cache_dir.to_path_buf(),
                auth,
            })
        }
    }
}

/// 从经过加载的配置构造不含路径和远端地址的公开工作区摘要。
fn workspace_summary(config: &WorkspaceConfig) -> WorkspaceSummary {
    WorkspaceSummary::from_status_parts(
        config.workspace_id,
        config.device.device_id(),
        config.backend.kind(),
    )
}

/// 对已有配置的每一个授权根做一次原生重新确认。
///
/// 这是防止“用户选了配置文件，就暗中信任该文件里任意目录”的边界。配置根和 native
/// 对话框中选到的目录都 canonicalize；任一不匹配都拒绝打开，且会撤销此前临时 token。
fn confirm_workspace_roots(
    app: &AppHandle,
    state: &DesktopState,
    config: &WorkspaceConfig,
) -> Result<ConfirmedRoots, OnboardingFailure> {
    let mut all = Vec::with_capacity(config.roots.len());
    let mut primary = None;

    for (alias, configured_path) in &config.roots {
        let configured = match AuthorizedRoot::open(alias, configured_path) {
            Ok(root) => root,
            Err(error) => {
                discard_root_capabilities(state, &all);
                return Err(OnboardingFailure::Core(error.into()));
            }
        };
        let selected = match picked_path(
            app.dialog()
                .file()
                .set_title("确认 EnvSync 授权根")
                .blocking_pick_folder(),
            "desktop.root_selection_cancelled",
        ) {
            Ok(path) => path,
            Err(code) => {
                discard_root_capabilities(state, &all);
                return Err(OnboardingFailure::Code(code));
            }
        };
        let view = match state.register_root_capability(&selected) {
            Ok(view) => view,
            Err(error) => {
                discard_root_capabilities(state, &all);
                return Err(OnboardingFailure::State(error));
            }
        };
        let (_, selected_path) = match state.root_capability(&view.token) {
            Ok(capability) => capability,
            Err(error) => {
                state.discard_root_capability(&view.token);
                discard_root_capabilities(state, &all);
                return Err(OnboardingFailure::State(error));
            }
        };
        if selected_path != configured.path() {
            state.discard_root_capability(&view.token);
            discard_root_capabilities(state, &all);
            return Err(OnboardingFailure::Code("desktop.root_capability_mismatch"));
        }
        if alias == "home" || primary.is_none() {
            primary = Some(view.clone());
        }
        all.push(view);
    }

    let Some(primary) = primary else {
        return Err(OnboardingFailure::Code("desktop.root_capability_required"));
    };
    Ok(ConfirmedRoots { primary, all })
}

/// 撤销本次打开流程生成、但尚未关联到已注册工作区的所有 token。
fn discard_root_capabilities(state: &DesktopState, roots: &[RootCapabilityView]) {
    for root in roots {
        state.discard_root_capability(&root.token);
    }
}

enum CommandFailure {
    /// 工作区注册或互斥边界失败。
    State(DesktopStateError),
    /// core application service 拒绝了操作。
    Core(CoreError),
}

impl CommandFailure {
    fn code(&self) -> &str {
        match self {
            CommandFailure::State(error) => error.code(),
            CommandFailure::Core(error) => error.code(),
        }
    }
}

fn call_service<T>(
    state: &DesktopState,
    workspace: WorkspaceId,
    operation: impl FnOnce(&mut EnvSyncService) -> CoreResult<T>,
) -> Result<T, CommandFailure> {
    state
        .with_service(workspace, operation)
        .map_err(CommandFailure::State)?
        .map_err(CommandFailure::Core)
}

/// 在后台 worker 中执行 apply，并将最终结果限制为脱敏 View。
fn apply_in_background(
    service: &mut EnvSyncService,
    plan_id: PlanId,
    operation: OperationId,
    cancellation: &dyn ApplyCancellation,
) -> CoreResult<ApplyView> {
    match service.apply_plan_with_operation(plan_id, operation, cancellation)? {
        ApplyOutcome::NoOp => Ok(ApplyView::no_op()),
        ApplyOutcome::Completed {
            operation,
            applied,
            published,
        } => {
            let record = service
                .journal()
                .operation(operation)?
                .ok_or_else(|| CoreError::OperationNotFound(operation.to_string()))?;
            Ok(ApplyView::completed(&record, applied, published))
        }
    }
}

fn checked_unavailable(
    state: &DesktopState,
    request: ApiRequest<WorkspaceRequest>,
    code: &'static str,
) -> ApiResponse<WorkspaceSummary> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    match state.contains(request.data().workspace_id) {
        Ok(true) => error_response(request_id, code),
        Ok(false) => state_error(request_id, DesktopStateError::UnknownWorkspace),
        Err(error) => state_error(request_id, error),
    }
}

fn schema_error<T: ViewData, P: Serialize>(request: &ApiRequest<P>) -> Option<ApiResponse<T>> {
    request.validate_schema().err().map(|_| {
        error_response(
            request.request_id().clone(),
            "api.unsupported_schema_version",
        )
    })
}

fn state_error<T: ViewData>(request_id: ApiRequestId, error: DesktopStateError) -> ApiResponse<T> {
    error_response(request_id, error.code())
}

fn command_error<T: ViewData>(request_id: ApiRequestId, error: CommandFailure) -> ApiResponse<T> {
    error_response(request_id, error.code())
}

fn error_response<T: ViewData>(request_id: ApiRequestId, code: &str) -> ApiResponse<T> {
    ApiResponse::error(
        request_id,
        vec![ViewDiagnostic {
            severity: "blocking".to_owned(),
            code: code.to_owned(),
            resource: None,
        }],
    )
    .expect("非空诊断可以构造错误响应")
}

fn apply_error_event(request_id: ApiRequestId, error: CommandFailure) -> ApiEvent<ApplyView> {
    ApiEvent::error(
        request_id,
        1,
        vec![ViewDiagnostic {
            severity: "blocking".to_owned(),
            code: error.code().to_owned(),
            resource: None,
        }],
    )
    .expect("非空诊断可以构造错误事件")
}

fn emit_event<T: ViewData>(app: &AppHandle, event: ApiEvent<T>) {
    let _ = app.emit(OPERATION_EVENT, &event);
}

#[cfg(test)]
mod onboarding_backend_tests {
    use std::path::Path;

    use envsync_backend::GitAuth;
    use envsync_core::BackendConfig;

    use super::{
        onboarding_backend, CreateWorkspaceRequest, GitOnboardingAuthKind, OnboardingBackendKind,
        OnboardingFailure,
    };

    fn request(backend_kind: OnboardingBackendKind) -> CreateWorkspaceRequest {
        CreateWorkspaceRequest {
            backend_kind,
            device_profile: "workstation".to_owned(),
            root_capability_token: "c7a16bdb-57b1-40bb-9cf1-1e42b463a53a".to_owned(),
            remote_url: None,
            git_auth: None,
        }
    }

    #[test]
    fn git_onboarding_uses_only_a_valid_remote_and_non_secret_auth() {
        let mut request = request(OnboardingBackendKind::Git);
        request.remote_url = Some("ssh://git@example.invalid/team/envsync.git".to_owned());
        request.git_auth = Some(GitOnboardingAuthKind::CredentialHelper);

        let backend = match onboarding_backend(
            &request,
            Path::new("local-backend"),
            Path::new("private-git-cache"),
        ) {
            Ok(backend) => backend,
            Err(_) => panic!("受控 Git 意图应可转换"),
        };

        assert!(matches!(
            backend,
            BackendConfig::Git {
                remote_url,
                auth: GitAuth::CredentialHelper,
                ..
            } if remote_url == "ssh://git@example.invalid/team/envsync.git"
        ));
    }

    #[test]
    fn onboarding_rejects_mixed_backend_fields_and_inline_credentials() {
        let mut local = request(OnboardingBackendKind::Local);
        local.remote_url = Some("https://example.invalid/envsync.git".to_owned());
        assert!(matches!(
            onboarding_backend(
                &local,
                Path::new("local-backend"),
                Path::new("private-git-cache"),
            ),
            Err(OnboardingFailure::Code(
                "desktop.invalid_backend_configuration"
            ))
        ));

        let mut git = request(OnboardingBackendKind::Git);
        git.remote_url =
            Some("https://token:must-not-appear@example.invalid/envsync.git".to_owned());
        git.git_auth = Some(GitOnboardingAuthKind::SshAgent);
        assert!(matches!(
            onboarding_backend(
                &git,
                Path::new("local-backend"),
                Path::new("private-git-cache"),
            ),
            Err(OnboardingFailure::Core(_))
        ));
    }
}
