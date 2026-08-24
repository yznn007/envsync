//! Tauri command 的窄 application-service 边界。
//!
//! 所有 command 都只接收 API v1 信封、强类型 ID 与已注册 workspace；本模块没有任意
//! 路径、shell、HTTP 或 Vault 明文入口。失败一律映射成脱敏的 [`ApiResponse`]。

use std::thread;

use envsync_core::{
    ApiEvent, ApiRequest, ApiRequestId, ApiResponse, ApplyCancellation, ApplyOutcome,
    ApplyStartView, ApplyView, CancellationView, ConflictListView, CoreError, CoreResult,
    EnvSyncService, OperationView, PlanView, StatusView, ViewData, ViewDiagnostic,
    WorkspaceSummary,
};
use envsync_domain::{ConflictId, OperationId, PlanId, WorkspaceId};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};

use crate::state::{DesktopState, DesktopStateError};

/// 后台 operation 进度使用的唯一事件名。
pub const OPERATION_EVENT: &str = "envsync://operation";

/// 经安全审查后可由桌面 UI 调用的 command 名称。
///
/// 此列表也会写入 Tauri build manifest；新增 command 必须先添加安全测试、明确输入 View
/// 和最小 capability，不能通过插件自动扩展。
pub const ALLOWED_COMMANDS: [&str; 8] = [
    "workspace_status",
    "workspace_plan",
    "workspace_apply",
    "operation_rollback",
    "conflict_list",
    "vault_metadata",
    "bundle_review",
    "operation_cancel",
];

/// 判断 command 是否位于静态白名单中。
pub fn is_allowed_command(command: &str) -> bool {
    ALLOWED_COMMANDS.contains(&command)
}

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

/// 为一次已登记 operation 请求回滚。
#[tauri::command]
pub fn operation_rollback(
    app: AppHandle,
    state: State<'_, DesktopState>,
    request: ApiRequest<OperationRequest>,
) -> ApiResponse<OperationView> {
    let request_id = request.request_id().clone();
    if let Some(response) = schema_error(&request) {
        return response;
    }
    let _operation_guard = state.inner().begin_operation();
    let operation_id = request.data().operation_id;
    match call_service(state.inner(), request.data().workspace_id, |service| {
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

/// 返回 Vault metadata endpoint 的受控未配置状态。
///
/// M4 后续 Vault 页面会将此 command 接到 metadata-only provider；在此之前不提供任何
/// Vault get/reveal 回退路径。
#[tauri::command]
pub fn vault_metadata(
    state: State<'_, DesktopState>,
    request: ApiRequest<WorkspaceRequest>,
) -> ApiResponse<WorkspaceSummary> {
    checked_unavailable(state.inner(), request, "desktop.vault_metadata_unavailable")
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
