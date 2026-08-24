//! M4 Task 1：桌面应用服务 View/API 契约的验收测试。

mod support;

use envsync_core::{
    ApiEvent, ApiRequest, ApiRequestId, ApiResponse, ApiResponseError, CancelOperationRequest,
    ConflictView, DiffView, OperationView, PlanView, ResourceStatus, StatusReport, StatusView,
    ViewDiagnostic, WorkspaceState, WorkspaceSummary, APPLICATION_SERVICE_SCHEMA_VERSION,
};
use envsync_domain::{
    BlobId, ConflictId, ConflictKind, DesiredDisposition, DeviceId, Diagnostic, Digest32,
    OperationId, PlanId, ResourceId, SnapshotId, WorkspaceId,
};
use envsync_storage::{
    ConflictRecord, ConflictState, ErrorDetail, OperationRecord, OperationState,
};

/// View API 不能把核心层的任意诊断文本直接交给 UI：诊断文本可能来自外部输入。
/// 该测试刻意塞入 canary，断言最终 JSON 仅保留稳定的机器可读信息。
#[test]
fn status_response_is_versioned_and_never_serializes_diagnostic_canary() {
    const CANARY: &str = "VIEW_API_CANARY_do_not_leak_7f1d2a";

    let report = StatusReport {
        workspace: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
            .parse::<WorkspaceId>()
            .expect("固定工作区标识有效"),
        device: DeviceId::derive(b"view-api-test-device"),
        backend_kind: "local",
        backend_reachable: true,
        last_known_revision_at_unix_ms: None,
        revision: 0,
        head: None,
        draft_head: None,
        state: WorkspaceState::Clean,
        resources: vec![ResourceStatus {
            resource: ResourceId::parse("shell/zsh/main").expect("测试资源标识有效"),
            observed: "present",
            disposition: None,
            needs_action: false,
        }],
        unfinished: Vec::new(),
        pending_actions: 0,
        open_conflicts: 0,
        diagnostics: vec![Diagnostic::warning(
            "status.canary",
            None,
            format!("token={CANARY}"),
        )],
    };

    let response = ApiResponse::ok(
        ApiRequestId::parse("req-status-v1").expect("请求标识有效"),
        StatusView::from_report(&report),
        report
            .diagnostics
            .iter()
            .map(ViewDiagnostic::from)
            .collect(),
    );

    let json = serde_json::to_value(response).expect("View API 必须可序列化");
    let rendered = json.to_string();

    assert_eq!(json["schema_version"], APPLICATION_SERVICE_SCHEMA_VERSION);
    assert_eq!(json["request_id"], "req-status-v1");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["data"]["state"], "clean");
    assert_eq!(json["data"]["resources"][0]["resource"], "shell/zsh/main");
    assert_eq!(json["diagnostics"][0]["code"], "status.canary");
    assert!(
        json["diagnostics"][0].get("message").is_none(),
        "View API 不得透传任意诊断正文"
    );
    assert!(
        !rendered.contains(CANARY),
        "任何 View/API JSON 都不得出现 canary"
    );
}

/// 请求与响应使用同一版本号及请求标识，桌面壳可以据此拒绝不兼容调用而不会猜测形状。
#[test]
fn request_is_explicitly_versioned_and_keeps_an_opaque_workspace_handle() {
    let request = ApiRequest::new(
        ApiRequestId::parse("req-workspace-status-v1").expect("请求标识有效"),
        "workspace-handle-01".to_owned(),
    );

    let json = serde_json::to_value(request).expect("请求必须可序列化");
    assert_eq!(json["schema_version"], APPLICATION_SERVICE_SCHEMA_VERSION);
    assert_eq!(json["request_id"], "req-workspace-status-v1");
    assert_eq!(json["data"], "workspace-handle-01");
}

/// 失败响应和成功响应共用一个稳定信封；失败时不允许伪装成含数据的成功响应，也不能
/// 在没有机器可读诊断的情况下丢失故障上下文。
#[test]
fn error_response_is_versioned_has_null_data_and_requires_a_diagnostic() {
    let request_id = ApiRequestId::parse("req-status-error-v1").expect("请求标识有效");
    let missing = ApiResponse::<StatusView>::error(request_id.clone(), Vec::new())
        .expect_err("错误响应必须至少有一条诊断");
    assert_eq!(missing, ApiResponseError::MissingDiagnostic);

    let response = ApiResponse::<StatusView>::error(
        request_id,
        vec![ViewDiagnostic {
            severity: "blocking".to_owned(),
            code: "status.backend_unreachable".to_owned(),
            resource: None,
        }],
    )
    .expect("带诊断的错误响应有效");

    let json = serde_json::to_value(response).expect("错误响应必须可序列化");
    assert_eq!(json["schema_version"], APPLICATION_SERVICE_SCHEMA_VERSION);
    assert_eq!(json["request_id"], "req-status-error-v1");
    assert_eq!(json["status"], "error");
    assert!(json["data"].is_null());
    assert_eq!(json["diagnostics"][0]["code"], "status.backend_unreachable");
}

/// 长操作只通过有序、版本化的事件更新，取消则是带操作 ID 的显式请求；二者都不能依赖
/// UI 侧的隐式状态或任意路径。
#[test]
fn operation_updates_are_versioned_and_cancellation_is_explicit() {
    let operation = "12345678-1234-4234-8234-123456789abc"
        .parse::<OperationId>()
        .expect("固定操作标识有效");
    let cancel = ApiRequest::new(
        ApiRequestId::parse("req-cancel-v1").expect("请求标识有效"),
        CancelOperationRequest::new(operation),
    );
    let cancel_json = serde_json::to_value(cancel).expect("取消请求必须可序列化");
    assert_eq!(
        cancel_json["schema_version"],
        APPLICATION_SERVICE_SCHEMA_VERSION
    );
    assert_eq!(cancel_json["data"]["operation_id"], operation.to_string());
    assert!(cancel_json["data"].get("path").is_none());

    let event = ApiEvent::ok(
        ApiRequestId::parse("req-apply-v1").expect("请求标识有效"),
        7,
        OperationView {
            operation: operation.to_string(),
            plan: PlanId::of(b"event-plan").to_string(),
            snapshot: SnapshotId::of(b"event-snapshot").to_string(),
            workspace: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0".to_owned(),
            revision: 3,
            state: "applying".to_owned(),
            created_at_unix_ms: 1_700_000_000_000,
            updated_at_unix_ms: 1_700_000_000_123,
            error_code: None,
        },
        Vec::new(),
    );
    let event_json = serde_json::to_value(event).expect("操作事件必须可序列化");
    assert_eq!(
        event_json["schema_version"],
        APPLICATION_SERVICE_SCHEMA_VERSION
    );
    assert_eq!(event_json["request_id"], "req-apply-v1");
    assert_eq!(event_json["sequence"], 7);
    assert_eq!(event_json["status"], "ok");
    assert_eq!(event_json["data"]["operation"], operation.to_string());
}

/// v1 golden fixture 固定已发布字段和值，但比较时允许响应额外增加字段。这保证删除或
/// 改名现有字段会失败，而兼容的 minor 扩展无需重写旧客户端的 fixture。
#[test]
fn status_response_preserves_v1_golden_contract() {
    let response = ApiResponse::ok(
        ApiRequestId::parse("req-status-golden-v1").expect("请求标识有效"),
        StatusView::from_report(&StatusReport {
            workspace: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
                .parse::<WorkspaceId>()
                .expect("固定工作区标识有效"),
            device: DeviceId::from_digest(Digest32::from_bytes([0x11; 32])),
            backend_kind: "local",
            backend_reachable: true,
            last_known_revision_at_unix_ms: None,
            revision: 42,
            head: None,
            draft_head: None,
            state: WorkspaceState::Clean,
            resources: vec![ResourceStatus {
                resource: ResourceId::parse("shell/zsh/main").expect("测试资源标识有效"),
                observed: "present",
                disposition: Some(DesiredDisposition::Managed),
                needs_action: false,
            }],
            unfinished: Vec::new(),
            pending_actions: 0,
            open_conflicts: 0,
            diagnostics: Vec::new(),
        }),
        vec![ViewDiagnostic {
            severity: "warning".to_owned(),
            code: "status.network_slow".to_owned(),
            resource: Some("shell/zsh/main".to_owned()),
        }],
    );
    let actual = serde_json::to_value(response).expect("golden 响应必须可序列化");
    let expected =
        serde_json::from_str(include_str!("fixtures/application-service-v1-status.json"))
            .expect("golden fixture 必须是有效 JSON");

    assert_json_contains(&actual, &expected, "$");
}

/// M4 的全部基础 View 都是纯元数据：既可序列化，又不会把计划内容或 journal 的错误正文
/// 交给 UI。秘密差异只保留“发生变更”这一事实。
#[test]
fn all_base_views_are_serializable_and_omit_sensitive_content() {
    const CANARY: &str = "VIEW_API_CANARY_do_not_leak_7f1d2a";
    let workspace = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
        .parse::<WorkspaceId>()
        .expect("固定工作区标识有效");

    let mut secret_action = support::write_action(
        "secret/example",
        "secret.txt",
        None,
        support::digest_of(b"after"),
        BlobId::of(CANARY.as_bytes()),
    );
    secret_action.secret = true;
    let plan = support::plan_of(vec![secret_action.clone()], 0, false);

    let conflict = ConflictRecord {
        conflict: ConflictId::of(b"view-api-conflict"),
        workspace,
        resource: ResourceId::parse("shell/zsh/main").expect("测试资源标识有效"),
        kind: ConflictKind::TextOverlap,
        base: None,
        ours: None,
        theirs: None,
        state: ConflictState::Open,
        choice: None,
        resolved_blob: None,
        created_at_unix_ms: 1_700_000_000_000,
        resolved_at_unix_ms: None,
    };
    let operation = OperationRecord {
        operation: "12345678-1234-4234-8234-123456789abc"
            .parse::<OperationId>()
            .expect("固定操作标识有效"),
        plan: PlanId::of(b"view-api-plan"),
        snapshot: SnapshotId::of(b"view-api-snapshot"),
        workspace,
        revision: 3,
        state: OperationState::PublishedNotConverged,
        created_at_unix_ms: 1_700_000_000_000,
        updated_at_unix_ms: 1_700_000_000_123,
        error: Some(ErrorDetail::new(
            "operation.failed",
            format!("token={CANARY}"),
        )),
    };

    let values = [
        serde_json::to_value(WorkspaceSummary::from_status_parts(
            workspace,
            DeviceId::derive(b"view-api-test-device"),
            "local",
        ))
        .expect("工作区摘要可序列化"),
        serde_json::to_value(PlanView::from_plan(&plan)).expect("计划 View 可序列化"),
        serde_json::to_value(DiffView::from_action(&secret_action)).expect("差异 View 可序列化"),
        serde_json::to_value(ConflictView::from_record(&conflict)).expect("冲突 View 可序列化"),
        serde_json::to_value(OperationView::from_record(&operation)).expect("操作 View 可序列化"),
    ];

    for value in &values {
        assert!(
            !value.to_string().contains(CANARY),
            "View 不得包含 canary：{value}"
        );
    }
    assert_eq!(values[2]["sensitive"], true);
    assert!(values[2]["before_digest"].is_null());
    assert!(values[2]["after_digest"].is_null());
    assert!(values[1]["actions"][0].get("content").is_none());
    assert_eq!(values[4]["error_code"], "operation.failed");
    assert!(values[4].get("error_message").is_none());
}

fn assert_json_contains(actual: &serde_json::Value, expected: &serde_json::Value, path: &str) {
    match expected {
        serde_json::Value::Object(expected_object) => {
            let actual_object = actual
                .as_object()
                .unwrap_or_else(|| panic!("{path} 应为 JSON object，实际为 {actual}"));
            for (key, expected_value) in expected_object {
                let child_path = format!("{path}.{key}");
                let actual_value = actual_object
                    .get(key)
                    .unwrap_or_else(|| panic!("缺少 v1 字段 {child_path}"));
                assert_json_contains(actual_value, expected_value, &child_path);
            }
        }
        serde_json::Value::Array(expected_items) => {
            let actual_items = actual
                .as_array()
                .unwrap_or_else(|| panic!("{path} 应为 JSON array，实际为 {actual}"));
            assert_eq!(
                actual_items.len(),
                expected_items.len(),
                "{path} 的数组长度改变会破坏 v1 fixture"
            );
            for (index, (actual_item, expected_item)) in
                actual_items.iter().zip(expected_items).enumerate()
            {
                assert_json_contains(actual_item, expected_item, &format!("{path}[{index}]"));
            }
        }
        _ => assert_eq!(actual, expected, "{path} 的 v1 值发生变化"),
    }
}
