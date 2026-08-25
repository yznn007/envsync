//! 桌面壳 IPC 面的安全回归测试。

use envsync_core::ApiRequest;
use envsync_desktop::{
    commands::{
        is_allowed_command, ApplyPlanRequest, ConflictResolutionRequest, CreateWorkspaceRequest,
        DeviceRevokeRequest, OperationRequest, RollbackExecutionRequest, WorkspaceRequest,
        ALLOWED_COMMANDS,
    },
    parse_safe_deep_link, SafeDeepLinkAction,
};
use envsync_domain::{OperationId, PlanId};

#[test]
fn only_reviewed_application_commands_are_exposed() {
    assert_eq!(
        ALLOWED_COMMANDS,
        [
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
        ]
    );

    for command in ALLOWED_COMMANDS {
        assert!(
            is_allowed_command(command),
            "白名单命令必须可识别：{command}"
        );
    }
    for forbidden in [
        "read_file",
        "write_file",
        "run_shell",
        "http_request",
        "vault_get_secret",
        "vault_set_secret",
        "secret_get",
    ] {
        assert!(
            !is_allowed_command(forbidden),
            "桌面端不得暴露高权限命令：{forbidden}"
        );
    }
}

/// application-service command 由四处共同声明；这个测试让任何一处遗漏或额外暴露都立即
/// 失败，而不是等到打包后的 capability 才发现。
#[test]
fn generated_command_registrations_match_the_allowlist() {
    let build = include_str!("../build.rs");
    let handler = include_str!("../src/lib.rs");
    let capabilities: serde_json::Value =
        serde_json::from_str(include_str!("../capabilities/default.json"))
            .expect("默认 capability 必须是合法 JSON");

    assert_eq!(quoted_names_after(build, ".commands(&["), ALLOWED_COMMANDS);
    assert_eq!(handler_names(handler), ALLOWED_COMMANDS);

    let capability_names = capabilities["permissions"]
        .as_array()
        .expect("permissions 必须是数组")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter_map(|permission| permission.strip_prefix("allow-"))
        .collect::<Vec<_>>();
    let expected_capabilities = ALLOWED_COMMANDS
        .iter()
        .map(|command| command.replace('_', "-"))
        .collect::<Vec<_>>();
    assert_eq!(
        capability_names,
        expected_capabilities
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
}

fn quoted_names_after<'a>(source: &'a str, marker: &str) -> Vec<&'a str> {
    source
        .split_once(marker)
        .expect("命令数组标记必须存在")
        .1
        .lines()
        .take_while(|line| !line.trim().starts_with("])"))
        .filter_map(|line| line.trim().strip_prefix('"'))
        .filter_map(|line| line.split_once('"').map(|(name, _)| name))
        .collect()
}

fn handler_names(source: &str) -> Vec<&str> {
    source
        .split_once(".invoke_handler(tauri::generate_handler![")
        .expect("Tauri handler 必须存在")
        .1
        .lines()
        .take_while(|line| !line.trim().starts_with("])"))
        .filter_map(|line| line.trim().strip_prefix("commands::"))
        .filter_map(|line| line.strip_suffix(','))
        .collect()
}

#[test]
fn command_payloads_reject_paths_and_unknown_fields() {
    let unsafe_payload = serde_json::json!({
        "schema_version": 1,
        "request_id": "req-path-injection",
        "data": {
            "workspace_id": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
            "path": "/Users/alice/.ssh/id_ed25519"
        }
    });
    assert!(
        serde_json::from_value::<ApiRequest<WorkspaceRequest>>(unsafe_payload).is_err(),
        "workspace command 不得接受 UI 提供的路径"
    );

    let unknown_envelope_field = serde_json::json!({
        "schema_version": 1,
        "request_id": "req-envelope-injection",
        "data": { "workspace_id": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0" },
        "shell": "rm -rf /"
    });
    assert!(
        serde_json::from_value::<ApiRequest<WorkspaceRequest>>(unknown_envelope_field).is_err(),
        "统一信封不得静默接受未知高权限字段"
    );
}

#[test]
fn onboarding_payloads_only_accept_native_root_capabilities() {
    let unsafe_create = serde_json::json!({
        "schema_version": 1,
        "request_id": "req-onboarding-path-injection",
        "data": {
            "backend_kind": "local",
            "device_profile": "workstation",
            "root_capability_token": "c7a16bdb-57b1-40bb-9cf1-1e42b463a53a",
            "path": "/Users/alice/.ssh/id_ed25519"
        }
    });
    assert!(
        serde_json::from_value::<ApiRequest<CreateWorkspaceRequest>>(unsafe_create).is_err(),
        "首次使用只能引用原生登记的 token，不能把路径传给 command"
    );

    let direct_path_token = serde_json::json!({
        "schema_version": 1,
        "request_id": "req-onboarding-direct-path",
        "data": {
            "backend_kind": "local",
            "device_profile": "workstation",
            "root_capability_token": "/Users/alice/.ssh/id_ed25519"
        }
    });
    let request = serde_json::from_value::<ApiRequest<CreateWorkspaceRequest>>(direct_path_token)
        .expect("协议层允许反序列化；原生状态层会拒绝非 token");
    assert_eq!(
        request.data().root_capability_token,
        "/Users/alice/.ssh/id_ed25519"
    );

    let token_paste = serde_json::json!({
        "schema_version": 1,
        "request_id": "req-onboarding-token-paste",
        "data": {
            "backend_kind": "git",
            "device_profile": "workstation",
            "root_capability_token": "c7a16bdb-57b1-40bb-9cf1-1e42b463a53a",
            "remote_url": "https://example.invalid/envsync.git",
            "git_auth": "token-secret-ref",
            "token": "must-not-be-accepted"
        }
    });
    assert!(
        serde_json::from_value::<ApiRequest<CreateWorkspaceRequest>>(token_paste).is_err(),
        "首次使用不得接受 token 或 token-secret-ref 伪装成认证参数"
    );
}

#[test]
fn mutating_command_payloads_only_accept_registered_ids() {
    let plan_id = PlanId::of(b"desktop-command-payload-plan").to_string();
    let operation_id = "12345678-1234-4234-8234-123456789abc"
        .parse::<OperationId>()
        .expect("固定操作标识有效")
        .to_string();

    let unsafe_apply = serde_json::json!({
        "schema_version": 1,
        "request_id": "req-apply-path-injection",
        "data": {
            "workspace_id": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
            "plan_id": plan_id,
            "path": "/Users/alice/.ssh/id_ed25519"
        }
    });
    assert!(
        serde_json::from_value::<ApiRequest<ApplyPlanRequest>>(unsafe_apply).is_err(),
        "apply 只能接收已保存的 Plan ID，不能接受路径"
    );

    let unsafe_cancel = serde_json::json!({
        "schema_version": 1,
        "request_id": "req-cancel-command-injection",
        "data": {
            "workspace_id": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
            "operation_id": operation_id,
            "shell": "rm -rf /"
        }
    });
    assert!(
        serde_json::from_value::<ApiRequest<OperationRequest>>(unsafe_cancel).is_err(),
        "取消只能引用 operation ID，不能传入 shell 参数"
    );

    let unsafe_resolution = serde_json::json!({
        "schema_version": 1,
        "request_id": "req-resolution-path-injection",
        "data": {
            "workspace_id": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
            "conflict_id": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
            "choice": "manual",
            "manual_content": "key = value",
            "path": "/Users/alice/.ssh/id_ed25519"
        }
    });
    assert!(
        serde_json::from_value::<ApiRequest<ConflictResolutionRequest>>(unsafe_resolution).is_err(),
        "冲突裁决不得带入路径或额外高权限字段"
    );

    let direct_rollback = serde_json::json!({
        "schema_version": 1,
        "request_id": "req-direct-rollback",
        "data": {
            "workspace_id": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
            "operation_id": operation_id
        }
    });
    assert!(
        serde_json::from_value::<ApiRequest<RollbackExecutionRequest>>(direct_rollback).is_err(),
        "回滚必须携带原生审核 token 与逐项确认，不能从 UI 直接执行"
    );

    let unsafe_revoke = serde_json::json!({
        "schema_version": 1,
        "request_id": "req-device-revoke-injection",
        "data": {
            "workspace_id": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
            "device_id": "1111111111111111111111111111111111111111111111111111111111111111",
            "confirmation": "1111111111111111111111111111111111111111111111111111111111111111",
            "shell": "rm -rf /"
        }
    });
    assert!(
        serde_json::from_value::<ApiRequest<DeviceRevokeRequest>>(unsafe_revoke).is_err(),
        "设备撤销不得接受 shell 或其他未审核字段"
    );
}

#[test]
fn csp_and_capability_forbid_remote_code_and_privileged_plugins() {
    let config: serde_json::Value =
        serde_json::from_str(include_str!("../tauri.conf.json")).expect("Tauri 配置必须是 JSON");
    let csp = config["app"]["security"]["csp"]
        .as_str()
        .expect("必须声明 CSP");
    assert!(!csp.contains("unsafe-eval"));
    assert!(!csp.contains("https:"));
    assert!(!csp.contains("connect-src *"));
    let connect_sources = csp
        .split(';')
        .map(str::trim)
        .find_map(|directive| directive.strip_prefix("connect-src "))
        .expect("CSP 必须显式限制 connect-src")
        .split_whitespace()
        .collect::<Vec<_>>();
    assert_eq!(
        connect_sources,
        [
            "'self'",
            "ipc:",
            "http://ipc.localhost",
            "http://127.0.0.1:1420"
        ]
    );

    let capability: serde_json::Value =
        serde_json::from_str(include_str!("../capabilities/default.json"))
            .expect("capability 必须是 JSON");
    let permissions = capability["permissions"]
        .as_array()
        .expect("capability 必须列出 permissions")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    assert!(permissions.contains(&"core:event:allow-listen"));
    assert!(permissions.contains(&"core:event:allow-unlisten"));
    for forbidden in [
        "core:default",
        "core:path",
        "core:app",
        "core:window",
        "core:resources",
        "core:image",
        "core:menu",
        "core:tray",
        "fs",
        "shell",
        "http",
        "dialog",
    ] {
        assert!(
            permissions
                .iter()
                .all(|permission| !permission.contains(forbidden)),
            "默认 capability 不得授予 {forbidden} 权限"
        );
    }

    let manifest = include_str!("../Cargo.toml");
    for forbidden in ["tauri-plugin-fs", "tauri-plugin-shell", "tauri-plugin-http"] {
        assert!(!manifest.contains(forbidden), "桌面壳不得链接 {forbidden}");
    }
}

#[test]
fn second_instance_forwards_only_a_parameterless_focus_action() {
    assert_eq!(
        parse_safe_deep_link(&["envsync-desktop".to_owned(), "envsync://focus".to_owned()]),
        Some(SafeDeepLinkAction::Focus)
    );
    for unsafe_argument in [
        "envsync://focus?token=do-not-forward",
        "envsync://open?path=/private/file",
        "--secret=do-not-forward",
    ] {
        assert_eq!(
            parse_safe_deep_link(&["envsync-desktop".to_owned(), unsafe_argument.to_owned()]),
            None,
            "第二实例不得把任意参数带入 UI：{unsafe_argument}"
        );
    }
}
