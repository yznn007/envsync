#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

//! EnvSync 的受限 Tauri 桌面壳。
//!
//! WebView 不直接访问文件系统、后端、shell 或 Vault。它仅通过 [`commands`] 调用 core
//! application service，所有输出均为版本化脱敏 View。

use serde::Serialize;
use tauri::{Emitter, Manager, WindowEvent};

/// 受控 IPC command。
pub mod commands;
/// 已注册 workspace 的进程状态。
pub mod state;

/// 第二实例可以要求主窗口执行的无参数安全动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeDeepLinkAction {
    /// 显示并聚焦既有主窗口。
    Focus,
}

/// 第二实例传给主实例的安全动作事件名。
pub const SAFE_DEEP_LINK_EVENT: &str = "envsync://focus";

/// 仅接受不携带用户数据的已知 deep-link。
///
/// 参数、cwd、query 与 fragment 都不会转发给 UI；不能把命令行中的秘密、路径或任意文本
/// 重新注入 WebView。
pub fn parse_safe_deep_link(arguments: &[String]) -> Option<SafeDeepLinkAction> {
    arguments
        .iter()
        .any(|argument| argument == "envsync://focus")
        .then_some(SafeDeepLinkAction::Focus)
}

/// 启动受限桌面壳。
pub fn run() -> tauri::Result<()> {
    let app = tauri::Builder::default()
        .manage(state::DesktopState::default())
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window
                    .state::<state::DesktopState>()
                    .has_active_operations()
                {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .plugin(tauri_plugin_single_instance::init(
            |app, arguments, _cwd| {
                if let Some(action) = parse_safe_deep_link(&arguments) {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                    let _ = app.emit(SAFE_DEEP_LINK_EVENT, action);
                }
            },
        ))
        // 原生 Rust command 使用系统选择器登记路径能力；WebView 不获得 dialog 或 fs
        // capability，也不会调用该插件暴露的 JS command。
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::onboarding_select_root,
            commands::onboarding_create_workspace,
            commands::onboarding_open_workspace,
            commands::workspace_status,
            commands::workspace_plan,
            commands::workspace_apply,
            commands::operation_rollback,
            commands::conflict_list,
            commands::vault_metadata,
            commands::bundle_review,
            commands::operation_cancel,
        ])
        .build(tauri::generate_context!())?;
    app.run(|app_handle, event| {
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            if app_handle
                .state::<state::DesktopState>()
                .has_active_operations()
            {
                api.prevent_exit();
            }
        }
    });
    Ok(())
}
