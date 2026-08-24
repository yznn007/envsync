fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "onboarding_select_root",
            "onboarding_create_workspace",
            "onboarding_open_workspace",
            "workspace_status",
            "workspace_plan",
            "workspace_apply",
            "operation_rollback",
            "conflict_list",
            "vault_metadata",
            "bundle_review",
            "operation_cancel",
        ]),
    ))
    .expect("生成 Tauri 受限命令权限失败");
}
