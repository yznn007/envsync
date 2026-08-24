use base64::Engine;
use envsync_plugin_api::{PluginCatalog, PluginManifest, PluginManifestError};

fn valid_manifest_json() -> serde_json::Value {
    serde_json::json!({
        "id": "com.example.calendar",
        "version": "1.2.0",
        "publisher": {
            "id": "com.example",
            "public_key": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
        },
        "api": ">=1.0.0, <2.0.0",
        "entrypoint": "bin/plugin",
        "targets": ["linux"],
        "capabilities": ["observe", "render"],
        "limits": {
            "max_runtime_ms": 5000,
            "max_memory_bytes": 67_108_864,
            "max_output_bytes": 1_048_576,
        },
        "signature": {
            "algorithm": "ed25519",
            "value": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 64]),
        },
    })
}

fn assert_error_code(json: serde_json::Value, expected: &str) {
    let error = PluginManifest::from_json_value(json).expect_err("必须拒绝不可信 manifest");
    assert_eq!(error.code(), expected);
}

#[test]
fn manifest_accepts_valid_value_and_produces_stable_unsigned_payload() {
    let manifest = PluginManifest::from_json_value(valid_manifest_json()).expect("合法 manifest");

    assert_eq!(manifest.id().as_str(), "com.example.calendar");
    assert_eq!(manifest.version().to_string(), "1.2.0");
    assert_eq!(manifest.entrypoint().as_str(), "bin/plugin");

    let payload = manifest.signing_payload().expect("payload 必须可序列化");
    assert_eq!(
        payload,
        manifest.signing_payload().expect("payload 必须确定")
    );
    let payload_json: serde_json::Value =
        serde_json::from_slice(&payload).expect("payload 是 JSON");
    assert!(payload_json.get("signature").is_none());
    assert_eq!(payload_json["targets"], serde_json::json!(["linux"]));
    assert_eq!(
        payload_json["capabilities"],
        serde_json::json!(["observe", "render"])
    );
}

#[test]
fn manifest_rejects_unsafe_entrypoints_unknown_capabilities_and_incompatible_api() {
    for (field, value, code) in [
        (
            "entrypoint",
            serde_json::json!("/etc/passwd"),
            "plugin.manifest.invalid_entrypoint",
        ),
        (
            "entrypoint",
            serde_json::json!("bin/../escape"),
            "plugin.manifest.invalid_entrypoint",
        ),
        (
            "capabilities",
            serde_json::json!(["observe", "network.raw"]),
            "plugin.manifest.unknown_capability",
        ),
        (
            "api",
            serde_json::json!("^2.0.0"),
            "plugin.manifest.incompatible_api",
        ),
    ] {
        let mut json = valid_manifest_json();
        json[field] = value;
        assert_error_code(json, code);
    }
}

#[test]
fn catalog_rejects_duplicate_normalized_plugin_ids() {
    let first = PluginManifest::from_json_value(valid_manifest_json()).expect("合法 manifest");
    let second = PluginManifest::from_json_value(valid_manifest_json()).expect("合法 manifest");
    let error = PluginCatalog::new(vec![first, second]).expect_err("同 ID 不能同时安装");
    assert_eq!(error.code(), "plugin.manifest.duplicate_id");
}

#[test]
fn manifest_rejects_invalid_semver_and_out_of_range_limits() {
    let mut invalid_version = valid_manifest_json();
    invalid_version["version"] = serde_json::json!("not-semver");
    assert_error_code(invalid_version, "plugin.manifest.invalid_semver");

    for (field, value) in [
        ("max_runtime_ms", serde_json::json!(0)),
        ("max_runtime_ms", serde_json::json!(30_001)),
        ("max_memory_bytes", serde_json::json!(1_048_575)),
        ("max_memory_bytes", serde_json::json!(268_435_457_u64)),
        ("max_output_bytes", serde_json::json!(0)),
        ("max_output_bytes", serde_json::json!(8_388_609)),
    ] {
        let mut json = valid_manifest_json();
        json["limits"][field] = value;
        assert_error_code(json, "plugin.manifest.invalid_limit");
    }
}

#[test]
fn manifest_rejects_bad_key_and_signature_shape() {
    let mut bad_key = valid_manifest_json();
    bad_key["publisher"]["public_key"] =
        serde_json::json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 31]));
    assert_error_code(bad_key, "plugin.manifest.invalid_signature");

    let mut bad_signature = valid_manifest_json();
    bad_signature["signature"]["value"] =
        serde_json::json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 63]));
    assert_error_code(bad_signature, "plugin.manifest.invalid_signature");
}

#[test]
fn manifest_rejects_empty_or_duplicate_sets_and_windows_entrypoints() {
    let mut empty_targets = valid_manifest_json();
    empty_targets["targets"] = serde_json::json!([]);
    assert_error_code(empty_targets, "plugin.manifest.invalid_target");

    let mut duplicate_targets = valid_manifest_json();
    duplicate_targets["targets"] = serde_json::json!(["linux", "linux"]);
    assert_error_code(duplicate_targets, "plugin.manifest.invalid_target");

    let mut duplicate_capabilities = valid_manifest_json();
    duplicate_capabilities["capabilities"] = serde_json::json!(["observe", "observe"]);
    assert_error_code(duplicate_capabilities, "plugin.manifest.unknown_capability");

    let mut windows_drive = valid_manifest_json();
    windows_drive["entrypoint"] = serde_json::json!("C:/plugin.exe");
    assert_error_code(windows_drive, "plugin.manifest.invalid_entrypoint");
}

#[test]
fn manifest_error_text_does_not_echo_untrusted_input() {
    let mut json = valid_manifest_json();
    json["signature"]["value"] = serde_json::json!("sensitive-signature-material");
    let error = PluginManifest::from_json_value(json).expect_err("无效签名必须被拒绝");
    assert_eq!(error.code(), "plugin.manifest.invalid_signature");
    assert!(!error.to_string().contains("sensitive-signature-material"));
    assert!(!format!("{error:?}").contains("sensitive-signature-material"));
}

#[test]
fn error_type_is_exposed_for_callers() {
    fn accepts_manifest_error(_: PluginManifestError) {}

    let mut json = valid_manifest_json();
    json["id"] = serde_json::json!("invalid");
    accepts_manifest_error(PluginManifest::from_json_value(json).expect_err("ID 必须被拒绝"));
}
