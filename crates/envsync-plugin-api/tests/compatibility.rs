use base64::Engine;
use std::io::{self, Cursor, Read, Write};

use envsync_plugin_api::{
    decode_frame, encode_frame, parse_initialize_result, read_frame, write_frame, PluginCatalog,
    PluginManifest, PluginManifestError, PluginMethod, PluginRpcError, RequestId, RpcErrorObject,
    RpcMessage, SchemaVersion, MAX_RPC_FRAME_BYTES,
};

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

fn request_json(method: &str, version: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "schema_version": version,
        "id": "request-0001",
        "method": method,
        "params": {},
    })
}

fn frame_with_payload(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn assert_rpc_error_code(error: PluginRpcError, expected: &str) {
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
fn manifest_rejects_structural_json_with_generic_safe_code() {
    let mut missing_field = valid_manifest_json();
    missing_field
        .as_object_mut()
        .expect("fixture 是 object")
        .remove("id");
    assert_error_code(missing_field, "plugin.manifest.invalid_manifest");

    let mut wrong_field_type = valid_manifest_json();
    wrong_field_type["limits"] = serde_json::json!("not-an-object");
    assert_error_code(wrong_field_type, "plugin.manifest.invalid_manifest");

    let mut unknown_field = valid_manifest_json();
    unknown_field["future_untrusted_field"] = serde_json::json!(true);
    assert_error_code(unknown_field, "plugin.manifest.invalid_manifest");
}

#[test]
fn manifest_signing_payload_preserves_v1_wire_order_and_bytes() {
    let mut json = valid_manifest_json();
    json["targets"] = serde_json::json!(["windows", "wasi-p2", "macos", "linux"]);
    json["capabilities"] = serde_json::json!(["verify", "render", "plan-command", "observe"]);

    let manifest = PluginManifest::from_json_value(json).expect("合法 manifest");
    let payload = manifest.signing_payload().expect("payload 必须可序列化");
    assert_eq!(
        payload,
        br#"{"id":"com.example.calendar","version":"1.2.0","publisher":{"id":"com.example","public_key":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"},"api":">=1.0.0, <2.0.0","entrypoint":"bin/plugin","targets":["macos","windows","linux","wasi-p2"],"capabilities":["observe","render","plan-command","verify"],"limits":{"max_runtime_ms":5000,"max_memory_bytes":67108864,"max_output_bytes":1048576}}"#,
        "签名 payload 的字段和 v1 数组顺序必须稳定",
    );
    let payload: serde_json::Value = serde_json::from_slice(&payload).expect("payload 是 JSON");

    assert_eq!(
        payload["targets"],
        serde_json::json!(["macos", "windows", "linux", "wasi-p2"])
    );
    assert_eq!(
        payload["capabilities"],
        serde_json::json!(["observe", "render", "plan-command", "verify"])
    );
}

#[test]
fn manifest_rejects_unsafe_entrypoints_unknown_capabilities_and_incompatible_api() {
    for (field, value, code) in [
        (
            "entrypoint",
            serde_json::json!(""),
            "plugin.manifest.invalid_entrypoint",
        ),
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
            "entrypoint",
            serde_json::json!("bin//plugin"),
            "plugin.manifest.invalid_entrypoint",
        ),
        (
            "entrypoint",
            serde_json::json!("bin\\\\plugin"),
            "plugin.manifest.invalid_entrypoint",
        ),
        (
            "entrypoint",
            serde_json::json!("bin\u{0000}plugin"),
            "plugin.manifest.invalid_entrypoint",
        ),
        (
            "entrypoint",
            serde_json::json!("bin:plugin"),
            "plugin.manifest.invalid_entrypoint",
        ),
        (
            "entrypoint",
            serde_json::json!("."),
            "plugin.manifest.invalid_entrypoint",
        ),
        (
            "entrypoint",
            serde_json::json!("./bin"),
            "plugin.manifest.invalid_entrypoint",
        ),
        (
            "entrypoint",
            serde_json::json!("bin/"),
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

    let mut malformed_key = valid_manifest_json();
    malformed_key["publisher"]["public_key"] = serde_json::json!("!".repeat(43));
    assert_error_code(malformed_key, "plugin.manifest.invalid_signature");

    let mut malformed_signature = valid_manifest_json();
    malformed_signature["signature"]["value"] = serde_json::json!("!".repeat(86));
    assert_error_code(malformed_signature, "plugin.manifest.invalid_signature");
}

#[test]
fn manifest_rejects_oversized_fixed_base64_values() {
    let mut oversized_key = valid_manifest_json();
    oversized_key["publisher"]["public_key"] = serde_json::json!("a".repeat(4_096));
    assert_error_code(oversized_key, "plugin.manifest.invalid_signature");

    let mut oversized_signature = valid_manifest_json();
    oversized_signature["signature"]["value"] = serde_json::json!("a".repeat(4_096));
    assert_error_code(oversized_signature, "plugin.manifest.invalid_signature");
}

#[test]
fn manifest_rejects_empty_or_duplicate_sets_and_windows_entrypoints() {
    let mut empty_targets = valid_manifest_json();
    empty_targets["targets"] = serde_json::json!([]);
    assert_error_code(empty_targets, "plugin.manifest.invalid_target");

    let mut freebsd_target = valid_manifest_json();
    freebsd_target["targets"] = serde_json::json!(["freebsd"]);
    assert_error_code(freebsd_target, "plugin.manifest.invalid_target");

    let mut duplicate_targets = valid_manifest_json();
    duplicate_targets["targets"] = serde_json::json!(["linux", "linux"]);
    assert_error_code(duplicate_targets, "plugin.manifest.invalid_target");

    let mut empty_capabilities = valid_manifest_json();
    empty_capabilities["capabilities"] = serde_json::json!([]);
    assert_error_code(empty_capabilities, "plugin.manifest.unknown_capability");

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
fn manifest_accepts_boundary_resource_limits() {
    for (runtime, memory, output) in [
        (100, 1_048_576_u64, 1_024_u64),
        (30_000, 268_435_456_u64, 8_388_608_u64),
    ] {
        let mut json = valid_manifest_json();
        json["limits"]["max_runtime_ms"] = serde_json::json!(runtime);
        json["limits"]["max_memory_bytes"] = serde_json::json!(memory);
        json["limits"]["max_output_bytes"] = serde_json::json!(output);

        let manifest = PluginManifest::from_json_value(json).expect("边界值必须被接受");
        assert_eq!(manifest.entrypoint().as_str(), "bin/plugin");
    }
}

#[test]
fn error_type_is_exposed_for_callers() {
    fn accepts_manifest_error(_: PluginManifestError) {}

    let mut json = valid_manifest_json();
    json["id"] = serde_json::json!("invalid");
    accepts_manifest_error(PluginManifest::from_json_value(json).expect_err("ID 必须被拒绝"));
}

#[test]
fn golden_initialize_frame_is_length_prefixed_and_round_trips() {
    let json = include_bytes!("fixtures/initialize-request-v1.0.json");
    let message = RpcMessage::from_json_slice(json).expect("fixture 合法");
    let frame = encode_frame(&message).expect("可编码");
    assert_eq!(&frame[..4], &(json.len() as u32).to_be_bytes());
    assert_eq!(&frame[4..], json);
    let decoded = decode_frame(&frame).expect("frame 可读");
    assert_eq!(
        decoded.request().expect("request").method(),
        PluginMethod::Initialize
    );
    assert_eq!(decoded.schema_version(), SchemaVersion::new(1, 0));
}

#[test]
fn golden_describe_response_frame_is_length_prefixed_and_round_trips() {
    let json = include_bytes!("fixtures/describe-response-v1.1.json");
    let message = RpcMessage::from_json_slice(json).expect("fixture 合法");
    let frame = encode_frame(&message).expect("可编码");
    assert_eq!(&frame[..4], &(json.len() as u32).to_be_bytes());
    assert_eq!(&frame[4..], json);
    let decoded = decode_frame(&frame).expect("frame 可读");
    assert!(decoded.response().is_some());
    assert_eq!(decoded.schema_version(), SchemaVersion::new(1, 1));
}

#[test]
fn supported_minors_ignore_extensions_but_unknown_methods_and_versions_fail() {
    let mut value: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/describe-response-v1.1.json"))
            .expect("fixture JSON");
    value["future_extension"] = serde_json::json!({"safe": true});
    assert!(RpcMessage::from_json_value(value).is_ok());

    for (method, version, code) in [
        (
            "erase-everything",
            serde_json::json!({"major": 1, "minor": 1}),
            "plugin.rpc.unknown_method",
        ),
        (
            "describe",
            serde_json::json!({"major": 2, "minor": 0}),
            "plugin.rpc.unsupported_version",
        ),
        (
            "describe",
            serde_json::json!({"major": 1, "minor": 2}),
            "plugin.rpc.unsupported_version",
        ),
    ] {
        let request = request_json(method, version);
        assert_eq!(
            RpcMessage::from_json_value(request).unwrap_err().code(),
            code
        );
    }
}

#[test]
fn frame_reader_rejects_oversized_prefix_before_allocating_body() {
    let declared_len = (MAX_RPC_FRAME_BYTES + 1) as u32;

    struct PrefixOnlyReader {
        prefix: [u8; 4],
        consumed: bool,
    }

    impl Read for PrefixOnlyReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            assert!(!self.consumed, "超长 prefix 后不得继续读取 body");
            buffer[..4].copy_from_slice(&self.prefix);
            self.consumed = true;
            Ok(4)
        }
    }

    let mut reader = PrefixOnlyReader {
        prefix: declared_len.to_be_bytes(),
        consumed: false,
    };
    let error = read_frame(&mut reader).expect_err("超长 frame 必须在读取 body 前拒绝");
    assert_rpc_error_code(error, "plugin.rpc.frame_too_large");
}

#[test]
fn frame_reader_rejects_truncated_prefix_and_body() {
    let mut prefix = Cursor::new([0_u8, 0, 0]);
    let error = read_frame(&mut prefix).expect_err("截断 prefix 必须被拒绝");
    assert_rpc_error_code(error, "plugin.rpc.truncated_frame");

    let mut body = Cursor::new([0_u8, 0, 0, 5, b'{', b'}']);
    let error = read_frame(&mut body).expect_err("截断 body 必须被拒绝");
    assert_rpc_error_code(error, "plugin.rpc.truncated_frame");
}

#[test]
fn frame_decoder_rejects_non_utf8_invalid_json_and_length_mismatches() {
    let error = decode_frame(&frame_with_payload(&[0xff])).expect_err("非 UTF-8 必须被拒绝");
    assert_rpc_error_code(error, "plugin.rpc.invalid_utf8");

    let error = decode_frame(&frame_with_payload(b"{")).expect_err("JSON 语法错误必须被拒绝");
    assert_rpc_error_code(error, "plugin.rpc.invalid_json");

    let mut truncated = 3_u32.to_be_bytes().to_vec();
    truncated.extend_from_slice(b"{}");
    let error = decode_frame(&truncated).expect_err("声明长度不足必须被拒绝");
    assert_rpc_error_code(error, "plugin.rpc.truncated_frame");

    let mut frame = frame_with_payload(b"{}");
    frame.push(b'!');
    let error = decode_frame(&frame).expect_err("尾随 bytes 必须被拒绝");
    assert_rpc_error_code(error, "plugin.rpc.length_mismatch");
}

#[test]
fn non_eof_io_errors_are_safe_and_not_reported_as_truncation() {
    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "secret /Users/example/Vault-token",
            ))
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "secret /Users/example/Vault-token",
            ))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let error = read_frame(&mut FailingReader).expect_err("非 EOF 读取错误必须被分类");
    assert_rpc_error_code(error, "plugin.rpc.io_error");
    assert!(!error.to_string().contains("Vault-token"));
    assert!(!format!("{error:?}").contains("Vault-token"));

    let message =
        RpcMessage::from_json_slice(include_bytes!("fixtures/initialize-request-v1.0.json"))
            .expect("fixture 合法");
    let error = write_frame(&mut FailingWriter, &message).expect_err("写入错误必须被分类");
    assert_rpc_error_code(error, "plugin.rpc.io_error");
    assert!(!error.to_string().contains("Vault-token"));
    assert!(!format!("{error:?}").contains("Vault-token"));
}

#[test]
fn request_id_boundaries_are_enforced_in_api_and_envelope() {
    assert_eq!(RequestId::parse("a").expect("最短 ID 合法").as_str(), "a");
    assert!(RequestId::parse(&"a".repeat(64)).is_ok());
    assert_eq!(
        RequestId::parse("").expect_err("空 ID 必须拒绝").code(),
        "plugin.rpc.invalid_request"
    );
    assert_eq!(
        RequestId::parse(&"a".repeat(65))
            .expect_err("超长 ID 必须拒绝")
            .code(),
        "plugin.rpc.invalid_request"
    );

    for id in [
        "has space",
        "line\nbreak",
        "nul\u{0000}byte",
        "slash/id",
        "非ascii",
    ] {
        assert_eq!(
            RequestId::parse(id)
                .expect_err("非法字符 ID 必须拒绝")
                .code(),
            "plugin.rpc.invalid_request"
        );
    }

    let mut request = request_json("describe", serde_json::json!({"major": 1, "minor": 1}));
    request["id"] = serde_json::json!("");
    assert_eq!(
        RpcMessage::from_json_value(request)
            .expect_err("envelope 空 ID 必须被拒绝")
            .code(),
        "plugin.rpc.invalid_request"
    );
}

#[test]
fn all_methods_are_closed_and_round_trip_without_other_variant() {
    for (wire, method) in [
        ("initialize", PluginMethod::Initialize),
        ("describe", PluginMethod::Describe),
        ("observe", PluginMethod::Observe),
        ("render", PluginMethod::Render),
        ("plan-command", PluginMethod::PlanCommand),
        ("verify", PluginMethod::Verify),
        ("shutdown", PluginMethod::Shutdown),
    ] {
        assert_eq!(PluginMethod::parse(wire).expect("method 合法"), method);
        assert_eq!(method.as_str(), wire);

        let message = RpcMessage::from_json_value(request_json(
            wire,
            serde_json::json!({"major": 1, "minor": 1}),
        ))
        .expect("封闭 method 必须可解析");
        assert_eq!(message.request().expect("request").method(), method);
    }

    assert_eq!(
        PluginMethod::parse("initialize-now")
            .expect_err("未知 method 必须拒绝")
            .code(),
        "plugin.rpc.unknown_method"
    );
}

#[test]
fn rpc_shape_rejects_bad_jsonrpc_id_batch_and_mixed_messages() {
    let mut bad_jsonrpc = request_json("describe", serde_json::json!({"major": 1, "minor": 1}));
    bad_jsonrpc["jsonrpc"] = serde_json::json!("1.0");
    assert_eq!(
        RpcMessage::from_json_value(bad_jsonrpc)
            .expect_err("jsonrpc 必须是 2.0")
            .code(),
        "plugin.rpc.invalid_request"
    );

    let mut missing_id = request_json("describe", serde_json::json!({"major": 1, "minor": 1}));
    missing_id.as_object_mut().expect("object").remove("id");
    assert_eq!(
        RpcMessage::from_json_value(missing_id)
            .expect_err("缺失 ID 必须被拒绝")
            .code(),
        "plugin.rpc.invalid_request"
    );

    let mut missing_params = request_json("describe", serde_json::json!({"major": 1, "minor": 1}));
    missing_params
        .as_object_mut()
        .expect("object")
        .remove("params");
    assert_eq!(
        RpcMessage::from_json_value(missing_params)
            .expect_err("缺失 params 必须被拒绝")
            .code(),
        "plugin.rpc.invalid_request"
    );

    for id in [serde_json::Value::Null, serde_json::json!(7)] {
        let mut request = request_json("describe", serde_json::json!({"major": 1, "minor": 1}));
        request["id"] = id;
        assert_eq!(
            RpcMessage::from_json_value(request)
                .expect_err("非字符串 ID 必须被拒绝")
                .code(),
            "plugin.rpc.invalid_request"
        );
    }

    let batch = serde_json::json!([request_json(
        "describe",
        serde_json::json!({"major": 1, "minor": 1})
    )]);
    assert_eq!(
        RpcMessage::from_json_value(batch)
            .expect_err("batch 必须被拒绝")
            .code(),
        "plugin.rpc.invalid_request"
    );

    let mut mixed = request_json("describe", serde_json::json!({"major": 1, "minor": 1}));
    mixed["result"] = serde_json::json!({});
    assert_eq!(
        RpcMessage::from_json_value(mixed)
            .expect_err("request/response 混形必须被拒绝")
            .code(),
        "plugin.rpc.invalid_request"
    );

    let mut mixed_error = request_json("describe", serde_json::json!({"major": 1, "minor": 1}));
    mixed_error["error"] = serde_json::json!({"code": "plugin.failed", "message": "failed"});
    assert_eq!(
        RpcMessage::from_json_value(mixed_error)
            .expect_err("request/error 混形必须被拒绝")
            .code(),
        "plugin.rpc.invalid_request"
    );
}

#[test]
fn response_requires_exactly_one_result_or_error() {
    let base = serde_json::json!({
        "jsonrpc": "2.0",
        "schema_version": {"major": 1, "minor": 1},
        "id": "request-0001",
    });

    let mut both = base.clone();
    both["result"] = serde_json::json!({});
    both["error"] = serde_json::json!({"code": "plugin.failed", "message": "failed"});
    assert_eq!(
        RpcMessage::from_json_value(both)
            .expect_err("result/error 不能同时存在")
            .code(),
        "plugin.rpc.invalid_response"
    );

    assert_eq!(
        RpcMessage::from_json_value(base)
            .expect_err("response 必须包含 result 或 error")
            .code(),
        "plugin.rpc.invalid_response"
    );

    let response_with_params = serde_json::json!({
        "jsonrpc": "2.0",
        "schema_version": {"major": 1, "minor": 1},
        "id": "request-0001",
        "params": {},
        "result": {},
    });
    assert_eq!(
        RpcMessage::from_json_value(response_with_params)
            .expect_err("response 不能携带 request params")
            .code(),
        "plugin.rpc.invalid_response"
    );
}

#[test]
fn write_and_read_frame_round_trip_supported_request() {
    let message =
        RpcMessage::from_json_slice(include_bytes!("fixtures/initialize-request-v1.0.json"))
            .expect("fixture 合法");
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &message).expect("frame 可写");

    let mut reader = Cursor::new(bytes);
    let decoded = read_frame(&mut reader).expect("frame 可读");
    assert_eq!(
        decoded.request().expect("request").id().as_str(),
        "request-0001"
    );
    assert_eq!(decoded.schema_version(), SchemaVersion::new(1, 0));
}

#[test]
fn parse_initialize_result_checks_selected_supported_version_after_correlation() {
    let selected = parse_initialize_result(&serde_json::json!({
        "selected_schema_version": {"major": 1, "minor": 1}
    }))
    .expect("关联后的 initialize result 合法");
    assert_eq!(selected, SchemaVersion::new(1, 1));

    let error = parse_initialize_result(&serde_json::json!({
        "selected_schema_version": {"major": 1, "minor": 2}
    }))
    .expect_err("future minor 必须被拒绝");
    assert_rpc_error_code(error, "plugin.rpc.unsupported_version");

    let error = parse_initialize_result(&serde_json::json!({"ok": true}))
        .expect_err("缺失 selected_schema_version 必须被拒绝");
    assert_rpc_error_code(error, "plugin.rpc.invalid_response");
}

#[test]
fn generic_response_does_not_validate_initialize_payload_without_correlation() {
    let message = RpcMessage::from_json_value(serde_json::json!({
        "jsonrpc": "2.0",
        "schema_version": {"major": 1, "minor": 1},
        "id": "request-0001",
        "result": {
            "selected_schema_version": {"major": 1, "minor": 2}
        }
    }))
    .expect("generic response 只校验 envelope");

    let result = message
        .response()
        .expect("response")
        .result()
        .expect("success result");
    assert_eq!(
        parse_initialize_result(result)
            .expect_err("关联为 initialize 后才验证 selected version")
            .code(),
        "plugin.rpc.unsupported_version"
    );
}

#[test]
fn public_constructors_build_supported_messages_and_reject_unsupported_versions() {
    let request = RpcMessage::new_request(
        SchemaVersion::new(1, 1),
        RequestId::parse("request_0002").expect("ID 合法"),
        PluginMethod::Describe,
        serde_json::json!({}),
    )
    .expect("Host 可安全构造 request");
    assert_eq!(
        decode_frame(&encode_frame(&request).expect("可编码"))
            .expect("可解码")
            .request()
            .expect("request")
            .id()
            .as_str(),
        "request_0002"
    );

    let success = RpcMessage::new_success_response(
        SchemaVersion::new(1, 1),
        RequestId::parse("request_0005").expect("ID 合法"),
        serde_json::json!({"name": "calendar"}),
    )
    .expect("Host 可安全构造 success response");
    let decoded_success = decode_frame(&encode_frame(&success).expect("可编码")).expect("可解码");
    assert_eq!(
        decoded_success
            .response()
            .expect("response")
            .result()
            .expect("success result"),
        &serde_json::json!({"name": "calendar"})
    );

    let response = RpcMessage::new_error_response(
        SchemaVersion::new(1, 1),
        RequestId::parse("request_0003").expect("ID 合法"),
        RpcErrorObject::new(
            "plugin.failed",
            "failed",
            Some(serde_json::json!({"retry": false})),
        ),
    )
    .expect("Host 可安全构造 error response");
    let decoded_response = decode_frame(&encode_frame(&response).expect("可编码")).expect("可解码");
    let error = decoded_response
        .response()
        .expect("response")
        .result()
        .expect_err("error response");
    assert_eq!(error.code, "plugin.failed");
    assert_eq!(error.data, Some(serde_json::json!({"retry": false})));

    assert_eq!(
        RpcMessage::new_request(
            SchemaVersion::new(1, 2),
            RequestId::parse("request_0004").expect("ID 合法"),
            PluginMethod::Describe,
            serde_json::json!({}),
        )
        .expect_err("Host 构造时也必须拒绝 unsupported version")
        .code(),
        "plugin.rpc.unsupported_version"
    );
}

#[test]
fn rpc_error_object_preserves_untrusted_payload_but_parser_errors_are_sanitized() {
    let message = RpcMessage::from_json_value(serde_json::json!({
        "jsonrpc": "2.0",
        "schema_version": {"major": 1, "minor": 1},
        "id": "request-0001",
        "error": {
            "code": "plugin.failed",
            "message": "secret /Users/example/Vault-token",
            "data": {"path": "/Users/example/Vault-token"}
        }
    }))
    .expect("error response envelope 合法");
    let error = message
        .response()
        .expect("response")
        .result()
        .expect_err("error response");
    assert!(error.message.contains("Vault-token"));

    let parser_error = RpcMessage::from_json_value(serde_json::json!({
        "jsonrpc": "2.0",
        "schema_version": {"major": 1, "minor": 1},
        "id": "request-0001",
        "error": {
            "code": "secret /Users/example/Vault-token"
        }
    }))
    .expect_err("非法 error object 必须变成本地解析错误");
    assert_rpc_error_code(parser_error, "plugin.rpc.invalid_response");
    assert!(!parser_error.to_string().contains("Vault-token"));
    assert!(!format!("{parser_error:?}").contains("Vault-token"));
}

#[test]
fn rpc_error_text_does_not_echo_untrusted_input() {
    let request = request_json(
        "secret-/Users/example/Vault-token",
        serde_json::json!({"major": 1, "minor": 1}),
    );
    let error = RpcMessage::from_json_value(request).expect_err("未知 method 必须被拒绝");
    assert_eq!(error.code(), "plugin.rpc.unknown_method");
    assert!(!error.to_string().contains("Vault-token"));
    assert!(!format!("{error:?}").contains("Vault-token"));
}
