mod support {
    pub mod mock_github;
}

use std::collections::BTreeMap;
use std::io::Write;
use std::time::{Duration, Instant};

use envsync_backend::gist::{GistBackend, GistCredentials, GistId};
use envsync_backend::gist_bundle::{
    gist_bundle_filename, inspect as gist_inspect, pack, GistBundleObject, GistBundleSigner,
    MAX_ENCODED_BUNDLE_LEN,
};
use envsync_crypto::device::DeviceKeypair;
use envsync_crypto::sealed::SecretId;
use envsync_crypto::suite::{DataKey, KeyEpoch, Plaintext};
use envsync_domain::{CborCodec, ObjectId, SnapshotBody, StateRoot, WorkspaceId, WorkspaceRef};
use serde_json::{json, Value};
use support::mock_github::{MockGithub, ResponseSpec};
use tempfile::NamedTempFile;

fn sealed_bundles() -> (WorkspaceId, String, String) {
    let (workspace, bundle_v1, bundle_v2, _) = sealed_bundle_versions();
    (workspace, bundle_v1, bundle_v2)
}

fn sealed_bundle_versions() -> (WorkspaceId, String, String, String) {
    let workspace = WorkspaceId::generate();
    let data_key = DataKey::generate().expect("生成测试数据密钥");
    let device = DeviceKeypair::generate().expect("生成测试设备密钥");
    let signer = GistBundleSigner::from_m2(Some(&data_key), Some(KeyEpoch::INITIAL), Some(&device))
        .expect("构造测试签名器");

    let bundle_v1 = sealed_bundle(
        workspace,
        WorkspaceRef::initial(workspace),
        &signer,
        &device,
    );
    let reference_v1 = WorkspaceRef::initial(workspace).advance(snapshot_id(workspace, &device, 1));
    let bundle_v2 = sealed_bundle(workspace, reference_v1, &signer, &device);
    let reference_v2 = WorkspaceRef::initial(workspace)
        .advance(snapshot_id(workspace, &device, 1))
        .advance(snapshot_id(workspace, &device, 2));
    let bundle_v3 = sealed_bundle(workspace, reference_v2, &signer, &device);

    (workspace, bundle_v1, bundle_v2, bundle_v3)
}

fn sealed_bundle_same_ref_ciphertext_variants() -> (WorkspaceId, String, String, String) {
    let workspace = WorkspaceId::generate();
    let data_key = DataKey::generate().expect("生成测试数据密钥");
    let device = DeviceKeypair::generate().expect("生成测试设备密钥");
    let signer = GistBundleSigner::from_m2(Some(&data_key), Some(KeyEpoch::INITIAL), Some(&device))
        .expect("构造测试签名器");

    let bundle_v1 = sealed_bundle(
        workspace,
        WorkspaceRef::initial(workspace),
        &signer,
        &device,
    );
    let reference_v1 = WorkspaceRef::initial(workspace).advance(snapshot_id(workspace, &device, 1));
    let candidate = sealed_bundle(workspace, reference_v1.clone(), &signer, &device);
    let same_ref_different_ciphertext = sealed_bundle(workspace, reference_v1, &signer, &device);

    (
        workspace,
        bundle_v1,
        candidate,
        same_ref_different_ciphertext,
    )
}

fn sealed_bundle(
    workspace: WorkspaceId,
    previous: WorkspaceRef,
    signer: &GistBundleSigner<'_>,
    device: &DeviceKeypair,
) -> String {
    let state = StateRoot::empty();
    let snapshot = SnapshotBody::new(
        workspace,
        Vec::new(),
        state.id(),
        device.device_id(),
        previous.revision,
        BTreeMap::new(),
    )
    .expect("构造测试快照");
    let reference = previous.advance(snapshot.id());
    let objects = vec![
        GistBundleObject::new(ObjectId::from(snapshot.id()), snapshot.to_canonical_vec()),
        GistBundleObject::new(ObjectId::from(state.id()), state.to_canonical_vec()),
    ];
    pack(&reference, objects, signer).expect("生成密封 bundle")
}

fn snapshot_id(
    workspace: WorkspaceId,
    device: &DeviceKeypair,
    revision: u64,
) -> envsync_domain::SnapshotId {
    let state = StateRoot::empty();
    SnapshotBody::new(
        workspace,
        Vec::new(),
        state.id(),
        device.device_id(),
        revision,
        BTreeMap::new(),
    )
    .expect("构造测试快照")
    .id()
}

fn credentials() -> GistCredentials {
    let secret_id = SecretId::parse("test/gist-token").expect("合法 SecretId");
    GistCredentials::from_vault(secret_id, Plaintext::from_slice(b"test-token"))
        .expect("构造 Gist 凭据")
}

fn gist_response(gist_id: &str, filename: &str, encoded: &str) -> String {
    json!({
        "id": gist_id,
        "files": {
            filename: {
                "truncated": false,
                "content": encoded,
            }
        }
    })
    .to_string()
}

fn truncated_gist_response(gist_id: &str, filename: &str, raw_url: &str, encoded: &str) -> String {
    json!({
        "id": gist_id,
        "files": {
            filename: {
                "truncated": true,
                "raw_url": raw_url,
                "content": encoded,
            }
        }
    })
    .to_string()
}

fn gist_id() -> GistId {
    GistId::parse("gist-123").expect("合法 Gist ID")
}

fn assert_safe_error(
    error: &envsync_backend::gist::GistError,
    expected_code: &'static str,
    forbidden: &str,
) {
    assert_eq!(error.code(), expected_code);
    assert!(
        !error.to_string().contains(forbidden),
        "错误 Display 不得回显受控内容"
    );
    assert!(
        !format!("{error:?}").contains(forbidden),
        "错误 Debug 不得回显受控内容"
    );
}

fn assert_error_does_not_leak(error: &envsync_backend::gist::GistError, forbidden: &str) {
    assert!(
        !error.to_string().contains(forbidden),
        "错误 Display 不得回显敏感内容"
    );
    assert!(
        !format!("{error:?}").contains(forbidden),
        "错误 Debug 不得回显敏感内容"
    );
}

fn request_json(request: &support::mock_github::RequestRecord) -> Value {
    serde_json::from_slice(&request.body).expect("请求必须是 JSON")
}

fn assert_cas_requests(
    requests: &[support::mock_github::RequestRecord],
    expected_etag: &str,
    filename: &str,
    candidate: &str,
) {
    assert_eq!(
        requests.len(),
        3,
        "CAS 分支必须恰好发送 GET、PATCH、GET 三个请求"
    );
    assert!(
        requests
            .iter()
            .map(|request| (request.method.as_str(), request.path.as_str()))
            .eq([
                ("GET", "/gists/gist-123"),
                ("PATCH", "/gists/gist-123"),
                ("GET", "/gists/gist-123"),
            ]),
        "CAS 分支必须按 GET、PATCH、GET 顺序请求"
    );
    assert_cas_patch_and_verify_requests(&requests[1..], expected_etag, filename, candidate);
}

fn assert_cas_patch_and_verify_requests(
    requests: &[support::mock_github::RequestRecord],
    expected_etag: &str,
    filename: &str,
    candidate: &str,
) {
    assert_eq!(
        requests.len(),
        2,
        "连续 CAS 的后续轮次必须恰好发送 PATCH、GET 两个请求"
    );
    assert!(
        requests
            .iter()
            .map(|request| (request.method.as_str(), request.path.as_str()))
            .eq([("PATCH", "/gists/gist-123"), ("GET", "/gists/gist-123")]),
        "连续 CAS 的后续轮次必须按 PATCH、GET 顺序请求"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "PATCH")
            .count(),
        1,
        "每个 CAS 分支都只能 PATCH 一次，绝不能盲重发"
    );
    let patch = &requests[0];
    assert_eq!(patch.header("if-match"), Some(expected_etag));
    let body = request_json(patch);
    assert_eq!(body.get("public"), None, "PATCH body 不得改变 Gist 可见性");
    let files = body["files"]
        .as_object()
        .expect("PATCH 必须包含 files 对象");
    assert_eq!(files.len(), 1, "PATCH body 必须只包含一个文件");
    assert_eq!(
        files[filename]["content"].as_str(),
        Some(candidate),
        "PATCH 必须发布候选 bundle 的完整 bytes"
    );
}

fn read_for_cas(
    backend: &GistBackend,
    credentials: &GistCredentials,
    workspace: WorkspaceId,
) -> envsync_backend::gist::GistBundleRecord {
    backend
        .read(credentials, &gist_id(), workspace)
        .expect("读取初始 bundle")
}

#[test]
fn read_maps_auth_forbidden_and_not_found_to_safe_codes() {
    for (status, expected_code) in [
        (401, "gist.authentication"),
        (403, "gist.forbidden"),
        (404, "gist.not_found"),
    ] {
        let mock = MockGithub::start().expect("启动 GitHub mock");
        let sentinel = "error-body-must-not-appear";
        mock.enqueue(ResponseSpec::new(status).body(sentinel));
        let backend = GistBackend::with_api_base(mock.base_url(), Duration::from_millis(100))
            .expect("构造 Gist 后端");

        let error = backend
            .read(&credentials(), &gist_id(), WorkspaceId::generate())
            .expect_err("认证与状态错误必须被读取操作返回");

        assert_safe_error(&error, expected_code, sentinel);
    }
}

#[test]
fn read_rejects_missing_etag_before_returning_unusable_revision() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let (workspace, bundle, _) = sealed_bundles();
    let filename = gist_bundle_filename(workspace);
    mock.enqueue(ResponseSpec::new(200).body(gist_response("gist-123", &filename, &bundle)));
    let backend = GistBackend::with_api_base(mock.base_url(), Duration::from_millis(100))
        .expect("构造 Gist 后端");

    let error = backend
        .read(&credentials(), &gist_id(), workspace)
        .expect_err("缺少 ETag 的读取不得返回 revision");

    assert_safe_error(&error, "gist.missing_etag", &bundle);
}

#[test]
fn read_timeout_is_reported_without_echoing_endpoint() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let endpoint = mock.base_url();
    let (workspace, bundle, _) = sealed_bundles();
    let filename = gist_bundle_filename(workspace);
    mock.enqueue(
        ResponseSpec::new(200)
            .body(gist_response("gist-123", &filename, &bundle))
            .delay(Duration::from_millis(200)),
    );
    let backend =
        GistBackend::with_api_base(&endpoint, Duration::from_millis(25)).expect("构造 Gist 后端");

    let error = backend
        .read(&credentials(), &gist_id(), workspace)
        .expect_err("超过超时的读取必须失败");

    assert_safe_error(&error, "gist.timeout", &endpoint);
}

#[test]
fn read_rejects_oversized_response_before_json_parsing() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let workspace = WorkspaceId::generate();
    let sentinel = "oversized-body-must-not-appear";
    mock.enqueue(
        ResponseSpec::new(200)
            .body(sentinel)
            .declared_content_length(MAX_ENCODED_BUNDLE_LEN + 128 * 1024 + 1)
            .delay_after_headers(Duration::from_millis(200)),
    );
    let backend = GistBackend::with_api_base(mock.base_url(), Duration::from_secs(1))
        .expect("构造 Gist 后端");

    let error = backend
        .read(&credentials(), &gist_id(), workspace)
        .expect_err("超出接收上限的响应必须被拒绝");

    assert_safe_error(&error, "gist.response_too_large", sentinel);
}

#[test]
fn truncated_gist_file_uses_allowed_uncredentialed_raw_url() {
    let mock = match MockGithub::start() {
        Ok(mock) => mock,
        Err(_) => panic!("启动 GitHub mock 失败"),
    };
    let (workspace, bundle_v1, bundle_v2) = sealed_bundles();
    let filename = gist_bundle_filename(workspace);
    let raw_path = format!("/raw/gist-123/{filename}");
    let raw_url = format!("{}{raw_path}", mock.base_url());
    let mut raw_file = match NamedTempFile::new() {
        Ok(file) => file,
        Err(_) => panic!("创建临时 raw bundle 文件失败"),
    };
    match raw_file.write_all(bundle_v2.as_bytes()) {
        Ok(()) => {}
        Err(_) => panic!("写入临时 raw bundle 文件失败"),
    }
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v1\"")
            .body(truncated_gist_response(
                "gist-123", &filename, &raw_url, &bundle_v1,
            )),
    );
    mock.enqueue(ResponseSpec::new(200).body_file(raw_file.path()));
    let backend = match GistBackend::with_api_base(mock.base_url(), Duration::from_millis(100)) {
        Ok(backend) => backend,
        Err(_) => panic!("构造 Gist 后端失败"),
    };

    let record = match backend.read(&credentials(), &gist_id(), workspace) {
        Ok(record) => record,
        Err(_) => panic!("允许的 raw URL 未返回完整 bundle"),
    };
    let expected_header = match gist_inspect(&bundle_v2) {
        Ok(header) => header,
        Err(_) => panic!("读取测试 bundle header 失败"),
    };

    assert!(
        bundle_v1.as_bytes() != bundle_v2.as_bytes(),
        "fixture 必须提供不同版本的 bundle"
    );
    assert!(
        record.encoded().as_bytes() == bundle_v2.as_bytes(),
        "raw 响应必须采用 V2 bundle"
    );
    assert!(
        record.revision().header() == &expected_header,
        "raw 响应必须产生正确的 bundle header"
    );
    let requests = mock.wait_for_requests(2, Duration::from_millis(200));
    assert!(
        requests.len() == 2,
        "截断文件必须恰好发出 API 与 raw 两个请求"
    );
    assert!(
        requests[0].header("authorization") == Some("Bearer test-token"),
        "初始 API 请求必须携带 Authorization"
    );
    assert!(requests[1].method == "GET", "raw 请求必须使用 GET");
    assert!(requests[1].path == raw_path, "raw 请求必须访问预期路径");
    assert!(
        requests[1].header("authorization").is_none(),
        "raw 请求不得携带 Authorization"
    );
}

#[test]
fn truncated_gist_rejects_untrusted_raw_url_without_following_it() {
    let raw_url_suffixes = [
        "http://127.0.0.1:9/other-origin",
        "{base}/raw/gist-123?query=controlled",
        "{base}/raw/gist-123#fragment",
        "http://user@127.0.0.1:9/raw/gist-123",
    ];

    for suffix in raw_url_suffixes {
        let mock = MockGithub::start().expect("启动 GitHub mock");
        let (workspace, bundle, _) = sealed_bundles();
        let filename = gist_bundle_filename(workspace);
        let raw_url = suffix.replace("{base}", &mock.base_url());
        mock.enqueue(ResponseSpec::new(200).header("etag", "\"v1\"").body(
            truncated_gist_response("gist-123", &filename, &raw_url, &bundle),
        ));
        let backend = GistBackend::with_api_base(mock.base_url(), Duration::from_millis(100))
            .expect("构造 Gist 后端");

        let error = backend
            .read(&credentials(), &gist_id(), workspace)
            .expect_err("不受信 raw URL 必须被拒绝");

        assert_safe_error(&error, "gist.invalid_raw_url", &raw_url);
        let requests = mock.wait_for_requests(1, Duration::from_millis(100));
        assert!(requests.len() == 1, "不受信 raw URL 不得触发第二个请求");
    }
}

#[test]
fn loopback_api_rejects_public_github_raw_url_without_following_it() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let (workspace, bundle, _) = sealed_bundles();
    let filename = gist_bundle_filename(workspace);
    let raw_url = format!("https://gist.githubusercontent.com/owner/gist-123/raw/{filename}");
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v1\"")
            .body(truncated_gist_response(
                "gist-123", &filename, &raw_url, &bundle,
            )),
    );
    let backend = GistBackend::with_api_base(mock.base_url(), Duration::from_millis(100))
        .expect("构造 loopback Gist 后端");

    let error = backend
        .read(&credentials(), &gist_id(), workspace)
        .expect_err("非默认 API base 不得接受公共 GitHub raw URL");

    assert_safe_error(&error, "gist.invalid_raw_url", &raw_url);
    let requests = mock.wait_for_requests(1, Duration::from_millis(100));
    assert_eq!(requests.len(), 1, "不受信 raw URL 不得触发第二个请求");
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].path, "/gists/gist-123");
}

#[test]
fn read_transport_failure_is_safe() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let endpoint = mock.base_url();
    mock.enqueue(ResponseSpec::new(200).disconnect());
    let backend =
        GistBackend::with_api_base(&endpoint, Duration::from_millis(100)).expect("构造 Gist 后端");

    let error = backend
        .read(&credentials(), &gist_id(), WorkspaceId::generate())
        .expect_err("连接断开必须作为传输错误返回");

    assert_eq!(error.code(), "gist.transport");
    assert!(
        !error.to_string().contains("test-token"),
        "传输错误 Display 不得回显 token"
    );
    assert!(
        !format!("{error:?}").contains("test-token"),
        "传输错误 Debug 不得回显 token"
    );
    assert!(
        !error.to_string().contains(&endpoint),
        "传输错误 Display 不得回显 endpoint"
    );
    assert!(
        !format!("{error:?}").contains(&endpoint),
        "传输错误 Debug 不得回显 endpoint"
    );
}

#[test]
fn create_sends_one_secret_post_without_implicit_read() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let (workspace, bundle, _) = sealed_bundles();
    let filename = gist_bundle_filename(workspace);
    mock.enqueue(ResponseSpec::new(201).body(json!({ "id": "gist-123" }).to_string()));
    let backend = GistBackend::with_api_base(mock.base_url(), Duration::from_millis(100))
        .expect("构造 Gist 后端");

    let created = backend
        .create(&credentials(), &bundle)
        .expect("创建 Gist 必须成功");

    assert_eq!(created.revision().gist_id().as_str(), "gist-123");
    let requests = mock.wait_for_requests(1, Duration::from_millis(200));
    assert_eq!(requests.len(), 1, "create 不得隐式读取 Gist");
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/gists");
    assert_eq!(
        request.header("accept"),
        Some("application/vnd.github+json")
    );
    assert_eq!(request.header("x-github-api-version"), Some("2022-11-28"));
    assert_eq!(request.header("user-agent"), Some("envsync"));
    assert_eq!(request.header("authorization"), Some("Bearer test-token"));

    let body = request_json(request);
    assert_eq!(body.get("public"), Some(&Value::Bool(false)));
    let files = body
        .get("files")
        .and_then(Value::as_object)
        .expect("创建请求必须包含文件对象");
    assert_eq!(files.len(), 1, "创建请求必须仅包含一个文件");
    assert_eq!(
        files
            .get(&filename)
            .and_then(Value::as_object)
            .and_then(|file| file.get("content"))
            .and_then(Value::as_str),
        Some(bundle.as_str())
    );
}

#[test]
fn create_then_read_then_publish_sends_expected_contract() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let (workspace, bundle_v1, bundle_v2) = sealed_bundles();
    let filename = gist_bundle_filename(workspace);
    mock.enqueue(ResponseSpec::new(201).body(json!({ "id": "gist-123" }).to_string()));
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v1\"")
            .body(gist_response("gist-123", &filename, &bundle_v1)),
    );
    mock.enqueue(ResponseSpec::new(200).body(json!({ "id": "gist-123" }).to_string()));
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v2\"")
            .body(gist_response("gist-123", &filename, &bundle_v2)),
    );

    let backend = GistBackend::with_api_base(mock.base_url(), Duration::from_millis(100))
        .expect("构造 Gist 后端");
    let credentials = credentials();
    let created = backend.create(&credentials, &bundle_v1).expect("创建 Gist");
    let read = backend
        .read(&credentials, created.revision().gist_id(), workspace)
        .expect("读取 Gist");
    let published = backend
        .compare_and_swap(&credentials, read.revision(), &bundle_v2)
        .expect("发布新版 bundle");
    let expected_head = gist_inspect(&bundle_v2)
        .expect("读取 revision 2 的 bundle 元数据")
        .head;

    assert!(
        published.revision().header().head == expected_head,
        "发布结果必须匹配 revision 2 的 head"
    );
    assert!(
        published.revision().header().workspace == workspace,
        "发布结果必须保留工作区标识"
    );
    assert!(
        published.revision().header().revision == 2,
        "发布结果必须为 revision 2"
    );

    let requests = mock.wait_for_requests(4, Duration::from_millis(200));
    assert_eq!(requests.len(), 4, "必须只发送四个 HTTP 请求");
    assert!(
        requests
            .iter()
            .map(|request| (request.method.as_str(), request.path.as_str()))
            .eq([
                ("POST", "/gists"),
                ("GET", "/gists/gist-123"),
                ("PATCH", "/gists/gist-123"),
                ("GET", "/gists/gist-123"),
            ]),
        "HTTP 请求必须按 POST、GET、PATCH、GET 顺序发送"
    );
    for request in &requests {
        assert!(
            request.header("authorization") == Some("Bearer test-token"),
            "每个 HTTP 请求都必须携带预期的 Authorization header"
        );
    }

    let create = request_json(&requests[0]);
    assert!(
        create.get("public") == Some(&Value::Bool(false)),
        "创建请求必须创建 secret（public:false）Gist"
    );
    assert!(
        create
            .get("files")
            .and_then(Value::as_object)
            .is_some_and(|files| files.len() == 1 && files.contains_key(&filename)),
        "创建请求必须仅包含预期文件名的一个文件"
    );
    assert!(
        create["files"][&filename]["content"]
            .as_str()
            .is_some_and(|content| content.as_bytes() == bundle_v1.as_bytes()),
        "创建请求必须携带 revision 1 的 bundle"
    );
    let patch = request_json(&requests[2]);
    assert!(
        patch["files"][&filename]["content"]
            .as_str()
            .is_some_and(|content| content.as_bytes() == bundle_v2.as_bytes()),
        "更新请求必须携带 revision 2 的 bundle"
    );
    assert!(
        requests[2].header("if-match") == Some("\"v1\""),
        "PATCH 请求必须携带初始 ETag"
    );
}

#[test]
fn descriptor_explicitly_reports_weak_cas() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let backend = GistBackend::with_api_base(mock.base_url(), Duration::from_millis(100))
        .expect("构造 Gist 后端");

    let descriptor = backend.descriptor();
    assert!(descriptor.kind == "gist", "descriptor 必须标识 gist 后端");
    assert!(!descriptor.supports_strong_cas);
}

#[test]
fn old_verify_read_after_patch_is_a_cas_conflict_without_patch_retry() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let (workspace, bundle_v1, bundle_v2) = sealed_bundles();
    let filename = gist_bundle_filename(workspace);
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v1\"")
            .body(gist_response("gist-123", &filename, &bundle_v1)),
    );
    mock.enqueue(ResponseSpec::new(200).body(json!({ "id": "gist-123" }).to_string()));
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v1\"")
            .body(gist_response("gist-123", &filename, &bundle_v1)),
    );

    let backend = GistBackend::with_api_base(mock.base_url(), Duration::from_millis(100))
        .expect("构造 Gist 后端");
    let credentials = credentials();
    let read = backend
        .read(
            &credentials,
            &envsync_backend::gist::GistId::parse("gist-123").expect("合法 Gist ID"),
            workspace,
        )
        .expect("读取初始 bundle");
    let error = match backend.compare_and_swap(&credentials, read.revision(), &bundle_v2) {
        Ok(_) => panic!("验证读取仍为旧 bundle 时必须返回 CAS 冲突"),
        Err(error) => error,
    };

    assert!(
        error.code() == "gist.cas_conflict",
        "验证读取仍为旧 bundle 时必须返回 gist.cas_conflict"
    );
    let requests = mock.wait_for_requests(3, Duration::from_millis(200));
    assert!(requests.len() == 3, "CAS 冲突路径必须恰好发送三个请求");
    assert!(
        requests
            .iter()
            .map(|request| (request.method.as_str(), request.path.as_str()))
            .eq([
                ("GET", "/gists/gist-123"),
                ("PATCH", "/gists/gist-123"),
                ("GET", "/gists/gist-123"),
            ]),
        "CAS 冲突路径必须按 GET、PATCH、GET 顺序发送请求"
    );
    assert!(
        requests
            .iter()
            .filter(|request| request.method == "PATCH")
            .count()
            == 1,
        "CAS 只能尝试一次 PATCH"
    );
}

#[test]
fn cas_success_verifies_complete_candidate_and_returns_new_etag() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let (workspace, bundle_v1, bundle_v2, bundle_v3) = sealed_bundle_versions();
    let filename = gist_bundle_filename(workspace);
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v1\"")
            .body(gist_response("gist-123", &filename, &bundle_v1)),
    );
    mock.enqueue(ResponseSpec::new(200).body(json!({ "id": "gist-123" }).to_string()));
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v2\"")
            .body(gist_response("gist-123", &filename, &bundle_v2)),
    );
    mock.enqueue(ResponseSpec::new(200).body(json!({ "id": "gist-123" }).to_string()));
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v3\"")
            .body(gist_response("gist-123", &filename, &bundle_v3)),
    );
    let backend = GistBackend::with_api_base(mock.base_url(), Duration::from_millis(100))
        .expect("构造 Gist 后端");
    let credentials = credentials();
    let read = read_for_cas(&backend, &credentials, workspace);

    let published = backend
        .compare_and_swap(&credentials, read.revision(), &bundle_v2)
        .expect("PATCH 成功后必须读取验证，并返回已发布的候选 bundle");
    let published_again = backend
        .compare_and_swap(&credentials, published.revision(), &bundle_v3)
        .expect("成功 CAS 返回的 revision 必须保存验证读取的新 ETag 以支持下一次 CAS");

    assert_eq!(published.encoded().as_bytes(), bundle_v2.as_bytes());
    assert_eq!(published_again.encoded().as_bytes(), bundle_v3.as_bytes());
    let requests = mock.wait_for_requests(5, Duration::from_millis(200));
    assert_eq!(requests.len(), 5, "连续两次 CAS 必须恰好发送五个请求");
    assert_cas_requests(&requests[..3], "\"v1\"", &filename, &bundle_v2);
    assert_cas_patch_and_verify_requests(&requests[3..], "\"v2\"", &filename, &bundle_v3);
}

#[test]
fn cas_412_verifies_candidate_once_and_reports_published() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let (workspace, bundle_v1, bundle_v2) = sealed_bundles();
    let filename = gist_bundle_filename(workspace);
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v1\"")
            .body(gist_response("gist-123", &filename, &bundle_v1)),
    );
    mock.enqueue(ResponseSpec::new(412).body("cas-412-sentinel"));
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v2\"")
            .body(gist_response("gist-123", &filename, &bundle_v2)),
    );
    let backend = GistBackend::with_api_base(mock.base_url(), Duration::from_millis(100))
        .expect("构造 Gist 后端");
    let credentials = credentials();
    let read = read_for_cas(&backend, &credentials, workspace);

    let published = backend
        .compare_and_swap(&credentials, read.revision(), &bundle_v2)
        .expect("412 后验证读到候选完整 bytes 时必须确认已发布");

    assert_eq!(published.encoded().as_bytes(), bundle_v2.as_bytes());
    let requests = mock.wait_for_requests(3, Duration::from_millis(200));
    assert_cas_requests(&requests, "\"v1\"", &filename, &bundle_v2);
}

#[test]
fn cas_disconnect_verifies_candidate_once_and_reports_published() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let endpoint = mock.base_url();
    let (workspace, bundle_v1, bundle_v2) = sealed_bundles();
    let filename = gist_bundle_filename(workspace);
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v1\"")
            .body(gist_response("gist-123", &filename, &bundle_v1)),
    );
    mock.enqueue(ResponseSpec::new(200).disconnect());
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v2\"")
            .body(gist_response("gist-123", &filename, &bundle_v2)),
    );
    let backend =
        GistBackend::with_api_base(&endpoint, Duration::from_millis(100)).expect("构造 Gist 后端");
    let credentials = credentials();
    let read = read_for_cas(&backend, &credentials, workspace);

    let published = backend
        .compare_and_swap(&credentials, read.revision(), &bundle_v2)
        .expect("断线后验证读到候选完整 bytes 时必须确认已发布");

    assert_eq!(published.encoded().as_bytes(), bundle_v2.as_bytes());
    let requests = mock.wait_for_requests(3, Duration::from_millis(200));
    assert_cas_requests(&requests, "\"v1\"", &filename, &bundle_v2);
}

#[test]
fn cas_412_with_failed_verification_reports_unknown_once() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let (workspace, bundle_v1, bundle_v2) = sealed_bundles();
    let filename = gist_bundle_filename(workspace);
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v1\"")
            .body(gist_response("gist-123", &filename, &bundle_v1)),
    );
    mock.enqueue(ResponseSpec::new(412).body("cas-412-body-sentinel"));
    mock.enqueue(ResponseSpec::new(500).body("verify-412-body-sentinel"));
    let backend = GistBackend::with_api_base(mock.base_url(), Duration::from_millis(100))
        .expect("构造 Gist 后端");
    let credentials = credentials();
    let read = read_for_cas(&backend, &credentials, workspace);

    let error = backend
        .compare_and_swap(&credentials, read.revision(), &bundle_v2)
        .expect_err("412 后验证读取失败必须报告结果未知");

    assert_safe_error(
        &error,
        "gist.update_outcome_unknown",
        "verify-412-body-sentinel",
    );
    let requests = mock.wait_for_requests(3, Duration::from_millis(200));
    assert_cas_requests(&requests, "\"v1\"", &filename, &bundle_v2);
}

#[test]
fn cas_disconnect_with_failed_verification_reports_unknown_once() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let (workspace, bundle_v1, bundle_v2) = sealed_bundles();
    let filename = gist_bundle_filename(workspace);
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v1\"")
            .body(gist_response("gist-123", &filename, &bundle_v1)),
    );
    mock.enqueue(ResponseSpec::new(200).disconnect());
    mock.enqueue(ResponseSpec::new(500).body("verify-disconnect-body-sentinel"));
    let backend = GistBackend::with_api_base(mock.base_url(), Duration::from_millis(100))
        .expect("构造 Gist 后端");
    let credentials = credentials();
    let read = read_for_cas(&backend, &credentials, workspace);

    let error = backend
        .compare_and_swap(&credentials, read.revision(), &bundle_v2)
        .expect_err("断线后验证读取失败必须报告结果未知");

    assert_safe_error(
        &error,
        "gist.update_outcome_unknown",
        "verify-disconnect-body-sentinel",
    );
    let requests = mock.wait_for_requests(3, Duration::from_millis(200));
    assert_cas_requests(&requests, "\"v1\"", &filename, &bundle_v2);
}

#[test]
fn cas_verifies_other_valid_bundle_as_conflict_once() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let (workspace, bundle_v1, bundle_v2, bundle_v3) = sealed_bundle_versions();
    let filename = gist_bundle_filename(workspace);
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v1\"")
            .body(gist_response("gist-123", &filename, &bundle_v1)),
    );
    mock.enqueue(ResponseSpec::new(200).body(json!({ "id": "gist-123" }).to_string()));
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v2\"")
            .body(gist_response("gist-123", &filename, &bundle_v3)),
    );
    let backend = GistBackend::with_api_base(mock.base_url(), Duration::from_millis(100))
        .expect("构造 Gist 后端");
    let credentials = credentials();
    let read = read_for_cas(&backend, &credentials, workspace);

    let error = backend
        .compare_and_swap(&credentials, read.revision(), &bundle_v2)
        .expect_err("验证读取其他有效 bundle 时必须报告 CAS 冲突");

    assert_ne!(bundle_v3.as_bytes(), bundle_v1.as_bytes());
    assert_ne!(bundle_v3.as_bytes(), bundle_v2.as_bytes());
    assert_safe_error(&error, "gist.cas_conflict", &bundle_v3);
    let requests = mock.wait_for_requests(3, Duration::from_millis(200));
    assert_cas_requests(&requests, "\"v1\"", &filename, &bundle_v2);
}

#[test]
fn cas_verifies_same_ref_different_ciphertext_as_conflict_once() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let (workspace, bundle_v1, candidate, same_ref_different_ciphertext) =
        sealed_bundle_same_ref_ciphertext_variants();
    let filename = gist_bundle_filename(workspace);
    let candidate_header = gist_inspect(&candidate).expect("候选 bundle 必须可由生产路径检查");
    let observed_header = gist_inspect(&same_ref_different_ciphertext)
        .expect("验证读取的 bundle 必须可由生产路径检查");
    assert_ne!(
        candidate.as_bytes(),
        same_ref_different_ciphertext.as_bytes(),
        "同一 ref 的两次真实密封必须产生不同 ciphertext bytes"
    );
    assert_eq!(candidate_header.workspace, observed_header.workspace);
    assert_eq!(candidate_header.revision, observed_header.revision);
    assert_eq!(candidate_header.head, observed_header.head);

    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v1\"")
            .body(gist_response("gist-123", &filename, &bundle_v1)),
    );
    mock.enqueue(ResponseSpec::new(200).body(json!({ "id": "gist-123" }).to_string()));
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v2\"")
            .body(gist_response(
                "gist-123",
                &filename,
                &same_ref_different_ciphertext,
            )),
    );
    let backend = GistBackend::with_api_base(mock.base_url(), Duration::from_millis(100))
        .expect("构造 Gist 后端");
    let credentials = credentials();
    let read = read_for_cas(&backend, &credentials, workspace);

    let error = backend
        .compare_and_swap(&credentials, read.revision(), &candidate)
        .expect_err("验证读取同 ref 但不同 bytes 的合法 bundle 时必须报告 CAS 冲突");

    assert_safe_error(&error, "gist.cas_conflict", &same_ref_different_ciphertext);
    let requests = mock.wait_for_requests(3, Duration::from_millis(200));
    assert_cas_requests(&requests, "\"v1\"", &filename, &candidate);
}

#[test]
fn cas_5xx_verifies_old_bundle_once_and_reports_conflict_without_leaks() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let endpoint = mock.base_url();
    let sentinel = "patch-5xx-conflict-body-sentinel";
    let (workspace, bundle_v1, bundle_v2) = sealed_bundles();
    let filename = gist_bundle_filename(workspace);
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v1\"")
            .body(gist_response("gist-123", &filename, &bundle_v1)),
    );
    mock.enqueue(ResponseSpec::new(503).body(sentinel));
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v1\"")
            .body(gist_response("gist-123", &filename, &bundle_v1)),
    );
    let backend =
        GistBackend::with_api_base(&endpoint, Duration::from_millis(100)).expect("构造 Gist 后端");
    let credentials = credentials();
    let read = read_for_cas(&backend, &credentials, workspace);

    let error = backend
        .compare_and_swap(&credentials, read.revision(), &bundle_v2)
        .expect_err("5xx 后验证仍为旧 bundle 必须报告 CAS 冲突");

    assert_safe_error(&error, "gist.cas_conflict", sentinel);
    assert_error_does_not_leak(&error, &endpoint);
    assert_error_does_not_leak(&error, "test-token");
    let requests = mock.wait_for_requests(3, Duration::from_millis(200));
    assert_cas_requests(&requests, "\"v1\"", &filename, &bundle_v2);
}

#[test]
fn cas_5xx_with_failed_verification_reports_unknown_once_without_leaks() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let endpoint = mock.base_url();
    let sentinel = "unknown-outcome-body-sentinel";
    let (workspace, bundle_v1, bundle_v2) = sealed_bundles();
    let filename = gist_bundle_filename(workspace);
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v1\"")
            .body(gist_response("gist-123", &filename, &bundle_v1)),
    );
    mock.enqueue(ResponseSpec::new(503).body(sentinel));
    mock.enqueue(ResponseSpec::new(500).body(sentinel));
    let backend =
        GistBackend::with_api_base(&endpoint, Duration::from_secs(1)).expect("构造 Gist 后端");
    let credentials = credentials();
    let read = read_for_cas(&backend, &credentials, workspace);

    let error = backend
        .compare_and_swap(&credentials, read.revision(), &bundle_v2)
        .expect_err("5xx 后验证失败必须报告结果未知");

    assert_safe_error(&error, "gist.update_outcome_unknown", sentinel);
    assert!(!error.to_string().contains(&endpoint));
    assert!(!format!("{error:?}").contains(&endpoint));
    assert_error_does_not_leak(&error, "test-token");
    let requests = mock.wait_for_requests(3, Duration::from_millis(200));
    assert_cas_requests(&requests, "\"v1\"", &filename, &bundle_v2);
}

#[test]
fn read_retries_once_after_zero_retry_after_without_real_wait() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let (workspace, bundle, _) = sealed_bundles();
    let filename = gist_bundle_filename(workspace);
    mock.enqueue(
        ResponseSpec::new(429)
            .header("retry-after", "0")
            .body("get-rate-limit-body-sentinel"),
    );
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v1\"")
            .body(gist_response("gist-123", &filename, &bundle)),
    );
    let backend = GistBackend::with_api_base(mock.base_url(), Duration::from_millis(100))
        .expect("构造 Gist 后端");

    let started_at = Instant::now();
    let record = backend
        .read(&credentials(), &gist_id(), workspace)
        .expect("Retry-After: 0 后必须立即重试一次读取");
    let elapsed = started_at.elapsed();

    assert_eq!(record.encoded().as_bytes(), bundle.as_bytes());
    assert!(
        elapsed < Duration::from_millis(75),
        "Retry-After: 0 不得触发固定真实退避；实际耗时：{elapsed:?}"
    );
    let requests = mock.wait_for_requests(2, Duration::from_millis(200));
    assert_eq!(requests.len(), 2, "GET 429 只允许额外重试一次");
    assert!(requests.iter().all(|request| request.method == "GET"));
}

#[test]
fn create_429_is_rate_limited_and_never_replays_post() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let endpoint = mock.base_url();
    let (_, bundle, _) = sealed_bundles();
    let sentinel = "post-rate-limit-body-sentinel";
    mock.enqueue(ResponseSpec::new(429).body(sentinel));
    let backend =
        GistBackend::with_api_base(&endpoint, Duration::from_millis(100)).expect("构造 Gist 后端");

    let error = backend
        .create(&credentials(), &bundle)
        .expect_err("POST 429 必须返回限流错误");

    assert_safe_error(&error, "gist.rate_limited", sentinel);
    assert_error_does_not_leak(&error, &endpoint);
    assert_error_does_not_leak(&error, "test-token");
    let requests = mock.wait_for_requests(1, Duration::from_millis(200));
    assert_eq!(requests.len(), 1, "POST 限流不得重放写请求");
    assert_eq!(requests[0].method, "POST");
}

#[test]
fn cas_patch_429_is_rate_limited_and_never_replays_patch() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let endpoint = mock.base_url();
    let (workspace, bundle_v1, bundle_v2) = sealed_bundles();
    let filename = gist_bundle_filename(workspace);
    let sentinel = "patch-rate-limit-body-sentinel";
    mock.enqueue(
        ResponseSpec::new(200)
            .header("etag", "\"v1\"")
            .body(gist_response("gist-123", &filename, &bundle_v1)),
    );
    mock.enqueue(ResponseSpec::new(429).body(sentinel));
    let backend =
        GistBackend::with_api_base(&endpoint, Duration::from_millis(100)).expect("构造 Gist 后端");
    let credentials = credentials();
    let read = read_for_cas(&backend, &credentials, workspace);

    let error = backend
        .compare_and_swap(&credentials, read.revision(), &bundle_v2)
        .expect_err("PATCH 429 必须返回限流错误");

    assert_safe_error(&error, "gist.rate_limited", sentinel);
    assert_error_does_not_leak(&error, &endpoint);
    assert_error_does_not_leak(&error, "test-token");
    let requests = mock.wait_for_requests(2, Duration::from_millis(200));
    assert_eq!(requests.len(), 2, "PATCH 限流不得重放写请求");
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[1].method, "PATCH");
}
