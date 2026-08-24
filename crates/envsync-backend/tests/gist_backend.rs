mod support {
    pub mod mock_github;
}

use std::collections::BTreeMap;
use std::time::Duration;

use envsync_backend::gist::{GistBackend, GistCredentials};
use envsync_backend::gist_bundle::{
    gist_bundle_filename, pack, GistBundleObject, GistBundleSigner,
};
use envsync_crypto::device::DeviceKeypair;
use envsync_crypto::sealed::SecretId;
use envsync_crypto::suite::{DataKey, KeyEpoch, Plaintext};
use envsync_domain::{ObjectId, SnapshotBody, StateRoot, WorkspaceId, WorkspaceRef};
use serde_json::{json, Value};
use support::mock_github::{MockGithub, ResponseSpec};

fn sealed_bundles() -> (WorkspaceId, String, String) {
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

    (workspace, bundle_v1, bundle_v2)
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

fn request_json(request: &support::mock_github::RequestRecord) -> Value {
    serde_json::from_slice(&request.body).expect("请求必须是 JSON")
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

    assert!(
        published.encoded().as_bytes() == bundle_v2.as_bytes(),
        "最终 bundle bytes 必须匹配"
    );
    assert_eq!(published.revision().header().workspace, workspace);
    assert_eq!(published.revision().header().revision, 2);

    let requests = mock.wait_for_requests(4, Duration::from_millis(200));
    assert_eq!(requests.len(), 4, "必须只发送四个 HTTP 请求");
    assert_eq!(
        requests
            .iter()
            .map(|request| (request.method.as_str(), request.path.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("POST", "/gists"),
            ("GET", "/gists/gist-123"),
            ("PATCH", "/gists/gist-123"),
            ("GET", "/gists/gist-123"),
        ]
    );
    for request in &requests {
        assert_eq!(request.header("authorization"), Some("Bearer test-token"));
    }

    let create = request_json(&requests[0]);
    assert_eq!(create["public"], false);
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
    assert_eq!(requests[2].header("if-match"), Some("\"v1\""));
}

#[test]
fn descriptor_explicitly_reports_weak_cas() {
    let mock = MockGithub::start().expect("启动 GitHub mock");
    let backend = GistBackend::with_api_base(mock.base_url(), Duration::from_millis(100))
        .expect("构造 Gist 后端");

    let descriptor = backend.descriptor();
    assert_eq!(descriptor.kind, "gist");
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

    assert_eq!(error.code(), "gist.cas_conflict");
    let requests = mock.wait_for_requests(3, Duration::from_millis(200));
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "PATCH")
            .count(),
        1,
        "CAS 只能尝试一次 PATCH"
    );
}
