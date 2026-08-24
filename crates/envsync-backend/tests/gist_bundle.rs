use std::collections::BTreeMap;

use base64::Engine;
use envsync_backend::gist_bundle::{
    gist_bundle_filename, inspect, inspect_bootstrap, pack, unpack, GistBundleError,
    GistBundleObject, GistBundleSigner, GistBundleVerifier, MAX_ENCODED_BUNDLE_LEN, MAX_OBJECTS,
    MAX_RESOURCES,
};
use envsync_crypto::device::DeviceKeypair;
use envsync_crypto::envelope::seal_envelope;
use envsync_crypto::sealed::{seal, SecretId};
use envsync_crypto::suite::{DataKey, KeyEpoch, Plaintext, MAX_PLAINTEXT_LEN};
use envsync_crypto::vault::{SecretRef, VaultIndex, VAULT_INDEX_METADATA_KEY};
use envsync_domain::cbor::{decode_canonical, encode, CborCodec, Value};
use envsync_domain::{
    BlobId, DesiredDisposition, DevicePublicBytes, FileMode, MembershipAction, MembershipEvent,
    ObjectId, ObjectKind, ResourceEntry, ResourceId, ResourcePolicy, SnapshotBody, StateRoot,
    WorkspaceId, WorkspaceRef, GENESIS_EPOCH, MEMBERSHIP_EVENT_FORMAT_VERSION,
};

fn fixture() -> (WorkspaceRef, DataKey, DeviceKeypair, Vec<GistBundleObject>) {
    let workspace = WorkspaceId::generate();
    let data_key = DataKey::generate().expect("生成 M2 数据密钥");
    let device = DeviceKeypair::generate().expect("生成设备密钥");
    let state = StateRoot::empty();
    let state_bytes = state.to_canonical_vec();
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "fixture-meta".to_owned(),
        "metadata=never-public".to_owned(),
    );
    let snapshot = SnapshotBody::new(
        workspace,
        Vec::new(),
        state.id(),
        device.device_id(),
        0,
        metadata,
    )
    .expect("构造 snapshot");
    let snapshot_bytes = snapshot.to_canonical_vec();
    let head = snapshot.id();
    let reference = WorkspaceRef::initial(workspace).advance(head);
    let resource_bytes =
        b"path=.config/private\nsecret_id=ci/npm-token\nmetadata=never-public\n".to_vec();
    let objects = vec![
        GistBundleObject::new(ObjectId::from(head), snapshot_bytes),
        GistBundleObject::new(ObjectId::from(state.id()), state_bytes),
        GistBundleObject::new(
            ObjectId::for_bytes(ObjectKind::Blob, &resource_bytes),
            resource_bytes,
        ),
    ];
    (reference, data_key, device, objects)
}

#[derive(Clone, Copy)]
struct VaultObjectIds {
    index: ObjectId,
    membership: ObjectId,
    envelope: ObjectId,
    secret: ObjectId,
    recovery: ObjectId,
}

fn vault_fixture() -> (
    WorkspaceRef,
    DataKey,
    DeviceKeypair,
    Vec<GistBundleObject>,
    SecretId,
    VaultObjectIds,
) {
    let workspace = WorkspaceId::generate();
    let data_key = DataKey::generate().expect("生成 M2 数据密钥");
    let device = DeviceKeypair::generate().expect("生成设备密钥");
    let resource_bytes = b"resource-path=.config/gist-private\nresource-value=never-public\n";
    let resource_blob = BlobId::of(resource_bytes);
    let state = StateRoot::from_entries([ResourceEntry {
        resource: ResourceId::parse("fixture/gist-resource").expect("资源 ID 合法"),
        disposition: DesiredDisposition::Managed,
        blob: Some(resource_blob),
        mode: FileMode::FullFile,
        policy: ResourcePolicy::default(),
    }])
    .expect("State Root 合法");

    let public = device.public();
    let mut genesis = MembershipEvent {
        format_version: MEMBERSHIP_EVENT_FORMAT_VERSION,
        workspace,
        sequence: 0,
        previous: None,
        epoch: GENESIS_EPOCH,
        actor: device.device_id(),
        action: MembershipAction::Genesis {
            subject: device.device_id(),
            public: DevicePublicBytes::from_parts(public.x25519, public.ed25519),
        },
        created_at_unix_ms: 0,
        signature: Vec::new(),
    };
    genesis.signature = device
        .sign("membership-event", workspace, &genesis.signing_payload())
        .expect("签发 genesis")
        .as_bytes()
        .to_vec();
    let membership_bytes = genesis.to_canonical_vec();
    let membership = ObjectId::for_bytes(ObjectKind::MembershipEvent, &membership_bytes);

    let envelope =
        seal_envelope(&public, workspace, KeyEpoch::INITIAL, &data_key).expect("生成设备信封");
    let envelope_bytes = envelope.to_canonical_vec();
    let envelope_object = ObjectId::for_bytes(ObjectKind::KeyEnvelope, &envelope_bytes);

    let secret_id = SecretId::parse("ci/gist-token").expect("秘密标识合法");
    let sealed = seal(
        &data_key,
        workspace,
        &secret_id,
        KeyEpoch::INITIAL,
        &Plaintext::from_slice(b"vault-value=never-public"),
    )
    .expect("密封秘密");
    let sealed_bytes = sealed.to_canonical_vec();
    let sealed_object = ObjectId::for_bytes(ObjectKind::SealedSecret, &sealed_bytes);
    let recovery_bytes = b"recovery-package=never-public".to_vec();
    let recovery = ObjectId::for_bytes(ObjectKind::Blob, &recovery_bytes);

    let mut index = VaultIndex::empty(workspace, KeyEpoch::INITIAL.get());
    index.membership.push(membership);
    index.envelopes.push(envelope_object);
    index.upsert(SecretRef {
        id: secret_id.clone(),
        object: sealed_object,
        epoch: KeyEpoch::INITIAL.get(),
        updated_at_unix_ms: 0,
        referenced_by: vec![ResourceId::parse("fixture/gist-resource").expect("资源 ID 合法")],
    });
    index.recovery = Some(recovery);
    let index_bytes = index.to_canonical_vec();
    let index_object = ObjectId::for_bytes(ObjectKind::Blob, &index_bytes);

    let mut metadata = BTreeMap::new();
    metadata.insert(
        VAULT_INDEX_METADATA_KEY.to_owned(),
        index_object.to_string(),
    );
    metadata.insert(
        "fixture-vault-metadata".to_owned(),
        "metadata=never-public".to_owned(),
    );
    let snapshot = SnapshotBody::new(
        workspace,
        Vec::new(),
        state.id(),
        device.device_id(),
        0,
        metadata,
    )
    .expect("构造 snapshot");
    let reference = WorkspaceRef::initial(workspace).advance(snapshot.id());
    let objects = vec![
        GistBundleObject::new(ObjectId::from(snapshot.id()), snapshot.to_canonical_vec()),
        GistBundleObject::new(ObjectId::from(state.id()), state.to_canonical_vec()),
        GistBundleObject::new(ObjectId::from(resource_blob), resource_bytes.to_vec()),
        GistBundleObject::new(index_object, index_bytes),
        GistBundleObject::new(membership, membership_bytes),
        GistBundleObject::new(envelope_object, envelope_bytes),
        GistBundleObject::new(sealed_object, sealed_bytes),
        GistBundleObject::new(recovery, recovery_bytes),
    ];
    (
        reference,
        data_key,
        device,
        objects,
        secret_id,
        VaultObjectIds {
            index: index_object,
            membership,
            envelope: envelope_object,
            secret: sealed_object,
            recovery,
        },
    )
}

fn signer<'a>(key: &'a DataKey, device: &'a DeviceKeypair) -> GistBundleSigner<'a> {
    GistBundleSigner::from_m2(Some(key), Some(KeyEpoch::INITIAL), Some(device))
        .expect("M2 密钥材料完整")
}

fn verifier<'a>(
    workspace: WorkspaceId,
    key: &'a DataKey,
    device: &DeviceKeypair,
) -> GistBundleVerifier<'a> {
    GistBundleVerifier::from_m2(
        Some(workspace),
        Some(key),
        Some(KeyEpoch::INITIAL),
        Some(BTreeMap::from([(device.device_id(), device.public())])),
    )
    .expect("M2 验证材料完整")
}

#[test]
fn pack_uses_a_canonical_unpadded_base64url_envelope_and_sorts_objects() {
    let (reference, key, device, mut objects) = fixture();
    objects.reverse();

    let encoded = pack(&reference, objects, &signer(&key, &device)).expect("打包成功");
    assert!(encoded.len() <= MAX_ENCODED_BUNDLE_LEN);
    assert!(!encoded.contains('='));
    assert!(encoded
        .bytes()
        .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') }));

    let wire = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&encoded)
        .expect("base64url 可解码");
    assert!(decode_canonical(&wire).is_ok(), "外层必须是 canonical CBOR");

    let header = inspect(&encoded).expect("可读取未验证路由 metadata");
    assert_eq!(header.workspace, reference.workspace);
    assert_eq!(header.revision, reference.revision);
    assert_eq!(header.head, reference.head);
    assert_eq!(header.epoch, KeyEpoch::INITIAL);
    assert_eq!(header.signer, device.device_id());
    assert_eq!(header.object_count, 3);

    let unpacked =
        unpack(&encoded, &verifier(reference.workspace, &key, &device)).expect("验签后解包成功");
    assert_eq!(unpacked.reference, reference);
    assert!(unpacked
        .objects
        .windows(2)
        .all(|pair| pair[0].id < pair[1].id));
}

#[test]
fn bundle_wire_never_contains_resource_plaintext_paths_secret_ids_or_metadata() {
    let (reference, key, device, objects) = fixture();
    let encoded = pack(&reference, objects, &signer(&key, &device)).expect("打包成功");
    let wire = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .expect("base64url 可解码");

    for forbidden in [
        b"path=.config/private".as_slice(),
        b"ci/npm-token".as_slice(),
        b"metadata=never-public".as_slice(),
    ] {
        assert!(
            !wire
                .windows(forbidden.len())
                .any(|window| window == forbidden),
            "密封 Gist 文件不能出现明文 fixture"
        );
    }
}

#[test]
fn missing_m2_material_cannot_enable_gist_bundle_operations() {
    let (_, key, device, _) = fixture();
    let error = GistBundleSigner::from_m2(None, Some(KeyEpoch::INITIAL), Some(&device))
        .expect_err("没有数据密钥时不能启用 Gist");
    assert_eq!(error.code(), "gist_bundle.m2_keys_required");

    let error = GistBundleVerifier::from_m2(
        Some(WorkspaceId::generate()),
        Some(&key),
        None,
        Some(BTreeMap::from([(device.device_id(), device.public())])),
    )
    .expect_err("没有密钥纪元时不能解包 Gist");
    assert_eq!(error.code(), "gist_bundle.m2_keys_required");
}

#[test]
fn rejects_duplicate_and_excessive_object_inputs() {
    let (reference, key, device, objects) = fixture();
    let duplicate = vec![objects[0].clone(), objects[0].clone()];
    let error =
        pack(&reference, duplicate, &signer(&key, &device)).expect_err("重复 Object ID 必须被拒绝");
    assert_eq!(error.code(), "gist_bundle.duplicate_object_id");

    let excessive = (0..=MAX_OBJECTS)
        .map(|index: usize| {
            let bytes = index.to_be_bytes().to_vec();
            GistBundleObject::new(ObjectId::for_bytes(ObjectKind::Blob, &bytes), bytes)
        })
        .collect::<Vec<_>>();
    let error = pack(
        &WorkspaceRef::initial(reference.workspace),
        excessive,
        &signer(&key, &device),
    )
    .expect_err("超过对象上限必须被拒绝");
    assert_eq!(error.code(), "gist_bundle.too_many_objects");
}

#[test]
fn rejects_a_state_root_with_more_than_256_resources() {
    let workspace = WorkspaceId::generate();
    let key = DataKey::generate().expect("生成 M2 数据密钥");
    let device = DeviceKeypair::generate().expect("生成设备密钥");
    let state = StateRoot::from_entries((0..=MAX_RESOURCES).map(|index| ResourceEntry {
        resource: ResourceId::parse(&format!("fixture/resource-{index}")).expect("资源 ID 合法"),
        disposition: DesiredDisposition::EnsureAbsent,
        blob: None,
        mode: FileMode::FullFile,
        policy: ResourcePolicy::default(),
    }))
    .expect("State Root 合法");
    let snapshot = SnapshotBody::new(
        workspace,
        Vec::new(),
        state.id(),
        device.device_id(),
        0,
        BTreeMap::new(),
    )
    .expect("构造 snapshot");
    let reference = WorkspaceRef::initial(workspace).advance(snapshot.id());
    let objects = vec![
        GistBundleObject::new(ObjectId::from(snapshot.id()), snapshot.to_canonical_vec()),
        GistBundleObject::new(ObjectId::from(state.id()), state.to_canonical_vec()),
    ];

    let error =
        pack(&reference, objects, &signer(&key, &device)).expect_err("超过资源上限必须被拒绝");
    assert_eq!(error.code(), "gist_bundle.too_many_resources");
}

#[test]
fn rejects_a_bundle_missing_a_referenced_managed_blob() {
    let workspace = WorkspaceId::generate();
    let key = DataKey::generate().expect("生成 M2 数据密钥");
    let device = DeviceKeypair::generate().expect("生成设备密钥");
    let missing_blob = BlobId::of(b"this blob is intentionally absent from the bundle");
    let state = StateRoot::from_entries([ResourceEntry {
        resource: ResourceId::parse("fixture/managed-resource").expect("资源 ID 合法"),
        disposition: DesiredDisposition::Managed,
        blob: Some(missing_blob),
        mode: FileMode::FullFile,
        policy: ResourcePolicy::default(),
    }])
    .expect("State Root 合法");
    let snapshot = SnapshotBody::new(
        workspace,
        Vec::new(),
        state.id(),
        device.device_id(),
        0,
        BTreeMap::new(),
    )
    .expect("构造 snapshot");
    let reference = WorkspaceRef::initial(workspace).advance(snapshot.id());
    let objects = vec![
        GistBundleObject::new(ObjectId::from(snapshot.id()), snapshot.to_canonical_vec()),
        GistBundleObject::new(ObjectId::from(state.id()), state.to_canonical_vec()),
    ];

    let error = pack(&reference, objects, &signer(&key, &device))
        .expect_err("缺少受管 Blob 的 Bundle 必须被拒绝");
    assert_eq!(error.code(), "gist_bundle.incomplete_closure");
}

#[test]
fn rejects_a_bundle_missing_a_parent_snapshot() {
    let workspace = WorkspaceId::generate();
    let key = DataKey::generate().expect("生成 M2 数据密钥");
    let device = DeviceKeypair::generate().expect("生成设备密钥");
    let state = StateRoot::empty();
    let missing_parent = envsync_domain::SnapshotId::of(b"missing parent snapshot");
    let snapshot = SnapshotBody::new(
        workspace,
        vec![missing_parent],
        state.id(),
        device.device_id(),
        0,
        BTreeMap::new(),
    )
    .expect("构造 snapshot");
    let reference = WorkspaceRef::initial(workspace).advance(snapshot.id());
    let objects = vec![
        GistBundleObject::new(ObjectId::from(snapshot.id()), snapshot.to_canonical_vec()),
        GistBundleObject::new(ObjectId::from(state.id()), state.to_canonical_vec()),
    ];

    let error = pack(&reference, objects, &signer(&key, &device))
        .expect_err("缺少父快照的 Bundle 必须被拒绝");
    assert_eq!(error.code(), "gist_bundle.incomplete_closure");
}

#[test]
fn rejects_a_bundle_missing_any_vault_closure_object_without_leaking_it() {
    for (label, select) in [
        (
            "Vault Index",
            (|ids: VaultObjectIds| ids.index) as fn(VaultObjectIds) -> ObjectId,
        ),
        ("成员事件", |ids: VaultObjectIds| ids.membership),
        ("设备信封", |ids: VaultObjectIds| ids.envelope),
        ("密封秘密", |ids: VaultObjectIds| ids.secret),
        ("恢复包", |ids: VaultObjectIds| ids.recovery),
    ] {
        let (reference, key, device, objects, secret_id, ids) = vault_fixture();
        let missing = select(ids);
        let incomplete = objects
            .into_iter()
            .filter(|object| object.id != missing)
            .collect();
        let error = pack(&reference, incomplete, &signer(&key, &device))
            .expect_err(&format!("缺少 {label} 时必须拒绝 Vault Bundle"));
        assert_eq!(error.code(), "gist_bundle.incomplete_closure");
        assert!(!error.to_string().contains(&missing.to_string()));
        assert!(!error.to_string().contains(secret_id.as_str()));
    }
}

#[test]
fn vault_bundle_exposes_only_bootstrap_membership_and_current_envelopes() {
    let (reference, key, device, objects, secret_id, _) = vault_fixture();
    let encoded = pack(&reference, objects, &signer(&key, &device)).expect("打包成功");
    let bootstrap = inspect_bootstrap(&encoded).expect("无需 M2 数据密钥即可读取引导区");
    assert_eq!(bootstrap.workspace, reference.workspace);
    assert_eq!(bootstrap.epoch, KeyEpoch::INITIAL);
    assert_eq!(bootstrap.membership.len(), 1);
    assert_eq!(bootstrap.envelopes.len(), 1);
    assert!(bootstrap
        .membership
        .iter()
        .all(|object| object.id.kind == ObjectKind::MembershipEvent));
    assert!(bootstrap
        .envelopes
        .iter()
        .all(|object| object.id.kind == ObjectKind::KeyEnvelope));
    let unpacked = unpack(&encoded, &verifier(reference.workspace, &key, &device))
        .expect("完整 Vault Bundle 可解包");
    assert_eq!(unpacked.objects.len(), 8);

    let wire = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .expect("base64url 可解码");
    for forbidden in [
        b"resource-path=.config/gist-private".as_slice(),
        b"resource-value=never-public".as_slice(),
        b"vault-value=never-public".as_slice(),
        b"recovery-package=never-public".as_slice(),
        b"metadata=never-public".as_slice(),
        VAULT_INDEX_METADATA_KEY.as_bytes(),
        secret_id.as_str().as_bytes(),
    ] {
        assert!(
            !wire
                .windows(forbidden.len())
                .any(|window| window == forbidden),
            "外层 bootstrap 不得泄露私有 Vault 或资源 payload"
        );
    }
}

#[test]
fn rejects_oversized_and_tampered_input_before_decryption() {
    let oversized = "A".repeat(MAX_ENCODED_BUNDLE_LEN + 1);
    let oversized_key = DataKey::generate().expect("生成 M2 数据密钥");
    let oversized_device = DeviceKeypair::generate().expect("生成设备密钥");
    let error = unpack(
        &oversized,
        &verifier(WorkspaceId::generate(), &oversized_key, &oversized_device),
    )
    .expect_err("超长编码必须先拒绝");
    assert_eq!(error.code(), "gist_bundle.encoded_too_large");

    let (reference, key, device, objects) = fixture();
    let encoded = pack(&reference, objects, &signer(&key, &device)).expect("打包成功");
    let mut wire = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .expect("base64url 可解码");

    let mut envelope = decode_canonical(&wire).expect("外层 canonical CBOR");
    let Value::Array(items) = &mut envelope else {
        unreachable!("Gist Bundle 外层必须是数组");
    };
    let Value::Bytes(digest) = &mut items[6] else {
        unreachable!("Gist Bundle 摘要必须是字节串");
    };
    digest[0] ^= 1;
    let tampered_digest =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(encode(&envelope));
    let error = unpack(
        &tampered_digest,
        &verifier(reference.workspace, &key, &device),
    )
    .expect_err("篡改摘要必须在解密前失败");
    assert!(matches!(error, GistBundleError::DigestMismatch));

    *wire.last_mut().expect("签名不为空") ^= 1;
    let tampered = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wire);
    let error = unpack(&tampered, &verifier(reference.workspace, &key, &device))
        .expect_err("篡改签名必须失败");
    assert!(matches!(error, GistBundleError::SignatureInvalid));
}

#[test]
fn accepts_only_the_locally_trusted_signer_and_workspace() {
    let (reference, key, device, objects) = fixture();
    let encoded = pack(&reference, objects, &signer(&key, &device)).expect("打包成功");
    let other_device = DeviceKeypair::generate().expect("生成另一台设备");
    let untrusted = GistBundleVerifier::from_m2(
        Some(reference.workspace),
        Some(&key),
        Some(KeyEpoch::INITIAL),
        Some(BTreeMap::from([(
            other_device.device_id(),
            other_device.public(),
        )])),
    )
    .expect("本地成员链非空");
    let error = unpack(&encoded, &untrusted).expect_err("不能信任 Bundle 自带 signer");
    assert_eq!(error.code(), "gist_bundle.signature_invalid");

    let error = unpack(&encoded, &verifier(WorkspaceId::generate(), &key, &device))
        .expect_err("跨工作区重放必须在解密前拒绝");
    assert_eq!(error.code(), "gist_bundle.workspace_mismatch");
}

#[test]
fn accepts_each_trusted_signer_at_the_matching_key_epoch() {
    let (reference, key, first_device, objects) = fixture();
    let signing_device = DeviceKeypair::generate().expect("生成第二台设备");
    let epoch = KeyEpoch::new(2);
    let signer = GistBundleSigner::from_m2(Some(&key), Some(epoch), Some(&signing_device))
        .expect("M2 密钥材料完整");
    let encoded = pack(&reference, objects, &signer).expect("第二台已信任设备可打包");
    let trusted_signers = BTreeMap::from([
        (first_device.device_id(), first_device.public()),
        (signing_device.device_id(), signing_device.public()),
    ]);
    let verifier = GistBundleVerifier::from_m2(
        Some(reference.workspace),
        Some(&key),
        Some(epoch),
        Some(trusted_signers.clone()),
    )
    .expect("当前成员链非空");
    let unpacked = unpack(&encoded, &verifier).expect("匹配纪元的已信任 signer 可解包");
    assert_eq!(unpacked.signer, signing_device.device_id());
    assert_eq!(unpacked.epoch, epoch);

    let stale_epoch = GistBundleVerifier::from_m2(
        Some(reference.workspace),
        Some(&key),
        Some(KeyEpoch::INITIAL),
        Some(trusted_signers),
    )
    .expect("当前成员链非空");
    let error = unpack(&encoded, &stale_epoch).expect_err("错误纪元不能解密 Bundle");
    assert_eq!(error.code(), "gist_bundle.chunk_header_mismatch");
}

#[test]
fn payloads_larger_than_one_secret_chunk_round_trip() {
    let (reference, key, device, mut objects) = fixture();
    let large = vec![b'x'; MAX_PLAINTEXT_LEN + 1];
    objects.push(GistBundleObject::new(
        ObjectId::for_bytes(ObjectKind::Blob, &large),
        large,
    ));

    let encoded = pack(&reference, objects, &signer(&key, &device)).expect("分块打包成功");
    let unpacked =
        unpack(&encoded, &verifier(reference.workspace, &key, &device)).expect("分块解包成功");
    assert_eq!(unpacked.objects.len(), 4);
}

#[test]
fn filename_is_bound_to_the_workspace_and_never_contains_paths() {
    let workspace = WorkspaceId::generate();
    assert_eq!(
        gist_bundle_filename(workspace),
        format!("envsync-{workspace}.bundle")
    );
}
