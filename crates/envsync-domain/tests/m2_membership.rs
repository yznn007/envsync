//! M2 成员事件链的领域层契约测试。
//!
//! 这里只测**不需要密码学就能判定**的性质：编码确定性、摘要覆盖范围、结构不变量。
//! 验签、授权与链回放属于 `envsync-core`，见 `crates/envsync-core/tests/membership_chain.rs`。

use std::collections::BTreeMap;

use envsync_domain::cbor::{encode, CborCodec, CborError, Value};
use envsync_domain::id::{DeviceId, Digest32, WorkspaceId};
use envsync_domain::membership::{
    DevicePublicBytes, MemberRecord, MemberRole, MembershipAction, MembershipEvent,
    MembershipEventError, MembershipState, DEVICE_PUBLIC_LEN, GENESIS_EPOCH,
    MEMBERSHIP_EVENT_FORMAT_VERSION, SIGNATURE_LEN,
};
use envsync_domain::object::{ObjectId, ObjectKind};

/// 构造一份确定性的「公开材料」。领域层把它当作不透明字节，因此不需要真实曲线点。
fn public(seed: u8) -> DevicePublicBytes {
    DevicePublicBytes::from_parts([seed; 32], [seed.wrapping_add(0x40); 32])
}

fn workspace() -> WorkspaceId {
    "0d9b6d0e-2f45-4a10-9a1e-2b3c4d5e6f70"
        .parse()
        .expect("固定 UUID 合法")
}

fn genesis() -> MembershipEvent {
    let admin = public(1);
    MembershipEvent {
        format_version: MEMBERSHIP_EVENT_FORMAT_VERSION,
        workspace: workspace(),
        sequence: 0,
        previous: None,
        epoch: GENESIS_EPOCH,
        actor: admin.device_id(),
        action: MembershipAction::Genesis {
            subject: admin.device_id(),
            public: admin,
        },
        created_at_unix_ms: 1_700_000_000_000,
        signature: vec![7u8; SIGNATURE_LEN],
    }
}

fn successor(previous: &MembershipEvent) -> MembershipEvent {
    let laptop = public(2);
    MembershipEvent {
        format_version: MEMBERSHIP_EVENT_FORMAT_VERSION,
        workspace: previous.workspace,
        sequence: previous.sequence + 1,
        previous: Some(previous.digest()),
        epoch: previous.epoch,
        actor: previous.action.subject(),
        action: MembershipAction::AddMember {
            subject: laptop.device_id(),
            public: laptop,
            role: MemberRole::Member,
        },
        created_at_unix_ms: previous.created_at_unix_ms + 1,
        signature: vec![8u8; SIGNATURE_LEN],
    }
}

#[test]
fn device_public_bytes_is_64_bytes_of_two_keys() {
    let value = public(9);
    assert_eq!(value.as_bytes().len(), DEVICE_PUBLIC_LEN);
    assert_eq!(value.x25519(), [9u8; 32]);
    assert_eq!(value.ed25519(), [9u8.wrapping_add(0x40); 32]);
    assert_eq!(
        DevicePublicBytes::from_parts(value.x25519(), value.ed25519()),
        value
    );
    assert_eq!(DevicePublicBytes::from_slice(value.as_bytes()), Some(value));
    assert_eq!(DevicePublicBytes::from_slice(&[0u8; 10]), None);
}

#[test]
fn device_id_is_derived_from_both_public_keys() {
    let base = public(1);
    let expected = DeviceId::derive(base.as_bytes());
    assert_eq!(base.device_id(), expected);

    // 只改 X25519 一半。
    let flipped_x = DevicePublicBytes::from_parts([2u8; 32], base.ed25519());
    assert_ne!(flipped_x.device_id(), base.device_id());
    // 只改 Ed25519 一半。
    let flipped_ed = DevicePublicBytes::from_parts(base.x25519(), [3u8; 32]);
    assert_ne!(flipped_ed.device_id(), base.device_id());
}

#[test]
fn device_public_bytes_round_trips_through_json_and_cbor() {
    let value = public(5);
    let json = serde_json::to_string(&value).expect("序列化");
    assert_eq!(json, format!("\"{}\"", value.to_hex()));
    assert_eq!(
        serde_json::from_str::<DevicePublicBytes>(&json).expect("反序列化"),
        value
    );
    assert_eq!(
        DevicePublicBytes::from_canonical_slice(&value.to_canonical_vec()).expect("CBOR"),
        value
    );
    // 长度不对的十六进制被拒绝。
    assert!(serde_json::from_str::<DevicePublicBytes>("\"deadbeef\"").is_err());
}

#[test]
fn event_encoding_is_deterministic_and_round_trips() {
    let event = genesis();
    let first = event.to_canonical_vec();
    let second = event.clone().to_canonical_vec();
    assert_eq!(first, second, "相同事件必须产生逐字节相同的编码");
    assert_eq!(
        MembershipEvent::from_canonical_slice(&first).expect("解码"),
        event
    );
    // 追加垃圾字节后必须被拒绝（非 canonical）。
    let mut corrupted = first.clone();
    corrupted.push(0x00);
    assert!(MembershipEvent::from_canonical_slice(&corrupted).is_err());
}

#[test]
fn digest_covers_the_signature_but_signing_payload_does_not() {
    let mut a = genesis();
    let mut b = genesis();
    a.signature = vec![1u8; SIGNATURE_LEN];
    b.signature = vec![2u8; SIGNATURE_LEN];

    // 待签内容与签名无关：验签方能独立复现「到底签了什么」。
    assert_eq!(a.signing_payload(), b.signing_payload());
    // 但事件摘要覆盖签名：换一枚签名就是另一个事件，无法在保持链接不变的前提下替换签名。
    assert_ne!(a.digest(), b.digest());
}

#[test]
fn digest_changes_with_every_field() {
    let base = genesis();
    let mut sequence_changed = base.clone();
    sequence_changed.sequence = 1;
    sequence_changed.previous = Some(Digest32::ZERO);
    assert_ne!(sequence_changed.digest(), base.digest());

    let mut epoch_changed = base.clone();
    epoch_changed.epoch = 2;
    assert_ne!(epoch_changed.digest(), base.digest());

    let mut time_changed = base.clone();
    time_changed.created_at_unix_ms += 1;
    assert_ne!(time_changed.digest(), base.digest());
}

#[test]
fn chain_links_are_expressed_by_the_previous_digest() {
    let genesis = genesis();
    let next = successor(&genesis);
    assert_eq!(next.previous, Some(genesis.digest()));
    assert_eq!(next.sequence, 1);
    assert!(genesis.is_genesis());
    assert!(!next.is_genesis());
}

#[test]
fn membership_events_have_their_own_object_domain() {
    let event = genesis();
    let bytes = event.to_canonical_vec();
    let object = ObjectId::for_bytes(ObjectKind::MembershipEvent, &bytes);
    assert!(object.verifies(&bytes));
    // 同样的字节在别的对象种类下必须得到不同摘要。
    assert_ne!(
        object.digest,
        ObjectId::for_bytes(ObjectKind::Blob, &bytes).digest
    );
    assert_eq!(object.to_string().split('/').next(), Some("membership"));
}

#[test]
fn unknown_format_version_is_rejected_rather_than_downgraded() {
    let event = genesis();
    let mut value = event.to_value();
    if let Value::Array(items) = &mut value {
        items[0] = Value::Uint(2);
    }
    assert_eq!(
        MembershipEvent::from_canonical_slice(&encode(&value)),
        Err(CborError::UnsupportedFormatVersion {
            found: 2,
            supported: MEMBERSHIP_EVENT_FORMAT_VERSION,
        })
    );
}

#[test]
fn decoding_enforces_the_structural_invariants() {
    // sequence 0 带 previous：genesis 形状被破坏。
    let mut event = genesis();
    event.previous = Some(Digest32::ZERO);
    let bytes = encode(&event.to_value());
    assert!(matches!(
        MembershipEvent::from_canonical_slice(&bytes),
        Err(CborError::InvalidValue(_))
    ));

    // 非 0 sequence 不带 previous。
    let mut event = genesis();
    event.sequence = 3;
    let bytes = encode(&event.to_value());
    assert!(matches!(
        MembershipEvent::from_canonical_slice(&bytes),
        Err(CborError::InvalidValue(_))
    ));

    // 主体与公钥不匹配。
    let mut event = genesis();
    event.action = MembershipAction::Genesis {
        subject: public(42).device_id(),
        public: public(1),
    };
    let bytes = encode(&event.to_value());
    assert!(matches!(
        MembershipEvent::from_canonical_slice(&bytes),
        Err(CborError::InvalidValue(_))
    ));
}

#[test]
fn signature_length_is_part_of_the_structural_contract() {
    let mut event = genesis();
    event.signature = vec![0u8; SIGNATURE_LEN - 1];
    assert_eq!(
        event.validate(),
        Err(MembershipEventError::SignatureLength {
            expected: SIGNATURE_LEN,
            found: SIGNATURE_LEN - 1,
        })
    );
}

#[test]
fn only_revoke_is_flagged_as_epoch_rotating() {
    let device = public(1).device_id();
    let public = public(1);
    assert!(MembershipAction::Revoke { subject: device }.is_revoke());
    for action in [
        MembershipAction::Genesis {
            subject: device,
            public,
        },
        MembershipAction::AddMember {
            subject: device,
            public,
            role: MemberRole::Admin,
        },
        MembershipAction::Promote { subject: device },
    ] {
        assert!(!action.is_revoke(), "{} 不应推进密钥纪元", action.kind());
    }
}

#[test]
fn action_kinds_are_a_stable_persistence_contract() {
    let device = public(1).device_id();
    let public = public(1);
    let kinds: Vec<&str> = vec![
        MembershipAction::Genesis {
            subject: device,
            public,
        }
        .kind(),
        MembershipAction::AddMember {
            subject: device,
            public,
            role: MemberRole::Member,
        }
        .kind(),
        MembershipAction::Promote { subject: device }.kind(),
        MembershipAction::Revoke { subject: device }.kind(),
    ];
    assert_eq!(kinds, vec!["genesis", "add_member", "promote", "revoke"]);
    assert_eq!(MemberRole::Admin.as_str(), "admin");
    assert_eq!(MemberRole::Member.as_str(), "member");
}

#[test]
fn membership_state_only_reports_current_members() {
    let admin = public(1);
    let laptop = public(2);
    let mut members = BTreeMap::new();
    members.insert(
        admin.device_id(),
        MemberRecord {
            device: admin.device_id(),
            public: admin,
            role: MemberRole::Admin,
            added_at_sequence: 0,
        },
    );
    members.insert(
        laptop.device_id(),
        MemberRecord {
            device: laptop.device_id(),
            public: laptop,
            role: MemberRole::Member,
            added_at_sequence: 1,
        },
    );
    let state = MembershipState {
        members,
        epoch: GENESIS_EPOCH,
        head: genesis().digest(),
        sequence: 1,
    };

    assert_eq!(state.len(), 2);
    assert!(!state.is_empty());
    assert_eq!(state.admin_count(), 1);
    assert!(state.is_admin(&admin.device_id()));
    assert!(!state.is_admin(&laptop.device_id()));
    assert!(state.contains(&laptop.device_id()));
    assert!(!state.contains(&public(3).device_id()));
    assert_eq!(
        state
            .member(&laptop.device_id())
            .map(|r| r.added_at_sequence),
        Some(1)
    );
    // 状态可以序列化，方便 CLI 输出与诊断。
    let json = serde_json::to_string(&state).expect("序列化");
    assert!(json.contains("\"admin\""));
}

#[test]
fn member_record_round_trips_through_cbor() {
    let device = public(6);
    let record = MemberRecord {
        device: device.device_id(),
        public: device,
        role: MemberRole::Admin,
        added_at_sequence: 12,
    };
    let bytes = record.to_canonical_vec();
    assert_eq!(
        MemberRecord::from_canonical_slice(&bytes).expect("解码"),
        record
    );
}
