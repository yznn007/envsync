//! M0 任务 3 验收：确定性对象与快照。
//!
//! 对应 M0 验收条件“相同输入在不同运行中产生相同 Snapshot ID”。

use std::collections::BTreeMap;

use envsync_domain::cbor::{self, CborCodec, CborError, Value};
use envsync_domain::id::{BlobId, DeviceId, ResourceId, StateRootId, WorkspaceId};
use envsync_domain::object::{Blob, StateRoot};
use envsync_domain::resource::{DesiredDisposition, FileMode, ResourceEntry, ResourcePolicy};
use envsync_domain::snapshot::SnapshotBody;

use proptest::prelude::*;

fn entry(name: &str, content: &[u8]) -> ResourceEntry {
    ResourceEntry {
        resource: ResourceId::parse(name).unwrap(),
        disposition: DesiredDisposition::Managed,
        blob: Some(BlobId::of(content)),
        mode: FileMode::FullFile,
        policy: ResourcePolicy::default(),
    }
}

fn snapshot(state_root: StateRootId, metadata: BTreeMap<String, String>) -> SnapshotBody {
    SnapshotBody::new(
        WorkspaceId::from_uuid(uuid::Uuid::from_u128(1)),
        vec![],
        state_root,
        DeviceId::derive(b"fixture-device"),
        1_700_000_000_000,
        metadata,
    )
    .unwrap()
}

#[test]
fn identical_bytes_always_hash_to_the_same_blob_id() {
    for payload in [b"".as_slice(), b"a", b"\x00\xff\x00", &[0u8; 4096]] {
        assert_eq!(Blob::new(payload.to_vec()).id(), BlobId::of(payload));
    }
}

#[test]
fn state_root_id_ignores_entry_insertion_order() {
    let names = ["git/config", "shell/zsh/main", "terminal/wezterm/lua"];
    let forward = StateRoot::from_entries(names.iter().map(|n| entry(n, n.as_bytes()))).unwrap();
    let backward =
        StateRoot::from_entries(names.iter().rev().map(|n| entry(n, n.as_bytes()))).unwrap();
    assert_eq!(forward.id(), backward.id());
}

#[test]
fn snapshot_id_ignores_metadata_order_but_tracks_content() {
    let state = StateRoot::from_entries([entry("git/config", b"x")]).unwrap();

    let mut forward = BTreeMap::new();
    forward.insert("host".to_owned(), "a".to_owned());
    forward.insert("tool".to_owned(), "b".to_owned());
    let mut backward = BTreeMap::new();
    backward.insert("tool".to_owned(), "b".to_owned());
    backward.insert("host".to_owned(), "a".to_owned());

    assert_eq!(
        snapshot(state.id(), forward.clone()).id(),
        snapshot(state.id(), backward).id()
    );

    let other_state = StateRoot::from_entries([entry("git/config", b"y")]).unwrap();
    assert_ne!(
        snapshot(state.id(), forward.clone()).id(),
        snapshot(other_state.id(), forward).id()
    );
}

#[test]
fn changing_the_format_version_changes_the_identity_and_decoding_is_refused() {
    let state = StateRoot::from_entries([entry("git/config", b"x")]).unwrap();
    let mut value = state.to_value();
    let Value::Array(items) = &mut value else {
        panic!("State Root 编码为数组")
    };
    items[0] = Value::Uint(2);
    let bytes = cbor::encode(&value);

    assert_ne!(StateRootId::of(&bytes), state.id());
    assert_eq!(
        StateRoot::from_canonical_slice(&bytes),
        Err(CborError::UnsupportedFormatVersion {
            found: 2,
            supported: 1
        })
    );
}

#[test]
fn non_canonical_encodings_are_refused() {
    let state = StateRoot::from_entries([entry("git/config", b"x")]).unwrap();
    let canonical = state.to_canonical_vec();

    // 1) 追加尾随字节。
    let mut trailing = canonical.clone();
    trailing.push(0);
    assert!(matches!(
        StateRoot::from_canonical_slice(&trailing),
        Err(CborError::TrailingBytes(_)) | Err(CborError::UnexpectedEof)
    ));

    // 2) 非最短整数编码：把顶层数组头 0x82 换成 0x98 0x02（用 1 字节写长度 2）。
    let mut non_minimal = vec![0x98, 0x02];
    non_minimal.extend_from_slice(&canonical[1..]);
    assert_eq!(
        StateRoot::from_canonical_slice(&non_minimal),
        Err(CborError::NonMinimalInteger)
    );

    // 3) 不定长度数组。
    let mut indefinite = vec![0x9f];
    indefinite.extend_from_slice(&canonical[1..]);
    indefinite.push(0xff);
    assert_eq!(
        StateRoot::from_canonical_slice(&indefinite),
        Err(CborError::IndefiniteLength)
    );
}

#[test]
fn digest_mismatch_is_detectable_by_recomputation() {
    let state = StateRoot::from_entries([entry("git/config", b"x")]).unwrap();
    let bytes = state.to_canonical_vec();
    let claimed = StateRootId::of(b"something else");
    assert_ne!(claimed, StateRootId::of(&bytes));
}

proptest! {
    /// 任意条目集合，无论以何种顺序构造，State Root 标识必须一致。
    #[test]
    fn state_root_identity_is_order_independent(
        mut names in prop::collection::hash_set("[a-z]{1,6}/[a-z]{1,6}", 0..12)
            .prop_map(|set| set.into_iter().collect::<Vec<_>>())
    ) {
        let forward = StateRoot::from_entries(
            names.iter().map(|n| entry(n, n.as_bytes()))
        ).unwrap();
        names.reverse();
        let backward = StateRoot::from_entries(
            names.iter().map(|n| entry(n, n.as_bytes()))
        ).unwrap();
        prop_assert_eq!(forward.id(), backward.id());
        prop_assert_eq!(forward.to_canonical_vec(), backward.to_canonical_vec());
    }

    /// canonical 编码必须可无损往返，且再次编码逐字节相同。
    #[test]
    fn state_root_encoding_round_trips(
        names in prop::collection::hash_set("[a-z]{1,6}/[a-z]{1,6}", 0..8)
            .prop_map(|set| set.into_iter().collect::<Vec<_>>())
    ) {
        let state = StateRoot::from_entries(names.iter().map(|n| entry(n, n.as_bytes()))).unwrap();
        let bytes = state.to_canonical_vec();
        let decoded = StateRoot::from_canonical_slice(&bytes).unwrap();
        prop_assert_eq!(decoded.to_canonical_vec(), bytes);
    }
}
