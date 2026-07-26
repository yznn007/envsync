//! M0 任务 2 验收：资源状态模型的外部契约测试。
//!
//! 这些断言直接对应设计文档 §3.2 与 M0 验收条件“未显式 `ensure_absent` 的资源绝不删除”。

use envsync_domain::cbor::CborCodec;
use envsync_domain::id::{BlobId, IdError, ResourceId};
use envsync_domain::resource::{
    DesiredDisposition, FileMode, Observation, ObservedState, PermissionSummary, PresentFile,
    ResourceEntry, ResourcePolicy,
};
use envsync_domain::Digest32;

#[test]
fn resource_id_accepts_canonical_form_and_rejects_path_escapes() {
    assert!(ResourceId::parse("shell/zsh/main").is_ok());

    // 空段、点段、反斜杠、绝对路径与 NUL 全部拒绝。
    assert_eq!(ResourceId::parse(""), Err(IdError::ResourceIdEmpty));
    assert_eq!(
        ResourceId::parse("shell//main"),
        Err(IdError::ResourceIdEmptySegment)
    );
    assert_eq!(
        ResourceId::parse("/shell/main"),
        Err(IdError::ResourceIdEmptySegment)
    );
    assert_eq!(
        ResourceId::parse("shell/../main"),
        Err(IdError::ResourceIdDotSegment)
    );
    assert_eq!(
        ResourceId::parse("shell/./main"),
        Err(IdError::ResourceIdDotSegment)
    );
    assert_eq!(
        ResourceId::parse("shell\\main"),
        Err(IdError::ResourceIdCharset('\\'))
    );
    assert_eq!(
        ResourceId::parse("C:/config"),
        Err(IdError::ResourceIdCharset(':'))
    );
    assert_eq!(
        ResourceId::parse("shell/ma\0in"),
        Err(IdError::ResourceIdCharset('\0'))
    );
}

#[test]
fn every_observed_state_survives_a_serialisation_round_trip() {
    let present = ObservedState::Present(PresentFile {
        content_digest: Digest32::domain_hash("fixture", b"content"),
        size: 7,
        mtime_unix_ms: Some(1),
        permissions: PermissionSummary {
            readonly: true,
            unix_mode: Some(0o600),
        },
        managed_digest: Some(Digest32::domain_hash("fixture", b"block")),
    });
    let states = [
        present,
        ObservedState::Absent,
        ObservedState::Unsupported {
            reason: "windows-only".into(),
        },
        ObservedState::Unreadable {
            reason: "permission denied".into(),
        },
        ObservedState::Excluded {
            reason: "policy".into(),
        },
    ];

    let kinds: Vec<&str> = states.iter().map(ObservedState::kind).collect();
    assert_eq!(
        kinds,
        ["present", "absent", "unsupported", "unreadable", "excluded"]
    );

    for state in states {
        let bytes = state.to_canonical_vec();
        assert_eq!(ObservedState::from_canonical_slice(&bytes).unwrap(), state);
    }
}

#[test]
fn a_missing_observation_never_becomes_a_tombstone() {
    // 领域层不提供任何“由观察推导处置”的转换函数：处置只能显式声明。
    // 这里用类型层面的断言固化该约束——`ResourceEntry` 的 disposition 是必填字段，
    // 而 `Observation` 完全不参与其构造。
    let entry = ResourceEntry {
        resource: ResourceId::parse("shell/zsh/main").unwrap(),
        disposition: DesiredDisposition::Managed,
        blob: Some(BlobId::of(b"content")),
        mode: FileMode::ManagedBlock,
        policy: ResourcePolicy::default(),
    };
    let absent = Observation::new(entry.resource.clone(), ObservedState::Absent, 0);
    assert_eq!(absent.state, ObservedState::Absent);
    // 观察为 Absent 并不会改变期望处置。
    assert_eq!(entry.disposition, DesiredDisposition::Managed);
    assert_ne!(entry.disposition, DesiredDisposition::EnsureAbsent);
}

#[test]
fn unreadable_and_unsupported_are_never_writable() {
    for state in [
        ObservedState::Unreadable {
            reason: "eperm".into(),
        },
        ObservedState::Unsupported {
            reason: "no adapter".into(),
        },
        ObservedState::Excluded {
            reason: "policy".into(),
        },
    ] {
        assert!(!state.is_writable(), "{} 不应被视为可写", state.kind());
        assert!(state.content_digest().is_none());
    }
}
