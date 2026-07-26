//! M1 领域 schema 的行为契约：设备 Profile、选择器 AST 与冲突解决方案。
//!
//! 这些测试固定的是**语义**而不是实现：选择器求值规则、资源上限、非法取值的拒绝
//! 方式，以及 canonical 编码的往返性质。

use std::collections::BTreeSet;

use envsync_domain::cbor::{CborCodec, CborError};
use envsync_domain::id::{BlobId, ConflictId, DeviceId, ResourceId};
use envsync_domain::object::{Conflict, ConflictKind, CONFLICT_FORMAT_VERSION};
use envsync_domain::profile::{
    Arch, ConflictResolution, DeviceProfile, Os, Predicate, ProfileError, ProjectionNote,
    ProjectionNoteKind, ResolutionChoice, Selector, MAX_PROFILE_ENTRIES, MAX_SELECTOR_DEPTH,
    MAX_SELECTOR_NODES,
};

#[test]
fn selector_requires_all_declared_constraints() {
    let profile = DeviceProfile::new(Os::Windows, Arch::X86_64)
        .with_tag("work")
        .with_capability("pwsh");
    let selector = Selector::all([
        Predicate::Os(Os::Windows),
        Predicate::Tag("work".into()),
        Predicate::Capability("pwsh".into()),
    ]);
    assert!(selector.matches(&profile));
    assert!(!selector.matches(&DeviceProfile::new(Os::Linux, Arch::X86_64)));
}

#[test]
fn any_matches_when_at_least_one_predicate_holds() {
    let profile = DeviceProfile::new(Os::Linux, Arch::Aarch64).with_tag("home");
    let selector = Selector::any([Predicate::Os(Os::Windows), Predicate::Tag("home".into())]);
    assert!(selector.validate().is_ok());
    assert!(selector.matches(&profile));

    let miss = Selector::any([Predicate::Os(Os::Windows), Predicate::Tag("work".into())]);
    assert!(!miss.matches(&profile));
}

#[test]
fn not_inverts_its_child() {
    let profile = DeviceProfile::new(Os::MacOs, Arch::Aarch64).with_capability("brew");
    let has_brew = Selector::is(Predicate::Capability("brew".into()));
    assert!(has_brew.matches(&profile));
    assert!(!Selector::negate(has_brew.clone()).matches(&profile));

    // 双重取反回到原语义。
    assert!(Selector::negate(Selector::negate(has_brew)).matches(&profile));
}

#[test]
fn empty_all_matches_everything_and_empty_any_matches_nothing() {
    // 空集合的语义必须固定下来，否则不同实现会给出不同的投影结果。
    let profile = DeviceProfile::new(Os::Linux, Arch::X86_64);
    assert!(Selector::all([]).matches(&profile));
    assert!(!Selector::any([]).matches(&profile));
}

#[test]
fn hostname_and_device_predicates_are_exact() {
    let device = DeviceId::derive(b"device-public-material");
    let other = DeviceId::derive(b"another-device");
    let profile = DeviceProfile::new(Os::Linux, Arch::X86_64)
        .with_hostname("build-01")
        .with_device(device);

    assert!(Selector::is(Predicate::Hostname("build-01".into())).matches(&profile));
    assert!(!Selector::is(Predicate::Hostname("build-0".into())).matches(&profile));
    assert!(Selector::is(Predicate::Device(device)).matches(&profile));
    assert!(!Selector::is(Predicate::Device(other)).matches(&profile));

    // 没有 hostname / device 的 Profile 不会被这两个谓词命中。
    let bare = DeviceProfile::new(Os::Linux, Arch::X86_64);
    assert!(!Selector::is(Predicate::Hostname("build-01".into())).matches(&bare));
    assert!(!Selector::is(Predicate::Device(device)).matches(&bare));
}

#[test]
fn depth_and_node_counts_are_reported() {
    let leaf = Selector::is(Predicate::Os(Os::Linux));
    assert_eq!(leaf.depth(), 1);
    assert_eq!(leaf.node_count(), 1);

    // All([Is, Is]) 深度 2、节点 3。
    let flat = Selector::all([Predicate::Os(Os::Linux), Predicate::Arch(Arch::X86_64)]);
    assert_eq!(flat.depth(), 2);
    assert_eq!(flat.node_count(), 3);

    // Not(All([Is, Is])) 深度 3、节点 4。
    let nested = Selector::negate(flat);
    assert_eq!(nested.depth(), 3);
    assert_eq!(nested.node_count(), 4);
}

#[test]
fn selector_depth_limit_is_enforced() {
    let mut selector = Selector::is(Predicate::Os(Os::Linux));
    for _ in 0..(MAX_SELECTOR_DEPTH - 1) {
        selector = Selector::negate(selector);
    }
    assert_eq!(selector.depth(), MAX_SELECTOR_DEPTH);
    assert!(selector.validate().is_ok(), "恰好达到上限应当被接受");

    // 再套一层就超限。
    let too_deep = Selector::negate(selector);
    assert_eq!(
        too_deep.validate(),
        Err(ProfileError::DepthLimitExceeded {
            max: MAX_SELECTOR_DEPTH
        })
    );

    // 超限的选择器仍然可以安全求值：保守判为不匹配，既不 panic 也不栈溢出。
    assert!(!too_deep.matches(&DeviceProfile::new(Os::Linux, Arch::X86_64)));
}

#[test]
fn selector_node_limit_is_enforced() {
    // All 自身占 1 个节点，因此 MAX 个谓词恰好超限 1 个。
    let ok = Selector::all(
        std::iter::repeat_n(Predicate::Os(Os::Linux), MAX_SELECTOR_NODES - 1).collect::<Vec<_>>(),
    );
    assert_eq!(ok.node_count(), MAX_SELECTOR_NODES);
    assert!(ok.validate().is_ok());

    let too_many = Selector::all(
        std::iter::repeat_n(Predicate::Os(Os::Linux), MAX_SELECTOR_NODES).collect::<Vec<_>>(),
    );
    assert_eq!(
        too_many.validate(),
        Err(ProfileError::NodeLimitExceeded {
            max: MAX_SELECTOR_NODES
        })
    );
    // 超出预算时同样保守返回 false。
    assert!(!too_many.matches(&DeviceProfile::new(Os::Linux, Arch::X86_64)));
}

#[test]
fn a_selector_exceeding_the_limit_under_not_does_not_become_true() {
    // 回归测试：若超限时直接返回 false，外层 Not 会把它翻成 true，
    // “资源耗尽”反而变成“匹配所有设备”。
    let mut inner = Selector::is(Predicate::Os(Os::Linux));
    for _ in 0..MAX_SELECTOR_DEPTH {
        inner = Selector::negate(inner);
    }
    assert!(inner.validate().is_err());
    assert!(!inner.matches(&DeviceProfile::new(Os::Linux, Arch::X86_64)));
    assert!(!inner.matches(&DeviceProfile::new(Os::Windows, Arch::X86_64)));
}

#[test]
fn blank_values_are_rejected_without_panicking() {
    // 1) 链式构造器：静默丢弃，绝不 panic。
    let profile = DeviceProfile::new(Os::Linux, Arch::X86_64)
        .with_tag("")
        .with_tag("   ")
        .with_tag("\t\n ")
        .with_capability("")
        .with_capability("  ")
        .with_hostname("")
        .with_hostname("   ");
    assert!(profile.tags.is_empty());
    assert!(profile.capabilities.is_empty());
    assert_eq!(profile.hostname, None);

    // 2) 受检构造器：返回错误。
    let base = DeviceProfile::new(Os::Linux, Arch::X86_64);
    assert_eq!(
        base.clone().try_with_tag("  "),
        Err(ProfileError::EmptyValue { field: "tag" })
    );
    assert_eq!(
        base.clone().try_with_capability(""),
        Err(ProfileError::EmptyValue {
            field: "capability"
        })
    );
    assert_eq!(
        base.try_with_hostname("\n"),
        Err(ProfileError::EmptyValue { field: "hostname" })
    );

    // 3) 受检谓词构造器。
    assert_eq!(
        Predicate::tag(" "),
        Err(ProfileError::EmptyValue { field: "tag" })
    );
    assert_eq!(
        Predicate::capability(""),
        Err(ProfileError::EmptyValue {
            field: "capability"
        })
    );
    assert_eq!(
        Predicate::hostname("  \t"),
        Err(ProfileError::EmptyValue { field: "hostname" })
    );
    assert_eq!(Predicate::tag(" work "), Ok(Predicate::Tag("work".into())));
}

#[test]
fn hand_constructed_blank_values_are_caught_by_validate() {
    // 直接构造变体（测试与配置解析会用到）绕过了受检构造器，validate 必须兜底。
    let mut profile = DeviceProfile::new(Os::Linux, Arch::X86_64);
    profile.tags.insert(String::new());
    assert_eq!(
        profile.validate(),
        Err(ProfileError::EmptyValue { field: "tag" })
    );

    let mut profile = DeviceProfile::new(Os::Linux, Arch::X86_64);
    profile.tags.insert("  padded  ".to_owned());
    assert_eq!(
        profile.validate(),
        Err(ProfileError::NotNormalized { field: "tag" })
    );

    let mut profile = DeviceProfile::new(Os::Linux, Arch::X86_64);
    profile.hostname = Some(" host ".to_owned());
    assert_eq!(
        profile.validate(),
        Err(ProfileError::NotNormalized { field: "hostname" })
    );

    assert_eq!(
        Selector::is(Predicate::Capability("  ".into())).validate(),
        Err(ProfileError::EmptyValue {
            field: "capability"
        })
    );
}

#[test]
fn oversized_collections_are_rejected() {
    let mut profile = DeviceProfile::new(Os::Linux, Arch::X86_64);
    for index in 0..=MAX_PROFILE_ENTRIES {
        profile.tags.insert(format!("tag-{index}"));
    }
    assert_eq!(
        profile.validate(),
        Err(ProfileError::TooManyEntries {
            field: "tags",
            max: MAX_PROFILE_ENTRIES
        })
    );
}

#[test]
fn profile_round_trips_through_cbor_and_serde() {
    let profile = DeviceProfile::new(Os::MacOs, Arch::Aarch64)
        .with_hostname("studio")
        .with_tag("work")
        .with_tag("laptop")
        .with_capability("brew")
        .with_device(DeviceId::derive(b"pk"));

    let bytes = profile.to_canonical_vec();
    assert_eq!(
        DeviceProfile::from_canonical_slice(&bytes).unwrap(),
        profile
    );
    // canonical：解码后重新编码必须逐字节相同。
    assert_eq!(
        DeviceProfile::from_canonical_slice(&bytes)
            .unwrap()
            .to_canonical_vec(),
        bytes
    );

    let json = serde_json::to_string(&profile).unwrap();
    assert_eq!(
        serde_json::from_str::<DeviceProfile>(&json).unwrap(),
        profile
    );
}

#[test]
fn selector_round_trips_through_cbor_and_serde() {
    let selector = Selector::All(vec![
        Selector::is(Predicate::Os(Os::Windows)),
        Selector::any([
            Predicate::Tag("work".into()),
            Predicate::Capability("pwsh".into()),
        ]),
        Selector::negate(Selector::is(Predicate::Arch(Arch::Aarch64))),
        Selector::is(Predicate::Device(DeviceId::derive(b"pk"))),
        Selector::is(Predicate::Hostname("build-01".into())),
    ]);
    assert!(selector.validate().is_ok());

    let bytes = selector.to_canonical_vec();
    let decoded = Selector::from_canonical_slice(&bytes).unwrap();
    assert_eq!(decoded, selector);
    assert_eq!(decoded.to_canonical_vec(), bytes);

    let json = serde_json::to_string(&selector).unwrap();
    assert_eq!(serde_json::from_str::<Selector>(&json).unwrap(), selector);
}

#[test]
fn cbor_decoding_rejects_non_normalized_and_unsorted_input() {
    // 未规范化的标签在解码时被拒绝，而不是悄悄进入投影。
    let mut profile = DeviceProfile::new(Os::Linux, Arch::X86_64);
    profile.tags.insert(" padded".to_owned());
    let bytes = profile.to_canonical_vec();
    assert!(matches!(
        DeviceProfile::from_canonical_slice(&bytes),
        Err(CborError::InvalidValue(_))
    ));

    // 集合乱序会破坏“同一逻辑值只有一种编码”，必须拒绝。
    let unsorted = envsync_domain::cbor::Value::Array(vec![
        envsync_domain::cbor::Value::Uint(1),
        Os::Linux.to_value(),
        Arch::X86_64.to_value(),
        envsync_domain::cbor::Value::Null,
        envsync_domain::cbor::Value::Array(vec![
            envsync_domain::cbor::Value::Text("b".into()),
            envsync_domain::cbor::Value::Text("a".into()),
        ]),
        envsync_domain::cbor::Value::Array(vec![]),
        envsync_domain::cbor::Value::Null,
    ]);
    assert!(matches!(
        DeviceProfile::from_canonical_slice(&envsync_domain::cbor::encode(&unsorted)),
        Err(CborError::InvalidValue(_))
    ));
}

#[test]
fn cbor_decoding_rejects_selectors_deeper_than_the_limit() {
    // 先构造一个合法选择器，再在字节层面手工加深，模拟恶意配置。
    let mut node = envsync_domain::cbor::Value::Array(vec![
        envsync_domain::cbor::Value::Text("is".into()),
        Predicate::Os(Os::Linux).to_value(),
    ]);
    for _ in 0..(MAX_SELECTOR_DEPTH + 1) {
        node = envsync_domain::cbor::Value::Array(vec![
            envsync_domain::cbor::Value::Text("not".into()),
            node,
        ]);
    }
    let wrapped =
        envsync_domain::cbor::Value::Array(vec![envsync_domain::cbor::Value::Uint(1), node]);
    assert!(matches!(
        Selector::from_canonical_slice(&envsync_domain::cbor::encode(&wrapped)),
        Err(CborError::InvalidValue(_))
    ));
}

#[test]
fn projection_note_round_trips() {
    let note = ProjectionNote::new(
        ResourceId::parse("shell/zsh/main").unwrap(),
        ProjectionNoteKind::UnsupportedCapability,
        "缺少能力 `brew`",
    );
    let bytes = note.to_canonical_vec();
    assert_eq!(ProjectionNote::from_canonical_slice(&bytes).unwrap(), note);

    let json = serde_json::to_string(&note).unwrap();
    assert_eq!(serde_json::from_str::<ProjectionNote>(&json).unwrap(), note);
}

/// 构造一个用于测试的冲突对象。
fn sample_conflict() -> Conflict {
    Conflict {
        format_version: CONFLICT_FORMAT_VERSION,
        resource: ResourceId::parse("git/config").unwrap(),
        kind: ConflictKind::TextOverlap,
        base: Some(BlobId::of(b"base")),
        ours: Some(BlobId::of(b"ours")),
        theirs: Some(BlobId::of(b"theirs")),
        diagnostics: vec!["行 10-12".into()],
    }
}

#[test]
fn resolution_must_reference_an_existing_blob() {
    let conflict = sample_conflict();
    let present = BlobId::of(b"merged");
    let missing = BlobId::of(b"never-stored");
    let known: BTreeSet<BlobId> = [present].into_iter().collect();
    let exists = |blob: BlobId| known.contains(&blob);

    let good = ConflictResolution::with_blob(
        conflict.id(),
        ResolutionChoice::Manual,
        present,
        1_700_000_000_000,
    );
    assert_eq!(good.validate(&exists), Ok(()));

    let bad = ConflictResolution::with_blob(
        conflict.id(),
        ResolutionChoice::Ours,
        missing,
        1_700_000_000_000,
    );
    assert_eq!(
        bad.validate(&exists),
        Err(ProfileError::ResolutionBlobUnknown {
            blob: missing.to_hex()
        })
    );
}

#[test]
fn resolution_shape_matches_the_choice() {
    let conflict = ConflictId::of(b"conflict");
    let blob = BlobId::of(b"content");
    let exists = |_: BlobId| true;

    // Delete 不能带 Blob。
    let bad_delete = ConflictResolution {
        conflict,
        choice: ResolutionChoice::Delete,
        resolved_blob: Some(blob),
        resolved_at_unix_ms: 1,
    };
    assert_eq!(
        bad_delete.validate(&exists),
        Err(ProfileError::ResolutionBlobUnexpected { choice: "delete" })
    );

    // Ours/Theirs/Manual 必须带 Blob。
    for choice in [
        ResolutionChoice::Ours,
        ResolutionChoice::Theirs,
        ResolutionChoice::Manual,
    ] {
        let missing = ConflictResolution {
            conflict,
            choice,
            resolved_blob: None,
            resolved_at_unix_ms: 1,
        };
        assert_eq!(
            missing.validate(&exists),
            Err(ProfileError::ResolutionBlobMissing {
                choice: choice.as_str()
            })
        );
    }

    assert_eq!(
        ConflictResolution::delete(conflict, 1).validate(&exists),
        Ok(())
    );
}

#[test]
fn resolution_round_trips_through_cbor_and_serde() {
    let resolution = ConflictResolution::with_blob(
        sample_conflict().id(),
        ResolutionChoice::Theirs,
        BlobId::of(b"theirs"),
        1_700_000_000_000,
    );
    let bytes = resolution.to_canonical_vec();
    assert_eq!(
        ConflictResolution::from_canonical_slice(&bytes).unwrap(),
        resolution
    );

    let json = serde_json::to_string(&resolution).unwrap();
    assert_eq!(
        serde_json::from_str::<ConflictResolution>(&json).unwrap(),
        resolution
    );

    // 形状不自洽的编码在解码时就被拒绝。
    let mut value = resolution.to_value();
    if let envsync_domain::cbor::Value::Array(items) = &mut value {
        items[3] = envsync_domain::cbor::Value::Null;
    }
    assert!(matches!(
        ConflictResolution::from_canonical_slice(&envsync_domain::cbor::encode(&value)),
        Err(CborError::InvalidValue(_))
    ));
}
