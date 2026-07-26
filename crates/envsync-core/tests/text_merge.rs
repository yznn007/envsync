//! M1 任务 5 验收测试：文本三方合并语义。
//!
//! 表格驱动地覆盖计划里列出的每一条语义，外加 property test。

use envsync_core::merge::{merge_text, MergeInput, MergeResult, MAX_INPUT_BYTES};
use envsync_domain::{ConflictKind, ResourceId};
use proptest::prelude::*;

fn resource() -> ResourceId {
    ResourceId::parse("shell/zsh/main").expect("valid resource id")
}

fn run<'a>(
    resource: &'a ResourceId,
    base: Option<&'a [u8]>,
    ours: Option<&'a [u8]>,
    theirs: Option<&'a [u8]>,
) -> MergeResult {
    merge_text(&MergeInput {
        resource,
        base,
        ours,
        theirs,
    })
    .expect("text merge never fails on content")
}

/// 断言结果是 Clean 并返回字节。
fn clean(result: MergeResult) -> Vec<u8> {
    match result {
        MergeResult::Clean { bytes, .. } => bytes,
        other => panic!("expected clean merge, got {other:?}"),
    }
}

/// 结果里绝不允许出现冲突 marker。
fn assert_no_markers(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    for marker in ["<<<<<<<", "=======", ">>>>>>>", "|||||||"] {
        assert!(
            !text.contains(marker),
            "merge output must never contain conflict markers"
        );
    }
}

#[test]
fn table_driven_clean_cases() {
    let resource = resource();
    // (名称, base, ours, theirs, 期望输出)
    let cases: &[(&str, &str, &str, &str, &str)] = &[
        (
            "只改 ours",
            "a\nb\nc\n",
            "A\nb\nc\n",
            "a\nb\nc\n",
            "A\nb\nc\n",
        ),
        (
            "只改 theirs",
            "a\nb\nc\n",
            "a\nb\nc\n",
            "a\nb\nC\n",
            "a\nb\nC\n",
        ),
        (
            "双方相同修改",
            "a\nb\nc\n",
            "a\nX\nc\n",
            "a\nX\nc\n",
            "a\nX\nc\n",
        ),
        (
            "互不相交的修改",
            "a\nb\nc\nd\ne\n",
            "A\nb\nc\nd\ne\n",
            "a\nb\nc\nd\nE\n",
            "A\nb\nc\nd\nE\n",
        ),
        (
            "两侧各自追加不同位置的新行",
            "one\ntwo\nthree\n",
            "zero\none\ntwo\nthree\n",
            "one\ntwo\nthree\nfour\n",
            "zero\none\ntwo\nthree\nfour\n",
        ),
        (
            "一侧删除若干行、另一侧改别处",
            "a\nb\nc\nd\ne\nf\n",
            "a\nd\ne\nf\n",
            "a\nb\nc\nd\ne\nF\n",
            "a\nd\ne\nF\n",
        ),
        ("双方新增相同内容", "", "new\n", "new\n", "new\n"),
    ];

    for (name, base, ours, theirs, expected) in cases {
        let result = run(
            &resource,
            Some(base.as_bytes()),
            Some(ours.as_bytes()),
            Some(theirs.as_bytes()),
        );
        let bytes = clean(result);
        assert_no_markers(&bytes);
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            *expected,
            "case `{name}` produced unexpected merge output"
        );
    }
}

#[test]
fn overlapping_edits_conflict_with_line_ranges_only() {
    let resource = resource();
    let result = run(
        &resource,
        Some(b"a\nb\nc\n"),
        Some(b"a\nX\nc\n"),
        Some(b"a\nY\nc\n"),
    );
    let conflict = match &result {
        MergeResult::Conflict(conflict) => conflict,
        other => panic!("expected conflict, got {other:?}"),
    };
    assert_eq!(conflict.kind, ConflictKind::TextOverlap);
    assert_eq!(conflict.diagnostics, vec!["ours 2..3 vs theirs 2..3"]);
    // 诊断只有行区间，绝不包含内容正文。
    for diagnostic in &conflict.diagnostics {
        assert!(!diagnostic.contains('X') && !diagnostic.contains('Y'));
    }
    assert!(result.bytes().is_none(), "conflict must not produce bytes");
}

#[test]
fn multi_line_overlap_reports_the_full_range() {
    let resource = resource();
    let result = run(
        &resource,
        Some(b"1\n2\n3\n4\n5\n"),
        Some(b"1\nX\nX\nX\n5\n"),
        Some(b"1\nY\nY\n5\n"),
    );
    let conflict = result.conflict().expect("expected conflict").clone();
    assert_eq!(conflict.kind, ConflictKind::TextOverlap);
    assert_eq!(conflict.diagnostics, vec!["ours 2..5 vs theirs 2..4"]);
}

#[test]
fn delete_modify_conflicts_both_directions() {
    let resource = resource();
    for (ours, theirs) in [
        (None, Some(b"a\nCHANGED\n".as_slice())),
        (Some(b"a\nCHANGED\n".as_slice()), None),
    ] {
        let result = run(&resource, Some(b"a\nb\n"), ours, theirs);
        let conflict = result.conflict().expect("expected conflict");
        assert_eq!(conflict.kind, ConflictKind::DeleteModify);
        assert_eq!(conflict.diagnostics.len(), 1);
        assert!(conflict.diagnostics[0].contains("deleted"));
    }
}

#[test]
fn delete_with_untouched_other_side_is_accepted() {
    let resource = resource();
    assert_eq!(
        run(&resource, Some(b"a\n"), None, Some(b"a\n")),
        MergeResult::Deleted
    );
    assert_eq!(
        run(&resource, Some(b"a\n"), Some(b"a\n"), None),
        MergeResult::Deleted
    );
}

#[test]
fn both_deleted_is_deleted() {
    let resource = resource();
    assert_eq!(
        run(&resource, Some(b"a\n"), None, None),
        MergeResult::Deleted
    );
}

#[test]
fn binary_content_is_never_line_merged() {
    let resource = resource();

    // 只有一侧改动 → Clean，逐字节等于改动那一侧。
    let clean_result = run(
        &resource,
        Some(b"\x00\x01binary"),
        Some(b"\x00\x01binary"),
        Some(b"\x00\x02binary"),
    );
    assert_eq!(clean(clean_result), b"\x00\x02binary".to_vec());

    // 双方都改 → BinaryBoth。
    let conflict = run(
        &resource,
        Some(b"\x00\x01binary"),
        Some(b"\x00\x03binary"),
        Some(b"\x00\x02binary"),
    );
    let conflict = conflict.conflict().expect("expected conflict");
    assert_eq!(conflict.kind, ConflictKind::BinaryBoth);
    assert!(conflict.diagnostics.iter().any(|d| d.contains("binary")));

    // 非法 UTF-8 同样按二进制处理。
    let invalid = run(
        &resource,
        Some(b"\xff\xfe base"),
        Some(b"\xff\xfe ours"),
        Some(b"\xff\xfe theirs"),
    );
    assert_eq!(
        invalid.conflict().expect("expected conflict").kind,
        ConflictKind::BinaryBoth
    );
}

#[test]
fn oversized_input_falls_back_to_opaque_rules() {
    let resource = resource();
    let filler = "x\n".repeat((MAX_INPUT_BYTES as usize / 2) + 1);
    let base = filler.clone();
    let ours = format!("{filler}ours\n");
    let theirs = format!("{filler}theirs\n");
    assert!(ours.len() as u64 > MAX_INPUT_BYTES);

    let result = run(
        &resource,
        Some(base.as_bytes()),
        Some(ours.as_bytes()),
        Some(theirs.as_bytes()),
    );
    let conflict = result.conflict().expect("expected conflict");
    assert_eq!(conflict.kind, ConflictKind::BinaryBoth);
    assert!(conflict
        .diagnostics
        .iter()
        .any(|d| d.contains("exceeds") && d.contains(&MAX_INPUT_BYTES.to_string())));
}

#[test]
fn oversized_input_with_one_sided_change_is_clean() {
    let resource = resource();
    let base = "x\n".repeat((MAX_INPUT_BYTES as usize / 2) + 1);
    let theirs = format!("{base}theirs\n");
    let result = run(
        &resource,
        Some(base.as_bytes()),
        Some(base.as_bytes()),
        Some(theirs.as_bytes()),
    );
    match result {
        MergeResult::Clean { bytes, provenance } => {
            assert_eq!(bytes, theirs.as_bytes());
            assert_eq!(provenance.took_theirs, 1);
        }
        other => panic!("expected clean, got {other:?}"),
    }
}

#[test]
fn mixed_line_endings_compare_normalized_and_keep_original_terminators() {
    let resource = resource();
    // ours 改第一行（LF），theirs 改第三行并整体使用 CRLF。
    let result = run(
        &resource,
        Some(b"a\nb\nc\n"),
        Some(b"A\nb\nc\n"),
        Some(b"a\r\nb\r\nC\r\n"),
    );
    let bytes = clean(result);
    // 采纳自 ours 的行保留 LF，采纳自 theirs 的行保留 CRLF。
    assert_eq!(String::from_utf8(bytes).unwrap(), "A\nb\nC\r\n");
}

#[test]
fn line_ending_only_difference_is_not_a_conflict() {
    let resource = resource();
    // theirs 只把行尾从 LF 换成 CRLF，ours 改了第一行 → 归一化后互不冲突。
    let result = run(
        &resource,
        Some(b"a\nb\n"),
        Some(b"A\nb\n"),
        Some(b"a\r\nb\r\n"),
    );
    let bytes = clean(result);
    assert_no_markers(&bytes);
    assert_eq!(String::from_utf8(bytes).unwrap(), "A\nb\n");
}

#[test]
fn provenance_tracks_each_side() {
    let resource = resource();
    let result = run(
        &resource,
        Some(b"a\nb\nc\nd\ne\n"),
        Some(b"A\nb\nc\nd\ne\n"),
        Some(b"a\nb\nc\nd\nE\n"),
    );
    match result {
        MergeResult::Clean { provenance, .. } => {
            assert_eq!(provenance.took_ours, 1);
            assert_eq!(provenance.took_theirs, 1);
            assert_eq!(provenance.took_base, 3);
            assert!(!provenance.notes.is_empty());
        }
        other => panic!("expected clean, got {other:?}"),
    }
}

#[test]
fn missing_trailing_newline_does_not_glue_lines() {
    let resource = resource();
    // ours 去掉了末行换行符，theirs 在末尾追加了一行。
    let result = run(
        &resource,
        Some(b"a\nb\n"),
        Some(b"a\nb"),
        Some(b"a\nb\nc\n"),
    );
    let bytes = clean(result);
    let text = String::from_utf8(bytes).unwrap();
    assert!(!text.contains("bc"), "lines must not be glued: {text:?}");
}

proptest! {
    /// `merge(base, x, x)` 必须是 `Clean(x)`，且逐字节相等。
    #[test]
    fn identical_sides_always_merge_to_that_side(
        base in prop::collection::vec(any::<u8>(), 0..128),
        same in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let resource = resource();
        let result = run(&resource, Some(&base), Some(&same), Some(&same));
        prop_assert_eq!(result.bytes().map(<[u8]>::to_vec), Some(same));
    }

    /// 只改一侧必为 Clean，且结果逐字节等于改动的那一侧。
    #[test]
    fn one_sided_change_is_always_clean(
        base in prop::collection::vec(any::<u8>(), 0..128),
        changed in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let resource = resource();

        let ours_only = run(&resource, Some(&base), Some(&changed), Some(&base));
        prop_assert_eq!(ours_only.bytes().map(<[u8]>::to_vec), Some(changed.clone()));

        let theirs_only = run(&resource, Some(&base), Some(&base), Some(&changed));
        prop_assert_eq!(theirs_only.bytes().map(<[u8]>::to_vec), Some(changed));
    }

    /// 任意输入都不 panic，且 Clean 结果里绝不含冲突 marker。
    #[test]
    fn arbitrary_inputs_never_panic(
        base in prop::option::of(prop::collection::vec(any::<u8>(), 0..96)),
        ours in prop::option::of(prop::collection::vec(any::<u8>(), 0..96)),
        theirs in prop::option::of(prop::collection::vec(any::<u8>(), 0..96)),
    ) {
        let resource = resource();
        let result = run(
            &resource,
            base.as_deref(),
            ours.as_deref(),
            theirs.as_deref(),
        );
        if let Some(bytes) = result.bytes() {
            assert_no_markers(bytes);
        }
    }

    /// 文本输入下的同一批 property（更容易命中真正的行合并路径）。
    #[test]
    fn arbitrary_line_inputs_never_panic(
        base in prop::collection::vec("[a-c]", 0..12),
        ours in prop::collection::vec("[a-c]", 0..12),
        theirs in prop::collection::vec("[a-c]", 0..12),
    ) {
        let resource = resource();
        let join = |lines: &[String]| lines.iter().map(|l| format!("{l}\n")).collect::<String>();
        let (base, ours, theirs) = (join(&base), join(&ours), join(&theirs));
        let result = run(
            &resource,
            Some(base.as_bytes()),
            Some(ours.as_bytes()),
            Some(theirs.as_bytes()),
        );
        if let Some(bytes) = result.bytes() {
            assert_no_markers(bytes);
            prop_assert!(std::str::from_utf8(bytes).is_ok());
        }
    }
}
