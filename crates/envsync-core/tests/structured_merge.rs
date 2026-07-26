//! M1 任务 6 验收测试：JSON / YAML / TOML / INI / Git config 语义三方合并。

use envsync_core::merge::{
    merge_structured, merge_structured_with, IniPolicy, MergeError, MergeInput, MergeOptions,
    MergeResult, MultiValuePolicy, MAX_INPUT_BYTES, MAX_PARSE_DEPTH,
};
use envsync_domain::{ConflictKind, ResourceId, StructuredFormat};

fn resource() -> ResourceId {
    ResourceId::parse("app/config").expect("valid resource id")
}

fn merge3(
    format: StructuredFormat,
    base: Option<&str>,
    ours: &str,
    theirs: &str,
) -> Result<MergeResult, MergeError> {
    let resource = resource();
    merge_structured(
        &MergeInput {
            resource: &resource,
            base: base.map(str::as_bytes),
            ours: Some(ours.as_bytes()),
            theirs: Some(theirs.as_bytes()),
        },
        format,
    )
}

fn clean_text(result: Result<MergeResult, MergeError>) -> String {
    match result.expect("merge must succeed") {
        MergeResult::Clean { bytes, .. } => String::from_utf8(bytes).expect("utf-8 output"),
        other => panic!("expected clean merge, got {other:?}"),
    }
}

fn conflict_of(result: Result<MergeResult, MergeError>) -> envsync_domain::Conflict {
    match result.expect("merge must succeed") {
        MergeResult::Conflict(conflict) => conflict,
        other => panic!("expected conflict, got {other:?}"),
    }
}

fn error_of(result: Result<MergeResult, MergeError>) -> MergeError {
    result.expect_err("expected a merge error")
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

#[test]
fn json_merges_objects_per_key() {
    let text = clean_text(merge3(
        StructuredFormat::Json,
        Some(r#"{"a": 1, "b": {"x": 1, "y": 2}}"#),
        r#"{"a": 2, "b": {"x": 1, "y": 2}}"#,
        r#"{"a": 1, "b": {"x": 1, "y": 9}}"#,
    ));
    let value: serde_json::Value = serde_json::from_str(&text).expect("valid json");
    assert_eq!(value["a"], serde_json::json!(2));
    assert_eq!(value["b"]["y"], serde_json::json!(9));
}

#[test]
fn json_arrays_are_atomic() {
    // 双方改同一个数组的不同元素 → 冲突（数组不做元素级合并）。
    let conflict = conflict_of(merge3(
        StructuredFormat::Json,
        Some(r#"{"list": [1, 2, 3]}"#),
        r#"{"list": [9, 2, 3]}"#,
        r#"{"list": [1, 2, 9]}"#,
    ));
    assert_eq!(conflict.kind, ConflictKind::StructuredKey);
    assert_eq!(conflict.diagnostics, vec!["modify/modify /list"]);
}

#[test]
fn json_null_is_a_value_not_a_deletion() {
    let text = clean_text(merge3(
        StructuredFormat::Json,
        Some(r#"{"a": 1, "b": 2}"#),
        r#"{"a": null, "b": 2}"#,
        r#"{"a": 1, "b": 3}"#,
    ));
    let value: serde_json::Value = serde_json::from_str(&text).expect("valid json");
    assert!(value.as_object().expect("object").contains_key("a"));
    assert_eq!(value["a"], serde_json::Value::Null);
    assert_eq!(value["b"], serde_json::json!(3));
}

#[test]
fn json_delete_modify_reports_json_pointer() {
    let conflict = conflict_of(merge3(
        StructuredFormat::Json,
        Some(r#"{"user": {"email": "a", "name": "n"}}"#),
        r#"{"user": {"name": "n"}}"#,
        r#"{"user": {"email": "b", "name": "n"}}"#,
    ));
    assert_eq!(conflict.kind, ConflictKind::DeleteModify);
    assert_eq!(conflict.diagnostics, vec!["delete/modify /user/email"]);
    // 诊断只有键路径，不含值。
    assert!(!conflict.diagnostics[0].contains('b'));
}

#[test]
fn json_key_deleted_on_one_side_and_untouched_on_the_other_is_removed() {
    let text = clean_text(merge3(
        StructuredFormat::Json,
        Some(r#"{"a": 1, "b": 2}"#),
        r#"{"a": 1}"#,
        r#"{"a": 1, "b": 2, "c": 3}"#,
    ));
    let value: serde_json::Value = serde_json::from_str(&text).expect("valid json");
    let object = value.as_object().expect("object");
    assert!(!object.contains_key("b"));
    assert!(object.contains_key("c"));
}

#[test]
fn json_duplicate_keys_are_rejected_with_pointer() {
    let error = error_of(merge3(
        StructuredFormat::Json,
        Some(r#"{"a": 1}"#),
        r#"{"outer": {"dup": 1, "dup": 2}}"#,
        r#"{"a": 2}"#,
    ));
    assert_eq!(error.code(), "merge.duplicate_key");
    match error {
        MergeError::DuplicateKey { pointer } => assert_eq!(pointer, "/outer/dup"),
        other => panic!("expected duplicate key, got {other:?}"),
    }
}

#[test]
fn json_invalid_input_reports_position_without_content() {
    let error = error_of(merge3(
        StructuredFormat::Json,
        Some(r#"{"a": 1}"#),
        r#"{"secret": "s3cret" "#,
        r#"{"a": 2}"#,
    ));
    assert_eq!(error.code(), "merge.parse");
    assert!(!error.to_string().contains("s3cret"));
}

// ---------------------------------------------------------------------------
// YAML
// ---------------------------------------------------------------------------

#[test]
fn yaml_merges_mappings_and_treats_sequences_as_atomic() {
    let text = clean_text(merge3(
        StructuredFormat::Yaml,
        Some("a: 1\nb:\n  x: 1\nlist:\n  - 1\n"),
        "a: 2\nb:\n  x: 1\nlist:\n  - 1\n",
        "a: 1\nb:\n  x: 1\n  y: 3\nlist:\n  - 1\n",
    ));
    let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(&text).expect("valid yaml");
    assert_eq!(value["a"], serde_yaml_ng::Value::from(2));
    assert_eq!(value["b"]["y"], serde_yaml_ng::Value::from(3));

    let conflict = conflict_of(merge3(
        StructuredFormat::Yaml,
        Some("list:\n  - 1\n  - 2\n"),
        "list:\n  - 9\n  - 2\n",
        "list:\n  - 1\n  - 9\n",
    ));
    assert_eq!(conflict.diagnostics, vec!["modify/modify /list"]);
}

#[test]
fn yaml_rejects_multiple_documents() {
    let error = error_of(merge3(
        StructuredFormat::Yaml,
        Some("a: 1\n"),
        "a: 2\n---\nb: 3\n",
        "a: 3\n",
    ));
    assert_eq!(error.code(), "merge.unsupported_construct");
    assert!(error.to_string().contains("documents"));
}

#[test]
fn yaml_rejects_custom_tags() {
    let error = error_of(merge3(
        StructuredFormat::Yaml,
        Some("a: 1\n"),
        "a: !Custom 2\n",
        "a: 3\n",
    ));
    assert_eq!(error.code(), "merge.unsupported_construct");
    assert!(error.to_string().contains("tag"));
}

#[test]
fn yaml_rejects_alias_cycles() {
    let error = error_of(merge3(
        StructuredFormat::Yaml,
        Some("a: 1\n"),
        "a: &anchor\n  b: *anchor\n",
        "a: 3\n",
    ));
    assert_eq!(error.code(), "merge.unsupported_construct");
}

#[test]
fn yaml_rejects_duplicate_keys() {
    let error = error_of(merge3(
        StructuredFormat::Yaml,
        Some("a: 1\n"),
        "dup: 1\ndup: 2\n",
        "a: 3\n",
    ));
    match error {
        MergeError::DuplicateKey { pointer } => assert_eq!(pointer, "/dup"),
        other => panic!("expected duplicate key, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// TOML
// ---------------------------------------------------------------------------

const TOML_BASE: &str = "\
# 顶部注释
name = \"envsync\"   # 行尾注释

[server]
# 端口说明
port = 8080
host = \"localhost\"
tags = [\"a\", \"b\"]
";

#[test]
fn toml_preserves_comments_and_merges_table_keys_independently() {
    let ours = TOML_BASE.replace("port = 8080", "port = 9090");
    let theirs = TOML_BASE.replace("host = \"localhost\"", "host = \"0.0.0.0\"");
    let text = clean_text(merge3(
        StructuredFormat::Toml,
        Some(TOML_BASE),
        &ours,
        &theirs,
    ));

    assert!(text.contains("# 顶部注释"), "top comment must survive");
    assert!(
        text.contains("# 端口说明"),
        "inline section comment must survive"
    );
    assert!(text.contains("# 行尾注释"), "trailing comment must survive");
    let doc: toml_edit::DocumentMut = text.parse().expect("valid toml");
    assert_eq!(doc["server"]["port"].as_integer(), Some(9090));
    assert_eq!(doc["server"]["host"].as_str(), Some("0.0.0.0"));
}

#[test]
fn toml_arrays_are_atomic() {
    let ours = TOML_BASE.replace("[\"a\", \"b\"]", "[\"a\", \"c\"]");
    let theirs = TOML_BASE.replace("[\"a\", \"b\"]", "[\"a\", \"d\"]");
    let conflict = conflict_of(merge3(
        StructuredFormat::Toml,
        Some(TOML_BASE),
        &ours,
        &theirs,
    ));
    assert_eq!(conflict.kind, ConflictKind::StructuredKey);
    assert_eq!(conflict.diagnostics, vec!["modify/modify /server/tags"]);
}

#[test]
fn toml_new_keys_from_both_sides_are_kept() {
    let ours = format!("{TOML_BASE}\n[client]\nretries = 3\n");
    let theirs = format!("{TOML_BASE}timeout = 30\n");
    let text = clean_text(merge3(
        StructuredFormat::Toml,
        Some(TOML_BASE),
        &ours,
        &theirs,
    ));
    let doc: toml_edit::DocumentMut = text.parse().expect("valid toml");
    assert_eq!(doc["client"]["retries"].as_integer(), Some(3));
    assert_eq!(doc["server"]["timeout"].as_integer(), Some(30));
}

#[test]
fn toml_duplicate_keys_are_rejected() {
    let error = error_of(merge3(
        StructuredFormat::Toml,
        Some("a = 1\n"),
        "a = 1\ndupkey = 1\ndupkey = 2\n",
        "a = 2\n",
    ));
    match error {
        MergeError::DuplicateKey { pointer } => assert_eq!(pointer, "/dupkey"),
        other => panic!("expected duplicate key, got {other:?}"),
    }
}

#[test]
fn toml_invalid_input_reports_line_without_content() {
    let error = error_of(merge3(
        StructuredFormat::Toml,
        Some("a = 1\n"),
        "a = 1\nsecret = = \"s3cret\"\n",
        "a = 2\n",
    ));
    assert_eq!(error.code(), "merge.parse");
    let rendered = error.to_string();
    assert!(rendered.contains("line 2"), "got {rendered}");
    assert!(!rendered.contains("s3cret"));
}

// ---------------------------------------------------------------------------
// INI
// ---------------------------------------------------------------------------

const INI_BASE: &str = "\
; 全局说明
[alpha]
# alpha 说明
one = 1
two = 2

[beta]
three = 3
";

fn merge_ini_with(
    policy: MultiValuePolicy,
    base: Option<&str>,
    ours: &str,
    theirs: &str,
) -> Result<MergeResult, MergeError> {
    let resource = resource();
    merge_structured_with(
        &MergeInput {
            resource: &resource,
            base: base.map(str::as_bytes),
            ours: Some(ours.as_bytes()),
            theirs: Some(theirs.as_bytes()),
        },
        StructuredFormat::Ini,
        &MergeOptions {
            ini: IniPolicy {
                multi_value: policy,
            },
        },
    )
}

#[test]
fn ini_preserves_comments_section_order_and_merges_per_key() {
    let ours = INI_BASE.replace("one = 1", "one = 11");
    let theirs = INI_BASE.replace("three = 3", "three = 33");
    let text = clean_text(merge3(
        StructuredFormat::Ini,
        Some(INI_BASE),
        &ours,
        &theirs,
    ));

    assert!(text.contains("; 全局说明"));
    assert!(text.contains("# alpha 说明"));
    assert!(text.contains("one = 11"));
    assert!(text.contains("three = 33"));
    let alpha = text.find("[alpha]").expect("alpha section");
    let beta = text.find("[beta]").expect("beta section");
    assert!(alpha < beta, "section order must be preserved");
}

#[test]
fn ini_keeps_original_line_endings() {
    let base = INI_BASE.replace('\n', "\r\n");
    let ours = base.replace("one = 1\r\n", "one = 11\r\n");
    let theirs = base.replace("three = 3", "three = 33");
    let text = clean_text(merge3(StructuredFormat::Ini, Some(&base), &ours, &theirs));
    assert!(text.contains("\r\n"), "CRLF style must be preserved");
    assert!(!text.contains("\n\n"), "no bare LF should be introduced");
}

#[test]
fn ini_rejects_duplicate_keys_by_default() {
    let error = error_of(merge3(
        StructuredFormat::Ini,
        Some("[s]\na = 1\n"),
        "[s]\na = 1\ndup = 1\ndup = 2\n",
        "[s]\na = 2\n",
    ));
    match error {
        MergeError::DuplicateKey { pointer } => assert_eq!(pointer, "/s/dup"),
        other => panic!("expected duplicate key, got {other:?}"),
    }
}

#[test]
fn ini_last_wins_policy_keeps_the_final_value() {
    let text = clean_text(merge_ini_with(
        MultiValuePolicy::LastWins,
        Some("[s]\na = 1\n"),
        "[s]\na = 1\nb = 1\nb = 2\n",
        "[s]\na = 9\n",
    ));
    assert!(text.contains("b = 2"));
    assert!(!text.contains("b = 1"));
    assert!(text.contains("a = 9"));
}

#[test]
fn ini_append_policy_keeps_every_value_in_order() {
    let text = clean_text(merge_ini_with(
        MultiValuePolicy::Append,
        Some("[s]\na = 1\n"),
        "[s]\na = 1\nb = 1\nb = 2\n",
        "[s]\na = 9\n",
    ));
    let first = text.find("b = 1").expect("first value");
    let second = text.find("b = 2").expect("second value");
    assert!(first < second, "multi-value order must be preserved");
}

#[test]
fn ini_delete_modify_conflicts_with_section_key_path() {
    let conflict = conflict_of(merge3(
        StructuredFormat::Ini,
        Some(INI_BASE),
        &INI_BASE.replace("two = 2\n", ""),
        &INI_BASE.replace("two = 2", "two = 22"),
    ));
    assert_eq!(conflict.kind, ConflictKind::DeleteModify);
    assert_eq!(conflict.diagnostics, vec!["delete/modify /alpha/two"]);
}

#[test]
fn ini_rejects_malformed_lines_with_line_number_only() {
    let error = error_of(merge3(
        StructuredFormat::Ini,
        Some("[s]\na = 1\n"),
        "[s]\na = 1\nthis line has no equals sign s3cret\n",
        "[s]\na = 2\n",
    ));
    assert_eq!(error.code(), "merge.parse");
    let rendered = error.to_string();
    assert!(rendered.contains("line 3"), "got {rendered}");
    assert!(!rendered.contains("s3cret"));
}

// ---------------------------------------------------------------------------
// Git config
// ---------------------------------------------------------------------------

const GIT_BASE: &str = "\
[user]
\tname = Alice
\temail = alice@example.com
[core]
\tautocrlf = input
[remote \"origin\"]
\turl = https://example.com/a.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
\tfetch = +refs/tags/*:refs/tags/*
";

#[test]
fn git_config_merges_independent_keys() {
    let ours = GIT_BASE.replace("name = Alice", "name = Alice Smith");
    let theirs = GIT_BASE.replace("autocrlf = input", "autocrlf = false");
    let text = clean_text(merge3(
        StructuredFormat::GitConfig,
        Some(GIT_BASE),
        &ours,
        &theirs,
    ));
    assert!(text.contains("name = Alice Smith"));
    assert!(text.contains("autocrlf = false"));
    assert!(text.contains("email = alice@example.com"));
}

#[test]
fn git_config_section_and_name_are_case_insensitive() {
    // ours 只改了 section / name 的大小写写法，值没变；theirs 改了值。
    // 按 git 规范这是同一个键，因此 ours 相对 base 没有语义变化 → 干净地取 theirs。
    let ours = GIT_BASE.replace("[user]\n\tname = Alice", "[USER]\n\tName = Alice");
    let theirs = GIT_BASE.replace("name = Alice", "name = Bob");
    let text = clean_text(merge3(
        StructuredFormat::GitConfig,
        Some(GIT_BASE),
        &ours,
        &theirs,
    ));
    assert!(
        text.contains("Bob"),
        "case-only rewrite must not block merge"
    );
    assert!(
        !text.contains("Alice\n"),
        "old value must be replaced: {text}"
    );
}

#[test]
fn git_config_subsection_is_case_sensitive() {
    let ours = format!("{GIT_BASE}[remote \"Origin\"]\n\turl = https://example.com/upper.git\n");
    let theirs = GIT_BASE.replace(
        "url = https://example.com/a.git",
        "url = https://example.com/b.git",
    );
    let text = clean_text(merge3(
        StructuredFormat::GitConfig,
        Some(GIT_BASE),
        &ours,
        &theirs,
    ));
    // 两个 subsection 是不同的键，互不覆盖。
    assert!(text.contains("https://example.com/upper.git"));
    assert!(text.contains("https://example.com/b.git"));
}

#[test]
fn git_config_multi_value_keys_keep_order() {
    let ours = GIT_BASE.replace("name = Alice", "name = Bob");
    let theirs = GIT_BASE.replace(
        "\tfetch = +refs/tags/*:refs/tags/*\n",
        "\tfetch = +refs/tags/*:refs/tags/*\n\tfetch = +refs/notes/*:refs/notes/*\n",
    );
    let text = clean_text(merge3(
        StructuredFormat::GitConfig,
        Some(GIT_BASE),
        &ours,
        &theirs,
    ));
    let heads = text.find("refs/heads").expect("heads fetch");
    let tags = text.find("refs/tags").expect("tags fetch");
    let notes = text.find("refs/notes").expect("notes fetch");
    assert!(heads < tags && tags < notes, "multi-value order preserved");
}

#[test]
fn git_config_include_path_uses_normalized_identity_and_is_never_read() {
    let base = format!("{GIT_BASE}[include]\n\tpath = ~/dotfiles/../gitconfig-extra\n");
    // ours 把 include 路径改写成等价的规范化形式（语义未变）。
    let ours = base.replace(
        "path = ~/dotfiles/../gitconfig-extra",
        "path = ~/gitconfig-extra",
    );
    // theirs 改了别的键。
    let theirs = base.replace("autocrlf = input", "autocrlf = true");
    let text = clean_text(merge3(
        StructuredFormat::GitConfig,
        Some(&base),
        &ours,
        &theirs,
    ));
    // 规范化后相同 → 不冲突，保留 ours 的字面写法。
    assert!(text.contains("path = ~/gitconfig-extra"));
    assert!(text.contains("autocrlf = true"));

    // include 目标不存在也完全不影响合并：合并器绝不读取 include。
    let missing =
        format!("{GIT_BASE}[include]\n\tpath = /nonexistent/definitely/missing.gitconfig\n");
    let missing_ours = missing.replace("name = Alice", "name = Bob");
    let merged = clean_text(merge3(
        StructuredFormat::GitConfig,
        Some(&missing),
        &missing_ours,
        &missing,
    ));
    assert!(merged.contains("/nonexistent/definitely/missing.gitconfig"));
}

#[test]
fn git_config_conflicting_single_value_reports_key_path() {
    let ours = GIT_BASE.replace("autocrlf = input", "autocrlf = true");
    let theirs = GIT_BASE.replace("autocrlf = input", "autocrlf = false");
    let conflict = conflict_of(merge3(
        StructuredFormat::GitConfig,
        Some(GIT_BASE),
        &ours,
        &theirs,
    ));
    assert_eq!(conflict.kind, ConflictKind::StructuredKey);
    assert_eq!(conflict.diagnostics, vec!["modify/modify /core/autocrlf"]);
}

// ---------------------------------------------------------------------------
// 跨格式：渲染后重解析校验 & 资源限制
// ---------------------------------------------------------------------------

/// 每种格式的干净合并结果都必须可以被同一个合并器重新解析并保持语义稳定。
///
/// 合并器内部在渲染后已经强制做过一次「重解析 + 语义比对」（不一致会返回
/// `RenderVerificationFailed`）；这里再从外部验证一次：把合并结果当作新的 base
/// 再合并一次，结果必须干净且幂等。
#[test]
fn every_format_output_reparses_and_is_idempotent() {
    let cases: &[(StructuredFormat, &str, &str, &str)] = &[
        (
            StructuredFormat::Json,
            r#"{"a": 1, "b": 2}"#,
            r#"{"a": 9, "b": 2}"#,
            r#"{"a": 1, "b": 8}"#,
        ),
        (
            StructuredFormat::Yaml,
            "a: 1\nb: 2\n",
            "a: 9\nb: 2\n",
            "a: 1\nb: 8\n",
        ),
        (
            StructuredFormat::Toml,
            TOML_BASE,
            "# 顶部注释\nname = \"envsync\"   # 行尾注释\n\n[server]\n# 端口说明\nport = 9090\nhost = \"localhost\"\ntags = [\"a\", \"b\"]\n",
            "# 顶部注释\nname = \"envsync\"   # 行尾注释\n\n[server]\n# 端口说明\nport = 8080\nhost = \"0.0.0.0\"\ntags = [\"a\", \"b\"]\n",
        ),
        (
            StructuredFormat::Ini,
            INI_BASE,
            "; 全局说明\n[alpha]\n# alpha 说明\none = 11\ntwo = 2\n\n[beta]\nthree = 3\n",
            "; 全局说明\n[alpha]\n# alpha 说明\none = 1\ntwo = 2\n\n[beta]\nthree = 33\n",
        ),
        (
            StructuredFormat::GitConfig,
            GIT_BASE,
            "[user]\n\tname = Bob\n\temail = alice@example.com\n[core]\n\tautocrlf = input\n[remote \"origin\"]\n\turl = https://example.com/a.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n\tfetch = +refs/tags/*:refs/tags/*\n",
            "[user]\n\tname = Alice\n\temail = bob@example.com\n[core]\n\tautocrlf = input\n[remote \"origin\"]\n\turl = https://example.com/a.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n\tfetch = +refs/tags/*:refs/tags/*\n",
        ),
    ];

    for (format, base, ours, theirs) in cases {
        let merged = clean_text(merge3(*format, Some(base), ours, theirs));
        // 1) 输出可以被同一解析器重新读取：以它为 base 再做一次单侧修改的合并。
        let second = merge3(*format, Some(&merged), &merged, &merged);
        match second.unwrap_or_else(|err| panic!("{format:?} output not re-parsable: {err}")) {
            MergeResult::Clean { bytes, .. } => {
                assert_eq!(
                    String::from_utf8(bytes).expect("utf-8"),
                    merged,
                    "{format:?} merge must be idempotent"
                );
            }
            other => panic!("{format:?} expected clean, got {other:?}"),
        }
        // 2) 输出里绝不出现冲突 marker。
        assert!(!merged.contains("<<<<<<<"), "{format:?} leaked markers");
    }
}

#[test]
fn deeply_nested_json_hits_the_depth_limit() {
    let mut deep = String::new();
    for _ in 0..100 {
        deep.push_str(r#"{"a":"#);
    }
    deep.push('1');
    for _ in 0..100 {
        deep.push('}');
    }

    let error = error_of(merge3(
        StructuredFormat::Json,
        Some(r#"{"a": 1}"#),
        &deep,
        r#"{"a": 2}"#,
    ));
    assert_eq!(error.code(), "merge.depth_limit");
    match error {
        MergeError::DepthLimitExceeded { limit } => assert_eq!(limit, MAX_PARSE_DEPTH),
        other => panic!("expected depth limit, got {other:?}"),
    }
}

#[test]
fn structured_merge_rejects_oversized_input() {
    let big = format!(
        "{{\"a\": \"{}\"}}",
        "x".repeat(MAX_INPUT_BYTES as usize + 8)
    );
    let error = error_of(merge3(
        StructuredFormat::Json,
        Some(r#"{"a": 1}"#),
        &big,
        r#"{"a": 2}"#,
    ));
    assert_eq!(error.code(), "merge.too_large");
    match error {
        MergeError::TooLarge { limit, .. } => assert_eq!(limit, MAX_INPUT_BYTES),
        other => panic!("expected too large, got {other:?}"),
    }
}

#[test]
fn structured_merge_handles_deletion_and_creation() {
    let resource = resource();
    // 双方一致删除。
    let deleted = merge_structured(
        &MergeInput {
            resource: &resource,
            base: Some(b"{\"a\": 1}"),
            ours: None,
            theirs: None,
        },
        StructuredFormat::Json,
    )
    .expect("merge");
    assert_eq!(deleted, MergeResult::Deleted);

    // 一侧删除、另一侧修改 → DeleteModify（文件级）。
    let conflict = merge_structured(
        &MergeInput {
            resource: &resource,
            base: Some(b"{\"a\": 1}"),
            ours: None,
            theirs: Some(b"{\"a\": 2}"),
        },
        StructuredFormat::Json,
    )
    .expect("merge");
    assert_eq!(
        conflict.conflict().expect("conflict").kind,
        ConflictKind::DeleteModify
    );
}
