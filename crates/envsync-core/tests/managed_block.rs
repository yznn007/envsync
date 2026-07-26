//! Full File 与 Managed Block 渲染的行为测试。
//!
//! 这里的每个用例都对应设计文档「文件管理模式」一节的一条硬性约束：
//! 块外字节必须逐字保留、marker 异常必须拒绝而不是猜测修复、渲染必须是纯函数。

use envsync_core::render::{
    detect_line_ending, extract_managed_block, remove_managed_block, render, RenderError,
    RenderInput, RenderedChange, DEFAULT_COMMENT_PREFIX, MANAGED_BLOCK_BEGIN, MANAGED_BLOCK_END,
};
use envsync_domain::id::ResourceId;
use envsync_domain::resource::{FileMode, LineEnding, ResourcePolicy};
use proptest::prelude::*;

const MAIN: &str = "shell/zsh/main";

/// 构造资源标识。
fn rid(text: &str) -> ResourceId {
    ResourceId::parse(text).expect("测试用资源标识必须合法")
}

/// 构造只改换行策略的资源策略。
fn policy(line_ending: LineEnding) -> ResourcePolicy {
    ResourcePolicy {
        line_ending,
        ..ResourcePolicy::default()
    }
}

/// 构造渲染输入（使用默认注释前缀）。
fn input<'a>(
    resource: &'a ResourceId,
    existing: Option<&'a [u8]>,
    desired: &'a [u8],
    mode: FileMode,
    policy: &'a ResourcePolicy,
) -> RenderInput<'a> {
    RenderInput {
        resource,
        existing,
        desired,
        mode,
        policy,
        comment_prefix: DEFAULT_COMMENT_PREFIX,
    }
}

/// 取出写入字节，非写入时直接失败。
fn written(change: RenderedChange) -> Vec<u8> {
    match change {
        RenderedChange::Write(bytes) => bytes,
        RenderedChange::Unchanged => panic!("期望产生写入，实际是 Unchanged"),
    }
}

/// 渲染并返回写入字节。
fn render_written(input: &RenderInput<'_>) -> Vec<u8> {
    written(render(input).expect("渲染应当成功"))
}

/// 拼出一个受管区块（LF 换行）。
fn block(resource: &str, inner: &str) -> String {
    format!("{DEFAULT_COMMENT_PREFIX}{MANAGED_BLOCK_BEGIN}{resource}\n{inner}{DEFAULT_COMMENT_PREFIX}{MANAGED_BLOCK_END}{resource}\n")
}

/// 便于阅读断言失败信息。
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// ---------------------------------------------------------------------------
// Full File
// ---------------------------------------------------------------------------

/// Full File 在 Preserve 下逐字节保留 desired，包括二进制和混合换行。
#[test]
fn full_file_preserves_bytes_exactly() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    let desired: &[u8] = b"\x00\x01\xff binary\r\nmixed\nno-trailing-newline";
    let out = render_written(&input(
        &resource,
        None,
        desired,
        FileMode::FullFile,
        &policy,
    ));
    assert_eq!(out, desired);
}

/// 非 UTF-8 内容在 Full File 下允许（对照 Managed Block 的 NotUtf8）。
#[test]
fn full_file_allows_non_utf8() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    let desired: &[u8] = &[0xff, 0xfe, 0x00, 0x80];
    let out = render_written(&input(
        &resource,
        Some(b"old"),
        desired,
        FileMode::FullFile,
        &policy,
    ));
    assert_eq!(out, desired);
}

/// 策略指定 CRLF/LF 时，Full File 才做整体换行转换。
#[test]
fn full_file_normalizes_line_endings_when_policy_demands() {
    let resource = rid(MAIN);

    let crlf = policy(LineEnding::Crlf);
    let out = render_written(&input(
        &resource,
        None,
        b"a\nb\r\nc\n",
        FileMode::FullFile,
        &crlf,
    ));
    assert_eq!(text(&out), "a\r\nb\r\nc\r\n");

    let lf = policy(LineEnding::Lf);
    let out = render_written(&input(
        &resource,
        None,
        b"a\r\nb\nc\r\n",
        FileMode::FullFile,
        &lf,
    ));
    assert_eq!(text(&out), "a\nb\nc\n");
}

/// 内容已一致时返回 Unchanged。
#[test]
fn full_file_unchanged_when_identical() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    let content = b"export EDITOR=nvim\n";
    let change = render(&input(
        &resource,
        Some(content),
        content,
        FileMode::FullFile,
        &policy,
    ))
    .expect("渲染应当成功");
    assert_eq!(change, RenderedChange::Unchanged);
}

// ---------------------------------------------------------------------------
// Managed Block：插入、更新、追加
// ---------------------------------------------------------------------------

/// 文件不存在时生成只含该区块的合法新文件。
#[test]
fn managed_block_creates_new_file_when_target_absent() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    let out = render_written(&input(
        &resource,
        None,
        b"export EDITOR=nvim\n",
        FileMode::ManagedBlock,
        &policy,
    ));
    assert_eq!(text(&out), block(MAIN, "export EDITOR=nvim\n"));
}

/// 期望内容缺末尾换行时自动补齐，保证结束 marker 独占一行。
#[test]
fn managed_block_appends_trailing_newline_to_inner() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    let out = render_written(&input(
        &resource,
        None,
        b"export EDITOR=nvim",
        FileMode::ManagedBlock,
        &policy,
    ));
    assert_eq!(text(&out), block(MAIN, "export EDITOR=nvim\n"));
}

/// 空期望内容生成空块，且可被 extract 还原成空字节。
#[test]
fn managed_block_supports_empty_inner() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    let out = render_written(&input(
        &resource,
        None,
        b"",
        FileMode::ManagedBlock,
        &policy,
    ));
    assert_eq!(text(&out), block(MAIN, ""));
    assert_eq!(
        extract_managed_block(&out, &resource).expect("抽取应当成功"),
        Some(Vec::new())
    );
}

/// 已有区块时只替换块内内容，块外与 marker 行逐字保留。
#[test]
fn managed_block_updates_only_inner_content() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    let existing = format!("头部\n\n{}\n尾部\n", block(MAIN, "旧内容\n"));
    let out = render_written(&input(
        &resource,
        Some(existing.as_bytes()),
        "新内容 A\n新内容 B\n".as_bytes(),
        FileMode::ManagedBlock,
        &policy,
    ));
    let expected = format!("头部\n\n{}\n尾部\n", block(MAIN, "新内容 A\n新内容 B\n"));
    assert_eq!(text(&out), expected);
}

/// 文件存在但没有区块时追加到末尾；追加前补齐换行。
#[test]
fn managed_block_appends_when_block_missing() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    let existing = b"line1\nline2";
    let out = render_written(&input(
        &resource,
        Some(existing),
        b"managed\n",
        FileMode::ManagedBlock,
        &policy,
    ));
    assert_eq!(
        text(&out),
        format!("line1\nline2\n{}", block(MAIN, "managed\n"))
    );
}

/// 空文件追加时不额外插入空行。
#[test]
fn managed_block_appends_to_empty_file_without_extra_newline() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    let out = render_written(&input(
        &resource,
        Some(b""),
        b"managed\n",
        FileMode::ManagedBlock,
        &policy,
    ));
    assert_eq!(text(&out), block(MAIN, "managed\n"));
}

/// 已经处于期望状态时返回 Unchanged（幂等）。
#[test]
fn managed_block_is_idempotent() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    let existing = format!("前\n{}后\n", block(MAIN, "managed\n"));
    let change = render(&input(
        &resource,
        Some(existing.as_bytes()),
        b"managed\n",
        FileMode::ManagedBlock,
        &policy,
    ))
    .expect("渲染应当成功");
    assert_eq!(change, RenderedChange::Unchanged);

    // 对渲染产物再渲染一次同样是 Unchanged。
    let created = render_written(&input(
        &resource,
        None,
        b"managed\n",
        FileMode::ManagedBlock,
        &policy,
    ));
    let again = render(&input(
        &resource,
        Some(&created),
        b"managed\n",
        FileMode::ManagedBlock,
        &policy,
    ))
    .expect("渲染应当成功");
    assert_eq!(again, RenderedChange::Unchanged);
}

/// 渲染是纯函数：同样输入两次调用逐字节相同。
#[test]
fn render_is_pure_and_deterministic() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    let existing = format!("前\n{}后\n", block(MAIN, "旧\n"));
    let request = input(
        &resource,
        Some(existing.as_bytes()),
        "新\n".as_bytes(),
        FileMode::ManagedBlock,
        &policy,
    );
    let first = render(&request).expect("渲染应当成功");
    let second = render(&request).expect("渲染应当成功");
    assert_eq!(first, second);
    assert!(first.is_write());
}

// ---------------------------------------------------------------------------
// marker 识别
// ---------------------------------------------------------------------------

/// marker 行允许首尾空白，且 marker 行本身逐字保留。
#[test]
fn managed_block_marker_tolerates_surrounding_whitespace() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    let existing =
        format!("\t  # {MANAGED_BLOCK_BEGIN}{MAIN}  \n旧\n   # {MANAGED_BLOCK_END}{MAIN}\t\n");
    let out = render_written(&input(
        &resource,
        Some(existing.as_bytes()),
        "新\n".as_bytes(),
        FileMode::ManagedBlock,
        &policy,
    ));
    assert_eq!(
        text(&out),
        format!("\t  # {MANAGED_BLOCK_BEGIN}{MAIN}  \n新\n   # {MANAGED_BLOCK_END}{MAIN}\t\n")
    );
}

/// 只认整行 marker：代码行里提到 marker 文本不算 marker。
#[test]
fn managed_block_ignores_marker_text_inside_code_lines() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    let existing = format!("echo \"# {MANAGED_BLOCK_BEGIN}{MAIN}\"\n");
    assert_eq!(
        extract_managed_block(existing.as_bytes(), &resource).expect("抽取应当成功"),
        None
    );
    let out = render_written(&input(
        &resource,
        Some(existing.as_bytes()),
        b"managed\n",
        FileMode::ManagedBlock,
        &policy,
    ));
    assert_eq!(
        text(&out),
        format!("{existing}{}", block(MAIN, "managed\n"))
    );
}

/// 资源标识必须精确匹配：不同资源的 marker 互不干扰。
#[test]
fn managed_block_requires_exact_resource_match() {
    let resource = rid(MAIN);
    let existing = format!(
        "# {MANAGED_BLOCK_BEGIN}shell/zsh/mainx\n干扰\n# {MANAGED_BLOCK_END}shell/zsh/mainx\n"
    );
    assert_eq!(
        extract_managed_block(existing.as_bytes(), &resource).expect("抽取应当成功"),
        None
    );
}

// ---------------------------------------------------------------------------
// marker 异常一律拒绝
// ---------------------------------------------------------------------------

/// 只有开始 marker：报 UnterminatedBlock。
#[test]
fn managed_block_rejects_unterminated_block() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    let existing = format!("头\n# {MANAGED_BLOCK_BEGIN}{MAIN}\n内容\n");
    let err = render(&input(
        &resource,
        Some(existing.as_bytes()),
        b"x\n",
        FileMode::ManagedBlock,
        &policy,
    ))
    .expect_err("必须拒绝");
    assert_eq!(
        err,
        RenderError::UnterminatedBlock {
            resource: resource.clone(),
            line: 2
        }
    );
    assert_eq!(err.code(), "render.unterminated_block");
}

/// 只有结束 marker：报 MisorderedBlock。
#[test]
fn managed_block_rejects_lone_end_marker() {
    let resource = rid(MAIN);
    let existing = format!("头\n# {MANAGED_BLOCK_END}{MAIN}\n");
    let err = extract_managed_block(existing.as_bytes(), &resource).expect_err("必须拒绝");
    assert_eq!(
        err,
        RenderError::MisorderedBlock {
            resource: resource.clone(),
            line: 2
        }
    );
    assert_eq!(err.code(), "render.misordered_block");
}

/// 结束 marker 出现在开始 marker 之前：报 MisorderedBlock。
#[test]
fn managed_block_rejects_misordered_markers() {
    let resource = rid(MAIN);
    let existing = format!(
        "# {MANAGED_BLOCK_END}{MAIN}\n内容\n# {MANAGED_BLOCK_BEGIN}{MAIN}\n# {MANAGED_BLOCK_END}{MAIN}\n"
    );
    let err = remove_managed_block(existing.as_bytes(), &resource).expect_err("必须拒绝");
    assert_eq!(
        err,
        RenderError::MisorderedBlock {
            resource: resource.clone(),
            line: 1
        }
    );
}

/// 同一资源出现两个区块：报 DuplicateBlock 并给出两处行号。
#[test]
fn managed_block_rejects_duplicate_blocks() {
    let resource = rid(MAIN);
    let existing = format!("{}{}", block(MAIN, "一\n"), block(MAIN, "二\n"));
    let err = extract_managed_block(existing.as_bytes(), &resource).expect_err("必须拒绝");
    assert_eq!(
        err,
        RenderError::DuplicateBlock {
            resource: resource.clone(),
            first_line: 1,
            second_line: 4
        }
    );
    assert_eq!(err.code(), "render.duplicate_block");
}

/// 块内再次出现开始 marker：报 NestedBlock。
#[test]
fn managed_block_rejects_nested_blocks() {
    let resource = rid(MAIN);
    let existing = format!(
        "# {MANAGED_BLOCK_BEGIN}{MAIN}\n内\n# {MANAGED_BLOCK_BEGIN}{MAIN}\n内\n# {MANAGED_BLOCK_END}{MAIN}\n"
    );
    let err = extract_managed_block(existing.as_bytes(), &resource).expect_err("必须拒绝");
    assert_eq!(
        err,
        RenderError::NestedBlock {
            resource: resource.clone(),
            line: 3
        }
    );
    assert_eq!(err.code(), "render.nested_block");
}

/// marker 行资源标识后带多余内容：报 MalformedMarker。
#[test]
fn managed_block_rejects_malformed_marker() {
    let resource = rid(MAIN);
    let existing =
        format!("# {MANAGED_BLOCK_BEGIN}{MAIN} extra\n内\n# {MANAGED_BLOCK_END}{MAIN}\n");
    let err = extract_managed_block(existing.as_bytes(), &resource).expect_err("必须拒绝");
    match &err {
        RenderError::MalformedMarker {
            resource: got,
            line,
            ..
        } => {
            assert_eq!(got, &resource);
            assert_eq!(*line, 1);
        }
        other => panic!("期望 MalformedMarker，实际 {other:?}"),
    }
    assert_eq!(err.code(), "render.malformed_marker");
}

/// 注释前缀含字母会破坏 marker 识别，必须提前拒绝。
#[test]
fn managed_block_rejects_alphanumeric_comment_prefix() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    let request = RenderInput {
        resource: &resource,
        existing: None,
        desired: b"x\n",
        mode: FileMode::ManagedBlock,
        policy: &policy,
        comment_prefix: "REM ",
    };
    let err = render(&request).expect_err("必须拒绝");
    assert_eq!(err.code(), "render.malformed_marker");
}

/// 非 UTF-8 文件禁止 Managed Block。
#[test]
fn managed_block_rejects_non_utf8_file() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    let existing: &[u8] = &[0xff, 0xfe, b'\n'];
    let err = render(&input(
        &resource,
        Some(existing),
        b"x\n",
        FileMode::ManagedBlock,
        &policy,
    ))
    .expect_err("必须拒绝");
    assert_eq!(
        err,
        RenderError::NotUtf8 {
            resource: resource.clone()
        }
    );
    assert_eq!(err.code(), "render.not_utf8");

    assert_eq!(
        extract_managed_block(existing, &resource).expect_err("必须拒绝"),
        RenderError::NotUtf8 { resource }
    );
}

/// M0 不支持 StructuredMerge / GeneratedInclude。
#[test]
fn render_rejects_unsupported_modes() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    for mode in [FileMode::StructuredMerge, FileMode::GeneratedInclude] {
        let err = render(&input(&resource, None, b"x\n", mode, &policy)).expect_err("必须拒绝");
        assert_eq!(err, RenderError::UnsupportedMode { mode });
        assert_eq!(err.code(), "render.unsupported_mode");
    }
}

/// 超过 max_bytes 时报 TooLarge，不截断。
#[test]
fn render_rejects_output_over_max_bytes() {
    let resource = rid(MAIN);
    let policy = ResourcePolicy {
        max_bytes: 8,
        ..ResourcePolicy::default()
    };
    let desired = vec![b'a'; 64];
    let err = render(&input(
        &resource,
        None,
        &desired,
        FileMode::FullFile,
        &policy,
    ))
    .expect_err("必须拒绝");
    assert_eq!(
        err,
        RenderError::TooLarge {
            limit: 8,
            actual: 64
        }
    );
    assert_eq!(err.code(), "render.too_large");

    // Managed Block 计算的是渲染后的完整文件长度。
    let err = render(&input(
        &resource,
        None,
        b"x\n",
        FileMode::ManagedBlock,
        &policy,
    ))
    .expect_err("必须拒绝");
    assert_eq!(err.code(), "render.too_large");
}

// ---------------------------------------------------------------------------
// 换行策略
// ---------------------------------------------------------------------------

/// detect_line_ending 按主导风格判定，且永不返回 Preserve。
#[test]
fn detect_line_ending_follows_majority() {
    assert_eq!(detect_line_ending(None), LineEnding::Lf);
    assert_eq!(detect_line_ending(Some(b"no newline")), LineEnding::Lf);
    assert_eq!(detect_line_ending(Some(b"a\r\nb\r\n")), LineEnding::Crlf);
    assert_eq!(detect_line_ending(Some(b"a\nb\n")), LineEnding::Lf);
    // 平局时保守选择 LF。
    assert_eq!(detect_line_ending(Some(b"a\r\nb\n")), LineEnding::Lf);
    assert_eq!(detect_line_ending(Some(b"a\r\nb\r\nc\n")), LineEnding::Crlf);
}

/// Preserve 时块内换行沿用现有文件的 CRLF 风格，块外不动。
#[test]
fn managed_block_preserve_follows_existing_crlf() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    let existing = format!(
        "头\r\n# {MANAGED_BLOCK_BEGIN}{MAIN}\r\n旧\r\n# {MANAGED_BLOCK_END}{MAIN}\r\n尾\r\n"
    );
    let out = render_written(&input(
        &resource,
        Some(existing.as_bytes()),
        "新 A\n新 B\n".as_bytes(),
        FileMode::ManagedBlock,
        &policy,
    ));
    assert_eq!(
        text(&out),
        format!(
            "头\r\n# {MANAGED_BLOCK_BEGIN}{MAIN}\r\n新 A\r\n新 B\r\n# {MANAGED_BLOCK_END}{MAIN}\r\n尾\r\n"
        )
    );
}

/// 文件不存在且策略为 Preserve 时使用 LF。
#[test]
fn managed_block_preserve_defaults_to_lf_for_new_file() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    let out = render_written(&input(
        &resource,
        None,
        b"a\r\nb\r\n",
        FileMode::ManagedBlock,
        &policy,
    ));
    assert_eq!(text(&out), block(MAIN, "a\nb\n"));
}

/// 显式 LF/CRLF 会强制转换整个输出文件。
#[test]
fn managed_block_forced_line_ending_rewrites_whole_file() {
    let resource = rid(MAIN);
    let existing = format!(
        "头\r\n# {MANAGED_BLOCK_BEGIN}{MAIN}\r\n旧\r\n# {MANAGED_BLOCK_END}{MAIN}\r\n尾\r\n"
    );

    let lf = policy(LineEnding::Lf);
    let out = render_written(&input(
        &resource,
        Some(existing.as_bytes()),
        "新\n".as_bytes(),
        FileMode::ManagedBlock,
        &lf,
    ));
    assert_eq!(
        text(&out),
        format!("头\n# {MANAGED_BLOCK_BEGIN}{MAIN}\n新\n# {MANAGED_BLOCK_END}{MAIN}\n尾\n")
    );

    let crlf = policy(LineEnding::Crlf);
    let plain = format!("头\n# {MANAGED_BLOCK_BEGIN}{MAIN}\n旧\n# {MANAGED_BLOCK_END}{MAIN}\n尾\n");
    let out = render_written(&input(
        &resource,
        Some(plain.as_bytes()),
        "新\n".as_bytes(),
        FileMode::ManagedBlock,
        &crlf,
    ));
    assert_eq!(
        text(&out),
        format!(
            "头\r\n# {MANAGED_BLOCK_BEGIN}{MAIN}\r\n新\r\n# {MANAGED_BLOCK_END}{MAIN}\r\n尾\r\n"
        )
    );
}

// ---------------------------------------------------------------------------
// 块外内容保护
// ---------------------------------------------------------------------------

/// 强测试：块外含 CRLF、制表符、非 ASCII 注释和 marker 仿冒行时逐字节保留。
#[test]
fn managed_block_preserves_outside_bytes_verbatim() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    let before = format!(
        "# 头部注释：中文 café ✅\r\n\t\techo\t'tab 缩进'\r\n\
         # {MANAGED_BLOCK_BEGIN}shell/zsh/other\r\n\
         echo \"# {MANAGED_BLOCK_BEGIN}{MAIN}\"\r\n\r\n"
    );
    let existing_block =
        format!("  # {MANAGED_BLOCK_BEGIN}{MAIN}\r\n旧\r\n  # {MANAGED_BLOCK_END}{MAIN}\r\n");
    let after = "\r\n# 尾部注释 ✅\r\n\t保留缩进\r\n没有结尾换行";
    let existing = format!("{before}{existing_block}{after}");

    let out = render_written(&input(
        &resource,
        Some(existing.as_bytes()),
        "新 1\n新 2\n".as_bytes(),
        FileMode::ManagedBlock,
        &policy,
    ));

    let expected_block = format!(
        "  # {MANAGED_BLOCK_BEGIN}{MAIN}\r\n新 1\r\n新 2\r\n  # {MANAGED_BLOCK_END}{MAIN}\r\n"
    );
    assert_eq!(text(&out), format!("{before}{expected_block}{after}"));
    assert!(out.starts_with(before.as_bytes()), "块前字节必须逐字保留");
    assert!(out.ends_with(after.as_bytes()), "块后字节必须逐字保留");
}

/// 同一文件里三个资源的区块共存，更新中间那个，另外两个完全不变。
#[test]
fn managed_block_updates_only_target_resource() {
    let first = rid("shell/zsh/first");
    let middle = rid("shell/zsh/middle");
    let last = rid("shell/zsh/last");
    let policy = policy(LineEnding::Preserve);

    let head = "# 顶部\n";
    let first_block = block("shell/zsh/first", "第一块\n");
    let middle_block = block("shell/zsh/middle", "旧的中间块\n");
    let last_block = block("shell/zsh/last", "第三块\n");
    let existing = format!("{head}{first_block}\n{middle_block}\n{last_block}# 底部\n");

    let out = render_written(&input(
        &middle,
        Some(existing.as_bytes()),
        "新的中间块 A\n新的中间块 B\n".as_bytes(),
        FileMode::ManagedBlock,
        &policy,
    ));

    let new_middle = block("shell/zsh/middle", "新的中间块 A\n新的中间块 B\n");
    assert_eq!(
        text(&out),
        format!("{head}{first_block}\n{new_middle}\n{last_block}# 底部\n")
    );
    assert_eq!(
        extract_managed_block(&out, &first).expect("抽取应当成功"),
        Some(b"\xe7\xac\xac\xe4\xb8\x80\xe5\x9d\x97\n".to_vec())
    );
    assert_eq!(
        extract_managed_block(&out, &last).expect("抽取应当成功"),
        Some("第三块\n".as_bytes().to_vec())
    );
}

// ---------------------------------------------------------------------------
// extract / remove
// ---------------------------------------------------------------------------

/// render 与 extract 的往返一致性。
#[test]
fn extract_round_trips_with_render() {
    let resource = rid(MAIN);
    let policy = policy(LineEnding::Preserve);
    for desired in [
        "export EDITOR=nvim\n".as_bytes(),
        "多行\n内容 with tabs\t\n".as_bytes(),
        "".as_bytes(),
    ] {
        let rendered = render_written(&input(
            &resource,
            None,
            desired,
            FileMode::ManagedBlock,
            &policy,
        ));
        assert_eq!(
            extract_managed_block(&rendered, &resource).expect("抽取应当成功"),
            Some(desired.to_vec()),
        );
    }
}

/// 已有文件中插入区块后同样能抽取回原内容。
#[test]
fn extract_returns_inner_of_existing_block() {
    let resource = rid(MAIN);
    let existing = format!("前\n{}后\n", block(MAIN, "受管内容\n"));
    assert_eq!(
        extract_managed_block(existing.as_bytes(), &resource).expect("抽取应当成功"),
        Some("受管内容\n".as_bytes().to_vec())
    );
}

/// 没有区块时 extract 返回 None。
#[test]
fn extract_returns_none_without_block() {
    let resource = rid(MAIN);
    assert_eq!(
        extract_managed_block(b"just a file\n", &resource).expect("抽取应当成功"),
        None
    );
}

/// remove 后 extract 返回 None，且块外内容逐字不变。
#[test]
fn remove_deletes_block_and_keeps_outside() {
    let resource = rid(MAIN);
    let before = "前置\n\t缩进\n";
    let after = "\n后置\n";
    let existing = format!("{before}{}{after}", block(MAIN, "受管内容\n"));

    let removed = remove_managed_block(existing.as_bytes(), &resource)
        .expect("移除应当成功")
        .expect("应当找到区块");
    assert_eq!(text(&removed), format!("{before}{after}"));
    assert_eq!(
        extract_managed_block(&removed, &resource).expect("抽取应当成功"),
        None
    );
}

/// 本来就没有区块时 remove 返回 None（不产生写入）。
#[test]
fn remove_returns_none_when_block_absent() {
    let resource = rid(MAIN);
    assert_eq!(
        remove_managed_block(b"nothing here\n", &resource).expect("移除应当成功"),
        None
    );
}

/// remove 只删除目标资源的区块。
#[test]
fn remove_keeps_other_resources() {
    let target = rid("shell/zsh/middle");
    let other = rid("shell/zsh/first");
    let existing = format!(
        "{}{}",
        block("shell/zsh/first", "保留\n"),
        block("shell/zsh/middle", "删除\n")
    );
    let removed = remove_managed_block(existing.as_bytes(), &target)
        .expect("移除应当成功")
        .expect("应当找到区块");
    assert_eq!(text(&removed), block("shell/zsh/first", "保留\n"));
    assert_eq!(
        extract_managed_block(&removed, &other).expect("抽取应当成功"),
        Some("保留\n".as_bytes().to_vec())
    );
}

// ---------------------------------------------------------------------------
// 属性测试
// ---------------------------------------------------------------------------

/// 块外内容取自不含 marker 字符（`>`、`<`、`:`）的字符集，保证生成的文件里
/// 只有构造出来的那一个区块。
const OUTSIDE: &str = "[a-zA-Z0-9 \t\n#=_-]{0,64}";

proptest! {
    /// 任意「前缀 + 区块 + 后缀」的文件，替换块内内容后前后缀逐字节不变。
    #[test]
    fn prop_outside_bytes_never_change(
        prefix in OUTSIDE,
        old_inner in OUTSIDE,
        new_inner in OUTSIDE,
        suffix in OUTSIDE,
    ) {
        let resource = rid(MAIN);
        let policy = policy(LineEnding::Preserve);

        // 区块必须从行首开始。
        let mut head = prefix;
        if !head.is_empty() && !head.ends_with('\n') {
            head.push('\n');
        }
        let mut old_body = old_inner;
        if !old_body.is_empty() && !old_body.ends_with('\n') {
            old_body.push('\n');
        }
        let mut new_body = new_inner;
        if !new_body.is_empty() && !new_body.ends_with('\n') {
            new_body.push('\n');
        }

        let existing = format!("{head}{}{suffix}", block(MAIN, &old_body));
        let out = render_written(&input(
            &resource,
            Some(existing.as_bytes()),
            new_body.as_bytes(),
            FileMode::ManagedBlock,
            &policy,
        ));

        prop_assert_eq!(
            String::from_utf8(out.clone()).expect("输出应为 UTF-8"),
            format!("{head}{}{suffix}", block(MAIN, &new_body))
        );
        prop_assert!(out.starts_with(head.as_bytes()));
        prop_assert!(out.ends_with(suffix.as_bytes()));
        prop_assert_eq!(
            extract_managed_block(&out, &resource).expect("抽取应当成功"),
            Some(new_body.as_bytes().to_vec())
        );
    }
}
