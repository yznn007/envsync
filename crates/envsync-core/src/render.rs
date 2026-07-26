//! 文件渲染：Full File、Managed Block 与 Structured Merge 的落盘语义。
//!
//! 本模块只做**纯计算**：输入是「目标文件现有字节 + 期望受管内容 + 资源策略」，
//! 输出是「应当写入的完整文件字节」或「无需写入」。它不读文件系统、不取时钟、
//! 不使用随机数，因此相同输入必然产生逐字节相同的输出，可以被计划阶段安全地
//! 反复调用（预演与实际应用必须得到同一结果）。
//!
//! # Structured Merge 与本模块的分工
//!
//! [`FileMode::StructuredMerge`] 描述的是**跨设备协调时用哪种语义去比较和合并**，
//! 而不是「写盘时怎么写」。真正的结构化合并发生在 [`crate::sync`] 的 merge 阶段：
//! 那里同时拿得到 base / ours / theirs 三侧内容，按
//! [`envsync_domain::StructuredFormat`] 选择 [`crate::merge`] 里的合并器，算出一份
//! **权威字节**并写进新的 Blob。
//!
//! 等这份权威字节流到渲染阶段时，合并已经结束：此处只剩「把它整份写进目标文件」这
//! 一件事。因此本模块对 `StructuredMerge` 采用与 [`FileMode::FullFile`] **完全相同**
//! 的语义——期望内容即完整文件内容。
//!
//! ```text
//! sync::merge_states   base + ours + theirs ──合并器──▶ 权威字节（新 Blob）
//! planner::build_plan  权威字节 + 目标现状 ──render──▶ 待写入的完整文件
//! ```
//!
//! 之所以**不**在渲染阶段再做一次结构化合并：渲染阶段只有 `existing` 与 `desired`，
//! 没有 base。缺 base 的「合并」只能靠猜，而猜错的代价是把另一台设备的改动当成删除。
//! 让权威性只在一个地方产生，是这条分工的全部意义。
//!
//! # Managed Block 的 marker 形状
//!
//! ```text
//! # >>> envsync:shell/zsh/main
//! export EDITOR=nvim
//! # <<< envsync:shell/zsh/main
//! ```
//!
//! 其中 `# ` 是注释前缀（由调用方按目标文件语法给出），`>>> envsync:` 与
//! `<<< envsync:` 是固定中缀，后面紧跟资源标识。
//!
//! # 安全约束
//!
//! 遇到缺一端、重复、嵌套、顺序颠倒的 marker 时一律返回错误，**绝不猜测修复**：
//! 用户文件里的 marker 异常通常意味着人工编辑冲突或文件损坏，静默「修好」它会
//! 造成不可见的数据丢失。

use std::str;

use envsync_domain::id::ResourceId;
use envsync_domain::resource::{FileMode, LineEnding, ResourcePolicy};

/// 受管区块开始 marker 的固定中缀。
pub const MANAGED_BLOCK_BEGIN: &str = ">>> envsync:";
/// 受管区块结束 marker 的固定中缀。
pub const MANAGED_BLOCK_END: &str = "<<< envsync:";
/// 默认注释前缀（shell、ini、toml 等 `#` 系语法）。
pub const DEFAULT_COMMENT_PREFIX: &str = "# ";

/// 一次渲染所需的全部输入。
///
/// 所有字段都是借用或 `Copy` 值，构造它不会发生任何 I/O。
#[derive(Debug, Clone, Copy)]
pub struct RenderInput<'a> {
    /// 被渲染的资源标识；同时决定 marker 中的标识文本。
    pub resource: &'a ResourceId,
    /// 目标文件现有内容；`None` 表示文件不存在。
    pub existing: Option<&'a [u8]>,
    /// 期望的受管内容。
    ///
    /// Full File 与 Structured Merge 下即整个文件内容；Managed Block 下是块内内容。
    pub desired: &'a [u8],
    /// 文件管理模式。
    ///
    /// 支持 [`FileMode::FullFile`]、[`FileMode::ManagedBlock`] 与
    /// [`FileMode::StructuredMerge`]（按 Full File 语义落盘，见模块级文档）；
    /// [`FileMode::GeneratedInclude`] 不是渲染模式，会被拒绝。
    pub mode: FileMode,
    /// 资源策略，提供换行风格与字节上限。
    pub policy: &'a ResourcePolicy,
    /// 注释前缀，例如 `"# "`（shell）、`"-- "`（lua）、`"// "`（jsonc）。
    pub comment_prefix: &'a str,
}

/// 渲染结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderedChange {
    /// 需要写入的**完整文件内容**。
    Write(Vec<u8>),
    /// 目标已符合期望，无需写入。
    Unchanged,
}

impl RenderedChange {
    /// 是否需要写入。
    pub fn is_write(&self) -> bool {
        matches!(self, RenderedChange::Write(_))
    }

    /// 取出待写入字节；`Unchanged` 时返回 `None`。
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            RenderedChange::Write(bytes) => Some(bytes),
            RenderedChange::Unchanged => None,
        }
    }
}

/// 渲染阶段的错误。
///
/// 每个变体都有稳定的 [`RenderError::code`]，用于日志、诊断和跨版本比对；
/// 展示文案可以改，code 不可以。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RenderError {
    /// Managed Block 要求目标文件是合法 UTF-8。
    #[error("资源 {resource} 的内容不是合法 UTF-8，Managed Block 模式无法处理")]
    NotUtf8 {
        /// 出错的资源。
        resource: ResourceId,
    },
    /// 只有开始 marker 没有结束 marker。
    #[error("资源 {resource} 的受管区块在第 {line} 行开始但没有结束 marker")]
    UnterminatedBlock {
        /// 出错的资源。
        resource: ResourceId,
        /// 未配对的开始 marker 所在行号（从 1 开始）。
        line: usize,
    },
    /// 同一文件里出现了同一资源的两个受管区块。
    #[error("资源 {resource} 存在重复受管区块：第 {first_line} 行与第 {second_line} 行")]
    DuplicateBlock {
        /// 出错的资源。
        resource: ResourceId,
        /// 第一个区块的开始 marker 行号。
        first_line: usize,
        /// 第二个区块的开始 marker 行号。
        second_line: usize,
    },
    /// 区块内部再次出现开始 marker。
    #[error("资源 {resource} 的受管区块内第 {line} 行出现嵌套开始 marker")]
    NestedBlock {
        /// 出错的资源。
        resource: ResourceId,
        /// 嵌套开始 marker 所在行号。
        line: usize,
    },
    /// 结束 marker 出现在开始 marker 之前（含没有开始 marker 的孤立结束 marker）。
    #[error("资源 {resource} 的结束 marker 出现在开始 marker 之前：第 {line} 行")]
    MisorderedBlock {
        /// 出错的资源。
        resource: ResourceId,
        /// 孤立结束 marker 所在行号。
        line: usize,
    },
    /// marker 行本身格式非法。
    #[error("资源 {resource} 第 {line} 行的 marker 格式非法：{detail}")]
    MalformedMarker {
        /// 出错的资源。
        resource: ResourceId,
        /// 出错行号；`0` 表示问题来自调用方传入的注释前缀而非文件内容。
        line: usize,
        /// 具体原因。
        detail: String,
    },
    /// 该模式没有对应的落盘语义。
    ///
    /// 目前只有 [`FileMode::GeneratedInclude`] 会触发：它由适配器拆成 Full File +
    /// Managed Block 两个资源实现，见 `docs/adapters.md`。
    #[error("文件模式 {mode:?} 没有对应的落盘语义（Generated Include 由适配器拆成两个资源实现）")]
    UnsupportedMode {
        /// 不支持的模式。
        mode: FileMode,
    },
    /// 渲染结果超过资源策略允许的字节上限。
    #[error("渲染结果 {actual} 字节超过上限 {limit} 字节")]
    TooLarge {
        /// 策略允许的上限。
        limit: u64,
        /// 实际渲染出的字节数。
        actual: u64,
    },
}

impl RenderError {
    /// 稳定错误码。
    pub fn code(&self) -> &'static str {
        match self {
            RenderError::NotUtf8 { .. } => "render.not_utf8",
            RenderError::UnterminatedBlock { .. } => "render.unterminated_block",
            RenderError::DuplicateBlock { .. } => "render.duplicate_block",
            RenderError::NestedBlock { .. } => "render.nested_block",
            RenderError::MisorderedBlock { .. } => "render.misordered_block",
            RenderError::MalformedMarker { .. } => "render.malformed_marker",
            RenderError::UnsupportedMode { .. } => "render.unsupported_mode",
            RenderError::TooLarge { .. } => "render.too_large",
        }
    }
}

/// 纯函数渲染：`existing + desired + policy -> RenderedChange`。
///
/// 返回 [`RenderedChange::Unchanged`] 当且仅当渲染结果与 `existing` 逐字节相同，
/// 因此本函数天然幂等：对已经处于期望状态的文件再次渲染不会产生写入。
pub fn render(input: &RenderInput<'_>) -> Result<RenderedChange, RenderError> {
    let output = match input.mode {
        // Structured Merge 的合并已经在 `sync` 阶段完成，落到本地的就是合并后的
        // 权威字节，因此写盘语义与 Full File 完全一致（见模块级文档）。
        FileMode::FullFile | FileMode::StructuredMerge => render_full_file(input),
        FileMode::ManagedBlock => render_managed_block(input)?,
        mode => return Err(RenderError::UnsupportedMode { mode }),
    };

    let actual = output.len() as u64;
    if actual > input.policy.max_bytes {
        return Err(RenderError::TooLarge {
            limit: input.policy.max_bytes,
            actual,
        });
    }

    match input.existing {
        Some(existing) if existing == output.as_slice() => Ok(RenderedChange::Unchanged),
        _ => Ok(RenderedChange::Write(output)),
    }
}

/// 从现有文件中抽取受管区块的块内内容（capture 用）。
///
/// 文件中没有该资源的区块时返回 `Ok(None)`；区块存在时返回块内的**原始字节**
/// （包含最后一行的换行符，不做任何换行规范化）。
pub fn extract_managed_block(
    existing: &[u8],
    resource: &ResourceId,
) -> Result<Option<Vec<u8>>, RenderError> {
    let text = decode_utf8(existing, resource)?;
    let span = find_block(text, resource)?;
    Ok(span.map(|span| text.as_bytes()[span.inner_start..span.inner_end].to_vec()))
}

/// 从现有文件中移除受管区块（`ensure_absent` 的块级删除用）。
///
/// 返回移除后的完整文件内容；原本就没有该区块时返回 `Ok(None)`。移除范围恰好是
/// 「开始 marker 行首」到「结束 marker 行尾（含换行）」，块外字节逐字保留。
pub fn remove_managed_block(
    existing: &[u8],
    resource: &ResourceId,
) -> Result<Option<Vec<u8>>, RenderError> {
    let text = decode_utf8(existing, resource)?;
    let Some(span) = find_block(text, resource)? else {
        return Ok(None);
    };
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() - (span.block_end - span.block_start));
    out.extend_from_slice(&bytes[..span.block_start]);
    out.extend_from_slice(&bytes[span.block_end..]);
    Ok(Some(out))
}

/// 探测现有文件使用的换行风格。
///
/// 统计 `\r\n` 与裸 `\n` 的出现次数：`\r\n` 更多时返回 [`LineEnding::Crlf`]，
/// 否则返回 [`LineEnding::Lf`]。文件不存在时返回 [`LineEnding::Lf`]。
/// 本函数**不会**返回 [`LineEnding::Preserve`]。
pub fn detect_line_ending(existing: Option<&[u8]>) -> LineEnding {
    let Some(bytes) = existing else {
        return LineEnding::Lf;
    };
    let mut crlf = 0usize;
    let mut bare_lf = 0usize;
    let mut prev_cr = false;
    for byte in bytes {
        if *byte == b'\n' {
            if prev_cr {
                crlf += 1;
            } else {
                bare_lf += 1;
            }
        }
        prev_cr = *byte == b'\r';
    }
    if crlf > bare_lf {
        LineEnding::Crlf
    } else {
        LineEnding::Lf
    }
}

// ---------------------------------------------------------------------------
// 内部实现
// ---------------------------------------------------------------------------

/// 受管区块在文件中的字节范围。
#[derive(Debug, Clone, Copy)]
struct BlockSpan {
    /// 开始 marker 的行号（从 1 开始）。
    begin_line: usize,
    /// 区块整体起点：开始 marker 行的行首。
    block_start: usize,
    /// 块内内容起点：开始 marker 行换行符之后。
    inner_start: usize,
    /// 块内内容终点：结束 marker 行的行首。
    inner_end: usize,
    /// 区块整体终点：结束 marker 行换行符之后。
    block_end: usize,
}

/// marker 种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkerKind {
    Begin,
    End,
}

/// 带偏移量的一行。
#[derive(Debug, Clone, Copy)]
struct LineRef<'a> {
    number: usize,
    start: usize,
    next: usize,
    text: &'a str,
}

/// Full File：`desired` 就是权威字节。
///
/// [`LineEnding::Preserve`] 时逐字节原样输出（因此允许二进制内容）；显式指定
/// Lf/Crlf 时才做整体换行规范化。
fn render_full_file(input: &RenderInput<'_>) -> Vec<u8> {
    match input.policy.line_ending {
        LineEnding::Preserve => input.desired.to_vec(),
        target => convert_line_endings(input.desired, target),
    }
}

/// Managed Block：只替换块内内容，块外字节逐字保留。
fn render_managed_block(input: &RenderInput<'_>) -> Result<Vec<u8>, RenderError> {
    validate_comment_prefix(input.comment_prefix, input.resource)?;

    let existing_text = match input.existing {
        Some(bytes) => Some(decode_utf8(bytes, input.resource)?),
        None => None,
    };
    let desired_text = decode_utf8(input.desired, input.resource)?;

    // Preserve 时沿用现有文件的主导风格；显式风格在最后统一转换整个文件。
    let target = match input.policy.line_ending {
        LineEnding::Preserve => detect_line_ending(input.existing),
        other => other,
    };
    let terminator = terminator_of(target);
    let inner = render_inner(desired_text, target);

    let mut out = match existing_text {
        // 文件不存在：生成只含该区块的新文件。
        None => build_block(input, &inner, terminator),
        Some(text) => match find_block(text, input.resource)? {
            // 已有区块：只替换 [inner_start, inner_end)，marker 行本身也逐字保留。
            Some(span) => {
                let bytes = text.as_bytes();
                let mut out = Vec::with_capacity(bytes.len() + inner.len());
                out.extend_from_slice(&bytes[..span.inner_start]);
                out.extend_from_slice(&inner);
                out.extend_from_slice(&bytes[span.inner_end..]);
                out
            }
            // 没有区块：追加到文件末尾，追加前保证前一行以换行结束。
            None => {
                let mut out = text.as_bytes().to_vec();
                if !out.is_empty() && !out.ends_with(b"\n") {
                    out.extend_from_slice(terminator);
                }
                out.extend_from_slice(&build_block(input, &inner, terminator));
                out
            }
        },
    };

    if !matches!(input.policy.line_ending, LineEnding::Preserve) {
        out = convert_line_endings(&out, input.policy.line_ending);
    }
    Ok(out)
}

/// 生成完整区块（开始 marker + 块内 + 结束 marker）。
fn build_block(input: &RenderInput<'_>, inner: &[u8], terminator: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(inner.len() + 2 * (input.comment_prefix.len() + 32));
    out.extend_from_slice(input.comment_prefix.as_bytes());
    out.extend_from_slice(MANAGED_BLOCK_BEGIN.as_bytes());
    out.extend_from_slice(input.resource.as_str().as_bytes());
    out.extend_from_slice(terminator);
    out.extend_from_slice(inner);
    out.extend_from_slice(input.comment_prefix.as_bytes());
    out.extend_from_slice(MANAGED_BLOCK_END.as_bytes());
    out.extend_from_slice(input.resource.as_str().as_bytes());
    out.extend_from_slice(terminator);
    out
}

/// 块内内容的规范形式：按目标换行风格转换，并补齐末尾换行。
///
/// 补齐是必要的：结束 marker 必须独占一行，否则文件会退化成非法 marker。
fn render_inner(desired: &str, target: LineEnding) -> Vec<u8> {
    let mut inner = convert_line_endings(desired.as_bytes(), target);
    if !inner.is_empty() && !inner.ends_with(b"\n") {
        inner.extend_from_slice(terminator_of(target));
    }
    inner
}

/// 目标换行风格对应的字节。
fn terminator_of(target: LineEnding) -> &'static [u8] {
    match target {
        LineEnding::Crlf => b"\r\n",
        // Preserve 不应到达这里；退化为 LF 是最保守的选择。
        LineEnding::Lf | LineEnding::Preserve => b"\n",
    }
}

/// 把所有 `\r\n` 与裸 `\n` 统一成目标换行；孤立的 `\r` 原样保留。
fn convert_line_endings(bytes: &[u8], target: LineEnding) -> Vec<u8> {
    if matches!(target, LineEnding::Preserve) {
        return bytes.to_vec();
    }
    let terminator = terminator_of(target);
    let mut out = Vec::with_capacity(bytes.len() + bytes.len() / 16);
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' if bytes.get(index + 1) == Some(&b'\n') => {
                out.extend_from_slice(terminator);
                index += 2;
            }
            b'\n' => {
                out.extend_from_slice(terminator);
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    out
}

/// 解码 UTF-8，失败时统一报 [`RenderError::NotUtf8`]。
fn decode_utf8<'a>(bytes: &'a [u8], resource: &ResourceId) -> Result<&'a str, RenderError> {
    str::from_utf8(bytes).map_err(|_| RenderError::NotUtf8 {
        resource: resource.clone(),
    })
}

/// 校验注释前缀。
///
/// 前缀不得含换行（否则 marker 会被拆成多行），也不得含字母或数字：marker 识别
/// 时无法知道调用方当初用的是什么前缀，只能靠「marker 之前没有字母数字」来区分
/// 真 marker 与恰好提到 marker 文本的普通代码行。
fn validate_comment_prefix(prefix: &str, resource: &ResourceId) -> Result<(), RenderError> {
    let bad = |detail: &str| RenderError::MalformedMarker {
        resource: resource.clone(),
        line: 0,
        detail: detail.to_owned(),
    };
    if prefix.contains('\n') || prefix.contains('\r') {
        return Err(bad("注释前缀不能包含换行"));
    }
    if prefix.chars().any(char::is_alphanumeric) {
        return Err(bad("注释前缀不能包含字母或数字"));
    }
    if prefix.contains(MANAGED_BLOCK_BEGIN) || prefix.contains(MANAGED_BLOCK_END) {
        return Err(bad("注释前缀不能包含 marker 中缀"));
    }
    Ok(())
}

/// 按行切分并记录字节偏移。行内容不含行尾换行符。
fn lines_with_offsets(text: &str) -> Vec<LineRef<'_>> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut number = 1usize;
    while start < bytes.len() {
        let (content_end, next) = match bytes[start..].iter().position(|byte| *byte == b'\n') {
            Some(offset) => (start + offset, start + offset + 1),
            None => (bytes.len(), bytes.len()),
        };
        out.push(LineRef {
            number,
            start,
            next,
            // `\n` 一定是字符边界，切片安全。
            text: &text[start..content_end],
        });
        start = next;
        number += 1;
    }
    out
}

/// 判断一行是否是指定资源的 marker。
///
/// 识别规则（只认整行）：
/// 1. 去掉行首尾空白后必须包含 marker 中缀；
/// 2. 中缀之前只能是注释前缀，即不含字母数字；
/// 3. 中缀之后必须**精确**等于目标资源标识。
///
/// 资源标识匹配但后面还有多余内容时返回 `Err(detail)`，由调用方补上行号。
fn classify_marker(line: &str, resource: &ResourceId) -> Result<Option<MarkerKind>, String> {
    let trimmed = line.trim();
    for (infix, kind) in [
        (MANAGED_BLOCK_BEGIN, MarkerKind::Begin),
        (MANAGED_BLOCK_END, MarkerKind::End),
    ] {
        let Some(position) = trimmed.find(infix) else {
            continue;
        };
        // marker 之前出现字母数字 => 这是普通代码行（例如 `echo "# >>> envsync:x"`）。
        if trimmed[..position].chars().any(char::is_alphanumeric) {
            continue;
        }
        let rest = trimmed[position + infix.len()..].trim();
        if rest == resource.as_str() {
            return Ok(Some(kind));
        }
        let mut parts = rest.split_whitespace();
        if parts.next() == Some(resource.as_str()) && parts.next().is_some() {
            return Err(format!("marker 在资源标识 `{resource}` 之后存在多余内容"));
        }
    }
    Ok(None)
}

/// 定位指定资源的受管区块；不存在返回 `Ok(None)`，异常一律报错。
fn find_block(text: &str, resource: &ResourceId) -> Result<Option<BlockSpan>, RenderError> {
    let mut found: Option<BlockSpan> = None;
    // (开始 marker 行号, 区块起点, 块内起点)
    let mut open: Option<(usize, usize, usize)> = None;

    for line in lines_with_offsets(text) {
        let kind = classify_marker(line.text, resource).map_err(|detail| {
            RenderError::MalformedMarker {
                resource: resource.clone(),
                line: line.number,
                detail,
            }
        })?;
        match kind {
            Some(MarkerKind::Begin) => {
                if open.is_some() {
                    return Err(RenderError::NestedBlock {
                        resource: resource.clone(),
                        line: line.number,
                    });
                }
                if let Some(first) = found {
                    return Err(RenderError::DuplicateBlock {
                        resource: resource.clone(),
                        first_line: first.begin_line,
                        second_line: line.number,
                    });
                }
                open = Some((line.number, line.start, line.next));
            }
            Some(MarkerKind::End) => match open.take() {
                Some((begin_line, block_start, inner_start)) => {
                    found = Some(BlockSpan {
                        begin_line,
                        block_start,
                        inner_start,
                        inner_end: line.start,
                        block_end: line.next,
                    });
                }
                None => {
                    return Err(RenderError::MisorderedBlock {
                        resource: resource.clone(),
                        line: line.number,
                    })
                }
            },
            None => {}
        }
    }

    if let Some((begin_line, _, _)) = open {
        return Err(RenderError::UnterminatedBlock {
            resource: resource.clone(),
            line: begin_line,
        });
    }
    Ok(found)
}
