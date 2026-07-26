//! 文本三方合并（diff3 风格，基于 [`similar`] 的行级 diff）。
//!
//! ## 合并规则
//!
//! | 情况 | 结果 |
//! |---|---|
//! | 只改 ours / 只改 theirs | `Clean`，逐字节等于改动那一侧 |
//! | 双方相同修改 | `Clean`，结果就是那份内容 |
//! | 互不相交的行区间修改 | `Clean`，两侧改动都保留 |
//! | 重叠区域双方不同修改 | `Conflict(TextOverlap)`，诊断给出行区间 |
//! | 一侧删除、另一侧修改 | `Conflict(DeleteModify)` |
//! | 双方都删除 | `Deleted` |
//! | 二进制内容双方都改 | `Conflict(BinaryBoth)`，不做行合并 |
//! | 超过 [`MAX_INPUT_BYTES`] 双方都改 | 同二进制规则，并在诊断里注明超限 |
//!
//! ## 换行符约定
//!
//! 行比较使用**行尾归一化**后的内容（`\r\n` 与 `\n` 视为同一行），
//! 输出则**保留被采纳那一侧该行的原始行尾**：
//!
//! - 稳定区（三方一致）沿用 **ours** 的原始行；
//! - 只有一侧改动的区段沿用**那一侧**的原始行。
//!
//! 因此「仅行尾风格不同」不会被当成内容变更，也不会产生冲突。当拼接处需要补一个
//! 行尾（前一段最后一行没有行终止符）时，使用 **base 的主导换行风格**（base 缺失
//! 时用 ours 的主导风格）。
//!
//! ## 已知限制
//!
//! - 纯行尾风格变更（例如 theirs 把整份文件从 LF 改成 CRLF，ours 改了别的行）
//!   在稳定区不会被采纳，因为稳定区固定沿用 ours 的原始行。这是有意的取舍：
//!   行尾归一化比较是避免「跨平台换行噪声」压垮合并的前提。
//! - 合并粒度是行，不做词级或语法级合并。

use envsync_domain::ConflictKind;
use similar::{capture_diff_slices, Algorithm, DiffOp};

use super::{
    build_conflict, classify, MergeError, MergeInput, MergeProvenance, MergeResult, Presence,
    MAX_INPUT_BYTES,
};

/// 文本三方合并入口。
///
/// 本函数不会失败于内容本身：对任何字节输入都会给出 `Clean` / `Conflict` /
/// `Deleted` 之一，`Result` 只是为了与结构化合并保持一致的签名。
pub fn merge_text(input: &MergeInput<'_>) -> Result<MergeResult, MergeError> {
    let (base, ours, theirs) = match classify(input) {
        Presence::Decided(result) => return Ok(result),
        Presence::Both { base, ours, theirs } => (base, ours, theirs),
    };

    // 到这里说明双方都存在、内容不同，且都相对 base 有改动。
    let oversized = [Some(ours), Some(theirs), base]
        .into_iter()
        .flatten()
        .any(|side| side.len() as u64 > MAX_INPUT_BYTES);
    let binary = [Some(ours), Some(theirs), base]
        .into_iter()
        .flatten()
        .any(|side: &[u8]| is_binary(side));

    if binary || oversized {
        let mut diagnostics = vec!["both sides modified non-line-mergeable content".to_owned()];
        if oversized {
            diagnostics.push(format!("input exceeds {MAX_INPUT_BYTES} bytes"));
        }
        if binary {
            diagnostics.push("content is binary (NUL byte or invalid UTF-8)".to_owned());
        }
        return Ok(MergeResult::Conflict(build_conflict(
            input,
            ConflictKind::BinaryBoth,
            diagnostics,
        )));
    }

    // 前面的 `is_binary` 已经保证三侧都是合法 UTF-8。
    let base_text = base.map(|b| std::str::from_utf8(b).expect("checked utf8"));
    let ours_text = std::str::from_utf8(ours).expect("checked utf8");
    let theirs_text = std::str::from_utf8(theirs).expect("checked utf8");

    Ok(merge_lines(
        input,
        base_text.unwrap_or(""),
        ours_text,
        theirs_text,
    ))
}

/// 是否按二进制处理：含 NUL 字节或不是合法 UTF-8。
fn is_binary(bytes: &[u8]) -> bool {
    bytes.contains(&0) || std::str::from_utf8(bytes).is_err()
}

/// 保留行终止符地切分行。最后一行可以没有终止符。
fn split_lines_keep(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (idx, ch) in text.char_indices() {
        if ch == '\n' {
            out.push(&text[start..=idx]);
            start = idx + 1;
        }
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

/// 去掉行尾终止符，得到用于比较的归一化行内容。
fn normalize(line: &str) -> &str {
    let line = line.strip_suffix('\n').unwrap_or(line);
    line.strip_suffix('\r').unwrap_or(line)
}

/// 主导换行风格：CRLF 数量严格多于纯 LF 数量时为 `\r\n`，否则为 `\n`。
fn dominant_newline(text: &str) -> &'static str {
    let crlf = text.matches("\r\n").count();
    let lf = text.matches('\n').count().saturating_sub(crlf);
    if crlf > lf {
        "\r\n"
    } else {
        "\n"
    }
}

/// diff 的 Equal 段，形如 `(base_index, side_index, len)`。
type MatchBlock = (usize, usize, usize);

fn matching_blocks(base: &[&str], side: &[&str]) -> Vec<MatchBlock> {
    capture_diff_slices(Algorithm::Myers, base, side)
        .into_iter()
        .filter_map(|op| match op {
            DiffOp::Equal {
                old_index,
                new_index,
                len,
            } => Some((old_index, new_index, len)),
            _ => None,
        })
        .collect()
}

/// 三方同步区：base / ours / theirs 三侧同时相等的一段。
struct SyncRegion {
    base_start: usize,
    base_end: usize,
    ours_start: usize,
    ours_end: usize,
    theirs_start: usize,
    theirs_end: usize,
}

/// 求 base→ours 与 base→theirs 两组 Equal 段在 base 坐标上的交集。
fn sync_regions(
    ours_blocks: &[MatchBlock],
    theirs_blocks: &[MatchBlock],
    base_len: usize,
    ours_len: usize,
    theirs_len: usize,
) -> Vec<SyncRegion> {
    let mut regions = Vec::new();
    let (mut ia, mut ib) = (0usize, 0usize);
    while ia < ours_blocks.len() && ib < theirs_blocks.len() {
        let (a_base, a_side, a_len) = ours_blocks[ia];
        let (b_base, b_side, b_len) = theirs_blocks[ib];
        let start = a_base.max(b_base);
        let end = (a_base + a_len).min(b_base + b_len);
        if start < end {
            regions.push(SyncRegion {
                base_start: start,
                base_end: end,
                ours_start: a_side + (start - a_base),
                ours_end: a_side + (end - a_base),
                theirs_start: b_side + (start - b_base),
                theirs_end: b_side + (end - b_base),
            });
        }
        if a_base + a_len < b_base + b_len {
            ia += 1;
        } else {
            ib += 1;
        }
    }
    // 末尾哨兵，保证最后一段不稳定区也会被处理。
    regions.push(SyncRegion {
        base_start: base_len,
        base_end: base_len,
        ours_start: ours_len,
        ours_end: ours_len,
        theirs_start: theirs_len,
        theirs_end: theirs_len,
    });
    regions
}

/// 逐行拼接输出，必要时补上主导换行符。
struct LineWriter {
    buf: String,
    newline: &'static str,
}

impl LineWriter {
    fn new(newline: &'static str) -> Self {
        LineWriter {
            buf: String::new(),
            newline,
        }
    }

    fn push(&mut self, lines: &[&str]) {
        for line in lines {
            if !self.buf.is_empty() && !self.buf.ends_with('\n') {
                self.buf.push_str(self.newline);
            }
            self.buf.push_str(line);
        }
    }
}

/// diff3 主循环。
fn merge_lines(input: &MergeInput<'_>, base: &str, ours: &str, theirs: &str) -> MergeResult {
    let base_lines = split_lines_keep(base);
    let ours_lines = split_lines_keep(ours);
    let theirs_lines = split_lines_keep(theirs);

    let base_norm: Vec<&str> = base_lines.iter().copied().map(normalize).collect();
    let ours_norm: Vec<&str> = ours_lines.iter().copied().map(normalize).collect();
    let theirs_norm: Vec<&str> = theirs_lines.iter().copied().map(normalize).collect();

    let regions = sync_regions(
        &matching_blocks(&base_norm, &ours_norm),
        &matching_blocks(&base_norm, &theirs_norm),
        base_norm.len(),
        ours_norm.len(),
        theirs_norm.len(),
    );

    let newline = if base.is_empty() {
        dominant_newline(ours)
    } else {
        dominant_newline(base)
    };
    let mut writer = LineWriter::new(newline);
    let mut provenance = MergeProvenance::default();
    let mut diagnostics: Vec<String> = Vec::new();

    let (mut iz, mut ia, mut ib) = (0usize, 0usize, 0usize);
    for region in &regions {
        let base_chunk = &base_norm[iz..region.base_start];
        let ours_chunk = &ours_norm[ia..region.ours_start];
        let theirs_chunk = &theirs_norm[ib..region.theirs_start];

        if !ours_chunk.is_empty() || !theirs_chunk.is_empty() {
            if ours_chunk == theirs_chunk {
                // 双方做了相同的修改。
                writer.push(&ours_lines[ia..region.ours_start]);
                provenance.took_ours += ours_chunk.len();
            } else if ours_chunk == base_chunk {
                // 只有 theirs 改了这一段。
                writer.push(&theirs_lines[ib..region.theirs_start]);
                provenance.took_theirs += theirs_chunk.len();
            } else if theirs_chunk == base_chunk {
                // 只有 ours 改了这一段。
                writer.push(&ours_lines[ia..region.ours_start]);
                provenance.took_ours += ours_chunk.len();
            } else {
                diagnostics.push(format!(
                    "ours {}..{} vs theirs {}..{}",
                    ia + 1,
                    region.ours_start + 1,
                    ib + 1,
                    region.theirs_start + 1
                ));
            }
        }

        if region.base_end > region.base_start {
            writer.push(&ours_lines[region.ours_start..region.ours_end]);
            provenance.took_base += region.base_end - region.base_start;
        }

        iz = region.base_end;
        ia = region.ours_end;
        ib = region.theirs_end;
    }

    if !diagnostics.is_empty() {
        return MergeResult::Conflict(build_conflict(
            input,
            ConflictKind::TextOverlap,
            diagnostics,
        ));
    }

    MergeResult::Clean {
        bytes: writer.buf.into_bytes(),
        provenance: provenance.note("行级 diff3 合并"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_lines_keeps_terminators() {
        assert_eq!(split_lines_keep("a\nb\r\nc"), vec!["a\n", "b\r\n", "c"]);
        assert_eq!(split_lines_keep(""), Vec::<&str>::new());
    }

    #[test]
    fn dominant_newline_prefers_majority() {
        assert_eq!(dominant_newline("a\r\nb\r\n"), "\r\n");
        assert_eq!(dominant_newline("a\nb\n"), "\n");
        assert_eq!(dominant_newline(""), "\n");
    }

    #[test]
    fn normalize_strips_both_styles() {
        assert_eq!(normalize("a\r\n"), "a");
        assert_eq!(normalize("a\n"), "a");
        assert_eq!(normalize("a"), "a");
    }
}
