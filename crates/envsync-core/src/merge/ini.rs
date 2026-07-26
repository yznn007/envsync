//! INI 三方合并（自带解析器，无第三方依赖）。
//!
//! 本模块同时是 [`super::git_config`] 的底座：两种格式共用同一套「节 + 键值行 +
//! 版式（layout）」模型，差别由内部的 `Dialect` 方言开关控制。
//!
//! ## INI 合并规则
//!
//! - **键的 identity 是 `section/key`**（节名与键名都大小写敏感）。
//! - 重复键按**显式** [`MultiValuePolicy`] 处理，默认 [`MultiValuePolicy::Reject`]：
//!   - `Reject`：同节内重复键直接报 [`MergeError::DuplicateKey`]；
//!   - `LastWins`：只保留最后一次出现的值，位置沿用**第一次**出现的位置；
//!   - `Append`：按出现顺序保留全部取值，合并时该键的值列表**整体**作为原子值。
//! - 单个键的值列表作为原子单元做三方合并；一侧删除、另一侧修改 → 冲突。
//! - **保留注释、空行、节顺序与原换行风格**：结果以 ours 的版式为骨架，
//!   未发生语义变化的行逐字保留。
//!
//! ## 语法子集
//!
//! - 节头：`[name]`（前后可有空白）。
//! - 键值：`key = value`（`=` 前后空白被裁剪；值不做引号解析，逐字保留）。
//! - 注释：整行以 `;` 或 `#` 开头；**行尾注释不被识别**，会成为值的一部分。
//! - 其他形态的行 → [`MergeError::Parse`]，诊断只含行号。

use std::collections::HashSet;

use envsync_domain::StructuredFormat;

use super::{
    child_pointer, classify, structured_conflict, Budget, ConflictShape, IniPolicy, KeyConflict,
    MergeError, MergeInput, MergeProvenance, MergeResult, MultiValuePolicy, Presence,
};

/// 解析方言：INI 与 Git config 共用同一套模型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dialect {
    /// 经典 INI：节名与键名大小写敏感，无 subsection。
    Ini,
    /// Git config：`[section "subsection"]`，section/name 大小写不敏感，
    /// subsection 大小写敏感。
    GitConfig,
}

impl Dialect {
    fn format(self) -> StructuredFormat {
        match self {
            Dialect::Ini => StructuredFormat::Ini,
            Dialect::GitConfig => StructuredFormat::GitConfig,
        }
    }
}

/// 一条键值项：同一 identity 下可以有多个取值（多值键）。
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    /// 归一化 identity。
    pub(crate) key: String,
    /// 原始键名写法，用于重新渲染。
    pub(crate) display: String,
    /// 按出现顺序排列的取值。
    pub(crate) values: Vec<String>,
    /// 每个取值对应的原始行（不含行终止符）。
    pub(crate) raws: Vec<String>,
}

/// 节内的版式元素。
#[derive(Debug, Clone)]
pub(crate) enum Layout {
    /// 注释行或空行，逐字保留。
    Verbatim(String),
    /// 某个键在此处出现（只记首次出现的位置）。
    Key(String),
}

/// 一个节。`header` 为 `None` 表示文件开头的隐式全局节。
#[derive(Debug, Clone)]
pub(crate) struct Section {
    /// 归一化 identity。
    pub(crate) id: String,
    /// 原始节头行；`None` 表示隐式全局节。
    pub(crate) header: Option<String>,
    /// 版式。
    pub(crate) layout: Vec<Layout>,
    /// 键值项。
    pub(crate) entries: Vec<Entry>,
}

impl Section {
    fn entry(&self, key: &str) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.key == key)
    }
}

/// 解析后的文档。
#[derive(Debug, Clone)]
pub(crate) struct Doc {
    /// 主导换行风格。
    pub(crate) newline: &'static str,
    /// 节，按出现顺序。
    pub(crate) sections: Vec<Section>,
}

impl Doc {
    fn section(&self, id: &str) -> Option<&Section> {
        self.sections.iter().find(|section| section.id == id)
    }
}

/// 合并后的语义模型：`[(section_id, [(key, values)])]`。
type Semantic = Vec<(String, Vec<(String, Vec<String>)>)>;

/// 比较用的值规范化函数：`(section_id, key, values) -> 比较键`。
pub(crate) type ValueIdentity = fn(&str, &str, &[String]) -> Vec<String>;

/// 默认：逐字比较。
fn literal_identity(_section: &str, _key: &str, values: &[String]) -> Vec<String> {
    values.to_vec()
}

/// INI 三方合并入口。
pub fn merge_ini(input: &MergeInput<'_>, policy: IniPolicy) -> Result<MergeResult, MergeError> {
    merge_config(input, Dialect::Ini, policy, literal_identity)
}

/// INI / Git config 共用的三方合并流程。
pub(crate) fn merge_config(
    input: &MergeInput<'_>,
    dialect: Dialect,
    policy: IniPolicy,
    identity: ValueIdentity,
) -> Result<MergeResult, MergeError> {
    let (base, ours, theirs) = match classify(input) {
        Presence::Decided(result) => return Ok(result),
        Presence::Both { base, ours, theirs } => (base, ours, theirs),
    };

    let base_doc = base.map(|b| parse(b, dialect, policy)).transpose()?;
    let ours_doc = parse(ours, dialect, policy)?;
    let theirs_doc = parse(theirs, dialect, policy)?;

    let mut conflicts = Vec::new();
    let mut provenance = MergeProvenance::default();
    let merged = merge_semantic(
        base_doc.as_ref(),
        &ours_doc,
        &theirs_doc,
        identity,
        &mut conflicts,
        &mut provenance,
    );

    if !conflicts.is_empty() {
        return Ok(MergeResult::Conflict(structured_conflict(
            input, &conflicts,
        )));
    }

    let bytes = render(&merged, &ours_doc, &theirs_doc, dialect).into_bytes();
    let reparsed = parse(&bytes, dialect, policy)?;
    if semantic_of(&reparsed) != merged {
        return Err(MergeError::RenderVerificationFailed {
            format: dialect.format(),
        });
    }

    let note = match dialect {
        Dialect::Ini => "ini 按 section/key 合并并保留 ours 的注释与版式",
        Dialect::GitConfig => "git config 按 section/subsection/name 合并，include.path 不被读取",
    };
    Ok(MergeResult::Clean {
        bytes,
        provenance: provenance.note(note),
    })
}

// ---------------------------------------------------------------------------
// 解析
// ---------------------------------------------------------------------------

/// 解析文档。
pub(crate) fn parse(bytes: &[u8], dialect: Dialect, policy: IniPolicy) -> Result<Doc, MergeError> {
    let format = dialect.format();
    let text = std::str::from_utf8(bytes).map_err(|err| MergeError::Parse {
        format,
        detail: format!("invalid utf-8 at byte {}", err.valid_up_to()),
    })?;
    let newline = dominant_newline(text);

    let mut budget = Budget::new();
    let mut sections: Vec<Section> = vec![Section {
        id: String::new(),
        header: None,
        layout: Vec::new(),
        entries: Vec::new(),
    }];
    let mut current = 0usize;
    budget.charge(1)?;

    // `str::lines()` 会顺带剥掉 `\r\n` 里的 `\r`，因此 raw_line 里不含行终止符；
    // 渲染时统一用 `newline` 重新拼接，从而保留文件原本的换行风格。
    for (index, raw_line) in text.lines().enumerate() {
        let line_no = index + 1;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
            sections[current]
                .layout
                .push(Layout::Verbatim(raw_line.to_owned()));
            continue;
        }
        if trimmed.starts_with('[') {
            let id = parse_header(trimmed, dialect, line_no, format)?;
            budget.charge(1)?;
            match sections.iter().position(|section| section.id == id) {
                // 同一节重复出现：后续行并入已有节，重复的节头行作为版式逐字保留。
                Some(existing) => {
                    current = existing;
                    sections[current]
                        .layout
                        .push(Layout::Verbatim(raw_line.to_owned()));
                }
                None => {
                    sections.push(Section {
                        id,
                        header: Some(raw_line.to_owned()),
                        layout: Vec::new(),
                        entries: Vec::new(),
                    });
                    current = sections.len() - 1;
                }
            }
            continue;
        }

        let (key_text, value_text) = trimmed.split_once('=').ok_or_else(|| MergeError::Parse {
            format,
            detail: format!("line {line_no}: expected `key = value` or section header"),
        })?;
        let display = key_text.trim().to_owned();
        if display.is_empty() {
            return Err(MergeError::Parse {
                format,
                detail: format!("line {line_no}: empty key"),
            });
        }
        let key = normalize_key(&display, dialect);
        let value = value_text.trim().to_owned();
        budget.charge(2)?;

        let section = &mut sections[current];
        let section_id = section.id.clone();
        match section.entries.iter_mut().find(|entry| entry.key == key) {
            None => {
                section.layout.push(Layout::Key(key.clone()));
                section.entries.push(Entry {
                    key,
                    display,
                    values: vec![value],
                    raws: vec![raw_line.to_owned()],
                });
            }
            Some(entry) => {
                let multi = match dialect {
                    Dialect::GitConfig => MultiValuePolicy::Append,
                    Dialect::Ini => policy.multi_value,
                };
                match multi {
                    MultiValuePolicy::Reject => {
                        return Err(MergeError::DuplicateKey {
                            pointer: pointer_of(&section_id, &key),
                        })
                    }
                    MultiValuePolicy::LastWins => {
                        entry.values = vec![value];
                        entry.raws = vec![raw_line.to_owned()];
                    }
                    MultiValuePolicy::Append => {
                        entry.values.push(value);
                        entry.raws.push(raw_line.to_owned());
                    }
                }
            }
        }
    }

    // 丢掉空的隐式全局节，避免它在渲染时占位。
    if sections
        .first()
        .is_some_and(|s| s.header.is_none() && s.entries.is_empty() && s.layout.is_empty())
    {
        sections.remove(0);
    }

    Ok(Doc { newline, sections })
}

/// 主导换行风格：CRLF 严格多于纯 LF 时为 `\r\n`。
fn dominant_newline(text: &str) -> &'static str {
    let crlf = text.matches("\r\n").count();
    let lf = text.matches('\n').count().saturating_sub(crlf);
    if crlf > lf {
        "\r\n"
    } else {
        "\n"
    }
}

/// 解析节头，返回归一化 identity。
fn parse_header(
    trimmed: &str,
    dialect: Dialect,
    line_no: usize,
    format: StructuredFormat,
) -> Result<String, MergeError> {
    let inner = trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or_else(|| MergeError::Parse {
            format,
            detail: format!("line {line_no}: unterminated section header"),
        })?
        .trim();
    if inner.is_empty() {
        return Err(MergeError::Parse {
            format,
            detail: format!("line {line_no}: empty section name"),
        });
    }
    match dialect {
        Dialect::Ini => Ok(inner.to_owned()),
        Dialect::GitConfig => {
            // `[section "subsection"]`：subsection 大小写敏感、逐字保留。
            if let Some((section, rest)) = inner.split_once('"') {
                let subsection = rest.strip_suffix('"').ok_or_else(|| MergeError::Parse {
                    format,
                    detail: format!("line {line_no}: unterminated subsection quote"),
                })?;
                return Ok(format!(
                    "{}\u{1}{}",
                    section.trim().to_ascii_lowercase(),
                    subsection
                ));
            }
            // 传统写法 `[section.subsection]`：subsection 同样大小写敏感。
            if let Some((section, subsection)) = inner.split_once('.') {
                return Ok(format!(
                    "{}\u{1}{}",
                    section.trim().to_ascii_lowercase(),
                    subsection
                ));
            }
            Ok(inner.to_ascii_lowercase())
        }
    }
}

fn normalize_key(display: &str, dialect: Dialect) -> String {
    match dialect {
        Dialect::Ini => display.to_owned(),
        Dialect::GitConfig => display.to_ascii_lowercase(),
    }
}

/// 诊断用的键路径：`/section/key`（全局节渲染为 `//key`）。
pub(crate) fn pointer_of(section_id: &str, key: &str) -> String {
    child_pointer(&child_pointer("", section_id), key)
}

// ---------------------------------------------------------------------------
// 语义合并
// ---------------------------------------------------------------------------

fn semantic_of(doc: &Doc) -> Semantic {
    doc.sections
        .iter()
        .filter(|section| !section.entries.is_empty())
        .map(|section| {
            (
                section.id.clone(),
                section
                    .entries
                    .iter()
                    .map(|entry| (entry.key.clone(), entry.values.clone()))
                    .collect(),
            )
        })
        .collect()
}

fn merge_semantic(
    base: Option<&Doc>,
    ours: &Doc,
    theirs: &Doc,
    identity: ValueIdentity,
    conflicts: &mut Vec<KeyConflict>,
    provenance: &mut MergeProvenance,
) -> Semantic {
    let mut section_ids: Vec<String> = Vec::new();
    for id in base
        .into_iter()
        .flat_map(|doc| doc.sections.iter())
        .chain(ours.sections.iter())
        .chain(theirs.sections.iter())
        .map(|section| section.id.clone())
    {
        if !section_ids.contains(&id) {
            section_ids.push(id);
        }
    }

    let mut merged: Semantic = Vec::new();
    for section_id in section_ids {
        let base_section = base.and_then(|doc| doc.section(&section_id));
        let ours_section = ours.section(&section_id);
        let theirs_section = theirs.section(&section_id);

        let mut keys: Vec<String> = Vec::new();
        for key in [base_section, ours_section, theirs_section]
            .into_iter()
            .flatten()
            .flat_map(|section| section.entries.iter())
            .map(|entry| entry.key.clone())
        {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }

        let mut section_entries: Vec<(String, Vec<String>)> = Vec::new();
        for key in keys {
            let values_of = |section: Option<&Section>| -> Option<Vec<String>> {
                section
                    .and_then(|section| section.entry(&key))
                    .map(|entry| entry.values.clone())
            };
            let base_values = values_of(base_section);
            let ours_values = values_of(ours_section);
            let theirs_values = values_of(theirs_section);

            let cmp = |values: &Option<Vec<String>>| -> Option<Vec<String>> {
                values
                    .as_ref()
                    .map(|values| identity(&section_id, &key, values))
            };
            let (base_cmp, ours_cmp, theirs_cmp) =
                (cmp(&base_values), cmp(&ours_values), cmp(&theirs_values));

            let chosen = if ours_cmp == theirs_cmp {
                if base_cmp == ours_cmp {
                    provenance.took_base += 1;
                } else {
                    provenance.took_ours += 1;
                    provenance.took_theirs += 1;
                }
                ours_values
            } else if base_cmp == ours_cmp {
                provenance.took_theirs += 1;
                theirs_values
            } else if base_cmp == theirs_cmp {
                provenance.took_ours += 1;
                ours_values
            } else {
                conflicts.push(KeyConflict {
                    pointer: pointer_of(&section_id, &key),
                    shape: if ours_values.is_none() || theirs_values.is_none() {
                        ConflictShape::DeleteModify
                    } else {
                        ConflictShape::ModifyModify
                    },
                });
                ours_values.or(theirs_values)
            };

            if let Some(values) = chosen {
                section_entries.push((key, values));
            }
        }

        if !section_entries.is_empty() {
            merged.push((section_id, section_entries));
        }
    }
    merged
}

// ---------------------------------------------------------------------------
// 渲染
// ---------------------------------------------------------------------------

/// 以 ours 的版式为骨架渲染合并结果。
///
/// 节顺序：隐式全局节永远排在最前（否则重新解析时会被算进上一个 `[section]`），
/// 其余按 ours 的原顺序，最后追加只存在于 theirs 的新节。
fn render(merged: &Semantic, ours: &Doc, theirs: &Doc, dialect: Dialect) -> String {
    let mut order: Vec<&str> = Vec::new();
    if merged.iter().any(|(id, _)| id.is_empty())
        || ours
            .sections
            .iter()
            .any(|section| section.id.is_empty() && !section.layout.is_empty())
    {
        order.push("");
    }
    for section in &ours.sections {
        let keep = merged.iter().any(|(id, _)| id == &section.id) || section.entries.is_empty();
        if keep && !order.contains(&section.id.as_str()) {
            order.push(&section.id);
        }
    }
    for (id, _) in merged {
        if !order.contains(&id.as_str()) {
            order.push(id);
        }
    }

    let mut lines: Vec<String> = Vec::new();
    for id in order {
        let entries: &[(String, Vec<String>)] = merged
            .iter()
            .find(|(section_id, _)| section_id == id)
            .map(|(_, entries)| entries.as_slice())
            .unwrap_or(&[]);
        let ours_section = ours.section(id);
        let skeleton = ours_section.or_else(|| theirs.section(id));
        if let Some(header) = skeleton.and_then(|section| section.header.clone()) {
            lines.push(header);
        }
        let mut emitted: HashSet<&str> = HashSet::new();
        if let Some(section) = ours_section {
            for item in &section.layout {
                match item {
                    Layout::Verbatim(text) => lines.push(text.clone()),
                    Layout::Key(key) => {
                        if !emitted.insert(key.as_str()) {
                            continue;
                        }
                        if let Some((_, values)) = entries.iter().find(|(k, _)| k == key) {
                            push_entry(&mut lines, id, key, values, ours, theirs, dialect);
                        }
                    }
                }
            }
        }
        for (key, values) in entries {
            if emitted.insert(key.as_str()) {
                push_entry(&mut lines, id, key, values, ours, theirs, dialect);
            }
        }
    }

    let mut text = lines.join(ours.newline);
    if !text.is_empty() {
        text.push_str(ours.newline);
    }
    text
}

/// 输出一个键的全部取值行；值未变化时复用原始行以保留缩进与写法。
#[allow(clippy::too_many_arguments)]
fn push_entry(
    lines: &mut Vec<String>,
    section_id: &str,
    key: &str,
    values: &[String],
    ours: &Doc,
    theirs: &Doc,
    dialect: Dialect,
) {
    let ours_entry = ours
        .section(section_id)
        .and_then(|section| section.entry(key));
    let theirs_entry = theirs
        .section(section_id)
        .and_then(|section| section.entry(key));
    for entry in [ours_entry, theirs_entry].into_iter().flatten() {
        if entry.values == values {
            lines.extend(entry.raws.iter().cloned());
            return;
        }
    }
    let display = ours_entry
        .or(theirs_entry)
        .map(|entry| entry.display.clone())
        .unwrap_or_else(|| key.to_owned());
    let indent = match dialect {
        Dialect::Ini => "",
        Dialect::GitConfig => "\t",
    };
    for value in values {
        lines.push(format!("{indent}{display} = {value}"));
    }
}
