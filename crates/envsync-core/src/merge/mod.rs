//! 三方合并引擎：文本行合并 + JSON/YAML/TOML/INI/Git config 语义合并。
//!
//! ## 设计约束
//!
//! 1. **冲突 marker 绝不写入用户内容**。合并要么产出干净字节，要么产出
//!    [`envsync_domain::Conflict`] 对象；`<<<<<<<` 之类的标记永远不出现在
//!    [`MergeResult::Clean`] 的字节里。
//! 2. **诊断不泄漏文件正文**。所有 `diagnostics` 与 [`MergeError`] 的 `detail`
//!    只包含结构位置（行区间、JSON Pointer、键路径），不包含值。
//! 3. **纯函数**。合并不读磁盘、不跟随 `include`、不解析环境变量。
//! 4. **有界资源**。见 [`MAX_INPUT_BYTES`]、[`MAX_PARSE_DEPTH`]、[`MAX_NODES`]。
//! 5. **渲染后校验**。结构化合并在渲染出字节后会重新解析一次，比对语义模型是否与
//!    合并结果一致，不一致返回 [`MergeError::RenderVerificationFailed`]。
//!
//! ## 入口
//!
//! | 函数 | 用途 |
//! |---|---|
//! | [`merge_text`] | 逐行三方合并（diff3 风格） |
//! | [`merge_structured`] | 按格式做语义合并，使用默认选项 |
//! | [`merge_structured_with`] | 同上，但可传入 [`MergeOptions`] |
//! | [`merge`] | 有格式时走语义合并，否则退化为文本合并 |

use std::fmt;

use envsync_domain::{
    BlobId, Conflict, ConflictKind, ResourceId, StructuredFormat, CONFLICT_FORMAT_VERSION,
};

pub mod git_config;
pub mod ini;
pub mod json;
pub mod text;
pub mod toml;
pub mod yaml;

pub use git_config::merge_git_config;
pub use ini::merge_ini;
pub use json::merge_json;
pub use toml::merge_toml;
pub use yaml::merge_yaml;

/// 单侧输入的最大字节数：4 MiB。
///
/// 文本合并遇到超限输入时**降级为整份内容比较**（等同二进制规则），
/// 结构化合并遇到超限输入则直接返回 [`MergeError::TooLarge`]。
pub const MAX_INPUT_BYTES: u64 = 4 * 1024 * 1024;

/// 结构化解析的最大嵌套深度。
pub const MAX_PARSE_DEPTH: usize = 64;

/// 结构化解析的最大节点数。
pub const MAX_NODES: usize = 100_000;

/// 三方合并的输入。
///
/// `base`/`ours`/`theirs` 为 `None` 表示该侧不存在该资源：`base` 为 `None`
/// 表示双方新增，`ours`/`theirs` 为 `None` 表示该侧删除。
#[derive(Debug, Clone, Copy)]
pub struct MergeInput<'a> {
    /// 被合并的资源标识，用于构造 [`Conflict`]。
    pub resource: &'a ResourceId,
    /// 合并基版本内容。
    pub base: Option<&'a [u8]>,
    /// 本地一侧内容。
    pub ours: Option<&'a [u8]>,
    /// 远端一侧内容。
    pub theirs: Option<&'a [u8]>,
}

/// 合并结果的来源摘要，用于审计「结果里哪些部分来自谁」。
///
/// 计数单位是**行**（文本合并）或**键**（结构化合并）。对不做细粒度合并的整份
/// 内容路径（二进制、超限、双方字节完全一致等快速路径），采纳的一侧按 `1` 计。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeProvenance {
    /// 取自 ours 的贡献数量。
    pub took_ours: usize,
    /// 取自 theirs 的贡献数量。
    pub took_theirs: usize,
    /// 三方一致、直接沿用 base 的贡献数量。
    pub took_base: usize,
    /// 审计备注（例如「输入超过 4 MiB，按整份内容处理」）。**不含文件正文**。
    pub notes: Vec<String>,
}

impl MergeProvenance {
    /// 构造一个只有计数、没有备注的 provenance。
    pub(crate) fn counts(took_ours: usize, took_theirs: usize, took_base: usize) -> Self {
        MergeProvenance {
            took_ours,
            took_theirs,
            took_base,
            notes: Vec::new(),
        }
    }

    /// 追加一条审计备注。
    pub(crate) fn note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }
}

/// 三方合并的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeResult {
    /// 干净合并。`bytes` 可直接落盘，**绝不含冲突 marker**。
    Clean {
        /// 合并后的内容。
        bytes: Vec<u8>,
        /// 来源摘要。
        provenance: MergeProvenance,
    },
    /// 冲突：只产出 [`Conflict`] 对象，由用户显式解决。
    Conflict(Conflict),
    /// 双方一致删除该资源。
    Deleted,
}

impl MergeResult {
    /// 是否为干净合并。
    pub fn is_clean(&self) -> bool {
        matches!(self, MergeResult::Clean { .. })
    }

    /// 干净合并时返回结果字节。
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            MergeResult::Clean { bytes, .. } => Some(bytes),
            _ => None,
        }
    }

    /// 冲突时返回冲突对象。
    pub fn conflict(&self) -> Option<&Conflict> {
        match self {
            MergeResult::Conflict(conflict) => Some(conflict),
            _ => None,
        }
    }
}

/// 合并失败的原因。
///
/// **`detail` 只描述位置与结构**（例如 `line 12`、`key path a.b`），
/// 永远不包含被解析文件的正文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeError {
    /// 输入超过 [`MAX_INPUT_BYTES`]。
    TooLarge {
        /// 上限（字节）。
        limit: u64,
        /// 实际大小（字节）。
        actual: u64,
    },
    /// 结构化文档嵌套超过 [`MAX_PARSE_DEPTH`]。
    DepthLimitExceeded {
        /// 上限。
        limit: usize,
    },
    /// 结构化文档节点数超过 [`MAX_NODES`]。
    NodeLimitExceeded {
        /// 上限。
        limit: usize,
    },
    /// 解析失败。
    Parse {
        /// 出错的格式。
        format: StructuredFormat,
        /// 位置/结构描述，不含正文。
        detail: String,
    },
    /// 同一容器里出现重复键。
    DuplicateKey {
        /// 重复键的路径（JSON Pointer 或等价的键路径）。
        pointer: String,
    },
    /// 遇到本合并器有意不支持的构造（例如 YAML 自定义 tag、多文档）。
    UnsupportedConstruct {
        /// 出错的格式。
        format: StructuredFormat,
        /// 构造描述，不含正文。
        detail: String,
    },
    /// 渲染后重新解析，语义与合并结果不一致。
    RenderVerificationFailed {
        /// 出错的格式。
        format: StructuredFormat,
    },
}

impl MergeError {
    /// 稳定错误码，供 CLI / JSON 输出使用。
    pub fn code(&self) -> &'static str {
        match self {
            MergeError::TooLarge { .. } => "merge.too_large",
            MergeError::DepthLimitExceeded { .. } => "merge.depth_limit",
            MergeError::NodeLimitExceeded { .. } => "merge.node_limit",
            MergeError::Parse { .. } => "merge.parse",
            MergeError::DuplicateKey { .. } => "merge.duplicate_key",
            MergeError::UnsupportedConstruct { .. } => "merge.unsupported_construct",
            MergeError::RenderVerificationFailed { .. } => "merge.render_verification_failed",
        }
    }
}

impl fmt::Display for MergeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MergeError::TooLarge { limit, actual } => {
                write!(f, "输入 {actual} 字节超过上限 {limit} 字节")
            }
            MergeError::DepthLimitExceeded { limit } => write!(f, "嵌套深度超过上限 {limit}"),
            MergeError::NodeLimitExceeded { limit } => write!(f, "节点数超过上限 {limit}"),
            MergeError::Parse { format, detail } => {
                write!(f, "{} 解析失败：{detail}", format_name(*format))
            }
            MergeError::DuplicateKey { pointer } => write!(f, "重复键 {pointer}"),
            MergeError::UnsupportedConstruct { format, detail } => {
                write!(f, "{} 不支持的构造：{detail}", format_name(*format))
            }
            MergeError::RenderVerificationFailed { format } => {
                write!(f, "{} 渲染后重解析校验失败", format_name(*format))
            }
        }
    }
}

impl std::error::Error for MergeError {}

/// 格式的稳定短名，用于诊断文本。
pub fn format_name(format: StructuredFormat) -> &'static str {
    match format {
        StructuredFormat::Json => "json",
        StructuredFormat::Yaml => "yaml",
        StructuredFormat::Toml => "toml",
        StructuredFormat::Ini => "ini",
        StructuredFormat::GitConfig => "git_config",
    }
}

/// INI 重复键（multi-value）的处理策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MultiValuePolicy {
    /// 默认：同一节内出现重复键直接报 [`MergeError::DuplicateKey`]。
    #[default]
    Reject,
    /// 后者覆盖前者，只保留最后一次出现的值。
    LastWins,
    /// 保留全部取值，按出现顺序组成多值键；合并时整体作为原子值。
    Append,
}

/// INI 合并策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IniPolicy {
    /// 重复键策略。
    pub multi_value: MultiValuePolicy,
}

/// 结构化合并的可调选项。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MergeOptions {
    /// INI 专用策略。
    pub ini: IniPolicy,
}

/// 文本三方合并。详见 [`text`] 模块文档。
pub fn merge_text(input: &MergeInput<'_>) -> Result<MergeResult, MergeError> {
    text::merge_text(input)
}

/// 结构化三方合并，使用默认 [`MergeOptions`]。
pub fn merge_structured(
    input: &MergeInput<'_>,
    format: StructuredFormat,
) -> Result<MergeResult, MergeError> {
    merge_structured_with(input, format, &MergeOptions::default())
}

/// 结构化三方合并，可传入选项（目前只有 INI 用到）。
pub fn merge_structured_with(
    input: &MergeInput<'_>,
    format: StructuredFormat,
    options: &MergeOptions,
) -> Result<MergeResult, MergeError> {
    for side in [input.base, input.ours, input.theirs].into_iter().flatten() {
        let actual = side.len() as u64;
        if actual > MAX_INPUT_BYTES {
            return Err(MergeError::TooLarge {
                limit: MAX_INPUT_BYTES,
                actual,
            });
        }
    }
    match format {
        StructuredFormat::Json => json::merge_json(input),
        StructuredFormat::Yaml => yaml::merge_yaml(input),
        StructuredFormat::Toml => toml::merge_toml(input),
        StructuredFormat::Ini => ini::merge_ini(input, options.ini),
        StructuredFormat::GitConfig => git_config::merge_git_config(input),
    }
}

/// 按资源模式选择合并器：给了格式就走语义合并，否则退化为文本合并。
pub fn merge(
    input: &MergeInput<'_>,
    format: Option<StructuredFormat>,
) -> Result<MergeResult, MergeError> {
    match format {
        Some(format) => merge_structured(input, format),
        None => merge_text(input),
    }
}

// ---------------------------------------------------------------------------
// 内部共享工具
// ---------------------------------------------------------------------------

/// 构造冲突对象。`diagnostics` 只允许包含位置/键路径。
pub(crate) fn build_conflict(
    input: &MergeInput<'_>,
    kind: ConflictKind,
    diagnostics: Vec<String>,
) -> Conflict {
    Conflict {
        format_version: CONFLICT_FORMAT_VERSION,
        resource: input.resource.clone(),
        kind,
        base: input.base.map(BlobId::of),
        ours: input.ours.map(BlobId::of),
        theirs: input.theirs.map(BlobId::of),
        diagnostics,
    }
}

/// 三方存在性的快速判定结果。
pub(crate) enum Presence<'a> {
    /// 已经可以直接给出结果，无需继续解析。
    Decided(MergeResult),
    /// 两侧内容都存在且互不相同，继续做内容级合并。
    Both {
        /// base 内容；双方新增时为 `None`。
        base: Option<&'a [u8]>,
        /// ours 内容。
        ours: &'a [u8],
        /// theirs 内容。
        theirs: &'a [u8],
    },
}

/// 处理「删除 / 新增 / 双方字节完全一致 / 只改一侧」这几类无需解析的情况。
///
/// 这些快速路径同时保证了 property：`merge(base, x, x)` 必然 `Clean(x)`，
/// 且只改一侧时结果逐字节等于改动的那一侧。
pub(crate) fn classify<'a>(input: &MergeInput<'a>) -> Presence<'a> {
    let (ours, theirs) = match (input.ours, input.theirs) {
        // 双方一致删除。
        (None, None) => return Presence::Decided(MergeResult::Deleted),
        (Some(present), None) => {
            return Presence::Decided(one_sided(input, present, "ours", "theirs"))
        }
        (None, Some(present)) => {
            return Presence::Decided(one_sided(input, present, "theirs", "ours"))
        }
        (Some(ours), Some(theirs)) => (ours, theirs),
    };

    // 双方新增了相同内容，或双方做了完全相同的修改。
    if ours == theirs {
        return Presence::Decided(MergeResult::Clean {
            bytes: ours.to_vec(),
            provenance: MergeProvenance::counts(1, 1, 0).note("ours 与 theirs 字节一致，直接采纳"),
        });
    }

    match input.base {
        Some(base) if base == ours => Presence::Decided(MergeResult::Clean {
            bytes: theirs.to_vec(),
            provenance: MergeProvenance::counts(0, 1, 0).note("仅 theirs 修改"),
        }),
        Some(base) if base == theirs => Presence::Decided(MergeResult::Clean {
            bytes: ours.to_vec(),
            provenance: MergeProvenance::counts(1, 0, 0).note("仅 ours 修改"),
        }),
        base => Presence::Both { base, ours, theirs },
    }
}

/// 一侧存在、另一侧删除时的判定。
fn one_sided(
    input: &MergeInput<'_>,
    present_bytes: &[u8],
    present_side: &str,
    deleted_side: &str,
) -> MergeResult {
    match input.base {
        // 一侧新增、另一侧仍不存在：采纳新增。
        None => MergeResult::Clean {
            bytes: present_bytes.to_vec(),
            provenance: side_counts(present_side).note(format!("仅 {present_side} 新增")),
        },
        // 一侧删除、另一侧未改动：接受删除。
        Some(base) if base == present_bytes => MergeResult::Deleted,
        // 一侧删除、另一侧修改：删除/修改冲突。
        Some(_) => MergeResult::Conflict(build_conflict(
            input,
            ConflictKind::DeleteModify,
            vec![format!("{deleted_side} deleted, {present_side} modified")],
        )),
    }
}

fn side_counts(side: &str) -> MergeProvenance {
    if side == "ours" {
        MergeProvenance::counts(1, 0, 0)
    } else {
        MergeProvenance::counts(0, 1, 0)
    }
}

/// 用于「渲染后重解析校验」的与格式无关的语义模型。
///
/// 数字统一按规范化文本比较，避免 `1.0` / `1` 这类往返表示差异造成误判；
/// `Map` 的键按字典序排序，因为所有目标格式的对象/表在语义上都是无序的。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Plain {
    /// 空值。
    Null,
    /// 布尔。
    Bool(bool),
    /// 数字（规范化文本）。
    Num(String),
    /// 字符串。
    Str(String),
    /// 序列（原子处理，但仍逐项比较）。
    Seq(Vec<Plain>),
    /// 映射，键按字典序排序。
    Map(Vec<(String, Plain)>),
}

impl Plain {
    /// 由 `(key, value)` 列表构造 Map，并按键排序以便比较。
    pub(crate) fn map(mut entries: Vec<(String, Plain)>) -> Plain {
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Plain::Map(entries)
    }
}

/// JSON Pointer token 转义（RFC 6901）。
pub(crate) fn escape_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// 在父路径上追加一个 token，得到子节点的 JSON Pointer。
pub(crate) fn child_pointer(parent: &str, token: &str) -> String {
    format!("{parent}/{}", escape_pointer_token(token))
}

/// 键级冲突的形态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConflictShape {
    /// 双方都改成了不同的值。
    ModifyModify,
    /// 一侧删除、另一侧修改。
    DeleteModify,
}

/// 结构化合并中记录到的单个键级冲突。
pub(crate) struct KeyConflict {
    /// 键路径（JSON Pointer 或等价形式）。
    pub(crate) pointer: String,
    /// 冲突形态。
    pub(crate) shape: ConflictShape,
}

impl KeyConflict {
    /// 渲染成不含正文的诊断行。
    pub(crate) fn diagnostic(&self) -> String {
        match self.shape {
            ConflictShape::ModifyModify => format!("modify/modify {}", self.pointer),
            ConflictShape::DeleteModify => format!("delete/modify {}", self.pointer),
        }
    }
}

/// 根据键级冲突列表构造 [`Conflict`]。
///
/// 全部为 delete/modify 时取 [`ConflictKind::DeleteModify`]，否则取
/// [`ConflictKind::StructuredKey`]。
pub(crate) fn structured_conflict(input: &MergeInput<'_>, conflicts: &[KeyConflict]) -> Conflict {
    let kind = if conflicts
        .iter()
        .all(|c| c.shape == ConflictShape::DeleteModify)
    {
        ConflictKind::DeleteModify
    } else {
        ConflictKind::StructuredKey
    };
    let mut diagnostics: Vec<String> = conflicts.iter().map(KeyConflict::diagnostic).collect();
    diagnostics.sort();
    diagnostics.dedup();
    build_conflict(input, kind, diagnostics)
}

/// 可按键递归合并的树形值。
///
/// 只有「键全部是字符串的映射」才允许递归；其他一切（数组、序列、标量、含非字符串
/// 键的映射）都按**原子值**处理，即整体取一侧或整体冲突。
pub(crate) trait TreeValue: Clone + PartialEq {
    /// 若自身是可递归的映射，返回其有序 `(key, value)` 列表。
    fn entries(&self) -> Option<Vec<(String, Self)>>;

    /// 由有序 `(key, value)` 列表重建映射。
    fn from_entries(entries: Vec<(String, Self)>) -> Self;
}

/// 通用的按键三方合并。
///
/// 返回 `None` 表示该键在结果中不存在（双方一致删除，或一侧删除且另一侧未改动）。
/// 冲突不会中断遍历，而是全部收集到 `conflicts` 里，便于一次性报告所有冲突键。
pub(crate) fn merge_tree<V: TreeValue>(
    base: Option<&V>,
    ours: Option<&V>,
    theirs: Option<&V>,
    pointer: &str,
    conflicts: &mut Vec<KeyConflict>,
    provenance: &mut MergeProvenance,
) -> Option<V> {
    // 双方结果一致（含双方一致删除）。
    if ours == theirs {
        if base == ours {
            provenance.took_base += 1;
        } else {
            provenance.took_ours += 1;
            provenance.took_theirs += 1;
        }
        return ours.cloned();
    }
    // 只有 theirs 改动。
    if base == ours {
        provenance.took_theirs += 1;
        return theirs.cloned();
    }
    // 只有 ours 改动。
    if base == theirs {
        provenance.took_ours += 1;
        return ours.cloned();
    }

    // 双方都改动且结果不同：只有「双方都还是映射」时才能继续按键下钻。
    if let (Some(ours_value), Some(theirs_value)) = (ours, theirs) {
        if let (Some(ours_entries), Some(theirs_entries)) =
            (ours_value.entries(), theirs_value.entries())
        {
            let base_entries = base.and_then(TreeValue::entries).unwrap_or_default();
            let merged = merge_entries(
                &base_entries,
                &ours_entries,
                &theirs_entries,
                pointer,
                conflicts,
                provenance,
            );
            return Some(V::from_entries(merged));
        }
    }

    conflicts.push(KeyConflict {
        pointer: if pointer.is_empty() {
            "/".to_owned()
        } else {
            pointer.to_owned()
        },
        shape: if ours.is_none() || theirs.is_none() {
            ConflictShape::DeleteModify
        } else {
            ConflictShape::ModifyModify
        },
    });
    // 占位：调用方在 `conflicts` 非空时会丢弃合并结果并产出 Conflict 对象。
    ours.or(theirs).cloned()
}

/// 按 base → ours → theirs 的出现顺序取键的并集，逐键递归合并。
fn merge_entries<V: TreeValue>(
    base: &[(String, V)],
    ours: &[(String, V)],
    theirs: &[(String, V)],
    pointer: &str,
    conflicts: &mut Vec<KeyConflict>,
    provenance: &mut MergeProvenance,
) -> Vec<(String, V)> {
    let mut order: Vec<&String> = Vec::new();
    for key in base
        .iter()
        .chain(ours.iter())
        .chain(theirs.iter())
        .map(|(k, _)| k)
    {
        if !order.contains(&key) {
            order.push(key);
        }
    }

    let lookup = |entries: &[(String, V)], key: &str| -> Option<V> {
        entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    };

    let mut merged = Vec::with_capacity(order.len());
    for key in order {
        let child_pointer = child_pointer(pointer, key);
        let base_child = lookup(base, key);
        let ours_child = lookup(ours, key);
        let theirs_child = lookup(theirs, key);
        if let Some(value) = merge_tree(
            base_child.as_ref(),
            ours_child.as_ref(),
            theirs_child.as_ref(),
            &child_pointer,
            conflicts,
            provenance,
        ) {
            merged.push((key.clone(), value));
        }
    }
    merged
}

/// 深度 / 节点预算，供各格式解析器共享。
pub(crate) struct Budget {
    nodes: usize,
}

impl Budget {
    /// 新建预算。
    pub(crate) fn new() -> Self {
        Budget { nodes: 0 }
    }

    /// 记一个节点并检查深度与节点数上限。
    pub(crate) fn charge(&mut self, depth: usize) -> Result<(), MergeError> {
        if depth > MAX_PARSE_DEPTH {
            return Err(MergeError::DepthLimitExceeded {
                limit: MAX_PARSE_DEPTH,
            });
        }
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(MergeError::NodeLimitExceeded { limit: MAX_NODES });
        }
        Ok(())
    }
}
