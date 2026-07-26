//! 设备 Profile、封闭选择器 AST、投影诊断与冲突解决方案。
//!
//! 设计文档 §3.1 要求同一个 Snapshot 能按设备 Profile 投影出不同的本地 Plan。本模块
//! 定义投影所需的**纯数据**：设备自身的属性（[`DeviceProfile`]）、描述“哪些设备适用”
//! 的选择器（[`Selector`]）、投影过程产生的诊断（[`ProjectionNote`]），以及冲突的
//! 解决方案（[`ConflictResolution`]）。
//!
//! ## 为什么选择器是“封闭”的
//!
//! 选择器来自会被同步到所有设备的配置，因此它是**不可信输入**：一台设备上写下的
//! 表达式会在其他所有设备上求值。所以这里刻意不提供正则、通配符或脚本，只保留
//! 一组固定的谓词（[`Predicate`]）和三个布尔组合子（`All`/`Any`/`Not`）。这样求值
//! 一定终止、代价与节点数成正比，也不存在灾难性回溯。
//!
//! 此外还有两道资源上限：递归深度 [`MAX_SELECTOR_DEPTH`] 与节点总数
//! [`MAX_SELECTOR_NODES`]。二者都在 [`Selector::validate`] 中强制。
//!
//! ## 使用契约：先 validate，再 matches
//!
//! **调用 [`Selector::matches`] 之前必须先调用 [`Selector::validate`]**，并且只在校验
//! 通过时才求值。`matches` 自身不返回错误（布尔谓词返回 `Result` 会污染全部调用方），
//! 但它内部仍保留一份硬性的深度与节点预算：一旦触碰上限，求值立刻中止并保守地
//! 返回 `false`（“不匹配”＝不下发任何资源），绝不 panic、绝不栈溢出。
//!
//! ## 字符串取值的规范化
//!
//! `hostname`、标签和能力都是在设备之间比较的字面量，因此必须只有一种表示：构造时
//! 统一 `trim`，空白与超长取值被拒绝。[`DeviceProfile`] 的链式构造器是**不返回错误**
//! 的（便于书写），它会丢弃非法取值；需要显式错误时使用对应的 `try_*` 方法。无论
//! 走哪条路径都不会 panic。
//!
//! ```
//! use envsync_domain::profile::{Arch, DeviceProfile, Os, Predicate, Selector};
//!
//! let profile = DeviceProfile::new(Os::Linux, Arch::Aarch64).with_tag("work");
//! let selector = Selector::all([Predicate::Os(Os::Linux), Predicate::Tag("work".into())]);
//! selector.validate()?;
//! assert!(selector.matches(&profile));
//! # Ok::<(), envsync_domain::profile::ProfileError>(())
//! ```

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::cbor::{CborCodec, CborError, Value};
use crate::id::{BlobId, ConflictId, DeviceId, ResourceId};

/// 选择器允许的最大递归深度。
///
/// 深度从 1 开始计（单个谓词深度为 1）。超过该值的选择器一律拒绝：它既无法表达
/// 真实需求，又是典型的资源耗尽载体。
pub const MAX_SELECTOR_DEPTH: usize = 16;

/// 选择器允许的最大节点总数（组合子与谓词都计入）。
pub const MAX_SELECTOR_NODES: usize = 256;

/// Profile 中单个字符串取值的最大字节长度。
pub const MAX_PROFILE_VALUE_LEN: usize = 256;

/// 标签集合或能力集合的最大元素个数。
pub const MAX_PROFILE_ENTRIES: usize = 128;

/// [`DeviceProfile`] 的编码格式版本。
pub const PROFILE_FORMAT_VERSION: u32 = 1;

/// [`Selector`] 的编码格式版本。
pub const SELECTOR_FORMAT_VERSION: u32 = 1;

/// [`ProjectionNote`] 的编码格式版本。
pub const PROJECTION_NOTE_FORMAT_VERSION: u32 = 1;

/// [`ConflictResolution`] 的编码格式版本。
pub const RESOLUTION_FORMAT_VERSION: u32 = 1;

/// Profile、选择器与冲突解决方案的校验错误。
///
/// 所有变体只描述结构问题，不携带资源内容，可以安全写入日志与 CLI 输出。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// 取值为空或只含空白。
    #[error("`{field}` 不能为空或只含空白")]
    EmptyValue {
        /// 出错的字段名。
        field: &'static str,
    },
    /// 取值超过 [`MAX_PROFILE_VALUE_LEN`]。
    #[error("`{field}` 长度 {len} 字节超过上限 {max} 字节")]
    ValueTooLong {
        /// 出错的字段名。
        field: &'static str,
        /// 实际长度。
        len: usize,
        /// 允许的上限。
        max: usize,
    },
    /// 取值首尾含空白，未经规范化。
    #[error("`{field}` 首尾不能包含空白")]
    NotNormalized {
        /// 出错的字段名。
        field: &'static str,
    },
    /// 集合元素个数超过 [`MAX_PROFILE_ENTRIES`]。
    #[error("`{field}` 的元素个数超过上限 {max}")]
    TooManyEntries {
        /// 出错的字段名。
        field: &'static str,
        /// 允许的上限。
        max: usize,
    },
    /// 选择器嵌套深度超过 [`MAX_SELECTOR_DEPTH`]。
    #[error("选择器嵌套深度超过上限 {max}")]
    DepthLimitExceeded {
        /// 允许的上限。
        max: usize,
    },
    /// 选择器节点数超过 [`MAX_SELECTOR_NODES`]。
    #[error("选择器节点数超过上限 {max}")]
    NodeLimitExceeded {
        /// 允许的上限。
        max: usize,
    },
    /// 解决方案需要一个结果 Blob，却没有提供。
    #[error("解决方式 `{choice}` 必须给出结果 Blob")]
    ResolutionBlobMissing {
        /// 所选的解决方式。
        choice: &'static str,
    },
    /// 解决方案不应带结果 Blob，却提供了。
    #[error("解决方式 `{choice}` 不能带结果 Blob")]
    ResolutionBlobUnexpected {
        /// 所选的解决方式。
        choice: &'static str,
    },
    /// 解决方案引用了并不存在的 Blob。
    #[error("解决方案引用的 Blob {blob} 不存在")]
    ResolutionBlobUnknown {
        /// 被引用的 Blob 的十六进制标识。
        blob: String,
    },
}

// ---------------------------------------------------------------------------
// 平台枚举
// ---------------------------------------------------------------------------

/// 操作系统。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Os {
    /// macOS。
    #[serde(rename = "macos")]
    MacOs,
    /// Linux。
    #[serde(rename = "linux")]
    Linux,
    /// Windows。
    #[serde(rename = "windows")]
    Windows,
}

impl Os {
    /// 稳定的短名称，用于持久化与诊断。
    pub const fn as_str(self) -> &'static str {
        match self {
            Os::MacOs => "macos",
            Os::Linux => "linux",
            Os::Windows => "windows",
        }
    }

    /// 由短名称解析；未知取值返回 `None`。
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "macos" => Os::MacOs,
            "linux" => Os::Linux,
            "windows" => Os::Windows,
            _ => return None,
        })
    }
}

crate::cbor_unit_enum!(Os {
    Os::MacOs => "macos",
    Os::Linux => "linux",
    Os::Windows => "windows",
});

/// 处理器架构。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Arch {
    /// 64 位 x86。
    #[serde(rename = "x86_64")]
    X86_64,
    /// 64 位 ARM。
    #[serde(rename = "aarch64")]
    Aarch64,
}

impl Arch {
    /// 稳定的短名称，用于持久化与诊断。
    pub const fn as_str(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        }
    }

    /// 由短名称解析；未知取值返回 `None`。
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "x86_64" => Arch::X86_64,
            "aarch64" => Arch::Aarch64,
            _ => return None,
        })
    }
}

crate::cbor_unit_enum!(Arch {
    Arch::X86_64 => "x86_64",
    Arch::Aarch64 => "aarch64",
});

// ---------------------------------------------------------------------------
// 字符串取值的规范化
// ---------------------------------------------------------------------------

/// 规范化一个 Profile 字符串取值：`trim` 后校验非空与长度。
fn normalize(field: &'static str, raw: &str) -> Result<String, ProfileError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ProfileError::EmptyValue { field });
    }
    if trimmed.len() > MAX_PROFILE_VALUE_LEN {
        return Err(ProfileError::ValueTooLong {
            field,
            len: trimmed.len(),
            max: MAX_PROFILE_VALUE_LEN,
        });
    }
    Ok(trimmed.to_owned())
}

/// 校验一个**已存在**的取值确实是规范形式（用于反序列化后的检查）。
fn check_normalized(field: &'static str, raw: &str) -> Result<(), ProfileError> {
    let normalized = normalize(field, raw)?;
    if normalized != raw {
        return Err(ProfileError::NotNormalized { field });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DeviceProfile
// ---------------------------------------------------------------------------

/// 设备 Profile：投影时用来判断“这台设备应该拿到什么”的全部输入。
///
/// 链式构造器不返回错误，非法取值会被**丢弃**而不是 panic；需要显式错误时用
/// `try_*` 版本。反序列化得到的实例必须先经过 [`DeviceProfile::validate`]。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceProfile {
    /// 操作系统。
    pub os: Os,
    /// 处理器架构。
    pub arch: Arch,
    /// 主机名；未知或刻意不参与投影时为 `None`。
    pub hostname: Option<String>,
    /// 设备标签，例如 `work`、`laptop`。
    pub tags: BTreeSet<String>,
    /// 可用能力，例如 `brew`、`scoop`、`pwsh`。
    pub capabilities: BTreeSet<String>,
    /// 设备标识；用于 device-id 级别的精确覆盖。
    pub device: Option<DeviceId>,
}

impl DeviceProfile {
    /// 构造一个只有操作系统与架构的最小 Profile。
    pub fn new(os: Os, arch: Arch) -> Self {
        DeviceProfile {
            os,
            arch,
            hostname: None,
            tags: BTreeSet::new(),
            capabilities: BTreeSet::new(),
            device: None,
        }
    }

    /// 添加一个标签；空白、超长或超出数量上限的取值会被静默丢弃。
    ///
    /// 需要知道取值是否被接受时请用 [`DeviceProfile::try_with_tag`]。
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        if let Ok(value) = normalize("tag", &tag.into()) {
            if self.tags.len() < MAX_PROFILE_ENTRIES || self.tags.contains(&value) {
                self.tags.insert(value);
            }
        }
        self
    }

    /// 添加一个标签，取值非法时返回错误。
    pub fn try_with_tag(mut self, tag: impl Into<String>) -> Result<Self, ProfileError> {
        let value = normalize("tag", &tag.into())?;
        if self.tags.len() >= MAX_PROFILE_ENTRIES && !self.tags.contains(&value) {
            return Err(ProfileError::TooManyEntries {
                field: "tags",
                max: MAX_PROFILE_ENTRIES,
            });
        }
        self.tags.insert(value);
        Ok(self)
    }

    /// 添加一个能力；空白、超长或超出数量上限的取值会被静默丢弃。
    pub fn with_capability(mut self, capability: impl Into<String>) -> Self {
        if let Ok(value) = normalize("capability", &capability.into()) {
            if self.capabilities.len() < MAX_PROFILE_ENTRIES || self.capabilities.contains(&value) {
                self.capabilities.insert(value);
            }
        }
        self
    }

    /// 添加一个能力，取值非法时返回错误。
    pub fn try_with_capability(
        mut self,
        capability: impl Into<String>,
    ) -> Result<Self, ProfileError> {
        let value = normalize("capability", &capability.into())?;
        if self.capabilities.len() >= MAX_PROFILE_ENTRIES && !self.capabilities.contains(&value) {
            return Err(ProfileError::TooManyEntries {
                field: "capabilities",
                max: MAX_PROFILE_ENTRIES,
            });
        }
        self.capabilities.insert(value);
        Ok(self)
    }

    /// 设置主机名；空白或超长的取值会被静默丢弃（保持原值）。
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        if let Ok(value) = normalize("hostname", &hostname.into()) {
            self.hostname = Some(value);
        }
        self
    }

    /// 设置主机名，取值非法时返回错误。
    pub fn try_with_hostname(mut self, hostname: impl Into<String>) -> Result<Self, ProfileError> {
        self.hostname = Some(normalize("hostname", &hostname.into())?);
        Ok(self)
    }

    /// 设置设备标识。
    pub fn with_device(mut self, device: DeviceId) -> Self {
        self.device = Some(device);
        self
    }

    /// 校验全部字符串取值都是规范形式、集合大小在上限之内。
    ///
    /// 链式构造器已经保证这一点；该方法用于反序列化或手工构造的实例。
    pub fn validate(&self) -> Result<(), ProfileError> {
        if let Some(hostname) = &self.hostname {
            check_normalized("hostname", hostname)?;
        }
        if self.tags.len() > MAX_PROFILE_ENTRIES {
            return Err(ProfileError::TooManyEntries {
                field: "tags",
                max: MAX_PROFILE_ENTRIES,
            });
        }
        for tag in &self.tags {
            check_normalized("tag", tag)?;
        }
        if self.capabilities.len() > MAX_PROFILE_ENTRIES {
            return Err(ProfileError::TooManyEntries {
                field: "capabilities",
                max: MAX_PROFILE_ENTRIES,
            });
        }
        for capability in &self.capabilities {
            check_normalized("capability", capability)?;
        }
        Ok(())
    }

    /// 是否具备给定能力。
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.contains(capability)
    }

    /// 是否带有给定标签。
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.contains(tag)
    }
}

// ---------------------------------------------------------------------------
// 选择器 AST
// ---------------------------------------------------------------------------

/// 选择器的叶子谓词。
///
/// 变体是公开的（便于在测试与配置解析中直接书写），因此**取值未必规范**；
/// 生产路径应使用 [`Predicate::tag`] 等受检构造器，或在求值前调用
/// [`Selector::validate`]。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Predicate {
    /// 操作系统等于给定值。
    Os(Os),
    /// 架构等于给定值。
    Arch(Arch),
    /// 主机名精确等于给定值。
    Hostname(String),
    /// 带有给定标签。
    Tag(String),
    /// 具备给定能力。
    Capability(String),
    /// 设备标识精确等于给定值。
    Device(DeviceId),
}

impl Predicate {
    /// 构造主机名谓词，取值非法时返回错误。
    pub fn hostname(value: impl Into<String>) -> Result<Self, ProfileError> {
        Ok(Predicate::Hostname(normalize("hostname", &value.into())?))
    }

    /// 构造标签谓词，取值非法时返回错误。
    pub fn tag(value: impl Into<String>) -> Result<Self, ProfileError> {
        Ok(Predicate::Tag(normalize("tag", &value.into())?))
    }

    /// 构造能力谓词，取值非法时返回错误。
    pub fn capability(value: impl Into<String>) -> Result<Self, ProfileError> {
        Ok(Predicate::Capability(normalize(
            "capability",
            &value.into(),
        )?))
    }

    /// 校验谓词携带的字符串取值是规范形式。
    pub fn validate(&self) -> Result<(), ProfileError> {
        match self {
            Predicate::Os(_) | Predicate::Arch(_) | Predicate::Device(_) => Ok(()),
            Predicate::Hostname(value) => check_normalized("hostname", value),
            Predicate::Tag(value) => check_normalized("tag", value),
            Predicate::Capability(value) => check_normalized("capability", value),
        }
    }

    /// 对给定 Profile 求值。
    pub fn matches(&self, profile: &DeviceProfile) -> bool {
        match self {
            Predicate::Os(os) => profile.os == *os,
            Predicate::Arch(arch) => profile.arch == *arch,
            Predicate::Hostname(value) => profile.hostname.as_deref() == Some(value.as_str()),
            Predicate::Tag(value) => profile.tags.contains(value),
            Predicate::Capability(value) => profile.capabilities.contains(value),
            Predicate::Device(device) => profile.device == Some(*device),
        }
    }
}

/// 封闭的选择器 AST。
///
/// 语义：
///
/// * `All` —— 全部子项都成立；**空 `All` 恒为真**（合取的单位元）；
/// * `Any` —— 至少一个子项成立；**空 `Any` 恒为假**（析取的单位元）；
/// * `Not` —— 子项取反；
/// * `Is` —— 单个谓词。
///
/// 空集合的语义刻意固定为上述数学约定，而不是“空即匹配全部”之类的隐式行为，
/// 以免不同实现给出不同结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Selector {
    /// 合取。
    All(Vec<Selector>),
    /// 析取。
    Any(Vec<Selector>),
    /// 取反。
    Not(Box<Selector>),
    /// 叶子谓词。
    Is(Predicate),
}

impl Selector {
    /// 由一组谓词构造合取选择器。
    pub fn all(items: impl IntoIterator<Item = Predicate>) -> Selector {
        Selector::All(items.into_iter().map(Selector::Is).collect())
    }

    /// 由一组谓词构造析取选择器。
    pub fn any(items: impl IntoIterator<Item = Predicate>) -> Selector {
        Selector::Any(items.into_iter().map(Selector::Is).collect())
    }

    /// 对一个子选择器取反。
    ///
    /// 刻意不叫 `not`：那会与 [`std::ops::Not::not`] 混淆。
    pub fn negate(inner: Selector) -> Selector {
        Selector::Not(Box::new(inner))
    }

    /// 由单个谓词构造叶子选择器。
    pub fn is(predicate: Predicate) -> Selector {
        Selector::Is(predicate)
    }

    /// 子节点视图；叶子返回空切片。
    fn children(&self) -> &[Selector] {
        match self {
            Selector::All(items) | Selector::Any(items) => items,
            Selector::Not(inner) => std::slice::from_ref(&**inner),
            Selector::Is(_) => &[],
        }
    }

    /// 节点总数（组合子与谓词都计入）。
    ///
    /// 实现是**迭代**的：选择器可能来自不可信配置，递归遍历本身就会成为栈溢出的入口。
    pub fn node_count(&self) -> usize {
        let mut count = 0usize;
        let mut stack = vec![self];
        while let Some(node) = stack.pop() {
            count = count.saturating_add(1);
            stack.extend(node.children());
        }
        count
    }

    /// 嵌套深度；单个谓词的深度为 1。
    ///
    /// 同样使用迭代实现，理由见 [`Selector::node_count`]。
    pub fn depth(&self) -> usize {
        let mut max_depth = 0usize;
        let mut stack = vec![(self, 1usize)];
        while let Some((node, depth)) = stack.pop() {
            max_depth = max_depth.max(depth);
            for child in node.children() {
                stack.push((child, depth.saturating_add(1)));
            }
        }
        max_depth
    }

    /// 校验深度、节点数与全部谓词取值。
    ///
    /// 遍历过程中一旦超过 [`MAX_SELECTOR_NODES`] 就立刻返回，不会先把整棵树走完，
    /// 因此对超大输入的代价是有界的。
    pub fn validate(&self) -> Result<(), ProfileError> {
        let mut visited = 0usize;
        let mut stack = vec![(self, 1usize)];
        while let Some((node, depth)) = stack.pop() {
            visited += 1;
            if visited > MAX_SELECTOR_NODES {
                return Err(ProfileError::NodeLimitExceeded {
                    max: MAX_SELECTOR_NODES,
                });
            }
            if depth > MAX_SELECTOR_DEPTH {
                return Err(ProfileError::DepthLimitExceeded {
                    max: MAX_SELECTOR_DEPTH,
                });
            }
            if let Selector::Is(predicate) = node {
                predicate.validate()?;
            }
            for child in node.children() {
                stack.push((child, depth + 1));
            }
        }
        Ok(())
    }

    /// 对给定 Profile 求值。
    ///
    /// **前置条件**：调用方应先调用 [`Selector::validate`] 并只在通过时求值。作为
    /// 纵深防御，本方法内部仍然保留深度与节点预算；一旦触碰上限，求值中止并返回
    /// `false`（保守地判定为“不匹配”，即不向该设备下发资源）。
    pub fn matches(&self, profile: &DeviceProfile) -> bool {
        let mut budget = MAX_SELECTOR_NODES;
        self.eval(profile, 1, &mut budget).unwrap_or(false)
    }

    /// 内部求值：返回 `None` 表示触碰了深度或节点预算。
    ///
    /// 用 `None` 而不是 `false` 表示“无法求值”至关重要：若超限时直接返回 `false`，
    /// 外层的 `Not` 会把它翻成 `true`，超限反而变成“匹配”，方向完全错误。
    fn eval(&self, profile: &DeviceProfile, depth: usize, budget: &mut usize) -> Option<bool> {
        if depth > MAX_SELECTOR_DEPTH || *budget == 0 {
            return None;
        }
        *budget -= 1;
        match self {
            Selector::All(items) => {
                for item in items {
                    if !item.eval(profile, depth + 1, budget)? {
                        return Some(false);
                    }
                }
                Some(true)
            }
            Selector::Any(items) => {
                for item in items {
                    if item.eval(profile, depth + 1, budget)? {
                        return Some(true);
                    }
                }
                Some(false)
            }
            Selector::Not(inner) => Some(!inner.eval(profile, depth + 1, budget)?),
            Selector::Is(predicate) => Some(predicate.matches(profile)),
        }
    }
}

// ---------------------------------------------------------------------------
// 投影诊断
// ---------------------------------------------------------------------------

/// 投影诊断的种类。
///
/// 诊断解释“某个资源为什么出现或没有出现在这台设备的视图里”。它**不是**错误：
/// 能力缺失只会产生 [`ProjectionNoteKind::UnsupportedCapability`]，绝不能被推断为
/// 删除意图（设计文档 §3.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionNoteKind {
    /// 作为全局资源被选中。
    SelectedByGlobal,
    /// 因选择器命中而被选中。
    SelectedBySelector,
    /// 被 device-id 级别的覆盖替换。
    OverriddenByDevice,
    /// 因选择器未命中而被排除。
    ExcludedBySelector,
    /// 被安全策略排除。
    ExcludedByPolicy,
    /// 当前设备缺少所需能力。
    UnsupportedCapability,
}

crate::cbor_unit_enum!(ProjectionNoteKind {
    ProjectionNoteKind::SelectedByGlobal => "selected_by_global",
    ProjectionNoteKind::SelectedBySelector => "selected_by_selector",
    ProjectionNoteKind::OverriddenByDevice => "overridden_by_device",
    ProjectionNoteKind::ExcludedBySelector => "excluded_by_selector",
    ProjectionNoteKind::ExcludedByPolicy => "excluded_by_policy",
    ProjectionNoteKind::UnsupportedCapability => "unsupported_capability",
});

/// 单条投影诊断。
///
/// `detail` 只放结构性说明（例如命中的谓词、被拒的策略名），**不得**包含资源内容。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionNote {
    /// 相关资源。
    pub resource: ResourceId,
    /// 诊断种类。
    pub kind: ProjectionNoteKind,
    /// 人类可读的补充说明。
    pub detail: String,
}

impl ProjectionNote {
    /// 构造一条诊断。
    pub fn new(resource: ResourceId, kind: ProjectionNoteKind, detail: impl Into<String>) -> Self {
        ProjectionNote {
            resource,
            kind,
            detail: detail.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// 冲突解决方案
// ---------------------------------------------------------------------------

/// 冲突的解决方式。
///
/// [`crate::object::Conflict`] 本身只描述“发生了什么冲突”，它是不可变的内容寻址
/// 对象；用户的决定单独记在这里，因此同一个冲突对象可以在不同工作区被不同地解决。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionChoice {
    /// 采用本地一侧的内容。
    Ours,
    /// 采用远端一侧的内容。
    Theirs,
    /// 采用人工合并后的内容。
    Manual,
    /// 确认删除该资源。
    Delete,
}

impl ResolutionChoice {
    /// 稳定的短名称，用于持久化与诊断。
    pub const fn as_str(self) -> &'static str {
        match self {
            ResolutionChoice::Ours => "ours",
            ResolutionChoice::Theirs => "theirs",
            ResolutionChoice::Manual => "manual",
            ResolutionChoice::Delete => "delete",
        }
    }

    /// 由短名称解析；未知取值返回 `None`。
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "ours" => ResolutionChoice::Ours,
            "theirs" => ResolutionChoice::Theirs,
            "manual" => ResolutionChoice::Manual,
            "delete" => ResolutionChoice::Delete,
            _ => return None,
        })
    }

    /// 该解决方式是否必须指向一个结果 Blob。
    pub const fn requires_blob(self) -> bool {
        !matches!(self, ResolutionChoice::Delete)
    }
}

crate::cbor_unit_enum!(ResolutionChoice {
    ResolutionChoice::Ours => "ours",
    ResolutionChoice::Theirs => "theirs",
    ResolutionChoice::Manual => "manual",
    ResolutionChoice::Delete => "delete",
});

/// 冲突的解决方案。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictResolution {
    /// 被解决的冲突。
    pub conflict: ConflictId,
    /// 解决方式。
    pub choice: ResolutionChoice,
    /// 解决后的内容；`Delete` 时必须为 `None`，其余方式必须为 `Some`。
    pub resolved_blob: Option<BlobId>,
    /// 解决时间（Unix 毫秒）。
    pub resolved_at_unix_ms: u64,
}

impl ConflictResolution {
    /// 构造一个“采用某个 Blob”的解决方案。
    pub fn with_blob(
        conflict: ConflictId,
        choice: ResolutionChoice,
        blob: BlobId,
        resolved_at_unix_ms: u64,
    ) -> Self {
        ConflictResolution {
            conflict,
            choice,
            resolved_blob: Some(blob),
            resolved_at_unix_ms,
        }
    }

    /// 构造一个“确认删除”的解决方案。
    pub fn delete(conflict: ConflictId, resolved_at_unix_ms: u64) -> Self {
        ConflictResolution {
            conflict,
            choice: ResolutionChoice::Delete,
            resolved_blob: None,
            resolved_at_unix_ms,
        }
    }

    /// 校验解决方案自洽，并且它引用的 Blob **确实存在**。
    ///
    /// 存在性由调用方注入：领域层不做 I/O，但“解决方案指向一个不存在的 Blob”是必须
    /// 在应用之前拦下的错误——否则收敛阶段会拿不到内容，而此时用户文件可能已被动过。
    pub fn validate(&self, blob_exists: &dyn Fn(BlobId) -> bool) -> Result<(), ProfileError> {
        match (self.choice.requires_blob(), self.resolved_blob) {
            (true, None) => Err(ProfileError::ResolutionBlobMissing {
                choice: self.choice.as_str(),
            }),
            (false, Some(_)) => Err(ProfileError::ResolutionBlobUnexpected {
                choice: self.choice.as_str(),
            }),
            (false, None) => Ok(()),
            (true, Some(blob)) => {
                if blob_exists(blob) {
                    Ok(())
                } else {
                    Err(ProfileError::ResolutionBlobUnknown {
                        blob: blob.to_hex(),
                    })
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// canonical CBOR 编码
// ---------------------------------------------------------------------------

/// 构造 `[版本, 字段...]` 形式的数组。
fn versioned(version: u32, fields: Vec<Value>) -> Value {
    let mut items = Vec::with_capacity(fields.len() + 1);
    items.push(Value::Uint(version as u64));
    items.extend(fields);
    Value::Array(items)
}

/// 校验 `[版本, 字段...]` 数组的版本与字段个数，返回字段切片。
///
/// 版本检查刻意排在字段个数检查之前：未来版本很可能字段更多，先报“字段数不符”
/// 会掩盖真正的原因（设计文档 §3.3 要求未知版本必须显式拒绝）。
fn expect_versioned(value: &Value, supported: u32, arity: usize) -> Result<&[Value], CborError> {
    let items = value.as_array()?;
    let (head, rest) = items.split_first().ok_or(CborError::ArityMismatch)?;
    let found = u32::from_value(head)?;
    if found != supported {
        return Err(CborError::UnsupportedFormatVersion { found, supported });
    }
    if rest.len() != arity {
        return Err(CborError::ArityMismatch);
    }
    Ok(rest)
}

/// 把字符串集合编码为 CBOR 数组（`BTreeSet` 的迭代顺序天然升序，因此结果确定）。
fn set_to_value(set: &BTreeSet<String>) -> Value {
    Value::Array(set.iter().map(|item| Value::Text(item.clone())).collect())
}

/// 解码字符串集合，并要求输入严格升序、无重复。
///
/// 若接受任意顺序，同一个逻辑集合就会有多种编码，破坏“解码后重新编码必然得到原
/// 字节”这一内容寻址前提。
fn set_from_value(value: &Value) -> Result<BTreeSet<String>, CborError> {
    let mut out = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for item in value.as_array()? {
        let text = item.as_text()?;
        match previous {
            Some(prev) if prev >= text => {
                return Err(CborError::InvalidValue(
                    "集合元素必须严格升序且互不相同".to_owned(),
                ));
            }
            _ => {}
        }
        previous = Some(text);
        out.insert(text.to_owned());
    }
    Ok(out)
}

impl CborCodec for DeviceProfile {
    fn to_value(&self) -> Value {
        versioned(
            PROFILE_FORMAT_VERSION,
            vec![
                self.os.to_value(),
                self.arch.to_value(),
                self.hostname.to_value(),
                set_to_value(&self.tags),
                set_to_value(&self.capabilities),
                self.device.to_value(),
            ],
        )
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let fields = expect_versioned(value, PROFILE_FORMAT_VERSION, 6)?;
        let profile = DeviceProfile {
            os: Os::from_value(&fields[0])?,
            arch: Arch::from_value(&fields[1])?,
            hostname: Option::<String>::from_value(&fields[2])?,
            tags: set_from_value(&fields[3])?,
            capabilities: set_from_value(&fields[4])?,
            device: Option::<DeviceId>::from_value(&fields[5])?,
        };
        profile
            .validate()
            .map_err(|error| CborError::InvalidValue(error.to_string()))?;
        Ok(profile)
    }
}

impl CborCodec for Predicate {
    fn to_value(&self) -> Value {
        let (tag, payload) = match self {
            Predicate::Os(os) => ("os", os.to_value()),
            Predicate::Arch(arch) => ("arch", arch.to_value()),
            Predicate::Hostname(value) => ("hostname", Value::Text(value.clone())),
            Predicate::Tag(value) => ("tag", Value::Text(value.clone())),
            Predicate::Capability(value) => ("capability", Value::Text(value.clone())),
            Predicate::Device(device) => ("device", device.to_value()),
        };
        Value::Array(vec![Value::Text(tag.to_owned()), payload])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        if items.len() != 2 {
            return Err(CborError::ArityMismatch);
        }
        let payload = &items[1];
        Ok(match items[0].as_text()? {
            "os" => Predicate::Os(Os::from_value(payload)?),
            "arch" => Predicate::Arch(Arch::from_value(payload)?),
            "hostname" => Predicate::Hostname(payload.as_text()?.to_owned()),
            "tag" => Predicate::Tag(payload.as_text()?.to_owned()),
            "capability" => Predicate::Capability(payload.as_text()?.to_owned()),
            "device" => Predicate::Device(DeviceId::from_value(payload)?),
            other => return Err(CborError::UnknownVariant(other.to_owned())),
        })
    }
}

/// 编码单个选择器节点（不含版本头）。
fn node_to_value(node: &Selector) -> Value {
    let (tag, payload) = match node {
        Selector::All(items) => (
            "all",
            Value::Array(items.iter().map(node_to_value).collect()),
        ),
        Selector::Any(items) => (
            "any",
            Value::Array(items.iter().map(node_to_value).collect()),
        ),
        Selector::Not(inner) => ("not", node_to_value(inner)),
        Selector::Is(predicate) => ("is", predicate.to_value()),
    };
    Value::Array(vec![Value::Text(tag.to_owned()), payload])
}

/// 解码单个选择器节点，并在递归过程中强制深度上限。
///
/// 这是**唯一**从不可信字节构造 [`Selector`] 的入口，因此深度保护必须在这里，
/// 而不是留给之后的 `validate`：递归解析本身就会先把栈耗尽。
fn node_from_value(value: &Value, depth: usize) -> Result<Selector, CborError> {
    if depth > MAX_SELECTOR_DEPTH {
        return Err(CborError::InvalidValue(format!(
            "选择器嵌套深度超过上限 {MAX_SELECTOR_DEPTH}"
        )));
    }
    let items = value.as_array()?;
    if items.len() != 2 {
        return Err(CborError::ArityMismatch);
    }
    let payload = &items[1];
    Ok(match items[0].as_text()? {
        "all" => Selector::All(
            payload
                .as_array()?
                .iter()
                .map(|item| node_from_value(item, depth + 1))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        "any" => Selector::Any(
            payload
                .as_array()?
                .iter()
                .map(|item| node_from_value(item, depth + 1))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        "not" => Selector::Not(Box::new(node_from_value(payload, depth + 1)?)),
        "is" => Selector::Is(Predicate::from_value(payload)?),
        other => return Err(CborError::UnknownVariant(other.to_owned())),
    })
}

impl CborCodec for Selector {
    fn to_value(&self) -> Value {
        versioned(SELECTOR_FORMAT_VERSION, vec![node_to_value(self)])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let fields = expect_versioned(value, SELECTOR_FORMAT_VERSION, 1)?;
        let selector = node_from_value(&fields[0], 1)?;
        selector
            .validate()
            .map_err(|error| CborError::InvalidValue(error.to_string()))?;
        Ok(selector)
    }
}

impl CborCodec for ProjectionNote {
    fn to_value(&self) -> Value {
        versioned(
            PROJECTION_NOTE_FORMAT_VERSION,
            vec![
                self.resource.to_value(),
                self.kind.to_value(),
                Value::Text(self.detail.clone()),
            ],
        )
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let fields = expect_versioned(value, PROJECTION_NOTE_FORMAT_VERSION, 3)?;
        Ok(ProjectionNote {
            resource: ResourceId::from_value(&fields[0])?,
            kind: ProjectionNoteKind::from_value(&fields[1])?,
            detail: fields[2].as_text()?.to_owned(),
        })
    }
}

impl CborCodec for ConflictResolution {
    fn to_value(&self) -> Value {
        versioned(
            RESOLUTION_FORMAT_VERSION,
            vec![
                self.conflict.to_value(),
                self.choice.to_value(),
                self.resolved_blob.to_value(),
                Value::Uint(self.resolved_at_unix_ms),
            ],
        )
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let fields = expect_versioned(value, RESOLUTION_FORMAT_VERSION, 4)?;
        let resolution = ConflictResolution {
            conflict: ConflictId::from_value(&fields[0])?,
            choice: ResolutionChoice::from_value(&fields[1])?,
            resolved_blob: Option::<BlobId>::from_value(&fields[2])?,
            resolved_at_unix_ms: fields[3].as_uint()?,
        };
        // 只校验“形状”：Blob 是否真的存在必须由持有存储的一层判断。
        let shape_ok = resolution.choice.requires_blob() == resolution.resolved_blob.is_some();
        if !shape_ok {
            return Err(CborError::InvalidValue(
                "解决方式与结果 Blob 不匹配".to_owned(),
            ));
        }
        Ok(resolution)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builders_drop_blank_values_without_panicking() {
        let profile = DeviceProfile::new(Os::Linux, Arch::X86_64)
            .with_tag("   ")
            .with_capability("\t\n")
            .with_hostname(" ");
        assert!(profile.tags.is_empty());
        assert!(profile.capabilities.is_empty());
        assert!(profile.hostname.is_none());
    }

    #[test]
    fn builders_trim_values() {
        let profile = DeviceProfile::new(Os::MacOs, Arch::Aarch64)
            .with_tag("  work  ")
            .with_hostname(" studio ");
        assert!(profile.has_tag("work"));
        assert_eq!(profile.hostname.as_deref(), Some("studio"));
    }

    #[test]
    fn empty_all_is_true_and_empty_any_is_false() {
        let profile = DeviceProfile::new(Os::Linux, Arch::X86_64);
        assert!(Selector::All(vec![]).matches(&profile));
        assert!(!Selector::Any(vec![]).matches(&profile));
    }

    #[test]
    fn deep_selector_does_not_match_instead_of_overflowing() {
        // 手工构造超过深度上限的选择器：validate 拒绝，matches 保守返回 false。
        let mut selector = Selector::Is(Predicate::Os(Os::Linux));
        for _ in 0..MAX_SELECTOR_DEPTH {
            selector = Selector::negate(selector);
        }
        assert!(selector.validate().is_err());
        assert!(!selector.matches(&DeviceProfile::new(Os::Linux, Arch::X86_64)));
    }

    #[test]
    fn selector_cbor_rejects_unknown_version() {
        let selector = Selector::all([Predicate::Os(Os::Windows)]);
        let mut value = selector.to_value();
        if let Value::Array(items) = &mut value {
            items[0] = Value::Uint(7);
        }
        assert_eq!(
            Selector::from_canonical_slice(&crate::cbor::encode(&value)),
            Err(CborError::UnsupportedFormatVersion {
                found: 7,
                supported: SELECTOR_FORMAT_VERSION
            })
        );
    }
}
