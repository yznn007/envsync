//! 包的期望状态模型。
//!
//! 设计文档 §6 要求包适配器**只同步期望状态**，不复制安装目录：一条 intent 说的是
//! 「这台设备上应该存在（或不应该存在）哪个包、什么版本」，而不是「把这些字节抄过去」。
//! 本模块定义这套期望状态，以及由「期望 + 观察」推导动作的**纯函数**。
//!
//! ## 三条硬约束
//!
//! 1. **观察不出来 ≠ 应该删除。** [`PackageState`] 的四个变体没有任何一个能被推断成
//!    卸载意图；只有显式的 [`PackageDisposition::EnsureAbsent`] 能产生
//!    [`PackageActionKind::Uninstall`]。观察到「多出来的包」更是结构上不可能产生动作
//!    ——[`PackageIntentSet::derive_actions`] 只遍历 intent，从不遍历观察结果。
//! 2. **身份由管理器决定。** 同一个字符串在不同包管理器下是不同的包，甚至在同一个
//!    管理器下的不同 tap / bucket 里也是不同的包。规范化规则同样由管理器决定，
//!    见 [`NameRules`]。
//! 3. **无法判定时阻塞，不猜。** 版本策略无法与已安装版本比较时（例如已安装版本不是
//!    合法 semver）返回 [`PackageIntentError::UndecidableVersion`]，而不是静默安装另一个
//!    版本。
//!
//! ## 为什么 [`PackageAction`] 也在领域层
//!
//! 它与 [`crate::plan::Action`] 完全同层：一个不可变的、可编码、可排序的「打算做什么」
//! 描述，不含任何执行手段。适配器负责把它变成命令，核心层负责让它过策略与确认，两者
//! 都需要看见同一个类型；把它放进适配器 crate 会让核心层反向依赖适配器。
//!
//! ## 示例
//!
//! ```
//! use envsync_domain::package::{
//!     PackageDisposition, PackageIdentity, PackageIntent, PackageIntentSet, VersionPolicy,
//! };
//!
//! // 大小写规则由管理器决定：Homebrew 不区分大小写。
//! let a: PackageIdentity = "brew:Ripgrep".parse()?;
//! let b: PackageIdentity = "brew:ripgrep".parse()?;
//! assert_eq!(a, b);
//!
//! // 不同 tap 的同名包是**不同**的包。
//! let tapped: PackageIdentity = "brew:homebrew/core/ripgrep".parse()?;
//! assert_ne!(a, tapped);
//!
//! // 默认处置是 Managed + Present。
//! let intent = PackageIntent::new(a);
//! assert_eq!(intent.disposition, PackageDisposition::Managed);
//! assert_eq!(intent.version, VersionPolicy::Present);
//!
//! // 乱序输入得到同一个摘要。
//! let one = PackageIntentSet::from_intents([intent.clone(), PackageIntent::new(tapped.clone())])?;
//! let two = PackageIntentSet::from_intents([PackageIntent::new(tapped), intent])?;
//! assert_eq!(one.state_digest(), two.state_digest());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use semver::{Op, Version, VersionReq};

use crate::cbor::{self, CborCodec, CborError, Value};
use crate::id::{Digest32, ResourceId};
use crate::plan::{Risk, RollbackCapability};
use crate::{cbor_struct, cbor_unit_enum};

/// [`PackageIntentSet`] 的当前格式版本。
pub const PACKAGE_INTENT_SET_FORMAT_VERSION: u32 = 1;

/// [`PackageObservationSet`] 的当前格式版本。
pub const PACKAGE_OBSERVATION_SET_FORMAT_VERSION: u32 = 1;

/// [`PackageIntentSet::state_digest`] 使用的哈希域分隔标签。
pub const PACKAGE_INTENT_SET_DOMAIN: &str = "envsync:package-intent-set:v1";

/// 一个 intent 集合允许包含的最大条目数。
///
/// 期望集合来自会被同步的配置，因此必须**有界**：推导动作是线性扫描，条目数直接决定
/// 每次计划的代价。
pub const MAX_PACKAGE_INTENTS: usize = 10_000;

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

/// 包期望状态相关的错误。
///
/// 所有变体的 `Display` 只描述**结构问题**与包身份，不含本机路径，也不含命令输出，
/// 可以直接写进日志与 CLI 诊断。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PackageIntentError {
    /// 包管理器标识为空。
    #[error("包管理器标识不能为空")]
    EmptyManager,
    /// 包管理器标识包含非法字符。
    #[error("包管理器标识包含非法字符 `{0}`")]
    ManagerCharset(char),
    /// 包管理器标识超长。
    #[error("包管理器标识 {0} 字节超过上限 {max} 字节", max = PackageManagerId::MAX_LEN)]
    ManagerTooLong(usize),
    /// 包名为空。
    #[error("包名不能为空")]
    EmptyName,
    /// 包名包含非法字符。
    #[error("包名包含非法字符 `{0}`")]
    NameCharset(char),
    /// 包名超长。
    #[error("包名 {0} 字节超过上限 {max} 字节", max = PackageIdentity::MAX_NAME_LEN)]
    NameTooLong(usize),
    /// 该管理器要求包名全小写。
    #[error("包管理器 `{manager}` 要求包名全小写，`{name}` 含大写字母")]
    NameMustBeLowercase {
        /// 包管理器标识。
        manager: String,
        /// 触发错误的原始包名。
        name: String,
    },
    /// 该管理器的包名不允许带 `/`。
    #[error("包管理器 `{manager}` 的包名不允许包含 `/`；tap / bucket 请写在 source 里")]
    NameSlashNotAllowed {
        /// 包管理器标识。
        manager: String,
    },
    /// 带 scope 的包名形态非法。
    #[error("带 scope 的包名必须形如 `@scope/name`，`{0}` 不符合")]
    InvalidScope(String),
    /// 来源为空。
    #[error("包来源（tap / bucket / registry）不能为空字符串；不需要来源时请用 None")]
    EmptySource,
    /// 来源包含非法字符。
    #[error("包来源包含非法字符 `{0}`")]
    SourceCharset(char),
    /// 来源超长。
    #[error("包来源 {0} 字节超过上限 {max} 字节", max = PackageIdentity::MAX_SOURCE_LEN)]
    SourceTooLong(usize),
    /// 来源的形态会让 `manager:source/name` 无法被唯一还原。
    #[error("包来源 `{0}` 不得以 `@` 开头，也不得包含 `/@`：那会让文本形式产生歧义")]
    AmbiguousSource(String),
    /// 文本形式缺少 `manager:` 前缀。
    #[error("包身份文本必须形如 `manager:name` 或 `manager:source/name`")]
    MissingManagerSeparator,
    /// 版本字符串为空。
    #[error("版本不能为空字符串")]
    EmptyVersion,
    /// 版本字符串包含非法字符。
    #[error("版本包含非法字符 `{0}`")]
    VersionCharset(char),
    /// semver 版本区间非法。
    #[error("版本区间非法：{0}")]
    InvalidVersionReq(String),
    /// 版本策略文本形式非法。
    #[error("版本策略文本 `{0}` 非法")]
    InvalidVersionPolicy(String),
    /// 同一个包身份上出现了互相冲突的期望状态。
    #[error("包 `{identity}` 上存在互相冲突的期望状态：已有 {existing}，又要求 {incoming}")]
    ConflictingIntent {
        /// 冲突的包身份（文本形式）。
        identity: String,
        /// 集合里已有的期望状态摘要。
        existing: String,
        /// 新加入的期望状态摘要。
        incoming: String,
    },
    /// tombstone 或 unmanaged 携带了版本策略。
    #[error("包 `{identity}` 的处置为 {disposition}，不能同时声明版本策略 {version}")]
    DispositionWithVersion {
        /// 出问题的包身份（文本形式）。
        identity: String,
        /// 处置。
        disposition: &'static str,
        /// 被声明的版本策略。
        version: String,
    },
    /// 观察结果与集合声明的包管理器不符。
    #[error("观察结果属于包管理器 `{found}`，与集合声明的 `{expected}` 不符")]
    ManagerMismatch {
        /// 集合声明的包管理器。
        expected: PackageManagerId,
        /// 观察结果里的包管理器。
        found: PackageManagerId,
    },
    /// 无法判定已安装版本与版本策略的关系。
    #[error("包 `{identity}` 已安装版本 `{installed}` 无法与版本策略 {policy} 比较；拒绝猜测")]
    UndecidableVersion {
        /// 出问题的包身份（文本形式）。
        identity: String,
        /// 已安装版本。
        installed: String,
        /// 版本策略。
        policy: String,
    },
    /// 条目数超过 [`MAX_PACKAGE_INTENTS`]。
    #[error("包期望条目数 {actual} 超过上限 {limit}")]
    TooManyIntents {
        /// 实际条目数。
        actual: usize,
        /// 允许的上限。
        limit: usize,
    },
    /// 身份未经规范化就被送进集合。
    #[error("包身份 `{0}` 未经规范化；请用 PackageIdentity::new 或 FromStr 构造")]
    NotNormalized(String),
}

impl PackageIntentError {
    /// 稳定的机器可读错误码，供 `--json` 输出与测试断言使用。
    pub fn code(&self) -> &'static str {
        match self {
            PackageIntentError::EmptyManager
            | PackageIntentError::ManagerCharset(_)
            | PackageIntentError::ManagerTooLong(_) => "package.invalid_manager",
            PackageIntentError::EmptyName
            | PackageIntentError::NameCharset(_)
            | PackageIntentError::NameTooLong(_)
            | PackageIntentError::NameMustBeLowercase { .. }
            | PackageIntentError::NameSlashNotAllowed { .. }
            | PackageIntentError::InvalidScope(_) => "package.invalid_name",
            PackageIntentError::EmptySource
            | PackageIntentError::SourceCharset(_)
            | PackageIntentError::SourceTooLong(_)
            | PackageIntentError::AmbiguousSource(_) => "package.invalid_source",
            PackageIntentError::MissingManagerSeparator => "package.invalid_identity_text",
            PackageIntentError::EmptyVersion
            | PackageIntentError::VersionCharset(_)
            | PackageIntentError::InvalidVersionReq(_)
            | PackageIntentError::InvalidVersionPolicy(_) => "package.invalid_version",
            PackageIntentError::ConflictingIntent { .. } => "package.conflicting_intent",
            PackageIntentError::DispositionWithVersion { .. } => "package.disposition_with_version",
            PackageIntentError::ManagerMismatch { .. } => "package.manager_mismatch",
            PackageIntentError::UndecidableVersion { .. } => "package.undecidable_version",
            PackageIntentError::TooManyIntents { .. } => "package.too_many_intents",
            PackageIntentError::NotNormalized(_) => "package.not_normalized",
        }
    }
}

// ---------------------------------------------------------------------------
// 包管理器标识与规范化规则
// ---------------------------------------------------------------------------

/// 包名的大小写规则。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NameCase {
    /// 大小写不敏感：折叠为小写。Homebrew、Scoop、Winget、Chocolatey、crates.io、PyPI。
    Fold,
    /// 大小写敏感：原样保留。APT、DNF、Pacman。
    Preserve,
    /// 保留大小写，但**拒绝**任何 ASCII 大写字母。
    ///
    /// npm 的规则不是「不区分大小写」而是「新包名必须全小写」：历史上确实存在含大写的
    /// 包名，但它们与小写名互不等价。折叠会把两个不同的包合成一个（危险方向），
    /// 原样保留又会让 `Foo` 与 `foo` 各自安装（也不对），所以唯一诚实的做法是拒绝。
    RejectUppercase,
}

/// 包名中分隔符的等价规则。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SeparatorRule {
    /// 原样保留。
    Keep,
    /// crates.io 规则：`-` 与 `_` 等价，统一成 `-`。
    HyphenUnderscore,
    /// PEP 503 规则：连续的 `-`、`_`、`.` 折叠成单个 `-`。
    Pep503,
}

/// 某个包管理器的包名规范化规则。
///
/// 规范化规则**属于包管理器**，不是全局约定：`brew:Ripgrep` 与 `brew:ripgrep` 是同一个
/// 包，而 `apt:Foo` 与 `apt:foo` 不是。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NameRules {
    /// 大小写规则。
    pub case: NameCase,
    /// 分隔符等价规则。
    pub separators: SeparatorRule,
    /// 包名是否可以带 `@scope/` 前缀（npm 系）。
    pub allow_scope: bool,
}

impl NameRules {
    /// 未知包管理器的保守默认规则：不折叠大小写、不改写分隔符、不允许 scope。
    ///
    /// 折叠是**危险方向**（会把两个不同的包合并成一个），因此未知管理器一律不折叠。
    /// 代价是两条本应等价的 intent 可能被当成两个包，那只会多做一次幂等安装。
    pub const CONSERVATIVE: NameRules = NameRules {
        case: NameCase::Preserve,
        separators: SeparatorRule::Keep,
        allow_scope: false,
    };
}

/// 包管理器标识（稳定字符串 newtype），例如 `brew`、`scoop`、`cargo`、`npm`、`apt`。
///
/// 它是 EnvSync 自己的词汇表而不是用户数据，因此**统一折叠为小写**：不存在两个只差
/// 大小写的包管理器。
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageManagerId(String);

impl PackageManagerId {
    /// 允许的最大长度（字节）。
    pub const MAX_LEN: usize = 32;

    /// 解析并规范化包管理器标识。
    pub fn parse(text: &str) -> Result<Self, PackageIntentError> {
        if text.is_empty() {
            return Err(PackageIntentError::EmptyManager);
        }
        if text.len() > Self::MAX_LEN {
            return Err(PackageIntentError::ManagerTooLong(text.len()));
        }
        for ch in text.chars() {
            if !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')) {
                return Err(PackageIntentError::ManagerCharset(ch));
            }
        }
        Ok(PackageManagerId(text.to_ascii_lowercase()))
    }

    /// 文本表示。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 该包管理器的包名规范化规则。
    ///
    /// 未登记的管理器落到 [`NameRules::CONSERVATIVE`]。
    pub fn rules(&self) -> NameRules {
        match self.0.as_str() {
            // 不区分大小写的管理器。
            "brew" | "homebrew" | "scoop" | "winget" | "choco" | "chocolatey" => NameRules {
                case: NameCase::Fold,
                separators: SeparatorRule::Keep,
                allow_scope: false,
            },
            // crates.io：小写，且 `-` 与 `_` 等价。
            "cargo" => NameRules {
                case: NameCase::Fold,
                separators: SeparatorRule::HyphenUnderscore,
                allow_scope: false,
            },
            // PyPI（PEP 503）：小写，`-_.` 连续段折叠成单个 `-`。
            "pipx" | "uv" | "pip" => NameRules {
                case: NameCase::Fold,
                separators: SeparatorRule::Pep503,
                allow_scope: false,
            },
            // npm 系：全小写要求 + `@scope/name`。
            "npm" | "pnpm" | "yarn" => NameRules {
                case: NameCase::RejectUppercase,
                separators: SeparatorRule::Keep,
                allow_scope: true,
            },
            // 系统包管理器：大小写敏感。
            "apt" | "dnf" | "yum" | "pacman" | "apk" | "zypper" => NameRules {
                case: NameCase::Preserve,
                separators: SeparatorRule::Keep,
                allow_scope: false,
            },
            _ => NameRules::CONSERVATIVE,
        }
    }
}

impl fmt::Display for PackageManagerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for PackageManagerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PackageManagerId({})", self.0)
    }
}

impl FromStr for PackageManagerId {
    type Err = PackageIntentError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        PackageManagerId::parse(text)
    }
}

impl CborCodec for PackageManagerId {
    fn to_value(&self) -> Value {
        Value::Text(self.0.clone())
    }
    fn from_value(value: &Value) -> Result<Self, CborError> {
        PackageManagerId::parse(value.as_text()?)
            .map_err(|err| CborError::InvalidValue(err.to_string()))
    }
}

// ---------------------------------------------------------------------------
// 包身份
// ---------------------------------------------------------------------------

/// 包身份：管理器 + 规范化名称 + 来源/频道。
///
/// # 文本形式
///
/// `manager:name` 或 `manager:source/name`。文本形式与结构可以**无损互转**：
///
/// * 不允许 scope 的管理器，包名里不能有 `/`，因此最后一个 `/` 之前的部分必然是来源
///   （Homebrew 的 tap 形如 `homebrew/core`，本身带 `/`，这也是为什么按**最后一个**
///   `/` 切分）；
/// * 允许 scope 的管理器（npm 系），包名可能是 `@scope/name`，因此从 `/@` 处切分；
///   来源不得以 `@` 开头也不得含 `/@`（[`PackageIntentError::AmbiguousSource`]）。
///
/// # 字段是公开的，但边界会校验
///
/// 直接构造结构体会**跳过**规范化。所有把身份纳入持久化或摘要的入口
/// （[`PackageIntentSet::insert`]、[`PackageObservationSet::insert`]、CBOR 解码）都会调用
/// [`PackageIdentity::validate`]，未规范化的身份在那里被拒绝。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageIdentity {
    /// 包管理器。
    pub manager: PackageManagerId,
    /// 已按该管理器规则规范化的包名。
    pub name: String,
    /// 来源 / 频道：tap、bucket、registry、repo。参与身份。
    pub source: Option<String>,
}

impl PackageIdentity {
    /// 包名允许的最大长度（字节）。
    pub const MAX_NAME_LEN: usize = 256;
    /// 来源允许的最大长度（字节）。
    pub const MAX_SOURCE_LEN: usize = 256;

    /// 构造并规范化包身份。
    ///
    /// 这是唯一保证结果已规范化的构造方式（[`FromStr`] 内部也走这里）。
    pub fn new(
        manager: PackageManagerId,
        name: &str,
        source: Option<&str>,
    ) -> Result<Self, PackageIntentError> {
        let normalized_name = normalize_name(&manager, name)?;
        let normalized_source = match source {
            None => None,
            Some(raw) => Some(normalize_source(raw)?),
        };
        Ok(PackageIdentity {
            manager,
            name: normalized_name,
            source: normalized_source,
        })
    }

    /// 解析文本形式，等价于 [`FromStr`]。
    pub fn parse(text: &str) -> Result<Self, PackageIntentError> {
        let (manager_text, rest) = text
            .split_once(':')
            .ok_or(PackageIntentError::MissingManagerSeparator)?;
        let manager = PackageManagerId::parse(manager_text)?;
        let (source, name) = split_source_and_name(&manager, rest);
        PackageIdentity::new(manager, name, source)
    }

    /// 校验身份是否已经规范化。
    ///
    /// 直接构造结构体可以绕过 [`PackageIdentity::new`]，因此每个把身份纳入摘要的边界
    /// 都要再查一次：一个未规范化的身份会让「同一个包」出现两条不同的 intent，
    /// 进而让 State Root 不再确定。
    pub fn validate(&self) -> Result<(), PackageIntentError> {
        let expected =
            PackageIdentity::new(self.manager.clone(), &self.name, self.source.as_deref())?;
        if &expected != self {
            return Err(PackageIntentError::NotNormalized(self.to_string()));
        }
        Ok(())
    }

    /// 尝试映射成 [`ResourceId`]，供策略规则做资源级匹配。
    ///
    /// **只在映射无损时返回 `Some`**：任何需要替换字符的情形（npm scope 的 `@`、
    /// git 来源里的 `:` 与 `//`）一律返回 `None`。有损映射会让两个不同的包落到同一个
    /// [`ResourceId`] 上，从而让一条 `allow` 规则意外覆盖到另一个包——那是安全事故，
    /// 而「策略匹配不到」只是功能缺失。
    pub fn to_resource_id(&self) -> Option<ResourceId> {
        let mut text = String::with_capacity(32);
        text.push_str("packages/");
        text.push_str(self.manager.as_str());
        if let Some(source) = &self.source {
            text.push('/');
            text.push_str(source);
        }
        text.push('/');
        text.push_str(&self.name);
        ResourceId::parse(&text).ok()
    }
}

/// 按管理器规则把 `source/name` 形态的文本切成来源与包名。
fn split_source_and_name<'a>(
    manager: &PackageManagerId,
    rest: &'a str,
) -> (Option<&'a str>, &'a str) {
    if manager.rules().allow_scope {
        // npm 系：包名可能是 `@scope/name`。以 `/@` 作为来源与包名的边界。
        if rest.starts_with('@') {
            return (None, rest);
        }
        if let Some(index) = rest.find("/@") {
            return (Some(&rest[..index]), &rest[index + 1..]);
        }
    }
    match rest.rsplit_once('/') {
        Some((source, name)) => (Some(source), name),
        None => (None, rest),
    }
}

/// 按管理器规则规范化包名。
fn normalize_name(manager: &PackageManagerId, raw: &str) -> Result<String, PackageIntentError> {
    if raw.is_empty() {
        return Err(PackageIntentError::EmptyName);
    }
    if raw.len() > PackageIdentity::MAX_NAME_LEN {
        return Err(PackageIntentError::NameTooLong(raw.len()));
    }
    for ch in raw.chars() {
        if !is_name_char(ch) {
            return Err(PackageIntentError::NameCharset(ch));
        }
    }

    let rules = manager.rules();
    if raw.contains('/') {
        if !rules.allow_scope {
            return Err(PackageIntentError::NameSlashNotAllowed {
                manager: manager.as_str().to_owned(),
            });
        }
        // 允许 scope 时，包名只能是 `@scope/name` 这一种形态。
        let Some((scope, bare)) = raw.split_once('/') else {
            return Err(PackageIntentError::InvalidScope(raw.to_owned()));
        };
        if !scope.starts_with('@') || scope.len() < 2 || bare.is_empty() || bare.contains('/') {
            return Err(PackageIntentError::InvalidScope(raw.to_owned()));
        }
    } else if raw.contains('@') {
        // `@` 只有作为 scope 前缀才有意义；`foo@1.2` 这种把版本写进名字的形态必须拒绝，
        // 否则版本策略就形同虚设。
        return Err(PackageIntentError::InvalidScope(raw.to_owned()));
    }

    let cased = match rules.case {
        NameCase::Fold => raw.to_ascii_lowercase(),
        NameCase::Preserve => raw.to_owned(),
        NameCase::RejectUppercase => {
            if raw.chars().any(|ch| ch.is_ascii_uppercase()) {
                return Err(PackageIntentError::NameMustBeLowercase {
                    manager: manager.as_str().to_owned(),
                    name: raw.to_owned(),
                });
            }
            raw.to_owned()
        }
    };

    Ok(apply_separator_rule(rules.separators, &cased))
}

/// 名称与来源允许的字符集。
///
/// 刻意不含 `:`（那是 `manager:` 分隔符）、空白与控制字符。
fn is_name_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '+' | '@' | '/')
}

/// 应用分隔符等价规则。
fn apply_separator_rule(rule: SeparatorRule, name: &str) -> String {
    match rule {
        SeparatorRule::Keep => name.to_owned(),
        SeparatorRule::HyphenUnderscore => name.replace('_', "-"),
        SeparatorRule::Pep503 => {
            let mut out = String::with_capacity(name.len());
            let mut in_run = false;
            for ch in name.chars() {
                if matches!(ch, '-' | '_' | '.') {
                    if !in_run {
                        out.push('-');
                        in_run = true;
                    }
                } else {
                    out.push(ch);
                    in_run = false;
                }
            }
            out
        }
    }
}

/// 规范化来源。
///
/// 来源是 tap / bucket / registry URL，跨管理器没有统一的大小写规则，因此**原样保留**，
/// 只做字符集与歧义检查。
fn normalize_source(raw: &str) -> Result<String, PackageIntentError> {
    if raw.is_empty() {
        return Err(PackageIntentError::EmptySource);
    }
    if raw.len() > PackageIdentity::MAX_SOURCE_LEN {
        return Err(PackageIntentError::SourceTooLong(raw.len()));
    }
    for ch in raw.chars() {
        if !is_name_char(ch) {
            return Err(PackageIntentError::SourceCharset(ch));
        }
    }
    if raw.starts_with('@') || raw.contains("/@") {
        return Err(PackageIntentError::AmbiguousSource(raw.to_owned()));
    }
    if raw.ends_with('/') || raw.starts_with('/') || raw.contains("//") {
        return Err(PackageIntentError::AmbiguousSource(raw.to_owned()));
    }
    Ok(raw.to_owned())
}

impl fmt::Display for PackageIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            Some(source) => write!(f, "{}:{}/{}", self.manager, source, self.name),
            None => write!(f, "{}:{}", self.manager, self.name),
        }
    }
}

impl FromStr for PackageIdentity {
    type Err = PackageIntentError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        PackageIdentity::parse(text)
    }
}

cbor_struct!(PackageIdentity {
    manager: PackageManagerId,
    name: String,
    source: Option<String>,
});

// ---------------------------------------------------------------------------
// 版本策略
// ---------------------------------------------------------------------------

/// 版本策略。
///
/// 设计文档 §6：每个包状态记录 `exact`、`compatible`、`latest` 或 `present` 之一。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum VersionPolicy {
    /// 只要装上了就行，不关心版本。**默认值**。
    #[default]
    Present,
    /// 钉死到某个版本字符串（逐字符比较，兼容非 semver 的包管理器）。
    Exact(String),
    /// 满足某个 semver 区间即可。
    Compatible(VersionReq),
    /// 始终收敛到管理器提供的最新版本。
    ///
    /// 纯函数层**无法**判定「已安装版本是不是最新」——那需要向包管理器查询。因此
    /// [`PackageIntentSet::derive_actions`] 在包已安装时不会为 `Latest` 产生任何动作，
    /// 由适配器结合观察到的可用版本补足。
    Latest,
}

impl VersionPolicy {
    /// 构造 [`VersionPolicy::Exact`]，校验版本字符串。
    pub fn exact(version: &str) -> Result<Self, PackageIntentError> {
        Ok(VersionPolicy::Exact(validate_version_text(version)?))
    }

    /// 由 semver 区间文本构造 [`VersionPolicy::Compatible`]。
    ///
    /// 提供这个构造器是为了让上层 crate 不必直接依赖 `semver`。
    pub fn compatible(requirement: &str) -> Result<Self, PackageIntentError> {
        let req = VersionReq::parse(requirement)
            .map_err(|err| PackageIntentError::InvalidVersionReq(err.to_string()))?;
        Ok(VersionPolicy::Compatible(req))
    }

    /// 稳定的判别式短名。
    pub const fn kind(&self) -> &'static str {
        match self {
            VersionPolicy::Present => "present",
            VersionPolicy::Exact(_) => "exact",
            VersionPolicy::Compatible(_) => "compatible",
            VersionPolicy::Latest => "latest",
        }
    }

    /// 排序权重，用于确定性排序。
    const fn order_rank(&self) -> u8 {
        match self {
            VersionPolicy::Present => 0,
            VersionPolicy::Exact(_) => 1,
            VersionPolicy::Compatible(_) => 2,
            VersionPolicy::Latest => 3,
        }
    }

    /// 某个候选版本是否满足本策略。
    ///
    /// 与 [`VersionPolicy::verdict`] 的区别是提问方向：`verdict` 问「已经装着的这个
    /// 版本要不要动」，`selects` 问「源里这个候选版本能不能用」。
    ///
    /// [`VersionPolicy::Latest`] 对任何候选都返回 `true`——「最新」是**相对**源里可用
    /// 版本集合的概念，由 [`VersionPolicy::best_match`] 挑选。
    pub fn selects(&self, candidate: &str) -> bool {
        match self {
            VersionPolicy::Present | VersionPolicy::Latest => true,
            VersionPolicy::Exact(want) => {
                if want == candidate {
                    return true;
                }
                match (Version::parse(candidate), Version::parse(want)) {
                    (Ok(have), Ok(want)) => {
                        compare_precedence(&have, &want) == std::cmp::Ordering::Equal
                    }
                    _ => false,
                }
            }
            VersionPolicy::Compatible(req) => Version::parse(candidate)
                .map(|version| req.matches(&version))
                .unwrap_or(false),
        }
    }

    /// 从候选版本集合里挑出满足本策略的**最高**版本。
    ///
    /// 排序键是 `(可解析的 semver, 原始文本)`：能解析成 semver 的候选按语义优先级比较，
    /// 不能解析的排在前面并按文本比较。这保证结果与候选顺序无关（确定性），同时不会让
    /// 一个无法解析的版本压过合法的 semver。
    pub fn best_match<'a, I>(&self, candidates: I) -> Option<&'a str>
    where
        I: IntoIterator<Item = &'a str>,
    {
        candidates
            .into_iter()
            .filter(|candidate| self.selects(candidate))
            .max_by(|left, right| {
                let left_version = Version::parse(left).ok();
                let right_version = Version::parse(right).ok();
                match (&left_version, &right_version) {
                    (Some(left_version), Some(right_version)) => {
                        compare_precedence(left_version, right_version)
                            .then_with(|| left.cmp(right))
                    }
                    (Some(_), None) => std::cmp::Ordering::Greater,
                    (None, Some(_)) => std::cmp::Ordering::Less,
                    (None, None) => left.cmp(right),
                }
            })
    }

    /// 判定已安装版本与本策略的关系。
    ///
    /// 见 [`VersionVerdict`]；无法判定时返回 [`VersionVerdict::Undecidable`]，
    /// 调用方必须阻塞而不是猜一个方向。
    pub fn verdict(&self, installed: &str) -> VersionVerdict {
        match self {
            VersionPolicy::Present => VersionVerdict::Satisfied,
            VersionPolicy::Latest => VersionVerdict::Undecidable,
            VersionPolicy::Exact(want) => {
                if want == installed {
                    return VersionVerdict::Satisfied;
                }
                match (Version::parse(installed), Version::parse(want)) {
                    (Ok(have), Ok(want)) => match compare_precedence(&have, &want) {
                        std::cmp::Ordering::Equal => VersionVerdict::Satisfied,
                        std::cmp::Ordering::Less => VersionVerdict::NeedsUpgrade,
                        std::cmp::Ordering::Greater => VersionVerdict::NeedsDowngrade,
                    },
                    // 至少一边不是 semver：确定要变，但方向不明。
                    _ => VersionVerdict::NeedsChange,
                }
            }
            VersionPolicy::Compatible(req) => match Version::parse(installed) {
                Err(_) => VersionVerdict::Undecidable,
                Ok(have) if req.matches(&have) => VersionVerdict::Satisfied,
                Ok(have) => {
                    if requires_newer_than(req, &have) {
                        VersionVerdict::NeedsUpgrade
                    } else {
                        VersionVerdict::NeedsDowngrade
                    }
                }
            },
        }
    }
}

/// 按 semver **优先级**比较两个版本：忽略 build metadata。
///
/// `semver::Version` 的 `Ord`/`PartialEq` 都是 derive 出来的，会把 build metadata 一并
/// 比较（`1.2.3+build` 被判为大于 `1.2.3`）。但 semver 规范明确规定 build metadata
/// 不参与优先级判定，只差 build metadata 的两个版本不构成「版本漂移」——否则每次
/// 包管理器换一个构建号都会被计划成一次降级。
fn compare_precedence(have: &Version, want: &Version) -> std::cmp::Ordering {
    (have.major, have.minor, have.patch)
        .cmp(&(want.major, want.minor, want.patch))
        .then_with(|| have.pre.cmp(&want.pre))
}

/// 区间里是否存在一个**高于**已安装版本的下界。
///
/// 这是「该升还是该降」的判据：`^1.2` 对 `1.0.0` 要求更新（下界 `1.2.0` 更高），
/// 对 `3.0.0` 则只能降级（没有任何下界高于它）。
fn requires_newer_than(req: &VersionReq, installed: &Version) -> bool {
    req.comparators.iter().any(|comparator| {
        let lower_bound = matches!(
            comparator.op,
            Op::Exact | Op::Greater | Op::GreaterEq | Op::Tilde | Op::Caret | Op::Wildcard
        );
        if !lower_bound {
            return false;
        }
        let minimum = Version {
            major: comparator.major,
            minor: comparator.minor.unwrap_or(0),
            patch: comparator.patch.unwrap_or(0),
            pre: comparator.pre.clone(),
            build: semver::BuildMetadata::EMPTY,
        };
        compare_precedence(&minimum, installed) == std::cmp::Ordering::Greater
    })
}

/// 校验版本字符串的字符集。
fn validate_version_text(version: &str) -> Result<String, PackageIntentError> {
    if version.is_empty() {
        return Err(PackageIntentError::EmptyVersion);
    }
    if version.len() > PackageIdentity::MAX_NAME_LEN {
        return Err(PackageIntentError::NameTooLong(version.len()));
    }
    for ch in version.chars() {
        // 版本串可能来自包管理器输出（例如 Debian 的 `1:2.3-4ubuntu1`），因此比包名
        // 多允许 `:` 与 `~`，但仍然拒绝空白、控制字符和引号。
        let allowed =
            ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '+' | ':' | '~' | '!');
        if !allowed {
            return Err(PackageIntentError::VersionCharset(ch));
        }
    }
    Ok(version.to_owned())
}

impl fmt::Display for VersionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionPolicy::Present => f.write_str("present"),
            VersionPolicy::Latest => f.write_str("latest"),
            VersionPolicy::Exact(version) => write!(f, "exact:{version}"),
            VersionPolicy::Compatible(req) => write!(f, "{req}"),
        }
    }
}

impl FromStr for VersionPolicy {
    type Err = PackageIntentError;

    /// 文本形式：`present`、`latest`、`exact:1.2.3`，其余按 semver 区间解析。
    ///
    /// `Exact` 刻意使用 `exact:` 前缀而不是 `=1.2.3`：后者同时是合法的 semver 比较器，
    /// 会让两种语义（逐字符串比较 vs semver 相等）在文本上无法区分。
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "present" => Ok(VersionPolicy::Present),
            "latest" => Ok(VersionPolicy::Latest),
            _ => match text.strip_prefix("exact:") {
                Some(version) => VersionPolicy::exact(version),
                None => VersionPolicy::compatible(text)
                    .map_err(|_| PackageIntentError::InvalidVersionPolicy(text.to_owned())),
            },
        }
    }
}

impl PartialOrd for VersionPolicy {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VersionPolicy {
    /// 先按变体权重，再按文本形式。`VersionReq` 没有自然序，用它的 canonical 文本代替
    /// 即可获得确定性。
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.order_rank()
            .cmp(&other.order_rank())
            .then_with(|| self.to_string().cmp(&other.to_string()))
    }
}

impl CborCodec for VersionPolicy {
    fn to_value(&self) -> Value {
        match self {
            VersionPolicy::Present => Value::Array(vec![Value::Text("present".into())]),
            VersionPolicy::Latest => Value::Array(vec![Value::Text("latest".into())]),
            VersionPolicy::Exact(version) => Value::Array(vec![
                Value::Text("exact".into()),
                Value::Text(version.clone()),
            ]),
            VersionPolicy::Compatible(req) => Value::Array(vec![
                Value::Text("compatible".into()),
                Value::Text(req.to_string()),
            ]),
        }
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        let tag = items.first().ok_or(CborError::ArityMismatch)?.as_text()?;
        match (tag, items.len()) {
            ("present", 1) => Ok(VersionPolicy::Present),
            ("latest", 1) => Ok(VersionPolicy::Latest),
            ("exact", 2) => VersionPolicy::exact(items[1].as_text()?)
                .map_err(|err| CborError::InvalidValue(err.to_string())),
            ("compatible", 2) => VersionPolicy::compatible(items[1].as_text()?)
                .map_err(|err| CborError::InvalidValue(err.to_string())),
            ("present" | "latest" | "exact" | "compatible", _) => Err(CborError::ArityMismatch),
            (other, _) => Err(CborError::UnknownVariant(other.to_owned())),
        }
    }
}

/// 版本策略与已安装版本的比较结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VersionVerdict {
    /// 已满足，无需动作。
    Satisfied,
    /// 需要升级到更高版本。
    NeedsUpgrade,
    /// 需要降级到更低版本。
    NeedsDowngrade,
    /// 确定需要改变版本，但方向无法判定（例如目标不是合法 semver）。
    NeedsChange,
    /// 完全无法判定：需要包管理器提供的额外信息（最新版本、非 semver 的版本序）。
    Undecidable,
}

impl VersionVerdict {
    /// 是否已经满足。
    pub const fn is_satisfied(self) -> bool {
        matches!(self, VersionVerdict::Satisfied)
    }
}

// ---------------------------------------------------------------------------
// 处置与 intent
// ---------------------------------------------------------------------------

/// 包的期望处置。
///
/// 与 [`crate::resource::DesiredDisposition`] 同构：只有显式的
/// [`PackageDisposition::EnsureAbsent`] 能产生卸载。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum PackageDisposition {
    /// 收敛到期望版本。**默认值**。
    #[default]
    Managed,
    /// 显式卸载（tombstone）。
    EnsureAbsent,
    /// 不归 EnvSync 管理，仅记录存在性。
    Unmanaged,
}

cbor_unit_enum!(PackageDisposition {
    PackageDisposition::Managed => "managed",
    PackageDisposition::EnsureAbsent => "ensure_absent",
    PackageDisposition::Unmanaged => "unmanaged",
});

impl PackageDisposition {
    /// 稳定短名。
    pub const fn as_str(self) -> &'static str {
        match self {
            PackageDisposition::Managed => "managed",
            PackageDisposition::EnsureAbsent => "ensure_absent",
            PackageDisposition::Unmanaged => "unmanaged",
        }
    }

    /// 该处置是否**允许**产生卸载动作。
    ///
    /// 这是设计文档 §6「卸载必须由显式 tombstone 和策略允许共同触发」的第一半：
    /// 三个变体里只有一个返回 `true`。
    pub const fn permits_removal(self) -> bool {
        matches!(self, PackageDisposition::EnsureAbsent)
    }
}

/// 单个包的期望状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageIntent {
    /// 包身份。
    pub identity: PackageIdentity,
    /// 期望处置。
    pub disposition: PackageDisposition,
    /// 版本策略。
    pub version: VersionPolicy,
    /// 可选包：本机装不上（平台不支持、源里没有）时降级为警告而不是阻塞。
    pub optional: bool,
}

cbor_struct!(PackageIntent {
    identity: PackageIdentity,
    disposition: PackageDisposition,
    version: VersionPolicy,
    optional: bool,
});

impl PackageIntent {
    /// 用**安全默认值**构造：`Managed` + `Present` + 非可选。
    pub fn new(identity: PackageIdentity) -> Self {
        PackageIntent {
            identity,
            disposition: PackageDisposition::default(),
            version: VersionPolicy::default(),
            optional: false,
        }
    }

    /// 设置版本策略。
    #[must_use]
    pub fn with_version(mut self, version: VersionPolicy) -> Self {
        self.version = version;
        self
    }

    /// 设置处置。
    #[must_use]
    pub fn with_disposition(mut self, disposition: PackageDisposition) -> Self {
        self.disposition = disposition;
        self
    }

    /// 标记为可选。
    #[must_use]
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    /// 校验 intent 自身的一致性。
    ///
    /// 「卸载这个包」和「把这个包钉到 1.2.3」不可能同时成立；不管理的包也不该带版本
    /// 策略。这类自相矛盾必须在进入集合之前被拒绝，而不是留到计划阶段再猜。
    pub fn validate(&self) -> Result<(), PackageIntentError> {
        self.identity.validate()?;
        if self.disposition != PackageDisposition::Managed && self.version != VersionPolicy::Present
        {
            return Err(PackageIntentError::DispositionWithVersion {
                identity: self.identity.to_string(),
                disposition: self.disposition.as_str(),
                version: self.version.to_string(),
            });
        }
        Ok(())
    }

    /// 供冲突诊断使用的简短摘要。
    fn summary(&self) -> String {
        format!(
            "{}/{}{}",
            self.disposition.as_str(),
            self.version,
            if self.optional { "/optional" } else { "" }
        )
    }
}

// ---------------------------------------------------------------------------
// 观察
// ---------------------------------------------------------------------------

/// 观察到的「已安装」状态所携带的信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledPackage {
    /// 已安装版本；管理器不报告版本时为 `None`。
    pub version: Option<String>,
    /// 是否为用户**显式**安装。
    ///
    /// 依赖自动引入的包（`explicit == false`）不会被 EnvSync 采集成 intent：
    /// 设计文档 §6 要求「忽略依赖自动安装项，保留用户显式包」。
    pub explicit: bool,
}

cbor_struct!(InstalledPackage {
    version: Option<String>,
    explicit: bool,
});

/// 包的观察状态。四个变体互斥，且**都不等价于「应该卸载」**。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageState {
    /// 已安装。
    Installed(InstalledPackage),
    /// 确定未安装。
    Absent,
    /// 该管理器在本平台不可用，或不支持这个包。
    Unsupported {
        /// 原因（不含本机路径）。
        reason: String,
    },
    /// 管理器在场但读不出状态（命令失败、输出无法解析）。
    Unreadable {
        /// 原因（不含命令输出正文）。
        reason: String,
    },
}

impl PackageState {
    /// 稳定的状态名。
    pub const fn kind(&self) -> &'static str {
        match self {
            PackageState::Installed(_) => "installed",
            PackageState::Absent => "absent",
            PackageState::Unsupported { .. } => "unsupported",
            PackageState::Unreadable { .. } => "unreadable",
        }
    }

    /// 取出已安装信息。
    pub const fn installed(&self) -> Option<&InstalledPackage> {
        match self {
            PackageState::Installed(info) => Some(info),
            _ => None,
        }
    }

    /// 状态是否**确定**（`Installed` 或 `Absent`）。
    ///
    /// 不确定的状态一律不产生动作：读不出来不等于没装。
    pub const fn is_conclusive(&self) -> bool {
        matches!(self, PackageState::Installed(_) | PackageState::Absent)
    }
}

impl CborCodec for PackageState {
    fn to_value(&self) -> Value {
        match self {
            PackageState::Installed(info) => {
                Value::Array(vec![Value::Text("installed".into()), info.to_value()])
            }
            PackageState::Absent => Value::Array(vec![Value::Text("absent".into())]),
            PackageState::Unsupported { reason } => Value::Array(vec![
                Value::Text("unsupported".into()),
                Value::Text(reason.clone()),
            ]),
            PackageState::Unreadable { reason } => Value::Array(vec![
                Value::Text("unreadable".into()),
                Value::Text(reason.clone()),
            ]),
        }
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        let tag = items.first().ok_or(CborError::ArityMismatch)?.as_text()?;
        match (tag, items.len()) {
            ("installed", 2) => Ok(PackageState::Installed(InstalledPackage::from_value(
                &items[1],
            )?)),
            ("absent", 1) => Ok(PackageState::Absent),
            ("unsupported", 2) => Ok(PackageState::Unsupported {
                reason: items[1].as_text()?.to_owned(),
            }),
            ("unreadable", 2) => Ok(PackageState::Unreadable {
                reason: items[1].as_text()?.to_owned(),
            }),
            ("installed" | "absent" | "unsupported" | "unreadable", _) => {
                Err(CborError::ArityMismatch)
            }
            (other, _) => Err(CborError::UnknownVariant(other.to_owned())),
        }
    }
}

/// 对单个包的一次观察。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageObservation {
    /// 被观察的包。
    pub identity: PackageIdentity,
    /// 观察到的状态。
    pub state: PackageState,
}

cbor_struct!(PackageObservation {
    identity: PackageIdentity,
    state: PackageState,
});

impl PackageObservation {
    /// 构造观察结果。
    pub fn new(identity: PackageIdentity, state: PackageState) -> Self {
        PackageObservation { identity, state }
    }

    /// 构造「已安装」观察结果（显式安装）。
    pub fn installed(identity: PackageIdentity, version: Option<&str>) -> Self {
        PackageObservation::new(
            identity,
            PackageState::Installed(InstalledPackage {
                version: version.map(str::to_owned),
                explicit: true,
            }),
        )
    }
}

/// 某个包管理器上的一批观察结果。
///
/// 集合里的**每个**身份都必须属于同一个包管理器：观察结果来自一次 `brew list` 这样的
/// 调用，混入别的管理器只会让「这个包到底谁在管」变成不确定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageObservationSet {
    manager: PackageManagerId,
    observations: BTreeMap<PackageIdentity, PackageObservation>,
    observed_at_unix_ms: u64,
}

impl PackageObservationSet {
    /// 构造空集合。
    pub fn new(manager: PackageManagerId, observed_at_unix_ms: u64) -> Self {
        PackageObservationSet {
            manager,
            observations: BTreeMap::new(),
            observed_at_unix_ms,
        }
    }

    /// 集合所属的包管理器。
    pub fn manager(&self) -> &PackageManagerId {
        &self.manager
    }

    /// 观察发生的时刻（Unix 毫秒），仅用于诊断。
    pub fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }

    /// 加入一条观察结果，覆盖同一身份的旧值。
    pub fn insert(&mut self, observation: PackageObservation) -> Result<(), PackageIntentError> {
        observation.identity.validate()?;
        if observation.identity.manager != self.manager {
            return Err(PackageIntentError::ManagerMismatch {
                expected: self.manager.clone(),
                found: observation.identity.manager.clone(),
            });
        }
        self.observations
            .insert(observation.identity.clone(), observation);
        Ok(())
    }

    /// 链式加入，便于构造夹具。
    #[must_use]
    pub fn with(mut self, observation: PackageObservation) -> Self {
        let _ = self.insert(observation);
        self
    }

    /// 查询某个身份的观察结果。
    pub fn get(&self, identity: &PackageIdentity) -> Option<&PackageObservation> {
        self.observations.get(identity)
    }

    /// 查询某个身份的状态；集合里没有该身份时视为 [`PackageState::Absent`]。
    ///
    /// 观察集合是「这个管理器当前装了什么」的**完整**列表，因此不在其中就意味着没装。
    /// 管理器本身读不出来的情形必须由适配器显式写入 [`PackageState::Unreadable`]，
    /// 而不是留空。
    pub fn state_of(&self, identity: &PackageIdentity) -> &PackageState {
        match self.observations.get(identity) {
            Some(observation) => &observation.state,
            None => &PackageState::Absent,
        }
    }

    /// 按身份升序遍历。
    pub fn iter(&self) -> impl Iterator<Item = &PackageObservation> {
        self.observations.values()
    }

    /// 已安装的包身份，按升序。
    pub fn installed_identities(&self) -> impl Iterator<Item = &PackageIdentity> {
        self.observations
            .values()
            .filter(|observation| observation.state.installed().is_some())
            .map(|observation| &observation.identity)
    }

    /// 条目数。
    pub fn len(&self) -> usize {
        self.observations.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }
}

impl CborCodec for PackageObservationSet {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Uint(PACKAGE_OBSERVATION_SET_FORMAT_VERSION as u64),
            self.manager.to_value(),
            self.observations.to_value(),
            Value::Uint(self.observed_at_unix_ms),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        if items.len() != 4 {
            return Err(CborError::ArityMismatch);
        }
        let found = u32::from_value(&items[0])?;
        if found != PACKAGE_OBSERVATION_SET_FORMAT_VERSION {
            return Err(CborError::UnsupportedFormatVersion {
                found,
                supported: PACKAGE_OBSERVATION_SET_FORMAT_VERSION,
            });
        }
        let manager = PackageManagerId::from_value(&items[1])?;
        let decoded = BTreeMap::<PackageIdentity, PackageObservation>::from_value(&items[2])?;
        let mut set = PackageObservationSet::new(manager, u64::from_value(&items[3])?);
        for (key, observation) in decoded {
            if key != observation.identity {
                return Err(CborError::InvalidValue(
                    "观察结果的 map 键与身份不一致".to_owned(),
                ));
            }
            set.insert(observation)
                .map_err(|err| CborError::InvalidValue(err.to_string()))?;
        }
        Ok(set)
    }
}

// ---------------------------------------------------------------------------
// 动作
// ---------------------------------------------------------------------------

/// 包动作种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PackageActionKind {
    /// 安装一个当前不存在的包。
    Install,
    /// 升级到更高版本。
    Upgrade,
    /// 降级到更低版本。
    Downgrade,
    /// 卸载。只能由显式 tombstone 触发。
    Uninstall,
    /// 同一个包名换到另一个 tap / bucket / registry。
    ChangeSource,
}

cbor_unit_enum!(PackageActionKind {
    PackageActionKind::Install => "install",
    PackageActionKind::Upgrade => "upgrade",
    PackageActionKind::Downgrade => "downgrade",
    PackageActionKind::Uninstall => "uninstall",
    PackageActionKind::ChangeSource => "change_source",
});

impl PackageActionKind {
    /// 稳定短名。
    pub const fn as_str(self) -> &'static str {
        match self {
            PackageActionKind::Install => "install",
            PackageActionKind::Upgrade => "upgrade",
            PackageActionKind::Downgrade => "downgrade",
            PackageActionKind::Uninstall => "uninstall",
            PackageActionKind::ChangeSource => "change_source",
        }
    }

    /// 排序权重：卸载最先，来源切换最后。
    pub const fn order_rank(self) -> u8 {
        match self {
            PackageActionKind::Uninstall => 0,
            PackageActionKind::Install => 1,
            PackageActionKind::Upgrade => 2,
            PackageActionKind::Downgrade => 3,
            PackageActionKind::ChangeSource => 4,
        }
    }

    /// 不加管理器信息时的**基线风险**。
    ///
    /// 卸载、降级、来源切换天然是高风险：它们都可能让本机丢失当前能用的版本，而多数
    /// 包管理器只能补偿性回滚。适配器可以把风险**升高**（系统级包管理器），
    /// 但不得降低——见 `envsync_adapters::packages::PackageManagerDescriptor::decorate`。
    pub const fn baseline_risk(self) -> Risk {
        match self {
            PackageActionKind::Install => Risk::Low,
            PackageActionKind::Upgrade => Risk::Medium,
            PackageActionKind::Downgrade
            | PackageActionKind::Uninstall
            | PackageActionKind::ChangeSource => Risk::High,
        }
    }

    /// 是否为破坏性动作（必然使本机失去当前已安装的东西）。
    pub const fn is_destructive(self) -> bool {
        matches!(
            self,
            PackageActionKind::Uninstall
                | PackageActionKind::Downgrade
                | PackageActionKind::ChangeSource
        )
    }
}

/// 一个待执行的包动作。
///
/// 它是**声明**而不是命令：具体 argv 由适配器在应用阶段生成，并经过
/// `envsync_platform::command::CommandRunner` 的模板校验。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageAction {
    /// 目标包。
    pub identity: PackageIdentity,
    /// 动作种类。
    pub kind: PackageActionKind,
    /// 动作前观察到的版本；安装动作为 `None`。
    pub from_version: Option<String>,
    /// 动作后应满足的版本策略。
    pub to_version: VersionPolicy,
    /// 风险等级。
    pub risk: Risk,
    /// 回滚能力。**如实标注**：多数包管理器只能 `Compensating`。
    pub rollback: RollbackCapability,
    /// 是否需要系统提权。
    pub elevation_required: bool,
}

cbor_struct!(PackageAction {
    identity: PackageIdentity,
    kind: PackageActionKind,
    from_version: Option<String>,
    to_version: VersionPolicy,
    risk: Risk,
    rollback: RollbackCapability,
    elevation_required: bool,
});

impl PackageAction {
    /// 用基线风险构造动作：`Risk` 取 [`PackageActionKind::baseline_risk`]，
    /// 回滚能力取 [`RollbackCapability::Compensating`]，不要求提权。
    ///
    /// 适配器随后用自己的 descriptor 调整（只能调严）。
    pub fn new(
        identity: PackageIdentity,
        kind: PackageActionKind,
        from_version: Option<String>,
        to_version: VersionPolicy,
    ) -> Self {
        PackageAction {
            identity,
            kind,
            from_version,
            to_version,
            risk: kind.baseline_risk(),
            rollback: RollbackCapability::Compensating,
            elevation_required: false,
        }
    }

    /// 确定性排序键：先按包身份，再按动作权重。
    pub fn sort_key(&self) -> (String, u8) {
        (self.identity.to_string(), self.kind.order_rank())
    }

    /// 该动作是否必须获得用户显式确认。
    ///
    /// 判据是「破坏性 或 需要提权 或 高风险」。核心层还会再过一遍策略引擎，两者是
    /// **并列**关系：策略说 allow 不代表可以跳过确认。
    pub const fn requires_confirmation(&self) -> bool {
        self.kind.is_destructive() || self.elevation_required || matches!(self.risk, Risk::High)
    }
}

// ---------------------------------------------------------------------------
// intent 集合
// ---------------------------------------------------------------------------

/// 一组包期望状态，按包身份索引。
///
/// 集合保证三件事：
///
/// 1. **确定性**：内部是 `BTreeMap`，插入顺序不影响 [`PackageIntentSet::state_digest`]；
/// 2. **无冲突**：同一身份上出现不同期望时立刻报
///    [`PackageIntentError::ConflictingIntent`]，而不是让后写的悄悄覆盖先写的；
/// 3. **已规范化**：进入集合的身份都通过 [`PackageIdentity::validate`]。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PackageIntentSet {
    intents: BTreeMap<PackageIdentity, PackageIntent>,
}

impl PackageIntentSet {
    /// 构造空集合。
    pub fn new() -> Self {
        PackageIntentSet::default()
    }

    /// 由一组 intent 构造，输入顺序任意。
    pub fn from_intents(
        intents: impl IntoIterator<Item = PackageIntent>,
    ) -> Result<Self, PackageIntentError> {
        let mut set = PackageIntentSet::new();
        for intent in intents {
            set.insert(intent)?;
        }
        Ok(set)
    }

    /// 插入一条 intent。
    ///
    /// 重复插入**完全相同**的 intent 是幂等的（两份配置声明了同一件事，没有歧义）；
    /// 身份相同但期望不同则返回 [`PackageIntentError::ConflictingIntent`]。
    pub fn insert(&mut self, intent: PackageIntent) -> Result<(), PackageIntentError> {
        intent.validate()?;
        if self.intents.len() >= MAX_PACKAGE_INTENTS && !self.intents.contains_key(&intent.identity)
        {
            return Err(PackageIntentError::TooManyIntents {
                actual: self.intents.len() + 1,
                limit: MAX_PACKAGE_INTENTS,
            });
        }
        if let Some(existing) = self.intents.get(&intent.identity) {
            if existing != &intent {
                return Err(PackageIntentError::ConflictingIntent {
                    identity: intent.identity.to_string(),
                    existing: existing.summary(),
                    incoming: intent.summary(),
                });
            }
            return Ok(());
        }
        self.intents.insert(intent.identity.clone(), intent);
        Ok(())
    }

    /// 查询某个身份的 intent。
    pub fn get(&self, identity: &PackageIdentity) -> Option<&PackageIntent> {
        self.intents.get(identity)
    }

    /// 按身份升序遍历。
    pub fn iter(&self) -> impl Iterator<Item = &PackageIntent> {
        self.intents.values()
    }

    /// 条目数。
    pub fn len(&self) -> usize {
        self.intents.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.intents.is_empty()
    }

    /// 集合的确定性摘要。
    ///
    /// 只覆盖内容，不覆盖插入顺序：乱序输入得到同一个摘要。
    pub fn state_digest(&self) -> Digest32 {
        Digest32::domain_hash(PACKAGE_INTENT_SET_DOMAIN, &self.to_canonical_vec())
    }

    /// 由期望集合与观察结果推导出待执行动作（**纯函数**）。
    ///
    /// # 安全语义（设计文档 §6 的硬约束）
    ///
    /// * **观察缺失只生成 install。** 观察不到就是没装，装上即可。
    /// * **观察到的额外包不生成 uninstall。** 这条不是「记得别写」，而是**结构上**
    ///   做不到：整个函数只遍历 `self.intents`，从不遍历 `observed` 的键集合。
    /// * **只有 `EnsureAbsent` 能产生 uninstall。**
    /// * **状态不确定就不动。** [`PackageState::Unsupported`] 与
    ///   [`PackageState::Unreadable`] 一律跳过。
    /// * **版本无法判定就报错。** 绝不静默安装另一个版本。
    ///
    /// 与 `observed` 所属管理器不同的 intent 会被跳过：一次调用只收敛一个管理器。
    pub fn derive_actions(
        &self,
        observed: &PackageObservationSet,
    ) -> Result<Vec<PackageAction>, PackageIntentError> {
        // 同管理器下「包名 -> 已安装身份」的索引，用于识别来源切换。
        let mut installed_by_name: BTreeMap<&str, &PackageIdentity> = BTreeMap::new();
        for identity in observed.installed_identities() {
            installed_by_name.insert(identity.name.as_str(), identity);
        }

        let mut actions = Vec::new();
        for intent in self.intents.values() {
            if intent.identity.manager != *observed.manager() {
                continue;
            }
            let state = observed.state_of(&intent.identity);
            match intent.disposition {
                // 不管理：永远不产生动作。
                PackageDisposition::Unmanaged => {}
                // 显式 tombstone：只有确定已安装时才卸载。
                PackageDisposition::EnsureAbsent => {
                    if let Some(info) = state.installed() {
                        actions.push(PackageAction::new(
                            intent.identity.clone(),
                            PackageActionKind::Uninstall,
                            info.version.clone(),
                            VersionPolicy::Present,
                        ));
                    }
                }
                PackageDisposition::Managed => {
                    match state {
                        PackageState::Installed(info) => {
                            if let Some(action) = self.version_action(intent, info)? {
                                actions.push(action);
                            }
                        }
                        PackageState::Absent => {
                            // 同名但来源不同的包已经装着 -> 来源切换，而不是并排安装。
                            let kind = match installed_by_name.get(intent.identity.name.as_str()) {
                                Some(other) if other.source != intent.identity.source => {
                                    PackageActionKind::ChangeSource
                                }
                                _ => PackageActionKind::Install,
                            };
                            let from = match kind {
                                PackageActionKind::ChangeSource => installed_by_name
                                    .get(intent.identity.name.as_str())
                                    .and_then(|other| observed.get(other))
                                    .and_then(|observation| observation.state.installed())
                                    .and_then(|info| info.version.clone()),
                                _ => None,
                            };
                            actions.push(PackageAction::new(
                                intent.identity.clone(),
                                kind,
                                from,
                                intent.version.clone(),
                            ));
                        }
                        // 读不出来 / 不支持：不产生任何动作。
                        PackageState::Unsupported { .. } | PackageState::Unreadable { .. } => {}
                    }
                }
            }
        }

        actions.sort_by_key(PackageAction::sort_key);
        Ok(actions)
    }

    /// 已安装时按版本策略决定动作。
    fn version_action(
        &self,
        intent: &PackageIntent,
        info: &InstalledPackage,
    ) -> Result<Option<PackageAction>, PackageIntentError> {
        // 管理器不报告版本：只能确认「装了」，任何版本判定都无从谈起。
        let Some(installed) = info.version.as_deref() else {
            return match intent.version {
                VersionPolicy::Present | VersionPolicy::Latest => Ok(None),
                _ => Err(PackageIntentError::UndecidableVersion {
                    identity: intent.identity.to_string(),
                    installed: "<unknown>".to_owned(),
                    policy: intent.version.to_string(),
                }),
            };
        };

        let kind = match intent.version.verdict(installed) {
            VersionVerdict::Satisfied => return Ok(None),
            VersionVerdict::NeedsUpgrade => PackageActionKind::Upgrade,
            VersionVerdict::NeedsDowngrade => PackageActionKind::Downgrade,
            // `Latest` 已安装时留给适配器判断；其余无法判定的情形一律阻塞。
            VersionVerdict::Undecidable if intent.version == VersionPolicy::Latest => {
                return Ok(None)
            }
            VersionVerdict::NeedsChange | VersionVerdict::Undecidable => {
                return Err(PackageIntentError::UndecidableVersion {
                    identity: intent.identity.to_string(),
                    installed: installed.to_owned(),
                    policy: intent.version.to_string(),
                })
            }
        };

        Ok(Some(PackageAction::new(
            intent.identity.clone(),
            kind,
            Some(installed.to_owned()),
            intent.version.clone(),
        )))
    }
}

impl CborCodec for PackageIntentSet {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Uint(PACKAGE_INTENT_SET_FORMAT_VERSION as u64),
            self.intents.to_value(),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        if items.len() != 2 {
            return Err(CborError::ArityMismatch);
        }
        let found = u32::from_value(&items[0])?;
        if found != PACKAGE_INTENT_SET_FORMAT_VERSION {
            return Err(CborError::UnsupportedFormatVersion {
                found,
                supported: PACKAGE_INTENT_SET_FORMAT_VERSION,
            });
        }
        let decoded = BTreeMap::<PackageIdentity, PackageIntent>::from_value(&items[1])?;
        let mut set = PackageIntentSet::new();
        for (key, intent) in decoded {
            // map 键必须与 intent 自述的身份一致，否则同一份内容会有多种编码，
            // 摘要就不再唯一。
            if key != intent.identity {
                return Err(CborError::InvalidValue(
                    "intent 的 map 键与身份不一致".to_owned(),
                ));
            }
            set.insert(intent)
                .map_err(|err| CborError::InvalidValue(err.to_string()))?;
        }
        Ok(set)
    }
}

/// 便于诊断输出的 canonical 编码。
impl PackageIntentSet {
    /// 集合的 canonical CBOR 编码字节。
    pub fn canonical_bytes(&self) -> Vec<u8> {
        cbor::encode(&self.to_value())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(text: &str) -> PackageIdentity {
        PackageIdentity::parse(text).expect("身份合法")
    }

    #[test]
    fn manager_id_is_folded_to_lowercase() {
        assert_eq!(PackageManagerId::parse("BREW").unwrap().as_str(), "brew");
        assert_eq!(
            PackageManagerId::parse(""),
            Err(PackageIntentError::EmptyManager)
        );
        assert_eq!(
            PackageManagerId::parse("brew:x"),
            Err(PackageIntentError::ManagerCharset(':'))
        );
    }

    #[test]
    fn display_and_parse_round_trip() {
        for text in [
            "brew:ripgrep",
            "brew:homebrew/core/ripgrep",
            "npm:@scope/pkg",
            "npm:registry.example/@scope/pkg",
            "cargo:cargo-edit",
            "apt:libFoo",
        ] {
            let parsed = identity(text);
            assert_eq!(
                parsed.to_string().parse::<PackageIdentity>().unwrap(),
                parsed,
                "文本形式 {text} 必须可无损往返"
            );
        }
    }

    #[test]
    fn identity_round_trips_through_canonical_cbor() {
        let parsed = identity("brew:homebrew/core/ripgrep");
        let bytes = parsed.to_canonical_vec();
        assert_eq!(
            PackageIdentity::from_canonical_slice(&bytes).unwrap(),
            parsed
        );
    }

    #[test]
    fn version_policy_text_round_trips() {
        for policy in [
            VersionPolicy::Present,
            VersionPolicy::Latest,
            VersionPolicy::exact("1.2.3").unwrap(),
            VersionPolicy::compatible("^1.2").unwrap(),
        ] {
            assert_eq!(policy.to_string().parse::<VersionPolicy>().unwrap(), policy);
            let bytes = policy.to_canonical_vec();
            assert_eq!(VersionPolicy::from_canonical_slice(&bytes).unwrap(), policy);
        }
    }

    #[test]
    fn conflicting_intent_is_rejected() {
        let base = PackageIntent::new(identity("brew:ripgrep"));
        let other = base
            .clone()
            .with_version(VersionPolicy::exact("14.0.0").unwrap());
        let mut set = PackageIntentSet::new();
        set.insert(base.clone()).unwrap();
        // 幂等：同一条 intent 重复插入没有歧义。
        set.insert(base).unwrap();
        assert!(matches!(
            set.insert(other),
            Err(PackageIntentError::ConflictingIntent { .. })
        ));
    }

    #[test]
    fn tombstone_cannot_carry_version_policy() {
        let intent = PackageIntent::new(identity("brew:ripgrep"))
            .with_disposition(PackageDisposition::EnsureAbsent)
            .with_version(VersionPolicy::exact("1.0.0").unwrap());
        assert!(matches!(
            intent.validate(),
            Err(PackageIntentError::DispositionWithVersion { .. })
        ));
    }

    #[test]
    fn unnormalized_identity_is_rejected_at_the_boundary() {
        // 绕过 `new` 直接构造一个未折叠大小写的身份。
        let raw = PackageIdentity {
            manager: PackageManagerId::parse("brew").unwrap(),
            name: "Ripgrep".to_owned(),
            source: None,
        };
        assert!(matches!(
            raw.validate(),
            Err(PackageIntentError::NotNormalized(_))
        ));
        let mut set = PackageIntentSet::new();
        assert!(set.insert(PackageIntent::new(raw)).is_err());
    }

    #[test]
    fn observation_set_rejects_foreign_manager() {
        let mut set = PackageObservationSet::new(PackageManagerId::parse("brew").unwrap(), 0);
        let err = set
            .insert(PackageObservation::installed(
                identity("cargo:ripgrep"),
                Some("14.0.0"),
            ))
            .unwrap_err();
        assert!(matches!(err, PackageIntentError::ManagerMismatch { .. }));
    }

    #[test]
    fn to_resource_id_is_lossless_or_none() {
        assert_eq!(
            identity("brew:ripgrep").to_resource_id().unwrap().as_str(),
            "packages/brew/ripgrep"
        );
        assert_eq!(
            identity("brew:homebrew/core/ripgrep")
                .to_resource_id()
                .unwrap()
                .as_str(),
            "packages/brew/homebrew/core/ripgrep"
        );
        // npm scope 含 `@`，无损映射不存在。
        assert!(identity("npm:@scope/pkg").to_resource_id().is_none());
    }
}
