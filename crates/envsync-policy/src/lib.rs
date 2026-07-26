//! # envsync-policy
//!
//! EnvSync 的**可解释安全策略引擎**：把「这台设备上允许发生什么」表达成一组封闭的、
//! 求值必然终止的规则，并对每个决策给出可审计的解释。
//!
//! 设计文档 §6 / §7 要求包卸载、降级、系统级提权与 Agent Bundle 启用都必须先过策略；
//! M3 计划 Task 7 进一步要求 **deny-first** 语义与完整解释。本 crate 只做这两件事：
//! 不做任何 I/O，不认识文件系统、命令、Vault 或网络。调用方把**已经发生的观察**
//! 摆到台面上（[`PolicyFacts`]），引擎给出决策与解释（[`DecisionOutcome`]）。
//!
//! ## 模块地图
//!
//! | 模块 | 职责 |
//! |---|---|
//! | [`ast`] | 封闭 AST：[`Decision`]、[`ResourceKind`]、[`Operation`]、[`FactPredicate`]、[`MatchExpr`]、[`Rule`]、[`PolicySet`] |
//! | [`evaluate`] | [`PolicyFacts`]、deny-first 求值、[`DecisionOutcome`] |
//! | [`explain`] | 事实摘要（[`facts_digest`]）与人类可读解释渲染 |
//! | [`load`] | 内建默认策略、YAML 解析与多来源合并 |
//!
//! ## 五条硬约束
//!
//! 1. **deny-first。** 任何一条命中的 [`Decision::Deny`] 都压过全部 `Allow` 与
//!    `RequireConfirmation`，与 priority、书写顺序无关。见 [`PolicySet::evaluate`]。
//! 2. **默认值分域。** 没有任何规则命中时，决策由资源种类决定，
//!    见 [`ResourceKind::default_decision`]。
//! 3. **求值必然终止。** AST 是封闭枚举：没有循环、没有正则、没有动态代码。
//!    通配只支持「精确」与「`*` 尾缀」两种形态，用 O(n) 的字节比较实现，
//!    **结构上**不存在灾难性回溯。资源上限见 [`MAX_RULES`]、[`MAX_AST_DEPTH`]、
//!    [`MAX_AST_NODES`]。
//! 4. **决策必须能解释。** 每个决策都带命中的规则标识、来源文件、priority 与输入
//!    事实摘要。
//! 5. **秘密只以 opaque 标识出现。** [`PolicyFacts::secret_refs`] 里只放 SecretRef 的
//!    逻辑标识，引擎从不接触明文；解释渲染还会再做一次字符集过滤（见 [`explain`]）。
//!
//! ## 规则文件是不可信输入
//!
//! 策略文件会随 Workspace 同步到所有设备：一台被攻陷的设备写下的规则会在其他每台设备
//! 上被解析和求值。因此 [`PolicySet::parse_yaml`] 在**解析之前**就拒绝 YAML 锚点/别名
//! （billion-laughs 式展开可以在解析阶段耗尽内存）与过深嵌套，随后拒绝未知字段、未知
//! 版本、重复规则标识，并对规则条数、AST 深度与节点数逐项设限。
//!
//! ## 示例
//!
//! ```
//! use envsync_domain::{Os, Risk};
//! use envsync_policy::{Decision, Operation, PolicyFacts, PolicySet, ResourceKind};
//!
//! let policy = PolicySet::builtin_defaults();
//!
//! // 没有任何规则允许的命令执行：按资源种类默认拒绝。
//! let run = PolicyFacts::new(ResourceKind::Command, Operation::Execute, Risk::Medium, Os::Linux);
//! assert_eq!(policy.evaluate(&run).decision, Decision::Deny);
//!
//! // 包卸载：内建规则要求显式确认，解释里能看到命中的规则标识。
//! let uninstall = PolicyFacts::new(
//!     ResourceKind::Package,
//!     Operation::Uninstall,
//!     Risk::High,
//!     Os::Linux,
//! )
//! .with_adapter("builtin.pkg.brew");
//! let outcome = policy.evaluate(&uninstall);
//! assert_eq!(outcome.decision, Decision::RequireConfirmation);
//! assert!(outcome
//!     .explanation
//!     .contains("builtin.package.uninstall-requires-confirmation"));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod ast;
pub mod evaluate;
pub mod explain;
pub mod load;

pub use ast::{
    Decision, FactPredicate, MatchExpr, Operation, PolicySet, ResourceGlob, ResourceKind, Rule,
    RuleId,
};
pub use evaluate::{DecisionOutcome, MatchedRule, PolicyFacts};
pub use explain::{facts_digest, summarize_facts};
pub use load::{
    BUILTIN_AGENT_BUNDLE_ENABLE, BUILTIN_ELEVATION_DENIED, BUILTIN_HIGH_RISK_COMMAND,
    BUILTIN_PACKAGE_DOWNGRADE, BUILTIN_PACKAGE_UNINSTALL, BUILTIN_SOURCE,
    BUILTIN_SYSTEM_PACKAGE_PREFIX, BUILTIN_SYSTEM_PACKAGE_WRITE, BUILTIN_UNSIGNED_ACTIVE_CONTENT,
};

/// 策略文件的当前格式版本。
///
/// 未知版本一律拒绝，绝不静默降级——这与 [`envsync_domain`] 对所有持久化格式的要求一致。
pub const POLICY_FORMAT_VERSION: u32 = 1;

/// 一个策略集允许包含的最大规则条数。
///
/// 规则集来自会被同步的配置，因此必须**有界**：求值是线性扫描，条数直接决定每次决策的
/// 代价。超限在 [`PolicySet::parse_yaml`] 与 [`PolicySet::merge`] 阶段被拒绝。
pub const MAX_RULES: usize = 10_000;

/// 单条规则的匹配表达式允许的最大嵌套深度。
///
/// 深度从 1 开始计（单个叶子谓词深度为 1）。它同时是求值时的硬预算：即便有人绕过校验
/// 直接构造更深的树，[`MatchExpr::matches`] 也会在预算耗尽时保守地返回「不匹配」，
/// 而不是递归到栈溢出。
pub const MAX_AST_DEPTH: usize = 32;

/// 单条规则的匹配表达式允许的最大节点总数（组合子与叶子都计入）。
pub const MAX_AST_NODES: usize = 256;

/// 策略文本允许的最大字节长度。
pub const MAX_POLICY_TEXT_LEN: usize = 1024 * 1024;

/// 策略文本允许的最大**输入嵌套**（缩进列数与流式括号深度的合计）。
///
/// 这是一道在 serde 反序列化**之前**执行的线性预检：YAML 反序列化会随输入嵌套递归，
/// 一份刻意构造的超深文档能把递归推到栈溢出（进程直接崩溃，连错误都返回不了）。
/// 预检把递归层数钉死在一个安全常数内，真实策略离这个上限差着两个数量级。
pub const MAX_INPUT_NESTING: usize = 128;

/// 规则标识允许的最大字节长度。
pub const MAX_RULE_ID_LEN: usize = 128;

/// 通配模式（资源 glob、adapter 前缀）允许的最大字节长度。
pub const MAX_PATTERN_LEN: usize = 256;

/// 规则理由允许的最大字节长度。
pub const MAX_REASON_LEN: usize = 512;

/// 规则来源标签允许的最大字节长度。
pub const MAX_SOURCE_LEN: usize = 128;

/// 单条 SecretRef opaque 标识允许的最大字节长度。
///
/// 超长或含非法字符的取值在解释里被替换成占位符——这是防止「有人把明文塞进
/// `secret_refs`」的最后一道网。
pub const MAX_SECRET_REF_LEN: usize = 128;

/// 解释文本中逐条列出的规则条数上限。
///
/// 超过后只给出汇总计数：一份 10,000 条的规则集不应该把终端刷屏。
pub const MAX_EXPLAIN_TRACE_RULES: usize = 200;

/// 策略解析、校验与合并错误。
///
/// 所有变体的 `Display` 输出只描述**结构问题**：字段名、上限、规则标识与不合法的取值
/// 片段。它们不含秘密值、不含绝对路径，可以直接写进日志与 CLI 诊断。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// 策略文本超过 [`MAX_POLICY_TEXT_LEN`]。
    #[error("策略文本 {actual} 字节超过上限 {limit} 字节")]
    TextTooLarge {
        /// 实际字节数。
        actual: usize,
        /// 允许的上限。
        limit: usize,
    },

    /// 策略文本的输入嵌套超过 [`MAX_INPUT_NESTING`]。
    #[error("策略文本第 {line} 行嵌套深度 {actual} 超过上限 {limit}")]
    NestingTooDeep {
        /// 触发上限的行号（从 1 开始）。
        line: usize,
        /// 实际嵌套深度。
        actual: usize,
        /// 允许的上限。
        limit: usize,
    },

    /// 策略文本里出现了 YAML 锚点、别名、合并键或标签。
    #[error(
        "策略文本第 {line} 行出现不允许的 YAML 构造 `{token}`（锚点/别名/合并键/标签一律禁止）"
    )]
    UnsafeYamlConstruct {
        /// 触发的行号（从 1 开始）。
        line: usize,
        /// 触发的记号。
        token: String,
    },

    /// YAML 语法错误或 schema 不符（含未知字段、类型不匹配、未知枚举取值）。
    #[error("策略文件 `{source_label}` 解析失败：{message}")]
    Yaml {
        /// 来源标签（已去掉目录）。
        source_label: String,
        /// 结构化描述。
        message: String,
    },

    /// `version` 不是本引擎支持的版本。
    #[error("不支持的策略格式版本 {actual}，本引擎只接受 {expected}")]
    UnsupportedVersion {
        /// 文件里声明的版本。
        actual: u32,
        /// 本引擎支持的版本。
        expected: u32,
    },

    /// 规则标识非法。
    #[error("规则标识 `{id}` 非法：{reason}")]
    InvalidRuleId {
        /// 出问题的标识（已截断）。
        id: String,
        /// 具体原因。
        reason: &'static str,
    },

    /// 同一个策略集里出现重复的规则标识。
    #[error("规则标识 `{id}` 重复")]
    DuplicateRuleId {
        /// 重复的标识。
        id: String,
    },

    /// 规则条数超过 [`MAX_RULES`]。
    #[error("规则条数 {actual} 超过上限 {limit}")]
    TooManyRules {
        /// 实际条数。
        actual: usize,
        /// 允许的上限。
        limit: usize,
    },

    /// 单条规则的匹配表达式过深。
    #[error("规则 `{rule}` 的匹配表达式深度 {actual} 超过上限 {limit}")]
    AstTooDeep {
        /// 规则标识。
        rule: String,
        /// 实际深度。
        actual: usize,
        /// 允许的上限。
        limit: usize,
    },

    /// 单条规则的匹配表达式节点过多。
    #[error("规则 `{rule}` 的匹配表达式节点数 {actual} 超过上限 {limit}")]
    AstTooLarge {
        /// 规则标识。
        rule: String,
        /// 实际节点数。
        actual: usize,
        /// 允许的上限。
        limit: usize,
    },

    /// 通配模式非法。
    #[error("模式 `{pattern}` 非法：{reason}")]
    InvalidPattern {
        /// 出问题的模式（已截断）。
        pattern: String,
        /// 具体原因。
        reason: &'static str,
    },

    /// 规则理由超长。
    #[error("规则 `{rule}` 的理由 {actual} 字节超过上限 {limit} 字节")]
    ReasonTooLong {
        /// 规则标识。
        rule: String,
        /// 实际字节数。
        actual: usize,
        /// 允许的上限。
        limit: usize,
    },
}

impl PolicyError {
    /// 稳定的机器可读错误码，供 `--json` 输出与测试断言使用。
    ///
    /// 错误码是 API 的一部分：新增变体可以增加新码，已有码不改名。
    pub fn code(&self) -> &'static str {
        match self {
            PolicyError::TextTooLarge { .. } => "policy.text_too_large",
            PolicyError::NestingTooDeep { .. } => "policy.nesting_too_deep",
            PolicyError::UnsafeYamlConstruct { .. } => "policy.unsafe_yaml_construct",
            PolicyError::Yaml { .. } => "policy.yaml",
            PolicyError::UnsupportedVersion { .. } => "policy.unsupported_version",
            PolicyError::InvalidRuleId { .. } => "policy.invalid_rule_id",
            PolicyError::DuplicateRuleId { .. } => "policy.duplicate_rule_id",
            PolicyError::TooManyRules { .. } => "policy.too_many_rules",
            PolicyError::AstTooDeep { .. } => "policy.ast_too_deep",
            PolicyError::AstTooLarge { .. } => "policy.ast_too_large",
            PolicyError::InvalidPattern { .. } => "policy.invalid_pattern",
            PolicyError::ReasonTooLong { .. } => "policy.reason_too_long",
        }
    }
}

/// 把用户输入截断到适合放进错误信息的长度，并抹掉控制字符。
///
/// 错误信息会进日志和终端；未经处理的输入可以用控制字符伪造日志行。
pub(crate) fn truncate_for_error(text: &str) -> String {
    const LIMIT: usize = 64;
    let cleaned: String = text
        .chars()
        .map(|ch| if ch.is_control() { '\u{fffd}' } else { ch })
        .collect();
    if cleaned.chars().count() <= LIMIT {
        return cleaned;
    }
    let head: String = cleaned.chars().take(LIMIT).collect();
    format!("{head}…")
}
