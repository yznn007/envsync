//! 策略规则的**封闭 AST**。
//!
//! 「封闭」在这里是一句可以被编译器检查的承诺：[`MatchExpr`] 与 [`FactPredicate`] 都是
//! 普通枚举，**没有** `#[non_exhaustive]`，所以下游可以写穷尽 `match` 把所有构造列全。
//! 列全之后就能看到这里没有任何危险构造：
//!
//! * 没有循环——树是有限的，[`MatchExpr::depth`] 与 [`MatchExpr::node_count`] 都用显式
//!   工作栈迭代计算，不递归，也就不会栈溢出；
//! * 没有正则——通配只有 [`ResourceGlob::Exact`] 与 [`ResourceGlob::Prefix`] 两种形态，
//!   实现是 `==` 与 `starts_with`，复杂度 O(n)，**结构上**不可能有灾难性回溯；
//! * 没有动态代码——没有函数指针、没有闭包、没有脚本字符串，谓词只能读
//!   [`crate::PolicyFacts`] 里已经存在的字段。
//!
//! 求值（[`MatchExpr::matches`]）实现在 [`crate::evaluate`]，因为它需要事实。

use std::collections::BTreeSet;

use envsync_domain::{Os, Risk};
use serde::{Deserialize, Serialize};

use crate::{
    truncate_for_error, PolicyError, MAX_AST_DEPTH, MAX_AST_NODES, MAX_PATTERN_LEN, MAX_REASON_LEN,
    MAX_RULES, MAX_RULE_ID_LEN, MAX_SOURCE_LEN,
};

/// 策略判定结果。
///
/// 三个取值构成一条严格的严厉度阶梯：`Deny` > `RequireConfirmation` > `Allow`。
/// 合并多条命中规则时按这条阶梯取最严厉者，见 [`crate::PolicySet::evaluate`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// 允许，无需额外确认。
    Allow,
    /// 需要用户显式确认后才能继续。
    RequireConfirmation,
    /// 拒绝。
    Deny,
}

impl Decision {
    /// 稳定短名称，用于持久化、日志与解释文本。
    pub const fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::RequireConfirmation => "require_confirmation",
            Decision::Deny => "deny",
        }
    }

    /// 由短名称解析；未知取值返回 `None`（绝不猜测）。
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "allow" => Decision::Allow,
            "require_confirmation" => Decision::RequireConfirmation,
            "deny" => Decision::Deny,
            _ => return None,
        })
    }
}

/// 被判定对象的种类。
///
/// 种类决定「没有任何规则命中时怎么办」，见 [`ResourceKind::default_decision`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// 普通配置文件（M0/M1 的文件同步）。
    File,
    /// 包管理器里的一个包。
    Package,
    /// Agent Bundle：Agent 定义、Skill、提示规则、MCP 配置等主动内容。
    AgentBundle,
    /// 通过 command runner 执行的外部命令。
    Command,
    /// 第三方插件。
    Plugin,
}

impl ResourceKind {
    /// 稳定短名称。
    pub const fn as_str(self) -> &'static str {
        match self {
            ResourceKind::File => "file",
            ResourceKind::Package => "package",
            ResourceKind::AgentBundle => "agent_bundle",
            ResourceKind::Command => "command",
            ResourceKind::Plugin => "plugin",
        }
    }

    /// 由短名称解析；未知取值返回 `None`。
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "file" => ResourceKind::File,
            "package" => ResourceKind::Package,
            "agent_bundle" => ResourceKind::AgentBundle,
            "command" => ResourceKind::Command,
            "plugin" => ResourceKind::Plugin,
            _ => return None,
        })
    }

    /// 没有任何规则命中时的默认决策。
    ///
    /// # 为什么默认值要分域
    ///
    /// 「默认拒绝」是安全默认值，但它只在**没有别的把关环节**时才是正确的默认值。
    /// EnvSync 的把关环节并不是均匀分布的：
    ///
    /// * [`ResourceKind::Command`]、[`ResourceKind::AgentBundle`]、[`ResourceKind::Plugin`]
    ///   是**主动内容**：它们会在本机执行代码，或者把代码交给 Agent 去执行。设计文档 §7
    ///   要求 Bundle「默认隔离到 quarantine，展示来源、签名、diff 与声明能力后再启用」，
    ///   M3 计划 Task 2/3 要求命令走 capability-scoped runner 且「默认 deny」。这些操作
    ///   **没有**任何一条既有链路能兜底，所以规则集没写到的一律 [`Decision::Deny`]：
    ///   新增一种没人想过的主动内容时，默认结果必须是「不跑」。
    ///
    /// * [`ResourceKind::File`] 沿用既有默认 [`Decision::Allow`]。文件同步从 M0 起就已经
    ///   被两道更强的机制把关了：任何写入都必须先出现在不可变 Plan 里（设计文档 §2 原则 2
    ///   「计划先行」、§3.4），并且 Plan 会展示 diff、风险与影响范围、由用户确认后才应用；
    ///   写入本身还受授权根目录约束（§5）。也就是说文件路径上「策略沉默」不等于「无人把关」。
    ///   如果这里改成默认拒绝，结果不是更安全，而是**空策略集下所有文件同步全部瘫痪**，
    ///   用户被迫写一条 `allow *` 兜底规则——那条兜底规则才是真正的安全事故，因为它同时
    ///   把未来新增的资源种类也一起放行了。
    ///
    /// * [`ResourceKind::Package`] 同样默认 [`Decision::Allow`]，理由与文件一致：包同步
    ///   走的是同一条 Plan + 显式确认链路（M3 计划 Task 3），而真正危险的包操作
    ///   ——卸载、降级、系统级包管理器写入、提权——都已经由
    ///   [`crate::PolicySet::builtin_defaults`] 里的**显式规则**兜住，不依赖默认值。
    ///   把默认值也设成拒绝，只会让「安装一个缺失的包」这种常规动作在空策略下失败。
    ///
    /// 一句话：默认值负责的是「规则集没覆盖到的未知情况」，而不是「已知的危险操作」。
    /// 已知的危险操作必须写成显式规则，这样它们才会出现在解释里。
    pub const fn default_decision(self) -> Decision {
        match self {
            ResourceKind::File | ResourceKind::Package => Decision::Allow,
            ResourceKind::Command | ResourceKind::AgentBundle | ResourceKind::Plugin => {
                Decision::Deny
            }
        }
    }
}

/// 被判定的操作。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// 读取。
    Read,
    /// 写入或覆盖。
    Write,
    /// 删除。
    Delete,
    /// 安装包。
    Install,
    /// 升级包。
    Upgrade,
    /// 降级包。
    Downgrade,
    /// 卸载包。
    Uninstall,
    /// 执行命令。
    Execute,
    /// 启用 Agent Bundle 或插件。
    Enable,
}

impl Operation {
    /// 稳定短名称。
    pub const fn as_str(self) -> &'static str {
        match self {
            Operation::Read => "read",
            Operation::Write => "write",
            Operation::Delete => "delete",
            Operation::Install => "install",
            Operation::Upgrade => "upgrade",
            Operation::Downgrade => "downgrade",
            Operation::Uninstall => "uninstall",
            Operation::Execute => "execute",
            Operation::Enable => "enable",
        }
    }

    /// 由短名称解析；未知取值返回 `None`。
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "read" => Operation::Read,
            "write" => Operation::Write,
            "delete" => Operation::Delete,
            "install" => Operation::Install,
            "upgrade" => Operation::Upgrade,
            "downgrade" => Operation::Downgrade,
            "uninstall" => Operation::Uninstall,
            "execute" => Operation::Execute,
            "enable" => Operation::Enable,
            _ => return None,
        })
    }

    /// 是否会改变目标状态（「写操作」）。
    ///
    /// [`Operation::Read`] 与 [`Operation::Execute`] 之外的操作都算写：`Execute` 单独排除
    /// 是因为它的危险性由 [`ResourceKind::Command`] 那条链路（命令 allowlist + 默认拒绝）
    /// 把关，与「包管理器改变了本机安装状态」不是同一件事。
    pub const fn is_write(self) -> bool {
        match self {
            Operation::Read | Operation::Execute => false,
            Operation::Write
            | Operation::Delete
            | Operation::Install
            | Operation::Upgrade
            | Operation::Downgrade
            | Operation::Uninstall
            | Operation::Enable => true,
        }
    }

    /// 全部写操作，按稳定顺序排列。
    pub fn write_operations() -> BTreeSet<Operation> {
        [
            Operation::Write,
            Operation::Delete,
            Operation::Install,
            Operation::Upgrade,
            Operation::Downgrade,
            Operation::Uninstall,
            Operation::Enable,
        ]
        .into_iter()
        .collect()
    }
}

/// 规则标识：策略集内唯一，出现在每一条解释里。
///
/// 字符集刻意收得很窄（ASCII 字母、数字、`.`、`-`、`_`、`:`）：标识会被拼进日志行和
/// 终端输出，允许空白或控制字符就等于允许伪造日志。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RuleId(String);

impl RuleId {
    /// 解析并校验规则标识。
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        if text.is_empty() {
            return Err(PolicyError::InvalidRuleId {
                id: String::new(),
                reason: "不能为空",
            });
        }
        if text.len() > MAX_RULE_ID_LEN {
            return Err(PolicyError::InvalidRuleId {
                id: truncate_for_error(text),
                reason: "超过长度上限",
            });
        }
        for ch in text.chars() {
            let allowed = ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ':');
            if !allowed {
                return Err(PolicyError::InvalidRuleId {
                    id: truncate_for_error(text),
                    reason: "只允许 ASCII 字母、数字与 `.`、`-`、`_`、`:`",
                });
            }
        }
        Ok(RuleId(text.to_owned()))
    }

    /// 文本表示。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// 受限的资源标识通配。
///
/// **只有**两种形态：精确相等，以及单个 `*` 尾缀构成的前缀匹配。没有 `?`、没有字符类、
/// 没有 `**`、没有正则。这是一条安全决定而不是功能取舍：策略文件是不可信输入，任何
/// 带回溯的匹配器都能被一份几十字节的规则文件变成 CPU 拒绝服务。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum ResourceGlob {
    /// 精确匹配。
    Exact(String),
    /// 前缀匹配，由 `前缀*` 解析得到；`*` 自身解析为空前缀，匹配一切。
    Prefix(String),
}

impl ResourceGlob {
    /// 解析通配模式。
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        if text.is_empty() {
            return Err(PolicyError::InvalidPattern {
                pattern: String::new(),
                reason: "不能为空",
            });
        }
        if text.len() > MAX_PATTERN_LEN {
            return Err(PolicyError::InvalidPattern {
                pattern: truncate_for_error(text),
                reason: "超过长度上限",
            });
        }
        if text.chars().any(char::is_control) {
            return Err(PolicyError::InvalidPattern {
                pattern: truncate_for_error(text),
                reason: "不能包含控制字符",
            });
        }
        match text.find('*') {
            None => Ok(ResourceGlob::Exact(text.to_owned())),
            Some(index) if index + 1 == text.len() => {
                Ok(ResourceGlob::Prefix(text[..index].to_owned()))
            }
            Some(_) => Err(PolicyError::InvalidPattern {
                pattern: truncate_for_error(text),
                reason: "`*` 只能作为末尾字符出现一次",
            }),
        }
    }

    /// 是否匹配给定取值。
    ///
    /// 复杂度是 O(模式长度)，没有回溯。
    pub fn matches(&self, value: &str) -> bool {
        match self {
            ResourceGlob::Exact(expected) => value == expected,
            ResourceGlob::Prefix(prefix) => value.starts_with(prefix.as_str()),
        }
    }

    /// 还原成书写形式，用于解释文本。
    pub fn to_source(&self) -> String {
        match self {
            ResourceGlob::Exact(value) => value.clone(),
            ResourceGlob::Prefix(prefix) => format!("{prefix}*"),
        }
    }
}

/// 叶子谓词：对 [`crate::PolicyFacts`] 单个维度的判断。
///
/// 集合型谓词（`Vec` 语义为「任意一个命中即命中」）用 [`BTreeSet`] 承载，因此**书写顺序
/// 不影响相等性，也不影响求值结果**——这是确定性的一部分。
///
/// 这是一个封闭枚举：下游可以对它写穷尽 `match`，从而在编译期确认没有遗漏的构造。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum FactPredicate {
    /// 资源种类属于集合。
    ResourceKind(BTreeSet<ResourceKind>),
    /// 操作属于集合。
    Operation(BTreeSet<Operation>),
    /// 操作系统属于集合。
    Os(BTreeSet<Os>),
    /// 适配器稳定 ID 精确属于集合；事实里没有适配器时不命中。
    Adapter(BTreeSet<String>),
    /// 适配器稳定 ID 以给定字符串开头；事实里没有适配器时不命中。
    AdapterPrefix(String),
    /// 风险不低于给定等级（`>=` 比较，用 [`Risk`] 自身的序）。
    RiskAtLeast(Risk),
    /// 设备 Profile 标签集合与给定集合有交集。
    ProfileTag(BTreeSet<String>),
    /// 设备能力集合与给定集合有交集。
    Capability(BTreeSet<String>),
    /// Bundle 声明能力集合与给定集合有交集。
    DeclaredCapability(BTreeSet<String>),
    /// 发布者签名指纹精确属于集合；事实里没有 signer 时不命中。
    Signer(BTreeSet<String>),
    /// 是否存在发布者签名指纹。`false` 即「未知 signer」。
    SignerPresent(bool),
    /// 资源标识匹配任意一个通配模式；事实里没有资源标识时不命中。
    Resource(BTreeSet<ResourceGlob>),
    /// 是否需要提权。
    ElevationRequired(bool),
}

/// 匹配表达式：叶子谓词加三个布尔组合子。
///
/// 这是一个封闭枚举，没有 `#[non_exhaustive]`：把这四个构造列全，就穷尽了策略语言的全部
/// 表达能力。没有第五种构造能引入循环、正则或动态求值。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum MatchExpr {
    /// 单个谓词。
    Leaf(FactPredicate),
    /// 全部子表达式都命中；空列表命中一切（YAML 里写空 `match:` 即此形态）。
    All(Vec<MatchExpr>),
    /// 任意一个子表达式命中；空列表永不命中。
    Any(Vec<MatchExpr>),
    /// 取反。
    Not(Box<MatchExpr>),
}

impl MatchExpr {
    /// 便捷构造：单个谓词。
    pub fn leaf(predicate: FactPredicate) -> Self {
        MatchExpr::Leaf(predicate)
    }

    /// 便捷构造：匹配一切。
    pub fn any_facts() -> Self {
        MatchExpr::All(Vec::new())
    }

    /// 节点总数（组合子与叶子都计入）。
    ///
    /// 用显式工作栈迭代计算：这个方法可能被喂进任意深的树（例如 property test 直接构造
    /// 的树），递归实现会栈溢出。
    pub fn node_count(&self) -> usize {
        let mut count = 0usize;
        let mut stack: Vec<&MatchExpr> = vec![self];
        while let Some(node) = stack.pop() {
            count = count.saturating_add(1);
            match node {
                MatchExpr::Leaf(_) => {}
                MatchExpr::All(children) | MatchExpr::Any(children) => {
                    stack.extend(children.iter())
                }
                MatchExpr::Not(inner) => stack.push(inner.as_ref()),
            }
        }
        count
    }

    /// 嵌套深度，叶子为 1。同样用显式工作栈迭代计算。
    pub fn depth(&self) -> usize {
        let mut max = 0usize;
        let mut stack: Vec<(&MatchExpr, usize)> = vec![(self, 1)];
        while let Some((node, depth)) = stack.pop() {
            max = max.max(depth);
            let next = depth.saturating_add(1);
            match node {
                MatchExpr::Leaf(_) => {}
                MatchExpr::All(children) | MatchExpr::Any(children) => {
                    stack.extend(children.iter().map(|child| (child, next)));
                }
                MatchExpr::Not(inner) => stack.push((inner.as_ref(), next)),
            }
        }
        max
    }

    /// 校验资源上限。
    ///
    /// `rule` 只用于错误信息。
    pub fn validate(&self, rule: &str) -> Result<(), PolicyError> {
        let depth = self.depth();
        if depth > MAX_AST_DEPTH {
            return Err(PolicyError::AstTooDeep {
                rule: truncate_for_error(rule),
                actual: depth,
                limit: MAX_AST_DEPTH,
            });
        }
        let nodes = self.node_count();
        if nodes > MAX_AST_NODES {
            return Err(PolicyError::AstTooLarge {
                rule: truncate_for_error(rule),
                actual: nodes,
                limit: MAX_AST_NODES,
            });
        }
        Ok(())
    }
}

/// 一条策略规则。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rule {
    /// 规则标识，策略集内唯一。
    pub id: RuleId,
    /// 显式优先级；数值越大越靠前。默认 0。
    ///
    /// priority **不影响** deny-first：它只决定命中列表与解释里的排列顺序。
    pub priority: i32,
    /// 命中时给出的决策。
    pub decision: Decision,
    /// 人类可读理由，会原样出现在解释里。
    pub reason: String,
    /// 匹配表达式。
    pub matcher: MatchExpr,
    /// 来源标签（文件名，不含目录）。
    pub source: String,
}

impl Rule {
    /// 构造一条 priority 为 0、无理由、来源为 `<inline>` 的规则。
    pub fn new(id: RuleId, decision: Decision, matcher: MatchExpr) -> Self {
        Rule {
            id,
            priority: 0,
            decision,
            reason: String::new(),
            matcher,
            source: "<inline>".to_owned(),
        }
    }

    /// 设置优先级。
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// 设置理由。
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    /// 设置来源；取值会经过 [`sanitize_source`]。
    pub fn with_source(mut self, source: &str) -> Self {
        self.source = sanitize_source(source);
        self
    }

    /// 校验规则自身的资源上限。
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.reason.len() > MAX_REASON_LEN {
            return Err(PolicyError::ReasonTooLong {
                rule: self.id.as_str().to_owned(),
                actual: self.reason.len(),
                limit: MAX_REASON_LEN,
            });
        }
        self.matcher.validate(self.id.as_str())
    }
}

/// 把来源标签收敛成「可以安全印到终端的文件名」。
///
/// 去掉目录（解释文本不应泄漏本机绝对路径）、抹掉控制字符、截断到
/// [`MAX_SOURCE_LEN`]；结果为空时返回 `<unknown>`。
pub fn sanitize_source(source: &str) -> String {
    let base = source
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(source)
        .trim()
        .chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>();
    if base.is_empty() {
        return "<unknown>".to_owned();
    }
    if base.len() <= MAX_SOURCE_LEN {
        return base;
    }
    base.chars().take(MAX_SOURCE_LEN / 4).collect()
}

/// 一组规则。
///
/// 规则始终按 **priority 降序、随后 rule_id 升序** 存放：构造函数负责排序，因此同一批
/// 规则无论以什么顺序传进来，得到的 [`PolicySet`] 完全相等，求值结果与命中顺序也完全
/// 相同（确定性）。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct PolicySet {
    pub(crate) rules: Vec<Rule>,
}

impl PolicySet {
    /// 空策略集：所有判定都落到 [`ResourceKind::default_decision`]。
    pub fn empty() -> Self {
        PolicySet { rules: Vec::new() }
    }

    /// 由规则列表构造：校验上限、拒绝重复标识，并按确定性顺序排序。
    pub fn from_rules(rules: Vec<Rule>) -> Result<Self, PolicyError> {
        if rules.len() > MAX_RULES {
            return Err(PolicyError::TooManyRules {
                actual: rules.len(),
                limit: MAX_RULES,
            });
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for rule in &rules {
            rule.validate()?;
            if !seen.insert(rule.id.as_str()) {
                return Err(PolicyError::DuplicateRuleId {
                    id: rule.id.as_str().to_owned(),
                });
            }
        }
        let mut rules = rules;
        sort_rules(&mut rules);
        Ok(PolicySet { rules })
    }

    /// 只读的规则视图，顺序即求值顺序。
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// 规则条数。
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// 是否不含任何规则。
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// 出现过的来源标签，按字典序去重。
    pub fn sources(&self) -> BTreeSet<&str> {
        self.rules.iter().map(|rule| rule.source.as_str()).collect()
    }
}

/// 确定性排序：priority 降序，rule_id 升序。
///
/// rule_id 唯一，因此这个序是**全序**，不存在需要靠输入顺序打破的平局——这正是
/// 「同一批规则乱序后结果不变」的实现基础。
pub(crate) fn sort_rules(rules: &mut [Rule]) {
    rules.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.id.as_str().cmp(right.id.as_str()))
    });
}
