//! 内建默认策略、YAML 解析与多来源合并。
//!
//! # 规则文件是不可信输入
//!
//! 策略文件随 Workspace 同步到每台设备，因此一份规则文件的解析路径必须假设它由攻击者
//! 书写。这里的防线按代价从低到高排列：
//!
//! 1. **文本预检**（[`crate::MAX_POLICY_TEXT_LEN`]、[`crate::MAX_INPUT_NESTING`]）：在
//!    serde 反序列化之前完成的线性扫描，拒绝超长文本、超深嵌套，以及 YAML 锚点、别名、
//!    合并键和标签。锚点/别名是 billion-laughs 的载体，超深嵌套能让反序列化递归到栈溢出
//!    ——这两样都必须在**进入解析器之前**挡掉。
//! 2. **schema 校验**：`deny_unknown_fields` 拒绝未知字段，未知 `version` 拒绝，未知枚举
//!    取值拒绝。绝不静默忽略看不懂的东西。
//! 3. **语义校验**：重复规则标识拒绝，规则条数、AST 深度与节点数逐项设限。

use std::collections::{BTreeMap, BTreeSet};

use envsync_domain::{Os, Risk};
use serde::Deserialize;

use crate::ast::{
    sanitize_source, Decision, FactPredicate, MatchExpr, Operation, PolicySet, ResourceGlob,
    ResourceKind, Rule, RuleId,
};
use crate::{
    truncate_for_error, PolicyError, MAX_AST_DEPTH, MAX_INPUT_NESTING, MAX_PATTERN_LEN,
    MAX_POLICY_TEXT_LEN, MAX_RULES, POLICY_FORMAT_VERSION,
};

/// 内建规则的来源标签。
pub const BUILTIN_SOURCE: &str = "<builtin>";

/// 系统级包管理器适配器 ID 的公共前缀。
///
/// APT、DNF、Pacman、system scope 的 Chocolatey 等都注册在这个前缀下（M3 计划 Task 5）。
pub const BUILTIN_SYSTEM_PACKAGE_PREFIX: &str = "builtin.pkg.system.";

/// 内建规则：需要提权的操作一律拒绝。
pub const BUILTIN_ELEVATION_DENIED: &str = "builtin.elevation-required-denied";

/// 内建规则：系统级包管理器的写操作一律拒绝。
pub const BUILTIN_SYSTEM_PACKAGE_WRITE: &str = "builtin.system-package-write-denied";

/// 内建规则：未知 signer 的 Bundle 与插件一律拒绝。
pub const BUILTIN_UNSIGNED_ACTIVE_CONTENT: &str = "builtin.unsigned-active-content-denied";

/// 内建规则：启用 Agent Bundle 需要显式确认。
pub const BUILTIN_AGENT_BUNDLE_ENABLE: &str = "builtin.agent-bundle.enable-requires-confirmation";

/// 内建规则：高风险命令需要显式确认。
pub const BUILTIN_HIGH_RISK_COMMAND: &str = "builtin.command.high-risk-requires-confirmation";

/// 内建规则：卸载包需要显式确认。
pub const BUILTIN_PACKAGE_UNINSTALL: &str = "builtin.package.uninstall-requires-confirmation";

/// 内建规则：降级包需要显式确认。
pub const BUILTIN_PACKAGE_DOWNGRADE: &str = "builtin.package.downgrade-requires-confirmation";

impl PolicySet {
    /// 内建默认策略。
    ///
    /// 这七条规则是设计文档 §6 / §7 与 M3「完成定义」在策略层的直接落地，都是**显式规则**
    /// 而不是默认值——只有写成规则，它们才会出现在解释里，用户才知道自己被什么挡住了：
    ///
    /// | 规则 | 决策 |
    /// |---|---|
    /// | [`BUILTIN_ELEVATION_DENIED`]：`elevation_required == true` | `deny` |
    /// | [`BUILTIN_SYSTEM_PACKAGE_WRITE`]：适配器以 [`BUILTIN_SYSTEM_PACKAGE_PREFIX`] 开头的写操作 | `deny` |
    /// | [`BUILTIN_UNSIGNED_ACTIVE_CONTENT`]：没有 signer 的 Bundle / 插件 | `deny` |
    /// | [`BUILTIN_AGENT_BUNDLE_ENABLE`]：启用 Agent Bundle | `require_confirmation` |
    /// | [`BUILTIN_HIGH_RISK_COMMAND`]：`Risk::High` 的命令 | `require_confirmation` |
    /// | [`BUILTIN_PACKAGE_UNINSTALL`]：卸载包 | `require_confirmation` |
    /// | [`BUILTIN_PACKAGE_DOWNGRADE`]：降级包 | `require_confirmation` |
    ///
    /// # 怎么放宽一条内建 deny
    ///
    /// deny-first 意味着**加规则永远放宽不了 deny**：新加一条 `allow` 不会盖过既有的
    /// `deny`。唯一的放宽途径是用**同一个 rule_id** 重新声明这条规则，再通过
    /// [`PolicySet::merge`] 把用户策略集放在内建策略集之后——后来的同 ID 规则整条替换
    /// 先前的。例如把提权从 `deny` 放宽成 `require_confirmation`：
    ///
    /// ```
    /// use envsync_domain::{Os, Risk};
    /// use envsync_policy::{
    ///     Decision, Operation, PolicyFacts, PolicySet, ResourceKind, BUILTIN_ELEVATION_DENIED,
    /// };
    ///
    /// let user = PolicySet::parse_yaml(
    ///     &format!(
    ///         "version: 1\nrules:\n  - id: {BUILTIN_ELEVATION_DENIED}\n    \
    ///          decision: require_confirmation\n    match:\n      elevation_required: true\n"
    ///     ),
    ///     "user.yaml",
    /// )?;
    /// let merged = PolicySet::merge(vec![PolicySet::builtin_defaults(), user])?;
    ///
    /// let facts = PolicyFacts::new(ResourceKind::Package, Operation::Install, Risk::High, Os::Linux)
    ///     .with_elevation_required(true);
    /// assert_eq!(
    ///     merged.evaluate(&facts).decision,
    ///     Decision::RequireConfirmation
    /// );
    /// # Ok::<(), envsync_policy::PolicyError>(())
    /// ```
    ///
    /// 这条路径是刻意设计成「必须指名道姓」的：想绕开一条内建安全规则，就得在自己的
    /// 策略文件里写下它的标识，从而在 diff 和审计里留下痕迹。
    pub fn builtin_defaults() -> Self {
        let rules = vec![
            builtin_rule(
                BUILTIN_ELEVATION_DENIED,
                900,
                Decision::Deny,
                "提权操作必须走平台 elevation broker 并单独授权，不能由同步流程隐式触发",
                MatchExpr::Leaf(FactPredicate::ElevationRequired(true)),
            ),
            builtin_rule(
                BUILTIN_SYSTEM_PACKAGE_WRITE,
                800,
                Decision::Deny,
                "系统级包管理需要单独的提权流程，默认不由 EnvSync 收敛",
                MatchExpr::All(vec![
                    MatchExpr::Leaf(FactPredicate::AdapterPrefix(
                        BUILTIN_SYSTEM_PACKAGE_PREFIX.to_owned(),
                    )),
                    MatchExpr::Leaf(FactPredicate::Operation(Operation::write_operations())),
                ]),
            ),
            builtin_rule(
                BUILTIN_UNSIGNED_ACTIVE_CONTENT,
                800,
                Decision::Deny,
                "来源不明的主动内容不可信：没有发布者签名就无法判断 diff 与声明能力属于谁",
                MatchExpr::All(vec![
                    MatchExpr::Leaf(FactPredicate::ResourceKind(
                        [ResourceKind::AgentBundle, ResourceKind::Plugin]
                            .into_iter()
                            .collect(),
                    )),
                    MatchExpr::Leaf(FactPredicate::SignerPresent(false)),
                ]),
            ),
            builtin_rule(
                BUILTIN_AGENT_BUNDLE_ENABLE,
                500,
                Decision::RequireConfirmation,
                "启用 Agent Bundle 会让它的提示与工具权限立即生效，必须由用户看过来源、签名与声明能力后确认",
                MatchExpr::All(vec![
                    MatchExpr::Leaf(FactPredicate::ResourceKind(
                        [ResourceKind::AgentBundle].into_iter().collect(),
                    )),
                    MatchExpr::Leaf(FactPredicate::Operation(
                        [Operation::Enable].into_iter().collect(),
                    )),
                ]),
            ),
            builtin_rule(
                BUILTIN_HIGH_RISK_COMMAND,
                400,
                Decision::RequireConfirmation,
                "高风险命令的副作用不可由计划完全预测，必须逐条确认",
                MatchExpr::All(vec![
                    MatchExpr::Leaf(FactPredicate::ResourceKind(
                        [ResourceKind::Command].into_iter().collect(),
                    )),
                    MatchExpr::Leaf(FactPredicate::RiskAtLeast(Risk::High)),
                ]),
            ),
            builtin_rule(
                BUILTIN_PACKAGE_UNINSTALL,
                300,
                Decision::RequireConfirmation,
                "卸载不可由「远端缺失」推断，必须由显式 tombstone 加用户确认共同触发",
                MatchExpr::All(vec![
                    MatchExpr::Leaf(FactPredicate::ResourceKind(
                        [ResourceKind::Package].into_iter().collect(),
                    )),
                    MatchExpr::Leaf(FactPredicate::Operation(
                        [Operation::Uninstall].into_iter().collect(),
                    )),
                ]),
            ),
            builtin_rule(
                BUILTIN_PACKAGE_DOWNGRADE,
                300,
                Decision::RequireConfirmation,
                "降级可能重新引入已修复的漏洞，也常常不可逆，必须确认",
                MatchExpr::All(vec![
                    MatchExpr::Leaf(FactPredicate::ResourceKind(
                        [ResourceKind::Package].into_iter().collect(),
                    )),
                    MatchExpr::Leaf(FactPredicate::Operation(
                        [Operation::Downgrade].into_iter().collect(),
                    )),
                ]),
            ),
        ];
        // 规则全部是编译期常量：这里 unwrap 失败只可能是本文件写错了，测试会立刻发现。
        PolicySet::from_rules(rules).expect("内建默认策略必须自洽")
    }

    /// 解析一份 YAML 策略文件。
    ///
    /// `source` 是来源标签（通常是文件路径）；它会被 [`sanitize_source`] 收敛成不含目录的
    /// 文件名后写进每条规则，出现在解释里。
    ///
    /// # 格式
    ///
    /// ```yaml
    /// version: 1
    /// rules:
    ///   - id: deny-system-package-writes
    ///     priority: 100                  # 可选，默认 0；越大越靠前
    ///     decision: deny                 # allow | deny | require_confirmation
    ///     reason: "系统级包管理需要单独的提权流程"   # 可选
    ///     match:                         # 可选；省略或写空表示匹配一切
    ///       resource_kind: package       # 单值或列表：file/package/agent_bundle/command/plugin
    ///       adapter_prefix: "builtin.pkg.system."
    ///       operation: [install, upgrade, uninstall]
    /// ```
    ///
    /// `match` 里的字段两两之间是**与**关系；单个字段写成列表时，列表内部是**或**关系。
    /// 可用字段：`resource_kind`、`operation`、`os`、`adapter`、`adapter_prefix`、
    /// `risk_at_least`、`profile_tag`、`capability`、`declared_capability`、`signer`、
    /// `signer_present`、`resource`、`elevation_required`，以及三个组合子 `all`、`any`、
    /// `not`。`resource` 的通配只支持精确匹配与 `*` 尾缀。
    ///
    /// # 拒绝路径
    ///
    /// 未知字段、未知 `version`、未知枚举取值、重复 `id`、空列表、非法通配、YAML 锚点/
    /// 别名/合并键/标签、超长文本、超深嵌套、超限规则条数与 AST 深度/节点数，全部返回
    /// 错误而不是尽力而为地解析。
    pub fn parse_yaml(text: &str, source: &str) -> Result<Self, PolicyError> {
        let label = sanitize_source(source);
        precheck_text(text)?;

        let document: RawDocument =
            serde_yaml_ng::from_str(text).map_err(|error| PolicyError::Yaml {
                source_label: label.clone(),
                message: sanitize_parser_message(&error.to_string()),
            })?;

        if document.version != POLICY_FORMAT_VERSION {
            return Err(PolicyError::UnsupportedVersion {
                actual: document.version,
                expected: POLICY_FORMAT_VERSION,
            });
        }
        if document.rules.len() > MAX_RULES {
            return Err(PolicyError::TooManyRules {
                actual: document.rules.len(),
                limit: MAX_RULES,
            });
        }

        let mut rules = Vec::with_capacity(document.rules.len());
        for raw in document.rules {
            rules.push(lower_rule(raw, &label)?);
        }
        PolicySet::from_rules(rules)
    }

    /// 合并多个来源的策略集。
    ///
    /// # 合并语义
    ///
    /// * **同 rule_id 后来居上**：列表里靠后的策略集整条替换靠前的同 ID 规则。这是唯一
    ///   能放宽一条内建 `deny` 的途径（见 [`PolicySet::builtin_defaults`]），也让「哪条规则
    ///   最终生效」始终唯一。
    /// * **不同 rule_id 全部保留**，随后统一按 priority 降序、rule_id 升序排序。因此合并
    ///   结果与各来源内部的书写顺序无关，只与来源之间的先后有关（而先后正是覆盖语义所
    ///   需要的信息）。
    /// * 合并后的规则总数仍受 [`crate::MAX_RULES`] 约束。
    pub fn merge(sets: Vec<PolicySet>) -> Result<Self, PolicyError> {
        let mut by_id: BTreeMap<String, Rule> = BTreeMap::new();
        let mut overridden = 0usize;
        for set in sets {
            for rule in set.rules {
                let id = rule.id.as_str().to_owned();
                if by_id.insert(id, rule).is_some() {
                    overridden += 1;
                }
                if by_id.len() > MAX_RULES {
                    return Err(PolicyError::TooManyRules {
                        actual: by_id.len(),
                        limit: MAX_RULES,
                    });
                }
            }
        }
        if overridden > 0 {
            tracing::debug!(overridden, "合并策略集：同 ID 规则被后来的来源替换");
        }
        PolicySet::from_rules(by_id.into_values().collect())
    }
}

/// 构造一条内建规则。
fn builtin_rule(
    id: &str,
    priority: i32,
    decision: Decision,
    reason: &str,
    matcher: MatchExpr,
) -> Rule {
    Rule {
        id: RuleId::parse(id).expect("内建规则标识必须合法"),
        priority,
        decision,
        reason: reason.to_owned(),
        matcher,
        source: BUILTIN_SOURCE.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// 文本预检
// ---------------------------------------------------------------------------

/// 在进入 YAML 解析器之前完成的线性预检。
///
/// 它只做两件事：把文本规模与**输入嵌套**钉在安全常数内，以及拒绝锚点、别名、合并键
/// 与标签。两件事都必须发生在解析之前——解析器一旦开始递归，就没有机会再返回错误了。
fn precheck_text(text: &str) -> Result<(), PolicyError> {
    if text.len() > MAX_POLICY_TEXT_LEN {
        return Err(PolicyError::TextTooLarge {
            actual: text.len(),
            limit: MAX_POLICY_TEXT_LEN,
        });
    }
    for (index, line) in text.lines().enumerate() {
        let line_no = index + 1;
        let nesting = scan_line(line, line_no)?;
        if nesting > MAX_INPUT_NESTING {
            return Err(PolicyError::NestingTooDeep {
                line: line_no,
                actual: nesting,
                limit: MAX_INPUT_NESTING,
            });
        }
    }
    Ok(())
}

/// 扫描一行，返回它的有效嵌套深度；遇到不允许的 YAML 构造时返回错误。
///
/// 深度取「缩进列数 + 块序列标记 + 行内流式括号最大深度」，是一个**保守的高估**：
/// 宁可多算，也不能低估到让解析器递归超出预期。
fn scan_line(line: &str, line_no: usize) -> Result<usize, PolicyError> {
    let mut depth = 0usize;
    let mut rest = line;
    loop {
        let whitespace = rest.len() - rest.trim_start_matches([' ', '\t']).len();
        depth = depth.saturating_add(whitespace);
        rest = &rest[whitespace..];
        if rest == "-" || rest.starts_with("- ") || rest.starts_with("-\t") {
            depth = depth.saturating_add(2);
            rest = &rest[1..];
            continue;
        }
        break;
    }

    let mut flow = 0usize;
    let mut max_flow = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut at_node_start = true;
    let mut prev_was_space = true;

    for ch in rest.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_double {
            match ch {
                '\\' => escaped = true,
                '"' => in_double = false,
                _ => {}
            }
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            continue;
        }
        match ch {
            '#' if prev_was_space => break,
            '"' => {
                in_double = true;
                at_node_start = false;
            }
            '\'' => {
                in_single = true;
                at_node_start = false;
            }
            '[' | '{' => {
                flow = flow.saturating_add(1);
                max_flow = max_flow.max(flow);
                at_node_start = true;
            }
            ']' | '}' => {
                flow = flow.saturating_sub(1);
                at_node_start = false;
            }
            ',' | ':' => at_node_start = true,
            ' ' | '\t' => {}
            '&' | '*' | '!' if at_node_start => {
                return Err(PolicyError::UnsafeYamlConstruct {
                    line: line_no,
                    token: ch.to_string(),
                });
            }
            _ => at_node_start = false,
        }
        prev_was_space = matches!(ch, ' ' | '\t');
    }

    Ok(depth.saturating_add(max_flow))
}

/// 把解析器的错误信息收敛成可以安全印出的一行。
fn sanitize_parser_message(message: &str) -> String {
    const LIMIT: usize = 200;
    let cleaned: String = message
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    if cleaned.chars().count() <= LIMIT {
        return cleaned;
    }
    cleaned.chars().take(LIMIT).collect::<String>() + "…"
}

// ---------------------------------------------------------------------------
// YAML schema
// ---------------------------------------------------------------------------

/// 单值或列表。列表内部是「或」关系。
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    fn into_vec(self) -> Vec<T> {
        match self {
            OneOrMany::One(value) => vec![value],
            OneOrMany::Many(values) => values,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDocument {
    version: u32,
    #[serde(default)]
    rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    #[serde(default)]
    priority: i32,
    decision: Decision,
    #[serde(default)]
    reason: String,
    #[serde(default, rename = "match")]
    matcher: Option<RawMatch>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMatch {
    #[serde(default)]
    resource_kind: Option<OneOrMany<ResourceKind>>,
    #[serde(default)]
    operation: Option<OneOrMany<Operation>>,
    #[serde(default)]
    os: Option<OneOrMany<Os>>,
    #[serde(default)]
    adapter: Option<OneOrMany<String>>,
    #[serde(default)]
    adapter_prefix: Option<String>,
    #[serde(default)]
    risk_at_least: Option<Risk>,
    #[serde(default)]
    profile_tag: Option<OneOrMany<String>>,
    #[serde(default)]
    capability: Option<OneOrMany<String>>,
    #[serde(default)]
    declared_capability: Option<OneOrMany<String>>,
    #[serde(default)]
    signer: Option<OneOrMany<String>>,
    #[serde(default)]
    signer_present: Option<bool>,
    #[serde(default)]
    resource: Option<OneOrMany<String>>,
    #[serde(default)]
    elevation_required: Option<bool>,
    #[serde(default)]
    all: Option<Vec<RawMatch>>,
    #[serde(default)]
    any: Option<Vec<RawMatch>>,
    #[serde(default)]
    not: Option<Box<RawMatch>>,
}

/// 把一条原始规则降解成 AST 规则。
fn lower_rule(raw: RawRule, source_label: &str) -> Result<Rule, PolicyError> {
    let id = RuleId::parse(&raw.id)?;
    let matcher = match raw.matcher {
        Some(raw_match) => lower_match(raw_match, id.as_str(), source_label, MAX_AST_DEPTH)?,
        None => MatchExpr::any_facts(),
    };
    let rule = Rule {
        id,
        priority: raw.priority,
        decision: raw.decision,
        reason: raw.reason,
        matcher,
        source: source_label.to_owned(),
    };
    rule.validate()?;
    Ok(rule)
}

/// 把一个 `match` 块降解成匹配表达式。
///
/// `budget` 是递归预算：输入嵌套已经被 [`precheck_text`] 限死，这里再加一道，保证这个
/// 函数在任何输入下都是**全函数**（要么返回表达式，要么返回错误，不会栈溢出）。
fn lower_match(
    raw: RawMatch,
    rule_id: &str,
    source_label: &str,
    budget: usize,
) -> Result<MatchExpr, PolicyError> {
    if budget == 0 {
        return Err(PolicyError::AstTooDeep {
            rule: truncate_for_error(rule_id),
            actual: MAX_AST_DEPTH + 1,
            limit: MAX_AST_DEPTH,
        });
    }

    let mut conjuncts: Vec<MatchExpr> = Vec::new();

    if let Some(values) = raw.resource_kind {
        let set = non_empty_set(values.into_vec(), "match.resource_kind", source_label)?;
        conjuncts.push(MatchExpr::Leaf(FactPredicate::ResourceKind(set)));
    }
    if let Some(values) = raw.operation {
        let set = non_empty_set(values.into_vec(), "match.operation", source_label)?;
        conjuncts.push(MatchExpr::Leaf(FactPredicate::Operation(set)));
    }
    if let Some(values) = raw.os {
        let set = non_empty_set(values.into_vec(), "match.os", source_label)?;
        conjuncts.push(MatchExpr::Leaf(FactPredicate::Os(set)));
    }
    if let Some(values) = raw.adapter {
        let set = literal_set(values.into_vec(), "match.adapter", source_label)?;
        conjuncts.push(MatchExpr::Leaf(FactPredicate::Adapter(set)));
    }
    if let Some(prefix) = raw.adapter_prefix {
        check_literal(&prefix)?;
        conjuncts.push(MatchExpr::Leaf(FactPredicate::AdapterPrefix(prefix)));
    }
    if let Some(risk) = raw.risk_at_least {
        conjuncts.push(MatchExpr::Leaf(FactPredicate::RiskAtLeast(risk)));
    }
    if let Some(values) = raw.profile_tag {
        let set = literal_set(values.into_vec(), "match.profile_tag", source_label)?;
        conjuncts.push(MatchExpr::Leaf(FactPredicate::ProfileTag(set)));
    }
    if let Some(values) = raw.capability {
        let set = literal_set(values.into_vec(), "match.capability", source_label)?;
        conjuncts.push(MatchExpr::Leaf(FactPredicate::Capability(set)));
    }
    if let Some(values) = raw.declared_capability {
        let set = literal_set(values.into_vec(), "match.declared_capability", source_label)?;
        conjuncts.push(MatchExpr::Leaf(FactPredicate::DeclaredCapability(set)));
    }
    if let Some(values) = raw.signer {
        let set = literal_set(values.into_vec(), "match.signer", source_label)?;
        conjuncts.push(MatchExpr::Leaf(FactPredicate::Signer(set)));
    }
    if let Some(expected) = raw.signer_present {
        conjuncts.push(MatchExpr::Leaf(FactPredicate::SignerPresent(expected)));
    }
    if let Some(values) = raw.resource {
        let patterns = values.into_vec();
        if patterns.is_empty() {
            return Err(empty_list_error("match.resource", source_label));
        }
        let mut globs = BTreeSet::new();
        for pattern in patterns {
            globs.insert(ResourceGlob::parse(&pattern)?);
        }
        conjuncts.push(MatchExpr::Leaf(FactPredicate::Resource(globs)));
    }
    if let Some(expected) = raw.elevation_required {
        conjuncts.push(MatchExpr::Leaf(FactPredicate::ElevationRequired(expected)));
    }

    if let Some(children) = raw.all {
        conjuncts.push(MatchExpr::All(lower_children(
            children,
            rule_id,
            source_label,
            budget - 1,
        )?));
    }
    if let Some(children) = raw.any {
        if children.is_empty() {
            return Err(empty_list_error("match.any", source_label));
        }
        conjuncts.push(MatchExpr::Any(lower_children(
            children,
            rule_id,
            source_label,
            budget - 1,
        )?));
    }
    if let Some(inner) = raw.not {
        conjuncts.push(MatchExpr::Not(Box::new(lower_match(
            *inner,
            rule_id,
            source_label,
            budget - 1,
        )?)));
    }

    // 只有一个条件时不再包一层 `All`：让 AST 深度直接对应用户写下的嵌套。
    Ok(if conjuncts.len() == 1 {
        conjuncts.remove(0)
    } else {
        MatchExpr::All(conjuncts)
    })
}

fn lower_children(
    children: Vec<RawMatch>,
    rule_id: &str,
    source_label: &str,
    budget: usize,
) -> Result<Vec<MatchExpr>, PolicyError> {
    let mut out = Vec::with_capacity(children.len());
    for child in children {
        out.push(lower_match(child, rule_id, source_label, budget)?);
    }
    Ok(out)
}

/// 把枚举列表收成非空集合。
fn non_empty_set<T: Ord>(
    values: Vec<T>,
    field: &str,
    source_label: &str,
) -> Result<BTreeSet<T>, PolicyError> {
    if values.is_empty() {
        return Err(empty_list_error(field, source_label));
    }
    Ok(values.into_iter().collect())
}

/// 把字面量列表收成非空集合，并逐个校验字符集与长度。
fn literal_set(
    values: Vec<String>,
    field: &str,
    source_label: &str,
) -> Result<BTreeSet<String>, PolicyError> {
    if values.is_empty() {
        return Err(empty_list_error(field, source_label));
    }
    let mut out = BTreeSet::new();
    for value in values {
        check_literal(&value)?;
        out.insert(value);
    }
    Ok(out)
}

/// 字面量取值：非空、不超长、无控制字符。
fn check_literal(value: &str) -> Result<(), PolicyError> {
    if value.is_empty() {
        return Err(PolicyError::InvalidPattern {
            pattern: String::new(),
            reason: "不能为空",
        });
    }
    if value.len() > MAX_PATTERN_LEN {
        return Err(PolicyError::InvalidPattern {
            pattern: truncate_for_error(value),
            reason: "超过长度上限",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(PolicyError::InvalidPattern {
            pattern: truncate_for_error(value),
            reason: "不能包含控制字符",
        });
    }
    Ok(())
}

/// 空列表是「永不命中」的静默陷阱，必须拒绝。
fn empty_list_error(field: &str, source_label: &str) -> PolicyError {
    PolicyError::Yaml {
        source_label: source_label.to_owned(),
        message: format!("`{field}` 不能是空列表（空列表永不命中，属于静默失效）"),
    }
}
