//! 输入事实与 deny-first 求值。
//!
//! [`PolicyFacts`] 是引擎唯一的输入：它的字段全部是**已经发生的观察**（借用形式的只读
//! 快照），没有任何可变引用，也没有回调。引擎因此不可能在判定过程中改变世界，判定也
//! 因此可以被完整重放和审计。

use std::collections::BTreeSet;
use std::sync::OnceLock;

use envsync_domain::{DeviceProfile, Os, ResourceId, Risk};
use serde::Serialize;

use crate::ast::{Decision, FactPredicate, MatchExpr, Operation, PolicySet, ResourceKind, Rule};
use crate::MAX_AST_DEPTH;

/// 一个可以被借用的空字符串集合，供 [`PolicyFacts::new`] 使用。
fn empty_string_set() -> &'static BTreeSet<String> {
    static EMPTY: OnceLock<BTreeSet<String>> = OnceLock::new();
    EMPTY.get_or_init(BTreeSet::new)
}

/// 被判定的事实。
///
/// 字段全部是**已经发生的观察**，不含任何可变引用：调用方先观察世界，再把观察结果摆到
/// 台面上让引擎判定。引擎不读时钟、不读磁盘、不发网络请求，因此相同事实必然得到相同
/// 决策（确定性）。
///
/// # 秘密
///
/// [`PolicyFacts::secret_refs`] 只允许放 SecretRef 的 **opaque 逻辑标识**（例如
/// `github/token`），绝不放明文。设计文档 §7 要求 Bundle「不得内嵌明文 Token，只能引用
/// Vault 中的逻辑 Secret ID」；这里是同一条约束在策略层的体现。解释渲染还会再做一次
/// 字符集过滤作为兜底，见 [`crate::explain`]。
#[derive(Debug, Clone, Copy)]
pub struct PolicyFacts<'a> {
    /// 被判定对象的种类。
    pub resource_kind: ResourceKind,
    /// 适配器稳定 ID，例如 `builtin.pkg.brew`；与适配器无关的判定为 `None`。
    pub adapter: Option<&'a str>,
    /// 被判定的操作。
    pub operation: Operation,
    /// 操作风险，复用 [`envsync_domain::Risk`]。
    pub risk: Risk,
    /// 本机操作系统。
    pub os: Os,
    /// 设备 Profile 标签。
    pub profile_tags: &'a BTreeSet<String>,
    /// 设备**实际**可用的能力。
    pub capabilities: &'a BTreeSet<String>,
    /// 相关资源标识；与具体资源无关的判定为 `None`。
    pub resource: Option<&'a ResourceId>,
    /// Bundle / 插件发布者的公钥指纹；未签名或来源不明时为 `None`。
    pub source_signer: Option<&'a str>,
    /// Bundle 在 manifest 里**声明**的能力。
    ///
    /// 与 [`PolicyFacts::capabilities`] 的区别是信任来源：后者是本机事实，前者是被判定
    /// 内容的自述，正因为是自述才需要过策略。
    pub declared_capabilities: &'a BTreeSet<String>,
    /// 该操作是否需要提权。
    pub elevation_required: bool,
    /// 涉及的 SecretRef opaque 标识；**只有标识，没有值**。
    pub secret_refs: &'a [String],
}

impl PolicyFacts<'static> {
    /// 构造只含必填维度的事实：无适配器、无资源、无 signer、不提权、无秘密引用，
    /// 标签与能力集合都为空。
    ///
    /// 其余维度用 `with_*` 链式补齐。
    pub fn new(resource_kind: ResourceKind, operation: Operation, risk: Risk, os: Os) -> Self {
        PolicyFacts {
            resource_kind,
            adapter: None,
            operation,
            risk,
            os,
            profile_tags: empty_string_set(),
            capabilities: empty_string_set(),
            resource: None,
            source_signer: None,
            declared_capabilities: empty_string_set(),
            elevation_required: false,
            secret_refs: &[],
        }
    }
}

impl<'a> PolicyFacts<'a> {
    /// 用设备 Profile 填充 `os`、`profile_tags` 与 `capabilities`。
    ///
    /// 复用 [`envsync_domain::DeviceProfile`]：策略层不重新定义设备属性，只借用。
    pub fn with_profile(mut self, profile: &'a DeviceProfile) -> Self {
        self.os = profile.os;
        self.profile_tags = &profile.tags;
        self.capabilities = &profile.capabilities;
        self
    }

    /// 设置适配器稳定 ID。
    pub fn with_adapter(mut self, adapter: &'a str) -> Self {
        self.adapter = Some(adapter);
        self
    }

    /// 设置设备 Profile 标签集合。
    pub fn with_profile_tags(mut self, tags: &'a BTreeSet<String>) -> Self {
        self.profile_tags = tags;
        self
    }

    /// 设置设备能力集合。
    pub fn with_capabilities(mut self, capabilities: &'a BTreeSet<String>) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// 设置相关资源标识。
    pub fn with_resource(mut self, resource: &'a ResourceId) -> Self {
        self.resource = Some(resource);
        self
    }

    /// 设置发布者签名指纹。
    pub fn with_signer(mut self, signer: &'a str) -> Self {
        self.source_signer = Some(signer);
        self
    }

    /// 设置 Bundle 声明的能力集合。
    pub fn with_declared_capabilities(mut self, declared: &'a BTreeSet<String>) -> Self {
        self.declared_capabilities = declared;
        self
    }

    /// 设置是否需要提权。
    pub fn with_elevation_required(mut self, required: bool) -> Self {
        self.elevation_required = required;
        self
    }

    /// 设置 SecretRef opaque 标识列表。
    ///
    /// 传入的必须是标识，不是值——引擎不会、也无法检测明文，只能在渲染时做字符集兜底。
    pub fn with_secret_refs(mut self, secret_refs: &'a [String]) -> Self {
        self.secret_refs = secret_refs;
        self
    }
}

/// 一条被命中的规则在决策里的留痕。
///
/// 它是 [`Rule`] 的**快照拷贝**而不是借用：决策结果要能脱离策略集独立进日志、进 journal、
/// 进 `--json` 输出。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MatchedRule {
    /// 规则标识。
    pub rule_id: String,
    /// 规则来源文件（不含目录）。
    pub source: String,
    /// 规则显式优先级。
    pub priority: i32,
    /// 该规则给出的决策。
    pub decision: Decision,
    /// 该规则的人类可读理由。
    pub reason: String,
}

impl MatchedRule {
    fn from_rule(rule: &Rule) -> Self {
        MatchedRule {
            rule_id: rule.id.as_str().to_owned(),
            source: rule.source.clone(),
            priority: rule.priority,
            decision: rule.decision,
            reason: rule.reason.clone(),
        }
    }
}

/// 一次判定的完整结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionOutcome {
    /// 最终决策。
    pub decision: Decision,
    /// 命中的规则，按 priority 降序、rule_id 升序排列（与策略集内的求值顺序一致）。
    pub matched: Vec<MatchedRule>,
    /// 输入事实的摘要，用于审计。只覆盖事实的结构与 opaque 标识，**不含秘密值**。
    pub facts_digest: String,
    /// 人类可读解释。
    pub explanation: String,
}

impl DecisionOutcome {
    /// 是否可以不经确认直接继续。
    pub fn is_allowed(&self) -> bool {
        self.decision == Decision::Allow
    }

    /// 是否为「没有任何规则命中，落到资源种类默认值」。
    pub fn is_default(&self) -> bool {
        self.matched.is_empty()
    }

    /// 命中规则的标识列表，按命中顺序。
    pub fn matched_rule_ids(&self) -> Vec<&str> {
        self.matched
            .iter()
            .map(|matched| matched.rule_id.as_str())
            .collect()
    }
}

impl FactPredicate {
    /// 该谓词是否命中给定事实。
    ///
    /// 所有分支都是集合查找、相等比较或前缀比较，没有回溯、没有分配、没有 I/O。
    pub fn matches(&self, facts: &PolicyFacts<'_>) -> bool {
        match self {
            FactPredicate::ResourceKind(kinds) => kinds.contains(&facts.resource_kind),
            FactPredicate::Operation(operations) => operations.contains(&facts.operation),
            FactPredicate::Os(systems) => systems.contains(&facts.os),
            FactPredicate::Adapter(adapters) => {
                facts.adapter.is_some_and(|value| adapters.contains(value))
            }
            FactPredicate::AdapterPrefix(prefix) => facts
                .adapter
                .is_some_and(|value| value.starts_with(prefix.as_str())),
            // `>=` 比较直接复用 `Risk` 自身的序：Low < Medium < High。
            FactPredicate::RiskAtLeast(threshold) => facts.risk >= *threshold,
            FactPredicate::ProfileTag(tags) => intersects(tags, facts.profile_tags),
            FactPredicate::Capability(capabilities) => intersects(capabilities, facts.capabilities),
            FactPredicate::DeclaredCapability(capabilities) => {
                intersects(capabilities, facts.declared_capabilities)
            }
            FactPredicate::Signer(signers) => facts
                .source_signer
                .is_some_and(|value| signers.contains(value)),
            FactPredicate::SignerPresent(expected) => facts.source_signer.is_some() == *expected,
            FactPredicate::Resource(globs) => facts
                .resource
                .is_some_and(|resource| globs.iter().any(|glob| glob.matches(resource.as_str()))),
            FactPredicate::ElevationRequired(expected) => facts.elevation_required == *expected,
        }
    }
}

/// 两个有序集合是否有交集。
///
/// 遍历较小的一侧，在较大的一侧查找：规则里写的集合通常很小，事实里的能力集合可能很大。
fn intersects(left: &BTreeSet<String>, right: &BTreeSet<String>) -> bool {
    let (small, large) = if left.len() <= right.len() {
        (left, right)
    } else {
        (right, left)
    };
    small.iter().any(|value| large.contains(value))
}

impl MatchExpr {
    /// 该表达式是否命中给定事实。
    ///
    /// 求值带一份硬预算（[`crate::MAX_AST_DEPTH`]）。正常路径上预算永远用不完，因为
    /// [`MatchExpr::validate`] 已经在构造阶段拒绝了更深的树；预算存在只是为了让「有人
    /// 绕过校验直接构造超深树」这条路径也保持**不 panic、不栈溢出**：预算耗尽时整个
    /// 表达式保守地判为不命中，而不是编造一个布尔值。
    pub fn matches(&self, facts: &PolicyFacts<'_>) -> bool {
        self.eval(facts, MAX_AST_DEPTH).unwrap_or(false)
    }

    /// `None` 表示预算耗尽。它会一路向上传播，因此 `Not` 不会把「无法判定」反转成
    /// 「命中」——这是保守方向的关键。
    fn eval(&self, facts: &PolicyFacts<'_>, budget: usize) -> Option<bool> {
        if budget == 0 {
            return None;
        }
        let next = budget - 1;
        Some(match self {
            MatchExpr::Leaf(predicate) => predicate.matches(facts),
            MatchExpr::All(children) => {
                let mut result = true;
                for child in children {
                    if !child.eval(facts, next)? {
                        result = false;
                        break;
                    }
                }
                result
            }
            MatchExpr::Any(children) => {
                let mut result = false;
                for child in children {
                    if child.eval(facts, next)? {
                        result = true;
                        break;
                    }
                }
                result
            }
            MatchExpr::Not(inner) => !inner.eval(facts, next)?,
        })
    }
}

impl PolicySet {
    /// 判定一组事实。
    ///
    /// # 语义
    ///
    /// 1. 按存放顺序（priority 降序、rule_id 升序）扫描全部规则，收集命中的规则；
    /// 2. **deny-first**：只要命中集合里存在 [`Decision::Deny`]，结果就是 `Deny`，
    ///    与 priority、书写顺序、其他规则都无关；
    /// 3. 否则只要存在 [`Decision::RequireConfirmation`]，结果就是 `RequireConfirmation`；
    /// 4. 否则（只有 `Allow` 命中）结果是 [`Decision::Allow`]；
    /// 5. 一条都没命中时，结果是 [`ResourceKind::default_decision`]。
    ///
    /// 第 2~4 步就是「取命中集合里最严厉的决策」，[`Decision`] 的序正是为此定义的。
    ///
    /// 该方法不会失败、不会 panic：任意事实、任意规则集都返回一个决策。
    pub fn evaluate(&self, facts: &PolicyFacts<'_>) -> DecisionOutcome {
        let matched: Vec<MatchedRule> = self
            .rules
            .iter()
            .filter(|rule| rule.matcher.matches(facts))
            .map(MatchedRule::from_rule)
            .collect();
        let decision = decide(facts.resource_kind, &matched);
        let facts_digest = crate::explain::facts_digest(facts);
        let explanation =
            crate::explain::render(self, facts, decision, &matched, &facts_digest, false);

        tracing::debug!(
            decision = decision.as_str(),
            resource_kind = facts.resource_kind.as_str(),
            operation = facts.operation.as_str(),
            matched_rules = matched.len(),
            facts_digest = %facts_digest,
            "策略判定完成"
        );

        DecisionOutcome {
            decision,
            matched,
            facts_digest,
            explanation,
        }
    }
}

/// 从命中集合推出最终决策。
pub(crate) fn decide(kind: ResourceKind, matched: &[MatchedRule]) -> Decision {
    matched
        .iter()
        .map(|rule| rule.decision)
        .max()
        .unwrap_or_else(|| kind.default_decision())
}
