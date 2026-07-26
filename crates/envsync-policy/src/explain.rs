//! 事实摘要与人类可读解释。
//!
//! 一个不能解释自己的安全决策等于没有决策：用户无法判断该不该覆盖它，审计也无法回答
//! 「当初为什么放行」。因此每次判定都回答四个问题——命中了哪些规则、规则来自哪个文件、
//! 优先级多少、输入事实是什么。
//!
//! # 秘密永远只以 opaque 标识出现
//!
//! [`crate::PolicyFacts`] 结构上就只有 SecretRef 的标识，没有值，所以解释里**不可能**
//! 出现明文。即便如此，[`summarize_facts`] 仍对每个标识做一次字符集与长度检查：万一
//! 上游哪天把值误塞进 `secret_refs`，渲染出来的也是占位符而不是那个值。这是纵深防御，
//! 不是主防线。
//!
//! [`facts_digest`] 走的是另一条路：它对**原始输入**做域分隔 BLAKE3。摘要是单向的，
//! 因此即使输入被污染，摘要也不会泄漏内容，同时仍能回答「两次判定的输入是否相同」。

use std::collections::BTreeSet;
use std::fmt::Write as _;

use envsync_domain::Digest32;

use crate::ast::{Decision, PolicySet};
use crate::evaluate::{MatchedRule, PolicyFacts};
use crate::{MAX_EXPLAIN_TRACE_RULES, MAX_SECRET_REF_LEN};

/// 事实摘要使用的哈希域分隔标签。
const FACTS_DIGEST_DOMAIN: &str = "envsync:policy:facts:v1";

/// 计算输入事实的审计摘要（64 位小写十六进制）。
///
/// 摘要覆盖 [`crate::PolicyFacts`] 的**全部**字段，采用长度前缀编码，因此不同事实不会
/// 因为拼接歧义碰撞（`adapter="a", signer="b"` 与 `adapter="ab", signer=""` 摘要不同）。
/// 集合字段本身有序，`secret_refs` 在摘要前排序去重，所以摘要与调用方的书写顺序无关。
///
/// 摘要是单向的：它能证明「这次判定的输入和上次一样」，但不能反推出输入内容，因此可以
/// 安全地写进 journal 与日志。
pub fn facts_digest(facts: &PolicyFacts<'_>) -> String {
    let mut buffer = String::new();
    push_field(&mut buffer, "kind", facts.resource_kind.as_str());
    push_field(&mut buffer, "operation", facts.operation.as_str());
    push_field(&mut buffer, "risk", risk_str(facts.risk));
    push_field(&mut buffer, "os", facts.os.as_str());
    push_field(&mut buffer, "adapter", facts.adapter.unwrap_or(""));
    push_field(
        &mut buffer,
        "adapter_present",
        bool_str(facts.adapter.is_some()),
    );
    push_field(
        &mut buffer,
        "resource",
        facts.resource.map(|id| id.as_str()).unwrap_or(""),
    );
    push_field(&mut buffer, "signer", facts.source_signer.unwrap_or(""));
    push_field(
        &mut buffer,
        "signer_present",
        bool_str(facts.source_signer.is_some()),
    );
    push_field(
        &mut buffer,
        "elevation_required",
        bool_str(facts.elevation_required),
    );
    push_field(
        &mut buffer,
        "profile_tags",
        &encode_sequence(facts.profile_tags.iter().map(String::as_str)),
    );
    push_field(
        &mut buffer,
        "capabilities",
        &encode_sequence(facts.capabilities.iter().map(String::as_str)),
    );
    push_field(
        &mut buffer,
        "declared_capabilities",
        &encode_sequence(facts.declared_capabilities.iter().map(String::as_str)),
    );
    let secrets: BTreeSet<&str> = facts.secret_refs.iter().map(String::as_str).collect();
    push_field(
        &mut buffer,
        "secret_refs",
        &encode_sequence(secrets.into_iter()),
    );

    Digest32::domain_hash(FACTS_DIGEST_DOMAIN, buffer.as_bytes()).to_hex()
}

/// 把事实渲染成一行人类可读摘要。
///
/// SecretRef 只显示 opaque 标识；不符合 opaque 标识形态的取值显示为
/// `<non-opaque-secret-ref>` 占位符并记一条 `warn` 日志。
pub fn summarize_facts(facts: &PolicyFacts<'_>) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "kind={} operation={} risk={} os={}",
        facts.resource_kind.as_str(),
        facts.operation.as_str(),
        risk_str(facts.risk),
        facts.os.as_str()
    );
    let _ = write!(out, " adapter={}", optional(facts.adapter));
    let _ = write!(
        out,
        " resource={}",
        optional(facts.resource.map(|id| id.as_str()))
    );
    let _ = write!(out, " signer={}", optional(facts.source_signer));
    let _ = write!(
        out,
        " elevation_required={}",
        bool_str(facts.elevation_required)
    );
    let _ = write!(
        out,
        " profile_tags={}",
        render_list(facts.profile_tags.iter().map(|tag| display_value(tag)))
    );
    let _ = write!(
        out,
        " capabilities={}",
        render_list(facts.capabilities.iter().map(|cap| display_value(cap)))
    );
    let _ = write!(
        out,
        " declared_capabilities={}",
        render_list(
            facts
                .declared_capabilities
                .iter()
                .map(|cap| display_value(cap))
        )
    );
    let secrets: BTreeSet<String> = facts
        .secret_refs
        .iter()
        .map(|value| sanitize_secret_ref(value))
        .collect();
    let _ = write!(out, " secret_refs={}", render_list(secrets.into_iter()));
    out
}

impl PolicySet {
    /// 渲染**完整判定过程**。
    ///
    /// 相比 [`crate::DecisionOutcome::explanation`]，这里额外给出规则集规模、来源清单，
    /// 以及逐条规则「命中/未命中」的轨迹。轨迹最多列出
    /// [`crate::MAX_EXPLAIN_TRACE_RULES`] 条，超出部分只给汇总计数——一份上限 10,000 条的
    /// 规则集不应该把终端刷屏。
    ///
    /// 该方法不会失败、不会 panic。
    pub fn explain(&self, facts: &PolicyFacts<'_>) -> String {
        let matched: Vec<MatchedRule> = self
            .rules
            .iter()
            .filter(|rule| rule.matcher.matches(facts))
            .map(|rule| MatchedRule {
                rule_id: rule.id.as_str().to_owned(),
                source: rule.source.clone(),
                priority: rule.priority,
                decision: rule.decision,
                reason: rule.reason.clone(),
            })
            .collect();
        let decision = crate::evaluate::decide(facts.resource_kind, &matched);
        let digest = facts_digest(facts);
        render(self, facts, decision, &matched, &digest, true)
    }
}

/// 渲染解释文本。`verbose` 为真时附加逐条规则轨迹。
pub(crate) fn render(
    set: &PolicySet,
    facts: &PolicyFacts<'_>,
    decision: Decision,
    matched: &[MatchedRule],
    digest: &str,
    verbose: bool,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "决策：{}", decision.as_str());
    let _ = writeln!(out, "事实摘要：{digest}");
    let _ = writeln!(out, "事实：{}", summarize_facts(facts));

    if matched.is_empty() {
        let _ = writeln!(out, "命中规则：无");
    } else {
        let _ = writeln!(
            out,
            "命中规则（priority 降序、rule_id 升序，共 {} 条）：",
            matched.len()
        );
        for (index, rule) in matched.iter().enumerate() {
            let _ = writeln!(
                out,
                "  {}. [{}] {}（priority={}，来源 {}）{}",
                index + 1,
                rule.decision.as_str(),
                rule.rule_id,
                rule.priority,
                rule.source,
                reason_suffix(&rule.reason)
            );
        }
    }

    let _ = writeln!(out, "判定依据：{}", derivation(facts, decision, matched));

    if verbose {
        let _ = writeln!(
            out,
            "规则集：共 {} 条规则，来源 {}",
            set.rule_count(),
            render_list(set.sources().into_iter().map(display_value))
        );
        let _ = writeln!(out, "逐条判定：");
        if set.is_empty() {
            let _ = writeln!(out, "  （规则集为空）");
        }
        let matched_ids: BTreeSet<&str> =
            matched.iter().map(|rule| rule.rule_id.as_str()).collect();
        for rule in set.rules().iter().take(MAX_EXPLAIN_TRACE_RULES) {
            let hit = matched_ids.contains(rule.id.as_str());
            let _ = writeln!(
                out,
                "  [{}] {}（priority={}，decision={}，来源 {}）",
                if hit { "命中" } else { "跳过" },
                rule.id,
                rule.priority,
                rule.decision.as_str(),
                rule.source
            );
        }
        if set.rule_count() > MAX_EXPLAIN_TRACE_RULES {
            let _ = writeln!(
                out,
                "  …另有 {} 条规则未逐条列出",
                set.rule_count() - MAX_EXPLAIN_TRACE_RULES
            );
        }
    }

    out
}

/// 说明最终决策是怎么来的。
fn derivation(facts: &PolicyFacts<'_>, decision: Decision, matched: &[MatchedRule]) -> String {
    if matched.is_empty() {
        return format!(
            "没有任何规则命中，按资源种类 `{}` 的默认决策 {}",
            facts.resource_kind.as_str(),
            decision.as_str()
        );
    }
    match decision {
        Decision::Deny => {
            let first = first_with(matched, Decision::Deny);
            format!(
                "deny-first —— 命中的 deny 规则 `{first}` 压过其余全部规则，与 priority 和书写顺序无关"
            )
        }
        Decision::RequireConfirmation => {
            let first = first_with(matched, Decision::RequireConfirmation);
            format!(
                "没有命中任何 deny 规则；命中的 require_confirmation 规则 `{first}` 要求用户显式确认"
            )
        }
        Decision::Allow => {
            "全部命中规则均为 allow，且没有命中任何 deny 或 require_confirmation 规则".to_owned()
        }
    }
}

/// 命中列表里第一条给出指定决策的规则标识。
fn first_with(matched: &[MatchedRule], decision: Decision) -> &str {
    matched
        .iter()
        .find(|rule| rule.decision == decision)
        .map(|rule| rule.rule_id.as_str())
        .unwrap_or("<未知>")
}

fn reason_suffix(reason: &str) -> String {
    if reason.trim().is_empty() {
        String::new()
    } else {
        format!("理由：{}", display_value(reason))
    }
}

/// SecretRef opaque 标识允许的字符。
fn is_opaque_secret_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | '/' | ':')
}

/// 把 SecretRef 收敛成「一定安全可印」的形态。
fn sanitize_secret_ref(value: &str) -> String {
    let opaque = !value.is_empty()
        && value.len() <= MAX_SECRET_REF_LEN
        && value.chars().all(is_opaque_secret_char);
    if opaque {
        return value.to_owned();
    }
    // 不记录取值本身：它有可能就是被误传进来的明文。
    tracing::warn!(
        length = value.len(),
        "secret_refs 里出现不符合 opaque 标识形态的取值，解释中已替换为占位符"
    );
    "<non-opaque-secret-ref>".to_owned()
}

/// 抹掉控制字符并截断，避免用输入伪造终端/日志行。
fn display_value(value: &str) -> String {
    const LIMIT: usize = 120;
    let cleaned: String = value
        .chars()
        .map(|ch| if ch.is_control() { '\u{fffd}' } else { ch })
        .collect();
    if cleaned.chars().count() <= LIMIT {
        return cleaned;
    }
    let head: String = cleaned.chars().take(LIMIT).collect();
    format!("{head}…")
}

fn optional(value: Option<&str>) -> String {
    match value {
        Some(text) => display_value(text),
        None => "<无>".to_owned(),
    }
}

fn render_list(values: impl Iterator<Item = String>) -> String {
    let joined: Vec<String> = values.collect();
    format!("[{}]", joined.join(","))
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn risk_str(risk: envsync_domain::Risk) -> &'static str {
    match risk {
        envsync_domain::Risk::Low => "low",
        envsync_domain::Risk::Medium => "medium",
        envsync_domain::Risk::High => "high",
    }
}

/// 长度前缀编码单个字段，杜绝拼接歧义。
fn push_field(buffer: &mut String, key: &str, value: &str) {
    let _ = write!(buffer, "{key}={}:{value};", value.len());
}

/// 长度前缀编码一个序列。
fn encode_sequence<'a>(values: impl Iterator<Item = &'a str>) -> String {
    let mut out = String::new();
    for value in values {
        let _ = write!(out, "{}:{value},", value.len());
    }
    out
}
