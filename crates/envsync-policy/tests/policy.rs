//! `envsync-policy` 的验收测试。
//!
//! 组织顺序与 M3 计划 Task 7 的语义清单一一对应：deny-first、默认值分域、
//! RequireConfirmation 的中间态、九个匹配维度、AST 封闭性、资源限制、可解释性、
//! 确定性、不 panic，随后是内建默认策略逐条用例与 YAML 的全部拒绝路径。

use std::collections::BTreeSet;

use envsync_domain::{Arch, DeviceProfile, Os, ResourceId, Risk};
use envsync_policy::{
    facts_digest, Decision, FactPredicate, MatchExpr, Operation, PolicyError, PolicyFacts,
    PolicySet, ResourceGlob, ResourceKind, Rule, RuleId, BUILTIN_AGENT_BUNDLE_ENABLE,
    BUILTIN_ELEVATION_DENIED, BUILTIN_HIGH_RISK_COMMAND, BUILTIN_PACKAGE_DOWNGRADE,
    BUILTIN_PACKAGE_UNINSTALL, BUILTIN_SOURCE, BUILTIN_SYSTEM_PACKAGE_WRITE,
    BUILTIN_UNSIGNED_ACTIVE_CONTENT, MAX_AST_DEPTH, MAX_RULES,
};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// 测试辅助
// ---------------------------------------------------------------------------

fn rule(id: &str, decision: Decision, matcher: MatchExpr) -> Rule {
    Rule::new(
        RuleId::parse(id).expect("测试规则标识必须合法"),
        decision,
        matcher,
    )
}

fn set_of(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|value| (*value).to_owned()).collect()
}

fn parse(text: &str) -> PolicySet {
    PolicySet::parse_yaml(text, "/etc/envsync/policy.yaml").expect("测试策略必须能解析")
}

fn package_facts() -> PolicyFacts<'static> {
    PolicyFacts::new(
        ResourceKind::Package,
        Operation::Install,
        Risk::Medium,
        Os::Linux,
    )
}

// ---------------------------------------------------------------------------
// 语义 1：deny-first
// ---------------------------------------------------------------------------

#[test]
fn deny_beats_allow_and_confirmation_regardless_of_priority() {
    // allow 的优先级远高于 deny，deny 仍然获胜。
    let policy = PolicySet::from_rules(vec![
        rule("allow-everything", Decision::Allow, MatchExpr::any_facts()).with_priority(10_000),
        rule(
            "confirm-everything",
            Decision::RequireConfirmation,
            MatchExpr::any_facts(),
        )
        .with_priority(5_000),
        rule("deny-everything", Decision::Deny, MatchExpr::any_facts()).with_priority(-10_000),
    ])
    .expect("规则集合法");

    let outcome = policy.evaluate(&package_facts());
    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(
        outcome.matched.len(),
        3,
        "三条规则都命中，只是决策取最严厉者"
    );
    assert!(outcome.explanation.contains("deny-first"));
    assert!(outcome.explanation.contains("deny-everything"));
}

#[test]
fn deny_first_is_independent_of_written_order() {
    let deny = rule("z-deny", Decision::Deny, MatchExpr::any_facts());
    let allow = rule("a-allow", Decision::Allow, MatchExpr::any_facts());

    let forward = PolicySet::from_rules(vec![deny.clone(), allow.clone()]).expect("合法");
    let backward = PolicySet::from_rules(vec![allow, deny]).expect("合法");

    assert_eq!(forward.evaluate(&package_facts()).decision, Decision::Deny);
    assert_eq!(backward.evaluate(&package_facts()).decision, Decision::Deny);
}

// ---------------------------------------------------------------------------
// 语义 2：默认值分域
// ---------------------------------------------------------------------------

#[test]
fn active_content_kinds_default_to_deny() {
    let empty = PolicySet::empty();
    for kind in [
        ResourceKind::Command,
        ResourceKind::AgentBundle,
        ResourceKind::Plugin,
    ] {
        let facts = PolicyFacts::new(kind, Operation::Execute, Risk::Low, Os::Linux);
        let outcome = empty.evaluate(&facts);
        assert_eq!(
            outcome.decision,
            Decision::Deny,
            "{} 属于主动内容，没有规则命中时必须拒绝",
            kind.as_str()
        );
        assert!(outcome.is_default());
        assert!(outcome.explanation.contains("没有任何规则命中"));
    }
}

#[test]
fn file_and_package_kinds_keep_the_existing_allow_default() {
    let empty = PolicySet::empty();
    for kind in [ResourceKind::File, ResourceKind::Package] {
        let facts = PolicyFacts::new(kind, Operation::Write, Risk::Medium, Os::MacOs);
        assert_eq!(
            empty.evaluate(&facts).decision,
            Decision::Allow,
            "{} 由 Plan 与用户确认把关，策略沉默不等于无人把关",
            kind.as_str()
        );
    }
}

#[test]
fn default_decision_matrix_is_exhaustive() {
    // 穷尽列出五个种类的默认值，任何新增种类都会让这个 match 编译失败。
    for kind in [
        ResourceKind::File,
        ResourceKind::Package,
        ResourceKind::AgentBundle,
        ResourceKind::Command,
        ResourceKind::Plugin,
    ] {
        let expected = match kind {
            ResourceKind::File | ResourceKind::Package => Decision::Allow,
            ResourceKind::AgentBundle | ResourceKind::Command | ResourceKind::Plugin => {
                Decision::Deny
            }
        };
        assert_eq!(kind.default_decision(), expected);
    }
}

// ---------------------------------------------------------------------------
// 语义 3：RequireConfirmation 是中间态
// ---------------------------------------------------------------------------

#[test]
fn confirmation_sits_between_allow_and_deny() {
    let allow_only =
        PolicySet::from_rules(vec![rule("a", Decision::Allow, MatchExpr::any_facts())])
            .expect("合法");
    assert_eq!(
        allow_only.evaluate(&package_facts()).decision,
        Decision::Allow
    );

    let allow_and_confirm = PolicySet::from_rules(vec![
        rule("a", Decision::Allow, MatchExpr::any_facts()),
        rule("c", Decision::RequireConfirmation, MatchExpr::any_facts()),
    ])
    .expect("合法");
    assert_eq!(
        allow_and_confirm.evaluate(&package_facts()).decision,
        Decision::RequireConfirmation,
        "只要有一条 require_confirmation，就不能直接放行"
    );

    let all_three = PolicySet::from_rules(vec![
        rule("a", Decision::Allow, MatchExpr::any_facts()),
        rule("c", Decision::RequireConfirmation, MatchExpr::any_facts()),
        rule("d", Decision::Deny, MatchExpr::any_facts()),
    ])
    .expect("合法");
    assert_eq!(
        all_three.evaluate(&package_facts()).decision,
        Decision::Deny,
        "有 deny 时 require_confirmation 也要让位"
    );
}

// ---------------------------------------------------------------------------
// 语义 4：九个匹配维度
// ---------------------------------------------------------------------------

#[test]
fn matches_on_resource_kind() {
    let policy = parse(
        "version: 1\n\
         rules:\n  \
         - id: only-plugins\n    \
         decision: deny\n    \
         match:\n      \
         resource_kind: plugin\n",
    );
    let plugin = PolicyFacts::new(
        ResourceKind::Plugin,
        Operation::Enable,
        Risk::Low,
        Os::Linux,
    )
    .with_signer("k1");
    let file = PolicyFacts::new(ResourceKind::File, Operation::Write, Risk::Low, Os::Linux);
    assert_eq!(policy.evaluate(&plugin).matched.len(), 1);
    assert!(policy.evaluate(&file).matched.is_empty());
}

#[test]
fn matches_on_adapter_exactly_and_by_prefix() {
    let policy = parse(
        "version: 1\n\
         rules:\n  \
         - id: exact-adapter\n    \
         decision: deny\n    \
         match:\n      \
         adapter: builtin.pkg.brew\n  \
         - id: prefix-adapter\n    \
         decision: require_confirmation\n    \
         match:\n      \
         adapter_prefix: \"builtin.pkg.\"\n",
    );

    let brew = package_facts().with_adapter("builtin.pkg.brew");
    assert_eq!(
        policy.evaluate(&brew).matched_rule_ids(),
        vec!["exact-adapter", "prefix-adapter"]
    );

    let scoop = package_facts().with_adapter("builtin.pkg.scoop");
    assert_eq!(
        policy.evaluate(&scoop).matched_rule_ids(),
        vec!["prefix-adapter"],
        "精确匹配不命中，前缀匹配命中"
    );

    let unrelated = package_facts().with_adapter("builtin.file.zsh");
    assert!(policy.evaluate(&unrelated).matched.is_empty());

    // 事实里没有适配器时，两条规则都不命中（而不是意外命中空串前缀）。
    assert!(policy.evaluate(&package_facts()).matched.is_empty());
}

#[test]
fn matches_on_operation_list() {
    let policy = parse(
        "version: 1\n\
         rules:\n  \
         - id: removals\n    \
         decision: deny\n    \
         match:\n      \
         operation: [uninstall, delete]\n",
    );
    for (operation, expected) in [
        (Operation::Uninstall, 1),
        (Operation::Delete, 1),
        (Operation::Install, 0),
    ] {
        let facts = PolicyFacts::new(ResourceKind::Package, operation, Risk::Low, Os::Linux);
        assert_eq!(policy.evaluate(&facts).matched.len(), expected);
    }
}

#[test]
fn matches_on_risk_with_greater_or_equal() {
    let policy = parse(
        "version: 1\n\
         rules:\n  \
         - id: risky\n    \
         decision: require_confirmation\n    \
         match:\n      \
         risk_at_least: medium\n",
    );
    for (risk, expected) in [(Risk::Low, 0), (Risk::Medium, 1), (Risk::High, 1)] {
        let facts = PolicyFacts::new(ResourceKind::File, Operation::Write, risk, Os::Linux);
        assert_eq!(
            policy.evaluate(&facts).matched.len(),
            expected,
            "risk_at_least 是 >= 比较"
        );
    }
}

#[test]
fn matches_on_os() {
    let policy = parse(
        "version: 1\n\
         rules:\n  \
         - id: windows-only\n    \
         decision: deny\n    \
         match:\n      \
         os: [windows]\n",
    );
    let windows = PolicyFacts::new(ResourceKind::File, Operation::Write, Risk::Low, Os::Windows);
    let linux = PolicyFacts::new(ResourceKind::File, Operation::Write, Risk::Low, Os::Linux);
    assert_eq!(policy.evaluate(&windows).decision, Decision::Deny);
    assert_eq!(policy.evaluate(&linux).decision, Decision::Allow);
}

#[test]
fn matches_on_profile_tag_and_capability_from_device_profile() {
    let policy = parse(
        "version: 1\n\
         rules:\n  \
         - id: work-devices\n    \
         decision: deny\n    \
         match:\n      \
         profile_tag: [work, corp]\n  \
         - id: needs-brew\n    \
         decision: require_confirmation\n    \
         match:\n      \
         capability: brew\n",
    );

    let work = DeviceProfile::new(Os::MacOs, Arch::Aarch64)
        .with_tag("work")
        .with_capability("brew");
    let facts = package_facts().with_profile(&work);
    assert_eq!(
        policy.evaluate(&facts).matched_rule_ids(),
        vec!["needs-brew", "work-devices"]
    );

    let home = DeviceProfile::new(Os::MacOs, Arch::Aarch64).with_tag("home");
    let home_facts = package_facts().with_profile(&home);
    assert!(policy.evaluate(&home_facts).matched.is_empty());
}

#[test]
fn matches_on_source_signer() {
    let policy = parse(
        "version: 1\n\
         rules:\n  \
         - id: trusted-signer\n    \
         decision: allow\n    \
         match:\n      \
         signer: [\"fingerprint-a\", \"fingerprint-b\"]\n",
    );
    let trusted = PolicyFacts::new(
        ResourceKind::AgentBundle,
        Operation::Enable,
        Risk::Low,
        Os::Linux,
    )
    .with_signer("fingerprint-a");
    let other = PolicyFacts::new(
        ResourceKind::AgentBundle,
        Operation::Enable,
        Risk::Low,
        Os::Linux,
    )
    .with_signer("fingerprint-z");
    assert_eq!(policy.evaluate(&trusted).matched.len(), 1);
    assert!(policy.evaluate(&other).matched.is_empty());
}

#[test]
fn matches_on_declared_capability() {
    let policy = parse(
        "version: 1\n\
         rules:\n  \
         - id: network-bundles\n    \
         decision: deny\n    \
         match:\n      \
         declared_capability: [network, filesystem-write]\n",
    );
    let declared = set_of(&["network"]);
    let facts = PolicyFacts::new(
        ResourceKind::AgentBundle,
        Operation::Enable,
        Risk::Low,
        Os::Linux,
    )
    .with_signer("k")
    .with_declared_capabilities(&declared);
    assert_eq!(policy.evaluate(&facts).decision, Decision::Deny);

    let harmless = set_of(&["clock"]);
    let harmless_facts = PolicyFacts::new(
        ResourceKind::AgentBundle,
        Operation::Enable,
        Risk::Low,
        Os::Linux,
    )
    .with_signer("k")
    .with_declared_capabilities(&harmless);
    assert!(policy.evaluate(&harmless_facts).matched.is_empty());
}

#[test]
fn matches_on_resource_glob_with_exact_and_suffix_star_only() {
    let policy = parse(
        "version: 1\n\
         rules:\n  \
         - id: agents-subtree\n    \
         decision: deny\n    \
         match:\n      \
         resource: [\"agents/\", \"shell/zsh/main\"]\n",
    );
    // 上面写的是精确匹配；再单独验证 `*` 尾缀。
    assert!(matches!(
        ResourceGlob::parse("agents/").expect("合法"),
        ResourceGlob::Exact(_)
    ));
    assert!(matches!(
        ResourceGlob::parse("agents/*").expect("合法"),
        ResourceGlob::Prefix(_)
    ));

    let exact = ResourceId::parse("shell/zsh/main").expect("合法");
    let facts = PolicyFacts::new(ResourceKind::File, Operation::Write, Risk::Low, Os::Linux)
        .with_resource(&exact);
    assert_eq!(policy.evaluate(&facts).decision, Decision::Deny);

    let other = ResourceId::parse("shell/bash/main").expect("合法");
    let other_facts = PolicyFacts::new(ResourceKind::File, Operation::Write, Risk::Low, Os::Linux)
        .with_resource(&other);
    assert!(policy.evaluate(&other_facts).matched.is_empty());

    let prefix_policy = parse(
        "version: 1\n\
         rules:\n  \
         - id: agents-prefix\n    \
         decision: deny\n    \
         match:\n      \
         resource: \"agents/claude/*\"\n",
    );
    let inside = ResourceId::parse("agents/claude/reviewer").expect("合法");
    let outside = ResourceId::parse("agents/codex/reviewer").expect("合法");
    let inside_facts = PolicyFacts::new(ResourceKind::File, Operation::Write, Risk::Low, Os::Linux)
        .with_resource(&inside);
    let outside_facts =
        PolicyFacts::new(ResourceKind::File, Operation::Write, Risk::Low, Os::Linux)
            .with_resource(&outside);
    assert_eq!(
        prefix_policy.evaluate(&inside_facts).decision,
        Decision::Deny
    );
    assert!(prefix_policy.evaluate(&outside_facts).matched.is_empty());

    // 事实里没有资源标识时不命中。
    let none_facts = PolicyFacts::new(ResourceKind::File, Operation::Write, Risk::Low, Os::Linux);
    assert!(prefix_policy.evaluate(&none_facts).matched.is_empty());
}

#[test]
fn resource_glob_rejects_anything_that_needs_backtracking() {
    for pattern in ["a*b", "*a*", "**", "a**b", "*/x"] {
        let error = ResourceGlob::parse(pattern).expect_err("必须拒绝");
        assert_eq!(error.code(), "policy.invalid_pattern", "模式 {pattern}");
    }
    assert!(ResourceGlob::parse("*").is_ok(), "单独的 `*` 匹配一切");
    assert!(
        ResourceGlob::parse(&"x".repeat(300)).is_err(),
        "超长模式被拒绝"
    );
}

#[test]
fn boolean_combinators_compose_dimensions() {
    let policy = parse(
        "version: 1\n\
         rules:\n  \
         - id: composed\n    \
         decision: deny\n    \
         match:\n      \
         resource_kind: package\n      \
         any:\n        \
         - operation: [uninstall]\n        \
         - risk_at_least: high\n      \
         not:\n        \
         profile_tag: lab\n",
    );

    let high_risk = PolicyFacts::new(
        ResourceKind::Package,
        Operation::Install,
        Risk::High,
        Os::Linux,
    );
    assert_eq!(policy.evaluate(&high_risk).decision, Decision::Deny);

    let lab = DeviceProfile::new(Os::Linux, Arch::X86_64).with_tag("lab");
    let lab_facts = PolicyFacts::new(
        ResourceKind::Package,
        Operation::Install,
        Risk::High,
        Os::Linux,
    )
    .with_profile(&lab);
    assert!(
        policy.evaluate(&lab_facts).matched.is_empty(),
        "`not` 把带 lab 标签的设备排除在外"
    );

    let low_risk_install = package_facts();
    assert!(policy.evaluate(&low_risk_install).matched.is_empty());
}

// ---------------------------------------------------------------------------
// 语义 5：AST 是封闭枚举
// ---------------------------------------------------------------------------

/// 对 [`MatchExpr`] 写穷尽 `match`：没有 `_` 兜底分支。
///
/// 这个函数本身就是断言——只要有人给 AST 加了新构造（尤其是能引入循环、正则或动态
/// 求值的构造），这里就会编译失败，从而强制在 review 里正视它。
fn classify_expr(expr: &MatchExpr) -> &'static str {
    match expr {
        MatchExpr::Leaf(predicate) => classify_predicate(predicate),
        MatchExpr::All(_) => "all",
        MatchExpr::Any(_) => "any",
        MatchExpr::Not(_) => "not",
    }
}

/// 对 [`FactPredicate`] 写穷尽 `match`：同样没有 `_` 兜底分支。
fn classify_predicate(predicate: &FactPredicate) -> &'static str {
    match predicate {
        FactPredicate::ResourceKind(_) => "resource_kind",
        FactPredicate::Operation(_) => "operation",
        FactPredicate::Os(_) => "os",
        FactPredicate::Adapter(_) => "adapter",
        FactPredicate::AdapterPrefix(_) => "adapter_prefix",
        FactPredicate::RiskAtLeast(_) => "risk_at_least",
        FactPredicate::ProfileTag(_) => "profile_tag",
        FactPredicate::Capability(_) => "capability",
        FactPredicate::DeclaredCapability(_) => "declared_capability",
        FactPredicate::Signer(_) => "signer",
        FactPredicate::SignerPresent(_) => "signer_present",
        FactPredicate::Resource(_) => "resource",
        FactPredicate::ElevationRequired(_) => "elevation_required",
    }
}

#[test]
fn ast_is_a_closed_enum_without_loops_regex_or_dynamic_code() {
    // 三个组合子 + 十三个叶子谓词，就是策略语言的全部表达能力。
    assert_eq!(classify_expr(&MatchExpr::All(vec![])), "all");
    assert_eq!(classify_expr(&MatchExpr::Any(vec![])), "any");
    assert_eq!(
        classify_expr(&MatchExpr::Not(Box::new(MatchExpr::any_facts()))),
        "not"
    );

    let leaves = [
        FactPredicate::ResourceKind(BTreeSet::new()),
        FactPredicate::Operation(BTreeSet::new()),
        FactPredicate::Os(BTreeSet::new()),
        FactPredicate::Adapter(BTreeSet::new()),
        FactPredicate::AdapterPrefix(String::new()),
        FactPredicate::RiskAtLeast(Risk::Low),
        FactPredicate::ProfileTag(BTreeSet::new()),
        FactPredicate::Capability(BTreeSet::new()),
        FactPredicate::DeclaredCapability(BTreeSet::new()),
        FactPredicate::Signer(BTreeSet::new()),
        FactPredicate::SignerPresent(true),
        FactPredicate::Resource(BTreeSet::new()),
        FactPredicate::ElevationRequired(true),
    ];
    let names: BTreeSet<&str> = leaves
        .iter()
        .map(|predicate| classify_predicate(predicate))
        .collect();
    assert_eq!(names.len(), leaves.len(), "谓词分类必须互不重名");

    // 决策也是封闭枚举。
    for decision in [
        Decision::Allow,
        Decision::RequireConfirmation,
        Decision::Deny,
    ] {
        let name = match decision {
            Decision::Allow => "allow",
            Decision::RequireConfirmation => "require_confirmation",
            Decision::Deny => "deny",
        };
        assert_eq!(decision.as_str(), name);
        assert_eq!(Decision::parse(name), Some(decision));
    }

    // 操作同样封闭：新增操作会让这个 match 编译失败。
    for operation in [
        Operation::Read,
        Operation::Write,
        Operation::Delete,
        Operation::Install,
        Operation::Upgrade,
        Operation::Downgrade,
        Operation::Uninstall,
        Operation::Execute,
        Operation::Enable,
    ] {
        let is_write = match operation {
            Operation::Read | Operation::Execute => false,
            Operation::Write
            | Operation::Delete
            | Operation::Install
            | Operation::Upgrade
            | Operation::Downgrade
            | Operation::Uninstall
            | Operation::Enable => true,
        };
        assert_eq!(operation.is_write(), is_write);
        assert_eq!(Operation::parse(operation.as_str()), Some(operation));
    }
}

#[test]
fn glob_matching_is_linear_and_cannot_backtrack() {
    // 一个对回溯型匹配器而言的病理输入：在这里只是一次 `starts_with`。
    let glob = ResourceGlob::parse(&format!("{}*", "a".repeat(200))).expect("合法");
    let value = "a".repeat(10_000);
    assert!(glob.matches(&value));
    assert!(!glob.matches("b"));
}

// ---------------------------------------------------------------------------
// 语义 6：资源限制
// ---------------------------------------------------------------------------

#[test]
fn parse_yaml_rejects_more_than_ten_thousand_rules() {
    let mut text = String::from("version: 1\nrules:\n");
    for index in 0..=MAX_RULES {
        text.push_str(&format!("  - id: r{index}\n    decision: allow\n"));
    }
    let error = PolicySet::parse_yaml(&text, "big.yaml").expect_err("必须拒绝");
    assert_eq!(error.code(), "policy.too_many_rules");
}

#[test]
fn merge_rejects_more_than_ten_thousand_rules() {
    let build = |prefix: &str| {
        let rules = (0..6_000)
            .map(|index| {
                rule(
                    &format!("{prefix}-{index}"),
                    Decision::Allow,
                    MatchExpr::any_facts(),
                )
            })
            .collect();
        PolicySet::from_rules(rules).expect("单个来源未超限")
    };
    let error = PolicySet::merge(vec![build("a"), build("b")]).expect_err("必须拒绝");
    assert_eq!(error.code(), "policy.too_many_rules");
}

#[test]
fn parse_yaml_rejects_ast_deeper_than_thirty_two() {
    let mut inner = String::from("{resource_kind: file}");
    for _ in 0..40 {
        inner = format!("{{not: {inner}}}");
    }
    let text =
        format!("version: 1\nrules:\n  - id: deep\n    decision: deny\n    match: {inner}\n");
    let error = PolicySet::parse_yaml(&text, "deep.yaml").expect_err("必须拒绝");
    assert_eq!(error.code(), "policy.ast_too_deep");

    // 上限之内的嵌套仍然可以解析。
    let mut shallow = String::from("{resource_kind: file}");
    for _ in 0..20 {
        shallow = format!("{{not: {shallow}}}");
    }
    let ok_text =
        format!("version: 1\nrules:\n  - id: ok\n    decision: deny\n    match: {shallow}\n");
    let policy = PolicySet::parse_yaml(&ok_text, "ok.yaml").expect("上限内必须接受");
    assert!(policy.rules()[0].matcher.depth() <= MAX_AST_DEPTH);
}

#[test]
fn parse_yaml_rejects_oversized_text_and_deep_input_nesting() {
    let huge = format!("version: 1\n# {}\n", "x".repeat(1024 * 1024));
    assert_eq!(
        PolicySet::parse_yaml(&huge, "huge.yaml")
            .expect_err("必须拒绝")
            .code(),
        "policy.text_too_large"
    );

    let deep_line = format!("version: 1\n{}key: value\n", " ".repeat(200));
    assert_eq!(
        PolicySet::parse_yaml(&deep_line, "deep.yaml")
            .expect_err("必须拒绝")
            .code(),
        "policy.nesting_too_deep"
    );
}

#[test]
fn matcher_depth_and_node_count_are_computed_without_recursion() {
    // 手工构造一棵远超上限的树：计算深度/节点数必须返回结果而不是栈溢出。
    let mut expr = MatchExpr::any_facts();
    for _ in 0..5_000 {
        expr = MatchExpr::Not(Box::new(expr));
    }
    assert_eq!(expr.depth(), 5_001);
    assert_eq!(expr.node_count(), 5_001);
    assert_eq!(
        expr.validate("deep").expect_err("超限").code(),
        "policy.ast_too_deep"
    );

    // 求值同样不会栈溢出：预算耗尽时保守地判为不命中。
    assert!(!expr.matches(&package_facts()));
}

// ---------------------------------------------------------------------------
// 语义 7：可解释性
// ---------------------------------------------------------------------------

#[test]
fn outcome_reports_rule_id_source_priority_and_facts_digest() {
    let policy = PolicySet::parse_yaml(
        "version: 1\n\
         rules:\n  \
         - id: deny-system-package-writes\n    \
         priority: 100\n    \
         decision: deny\n    \
         reason: \"系统级包管理需要单独的提权流程\"\n    \
         match:\n      \
         resource_kind: package\n      \
         adapter_prefix: \"builtin.pkg.system.\"\n      \
         operation: [install, upgrade, uninstall]\n",
        "/home/someone/.config/envsync/policy.yaml",
    )
    .expect("合法");

    let facts = package_facts().with_adapter("builtin.pkg.system.apt");
    let outcome = policy.evaluate(&facts);

    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(outcome.matched.len(), 1);
    let matched = &outcome.matched[0];
    assert_eq!(matched.rule_id, "deny-system-package-writes");
    assert_eq!(matched.priority, 100);
    assert_eq!(
        matched.source, "policy.yaml",
        "来源只保留文件名，不泄漏本机绝对路径"
    );
    assert_eq!(matched.decision, Decision::Deny);
    assert!(matched.reason.contains("提权"));

    assert_eq!(outcome.facts_digest.len(), 64);
    assert!(outcome
        .facts_digest
        .chars()
        .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch)));
    assert_eq!(outcome.facts_digest, facts_digest(&facts));

    assert!(outcome.explanation.contains("deny-system-package-writes"));
    assert!(outcome.explanation.contains("priority=100"));
    assert!(outcome.explanation.contains("policy.yaml"));
    assert!(outcome.explanation.contains(&outcome.facts_digest));
    assert!(!outcome.explanation.contains("/home/someone"));
}

#[test]
fn facts_digest_changes_with_every_field_and_ignores_input_ordering() {
    let base = package_facts();
    let baseline = facts_digest(&base);

    assert_ne!(baseline, facts_digest(&base.with_adapter("brew")));
    assert_ne!(baseline, facts_digest(&base.with_elevation_required(true)));
    assert_ne!(baseline, facts_digest(&base.with_signer("k")));

    // 长度前缀编码：拼接歧义不会造成碰撞。
    assert_ne!(
        facts_digest(&base.with_adapter("ab").with_signer("")),
        facts_digest(&base.with_adapter("a").with_signer("b"))
    );

    // `secret_refs` 顺序不同不改变摘要。
    let forward = vec!["a/one".to_owned(), "b/two".to_owned()];
    let backward = vec!["b/two".to_owned(), "a/one".to_owned()];
    assert_eq!(
        facts_digest(&base.with_secret_refs(&forward)),
        facts_digest(&base.with_secret_refs(&backward))
    );
}

#[test]
fn explanation_only_ever_shows_opaque_secret_ref_ids() {
    let policy = PolicySet::builtin_defaults();
    let secrets = vec!["github/token".to_owned(), "npm/registry-token".to_owned()];
    let facts = package_facts()
        .with_adapter("builtin.pkg.brew")
        .with_secret_refs(&secrets);

    let outcome = policy.evaluate(&facts);
    let full = policy.explain(&facts);

    for text in [&outcome.explanation, &full] {
        // opaque 标识本身可以出现——它就是给人看的。
        assert!(text.contains("github/token"));
        assert!(text.contains("npm/registry-token"));
        // 任何“看起来像值”的东西都不该出现。引擎结构上就拿不到值，这里是回归护栏。
        for needle in [
            "ghp_",
            "xoxb-",
            "AKIA",
            "-----BEGIN",
            "PRIVATE KEY",
            "password",
            "secret=",
            "token=",
            "Bearer ",
        ] {
            assert!(
                !text.contains(needle),
                "解释里不应出现疑似秘密值的片段：{needle}"
            );
        }
    }
    // 摘要是单向哈希，同样不含标识原文。
    assert!(!outcome.facts_digest.contains("github"));
}

#[test]
fn non_opaque_secret_ref_is_replaced_by_a_placeholder() {
    let policy = PolicySet::builtin_defaults();
    // 假想上游出错，把明文塞进了 `secret_refs`：渲染出来必须是占位符。
    let leaked = vec!["ghp_LIVE TOKEN value=abc".to_owned()];
    let facts = package_facts().with_secret_refs(&leaked);
    let outcome = policy.evaluate(&facts);

    assert!(outcome.explanation.contains("<non-opaque-secret-ref>"));
    assert!(!outcome.explanation.contains("ghp_LIVE"));
    assert!(!outcome.explanation.contains("value=abc"));
}

#[test]
fn explain_renders_the_full_decision_trace() {
    let policy = PolicySet::builtin_defaults();
    let facts = PolicyFacts::new(
        ResourceKind::Package,
        Operation::Uninstall,
        Risk::High,
        Os::Linux,
    )
    .with_adapter("builtin.pkg.brew");

    let trace = policy.explain(&facts);
    assert!(trace.contains("逐条判定"));
    assert!(trace.contains("规则集：共 7 条规则"));
    assert!(trace.contains(BUILTIN_SOURCE));
    assert!(trace.contains("[命中]"));
    assert!(trace.contains("[跳过]"));
    assert!(trace.contains(BUILTIN_PACKAGE_UNINSTALL));
    // 逐条轨迹里出现了没有命中的内建规则，说明「完整过程」是真的完整。
    assert!(trace.contains(BUILTIN_ELEVATION_DENIED));
}

// ---------------------------------------------------------------------------
// 语义 8：确定性
// ---------------------------------------------------------------------------

#[test]
fn shuffled_rules_produce_identical_sets_decisions_and_match_order() {
    let rules = vec![
        rule(
            "m-mid",
            Decision::RequireConfirmation,
            MatchExpr::any_facts(),
        )
        .with_priority(100),
        rule("a-mid", Decision::Allow, MatchExpr::any_facts()).with_priority(100),
        rule("z-high", Decision::Allow, MatchExpr::any_facts()).with_priority(500),
        rule("b-low", Decision::Allow, MatchExpr::any_facts()).with_priority(-5),
    ];

    let expected_order = vec!["z-high", "a-mid", "m-mid", "b-low"];
    let baseline = PolicySet::from_rules(rules.clone()).expect("合法");
    assert_eq!(
        baseline.evaluate(&package_facts()).matched_rule_ids(),
        expected_order,
        "priority 降序，随后 rule_id 升序"
    );

    // 遍历若干个排列：策略集、决策与命中顺序全都必须一致。
    for rotation in 0..rules.len() {
        let mut permuted = rules.clone();
        permuted.rotate_left(rotation);
        let shuffled = PolicySet::from_rules(permuted).expect("合法");
        assert_eq!(shuffled, baseline, "排列 {rotation} 应得到相同策略集");
        let outcome = shuffled.evaluate(&package_facts());
        assert_eq!(outcome.decision, Decision::RequireConfirmation);
        assert_eq!(outcome.matched_rule_ids(), expected_order);
        assert_eq!(
            outcome,
            baseline.evaluate(&package_facts()),
            "整个 DecisionOutcome 逐字段相同"
        );
    }

    let mut reversed = rules;
    reversed.reverse();
    assert_eq!(
        PolicySet::from_rules(reversed).expect("合法"),
        baseline,
        "完全逆序同样等价"
    );
}

#[test]
fn merge_is_deterministic_and_lets_later_sources_override_by_rule_id() {
    let builtin = PolicySet::builtin_defaults();
    let user = parse(
        "version: 1\n\
         rules:\n  \
         - id: builtin.elevation-required-denied\n    \
         priority: 900\n    \
         decision: require_confirmation\n    \
         reason: \"本机允许在确认后提权\"\n    \
         match:\n      \
         elevation_required: true\n",
    );

    let merged = PolicySet::merge(vec![builtin.clone(), user.clone()]).expect("合法");
    assert_eq!(
        merged.rule_count(),
        builtin.rule_count(),
        "同 ID 覆盖不会增加规则条数"
    );

    let facts = package_facts().with_elevation_required(true);
    assert_eq!(
        merged.evaluate(&facts).decision,
        Decision::RequireConfirmation,
        "唯一能放宽内建 deny 的途径就是指名道姓地覆盖它"
    );

    // 反过来合并，内建的 deny 重新生效：合并顺序是有意义的输入。
    let reversed = PolicySet::merge(vec![user, builtin]).expect("合法");
    assert_eq!(reversed.evaluate(&facts).decision, Decision::Deny);
}

// ---------------------------------------------------------------------------
// 内建默认策略：逐条用例
// ---------------------------------------------------------------------------

#[test]
fn builtin_defaults_confirm_package_uninstall() {
    let policy = PolicySet::builtin_defaults();
    let facts = PolicyFacts::new(
        ResourceKind::Package,
        Operation::Uninstall,
        Risk::High,
        Os::Linux,
    )
    .with_adapter("builtin.pkg.brew");
    let outcome = policy.evaluate(&facts);
    assert_eq!(outcome.decision, Decision::RequireConfirmation);
    assert_eq!(outcome.matched_rule_ids(), vec![BUILTIN_PACKAGE_UNINSTALL]);
}

#[test]
fn builtin_defaults_confirm_package_downgrade() {
    let policy = PolicySet::builtin_defaults();
    let facts = PolicyFacts::new(
        ResourceKind::Package,
        Operation::Downgrade,
        Risk::Medium,
        Os::MacOs,
    )
    .with_adapter("builtin.pkg.brew");
    let outcome = policy.evaluate(&facts);
    assert_eq!(outcome.decision, Decision::RequireConfirmation);
    assert_eq!(outcome.matched_rule_ids(), vec![BUILTIN_PACKAGE_DOWNGRADE]);
}

#[test]
fn builtin_defaults_deny_elevation() {
    let policy = PolicySet::builtin_defaults();
    let facts = package_facts()
        .with_adapter("builtin.pkg.brew")
        .with_elevation_required(true);
    let outcome = policy.evaluate(&facts);
    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(outcome.matched_rule_ids(), vec![BUILTIN_ELEVATION_DENIED]);
}

#[test]
fn builtin_defaults_deny_system_package_writes() {
    let policy = PolicySet::builtin_defaults();
    for operation in [
        Operation::Install,
        Operation::Upgrade,
        Operation::Downgrade,
        Operation::Uninstall,
        Operation::Write,
        Operation::Delete,
    ] {
        let facts = PolicyFacts::new(ResourceKind::Package, operation, Risk::Medium, Os::Linux)
            .with_adapter("builtin.pkg.system.apt");
        let outcome = policy.evaluate(&facts);
        assert_eq!(
            outcome.decision,
            Decision::Deny,
            "系统级包管理器的 {} 必须被拒绝",
            operation.as_str()
        );
        assert!(outcome
            .matched_rule_ids()
            .contains(&BUILTIN_SYSTEM_PACKAGE_WRITE));
    }

    // 读操作不受这条规则约束：观察系统包清单是安全的。
    let read = PolicyFacts::new(ResourceKind::Package, Operation::Read, Risk::Low, Os::Linux)
        .with_adapter("builtin.pkg.system.apt");
    assert_eq!(policy.evaluate(&read).decision, Decision::Allow);
}

#[test]
fn builtin_defaults_confirm_agent_bundle_enable() {
    let policy = PolicySet::builtin_defaults();
    let facts = PolicyFacts::new(
        ResourceKind::AgentBundle,
        Operation::Enable,
        Risk::Medium,
        Os::Linux,
    )
    .with_signer("ed25519:fingerprint");
    let outcome = policy.evaluate(&facts);
    assert_eq!(outcome.decision, Decision::RequireConfirmation);
    assert_eq!(
        outcome.matched_rule_ids(),
        vec![BUILTIN_AGENT_BUNDLE_ENABLE]
    );
}

#[test]
fn builtin_defaults_deny_bundles_and_plugins_from_unknown_signers() {
    let policy = PolicySet::builtin_defaults();
    for kind in [ResourceKind::AgentBundle, ResourceKind::Plugin] {
        let facts = PolicyFacts::new(kind, Operation::Enable, Risk::Medium, Os::Linux);
        let outcome = policy.evaluate(&facts);
        assert_eq!(
            outcome.decision,
            Decision::Deny,
            "{} 没有 signer 时必须拒绝",
            kind.as_str()
        );
        assert!(outcome
            .matched_rule_ids()
            .contains(&BUILTIN_UNSIGNED_ACTIVE_CONTENT));
    }

    // 未知 signer 的 deny 压过 Bundle 启用的 require_confirmation（deny-first）。
    let unsigned_bundle = PolicyFacts::new(
        ResourceKind::AgentBundle,
        Operation::Enable,
        Risk::Medium,
        Os::Linux,
    );
    let outcome = policy.evaluate(&unsigned_bundle);
    assert_eq!(outcome.matched.len(), 2);
    assert_eq!(outcome.decision, Decision::Deny);
}

#[test]
fn builtin_defaults_confirm_high_risk_commands() {
    let policy = PolicySet::builtin_defaults();
    let high = PolicyFacts::new(
        ResourceKind::Command,
        Operation::Execute,
        Risk::High,
        Os::Linux,
    );
    assert_eq!(
        policy.evaluate(&high).decision,
        Decision::RequireConfirmation
    );
    assert_eq!(
        policy.evaluate(&high).matched_rule_ids(),
        vec![BUILTIN_HIGH_RISK_COMMAND]
    );

    // 其余风险等级的命令没有规则命中，落到 Command 的默认拒绝。
    let medium = PolicyFacts::new(
        ResourceKind::Command,
        Operation::Execute,
        Risk::Medium,
        Os::Linux,
    );
    let outcome = policy.evaluate(&medium);
    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.is_default());
}

#[test]
fn builtin_defaults_are_self_consistent() {
    let policy = PolicySet::builtin_defaults();
    assert_eq!(policy.rule_count(), 7);
    assert_eq!(policy.sources(), [BUILTIN_SOURCE].into_iter().collect());
    for rule in policy.rules() {
        assert!(rule.validate().is_ok());
        assert!(!rule.reason.is_empty(), "内建规则必须写明理由");
    }
    // 构造两次结果完全相同（不读时钟、不读环境）。
    assert_eq!(policy, PolicySet::builtin_defaults());
}

// ---------------------------------------------------------------------------
// YAML：接受路径与全部拒绝路径
// ---------------------------------------------------------------------------

#[test]
fn parses_the_documented_example() {
    let policy = PolicySet::parse_yaml(
        "version: 1\n\
         rules:\n  \
         - id: deny-system-package-writes\n    \
         priority: 100\n    \
         decision: deny\n    \
         reason: \"系统级包管理需要单独的提权流程\"\n    \
         match:\n      \
         resource_kind: package\n      \
         adapter_prefix: \"builtin.pkg.system.\"\n      \
         operation: [install, upgrade, uninstall]\n",
        "policy.yaml",
    )
    .expect("文档示例必须能解析");
    assert_eq!(policy.rule_count(), 1);
    assert_eq!(policy.rules()[0].priority, 100);
    assert_eq!(policy.rules()[0].decision, Decision::Deny);
}

#[test]
fn parses_a_rule_without_match_as_matching_everything() {
    let policy = parse("version: 1\nrules:\n  - id: blanket\n    decision: deny\n");
    assert_eq!(policy.evaluate(&package_facts()).decision, Decision::Deny);
    assert_eq!(policy.rules()[0].matcher, MatchExpr::any_facts());
}

#[test]
fn parses_a_document_without_rules() {
    let policy = parse("version: 1\n");
    assert!(policy.is_empty());
    assert_eq!(policy.rule_count(), 0);
}

#[test]
fn rejects_unknown_fields() {
    for text in [
        "version: 1\nextra: true\n",
        "version: 1\nrules:\n  - id: a\n    decision: allow\n    oops: 1\n",
        "version: 1\nrules:\n  - id: a\n    decision: allow\n    match:\n      nope: 1\n",
    ] {
        let error = PolicySet::parse_yaml(text, "p.yaml").expect_err("必须拒绝未知字段");
        assert_eq!(error.code(), "policy.yaml", "文本：{text}");
    }
}

#[test]
fn rejects_unknown_version() {
    for text in ["version: 2\n", "version: 0\n", "version: 99\nrules: []\n"] {
        let error = PolicySet::parse_yaml(text, "p.yaml").expect_err("必须拒绝未知版本");
        assert_eq!(error.code(), "policy.unsupported_version");
    }
    // 缺少 version 同样拒绝。
    assert_eq!(
        PolicySet::parse_yaml("rules: []\n", "p.yaml")
            .expect_err("必须拒绝")
            .code(),
        "policy.yaml"
    );
    // 空文档拒绝。
    assert!(PolicySet::parse_yaml("", "p.yaml").is_err());
}

#[test]
fn rejects_duplicate_rule_ids() {
    let error = PolicySet::parse_yaml(
        "version: 1\n\
         rules:\n  \
         - id: same\n    decision: allow\n  \
         - id: same\n    decision: deny\n",
        "p.yaml",
    )
    .expect_err("必须拒绝重复标识");
    assert_eq!(error.code(), "policy.duplicate_rule_id");
    assert!(matches!(error, PolicyError::DuplicateRuleId { ref id } if id == "same"));
}

#[test]
fn rejects_invalid_rule_ids() {
    for id in ["", "has space", "has/slash", "换行\n", &"x".repeat(200)] {
        let text = format!(
            "version: 1\nrules:\n  - id: \"{}\"\n    decision: allow\n",
            id.escape_debug()
        );
        let error = PolicySet::parse_yaml(&text, "p.yaml").expect_err("必须拒绝");
        assert!(
            matches!(
                error,
                PolicyError::InvalidRuleId { .. } | PolicyError::Yaml { .. }
            ),
            "标识 {id:?} 应被拒绝，实际 {error:?}"
        );
    }
}

#[test]
fn rejects_unknown_enum_values() {
    for text in [
        "version: 1\nrules:\n  - id: a\n    decision: maybe\n",
        "version: 1\nrules:\n  - id: a\n    decision: allow\n    match:\n      resource_kind: socket\n",
        "version: 1\nrules:\n  - id: a\n    decision: allow\n    match:\n      operation: [teleport]\n",
        "version: 1\nrules:\n  - id: a\n    decision: allow\n    match:\n      os: [plan9]\n",
        "version: 1\nrules:\n  - id: a\n    decision: allow\n    match:\n      risk_at_least: extreme\n",
    ] {
        assert_eq!(
            PolicySet::parse_yaml(text, "p.yaml")
                .expect_err("必须拒绝未知枚举取值")
                .code(),
            "policy.yaml",
            "文本：{text}"
        );
    }
}

#[test]
fn rejects_empty_lists_because_they_silently_never_match() {
    for field in ["resource_kind", "operation", "os", "adapter", "resource"] {
        let text = format!(
            "version: 1\nrules:\n  - id: a\n    decision: deny\n    match:\n      {field}: []\n"
        );
        let error = PolicySet::parse_yaml(&text, "p.yaml").expect_err("必须拒绝空列表");
        assert_eq!(error.code(), "policy.yaml", "字段 {field}");
        assert!(error.to_string().contains("空列表"));
    }
}

#[test]
fn rejects_invalid_globs_and_literals() {
    let error = PolicySet::parse_yaml(
        "version: 1\nrules:\n  - id: a\n    decision: deny\n    match:\n      resource: \"a*b\"\n",
        "p.yaml",
    )
    .expect_err("必须拒绝");
    assert_eq!(error.code(), "policy.invalid_pattern");

    let empty_literal = PolicySet::parse_yaml(
        "version: 1\nrules:\n  - id: a\n    decision: deny\n    match:\n      adapter: \"\"\n",
        "p.yaml",
    )
    .expect_err("必须拒绝");
    assert_eq!(empty_literal.code(), "policy.invalid_pattern");
}

#[test]
fn rejects_yaml_anchors_aliases_merge_keys_and_tags() {
    let cases = [
        "version: 1\nrules: &anchor []\n",
        "version: 1\nrules: *anchor\n",
        "version: 1\nbase: &b {id: a}\nrules:\n  - <<: *b\n    decision: allow\n",
        "version: 1\nrules:\n  - id: a\n    decision: !!str allow\n",
        "version: 1\nrules: [*a, *b]\n",
    ];
    for text in cases {
        let error = PolicySet::parse_yaml(text, "p.yaml").expect_err("必须拒绝");
        assert_eq!(
            error.code(),
            "policy.unsafe_yaml_construct",
            "文本：{text:?} 实际 {error:?}"
        );
    }

    // 反向验证：引号里的 `*` 与 `!` 是普通字符，不该被误伤。
    let ok = parse(
        "version: 1\n\
         rules:\n  \
         - id: quoted\n    \
         decision: deny\n    \
         reason: \"别这样做！*重要*\"\n    \
         match:\n      \
         resource: \"agents/*\"\n",
    );
    assert_eq!(ok.rule_count(), 1);
}

#[test]
fn rejects_overlong_reason() {
    let text = format!(
        "version: 1\nrules:\n  - id: a\n    decision: allow\n    reason: \"{}\"\n",
        "理".repeat(400)
    );
    let error = PolicySet::parse_yaml(&text, "p.yaml").expect_err("必须拒绝");
    assert_eq!(error.code(), "policy.reason_too_long");
}

#[test]
fn from_rules_rejects_duplicate_ids_and_oversized_sets() {
    let duplicate = PolicySet::from_rules(vec![
        rule("dup", Decision::Allow, MatchExpr::any_facts()),
        rule("dup", Decision::Deny, MatchExpr::any_facts()),
    ])
    .expect_err("必须拒绝");
    assert_eq!(duplicate.code(), "policy.duplicate_rule_id");

    let too_many: Vec<Rule> = (0..=MAX_RULES)
        .map(|index| {
            rule(
                &format!("r{index}"),
                Decision::Allow,
                MatchExpr::any_facts(),
            )
        })
        .collect();
    assert_eq!(
        PolicySet::from_rules(too_many)
            .expect_err("必须拒绝")
            .code(),
        "policy.too_many_rules"
    );
}

// ---------------------------------------------------------------------------
// 语义 9：不 panic（property tests）
// ---------------------------------------------------------------------------

fn kind_from_index(index: usize) -> ResourceKind {
    [
        ResourceKind::File,
        ResourceKind::Package,
        ResourceKind::AgentBundle,
        ResourceKind::Command,
        ResourceKind::Plugin,
    ][index % 5]
}

fn operation_from_index(index: usize) -> Operation {
    [
        Operation::Read,
        Operation::Write,
        Operation::Delete,
        Operation::Install,
        Operation::Upgrade,
        Operation::Downgrade,
        Operation::Uninstall,
        Operation::Execute,
        Operation::Enable,
    ][index % 9]
}

fn risk_from_index(index: usize) -> Risk {
    [Risk::Low, Risk::Medium, Risk::High][index % 3]
}

fn os_from_index(index: usize) -> Os {
    [Os::MacOs, Os::Linux, Os::Windows][index % 3]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// 任意事实都不会让引擎 panic，决策恒为三值之一。
    #[test]
    fn arbitrary_facts_never_panic_and_always_yield_one_of_three_decisions(
        kind_index in 0usize..5,
        operation_index in 0usize..9,
        risk_index in 0usize..3,
        os_index in 0usize..3,
        adapter in proptest::option::of("[ -~]{0,40}"),
        signer in proptest::option::of("[ -~]{0,40}"),
        resource_segment in "[a-z]{1,6}",
        has_resource in any::<bool>(),
        elevation in any::<bool>(),
        tags in proptest::collection::btree_set("[ -~]{0,12}", 0..4),
        capabilities in proptest::collection::btree_set("[ -~]{0,12}", 0..4),
        declared in proptest::collection::btree_set("[ -~]{0,12}", 0..4),
        secrets in proptest::collection::vec("(?s).{0,32}", 0..4),
    ) {
        let policy = PolicySet::builtin_defaults();
        let resource = ResourceId::parse(&format!("{resource_segment}/{resource_segment}"))
            .expect("生成的资源标识合法");

        let mut facts = PolicyFacts::new(
            kind_from_index(kind_index),
            operation_from_index(operation_index),
            risk_from_index(risk_index),
            os_from_index(os_index),
        )
        .with_profile_tags(&tags)
        .with_capabilities(&capabilities)
        .with_declared_capabilities(&declared)
        .with_elevation_required(elevation)
        .with_secret_refs(&secrets);
        if let Some(ref value) = adapter {
            facts = facts.with_adapter(value);
        }
        if let Some(ref value) = signer {
            facts = facts.with_signer(value);
        }
        if has_resource {
            facts = facts.with_resource(&resource);
        }

        let outcome = policy.evaluate(&facts);
        prop_assert!(matches!(
            outcome.decision,
            Decision::Allow | Decision::Deny | Decision::RequireConfirmation
        ));
        prop_assert_eq!(outcome.facts_digest.len(), 64);
        prop_assert!(!outcome.explanation.is_empty());
        // 判定是纯函数：重算一次结果完全相同。
        prop_assert_eq!(&policy.evaluate(&facts), &outcome);
        // 完整解释同样不 panic。
        prop_assert!(!policy.explain(&facts).is_empty());
    }

    /// 任意文本喂给解析器都不会 panic：要么得到策略集，要么得到错误。
    #[test]
    fn arbitrary_text_never_panics_the_parser(text in "(?s).{0,400}") {
        match PolicySet::parse_yaml(&text, "fuzz.yaml") {
            Ok(policy) => {
                prop_assert!(policy.rule_count() <= MAX_RULES);
                let _ = policy.evaluate(&package_facts());
            }
            Err(error) => {
                prop_assert!(!error.code().is_empty());
                prop_assert!(!error.to_string().is_empty());
            }
        }
    }

    /// 近似合法的 YAML 片段同样不会 panic。
    #[test]
    fn arbitrary_rule_shaped_yaml_never_panics(
        id in "[ -~]{0,20}",
        decision in "[a-z_]{0,20}",
        priority in any::<i32>(),
        kind in "[a-z_]{0,16}",
    ) {
        let text = format!(
            "version: 1\nrules:\n  - id: \"{}\"\n    priority: {priority}\n    \
             decision: \"{}\"\n    match:\n      resource_kind: \"{}\"\n",
            id.escape_debug(),
            decision.escape_debug(),
            kind.escape_debug(),
        );
        let _ = PolicySet::parse_yaml(&text, "fuzz.yaml");
    }
}
