//! M3 任务 9：统一 Agent/Skill/MCP 模型到三个目标工具的渲染、往返与校验。
//!
//! 每个渲染器都要满足同一组性质，因此测试按**性质**而不是按工具组织：
//!
//! 1. **往返等价**：`render → merge_rendered → capture` 得到语义上等价的统一模型；
//! 2. **损失显式**：目标工具表达不了的东西一定出现在 loss report，声明能力不被支持时
//!    是 [`LossSeverity::Blocking`]；
//! 3. **Secret 只以引用出现**：渲染产物里只有占位符，真实取值靠注入描述符；
//! 4. **不覆盖本地未管理内容**：合并进已有文件后，用户自己的条目原样保留；
//! 5. **verify 比语义不比字节**：重排、补默认值、外加未管理条目都不算漂移，改动受管
//!    条目才算。

use std::collections::{BTreeMap, BTreeSet};

use envsync_adapters::agents::{
    builtin_renderers, claude, codex, merge_rendered, opencode, renderer_for, AgentBundleContent,
    AgentDefinition, AgentRenderer, CommandTemplate, LossSeverity, McpServerDefinition,
    McpTransport, PermissionTemplate, SecretInjection, SecretRefOrLiteral, SkillDefinition,
    SECRET_PLACEHOLDER_PREFIX,
};
use envsync_domain::id::Digest32;

// ---------------------------------------------------------------------------
// 夹具
// ---------------------------------------------------------------------------

fn digest(label: &str) -> Digest32 {
    Digest32::domain_hash("test:agent-renderers", label.as_bytes())
}

fn reviewer() -> AgentDefinition {
    AgentDefinition {
        name: "reviewer".to_owned(),
        description: "审查改动并给出结论".to_owned(),
        instructions: "只读代码，不要改动任何文件。\n先看 diff，再看上下文。\n".to_owned(),
        tools: BTreeSet::from(["read".to_owned(), "search".to_owned()]),
        model: Some("claude-sonnet-4-5".to_owned()),
    }
}

fn pdf_skill() -> SkillDefinition {
    SkillDefinition {
        name: "pdf".to_owned(),
        description: "处理 PDF 文件".to_owned(),
        body: "# PDF\n\n用 pdftotext 抽取文本。\n".to_owned(),
        files: BTreeMap::from([("scripts/extract.py".to_owned(), digest("extract.py"))]),
    }
}

fn docs_server() -> McpServerDefinition {
    McpServerDefinition {
        name: "docs".to_owned(),
        transport: McpTransport::Stdio,
        command: Some(CommandTemplate {
            program: "docs-mcp".to_owned(),
            args: vec!["--root".to_owned(), "docs".to_owned()],
        }),
        url: None,
        env: BTreeMap::from([
            (
                "DOCS_API_TOKEN".to_owned(),
                SecretRefOrLiteral::secret_ref("secret://docs/token"),
            ),
            ("LOG_LEVEL".to_owned(), SecretRefOrLiteral::literal("info")),
        ]),
        enabled: true,
    }
}

fn remote_server(transport: McpTransport) -> McpServerDefinition {
    McpServerDefinition {
        name: "remote".to_owned(),
        transport,
        command: None,
        url: Some("https://mcp.example.com/v1".to_owned()),
        env: BTreeMap::new(),
        enabled: true,
    }
}

fn permissions() -> PermissionTemplate {
    PermissionTemplate {
        allow: BTreeSet::from(["Read(src/**)".to_owned()]),
        deny: BTreeSet::from(["Bash(rm:*)".to_owned()]),
        ask: BTreeSet::from(["WebFetch".to_owned()]),
    }
}

/// 一份三个工具都能完整表达的内容。
fn portable_content() -> AgentBundleContent {
    AgentBundleContent {
        agents: BTreeMap::from([("reviewer".to_owned(), reviewer())]),
        skills: BTreeMap::new(),
        mcp_servers: BTreeMap::from([("docs".to_owned(), docs_server())]),
        permissions: permissions(),
        declared_capabilities: BTreeSet::from([
            "agents".to_owned(),
            "mcp.stdio".to_owned(),
            "permissions".to_owned(),
        ]),
    }
}

/// 一份带 Skill 的内容（OpenCode 表达不了）。
fn content_with_skill() -> AgentBundleContent {
    let mut content = portable_content();
    content.skills.insert("pdf".to_owned(), pdf_skill());
    content.declared_capabilities.insert("skills".to_owned());
    content
}

/// 渲染并合并到一份空的现有文件集合上，得到「落盘后的文件」。
fn render_to_files(
    renderer: &dyn AgentRenderer,
    content: &AgentBundleContent,
) -> BTreeMap<String, Vec<u8>> {
    let rendered = renderer.render(content).expect("渲染成功");
    merge_rendered(&rendered, &BTreeMap::new())
        .expect("合并成功")
        .into_iter()
        .collect()
}

// ---------------------------------------------------------------------------
// 往返
// ---------------------------------------------------------------------------

#[test]
fn every_renderer_round_trips_a_portable_bundle() {
    let content = portable_content();
    for renderer in builtin_renderers() {
        let files = render_to_files(renderer.as_ref(), &content);
        assert!(
            !files.is_empty(),
            "{} 应当产出至少一个文件",
            renderer.tool_id()
        );
        let captured = renderer.capture(&files).expect("capture 成功");
        assert_eq!(
            captured.semantic_digest(),
            content.project_managed(&content).semantic_digest(),
            "{} 的往返必须语义等价",
            renderer.tool_id()
        );
        // 往返之后 verify 必须通过。
        renderer.verify(&content, &files).expect("verify 通过");
    }
}

#[test]
fn claude_and_codex_round_trip_skills_but_opencode_does_not() {
    let content = content_with_skill();

    for tool in ["claude", "codex"] {
        let renderer = renderer_for(tool).expect("渲染器存在");
        let files = render_to_files(renderer.as_ref(), &content);
        let captured = renderer.capture(&files).expect("capture 成功");
        assert_eq!(
            captured.skills.get("pdf"),
            Some(&pdf_skill()),
            "{tool} 必须完整往返 Skill（含附件摘要）"
        );
    }

    let renderer = renderer_for("opencode").expect("渲染器存在");
    let files = render_to_files(renderer.as_ref(), &content);
    let captured = renderer.capture(&files).expect("capture 成功");
    assert!(captured.skills.is_empty(), "OpenCode 没有 Skill 概念");
    // 去掉 Skill 之后，其余部分依然语义等价。
    let expected = content.without_skills();
    assert_eq!(
        captured.semantic_digest(),
        expected.project_managed(&expected).semantic_digest()
    );
}

#[test]
fn renderers_are_deterministic() {
    let content = content_with_skill();
    for renderer in builtin_renderers() {
        let first = renderer.render(&content).expect("首次渲染");
        let second = renderer.render(&content).expect("再次渲染");
        assert_eq!(first, second, "{} 的渲染必须确定性", renderer.tool_id());
    }
}

#[test]
fn stable_paths_are_used() {
    let content = content_with_skill();

    let claude_files = render_to_files(
        renderer_for("claude").expect("渲染器存在").as_ref(),
        &content,
    );
    for expected in [
        ".claude/agents/reviewer.md",
        ".claude/skills/pdf/SKILL.md",
        claude::SETTINGS_PATH,
        claude::MCP_PATH,
    ] {
        assert!(claude_files.contains_key(expected), "缺少 {expected}");
    }

    let codex_files = render_to_files(
        renderer_for("codex").expect("渲染器存在").as_ref(),
        &content,
    );
    for expected in [
        ".codex/agents/reviewer.md",
        ".codex/skills/pdf/SKILL.md",
        codex::CONFIG_PATH,
    ] {
        assert!(codex_files.contains_key(expected), "缺少 {expected}");
    }

    let opencode_files = render_to_files(
        renderer_for("opencode").expect("渲染器存在").as_ref(),
        &content,
    );
    assert_eq!(
        opencode_files.keys().cloned().collect::<Vec<_>>(),
        vec![opencode::CONFIG_PATH.to_owned()]
    );
}

// ---------------------------------------------------------------------------
// 损失
// ---------------------------------------------------------------------------

#[test]
fn a_declared_capability_the_tool_cannot_provide_blocks_the_plan() {
    let mut content = portable_content();
    content.declared_capabilities.insert("skills".to_owned());

    let renderer = renderer_for("opencode").expect("渲染器存在");
    let rendered = renderer.render(&content).expect("渲染成功");
    assert!(rendered.is_blocked(), "声明能力不被支持时计划必须阻塞");
    let blocking = rendered.blocking_losses();
    assert_eq!(blocking.len(), 1);
    assert_eq!(blocking[0].subject, "skills");
    assert_eq!(blocking[0].field, "declared_capability");
    assert_eq!(blocking[0].severity, LossSeverity::Blocking);

    // Claude 支持 Skill，同一份内容不会阻塞。
    let claude = renderer_for("claude").expect("渲染器存在");
    assert!(!claude.render(&content).expect("渲染成功").is_blocked());
}

#[test]
fn unsupported_content_is_reported_but_never_silently_dropped() {
    // Codex 没有 SSE 传输：server 被跳过，但必须留下一条诊断。
    let mut content = portable_content();
    content
        .mcp_servers
        .insert("remote".to_owned(), remote_server(McpTransport::Sse));

    let renderer = renderer_for("codex").expect("渲染器存在");
    let rendered = renderer.render(&content).expect("渲染成功");
    let note = rendered
        .loss_report
        .iter()
        .find(|note| note.subject == "remote")
        .expect("必须有一条关于 remote 的诊断");
    assert_eq!(note.field, "mcp_server.transport");
    assert_eq!(note.severity, LossSeverity::Info);
    assert!(note.detail.contains("sse"));

    // OpenCode 的 Skill 同理。
    let renderer = renderer_for("opencode").expect("渲染器存在");
    let rendered = renderer.render(&content_with_skill()).expect("渲染成功");
    assert!(rendered
        .loss_report
        .iter()
        .any(|note| note.field == "skill" && note.subject == "pdf"));
}

#[test]
fn opencode_supports_http_but_not_sse() {
    let renderer = renderer_for("opencode").expect("渲染器存在");

    let mut http = portable_content();
    http.mcp_servers
        .insert("remote".to_owned(), remote_server(McpTransport::Http));
    let files = render_to_files(renderer.as_ref(), &http);
    let captured = renderer.capture(&files).expect("capture 成功");
    assert_eq!(
        captured.mcp_servers.get("remote").map(|s| s.transport),
        Some(McpTransport::Http)
    );

    let mut sse = portable_content();
    sse.mcp_servers
        .insert("remote".to_owned(), remote_server(McpTransport::Sse));
    let rendered = renderer.render(&sse).expect("渲染成功");
    assert!(rendered
        .loss_report
        .iter()
        .any(|note| note.subject == "remote" && note.field == "mcp_server.transport"));
}

// ---------------------------------------------------------------------------
// Secret
// ---------------------------------------------------------------------------

#[test]
fn secrets_are_rendered_as_placeholders_with_injection_descriptors() {
    let content = portable_content();
    for renderer in builtin_renderers() {
        let rendered = renderer.render(&content).expect("渲染成功");
        assert_eq!(
            rendered.secret_injections,
            vec![SecretInjection {
                server: "docs".to_owned(),
                env_key: "DOCS_API_TOKEN".to_owned(),
                secret_ref: "secret://docs/token".to_owned(),
            }],
            "{} 的注入描述符不符",
            renderer.tool_id()
        );

        let all: String = rendered
            .files
            .iter()
            .map(|(_, bytes)| String::from_utf8_lossy(bytes).into_owned())
            .collect();
        assert!(
            all.contains(SECRET_PLACEHOLDER_PREFIX),
            "{} 的产物里必须出现占位符",
            renderer.tool_id()
        );
        // 非敏感字面量照常写出。
        assert!(
            all.contains("info"),
            "{} 应当写出非敏感字面量",
            renderer.tool_id()
        );
    }
}

#[test]
fn a_literal_under_a_sensitive_key_is_rejected() {
    let mut content = portable_content();
    let server = content.mcp_servers.get_mut("docs").expect("server 存在");
    server.env.insert(
        "DOCS_API_TOKEN".to_owned(),
        SecretRefOrLiteral::literal("plain-token-value"),
    );

    for renderer in builtin_renderers() {
        let error = renderer.render(&content).expect_err("必须拒绝");
        assert_eq!(error.code(), "adapter.structured");
        assert!(
            error.to_string().contains("SecretRef"),
            "{} 的错误信息应当指明只能用 SecretRef：{error}",
            renderer.tool_id()
        );
    }
}

#[test]
fn a_credential_shaped_literal_is_rejected_even_under_a_harmless_key() {
    let mut content = portable_content();
    let server = content.mcp_servers.get_mut("docs").expect("server 存在");
    server.env.insert(
        "DOCS_ENDPOINT_HINT".to_owned(),
        SecretRefOrLiteral::literal("ghp_0123456789abcdefghijKLMN"),
    );
    let renderer = renderer_for("claude").expect("渲染器存在");
    let error = renderer.render(&content).expect_err("必须拒绝");
    assert!(error.to_string().contains("凭据"), "{error}");
}

#[test]
fn secret_placeholders_survive_a_round_trip() {
    let content = portable_content();
    for renderer in builtin_renderers() {
        let files = render_to_files(renderer.as_ref(), &content);
        let captured = renderer.capture(&files).expect("capture 成功");
        let server = captured.mcp_servers.get("docs").expect("server 存在");
        assert_eq!(
            server.env.get("DOCS_API_TOKEN"),
            Some(&SecretRefOrLiteral::secret_ref("secret://docs/token")),
            "{} 必须把占位符还原成 SecretRef",
            renderer.tool_id()
        );
        assert_eq!(
            server.env.get("LOG_LEVEL"),
            Some(&SecretRefOrLiteral::literal("info"))
        );
    }
}

// ---------------------------------------------------------------------------
// 不覆盖本地未管理内容
// ---------------------------------------------------------------------------

#[test]
fn json_merge_keeps_the_users_own_entries() {
    let content = portable_content();
    let renderer = renderer_for("claude").expect("渲染器存在");
    let rendered = renderer.render(&content).expect("渲染成功");

    let existing: BTreeMap<String, Vec<u8>> = BTreeMap::from([
        (
            claude::MCP_PATH.to_owned(),
            br#"{"mcpServers":{"my-own":{"command":"mine"}}}"#.to_vec(),
        ),
        (
            claude::SETTINGS_PATH.to_owned(),
            br#"{"theme":"dark","permissions":{"defaultMode":"acceptEdits"}}"#.to_vec(),
        ),
    ]);
    let merged: BTreeMap<String, Vec<u8>> = merge_rendered(&rendered, &existing)
        .expect("合并成功")
        .into_iter()
        .collect();

    let mcp: serde_json::Value =
        serde_json::from_slice(&merged[claude::MCP_PATH]).expect("合法 JSON");
    assert_eq!(mcp["mcpServers"]["my-own"]["command"], "mine");
    assert_eq!(mcp["mcpServers"]["docs"]["command"], "docs-mcp");

    let settings: serde_json::Value =
        serde_json::from_slice(&merged[claude::SETTINGS_PATH]).expect("合法 JSON");
    assert_eq!(settings["theme"], "dark");
    assert_eq!(settings["permissions"]["defaultMode"], "acceptEdits");
    assert_eq!(settings["permissions"]["allow"][0], "Read(src/**)");
}

#[test]
fn opencode_merge_keeps_the_users_own_keys() {
    let content = portable_content();
    let renderer = renderer_for("opencode").expect("渲染器存在");
    let rendered = renderer.render(&content).expect("渲染成功");
    let existing = BTreeMap::from([(
        opencode::CONFIG_PATH.to_owned(),
        br#"{"$schema":"https://opencode.ai/config.json","theme":"tokyonight","mcp":{"mine":{"type":"local"}}}"#.to_vec(),
    )]);
    let merged: BTreeMap<String, Vec<u8>> = merge_rendered(&rendered, &existing)
        .expect("合并成功")
        .into_iter()
        .collect();
    let value: serde_json::Value =
        serde_json::from_slice(&merged[opencode::CONFIG_PATH]).expect("合法 JSON");
    assert_eq!(value["$schema"], "https://opencode.ai/config.json");
    assert_eq!(value["theme"], "tokyonight");
    assert_eq!(value["mcp"]["mine"]["type"], "local");
    assert_eq!(value["mcp"]["docs"]["type"], "local");
}

#[test]
fn the_codex_managed_block_leaves_user_toml_untouched() {
    let content = portable_content();
    let renderer = renderer_for("codex").expect("渲染器存在");
    let rendered = renderer.render(&content).expect("渲染成功");

    let user_toml = "# 我自己的设置\nmodel = \"gpt-5\"\napproval_policy = \"on-request\"\n";
    let existing = BTreeMap::from([(codex::CONFIG_PATH.to_owned(), user_toml.as_bytes().to_vec())]);
    let merged: BTreeMap<String, Vec<u8>> = merge_rendered(&rendered, &existing)
        .expect("合并成功")
        .into_iter()
        .collect();

    let text = String::from_utf8(merged[codex::CONFIG_PATH].clone()).expect("合法 UTF-8");
    assert!(text.starts_with(user_toml), "用户内容必须逐字保留在最前面");
    assert!(text.contains(">>> envsync:agents/codex/config"));
    assert!(text.contains("[mcp_servers.docs]"));

    // 从合并结果里 capture 只会看到受管区块内的内容，用户的 `model` 不会被误当成受管。
    let captured = renderer.capture(&merged).expect("capture 成功");
    assert_eq!(captured.mcp_servers.len(), 1);
    assert!(captured.mcp_servers.contains_key("docs"));

    // 再次应用是幂等的：没有任何待写入的变化，用户的 TOML 也不会被再动一次。
    assert!(merge_rendered(&rendered, &merged)
        .expect("再次合并")
        .is_empty());
}

#[test]
fn re_applying_an_unchanged_config_writes_nothing() {
    let content = portable_content();
    for renderer in builtin_renderers() {
        let rendered = renderer.render(&content).expect("渲染成功");
        let files = render_to_files(renderer.as_ref(), &content);
        assert!(
            merge_rendered(&rendered, &files)
                .expect("再次合并")
                .is_empty(),
            "{} 的重复应用必须是幂等的",
            renderer.tool_id()
        );
    }
}

// ---------------------------------------------------------------------------
// verify：语义比对
// ---------------------------------------------------------------------------

#[test]
fn verify_ignores_formatting_and_unmanaged_entries() {
    let content = portable_content();
    let renderer = renderer_for("claude").expect("渲染器存在");
    let mut files = render_to_files(renderer.as_ref(), &content);

    // 目标工具重排了键、改了缩进，还加了自己的 server 与设置。
    files.insert(
        claude::MCP_PATH.to_owned(),
        br#"{"mcpServers":{"zzz-other":{"command":"other"},"docs":{"disabled":false,"env":{"LOG_LEVEL":"info","DOCS_API_TOKEN":"${ENVSYNC_SECRET:secret://docs/token}"},"args":["--root","docs"],"command":"docs-mcp","type":"stdio"}}}"#.to_vec(),
    );
    files.insert(
        claude::SETTINGS_PATH.to_owned(),
        br#"{"theme":"dark","permissions":{"ask":["WebFetch"],"deny":["Bash(rm:*)"],"allow":["Read(src/**)"],"defaultMode":"acceptEdits"}}"#.to_vec(),
    );
    renderer
        .verify(&content, &files)
        .expect("重排与额外条目不算漂移");
}

#[test]
fn verify_detects_a_changed_managed_value() {
    let content = portable_content();
    let renderer = renderer_for("claude").expect("渲染器存在");
    let mut files = render_to_files(renderer.as_ref(), &content);

    // 有人把受管 server 的命令换掉了。
    files.insert(
        claude::MCP_PATH.to_owned(),
        br#"{"mcpServers":{"docs":{"type":"stdio","command":"evil","args":["--root","docs"],"env":{},"disabled":false}}}"#.to_vec(),
    );
    let error = renderer.verify(&content, &files).expect_err("必须报漂移");
    assert_eq!(error.code(), "adapter.verify_failed");
}

#[test]
fn verify_detects_a_deleted_managed_agent() {
    let content = portable_content();
    let renderer = renderer_for("codex").expect("渲染器存在");
    let mut files = render_to_files(renderer.as_ref(), &content);
    files.remove(".codex/agents/reviewer.md");
    let error = renderer.verify(&content, &files).expect_err("必须报漂移");
    assert_eq!(error.code(), "adapter.verify_failed");
}

#[test]
fn capture_rejects_a_malformed_managed_block() {
    let renderer = renderer_for("codex").expect("渲染器存在");
    let broken = "# >>> envsync:agents/codex/config\nthis is not a key value line\n# <<< envsync:agents/codex/config\n";
    let files = BTreeMap::from([(codex::CONFIG_PATH.to_owned(), broken.as_bytes().to_vec())]);
    let error = renderer.capture(&files).expect_err("必须拒绝");
    assert_eq!(error.code(), "adapter.structured");
}

#[test]
fn capture_rejects_an_unknown_frontmatter_key() {
    let renderer = renderer_for("claude").expect("渲染器存在");
    let broken = "---\nname: x\nhooks: rm -rf /\n---\nbody\n";
    let files = BTreeMap::from([(".claude/agents/x.md".to_owned(), broken.as_bytes().to_vec())]);
    let error = renderer.capture(&files).expect_err("必须拒绝");
    assert_eq!(error.code(), "adapter.structured");
}

// ---------------------------------------------------------------------------
// 模型校验
// ---------------------------------------------------------------------------

#[test]
fn names_that_could_escape_a_path_are_rejected() {
    for bad in ["../evil", "a/b", "C:evil", ".hidden"] {
        let mut content = portable_content();
        let mut agent = reviewer();
        agent.name = bad.to_owned();
        content.agents = BTreeMap::from([(bad.to_owned(), agent)]);
        let renderer = renderer_for("claude").expect("渲染器存在");
        assert!(
            renderer.render(&content).is_err(),
            "名称 `{bad}` 必须被拒绝"
        );
    }
}

#[test]
fn a_rule_in_both_allow_and_deny_is_rejected() {
    let mut content = portable_content();
    content.permissions.allow.insert("Bash(rm:*)".to_owned());
    let renderer = renderer_for("claude").expect("渲染器存在");
    let error = renderer.render(&content).expect_err("必须拒绝");
    assert!(error.to_string().contains("allow"), "{error}");
}

#[test]
fn a_transport_without_its_required_field_is_rejected() {
    let mut content = portable_content();
    content.mcp_servers.insert(
        "broken".to_owned(),
        McpServerDefinition {
            name: "broken".to_owned(),
            transport: McpTransport::Http,
            command: None,
            url: None,
            env: BTreeMap::new(),
            enabled: true,
        },
    );
    let renderer = renderer_for("claude").expect("渲染器存在");
    assert!(renderer.render(&content).is_err());
}

#[test]
fn an_unknown_tool_id_has_no_renderer() {
    assert!(renderer_for("evil-tool").is_none());
    assert_eq!(builtin_renderers().len(), 3);
    let ids: Vec<&str> = builtin_renderers()
        .iter()
        .map(|renderer| renderer.tool_id())
        .collect();
    assert_eq!(ids, vec!["claude", "codex", "opencode"]);
}
