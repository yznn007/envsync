//! Codex CLI 渲染器。
//!
//! # 路径与策略
//!
//! | 路径 | 策略 | 为什么 |
//! |---|---|---|
//! | `.codex/agents/<name>.md` | **Full File** | 目录由 EnvSync 独占，一个文件恰好是一个 Agent |
//! | `.codex/skills/<name>/SKILL.md` | **Full File** | 同上 |
//! | `.codex/config.toml` | **Managed Block** | 这是 Codex 的主配置文件，用户在里面写自己的模型、审批策略、沙箱设置。TOML **有 `#` 行注释**，因此可以用 Managed Block 把受管内容与用户内容在同一个文件里清晰隔开——这比 JSON 那条「只能解析后合并」的路子更透明：用户一眼就看得出哪几行是 EnvSync 写的 |
//!
//! # 为什么这里敢自己解析 TOML
//!
//! 受管区块里的内容**只由本模块写入**：区块外的用户 TOML 从不被解析，区块内的字节是
//! 本文件 [`render_config_block`] 产生的严格子集（只有 `[表头]`、`key = "字符串"`、
//! `key = ["字符串", …]` 与 `key = true|false` 四种行）。因此
//! [`parse_config_block`] 只需要认得这四种形态，遇到任何别的东西一律报错，**绝不猜**。
//!
//! 这条边界是有意划的：引入一个完整 TOML 解析器意味着让用户文件里任意一段 TOML 都能
//! 影响我们的解析路径，而我们真正需要读回来的只有自己写下的那几行。取值在
//! [`super::validate_config_value`] 里已经排除了引号、反斜杠与控制字符，所以子集写出
//! 器不需要转义规则——不实现转义比实现一半安全。
//!
//! # 损失
//!
//! Codex 没有远端 MCP 传输（SSE / Streamable HTTP）的等价配置，因此
//! [`McpTransport::Sse`] 与 [`McpTransport::Http`] 的 server 会被跳过并记入
//! [`RenderedAgentConfig::loss_report`]；Bundle 声明了 `mcp.sse` / `mcp.http` 时，
//! 那条声明能力损失是 [`super::LossSeverity::Blocking`] 的。

use std::collections::{BTreeMap, BTreeSet};

use envsync_core::render::extract_managed_block;
use envsync_domain::id::{Digest32, ResourceId};

use super::{
    capability_losses, join_set, read_frontmatter, split_set, structured_error, write_frontmatter,
    AgentBundleContent, AgentDefinition, AgentModelError, AgentRenderer, CommandTemplate, LossNote,
    LossSeverity, McpServerDefinition, McpTransport, PermissionTemplate, RenderedAgentConfig,
    SecretRefOrLiteral, SkillDefinition, WriteStrategy, COMMENT_PREFIX,
};
use crate::AdapterError;

/// 工具标识。
pub const TOOL_ID: &str = "codex";

/// Agent 文件所在目录。
pub const AGENTS_DIR: &str = ".codex/agents";

/// Skill 目录。
pub const SKILLS_DIR: &str = ".codex/skills";

/// 主配置文件。
pub const CONFIG_PATH: &str = ".codex/config.toml";

/// 受管区块的资源标识文本。
pub const CONFIG_RESOURCE: &str = "agents/codex/config";

/// 权限模板在配置里的表名。
const PERMISSIONS_TABLE: &str = "envsync_permissions";

/// Codex CLI 支持的 capability。
const SUPPORTED: &[&str] = &[
    "agents",
    "mcp.stdio",
    "model.override",
    "permissions",
    "skills",
];

/// Codex CLI 渲染器。
#[derive(Debug, Clone, Copy, Default)]
pub struct CodexRenderer;

impl CodexRenderer {
    /// 构造渲染器。
    pub const fn new() -> Self {
        CodexRenderer
    }
}

/// 受管区块的资源标识。
fn config_resource() -> ResourceId {
    ResourceId::parse(CONFIG_RESOURCE).expect("常量资源标识合法")
}

impl AgentRenderer for CodexRenderer {
    fn tool_id(&self) -> &'static str {
        TOOL_ID
    }

    fn supported_capabilities(&self) -> &'static [&'static str] {
        SUPPORTED
    }

    fn render(&self, content: &AgentBundleContent) -> Result<RenderedAgentConfig, AdapterError> {
        content
            .validate()
            .map_err(|error| error.into_adapter(TOOL_ID))?;

        let mut files: Vec<(String, Vec<u8>)> = Vec::new();
        let mut strategies: BTreeMap<String, WriteStrategy> = BTreeMap::new();
        let mut loss_report = capability_losses(TOOL_ID, content, SUPPORTED);

        for agent in content.agents.values() {
            let path = format!("{AGENTS_DIR}/{}.md", agent.name);
            files.push((path.clone(), render_agent(agent)));
            strategies.insert(path, WriteStrategy::FullFile);
        }
        for skill in content.skills.values() {
            let path = format!("{SKILLS_DIR}/{}/SKILL.md", skill.name);
            files.push((path.clone(), render_skill(skill)));
            strategies.insert(path, WriteStrategy::FullFile);
        }

        let mut local_servers: Vec<&McpServerDefinition> = Vec::new();
        for server in content.mcp_servers.values() {
            if server.transport.is_local() {
                local_servers.push(server);
            } else {
                loss_report.push(LossNote {
                    tool: TOOL_ID,
                    subject: server.name.clone(),
                    field: "mcp_server.transport",
                    detail: format!(
                        "Codex 没有 `{}` 传输的等价配置，该 MCP server 未被渲染",
                        server.transport.as_str()
                    ),
                    severity: LossSeverity::Info,
                });
            }
        }

        if !local_servers.is_empty() || !content.permissions.is_empty() {
            let block = render_config_block(&local_servers, &content.permissions);
            files.push((CONFIG_PATH.to_owned(), block.into_bytes()));
            strategies.insert(
                CONFIG_PATH.to_owned(),
                WriteStrategy::ManagedBlock {
                    resource: config_resource(),
                    comment_prefix: COMMENT_PREFIX.to_owned(),
                },
            );
        }

        files.sort_by(|left, right| left.0.cmp(&right.0));
        loss_report.sort();
        // 只为真正渲染出来的 server 产生注入描述符：跳过的 server 不会被启动，
        // 给它注入秘密等于把秘密交给一个没人会读的地方。
        let rendered_names: BTreeSet<&str> = local_servers
            .iter()
            .map(|server| server.name.as_str())
            .collect();
        let secret_injections = content
            .secret_injections()
            .into_iter()
            .filter(|injection| rendered_names.contains(injection.server.as_str()))
            .collect();

        Ok(RenderedAgentConfig {
            files,
            secret_injections,
            loss_report,
            strategies,
        })
    }

    fn capture(
        &self,
        files: &BTreeMap<String, Vec<u8>>,
    ) -> Result<AgentBundleContent, AdapterError> {
        let mut content = AgentBundleContent::default();

        for (path, bytes) in files {
            if let Some(name) = path
                .strip_prefix(&format!("{AGENTS_DIR}/"))
                .and_then(|rest| rest.strip_suffix(".md"))
            {
                let agent = parse_agent(name, bytes).map_err(to_adapter)?;
                content.agents.insert(agent.name.clone(), agent);
            } else if let Some(name) = path
                .strip_prefix(&format!("{SKILLS_DIR}/"))
                .and_then(|rest| rest.strip_suffix("/SKILL.md"))
            {
                let skill = parse_skill(name, bytes).map_err(to_adapter)?;
                content.skills.insert(skill.name.clone(), skill);
            }
        }

        if let Some(bytes) = files.get(CONFIG_PATH) {
            // 只解析受管区块：区块外是用户自己的 TOML，我们既不解析也不理解它。
            let resource = config_resource();
            let block = extract_managed_block(bytes, &resource)?;
            if let Some(block) = block {
                let text = String::from_utf8(block).map_err(|_| {
                    structured_error(TOOL_ID, "受管区块内容不是合法 UTF-8".to_owned())
                })?;
                let (servers, permissions) = parse_config_block(&text).map_err(to_adapter)?;
                content.mcp_servers = servers;
                content.permissions = permissions;
            }
        }

        Ok(content)
    }
}

// ---------------------------------------------------------------------------
// 渲染
// ---------------------------------------------------------------------------

fn render_agent(agent: &AgentDefinition) -> Vec<u8> {
    let mut fields = vec![
        ("name".to_owned(), agent.name.clone()),
        ("description".to_owned(), agent.description.clone()),
    ];
    if let Some(model) = agent.model.as_ref() {
        fields.push(("model".to_owned(), model.clone()));
    }
    fields.push(("tools".to_owned(), join_set(&agent.tools)));
    write_frontmatter(&fields, &agent.instructions)
}

fn render_skill(skill: &SkillDefinition) -> Vec<u8> {
    let mut fields = vec![
        ("name".to_owned(), skill.name.clone()),
        ("description".to_owned(), skill.description.clone()),
    ];
    for (path, digest) in &skill.files {
        fields.push(("file".to_owned(), format!("{path} {}", digest.to_hex())));
    }
    write_frontmatter(&fields, &skill.body)
}

/// 生成受管区块的内容（TOML 严格子集）。
fn render_config_block(
    servers: &[&McpServerDefinition],
    permissions: &PermissionTemplate,
) -> String {
    let mut out = String::new();
    for server in servers {
        out.push_str(&format!("[mcp_servers.{}]\n", server.name));
        out.push_str(&format!("transport = \"{}\"\n", server.transport.as_str()));
        if let Some(command) = server.command.as_ref() {
            out.push_str(&format!("command = \"{}\"\n", command.program));
            out.push_str(&format!("args = {}\n", toml_list(&command.args)));
        }
        if let Some(url) = server.url.as_ref() {
            out.push_str(&format!("url = \"{url}\"\n"));
        }
        out.push_str(&format!("enabled = {}\n", server.enabled));
        for (key, value) in &server.env {
            // 与另外两个渲染器完全一致：SecretRef 写成占位符，字面量原样写出。
            // 统一形态让「配置文件里绝不出现秘密取值」这条性质只需要在一个地方检查。
            out.push_str(&format!("env.{key} = \"{}\"\n", value.to_rendered()));
        }
    }
    if !permissions.is_empty() {
        out.push_str(&format!("[{PERMISSIONS_TABLE}]\n"));
        out.push_str(&format!(
            "allow = {}\n",
            toml_list_from_set(&permissions.allow)
        ));
        out.push_str(&format!(
            "deny = {}\n",
            toml_list_from_set(&permissions.deny)
        ));
        out.push_str(&format!("ask = {}\n", toml_list_from_set(&permissions.ask)));
    }
    out
}

fn toml_list(items: &[String]) -> String {
    let inner = items
        .iter()
        .map(|item| format!("\"{item}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{inner}]")
}

fn toml_list_from_set(items: &BTreeSet<String>) -> String {
    let owned: Vec<String> = items.iter().cloned().collect();
    toml_list(&owned)
}

// ---------------------------------------------------------------------------
// 解析
// ---------------------------------------------------------------------------

fn parse_agent(name: &str, bytes: &[u8]) -> Result<AgentDefinition, AgentModelError> {
    let (fields, body) = read_frontmatter(TOOL_ID, bytes)?;
    let mut agent = AgentDefinition {
        name: name.to_owned(),
        instructions: body,
        ..AgentDefinition::default()
    };
    for (key, value) in fields {
        match key.as_str() {
            "name" => agent.name = value,
            "description" => agent.description = value,
            "model" => agent.model = Some(value),
            "tools" => agent.tools = split_set(&value),
            other => {
                return Err(AgentModelError::UnexpectedShape {
                    tool: TOOL_ID,
                    detail: format!("Agent frontmatter 中出现未知键 `{other}`"),
                })
            }
        }
    }
    Ok(agent)
}

fn parse_skill(name: &str, bytes: &[u8]) -> Result<SkillDefinition, AgentModelError> {
    let (fields, body) = read_frontmatter(TOOL_ID, bytes)?;
    let mut skill = SkillDefinition {
        name: name.to_owned(),
        body,
        ..SkillDefinition::default()
    };
    for (key, value) in fields {
        match key.as_str() {
            "name" => skill.name = value,
            "description" => skill.description = value,
            "file" => {
                let (path, digest) =
                    value
                        .rsplit_once(' ')
                        .ok_or_else(|| AgentModelError::UnexpectedShape {
                            tool: TOOL_ID,
                            detail: "Skill 附件行必须是 `file: <路径> <摘要>`".to_owned(),
                        })?;
                let digest = digest.parse::<Digest32>().map_err(|error| {
                    AgentModelError::UnexpectedShape {
                        tool: TOOL_ID,
                        detail: format!("Skill 附件摘要非法：{error}"),
                    }
                })?;
                skill.files.insert(path.to_owned(), digest);
            }
            other => {
                return Err(AgentModelError::UnexpectedShape {
                    tool: TOOL_ID,
                    detail: format!("Skill frontmatter 中出现未知键 `{other}`"),
                })
            }
        }
    }
    Ok(skill)
}

/// TOML 严格子集里的一个取值。
enum TomlValue {
    Text(String),
    List(Vec<String>),
    Bool(bool),
}

/// 解析受管区块里的 TOML 严格子集。
///
/// 只接受四种行：空行、`[表头]`、`key = 取值`，以及以 `#` 开头的注释。取值只能是
/// `"字符串"`、`["字符串", …]` 或 `true` / `false`。任何别的形态都返回错误。
fn parse_config_block(
    text: &str,
) -> Result<(BTreeMap<String, McpServerDefinition>, PermissionTemplate), AgentModelError> {
    let mut servers: BTreeMap<String, McpServerDefinition> = BTreeMap::new();
    let mut permissions = PermissionTemplate::default();
    let mut section: Option<String> = None;

    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let shape = |detail: String| AgentModelError::UnexpectedShape {
            tool: TOOL_ID,
            detail: format!("受管区块第 {} 行：{detail}", index + 1),
        };
        if let Some(header) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            if let Some(name) = header.strip_prefix("mcp_servers.") {
                servers
                    .entry(name.to_owned())
                    .or_insert(McpServerDefinition {
                        name: name.to_owned(),
                        ..McpServerDefinition::default()
                    });
                section = Some(header.to_owned());
            } else if header == PERMISSIONS_TABLE {
                section = Some(header.to_owned());
            } else {
                return Err(shape(format!("未知表头 `{header}`")));
            }
            continue;
        }
        let Some((key, value)) = line.split_once(" = ") else {
            return Err(shape("不是 `key = value` 形式".to_owned()));
        };
        let value = parse_toml_value(value).ok_or_else(|| shape(format!("取值 `{value}` 非法")))?;
        let Some(section) = section.as_deref() else {
            return Err(shape("键出现在任何表头之前".to_owned()));
        };
        if section == PERMISSIONS_TABLE {
            let TomlValue::List(items) = value else {
                return Err(shape("权限字段必须是字符串列表".to_owned()));
            };
            let items: BTreeSet<String> = items.into_iter().collect();
            match key {
                "allow" => permissions.allow = items,
                "deny" => permissions.deny = items,
                "ask" => permissions.ask = items,
                other => return Err(shape(format!("未知权限字段 `{other}`"))),
            }
            continue;
        }
        let name = section
            .strip_prefix("mcp_servers.")
            .ok_or_else(|| shape("键出现在未知表里".to_owned()))?;
        let server = servers
            .get_mut(name)
            .ok_or_else(|| shape("键出现在未声明的 server 表里".to_owned()))?;
        apply_server_field(server, key, value).map_err(shape)?;
    }

    Ok((servers, permissions))
}

/// 把一行键值对应用到 server 定义上。
fn apply_server_field(
    server: &mut McpServerDefinition,
    key: &str,
    value: TomlValue,
) -> Result<(), String> {
    match (key, value) {
        ("transport", TomlValue::Text(text)) => {
            server.transport =
                McpTransport::parse(&text).ok_or_else(|| format!("未知传输方式 `{text}`"))?;
        }
        ("command", TomlValue::Text(text)) => {
            let args = server
                .command
                .take()
                .map(|command| command.args)
                .unwrap_or_default();
            server.command = Some(CommandTemplate {
                program: text,
                args,
            });
        }
        ("args", TomlValue::List(items)) => {
            let command = server.command.get_or_insert_with(CommandTemplate::default);
            command.args = items;
        }
        ("url", TomlValue::Text(text)) => server.url = Some(text),
        ("enabled", TomlValue::Bool(flag)) => server.enabled = flag,
        (dotted, TomlValue::Text(text)) => {
            let Some(env_key) = dotted.strip_prefix("env.") else {
                return Err(format!("未知字段 `{dotted}`"));
            };
            server
                .env
                .insert(env_key.to_owned(), SecretRefOrLiteral::from_rendered(&text));
        }
        (other, _) => return Err(format!("字段 `{other}` 的取值类型不符")),
    }
    Ok(())
}

/// 解析严格子集里的一个取值。
fn parse_toml_value(text: &str) -> Option<TomlValue> {
    let text = text.trim();
    if text == "true" {
        return Some(TomlValue::Bool(true));
    }
    if text == "false" {
        return Some(TomlValue::Bool(false));
    }
    if let Some(inner) = text
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    {
        // 子集写出器从不转义，因此内部再出现引号或反斜杠就说明这行不是我们写的。
        if inner.contains('"') || inner.contains('\\') {
            return None;
        }
        return Some(TomlValue::Text(inner.to_owned()));
    }
    let inner = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))?;
    if inner.trim().is_empty() {
        return Some(TomlValue::List(Vec::new()));
    }
    let mut items = Vec::new();
    for part in inner.split(',') {
        let part = part.trim();
        let value = part
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))?;
        if value.contains('"') || value.contains('\\') {
            return None;
        }
        items.push(value.to_owned());
    }
    Some(TomlValue::List(items))
}

fn to_adapter(error: AgentModelError) -> AdapterError {
    error.into_adapter(TOOL_ID)
}
