//! Claude Code 渲染器。
//!
//! # 路径与策略
//!
//! | 路径 | 策略 | 为什么 |
//! |---|---|---|
//! | `.claude/agents/<name>.md` | **Full File** | 目录由 EnvSync 独占，一个文件恰好是一个 Agent。整份内容都是受管内容，没有「用户在同一个文件里写了别的东西」这种情况，Managed Block 只会平白多出两行 marker |
//! | `.claude/skills/<name>/SKILL.md` | **Full File** | 同上 |
//! | `.claude/settings.json` | **结构化 JSON 合并** | 用户在这里写自己的模型、主题、hook 等设置。JSON **没有注释语法**，因此无法用 Managed Block 隔开；只能解析成对象后只替换 `permissions` 这一个键 |
//! | `.mcp.json` | **结构化 JSON 合并** | 用户会在这里登记自己的 MCP server。合并按 server 名进行：EnvSync 只写自己声明的那几个，其余原样保留 |
//!
//! # Secret
//!
//! MCP server 的环境变量里，凡是 SecretRef 都渲染成
//! [`SECRET_PLACEHOLDER_PREFIX`] 形式的占位符，真实取值**从不写进文件**；调用方拿
//! [`RenderedAgentConfig::secret_injections`] 在启动时注入。
//!
//! # 损失
//!
//! Claude Code 能表达统一模型里的全部四类内容，因此本渲染器只在**声明能力**层面产生
//! 损失：Bundle 声明了 [`ClaudeRenderer::supported_capabilities`] 之外的能力时，产出
//! 一条 [`LossSeverity::Blocking`] 诊断。

use std::collections::{BTreeMap, BTreeSet};

use envsync_domain::id::Digest32;

use super::{
    capability_losses, join_set, read_frontmatter, split_set, structured_error, write_frontmatter,
    AgentBundleContent, AgentDefinition, AgentModelError, AgentRenderer, CommandTemplate,
    McpServerDefinition, McpTransport, PermissionTemplate, RenderedAgentConfig, SecretRefOrLiteral,
    SkillDefinition, WriteStrategy,
};
use crate::AdapterError;

/// 工具标识。
pub const TOOL_ID: &str = "claude";

/// Agent 文件所在目录。
pub const AGENTS_DIR: &str = ".claude/agents";

/// Skill 目录。
pub const SKILLS_DIR: &str = ".claude/skills";

/// 用户设置文件。
pub const SETTINGS_PATH: &str = ".claude/settings.json";

/// MCP server 配置文件。
pub const MCP_PATH: &str = ".mcp.json";

/// Claude Code 支持的 capability。
const SUPPORTED: &[&str] = &[
    "agents",
    "mcp.http",
    "mcp.sse",
    "mcp.stdio",
    "model.override",
    "permissions",
    "skills",
];

/// Claude Code 渲染器。
#[derive(Debug, Clone, Copy, Default)]
pub struct ClaudeRenderer;

impl ClaudeRenderer {
    /// 构造渲染器。
    pub const fn new() -> Self {
        ClaudeRenderer
    }
}

impl AgentRenderer for ClaudeRenderer {
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

        if !content.mcp_servers.is_empty() {
            let mut servers = serde_json::Map::new();
            for server in content.mcp_servers.values() {
                servers.insert(server.name.clone(), render_server(server));
            }
            let document = serde_json::json!({ "mcpServers": servers });
            files.push((MCP_PATH.to_owned(), to_json_bytes(&document)?));
            strategies.insert(MCP_PATH.to_owned(), WriteStrategy::JsonMerge);
        }

        if !content.permissions.is_empty() {
            let document = serde_json::json!({
                "permissions": {
                    "allow": to_json_array(&content.permissions.allow),
                    "deny": to_json_array(&content.permissions.deny),
                    "ask": to_json_array(&content.permissions.ask),
                }
            });
            files.push((SETTINGS_PATH.to_owned(), to_json_bytes(&document)?));
            strategies.insert(SETTINGS_PATH.to_owned(), WriteStrategy::JsonMerge);
        }

        files.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(RenderedAgentConfig {
            files,
            secret_injections: content.secret_injections(),
            loss_report: capability_losses(TOOL_ID, content, SUPPORTED),
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

        if let Some(bytes) = files.get(MCP_PATH) {
            let document = parse_json(MCP_PATH, bytes)?;
            if let Some(servers) = document
                .get("mcpServers")
                .and_then(|value| value.as_object())
            {
                for (name, value) in servers {
                    let server = parse_server(name, value).map_err(to_adapter)?;
                    content.mcp_servers.insert(server.name.clone(), server);
                }
            }
        }

        if let Some(bytes) = files.get(SETTINGS_PATH) {
            let document = parse_json(SETTINGS_PATH, bytes)?;
            if let Some(permissions) = document.get("permissions") {
                content.permissions = PermissionTemplate {
                    allow: json_string_set(permissions.get("allow")),
                    deny: json_string_set(permissions.get("deny")),
                    ask: json_string_set(permissions.get("ask")),
                };
            }
        }

        Ok(content)
    }
}

// ---------------------------------------------------------------------------
// 渲染
// ---------------------------------------------------------------------------

/// Agent 文件：YAML frontmatter + 指令正文。
fn render_agent(agent: &AgentDefinition) -> Vec<u8> {
    let mut fields = vec![
        ("name".to_owned(), agent.name.clone()),
        ("description".to_owned(), agent.description.clone()),
    ];
    if let Some(model) = agent.model.as_ref() {
        fields.push(("model".to_owned(), model.clone()));
    }
    // `tools` 恒定写出（哪怕为空）：缺这一行与「一个工具都不许用」是两种不同的语义，
    // 前者会被 Claude Code 理解成「继承默认工具集」。
    fields.push(("tools".to_owned(), join_set(&agent.tools)));
    write_frontmatter(&fields, &agent.instructions)
}

/// Skill 文件：frontmatter + 正文；附件以重复的 `file` 行记录。
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

/// 一个 MCP server 的 JSON 表示。
fn render_server(server: &McpServerDefinition) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    object.insert(
        "type".to_owned(),
        serde_json::Value::String(server.transport.as_str().to_owned()),
    );
    if let Some(command) = server.command.as_ref() {
        object.insert(
            "command".to_owned(),
            serde_json::Value::String(command.program.clone()),
        );
        object.insert(
            "args".to_owned(),
            serde_json::Value::Array(
                command
                    .args
                    .iter()
                    .map(|arg| serde_json::Value::String(arg.clone()))
                    .collect(),
            ),
        );
    }
    if let Some(url) = server.url.as_ref() {
        object.insert("url".to_owned(), serde_json::Value::String(url.clone()));
    }
    let env: serde_json::Map<String, serde_json::Value> = server
        .env
        .iter()
        .map(|(key, value)| (key.clone(), serde_json::Value::String(value.to_rendered())))
        .collect();
    object.insert("env".to_owned(), serde_json::Value::Object(env));
    object.insert(
        "disabled".to_owned(),
        serde_json::Value::Bool(!server.enabled),
    );
    serde_json::Value::Object(object)
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

/// 从 JSON 还原一个 MCP server 定义。
///
/// 这是共用逻辑：Claude 与 OpenCode 的 JSON 形状不同，但「传输 + 命令/URL + env +
/// 开关」这四件事是统一模型定义的，解析器只需要各自把键名对上。
pub(super) fn parse_server(
    name: &str,
    value: &serde_json::Value,
) -> Result<McpServerDefinition, AgentModelError> {
    let object = value
        .as_object()
        .ok_or_else(|| AgentModelError::UnexpectedShape {
            tool: TOOL_ID,
            detail: format!("MCP server `{name}` 不是一个对象"),
        })?;
    let transport_text = object
        .get("type")
        .and_then(|value| value.as_str())
        .unwrap_or("stdio");
    let transport =
        McpTransport::parse(transport_text).ok_or_else(|| AgentModelError::UnexpectedShape {
            tool: TOOL_ID,
            detail: format!("MCP server `{name}` 的传输方式 `{transport_text}` 未知"),
        })?;
    let command = object
        .get("command")
        .and_then(|value| value.as_str())
        .map(|program| CommandTemplate {
            program: program.to_owned(),
            args: object
                .get("args")
                .and_then(|value| value.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
        });
    let url = object
        .get("url")
        .and_then(|value| value.as_str())
        .map(str::to_owned);
    let env = object
        .get("env")
        .and_then(|value| value.as_object())
        .map(|items| {
            items
                .iter()
                .filter_map(|(key, value)| {
                    value
                        .as_str()
                        .map(|text| (key.clone(), SecretRefOrLiteral::from_rendered(text)))
                })
                .collect()
        })
        .unwrap_or_default();
    // `disabled` 缺席等于「启用」：这是 Claude Code 的默认语义，不是我们的猜测。
    let enabled = !object
        .get("disabled")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    Ok(McpServerDefinition {
        name: name.to_owned(),
        transport,
        command,
        url,
        env,
        enabled,
    })
}

// ---------------------------------------------------------------------------
// 共用辅助
// ---------------------------------------------------------------------------

/// 把 JSON 值写成带结尾换行的 pretty 字节。
pub(super) fn to_json_bytes(value: &serde_json::Value) -> Result<Vec<u8>, AdapterError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| structured_error(TOOL_ID, format!("JSON 序列化失败：{error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// 解析一个 JSON 文件。
pub(super) fn parse_json(path: &str, bytes: &[u8]) -> Result<serde_json::Value, AdapterError> {
    serde_json::from_slice(bytes)
        .map_err(|error| structured_error(TOOL_ID, format!("`{path}` 不是合法 JSON：{error}")))
}

/// 集合到 JSON 数组。
pub(super) fn to_json_array(items: &BTreeSet<String>) -> serde_json::Value {
    serde_json::Value::Array(
        items
            .iter()
            .map(|item| serde_json::Value::String(item.clone()))
            .collect(),
    )
}

/// JSON 数组到集合；非数组或缺席时返回空集。
pub(super) fn json_string_set(value: Option<&serde_json::Value>) -> BTreeSet<String> {
    value
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn to_adapter(error: AgentModelError) -> AdapterError {
    error.into_adapter(TOOL_ID)
}
