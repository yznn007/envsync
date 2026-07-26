//! OpenCode 渲染器。
//!
//! # 路径与策略
//!
//! | 路径 | 策略 | 为什么 |
//! |---|---|---|
//! | `opencode.json` | **结构化 JSON 合并** | OpenCode 把 agent、MCP server 与权限**全部**放在这一个用户可编辑的 JSON 里。它没有注释语法，无法用 Managed Block；也不能整份替换，否则用户的 `$schema`、`theme`、`provider` 等设置会被抹掉。因此只能解析成对象后按键合并：EnvSync 只写 `agent`、`mcp`、`permission` 三个键下自己声明的条目 |
//!
//! 与 Claude / Codex 不同，这里**没有** Full File 产出：OpenCode 没有「一个 Agent 一个
//! 文件」的布局，所有东西都在同一份 JSON 里。
//!
//! # 损失
//!
//! * **Skill**：OpenCode 没有 Skill 概念，每个 Skill 产出一条
//!   [`LossSeverity::Info`] 诊断；Bundle 若**声明**了 `skills` 能力，还会额外得到一条
//!   [`LossSeverity::Blocking`] 诊断，计划必须因此阻塞。
//! * **SSE 传输**：OpenCode 只有 `local`（stdio）与 `remote`（HTTP）两种，SSE server
//!   被跳过并记入损失。

use std::collections::BTreeMap;

use super::claude::{json_string_set, parse_json, to_json_array, to_json_bytes};
use super::{
    capability_losses, structured_error, AgentBundleContent, AgentDefinition, AgentModelError,
    AgentRenderer, CommandTemplate, LossNote, LossSeverity, McpServerDefinition, McpTransport,
    PermissionTemplate, RenderedAgentConfig, SecretRefOrLiteral, WriteStrategy,
};
use crate::AdapterError;

/// 工具标识。
pub const TOOL_ID: &str = "opencode";

/// 配置文件路径。
pub const CONFIG_PATH: &str = "opencode.json";

/// OpenCode 支持的 capability。
const SUPPORTED: &[&str] = &[
    "agents",
    "mcp.http",
    "mcp.stdio",
    "model.override",
    "permissions",
];

/// OpenCode 渲染器。
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenCodeRenderer;

impl OpenCodeRenderer {
    /// 构造渲染器。
    pub const fn new() -> Self {
        OpenCodeRenderer
    }
}

impl AgentRenderer for OpenCodeRenderer {
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

        let mut loss_report = capability_losses(TOOL_ID, content, SUPPORTED);
        for skill in content.skills.values() {
            loss_report.push(LossNote {
                tool: TOOL_ID,
                subject: skill.name.clone(),
                field: "skill",
                detail: "OpenCode 没有 Skill 的等价概念，该 Skill 未被渲染".to_owned(),
                severity: LossSeverity::Info,
            });
        }

        let mut document = serde_json::Map::new();

        if !content.agents.is_empty() {
            let mut agents = serde_json::Map::new();
            for agent in content.agents.values() {
                agents.insert(agent.name.clone(), render_agent(agent));
            }
            document.insert("agent".to_owned(), serde_json::Value::Object(agents));
        }

        let mut rendered_servers = serde_json::Map::new();
        let mut rendered_names: Vec<String> = Vec::new();
        for server in content.mcp_servers.values() {
            match server.transport {
                McpTransport::Stdio | McpTransport::Http => {
                    rendered_servers.insert(server.name.clone(), render_server(server));
                    rendered_names.push(server.name.clone());
                }
                McpTransport::Sse => loss_report.push(LossNote {
                    tool: TOOL_ID,
                    subject: server.name.clone(),
                    field: "mcp_server.transport",
                    detail:
                        "OpenCode 只有 local（stdio）与 remote（HTTP）两种传输，SSE server 未被渲染"
                            .to_owned(),
                    severity: LossSeverity::Info,
                }),
            }
        }
        if !rendered_servers.is_empty() {
            document.insert(
                "mcp".to_owned(),
                serde_json::Value::Object(rendered_servers),
            );
        }

        if !content.permissions.is_empty() {
            document.insert(
                "permission".to_owned(),
                serde_json::json!({
                    "allow": to_json_array(&content.permissions.allow),
                    "deny": to_json_array(&content.permissions.deny),
                    "ask": to_json_array(&content.permissions.ask),
                }),
            );
        }

        let mut files = Vec::new();
        let mut strategies = BTreeMap::new();
        if !document.is_empty() {
            files.push((
                CONFIG_PATH.to_owned(),
                to_json_bytes(&serde_json::Value::Object(document))
                    .map_err(|error| structured_error(TOOL_ID, error.to_string()))?,
            ));
            strategies.insert(CONFIG_PATH.to_owned(), WriteStrategy::JsonMerge);
        }

        loss_report.sort();
        let secret_injections = content
            .secret_injections()
            .into_iter()
            .filter(|injection| rendered_names.iter().any(|name| name == &injection.server))
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
        let Some(bytes) = files.get(CONFIG_PATH) else {
            return Ok(content);
        };
        let document = parse_json(CONFIG_PATH, bytes)
            .map_err(|error| structured_error(TOOL_ID, error.to_string()))?;

        if let Some(agents) = document.get("agent").and_then(|value| value.as_object()) {
            for (name, value) in agents {
                let agent = parse_agent(name, value).map_err(to_adapter)?;
                content.agents.insert(agent.name.clone(), agent);
            }
        }
        if let Some(servers) = document.get("mcp").and_then(|value| value.as_object()) {
            for (name, value) in servers {
                let server = parse_server(name, value).map_err(to_adapter)?;
                content.mcp_servers.insert(server.name.clone(), server);
            }
        }
        if let Some(permission) = document.get("permission") {
            content.permissions = PermissionTemplate {
                allow: json_string_set(permission.get("allow")),
                deny: json_string_set(permission.get("deny")),
                ask: json_string_set(permission.get("ask")),
            };
        }
        Ok(content)
    }
}

// ---------------------------------------------------------------------------
// 渲染
// ---------------------------------------------------------------------------

fn render_agent(agent: &AgentDefinition) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    object.insert(
        "description".to_owned(),
        serde_json::Value::String(agent.description.clone()),
    );
    object.insert(
        "prompt".to_owned(),
        serde_json::Value::String(agent.instructions.clone()),
    );
    if let Some(model) = agent.model.as_ref() {
        object.insert("model".to_owned(), serde_json::Value::String(model.clone()));
    }
    // OpenCode 的 `tools` 是「工具名 -> 布尔」而不是列表：统一模型里的集合语义是
    // 「这些工具被允许」，因此全部写成 `true`，不发明「显式禁用」这种模型里没有的概念。
    let tools: serde_json::Map<String, serde_json::Value> = agent
        .tools
        .iter()
        .map(|tool| (tool.clone(), serde_json::Value::Bool(true)))
        .collect();
    object.insert("tools".to_owned(), serde_json::Value::Object(tools));
    serde_json::Value::Object(object)
}

fn render_server(server: &McpServerDefinition) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    let kind = if server.transport.is_local() {
        "local"
    } else {
        "remote"
    };
    object.insert(
        "type".to_owned(),
        serde_json::Value::String(kind.to_owned()),
    );
    if let Some(command) = server.command.as_ref() {
        let mut parts = vec![serde_json::Value::String(command.program.clone())];
        parts.extend(
            command
                .args
                .iter()
                .map(|arg| serde_json::Value::String(arg.clone())),
        );
        object.insert("command".to_owned(), serde_json::Value::Array(parts));
    }
    if let Some(url) = server.url.as_ref() {
        object.insert("url".to_owned(), serde_json::Value::String(url.clone()));
    }
    let environment: serde_json::Map<String, serde_json::Value> = server
        .env
        .iter()
        .map(|(key, value)| (key.clone(), serde_json::Value::String(value.to_rendered())))
        .collect();
    object.insert(
        "environment".to_owned(),
        serde_json::Value::Object(environment),
    );
    object.insert(
        "enabled".to_owned(),
        serde_json::Value::Bool(server.enabled),
    );
    serde_json::Value::Object(object)
}

// ---------------------------------------------------------------------------
// 解析
// ---------------------------------------------------------------------------

fn parse_agent(name: &str, value: &serde_json::Value) -> Result<AgentDefinition, AgentModelError> {
    let object = value
        .as_object()
        .ok_or_else(|| AgentModelError::UnexpectedShape {
            tool: TOOL_ID,
            detail: format!("agent `{name}` 不是一个对象"),
        })?;
    Ok(AgentDefinition {
        name: name.to_owned(),
        description: string_field(object, "description"),
        instructions: string_field(object, "prompt"),
        tools: object
            .get("tools")
            .and_then(|value| value.as_object())
            .map(|tools| {
                tools
                    .iter()
                    .filter(|(_, enabled)| enabled.as_bool().unwrap_or(false))
                    .map(|(tool, _)| tool.clone())
                    .collect()
            })
            .unwrap_or_default(),
        model: object
            .get("model")
            .and_then(|value| value.as_str())
            .map(str::to_owned),
    })
}

fn parse_server(
    name: &str,
    value: &serde_json::Value,
) -> Result<McpServerDefinition, AgentModelError> {
    let object = value
        .as_object()
        .ok_or_else(|| AgentModelError::UnexpectedShape {
            tool: TOOL_ID,
            detail: format!("MCP server `{name}` 不是一个对象"),
        })?;
    let kind = object
        .get("type")
        .and_then(|value| value.as_str())
        .unwrap_or("local");
    let transport = match kind {
        "local" => McpTransport::Stdio,
        "remote" => McpTransport::Http,
        other => {
            return Err(AgentModelError::UnexpectedShape {
                tool: TOOL_ID,
                detail: format!("MCP server `{name}` 的类型 `{other}` 未知"),
            })
        }
    };
    let command = object
        .get("command")
        .and_then(|value| value.as_array())
        .and_then(|parts| {
            let mut iter = parts.iter().filter_map(|part| part.as_str());
            let program = iter.next()?.to_owned();
            Some(CommandTemplate {
                program,
                args: iter.map(str::to_owned).collect(),
            })
        });
    Ok(McpServerDefinition {
        name: name.to_owned(),
        transport,
        command,
        url: object
            .get("url")
            .and_then(|value| value.as_str())
            .map(str::to_owned),
        env: object
            .get("environment")
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
            .unwrap_or_default(),
        enabled: object
            .get("enabled")
            .and_then(|value| value.as_bool())
            .unwrap_or(true),
    })
}

fn string_field(object: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
    object
        .get(key)
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_owned()
}

fn to_adapter(error: AgentModelError) -> AdapterError {
    error.into_adapter(TOOL_ID)
}
