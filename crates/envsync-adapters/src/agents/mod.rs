//! 统一 Agent / Skill / MCP 模型，以及到具体工具配置的渲染器。
//!
//! 设计文档 §7 要求「适配器将统一模型渲染为各工具格式，并保留不支持字段的诊断信息」。
//! 本模块定义那个统一模型（[`AgentBundleContent`]）与渲染契约（[`AgentRenderer`]），
//! 三个具体渲染器分别在 [`claude`]、[`codex`]、[`opencode`] 里。
//!
//! # 四条硬约束
//!
//! 1. **渲染只产生文件与注入描述符，绝不启动任何进程。**
//!    [`AgentRenderer::render`] 是纯函数：它不 spawn MCP server、不发网络请求、不读
//!    文件系统。MCP server 的启动是目标工具自己的事，EnvSync 只负责把配置摆对。
//! 2. **秘密只以引用出现。** [`McpServerDefinition::env`] 里凡是敏感键名一律**只能**
//!    是 [`SecretRefOrLiteral::SecretRef`]；渲染出的文件里写的是占位符
//!    [`SECRET_PLACEHOLDER_PREFIX`]，真实取值由运行时按
//!    [`SecretInjection`] 从 Vault 解析后注入进程环境，**从不落盘**。
//! 3. **不支持的字段绝不静默丢失。** 目标工具表达不了的东西一律进
//!    [`RenderedAgentConfig::loss_report`]；Bundle 声明了目标工具不支持的 capability
//!    时，损失条目的严重级别是 [`LossSeverity::Blocking`]，计划必须因此阻塞，
//!    除非用户显式接受一条 loss policy。
//! 4. **不覆盖本地未管理内容。** 每条产出路径都带一个写入策略
//!    （[`WriteStrategy`]），由 [`merge_rendered`] 施加到现有文件上。
//!
//! # 为什么 `render` 不接收现有文件
//!
//! [`AgentRenderer::render`] 只看统一模型，因此它的输出**只由 Bundle 内容决定**：
//! 同一份 Bundle 在任何机器上渲染出的字节完全相同，可以进快照、可以做 diff、可以在
//! 计划阶段与应用阶段各算一次并要求逐字节一致。
//!
//! 「怎么把这份期望内容落到一个用户也在编辑的文件上」是另一件事，由
//! [`merge_rendered`] 按 [`WriteStrategy`] 完成。把两者分开，是为了让「渲染结果」这
//! 个概念保持确定性——否则本地文件的任何变动都会让渲染结果跟着变，预演就失去意义。
//!
//! # 三个渲染器的策略对照
//!
//! | 工具 | 路径 | 策略 | 为什么 |
//! |---|---|---|---|
//! | Claude | `.claude/agents/*.md`、`.claude/skills/*/SKILL.md` | Full File | 目录由 EnvSync 独占，一个文件对应一个 Agent/Skill |
//! | Claude | `.claude/settings.json`、`.mcp.json` | 结构化 JSON 合并 | 用户也在这两个文件里写自己的设置，JSON 没有注释因而无法用 Managed Block |
//! | Codex | `.codex/agents/*.md`、`.codex/skills/*/SKILL.md` | Full File | 同上 |
//! | Codex | `.codex/config.toml` | Managed Block | TOML 支持 `#` 行注释，Managed Block 能把用户内容与受管内容在**同一个文件里**清晰隔开 |
//! | OpenCode | `opencode.json` | 结构化 JSON 合并 | OpenCode 把 agent / mcp / permission 全部放在一个用户可编辑的 JSON 里 |

use std::collections::{BTreeMap, BTreeSet};

use envsync_core::render::{
    render as render_file, RenderInput, RenderedChange, DEFAULT_COMMENT_PREFIX,
};
use envsync_domain::cbor::{encode, Value};
use envsync_domain::id::{Digest32, ResourceId};
use envsync_domain::resource::{FileMode, ResourcePolicy};

use crate::AdapterError;

pub mod claude;
pub mod codex;
pub mod opencode;

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

/// 渲染结果里 Secret 占位符的前缀。
///
/// 完整形态是 `${ENVSYNC_SECRET:secret://<id>}`。它出现在目标工具的配置文件里，
/// 真实取值**永远不写进文件**：运行时按 [`SecretInjection`] 从 Vault 解析后注入子进程
/// 环境变量。占位符可被 [`AgentRenderer::capture`] 原样解析回 [`SecretRefOrLiteral`]，
/// 因此往返不丢信息。
pub const SECRET_PLACEHOLDER_PREFIX: &str = "${ENVSYNC_SECRET:";

/// Secret 占位符的结尾。
pub const SECRET_PLACEHOLDER_SUFFIX: &str = "}";

/// SecretRef 唯一被接受的前缀（与 `envsync_domain::agent_bundle::SECRET_REF_SCHEME` 一致）。
pub const SECRET_REF_SCHEME: &str = "secret://";

/// 语义摘要的域标签。
pub const AGENT_CONTENT_DIGEST_DOMAIN: &str = "envsync:agent-content:v1";

/// 统一模型里被认可的 capability 名。
///
/// 这是一个**封闭集合**：渲染器只能对它认识的能力表态。Bundle 声明了不在此列的能力
/// 时，每个渲染器都会把它记成一条 [`LossSeverity::Blocking`] 的损失——「我不知道这是
/// 什么」和「我不支持这个」对用户的结论相同：不能默默继续。
pub const KNOWN_CAPABILITIES: &[&str] = &[
    "agents",
    "mcp.http",
    "mcp.sse",
    "mcp.stdio",
    "model.override",
    "permissions",
    "skills",
];

/// 单个字符串字段允许的最大长度。
pub const MAX_FIELD_LEN: usize = 4_096;

/// 指令 / Skill 正文允许的最大长度。
pub const MAX_BODY_LEN: usize = 256 * 1024;

// ---------------------------------------------------------------------------
// 模型
// ---------------------------------------------------------------------------

/// 一个 Agent 定义。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AgentDefinition {
    /// Agent 名，同时决定落盘文件名。
    pub name: String,
    /// 一句话描述。
    pub description: String,
    /// 系统提示 / 指令正文。
    pub instructions: String,
    /// 允许使用的工具名集合。
    pub tools: BTreeSet<String>,
    /// 模型覆盖；`None` 表示沿用目标工具的默认模型。
    pub model: Option<String>,
}

/// 一个 Skill 定义。
///
/// [`SkillDefinition::files`] 只记录**路径到摘要**，不含内容：Skill 的附属文件躺在
/// Bundle 的 quarantine 目录里，渲染阶段不搬运它们，只在 Skill 头部记下它们的摘要，
/// 让「附件被改过」这件事可被检测。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SkillDefinition {
    /// Skill 名，同时决定落盘目录名。
    pub name: String,
    /// 一句话描述。
    pub description: String,
    /// Skill 正文。
    pub body: String,
    /// 附属文件：相对路径 -> 内容摘要。
    pub files: BTreeMap<String, Digest32>,
}

/// MCP server 的传输方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum McpTransport {
    /// 本地子进程，通过 stdio 通信。
    Stdio,
    /// 远端 Server-Sent Events。
    Sse,
    /// 远端 Streamable HTTP。
    Http,
}

impl McpTransport {
    /// 稳定短名。
    pub const fn as_str(self) -> &'static str {
        match self {
            McpTransport::Stdio => "stdio",
            McpTransport::Sse => "sse",
            McpTransport::Http => "http",
        }
    }

    /// 由短名解析；未知取值返回 `None`。
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "stdio" => McpTransport::Stdio,
            "sse" => McpTransport::Sse,
            "http" => McpTransport::Http,
            _ => return None,
        })
    }

    /// 该传输方式对应的 capability 名。
    pub const fn capability(self) -> &'static str {
        match self {
            McpTransport::Stdio => "mcp.stdio",
            McpTransport::Sse => "mcp.sse",
            McpTransport::Http => "mcp.http",
        }
    }

    /// 是否需要启动本地进程。
    pub const fn is_local(self) -> bool {
        matches!(self, McpTransport::Stdio)
    }
}

/// 启动一个本地 MCP server 的命令模板。
///
/// 它是**模板**而不是命令行字符串：程序与参数分开存放，渲染时也分开写出，因此不存在
/// 「参数里带空格导致被重新切分」这类注入面。EnvSync 自己**从不执行**它。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CommandTemplate {
    /// 可执行程序名或路径。
    pub program: String,
    /// 参数，按顺序。
    pub args: Vec<String>,
}

/// 环境变量取值：Secret 引用或字面量。
///
/// # 选定的方案：敏感键名一律禁止字面量
///
/// 任务允许两种方案，这里选的是**「只允许非敏感键用 Literal」**，并在其上再叠一层
/// 取值启发式作为兜底：
///
/// * **按键名判定是主判据**，因为它是**确定性**的：`GITHUB_TOKEN` 这个名字本身就说明
///   了这里放的是什么，与取值长什么样无关。用户改不了判据，攻击者也绕不过——想让一个
///   秘密通过，就得把键名改成不敏感的，而那样目标工具就读不到它了。
/// * **按取值判定只能是兜底**，因为它必然不完整：任何基于长度与字符集的启发式都能被
///   构造出的取值绕过。把它当主判据等于宣称「我能识别所有秘密」，那是做不到的。
///
/// 两条判据都不通过才接受一个字面量，见 [`McpServerDefinition::validate`]。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRefOrLiteral {
    /// Vault 中的逻辑 Secret 标识，形如 `secret://github/token`。
    SecretRef(String),
    /// 非敏感字面量。
    Literal(String),
}

impl SecretRefOrLiteral {
    /// 构造一个 Secret 引用。
    pub fn secret_ref(value: impl Into<String>) -> Self {
        SecretRefOrLiteral::SecretRef(value.into())
    }

    /// 构造一个字面量。
    ///
    /// 合法性（键名是否敏感、取值是否像凭据）在
    /// [`McpServerDefinition::validate`] 里判定：那里才同时拿得到键名与取值。
    pub fn literal(value: impl Into<String>) -> Self {
        SecretRefOrLiteral::Literal(value.into())
    }

    /// 若为 Secret 引用则返回它的逻辑标识。
    pub fn as_secret_ref(&self) -> Option<&str> {
        match self {
            SecretRefOrLiteral::SecretRef(value) => Some(value),
            SecretRefOrLiteral::Literal(_) => None,
        }
    }

    /// 落到配置文件里的文本：引用渲染成占位符，字面量原样写出。
    pub fn to_rendered(&self) -> String {
        match self {
            SecretRefOrLiteral::SecretRef(reference) => {
                format!("{SECRET_PLACEHOLDER_PREFIX}{reference}{SECRET_PLACEHOLDER_SUFFIX}")
            }
            SecretRefOrLiteral::Literal(value) => value.clone(),
        }
    }

    /// 从配置文件里的文本还原。
    pub fn from_rendered(text: &str) -> Self {
        match text
            .strip_prefix(SECRET_PLACEHOLDER_PREFIX)
            .and_then(|rest| rest.strip_suffix(SECRET_PLACEHOLDER_SUFFIX))
        {
            Some(reference) => SecretRefOrLiteral::SecretRef(reference.to_owned()),
            None => SecretRefOrLiteral::Literal(text.to_owned()),
        }
    }
}

/// 一个 MCP server 定义。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServerDefinition {
    /// server 名。
    pub name: String,
    /// 传输方式。
    pub transport: McpTransport,
    /// 本地传输的命令模板；远端传输为 `None`。
    pub command: Option<CommandTemplate>,
    /// 远端传输的 URL；本地传输为 `None`。
    pub url: Option<String>,
    /// 环境变量。
    pub env: BTreeMap<String, SecretRefOrLiteral>,
    /// 是否启用。
    pub enabled: bool,
}

impl Default for McpServerDefinition {
    fn default() -> Self {
        McpServerDefinition {
            name: String::new(),
            transport: McpTransport::Stdio,
            command: None,
            url: None,
            env: BTreeMap::new(),
            enabled: true,
        }
    }
}

/// 敏感环境变量键名的判据片段（大写后做子串匹配）。
///
/// 清单刻意偏宽：误判的代价是「用户必须把一个本来无害的取值放进 Vault」，漏判的代价是
/// 「一枚 Token 被写进配置文件并随快照扩散」。两者不对称，因此宁可宽。
const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "APIKEY",
    "AUTH",
    "COOKIE",
    "CREDENTIAL",
    "KEY",
    "PASS",
    "PRIVATE",
    "SECRET",
    "SESSION",
    "SIGNATURE",
    "TOKEN",
];

/// 键名是否敏感。
pub fn is_sensitive_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    SENSITIVE_KEY_FRAGMENTS
        .iter()
        .any(|fragment| upper.contains(fragment))
}

impl McpServerDefinition {
    /// 校验定义自身。
    pub fn validate(&self) -> Result<(), AgentModelError> {
        validate_name("mcp_server.name", &self.name)?;
        match self.transport {
            McpTransport::Stdio => {
                let Some(command) = self.command.as_ref() else {
                    return Err(AgentModelError::TransportMismatch {
                        server: self.name.clone(),
                        detail: "stdio 传输必须提供 command",
                    });
                };
                validate_config_value("mcp_server.command.program", &command.program)?;
                for arg in &command.args {
                    validate_config_value("mcp_server.command.args", arg)?;
                }
                if self.url.is_some() {
                    return Err(AgentModelError::TransportMismatch {
                        server: self.name.clone(),
                        detail: "stdio 传输不能同时提供 url",
                    });
                }
            }
            McpTransport::Sse | McpTransport::Http => {
                let Some(url) = self.url.as_ref() else {
                    return Err(AgentModelError::TransportMismatch {
                        server: self.name.clone(),
                        detail: "远端传输必须提供 url",
                    });
                };
                validate_config_value("mcp_server.url", url)?;
                if self.command.is_some() {
                    return Err(AgentModelError::TransportMismatch {
                        server: self.name.clone(),
                        detail: "远端传输不能同时提供 command",
                    });
                }
            }
        }
        for (key, value) in &self.env {
            validate_name("mcp_server.env.key", key)?;
            match value {
                SecretRefOrLiteral::SecretRef(reference) => {
                    validate_secret_reference(&self.name, key, reference)?;
                }
                SecretRefOrLiteral::Literal(literal) => {
                    // 主判据：敏感键名一律不许用字面量。
                    if is_sensitive_env_key(key) {
                        return Err(AgentModelError::LiteralForSensitiveKey {
                            server: self.name.clone(),
                            key: key.clone(),
                        });
                    }
                    // 兜底：取值本身看起来像凭据时也拒绝。
                    if looks_like_credential(literal) {
                        return Err(AgentModelError::LiteralLooksLikeCredential {
                            server: self.name.clone(),
                            key: key.clone(),
                        });
                    }
                    validate_config_value("mcp_server.env.value", literal)?;
                }
            }
        }
        Ok(())
    }

    /// 该定义产生的 Secret 注入描述符，按环境变量名升序。
    pub fn secret_injections(&self) -> Vec<SecretInjection> {
        self.env
            .iter()
            .filter_map(|(key, value)| {
                value.as_secret_ref().map(|reference| SecretInjection {
                    server: self.name.clone(),
                    env_key: key.clone(),
                    secret_ref: reference.to_owned(),
                })
            })
            .collect()
    }
}

/// 工具权限模板。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PermissionTemplate {
    /// 直接允许。
    pub allow: BTreeSet<String>,
    /// 直接拒绝。
    pub deny: BTreeSet<String>,
    /// 每次询问。
    pub ask: BTreeSet<String>,
}

impl PermissionTemplate {
    /// 是否为空模板。
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty() && self.ask.is_empty()
    }

    /// 校验模板：三个集合的字符集，以及 `allow` 与 `deny` 不得交叠。
    ///
    /// 交叠必须拒绝而不是「deny 优先」：一条同时出现在两侧的规则说明作者对它的意图
    /// 自相矛盾，替他决定是危险的。
    pub fn validate(&self) -> Result<(), AgentModelError> {
        // 权限规则的写法由目标工具决定（`Bash(git diff:*)`、`net:*` 等），因此这里
        // 只做「不能含控制字符、引号与反斜杠」这条配置语法安全约束，不限定形状。
        for value in self.allow.iter().chain(&self.deny).chain(&self.ask) {
            validate_config_value("permissions", value)?;
        }
        if let Some(conflict) = self.allow.intersection(&self.deny).next() {
            return Err(AgentModelError::PermissionConflict {
                rule: conflict.clone(),
            });
        }
        Ok(())
    }
}

/// 统一 Agent Bundle 内容。
///
/// 这是「一个 Bundle 想让 AI 工具做什么」的**工具无关**表达。渲染器把它投影到具体
/// 工具的配置格式；[`AgentRenderer::capture`] 做反方向的投影。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AgentBundleContent {
    /// Agent 定义，按名索引。
    pub agents: BTreeMap<String, AgentDefinition>,
    /// Skill 定义，按名索引。
    pub skills: BTreeMap<String, SkillDefinition>,
    /// MCP server 定义，按名索引。
    pub mcp_servers: BTreeMap<String, McpServerDefinition>,
    /// 工具权限模板。
    pub permissions: PermissionTemplate,
    /// Bundle 在 manifest 里声明的能力。
    ///
    /// 它**不参与** [`AgentBundleContent::semantic_digest`]：声明是 Bundle 元数据，
    /// 无法从目标工具的配置文件里 capture 回来，把它算进语义摘要会让往返永远不相等。
    pub declared_capabilities: BTreeSet<String>,
}

impl AgentBundleContent {
    /// 校验整份内容。
    pub fn validate(&self) -> Result<(), AgentModelError> {
        for (name, agent) in &self.agents {
            if name != &agent.name {
                return Err(AgentModelError::KeyMismatch {
                    field: "agents",
                    key: name.clone(),
                    name: agent.name.clone(),
                });
            }
            validate_name("agent.name", &agent.name)?;
            validate_config_value("agent.description", &agent.description)?;
            validate_body("agent.instructions", &agent.instructions)?;
            for tool in &agent.tools {
                validate_qualified("agent.tools", tool)?;
            }
            if let Some(model) = agent.model.as_ref() {
                validate_qualified("agent.model", model)?;
            }
        }
        for (name, skill) in &self.skills {
            if name != &skill.name {
                return Err(AgentModelError::KeyMismatch {
                    field: "skills",
                    key: name.clone(),
                    name: skill.name.clone(),
                });
            }
            validate_name("skill.name", &skill.name)?;
            validate_config_value("skill.description", &skill.description)?;
            validate_body("skill.body", &skill.body)?;
            for path in skill.files.keys() {
                envsync_domain::agent_bundle::validate_bundle_path(path).map_err(|error| {
                    AgentModelError::InvalidValue {
                        field: "skill.files",
                        detail: error.to_string(),
                    }
                })?;
            }
        }
        for (name, server) in &self.mcp_servers {
            if name != &server.name {
                return Err(AgentModelError::KeyMismatch {
                    field: "mcp_servers",
                    key: name.clone(),
                    name: server.name.clone(),
                });
            }
            server.validate()?;
        }
        self.permissions.validate()?;
        for capability in &self.declared_capabilities {
            validate_qualified("declared_capabilities", capability)?;
        }
        Ok(())
    }

    /// 全部 Secret 注入描述符，按 `(server, env_key)` 升序。
    pub fn secret_injections(&self) -> Vec<SecretInjection> {
        let mut out: Vec<SecretInjection> = self
            .mcp_servers
            .values()
            .flat_map(McpServerDefinition::secret_injections)
            .collect();
        out.sort_by(|left, right| {
            (&left.server, &left.env_key).cmp(&(&right.server, &right.env_key))
        });
        out
    }

    /// 内容的**语义摘要**。
    ///
    /// 它覆盖 Agent、Skill、MCP server 与权限模板的逻辑内容，不覆盖任何字节层面的东西
    /// （缩进、键顺序、换行风格、目标工具的语法糖）。因此
    /// [`AgentRenderer::verify`] 用它比对时，比的是「配置的意思有没有变」，而不是
    /// 「文件长得一不一样」——后者会被目标工具自己的格式化重写打成一片噪音。
    pub fn semantic_digest(&self) -> Digest32 {
        let value = Value::Array(vec![
            map_value(&self.agents, agent_value),
            map_value(&self.skills, skill_value),
            map_value(&self.mcp_servers, server_value),
            permissions_value(&self.permissions),
        ]);
        Digest32::domain_hash(AGENT_CONTENT_DIGEST_DOMAIN, &encode(&value))
    }

    /// 从 `other` 中只取本内容声明过的键，构成一份可与自身比较的投影。
    ///
    /// 这是 [`AgentRenderer::verify`] 的核心：目标工具的配置文件里通常还有用户自己的
    /// Agent、MCP server 与权限条目，它们**不该**参与比较——EnvSync 从没声称管理它们。
    /// 投影之后再比语义摘要，比的就恰好是「我管的那部分对不对」。
    pub fn project_managed(&self, other: &AgentBundleContent) -> AgentBundleContent {
        fn keys<T>(items: &BTreeMap<String, T>) -> BTreeSet<String> {
            items.keys().cloned().collect()
        }
        let agent_names = keys(&self.agents);
        let skill_names = keys(&self.skills);
        let server_names = keys(&self.mcp_servers);
        AgentBundleContent {
            agents: other
                .agents
                .iter()
                .filter(|(name, _)| agent_names.contains(*name))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
            skills: other
                .skills
                .iter()
                .filter(|(name, _)| skill_names.contains(*name))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
            mcp_servers: other
                .mcp_servers
                .iter()
                .filter(|(name, _)| server_names.contains(*name))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
            permissions: PermissionTemplate {
                allow: intersect(&self.permissions.allow, &other.permissions.allow),
                deny: intersect(&self.permissions.deny, &other.permissions.deny),
                ask: intersect(&self.permissions.ask, &other.permissions.ask),
            },
            declared_capabilities: BTreeSet::new(),
        }
    }

    /// 去掉 Skill 的副本，供不支持 Skill 的工具做往返比较。
    pub fn without_skills(&self) -> AgentBundleContent {
        AgentBundleContent {
            skills: BTreeMap::new(),
            ..self.clone()
        }
    }
}

/// 两个集合的交集。
fn intersect(left: &BTreeSet<String>, right: &BTreeSet<String>) -> BTreeSet<String> {
    left.intersection(right).cloned().collect()
}

// ---------------------------------------------------------------------------
// 渲染结果
// ---------------------------------------------------------------------------

/// 一条运行时 Secret 注入描述符。
///
/// 它描述的是「把 Vault 里 `secret_ref` 的取值放进 `server` 这个进程的 `env_key`
/// 环境变量」。EnvSync 自己不启动那个进程；描述符交给目标工具的启动方使用。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SecretInjection {
    /// 目标 MCP server 名。
    pub server: String,
    /// 环境变量名。
    pub env_key: String,
    /// Vault 中的逻辑 Secret 标识，形如 `secret://github/token`。
    pub secret_ref: String,
}

/// 一条损失的严重级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LossSeverity {
    /// 有内容表达不了，必须告知用户，但不阻塞。
    Info,
    /// Bundle **声明**的能力目标工具不支持，计划必须阻塞。
    ///
    /// 与 [`LossSeverity::Info`] 的区别在于「声明」二字：Bundle 说了它需要这项能力，
    /// 而目标工具给不了。此时继续渲染等于让 Bundle 在一个它明确说过不成立的前提下
    /// 运行，结果不可预测。
    Blocking,
}

/// 一条「目标工具表达不了」的诊断。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LossNote {
    /// 目标工具标识。
    pub tool: &'static str,
    /// 相关的模型元素（Agent 名、Skill 名、server 名或 capability 名）。
    pub subject: String,
    /// 丢失的字段或概念。
    pub field: &'static str,
    /// 人类可读说明；不含秘密值与本机绝对路径。
    pub detail: String,
    /// 严重级别。
    pub severity: LossSeverity,
}

/// 一次渲染的完整产出。
///
/// **不包含任何进程**：渲染只产生文件与注入描述符。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RenderedAgentConfig {
    /// 相对路径 -> 期望内容（假设 EnvSync 独占该路径时的完整内容）。
    ///
    /// 真正落盘前要经过 [`merge_rendered`]：它按 [`RenderedAgentConfig::strategies`]
    /// 把这些期望内容合并进现有文件，从而不覆盖本地未管理内容。
    pub files: Vec<(String, Vec<u8>)>,
    /// 运行时 Secret 注入描述符。
    pub secret_injections: Vec<SecretInjection>,
    /// 目标工具不支持的字段。
    pub loss_report: Vec<LossNote>,
    /// 每条路径的写入策略。
    pub strategies: BTreeMap<String, WriteStrategy>,
}

impl RenderedAgentConfig {
    /// 是否存在阻塞级损失。
    ///
    /// 为 `true` 时计划必须阻塞：要么用户显式接受一条 loss policy，要么这个 Bundle
    /// 就不该投影到这个工具上。
    pub fn is_blocked(&self) -> bool {
        self.loss_report
            .iter()
            .any(|note| note.severity == LossSeverity::Blocking)
    }

    /// 全部阻塞级损失。
    pub fn blocking_losses(&self) -> Vec<&LossNote> {
        self.loss_report
            .iter()
            .filter(|note| note.severity == LossSeverity::Blocking)
            .collect()
    }
}

/// 一条产出路径的写入策略。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteStrategy {
    /// 整个文件由 EnvSync 独占，直接替换。
    ///
    /// 只用于 EnvSync 自己创建的目录下的文件（`.claude/agents/`、`.codex/skills/` 等）：
    /// 一个文件对应一个 Agent 或 Skill，用户没有在同一个文件里写别的东西的理由。
    FullFile,
    /// 受管区块：把期望内容包在 marker 之间插进用户文件，块外字节逐字保留。
    ManagedBlock {
        /// 区块标识，出现在 marker 里。
        resource: ResourceId,
        /// 注释前缀，例如 `"# "`。
        comment_prefix: String,
    },
    /// 结构化 JSON 合并：期望内容的键覆盖同名键，现有文件的其余键原样保留。
    JsonMerge,
}

/// 把渲染结果合并进现有文件。
///
/// 这是「不覆盖本地未管理内容」真正落地的地方。返回值是**待写入的完整文件内容**，
/// 已经跳过了内容无变化的路径（因此重复应用是幂等的）。
///
/// * [`WriteStrategy::FullFile`]：直接使用期望内容；
/// * [`WriteStrategy::ManagedBlock`]：交给 [`envsync_core::render::render`]，块外字节
///   逐字保留；
/// * [`WriteStrategy::JsonMerge`]：把期望内容的对象**递归合并**进现有对象。同名键由
///   期望内容覆盖，未出现的键原样保留。数组整体替换而不是逐元素合并——`allow` 列表是
///   一个整体语义，逐元素合并会产生一个谁都没批准过的并集。
pub fn merge_rendered(
    rendered: &RenderedAgentConfig,
    existing: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<(String, Vec<u8>)>, AdapterError> {
    let mut out = Vec::with_capacity(rendered.files.len());
    for (path, desired) in &rendered.files {
        let current = existing.get(path).map(Vec::as_slice);
        let strategy = rendered
            .strategies
            .get(path)
            .cloned()
            .unwrap_or(WriteStrategy::FullFile);
        let merged = match strategy {
            WriteStrategy::FullFile => desired.clone(),
            WriteStrategy::ManagedBlock {
                ref resource,
                ref comment_prefix,
            } => {
                let policy = ResourcePolicy::default();
                let input = RenderInput {
                    resource,
                    existing: current,
                    desired,
                    mode: FileMode::ManagedBlock,
                    policy: &policy,
                    comment_prefix,
                };
                match render_file(&input)? {
                    RenderedChange::Write(bytes) => bytes,
                    RenderedChange::Unchanged => continue,
                }
            }
            WriteStrategy::JsonMerge => merge_json_bytes(path, current, desired)?,
        };
        if current == Some(merged.as_slice()) {
            continue;
        }
        out.push((path.clone(), merged));
    }
    Ok(out)
}

/// 把期望 JSON 递归合并进现有 JSON。
fn merge_json_bytes(
    path: &str,
    existing: Option<&[u8]>,
    desired: &[u8],
) -> Result<Vec<u8>, AdapterError> {
    let desired_value: serde_json::Value = serde_json::from_slice(desired).map_err(|error| {
        structured_error("agents", format!("渲染产出的 JSON 非法（{path}）：{error}"))
    })?;
    let existing_value: serde_json::Value = match existing {
        None => serde_json::Value::Object(serde_json::Map::new()),
        Some(bytes) if bytes.iter().all(u8::is_ascii_whitespace) => {
            serde_json::Value::Object(serde_json::Map::new())
        }
        Some(bytes) => serde_json::from_slice(bytes).map_err(|error| {
            structured_error(
                "agents",
                format!("目标工具的现有配置不是合法 JSON（{path}）：{error}"),
            )
        })?,
    };
    let merged = merge_json_value(existing_value, desired_value);
    let mut bytes = serde_json::to_vec_pretty(&merged).map_err(|error| {
        structured_error("agents", format!("JSON 序列化失败（{path}）：{error}"))
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// 递归合并两个 JSON 值。
fn merge_json_value(existing: serde_json::Value, desired: serde_json::Value) -> serde_json::Value {
    match (existing, desired) {
        (serde_json::Value::Object(mut base), serde_json::Value::Object(overlay)) => {
            for (key, value) in overlay {
                let merged = match base.remove(&key) {
                    Some(current) => merge_json_value(current, value),
                    None => value,
                };
                base.insert(key, merged);
            }
            serde_json::Value::Object(base)
        }
        // 非对象一律整体替换：数组与标量没有「部分受管」这个概念。
        (_, desired) => desired,
    }
}

// ---------------------------------------------------------------------------
// 渲染器契约
// ---------------------------------------------------------------------------

/// 统一模型到具体工具配置的渲染器。
///
/// 四个方法**全部是纯函数**：不读文件系统、不取时钟、不使用随机数、不启动进程。
/// [`AgentRenderer::render`] 对同一份内容连续调用两次必须返回逐字节相同的结果——
/// 计划阶段与应用阶段会各调一次，两次不同就意味着预演结果不可信。
pub trait AgentRenderer: Send + Sync {
    /// 目标工具的稳定标识（`claude` / `codex` / `opencode`）。
    fn tool_id(&self) -> &'static str;

    /// 把统一模型渲染成目标工具的配置。
    ///
    /// 只产生文件与 [`SecretInjection`]；**绝不**启动 MCP server 或任何其他进程。
    fn render(&self, content: &AgentBundleContent) -> Result<RenderedAgentConfig, AdapterError>;

    /// 从目标工具的配置文件反向构造统一模型。
    ///
    /// 输入是「相对路径 -> 文件内容」。capture **不区分**某条配置是 EnvSync 写的还是
    /// 用户自己写的——它没有判断依据。区分工作由调用方按 Bundle 记录完成，比较时用
    /// [`AgentBundleContent::project_managed`] 把范围收窄。
    fn capture(
        &self,
        files: &BTreeMap<String, Vec<u8>>,
    ) -> Result<AgentBundleContent, AdapterError>;

    /// 校验目标工具的实际配置是否仍符合期望。
    ///
    /// 比的是**语义摘要**而不是字节：目标工具自己会重排键、改缩进、补默认值，字节比较
    /// 会把这些无害变化全部报成漂移。默认实现是「capture 出来，投影到受管范围，比摘要」。
    fn verify(
        &self,
        content: &AgentBundleContent,
        actual: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), AdapterError> {
        let captured = self.capture(actual)?;
        let projected = content.project_managed(&captured);
        let expected = content.project_managed(content);
        if projected.semantic_digest() != expected.semantic_digest() {
            return Err(AdapterError::VerifyFailed {
                resource: tool_resource(self.tool_id()),
                detail: format!(
                    "{} 的实际配置与期望的语义摘要不符（期望 {}，实际 {}）",
                    self.tool_id(),
                    expected.semantic_digest().short(),
                    projected.semantic_digest().short()
                ),
            });
        }
        Ok(())
    }

    /// 该工具支持的 capability 集合。
    fn supported_capabilities(&self) -> &'static [&'static str];
}

/// 按标识取内建渲染器。
pub fn renderer_for(tool_id: &str) -> Option<Box<dyn AgentRenderer>> {
    match tool_id {
        "claude" => Some(Box::new(claude::ClaudeRenderer::new())),
        "codex" => Some(Box::new(codex::CodexRenderer::new())),
        "opencode" => Some(Box::new(opencode::OpenCodeRenderer::new())),
        _ => None,
    }
}

/// 全部内建渲染器，按标识升序。
pub fn builtin_renderers() -> Vec<Box<dyn AgentRenderer>> {
    vec![
        Box::new(claude::ClaudeRenderer::new()),
        Box::new(codex::CodexRenderer::new()),
        Box::new(opencode::OpenCodeRenderer::new()),
    ]
}

/// 为一个工具生成 [`AdapterError`] 里用的资源标识。
pub(crate) fn tool_resource(tool: &str) -> ResourceId {
    ResourceId::parse(&format!("agents/{tool}"))
        .unwrap_or_else(|_| ResourceId::parse("agents/unknown").expect("常量标识合法"))
}

/// 构造一个结构化错误。
pub(crate) fn structured_error(tool: &str, detail: impl Into<String>) -> AdapterError {
    AdapterError::Structured {
        resource: tool_resource(tool),
        detail: detail.into(),
    }
}

/// 检查声明能力，产出阻塞级损失条目。
pub(crate) fn capability_losses(
    tool: &'static str,
    content: &AgentBundleContent,
    supported: &'static [&'static str],
) -> Vec<LossNote> {
    content
        .declared_capabilities
        .iter()
        .filter(|capability| !supported.contains(&capability.as_str()))
        .map(|capability| LossNote {
            tool,
            subject: capability.clone(),
            field: "declared_capability",
            detail: format!(
                "{tool} 不支持声明的能力 `{capability}`；计划必须阻塞或由用户显式接受 loss policy"
            ),
            severity: LossSeverity::Blocking,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 校验
// ---------------------------------------------------------------------------

/// 统一模型的校验错误。
///
/// 它通过 [`AgentModelError::into_adapter`] 转成 [`AdapterError::Structured`]：
/// 渲染器对外只暴露 [`AdapterError`]，本枚举是内部诊断的载体。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AgentModelError {
    /// 名称字符集非法或超长。
    #[error("字段 `{field}` 的取值 `{value}` 非法：{reason}")]
    InvalidName {
        /// 字段名。
        field: &'static str,
        /// 被截断的取值。
        value: String,
        /// 具体原因。
        reason: &'static str,
    },

    /// 取值非法（含控制字符、引号、反斜杠或超长）。
    #[error("字段 `{field}` 非法：{detail}")]
    InvalidValue {
        /// 字段名。
        field: &'static str,
        /// 具体说明。
        detail: String,
    },

    /// map 的键与元素自述的名字不一致。
    #[error("`{field}` 里键 `{key}` 与元素自述的名字 `{name}` 不一致")]
    KeyMismatch {
        /// 字段名。
        field: &'static str,
        /// map 的键。
        key: String,
        /// 元素自述的名字。
        name: String,
    },

    /// 传输方式与 `command` / `url` 不匹配。
    #[error("MCP server `{server}` 的传输配置不一致：{detail}")]
    TransportMismatch {
        /// server 名。
        server: String,
        /// 具体说明。
        detail: &'static str,
    },

    /// 敏感键名使用了字面量。
    #[error("MCP server `{server}` 的环境变量 `{key}` 是敏感键名，只能使用 SecretRef")]
    LiteralForSensitiveKey {
        /// server 名。
        server: String,
        /// 环境变量名。
        key: String,
    },

    /// 字面量取值看起来像一枚真实凭据。
    #[error(
        "MCP server `{server}` 的环境变量 `{key}` 的字面量看起来是一枚凭据，只能使用 SecretRef"
    )]
    LiteralLooksLikeCredential {
        /// server 名。
        server: String,
        /// 环境变量名。
        key: String,
    },

    /// SecretRef 不是 `secret://<id>` 形式。
    #[error("MCP server `{server}` 的环境变量 `{key}` 不是 `secret://<id>` 形式的引用")]
    InvalidSecretRef {
        /// server 名。
        server: String,
        /// 环境变量名。
        key: String,
    },

    /// 同一条规则同时出现在 allow 与 deny。
    #[error("权限规则 `{rule}` 同时出现在 allow 与 deny 中")]
    PermissionConflict {
        /// 冲突的规则。
        rule: String,
    },

    /// 目标工具的配置文件结构不符合预期。
    #[error("{tool} 的配置结构不符合预期：{detail}")]
    UnexpectedShape {
        /// 工具标识。
        tool: &'static str,
        /// 具体说明。
        detail: String,
    },
}

impl AgentModelError {
    /// 转成对外的 [`AdapterError`]。
    pub fn into_adapter(self, tool: &str) -> AdapterError {
        structured_error(tool, self.to_string())
    }
}

/// 校验一个**会被当作路径分段使用**的名称：ASCII 字母数字与 `-`、`_`、`.`，非空且
/// 不超长，不含 `/`、`:` 与 `..`，不以 `.` 开头。
///
/// Agent 名、Skill 名、MCP server 名与环境变量名都会被直接拼进文件路径、JSON 键与
/// TOML 表头。排除 `/` 与 `:` 是硬要求：前者能把 `.claude/agents/<name>.md` 变成任意
/// 深度的路径（进而配合 `..` 变成路径穿越），后者在 Windows 上是盘符与数据流分隔符。
pub(crate) fn validate_name(field: &'static str, value: &str) -> Result<(), AgentModelError> {
    if value.is_empty() {
        return Err(AgentModelError::InvalidName {
            field,
            value: String::new(),
            reason: "不能为空",
        });
    }
    if value.len() > 128 {
        return Err(AgentModelError::InvalidName {
            field,
            value: truncate(value),
            reason: "超过长度上限",
        });
    }
    if value.contains("..") || value.starts_with('.') {
        return Err(AgentModelError::InvalidName {
            field,
            value: truncate(value),
            reason: "不能包含 `..`，也不能以 `.` 开头",
        });
    }
    for ch in value.chars() {
        if !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')) {
            return Err(AgentModelError::InvalidName {
                field,
                value: truncate(value),
                reason: "只允许 ASCII 字母、数字与 `-`、`_`、`.`",
            });
        }
    }
    Ok(())
}

/// 校验一个**不会**被当作路径分段的限定名（模型名、能力名）。
///
/// 比 [`validate_name`] 多允许 `/` 与 `:`：模型名常写成 `provider/model`，能力名常写成
/// `mcp.stdio` 或 `fs:read`。它们只出现在配置值的位置，不参与路径拼接，因此这两个字符
/// 是安全的；`..` 与前导 `.` 仍然拒绝。
pub(crate) fn validate_qualified(field: &'static str, value: &str) -> Result<(), AgentModelError> {
    if value.is_empty() || value.len() > 128 {
        return Err(AgentModelError::InvalidName {
            field,
            value: truncate(value),
            reason: "不能为空且不能超过长度上限",
        });
    }
    if value.contains("..") || value.starts_with('.') {
        return Err(AgentModelError::InvalidName {
            field,
            value: truncate(value),
            reason: "不能包含 `..`，也不能以 `.` 开头",
        });
    }
    for ch in value.chars() {
        if !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '/')) {
            return Err(AgentModelError::InvalidName {
                field,
                value: truncate(value),
                reason: "只允许 ASCII 字母、数字与 `-`、`_`、`.`、`:`、`/`",
            });
        }
    }
    Ok(())
}

/// 校验一个会被写进配置语法的取值。
///
/// 拒绝控制字符、双引号与反斜杠：这三类字符都会在 JSON / TOML 里触发转义规则，而本
/// 模块的 TOML 子集写出器**刻意不实现转义**——不实现比实现一半安全。需要它们的场景
/// （例如 Windows 路径）应当用正斜杠或环境变量表达。
pub(crate) fn validate_config_value(
    field: &'static str,
    value: &str,
) -> Result<(), AgentModelError> {
    if value.len() > MAX_FIELD_LEN {
        return Err(AgentModelError::InvalidValue {
            field,
            detail: format!("长度 {} 超过上限 {MAX_FIELD_LEN}", value.len()),
        });
    }
    if let Some(bad) = value
        .chars()
        .find(|ch| ch.is_control() || matches!(ch, '"' | '\\'))
    {
        return Err(AgentModelError::InvalidValue {
            field,
            detail: format!("不能包含字符 {bad:?}（控制字符、双引号与反斜杠一律拒绝）"),
        });
    }
    Ok(())
}

/// 校验一段正文（允许换行，禁止其他控制字符）。
pub(crate) fn validate_body(field: &'static str, value: &str) -> Result<(), AgentModelError> {
    if value.len() > MAX_BODY_LEN {
        return Err(AgentModelError::InvalidValue {
            field,
            detail: format!("长度 {} 超过上限 {MAX_BODY_LEN}", value.len()),
        });
    }
    if let Some(bad) = value
        .chars()
        .find(|ch| ch.is_control() && !matches!(ch, '\n' | '\t'))
    {
        return Err(AgentModelError::InvalidValue {
            field,
            detail: format!("不能包含控制字符 {bad:?}"),
        });
    }
    Ok(())
}

/// 校验一条 SecretRef。
fn validate_secret_reference(
    server: &str,
    key: &str,
    reference: &str,
) -> Result<(), AgentModelError> {
    let invalid = || AgentModelError::InvalidSecretRef {
        server: server.to_owned(),
        key: key.to_owned(),
    };
    let Some(id) = reference.strip_prefix(SECRET_REF_SCHEME) else {
        return Err(invalid());
    };
    if id.is_empty() || id.len() > 128 {
        return Err(invalid());
    }
    for segment in id.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(invalid());
        }
        if !segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(invalid());
        }
    }
    Ok(())
}

/// 复用领域层的凭据启发式，保证两处判据一致。
pub(crate) fn looks_like_credential(value: &str) -> bool {
    envsync_domain::agent_bundle::looks_like_credential(value)
}

fn truncate(value: &str) -> String {
    value.chars().take(64).collect()
}

// ---------------------------------------------------------------------------
// 语义摘要的 CBOR 投影
// ---------------------------------------------------------------------------

fn map_value<T>(items: &BTreeMap<String, T>, to_value: fn(&T) -> Value) -> Value {
    Value::Array(
        items
            .iter()
            .map(|(key, value)| Value::Array(vec![Value::Text(key.clone()), to_value(value)]))
            .collect(),
    )
}

fn set_value(items: &BTreeSet<String>) -> Value {
    Value::Array(items.iter().map(|item| Value::Text(item.clone())).collect())
}

fn agent_value(agent: &AgentDefinition) -> Value {
    Value::Array(vec![
        Value::Text(agent.name.clone()),
        Value::Text(agent.description.clone()),
        Value::Text(agent.instructions.clone()),
        set_value(&agent.tools),
        match agent.model.as_ref() {
            Some(model) => Value::Text(model.clone()),
            None => Value::Null,
        },
    ])
}

fn skill_value(skill: &SkillDefinition) -> Value {
    Value::Array(vec![
        Value::Text(skill.name.clone()),
        Value::Text(skill.description.clone()),
        Value::Text(skill.body.clone()),
        Value::Array(
            skill
                .files
                .iter()
                .map(|(path, digest)| {
                    Value::Array(vec![
                        Value::Text(path.clone()),
                        Value::Bytes(digest.as_bytes().to_vec()),
                    ])
                })
                .collect(),
        ),
    ])
}

fn server_value(server: &McpServerDefinition) -> Value {
    Value::Array(vec![
        Value::Text(server.name.clone()),
        Value::Text(server.transport.as_str().to_owned()),
        match server.command.as_ref() {
            Some(command) => Value::Array(vec![
                Value::Text(command.program.clone()),
                Value::Array(
                    command
                        .args
                        .iter()
                        .map(|arg| Value::Text(arg.clone()))
                        .collect(),
                ),
            ]),
            None => Value::Null,
        },
        match server.url.as_ref() {
            Some(url) => Value::Text(url.clone()),
            None => Value::Null,
        },
        Value::Array(
            server
                .env
                .iter()
                .map(|(key, value)| {
                    let (tag, text) = match value {
                        SecretRefOrLiteral::SecretRef(reference) => ("secret_ref", reference),
                        SecretRefOrLiteral::Literal(literal) => ("literal", literal),
                    };
                    Value::Array(vec![
                        Value::Text(key.clone()),
                        Value::Text(tag.to_owned()),
                        Value::Text(text.clone()),
                    ])
                })
                .collect(),
        ),
        Value::Bool(server.enabled),
    ])
}

fn permissions_value(permissions: &PermissionTemplate) -> Value {
    Value::Array(vec![
        set_value(&permissions.allow),
        set_value(&permissions.deny),
        set_value(&permissions.ask),
    ])
}

// ---------------------------------------------------------------------------
// Markdown frontmatter：Agent 与 Skill 文件的共用格式
// ---------------------------------------------------------------------------

/// frontmatter 的围栏。
pub(crate) const FRONTMATTER_FENCE: &str = "---";

/// 把一组有序键值对写成 frontmatter + 正文的完整文件。
///
/// 取值已经在 [`validate_config_value`] 里排除了控制字符与引号，因此这里**不需要
/// 转义**：写出去的每一行都是 `key: value`，解析时按第一个 `: ` 切开即可。
pub(crate) fn write_frontmatter(fields: &[(String, String)], body: &str) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(FRONTMATTER_FENCE);
    out.push('\n');
    for (key, value) in fields {
        out.push_str(key);
        out.push_str(": ");
        out.push_str(value);
        out.push('\n');
    }
    out.push_str(FRONTMATTER_FENCE);
    out.push('\n');
    out.push_str(body);
    if !body.ends_with('\n') {
        out.push('\n');
    }
    out.into_bytes()
}

/// 解析 frontmatter + 正文。
///
/// 返回 `(有序键值对, 正文)`。同名键可以重复出现（Skill 的附件行就靠这一点）。
/// 结构不符（缺围栏、非 UTF-8、某行没有 `: `）一律报错，**绝不猜测修复**。
pub(crate) fn read_frontmatter(
    tool: &'static str,
    bytes: &[u8],
) -> Result<(Vec<(String, String)>, String), AgentModelError> {
    let text = std::str::from_utf8(bytes).map_err(|_| AgentModelError::UnexpectedShape {
        tool,
        detail: "文件不是合法 UTF-8".to_owned(),
    })?;
    let mut lines = text.split_inclusive('\n');
    let first = lines.next().unwrap_or("");
    if first.trim_end_matches(['\r', '\n']) != FRONTMATTER_FENCE {
        return Err(AgentModelError::UnexpectedShape {
            tool,
            detail: "缺少 frontmatter 起始围栏 `---`".to_owned(),
        });
    }
    let mut fields = Vec::new();
    let mut consumed = first.len();
    let mut closed = false;
    for line in lines {
        consumed += line.len();
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed == FRONTMATTER_FENCE {
            closed = true;
            break;
        }
        let Some((key, value)) = trimmed.split_once(": ") else {
            return Err(AgentModelError::UnexpectedShape {
                tool,
                detail: "frontmatter 中出现了不是 `key: value` 的行".to_owned(),
            });
        };
        fields.push((key.to_owned(), value.to_owned()));
    }
    if !closed {
        return Err(AgentModelError::UnexpectedShape {
            tool,
            detail: "缺少 frontmatter 结束围栏 `---`".to_owned(),
        });
    }
    Ok((fields, text[consumed..].to_owned()))
}

/// frontmatter 中列表字段的分隔符。
pub(crate) const LIST_SEPARATOR: &str = ", ";

/// 把集合写成逗号分隔的列表。
pub(crate) fn join_set(items: &BTreeSet<String>) -> String {
    items
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(LIST_SEPARATOR)
}

/// 解析逗号分隔的列表。
pub(crate) fn split_set(text: &str) -> BTreeSet<String> {
    text.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

/// 默认注释前缀（供 Managed Block 策略使用）。
pub(crate) const COMMENT_PREFIX: &str = DEFAULT_COMMENT_PREFIX;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_keys_reject_literals() {
        let server = McpServerDefinition {
            name: "docs".to_owned(),
            transport: McpTransport::Stdio,
            command: Some(CommandTemplate {
                program: "docs".to_owned(),
                args: Vec::new(),
            }),
            env: BTreeMap::from([(
                "API_TOKEN".to_owned(),
                SecretRefOrLiteral::literal("plain-value"),
            )]),
            ..McpServerDefinition::default()
        };
        assert!(matches!(
            server.validate(),
            Err(AgentModelError::LiteralForSensitiveKey { .. })
        ));
    }

    #[test]
    fn non_sensitive_keys_accept_literals() {
        let server = McpServerDefinition {
            name: "docs".to_owned(),
            transport: McpTransport::Stdio,
            command: Some(CommandTemplate {
                program: "docs".to_owned(),
                args: Vec::new(),
            }),
            env: BTreeMap::from([("LOG_LEVEL".to_owned(), SecretRefOrLiteral::literal("info"))]),
            ..McpServerDefinition::default()
        };
        assert!(server.validate().is_ok());
    }

    #[test]
    fn frontmatter_round_trips() {
        let fields = vec![
            ("name".to_owned(), "reviewer".to_owned()),
            ("tools".to_owned(), "read, search".to_owned()),
        ];
        let bytes = write_frontmatter(&fields, "指令正文\n");
        let (parsed, body) = read_frontmatter("test", &bytes).expect("解析成功");
        assert_eq!(parsed, fields);
        assert_eq!(body, "指令正文\n");
    }

    #[test]
    fn json_merge_keeps_unmanaged_keys() {
        let existing = br#"{"mcpServers":{"local":{"command":"x"}},"theme":"dark"}"#.to_vec();
        let desired = br#"{"mcpServers":{"docs":{"command":"y"}}}"#.to_vec();
        let merged = merge_json_bytes("x.json", Some(&existing), &desired).expect("合并成功");
        let value: serde_json::Value = serde_json::from_slice(&merged).expect("合法 JSON");
        assert_eq!(value["theme"], "dark");
        assert_eq!(value["mcpServers"]["local"]["command"], "x");
        assert_eq!(value["mcpServers"]["docs"]["command"], "y");
    }
}
