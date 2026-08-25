//! 插件 JSON proposal 的 Host 侧闭合验证。
//!
//! 插件只能返回逻辑根别名、相对目标和受 Host 注册模板约束的 argv。这里不解析真实
//! 路径、不执行命令，也不接受 SecretRef、环境或任意 JSON 扩展字段。

use std::collections::BTreeMap;

use envsync_platform::{RelativeTarget, RootRegistry};
use envsync_plugin_api::PluginMethod;
use serde::Deserialize;
use serde_json::Value;

use crate::HostError;

const MAX_TEMPLATE_ID_LEN: usize = 128;
const MAX_ARGV_LEN: usize = 64;
const MAX_ARG_LEN: usize = 4096;
const SHELL_METACHARACTERS: &[char] = &[
    ';', '|', '&', '$', '`', '<', '>', '(', ')', '{', '}', '[', ']', '!', '*', '?', '~', '\'', '"',
    '\\', '\n', '\r',
];

/// 由 Host 目录约束的一个命令参数位置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandArgumentRule {
    /// 调用方必须逐字提供的固定参数。
    Literal(String),
    /// 一个受限的普通 token；不能以 `-` 开头，不能携带路径穿越或 shell 形状。
    Token,
}

impl CommandArgumentRule {
    /// 构造一个 token 参数规则。
    pub const fn token() -> Self {
        Self::Token
    }
}

/// Host 注册的、不可由插件自行扩张的命令提案模板。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandProposalTemplate {
    id: String,
    argument_rules: Vec<CommandArgumentRule>,
}

impl CommandProposalTemplate {
    /// 创建并验证一个命令提案模板。
    ///
    /// 模板只能由 Host 配置；这里提前校验其 ID 与固定参数，避免不安全的 Host 配置
    /// 被误当作安全的插件输入。
    pub fn new(
        id: impl Into<String>,
        argument_rules: Vec<CommandArgumentRule>,
    ) -> Result<Self, HostError> {
        let id = id.into();
        validate_template_id(&id)?;
        if argument_rules.len() > MAX_ARGV_LEN {
            return Err(HostError::InvalidCommand);
        }
        for rule in &argument_rules {
            if let CommandArgumentRule::Literal(value) = rule {
                validate_argument_shape(value, false)?;
            }
        }
        Ok(Self { id, argument_rules })
    }

    /// 返回 opaque 模板 ID。
    pub fn id(&self) -> &str {
        &self.id
    }

    /// 返回每个 argv 位置的 Host 规则。
    pub fn argument_rules(&self) -> &[CommandArgumentRule] {
        &self.argument_rules
    }

    fn validate_argv(&self, argv: &[String]) -> Result<(), HostError> {
        if argv.len() != self.argument_rules.len() || argv.len() > MAX_ARGV_LEN {
            return Err(HostError::InvalidCommand);
        }
        for (rule, value) in self.argument_rules.iter().zip(argv) {
            match rule {
                CommandArgumentRule::Literal(expected) if value == expected => {}
                CommandArgumentRule::Literal(_) => return Err(HostError::InvalidCommand),
                CommandArgumentRule::Token => validate_token(value)?,
            }
        }
        Ok(())
    }
}

/// 受 Host 控制的命令提案模板目录。
///
/// 此目录只完成声明验证；它不持有可执行文件路径，也不能执行任何命令。
#[derive(Debug, Default)]
pub struct CommandProposalCatalog {
    templates: BTreeMap<String, CommandProposalTemplate>,
}

impl CommandProposalCatalog {
    /// 创建空目录。空目录会拒绝所有 `plan-command` proposal。
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册一个唯一的 Host 命令提案模板。
    pub fn register(&mut self, template: CommandProposalTemplate) -> Result<(), HostError> {
        if self.templates.contains_key(template.id()) {
            return Err(HostError::InvalidCommand);
        }
        self.templates.insert(template.id.clone(), template);
        Ok(())
    }

    /// 按 opaque ID 查找已注册模板。
    pub fn get(&self, id: &str) -> Option<&CommandProposalTemplate> {
        self.templates.get(id)
    }

    /// 已注册模板的数量。
    pub fn len(&self) -> usize {
        self.templates.len()
    }

    /// 目录是否为空。
    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }
}

/// 通过 Host 边界校验后、仍不含执行能力的 plugin proposal。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatedProposal {
    /// 对受注册根约束的目标提出观察请求。
    Observation {
        /// 已注册的逻辑根别名。
        root: String,
        /// 已校验的、跨平台的相对目标。
        target: RelativeTarget,
    },
    /// 对受注册根约束的目标提出渲染请求。
    Render {
        /// 已注册的逻辑根别名。
        root: String,
        /// 已校验的、跨平台的相对目标。
        target: RelativeTarget,
    },
    /// 对受注册根约束的目标提出验证请求。
    Verification {
        /// 已注册的逻辑根别名。
        root: String,
        /// 已校验的、跨平台的相对目标。
        target: RelativeTarget,
    },
    /// 仅由 Host 模板 ID 和已校验 argv 组成的命令计划声明。
    Command {
        /// 已注册的 opaque 命令模板 ID。
        template_id: String,
        /// 与模板逐位匹配的安全参数。
        argv: Vec<String>,
    },
}

/// 将 plugin RPC response 的未解释 JSON 重新解析为受限 proposal 的 Host mediator。
///
/// mediator 不执行文件 I/O 或命令。调用方必须把 [`ValidatedProposal`] 再送入现有
/// core / policy / plan 链路，不能把它当成执行授权。
#[derive(Debug)]
pub struct CapabilityMediator<'a> {
    roots: &'a RootRegistry,
    commands: &'a CommandProposalCatalog,
}

impl<'a> CapabilityMediator<'a> {
    /// 创建一个使用给定逻辑根和命令模板目录的 mediator。
    pub const fn new(roots: &'a RootRegistry, commands: &'a CommandProposalCatalog) -> Self {
        Self { roots, commands }
    }

    /// 按已发出的 RPC method 验证一份 plugin result proposal。
    ///
    /// `initialize`、`describe` 与 `shutdown` 没有 capability proposal；未知字段、
    /// 不匹配的对象形状和未注册的命令都会在这里失败。
    pub fn validate(
        &self,
        method: PluginMethod,
        proposal: Value,
    ) -> Result<ValidatedProposal, HostError> {
        match method {
            PluginMethod::Observe => self.validate_file(proposal, ProposalKind::Observation),
            PluginMethod::Render => self.validate_file(proposal, ProposalKind::Render),
            PluginMethod::Verify => self.validate_file(proposal, ProposalKind::Verification),
            PluginMethod::PlanCommand => self.validate_command(proposal),
            PluginMethod::Initialize | PluginMethod::Describe | PluginMethod::Shutdown => {
                Err(HostError::InvalidProposal)
            }
        }
    }

    fn validate_file(
        &self,
        proposal: Value,
        kind: ProposalKind,
    ) -> Result<ValidatedProposal, HostError> {
        let proposal: RawFileProposal =
            serde_json::from_value(proposal).map_err(|_| HostError::InvalidProposal)?;
        let target =
            RelativeTarget::parse(&proposal.target).map_err(|_| HostError::InvalidTarget)?;
        self.roots
            .get(&proposal.root)
            .map_err(|_| HostError::UnknownRoot)?;
        Ok(match kind {
            ProposalKind::Observation => ValidatedProposal::Observation {
                root: proposal.root,
                target,
            },
            ProposalKind::Render => ValidatedProposal::Render {
                root: proposal.root,
                target,
            },
            ProposalKind::Verification => ValidatedProposal::Verification {
                root: proposal.root,
                target,
            },
        })
    }

    fn validate_command(&self, proposal: Value) -> Result<ValidatedProposal, HostError> {
        let proposal: RawCommandProposal =
            serde_json::from_value(proposal).map_err(|_| HostError::InvalidProposal)?;
        let template = self
            .commands
            .get(&proposal.template_id)
            .ok_or(HostError::UnknownCommand)?;
        template.validate_argv(&proposal.argv)?;
        Ok(ValidatedProposal::Command {
            template_id: proposal.template_id,
            argv: proposal.argv,
        })
    }
}

#[derive(Clone, Copy)]
enum ProposalKind {
    Observation,
    Render,
    Verification,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFileProposal {
    root: String,
    target: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCommandProposal {
    template_id: String,
    argv: Vec<String>,
}

fn validate_template_id(id: &str) -> Result<(), HostError> {
    if id.is_empty()
        || id.len() > MAX_TEMPLATE_ID_LEN
        || !id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
    {
        return Err(HostError::InvalidCommand);
    }
    Ok(())
}

fn validate_token(value: &str) -> Result<(), HostError> {
    validate_argument_shape(value, true)?;
    if !value.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || matches!(character, '.' | '_' | '-' | '+' | '@' | ':' | '/')
    }) {
        return Err(HostError::InvalidCommand);
    }
    if value
        .split('/')
        .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(HostError::InvalidCommand);
    }
    Ok(())
}

fn validate_argument_shape(value: &str, reject_leading_dash: bool) -> Result<(), HostError> {
    if value.is_empty()
        || value.len() > MAX_ARG_LEN
        || value.contains('\0')
        || value.chars().any(char::is_control)
        || value
            .chars()
            .any(|character| SHELL_METACHARACTERS.contains(&character))
        || looks_like_absolute_path(value)
        || (reject_leading_dash && value.starts_with('-'))
    {
        return Err(HostError::InvalidCommand);
    }
    Ok(())
}

fn looks_like_absolute_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.starts_with('/')
        || value.starts_with('\\')
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
}
