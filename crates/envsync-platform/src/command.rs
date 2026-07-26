//! 能力约束的命令执行器。
//!
//! M3 让 EnvSync 第一次需要**执行外部程序**（包管理器）。这是整个产品里权限最大的
//! 一件事，因此这里的设计目标不是「方便地跑命令」，而是「让每一次执行都可以被逐条
//! 审计」。M3 计划 Task 2 的六条要求逐一落在下面：
//!
//! 1. **只允许注册过的可执行文件身份与参数模板。** [`CommandRunner::register`] 是唯一
//!    入口；[`CommandRunner::run`] 只接受 [`CommandSpec`]，并逐位比对 [`CommandTemplate`]。
//!    绝对路径、参数个数、参数取值、cwd、环境变量名全部要对得上。
//! 2. **绝不经过 shell。** 始终 `Command::new(exe).args(argv)`；可执行文件名如果是
//!    `sh`、`bash`、`pwsh`、`cmd` 之类，注册与执行两道关卡都会拒绝
//!    （[`PlatformError::CommandShellRejected`]）。
//! 3. **stdin 不继承。** 恒为 [`Stdio::null`]，子进程读 stdin 立刻拿到 EOF。
//! 4. **超时与输出上限都会终止进程。** 见下面「进程树」一节。
//! 5. **注入的秘密在捕获输出里被脱敏。** [`SecretEnvValue`] 不实现 `Debug` / `Display`，
//!    `Drop` 时清零；捕获到的字节在转成字符串**之前**就被手写扫描替换为
//!    [`REDACTED_PLACEHOLDER`]。
//! 6. **收据只留摘要。** [`CommandOutcome::receipt`] 产出的 [`CommandReceipt`] 里没有
//!    环境变量，输出只保留头尾若干行与行数统计。
//!
//! ## 关于「终止进程树」的诚实说明
//!
//! 本 crate 是 `#![forbid(unsafe_code)]`。要真正杀掉**整棵**进程树，POSIX 上的做法是
//! 用 `CommandExt::process_group(0)` 把子进程放进新进程组，再对 `-pgid` 调
//! `killpg(2)`——而 `killpg` 只能通过 FFI 调用，那就必须引入 `unsafe`（自己写 `extern`
//! 声明）或引入 `libc`/`nix` 依赖。
//!
//! 我们选择**不**这么做：超时与输出超限时只调用 [`std::process::Child::kill`]，
//! 它只终止直接子进程。因此：
//!
//! > **已知限制：** 如果被执行的程序自己 fork 了后代（例如包管理器拉起的下载子进程），
//! > 这些孙进程在超时后**可能继续存活**，直到它们自己退出。
//!
//! 这个取舍是可接受的，因为：直接子进程一死，管道随之关闭，孙进程的输出不会再被
//! EnvSync 捕获或写入收据；能被注册的可执行文件是一份很小的白名单；而放宽
//! `forbid(unsafe_code)` 会削弱整个平台层最重要的一条静态保证。将来若确有需要，
//! 正确的做法是引入经过审计的 `nix`/`libc` 依赖并把 `killpg` 收敛到一个函数里，
//! 而不是在这里散落 `unsafe` 块。
//!
//! ## 示例
//!
//! ```no_run
//! use std::path::PathBuf;
//! use envsync_platform::command::{ArgPattern, CommandRunner, CommandSpec, CommandTemplate};
//!
//! let mut runner = CommandRunner::new();
//! runner.register(CommandTemplate::new(
//!     "brew.list",
//!     "homebrew",
//!     "brew",
//!     vec![ArgPattern::literal("list"), ArgPattern::literal("--versions")],
//! ))?;
//!
//! // `executable` 必须是能力探测得到的绝对路径。
//! let spec = CommandSpec::new("brew.list", PathBuf::from("/opt/homebrew/bin/brew"))
//!     .arg("list")
//!     .arg("--versions");
//! let outcome = runner.run(&spec)?;
//! println!("exit={:?}", outcome.exit_code);
//! # Ok::<(), envsync_platform::PlatformError>(())
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use envsync_domain::unix_millis_now;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::capability::AuthorizedRoot;
use crate::PlatformError;

/// 捕获输出的默认上限，同时也是**硬上限**：4 MiB。
///
/// 超过它就停止读取、终止进程并标记 [`CommandOutcome::truncated`]。包管理器的正常
/// 输出远小于这个量级，撞上它基本等同于「对端在刷屏」。
pub const MAX_OUTPUT_LIMIT: usize = 4 * 1024 * 1024;

/// 默认超时。
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// 允许配置的最长超时。
pub const MAX_TIMEOUT: Duration = Duration::from_secs(3600);

/// 脱敏后的替换文本。
pub const REDACTED_PLACEHOLDER: &str = "<redacted>";

/// 收据里保留的输出头部行数。
pub const RECEIPT_HEAD_LINES: usize = 20;

/// 收据里保留的输出尾部行数。
pub const RECEIPT_TAIL_LINES: usize = 20;

/// 参数模板允许的最大长度。
pub const MAX_ARGV_LEN: usize = 64;

/// 单个参数允许的最大字节长度。
pub const MAX_ARG_LEN: usize = 4096;

/// 环境变量名允许的最大字节长度。
pub const MAX_ENV_NAME_LEN: usize = 128;

/// 轮询子进程状态的间隔。
///
/// 取 5ms 是在「超时精度」和「空转开销」之间的折中：命令通常跑几百毫秒到几十秒，
/// 5ms 的误差可以忽略，而每秒 200 次 `try_wait` 的代价同样可以忽略。
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// 一律拒绝直接执行的解释器/shell 可执行文件名（不区分大小写，含 `.exe` 形式）。
///
/// 它们的存在意义就是「把一个字符串当成命令来解释」，一旦允许注册，参数模板的
/// 全部保证立刻归零。
const SHELL_EXECUTABLES: &[&str] = &[
    "ash",
    "bash",
    "busybox",
    "cmd",
    "command",
    "csh",
    "dash",
    "fish",
    "ksh",
    "powershell",
    "pwsh",
    "sh",
    "tcsh",
    "zsh",
];

/// 参数取值里一律拒绝的字符。
///
/// 我们并不经过 shell，所以这些字符本身不会被解释；拒绝它们是**纵深防御**：
/// 万一将来某个环节把 argv 拼回字符串（日志、诊断、别的工具），也不会凭空长出一条
/// 可执行的命令。
const SHELL_METACHARACTERS: &[char] = &[
    ';', '|', '&', '$', '`', '<', '>', '(', ')', '{', '}', '[', ']', '!', '*', '?', '~', '\'', '"',
    '\\', '\n', '\r',
];

/// EnvSync 为每个子进程固定设置的环境变量。
///
/// 包管理器的输出会被解析，因此 locale 必须固定：本地化过的输出会让 parser 在不同
/// 机器上给出不同结果（M3 计划 Task 5 Step 3）。
const FIXED_ENV: &[(&str, &str)] = &[("LC_ALL", "C"), ("LANG", "C")];

// ---------------------------------------------------------------------------
// 秘密环境变量取值
// ---------------------------------------------------------------------------

/// 要注入子进程环境的秘密取值。
///
/// 刻意**不实现** `Debug` / `Display` / `Serialize`：想把它变成字符串只有
/// `SecretEnvValue::expose` 这一条路，而它是 crate 私有的（因此这里不能写成
/// 文档链接），只有本模块在真正要把值交给 [`Command::env`] 时才调用。`Drop` 时清零。
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretEnvValue(String);

impl SecretEnvValue {
    /// 由明文构造。
    pub fn new(value: impl Into<String>) -> Self {
        SecretEnvValue(value.into())
    }

    /// 取值的字节长度。
    ///
    /// 长度**不是**秘密（收据里也不记它），暴露它只是为了让调用方能校验
    /// 「Vault 里真的取到了东西」。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 取值是否为空。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 借出明文。**只有**本 crate 在设置子进程环境与构造脱敏表时调用。
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// 参数模板
// ---------------------------------------------------------------------------

/// 占位符取值的形状约束。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueClass {
    /// 标识符：ASCII 字母数字与 `. _ - + @ : /`，且**不能以 `-` 开头**。
    ///
    /// 禁止以 `-` 开头是为了堵住选项注入：一个叫 `--force` 的「包名」会被目标程序
    /// 当成开关而不是操作数。
    Token,
    /// 绝对路径：必须是绝对路径、不含 `..` 分段、不含控制字符。
    AbsolutePath,
}

impl ValueClass {
    /// 校验一个占位符取值。
    fn validate(self, index: usize, value: &str) -> Result<(), PlatformError> {
        let reject =
            |reason: &'static str| Err(PlatformError::CommandArgRejected { index, reason });
        if value.is_empty() {
            return reject("参数不能为空");
        }
        if value.len() > MAX_ARG_LEN {
            return reject("参数超过长度上限");
        }
        if value.chars().any(char::is_control) {
            return reject("参数不能包含控制字符");
        }
        match self {
            ValueClass::Token => {
                if value.starts_with('-') {
                    return reject("Token 参数不能以 `-` 开头");
                }
                for ch in value.chars() {
                    let ok = ch.is_ascii_alphanumeric()
                        || matches!(ch, '.' | '_' | '-' | '+' | '@' | ':' | '/');
                    if !ok {
                        return reject("Token 参数含不允许的字符");
                    }
                }
            }
            ValueClass::AbsolutePath => {
                let path = Path::new(value);
                if !path.is_absolute() {
                    return reject("路径参数必须是绝对路径");
                }
                if path
                    .components()
                    .any(|component| matches!(component, Component::ParentDir))
                {
                    return reject("路径参数不能包含 `..`");
                }
            }
        }
        if value.chars().any(|ch| SHELL_METACHARACTERS.contains(&ch)) {
            return reject("参数不能包含 shell 元字符");
        }
        Ok(())
    }
}

/// 参数模板里的一个位置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgPattern {
    /// 固定字面量：调用方必须原样给出。
    Literal(String),
    /// 占位符：调用方给出的取值必须通过 [`ValueClass`] 校验。
    Placeholder {
        /// 占位符名字，只用于诊断。
        name: String,
        /// 取值约束。
        class: ValueClass,
    },
}

impl ArgPattern {
    /// 构造一个字面量位置。
    pub fn literal(value: impl Into<String>) -> Self {
        ArgPattern::Literal(value.into())
    }

    /// 构造一个 [`ValueClass::Token`] 占位符。
    pub fn token(name: impl Into<String>) -> Self {
        ArgPattern::Placeholder {
            name: name.into(),
            class: ValueClass::Token,
        }
    }

    /// 构造一个 [`ValueClass::AbsolutePath`] 占位符。
    pub fn absolute_path(name: impl Into<String>) -> Self {
        ArgPattern::Placeholder {
            name: name.into(),
            class: ValueClass::AbsolutePath,
        }
    }

    /// 校验调用方在这个位置给出的实参。
    fn check(&self, index: usize, actual: &str) -> Result<(), PlatformError> {
        match self {
            ArgPattern::Literal(expected) => {
                if expected == actual {
                    Ok(())
                } else {
                    Err(PlatformError::CommandArgRejected {
                        index,
                        reason: "与模板字面量不一致",
                    })
                }
            }
            ArgPattern::Placeholder { class, .. } => class.validate(index, actual),
        }
    }

    /// 注册时校验模板自身。
    fn validate_template(&self, index: usize) -> Result<(), PlatformError> {
        match self {
            ArgPattern::Literal(value) => {
                if value.is_empty() {
                    return Err(PlatformError::CommandArgRejected {
                        index,
                        reason: "模板字面量不能为空",
                    });
                }
                if value.len() > MAX_ARG_LEN {
                    return Err(PlatformError::CommandArgRejected {
                        index,
                        reason: "模板字面量超过长度上限",
                    });
                }
                if value.chars().any(char::is_control) {
                    return Err(PlatformError::CommandArgRejected {
                        index,
                        reason: "模板字面量不能包含控制字符",
                    });
                }
                Ok(())
            }
            ArgPattern::Placeholder { name, .. } => {
                if name.is_empty() {
                    return Err(PlatformError::CommandArgRejected {
                        index,
                        reason: "占位符必须有名字",
                    });
                }
                Ok(())
            }
        }
    }
}

/// 工作目录策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CwdPolicy {
    /// 不允许设置工作目录；子进程继承 EnvSync 自己的当前目录。
    Forbidden,
    /// 允许设置工作目录，但必须落在 [`CommandRunner::authorize_cwd_root`] 授权过的根之内。
    WithinAuthorizedRoots,
}

/// 一个被允许执行的命令模板。
///
/// 字段私有：所有取值都在 [`CommandRunner::register`] 里被校验过，之后不可再改。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandTemplate {
    id: &'static str,
    adapter: &'static str,
    executable_name: &'static str,
    argv: Vec<ArgPattern>,
    env_allowlist: BTreeSet<String>,
    env_inject_allowlist: BTreeSet<String>,
    cwd: CwdPolicy,
    max_timeout: Duration,
}

impl CommandTemplate {
    /// 构造一个模板：默认不允许 cwd、不透传任何环境变量、不注入秘密、超时上限
    /// 为 [`MAX_TIMEOUT`]。
    pub fn new(
        id: &'static str,
        adapter: &'static str,
        executable_name: &'static str,
        argv: Vec<ArgPattern>,
    ) -> Self {
        CommandTemplate {
            id,
            adapter,
            executable_name,
            argv,
            env_allowlist: BTreeSet::new(),
            env_inject_allowlist: BTreeSet::new(),
            cwd: CwdPolicy::Forbidden,
            max_timeout: MAX_TIMEOUT,
        }
    }

    /// 声明一个可以从当前进程透传的环境变量名。
    pub fn allow_env(mut self, name: impl Into<String>) -> Self {
        self.env_allowlist.insert(name.into());
        self
    }

    /// 声明一个可以由 Vault 注入的环境变量名。
    pub fn allow_env_inject(mut self, name: impl Into<String>) -> Self {
        self.env_inject_allowlist.insert(name.into());
        self
    }

    /// 设置工作目录策略。
    pub fn with_cwd(mut self, policy: CwdPolicy) -> Self {
        self.cwd = policy;
        self
    }

    /// 设置该模板允许的最长超时。
    pub fn with_max_timeout(mut self, timeout: Duration) -> Self {
        self.max_timeout = timeout;
        self
    }

    /// 模板标识。
    pub fn id(&self) -> &'static str {
        self.id
    }

    /// 归属的适配器。
    pub fn adapter(&self) -> &'static str {
        self.adapter
    }

    /// 允许的可执行文件名（不含目录）。
    pub fn executable_name(&self) -> &'static str {
        self.executable_name
    }

    /// 参数模板。
    pub fn argv(&self) -> &[ArgPattern] {
        &self.argv
    }
}

// ---------------------------------------------------------------------------
// 执行请求
// ---------------------------------------------------------------------------

/// 一次具体的执行请求。
pub struct CommandSpec {
    /// 稳定的模板标识，会原样写进收据。
    pub template_id: &'static str,
    /// 可执行文件的**绝对路径**，由能力探测得到。
    pub executable: PathBuf,
    /// 参数列表，**不含**可执行文件本身。
    pub argv: Vec<String>,
    /// 工作目录；必须落在授权根之内。
    pub cwd: Option<PathBuf>,
    /// 允许从当前进程透传的环境变量名。
    pub env_allowlist: Vec<String>,
    /// 由 Vault 注入的环境变量。
    pub env_inject: BTreeMap<String, SecretEnvValue>,
    /// 超时。
    pub timeout: Duration,
    /// stdout 捕获上限。
    pub stdout_limit: usize,
    /// stderr 捕获上限。
    pub stderr_limit: usize,
}

impl CommandSpec {
    /// 构造一个最小请求：无参数、无 cwd、无环境变量，超时与上限取默认值。
    pub fn new(template_id: &'static str, executable: PathBuf) -> Self {
        CommandSpec {
            template_id,
            executable,
            argv: Vec::new(),
            cwd: None,
            env_allowlist: Vec::new(),
            env_inject: BTreeMap::new(),
            timeout: DEFAULT_TIMEOUT,
            stdout_limit: MAX_OUTPUT_LIMIT,
            stderr_limit: MAX_OUTPUT_LIMIT,
        }
    }

    /// 追加一个参数。
    pub fn arg(mut self, value: impl Into<String>) -> Self {
        self.argv.push(value.into());
        self
    }

    /// 设置工作目录。
    pub fn cwd(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    /// 追加一个透传环境变量名。
    pub fn allow_env(mut self, name: impl Into<String>) -> Self {
        self.env_allowlist.push(name.into());
        self
    }

    /// 注入一个秘密环境变量。
    pub fn inject_env(mut self, name: impl Into<String>, value: SecretEnvValue) -> Self {
        self.env_inject.insert(name.into(), value);
        self
    }

    /// 设置超时。
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 设置 stdout / stderr 的捕获上限。
    pub fn output_limits(mut self, stdout: usize, stderr: usize) -> Self {
        self.stdout_limit = stdout;
        self.stderr_limit = stderr;
        self
    }
}

impl std::fmt::Debug for CommandSpec {
    /// 手写实现：派生的 `Debug` 会在将来某天把 `env_inject` 的取值打出来。这里只列
    /// **变量名**，取值本身连类型都没有 `Debug`。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandSpec")
            .field("template_id", &self.template_id)
            .field("executable", &self.executable)
            .field("argv", &self.argv)
            .field("cwd", &self.cwd)
            .field("env_allowlist", &self.env_allowlist)
            .field(
                "env_inject",
                &self.env_inject.keys().collect::<Vec<&String>>(),
            )
            .field("timeout", &self.timeout)
            .field("stdout_limit", &self.stdout_limit)
            .field("stderr_limit", &self.stderr_limit)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// 执行结果与收据
// ---------------------------------------------------------------------------

/// 一次执行的结果。
///
/// `stdout` / `stderr` **已经**脱敏并按上限截断，可以直接展示；但它们仍然是完整输出，
/// 写入操作日志请用 [`CommandOutcome::receipt`]。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutcome {
    /// 归属的适配器。
    pub adapter: &'static str,
    /// 模板标识。
    pub template_id: &'static str,
    /// 退出码。
    ///
    /// `None` 表示进程**没有正常退出**：被 EnvSync 因输出超限终止，或被信号杀死。
    /// 调用方必须把它当作失败处理。见 [`CommandOutcome::killed_for_output`]。
    pub exit_code: Option<i32>,
    /// 已脱敏、已截断的 stdout。
    pub stdout: String,
    /// 已脱敏、已截断的 stderr。
    pub stderr: String,
    /// 启动时刻（Unix 毫秒）。
    pub started_at_unix_ms: u64,
    /// 结束时刻（Unix 毫秒）。
    pub finished_at_unix_ms: u64,
    /// 是否有输出因为撞上上限而被丢弃。
    pub truncated: bool,
}

impl CommandOutcome {
    /// 是否正常退出且退出码为 0。
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }

    /// 是否因为输出超限而被 EnvSync 终止。
    ///
    /// 判据是「没有退出码」且「有输出被丢弃」。被信号杀死同时输出又恰好超限时会与
    /// 本情形混淆，但两者对调用方的含义相同：这次执行不可信，必须当作失败。
    pub fn killed_for_output(&self) -> bool {
        self.exit_code.is_none() && self.truncated
    }

    /// 执行耗时（毫秒）。
    pub fn duration_ms(&self) -> u64 {
        self.finished_at_unix_ms
            .saturating_sub(self.started_at_unix_ms)
    }

    /// 生成写入操作日志的收据。
    ///
    /// 收据里**没有**任何环境变量（更不会有注入的秘密），输出只保留头
    /// [`RECEIPT_HEAD_LINES`] 行、尾 [`RECEIPT_TAIL_LINES`] 行与行数统计。
    pub fn receipt(&self) -> CommandReceipt {
        CommandReceipt {
            adapter: self.adapter,
            template_id: self.template_id,
            exit_code: self.exit_code,
            started_at_unix_ms: self.started_at_unix_ms,
            finished_at_unix_ms: self.finished_at_unix_ms,
            truncated: self.truncated,
            stdout: OutputSummary::of(&self.stdout),
            stderr: OutputSummary::of(&self.stderr),
        }
    }
}

/// 输出摘要：头尾若干行 + 行数统计。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OutputSummary {
    /// 头部若干行。
    pub head: Vec<String>,
    /// 尾部若干行；与 `head` 不重叠。
    pub tail: Vec<String>,
    /// 输出总行数。
    pub line_count: usize,
    /// 既不在 `head` 也不在 `tail` 里的行数。
    pub omitted_lines: usize,
}

impl OutputSummary {
    /// 由已脱敏的完整文本生成摘要。
    pub fn of(text: &str) -> Self {
        let lines: Vec<&str> = if text.is_empty() {
            Vec::new()
        } else {
            text.lines().collect()
        };
        let total = lines.len();
        if total <= RECEIPT_HEAD_LINES + RECEIPT_TAIL_LINES {
            return OutputSummary {
                head: lines.iter().map(|line| (*line).to_owned()).collect(),
                tail: Vec::new(),
                line_count: total,
                omitted_lines: 0,
            };
        }
        let head = lines[..RECEIPT_HEAD_LINES]
            .iter()
            .map(|line| (*line).to_owned())
            .collect();
        let tail = lines[total - RECEIPT_TAIL_LINES..]
            .iter()
            .map(|line| (*line).to_owned())
            .collect();
        OutputSummary {
            head,
            tail,
            line_count: total,
            omitted_lines: total - RECEIPT_HEAD_LINES - RECEIPT_TAIL_LINES,
        }
    }
}

/// 写入操作日志的执行收据。
///
/// 结构上不可能携带秘密：它没有环境变量字段，输出摘要来自**已脱敏**的文本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandReceipt {
    /// 归属的适配器。
    pub adapter: &'static str,
    /// 模板标识。
    pub template_id: &'static str,
    /// 退出码；`None` 表示未正常退出。
    pub exit_code: Option<i32>,
    /// 启动时刻（Unix 毫秒）。
    pub started_at_unix_ms: u64,
    /// 结束时刻（Unix 毫秒）。
    pub finished_at_unix_ms: u64,
    /// 是否有输出被丢弃。
    pub truncated: bool,
    /// stdout 摘要。
    pub stdout: OutputSummary,
    /// stderr 摘要。
    pub stderr: OutputSummary,
}

// ---------------------------------------------------------------------------
// 执行器
// ---------------------------------------------------------------------------

/// 命令执行器：模板注册表 + 唯一的执行入口。
#[derive(Debug, Default)]
pub struct CommandRunner {
    templates: BTreeMap<&'static str, CommandTemplate>,
    cwd_roots: Vec<PathBuf>,
}

impl CommandRunner {
    /// 构造一个空执行器：没有任何模板，因此**什么都跑不了**。
    pub fn new() -> Self {
        CommandRunner::default()
    }

    /// 注册一个模板。
    ///
    /// 重复标识、shell 可执行文件、带目录分隔符的可执行文件名、非法参数模板与非法
    /// 环境变量名都会被拒绝。
    pub fn register(&mut self, template: CommandTemplate) -> Result<(), PlatformError> {
        if template.id.is_empty() {
            return Err(PlatformError::CommandSpecInvalid {
                reason: "模板标识不能为空",
            });
        }
        if self.templates.contains_key(template.id) {
            return Err(PlatformError::CommandTemplateDuplicate {
                template_id: template.id,
            });
        }
        check_executable_name(template.executable_name)?;
        if template.argv.len() > MAX_ARGV_LEN {
            return Err(PlatformError::CommandSpecInvalid {
                reason: "参数模板超过长度上限",
            });
        }
        for (index, pattern) in template.argv.iter().enumerate() {
            pattern.validate_template(index)?;
        }
        for name in template
            .env_allowlist
            .iter()
            .chain(template.env_inject_allowlist.iter())
        {
            check_env_name(name)?;
        }
        if template.max_timeout.is_zero() || template.max_timeout > MAX_TIMEOUT {
            return Err(PlatformError::CommandSpecInvalid {
                reason: "模板超时上限不合法",
            });
        }
        self.templates.insert(template.id, template);
        Ok(())
    }

    /// 授权一个可以作为工作目录的根。
    ///
    /// 路径会被 `canonicalize`（因此符号链接在这里就被解开），之后 [`CommandRunner::run`]
    /// 用同样 canonical 化的 cwd 做前缀比较。
    pub fn authorize_cwd_root(&mut self, root: &AuthorizedRoot) -> Result<(), PlatformError> {
        let canonical = root
            .path()
            .canonicalize()
            .map_err(|error| PlatformError::io("解析工作目录授权根", &error))?;
        self.cwd_roots.push(canonical);
        Ok(())
    }

    /// 已注册的模板。
    pub fn template(&self, id: &str) -> Option<&CommandTemplate> {
        self.templates.get(id)
    }

    /// 已注册模板的个数。
    pub fn len(&self) -> usize {
        self.templates.len()
    }

    /// 是否没有注册任何模板。
    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }

    /// 执行一次命令。
    ///
    /// 全部校验都在 `spawn` **之前**完成：任何一项不满足就直接返回错误，进程根本不会
    /// 被创建。
    pub fn run(&self, spec: &CommandSpec) -> Result<CommandOutcome, PlatformError> {
        let template = self.templates.get(spec.template_id).ok_or_else(|| {
            PlatformError::CommandTemplateUnknown {
                template_id: spec.template_id.to_owned(),
            }
        })?;

        self.check_executable(template, spec)?;
        check_argv(template, spec)?;
        self.check_cwd(template, spec)?;
        check_env(template, spec)?;
        check_budgets(template, spec)?;

        let mut command = Command::new(&spec.executable);
        command
            .args(&spec.argv)
            // stdin 不继承：子进程读 stdin 立刻 EOF，绝不会挂在等待用户输入上。
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // 先清空再逐项加回：默认继承整个环境等于把 EnvSync 见过的所有秘密
            // 交给子进程。
            .env_clear();
        for (name, value) in FIXED_ENV {
            command.env(name, value);
        }
        for name in &spec.env_allowlist {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        // 注入放在最后：即使某个名字同时出现在透传清单里，注入值也一定胜出。
        for (name, value) in &spec.env_inject {
            command.env(name, value.expose());
        }
        if let Some(dir) = &spec.cwd {
            command.current_dir(dir);
        }

        let started_at_unix_ms = unix_millis_now();
        let mut child = command
            .spawn()
            .map_err(|error| PlatformError::io("启动子进程", &error))?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let capture = pump(&mut child, stdout, stderr, spec)?;
        let finished_at_unix_ms = unix_millis_now();

        if capture.timed_out {
            return Err(PlatformError::CommandTimeout {
                template_id: template.id,
                timeout_ms: spec.timeout.as_millis().min(u128::from(u64::MAX)) as u64,
            });
        }

        let needles = redaction_needles(spec);
        let truncated = capture.stdout_truncated || capture.stderr_truncated;
        if truncated {
            tracing::warn!(
                template = template.id,
                adapter = template.adapter,
                "命令输出超过上限，已终止进程并截断捕获"
            );
        }

        Ok(CommandOutcome {
            adapter: template.adapter,
            template_id: template.id,
            // 主动杀掉的进程一律记为「没有退出码」：Windows 上 `Child::kill` 会留下
            // 一个看起来正常的退出码 1，照抄会把「被我们杀了」伪装成「跑完了」。
            exit_code: if capture.killed {
                None
            } else {
                capture.status.and_then(|status| status.code())
            },
            stdout: redact_to_string(&capture.stdout, &needles),
            stderr: redact_to_string(&capture.stderr, &needles),
            started_at_unix_ms,
            finished_at_unix_ms,
            truncated,
        })
    }

    /// 校验可执行文件：绝对路径、无 `..`、文件名与模板一致、不是 shell、确实可执行。
    fn check_executable(
        &self,
        template: &CommandTemplate,
        spec: &CommandSpec,
    ) -> Result<(), PlatformError> {
        let path = spec.executable.as_path();
        if !path.is_absolute() {
            return Err(PlatformError::CommandExecutableRejected {
                reason: "可执行文件必须是绝对路径",
            });
        }
        if path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(PlatformError::CommandExecutableRejected {
                reason: "可执行文件路径不能包含 `..`",
            });
        }
        let name = path.file_name().and_then(|name| name.to_str()).ok_or(
            PlatformError::CommandExecutableRejected {
                reason: "无法取得可执行文件名",
            },
        )?;
        reject_shell(name)?;
        if name != template.executable_name {
            return Err(PlatformError::CommandExecutableRejected {
                reason: "可执行文件名与模板不一致",
            });
        }
        let metadata =
            std::fs::metadata(path).map_err(|error| PlatformError::io("检查可执行文件", &error))?;
        if !metadata.is_file() {
            return Err(PlatformError::CommandExecutableRejected {
                reason: "目标不是普通文件",
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(PlatformError::CommandExecutableRejected {
                    reason: "目标没有可执行位",
                });
            }
        }
        Ok(())
    }

    /// 校验工作目录。
    fn check_cwd(
        &self,
        template: &CommandTemplate,
        spec: &CommandSpec,
    ) -> Result<(), PlatformError> {
        let Some(dir) = &spec.cwd else {
            return Ok(());
        };
        if template.cwd == CwdPolicy::Forbidden {
            return Err(PlatformError::CommandCwdRejected {
                reason: "模板未声明工作目录",
            });
        }
        if !dir.is_absolute() {
            return Err(PlatformError::CommandCwdRejected {
                reason: "工作目录必须是绝对路径",
            });
        }
        let canonical = dir
            .canonicalize()
            .map_err(|error| PlatformError::io("解析工作目录", &error))?;
        if !canonical.is_dir() {
            return Err(PlatformError::CommandCwdRejected {
                reason: "工作目录不是目录",
            });
        }
        if self
            .cwd_roots
            .iter()
            .any(|root| canonical.starts_with(root))
        {
            Ok(())
        } else {
            Err(PlatformError::CommandCwdRejected {
                reason: "工作目录不在任何授权根之内",
            })
        }
    }
}

/// 校验参数：个数必须与模板完全一致，逐位比对。
fn check_argv(template: &CommandTemplate, spec: &CommandSpec) -> Result<(), PlatformError> {
    if spec.argv.len() != template.argv.len() {
        return Err(PlatformError::CommandArgRejected {
            index: spec.argv.len().min(template.argv.len()),
            reason: "参数个数与模板不一致",
        });
    }
    for (index, (pattern, actual)) in template.argv.iter().zip(spec.argv.iter()).enumerate() {
        if actual.as_bytes().contains(&0) {
            return Err(PlatformError::CommandArgRejected {
                index,
                reason: "参数不能包含 NUL 字节",
            });
        }
        pattern.check(index, actual)?;
    }
    Ok(())
}

/// 校验环境变量：名字合法，且必须出现在模板声明里。
fn check_env(template: &CommandTemplate, spec: &CommandSpec) -> Result<(), PlatformError> {
    for name in &spec.env_allowlist {
        check_env_name(name)?;
        if !template.env_allowlist.contains(name) {
            return Err(PlatformError::CommandEnvRejected {
                name: name.clone(),
                reason: "模板未声明该透传环境变量",
            });
        }
    }
    for name in spec.env_inject.keys() {
        check_env_name(name)?;
        if !template.env_inject_allowlist.contains(name) {
            return Err(PlatformError::CommandEnvRejected {
                name: name.clone(),
                reason: "模板未声明该注入环境变量",
            });
        }
    }
    Ok(())
}

/// 校验超时与输出上限。
fn check_budgets(template: &CommandTemplate, spec: &CommandSpec) -> Result<(), PlatformError> {
    if spec.timeout.is_zero() {
        return Err(PlatformError::CommandSpecInvalid {
            reason: "超时必须为正",
        });
    }
    if spec.timeout > template.max_timeout || spec.timeout > MAX_TIMEOUT {
        return Err(PlatformError::CommandSpecInvalid {
            reason: "超时超过模板允许的上限",
        });
    }
    for limit in [spec.stdout_limit, spec.stderr_limit] {
        if limit == 0 {
            return Err(PlatformError::CommandSpecInvalid {
                reason: "输出上限必须为正",
            });
        }
        if limit > MAX_OUTPUT_LIMIT {
            return Err(PlatformError::CommandSpecInvalid {
                reason: "输出上限超过 4 MiB 硬上限",
            });
        }
    }
    Ok(())
}

/// 可执行文件名的静态校验（注册期）。
fn check_executable_name(name: &str) -> Result<(), PlatformError> {
    if name.is_empty() {
        return Err(PlatformError::CommandExecutableRejected {
            reason: "可执行文件名不能为空",
        });
    }
    if name.contains('/') || name.contains('\\') {
        return Err(PlatformError::CommandExecutableRejected {
            reason: "模板里的可执行文件名不能包含目录分隔符",
        });
    }
    reject_shell(name)
}

/// 拒绝 shell / 解释器。
fn reject_shell(name: &str) -> Result<(), PlatformError> {
    let lowered = name.to_ascii_lowercase();
    let stem = lowered.strip_suffix(".exe").unwrap_or(&lowered);
    if SHELL_EXECUTABLES.contains(&stem) {
        return Err(PlatformError::CommandShellRejected {
            name: stem.to_owned(),
        });
    }
    Ok(())
}

/// 环境变量名校验。
fn check_env_name(name: &str) -> Result<(), PlatformError> {
    let invalid = |reason: &'static str| {
        Err(PlatformError::CommandEnvRejected {
            name: name.to_owned(),
            reason,
        })
    };
    if name.is_empty() {
        return invalid("环境变量名不能为空");
    }
    if name.len() > MAX_ENV_NAME_LEN {
        return invalid("环境变量名超过长度上限");
    }
    if name.starts_with(|ch: char| ch.is_ascii_digit()) {
        return invalid("环境变量名不能以数字开头");
    }
    for ch in name.chars() {
        if !(ch.is_ascii_alphanumeric() || ch == '_') {
            return invalid("环境变量名只允许 ASCII 字母、数字与下划线");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 捕获、超时与终止
// ---------------------------------------------------------------------------

/// 一次捕获的原始结果。
struct Capture {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
    status: Option<ExitStatus>,
    killed: bool,
    timed_out: bool,
}

/// 并发读取两条管道，同时轮询子进程状态。
///
/// **必须**用两个线程分别读 stdout 与 stderr：顺序读取时，只要子进程把另一条管道写满
/// （典型是 64 KiB），双方就会互相等待，形成死锁。
fn pump(
    child: &mut Child,
    stdout: Option<std::process::ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
    spec: &CommandSpec,
) -> Result<Capture, PlatformError> {
    let over_limit = AtomicBool::new(false);
    let deadline = Instant::now() + spec.timeout;

    thread::scope(|scope| {
        let stdout_reader = scope.spawn(|| read_capped(stdout, spec.stdout_limit, &over_limit));
        let stderr_reader = scope.spawn(|| read_capped(stderr, spec.stderr_limit, &over_limit));

        let mut killed = false;
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {}
                Err(error) => return Err(PlatformError::io("等待子进程", &error)),
            }
            if over_limit.load(Ordering::Relaxed) {
                killed = true;
            } else if Instant::now() >= deadline {
                killed = true;
                timed_out = true;
            }
            if killed {
                // 只杀直接子进程；孙进程可能存活，理由见模块文档。
                let _ = child.kill();
                break child.wait().ok();
            }
            thread::sleep(POLL_INTERVAL);
        };

        let (stdout, stdout_truncated) = stdout_reader
            .join()
            .map_err(|_| reader_panicked("stdout"))?;
        let (stderr, stderr_truncated) = stderr_reader
            .join()
            .map_err(|_| reader_panicked("stderr"))?;

        Ok(Capture {
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
            status,
            killed,
            timed_out,
        })
    })
}

/// 读线程 panic 时的错误（正常路径不可达：[`read_capped`] 不会 panic）。
fn reader_panicked(stream: &'static str) -> PlatformError {
    PlatformError::Io {
        operation: "读取子进程输出",
        kind: io::ErrorKind::Other,
        detail: format!("{stream} 读取线程异常终止"),
    }
}

/// 带上限地读完一条管道。
///
/// 撞上限时立刻停止读取并置位 `over_limit`，由轮询线程负责杀进程。返回值的第二项
/// 表示「有输出被丢弃」。
fn read_capped<R: Read>(
    reader: Option<R>,
    limit: usize,
    over_limit: &AtomicBool,
) -> (Vec<u8>, bool) {
    let Some(mut reader) = reader else {
        return (Vec::new(), false);
    };
    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                let remaining = limit.saturating_sub(buffer.len());
                if count > remaining {
                    buffer.extend_from_slice(&chunk[..remaining]);
                    over_limit.store(true, Ordering::Relaxed);
                    return (buffer, true);
                }
                buffer.extend_from_slice(&chunk[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            // 进程被杀之后读端会拿到错误，这不是需要上报的失败。
            Err(_) => break,
        }
    }
    (buffer, false)
}

// ---------------------------------------------------------------------------
// 脱敏
// ---------------------------------------------------------------------------

/// 收集需要脱敏的字节串，按长度降序（优先替换更长的匹配）。
fn redaction_needles(spec: &CommandSpec) -> Vec<&[u8]> {
    let mut needles: Vec<&[u8]> = spec
        .env_inject
        .values()
        .map(|value| value.expose().as_bytes())
        .filter(|bytes| !bytes.is_empty())
        .collect();
    needles.sort_unstable_by_key(|needle| std::cmp::Reverse(needle.len()));
    needles.dedup();
    needles
}

/// 先在**字节**上脱敏，再做有损 UTF-8 转换。
///
/// 顺序很关键：如果先转字符串，一个跨越无效 UTF-8 边界的秘密会被替换字符切断，
/// 从而躲过脱敏。
fn redact_to_string(raw: &[u8], needles: &[&[u8]]) -> String {
    String::from_utf8_lossy(&redact_bytes(raw, needles)).into_owned()
}

/// 手写的多模式替换扫描。**不引入正则引擎。**
///
/// 每个位置最多尝试 `needles.len()` 次前缀比较，因此代价是
/// O(haystack × needles × needle_len)；在 4 MiB 上限与个位数注入变量的前提下完全可控。
fn redact_bytes(haystack: &[u8], needles: &[&[u8]]) -> Vec<u8> {
    if needles.is_empty() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut index = 0usize;
    'outer: while index < haystack.len() {
        for needle in needles {
            if starts_with_at(haystack, index, needle) {
                out.extend_from_slice(REDACTED_PLACEHOLDER.as_bytes());
                index += needle.len();
                continue 'outer;
            }
        }
        out.push(haystack[index]);
        index += 1;
    }
    out
}

/// `haystack[at..]` 是否以 `needle` 开头（手写字节比较）。
fn starts_with_at(haystack: &[u8], at: usize, needle: &[u8]) -> bool {
    if needle.is_empty() || at + needle.len() > haystack.len() {
        return false;
    }
    let mut offset = 0usize;
    while offset < needle.len() {
        if haystack[at + offset] != needle[offset] {
            return false;
        }
        offset += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_executables_are_rejected_in_every_spelling() {
        assert!(reject_shell("sh").is_err());
        assert!(reject_shell("BASH").is_err());
        assert!(reject_shell("cmd.exe").is_err());
        assert!(reject_shell("PowerShell.EXE").is_err());
        assert!(reject_shell("brew").is_ok());
        assert!(reject_shell("echo").is_ok());
    }

    #[test]
    fn token_values_reject_option_injection_and_metacharacters() {
        assert!(ValueClass::Token.validate(0, "ripgrep").is_ok());
        assert!(ValueClass::Token.validate(0, "@scope/pkg").is_ok());
        assert!(ValueClass::Token.validate(0, "--force").is_err());
        assert!(ValueClass::Token.validate(0, "a; rm -rf /").is_err());
        assert!(ValueClass::Token.validate(0, "a b").is_err());
        assert!(ValueClass::Token.validate(0, "").is_err());
    }

    #[test]
    fn absolute_path_values_reject_traversal() {
        assert!(ValueClass::AbsolutePath.validate(0, "/tmp/x.txt").is_ok());
        assert!(ValueClass::AbsolutePath.validate(0, "tmp/x.txt").is_err());
        assert!(ValueClass::AbsolutePath.validate(0, "/tmp/../etc").is_err());
    }

    #[test]
    fn redaction_replaces_every_occurrence_and_prefers_longer_secrets() {
        let secrets: Vec<&[u8]> = vec![b"SUPERSECRETVALUE", b"SECRET"];
        let redacted = redact_bytes(b"a SUPERSECRETVALUE b SECRET c", &secrets);
        assert_eq!(
            String::from_utf8_lossy(&redacted),
            "a <redacted> b <redacted> c"
        );
    }

    #[test]
    fn redaction_survives_invalid_utf8() {
        let secrets: Vec<&[u8]> = vec![b"TOKEN"];
        let raw = [0xffu8, b'T', b'O', b'K', b'E', b'N', 0xfe];
        let text = redact_to_string(&raw, &secrets);
        assert!(text.contains("<redacted>"));
        assert!(!text.contains("TOKEN"));
    }

    #[test]
    fn output_summary_keeps_head_and_tail_only() {
        let text: String = (0..100)
            .map(|index| format!("line{index}\n"))
            .collect::<Vec<String>>()
            .concat();
        let summary = OutputSummary::of(&text);
        assert_eq!(summary.line_count, 100);
        assert_eq!(summary.head.len(), RECEIPT_HEAD_LINES);
        assert_eq!(summary.tail.len(), RECEIPT_TAIL_LINES);
        assert_eq!(
            summary.omitted_lines,
            100 - RECEIPT_HEAD_LINES - RECEIPT_TAIL_LINES
        );
        assert_eq!(summary.head[0], "line0");
        assert_eq!(summary.tail[RECEIPT_TAIL_LINES - 1], "line99");
    }

    #[test]
    fn short_output_is_kept_whole() {
        let summary = OutputSummary::of("a\nb\n");
        assert_eq!(summary.head, vec!["a".to_owned(), "b".to_owned()]);
        assert!(summary.tail.is_empty());
        assert_eq!(summary.omitted_lines, 0);
    }

    #[test]
    fn command_spec_debug_never_shows_injected_values() {
        let spec = CommandSpec::new("t", PathBuf::from("/bin/echo"))
            .inject_env("TOKEN", SecretEnvValue::new("super-secret"));
        let rendered = format!("{spec:?}");
        assert!(rendered.contains("TOKEN"));
        assert!(!rendered.contains("super-secret"));
    }

    #[test]
    fn env_names_are_validated() {
        assert!(check_env_name("HOMEBREW_NO_AUTO_UPDATE").is_ok());
        assert!(check_env_name("1BAD").is_err());
        assert!(check_env_name("BAD=NAME").is_err());
        assert!(check_env_name("").is_err());
    }
}
