#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! EnvSync 内建适配器框架与首批内建适配器。
//!
//! 适配器回答三个问题：
//!
//! 1. **这台设备上有哪些资源应该被管理**（[`Adapter::discover`]）；
//! 2. **从一份原始文件里应该抽出哪些字节作为受管内容**（[`Adapter::capture`]）；
//! 3. **给定受管内容，目标文件最终应该长成什么样**（[`Adapter::render`]、
//!    [`Adapter::verify`]）。
//!
//! # 纯函数与最小权限
//!
//! 适配器的四个方法**全部是纯函数**：不读文件系统、不取时钟、不使用随机数、不发起
//! 网络请求。它们拿到的唯一上下文是 [`AdapterContext`]，其中**没有** Backend、没有
//! Journal、没有文件系统句柄，只有设备 Profile 与「授权根别名 -> 相对前缀」的映射。
//! 因此适配器既无法越权访问用户磁盘，也无法把任何本机绝对路径写进产出物：
//! [`DiscoveredResource::target`] 永远是**相对授权根**的路径。
//!
//! 真正的读、写、备份、回滚全部由宿主（`envsync-core` 的捕获与应用服务，配合
//! `envsync-platform` 的能力句柄）完成。
//!
//! # 为什么 [`Adapter`] 是 sealed 的
//!
//! [`Adapter`] 继承了一个私有的 `sealed::Sealed`，因此**只有本 crate 内的类型能实现
//! 它**。M1 刻意只允许编译期内建适配器：一个能被任意 crate 实现的 trait 等价于把
//! 「在 EnvSync 进程内执行任意代码」这一权限开放给第三方，而适配器恰好负责决定
//! 「哪些文件会被读写」。
//!
//! M4 的插件 SDK **不会**放开这个 trait，而是走独立的进程隔离通道：插件运行在单独的
//! 子进程里，通过受限的 IPC 协议交换与本模块同构的消息（descriptor / discover /
//! capture / render / verify），由宿主在边界上做能力裁剪与资源配额。换句话说，扩展点
//! 是**协议**而不是 trait 实现。
//!
//! # 模块划分
//!
//! | 模块 | 内容 |
//! |---|---|
//! | [`mod@file`] | 通用文件适配器引擎：Full File / Managed Block / Structured Merge |
//! | [`shell`] | Bash / Zsh RC 与 PowerShell Profile |
//! | [`wezterm`] | WezTerm Lua（Generated Include） |
//! | [`git_config`] | 用户级 Git 配置（结构化合并）与系统级 Git 配置（只观察） |

use std::collections::BTreeMap;

use envsync_domain::id::ResourceId;
use envsync_domain::profile::{DeviceProfile, Os, Selector};
use envsync_domain::resource::{DesiredDisposition, FileMode, ResourcePolicy};

pub mod file;
pub mod git_config;
pub mod shell;
pub mod wezterm;

/// 用户主目录授权根的约定别名。
///
/// 宿主必须为该别名注册一个授权根；[`AdapterContext::prefix`] 在 `roots` 里找不到它
/// 时会退回 [`AdapterContext::home_relative`]。
pub const ROOT_HOME: &str = "home";

/// 系统级配置授权根的约定别名（例如 POSIX 的 `/etc`）。
///
/// 该根**只用于观察**：内建适配器在这个根下产出的资源处置恒为
/// [`DesiredDisposition::Unmanaged`]。宿主没有注册该别名时，相关资源不会出现在
/// [`Adapter::discover`] 的结果里。
pub const ROOT_SYSTEM: &str = "system";

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

/// 适配器层错误。
///
/// 所有变体的 `Display` 输出都**不含本机绝对路径**：只出现资源标识、授权根别名和
/// 相对分段，可以直接写进日志或 JSON 诊断。
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// 注册表中已存在同名适配器。
    #[error("适配器 ID `{0}` 已注册")]
    DuplicateAdapterId(&'static str),
    /// 请求的资源不属于该适配器。
    #[error("资源 {0} 不属于该适配器")]
    UnknownResource(ResourceId),
    /// 由授权根前缀与相对分段拼接出的目标非法。
    #[error("授权根 `{root}` 下的相对目标非法：{source}")]
    InvalidTarget {
        /// 授权根别名。
        root: &'static str,
        /// 平台层给出的具体原因。
        #[source]
        source: envsync_platform::PlatformError,
    },
    /// 渲染失败（marker 异常、非 UTF-8、超出字节上限等）。
    #[error("渲染资源失败：{0}")]
    Render(#[from] envsync_core::render::RenderError),
    /// 结构化内容解析失败。
    #[error("资源 {resource} 的结构化内容非法：{detail}")]
    Structured {
        /// 出错的资源。
        resource: ResourceId,
        /// 只描述结构位置，不含文件正文。
        detail: String,
    },
    /// 该资源只观察、不写入。
    ///
    /// 处置为 [`DesiredDisposition::Unmanaged`] 的资源（例如系统级 Git 配置）不会被
    /// 采集内容，也**永远不会**被渲染成待写入字节。
    #[error("资源 {0} 只观察不写入")]
    ObserveOnly(ResourceId),
    /// 目标文件与期望不符。
    #[error("资源 {resource} 校验失败：{detail}")]
    VerifyFailed {
        /// 出错的资源。
        resource: ResourceId,
        /// 失败原因，不含文件正文。
        detail: String,
    },
}

impl AdapterError {
    /// 稳定错误码，用于日志与跨版本比对；展示文案可以改，错误码不可以。
    pub fn code(&self) -> &'static str {
        match self {
            AdapterError::DuplicateAdapterId(_) => "adapter.duplicate_id",
            AdapterError::UnknownResource(_) => "adapter.unknown_resource",
            AdapterError::InvalidTarget { .. } => "adapter.invalid_target",
            AdapterError::Render(_) => "adapter.render",
            AdapterError::Structured { .. } => "adapter.structured",
            AdapterError::ObserveOnly(_) => "adapter.observe_only",
            AdapterError::VerifyFailed { .. } => "adapter.verify_failed",
        }
    }
}

// ---------------------------------------------------------------------------
// 描述符与上下文
// ---------------------------------------------------------------------------

/// 适配器自述。
///
/// 全部字段都是 `'static`：描述符是编译期常量，不依赖任何运行期状态，因此
/// [`AdapterRegistry`] 可以在不构造任何设备上下文的情况下枚举与过滤适配器。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterDescriptor {
    /// 稳定 ID，例如 `builtin.shell.zsh`。
    ///
    /// 该 ID 会进入日志、配置与诊断输出，**跨版本不得更改**；语义变化请提升
    /// [`AdapterDescriptor::version`]。
    pub id: &'static str,
    /// 适配器版本，语义变化时提升。
    pub version: u32,
    /// 展示名。
    pub display_name: &'static str,
    /// 支持的操作系统；空列表意味着该适配器永远不会被选中，因此不允许为空。
    pub supported_os: &'static [Os],
    /// 所需能力；设备 Profile 必须具备**全部**能力，适配器才会参与发现。
    pub required_capabilities: &'static [&'static str],
    /// 该适配器的主要文件管理模式，仅用于展示与诊断。
    pub default_mode: FileMode,
}

impl AdapterDescriptor {
    /// 该适配器是否适用于给定设备。
    ///
    /// 判据是「操作系统在支持列表内」且「所需能力全部具备」。资源级别的进一步筛选
    /// 由 [`DiscoveredResource::selector`] 完成。
    pub fn applies_to(&self, profile: &DeviceProfile) -> bool {
        self.supported_os.contains(&profile.os)
            && self
                .required_capabilities
                .iter()
                .all(|capability| profile.has_capability(capability))
    }
}

/// 适配器可见的**全部**上下文。
///
/// 这个结构体的字段集合本身就是一条安全约束：它**没有** Backend、没有 Journal、
/// 没有文件系统句柄、没有绝对路径。适配器因此在类型层面就不可能读写授权根之外的
/// 任何东西——它连表达一个绝对路径的手段都没有。
///
/// 新增字段前请先确认它不会把上述能力带进来。
#[derive(Debug, Clone, Copy)]
pub struct AdapterContext<'a> {
    /// 本设备 Profile。
    pub profile: &'a DeviceProfile,
    /// 授权根别名 -> 该根下的相对前缀。
    ///
    /// 前缀由宿主提供（例如 `home` -> `""`、`system` -> `"etc"`），适配器只做拼接，
    /// **不解析绝对路径**。
    pub roots: &'a BTreeMap<String, String>,
    /// 用户主目录在 [`ROOT_HOME`] 根下的相对前缀。
    ///
    /// 这是 `roots["home"]` 的便捷回退：绝大多数适配器只关心主目录，无需查表。
    pub home_relative: &'a str,
}

impl<'a> AdapterContext<'a> {
    /// 构造上下文。
    pub fn new(
        profile: &'a DeviceProfile,
        roots: &'a BTreeMap<String, String>,
        home_relative: &'a str,
    ) -> Self {
        AdapterContext {
            profile,
            roots,
            home_relative,
        }
    }

    /// 取某个授权根的相对前缀。
    ///
    /// [`ROOT_HOME`] 在 `roots` 中缺失时退回 [`AdapterContext::home_relative`]；
    /// 其他根缺失时返回 `None`，调用方应当跳过对应资源而不是猜测路径。
    pub fn prefix(&self, root: &str) -> Option<&str> {
        match self.roots.get(root) {
            Some(prefix) => Some(prefix.as_str()),
            None if root == ROOT_HOME => Some(self.home_relative),
            None => None,
        }
    }
}

// ---------------------------------------------------------------------------
// 发现结果
// ---------------------------------------------------------------------------

/// 一条被发现的资源。
///
/// 它描述「这台设备上应该存在什么」，但**不包含任何观察结果**：文件是否存在、是否
/// 可读由宿主读取后填入 [`envsync_domain::resource::ObservedState`]。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredResource {
    /// 资源标识。
    pub id: ResourceId,
    /// 授权根别名。
    pub root: String,
    /// 相对该根的目标路径，以 `/` 分隔且已通过
    /// [`envsync_platform::RelativeTarget`] 校验。
    pub target: String,
    /// 文件管理模式。
    pub mode: FileMode,
    /// 期望处置。
    ///
    /// 内建适配器只会产出 [`DesiredDisposition::Managed`] 或
    /// [`DesiredDisposition::Unmanaged`]；**永远不会**产出
    /// [`DesiredDisposition::EnsureAbsent`]——删除意图必须由用户显式表达。
    pub disposition: DesiredDisposition,
    /// 写入策略。
    pub policy: ResourcePolicy,
    /// Managed Block 使用的注释前缀。
    pub comment_prefix: String,
    /// 资源级选择器；`None` 表示无附加条件。
    pub selector: Option<Selector>,
}

/// [`Adapter::render`] 的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderedFile {
    /// 需要写入的**完整文件内容**。
    Write(Vec<u8>),
    /// 目标已符合期望，无需写入。
    Unchanged,
}

impl RenderedFile {
    /// 是否需要写入。
    pub fn is_write(&self) -> bool {
        matches!(self, RenderedFile::Write(_))
    }

    /// 取出待写入字节；[`RenderedFile::Unchanged`] 时返回 `None`。
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            RenderedFile::Write(bytes) => Some(bytes),
            RenderedFile::Unchanged => None,
        }
    }
}

// ---------------------------------------------------------------------------
// sealed trait
// ---------------------------------------------------------------------------

/// 封印模块：[`Adapter`] 的超 trait 定义在这里，因此外部 crate 无法实现 [`Adapter`]。
///
/// 详见 crate 级文档中「为什么 [`Adapter`] 是 sealed 的」一节。
pub(crate) mod sealed {
    /// 封印标记。只有 `envsync-adapters` 内部的类型会实现它。
    pub trait Sealed {}
}

/// 内建适配器契约。
///
/// **本 trait 是 sealed 的**，外部 crate 无法实现；M4 的插件 SDK 会通过独立的进程
/// 隔离通道扩展 EnvSync，而不是放开这个 trait。
///
/// 全部方法必须是纯函数且**确定性**：对同一输入连续调用两次必须返回逐字节相同的
/// 结果。计划阶段（预演）与应用阶段会各调用一次 [`Adapter::render`]，两次结果不同
/// 就意味着预演结果不可信。
pub trait Adapter: sealed::Sealed + Send + Sync {
    /// 适配器自述。
    fn descriptor(&self) -> &'static AdapterDescriptor;

    /// 发现本设备上该适配器应该管理哪些资源。
    ///
    /// 这是**纯逻辑**：只根据 [`AdapterContext`] 计算路径，不读文件系统，因此在
    /// 一台设备上可以安全地为另一台设备的 Profile 做预演。
    fn discover(&self, ctx: &AdapterContext<'_>) -> Result<Vec<DiscoveredResource>, AdapterError>;

    /// 从原始文件内容中提取受管内容（capture）。
    ///
    /// 返回 `Ok(None)` 表示「文件存在，但其中没有属于 EnvSync 的内容」（例如
    /// Managed Block 尚未注入），这与「文件不存在」是不同的信号，调用方不得把它
    /// 当作删除意图。
    fn capture(&self, resource: &ResourceId, raw: &[u8]) -> Result<Option<Vec<u8>>, AdapterError>;

    /// 把受管内容渲染成完整文件内容（apply）。
    ///
    /// `existing` 为 `None` 表示目标文件不存在。返回
    /// [`RenderedFile::Unchanged`] 当且仅当渲染结果与 `existing` 逐字节相同，
    /// 因此本方法天然幂等。
    fn render(
        &self,
        resource: &ResourceId,
        existing: Option<&[u8]>,
        desired: &[u8],
    ) -> Result<RenderedFile, AdapterError>;

    /// 校验目标文件是否符合期望。
    ///
    /// 语义与 [`Adapter::render`] 严格一致：`verify` 通过当且仅当以 `actual` 为
    /// 现状再渲染一次会得到 [`RenderedFile::Unchanged`]。Managed Block 因此只校验
    /// 块内内容，块外的用户内容不参与比较。
    fn verify(
        &self,
        resource: &ResourceId,
        actual: &[u8],
        desired: &[u8],
    ) -> Result<(), AdapterError>;
}

// ---------------------------------------------------------------------------
// 注册表
// ---------------------------------------------------------------------------

/// 适配器注册表。
///
/// 按稳定 ID 索引，**拒绝重复 ID**：两个适配器声称管理同一批资源会让「谁的渲染结果
/// 生效」变成不确定行为。
#[derive(Default)]
pub struct AdapterRegistry {
    adapters: BTreeMap<&'static str, Box<dyn Adapter>>,
}

impl std::fmt::Debug for AdapterRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterRegistry")
            .field("ids", &self.ids())
            .finish()
    }
}

impl AdapterRegistry {
    /// 空注册表。
    pub fn new() -> Self {
        AdapterRegistry::default()
    }

    /// 装载全部内建适配器。
    ///
    /// 内建 ID 在编译期互不相同，因此本方法不会失败。
    pub fn builtin() -> Self {
        let mut registry = AdapterRegistry::new();
        let builtins: Vec<Box<dyn Adapter>> = vec![
            Box::new(shell::bash_adapter()),
            Box::new(shell::zsh_adapter()),
            Box::new(shell::powershell_adapter()),
            Box::new(wezterm::wezterm_adapter()),
            Box::new(git_config::git_adapter()),
        ];
        for adapter in builtins {
            registry
                .register(adapter)
                .expect("内建适配器 ID 在编译期唯一");
        }
        registry
    }

    /// 注册一个适配器；ID 重复时返回 [`AdapterError::DuplicateAdapterId`]。
    pub fn register(&mut self, adapter: Box<dyn Adapter>) -> Result<(), AdapterError> {
        let id = adapter.descriptor().id;
        if self.adapters.contains_key(id) {
            return Err(AdapterError::DuplicateAdapterId(id));
        }
        self.adapters.insert(id, adapter);
        Ok(())
    }

    /// 按 ID 查找。
    pub fn get(&self, id: &str) -> Option<&dyn Adapter> {
        self.adapters.get(id).map(AsRef::as_ref)
    }

    /// 全部已注册 ID，按字典序排列（`BTreeMap` 保证顺序稳定）。
    pub fn ids(&self) -> Vec<&'static str> {
        self.adapters.keys().copied().collect()
    }

    /// 已注册适配器的迭代视图，顺序与 [`AdapterRegistry::ids`] 一致。
    pub fn adapters(&self) -> impl Iterator<Item = &dyn Adapter> {
        self.adapters.values().map(AsRef::as_ref)
    }

    /// 在给定设备上发现全部资源，结果按资源标识排序。
    ///
    /// 过滤分三层：适配器的 [`AdapterDescriptor::applies_to`]、资源的
    /// [`DiscoveredResource::selector`]、以及适配器自身在 [`Adapter::discover`] 里
    /// 做的判断（例如缺少授权根时跳过）。
    ///
    /// 单个适配器出错**不会**中断整体发现：错误被记录到 `tracing` 后跳过该适配器，
    /// 否则一个适配器的边角问题会让整台设备无法同步。
    pub fn discover_all(&self, ctx: &AdapterContext<'_>) -> Vec<DiscoveredResource> {
        let mut out = Vec::new();
        for adapter in self.adapters.values() {
            let descriptor = adapter.descriptor();
            if !descriptor.applies_to(ctx.profile) {
                continue;
            }
            match adapter.discover(ctx) {
                Ok(resources) => out.extend(
                    resources
                        .into_iter()
                        .filter(|resource| selector_matches(resource.selector.as_ref(), ctx)),
                ),
                Err(error) => {
                    tracing::warn!(
                        adapter = descriptor.id,
                        code = error.code(),
                        "适配器发现失败，已跳过"
                    );
                }
            }
        }
        out.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        out
    }
}

/// 求值资源级选择器。
///
/// 选择器来自内建适配器（可信），但仍然先 `validate` 再 `matches`：这是
/// [`Selector`] 的使用契约，校验失败时保守地判定为「不匹配」。
fn selector_matches(selector: Option<&Selector>, ctx: &AdapterContext<'_>) -> bool {
    match selector {
        None => true,
        Some(selector) => selector.validate().is_ok() && selector.matches(ctx.profile),
    }
}
