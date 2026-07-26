//! WezTerm Lua 配置适配器（Generated Include 模式）。
//!
//! # 为什么 Generated Include 被拆成两个资源
//!
//! 设计文档 §5 把 Generated Include 描述为「生成独立文件，再向主配置注入一条
//! include/source」。它在本质上就是**两件事**，而这两件事恰好各自对应一种已经实现
//! 且经过测试的模式：
//!
//! | 资源 | 模式 | 目标 | 作用 |
//! |---|---|---|---|
//! | `terminal/wezterm/module` | [`FileMode::FullFile`] | `.config/wezterm/envsync.lua` | EnvSync 独占的生成文件 |
//! | `terminal/wezterm/include` | [`FileMode::ManagedBlock`] | `.wezterm.lua` | 向用户主配置注入 include 语句 |
//!
//! 因此本适配器**不新增渲染模式**：`envsync-core` 的 [`mod@envsync_core::render`] 只需要
//! 继续支持 Full File 与 Managed Block 两种模式即可。
//! [`FileMode::GeneratedInclude`] 只出现在
//! [`crate::AdapterDescriptor::default_mode`] 里，作为对外的**语义标签**——它告诉用户
//! 「这个适配器采用生成+注入的组合」，而不是一种需要在渲染层特殊处理的模式。
//!
//! 这样拆分还带来两个实际好处：
//!
//! * 生成文件可以被整份覆盖与整份校验，语义最简单，出错时可以直接重写；
//! * 用户主配置只被注入一小段 marker 包裹的 include 语句，块外的手写配置逐字保留，
//!   卸载 EnvSync 时只需移除该块。
//!
//! # 注入的 include 语句
//!
//! 见 [`include_snippet`]。它把生成文件所在目录加入 Lua 的 `package.path`，再
//! `require` 生成模块，并把结果放到全局变量 `ENVSYNC` 上，供用户在块外的配置里引用。
//! 语句不含任何本机绝对路径：路径在运行期由 WezTerm 自己的 `wezterm.home_dir` 拼出。

use envsync_domain::resource::FileMode;

use crate::file::{FileAdapter, FileSpec};
use crate::{AdapterDescriptor, ROOT_HOME};
use envsync_domain::profile::Os;

/// WezTerm 适配器描述符。
///
/// `default_mode` 是 [`FileMode::GeneratedInclude`]，但具体资源使用 Full File 与
/// Managed Block 两种模式，理由见模块文档。
pub static WEZTERM_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    id: "builtin.terminal.wezterm",
    version: 1,
    display_name: "WezTerm 配置",
    supported_os: &[Os::MacOs, Os::Linux, Os::Windows],
    required_capabilities: &[],
    default_mode: FileMode::GeneratedInclude,
};

/// Lua 的注释前缀。
pub const LUA_COMMENT_PREFIX: &str = "-- ";

/// 生成文件的资源标识。
pub const MODULE_RESOURCE: &str = "terminal/wezterm/module";

/// 主配置注入块的资源标识。
pub const INCLUDE_RESOURCE: &str = "terminal/wezterm/include";

/// 生成文件相对主目录的分段。
pub const MODULE_SEGMENTS: &[&str] = &[".config", "wezterm", "envsync.lua"];

/// 主配置相对主目录的分段。
pub const INCLUDE_SEGMENTS: &[&str] = &[".wezterm.lua"];

/// 注入到 `.wezterm.lua` 受管块内的 Lua 语句。
///
/// 它做三件事：
///
/// 1. 把 `~/.config/wezterm` 加入 `package.path`，使 `require` 能找到生成模块；
/// 2. `require("envsync")` 加载生成模块；
/// 3. 把结果绑定到全局变量 `ENVSYNC`，用户可以在受管块之外自由引用。
///
/// 路径由 WezTerm 运行期的 `wezterm.home_dir` 拼出，因此这段文本里**没有**任何本机
/// 绝对路径，可以安全地同步到其他设备。
pub fn include_snippet() -> &'static str {
    concat!(
        "-- 这段内容由 EnvSync 生成，请勿手工编辑；块外的配置属于你自己。\n",
        "package.path = require(\"wezterm\").home_dir\n",
        "  .. \"/.config/wezterm/?.lua;\"\n",
        "  .. package.path\n",
        "ENVSYNC = require(\"envsync\")\n",
    )
}

/// 构造 WezTerm 适配器。
pub fn wezterm_adapter() -> FileAdapter {
    let module = FileSpec::new(
        MODULE_RESOURCE,
        ROOT_HOME,
        MODULE_SEGMENTS,
        FileMode::FullFile,
    )
    .with_comment_prefix(LUA_COMMENT_PREFIX)
    .with_unix_mode(0o644);
    let include = FileSpec::new(
        INCLUDE_RESOURCE,
        ROOT_HOME,
        INCLUDE_SEGMENTS,
        FileMode::ManagedBlock,
    )
    .with_comment_prefix(LUA_COMMENT_PREFIX)
    .with_unix_mode(0o644);
    FileAdapter::new(&WEZTERM_DESCRIPTOR, vec![module, include])
}
