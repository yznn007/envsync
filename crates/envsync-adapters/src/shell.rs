//! Shell 启动文件适配器：Bash、Zsh 与 PowerShell。
//!
//! 三个适配器都使用 [`FileMode::ManagedBlock`]：启动文件几乎总是用户自己也在编辑的
//! 文件，整份接管等于随时准备丢掉用户的手写配置。Managed Block 只在 marker 之间写入，
//! 块外内容逐字保留。
//!
//! # 资源一览
//!
//! | 适配器 | 资源 | 目标（相对主目录） |
//! |---|---|---|
//! | `builtin.shell.bash` | `shell/bash/bashrc` | `.bashrc` |
//! | `builtin.shell.bash` | `shell/bash/bash_profile` | `.bash_profile` |
//! | `builtin.shell.zsh` | `shell/zsh/zshrc` | `.zshrc` |
//! | `builtin.shell.zsh` | `shell/zsh/zshenv` | `.zshenv` |
//! | `builtin.shell.powershell` | `shell/powershell/profile-windows` | `Documents/PowerShell/Microsoft.PowerShell_profile.ps1` |
//! | `builtin.shell.powershell` | `shell/powershell/profile-xdg` | `.config/powershell/Microsoft.PowerShell_profile.ps1` |
//!
//! # 平台与能力
//!
//! Bash 与 Zsh 只在 macOS 与 Linux 上启用：Windows 上虽然可能装有 Git Bash 或 WSL，
//! 但它们的主目录不是本机主目录，路径推断会出错，宁可不产出资源也不要写错位置。
//!
//! PowerShell 适配器要求设备具备 `pwsh` 能力（见
//! [`AdapterDescriptor::required_capabilities`]），并按操作系统在两条 profile 路径中
//! 二选一：Windows 用 `Documents/PowerShell/...`，跨平台 pwsh 用
//! `.config/powershell/...`。两条路径各自带 selector，因此同一台设备上只会命中一条。

use envsync_domain::profile::{Os, Predicate, Selector};
use envsync_domain::resource::FileMode;

use crate::file::{FileAdapter, FileSpec};
use crate::{AdapterDescriptor, ROOT_HOME};

/// Bash 适配器描述符。
pub static BASH_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    id: "builtin.shell.bash",
    version: 1,
    display_name: "Bash 启动文件",
    supported_os: &[Os::MacOs, Os::Linux],
    required_capabilities: &[],
    default_mode: FileMode::ManagedBlock,
};

/// Zsh 适配器描述符。
pub static ZSH_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    id: "builtin.shell.zsh",
    version: 1,
    display_name: "Zsh 启动文件",
    supported_os: &[Os::MacOs, Os::Linux],
    required_capabilities: &[],
    default_mode: FileMode::ManagedBlock,
};

/// PowerShell 适配器描述符。
///
/// `required_capabilities` 里的 `pwsh` 是硬门槛：设备没有探测到 PowerShell 时，
/// [`crate::AdapterRegistry::discover_all`] 根本不会调用该适配器。
pub static POWERSHELL_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    id: "builtin.shell.powershell",
    version: 1,
    display_name: "PowerShell Profile",
    supported_os: &[Os::MacOs, Os::Linux, Os::Windows],
    required_capabilities: &[CAPABILITY_PWSH],
    default_mode: FileMode::ManagedBlock,
};

/// PowerShell 适配器所需的能力名。
pub const CAPABILITY_PWSH: &str = "pwsh";

/// Shell 脚本的注释前缀。Bash、Zsh 与 PowerShell 都用 `#`。
pub const SHELL_COMMENT_PREFIX: &str = "# ";

/// 构造 Bash 适配器。
pub fn bash_adapter() -> FileAdapter {
    FileAdapter::new(
        &BASH_DESCRIPTOR,
        vec![
            rc_spec("shell/bash/bashrc", &[".bashrc"]),
            rc_spec("shell/bash/bash_profile", &[".bash_profile"]),
        ],
    )
}

/// 构造 Zsh 适配器。
pub fn zsh_adapter() -> FileAdapter {
    FileAdapter::new(
        &ZSH_DESCRIPTOR,
        vec![
            rc_spec("shell/zsh/zshrc", &[".zshrc"]),
            rc_spec("shell/zsh/zshenv", &[".zshenv"]),
        ],
    )
}

/// 构造 PowerShell 适配器。
///
/// 两条 profile 路径互斥：Windows 命中 `Documents/PowerShell/...`，macOS 与 Linux 上的
/// 跨平台 pwsh 命中 `.config/powershell/...`。两者都额外要求 `pwsh` 能力，因此即使
/// 调用方绕过描述符直接求值 selector，也不会在没有 PowerShell 的设备上写文件。
pub fn powershell_adapter() -> FileAdapter {
    let windows = rc_spec(
        "shell/powershell/profile-windows",
        &[
            "Documents",
            "PowerShell",
            "Microsoft.PowerShell_profile.ps1",
        ],
    )
    .with_selector(Selector::all([
        Predicate::Os(Os::Windows),
        Predicate::Capability(CAPABILITY_PWSH.to_owned()),
    ]));

    let cross_platform = rc_spec(
        "shell/powershell/profile-xdg",
        &[".config", "powershell", "Microsoft.PowerShell_profile.ps1"],
    )
    .with_selector(Selector::All(vec![
        Selector::any([Predicate::Os(Os::MacOs), Predicate::Os(Os::Linux)]),
        Selector::is(Predicate::Capability(CAPABILITY_PWSH.to_owned())),
    ]));

    FileAdapter::new(&POWERSHELL_DESCRIPTOR, vec![windows, cross_platform])
}

/// 构造一条 Managed Block 形式的启动文件资源。
///
/// 权限位固定为 `0o644`：启动文件会被 shell 读取但不应可写给同组用户；它不是秘密
/// 文件（真正的秘密应当放在独立资源里并标记 `secret`）。
fn rc_spec(id: &str, segments: &'static [&'static str]) -> FileSpec {
    FileSpec::new(id, ROOT_HOME, segments, FileMode::ManagedBlock)
        .with_comment_prefix(SHELL_COMMENT_PREFIX)
        .with_unix_mode(0o644)
}
