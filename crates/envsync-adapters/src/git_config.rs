//! Git 配置适配器。
//!
//! # 用户级配置：结构化合并
//!
//! `~/.gitconfig` 使用 [`FileMode::StructuredMerge`] 加
//! [`StructuredFormat::GitConfig`]。选择结构化而不是逐行文本合并，是因为 git config
//! 的键 identity 有自己的规则（节名与键名大小写不敏感、subsection 大小写敏感、同名键
//! 可以多值），按行合并会在这些地方给出语义错误的结果。
//!
//! 具体的三方合并发生在 `envsync-core` 的 [`mod@envsync_core::merge`] 里——那里才有 base。
//! 本适配器只负责：capture 时用同一个解析器校验内容确实是合法 git config，render 时把
//! 合并好的权威字节落盘。详见 [`crate::file`] 的模块文档。
//!
//! ## 为什么默认不管理 `~/.config/git/config`
//!
//! git 在 `~/.gitconfig` 存在时**不会**读取 XDG 路径下的 `~/.config/git/config`。
//! 同时把两者都设为受管，会在一台设备上产生「写了却不生效」的静默失败，还会让两份
//! 内容各自漂移。因此 XDG 变体默认不下发，只有设备 Profile 带上
//! [`TAG_XDG_GIT`] 标签时才会出现——那意味着用户明确声明了这台设备用 XDG 布局。
//!
//! # 系统级配置：只观察，绝不写入
//!
//! 系统级 git config（POSIX 上的 `/etc/gitconfig`）以
//! [`DesiredDisposition::Unmanaged`] 产出，处置**恒为** `Unmanaged`，不受任何配置影响：
//!
//! * 它在授权根 [`crate::ROOT_SYSTEM`] 下，需要提升权限才能写；
//! * 它影响机器上的所有用户，跨设备同步它等于把一台机器的策略强加给另一台；
//! * 它经常由包管理器或企业策略托管，EnvSync 覆写会与之打架。
//!
//! [`crate::file::FileAdapter`] 对 `Unmanaged` 资源有统一约束：capture 返回 `None`
//! （只记录存在性，不采集内容），render 直接返回
//! [`crate::AdapterError::ObserveOnly`]。因此「只观察」不是一句注释，而是一条在
//! 代码里强制执行的规则。宿主没有注册 [`crate::ROOT_SYSTEM`] 根时，该资源不会被发现。

use envsync_domain::profile::{Os, Predicate, Selector};
use envsync_domain::resource::{DesiredDisposition, FileMode, StructuredFormat};

use crate::file::{FileAdapter, FileSpec};
use crate::{AdapterDescriptor, ROOT_HOME, ROOT_SYSTEM};

/// Git 配置适配器描述符。
pub static GIT_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    id: "builtin.vcs.git",
    version: 1,
    display_name: "Git 配置",
    supported_os: &[Os::MacOs, Os::Linux, Os::Windows],
    required_capabilities: &[],
    default_mode: FileMode::StructuredMerge,
};

/// 用户级 Git 配置的资源标识。
pub const USER_RESOURCE: &str = "vcs/git/user";

/// XDG 布局下用户级 Git 配置的资源标识。
pub const USER_XDG_RESOURCE: &str = "vcs/git/user-xdg";

/// 系统级 Git 配置的资源标识（只观察）。
pub const SYSTEM_RESOURCE: &str = "vcs/git/system";

/// 启用 XDG 布局（`~/.config/git/config`）所需的设备标签。
pub const TAG_XDG_GIT: &str = "git-xdg";

/// Git 配置文件的注释前缀。
pub const GIT_COMMENT_PREFIX: &str = "# ";

/// 构造 Git 配置适配器。
pub fn git_adapter() -> FileAdapter {
    let user = git_spec(USER_RESOURCE, &[".gitconfig"]);
    let user_xdg = git_spec(USER_XDG_RESOURCE, &[".config", "git", "config"])
        .with_selector(Selector::all([Predicate::Tag(TAG_XDG_GIT.to_owned())]));
    // 系统级配置：根不同、处置恒为 Unmanaged。
    let system = FileSpec::new(
        SYSTEM_RESOURCE,
        ROOT_SYSTEM,
        &["gitconfig"],
        FileMode::StructuredMerge,
    )
    .with_comment_prefix(GIT_COMMENT_PREFIX)
    .with_structured_format(StructuredFormat::GitConfig)
    .with_disposition(DesiredDisposition::Unmanaged);

    FileAdapter::new(&GIT_DESCRIPTOR, vec![user, user_xdg, system])
}

/// 构造一条用户级 git config 资源。
fn git_spec(id: &str, segments: &'static [&'static str]) -> FileSpec {
    FileSpec::new(id, ROOT_HOME, segments, FileMode::StructuredMerge)
        .with_comment_prefix(GIT_COMMENT_PREFIX)
        .with_structured_format(StructuredFormat::GitConfig)
        .with_unix_mode(0o644)
}
