//! 工作区配置：schema、解析与校验。
//!
//! 配置是 EnvSync 的**唯一授权来源**：它声明了哪些目录可以被写入（授权根）、
//! 哪些文件被管理（资源）、以及本地状态放在哪里。因此这里的解析必须是
//! “严格且不惊喜”的：
//!
//! * **不静默降级。** 版本号不认识就报错，绝不按旧版语义猜测；
//! * **不接受未知字段。** 拼错的字段名如果被忽略，用户会以为策略生效了，
//!   而实际上文件正在用默认策略被改写；
//! * **不接受可疑目标。** `target` 必须通过
//!   [`envsync_platform::RelativeTarget::parse`] 的纯文本校验，绝对路径、`..`、
//!   盘符、UNC、NUL 等一律在解析期就被挡住，而不是等到写文件时才发现；
//! * **不泄露本机布局。** I/O 失败的诊断里只出现文件名，不出现绝对路径。
//!
//! ## 示例
//!
//! ```
//! use std::path::Path;
//! use envsync_core::config::WorkspaceConfig;
//!
//! let text = r#"
//! version: 1
//! workspace_id: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
//! device:
//!   name: workstation
//!   seed_hex: "1111111111111111111111111111111111111111111111111111111111111111"
//! backend:
//!   kind: local
//!   path: backend
//! roots:
//!   home: /home/example
//! resources:
//!   - id: shell/zsh/main
//!     root: home
//!     target: .zshrc
//!     mode: managed_block
//!     disposition: managed
//! "#;
//!
//! let config = WorkspaceConfig::parse_yaml(text, Path::new("/etc/envsync"))?;
//! // 相对路径统一相对配置文件所在目录解析。
//! assert_eq!(config.journal_path(), Path::new("/etc/envsync/.envsync/journal.db"));
//! assert_eq!(config.root_path("home")?, Path::new("/home/example"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use envsync_backend::git::DEFAULT_BRANCH as DEFAULT_GIT_BRANCH;
use envsync_backend::git_auth::validate_remote_url;
use envsync_backend::GitAuth;
use envsync_domain::{
    ActionTarget, Arch, DesiredDisposition, DeviceId, DeviceProfile, Digest32, FileMode,
    LineEnding, Os, ProfileError, ResourceId, ResourcePolicy, Selector, StructuredFormat,
    WorkspaceId, MAX_SELECTOR_DEPTH,
};
use envsync_platform::{PlatformError, RelativeTarget};

/// 本程序写出的配置版本。
///
/// M1 把版本提升到 2：新增 `profile`、资源级 `selector` 与 `device_overrides`，
/// 以及 Git 后端。**读取**仍然兼容版本 1（见 [`MIN_CONFIG_VERSION`]）；范围之外的
/// 版本号一律报 [`ConfigError::UnsupportedVersion`]，绝不按别的版本猜测语义。
pub const CONFIG_VERSION: u32 = 2;

/// 仍然可以被读取的最低配置版本。
///
/// 版本 1 的文档没有 M1 新增字段，解析时一律取默认值；反过来，在声明 `version: 1`
/// 的文档里写 M1 字段会被拒绝——否则用户会以为选择器生效了，而实际上它只是被当成
/// 未来版本的噪声。
pub const MIN_CONFIG_VERSION: u32 = 1;

/// 首个带有 `profile` / `selector` / `device_overrides` / Git 后端的版本。
const PROFILE_CONFIG_VERSION: u32 = 2;

/// 默认的本地状态目录名（相对配置文件所在目录）。
pub const DEFAULT_STATE_DIR: &str = ".envsync";

/// Managed Block 的默认注释前缀。
pub const DEFAULT_COMMENT_PREFIX: &str = "# ";

/// Git 后端私有 cache clone 的默认目录名（相对 `state_dir`）。
pub const DEFAULT_GIT_CACHE_DIR: &str = "git-cache";

/// 派生 `scaffold` 设备种子时使用的域分隔标签。
const DEVICE_SEED_DOMAIN: &str = "envsync:config:device-seed:v1";

/// 工作区配置。
///
/// 所有路径字段在解析完成后都是**绝对路径**：相对路径在
/// [`WorkspaceConfig::parse_yaml`] 里已经相对 `base_dir`（配置文件所在目录）
/// 解析完毕，上层不需要再关心 cwd。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceConfig {
    /// 配置版本，必须等于 [`CONFIG_VERSION`]。
    pub version: u32,
    /// 工作区标识。
    pub workspace_id: WorkspaceId,
    /// 本设备配置。
    pub device: DeviceConfig,
    /// 后端配置。
    pub backend: BackendConfig,
    /// 本地状态目录（journal / 草稿 / 备份）。默认 `<配置文件所在目录>/.envsync`。
    pub state_dir: PathBuf,
    /// 授权根：别名 -> 绝对路径。
    pub roots: BTreeMap<String, PathBuf>,
    /// 本设备的 Profile 声明（标签、能力、可选主机名）。
    ///
    /// **不包含 `os` / `arch`**：这两项由编译期 `cfg` 探测（见
    /// [`detected_os`] 与 [`detected_arch`]），不从配置读取——配置会被同步到所有
    /// 设备，允许它自报平台等于允许一台设备冒充另一台。
    pub profile: DeviceProfileConfig,
    /// 被管理的资源列表；空列表表示空工作区，是合法配置。
    pub resources: Vec<ResourceConfig>,
}

/// 本设备的 Profile 声明。
///
/// 取值都会在解析期做规范化校验（`trim` 后非空、长度与数量有上限），因此由
/// [`WorkspaceConfig::device_profile`] 构造出的 [`DeviceProfile`] 一定通过
/// [`DeviceProfile::validate`]。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceProfileConfig {
    /// 主机名覆盖；省略时 Profile 的 `hostname` 为 `None`（即不参与投影）。
    pub hostname: Option<String>,
    /// 设备标签，例如 `work`、`laptop`。
    pub tags: BTreeSet<String>,
    /// 本设备可用能力，例如 `pwsh`、`brew`。
    pub capabilities: BTreeSet<String>,
}

/// 本设备配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceConfig {
    /// 设备显示名（仅诊断用）。
    pub name: String,
    /// 设备种子的十六进制表示，用于派生 [`DeviceId`]（见 ADR-0002）。
    ///
    /// 必须是 64 个**小写**十六进制字符（32 字节）。种子是本设备的私有材料，
    /// 绝不会出现在快照、计划或任何上传到后端的对象里。
    pub seed_hex: String,
}

impl DeviceConfig {
    /// 由设备种子派生 [`DeviceId`]。
    ///
    /// 按 ADR-0002，`DeviceId` 从 M0 起就是域分隔摘要而不是 UUID：M2 起把输入从
    /// 随机种子换成公钥材料时，类型、宽度与编码都不变。
    ///
    /// 经 [`WorkspaceConfig::parse_yaml`] 得到的配置一定持有合法种子。若调用方
    /// 手工构造了非法 `seed_hex`（未经解析校验），这里退化为直接对原始文本字节
    /// 求摘要，从而保证本函数**永不 panic**。
    pub fn device_id(&self) -> DeviceId {
        match decode_seed(&self.seed_hex) {
            Some(bytes) => DeviceId::derive(&bytes),
            None => DeviceId::derive(self.seed_hex.as_bytes()),
        }
    }
}

/// 后端配置。
///
/// 用枚举而不是结构体，是为了让新增后端时，所有需要分支处理的调用点都被编译器
/// 点名，而不是被一个默认分支悄悄吞掉。
///
/// 这里**不加** `#[non_exhaustive]`：调用方用 `match` 穷举是当前最自然的写法，
/// 新增变体时让它们编译失败正是我们想要的。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendConfig {
    /// 本地目录后端（内容寻址对象库 + 引用文件）。
    Local {
        /// 后端根目录的绝对路径。
        path: PathBuf,
    },
    /// Git 后端：把内容寻址对象映射到普通 Git tree，用远端 branch head 做 CAS。
    Git {
        /// 远端 URL。已通过
        /// [`validate_remote_url`](envsync_backend::git_auth::validate_remote_url)：
        /// 不含 userinfo，也不带查询串，因此凭据不可能藏在配置里。
        remote_url: String,
        /// 受信分支名；省略时取
        /// [`DEFAULT_BRANCH`](envsync_backend::git::DEFAULT_BRANCH)。
        branch: String,
        /// 私有 cache clone 的绝对路径；省略时取 `<state_dir>/git-cache`。
        cache_dir: PathBuf,
        /// 认证方式；只能是 `ssh-agent`、`credential-helper` 或 `token-secret-ref`。
        auth: GitAuth,
    },
}

impl BackendConfig {
    /// 后端种类的稳定短名称，用于诊断与 CLI 输出。
    pub fn kind(&self) -> &'static str {
        match self {
            BackendConfig::Local { .. } => "local",
            BackendConfig::Git { .. } => "git",
        }
    }
}

/// 针对**单台设备**的资源覆盖。
///
/// 覆盖只能收窄或改写已有资源的落地方式，**不能**引入 Workspace 中不存在的资源：
/// 投影阶段先按资源标识去 Snapshot 里找条目，找不到就没有任何可覆盖的对象。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceOverride {
    /// 覆盖期望处置；省略时沿用全局取值。
    pub disposition: Option<DesiredDisposition>,
    /// 覆盖相对授权根的目标路径；省略时沿用全局取值。
    pub target: Option<String>,
}

impl ResourceOverride {
    /// 是否什么都没覆盖。
    pub fn is_empty(&self) -> bool {
        self.disposition.is_none() && self.target.is_none()
    }
}

/// 单个资源的配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceConfig {
    /// 资源标识，例如 `shell/zsh/main`。
    pub id: ResourceId,
    /// 授权根别名，必须在 [`WorkspaceConfig::roots`] 中声明。
    pub root: String,
    /// 相对授权根的目标路径，形如 `.zshrc` 或 `.config/git/config`。
    pub target: String,
    /// 文件管理模式。
    pub mode: FileMode,
    /// 期望处置。
    pub disposition: DesiredDisposition,
    /// 写入策略。
    pub policy: ResourcePolicy,
    /// Managed Block 的注释前缀，默认 [`DEFAULT_COMMENT_PREFIX`]。
    pub comment_prefix: String,
    /// 选择器：声明「哪些设备适用该资源」；`None` 表示全局资源。
    ///
    /// 解析期已通过 [`Selector::validate`]，因此可以直接求值。
    pub selector: Option<Selector>,
    /// device-id 级别的覆盖：十六进制设备标识 -> 覆盖内容。
    ///
    /// 键是 [`DeviceId`] 的十六进制文本，解析期已校验其合法性。
    pub device_overrides: BTreeMap<String, ResourceOverride>,
}

impl ResourceConfig {
    /// 查询针对某台设备的覆盖。
    pub fn override_for(&self, device: DeviceId) -> Option<&ResourceOverride> {
        self.device_overrides.get(&device.to_hex())
    }

    /// 应用某台设备的覆盖，得到该设备实际使用的资源配置。
    ///
    /// 没有覆盖时返回克隆的原配置；这让调用方可以无条件地使用返回值，而不必在
    /// 两条路径之间做分支。
    pub fn resolved_for(&self, device: DeviceId) -> ResourceConfig {
        let mut resolved = self.clone();
        if let Some(overrides) = self.override_for(device) {
            if let Some(disposition) = overrides.disposition {
                resolved.disposition = disposition;
            }
            if let Some(target) = &overrides.target {
                resolved.target = target.clone();
            }
        }
        resolved
    }
    /// 转换为领域层的动作目标。
    ///
    /// 计划里只保存“根别名 + 相对分段”，绝不保存绝对路径——绝对路径既是本机信息
    /// 泄露，也让计划无法在设备之间被审阅比较。
    ///
    /// 经解析得到的 `target` 一定通过了 [`RelativeTarget::parse`]。手工构造的非法
    /// `target` 在这里退化为朴素切分，以保证本函数**永不 panic**；真正的拒绝发生在
    /// 平台层解析路径时。
    pub fn action_target(&self) -> ActionTarget {
        let segments = match RelativeTarget::parse(&self.target) {
            Ok(target) => target.segments().to_vec(),
            Err(_) => self
                .target
                .split('/')
                .filter(|segment| !segment.is_empty())
                .map(str::to_owned)
                .collect(),
        };
        ActionTarget {
            root: self.root.clone(),
            segments,
        }
    }
}

impl WorkspaceConfig {
    /// 解析 YAML 文本。
    ///
    /// `base_dir` 是解析相对路径（`state_dir`、`backend.path`、`roots.*`）的基准，
    /// 通常是配置文件所在目录。
    pub fn parse_yaml(text: &str, base_dir: &Path) -> Result<Self, ConfigError> {
        // 先只看版本号：版本不匹配时，后续字段的语义本就未知，继续按当前 schema
        // 解析只会产生误导性的字段级错误。
        let probe: VersionProbe = serde_yaml_ng::from_str(text).map_err(ConfigError::from_yaml)?;
        if probe.version < MIN_CONFIG_VERSION || probe.version > CONFIG_VERSION {
            return Err(ConfigError::UnsupportedVersion {
                found: probe.version,
                supported: CONFIG_VERSION,
            });
        }

        let raw: RawConfig = serde_yaml_ng::from_str(text).map_err(ConfigError::from_yaml)?;
        raw.into_config(base_dir)
    }

    /// 从文件读取并解析配置。
    ///
    /// `base_dir` 取配置文件所在目录；路径没有父目录时取当前目录（`.`）。
    /// 读取失败时错误里**只**出现文件名，不出现绝对路径。
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|error| ConfigError::Io {
            file: file_label(path),
            kind: error.kind(),
        })?;
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        Self::parse_yaml(&text, base_dir)
    }

    /// 按标识查找资源。
    pub fn resource(&self, id: &ResourceId) -> Option<&ResourceConfig> {
        self.resources.iter().find(|resource| &resource.id == id)
    }

    /// 查询授权根的绝对路径。
    pub fn root_path(&self, alias: &str) -> Result<&Path, ConfigError> {
        self.roots
            .get(alias)
            .map(PathBuf::as_path)
            .ok_or_else(|| ConfigError::UnknownRoot {
                alias: alias.to_owned(),
                resource: None,
            })
    }

    /// journal 数据库路径：`state_dir/journal.db`。
    pub fn journal_path(&self) -> PathBuf {
        self.state_dir.join("journal.db")
    }

    /// 草稿库目录：`state_dir/draft`。
    pub fn draft_dir(&self) -> PathBuf {
        self.state_dir.join("draft")
    }

    /// 备份根：`state_dir/backups`。
    pub fn backup_root(&self) -> PathBuf {
        self.state_dir.join("backups")
    }

    /// 冲突索引数据库路径。
    ///
    /// 刻意与草稿库**同一个文件**：[`envsync_storage::ConflictStore::resolve`] 需要在
    /// `objects` 表里确认结果 Blob 确实存在，而那张表属于草稿库。分成两个文件会让
    /// 这道检查永远失败。
    pub fn conflict_db_path(&self) -> PathBuf {
        self.draft_dir().join(envsync_storage::DATABASE_FILE_NAME)
    }

    /// 由配置构造本设备的 [`DeviceProfile`]。
    ///
    /// `os` / `arch` 来自编译期 `cfg`，`hostname` / `tags` / `capabilities` 来自
    /// `profile` 段，`device` 取由种子派生的 [`DeviceId`]。
    pub fn device_profile(&self) -> DeviceProfile {
        let mut profile =
            DeviceProfile::new(detected_os(), detected_arch()).with_device(self.device.device_id());
        if let Some(hostname) = &self.profile.hostname {
            profile = profile.with_hostname(hostname);
        }
        for tag in &self.profile.tags {
            profile = profile.with_tag(tag);
        }
        for capability in &self.profile.capabilities {
            profile = profile.with_capability(capability);
        }
        profile
    }

    /// 生成「已经套用本设备覆盖」的配置副本。
    ///
    /// 计划阶段使用它而不是原始配置：device-id 覆盖里的 `target` 只影响本机落地
    /// 位置，绝不能改变共享 Snapshot 的内容。
    pub fn for_device(&self, device: DeviceId) -> WorkspaceConfig {
        let mut resolved = self.clone();
        resolved.resources = self
            .resources
            .iter()
            .map(|resource| resource.resolved_for(device))
            .collect();
        resolved
    }

    /// 生成一份最小可用的初始配置（`envsync init` 用）。
    ///
    /// 生成结果满足全部校验规则：声明了一个名为 `home` 的授权根（取 `HOME` /
    /// `USERPROFILE`，取不到时退回 `base_dir`），资源列表为空——空工作区是合法的，
    /// 用户随后再往里添加资源。
    ///
    /// 设备种子由“工作区标识 + 设备名 + 进程号 + 当前时间”经域分隔 BLAKE3 派生。
    /// 这在 M0 足够（只需要稳定唯一的本地设备标识）；M2 起种子会被真正的密钥材料
    /// 取代，见 ADR-0002。
    pub fn scaffold(
        workspace_id: WorkspaceId,
        device_name: &str,
        backend_path: &Path,
        base_dir: &Path,
    ) -> Self {
        let mut roots = BTreeMap::new();
        roots.insert("home".to_owned(), default_home_dir(base_dir));

        WorkspaceConfig {
            version: CONFIG_VERSION,
            workspace_id,
            device: DeviceConfig {
                name: device_name.to_owned(),
                seed_hex: generate_seed_hex(&workspace_id, device_name),
            },
            backend: BackendConfig::Local {
                path: resolve_path(base_dir, backend_path),
            },
            state_dir: base_dir.join(DEFAULT_STATE_DIR),
            roots,
            profile: DeviceProfileConfig::default(),
            resources: Vec::new(),
        }
    }

    /// 序列化回 YAML（`envsync init` 写文件用）。
    ///
    /// 输出里的路径都是解析后的绝对路径，因此再次 [`WorkspaceConfig::parse_yaml`]
    /// 时与 `base_dir` 无关，往返结果稳定。
    pub fn to_yaml(&self) -> Result<String, ConfigError> {
        let raw = RawConfig::from_config(self)?;
        serde_yaml_ng::to_string(&raw).map_err(|error| ConfigError::Serialize {
            message: error.to_string(),
        })
    }
}

/// 配置解析与校验错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// 配置版本不受支持。绝不静默按其他版本解释。
    #[error("不支持的配置版本 {found}，本程序只支持 {supported}")]
    UnsupportedVersion {
        /// 配置里写的版本号。
        found: u32,
        /// 本程序支持的版本号。
        supported: u32,
    },

    /// 出现未知字段。拼错的字段名必须报错，否则用户会以为策略生效了。
    #[error("配置包含未知字段 `{field}`")]
    UnknownField {
        /// 未知字段名。
        field: String,
    },

    /// 同一个 `ResourceId` 出现多次。
    #[error("资源标识 `{id}` 重复声明")]
    DuplicateResource {
        /// 重复的资源标识。
        id: String,
    },

    /// 引用了未声明的授权根别名。
    #[error("未声明的授权根别名 `{alias}`{}", format_resource_hint(.resource.as_deref()))]
    UnknownRoot {
        /// 被引用的别名。
        alias: String,
        /// 引用它的资源标识；直接查询根时为 `None`。
        resource: Option<String>,
    },

    /// `target` 未通过相对目标的文本校验。
    #[error("资源 `{resource}` 的 target 非法：{source}")]
    InvalidTarget {
        /// 出问题的资源标识。
        resource: String,
        /// 平台层给出的具体原因。
        #[source]
        source: PlatformError,
    },

    /// 授权根解析后仍不是绝对路径。
    #[error("授权根 `{alias}` 必须是绝对路径（相对路径需要绝对的配置目录作基准）")]
    RootNotAbsolute {
        /// 出问题的别名。
        alias: String,
    },

    /// 没有声明任何授权根。
    #[error("配置必须至少声明一个授权根")]
    NoRoots,

    /// `structured_merge` 缺少 `policy.structured_format`。
    #[error("资源 `{resource}` 使用 structured_merge 但未声明 policy.structured_format")]
    StructuredWithoutFormat {
        /// 出问题的资源标识。
        resource: String,
    },

    /// 使用了 M0 尚未实现的文件模式。
    #[error("资源 `{resource}` 使用的模式 `{mode}` 在 M0 尚未支持")]
    ModeNotSupportedInM0 {
        /// 出问题的资源标识。
        resource: String,
        /// 被拒绝的模式名。
        mode: &'static str,
    },

    /// 设备种子格式非法。
    #[error("device.seed_hex 必须是 64 个小写十六进制字符：{reason}")]
    InvalidDeviceSeed {
        /// 具体原因。
        reason: &'static str,
    },

    /// `workspace_id` 不是合法 UUID。
    #[error("workspace_id 不是合法的 UUID")]
    InvalidWorkspaceId,

    /// 资源标识不合法。
    #[error("资源标识 `{value}` 非法：{source}")]
    InvalidResourceId {
        /// 原始文本。
        value: String,
        /// 领域层给出的具体原因。
        #[source]
        source: envsync_domain::IdError,
    },

    /// `policy.unix_mode` 不是合法的权限位。
    #[error("资源 `{resource}` 的 policy.unix_mode 非法：{reason}")]
    InvalidUnixMode {
        /// 出问题的资源标识。
        resource: String,
        /// 具体原因。
        reason: String,
    },

    /// 未知的后端种类。
    #[error("未知的后端种类 `{kind}`")]
    UnknownBackendKind {
        /// 配置里写的种类。
        kind: String,
    },

    /// 后端配置的字段与所声明的种类不匹配。
    #[error("`{kind}` 后端的配置非法：{reason}")]
    InvalidBackend {
        /// 后端种类。
        kind: &'static str,
        /// 具体原因；只描述结构，绝不回显 URL 或凭据。
        reason: String,
    },

    /// 在旧版本文档里使用了更高版本才引入的字段。
    #[error("字段 `{field}` 需要配置版本 {since}，当前文档声明的是版本 {found}")]
    FieldRequiresVersion {
        /// 越界使用的字段。
        field: &'static str,
        /// 引入该字段的版本。
        since: u32,
        /// 文档自己声明的版本。
        found: u32,
    },

    /// `profile` 段的取值不规范。
    #[error("profile.{field} 非法：{source}")]
    InvalidProfileValue {
        /// 出错的字段名。
        field: &'static str,
        /// 领域层给出的具体原因。
        #[source]
        source: ProfileError,
    },

    /// 资源的选择器写法不对（不是单键映射、键未知、取值类型不对或嵌套过深）。
    #[error("资源 `{resource}` 的 selector 写法不对：{reason}")]
    InvalidSelectorShape {
        /// 出问题的资源标识。
        resource: String,
        /// 具体原因。
        reason: String,
    },

    /// 资源的选择器不合法（深度、节点数或取值不规范）。
    #[error("资源 `{resource}` 的 selector 非法：{source}")]
    InvalidSelector {
        /// 出问题的资源标识。
        resource: String,
        /// 领域层给出的具体原因。
        #[source]
        source: ProfileError,
    },

    /// `device_overrides` 的键不是合法的设备标识。
    #[error("资源 `{resource}` 的 device_overrides 键 `{key}` 不是合法的设备标识")]
    InvalidDeviceOverrideKey {
        /// 出问题的资源标识。
        resource: String,
        /// 非法的键。
        key: String,
    },

    /// `device_overrides` 中出现了什么都不覆盖的空条目。
    #[error("资源 `{resource}` 的 device_overrides 条目 `{key}` 没有覆盖任何字段")]
    EmptyDeviceOverride {
        /// 出问题的资源标识。
        resource: String,
        /// 空条目的键。
        key: String,
    },

    /// YAML 语法或类型错误。
    #[error("配置 YAML 解析失败（第 {line} 行，第 {column} 列）：{message}")]
    Yaml {
        /// 行号（1 起）；位置不可用时为 0。
        line: usize,
        /// 列号（1 起）；位置不可用时为 0。
        column: usize,
        /// 原始错误信息。
        message: String,
    },

    /// 读取配置文件失败。诊断里只保留文件名与错误类别，不含绝对路径。
    #[error("读取配置文件 `{file}` 失败：{}", io_kind_label(.kind))]
    Io {
        /// 配置文件名（不含目录）。
        file: String,
        /// I/O 错误类别。
        kind: std::io::ErrorKind,
    },

    /// 路径不是合法 UTF-8，无法写进 YAML。
    #[error("路径包含非 UTF-8 字节，无法序列化为配置（{context}）")]
    NonUtf8Path {
        /// 出问题的字段位置描述。
        context: String,
    },

    /// 序列化回 YAML 失败。
    #[error("配置序列化失败：{message}")]
    Serialize {
        /// 原始错误信息。
        message: String,
    },
}

impl ConfigError {
    /// 稳定的机器可读错误码，用于 CLI 的 JSON 诊断输出。
    pub fn code(&self) -> &'static str {
        match self {
            ConfigError::UnsupportedVersion { .. } => "config.unsupported_version",
            ConfigError::UnknownField { .. } => "config.unknown_field",
            ConfigError::DuplicateResource { .. } => "config.duplicate_resource",
            ConfigError::UnknownRoot { .. } => "config.unknown_root",
            ConfigError::InvalidTarget { .. } => "config.invalid_target",
            ConfigError::RootNotAbsolute { .. } => "config.root_not_absolute",
            ConfigError::NoRoots => "config.no_roots",
            ConfigError::StructuredWithoutFormat { .. } => "config.structured_without_format",
            ConfigError::ModeNotSupportedInM0 { .. } => "config.mode_not_supported",
            ConfigError::InvalidDeviceSeed { .. } => "config.invalid_device_seed",
            ConfigError::InvalidWorkspaceId => "config.invalid_workspace_id",
            ConfigError::InvalidResourceId { .. } => "config.invalid_resource_id",
            ConfigError::InvalidUnixMode { .. } => "config.invalid_unix_mode",
            ConfigError::UnknownBackendKind { .. } => "config.unknown_backend_kind",
            ConfigError::InvalidBackend { .. } => "config.invalid_backend",
            ConfigError::FieldRequiresVersion { .. } => "config.field_requires_version",
            ConfigError::InvalidProfileValue { .. } => "config.invalid_profile_value",
            ConfigError::InvalidSelector { .. } => "config.invalid_selector",
            ConfigError::InvalidSelectorShape { .. } => "config.invalid_selector",
            ConfigError::InvalidDeviceOverrideKey { .. } => "config.invalid_device_override_key",
            ConfigError::EmptyDeviceOverride { .. } => "config.empty_device_override",
            ConfigError::Yaml { .. } => "config.yaml",
            ConfigError::Io { .. } => "config.io",
            ConfigError::NonUtf8Path { .. } => "config.non_utf8_path",
            ConfigError::Serialize { .. } => "config.serialize",
        }
    }

    /// 把 serde 错误转成配置错误。
    ///
    /// `deny_unknown_fields` 触发的错误被单独识别出来，因为“字段拼错”是最常见的
    /// 用户错误，值得一个专门的错误码而不是笼统的“YAML 解析失败”。
    fn from_yaml(error: serde_yaml_ng::Error) -> Self {
        let message = error.to_string();
        if let Some(field) = unknown_field_name(&message) {
            return ConfigError::UnknownField { field };
        }
        let (line, column) = error
            .location()
            .map(|location| (location.line(), location.column()))
            .unwrap_or((0, 0));
        ConfigError::Yaml {
            line,
            column,
            message,
        }
    }
}

/// 从 serde 的 `unknown field \`x\`, expected ...` 里取出字段名。
fn unknown_field_name(message: &str) -> Option<String> {
    let rest = message.split_once("unknown field `")?.1;
    let (field, _) = rest.split_once('`')?;
    Some(field.to_owned())
}

/// 为 [`ConfigError::UnknownRoot`] 拼接可选的资源上下文。
fn format_resource_hint(resource: Option<&str>) -> String {
    match resource {
        Some(id) => format!("（资源 `{id}`）"),
        None => String::new(),
    }
}

/// I/O 错误类别的中文标签。避免直接输出可能含路径的 `io::Error` Display。
fn io_kind_label(kind: &std::io::ErrorKind) -> &'static str {
    match *kind {
        std::io::ErrorKind::NotFound => "文件不存在",
        std::io::ErrorKind::PermissionDenied => "权限不足",
        std::io::ErrorKind::InvalidData => "内容不是合法 UTF-8",
        _ => "I/O 错误",
    }
}

/// 只取文件名作为诊断标签，绝不泄露所在目录。
fn file_label(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "配置文件".to_owned())
}

/// 相对 `base_dir` 解析路径；已是绝对路径时原样返回。
fn resolve_path(base_dir: &Path, raw: &Path) -> PathBuf {
    if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        base_dir.join(raw)
    }
}

/// 解析 64 个小写十六进制字符为 32 字节。
fn decode_seed(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        if chunk.iter().any(|byte| byte.is_ascii_uppercase()) {
            return None;
        }
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        bytes[index] = ((hi << 4) | lo) as u8;
    }
    Some(bytes)
}

/// 校验设备种子文本。
fn validate_seed(hex: &str) -> Result<(), ConfigError> {
    if hex.len() != 64 {
        return Err(ConfigError::InvalidDeviceSeed {
            reason: "长度不是 64 个字符",
        });
    }
    if hex.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(ConfigError::InvalidDeviceSeed {
            reason: "包含大写字母（同一种子只允许一种文本表示）",
        });
    }
    if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ConfigError::InvalidDeviceSeed {
            reason: "包含非十六进制字符",
        });
    }
    Ok(())
}

/// 为 `scaffold` 生成设备种子。
fn generate_seed_hex(workspace_id: &WorkspaceId, device_name: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    let mut payload = Vec::new();
    payload.extend_from_slice(workspace_id.as_uuid().as_bytes());
    payload.extend_from_slice(device_name.as_bytes());
    payload.extend_from_slice(&std::process::id().to_be_bytes());
    payload.extend_from_slice(&nanos.to_be_bytes());

    Digest32::domain_hash(DEVICE_SEED_DOMAIN, &payload).to_hex()
}

/// `scaffold` 用的默认 home 目录：取 `HOME` / `USERPROFILE`，取不到或不是绝对路径
/// 时退回 `base_dir`，保证生成的配置一定能通过校验。
fn default_home_dir(base_dir: &Path) -> PathBuf {
    for key in ["HOME", "USERPROFILE"] {
        if let Some(value) = std::env::var_os(key) {
            let path = PathBuf::from(value);
            if path.is_absolute() {
                return path;
            }
        }
    }
    base_dir.to_path_buf()
}

// ---------------------------------------------------------------------------
// 选择器的 YAML 写法
//
// 每个节点都是**单键映射**，键决定节点种类：
//
// ```yaml
// selector:
//   all:
//     - os: windows
//     - capability: pwsh
//     - not:
//         tag: server
// ```
//
// 组合子：`all`（序列）、`any`（序列）、`not`（单个节点）；
// 谓词：`os`、`arch`、`hostname`、`tag`、`capability`、`device`（都取字符串）。
// ---------------------------------------------------------------------------

/// 把 YAML 节点转成领域层选择器，并在**转换过程中**限制深度。
///
/// 深度检查必须发生在这里而不是留给之后的 `validate`：递归转换本身就会先把栈耗尽。
fn selector_from_yaml(
    value: &serde_yaml_ng::Value,
    resource: &str,
    depth: usize,
) -> Result<Selector, ConfigError> {
    if depth > MAX_SELECTOR_DEPTH {
        return Err(selector_shape(
            resource,
            format!("嵌套深度超过上限 {MAX_SELECTOR_DEPTH}"),
        ));
    }
    let mapping = value
        .as_mapping()
        .ok_or_else(|| selector_shape(resource, "选择器节点必须是映射".to_owned()))?;
    if mapping.len() != 1 {
        return Err(selector_shape(
            resource,
            format!("选择器节点必须正好有一个键，实际有 {} 个", mapping.len()),
        ));
    }
    let (key, payload) = mapping
        .iter()
        .next()
        .ok_or_else(|| selector_shape(resource, "选择器节点为空".to_owned()))?;
    let key = key
        .as_str()
        .ok_or_else(|| selector_shape(resource, "选择器的键必须是字符串".to_owned()))?;

    let children = |items: &serde_yaml_ng::Value| -> Result<Vec<Selector>, ConfigError> {
        items
            .as_sequence()
            .ok_or_else(|| selector_shape(resource, format!("`{key}` 的取值必须是序列")))?
            .iter()
            .map(|item| selector_from_yaml(item, resource, depth + 1))
            .collect()
    };

    Ok(match key {
        "all" => Selector::All(children(payload)?),
        "any" => Selector::Any(children(payload)?),
        "not" => Selector::Not(Box::new(selector_from_yaml(payload, resource, depth + 1)?)),
        _ => Selector::Is(predicate_from_yaml(key, payload, resource)?),
    })
}

/// 把单个谓词键值对转成领域层谓词。
fn predicate_from_yaml(
    key: &str,
    payload: &serde_yaml_ng::Value,
    resource: &str,
) -> Result<envsync_domain::Predicate, ConfigError> {
    use envsync_domain::Predicate;

    let text = payload
        .as_str()
        .ok_or_else(|| selector_shape(resource, format!("`{key}` 的取值必须是字符串")))?;
    let invalid = |detail: String| selector_shape(resource, detail);

    Ok(match key {
        "os" => Predicate::Os(
            Os::parse(text).ok_or_else(|| invalid(format!("未知的操作系统 `{text}`")))?,
        ),
        "arch" => Predicate::Arch(
            Arch::parse(text).ok_or_else(|| invalid(format!("未知的架构 `{text}`")))?,
        ),
        "hostname" => Predicate::hostname(text).map_err(|source| ConfigError::InvalidSelector {
            resource: resource.to_owned(),
            source,
        })?,
        "tag" => Predicate::tag(text).map_err(|source| ConfigError::InvalidSelector {
            resource: resource.to_owned(),
            source,
        })?,
        "capability" => {
            Predicate::capability(text).map_err(|source| ConfigError::InvalidSelector {
                resource: resource.to_owned(),
                source,
            })?
        }
        "device" => Predicate::Device(
            text.parse::<DeviceId>()
                .map_err(|_| invalid(format!("`{text}` 不是合法的设备标识")))?,
        ),
        other => return Err(invalid(format!("未知的选择器键 `{other}`"))),
    })
}

/// 把领域层选择器写回 YAML 的单键映射形式。
fn selector_to_yaml(selector: &Selector) -> serde_yaml_ng::Value {
    use envsync_domain::Predicate;
    use serde_yaml_ng::Value;

    let single = |key: &str, payload: Value| -> Value {
        let mut mapping = serde_yaml_ng::Mapping::new();
        mapping.insert(Value::String(key.to_owned()), payload);
        Value::Mapping(mapping)
    };

    match selector {
        Selector::All(items) => single(
            "all",
            Value::Sequence(items.iter().map(selector_to_yaml).collect()),
        ),
        Selector::Any(items) => single(
            "any",
            Value::Sequence(items.iter().map(selector_to_yaml).collect()),
        ),
        Selector::Not(inner) => single("not", selector_to_yaml(inner)),
        Selector::Is(predicate) => {
            let (key, text) = match predicate {
                Predicate::Os(os) => ("os", os.as_str().to_owned()),
                Predicate::Arch(arch) => ("arch", arch.as_str().to_owned()),
                Predicate::Hostname(value) => ("hostname", value.clone()),
                Predicate::Tag(value) => ("tag", value.clone()),
                Predicate::Capability(value) => ("capability", value.clone()),
                Predicate::Device(device) => ("device", device.to_hex()),
            };
            single(key, Value::String(text))
        }
    }
}

/// 构造「选择器写法不对」的错误。
fn selector_shape(resource: &str, reason: String) -> ConfigError {
    ConfigError::InvalidSelectorShape {
        resource: resource.to_owned(),
        reason,
    }
}

/// 本次编译目标的操作系统。
///
/// 刻意**不从配置读取**：配置会被同步到所有设备，让它自报平台等于允许一台设备
/// 冒充另一台，从而绕过按 `os` 编写的选择器。未收录的操作系统退化为
/// [`Os::Linux`]——EnvSync 只在三大平台上做过验证，退化取值让程序仍可运行，而选择
/// 器写 `os: linux` 时的行为是可预期的。
pub fn detected_os() -> Os {
    if cfg!(target_os = "macos") {
        Os::MacOs
    } else if cfg!(target_os = "windows") {
        Os::Windows
    } else {
        Os::Linux
    }
}

/// 本次编译目标的处理器架构；理由同 [`detected_os`]。
pub fn detected_arch() -> Arch {
    if cfg!(target_arch = "aarch64") {
        Arch::Aarch64
    } else {
        Arch::X86_64
    }
}

/// 路径转 UTF-8 字符串，用于序列化。
fn path_to_string(path: &Path, context: &str) -> Result<String, ConfigError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| ConfigError::NonUtf8Path {
            context: context.to_owned(),
        })
}

// ---------------------------------------------------------------------------
// 线格式（wire format）：只在本模块内部可见。
//
// 把线格式与领域模型分开，可以让 YAML 的“可省略/多写法”只影响这里，而
// [`WorkspaceConfig`] 始终是解析完毕、字段齐全的强类型。
// ---------------------------------------------------------------------------

/// 只探测版本号的第一遍解析。这里**不能**开 `deny_unknown_fields`。
#[derive(Deserialize)]
struct VersionProbe {
    version: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    version: u32,
    workspace_id: String,
    device: RawDevice,
    backend: RawBackend,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state_dir: Option<String>,
    #[serde(default)]
    roots: BTreeMap<String, String>,
    /// 版本 2 起可用；版本 1 的文档里出现它会被拒绝。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile: Option<RawProfile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    resources: Vec<RawResource>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDevice {
    name: String,
    seed_hex: String,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    tags: BTreeSet<String>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    capabilities: BTreeSet<String>,
}

/// 后端线格式。
///
/// 所有子字段都是可选的，由 `kind` 决定哪些必须出现、哪些必须缺席；缺少或多写都
/// 报错，绝不「按种类忽略无关字段」——那会让写错种类的配置静默地用上默认后端。
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBackend {
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remote_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cache_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth: Option<RawGitAuth>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGitAuth {
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResource {
    id: String,
    root: String,
    target: String,
    mode: FileMode,
    disposition: DesiredDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    comment_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy: Option<RawPolicy>,
    /// 版本 2 起可用。
    ///
    /// 这里刻意用 [`serde_yaml_ng::Value`] 而不是直接 `Selector`：领域层的
    /// `Selector` 是外部标记（externally tagged）枚举，YAML 会把它写成 `!all` 这样的
    /// **标签**，对手写配置极不友好。配置层因此定义自己的「单键映射」写法，并在
    /// [`selector_from_yaml`] 里显式转换与限深。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    selector: Option<serde_yaml_ng::Value>,
    /// 版本 2 起可用。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    device_overrides: BTreeMap<String, RawResourceOverride>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawResourceOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    disposition: Option<DesiredDisposition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    max_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    line_ending: Option<LineEnding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unix_mode: Option<RawUnixMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    structured_format: Option<StructuredFormat>,
}

/// `unix_mode` 的两种写法：字符串八进制（`"0644"`、`"0o644"`）或整数（`420`）。
///
/// YAML 里裸写的 `0644` 会被解析成整数 644（十进制），那不是用户想要的权限位，
/// 所以文档统一建议加引号；两种写法在这里都能被正确接受。
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum RawUnixMode {
    /// 十进制整数写法。
    Int(i64),
    /// 八进制字符串写法。
    Text(String),
}

impl RawUnixMode {
    /// 转换为权限位。
    fn to_mode(&self, resource: &str) -> Result<u32, ConfigError> {
        let value = match self {
            RawUnixMode::Int(raw) => {
                u32::try_from(*raw).map_err(|_| ConfigError::InvalidUnixMode {
                    resource: resource.to_owned(),
                    reason: format!("{raw} 不是非负整数"),
                })?
            }
            RawUnixMode::Text(text) => {
                let digits = text
                    .strip_prefix("0o")
                    .or_else(|| text.strip_prefix("0O"))
                    .unwrap_or(text);
                u32::from_str_radix(digits, 8).map_err(|_| ConfigError::InvalidUnixMode {
                    resource: resource.to_owned(),
                    reason: format!("`{text}` 不是合法的八进制权限位"),
                })?
            }
        };
        if value > 0o7777 {
            return Err(ConfigError::InvalidUnixMode {
                resource: resource.to_owned(),
                reason: format!("0o{value:o} 超出权限位范围（最大 0o7777）"),
            });
        }
        Ok(value)
    }

    /// 序列化时统一写成带前导零的八进制字符串，往返解析结果不变。
    fn from_mode(mode: u32) -> Self {
        RawUnixMode::Text(format!("0{mode:o}"))
    }
}

impl RawConfig {
    /// 线格式 -> 强类型，并执行全部配置层校验。
    fn into_config(self, base_dir: &Path) -> Result<WorkspaceConfig, ConfigError> {
        let workspace_id = self
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|_| ConfigError::InvalidWorkspaceId)?;

        validate_seed(&self.device.seed_hex)?;
        self.reject_future_fields()?;

        if self.roots.is_empty() {
            return Err(ConfigError::NoRoots);
        }
        let mut roots = BTreeMap::new();
        for (alias, raw) in self.roots {
            let path = resolve_path(base_dir, Path::new(&raw));
            if !path.is_absolute() {
                return Err(ConfigError::RootNotAbsolute { alias });
            }
            roots.insert(alias, path);
        }

        let state_dir = match self.state_dir {
            Some(raw) => resolve_path(base_dir, Path::new(&raw)),
            None => base_dir.join(DEFAULT_STATE_DIR),
        };

        // 后端解析要用到 state_dir（Git cache 的默认位置），因此排在它之后。
        let backend = self.backend.into_config(base_dir, &state_dir)?;
        let profile = self.profile.unwrap_or_default().into_config()?;

        let mut seen: BTreeSet<ResourceId> = BTreeSet::new();
        let mut resources = Vec::with_capacity(self.resources.len());
        for raw in self.resources {
            let resource = raw.into_config(&roots)?;
            if !seen.insert(resource.id.clone()) {
                return Err(ConfigError::DuplicateResource {
                    id: resource.id.to_string(),
                });
            }
            resources.push(resource);
        }

        Ok(WorkspaceConfig {
            version: CONFIG_VERSION,
            workspace_id,
            device: DeviceConfig {
                name: self.device.name,
                seed_hex: self.device.seed_hex,
            },
            backend,
            state_dir,
            roots,
            profile,
            resources,
        })
    }

    /// 拒绝「旧版本文档里写了新版本字段」。
    ///
    /// 忽略它们比报错更危险：用户会以为选择器或 Git 后端已经生效，而实际上程序
    /// 正在按全局资源和本地目录后端运行。
    fn reject_future_fields(&self) -> Result<(), ConfigError> {
        if self.version >= PROFILE_CONFIG_VERSION {
            return Ok(());
        }
        let mut offender = None;
        if self.profile.is_some() {
            offender = Some("profile");
        } else if self.backend.kind == "git" {
            offender = Some("backend.kind=git");
        } else if let Some(resource) = self
            .resources
            .iter()
            .find(|resource| resource.selector.is_some())
        {
            let _ = resource;
            offender = Some("resources[].selector");
        } else if self
            .resources
            .iter()
            .any(|resource| !resource.device_overrides.is_empty())
        {
            offender = Some("resources[].device_overrides");
        }
        match offender {
            Some(field) => Err(ConfigError::FieldRequiresVersion {
                field,
                since: PROFILE_CONFIG_VERSION,
                found: self.version,
            }),
            None => Ok(()),
        }
    }

    /// 强类型 -> 线格式。
    fn from_config(config: &WorkspaceConfig) -> Result<Self, ConfigError> {
        let mut roots = BTreeMap::new();
        for (alias, path) in &config.roots {
            roots.insert(
                alias.clone(),
                path_to_string(path, &format!("roots.{alias}"))?,
            );
        }

        let mut resources = Vec::with_capacity(config.resources.len());
        for resource in &config.resources {
            resources.push(RawResource::from_config(resource));
        }

        Ok(RawConfig {
            version: config.version,
            workspace_id: config.workspace_id.to_string(),
            device: RawDevice {
                name: config.device.name.clone(),
                seed_hex: config.device.seed_hex.clone(),
            },
            backend: RawBackend::from_config(&config.backend)?,
            state_dir: Some(path_to_string(&config.state_dir, "state_dir")?),
            roots,
            profile: RawProfile::from_config(&config.profile),
            resources,
        })
    }
}

impl RawProfile {
    /// 线格式 -> 强类型，逐项做规范化校验。
    fn into_config(self) -> Result<DeviceProfileConfig, ConfigError> {
        // 借领域层的构造器做校验：它对 trim、空值、长度和数量的判断与投影时完全一致。
        let mut probe = DeviceProfile::new(detected_os(), detected_arch());
        if let Some(hostname) = &self.hostname {
            probe = probe
                .try_with_hostname(hostname.clone())
                .map_err(|source| ConfigError::InvalidProfileValue {
                    field: "hostname",
                    source,
                })?;
        }
        for tag in &self.tags {
            probe = probe.try_with_tag(tag.clone()).map_err(|source| {
                ConfigError::InvalidProfileValue {
                    field: "tags",
                    source,
                }
            })?;
        }
        for capability in &self.capabilities {
            probe = probe
                .try_with_capability(capability.clone())
                .map_err(|source| ConfigError::InvalidProfileValue {
                    field: "capabilities",
                    source,
                })?;
        }
        probe
            .validate()
            .map_err(|source| ConfigError::InvalidProfileValue {
                field: "profile",
                source,
            })?;

        Ok(DeviceProfileConfig {
            hostname: probe.hostname,
            tags: probe.tags,
            capabilities: probe.capabilities,
        })
    }

    /// 强类型 -> 线格式。
    fn from_config(profile: &DeviceProfileConfig) -> Option<Self> {
        if profile.hostname.is_none() && profile.tags.is_empty() && profile.capabilities.is_empty()
        {
            return None;
        }
        Some(RawProfile {
            hostname: profile.hostname.clone(),
            tags: profile.tags.clone(),
            capabilities: profile.capabilities.clone(),
        })
    }
}

impl RawBackend {
    /// 线格式 -> 强类型：按 `kind` 决定必须出现和必须缺席的字段。
    fn into_config(self, base_dir: &Path, state_dir: &Path) -> Result<BackendConfig, ConfigError> {
        match self.kind.as_str() {
            "local" => {
                let path = self.path.ok_or(ConfigError::InvalidBackend {
                    kind: "local",
                    reason: "缺少 `path`".to_owned(),
                })?;
                for (field, present) in [
                    ("remote_url", self.remote_url.is_some()),
                    ("branch", self.branch.is_some()),
                    ("cache_dir", self.cache_dir.is_some()),
                    ("auth", self.auth.is_some()),
                ] {
                    if present {
                        return Err(ConfigError::InvalidBackend {
                            kind: "local",
                            reason: format!("`{field}` 只属于 git 后端"),
                        });
                    }
                }
                Ok(BackendConfig::Local {
                    path: resolve_path(base_dir, Path::new(&path)),
                })
            }
            "git" => {
                if self.path.is_some() {
                    return Err(ConfigError::InvalidBackend {
                        kind: "git",
                        reason: "`path` 只属于 local 后端；请用 `remote_url`".to_owned(),
                    });
                }
                let remote_url = self.remote_url.ok_or(ConfigError::InvalidBackend {
                    kind: "git",
                    reason: "缺少 `remote_url`".to_owned(),
                })?;
                // 校验只回显静态原因，绝不把 URL 拼进错误信息——它可能带凭据。
                validate_remote_url(&remote_url).map_err(|error| ConfigError::InvalidBackend {
                    kind: "git",
                    reason: error.to_string(),
                })?;
                let auth = self.auth.ok_or(ConfigError::InvalidBackend {
                    kind: "git",
                    reason: format!("缺少 `auth`；可选值：{}", GitAuth::KINDS.join("、")),
                })?;
                let auth =
                    GitAuth::parse(&auth.kind, auth.secret_id.as_deref()).map_err(|error| {
                        ConfigError::InvalidBackend {
                            kind: "git",
                            reason: error.to_string(),
                        }
                    })?;
                Ok(BackendConfig::Git {
                    remote_url,
                    branch: self.branch.unwrap_or_else(|| DEFAULT_GIT_BRANCH.to_owned()),
                    cache_dir: match self.cache_dir {
                        Some(raw) => resolve_path(base_dir, Path::new(&raw)),
                        None => state_dir.join(DEFAULT_GIT_CACHE_DIR),
                    },
                    auth,
                })
            }
            _ => Err(ConfigError::UnknownBackendKind { kind: self.kind }),
        }
    }

    /// 强类型 -> 线格式。
    fn from_config(backend: &BackendConfig) -> Result<Self, ConfigError> {
        Ok(match backend {
            BackendConfig::Local { path } => RawBackend {
                kind: "local".to_owned(),
                path: Some(path_to_string(path, "backend.path")?),
                remote_url: None,
                branch: None,
                cache_dir: None,
                auth: None,
            },
            BackendConfig::Git {
                remote_url,
                branch,
                cache_dir,
                auth,
            } => RawBackend {
                kind: "git".to_owned(),
                path: None,
                remote_url: Some(remote_url.clone()),
                branch: Some(branch.clone()),
                cache_dir: Some(path_to_string(cache_dir, "backend.cache_dir")?),
                auth: Some(RawGitAuth {
                    kind: auth.kind().to_owned(),
                    secret_id: match auth {
                        GitAuth::TokenSecretRef { secret_id } => Some(secret_id.clone()),
                        _ => None,
                    },
                }),
            },
        })
    }
}

impl RawResource {
    /// 线格式 -> 强类型，并执行资源级校验。
    fn into_config(self, roots: &BTreeMap<String, PathBuf>) -> Result<ResourceConfig, ConfigError> {
        let id = ResourceId::parse(&self.id).map_err(|source| ConfigError::InvalidResourceId {
            value: self.id.clone(),
            source,
        })?;

        if !roots.contains_key(&self.root) {
            return Err(ConfigError::UnknownRoot {
                alias: self.root,
                resource: Some(id.to_string()),
            });
        }

        // 直接复用平台层的纯文本校验：配置里能写的目标，必须正好是平台层敢写的目标。
        RelativeTarget::parse(&self.target).map_err(|source| ConfigError::InvalidTarget {
            resource: id.to_string(),
            source,
        })?;

        let raw_policy = self.policy.unwrap_or_default();
        let mut policy = ResourcePolicy::default();
        if let Some(max_bytes) = raw_policy.max_bytes {
            policy.max_bytes = max_bytes;
        }
        if let Some(line_ending) = raw_policy.line_ending {
            policy.line_ending = line_ending;
        }
        if let Some(raw_mode) = &raw_policy.unix_mode {
            policy.unix_mode = Some(raw_mode.to_mode(&id.to_string())?);
        }
        if let Some(secret) = raw_policy.secret {
            policy.secret = secret;
        }
        policy.structured_format = raw_policy.structured_format;

        // 先报“缺少格式”，再报“模式未实现”：前者是配置本身自相矛盾，
        // 无论哪个里程碑都是错的；后者只是当前版本的能力边界。
        if self.mode == FileMode::StructuredMerge && policy.structured_format.is_none() {
            return Err(ConfigError::StructuredWithoutFormat {
                resource: id.to_string(),
            });
        }
        match self.mode {
            FileMode::StructuredMerge => {
                return Err(ConfigError::ModeNotSupportedInM0 {
                    resource: id.to_string(),
                    mode: "structured_merge",
                })
            }
            FileMode::GeneratedInclude => {
                return Err(ConfigError::ModeNotSupportedInM0 {
                    resource: id.to_string(),
                    mode: "generated_include",
                })
            }
            FileMode::FullFile | FileMode::ManagedBlock => {}
        }

        // 选择器来自会被同步到所有设备的配置，是不可信输入：转换时限深，转换后再
        // 校验一次深度、节点数与取值规范性。
        let selector = match &self.selector {
            Some(raw) => {
                let selector = selector_from_yaml(raw, &id.to_string(), 1)?;
                selector
                    .validate()
                    .map_err(|source| ConfigError::InvalidSelector {
                        resource: id.to_string(),
                        source,
                    })?;
                Some(selector)
            }
            None => None,
        };

        let mut device_overrides = BTreeMap::new();
        for (key, raw_override) in self.device_overrides {
            // 键必须是合法设备标识：拼错的键会静默失效，那是最难排查的一类问题。
            key.parse::<DeviceId>()
                .map_err(|_| ConfigError::InvalidDeviceOverrideKey {
                    resource: id.to_string(),
                    key: key.clone(),
                })?;
            let overrides = ResourceOverride {
                disposition: raw_override.disposition,
                target: raw_override.target,
            };
            if overrides.is_empty() {
                return Err(ConfigError::EmptyDeviceOverride {
                    resource: id.to_string(),
                    key,
                });
            }
            if let Some(target) = &overrides.target {
                RelativeTarget::parse(target).map_err(|source| ConfigError::InvalidTarget {
                    resource: id.to_string(),
                    source,
                })?;
            }
            device_overrides.insert(key, overrides);
        }

        // disposition 与 blob 的组合一致性属于快照语义，由
        // `envsync_domain::ResourceEntry::validate` 在构造 State Root 时判定；
        // 配置层没有 blob，因此不在这里重复判断。

        Ok(ResourceConfig {
            id,
            root: self.root,
            target: self.target,
            mode: self.mode,
            disposition: self.disposition,
            policy,
            comment_prefix: self
                .comment_prefix
                .unwrap_or_else(|| DEFAULT_COMMENT_PREFIX.to_owned()),
            selector,
            device_overrides,
        })
    }

    /// 强类型 -> 线格式。策略字段全量写出，保证往返一致。
    fn from_config(resource: &ResourceConfig) -> Self {
        RawResource {
            id: resource.id.to_string(),
            root: resource.root.clone(),
            target: resource.target.clone(),
            mode: resource.mode,
            disposition: resource.disposition,
            comment_prefix: Some(resource.comment_prefix.clone()),
            policy: Some(RawPolicy {
                max_bytes: Some(resource.policy.max_bytes),
                line_ending: Some(resource.policy.line_ending),
                unix_mode: resource.policy.unix_mode.map(RawUnixMode::from_mode),
                secret: Some(resource.policy.secret),
                structured_format: resource.policy.structured_format,
            }),
            selector: resource.selector.as_ref().map(selector_to_yaml),
            device_overrides: resource
                .device_overrides
                .iter()
                .map(|(key, overrides)| {
                    (
                        key.clone(),
                        RawResourceOverride {
                            disposition: overrides.disposition,
                            target: overrides.target.clone(),
                        },
                    )
                })
                .collect(),
        }
    }
}
