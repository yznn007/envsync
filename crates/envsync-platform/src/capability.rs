//! 授权根、相对目标与逐段 no-follow 路径解析。
//!
//! 这里实现设计文档 §5「写入约束」的第一条：
//!
//! > 目标必须位于授权根目录内；拒绝 `..`、绝对路径逃逸和符号链接穿越。
//!
//! ## 为什么需要两层防护
//!
//! 第一层是 [`RelativeTarget::parse`] 的**纯文本**校验：它在任何系统调用之前就把
//! 绝对路径、`..`、盘符、UNC、保留设备名、NUL 等形状挡在门外。纯文本校验可以在
//! 没有文件系统的环境（例如审阅计划）里执行，因此计划本身就能被验证。
//!
//! 第二层是 [`AuthorizedRoot::resolve`] 的**运行时**校验：即使目标文本合法，中间
//! 目录仍然可能是指向授权根之外的符号链接。我们持有授权根的 [`cap_std::fs::Dir`]
//! 能力句柄，逐段执行 `symlink_metadata`（no-follow）确认不是符号链接后再
//! `open_dir` 进入下一段。
//!
//! ## 关于 cap-std 3.x 的 API 选择
//!
//! cap-std 3.4 的 [`cap_std::fs::Dir`] **没有**暴露 `open_dir_nofollow`（也没有
//! `OpenOptions` 级别的 `nofollow` 开关），因此这里采用等价实现：
//! 对每一段先调用 `Dir::symlink_metadata`（内部使用 `FollowSymlinks::No`）判断类型，
//! 确认是普通目录后再 `Dir::open_dir` 进入。所有调用都是**相对当前目录句柄**的，
//! 不经过任何绝对路径，因此不依赖进程 cwd，也不受路径拼接歧义影响。
//!
//! 这种“先 stat 再 open”存在理论上的 TOCTOU 窗口。它被两点约束住：
//!
//! * cap-std 自身保证相对操作不会逃出根目录句柄，所以最坏情况仍被限制在授权根内；
//! * 写入路径在 rename 之前还会再次比对内容摘要（见 [`crate::writer`]），
//!   被掉包的目标会以 [`crate::PlatformError::StaleObservation`] 失败而不是被覆盖。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use envsync_domain::ActionTarget;

use crate::PlatformError;

/// 相对目标的文本校验错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TargetError {
    /// 目标文本为空。
    #[error("目标不能为空")]
    Empty,
    /// 目标是绝对路径（以 `/` 或 `\` 开头）。
    #[error("目标不能是绝对路径")]
    Absolute,
    /// 目标是 UNC 路径（以 `\\` 或 `//` 开头）。
    #[error("目标不能是 UNC 路径")]
    UncPrefix,
    /// 目标带 Windows 盘符，例如 `C:`。
    #[error("目标不能包含盘符")]
    DriveLetter,
    /// 目标包含反斜杠。分段表示里反斜杠只能是普通字符，但在 Windows 上它是分隔符，
    /// 为了让同一个计划在三大平台上语义一致，一律拒绝。
    #[error("目标不能包含反斜杠")]
    Backslash,
    /// 目标包含 NUL 字节。
    #[error("目标不能包含 NUL 字节")]
    NulByte,
    /// 目标包含其他控制字符。
    #[error("目标不能包含控制字符")]
    ControlCharacter,
    /// 目标包含空段（连续或首尾的 `/`）。
    #[error("目标不能包含空段")]
    EmptySegment,
    /// 目标包含 `.` 或 `..` 段。
    #[error("目标不能包含 `.` 或 `..` 段")]
    DotSegment,
    /// 目标包含 Windows 保留设备名。
    #[error("目标段 `{0}` 是保留设备名")]
    ReservedDeviceName(String),
    /// 目标段以空格或点结尾。Windows 会静默去掉它们，从而让两个不同的目标指向同一个
    /// 文件，这会破坏“计划决定唯一目标”的前提。
    #[error("目标段 `{0}` 不能以空格或点结尾")]
    TrailingDotOrSpace(String),
    /// 段数超过上限。
    #[error("目标分段数超过上限 {max}", max = RelativeTarget::MAX_SEGMENTS)]
    TooManySegments,
    /// 目标总长度超过上限。
    #[error("目标长度超过上限 {max} 字节", max = RelativeTarget::MAX_LEN)]
    TooLong,
}

/// Windows 保留设备名（不区分大小写，且对 `NUL.txt` 这类带扩展名的形式同样生效）。
const RESERVED_DEVICE_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// 平台无关的相对目标：以分段表示，任何一段都不含路径分隔符。
///
/// 计划里保存的就是这种形式（见 [`envsync_domain::ActionTarget`]），因此同一份计划
/// 在 Linux、macOS、Windows 上表达完全相同的意图，也可以在没有文件系统的环境里被审阅。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelativeTarget(Vec<String>);

impl RelativeTarget {
    /// 允许的最大分段数。
    pub const MAX_SEGMENTS: usize = 32;
    /// 允许的最大文本长度（字节）。
    pub const MAX_LEN: usize = 1024;

    /// 解析 `a/b/c` 形式的相对目标。
    ///
    /// 接受：以 `/` 分隔的非空段。
    ///
    /// 拒绝：空文本、绝对路径、UNC 前缀、Windows 盘符、反斜杠、`.`、`..`、空段、
    /// NUL 与控制字符、保留设备名、以空格或点结尾的段、超长与超段数。
    pub fn parse(text: &str) -> Result<Self, PlatformError> {
        Ok(RelativeTarget(parse_segments(text)?))
    }

    /// 由已有分段构造，逐段执行与 [`RelativeTarget::parse`] 相同的校验。
    pub fn from_segments<I, S>(segments: I) -> Result<Self, PlatformError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let owned: Vec<String> = segments
            .into_iter()
            .map(|item| item.as_ref().to_owned())
            .collect();
        if owned.is_empty() {
            return Err(TargetError::Empty.into());
        }
        // 复用同一份校验逻辑：任何一段自带分隔符都会在这里被拆出空段或反斜杠错误。
        Self::parse(&owned.join("/"))
    }

    /// 由领域层的 [`ActionTarget`] 构造（只取相对分段，忽略根别名）。
    pub fn from_action_target(target: &ActionTarget) -> Result<Self, PlatformError> {
        Self::from_segments(&target.segments)
    }

    /// 分段视图。
    pub fn segments(&self) -> &[String] {
        &self.0
    }

    /// 以 `/` 连接的展示形式。相对分段不含本机绝对路径，可安全出现在诊断里。
    pub fn display_path(&self) -> String {
        self.0.join("/")
    }

    /// 最后一段，即文件名。
    pub fn file_name(&self) -> &str {
        // 构造时保证至少有一段。
        self.0.last().map(String::as_str).unwrap_or_default()
    }
}

impl std::fmt::Display for RelativeTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display_path())
    }
}

/// 执行相对目标的文本校验并返回分段。
fn parse_segments(text: &str) -> Result<Vec<String>, TargetError> {
    if text.is_empty() {
        return Err(TargetError::Empty);
    }
    if text.len() > RelativeTarget::MAX_LEN {
        return Err(TargetError::TooLong);
    }
    if text.contains('\0') {
        return Err(TargetError::NulByte);
    }
    // UNC 必须在“绝对路径”之前判断，否则 `//server/share` 会被误报为普通绝对路径。
    if text.starts_with("\\\\") || text.starts_with("//") {
        return Err(TargetError::UncPrefix);
    }
    if text.starts_with('/') || text.starts_with('\\') {
        return Err(TargetError::Absolute);
    }
    if has_drive_prefix(text) {
        return Err(TargetError::DriveLetter);
    }
    if text.contains('\\') {
        return Err(TargetError::Backslash);
    }
    // 冒号在 NTFS 上是备用数据流分隔符；即使不在开头也一律拒绝。
    if text.contains(':') {
        return Err(TargetError::DriveLetter);
    }
    if text.chars().any(char::is_control) {
        return Err(TargetError::ControlCharacter);
    }

    let segments: Vec<&str> = text.split('/').collect();
    if segments.len() > RelativeTarget::MAX_SEGMENTS {
        return Err(TargetError::TooManySegments);
    }
    for segment in &segments {
        if segment.is_empty() {
            return Err(TargetError::EmptySegment);
        }
        if *segment == "." || *segment == ".." {
            return Err(TargetError::DotSegment);
        }
        if segment.ends_with(' ') || segment.ends_with('.') {
            return Err(TargetError::TrailingDotOrSpace((*segment).to_owned()));
        }
        if is_reserved_device_name(segment) {
            return Err(TargetError::ReservedDeviceName((*segment).to_owned()));
        }
    }
    Ok(segments.into_iter().map(str::to_owned).collect())
}

/// 是否形如 `C:` 开头的盘符路径。
fn has_drive_prefix(text: &str) -> bool {
    let mut chars = text.chars();
    match (chars.next(), chars.next()) {
        (Some(letter), Some(':')) => letter.is_ascii_alphabetic(),
        _ => false,
    }
}

/// 是否是 Windows 保留设备名。
///
/// Windows 把 `NUL`、`NUL.txt`、`nul` 都解析成设备而不是文件，因此比较的是第一个 `.`
/// 之前的部分，并且忽略大小写。
fn is_reserved_device_name(segment: &str) -> bool {
    let stem = segment.split('.').next().unwrap_or(segment);
    RESERVED_DEVICE_NAMES
        .iter()
        .any(|name| stem.eq_ignore_ascii_case(name))
}

/// 已完成校验的解析结果：目标所在目录的能力句柄 + 文件名。
///
/// 拿到 `ResolvedPath` 就意味着「路径边界检查已经通过」。所有真实的读写都通过
/// [`ResolvedPath::dir`] 的相对操作完成，不再拼接绝对路径。
pub struct ResolvedPath {
    /// 授权根别名，用于诊断。
    alias: String,
    /// 目标**所在目录**的能力句柄。
    dir: Dir,
    /// 目标文件名（相对 `dir` 的单个分段）。
    file_name: String,
    /// 目标文件名在整个相对目标中的分段序号，用于诊断。
    file_index: usize,
    /// 目标的绝对路径。仅用于日志/备份等确实需要绝对路径的场合，**绝不**进入错误信息。
    absolute: PathBuf,
    /// `alias:a/b/c` 形式的展示串。
    display: String,
}

impl ResolvedPath {
    /// 授权根别名。
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// 目标所在目录的能力句柄。
    pub fn dir(&self) -> &Dir {
        &self.dir
    }

    /// 目标文件名。
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// 目标文件名在相对目标中的分段序号（从 0 开始）。
    pub fn file_index(&self) -> usize {
        self.file_index
    }

    /// 目标绝对路径。
    ///
    /// 只提供给确实需要绝对路径的调用方（例如把备份位置写进收据供人工排查）。
    /// **不要**把它放进错误信息或 JSON 诊断。
    pub fn absolute_path(&self) -> &Path {
        &self.absolute
    }

    /// `alias:a/b/c` 形式的展示串，可安全出现在诊断中。
    pub fn display_target(&self) -> &str {
        &self.display
    }
}

impl std::fmt::Debug for ResolvedPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 故意不打印绝对路径，避免 `{:?}` 意外泄露本机布局。
        f.debug_struct("ResolvedPath")
            .field("target", &self.display)
            .finish()
    }
}

/// 一个被显式授权的根目录。
///
/// 构造时把路径 canonicalize 成绝对路径，并打开目录能力句柄。此后所有操作都相对这个
/// 句柄执行：即使根目录在运行期被改名或替换，已持有的句柄仍指向最初被授权的目录。
pub struct AuthorizedRoot {
    /// 逻辑别名，例如 `home`。计划里只出现别名，不出现绝对路径。
    alias: String,
    /// canonicalize 之后的绝对路径。
    path: PathBuf,
    /// 根目录能力句柄。
    dir: Dir,
}

impl AuthorizedRoot {
    /// 打开授权根。
    ///
    /// `path` 会被 canonicalize（因此根目录本身允许是符号链接——用户显式授权的就是它
    /// 指向的真实目录），随后校验它确实是目录，最后打开能力句柄。
    pub fn open(alias: impl Into<String>, path: &Path) -> Result<Self, PlatformError> {
        let alias = alias.into();
        let canonical =
            std::fs::canonicalize(path).map_err(|error| PlatformError::RootUnavailable {
                alias: alias.clone(),
                detail: crate::describe_io(&error),
            })?;
        let metadata =
            std::fs::metadata(&canonical).map_err(|error| PlatformError::RootUnavailable {
                alias: alias.clone(),
                detail: crate::describe_io(&error),
            })?;
        if !metadata.is_dir() {
            return Err(PlatformError::RootNotDirectory { alias });
        }
        let dir = Dir::open_ambient_dir(&canonical, ambient_authority()).map_err(|error| {
            PlatformError::RootUnavailable {
                alias: alias.clone(),
                detail: crate::describe_io(&error),
            }
        })?;
        tracing::debug!(alias = %alias, "打开授权根");
        Ok(AuthorizedRoot {
            alias,
            path: canonical,
            dir,
        })
    }

    /// 授权根别名。
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// 授权根的 canonical 绝对路径。仅用于日志与备份定位，不应进入错误信息。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 根目录能力句柄。
    pub fn dir(&self) -> &Dir {
        &self.dir
    }

    /// 逐段 no-follow 解析相对目标。
    ///
    /// 对每个**中间**段：`symlink_metadata` 确认既不是符号链接又确实是目录，然后
    /// `open_dir` 进入。对**最终**段：若已存在则确认不是符号链接；不存在是允许的
    /// （写入新文件的场景），由调用方决定如何处理。
    ///
    /// # 错误
    ///
    /// * [`PlatformError::SymlinkRejected`]：任意一段是符号链接。
    /// * [`PlatformError::NotADirectory`]：中间段存在但不是目录。
    /// * [`PlatformError::Io`] 且 `kind == NotFound`：中间目录不存在。
    ///   调用方据此判定为 [`envsync_domain::ObservedState::Absent`]。
    pub fn resolve(&self, target: &RelativeTarget) -> Result<ResolvedPath, PlatformError> {
        let segments = target.segments();
        let (file_name, parents) = segments
            .split_last()
            .ok_or_else(|| PlatformError::from(TargetError::Empty))?;

        let mut dir = self
            .dir
            .try_clone()
            .map_err(|error| PlatformError::io("克隆授权根句柄", &error))?;
        let mut absolute = self.path.clone();

        for (index, segment) in parents.iter().enumerate() {
            let metadata = dir
                .symlink_metadata(segment)
                .map_err(|error| PlatformError::io("读取中间目录元数据", &error))?;
            if metadata.is_symlink() {
                return Err(PlatformError::SymlinkRejected {
                    alias: self.alias.clone(),
                    index,
                    segment: segment.clone(),
                });
            }
            if !metadata.is_dir() {
                return Err(PlatformError::NotADirectory {
                    alias: self.alias.clone(),
                    segment: segment.clone(),
                });
            }
            dir = dir
                .open_dir(segment)
                .map_err(|error| PlatformError::io("打开中间目录", &error))?;
            absolute.push(segment);
        }

        // 最终段：存在则必须不是符号链接；不存在是合法的（待创建）。
        match dir.symlink_metadata(file_name) {
            Ok(metadata) if metadata.is_symlink() => {
                return Err(PlatformError::SymlinkRejected {
                    alias: self.alias.clone(),
                    index: parents.len(),
                    segment: file_name.clone(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(PlatformError::io("读取目标元数据", &error)),
        }
        absolute.push(file_name);

        Ok(ResolvedPath {
            alias: self.alias.clone(),
            dir,
            file_name: file_name.clone(),
            file_index: parents.len(),
            absolute,
            display: format!("{}:{}", self.alias, target.display_path()),
        })
    }
}

impl std::fmt::Debug for AuthorizedRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 同 `ResolvedPath`：不打印绝对路径。
        f.debug_struct("AuthorizedRoot")
            .field("alias", &self.alias)
            .finish()
    }
}

/// 授权根注册表：按别名查找授权根。
///
/// 计划中的 [`ActionTarget::root`] 是别名而不是路径，注册表负责把别名映射回本机能力。
/// 未注册的别名一律报错，绝不回退到“当前目录”之类的隐式行为。
#[derive(Debug, Default)]
pub struct RootRegistry {
    roots: BTreeMap<String, AuthorizedRoot>,
}

impl RootRegistry {
    /// 创建空注册表。
    pub fn new() -> Self {
        RootRegistry::default()
    }

    /// 注册授权根；同名会被替换并返回旧值。
    pub fn insert(&mut self, root: AuthorizedRoot) -> Option<AuthorizedRoot> {
        self.roots.insert(root.alias().to_owned(), root)
    }

    /// 按别名查找授权根。
    pub fn get(&self, alias: &str) -> Result<&AuthorizedRoot, PlatformError> {
        self.roots
            .get(alias)
            .ok_or_else(|| PlatformError::UnknownRoot {
                alias: alias.to_owned(),
            })
    }

    /// 已注册的别名（字典序）。
    pub fn aliases(&self) -> impl Iterator<Item = &str> {
        self.roots.keys().map(String::as_str)
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// 已注册的授权根数量。
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// 把领域层的 [`ActionTarget`] 解析为本机路径。
    pub fn resolve_action_target(
        &self,
        target: &ActionTarget,
    ) -> Result<ResolvedPath, PlatformError> {
        let root = self.get(&target.root)?;
        let relative = RelativeTarget::from_action_target(target)?;
        root.resolve(&relative)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(text: &str) -> TargetError {
        match RelativeTarget::parse(text) {
            Err(PlatformError::InvalidTarget(inner)) => inner,
            other => panic!("期望目标校验错误，实际 {other:?}"),
        }
    }

    #[test]
    fn accepts_multi_segment_relative_target() {
        let target = RelativeTarget::parse(".config/envsync/demo.toml").unwrap();
        assert_eq!(target.segments(), [".config", "envsync", "demo.toml"]);
        assert_eq!(target.file_name(), "demo.toml");
        assert_eq!(target.display_path(), ".config/envsync/demo.toml");
    }

    #[test]
    fn rejects_path_like_forms() {
        assert_eq!(err(""), TargetError::Empty);
        assert_eq!(err("/etc/passwd"), TargetError::Absolute);
        assert_eq!(err("\\windows\\system32"), TargetError::Absolute);
        assert_eq!(err("//server/share"), TargetError::UncPrefix);
        assert_eq!(err("\\\\server\\share"), TargetError::UncPrefix);
        assert_eq!(err("C:/Windows"), TargetError::DriveLetter);
        assert_eq!(err("a\\b"), TargetError::Backslash);
        assert_eq!(err("a\0b"), TargetError::NulByte);
        assert_eq!(err("a\nb"), TargetError::ControlCharacter);
        assert_eq!(err("a//b"), TargetError::EmptySegment);
        assert_eq!(err("a/"), TargetError::EmptySegment);
        assert_eq!(err("a/./b"), TargetError::DotSegment);
        assert_eq!(err("../escape"), TargetError::DotSegment);
        assert_eq!(
            err("CON"),
            TargetError::ReservedDeviceName("CON".to_owned())
        );
        assert_eq!(
            err("dir/nul.txt"),
            TargetError::ReservedDeviceName("nul.txt".to_owned())
        );
        assert_eq!(
            err("com9"),
            TargetError::ReservedDeviceName("com9".to_owned())
        );
        assert_eq!(
            err("trailing "),
            TargetError::TrailingDotOrSpace("trailing ".to_owned())
        );
        assert_eq!(err(&"a/".repeat(40)), TargetError::TooManySegments);
        assert_eq!(
            err(&"x".repeat(RelativeTarget::MAX_LEN + 1)),
            TargetError::TooLong
        );
    }

    #[test]
    fn from_segments_rejects_embedded_separators() {
        assert_eq!(
            RelativeTarget::from_segments(["a", "b/../c"])
                .unwrap_err()
                .to_string(),
            PlatformError::from(TargetError::DotSegment).to_string()
        );
        let ok = RelativeTarget::from_segments(["a", "b"]).unwrap();
        assert_eq!(ok.segments(), ["a", "b"]);
    }

    #[test]
    fn unknown_alias_is_rejected() {
        let registry = RootRegistry::new();
        assert!(registry.is_empty());
        let error = registry.get("home").unwrap_err();
        assert!(matches!(error, PlatformError::UnknownRoot { .. }));
    }
}
