//! Git config 三方合并（自带解析器，无第三方依赖）。
//!
//! 复用 [`super::ini`] 的「节 + 键值行 + 版式」模型，并按 git 规范扩展：
//!
//! ## 键 identity
//!
//! identity 是 `section / subsection / name`：
//!
//! - **section 大小写不敏感**（`[Core]` 与 `[core]` 是同一节）；
//! - **subsection 大小写敏感**且逐字保留（`[remote "Origin"]` ≠ `[remote "origin"]`），
//!   两种写法 `[section "sub"]` 与传统的 `[section.sub]` 都被识别为同一 identity；
//! - **name 大小写不敏感**（`autoCRLF` 与 `autocrlf` 是同一个键）。
//!
//! ## 多值键
//!
//! git 允许同一个键出现多次（例如 `remote.origin.fetch`）。这里把一个键的**取值
//! 列表**当作有序的整体参与三方合并：顺序被完整保留，单值键因此天然退化为独立合并。
//!
//! ## `include.path` 的安全约束
//!
//! `include.path` 与 `includeIf.*.path` 的取值按**规范化路径**做身份识别
//! （纯词法规范化：折叠 `//`、消解 `.` 与 `..`、去掉结尾 `/`），
//! 因此 `~/git/../gitconfig` 与 `~/gitconfig` 被认为是同一条 include。
//!
//! **合并器绝不打开、读取或跟随 include 目标**：跟随 include 等价于按文件内容里的
//! 任意路径去读盘，是明确的越权面。include 只被当作普通的字符串键值处理。
//!
//! ## 已知限制
//!
//! - 值不做引号 / 转义 / 续行解析，逐字保留原文；因此 `foo = "a; b"` 里的 `;`
//!   不会被当作注释，但也不会被反转义。
//! - 布尔简写（只有键名没有 `=`）暂不支持，会报 [`super::MergeError::Parse`]。

use super::ini::{merge_config, Dialect};
use super::{IniPolicy, MergeError, MergeInput, MergeResult, MultiValuePolicy};

/// Git config 三方合并入口。
pub fn merge_git_config(input: &MergeInput<'_>) -> Result<MergeResult, MergeError> {
    // git config 天然允许多值键，因此固定使用 Append 策略。
    let policy = IniPolicy {
        multi_value: MultiValuePolicy::Append,
    };
    merge_config(input, Dialect::GitConfig, policy, include_aware_identity)
}

/// 值的比较身份：`include.path` / `includeIf.*.path` 按规范化路径比较，其余逐字比较。
fn include_aware_identity(section_id: &str, key: &str, values: &[String]) -> Vec<String> {
    if is_include_path(section_id, key) {
        return values.iter().map(|value| normalize_path(value)).collect();
    }
    values.to_vec()
}

/// 判断某个键是否是 include 目标路径。
///
/// `section_id` 形如 `include` 或 `includeif\u{1}gitdir:~/work/`。
fn is_include_path(section_id: &str, key: &str) -> bool {
    if key != "path" {
        return false;
    }
    let section = section_id.split('\u{1}').next().unwrap_or(section_id);
    section == "include" || section == "includeif"
}

/// 纯词法路径规范化：**不触碰文件系统**，不解析符号链接，不展开 `~`。
///
/// - `\` 统一按 `/` 处理，便于 Windows 风格路径比较；
/// - 折叠重复分隔符；
/// - 消解 `.`；对 `..` 做词法回退（无可回退项时保留 `..`）；
/// - 去掉结尾分隔符（根路径除外）。
pub(crate) fn normalize_path(raw: &str) -> String {
    let trimmed = raw.trim();
    let unified = trimmed.replace('\\', "/");
    let absolute = unified.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for segment in unified.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if matches!(parts.last(), Some(&last) if last != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    if absolute {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_owned()
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_is_lexical_only() {
        assert_eq!(normalize_path("~/git/../gitconfig"), "~/gitconfig");
        assert_eq!(normalize_path("  ./a//b/./c/  "), "a/b/c");
        assert_eq!(normalize_path("/a/b/../../c"), "/c");
        assert_eq!(normalize_path("../../x"), "../../x");
        assert_eq!(
            normalize_path("C:\\Users\\me\\.gitconfig"),
            "C:/Users/me/.gitconfig"
        );
    }

    #[test]
    fn include_path_detection_covers_conditional_includes() {
        assert!(is_include_path("include", "path"));
        assert!(is_include_path("includeif\u{1}gitdir:~/work/", "path"));
        assert!(!is_include_path("core", "path"));
        assert!(!is_include_path("include", "other"));
    }
}
