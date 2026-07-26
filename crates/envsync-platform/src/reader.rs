//! 能力约束的文件读取。
//!
//! 读取是整个同步链条的输入。它的正确性要求比写入更微妙：**把失败读成“不存在”会
//! 直接导致数据丢失**——计划层看到 `Absent` 就认为可以放心创建/覆盖。因此这里的
//! 映射规则是死的：
//!
//! | 情况 | 结果 |
//! |---|---|
//! | 普通文件读取成功 | [`ObservedState::Present`] |
//! | 目标或其父目录确定不存在 | [`ObservedState::Absent`] |
//! | 权限不足、I/O 错误、超过大小上限、目标是目录 | [`ObservedState::Unreadable`] |
//! | 路径被策略拒绝（符号链接、非法目标、未注册根） | [`ObservedState::Excluded`] |
//!
//! 超过 [`ResourcePolicy::max_bytes`] 时返回 [`PlatformError::TooLarge`]，**绝不截断**：
//! 截断读会产生一个看似合法却与磁盘内容不符的摘要，进而让写入路径覆盖掉真实内容。

use std::io::Read;

use cap_std::fs::{Metadata, OpenOptions};
use envsync_domain::{
    Digest32, Observation, ObservedState, PermissionSummary, PresentFile, ResourceId,
    ResourcePolicy,
};

use crate::capability::{AuthorizedRoot, RelativeTarget, ResolvedPath};
use crate::PlatformError;

/// 文件内容摘要使用的域分隔标签。
///
/// 与 [`envsync_domain::BlobId`] 的 `envsync:blob:v1` 刻意区分：Blob 是后端对象，
/// 文件内容摘要是本机观察结果，两者即使字节相同也不应该被混用。
pub const FILE_CONTENT_DOMAIN: &str = "envsync:file-content:v1";

/// 一次成功读取的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOutcome {
    /// 文件完整内容。
    pub bytes: Vec<u8>,
    /// 内容摘要，域标签为 [`FILE_CONTENT_DOMAIN`]。
    pub digest: Digest32,
    /// 字节数（等于 `bytes.len()`，单独给出以便调用方不必持有 bytes）。
    pub size: u64,
    /// 修改时间（Unix 毫秒）；文件系统不提供时为 `None`。仅作诊断，新鲜度判定用摘要。
    pub mtime_unix_ms: Option<u64>,
    /// 权限摘要。
    pub permissions: PermissionSummary,
}

impl ReadOutcome {
    /// 转换为领域层的 [`PresentFile`]。
    ///
    /// `managed_digest` 由 core 的渲染器在解析出受管区块后补充，平台层不解释文件内容。
    pub fn to_present_file(&self) -> PresentFile {
        PresentFile {
            content_digest: self.digest,
            size: self.size,
            mtime_unix_ms: self.mtime_unix_ms,
            permissions: self.permissions,
            managed_digest: None,
        }
    }
}

/// 能力约束的文件读取器。
///
/// 无状态：所有能力都来自传入的 [`AuthorizedRoot`]。
#[derive(Debug, Clone, Copy, Default)]
pub struct FileReader;

impl FileReader {
    /// 计算文件内容摘要。
    pub fn content_digest(bytes: &[u8]) -> Digest32 {
        Digest32::domain_hash(FILE_CONTENT_DOMAIN, bytes)
    }

    /// 观察目标，产出领域层的 [`Observation`]。
    ///
    /// 该函数**不返回错误**：所有失败都被映射成对应的 [`ObservedState`]，因为“观察
    /// 失败”本身就是一种需要进入计划的状态，而不是应当中止流程的异常。
    pub fn observe(
        root: &AuthorizedRoot,
        target: &RelativeTarget,
        resource: &ResourceId,
        policy: &ResourcePolicy,
        now_unix_ms: u64,
    ) -> Observation {
        let outcome = root
            .resolve(target)
            .and_then(|resolved| Self::read_resolved(&resolved, policy.max_bytes));
        let state = match outcome {
            Ok(Some(read)) => ObservedState::Present(read.to_present_file()),
            Ok(None) => ObservedState::Absent,
            Err(error) => Self::state_for_error(&error),
        };
        tracing::debug!(
            resource = %resource,
            root = root.alias(),
            state = state.kind(),
            "完成一次观察"
        );
        Observation::new(resource.clone(), state, now_unix_ms)
    }

    /// 读取目标内容。
    ///
    /// # 错误
    ///
    /// * [`PlatformError::TooLarge`]：超过 `policy.max_bytes`；内容不会被截断。
    /// * [`PlatformError::SymlinkRejected`] / [`PlatformError::InvalidTarget`]：路径被拒绝。
    /// * [`PlatformError::Io`] 且 `kind == NotFound`：目标不存在。
    pub fn read_bytes(
        root: &AuthorizedRoot,
        target: &RelativeTarget,
        policy: &ResourcePolicy,
    ) -> Result<ReadOutcome, PlatformError> {
        let resolved = root.resolve(target)?;
        match Self::read_resolved(&resolved, policy.max_bytes)? {
            Some(outcome) => Ok(outcome),
            None => Err(PlatformError::Io {
                operation: "读取目标文件",
                kind: std::io::ErrorKind::NotFound,
                detail: "目标不存在".to_owned(),
            }),
        }
    }

    /// 读取当前摘要；目标不存在时返回 `None`。
    ///
    /// 写入路径用它做 stale 判定，因此它必须严格区分“不存在”和“读不出来”。
    pub fn current_digest(
        resolved: &ResolvedPath,
        max_bytes: u64,
    ) -> Result<Option<Digest32>, PlatformError> {
        Ok(Self::read_resolved(resolved, max_bytes)?.map(|outcome| outcome.digest))
    }

    /// 在已解析的路径上读取；目标不存在时返回 `Ok(None)`。
    ///
    /// 这是全部读取逻辑的唯一实现点，[`FileReader::observe`] 与 [`crate::writer`]
    /// 都复用它，保证“读”的语义在观察和写入前检查中完全一致。
    pub fn read_resolved(
        resolved: &ResolvedPath,
        max_bytes: u64,
    ) -> Result<Option<ReadOutcome>, PlatformError> {
        let dir = resolved.dir();
        let name = resolved.file_name();

        // 第一次 no-follow stat：确认类型，并在打开之前就挡掉超大文件。
        let metadata = match dir.symlink_metadata(name) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(PlatformError::io("读取目标元数据", &error)),
        };
        if metadata.is_symlink() {
            return Err(PlatformError::SymlinkRejected {
                alias: resolved.alias().to_owned(),
                index: resolved.file_index(),
                segment: name.to_owned(),
            });
        }
        check_regular_file(&metadata)?;
        if metadata.len() > max_bytes {
            return Err(PlatformError::TooLarge {
                limit: max_bytes,
                actual: metadata.len(),
            });
        }

        let mut file = match dir.open_with(name, OpenOptions::new().read(true)) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(PlatformError::io("打开目标文件", &error)),
        };

        // 第二次 stat 走已打开的句柄，不再受路径竞争影响；这是权威的类型与大小来源。
        let metadata = file
            .metadata()
            .map_err(|error| PlatformError::io("读取已打开文件的元数据", &error))?;
        check_regular_file(&metadata)?;
        if metadata.len() > max_bytes {
            return Err(PlatformError::TooLarge {
                limit: max_bytes,
                actual: metadata.len(),
            });
        }

        // 多读一个字节：文件在 stat 与 read 之间变大时能被发现，从而报错而不是静默截断。
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        let read = (&mut file)
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| PlatformError::io("读取目标文件", &error))?;
        if read as u64 > max_bytes {
            return Err(PlatformError::TooLarge {
                limit: max_bytes,
                actual: read as u64,
            });
        }

        let digest = Self::content_digest(&bytes);
        Ok(Some(ReadOutcome {
            size: bytes.len() as u64,
            bytes,
            digest,
            mtime_unix_ms: mtime_unix_ms(&metadata),
            permissions: permission_summary(&metadata),
        }))
    }

    /// 把平台错误映射成观察状态。
    ///
    /// 只有**确定不存在**才映射为 `Absent`；策略拒绝映射为 `Excluded`；其余一律
    /// `Unreadable`。所有 reason 都来自 [`PlatformError`] 的 `Display`，因此不含绝对路径。
    fn state_for_error(error: &PlatformError) -> ObservedState {
        match error {
            PlatformError::Io {
                kind: std::io::ErrorKind::NotFound,
                ..
            } => ObservedState::Absent,
            PlatformError::InvalidTarget(_)
            | PlatformError::SymlinkRejected { .. }
            | PlatformError::UnknownRoot { .. }
            | PlatformError::RootNotDirectory { .. } => ObservedState::Excluded {
                reason: error.to_string(),
            },
            _ => ObservedState::Unreadable {
                reason: error.to_string(),
            },
        }
    }
}

/// 确认元数据描述的是普通文件。
fn check_regular_file(metadata: &Metadata) -> Result<(), PlatformError> {
    if metadata.is_dir() {
        return Err(PlatformError::NotAFile { kind: "directory" });
    }
    if !metadata.is_file() {
        return Err(PlatformError::NotAFile {
            kind: "special file",
        });
    }
    Ok(())
}

/// 提取修改时间（Unix 毫秒）。
fn mtime_unix_ms(metadata: &Metadata) -> Option<u64> {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.into_std().duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as u64)
}

/// 提取权限摘要。
///
/// 只记录同步语义关心的字段：只读标志与 POSIX 权限位；属主 uid/gid 等本机信息一律不记录。
fn permission_summary(metadata: &Metadata) -> PermissionSummary {
    let permissions = metadata.permissions();
    #[cfg(unix)]
    let unix_mode = {
        use cap_std::fs::PermissionsExt;
        Some(permissions.mode() & 0o7777)
    };
    #[cfg(not(unix))]
    let unix_mode = None;
    PermissionSummary {
        readonly: permissions.readonly(),
        unix_mode,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_digest_is_domain_separated() {
        let payload = b"same bytes";
        assert_ne!(
            FileReader::content_digest(payload),
            envsync_domain::BlobId::of(payload).digest()
        );
        assert_eq!(
            FileReader::content_digest(payload),
            Digest32::domain_hash(FILE_CONTENT_DOMAIN, payload)
        );
    }
}
