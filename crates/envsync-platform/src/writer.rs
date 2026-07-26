//! 安全写入、备份、删除与回滚收据。
//!
//! 实现设计文档 §5「写入约束」的其余部分与 §4「同步事务」的 Stage/Apply 阶段。
//!
//! ## 固定顺序
//!
//! ```text
//! 解析路径 → 重读目标并比对 expected_before
//!          → 同目录临时文件写入 → fsync(temp)
//!          → 备份原文件（copy 语义，原文件保持原地）
//!          → rename 覆盖 → fsync(parent)
//! ```
//!
//! 每一步的顺序都有原因：
//!
//! * **先比对再写。** 计划绑定了生成时的观察结果，写入前必须重新读取确认目标没被
//!   外部改动，否则会静默覆盖用户的新修改（见 [`PlatformError::StaleObservation`]）。
//! * **临时文件在同一个目录。** 跨目录 rename 可能跨文件系统而退化成 copy+delete，
//!   失去原子性；同目录 rename 在 POSIX 与 Windows 上都是原子替换。
//! * **备份在 rename 之前、且用 copy 而不是 rename。** 如果用 rename 把原文件挪走，
//!   在备份完成到新文件就位之间目标会短暂消失；用 copy 则原文件在被覆盖前始终完好。
//! * **rename 之后 fsync 父目录。** 否则崩溃后目录项可能仍指向旧 inode。
//!
//! ## Windows 说明
//!
//! [`std::fs::rename`]（以及 [`cap_std::fs::Dir::rename`]）在 Windows 上已经是替换
//! 语义（内部走 `MoveFileEx` + `MOVEFILE_REPLACE_EXISTING`），因此这里直接使用它。
//!
//! 我们**不使用** `ReplaceFileW`：它需要 `unsafe` FFI，而本 crate 是
//! `#![forbid(unsafe_code)]`，交接指南也禁止引入 unsafe。设计文档中 `ReplaceFileW`
//! 想要的「journaled replace」保证，由 core 的 SQLite journal（记录操作状态机）
//! 加上本模块的备份收据共同提供等价效果：崩溃后可以从 journal 判断处于哪个阶段，
//! 并用 [`Receipt::backup_path`] 精确恢复原字节。
//!
//! Windows 没有「fsync 一个目录句柄」的等价操作，[`sync_parent_dir`] 在非 unix 平台
//! 上是空操作；耐久性由 journal 的恢复流程补齐。

use std::io::Write;
use std::path::{Path, PathBuf};

use cap_std::fs::{Dir, OpenOptions};
use envsync_domain::{Digest32, OperationId, ResourceId, RollbackCapability};

use crate::capability::{AuthorizedRoot, RelativeTarget};
use crate::reader::{FileReader, ReadOutcome};
use crate::{digest_label, PlatformError};

/// 同目录临时文件的名字前缀。
///
/// 以 `.` 开头，便于恢复流程识别并清理遗留的 staging 文件。
pub const TEMP_FILE_PREFIX: &str = ".envsync-tmp-";

/// 秘密资源在未显式指定权限时的默认 POSIX 权限位。
pub const SECRET_DEFAULT_MODE: u32 = 0o600;

/// 创建临时文件时的最大重试次数（`create_new` 撞名时重试）。
const TEMP_NAME_ATTEMPTS: u32 = 8;

/// 测试专用的故障注入钩子。
///
/// 生产代码把它保持为 [`FaultInjection::default`]（全 `false`），因此零开销且行为不变。
/// 它的用途是验证「注入 rename/fsync 失败时保留可恢复证据」这一条验收标准：真实的
/// 磁盘故障无法在单元测试里稳定复现，但故障点的**善后行为**必须可测。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FaultInjection {
    /// 临时文件写入并 fsync 之后失败。此时尚未备份、尚未替换，临时文件会被清理。
    pub fail_after_temp_write: bool,
    /// 备份原文件之前失败。临时文件会被清理，目标不变。
    pub fail_before_backup: bool,
    /// 备份完成、rename（或删除）之前失败。
    /// **保留**临时文件与备份作为可恢复证据。
    pub fail_before_rename: bool,
    /// rename（或删除）完成、父目录 fsync 之前失败。备份保留。
    pub fail_after_rename: bool,
}

impl FaultInjection {
    /// 是否完全没有注入任何故障。
    pub fn is_disabled(&self) -> bool {
        *self == FaultInjection::default()
    }
}

/// 一次写入请求。
#[derive(Debug)]
pub struct WriteRequest<'a> {
    /// 所属操作，决定备份目录。
    pub operation: OperationId,
    /// 目标资源。
    pub resource: &'a ResourceId,
    /// 授权根。
    pub root: &'a AuthorizedRoot,
    /// 相对目标。
    pub target: &'a RelativeTarget,
    /// 待写入的完整内容。平台层不做任何渲染，字节即最终结果。
    pub content: &'a [u8],
    /// 写入前目标应有的摘要；`None` 表示期望目标不存在。
    pub expected_before: Option<Digest32>,
    /// 期望的 POSIX 权限位；`None` 时按 [`SafeWriter::effective_mode`] 的规则推导。
    pub unix_mode: Option<u32>,
    /// 是否是秘密资源。秘密资源不得退化到可能暴露明文的写入路径。
    pub secret: bool,
}

/// 一次删除请求。
#[derive(Debug)]
pub struct DeleteRequest<'a> {
    /// 所属操作，决定备份目录。
    pub operation: OperationId,
    /// 目标资源。
    pub resource: &'a ResourceId,
    /// 授权根。
    pub root: &'a AuthorizedRoot,
    /// 相对目标。
    pub target: &'a RelativeTarget,
    /// 删除前目标应有的摘要；`None` 表示期望目标已经不存在（幂等删除）。
    pub expected_before: Option<Digest32>,
}

/// 回滚收据：一次成功变更所留下的、足以精确撤销它的全部证据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// 被变更的资源。
    pub resource: ResourceId,
    /// 原文件备份路径；原文件不存在时为 `None`。
    pub backup_path: Option<PathBuf>,
    /// 变更前的内容摘要；原文件不存在时为 `None`。
    pub original_digest: Option<Digest32>,
    /// 变更后的内容摘要；删除动作为 `None`。
    pub applied_digest: Option<Digest32>,
    /// 回滚能力。
    pub guarantee: RollbackCapability,
}

/// 安全写入器。
///
/// `backup_root` 由调用方给出（通常是本地状态目录下的 `backups/`），本模块不猜测位置，
/// 也不把备份放进授权根内——否则备份自身会被下一次同步当成用户文件。
#[derive(Debug, Clone)]
pub struct SafeWriter {
    /// 备份根目录。
    backup_root: PathBuf,
    /// 读取原文件时的字节上限；超过则拒绝写入而不是丢弃备份。
    max_bytes: u64,
    /// 故障注入配置。
    faults: FaultInjection,
}

impl SafeWriter {
    /// 以给定备份根目录构造。
    pub fn new(backup_root: impl Into<PathBuf>) -> Self {
        SafeWriter {
            backup_root: backup_root.into(),
            max_bytes: envsync_domain::ResourcePolicy::DEFAULT_MAX_BYTES,
            faults: FaultInjection::default(),
        }
    }

    /// 设置读取原文件与写入内容的字节上限。
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// 设置故障注入配置（测试专用）。
    #[must_use]
    pub fn with_fault_injection(mut self, faults: FaultInjection) -> Self {
        self.faults = faults;
        self
    }

    /// 备份根目录。
    pub fn backup_root(&self) -> &Path {
        &self.backup_root
    }

    /// 备份路径是确定性的：`<backup_root>/<operation_id>/<resource_id>`。
    ///
    /// 确定性让恢复流程无需读 journal 就能定位备份，也让重复执行同一操作不会产生
    /// 无法关联的孤儿文件。
    pub fn backup_path_for(&self, operation: OperationId, resource: &ResourceId) -> PathBuf {
        self.backup_root
            .join(operation.to_filename())
            .join(resource.to_filename())
    }

    /// 推导临时文件与最终文件应有的 POSIX 权限位。
    ///
    /// 优先级：显式 `unix_mode` > 秘密资源默认 [`SECRET_DEFAULT_MODE`] > 沿用原文件权限 >
    /// 平台默认（返回 `None`，由 umask 决定）。
    fn effective_mode(request: &WriteRequest<'_>, current: Option<&ReadOutcome>) -> Option<u32> {
        if let Some(mode) = request.unix_mode {
            return Some(mode & 0o7777);
        }
        if request.secret {
            return Some(SECRET_DEFAULT_MODE);
        }
        current.and_then(|outcome| outcome.permissions.unix_mode)
    }

    /// 原子写入目标。
    ///
    /// # 错误
    ///
    /// * [`PlatformError::StaleObservation`]：写入前重读的摘要与 `expected_before` 不符。
    /// * [`PlatformError::TooLarge`]：内容或原文件超过上限。
    /// * 路径类错误：见 [`AuthorizedRoot::resolve`]。
    pub fn apply_write(&self, request: &WriteRequest<'_>) -> Result<Receipt, PlatformError> {
        if request.content.len() as u64 > self.max_bytes {
            return Err(PlatformError::TooLarge {
                limit: self.max_bytes,
                actual: request.content.len() as u64,
            });
        }

        let resolved = request.root.resolve(request.target)?;
        let current = FileReader::read_resolved(&resolved, self.max_bytes)?;
        let actual = current.as_ref().map(|outcome| outcome.digest);
        if actual != request.expected_before {
            return Err(PlatformError::StaleObservation {
                expected: request.expected_before,
                actual,
            });
        }

        let mode = Self::effective_mode(request, current.as_ref());
        let temp_name = create_temp_file(
            resolved.dir(),
            &request.operation.to_filename(),
            request.content,
            mode,
        )?;

        // 到这里为止目标文件一个字节都没有变过：临时文件是新建的独立 inode。
        if self.faults.fail_after_temp_write {
            let _ = resolved.dir().remove_file(&temp_name);
            return Err(PlatformError::FaultInjected {
                stage: "after_temp_write",
            });
        }
        if self.faults.fail_before_backup {
            let _ = resolved.dir().remove_file(&temp_name);
            return Err(PlatformError::FaultInjected {
                stage: "before_backup",
            });
        }

        let backup_path = match current.as_ref() {
            Some(outcome) => {
                match self.write_backup(request.operation, request.resource, outcome) {
                    Ok(path) => Some(path),
                    Err(error) => {
                        // 备份失败即动作失败：宁可什么都不做，也不能在没有退路的情况下覆盖。
                        let _ = resolved.dir().remove_file(&temp_name);
                        return Err(error);
                    }
                }
            }
            None => None,
        };

        if self.faults.fail_before_rename {
            // 故意不清理：临时文件 + 备份就是「可恢复证据」，恢复流程据此判断阶段。
            return Err(PlatformError::FaultInjected {
                stage: "before_rename",
            });
        }

        // POSIX：rename 原子替换。Windows：MoveFileEx + REPLACE_EXISTING，同样是替换语义。
        resolved
            .dir()
            .rename(&temp_name, resolved.dir(), resolved.file_name())
            .map_err(|error| PlatformError::io("原子替换目标", &error))?;

        if self.faults.fail_after_rename {
            return Err(PlatformError::FaultInjected {
                stage: "after_rename",
            });
        }
        sync_parent_dir(resolved.dir())?;

        let applied_digest = FileReader::content_digest(request.content);
        tracing::info!(
            resource = %request.resource,
            operation = %request.operation,
            target = resolved.display_target(),
            applied = %applied_digest.short(),
            "完成原子写入"
        );
        Ok(Receipt {
            resource: request.resource.clone(),
            backup_path,
            original_digest: actual,
            applied_digest: Some(applied_digest),
            // 原文件已按字节备份，或原本就不存在（回滚 = 删除），两种情况都能精确复原。
            guarantee: RollbackCapability::Exact,
        })
    }

    /// 删除目标。
    ///
    /// **总是先备份**；目标不存在时是幂等成功，返回 `backup_path` 为 `None` 的收据。
    pub fn apply_delete(&self, request: &DeleteRequest<'_>) -> Result<Receipt, PlatformError> {
        let resolved = request.root.resolve(request.target)?;
        let current = FileReader::read_resolved(&resolved, self.max_bytes)?;
        let actual = current.as_ref().map(|outcome| outcome.digest);
        if actual != request.expected_before {
            return Err(PlatformError::StaleObservation {
                expected: request.expected_before,
                actual,
            });
        }

        let Some(outcome) = current else {
            // 幂等：目标已经不存在，什么都不做也算收敛成功。
            tracing::debug!(
                resource = %request.resource,
                target = resolved.display_target(),
                "删除目标已不存在，视为幂等成功"
            );
            return Ok(Receipt {
                resource: request.resource.clone(),
                backup_path: None,
                original_digest: None,
                applied_digest: None,
                guarantee: RollbackCapability::Exact,
            });
        };

        if self.faults.fail_before_backup {
            return Err(PlatformError::FaultInjected {
                stage: "before_backup",
            });
        }
        let backup_path = self.write_backup(request.operation, request.resource, &outcome)?;

        if self.faults.fail_before_rename {
            // 备份已经落盘：即使这里中断，原内容仍可完整恢复。
            return Err(PlatformError::FaultInjected {
                stage: "before_remove",
            });
        }

        resolved
            .dir()
            .remove_file(resolved.file_name())
            .map_err(|error| PlatformError::io("删除目标", &error))?;

        if self.faults.fail_after_rename {
            return Err(PlatformError::FaultInjected {
                stage: "after_remove",
            });
        }
        sync_parent_dir(resolved.dir())?;

        tracing::info!(
            resource = %request.resource,
            operation = %request.operation,
            target = resolved.display_target(),
            "完成受控删除"
        );
        Ok(Receipt {
            resource: request.resource.clone(),
            backup_path: Some(backup_path),
            original_digest: Some(outcome.digest),
            applied_digest: None,
            guarantee: RollbackCapability::Exact,
        })
    }

    /// 按收据回滚。
    ///
    /// 只有在「目标当前摘要 == `receipt.applied_digest`」时才执行，否则返回
    /// [`PlatformError::RollbackRefused`]：摘要不符说明用户在此期间又改过这个文件，
    /// 盲目回滚会把用户的新修改一起抹掉。备份缺失或备份内容与
    /// `receipt.original_digest` 不符时同样拒绝，并保持现场不变以便人工诊断。
    pub fn rollback(
        &self,
        receipt: &Receipt,
        root: &AuthorizedRoot,
        target: &RelativeTarget,
    ) -> Result<(), PlatformError> {
        let resolved = root.resolve(target)?;
        let current = FileReader::read_resolved(&resolved, self.max_bytes)?;
        let actual = current.as_ref().map(|outcome| outcome.digest);
        if actual != receipt.applied_digest {
            return Err(PlatformError::RollbackRefused {
                reason: format!(
                    "目标当前摘要 {} 与收据记录的应用后摘要 {} 不一致，可能已被外部修改",
                    digest_label(&actual),
                    digest_label(&receipt.applied_digest)
                ),
            });
        }

        let Some(original_digest) = receipt.original_digest else {
            // 原本不存在 → 回滚就是删除。
            if current.is_some() {
                resolved
                    .dir()
                    .remove_file(resolved.file_name())
                    .map_err(|error| PlatformError::io("回滚时删除目标", &error))?;
                sync_parent_dir(resolved.dir())?;
            }
            tracing::info!(
                resource = %receipt.resource,
                target = resolved.display_target(),
                "回滚完成：目标恢复为不存在"
            );
            return Ok(());
        };

        let backup_path =
            receipt
                .backup_path
                .as_ref()
                .ok_or_else(|| PlatformError::RollbackRefused {
                    reason: format!(
                        "收据声明原始摘要 {} 但没有备份路径",
                        original_digest.short()
                    ),
                })?;
        let bytes = std::fs::read(backup_path).map_err(|error| PlatformError::RollbackRefused {
            reason: format!("备份不可读：{}", crate::describe_io(&error)),
        })?;
        let backup_digest = FileReader::content_digest(&bytes);
        if backup_digest != original_digest {
            return Err(PlatformError::RollbackRefused {
                reason: format!(
                    "备份内容摘要 {} 与收据记录的原始摘要 {} 不符",
                    backup_digest.short(),
                    original_digest.short()
                ),
            });
        }

        // 备份文件在创建时被赋予了原文件的权限位，因此这里可以顺带恢复权限。
        let mode = backup_unix_mode(backup_path);
        let temp_name = create_temp_file(resolved.dir(), "rollback", &bytes, mode)?;
        resolved
            .dir()
            .rename(&temp_name, resolved.dir(), resolved.file_name())
            .map_err(|error| {
                let _ = resolved.dir().remove_file(&temp_name);
                PlatformError::io("回滚时原子替换目标", &error)
            })?;
        sync_parent_dir(resolved.dir())?;

        tracing::info!(
            resource = %receipt.resource,
            target = resolved.display_target(),
            restored = %original_digest.short(),
            "回滚完成：目标已恢复为原字节"
        );
        Ok(())
    }

    /// 校验目标当前内容摘要。
    ///
    /// `expected` 为 `None` 表示期望目标不存在。
    pub fn verify(
        &self,
        root: &AuthorizedRoot,
        target: &RelativeTarget,
        expected: Option<Digest32>,
    ) -> Result<(), PlatformError> {
        let resolved = root.resolve(target)?;
        let actual = FileReader::current_digest(&resolved, self.max_bytes)?;
        if actual == expected {
            Ok(())
        } else {
            Err(PlatformError::VerificationFailed { expected, actual })
        }
    }

    /// 把原文件内容备份到确定性路径。
    ///
    /// 采用 copy 语义而不是 rename：原文件在被 rename 覆盖之前必须始终完好。这里写入的
    /// 是刚刚读出并已计算摘要的同一份字节，因此备份内容与
    /// [`Receipt::original_digest`] 天然一致，比「再 copy 一次」少一个竞态窗口。
    fn write_backup(
        &self,
        operation: OperationId,
        resource: &ResourceId,
        outcome: &ReadOutcome,
    ) -> Result<PathBuf, PlatformError> {
        let directory = self.backup_root.join(operation.to_filename());
        std::fs::create_dir_all(&directory)
            .map_err(|error| PlatformError::io("创建备份目录", &error))?;
        let path = directory.join(resource.to_filename());

        let mut file = std::fs::File::create(&path)
            .map_err(|error| PlatformError::io("创建备份文件", &error))?;
        file.write_all(&outcome.bytes)
            .map_err(|error| PlatformError::io("写入备份文件", &error))?;
        file.sync_all()
            .map_err(|error| PlatformError::io("同步备份文件", &error))?;
        drop(file);

        #[cfg(unix)]
        if let Some(mode) = outcome.permissions.unix_mode {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .map_err(|error| PlatformError::io("设置备份文件权限", &error))?;
        }

        sync_ambient_dir(&directory)?;
        tracing::debug!(
            resource = %resource,
            operation = %operation,
            digest = %outcome.digest.short(),
            "已备份原文件"
        );
        Ok(path)
    }
}

/// 在目标同目录创建并写入临时文件，返回临时文件名。
///
/// 使用 `create_new`（`O_EXCL`）保证不会覆盖同名文件；撞名时换一个后缀重试。
/// 写入后 `sync_all`，确保 rename 之后即使断电也能读到完整内容。
fn create_temp_file(
    dir: &Dir,
    tag: &str,
    content: &[u8],
    mode: Option<u32>,
) -> Result<String, PlatformError> {
    let mut last_error = None;
    for _ in 0..TEMP_NAME_ATTEMPTS {
        let name = format!("{TEMP_FILE_PREFIX}{tag}-{}", unique_suffix());
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        // 秘密资源必须**从创建的那一刻**就是受限权限，不能先以默认权限落盘再收紧。
        #[cfg(unix)]
        if let Some(mode) = mode {
            use cap_std::fs::OpenOptionsExt;
            options.mode(mode);
        }
        match dir.open_with(&name, &options) {
            Ok(mut file) => {
                file.write_all(content)
                    .map_err(|error| PlatformError::io("写入临时文件", &error))?;
                // umask 会削弱 `O_CREAT` 传入的 mode，因此再显式设置一次。
                #[cfg(unix)]
                if let Some(mode) = mode {
                    use cap_std::fs::{Permissions, PermissionsExt};
                    file.set_permissions(Permissions::from_mode(mode))
                        .map_err(|error| PlatformError::io("设置临时文件权限", &error))?;
                }
                file.sync_all()
                    .map_err(|error| PlatformError::io("同步临时文件", &error))?;
                return Ok(name);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_error = Some(error);
            }
            Err(error) => return Err(PlatformError::io("创建临时文件", &error)),
        }
    }
    #[cfg(not(unix))]
    let _ = mode;
    let error = last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AlreadyExists, "临时文件名重复")
    });
    Err(PlatformError::io("创建临时文件", &error))
}

/// 生成临时文件名后缀。
///
/// 不是密码学随机数：临时文件的安全性由 `O_EXCL` + 同目录 + 只在本次操作内可见保证，
/// 后缀只需要「大概率不撞」，撞了也会被 `create_new` 检出并重试。
fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or_default();
    format!("{:x}-{:x}-{:x}", std::process::id(), nanos, counter)
}

/// 读取备份文件的 POSIX 权限位。
#[cfg(unix)]
fn backup_unix_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions().mode() & 0o7777)
}

/// 非 unix 平台没有 POSIX 权限位。
#[cfg(not(unix))]
fn backup_unix_mode(_path: &Path) -> Option<u32> {
    None
}

/// fsync 目标所在目录，保证目录项本身也落盘。
///
/// 不能直接对 [`Dir`] 自身的描述符 fsync：cap-std 在 Linux 上用 `O_PATH` 打开目录，
/// 对 `O_PATH` 描述符调用 `fsync` 会返回 `EBADF`。这里以相对路径 `"."` 重新打开一个
/// 可读的目录描述符——仍然是相对当前能力句柄的操作，不引入任何绝对路径。
#[cfg(unix)]
fn sync_parent_dir(dir: &Dir) -> Result<(), PlatformError> {
    let handle = dir
        .open_with(".", OpenOptions::new().read(true))
        .map_err(|error| PlatformError::io("打开父目录", &error))?;
    handle
        .sync_all()
        .map_err(|error| PlatformError::io("同步父目录", &error))
}

/// Windows 不支持对目录句柄 fsync。
///
/// 这不是被忽略的耐久性缺口：崩溃后由 core 的 journal 判断操作处于哪个阶段，再结合
/// [`Receipt`] 重放或回滚，效果等价于 `ReplaceFileW` 的 journaled replace。
#[cfg(not(unix))]
fn sync_parent_dir(_dir: &Dir) -> Result<(), PlatformError> {
    Ok(())
}

/// fsync 一个用绝对路径给出的目录（备份目录）。
#[cfg(unix)]
fn sync_ambient_dir(path: &Path) -> Result<(), PlatformError> {
    let handle =
        std::fs::File::open(path).map_err(|error| PlatformError::io("打开备份目录", &error))?;
    handle
        .sync_all()
        .map_err(|error| PlatformError::io("同步备份目录", &error))
}

/// 同 [`sync_parent_dir`]：Windows 上是空操作。
#[cfg(not(unix))]
fn sync_ambient_dir(_path: &Path) -> Result<(), PlatformError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_suffix_differs_between_calls() {
        assert_ne!(unique_suffix(), unique_suffix());
    }

    #[test]
    fn fault_injection_is_disabled_by_default() {
        assert!(FaultInjection::default().is_disabled());
    }

    #[test]
    fn backup_path_is_deterministic() {
        let writer = SafeWriter::new("/tmp/envsync-backups");
        let operation = OperationId::generate();
        let resource = ResourceId::parse("shell/zsh/main").unwrap();
        let first = writer.backup_path_for(operation, &resource);
        assert_eq!(first, writer.backup_path_for(operation, &resource));
        assert!(first.ends_with("shell__zsh__main"));
    }
}
