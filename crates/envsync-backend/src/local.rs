//! 基于本地目录的后端实现。
//!
//! ## 磁盘布局
//!
//! ```text
//! root/
//!   format                          # 文本标记，打开时校验
//!   objects/ab/cdef….blob           # ab = 摘要 hex 前两位；扩展名是对象种类
//!   refs/<workspace-uuid>.cbor      # canonical CBOR 编码的 WorkspaceRef
//!   locks/<workspace-uuid>.lock     # per-workspace advisory lock
//! ```
//!
//! 对象文件名带种类扩展名，是为了让 [`LocalBackend::list_objects`] 能还原
//! [`ObjectId`]（`ObjectId` = 种类 + 摘要，而摘要本身不携带种类）。种类之间已经通过
//! 哈希域分隔，扩展名只是路径层的元数据，不参与摘要计算。
//!
//! ## 崩溃安全
//!
//! 所有写入都走「同目录临时文件 → `write_all` → `sync_all` → `rename` → 父目录 fsync」
//! 的序列。因此任何时刻被中断，目标路径要么是旧内容要么是新内容，不会出现半截文件；
//! 残留的临时文件不会被 [`LocalBackend::get_ref`] 或 [`LocalBackend::list_objects`]
//! 误认为有效数据。

use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use envsync_domain::{
    unix_millis_now, CborCodec, Digest32, ObjectId, ObjectKind, OperationId, WorkspaceId,
    WorkspaceRef,
};

use crate::{Backend, BackendDescriptor, BackendError};

/// 后端格式标记文件的完整内容。
///
/// 打开目录时逐字节比较；不一致一律拒绝，绝不静默升级或降级。
pub const FORMAT_MARKER: &str = "envsync-backend-format=1\n";

/// 格式标记文件名。
const FORMAT_FILE: &str = "format";
/// 对象目录名。
const OBJECTS_DIR: &str = "objects";
/// Ref 目录名。
const REFS_DIR: &str = "refs";
/// 锁目录名。
const LOCKS_DIR: &str = "locks";
/// 临时文件名前缀；该前缀保证临时文件永远无法被解析成合法对象或 Ref。
const TEMP_PREFIX: &str = ".tmp-";

/// 锁重试间隔。
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(5);
/// 锁重试次数上限，配合间隔构成有界等待（约 5 秒）。
const LOCK_MAX_ATTEMPTS: u32 = 1_000;
/// 超过该年龄的锁文件视为陈旧（持有者崩溃或被强杀），可被回收。
const LOCK_STALE_AFTER: Duration = Duration::from_secs(30);

/// 本地目录后端。
///
/// 适用于离线测试、单机使用和可移动介质。CAS 依赖 `O_CREAT|O_EXCL` 的原子性，在
/// 本地文件系统上成立；放在不保证该语义的网络文件系统上时，多写入者的强 CAS 不再成立。
#[derive(Debug, Clone)]
pub struct LocalBackend {
    /// 后端根目录的绝对路径。**绝不**出现在任何错误信息里。
    root: PathBuf,
}

impl LocalBackend {
    /// 打开（必要时初始化）一个本地后端目录。
    ///
    /// 目录不存在或为空时创建完整布局并写入格式标记；已存在格式标记时逐字节校验，
    /// 不匹配返回 [`BackendError::FormatMismatch`]。
    ///
    /// # 错误
    ///
    /// * [`BackendError::FormatMismatch`]：格式标记版本不对；
    /// * [`BackendError::Io`]：目录不可创建或不可写。
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, BackendError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|err| BackendError::io(".", err))?;
        for dir in [OBJECTS_DIR, REFS_DIR, LOCKS_DIR] {
            fs::create_dir_all(root.join(dir)).map_err(|err| BackendError::io(dir, err))?;
        }

        let marker = root.join(FORMAT_FILE);
        match fs::read(&marker) {
            Ok(bytes) => {
                if bytes != FORMAT_MARKER.as_bytes() {
                    return Err(BackendError::FormatMismatch {
                        expected: escape_marker(FORMAT_MARKER),
                        found: escape_marker(&String::from_utf8_lossy(&bytes)),
                    });
                }
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                write_atomic(&root, &marker, FORMAT_FILE, FORMAT_MARKER.as_bytes())?;
            }
            Err(err) => return Err(BackendError::io(FORMAT_FILE, err)),
        }

        Ok(LocalBackend { root })
    }

    /// 对象在后端中的相对路径，用于错误信息（不含绝对路径）。
    fn object_rel(id: ObjectId) -> String {
        let (shard, rest) = id.storage_segments();
        format!("{OBJECTS_DIR}/{shard}/{rest}.{}", id.kind.as_str())
    }

    /// 对象所在目录（分片目录）。
    fn object_dir(&self, id: ObjectId) -> PathBuf {
        let (shard, _) = id.storage_segments();
        self.root.join(OBJECTS_DIR).join(shard)
    }

    /// 对象文件路径。
    fn object_path(&self, id: ObjectId) -> PathBuf {
        let (_, rest) = id.storage_segments();
        self.object_dir(id)
            .join(format!("{rest}.{}", id.kind.as_str()))
    }

    /// Ref 在后端中的相对路径。
    fn ref_rel(workspace: WorkspaceId) -> String {
        format!("{REFS_DIR}/{workspace}.cbor")
    }

    /// Ref 文件路径。
    fn ref_path(&self, workspace: WorkspaceId) -> PathBuf {
        self.root.join(REFS_DIR).join(format!("{workspace}.cbor"))
    }

    /// 锁文件路径。
    fn lock_path(&self, workspace: WorkspaceId) -> PathBuf {
        self.root.join(LOCKS_DIR).join(format!("{workspace}.lock"))
    }

    /// 获取 per-workspace advisory lock。
    ///
    /// 用 `create_new(true)` 的原子性实现互斥：创建成功即持锁。竞争时有界重试；发现
    /// 陈旧锁（超过 [`LOCK_STALE_AFTER`] 未更新，说明持有者已崩溃）则回收后重试。
    fn acquire_lock(&self, workspace: WorkspaceId) -> Result<LockGuard, BackendError> {
        let path = self.lock_path(workspace);
        let rel = format!("{LOCKS_DIR}/{workspace}.lock");
        for _ in 0..LOCK_MAX_ATTEMPTS {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    // 持有者信息仅供人工诊断，写失败不影响锁语义。
                    let _ = writeln!(file, "pid={} at={}", std::process::id(), unix_millis_now());
                    let _ = file.sync_all();
                    return Ok(LockGuard { path });
                }
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                    if !reap_stale_lock(&path) {
                        std::thread::sleep(LOCK_RETRY_INTERVAL);
                    }
                }
                Err(err) => return Err(BackendError::io(rel, err)),
            }
        }
        Err(BackendError::Locked {
            workspace,
            detail: format!(
                "等待 {} 次仍未获得锁，请确认没有其他进程正在发布",
                LOCK_MAX_ATTEMPTS
            ),
        })
    }

    /// 读取并校验 Ref 文件。
    ///
    /// 只读取该工作区自己的文件，不列目录。
    fn read_ref(&self, workspace: WorkspaceId) -> Result<WorkspaceRef, BackendError> {
        let path = self.ref_path(workspace);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == ErrorKind::NotFound => {
                return Err(BackendError::RefNotFound(workspace))
            }
            Err(err) => return Err(BackendError::io(Self::ref_rel(workspace), err)),
        };
        // canonical 解码顺带完成结构校验（含 revision/head 一致性）。
        let reference = WorkspaceRef::from_canonical_slice(&bytes)?;
        if reference.workspace != workspace {
            return Err(BackendError::InvalidRef {
                workspace,
                detail: format!("文件记录的工作区是 {}，与请求不符", reference.workspace),
            });
        }
        Ok(reference)
    }
}

impl Backend for LocalBackend {
    fn describe(&self) -> BackendDescriptor {
        BackendDescriptor {
            kind: "local",
            supports_strong_cas: true,
        }
    }

    fn get_ref(&self, workspace: WorkspaceId) -> Result<WorkspaceRef, BackendError> {
        self.read_ref(workspace)
    }

    fn compare_and_swap_ref(
        &self,
        workspace: WorkspaceId,
        expected_revision: u64,
        next: &WorkspaceRef,
    ) -> Result<(), BackendError> {
        // 先做不依赖后端状态的校验，避免为必然失败的请求去抢锁。
        next.validate().map_err(|err| BackendError::InvalidRef {
            workspace,
            detail: err.to_string(),
        })?;
        if next.workspace != workspace {
            return Err(BackendError::InvalidRef {
                workspace,
                detail: format!("待写入 Ref 属于工作区 {}", next.workspace),
            });
        }

        let _guard = self.acquire_lock(workspace)?;

        // 锁内重读 revision：这是 CAS 的判定依据，锁外读到的值可能已经过期。
        let current = match self.read_ref(workspace) {
            Ok(reference) => Some(reference),
            Err(BackendError::RefNotFound(_)) => None,
            Err(err) => return Err(err),
        };
        let observed = current.as_ref().map_or(0, |reference| reference.revision);
        if observed != expected_revision {
            return Err(BackendError::CasConflict {
                expected: expected_revision,
                observed,
            });
        }

        // Ref 缺失时以「revision 0 的初始引用」作为基准，从而同样要求严格递增。
        let base = current.unwrap_or_else(|| WorkspaceRef::initial(workspace));
        base.check_successor(next)
            .map_err(|err| BackendError::InvalidRef {
                workspace,
                detail: err.to_string(),
            })?;

        let rel = Self::ref_rel(workspace);
        write_atomic(
            &self.root.join(REFS_DIR),
            &self.ref_path(workspace),
            &rel,
            &next.to_canonical_vec(),
        )?;
        tracing::debug!(
            %workspace,
            from = observed,
            to = next.revision,
            "已发布新的工作区 Ref"
        );
        Ok(())
    }

    fn get_object(&self, id: ObjectId) -> Result<Vec<u8>, BackendError> {
        let path = self.object_path(id);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == ErrorKind::NotFound => {
                return Err(BackendError::ObjectNotFound(id))
            }
            Err(err) => return Err(BackendError::io(Self::object_rel(id), err)),
        };
        // 重算摘要：损坏的对象绝不返回内容。
        if !id.verifies(&bytes) {
            return Err(BackendError::Corruption {
                id,
                detail: format!("读出的 {} 字节重算摘要与对象标识不一致", bytes.len()),
            });
        }
        Ok(bytes)
    }

    fn put_object(&self, id: ObjectId, bytes: &[u8]) -> Result<(), BackendError> {
        if !id.verifies(bytes) {
            return Err(BackendError::Corruption {
                id,
                detail: "待写入内容的摘要与对象标识不一致".to_owned(),
            });
        }

        let path = self.object_path(id);
        match fs::read(&path) {
            Ok(existing) => {
                return if existing == bytes {
                    // 幂等：同一标识重复写入相同内容直接成功。
                    Ok(())
                } else {
                    // 同一标识出现两种内容说明内容寻址已被破坏，绝不覆盖。
                    Err(BackendError::Corruption {
                        id,
                        detail: "后端已存在同标识但内容不同的对象".to_owned(),
                    })
                };
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(BackendError::io(Self::object_rel(id), err)),
        }

        let dir = self.object_dir(id);
        let (shard, _) = id.storage_segments();
        fs::create_dir_all(&dir)
            .map_err(|err| BackendError::io(format!("objects/{shard}"), err))?;
        write_atomic(&dir, &path, &Self::object_rel(id), bytes)
    }

    fn has_object(&self, id: ObjectId) -> Result<bool, BackendError> {
        match fs::metadata(self.object_path(id)) {
            Ok(meta) => Ok(meta.is_file()),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
            Err(err) => Err(BackendError::io(Self::object_rel(id), err)),
        }
    }

    fn list_objects(&self, prefix: &str) -> Result<Vec<ObjectId>, BackendError> {
        validate_prefix(prefix)?;
        let shard_prefix = &prefix[..prefix.len().min(2)];

        let mut found = Vec::new();
        let objects = self.root.join(OBJECTS_DIR);
        let shards = match fs::read_dir(&objects) {
            Ok(entries) => entries,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(found),
            Err(err) => return Err(BackendError::io(OBJECTS_DIR, err)),
        };

        for shard in shards {
            let shard = shard.map_err(|err| BackendError::io(OBJECTS_DIR, err))?;
            let Some(shard_name) = shard.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            // 分片目录名必须恰好是两位小写十六进制，其余一律忽略。
            if shard_name.len() != 2 || !is_lower_hex(&shard_name) {
                continue;
            }
            if !shard_name.starts_with(shard_prefix) {
                continue;
            }

            let files = match fs::read_dir(shard.path()) {
                Ok(entries) => entries,
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(BackendError::io(format!("{OBJECTS_DIR}/{shard_name}"), err))
                }
            };
            for file in files {
                let file = file
                    .map_err(|err| BackendError::io(format!("{OBJECTS_DIR}/{shard_name}"), err))?;
                let Some(name) = file.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                // 临时文件与任何不符合 `<摘要余段>.<种类>` 形式的条目都被跳过。
                let Some(id) = parse_object_name(&shard_name, &name) else {
                    continue;
                };
                if id.hex().starts_with(prefix) {
                    found.push(id);
                }
            }
        }

        // 目录遍历顺序由文件系统决定，这里排序以获得确定性输出。
        found.sort();
        Ok(found)
    }
}

/// 工作区锁的 RAII 守卫：离开作用域（含 panic 展开）时删除锁文件。
struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.path) {
            // 不记录绝对路径，只记录错误种类；锁最终会被陈旧检测回收。
            tracing::warn!(kind = ?err.kind(), "释放工作区锁失败");
        }
    }
}

/// 回收陈旧锁文件；成功回收返回 `true`。
fn reap_stale_lock(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        // 锁刚好被持有者释放，直接重试即可。
        return true;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    let Ok(age) = SystemTime::now().duration_since(modified) else {
        // 时钟回拨：宁可继续等待，也不误删活跃锁。
        return false;
    };
    if age < LOCK_STALE_AFTER {
        return false;
    }
    tracing::warn!(age_secs = age.as_secs(), "回收陈旧的工作区锁");
    fs::remove_file(path).is_ok()
}

/// 原子写入：同目录临时文件 → `sync_all` → `rename` → 父目录 fsync。
///
/// `rel` 是相对于后端根的路径，仅用于错误信息。失败时清理临时文件。
fn write_atomic(dir: &Path, target: &Path, rel: &str, bytes: &[u8]) -> Result<(), BackendError> {
    // 临时文件名带随机 UUID，保证同目录内多线程/多进程互不干扰。
    let temp = dir.join(format!(
        "{TEMP_PREFIX}{}",
        OperationId::generate().to_filename()
    ));
    match write_atomic_io(&temp, target, dir, bytes) {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = fs::remove_file(&temp);
            Err(BackendError::io(rel, err))
        }
    }
}

/// [`write_atomic`] 的裸 I/O 部分。
fn write_atomic_io(temp: &Path, target: &Path, dir: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = File::create(temp)?;
    file.write_all(bytes)?;
    // 先落盘数据，再 rename：否则崩溃后可能得到一个名字正确但内容为空的文件。
    file.sync_all()?;
    drop(file);
    fs::rename(temp, target)?;
    // 最后 fsync 父目录，让 rename 这条目录项本身也持久化。
    sync_dir(dir)
}

/// fsync 目录，使其中的 rename 持久化。
#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Windows 不允许以普通方式打开目录句柄并 fsync，只能跳过。
///
/// 代价是崩溃后 rename 可能丢失，但不会出现半截文件：NTFS 的 rename 本身是原子的，
/// 目标路径要么是旧内容要么是新内容。
#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// 校验 `list_objects` 的前缀。
pub(crate) fn validate_prefix(prefix: &str) -> Result<(), BackendError> {
    let reject = |detail: &str| BackendError::InvalidPrefix {
        prefix: prefix.to_owned(),
        detail: detail.to_owned(),
    };
    if prefix.len() > 64 {
        return Err(reject("前缀长度超过摘要的 64 个十六进制字符"));
    }
    for ch in prefix.chars() {
        if matches!(ch, '/' | '\\' | '.') {
            return Err(reject("前缀不能包含路径分隔符或 `.` / `..` 段"));
        }
        if !matches!(ch, '0'..='9' | 'a'..='f') {
            return Err(reject("前缀只能包含小写十六进制字符"));
        }
    }
    Ok(())
}

/// 判断字符串是否全为小写十六进制字符。
pub(crate) fn is_lower_hex(text: &str) -> bool {
    !text.is_empty() && text.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f'))
}

/// 由分片目录名与文件名还原 [`ObjectId`]；不合法返回 `None`。
pub(crate) fn parse_object_name(shard: &str, name: &str) -> Option<ObjectId> {
    let (rest, kind) = name.rsplit_once('.')?;
    let kind = ObjectKind::parse(kind)?;
    let hex = format!("{shard}{rest}");
    let digest = hex.parse::<Digest32>().ok()?;
    Some(ObjectId { kind, digest })
}

/// 把格式标记转成可安全展示的单行文本。
pub(crate) fn escape_marker(text: &str) -> String {
    text.chars().take(64).flat_map(char::escape_debug).collect()
}
