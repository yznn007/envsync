//! 「上次成功读到的后端 Ref」的本地留存。
//!
//! 后端不可达时，`status` 与 `doctor` 需要一个可信的**降级答案**：不是猜、也不是
//! 沉默地报 `clean`，而是「我最后一次联系上远端时看到的是这个」。这份事实必须持久化
//! 在本地，因为它恰恰要在远端读不到的时候被用到。
//!
//! # 为什么是一个独立文件，而不是 `DraftStore` 的 meta 表
//!
//! 最自然的位置是草稿库的 `draft_meta` 表（它已经存着 `head_draft`）。但
//! [`envsync_storage::DraftStore`] 只暴露 `set_head_draft` / `head_draft` 这一对**专用**
//! 方法，没有通用的 `set_meta` / `meta` 接口；用它来存别的键需要改 `envsync-storage`，
//! 而本次改动的边界不含那个 crate。
//!
//! 于是退而求其次：`<state_dir>/last-known-ref.cbor`，一个文件、一条记录。代价是多一个
//! 文件；收益是不必为一条纯诊断信息去动已发布的存储 schema。等 `DraftStore` 有了通用
//! meta API，这里可以整体搬过去而不影响任何调用方——本模块对外只暴露
//! [`LastKnownRefStore`] 的两个方法。
//!
//! # 三条约束
//!
//! * **它不是权威。** 任何会改动远端的操作（`capture`、`plan`、`sync`、`fetch`）都必须
//!   走真实的 `get_ref`；这份缓存只用于「读不到时如实报告上次看到了什么」。基于缓存的
//!   revision 去做 CAS 会让反回滚保护形同虚设。
//! * **写入是原子的。** 临时文件 + `rename`，与 [`envsync_platform::writer`] 的理由相同：
//!   崩溃时要么读到旧记录，要么读到新记录，不会读到半条。
//! * **读失败不致命。** 文件缺失、损坏、被外部工具改坏，一律当作「没有上次已知状态」，
//!   而不是让 `status` 失败——一个诊断用的缓存不该有能力阻塞诊断本身。

use std::path::{Path, PathBuf};

use envsync_domain::cbor::Value;
use envsync_domain::{CborCodec, CborError, WorkspaceId, WorkspaceRef};

use crate::error::{CoreError, CoreResult};

/// 记录文件名（相对 `state_dir`）。
pub const LAST_KNOWN_REF_FILE: &str = "last-known-ref.cbor";

/// 本记录的格式版本。未知版本一律拒绝解码，绝不按别的版本猜测语义。
const LAST_KNOWN_FORMAT_VERSION: u32 = 1;

/// 一条「上次成功读到的后端 Ref」记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastKnownRef {
    /// 格式版本。
    pub format_version: u32,
    /// 当时读到的完整 Ref（含工作区、revision 与头快照）。
    pub reference: WorkspaceRef,
    /// 读到它的本机时刻（Unix 毫秒）。
    ///
    /// 这是**本机时钟**下「我最后一次联系上远端」的时间，不是远端的发布时间：后者需要
    /// 读快照才知道，而降级路径恰恰读不到远端。
    pub observed_at_unix_ms: u64,
}

impl CborCodec for LastKnownRef {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Uint(self.format_version as u64),
            self.reference.to_value(),
            Value::Uint(self.observed_at_unix_ms),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        if items.len() != 3 {
            return Err(CborError::ArityMismatch);
        }
        let format_version = u32::from_value(&items[0])?;
        if format_version != LAST_KNOWN_FORMAT_VERSION {
            return Err(CborError::UnsupportedFormatVersion {
                found: format_version,
                supported: LAST_KNOWN_FORMAT_VERSION,
            });
        }
        Ok(LastKnownRef {
            format_version,
            reference: WorkspaceRef::from_value(&items[1])?,
            observed_at_unix_ms: u64::from_value(&items[2])?,
        })
    }
}

/// 「上次已知后端 Ref」的本地存储。
#[derive(Debug, Clone)]
pub struct LastKnownRefStore {
    path: PathBuf,
}

impl LastKnownRefStore {
    /// 以状态目录构造。文件路径固定为 `<state_dir>/last-known-ref.cbor`。
    pub fn new(state_dir: &Path) -> Self {
        LastKnownRefStore {
            path: state_dir.join(LAST_KNOWN_REF_FILE),
        }
    }

    /// 记录文件路径。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 记下一次**成功**读到的后端 Ref。
    ///
    /// 每次真实读到远端 Ref 时调用，因此缓存总是与最后一次成功通信同步。写入采用
    /// 「同目录临时文件 + rename」，中途崩溃不会留下半条记录。
    pub fn record(&self, reference: &WorkspaceRef, observed_at_unix_ms: u64) -> CoreResult<()> {
        let record = LastKnownRef {
            format_version: LAST_KNOWN_FORMAT_VERSION,
            reference: reference.clone(),
            observed_at_unix_ms,
        };
        let bytes = record.to_canonical_vec();

        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)
            .map_err(|error| envsync_platform::PlatformError::io("创建状态目录", &error))?;

        // 临时文件与目标同目录：跨目录 rename 可能跨文件系统而退化成 copy + delete，
        // 失去原子性。
        let temporary = self.path.with_extension("cbor.tmp");
        std::fs::write(&temporary, &bytes).map_err(|error| {
            envsync_platform::PlatformError::io("写入上次已知 Ref 的临时文件", &error)
        })?;
        std::fs::rename(&temporary, &self.path).map_err(|error| {
            let _ = std::fs::remove_file(&temporary);
            envsync_platform::PlatformError::io("提交上次已知 Ref", &error)
        })?;
        Ok(())
    }

    /// 读取该工作区上次已知的后端 Ref。
    ///
    /// 返回 `None` 的三种情况一视同仁：从未记录过、文件损坏、记录属于**另一个**工作区
    /// （同一个状态目录被复用到别的工作区上）。它们都意味着「没有可信的上次已知状态」，
    /// 而降级路径对这三者的处理完全一样。损坏与串号会各留一条 `tracing` 警告。
    pub fn load(&self, workspace: WorkspaceId) -> Option<LastKnownRef> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "读取上次已知 Ref 失败，按「没有上次已知状态」处理"
                );
                return None;
            }
        };
        let record = match LastKnownRef::from_canonical_slice(&bytes) {
            Ok(record) => record,
            Err(error) => {
                tracing::warn!(%error, "上次已知 Ref 记录已损坏，按「没有上次已知状态」处理");
                return None;
            }
        };
        if record.reference.workspace != workspace {
            tracing::warn!("上次已知 Ref 属于另一个工作区，已忽略");
            return None;
        }
        Some(record)
    }
}

/// 判断一个错误是否属于「后端暂时联系不上」，因而可以降级到本地上次已知状态。
///
/// **只有 I/O 类失败算数**。这条判据是本次降级的安全边界：
///
/// | 错误 | 是否降级 | 理由 |
/// |---|---|---|
/// | [`envsync_backend::BackendError::Io`] | 是 | 网络不通、远端目录被删、DNS 失败——远端**说不定**一切正常，只是我们够不着 |
/// | `Corruption` / `InvalidRef` / `FormatMismatch` / `Codec` | 否 | 远端够得着，但内容坏了。这是需要人立刻知道的事故，用一份旧缓存把它盖住是最糟的处理 |
/// | `CasConflict` / `RefNotFound` / `ObjectNotFound` | 否 | 这些是**成功的**读取结果，本来就有各自的语义 |
/// | `Locked` | 否 | 后端够得着，只是被占用；重试即可，不该让用户以为自己离线了 |
pub fn is_backend_unreachable(error: &CoreError) -> bool {
    matches!(
        error,
        CoreError::Backend(envsync_backend::BackendError::Io { .. })
    )
}

/// 判断一个后端层错误是否属于「后端暂时联系不上」。
///
/// 与 [`is_backend_unreachable`] 同一条判据，只是作用在尚未被包进 [`CoreError`] 的
/// [`envsync_backend::BackendError`] 上（打开后端时用得到）。
pub fn is_backend_error_unreachable(error: &envsync_backend::BackendError) -> bool {
    matches!(error, envsync_backend::BackendError::Io { .. })
}

#[cfg(test)]
mod tests {
    use super::*;
    use envsync_domain::SnapshotId;

    fn store() -> (tempfile::TempDir, LastKnownRefStore) {
        let dir = tempfile::tempdir().expect("创建临时状态目录");
        let store = LastKnownRefStore::new(dir.path());
        (dir, store)
    }

    #[test]
    fn round_trips_through_canonical_cbor() {
        let (_dir, store) = store();
        let workspace = WorkspaceId::generate();
        let reference = WorkspaceRef::initial(workspace).advance(SnapshotId::of(b"snapshot"));

        assert_eq!(store.load(workspace), None, "从未记录过时返回 None");
        store.record(&reference, 1_700_000_000_000).expect("可写入");

        let loaded = store.load(workspace).expect("刚写过一定读得到");
        assert_eq!(loaded.reference, reference);
        assert_eq!(loaded.observed_at_unix_ms, 1_700_000_000_000);
        // canonical 编码是确定的：同一条记录反复编码逐字节相同。
        assert_eq!(loaded.to_canonical_vec(), loaded.to_canonical_vec());
    }

    #[test]
    fn ignores_records_belonging_to_another_workspace() {
        let (_dir, store) = store();
        let mine = WorkspaceId::generate();
        let other = WorkspaceId::generate();
        store
            .record(&WorkspaceRef::initial(other), 1)
            .expect("可写入");
        assert_eq!(store.load(mine), None);
    }

    #[test]
    fn corrupted_record_is_treated_as_absent_instead_of_failing() {
        let (_dir, store) = store();
        let workspace = WorkspaceId::generate();
        std::fs::write(store.path(), b"not canonical cbor at all").expect("写入垃圾");
        assert_eq!(store.load(workspace), None);
    }

    #[test]
    fn only_io_failures_are_treated_as_unreachable() {
        use envsync_backend::BackendError;

        assert!(is_backend_unreachable(&CoreError::Backend(
            BackendError::Io {
                context: "git fetch".to_owned(),
                source: std::io::Error::other("connection refused"),
            }
        )));
        assert!(!is_backend_unreachable(&CoreError::Backend(
            BackendError::FormatMismatch {
                expected: "a".to_owned(),
                found: "b".to_owned(),
            }
        )));
        assert!(!is_backend_unreachable(&CoreError::Backend(
            BackendError::CasConflict {
                expected: 1,
                observed: 2,
            }
        )));
        assert!(!is_backend_unreachable(&CoreError::Invariant(
            "boom".to_owned()
        )));
    }
}
