//! 后端联系不上时的占位实现。
//!
//! # 为什么需要它
//!
//! Git 后端在 [`GitBackend::open`](envsync_backend::GitBackend::open) 里就会去 fetch
//! 一次远端：远端不可达时，**打开服务**这一步就失败了。于是本机上一切都还完好——
//! journal 在、草稿库在、cache clone 在——用户却连一句 `envsync status` 都跑不出来，
//! 只能得到一条 `io` 诊断和退出码 1。
//!
//! [`UnreachableBackend`] 把「够不着远端」从**打开失败**降级成**每次调用失败**：服务照常
//! 打开，本地状态照常可读，只有真正需要远端的那一步才报错。这让
//! [`EnvSyncService::status`](crate::EnvSyncService::status) 与
//! [`doctor`](crate::EnvSyncService::doctor) 得以按本地上次已知状态如实作答。
//!
//! # 它绝不假装成功
//!
//! 每一个方法都返回创建时记下的那条 [`BackendError::Io`]，**没有任何一条**返回
//! 「空」「无」或默认值。区别在于失败发生的**位置**，不在于失败与否：
//!
//! * `get_ref` 报错 → `status` 显式降级并标注不可达；
//! * `put_object` / `compare_and_swap_ref` 报错 → `sync` 照旧失败，绝不会有人以为
//!   自己发布出去了。
//!
//! 如果这里有任何一个方法返回 `Ok`，「不可达」就会变成「一切正常」——那正是本次改动要
//! 消灭的失败模式。

use envsync_backend::{Backend, BackendDescriptor, BackendError};
use envsync_domain::{ObjectId, WorkspaceId, WorkspaceRef};

/// 联系不上的后端：所有操作都以创建时记录的 I/O 失败告终。
#[derive(Debug)]
pub struct UnreachableBackend {
    /// 真实后端的种类短名（例如 `git`），保持诊断输出与在线时一致。
    kind: &'static str,
    /// 打开真实后端时失败的操作描述，不含绝对路径与凭据。
    context: String,
    /// 不含路径的失败原因。
    detail: String,
}

impl UnreachableBackend {
    /// 由「打开真实后端时的失败」构造。
    ///
    /// `kind` 取真实后端的种类短名：`status` 的输出里 `backend_kind` 不应该因为一次
    /// 网络故障就变成别的东西。
    pub fn new(kind: &'static str, error: &BackendError) -> Self {
        let (context, detail) = match error {
            BackendError::Io { context, source } => (context.clone(), source.to_string()),
            other => ("打开后端".to_owned(), other.to_string()),
        };
        UnreachableBackend {
            kind,
            context,
            detail,
        }
    }

    /// 人类可读的失败说明，供 `doctor` 的 finding 使用。
    pub fn detail(&self) -> String {
        format!("{}：{}", self.context, self.detail)
    }

    /// 复制一份失败，交给每一个后端方法返回。
    fn failure(&self) -> BackendError {
        BackendError::Io {
            context: self.context.clone(),
            source: std::io::Error::other(self.detail.clone()),
        }
    }
}

impl Backend for UnreachableBackend {
    fn describe(&self) -> BackendDescriptor {
        BackendDescriptor {
            kind: self.kind,
            // 联系不上时不可能提供任何 CAS 保证；照实说，别让上层以为可以安全发布。
            supports_strong_cas: false,
        }
    }

    fn get_ref(&self, _workspace: WorkspaceId) -> Result<WorkspaceRef, BackendError> {
        Err(self.failure())
    }

    fn compare_and_swap_ref(
        &self,
        _workspace: WorkspaceId,
        _expected_revision: u64,
        _next: &WorkspaceRef,
    ) -> Result<(), BackendError> {
        Err(self.failure())
    }

    fn get_object(&self, _id: ObjectId) -> Result<Vec<u8>, BackendError> {
        Err(self.failure())
    }

    fn put_object(&self, _id: ObjectId, _bytes: &[u8]) -> Result<(), BackendError> {
        Err(self.failure())
    }

    fn has_object(&self, _id: ObjectId) -> Result<bool, BackendError> {
        Err(self.failure())
    }

    fn list_objects(&self, _prefix: &str) -> Result<Vec<ObjectId>, BackendError> {
        Err(self.failure())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unreachable() -> UnreachableBackend {
        UnreachableBackend::new(
            "git",
            &BackendError::Io {
                context: "git fetch（host=example.invalid, branch=envsync）".to_owned(),
                source: std::io::Error::other("connection refused"),
            },
        )
    }

    #[test]
    fn every_operation_fails_with_io() {
        let backend = unreachable();
        let workspace = WorkspaceId::generate();
        let object = ObjectId::for_bytes(envsync_domain::ObjectKind::Blob, b"x");

        assert_eq!(backend.describe().kind, "git");
        assert!(!backend.describe().supports_strong_cas);
        for code in [
            backend.get_ref(workspace).unwrap_err().code(),
            backend.get_object(object).unwrap_err().code(),
            backend.put_object(object, b"x").unwrap_err().code(),
            backend.has_object(object).unwrap_err().code(),
            backend.list_objects("00").unwrap_err().code(),
            backend
                .compare_and_swap_ref(workspace, 0, &WorkspaceRef::initial(workspace))
                .unwrap_err()
                .code(),
        ] {
            assert_eq!(
                code, "backend.io",
                "每个方法都必须以 I/O 失败告终，绝不假装成功"
            );
        }
    }

    #[test]
    fn detail_keeps_the_original_context_without_paths() {
        let detail = unreachable().detail();
        assert!(detail.contains("git fetch"), "{detail}");
        assert!(detail.contains("connection refused"), "{detail}");
    }
}
