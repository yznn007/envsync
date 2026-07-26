//! 核心层依赖的端口（port）抽象。
//!
//! [`crate::apply::ApplyEngine`] 只依赖这些 trait，不直接触碰文件系统和时钟。这样
//! 事务顺序的测试可以用内存 fake 精确注入「preflight 失败」「第 3 个动作写入失败」
//! 「verify 不通过」「回滚也失败」等场景，而不必真的制造 I/O 错误。
//!
//! 生产实现在 [`platform`] 子模块里，用 `envsync-platform` 的能力约束读写器包装。

use std::path::PathBuf;

use envsync_domain::{
    Action, ActionTarget, Digest32, Observation, OperationId, ResourceId, ResourcePolicy,
    RollbackCapability,
};

use crate::error::{CoreError, CoreResult};

/// 时钟端口。测试注入固定时钟以获得确定性输出。
pub trait Clock: Send + Sync {
    /// 当前 Unix 毫秒时间戳。
    fn now_unix_ms(&self) -> u64;
}

/// 系统时钟。
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_ms(&self) -> u64 {
        envsync_domain::unix_millis_now()
    }
}

/// 固定时钟，仅用于测试与可复现构建。
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_unix_ms(&self) -> u64 {
        self.0
    }
}

/// 观察端口：把「某个资源在本机当前是什么样子」变成领域层的 [`Observation`]。
pub trait Observer: Send + Sync {
    /// 观察单个资源。
    ///
    /// 该方法**不返回错误**：一切失败都会被映射成 `ObservedState` 的某个非 `Present`
    /// 变体，这样「读不出来」永远不会被上层误当成「不存在」。
    fn observe(
        &self,
        resource: &ResourceId,
        target: &ActionTarget,
        policy: &ResourcePolicy,
    ) -> Observation;

    /// 读取目标文件的原始字节。
    ///
    /// 与 [`Observer::observe`] 不同，这里会返回错误：调用方（capture、渲染）确实
    /// 需要区分「读不到」和「空文件」。
    fn read(&self, target: &ActionTarget, policy: &ResourcePolicy) -> CoreResult<Vec<u8>>;

    /// 目标当前内容摘要；不存在时返回 `None`。
    fn current_digest(
        &self,
        target: &ActionTarget,
        policy: &ResourcePolicy,
    ) -> CoreResult<Option<Digest32>>;
}

/// 一次动作应用后的回滚凭据。
///
/// 与 `envsync_platform::Receipt` 结构一致，但属于核心层，方便 fake 实现构造。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionReceipt {
    /// 关联资源。
    pub resource: ResourceId,
    /// 备份文件路径；目标原本不存在时为 `None`。
    pub backup_path: Option<PathBuf>,
    /// 应用前的原内容摘要；目标原本不存在时为 `None`。
    pub original_digest: Option<Digest32>,
    /// 应用后的内容摘要；删除动作为 `None`。
    pub applied_digest: Option<Digest32>,
    /// 回滚能力。
    pub guarantee: RollbackCapability,
    /// 本次写入新创建的中间目录（相对授权根的路径）。
    ///
    /// 它**不会**被写进 journal：`envsync_storage::Receipt` 的字段集合属于已发布的
    /// 存储 schema，为一条纯诊断信息升一次 schema 版本并不划算。因此从 journal 读回
    /// 的收据这一项恒为空，留痕由写入与回滚时的 `tracing` 记录承担——它本来也只用于
    /// 人工排查「这些目录是谁建的」，不参与任何判定。
    pub created_dirs: Vec<String>,
}

/// 文件变更端口：执行单个动作、验证结果、回滚。
pub trait FileMutator: Send + Sync {
    /// 预检单个动作：确认目标可解析、未越权、且当前摘要仍等于 `expected_before`。
    ///
    /// 预检**绝不**修改目标文件。
    fn preflight(&self, action: &Action) -> CoreResult<()>;

    /// 应用单个动作。`content` 是待写入的完整文件内容；删除动作为 `None`。
    fn apply(
        &self,
        operation: OperationId,
        action: &Action,
        content: Option<&[u8]>,
    ) -> CoreResult<ActionReceipt>;

    /// 按动作的 verify 规则重新观察并校验。
    fn verify(&self, action: &Action) -> CoreResult<()>;

    /// 依据收据回滚单个动作。
    fn rollback(&self, action: &Action, receipt: &ActionReceipt) -> CoreResult<()>;

    /// 清理某次操作在目标目录留下的暂存临时文件，返回清理数量。
    ///
    /// 崩溃恢复在「尚未发布」的操作上调用它。默认实现什么也不做，方便内存 fake。
    fn cleanup_staged(&self, _operation: OperationId, _action: &Action) -> CoreResult<usize> {
        Ok(0)
    }
}

/// 基于 `envsync-platform` 的生产实现。
pub mod platform {
    use super::*;

    use envsync_domain::{ObservedState, VerifyRule};
    use envsync_platform::{
        DeleteRequest, FileReader, RelativeTarget, RootRegistry, SafeWriter, WriteRequest,
    };

    /// 用授权根注册表实现的观察器。
    pub struct PlatformObserver {
        roots: std::sync::Arc<RootRegistry>,
        clock: std::sync::Arc<dyn Clock>,
    }

    impl PlatformObserver {
        /// 构造观察器。
        pub fn new(roots: std::sync::Arc<RootRegistry>, clock: std::sync::Arc<dyn Clock>) -> Self {
            PlatformObserver { roots, clock }
        }
    }

    impl Observer for PlatformObserver {
        fn observe(
            &self,
            resource: &ResourceId,
            target: &ActionTarget,
            policy: &ResourcePolicy,
        ) -> Observation {
            let now = self.clock.now_unix_ms();
            let root = match self.roots.get(&target.root) {
                Ok(root) => root,
                // 授权根未注册属于配置问题，不是「资源不存在」。
                Err(err) => {
                    return Observation::new(
                        resource.clone(),
                        ObservedState::Unsupported {
                            reason: err.to_string(),
                        },
                        now,
                    )
                }
            };
            let relative = match RelativeTarget::from_action_target(target) {
                Ok(relative) => relative,
                Err(err) => {
                    return Observation::new(
                        resource.clone(),
                        ObservedState::Excluded {
                            reason: err.to_string(),
                        },
                        now,
                    )
                }
            };
            FileReader::observe(root, &relative, resource, policy, now)
        }

        fn read(&self, target: &ActionTarget, policy: &ResourcePolicy) -> CoreResult<Vec<u8>> {
            let root = self.roots.get(&target.root)?;
            let relative = RelativeTarget::from_action_target(target)?;
            Ok(FileReader::read_bytes(root, &relative, policy)?.bytes)
        }

        fn current_digest(
            &self,
            target: &ActionTarget,
            policy: &ResourcePolicy,
        ) -> CoreResult<Option<Digest32>> {
            let root = self.roots.get(&target.root)?;
            let relative = RelativeTarget::from_action_target(target)?;
            // 中间目录不存在 ⇒ 目标不存在。这里**不**用 `resolve_for_create`：只是想知道
            // 一个摘要，不该顺手在用户磁盘上造目录。
            let resolved = match root.resolve(&relative) {
                Ok(resolved) => resolved,
                Err(error) if error.is_not_found() => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            Ok(FileReader::current_digest(&resolved, policy.max_bytes)?)
        }
    }

    /// 用安全写入器实现的文件变更器。
    pub struct PlatformMutator {
        roots: std::sync::Arc<RootRegistry>,
        writer: SafeWriter,
    }

    impl PlatformMutator {
        /// 构造变更器。
        pub fn new(roots: std::sync::Arc<RootRegistry>, writer: SafeWriter) -> Self {
            PlatformMutator { roots, writer }
        }

        /// 底层安全写入器（供恢复流程直接使用）。
        pub fn writer(&self) -> &SafeWriter {
            &self.writer
        }

        fn resolve<'a>(
            &'a self,
            action: &Action,
        ) -> CoreResult<(&'a envsync_platform::AuthorizedRoot, RelativeTarget)> {
            let root = self.roots.get(&action.target.root)?;
            let relative = RelativeTarget::from_action_target(&action.target)?;
            Ok((root, relative))
        }
    }

    impl FileMutator for PlatformMutator {
        fn preflight(&self, action: &Action) -> CoreResult<()> {
            let (root, relative) = self.resolve(action)?;
            // 只解析路径 + 读取当前摘要，**绝不写入**，因此这里刻意用 `resolve` 而不是
            // `resolve_for_create`：预检不该有任何副作用。中间目录不存在意味着目标不存在，
            // 这对「即将创建它」的动作来说恰恰是期望中的状态，真正的建目录发生在
            // `apply` 里。
            let current = match root.resolve(&relative) {
                Ok(resolved) => {
                    FileReader::current_digest(&resolved, ResourcePolicy::DEFAULT_MAX_BYTES)?
                }
                Err(error) if error.is_not_found() => None,
                Err(error) => return Err(error.into()),
            };
            if current != action.expected_before {
                return Err(CoreError::Platform(
                    envsync_platform::PlatformError::StaleObservation {
                        expected: action.expected_before,
                        actual: current,
                    },
                ));
            }
            Ok(())
        }

        fn apply(
            &self,
            operation: OperationId,
            action: &Action,
            content: Option<&[u8]>,
        ) -> CoreResult<ActionReceipt> {
            let (root, relative) = self.resolve(action)?;
            let receipt = match content {
                Some(bytes) => self.writer.apply_write(&WriteRequest {
                    operation,
                    resource: &action.resource,
                    root,
                    target: &relative,
                    content: bytes,
                    expected_before: action.expected_before,
                    unix_mode: action.unix_mode,
                    secret: action.secret,
                })?,
                None => self.writer.apply_delete(&DeleteRequest {
                    operation,
                    resource: &action.resource,
                    root,
                    target: &relative,
                    expected_before: action.expected_before,
                })?,
            };
            Ok(ActionReceipt {
                resource: receipt.resource,
                backup_path: receipt.backup_path,
                original_digest: receipt.original_digest,
                applied_digest: receipt.applied_digest,
                guarantee: receipt.guarantee,
                created_dirs: receipt.created_dirs,
            })
        }

        fn verify(&self, action: &Action) -> CoreResult<()> {
            let (root, relative) = self.resolve(action)?;
            let expected = match &action.verify {
                VerifyRule::ExpectDigest(digest) => Some(*digest),
                VerifyRule::ExpectAbsent => None,
            };
            self.writer.verify(root, &relative, expected)?;
            Ok(())
        }

        fn cleanup_staged(&self, operation: OperationId, action: &Action) -> CoreResult<usize> {
            let (root, relative) = self.resolve(action)?;
            // 中间目录不存在时没有任何暂存文件可清理，不是错误；这里也**绝不**为了
            // 清理而把目录建出来。
            let resolved = match root.resolve(&relative) {
                Ok(resolved) => resolved,
                Err(error) if error.is_not_found() => return Ok(0),
                Err(error) => return Err(error.into()),
            };
            let prefix = format!(
                "{}{}-",
                envsync_platform::TEMP_FILE_PREFIX,
                operation.to_filename()
            );
            let mut removed = 0usize;
            let entries = match resolved.dir().entries() {
                Ok(entries) => entries,
                // 目标目录不存在时没有暂存文件可清理，不是错误。
                Err(_) => return Ok(0),
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if name.starts_with(&prefix) && resolved.dir().remove_file(name).is_ok() {
                    removed += 1;
                }
            }
            Ok(removed)
        }

        fn rollback(&self, action: &Action, receipt: &ActionReceipt) -> CoreResult<()> {
            let (root, relative) = self.resolve(action)?;
            let platform_receipt = envsync_platform::Receipt {
                resource: receipt.resource.clone(),
                backup_path: receipt.backup_path.clone(),
                original_digest: receipt.original_digest,
                applied_digest: receipt.applied_digest,
                guarantee: receipt.guarantee,
                created_dirs: receipt.created_dirs.clone(),
            };
            self.writer.rollback(&platform_receipt, root, &relative)?;
            Ok(())
        }
    }
}
