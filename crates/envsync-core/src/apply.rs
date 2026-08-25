//! 事务化应用引擎。
//!
//! 固定顺序（设计文档 §4）：
//!
//! ```text
//! Preflight  → 校验全部动作，任何一个不通过就整体中止，后端与本地零变更
//! Publish    → CAS 更新后端 Ref；冲突时绝不调用 FileMutator
//! Apply      → 逐动作应用，每个动作立刻落 receipt，再逐个 verify
//! Verify     → 失败则连同当前动作一起逆序回滚
//! Journal    → 每一步都先写日志再动作，崩溃后可从日志判断处境
//! ```
//!
//! **CAS 冲突必须发生在本地变更之前**，这是「失败方本地零变更」这一验收条件的
//! 实现基础。反过来，Publish 成功但本地应用失败时状态是 `published_not_converged`，
//! 它不是普通失败：后端已经声称这个快照是当前头，本地必须继续收敛或显式回滚。

use envsync_backend::Backend;
use envsync_domain::{Action, OperationId, Plan};
use envsync_storage::{ErrorDetail, Journal, OperationState};

use crate::error::{CoreError, CoreResult};
use crate::planner::{requires_publish, BlobSource};
use crate::ports::{ActionReceipt, FileMutator};

/// 应用结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// 计划没有任何动作，且无需发布。
    NoOp,
    /// 全部动作成功应用并通过验证。
    Completed {
        /// 本次操作标识。
        operation: OperationId,
        /// 已应用的动作数量。
        applied: usize,
        /// 是否向后端发布了新引用。
        published: bool,
    },
}

/// 在不破坏事务边界的安全点查询取消状态。
///
/// 取消只会在 preflight 完成前或发布前被采纳。一旦后端 Ref 已发布，继续收敛或执行显式
/// 回滚才是安全路径；此时绝不能通过杀线程把 journal 留在不可信的半状态。
pub trait ApplyCancellation {
    /// 是否已经请求取消当前 operation。
    fn is_cancelled(&self) -> bool;

    /// 原子地关闭取消窗口。
    ///
    /// 返回 `true` 表示调用方已独占不可逆边界，可以继续发布或写入本地文件；返回 `false`
    /// 表示取消请求与关闭窗口发生了竞争，事务必须中止。默认实现适用于同步、不可取消的
    /// 调用方；可取消宿主必须提供线性化实现，避免“UI 显示已取消但 CAS 已发生”的竞态。
    fn close_cancellation_window(&self) -> bool {
        true
    }
}

/// 默认的不可取消实现，供 CLI 等同步调用使用。
#[derive(Debug, Clone, Copy, Default)]
pub struct NeverCancelled;

impl ApplyCancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// 应用引擎。
pub struct ApplyEngine<'a> {
    backend: &'a dyn Backend,
    mutator: &'a dyn FileMutator,
    journal: &'a mut Journal,
    blobs: &'a dyn BlobSource,
}

impl<'a> ApplyEngine<'a> {
    /// 构造应用引擎。
    pub fn new(
        backend: &'a dyn Backend,
        mutator: &'a dyn FileMutator,
        journal: &'a mut Journal,
        blobs: &'a dyn BlobSource,
    ) -> Self {
        ApplyEngine {
            backend,
            mutator,
            journal,
            blobs,
        }
    }

    /// 应用计划。
    pub fn apply(&mut self, plan: &Plan) -> CoreResult<ApplyOutcome> {
        self.apply_with_operation(plan, OperationId::generate(), &NeverCancelled)
    }

    /// 用调用方预先分配的 operation ID 应用计划。
    ///
    /// 桌面端在后台启动事务前生成该 ID，从而可以在完成前订阅事件或请求取消。被策略
    /// 阻塞与 no-op 仍不登记 operation，保持既有 journal 语义。
    pub fn apply_with_operation(
        &mut self,
        plan: &Plan,
        operation: OperationId,
        cancellation: &dyn ApplyCancellation,
    ) -> CoreResult<ApplyOutcome> {
        if let Some(outcome) = Self::register_operation(self.journal, plan, operation)? {
            return Ok(outcome);
        }
        self.apply_registered(plan, operation, cancellation)
    }

    /// 登记一个将要执行的 operation。
    ///
    /// 返回 [`Some`] 仅表示该 Plan 是无需写入也无需发布的 no-op；其他成功情形都已经
    /// 在 journal 中留下 `planned` 记录，调用方随后必须调用 [`Self::apply_registered`]
    /// 或将该记录安全地中止。应用服务会利用这个拆分，在上传不可变对象前就把桌面端
    /// 预先分配的 operation ID 写入 journal。
    pub(crate) fn register_operation(
        journal: &mut Journal,
        plan: &Plan,
        operation: OperationId,
    ) -> CoreResult<Option<ApplyOutcome>> {
        // 阻塞诊断在**登记操作之前**拦截：被策略拒绝的计划不应该在日志里留下
        // 一条永远不会推进的操作记录。
        if plan.is_blocked() {
            let blocking: Vec<&envsync_domain::Diagnostic> = plan.blocking_diagnostics().collect();
            return Err(CoreError::PlanBlocked {
                count: blocking.len(),
                first: blocking
                    .first()
                    .map(|d| format!("[{}] {}", d.code, d.message))
                    .unwrap_or_default(),
            });
        }

        let publish = requires_publish(plan);
        if plan.actions.is_empty() && !publish {
            return Ok(Some(ApplyOutcome::NoOp));
        }

        journal.begin_with_id(operation, plan)?;
        Ok(None)
    }

    /// 推进已处于 `planned` 状态的 operation。
    ///
    /// 调用方必须刚刚通过 [`Self::register_operation`] 登记 `operation`，且在此期间没有
    /// 对它做状态迁移。这个入口仅供 application service 在“登记 → 上传不可变对象 →
    /// 预检/发布/落盘”的安全顺序中复用，避免 UI 线程持有服务实例或绕过 journal。
    pub(crate) fn apply_registered(
        &mut self,
        plan: &Plan,
        operation: OperationId,
        cancellation: &dyn ApplyCancellation,
    ) -> CoreResult<ApplyOutcome> {
        let publish = requires_publish(plan);

        if cancellation.is_cancelled() {
            return self.cancel(operation);
        }

        // ---- 阶段 1：Preflight ----------------------------------------------
        // 预检期间**不做任何写入**；任何一个动作不通过，后端 Ref 与本地文件均不变。
        let staged = match self.preflight(plan) {
            Ok(staged) => staged,
            Err(err) => {
                self.abort(operation, &err)?;
                return Err(err);
            }
        };
        if cancellation.is_cancelled() {
            return self.cancel(operation);
        }
        self.journal
            .transition(operation, OperationState::Preflighted)?;

        if cancellation.is_cancelled() || !cancellation.close_cancellation_window() {
            return self.cancel(operation);
        }

        // ---- 阶段 2：Publish -------------------------------------------------
        if publish {
            if let Err(err) = self.backend.compare_and_swap_ref(
                plan.workspace,
                plan.base_revision,
                &plan.next_ref,
            ) {
                // CAS 失败：一个字节都还没写过。
                let err = CoreError::Backend(err);
                self.abort(operation, &err)?;
                return Err(err);
            }
        }
        self.journal
            .transition(operation, OperationState::Published)?;
        self.journal
            .transition(operation, OperationState::Applying)?;

        // ---- 阶段 3：逐动作应用 + 验证 ---------------------------------------
        let mut applied: Vec<(usize, ActionReceipt)> = Vec::new();
        for (ordinal, action) in plan.actions.iter().enumerate() {
            let content = staged[ordinal].as_deref();

            let receipt = match self.mutator.apply(operation, action, content) {
                Ok(receipt) => receipt,
                Err(err) => {
                    self.record_action_failure(operation, ordinal, &err)?;
                    return self.rollback_after_failure(plan, operation, applied, err);
                }
            };

            // receipt 必须在动作生效后**立刻**落盘。若落盘失败，我们持有的回滚凭据
            // 就没有进入崩溃恢复的事实来源，此时唯一安全的做法是立即回滚（含本动作），
            // 而不是继续往前走。
            if let Err(err) = self.persist_receipt(operation, ordinal, &receipt) {
                applied.push((ordinal, receipt));
                return self.rollback_after_failure(plan, operation, applied, err);
            }

            if let Err(err) = self.mutator.verify(action) {
                applied.push((ordinal, receipt));
                self.record_action_failure(operation, ordinal, &err)?;
                return self.rollback_after_failure(plan, operation, applied, err);
            }

            applied.push((ordinal, receipt));
        }

        self.journal
            .transition(operation, OperationState::Verified)?;
        self.journal
            .transition(operation, OperationState::Completed)?;
        Ok(ApplyOutcome::Completed {
            operation,
            applied: plan.actions.len(),
            published: publish,
        })
    }

    /// 预检并暂存每个动作的写入内容。
    fn preflight(&self, plan: &Plan) -> CoreResult<Vec<Option<Vec<u8>>>> {
        let mut staged = Vec::with_capacity(plan.actions.len());
        for action in &plan.actions {
            self.mutator.preflight(action)?;
            match action.content {
                Some(blob) => {
                    let bytes = self.blobs.blob(blob)?;
                    // 内容寻址自校验：草稿库或后端返回的字节必须确实是计划里那一份。
                    if envsync_domain::BlobId::of(&bytes) != blob {
                        return Err(CoreError::MissingObject(format!(
                            "动作内容 Blob {} 的实际内容与标识不符",
                            blob.short()
                        )));
                    }
                    staged.push(Some(bytes));
                }
                None => staged.push(None),
            }
        }
        Ok(staged)
    }

    /// 失败后逆序回滚已应用的动作。
    fn rollback_after_failure(
        &mut self,
        plan: &Plan,
        operation: OperationId,
        applied: Vec<(usize, ActionReceipt)>,
        cause: CoreError,
    ) -> CoreResult<ApplyOutcome> {
        if applied.is_empty() {
            // 一个动作都没生效：直接进入回滚终态，语义上等价于「什么都没做」。
            self.journal
                .transition(operation, OperationState::RollingBack)?;
            self.journal.record_error(
                operation,
                &ErrorDetail::new(cause.code(), cause.to_string()),
            )?;
            self.journal
                .transition(operation, OperationState::RolledBack)?;
            return Err(cause);
        }

        self.journal
            .transition(operation, OperationState::RollingBack)?;

        let mut rollback_failures: Vec<String> = Vec::new();
        for (ordinal, receipt) in applied.iter().rev() {
            let action: &Action = &plan.actions[*ordinal];
            if let Err(err) = self.mutator.rollback(action, receipt) {
                rollback_failures.push(format!("动作 #{ordinal}（{}）：{err}", action.resource));
            }
        }

        if rollback_failures.is_empty() {
            self.journal.record_error(
                operation,
                &ErrorDetail::new(cause.code(), cause.to_string()),
            )?;
            self.journal
                .transition(operation, OperationState::RolledBack)?;
            return Err(cause);
        }

        // 回滚也失败：保留 published_not_converged 与**双重错误**，等待恢复流程或
        // 人工处理。绝不把它降级成普通失败。
        let detail = format!(
            "应用失败：{cause}；回滚失败：{}",
            rollback_failures.join("；")
        );
        self.journal.record_error(
            operation,
            &ErrorDetail::new("sync.published_not_converged", detail.clone()),
        )?;
        self.journal
            .transition(operation, OperationState::PublishedNotConverged)?;
        Err(CoreError::PublishedNotConverged {
            operation: operation.to_string(),
            detail,
        })
    }

    fn abort(&mut self, operation: OperationId, cause: &CoreError) -> CoreResult<()> {
        Self::abort_registered(self.journal, operation, cause)
    }

    /// 以给定原因安全中止仍处于可中止边界的 operation。
    pub(crate) fn abort_registered(
        journal: &mut Journal,
        operation: OperationId,
        cause: &CoreError,
    ) -> CoreResult<()> {
        journal.transition_failed(
            operation,
            OperationState::Aborted,
            &ErrorDetail::new(cause.code(), cause.to_string()),
        )?;
        Ok(())
    }

    fn cancel(&mut self, operation: OperationId) -> CoreResult<ApplyOutcome> {
        let error = CoreError::OperationCancelled {
            operation: operation.to_string(),
        };
        self.abort(operation, &error)?;
        Err(error)
    }

    fn record_action_failure(
        &mut self,
        operation: OperationId,
        ordinal: usize,
        cause: &CoreError,
    ) -> CoreResult<()> {
        self.journal.record_action_error(
            operation,
            ordinal as u32,
            &ErrorDetail::new(cause.code(), cause.to_string()),
        )?;
        Ok(())
    }

    fn persist_receipt(
        &mut self,
        operation: OperationId,
        ordinal: usize,
        receipt: &ActionReceipt,
    ) -> CoreResult<()> {
        let stored = envsync_storage::Receipt {
            ordinal: ordinal as u32,
            resource: receipt.resource.clone(),
            backup_path: receipt
                .backup_path
                .as_ref()
                .map(|p| p.display().to_string()),
            original_digest: receipt.original_digest,
            applied_digest: receipt.applied_digest,
            guarantee: receipt.guarantee,
        };
        self.journal.record_receipt(operation, &stored)?;
        Ok(())
    }
}
