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
            return Ok(ApplyOutcome::NoOp);
        }

        let record = self.journal.begin(plan)?;
        let operation = record.operation;

        // ---- 阶段 1：Preflight ----------------------------------------------
        // 预检期间**不做任何写入**；任何一个动作不通过，后端 Ref 与本地文件均不变。
        let staged = match self.preflight(plan) {
            Ok(staged) => staged,
            Err(err) => {
                self.abort(operation, &err)?;
                return Err(err);
            }
        };
        self.journal
            .transition(operation, OperationState::Preflighted)?;

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
        self.journal.record_error(
            operation,
            &ErrorDetail::new(cause.code(), cause.to_string()),
        )?;
        self.journal
            .transition(operation, OperationState::Aborted)?;
        Ok(())
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
