//! 崩溃恢复与显式回滚。
//!
//! 恢复的事实来源是 [`Journal`]：进程可能在任何一步被杀死，但只要日志写在动作之前，
//! 下次启动就能判断「我当时走到哪一步」。恢复算法必须**幂等**——连续运行两次得到
//! 相同最终状态，因此每一步都以「目标文件当前摘要」而不是「上次运行的内存状态」
//! 作为判据。
//!
//! 三个判据摘要：
//!
//! | 目标当前摘要 | 含义 | 处理 |
//! |---|---|---|
//! | `== expected_after` | 该动作已经生效 | 跳到下一个动作 |
//! | `== expected_before` | 该动作尚未生效 | 重新应用 |
//! | 两者都不等 | 期间被外部修改 | **停止**，报告人工冲突 |
//!
//! `doctor` 只调用 [`RecoveryEngine::diagnose`]（只读），`recover` 才调用
//! [`RecoveryEngine::recover_all`]（会修改）。

use envsync_domain::{Action, OperationId, Plan, PlanId};
use envsync_storage::{ActionState, ErrorDetail, Journal, OperationState};

use crate::error::{CoreError, CoreResult};
use crate::ports::{ActionReceipt, FileMutator, Observer};

/// 计划来源：恢复时需要拿回原始计划才能重新应用。
pub trait PlanSource {
    /// 按标识读取计划。
    fn plan(&self, id: PlanId) -> CoreResult<Option<Plan>>;
}

/// 单个操作的恢复诊断（只读）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryDiagnosis {
    /// 操作标识。
    pub operation: OperationId,
    /// 操作当前状态。
    pub state: OperationState,
    /// 建议的处理方式。
    pub suggestion: RecoverySuggestion,
    /// 人类可读说明。
    pub notes: Vec<String>,
}

/// 恢复建议。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoverySuggestion {
    /// 已是终态，无需处理。
    Nothing,
    /// 清理暂存文件后中止。
    AbortStaged,
    /// 继续本地收敛。
    Reconverge {
        /// 尚未生效的动作数量。
        pending: usize,
    },
    /// 继续逆序回滚。
    ContinueRollback {
        /// 尚待回滚的动作数量。
        pending: usize,
    },
    /// 需要人工处理。
    Manual {
        /// 原因。
        reason: String,
    },
}

/// 恢复执行结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    /// 操作标识。
    pub operation: OperationId,
    /// 恢复前状态。
    pub before: OperationState,
    /// 恢复后状态。
    pub after: OperationState,
    /// 执行摘要。
    pub notes: Vec<String>,
}

/// 恢复引擎。
pub struct RecoveryEngine<'a> {
    journal: &'a mut Journal,
    plans: &'a dyn PlanSource,
    blobs: &'a dyn crate::planner::BlobSource,
    observer: &'a dyn Observer,
    mutator: &'a dyn FileMutator,
}

impl<'a> RecoveryEngine<'a> {
    /// 构造恢复引擎。
    pub fn new(
        journal: &'a mut Journal,
        plans: &'a dyn PlanSource,
        blobs: &'a dyn crate::planner::BlobSource,
        observer: &'a dyn Observer,
        mutator: &'a dyn FileMutator,
    ) -> Self {
        RecoveryEngine {
            journal,
            plans,
            blobs,
            observer,
            mutator,
        }
    }

    /// 只读诊断：列出所有未完成操作及建议处理方式，**不做任何修改**。
    pub fn diagnose(&self) -> CoreResult<Vec<RecoveryDiagnosis>> {
        let mut out = Vec::new();
        for record in self.journal.list_unfinished()? {
            let plan = self.plans.plan(record.plan)?;
            let diagnosis = match (record.state, plan) {
                (state, _) if state.is_terminal() => RecoveryDiagnosis {
                    operation: record.operation,
                    state,
                    suggestion: RecoverySuggestion::Nothing,
                    notes: vec![],
                },
                (state, None) => RecoveryDiagnosis {
                    operation: record.operation,
                    state,
                    suggestion: RecoverySuggestion::Manual {
                        reason: format!("草稿库中找不到计划 {}，无法自动恢复", record.plan),
                    },
                    notes: vec![],
                },
                (OperationState::Planned | OperationState::Preflighted, Some(_)) => {
                    RecoveryDiagnosis {
                        operation: record.operation,
                        state: record.state,
                        suggestion: RecoverySuggestion::AbortStaged,
                        notes: vec!["尚未发布，清理暂存文件后中止即可".into()],
                    }
                }
                (
                    OperationState::Published
                    | OperationState::Applying
                    | OperationState::Verified
                    | OperationState::PublishedNotConverged,
                    Some(plan),
                ) => self.diagnose_convergence(&record, &plan)?,
                (OperationState::RollingBack, Some(plan)) => {
                    let receipts = self.journal.receipts(record.operation)?;
                    let _ = &plan;
                    RecoveryDiagnosis {
                        operation: record.operation,
                        state: record.state,
                        suggestion: RecoverySuggestion::ContinueRollback {
                            pending: receipts.len(),
                        },
                        notes: vec![format!("有 {} 条收据可用于逆序回滚", receipts.len())],
                    }
                }
                (state, Some(_)) => RecoveryDiagnosis {
                    operation: record.operation,
                    state,
                    suggestion: RecoverySuggestion::Nothing,
                    notes: vec![],
                },
            };
            out.push(diagnosis);
        }
        Ok(out)
    }

    fn diagnose_convergence(
        &self,
        record: &envsync_storage::OperationRecord,
        plan: &Plan,
    ) -> CoreResult<RecoveryDiagnosis> {
        let mut pending = 0usize;
        let mut notes = Vec::new();
        for action in &plan.actions {
            match self.classify(action)? {
                ActionProgress::Applied => {}
                ActionProgress::NotApplied => pending += 1,
                ActionProgress::Diverged { current } => {
                    return Ok(RecoveryDiagnosis {
                        operation: record.operation,
                        state: record.state,
                        suggestion: RecoverySuggestion::Manual {
                            reason: format!(
                                "资源 {} 的目标既不等于应用前摘要也不等于应用后摘要（当前 {}），\
                                 说明期间被外部修改",
                                action.resource,
                                current.unwrap_or_else(|| "不存在".into())
                            ),
                        },
                        notes,
                    });
                }
            }
        }
        notes.push(format!("{} 个动作尚未生效", pending));
        Ok(RecoveryDiagnosis {
            operation: record.operation,
            state: record.state,
            suggestion: RecoverySuggestion::Reconverge { pending },
            notes,
        })
    }

    /// 执行恢复。返回每个被处理操作的报告。
    pub fn recover_all(&mut self) -> CoreResult<Vec<RecoveryReport>> {
        let unfinished = self.journal.list_unfinished()?;
        let mut reports = Vec::new();
        for record in unfinished {
            let report = self.recover_one(record)?;
            reports.push(report);
        }
        Ok(reports)
    }

    fn recover_one(
        &mut self,
        record: envsync_storage::OperationRecord,
    ) -> CoreResult<RecoveryReport> {
        let operation = record.operation;
        let before = record.state;
        let plan = self.plans.plan(record.plan)?;

        let Some(plan) = plan else {
            let detail = format!("草稿库中找不到计划 {}，无法自动恢复", record.plan);
            self.journal.record_error(
                operation,
                &ErrorDetail::new("recovery.manual_required", &detail),
            )?;
            return Ok(RecoveryReport {
                operation,
                before,
                after: before,
                notes: vec![detail],
            });
        };

        match before {
            OperationState::Planned | OperationState::Preflighted => {
                let cleaned = self.cleanup_staged(operation, &plan)?;
                self.journal
                    .transition(operation, OperationState::Aborted)?;
                Ok(RecoveryReport {
                    operation,
                    before,
                    after: OperationState::Aborted,
                    notes: vec![format!("清理了 {cleaned} 个暂存文件并中止（未发布）")],
                })
            }
            OperationState::Published
            | OperationState::Applying
            | OperationState::PublishedNotConverged => self.reconverge(operation, before, &plan),
            OperationState::Verified => {
                // 验证已通过，只差最后一次状态迁移。
                self.journal
                    .transition(operation, OperationState::Completed)?;
                Ok(RecoveryReport {
                    operation,
                    before,
                    after: OperationState::Completed,
                    notes: vec!["验证已通过，补记完成状态".into()],
                })
            }
            OperationState::RollingBack => self.continue_rollback(operation, before, &plan),
            terminal => Ok(RecoveryReport {
                operation,
                before,
                after: terminal,
                notes: vec!["已是终态，跳过".into()],
            }),
        }
    }

    /// 继续本地收敛。
    fn reconverge(
        &mut self,
        operation: OperationId,
        before: OperationState,
        plan: &Plan,
    ) -> CoreResult<RecoveryReport> {
        // 先把状态推进到 applying（若尚未在该状态），保证中途再次崩溃时判据不变。
        if before != OperationState::Applying {
            self.journal
                .transition(operation, OperationState::Applying)?;
        }

        let mut notes = Vec::new();
        let mut reapplied = 0usize;

        for (ordinal, action) in plan.actions.iter().enumerate() {
            match self.classify(action)? {
                ActionProgress::Applied => {
                    self.journal.set_action_state(
                        operation,
                        ordinal as u32,
                        ActionState::Applied,
                    )?;
                }
                ActionProgress::NotApplied => {
                    let content = match action.content {
                        Some(blob) => Some(self.blobs.blob(blob)?),
                        None => None,
                    };
                    match self.mutator.apply(operation, action, content.as_deref()) {
                        Ok(receipt) => {
                            self.persist(operation, ordinal, &receipt)?;
                            reapplied += 1;
                        }
                        Err(err) => {
                            let detail = format!(
                                "恢复时重新应用动作 #{ordinal}（{}）失败：{err}",
                                action.resource
                            );
                            self.journal.record_error(
                                operation,
                                &ErrorDetail::new("sync.published_not_converged", &detail),
                            )?;
                            self.journal
                                .transition(operation, OperationState::PublishedNotConverged)?;
                            notes.push(detail);
                            return Ok(RecoveryReport {
                                operation,
                                before,
                                after: OperationState::PublishedNotConverged,
                                notes,
                            });
                        }
                    }
                }
                ActionProgress::Diverged { current } => {
                    // 绝不覆盖：目标在中断期间被外部修改，只有人能决定谁对。
                    let detail = format!(
                        "资源 {} 的目标既不等于应用前摘要也不等于应用后摘要（当前 {}），需要人工处理",
                        action.resource,
                        current.unwrap_or_else(|| "不存在".into())
                    );
                    self.journal.record_error(
                        operation,
                        &ErrorDetail::new("recovery.manual_required", &detail),
                    )?;
                    if before != OperationState::PublishedNotConverged {
                        self.journal
                            .transition(operation, OperationState::PublishedNotConverged)?;
                    }
                    notes.push(detail);
                    return Ok(RecoveryReport {
                        operation,
                        before,
                        after: OperationState::PublishedNotConverged,
                        notes,
                    });
                }
            }
        }

        for action in &plan.actions {
            self.mutator.verify(action)?;
        }
        self.journal
            .transition(operation, OperationState::Verified)?;
        self.journal
            .transition(operation, OperationState::Completed)?;
        notes.push(format!("重新应用了 {reapplied} 个动作并完成收敛"));
        Ok(RecoveryReport {
            operation,
            before,
            after: OperationState::Completed,
            notes,
        })
    }

    /// 依据收据继续逆序回滚。
    fn continue_rollback(
        &mut self,
        operation: OperationId,
        before: OperationState,
        plan: &Plan,
    ) -> CoreResult<RecoveryReport> {
        let receipts = self.journal.receipts(operation)?;
        let mut failures = Vec::new();
        let mut rolled = 0usize;

        for stored in receipts.iter().rev() {
            let ordinal = stored.receipt.ordinal as usize;
            let Some(action) = plan.actions.get(ordinal) else {
                failures.push(format!("收据 #{ordinal} 在计划中没有对应动作"));
                continue;
            };
            let receipt = to_action_receipt(&stored.receipt);
            // 幂等：目标已经等于原摘要时，说明这一条已经回滚过了。
            if self.digest_of(action)? == receipt.original_digest {
                rolled += 1;
                continue;
            }
            if let Err(err) = self.mutator.rollback(action, &receipt) {
                failures.push(format!(
                    "动作 #{ordinal}（{}）回滚失败：{err}",
                    action.resource
                ));
            } else {
                rolled += 1;
            }
        }

        if failures.is_empty() {
            self.journal
                .transition(operation, OperationState::RolledBack)?;
            Ok(RecoveryReport {
                operation,
                before,
                after: OperationState::RolledBack,
                notes: vec![format!("完成 {rolled} 条动作的逆序回滚")],
            })
        } else {
            let detail = failures.join("；");
            self.journal.record_error(
                operation,
                &ErrorDetail::new("sync.published_not_converged", &detail),
            )?;
            self.journal
                .transition(operation, OperationState::PublishedNotConverged)?;
            Ok(RecoveryReport {
                operation,
                before,
                after: OperationState::PublishedNotConverged,
                notes: failures,
            })
        }
    }

    /// 显式回滚一个已完成的操作。
    pub fn rollback_operation(&mut self, operation: OperationId) -> CoreResult<RecoveryReport> {
        let record = self
            .journal
            .operation(operation)?
            .ok_or_else(|| CoreError::OperationNotFound(operation.to_string()))?;
        let plan = self
            .plans
            .plan(record.plan)?
            .ok_or(CoreError::PlanNotFound(record.plan))?;

        if !matches!(
            record.state,
            OperationState::Completed
                | OperationState::Applying
                | OperationState::PublishedNotConverged
                | OperationState::RollingBack
        ) {
            return Err(CoreError::Rollback(format!(
                "操作 {operation} 当前状态为 {}，不支持回滚",
                record.state
            )));
        }

        if record.state != OperationState::RollingBack {
            self.journal
                .transition(operation, OperationState::RollingBack)?;
        }
        self.continue_rollback(operation, record.state, &plan)
    }

    // ---- 辅助 ----------------------------------------------------------------

    fn classify(&self, action: &Action) -> CoreResult<ActionProgress> {
        let current = self.digest_of(action)?;
        if current == action.expected_after {
            Ok(ActionProgress::Applied)
        } else if current == action.expected_before {
            Ok(ActionProgress::NotApplied)
        } else {
            Ok(ActionProgress::Diverged {
                current: current.map(|d| d.short()),
            })
        }
    }

    fn digest_of(&self, action: &Action) -> CoreResult<Option<envsync_domain::Digest32>> {
        self.observer
            .current_digest(&action.target, &envsync_domain::ResourcePolicy::default())
    }

    fn cleanup_staged(&self, operation: OperationId, plan: &Plan) -> CoreResult<usize> {
        let mut cleaned = 0usize;
        for action in &plan.actions {
            cleaned += self.mutator.cleanup_staged(operation, action)?;
        }
        Ok(cleaned)
    }

    fn persist(
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

/// 单个动作在恢复时的进度判定。
#[derive(Debug, Clone, PartialEq, Eq)]
enum ActionProgress {
    /// 已生效。
    Applied,
    /// 尚未生效。
    NotApplied,
    /// 目标被外部修改，两个判据都不匹配。
    Diverged {
        /// 当前摘要的短表示。
        current: Option<String>,
    },
}

fn to_action_receipt(stored: &envsync_storage::Receipt) -> ActionReceipt {
    ActionReceipt {
        resource: stored.resource.clone(),
        backup_path: stored.backup_path.as_ref().map(std::path::PathBuf::from),
        original_digest: stored.original_digest,
        applied_digest: stored.applied_digest,
        guarantee: stored.guarantee,
    }
}
