//! 操作日志的行为测试。
//!
//! 覆盖：迁移幂等与 PRAGMA、状态机（穷举合法/非法迁移）、写入原子性、
//! 重开数据库后的恢复查询、schema 版本保护与错误记录。

use envsync_domain::id::{Digest32, OperationId, ResourceId, SnapshotId, WorkspaceId};
use envsync_domain::plan::{
    Action, ActionKind, ActionTarget, BackupPolicy, Plan, Risk, RollbackCapability, VerifyRule,
};
use envsync_domain::snapshot::WorkspaceRef;
use envsync_domain::{BlobId, DeviceId};
use envsync_storage::journal::{
    ActionState, ErrorDetail, Journal, JournalError, OperationState, Receipt,
};
use envsync_storage::SCHEMA_VERSION;
use tempfile::TempDir;

/// 构造一个可用于测试的动作。
fn action(resource: &str, kind: ActionKind) -> Action {
    let before = Digest32::domain_hash("test:before", resource.as_bytes());
    let after = Digest32::domain_hash("test:after", resource.as_bytes());
    Action {
        resource: ResourceId::parse(resource).expect("资源标识合法"),
        kind,
        target: ActionTarget {
            root: "home".into(),
            segments: vec![format!(".{resource}").replace('/', "_")],
        },
        expected_before: Some(before),
        expected_after: Some(after),
        content: Some(BlobId::of(resource.as_bytes())),
        risk: Risk::Medium,
        backup: BackupPolicy::Required,
        rollback: RollbackCapability::Exact,
        unix_mode: Some(0o644),
        secret: false,
        verify: VerifyRule::ExpectDigest(after),
    }
}

/// 构造一个绑定给定动作的计划。
fn plan_with(actions: Vec<Action>) -> Plan {
    let workspace = WorkspaceId::generate();
    let snapshot = SnapshotId::of(b"test-snapshot");
    Plan::new(
        workspace,
        DeviceId::derive(b"test-device"),
        snapshot,
        7,
        WorkspaceRef::initial(workspace).advance(snapshot),
        vec![],
        actions,
        vec![],
        1_700_000_000_000,
    )
}

/// 默认的两动作计划。
fn sample_plan() -> Plan {
    plan_with(vec![
        action("shell/zsh/main", ActionKind::UpdateManagedBlock),
        action("git/config", ActionKind::ReplaceFile),
    ])
}

fn open_journal(dir: &TempDir) -> Journal {
    Journal::open(dir.path().join("journal.db")).expect("打开 journal")
}

/// 从 `planned` 走到目标状态所需的合法迁移序列。
fn path_to(state: OperationState) -> Vec<OperationState> {
    use OperationState::*;
    match state {
        Planned => vec![],
        Preflighted => vec![Preflighted],
        Published => vec![Preflighted, Published],
        Applying => vec![Preflighted, Published, Applying],
        Verified => vec![Preflighted, Published, Applying, Verified],
        Completed => vec![Preflighted, Published, Applying, Verified, Completed],
        PublishedNotConverged => vec![Preflighted, Published, PublishedNotConverged],
        Aborted => vec![Aborted],
        RollingBack => vec![Preflighted, Published, Applying, RollingBack],
        RolledBack => vec![Preflighted, Published, Applying, RollingBack, RolledBack],
    }
}

/// 新登记一个操作并把它驱动到指定状态。
fn operation_in_state(journal: &mut Journal, state: OperationState) -> OperationId {
    let record = journal.begin(&sample_plan()).expect("登记操作");
    let operation = record.operation;
    for step in path_to(state) {
        journal
            .transition(operation, step)
            .unwrap_or_else(|error| panic!("驱动到 {state} 时 {step} 失败：{error}"));
    }
    assert_eq!(
        journal.operation_state(operation).expect("读取状态"),
        Some(state)
    );
    operation
}

#[test]
fn migration_is_idempotent_and_pragmas_take_effect() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");

    let first = Journal::open(&path).expect("首次打开");
    let diagnostics = first.diagnostics().expect("读取诊断");
    assert_eq!(diagnostics.journal_mode, "wal", "journal_mode 必须是 WAL");
    assert!(diagnostics.foreign_keys, "外键必须启用");
    assert_eq!(diagnostics.busy_timeout_ms, 5_000);
    assert_eq!(diagnostics.synchronous, 2, "synchronous 必须是 FULL(2)");
    assert_eq!(diagnostics.schema_version, SCHEMA_VERSION);
    assert!(diagnostics.is_durable());
    drop(first);

    // 重复打开必须成功且 schema 版本不变，这就是迁移幂等。
    let second = Journal::open(&path).expect("再次打开");
    assert_eq!(second.schema_version().expect("读取版本"), SCHEMA_VERSION);
    assert_eq!(second.diagnostics().expect("读取诊断"), diagnostics);

    // 第三次打开仍然可用，并且能正常登记操作。
    let mut third = Journal::open(&path).expect("第三次打开");
    third.begin(&sample_plan()).expect("登记操作");
    assert_eq!(third.list_unfinished().expect("查询未完成").len(), 1);
}

#[test]
fn every_transition_pair_matches_the_declared_state_machine() {
    let dir = TempDir::new().expect("临时目录");
    let mut journal = open_journal(&dir);

    for from in OperationState::ALL {
        for to in OperationState::ALL {
            let operation = operation_in_state(&mut journal, from);
            let result = journal.transition(operation, to);
            let legal = from.can_transition_to(to);
            match (legal, result) {
                (true, Ok(record)) => {
                    assert_eq!(record.state, to, "合法迁移后状态必须更新");
                    assert_eq!(
                        journal.operation_state(operation).expect("读取状态"),
                        Some(to),
                        "合法迁移必须持久化"
                    );
                }
                (true, Err(error)) => panic!("合法迁移 {from} -> {to} 被拒绝：{error}"),
                (false, Err(JournalError::IllegalTransition { from: f, to: t })) => {
                    assert_eq!((f, t), (from, to));
                    assert_eq!(
                        journal.operation_state(operation).expect("读取状态"),
                        Some(from),
                        "非法迁移不得改变状态"
                    );
                }
                (false, Err(other)) => {
                    panic!("非法迁移 {from} -> {to} 应返回 IllegalTransition，实际：{other}")
                }
                (false, Ok(_)) => panic!("非法迁移 {from} -> {to} 竟然被接受"),
            }
        }
    }
}

#[test]
fn named_illegal_transitions_are_rejected_without_panicking() {
    let dir = TempDir::new().expect("临时目录");
    let mut journal = open_journal(&dir);

    let cases = [
        (OperationState::Planned, OperationState::Verified),
        (OperationState::Completed, OperationState::Applying),
        (OperationState::RolledBack, OperationState::Applying),
        (OperationState::Aborted, OperationState::Published),
    ];

    for (from, to) in cases {
        let operation = operation_in_state(&mut journal, from);
        match journal.transition(operation, to) {
            Err(JournalError::IllegalTransition { from: f, to: t }) => {
                assert_eq!((f, t), (from, to));
            }
            other => panic!("{from} -> {to} 期望 IllegalTransition，实际：{other:?}"),
        }
        assert_eq!(
            journal.operation_state(operation).expect("读取状态"),
            Some(from)
        );
    }
}

#[test]
fn happy_path_reaches_completed_and_leaves_nothing_unfinished() {
    let dir = TempDir::new().expect("临时目录");
    let mut journal = open_journal(&dir);
    let record = journal.begin(&sample_plan()).expect("登记操作");
    let operation = record.operation;

    assert_eq!(record.state, OperationState::Planned);
    assert_eq!(record.revision, 7);
    assert_eq!(journal.list_unfinished().expect("查询未完成").len(), 1);

    for step in [
        OperationState::Preflighted,
        OperationState::Published,
        OperationState::Applying,
        OperationState::Verified,
        OperationState::Completed,
    ] {
        journal.transition(operation, step).expect("合法迁移");
    }

    assert!(
        journal.list_unfinished().expect("查询未完成").is_empty(),
        "completed 属于终态，不应出现在未完成列表中"
    );
}

#[test]
fn begin_writes_operation_and_actions_in_one_transaction() {
    let dir = TempDir::new().expect("临时目录");
    let mut journal = open_journal(&dir);

    // 同一资源上出现两条完全相同的动作：第 0 条写入成功、第 1 条违反唯一约束。
    // 如果 begin 不是单事务，第一条动作和 operations 行就会留在库里。
    let duplicated = action("shell/zsh/main", ActionKind::ReplaceFile);
    let plan = plan_with(vec![
        duplicated.clone(),
        action("git/config", ActionKind::ReplaceFile),
        duplicated,
    ]);
    let operation = OperationId::generate();

    match journal.begin_with_id(operation, &plan) {
        Err(JournalError::DuplicateAction { resource, kind }) => {
            assert_eq!(resource, "shell/zsh/main");
            assert_eq!(kind, "replace_file");
        }
        other => panic!("期望 DuplicateAction，实际：{other:?}"),
    }

    assert!(
        journal.operation(operation).expect("查询操作").is_none(),
        "失败的 begin 不得留下 operations 行"
    );
    assert!(
        journal.actions(operation).expect("查询动作").is_empty(),
        "失败的 begin 不得留下 actions 行"
    );
    assert!(
        journal.list_unfinished().expect("查询未完成").is_empty(),
        "失败的 begin 不得产生未完成操作"
    );

    // 事务回滚后同一个操作标识仍然可以正常登记。
    journal
        .begin_with_id(operation, &sample_plan())
        .expect("回滚后重新登记");
    assert_eq!(journal.actions(operation).expect("查询动作").len(), 2);
}

#[test]
fn record_receipt_is_atomic_and_marks_action_applied() {
    let dir = TempDir::new().expect("临时目录");
    let mut journal = open_journal(&dir);
    let operation = operation_in_state(&mut journal, OperationState::Applying);

    // 序号不存在：收据与动作状态都不能落库。
    let orphan = Receipt {
        ordinal: 99,
        resource: ResourceId::parse("git/config").unwrap(),
        backup_path: Some("backups/op/99".into()),
        original_digest: None,
        applied_digest: None,
        guarantee: RollbackCapability::Exact,
    };
    match journal.record_receipt(operation, &orphan) {
        Err(JournalError::UnknownAction {
            operation: op,
            ordinal,
        }) => {
            assert_eq!(op, operation);
            assert_eq!(ordinal, 99);
        }
        other => panic!("期望 UnknownAction，实际：{other:?}"),
    }
    assert!(
        journal.receipts(operation).expect("查询收据").is_empty(),
        "失败的 record_receipt 不得留下收据"
    );
    assert!(
        journal
            .actions(operation)
            .expect("查询动作")
            .iter()
            .all(|a| a.state == ActionState::Pending),
        "失败的 record_receipt 不得改动作状态"
    );

    // 收据资源与动作登记的资源不符时同样整体拒绝。
    let actions = journal.actions(operation).expect("查询动作");
    let mismatched = Receipt {
        ordinal: actions[0].ordinal,
        resource: ResourceId::parse("wrong/resource").unwrap(),
        backup_path: None,
        original_digest: None,
        applied_digest: None,
        guarantee: RollbackCapability::None,
    };
    assert!(matches!(
        journal.record_receipt(operation, &mismatched),
        Err(JournalError::ReceiptResourceMismatch { .. })
    ));
    assert!(journal.receipts(operation).expect("查询收据").is_empty());

    // 正常写入：收据落库且动作被置为 applied，两者在同一事务里。
    let good = Receipt {
        ordinal: actions[0].ordinal,
        resource: actions[0].resource.clone(),
        backup_path: Some("backups/op/0000".into()),
        original_digest: actions[0].expected_before,
        applied_digest: actions[0].expected_after,
        guarantee: RollbackCapability::Exact,
    };
    journal.record_receipt(operation, &good).expect("写入收据");
    let stored = journal.receipts(operation).expect("查询收据");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].receipt, good);
    assert!(stored[0].created_at_unix_ms > 0);
    assert_eq!(
        journal.actions(operation).expect("查询动作")[0].state,
        ActionState::Applied
    );

    // 重复写入同一序号是幂等的，恢复流程可以安全重放。
    journal.record_receipt(operation, &good).expect("重放收据");
    assert_eq!(journal.receipts(operation).expect("查询收据").len(), 1);
}

#[test]
fn reopened_database_exposes_unfinished_operations_and_receipts() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");

    let (interrupted, finished, receipt) = {
        let mut journal = Journal::open(&path).expect("打开 journal");

        let interrupted = operation_in_state(&mut journal, OperationState::Applying);
        let actions = journal.actions(interrupted).expect("查询动作");
        let receipt = Receipt {
            ordinal: actions[0].ordinal,
            resource: actions[0].resource.clone(),
            backup_path: Some("backups/interrupted/0000".into()),
            original_digest: actions[0].expected_before,
            applied_digest: actions[0].expected_after,
            guarantee: RollbackCapability::Exact,
        };
        journal
            .record_receipt(interrupted, &receipt)
            .expect("写入收据");

        let finished = operation_in_state(&mut journal, OperationState::Completed);
        (interrupted, finished, receipt)
    };

    // 模拟进程重启：连接已关闭，一切必须能从磁盘重新读出来。
    let journal = Journal::open(&path).expect("重新打开 journal");

    let unfinished = journal.list_unfinished().expect("查询未完成");
    assert_eq!(unfinished.len(), 1, "只有 applying 的操作需要恢复");
    assert_eq!(unfinished[0].operation, interrupted);
    assert_eq!(unfinished[0].state, OperationState::Applying);
    assert_eq!(unfinished[0].revision, 7);
    assert!(
        !unfinished.iter().any(|r| r.operation == finished),
        "completed 的操作不应出现在未完成列表中"
    );

    let restored = journal.receipts(interrupted).expect("查询收据");
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].receipt, receipt);
    assert_eq!(restored[0].operation, interrupted);

    // 动作的目标、种类与预期摘要同样必须完整还原。
    let actions = journal.actions(interrupted).expect("查询动作");
    assert_eq!(actions.len(), 2);
    assert_eq!(actions[0].target.root, "home");
    assert_eq!(actions[0].kind, ActionKind::ReplaceFile);
    assert_eq!(actions[0].state, ActionState::Applied);
    assert_eq!(actions[1].state, ActionState::Pending);
    assert!(actions[0].expected_before.is_some());
    assert!(actions[0].expected_after.is_some());
}

#[test]
fn schema_version_newer_than_supported_is_rejected() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");
    Journal::open(&path).expect("首次打开");

    // 模拟“新版本 EnvSync 升级过 schema”，旧版本绝不能继续改写它。
    let raw = rusqlite::Connection::open(&path).expect("直接打开数据库");
    raw.execute(
        "UPDATE schema_meta SET value = ?1 WHERE key = 'schema_version'",
        [(SCHEMA_VERSION + 98).to_string()],
    )
    .expect("篡改版本号");
    drop(raw);

    match Journal::open(&path) {
        Err(JournalError::SchemaTooNew { found, supported }) => {
            assert_eq!(found, SCHEMA_VERSION + 98);
            assert_eq!(supported, SCHEMA_VERSION);
        }
        other => panic!("期望 SchemaTooNew，实际：{:?}", other.map(|_| "Ok")),
    }
}

#[test]
fn errors_are_persisted_and_not_converged_operations_are_queryable() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");
    let mut journal = Journal::open(&path).expect("打开 journal");

    let operation = operation_in_state(&mut journal, OperationState::Published);
    let detail = ErrorDetail::new(
        "apply.rename_failed",
        "替换目标文件时 rename 失败，本地未收敛",
    );
    let record = journal
        .transition_failed(operation, OperationState::PublishedNotConverged, &detail)
        .expect("带错误迁移");
    assert_eq!(record.state, OperationState::PublishedNotConverged);
    assert_eq!(record.error.as_ref(), Some(&detail));

    // 动作级错误同样可写可读。
    let action_error = ErrorDetail::new("apply.stale_observation", "写入前摘要与计划不符");
    journal
        .record_action_error(operation, 1, &action_error)
        .expect("记录动作错误");

    // 不改状态、只补充错误说明。
    let refined = ErrorDetail::new("apply.rename_failed", "备份仍然完好，可回滚");
    journal.record_error(operation, &refined).expect("记录错误");

    drop(journal);
    let journal = Journal::open(&path).expect("重新打开");

    let not_converged = journal
        .list_by_state(OperationState::PublishedNotConverged)
        .expect("按状态查询");
    assert_eq!(not_converged.len(), 1);
    assert_eq!(not_converged[0].operation, operation);
    assert_eq!(not_converged[0].error.as_ref(), Some(&refined));

    let actions = journal.actions(operation).expect("查询动作");
    assert_eq!(actions[1].state, ActionState::Failed);
    assert_eq!(actions[1].error.as_ref(), Some(&action_error));

    // published_not_converged 不是终态，必须继续出现在恢复列表里。
    let unfinished = journal.list_unfinished().expect("查询未完成");
    assert_eq!(unfinished.len(), 1);
    assert_eq!(unfinished[0].state, OperationState::PublishedNotConverged);

    // 未知操作的错误记录必须报错而不是静默丢弃。
    assert!(matches!(
        journal.record_error(OperationId::generate(), &refined),
        Err(JournalError::UnknownOperation(_))
    ));
}

#[test]
fn pruning_an_operation_cascades_to_actions_and_receipts() {
    let dir = TempDir::new().expect("临时目录");
    let mut journal = open_journal(&dir);
    let operation = operation_in_state(&mut journal, OperationState::Applying);
    let actions = journal.actions(operation).expect("查询动作");
    journal
        .record_receipt(
            operation,
            &Receipt {
                ordinal: actions[0].ordinal,
                resource: actions[0].resource.clone(),
                backup_path: Some("backups/pruned/0000".into()),
                original_digest: None,
                applied_digest: actions[0].expected_after,
                guarantee: RollbackCapability::Compensating,
            },
        )
        .expect("写入收据");

    assert!(journal.prune_operation(operation).expect("删除操作"));
    assert!(journal.operation(operation).expect("查询操作").is_none());
    assert!(journal.actions(operation).expect("查询动作").is_empty());
    assert!(journal.receipts(operation).expect("查询收据").is_empty());
    assert!(!journal.prune_operation(operation).expect("重复删除"));
}
