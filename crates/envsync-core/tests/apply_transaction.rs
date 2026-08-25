//! 任务 10：ApplyEngine 事务顺序的验收测试。
//!
//! 组合方式刻意是「真实 + 伪造」的混合：
//!
//! * **真实 [`Journal`]**（tempdir 上的 SQLite）——状态机与收据是崩溃恢复的事实来源，
//!   用真的才能断言状态迁移合法性与收据落盘顺序；
//! * **真实 [`LocalBackend`]**（tempdir）——CAS 冲突必须是后端真的拒绝，而不是 fake
//!   编造的错误；
//! * **伪造 `FileMutator`**——只有 fake 才能精确注入「第 2 个动作写入失败」
//!   「verify 不通过」「回滚也失败」这类现实中无法稳定复现的场景，并记录调用顺序。
//!
//! 覆盖计划文档任务 10 的 8 条测试先行清单，外加一条「阻塞计划不留 journal 记录」。

mod support;

use envsync_backend::{Backend, LocalBackend};
use envsync_core::apply::{ApplyCancellation, ApplyEngine, ApplyOutcome};
use envsync_core::error::CoreError;
use envsync_domain::{BlobId, Diagnostic, Digest32, Plan, SnapshotId, WorkspaceRef};
use envsync_storage::{Journal, OperationState};

use support::{
    delete_action, digest_of, error_message_of, journal_is_empty, plan_of, plan_of_with, state_of,
    workspace_id, write_action, FakeBlobs, FakeMutator, ProbingBackend, StateProbe,
    FAKE_APPLY_FAILURE, FAKE_ROLLBACK_FAILURE,
};

/// 一次测试所需的全部真实组件。
struct Harness {
    _dir: tempfile::TempDir,
    journal: Journal,
    journal_path: std::path::PathBuf,
    backend: LocalBackend,
    blobs: FakeBlobs,
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("创建临时目录");
        let journal_path = dir.path().join("journal.db");
        let journal = Journal::open(&journal_path).expect("打开 journal");
        let backend = LocalBackend::open(dir.path().join("backend")).expect("打开本地后端");
        Harness {
            _dir: dir,
            journal,
            journal_path,
            backend,
            blobs: FakeBlobs::new(),
        }
    }

    /// 注册一份写入内容并返回 `(BlobId, 内容摘要)`。
    fn content(&self, bytes: &[u8]) -> (BlobId, Digest32) {
        (self.blobs.insert(bytes), digest_of(bytes))
    }

    /// 后端当前 revision；从未发布过时为 0。
    fn revision(&self) -> u64 {
        match self.backend.get_ref(workspace_id()) {
            Ok(reference) => reference.revision,
            Err(envsync_backend::BackendError::RefNotFound(_)) => 0,
            Err(err) => panic!("读取后端引用失败：{err}"),
        }
    }

    /// 当前唯一操作的标识。
    fn only_operation(&self) -> envsync_domain::OperationId {
        let mut all: Vec<envsync_storage::OperationRecord> = Vec::new();
        for state in OperationState::ALL {
            all.extend(self.journal.list_by_state(state).expect("按状态查询"));
        }
        assert_eq!(all.len(), 1, "期望恰好一条操作记录");
        all[0].operation
    }
}

/// 构造一份含三个写入动作的计划，动作按资源标识 `a/one`、`b/two`、`c/three` 排序。
fn three_write_plan(harness: &Harness) -> Plan {
    let (blob_a, after_a) = harness.content(b"content-a\n");
    let (blob_b, after_b) = harness.content(b"content-b\n");
    let (blob_c, after_c) = harness.content(b"content-c\n");
    plan_of(
        vec![
            write_action("a/one", "a.txt", None, after_a, blob_a),
            write_action("b/two", "b.txt", None, after_b, blob_b),
            write_action("c/three", "c.txt", None, after_c, blob_c),
        ],
        0,
        true,
    )
}

// ---------------------------------------------------------------------------
// 1 & 8：成功路径的顺序与状态序列
// ---------------------------------------------------------------------------

/// 计划文档任务 10 第 1 条与第 8 条：
/// 全部动作 preflight 成功后才允许 Publish；成功路径状态序列为
/// published → applying → verified → completed。
///
/// 状态序列的断言方式：用 [`StateProbe`]（同一数据库上的第二条连接）在事务中途采样。
/// 采样点只能看到 `Preflighted`（CAS 瞬间）与 `Applying`（apply / verify 瞬间），
/// 因为 `Published` 与 `Verified` 都会被紧接着的下一次迁移覆盖；而 journal 的状态机
/// **禁止** `Preflighted -> Applying` 与 `Applying -> Completed` 直接跳转，所以这两个
/// 中间态必然被经过。测试把这两条禁令也一并断言，使推理自洽。
#[test]
fn successful_apply_follows_published_applying_verified_completed() {
    let mut harness = Harness::new();
    let plan = three_write_plan(&harness);

    let probe = StateProbe::open(&harness.journal_path);
    let mutator = FakeMutator::new().with_probe(probe.clone());
    let backend = ProbingBackend::new(&harness.backend, probe.clone());

    let outcome = {
        let mut engine = ApplyEngine::new(&backend, &mutator, &mut harness.journal, &harness.blobs);
        engine.apply(&plan).expect("成功路径")
    };

    let operation = match outcome {
        ApplyOutcome::Completed {
            operation,
            applied,
            published,
        } => {
            assert_eq!(applied, 3);
            assert!(published, "next_ref 前进时必须发布");
            operation
        }
        other => panic!("期望 Completed，实际 {other:?}"),
    };

    // 顺序：三次 preflight 全部先于第一次 apply。
    let labels: Vec<String> = mutator
        .calls()
        .iter()
        .map(|call| format!("{call:?}"))
        .collect();
    let first_apply = labels
        .iter()
        .position(|label| label.starts_with("Apply"))
        .expect("必须有 apply");
    let last_preflight = labels
        .iter()
        .rposition(|label| label.starts_with("Preflight"))
        .expect("必须有 preflight");
    assert!(
        last_preflight < first_apply,
        "全部动作 preflight 成功之后才允许开始写入：{labels:?}"
    );

    // 状态序列。
    assert_eq!(
        probe.state_at("cas"),
        Some(OperationState::Preflighted),
        "CAS 必须发生在 preflight 之后、任何本地写入之前"
    );
    assert_eq!(
        probe.state_at("apply:a/one"),
        Some(OperationState::Applying),
        "开始写入时操作必须已经处于 applying"
    );
    assert_eq!(
        probe.state_at("verify:c/three"),
        Some(OperationState::Applying),
        "verify 阶段仍处于 applying"
    );
    assert_eq!(
        state_of(&harness.journal, operation),
        OperationState::Completed
    );

    // 状态机禁令：证明 published 与 verified 两个中间态必然被经过。
    assert!(
        !OperationState::Preflighted.can_transition_to(OperationState::Applying),
        "preflighted 不能直接跳到 applying，因此必然经过 published"
    );
    assert!(
        !OperationState::Applying.can_transition_to(OperationState::Completed),
        "applying 不能直接跳到 completed，因此必然经过 verified"
    );

    assert_eq!(harness.revision(), 1, "成功路径必须把后端 Ref 前进一格");
}

// ---------------------------------------------------------------------------
// 2：preflight 失败
// ---------------------------------------------------------------------------

/// 计划文档任务 10 第 2 条：任一 preflight 失败时，后端 Ref 和本地文件均不变。
#[test]
fn preflight_failure_leaves_backend_and_local_untouched() {
    let mut harness = Harness::new();
    let plan = three_write_plan(&harness);
    // 让排在最后的动作 preflight 失败：前两个已经通过，仍然必须整体中止。
    let mutator = FakeMutator::new().fail_preflight("c/three");

    let error = {
        let mut engine = ApplyEngine::new(
            &harness.backend,
            &mutator,
            &mut harness.journal,
            &harness.blobs,
        );
        engine.apply(&plan).expect_err("preflight 失败必须整体失败")
    };
    assert_eq!(error.code(), "platform.stale_observation");

    assert_eq!(
        mutator.apply_count(),
        0,
        "preflight 未全部通过时，一个字节都不许写"
    );
    assert!(mutator.rolled_back().is_empty(), "什么都没做就没有可回滚的");
    assert_eq!(harness.revision(), 0, "后端 Ref 必须保持不变");

    let operation = harness.only_operation();
    assert_eq!(
        state_of(&harness.journal, operation),
        OperationState::Aborted,
        "尚未发布就失败，应当中止而不是进入未收敛状态"
    );
}

/// 已收到取消请求的 operation 必须在任何 preflight、CAS 或本地写入之前记录为 aborted。
/// 取消不能通过杀线程实现，否则会破坏 journal 对真实现场的描述。
#[test]
fn cancellation_before_preflight_aborts_the_registered_operation_without_side_effects() {
    struct AlreadyCancelled;

    impl ApplyCancellation for AlreadyCancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }

    let mut harness = Harness::new();
    let plan = three_write_plan(&harness);
    let operation = "12345678-1234-4234-8234-123456789abc"
        .parse()
        .expect("固定操作标识有效");
    let mutator = FakeMutator::new();
    let error = {
        let mut engine = ApplyEngine::new(
            &harness.backend,
            &mutator,
            &mut harness.journal,
            &harness.blobs,
        );
        engine
            .apply_with_operation(&plan, operation, &AlreadyCancelled)
            .expect_err("取消必须阻止事务开始")
    };

    assert_eq!(error.code(), "operation.cancelled");
    assert_eq!(mutator.apply_count(), 0);
    assert!(mutator.rolled_back().is_empty());
    assert_eq!(harness.revision(), 0);
    let journal_path = harness.journal_path.clone();
    drop(harness.journal);

    // 模拟进程在取消结果写入后立刻退出；重开 journal 时必须同时看到最终状态与原因。
    // `transition_failed` 是单条 UPDATE，不能留下「已有取消错误但仍是 planned」的半成品。
    let reopened = Journal::open(&journal_path).expect("重开取消后的 journal");
    let record = reopened
        .operation(operation)
        .expect("读取重开后的操作")
        .expect("取消操作必须保留");
    assert_eq!(record.state, OperationState::Aborted);
    assert_eq!(
        record.error.as_ref().map(|detail| detail.code.as_str()),
        Some("operation.cancelled"),
        "重开后必须保留取消原因"
    );
}

/// 若 UI 的取消请求与“关闭发布窗口”竞争，core 必须优先中止。这样 UI 得到 `requested`
/// 响应就意味着 CAS 尚未发生，而不是一个无效的乐观提示。
#[test]
fn cancellation_racing_with_publish_window_aborts_before_cas() {
    struct CancelAtPublishBoundary;

    impl ApplyCancellation for CancelAtPublishBoundary {
        fn is_cancelled(&self) -> bool {
            false
        }

        fn close_cancellation_window(&self) -> bool {
            false
        }
    }

    let mut harness = Harness::new();
    let plan = three_write_plan(&harness);
    let operation = "22345678-1234-4234-8234-123456789abc"
        .parse()
        .expect("固定 operation 标识有效");
    let mutator = FakeMutator::new();
    let error = {
        let mut engine = ApplyEngine::new(
            &harness.backend,
            &mutator,
            &mut harness.journal,
            &harness.blobs,
        );
        engine
            .apply_with_operation(&plan, operation, &CancelAtPublishBoundary)
            .expect_err("发布窗口竞争时必须取消")
    };

    assert_eq!(error.code(), "operation.cancelled");
    assert_eq!(harness.revision(), 0, "取消不得推进 CAS");
    assert_eq!(mutator.apply_count(), 0, "取消不得写入本地文件");
    assert_eq!(
        state_of(&harness.journal, operation),
        OperationState::Aborted
    );
}

// ---------------------------------------------------------------------------
// 3：CAS 冲突
// ---------------------------------------------------------------------------

/// 计划文档任务 10 第 3 条：CAS 失败时**没有调用 FileMutator** 的任何写入方法。
///
/// 这是设计文档 §12「CAS 冲突时本地文件没有任何变化」验收条件的直接实现：冲突必须发生
/// 在本地变更之前。
#[test]
fn cas_conflict_never_invokes_the_file_mutator() {
    let mut harness = Harness::new();
    let plan = three_write_plan(&harness);

    // 抢先把后端 Ref 推到 revision 1，让计划里 base_revision = 0 的 CAS 必然冲突。
    let winner = WorkspaceRef::initial(workspace_id()).advance(SnapshotId::of(b"someone-else"));
    harness
        .backend
        .compare_and_swap_ref(workspace_id(), 0, &winner)
        .expect("另一台设备先发布成功");
    assert_eq!(harness.revision(), 1);

    let mutator = FakeMutator::new();
    let error = {
        let mut engine = ApplyEngine::new(
            &harness.backend,
            &mutator,
            &mut harness.journal,
            &harness.blobs,
        );
        engine.apply(&plan).expect_err("CAS 必须冲突")
    };

    assert!(
        error.is_cas_conflict(),
        "错误必须被识别为 CAS 冲突：{error}"
    );
    assert_eq!(error.code(), "backend.cas_conflict");
    assert_eq!(mutator.apply_count(), 0, "CAS 失败时不得调用 apply");
    assert!(
        mutator.rolled_back().is_empty(),
        "CAS 失败时不得调用 rollback"
    );
    assert_eq!(
        harness.backend.get_ref(workspace_id()).unwrap().head,
        winner.head,
        "失败方不得覆盖胜出方的头"
    );
    assert_eq!(
        state_of(&harness.journal, harness.only_operation()),
        OperationState::Aborted
    );
}

// ---------------------------------------------------------------------------
// 4：逐项落收据
// ---------------------------------------------------------------------------

/// 计划文档任务 10 第 4 条：Publish 后动作依序应用并逐项保存 receipt。
///
/// 断言两件事：`apply` 的调用顺序与计划顺序一致；journal 里的收据 ordinal 恰好是
/// `0,1,2` 且与对应动作的资源一致——回滚要靠它逆序消费，顺序错了就会还原错文件。
#[test]
fn receipts_are_persisted_in_action_order() {
    let mut harness = Harness::new();
    let plan = three_write_plan(&harness);
    let mutator = FakeMutator::new();

    let operation = {
        let mut engine = ApplyEngine::new(
            &harness.backend,
            &mutator,
            &mut harness.journal,
            &harness.blobs,
        );
        match engine.apply(&plan).expect("成功路径") {
            ApplyOutcome::Completed { operation, .. } => operation,
            other => panic!("期望 Completed，实际 {other:?}"),
        }
    };

    assert_eq!(
        mutator.applied(),
        vec!["a/one", "b/two", "c/three"],
        "动作必须按计划顺序依次应用"
    );

    let receipts = harness.journal.receipts(operation).expect("读取收据");
    let ordinals: Vec<u32> = receipts.iter().map(|r| r.receipt.ordinal).collect();
    assert_eq!(ordinals, vec![0, 1, 2], "收据必须逐项保存且序号连续");
    let resources: Vec<String> = receipts
        .iter()
        .map(|r| r.receipt.resource.to_string())
        .collect();
    assert_eq!(resources, vec!["a/one", "b/two", "c/three"]);
    for (index, record) in receipts.iter().enumerate() {
        assert_eq!(
            record.receipt.applied_digest, plan.actions[index].expected_after,
            "收据里的应用后摘要必须与动作一致"
        );
    }

    // 全部动作都必须被登记为已应用。
    let states: Vec<envsync_storage::ActionState> = harness
        .journal
        .actions(operation)
        .expect("读取动作")
        .into_iter()
        .map(|record| record.state)
        .collect();
    assert!(states
        .iter()
        .all(|state| *state == envsync_storage::ActionState::Applied));
}

// ---------------------------------------------------------------------------
// 5：中途失败逆序回滚
// ---------------------------------------------------------------------------

/// 计划文档任务 10 第 5 条：中途失败时已应用动作**逆序**回滚。
///
/// 让第三个动作的 apply 失败，此时前两个已经生效；回滚顺序必须是 `b/two`、`a/one`。
/// 逆序是必要的：动作之间可能存在依赖（例如先写 include 目标再改主配置），顺序回滚
/// 会让中间态短暂不自洽。
#[test]
fn failure_midway_rolls_back_applied_actions_in_reverse_order() {
    let mut harness = Harness::new();
    let plan = three_write_plan(&harness);
    let mutator = FakeMutator::new().fail_apply("c/three");

    let error = {
        let mut engine = ApplyEngine::new(
            &harness.backend,
            &mutator,
            &mut harness.journal,
            &harness.blobs,
        );
        engine.apply(&plan).expect_err("第三个动作失败")
    };
    assert!(error.to_string().contains(FAKE_APPLY_FAILURE));

    assert_eq!(mutator.applied(), vec!["a/one", "b/two", "c/three"]);
    assert_eq!(
        mutator.rolled_back(),
        vec!["b/two", "a/one"],
        "已应用的动作必须逆序回滚；失败的第三个动作没有生效，不参与回滚"
    );

    let operation = harness.only_operation();
    assert_eq!(
        state_of(&harness.journal, operation),
        OperationState::RolledBack,
        "回滚成功后应当停在 rolled_back 终态"
    );
    assert!(error_message_of(&harness.journal, operation).contains(FAKE_APPLY_FAILURE));
}

// ---------------------------------------------------------------------------
// 6：verify 失败
// ---------------------------------------------------------------------------

/// 计划文档任务 10 第 6 条：verify 失败时**当前动作和此前动作全部**回滚。
///
/// 第二个动作写入成功但校验不过——它已经改动了文件，因此必须连同它自己一起回滚。
#[test]
fn verify_failure_rolls_back_current_and_previous_actions() {
    let mut harness = Harness::new();
    let plan = three_write_plan(&harness);
    let mutator = FakeMutator::new().fail_verify("b/two");

    let error = {
        let mut engine = ApplyEngine::new(
            &harness.backend,
            &mutator,
            &mut harness.journal,
            &harness.blobs,
        );
        engine.apply(&plan).expect_err("verify 失败")
    };
    assert_eq!(error.code(), "platform.verification_failed");

    assert_eq!(
        mutator.applied(),
        vec!["a/one", "b/two"],
        "verify 失败后不得继续应用后面的动作"
    );
    assert_eq!(
        mutator.rolled_back(),
        vec!["b/two", "a/one"],
        "verify 失败的当前动作也已经改过文件，必须一并逆序回滚"
    );
    assert_eq!(
        state_of(&harness.journal, harness.only_operation()),
        OperationState::RolledBack
    );
}

// ---------------------------------------------------------------------------
// 7：回滚也失败
// ---------------------------------------------------------------------------

/// 计划文档任务 10 第 7 条：回滚失败保留 `published_not_converged` 及**双重错误**。
///
/// 后端已经声称新快照是当前头，而本地既没收敛也没回滚干净——这不是普通失败，绝不能
/// 降级成 `rolled_back`。journal 的错误信息里必须同时保留「应用为什么失败」和
/// 「回滚为什么失败」，否则人工介入时无从判断现场。
#[test]
fn rollback_failure_keeps_published_not_converged_with_both_errors() {
    let mut harness = Harness::new();
    let plan = three_write_plan(&harness);
    let mutator = FakeMutator::new()
        .fail_apply("c/three")
        .fail_rollback("a/one");

    let error = {
        let mut engine = ApplyEngine::new(
            &harness.backend,
            &mutator,
            &mut harness.journal,
            &harness.blobs,
        );
        engine.apply(&plan).expect_err("应用与回滚都失败")
    };

    assert!(
        error.is_partial_convergence(),
        "必须是 published_not_converged 而不是普通失败：{error}"
    );
    assert_eq!(error.code(), "sync.published_not_converged");
    assert!(error.to_string().contains(FAKE_APPLY_FAILURE));
    assert!(error.to_string().contains(FAKE_ROLLBACK_FAILURE));

    let operation = harness.only_operation();
    assert_eq!(
        state_of(&harness.journal, operation),
        OperationState::PublishedNotConverged
    );
    let recorded = error_message_of(&harness.journal, operation);
    assert!(
        recorded.contains(FAKE_APPLY_FAILURE),
        "journal 必须保留应用失败原因：{recorded}"
    );
    assert!(
        recorded.contains(FAKE_ROLLBACK_FAILURE),
        "journal 必须保留回滚失败原因：{recorded}"
    );
    assert!(recorded.contains("sync.published_not_converged"));

    // 后端已经发布过：状态确实是「已发布未收敛」，而不是「什么都没发生」。
    assert_eq!(harness.revision(), 1);
}

// ---------------------------------------------------------------------------
// 补充：阻塞计划 / 空计划 / 删除动作
// ---------------------------------------------------------------------------

/// 计划含阻塞诊断时 `apply` 直接返回 `PlanBlocked`，且 journal 里**没有**任何操作记录。
///
/// 被策略拒绝的计划不应该在日志里留下一条永远不会推进的操作，否则每次恢复都会看到它。
#[test]
fn blocked_plan_is_rejected_without_touching_the_journal() {
    let mut harness = Harness::new();
    let (blob, after) = harness.content(b"content-a\n");
    let plan = plan_of_with(
        vec![write_action("a/one", "a.txt", None, after, blob)],
        vec![Diagnostic::blocking(
            "resource.unreadable",
            Some(support::rid("a/one")),
            "权限不足，无法确定当前内容",
        )],
        0,
        true,
    );

    let mutator = FakeMutator::new();
    let error = {
        let mut engine = ApplyEngine::new(
            &harness.backend,
            &mutator,
            &mut harness.journal,
            &harness.blobs,
        );
        engine.apply(&plan).expect_err("阻塞计划必须被拒绝")
    };

    assert!(error.is_policy_block(), "必须是策略阻塞：{error}");
    assert_eq!(error.code(), "plan.blocked");
    assert!(matches!(error, CoreError::PlanBlocked { count: 1, .. }));

    assert!(mutator.calls().is_empty(), "阻塞计划不得触碰 FileMutator");
    assert_eq!(harness.revision(), 0, "阻塞计划不得发布");
    assert!(
        journal_is_empty(&harness.journal),
        "阻塞计划不得在 journal 里留下操作记录"
    );
}

/// 没有动作且无需发布的计划是纯粹的 no-op：不登记操作，不触碰后端。
#[test]
fn empty_plan_without_publish_is_a_noop() {
    let mut harness = Harness::new();
    let base_ref = WorkspaceRef::initial(workspace_id());
    let plan = Plan::new(
        workspace_id(),
        support::device_id(),
        SnapshotId::of(b"noop"),
        base_ref.revision,
        base_ref,
        vec![],
        vec![],
        vec![],
        support::FIXED_NOW,
    );

    let mutator = FakeMutator::new();
    let outcome = {
        let mut engine = ApplyEngine::new(
            &harness.backend,
            &mutator,
            &mut harness.journal,
            &harness.blobs,
        );
        engine.apply(&plan).expect("no-op 必须成功")
    };

    assert_eq!(outcome, ApplyOutcome::NoOp);
    assert!(mutator.calls().is_empty());
    assert!(journal_is_empty(&harness.journal));
}

/// 删除动作同样进入完整事务：登记、应用、落收据、验证。
#[test]
fn delete_action_goes_through_the_same_transaction() {
    let mut harness = Harness::new();
    let before = digest_of(b"to-be-removed\n");
    let plan = plan_of(
        vec![delete_action("z/legacy", "legacy.conf", before)],
        0,
        true,
    );

    let mutator = FakeMutator::new();
    let operation = {
        let mut engine = ApplyEngine::new(
            &harness.backend,
            &mutator,
            &mut harness.journal,
            &harness.blobs,
        );
        match engine.apply(&plan).expect("删除路径应当成功") {
            ApplyOutcome::Completed { operation, .. } => operation,
            other => panic!("期望 Completed，实际 {other:?}"),
        }
    };

    let receipts = harness.journal.receipts(operation).expect("读取收据");
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].receipt.original_digest,
        Some(before),
        "删除必须记录被删内容的摘要，否则无法还原"
    );
    assert_eq!(receipts[0].receipt.applied_digest, None);
    assert!(receipts[0].receipt.backup_path.is_some(), "删除前必须备份");
    assert_eq!(
        state_of(&harness.journal, operation),
        OperationState::Completed
    );
}

/// 动作内容与 `BlobId` 不符时在 preflight 阶段就被拒绝，绝不写入。
///
/// 内容寻址自校验：草稿库或后端返回的字节必须确实是计划里那一份。
#[test]
fn preflight_rejects_content_that_does_not_match_its_blob_id() {
    let mut harness = Harness::new();
    // 计划声称写入 `真内容`，但 Blob 源里只有一个标识对不上的条目。
    let lying_blob = BlobId::of(b"real-content\n");
    harness.blobs.insert(b"tampered-content\n");
    let plan = plan_of(
        vec![write_action(
            "a/one",
            "a.txt",
            None,
            digest_of(b"real-content\n"),
            lying_blob,
        )],
        0,
        true,
    );

    let mutator = FakeMutator::new();
    let error = {
        let mut engine = ApplyEngine::new(
            &harness.backend,
            &mutator,
            &mut harness.journal,
            &harness.blobs,
        );
        engine.apply(&plan).expect_err("内容缺失必须失败")
    };

    assert_eq!(error.code(), "object.missing");
    assert_eq!(mutator.apply_count(), 0);
    assert_eq!(harness.revision(), 0, "preflight 失败不得发布");
    assert_eq!(
        state_of(&harness.journal, harness.only_operation()),
        OperationState::Aborted
    );
}
