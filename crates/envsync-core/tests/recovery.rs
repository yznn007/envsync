//! 任务 13：崩溃恢复与显式回滚的验收测试。
//!
//! 构造中断状态的方法与计划文档一致：**直接用 [`Journal`] 的 API 把操作驱动到目标
//! 状态，再手工摆好文件系统现场**。这样可以精确复现「进程在第 N 步被杀死」的各种
//! 处境，而不必真的去 kill 一个进程。
//!
//! 组件搭配：
//!
//! * 真实 [`Journal`]（tempdir 上的 SQLite）——恢复的事实来源必须是真的；
//! * 真实 `PlatformObserver` / `PlatformMutator`（tempdir 授权根）——「不覆盖用户修改」
//!   「备份摘要不符就拒绝」这些断言只有在真实读写下才有意义；
//! * 内存 `BlobSource` / `PlanSource`——它们只是查表，用 fake 可以让用例聚焦。
//!
//! 覆盖计划文档任务 13 的测试矩阵，外加「恢复算法幂等」与「`doctor` 只报告」。

mod support;

use std::path::PathBuf;
use std::sync::Arc;

use envsync_backend::{Backend, LocalBackend};
use envsync_core::error::CoreError;
use envsync_core::ports::platform::{PlatformMutator, PlatformObserver};
use envsync_core::ports::{Clock, FixedClock};
use envsync_core::recovery::{RecoveryEngine, RecoveryReport, RecoverySuggestion};
use envsync_core::service::EnvSyncService;
use envsync_domain::{
    Action, DesiredDisposition, FileMode, OperationId, Plan, SnapshotId, WorkspaceRef,
};
use envsync_platform::{AuthorizedRoot, RootRegistry, SafeWriter, TEMP_FILE_PREFIX};
use envsync_storage::{ActionState, Journal, OperationState, Receipt};

use support::{
    digest_of, plan_of, rid, state_of, workspace_config, workspace_id, write_action, FakeBlobs,
    FakeMutator, FakeObserver, FakePlans, FIXED_NOW, SEED_A,
};

/// 一次恢复测试所需的全部组件。
struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    journal: Journal,
    observer: PlatformObserver,
    mutator: PlatformMutator,
    backend: LocalBackend,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("创建临时目录");
        let home = dir.path().join("home");
        let state = dir.path().join("state");
        std::fs::create_dir_all(&home).expect("创建授权根");
        std::fs::create_dir_all(&state).expect("创建状态目录");

        let mut registry = RootRegistry::new();
        registry.insert(AuthorizedRoot::open("home", &home).expect("打开授权根"));
        let roots = Arc::new(registry);

        let clock: Arc<dyn Clock> = Arc::new(FixedClock(FIXED_NOW));
        let observer = PlatformObserver::new(Arc::clone(&roots), clock);
        let mutator = PlatformMutator::new(roots, SafeWriter::new(state.join("backups")));

        Fixture {
            journal: Journal::open(state.join("journal.db")).expect("打开 journal"),
            observer,
            mutator,
            backend: LocalBackend::open(dir.path().join("backend")).expect("打开后端"),
            home,
            _dir: dir,
        }
    }

    fn write(&self, name: &str, content: &str) {
        std::fs::write(self.home.join(name), content).expect("写入测试文件");
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.home.join(name)).expect("读取测试文件")
    }

    fn exists(&self, name: &str) -> bool {
        self.home.join(name).exists()
    }

    /// 登记操作并按给定顺序驱动状态机。
    fn begin(&mut self, plan: &Plan, path: &[OperationState]) -> OperationId {
        let record = self.journal.begin(plan).expect("登记操作");
        for state in path {
            self.journal
                .transition(record.operation, *state)
                .expect("驱动状态机");
        }
        record.operation
    }

    /// 写入一条真实可用的收据：备份文件落到确定性路径，内容就是「应用前的原字节」。
    fn record_receipt_with_backup(
        &mut self,
        operation: OperationId,
        ordinal: u32,
        resource: &str,
        original: &str,
        applied: &str,
    ) {
        let resource_id = rid(resource);
        let path = self
            .mutator
            .writer()
            .backup_path_for(operation, &resource_id);
        std::fs::create_dir_all(path.parent().expect("备份目录")).expect("创建备份目录");
        std::fs::write(&path, original).expect("写入备份");
        self.journal
            .record_receipt(
                operation,
                &Receipt {
                    ordinal,
                    resource: resource_id,
                    backup_path: Some(path.display().to_string()),
                    original_digest: Some(digest_of(original.as_bytes())),
                    applied_digest: Some(digest_of(applied.as_bytes())),
                    guarantee: envsync_domain::RollbackCapability::Exact,
                },
            )
            .expect("保存收据");
    }

    /// 用真实观察器与变更器跑一次完整恢复。
    fn recover(&mut self, plans: &FakePlans, blobs: &FakeBlobs) -> Vec<RecoveryReport> {
        let mut engine = RecoveryEngine::new(
            &mut self.journal,
            plans,
            blobs,
            &self.observer,
            &self.mutator,
        );
        engine.recover_all().expect("恢复流程本身不应失败")
    }
}

/// 构造一个「把 `file` 从 `before` 改写成 `after`」的动作，并把内容放进 Blob 源。
fn action(
    blobs: &FakeBlobs,
    resource: &str,
    file: &str,
    before: Option<&str>,
    after: &str,
) -> Action {
    let blob = blobs.insert(after.as_bytes());
    write_action(
        resource,
        file,
        before.map(|text| digest_of(text.as_bytes())),
        digest_of(after.as_bytes()),
        blob,
    )
}

/// 把计划登记到内存计划源。
fn register(plans: &FakePlans, plan: &Plan) -> Plan {
    plans.insert(plan);
    plan.clone()
}

const OLD: &str = "export EDITOR=nvim\n";
const NEW: &str = "export EDITOR=helix\n";
const USER_EDIT: &str = "export EDITOR=emacs # 我自己改的\n";

// ---------------------------------------------------------------------------
// preflighted
// ---------------------------------------------------------------------------

/// 矩阵第 1 行：`preflighted` —— 清理 staged 文件，标记 aborted。
///
/// 尚未发布就崩溃，说明后端 Ref 一定没动过，本地也只可能留下同目录临时文件。
/// 正确的善后是把临时文件清掉、把操作标为 aborted，绝不能推进任何写入。
#[test]
fn preflighted_operation_cleans_staged_files_and_aborts() {
    let mut fx = Fixture::new();
    let blobs = FakeBlobs::new();
    let plans = FakePlans::new();

    fx.write(".zshrc", OLD);
    let plan = register(
        &plans,
        &plan_of(
            vec![action(&blobs, "shell/zsh/main", ".zshrc", Some(OLD), NEW)],
            0,
            true,
        ),
    );
    let operation = fx.begin(&plan, &[OperationState::Preflighted]);

    // 手工摆出「暂存文件已就绪但还没 rename」的现场。
    let staged = fx.home.join(format!(
        "{TEMP_FILE_PREFIX}{}-0001",
        operation.to_filename()
    ));
    std::fs::write(&staged, NEW).expect("放置暂存文件");
    assert!(staged.exists());

    let reports = fx.recover(&plans, &blobs);

    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].before, OperationState::Preflighted);
    assert_eq!(reports[0].after, OperationState::Aborted);
    assert!(
        reports[0].notes.iter().any(|note| note.contains("1")),
        "报告里应当说明清理了几个暂存文件：{:?}",
        reports[0].notes
    );
    assert!(!staged.exists(), "暂存文件必须被清理");
    assert_eq!(fx.read(".zshrc"), OLD, "未发布的操作绝不能改动目标文件");
    assert_eq!(state_of(&fx.journal, operation), OperationState::Aborted);
}

// ---------------------------------------------------------------------------
// published
// ---------------------------------------------------------------------------

/// 矩阵第 2 行：`published` —— 重新收敛本地，**不重复 CAS**。
///
/// 后端 Ref 已经前进过了；恢复要做的只是把本地补上。恢复引擎根本不持有 Backend，
/// 这里通过「恢复前后 revision 完全相同」把这一点变成可断言的事实。
#[test]
fn published_operation_reconverges_without_publishing_again() {
    let mut fx = Fixture::new();
    let blobs = FakeBlobs::new();
    let plans = FakePlans::new();

    // 模拟崩溃前已经成功发布：后端 revision 已经是 1。
    let published_ref = WorkspaceRef::initial(workspace_id()).advance(SnapshotId::of(b"published"));
    fx.backend
        .compare_and_swap_ref(workspace_id(), 0, &published_ref)
        .expect("模拟已完成的发布");
    assert_eq!(fx.backend.get_ref(workspace_id()).unwrap().revision, 1);

    fx.write(".zshrc", OLD);
    let plan = register(
        &plans,
        &plan_of(
            vec![action(&blobs, "shell/zsh/main", ".zshrc", Some(OLD), NEW)],
            0,
            true,
        ),
    );
    let operation = fx.begin(
        &plan,
        &[OperationState::Preflighted, OperationState::Published],
    );

    let reports = fx.recover(&plans, &blobs);

    assert_eq!(reports[0].before, OperationState::Published);
    assert_eq!(reports[0].after, OperationState::Completed);
    assert_eq!(fx.read(".zshrc"), NEW, "本地必须补上收敛");
    assert_eq!(state_of(&fx.journal, operation), OperationState::Completed);
    assert_eq!(
        fx.backend.get_ref(workspace_id()).unwrap().revision,
        1,
        "恢复绝不能再做一次 CAS"
    );
    assert_eq!(
        fx.journal.receipts(operation).unwrap().len(),
        1,
        "重新应用的动作必须留下收据"
    );
}

// ---------------------------------------------------------------------------
// applying：三种判据
// ---------------------------------------------------------------------------

/// 矩阵第 3、4 行：`applying` 时按目标当前摘要分流——
/// 等于 applied digest 就跳过并继续下一个动作，等于 original digest 就重新应用。
#[test]
fn applying_skips_finished_actions_and_reapplies_pending_ones() {
    let mut fx = Fixture::new();
    let blobs = FakeBlobs::new();
    let plans = FakePlans::new();

    // a/one 已经生效（磁盘等于 NEW），b/two 还没有（磁盘仍是 OLD）。
    fx.write("a.txt", NEW);
    fx.write("b.txt", OLD);
    let plan = register(
        &plans,
        &plan_of(
            vec![
                action(&blobs, "a/one", "a.txt", Some(OLD), NEW),
                action(&blobs, "b/two", "b.txt", Some(OLD), NEW),
            ],
            0,
            true,
        ),
    );
    let operation = fx.begin(
        &plan,
        &[
            OperationState::Preflighted,
            OperationState::Published,
            OperationState::Applying,
        ],
    );

    let reports = fx.recover(&plans, &blobs);

    assert_eq!(reports[0].before, OperationState::Applying);
    assert_eq!(reports[0].after, OperationState::Completed);
    assert!(
        reports[0]
            .notes
            .iter()
            .any(|note| note.contains("重新应用了 1 个动作")),
        "只应重新应用尚未生效的那一个：{:?}",
        reports[0].notes
    );

    assert_eq!(fx.read("a.txt"), NEW);
    assert_eq!(fx.read("b.txt"), NEW, "尚未生效的动作必须被重新应用");

    // 「跳过」的证据：只有被重新应用的动作留下了收据。
    let receipts = fx.journal.receipts(operation).unwrap();
    let ordinals: Vec<u32> = receipts.iter().map(|r| r.receipt.ordinal).collect();
    assert_eq!(
        ordinals,
        vec![1],
        "已生效的动作不应被重新应用，也就没有新收据"
    );

    // 但两个动作都必须被登记为已应用，否则下一次恢复会重复处理。
    let states: Vec<ActionState> = fx
        .journal
        .actions(operation)
        .unwrap()
        .into_iter()
        .map(|record| record.state)
        .collect();
    assert_eq!(states, vec![ActionState::Applied, ActionState::Applied]);
}

/// 矩阵第 4 行的单动作版本：目标等于 original digest 时重新应用当前动作。
#[test]
fn applying_reapplies_an_action_that_never_took_effect() {
    let mut fx = Fixture::new();
    let blobs = FakeBlobs::new();
    let plans = FakePlans::new();

    fx.write(".zshrc", OLD);
    let plan = register(
        &plans,
        &plan_of(
            vec![action(&blobs, "shell/zsh/main", ".zshrc", Some(OLD), NEW)],
            0,
            true,
        ),
    );
    let operation = fx.begin(
        &plan,
        &[
            OperationState::Preflighted,
            OperationState::Published,
            OperationState::Applying,
        ],
    );

    fx.recover(&plans, &blobs);

    assert_eq!(fx.read(".zshrc"), NEW);
    assert_eq!(state_of(&fx.journal, operation), OperationState::Completed);
}

/// 矩阵第 5 行：目标两者都不等 —— **停止**并报告人工冲突，绝不覆盖用户的修改。
///
/// 这是恢复流程里最危险的一格：崩溃期间用户自己动过这个文件。任何「按计划继续写」
/// 的行为都会静默抹掉他的修改，因此唯一安全的做法是停下来交给人。
#[test]
fn diverged_target_stops_and_never_overwrites_user_changes() {
    let mut fx = Fixture::new();
    let blobs = FakeBlobs::new();
    let plans = FakePlans::new();

    // 磁盘内容既不是 OLD 也不是 NEW：崩溃期间被用户改过。
    fx.write(".zshrc", USER_EDIT);
    let plan = register(
        &plans,
        &plan_of(
            vec![action(&blobs, "shell/zsh/main", ".zshrc", Some(OLD), NEW)],
            0,
            true,
        ),
    );
    let operation = fx.begin(
        &plan,
        &[
            OperationState::Preflighted,
            OperationState::Published,
            OperationState::Applying,
        ],
    );

    let reports = fx.recover(&plans, &blobs);

    assert_eq!(reports[0].after, OperationState::PublishedNotConverged);
    assert!(
        reports[0]
            .notes
            .iter()
            .any(|note| note.contains("需要人工处理")),
        "必须明确报告人工冲突：{:?}",
        reports[0].notes
    );
    assert_eq!(
        fx.read(".zshrc"),
        USER_EDIT,
        "用户在崩溃期间的修改绝不能被覆盖"
    );
    assert_eq!(
        state_of(&fx.journal, operation),
        OperationState::PublishedNotConverged,
        "必须停在可诊断的未收敛状态，而不是被标为完成"
    );
    let record = fx.journal.operation(operation).unwrap().unwrap();
    assert_eq!(
        record.error.as_ref().map(|detail| detail.code.as_str()),
        Some("recovery.manual_required")
    );
}

// ---------------------------------------------------------------------------
// rolling_back
// ---------------------------------------------------------------------------

/// 矩阵第 6 行：`rolling_back` —— 根据 receipt 继续回滚，并且真的还原了原字节。
#[test]
fn rolling_back_restores_original_bytes_from_receipts() {
    let mut fx = Fixture::new();
    let blobs = FakeBlobs::new();
    let plans = FakePlans::new();

    // 两个动作都已经生效（磁盘是 NEW），随后事务决定回滚。
    fx.write("a.txt", NEW);
    fx.write("b.txt", NEW);
    let plan = register(
        &plans,
        &plan_of(
            vec![
                action(&blobs, "a/one", "a.txt", Some(OLD), NEW),
                action(&blobs, "b/two", "b.txt", Some(OLD), NEW),
            ],
            0,
            true,
        ),
    );
    let operation = fx.begin(
        &plan,
        &[
            OperationState::Preflighted,
            OperationState::Published,
            OperationState::Applying,
        ],
    );
    fx.record_receipt_with_backup(operation, 0, "a/one", OLD, NEW);
    fx.record_receipt_with_backup(operation, 1, "b/two", OLD, NEW);
    fx.journal
        .transition(operation, OperationState::RollingBack)
        .expect("进入回滚");

    let reports = fx.recover(&plans, &blobs);

    assert_eq!(reports[0].before, OperationState::RollingBack);
    assert_eq!(reports[0].after, OperationState::RolledBack);
    assert_eq!(fx.read("a.txt"), OLD, "必须精确还原为备份里的原字节");
    assert_eq!(fx.read("b.txt"), OLD);
    assert_eq!(state_of(&fx.journal, operation), OperationState::RolledBack);
}

/// 矩阵第 6 行的顺序断言：回滚必须按收据**逆序**进行。
///
/// 顺序无法从真实文件系统的最终状态观察出来，因此这一条改用内存 fake：观察器不提供
/// 任何文件（当前摘要为 `None`，与收据的 original digest 不等，因此每条收据都会真的
/// 触发一次回滚），变更器逐条记录调用顺序。
#[test]
fn rolling_back_consumes_receipts_in_reverse_order() {
    let mut fx = Fixture::new();
    let blobs = FakeBlobs::new();
    let plans = FakePlans::new();

    let plan = register(
        &plans,
        &plan_of(
            vec![
                action(&blobs, "a/one", "a.txt", Some(OLD), NEW),
                action(&blobs, "b/two", "b.txt", Some(OLD), NEW),
                action(&blobs, "c/three", "c.txt", Some(OLD), NEW),
            ],
            0,
            true,
        ),
    );
    let operation = fx.begin(
        &plan,
        &[
            OperationState::Preflighted,
            OperationState::Published,
            OperationState::Applying,
        ],
    );
    for (ordinal, resource) in ["a/one", "b/two", "c/three"].into_iter().enumerate() {
        fx.record_receipt_with_backup(operation, ordinal as u32, resource, OLD, NEW);
    }
    fx.journal
        .transition(operation, OperationState::RollingBack)
        .expect("进入回滚");

    let observer = FakeObserver::new();
    let mutator = FakeMutator::new();
    {
        let mut engine = RecoveryEngine::new(&mut fx.journal, &plans, &blobs, &observer, &mutator);
        engine.recover_all().expect("恢复流程本身不应失败");
    }

    assert_eq!(
        mutator.rolled_back(),
        vec!["c/three", "b/two", "a/one"],
        "回滚必须严格按收据逆序进行"
    );
    assert_eq!(state_of(&fx.journal, operation), OperationState::RolledBack);
}

// ---------------------------------------------------------------------------
// 备份缺失 / 摘要不符
// ---------------------------------------------------------------------------

/// 矩阵第 7 行：备份缺失时不覆盖，保留可诊断状态。
#[test]
fn missing_backup_refuses_rollback_and_keeps_a_diagnosable_state() {
    let mut fx = Fixture::new();
    let blobs = FakeBlobs::new();
    let plans = FakePlans::new();

    fx.write(".zshrc", NEW);
    let plan = register(
        &plans,
        &plan_of(
            vec![action(&blobs, "shell/zsh/main", ".zshrc", Some(OLD), NEW)],
            0,
            true,
        ),
    );
    let operation = fx.begin(
        &plan,
        &[
            OperationState::Preflighted,
            OperationState::Published,
            OperationState::Applying,
        ],
    );
    // 收据声称有备份，但备份文件根本不存在（例如备份目录被清理脚本删掉了）。
    fx.journal
        .record_receipt(
            operation,
            &Receipt {
                ordinal: 0,
                resource: rid("shell/zsh/main"),
                backup_path: Some(
                    fx.home
                        .join("..")
                        .join("missing-backup")
                        .display()
                        .to_string(),
                ),
                original_digest: Some(digest_of(OLD.as_bytes())),
                applied_digest: Some(digest_of(NEW.as_bytes())),
                guarantee: envsync_domain::RollbackCapability::Exact,
            },
        )
        .expect("保存收据");
    fx.journal
        .transition(operation, OperationState::RollingBack)
        .expect("进入回滚");

    let reports = fx.recover(&plans, &blobs);

    assert_eq!(
        reports[0].after,
        OperationState::PublishedNotConverged,
        "回滚失败必须停在未收敛状态，绝不能降级为普通终态"
    );
    assert_eq!(fx.read(".zshrc"), NEW, "备份不可用时绝不能乱写目标文件");
    let record = fx.journal.operation(operation).unwrap().unwrap();
    let detail = record.error.expect("必须留下可诊断的错误");
    assert_eq!(detail.code, "sync.published_not_converged");
    assert!(
        detail.message.contains("回滚失败"),
        "错误信息必须说明是回滚阶段出的问题：{}",
        detail.message
    );
}

/// 矩阵第 7 行的另一半：备份内容摘要与收据不符时同样拒绝回滚。
#[test]
fn corrupted_backup_refuses_rollback() {
    let mut fx = Fixture::new();
    let blobs = FakeBlobs::new();
    let plans = FakePlans::new();

    fx.write(".zshrc", NEW);
    let plan = register(
        &plans,
        &plan_of(
            vec![action(&blobs, "shell/zsh/main", ".zshrc", Some(OLD), NEW)],
            0,
            true,
        ),
    );
    let operation = fx.begin(
        &plan,
        &[
            OperationState::Preflighted,
            OperationState::Published,
            OperationState::Applying,
        ],
    );
    // 备份文件存在，但内容被改坏了：摘要与收据记录的 original_digest 不符。
    fx.record_receipt_with_backup(operation, 0, "shell/zsh/main", OLD, NEW);
    let backup = fx
        .mutator
        .writer()
        .backup_path_for(operation, &rid("shell/zsh/main"));
    std::fs::write(&backup, "被外部工具改坏的备份\n").expect("破坏备份");
    fx.journal
        .transition(operation, OperationState::RollingBack)
        .expect("进入回滚");

    let reports = fx.recover(&plans, &blobs);

    assert_eq!(reports[0].after, OperationState::PublishedNotConverged);
    assert_eq!(
        fx.read(".zshrc"),
        NEW,
        "宁可保持现状，也绝不用摘要不符的备份覆盖目标"
    );
    assert!(fx.exists(".zshrc"));
}

// ---------------------------------------------------------------------------
// 幂等
// ---------------------------------------------------------------------------

/// 恢复算法必须幂等：连续运行两次得到相同最终状态（成功收敛的分支）。
#[test]
fn recovery_is_idempotent_on_the_converging_path() {
    let mut fx = Fixture::new();
    let blobs = FakeBlobs::new();
    let plans = FakePlans::new();

    fx.write(".zshrc", OLD);
    let plan = register(
        &plans,
        &plan_of(
            vec![action(&blobs, "shell/zsh/main", ".zshrc", Some(OLD), NEW)],
            0,
            true,
        ),
    );
    let operation = fx.begin(
        &plan,
        &[
            OperationState::Preflighted,
            OperationState::Published,
            OperationState::Applying,
        ],
    );

    fx.recover(&plans, &blobs);
    let state_after_first = state_of(&fx.journal, operation);
    let content_after_first = fx.read(".zshrc");

    let second = fx.recover(&plans, &blobs);

    assert!(
        second.is_empty(),
        "已经进入终态的操作不应再被处理：{second:?}"
    );
    assert_eq!(state_of(&fx.journal, operation), state_after_first);
    assert_eq!(fx.read(".zshrc"), content_after_first);
    assert_eq!(state_after_first, OperationState::Completed);
}

/// 恢复算法必须幂等：人工冲突分支连续运行两次也必须停在同一个状态。
///
/// 这条尤其重要——`published_not_converged` **不是**终态，每次 `sync` 启动都会再跑一次
/// 恢复。如果第二次运行把状态留在别处（例如卡在 `applying`），`status` 就会给出与第一次
/// 不同的答案，人工处理时无从判断现场。
#[test]
fn recovery_is_idempotent_on_the_manual_conflict_path() {
    let mut fx = Fixture::new();
    let blobs = FakeBlobs::new();
    let plans = FakePlans::new();

    fx.write(".zshrc", USER_EDIT);
    let plan = register(
        &plans,
        &plan_of(
            vec![action(&blobs, "shell/zsh/main", ".zshrc", Some(OLD), NEW)],
            0,
            true,
        ),
    );
    let operation = fx.begin(
        &plan,
        &[
            OperationState::Preflighted,
            OperationState::Published,
            OperationState::Applying,
        ],
    );

    let first = fx.recover(&plans, &blobs);
    let state_after_first = state_of(&fx.journal, operation);
    let content_after_first = fx.read(".zshrc");

    let second = fx.recover(&plans, &blobs);

    assert_eq!(first[0].after, OperationState::PublishedNotConverged);
    assert_eq!(
        second[0].after,
        OperationState::PublishedNotConverged,
        "第二次恢复的结论必须与第一次一致"
    );
    assert_eq!(
        state_of(&fx.journal, operation),
        state_after_first,
        "journal 状态必须稳定在 published_not_converged"
    );
    assert_eq!(state_after_first, OperationState::PublishedNotConverged);
    assert_eq!(fx.read(".zshrc"), content_after_first);
    assert_eq!(fx.read(".zshrc"), USER_EDIT);
}

// ---------------------------------------------------------------------------
// 找不到计划
// ---------------------------------------------------------------------------

/// 草稿库里找不到原计划时无法自动恢复：记录错误，交给人工，绝不猜测。
#[test]
fn recovery_without_the_original_plan_requires_manual_intervention() {
    let mut fx = Fixture::new();
    let blobs = FakeBlobs::new();
    let plans = FakePlans::new();

    fx.write(".zshrc", OLD);
    // 刻意**不**把计划登记进计划源。
    let plan = plan_of(
        vec![action(&blobs, "shell/zsh/main", ".zshrc", Some(OLD), NEW)],
        0,
        true,
    );
    let operation = fx.begin(
        &plan,
        &[
            OperationState::Preflighted,
            OperationState::Published,
            OperationState::Applying,
        ],
    );

    let reports = fx.recover(&plans, &blobs);

    assert_eq!(reports[0].after, OperationState::Applying, "状态保持不变");
    assert_eq!(fx.read(".zshrc"), OLD, "拿不到计划就绝不动文件");
    let record = fx.journal.operation(operation).unwrap().unwrap();
    assert_eq!(
        record.error.as_ref().map(|detail| detail.code.as_str()),
        Some("recovery.manual_required")
    );
}

// ---------------------------------------------------------------------------
// 显式回滚
// ---------------------------------------------------------------------------

/// 显式回滚一次**已完成**的操作：状态机允许 `completed -> rolling_back`，
/// 并且必须留下完整审计记录，而不是绕过日志直接改文件。
#[test]
fn explicit_rollback_of_a_completed_operation_restores_original_bytes() {
    let mut fx = Fixture::new();
    let blobs = FakeBlobs::new();
    let plans = FakePlans::new();

    fx.write(".zshrc", NEW);
    let plan = register(
        &plans,
        &plan_of(
            vec![action(&blobs, "shell/zsh/main", ".zshrc", Some(OLD), NEW)],
            0,
            true,
        ),
    );
    let operation = fx.begin(
        &plan,
        &[
            OperationState::Preflighted,
            OperationState::Published,
            OperationState::Applying,
        ],
    );
    fx.record_receipt_with_backup(operation, 0, "shell/zsh/main", OLD, NEW);
    for state in [OperationState::Verified, OperationState::Completed] {
        fx.journal.transition(operation, state).expect("补齐状态");
    }

    let report = {
        let mut engine =
            RecoveryEngine::new(&mut fx.journal, &plans, &blobs, &fx.observer, &fx.mutator);
        engine.rollback_operation(operation).expect("显式回滚")
    };

    assert_eq!(report.before, OperationState::Completed);
    assert_eq!(report.after, OperationState::RolledBack);
    assert_eq!(fx.read(".zshrc"), OLD);
    assert_eq!(state_of(&fx.journal, operation), OperationState::RolledBack);
}

/// 处于 `preflighted` 的操作不支持显式回滚：它还没有改过任何文件。
#[test]
fn explicit_rollback_is_refused_for_operations_that_changed_nothing() {
    let mut fx = Fixture::new();
    let blobs = FakeBlobs::new();
    let plans = FakePlans::new();

    fx.write(".zshrc", OLD);
    let plan = register(
        &plans,
        &plan_of(
            vec![action(&blobs, "shell/zsh/main", ".zshrc", Some(OLD), NEW)],
            0,
            true,
        ),
    );
    let operation = fx.begin(&plan, &[OperationState::Preflighted]);

    let error = {
        let mut engine =
            RecoveryEngine::new(&mut fx.journal, &plans, &blobs, &fx.observer, &fx.mutator);
        engine
            .rollback_operation(operation)
            .expect_err("尚未发布的操作不支持回滚")
    };
    assert!(matches!(error, CoreError::Rollback(_)));
    assert_eq!(error.code(), "rollback.failed");
    assert_eq!(fx.read(".zshrc"), OLD);
}

// ---------------------------------------------------------------------------
// doctor 只报告
// ---------------------------------------------------------------------------

/// 验收条件：`doctor` 在任何修复之前**只报告**。
///
/// 这里造一个真实的中断操作（`applying` 且目标已被用户改动），然后断言调用 `doctor`
/// 前后 journal 状态、动作状态、收据与文件内容**完全不变**，同时它确实给出了诊断。
#[test]
fn doctor_only_reports_and_never_repairs() {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    let state = dir.path().join("state");
    std::fs::create_dir_all(&home).expect("创建授权根");
    std::fs::create_dir_all(&state).expect("创建状态目录");

    let config = workspace_config(
        "doctor",
        SEED_A,
        &dir.path().join("backend"),
        &state,
        &home,
        vec![support::resource_config(
            "shell/zsh/main",
            ".zshrc",
            FileMode::FullFile,
            DesiredDisposition::Managed,
        )],
    );

    std::fs::write(home.join(".zshrc"), OLD).expect("写入初始内容");

    // 先跑完一次正常同步，让后端有头、草稿库里有计划。
    let plan = {
        let mut service =
            EnvSyncService::open_with_clock(config.clone(), Arc::new(FixedClock(FIXED_NOW)))
                .expect("打开服务");
        let capture = service.capture().expect("capture");
        let plan = service.build_plan().expect("build_plan");
        service.apply_plan(plan.id()).expect("apply_plan");
        assert!(capture.changed);

        // 用户改动目标文件，于是重新计划会产生一个「恢复原状」的动作。
        std::fs::write(home.join(".zshrc"), USER_EDIT).expect("用户改动");
        service.build_plan().expect("生成中断用的计划")
    };
    assert_eq!(plan.actions.len(), 1);

    // 手工把这份计划驱动到 applying，模拟「写到一半被杀死」。
    let operation = {
        let mut journal = Journal::open(config.journal_path()).expect("另开 journal");
        let record = journal.begin(&plan).expect("登记操作");
        for target in [
            OperationState::Preflighted,
            OperationState::Published,
            OperationState::Applying,
        ] {
            journal
                .transition(record.operation, target)
                .expect("驱动状态机");
        }
        record.operation
    };

    // 记录 doctor 之前的全部现场。
    let snapshot_before = {
        let journal = Journal::open(config.journal_path()).expect("读取 journal");
        (
            state_of(&journal, operation),
            journal.actions(operation).unwrap(),
            journal.receipts(operation).unwrap(),
            std::fs::read(home.join(".zshrc")).unwrap(),
        )
    };

    let report = {
        let mut service =
            EnvSyncService::open_with_clock(config.clone(), Arc::new(FixedClock(FIXED_NOW)))
                .expect("重新打开服务");
        service.doctor().expect("doctor")
    };

    // doctor 确实看见了问题……
    assert!(!report.is_healthy(), "存在未完成操作时不应报告健康");
    let diagnosis = report
        .recovery
        .iter()
        .find(|d| d.operation == operation)
        .expect("必须诊断出这次中断的操作");
    assert_eq!(diagnosis.state, OperationState::Applying);
    assert!(
        matches!(
            diagnosis.suggestion,
            RecoverySuggestion::Reconverge { .. } | RecoverySuggestion::Manual { .. }
        ),
        "应当给出可执行的建议：{:?}",
        diagnosis.suggestion
    );

    // ……但什么都没有改。
    let snapshot_after = {
        let journal = Journal::open(config.journal_path()).expect("读取 journal");
        (
            state_of(&journal, operation),
            journal.actions(operation).unwrap(),
            journal.receipts(operation).unwrap(),
            std::fs::read(home.join(".zshrc")).unwrap(),
        )
    };
    assert_eq!(
        snapshot_before, snapshot_after,
        "doctor 在任何修复之前只报告，绝不改动 journal 或文件"
    );
    assert_eq!(snapshot_after.3, USER_EDIT.as_bytes());
}
