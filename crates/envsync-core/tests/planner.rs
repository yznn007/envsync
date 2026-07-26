//! 任务 7：不可变 Observation-bound Plan 的验收测试。
//!
//! 全部用例都在内存里完成：`Observer` 与 `BlobSource` 由 `support` 模块的内存 fake
//! 提供，时钟是 `FixedClock`，因此计划生成既不读文件系统也不取真实时间，结果完全确定。
//!
//! 覆盖的验收条件（设计文档 §3.4、§12，计划文档任务 7）：
//!
//! * 动作顺序与输入顺序无关；
//! * Snapshot / revision / Observation / Action 任一改变都改变 Plan ID；
//! * `Absent` 只在期望为 `Managed` 时产生 create；
//! * 只有 `EnsureAbsent` 产生 delete，`Managed` 永不删除；
//! * `Unreadable` / `Unsupported` / `Excluded` 产生阻塞诊断且零动作；
//! * 动作携带正确的 Risk / 备份策略 / 回滚能力 / 前后摘要 / verify 规则；
//! * 目标已符合期望时零动作（幂等）；
//! * Managed Block 的 tombstone 只移除区块、保留块外内容；
//! * 快照里有但配置里没有的资源产生 warning 而不是被静默丢弃。

mod support;

use std::path::Path;

use envsync_core::config::{ResourceConfig, WorkspaceConfig};
use envsync_core::planner::{self, PlanRequest};
use envsync_core::ports::FixedClock;
use envsync_core::render;
use envsync_domain::{
    Action, ActionKind, BackupPolicy, BlobId, DesiredDisposition, FileMode, ObservedState, Plan,
    ResourceEntry, Risk, RollbackCapability, Severity, SnapshotId, StateRoot, VerifyRule,
    WorkspaceRef,
};

use support::{
    digest_of, resource_config, rid, state_root, workspace_config, workspace_id, FakeBlobs,
    FakeObserver, FIXED_NOW, SEED_A,
};

const ZSHRC: &str = "shell/zsh/main";
const GITCFG: &str = "git/config";

/// 组装一份不依赖真实目录的配置（计划阶段只用到根别名与相对目标）。
fn config(resources: Vec<ResourceConfig>) -> WorkspaceConfig {
    workspace_config(
        "planner",
        SEED_A,
        Path::new("/nonexistent/backend"),
        Path::new("/nonexistent/state"),
        Path::new("/nonexistent/home"),
        resources,
    )
}

/// 目标快照标识；除非用例显式改变，否则固定。
fn snapshot() -> SnapshotId {
    SnapshotId::of(b"planner-target-snapshot")
}

/// 生成计划（发布路径：`next_ref` 比 `base_ref` 前进一格）。
fn build(
    config: &WorkspaceConfig,
    state: &StateRoot,
    observer: &FakeObserver,
    blobs: &FakeBlobs,
) -> Plan {
    build_with(config, state, observer, blobs, snapshot(), 0)
}

/// 生成计划，允许指定目标快照与基准 revision。
fn build_with(
    config: &WorkspaceConfig,
    state: &StateRoot,
    observer: &FakeObserver,
    blobs: &FakeBlobs,
    target_snapshot: SnapshotId,
    base_revision: u64,
) -> Plan {
    let mut base_ref = WorkspaceRef::initial(workspace_id());
    for index in 0..base_revision {
        base_ref = base_ref.advance(SnapshotId::of(format!("history-{index}").as_bytes()));
    }
    let next_ref = base_ref.advance(target_snapshot);
    let request = PlanRequest {
        config,
        target_state: state,
        target_snapshot,
        base_ref: &base_ref,
        next_ref,
    };
    planner::build_plan(&request, observer, blobs, &FixedClock(FIXED_NOW))
        .expect("计划生成应当成功")
        .plan
}

/// 取出唯一动作，数量不为 1 时直接失败。
fn only_action(plan: &Plan) -> &Action {
    assert_eq!(
        plan.actions.len(),
        1,
        "期望恰好一个动作：{:?}",
        plan.actions
    );
    &plan.actions[0]
}

/// 组装一个 Managed 条目并把内容写进 Blob 源。
fn managed_entry(blobs: &FakeBlobs, id: &str, content: &[u8], mode: FileMode) -> ResourceEntry {
    let blob = blobs.insert(content);
    support::entry(id, DesiredDisposition::Managed, Some(blob), mode)
}

/// 拼一个受管区块（LF 换行）。
fn block(resource: &str, inner: &str) -> String {
    format!("# >>> envsync:{resource}\n{inner}# <<< envsync:{resource}\n")
}

// ---------------------------------------------------------------------------
// 计划标识的确定性
// ---------------------------------------------------------------------------

/// 验收条件「Action 与 map 的插入顺序不影响 Plan ID」。
///
/// 计划器按配置中的资源顺序遍历，因此这里把配置顺序完全颠倒，并让 State Root 的条目
/// 也以相反顺序插入；两次生成的计划标识必须相同，动作顺序必须按资源标识升序固定。
#[test]
fn plan_id_is_independent_of_input_order() {
    let forward_config = config(vec![
        resource_config(
            ZSHRC,
            ".zshrc",
            FileMode::FullFile,
            DesiredDisposition::Managed,
        ),
        resource_config(
            GITCFG,
            ".gitconfig",
            FileMode::FullFile,
            DesiredDisposition::Managed,
        ),
    ]);
    let backward_config = config(vec![
        resource_config(
            GITCFG,
            ".gitconfig",
            FileMode::FullFile,
            DesiredDisposition::Managed,
        ),
        resource_config(
            ZSHRC,
            ".zshrc",
            FileMode::FullFile,
            DesiredDisposition::Managed,
        ),
    ]);

    let blobs = FakeBlobs::new();
    let zsh = managed_entry(&blobs, ZSHRC, b"export EDITOR=nvim\n", FileMode::FullFile);
    let git = managed_entry(&blobs, GITCFG, b"[user]\n\tname = a\n", FileMode::FullFile);

    let forward_state = state_root(vec![zsh.clone(), git.clone()]);
    let backward_state = state_root(vec![git, zsh]);

    let observer = FakeObserver::new();
    let forward = build(&forward_config, &forward_state, &observer, &blobs);
    let backward = build(&backward_config, &backward_state, &observer, &blobs);

    assert_eq!(forward.id(), backward.id(), "输入顺序不应影响计划标识");
    let order: Vec<&str> = forward
        .actions
        .iter()
        .map(|action| action.resource.as_str())
        .collect();
    assert_eq!(order, vec![GITCFG, ZSHRC], "动作必须按资源标识升序排列");
}

/// 验收条件「Snapshot、revision、Observation 或 Action 改变都会改变 Plan ID」。
///
/// 基线里放一个 `Managed` 资源（决定 Action）和一个 `Unmanaged` 资源（只贡献
/// Observation），这样「只改观察」与「只改动作」可以被分别隔离出来。
#[test]
fn plan_id_changes_when_any_bound_input_changes() {
    let cfg = config(vec![
        resource_config(
            ZSHRC,
            ".zshrc",
            FileMode::FullFile,
            DesiredDisposition::Managed,
        ),
        resource_config(
            GITCFG,
            ".gitconfig",
            FileMode::FullFile,
            DesiredDisposition::Unmanaged,
        ),
    ]);
    let blobs = FakeBlobs::new();
    let state = state_root(vec![
        managed_entry(&blobs, ZSHRC, b"export EDITOR=nvim\n", FileMode::FullFile),
        support::entry(
            GITCFG,
            DesiredDisposition::Unmanaged,
            None,
            FileMode::FullFile,
        ),
    ]);
    let observer = FakeObserver::new();
    let baseline = build(&cfg, &state, &observer, &blobs);

    // 1) 目标快照变化。
    let other_snapshot = build_with(
        &cfg,
        &state,
        &observer,
        &blobs,
        SnapshotId::of(b"another-snapshot"),
        0,
    );
    assert_ne!(
        baseline.id(),
        other_snapshot.id(),
        "目标快照变化必须改变计划标识"
    );

    // 2) 后端 revision 变化。
    let other_revision = build_with(&cfg, &state, &observer, &blobs, snapshot(), 3);
    assert_ne!(
        baseline.id(),
        other_revision.id(),
        "revision 变化必须改变计划标识"
    );

    // 3) Observation 变化：只改 Unmanaged 资源的现状，动作集合保持不变。
    let observer_changed = FakeObserver::new();
    observer_changed.set_file(&support::target(".gitconfig"), b"[user]\n");
    let with_observation = build(&cfg, &state, &observer_changed, &blobs);
    assert_eq!(
        with_observation.actions, baseline.actions,
        "该用例只应改变观察，不应改变动作"
    );
    assert_ne!(
        baseline.id(),
        with_observation.id(),
        "观察变化必须改变计划标识"
    );

    // 4) Action 变化：期望内容不同 => expected_after 不同。
    let other_blobs = FakeBlobs::new();
    let other_state = state_root(vec![
        managed_entry(
            &other_blobs,
            ZSHRC,
            b"export EDITOR=helix\n",
            FileMode::FullFile,
        ),
        support::entry(
            GITCFG,
            DesiredDisposition::Unmanaged,
            None,
            FileMode::FullFile,
        ),
    ]);
    let with_action = build(&cfg, &other_state, &observer, &other_blobs);
    assert_eq!(
        with_action.observations, baseline.observations,
        "该用例只应改变动作，不应改变观察"
    );
    assert_ne!(baseline.id(), with_action.id(), "动作变化必须改变计划标识");
}

/// 计划标识不含创建时刻，否则「重新计划并比较标识」这一新鲜度检查将永远失败。
#[test]
fn plan_id_is_independent_of_creation_time() {
    let cfg = config(vec![resource_config(
        ZSHRC,
        ".zshrc",
        FileMode::FullFile,
        DesiredDisposition::Managed,
    )]);
    let blobs = FakeBlobs::new();
    let state = state_root(vec![managed_entry(
        &blobs,
        ZSHRC,
        b"export EDITOR=nvim\n",
        FileMode::FullFile,
    )]);
    let observer = FakeObserver::new();

    let base_ref = WorkspaceRef::initial(workspace_id());
    let request = PlanRequest {
        config: &cfg,
        target_state: &state,
        target_snapshot: snapshot(),
        base_ref: &base_ref,
        next_ref: base_ref.advance(snapshot()),
    };
    let early = planner::build_plan(&request, &observer, &blobs, &FixedClock(1)).unwrap();
    let late = planner::build_plan(&request, &observer, &blobs, &FixedClock(9_999_999)).unwrap();

    assert_eq!(early.plan.id(), late.plan.id());
    assert_ne!(
        early.plan.created_at_unix_ms, late.plan.created_at_unix_ms,
        "两次生成的时间戳确实不同，上面的相等断言才有意义"
    );
}

/// 同一份输入重复生成的计划逐字段相等：计划生成是纯函数。
#[test]
fn planning_is_deterministic_across_runs() {
    let cfg = config(vec![resource_config(
        ZSHRC,
        ".zshrc",
        FileMode::ManagedBlock,
        DesiredDisposition::Managed,
    )]);
    let blobs = FakeBlobs::new();
    let state = state_root(vec![managed_entry(
        &blobs,
        ZSHRC,
        b"export EDITOR=nvim\n",
        FileMode::ManagedBlock,
    )]);
    let observer = FakeObserver::new();
    observer.set_file(&support::target(".zshrc"), b"alias ll='ls -l'\n");

    let first = build(&cfg, &state, &observer, &blobs);
    let second = build(&cfg, &state, &observer, &blobs);
    assert_eq!(first, second);
    assert_eq!(first.id(), second.id());
}

// ---------------------------------------------------------------------------
// 处置语义：谁能产生 create、谁能产生 delete
// ---------------------------------------------------------------------------

/// 验收条件「`Absent` 仅在期望为 `Managed` 时生成 create」。
#[test]
fn absent_target_creates_file_only_when_managed() {
    let cfg = config(vec![resource_config(
        ZSHRC,
        ".zshrc",
        FileMode::FullFile,
        DesiredDisposition::Managed,
    )]);
    let blobs = FakeBlobs::new();
    let content = b"export EDITOR=nvim\n";
    let state = state_root(vec![managed_entry(
        &blobs,
        ZSHRC,
        content,
        FileMode::FullFile,
    )]);

    // 观察器为空 => 目标 Absent。
    let plan = build(&cfg, &state, &FakeObserver::new(), &blobs);
    let action = only_action(&plan);

    assert_eq!(action.kind, ActionKind::CreateFile);
    assert_eq!(action.expected_before, None, "目标不存在时前置摘要必须为空");
    assert_eq!(action.expected_after, Some(digest_of(content)));
    assert_eq!(
        action.backup,
        BackupPolicy::NotApplicable,
        "原本不存在的文件没有可备份的内容"
    );
    assert_eq!(action.risk, Risk::Low, "创建新文件是无损操作");
}

/// 验收条件「期望为 `EnsureAbsent` 且目标已 absent 时零动作」（幂等 tombstone）。
#[test]
fn absent_target_with_ensure_absent_produces_no_action() {
    let cfg = config(vec![resource_config(
        ZSHRC,
        ".zshrc",
        FileMode::FullFile,
        DesiredDisposition::EnsureAbsent,
    )]);
    let state = state_root(vec![support::entry(
        ZSHRC,
        DesiredDisposition::EnsureAbsent,
        None,
        FileMode::FullFile,
    )]);

    let plan = build(&cfg, &state, &FakeObserver::new(), &FakeBlobs::new());
    assert!(plan.actions.is_empty(), "已经不存在就不需要再删一次");
    assert!(!plan.is_blocked());
}

/// 验收条件「只有 `EnsureAbsent` 生成 delete」，同时验证 `Managed` 永不产生删除。
///
/// 对应设计文档「默认不删除」原则：远端缺失、观察缺失都不等于删除意图。
#[test]
fn only_ensure_absent_produces_delete_actions() {
    let cfg = config(vec![
        resource_config(
            ZSHRC,
            ".zshrc",
            FileMode::FullFile,
            DesiredDisposition::EnsureAbsent,
        ),
        resource_config(
            GITCFG,
            ".gitconfig",
            FileMode::FullFile,
            DesiredDisposition::Managed,
        ),
    ]);
    let blobs = FakeBlobs::new();
    let state = state_root(vec![
        support::entry(
            ZSHRC,
            DesiredDisposition::EnsureAbsent,
            None,
            FileMode::FullFile,
        ),
        managed_entry(&blobs, GITCFG, b"[user]\n\tname = a\n", FileMode::FullFile),
    ]);

    let observer = FakeObserver::new();
    let existing = b"export EDITOR=nvim\n";
    observer.set_file(&support::target(".zshrc"), existing);
    observer.set_file(&support::target(".gitconfig"), b"[user]\n\tname = old\n");

    let plan = build(&cfg, &state, &observer, &blobs);

    let deletes: Vec<&str> = plan
        .actions
        .iter()
        .filter(|action| action.kind.is_delete())
        .map(|action| action.resource.as_str())
        .collect();
    assert_eq!(deletes, vec![ZSHRC], "只有显式 tombstone 才产生删除");

    let delete = plan
        .actions
        .iter()
        .find(|action| action.kind == ActionKind::DeleteFile)
        .expect("应当有一个删除动作");
    assert_eq!(delete.expected_before, Some(digest_of(existing)));
    assert_eq!(delete.expected_after, None);
    assert_eq!(delete.content, None, "删除动作不携带内容");
    assert_eq!(delete.risk, Risk::High, "删除是不可逆的高风险动作");
    assert_eq!(delete.backup, BackupPolicy::Required, "删除前必须备份");
    assert_eq!(delete.rollback, RollbackCapability::Exact);
    assert_eq!(delete.verify, VerifyRule::ExpectAbsent);

    // 同一份计划里的 Managed 资源只产生替换，绝不产生删除。
    let managed = plan
        .actions
        .iter()
        .find(|action| action.resource.as_str() == GITCFG)
        .expect("Managed 资源应当有动作");
    assert_eq!(managed.kind, ActionKind::ReplaceFile);
}

/// 配置声明了、但目标快照未包含的资源：只留 info 诊断，绝不推断为删除。
#[test]
fn resource_missing_from_snapshot_is_never_deleted() {
    let cfg = config(vec![resource_config(
        ZSHRC,
        ".zshrc",
        FileMode::FullFile,
        DesiredDisposition::Managed,
    )]);
    let observer = FakeObserver::new();
    observer.set_file(&support::target(".zshrc"), b"export EDITOR=nvim\n");

    let plan = build(&cfg, &StateRoot::empty(), &observer, &FakeBlobs::new());

    assert!(plan.actions.is_empty(), "快照里没有 => 什么都不做");
    let diagnostic = plan
        .diagnostics
        .iter()
        .find(|d| d.code == "resource.not_in_snapshot")
        .expect("应当留下一条诊断");
    assert_eq!(diagnostic.severity, Severity::Info);
    assert!(!plan.is_blocked());
}

/// 处置为 `Unmanaged` 的资源只贡献观察，不产生任何动作。
#[test]
fn unmanaged_resource_contributes_observation_only() {
    let cfg = config(vec![resource_config(
        GITCFG,
        ".gitconfig",
        FileMode::FullFile,
        DesiredDisposition::Unmanaged,
    )]);
    let state = state_root(vec![support::entry(
        GITCFG,
        DesiredDisposition::Unmanaged,
        None,
        FileMode::FullFile,
    )]);
    let observer = FakeObserver::new();
    observer.set_file(&support::target(".gitconfig"), b"[user]\n");

    let plan = build(&cfg, &state, &observer, &FakeBlobs::new());
    assert!(plan.actions.is_empty());
    assert_eq!(plan.observations.len(), 1, "观察仍然必须被记录下来");
    assert!(plan.observation(&rid(GITCFG)).is_some());
}

// ---------------------------------------------------------------------------
// 不可写观察状态：阻塞诊断 + 零动作
// ---------------------------------------------------------------------------

/// 验收条件「`Unreadable` / `Unsupported` / `Excluded` 产生阻塞诊断，不产生写入」。
///
/// 三种状态的共同点是「我们不知道目标当前是什么」，此时任何写入或删除都可能造成不可
/// 恢复的数据丢失，因此计划必须被拦住，而不是带着猜测继续。`Managed` 与
/// `EnsureAbsent` 两条路径都要覆盖。
#[test]
fn unwritable_observations_block_the_plan_without_actions() {
    let cases = [
        (
            ObservedState::Unreadable {
                reason: "权限不足".into(),
            },
            "resource.unreadable",
        ),
        (
            ObservedState::Unsupported {
                reason: "当前平台不支持".into(),
            },
            "resource.unsupported",
        ),
        (
            ObservedState::Excluded {
                reason: "被策略排除".into(),
            },
            "resource.excluded",
        ),
    ];

    for (state, code) in cases {
        for disposition in [
            DesiredDisposition::Managed,
            DesiredDisposition::EnsureAbsent,
        ] {
            let cfg = config(vec![resource_config(
                ZSHRC,
                ".zshrc",
                FileMode::FullFile,
                disposition,
            )]);
            let blobs = FakeBlobs::new();
            let entry = match disposition {
                DesiredDisposition::Managed => {
                    managed_entry(&blobs, ZSHRC, b"content\n", FileMode::FullFile)
                }
                other => support::entry(ZSHRC, other, None, FileMode::FullFile),
            };
            let target_state = state_root(vec![entry]);

            let observer = FakeObserver::new();
            observer.force_state(&support::target(".zshrc"), state.clone());

            let plan = build(&cfg, &target_state, &observer, &blobs);

            assert!(
                plan.actions.is_empty(),
                "{code} / {disposition:?} 不得产生任何写入动作"
            );
            assert!(plan.is_blocked(), "{code} / {disposition:?} 必须阻塞计划");
            let diagnostic = plan
                .diagnostics
                .iter()
                .find(|d| d.code == code)
                .unwrap_or_else(|| panic!("缺少诊断 {code}"));
            assert_eq!(diagnostic.severity, Severity::Blocking);
            assert_eq!(diagnostic.resource.as_ref(), Some(&rid(ZSHRC)));
        }
    }
}

// ---------------------------------------------------------------------------
// 动作元数据与幂等
// ---------------------------------------------------------------------------

/// 验收条件「动作携带 Risk、备份策略、回滚能力、预计摘要和 verify 规则」。
#[test]
fn replace_action_carries_full_risk_and_rollback_metadata() {
    let cfg = config(vec![resource_config(
        ZSHRC,
        ".zshrc",
        FileMode::FullFile,
        DesiredDisposition::Managed,
    )]);
    let blobs = FakeBlobs::new();
    let desired = b"export EDITOR=helix\n";
    let state = state_root(vec![managed_entry(
        &blobs,
        ZSHRC,
        desired,
        FileMode::FullFile,
    )]);

    let observer = FakeObserver::new();
    let existing = b"export EDITOR=nvim\n";
    observer.set_file(&support::target(".zshrc"), existing);

    let plan = build(&cfg, &state, &observer, &blobs);
    let action = only_action(&plan);

    assert_eq!(action.kind, ActionKind::ReplaceFile);
    assert_eq!(action.risk, Risk::Medium, "覆盖已有文件属于中风险");
    assert_eq!(action.backup, BackupPolicy::Required, "覆盖前必须备份");
    assert_eq!(action.rollback, RollbackCapability::Exact);
    assert_eq!(
        action.expected_before,
        Some(digest_of(existing)),
        "前置摘要必须绑定生成计划时观察到的内容"
    );
    assert_eq!(action.expected_after, Some(digest_of(desired)));
    assert_eq!(
        action.verify,
        VerifyRule::ExpectDigest(digest_of(desired)),
        "verify 规则必须与 expected_after 一致"
    );
    assert!(!action.secret);
    assert_eq!(
        action.target,
        support::target(".zshrc"),
        "计划只保存根别名与相对分段，不保存绝对路径"
    );
    assert_eq!(action.content, Some(BlobId::of(desired)));
    assert_eq!(plan.max_risk(), Some(Risk::Medium));
}

/// 秘密资源的任何写入都被升级为高风险，且沿用策略里的权限位。
#[test]
fn secret_resource_writes_are_always_high_risk() {
    let mut resource = resource_config(
        "secret/token",
        ".token",
        FileMode::FullFile,
        DesiredDisposition::Managed,
    );
    resource.policy.secret = true;
    resource.policy.unix_mode = Some(0o600);
    let cfg = config(vec![resource]);

    let blobs = FakeBlobs::new();
    let blob = blobs.insert(b"t0ken\n");
    let mut entry = support::entry(
        "secret/token",
        DesiredDisposition::Managed,
        Some(blob),
        FileMode::FullFile,
    );
    entry.policy.secret = true;
    let state = state_root(vec![entry]);

    let plan = build(&cfg, &state, &FakeObserver::new(), &blobs);
    let action = only_action(&plan);

    assert_eq!(
        action.kind,
        ActionKind::CreateFile,
        "该用例创建新文件；若不是秘密资源，风险应为 Low"
    );
    assert_eq!(action.risk, Risk::High, "秘密资源的写入必须是高风险");
    assert!(action.secret);
    assert_eq!(action.unix_mode, Some(0o600));
}

/// 验收条件「目标已符合期望时不生成动作」（Full File 幂等）。
#[test]
fn full_file_already_converged_produces_no_action() {
    let cfg = config(vec![resource_config(
        ZSHRC,
        ".zshrc",
        FileMode::FullFile,
        DesiredDisposition::Managed,
    )]);
    let blobs = FakeBlobs::new();
    let content = b"export EDITOR=nvim\n";
    let state = state_root(vec![managed_entry(
        &blobs,
        ZSHRC,
        content,
        FileMode::FullFile,
    )]);

    let observer = FakeObserver::new();
    observer.set_file(&support::target(".zshrc"), content);

    let plan = build(&cfg, &state, &observer, &blobs);
    assert!(plan.actions.is_empty(), "内容已一致时不应产生写入");
    assert!(plan.is_noop());
}

/// Managed Block 模式下块内内容已一致时同样零动作（块外内容不参与比较）。
#[test]
fn managed_block_already_converged_produces_no_action() {
    let cfg = config(vec![resource_config(
        ZSHRC,
        ".zshrc",
        FileMode::ManagedBlock,
        DesiredDisposition::Managed,
    )]);
    let blobs = FakeBlobs::new();
    let inner = "export EDITOR=nvim\n";
    let state = state_root(vec![managed_entry(
        &blobs,
        ZSHRC,
        inner.as_bytes(),
        FileMode::ManagedBlock,
    )]);

    let observer = FakeObserver::new();
    let existing = format!(
        "# 用户自己的设置\nalias ll='ls -l'\n{}",
        block(ZSHRC, inner)
    );
    observer.set_file(&support::target(".zshrc"), existing.as_bytes());

    let plan = build(&cfg, &state, &observer, &blobs);
    assert!(plan.actions.is_empty());
}

/// Managed Block 需要更新时生成 `UpdateManagedBlock`，且渲染产物保留块外内容。
#[test]
fn managed_block_update_preserves_content_outside_the_block() {
    let cfg = config(vec![resource_config(
        ZSHRC,
        ".zshrc",
        FileMode::ManagedBlock,
        DesiredDisposition::Managed,
    )]);
    let blobs = FakeBlobs::new();
    let desired = "export EDITOR=helix\n";
    let state = state_root(vec![managed_entry(
        &blobs,
        ZSHRC,
        desired.as_bytes(),
        FileMode::ManagedBlock,
    )]);

    let prologue = "# 用户自己的设置\nalias ll='ls -l'\n";
    let epilogue = "export PATH=\"$HOME/bin:$PATH\"\n";
    let existing = format!(
        "{prologue}{}{epilogue}",
        block(ZSHRC, "export EDITOR=nvim\n")
    );
    let observer = FakeObserver::new();
    observer.set_file(&support::target(".zshrc"), existing.as_bytes());

    let outcome = plan_outcome(&cfg, &state, &observer, &blobs);
    let action = only_action(&outcome.plan);
    assert_eq!(action.kind, ActionKind::UpdateManagedBlock);

    let bytes = rendered_bytes(&outcome, action);
    let text = String::from_utf8(bytes.clone()).expect("渲染产物是 UTF-8");
    assert!(text.starts_with(prologue), "块前内容必须逐字保留：{text}");
    assert!(text.ends_with(epilogue), "块后内容必须逐字保留：{text}");
    assert!(text.contains(desired));
}

// ---------------------------------------------------------------------------
// Managed Block 的 tombstone
// ---------------------------------------------------------------------------

/// 验收条件「Managed Block 的 `EnsureAbsent` 只移除区块、保留块外内容」。
///
/// 用户的 `.zshrc` 不属于 EnvSync，取消管理绝不能把整个文件删掉，因此这里必须生成
/// `UpdateManagedBlock` 而不是 `DeleteFile`。
#[test]
fn managed_block_tombstone_removes_block_not_file() {
    let cfg = config(vec![resource_config(
        ZSHRC,
        ".zshrc",
        FileMode::ManagedBlock,
        DesiredDisposition::EnsureAbsent,
    )]);
    let state = state_root(vec![support::entry(
        ZSHRC,
        DesiredDisposition::EnsureAbsent,
        None,
        FileMode::ManagedBlock,
    )]);

    let prologue = "# 用户自己的设置\nalias ll='ls -l'\n";
    let epilogue = "export PATH=\"$HOME/bin:$PATH\"\n";
    let existing = format!(
        "{prologue}{}{epilogue}",
        block(ZSHRC, "export EDITOR=nvim\n")
    );

    let observer = FakeObserver::new();
    observer.set_file(&support::target(".zshrc"), existing.as_bytes());
    let blobs = FakeBlobs::new();

    let outcome = plan_outcome(&cfg, &state, &observer, &blobs);
    let action = only_action(&outcome.plan);

    assert_eq!(
        action.kind,
        ActionKind::UpdateManagedBlock,
        "Managed Block 的 tombstone 绝不能退化成 DeleteFile"
    );
    assert!(action.content.is_some(), "块级删除仍然是一次写入");
    assert_eq!(action.risk, Risk::High);
    assert_eq!(action.backup, BackupPolicy::Required);
    assert_eq!(action.rollback, RollbackCapability::Exact);
    assert_eq!(action.expected_before, Some(digest_of(existing.as_bytes())));

    let bytes = rendered_bytes(&outcome, action);
    let expected = render::remove_managed_block(existing.as_bytes(), &rid(ZSHRC))
        .expect("移除区块应当成功")
        .expect("原文件确实含有区块");
    assert_eq!(bytes, expected);
    assert_eq!(
        String::from_utf8(bytes.clone()).unwrap(),
        format!("{prologue}{epilogue}"),
        "块外内容必须逐字保留"
    );
    assert_eq!(action.expected_after, Some(digest_of(&bytes)));
    assert_eq!(action.verify, VerifyRule::ExpectDigest(digest_of(&bytes)));
    assert_eq!(action.content, Some(BlobId::of(&bytes)));
}

/// 文件里本来就没有该区块时，`EnsureAbsent` 是零动作的幂等操作。
#[test]
fn managed_block_tombstone_is_noop_without_a_block() {
    let cfg = config(vec![resource_config(
        ZSHRC,
        ".zshrc",
        FileMode::ManagedBlock,
        DesiredDisposition::EnsureAbsent,
    )]);
    let state = state_root(vec![support::entry(
        ZSHRC,
        DesiredDisposition::EnsureAbsent,
        None,
        FileMode::ManagedBlock,
    )]);
    let observer = FakeObserver::new();
    observer.set_file(&support::target(".zshrc"), b"alias ll='ls -l'\n");

    let plan = build(&cfg, &state, &observer, &FakeBlobs::new());
    assert!(plan.actions.is_empty());
}

// ---------------------------------------------------------------------------
// 未声明资源的可见性与发布判定
// ---------------------------------------------------------------------------

/// 验收条件「快照里有、本机配置里没有的资源必须留下 warning，而不是被静默丢弃」。
#[test]
fn snapshot_resource_missing_from_config_yields_warning() {
    let cfg = config(vec![resource_config(
        ZSHRC,
        ".zshrc",
        FileMode::FullFile,
        DesiredDisposition::Managed,
    )]);
    let blobs = FakeBlobs::new();
    let state = state_root(vec![
        managed_entry(&blobs, ZSHRC, b"export EDITOR=nvim\n", FileMode::FullFile),
        managed_entry(
            &blobs,
            "terminal/wezterm",
            b"return {}\n",
            FileMode::FullFile,
        ),
    ]);

    let plan = build(&cfg, &state, &FakeObserver::new(), &blobs);

    let diagnostic = plan
        .diagnostics
        .iter()
        .find(|d| d.code == "resource.not_configured")
        .expect("未声明资源必须留下诊断");
    assert_eq!(diagnostic.severity, Severity::Warning);
    assert_eq!(
        diagnostic.resource.as_ref(),
        Some(&rid("terminal/wezterm")),
        "诊断必须指明是哪一个资源被忽略"
    );
    assert!(
        !plan.is_blocked(),
        "本设备不关心的资源只是警告，不应阻塞整个同步"
    );
    assert_eq!(
        plan.actions.len(),
        1,
        "未声明的资源不产生动作：没有授权根就没有写入权"
    );
}

/// `requires_publish` 只在 `next_ref` 真的前进时才要求 CAS。
#[test]
fn publish_is_required_only_when_ref_advances() {
    let cfg = config(vec![]);
    let base_ref = WorkspaceRef::initial(workspace_id()).advance(snapshot());

    let same_head = planner::build_plan(
        &PlanRequest {
            config: &cfg,
            target_state: &StateRoot::empty(),
            target_snapshot: snapshot(),
            base_ref: &base_ref,
            next_ref: base_ref.clone(),
        },
        &FakeObserver::new(),
        &FakeBlobs::new(),
        &FixedClock(FIXED_NOW),
    )
    .unwrap()
    .plan;
    assert!(
        !planner::requires_publish(&same_head),
        "目标已是后端当前头时不应再做一次 CAS"
    );

    let advancing = planner::build_plan(
        &PlanRequest {
            config: &cfg,
            target_state: &StateRoot::empty(),
            target_snapshot: snapshot(),
            base_ref: &base_ref,
            next_ref: base_ref.advance(SnapshotId::of(b"newer")),
        },
        &FakeObserver::new(),
        &FakeBlobs::new(),
        &FixedClock(FIXED_NOW),
    )
    .unwrap()
    .plan;
    assert!(planner::requires_publish(&advancing));
}

// ---------------------------------------------------------------------------
// 内部辅助
// ---------------------------------------------------------------------------

/// 生成计划并保留渲染产物。
fn plan_outcome(
    config: &WorkspaceConfig,
    state: &StateRoot,
    observer: &FakeObserver,
    blobs: &FakeBlobs,
) -> planner::PlanOutcome {
    let base_ref = WorkspaceRef::initial(workspace_id());
    let target_snapshot = snapshot();
    planner::build_plan(
        &PlanRequest {
            config,
            target_state: state,
            target_snapshot,
            base_ref: &base_ref,
            next_ref: base_ref.advance(target_snapshot),
        },
        observer,
        blobs,
        &FixedClock(FIXED_NOW),
    )
    .expect("计划生成应当成功")
}

/// 取出某个动作对应的渲染产物；渲染产物必须与动作内容一一对应。
fn rendered_bytes(outcome: &planner::PlanOutcome, action: &Action) -> Vec<u8> {
    outcome
        .rendered
        .iter()
        .find(|(id, _)| Some(*id) == action.content)
        .map(|(_, bytes)| bytes.clone())
        .expect("动作内容 Blob 必须出现在渲染产物中")
}
