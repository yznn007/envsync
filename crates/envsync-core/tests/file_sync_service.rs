//! 任务 11：M0 应用服务（`EnvSyncService`）的端到端验收测试。
//!
//! 这里**不使用任何 fake**：授权根和后端都是真实的 tempdir，读写走
//! `envsync-platform` 的能力约束读写器，journal 与草稿库是真实 SQLite。只有时钟被
//! 固定，以保证快照标识可复现。
//!
//! 覆盖的验收条件（设计文档 §12，计划文档任务 11）：
//!
//! * `init_workspace` 写出的配置能被 `WorkspaceConfig::load` 读回；重复 init 报错不覆盖；
//! * capture 只写本地草稿，**不**更新后端 Ref；重复 capture 幂等；
//! * capture 读不到资源时沿用上一版快照条目，绝不变成删除；
//! * plan 同时比较草稿头、后端头与本机观察；
//! * `apply_plan` 只接受匹配且新鲜的 Plan ID；
//! * 完整 capture → plan → sync → verify 闭环，随后 status 为 clean；
//! * 第二台设备拉取后内容一致，且 State Root 与 Snapshot ID 相同；
//! * status 区分 clean / drifted / published_not_converged；
//! * Managed Block 场景下块外内容在整个流程中逐字节不变。

mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use envsync_backend::{Backend, BackendError, LocalBackend};
use envsync_core::config::WorkspaceConfig;
use envsync_core::ports::FixedClock;
use envsync_core::service::{EnvSyncService, WorkspaceState};
use envsync_core::{ApplyCancellation, ApplyOutcome};
use envsync_domain::{
    BlobId, DesiredDisposition, FileMode, ObjectId, PlanId, SnapshotId, StateRootId,
};
use envsync_storage::{ErrorDetail, Journal, OperationState};

use support::{resource_config, workspace_config, workspace_id, FIXED_NOW, SEED_A, SEED_B};

const ZSHRC: &str = "shell/zsh/main";
const GITCFG: &str = "git/config";

/// 设备一 `.zshrc` 的块外内容（前后各一段），整个流程中必须逐字节不变。
const DEV1_PROLOGUE: &str = "# 设备一自己的设置\nalias ll='ls -l'\n";
const DEV1_EPILOGUE: &str = "export PATH=\"$HOME/bin:$PATH\"\n";
/// 设备二 `.zshrc` 的块外内容，与设备一刻意不同。
const DEV2_PROLOGUE: &str = "# 设备二自己的设置\nexport LANG=C.UTF-8\n";
const DEV2_EPILOGUE: &str = "# 设备二的收尾\n";

/// 受管区块的内容（块内），也是 Blob 的字节。
const BLOCK_V1: &str = "export EDITOR=nvim\n";
const BLOCK_V2: &str = "export EDITOR=helix\nexport VISUAL=helix\n";
/// Full File 资源的内容。
const GIT_V1: &str = "[user]\n\tname = alice\n";

/// 拼一个受管区块（LF 换行，默认注释前缀）。
fn block(inner: &str) -> String {
    format!("# >>> envsync:{ZSHRC}\n{inner}# <<< envsync:{ZSHRC}\n")
}

/// M0 支持的两种模式各一个资源；目标都在授权根顶层（平台层不会自动创建中间目录）。
fn resources() -> Vec<envsync_core::config::ResourceConfig> {
    vec![
        resource_config(
            ZSHRC,
            ".zshrc",
            FileMode::ManagedBlock,
            DesiredDisposition::Managed,
        ),
        resource_config(
            GITCFG,
            ".gitconfig",
            FileMode::FullFile,
            DesiredDisposition::Managed,
        ),
    ]
}

/// 一台设备：独立的授权根与本地状态目录，共享同一个后端。
struct DeviceFixture {
    home: PathBuf,
    config: WorkspaceConfig,
}

impl DeviceFixture {
    /// 打开该设备的应用服务（固定时钟）。
    fn service(&self) -> EnvSyncService {
        EnvSyncService::open_with_clock(self.config.clone(), Arc::new(FixedClock(FIXED_NOW)))
            .expect("打开应用服务")
    }

    /// 读取授权根下某个文件的完整内容。
    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.home.join(name))
            .unwrap_or_else(|err| panic!("读取 {name} 失败：{err}"))
    }

    /// 写入授权根下某个文件。
    fn write(&self, name: &str, content: &str) {
        std::fs::write(self.home.join(name), content).expect("写入测试文件");
    }

    /// 目标文件是否存在。
    fn exists(&self, name: &str) -> bool {
        self.home.join(name).exists()
    }
}

/// 一个包含后端与若干设备的测试世界。
struct World {
    dir: tempfile::TempDir,
}

impl World {
    fn new() -> Self {
        World {
            dir: tempfile::tempdir().expect("创建临时目录"),
        }
    }

    fn backend_path(&self) -> PathBuf {
        self.dir.path().join("backend")
    }

    /// 打开（必要时初始化）共享后端。
    fn backend(&self) -> LocalBackend {
        LocalBackend::open(self.backend_path()).expect("打开共享后端")
    }

    /// 后端当前 revision；从未发布过时返回 0。
    fn revision(&self) -> u64 {
        match self.backend().get_ref(workspace_id()) {
            Ok(reference) => reference.revision,
            Err(BackendError::RefNotFound(_)) => 0,
            Err(err) => panic!("读取后端引用失败：{err}"),
        }
    }

    /// 后端当前头快照。
    fn head(&self) -> Option<SnapshotId> {
        match self.backend().get_ref(workspace_id()) {
            Ok(reference) => reference.head,
            Err(BackendError::RefNotFound(_)) => None,
            Err(err) => panic!("读取后端引用失败：{err}"),
        }
    }

    /// 创建一台设备。
    fn device(&self, name: &str, seed: &str) -> DeviceFixture {
        let home = self.dir.path().join(format!("{name}-home"));
        let state = self.dir.path().join(format!("{name}-state"));
        std::fs::create_dir_all(&home).expect("创建授权根");
        std::fs::create_dir_all(&state).expect("创建状态目录");
        let config = workspace_config(name, seed, &self.backend_path(), &state, &home, resources());
        DeviceFixture { home, config }
    }
}

/// 在设备一上准备一份「块外内容 + 受管区块」的 `.zshrc` 和一个 Full File 资源。
fn seed_device_one(device: &DeviceFixture, inner: &str) {
    device.write(
        ".zshrc",
        &format!("{DEV1_PROLOGUE}{}{DEV1_EPILOGUE}", block(inner)),
    );
    device.write(".gitconfig", GIT_V1);
}

/// 走一遍 capture → plan → sync，返回 `(快照标识, 应用结果)`。
fn capture_plan_sync(service: &mut EnvSyncService) -> (SnapshotId, ApplyOutcome) {
    let capture = service.capture().expect("capture 成功");
    let plan = service.build_plan().expect("build_plan 成功");
    let outcome = service.apply_plan(plan.id()).expect("apply_plan 成功");
    (capture.snapshot, outcome)
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

/// 验收条件：`init_workspace` 生成的配置能被 `WorkspaceConfig::load` 原样读回。
#[test]
fn init_workspace_writes_a_config_that_loads_back() {
    let dir = tempfile::tempdir().expect("临时目录");
    let config_path = dir.path().join("workspace.yaml");
    let backend_path = dir.path().join("backend");

    let created = EnvSyncService::init_workspace(&config_path, "workstation", &backend_path)
        .expect("初始化成功");

    let loaded = WorkspaceConfig::load(&config_path).expect("配置必须能被读回");
    assert_eq!(loaded, created, "写出的配置与读回的配置必须一致");
    assert!(backend_path.join("format").exists(), "后端布局应当已建立");
    assert!(created.state_dir.exists(), "状态目录应当已建立");

    // 读回的配置可以直接打开服务。
    let service = EnvSyncService::open_with_clock(loaded, Arc::new(FixedClock(FIXED_NOW)));
    assert!(service.is_ok(), "读回的配置必须可用");
}

/// 验收条件：重复 `init` 必须报错且**不覆盖**已有配置。
#[test]
fn init_workspace_refuses_to_overwrite_an_existing_config() {
    let dir = tempfile::tempdir().expect("临时目录");
    let config_path = dir.path().join("workspace.yaml");
    let backend_path = dir.path().join("backend");

    EnvSyncService::init_workspace(&config_path, "first", &backend_path).expect("首次初始化");
    let original = std::fs::read_to_string(&config_path).expect("读取首次写出的配置");

    let error = EnvSyncService::init_workspace(&config_path, "second", &backend_path)
        .expect_err("重复初始化必须失败");
    assert_eq!(error.code(), "recovery.manual_required");

    assert_eq!(
        std::fs::read_to_string(&config_path).unwrap(),
        original,
        "失败的初始化绝不能改动已有配置文件"
    );
}

// ---------------------------------------------------------------------------
// capture
// ---------------------------------------------------------------------------

/// 验收条件：capture 保存草稿 Blob/State/Snapshot，但**不更新后端 Ref**。
#[test]
fn capture_writes_drafts_only_and_never_touches_the_backend_ref() {
    let world = World::new();
    let device = world.device("one", SEED_A);
    seed_device_one(&device, BLOCK_V1);

    let mut service = device.service();
    let capture = service.capture().expect("capture 成功");
    assert!(capture.changed, "首次 capture 必然产生新快照");

    // 草稿库里三类对象齐备。
    let drafts = service.drafts();
    assert!(
        drafts
            .has(ObjectId::from(BlobId::of(BLOCK_V1.as_bytes())))
            .unwrap(),
        "Managed Block 的块内内容必须作为 Blob 落草稿库"
    );
    assert!(
        drafts
            .has(ObjectId::from(BlobId::of(GIT_V1.as_bytes())))
            .unwrap(),
        "Full File 的完整内容必须作为 Blob 落草稿库"
    );
    assert!(drafts.has(ObjectId::from(capture.state_root)).unwrap());
    assert!(drafts.has(ObjectId::from(capture.snapshot)).unwrap());
    assert_eq!(drafts.head_draft().unwrap(), Some(capture.snapshot));

    // 后端一个字节都没动。
    assert!(
        matches!(
            world.backend().get_ref(workspace_id()),
            Err(BackendError::RefNotFound(_))
        ),
        "capture 之后后端 Ref 仍应不存在"
    );
    assert_eq!(world.revision(), 0);
    assert!(
        !world
            .backend()
            .has_object(ObjectId::from(capture.snapshot))
            .unwrap(),
        "草稿对象绝不能污染后端"
    );
}

/// 验收条件：内容没变时重复 capture 是幂等的（`changed == false`）。
#[test]
fn repeated_capture_is_idempotent() {
    let world = World::new();
    let device = world.device("one", SEED_A);
    seed_device_one(&device, BLOCK_V1);

    let mut service = device.service();
    let first = service.capture().expect("首次 capture");
    let second = service.capture().expect("再次 capture");

    assert!(first.changed);
    assert_eq!(
        second.state_root, first.state_root,
        "内容没变时 State Root 必须相同"
    );
    // 第二次 capture 时后端仍无头，因此仍会生成快照对象，但状态是等价的。
    assert_eq!(second.snapshot, first.snapshot, "快照标识必须可复现");

    // 同步之后再 capture，才能走到「已经等于后端头」这条幂等分支。
    let plan = service.build_plan().expect("build_plan");
    service.apply_plan(plan.id()).expect("apply_plan");
    let third = service.capture().expect("同步后再次 capture");
    assert!(!third.changed, "内容与后端头一致时 changed 必须为 false");
    assert_eq!(third.snapshot, first.snapshot);
    assert_eq!(third.state_root, first.state_root);
}

/// 验收条件：capture 时资源**读不到**要沿用上一版快照条目，绝不变成删除。
///
/// 这里把 `.gitconfig` 换成一个目录，观察结果就是 `Unreadable`（既不是 `Present`
/// 也不是 `Absent`）。capture 必须留下 `capture.reused_previous` 诊断，并保持 State
/// Root 不变。
#[test]
fn capture_reuses_previous_entry_when_a_resource_is_unreadable() {
    let world = World::new();
    let device = world.device("one", SEED_A);
    seed_device_one(&device, BLOCK_V1);

    let mut service = device.service();
    let (snapshot, _) = capture_plan_sync(&mut service);
    let baseline = service.capture().expect("基线 capture");
    assert!(!baseline.changed);

    // 让 `.gitconfig` 变成一个目录：存在，但读不出内容。
    std::fs::remove_file(device.home.join(".gitconfig")).expect("移除文件");
    std::fs::create_dir(device.home.join(".gitconfig")).expect("放一个目录上去");

    let capture = service.capture().expect("capture 仍应成功");
    let codes: Vec<&str> = capture
        .diagnostics
        .iter()
        .map(|d| d.code.as_str())
        .collect();
    assert!(
        codes.contains(&"capture.unreadable"),
        "必须报告读不到：{codes:?}"
    );
    assert!(
        codes.contains(&"capture.reused_previous"),
        "必须明确说明沿用了上一版快照条目：{codes:?}"
    );
    assert_eq!(
        capture.state_root, baseline.state_root,
        "读不到绝不能变成删除，State Root 必须原样保留该条目"
    );
    assert_eq!(capture.snapshot, snapshot);
    assert!(!capture.changed);
}

/// 资源被用户删掉时同样沿用上一版条目：`absent` 不等于 `ensure_absent`。
#[test]
fn capture_never_turns_a_missing_file_into_a_deletion() {
    let world = World::new();
    let device = world.device("one", SEED_A);
    seed_device_one(&device, BLOCK_V1);

    let mut service = device.service();
    let (_, _) = capture_plan_sync(&mut service);
    let baseline = service.capture().expect("基线 capture");

    std::fs::remove_file(device.home.join(".gitconfig")).expect("删除文件");

    let capture = service.capture().expect("capture 仍应成功");
    assert!(
        capture
            .diagnostics
            .iter()
            .any(|d| d.code == "capture.reused_previous"),
        "缺失资源必须沿用上一版条目并留下诊断"
    );
    assert_eq!(
        capture.state_root, baseline.state_root,
        "缺失绝不能被推断为删除意图"
    );

    // 因此重新计划出来的动作是「把文件恢复回来」，而不是「删掉别的东西」。
    let plan = service.build_plan().expect("build_plan");
    assert!(
        plan.actions.iter().all(|action| !action.kind.is_delete()),
        "绝不应出现删除动作：{:?}",
        plan.actions
    );
}

// ---------------------------------------------------------------------------
// plan
// ---------------------------------------------------------------------------

/// 验收条件：plan 同时比较草稿头、后端头与本机观察。
#[test]
fn plan_binds_draft_head_backend_ref_and_local_observations() {
    let world = World::new();
    let device = world.device("one", SEED_A);
    seed_device_one(&device, BLOCK_V1);

    let mut service = device.service();
    let capture = service.capture().expect("capture");

    // 后端尚无头：目标取草稿头，next_ref 必须前进一格（需要发布）。
    let plan = service.build_plan().expect("build_plan");
    assert_eq!(plan.target_snapshot, capture.snapshot, "目标必须是草稿头");
    assert_eq!(plan.base_revision, 0, "必须绑定生成计划时的后端 revision");
    assert_eq!(plan.next_ref.revision, 1);
    assert!(envsync_core::planner::requires_publish(&plan));

    // 观察必须来自本机现状。
    let zsh = plan
        .observation(&support::rid(ZSHRC))
        .expect("必须包含 .zshrc 的观察");
    assert_eq!(zsh.state.kind(), "present");
    assert_eq!(
        zsh.state.content_digest(),
        Some(support::digest_of(device.read(".zshrc").as_bytes())),
        "观察里的摘要必须等于磁盘上的真实内容"
    );

    // 发布之后：目标已经是后端头，只需本地收敛，不再需要 CAS。
    service.apply_plan(plan.id()).expect("apply_plan");
    let after = service.build_plan().expect("再次 build_plan");
    assert_eq!(after.base_revision, 1, "必须反映后端新的 revision");
    assert_eq!(after.next_ref.revision, 1);
    assert!(!envsync_core::planner::requires_publish(&after));
    assert!(after.actions.is_empty(), "已经收敛后不应再有动作");
}

// ---------------------------------------------------------------------------
// apply_plan 的新鲜度
// ---------------------------------------------------------------------------

/// 验收条件：`apply_plan` 只接受匹配的 Plan ID。
#[test]
fn apply_plan_rejects_an_unknown_plan_id() {
    let world = World::new();
    let device = world.device("one", SEED_A);
    seed_device_one(&device, BLOCK_V1);

    let mut service = device.service();
    service.capture().expect("capture");
    service.build_plan().expect("build_plan");

    let error = service
        .apply_plan(PlanId::of(b"never-generated"))
        .expect_err("未知计划必须被拒绝");
    assert_eq!(error.code(), "plan.not_found");
    assert_eq!(world.revision(), 0, "被拒绝的计划不得发布");
}

/// 桌面后台 worker 预先分配的 operation ID 必须原样进入 journal；若 UI 在 publish 前已经
/// 请求取消，则事务留下 aborted 审计记录且后端 Ref 不前进。
#[test]
fn apply_plan_with_operation_id_honours_cancellation_before_publish() {
    struct AlreadyCancelled;

    impl ApplyCancellation for AlreadyCancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }

    let world = World::new();
    let device = world.device("one", SEED_A);
    seed_device_one(&device, BLOCK_V1);
    let mut service = device.service();
    service.capture().expect("capture");
    let plan = service.build_plan().expect("build_plan");
    let operation = "12345678-1234-4234-8234-123456789abc"
        .parse()
        .expect("固定 operation 标识有效");

    let error = service
        .apply_plan_with_operation(plan.id(), operation, &AlreadyCancelled)
        .expect_err("取消必须阻止 publish");

    assert_eq!(error.code(), "operation.cancelled");
    assert_eq!(world.revision(), 0, "取消前不得推进后端 Ref");
    let record = service
        .journal()
        .operation(operation)
        .expect("读取 operation")
        .expect("取消仍必须留下 journal 记录");
    assert_eq!(record.state, OperationState::Aborted);
}

/// 验收条件：应用前文件被外部修改时 Plan 失效（设计文档 §12）。
///
/// 计划绑定了生成时的全部观察结果，因此「plan 之后手工改动目标文件」必然导致重新
/// 计算出的计划标识不同，服务必须返回 `StalePlan` 而不是照旧写入。
#[test]
fn apply_plan_rejects_a_stale_plan_after_the_target_changed() {
    let world = World::new();
    let device = world.device("one", SEED_A);
    seed_device_one(&device, BLOCK_V1);

    let mut service = device.service();
    service.capture().expect("capture");
    let plan = service.build_plan().expect("build_plan");

    // 计划生成之后，用户又手工改了目标文件。
    device.write(".gitconfig", "[user]\n\tname = mallory\n");

    let error = service
        .apply_plan(plan.id())
        .expect_err("过期计划必须被拒绝");
    assert!(error.is_stale_plan(), "必须被识别为 stale plan：{error}");
    assert_eq!(error.code(), "plan.stale");

    assert_eq!(world.revision(), 0, "过期计划不得发布");
    assert_eq!(
        device.read(".gitconfig"),
        "[user]\n\tname = mallory\n",
        "用户的新修改不得被覆盖"
    );
}

// ---------------------------------------------------------------------------
// 完整闭环与第二台设备
// ---------------------------------------------------------------------------

/// 验收条件：完整 capture → plan → sync → 内容正确 → status 为 clean。
#[test]
fn full_loop_converges_and_ends_clean() {
    let world = World::new();
    let device = world.device("one", SEED_A);
    seed_device_one(&device, BLOCK_V1);
    let before = device.read(".zshrc");

    let mut service = device.service();
    let (snapshot, outcome) = capture_plan_sync(&mut service);

    match outcome {
        ApplyOutcome::Completed { published, .. } => assert!(published, "首次同步必须发布"),
        // 设备一的磁盘内容本来就等于快照内容，因此本地无需任何动作。
        ApplyOutcome::NoOp => panic!("需要发布时不应是 NoOp"),
    }
    assert_eq!(world.revision(), 1);
    assert_eq!(world.head(), Some(snapshot));
    assert_eq!(
        device.read(".zshrc"),
        before,
        "源设备本来就已收敛，同步不应改动它的文件"
    );

    let status = service.status().expect("status");
    assert_eq!(status.state, WorkspaceState::Clean);
    assert_eq!(status.revision, 1);
    assert_eq!(status.head, Some(snapshot));
    assert_eq!(status.draft_head, None, "同步成功后草稿头必须被清除");
    assert_eq!(status.pending_actions, 0);
    assert!(status.unfinished.is_empty());
    assert_eq!(status.resources.len(), 2);
}

/// 验收条件：第二台设备拉取后内容一致，且 State Root 与 Snapshot ID 相同；
/// Managed Block 场景下块外内容在整个流程中逐字节不变。
#[test]
fn second_device_pulls_identical_state_and_preserves_its_own_content() {
    let world = World::new();
    let one = world.device("one", SEED_A);
    let two = world.device("two", SEED_B);

    seed_device_one(&one, BLOCK_V1);
    // 设备二有自己的 `.zshrc`，块外内容与设备一完全不同，且还没有受管区块。
    two.write(".zshrc", &format!("{DEV2_PROLOGUE}{DEV2_EPILOGUE}"));
    assert!(!two.exists(".gitconfig"));

    // ---- 第一轮：设备一发布 ----
    let mut svc_one = one.service();
    let source = svc_one.capture().expect("capture");
    let plan = svc_one.build_plan().expect("build_plan");
    svc_one.apply_plan(plan.id()).expect("apply_plan");

    // ---- 设备二拉取 ----
    let mut svc_two = two.service();
    let pull = svc_two.build_plan().expect("设备二基于后端头生成计划");
    assert_eq!(pull.target_snapshot, source.snapshot, "两台设备的目标一致");
    assert!(
        !envsync_core::planner::requires_publish(&pull),
        "拉取不需要再发布一次"
    );
    svc_two.apply_plan(pull.id()).expect("设备二应用计划");

    // 内容一致：块内内容相同，Full File 逐字节相同。
    assert_eq!(two.read(".gitconfig"), GIT_V1);
    assert_eq!(
        two.read(".zshrc"),
        format!("{DEV2_PROLOGUE}{DEV2_EPILOGUE}{}", block(BLOCK_V1)),
        "受管区块被追加到文件末尾，块外内容逐字节保留"
    );

    // State Root 与 Snapshot ID 相同。
    let echo = svc_two.capture().expect("设备二 capture");
    assert!(!echo.changed, "内容已经一致，不应产生新快照");
    assert_eq!(
        echo.state_root, source.state_root,
        "两台设备的 State Root 必须相同"
    );
    assert_eq!(
        echo.snapshot, source.snapshot,
        "两台设备的 Snapshot ID 必须相同"
    );
    assert_eq!(svc_two.status().unwrap().state, WorkspaceState::Clean);

    // ---- 第二轮：设备一改动区块内容，设备二再次拉取 ----
    one.write(
        ".zshrc",
        &format!("{DEV1_PROLOGUE}{}{DEV1_EPILOGUE}", block(BLOCK_V2)),
    );
    let updated = svc_one.capture().expect("再次 capture");
    assert!(updated.changed);
    let plan = svc_one.build_plan().expect("build_plan");
    svc_one.apply_plan(plan.id()).expect("apply_plan");
    assert_eq!(world.revision(), 2);

    let pull = svc_two.build_plan().expect("设备二再次生成计划");
    assert_eq!(pull.actions.len(), 1, "只有 .zshrc 需要更新");
    assert_eq!(
        pull.actions[0].kind,
        envsync_domain::ActionKind::UpdateManagedBlock
    );
    svc_two.apply_plan(pull.id()).expect("设备二再次应用");

    assert_eq!(
        two.read(".zshrc"),
        format!("{DEV2_PROLOGUE}{DEV2_EPILOGUE}{}", block(BLOCK_V2)),
        "块外内容在整个流程中必须逐字节不变"
    );
    // 设备一自己的块外内容同样不变。
    assert!(one.read(".zshrc").starts_with(DEV1_PROLOGUE));
    assert!(one.read(".zshrc").ends_with(DEV1_EPILOGUE));

    let echo = svc_two.capture().expect("设备二再次 capture");
    let state_roots: Vec<StateRootId> = vec![echo.state_root, updated.state_root];
    assert_eq!(state_roots[0], state_roots[1], "第二轮同样必须完全一致");
    assert_eq!(echo.snapshot, updated.snapshot);
}

// ---------------------------------------------------------------------------
// status 的三种状态
// ---------------------------------------------------------------------------

/// 验收条件：`status` 能区分 clean / drifted / published_not_converged。
#[test]
fn status_distinguishes_clean_drifted_and_published_not_converged() {
    let world = World::new();
    let device = world.device("one", SEED_A);
    seed_device_one(&device, BLOCK_V1);

    let mut service = device.service();
    capture_plan_sync(&mut service);
    assert_eq!(
        service.status().unwrap().state,
        WorkspaceState::Clean,
        "刚同步完必须是 clean"
    );

    // drifted：本机被改动，存在待应用的动作。
    device.write(".gitconfig", "[user]\n\tname = drifted\n");
    let drifted = service.status().expect("status");
    assert_eq!(drifted.state, WorkspaceState::Drifted);
    assert_eq!(drifted.pending_actions, 1);
    assert!(drifted
        .resources
        .iter()
        .any(|r| r.resource == support::rid(GITCFG) && r.needs_action));

    // published_not_converged：直接用 journal API 造出一次「已发布但本地没跟上」的操作。
    let plan = service.build_plan().expect("build_plan");
    let operation = {
        let mut journal = Journal::open(device.config.journal_path()).expect("另开一条 journal");
        let record = journal.begin(&plan).expect("登记操作");
        for state in [
            OperationState::Preflighted,
            OperationState::Published,
            OperationState::PublishedNotConverged,
        ] {
            journal
                .transition(record.operation, state)
                .expect("驱动状态机");
        }
        journal
            .record_error(
                record.operation,
                &ErrorDetail::new("sync.published_not_converged", "注入的未收敛状态"),
            )
            .expect("记录错误");
        record.operation
    };

    let stuck = service.status().expect("status");
    assert_eq!(
        stuck.state,
        WorkspaceState::PublishedNotConverged,
        "存在未收敛操作时必须压过 drifted"
    );
    assert!(stuck
        .unfinished
        .iter()
        .any(|(id, state)| *id == operation && *state == OperationState::PublishedNotConverged));
}

/// `doctor` 在健康工作区上应当全绿，并且不改变任何状态。
#[test]
fn doctor_reports_a_healthy_workspace_without_changing_anything() {
    let world = World::new();
    let device = world.device("one", SEED_A);
    seed_device_one(&device, BLOCK_V1);

    let mut service = device.service();
    capture_plan_sync(&mut service);

    let before = device.read(".zshrc");
    let report = service.doctor().expect("doctor");
    assert!(report.is_healthy(), "健康工作区应当全绿：{report:?}");
    assert!(report
        .findings
        .iter()
        .any(|f| f.check.contains("授权根") && f.ok));
    assert!(report.recovery.is_empty(), "没有未完成操作就没有恢复建议");
    assert_eq!(device.read(".zshrc"), before, "doctor 绝不改动文件");
}

/// 授权根丢失时 `doctor` 必须如实报告，而不是悄悄跳过该资源。
#[test]
fn doctor_reports_an_unavailable_authorized_root() {
    let world = World::new();
    let device = world.device("one", SEED_A);
    seed_device_one(&device, BLOCK_V1);

    let mut service = device.service();
    capture_plan_sync(&mut service);

    #[cfg(windows)]
    {
        // Windows 不允许在仍持有授权根目录句柄时删除目录；验证底层授权根探测的
        // 失败分类，等价覆盖 doctor 使用的可访问性判据。
        drop(service);
        std::fs::remove_dir_all(&device.home).expect("移除授权根");
        assert!(envsync_platform::AuthorizedRoot::open("home", &device.home).is_err());
    }

    #[cfg(not(windows))]
    {
        std::fs::remove_dir_all(&device.home).expect("移除授权根");
        let report = service.doctor().expect("doctor 仍应返回报告");
        assert!(!report.is_healthy());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.check.contains("授权根") && !f.ok),
            "必须点名不可用的授权根：{report:?}"
        );
    }
}

/// 配置里的相对路径与本机布局无关：服务打开后各路径都在声明的状态目录下。
#[test]
fn service_keeps_all_local_state_under_the_configured_state_dir() {
    let world = World::new();
    let device = world.device("one", SEED_A);
    seed_device_one(&device, BLOCK_V1);

    let mut service = device.service();
    capture_plan_sync(&mut service);

    let state_dir: &Path = &device.config.state_dir;
    assert!(device.config.journal_path().starts_with(state_dir));
    assert!(device.config.draft_dir().starts_with(state_dir));
    assert!(device.config.backup_root().starts_with(state_dir));
    assert!(
        !device.config.backup_root().starts_with(&device.home),
        "备份绝不能落在授权根内，否则会被下一次同步当成用户文件"
    );
    assert!(
        service.journal().path().starts_with(state_dir),
        "journal 必须位于状态目录"
    );
}
