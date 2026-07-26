//! M0 端到端验收套件（计划文档任务 14 的 `tests/e2e/local_file_loop.rs`）。
//!
//! 每个测试都通过 [`std::process::Command`] 启动真正的 `envsync` 二进制，只用
//! `--json` 的对外契约和文件系统本身做断言，**不调用任何库 API 去驱动流程**——
//! 库级流程已由 `crates/envsync-core/tests/` 覆盖，这里要验的是「真实进程 + 真实
//! 退出码 + 真实并发」这一层。
//!
//! 测试之间没有任何共享状态：每个测试各持一个 `E2eWorld`（独立的 `tempfile` 临时
//! 目录、独立的 Local Backend、独立的 journal 与草稿库），因此可以并行执行。
//!
//! # 场景与验收条件对照
//!
//! | 计划文档场景 | 测试函数 |
//! |---|---|
//! | 1 临时授权根 + Local Backend 初始化 | `init_creates_temp_root_backend_and_state_dir` |
//! | 2 捕获 Full File 与 Managed Block | `capture_covers_full_file_and_managed_block` |
//! | 3 生成并保存 Plan | `plan_is_deterministic_and_persisted_in_the_draft_store` |
//! | 4、5 第二设备拉取、块外不变、Snapshot 相同、clean | `second_device_pulls_and_preserves_out_of_block_bytes` |
//! | 6 修改源设备并再次同步 | `source_device_edit_propagates_to_the_second_device` |
//! | 7 回滚第二次 operation | `rolling_back_the_second_operation_restores_the_first_content` |
//! | 8 CAS race，失败方本地零变更 | `cas_race_loser_exits_10_with_zero_local_changes` |
//! | 9 注入 apply 中断并恢复 | `interrupted_apply_is_completed_by_the_next_run` |
//! | 10 缺失不删除，只有 tombstone 才删除 | `missing_resource_is_kept_and_only_ensure_absent_deletes` |
//!
//! 直接对应设计文档 §12 的补充断言：
//!
//! | §12 验收条件 | 测试函数 |
//! |---|---|
//! | 相同输入产生相同确定性标识 | `identical_input_yields_identical_state_root_in_independent_runs` |
//! | 越权路径在读写前被拒绝 | `escaping_targets_are_rejected_before_any_read_or_write` |
//! | 符号链接逃逸在读写前被拒绝 | `symlink_escape_is_rejected_before_any_read_or_write` |
//! | 应用前被外部修改则 Plan 失效（退出码 11） | `externally_modified_target_invalidates_the_plan` |
//! | Managed Block 拒绝重复或畸形 marker | `managed_block_rejects_duplicate_and_malformed_markers` |

use envsync_domain::{DesiredDisposition, FileMode, OperationId};
use envsync_e2e::{
    assert_bytes_eq, resource, wait_for_objects, BackendLock, Device, E2eWorld, PlanInfo,
};
use envsync_storage::OperationState;

// ---------------------------------------------------------------------------
// 固定数据
// ---------------------------------------------------------------------------

/// Managed Block 资源：只管理 `.zshrc` 里带 marker 的那一段。
const ZSHRC: &str = "shell/zsh/main";
/// Full File 资源：整个 `.gitconfig` 都归 EnvSync 管。
const GITCONFIG: &str = "git/config";
/// 一个只存在于第二台设备上的资源，用来验证「缺失 ≠ 删除」。
const STARSHIP: &str = "prompt/starship";

/// 源设备 `.zshrc` 的块外内容：整个流程中必须逐字节不变。
const A_PROLOGUE: &str = "# 源设备自己的设置\nalias ll='ls -l'\n";
const A_EPILOGUE: &str = "export PATH=\"$HOME/bin:$PATH\"\n";
/// 第二台设备的块外内容，刻意与源设备不同。
const B_PROLOGUE: &str = "# 第二台设备自己的设置\nexport LANG=C.UTF-8\n";
const B_EPILOGUE: &str = "# 第二台设备的收尾\nsource ~/.local.zsh\n";

/// 受管区块的**块内**内容，也就是 Blob 的字节。
const BLOCK_V1: &str = "export EDITOR=nvim\n";
const BLOCK_V2: &str = "export EDITOR=helix\nexport VISUAL=helix\n";
/// Full File 资源的内容。
const GIT_V1: &str = "[user]\n\tname = alice\n";
const GIT_V2: &str = "[user]\n\tname = alice\n\temail = alice@example.com\n";

/// 拼一个完整的受管区块（LF 换行、默认 `# ` 注释前缀）。
fn block(inner: &str) -> String {
    format!("# >>> envsync:{ZSHRC}\n{inner}# <<< envsync:{ZSHRC}\n")
}

/// M0 支持的两种模式各一个资源，顺序即计划里的动作顺序。
fn two_modes() -> Vec<envsync_core::ResourceConfig> {
    vec![
        resource(
            ZSHRC,
            ".zshrc",
            FileMode::ManagedBlock,
            DesiredDisposition::Managed,
        ),
        resource(
            GITCONFIG,
            ".gitconfig",
            FileMode::FullFile,
            DesiredDisposition::Managed,
        ),
    ]
}

/// 源设备：两个资源都已就位，`.zshrc` 的受管区块前后各有一段自有内容。
fn source_device(world: &E2eWorld) -> Device {
    let device = world.primary("laptop");
    device.set_resources(two_modes());
    device.write_home(
        ".zshrc",
        format!("{A_PROLOGUE}{}{A_EPILOGUE}", block(BLOCK_V1)),
    );
    device.write_home(".gitconfig", GIT_V1);
    device
}

/// 第二台设备：同一后端、同一 workspace_id，但授权根、状态目录、设备身份都不同。
///
/// 它的 `.zshrc` 里已经有一对**空的** marker，前后各有一段自有内容——这样才能验证
/// 「块内被替换、块外一个字节都没动」。`.gitconfig` 则完全不存在，走创建路径。
fn second_device(world: &E2eWorld, source: &Device) -> Device {
    let device = world.secondary(source, "desktop");
    device.set_resources(two_modes());
    device.write_home(".zshrc", format!("{B_PROLOGUE}{}{B_EPILOGUE}", block("")));
    device
}

/// 第二台设备同步某一版块内内容之后，`.zshrc` 应有的完整内容。
fn second_device_zshrc(inner: &str) -> String {
    format!("{B_PROLOGUE}{}{B_EPILOGUE}", block(inner))
}

/// 源设备 `.zshrc` 应有的完整内容。
fn source_device_zshrc(inner: &str) -> String {
    format!("{A_PROLOGUE}{}{A_EPILOGUE}", block(inner))
}

/// 一个已经发布过第一版内容的世界：源设备已 `capture` + `sync`，第二台设备尚未同步。
fn published_world() -> (E2eWorld, Device, Device) {
    let world = E2eWorld::new();
    let source = source_device(&world);
    let second = second_device(&world, &source);

    let capture = source.capture();
    assert!(capture.changed, "首次捕获应当产生新草稿");
    let sync = source.converge();
    assert_eq!(sync.outcome, "completed");
    assert!(sync.published, "首次同步必须向后端发布新引用");

    (world, source, second)
}

// ---------------------------------------------------------------------------
// 场景 1
// ---------------------------------------------------------------------------

/// 场景 1：临时授权根 + Local Backend 初始化。
///
/// `envsync init` 必须一次性把「配置文件、后端目录布局、本地状态目录」都建好，
/// 并且生成的配置能被原样读回——否则后续任何命令都无从谈起。
#[test]
fn init_creates_temp_root_backend_and_state_dir() {
    let world = E2eWorld::new();
    let device = world.primary("laptop");

    let init = device
        .init_json()
        .expect("第一台设备应当有 init 的 JSON 输出")
        .clone();
    assert_eq!(init["schema_version"], 1);
    assert_eq!(init["command"], "init");
    assert_eq!(init["status"], "ok");
    assert_eq!(init["data"]["backend_kind"], "local");
    assert_eq!(init["data"]["device_name"], "laptop");

    // 后端布局：内容寻址对象库 + 引用目录 + 每工作区的锁目录。
    for sub in ["objects", "refs", "locks"] {
        assert!(
            world.backend().join(sub).is_dir(),
            "Local Backend 应当建好 `{sub}/` 目录"
        );
    }

    // 授权根是本次测试专属的临时目录，不是跑测试的人的家目录。
    let config = device.config();
    let home = config.roots.get("home").expect("配置里应当声明 home 根");
    assert_eq!(home, device.home(), "授权根必须指向临时目录");
    assert!(
        home.starts_with(world.path()),
        "授权根必须落在临时目录内，实际是 {home:?}"
    );

    // 状态目录（journal / 草稿 / 备份）已建好，且 `status` 立刻可用。
    assert!(device.state_dir().is_dir(), "状态目录应当已创建");
    let status = device.status();
    assert_eq!(status["backend_kind"], "local");
    assert_eq!(status["revision"], 0);
    assert!(status["head"].is_null(), "刚初始化的工作区没有头");
    assert_eq!(status["state"], "clean");

    // 空工作区也应当体检全绿。
    let doctor = device.run_json(&["doctor"]);
    doctor.expect_ok();
    assert_eq!(doctor.data()["healthy"], true);
}

// ---------------------------------------------------------------------------
// 场景 2
// ---------------------------------------------------------------------------

/// 场景 2：同一次 capture 同时覆盖 Full File 与 Managed Block 两类资源。
///
/// 关键断言是「Managed Block 捕获的是**块内**内容」：如果实现把整个 `.zshrc` 存进
/// 快照，第二台设备就会连别人的别名和 PATH 一起被覆盖。这里直接把草稿库里的 Blob
/// 原始字节取出来逐字节比对，而不是只看命令是否成功。
#[test]
fn capture_covers_full_file_and_managed_block() {
    let world = E2eWorld::new();
    let device = source_device(&world);

    let capture = device.capture();
    assert!(capture.changed);
    assert_eq!(capture.snapshot.len(), 64, "快照标识是 64 位十六进制");
    assert_eq!(capture.state_root.len(), 64);
    assert!(
        capture.diagnostic_codes.is_empty(),
        "两个资源都在位时不应有诊断：{:?}",
        capture.diagnostic_codes
    );

    // Managed Block：Blob 只含块内内容。
    let zsh_blob = device
        .draft_blob_of(&capture.snapshot, ZSHRC)
        .expect("快照里应当有 Managed Block 资源的 Blob");
    assert_bytes_eq(&zsh_blob, BLOCK_V1.as_bytes(), "Managed Block 的 Blob");

    // Full File：Blob 是整个文件。
    let git_blob = device
        .draft_blob_of(&capture.snapshot, GITCONFIG)
        .expect("快照里应当有 Full File 资源的 Blob");
    assert_bytes_eq(&git_blob, GIT_V1.as_bytes(), "Full File 的 Blob");

    // capture 只写本地草稿：后端 Ref 一动不动。
    let status = device.status();
    assert_eq!(status["revision"], 0, "capture 不得推进后端 revision");
    assert!(status["head"].is_null(), "capture 不得更新后端头");
    assert_eq!(status["draft_head"], capture.snapshot.as_str());
    assert_eq!(status["state"], "drifted");

    // 两个资源都被观察为 present 且处置为 managed。
    let resources = status["resources"].as_array().expect("resources 是数组");
    assert_eq!(resources.len(), 2);
    for entry in resources {
        assert_eq!(entry["observed"], "present", "{entry}");
        assert_eq!(entry["disposition"], "managed", "{entry}");
    }

    // 源设备自己的文件在 capture 前后逐字节不变——capture 是纯读操作。
    device.assert_home_bytes(".zshrc", &source_device_zshrc(BLOCK_V1));
    device.assert_home_bytes(".gitconfig", GIT_V1);
}

// ---------------------------------------------------------------------------
// 场景 3
// ---------------------------------------------------------------------------

/// 场景 3：生成并保存 Plan，`--json` 取回 plan id。
///
/// Plan 必须是「同样的输入 → 同样的标识」，并且真的落进了本地草稿库——否则
/// `sync --plan <id>` 只能靠运气找到它。
#[test]
fn plan_is_deterministic_and_persisted_in_the_draft_store() {
    let world = E2eWorld::new();
    let device = source_device(&world);
    device.capture();

    // 制造一处本地漂移，让计划里确实有动作可看。
    device.write_home(".gitconfig", "[user]\n\tname = 被别人改过\n");

    let first: PlanInfo = device.plan();
    assert_eq!(first.id.len(), 64, "计划标识是 64 位十六进制");
    assert_eq!(first.action_count, 1);
    assert!(!first.blocked);
    assert_eq!(first.base_revision, 0);
    assert_eq!(first.next_revision, 1, "目标快照尚未发布，Ref 需要前进");

    let action = first
        .action(GITCONFIG)
        .expect("漂移的 Full File 资源应当有一个动作");
    assert_eq!(action["kind"], "replace_file");
    assert_eq!(
        action["target"], "home:.gitconfig",
        "计划里只能出现「根别名 + 相对路径」，绝不能是绝对路径"
    );
    assert_eq!(action["rollback"], "exact");
    assert_eq!(action["backup"], "required");
    assert_eq!(action["sensitive"], false);

    // 输入没变 → 标识必须一模一样。
    let second = device.plan();
    assert_eq!(
        first.id, second.id,
        "同样的输入必须产生同一个不可变计划标识"
    );

    // 计划确实被保存了：草稿库里按标识取得回来，动作数量一致。
    let stored = device
        .drafts()
        .get_plan(first.id.parse().expect("计划标识应当合法"))
        .expect("草稿库可读")
        .expect("计划应当已保存在草稿库里");
    assert_eq!(stored.actions.len(), first.action_count);
    assert_eq!(stored.id().to_hex(), first.id);
}

// ---------------------------------------------------------------------------
// 场景 4、5
// ---------------------------------------------------------------------------

/// 场景 4、5：第二台设备拉取并应用；块外内容逐字节不变、两端 Snapshot ID 相同、
/// 两端状态都是 clean。
#[test]
fn second_device_pulls_and_preserves_out_of_block_bytes() {
    let (_world, source, second) = published_world();

    // 同步前先把第二台设备的原始字节记下来，用于事后比对块外内容。
    let before = second.read_home(".zshrc");
    assert!(
        !second.home_exists(".gitconfig"),
        "第二台设备原本没有该文件"
    );

    let plan = second.plan();
    assert_eq!(plan.action_count, 2, "两个资源都需要写入");
    assert_eq!(plan.base_revision, 1);
    assert_eq!(
        plan.next_revision, 1,
        "拉取别人的快照不需要再发布一次，Ref 不应前进"
    );
    assert_eq!(
        plan.action(ZSHRC).expect("应当有 Managed Block 动作")["kind"],
        "update_managed_block"
    );
    assert_eq!(
        plan.action(GITCONFIG).expect("应当有 Full File 动作")["kind"],
        "create_file"
    );

    let sync = second.sync(&plan.id);
    sync.expect_ok();
    assert_eq!(sync.data()["outcome"], "completed");
    assert_eq!(sync.data()["applied"], 2);
    assert_eq!(
        sync.data()["published"],
        false,
        "第二台设备只是本地收敛，不该动后端 Ref"
    );

    // 场景 5-a：块内被替换，块外**逐字节**不变。
    second.assert_home_bytes(".zshrc", &second_device_zshrc(BLOCK_V1));
    let after = second.read_home(".zshrc");
    assert_bytes_eq(
        &after[..B_PROLOGUE.len()],
        &before[..B_PROLOGUE.len()],
        "第二台设备的块前内容",
    );
    assert_bytes_eq(
        &after[after.len() - B_EPILOGUE.len()..],
        &before[before.len() - B_EPILOGUE.len()..],
        "第二台设备的块后内容",
    );

    // Full File 资源被逐字节复制过来。
    second.assert_home_bytes(".gitconfig", GIT_V1);

    // 源设备的文件没有被这次同步碰过。
    source.assert_home_bytes(".zshrc", &source_device_zshrc(BLOCK_V1));
    source.assert_home_bytes(".gitconfig", GIT_V1);

    // 场景 5-b：两端 Snapshot ID 相同，且都是 clean。
    let source_status = source.status();
    let second_status = second.status();
    assert_eq!(
        source_status["head"], second_status["head"],
        "两台设备必须指向同一个快照"
    );
    assert_eq!(source_status["head"], plan.target_snapshot.as_str());
    assert_eq!(source_status["state"], "clean");
    assert_eq!(second_status["state"], "clean");
    assert_eq!(source_status["pending_actions"], 0);
    assert_eq!(second_status["pending_actions"], 0);
    assert!(second_status["draft_head"].is_null());
    for status in [&source_status, &second_status] {
        assert!(
            status["unfinished"]
                .as_array()
                .expect("unfinished 是数组")
                .is_empty(),
            "收敛之后不应有未完成操作：{status}"
        );
    }
}

// ---------------------------------------------------------------------------
// 场景 6
// ---------------------------------------------------------------------------

/// 场景 6：修改源设备并再次同步，第二台设备拿到第二版内容。
///
/// 这一轮里两个资源都变了，而第二台设备的块外内容依然必须逐字节不变。
#[test]
fn source_device_edit_propagates_to_the_second_device() {
    let (_world, source, second) = published_world();
    second.converge();
    second.assert_home_bytes(".zshrc", &second_device_zshrc(BLOCK_V1));

    // 源设备改动两个资源，重新捕获并发布。
    source.write_home(".zshrc", source_device_zshrc(BLOCK_V2));
    source.write_home(".gitconfig", GIT_V2);
    let capture = source.capture();
    assert!(capture.changed, "内容变了就必须产生新草稿");

    let plan = source.plan();
    assert_eq!(
        plan.action_count, 0,
        "源设备本机已经是目标内容，只需要发布，不需要写文件"
    );
    assert_eq!(plan.base_revision, 1);
    assert_eq!(plan.next_revision, 2);
    let sync = source.sync(&plan.id);
    sync.expect_ok();
    assert_eq!(sync.data()["published"], true);

    // 第二台设备再同步一次。
    let second_plan = second.plan();
    assert_eq!(second_plan.action_count, 2);
    assert_eq!(second_plan.base_revision, 2);
    let second_sync = second.sync(&second_plan.id);
    second_sync.expect_ok();
    assert_eq!(second_sync.data()["applied"], 2);

    second.assert_home_bytes(".zshrc", &second_device_zshrc(BLOCK_V2));
    second.assert_home_bytes(".gitconfig", GIT_V2);
    assert_eq!(second.status()["state"], "clean");
    assert_eq!(source.status()["revision"], 2);
}

// ---------------------------------------------------------------------------
// 场景 7
// ---------------------------------------------------------------------------

/// 场景 7：回滚第二次 operation，验证恢复到第一次同步后的内容。
///
/// 回滚必须依据收据把**每一个**被改动的文件还原到该次操作应用前的样子，块外内容
/// 同样逐字节不变。
#[test]
fn rolling_back_the_second_operation_restores_the_first_content() {
    let (_world, source, second) = published_world();

    // 第一次：第二台设备同步到 V1。
    let first_operation = second.converge();
    assert_eq!(first_operation.applied, 2);
    let after_first_zshrc = second.read_home(".zshrc");
    let after_first_git = second.read_home(".gitconfig");
    assert_bytes_eq(
        &after_first_zshrc,
        second_device_zshrc(BLOCK_V1).as_bytes(),
        "第一次同步后的 .zshrc",
    );

    // 源设备发布 V2。
    source.write_home(".zshrc", source_device_zshrc(BLOCK_V2));
    source.write_home(".gitconfig", GIT_V2);
    source.capture();
    source.converge();

    // 第二次：第二台设备同步到 V2。
    let second_operation = second.converge();
    assert_eq!(second_operation.applied, 2);
    second.assert_home_bytes(".zshrc", &second_device_zshrc(BLOCK_V2));
    second.assert_home_bytes(".gitconfig", GIT_V2);

    // 回滚第二次 operation。
    let rollback = second.run_json(&["rollback", "--operation", second_operation.operation()]);
    rollback.expect_ok();
    let data = rollback.data();
    assert_eq!(data["handled"], 1);
    assert_eq!(
        data["operations"][0]["operation"],
        second_operation.operation()
    );
    assert_eq!(data["operations"][0]["before"], "completed");
    assert_eq!(data["operations"][0]["after"], "rolled_back");

    // 内容回到第一次同步后的样子——逐字节比对，块外内容同样必须原封不动。
    assert_bytes_eq(
        &second.read_home(".zshrc"),
        &after_first_zshrc,
        "回滚后的 .zshrc",
    );
    assert_bytes_eq(
        &second.read_home(".gitconfig"),
        &after_first_git,
        "回滚后的 .gitconfig",
    );

    // 回滚只动本地文件，后端 Ref 仍然指向 V2。
    assert_eq!(second.status()["revision"], 2);
}

// ---------------------------------------------------------------------------
// 场景 8 / 设计文档 §12：CAS 冲突时本地文件没有任何变化
// ---------------------------------------------------------------------------

/// 场景 8：两台设备从同一 revision 各自发布，失败方退出码 10 且**本地零变更**。
///
/// 制造竞争的办法是先占住后端的 per-workspace 锁，让两个 `sync` 都完成「重新计划 +
/// 上传对象」后停在 CAS 之前；释放锁后谁先拿到锁谁赢。失败方必须在 CAS 之前中止，
/// 因此它的目标文件在 sync 前后**逐字节完全相同**。
#[test]
fn cas_race_loser_exits_10_with_zero_local_changes() {
    let world = E2eWorld::new();
    let only_gitconfig = || {
        vec![resource(
            GITCONFIG,
            ".gitconfig",
            FileMode::FullFile,
            DesiredDisposition::Managed,
        )]
    };

    let first = world.primary("laptop");
    first.set_resources(only_gitconfig());
    let second = world.secondary(&first, "desktop");
    second.set_resources(only_gitconfig());

    // 两台设备各自捕获自己的内容，然后在本地再改一次——于是各自的计划里都有一个
    // 「把本地文件改回快照内容」的写动作。失败方那一个必须一个字节都不落地。
    first.write_home(".gitconfig", "[user]\n\tname = 第一台设备\n");
    second.write_home(".gitconfig", "[user]\n\tname = 第二台设备\n");
    first.capture();
    second.capture();
    first.write_home(".gitconfig", "[user]\n\tname = 第一台设备的本地草稿\n");
    second.write_home(".gitconfig", "[user]\n\tname = 第二台设备的本地草稿\n");

    let first_plan = first.plan();
    let second_plan = second.plan();
    assert_eq!(first_plan.action_count, 1);
    assert_eq!(second_plan.action_count, 1);
    assert_eq!(first_plan.base_revision, 0);
    assert_eq!(
        second_plan.base_revision, 0,
        "两台设备必须从同一 revision 出发"
    );

    let first_before = first.read_home(".gitconfig");
    let second_before = second.read_home(".gitconfig");

    let workspace_id = first.config().workspace_id.to_string();
    let objects_dir = world.backend().join("objects");
    let lock = BackendLock::hold(&world.backend(), &workspace_id);

    // 每台设备发布 blob + state root + snapshot + signature 共 4 个对象；对象上传在
    // CAS 之前完成，因此「对象已到齐」即「该进程正卡在锁上」。
    let first_child = first.spawn_json(&["sync", "--plan", &first_plan.id]);
    wait_for_objects(&objects_dir, 4);
    let second_child = second.spawn_json(&["sync", "--plan", &second_plan.id]);
    wait_for_objects(&objects_dir, 8);

    lock.release();

    let first_run = first_child.wait();
    let second_run = second_child.wait();

    let mut codes = [first_run.code, second_run.code];
    codes.sort_unstable();
    assert_eq!(
        codes,
        [0, 10],
        "恰好一台设备成功、另一台以 CAS 冲突退出\n第一台：{first_run:?}\n第二台：{second_run:?}"
    );

    let (winner, loser, loser_before, loser_device) = if first_run.code == 0 {
        (&first_run, &second_run, &second_before, &second)
    } else {
        (&second_run, &first_run, &first_before, &first)
    };

    loser.expect_diagnostic("cas_conflict");
    assert_eq!(
        loser.json()["status"],
        "error",
        "失败方必须给出结构一致的错误信封"
    );
    assert_eq!(winner.data()["outcome"], "completed");
    assert_eq!(winner.data()["published"], true);

    // 核心断言：失败方的目标文件在 sync 前后逐字节完全相同。
    assert_bytes_eq(
        &loser_device.read_home(".gitconfig"),
        loser_before,
        "CAS 失败方的目标文件",
    );

    // 失败方的日志里也不应留下任何未完成操作：CAS 在本地写入之前就失败了。
    let status = loser_device.status();
    let unfinished = status["unfinished"]
        .as_array()
        .expect("unfinished 是数组")
        .clone();
    assert!(
        unfinished.is_empty(),
        "CAS 在本地写入之前失败，不应留下未完成操作：{unfinished:?}"
    );
    // 后端只前进了一格：CAS 保证 revision 单调。
    assert_eq!(status["revision"], 1);
}

// ---------------------------------------------------------------------------
// 场景 9 / 设计文档 §12：replace 中断后下一次启动能从 journal 恢复
// ---------------------------------------------------------------------------

/// 场景 9：注入 apply 中断，再次启动完成恢复。
///
/// 直接用 `envsync-storage::Journal` 把一次操作驱动到 `applying`，并**只完成计划的
/// 第一个动作**，从而精确复现「进程在两个动作之间被杀掉」的现场（真的 kill 进程会
/// 让中断点不可复现）。随后 `envsync recover` 必须：
///
/// * 认出第一个动作已经生效（当前摘要 == `expected_after`）而不重复应用；
/// * 把尚未生效的第二个动作补上；
/// * 把操作推进到终态；并且连续运行两次结果相同（恢复必须幂等）。
#[test]
fn interrupted_apply_is_completed_by_the_next_run() {
    let (_world, _source, second) = published_world();

    let plan = second.plan();
    assert_eq!(
        plan.action_count, 2,
        "需要一个多动作计划才谈得上「写了一半」"
    );

    // 计划里的动作按 (资源, 种类) 排序，因此 `git/config` 在前、`shell/zsh/main`
    // 在后。前者在第二台设备上还不存在（创建），后者已存在但块内还是空的（更新）。
    let staged = second.plan_actions(&plan.id);
    assert_eq!(staged.len(), 2);
    let first_action = &staged[0];
    let last_action = &staged[1];
    assert_eq!(first_action.resource, GITCONFIG);
    assert_eq!(last_action.resource, ZSHRC);

    // 把 journal 驱动到 applying：planned → preflighted → published → applying。
    let operation = OperationId::generate();
    {
        let stored_plan = second
            .drafts()
            .get_plan(plan.id.parse().expect("计划标识应当合法"))
            .expect("草稿库可读")
            .expect("计划应当已保存");
        let mut journal = second.journal();
        journal
            .begin_with_id(operation, &stored_plan)
            .expect("应当能登记操作");
        for state in [
            OperationState::Preflighted,
            OperationState::Published,
            OperationState::Applying,
        ] {
            journal
                .transition(operation, state)
                .expect("状态迁移应当合法");
        }
    }

    // 摆好现场：第一个动作已经落盘，第二个动作还没开始。
    let content = first_action.content.as_ref().expect("写入类动作一定带内容");
    std::fs::write(&first_action.path, content).expect("应当能写目标文件");
    assert_ne!(
        std::fs::read(&last_action.path).ok(),
        last_action.content,
        "第二个动作此时必须还没生效，否则这个「中断现场」是假的"
    );

    // 中断状态下 `status` 必须如实报告未完成操作。
    let interrupted = second.status();
    let unfinished = interrupted["unfinished"]
        .as_array()
        .expect("unfinished 是数组");
    assert_eq!(unfinished.len(), 1);
    assert_eq!(unfinished[0]["operation"], operation.to_string());
    assert_eq!(unfinished[0]["state"], "applying");

    // 下一次启动：恢复。
    let recover = second.run_json(&["recover"]);
    recover.expect_ok();
    let data = recover.data();
    assert_eq!(data["handled"], 1);
    assert_eq!(data["operations"][0]["operation"], operation.to_string());
    assert_eq!(data["operations"][0]["before"], "applying");
    assert_eq!(
        data["operations"][0]["after"], "completed",
        "恢复必须把中断的操作推到终态：{data}"
    );

    // 两个目标都收敛到计划里的内容，逐字节比对。
    second.assert_home_bytes(".zshrc", &second_device_zshrc(BLOCK_V1));
    second.assert_home_bytes(".gitconfig", GIT_V1);

    // 幂等：再跑一次恢复什么也不做。
    let again = second.run_json(&["recover"]);
    again.expect_ok();
    assert_eq!(again.data()["handled"], 0, "恢复必须幂等");

    let status = second.status();
    assert_eq!(status["state"], "clean");
    assert!(status["unfinished"]
        .as_array()
        .expect("unfinished 是数组")
        .is_empty());
    assert_eq!(
        second
            .journal()
            .operation_state(operation)
            .expect("日志可读")
            .expect("操作应当存在"),
        OperationState::Completed
    );
}

// ---------------------------------------------------------------------------
// 场景 10 / 设计文档 §12：未显式 `ensure_absent` 的资源绝不删除
// ---------------------------------------------------------------------------

/// 场景 10：源设备缺失的资源不会导致第二台设备被删文件；只有显式
/// `disposition: ensure_absent` 才真的删除。
#[test]
fn missing_resource_is_kept_and_only_ensure_absent_deletes() {
    let world = E2eWorld::new();

    let managed_pair = |disposition| {
        vec![
            resource(
                ZSHRC,
                ".zshrc",
                FileMode::ManagedBlock,
                DesiredDisposition::Managed,
            ),
            resource(STARSHIP, ".starship.toml", FileMode::FullFile, disposition),
        ]
    };

    // 源设备根本没有 `.starship.toml`。
    let source = world.primary("laptop");
    source.set_resources(managed_pair(DesiredDisposition::Managed));
    source.write_home(".zshrc", source_device_zshrc(BLOCK_V1));

    let capture = source.capture();
    assert!(
        capture
            .diagnostic_codes
            .iter()
            .any(|code| code == "capture.skipped"),
        "本机没有的资源应当留下诊断而不是被当成删除：{:?}",
        capture.diagnostic_codes
    );
    assert!(
        source.draft_blob_of(&capture.snapshot, STARSHIP).is_none(),
        "缺失的资源不应进入快照"
    );
    source.converge();

    // 第二台设备两个文件都有，其中 `.starship.toml` 是它自己的东西。
    let second = world.secondary(&source, "desktop");
    second.set_resources(managed_pair(DesiredDisposition::Managed));
    second.write_home(".zshrc", format!("{B_PROLOGUE}{}{B_EPILOGUE}", block("")));
    let private = "add_newline = false\n# 只有第二台设备才有的提示符配置\n";
    second.write_home(".starship.toml", private);

    let plan = second.plan();
    assert_eq!(plan.action_count, 1, "只有 .zshrc 需要写入");
    assert!(
        plan.action(STARSHIP).is_none(),
        "缺失的资源不得产生任何动作"
    );
    assert!(
        plan.diagnostic_codes
            .iter()
            .any(|code| code == "resource.not_in_snapshot"),
        "快照里没有该资源时应当只留一条诊断：{:?}",
        plan.diagnostic_codes
    );
    second.sync(&plan.id).expect_ok();

    // 前一半的结论：文件还在，且逐字节没被动过。
    assert!(second.home_exists(".starship.toml"), "缺失 ≠ 删除");
    second.assert_home_bytes(".starship.toml", private);
    second.assert_home_bytes(".zshrc", &second_device_zshrc(BLOCK_V1));

    // 现在改成显式 tombstone，两台设备都更新配置。
    source.set_resources(managed_pair(DesiredDisposition::EnsureAbsent));
    second.set_resources(managed_pair(DesiredDisposition::EnsureAbsent));

    let tombstone = source.capture();
    assert!(tombstone.changed, "处置变了就应当产生新快照");
    source.converge();

    let delete_plan = second.plan();
    assert_eq!(delete_plan.action_count, 1);
    let action = delete_plan
        .action(STARSHIP)
        .expect("显式 tombstone 必须产生删除动作");
    assert_eq!(action["kind"], "delete_file");
    assert_eq!(action["risk"], "high", "删除是高风险动作");
    assert_eq!(action["backup"], "required", "删除前必须备份");
    second.sync(&delete_plan.id).expect_ok();

    // 后一半的结论：只有显式 tombstone 才删除，而且只删该资源。
    assert!(
        !second.home_exists(".starship.toml"),
        "显式 ensure_absent 之后文件应当被删除"
    );
    second.assert_home_bytes(".zshrc", &second_device_zshrc(BLOCK_V1));
    assert_eq!(second.status()["state"], "clean");
}

// ---------------------------------------------------------------------------
// 设计文档 §12：相同输入在不同运行中产生相同确定性标识
// ---------------------------------------------------------------------------

/// 设计文档 §12 第 1 条：相同输入在两次**完全独立**的运行中产生相同的确定性标识。
///
/// 两个互不相干的临时目录、两个各自 `init` 出来的工作区，只要被管理的内容一致，
/// State Root ID 就必须逐字符相同——它是「内容 → 标识」这条确定性链路的核心。
///
/// **本测试刻意不断言 Snapshot ID 相同**：`SnapshotBody` 含有 `created_at_unix_ms`
/// 与作者设备标识，而 CLI 没有提供固定时钟的入口，因此通过真实进程无法让两次独立
/// 运行得到同一个 Snapshot ID；这一条只能在库级测试里用 `FixedClock` 验证。同一个
/// 快照在**多台设备之间**保持同一个 ID 的性质，由
/// `second_device_pulls_and_preserves_out_of_block_bytes` 覆盖。
#[test]
fn identical_input_yields_identical_state_root_in_independent_runs() {
    // `world` 必须一起返回，否则临时目录会在函数返回时被立刻删掉。
    let independent_run = || {
        let world = E2eWorld::new();
        let device = source_device(&world);
        let capture = device.capture();
        (world, capture)
    };

    let (_first_world, first) = independent_run();
    let (_second_world, second) = independent_run();

    assert_eq!(
        first.state_root, second.state_root,
        "相同输入必须产生相同的 State Root ID"
    );
    assert_eq!(first.state_root.len(), 64);
}

// ---------------------------------------------------------------------------
// 设计文档 §12：越权路径与符号链接逃逸在读取或写入前被拒绝
// ---------------------------------------------------------------------------

/// 设计文档 §12 第 2 条（越权路径部分）：`..` 与绝对路径目标在**任何读写之前**就被
/// 配置解析拒绝。
///
/// 断言不止「命令失败」，还包括「根外的那个文件既没被创建也没被改动」。
#[test]
fn escaping_targets_are_rejected_before_any_read_or_write() {
    let world = E2eWorld::new();
    let device = source_device(&world);
    device.capture();
    // 写进非法配置之后就再也读不回来了，先留一份合法基准。
    let base = device.config();

    // 根外的诱饵文件：任何一次逃逸成功都会改到它。
    let bait_path = world.path().join("escape-bait.txt");
    let bait = "根目录之外的内容，绝不允许被 EnvSync 触碰\n";
    std::fs::write(&bait_path, bait).expect("应当能写诱饵文件");
    let absolute_target = bait_path.to_str().expect("测试路径应当是 UTF-8").to_owned();

    for escaping_target in [
        "../escape-bait.txt",
        "../../escape-bait.txt",
        "sub/../../escape-bait.txt",
        // 绝对路径同样在解析期就被挡住。
        absolute_target.as_str(),
    ] {
        device.set_resources_from(
            &base,
            vec![resource(
                GITCONFIG,
                escaping_target,
                FileMode::FullFile,
                DesiredDisposition::Managed,
            )],
        );
        // 三条命令覆盖「只读」「读取」「计划写入」三条路径，都必须在解析期就失败。
        for command in ["status", "capture", "plan"] {
            let run = device.run_json(&[command]);
            run.expect_code(1);
            run.expect_diagnostic("config.invalid_target");
        }
    }

    assert_bytes_eq(
        &std::fs::read(&bait_path).expect("诱饵文件应当还在"),
        bait.as_bytes(),
        "授权根之外的文件",
    );
}

/// 设计文档 §12 第 2 条（符号链接部分）：目标是指向授权根之外的符号链接时，在读取
/// 或写入之前就被拒绝。
///
/// 只在 Unix 上运行：Windows 创建符号链接需要额外权限，把它当作硬性前提会让 CI 在
/// 某些机器上直接失败，而不是发现真实缺陷。Windows 的路径约束由 `envsync-platform`
/// 自己的测试覆盖。
#[cfg(unix)]
#[test]
fn symlink_escape_is_rejected_before_any_read_or_write() {
    let world = E2eWorld::new();
    let device = world.primary("laptop");
    device.set_resources(vec![resource(
        GITCONFIG,
        ".gitconfig",
        FileMode::FullFile,
        DesiredDisposition::Managed,
    )]);
    device.write_home(".gitconfig", GIT_V1);
    device.capture();
    device.converge();

    // 把目标替换成一个指向授权根之外的符号链接。
    let outside = world.path().join("outside-secret.txt");
    let secret = "根外的机密内容，既不能被读进快照，也不能被写坏\n";
    std::fs::write(&outside, secret).expect("应当能写根外文件");
    let target = device.home_path(".gitconfig");
    std::fs::remove_file(&target).expect("应当能删除原文件");
    std::os::unix::fs::symlink(&outside, &target).expect("应当能创建符号链接");

    // 读取路径：capture 拒绝跟随，并留下诊断。
    let capture = device.run_json(&["capture"]);
    capture.expect_ok();
    capture.expect_diagnostic("capture.excluded");

    // 写入路径：计划被阻塞诊断拦下，`sync` 以策略阻塞退出码 12 结束。
    let plan = device.run_json(&["plan"]);
    plan.expect_ok();
    assert_eq!(plan.data()["blocked"], true);
    assert_eq!(plan.data()["action_count"], 0, "被拒绝的目标不得产生动作");
    plan.expect_diagnostic("resource.excluded");
    let plan_id = plan.data()["plan"]
        .as_str()
        .expect("plan 是字符串")
        .to_owned();

    let sync = device.sync(&plan_id);
    sync.expect_code(12);
    sync.expect_diagnostic("plan.blocked");

    // 结论：根外文件逐字节没变，符号链接本身也没被替换成普通文件。
    assert_bytes_eq(
        &std::fs::read(&outside).expect("根外文件应当还在"),
        secret.as_bytes(),
        "符号链接指向的根外文件",
    );
    assert!(
        std::fs::symlink_metadata(&target)
            .expect("目标应当还在")
            .is_symlink(),
        "目标应当仍是符号链接，说明没有发生任何写入"
    );
}

// ---------------------------------------------------------------------------
// 设计文档 §12：应用前文件被外部修改时 Plan 失效
// ---------------------------------------------------------------------------

/// 设计文档 §12 第 4 条：生成计划之后、应用之前目标被外部改动，`sync` 必须以退出码
/// 11 拒绝，并且**一个字节都不写**。
#[test]
fn externally_modified_target_invalidates_the_plan() {
    let world = E2eWorld::new();
    let device = source_device(&world);
    device.capture();

    device.write_home(".gitconfig", "[user]\n\tname = 本地漂移\n");
    let plan = device.plan();
    assert_eq!(plan.action_count, 1);

    // 计划已经生成，但目标又被别人动了一次。
    let meddled = "[user]\n\tname = 应用前被外部再次修改\n";
    device.write_home(".gitconfig", meddled);
    let zshrc_before = device.read_home(".zshrc");

    let sync = device.sync(&plan.id);
    sync.expect_code(11);
    sync.expect_diagnostic("plan.stale");

    device.assert_home_bytes(".gitconfig", meddled);
    assert_bytes_eq(
        &device.read_home(".zshrc"),
        &zshrc_before,
        "计划失效时其他资源同样不得被写入",
    );
    assert_eq!(device.status()["revision"], 0, "计划失效时不得发布");
}

// ---------------------------------------------------------------------------
// 设计文档 §12：Managed Block 拒绝重复或畸形 marker
// ---------------------------------------------------------------------------

/// 设计文档 §12 第 8 条：Managed Block 遇到重复、畸形、缺一端或顺序颠倒的 marker
/// 时一律报错，**绝不猜测修复**——静默「修好」等于不可见的数据丢失。
///
/// 每一种坏 marker 都断言两件事：稳定错误码正确，且文件逐字节没被动过。
#[test]
fn managed_block_rejects_duplicate_and_malformed_markers() {
    let world = E2eWorld::new();
    let device = world.primary("laptop");
    device.set_resources(vec![resource(
        ZSHRC,
        ".zshrc",
        FileMode::ManagedBlock,
        DesiredDisposition::Managed,
    )]);

    let begin = format!("# >>> envsync:{ZSHRC}\n");
    let end = format!("# <<< envsync:{ZSHRC}\n");

    let cases: [(&str, String); 4] = [
        // 同一个资源出现两个受管区块。
        (
            "render.duplicate_block",
            format!(
                "{A_PROLOGUE}{}{}{A_EPILOGUE}",
                block(BLOCK_V1),
                block(BLOCK_V2)
            ),
        ),
        // marker 行在资源标识之后还有多余内容。
        (
            "render.malformed_marker",
            format!("{A_PROLOGUE}# >>> envsync:{ZSHRC} 多余内容\n{BLOCK_V1}{end}"),
        ),
        // 只有开始 marker，没有结束 marker。
        (
            "render.unterminated_block",
            format!("{A_PROLOGUE}{begin}{BLOCK_V1}"),
        ),
        // 结束 marker 出现在开始 marker 之前。
        (
            "render.misordered_block",
            format!("{A_PROLOGUE}{end}{BLOCK_V1}{begin}{end}"),
        ),
    ];

    for (expected_code, contents) in cases {
        device.write_home(".zshrc", &contents);
        let run = device.run_json(&["capture"]);
        run.expect_code(1);
        run.expect_diagnostic(expected_code);
        assert_bytes_eq(
            &device.read_home(".zshrc"),
            contents.as_bytes(),
            &format!("被拒绝的 marker 场景 `{expected_code}` 下的目标文件"),
        );
    }

    // 对照组：marker 正常时同一条命令成功。
    let healthy = source_device_zshrc(BLOCK_V1);
    device.write_home(".zshrc", &healthy);
    let capture = device.capture();
    assert!(capture.changed);
    assert_bytes_eq(
        &device
            .draft_blob_of(&capture.snapshot, ZSHRC)
            .expect("应当捕获到块内内容"),
        BLOCK_V1.as_bytes(),
        "对照组捕获到的块内内容",
    );
}
