//! M1 多设备端到端验收套件（计划文档「任务 9 · 步骤 1」的
//! `tests/e2e/git_multi_device.rs`）。
//!
//! 与 M0 的 `local_file_loop.rs` 一样，这里的每一步都通过 [`std::process::Command`]
//! 启动**真正的** `envsync` 二进制，只用 `--json` 的对外契约、文件系统本身和一个
//! **真实的裸 Git 仓库**做断言；不调用任何库 API 去驱动流程。库级流程已经由
//! `crates/envsync-core/tests/` 与 `crates/envsync-backend/tests/` 覆盖，这里要验的是
//! 「真实进程 + 真实远端 + 真实并发 + 真实退出码」这一层。
//!
//! 每个测试各持一个 `E2eWorld`（独立临时目录、独立裸远端、独立 cache clone、独立
//! journal 与草稿库），彼此没有任何共享状态，因此可以并行执行。
//!
//! # 与 Task 9 的条目对照
//!
//! | Task 9 步骤 1 的条目 | 测试函数 |
//! |---|---|
//! | 1 两设备 clean merge | `two_devices_merge_disjoint_edits_over_a_real_git_remote` |
//! | 2 Profile 差异 | `different_profiles_project_the_same_snapshot_differently` |
//! | 3 CAS race | `cas_race_loser_exits_10_and_the_remote_keeps_the_winners_ref` |
//! | 4 冲突解决 | `conflicted_sync_exits_13_and_touches_neither_local_nor_remote`、`each_resolution_choice_finishes_the_sync_with_the_chosen_bytes` |
//! | 5 离线 cache | `unreachable_remote_is_reported_loudly_instead_of_clean` |
//! | 6 认证 redaction | `credentials_never_appear_in_any_output` |
//!
//! # 为什么断言的是完整字节 / 退出码 / OID
//!
//! 「输出里包含某个子串」在这套流程里几乎总是能被蒙对：块外内容被吞掉一半、失败方
//! 少写了一个字节、远端分支被 force 覆盖成别人的历史——这些都不会让子串消失。所以
//! 全文件用 [`assert_bytes_eq`] 逐字节比较，进程用退出码比较，远端用提交 OID 与
//! canonical CBOR 解出来的 Ref 比较。

use std::collections::BTreeMap;

use envsync_backend::GitAuth;
use envsync_core::{BackendConfig, ResourceConfig};
use envsync_domain::{DesiredDisposition, FileMode, Predicate, Selector, StructuredFormat};
use envsync_e2e::{
    assert_bytes_eq, resource, wait_for_path, CliRun, Device, E2eWorld, GitRemote, PlanInfo,
    RemoteRef,
};
use serde_json::Value;

// ---------------------------------------------------------------------------
// 固定数据
// ---------------------------------------------------------------------------

/// Managed Block 资源：只管理 `.zshrc` 里带 marker 的那一段。
const ZSHRC: &str = "shell/zsh/main";
/// Full File 资源：整个 `.gitconfig` 都归 EnvSync 管。
const GITCONFIG: &str = "git/config";
/// 只对带 `work` 标签的设备下发。
const WORK_VPN: &str = "work/vpn";
/// 只对具备 `pwsh` 能力的设备下发。
const PWSH: &str = "shell/pwsh/profile";

/// 设备 A 的块外内容：整个流程中必须逐字节不变。
const A_PROLOGUE: &str = "# A 自己的设置\nalias ll='ls -l'\n";
const A_EPILOGUE: &str = "export PATH=\"$HOME/bin:$PATH\"\n";
/// 设备 B 的块外内容，刻意与 A 不同。
const B_PROLOGUE: &str = "# B 自己的设置\nexport LANG=C.UTF-8\n";
const B_EPILOGUE: &str = "# B 的收尾\nsource ~/.local.zsh\n";

/// 受管区块的**块内**内容，也就是 Blob 的字节。
const BLOCK_V1: &str = "export EDITOR=nvim\n";
const BLOCK_V2: &str = "export EDITOR=helix\nexport VISUAL=helix\n";

/// `.gitconfig` 的三个版本：共同 base、A 的改动、B 的改动。
const GIT_BASE: &str = "[user]\n\temail = base@example.com\n";
const GIT_ALICE: &str = "[user]\n\temail = alice@example.com\n";
const GIT_BOB: &str = "[user]\n\temail = bob@example.com\n";
/// 人工裁决时写进 `--file` 的内容。
const GIT_MANUAL: &str = "[user]\n\temail = merged-by-hand@example.com\n";

/// 认证测试用的诱饵 token。
///
/// 字符集刻意落在 `secret_id` 允许的范围内（字母、数字、`-`），这样它既能被塞进
/// 合法配置，又能在越权 URL 里出现——两条路径都必须一个字节都不回显。
const CANARY: &str = "envsync-e2e-canary-9c1f2b7d";

/// 拼一个完整的受管区块（LF 换行、默认 `# ` 注释前缀）。
fn block(inner: &str) -> String {
    format!("# >>> envsync:{ZSHRC}\n{inner}# <<< envsync:{ZSHRC}\n")
}

/// 设备 A 的 `.zshrc` 完整内容。
fn a_zshrc(inner: &str) -> String {
    format!("{A_PROLOGUE}{}{A_EPILOGUE}", block(inner))
}

/// 设备 B 的 `.zshrc` 完整内容。
fn b_zshrc(inner: &str) -> String {
    format!("{B_PROLOGUE}{}{B_EPILOGUE}", block(inner))
}

// ---------------------------------------------------------------------------
// 脚手架
// ---------------------------------------------------------------------------

/// 建一台**以 Git 为后端**的设备。
///
/// `previous` 为 `None` 时是工作区的第一台设备（跑一次真正的 `envsync init`），
/// 否则复用同一个 `workspace_id`，但授权根、状态目录、cache clone 与设备身份都独立。
fn git_device(
    world: &E2eWorld,
    remote: &GitRemote,
    previous: Option<&Device>,
    name: &str,
    resources: Vec<ResourceConfig>,
) -> Device {
    let device = match previous {
        None => world.primary(name),
        Some(first) => world.secondary(first, name),
    };
    device.use_git_backend(remote, GitAuth::SshAgent);
    device.set_resources(resources);
    let config = device.config();
    assert_eq!(config.backend.kind(), "git", "{name} 的后端应当是 git");
    device
}

/// M1 clean merge 场景用的两个资源：一个 Managed Block、一个 Full File。
fn two_modes() -> Vec<ResourceConfig> {
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

/// 声明了结构化格式的 `.gitconfig` 资源。
///
/// 模式仍是 `full_file`（`structured_merge` 在当前里程碑还没放开），但
/// `policy.structured_format` 会让三方合并按 git config 的**键**去比较，于是
/// 「双方改了同一个 key」才是真正的键级冲突，而不是碰巧撞在同一行上。
fn structured_gitconfig() -> ResourceConfig {
    let mut config = resource(
        GITCONFIG,
        ".gitconfig",
        FileMode::FullFile,
        DesiredDisposition::Managed,
    );
    config.policy.structured_format = Some(StructuredFormat::GitConfig);
    config
}

/// 带选择器的资源。
fn with_selector(mut config: ResourceConfig, selector: Selector) -> ResourceConfig {
    config.selector = Some(selector);
    config
}

/// Profile 场景用的三个资源：全局、按标签、按能力。
fn profile_resources() -> Vec<ResourceConfig> {
    vec![
        resource(
            ZSHRC,
            ".zshrc",
            FileMode::FullFile,
            DesiredDisposition::Managed,
        ),
        with_selector(
            resource(
                WORK_VPN,
                ".work-vpn.conf",
                FileMode::FullFile,
                DesiredDisposition::Managed,
            ),
            Selector::is(Predicate::tag("work").expect("标签合法")),
        ),
        with_selector(
            resource(
                PWSH,
                ".pwshrc",
                FileMode::FullFile,
                DesiredDisposition::Managed,
            ),
            Selector::is(Predicate::capability("pwsh").expect("能力合法")),
        ),
    ]
}

/// 取 `profile explain` 里某个资源的投影结论。
fn note<'a>(explain: &'a Value, resource: &str) -> &'a Value {
    explain["resources"]
        .as_array()
        .expect("resources 是数组")
        .iter()
        .find(|note| note["resource"] == resource)
        .unwrap_or_else(|| panic!("`profile explain` 里应当有资源 {resource}：{explain}"))
}

/// 计划里全部动作的「资源 → 动作种类」，按资源标识升序。
fn action_kinds(plan: &PlanInfo) -> BTreeMap<String, String> {
    plan.actions
        .iter()
        .map(|action| {
            (
                action["resource"]
                    .as_str()
                    .expect("resource 是字符串")
                    .to_owned(),
                action["kind"].as_str().expect("kind 是字符串").to_owned(),
            )
        })
        .collect()
}

/// 远端当前记录的工作区 Ref。
fn remote_ref(remote: &GitRemote, device: &Device) -> RemoteRef {
    remote
        .workspace_ref(&device.config().workspace_id.to_string())
        .expect("远端应当已经有这个工作区的 Ref")
}

// ---------------------------------------------------------------------------
// Task 9 · 条目 1：两设备 clean merge
// ---------------------------------------------------------------------------

/// **对应 Task 9 步骤 1 的第 1 条：两设备 clean merge。**
///
/// 临时裸 Git 远端作后端；A 与 B 从共同 base 分叉，各改**互不重叠**的资源
/// （A 改 Managed Block 的块内内容，B 改 Full File）；A 发布 → B fetch → merge →
/// plan → sync，再让 A 收敛回同一状态。
///
/// 断言：最终两端的 State Root（与设备视图）完全相同；两端文件都同时包含双方的改
/// 动；两台设备各自的 Managed Block **块外**内容逐字节不变。
#[test]
fn two_devices_merge_disjoint_edits_over_a_real_git_remote() {
    let world = E2eWorld::new();
    let remote = world.git_remote("origin");

    let alice = git_device(&world, &remote, None, "alice", two_modes());
    alice.write_home(".zshrc", a_zshrc(BLOCK_V1));
    alice.write_home(".gitconfig", GIT_BASE);

    let bob = git_device(&world, &remote, Some(&alice), "bob", two_modes());
    // B 的 `.zshrc` 里已经有一对**空的** marker，前后各有一段自有内容——这样才验得到
    // 「块内被替换、块外一个字节都没动」。
    bob.write_home(".zshrc", b_zshrc(""));

    // ---- 共同 base ---------------------------------------------------------
    let base_capture = alice.capture();
    assert!(base_capture.changed);
    let published = alice.converge();
    assert_eq!(published.outcome, "completed");
    assert!(published.published, "首次同步必须向 Git 远端发布新引用");
    let base_snapshot = base_capture.snapshot.clone();
    assert_eq!(
        remote_ref(&remote, &alice),
        RemoteRef {
            revision: 1,
            head: Some(base_snapshot.clone()),
        }
    );

    let fetched = bob.fetch();
    assert_eq!(fetched["revision"], 1);
    assert_eq!(fetched["head"], base_snapshot.as_str());
    assert!(
        fetched["objects"].as_u64().expect("objects 是整数") > 0,
        "第一次 fetch 必须真的把对象拉下来：{fetched}"
    );
    let converged = bob.converge();
    assert_eq!(converged.applied, 2);
    assert!(!converged.published, "拉取别人的快照不该推进远端 Ref");
    bob.assert_home_bytes(".zshrc", &b_zshrc(BLOCK_V1));
    bob.assert_home_bytes(".gitconfig", GIT_BASE);

    // ---- 分叉 --------------------------------------------------------------
    // B 先捕获（父快照仍是共同 base），A 随后发布，于是两条历史真正分叉。
    bob.write_home(".gitconfig", GIT_BOB);
    let bob_capture = bob.capture();
    assert!(bob_capture.changed);

    alice.write_home(".zshrc", a_zshrc(BLOCK_V2));
    let alice_capture = alice.capture();
    assert!(alice_capture.changed);
    let alice_publish = alice.converge();
    assert!(alice_publish.published);
    assert_eq!(
        remote_ref(&remote, &alice),
        RemoteRef {
            revision: 2,
            head: Some(alice_capture.snapshot.clone()),
        }
    );

    // ---- B：fetch → merge → plan → sync ------------------------------------
    let before_merge = bob.read_home(".zshrc");
    bob.fetch();
    let merged = bob.merge();
    assert_eq!(merged["outcome"], "merged", "互不重叠的改动必须干净合并");
    assert_eq!(merged["base"], base_snapshot.as_str());
    assert_eq!(merged["local"], bob_capture.snapshot.as_str());
    assert_eq!(merged["remote"], alice_capture.snapshot.as_str());
    assert!(
        merged["conflicts"]
            .as_array()
            .expect("conflicts 是数组")
            .is_empty(),
        "clean merge 不应登记任何冲突：{merged}"
    );
    let merged_snapshot = merged["merged"]
        .as_str()
        .expect("干净合并必须产出合并快照")
        .to_owned();

    let bob_plan = bob.plan();
    assert_eq!(bob_plan.target_snapshot, merged_snapshot);
    assert_eq!(bob_plan.base_revision, 2);
    assert_eq!(bob_plan.next_revision, 3);
    assert_eq!(
        action_kinds(&bob_plan),
        BTreeMap::from([(ZSHRC.to_owned(), "update_managed_block".to_owned())]),
        "B 只需要把 A 改过的块内内容写下来"
    );
    let bob_sync = bob.sync(&bob_plan.id);
    bob_sync.expect_ok();
    assert_eq!(bob_sync.data()["published"], true);

    // ---- A 收敛回同一状态 ---------------------------------------------------
    alice.fetch();
    let alice_merge = alice.merge();
    assert_eq!(
        alice_merge["outcome"], "fast_forward",
        "A 没有本地草稿，只能快进到 B 发布的合并快照"
    );
    let alice_plan = alice.plan();
    assert_eq!(alice_plan.target_snapshot, merged_snapshot);
    assert_eq!(
        action_kinds(&alice_plan),
        BTreeMap::from([(GITCONFIG.to_owned(), "replace_file".to_owned())]),
        "A 只需要接收 B 改过的 Full File"
    );
    alice.converge();

    // ---- 断言：两端状态完全一致 ---------------------------------------------
    let alice_view = alice.profile_explain();
    let bob_view = bob.profile_explain();
    assert_eq!(
        alice_view["state_root"], bob_view["state_root"],
        "收敛之后两端的 State Root 必须相同"
    );
    assert_eq!(
        alice_view["device_view"], bob_view["device_view"],
        "两台设备的 Profile 相同，投影结果也必须相同"
    );
    assert_eq!(alice_view["state_root"].as_str().map(str::len), Some(64));

    let alice_status = alice.status();
    let bob_status = bob.status();
    assert_eq!(alice_status["head"], merged_snapshot.as_str());
    assert_eq!(bob_status["head"], merged_snapshot.as_str());
    assert_eq!(alice_status["state"], "clean");
    assert_eq!(bob_status["state"], "clean");
    assert_eq!(alice_status["revision"], 3);
    assert_eq!(bob_status["revision"], 3);
    assert_eq!(
        remote_ref(&remote, &alice),
        RemoteRef {
            revision: 3,
            head: Some(merged_snapshot.clone()),
        }
    );

    // ---- 断言：双方的改动都到齐，且块外一个字节没动 --------------------------
    alice.assert_home_bytes(".zshrc", &a_zshrc(BLOCK_V2));
    alice.assert_home_bytes(".gitconfig", GIT_BOB);
    bob.assert_home_bytes(".zshrc", &b_zshrc(BLOCK_V2));
    bob.assert_home_bytes(".gitconfig", GIT_BOB);

    let after_merge = bob.read_home(".zshrc");
    assert_bytes_eq(
        &after_merge[..B_PROLOGUE.len()],
        &before_merge[..B_PROLOGUE.len()],
        "B 的块前内容",
    );
    assert_bytes_eq(
        &after_merge[after_merge.len() - B_EPILOGUE.len()..],
        &before_merge[before_merge.len() - B_EPILOGUE.len()..],
        "B 的块后内容",
    );
}

// ---------------------------------------------------------------------------
// Task 9 · 条目 2：Profile 差异
// ---------------------------------------------------------------------------

/// **对应 Task 9 步骤 1 的第 2 条：Profile 差异。**
///
/// 同一个快照，两台设备的标签与能力不同：`worker` 有 `work` 标签但没有 `pwsh`
/// 能力，`shellbox` 反过来。断言两者的 `profile explain` 结论不同、`device_view`
/// 不同、plan 的动作集合不同。
///
/// 更重要的是最后一条：**投影绝不产生删除动作**。设备上那份「本次不下发」的资源
/// 文件必须逐字节保留——「今天这台机器没装 pwsh」不能变成「把别人的 PowerShell 配置
/// 删掉」。
#[test]
fn different_profiles_project_the_same_snapshot_differently() {
    const HUB_ZSHRC: &str = "export EDITOR=nvim\n";
    const HUB_VPN: &str = "endpoint = vpn.corp.example\n";
    const HUB_PWSH: &str = "Set-Alias ll Get-ChildItem\n";
    /// 两台设备各自**已有的**、不属于本机投影范围的文件；必须原封不动。
    const WORKER_OWN_PWSH: &str = "# worker 自己装的 pwsh 配置\nSet-Alias g git\n";
    const SHELLBOX_OWN_VPN: &str = "# shellbox 自己的 vpn 配置\nendpoint = home.example\n";

    let world = E2eWorld::new();
    let remote = world.git_remote("origin");

    // 发布者：标签与能力都齐全，因此它自己的视图包含全部三个资源。
    let hub = git_device(&world, &remote, None, "hub", profile_resources());
    hub.set_profile(&["work"], &["pwsh"]);
    hub.write_home(".zshrc", HUB_ZSHRC);
    hub.write_home(".work-vpn.conf", HUB_VPN);
    hub.write_home(".pwshrc", HUB_PWSH);
    hub.capture();
    let published = hub.converge();
    assert!(published.published);
    let snapshot = hub.status()["head"]
        .as_str()
        .expect("发布之后一定有头")
        .to_owned();

    let worker = git_device(&world, &remote, Some(&hub), "worker", profile_resources());
    worker.set_profile(&["work"], &[]);
    worker.write_home(".pwshrc", WORKER_OWN_PWSH);

    let shellbox = git_device(&world, &remote, Some(&hub), "shellbox", profile_resources());
    shellbox.set_profile(&["home"], &["pwsh"]);
    shellbox.write_home(".work-vpn.conf", SHELLBOX_OWN_VPN);

    worker.fetch();
    shellbox.fetch();

    // ---- 投影结论不同 -------------------------------------------------------
    let worker_view = worker.profile_explain();
    let shellbox_view = shellbox.profile_explain();
    assert_eq!(worker_view["state_root"], snapshot_state_root(&hub));
    assert_eq!(
        worker_view["state_root"], shellbox_view["state_root"],
        "两台设备被投影的是同一个完整状态"
    );
    assert_ne!(
        worker_view["device_view"], shellbox_view["device_view"],
        "Profile 不同，设备视图必须不同"
    );

    for (view, label) in [(&worker_view, "worker"), (&shellbox_view, "shellbox")] {
        assert_eq!(note(view, ZSHRC)["kind"], "selected_by_global", "{label}");
        assert_eq!(note(view, ZSHRC)["included"], true, "{label}");
    }
    assert_eq!(note(&worker_view, WORK_VPN)["kind"], "selected_by_selector");
    assert_eq!(note(&worker_view, WORK_VPN)["included"], true);
    assert_eq!(
        note(&worker_view, PWSH)["kind"],
        "unsupported_capability",
        "缺能力必须是「不下发」而不是「未命中」，两者的补救动作完全不同"
    );
    assert_eq!(note(&worker_view, PWSH)["included"], false);

    assert_eq!(
        note(&shellbox_view, WORK_VPN)["kind"],
        "excluded_by_selector"
    );
    assert_eq!(note(&shellbox_view, WORK_VPN)["included"], false);
    assert_eq!(note(&shellbox_view, PWSH)["kind"], "selected_by_selector");
    assert_eq!(note(&shellbox_view, PWSH)["included"], true);

    // ---- 动作集合不同，且都没有删除动作 --------------------------------------
    let worker_plan = worker.plan();
    let shellbox_plan = shellbox.plan();
    assert_eq!(
        action_kinds(&worker_plan),
        BTreeMap::from([
            (ZSHRC.to_owned(), "create_file".to_owned()),
            (WORK_VPN.to_owned(), "create_file".to_owned()),
        ])
    );
    assert_eq!(
        action_kinds(&shellbox_plan),
        BTreeMap::from([
            (ZSHRC.to_owned(), "create_file".to_owned()),
            (PWSH.to_owned(), "create_file".to_owned()),
        ])
    );
    for (plan, label) in [(&worker_plan, "worker"), (&shellbox_plan, "shellbox")] {
        assert!(!plan.blocked, "{label} 的计划不应被阻塞");
        for action in &plan.actions {
            assert_ne!(
                action["kind"], "delete_file",
                "{label}：投影绝不能产生删除动作，实际是 {action}"
            );
        }
    }

    // ---- 收敛之后：该下发的到了，不该下发的一个字节没动 -----------------------
    worker.converge();
    shellbox.converge();

    worker.assert_home_bytes(".zshrc", HUB_ZSHRC);
    worker.assert_home_bytes(".work-vpn.conf", HUB_VPN);
    worker.assert_home_bytes(".pwshrc", WORKER_OWN_PWSH);

    shellbox.assert_home_bytes(".zshrc", HUB_ZSHRC);
    shellbox.assert_home_bytes(".pwshrc", HUB_PWSH);
    shellbox.assert_home_bytes(".work-vpn.conf", SHELLBOX_OWN_VPN);

    for (device, label) in [(&worker, "worker"), (&shellbox, "shellbox")] {
        let status = device.status();
        assert_eq!(status["state"], "clean", "{label}");
        assert_eq!(status["pending_actions"], 0, "{label}");
        assert_eq!(status["open_conflicts"], 0, "{label}");
        assert_eq!(status["head"], snapshot.as_str(), "{label}");
    }

    // 投影只发生在计划阶段：远端 Ref 仍然是发布者写下的那一个完整快照。
    assert_eq!(
        remote_ref(&remote, &hub),
        RemoteRef {
            revision: 1,
            head: Some(snapshot),
        }
    );
}

/// 发布者自己看到的完整 State Root。
fn snapshot_state_root(device: &Device) -> Value {
    device.profile_explain()["state_root"].clone()
}

// ---------------------------------------------------------------------------
// Task 9 · 条目 3：CAS race
// ---------------------------------------------------------------------------

/// 制造 CAS 竞争时，「慢的一方」声明的资源数量。
///
/// 见下面测试文档里的时序说明：这个数字只影响**观察阶段**的耗时，不影响要上传的
/// 对象数量（所有文件内容相同，因此只有一个 Blob）。
const BULK_RESOURCES: usize = 4000;

/// 大批量资源的公共内容。
fn bulk_content() -> String {
    "envsync bulk fixture line\n".repeat(4)
}

/// 生成 [`BULK_RESOURCES`] 个内容相同的 Full File 资源。
fn bulk_resources() -> Vec<ResourceConfig> {
    (0..BULK_RESOURCES)
        .map(|index| {
            resource(
                &format!("bulk/r{index}"),
                &format!("bulk/f{index}.conf"),
                FileMode::FullFile,
                DesiredDisposition::Managed,
            )
        })
        .collect()
}

/// **对应 Task 9 步骤 1 的第 3 条：CAS race。**
///
/// 两台设备从**同一个 revision**（这里是 0）各自发布，断言失败方以退出码 10 结束、
/// 本地文件逐字节不变、远端受信分支上最新的一次 Ref 发布是胜者的提交。
///
/// # 时序是怎么被钉死的
///
/// `sync` 的内部顺序是：打开后端（fetch #1）→ 重新计划（fetch #2 读到 revision，
/// 随后**观察本机全部资源**）→ 上传对象 → CAS。要稳定地制造 CAS 冲突，必须让失败方
/// 「读到 revision」早于胜者发布、「CAS」晚于胜者发布，也就是要在这两步之间插进一个
/// 足够长、**又不碰远端**的阶段。
///
/// 于是：
///
/// * 失败方声明 [`BULK_RESOURCES`] 个资源，观察阶段因此要花上百毫秒；但这些文件内容
///   完全相同，所以待上传的对象只有一个 Blob——慢在观察，不慢在推送，两边的推送阶段
///   不会重叠（libgit2 的本地传输对并发推送同一个裸仓库并不友好，重叠只会得到锁竞争
///   错误而不是干净的 CAS 冲突）。
/// * 不用 sleep 猜时序：先删掉失败方 cache clone 里的 `FETCH_HEAD`，再等它重新出现
///   ——libgit2 每次 fetch 都会重写它，所以这是「失败方已经联过远端」的正向信号。
///
/// # 为什么断言的是「最新的 Ref 提交」而不是分支头 OID
///
/// 对象上传也会在同一条分支上留下提交，失败方的对象在它撞上 CAS 之前就已经推上去了，
/// 因此分支头 OID 未必等于胜者那一条。真正的不变量是：**分支上最新的一次 Ref 发布
/// 属于胜者，失败方一条 Ref 提交都没留下**，且胜者的提交仍在分支历史里。
#[test]
fn cas_race_loser_exits_10_and_the_remote_keeps_the_winners_ref() {
    const FAST_CONTENT: &str = "[user]\n\temail = fast@example.com\n";
    const DRIFT_ONE: &str = "本地漂移一\n";
    const DRIFT_TWO: &str = "本地漂移二\n";

    let world = E2eWorld::new();
    let remote = world.git_remote("origin");

    let slow = git_device(&world, &remote, None, "slow", bulk_resources());
    let content = bulk_content();
    for index in 0..BULK_RESOURCES {
        slow.write_home(&format!("bulk/f{index}.conf"), &content);
    }
    let fast = git_device(
        &world,
        &remote,
        Some(&slow),
        "fast",
        vec![resource(
            GITCONFIG,
            ".gitconfig",
            FileMode::FullFile,
            DesiredDisposition::Managed,
        )],
    );
    fast.write_home(".gitconfig", FAST_CONTENT);

    slow.capture();
    fast.capture();

    // 捕获之后再制造两处本地漂移：失败方的计划里因此有真正的写动作，
    // 「失败方一个字节都没落地」才是可验证的断言而不是空话。
    slow.write_home("bulk/f0.conf", DRIFT_ONE);
    slow.write_home("bulk/f1.conf", DRIFT_TWO);

    let slow_plan = slow.plan();
    let fast_plan = fast.plan();
    assert_eq!(slow_plan.base_revision, 0);
    assert_eq!(fast_plan.base_revision, 0);
    assert_eq!(slow_plan.next_revision, 1);
    assert_eq!(fast_plan.next_revision, 1);
    assert_eq!(
        slow_plan.action_count,
        2,
        "只有被改过的两个文件需要写回：{:?}",
        action_kinds(&slow_plan)
    );
    assert!(remote.branch_head().is_none(), "此刻远端还是空的");

    // 失败方先跑；等它真的联过一次远端（读到 revision 0）之后，胜者才开始。
    let marker = slow.git_fetch_marker();
    std::fs::remove_file(&marker).expect("cache clone 里应当已经有 FETCH_HEAD");
    let running = slow.spawn_json(&["sync", "--plan", &slow_plan.id]);
    wait_for_path(&marker, 60);

    let winner = fast.sync(&fast_plan.id);
    winner.expect_ok();
    assert_eq!(winner.data()["published"], true);
    let winner_commit = remote
        .latest_ref_commit()
        .expect("胜者必须在远端留下一条 Ref 提交");

    let loser = running.wait();
    loser.expect_code(10);
    loser.expect_diagnostic("cas_conflict");
    assert!(
        loser.json()["data"].is_null(),
        "失败的 sync 不应带 data：{}",
        loser.stdout
    );

    // 失败方本地**逐字节**不变：CAS 在任何写入之前就失败了。
    slow.assert_home_bytes("bulk/f0.conf", DRIFT_ONE);
    slow.assert_home_bytes("bulk/f1.conf", DRIFT_TWO);
    slow.assert_home_bytes("bulk/f2.conf", &content);

    // 远端只承认胜者：Ref 是胜者写的，最新的 Ref 提交仍是胜者那一条，
    // 而且它没有被从历史里挤掉（没有人 force push）。
    assert_eq!(
        remote_ref(&remote, &fast),
        RemoteRef {
            revision: 1,
            head: Some(fast_plan.target_snapshot.clone()),
        }
    );
    assert_eq!(
        remote.latest_ref_commit().expect("Ref 提交仍在").oid,
        winner_commit.oid,
        "失败方绝不能在远端留下 Ref 提交"
    );
    assert!(
        remote.branch_contains(&winner_commit.oid),
        "胜者的提交必须仍在受信分支的历史里"
    );

    // 失败方的补救动作是重新计划：这一次它会看到 revision 1。
    let retry = slow.plan();
    assert_eq!(retry.base_revision, 1);
}

// ---------------------------------------------------------------------------
// Task 9 · 条目 4：冲突解决
// ---------------------------------------------------------------------------

/// 把两台设备推进到「双方改了同一个 git config key」的状态。
///
/// 返回时：远端在 revision 2（A 的版本），B 手里攥着一份基于共同 base 的本地草稿。
fn conflicted_world() -> (E2eWorld, GitRemote, Device, Device) {
    let world = E2eWorld::new();
    let remote = world.git_remote("origin");

    let alice = git_device(&world, &remote, None, "alice", vec![structured_gitconfig()]);
    let bob = git_device(
        &world,
        &remote,
        Some(&alice),
        "bob",
        vec![structured_gitconfig()],
    );

    alice.write_home(".gitconfig", GIT_BASE);
    alice.capture();
    alice.converge();

    bob.fetch();
    bob.converge();
    bob.assert_home_bytes(".gitconfig", GIT_BASE);

    // B 先捕获（父快照仍是共同 base），A 随后发布，两条历史真正分叉。
    bob.write_home(".gitconfig", GIT_BOB);
    bob.capture();

    alice.write_home(".gitconfig", GIT_ALICE);
    alice.capture();
    alice.converge();

    (world, remote, alice, bob)
}

/// **对应 Task 9 步骤 1 的第 4 条（前半）：冲突让 `sync` 退出 13，本地与远端都不变。**
#[test]
fn conflicted_sync_exits_13_and_touches_neither_local_nor_remote() {
    let (_world, remote, alice, bob) = conflicted_world();

    let local_before = bob.read_home(".gitconfig");
    let alice_before = alice.read_home(".gitconfig");
    let branch_before = remote.branch_head().expect("远端已有分支");
    let ref_before = remote_ref(&remote, &bob);
    assert_eq!(ref_before.revision, 2);

    bob.fetch();
    let merged = bob.merge();
    assert_eq!(merged["outcome"], "conflicted");
    assert!(merged["merged"].is_null(), "冲突时绝不生成快照");
    assert!(merged["state_root"].is_null());
    let conflicts = merged["conflicts"].as_array().expect("conflicts 是数组");
    assert_eq!(conflicts.len(), 1, "只有一个资源冲突：{merged}");
    let conflict = conflicts[0].as_str().expect("冲突标识是字符串").to_owned();
    assert_eq!(conflict.len(), 64);

    // `conflicts list` 能看到它。
    let listed = bob.conflicts();
    assert_eq!(listed["open"], 1);
    assert_eq!(listed["conflicts"][0]["conflict"], conflict.as_str());
    assert_eq!(listed["conflicts"][0]["resource"], GITCONFIG);
    assert_eq!(listed["conflicts"][0]["state"], "open");
    assert_eq!(
        listed["conflicts"][0]["kind"], "structured_key",
        "双方改的是同一个 git config 键，冲突种类必须是键级而不是行级"
    );

    // `conflicts show` 只给三侧摘要与结构性诊断，绝不回显文件正文。
    let shown = bob.run_json(&["conflicts", "show", "--conflict", &conflict]);
    shown.expect_ok();
    let detail = shown.data();
    assert_eq!(detail["resource"], GITCONFIG);
    assert_eq!(detail["state"], "open");
    assert_eq!(detail["kind"], "structured_key");
    for side in ["base", "ours", "theirs"] {
        assert_eq!(
            detail[side].as_str().map(str::len),
            Some(64),
            "{side} 应当是内容标识：{detail}"
        );
    }
    let rendered = serde_json::to_string(&detail).expect("详情可序列化");
    for secret in ["alice@example.com", "bob@example.com", "base@example.com"] {
        assert!(
            !rendered.contains(secret),
            "冲突详情里不应出现文件正文：{rendered}"
        );
    }

    // 存在未解决冲突时，`sync` 一票否决。
    let plan = bob.plan();
    let sync = bob.sync(&plan.id);
    sync.expect_code(13);
    sync.expect_diagnostic("sync.conflicted");
    assert!(sync.json()["data"].is_null());

    // 本地与远端都**逐字节**不变。
    assert_bytes_eq(
        &bob.read_home(".gitconfig"),
        &local_before,
        "B 的 .gitconfig",
    );
    assert_bytes_eq(
        &alice.read_home(".gitconfig"),
        &alice_before,
        "A 的 .gitconfig",
    );
    assert_eq!(
        remote.branch_head().expect("远端分支还在"),
        branch_before,
        "冲突路径不得在远端留下任何提交"
    );
    assert_eq!(remote_ref(&remote, &bob), ref_before);

    let status = bob.status();
    assert_eq!(status["state"], "conflicted");
    assert_eq!(status["open_conflicts"], 1);
}

/// **对应 Task 9 步骤 1 的第 4 条（后半）：三种裁决都能把同步跑完。**
///
/// `--ours` / `--theirs` / `--file` 分别裁决之后，同步都必须能走完，而且最终落地的
/// 内容**确实**是所选的那一份——三种裁决各起一个独立的世界，互不干扰。
#[test]
fn each_resolution_choice_finishes_the_sync_with_the_chosen_bytes() {
    for (label, expected) in [
        ("--ours", GIT_BOB),
        ("--theirs", GIT_ALICE),
        ("--file", GIT_MANUAL),
    ] {
        let (world, remote, alice, bob) = conflicted_world();
        bob.fetch();
        let merged = bob.merge();
        assert_eq!(merged["outcome"], "conflicted", "{label}");
        let conflict = merged["conflicts"][0]
            .as_str()
            .expect("应当登记了一个冲突")
            .to_owned();

        let manual = world.path().join("manual-resolution.gitconfig");
        std::fs::write(&manual, GIT_MANUAL).expect("应当能写人工裁决内容");
        let manual_arg = manual.to_str().expect("路径是 UTF-8").to_owned();
        let mut args = vec!["conflicts", "resolve", "--conflict", &conflict, label];
        if label == "--file" {
            args.push(&manual_arg);
        }
        let resolved = bob.run_json(&args);
        resolved.expect_ok();
        let resolution = resolved.data();
        assert_eq!(resolution["conflict"], conflict.as_str(), "{label}");
        assert_eq!(
            resolution["resolved_blob"].as_str().map(str::len),
            Some(64),
            "{label}：裁决结果必须落成一个 Blob"
        );

        // 裁决之后重新合并即可干净收敛。
        let remerged = bob.merge();
        assert_eq!(remerged["outcome"], "merged", "{label}：{remerged}");
        assert!(bob.conflicts()["conflicts"]
            .as_array()
            .expect("conflicts 是数组")
            .is_empty());
        let bob_sync = bob.converge();
        assert!(bob_sync.published, "{label}：裁决后的合并结果要发布出去");

        assert_bytes_eq(
            &bob.read_home(".gitconfig"),
            expected.as_bytes(),
            &format!("{label} 裁决后 B 的 .gitconfig"),
        );
        assert_eq!(
            remote_ref(&remote, &bob).revision,
            3,
            "{label}：远端应当前进到 revision 3"
        );

        // 另一台设备拉下来的也必须是同一份字节。
        alice.fetch();
        assert_eq!(alice.merge()["outcome"], "fast_forward", "{label}");
        alice.converge();
        assert_bytes_eq(
            &alice.read_home(".gitconfig"),
            expected.as_bytes(),
            &format!("{label} 裁决后 A 的 .gitconfig"),
        );
        assert_eq!(bob.status()["state"], "clean", "{label}");
        assert_eq!(alice.status()["state"], "clean", "{label}");
    }
}

// ---------------------------------------------------------------------------
// Task 9 · 条目 5：离线 cache
// ---------------------------------------------------------------------------

/// **对应 Task 9 步骤 1 的第 5 条：远端不可达时的行为。**
///
/// 远端不可达时，`status` 基于本地记录的**上次已知** Ref 继续作答，并把这件事说清楚：
/// 退出码 0、`backend_reachable: false`、`state` 为 `backend_unreachable`、
/// `revision` / `head` 是上次已知的那一份。`doctor` 同理——不可达是一条 `ok: false` 的
/// finding，而不是让整个命令失败的理由。
///
/// 真正要紧的安全性质在降级之后**依然成立**：不可达**绝不能**被报成 `clean`。把「远端
/// 连不上」说成「已收敛」会让用户以为自己的改动已经同步出去，这比直接报错危险得多。
/// 因此降级只发生在只读诊断上；任何会改动远端或依赖真实 revision 的命令
/// （`fetch` / `capture` / `plan` / `sync`）仍然是显式失败。
#[test]
fn unreachable_remote_is_reported_loudly_instead_of_clean() {
    let world = E2eWorld::new();
    let remote = world.git_remote("origin");
    let alice = git_device(&world, &remote, None, "alice", two_modes());
    alice.write_home(".zshrc", a_zshrc(BLOCK_V1));
    alice.write_home(".gitconfig", GIT_BASE);
    alice.capture();
    alice.converge();

    let online = alice.status();
    assert_eq!(online["state"], "clean");
    assert_eq!(online["revision"], 1);
    assert_eq!(
        online["backend_reachable"], true,
        "远端正常时必须报告可达：{online}"
    );
    assert!(
        online["last_known_revision_at_unix_ms"].is_null(),
        "可达时不需要用时间戳限定 revision：{online}"
    );
    let known_head = online["head"].as_str().expect("已发布过").to_owned();

    // ---- 远端不可达 ---------------------------------------------------------
    remote.take_offline();

    let offline = alice.run_json(&["status"]);
    offline.expect_ok();
    let envelope = offline.json();
    assert_eq!(envelope["status"], "ok");
    let data = offline.data();

    // 降级作答：上次已知状态原封不动地报出来。
    assert_eq!(
        data["backend_reachable"], false,
        "必须明确标注不可达：{data}"
    );
    assert_eq!(
        data["state"], "backend_unreachable",
        "状态必须是不可达而不是任何一种「正常」状态：{data}"
    );
    assert_ne!(data["state"], "clean", "不可达绝不能被报成 clean：{data}");
    assert_eq!(data["revision"], 1, "显示上次已知的 revision：{data}");
    assert_eq!(
        data["head"],
        known_head.as_str(),
        "显示上次已知的头快照：{data}"
    );
    assert_eq!(data["backend_kind"], "git", "后端种类不该因为断网而改变");
    assert!(
        data["last_known_revision_at_unix_ms"]
            .as_u64()
            .is_some_and(|at| at > 0),
        "必须给出「这份状态有多旧」：{data}"
    );
    offline.expect_diagnostic("backend.unreachable");
    assert!(
        !offline.stdout.contains("\"clean\""),
        "远端不可达绝不能被报成 clean：{}",
        offline.stdout
    );

    // 人类可读模式同样要把「这是旧数据」说出来，而不是给一份看起来很正常的报告。
    let human = alice.run(&["status"]);
    human.expect_ok();
    assert!(
        human.stdout.contains("不可达"),
        "人类可读输出必须显式说明后端不可达：{}",
        human.stdout
    );
    assert!(
        human.stdout.contains("上次已知"),
        "人类可读输出必须说明这是上次已知状态：{}",
        human.stdout
    );
    assert!(
        !human.stdout.contains("已收敛"),
        "人类可读输出也不能声称已收敛：{}",
        human.stdout
    );

    // `doctor` 只报告不修复：不可达是一条 ok:false 的 finding，命令本身仍然退出 0。
    let doctor = alice.run_json(&["doctor"]);
    doctor.expect_ok();
    let report = doctor.data();
    assert_eq!(
        report["healthy"], false,
        "后端不可达时体检结论必须是「存在问题」：{report}"
    );
    let backend_finding = report["findings"]
        .as_array()
        .expect("findings 是数组")
        .iter()
        .find(|finding| finding["check"] == "后端可达性")
        .unwrap_or_else(|| panic!("体检里应当有后端可达性一项：{report}"))
        .clone();
    assert_eq!(backend_finding["ok"], false, "{backend_finding}");
    assert!(
        backend_finding["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("上次已知")),
        "finding 应当带上上次已知状态：{backend_finding}"
    );

    // 会改动远端、或依赖真实 revision 的命令仍然是显式失败——降级只给只读诊断。
    for command in [["fetch"], ["capture"], ["plan"]] {
        let run = alice.run_json(&command);
        run.expect_code(1);
        run.expect_diagnostic("io");
        assert!(
            run.json()["data"].is_null(),
            "失败的 `{command:?}` 不应带 data：{}",
            run.stdout
        );
    }

    // 本地 cache clone 还在原地。
    assert!(
        alice.git_cache_dir().join("FETCH_HEAD").is_file(),
        "cache clone 应当保留上一次 fetch 的结果"
    );

    // ---- 远端恢复 -----------------------------------------------------------
    remote.bring_online();

    let restored = alice.status();
    assert_eq!(restored["state"], "clean");
    assert_eq!(restored["revision"], 1);
    assert_eq!(restored["head"], known_head.as_str());

    // 恢复之后还能继续同步。
    alice.write_home(".gitconfig", GIT_ALICE);
    let capture = alice.capture();
    assert!(capture.changed);
    let synced = alice.converge();
    assert!(synced.published);
    assert_eq!(
        remote_ref(&remote, &alice),
        RemoteRef {
            revision: 2,
            head: Some(capture.snapshot),
        }
    );
    alice.assert_home_bytes(".gitconfig", GIT_ALICE);
}

// ---------------------------------------------------------------------------
// Task 9 · 条目 6：认证 redaction
// ---------------------------------------------------------------------------

/// **对应 Task 9 步骤 1 的第 6 条：认证信息永不出现在输出里。**
///
/// 两条路径都要验：
///
/// 1. 把 canary 藏在远端 URL 的 userinfo 里——配置校验必须**拒绝**它，而且拒绝理由里
///    一个字节的 canary 都不能有（这就是错误载荷用 `&'static str` 的意义）；
/// 2. 换成合法的远端 URL，但把 canary 填进 `auth.token-secret-ref` 的 `secret_id`
///    ——完整跑一遍 capture / plan / sync / status / fetch / merge / profile /
///    conflicts / doctor（而且开到 `-vvv` 让 tracing 全开），stdout 与 stderr 全程
///    不得出现 canary。
#[test]
fn credentials_never_appear_in_any_output() {
    let world = E2eWorld::new();
    let remote = world.git_remote("origin");
    let alice = git_device(&world, &remote, None, "alice", two_modes());
    alice.write_home(".zshrc", a_zshrc(BLOCK_V1));
    alice.write_home(".gitconfig", GIT_BASE);
    let good = alice.config();

    // ---- 1. URL 里带凭据：必须被配置校验挡下 ---------------------------------
    let mut bad = good.clone();
    bad.backend = BackendConfig::Git {
        remote_url: format!("https://x-access-token:{CANARY}@example.invalid/dotfiles.git"),
        branch: "envsync".to_owned(),
        cache_dir: alice.git_cache_dir(),
        auth: GitAuth::SshAgent,
    };
    alice.write_config(&bad);
    assert!(
        config_text(&alice).contains(CANARY),
        "测试前提：配置文件里确实写着 canary"
    );

    let mut transcript: Vec<CliRun> = Vec::new();
    for command in [["status"], ["doctor"], ["fetch"], ["plan"], ["capture"]] {
        let json = alice.run_json(&command);
        json.expect_code(1);
        json.expect_diagnostic("config.invalid_backend");
        let human = alice.run(&command);
        human.expect_code(1);
        transcript.push(json);
        transcript.push(human);
    }

    // ---- 2. 合法 URL + secret 引用：跑完整流程 -------------------------------
    alice.write_config(&good);
    alice.use_git_backend(
        &remote,
        GitAuth::TokenSecretRef {
            secret_id: CANARY.to_owned(),
        },
    );
    assert!(
        config_text(&alice).contains(CANARY),
        "测试前提：secret 引用里确实写着 canary"
    );

    let capture = traced(&alice, &["capture"], &mut transcript);
    capture.expect_ok();
    let plan = traced(&alice, &["plan"], &mut transcript);
    plan.expect_ok();
    let plan_id = plan.data()["plan"]
        .as_str()
        .expect("plan 输出里有计划标识")
        .to_owned();
    let sync = traced(&alice, &["sync", "--plan", &plan_id], &mut transcript);
    sync.expect_ok();
    assert_eq!(sync.data()["published"], true, "完整流程必须真的发布出去");

    for command in [
        vec!["status"],
        vec!["fetch"],
        vec!["merge"],
        vec!["profile", "explain"],
        vec!["conflicts", "list"],
        vec!["doctor"],
    ] {
        traced(&alice, &command, &mut transcript).expect_ok();
    }
    // 人类可读模式也过一遍：脱敏不能只做在 JSON 分支上。
    for command in [vec!["status"], vec!["profile", "explain"], vec!["doctor"]] {
        let mut argv = vec!["-vvv"];
        argv.extend_from_slice(&command);
        let run = alice.run(&argv);
        run.expect_ok();
        transcript.push(run);
    }

    // ---- 断言：整段流水里没有一个字节的 canary --------------------------------
    assert!(
        transcript.len() >= 20,
        "流水记录太少，说明上面的命令没跑起来：{}",
        transcript.len()
    );
    for run in &transcript {
        assert!(
            !run.stdout.contains(CANARY),
            "`envsync {:?}` 的 stdout 里出现了凭据：{}",
            run.argv,
            run.stdout
        );
        assert!(
            !run.stderr.contains(CANARY),
            "`envsync {:?}` 的 stderr 里出现了凭据：{}",
            run.argv,
            run.stderr
        );
    }

    // 最后确认这一段不是空跑：远端上确实留下了一次真实发布，
    // 也就是说上面那一串「没有 canary」的断言是在**跑通的**流程上做的。
    assert_eq!(remote_ref(&remote, &alice).revision, 1);
}

/// 以 `-vvv`（trace 级日志）运行一条命令并记进流水。
fn traced(device: &Device, args: &[&str], transcript: &mut Vec<CliRun>) -> CliRun {
    let mut argv = vec!["-vvv"];
    argv.extend_from_slice(args);
    let run = device.run_json(&argv);
    transcript.push(run.clone());
    run
}

/// 配置文件的原始文本。
fn config_text(device: &Device) -> String {
    std::fs::read_to_string(device.config_path()).expect("应当能读配置文件")
}
