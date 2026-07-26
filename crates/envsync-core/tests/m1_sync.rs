//! M1 多设备同步验收：fetch → 合并基 → 三方合并 → 投影 → 计划 → 显式应用。
//!
//! 两台设备共享同一个后端目录（充当「远端」），各自拥有独立的授权根、状态目录与
//! 设备种子，因此除了共享对象库之外互不可见——这正是真实多设备场景的最小可信复现。
//!
//! 覆盖三条主线：
//!
//! 1. 从共同 base 分叉后修改**不冲突**的资源，双方最终收敛到同一个 State Root；
//! 2. 双方修改同一个 Git config key 时创建 Conflict，`sync` 返回
//!    `CoreError::Conflicted`，且本地文件与远端 Ref 一个字节都不变；
//! 3. 冲突按 ours / theirs / manual 裁决后，同步可以正常走完。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use envsync_core::config::{
    BackendConfig, DeviceConfig, DeviceProfileConfig, ResourceConfig, WorkspaceConfig,
    CONFIG_VERSION, DEFAULT_COMMENT_PREFIX,
};
use envsync_core::sync::MergeKind;
use envsync_core::{ApplyOutcome, EnvSyncService, FixedClock};
use envsync_domain::{
    DesiredDisposition, FileMode, ResolutionChoice, ResourceId, ResourcePolicy, StateRootId,
    StructuredFormat, WorkspaceId,
};
use tempfile::TempDir;

const SEED_A: &str = "3a7f1c92b4de5068a1cf23947db6e50f8c41a2937be05d6c1f83a4b72e90cd15";
const SEED_B: &str = "9c02e5471ab38df6205e94c7130a6b8fe2d47a95c60b381fe74a2d5093bc1607";
const WORKSPACE_UUID: &str = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";

/// 两台设备共享的资源：一个普通文本文件与一个 Git config。
const ZSHRC: &str = "shell/zsh/main";
const GITCONFIG: &str = "git/config";

// ---------------------------------------------------------------------------
// 脚手架
// ---------------------------------------------------------------------------

/// 一次测试里的「世界」：一个共享后端 + 若干台设备。
struct World {
    root: TempDir,
}

impl World {
    fn new() -> Self {
        let root = TempDir::new().expect("应当能创建临时目录");
        std::fs::create_dir_all(root.path().join("backend")).expect("应当能创建后端目录");
        World { root }
    }

    fn backend(&self) -> PathBuf {
        self.root.path().join("backend")
    }

    /// 创建一台设备：独立的 home 根与状态目录，共享后端。
    fn device(&self, name: &str, seed: &str) -> Device {
        let home = self.root.path().join(name).join("home");
        let state_dir = self.root.path().join(name).join("state");
        std::fs::create_dir_all(&home).expect("应当能创建 home 目录");
        std::fs::create_dir_all(&state_dir).expect("应当能创建状态目录");

        let mut roots = std::collections::BTreeMap::new();
        roots.insert("home".to_owned(), home.clone());

        let config = WorkspaceConfig {
            version: CONFIG_VERSION,
            workspace_id: WORKSPACE_UUID
                .parse::<WorkspaceId>()
                .expect("工作区标识合法"),
            device: DeviceConfig {
                name: name.to_owned(),
                seed_hex: seed.to_owned(),
            },
            backend: BackendConfig::Local {
                path: self.backend(),
            },
            state_dir,
            roots,
            profile: DeviceProfileConfig::default(),
            resources: vec![
                text_resource(ZSHRC, ".zshrc"),
                git_config_resource(GITCONFIG, ".gitconfig"),
            ],
        };
        Device { home, config }
    }
}

fn text_resource(id: &str, target: &str) -> ResourceConfig {
    ResourceConfig {
        id: ResourceId::parse(id).expect("资源标识合法"),
        root: "home".to_owned(),
        target: target.to_owned(),
        mode: FileMode::FullFile,
        disposition: DesiredDisposition::Managed,
        policy: ResourcePolicy::default(),
        comment_prefix: DEFAULT_COMMENT_PREFIX.to_owned(),
        selector: None,
        device_overrides: std::collections::BTreeMap::new(),
    }
}

/// Git config 资源：整份文件管理，但合并时走 git config 的语义合并。
fn git_config_resource(id: &str, target: &str) -> ResourceConfig {
    let mut resource = text_resource(id, target);
    resource.policy = ResourcePolicy {
        structured_format: Some(StructuredFormat::GitConfig),
        ..ResourcePolicy::default()
    };
    resource
}

struct Device {
    home: PathBuf,
    config: WorkspaceConfig,
}

impl Device {
    fn service(&self) -> EnvSyncService {
        // 固定时钟：快照标识只由内容与父子关系决定，测试因此可复现。
        EnvSyncService::open_with_clock(
            self.config.clone(),
            Arc::new(FixedClock(1_700_000_000_000)),
        )
        .expect("应当能打开服务")
    }

    fn write(&self, target: &str, content: &str) {
        std::fs::write(self.home.join(target), content).expect("应当能写入 home 文件");
    }

    fn read(&self, target: &str) -> String {
        std::fs::read_to_string(self.home.join(target)).expect("应当能读取 home 文件")
    }

    fn exists(&self, target: &str) -> bool {
        self.home.join(target).exists()
    }

    /// capture → plan → sync 的完整一轮；返回是否真的应用了动作。
    fn capture_plan_sync(&self) -> ApplyOutcome {
        let mut service = self.service();
        service.capture().expect("capture 应当成功");
        let plan = service.build_plan().expect("plan 应当成功");
        service.apply_plan(plan.id()).expect("sync 应当成功")
    }

    /// plan → sync（不 capture）：用于把远端内容收敛到本机。
    fn plan_sync(&self) -> ApplyOutcome {
        let mut service = self.service();
        let plan = service.build_plan().expect("plan 应当成功");
        service.apply_plan(plan.id()).expect("sync 应当成功")
    }

    /// 本机当前认定的目标 State Root（草稿头优先，否则远端头）。
    fn state_root(&self) -> StateRootId {
        let mut service = self.service();
        service
            .profile_explain()
            .expect("profile explain 应当成功")
            .state_root
            .expect("工作区应当已有快照")
    }
}

/// 读取后端当前 Ref 的 (revision, head)。
fn remote_ref(device: &Device) -> (u64, Option<String>) {
    let mut service = device.service();
    let outcome = service.fetch().expect("fetch 应当成功");
    (outcome.revision, outcome.head.map(|id| id.to_hex()))
}

fn read_file(path: &Path) -> String {
    std::fs::read_to_string(path).expect("应当能读取文件")
}

// ---------------------------------------------------------------------------
// 场景 1：不冲突的分叉可以自动合并
// ---------------------------------------------------------------------------

#[test]
fn two_devices_diverge_on_different_resources_and_converge() {
    let world = World::new();
    let alice = world.device("alice", SEED_A);
    let bob = world.device("bob", SEED_B);

    // 共同 base：A 捕获两份文件并发布。
    alice.write(".zshrc", "export EDITOR=nvim\n");
    alice.write(".gitconfig", "[user]\n\temail = a@example.com\n");
    alice.capture_plan_sync();

    // B 先 fetch 再收敛到共同 base。
    let fetched = bob.service().fetch().expect("fetch 应当成功");
    assert!(fetched.head.is_some(), "fetch 之后应当看到远端头");
    assert!(fetched.objects > 0, "首次 fetch 应当把对象拉进本地");
    bob.plan_sync();
    assert_eq!(bob.read(".zshrc"), "export EDITOR=nvim\n");

    // 分叉：两台设备都基于同一个 base 各改各的（互不冲突）。
    // B 先捕获——此时远端头还是共同 base，因此草稿的父快照就是 base。
    bob.write(
        ".gitconfig",
        "[user]\n\temail = a@example.com\n\tname = Bob\n",
    );
    let mut bob_service = bob.service();
    bob_service.capture().expect("capture 应当成功");

    // A 随后发布自己的改动，远端头前进，两条历史至此真正分叉。
    alice.write(".zshrc", "export EDITOR=nvim\nexport PAGER=less\n");
    alice.capture_plan_sync();

    // B：fetch → merge → plan → publish → apply。
    bob_service.fetch().expect("fetch 应当成功");
    let merged = bob_service.merge_states().expect("merge 应当成功");
    assert_eq!(merged.kind, MergeKind::Merged, "两侧都改过，应当三方合并");
    assert!(merged.base.is_some(), "应当找到共同的合并基");
    assert!(merged.conflicts.is_empty(), "改动不重叠时不应当有冲突");

    let plan = bob_service.build_plan().expect("plan 应当成功");
    let outcome = bob_service.apply_plan(plan.id()).expect("sync 应当成功");
    assert!(matches!(outcome, ApplyOutcome::Completed { .. }));

    // B 本机同时拿到了两侧的改动。
    assert_eq!(
        bob.read(".zshrc"),
        "export EDITOR=nvim\nexport PAGER=less\n"
    );
    assert!(bob.read(".gitconfig").contains("name = Bob"));

    // A：fetch → merge（快进）→ plan → apply。
    let mut alice_service = alice.service();
    alice_service.fetch().expect("fetch 应当成功");
    let alice_merge = alice_service.merge_states().expect("merge 应当成功");
    assert_eq!(
        alice_merge.kind,
        MergeKind::FastForward,
        "本地没有新草稿时应当直接快进到远端"
    );
    let plan = alice_service.build_plan().expect("plan 应当成功");
    alice_service.apply_plan(plan.id()).expect("sync 应当成功");

    // 收敛判据：两端的目标 State Root 完全一致，文件内容也一致。
    assert_eq!(alice.state_root(), bob.state_root());
    assert_eq!(alice.read(".zshrc"), bob.read(".zshrc"));
    assert_eq!(alice.read(".gitconfig"), bob.read(".gitconfig"));
}

// ---------------------------------------------------------------------------
// 场景 2：同一个 Git config key 双方修改 → 冲突
// ---------------------------------------------------------------------------

/// 把两台设备推进到「同一个 git config key 上双方改动不同」的状态。
fn diverge_on_same_key(world: &World) -> (Device, Device) {
    let alice = world.device("alice", SEED_A);
    let bob = world.device("bob", SEED_B);

    alice.write(".zshrc", "export EDITOR=nvim\n");
    alice.write(".gitconfig", "[user]\n\temail = base@example.com\n");
    alice.capture_plan_sync();

    bob.service().fetch().expect("fetch 应当成功");
    bob.plan_sync();

    // 双方把同一个 key 改成不同的值；B 先捕获，保证草稿的父快照是共同 base。
    bob.write(".gitconfig", "[user]\n\temail = bob@example.com\n");
    bob.service().capture().expect("capture 应当成功");

    alice.write(".gitconfig", "[user]\n\temail = alice@example.com\n");
    alice.capture_plan_sync();

    (alice, bob)
}

#[test]
fn same_git_config_key_conflicts_and_sync_changes_nothing() {
    let world = World::new();
    let (_alice, bob) = diverge_on_same_key(&world);

    let before_file = bob.read(".gitconfig");
    let before_ref = remote_ref(&bob);

    let mut service = bob.service();
    service.fetch().expect("fetch 应当成功");
    let merged = service.merge_states().expect("merge 本身应当成功返回");

    assert_eq!(merged.kind, MergeKind::Conflicted);
    assert_eq!(merged.conflicts.len(), 1, "只有 .gitconfig 冲突");
    assert!(merged.merged.is_none(), "冲突时绝不生成快照");

    // 冲突已登记，并且能被读回（诊断只含键路径，不含正文）。
    let open = service.conflicts_list().expect("列出冲突应当成功");
    assert_eq!(open.len(), 1);
    let detail = service
        .conflicts_show(open[0].conflict)
        .expect("查看冲突应当成功");
    assert_eq!(detail.record.resource.as_str(), GITCONFIG);
    assert!(!detail.conflict.diagnostics.is_empty());
    assert!(
        !detail
            .conflict
            .diagnostics
            .iter()
            .any(|line| line.contains("example.com")),
        "诊断不得泄漏文件正文"
    );

    // sync 必须以「存在冲突」拒绝，且什么都不动。
    let plan_error = service
        .build_plan()
        .map(|plan| service.apply_plan(plan.id()))
        .expect("plan 本身仍可生成")
        .expect_err("存在冲突时 sync 必须失败");
    assert!(plan_error.is_conflicted(), "错误必须是 Conflicted");
    assert_eq!(plan_error.code(), "sync.conflicted");

    assert_eq!(bob.read(".gitconfig"), before_file, "本地文件不得被改动");
    assert_eq!(remote_ref(&bob), before_ref, "远端 Ref 不得被推进");
}

// ---------------------------------------------------------------------------
// 场景 3：裁决之后可以完成同步
// ---------------------------------------------------------------------------

/// 走完「制造冲突 → 裁决 → 重新合并 → 应用」的全过程，返回 bob 最终的 .gitconfig。
fn resolve_and_finish(choice: ResolutionChoice, manual: Option<&str>) -> String {
    let world = World::new();
    let (_alice, bob) = diverge_on_same_key(&world);

    let mut service = bob.service();
    service.fetch().expect("fetch 应当成功");
    let merged = service.merge_states().expect("merge 应当成功返回");
    let conflict = merged.conflicts[0];

    let manual_file = world.root.path().join("manual.gitconfig");
    let content = match manual {
        Some(text) => {
            std::fs::write(&manual_file, text).expect("应当能写入人工合并结果");
            Some(read_file(&manual_file).into_bytes())
        }
        None => None,
    };
    service
        .conflicts_resolve(conflict, choice, content.as_deref())
        .expect("裁决应当成功");
    assert!(
        service.conflicts_list().expect("列出冲突").is_empty(),
        "裁决之后不应再有未解决冲突"
    );

    // 重新合并：这次应当干净通过，并生成合并快照。
    let merged = service.merge_states().expect("重新合并应当成功");
    assert_eq!(merged.kind, MergeKind::Merged);
    assert!(merged.conflicts.is_empty());

    let plan = service.build_plan().expect("plan 应当成功");
    let outcome = service.apply_plan(plan.id()).expect("sync 应当成功");
    assert!(matches!(outcome, ApplyOutcome::Completed { .. }));
    assert!(bob.exists(".gitconfig"));
    bob.read(".gitconfig")
}

#[test]
fn resolving_with_ours_keeps_local_content() {
    let content = resolve_and_finish(ResolutionChoice::Ours, None);
    assert!(content.contains("bob@example.com"), "ours 应当保留本地取值");
}

#[test]
fn resolving_with_theirs_takes_remote_content() {
    let content = resolve_and_finish(ResolutionChoice::Theirs, None);
    assert!(
        content.contains("alice@example.com"),
        "theirs 应当采用远端取值"
    );
}

#[test]
fn resolving_manually_uses_the_supplied_file() {
    let merged_text = "[user]\n\temail = team@example.com\n";
    let content = resolve_and_finish(ResolutionChoice::Manual, Some(merged_text));
    assert_eq!(content, merged_text, "manual 应当逐字采用人工结果");
}

// ---------------------------------------------------------------------------
// fetch 的性质
// ---------------------------------------------------------------------------

#[test]
fn fetch_is_idempotent_and_touches_no_user_file() {
    let world = World::new();
    let alice = world.device("alice", SEED_A);
    let bob = world.device("bob", SEED_B);

    alice.write(".zshrc", "export EDITOR=nvim\n");
    alice.write(".gitconfig", "[user]\n\temail = a@example.com\n");
    alice.capture_plan_sync();

    let mut service = bob.service();
    let first = service.fetch().expect("fetch 应当成功");
    assert!(first.objects > 0);
    assert!(!first.up_to_date);

    let second = service.fetch().expect("fetch 应当成功");
    assert_eq!(second.objects, 0, "重复 fetch 是幂等空转");
    assert!(second.up_to_date);

    // fetch 只搬对象，绝不碰用户文件。
    assert!(!bob.exists(".zshrc"));
    assert!(!bob.exists(".gitconfig"));
}

// ---------------------------------------------------------------------------
// 场景 5：`mode: structured_merge` 在 capture → plan → sync 上真正走得通
//
// 在此之前配置层直接拒绝这个模式（`config.mode_not_supported`），于是虽然 M1 已经实现
// 了五种结构化合并器，用户却只能把资源写成 `full_file` + `policy.structured_format`。
// 现在模式本身放开，落盘语义是 **Full File**：结构化合并发生在 `sync` 的 merge 阶段，
// 写到本地的就是合并后的权威字节（见 `envsync_core::render` 的模块级文档）。
// ---------------------------------------------------------------------------

/// 用 `mode: structured_merge` 声明的 Git config 资源。
fn structured_merge_resource(id: &str, target: &str) -> ResourceConfig {
    let mut resource = text_resource(id, target);
    resource.mode = FileMode::StructuredMerge;
    resource.policy = ResourcePolicy {
        structured_format: Some(StructuredFormat::GitConfig),
        ..ResourcePolicy::default()
    };
    resource
}

/// 只声明一个 `structured_merge` 资源的设备。
fn structured_device(world: &World, name: &str, seed: &str) -> Device {
    let mut device = world.device(name, seed);
    device.config.resources = vec![structured_merge_resource(GITCONFIG, ".gitconfig")];
    device
}

#[test]
fn structured_merge_mode_goes_through_capture_plan_and_sync() {
    let world = World::new();
    let alice = structured_device(&world, "alice", SEED_A);
    let bob = structured_device(&world, "bob", SEED_B);

    // ---- capture：整份文件即受管内容 ----------------------------------------
    const BASE: &str = "[user]\n\temail = base@example.com\n";
    alice.write(".gitconfig", BASE);
    let outcome = alice.capture_plan_sync();
    assert!(
        matches!(
            outcome,
            ApplyOutcome::Completed {
                published: true,
                ..
            }
        ),
        "首次同步必须把快照发布出去：{outcome:?}"
    );

    // ---- plan + sync：B 从零收敛，落地字节与 A 完全一致 ----------------------
    bob.service().fetch().expect("fetch 应当成功");
    let plan = bob.service().build_plan().expect("plan 应当成功");
    assert_eq!(
        plan.actions.len(),
        1,
        "B 手上还没有这个文件，应当正好有一个创建动作"
    );
    assert_eq!(
        plan.actions[0].kind,
        envsync_domain::ActionKind::CreateFile,
        "structured_merge 的落盘语义是 Full File，因此是整份创建"
    );
    bob.plan_sync();
    assert_eq!(bob.read(".gitconfig"), BASE, "落地的必须是权威字节本身");

    // ---- 三方合并：双方改**不同的键**，结构化合并把两边都留下 ----------------
    bob.write(
        ".gitconfig",
        "[user]\n\temail = base@example.com\n\tname = Bob\n",
    );
    let mut bob_service = bob.service();
    bob_service.capture().expect("capture 应当成功");

    alice.write(
        ".gitconfig",
        "[core]\n\teditor = nvim\n[user]\n\temail = base@example.com\n",
    );
    alice.capture_plan_sync();

    bob_service.fetch().expect("fetch 应当成功");
    let merged = bob_service.merge_states().expect("merge 应当成功");
    assert_eq!(
        merged.kind,
        MergeKind::Merged,
        "改的是不同的键，必须是干净的三方合并"
    );
    assert!(merged.conflicts.is_empty(), "键不重叠时不该有冲突");

    let plan = bob_service.build_plan().expect("plan 应当成功");
    bob_service
        .apply_plan(plan.id())
        .expect("应用合并结果应当成功");

    // 合并后的权威字节被整份写进本地：两侧的键都在。
    let merged_text = bob.read(".gitconfig");
    assert!(merged_text.contains("name = Bob"), "{merged_text}");
    assert!(merged_text.contains("editor = nvim"), "{merged_text}");
    assert!(
        merged_text.contains("email = base@example.com"),
        "{merged_text}"
    );

    // A 收敛回同一份字节：两端逐字节一致，State Root 也一致。
    alice.plan_sync();
    assert_eq!(alice.read(".gitconfig"), merged_text);
    assert_eq!(alice.state_root(), bob.state_root());

    // 幂等：再跑一轮不产生任何动作。
    let again = bob.service().build_plan().expect("plan 应当成功");
    assert!(
        again.actions.is_empty(),
        "已经收敛之后不该再有动作：{:?}",
        again.actions
    );
}
