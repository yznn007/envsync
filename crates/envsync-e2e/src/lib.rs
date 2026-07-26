#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

//! EnvSync M0 端到端验收套件的共用夹具。
//!
//! # 与计划文档的对应关系
//!
//! 计划文档「任务 14」把端到端测试写在 `tests/e2e/local_file_loop.rs`。本仓库把它
//! 落成一个独立的工作区成员 `crates/envsync-e2e`，测试本体在
//! `crates/envsync-e2e/tests/local_file_loop.rs`——**即计划中的
//! `tests/e2e/local_file_loop.rs`**。这样做的唯一原因是不必为了挂一个测试目标去改
//! 动其他 crate；场景、断言与验收条件的对应关系完全不变。
//!
//! # 为什么必须走真实进程
//!
//! `envsync-core` 已经有覆盖同一批流程的库级测试（`crates/envsync-core/tests/`）。
//! 本套件刻意**不**调用 `EnvSyncService`，而是用 [`std::process::Command`] 启动真正
//! 的 `envsync` 二进制：退出码、`--json` 的 stdout/stderr 分流、跨进程的 CAS 竞争、
//! 「进程被中断后下一次启动能否恢复」这些性质，只有在真进程里才成立。
//!
//! # 二进制定位
//!
//! `env!("CARGO_BIN_EXE_envsync")` **在这里不可用**：Cargo 只为「定义该二进制的那个
//! package」的集成测试注入 `CARGO_BIN_EXE_*`。两条路都实测过：
//!
//! * 直接用：`option_env!("CARGO_BIN_EXE_envsync")` 返回 `None`；
//! * 按建议加上 `[dev-dependencies] envsync-cli = { path = "../envsync-cli" }`：
//!   Cargo 接受这个声明（不报错），但 `option_env!` **依然是 `None`**，而且
//!   `cargo test -p envsync-e2e` 也**不会**去构建那个二进制——`target/debug/envsync`
//!   仍然不存在。
//!
//! 因此 [`envsync_binary`] 改为在测试进程里调用一次
//! `cargo build -p envsync-cli --bin envsync --message-format=json`，从 Cargo 的
//! `compiler-artifact` 消息里读回 `executable` 的绝对路径。这条路径：
//!
//! * 即使产物已是最新（`"fresh": true`）也会被输出，所以不会额外触发编译；
//! * 尊重 `CARGO_TARGET_DIR`，不需要猜 `target/debug/envsync`；
//! * 让 `cargo test -p envsync-e2e` 单独运行时也一定能拿到**最新**的二进制——指望
//!   `target/debug/` 里「碰巧还留着上次构建产物」是不可靠的。
//!
//! 嵌套调用 Cargo 是安全的：`cargo test` 在运行测试进程时已经放开了构建锁。构建用
//! 的是 dev profile，因此即使外层跑的是 `--release`，这里拿到的也是 debug 二进制；
//! 对验收测试而言无所谓，只是会多编译一次。
//!
//! 若 Cargo 不可用（例如产物被拷到别处执行），会退回到「从
//! [`std::env::current_exe`] 出发在同级与上级目录里找 `envsync`」。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use envsync_core::{DeviceConfig, ResourceConfig, WorkspaceConfig};
use envsync_domain::{
    CborCodec, DesiredDisposition, FileMode, ObjectId, ResourceId, ResourcePolicy, SnapshotBody,
    SnapshotId, StateRoot,
};
use envsync_storage::{DraftStore, Journal};
use serde_json::Value;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// 二进制定位
// ---------------------------------------------------------------------------

/// 被测 `envsync` 二进制的绝对路径。
///
/// 首次调用会（在必要时）构建二进制，后续调用复用缓存结果，因此多个测试并行运行
/// 时只会有一次构建。
pub fn envsync_binary() -> &'static Path {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY.get_or_init(locate_binary).as_path()
}

/// 实际的定位逻辑，见模块文档。
fn locate_binary() -> PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_envsync") {
        // 未来若把本套件搬回 `envsync-cli` 内部，这条分支会自动生效。
        return PathBuf::from(path);
    }
    if let Some(path) = binary_from_cargo() {
        return path;
    }
    if let Some(path) = binary_next_to_test_executable() {
        return path;
    }
    panic!(
        "无法定位 `envsync` 二进制：`cargo build -p envsync-cli` 失败，且测试可执行文件\
         附近也没有它。请先运行 `cargo build -p envsync-cli`。"
    );
}

/// 问 Cargo 要二进制路径。
fn binary_from_cargo() -> Option<PathBuf> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args([
            "build",
            "-p",
            "envsync-cli",
            "--bin",
            "envsync",
            "--message-format=json",
        ])
        .stderr(Stdio::inherit())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    for line in stdout.lines() {
        let Ok(message) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if message["reason"] != "compiler-artifact" || message["target"]["name"] != "envsync" {
            continue;
        }
        if let Some(executable) = message["executable"].as_str() {
            return Some(PathBuf::from(executable));
        }
    }
    None
}

/// 退路：测试可执行文件在 `<target>/<profile>/deps/` 下，二进制在其上一层。
fn binary_next_to_test_executable() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let deps_dir = exe.parent()?;
    let candidates = [deps_dir.to_path_buf(), deps_dir.parent()?.to_path_buf()];
    for dir in candidates {
        let candidate = dir.join(format!("envsync{}", std::env::consts::EXE_SUFFIX));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 一次 CLI 调用
// ---------------------------------------------------------------------------

/// 一次 `envsync` 进程调用的完整结果。
#[derive(Debug, Clone)]
pub struct CliRun {
    /// 实际传给二进制的参数，出错时打印出来便于复现。
    pub argv: Vec<String>,
    /// 进程退出码。
    pub code: i32,
    /// 标准输出。
    pub stdout: String,
    /// 标准错误。
    pub stderr: String,
}

impl CliRun {
    /// 由 [`Output`] 构造；被信号杀死时直接失败。
    fn from_output(argv: Vec<String>, output: &Output) -> Self {
        let code = output
            .status
            .code()
            .unwrap_or_else(|| panic!("envsync {argv:?} 应当正常退出而不是被信号终止"));
        CliRun {
            argv,
            code,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    /// 断言退出码为 0，返回自身以便链式调用。
    pub fn expect_ok(&self) -> &Self {
        self.expect_code(0)
    }

    /// 断言退出码等于 `expected`。
    pub fn expect_code(&self, expected: i32) -> &Self {
        assert_eq!(
            self.code, expected,
            "envsync {:?} 应当以退出码 {expected} 结束，实际 {}\nstdout: {}\nstderr: {}",
            self.argv, self.code, self.stdout, self.stderr
        );
        self
    }

    /// 解析 `--json` 信封；同时断言 stdout **只有一行** JSON。
    pub fn json(&self) -> Value {
        let trimmed = self.stdout.trim();
        assert_eq!(
            trimmed.lines().count(),
            1,
            "envsync {:?} 的 stdout 必须只有一行 JSON，实际是：{:?}\nstderr: {}",
            self.argv,
            self.stdout,
            self.stderr
        );
        serde_json::from_str(trimmed).unwrap_or_else(|error| {
            panic!(
                "envsync {:?} 的 stdout 必须是合法 JSON：{error}\n{trimmed}",
                self.argv
            )
        })
    }

    /// `--json` 信封里的 `data`。
    pub fn data(&self) -> Value {
        self.json()["data"].clone()
    }

    /// `--json` 信封里全部诊断的稳定错误码。
    pub fn diagnostic_codes(&self) -> Vec<String> {
        self.json()["diagnostics"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item["code"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 断言诊断里出现了某个错误码。
    pub fn expect_diagnostic(&self, code: &str) -> &Self {
        let codes = self.diagnostic_codes();
        assert!(
            codes.iter().any(|found| found == code),
            "envsync {:?} 的诊断里应当包含 `{code}`，实际是 {codes:?}\nstdout: {}",
            self.argv,
            self.stdout
        );
        self
    }
}

// ---------------------------------------------------------------------------
// 世界与设备
// ---------------------------------------------------------------------------

/// 一个隔离的测试世界：一个临时目录 + 一个共享的 Local Backend。
///
/// 每个测试各持一个 [`E2eWorld`]，彼此没有任何共享状态（临时目录、后端、journal
/// 都是独立的），因此可以安全并行执行。
#[derive(Debug, Clone)]
pub struct E2eWorld {
    root: Arc<TempDir>,
}

impl E2eWorld {
    /// 创建一个新世界。
    pub fn new() -> Self {
        let root = TempDir::new().expect("应当能创建临时目录");
        std::fs::create_dir_all(root.path().join("backend")).expect("应当能创建后端目录");
        E2eWorld {
            root: Arc::new(root),
        }
    }

    /// 世界根目录。
    pub fn path(&self) -> &Path {
        self.root.path()
    }

    /// 共享的 Local Backend 目录。
    pub fn backend(&self) -> PathBuf {
        self.root.path().join("backend")
    }

    /// 创建**第一台设备**：真正跑一次 `envsync init`，由它决定 `workspace_id`。
    ///
    /// 授权根是这台设备专属的临时目录（场景 1 的「临时授权根」）。
    pub fn primary(&self, name: &str) -> Device {
        let device = self.device_layout(name);
        let run = run_binary(&[
            "init",
            "--config",
            &arg(&device.config_path),
            "--backend-path",
            &arg(&self.backend()),
            "--device-name",
            name,
            "--json",
        ]);
        run.expect_ok();

        // `init` 生成的配置把 `home` 指向真实 HOME；测试必须把它挪进临时目录，
        // 否则任何一次 sync 都会写到跑测试的人的家目录里。
        //
        // `state_dir` 保持 `init` 自己选的默认值（配置文件同级的 `.envsync/`），
        // 这样场景 1 才能真正验到「init 把状态目录建好了」。
        let mut config = device.config();
        config.roots.insert("home".to_owned(), device.home.clone());
        device.write_config(&config);
        assert_eq!(
            config.state_dir, device.state_dir,
            "夹具假设的状态目录与 init 生成的不一致"
        );

        Device {
            init_json: Some(run.json()),
            ..device
        }
    }

    /// 创建**第二台设备**：复用同一后端与同一 `workspace_id`，但有独立的授权根、
    /// 状态目录和设备身份（场景 4 的「模拟第二设备」）。
    pub fn secondary(&self, primary: &Device, name: &str) -> Device {
        let device = self.device_layout(name);
        let mut config = primary.config();
        config.device = DeviceConfig {
            name: name.to_owned(),
            // 设备种子必须不同：设备身份不同才谈得上「两台设备」。
            seed_hex: device_seed(name),
        };
        config.state_dir = device.state_dir.clone();
        config.roots.insert("home".to_owned(), device.home.clone());
        config.resources.clear();
        device.write_config(&config);
        device
    }

    /// 准备一台设备的目录布局，但不写配置。
    fn device_layout(&self, name: &str) -> Device {
        let base = self.root.path().join(name);
        let home = base.join("home");
        std::fs::create_dir_all(&home).expect("应当能创建授权根目录");
        Device {
            world: self.clone(),
            name: name.to_owned(),
            config_path: base.join("envsync.yaml"),
            home,
            // 与 `envsync_core::config::DEFAULT_STATE_DIR` 一致：配置文件同级的
            // `.envsync/`。第二台设备的配置是从第一台复制来的，因此必须显式改写。
            state_dir: base.join(".envsync"),
            init_json: None,
        }
    }
}

impl Default for E2eWorld {
    fn default() -> Self {
        E2eWorld::new()
    }
}

/// 由设备名派生一个确定的 64 位十六进制种子。
///
/// 不用随机值：测试失败时同一个设备名必须对应同一个 `DeviceId`，否则日志无法对照。
fn device_seed(name: &str) -> String {
    let mut seed = String::with_capacity(64);
    for byte in name.as_bytes().iter().cycle().take(32) {
        seed.push_str(&format!("{byte:02x}"));
    }
    seed
}

/// 一台「设备」：独立的授权根、配置文件与本地状态目录。
#[derive(Debug, Clone)]
pub struct Device {
    world: E2eWorld,
    name: String,
    config_path: PathBuf,
    home: PathBuf,
    state_dir: PathBuf,
    init_json: Option<Value>,
}

impl Device {
    /// 设备名。
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 配置文件路径。
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// 授权根（`home` 别名）的绝对路径。
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// 本地状态目录（journal / 草稿 / 备份）。
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// 共享后端目录。
    pub fn backend(&self) -> PathBuf {
        self.world.backend()
    }

    /// `envsync init` 的 JSON 信封；只有第一台设备有。
    pub fn init_json(&self) -> Option<&Value> {
        self.init_json.as_ref()
    }

    // ---- 配置 --------------------------------------------------------------

    /// 读回当前配置。
    pub fn config(&self) -> WorkspaceConfig {
        WorkspaceConfig::load(&self.config_path).expect("配置应当可读且合法")
    }

    /// 覆盖写配置文件。
    pub fn write_config(&self, config: &WorkspaceConfig) {
        std::fs::write(
            &self.config_path,
            config.to_yaml().expect("配置应当可序列化"),
        )
        .expect("应当能写配置文件");
    }

    /// 替换资源列表。
    pub fn set_resources(&self, resources: Vec<ResourceConfig>) {
        self.set_resources_from(&self.config(), resources);
    }

    /// 以给定配置为基准替换资源列表并写回。
    ///
    /// 上一次写入的若是**故意非法**的配置（例如越权 `target`），[`Device::config`]
    /// 已经读不回来了，这时必须用调用方自己留着的那份合法基准。
    pub fn set_resources_from(&self, base: &WorkspaceConfig, resources: Vec<ResourceConfig>) {
        let mut config = base.clone();
        config.resources = resources;
        self.write_config(&config);
    }

    // ---- 授权根内的文件 -----------------------------------------------------

    /// 授权根内某个相对路径的绝对路径。
    pub fn home_path(&self, relative: &str) -> PathBuf {
        let mut path = self.home.clone();
        for segment in relative.split('/') {
            path.push(segment);
        }
        path
    }

    /// 往授权根里写一个文件（必要时创建父目录）。
    pub fn write_home(&self, relative: &str, contents: impl AsRef<[u8]>) {
        let path = self.home_path(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("应当能创建父目录");
        }
        std::fs::write(&path, contents).expect("应当能写文件");
    }

    /// 读回授权根里的文件**原始字节**。
    pub fn read_home(&self, relative: &str) -> Vec<u8> {
        std::fs::read(self.home_path(relative))
            .unwrap_or_else(|error| panic!("{}：应当能读 `{relative}`：{error}", self.name))
    }

    /// 目标是否存在（不跟随符号链接）。
    pub fn home_exists(&self, relative: &str) -> bool {
        std::fs::symlink_metadata(self.home_path(relative)).is_ok()
    }

    /// 断言授权根里的文件与期望**逐字节**相同。
    pub fn assert_home_bytes(&self, relative: &str, expected: &str) {
        let actual = self.read_home(relative);
        assert_bytes_eq(
            &actual,
            expected.as_bytes(),
            &format!("{}:{relative}", self.name),
        );
    }

    // ---- 运行 CLI ----------------------------------------------------------

    /// 运行一次子命令（自动补 `--config`），不加 `--json`。
    pub fn run(&self, args: &[&str]) -> CliRun {
        let mut all: Vec<String> = args.iter().map(|item| (*item).to_owned()).collect();
        all.extend(["--config".to_owned(), arg(&self.config_path)]);
        run_binary_owned(all)
    }

    /// 运行一次子命令（自动补 `--config` 与 `--json`）。
    pub fn run_json(&self, args: &[&str]) -> CliRun {
        run_binary_owned(self.json_argv(args))
    }

    /// 后台启动一次子命令，用于制造跨进程竞争。
    pub fn spawn_json(&self, args: &[&str]) -> SpawnedRun {
        let argv = self.json_argv(args);
        let child = Command::new(envsync_binary())
            .args(&argv)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("应当能够启动 envsync 二进制");
        SpawnedRun { argv, child }
    }

    fn json_argv(&self, args: &[&str]) -> Vec<String> {
        let mut all: Vec<String> = args.iter().map(|item| (*item).to_owned()).collect();
        all.extend([
            "--config".to_owned(),
            arg(&self.config_path),
            "--json".to_owned(),
        ]);
        all
    }

    // ---- 常用命令的强类型包装 -----------------------------------------------

    /// `envsync capture`，断言成功。
    pub fn capture(&self) -> CaptureInfo {
        let run = self.run_json(&["capture"]);
        run.expect_ok();
        let data = run.data();
        CaptureInfo {
            snapshot: string_field(&data, "snapshot"),
            state_root: string_field(&data, "state_root"),
            changed: data["changed"].as_bool().expect("changed 是布尔"),
            diagnostic_codes: run.diagnostic_codes(),
        }
    }

    /// `envsync plan`，断言成功。
    pub fn plan(&self) -> PlanInfo {
        let run = self.run_json(&["plan"]);
        run.expect_ok();
        let data = run.data();
        PlanInfo {
            id: string_field(&data, "plan"),
            target_snapshot: string_field(&data, "target_snapshot"),
            base_revision: data["base_revision"]
                .as_u64()
                .expect("base_revision 是整数"),
            next_revision: data["next_revision"]
                .as_u64()
                .expect("next_revision 是整数"),
            action_count: data["action_count"].as_u64().expect("action_count 是整数") as usize,
            blocked: data["blocked"].as_bool().expect("blocked 是布尔"),
            actions: data["actions"].as_array().cloned().unwrap_or_default(),
            diagnostic_codes: run.diagnostic_codes(),
        }
    }

    /// `envsync sync --plan <id>`（不断言退出码）。
    pub fn sync(&self, plan: &str) -> CliRun {
        self.run_json(&["sync", "--plan", plan])
    }

    /// `envsync plan` + `envsync sync`，断言两步都成功。
    pub fn converge(&self) -> SyncInfo {
        let plan = self.plan();
        assert!(
            !plan.blocked,
            "{}：计划 {} 存在阻塞诊断：{:?}",
            self.name, plan.id, plan.diagnostic_codes
        );
        let run = self.sync(&plan.id);
        run.expect_ok();
        let data = run.data();
        SyncInfo {
            outcome: string_field(&data, "outcome"),
            operation: data["operation"].as_str().map(str::to_owned),
            applied: data["applied"].as_u64().expect("applied 是整数") as usize,
            published: data["published"].as_bool().expect("published 是布尔"),
        }
    }

    /// `envsync status --json` 的 `data`。
    pub fn status(&self) -> Value {
        let run = self.run_json(&["status"]);
        run.expect_ok();
        run.data()
    }

    // ---- 本地状态的直接访问 -------------------------------------------------
    //
    // 这些方法绕过 CLI 直接读本地存储，用来对 CLI 输出之外的不变量做精确断言
    // （例如「Managed Block 捕获的到底是块内内容还是整个文件」）。

    /// 打开这台设备的操作日志。
    pub fn journal(&self) -> Journal {
        Journal::open(self.state_dir.join("journal.db")).expect("应当能打开操作日志")
    }

    /// 打开这台设备的草稿库。
    pub fn drafts(&self) -> DraftStore {
        DraftStore::open(self.state_dir.join("draft")).expect("应当能打开草稿库")
    }

    /// 从草稿库读出某个快照里某个资源的 Blob **原始字节**。
    pub fn draft_blob_of(&self, snapshot: &str, resource: &str) -> Option<Vec<u8>> {
        let drafts = self.drafts();
        let snapshot: SnapshotId = snapshot.parse().expect("快照标识应当合法");
        let body_bytes = drafts
            .get(ObjectId::from(snapshot))
            .expect("草稿库可读")
            .expect("草稿库里应当有该快照");
        let body = SnapshotBody::from_canonical_slice(&body_bytes).expect("快照应当可解码");
        let state_bytes = drafts
            .get(ObjectId::from(body.state_root))
            .expect("草稿库可读")
            .expect("草稿库里应当有 State Root");
        let state = StateRoot::from_canonical_slice(&state_bytes).expect("State Root 应当可解码");
        let resource = ResourceId::parse(resource).expect("资源标识应当合法");
        let blob = state.get(&resource)?.blob?;
        drafts.get(ObjectId::from(blob)).expect("草稿库可读")
    }

    /// 读出某个计划里所有动作的落点：`(序号, 资源, 目标绝对路径, 待写入内容)`。
    ///
    /// 场景 9 用它「手工完成计划的前半段」，从而在不真的杀进程的前提下，制造出与
    /// 「apply 写到一半被打断」完全一样的现场。
    pub fn plan_actions(&self, plan_id: &str) -> Vec<StagedAction> {
        let drafts = self.drafts();
        let plan = drafts
            .get_plan(plan_id.parse().expect("计划标识应当合法"))
            .expect("草稿库可读")
            .expect("草稿库里应当有该计划");
        plan.actions
            .iter()
            .enumerate()
            .map(|(ordinal, action)| {
                let mut path = self.home.clone();
                for segment in &action.target.segments {
                    path.push(segment);
                }
                let content = action.content.map(|blob| {
                    drafts
                        .get(ObjectId::from(blob))
                        .expect("草稿库可读")
                        .expect("计划引用的渲染产物应当在草稿库里")
                });
                StagedAction {
                    ordinal,
                    resource: action.resource.to_string(),
                    path,
                    content,
                }
            })
            .collect()
    }
}

/// 一个后台运行中的 CLI 进程。
#[derive(Debug)]
pub struct SpawnedRun {
    argv: Vec<String>,
    child: Child,
}

impl SpawnedRun {
    /// 等待进程结束并取回结果。
    pub fn wait(self) -> CliRun {
        let output = self.child.wait_with_output().expect("子进程应当能够结束");
        CliRun::from_output(self.argv, &output)
    }
}

/// 计划中的一个动作在本机的落点。
#[derive(Debug, Clone)]
pub struct StagedAction {
    /// 在计划中的序号。
    pub ordinal: usize,
    /// 关联资源标识。
    pub resource: String,
    /// 目标文件的绝对路径。
    pub path: PathBuf,
    /// 待写入的完整文件内容；删除动作为 `None`。
    pub content: Option<Vec<u8>>,
}

/// `capture` 的结果。
#[derive(Debug, Clone)]
pub struct CaptureInfo {
    /// 快照标识。
    pub snapshot: String,
    /// State Root 标识。
    pub state_root: String,
    /// 是否产生了新草稿。
    pub changed: bool,
    /// 诊断码。
    pub diagnostic_codes: Vec<String>,
}

/// `plan` 的结果。
#[derive(Debug, Clone)]
pub struct PlanInfo {
    /// 计划标识。
    pub id: String,
    /// 目标快照。
    pub target_snapshot: String,
    /// 生成计划时的后端 revision。
    pub base_revision: u64,
    /// 应用后 Ref 将前进到的 revision。
    pub next_revision: u64,
    /// 动作数量。
    pub action_count: usize,
    /// 是否被阻塞诊断拦下。
    pub blocked: bool,
    /// 动作明细（原始 JSON）。
    pub actions: Vec<Value>,
    /// 诊断码。
    pub diagnostic_codes: Vec<String>,
}

impl PlanInfo {
    /// 按资源标识查动作。
    pub fn action(&self, resource: &str) -> Option<&Value> {
        self.actions
            .iter()
            .find(|action| action["resource"] == resource)
    }
}

/// `sync` 的结果。
#[derive(Debug, Clone)]
pub struct SyncInfo {
    /// `no_op` 或 `completed`。
    pub outcome: String,
    /// 操作标识；`no_op` 时为 `None`。
    pub operation: Option<String>,
    /// 已应用动作数量。
    pub applied: usize,
    /// 是否发布了新引用。
    pub published: bool,
}

impl SyncInfo {
    /// 取操作标识，`no_op` 时直接失败。
    pub fn operation(&self) -> &str {
        self.operation
            .as_deref()
            .unwrap_or_else(|| panic!("本次 sync 是 {}，没有操作标识", self.outcome))
    }
}

// ---------------------------------------------------------------------------
// 通用小工具
// ---------------------------------------------------------------------------

/// 以任意参数运行二进制（不补 `--config`）。
pub fn run_binary(args: &[&str]) -> CliRun {
    run_binary_owned(args.iter().map(|item| (*item).to_owned()).collect())
}

fn run_binary_owned(argv: Vec<String>) -> CliRun {
    let output = Command::new(envsync_binary())
        .args(&argv)
        .output()
        .expect("应当能够启动 envsync 二进制");
    CliRun::from_output(argv, &output)
}

/// 路径转命令行参数。
pub fn arg(path: &Path) -> String {
    path.to_str().expect("测试路径应当是 UTF-8").to_owned()
}

/// 构造一个资源配置（根别名固定为 `home`，策略取默认值）。
pub fn resource(
    id: &str,
    target: &str,
    mode: FileMode,
    disposition: DesiredDisposition,
) -> ResourceConfig {
    ResourceConfig {
        id: ResourceId::parse(id).expect("资源标识应当合法"),
        root: "home".to_owned(),
        target: target.to_owned(),
        mode,
        disposition,
        policy: ResourcePolicy::default(),
        comment_prefix: "# ".to_owned(),
    }
}

/// 从 JSON 里取一个必然存在的字符串字段。
fn string_field(value: &Value, key: &str) -> String {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("字段 `{key}` 应当是字符串，实际是 {value}"))
        .to_owned()
}

/// 逐字节比较，并在失败时给出可读的差异说明。
///
/// 断言的是**完整字节**而不是「包含某子串」：Managed Block 的全部价值就在于块外的
/// 每一个字节都没被动过，子串匹配看不出这一点。
pub fn assert_bytes_eq(actual: &[u8], expected: &[u8], context: &str) {
    if actual == expected {
        return;
    }
    let first_diff = actual
        .iter()
        .zip(expected.iter())
        .position(|(left, right)| left != right)
        .unwrap_or_else(|| actual.len().min(expected.len()));
    panic!(
        "{context}：内容与期望不是逐字节相同（首个差异在第 {first_diff} 字节；\
         实际 {} 字节，期望 {} 字节）\n---- 实际 ----\n{}\n---- 期望 ----\n{}",
        actual.len(),
        expected.len(),
        String::from_utf8_lossy(actual),
        String::from_utf8_lossy(expected),
    );
}

/// 递归统计目录下的文件数量。
pub fn count_files(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut total = 0;
    for entry in entries.flatten() {
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => total += count_files(&entry.path()),
            Ok(_) => total += 1,
            Err(_) => {}
        }
    }
    total
}

/// 等待后端对象库里至少出现 `expected` 个对象。
///
/// 对象上传发生在 CAS 之前，因此「对象已到齐」意味着该进程已经完成重新计划、正卡在
/// 后端锁上等待发布——这正是制造 CAS 竞争所需要的时刻。
pub fn wait_for_objects(objects_dir: &Path, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if count_files(objects_dir) >= expected {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "等待后端对象超时：期望至少 {expected} 个，实际 {}",
        count_files(objects_dir)
    );
}

/// 占住某个工作区的后端锁，让所有 `sync` 都停在 CAS 之前。
///
/// 守卫被丢弃时释放锁。后端把超过 30 秒未更新的锁当成陈旧锁回收，因此持有时间必须
/// 远小于它。
#[derive(Debug)]
pub struct BackendLock {
    path: PathBuf,
}

impl BackendLock {
    /// 占住 `backend/locks/<workspace_id>.lock`。
    pub fn hold(backend: &Path, workspace_id: &str) -> Self {
        let path = backend.join("locks").join(format!("{workspace_id}.lock"));
        std::fs::create_dir_all(path.parent().expect("锁文件有父目录")).expect("应当能创建锁目录");
        let mut file = std::fs::File::create(&path).expect("应当能创建锁文件");
        file.write_all(b"held by e2e test\n")
            .expect("应当能写锁文件");
        BackendLock { path }
    }

    /// 提前释放锁。
    pub fn release(self) {
        drop(self);
    }
}

impl Drop for BackendLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
