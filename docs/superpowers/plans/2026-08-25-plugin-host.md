# Plugin Host Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付默认拒绝、签名绑定入口制品、独立进程运行并经 Host 重新授权的插件 Host。

**Architecture:** `envsync-plugin-api` 先把单入口 BLAKE3 摘要并入已签名 manifest；`envsync-plugin-host` 将入口文件写入不可执行 quarantine，只有通过 publisher、policy 与 approval 后才复制到 runtime。Unix runner 使用 process group 和 `RLIMIT_AS`；没有实际 OS sandbox 的生产 Host 保持不可运行，test-only launcher 只为隔离测试提供受控执行路径。

**Tech Stack:** Rust stable 1.82、envsync-plugin-api/core/crypto/policy/platform、BLAKE3、serde_json、nix（Unix 的安全 process-group/rlimit API）、tempfile。

---

## 文件结构

- `crates/envsync-plugin-api/src/manifest.rs`：新增被签名的单入口摘要值对象。
- `crates/envsync-plugin-api/tests/compatibility.rs`：摘要编码、长度和签名 payload golden。
- `crates/envsync-plugin-host/src/quarantine.rs`：制品验签、无执行位 staging、审批、审计和撤销。
- `crates/envsync-plugin-host/src/process.rs`：runner 启动、帧会话、总输出/timeout、进程组清理。
- `crates/envsync-plugin-host/src/capability.rs`：proposal 的根、路径和命令再校验。
- `crates/envsync-plugin-host/src/lib.rs`：窄公开 API、稳定错误码和模块 re-export。
- `crates/envsync-plugin-host/src/bin/envsync-plugin-runner.rs`：Unix rlimit + exec helper。
- `crates/envsync-plugin-host/tests/isolation.rs`：真实恶意子进程的集成验收。

### Task 1: 将入口制品摘要纳入已签名 manifest

**Files:**

- Modify: `Cargo.toml`
- Modify: `crates/envsync-plugin-api/Cargo.toml`
- Modify: `crates/envsync-plugin-api/src/manifest.rs`
- Modify: `crates/envsync-plugin-api/src/lib.rs`
- Modify: `crates/envsync-plugin-api/tests/compatibility.rs`

- [ ] **Step 1: 写失败测试**

给 `valid_manifest_json()` 加入合法 `entrypoint_digest`，并断言缺失、42/44 字符、43 字符但非法 base64url 分别被拒绝：

```rust
let mut missing = valid_manifest_json();
missing.as_object_mut().expect("object").remove("entrypoint_digest");
assert_error_code(missing, "plugin.manifest.invalid_manifest");

let mut malformed = valid_manifest_json();
malformed["entrypoint_digest"] = serde_json::json!("!".repeat(43));
assert_error_code(malformed, "plugin.manifest.invalid_artifact_digest");
```

再断言完整 `signing_payload()` 原始字节包含该字段，改变任意摘要字节会改变 payload。

- [ ] **Step 2: 验证红灯**

Run: `cargo test -p envsync-plugin-api --test compatibility manifest_`

Expected: FAIL，因为 API 尚无 `entrypoint_digest`。

- [ ] **Step 3: 实现最小值对象**

在私有 `RawManifest`、`PluginManifest` 和 `UnsignedManifest` 加入字段，定义并 re-export：

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginArtifactDigest([u8; 32]);

impl PluginArtifactDigest {
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}
```

专用解码器必须先检查无填充 base64url 的 43 字符长度，再解码为恰好 32 字节；失败使用新稳定码 `plugin.manifest.invalid_artifact_digest`。不得在 API crate 内计算 BLAKE3，也不得改变既有 targets/capabilities 的 v1 签名数组顺序。

- [ ] **Step 4: 验证并提交**

Run: `cargo fmt --all --check && cargo test -p envsync-plugin-api && cargo clippy -p envsync-plugin-api --all-targets -- -D warnings`

Expected: PASS。

```bash
git add Cargo.toml Cargo.lock crates/envsync-plugin-api
git commit -m "feat(plugins): 签名绑定入口制品摘要"
```

### Task 2: 建立 quarantine、验签、审批与撤销状态机

**Files:**

- Create: `crates/envsync-plugin-host/Cargo.toml`
- Modify: `Cargo.toml`
- Create: `crates/envsync-plugin-host/src/lib.rs`
- Create: `crates/envsync-plugin-host/src/quarantine.rs`
- Test: `crates/envsync-plugin-host/tests/isolation.rs`

- [ ] **Step 1: 写 lifecycle 红灯测试**

用 `DeviceKeypair` 对 manifest payload 签名，入口字节的 BLAKE3 摘要写入 manifest。覆盖未知 signer、篡改入口、quarantine 无 execute bit、内容/能力扩张重审、撤销后 retained audit：

```rust
assert_eq!(record.state(), PluginState::Quarantined);
assert_eq!(mode(&staged_entry) & 0o111, 0);
assert_eq!(host.revoke_publisher(key, NOW).affected(), 1);
assert_eq!(host.record(id).expect("record").state(), PluginState::Revoked);
```

- [ ] **Step 2: 验证红灯**

Run: `cargo test -p envsync-plugin-host --test isolation quarantine`

Expected: FAIL，因为 Host crate 尚不存在。

- [ ] **Step 3: 实现 trust 和 staging**

`PluginArtifact` 只拥有 `PluginManifest` 和入口字节；先以 `blake3::hash` 比对 `entrypoint_digest`，再通过 `envsync_crypto::device::verify`、`PublisherRegistry`、`publisher_namespace()` 和 domain `envsync-plugin` 验签。quarantine 路径逐段 no-follow，文件用 `create_new` 写入并去除 execute bit；错误不含绝对路径或原始 bytes。

定义 `PluginApproval`（id、manifest digest、artifact digest、capabilities、profile、signer）和 append-only `PluginAuditEvent`。`approve`/`enable` 以 `ResourceKind::Plugin`、`Operation::Enable`、`Risk::High` 和 profile/signer/capability 事实执行 policy。未确认、policy deny 或不可信 signer 均不创建 runtime copy；`revoke_publisher` 永远可降级且保留审计。

- [ ] **Step 4: 验证并提交**

Run: `cargo fmt --all --check && cargo test -p envsync-plugin-host --test isolation quarantine && cargo clippy -p envsync-plugin-host --all-targets -- -D warnings`

Expected: PASS。

```bash
git add Cargo.toml Cargo.lock crates/envsync-plugin-host
git commit -m "feat(plugins): 添加签名 quarantine 状态机"
```

### Task 3: 实现受限 runner、资源配额和进程树清理

**Files:**

- Modify: `Cargo.toml`
- Modify: `crates/envsync-plugin-host/Cargo.toml`
- Create: `crates/envsync-plugin-host/src/process.rs`
- Create: `crates/envsync-plugin-host/src/bin/envsync-plugin-runner.rs`
- Modify: `crates/envsync-plugin-host/src/lib.rs`
- Modify: `crates/envsync-plugin-host/tests/isolation.rs`

- [ ] **Step 1: 写恶意进程红灯测试**

fixture 模式包含 `loop`、`flood-stderr`、`crash`、`bad-frame`、`wrong-id`、`ignore-shutdown`。父测试设置 `ENVSYNC_PLUGIN_SECRET_CANARY`，并断言子进程看不到它、cwd 为空、timeout/输出/shutdown 返回稳定错误且整组进程已结束。

```rust
assert_eq!(host.call(&mut session, request).expect_err("timeout").code(), "plugin.host.timeout");
assert_eq!(host.shutdown(session).expect_err("must stop").code(), "plugin.host.shutdown_timeout");
assert!(!stderr.contains("ENVSYNC_PLUGIN_SECRET_CANARY"));
```

- [ ] **Step 2: 验证红灯**

Run: `cargo test -p envsync-plugin-host --test isolation process`

Expected: FAIL，因为尚无 runner/session。

- [ ] **Step 3: 实现 runner 和 session**

Unix runner 只接受 `--memory-bytes <u64> -- <absolute-entrypoint>`，拒绝任何其他 argv；使用安全 nix API 设置 `RLIMIT_AS`、建立自身 process group，再 `exec` 精确入口。Host 以 `Command::new(runner)` 启动，`env_clear()` 后只设置协议标记，设置空 `TempDir` cwd，管道化 stdio；不经过 shell、不转发环境、不接受 plugin argv。

`PluginSession::call` 必须 `write_frame`，在 manifest runtime deadline 内读取同 ID response。一个原子总输出计数同时约束 stdout/stderr，超过 manifest output limit 前拒绝继续分配并 kill process group。Unix 用 `nix::sys::signal::kill(Pid::from_raw(-pgid), SIGKILL)` 后 wait；非 Unix 和普通生产 Host 返回 `plugin.host.sandbox_unavailable`，不得降级为直接执行。

`test-support` feature 只导出 `PluginHost::for_test_runner`；用自引用 dev-dependency 自动为 integration tests 启用，而普通 `cargo build` 没有此入口。

- [ ] **Step 4: 验证并提交**

Run: `cargo fmt --all --check && cargo test -p envsync-plugin-host --test isolation process && cargo clippy -p envsync-plugin-host --all-targets -- -D warnings`

Expected: PASS。

```bash
git add Cargo.toml Cargo.lock crates/envsync-plugin-host
git commit -m "feat(plugins): 添加受限插件 runner"
```

### Task 4: 实现 Host-mediated proposal 验证

**Files:**

- Create: `crates/envsync-plugin-host/src/capability.rs`
- Modify: `crates/envsync-plugin-host/src/lib.rs`
- Modify: `crates/envsync-plugin-host/tests/isolation.rs`

- [ ] **Step 1: 写 capability 红灯测试**

对 `../../secret`、`/etc/passwd`、未注册 root、未知 command template、shell 元字符、NUL argv 和合法 observe/render/verify proposal 分别断言非法值在 Host 边界失败，合法值只形成 `ValidatedProposal`。

```rust
assert_eq!(mediator.validate(PluginMethod::Observe, proposal).expect_err("unsafe").code(),
           "plugin.host.invalid_target");
assert!(matches!(validated, ValidatedProposal::Observation { .. }));
```

- [ ] **Step 2: 验证红灯**

Run: `cargo test -p envsync-plugin-host --test isolation capability`

Expected: FAIL，因为 mediator 尚不存在。

- [ ] **Step 3: 实现闭合 proposal schema**

用 `serde_json::Value` 填充私有 raw structs；`RootRegistry::get` 验证 opaque root alias，`RelativeTarget::parse` 验证相对目标。命令 proposal 只能引用 Host 的 `CommandProposalCatalog`，argv 最多 64 项、每项最多 4096 bytes，且不能含 NUL、控制字符或 shell 元字符。`ValidatedProposal` 不含绝对路径和秘密值；crate 不提供直接文件/命令/Vault 操作。

- [ ] **Step 4: 验证并提交**

Run: `cargo fmt --all --check && cargo test -p envsync-plugin-host --test isolation capability && cargo clippy -p envsync-plugin-host --all-targets -- -D warnings`

Expected: PASS。

```bash
git add crates/envsync-plugin-host
git commit -m "feat(plugins): 代理插件 capability proposal"
```

### Task 5: 完成隔离验收与文档同步

**Files:**

- Modify: `crates/envsync-plugin-host/tests/isolation.rs`
- Modify: `docs/superpowers/specs/2026-08-25-plugin-host-design.md`
- Modify: `docs/superpowers/plans/2026-07-24-envsync-m4-desktop-gist-plugins.md`

- [ ] **Step 1: 运行完整恶意 fixture 矩阵**

Run: `cargo test -p envsync-plugin-host --test isolation`

Expected: loop、输出洪泛、崩溃、协议欺骗、未授权路径、未知命令、环境泄漏和 shutdown 逃逸均有独立 PASS 断言；没有测试通过忽略错误或只检查 helper 自己。

- [ ] **Step 2: 运行关联验证**

Run: `cargo fmt --all --check && cargo test -p envsync-plugin-api && cargo test -p envsync-plugin-host && cargo clippy -p envsync-plugin-api -p envsync-plugin-host --all-targets -- -D warnings && git diff --check`

Expected: PASS。

- [ ] **Step 3: 标记 M4 Task 10 并提交**

将原 M4 计划 Task 10 的五个步骤标为完成，并记录普通构建默认拒绝与 test-only feature 的边界。

```bash
git add docs crates/envsync-plugin-api crates/envsync-plugin-host Cargo.toml Cargo.lock
git commit -m "test(plugins): 覆盖 Host 隔离边界"
```
