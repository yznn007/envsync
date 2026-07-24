# EnvSync M3 包管理器与 Agent Bundle 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox
> (`- [ ]`) syntax for tracking.

**Goal:** 将跨平台包的期望状态、AI Agent/Skill/MCP 配置和安全策略纳入可计划、可审计、
可回滚的同步模型。

**Architecture:** Package Adapter 只观察和收敛声明式 package intent，不复制安装目录；
命令执行经 capability-scoped runner 和明确授权。Agent Bundle 是签名的主动内容，先进入
quarantine，经静态检查与用户策略批准后才投影到具体工具；Token 始终由 SecretRef 解析。

**Tech Stack:** Rust stable、Tokio、Serde、semver、spdx、regex-automata、cap-std、
ed25519-dalek、tempfile、insta。

---

## 前置门槛

- M2 Vault、SecretRef、membership、policy boundary 稳定。
- ApplyEngine 支持非文件 Action，但默认 deny 且有 receipt/verify。
- command runner 能捕获结构化 stdout/stderr，并统一 redaction。

## 文件结构

- `crates/envsync-domain/src/package.rs`：包身份、来源、版本策略和 intent。
- `crates/envsync-domain/src/agent_bundle.rs`：Bundle manifest、能力、签名和状态。
- `crates/envsync-policy/`：规则 AST、编译器、决策与解释。
- `crates/envsync-platform/src/command.rs`：能力约束命令执行。
- `crates/envsync-adapters/src/packages/`：各包管理器适配器。
- `crates/envsync-adapters/src/agents/`：统一 Agent 模型到具体工具的渲染器。
- `crates/envsync-core/src/packages.rs`：包计划与收敛。
- `crates/envsync-core/src/bundles.rs`：quarantine、审核、启用与撤销。

### Task 1: Package Intent domain model

**Files:**

- Create: `crates/envsync-domain/src/package.rs`
- Modify: `crates/envsync-domain/src/lib.rs`
- Test: `crates/envsync-domain/tests/package_intent.rs`

- [ ] **Step 1: 写 package identity 测试**

identity 由 manager、normalized name、source/channel 构成；大小写规则由 manager 决定。
`brew:Ripgrep` 与 `brew:ripgrep` 相同，Cargo crate 名按 crates.io 规则规范化，不同 tap
或 bucket 的同名包不同。

- [ ] **Step 2: 运行失败测试**

Run: `cargo test -p envsync-domain --test package_intent`
Expected: FAIL，`PackageIntent` 未定义。

- [ ] **Step 3: 实现版本策略**

```rust
pub enum VersionPolicy {
    Present,
    Exact(String),
    Compatible(VersionReq),
    Latest,
}
```

`PackageDisposition` 为 `Managed`、`EnsureAbsent`、`Unmanaged`。默认 Managed + Present；
观察缺失只生成 install，观察额外包不生成 uninstall。

- [ ] **Step 4: 写确定性 State Root 测试**

同一 intent 乱序输入产生相同摘要；重复 identity 且策略不同必须报配置冲突。

- [ ] **Step 5: 验证并提交**

```bash
cargo test -p envsync-domain --test package_intent
git commit -am "feat(domain): 添加包期望状态模型"
```

### Task 2: Capability-scoped Command Runner

**Files:**

- Create: `crates/envsync-platform/src/command.rs`
- Test: `crates/envsync-platform/tests/command_runner.rs`

- [ ] **Step 1: 写 allowlist 测试**

只允许注册过的 executable identity 与参数模板；拒绝 shell 字符串、相对 executable、
额外参数、未声明 cwd/env、stdin 继承和无限输出。

- [ ] **Step 2: 实现 CommandSpec**

`CommandSpec` 分开保存 executable、argv、cwd capability、env allowlist、timeout、
stdout/stderr limits。始终使用 `Command::new(...).args(...)`，不调用 shell。

- [ ] **Step 3: 写取消与 redaction 测试**

timeout 后终止进程树；输出超过 4 MiB 时停止并诊断。Vault 注入的 env 值在捕获输出和日志
中被 canary redactor 清除。

- [ ] **Step 4: 添加 receipt**

receipt 记录 adapter、命令模板 ID、退出码、开始/结束时间和脱敏摘要，不记录 secret env
value 或完整包管理器输出。

- [ ] **Step 5: 验证并提交**

```bash
cargo test -p envsync-platform --test command_runner
git commit -am "feat(platform): 添加受限命令执行器"
```

### Task 3: Package Adapter contract 与 fake manager

**Files:**

- Create: `crates/envsync-adapters/src/packages/mod.rs`
- Create: `crates/envsync-adapters/src/packages/fake.rs`
- Test: `crates/envsync-adapters/tests/package_contract.rs`
- Test: `crates/envsync-core/tests/package_planner.rs`

- [ ] **Step 1: 定义 contract**

```rust
pub trait PackageAdapter {
    fn descriptor(&self) -> &PackageManagerDescriptor;
    async fn observe(&self, ctx: &ObserveContext) -> Result<PackageObservationSet, AdapterError>;
    fn plan(&self, desired: &[PackageIntent], observed: &PackageObservationSet)
        -> Result<Vec<PackageAction>, AdapterError>;
    async fn apply(&self, action: &PackageAction, ctx: &ApplyContext)
        -> Result<PackageReceipt, AdapterError>;
    async fn verify(&self, action: &PackageAction, ctx: &ObserveContext)
        -> Result<VerifyResult, AdapterError>;
}
```

- [ ] **Step 2: 用 fake manager 写 red-green tests**

覆盖 install、upgrade、already satisfied、unsupported version、显式 uninstall、partial
failure、verify drift 和 rollback capability `None/Compensating/Exact`。

- [ ] **Step 3: 实现 planner 安全规则**

system package、uninstall、downgrade 和 source change 风险为 High，要求 policy allow 与
显式确认。`--yes` 只接受已保存 Plan ID，不能跳过 policy。

- [ ] **Step 4: 验证并提交**

```bash
cargo test -p envsync-adapters --test package_contract
cargo test -p envsync-core --test package_planner
git commit -am "feat(packages): 建立包适配器契约"
```

### Task 4: Homebrew 与 Scoop

**Files:**

- Create: `crates/envsync-adapters/src/packages/homebrew.rs`
- Create: `crates/envsync-adapters/src/packages/scoop.rs`
- Test: `crates/envsync-adapters/tests/homebrew.rs`
- Test: `crates/envsync-adapters/tests/scoop.rs`

- [ ] **Step 1: Homebrew fixture tests**

解析 `brew bundle dump` 等价数据：formula、cask、tap。忽略依赖自动安装项；保留用户显式
包。生成命令逐 action，不直接执行不透明 Brewfile。

- [ ] **Step 2: Scoop fixture tests**

解析 bucket、app、version 和 persist metadata；bucket URL 是 source identity。安装目录
只作为观察元数据，不捕获其中二进制。

- [ ] **Step 3: 实现能力探测与命令模板**

只接受由 capability discovery 得到的绝对 executable。Homebrew 不以 root 运行；Scoop
默认当前用户 scope。无法满足版本策略时阻塞而非静默安装其他版本。

- [ ] **Step 4: 验证并提交**

```bash
cargo test -p envsync-adapters --test homebrew
cargo test -p envsync-adapters --test scoop
git commit -am "feat(packages): 添加 Homebrew 与 Scoop"
```

### Task 5: Winget、Chocolatey 与系统包

**Files:**

- Create: `crates/envsync-adapters/src/packages/winget.rs`
- Create: `crates/envsync-adapters/src/packages/chocolatey.rs`
- Create: `crates/envsync-adapters/src/packages/system.rs`
- Test: `crates/envsync-adapters/tests/system_packages.rs`

- [ ] **Step 1: Windows manager 测试**

Winget identity 包含 source；处理 agreement 参数但不自动同意未知协议。Chocolatey
system scope 标记 elevation requirement。

- [ ] **Step 2: Linux system manager 只读/显式写测试**

APT、DNF、Pacman 观察显式安装包；默认 policy 禁止 apply。允许时每个命令显示 exact argv
并通过平台 elevation broker，不从环境继承 `sudo` 配置。

- [ ] **Step 3: 实现 manager-specific parser**

parser 使用固定 locale/env，解析结构化或稳定机器输出。命令版本不兼容时返回
`UnsupportedManagerVersion`，不能基于人类输出猜测。

- [ ] **Step 4: 验证并提交**

```bash
cargo test -p envsync-adapters --test system_packages
git commit -am "feat(packages): 添加 Windows 与 Linux 系统包适配器"
```

### Task 6: 开发者工具包管理器

**Files:**

- Create: `crates/envsync-adapters/src/packages/cargo.rs`
- Create: `crates/envsync-adapters/src/packages/node.rs`
- Create: `crates/envsync-adapters/src/packages/python.rs`
- Test: `crates/envsync-adapters/tests/developer_packages.rs`

- [ ] **Step 1: Cargo tests**

观察 `cargo install --list` 等价 fixture；记录 crate、version、source。Git source pin 到 commit
时为 Exact；branch 不视为可复现 Exact。

- [ ] **Step 2: Node tests**

npm 与 pnpm 分开 identity；只管理显式 global package。corepack manager/version 作为独立
资源，不改写项目局部依赖。

- [ ] **Step 3: Python tests**

支持 pipx 与 uv tools；不捕获任意 global pip environment。记录 interpreter constraint
和 injected packages。

- [ ] **Step 4: 实现并验证**

```bash
cargo test -p envsync-adapters --test developer_packages
git commit -am "feat(packages): 添加开发者工具适配器"
```

### Task 7: Policy Engine

**Files:**

- Create: `crates/envsync-policy/Cargo.toml`
- Modify: `Cargo.toml`
- Create: `crates/envsync-policy/src/lib.rs`
- Create: `crates/envsync-policy/src/ast.rs`
- Create: `crates/envsync-policy/src/evaluate.rs`
- Test: `crates/envsync-policy/tests/policy.rs`

- [ ] **Step 1: 写 deny-first 测试**

decision 为 `Allow`、`Deny`、`RequireConfirmation`。任一匹配 Deny 优先；无匹配默认 Deny
用于命令/Bundle capability，普通文件延续现有默认。

- [ ] **Step 2: 定义版本化规则**

规则可匹配 resource kind、adapter、operation、risk、OS、profile tag、source signer、
capability。AST 不允许循环、正则回溯或动态代码。

- [ ] **Step 3: 实现 explain**

每个 decision 返回匹配 rule ID、来源文件、优先级和输入事实摘要。解释中 SecretRef 仅显示
opaque ID。

- [ ] **Step 4: 加入资源限制/property tests**

规则上限 10,000、AST 深度 32；任意输入不得 panic。相同规则乱序后按显式 priority/ID
排序得到相同 decision。

- [ ] **Step 5: 验证并提交**

```bash
cargo test -p envsync-policy
git commit -am "feat(policy): 添加可解释安全策略引擎"
```

### Task 8: Agent Bundle domain、签名与 quarantine

**Files:**

- Create: `crates/envsync-domain/src/agent_bundle.rs`
- Create: `crates/envsync-core/src/bundles.rs`
- Create: `crates/envsync-storage/migrations/0005_bundles.sql`
- Test: `crates/envsync-core/tests/bundle_quarantine.rs`

- [ ] **Step 1: 写 manifest 测试**

manifest 包含 bundle ID/version、publisher key、files 摘要、entrypoints、declared
capabilities、SecretRef、目标工具和最低 EnvSync 版本。拒绝路径穿越、symlink、重复路径、
未声明文件和总大小超过 10 MiB。

- [ ] **Step 2: 写签名测试**

签名覆盖 canonical manifest 和所有 file digest。任一文件变化、未知 signer 或撤销 signer
都进入 blocked 状态。

- [ ] **Step 3: 实现 quarantine 状态机**

`downloaded -> inspected -> approved -> enabled`；任一状态可 `blocked/revoked`。下载后内容
只放不可执行 quarantine 根，权限去除 execute bit，不跟随链接。

- [ ] **Step 4: policy 审核**

批准绑定 bundle digest、capability set、目标 Profile 和 signer；Bundle 更新后必须重新
审核新增 capability。

- [ ] **Step 5: 验证并提交**

```bash
cargo test -p envsync-core --test bundle_quarantine
git commit -am "feat(agents): 添加签名 Bundle 隔离流程"
```

### Task 9: 统一 Agent/Skill 模型与工具渲染

**Files:**

- Create: `crates/envsync-adapters/src/agents/mod.rs`
- Create: `crates/envsync-adapters/src/agents/codex.rs`
- Create: `crates/envsync-adapters/src/agents/claude.rs`
- Create: `crates/envsync-adapters/src/agents/opencode.rs`
- Test: `crates/envsync-adapters/tests/agent_renderers.rs`

- [ ] **Step 1: 定义统一模型**

`AgentDefinition`、`SkillDefinition`、`McpServerDefinition`、`PermissionTemplate`。
Secret 字段只能是 SecretRef。unsupported 字段产生 loss report，不能静默丢失。

- [ ] **Step 2: Codex renderer tests**

测试 Agent、Skill、规则和 MCP 配置的稳定路径、managed block/full file 策略、SecretRef
运行时注入以及不覆盖本地未管理内容。

- [ ] **Step 3: Claude/OpenCode renderer tests**

同一统一模型渲染到各工具 fixture；重新 capture 得到等价统一模型。工具不支持的 capability
使计划阻塞或要求用户接受明确 loss policy。

- [ ] **Step 4: 实现 renderer 与 verify**

renderer 只生成文件和 Secret injection descriptor，不启动 MCP server。verify 重新解析
目标工具配置并对比语义摘要。

- [ ] **Step 5: 验证并提交**

```bash
cargo test -p envsync-adapters --test agent_renderers
git commit -am "feat(agents): 渲染 Codex Claude 与 OpenCode 配置"
```

### Task 10: CLI、E2E、文档与 CI

**Files:**

- Modify: `crates/envsync-cli/src/main.rs`
- Test: `crates/envsync-cli/tests/m3_cli.rs`
- Create: `tests/e2e/packages_and_bundles.rs`
- Create: `docs/packages.md`
- Create: `docs/agents-and-skills.md`
- Create: `docs/policy.md`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: 新增命令**

`packages capture/plan/apply`、`bundles inspect/approve/enable/revoke`、
`policy check/explain`。包 apply 和 Bundle enable 必须接收已保存 Plan ID。

- [ ] **Step 2: Fake manager E2E**

CI 默认使用 fake executable 测试完整事务、失败注入和回滚；平台专属 job 在可用环境运行
只读 discovery，不修改 runner 系统。

- [ ] **Step 3: Bundle 攻击 E2E**

覆盖路径穿越、篡改签名、秘密内嵌、未声明 capability、更新后 capability 扩张、撤销 signer
和 quarantine 文件不可执行。

- [ ] **Step 4: 文档**

列出各 manager 支持矩阵、rollback guarantee、elevation 风险、Bundle 信任仪式、Token 注入
和完整 policy 示例。

- [ ] **Step 5: 完整验证与提交**

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --doc
git add crates tests docs .github
git commit -m "test: 完成 M3 包与 Agent Bundle 验收"
```

## M3 完成定义

- 包同步只管理显式 intent，不复制安装目录或隐式依赖。
- uninstall、downgrade、system elevation 默认被 policy 阻止。
- Agent Bundle 在签名、静态检查、policy 批准前不可启用。
- Token 只通过 SecretRef 和 Vault 注入，不进入 Bundle、Snapshot 或日志。
- 包与 Agent 操作具有 Plan、journal、receipt、verify 和准确的回滚能力说明。
