# EnvSync M1 Git、Profile 与合并实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox
> (`- [ ]`) syntax for tracking.

**Goal:** 在 M0 安全文件闭环之上加入 Git Backend、设备 Profile 投影、三方合并、
冲突对象和首批 Git/shell/终端适配器。

**Architecture:** Workspace Snapshot 仍是唯一完整期望状态；Profile Engine 在计划阶段
生成设备投影。Git Backend 将内容寻址对象映射到普通 Git tree，并使用远端 branch
head 作为 CAS；Merge Engine 只生成合并结果或显式 Conflict，不直接写本地文件。

**Tech Stack:** Rust stable、git2、Serde、minicbor、gix-config、toml_edit、
serde_json、similar、proptest、insta。

---

## 前置门槛

- M0 全部验收测试通过。
- M0 持久化 schema 和 CLI JSON schema 有迁移测试。
- Backend、Planner、Observer、ApplyEngine trait 已公开且有 rustdoc。

## 文件结构

- `crates/envsync-domain/src/profile.rs`：Profile、selector、capability 和投影诊断。
- `crates/envsync-domain/src/conflict.rs`：Conflict 对象及可选 resolution。
- `crates/envsync-backend/src/git.rs`：Git 对象映射、fetch、push 和 CAS。
- `crates/envsync-core/src/projection.rs`：Workspace 到 DeviceView 的纯函数投影。
- `crates/envsync-core/src/merge/`：文本、JSON、TOML 和 Git config 三方合并。
- `crates/envsync-adapters/`：适配器 trait、注册表及内建适配器。
- `crates/envsync-core/src/sync.rs`：fetch、merge、plan 的应用服务编排。

### Task 1: 建立 M1 domain schema 与迁移

**Files:**

- Create: `crates/envsync-domain/src/profile.rs`
- Create: `crates/envsync-domain/src/conflict.rs`
- Modify: `crates/envsync-domain/src/lib.rs`
- Create: `crates/envsync-domain/tests/m1_schema.rs`
- Create: `crates/envsync-storage/migrations/0002_profiles_conflicts.sql`
- Test: `crates/envsync-storage/tests/m1_migration.rs`

- [ ] **Step 1: 写 Profile schema 失败测试**

```rust
#[test]
fn selector_requires_all_declared_constraints() {
    let profile = DeviceProfile::new(Os::Windows, Arch::X86_64)
        .with_tag("work")
        .with_capability("pwsh");
    let selector = Selector::all([
        Predicate::Os(Os::Windows),
        Predicate::Tag("work".into()),
        Predicate::Capability("pwsh".into()),
    ]);
    assert!(selector.matches(&profile));
    assert!(!selector.matches(&DeviceProfile::new(Os::Linux, Arch::X86_64)));
}
```

- [ ] **Step 2: 运行测试并确认缺少类型**

Run: `cargo test -p envsync-domain --test m1_schema`
Expected: FAIL，编译器报告 `DeviceProfile`、`Selector` 未定义。

- [ ] **Step 3: 实现封闭 selector AST**

实现 `Os`、`Arch`、`DeviceProfile`、`Predicate`、`Selector::{All,Any,Not}`。字符串值在
构造时 trim、拒绝空值；递归深度上限 16，节点上限 256，防止恶意配置造成资源耗尽。

- [ ] **Step 4: 写 Conflict 与 migration 测试**

测试 Conflict 必须包含 resource、base/ours/theirs 摘要、kind、diagnostics；resolution
只能引用已存在 Blob。migration 从 M0 数据库升级后保留 operation 数据，并能回滚事务。

- [ ] **Step 5: 实现 schema 与 migration**

新增 `profiles`、`conflicts` 表；Conflict 对象以 canonical CBOR 内容寻址，数据库只保存
索引和状态。

- [ ] **Step 6: 验证并提交**

```bash
cargo test -p envsync-domain --test m1_schema
cargo test -p envsync-storage --test m1_migration
git add crates/envsync-domain crates/envsync-storage
git commit -m "feat(domain): 添加 Profile 与冲突模型"
```

### Task 2: 实现纯函数 Profile Projection

**Files:**

- Create: `crates/envsync-core/src/projection.rs`
- Modify: `crates/envsync-core/src/lib.rs`
- Test: `crates/envsync-core/tests/projection.rs`

- [ ] **Step 1: 写投影规则测试**

覆盖 selector 命中、未命中、priority、设备 override、能力缺失和策略 deny。相同输入乱序
后输出 ResourceEntry 顺序和 DeviceView ID 必须相同。

- [ ] **Step 2: 运行目标测试**

Run: `cargo test -p envsync-core --test projection`
Expected: FAIL，编译器报告 `project_workspace` 未定义。

- [ ] **Step 3: 实现投影 API**

```rust
pub fn project_workspace(
    state: &StateRoot,
    profile: &DeviceProfile,
    policy: &ProjectionPolicy,
) -> Result<DeviceView, ProjectionError>;
```

优先级固定为：全局资源 < selector override < device-id override < 安全 policy。能力缺失
生成 `Unsupported` 诊断；它不能生成 tombstone。

- [ ] **Step 4: 添加 property tests**

验证确定性、幂等性和“投影不会新增 Workspace 中不存在的 ResourceId”。

- [ ] **Step 5: 验证并提交**

```bash
cargo test -p envsync-core --test projection
git commit -am "feat(core): 添加设备 Profile 投影"
```

### Task 3: Git Backend 对象布局与本地 round trip

**Files:**

- Create: `crates/envsync-backend/src/git.rs`
- Modify: `crates/envsync-backend/src/lib.rs`
- Test: `crates/envsync-backend/tests/git_backend.rs`

**Git tree：**

```text
.envsync/
  format
  objects/ab/cdef...
  refs/<workspace-id>.cbor
```

- [ ] **Step 1: 写 bare repository round-trip 测试**

临时 bare remote 上执行 put/get object、读空 Ref、首次 CAS、错误 revision 冲突、重新打开后
读取相同 Snapshot。

- [ ] **Step 2: 运行测试**

Run: `cargo test -p envsync-backend --test git_backend`
Expected: FAIL，`GitBackend` 未定义。

- [ ] **Step 3: 实现本地 Git 映射**

`GitBackend::open` 创建私有 cache clone。每次写入从受信 remote branch fetch，在临时
index 构造新 tree 和 commit；commit message 只含 workspace、revision、Snapshot ID。
对象内容与 Local Backend 完全相同。

- [ ] **Step 4: 加入损坏与边界测试**

拒绝目录穿越 tree path、错误内容摘要、非 fast-forward ref 和非 canonical Ref。

- [ ] **Step 5: 验证并提交**

```bash
cargo test -p envsync-backend --test git_backend
git commit -am "feat(backend): 添加 Git 对象后端"
```

### Task 4: Git Remote CAS 与认证隔离

**Files:**

- Create: `crates/envsync-backend/src/git_auth.rs`
- Test: `crates/envsync-backend/tests/git_cas.rs`
- Modify: `crates/envsync-core/src/config.rs`

- [ ] **Step 1: 写并发 push 测试**

两个 clone 从同一 revision 发布不同 Snapshot，断言只有一个成功；失败方返回 observed
remote revision，且不自动 force push。

- [ ] **Step 2: 写认证配置测试**

配置只允许 `ssh-agent`、`credential-helper`、`token-secret-ref`；URL 中含 password/token
时拒绝。诊断和 tracing 不得输出 credential。

- [ ] **Step 3: 实现 fetch-compare-push**

push 使用 `<local-oid>:refs/heads/<configured-branch>` 加 expected old OID lease。远端
不支持 lease 时使用临时 ref + 原子 ref transaction；两者都不支持则报告 capability
错误，不能弱化为最后写入获胜。

- [ ] **Step 4: 验证并提交**

```bash
cargo test -p envsync-backend --test git_cas
git commit -am "feat(backend): 实现 Git 远端 CAS"
```

### Task 5: 文本三方合并与 Conflict

**Files:**

- Create: `crates/envsync-core/src/merge/mod.rs`
- Create: `crates/envsync-core/src/merge/text.rs`
- Test: `crates/envsync-core/tests/text_merge.rs`

- [ ] **Step 1: 写 base/ours/theirs 表格测试**

覆盖只改 ours、只改 theirs、两边相同修改、互不相交修改、同一行冲突、删除/修改冲突、
二进制内容和换行符差异。

- [ ] **Step 2: 运行测试**

Run: `cargo test -p envsync-core --test text_merge`
Expected: FAIL，`merge_text` 未定义。

- [ ] **Step 3: 实现结果类型**

```rust
pub enum MergeResult {
    Clean { blob: Blob, provenance: MergeProvenance },
    Conflict(Conflict),
}
```

二进制和超过 4 MiB 的文件不做行合并；若双方都改动则直接 Conflict。冲突 marker 不写入
用户文件，只存 Conflict 对象。

- [ ] **Step 4: property test 与提交**

验证 `merge(base, x, x) == x`、只改一侧必为 clean，随后：

```bash
cargo test -p envsync-core --test text_merge
git commit -am "feat(core): 添加文本三方合并"
```

### Task 6: JSON、YAML、TOML、INI 与 Git config 语义合并

**Files:**

- Create: `crates/envsync-core/src/merge/json.rs`
- Create: `crates/envsync-core/src/merge/yaml.rs`
- Create: `crates/envsync-core/src/merge/toml.rs`
- Create: `crates/envsync-core/src/merge/ini.rs`
- Create: `crates/envsync-core/src/merge/git_config.rs`
- Test: `crates/envsync-core/tests/structured_merge.rs`

- [ ] **Step 1: 写 JSON 测试**

对象按 key 递归三方合并；array 默认原子值。`null` 是值，不代表删除。键删除与另一侧修改
形成 Conflict，并记录 JSON Pointer。

- [ ] **Step 2: 写 TOML 测试**

保留注释和格式；table key 可独立合并，array 原子处理；重复 key 和无效 TOML 产生解析诊断。

- [ ] **Step 3: 写 YAML 与 INI 测试**

YAML 只接受单文档安全数据模型，拒绝自定义 tag、alias cycle 和重复 key；mapping 递归合并，
sequence 原子处理。INI identity 为 section/key，重复 key 按显式 multi-value policy
处理；保留注释、节顺序和原换行风格。

- [ ] **Step 4: 写 Git config 测试**

key identity 为 section/subsection/name；多值键保留顺序，单值键独立合并；`include.path`
按规范化路径识别但不读取 include 目标。

- [ ] **Step 5: 实现五个合并器和统一限制**

最大解析深度 64、节点 100,000、输入 4 MiB。结构化渲染后重新解析并校验语义，再生成 Blob。

- [ ] **Step 6: 验证并提交**

```bash
cargo test -p envsync-core --test structured_merge
git commit -am "feat(core): 添加结构化三方合并"
```

### Task 7: 内建适配器框架与首批适配器

**Files:**

- Create: `crates/envsync-adapters/Cargo.toml`
- Modify: `Cargo.toml`
- Create: `crates/envsync-adapters/src/lib.rs`
- Create: `crates/envsync-adapters/src/file.rs`
- Create: `crates/envsync-adapters/src/git_config.rs`
- Create: `crates/envsync-adapters/src/shell.rs`
- Create: `crates/envsync-adapters/src/wezterm.rs`
- Test: `crates/envsync-adapters/tests/builtin.rs`

- [ ] **Step 1: 写 adapter contract tests**

每个 adapter 声明 stable ID、版本、支持平台、所需 capability、discover/capture/render/verify。
同一输入 capture 和 render 必须确定性。

- [ ] **Step 2: 实现 sealed trait 与注册表**

M1 只允许编译期内建 adapter；注册表拒绝重复 ID。adapter 不能直接获得 Backend、Journal
或全局 filesystem，只接收 scoped context。

- [ ] **Step 3: 实现资源**

加入 Bash/Zsh RC managed block、PowerShell Profile、WezTerm Lua full-file/generated
include、用户级 Git config structured merge。系统级 Git config 只观察，不写入。

- [ ] **Step 4: fixture matrix**

为 macOS/Linux/Windows 路径、LF/CRLF、非 ASCII 用户名、文件不存在和权限不足添加 fixture。

- [ ] **Step 5: 验证并提交**

```bash
cargo test -p envsync-adapters
git commit -am "feat(adapters): 添加首批内建配置适配器"
```

### Task 8: Fetch、merge、plan 编排与 CLI

**Files:**

- Create: `crates/envsync-core/src/sync.rs`
- Modify: `crates/envsync-core/src/service.rs`
- Modify: `crates/envsync-cli/src/main.rs`
- Test: `crates/envsync-core/tests/m1_sync.rs`
- Test: `crates/envsync-cli/tests/m1_cli.rs`

- [ ] **Step 1: 写双设备集成测试**

设备 A 与 B 从共同 base 分叉，分别修改不冲突的资源；A 发布后 B fetch、merge、plan、
publish、apply，最终两端 State Root 相同。

- [ ] **Step 2: 写冲突路径测试**

同一 Git key 双方修改时创建 Conflict，`sync` 退出 13，本地文件和远端 Ref 不变。

- [ ] **Step 3: 实现服务流程**

```text
fetch remote -> find merge base -> merge full states -> project for device
-> observe -> build immutable plan -> explicit apply
```

新增 `envsync fetch`、`envsync conflicts list/show/resolve`、`envsync profile explain`。
resolve 接受 `ours`、`theirs` 或用户提供文件，并把选择保存为新 Blob。

- [ ] **Step 4: JSON schema migration**

把 CLI schema 从 v1 升为 v2；保留 v1 reader，新增 golden tests，未知输出版本不可静默接受。

- [ ] **Step 5: 验证并提交**

```bash
cargo test -p envsync-core --test m1_sync
cargo test -p envsync-cli --test m1_cli
git commit -am "feat(sync): 编排 Git 多设备同步"
```

### Task 9: M1 端到端、文档与 CI

**Files:**

- Create: `tests/e2e/git_multi_device.rs`
- Create: `docs/profiles.md`
- Create: `docs/backends/git.md`
- Create: `docs/conflicts.md`
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`

- [ ] **Step 1: 编写三平台 E2E**

测试两设备 clean merge、Profile 差异、CAS race、冲突解决、离线 cache、认证 redaction。

- [ ] **Step 2: 编写操作文档**

提供 Git SSH/HTTPS 配置、Profile 解释、冲突恢复、换后端和备份步骤；示例只用虚构凭据。

- [ ] **Step 3: 运行完整门槛**

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --doc
```

Expected: 所有命令 exit 0，CI 三平台成功。

- [ ] **Step 4: 提交**

```bash
git add README.md docs tests .github
git commit -m "test: 完成 M1 多设备同步验收"
```

## M1 完成定义

- Git Backend 不依赖 force push，并通过真实 bare remote 并发测试。
- Profile Projection 确定、可解释且不能绕过 policy。
- 三方合并不把冲突 marker 写入用户文件。
- Git、shell、PowerShell、WezTerm 内建适配器通过跨平台 fixture。
- 双设备 E2E、CAS race、冲突解决与 schema migration 全部通过。
