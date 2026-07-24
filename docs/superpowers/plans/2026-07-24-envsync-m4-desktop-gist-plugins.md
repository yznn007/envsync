# EnvSync M4 桌面端、Gist 与插件 SDK 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox
> (`- [ ]`) syntax for tracking.

**Goal:** 交付 Tauri 桌面产品、sealed-only GitHub Gist Backend、受限插件 SDK、安装包、
升级和完整产品级可观测性。

**Architecture:** Desktop 只调用与 CLI 相同的 Rust application service，通过窄而版本化的
Tauri command API；Vue 不直接访问用户文件、后端或 Vault。Gist 把不可变对象打包为单个
sealed bundle 并用 revision token 做 CAS。插件运行在独立受限进程，通过版本化 RPC 请求
Host capability，不加载进主进程地址空间。

**Tech Stack:** Rust stable、Tauri 2、Vue 3、TypeScript、Vite、Pinia、Vitest、
Playwright、shadcn-vue、reqwest、JSON-RPC、WASI Preview 2（实验适配器）。

---

## 前置门槛

- M3 application service API 稳定并有可脚本化 JSON 契约。
- 所有秘密与主动内容策略已在 core 层强制，UI 不是安全边界。
- 失败状态、Plan、diff、Conflict、receipt 都能序列化为脱敏 view model。

## 文件结构

- `apps/desktop/`：Tauri 2 Rust 壳、command、事件和窗口生命周期。
- `apps/desktop-ui/`：Vue 3 页面、组件、状态和 E2E。
- `crates/envsync-backend/src/gist.rs`：Gist sealed bundle 和 CAS。
- `crates/envsync-plugin-api/`：manifest、RPC schema、capability 与 SDK。
- `crates/envsync-plugin-host/`：进程隔离、授权、限额和生命周期。
- `docs/product/`：桌面工作流、无障碍、安装和恢复。

### Task 1: 冻结 application service view API

**Files:**

- Create: `crates/envsync-core/src/view.rs`
- Create: `crates/envsync-core/src/api.rs`
- Test: `crates/envsync-core/tests/view_api.rs`
- Create: `docs/api/application-service-v1.md`

- [ ] **Step 1: 写脱敏 view 测试**

WorkspaceSummary、StatusView、PlanView、DiffView、ConflictView、OperationView 均可
序列化；放入 canary secret 后任何 JSON 不出现 canary。

- [ ] **Step 2: 定义版本化 Request/Response**

所有 response 含 `schema_version`、request ID、status、data、diagnostics。长操作通过
operation ID 和 event stream 更新；取消是显式 command。

- [ ] **Step 3: 写兼容性 golden tests**

将 v1 JSON 保存为 fixture，字段顺序不作为契约；删除/改名已有字段使测试失败。新增字段
必须有默认或 minor version 规则。

- [ ] **Step 4: 验证并提交**

```bash
cargo test -p envsync-core --test view_api
git commit -am "feat(api): 冻结桌面应用服务契约"
```

### Task 2: Tauri 2 安全壳

**Files:**

- Create: `apps/desktop/Cargo.toml`
- Modify: `Cargo.toml`
- Create: `apps/desktop/src/main.rs`
- Create: `apps/desktop/src/commands.rs`
- Create: `apps/desktop/src/state.rs`
- Create: `apps/desktop/tauri.conf.json`
- Create: `apps/desktop/capabilities/default.json`
- Test: `apps/desktop/tests/commands.rs`

- [ ] **Step 1: 写 command allowlist 测试**

前端只能调用 workspace/status/plan/apply/rollback/conflict/vault metadata/bundle review
命令；没有任意路径读写、任意 shell、任意 HTTP 或直接 secret get command。

- [ ] **Step 2: 初始化 Tauri 壳**

CSP 禁止 remote script、`eval` 和任意 connect-src；只打包本地 UI。关闭不需要的
shell/fs/http 插件。single-instance 仅转发安全的 deep-link action，不转发 secret。

- [ ] **Step 3: command 参数验证**

所有 path 使用已经注册的 Workspace ID/Resource ID，不接收前端绝对路径。apply 必须接收
Plan ID；Rust core 再次检查新鲜度。

- [ ] **Step 4: 事件与取消**

事件只发送 view API；窗口关闭不杀死正在 journaled apply，后台完成后通知。取消只在安全
边界生效并留下 operation 状态。

- [ ] **Step 5: 验证并提交**

```bash
cargo test -p envsync-desktop
git commit -am "feat(desktop): 建立安全 Tauri 应用壳"
```

### Task 3: Vue 3 设计系统与导航

**Files:**

- Create: `apps/desktop-ui/package.json`
- Create: `apps/desktop-ui/vite.config.ts`
- Create: `apps/desktop-ui/src/main.ts`
- Create: `apps/desktop-ui/src/App.vue`
- Create: `apps/desktop-ui/src/styles/tokens.css`
- Create: `apps/desktop-ui/src/router.ts`
- Test: `apps/desktop-ui/src/App.test.ts`

- [ ] **Step 1: 建立设计 token**

定义中性背景、语义状态色、4/8px spacing、字体层级、focus ring、motion duration；支持
dark/light/high-contrast 和 reduced-motion。

- [ ] **Step 2: 写导航测试**

Workspace、Changes、Conflicts、Packages、Agents、Vault、Devices、History、Settings。
键盘可达，当前页面有 `aria-current`，窄窗口降级为 drawer。

- [ ] **Step 3: 实现 app shell**

Pinia 只存 view model 与 UI 状态，不存 secret plaintext。error boundary 展示 request ID
和脱敏诊断。

- [ ] **Step 4: lint/typecheck/test**

```bash
pnpm --dir apps/desktop-ui lint
pnpm --dir apps/desktop-ui typecheck
pnpm --dir apps/desktop-ui test
```

Expected: 全部 exit 0。

- [ ] **Step 5: 提交**

```bash
git add apps/desktop-ui
git commit -m "feat(ui): 建立桌面导航与设计系统"
```

### Task 4: Workspace、状态与首次使用流程

**Files:**

- Create: `apps/desktop-ui/src/pages/OnboardingPage.vue`
- Create: `apps/desktop-ui/src/pages/WorkspacePage.vue`
- Create: `apps/desktop-ui/src/pages/StatusPage.vue`
- Create: `apps/desktop-ui/src/stores/workspace.ts`
- Test: `apps/desktop-ui/src/pages/OnboardingPage.test.ts`

- [ ] **Step 1: 写 onboarding 测试**

创建/打开 Workspace、选择 Local/Git/Gist、授权根、设备 Profile。路径选择通过 Tauri
dialog 后由 Rust 注册 capability，前端不保留绝对路径。

- [ ] **Step 2: 实现状态 dashboard**

显示后端、head、设备、最近 sync、drift、未收敛 operation、安全告警。每个异常都有明确
下一动作，不能只显示通用 error。

- [ ] **Step 3: offline 与 loading 状态**

Git/Gist 不可达时展示本地最后状态及其时间；不得把不可达显示为 clean。

- [ ] **Step 4: 验证并提交**

```bash
pnpm --dir apps/desktop-ui test -- OnboardingPage
git commit -am "feat(ui): 添加首次使用与工作区状态"
```

### Task 5: Plan、Diff、Conflict 与回滚 UI

**Files:**

- Create: `apps/desktop-ui/src/pages/ChangesPage.vue`
- Create: `apps/desktop-ui/src/components/DiffViewer.vue`
- Create: `apps/desktop-ui/src/pages/ConflictsPage.vue`
- Create: `apps/desktop-ui/src/pages/HistoryPage.vue`
- Test: `apps/desktop-ui/src/components/DiffViewer.test.ts`

- [ ] **Step 1: Diff 测试**

支持文本、structured key diff、binary summary、create/delete、Managed Block 边界；秘密只
显示“值已更改”。大文件虚拟滚动并有截断提示。

- [ ] **Step 2: Plan 审核**

按风险分组 action，显示 source/target、备份和 rollback guarantee。High risk 逐项确认；
apply 按钮只发送当前 Plan ID，stale 后强制重新加载。

- [ ] **Step 3: Conflict 解决**

ours/theirs/manual 三种选择，manual 编辑器只处理非秘密文本并在提交前解析/验证。冲突未
解决时不出现误导性的“同步成功”。

- [ ] **Step 4: History 与回滚**

展示 operation 状态机、receipt、失败点和 recovery action。回滚先生成逆向 Plan 并再次
审核。

- [ ] **Step 5: 验证并提交**

```bash
pnpm --dir apps/desktop-ui test
git commit -am "feat(ui): 添加差异冲突与历史恢复"
```

### Task 6: Packages、Agents、Vault 与 Devices UI

**Files:**

- Create: `apps/desktop-ui/src/pages/PackagesPage.vue`
- Create: `apps/desktop-ui/src/pages/AgentsPage.vue`
- Create: `apps/desktop-ui/src/pages/VaultPage.vue`
- Create: `apps/desktop-ui/src/pages/DevicesPage.vue`
- Test: `apps/desktop-ui/src/pages/SecurityPages.test.ts`

- [ ] **Step 1: Package 风险测试**

install/upgrade/downgrade/uninstall/elevation 有不同标签。批量批准不能包含被 policy deny 的
action。

- [ ] **Step 2: Bundle 审核测试**

显示 signer、digest、文件、capability、SecretRef 和版本 diff。新 capability 必须单独
确认；quarantine 内容不能从 UI 直接执行。

- [ ] **Step 3: Vault UI**

列表只显示 Secret ID、更新时间、引用者。设置 secret 使用单次 modal buffer，提交或关闭后
清空；不提供复制全部 vault 或 reveal-by-default。

- [ ] **Step 4: Device UI**

邀请二维码/短码不得含 private material；撤销展示将触发 key rotation。恢复流程要求明确
展示旧设备重新授权影响。

- [ ] **Step 5: 验证并提交**

```bash
pnpm --dir apps/desktop-ui test -- SecurityPages
git commit -am "feat(ui): 添加包 Agent Vault 与设备管理"
```

### Task 7: Gist sealed bundle 格式

**Files:**

- Create: `crates/envsync-backend/src/gist_bundle.rs`
- Test: `crates/envsync-backend/tests/gist_bundle.rs`
- Create: `docs/backends/gist.md`

- [ ] **Step 1: 写格式测试**

一个 Gist 文件 `envsync-<workspace>.bundle`，内容为 base64url canonical envelope：
version、workspace、revision、head、objects、bundle digest、signature。最多 256 resources
和 5 MiB encoded size。

- [ ] **Step 2: sealed-only 测试**

配置 Vault 或普通资源时 bundle payload 始终是 ciphertext；fixture 扫描不得出现资源明文、
路径、Secret ID 或 metadata。未启用 M2 密钥的 Workspace 不能选择 Gist。

- [ ] **Step 3: 实现 pack/unpack**

对象排序确定；解包先检查 encoded size、版本和计数，再验证 digest/signature，最后解密。
拒绝压缩炸弹和重复 object ID。

- [ ] **Step 4: 验证并提交**

```bash
cargo test -p envsync-backend --test gist_bundle
git commit -am "feat(backend): 添加密封 Gist bundle 格式"
```

### Task 8: GitHub Gist Backend 与 CAS

**Files:**

- Create: `crates/envsync-backend/src/gist.rs`
- Test: `crates/envsync-backend/tests/gist_backend.rs`
- Create: `crates/envsync-backend/tests/support/mock_github.rs`

- [ ] **Step 1: 写 HTTP contract tests**

mock API 覆盖 create/read/update、ETag/If-Match、rate limit、401/403/404、超时、截断响应和
服务端返回旧 revision。

- [ ] **Step 2: 实现 CAS**

读取保存 ETag 与 revision；更新同时发送 If-Match，并在响应后重读验证 revision/head。
GitHub 不保证的条件不能被描述为强 CAS；检测竞争后返回 conflict 并保持本地零变更。

- [ ] **Step 3: Token 集成**

Token 只来自 Vault SecretRef，最小 scope，日志只显示 GitHub request ID。URL、header 和
错误 body 统一 redaction。

- [ ] **Step 4: rate-limit/backoff**

尊重 Retry-After 和 rate headers；重试只用于幂等 GET。未知 PATCH 结果先 GET 判定，不能
盲目重复发布。

- [ ] **Step 5: 验证并提交**

```bash
cargo test -p envsync-backend --test gist_backend
git commit -am "feat(backend): 添加 GitHub Gist 后端"
```

### Task 9: 插件 manifest 与版本化 RPC

**Files:**

- Create: `crates/envsync-plugin-api/Cargo.toml`
- Modify: `Cargo.toml`
- Create: `crates/envsync-plugin-api/src/lib.rs`
- Create: `crates/envsync-plugin-api/src/manifest.rs`
- Create: `crates/envsync-plugin-api/src/rpc.rs`
- Test: `crates/envsync-plugin-api/tests/compatibility.rs`

- [ ] **Step 1: manifest 测试**

manifest 含 ID、semver、publisher、API range、entrypoint、目标平台、capability、资源限制和
签名。拒绝绝对 entrypoint、路径穿越、重复 ID、未知 capability 和不兼容 API。

- [ ] **Step 2: RPC schema**

长度前缀 JSON-RPC，仅允许 initialize、describe、observe、render、plan-command、verify、
shutdown。每条消息带 schema version、request ID 和 8 MiB 限制。

- [ ] **Step 3: compatibility tests**

Host 支持一个 major 的两个 minor；未知字段按 minor 规则忽略，未知 method/version 拒绝。
golden fixtures 固定 request/response。

- [ ] **Step 4: 验证并提交**

```bash
cargo test -p envsync-plugin-api
git commit -am "feat(plugins): 定义插件 manifest 与 RPC"
```

### Task 10: 隔离插件 Host

**Files:**

- Create: `crates/envsync-plugin-host/Cargo.toml`
- Modify: `Cargo.toml`
- Create: `crates/envsync-plugin-host/src/lib.rs`
- Create: `crates/envsync-plugin-host/src/process.rs`
- Create: `crates/envsync-plugin-host/src/capability.rs`
- Test: `crates/envsync-plugin-host/tests/isolation.rs`

- [ ] **Step 1: 写 malicious plugin fixtures**

测试无限循环、超大输出、崩溃、协议欺骗、读取未授权路径、请求未知命令、泄露环境变量和在
shutdown 后继续运行。

- [ ] **Step 2: 独立进程执行**

清空环境后只注入协议 channel；cwd 为临时空目录。timeout、内存/输出限制、进程树清理。
平台 sandbox capability 不可用时，插件默认禁止启用，不伪称已隔离。

- [ ] **Step 3: Host-mediated capability**

插件只返回 declarative observation/render/command proposal；Host 重新验证路径和命令，
再进入普通 Plan/policy/apply 流程。插件不能获得 Vault plaintext。

- [ ] **Step 4: 签名与 quarantine**

复用 Bundle publisher trust；安装、更新、权限扩张均进入 quarantine 审核。撤销 publisher
会禁用其插件但保留审计数据。

- [ ] **Step 5: 验证并提交**

```bash
cargo test -p envsync-plugin-host --test isolation
git commit -am "feat(plugins): 添加隔离插件 Host"
```

### Task 11: 桌面 E2E、无障碍与视觉回归

**Files:**

- Create: `apps/desktop-ui/e2e/onboarding.spec.ts`
- Create: `apps/desktop-ui/e2e/sync.spec.ts`
- Create: `apps/desktop-ui/e2e/recovery.spec.ts`
- Create: `apps/desktop-ui/e2e/security.spec.ts`
- Create: `apps/desktop-ui/e2e/accessibility.spec.ts`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Playwright 场景**

首次使用、Local/Git/Gist、计划审核、CAS conflict、包风险、Bundle 审核、设备撤销、
published_not_converged 恢复和 rollback。

- [ ] **Step 2: 安全 UI 测试**

canary secret 不出现在 DOM snapshot、console、错误 toast、截图文件名或 application log。
远端 HTML/error body 以纯文本显示。

- [ ] **Step 3: 无障碍**

键盘完成所有主要流程；axe 无 serious/critical 问题；焦点管理、live region、对比度、
200% zoom 和 reduced motion 通过。

- [ ] **Step 4: 视觉回归**

只固定关键状态截图：clean、drift、conflict、high-risk plan、offline、recovery。字体和
动画在测试环境固定。

- [ ] **Step 5: 验证并提交**

```bash
pnpm --dir apps/desktop-ui lint
pnpm --dir apps/desktop-ui typecheck
pnpm --dir apps/desktop-ui test
pnpm --dir apps/desktop-ui exec playwright test
git commit -am "test: 添加桌面端产品验收"
```

### Task 12: 安装、升级、可观测性与发布文档

**Files:**

- Create: `docs/product/install.md`
- Create: `docs/product/upgrade.md`
- Create: `docs/product/diagnostics.md`
- Create: `docs/product/plugin-security.md`
- Create: `docs/release-checklist.md`
- Modify: `apps/desktop/tauri.conf.json`
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`

- [ ] **Step 1: schema migration E2E**

从 M0、M1、M2、M3 fixture 逐版本升级到 M4；失败时事务回滚并保留可恢复备份。降级启动时
只读阻塞，不让旧版本改写新 schema。

- [ ] **Step 2: 安装包**

生成 macOS universal/arch app、Windows MSI/NSIS、Linux AppImage/deb/rpm。签名和
notarization key 只来自 CI secret store，不进入仓库。

- [ ] **Step 3: 更新**

更新 manifest 签名验证、channel、版本单调性、下载摘要和失败回退。更新不能在 apply
operation 进行时重启。

- [ ] **Step 4: 诊断包**

用户显式生成；只含版本、脱敏日志、operation metadata、capability 状态。生成前显示文件
清单并运行 canary/SecretRef/path redaction。

- [ ] **Step 5: 全量验证**

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --doc
pnpm --dir apps/desktop-ui lint
pnpm --dir apps/desktop-ui typecheck
pnpm --dir apps/desktop-ui test
pnpm --dir apps/desktop-ui build
```

Expected: 全部 exit 0；三平台安装包 smoke test、schema upgrade、Gist mock/opt-in live test
和桌面 E2E 成功。

- [ ] **Step 6: 提交**

```bash
git add README.md docs apps .github
git commit -m "docs: 完成 M4 发布与运维交付"
```

## M4 完成定义

- UI 不拥有安全决策，所有变更仍经 core Plan/policy/journal。
- Gist 只保存 sealed bundle，并强制 256 resources/5 MiB 上限。
- 插件不加载进主进程，未获 Host capability 时不能访问路径、命令或秘密。
- 桌面主要流程、无障碍、安全 UI 和 schema migration 有自动化 E2E。
- 三平台安装、签名、升级、回退、诊断和发布清单具备可复现证据。
