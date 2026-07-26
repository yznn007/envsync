# EnvSync M0 运维手册

本文面向**运行、排查和恢复** EnvSync M0 的人，回答四类问题：

1. 磁盘上到底存了什么，它们之间是什么关系；
2. 一次同步的事务边界在哪里，进程在任意一点被杀掉会留下什么；
3. 出问题时先看什么、动什么、什么时候必须停手叫人；
4. 现在写下的数据，在 M1–M4 升级时会怎么被对待。

命令的**参数与 JSON 契约**不在本文重复，见 [`docs/cli.md`](cli.md)。本文只在流程层面
引用命令。安全模型与威胁边界见 [`docs/security-model.md`](security-model.md)。

相关决策记录：

| ADR | 主题 |
|---|---|
| [ADR-0001](decisions/2026-07-26-canonical-cbor-in-domain.md) | 在 domain crate 内自实现严格 canonical CBOR |
| [ADR-0002](decisions/2026-07-26-device-id-derivation.md) | `DeviceId` 从第一天起就是派生摘要 |
| [ADR-0003](decisions/2026-07-26-plan-id-excludes-timestamp.md) | Plan ID 绑定输入而不绑定生成时刻 |
| [ADR-0004](decisions/2026-07-26-synchronous-backend-trait.md) | Backend 与适配器 trait 采用同步 I/O |

---

## 1. 数据模型

### 1.1 七种实体

| 实体 | 类型 | 存在于 | 标识 |
|---|---|---|---|
| Workspace | `WorkspaceId` | 配置文件 `workspace_id` | 随机 UUID，终生不变 |
| Snapshot | `SnapshotBody` | 后端 / 草稿库 | `SnapshotId`，内容寻址 |
| State Root | `StateRoot` | 后端 / 草稿库 | `StateRootId`，内容寻址 |
| Blob | 裸字节 | 后端 / 草稿库 | `BlobId`，内容寻址 |
| Ref | `WorkspaceRef` | 后端 `refs/<workspace>.cbor` | 无独立标识，按工作区唯一 |
| Plan | `Plan` | 草稿库 `plans` 表 | `PlanId`，由绑定内容派生 |
| Operation | journal 记录 | `journal.db` | `OperationId`，随机 UUID |

**Workspace** 是唯一的逻辑同步头。一个工作区在任意时刻只有一个 Ref，Ref 指向一个
Snapshot；Snapshot 指向一个 State Root；State Root 是 `ResourceId -> ResourceEntry`
的有序映射；每个 managed 条目指向一个 Blob。

**Plan 不是数据模型的一部分，而是一次决策的快照**：它把「目标 Snapshot + 后端 revision
+ 本机全部观察结果 + 动作 + 诊断」冻结成一个可复算的标识。**Operation** 则是 Plan 的
一次执行记录，是崩溃恢复的唯一事实来源。

### 1.2 关系图

```text
                          配置文件 envsync.yaml
                          workspace_id / device / roots / resources
                                        │
                                        │ 声明
                                        ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │                          Workspace                               │
  └──────────────────────────────────────────────────────────────────┘
                                        │
                     后端 refs/<workspace-uuid>.cbor
                                        ▼
        ┌───────────────────────────────────────────────┐
        │ Ref (WorkspaceRef)                            │
        │   format_version / workspace                  │
        │   revision : u64   ← 只能通过 CAS 严格递增     │
        │   head     : Option<SnapshotId>               │
        └───────────────────┬───────────────────────────┘
                            │ head
                            ▼
        ┌───────────────────────────────────────────────┐        ┌──────────────────────┐
        │ Snapshot Body                                 │◄───────┤ SnapshotSignature    │
        │   format_version / workspace                  │ snapshot│  M0: algorithm="none"│
        │   parents : Vec<SnapshotId>  (≤8, 升序去重)    │        │  M2: Ed25519         │
        │   state_root : StateRootId                    │        └──────────────────────┘
        │   author_device : DeviceId                    │
        │   created_at_unix_ms / metadata (≤64 项)      │
        └───────────────────┬───────────────────────────┘
                            │ state_root
                            ▼
        ┌───────────────────────────────────────────────┐
        │ State Root                                    │
        │   format_version                              │
        │   entries : BTreeMap<ResourceId, Entry>       │
        └───────────────────┬───────────────────────────┘
                            │ 每个 entry
                            ▼
        ┌───────────────────────────────────────────────┐
        │ ResourceEntry                                 │
        │   resource / disposition / mode / policy      │
        │   blob : Option<BlobId>                       │
        └───────────────────┬───────────────────────────┘
                            │ blob（managed 才有）
                            ▼
        ┌───────────────────────────────────────────────┐
        │ Blob = 裸字节，不经 CBOR 包装                  │
        └───────────────────────────────────────────────┘

  ─────────────────── 以下只存在于本机 state_dir，不进后端 ───────────────────

        ┌───────────────────────────────────────────────┐
        │ Plan（草稿库 draft.db）                        │
        │   target_snapshot / base_revision / next_ref  │
        │   observations[]  ← 绑定本机现状（含内容摘要） │
        │   actions[]       ← expected_before/after     │
        │   diagnostics[]                               │
        └───────────────────┬───────────────────────────┘
                            │ 一次执行
                            ▼
        ┌───────────────────────────────────────────────┐
        │ Operation（journal.db）                        │
        │   state : OperationState 状态机                │
        │   actions[] : ActionState                     │
        │   receipts[] : backup_path / original_digest  │
        │                / applied_digest / guarantee   │
        └───────────────────┬───────────────────────────┘
                            │ backup_path
                            ▼
          <state_dir>/backups/<operation-id>/<resource-id>
```

### 1.3 内容寻址与域分隔哈希

所有内容寻址标识都是 **BLAKE3 的 32 字节摘要**，且**先喂一个域分隔标签再喂内容**
（`Digest32::domain_hash(domain, payload)`）。这样字节完全相同的两份内容，只要种类不同，
摘要就一定不同——攻击者无法用一个 Blob 冒充一个 State Root。

| 用途 | 域标签 | 定义位置 |
|---|---|---|
| Blob | `envsync:blob:v1` | `envsync-domain::id` |
| State Root | `envsync:state:v1` | `envsync-domain::id` |
| Snapshot Body | `envsync:snapshot:v1` | `envsync-domain::id` |
| Plan | `envsync:plan:v1` | `envsync-domain::id` |
| Conflict（M1 使用） | `envsync:conflict:v1` | `envsync-domain::id` |
| Device | `envsync:device:v1` | `envsync-domain::id`，见 ADR-0002 |
| Snapshot Signature | `envsync:snapshot-signature:v1` | `ObjectKind::domain` |
| Membership Event（M2） | `envsync:membership-event:v1` | `ObjectKind::domain` |
| Key Envelope（M2） | `envsync:key-envelope:v1` | `ObjectKind::domain` |
| Sealed Secret（M2） | `envsync:sealed-secret:v1` | `ObjectKind::domain` |
| **本机文件内容观察** | `envsync:file-content:v1` | `envsync-platform::FILE_CONTENT_DOMAIN` |

最后一行值得单独注意：`Action.expected_before` / `expected_after` / `VerifyRule::ExpectDigest`
用的是**文件内容域**（`envsync:file-content:v1`），而 `Action.content` 是一个 **`BlobId`**
（`envsync:blob:v1` 域）。同一段字节在两处的摘要不同，这是有意为之：前者回答「磁盘上这个
文件现在是不是它」，后者回答「对象库里那个对象是不是它」，两个问题不应该共用一个键空间。

除 Blob 外的所有对象都用**严格 canonical CBOR** 编码（见 ADR-0001）：确定长度、最短整数、
map 键按编码字节升序、无重复键、不支持浮点与 tag。解码后还会重新编码并逐字节比较，
非 canonical 表示一律拒绝。Blob 是裸字节，不做 CBOR 包装，任何工具都能直接读出文件内容。

### 1.4 磁盘布局

后端（`LocalBackend`）：

```text
<backend.path>/
  format                              # 逐字节校验 "envsync-backend-format=1\n"
  objects/<hex[0..2]>/<hex[2..]>.<kind>   # kind ∈ blob|state|snapshot|signature|
                                          #        conflict|membership|envelope|secret
  refs/<workspace-uuid>.cbor          # canonical CBOR 的 WorkspaceRef
  locks/<workspace-uuid>.lock         # per-workspace advisory lock
```

本机状态目录（配置里的 `state_dir`，默认为配置文件同目录下的 `.envsync`）：

```text
<state_dir>/
  journal.db                          # 操作日志（SQLite，synchronous=FULL）
  draft/draft.db                      # 草稿对象库 + 计划表（SQLite）
  backups/<operation-id>/<resource-id>
```

命名细节（会影响你用 `ls` 找文件）：

- `<operation-id>` 是 UUID 的 **simple 形式**，即**不带连字符**，而 CLI 输出的
  `operation` 字段是带连字符的标准形式；
- `<resource-id>` 把资源标识里的 `/` 替换成 `__`，例如 `shell/zsh/main` →
  `shell__zsh__main`；
- 写入过程中的临时文件落在**目标文件同目录**，命名为
  `.envsync-tmp-<operation-id>-<随机后缀>`。

**草稿库不污染后端**：`capture` 产生的 Blob、State Root、Snapshot 先落本地草稿库，
只有 `sync` 发布时才上传到后端。这样试验性的捕获不会在共享的不可变对象库里留下垃圾。

---

## 2. 事务边界与失败状态

### 2.1 固定顺序

```text
①  recover      自动清理上一次的未完成操作（sync 启动即执行）
②  freshness    重新观察、重新计划，与提交的 --plan 比对；不一致 → 退出码 11
③  upload       把目标快照可达的全部对象上传到后端（需要发布时）
④  journal.begin 登记 operation 与 actions          [state = planned]
⑤  preflight    逐动作重读目标并比对 expected_before  [state = preflighted]
                ← 到这一步为止，后端 Ref 与本地文件都是零变更
⑥  publish      CAS 更新后端 Ref                     [state = published]
                ← CAS 失败在这里返回，本地一个字节都没写过（退出码 10）
⑦  apply        逐动作：临时文件 → 备份 → 原子替换   [state = applying]
                每个动作生效后**立刻**落 receipt，再 verify
⑧  verify       全部通过                             [state = verified]
⑨  commit       事务成功                             [state = completed]
```

三条边界必须记牢：

1. **CAS 发生在任何本地写入之前。** 这是「CAS 冲突时失败方本地零变更」这条验收条件的
   实现基础（测试 `cas_conflict_never_invokes_the_file_mutator`）。
2. **receipt 在动作生效后立刻落盘。** 若 receipt 落盘失败，引擎不会继续往前走，而是把
   当前动作一并纳入回滚——回滚凭据没有进入事实来源，继续执行等于走进没有退路的区域。
3. **阻塞诊断在登记 operation 之前拦截。** 被策略拒绝的计划不会在 journal 里留下一条
   永远不会推进的记录（测试 `blocked_plan_is_rejected_without_touching_the_journal`）。

### 2.2 状态机

```text
                    ┌──────────┐
                    │ planned  │
                    └────┬─────┘
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
      ┌──────────────┐        ┌──────────┐
      │ preflighted  │───────►│ aborted  │  (终态)
      └──────┬───────┘        └──────────┘
             │  CAS 成功            ▲
             ▼                      │
      ┌──────────────┐              │
      │  published   │──────────────┘（planned/preflighted 才能 abort）
      └──────┬───────┘
             │              ┌──────────────────────────┐
             ├─────────────►│ published_not_converged  │◄──┐
             ▼              └────────┬─────────┬───────┘   │
      ┌──────────────┐               │         │           │
   ┌─►│   applying   │◄──────────────┘         │           │
   │  └──────┬───────┘   （recover 重新收敛）   │           │
   │         │                                 │           │
   │         ├────────────────────────────────►┘           │
   │         │  （applying 中发现人工冲突）                  │
   │         ▼                                             │
   │  ┌──────────────┐      ┌───────────┐                  │
   │  │   verified   │─────►│ completed │ (终态)            │
   │  └──────────────┘      └─────┬─────┘                  │
   │                              │ envsync rollback       │
   │                              ▼                        │
   │                      ┌──────────────┐                 │
   └─────────────────────►│ rolling_back │─────────────────┘
      （applying 失败）    └──────┬───────┘  （回滚本身失败）
                                 ▼
                          ┌──────────────┐
                          │ rolled_back  │ (终态)
                          └──────────────┘
```

合法迁移由 Rust 层强制（`OperationState::can_transition_to`），数据库只把状态当字符串存。
**不允许自迁移**：把同一状态重复写入通常意味着调用方丢了上下文，与其静默接受不如显式失败
（`JournalError::IllegalTransition`，错误码 `storage.illegal_transition`）。

完整迁移表：

| 从 | 可到 |
|---|---|
| `planned` | `preflighted`、`aborted` |
| `preflighted` | `published`、`aborted` |
| `published` | `applying`、`published_not_converged` |
| `applying` | `verified`、`rolling_back`、`published_not_converged` |
| `verified` | `completed` |
| `completed` | `rolling_back`（显式 `envsync rollback`） |
| `published_not_converged` | `applying`（重新收敛）、`rolling_back` |
| `rolling_back` | `rolled_back`、`published_not_converged`（回滚本身失败） |
| `aborted` / `rolled_back` / `completed` | 终态，`list_unfinished` 不再返回 |

### 2.3 逐状态：进程在这里被杀掉会怎样

下表的「下次启动」指 `envsync recover`，或 `envsync sync` 启动时自动执行的同一套流程。

| 状态 | 现场（磁盘上真实发生了什么） | 下次启动如何恢复 | 恢复后状态 |
|---|---|---|---|
| `planned` | journal 里有 operation 与 actions；**后端零变更，本地零变更** | 清理该 operation 遗留的 `.envsync-tmp-<operation-id>-*`，直接中止 | `aborted` |
| `preflighted` | 全部动作预检通过（只读了目标摘要）；仍然**后端零变更、本地零变更** | 同上 | `aborted` |
| `published` | **后端 Ref 已经前进**，本地一个动作都还没应用 | 逐动作按三条判据分类后重新收敛，**不再重复 CAS** | `completed` 或 `published_not_converged` |
| `applying` | 后端已前进；部分动作已生效并留下 receipt，部分未生效；可能有一个动作正处在「临时文件已写、rename 未完成」之间 | 逐动作按三条判据分类：已生效则跳过，未生效则重新应用；任一动作两条判据都不匹配则**停手** | `completed` 或 `published_not_converged` |
| `verified` | 全部动作已生效并通过校验，只差最后一次状态迁移 | 补记完成状态，不碰任何文件 | `completed` |
| `published_not_converged` | 后端已前进，本地既没收敛也没干净回滚 | 与 `applying` 相同的重新收敛流程；仍然不行则原地停留 | `completed` 或 `published_not_converged` |
| `rolling_back` | 后端已前进；部分动作已按 receipt 还原 | 按 receipt **逆序**继续回滚；目标已等于 `original_digest` 的条目视为已回滚（幂等） | `rolled_back` 或 `published_not_converged` |
| `completed` / `aborted` / `rolled_back` | 终态 | 跳过 | 不变 |

单个动作被中断时的原子性由平台层保证。写入序列是：

```text
解析路径（逐段 no-follow）
  → 重读目标并比对 expected_before        ← 不符即 platform.stale_observation，放弃
  → 同目录临时文件写入 + fsync
  → 备份原文件（copy 语义，原文件保持原地）
  → rename 覆盖（POSIX 原子；Windows 走 MoveFileEx + REPLACE_EXISTING）
  → fsync 父目录
```

因此**任何时刻断电，目标文件要么是旧内容要么是新内容**，不会出现半截文件。备份用 copy
而不是 rename，是为了让原文件在被覆盖前始终完好——若用 rename 挪走原文件，在「备份完成」
到「新文件就位」之间目标会短暂消失。

### 2.4 为什么 `published_not_converged` 不是普通失败

普通失败的语义是「什么都没发生，重试即可」。`published_not_converged` 恰恰相反：

**后端 Ref 已经通过 CAS 前进了，全世界（包括其他设备）都会认为这个快照是当前头，
而本机文件没有跟上。**

它带来三个具体后果：

1. **重试无效。** 再跑一次 `plan` → `sync` 只会得到 `no_op` 或一个与实际不符的计划——
   后端头已经是目标快照，`requires_publish` 为假，问题不会自己消失。
2. **别的设备会基于一个本机从未真正应用过的状态继续演进。** 它们的 `plan` 会以这个头为
   基准，本机的落后会被越拉越远。
3. **只有两条出路，且都必须显式选择：**
   - `envsync recover` —— 继续向前收敛到目标快照；
   - `envsync rollback --operation <id>` —— 按 receipt 逆序把本地还原，接受「后端头领先
     本地」这个事实，之后重新 `capture` → `plan` → `sync`。

因此它有自己的终态外状态、自己的错误码 `sync.published_not_converged`、自己的退出码
**20**，`status` 也把它作为独立的整体状态返回。设计上刻意**不允许**它降级成普通失败终态：
即使回滚本身也失败了（应用失败 + 回滚失败的双重错误），操作仍然停在
`published_not_converged` 并记录两条错误，而不是被写成 `rolled_back`
（测试 `rollback_failure_keeps_published_not_converged_with_both_errors`）。

---

## 3. 配置与完整 CLI 流程

配置文件的**逐字段说明**见 [`examples/workspace.yaml`](../examples/workspace.yaml)——那份文件
被 `crates/envsync-core/tests/config.rs` 用 `include_str!` 真实解析，字段改名会让测试立刻
失败，所以它永远不会过期。命令参数与 JSON 契约见 [`docs/cli.md`](cli.md)。

下面只给运维视角的**最小可用配置**与四条流程。所有路径都是占位符。

### 3.1 最小可用配置

```yaml
version: 1
workspace_id: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"

device:
  name: "laptop"
  seed_hex: "3a7f1c92b4de5068a1cf23947db6e50f8c41a2937be05d6c1f83a4b72e90cd15"

backend:
  kind: local
  path: "/srv/YOUR_BACKEND/envsync"

state_dir: ".envsync"

roots:
  home: "/home/YOUR_USER"

resources:
  - id: git/config/global
    root: home
    target: .config/git/config
    mode: full_file
    disposition: managed

  - id: shell/zsh/main
    root: home
    target: .zshrc
    mode: managed_block
    disposition: managed
    comment_prefix: "# "
    policy:
      unix_mode: "0644"
      secret: false
```

四个必须理解的字段：

| 字段 | 含义 | 运维影响 |
|---|---|---|
| `roots` | 授权根白名单 | EnvSync 只能触碰这些目录内部。收紧它就是收紧影响半径 |
| `device.seed_hex` | 本机私有设备种子 | **绝不上传、绝不跨机复制**；换机器重新生成（ADR-0002） |
| `state_dir` | 本机 journal / 草稿 / 备份 | **绝不跨设备复制**，否则恢复流程会读到别人的历史 |
| `disposition` | `managed` / `ensure_absent` / `unmanaged` | 只有 `ensure_absent` 能产生删除 |

未知字段会被**拒绝**而不是忽略：写错字段名会报 `config.unknown_field`，而不是让你以为策略
生效了。相对路径一律相对**配置文件所在目录**解析，与你在哪个目录执行命令无关。

### 3.2 首次使用

```bash
# 1) 初始化：生成配置、后端目录与状态目录
envsync init --config /home/YOUR_USER/.config/envsync/envsync.yaml \
             --backend-path /srv/YOUR_BACKEND/envsync \
             --device-name laptop

# 2) 编辑配置，把要管理的文件填进 resources
#    生成的配置里 resources 为空——空工作区是合法的

# 3) 体检：授权根可访问性、资源目标合法性、后端可达性、journal schema
envsync doctor --config /home/YOUR_USER/.config/envsync/envsync.yaml

# 4) 捕获本机现状（只写本地草稿库，不碰后端）
envsync capture --config /home/YOUR_USER/.config/envsync/envsync.yaml

# 5) 生成计划并审阅
envsync plan --config /home/YOUR_USER/.config/envsync/envsync.yaml

# 6) 应用
envsync sync --config /home/YOUR_USER/.config/envsync/envsync.yaml --plan <plan-id>

# 7) 确认收敛
envsync status --config /home/YOUR_USER/.config/envsync/envsync.yaml
```

脚本化时用 `--json` 取计划标识：

```bash
CFG=/home/YOUR_USER/.config/envsync/envsync.yaml
envsync capture --config "$CFG" --json >/dev/null
PLAN=$(envsync plan --config "$CFG" --json | jq -r '.data.plan')
envsync sync --config "$CFG" --plan "$PLAN" --json | jq -r '.data.outcome'
```

`plan` 即使发现阻塞诊断也以退出码 **0** 结束——它只是一次预演。要判断能不能应用，读
`data.blocked`，不要读退出码。

### 3.3 第二台设备接入

第二台设备必须与第一台共享 **`workspace_id`** 和 **`backend.path`**，其余全部独立。

```bash
CFG=/home/YOUR_USER/.config/envsync/envsync.yaml

# 1) 初始化，指向同一个后端
envsync init --config "$CFG" \
             --backend-path /srv/YOUR_BACKEND/envsync \
             --device-name desktop

# 2) 手工把 workspace_id 改成与第一台一致；
#    device.name / device.seed_hex / state_dir / roots 保持本机自己的值

# 3) 直接 plan：没有本地草稿头时，目标快照取后端当前头，本机文件向它收敛
envsync plan --config "$CFG"
envsync sync --config "$CFG" --plan <plan-id>

# 4) 确认
envsync status --config "$CFG"
```

| 项目 | 是否跨设备共享 | 原因 |
|---|---|---|
| `workspace_id` | **必须相同** | 它参与快照与 Ref 的绑定 |
| `backend.path` | **必须指向同一个后端** | 否则是两个互不相关的工作区 |
| `device.name` | 各自独立 | 只用于诊断输出 |
| `device.seed_hex` | **各自独立，绝不复制** | 复制会让两台机器拥有同一个 `DeviceId` |
| `state_dir` | **各自独立，绝不复制** | 里面是本机的 journal、草稿与备份 |
| `roots` | 各自独立 | 每台机器的目录布局本来就不同 |

Managed Block 模式在第二台设备上**只替换块内内容，块外字节逐字保留**
（测试 `second_device_pulls_identical_state_and_preserves_its_own_content`、
`managed_block_preserves_outside_bytes_verbatim`）。

### 3.4 日常同步

```bash
CFG=/home/YOUR_USER/.config/envsync/envsync.yaml

# 本机改了配置，想推上去
envsync capture --config "$CFG"          # 生成新草稿快照
envsync plan    --config "$CFG"          # 审阅动作、风险、备份策略
envsync sync    --config "$CFG" --plan <plan-id>

# 别的设备推了新内容，想拉下来
envsync plan    --config "$CFG"          # 无本地草稿头时目标取后端当前头
envsync sync    --config "$CFG" --plan <plan-id>
```

`capture` 是**幂等**的：内容没变就不生成新草稿，`data.changed` 为 `false`。本机读不到某个
资源时，`capture` 会沿用上一版快照中的内容并留一条 `capture.reused_previous` 警告——
「观察不到」永远不等于「删掉它」。

生成计划到应用之间目标被外部改动，`sync` 会以退出码 **11**（`plan.stale`）拒绝。这不是
故障，是设计：重新 `plan` 再 `sync` 即可。

### 3.5 查看状态

```bash
envsync status --config "$CFG"
envsync status --config "$CFG" --json | jq '{state: .data.state, pending: .data.pending_actions, unfinished: .data.unfinished}'
```

| `data.state` | 含义 | 该做什么 |
|---|---|---|
| `clean` | 本机与目标快照一致，无未完成操作 | 无 |
| `drifted` | 有待应用的变更，或存在本地草稿头 | `plan` → `sync` |
| `conflicted` | 计划里有阻塞诊断 | 按 `diagnostics[].code` 修资源，再重新 `plan` |
| `published_not_converged` | 后端头已前进但本地没跟上 | `doctor` 看建议，再 `recover` 或 `rollback` |

`doctor` **恒以退出码 0 结束**，因为「体检本身成功了」。判断健康与否请读 `data.healthy`。
`doctor` 的四类检查项：授权根可访问性、每个资源的目标路径合法性、后端可达性、操作日志
schema 版本；外加只读的恢复建议列表。

---

## 4. 备份、恢复与人工冲突处理

### 4.1 备份在哪里

```text
<state_dir>/backups/<operation-id>/<resource-id>
```

- 路径是**确定性**的（`SafeWriter::backup_path_for`）：恢复流程无需读 journal 就能定位备份，
  重复执行同一操作也不会产生无法关联的孤儿文件；
- `<operation-id>` 是**不带连字符**的 UUID，`<resource-id>` 里的 `/` 换成 `__`；
- 备份**不放在授权根内部**——否则备份自身会被下一次同步当成用户文件；
- 在 unix 上，备份文件会被赋予原文件的权限位，回滚时顺带恢复权限；
- **备份失败即动作失败。** 宁可什么都不做，也不在没有退路的情况下覆盖
  （测试 `original_file_is_backed_up_to_deterministic_path`、`delete_always_backs_up_first`）。

删除动作**总是先备份**。目标原本就不存在时是幂等成功，收据的 `backup_path` 与
`original_digest` 均为 `None`——此时「回滚」的语义是「把文件删掉」。

`<state_dir>/backups/` 目录在 M0 **不会自动清理**。它是你唯一的字节级退路，占用空间前请先
确认对应的 operation 已经处于终态。

### 4.2 `doctor` 与 `recover` 的区别

| | `envsync doctor` | `envsync recover` |
|---|---|---|
| 是否修改任何东西 | **绝不** | 会写文件、会改 journal 状态 |
| 底层调用 | `RecoveryEngine::diagnose()` | `RecoveryEngine::recover_all()` |
| 退出码 | 恒为 0（读 `data.healthy` 判断健康） | 成功 0；需要人工介入时 1（`recovery.manual_required`） |
| 何时自动运行 | 从不自动运行 | **`sync` 启动时自动运行一次** |
| 典型用途 | 出事后第一件事：看清现场 | 确认建议合理后再执行 |
| 幂等 | 天然幂等（只读） | 是：连续运行两次得到相同最终状态 |

**顺序永远是先 `doctor` 后 `recover`。** `doctor` 的 `data.recovery[]` 会给出每个未完成操作
的 `suggestion`：

| `suggestion` | 含义 | `recover` 会做什么 |
|---|---|---|
| `nothing` | 已是终态 | 跳过 |
| `abort_staged` | 尚未发布 | 清理暂存文件，迁移到 `aborted` |
| `reconverge` | 已发布，需继续本地收敛 | 重新应用未生效的动作，走到 `completed` |
| `continue_rollback` | 正在回滚 | 按 receipt 逆序继续 |
| `manual` | 需要人工处理 | 记录错误，**不覆盖任何文件** |

测试 `doctor_only_reports_and_never_repairs`、`recovery_is_idempotent_on_the_converging_path`、
`recovery_is_idempotent_on_the_manual_conflict_path` 分别锁定了这三条性质。

### 4.3 恢复算法的三条判据

恢复的判据是「**目标文件当前的内容摘要**」，而不是「上次运行的内存状态」——这正是恢复能够
幂等的原因。对计划里的每个动作：

```text
                    读取目标文件当前摘要 current
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
current == expected_after  current == expected_before   两者都不等
        │                     │                     │
   【已生效】             【未生效】              【已偏离】
        │                     │                     │
        ▼                     ▼                     ▼
  标记 applied，          重新应用该动作，       立即停止整个恢复，
  跳到下一个动作           落新的 receipt        记录 recovery.manual_required，
                                                 迁移到 published_not_converged
```

对应实现：`RecoveryEngine::classify` → `ActionProgress::{Applied, NotApplied, Diverged}`。

「已偏离」的含义是：**在中断期间，有人（或有别的程序）改过这个文件。** 它既不是我们动手前
的样子，也不是我们想写成的样子。此时任何自动化选择都可能销毁用户的真实工作，所以引擎选择
**停手**——这条行为由测试 `diverged_target_stops_and_never_overwrites_user_changes` 锁定。

注意判据顺序：先比 `expected_after` 再比 `expected_before`。当一个动作的前后摘要相同
（内容未变）时，它会被判为「已生效」，这是正确的——无事可做。

### 4.4 「两者都不等」时的人工操作指引

`recover` 停在 `published_not_converged`，`diagnostics[0].code` 为 `recovery.manual_required`，
消息里带资源标识和当前摘要短表示。按下面的顺序做，**每一步做完再看下一步**。

**第 1 步：看清现场，不要动任何文件。**

```bash
CFG=/home/YOUR_USER/.config/envsync/envsync.yaml
envsync doctor --config "$CFG" --json | jq '.data.recovery'
```

记下 `operation`、`state`、`reason` 里提到的资源标识。

**第 2 步：找到该资源的备份与收据。**

```bash
# 备份文件（operation-id 去掉连字符，resource-id 的 / 换成 __）
OP=6f0f0a5c-1f2e-4a3b-9c8d-7e6f5a4b3c2d
ls -l /home/YOUR_USER/.config/envsync/.envsync/backups/${OP//-/}/
```

`journal.db` 的 `receipts` 表里记录了这个动作的 `original_digest`（我们动手前的内容）与
`applied_digest`（我们想写成的内容）。备份文件的内容就是 `original_digest` 对应的字节。

**第 3 步：把三份内容摆在一起对比。**

| 来源 | 代表什么 |
|---|---|
| 备份文件 | 我们动手**之前**目标文件的原样 |
| 目标快照里的期望内容 | 我们**想写成**的样子 |
| 磁盘上的当前文件 | 中断期间被改成的样子——**唯一可能包含他人新工作的版本** |

先把当前文件复制到授权根**之外**的位置留档，再做任何决定：

```bash
cp /home/YOUR_USER/.zshrc /tmp/zshrc.diverged.$(date +%s)
```

**第 4 步：三选一。**

- **A. 当前文件的改动值得保留。** 手工把目标快照里的期望内容合并进当前文件，然后：

  ```bash
  envsync rollback --config "$CFG" --operation "$OP"   # 把这次操作标记为已回滚
  envsync capture  --config "$CFG"                     # 把合并后的现状捕获成新快照
  envsync plan     --config "$CFG"
  envsync sync     --config "$CFG" --plan <新的 plan-id>
  ```

  注意：若目标文件当前摘要与收据里的 `applied_digest` 不符，`rollback` 会以
  `platform.rollback_refused` **拒绝执行**——这正是它该做的。此时先把文件恢复成备份内容
  （`cp <备份> <目标>`）再重试 rollback，或者直接走方案 C。

- **B. 当前文件的改动可以丢弃，要向前收敛到目标快照。** 用备份把目标文件还原成动手前的
  样子，让判据重新落到「未生效」，然后重跑恢复：

  ```bash
  cp /home/YOUR_USER/.config/envsync/.envsync/backups/${OP//-/}/shell__zsh__main \
     /home/YOUR_USER/.zshrc
  envsync recover --config "$CFG"
  envsync status  --config "$CFG"
  ```

- **C. 当前文件的改动可以丢弃，要退回到同步之前。** 同样用备份还原目标文件，然后：

  ```bash
  cp /home/YOUR_USER/.config/envsync/.envsync/backups/${OP//-/}/shell__zsh__main \
     /home/YOUR_USER/.zshrc
  envsync rollback --config "$CFG" --operation "$OP"
  ```

  回滚只让**本地**退回，后端 Ref 不会倒退（M0 没有 Ref 回退能力，也不应该有）。之后
  `capture` → `plan` → `sync` 重新走一遍。

**第 5 步：确认回到可预测状态。**

```bash
envsync status --config "$CFG"   # 期望 clean 或 drifted，不应再是 published_not_converged
envsync doctor --config "$CFG" --json | jq '.data.healthy'
```

**永远不要**手工修改 `journal.db` 来「让状态好看」。状态机是恢复的唯一事实来源，改坏它之后
再发生的中断将无法自动恢复。

### 4.5 显式回滚

`envsync rollback --operation <id>` 用于反悔一次**已完成**的同步，它同样走完整的日志与收据
路径，而不是绕过 journal 直接改文件。

- 只接受处于 `completed`、`applying`、`published_not_converged`、`rolling_back` 的操作，
  其他状态返回 `rollback.failed`；
- 按 receipt **逆序**还原；
- 目标当前摘要与 `applied_digest` 不符时**拒绝**（可能已被外部修改）；
- 备份缺失或备份内容摘要与 `original_digest` 不符时**拒绝**，保留可诊断现场
  （测试 `rollback_refused_when_backup_is_missing`、`rollback_refused_when_backup_content_is_corrupted`）。

拒绝不是失败模式，是保护模式：写一个可能错误的结果，比停下来叫人糟糕得多。

---

## 5. 威胁边界与安全保证

M0 的信任边界、提供的保证、以及**明确不提供**的保证，全部集中在
[`docs/security-model.md`](security-model.md)。在把真实凭据交给 EnvSync 之前请先读它。

---

## 6. 版本号与升级兼容策略

### 6.1 九个版本号

EnvSync 不使用「一个全局版本号」，而是让每一层各自携带版本，这样一次演进只需要动真正变化
的那一层。

| # | 版本号 | 常量 / 位置 | 当前值 | 出现在哪里 |
|---|---|---|---|---|
| 1 | State Root 格式 | `STATE_ROOT_FORMAT_VERSION`（`envsync-domain::object`） | 1 | State Root 对象首字段 |
| 2 | Snapshot 格式 | `SNAPSHOT_FORMAT_VERSION`（`envsync-domain::snapshot`） | 1 | Snapshot Body 与 SnapshotSignature 首字段 |
| 3 | Ref 格式 | `REF_FORMAT_VERSION`（`envsync-domain::snapshot`） | 1 | `refs/<workspace>.cbor` 首字段 |
| 4 | Plan 格式 | `PLAN_FORMAT_VERSION`（`envsync-domain::plan`） | 1 | Plan 绑定原像首字段 |
| 5 | Conflict 格式 | `CONFLICT_FORMAT_VERSION`（`envsync-domain::object`） | 1 | Conflict 对象首字段（M0 只定义 schema） |
| 6 | 配置版本 | `CONFIG_VERSION`（`envsync-core::config`） | 1 | YAML 的 `version:` |
| 7 | 存储 schema | `SCHEMA_VERSION`（`envsync-storage::migrations`） | 1 | `journal.db` / `draft.db` 的 `schema_meta` 表 |
| 8 | CLI JSON schema | `JSON_SCHEMA_VERSION`（`envsync-cli::output`） | 1 | JSON 信封的 `schema_version` |
| 9 | 后端目录格式 | `FORMAT_MARKER`（`envsync-backend::local`） | `envsync-backend-format=1` | 后端根的 `format` 文件 |

### 6.2 未知版本一律拒绝

规则：**读到不认识的版本号就停下来报错，绝不静默降级、绝不「尽力解析」。**

| 层 | 遇到未知版本时 | 错误码 |
|---|---|---|
| State Root / Snapshot Body / Ref / Plan | `CborError::UnsupportedFormatVersion { found, supported }` | `codec.invalid` |
| 配置 | `ConfigError::UnsupportedVersion` | `config.unsupported_version` |
| 存储 schema（更高版本） | `JournalError::SchemaTooNew { found, supported }`，**拒绝打开数据库** | `storage.schema_too_new` |
| 后端目录格式 | `BackendError::FormatMismatch { expected, found }` | `backend.format_mismatch` |

四条理由：

1. **内容寻址的唯一性依赖它。** 摘要是对「某个具体编码」的承诺。如果旧版本可以「忽略新增
   字段」地解析新对象，同一个逻辑状态就会有两个不同的摘要，去重、校验和（M2 的）反回滚
   检查全部失效。
2. **静默降级会丢语义，而丢掉的往往正是安全语义。** 假设 M2 给 `ResourcePolicy` 加了
   `require_vault: true`，旧版本忽略这个字段的后果是把本该加密的秘密以明文写盘。「不认识
   就不做」是这里唯一可接受的默认。
3. **旧程序改写新 schema 会造成不可逆的数据损坏。** 这就是 `SchemaTooNew` 直接拒绝打开
   数据库、而不是只读降级的原因：一次误写就可能让 journal 不再可解释，而 journal 是崩溃
   恢复的唯一事实来源。
4. **拒绝是可诊断的，静默降级不是。** 前者给出 `found` / `supported` 两个数字，用户立刻知道
   该升级哪一端；后者会在几天后以「文件内容莫名其妙不对」的形式暴露。

### 6.3 M1–M4 各自会动哪些版本号

下表基于各里程碑的实施计划。它说明**升级时哪些数据需要迁移**、哪些可以原样带走。

| 里程碑 | 会动的版本号 | 具体变化 | 对 M0 数据的影响 |
|---|---|---|---|
| **M1**（Git 后端、Profile、结构化合并） | ①State Root、②Snapshot、⑤Conflict、⑦存储 schema、⑧CLI JSON | 新增 Profile 与 Conflict 的 domain schema；`journal.db` 新增 `profiles`、`conflicts` 表；CLI JSON 升为 v2 并**保留 v1 reader** | M0 的对象需要通过迁移测试升级；M0 的 CLI JSON 调用方在 v1 reader 保留期内不受影响 |
| **M2**（Vault、设备身份、反回滚） | ②Snapshot（元数据新增 `envsync.` 前缀的工作区级键）、⑦存储 schema，新增 sealed 对象格式版本 | 头快照的 **Vault 索引背书**（`envsync.vault.attestation`）开始强制校验，错误码 `snapshot.signature_invalid`；快照标识本身的签名对象仍是审计用途，理由见 `docs/security/vault-format.md` §5.4。新增 Membership Event / Key Envelope / Sealed Secret 三类对象；新增本地检查点表 | **`DeviceId` 需要重新派生**：输入从设备种子换成 `X25519 ‖ Ed25519` 公钥（ADR-0002）。这被记录为一次显式的设备重新注册，而不是静默改写历史。类型、宽度与编码都不变 |
| **M3**（包管理器、Agent Bundle） | ①State Root（新增包与 Bundle 条目种类）、⑦存储 schema、⑧CLI JSON | 新增包身份 / 版本策略 / Agent Bundle manifest 的 schema；manifest 自带最低 EnvSync 版本要求 | 纯文件资源的 State Root 语义不变；新种类只是新增条目 |
| **M4**（桌面端、Gist、插件） | ⑦存储 schema、⑧CLI JSON，新增 Gist sealed bundle 格式版本与插件 RPC schema 版本 | 插件 RPC 独立版本化，host 支持一个 major 的两个 minor，未知 method/version 拒绝；Gist bundle 解包先检查版本与计数再验摘要 | M4 计划包含「从 M0、M1、M2、M3 fixture 逐版本升级」的 E2E；迁移失败时事务回滚并保留可恢复备份 |

三条贯穿全程的约定：

- **只增不改。** 稳定错误码（`CoreError::code`、`PlatformError::code`、`JournalError::code`、
  `BackendError::code`、`DraftError::code`、`ConfigError::code`）与 CLI 退出码只能新增，
  不能重命名或改变语义。
- **降级启动只读阻塞。** 新版本写过的数据不允许被旧版本改写（M4 计划明确要求）。
- **`DeviceId` 的宽度与编码从 M0 起就是终态。** 这是 ADR-0002 的全部意义：M2 只换 `derive`
  的输入，不破坏 schema。

---

## 7. 故障排查手册

### 7.1 退出码速查

| 码 | 症状 | 可能原因 | 处理 |
|---|---|---|---|
| **0** | 命令成功 | — | `plan`/`doctor` 恒为 0，健康与否请读 `data.blocked` / `data.healthy` |
| **1** | 一般错误 | 配置读不到、I/O 失败、需要人工处理 | 读 `diagnostics[0].code`，对照下表 |
| **2** | 用法错误 | 缺参数、参数值非法、未知子命令 | `envsync <子命令> --help` |
| **10** | `backend.cas_conflict` | 别的设备在你 `plan` 之后先发布了 | **本地零变更**，安全。`capture` → `plan` → `sync` 重来 |
| **11** | `plan.stale` / `plan.not_found` | 计划生成后目标被改动，或计划标识写错 / 草稿库已清 | 重新 `plan` 再 `sync`。两者补救动作相同，故共用一个码 |
| **12** | `plan.blocked` | 计划里有阻塞诊断 | 读 `diagnostics[]`，按资源逐个修好，再重新 `plan` |
| **13** | `sync.conflicted` | 存在未解决的合并冲突（M1） | 先 `envsync conflicts resolve`；**本地文件与远端 Ref 都没有被改动** |
| **14** | `checkpoint.*`（M2） | **检测到后端回滚或分叉**：远端给出的 revision / 成员链头 / 密钥纪元相对本机检查点倒退了 | **不要重试**，这是一次安全事件。读路径与写路径都会以它失败，且**后端 revision 一格都不会被推进**。先用 `envsync security checkpoint` 看本机信任根，再确认后端是不是被回退或替换过 |
| **15** | `platform.secure_store_*`（M2） | 系统凭据库不存在 / 被锁定 / 拒绝访问 | 解锁凭据库或授予访问权限后重试。**绝不会**回退到明文存储 |
| **20** | `sync.published_not_converged` | 后端头已前进但本地没跟上 | `doctor` 看建议 → `recover` 或 `rollback`。见 §2.4、§4.4 |

### 7.2 症状 → 原因 → 处理

| 症状 | 错误码 | 可能原因 | 处理 |
|---|---|---|---|
| `sync` 退出 10，抱怨 CAS 冲突 | `backend.cas_conflict` | 另一台设备在你的 `base_revision` 之后发布了新头 | 无需担心本地：CAS 在任何本地写入之前。`capture` → `plan` → `sync` 重来 |
| `sync` 退出 11，说计划已失效 | `plan.stale` | `plan` 与 `sync` 之间目标文件被外部修改；或后端 revision 前进了 | 重新 `plan`。注意：计划**不会**因为「审阅花了三分钟」而失效——时刻不参与 Plan ID（ADR-0003） |
| `sync` 退出 11，说找不到计划 | `plan.not_found` | 计划标识抄错；或换了 `state_dir`；或草稿库被清空 | 重新 `plan` 取新标识 |
| `sync` 退出 12 | `plan.blocked` | 某资源观察为 `unreadable` / `unsupported` / `excluded` | 逐条读 `diagnostics[].resource` 与 `message`；修好权限或目标类型后重新 `plan`。这三种状态**不会**产生任何写入，更不会被推断为删除 |
| `sync` 退出 20 | `sync.published_not_converged` | 后端已发布，本地应用中断或失败 | 见 §2.4 与 §4.4，先 `doctor` 后决策 |
| 命令挂住约 5 秒后报「工作区被锁定」 | `backend.locked` | 另一个进程正持有 per-workspace 发布锁；或上一个持有者被强杀留下锁文件 | 有界重试上限约 5 秒（1000 次 × 5 ms）。超过 30 秒未更新的锁文件会被自动回收后重试。仍然失败时确认没有其他 `envsync sync` 在跑，再检查 `<backend.path>/locks/<workspace-uuid>.lock` |
| 打开后端就报格式标记不匹配 | `backend.format_mismatch` | `backend.path` 指向了别的目录（不是 EnvSync 后端）；或后端由更高版本写过 | 核对 `backend.path`。`<backend.path>/format` 的内容必须**逐字节**等于 `envsync-backend-format=1`（含结尾换行）。**不要手工改这个文件**——它是版本闸门，不是配置项 |
| 报「授权根不可用」 | `platform.root_unavailable` | 根目录不存在、被卸载、无权限；或是网络挂载尚未就绪 | `doctor` 会单独列出每个根的可访问性。确认路径存在且可读写。根路径必须是**绝对路径**（否则 `config.root_not_absolute`） |
| 报「授权根不是目录」 | `platform.root_not_directory` | 根路径指向了一个文件 | 改配置 |
| 报「未注册的授权根别名」 | `platform.unknown_root` / `config.unknown_root` | 资源的 `root:` 写了 `roots:` 里没有的别名 | 对齐别名拼写 |
| 报「拒绝穿越符号链接」 | `platform.symlink_rejected` | 目标路径的某一段（或最终文件）是符号链接 | **不要**通过加符号链接来「绕过」。把授权根直接指向真实目录，或把资源的 `target` 改成真实路径 |
| 回滚被拒绝，说备份不可读 | `platform.rollback_refused` | `<state_dir>/backups/...` 下的备份被删除或移动 | 备份是唯一的字节级退路。若确实丢失，只能走 §4.4 的人工流程：手工确认目标文件内容后重新 `capture` → `plan` → `sync`。**拒绝覆盖是正确行为**，不要设法跳过它 |
| 回滚被拒绝，说备份内容摘要不符 | `platform.rollback_refused` | 备份文件被外部改写；或磁盘位翻转 | 同上。摘要不符意味着我们不知道备份里是什么，写回去等于随机赋值 |
| 回滚被拒绝，说目标当前摘要与收据不一致 | `platform.rollback_refused` | 同步之后你又手工改过这个文件 | 先把当前文件另存留档，再决定是保留手改（放弃回滚，直接 `capture`）还是丢弃（把文件恢复成 `applied_digest` 对应内容后重试） |
| 写入前报「观察已过期」 | `platform.stale_observation` | 从 preflight 到真正 rename 之间目标被改动 | 这是防止静默覆盖的最后一道闸门。重新 `plan` 即可 |
| 读文件报「目标不是普通文件」 | `platform.not_a_file` | `target` 指向了目录、设备文件或 FIFO | 改配置里的 `target` |
| 报「目标大小超过上限」 | `platform.too_large` | 文件超过 `policy.max_bytes`（默认 16 MiB） | **绝不截断**是刻意设计。提高该资源的 `policy.max_bytes`，或把大文件移出同步范围 |
| 报「数据库 schema 版本高于本版本支持」 | `storage.schema_too_new` | 用旧版 EnvSync 打开了新版写过的 `state_dir` | 升级 EnvSync。**不要**删掉 `journal.db` 来「解决」问题——那会丢掉全部恢复凭据 |
| 报「非法状态迁移」 | `storage.illegal_transition` | 出现即说明实现有 bug，或 `journal.db` 被手工改过 | 保留 `journal.db` 与 `backups/` 原样并报告问题；不要继续在这个 `state_dir` 上操作 |
| 报「对象内容损坏」 | `backend.corruption` / `draft.corruption` | 后端对象或草稿库内容与其摘要不符（外部工具改写、磁盘错误） | 内容寻址自校验拦下了它，**损坏内容绝不会流向用户文件**。定位到具体对象后从其他设备重新同步 |
| `device revoke` 撤销本机自己被拒 | `rotation.cannot_revoke_self`（M2） | 撤销自己会产生一个由**非成员**签出的头快照，读路径要求背书由当前成员签出，工作区会就此永久锁死 | 在另一台管理员设备上撤销它；本机随后用 `envsync device forget` 清理身份 |
| `vault list` 报 `vault.index_missing` | `vault.index_missing`（M2） | 当前头快照上没有 Vault 索引指针，但本机的密钥环/检查点证明这台设备加入过这个 Vault | 这是「读不到」而不是「里面是空的」。密封对象是内容寻址的，多半仍在后端上：从另一台正常设备跑任意一条 `vault set` / `vault delete` 即可重建指针 |
| 读 Vault 报 `snapshot.signature_invalid` | `snapshot.signature_invalid`（M2） | 头快照的 Vault 索引背书缺失，或不是由当前成员链上的设备签出的 | **后端交给你的索引来路不明**，不要重试。核对后端是否被第三方写过；必要时从可信设备重新发布一次 Vault |
| 报「引用了缺失的对象」 | `object.missing` | 后端里缺少目标快照可达的某个 Blob | 通常是后端被部分删除。从仍然完整的设备重新 `capture` → `sync` |
| 配置改了却不生效 | `config.unknown_field` | 字段名写错。未知字段是**拒绝**而不是忽略 | 对照 `examples/workspace.yaml` |
| `target` 被拒绝 | `config.invalid_target` / `platform.invalid_target` | 绝对路径、`..`、`.`、空段、反斜杠、冒号、UNC 前缀、Windows 保留设备名、以空格或点结尾的段、超长（>1024 字节）或超段数（>32） | 这些限制在三大平台上**一致**生效，好让同一份配置表达完全相同的意图 |
| 用 `generated_include` | `config.mode_not_supported` | 该模式由适配器拆成「Full File + Managed Block」两个资源实现，不作为独立模式暴露 | 见 `docs/adapters.md`；`structured_merge` 自 M1 起可用，但需同时声明 `policy.structured_format` |
| Managed Block 报 marker 异常 | `render.*` | 用户文件里的 marker 重复、嵌套、顺序颠倒、缺一端或格式非法 | **绝不猜测修复**：marker 异常通常意味着人工编辑冲突或文件损坏。手工整理该文件的 `>>> envsync:` / `<<< envsync:` 区块后重新 `plan` |
| `--json` 输出无法被 `jq` 解析 | — | 有日志混进了 stdout | 不应发生：日志 writer 固定为 stderr。若复现请报告，并附 `RUST_LOG` 取值 |

### 7.3 排查时的通用顺序

```text
1. envsync status --config <cfg> --json     ← 先看整体状态与 unfinished
2. envsync doctor --config <cfg> --json     ← 只读体检，绝不修改
3. 读 diagnostics[0].code，对照 §7.2
4. 需要动手时：先备份现场（cp 到授权根之外），再执行 recover / rollback
5. 再跑一次 status，确认回到 clean 或 drifted
```

提高日志级别用 `-v`（info）、`-vv`（debug）、`-vvv`（trace），或
`RUST_LOG=envsync_core=debug`。无论怎么设置，日志都写 **stderr**，不会破坏 `--json` 的
「stdout 只有一行 JSON」契约。
