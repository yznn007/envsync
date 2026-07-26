# EnvSync 命令行（M0 + M1）

EnvSync 把开发环境中**被显式声明**的文件，安全地在多台设备之间同步。命令行是
`envsync-core::EnvSyncService` 的一层薄壳：所有安全决策（计划、策略、日志、回滚）
都在核心层完成，CLI 只负责解析参数、渲染结果和把错误映射成稳定的退出码。

三条贯穿全文的约定：

- **任何写入都必须先出现在一份不可变的计划里。** 没有 `plan` 就没有 `sync`。
- **`--json` 时 stdout 只有一行 JSON。** 日志、进度、诊断一律写 stderr。
- **存在未解决的合并冲突时，`sync` 一票否决**（退出码 13），本地文件与远端 Ref 都不变。

---

## 1. 命令一览

```text
# M0
envsync init      --config <path> [--device-name <name>] --backend-path <path> [--discover]
envsync capture   --config <path>
envsync plan      --config <path>
envsync sync      --config <path> --plan <plan-id>
envsync status    --config <path>
envsync rollback  --config <path> --operation <id>
envsync doctor    --config <path>
envsync recover   --config <path>

# M1 新增
envsync fetch     --config <path>
envsync merge     --config <path>
envsync conflicts list    --config <path>
envsync conflicts show    --config <path> --conflict <conflict-id>
envsync conflicts resolve --config <path> --conflict <conflict-id>
                          (--ours | --theirs | --file <path> | --delete)
envsync profile   explain --config <path>
envsync adapters  list     --config <path> [--all]
envsync adapters  discover --config <path>
```

全局参数（放在子命令前后都可以）：

| 参数 | 默认 | 说明 |
|---|---|---|
| `--json` | 关 | 以单行 JSON 输出结果；日志与诊断写 stderr |
| `--schema-version <VERSION>` | `2` | JSON 契约版本：`2`（含 M1 新字段）或 `1`（M0 字段集合）。范围之外是**用法错误**（退出码 2），绝不静默按某个版本输出 |
| `-v` / `--verbose` | — | 提高日志级别，可重复：`-v` 为 info，`-vv` 为 debug，`-vvv` 为 trace |
| `--help` / `--version` | — | 帮助与版本 |

日志级别也可以用 `RUST_LOG` 覆盖（例如 `RUST_LOG=envsync_core=debug`）；无论怎么设置，
日志的 writer 都固定为 stderr。

`--schema-version 1` 只影响**输出形状**（见 [§2.3](#23-schema-版本与降级)），不改变命令
行为。M1 新增的五组命令（`fetch` / `merge` / `conflicts` / `profile` / `adapters`）在 v1 里没有定义的形状，因此以 `--schema-version 1` 调用它们会
**报错**（错误码 `recovery.manual_required`，退出码 1）而不是输出一个 v1 读者无法
解释的信封。

### 1.1 `init`

初始化一个新工作区：生成配置文件、后端目录与本地状态目录。

| 参数 | 必需 | 说明 |
|---|---|---|
| `--config <path>` | 是 | 要生成的配置文件路径；**已存在时报错而不覆盖** |
| `--backend-path <path>` | 是 | 本地后端目录；不存在时创建 |
| `--device-name <name>` | 否 | 设备显示名；省略时取 `ENVSYNC_DEVICE_NAME` / `HOSTNAME` / `COMPUTERNAME`，都取不到时用 `envsync-device` |
| `--discover` | 否 | 用内建适配器发现本设备上该管理的资源，并写进生成的配置 |

不加 `--discover` 时生成的配置里 `resources` 为空——空工作区是合法的，随后由你把要管理
的文件填进去（`envsync adapters discover` 可以生成一份建议）。

加了 `--discover` 时，初始化会立刻跑一次适配器发现并把结果写进同一个配置文件；
`data.discovered_resources`（schema v2 起）给出写进去了几条。发现是**纯计算**——不读用户
文件、不联网，因此不会因为「这台机器上还没有 `.zshrc`」而失败：它声明的是「这台设备上
**应该**管哪些文件」，实际存不存在由 `capture` 观察。

### 1.2 `capture`

观察本机现状，生成一份快照草稿。**不写后端**：对象与快照都先落在本地草稿库，直到
`sync` 才发布。重复 `capture` 是幂等的：内容没变就不会生成新草稿。

本机读不到某个资源时，`capture` 会**沿用上一版快照中的内容**并留下一条 warning 级
诊断——「观察不到」永远不等于「删掉它」。

### 1.3 `plan`

读取后端 Ref、本地草稿头与本机观察结果，生成一份**不可变**计划并存入草稿库。
计划同时绑定目标快照、后端 revision 和每个资源的内容摘要，因此「生成计划之后文件被
外部改动」一定会被后续的新鲜度检查抓住。

计划里存在阻塞诊断时，`plan` 本身仍以退出码 0 结束（它只是一次预演），但 `data.blocked`
为 `true`，随后的 `sync` 会以退出码 12 拒绝应用。

计划针对的是**投影后**的目标状态：`data.device_view`（schema v2 起）给出本设备视图的
标识。两台设备的这个值相同 ⟺ 它们应当收敛到完全相同的内容。详见
[设备 Profile 与投影](profiles.md)。

### 1.4 `sync`

应用指定计划。执行顺序：

1. **未解决的合并冲突一票否决**（退出码 13）——这条检查排在最前面，因此之后的每一步
   都还没发生：本地文件与远端 Ref 都不变；
2. 自动运行崩溃恢复；
3. 重新观察、重新计划，与提交的 `--plan` 比对，不一致即判定失效（退出码 11）；
4. 上传目标快照可达的全部对象；
5. CAS 发布后端 Ref（冲突退出码 10，此时**一个本地字节都没写**）；
6. 逐动作应用并验证，任一动作失败则按逆序回滚。

| 参数 | 必需 | 说明 |
|---|---|---|
| `--plan <plan-id>` | 是 | `envsync plan` 输出的 64 位十六进制计划标识 |

### 1.5 `status`

汇总工作区状态，区分五种整体状态：

| 状态 | 含义 |
|---|---|
| `clean` | 本机与目标快照一致，且没有未完成操作 |
| `drifted` | 存在需要应用的变更 |
| `conflicted` | 存在未解决的合并冲突，**或**存在阻塞诊断，需要人工处理 |
| `published_not_converged` | 后端头已前进但本地没跟上，必须 `recover` 或 `rollback` |
| `backend_unreachable` | 联系不上后端；报告的是本地记录的**上次已知状态** |

`data.open_conflicts`（schema v2 起）给出未解决的合并冲突数量。

#### 后端不可达时的降级

读不到后端 Ref、且原因是**网络 / IO 不可达**（不是内容损坏）时，`status` 不再以退出码 1
失败，而是改用本地记录的上次已知 Ref 继续作答：

| 字段 | 不可达时 |
|---|---|
| `backend_reachable`（v2） | `false` |
| `last_known_revision_at_unix_ms`（v2） | 上次成功读到后端 Ref 的**本机**时刻；可达时为 `null` |
| `revision` / `head` | 上次已知的值，**不是**远端此刻的内容 |
| `state` | 恒为 `backend_unreachable` |

`state` 压过其余一切判定：不可达**绝不会**被报成 `clean`。把「远端连不上」说成「已收敛」
会让用户以为改动已经同步出去了，这比直接报错危险得多。

降级只发生在**只读诊断**上。任何会改动远端或依赖真实 revision 的命令
（`capture` / `plan` / `sync` / `fetch` / `merge`）仍然以退出码 1 失败：拿一份缓存的
revision 去做 CAS，等于把反回滚保护交给一个可能已经过期好几天的数字。

「够得着但内容坏了」的错误（`corruption`、`format_mismatch`、`invalid_ref`）照常失败——
用一份旧缓存把事故盖住，比直接报错糟得多。

上次已知 Ref 存在 `<state_dir>/last-known-ref.cbor`（canonical CBOR，临时文件 + rename
原子写入），每次成功读到远端 Ref 时更新。这个文件损坏或缺失只会让降级作答退回「没有上次
已知状态」，不会让任何命令失败。

### 1.6 `rollback`

按收据逆序还原一次操作。操作标识可以从 `status` 的 `unfinished`、`doctor` 的
`recovery`，或成功 `sync` 的 `data.operation` 里拿到。

备份缺失或摘要不符时**拒绝覆盖**，保留可诊断状态而不是猜一个结果。

### 1.7 `doctor`

只读体检：检查授权根可访问性、资源目标合法性、后端可达性、操作日志 schema，并给出
未完成操作的恢复建议。**绝不修改任何东西**。

因为体检本身总是成功的，`doctor` 恒以退出码 0 结束；判断健康与否请读 `data.healthy`，
不要读退出码。**后端不可达同样如此**：它是一条 `ok: false` 的 finding（`detail` 里带上
上次已知的 revision），而不是让整个命令失败的理由——体检的价值恰恰在于「网络断了也能把
本机情况说清楚」。

### 1.8 `recover`

显式触发崩溃恢复。`sync` 启动时会自动运行同一套流程，这个命令用于在不打算立刻同步时
先把未完成操作清理干净。恢复算法是幂等的：连续运行两次得到相同的最终状态。

### 1.9 `fetch`（M1）

读取远端引用与头快照，把可达对象拉进本地草稿库。

**只做「复制对象」**：不改本地 Ref、不生成快照、不碰用户文件。`fetch` 之后本机的可见
行为应当完全不变，变化只发生在下一次 `merge` 与 `plan`。

拉取范围是远端头的可达闭包：Snapshot Body → State Root → 各资源条目的 Blob。已在草稿库
里的对象会被跳过，因此重复 `fetch` 是廉价且幂等的（`data.objects` 为 `0`）。

### 1.10 `merge`（M1）

三方合并**本地草稿头**与**远端头**：

```text
fetch remote → find merge base → merge full states → 干净 ? 生成合并快照 : 只登记冲突
```

| `data.outcome` | 含义 | 生成快照 |
|---|---|---|
| `already_up_to_date` | 远端没有新内容，或本地已经领先 | 否 |
| `fast_forward` | 本地是远端的祖先：直接采用远端状态 | 否 |
| `merged` | 真正做了三方合并 | 是，`parents = [local, remote]`，并设为草稿头 |
| `conflicted` | 存在需要人工裁决的冲突 | **否** |

**冲突时 `merge` 的退出码仍然是 0**：它成功地完成了自己的工作——发现并登记了冲突，
这不是失败。退出码 13 只在你试图 `sync` 时出现。脚本应当读 `data.outcome`：

```bash
MERGED=$(envsync merge --config "$CFG" --json)
[ "$(echo "$MERGED" | jq -r '.data.outcome')" = "conflicted" ] && { echo "$MERGED" | jq -r '.data.conflicts[]'; exit 1; }
```

合并冲突时**不**生成快照、**不**设草稿头、**不**推进远端 Ref、**不**改任何本地文件；
冲突 marker 也绝不写进用户内容。详见 [冲突处理](conflicts.md)。

### 1.11 `conflicts`（M1）

查看与裁决合并冲突。三条子命令**只读写本地冲突索引与草稿库**，不联网、不碰用户文件，
因此**离线可用**。

```text
envsync conflicts list    --config <path>
envsync conflicts show    --config <path> --conflict <conflict-id>
envsync conflicts resolve --config <path> --conflict <conflict-id>
                          (--ours | --theirs | --file <path> | --delete)
```

| 参数 | 说明 |
|---|---|
| `--conflict <conflict-id>` | 冲突标识（64 位十六进制），由 `merge` 或 `conflicts list` 输出 |
| `--ours` | 采用**本地**一侧的内容 |
| `--theirs` | 采用**远端**一侧的内容 |
| `--file <path>` | 采用该文件的内容（人工合并结果），会被存成新的 Blob |
| `--delete` | 确认删除该资源；这是**唯一**能让资源消失的裁决 |

四个裁决开关**互斥**，必须给出且只能给出一个。一个都不给是**用法错误**（退出码 2）——
EnvSync 不会替你挑一个默认值。

`--ours` / `--theirs` 指向的那一侧是删除时会报错（`recovery.manual_required`）：
「采用远端**的内容**」在远端根本没有内容时没有意义，请改用 `--file` 或 `--delete`。

`conflicts show` **不输出文件正文**，只给三侧的内容标识与结构性诊断（行区间 / JSON
Pointer / 键路径）。

### 1.12 `profile explain`（M1）

解释本设备 Profile 与每个资源的投影结论。

```text
envsync profile explain --config <path>
```

输出包含编译期探测的 `os` / `arch`（**配置层不能覆盖**）、`hostname`、`tags`、
`capabilities`、设备标识，以及逐资源的投影诊断。`✓` 表示该资源在本设备视图里，
`·` 表示不在——**不在视图里的资源不会被写，也不会被删**。

`data.device_view` 与 `plan` 的 `data.device_view` 是同一个值。完整的诊断种类表与配方
见 [设备 Profile 与投影](profiles.md)。

### 1.13 `adapters`（M1）

查看内建适配器，或让它们为本设备生成资源配置。

```text
envsync adapters list     --config <path> [--all]
envsync adapters discover --config <path>
```

**`adapters list`** 列出每个内建适配器的 ID、展示名、版本、支持平台、所需 capability、
默认模式，以及它在本设备授权根下的**目标资源**（资源标识、根别名、相对目标、模式、处置、
结构化格式）。默认按当前设备 Profile 过滤——缺少 `pwsh` 能力的机器不会看到 PowerShell
适配器，没打 `git-xdg` 标签的机器不会看到 `~/.config/git/config`。`--all` 列出全部，
包括本设备用不上的。

**`adapters discover`** 对当前设备跑一次 `discover_all`，输出**可直接粘贴进配置**的
`resources:` YAML 片段：

```console
$ envsync adapters discover --config envsync.yaml
发现 7 个可管理的资源（设备 5e214746…）。
把下面这段粘贴进配置文件的顶层即可：

resources:
- id: shell/zsh/zshrc
  root: home
  target: .zshrc
  mode: managed_block
  disposition: managed
  policy:
    unix_mode: '0644'
...
```

片段由与配置写出时**同一套线格式类型**序列化，因此粘贴之后一定能被解析回来；取默认值的
策略字段（`max_bytes`、`line_ending`、`secret`）被省略，解析时会取回同一个默认值。

两条命令都**只列配置里声明过的授权根**下的资源：没有声明 `system` 根时，系统级 Git 配置
（只观察、绝不写入）不会出现，命令会留一条 `adapters.system_root_not_declared` 的 info
诊断说明这件事。这是**推荐**配置，理由见 [内建适配器](adapters.md)。

想在初始化时一步到位，用 `envsync init --discover`。

---

## 2. JSON 契约

`--json` 时 stdout 是**恰好一行** JSON，形状固定：

```json
{
  "schema_version": 2,
  "command": "plan",
  "status": "ok",
  "data": { },
  "diagnostics": [
    {
      "severity": "blocking",
      "code": "resource.unreadable",
      "resource": "shell/zsh/main",
      "message": "目标是目录，无法作为文件读取"
    }
  ]
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `schema_version` | 整数 | 契约版本，当前为 `2`；语义不兼容变化时才递增 |
| `command` | 字符串 | 命令名，见下 |
| `status` | 字符串 | `ok` 或 `error` |
| `data` | 对象或 `null` | 命令专属数据；`status` 为 `error` 时恒为 `null` |
| `diagnostics` | 数组 | 诊断列表；失败时至少有一条，`code` 即核心层的稳定错误码 |

`command` 的取值：`init` / `capture` / `plan` / `sync` / `status` / `rollback` /
`doctor` / `recover` / `fetch` / `merge` / `conflicts.list` / `conflicts.show` /
`conflicts.resolve` / `profile.explain` / `adapters.list` / `adapters.discover`。
子命令用 `.` 连接。

`diagnostics[].severity` 取值为 `blocking` / `warning` / `info`，`resource` 与具体资源
无关时为 `null`。

### 2.1 各命令的 `data`

**`init`**

```json
{
  "workspace": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
  "device_name": "laptop",
  "device": "eb4a433c…",
  "config_path": "/path/to/envsync.yaml",
  "backend_kind": "local",
  "state_dir": "/path/to/.envsync",
  "discovered_resources": 0
}
```

`discovered_resources`（**schema v2 起新增**）是 `--discover` 写进配置的资源数量；
没加该开关时恒为 `0`。`--schema-version 1` 时该字段被移除。

**`capture`**

```json
{
  "snapshot": "5be47e77…",
  "state_root": "541725ed…",
  "changed": true
}
```

**`plan`**

```json
{
  "plan": "487a3c78…",
  "target_snapshot": "5be47e77…",
  "base_revision": 0,
  "next_revision": 1,
  "action_count": 1,
  "blocked": false,
  "device_view": "4b1d7c02a9…",
  "actions": [
    {
      "resource": "shell/zsh/main",
      "kind": "replace_file",
      "target": "home:.zshrc",
      "risk": "medium",
      "backup": "required",
      "rollback": "exact",
      "sensitive": false
    }
  ]
}
```

`target` 永远是「授权根别名 + 相对路径」，**绝不是绝对路径**：计划要能在设备之间被
审阅比较，也不该泄露本机布局。

`kind` 取值 `delete_file` / `create_file` / `replace_file` / `update_managed_block`；
`risk` 取值 `low` / `medium` / `high`；`backup` 取值 `required` / `not_applicable`；
`rollback` 取值 `exact` / `compensating` / `none`。

`device_view`（**schema v2 起新增**）是本设备投影视图的标识——计划针对的正是投影后的
目标状态。`--schema-version 1` 时该字段被移除。

**`sync`**

```json
{
  "outcome": "completed",
  "operation": "6f0f0a5c-1f2e-4a3b-9c8d-7e6f5a4b3c2d",
  "applied": 1,
  "published": true
}
```

`outcome` 为 `no_op` 时表示无事可做，`operation` 为 `null`。

**`status`**

```json
{
  "workspace": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
  "device": "eb4a433c…",
  "backend_kind": "local",
  "backend_reachable": true,
  "last_known_revision_at_unix_ms": null,
  "revision": 1,
  "head": "5be47e77…",
  "draft_head": null,
  "state": "clean",
  "pending_actions": 0,
  "open_conflicts": 0,
  "resources": [
    {
      "resource": "shell/zsh/main",
      "observed": "present",
      "disposition": "managed",
      "needs_action": false
    }
  ],
  "unfinished": []
}
```

`observed` 取值 `present` / `absent` / `unreadable` / `unsupported` / `excluded`；
`disposition` 取值 `managed` / `unmanaged` / `ensure_absent`，目标快照里没有该资源时
为 `null`。

`open_conflicts`（**schema v2 起新增**）是未解决的合并冲突数量；大于 `0` 时 `state`
必为 `conflicted`，且 `sync` 会以退出码 13 拒绝。`--schema-version 1` 时该字段被移除。

`backend_reachable` 与 `last_known_revision_at_unix_ms`（同为 **schema v2 起新增**）用于
后端不可达时的降级作答，语义见 [§1.5](#15-status)。`--schema-version 1` 时两者一并被移除
——v1 的读者没有理解「这是上次已知状态」的手段，与其给它一个看起来正常的 `revision`，
不如让形状与 M0 完全一致。

**`doctor`**

```json
{
  "healthy": true,
  "findings": [
    { "check": "后端可达性", "ok": true, "detail": "可读取 Ref（revision 1）" }
  ],
  "recovery": [
    {
      "operation": "6f0f0a5c-…",
      "state": "applying",
      "suggestion": "reconverge",
      "pending": 2,
      "reason": null,
      "notes": []
    }
  ]
}
```

`suggestion` 取值 `nothing` / `abort_staged` / `reconverge` / `continue_rollback` /
`manual`。

**`rollback` 与 `recover`**

```json
{
  "handled": 1,
  "operations": [
    {
      "operation": "6f0f0a5c-…",
      "before": "applying",
      "after": "rolled_back",
      "notes": ["按收据逆序还原 2 个动作"]
    }
  ]
}
```

**`fetch`**（**仅 schema v2**）

```json
{
  "revision": 7,
  "head": "5be47e77…",
  "objects": 12,
  "up_to_date": false
}
```

`head` 在远端从未发布过时为 `null`；`up_to_date` 为 `true` 表示本地已拥有远端头的全部
可达对象（此时 `objects` 为 `0`）。

**`merge`**（**仅 schema v2**）

```json
{
  "outcome": "conflicted",
  "local": "a1b2c3d4…",
  "remote": "5be47e77…",
  "base": "70a1c3e5…",
  "merged": null,
  "state_root": null,
  "resources": 9,
  "conflicts": ["3f8a1c05d2e7…", "a91b7e44c608…"]
}
```

| 字段 | 说明 |
|---|---|
| `outcome` | `already_up_to_date` / `fast_forward` / `merged` / `conflicted` |
| `local` / `remote` | 本地草稿头与远端头；不存在时为 `null` |
| `base` | 合并基；没有共同历史时为 `null` |
| `merged` / `state_root` | 合并后的目标快照与 State Root；**冲突时为 `null`** |
| `resources` | 参与合并的资源数量（三侧标识的并集） |
| `conflicts` | 本次登记的冲突标识，按标识升序 |

**`conflicts.list`**（**仅 schema v2**）

```json
{
  "open": 2,
  "conflicts": [
    {
      "conflict": "3f8a1c05d2e7…",
      "resource": "vcs/git/user",
      "kind": "structured_key",
      "state": "open"
    }
  ]
}
```

**`conflicts.show`**（**仅 schema v2**）

```json
{
  "conflict": "3f8a1c05d2e7…",
  "resource": "vcs/git/user",
  "kind": "structured_key",
  "state": "open",
  "base": "7a2c9e11…",
  "ours": "4d0f5b83…",
  "theirs": "91ce7a20…",
  "diagnostics": ["modify/modify /user/email"]
}
```

`kind` 取值 `text_overlap` / `delete_modify` / `structured_key` / `binary_both` /
`incompatible_policy`；`state` 取值 `open` / `resolved` / `superseded`。
`base` / `ours` / `theirs` 为 `null` 表示该侧不存在该资源。
`diagnostics` **只含位置与结构**（行区间、JSON Pointer、键路径），**绝不含文件正文**。

**`conflicts.resolve`**（**仅 schema v2**）

```json
{
  "conflict": "3f8a1c05d2e7…",
  "choice": "theirs",
  "resolved_blob": "91ce7a20…"
}
```

`choice` 取值 `ours` / `theirs` / `manual` / `delete`；`--delete` 时 `resolved_blob`
为 `null`。

**`profile.explain`**（**仅 schema v2**）

```json
{
  "os": "linux",
  "arch": "x86_64",
  "hostname": "workstation",
  "device": "9f2c3d4e5a6b…",
  "tags": ["laptop", "work"],
  "capabilities": ["git-xdg", "pwsh"],
  "state_root": "70a1c3e5…",
  "device_view": "4b1d7c02a9…",
  "resources": [
    {
      "resource": "shell/powershell/profile",
      "kind": "unsupported_capability",
      "included": false,
      "detail": "本设备缺少所需能力：pwsh；该资源本次不下发，但**不会**被删除。"
    }
  ]
}
```

`resources[].kind` 取值 `selected_by_global` / `selected_by_selector` /
`overridden_by_device` / `excluded_by_selector` / `excluded_by_policy` /
`unsupported_capability`；`included` 由 `kind` 唯一决定。`state_root` 在工作区还没有
任何快照时为 `null`。

**`adapters.list`**（**仅 schema v2**）

```json
{
  "all": false,
  "os": "linux",
  "arch": "x86_64",
  "count": 4,
  "adapters": [
    {
      "id": "builtin.vcs.git",
      "display_name": "Git 配置",
      "version": 1,
      "supported_os": ["macos", "linux", "windows"],
      "required_capabilities": [],
      "default_mode": "structured_merge",
      "applies": true,
      "resources": [
        {
          "resource": "vcs/git/user",
          "root": "home",
          "target": ".gitconfig",
          "mode": "structured_merge",
          "disposition": "managed",
          "structured_format": "git_config",
          "selected": true
        }
      ]
    }
  ]
}
```

`applies` 表示该适配器是否适用于本设备（操作系统在 `supported_os` 内 ∧
`required_capabilities` 全部具备）；不带 `--all` 时列出的适配器 `applies` 恒为 `true`。
`resources[].selected` 是资源级选择器在本设备上的求值结果；不带 `--all` 时恒为 `true`。
`default_mode` 只是**展示与诊断用的语义标签**，具体资源用的模式看 `resources[].mode`。

**`adapters.discover`**（**仅 schema v2**）

```json
{
  "device": "9f2c3d4e5a6b…",
  "count": 7,
  "resources": [
    {
      "resource": "shell/zsh/zshrc",
      "root": "home",
      "target": ".zshrc",
      "mode": "managed_block",
      "disposition": "managed",
      "structured_format": null,
      "selected": true
    }
  ],
  "yaml": "resources:\n- id: shell/zsh/zshrc\n  root: home\n  ...\n"
}
```

`yaml` 是可以直接粘贴进配置文件顶层的 `resources:` 片段。`disposition` 永远不会是
`ensure_absent`：**删除意图必须由用户显式表达**，内建适配器不产出 tombstone。

### 2.2 失败时的信封

```json
{
  "schema_version": 2,
  "command": "sync",
  "status": "error",
  "data": null,
  "diagnostics": [
    {
      "severity": "blocking",
      "code": "plan.stale",
      "resource": null,
      "message": "计划 487a3c78… 已失效；在当前条件下应为 c65952c8…"
    }
  ]
}
```

**成功与失败共用同一个信封**：调用方无论如何都只需要解析同一个位置的同一种形状，
先看 `status`，再决定读 `data` 还是 `diagnostics`。

### 2.3 schema 版本与降级

| 版本 | 状态 |
|---|---|
| `2` | **当前版本**，`--schema-version` 的默认值 |
| `1` | 仍可请求；输出退回 M0 的字段集合 |
| 其他 | **用法错误**（退出码 2），绝不静默按某个版本输出 |

v1 与 v2 的差异只有「v2 多了哪些字段」，因此降级的手段就是**剔除**：

| 命令 | 只在 v2 存在的字段 |
|---|---|
| `status` | `open_conflicts` |
| `plan` | `device_view` |

M1 新增的四组命令（`fetch` / `merge` / `conflicts.*` / `profile.*`）在 v1 里**没有形状**，
因此以 `--schema-version 1` 调用它们会在派发阶段就被拒绝：

```bash
envsync fetch --config "$CFG" --schema-version 1 --json
# → status=error，code=recovery.manual_required，退出码 1
#   「命令 `fetch` 只在 JSON schema v2 中定义；请去掉 `--schema-version 1`」
```

信封本身的五个字段（`schema_version` / `command` / `status` / `data` / `diagnostics`）
在两个版本里完全一致。

---

## 3. 退出码

| 码 | 含义 | 补救 |
|---|---|---|
| 0 | 成功 | — |
| 1 | 一般错误（配置读不到、I/O 失败、需要人工处理等） | 看 `diagnostics[0].code` |
| 2 | 用法错误：缺参数、参数值非法、未知子命令、`--schema-version` 越界 | 看 `--help` |
| 10 | 后端 CAS 冲突：别的设备先发布了 | `fetch` → `merge` → `plan` → `sync` 重来 |
| 11 | 计划失效或不存在 | 重新 `plan` 再 `sync` |
| 12 | 策略阻塞：计划里有阻塞诊断 | 按诊断修好资源，再重新 `plan` |
| **13** | **存在未解决的合并冲突** | `envsync conflicts list` / `show` / `resolve`，再 `merge` |
| 20 | 已发布但本地未收敛 | `envsync recover`，或 `envsync rollback --operation <id>` |

退出码只从 `envsync-core::CoreError` 的判定方法派生，**不看错误文本**，因此错误信息可以
随时改写而不破坏脚本。

需要注意的四点：

- 退出码 10 意味着**本地一个字节都没有被写过**：CAS 发生在任何本地写入之前；
- 退出码 11 同时覆盖「计划失效」和「计划不存在」：对调用方来说补救动作完全一样，用两个
  码只会让脚本多写一个分支；
- 退出码 **13** 的错误码是 `sync.conflicted`，`diagnostics[0].message` 给出冲突数量。
  它保证**本地文件与远端 Ref 都没有被改动**——这条检查排在 `apply_plan` 的第一行，
  之后的每一步（恢复、新鲜度校验、上传对象、CAS 发布、逐动作应用）都还没发生；
- **`merge` 发现冲突时退出码是 0**，不是 13。merge 成功地完成了它的工作（发现并登记
  冲突）；请读 `data.outcome == "conflicted"`。

### 3.1 退出码 10 与 13 的区别

| | 10（CAS 冲突） | 13（合并冲突） |
|---|---|---|
| 冲突在哪一层 | 后端 Ref 的 revision | 资源**内容** |
| 谁能解决 | 机器：重新 `fetch`/`merge`/`plan`/`sync` | **只能由人**裁决 |
| 错误码 | `cas_conflict` | `sync.conflicted` |
| 保证 | 本地一个字节都没被写过 | 本地文件与远端 Ref **都没有被改动** |

---

## 4. 典型工作流

以下示例只用占位路径，请按实际情况替换。

### 4.1 首次使用

```bash
# 1) 初始化
envsync init --config /path/to/envsync.yaml \
             --backend-path /path/to/backend \
             --device-name laptop

# 2) 编辑 /path/to/envsync.yaml，把要管理的文件写进 resources
#    （roots 里的别名决定了哪些目录允许被写入）
#    想省事：`envsync adapters discover --config /path/to/envsync.yaml`
#    会输出一段可直接粘贴的 resources；或者在第 1 步就加上 `--discover`

# 3) 体检一下配置
envsync doctor --config /path/to/envsync.yaml

# 4) 捕获本机现状
envsync capture --config /path/to/envsync.yaml

# 5) 生成计划并审阅
envsync plan --config /path/to/envsync.yaml

# 6) 应用
envsync sync --config /path/to/envsync.yaml --plan <plan-id>

# 7) 确认收敛
envsync status --config /path/to/envsync.yaml
```

脚本化时用 `--json` 取计划标识：

```bash
PLAN=$(envsync plan --config /path/to/envsync.yaml --json | jq -r '.data.plan')
envsync sync --config /path/to/envsync.yaml --plan "$PLAN"
```

### 4.2 第二台设备

第二台设备要用**同一个 `workspace_id`** 和**同一个后端**，但拥有自己的
`device.name`、`device.seed_hex`、`state_dir` 和授权根。

```bash
# 1) 初始化后，把 workspace_id 与 backend 段改成与第一台一致
envsync init --config /path/to/envsync.yaml \
             --backend-path /path/to/shared-backend \
             --device-name desktop

# 2) 直接 plan：目标快照取后端当前头，本机文件会向它收敛
envsync plan --config /path/to/envsync.yaml
envsync sync --config /path/to/envsync.yaml --plan <plan-id>
```

不要复制第一台设备的 `state_dir`：里面是本机的操作日志、草稿库和备份，跨设备复用会让
崩溃恢复读到别人的历史。

配置好 `profile` 之后，用 `profile explain` 确认这台设备会拿到哪些资源：

```bash
envsync profile explain --config /path/to/envsync.yaml
```

### 4.3 M1 日常闭环（多设备）

```bash
CFG=/path/to/envsync.yaml

envsync fetch   --config "$CFG"                 # 拉远端对象，不碰用户文件
envsync merge   --config "$CFG"                 # 三方合并（有冲突只登记，退出码仍是 0）
envsync capture --config "$CFG"                 # 观察本机现状
envsync plan    --config "$CFG"                 # 生成不可变计划
envsync sync    --config "$CFG" --plan <plan-id>
envsync status  --config "$CFG"
```

脚本化版本：

```bash
set -e
envsync fetch --config "$CFG" --json > /dev/null

OUTCOME=$(envsync merge --config "$CFG" --json | jq -r '.data.outcome')
if [ "$OUTCOME" = "conflicted" ]; then
    envsync conflicts list --config "$CFG"
    exit 1                                       # 需要人来裁决，不要自动挑一边
fi

envsync capture --config "$CFG" --json > /dev/null
PLAN=$(envsync plan --config "$CFG" --json | jq -r '.data.plan')
envsync sync --config "$CFG" --plan "$PLAN"
```

### 4.4 CAS 冲突之后（退出码 10）

```bash
envsync sync --config "$CFG" --plan <plan-id>
# 退出码 10：别的设备先发布了；本地一个字节都没写

envsync fetch   --config "$CFG"                 # 拿到别人发布的对象
envsync merge   --config "$CFG"                 # 与本地草稿三方合并
envsync capture --config "$CFG"                 # 重新观察本机
envsync plan    --config "$CFG"                 # 基于新的后端头重新计划
envsync sync    --config "$CFG" --plan <新的 plan-id>
```

### 4.5 合并冲突之后（退出码 13）

```bash
envsync sync --config "$CFG" --plan <plan-id>
# 退出码 13：存在未解决的合并冲突；本地文件与远端 Ref 都没变

# 1) 看有哪些冲突
envsync conflicts list --config "$CFG"

# 2) 逐个看详情（只有摘要与结构性诊断，没有文件正文）
envsync conflicts show --config "$CFG" --conflict <conflict-id>

# 3) 裁决：采用一侧、给出人工合并结果，或确认删除
envsync conflicts resolve --config "$CFG" --conflict <conflict-id> --theirs
envsync conflicts resolve --config "$CFG" --conflict <conflict-id> --file /tmp/merged
envsync conflicts resolve --config "$CFG" --conflict <conflict-id> --delete

# 4) 重新合并：已裁决的冲突会被自动复用（冲突是内容寻址的）
envsync merge --config "$CFG" --json | jq -r '.data.outcome'   # → "merged"

# 5) 计划并应用
PLAN=$(envsync plan --config "$CFG" --json | jq -r '.data.plan')
envsync sync --config "$CFG" --plan "$PLAN"
```

完整说明见 [冲突处理](conflicts.md)。

如果退出码是 20（已发布但本地未收敛）：

```bash
envsync doctor  --config /path/to/envsync.yaml   # 先看建议，doctor 不会动任何东西
envsync recover --config /path/to/envsync.yaml   # 按建议自动恢复
envsync status  --config /path/to/envsync.yaml   # 确认回到 clean 或 drifted
```

`recover` 需要人工介入时会以退出码 1 结束并给出 `recovery.manual_required`——这通常意味着
备份缺失或目标文件在恢复期间又被外部改过，此时**不覆盖**是唯一安全的选择。

### 4.4 回滚

```bash
# 从成功的 sync 里拿操作标识
OP=$(envsync sync --config /path/to/envsync.yaml --plan "$PLAN" --json | jq -r '.data.operation')

# 或者从 status / doctor 里找未完成操作
envsync status --config /path/to/envsync.yaml --json | jq '.data.unfinished'

envsync rollback --config /path/to/envsync.yaml --operation "$OP"
```

回滚按收据**逆序**还原；备份摘要与记录不符时会拒绝执行，而不是写一个可能错误的结果。

---

## 5. 脱敏

所有输出——人类可读文本和 JSON——都会经过同一个脱敏器，规则如下：

1. **按键名。** JSON 里键名（忽略大小写与 `-`/`_`）包含 `token`、`secret`、`password`、
   `apikey`、`authorization`、`bearer` 的字段，其**整个值**（哪怕是对象或数组）被替换为
   `"<redacted>"`。因此 `api_key`、`API-KEY`、`access_token`、`client-secret` 都会命中。
2. **按文本。** 纯文本里的 `bearer <令牌>`（令牌至少 8 个 `[A-Za-z0-9._-]` 字符）以及
   `<敏感键>=<值>` / `<敏感键>: <值>` 会被替换为 `<redacted>`。

```text
Authorization: Bearer abcdefgh12345678   →  Authorization: <redacted>
api_key=AKIA0123456789                   →  api_key=<redacted>
```

脱敏是**保守**的：值必须以 ASCII 字母或数字开头才会被吃掉，所以

```text
资源 shell/token/main 已同步，token 数量为 3
计划失效：token 已过期，请重新 plan
```

这类正常内容不会被误伤。

两点需要清楚：

- 脱敏是**最后一道防线**，不是唯一一道。真正的秘密内容从设计上就不会进入诊断文本：
  下层错误只带错误类别与相对路径，不带文件内容；
- 被 `policy.secret` 标成秘密的资源，其**内容**从来不会出现在任何输出里；计划里只会
  出现 `sensitive: true` 这个标记和内容摘要。

---

Git 后端另有一层专门的脱敏：远端 URL 的 userinfo、查询串与本地路径在写进日志、`Debug`
输出和错误上下文之前就已经被替换，`tracing` 里只出现主机名。见
[Git 后端 §3.3](backends/git.md#33-redaction-保证)。

---

## 6. 相关文档

**M1 专题**

- [设备 Profile 与投影](profiles.md)：selector 语法、投影优先级、`profile explain` 的解读
- [Git 后端](backends/git.md)：tree 布局、CAS 语义与前提、认证与脱敏、故障排查
- [冲突处理](conflicts.md)：冲突对象、状态机、`conflicts` 命令、退出码 13 与恢复流程
- [合并规则](merge.md)：五种结构化格式与文本合并的规则、已知限制与资源上限
- [适配器](adapters.md)：内建适配器清单、sealed trait、系统级 Git 配置

**通用**

- [M0 运维手册](m0-operations.md)：数据模型、事务边界、备份与恢复、故障排查
- [安全模型](security-model.md)：信任边界、提供与**不提供**的保证
- [配置示例](../examples/workspace.yaml)、[Git 后端配置示例](../examples/workspace-git.yaml)
- 设计文档：`docs/superpowers/specs/2026-07-24-envsync-design.md`
- M0 实施计划：`docs/superpowers/plans/2026-07-24-envsync-m0-safe-file-loop.md`
- M1 实施计划：`docs/superpowers/plans/2026-07-24-envsync-m1-git-profiles-merge.md`
- ADR-0003（Plan ID 绑定输入而不绑定生成时刻）：`docs/decisions/2026-07-26-plan-id-excludes-timestamp.md`
