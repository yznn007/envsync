# EnvSync 命令行（M0）

EnvSync 把开发环境中**被显式声明**的文件，安全地在多台设备之间同步。命令行是
`envsync-core::EnvSyncService` 的一层薄壳：所有安全决策（计划、策略、日志、回滚）
都在核心层完成，CLI 只负责解析参数、渲染结果和把错误映射成稳定的退出码。

两条贯穿全文的约定：

- **任何写入都必须先出现在一份不可变的计划里。** 没有 `plan` 就没有 `sync`。
- **`--json` 时 stdout 只有一行 JSON。** 日志、进度、诊断一律写 stderr。

---

## 1. 命令一览

```text
envsync init     --config <path> [--device-name <name>] --backend-path <path>
envsync capture  --config <path>
envsync plan     --config <path>
envsync sync     --config <path> --plan <plan-id>
envsync status   --config <path>
envsync rollback --config <path> --operation <id>
envsync doctor   --config <path>
envsync recover  --config <path>
```

全局参数（放在子命令前后都可以）：

| 参数 | 说明 |
|---|---|
| `--json` | 以单行 JSON 输出结果；日志与诊断写 stderr |
| `-v` / `--verbose` | 提高日志级别，可重复：`-v` 为 info，`-vv` 为 debug，`-vvv` 为 trace |
| `--help` / `--version` | 帮助与版本 |

日志级别也可以用 `RUST_LOG` 覆盖（例如 `RUST_LOG=envsync_core=debug`）；无论怎么设置，
日志的 writer 都固定为 stderr。

### 1.1 `init`

初始化一个新工作区：生成配置文件、后端目录与本地状态目录。

| 参数 | 必需 | 说明 |
|---|---|---|
| `--config <path>` | 是 | 要生成的配置文件路径；**已存在时报错而不覆盖** |
| `--backend-path <path>` | 是 | 本地后端目录；不存在时创建 |
| `--device-name <name>` | 否 | 设备显示名；省略时取 `ENVSYNC_DEVICE_NAME` / `HOSTNAME` / `COMPUTERNAME`，都取不到时用 `envsync-device` |

生成的配置里 `resources` 为空——空工作区是合法的，随后由你把要管理的文件填进去。

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

### 1.4 `sync`

应用指定计划。执行顺序：

1. 自动运行崩溃恢复；
2. 重新观察、重新计划，与提交的 `--plan` 比对，不一致即判定失效（退出码 11）；
3. 上传目标快照可达的全部对象；
4. CAS 发布后端 Ref（冲突退出码 10，此时**一个本地字节都没写**）；
5. 逐动作应用并验证，任一动作失败则按逆序回滚。

| 参数 | 必需 | 说明 |
|---|---|---|
| `--plan <plan-id>` | 是 | `envsync plan` 输出的 64 位十六进制计划标识 |

### 1.5 `status`

汇总工作区状态，区分四种整体状态：

| 状态 | 含义 |
|---|---|
| `clean` | 本机与目标快照一致，且没有未完成操作 |
| `drifted` | 存在需要应用的变更 |
| `conflicted` | 存在阻塞诊断，需要人工处理 |
| `published_not_converged` | 后端头已前进但本地没跟上，必须 `recover` 或 `rollback` |

### 1.6 `rollback`

按收据逆序还原一次操作。操作标识可以从 `status` 的 `unfinished`、`doctor` 的
`recovery`，或成功 `sync` 的 `data.operation` 里拿到。

备份缺失或摘要不符时**拒绝覆盖**，保留可诊断状态而不是猜一个结果。

### 1.7 `doctor`

只读体检：检查授权根可访问性、资源目标合法性、后端可达性、操作日志 schema，并给出
未完成操作的恢复建议。**绝不修改任何东西**。

因为体检本身总是成功的，`doctor` 恒以退出码 0 结束；判断健康与否请读 `data.healthy`，
不要读退出码。

### 1.8 `recover`

显式触发崩溃恢复。`sync` 启动时会自动运行同一套流程，这个命令用于在不打算立刻同步时
先把未完成操作清理干净。恢复算法是幂等的：连续运行两次得到相同的最终状态。

---

## 2. JSON 契约

`--json` 时 stdout 是**恰好一行** JSON，形状固定：

```json
{
  "schema_version": 1,
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
| `schema_version` | 整数 | 契约版本，当前为 `1`；语义不兼容变化时才递增 |
| `command` | 字符串 | 命令名：`init` / `capture` / `plan` / `sync` / `status` / `rollback` / `doctor` / `recover` |
| `status` | 字符串 | `ok` 或 `error` |
| `data` | 对象或 `null` | 命令专属数据；`status` 为 `error` 时恒为 `null` |
| `diagnostics` | 数组 | 诊断列表；失败时至少有一条，`code` 即核心层的稳定错误码 |

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
  "state_dir": "/path/to/.envsync"
}
```

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
  "revision": 1,
  "head": "5be47e77…",
  "draft_head": null,
  "state": "clean",
  "pending_actions": 0,
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

**`doctor`**

```json
{
  "healthy": true,
  "findings": [
    { "check": "后端可达性", "ok": true, "detail": "可读取 Ref" }
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

### 2.2 失败时的信封

```json
{
  "schema_version": 1,
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

---

## 3. 退出码

| 码 | 含义 | 补救 |
|---|---|---|
| 0 | 成功 | — |
| 1 | 一般错误（配置读不到、I/O 失败、需要人工处理等） | 看 `diagnostics[0].code` |
| 2 | 用法错误：缺参数、参数值非法、未知子命令 | 看 `--help` |
| 10 | 后端 CAS 冲突：别的设备先发布了 | `capture` → `plan` → `sync` 重来 |
| 11 | 计划失效或不存在 | 重新 `plan` 再 `sync` |
| 12 | 策略阻塞：计划里有阻塞诊断 | 按诊断修好资源，再重新 `plan` |
| 20 | 已发布但本地未收敛 | `envsync recover`，或 `envsync rollback --operation <id>` |

退出码只从 `envsync-core::CoreError` 的判定方法派生，**不看错误文本**，因此错误信息可以
随时改写而不破坏脚本。

需要注意的两点：

- 退出码 10 意味着**本地一个字节都没有被写过**：CAS 发生在任何本地写入之前；
- 退出码 11 同时覆盖「计划失效」和「计划不存在」：对调用方来说补救动作完全一样，用两个
  码只会让脚本多写一个分支。

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
# 1) 初始化后，把 workspace_id 与 backend.path 改成与第一台一致
envsync init --config /path/to/envsync.yaml \
             --backend-path /path/to/shared-backend \
             --device-name desktop

# 2) 直接 plan：目标快照取后端当前头，本机文件会向它收敛
envsync plan --config /path/to/envsync.yaml
envsync sync --config /path/to/envsync.yaml --plan <plan-id>
```

不要复制第一台设备的 `state_dir`：里面是本机的操作日志、草稿库和备份，跨设备复用会让
崩溃恢复读到别人的历史。

### 4.3 冲突之后

```bash
envsync sync --config /path/to/envsync.yaml --plan <plan-id>
# 退出码 10：别的设备先发布了

envsync capture --config /path/to/envsync.yaml   # 重新观察本机
envsync plan    --config /path/to/envsync.yaml   # 基于新的后端头重新计划
envsync sync    --config /path/to/envsync.yaml --plan <新的 plan-id>
```

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

## 6. 相关文档

- 设计文档：`docs/superpowers/specs/2026-07-24-envsync-design.md`
- M0 实施计划：`docs/superpowers/plans/2026-07-24-envsync-m0-safe-file-loop.md`
- ADR-0003（Plan ID 绑定输入而不绑定生成时刻）：`docs/decisions/2026-07-26-plan-id-excludes-timestamp.md`
