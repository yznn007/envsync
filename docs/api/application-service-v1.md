# Application Service API v1

本契约定义 EnvSync application service 面向桌面壳及其他受控宿主的**脱敏** JSON 边界。
它不是后端存储格式，也不是对用户文件、Vault 或任意错误文本的访问接口。

## 版本与兼容性

- 当前版本为 `schema_version: 1`，常量为
  `envsync_core::APPLICATION_SERVICE_SCHEMA_VERSION`。
- 每个 request、response 和 event 均携带 `schema_version` 与 `request_id`。
- `request_id` 由宿主生成，只允许 1–128 个 ASCII 字母、数字、`-`、`_`、`.`；它用于
  关联调用、事件和本地化诊断，不能承载路径、内容或秘密。
- v1 已发布字段不可删除、改名或改变 JSON 类型。新增字段必须可选，或者仅在新的 minor
  规则下由显式协商的客户端消费。客户端必须忽略未知字段。
- `crates/envsync-core/tests/fixtures/application-service-v1-status.json` 是 v1 状态响应的
  golden fixture。测试按 JSON 结构而非字段顺序比较；移除或改名 fixture 中的字段会失败。

## 统一信封

请求：

```json
{
  "schema_version": 1,
  "request_id": "req-status-v1",
  "data": { "workspace_handle": "workspace-01" }
}
```

成功响应：

```json
{
  "schema_version": 1,
  "request_id": "req-status-v1",
  "status": "ok",
  "data": { "...": "审核过的 View" },
  "diagnostics": []
}
```

失败响应：

```json
{
  "schema_version": 1,
  "request_id": "req-status-v1",
  "status": "error",
  "data": null,
  "diagnostics": [
    {
      "severity": "blocking",
      "code": "status.backend_unreachable",
      "resource": null
    }
  ]
}
```

`status = "error"` 时 `data` 必须为 `null`，并且至少有一条诊断。诊断只含稳定的
`severity`、`code` 和可选 `resource`；UI 根据 `code` 本地化文案，绝不显示或记录原始
诊断正文。

## 审核过的 View

`ApiResponse<T>` 与 `ApiEvent<T>` 的 `T` 受 `ViewData` 密封约束，只能是 core 审核过的
View：

| View | 用途 | 明确不包含 |
| --- | --- | --- |
| `WorkspaceSummary` | 工作区、设备、后端类别 | 后端 URL、凭据、授权根绝对路径 |
| `StatusView` | 状态、ref、资源摘要、未完成操作计数 | 文件内容、诊断正文 |
| `PlanView` | 计划与动作审核 | Blob ID、文件正文、绝对路径 |
| `DiffView` | 变化摘要 | 敏感资源的摘要与任何内容 |
| `ConflictView` | 冲突状态与已选策略 | base/ours/theirs/resolved Blob |
| `OperationView` | journal 操作状态 | 原始错误消息、收据内容 |

敏感动作的 `DiffView` 仅报告 `sensitive: true` 与变化类型；`before_digest`、
`after_digest` 均为 `null`。

## 长操作、事件与取消

`plan.apply`、`operation.rollback` 等长操作先返回 `OperationView`，其 `operation` 是后续
查询、事件和恢复的唯一引用。宿主通过 `ApiEvent<OperationView>` 接收进度：

```json
{
  "schema_version": 1,
  "request_id": "req-apply-v1",
  "sequence": 7,
  "status": "ok",
  "data": { "operation": "12345678-1234-4234-8234-123456789abc", "...": "状态 View" },
  "diagnostics": []
}
```

`sequence` 只在同一个 `request_id` 内单调递增。客户端可去重；若序号缺失或窗口重连，必须
重新查询 operation，不能自行推断事务结果。

取消为显式的 `operation.cancel` 命令，负载只能是已登记的操作 ID：

```json
{
  "schema_version": 1,
  "request_id": "req-cancel-v1",
  "data": { "operation_id": "12345678-1234-4234-8234-123456789abc" }
}
```

取消并不等于杀死进程或跳过 journal；application service 在安全边界决定该操作此刻是否可
取消，并用 `OperationView` 事件报告结果。

## 宿主边界

桌面壳只可传递已注册的 workspace/resource/plan/operation 标识。它不得提供任意文件路径、
shell 命令、HTTP 请求或 Vault 明文参数。实际 command allowlist、Tauri capability 与参数
解析将在桌面壳中执行，但必须继续使用本契约的 request、response 和 event 信封。
