# EnvSync 插件 manifest 与版本化 RPC 设计

**目标：** 为 M4 的第三方插件定义一个可验证、可演进且不授予宿主权限的纯数据 API；插件
只能在 Task 10 的独立子进程中通过该 API 与 EnvSync Host 通信。

## 范围与边界

本设计实现 `envsync-plugin-api` crate：不访问文件系统、不启动进程、不读取环境变量、不接触
Vault，也不决定任何策略或授权。它只提供 manifest 的语法/语义校验、版本化 JSON-RPC 的
帧编解码和稳定错误码。

Task 10 才负责进程隔离、OS sandbox、超时/内存/输出配额的实际执行、发布者信任、验签、
quarantine 与 Host-mediated capability。manifest 中的 capability 和资源限制都是不可信的
声明，绝不是权限或授权令牌。

## 方案选择

| 方案 | 结论 | 原因 |
| --- | --- | --- |
| 对外开放 `envsync_adapters::Adapter` trait | 拒绝 | 第三方代码会进入主进程，无法限制文件、命令、内存或环境变量访问。 |
| 直接以 WASM/ABI 作为 SDK | 延后 | 需要先固定 runtime、WASI 权限与跨平台分发方案，当前不必要地扩大 M4 范围。 |
| 独立进程 + 长度前缀 JSON-RPC | 采用 | 协议可独立测试，进程边界可由 Host 强制资源与能力限制，且消息可以版本化。 |

```text
不可信 plugin manifest / plugin stdout
          │
          ▼
envsync-plugin-api
  ├─ Manifest::validate()       仅结构与上限
  └─ RPC frame decode()         仅协议与版本
          │
          ▼
envsync-plugin-host（Task 10）
  ├─ 验签、quarantine、策略与 publisher trust
  ├─ 启动隔离子进程并强制实际资源上限
  └─ 重新验证所有 observation / command proposal
          │
          ▼
envsync-core 的普通 Plan / policy / apply 流程
```

## Manifest 模型

`PluginManifest` 使用 JSON 表示，包含下列字段：

```json
{
  "id": "com.example.calendar",
  "version": "1.2.0",
  "publisher": {
    "id": "com.example",
    "public_key": "base64url-no-padding-ed25519-public-key"
  },
  "api": ">=1.0.0, <2.0.0",
  "entrypoint": "bin/plugin",
  "targets": ["macos", "linux"],
  "capabilities": ["observe", "render"],
  "limits": {
    "max_runtime_ms": 5000,
    "max_memory_bytes": 67108864,
    "max_output_bytes": 1048576
  },
  "signature": {
    "algorithm": "ed25519",
    "value": "base64url-no-padding-ed25519-signature"
  }
}
```

`id` 与 `publisher.id` 为小写反向域名式标识（ASCII、点分段、最长 128 字节）；`version` 必须
是 `semver::Version`；`api` 是 `semver::VersionReq`，且必须匹配 Host 当前支持的至少一个
协议版本（`1.0.0` 或 `1.1.0`）。`PluginCatalog::validate()` 额外拒绝同一安装批次中规范化后
相同的 `id`。

`entrypoint` 是最大 512 字节的相对 Unix 风格路径：不得为空、绝对、含 `.` / `..` 段、反斜杠、
NUL、盘符或 UNC 表示。它在任何平台按同一规则拒绝，避免 Windows/Unix 解释差异。

`targets` 必须非空，且只能是 `macos`、`windows`、`linux`、`wasi-p2`；`capabilities` 是有序去重
集合，且只能是 `observe`、`render`、`plan-command`、`verify`。`initialize`、`describe` 与
`shutdown` 是协议生命周期消息，不是可申请的高权限 capability。

资源限制采用固定请求上限：`100..=30_000` ms、`1 MiB..=256 MiB` memory、`1 KiB..=8 MiB`
output。超出、零值与不合法签名编码都拒绝。`signature.algorithm` 仅接受 `ed25519`，公钥解码后
必须正好 32 字节、签名必须正好 64 字节。签名覆盖除 `signature` 外的确定性 JSON payload；本
crate 只构造 payload 并验证编码形状，Task 10 才将其与 PublisherRegistry 和 quarantine 状态
结合进行密码学验证。

错误类型为 `PluginManifestError`，提供稳定 `code()`；错误文本只包含字段名、长度/版本或受限
标识片段，绝不回显 signature、任意 payload 或绝对路径。

## RPC 模型

所有 stdout/stdin 消息均为 4 字节大端长度前缀加 UTF-8 JSON，前缀后的 JSON 最大
`8 * 1024 * 1024` 字节。`read_frame` 在分配 payload 前检查宣称长度，必须 `read_exact`；
截断、非 UTF-8、JSON 语法错误、长度不符、尾随字节和超过上限都返回稳定 `PluginRpcError`。
`write_frame` 只在序列化后的 payload 未超限时写入完整前缀与 payload。

每个请求和响应均固定为 JSON-RPC 2.0，并包含 `schema_version` 与非空 request ID：

```json
{
  "jsonrpc": "2.0",
  "schema_version": { "major": 1, "minor": 0 },
  "id": "request-0001",
  "method": "initialize",
  "params": {}
}
```

允许的请求方法是封闭枚举：`initialize`、`describe`、`observe`、`render`、`plan-command`、
`verify`、`shutdown`。任何未知方法、通知（缺失 ID）、批量请求、错误 `jsonrpc` 值或
request/response 混合形状一律拒绝。响应必须恰有 `result` 或 `error` 之一，且也带相同
`schema_version` 和 `id`。

Host 支持唯一 major `1` 的两个 minor：`1.0` 和 `1.1`。major 不等于 `1`、minor 大于 `1` 或
小于 `0` 均拒绝，不能通过“忽略未知字段”悄悄接受不兼容协议。声明为已支持 minor 的消息可
携带未知扩展字段，解码器在所有必填字段与方法已验证后忽略它们；新增会改变语义的字段必须
同时增加 minor，且由 `initialize` 结果中的 `selected_schema_version` 协商出双方共同版本。
这样旧端不会把未知 method 或未知版本误当作安全的无操作。

`params`、`result` 与错误的结构化 `data` 保持 `serde_json::Value`，因为其具体 proposal schema
由后续 Host capability 层解释；API crate 绝不把它们转换成路径、命令、环境变量或秘密。

## 兼容性与测试标准

- `tests/compatibility.rs` 以固定 JSON fixture 验证 `initialize` 请求与 `describe` 响应的
  逐字节帧格式。
- 有效 manifest、重复 ID、绝对/穿越 entrypoint、非法 semver、未知 capability、不兼容 API、
  越界资源限制和错误签名长度均有独立断言。
- `1.0` 与 `1.1` 请求/响应可往返；受支持 minor 的未知扩展字段可忽略；未知 method、major
  不匹配和 future minor 必须拒绝。
- 4 字节长度前缀、宣称超过 8 MiB、截断 body、非法 UTF-8、长度不匹配和 response 的
  `result`/`error` 互斥关系均有测试。
- crate 启用 `#![forbid(unsafe_code)]`、`#![warn(missing_docs)]`、`#![warn(clippy::all)]`，并通过
  `cargo fmt --all --check`、`cargo test -p envsync-plugin-api` 与严格 Clippy。

## 与后续任务的接口承诺

Task 10 只能从本 crate 取得已校验的 `PluginManifest` 与 `RpcMessage`。它必须自行执行签名信任、
quarantine、进程树清理、OS sandbox 侦测、资源限制和 proposal 的路径/命令再校验；不可将
manifest 的 capability 或签名存在本身视为已授权，也不可向插件发送 Vault plaintext。
