# EnvSync 插件 Host 隔离设计

**目标：** 让第三方插件只在独立、受限、可审计的子进程中运行；任何未签名、未审核、未隔离或越权的插件输入都不能获得文件、命令、环境变量或 Vault 明文权限。

## 方案选择

| 方案 | 结论 | 原因 |
| --- | --- | --- |
| 在主进程加载动态库或开放 Adapter trait | 拒绝 | 第三方代码会继承 EnvSync 的文件、网络、Vault 与内存权限。 |
| 允许调用方传入任意“已隔离”标记 | 拒绝 | 容易把未隔离进程伪装为安全运行时。 |
| 独立 runner + 显式 test-only 后端 + 生产默认拒绝 | 采用 | 可验证协议、资源与进程树行为；没有实际 OS sandbox 时不作虚假安全承诺。 |

## 信任与制品完整性

当前 manifest 的签名若只覆盖元数据，攻击者仍可替换入口程序。因此 Host 前先扩展 `envsync-plugin-api`：manifest 增加 `entrypoint_digest`，它是入口文件原始字节的 32 字节 BLAKE3 摘要（base64url 无填充编码），并被既有无签名 manifest payload 一并签名。

v1 插件包只含一个入口文件；不接受 symlink、额外文件或目录依赖。这个刻意收紧的格式避免在没有已签名文件清单时误接受多文件代码包。未来多文件包必须新增带完整文件摘要清单的 manifest 版本，不能静默放宽 v1。

安装顺序固定如下：

```text
manifest + entrypoint bytes
  │ parse / digest / publisher trust / Ed25519 verify
  ▼
non-executable quarantine
  │ policy + explicit approval（digest、能力、profile、signer）
  ▼
verified runtime copy
  │ 每次启动前再比对 digest
  ▼
isolated runner
```

quarantine 与 runtime 根都由 Host 自己创建，逐段拒绝符号链接。quarantine 文件去掉全部 execute 位；批准后才写入新的 runtime 目录，并且只给该入口文件执行位。失败、更新、能力扩张、签名不匹配或发布者撤销都不覆盖旧审计记录。

`envsync_core::bundles::PublisherRegistry`、`publisher_namespace()` 与发布者指纹仍是唯一的发布者信任来源；插件使用独立的签名 domain `envsync-plugin`，避免与 Agent Bundle 重放。

## 生命周期与策略

`PluginRecord` 的状态为 `Quarantined`、`Approved`、`Enabled`、`Blocked` 或 `Revoked`。批准绑定插件 ID、manifest/入口 digest、声明 capability、profile 和 signer。内容、signer 或 capability 扩张都会使批准失效并回到 quarantine。撤销是降级动作：立即把同一 signer 的已启用插件标为 `Revoked`，保留 append-only `PluginAuditEvent`。

启用时使用 `ResourceKind::Plugin` / `Operation::Enable` / `Risk::High` 评估现有 policy。`Deny` 或缺失确认不会启动进程；发布者在批准和启动之间被撤销也会阻断启动。

## 进程、资源与 sandbox

`envsync-plugin-runner` 是一个独立的 Unix helper：它只接收 Host 构造的绝对入口路径和数值内存上限，不使用 shell；先建立独立 process group、设置 `RLIMIT_AS`，再 `exec` 入口程序。Host 在 timeout、总 stdout/stderr 输出超限、协议错误或 shutdown 宽限期结束时用该 process group 终止整个进程树，而不是只 kill 直接子进程。

Host 为每次会话新建空临时 cwd，使用 `env_clear()`，仅注入固定的 `ENVSYNC_PLUGIN_PROTOCOL=stdio-v1`；stdin/stdout 是长度前缀 RPC 管道，stderr 仅作为有上限的诊断字节流。Host 不继承 `PATH`、用户环境、工作目录、文件句柄或 Vault 句柄。

本次不把 runner 的资源限制伪装成 OS filesystem/network sandbox。普通构建的 `PluginHost::new()` 报告 `SandboxUnavailable` 并拒绝启用或运行插件。仅 `test-support` feature 提供明确命名的未隔离测试 launcher，用于运行恶意 fixture 来验证 Host 的超时、输出、环境清理、协议拒绝与进程组清理；该 feature 通过自引用 dev-dependency 仅在测试构建启用。未来真实 sandbox 后端必须先提供可验证的 mount/network/identity 隔离证明，才可替换默认拒绝。

## Host-mediated capability

插件只能把 JSON proposal 作为 RPC response 返回，不能获得 Host 的路径、命令或 SecretRef 值。`CapabilityMediator` 按调用方法重新解析并验证：

- `observe`、`render`、`verify`：`root` 必须是已注册的逻辑别名；`target` 必须通过 `RelativeTarget::parse`，并由 `RootRegistry` 解析为 capability-scoped target；返回值仅是已验证的声明，Host 决定是否调用 core。
- `plan-command`：只允许 Host 注册的 opaque command template ID 与其预定义参数规则；未知 ID、NUL、控制字符、shell 元字符、超长或超量 argv 一律拒绝。proposal 进入普通 Plan/policy/apply 链路，Host 不会因 plugin response 直接执行命令。
- `initialize`、`describe`、`shutdown` 不是 capability。response 必须关联到原 request ID、方法与支持的 schema version；插件主动发 request、未知 method、错 ID 或不合法 result 一律失败。

任何消息中的 `secret`、`token`、绝对路径或环境值都不是 Host proposal schema 的字段。错误、审计和诊断只记录稳定错误码、插件 ID、短摘要、方法和 I/O kind，不回显入口绝对路径、原始 JSON、stderr 或 Vault 数据。

## 验收矩阵

- 结构：错误 manifest、错误入口摘要、未知/撤销 signer、篡改 runtime copy、能力扩张与更新均停在 quarantine 或转为 blocked/revoked。
- 进程：无限循环、超大 stdout/stderr、崩溃、坏 frame、错 response ID 和 shutdown 后继续运行都被 Host 终止并得到稳定错误码；父进程派生的子进程也随 process group 消失。
- 环境：fixture 看不到父进程 canary、cwd 为空、不会收到 Vault 明文。
- capability：路径穿越、未知 root、未知命令和 shell 形状都在 Host 边界拒绝；合法 proposal 仅形成经过验证的声明，绝不直接执行。
- 安全默认：普通构建在 sandbox 不可用时拒绝启动，测试模式不会被报告为生产隔离。
