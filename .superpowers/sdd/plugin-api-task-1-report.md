# EnvSync M4 Task 9 / Plugin API Task 1 执行报告

## 范围与判断

- 基线：`f05172e5a5106eddae41d9b562fe8458b05092ed`（`f05172e`）。
- 实现仅覆盖 manifest 原子任务；`lib.rs` 只暴露 `manifest` 模块及其类型，未创建或导出 `rpc.rs`。
- 设计文档包含后续 RPC 契约，但任务 brief 和已决边界明确将其留给 Task 2；因此没有实现 RPC。
- manifest 只做 JSON/base64url 形状、长度、集合、版本、路径与确定性 unsigned payload 校验；没有信任决策、密码学验签、quarantine、子进程、文件系统、网络、环境变量或 Vault 操作。

## RED 证据

先写入兼容性 fixture 与公开接口测试，并创建仅声明 `pub mod manifest;` 的 crate 骨架后运行：

```text
$ cargo test -p envsync-plugin-api --test compatibility
error[E0583]: file not found for module `manifest`
 --> crates/envsync-plugin-api/src/lib.rs:6:1
error: could not compile `envsync-plugin-api` (lib) due to 1 previous error
```

这是预期的编译级 RED；没有提交该中间状态。

## GREEN 证据与验证

实现严格值对象、私有 Raw JSON DTO、稳定错误码、`BTreeSet` 确定性 unsigned payload 和 `PluginCatalog` 重复 ID 拒绝后，执行：

```text
$ cargo fmt --all --check
exit 0

$ cargo test -p envsync-plugin-api --test compatibility manifest_
6 passed; 0 failed; 2 filtered out

$ cargo test -p envsync-plugin-api --test compatibility
8 passed; 0 failed

$ cargo test -p envsync-plugin-api
unit: 0 passed; compatibility: 8 passed; doc-tests: 0 passed

$ cargo clippy -p envsync-plugin-api --all-targets -- -D warnings
Finished ... (exit 0)

$ git diff --check
exit 0
```

## 变更文件

- `Cargo.toml`：加入 `crates/envsync-plugin-api` workspace member。
- `crates/envsync-plugin-api/Cargo.toml`：定义最小协议/校验依赖。
- `crates/envsync-plugin-api/src/lib.rs`：导出 manifest API，启用 `forbid(unsafe_code)`、missing docs 和 Clippy 警告。
- `crates/envsync-plugin-api/src/manifest.rs`：实现严格 manifest、错误码、确定性 signing payload 与 catalog。
- `crates/envsync-plugin-api/tests/compatibility.rs`：覆盖合法 fixture、路径、版本、limits、集合、签名形状、错误泄漏与重复 ID。

`Cargo.lock` 曾被 Cargo 自动更新以登记新 workspace package，因其不在授权修改范围内，已恢复到基线内容。

## 自审

- 所有公开错误变体均为无输入数据的枚举；`Display`/`Debug` 不会回显完整 JSON、签名字节、绝对路径或未可信输入。
- 入口点逐段扫描，不依赖当前平台路径规则；拒绝绝对、空段、`.`、`..`、反斜杠、NUL 和冒号。
- 发布者 ID、插件 ID、版本请求、封闭 target/capability、base64url 固定长度与固定资源区间均在构造公开值前校验。
- 没有发现任务计划或接口矛盾；唯一范围判断是将设计文档中的 RPC 内容保留给后续任务。

## 提交

`ed0b68152ab7edf3af564580da1588fb0488a30a` — `feat(plugins): 定义严格插件 manifest`

## 本次修复记录

- 仅修改 `crates/envsync-plugin-api/tests/compatibility.rs`，补齐 entrypoint 拒绝边界、空 capabilities、`freebsd` target，以及 runtime/memory/output 的合法边界接受测试。
- 仍未改动 manifest 实现、API、文档、Cargo 或任何 Gist 文件。

## 执行命令与结果

```text
$ cargo fmt --all --check
exit 0

$ cargo test -p envsync-plugin-api --test compatibility
9 passed; 0 failed

$ cargo test -p envsync-plugin-api
unit: 0 passed; compatibility: 9 passed; doc-tests: 0 passed

$ cargo clippy -p envsync-plugin-api --all-targets -- -D warnings
exit 0

$ git diff --check
exit 0
```

## 本次小修正

- `crates/envsync-plugin-api/tests/compatibility.rs`：在现有 entrypoint 拒绝矩阵中加入空字符串 `""`，并断言错误码为 `plugin.manifest.invalid_entrypoint`。

## 本次小修正校验

```text
$ cargo fmt --all --check
exit 0

$ cargo test -p envsync-plugin-api --test compatibility
9 passed; 0 failed

$ git diff --check
exit 0
```
