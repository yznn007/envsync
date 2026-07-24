# EnvSync M0 安全文件闭环实施计划

> **执行要求：** 实施时必须使用 `subagent-driven-development` 或
> `executing-plans`，每个行为先写失败测试，再写最小实现；完成前使用
> `verification-before-completion`。

**目标：** 交付可验证、可回滚的 Local Backend 文件同步闭环：capture、plan、
CAS publish、apply、verify、rollback。

**架构：** Rust workspace 按 domain、backend、platform、storage、core、cli
分层。Domain 保持纯逻辑；I/O 经 trait 注入；平台层独占文件系统能力；Core
编排事务；SQLite journal 是崩溃恢复的事实来源。

**技术栈：** Rust stable、Tokio、Serde、minicbor、BLAKE3、cap-std、rusqlite、
clap、tracing、thiserror、tempfile、proptest、insta。

**非目标：** M0 不实现 Git/Gist、Vault、包管理器、Agent Bundle、桌面端和插件。

## 任务 1：建立 workspace 与质量基线

**文件：**

- 新建 `Cargo.toml`
- 新建 `rust-toolchain.toml`
- 新建 `.gitignore`
- 新建 `crates/envsync-{domain,backend,platform,storage,core,cli}/Cargo.toml`
- 新建每个 crate 的 `src/lib.rs`，CLI 使用 `src/main.rs`
- 新建 `.github/workflows/ci.yml`

**步骤：**

1. 写 workspace smoke test，断言各 crate 可链接。
2. 运行 `cargo test --workspace`，确认因 crate 缺失而失败。
3. 建立最小 crate 和统一依赖；所有库设置 `#![forbid(unsafe_code)]`。
4. CI 矩阵固定 `ubuntu-latest`、`macos-latest`、`windows-latest`。
5. 运行：

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

6. 提交：`chore: bootstrap Rust workspace`

## 任务 2：实现强类型 ID 与资源状态

**文件：**

- 新建 `crates/envsync-domain/src/id.rs`
- 新建 `crates/envsync-domain/src/resource.rs`
- 修改 `crates/envsync-domain/src/lib.rs`
- 新建 `crates/envsync-domain/tests/resource_state.rs`

**测试先行：**

- `ResourceId` 接受 `shell/zsh/main`，拒绝空段、`.`、`..`、反斜杠和绝对路径。
- `Observation` 的五种状态可无损序列化。
- `DesiredDisposition` 只有 `Managed`、`EnsureAbsent`、`Unmanaged`。
- 缺失 Observation 不会自动转成 `EnsureAbsent`。

**实现约束：**

- `WorkspaceId`、`DeviceId` 使用 UUID newtype。
- `BlobId`、`StateRootId`、`SnapshotId`、`PlanId` 是 32 字节摘要 newtype。
- ID 实现 `Display`、`FromStr`、Serde；解析错误不得 panic。

**验证与提交：**

```bash
cargo test -p envsync-domain --test resource_state
cargo clippy -p envsync-domain --all-targets -- -D warnings
git commit -m "feat(domain): add resource state model"
```

## 任务 3：确定性对象与快照

**文件：**

- 新建 `crates/envsync-domain/src/object.rs`
- 新建 `crates/envsync-domain/src/snapshot.rs`
- 新建 `crates/envsync-domain/tests/deterministic_snapshot.rs`

**测试先行：**

- 相同 bytes 始终产生相同 `BlobId`。
- ResourceEntry 插入顺序不同，State Root ID 相同。
- Snapshot metadata map 顺序不同，Snapshot ID 相同。
- 内容或格式版本变化会改变 ID。
- 非 canonical CBOR、未知版本和摘要不匹配均被拒绝。

**实现：**

- 使用 `BTreeMap` 和严格字段顺序编码 canonical CBOR。
- 哈希加入域分隔：`envsync:blob:v1`、`envsync:state:v1`、
  `envsync:snapshot:v1`。
- Snapshot ID 只覆盖 Snapshot Body；签名作为独立对象。
- 解码后重新编码并比较，拒绝非 canonical 表示。

**验证与提交：**

```bash
cargo test -p envsync-domain --test deterministic_snapshot
git commit -m "feat(domain): add deterministic snapshots"
```

## 任务 4：实现 Local Backend 与 CAS

**文件：**

- 新建 `crates/envsync-backend/src/lib.rs`
- 新建 `crates/envsync-backend/src/local.rs`
- 新建 `crates/envsync-backend/tests/local_backend.rs`

**对象布局：**

```text
root/
  objects/ab/cdef...
  refs/<workspace-id>.cbor
  locks/<workspace-id>.lock
```

**测试先行：**

- `put_object` 幂等；同 ID 不同内容返回 corruption。
- `get_object` 校验摘要，损坏对象不可返回。
- 首次 CAS 只接受 expected revision 0。
- 错误 revision 返回包含 observed revision 的冲突。
- 两线程竞争只有一方 CAS 成功。
- Ref 替换中断后旧 Ref 或新 Ref 必有一个完整可读。

**实现：**

- 定义 async `Backend` trait。
- 对象以同目录临时文件写入，flush/fsync 后 rename。
- Ref CAS 获取 per-workspace advisory lock，锁内重读 revision。
- 更新 Ref 时 fsync 文件和父目录；显式调用 `FileExt::unlock(&lock)`。
- 不通过列目录推导 Workspace 头。

**验证与提交：**

```bash
cargo test -p envsync-backend --test local_backend
git commit -m "feat(backend): add local CAS backend"
```

## 任务 5：能力约束的安全读取

**文件：**

- 新建 `crates/envsync-platform/src/capability.rs`
- 新建 `crates/envsync-platform/src/reader.rs`
- 新建 `crates/envsync-platform/tests/path_confinement.rs`

**测试先行：**

- 读取授权根内普通文件成功。
- 绝对目标、`..` 和 NUL 被拒绝。
- 中间目录或最终文件为 symlink 时拒绝。
- 不存在返回 `Observation::Absent`。
- 权限错误返回 `Unreadable`，不伪装成 Absent。
- 超过大小上限时返回明确错误且不截断。

**实现：**

- `AuthorizedRoot` 在初始化时 canonicalize 根目录并持有目录 capability。
- 相对目标以平台无关分段表示。
- 使用 `cap-std` 相对目录操作；逐段执行 no-follow 检查。
- 默认文件上限 16 MiB，可由资源策略降低。
- 读取返回 bytes、BLAKE3、mtime、长度和权限摘要。

**验证与提交：**

```bash
cargo test -p envsync-platform --test path_confinement
git commit -m "feat(platform): add capability-scoped reads"
```

## 任务 6：Full File 与 Managed Block 渲染

**文件：**

- 新建 `crates/envsync-core/src/render.rs`
- 新建 `crates/envsync-core/tests/managed_block.rs`

**测试先行：**

- Full File 精确保留 bytes。
- Managed Block 插入、更新、删除时保留块外 bytes。
- LF/CRLF 由资源策略确定，默认沿用现有文件。
- marker 缺一端、重复、嵌套或顺序错误均拒绝。
- 目标不存在时生成合法新文件。
- 非 UTF-8 文件禁止 Managed Block，但允许 Full File。

**marker：**

```text
# >>> envsync:<resource-id>
managed content
# <<< envsync:<resource-id>
```

渲染函数必须是纯函数：`existing + desired + policy -> RenderedChange`。

**验证与提交：**

```bash
cargo test -p envsync-core --test managed_block
git commit -m "feat(core): add file renderers"
```

## 任务 7：不可变 Observation-bound Plan

**文件：**

- 新建 `crates/envsync-domain/src/plan.rs`
- 新建 `crates/envsync-domain/tests/plan_identity.rs`
- 新建 `crates/envsync-core/src/planner.rs`
- 新建 `crates/envsync-core/tests/planner.rs`

**测试先行：**

- Action 顺序与 map 插入顺序不影响 Plan ID。
- Snapshot、revision、Observation 或 Action 改变都会改变 Plan ID。
- `Absent` 仅在期望为 Managed 时生成 create。
- 只有 `EnsureAbsent` 生成 delete。
- Unreadable/Unsupported/Excluded 产生阻塞诊断，不产生写入。
- 动作携带 `Risk`、备份策略、预计摘要和 verify 规则。

**动作固定排序：** `ResourceId`，再按 delete/write/block-update 类型排序。

**验证与提交：**

```bash
cargo test -p envsync-domain --test plan_identity
cargo test -p envsync-core --test planner
git commit -m "feat(core): add immutable sync plans"
```

## 任务 8：SQLite 操作日志

**文件：**

- 新建 `crates/envsync-storage/src/journal.rs`
- 新建 `crates/envsync-storage/migrations/0001_journal.sql`
- 新建 `crates/envsync-storage/tests/journal.rs`

**状态机：**

```text
planned -> preflighted -> published -> applying -> verified -> completed
                                     \-> published_not_converged
planned/preflighted -> aborted
applying/published_not_converged -> rolling_back -> rolled_back
```

**表：**

- `operations`: operation_id、plan_id、snapshot_id、revision、state、时间、错误。
- `actions`: operation_id、ordinal、resource_id、target、state、摘要、错误。
- `receipts`: backup_path、original_digest、applied_digest、guarantee。

**测试先行：**

- migration 幂等且启用 WAL、foreign keys、busy timeout。
- 非法状态迁移被 Rust 层拒绝。
- operation 与 action/receipt 在事务中持久化。
- 重开数据库后可查询未完成操作。
- storage crate 不依赖 platform crate；receipt 只存原始字段。

**验证与提交：**

```bash
cargo test -p envsync-storage --test journal
git commit -m "feat(storage): add operation journal"
```

## 任务 9：安全写入、备份和回滚收据

**文件：**

- 新建 `crates/envsync-platform/src/writer.rs`
- 新建 `crates/envsync-platform/tests/safe_writer.rs`

**测试先行：**

- 同目录临时文件不会提前改变目标。
- 成功替换后权限符合策略，内容摘要匹配。
- 原文件备份到按 operation/resource 命名的确定性路径。
- 删除总是先备份；不存在的显式删除是幂等操作。
- 写入前摘要不匹配返回 stale observation。
- 回滚只在当前摘要等于 applied digest 时执行，避免覆盖用户新修改。
- 注入 rename/fsync 失败时保留可恢复证据。

**平台策略：**

- POSIX：temp → fsync(temp) → backup → rename → fsync(parent)。
- Windows：优先 `ReplaceFileW` 封装；不可用时采用 journaled replace。
- M0 文件均为非秘密；未来秘密资源禁止降级到暴露明文的替换路径。

生产代码不使用不受约束的绝对路径；测试通过临时授权根执行。

**验证与提交：**

```bash
cargo test -p envsync-platform --test safe_writer
git commit -m "feat(platform): add recoverable file writes"
```

## 任务 10：实现 ApplyEngine 事务顺序

**文件：**

- 新建 `crates/envsync-core/src/apply.rs`
- 新建 `crates/envsync-core/tests/apply_transaction.rs`

**依赖注入：**

- `Backend`
- `Observer`
- `FileMutator`
- `Journal`
- `Clock`

**测试先行：**

1. 全部动作 preflight 成功后才允许 Publish。
2. 任一 preflight 失败时后端 Ref 和本地文件均不变。
3. CAS 失败时没有调用 FileMutator。
4. Publish 后动作依序应用并逐项保存 receipt。
5. 中途失败时已应用动作逆序回滚。
6. verify 失败时当前动作和此前动作全部回滚。
7. 回滚失败保留 `published_not_converged` 及双重错误。
8. 成功路径为 published → applying → verified → completed。

**实现伪代码：**

```rust
pub async fn apply(&self, plan: &Plan) -> Result<ApplyOutcome, ApplyError> {
    let op = self.journal.begin(plan)?;
    let staged = self.preflight_and_stage(plan, &op).await?;
    self.backend
        .compare_and_swap_ref(plan.workspace(), plan.revision(), plan.next_ref())
        .await?;
    self.journal.mark_published(&op)?;

    let mut receipts = Vec::new();
    for action in staged {
        match self.mutator.apply(&action).await {
            Ok(receipt) => {
                self.journal.record_receipt(&op, &receipt)?;
                if let Err(verify_error) = self.verify(&action).await {
                    return self.rollback_after_failure(&op, receipts, Some(receipt), verify_error).await;
                }
                receipts.push(receipt);
            }
            Err(apply_error) => {
                return self.rollback_after_failure(&op, receipts, None, apply_error).await;
            }
        }
    }
    self.journal.complete(&op)?;
    Ok(ApplyOutcome::Completed)
}
```

若 receipt 持久化失败，必须立即尝试回滚该动作和此前动作；不能直接返回。

**验证与提交：**

```bash
cargo test -p envsync-core --test apply_transaction
git commit -m "feat(core): add transactional apply engine"
```

## 任务 11：Workspace 配置、草稿与应用服务

**文件：**

- 新建 `crates/envsync-core/src/config.rs`
- 新建 `crates/envsync-storage/src/draft.rs`
- 新建 `crates/envsync-core/src/service.rs`
- 新建 `crates/envsync-core/tests/file_sync_service.rs`
- 新建 `examples/workspace.yaml`

**M0 配置 schema：**

```yaml
version: 1
workspace_id: "uuid"
backend:
  kind: local
  path: "/explicit/backend/path"
roots:
  home: "/explicit/authorized/root"
resources:
  - id: shell/zsh/main
    root: home
    target: .zshrc
    mode: managed_block
    disposition: managed
```

**测试先行：**

- 未知 version、重复 ResourceId、未知 root、绝对 target 均拒绝。
- capture 保存草稿 Blob/State/Snapshot，但不更新远端 Ref。
- plan 比较 draft、远端头和本地 Observation。
- sync 只接受 Plan ID；重新生成不一致时返回 stale plan。
- status 区分 clean、drifted、conflicted、published_not_converged。

**服务 API：**

- `init_workspace`
- `capture`
- `build_plan`
- `apply_plan`
- `status`
- `rollback`
- `recover`

草稿对象放在本地 storage，不污染 Backend；发布时才上传缺失对象并执行 CAS。

**验证与提交：**

```bash
cargo test -p envsync-core --test file_sync_service
git commit -m "feat(core): add M0 application service"
```

## 任务 12：CLI、JSON 契约与退出码

**文件：**

- 新建 `crates/envsync-cli/src/main.rs`
- 新建 `crates/envsync-cli/src/output.rs`
- 新建 `crates/envsync-cli/tests/cli.rs`
- 新建 `docs/cli.md`

**命令：**

```text
envsync init --config <path>
envsync capture --config <path>
envsync plan --config <path>
envsync sync --config <path> --plan <plan-id>
envsync status --config <path>
envsync rollback --config <path> --operation <id>
envsync doctor --config <path>
```

**测试先行：**

- 每个命令有帮助文本，缺参退出 2。
- `--json` 输出 `{schema_version, command, status, data, diagnostics}`。
- JSON stdout 只有 JSON；日志写 stderr。
- CAS conflict 退出 10、stale plan 11、policy block 12、partial convergence 20。
- 输出中的 secret-like 字段经过统一 redactor。

**验证与提交：**

```bash
cargo test -p envsync-cli
cargo run -p envsync-cli -- --help
git commit -m "feat(cli): expose M0 sync workflow"
```

## 任务 13：崩溃恢复与显式回滚

**文件：**

- 新建 `crates/envsync-core/src/recovery.rs`
- 新建 `crates/envsync-core/tests/recovery.rs`
- 修改 `crates/envsync-platform/src/writer.rs`

**测试矩阵：**

- `preflighted`：清理 staged 文件，标记 aborted。
- `published`：重新计划本地收敛，不重复 CAS。
- `applying` 且目标等于 applied digest：继续下一动作。
- `applying` 且目标等于 original digest：重新应用当前动作。
- 目标两者都不等：停止并报告人工冲突。
- `rolling_back`：根据 receipt 逆序继续。
- 备份缺失或摘要不符：不覆盖，保留可诊断状态。

恢复算法必须幂等；连续运行两次得到相同最终状态。`doctor` 在任何修复前只报告，
`recover` 由 `sync` 启动时自动运行，并写审计事件。

**验证与提交：**

```bash
cargo test -p envsync-core --test recovery
git commit -m "feat(core): recover interrupted operations"
```

## 任务 14：端到端验收、CI 与运维文档

**文件：**

- 新建 `tests/e2e/local_file_loop.rs`
- 新建 `docs/m0-operations.md`
- 新建 `docs/security-model.md`
- 修改 `.github/workflows/ci.yml`
- 修改 `README.md`

**E2E 场景：**

1. 临时授权根和 Local Backend 初始化。
2. 捕获 Full File 与 Managed Block。
3. 生成并保存 Plan。
4. 模拟第二设备拉取并应用。
5. 验证块外内容不变、Snapshot ID 相同、状态 clean。
6. 修改源设备并再次同步。
7. 回滚第二次 operation，验证恢复到第一次内容。
8. 模拟 CAS race，验证失败方本地零变更。
9. 注入 apply 中断，再次启动完成恢复。
10. 确认普通缺失资源未被删除，显式 tombstone 才删除。

**文档必须说明：**

- 数据模型、事务边界和失败状态。
- 配置示例与完整 CLI 流程。
- 备份位置、恢复与人工冲突处理。
- M0 威胁边界和不提供的安全保证。
- 从 M0 升级到后续 schema 的兼容策略。

**最终验证：**

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --doc
```

在 Linux、macOS、Windows CI 都成功后提交：

```bash
git commit -m "test: complete M0 acceptance suite"
```

## M0 完成定义

- 设计文档中的十项 M0 验收条件全部有自动化测试。
- 所有外部写入都有 Plan、journal 和 rollback receipt。
- 所有错误保留机器可读错误码和不含秘密的诊断。
- 无未决占位说明、忽略测试、未解释的 `allow` 或 Clippy warning。
- README、CLI、运维、安全文档与实现一致。
- 工作树 clean，所有验证命令输出已记录在最终交付说明中。
