# EnvSync 实施交接指南

本文是后续 Agent 的入口。开始工作前先读：

1. `docs/superpowers/specs/2026-07-24-envsync-design.md`
2. 本文
3. 当前里程碑对应的实施计划
4. `git log --oneline --decorate -20`
5. `git status --short`

## 执行顺序

| 顺序 | 计划 | 前置条件 | 可交付结果 |
|---|---|---|---|
| 1 | `2026-07-24-envsync-m0-safe-file-loop.md` | 设计已批准 | Local Backend 文件同步闭环 |
| 2 | `2026-07-24-envsync-m1-git-profiles-merge.md` | M0 验收全部通过 | Git、多 Profile、结构化合并 |
| 3 | `2026-07-24-envsync-m2-vault-device-security.md` | M1 schema 冻结 | 多设备身份与端到端加密 Vault |
| 4 | `2026-07-24-envsync-m3-packages-agent-bundles.md` | M2 policy 与 Vault API 稳定 | 包管理器和 Agent/Skill 同步 |
| 5 | `2026-07-24-envsync-m4-desktop-gist-plugins.md` | M3 application service 稳定 | 桌面端、Gist、插件 SDK |

里程碑必须按顺序合并。一个 Agent 可以只执行一份计划；不得用后续里程碑绕过当前
里程碑的完成条件。

## 每个 Agent 的工作协议

1. 使用隔离 worktree 和功能分支：`feature/mN-<slice>`。
2. 使用计划头部要求的执行技能，逐任务勾选。
3. 每个行为先添加失败测试，保存失败输出，再写最小实现。
4. 每个任务独立提交，提交遵循 Conventional Commits。
5. 不修改已批准语义；发现设计冲突时在
   `docs/decisions/YYYY-MM-DD-<decision>.md` 写 ADR，并暂停冲突任务。
6. 不把 Token、私钥、真实用户路径或本机配置加入 fixture。
7. 不使用 `unsafe`；确需平台 FFI 时放入单独的、审计过的 platform crate，并以
   安全 wrapper 限定范围。
8. 完成前执行当前计划的全量验证命令，记录实际输出。

## 共享不变量

- Backend 对象不可变，Ref 只能通过 CAS 前进。
- Observation 缺失不代表删除；只有 `EnsureAbsent` 可以产生 delete。
- Apply 前 Plan 必须仍绑定当前 Observation 和 Ref revision。
- 普通同步对象绝不包含明文秘密。
- 所有本地修改都有 journal、receipt、verify 和可诊断恢复路径。
- Profile 只能缩小或转换 Workspace 意图，不能绕过安全策略。
- 插件、Agent Bundle 和远端内容默认不可信。
- JSON API 与持久化 schema 都有显式版本号。

## 分支交接模板

后续 Agent 在最终消息和提交说明中提供：

```text
里程碑/任务：
分支与提交：
已实现：
验证命令与结果：
schema/API 变化：
安全影响：
未完成或已知限制：
下一任务入口：
```

## 全局质量门槛

每个里程碑至少执行：

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --doc
```

有前端后再执行：

```bash
pnpm --dir apps/desktop-ui lint
pnpm --dir apps/desktop-ui typecheck
pnpm --dir apps/desktop-ui test
pnpm --dir apps/desktop-ui build
```

CI 必须覆盖 Linux、macOS、Windows。不得以跳过测试或降低 warning 等级完成里程碑。

## 发布前的最终审计

M4 完成后另开计划处理：

- 威胁模型复核与第三方安全审计。
- 加密格式测试向量和跨版本解密兼容性。
- 数据迁移演练、备份恢复演练、安装包签名。
- SBOM、依赖许可证、漏洞扫描和可复现构建。
- 性能基准、故障注入和至少两台真实设备的升级测试。
