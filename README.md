# EnvSync

EnvSync 是一个本地优先、跨平台的开发环境同步工具。它面向 macOS、Linux 和
Windows，统一管理 shell 配置、终端配置、Git 参数、包管理器期望状态、AI
Agent/Skill 配置以及显式选择的凭据。

项目状态：**M0（安全文件闭环）已完成**——本地后端、Full File 与 Managed Block、确定性快照、
不可变 Plan、CAS 发布、安全写入、SQLite journal、验证、回滚与崩溃恢复、可脚本化 CLI，
以及 Linux / macOS / Windows 三平台 CI 全部就绪。M1 尚未开始。

> M0 **不提供**密码学签名、加密和反回滚保护。在 M2 的 Vault 交付之前，
> 不要把真实凭据放进 EnvSync 管理的普通资源——详见[安全模型](docs/security-model.md)。

## 快速开始

```bash
# 1) 构建（需要 Rust stable，MSRV 1.82）
cargo build --release -p envsync-cli

# 2) 安装到 ~/.cargo/bin
cargo install --path crates/envsync-cli

# 3) 初始化工作区，然后编辑生成的配置把要管理的文件填进 resources
envsync init --config /home/YOUR_USER/.config/envsync/envsync.yaml \
             --backend-path /srv/YOUR_BACKEND/envsync \
             --device-name laptop
```

随后的日常闭环：

```bash
CFG=/home/YOUR_USER/.config/envsync/envsync.yaml
envsync doctor  --config "$CFG"   # 只读体检
envsync capture --config "$CFG"   # 观察本机现状，生成快照草稿
envsync plan    --config "$CFG"   # 生成并审阅不可变计划
envsync sync    --config "$CFG" --plan <plan-id>
envsync status  --config "$CFG"
```

配置文件的逐字段说明见 [`examples/workspace.yaml`](examples/workspace.yaml)，
完整命令与 JSON 契约见 [命令行文档](docs/cli.md)。

## 架构

Rust workspace，六个功能 crate 严格分层，依赖只能自下而上：

```text
                      ┌───────────────────┐
                      │   envsync-cli     │  参数解析、JSON 信封、退出码、脱敏
                      └─────────┬─────────┘
                                │
                      ┌─────────▼─────────┐
                      │   envsync-core    │  capture / plan / sync / recover / rollback
                      │                   │  应用服务，CLI 与桌面端共用的唯一入口
                      └──┬─────┬───────┬──┘
             ┌───────────┘     │       └───────────┐
             │                 │                   │
   ┌─────────▼────────┐ ┌──────▼────────┐ ┌────────▼────────┐
   │ envsync-backend  │ │envsync-platform│ │ envsync-storage │
   │ Backend trait    │ │ 授权根、安全读写│ │ SQLite journal  │
   │ + LocalBackend   │ │ 备份与回滚收据 │ │ + 草稿对象库    │
   └─────────┬────────┘ └──────┬────────┘ └────────┬────────┘
             └─────────────────┼───────────────────┘
                               │
                     ┌─────────▼─────────┐
                     │  envsync-domain   │  ID、资源状态、快照、计划、
                     │                   │  canonical CBOR，纯逻辑无 I/O
                     └───────────────────┘
```

（`envsync-cli` 另外直接依赖 `envsync-domain`、`envsync-backend`、`envsync-storage`
用于类型解析与错误码渲染。）

四条分层不变量：

| 不变量 | 由谁保证 |
|---|---|
| 领域层是纯逻辑，不做任何 I/O | `envsync-domain` 不依赖任何其他 workspace crate |
| 只有一个 crate 能碰用户文件系统 | `envsync-platform` 独占 `cap-std` 能力句柄 |
| 崩溃恢复只信任一个事实来源 | `envsync-storage` 的 `journal.db`（`synchronous=FULL`） |
| 全部安全决策在核心层，界面只展示 | `envsync-core::EnvSyncService` 是唯一入口 |

此外还有一个不被任何 crate 依赖的端到端验收套件 `envsync-e2e`：它不调用
`EnvSyncService`，而是启动真正的 `envsync` 二进制，覆盖退出码、`--json` 的
stdout/stderr 分流、跨进程 CAS 竞争与中断后恢复——这些性质只有在真进程里才成立。

工作区内**全部** crate 均设置 `#![forbid(unsafe_code)]`。

## 质量门槛

以下命令必须在 Linux、macOS、Windows 三平台全部通过：

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --doc
```

CI（[`.github/workflows/ci.yml`](.github/workflows/ci.yml)）在
`ubuntu-latest` / `macos-latest` / `windows-latest` 上运行同一组命令，
另有 `cargo audit` 依赖审计（记录但不阻塞合并）。

## 文档

**使用与运维**

- [命令行文档](docs/cli.md)：命令、参数、JSON 契约、退出码、脱敏规则
- [M0 运维手册](docs/m0-operations.md)：数据模型、事务边界与失败状态、备份与恢复、
  版本兼容策略、故障排查手册
- [安全模型](docs/security-model.md)：信任边界、M0 提供与**不提供**的保证、秘密处理约定
- [配置示例](examples/workspace.yaml)：逐字段注释，且被测试真实解析

**设计与计划**

- [系统设计](docs/superpowers/specs/2026-07-24-envsync-design.md)
- [M0 实施计划](docs/superpowers/plans/2026-07-24-envsync-m0-safe-file-loop.md)
- [M1 Git、Profile 与合并计划](docs/superpowers/plans/2026-07-24-envsync-m1-git-profiles-merge.md)
- [M2 Vault 与设备安全计划](docs/superpowers/plans/2026-07-24-envsync-m2-vault-device-security.md)
- [M3 包管理器与 Agent Bundle 计划](docs/superpowers/plans/2026-07-24-envsync-m3-packages-agent-bundles.md)
- [M4 桌面端、Gist 与插件计划](docs/superpowers/plans/2026-07-24-envsync-m4-desktop-gist-plugins.md)
- [实施交接指南](docs/IMPLEMENTATION_HANDOFF.md)

**决策记录**（[`docs/decisions/`](docs/decisions/)）

- [ADR-0001：在 domain crate 内自实现严格 canonical CBOR 编解码器](docs/decisions/2026-07-26-canonical-cbor-in-domain.md)
- [ADR-0002：DeviceId 从第一天起就是派生摘要而非 UUID](docs/decisions/2026-07-26-device-id-derivation.md)
- [ADR-0003：Plan ID 绑定输入而不绑定生成时刻](docs/decisions/2026-07-26-plan-id-excludes-timestamp.md)
- [ADR-0004：Backend 与适配器 trait 采用同步 I/O](docs/decisions/2026-07-26-synchronous-backend-trait.md)

## 路线图

- **M0（已完成）**：本地后端、安全文件捕获、计划、应用、验证和回滚
- M1：Git 后端、Profile 投影、三方合并
- M2：Vault、设备身份、成员关系与恢复
- M3：包管理器、Agent Bundle、Skill 和策略引擎
- M4：Tauri 桌面端、Gist 后端、插件 SDK

完整命令行和桌面端技术栈为 Rust、Tauri 2、Vue 3、TypeScript。
