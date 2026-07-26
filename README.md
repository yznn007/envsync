# EnvSync

EnvSync 是一个本地优先、跨平台的开发环境同步工具。它面向 macOS、Linux 和
Windows，统一管理 shell 配置、终端配置、Git 参数、包管理器期望状态、AI
Agent/Skill 配置以及显式选择的凭据。

项目状态：**M0、M1 已完成；M2 进行中。**

- **M0（安全文件闭环）**：本地后端、Full File 与 Managed Block、确定性快照、不可变
  Plan、CAS 发布、安全写入、SQLite journal、验证、回滚与崩溃恢复、可脚本化 CLI。
- **M1（可用同步）**：Git 后端、设备 Profile 投影、三方合并（文本 + JSON/YAML/TOML/
  INI/Git config）、冲突对象与裁决流程、首批 shell / 终端 / Git 内建适配器，
  以及 `fetch` / `merge` / `conflicts` / `profile explain` 四组新命令与 JSON 契约 v2。
- **M2（Vault 与设备安全，进行中）**：密码学层（固定算法套件、设备身份与域分隔签名、
  密封秘密对象、HPKE 设备信封、Argon2id 恢复包）、设备成员签名链、系统安全存储接入、
  反回滚检查点、可恢复的密钥轮换与 Vault 应用服务均已落地并有攻击路径测试；
  `device` / `vault` / `recovery` / `security` 四组命令行入口仍在开发中。

Linux / macOS / Windows 三平台 CI 全部就绪。

**Git 后端**把 EnvSync 的内容寻址对象映射进一棵普通的 Git tree
（`.envsync/objects/…` + `.envsync/refs/<workspace>.cbor`），用远端 branch head 做
CAS：push 永不带 force，发布前做 lease 校验、发布后回读确认，凭据只能来自 ssh-agent、
git credential helper 或 Vault secret 引用——URL 里写不进凭据。详见
[Git 后端文档](docs/backends/git.md)。

> **普通同步资源在后端上仍然是明文**——M2 的端到端加密只覆盖 Vault。不要把真实凭据
> 放进 EnvSync 管理的普通资源，详见[安全模型](docs/security-model.md)（§3.2、§5.3.8）。
> M2 已提供的保证与**仍然不提供**的保证见同一文档的 §5.2 与 §5.3。

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

多设备（M1）在 `capture` 之前多两步——先把远端拉下来并合并：

```bash
envsync fetch   --config "$CFG"   # 拉远端对象，不碰用户文件
envsync merge   --config "$CFG"   # 三方合并；有冲突只登记，不改任何文件
envsync profile explain --config "$CFG"   # 这台设备会拿到哪些资源、为什么

# 有冲突时（sync 会以退出码 13 拒绝，本地文件与远端 Ref 都不变）
envsync conflicts list    --config "$CFG"
envsync conflicts resolve --config "$CFG" --conflict <id> --theirs
```

配置文件的逐字段说明见 [`examples/workspace.yaml`](examples/workspace.yaml)（本地后端）
与 [`examples/workspace-git.yaml`](examples/workspace-git.yaml)（Git 后端 + Profile +
selector + 设备覆盖），完整命令与 JSON 契约见 [命令行文档](docs/cli.md)。

## 架构

Rust workspace，七个功能 crate 严格分层，依赖只能自下而上：

```text
        ┌───────────────────┐         ┌────────────────────┐
        │   envsync-cli     │         │  envsync-adapters  │  内建文件 / Shell /
        │ 参数解析、JSON 信封 │         │  sealed Adapter    │  WezTerm / Git 配置
        │ 退出码、脱敏       │         │  trait + 注册表     │  适配器（纯函数）
        └─────────┬─────────┘         └─────────┬──────────┘
                  │                             │
                  └──────────────┬──────────────┘
                                 │
                       ┌─────────▼─────────┐
                       │   envsync-core    │  capture / plan / sync / recover / rollback
                       │                   │  + M1：projection / merge / sync 编排
                       │                   │  应用服务，CLI 与桌面端共用的唯一入口
                       └──┬─────┬───────┬──┘
              ┌───────────┘     │       └───────────┐
              │                 │                   │
    ┌─────────▼────────┐ ┌──────▼────────┐ ┌────────▼────────┐
    │ envsync-backend  │ │envsync-platform│ │ envsync-storage │
    │ Backend trait    │ │ 授权根、安全读写│ │ SQLite journal  │
    │ + Local + Git    │ │ 备份与回滚收据 │ │ + 草稿库 + 冲突索引│
    └─────────┬────────┘ └──────┬────────┘ └────────┬────────┘
              └─────────────────┼───────────────────┘
                                │
                      ┌─────────▼─────────┐
                      │  envsync-domain   │  ID、资源状态、快照、计划、Profile、
                      │                   │  冲突，canonical CBOR，纯逻辑无 I/O
                      └───────────────────┘
```

（`envsync-cli` 另外直接依赖 `envsync-domain`、`envsync-backend`、`envsync-storage`
用于类型解析与错误码渲染；`envsync-adapters` 另外直接依赖 `envsync-domain` 与
`envsync-platform`。）

六条分层不变量：

| 不变量 | 由谁保证 |
|---|---|
| 领域层是纯逻辑，不做任何 I/O | `envsync-domain` 不依赖任何其他 workspace crate |
| 只有一个 crate 能碰用户文件系统 | `envsync-platform` 独占 `cap-std` 能力句柄 |
| 崩溃恢复只信任一个事实来源 | `envsync-storage` 的 `journal.db`（`synchronous=FULL`） |
| 全部安全决策在核心层，界面只展示 | `envsync-core::EnvSyncService` 是唯一入口 |
| 第三方不能在进程内决定「哪些文件被读写」 | `envsync-adapters::Adapter` 是 **sealed** trait；M4 的插件走进程隔离 IPC，不放开这个 trait |
| 凭据不进入进程状态，也不进入日志 | `envsync-backend::git_auth` 的封闭枚举 + 静态错误文本 + 统一 redaction |

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

- [命令行文档](docs/cli.md)：命令、参数、JSON 契约（v1/v2）、退出码、脱敏规则
- [M0 运维手册](docs/m0-operations.md)：数据模型、事务边界与失败状态、备份与恢复、
  版本兼容策略、故障排查手册
- [安全模型](docs/security-model.md)：信任边界（M0 基线 + M2 叠加）、提供与**不提供**的
  保证、秘密处理约定
- [配置示例](examples/workspace.yaml)：逐字段注释，且被测试真实解析
- [Git 后端配置示例](examples/workspace-git.yaml)：Git 后端 + Profile + selector + 设备覆盖

**M1 专题**

- [设备 Profile 与投影](docs/profiles.md)：Profile 组成、selector 语法、投影优先级、
  `profile explain` 的解读与常用配方
- [Git 后端](docs/backends/git.md)：tree 布局、CAS 的确切保证与前提、认证与 redaction、
  离线行为、换后端、备份与故障排查
- [冲突处理](docs/conflicts.md)：冲突对象与状态机、`conflicts` 命令、退出码 13、恢复流程
- [合并规则](docs/merge.md)：文本 diff3 与五种结构化格式的规则、已知限制、资源上限
- [适配器](docs/adapters.md)：内建适配器清单、sealed trait 与 M4 插件 SDK 的关系

**M2 安全专题**

- [Vault 线格式与密钥派生](docs/security/vault-format.md)：算法套件、sealed object 与
  HPKE 信封的逐字段定义、域分隔标签总表、纪元语义与 lazy rewrap 边界、nonce 生日界、
  编译期不变量清单
- [设备成员链与反回滚检查点](docs/security/device-membership.md)：事件链结构、角色授权
  矩阵、26 条攻击路径与对应错误码、邀请/加入/撤销/恢复四个仪式、`DeviceId` 迁移步骤、
  检查点判定规则与 `reset_trust_root` 的危险性
- [恢复短语与恢复包](docs/security/recovery.md)：熵与 Base32-Crockford 编码、Argon2id
  参数上下限、恢复仪式、**备份责任与丢失短语的后果**
- [测试向量](docs/security/test-vectors/README.md)：冻结的回归向量（**非官方互操作
  向量**）与发布前审计待办

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
- **M1（已完成）**：Git 后端、Profile 投影、三方合并、冲突对象、首批内建适配器
- **M2（进行中）**：Vault、设备身份、成员关系与恢复
- M3：包管理器、Agent Bundle、Skill 和策略引擎
- M4：Tauri 桌面端、Gist 后端、插件 SDK

完整命令行和桌面端技术栈为 Rust、Tauri 2、Vue 3、TypeScript。
