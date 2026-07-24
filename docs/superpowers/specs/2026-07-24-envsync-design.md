# EnvSync 系统设计

**日期：** 2026-07-24

**状态：** 已批准

**目标平台：** macOS、Linux、Windows

## 1. 产品定义

EnvSync 将不同设备上的开发环境表达为一个可审计、可投影、可回滚的 Workspace。
它不是简单复制整个家目录，也不直接把一台机器的绝对路径强加给另一台机器。

首要使用场景：

- 同步 `.bashrc`、`.zshrc`、PowerShell Profile、WezTerm Lua、Git 配置。
- 同步 Homebrew、Scoop、Winget、Chocolatey、APT、Cargo、npm/pnpm 等包清单。
- 同步应用或包管理器的配置，但不默认同步缓存和安装目录的二进制内容。
- 同步 Codex、Claude Code、OpenCode 等工具的 Agent、Skill、MCP 配置与规则。
- 在显式授权后同步 API Token、SSH/GPG 引用和其他秘密。
- 使用本地目录、Git 仓库或 GitHub Gist 作为后端。

## 2. 设计原则

1. **本地优先。** 所有扫描、比较、渲染、加解密和计划生成都在本机完成。
2. **计划先行。** 任何写入前都必须产生不可变 Plan，展示差异、风险和影响范围。
3. **最小权限。** 适配器只能访问声明过的路径、命令和环境变量。
4. **默认不删除。** 远端缺失不等于本地删除；删除必须是显式 tombstone。
5. **秘密默认隔离。** 普通快照不含明文秘密，Vault 内容端到端加密。
6. **可恢复。** 文件写入有备份和收据，操作有日志，可从中断点恢复或回滚。
7. **确定性。** 相同规范化输入产生相同 Blob、State Root 和 Snapshot ID。
8. **跨平台投影。** Workspace 表达意图，Profile 决定每台设备实际应用的子集。

## 3. 核心模型

### 3.1 Workspace 与 Profile

Workspace 是唯一逻辑同步头。每次发布生成完整 Snapshot。设备通过 Profile
Projection 选择适合自己的资源：

- `os`: macOS / Linux / Windows
- `arch`: x86_64 / aarch64
- `hostname`、标签、角色
- 可用能力，例如 `brew`、`scoop`、`pwsh`
- 用户覆盖和策略

同一个 Snapshot 因设备 Profile 不同，可以产生不同的本地 Plan。

### 3.2 资源状态

观察状态必须显式区分：

- `present`：资源存在且可读取
- `absent`：资源确定不存在
- `unsupported`：当前平台或适配器不支持
- `unreadable`：存在但无权限或读取失败
- `excluded`：被策略排除

期望处置：

- `managed`：将资源收敛到快照内容
- `ensure_absent`：显式删除，即 tombstone
- `unmanaged`：不归 EnvSync 管理

`absent`、`unsupported`、`unreadable`、`excluded` 都不能被推断为删除意图。

### 3.3 内容寻址对象

后端保存不可变对象：

- Blob：原始或规范化后的资源内容
- State Root：`ResourceId -> ResourceEntry`
- Snapshot Body：父快照、State Root、作者设备、格式版本、元数据
- Snapshot Signature：设备签名
- Ref：Workspace 当前头及单调 revision

所有对象使用 BLAKE3 内容摘要。编码使用严格版本化的 canonical CBOR。未知格式版本
必须拒绝，不能静默降级。

### 3.4 Plan

Plan 绑定：

- 目标 Snapshot ID
- 后端 Ref revision
- 本机所有相关 Observation
- 排序后的 Action
- 风险、预计副作用和回滚能力

Plan ID 由上述完整内容确定。应用前重新观察；任何内容摘要或能力变化都会使计划失效。

## 4. 同步事务

固定顺序如下：

1. Preflight：验证能力、路径边界、快照、Blob 和计划新鲜度。
2. Stage：在目标文件同目录准备临时文件、权限与备份。
3. Publish：通过 CAS 更新后端 Ref。
4. Apply/Converge：原子替换、受控删除或命令执行。
5. Verify：重新观察并核对应用后摘要。
6. Commit journal：记录结果和回滚收据。

CAS 冲突必须发生在本地变更之前。Publish 成功但本地应用失败时，状态为
`published_not_converged`；它不是普通失败，后续必须恢复收敛或显式回滚本地状态。

## 5. 文件管理模式

- **Full File**：EnvSync 管理整个文件，适合专用配置文件。
- **Managed Block**：仅管理带稳定标识的区块，适合 `.zshrc` 等用户文件。
- **Structured Merge**：对 JSON/YAML/TOML/INI/Git config 做语义合并。
- **Generated Include**：生成独立文件，再向主配置注入一个 include/source。

写入约束：

- 目标必须位于授权根目录内；拒绝 `..`、绝对路径逃逸和符号链接穿越。
- POSIX 优先同目录临时文件、fsync、rename、目录 fsync。
- Windows 使用 `ReplaceFile` 或可恢复的 journaled replace。
- 删除前必须备份；秘密文件不得退化为可暴露明文的非原子流程。

## 6. 包管理器

包适配器同步的是期望状态，不复制安装目录：

- Homebrew：formula、cask、tap，导入/导出 Brewfile。
- Scoop：bucket、app、persist 元数据。
- Winget/Chocolatey：已选包和可选版本约束。
- APT/DNF/Pacman：显式包清单；系统级应用需要单独提升权限。
- Cargo、npm、pnpm、pipx、uv：全局工具与来源。

每个包状态记录版本策略：`exact`、`compatible`、`latest` 或 `present`。默认只安装缺失项；
卸载必须由显式 tombstone 和策略允许共同触发。

## 7. Agent、Skill 与凭据

Agent Bundle 是一类主动内容，必须经过独立策略：

- 可同步 Agent 定义、Skill、提示规则、MCP 配置和工具权限模板。
- 默认隔离到 quarantine，展示来源、签名、diff 与声明能力后再启用。
- Bundle 不得内嵌明文 Token，只能引用 Vault 中的逻辑 Secret ID。
- 适配器将统一模型渲染为各工具格式，并保留不支持字段的诊断信息。

Vault：

- 每个 Workspace 使用随机数据密钥。
- 每个设备使用 HPKE envelope 获取数据密钥。
- 恢复密钥通过 Argon2id 派生，仅保存加密包。
- 设备成员关系使用管理员/成员签名链；移除设备后轮换数据密钥。
- 本地密钥优先存入 Keychain、Windows Credential Manager 或 Secret Service。
- 快照检查点防止后端回滚攻击。

秘密默认不进入普通 Git diff。Gist MVP 只允许 sealed bundle，不提供明文模式。

## 8. 后端

统一 Backend trait：

- `get_ref(workspace)`
- `compare_and_swap_ref(workspace, expected_revision, next)`
- `get_object(id)`
- `put_object(id, bytes)`（幂等）
- `list_objects(prefix)`（维护用途）

实现顺序：

1. Local directory：离线测试、单机和可移动介质。
2. Git：普通远程、自托管 GitHub/GitLab/Gitea。
3. GitHub Gist：单文件 sealed bundle，MVP 上限 256 个资源、5 MiB。
4. 后续：S3/WebDAV/对象存储，通过同一对象与 CAS 语义接入。

## 9. 技术架构

Rust workspace：

- `envsync-domain`：ID、资源状态、快照、计划和错误模型。
- `envsync-backend`：Backend trait 与 Local/Git/Gist 实现。
- `envsync-platform`：授权路径、安全读写、能力探测。
- `envsync-adapters`：内建文件、Git、包管理器、Agent 适配器。
- `envsync-storage`：SQLite 操作日志、草稿和本地索引。
- `envsync-core`：捕获、合并、计划、同步、恢复和回滚服务。
- `envsync-cli`：可脚本化 CLI。
- `envsync-desktop`：Tauri 2 桌面壳。

桌面端使用 Vue 3、TypeScript、Vite、Pinia，调用与 CLI 相同的 Rust application service。
前端不直接读写用户配置文件。

## 10. 命令面

M0：

- `envsync init`
- `envsync capture`
- `envsync plan`
- `envsync sync`
- `envsync status`
- `envsync rollback`
- `envsync doctor`

所有命令支持 `--json`；JSON schema 带版本号。默认人类输出不得泄漏秘密内容。

## 11. 里程碑

### M0：安全文件闭环

Local Backend、Full File、Managed Block、确定性快照、不可变 Plan、CAS 发布、安全写入、
SQLite journal、验证、回滚、CLI 和 Linux/macOS/Windows CI。

### M1：可用同步

Git Backend、Profile Projection、structured merge、冲突对象、Git 参数和更多 shell/终端适配器。

### M2：安全多设备

Vault、设备身份、成员关系、恢复、密钥轮换、反回滚和秘密审计。

### M3：开发生态

包管理器期望状态、Agent Bundle、Skill、quarantine、策略引擎。

### M4：产品化

Tauri 桌面端、Gist 后端、可视化 diff/恢复、插件 SDK、签名分发和升级。

## 12. M0 验收条件

- 相同输入在不同运行中产生相同 Snapshot ID。
- 越权路径和符号链接逃逸均在读取或写入前被拒绝。
- CAS 冲突时本地文件没有任何变化。
- 应用前文件被外部修改时 Plan 失效。
- 应用中任一动作失败时，已应用动作按逆序回滚。
- 进程在 replace 中断后，下一次启动能从 journal 判断并恢复。
- 未显式 `ensure_absent` 的资源绝不删除。
- Managed Block 保留块外内容，并拒绝重复或畸形 marker。
- CLI 集成测试覆盖 capture → plan → sync → verify → rollback。
- `cargo fmt --check`、`cargo clippy --workspace --all-targets -- -D warnings`、
  `cargo test --workspace` 在三大操作系统 CI 通过。
