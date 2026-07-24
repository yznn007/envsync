# EnvSync

EnvSync 是一个本地优先、跨平台的开发环境同步工具。它面向 macOS、Linux 和
Windows，统一管理 shell 配置、终端配置、Git 参数、包管理器期望状态、AI
Agent/Skill 配置以及显式选择的凭据。

项目状态：架构设计已批准，M0–M4 实施计划与跨 Agent 交接指南已完成，尚未开始编码。

## 文档

- [系统设计](docs/superpowers/specs/2026-07-24-envsync-design.md)
- [M0 实施计划](docs/superpowers/plans/2026-07-24-envsync-m0-safe-file-loop.md)
- [M1 Git、Profile 与合并计划](docs/superpowers/plans/2026-07-24-envsync-m1-git-profiles-merge.md)
- [M2 Vault 与设备安全计划](docs/superpowers/plans/2026-07-24-envsync-m2-vault-device-security.md)
- [M3 包管理器与 Agent Bundle 计划](docs/superpowers/plans/2026-07-24-envsync-m3-packages-agent-bundles.md)
- [M4 桌面端、Gist 与插件计划](docs/superpowers/plans/2026-07-24-envsync-m4-desktop-gist-plugins.md)
- [实施交接指南](docs/IMPLEMENTATION_HANDOFF.md)

## 路线图

- M0：本地后端、安全文件捕获、计划、应用、验证和回滚
- M1：Git 后端、Profile 投影、三方合并
- M2：Vault、设备身份、成员关系与恢复
- M3：包管理器、Agent Bundle、Skill 和策略引擎
- M4：Tauri 桌面端、Gist 后端、插件 SDK

完整命令行和桌面端技术栈为 Rust、Tauri 2、Vue 3、TypeScript。
