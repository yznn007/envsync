# ADR-0002：DeviceId 从第一天起就是派生摘要而非 UUID

**日期：** 2026-07-26

**状态：** 已接受

**相关计划：** M0 任务 2；M2 任务 2

## 背景

两份计划对 `DeviceId` 的定义不一致：

- M0 任务 2：「`WorkspaceId`、`DeviceId` 使用 UUID newtype」。
- M2 任务 2：「`DeviceId` 由两个 public key 的域分隔摘要派生。修改任一 key 都改变
  DeviceId。」

按交接指南「不修改已批准语义；发现设计冲突时写 ADR 并暂停冲突任务」，此处记录冲突及
处理方式。

## 决策

`DeviceId` 从 M0 起就定义为 32 字节域分隔摘要（域标签 `envsync:device:v1`），构造函数为
`DeviceId::derive(public_material)`：

- **M2 之前**：传入设备初始化时生成的随机设备种子；
- **M2 起**：传入 `X25519 公钥 || Ed25519 公钥`。

`WorkspaceId` 保持 UUID newtype 不变——工作区没有与之绑定的密钥材料，随机标识是正确
选择。

## 理由

`DeviceId` 出现在 `SnapshotBody.author_device`、`SnapshotSignature.device`、成员事件、
HPKE envelope 和本地检查点中。如果 M0 用 UUID、M2 改为摘要，则：

1. 所有已发布快照的 `author_device` 字段类型宽度改变，State Root 与 Snapshot ID 全部
   失效，等于强制所有用户重新初始化工作区；
2. M2 的反回滚检查点保存的历史 `DeviceId` 无法与新格式比较，安全属性在迁移窗口内失守。

而提前采用摘要形式的成本几乎为零：M0 只需要一个稳定唯一的设备标识，随机种子的摘要
完全满足；同时 M2 切换到公钥派生时，**类型、宽度与编码都不变**，只是 `derive` 的输入
从种子换成公钥，属于纯粹的语义收紧而非 schema 破坏。

## 后果

- M2 的「修改任一 key 都改变 DeviceId」由 `derive` 的域分隔哈希天然满足，M0 已有测试
  `device_id_changes_with_any_public_key_bit` 覆盖；
- M0 到 M2 的迁移中，已有设备需要重新派生 `DeviceId`（因为输入从种子换成公钥）。这被
  视为一次**显式设备重新注册**，会在 M2 的成员链中作为 `AddMember` 事件记录，而不是
  静默改写历史；相关流程写入 `docs/security/device-membership.md`。

## 影响范围

`envsync-domain::id::DeviceId`；`SnapshotBody`；`SnapshotSignature`；M2 成员链与检查点。
