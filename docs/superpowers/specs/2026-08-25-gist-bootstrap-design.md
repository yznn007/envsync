# Gist 密封 Bundle 引导层设计

## 目标

让 M2 工作区能在 GitHub Gist 的单文件密封 Bundle 上安全同步：普通资源、Vault 索引、
Secret ID 与快照 metadata 保持密封；新设备和密钥轮换后的有效设备仍能先取得自己的当前
纪元 `DataKey`，再解开私有对象。

## 约束

- 单文件 Base64URL/canonical CBOR，编码后最多 5 MiB，最多 256 条资源。
- 资源路径、资源正文、Snapshot metadata、Vault Secret ID、Vault Index 与密封秘密对象
  不得出现在外层明文。
- 已撤销设备绝不能依赖旧纪元密钥读取新 Bundle；不能以旧密钥再包一层当前内容。
- 后端不能依赖 `envsync-core`，但必须能验证 Vault 对象闭包。
- 外层任何字段都不是信任根；新设备仍以邀请中的 genesis 为根，现有设备仍以本地已验证
  成员链和反回滚检查点为根。

## 决策

将 Vault Index 的纯线格式模型移动到 `envsync-crypto::vault`，由 core 和 backend 共同使用。
它仍只包含公开标识与密文对象引用，不持有设备私钥或 I/O。这样 Gist 格式可准确遍历
`VaultIndex -> membership events / current KeyEnvelope / SealedSecret / recovery package`，而不
复制 Vault CBOR schema。

Bundle 外层新增一个**最小引导区**，仅可含两种已校验对象：

1. `MembershipEvent`：完整成员链，供核心层从邀请 genesis 或本地锚点重放验证；
2. `KeyEnvelope`：当前纪元发给成员设备的 HPKE 信封，供目标设备解开当前 `DataKey`。

它们都由 bundle digest 和设备签名认证，并且会从私有 payload 中移出以避免重复。引导区
不会携带 Vault Index、Secret ID、资源路径或任意 Blob；所有这些仍在 AEAD 密封 payload 中。
`inspect_bootstrap()` 可在没有 DataKey 时读取**未验证**引导数据；core 的
`verify_gist_bootstrap_for_invitation()` 以邀请的 genesis、成员链锚点和签名验证它，再仅为
同一份 bundle 的完整解包打开本机信封。`GistBootstrapTrust::unpack()` 消费这份临时材料；
只有摘要、签名、AEAD 和完整闭包都成功后，它才会交出已验证对象与可持久化的当前密钥。

## 数据流

```text
完整对象集
  -> 从 Ref head 递归检查 Snapshot / StateRoot / Blob / VaultIndex 闭包
  -> 从 head VaultIndex 提取 membership + 当前 KeyEnvelope
  -> bootstrap（外层、签名绑定） + 其余对象（AEAD 私有 payload）
  -> Gist 单文件

新设备
  -> inspect_bootstrap（不信任）
  -> verify_gist_bootstrap_for_invitation（邀请 genesis/锚点/签名 + 成员链）
  -> HPKE 打开本设备当前 KeyEnvelope，构造不可直接取出密钥的临时 trust
  -> GistBootstrapTrust::unpack（digest -> signer -> AEAD -> 全闭包 -> 才返回 DataKey）

已有设备在其他设备完成轮换后
  -> inspect_bootstrap（不信任）
  -> verify_gist_bootstrap_for_checkpoint（本地 checkpoint 的成员链锚点 + 最低纪元）
  -> 仅当前成员可打开当前 KeyEnvelope
  -> GistBootstrapTrust::unpack（digest -> signer -> AEAD -> 全闭包 -> 才返回 DataKey）
```

## 错误与测试

缺少任意 Snapshot、StateRoot、Blob、Vault Index、成员事件、信封、密封秘密或恢复包时，
pack/unpack 返回不泄露内部标识的 `gist_bundle.incomplete_closure`。bootstrap 包含非 allowlist
对象、与 head Vault Index 不一致的对象或错误纪元时一律拒绝。测试覆盖 Vault 闭包、外层
明文扫描、无 DataKey 的 bootstrap 读取、邀请锚定后的临时解包、当前纪元/已信任设备解包与
错误纪元拒绝、checkpoint 锚定后的轮换取钥与撤销设备拒绝。
