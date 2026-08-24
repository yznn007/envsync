# GitHub Gist 密封 Bundle 格式

M4 的 Gist 后端把一个工作区的当前 Ref 与所需对象放进**唯一**的 Gist 文件：

```text
envsync-<workspace-uuid>.bundle
```

文件正文是无 padding 的 Base64URL；解码后必须是 canonical CBOR。它不是可读备份，也
不是压缩归档：资源路径、普通资源正文、Snapshot metadata、Vault Secret ID、Vault Index
与 Vault 密封对象均只存在于认证加密后的内层。唯一例外是为新设备取得当前数据密钥所需
的最小公开 bootstrap，详见下文。

实现位于 `crates/envsync-backend/src/gist_bundle.rs`。本格式只负责 pack/unpack；GitHub
HTTP、ETag 与 CAS 在后续 Gist backend 中处理。

## HTTP 与凭据

Gist 后端只发布一个工作区唯一的 `envsync-<workspace-uuid>.bundle` 文件，并且创建的 Gist
永远是 private。用于此后端的 fine-grained personal access token 仅授予 **Gists: write** 权限。
token 只能由 Vault `SecretRef` 注入 HTTP 客户端；它不得写入配置、日志、诊断或错误消息。

EnvSync 自己的 encoded bundle 上限为 5 MiB；超过该上限立即拒绝，绝不将内容克隆、缓存或
转交给其他位置。GitHub Gist API 的读取响应中，每个文件最多提供 1 MiB 的 `content`；若
响应标记 `truncated`，客户端仅可从该文件受限的 `raw_url` 取得完整内容。这是**读取响应的
内容提供限制**，不是创建 Gist 时的 API 大小限制。

`raw_url` 必须经过受限来源校验：自定义或测试 API base 时只允许与 API 同源；公共 GitHub API
时只允许 `https://gist.githubusercontent.com` 这一 allow-list 来源。请求 raw 内容时不发送
`Authorization`。这既避免将 token 发送到未经允许的端点，也不把 raw URL 当作可执行的重定向能力。

ETag 仅是检测竞争的弱并发提示，不构成强 CAS。发布时带上读取到的 ETag，写入成功后必须再
读取并以完整 bytes 验证目标文件，验证通过才确认发布；检测到冲突由上层重新同步。PATCH 的
结果未知时只做 GET 判定，绝不盲目重写。受控重试只适用于 GET 的限流情形；POST 与 PATCH
不会自动重放。

测试仅访问 loopback GitHub mock，不访问真实 GitHub，也不读取或使用真实凭据。

GitHub 的响应截断行为及 `raw_url` 的用法见 [Gist REST API 文档](https://docs.github.com/en/rest/gists/gists)；
条件请求和限流处理遵循 [REST API 最佳实践](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api)。

## 前提与信任边界

Gist 只允许 M2 已初始化的工作区使用。调用方必须向 bundle 层注入：

- 当前或指定纪元的 `DataKey`；
- 对应的 `KeyEpoch`；
- 写入方的 `DeviceKeypair`；
- 读取方本地已验证的 `DeviceId -> DevicePublic` 成员表。

普通读取时先用外层 signer ID 在本地成员表中查找公钥，再验签；未知 signer 与坏签名一律
拒绝。后端自身不得读取系统安全存储，也不得把 `DataKey` 放进配置文件。

对于还没有本地 `DataKey` 的新设备，outer bootstrap 可公开完整 `MembershipEvent` 链和当前
纪元的 `KeyEnvelope`。这些字段也**不是信任根**：core 必须用邀请中的 genesis、成员链锚点
和邀请签名重放验证后，才能打开仅发给本机的 HPKE 信封。随后仍必须对同一份 bundle 调用
`unpack()`；只有 digest、设备签名、AEAD 和完整对象闭包都通过后，候选密钥才能写入本地
密钥环。`envsync_core::verify_gist_bootstrap_for_invitation` 与
`GistBootstrapTrust` 固化了这条顺序。

已经加入工作区但尚未持有轮换后纪元的设备走同样的顺序，只是信任根换成其本地反回滚
`Checkpoint`：`verify_gist_bootstrap_for_checkpoint` 要求公开成员链严格延续 checkpoint 的
`membership_digest`/`membership_sequence`，且绝不允许 key epoch 回退。被撤销设备即使还
保留旧 checkpoint，也不是当前成员，不能打开任何当前信封。

`inspect()` 只解析未验证的外层路由 metadata，供后端选择对应工作区的成员表和 `KeyRing`
中的纪元密钥；它返回的 workspace、revision、head、epoch、signer 和对象数在 `unpack()`
验过摘要、签名并解密前都不可信。

`inspect_bootstrap()` 同样只返回未验证的公开 bootstrap。它不需要 `DataKey`，仅供设备加入
或当前纪元密钥尚未落盘时的引导；常规读取不应绕过已有的本地成员链、反回滚检查点和
`unpack()`。对新设备，`GistBootstrapTrust::unpack()` 消费临时信任材料；它失败时不会交出
候选密钥，成功时才同时返回已验证对象和可持久化的当前 `DataKey`。

## v1 线格式

```text
base64url_no_pad(canonical_cbor([
  1,                         // format version
  workspace_id,              // bytes(16)
  revision,                  // uint
  head,                      // SnapshotId 或 null
  [object_count, chunks],    // 总逻辑对象数（含 bootstrap）与密封对象目录
  [                         // 最小公开 bootstrap
    membership_records,      // 仅 MembershipEvent 的 [kind, digest32, bytes]
    envelope_records         // 仅当前 epoch KeyEnvelope 的 [kind, digest32, bytes]
  ],
  bundle_digest,             // BLAKE3 domain digest
  [signer_device_id, signature]
]))
```

`chunks` 是一组 M2 `SealedSecret` 线格式对象。它们的逻辑标识由外层的
`workspace/revision/head/epoch/signer/chunk-index/chunk-count` 作域分隔哈希派生，不能是
用户的 Vault Secret ID。这样密文块的 AAD 同时绑定工作区、纪元和该 Bundle 的位置。

解密后才会看到内层 canonical CBOR：

```text
[
  1,
  WorkspaceRef,
  [[object_kind, digest32, object_bytes], ...]  // ObjectId 严格升序
]
```

bootstrap 中只能出现 `MembershipEvent` 与当前 epoch 的 `KeyEnvelope`，并且两类记录都按
`ObjectId` 严格递增。它不会携带 Vault Index、Vault Secret ID、普通 Blob、Snapshot metadata
或资源路径/正文；这些对象继续只存在于内层。bootstrap 的记录从 inner 对象清单中移出，
所以 `object_count` 统计两侧合并后的逻辑对象总数。

`bundle_digest` 是外层前六项 canonical 编码的
`BLAKE3("envsync:gist-bundle:v1", ...)`。设备签名的 payload 还包含格式版本和 signer ID，
再由 `DeviceKeypair::sign("gist-bundle", workspace, ...)` 做现有的工作区绑定与域分隔。

v1 **没有压缩算法或解压路径**。任何未来的压缩格式都必须提升版本，并采用有界、流式的
解压实现；当前版本不会把小文件扩张成压缩炸弹。

## 限额与校验顺序

- 编码文本最多 5 MiB；解码前先拒绝超限输入。
- 最多 512 条对象记录，最多 4 个 1 MiB 密文分块。
- 解密后从 `head` 递归验证父快照、每个 `SnapshotBody -> StateRoot`、受管资源 Blob 以及
  `VaultIndex -> 成员事件 / 当前 KeyEnvelope / 密封秘密 / 恢复包` 的完整对象闭包；任一
  State Root 最多 256 条资源。

解包顺序固定为：

1. 检查文本长度并严格解 Base64URL。
2. canonical 解外层，检查版本、对象数、分块数和 bootstrap 的 allowlist/对象摘要。
3. 检查本地预期工作区，重算覆盖 bootstrap 的 bundle digest。
4. 从本地成员表解析 signer 并验证签名。
5. 检查每块的 workspace、epoch 与派生 AAD 标识后再解密。
6. canonical 解内层，交叉校验 Ref，拒绝无序/重复 Object ID 与摘要不匹配。
7. 合并 inner 与 bootstrap，递归验证 Snapshot、State Root、受管 Blob 及 Vault Index
   闭包；重算 head Vault Index 导出的 bootstrap，二者任何不一致都拒绝。

外层必然公开工作区 UUID、revision、head 摘要、对象/分块数量、密钥纪元、设备 ID、成员链
的公开身份材料、当前 HPKE 信封和文件长度；它不会公开资源名、路径、值、Vault Index、
Secret ID 或用户 metadata。若未来需要隐藏这些粗粒度信息，应另起格式版本并使用定长
padding，而不是悄悄改变 v1。

## 验证

```bash
cargo test -p envsync-backend --test gist_bundle
```

测试覆盖 canonical Base64URL、随机 nonce 下的分块 round-trip、wire 明文扫描、M2 前提、
本地 signer/工作区信任、资源和对象上限、重复 ID、父快照/受管 Blob/Vault 闭包、公开
bootstrap allowlist、邀请锚定引导、摘要/签名篡改与文件名绑定。
