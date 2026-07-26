# EnvSync Vault 线格式与密钥派生（M2）

本文是 EnvSync **M2 密码学层的规范文档**：算法套件、每一种线格式对象的逐字段定义、
域分隔标签总表、HPKE 信封的完整密钥派生链、纪元语义、nonce 的生日界分析，以及由类型
系统强制的一组不变量。

**目标读者是审计者。** 本文的每一节都写到「拿着 RFC 和一个 CBOR 解码器就能独立复现」
的粒度；实现依据全部指向 `crates/envsync-crypto/`，冻结向量见
[`test-vectors/`](test-vectors/README.md)。

配套文档：成员链与设备生命周期见 [`device-membership.md`](device-membership.md)，
恢复短语与恢复包见 [`recovery.md`](recovery.md)，信任边界与「不提供的保证」见
[`../security-model.md`](../security-model.md)。命令与参数见 [`../cli.md`](../cli.md)。

---

## 1. 算法套件

M2 只有**一套**算法组合，它的名字被写进每一个线格式对象：

```text
ESV1_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519
 │    │       │           │                 └─ 签名：Ed25519
 │    │       │           └─ AEAD：ChaCha20-Poly1305
 │    │       └─ KDF：HKDF-SHA256
 │    └─ KEM：X25519（DHKEM，RFC 9180 §4.1）
 └─ EnvSync 套件版本 1
```

| 组件 | 取值 | 角色 | 参数 | 实现常量 |
|---|---|---|---|---|
| KEM | DHKEM(X25519, HKDF-SHA256) | 把工作区数据密钥封装给单台设备 | 公钥 / 私钥 / 共享秘密均 32 字节（`X25519_LEN`）；RFC 9180 `kem_id = 0x0020` | `envelope::KEM_ID` |
| KDF | HKDF-SHA256 | HPKE key schedule；恢复 KEK 的第二级派生 | PRK 与输出块 32 字节；`kdf_id = 0x0001` | `envelope::KDF_ID` |
| AEAD | ChaCha20-Poly1305 | 密封秘密、设备信封、恢复包三处的对称加密 | key 32 字节（`KEY_LEN`）、nonce 12 字节（`NONCE_LEN`）、tag 16 字节（`TAG_LEN`）；`aead_id = 0x0003` | `envelope::AEAD_ID` |
| 签名 | Ed25519 | 设备身份、成员事件、对象签名 | 公钥 32 字节（`ED25519_PUBLIC_LEN`）、签名 64 字节（`SIGNATURE_LEN`）；验签用 `verify_strict` | `device::verify` |
| 摘要 | BLAKE3 + 域分隔 | 所有内容寻址标识与 `DeviceId` 派生 | 32 字节输出 | `envsync_domain::id::Digest32::domain_hash` |
| 口令 KDF | Argon2id（v0x13） | 只用于恢复包，见 [`recovery.md`](recovery.md) | 下限 64 MiB / 3 次 / 1 线程 | `recovery::Argon2Params` |

**「只有一套」是刻意的：没有协商就没有降级攻击。**

* `CryptoSuite::parse` 对任何其他名称返回 `CryptoError::UnsupportedSuite`——包括大小写
  不同、尾部多一个空格、`ESV0_…`、`ESV2_…`。测试 `unknown_suites_are_rejected`
  逐个钉住了这些形状，`unknown_suite_is_rejected_on_the_wire_too` 覆盖了 CBOR 解码路径。
* `SealedFormatVersion::parse` 只接受 `1`，其余（含 `0` 与 `u32::MAX`）返回
  `CryptoError::UnsupportedFormatVersion { found, supported }`。测试
  `only_format_version_one_is_accepted`、`unknown_format_version_is_rejected_on_the_wire`。
* 上表中的长度常量由测试 `documented_constants_match_the_suite` 直接断言，因此本节的
  数字与实现不可能悄悄漂移。

`verify_strict` 值得单独说明：它额外拒绝小阶公钥和带扭转分量的签名，从而排除「同一条
消息存在多枚都合法的签名」这种可塑性。成员链把事件摘要当作链接（见
[`device-membership.md`](device-membership.md) §1），可塑签名会直接破坏链的唯一性。
测试 `small_order_public_key_cannot_verify`。

---

## 2. Sealed Secret 的线格式

一条秘密值在后端上的唯一表示。对象种类为 `ObjectKind::SealedSecret`，内容寻址域标签
`envsync:sealed-secret:v1`。

### 2.1 逐字段表

编码是 **7 元 canonical CBOR 数组**（严格 canonical 子集，见 ADR-0001）：

| # | 字段 | CBOR 类型 | 长度 / 取值 | 进 AAD | 说明 |
|---|---|---|---|---|---|
| 0 | `version` | uint | 恒为 `1`（`SealedFormatVersion::V1`） | ✅ | 未知版本在任何密码学运算前被拒 |
| 1 | `suite` | text | 恒为 `ESV1_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519` | ✅ | 未知套件被拒 |
| 2 | `workspace_id` | bytes | 16（UUID 原始字节） | ✅ | 绑定工作区 |
| 3 | `secret_id` | text | 1..=128 字节（`SecretId::MAX_LEN`） | ✅ | **逻辑标识**，见 §2.3 |
| 4 | `key_epoch` | uint | ≥ 1（`KeyEpoch`） | ✅ | 加密时所用数据密钥的纪元 |
| 5 | `nonce` | bytes | 12（`NONCE_LEN`） | ✅ | 每次密封由 `OsRng` 新生成 |
| 6 | `ciphertext` | bytes | 16..=1 MiB+16（含 16 字节 Poly1305 tag） | ❌ | 被 AEAD 保护的内容 |

字段 0..5 合起来就是 `SealedHeader`；字段 6 是密文。`SealedSecret::header()` 返回前者，
`SealedSecret::ciphertext()` 返回后者。

明文上限 `MAX_PLAINTEXT_LEN = 1 MiB`：Vault 存的是 token、密钥、连接串这类配置秘密，
不是文件。超限在做任何分配之前就返回 `CryptoError::PlaintextTooLarge`
（测试 `above_one_mib_is_rejected`、边界成功用例 `round_trip_at_one_mib_boundary`）。
解码时同样先看长度：密文短于 `TAG_LEN` 或长于 `MAX_PLAINTEXT_LEN + TAG_LEN` 直接拒绝
（`truncated_ciphertext_is_rejected`、`oversized_ciphertext_is_rejected_at_decode`）。

### 2.2 AAD 的精确定义

```text
AAD = canonical_cbor([version, suite, workspace_id, secret_id, key_epoch, nonce])
```

也就是**把 7 元数组的前 6 项重新编码成一个 6 元数组**。注意它不是「整个对象的前缀
字节」——数组头从 `0x87` 变成了 `0x86`。实现为 `SealedSecret::aad()`，等价于
`self.header().to_canonical_vec()`；单元测试 `aad_is_header_without_ciphertext` 与集成
测试 `aad_is_exactly_the_header_without_ciphertext` 同时钉住了「等于 header 编码」和
「不等于整对象编码」两侧。

**AAD 是重新计算出来的，不是从输入里读出来的。** 这一点是「非 canonical 等价编码也会
失败」的根据：解码器只接受唯一 canonical 表示，随后 `open` 又用解码得到的结构重新编码
一次 AAD，两条路径都不给攻击者留下「语义相同、字节不同」的余地。

由此得到六条绑定，每一条都有专属测试：

| 攻击 | 结果 | 测试 |
|---|---|---|
| 改一位密文或 tag | `CryptoError::Authentication` | `flipping_any_ciphertext_or_tag_bit_fails` |
| 改一位 nonce | `CryptoError::Authentication` | `flipping_any_nonce_bit_fails` |
| 把密文挪到另一个工作区 | `CryptoError::Authentication` | `cross_workspace_decryption_fails` |
| 把密文挂到另一个 `secret_id` | `CryptoError::Authentication` | `cross_secret_id_decryption_fails` |
| 把 `key_epoch` 改成别的值 | `CryptoError::Authentication` | `cross_epoch_decryption_fails` |
| 用错误的数据密钥打开 | `CryptoError::Authentication` | `wrong_key_fails` |

注意所有失败都归一到同一个 `CryptoError::Authentication`。`open` 内部的检查顺序是
**版本 → 套件 → 长度 → 密码学**，前三步返回结构性错误（它们本来就是公开信息），
第四步的一切失败都不区分原因，不给攻击者可用的区分 oracle。

### 2.3 为什么 `SecretId` 是逻辑标识而不是明文摘要

`SecretId` 是**用户给的名字**（`ci/npm-token`），**绝不**由明文摘要生成。

如果用明文摘要当标识，两条取值相同的秘密就会拥有相同的标识。后端只需要看一眼对象的
`secret_id` 字段，就能判断「A 项目的 token 和 B 项目的 token 是同一个」——在完全不解密
的前提下。这是明确要避免的**相等性泄露**：它能把「同一把密钥被复用到了哪些地方」这张
图完整地画给一个只有读权限的攻击者，而这恰恰是密钥轮换时最敏感的信息。

同样的理由让**密文不可用于相等性判断**：随机 nonce 使得同一条明文两次密封产生完全不同
的密文（测试 `nonce_is_fresh_for_every_seal`）。测试
`secret_id_is_a_logical_name_not_a_plaintext_digest` 把这两条钉在一起——把**同一个明文**
密封到两个不同逻辑名下，断言 `secret()` 不同、`ciphertext()` 也不同，并断言逻辑名就是
调用者给的那个字符串（`ci/npm-token`）而非任何派生值。

`SecretId` 的命名规则刻意收紧（`SecretId::parse`）：由 `/` 分隔的段，每段非空、不是
`.` 或 `..`，只允许 ASCII 字母数字与 `-`、`_`、`.`，总长 ≤ 128 字节。这样它能安全地出现
在文件名、URL、日志与 CBOR 文本串里，且不含控制字符。违规返回
`CryptoError::SecretIdInvalid { reason }`，其中 `reason` 是 `&'static str`——**绝不回显
输入内容**，否则「把明文当成名字传进来」本身就会变成一次泄露（这条路径在
`no_error_path_leaks_the_canary_plaintext` 里被覆盖）。

---

## 3. 域分隔标签总表

所有摘要都是 `BLAKE3(domain || 0x00 || u64_be(len(payload)) || payload)`
（`Digest32::domain_hash`）。域标签使字节相同、用途不同的输入落在互不相交的摘要空间里。

| 域标签 | 用途 | 定义位置 |
|---|---|---|
| `envsync:device:v1` | `DeviceId` 派生：`H(x25519_pk ‖ ed25519_pk)`，见 ADR-0002 | `envsync_domain::id::DeviceId::derive` |
| `envsync:device-signature:v1` | 设备签名待签结构的**域前缀**（CBOR 数组第 0 项，非哈希域） | `envsync_crypto::device::SIGNATURE_DOMAIN_PREFIX` |
| `envsync:device-signature-payload:v1` | 待签 payload 的摘要域 | `envsync_crypto::device::SIGNATURE_PAYLOAD_DOMAIN` |
| `envsync:signature-fingerprint:v1` | `Signature` 的 `Debug` 指纹（只用于日志展示） | `envsync_crypto::device`（`Signature::fmt`） |
| `envsync:key-envelope:v1` | ① 信封对象的内容寻址域；② HPKE `info` 的域标签 | `ObjectKind::domain` / `envelope::ENVELOPE_INFO_DOMAIN` |
| `envsync:key-envelope-fingerprint:v1` | 信封的公开指纹，用于日志与审计 | `envsync_crypto::envelope::envelope_fingerprint` |
| `envsync:sealed-secret:v1` | 密封秘密对象的内容寻址域 | `ObjectKind::domain` |
| `envsync:membership-event:v1` | 成员事件对象的内容寻址域 | `ObjectKind::domain` |
| `envsync:membership-event-digest:v1` | 成员事件的**链接摘要**（后继事件 `previous` 指向它） | `envsync_domain::membership::MEMBERSHIP_EVENT_DIGEST_DOMAIN` |
| `envsync:recovery-phrase:v1` | 恢复短语校验位的摘要域 | `envsync_crypto::recovery::RECOVERY_PHRASE_DOMAIN` |
| `envsync:recovery-kek:v1` | 恢复 KEK 第二级 HKDF 的 **salt**（不是哈希域） | `envsync_crypto::recovery::RECOVERY_KEK_DOMAIN` |
| `envsync:snapshot-signature:v1` | 快照签名对象的内容寻址域 | `ObjectKind::domain` |
| `vault-index` | Vault 索引背书的**用途标签**（进设备签名待签结构，非哈希域） | `envsync_core::attestation::VAULT_ATTESTATION_DOMAIN` |
| `envsync:config:device-seed:v1` | M0 遗留：由配置里的设备种子派生 `DeviceId` | `envsync_core::config` |

M0/M1 已有的 `envsync:blob:v1`、`envsync:state:v1`、`envsync:snapshot:v1`、
`envsync:plan:v1`、`envsync:conflict:v1`、`envsync:file-content:v1` 见
[`../m0-operations.md` §1.3](../m0-operations.md)，M2 未改动它们。

同一条成员事件同时拥有**两个**摘要，这是刻意的：`envsync:membership-event:v1` 回答
「对象库里那个对象是不是它」（`ObjectId`），`envsync:membership-event-digest:v1` 回答
「链上的前一条是不是它」（`previous`）。两个问题不共用键空间。

---

## 4. HPKE 设备信封：完整密钥派生链

信封把工作区数据密钥（`DataKey`）分发给**单台**设备。每个 active 设备一个信封；信封
本体是公开材料，可以随快照一起放在不受信任的后端上。

实现按 [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) §4.1（DHKEM(X25519,
HKDF-SHA256)）与 §5.1（`mode_base` key schedule）逐步展开，原语分别取自
`x25519-dalek`、`hkdf` + `sha2`、`chacha20poly1305`。

> **审计待办：** 本实现尚未与 RFC 9180 附录 A.3 的官方测试向量做互操作验证。详见
> [`test-vectors/README.md` 的 TODO-for-audit](test-vectors/README.md#todo-for-audit)。

### 4.1 算法标识与 `suite_id` 的字节编码

| 项 | 值 |
|---|---|
| `mode` | `0x00`（base，无 PSK、无发送方认证） |
| `kem_id` | `0x0020` |
| `kdf_id` | `0x0001` |
| `aead_id` | `0x0003` |

两个 `suite_id` 都是**字面 ASCII 前缀 + 大端 2 字节标识**：

```text
KEM  suite_id = "KEM"  ‖ I2OSP(0x0020, 2)                                   （5 字节）
              = 4b 45 4d 00 20

HPKE suite_id = "HPKE" ‖ I2OSP(0x0020,2) ‖ I2OSP(0x0001,2) ‖ I2OSP(0x0003,2)（10 字节）
              = 48 50 4b 45 00 20 00 01 00 03
```

单元测试 `suite_ids_match_rfc9180_identifiers` 直接断言这两串字节。

### 4.2 标签化的 HKDF 原语

```text
LabeledExtract(salt, label, ikm)
    = HKDF-SHA256-Extract(salt, "HPKE-v1" ‖ suite_id ‖ label ‖ ikm)

LabeledExpand(prk, label, info, L)
    = HKDF-SHA256-Expand(prk, I2OSP(L, 2) ‖ "HPKE-v1" ‖ suite_id ‖ label ‖ info, L)
```

`"HPKE-v1"` 即 `envelope::HPKE_VERSION_LABEL`（7 字节 ASCII，无 NUL 结尾）。实现分别是
`labeled_extract` 与 `labeled_expand`；`L` 用 `u16::try_from` 校验，越界返回
`CryptoError::KeyDerivation`。

### 4.3 派生链：第一步 DHKEM 封装（`suite_id` 用 KEM 版）

1. **临时密钥对。** `esk` 是 32 字节 `OsRng` 随机数（`seal_envelope` 内部生成，
   调用者无法注入）；`enc = X25519(esk, basepoint)`，32 字节。
2. **DH。** `dh = X25519(esk, pkR)`，32 字节。随后检查 `was_contributory()`——
   全零共享秘密（对端用了小阶点）返回 `CryptoError::NonContributoryKeyExchange`。
   测试 `small_order_ephemeral_key_is_rejected`。
3. **`kem_context = enc ‖ pkR`**，64 字节。
4. **`eae_prk = LabeledExtract(salt = "", label = "eae_prk", ikm = dh)`**，32 字节。
5. **`shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, 32)`**，32 字节。

解封时第 1–2 步换成 `dh = X25519(skR, enc)`，第 3 步的 `kem_context` 仍是
`enc ‖ pkR`（`pkR` 取自本设备的公钥），因此双方算出同一个 `shared_secret`。

### 4.4 派生链：第二步 base 模式 key schedule（`suite_id` 用 HPKE 版）

6. `psk_id_hash = LabeledExtract(salt = "", label = "psk_id_hash", ikm = "")`，32 字节。
7. `info_hash = LabeledExtract(salt = "", label = "info_hash", ikm = info)`，32 字节。
8. `key_schedule_context = 0x00 ‖ psk_id_hash ‖ info_hash`，65 字节。
9. `secret = LabeledExtract(salt = shared_secret, label = "secret", ikm = "")`，32 字节。
10. `key = LabeledExpand(secret, "key", key_schedule_context, 32)`，32 字节。
11. `base_nonce = LabeledExpand(secret, "base_nonce", key_schedule_context, 12)`，12 字节。

信封只做**一次**封装，序列号恒为 `0`，因此 `nonce = base_nonce`（`0 XOR base_nonce`）。
导出接口（`exporter_secret`）在 M2 用不到，实现中**未派生**。

单元测试 `key_schedule_is_deterministic_and_info_bound` 钉住了「同 `info` 同结果、
异 `info` 异结果」。

### 4.5 第三步 AEAD

```text
ciphertext = ChaCha20Poly1305-Seal(key, base_nonce, aad, data_key)
```

明文恒为 32 字节数据密钥，因此密文恒为 `ENVELOPE_CIPHERTEXT_LEN = 32 + 16 = 48` 字节。
解码时长度不符直接返回 `CborError::LengthMismatch`，`open_envelope` 里再查一次并返回
`CryptoError::InvalidLength { field: "envelope_ciphertext", .. }`。测试
`wrong_ciphertext_length_is_rejected_at_decode`。

### 4.6 `info` 与 `aad` 的 canonical CBOR 结构

两者都是 canonical CBOR，可以被任何 CBOR 解码器独立复现。

```text
info = canonical_cbor([
    "envsync:key-envelope:v1",   // text，域标签 ENVELOPE_INFO_DOMAIN
    1,                           // uint，信封格式版本
    "ESV1_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519",  // text，套件名
    workspace_id,                // bytes(16)
    recipient,                   // bytes(32)，DeviceId = H(x25519_pk ‖ ed25519_pk)
    epoch,                       // uint
])

aad = canonical_cbor([
    1,                           // uint，版本
    "ESV1_…",                    // text，套件名
    workspace_id,                // bytes(16)
    recipient,                   // bytes(32)
    epoch,                       // uint
    enc,                         // bytes(32)，DHKEM 临时公钥
])
```

实现分别是 `envelope::envelope_info`（`pub`，刻意公开以便审计）与 `KeyEnvelope::aad`。
具体字节见 [`test-vectors/envelope.txt`](test-vectors/envelope.txt)。

**`info` 与 `aad` 的分工：** `info` 经第 7 步进入 `info_hash`，再经第 8–11 步烙进 AEAD
**密钥本身**；`aad` 只进入认证标签。因此 `workspace_id`、`recipient`、`epoch` 三项被
**两次**绑定，而 `enc` 只由 `aad` 绑定（它已经通过 `kem_context` 影响了 `shared_secret`，
不需要再进 `info`）。

由此得到四条性质：

| 攻击 | 为什么失败 | 测试 |
|---|---|---|
| 非目标设备打开信封 | `shared_secret` 需要 `skR`；且 `open_envelope` 先比对 `recipient != device_id()` 返回 `CryptoError::RecipientMismatch` | `only_the_target_device_can_open` |
| 交换两台设备的信封 | `pkR` 进 `kem_context`，`recipient` 进 `info` | `swapping_two_devices_envelopes_fails` |
| 降级 `epoch` | `epoch` 同时在 `info` 与 `aad` | `epoch_downgrade_fails` |
| 跨工作区重放 | `workspace_id` 同时在 `info` 与 `aad` | `cross_workspace_replay_fails` |
| 改一位密文 / 改一位 `enc` | AEAD tag 失败 / `shared_secret` 改变 | `flipping_any_ciphertext_bit_fails`、`flipping_any_enc_bit_fails` |

测试 `info_binds_workspace_recipient_and_epoch` 直接断言把三项中任意一项改掉都会得到
不同的 `info` 字节；`every_seal_uses_a_fresh_ephemeral_key` 断言生产 API 每次封装都用
新的临时密钥。

### 4.7 信封的线格式

对象种类 `ObjectKind::KeyEnvelope`，内容寻址域 `envsync:key-envelope:v1`。
编码是 **7 元 canonical CBOR 数组**：

| # | 字段 | CBOR 类型 | 长度 / 取值 | 进 AAD | 进 `info` |
|---|---|---|---|---|---|
| 0 | `version` | uint | 恒为 `1` | ✅ | ✅ |
| 1 | `suite` | text | 恒为 `ESV1_…` | ✅ | ✅（作为字面量重新写入） |
| 2 | `workspace` | bytes | 16 | ✅ | ✅ |
| 3 | `recipient` | bytes | 32（`DeviceId`） | ✅ | ✅ |
| 4 | `epoch` | uint | ≥ 1 | ✅ | ✅ |
| 5 | `enc` | bytes | 32（DHKEM 临时公钥） | ✅ | ❌ |
| 6 | `ciphertext` | bytes | 恒为 48 | ❌ | ❌ |

`open_envelope` 的检查顺序：**版本 → 套件 → 收件人 → 长度 → 密码学**。

### 4.8 使用顺序（这一条是安全前提，不是建议）

```text
① 验证成员链（verify_membership_chain）
② 确认信封的 recipient 是本设备、epoch 是链上当前纪元
③ 才允许 open_envelope
```

信封对象本身应当由管理员设备签名后上传。**成员链验证必须先于打开信封**——否则攻击者
可以用一个自己生成的数据密钥替换信封，把本设备后续写入的所有秘密引导到它控制的密钥上。
`envsync-crypto` 只负责密码学部分，链验证在 `envsync-core::membership`。

---

## 5. 纪元（epoch）语义

`KeyEpoch` 是工作区数据密钥的版本号，从 `KeyEpoch::INITIAL = 1` 开始
（域常量 `GENESIS_EPOCH = 1`）。它出现在三处：sealed object 的 AAD、设备信封的 `info`
与 `aad`、成员事件的 `epoch` 字段。

### 5.1 两条对称的强制规则

成员链验证器 `ChainReplay::check_epoch` 对每一条后继事件强制：

| 事件类型 | 纪元要求 | 违反时的错误 |
|---|---|---|
| `Revoke` | **恰好 `+1`** | `MembershipError::RevocationMustRotateEpoch { sequence, expected }` |
| `Genesis` / `AddMember` / `Promote` | **必须保持不变** | `MembershipError::EpochAdvancedWithoutRevocation { sequence, action }` |
| 任意 | 不得变小 | `MembershipError::EpochRollback { sequence, current, found }` |
| 任意 | 一次不得跳超过 `+1` | `MembershipError::EpochJump { sequence, current, found }` |

**双向都强制**的意义在于：纪元号因此成为「撤销发生过多少次」的**精确计数器**。

* 只禁止回退不够——攻击者可以悄悄把纪元前进，骗设备去等一个不存在的新信封，
  制造拒绝服务，或者掩盖「其实没有发生过撤销」。
* 只禁止前进也不够——攻击者可以撤销一台设备却不轮换密钥，让已撤销设备继续解密新写入
  的内容，撤销就成了摆设。

测试：`future_epoch_jump_is_rejected`、`advancing_the_epoch_without_a_revocation_is_rejected`、
`revoking_without_rotating_the_epoch_is_rejected`、`rolling_the_epoch_back_is_rejected`。
`KeyEpoch::next()` 在 `u64::MAX` 处返回 `None` 而不是环绕（`key_epoch_does_not_wrap`）。

纪元同时是反回滚检查点的四个维度之一，见
[`device-membership.md` §6](device-membership.md)。

### 5.2 lazy rewrap 与它的安全边界

撤销发生后，纪元推进到 `n+1`，管理员为剩余的每台设备重新签发新纪元的信封。此时后端上
存在两代对象：

* **新写入的秘密**一律用新纪元的数据密钥密封；
* **既有的旧对象**仍然是 `key_epoch = n` 的密文，**不做立即重写**。它们在下一次被某台
  仍然有权限的设备读取后，用新纪元密钥重新密封（rewrap），再发布回后端。这就是
  **lazy rewrap**。

选择 lazy 而不是 eager 的理由是可恢复性：eager rewrap 要在一次操作里重写整个 Vault，
中断后会留下一半新一半旧的状态，而这个状态无法只靠对象本身区分「已重写」与「未重写」。
lazy rewrap 的每一步都是幂等的单对象操作。

**安全边界必须说清楚——lazy rewrap 不提供前向保密：**

1. 一台设备在被撤销**之前**就已经拿到了纪元 `n` 的数据密钥。撤销**不能**收回它。
   因此该设备仍然能解密**所有它撤销前有权访问过的、且尚未被 rewrap 的**旧对象——
   只要它在被撤销前拷贝过那些密文，甚至不需要继续访问后端。
2. 撤销真正保证的是：**该设备无法解密纪元 `n+1` 及以后写入的任何内容**，因为它拿不到
   新纪元的数据密钥（新信封不会发给它，旧信封绑定的是旧 `epoch`，
   测试 `new_epoch_envelope_does_not_unlock_old_epoch_object`）。
3. 推论：**撤销一台可能已经泄露的设备之后，必须假设所有旧纪元的秘密值都已经泄露，
   并到各自的签发方去轮换它们**（重新生成 API token、重新签发证书……）。EnvSync 能做的
   是让新值只对剩余设备可见，它无法让已经离开进程的字节回来。

这一条同时说明了为什么 rewrap 的**进度**不是安全属性：无论旧对象被重写得多快，
上面第 1 条都成立。rewrap 的价值是让「当前有效密钥集合」收敛到一个，从而减少将来一次
密钥泄露的爆炸半径，而不是补救已经发生的泄露。

### 5.3 轮换的可恢复编排

撤销不是「从名单里划掉一行」，而是一次跨越后端、安全存储与本地 journal 的状态迁移。
`envsync_core::rotation` 把它建模成一个五阶段状态机（`RotationStage`）：

```text
prepared → envelopes_published → head_published → rewrapping → complete
```

进程可能在任何两步之间被杀死；`rotation::drive` 保证从**任何**阶段恢复都能得到同一个
终态。

**唯一不可颠倒的顺序：信封先于新头。** 新头（推进纪元的 `Revoke` 事件 + 新快照）一旦
发布，工作区的纪元就是 `n+1`；此时若信封还没发布，剩余设备拿不到 `n+1` 的数据密钥，
工作区会卡在「所有人都读不了新内容」的状态——而这是后端上的既成事实，重试无法自愈。
反过来「信封发布了、新头还没发」完全安全：多出来的信封只是几个没人引用的不可变对象，
下一次恢复原样复用。

因此进入 `HeadPublished` 之前会**实际回后端确认**每个信封对象都在，不在就以
`RotationError::EnvelopesMissing` 中止。这不是断言而是运行期检查：journal 说
「发过了」而后端说「没有」时，可信的是后端。

幂等性来自「一切可重放」：新纪元密钥在 `prepared` 阶段就写进密钥环且**已存在不覆盖**；
信封、成员事件、密封对象都是内容寻址的不可变对象；`Revoke` 事件的创建时刻固定在
journal 里，因此每次重放都签出**字节完全相同**的事件，摘要与链头不变。

| 性质 | 锁定测试（`crates/envsync-core/tests/key_rotation.rs`） |
|---|---|
| 撤销推进纪元并为剩余设备重签信封 | `revocation_advances_the_epoch_and_reissues_envelopes` |
| 已撤销设备读不到轮换之后写入的内容 | `a_revoked_device_cannot_read_anything_written_after_the_rotation` |
| 新头绝不先于信封发布 | `the_new_head_is_never_published_before_the_envelopes` |
| journal 谎称信封已发布时拒绝推进 | `the_head_is_refused_when_the_journal_lies_about_published_envelopes` |
| 从任一阶段幂等恢复 | `rotation_resumes_idempotently_from_every_stage` |
| 中断的轮换被下一次同设备撤销接管 | `an_interrupted_rotation_is_picked_up_by_the_next_revoke_of_the_same_device` |
| 未完成的轮换期间拒绝第二次轮换 | `a_second_rotation_for_a_different_device_is_refused_while_one_is_pending` |
| 连续两次轮换后旧对象仍可读 | `two_consecutive_rotations_keep_every_older_object_readable` |

命令入口见 [`../cli.md`](../cli.md)。

### 5.4 头快照上的工作区级元数据与 Vault 索引背书

Vault 与 M0/M1 的普通文件同步**共用同一条工作区 Ref**。头快照的 `metadata` 因此混着
两类事实：

| 类别 | 例子 | 归属 |
|---|---|---|
| 本次发布自己的事实 | `device_name`、`format`、`merge` | 谁发布了这一版 |
| **工作区级**事实 | `envsync.vault.index`、`envsync.vault.attestation` | 这个工作区现在是什么样 |

第二类以 `envsync.` 为前缀（`envsync_core::vault::WORKSPACE_METADATA_PREFIX`），并且
**必须被每一条产出新快照的路径从父快照原样继承**：M0 的 `capture`、M1 的三方合并、M2 的
Vault 发布，一条都不能漏。

不继承的后果不是「少一条元数据」，而是**一次例行 `envsync sync` 静默抹掉整个 Vault**：
索引指针没了，`vault get` 报 `vault.secret_not_found`，而 `vault list` 照常以
`status: ok` 返回一个空清单。密封对象本身还在后端上（内容寻址、不可变），丢的只是那个
指针——但从用户视角看，Vault 就是消失了。作为第二道防线，`vault list` 在「本机确实加入过
这个 Vault、当前头却没有索引指针」时给出一条 `blocking` 级诊断 `vault.index_missing`。

#### 背书为什么覆盖索引对象标识，而不是快照标识

`envsync.vault.attestation` 的值是一段 ASCII：

```text
ed25519:<设备标识 64 位小写十六进制>:<签名 128 位小写十六进制>
```

签名覆盖 `(用途标签 "vault-index", 工作区, 索引对象标识的规范文本)`，签发者必须是**当前
成员链上的设备**。读路径在 `VaultService::reload` 里强制校验，缺失或验不过一律返回错误码
`snapshot.signature_invalid`。

直觉上应该签快照标识，但那条路走不通，原因有两条：

1. **内容寻址造成循环。** 签名要么存成独立对象（标识 = 签名字节的摘要，读者算不出来），
   要么存进快照元数据（元数据进快照标识，而签名又覆盖快照标识）。两条都是循环。
2. **普通同步必须不能让 Vault 失效。** M0/M1 的发布路径手里没有成员链上的签名密钥——
   它用的是配置里种子派生的 `DeviceId`，与成员链上的密码学设备标识是**两套身份**
   （ADR-0002）。绑定快照标识意味着每一次普通同步都会打断背书，读路径只能二选一：
   拒绝（`sync` 之后 Vault 不可用），或放行（背书形同虚设）。

覆盖索引对象标识同时满足两者：索引是内容寻址的，覆盖它的标识等于覆盖它的**全部内容**
（成员链、信封、每一条 `SecretRef`）；而索引对象标识是工作区级元数据，普通同步只是把它
原样搬过去，背书跟着一起继承，仍然有效。

#### 它挡得住什么、挡不住什么

**挡得住：** 伪造索引——改成员名单、把某条秘密指向攻击者自己的密封对象、篡改纪元。
攻击者没有任何成员的私钥。

**挡不住（残留风险）：** 把一份**旧的、真实签过的**索引重新挂到一个新 revision 上。
第一道防线是反回滚检查点（revision / 成员链 sequence / 密钥纪元三条线单调），但检查点
**不覆盖索引里的秘密条目**：同一个纪元、同一个成员链 sequence 下的秘密条目回退不会被
检出。堵住它需要给索引本身加一条单调计数，而那会让普通同步重新需要签名密钥——留待后续
里程碑权衡。

**同样挡不住：** `SnapshotBody.state_root`，也就是普通同步的**文件内容**。M2 只把 Vault
秘密纳入了密码学保护，普通资源在后端上仍然是明文 Blob 且无签名（见
[`../security-model.md` §5.3.8](../security-model.md)）。

---

## 6. 随机 nonce 的生日界分析

ChaCha20-Poly1305 使用 96-bit nonce。EnvSync 的三处 AEAD 用法各不相同：

| 用法 | nonce 来源 | 同一密钥下的封装次数 |
|---|---|---|
| Sealed Secret | 每次 `seal` 从 `OsRng` 取 12 字节 | 该工作区在**单个纪元内**密封的秘密条数 |
| Key Envelope | HPKE `base_nonce`，由 `esk`（每次新随机）经 key schedule 派生 | 每个 `(esk, pkR)` 组合恰好 1 次 |
| Recovery Package | 每次 `create` 从 `OsRng` 取 12 字节 | 每个恢复包 1 次 |

后两者结构上就不存在重用（每次都是全新的密钥 + 全新的 nonce），因此生日界只对第一种
用法有意义。

**生日界。** 从 96-bit 空间中均匀独立地取 `q` 个 nonce，至少发生一次碰撞的概率满足

```text
P(collision) ≤ q·(q−1) / 2 / 2^96 ≈ q² / 2^97
```

代入 `q = 2^32`：

```text
P ≈ 2^64 / 2^97 = 2^−33  ≤  2^−32
```

也就是说，**在同一个数据密钥下做 2^32（约 43 亿）次封装之后，nonce 碰撞的概率仍不超过
2^−32**。

**当前使用模式为什么远在这个界内：**

1. 计数单位是「同一纪元内的**密封操作次数**」，不是秘密条数。每次 `vault set` 与每次
   lazy rewrap 各算一次。一个团队工作区的 Vault 通常是 10^1–10^3 条秘密，即便每条每天
   被重写一次，一年也只有 10^5–10^6 量级，距离 2^32 有三到四个数量级的余量。
2. **每次撤销都换密钥。** 纪元推进后的写入用的是一把全新的 32 字节随机密钥，计数器
   归零。因此 `q` 是「两次撤销之间的封装次数」，而不是工作区的终身累计值。
3. 明文上限 1 MiB 把「用 Vault 当文件同步」这种会把 `q` 推高几个数量级的用法从结构上
   排除掉了。
4. nonce **只能**由 `crate::fill_random`（唯一的 `OsRng` 入口）产生。生产 API 不接受
   调用者传入 nonce，因此不存在「调用方用计数器、重启后从 0 重来」这种把碰撞概率从
   2^−33 一口气推到 1 的经典错误。

**如果这个界被突破会怎样：** 两条使用同一 `(key, nonce)` 的密文会泄露两条明文的异或，
并让 Poly1305 的认证密钥可被恢复。这就是为什么下一节的「nonce 永不由调用者传入」被写成
编译期约束，而不是文档里的一句提醒。

---

## 7. 不变量清单

以下每一条都不是「我们会注意」，而是**类型系统或结构强制**的。

### 7.1 普通同步对象绝不含明文秘密

M0/M1 的 Blob 是文件原始字节，后端持有明文（见
[`../security-model.md` §3.2](../security-model.md)）。M2 的 Vault 走**另一条**对象通道：
秘密值只以 `ObjectKind::SealedSecret` 存在，快照里只保存逻辑引用与 sealed object 标识。
两类对象的域标签不同（`envsync:blob:v1` vs `envsync:sealed-secret:v1`），因此它们的
摘要空间不相交，一个 Blob 不可能被当成 Sealed Secret，反之亦然。

对**后端只有读权限**的攻击者而言，扫描全部 Blob 得不到任何 Vault 明文；扫描全部 Sealed
Secret 只能得到「有哪些逻辑名、属于哪个工作区、哪个纪元、密文多长」这些元数据。

### 7.2 nonce 永不由调用者传入

`sealed::seal`、`envelope::seal_envelope`、`RecoveryPackage::create` 的签名里**没有**
nonce 参数。固定 nonce / 固定临时密钥 / 固定 salt 的确定性构造函数
（`seal_with_nonce_for_tests`、`seal_envelope_with_ephemeral_for_tests`、
`create_with_salt_nonce_for_tests`）全部被 `#[cfg(feature = "test-vectors")]` 包住。

该 feature 由 `envsync-crypto` 的**自引用 dev-dependency** 打开：`cargo test` 与
`cargo clippy --all-targets` 会启用它，而 `cargo build` 不会。也就是说**生产构建里这些
函数根本不存在**——不是「不该调用」，是链接期没有这个符号。

`production_api_never_produces_the_fixed_nonce_vector` 断言生产 API 的两次相同调用得到
不同 nonce，且都不等于测试向量里的固定 nonce。

### 7.3 敏感类型不实现 Debug / Serialize，且 Drop 时 zeroize

| 类型 | 位置 | 约束 |
|---|---|---|
| `suite::DataKey` | 工作区数据密钥 | 无 `Debug` / `Display` / `CborCodec`；`Zeroize + ZeroizeOnDrop`；`PartialEq` 走 `subtle::ConstantTimeEq` |
| `suite::Plaintext` | 秘密明文 | 同上 |
| `device::DeviceKeypair` | 两把设备私钥 | 无 `Debug` / `Display` / `Clone` / 序列化；`ZeroizeOnDrop`；导出只经 `export_secret_bytes`（返回 `Zeroizing`） |
| `recovery::RecoveryPhrase` | 128-bit 恢复熵 | 同上，另外**不实现 `Clone`**（否则「克隆再展示两次」能绕过只展示一次） |
| `platform::SecretBytes` | 安全存储读出的字节 | 无 `Debug` / `Display` / 序列化；`Zeroize + ZeroizeOnDrop` |

**这是编译期约束，不是运行时检查。** 想把 `DataKey` 写进 `tracing::info!`、
`format!("{:?}")` 或 `serde_json::to_string`，代码根本不会编译——不存在「忘了脱敏」这个
失败模式，只存在「显式调用了 `expose_bytes()` / `expose()`」这个在 review 中一眼可见的
调用点。

代价是真实的，也应当记录：测试里不能对这些类型用 `assert_eq!`（它要求 `Debug`），
所以 `tests/vectors.rs` 里有一个 `expect_err` 小助手，`suite.rs` 的
`data_key_compares_in_constant_time` 用 `assert!(a == b)` 而不是 `assert_eq!`。
**这个不便本身就是约束生效的证据。**

配套的两条：

* **常量时间比较。** `DataKey` 与 `Plaintext` 的 `PartialEq` 委托给
  `subtle::ConstantTimeEq`，避免用比较耗时区分共同前缀长度。
* **失败路径清零。** 每一处 AEAD 失败分支（`seal`、`open`、`seal_envelope`、
  `open_envelope`、`RecoveryPackage::create`/`open`）都在返回错误前对工作缓冲区调用
  `zeroize()`——认证失败时缓冲区里可能已经有部分解密结果。

### 7.4 错误只描述结构，绝不携带秘密

`CryptoError` 的每个变体只带「类型、版本号、长度、`&'static str` 字段名」。测试
`no_error_path_leaks_the_canary_plaintext` 走遍 **14 条**会接触明文的失败路径（错误密钥、
密文篡改、AAD 篡改、超限、把明文当 `SecretId`、错误 signer、非法域标签、签名篡改、
非目标设备、错误恢复短语、把明文当短语解析、KDF 参数过弱、KDF 参数过大、把明文塞进
CBOR 的 `SecretId` 字段），对每个错误收集 `Display` + `Debug` + 整条
`std::error::Error::source()` 链，断言 canary 字符串及其片段都不出现。

同一文件里的 `the_canary_test_would_actually_catch_a_leak` 是反向自检：故意构造一个
真的携带明文的错误，断言探针能看见它——否则上面那条测试可能只是个空断言。

`sealed_object_debug_shows_no_plaintext` 补上另一侧：`SealedSecret` 的 `Debug`
可以显示逻辑名 `ci/npm-token`（那是元数据），但不得出现明文。

`Signature` 的 `Debug` 只输出版本号与
`BLAKE3_domain("envsync:signature-fingerprint:v1", …)` 的前 12 位十六进制——签名本身是
公开材料，但完整回显对日志毫无价值。

### 7.5 `#![forbid(unsafe_code)]`

`envsync-crypto` 与工作区其余全部 crate 一样在 crate 根设置 `#![forbid(unsafe_code)]`。
这是编译期强制的，无法用 `#[allow]` 局部豁免。

### 7.6 唯一的随机数入口

全 crate 只有一个函数接触随机数源：`crate::fill_random`，内部是
`rand_core::OsRng::try_fill_bytes`，失败返回 `CryptoError::Rng`。审计「所有随机数都来自
OsRng」因此是一次 grep，而不是一次通读。

---

## 8. 快速核对清单（给审计者）

| 要核对的事 | 怎么核对 |
|---|---|
| 套件名与长度常量 | `cargo test -p envsync-crypto documented_constants_match_the_suite` |
| 三种线格式没有漂移 | `cargo test -p envsync-crypto --test vectors`；向量说明见 [`test-vectors/`](test-vectors/README.md) |
| AAD 确实是「去掉密文的 header」 | `cargo test -p envsync-crypto aad_is_exactly_the_header_without_ciphertext` |
| HPKE `suite_id` 的字节 | `cargo test -p envsync-crypto suite_ids_match_rfc9180_identifiers` |
| `info` 绑定了工作区 / 收件人 / 纪元 | `cargo test -p envsync-crypto info_binds_workspace_recipient_and_epoch` |
| 纪元规则双向强制 | `cargo test -p envsync-core --test membership_chain` |
| 错误路径不泄露明文 | `cargo test -p envsync-crypto no_error_path_leaks_the_canary_plaintext` |
| 生产构建里没有固定 nonce 入口 | `cargo build -p envsync-crypto` 后 grep `seal_with_nonce_for_tests` 无符号 |
| **RFC 9180 官方向量互操作** | **尚未完成**，见 [TODO-for-audit](test-vectors/README.md#todo-for-audit) |
