# EnvSync M2 测试向量

本目录把 `crates/envsync-crypto/tests/vectors.rs` 里**已冻结**的线格式向量导出成纯文本，
供审计者在不编译 Rust 的前提下核对字节。

> **⚠️ 本目录中的每一个密钥、种子、salt、nonce 与恢复短语都是硬编码的测试专用假值
> （`0x2a`、`0x51` 之类的填充模式）。它们不是、也永远不会是任何真实凭据。
> 仅供测试，绝不用于生产。**

---

## 1. 这些向量是什么

| 文件 | 覆盖的构造 | 对应测试 |
|---|---|---|
| [`sealed.txt`](sealed.txt) | Sealed Secret 线格式与 AAD | `sealed_secret_wire_vector_is_frozen` |
| [`device-signature.txt`](device-signature.txt) | 设备身份派生与域分隔 Ed25519 签名 | `device_identity_vector_is_frozen` |
| [`envelope.txt`](envelope.txt) | HPKE 设备信封线格式、`info` 与 `aad` | `key_envelope_wire_vector_is_frozen` |
| [`recovery.txt`](recovery.txt) | Argon2id 恢复包线格式与 header | `recovery_package_wire_vector_is_frozen` |
| [`recovery-phrase.txt`](recovery-phrase.txt) | Base32-Crockford 恢复短语编码与校验位 | `recovery_phrase_vector_is_frozen` |

规范说明见 [`../vault-format.md`](../vault-format.md) 与 [`../recovery.md`](../recovery.md)。

---

## 2. 用途：格式冻结（回归向量）

**这些是本实现自产的回归向量（regression vectors），不是官方互操作向量。**

这个区别很重要，请不要弄混：

| | 回归向量（本目录） | 互操作向量（例如 RFC 9180 附录 A） |
|---|---|---|
| 从哪来 | **本实现自己算出来，然后钉死** | 规范作者提供，多个独立实现共同验证 |
| 能证明什么 | 「今天的实现和冻结那天的实现产出相同字节」 | 「本实现与规范一致，能与其他实现互操作」 |
| 不能证明什么 | **不能证明实现是对的**——如果冻结那天就错了，向量会把错误一起冻住 | — |
| 什么时候会失败 | 字段顺序、域标签、派生链、编码规则被改动时 | 实现偏离规范时 |

**回归向量的价值在于让改动变得可见。** 任何人动了 `SealedHeader` 的字段顺序、改了一个
域标签、在 `signing_input` 里多加一项、或者把 canonical CBOR 的整数编码从最短形式改成
固定宽度——测试立刻红。它挡住的是「无意的格式漂移」，尤其是那种在功能测试里完全看不出来
的漂移（往返测试对「两边一起改」是免疫的，冻结向量不是）。

**回归向量的局限也必须说清楚。** 如果冻结的那一刻实现就偏离了 RFC 9180，这些向量会把
偏离忠实地保存下来，并且每次 CI 都告诉你「一切正常」。这正是下面 TODO-for-audit 那一节
存在的理由。

---

## 3. 生成方式

向量由 `crates/envsync-crypto/tests/vectors.rs` 用**只在 `test-vectors` feature 下存在**
的确定性构造函数产生：

| 构造函数 | 注入的随机量 |
|---|---|
| `sealed::seal_with_nonce_for_tests` | 固定 12 字节 nonce |
| `envelope::seal_envelope_with_ephemeral_for_tests` | 固定 32 字节 HPKE 临时私钥 |
| `RecoveryPackage::create_with_salt_nonce_for_tests` | 固定 16 字节 salt + 12 字节 nonce |
| `RecoveryPhrase::from_entropy_for_tests` / `render_for_tests` | 固定 16 字节熵 |
| `DeviceKeypair::from_secret_bytes` | 固定两把 32 字节私钥种子（这是生产 API，用于从安全存储还原） |

设备签名不需要注入任何东西：Ed25519 是确定性签名（RFC 8032），相同密钥 + 相同消息恒得
相同签名，因此可以直接冻结。

`test-vectors` feature 由 `envsync-crypto` 的**自引用 dev-dependency** 打开：
`cargo test` 与 `cargo clippy --all-targets` 会启用它，`cargo build` 不会。
**生产构建里这些函数根本不存在**，不是「不该调用」，是链接期没有这个符号。

复现命令：

```bash
cargo test -p envsync-crypto --test vectors
```

修改本目录的文本文件**不会**影响 CI——真正的事实来源是 `vectors.rs`。这些文本是它的
可读镜像；如果两者对不上，以 `vectors.rs` 为准，并请报告这个不一致（文档与实现不一致
在本项目里被视为安全问题的一种）。

---

## 4. 怎么读这些文件

每个文件的结构一致：

```text
1. 固定输入      —— 每一项都标注长度与用途
2. 派生的中间量  —— DeviceId、AAD、info、header 等，可独立复现
3. 输出          —— 完整的 canonical CBOR 十六进制
4. 字段拆解      —— 按 CBOR 主类型逐项对齐，附上每个字段的含义
5. 怎么核对      —— 用哪条命令、能证明什么
```

十六进制一律小写、无分隔符。CBOR 头字节在「字段拆解」一节里单独列出，例如 `87` 表示
「7 元数组」、`5820` 表示「32 字节的 bytes」、`7830` 表示「48 字节的 text」。

---

## 5. 安全声明

* 本目录中的所有密钥材料都是**填充模式常量**（`[0x2a; 32]`、`[0x51; 32]` 之类）或
  可预测的递增序列，任何人都能在一秒内重新生成它们。
* 唯一的「工作区标识」是 `11111111-1111-4111-8111-111111111111`，一个刻意选取的
  非随机 UUID。
* 唯一的恢复短语 `008J-4CT4-ANK7-F24S-NAXW-SQFE-ZYGH-7XZ2` 对应固定熵
  `00112233445566778899aabbccddeeff`。**任何在真实工作区里出现的相同短语都意味着有人
  把测试常量当成了生产密钥。**
* 明文全部是 `test-vector-…` 形状的自描述字符串，不含任何真实凭据。

---

## 6. TODO-for-audit

<a id="todo-for-audit"></a>

以下是**发布前审计必须补上**的一项。它被单独列出来，而不是藏在某段散文里，因为它是本
密码学层目前唯一一处「有测试覆盖但覆盖的性质不对」的地方。

### 6.1 HPKE 尚未做 RFC 9180 官方向量互操作验证

**现状：** `crates/envsync-crypto/src/envelope.rs` 按 RFC 9180 §4.1（DHKEM(X25519,
HKDF-SHA256)）与 §5.1（`mode_base` key schedule）**手工**实现了 HPKE，底层原语来自
`x25519-dalek`、`hkdf` + `sha2` 与 `chacha20poly1305`。当前的测试覆盖是：

| 已覆盖 | 测试 |
|---|---|
| `suite_id` 的字节编码 | `suite_ids_match_rfc9180_identifiers` |
| key schedule 的确定性与 `info` 绑定 | `key_schedule_is_deterministic_and_info_bound` |
| 端到端往返（本实现封、本实现开） | `only_the_target_device_can_open` 等 |
| 线格式冻结 | `key_envelope_wire_vector_is_frozen`（见 [`envelope.txt`](envelope.txt)） |

**缺口：** 上面每一条都是**自洽性**测试——它们证明「封装和解封是同一套算法」，但
**不能**证明「这套算法就是 RFC 9180」。一个在 `LabeledExtract` 里漏掉 `suite_id`、
或者把 `key_schedule_context` 的 `mode` 字节放错位置的实现，会完美通过上述全部测试，
并且被冻结向量忠实地保存下来。

**必须补的：** 用 **RFC 9180 附录 A.3**（DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
ChaCha20Poly1305，即本实现使用的 `0x0020 / 0x0001 / 0x0003` 组合）的官方测试向量做
逐步验证，至少断言：

1. `mode_base` 情形下，给定 `skEm` / `pkRm` / `info`，算出的 `enc` 与官方一致；
2. `shared_secret`（DHKEM 第 5 步输出）与官方一致；
3. `key_schedule_context`、`secret`、`key`、`base_nonce` 四个中间量与官方一致——
   逐个断言而不只断言最终密文，否则两个错误互相抵消时测试仍会通过；
4. `seq = 0` 的密文与官方一致。

**为什么这一项不能省。** 自研 HPKE 实现是本密码学层唯一一处「不是直接调用现成
高层库」的地方（其余原语——Ed25519、X25519、HKDF、ChaCha20-Poly1305、Argon2id、
BLAKE3——都是直接调 RustCrypto / dalek 的成品）。项目的安全边界之一是「不自创密码学
原语」；手工拼装 RFC 9180 的 key schedule 处在这条边界的边缘上，只有官方向量能把它
拉回边界之内。

**在这一项完成之前，请把设备信封的安全性理解为「依赖本实现对 RFC 9180 的解读正确」，
而不是「已验证符合 RFC 9180」。** 这一点同时记录在
[`../../security-model.md`](../../security-model.md) 的「M2 不提供的保证」一节。
