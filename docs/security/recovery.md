# EnvSync 恢复短语与恢复包（M2）

恢复流程解决的是**「所有设备都丢了」**这一场景：用户手上只有一串离线抄写的短语，凭它
解开一个存放在（不受信任的）后端上的加密包，包里是重建工作区访问权所需的恢复材料。

本文描述短语的熵与编码、Argon2id 参数边界、恢复包的线格式与 KEK 派生链、恢复仪式的
完整步骤，以及**用户必须自己承担的备份责任**。

配套文档：算法套件与线格式见 [`vault-format.md`](vault-format.md)，成员链与设备生命
周期见 [`device-membership.md`](device-membership.md)，信任边界见
[`../security-model.md`](../security-model.md)。命令细节见 [`../cli.md`](../cli.md)。

---

## 1. 恢复短语

### 1.1 熵与编码

```text
entropy   = 16 字节（128 bit）系统随机数            // RECOVERY_ENTROPY_LEN
checksum  = BLAKE3_domain("envsync:recovery-phrase:v1", entropy)[0..4]   // RECOVERY_CHECKSUM_LEN
payload   = entropy ‖ checksum                     // 20 字节 = 160 bit
phrase    = Base32-Crockford(payload)              // 恰好 32 个符号，无填充
展示形式   = 8 组 × 4 符号，用 `-` 分隔              // RECOVERY_PHRASE_GROUP = 4
```

**熵来源。** 128 bit 全部来自 `rand_core::OsRng`，经由全 crate 唯一的随机数入口
`crate::fill_random`；失败返回 `CryptoError::Rng`，绝不退化为弱随机源。128 bit 是
对称密钥级别的强度——穷举它比穷举被它保护的 256-bit KEK 更难吗？不是，但结合 Argon2id
的内存硬性代价，离线穷举 128 bit 熵在任何可预见的算力下都不成立。

**为什么是 160 bit 恰好 32 个符号。** Base32 每符号携带 5 bit，160 = 32 × 5，因此
**不存在填充位**，编码是双射的：每一个 32 符号串最多对应一个 20 字节 payload，反之亦然。
如果用别的长度（比如 128 bit = 25.6 个符号），就得引入填充，而填充位是「同一份熵有多种
合法文本表示」的经典来源，会让「抄错了」和「抄的是另一种写法」变得无法区分。

**为什么用 Crockford 字母表。** 字母表是 `0123456789ABCDEFGHJKMNPQRSTVWXYZ`，剔除了
`I`、`L`、`O`、`U`：

* `I` / `L` / `1` 与 `O` / `0` 是手写与屏幕上最容易混淆的几组；
* `U` 被剔除是 Crockford 的原始设计，用于降低偶然拼出冒犯性单词的概率。

解析时（`RecoveryPhrase::parse`）按 Crockford 规则做**归一化**而不是拒绝：

| 输入 | 归一为 |
|---|---|
| 小写字母 | 对应大写 |
| `O` / `o` | `0` |
| `I` / `i` / `L` / `l` | `1` |
| `-` 与任意空白（任意位置、任意数量） | 忽略 |

测试 `phrase_parsing_normalizes_case_separators_and_crockford_aliases`、
`phrase_round_trips_through_text`、`phrase_grouping_is_stable`。

**分组只影响展示。** `-` 在解析时被忽略，因此用户把短语抄成一整串、或者按别的分组
抄写，都能正常解析。分组存在的唯一理由是让人抄得动。

### 1.2 校验位能发现什么

校验位是 32 bit（BLAKE3 域分隔摘要的前 4 字节）。它是**完整性检查而非认证标签**——
熵本身就是秘密，校验位由熵唯一决定，任何知道短语的人都能算出它，所以这里按位比较即可，
不需要常量时间比较（没有秘密可供计时区分）。

它能发现什么：

| 错误类型 | 能否发现 |
|---|---|
| **任意单字符替换** | **能，且是穷举验证过的**——见下 |
| 字符数不足 32 或超过 32 | 能（`RecoveryPhraseMalformed`，长度检查先于校验位） |
| 出现字母表外的字符 | 能（`RecoveryPhraseMalformed`） |
| 多字符错误 / 换位 | 概率性地能，漏检概率约 `2^-32` |
| 把整串短语换成另一串**合法**短语 | **不能**——那是另一个人的合法短语，校验位当然对得上 |

关于第一行：测试 `checksum_detects_every_single_character_substitution` 对冻结的测试熵
穷举了**全部 32 × 31 = 992 种**单符号替换，断言每一种都返回
`CryptoError::RecoveryPhraseChecksum`。这不是抽样，是穷举。

关于最后一行：校验位保证的是「这串字符是**某个** EnvSync 短语」，不是「这串字符是
**你的** EnvSync 短语」。后者只能由 `RecoveryPackage::open` 回答——口令不对时返回
`CryptoError::Authentication`（见 §6）。

两类错误的错误码刻意分开：

* `CryptoError::RecoveryPhraseMalformed`——字符集、长度或分组不合法，说明**抄漏 / 抄多 /
  抄了别的东西**；
* `CryptoError::RecoveryPhraseChecksum`——格式合法但校验位不匹配，说明**存在录入错误**，
  提示用户逐组核对即可。

测试 `malformed_phrases_are_rejected` 覆盖了长度不足、长度超出、非法字符等形状。

### 1.3 只展示一次

`RecoveryPhrase` **刻意不实现** `Debug`、`Display`、`CborCodec` 与任何序列化 trait，
`Drop` 时清零。唯一的展示入口是 `RecoveryPhrase::display_once()`，它**一辈子只成功
一次**——第二次调用返回 `CryptoError::RecoveryPhraseAlreadyRevealed`。

「只展示一次」被写进了**类型的状态**（`revealed: bool`），而不是写在文档里靠人记住。
同样刻意的是：`RecoveryPhrase` **不实现 `Clone`**，否则「先克隆再各展示一次」就能绕过
这条约束。

`display_once` 的返回值是 `Zeroizing<String>`，离开作用域即清零。

测试 `phrase_is_displayed_exactly_once`、`generated_phrases_are_distinct`。

### 1.4 短语作为 KDF 口令时用的是熵，不是文本

`RecoveryPhrase::password_bytes()` 返回的是**原始 16 字节熵**，不是渲染出来的文本。

理由：文本经过大小写归一、Crockford 别名归一、分隔符剔除三道处理，如果拿文本当口令，
KEK 就会依赖这些归一化规则的实现细节。哪天归一化逻辑动一个字节（比如未来允许全角
连字符），所有既有恢复包就全部打不开了。用熵作口令则完全绕开这个脆弱面：文本只是熵的
一种可抄写的表示。

---

## 2. Argon2id 参数边界

`Argon2Params` 的构造函数是唯一入口，因此**不可能**存在一个越界的 `Argon2Params` 值。
算法固定为 `Algorithm::Argon2id` + `Version::V0x13`，输出长度固定 32 字节。

| 参数 | 下限（`MIN_*`） | 上限（`MAX_*`） | 推荐值（`recommended()`） |
|---|---|---|---|
| `memory_kib` | `64 * 1024` = 64 MiB | `2 * 1024 * 1024` = 2 GiB | 64 MiB |
| `time_cost` | `3` | `32` | 3 |
| `parallelism` | `1` | `16` | 1 |

`recommended()` **正好等于下限**，测试 `recommended_parameters_equal_the_project_floor`
断言这一点。

### 2.1 下限的理由

下限存在是为了让**创建**恢复包这件事不可能悄悄产生一个弱包。低于下限返回
`CryptoError::KdfParametersTooWeak { min_memory_kib, min_time, min_parallelism }`。

64 MiB / 3 次是「任何一台还能跑 EnvSync 的机器都扛得住」的取值：它在低端笔记本和 CI
容器上都能在一秒量级完成，同时把 GPU / ASIC 的并行优势压到内存带宽上。桌面端可以在
设置里调高——上限允许到 2 GiB / 32 次。

**诚实的边界：** 按 2026 年的实践，64 MiB 属于偏保守的一端。它是**下限**而不是
「安全建议值」；把它当默认值的取舍在于「所有平台都能用」优先于「单机最强」。这条已经
写进 [`../security-model.md`](../security-model.md) 的「M2 不提供的保证」。

### 2.2 为什么读取时也拒绝低于下限的包

这一条容易被忽略，但它很重要。

直觉上「读取时应该宽容」——毕竟包可能是旧版本创建的。EnvSync **不这样做**：
`RecoveryPackage::from_value` 在解码期就调用 `Argon2Params::new`，因此
**一个 `memory_kib = 1` 的恢复包根本无法从 canonical CBOR 解码出来**。

理由：**恢复包的 KDF 参数是包自己声明的，而包来自不受信任的后端。**

如果读取时接受任意弱参数，攻击者就有了一条降级路径：拿到用户的恢复包（它是公开材料），
把 `memory_kib` 改成 `8`、`time_cost` 改成 `1`，然后离线穷举那 128 bit 熵——代价从
「64 MiB × 3 次 × 2^128」降到「8 KiB × 1 次 × 2^128」。虽然 2^128 本身仍然不可行，
但这条路径的存在意味着**包里记录的参数不再是安全边界**，而参数正是唯一决定破解成本的
东西。

（注意 KEK 派生把参数绑进了 HKDF 的 `info`，见 §3.2——因此改参数会让派生出的密钥不同，
解密必然失败。参数校验是**第二道**防线：它让攻击者连「花时间跑一次弱 KDF」的机会都
没有。）

### 2.3 上限的理由：拒绝畸形包

上限的作用是拒绝**资源耗尽输入**。攻击者把 `memory_kib` 写成 `u32::MAX`（4 TiB）或把
`time_cost` 写成 `1_000_000`，本实现在做**任何分配**之前就返回
`CryptoError::KdfParametersTooLarge { max_memory_kib, max_time, max_parallelism }`。

测试 `malformed_package_never_requests_more_than_two_gib_or_endless_iterations` 不只断言
「被拒绝」，还断言**拒绝必须是立即的**（< 200 ms）——如果耗时超标，说明真的开始跑 KDF
了，那么拒绝就来得太晚了。覆盖的畸形参数包括 `(u32::MAX, u32::MAX, u32::MAX)`、
4 GiB 内存、100 万次迭代、4096 并行度与全零。

配套测试：`parameters_below_project_floor_are_rejected`（5 组低于下限的取值）、
`parameters_above_machine_ceiling_are_rejected`（5 组超过上限的取值，同时断言
`(2 GiB, 32, 16)` 这个边界值是**接受**的）。

**检查顺序是「先上限、后下限」**：因此 `(0, 0, 0)` 这样两侧都违反的输入报
`KdfParametersTooWeak`。

---

## 3. `RecoveryPackage` 的线格式与 KEK 派生链

### 3.1 逐字段表

canonical CBOR **8 元数组**：

| # | 字段 | CBOR 类型 | 长度 / 取值 | 进 AAD | 进 HKDF `info` |
|---|---|---|---|---|---|
| 0 | `version` | uint | 恒为 `1`（`SealedFormatVersion::V1`） | ✅ | ✅ |
| 1 | `suite` | text | 恒为 `ESV1_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519` | ✅ | ✅ |
| 2 | `memory_kib` | uint | 65536..=2097152 | ✅ | ✅ |
| 3 | `time_cost` | uint | 3..=32 | ✅ | ✅ |
| 4 | `parallelism` | uint | 1..=16 | ✅ | ✅ |
| 5 | `salt` | bytes | 16（`RECOVERY_SALT_LEN`），每包由 `OsRng` 新生成 | ✅ | ✅ |
| 6 | `nonce` | bytes | 12（`NONCE_LEN`），每包由 `OsRng` 新生成 | ✅ | ✅ |
| 7 | `ciphertext` | bytes | 16..=1 MiB+16（含 16 字节 Poly1305 tag） | ❌ | ❌ |

字段 0..6 合起来是 `RecoveryHeader`。它同时充当**两个**角色：AEAD 的 AAD 与 HKDF 的
`info`（见 §3.2）。`RecoveryPackage::aad()` 返回它的 canonical 编码。

**header 与密文都是公开材料**，可以放在不受信任的后端上。salt 与 nonce 的公开性是
设计的一部分：它们的作用是保证「同一串短语在两个不同工作区 / 两次不同创建下派生出不同
的 KEK」，而不是保密。

`salt` 与 `nonce` 都在 `RecoveryPackage::create` 内部生成，**调用者无法注入**
（测试 `salt_and_nonce_are_fresh_for_every_package`）。固定 salt / nonce 的构造函数
`create_with_salt_nonce_for_tests` 被 `#[cfg(feature = "test-vectors")]` 包住，生产构建
里不存在这个符号。

**载荷内容。** 密码学层对载荷是不透明的（`Plaintext`）：它只负责「用短语保护一段字节」。
按设计，这段字节承载恢复身份的密钥材料与工作区恢复材料，恢复后写入系统安全存储的
`SecurePurpose::RecoveryIdentity` 条目。载荷长度受 `MAX_PLAINTEXT_LEN = 1 MiB` 约束。

### 3.2 KEK 派生链

```text
① kek_raw = Argon2id(
       password  = entropy(16 字节，短语的原始熵，不是文本),
       salt      = salt(16 字节，来自 header),
       memory    = memory_kib,   time = time_cost,   lanes = parallelism,
       version   = 0x13,
       out_len   = 32
   )

② prk = HKDF-SHA256-Extract(
       salt = "envsync:recovery-kek:v1",   // RECOVERY_KEK_DOMAIN，ASCII 字面量
       ikm  = kek_raw
   )

③ kek = HKDF-SHA256-Expand(
       prk,
       info = canonical_cbor([version, suite, memory_kib, time_cost, parallelism, salt, nonce]),
       L    = 32
   )

④ ciphertext = ChaCha20Poly1305-Seal(kek, nonce, aad = 同一份 canonical header, payload)
```

**为什么 Argon2id 的输出还要再过一次 HKDF。** 因为要把**格式版本、算法套件与全部 KDF
参数**绑进最终密钥。Argon2id 本身只吃 `password` 与 `salt`，参数只影响计算过程、不进入
输入域；换句话说，如果直接用 `kek_raw` 当 AEAD 密钥，那么「包里记录的参数」与「密钥」
之间就只有一层间接关系。

加上第 ②③ 步之后，**改写包里的任何一个 header 字段都会派生出一把不同的 KEK**，解密
直接失败。这与第 §2.2 节的解码期参数校验构成两道独立防线。

注意 `info` 与 `aad` 是**同一串字节**（都是 canonical header）。这不是巧合而是刻意：
header 的每一位都同时通过密钥派生和认证标签两条路径被绑定。

---

## 4. 恢复仪式

图中 `BE` 是后端（**不受信任**），`SS` 是系统安全存储。完整的成员链侧视角见
[`device-membership.md` §4.4](device-membership.md)。

### 4.1 创建恢复包（正常运转时做，不是出事后做）

```text
 管理员设备 A                               BE                  用户
     │                                      │                    │
     │ ① RecoveryPhrase::generate()         │                    │
     │    128-bit OsRng 熵                   │                    │
     │ ② 收集恢复材料（恢复身份密钥 + 工作区恢复材料）              │
     │ ③ RecoveryPackage::create(phrase, Argon2Params::recommended(), payload)
     │    salt / nonce 内部生成               │                    │
     │ ④ 发布恢复包对象 ────────────────────▶│                    │
     │                                      │                    │
     │ ⑤ phrase.display_once() ───────────────────────────────────▶│
     │    返回 Zeroizing<String>，离开作用域即清零                   │
     │    第二次调用返回 RecoveryPhraseAlreadyRevealed              │
     │                                      │      ⑥ 用户离线抄写   │
     │                                      │         并妥善保管    │
     │ ⑦ phrase 离开作用域 → Drop 时 zeroize                        │
```

**第 ⑤⑥ 步之后，EnvSync 就再也不知道这串短语了。** 它不在安全存储里、不在后端上、
不在任何日志里。这是有意的——见 §5。

### 4.2 使用恢复包重建访问权

```text
 用户 + 新设备 D                BE                    SS
    │                          │                      │
    │ ① 输入抄写的短语           │                      │
    │    RecoveryPhrase::parse()                       │
    │    ├─ 字符集/长度不合法 → RecoveryPhraseMalformed  │
    │    └─ 校验位不匹配      → RecoveryPhraseChecksum   │
    │                          │                      │
    │ ② 拉取恢复包 ◀────────────│                      │
    │ ③ 解码：版本 → 套件 → KDF 参数区间 → 密文长度       │
    │    任一不合法即拒绝，**不做任何 Argon2 分配**       │
    │                          │                      │
    │ ④ package.open(&phrase)  │                      │
    │    Argon2id → HKDF → ChaCha20-Poly1305-Open      │
    │    失败一律 CryptoError::Authentication（见 §6）  │
    │                          │                      │
    │ ⑤ 得到恢复材料 → 重建恢复身份                       │
    │──── put(recovery-identity) ─────────────────────▶│
    │                          │                      │
    │ ⑥ 生成 D 的设备密钥对，用恢复身份签发 AddMember{D, Admin}
    │──── 发布事件 ─────────────▶│                      │
    │ ⑦ 逐台 Revoke 全部旧设备；每一次 epoch +1 ─────────▶│
    │ ⑧ 为 D 签发新纪元信封 ─────▶│                      │
    │──── put(device-*-key / workspace-data-key / checkpoint) ────▶│
```

**第 ③ 步的顺序不能调换。** 参数区间检查必须在任何 Argon2 分配之前完成，否则一个畸形包
就是一次拒绝服务。

### 4.3 恢复对现有设备的影响

**恢复的后果是：全部旧设备失去访问权，必须重新授权。** 这不是副作用，这是恢复的定义。

恢复流程的触发前提是「所有设备都丢了」。既然它们丢了，就必须假设它们**落在了别人手里**。
因此第 ⑦ 步撤销全部旧设备不是可选项：

* 每一次 `Revoke` 强制推进密钥纪元 `n → n+1`（`RevocationMustRotateEpoch`），
  因此撤销 k 台旧设备后纪元前进 k；
* 旧设备拿不到新纪元的信封 → 解不开恢复之后写入的任何秘密；
* 旧设备签发的任何事件被拒（`ActorRevoked`）；
* 如果某台旧设备后来找回了，它必须走完整的邀请流程重新加入
  （[`device-membership.md` §4.2](device-membership.md)），并且**应该重新生成密钥对**。

测试 `recovery_starts_a_new_epoch_and_forces_old_devices_to_re_authorise` 覆盖了整条
路径：旧设备失去成员资格、纪元从 1 推进到 2、检查点随之前进。

**恢复不重写历史。** genesis 不变，`previous` 链不断，sequence 连续递增。链上因此永久
记录着「某个时刻，恢复身份加入并撤销了全部旧设备」——恢复过程本身是可审计的。

**恢复不能收回已经泄露的旧秘密。** 旧设备持有旧纪元的数据密钥，它能解密它在丢失前
拷贝走的任何密文。因此**恢复之后必须到各自的签发方去轮换所有秘密值**：重新生成 API
token、重新签发证书、重置口令。详见 [`vault-format.md` §5.2](vault-format.md)。

---

## 5. 备份责任

这一节请完整读完。它描述的是**用户必须自己承担、EnvSync 无法代劳**的部分。

### 5.1 用户必须自己保管的

| 东西 | 为什么必须离线保管 |
|---|---|
| **恢复短语（32 个符号，展示为 8 组 × 4，共 39 个字符）** | 它是恢复包的唯一钥匙。EnvSync 只在创建时展示它一次，之后不再持有它。 |

保管建议（按推荐度排序）：

1. **手写在纸上，放进你保管重要证件的地方。** 纸不联网、不会被恶意软件读走、不会因为
   云盘账号被盗而泄露。至少抄两份，放在两个物理位置。
2. **刻在金属备份板上**（如果这个工作区里的秘密值得这个成本）。
3. **存进一个与 EnvSync 完全独立的密码管理器**——注意「独立」：如果那个密码管理器的
   主密码又存在 EnvSync 里，你就造了一个循环。

**不要**：截图、拍照后留在相册里、发给自己的聊天工具、存在 EnvSync 同步的任何文件里、
存在与工作区后端同一个云账号下。

### 5.2 EnvSync 保管的

| 东西 | 存在哪里 | 丢了怎么办 |
|---|---|---|
| 设备私钥（X25519 + Ed25519） | 系统安全存储（`device-kem-key` / `device-signing-key`） | 用另一台设备重新邀请这台设备 |
| 工作区数据密钥 | 系统安全存储（`workspace-data-key`）+ 后端上的每设备 HPKE 信封 | 用另一台在册设备的信封取回 |
| 反回滚检查点 | 系统安全存储（`checkpoint`），SQLite 里有审计副本 | 由恢复流程重建（见 §4.2） |
| 恢复身份材料 | 后端上的加密恢复包 + 恢复后写入 `recovery-identity` | 需要恢复短语才能取出 |
| 成员事件、信封、密封秘密 | 后端（内容寻址不可变对象） | 后端的备份责任；本地 SQLite 只有索引 |

### 5.3 EnvSync 明确**不**保管的

* **恢复短语本身。** 没有托管、没有找回、没有客服重置、没有「安全问题」。
* **任何形式的短语备份或影子副本。** 短语从不写入安全存储，不写入后端，不写入日志。
* **能绕过短语打开恢复包的后门。** 恢复包的 KEK 只由短语的熵派生（§3.2），不存在第二条
  路径。

### 5.4 丢失恢复短语的后果

**分两种情况，后果完全不同：**

| 情况 | 后果 |
|---|---|
| 短语丢了，但**还有至少一台在册设备** | 不影响日常使用。**立刻**创建一个新的恢复包并抄写新短语（旧包作废）。这是唯一的补救窗口。 |
| 短语丢了，且**所有设备都丢了** | **工作区里的秘密永久无法恢复。** 没有任何技术手段能挽回。 |

第二行不是「很难恢复」，是**数学上不可能**：数据密钥只存在于（已丢失的）设备安全存储和
（需要短语才能打开的）恢复包里。密封秘密的密文还在后端上，但打开它需要一把已经不存在于
任何可访问位置的密钥。

**因此：短语丢失时的正确反应是立刻趁还有设备赶紧重建恢复包，而不是等到出事再说。**

同理，**恢复包本身也要活着**：如果后端上的恢复包被删掉了，短语再完好也没用。恢复包是
一个普通的内容寻址对象，跟随后端的备份策略。

---

## 6. 为什么错误口令只返回统一的 authentication failure

`RecoveryPackage::open` 的失败分成两类：

| 类别 | 返回 | 是否区分原因 |
|---|---|---|
| 结构性（版本未知、套件未知、密文长度越界） | `UnsupportedFormatVersion` / `UnsupportedSuite` / `InvalidLength` / `CiphertextTooLarge` | ✅ 区分——这些本来就是公开信息 |
| 密码学性（口令不对、密文被改、tag 被改、header 被改） | **一律 `CryptoError::Authentication`** | ❌ 不区分 |

### 6.1 理由

**任何能区分「口令错了」和「密文被改了」的信号，都是一个 oracle。**

设想一个更「友好」的实现，它区分这两种情况。攻击者拿到恢复包（它是公开材料）之后可以：

1. 逐位翻转密文，观察返回的是「密文损坏」还是「口令错误」，从而**在不知道口令的情况下
   定位 AEAD 的内部结构**；
2. 更糟的是，如果实现在「口令对但密文坏」时给出不同的响应，攻击者就得到了一个
   **离线口令验证器**——它可以在本地穷举候选短语，用响应差异判断哪一个是对的，
   完全绕过 Argon2id 之外的一切防护。

（Argon2id 的内存硬性代价仍然在，所以这不是一个致命漏洞；但它把攻击者需要的
「区分成功与失败」这一步从「需要真正解密成功」降级成「观察错误分类」，而后者往往能被
时间侧信道、日志差异或错误码泄露。）

**归一到一个错误就消灭了整类问题。** 攻击者只能得到一个 bit：成功，或者失败。

### 6.2 同一条原则贯穿整个密码学层

这不是恢复包的特例。`CryptoError::Authentication` 的文档写得很清楚：一切「解不开」的
情况——密钥不对、口令不对、密文被改、AAD 被改、参数被改——都归一到它。

* Sealed Secret：错误密钥 / 篡改密文 / 跨工作区 / 跨秘密名 / 跨纪元，全部
  `Authentication`（见 [`vault-format.md` §2.2](vault-format.md)）。
* Key Envelope：非目标设备（长度检查之后）、篡改密文、篡改 `enc`，全部 `Authentication`。
* Recovery Package：本节。

测试 `wrong_phrase_returns_the_same_authentication_failure` 直接断言错误口令与其他
密码学失败返回同一个变体。

### 6.3 副作用：错误信息不含任何可用于关联的内容

`CryptoError::Authentication` 的 `Display` 是固定的四个汉字「认证失败」，没有字段。
因此它不可能携带口令片段、密文片段或 salt。这一条被
`no_error_path_leaks_the_canary_plaintext` 覆盖：该测试把 canary 明文喂进包括
「错误恢复短语」「把明文当短语解析」「KDF 参数越界」在内的 14 条失败路径，断言
`Display`、`Debug` 与整条 `source()` 链里都不出现它。

**代价与取舍：** 用户输错短语时看到的是「认证失败」而不是「口令不对」。这确实不够
友好——但校验位已经在**更早的阶段**把「抄错了」这一类问题挡下来并给出了明确的
`RecoveryPhraseChecksum`。走到 `open` 还失败，说明短语格式完全正确、校验位也对，
那么最可能的情况是**这串短语属于另一个工作区**，而这一点恰恰不应该被确认。
