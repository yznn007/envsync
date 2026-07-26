# EnvSync 设备成员链与反回滚检查点（M2）

一个工作区的成员关系不是一张可以被后端随意改写的表，而是一条**签名事件链**。本文描述
这条链的结构、角色授权矩阵、验证器拒绝的全部攻击路径、四个运维仪式的完整步骤、
`DeviceId` 派生方式变更的迁移说明，以及建立在链之上的反回滚检查点。

配套文档：算法套件与线格式见 [`vault-format.md`](vault-format.md)，恢复短语与恢复包见
[`recovery.md`](recovery.md)，信任边界见 [`../security-model.md`](../security-model.md)。
**命令细节见 [`../cli.md`](../cli.md)**——本文只描述服务层语义。

---

## 1. 成员事件链的结构

```text
genesis (seq 0, previous = None, epoch 1)
   └─ e1 (seq 1, previous = digest(genesis))
        └─ e2 (seq 2, previous = digest(e1))
             └─ …
```

事件定义在 `envsync_domain::membership::MembershipEvent`。领域层**不依赖
`envsync-crypto`**：它只定义结构、编码与摘要规则，把公钥当作不透明的 64 字节
（`DevicePublicBytes`）保存。验签、授权判定与链回放在 `envsync_core::membership`。

### 1.1 事件字段表

canonical CBOR **9 元数组**，字段顺序即数组顺序，任何增删都必须提升
`MEMBERSHIP_EVENT_FORMAT_VERSION`：

| # | 字段 | CBOR 类型 | 取值 | 进签名 | 进事件摘要 |
|---|---|---|---|---|---|
| 0 | `format_version` | uint | 恒为 `1`（`MEMBERSHIP_EVENT_FORMAT_VERSION`） | ✅ | ✅ |
| 1 | `workspace` | bytes(16) | 所属工作区 UUID | ✅ | ✅ |
| 2 | `sequence` | uint | 链上位置，从 `0`（genesis）连续递增 | ✅ | ✅ |
| 3 | `previous` | bytes(32) 或 `null` | 前一事件的摘要；genesis 为 `null` | ✅ | ✅ |
| 4 | `epoch` | uint | 本事件生效后的密钥纪元 | ✅ | ✅ |
| 5 | `actor` | bytes(32) | 签发该事件的 `DeviceId` | ✅ | ✅ |
| 6 | `action` | array | 见 §1.2 | ✅ | ✅ |
| 7 | `created_at_unix_ms` | uint | 创建时刻，**仅供审计，不参与任何判定** | ✅ | ✅ |
| 8 | `signature` | bytes(64) | `actor` 对 §1.3 的 Ed25519 签名 | ❌ | ✅ |

### 1.2 `action` 的四个变体

判别式是**文本**而不是整数：整数判别式在人工排查线格式时毫无意义，文本判别式的字节
顺序也天然稳定。

| 动作 | CBOR 形状 | 携带公钥 | 推进纪元 |
|---|---|---|---|
| `Genesis` | `["genesis", subject(32), public(64)]` | ✅ | ❌（恒为 `GENESIS_EPOCH = 1`） |
| `AddMember` | `["add_member", subject(32), public(64), role]` | ✅ | ❌ |
| `Promote` | `["promote", subject(32)]` | ❌ | ❌ |
| `Revoke` | `["revoke", subject(32)]` | ❌ | ✅ 恰好 `+1` |

`role` 是文本单元枚举，取值 `"admin"` 或 `"member"`。动作短名
（`MembershipAction::kind()` 返回的 `"genesis"` / `"add_member"` / `"promote"` /
`"revoke"`）是**持久化契约**，只能新增不能重命名，测试
`action_kinds_are_a_stable_persistence_contract` 钉住它。

`DevicePublicBytes` 是 `X25519 公钥(32) ‖ Ed25519 公钥(32)`，共 `DEVICE_PUBLIC_LEN = 64`
字节。它的文本表示是 128 个**小写**十六进制字符，大写一律拒绝（保证一份公钥在 JSON、
CBOR 和日志里只有一种写法）。

**携带公钥的动作必须自洽：** `MembershipAction::validate` 检查
`public.device_id() == subject`，不成立返回 `MembershipEventError::SubjectKeyMismatch`。
因为 `DeviceId = BLAKE3_domain("envsync:device:v1", x25519_pk ‖ ed25519_pk)`，这条检查
意味着**攻击者无法在保持 `DeviceId` 不变的前提下换掉其中一把密钥**——比如把 HPKE 信封
重定向到自己控制的 X25519 私钥。测试 `device_id_is_derived_from_both_public_keys`、
`device_id_changes_with_any_public_key_bit`、`flipping_any_public_key_bit_changes_device_id`。

### 1.3 签名覆盖范围

待签内容是 `MembershipEvent::signing_payload()`——**除签名之外的全部 8 个字段**的
canonical CBOR 数组：

```text
signing_payload = canonical_cbor([
    format_version, workspace, sequence, previous, epoch, actor, action, created_at_unix_ms
])
```

它被单独构造而不是「整个事件去掉最后一项」，是为了让「到底签了什么」可以被独立复现：
任何人拿到事件都能重新算出这串字节并自行验签。测试
`digest_covers_the_signature_but_signing_payload_does_not`、
`signing_payload_excludes_the_signature`。

这串字节随后作为 `payload` 进入密码学层的**域分隔签名结构**
（`envsync_crypto::device::signing_input`，见 [`vault-format.md` §3](vault-format.md)）：

```text
signing_input = canonical_cbor([
    "envsync:device-signature:v1",                      // 域前缀
    1,                                                  // 签名格式版本
    "ESV1_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519",  // 套件名
    "membership-event",                                 // 用途标签 MEMBERSHIP_SIGNATURE_DOMAIN
    workspace_id (bytes 16),                            // 再次绑定工作区
    BLAKE3_domain("envsync:device-signature-payload:v1", signing_payload),
])
```

Ed25519 覆盖的是 `signing_input`，不是 `signing_payload` 本身。四条推论：

* **跨工作区重放失败**——`workspace_id` 在签名结构里（`cross_workspace_replay_is_rejected`）；
* **改 payload 失败**——payload 摘要在签名结构里（`modified_payload_is_rejected`）；
* **换 signer 失败**——验签公钥来自链上登记的 actor 记录（`wrong_signer_is_rejected`）；
* **成员事件签名不能被复用成快照签名或信封签名**——用途标签 `"membership-event"` 在签名
  结构里（`different_domain_is_rejected`）。

### 1.4 `previous` 摘要链

后继事件的 `previous` 指向前一事件的
`Digest32::domain_hash("envsync:membership-event-digest:v1", canonical_cbor(整个事件))`。

**摘要覆盖整个事件，包括签名。** 因此「换一枚签名」等价于「换一个事件」：攻击者无法在
保持链接不变的前提下替换签名。测试 `digest_changes_with_every_field`、
`chain_links_are_expressed_by_the_previous_digest`。

同一条事件另有一个**对象标识** `ObjectId::for_bytes(ObjectKind::MembershipEvent, …)`
（域 `envsync:membership-event:v1`），用于在 Backend 里寻址。两个摘要用不同的域标签，
键空间不相交，测试 `membership_events_have_their_own_object_domain`、
`events_are_content_addressed_objects`。

### 1.5 结构不变量与资源上限

`MembershipEvent::validate()` 是**不需要密码学**就能做的结构性校验，返回
`MembershipEventError`：

| 检查 | 违反时的错误 |
|---|---|
| `format_version == 1` | `UnsupportedFormatVersion { found, supported }` |
| `sequence == 0` ⇒ `previous == None` | `MalformedGenesis` |
| `sequence == 0` ⇒ 动作是 `Genesis` | `NonGenesisAtZero` |
| `sequence > 0` ⇒ `previous == Some(_)` | `MissingPrevious(sequence)` |
| `signature.len() == 64` | `SignatureLength { expected, found }` |
| 携带公钥时 `public.device_id() == subject` | `SubjectKeyMismatch` |
| 公钥文本是 128 个小写十六进制字符 | `PublicKeyMalformed { expected }` |

解码器在 `from_value` 末尾就调用 `validate()`，因此**一条结构非法的事件根本无法从
canonical CBOR 解码出来**（测试 `decoding_enforces_the_structural_invariants`、
`unknown_format_version_is_rejected_rather_than_downgraded`）。

一条链最多 `MAX_MEMBERSHIP_EVENTS = 4096` 条事件（含 genesis）。这个上限在做**任何**
曲线运算之前生效，防止「超长链」这种资源耗尽输入。

---

## 2. 角色与授权矩阵

只有两级角色（`MemberRole`）：`Admin` 可以变更成员关系，`Member` 只能读写秘密内容。
刻意不做更细的权限矩阵——角色越多，授权判定的攻击面越大。

`MemberRole::can_administer()` 是唯一的判定函数：`Admin => true`，`Member => false`。

### 2.1 谁可以签发什么

| actor 角色 \ 动作 | `Genesis` | `AddMember` | `Promote` | `Revoke` |
|---|---|---|---|---|
| **链外设备**（未登记 / 未知） | ✅ 仅限 seq 0 且自签自己 | ❌ `ActorUnknown` | ❌ `ActorUnknown` | ❌ `ActorUnknown` |
| **Admin** | ❌ `DuplicateGenesis` | ✅ | ✅ | ✅（除非是最后一个管理员） |
| **Member** | ❌ `DuplicateGenesis` | ❌ `ActorNotAdmin` | ❌ `ActorNotAdmin` | ❌ `ActorNotAdmin` |
| **已撤销设备** | ❌ `DuplicateGenesis` | ❌ `ActorRevoked` | ❌ `ActorRevoked` | ❌ `ActorRevoked` |

三点说明：

1. **`Genesis` 是链的信任根，只能出现一次，且必须自签。** `ChainReplay::start` 要求
   `genesis.actor == subject`，否则 `GenesisActorMismatch`——不然「谁是第一个管理员」
   就不是自证的了。genesis 之后任何位置再出现 `Genesis` 动作一律
   `DuplicateGenesis { sequence }`。
2. **判定顺序是「先验签，后看角色」。** `ChainReplay::apply` 先 `resolve_actor`（解析
   成员记录，同时区分「陌生」与「已撤销」），再 `verify_event_signature`，最后才检查
   `can_administer()`。验签失败的事件不应该继续暴露授权逻辑的分支。
3. **`DuplicateGenesis` 出现在授权检查之后。** 上表中「Admin/Member/已撤销设备签发
   `Genesis`」的结果是 `DuplicateGenesis` 而非角色错误，因为 `apply_action` 在角色检查
   通过后才判定动作语义；`Member` 与已撤销设备会先在角色 / actor 解析处被拦下。

### 2.2 动作的主体侧约束

| 动作 | 主体必须 | 违反时的错误 |
|---|---|---|
| `AddMember` | **不是**当前成员 | `MemberAlreadyExists { sequence, device }` |
| `AddMember` | 公钥是合法曲线点 | `PublicKeyInvalid { sequence }` |
| `Promote` | 是当前成员 | `SubjectNotMember { sequence, device }` |
| `Promote` | **不是**管理员 | `AlreadyAdmin { sequence, device }` |
| `Revoke` | 是当前成员 | `SubjectNotMember { sequence, device }` |
| `Revoke` | 不是最后一个管理员 | `LastAdminRevoked { sequence }` |

`AddMember` 处校验公钥曲线点合法性的理由：否则这台设备将来根本无法被验签，等于往链上
写了一条永远不能行使权限的记录。

**重新加入一台曾被撤销的设备是允许的**——那是管理员的显式决定（例如设备找回）。实现只
把它从「已撤销」集合里移除，让后续的错误分类保持准确。注意它必须用**新的密钥对**重新
注册才有意义：旧密钥仍然能解密旧纪元的内容（见
[`vault-format.md` §5.2](vault-format.md)）。

### 2.3 `MembershipState` 只包含当前有效成员

回放整条链得到 `MembershipState { members, epoch, head, sequence }`。**被撤销的设备
直接从 `members` 中消失**，不留「已撤销」的软状态——那种标记非常容易被调用方误当作
「仍然是成员」。「谁曾经被撤销过」属于历史，需要时回放事件即可。

链的不变量保证 `admin_count() >= 1` 且 `is_empty() == false` 永远成立。测试
`membership_state_only_reports_current_members`。

「已撤销设备」的集合只在回放器 `ChainReplay` 内部存在，**仅用于错误分类**：把「陌生
设备」和「已撤销设备」这两种同样要拒绝、但运维含义完全不同的情况区分开。

---

## 3. 验证器拒绝的全部攻击路径

`verify_membership_chain(genesis, events) -> Result<MembershipState, MembershipError>`
是**纯函数**：不读网络、不读数据库、不看时钟。输入是「我已经信任的 genesis」加上
「后端声称的后续事件」，输出要么是可信状态，要么是一个说明**哪一条事件、因为什么原因**
被拒绝的错误。做成纯函数的意义是：它可以被完整地做成攻击路径测试矩阵，而不需要搭出
后端和数据库。

**检查顺序（便宜的先做）：**

```text
1. 结构限制：事件总数上限 → genesis 形状 → 格式版本
2. 逐事件：workspace → sequence（分叉/重复/回退/跳号）→ previous 链接
           → epoch 单调性与「只有撤销能推进纪元」
           → actor 解析（未知 / 已撤销）→ 验签 → 角色授权
           → 动作语义（重复 genesis、主体校验、最后一个管理员）
```

曲线运算刻意排在最后一批：任何结构性问题都应该在做昂贵计算之前被拒绝。

### 3.1 攻击路径矩阵

`MembershipError` 的每个变体都带上出问题的 `sequence`，让「链的第几条事件坏了」在日志
与 CLI 输出里一目了然。`code()` 返回的字符串是**对外契约**，只能新增不能重命名。

| # | 攻击 | 错误变体 | 错误码 | 锁定测试 |
|---|---|---|---|---|
| 1 | **断链**：`previous` 与前一事件摘要不符 | `ChainBroken { sequence }` | `membership.chain_broken` | `broken_chain_link_is_rejected` |
| 2 | **分叉**：同一 `sequence` 上两个不同事件 | `ForkDetected { sequence }` | `membership.fork` | `fork_at_the_same_sequence_is_rejected` |
| 3 | **重复 sequence**：同一事件被提交两次 | `DuplicateSequence { sequence }` | `membership.duplicate_sequence` | `duplicated_event_at_the_same_sequence_is_rejected` |
| 4 | **旧事件重放**：`sequence` 低于链头 | `SequenceRollback { head, found }` | `membership.sequence_rollback` | `replaying_an_old_event_is_rejected` |
| 5 | **sequence 跳号** | `SequenceGap { expected, found }` | `membership.sequence_gap` | `sequence_gaps_are_rejected` |
| 6 | **纪元跳跃**：一次前进超过 `+1` | `EpochJump { sequence, current, found }` | `membership.epoch_jump` | `future_epoch_jump_is_rejected` |
| 7 | **纪元回退** | `EpochRollback { sequence, current, found }` | `membership.epoch_rollback` | `rolling_the_epoch_back_is_rejected` |
| 8 | **非撤销事件推进纪元** | `EpochAdvancedWithoutRevocation { sequence, action }` | `membership.epoch_without_revocation` | `advancing_the_epoch_without_a_revocation_is_rejected` |
| 9 | **撤销却不轮换纪元** | `RevocationMustRotateEpoch { sequence, expected }` | `membership.revocation_no_rotation` | `revoking_without_rotating_the_epoch_is_rejected` |
| 10 | **已撤销 actor 继续签发** | `ActorRevoked { sequence, device }` | `membership.actor_revoked` | `a_revoked_actor_cannot_sign_further_events` |
| 11 | **陌生 actor**（含伪造 invitation） | `ActorUnknown { sequence, device }` | `membership.actor_unknown` | `an_unknown_actor_is_rejected`、`a_new_device_bootstraps_its_checkpoint_from_an_admin_signed_invitation` |
| 12 | **越权**：`Member` 签发成员变更 | `ActorNotAdmin { sequence, device }` | `membership.actor_not_admin` | `a_plain_member_cannot_add_promote_or_revoke` |
| 13 | **撤销最后一个 admin** | `LastAdminRevoked { sequence }` | `membership.last_admin` | `the_last_admin_cannot_be_revoked` |
| 14 | **跨 workspace 混入** | `WorkspaceMismatch { sequence }` | `membership.workspace_mismatch` | `cross_workspace_events_are_rejected` |
| 15 | **签名无效**（篡改签名字节） | `SignatureInvalid { sequence }` | `membership.signature_invalid` | `a_tampered_signature_is_rejected`、`error_codes_are_stable_and_unique_per_variant` |
| 16 | **换设备签名**（actor 声称是 A，实际由 B 签） | `SignatureInvalid { sequence }` | `membership.signature_invalid` | `signing_with_another_device_key_is_rejected` |
| 17 | **篡改 genesis 签名** | `SignatureInvalid { sequence: 0 }` | `membership.signature_invalid` | `a_tampered_genesis_signature_is_rejected` |
| 18 | **第二个 Genesis** | `DuplicateGenesis { sequence }` | `membership.duplicate_genesis` | `a_second_genesis_is_rejected` |
| 19 | **首条不是 genesis** | `GenesisMissing` | `membership.genesis_missing` | `a_non_genesis_first_event_is_rejected` |
| 20 | **genesis 由他人签发** | `GenesisActorMismatch` | `membership.genesis_actor_mismatch` | `genesis_must_be_self_signed_by_the_admin_it_registers` |
| 21 | **genesis 用了非初始纪元** | `GenesisEpoch { expected, found }` | `membership.genesis_epoch` | `genesis_must_use_the_initial_epoch` |
| 22 | **重复添加成员** | `MemberAlreadyExists { sequence, device }` | `membership.member_exists` | `duplicate_members_are_rejected` |
| 23 | **提升非成员 / 已是管理员** | `SubjectNotMember` / `AlreadyAdmin` | `membership.subject_not_member` / `membership.already_admin` | `promoting_a_non_member_or_an_existing_admin_is_rejected` |
| 24 | **超长链耗尽资源** | `TooManyEvents { limit, found }` | `membership.too_many_events` | `oversized_chains_are_rejected_before_any_crypto` |
| 25 | **结构非法的事件** | `Event { sequence, source }` | `membership.malformed_event` | `decoding_enforces_the_structural_invariants`、`signature_length_is_part_of_the_structural_contract` |
| 26 | **非法曲线点公钥** | `PublicKeyInvalid { sequence }` | `membership.public_key_invalid` | 密码学层：`invalid_public_key_encoding_is_rejected`、`small_order_public_key_cannot_verify` |

关于第 16 行：**「签名者不是 actor 声称的设备」不需要单独判断**——验签用的公钥来自
**链上登记的 actor 记录**，换一台设备来签就必然验不过。这是一条结构性保证，不是一条
额外的 if。

关于第 26 行：链验证器有 `PublicKeyInvalid` 分支（`AddMember` 登记时与验签取公钥时各
一处），但目前**没有**直接构造非法曲线点公钥的成员链攻击测试；覆盖来自密码学层的
`DevicePublic::validate` 测试。

### 3.2 生成侧的自检

`create_genesis` 与 `append` 在返回事件之前，都会用**与验证器完全相同**的转移规则做一次
dry run（`ChainReplay::start` / `ChainReplay::apply`）。宁可在本机失败，也不要把一条会
被所有其他设备拒绝的事件发布到后端。测试
`append_never_produces_an_event_the_verifier_would_reject`。

`append` 的 `sequence`、`previous`、`epoch` 全部**由已验证状态推导**，调用方无法指定：
这些字段一旦可以由外部指定，就等于把链的不变量交给了调用点去维护。

唯一的措辞差异：`MembershipState` 不携带「已撤销设备」集合，因此本地状态已经不认识的
签发者一律报 `ActorUnknown` 而不是 `ActorRevoked`。这只影响诊断措辞，不影响是否放行。

---

## 4. 四个仪式

以下序列图描述**服务层语义**：谁做什么、传什么、验什么。具体命令名与参数见
[`../cli.md`](../cli.md)。

图中 `BE` 是后端（**不受信任**），`SS` 是系统安全存储（macOS Keychain / Windows
Credential Manager / Linux Secret Service）。

### 4.1 创建工作区（genesis）

```text
 管理员设备 A                          SS                 BE
     │                                 │                  │
     │ ① 生成 X25519 + Ed25519 密钥对   │                  │
     │    DeviceId = H(x_pk ‖ ed_pk)   │                  │
     │────────── put(device-kem-key) ─▶│                  │
     │────────── put(device-signing-key)▶                 │
     │                                 │                  │
     │ ② create_genesis(A, workspace, now)                │
     │    seq 0 / previous=null / epoch 1 / 自签           │
     │ ③ 自检：ChainReplay::start(genesis) 必须通过         │
     │                                 │                  │
     │ ④ 生成 DataKey（32 字节 OsRng）  │                  │
     │────────── put(workspace-data-key)▶                 │
     │ ⑤ seal_envelope(A.public, ws, epoch=1, DataKey)    │
     │                                 │                  │
     │ ⑥ 发布 genesis 事件对象 + 自己的信封 ───────────────▶│
     │ ⑦ 事务提交后才推进 checkpoint    │                  │
     │────────── put(checkpoint) ─────▶│                  │
```

**验什么：** genesis 必须自签（`actor == subject`）、`epoch == GENESIS_EPOCH`、
`previous == null`、`sequence == 0`。这四条由 `ChainReplay::start` 在第 ③ 步立刻检查，
因此本机不可能产出一条别人会拒绝的 genesis。

### 4.2 邀请 / 加入（新设备克隆）

```text
 新设备 N            带外渠道           管理员 A            BE            N 的 SS
    │                   │                 │                │                │
    │ ① 生成密钥对        │                 │                │                │
    │   DeviceId_N       │                 │                │                │
    │──── DeviceId_N + DevicePublicBytes ─▶│                │                │
    │                   │                 │                │                │
    │                   │  ② 校验 public.device_id()==subject               │
    │                   │  ③ append(state, A, AddMember{N, public, role})   │
    │                   │     epoch 不变（AddMember 不轮换）                  │
    │                   │  ④ seal_envelope(N.public, ws, epoch, DataKey)    │
    │                   │                 │─── 发布事件 + 信封 ─▶│           │
    │◀── genesis 摘要（带外，必须可信）────│                │                │
    │                   │                 │                │                │
    │ ⑤ 从 BE 拉 genesis + 全部后继事件 ◀──────────────────│                │
    │ ⑥ 比对 genesis 摘要 == 带外收到的那个                  │                │
    │ ⑦ verify_membership_chain(genesis, events)           │                │
    │ ⑧ 确认 state.contains(DeviceId_N)                     │                │
    │ ⑨ 取自己的信封，先确认 recipient==自己、epoch==state.epoch              │
    │    再 open_envelope → DataKey                        │                │
    │──── put(device-*-key, workspace-data-key) ───────────────────────────▶│
    │ ⑩ 建立首个 checkpoint（check_advance(None, …) 一律放行）              │
    │──── put(checkpoint) ─────────────────────────────────────────────────▶│
```

**第 ⑥ 步是整个流程里唯一无法用密码学替代的一步。** `verify_membership_chain` 只能证明
「这条链从给定的 genesis 合法延伸而来」，**无法证明「这个 genesis 是对的」**。genesis
摘要必须通过带外可信渠道（当面、已认证的即时通讯、已有的可信设备显示的二维码）送达。

伪造的 invitation 过不了第 ⑦ 步：攻击者用自己的密钥重签一条 `AddMember`，其 `actor`
不在链上，返回 `ActorUnknown`。测试
`a_new_device_bootstraps_its_checkpoint_from_an_admin_signed_invitation` 覆盖了正常路径
与伪造路径两侧。

**第 ⑨ 步的顺序不能颠倒。** 成员链验证必须先于打开信封，否则攻击者可以用自己生成的
数据密钥替换信封，把新设备后续写入的秘密引导到它控制的密钥上。

### 4.3 撤销设备

```text
 管理员 A                        BE                     其余设备 R
    │                            │                         │
    │ ① 拉最新链并验证             │                         │
    │◀────── genesis + events ───│                         │
    │ ② append(state, A, Revoke{X})                        │
    │    epoch: n → n+1（强制，否则 RevocationMustRotateEpoch）
    │    若 X 是最后一个管理员 → LastAdminRevoked，拒绝签发    │
    │ ③ 生成新 DataKey'（32 字节 OsRng）                     │
    │ ④ 对每台**剩余** active 设备 seal_envelope(…, epoch=n+1, DataKey')
    │ ⑤ 先发布全部新信封 ─────────▶│                         │
    │ ⑥ 再发布 Revoke 事件（新链头）▶│                         │
    │ ⑦ 本地事务提交后推进 checkpoint（revision / membership / epoch 同时前进）
    │                            │                         │
    │                            │◀── 拉链并验证 ────────────│
    │                            │    看到 epoch n+1        │
    │                            │─── 新信封 ──────────────▶│
    │                            │    open_envelope → DataKey'
    │                            │    新写入用 DataKey'；旧对象按 lazy rewrap
```

**第 ⑤ 步必须先于第 ⑥ 步。** 新链头一旦发布，所有设备都会开始期待新纪元的信封；如果
信封还没上传，剩余设备会陷入「链说 epoch 是 n+1，但我没有 n+1 的密钥」的状态，而这是
后端上的既成事实，重试无法自愈。反过来先发信封则完全安全——一个纪元 `n+1` 的信封在
链头还是 `n` 的时候只是一个无人引用的不可变对象。

整个流程由 `envsync_core::rotation` 的五阶段状态机（`prepared` →
`envelopes_published` → `head_published` → `rewrapping` → `complete`）编排，任一阶段
中断都能幂等恢复；进入 `head_published` 之前会**实际回后端确认**信封都在。详见
[`vault-format.md` §5.3](vault-format.md)。

被撤销设备 X 的后果：

* 它拿不到新信封 → 解不开 `epoch = n+1` 及以后的任何 sealed object；
* 它签发的任何新事件都会被拒（`ActorRevoked`）；
* **它仍然持有旧的 `DataKey`**，因此仍能解密它在撤销前拷贝走的旧密文。详见
  [`vault-format.md` §5.2](vault-format.md) 的 lazy rewrap 安全边界，以及本文
  §7 的处置建议。

### 4.4 灾难恢复（所有设备都丢了）

```text
 用户 + 新设备 D              恢复短语        BE                    SS
    │                           │             │                     │
    │ ① 输入 32 符号恢复短语 ─────│             │                     │
    │    parse() 校验位不匹配即拒绝（RecoveryPhraseChecksum）          │
    │ ② 从 BE 取 RecoveryPackage ◀────────────│                     │
    │ ③ 解码时校验 Argon2id 参数在 [下限, 上限] 内                     │
    │ ④ open() → 恢复身份密钥材料（失败一律 Authentication）           │
    │                           │             │                     │
    │ ⑤ 用恢复身份重新登记一台管理员设备 D                             │
    │    AddMember{D, public_D, Admin}，epoch 不变 ──────────────────▶│
    │ ⑥ 逐台 Revoke 全部旧设备；每一次 epoch +1 ─────────────────────▶│
    │ ⑦ 为 D 签发新纪元信封 ────────────────────────────────────────▶│
    │ ⑧ 重建本地信任根                                                │
    │──── put(device-*-key / workspace-data-key / checkpoint) ──────▶│
```

**恢复不是「重置链」，而是在同一条链上往前走。** genesis 不变，`previous` 链不断，
sequence 连续递增。这一点很重要：它意味着恢复过程本身是**可审计**的——链上永久记录着
「某个时刻，恢复身份加入并撤销了全部旧设备」，而不是历史被静默改写。

测试 `recovery_starts_a_new_epoch_and_forces_old_devices_to_re_authorise` 覆盖了这条
路径：旧设备失去成员资格、纪元从 1 推进到 2、检查点随之前进。

恢复对现有设备的影响与备份责任见 [`recovery.md`](recovery.md) §4、§5。

---

## 5. `DeviceId` 从 UUID 改为公钥派生的迁移

[ADR-0002](../decisions/2026-07-26-device-id-derivation.md) 承诺把这段流程写在这里。

### 5.1 变了什么、没变什么

`DeviceId` **从 M0 起**就是 32 字节域分隔摘要（`envsync:device:v1`），构造函数是
`DeviceId::derive(public_material)`。M2 只改变了**输入**：

| 阶段 | `DeviceId::derive` 的输入 |
|---|---|
| M0 / M1 | 设备初始化时生成的随机设备种子（`envsync:config:device-seed:v1` 路径） |
| M2 起 | `X25519 公钥 ‖ Ed25519 公钥`（64 字节，`DevicePublicBytes`） |

**类型、宽度与编码都没变**（`Digest32` 的 32 字节，64 位小写十六进制文本）。因此
`SnapshotBody.author_device`、`SnapshotSignature.device`、本地检查点里已有的
`DeviceId` 字段全部**保持可解析**，不存在 schema 破坏。

变的是**值**：同一台物理机器在 M1 与 M2 下会得到两个不同的 `DeviceId`，因为输入换了。

### 5.2 为什么这必须是一次显式重新注册

一台已有设备升级到 M2 后，会持有一个新的 `DeviceId`。有两条路可走：

* **静默改写历史**：把链上（或本地记录里）的旧 `DeviceId` 就地替换成新的。**这条路被
  明确拒绝**——它要求某个组件有权在事后修改已签名的历史，而这正是成员链要消除的能力。
  一旦存在这样一条代码路径，它就是攻击者的目标。
* **显式重新注册**：把新的公钥材料当作一台**新设备**，由管理员签发一条 `AddMember`
  事件记录在链上。旧的 `DeviceId` 保持它在历史里的样子，不被触碰。

M2 选择后者。链上因此会看到「同一台物理机器先后有两个设备身份」，这是**准确**的描述：
M1 的身份没有任何密钥材料背书，M2 的身份有；它们不是同一个安全主体。

### 5.3 操作步骤

前提：至少有一台设备已经完成 M2 初始化并持有管理员角色（第一台设备走
[§4.1](#41-创建工作区genesis) 的 genesis 流程，其余设备走本节）。

1. **升级二进制**，但**先不要**删除任何本地状态。M1 的 `journal.db` 与备份目录在 M2
   仍然有效（schema 自动迁移，测试
   `m1_database_upgrades_to_v5_without_losing_data`；失败的迁移完整回滚，测试
   `a_failed_v3_migration_rolls_back_completely`）。
2. **在待迁移设备上生成 M2 密钥对。** 两把私钥写入系统安全存储
   （`SecurePurpose::DeviceKemKey`、`SecurePurpose::DeviceSigningKey`）。
   安全存储不可用时**必须终止**——M2 没有明文文件回退路径，见
   `PlatformError::SecureStoreUnavailable`。
3. **把新的 `DevicePublicBytes`（128 位小写十六进制）交给管理员设备**，通过带外可信
   渠道。同时把管理员那边的 genesis 摘要带回来。
4. **管理员签发 `AddMember`**，走 [§4.2](#42-邀请--加入新设备克隆) 的完整邀请流程。
   角色按需选择；把一台迁移设备直接提升为管理员时用两条事件（`AddMember` +
   `Promote`），不要在 `AddMember` 里直接给 `Admin` 除非你确实想让它一步到位。
5. **待迁移设备验链、开信封、建立检查点**（[§4.2](#42-邀请--加入新设备克隆) 第 ⑤–⑩ 步）。
6. **确认新旧身份都在预期状态**：新 `DeviceId` 出现在 `MembershipState::members` 里；
   旧 `DeviceId` **不在**——它从来就没有被登记过，因为 M1 没有成员链。
7. **`device.seed_hex` 的处置。** 它是 M1 的本机私有材料，从不上传后端。迁移完成后
   它对成员链毫无作用；保留它只影响 M1 兼容路径下的 `DeviceId` 计算。**不要**把它
   复制到其他机器（这条约束在 M1 就已成立，见
   [`../security-model.md` §4.3](../security-model.md)）。

**不需要做的事：** 不需要重建工作区、不需要重新 `capture`、不需要让已发布的快照失效。
`author_device` 字段里的旧 `DeviceId` 只是一个历史自述值，M2 不会因为它不在成员链上而
拒绝一份 M1 时代的快照——但也**不会**因此认为它可信（M1 的快照签名 `algorithm` 恒为
`"none"`）。

---

## 6. 反回滚检查点

CAS 只能保证「同一个后端上 revision 单调前进」，无法阻止后端**对某一台设备单独**回放
一份旧快照。那台设备会以为自己是最新的，从而：

* 用旧的 State Root 覆盖掉别人刚同步上去的配置；
* 用**撤销发生之前**的成员链头继续给已撤销设备发信封；
* 用旧的密钥纪元继续加密，让已撤销设备仍能解密新秘密。

检查点就是设备**自己记住的高水位线**。

### 6.1 四元组（外加两个辅助字段）

`envsync_core::checkpoint::Checkpoint`：

| 字段 | 类型 | 含义 | 参与判定 |
|---|---|---|---|
| `workspace` | `WorkspaceId` | 所属工作区 | ✅（必须相等） |
| `revision` | `u64` | 已接受的最高后端 revision | ✅ 单调不减 |
| `snapshot` | `SnapshotId` | 该 revision 对应的快照 | ✅ 同 revision 必须同快照 |
| `membership_digest` | `Digest32` | 已验证的成员链头摘要 | ✅ 同 sequence 必须同摘要 |
| `membership_sequence` | `u64` | 该链头在链上的位置 | ✅ 单调不减 |
| `key_epoch` | `u64` | 已知的最高密钥纪元 | ✅ 单调不减 |
| `updated_at_unix_ms` | `u64` | 本机更新时刻 | ❌ **仅供审计** |

`updated_at_unix_ms` 不参与任何判定，这是刻意的：时间来自本机时钟，攻击者影响不了它，
它也证明不了任何事。

### 6.2 为什么摘要之间没有顺序，所以需要 `membership_sequence`

**摘要不可比较。** 只拿到两个 `membership_digest`，本地无法判断哪个更新，也无法判断新
的那个是不是从旧的那个延伸出来的——哈希值之间没有序关系。

设计文档给定的四元组是「revision / snapshot / membership_digest / key_epoch」。实现
**额外记录了 `membership_sequence`**，即已验证链头在链上的位置。有了它，规则就完全
可判定：

```text
candidate.membership_sequence <  current.membership_sequence          → 阻塞（旧 head）
candidate.membership_sequence == current.membership_sequence
    且 membership_digest 不等                                        → 阻塞（链分叉）
candidate.membership_sequence >  current.membership_sequence          → 放行
```

最后一条之所以敢放行，是因为**链延续性由 `verify_membership_chain` 负责**：调用方必须
先从已信任的 genesis 完整回放到 `candidate.membership_digest`，验证通过才允许把它塞进
`candidate`。检查点只做单调性判定，不重复做链验证——两处各自负责一件事，比一个什么都做
的大函数更容易审计。

### 6.3 `check_advance` 判定规则表

`check_advance(current: Option<&Checkpoint>, candidate: &Checkpoint)`：

| 情况 | 结果 | 错误码 |
|---|---|---|
| `current == None`（首次建立信任根） | `Ok` | — |
| 工作区不同 | `WorkspaceMismatch` | `checkpoint.workspace_mismatch` |
| `revision` 变小 | `RevisionRollback { current, candidate }` | `checkpoint.revision_rollback` |
| `membership_sequence` 变小 | `MembershipRollback { current, candidate }` | `checkpoint.membership_rollback` |
| `membership_sequence` 相同但摘要不同 | `MembershipForked { sequence }` | `checkpoint.membership_forked` |
| `key_epoch` 变小 | `KeyEpochRollback { current, candidate }` | `checkpoint.key_epoch_rollback` |
| `revision` 相同但快照不同 | `SnapshotForked { revision }` | `checkpoint.snapshot_forked` |
| `revision` 与快照都相同，但链头或纪元不同 | `Diverged { revision }` | `checkpoint.diverged` |
| 完全相同 | `Ok`（幂等重放同一个头是允许的） | — |

判定顺序即上表顺序，实现在 `check_advance` 里是一串顺序的 `if`。

`CheckpointError::is_rollback_attack()` 把上面六个「检测到回滚 / 分叉」的变体与
「本机问题」（`Storage`、`Poisoned`）区分开：前者**必须中止本次同步**，不是重试；
后者修复后可以继续。测试 `storage_errors_are_not_rollback_attacks`。

**`current == None` 一律放行**是有意的：检查点无法凭空判断第一份状态的真伪，由调用方
负责先验证管理员签名的 invitation（[§4.2](#42-邀请--加入新设备克隆) 第 ⑥–⑦ 步）。

锁定测试（`crates/envsync-core/tests/anti_rollback.rs`）：
`a_lower_revision_is_blocked`、`a_different_snapshot_at_the_same_revision_is_blocked`、
`an_older_membership_head_is_blocked_even_when_the_revision_advances`、
`a_forked_membership_head_at_the_same_sequence_is_blocked`、
`an_older_key_epoch_is_blocked`、`the_same_revision_with_a_diverging_epoch_is_blocked`、
`a_checkpoint_from_another_workspace_is_blocked`、`a_genuine_advance_is_accepted`、
`replaying_the_same_head_is_idempotent`、`the_sqlite_audit_copy_enforces_the_same_rules`。

### 6.4 推进顺序

```text
1. 拉取后端头 → 2. 验证成员链 → 3. check_advance → 4. 应用到本地
                                                  → 5. 事务提交
                                                  → 6. 才推进 checkpoint
```

**第 6 步必须在第 5 步之后。** 反过来的话，进程在两步之间崩溃就会留下「检查点说我已经
到 12 了，本地其实还在 11」的状态，而 11 的数据再也无法被接受——设备把自己锁死了。

`advance(store, candidate)` 是推进检查点的**唯一推荐入口**：它把「判定」和「保存」绑在
一起，调用点就不可能漏掉判定。`CheckpointStore` 的实现**不应该**在 `save` 里自行做单调
性判定——判定规则是 `check_advance` 这一个纯函数，散落到每个实现里只会产生不一致的安全
边界。

### 6.5 权威副本在安全存储，SQLite 只是审计副本

| 副本 | 实现 | 位置 | 地位 |
|---|---|---|---|
| **权威** | `SecureCheckpointStore` | 系统安全存储，`SecurePurpose::Checkpoint`，account 名 `<workspace>/-/checkpoint` | 反回滚判定的依据 |
| 审计 | `SqliteCheckpointStore` | SQLite `checkpoints` 表 | 供 `doctor` 与事后排查 |
| 测试 | `InMemoryCheckpointStore` | 进程内存 | **不得**用于生产路径——它随进程消失，等于每次启动都重置信任根 |

理由：**SQLite 文件躺在用户目录里，任何本地进程都能改写它**；安全存储至少要求用户账户
已解锁且授予了访问权限。

注意检查点里**没有任何密钥材料**——它全部是公开元数据（revision、快照标识、链头摘要、
纪元）。把它放进安全存储不是为了保密，而是为了**完整性**。

`SecureCheckpointStore` 里「读不到」与「没有」被严格区分：`SecureStore::get` 的 `Err`
（凭据库锁定、访问被拒绝）原样上抛，**绝不**被当成「还没有检查点」。把两者混为一谈等于
给攻击者一条免费的回滚通道——锁住凭据库就能让设备接受任意旧状态。

两者不一致时**以安全存储为准并告警**。绝不能出现「SQLite 里的检查点更旧，于是把安全
存储里的降下来」这种逻辑——那等于给攻击者提供一条免费的回滚通道。

同样的分工也适用于成员链：事件正文存在 Backend（`ObjectKind::MembershipEvent`），
SQLite 的 `membership_events` / `membership_head` 两张表只保存「本机已经验证到哪儿了」
这个本地事实，**事件正文与签名刻意不落库**——复制一份进关系表就会出现两个可能不一致的
事实来源，而且会让人误以为可以「查表验签」。

`MembershipIndex::append_verified` 的名字就是它的契约：调用方必须先用
`verify_membership_chain` 验证过整条链才允许写入；这一层再加一道结构性防线——写入必须是
对当前链头的合法延伸（测试 `only_a_successor_of_the_current_head_can_be_appended`、
`appending_the_same_event_twice_is_idempotent`、
`a_malformed_event_is_rejected_before_touching_the_database`）。

### 6.6 `reset_trust_root` 的危险性与唯一合法使用场景

有两个「重置信任根」的入口，它们**必须成对调用**：

| 入口 | 清除的东西 |
|---|---|
| `MembershipIndex::reset_trust_root(workspace)` | 本机的成员事件索引与链头 |
| `CheckpointStore::reset(workspace)` | 本机的反回滚检查点 |

**调用之后，本设备会接受后端给出的任意状态**——包括一份精心构造的旧快照，以及攻击者
构造的、把自己设为管理员的 genesis。这不是「降低了一点安全性」，这是**完全放弃**了 M2
提供的两条核心保证。

**唯一合法使用场景：** 用户持恢复短语走
[§4.4](#44-灾难恢复所有设备都丢了) 的显式灾难恢复流程。并且必须：

1. 要求用户**交互确认**；
2. 两个入口**一起**调用——只重置一半会留下自相矛盾的本地状态；
3. 在下一次同步时用管理员签名的 invitation 或恢复包**重新建立**信任根。

**普通的同步失败、CAS 冲突、合并冲突、网络错误、验证失败都不是调用它的理由。**
验证失败恰恰说明有人在攻击，这时重置信任根等于直接投降。

实现里 `reset_trust_root` 会打一条 `tracing::warn!`：
「成员链信任根已被重置：下一次同步会接受任意 genesis，必须由恢复流程重新背书」。
测试 `reset_trust_root_clears_only_the_given_workspace` 确认它只影响给定工作区，
`only_an_explicit_reset_can_lower_the_trust_root` 确认没有别的路径能降低信任根。

---

## 7. 撤销之后应该做什么

撤销让被撤销设备失去**未来**的访问权，它不能收回**过去**已经交出去的字节。因此撤销
一台**可能已经泄露**的设备之后：

1. **假设所有旧纪元的秘密值都已泄露。** 到各自的签发方去轮换它们——重新生成 API token、
   重新签发证书、重置数据库口令。EnvSync 能保证新值只对剩余设备可见，它无法让已经离开
   进程的字节回来。
2. **检查该设备是否曾是管理员。** 如果是，它在被撤销前签发过的事件仍然是链上合法的
   历史，需要人工复核那段时间的成员变更（`MembershipIndex::events()` 按 sequence 列出
   全部事件索引）。
3. **不要**用 `reset_trust_root` 来「清理」——见 §6.6。
4. 撤销纯粹是**运维决定**而非泄露响应时（例如一台机器报废），第 1 条可以按秘密的敏感度
   分级处理，但至少要记录下「这些秘密曾经在那台机器上出现过」。
