# EnvSync M2 Vault 与设备安全实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox
> (`- [ ]`) syntax for tracking.

**Goal:** 加入设备身份、成员签名链、端到端加密 Vault、恢复密钥、设备撤销、密钥轮换和
反回滚检查点，使普通后端无需被信任也能承载秘密。

**Architecture:** Workspace 有独立数据加密密钥；秘密值使用 AEAD sealed object 存储，
数据密钥通过 HPKE 分发给成员设备。成员事件构成签名链，设备仅接受从已信任 genesis
延伸的有效链；本地安全存储保存设备私钥和最近检查点。

**Tech Stack:** Rust stable、hpke、chacha20poly1305、ed25519-dalek、argon2、
zeroize、secrecy、rand_core、keyring、minicbor、proptest。

---

## 安全边界

- 后端、网络、其他已撤销设备均视为攻击者可控。
- 本地已解锁用户账户和运行中的 EnvSync 进程不在 M2 防护范围内。
- 不自创密码学原语；固定算法套件并提供测试向量。
- 错误、日志、panic、core dump fixture 均不得包含秘密明文。

## 文件结构

- `crates/envsync-crypto/`：算法套件、sealed object、HPKE envelope、恢复包。
- `crates/envsync-domain/src/membership.rs`：成员事件、角色、epoch、检查点。
- `crates/envsync-platform/src/secure_store.rs`：系统凭据库抽象。
- `crates/envsync-core/src/vault.rs`：Vault application service。
- `crates/envsync-core/src/membership.rs`：邀请、加入、撤销、轮换编排。

### Task 1: 建立 crypto crate 与固定测试向量

**Files:**

- Create: `crates/envsync-crypto/Cargo.toml`
- Create: `crates/envsync-crypto/src/lib.rs`
- Create: `crates/envsync-crypto/src/suite.rs`
- Create: `crates/envsync-crypto/tests/vectors.rs`
- Modify: `Cargo.toml`

- [ ] **Step 1: 写算法套件解析测试**

唯一 M2 suite 为 `ESV1_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519`；未知 suite 和
未知 sealed format version 均拒绝。

- [ ] **Step 2: 运行失败测试**

Run: `cargo test -p envsync-crypto --test vectors`
Expected: FAIL，package 或 `CryptoSuite` 不存在。

- [ ] **Step 3: 实现 suite 与敏感类型**

私钥、数据密钥和 plaintext wrapper 使用 `secrecy`，Drop 时 zeroize；不实现 Debug、
Display、Serialize。公开 key 和 ciphertext 可以序列化。

- [ ] **Step 4: 固定 deterministic decode vectors**

随机加密不可断言相同 ciphertext；测试固定 key/nonce 的底层向量只在 `tests` feature
开放。生产 API 内部生成 nonce，拒绝调用者传入。

- [ ] **Step 5: 验证并提交**

```bash
cargo test -p envsync-crypto --test vectors
git commit -am "feat(crypto): 建立版本化密码套件"
```

### Task 2: 设备身份与签名

**Files:**

- Create: `crates/envsync-crypto/src/device.rs`
- Create: `crates/envsync-domain/src/membership.rs`
- Test: `crates/envsync-crypto/tests/device_identity.rs`

- [ ] **Step 1: 写身份测试**

生成设备同时产生 X25519 HPKE key 和 Ed25519 signing key；`DeviceId` 由两个 public key
的域分隔摘要派生。修改任一 key 都改变 DeviceId。

- [ ] **Step 2: 写签名测试**

签名覆盖 domain、format version、workspace、payload digest。跨 workspace 重放、修改
payload、错误 signer 和非 canonical payload 均验证失败。

- [ ] **Step 3: 实现 key generation/sign/verify**

所有随机数来自 `OsRng`；签名前 canonical encode。verify 先检查长度和版本，再做密码学
验证，错误分类不泄露 key material。

- [ ] **Step 4: 验证并提交**

```bash
cargo test -p envsync-crypto --test device_identity
git commit -am "feat(crypto): 添加设备身份与签名"
```

### Task 3: 成员事件链

**Files:**

- Create: `crates/envsync-core/src/membership.rs`
- Create: `crates/envsync-storage/migrations/0003_membership.sql`
- Test: `crates/envsync-core/tests/membership_chain.rs`

- [ ] **Step 1: 写 genesis 与角色测试**

genesis 创建唯一 admin；Admin 可 AddMember、Promote、Revoke，Member 不能。事件包含
sequence、previous digest、epoch、actor、subject 和签名。

- [ ] **Step 2: 写攻击路径测试**

拒绝断链、分叉、重复 sequence、未来 epoch、已撤销 actor、最后一个 admin 被撤销和旧
事件重放。

- [ ] **Step 3: 实现纯验证器**

```rust
pub fn verify_membership_chain(
    genesis: &MembershipEvent,
    events: &[MembershipEvent],
) -> Result<MembershipState, MembershipError>;
```

验证器不读取网络或数据库；先做结构限制，再逐事件验签和授权。

- [ ] **Step 4: 持久化与提交**

成员对象保存到 Backend；SQLite 保存已验证链头和 epoch。事务提交后才更新本地 trusted
checkpoint。

```bash
cargo test -p envsync-core --test membership_chain
git commit -am "feat(core): 添加设备成员签名链"
```

### Task 4: Sealed Secret Object

**Files:**

- Create: `crates/envsync-crypto/src/sealed.rs`
- Test: `crates/envsync-crypto/tests/sealed_secret.rs`

- [ ] **Step 1: 写 round-trip 和篡改测试**

覆盖空值、二进制值、1 MiB 上限、AAD workspace/secret/version 绑定；翻转 nonce、
ciphertext、tag 或 AAD 均失败。

- [ ] **Step 2: 实现格式**

```text
version | suite | workspace_id | secret_id | key_epoch | nonce | ciphertext
```

AEAD AAD 是除 ciphertext 外的 canonical header。Secret ID 是逻辑标识，不由 plaintext
摘要生成，避免相等性泄露。

- [ ] **Step 3: 加入内存与日志测试**

错误实现 `Debug` 时只显示类型、版本和 opaque ID；tracing field 不接受 plaintext
wrapper。解密 buffer 在消费后 zeroize。

- [ ] **Step 4: 验证并提交**

```bash
cargo test -p envsync-crypto --test sealed_secret
git commit -am "feat(crypto): 添加密封秘密对象"
```

### Task 5: HPKE 设备 envelope 与 epoch 轮换

**Files:**

- Create: `crates/envsync-crypto/src/envelope.rs`
- Test: `crates/envsync-crypto/tests/device_envelope.rs`
- Test: `crates/envsync-core/tests/key_rotation.rs`

- [ ] **Step 1: 写 envelope 测试**

只有目标设备能打开 envelope；workspace、device、epoch 作为 info/AAD。交换两个设备的
envelope 或降级 epoch 均失败。

- [ ] **Step 2: 实现 envelope**

每个 active device 一个 envelope，内容为 Workspace Data Key 与 epoch。envelope 对象
签名后上传，成员链验证先于打开 envelope。

- [ ] **Step 3: 写撤销与轮换测试**

撤销设备使 epoch `n -> n+1`，为剩余设备产生新 envelope；新秘密只用新 key。旧对象按
lazy rewrap 策略在读取后重加密；已撤销设备无法读取新对象。

- [ ] **Step 4: 实现可恢复轮换 journal**

rotation 状态：prepared → envelopes_published → head_published → rewrapping → complete。
任一阶段中断可幂等恢复，不能让新头引用尚未发布的 envelope。

- [ ] **Step 5: 验证并提交**

```bash
cargo test -p envsync-crypto --test device_envelope
cargo test -p envsync-core --test key_rotation
git commit -am "feat(crypto): 实现设备密钥分发与轮换"
```

### Task 6: 系统安全存储

**Files:**

- Create: `crates/envsync-platform/src/secure_store.rs`
- Create: `crates/envsync-platform/src/secure_store/macos.rs`
- Create: `crates/envsync-platform/src/secure_store/windows.rs`
- Create: `crates/envsync-platform/src/secure_store/linux.rs`
- Test: `crates/envsync-platform/tests/secure_store_contract.rs`

- [ ] **Step 1: 定义 contract tests**

`put/get/delete`、覆盖、not-found、锁定凭据库和访问拒绝。service/account 名称包含
workspace 和 device，但不含 secret value。

- [ ] **Step 2: 实现平台后端**

macOS Keychain、Windows Credential Manager、Linux Secret Service。无可用安全存储时
返回 `SecureStoreUnavailable`；M2 不自动退化到明文文件。

- [ ] **Step 3: 添加 fake store**

仅 test feature 提供内存 fake；Drop zeroize values。生产构建不能选择 fake。

- [ ] **Step 4: 三平台验证与提交**

```bash
cargo test -p envsync-platform --test secure_store_contract
git commit -am "feat(platform): 接入系统安全存储"
```

### Task 7: Argon2id 恢复包

**Files:**

- Create: `crates/envsync-crypto/src/recovery.rs`
- Test: `crates/envsync-crypto/tests/recovery_package.rs`

- [ ] **Step 1: 写参数与 round-trip 测试**

恢复包记录 salt、Argon2id memory/time/parallelism、suite、nonce 和 ciphertext。参数低于
项目安全下限时拒绝创建；读取允许更高参数但有本机资源上限。

- [ ] **Step 2: 实现恢复包**

恢复短语由系统随机产生 128-bit entropy 并以校验编码展示一次；Argon2id 派生 KEK，
加密 recovery identity 和 workspace recovery material。

- [ ] **Step 3: 错误口令与资源耗尽测试**

错误口令只返回统一 authentication failure。畸形包不能要求超过 2 GiB 内存或无限迭代。

- [ ] **Step 4: 验证并提交**

```bash
cargo test -p envsync-crypto --test recovery_package
git commit -am "feat(crypto): 添加工作区恢复包"
```

### Task 8: Vault application service 与 CLI

**Files:**

- Create: `crates/envsync-core/src/vault.rs`
- Modify: `crates/envsync-cli/src/main.rs`
- Test: `crates/envsync-core/tests/vault_service.rs`
- Test: `crates/envsync-cli/tests/vault_cli.rs`

- [ ] **Step 1: 写服务测试**

create/set/get/list/delete secret；list 只返回 metadata。Snapshot 中只保存 SecretRef 和
sealed object ID，普通 Blob 扫描不得发现 plaintext。

- [ ] **Step 2: 实现 API**

`SecretValue` 只能从 stdin、环境变量名或交互式 hidden prompt 输入；CLI 参数禁止直接传值。
stdout 默认不显示 secret，`vault get --output stdout` 要求 TTY 确认或显式
`--allow-non-tty`。

- [ ] **Step 3: 新增命令**

`device init/list/invite/join/revoke`、`vault set/get/list/delete`、
`recovery create/restore`、`security checkpoint`。

- [ ] **Step 4: redaction golden tests**

将 canary secret 放入所有成功与失败路径，捕获 stdout/stderr/tracing/JSON，断言 canary
从不出现，只有显式 vault get 输出例外。

- [ ] **Step 5: 验证并提交**

```bash
cargo test -p envsync-core --test vault_service
cargo test -p envsync-cli --test vault_cli
git commit -am "feat(vault): 添加秘密与设备管理命令"
```

### Task 9: 反回滚检查点

**Files:**

- Create: `crates/envsync-core/src/checkpoint.rs`
- Create: `crates/envsync-storage/migrations/0004_checkpoints.sql`
- Test: `crates/envsync-core/tests/anti_rollback.rs`

- [ ] **Step 1: 写回滚攻击测试**

设备接受 revision 12 后，后端返回 revision 11、不同 revision 12、旧 membership head 或旧
key epoch 时全部阻塞。仅恢复流程可显式重置信任根。

- [ ] **Step 2: 实现 checkpoint**

安全存储保存 workspace 的最高 revision、Snapshot ID、membership digest、key epoch；
SQLite 保存审计副本。接受新头前检查单调性和链延续，应用完成后再推进 checkpoint。

- [ ] **Step 3: 克隆与灾难恢复测试**

新设备通过管理员签名 invitation 建立初始 checkpoint；恢复身份使用 recovery-signed
事件建立新 epoch，旧设备全部要求重新授权。

- [ ] **Step 4: 验证并提交**

```bash
cargo test -p envsync-core --test anti_rollback
git commit -am "feat(security): 阻止后端回滚攻击"
```

### Task 10: M2 安全验收、文档与 CI

**Files:**

- Create: `tests/e2e/vault_multi_device.rs`
- Create: `docs/security/vault-format.md`
- Create: `docs/security/device-membership.md`
- Create: `docs/security/recovery.md`
- Create: `docs/security/test-vectors/`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: 端到端攻击矩阵**

覆盖后端读权限、ciphertext 篡改、替换 envelope、撤销设备、旧 head、错误恢复口令、进程
中断轮换、日志 canary 和跨 workspace 重放。

- [ ] **Step 2: 文档格式与仪式**

记录 wire format、域分隔、算法 suite、参数、邀请/撤销/恢复操作、备份责任和威胁边界。
测试向量只含公开或固定测试 key。

- [ ] **Step 3: 完整验证**

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --doc
cargo audit
```

Expected: 所有命令 exit 0；三平台 CI 和安全存储集成测试成功。

- [ ] **Step 4: 提交**

```bash
git add docs tests .github
git commit -m "test: 完成 M2 设备与 Vault 安全验收"
```

## M2 完成定义

- 后端泄露不会暴露 Vault plaintext。
- 已撤销设备无法解密新 epoch 内容。
- membership chain、envelope、sealed object 和 checkpoint 有攻击路径测试。
- 系统安全存储不可用时安全失败，不写明文 fallback。
- 恢复、轮换和中断恢复均通过双设备 E2E。
