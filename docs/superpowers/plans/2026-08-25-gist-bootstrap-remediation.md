# Gist 密封 Bundle 引导层修复 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 补全 Gist Bundle 的 Vault 对象闭包，并提供不会降低撤销语义的新设备/新纪元密钥引导层。

**Architecture:** 将 Vault Index CBOR 模型下沉至 `envsync-crypto`，让 backend 可验证完整闭包。Bundle 将 head Vault Index 中的成员事件与当前 KeyEnvelope 放入被 digest/签名绑定的受限 bootstrap 区，其余对象继续 AEAD 密封；core 以邀请或本地锚点验证 bootstrap 后，再只为同一 bundle 的常规解包提供临时验证器。

**Tech Stack:** Rust、canonical CBOR、Ed25519、HPKE、ChaCha20-Poly1305、Cargo workspace。

---

### Task 1: 共享 Vault Index 线格式

**Files:**
- Create: `crates/envsync-crypto/src/vault.rs`
- Modify: `crates/envsync-crypto/src/lib.rs`
- Modify: `crates/envsync-core/src/vault.rs`
- Test: `crates/envsync-crypto/src/vault.rs`

- [x] **Step 1: 迁移 schema 测试**

将现有 VaultIndex 的 canonical round-trip、秘密条数上限与未知格式拒绝测试移动到 crypto 层，
确保 `SecretRef`、`VaultIndex`、`VAULT_INDEX_FORMAT_VERSION` 与 `MAX_SECRETS` 行为不变。

- [x] **Step 2: 迁移实现并保留 core API**

在 `envsync_crypto::vault` 定义 `SecretRef`、`VaultIndex`、`referenced_objects()` 和受控的
`upsert`/`remove`；core `vault` 通过公开 re-export 保持现有调用点与下游测试的类型路径不变。

- [x] **Step 3: 验证迁移**

Run: `cargo test -p envsync-crypto -p envsync-core --lib`

Expected: PASS，Vault Index 字节格式与既有测试一致。

### Task 2: 先写 Gist bootstrap 与 Vault 闭包失败测试

**Files:**
- Modify: `crates/envsync-backend/tests/gist_bundle.rs`

- [x] **Step 1: Vault fixture**

构造 head metadata 指向的 VaultIndex、成员事件、当前设备 KeyEnvelope、密封秘密与恢复包，
并将其与 Snapshot/StateRoot/Blob 一起传给 `pack()`。

- [x] **Step 2: 闭包失败断言**

分别省略 VaultIndex、成员事件、KeyEnvelope、密封秘密和恢复包，断言 `pack()` 返回
`gist_bundle.incomplete_closure`，且展示错误不含任一遗漏对象 ID 或 Secret ID。

- [x] **Step 3: 引导安全断言**

断言 `inspect_bootstrap()` 无需 DataKey 即可读取成员事件与当前 KeyEnvelope；对 wire 扫描时
仍找不到 Vault Index、Secret ID、metadata、资源路径或资源正文；并断言 bootstrap 中只能
出现 `MembershipEvent` 与 `KeyEnvelope`。

- [x] **Step 4: 运行红灯测试**

Run: `cargo test -p envsync-backend --test gist_bundle`

Expected: FAIL，缺少 `inspect_bootstrap` 且 Vault 依赖尚未被检查。

### Task 3: 实现认证 bootstrap 与完整闭包

**Files:**
- Modify: `crates/envsync-backend/src/gist_bundle.rs`
- Modify: `crates/envsync-core/src/device_admin.rs`
- Modify: `crates/envsync-core/src/lib.rs`
- Modify: `docs/backends/gist.md`

- [x] **Step 1: 定义 outer bootstrap 线格式**

给 outer canonical array 增加 `[membership_records, envelope_records]` 字段。每条记录保留
`[kind, digest32, bytes]`，逐条校验 ObjectId、canonical CBOR 与允许的对象种类；bundle digest
覆盖该字段，签名继续覆盖 digest 与 signer。

- [x] **Step 2: 从 head VaultIndex 抽取 bootstrap**

将已验证的完整对象集按 ObjectId 排序；若 head snapshot 带 `envsync.vault.index`，解析共享
VaultIndex，验证其 workspace、成员链对象、当前 KeyEnvelope、每条密封秘密及恢复包均存在。
把仅 head 的 membership/envelope 记录移到 outer bootstrap，保留其余记录在密封 payload。

- [x] **Step 3: 合并时重新验证**

`unpack()` 在 digest/signature/AAD 检查后解密私有记录，与 bootstrap 合并并重新执行完整
Snapshot/Vault 闭包校验；任何重复或缺失均拒绝。`inspect_bootstrap()` 只返回标为未验证的
公开引导记录，不建立信任也不解密。

- [x] **Step 4: 用邀请锚定并临时使用候选密钥**

`verify_gist_bootstrap_for_invitation()` 必须以邀请 genesis、签发时成员链锚点、邀请签名和
本机收件人身份验证 bootstrap；`GistBootstrapTrust::unpack()` 消费临时 trust，并且仅在同一
bundle 的 `unpack()` 成功后才同时把已认证对象与当前 DataKey 交给后续加入/轮换流程。
已加入设备的轮换路径必须由 `verify_gist_bootstrap_for_checkpoint()` 以本地 checkpoint 的成员
链摘要、sequence 和最低纪元锚定；已撤销设备不得借旧 checkpoint 或残留信封重新取得新密钥。

- [x] **Step 5: 运行定向测试**

Run: `cargo fmt && cargo test -p envsync-backend --test gist_bundle && cargo clippy -p envsync-backend --all-targets -- -D warnings`

Expected: PASS。

### Task 4: 文档和全仓验证

**Files:**
- Modify: `docs/backends/gist.md`
- Modify: `docs/superpowers/plans/2026-07-24-envsync-m4-desktop-gist-plugins.md`

- [x] **Step 1: 记录信任边界**

明确 bootstrap 的公开字段、core 必须先用邀请/本地锚点验证成员链再打开信封，以及旧纪元
密钥绝不能作为当前 bundle 的解密回退。

- [x] **Step 2: 全仓验证**

Run: `cargo fmt --check && cargo test --workspace -q && cargo clippy --workspace --all-targets -- -D warnings && git diff --check`

Expected: 所有命令 exit 0。

- [x] **Step 3: 提交**

Run: `git add Cargo.toml Cargo.lock crates/envsync-crypto crates/envsync-core crates/envsync-backend docs && git commit -m "feat(backend): 添加可引导的密封 Gist bundle"`

Expected: 单个 Conventional Commit，包含格式、测试与文档。
