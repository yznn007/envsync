//! M3 任务 8：Agent Bundle 的 manifest 校验、签名覆盖范围、隔离状态机与 quarantine。
//!
//! 这份测试的组织方式对应四条安全主张：
//!
//! 1. **manifest 是不可信输入。** 每一条拒绝规则各有一个测试，且都断言稳定错误码
//!    ——错误码是对外契约，改文案可以，改码不行。
//! 2. **签名覆盖 canonical manifest 与全部 file digest。** 改任意一个文件摘要都必须
//!    让验签失败并进入 `blocked`；未知与已撤销 signer 同样进入 `blocked`。
//! 3. **状态机只允许逐级前进，但任何状态都能被阻断或撤销。**
//! 4. **落盘先失能。** quarantine 里的文件不带任何 execute bit，写入不跟随链接。

use std::collections::{BTreeMap, BTreeSet};

use envsync_core::bundles::{
    approve, block, enable, inspect, publisher_fingerprint, publisher_namespace, review_update,
    revoke, strip_execute_bits, verify_bundle_signature, ApprovalGap, BundleApproval,
    BundleContext, BundleError, PublisherRegistry, QuarantineRoot, BUNDLE_SIGNATURE_DOMAIN,
};
use envsync_crypto::device::DeviceKeypair;
use envsync_domain::agent_bundle::{
    bundle_file_digest, BundleEntryKind, BundleFileEntry, BundleId, BundleManifest,
    BundleManifestError, BundleSignature, BundleState, BUNDLE_MANIFEST_FORMAT_VERSION,
    BUNDLE_SIGNATURE_FORMAT_VERSION, MAX_BUNDLE_TOTAL_BYTES,
};
use envsync_domain::id::Digest32;
use envsync_domain::profile::{Arch, DeviceProfile, Os};
use envsync_policy::{Decision, FactPredicate, MatchExpr, PolicySet, ResourceKind, Rule, RuleId};
use envsync_storage::bundles::BundleRecord;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// 夹具
// ---------------------------------------------------------------------------

const NOW: u64 = 1_700_000_000_000;

/// 一份最小但完整的载荷。
fn payload() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        (
            "agents/main.md".to_owned(),
            b"---\nname: main\n---\n\xe6\x8c\x87\xe4\xbb\xa4\n".to_vec(),
        ),
        ("skills/pdf/SKILL.md".to_owned(), b"# PDF\n".to_vec()),
    ])
}

/// 由载荷推出的 manifest。
fn manifest_for(publisher_key: [u8; 32], contents: &BTreeMap<String, Vec<u8>>) -> BundleManifest {
    BundleManifest {
        format_version: BUNDLE_MANIFEST_FORMAT_VERSION,
        id: BundleId::parse("com.example.my-agent").expect("固定标识合法"),
        version: "1.2.3".to_owned(),
        publisher_key,
        files: contents
            .iter()
            .map(|(path, bytes)| (path.clone(), bundle_file_digest(bytes)))
            .collect(),
        entrypoints: BTreeMap::from([("agent".to_owned(), "agents/main.md".to_owned())]),
        declared_capabilities: BTreeSet::from(["agents".to_owned(), "skills".to_owned()]),
        secret_refs: BTreeSet::from(["secret://github/token".to_owned()]),
        target_tools: BTreeSet::from(["claude".to_owned()]),
        min_envsync_version: "0.1.0".to_owned(),
        total_bytes: contents.values().map(|bytes| bytes.len() as u64).sum(),
    }
}

/// 由载荷推出的条目清单。
fn entries_for(contents: &BTreeMap<String, Vec<u8>>) -> Vec<BundleFileEntry> {
    contents
        .iter()
        .map(|(path, bytes)| BundleFileEntry {
            path: path.clone(),
            kind: BundleEntryKind::File,
            digest: bundle_file_digest(bytes),
            bytes: bytes.len() as u64,
        })
        .collect()
}

/// 一个发布者：密钥对 + 只信任它的注册表。
struct Publisher {
    keypair: DeviceKeypair,
}

impl Publisher {
    fn new() -> Self {
        Publisher {
            keypair: DeviceKeypair::generate().expect("生成密钥对"),
        }
    }

    fn key(&self) -> [u8; 32] {
        self.keypair.public().ed25519
    }

    fn sign(&self, manifest: &BundleManifest) -> BundleSignature {
        let signature = self
            .keypair
            .sign(
                BUNDLE_SIGNATURE_DOMAIN,
                publisher_namespace(),
                &manifest.signing_payload(),
            )
            .expect("签名成功");
        BundleSignature {
            format_version: BUNDLE_SIGNATURE_FORMAT_VERSION,
            bundle: manifest.id.clone(),
            manifest_digest: manifest.manifest_digest(),
            signature: signature.as_bytes().to_vec(),
        }
    }

    fn registry(&self) -> PublisherRegistry {
        let mut registry = PublisherRegistry::new();
        registry.trust(self.key(), "example.com");
        registry
    }
}

fn profile() -> DeviceProfile {
    DeviceProfile::new(Os::Linux, Arch::X86_64)
}

fn record(manifest: &BundleManifest, state: BundleState) -> BundleRecord {
    BundleRecord {
        bundle: manifest.id.clone(),
        version: manifest.version.clone(),
        manifest_digest: manifest.manifest_digest(),
        publisher_key: manifest.publisher_key,
        state,
        approved_capabilities: BTreeSet::new(),
        approved_at_unix_ms: None,
        blocked_reason: None,
        updated_at_unix_ms: NOW,
    }
}

/// 一个确认过的上下文：内建策略对 Agent Bundle 一律要求确认。
struct Fixture {
    policy: PolicySet,
    profile: DeviceProfile,
    publishers: PublisherRegistry,
}

impl Fixture {
    fn new(publishers: PublisherRegistry) -> Self {
        Fixture {
            policy: PolicySet::builtin_defaults(),
            profile: profile(),
            publishers,
        }
    }

    fn with_policy(mut self, policy: PolicySet) -> Self {
        self.policy = policy;
        self
    }

    fn ctx(&self, confirmed: bool) -> BundleContext<'_> {
        BundleContext {
            policy: &self.policy,
            profile: &self.profile,
            profile_name: "work",
            publishers: &self.publishers,
            confirmed,
        }
    }
}

/// 走完 `downloaded → inspected → approved`，返回记录与批准。
fn approved_state(
    fixture: &Fixture,
    manifest: &BundleManifest,
    signature: &BundleSignature,
    contents: &BTreeMap<String, Vec<u8>>,
) -> (BundleRecord, BundleApproval) {
    let downloaded = record(manifest, BundleState::Downloaded);
    let inspected = inspect(
        &downloaded,
        manifest,
        signature,
        &entries_for(contents),
        &fixture.ctx(true),
        NOW,
    )
    .expect("inspect 成功");
    assert_eq!(inspected.to, BundleState::Inspected);
    let (approved, approval) =
        approve(&inspected.record, manifest, &fixture.ctx(true), NOW).expect("approve 成功");
    assert_eq!(approved.to, BundleState::Approved);
    (approved.record, approval)
}

// ---------------------------------------------------------------------------
// manifest 拒绝路径：每条一个测试
// ---------------------------------------------------------------------------

/// 把 manifest 的 files 换成一条给定路径，用来逐条测试路径规则。
fn manifest_with_path(path: &str) -> BundleManifest {
    let contents = BTreeMap::from([(path.to_owned(), b"x".to_vec())]);
    let mut manifest = manifest_for([3u8; 32], &contents);
    manifest.entrypoints = BTreeMap::new();
    manifest
}

#[test]
fn rejects_parent_directory_traversal() {
    let error = manifest_with_path("../../etc/passwd")
        .validate()
        .expect_err("必须拒绝");
    assert_eq!(error.code(), "bundle.invalid_path");
}

#[test]
fn rejects_absolute_paths() {
    let error = manifest_with_path("/etc/passwd")
        .validate()
        .expect_err("必须拒绝");
    assert_eq!(error.code(), "bundle.invalid_path");
}

#[test]
fn rejects_windows_drive_letters() {
    let error = manifest_with_path("C:/Windows/system32/x.dll")
        .validate()
        .expect_err("必须拒绝");
    assert_eq!(error.code(), "bundle.invalid_path");
}

#[test]
fn rejects_unc_paths() {
    let error = manifest_with_path("\\\\attacker\\share\\payload.md")
        .validate()
        .expect_err("必须拒绝");
    assert_eq!(error.code(), "bundle.invalid_path");
}

#[test]
fn rejects_case_folded_duplicate_paths() {
    let contents = BTreeMap::from([
        ("agents/Main.md".to_owned(), b"a".to_vec()),
        ("agents/main.md".to_owned(), b"b".to_vec()),
    ]);
    let mut manifest = manifest_for([3u8; 32], &contents);
    manifest.entrypoints = BTreeMap::new();
    let error = manifest.validate().expect_err("必须拒绝");
    assert_eq!(error.code(), "bundle.duplicate_path");
}

#[test]
fn rejects_symlink_entries_in_the_payload() {
    let contents = payload();
    let manifest = manifest_for([3u8; 32], &contents);
    let mut entries = entries_for(&contents);
    entries[0].kind = BundleEntryKind::Symlink;
    let error = manifest.check_payload(&entries).expect_err("必须拒绝");
    assert_eq!(error.code(), "bundle.non_regular_entry");
}

#[test]
fn rejects_files_not_declared_in_the_manifest() {
    let contents = payload();
    let manifest = manifest_for([3u8; 32], &contents);
    let mut entries = entries_for(&contents);
    entries.push(BundleFileEntry {
        path: "hooks/post-install.sh".to_owned(),
        kind: BundleEntryKind::File,
        digest: bundle_file_digest(b"#!/bin/sh\n"),
        bytes: 10,
    });
    let error = manifest.check_payload(&entries).expect_err("必须拒绝");
    assert_eq!(error.code(), "bundle.undeclared_file");
}

#[test]
fn rejects_bundles_larger_than_ten_mebibytes() {
    let contents = payload();
    let mut manifest = manifest_for([3u8; 32], &contents);
    manifest.total_bytes = MAX_BUNDLE_TOTAL_BYTES + 1;
    let error = manifest.validate().expect_err("必须拒绝");
    assert_eq!(error.code(), "bundle.too_large");
}

#[test]
fn rejects_empty_bundle_ids() {
    let error = BundleId::parse("").expect_err("必须拒绝");
    assert_eq!(error.code(), "bundle.invalid_id");
    // 单段标识同样不是反向域名。
    assert!(BundleId::parse("myagent").is_err());
}

#[test]
fn rejects_non_semver_versions() {
    let contents = payload();
    let mut manifest = manifest_for([3u8; 32], &contents);
    manifest.version = "v1.2".to_owned();
    let error = manifest.validate().expect_err("必须拒绝");
    assert_eq!(error.code(), "bundle.invalid_semver");
}

#[test]
fn rejects_secret_refs_that_look_like_real_credentials() {
    let contents = payload();
    let mut manifest = manifest_for([3u8; 32], &contents);
    manifest.secret_refs = BTreeSet::from(["ghp_0123456789abcdefghijKLMNOP".to_owned()]);
    let error = manifest.validate().expect_err("必须拒绝");
    assert_eq!(error.code(), "bundle.secret_ref_credential");

    // 加上前缀也救不了：`secret://` 后面依然是一枚 token。
    let mut manifest = manifest_for([3u8; 32], &contents);
    manifest.secret_refs = BTreeSet::from(["secret://ghp_0123456789abcdefghij".to_owned()]);
    assert_eq!(
        manifest.validate().expect_err("必须拒绝").code(),
        "bundle.secret_ref_credential"
    );

    // 非 `secret://` 形式的普通字符串报的是另一条码。
    let mut manifest = manifest_for([3u8; 32], &contents);
    manifest.secret_refs = BTreeSet::from(["github/token".to_owned()]);
    assert_eq!(
        manifest.validate().expect_err("必须拒绝").code(),
        "bundle.secret_ref_not_reference"
    );
}

#[test]
fn rejects_entrypoints_pointing_at_undeclared_files() {
    let contents = payload();
    let mut manifest = manifest_for([3u8; 32], &contents);
    manifest
        .entrypoints
        .insert("extra".to_owned(), "agents/missing.md".to_owned());
    assert_eq!(
        manifest.validate().expect_err("必须拒绝").code(),
        "bundle.dangling_entrypoint"
    );
}

#[test]
fn rejects_unknown_target_tools() {
    let contents = payload();
    let mut manifest = manifest_for([3u8; 32], &contents);
    manifest.target_tools = BTreeSet::from(["evil-tool".to_owned()]);
    assert_eq!(
        manifest.validate().expect_err("必须拒绝").code(),
        "bundle.unknown_target_tool"
    );
}

// ---------------------------------------------------------------------------
// 签名覆盖范围
// ---------------------------------------------------------------------------

#[test]
fn a_valid_signature_verifies() {
    let publisher = Publisher::new();
    let contents = payload();
    let manifest = manifest_for(publisher.key(), &contents);
    let signature = publisher.sign(&manifest);
    verify_bundle_signature(&manifest, &signature, &publisher.registry()).expect("验签通过");
}

#[test]
fn changing_any_file_digest_breaks_the_signature() {
    let publisher = Publisher::new();
    let mut contents = payload();
    let manifest = manifest_for(publisher.key(), &contents);
    let signature = publisher.sign(&manifest);

    // 篡改一个文件的内容并重算 manifest：签名覆盖了 files_digest，因此必然失配。
    contents.insert("skills/pdf/SKILL.md".to_owned(), b"# PDF (evil)\n".to_vec());
    let tampered = manifest_for(publisher.key(), &contents);
    assert_ne!(tampered.files_digest(), manifest.files_digest());

    let error = verify_bundle_signature(&tampered, &signature, &publisher.registry())
        .expect_err("必须失败");
    // 签名对象里的 manifest 摘要先对不上，形状检查就已经拦住了。
    assert_eq!(error.code(), "bundle.signature_mismatch");

    // 即便攻击者顺手把签名对象里的摘要改成新的，曲线验签仍然失败。
    let forged = BundleSignature {
        manifest_digest: tampered.manifest_digest(),
        ..signature
    };
    assert_eq!(
        verify_bundle_signature(&tampered, &forged, &publisher.registry())
            .expect_err("必须失败")
            .code(),
        "bundle.crypto"
    );
}

#[test]
fn a_signature_cannot_be_replayed_onto_another_bundle() {
    let publisher = Publisher::new();
    let contents = payload();
    let manifest = manifest_for(publisher.key(), &contents);
    let signature = publisher.sign(&manifest);

    let mut other = manifest.clone();
    other.id = BundleId::parse("com.example.other-agent").expect("固定标识合法");
    let replayed = BundleSignature {
        bundle: other.id.clone(),
        manifest_digest: other.manifest_digest(),
        ..signature
    };
    assert_eq!(
        verify_bundle_signature(&other, &replayed, &publisher.registry())
            .expect_err("必须失败")
            .code(),
        "bundle.crypto"
    );
}

#[test]
fn an_unknown_signer_moves_the_bundle_to_blocked() {
    let publisher = Publisher::new();
    let contents = payload();
    let manifest = manifest_for(publisher.key(), &contents);
    let signature = publisher.sign(&manifest);

    // 空注册表：这把公钥没人登记过。
    let fixture = Fixture::new(PublisherRegistry::new());
    let transition = inspect(
        &record(&manifest, BundleState::Downloaded),
        &manifest,
        &signature,
        &entries_for(&contents),
        &fixture.ctx(true),
        NOW,
    )
    .expect("迁移本身成功");
    assert_eq!(transition.to, BundleState::Blocked);
    assert_eq!(
        transition.record.blocked_reason.as_deref(),
        Some("发布者公钥未登记在信任名单中")
    );
}

#[test]
fn a_revoked_signer_moves_the_bundle_to_blocked() {
    let publisher = Publisher::new();
    let contents = payload();
    let manifest = manifest_for(publisher.key(), &contents);
    let signature = publisher.sign(&manifest);

    let mut registry = publisher.registry();
    registry.revoke(publisher.key());
    let fixture = Fixture::new(registry);
    let transition = inspect(
        &record(&manifest, BundleState::Downloaded),
        &manifest,
        &signature,
        &entries_for(&contents),
        &fixture.ctx(true),
        NOW,
    )
    .expect("迁移本身成功");
    assert_eq!(transition.to, BundleState::Blocked);
    assert_eq!(
        transition.record.blocked_reason.as_deref(),
        Some("发布者公钥已被撤销")
    );
}

#[test]
fn revoking_the_signer_after_approval_blocks_enabling() {
    let publisher = Publisher::new();
    let contents = payload();
    let manifest = manifest_for(publisher.key(), &contents);
    let signature = publisher.sign(&manifest);

    let fixture = Fixture::new(publisher.registry());
    let (approved, approval) = approved_state(&fixture, &manifest, &signature, &contents);

    // 批准之后、启用之前，发布者被撤销。
    let mut registry = publisher.registry();
    registry.revoke(publisher.key());
    let revoked_fixture = Fixture::new(registry);
    let transition = enable(
        &approved,
        &manifest,
        &approval,
        &revoked_fixture.ctx(true),
        NOW,
    )
    .expect("迁移本身成功");
    assert_eq!(transition.to, BundleState::Blocked);
}

// ---------------------------------------------------------------------------
// 状态机
// ---------------------------------------------------------------------------

#[test]
fn the_happy_path_walks_one_step_at_a_time() {
    let publisher = Publisher::new();
    let contents = payload();
    let manifest = manifest_for(publisher.key(), &contents);
    let signature = publisher.sign(&manifest);
    let fixture = Fixture::new(publisher.registry());

    let (approved, approval) = approved_state(&fixture, &manifest, &signature, &contents);
    assert_eq!(
        approved.approved_capabilities,
        manifest.declared_capabilities
    );
    assert_eq!(approval.profile, "work");
    assert_eq!(approval.signer, publisher.key());

    let enabled =
        enable(&approved, &manifest, &approval, &fixture.ctx(true), NOW).expect("enable 成功");
    assert_eq!(enabled.to, BundleState::Enabled);
    assert!(enabled.record.is_active());
}

#[test]
fn skipping_a_step_is_rejected() {
    let publisher = Publisher::new();
    let contents = payload();
    let manifest = manifest_for(publisher.key(), &contents);
    let fixture = Fixture::new(publisher.registry());

    let downloaded = record(&manifest, BundleState::Downloaded);
    let approval = BundleApproval {
        bundle: manifest.id.clone(),
        manifest_digest: manifest.manifest_digest(),
        capabilities: manifest.declared_capabilities.clone(),
        profile: "work".to_owned(),
        signer: manifest.publisher_key,
        approved_at_unix_ms: NOW,
    };
    let error =
        enable(&downloaded, &manifest, &approval, &fixture.ctx(true), NOW).expect_err("必须拒绝");
    assert_eq!(error.code(), "bundle.illegal_transition");
}

#[test]
fn every_state_can_be_blocked_and_revoked() {
    let publisher = Publisher::new();
    let contents = payload();
    let manifest = manifest_for(publisher.key(), &contents);
    let fixture = Fixture::new(publisher.registry());

    for state in BundleState::ALL {
        let current = record(&manifest, state);
        if state != BundleState::Blocked && state != BundleState::Revoked {
            let blocked =
                block(&current, "手工阻断", &fixture.ctx(false), NOW).expect("block 成功");
            assert_eq!(blocked.to, BundleState::Blocked);
            assert_eq!(blocked.record.blocked_reason.as_deref(), Some("手工阻断"));
        }
        if state != BundleState::Revoked {
            let revoked =
                revoke(&current, "手工撤销", &fixture.ctx(false), NOW).expect("revoke 成功");
            assert_eq!(revoked.to, BundleState::Revoked);
        }
    }

    // `revoked` 是吸收态：没有任何出边。
    let revoked = record(&manifest, BundleState::Revoked);
    assert!(block(&revoked, "x", &fixture.ctx(false), NOW).is_err());
    assert!(revoke(&revoked, "x", &fixture.ctx(false), NOW).is_err());
}

#[test]
fn blocking_is_not_subject_to_policy_denial() {
    // 一条把 Agent Bundle 全部拒绝的策略：它必须挡住前进，但**不能**挡住阻断。
    let deny_all = PolicySet::from_rules(vec![Rule::new(
        RuleId::parse("test.deny-all-bundles").expect("规则标识合法"),
        Decision::Deny,
        MatchExpr::Leaf(FactPredicate::ResourceKind(
            [ResourceKind::AgentBundle].into_iter().collect(),
        )),
    )])
    .expect("策略集自洽");

    let publisher = Publisher::new();
    let contents = payload();
    let manifest = manifest_for(publisher.key(), &contents);
    let signature = publisher.sign(&manifest);
    let fixture = Fixture::new(publisher.registry()).with_policy(deny_all);

    let error = inspect(
        &record(&manifest, BundleState::Downloaded),
        &manifest,
        &signature,
        &entries_for(&contents),
        &fixture.ctx(true),
        NOW,
    )
    .expect_err("前进必须被拒绝");
    assert_eq!(error.code(), "bundle.policy_denied");

    // 同一条策略下，阻断照常可用——安全动作不需要许可。
    let blocked = block(
        &record(&manifest, BundleState::Enabled),
        "策略之外的止损",
        &fixture.ctx(false),
        NOW,
    )
    .expect("阻断必须成功");
    assert_eq!(blocked.to, BundleState::Blocked);
    // 策略仍然被求值并记录下来，只是不被执行。
    assert_eq!(blocked.outcome.decision, Decision::Deny);
}

#[test]
fn enabling_without_confirmation_is_refused() {
    let publisher = Publisher::new();
    let contents = payload();
    let manifest = manifest_for(publisher.key(), &contents);
    let signature = publisher.sign(&manifest);
    let fixture = Fixture::new(publisher.registry());
    let (approved, approval) = approved_state(&fixture, &manifest, &signature, &contents);

    let error = enable(&approved, &manifest, &approval, &fixture.ctx(false), NOW)
        .expect_err("必须要求确认");
    assert_eq!(error.code(), "bundle.confirmation_required");
    // 内建规则的标识必须出现在解释里，用户才知道是谁要求的确认。
    match error {
        BundleError::ConfirmationRequired { explanation, .. } => assert!(
            explanation.contains("builtin.agent-bundle.enable-requires-confirmation"),
            "解释里应当出现内建规则标识：{explanation}"
        ),
        other => panic!("错误类型不符：{other:?}"),
    }
}

#[test]
fn an_unsigned_bundle_is_denied_by_the_builtin_policy() {
    // signer 缺席时内建策略 `builtin.unsigned-active-content-denied` 直接拒绝。
    // 这里用一个被 block 过、随后被强行放回 downloaded 的记录来触发「有 manifest
    // 但没有可信 signer」的前进尝试。
    let publisher = Publisher::new();
    let contents = payload();
    let manifest = manifest_for(publisher.key(), &contents);
    let signature = publisher.sign(&manifest);
    let fixture = Fixture::new(PublisherRegistry::new());

    let transition = inspect(
        &record(&manifest, BundleState::Downloaded),
        &manifest,
        &signature,
        &entries_for(&contents),
        &fixture.ctx(true),
        NOW,
    )
    .expect("迁移成功");
    // 没有可信 signer 时不会前进到 inspected，而是进 blocked。
    assert_eq!(transition.to, BundleState::Blocked);
    assert_eq!(transition.outcome.decision, Decision::Deny);
    assert!(transition
        .outcome
        .explanation
        .contains("builtin.unsigned-active-content-denied"));
}

// ---------------------------------------------------------------------------
// 批准四元组与能力扩张
// ---------------------------------------------------------------------------

#[test]
fn capability_expansion_requires_a_fresh_review() {
    let publisher = Publisher::new();
    let contents = payload();
    let manifest = manifest_for(publisher.key(), &contents);
    let signature = publisher.sign(&manifest);
    let fixture = Fixture::new(publisher.registry());
    let (_, approval) = approved_state(&fixture, &manifest, &signature, &contents);

    // 新版本多声明了一项能力。
    let mut next = manifest.clone();
    next.version = "1.3.0".to_owned();
    next.declared_capabilities.insert("mcp.stdio".to_owned());

    let review = review_update(&approval, &next);
    assert!(review.is_capability_expansion());
    assert!(review.requires_reapproval());
    assert_eq!(
        review.added_capabilities,
        BTreeSet::from(["mcp.stdio".to_owned()])
    );

    // 老批准不会自动继承到新版本：启用直接失败。
    let approved = BundleRecord {
        state: BundleState::Approved,
        approved_capabilities: approval.capabilities.clone(),
        approved_at_unix_ms: Some(NOW),
        manifest_digest: next.manifest_digest(),
        version: next.version.clone(),
        ..record(&manifest, BundleState::Approved)
    };
    let error = enable(&approved, &next, &approval, &fixture.ctx(true), NOW).expect_err("必须拒绝");
    assert_eq!(error.code(), "bundle.approval_stale");
    match error {
        BundleError::ApprovalStale { gap, .. } => {
            assert_eq!(gap.code(), "approval.capabilities_expanded");
        }
        other => panic!("错误类型不符：{other:?}"),
    }
}

#[test]
fn an_approval_does_not_carry_across_profiles_or_signers() {
    let publisher = Publisher::new();
    let contents = payload();
    let manifest = manifest_for(publisher.key(), &contents);
    let approval = BundleApproval {
        bundle: manifest.id.clone(),
        manifest_digest: manifest.manifest_digest(),
        capabilities: manifest.declared_capabilities.clone(),
        profile: "work".to_owned(),
        signer: manifest.publisher_key,
        approved_at_unix_ms: NOW,
    };

    // 同一份内容，换一个 Profile。
    assert!(matches!(
        approval.check_covers(&manifest, "personal"),
        Err(ApprovalGap::ProfileChanged { .. })
    ));

    // 同一个 Profile，换一个发布者。
    let other = Publisher::new();
    let mut resigned = manifest.clone();
    resigned.publisher_key = other.key();
    assert!(matches!(
        approval.check_covers(&resigned, "work"),
        Err(ApprovalGap::SignerChanged)
    ));

    // 能力没变但内容变了：仍然要重新审核。
    let mut edited = manifest.clone();
    edited.version = "1.2.4".to_owned();
    assert!(matches!(
        approval.check_covers(&edited, "work"),
        Err(ApprovalGap::DigestChanged)
    ));

    // 原样比对通过。
    assert!(approval.check_covers(&manifest, "work").is_ok());
}

#[test]
fn removing_capabilities_does_not_require_reapproval_by_itself() {
    let publisher = Publisher::new();
    let contents = payload();
    let manifest = manifest_for(publisher.key(), &contents);
    let approval = BundleApproval {
        bundle: manifest.id.clone(),
        manifest_digest: manifest.manifest_digest(),
        capabilities: manifest.declared_capabilities.clone(),
        profile: "work".to_owned(),
        signer: manifest.publisher_key,
        approved_at_unix_ms: NOW,
    };
    let mut next = manifest.clone();
    next.declared_capabilities.remove("skills");

    let review = review_update(&approval, &next);
    assert!(!review.is_capability_expansion());
    assert_eq!(
        review.removed_capabilities,
        BTreeSet::from(["skills".to_owned()])
    );
    // 但内容摘要变了，仍然要重新审核内容本身。
    assert!(review.digest_changed);
    assert!(review.requires_reapproval());
}

// ---------------------------------------------------------------------------
// quarantine
// ---------------------------------------------------------------------------

#[test]
fn execute_bits_are_stripped_from_the_requested_mode() {
    assert_eq!(strip_execute_bits(0o755), 0o644);
    assert_eq!(strip_execute_bits(0o111), 0);
}

#[test]
fn staged_files_are_never_executable() {
    let dir = TempDir::new().expect("临时目录");
    let root = QuarantineRoot::open(dir.path().join("quarantine")).expect("打开 quarantine 根");
    let contents = payload();
    let manifest = manifest_for([5u8; 32], &contents);

    let staged = root.stage(&manifest, &contents).expect("解包成功");
    assert_eq!(staged.entries.len(), contents.len());
    assert_eq!(staged.files().len(), contents.len());

    for (path, bytes) in &contents {
        let target = staged.root.join(path);
        let meta = std::fs::symlink_metadata(&target).expect("条目存在");
        assert!(meta.is_file(), "{path} 应当是普通文件");
        assert_eq!(std::fs::read(&target).expect("读回"), *bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                meta.permissions().mode() & 0o111,
                0,
                "{path} 不允许带任何 execute bit"
            );
        }
    }
}

#[test]
fn staging_refuses_to_follow_a_symlinked_directory() {
    let dir = TempDir::new().expect("临时目录");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&outside).expect("创建目标目录");
    let quarantine = dir.path().join("quarantine");
    let root = QuarantineRoot::open(&quarantine).expect("打开 quarantine 根");

    let contents = payload();
    let manifest = manifest_for([5u8; 32], &contents);

    // 攻击者把 `<quarantine>/<bundle-id>` 事先做成一条指向别处的符号链接。
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, quarantine.join(manifest.id.as_str()))
            .expect("创建符号链接");
        let error = root.stage(&manifest, &contents).expect_err("必须拒绝");
        assert_eq!(error.code(), "bundle.unsafe_quarantine_path");
        // 链接目标里什么都没写进去。
        assert_eq!(
            std::fs::read_dir(&outside).expect("读取目标目录").count(),
            0
        );
    }
    #[cfg(not(unix))]
    {
        let _ = (root, contents, manifest, outside);
    }
}

#[test]
fn staging_writes_nothing_when_the_payload_does_not_match() {
    let dir = TempDir::new().expect("临时目录");
    let quarantine = dir.path().join("quarantine");
    let root = QuarantineRoot::open(&quarantine).expect("打开 quarantine 根");

    let contents = payload();
    let manifest = manifest_for([5u8; 32], &contents);

    // 载荷里多出一个 manifest 没声明的文件。
    let mut tampered = contents.clone();
    tampered.insert("hooks/post-install.sh".to_owned(), b"#!/bin/sh\n".to_vec());
    let error = root.stage(&manifest, &tampered).expect_err("必须拒绝");
    assert_eq!(error.code(), "bundle.undeclared_file");

    // 校验发生在写入之前：目录连建都没建。
    assert!(!root
        .bundle_dir(&manifest.id, manifest.manifest_digest())
        .exists());
}

#[test]
fn staging_the_same_version_twice_is_refused() {
    let dir = TempDir::new().expect("临时目录");
    let root = QuarantineRoot::open(dir.path().join("quarantine")).expect("打开 quarantine 根");
    let contents = payload();
    let manifest = manifest_for([5u8; 32], &contents);

    root.stage(&manifest, &contents).expect("首次解包成功");
    let error = root.stage(&manifest, &contents).expect_err("必须拒绝");
    assert_eq!(error.code(), "bundle.already_staged");

    // 清理之后可以重来。
    assert!(root
        .purge(&manifest.id, manifest.manifest_digest())
        .expect("清理"));
    root.stage(&manifest, &contents).expect("再次解包成功");
}

#[test]
fn two_versions_of_the_same_bundle_live_side_by_side() {
    let dir = TempDir::new().expect("临时目录");
    let root = QuarantineRoot::open(dir.path().join("quarantine")).expect("打开 quarantine 根");
    let contents = payload();
    let v1 = manifest_for([5u8; 32], &contents);
    let mut v2 = v1.clone();
    v2.version = "1.3.0".to_owned();

    let first = root.stage(&v1, &contents).expect("解包 v1");
    let second = root.stage(&v2, &contents).expect("解包 v2");
    assert_ne!(first.root, second.root, "不同版本必须各占一个目录");
    assert!(first.root.exists() && second.root.exists());
}

#[test]
fn publisher_fingerprints_are_stable_and_key_specific() {
    let publisher = Publisher::new();
    let first = publisher_fingerprint(&publisher.key());
    assert_eq!(first, publisher_fingerprint(&publisher.key()));
    assert_ne!(first, publisher_fingerprint(&Publisher::new().key()));
}

#[test]
fn a_manifest_digest_covers_every_field() {
    let contents = payload();
    let base = manifest_for([5u8; 32], &contents);
    let mut seen = BTreeSet::new();
    seen.insert(base.manifest_digest());

    let mut variants = Vec::new();
    let mut changed = base.clone();
    changed.version = "9.9.9".to_owned();
    variants.push(changed);
    let mut changed = base.clone();
    changed.publisher_key = [6u8; 32];
    variants.push(changed);
    let mut changed = base.clone();
    changed.min_envsync_version = "0.2.0".to_owned();
    variants.push(changed);
    let mut changed = base.clone();
    changed.total_bytes += 1;
    variants.push(changed);
    let mut changed = base.clone();
    changed.declared_capabilities.insert("mcp.stdio".to_owned());
    variants.push(changed);
    let mut changed = base.clone();
    changed
        .files
        .insert("agents/main.md".to_owned(), Digest32::ZERO);
    variants.push(changed);

    for variant in variants {
        assert!(
            seen.insert(variant.manifest_digest()),
            "改动任意字段都必须改变 manifest 摘要"
        );
    }
}

#[test]
fn a_manifest_round_trips_through_canonical_cbor() {
    use envsync_domain::cbor::CborCodec;
    let contents = payload();
    let manifest = manifest_for([5u8; 32], &contents);
    let bytes = manifest.to_canonical_vec();
    assert_eq!(
        BundleManifest::from_canonical_slice(&bytes).expect("解码成功"),
        manifest
    );

    // 未知格式版本必须被拒绝，绝不静默降级。
    let mut future = manifest.clone();
    future.format_version = BUNDLE_MANIFEST_FORMAT_VERSION + 1;
    assert!(BundleManifest::from_canonical_slice(&future.to_canonical_vec()).is_err());
    assert!(matches!(
        future.validate(),
        Err(BundleManifestError::UnsupportedFormatVersion { .. })
    ));
}
