#![cfg(unix)]

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::fs::PermissionsExt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use envsync_core::bundles::{publisher_fingerprint, publisher_namespace};
use envsync_core::PublisherRegistry;
use envsync_crypto::device::DeviceKeypair;
use envsync_domain::{Arch, DeviceProfile, Os};
use envsync_plugin_api::{PluginId, PluginManifest};
use envsync_plugin_host::{
    ApprovalGap, HostError, PluginArtifact, PluginHost, PluginState, PLUGIN_SIGNATURE_DOMAIN,
};
use envsync_policy::{
    Decision, FactPredicate, MatchExpr, Operation, PolicySet, ResourceKind, Rule, RuleId,
};
use tempfile::TempDir;

const NOW: u64 = 1_777_777_777_000;

struct Fixture {
    temp: TempDir,
    signer: DeviceKeypair,
}

impl Fixture {
    fn new() -> Self {
        Self {
            temp: tempfile::tempdir().expect("tempdir"),
            signer: DeviceKeypair::generate().expect("keypair"),
        }
    }

    fn registry(&self) -> PublisherRegistry {
        let mut registry = PublisherRegistry::new();
        registry.trust(self.signer.public().ed25519, "fixture publisher");
        registry
    }

    fn host(&self, registry: PublisherRegistry) -> PluginHost {
        PluginHost::open(
            self.temp.path().join("quarantine"),
            self.temp.path().join("runtime"),
            registry,
        )
        .expect("host roots")
    }

    fn artifact(&self, id: &str, bytes: &[u8], capabilities: &[&str]) -> PluginArtifact {
        artifact_signed_by(&self.signer, &self.signer, id, bytes, capabilities)
    }
}

fn artifact_signed_by(
    declared: &DeviceKeypair,
    signing: &DeviceKeypair,
    id: &str,
    bytes: &[u8],
    capabilities: &[&str],
) -> PluginArtifact {
    let digest = URL_SAFE_NO_PAD.encode(blake3::hash(bytes).as_bytes());
    let public_key = URL_SAFE_NO_PAD.encode(declared.public().ed25519);
    let mut value = serde_json::json!({
        "id": id,
        "version": "1.0.0",
        "publisher": { "id": "com.example.publisher", "public_key": public_key },
        "api": "^1.0",
        "entrypoint": "bin/plugin",
        "entrypoint_digest": digest,
        "targets": ["macos"],
        "capabilities": capabilities,
        "limits": {
            "max_runtime_ms": 1000,
            "max_memory_bytes": 1048576,
            "max_output_bytes": 1024
        },
        "signature": { "algorithm": "ed25519", "value": URL_SAFE_NO_PAD.encode([0_u8; 64]) }
    });
    let unsigned = PluginManifest::from_json_value(value.clone()).expect("unsigned shape");
    let signature = signing
        .sign(
            PLUGIN_SIGNATURE_DOMAIN,
            publisher_namespace(),
            &unsigned.signing_payload().expect("payload"),
        )
        .expect("sign manifest");
    value["signature"]["value"] =
        serde_json::Value::String(URL_SAFE_NO_PAD.encode(signature.as_bytes()));
    let manifest = PluginManifest::from_json_value(value).expect("signed manifest");
    PluginArtifact::new(manifest, bytes.to_vec())
}

fn profile() -> DeviceProfile {
    DeviceProfile::new(Os::MacOs, Arch::Aarch64).with_tag("work")
}

fn policy(decision: Decision) -> PolicySet {
    PolicySet::from_rules(vec![Rule::new(
        RuleId::parse("test.plugin").expect("rule id"),
        decision,
        MatchExpr::All(vec![
            MatchExpr::leaf(FactPredicate::ResourceKind(BTreeSet::from([
                ResourceKind::Plugin,
            ]))),
            MatchExpr::leaf(FactPredicate::Operation(BTreeSet::from([
                Operation::Enable,
            ]))),
        ]),
    )])
    .expect("policy")
}

#[test]
fn quarantine_unknown_signer_is_blocked_without_writing_entrypoint() {
    let fixture = Fixture::new();
    let mut host = fixture.host(PublisherRegistry::new());
    let id = PluginId::parse("com.example.unknown").expect("id");

    let record = host
        .quarantine(fixture.artifact(id.as_str(), b"unknown", &["observe"]), NOW)
        .expect("blocked record");

    assert_eq!(record.state(), PluginState::Blocked);
    assert!(record.quarantined_entry().is_none());
    assert!(record.runtime_entry().is_none());
    assert_eq!(host.audit_for(&id).len(), 1);
}

#[test]
fn quarantine_tampered_entry_and_invalid_signature_are_blocked_before_disk() {
    let fixture = Fixture::new();
    let mut host = fixture.host(fixture.registry());
    let tampered_id = PluginId::parse("com.example.tampered").expect("id");
    let valid = fixture.artifact(tampered_id.as_str(), b"trusted", &["observe"]);
    let tampered = PluginArtifact::new(valid.manifest().clone(), b"tampered".to_vec());

    let record = host.quarantine(tampered, NOW).expect("blocked record");
    assert_eq!(record.state(), PluginState::Blocked);
    assert!(record.quarantined_entry().is_none());

    let other = DeviceKeypair::generate().expect("other keypair");
    let invalid_id = PluginId::parse("com.example.bad-signature").expect("id");
    let invalid = artifact_signed_by(
        &fixture.signer,
        &other,
        invalid_id.as_str(),
        b"bad signature",
        &["observe"],
    );
    let record = host.quarantine(invalid, NOW + 1).expect("blocked record");
    assert_eq!(record.state(), PluginState::Blocked);
    assert!(record.quarantined_entry().is_none());
}

#[test]
fn quarantine_verified_entrypoint_has_no_execute_bits() {
    let fixture = Fixture::new();
    let mut host = fixture.host(fixture.registry());
    let id = PluginId::parse("com.example.safe").expect("id");

    let record = host
        .quarantine(
            fixture.artifact(id.as_str(), b"#!/bin/sh\n", &["observe"]),
            NOW,
        )
        .expect("quarantine");
    let staged_entry = record.quarantined_entry().expect("staged entry");

    assert_eq!(record.state(), PluginState::Quarantined);
    assert_eq!(
        fs::metadata(staged_entry)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o111,
        0
    );
    assert_eq!(fs::read(staged_entry).expect("read entry"), b"#!/bin/sh\n");
    assert!(record.runtime_entry().is_none());
}

#[test]
fn quarantine_refuses_a_symlinked_plugin_directory() {
    let fixture = Fixture::new();
    let mut host = fixture.host(fixture.registry());
    let id = PluginId::parse("com.example.symlink").expect("id");
    let outside = fixture.temp.path().join("outside");
    fs::create_dir(&outside).expect("outside directory");
    symlink(
        &outside,
        fixture.temp.path().join("quarantine").join(id.as_str()),
    )
    .expect("poison plugin directory");

    let error = match host.quarantine(fixture.artifact(id.as_str(), b"safe", &["observe"]), NOW) {
        Err(error) => error,
        Ok(_) => panic!("symlink must be rejected"),
    };

    assert!(matches!(error, HostError::UnsafePath));
    assert!(fs::read_dir(outside)
        .expect("read outside")
        .next()
        .is_none());
}

#[test]
fn quarantine_tampering_after_approval_blocks_enable_before_runtime_copy() {
    let fixture = Fixture::new();
    let mut host = fixture.host(fixture.registry());
    let id = PluginId::parse("com.example.runtime-tamper").expect("id");
    let device = profile();
    let allow = policy(Decision::Allow);

    host.quarantine(
        fixture.artifact(id.as_str(), b"verified", &["observe"]),
        NOW,
    )
    .expect("quarantine");
    let approval = host
        .approve(&id, "work", &device, &allow, true, NOW + 1)
        .expect("approve");
    let staged = host
        .record(&id)
        .expect("record")
        .quarantined_entry()
        .expect("staged")
        .to_path_buf();
    fs::write(staged, b"tampered after approval").expect("replace staged bytes");

    let error = host
        .enable(&id, &approval, "work", &device, &allow, true, NOW + 2)
        .expect_err("tampered staging must block");

    assert!(matches!(error, HostError::ArtifactTampered));
    let record = host.record(&id).expect("record");
    assert_eq!(record.state(), PluginState::Blocked);
    assert!(record.runtime_entry().is_none());
}

#[test]
fn quarantine_updates_and_capability_expansion_require_fresh_approval() {
    let fixture = Fixture::new();
    let mut host = fixture.host(fixture.registry());
    let id = PluginId::parse("com.example.updates").expect("id");
    let allow = policy(Decision::Allow);
    let device = profile();

    host.quarantine(fixture.artifact(id.as_str(), b"v1", &["observe"]), NOW)
        .expect("quarantine v1");
    let approval_v1 = host
        .approve(&id, "work", &device, &allow, true, NOW + 1)
        .expect("approve v1");
    host.enable(&id, &approval_v1, "work", &device, &allow, true, NOW + 2)
        .expect("enable v1");

    let updated = host
        .quarantine(fixture.artifact(id.as_str(), b"v2", &["observe"]), NOW + 3)
        .expect("quarantine v2");
    assert_eq!(updated.state(), PluginState::Quarantined);
    assert!(matches!(
        approval_v1.check_covers(updated, "work"),
        Err(ApprovalGap::ArtifactDigestChanged | ApprovalGap::ManifestDigestChanged)
    ));
    let approval_v2 = host
        .approve(&id, "work", &device, &allow, true, NOW + 4)
        .expect("approve v2");

    let expanded = host
        .quarantine(
            fixture.artifact(id.as_str(), b"v3", &["observe", "plan-command"]),
            NOW + 5,
        )
        .expect("quarantine expanded");
    assert_eq!(expanded.state(), PluginState::Quarantined);
    assert!(matches!(
        approval_v2.check_covers(expanded, "work"),
        Err(ApprovalGap::CapabilitiesExpanded { .. })
    ));
}

#[test]
fn quarantine_policy_and_confirmation_gate_runtime_copy() {
    let fixture = Fixture::new();
    let mut host = fixture.host(fixture.registry());
    let id = PluginId::parse("com.example.policy").expect("id");
    let device = profile();
    host.quarantine(fixture.artifact(id.as_str(), b"policy", &["observe"]), NOW)
        .expect("quarantine");

    let error = host
        .approve(&id, "work", &device, &policy(Decision::Deny), true, NOW + 1)
        .expect_err("deny approval");
    assert_eq!(error.code(), "plugin.host.policy_denied");
    assert!(host.record(&id).expect("record").runtime_entry().is_none());

    let error = host
        .approve(
            &id,
            "work",
            &device,
            &policy(Decision::RequireConfirmation),
            false,
            NOW + 2,
        )
        .expect_err("confirmation required");
    assert!(matches!(error, HostError::ConfirmationRequired));
    assert!(host.record(&id).expect("record").runtime_entry().is_none());

    let approval = host
        .approve(
            &id,
            "work",
            &device,
            &policy(Decision::Allow),
            true,
            NOW + 3,
        )
        .expect("approve");
    let error = host
        .enable(
            &id,
            &approval,
            "work",
            &device,
            &policy(Decision::RequireConfirmation),
            false,
            NOW + 4,
        )
        .expect_err("enable confirmation required");
    assert!(matches!(error, HostError::ConfirmationRequired));
    assert!(host.record(&id).expect("record").runtime_entry().is_none());

    host.enable(
        &id,
        &approval,
        "work",
        &device,
        &policy(Decision::RequireConfirmation),
        true,
        NOW + 5,
    )
    .expect("confirmed enable");
    assert_eq!(
        host.record(&id).expect("record").state(),
        PluginState::Enabled
    );
    assert!(host.record(&id).expect("record").runtime_entry().is_some());
}

#[test]
fn quarantine_publisher_revocation_disables_records_and_retains_audit() {
    let fixture = Fixture::new();
    let signer = fixture.signer.public().ed25519;
    let mut host = fixture.host(fixture.registry());
    let id = PluginId::parse("com.example.revoked").expect("id");
    let device = profile();
    let allow = policy(Decision::Allow);
    host.quarantine(fixture.artifact(id.as_str(), b"enabled", &["observe"]), NOW)
        .expect("quarantine");
    let approval = host
        .approve(&id, "work", &device, &allow, true, NOW + 1)
        .expect("approve");
    host.enable(&id, &approval, "work", &device, &allow, true, NOW + 2)
        .expect("enable");
    let audit_before = host.audit_for(&id).len();

    let outcome = host.revoke_publisher(signer, NOW + 3);

    assert_eq!(outcome.affected(), 1);
    assert_eq!(
        host.record(&id).expect("record").state(),
        PluginState::Revoked
    );
    assert!(host.audit_for(&id).len() > audit_before);
    assert!(host
        .audit_for(&id)
        .iter()
        .any(|event| event.to() == PluginState::Enabled));
    let runtime = host
        .record(&id)
        .expect("record")
        .runtime_entry()
        .expect("runtime");
    assert_eq!(
        fs::metadata(runtime)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o111,
        0
    );

    let second = PluginId::parse("com.example.revoked-second").expect("id");
    let blocked = host
        .quarantine(
            fixture.artifact(second.as_str(), b"revoked", &["observe"]),
            NOW + 4,
        )
        .expect("blocked record");
    assert_eq!(blocked.state(), PluginState::Blocked);
    assert!(blocked.quarantined_entry().is_none());
    assert_eq!(
        host.record(&id).expect("record").signer_fingerprint(),
        publisher_fingerprint(&signer)
    );
}
