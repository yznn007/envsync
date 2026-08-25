#![cfg(unix)]

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
#[cfg(not(target_os = "macos"))]
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use envsync_core::bundles::{publisher_fingerprint, publisher_namespace};
use envsync_core::PublisherRegistry;
use envsync_crypto::device::DeviceKeypair;
use envsync_domain::{Arch, DeviceProfile, Os};
use envsync_platform::{AuthorizedRoot, RootRegistry};
#[cfg(not(target_os = "macos"))]
use envsync_plugin_api::{encode_frame, RequestId, RpcMessage, RpcRequest, SchemaVersion};
use envsync_plugin_api::{PluginId, PluginManifest, PluginMethod};
use envsync_plugin_host::{
    ApprovalGap, CapabilityMediator, CommandArgumentRule, CommandProposalCatalog,
    CommandProposalTemplate, HostError, PluginArtifact, PluginHost, PluginState, ValidatedProposal,
    PLUGIN_SIGNATURE_DOMAIN,
};
use envsync_policy::{
    Decision, FactPredicate, MatchExpr, Operation, PolicySet, ResourceKind, Rule, RuleId,
};
#[cfg(not(target_os = "macos"))]
use nix::errno::Errno;
#[cfg(not(target_os = "macos"))]
use nix::sys::signal::kill;
#[cfg(not(target_os = "macos"))]
use nix::unistd::Pid;
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
        let root = self.temp.path().canonicalize().expect("canonical tempdir");
        PluginHost::open(root.join("quarantine"), root.join("runtime"), registry)
            .expect("host roots")
    }

    fn test_host(&self, registry: PublisherRegistry, runner: &Path) -> PluginHost {
        let root = self.temp.path().canonicalize().expect("canonical tempdir");
        PluginHost::for_test_runner(
            root.join("quarantine"),
            root.join("runtime"),
            registry,
            runner,
        )
        .expect("test host roots")
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
            "max_memory_bytes": 67108864,
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

fn capability_context(temp: &TempDir) -> (RootRegistry, CommandProposalCatalog) {
    let root_path = temp.path().join("workspace");
    fs::create_dir(&root_path).expect("workspace root");
    let root = AuthorizedRoot::open("workspace", &root_path).expect("authorized root");
    let mut roots = RootRegistry::new();
    roots.insert(root);

    let mut commands = CommandProposalCatalog::new();
    commands
        .register(
            CommandProposalTemplate::new("envsync.status", vec![CommandArgumentRule::token()])
                .expect("command template"),
        )
        .expect("register command template");
    (roots, commands)
}

#[cfg(not(target_os = "macos"))]
fn runner_path() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_envsync-plugin-runner"))
}

#[cfg(not(target_os = "macos"))]
fn environment_check_script(request_id: &str) -> Vec<u8> {
    let response = RpcMessage::new_success_response(
        SchemaVersion::new(1, 0),
        RequestId::parse(request_id).expect("request id"),
        serde_json::json!({ "canary_visible": false, "cwd_empty": true }),
    )
    .expect("response");
    let escaped_frame = encode_frame(&response)
        .expect("frame")
        .iter()
        .map(|byte| format!("\\{byte:03o}"))
        .collect::<String>();
    format!(
        "#!/bin/sh\nif [ -n \"${{ENVSYNC_PLUGIN_SECRET_CANARY+x}}\" ]; then exit 42; fi\nif [ -n \"$(/bin/ls -A)\" ]; then exit 43; fi\nprintf '%b' '{escaped_frame}'\n"
    )
    .into_bytes()
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
fn host_open_refuses_a_root_beneath_an_ancestor_symlink() {
    let fixture = Fixture::new();
    let outside = fixture.temp.path().join("outside");
    fs::create_dir_all(outside.join("quarantine")).expect("outside quarantine");
    let linked_parent = fixture.temp.path().join("linked-parent");
    symlink(&outside, &linked_parent).expect("poison ancestor");

    let error = match PluginHost::open(
        linked_parent.join("quarantine"),
        fixture.temp.path().join("runtime"),
        fixture.registry(),
    ) {
        Err(error) => error,
        Ok(_) => panic!("ancestor symlink must be rejected"),
    };

    assert!(matches!(error, HostError::UnsafePath));
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
}

#[test]
fn quarantine_symlink_replacement_blocks_enable() {
    let fixture = Fixture::new();
    let mut host = fixture.host(fixture.registry());
    let id = PluginId::parse("com.example.symlink-replacement").expect("id");
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
    fs::remove_file(&staged).expect("remove staged file");
    symlink(fixture.temp.path().join("outside-entry"), &staged).expect("replace with symlink");

    let error = host
        .enable(&id, &approval, "work", &device, &allow, true, NOW + 2)
        .expect_err("symlinked staging must block");

    assert!(matches!(error, HostError::UnsafePath));
    assert_eq!(
        host.record(&id).expect("record").state(),
        PluginState::Blocked
    );
}

#[test]
fn default_host_refuses_to_create_an_executable_runtime() {
    let fixture = Fixture::new();
    let mut host = fixture.host(fixture.registry());
    let id = PluginId::parse("com.example.default-host").expect("id");
    let device = profile();
    let allow = policy(Decision::Allow);

    host.quarantine(
        fixture.artifact(id.as_str(), b"approved only", &["observe"]),
        NOW,
    )
    .expect("quarantine");
    let approval = host
        .approve(&id, "work", &device, &allow, true, NOW + 1)
        .expect("approve");

    let error = host
        .enable(&id, &approval, "work", &device, &allow, true, NOW + 2)
        .expect_err("ordinary Host has no sandbox runner");

    assert_eq!(error.code(), "plugin.host.sandbox_unavailable");
    let record = host.record(&id).expect("record");
    assert_eq!(record.state(), PluginState::Approved);
}

#[test]
fn test_support_host_enables_a_verified_approved_entrypoint() {
    let fixture = Fixture::new();
    let runner = fixture.temp.path().join("runner");
    let mut host = fixture.test_host(fixture.registry(), &runner);
    let id = PluginId::parse("com.example.test-runner").expect("id");
    let device = profile();
    let allow = policy(Decision::Allow);

    host.quarantine(
        fixture.artifact(id.as_str(), b"#!/bin/sh\nexit 0\n", &["observe"]),
        NOW,
    )
    .expect("quarantine");
    let approval = host
        .approve(&id, "work", &device, &allow, true, NOW + 1)
        .expect("approve");

    host.enable(&id, &approval, "work", &device, &allow, true, NOW + 2)
        .expect("test-only launcher can enable a verified entrypoint");

    assert_eq!(
        host.record(&id).expect("record").state(),
        PluginState::Enabled
    );
}

#[test]
fn capability_mediator_returns_only_validated_file_declarations() {
    let fixture = Fixture::new();
    let (roots, commands) = capability_context(&fixture.temp);
    let mediator = CapabilityMediator::new(&roots, &commands);
    let proposal = serde_json::json!({ "root": "workspace", "target": "config/state.json" });

    let observed = mediator
        .validate(PluginMethod::Observe, proposal.clone())
        .expect("observe proposal");
    assert!(matches!(
        observed,
        ValidatedProposal::Observation { root, target }
            if root == "workspace" && target.display_path() == "config/state.json"
    ));

    let rendered = mediator
        .validate(PluginMethod::Render, proposal.clone())
        .expect("render proposal");
    assert!(matches!(rendered, ValidatedProposal::Render { .. }));

    let verified = mediator
        .validate(PluginMethod::Verify, proposal)
        .expect("verify proposal");
    assert!(matches!(verified, ValidatedProposal::Verification { .. }));
}

#[test]
fn capability_mediator_rejects_unsafe_or_unregistered_targets() {
    let fixture = Fixture::new();
    let (roots, commands) = capability_context(&fixture.temp);
    let mediator = CapabilityMediator::new(&roots, &commands);

    for target in ["../../secret", "/etc/passwd"] {
        let error = mediator
            .validate(
                PluginMethod::Observe,
                serde_json::json!({ "root": "workspace", "target": target }),
            )
            .expect_err("unsafe target");
        assert_eq!(error.code(), "plugin.host.invalid_target");
    }

    let error = mediator
        .validate(
            PluginMethod::Render,
            serde_json::json!({ "root": "missing", "target": "config/state.json" }),
        )
        .expect_err("unknown root");
    assert_eq!(error.code(), "plugin.host.unknown_root");

    let error = mediator
        .validate(
            PluginMethod::Verify,
            serde_json::json!({
                "root": "workspace",
                "target": "config/state.json",
                "secret": "must-not-be-a-schema-field"
            }),
        )
        .expect_err("unknown field");
    assert_eq!(error.code(), "plugin.host.invalid_proposal");
}

#[test]
fn capability_mediator_rejects_untrusted_commands_without_execution() {
    let fixture = Fixture::new();
    let (roots, commands) = capability_context(&fixture.temp);
    let mediator = CapabilityMediator::new(&roots, &commands);

    let valid = mediator
        .validate(
            PluginMethod::PlanCommand,
            serde_json::json!({ "template_id": "envsync.status", "argv": ["workspace"] }),
        )
        .expect("valid command proposal");
    assert!(matches!(valid, ValidatedProposal::Command { .. }));

    let error = mediator
        .validate(
            PluginMethod::PlanCommand,
            serde_json::json!({ "template_id": "missing", "argv": [] }),
        )
        .expect_err("unknown template");
    assert_eq!(error.code(), "plugin.host.unknown_command");

    for argv in [
        serde_json::json!(["workspace;rm"]),
        serde_json::json!(["workspace\u{0}secret"]),
        serde_json::json!(vec!["workspace"; 65]),
    ] {
        let error = mediator
            .validate(
                PluginMethod::PlanCommand,
                serde_json::json!({ "template_id": "envsync.status", "argv": argv }),
            )
            .expect_err("unsafe argv");
        assert_eq!(error.code(), "plugin.host.invalid_command");
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn test_runner_clears_environment_uses_empty_cwd_and_correlates_response() {
    let fixture = Fixture::new();
    let mut host = fixture.test_host(fixture.registry(), runner_path());
    let id = PluginId::parse("com.example.environment").expect("id");
    let device = profile();
    let allow = policy(Decision::Allow);
    let request = RpcRequest::new(
        SchemaVersion::new(1, 0),
        RequestId::parse("environment_check").expect("request id"),
        PluginMethod::Observe,
        serde_json::json!({}),
    )
    .expect("request");

    host.quarantine(
        fixture.artifact(
            id.as_str(),
            &environment_check_script(request.id().as_str()),
            &["observe"],
        ),
        NOW,
    )
    .expect("quarantine");
    let approval = host
        .approve(&id, "work", &device, &allow, true, NOW + 1)
        .expect("approve");
    host.enable(&id, &approval, "work", &device, &allow, true, NOW + 2)
        .expect("enable");

    std::env::set_var("ENVSYNC_PLUGIN_SECRET_CANARY", "must-not-reach-plugin");
    let mut session = host.start(&id, NOW + 3).expect("start test runner");
    let response = session.call(request).expect("correlated response");
    std::env::remove_var("ENVSYNC_PLUGIN_SECRET_CANARY");

    assert_eq!(
        response.result().expect("success result"),
        &serde_json::json!({ "canary_visible": false, "cwd_empty": true })
    );
}

#[cfg(target_os = "macos")]
#[test]
fn test_runner_fails_closed_when_darwin_rejects_rlimit_as() {
    let fixture = Fixture::new();
    let runner = fixture.temp.path().join("runner");
    let mut host = fixture.test_host(fixture.registry(), &runner);
    let id = PluginId::parse("com.example.darwin-runner").expect("id");
    let device = profile();
    let allow = policy(Decision::Allow);

    host.quarantine(
        fixture.artifact(id.as_str(), b"#!/bin/sh\nexit 0\n", &["observe"]),
        NOW,
    )
    .expect("quarantine");
    let approval = host
        .approve(&id, "work", &device, &allow, true, NOW + 1)
        .expect("approve");
    host.enable(&id, &approval, "work", &device, &allow, true, NOW + 2)
        .expect("enable");

    let error = match host.start(&id, NOW + 3) {
        Ok(_) => panic!("Darwin must not run without a verifiable address-space limit"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "plugin.host.sandbox_unavailable");
}

#[cfg(not(target_os = "macos"))]
#[test]
fn test_runner_times_out_and_terminates_a_looping_process_group() {
    let fixture = Fixture::new();
    let mut host = fixture.test_host(fixture.registry(), runner_path());
    let id = PluginId::parse("com.example.loop").expect("id");
    let device = profile();
    let allow = policy(Decision::Allow);
    let request = RpcRequest::new(
        SchemaVersion::new(1, 0),
        RequestId::parse("loop_request").expect("request id"),
        PluginMethod::Observe,
        serde_json::json!({}),
    )
    .expect("request");

    host.quarantine(
        fixture.artifact(
            id.as_str(),
            b"#!/bin/sh\nwhile :; do :; done\n",
            &["observe"],
        ),
        NOW,
    )
    .expect("quarantine");
    let approval = host
        .approve(&id, "work", &device, &allow, true, NOW + 1)
        .expect("approve");
    host.enable(&id, &approval, "work", &device, &allow, true, NOW + 2)
        .expect("enable");

    let mut session = host.start(&id, NOW + 3).expect("start runner");
    let started = Instant::now();
    let error = match session.call(request) {
        Ok(_) => panic!("looping plugin must time out"),
        Err(error) => error,
    };

    assert_eq!(error.code(), "plugin.host.timeout");
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn test_runner_enforces_a_combined_stderr_output_limit_without_echoing_diagnostics() {
    let fixture = Fixture::new();
    let mut host = fixture.test_host(fixture.registry(), runner_path());
    let id = PluginId::parse("com.example.stderr-flood").expect("id");
    let device = profile();
    let allow = policy(Decision::Allow);
    let request = RpcRequest::new(
        SchemaVersion::new(1, 0),
        RequestId::parse("stderr_flood").expect("request id"),
        PluginMethod::Observe,
        serde_json::json!({}),
    )
    .expect("request");

    host.quarantine(
        fixture.artifact(
            id.as_str(),
            b"#!/bin/sh\nwhile :; do printf 'fixture-secret-stderr' >&2; done\n",
            &["observe"],
        ),
        NOW,
    )
    .expect("quarantine");
    let approval = host
        .approve(&id, "work", &device, &allow, true, NOW + 1)
        .expect("approve");
    host.enable(&id, &approval, "work", &device, &allow, true, NOW + 2)
        .expect("enable");

    let mut session = host.start(&id, NOW + 3).expect("start runner");
    let error = match session.call(request) {
        Ok(_) => panic!("stderr flood must exceed the combined output limit"),
        Err(error) => error,
    };

    assert_eq!(error.code(), "plugin.host.output_limit");
    assert!(!error.to_string().contains("fixture-secret-stderr"));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn test_runner_kills_a_late_stderr_flood_after_a_valid_response() {
    let fixture = Fixture::new();
    let mut host = fixture.test_host(fixture.registry(), runner_path());
    let id = PluginId::parse("com.example.late-stderr-flood").expect("id");
    let device = profile();
    let allow = policy(Decision::Allow);
    let request = RpcRequest::new(
        SchemaVersion::new(1, 0),
        RequestId::parse("late_stderr_flood").expect("request id"),
        PluginMethod::Observe,
        serde_json::json!({}),
    )
    .expect("request");
    let response = RpcMessage::new_success_response(
        SchemaVersion::new(1, 0),
        request.id().clone(),
        serde_json::json!({ "accepted": true }),
    )
    .expect("response");
    let escaped_frame = encode_frame(&response)
        .expect("frame")
        .iter()
        .map(|byte| format!("\\{byte:03o}"))
        .collect::<String>();
    let survivor_marker = fixture.temp.path().join("stderr-flood-survivor");
    let survivor_marker = survivor_marker.to_string_lossy().replace('\'', "'\"'\"'");
    let script = format!(
        "#!/bin/sh\nprintf '%b' '{escaped_frame}'\n/bin/sleep 0.05\nprintf '%b' '{escaped_frame}'\nprintf '%b' '{escaped_frame}'\nprintf '%b' '{escaped_frame}'\nprintf '%b' '{escaped_frame}'\n(/bin/sleep 0.2; printf survived > '{survivor_marker}') &\nwhile :; do printf 'fixture-secret-stderr' >&2; done\n"
    );

    host.quarantine(
        fixture.artifact(id.as_str(), script.as_bytes(), &["observe"]),
        NOW,
    )
    .expect("quarantine");
    let approval = host
        .approve(&id, "work", &device, &allow, true, NOW + 1)
        .expect("approve");
    host.enable(&id, &approval, "work", &device, &allow, true, NOW + 2)
        .expect("enable");

    let mut session = host.start(&id, NOW + 3).expect("start runner");
    let first_response = session
        .call(request)
        .expect("first response before late flood");
    assert_eq!(
        first_response.result().expect("success result"),
        &serde_json::json!({ "accepted": true })
    );

    std::thread::sleep(Duration::from_millis(350));
    assert!(
        !fixture.temp.path().join("stderr-flood-survivor").exists(),
        "output-limit handling must kill descendants before they can survive"
    );

    let follow_up = RpcRequest::new(
        SchemaVersion::new(1, 0),
        RequestId::parse("late_stderr_flood_follow_up").expect("request id"),
        PluginMethod::Observe,
        serde_json::json!({}),
    )
    .expect("request");
    let error = session
        .call(follow_up)
        .expect_err("late stderr flood must remain an output-limit failure");
    assert_eq!(error.code(), "plugin.host.output_limit");
}

#[cfg(not(target_os = "macos"))]
#[test]
fn test_runner_shutdown_times_out_when_plugin_ignores_the_request() {
    let fixture = Fixture::new();
    let mut host = fixture.test_host(fixture.registry(), runner_path());
    let id = PluginId::parse("com.example.ignore-shutdown").expect("id");
    let device = profile();
    let allow = policy(Decision::Allow);

    host.quarantine(
        fixture.artifact(
            id.as_str(),
            b"#!/bin/sh\nwhile :; do :; done\n",
            &["observe"],
        ),
        NOW,
    )
    .expect("quarantine");
    let approval = host
        .approve(&id, "work", &device, &allow, true, NOW + 1)
        .expect("approve");
    host.enable(&id, &approval, "work", &device, &allow, true, NOW + 2)
        .expect("enable");

    let mut session = host.start(&id, NOW + 3).expect("start runner");
    let error = match session.shutdown() {
        Ok(()) => panic!("plugin that ignores shutdown must be terminated"),
        Err(error) => error,
    };

    assert_eq!(error.code(), "plugin.host.shutdown_timeout");
}

#[cfg(not(target_os = "macos"))]
#[test]
fn test_runner_rejects_wrong_response_id_and_malformed_frame() {
    let fixture = Fixture::new();
    let device = profile();
    let allow = policy(Decision::Allow);

    let wrong_id = PluginId::parse("com.example.wrong-id").expect("id");
    let mut wrong_id_host = fixture.test_host(fixture.registry(), runner_path());
    wrong_id_host
        .quarantine(
            fixture.artifact(
                wrong_id.as_str(),
                &environment_check_script("different_request"),
                &["observe"],
            ),
            NOW,
        )
        .expect("quarantine");
    let approval = wrong_id_host
        .approve(&wrong_id, "work", &device, &allow, true, NOW + 1)
        .expect("approve");
    wrong_id_host
        .enable(&wrong_id, &approval, "work", &device, &allow, true, NOW + 2)
        .expect("enable");
    let mut wrong_id_session = wrong_id_host
        .start(&wrong_id, NOW + 3)
        .expect("start runner");
    let request = RpcRequest::new(
        SchemaVersion::new(1, 0),
        RequestId::parse("expected_request").expect("request id"),
        PluginMethod::Observe,
        serde_json::json!({}),
    )
    .expect("request");
    let error = match wrong_id_session.call(request) {
        Ok(_) => panic!("wrong response ID must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "plugin.host.protocol");

    let malformed = PluginId::parse("com.example.bad-frame").expect("id");
    let mut malformed_host = fixture.test_host(fixture.registry(), runner_path());
    malformed_host
        .quarantine(
            fixture.artifact(
                malformed.as_str(),
                b"#!/bin/sh\nprintf '%b' '\\000\\000\\000\\001}'\n",
                &["observe"],
            ),
            NOW + 4,
        )
        .expect("quarantine");
    let approval = malformed_host
        .approve(&malformed, "work", &device, &allow, true, NOW + 5)
        .expect("approve");
    malformed_host
        .enable(
            &malformed,
            &approval,
            "work",
            &device,
            &allow,
            true,
            NOW + 6,
        )
        .expect("enable");
    let mut malformed_session = malformed_host
        .start(&malformed, NOW + 7)
        .expect("start runner");
    let request = RpcRequest::new(
        SchemaVersion::new(1, 0),
        RequestId::parse("bad_frame").expect("request id"),
        PluginMethod::Observe,
        serde_json::json!({}),
    )
    .expect("request");
    let error = match malformed_session.call(request) {
        Ok(_) => panic!("malformed frame must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "plugin.host.protocol");
}

#[cfg(not(target_os = "macos"))]
#[test]
fn test_runner_timeout_kills_descendants_in_the_same_process_group() {
    let fixture = Fixture::new();
    let mut host = fixture.test_host(fixture.registry(), runner_path());
    let id = PluginId::parse("com.example.process-tree").expect("id");
    let device = profile();
    let allow = policy(Decision::Allow);
    let marker = fixture.temp.path().join("descendant.pid");
    let marker = marker.to_string_lossy().replace('\'', "'\"'\"'");
    let script = format!(
        "#!/bin/sh\n/bin/sleep 30 &\nprintf '%s' \"$!\" > '{marker}'\nwhile :; do :; done\n"
    );
    let request = RpcRequest::new(
        SchemaVersion::new(1, 0),
        RequestId::parse("process_tree").expect("request id"),
        PluginMethod::Observe,
        serde_json::json!({}),
    )
    .expect("request");

    host.quarantine(
        fixture.artifact(id.as_str(), script.as_bytes(), &["observe"]),
        NOW,
    )
    .expect("quarantine");
    let approval = host
        .approve(&id, "work", &device, &allow, true, NOW + 1)
        .expect("approve");
    host.enable(&id, &approval, "work", &device, &allow, true, NOW + 2)
        .expect("enable");

    let mut session = host.start(&id, NOW + 3).expect("start runner");
    let error = match session.call(request) {
        Ok(_) => panic!("process tree fixture must time out"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "plugin.host.timeout");

    let child_pid = fs::read_to_string(fixture.temp.path().join("descendant.pid"))
        .expect("fixture wrote descendant PID")
        .trim()
        .parse::<i32>()
        .expect("valid descendant PID");
    for _ in 0..50 {
        if matches!(kill(Pid::from_raw(child_pid), None), Err(Errno::ESRCH)) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("descendant process survived process-group termination");
}

#[test]
fn approval_cannot_cross_the_actual_device_profile() {
    let fixture = Fixture::new();
    let mut host = fixture.host(fixture.registry());
    let id = PluginId::parse("com.example.profile-binding").expect("id");
    let approved_profile = profile();
    let other_profile = DeviceProfile::new(Os::Linux, Arch::X86_64).with_tag("work");
    let allow = policy(Decision::Allow);

    host.quarantine(fixture.artifact(id.as_str(), b"profile", &["observe"]), NOW)
        .expect("quarantine");
    let approval = host
        .approve(&id, "work", &approved_profile, &allow, true, NOW + 1)
        .expect("approve");

    let error = host
        .enable(
            &id,
            &approval,
            "work",
            &other_profile,
            &allow,
            true,
            NOW + 2,
        )
        .expect_err("different actual profile must invalidate approval");

    assert!(matches!(
        error,
        HostError::ApprovalStale(ApprovalGap::ProfileChanged)
    ));
    assert_eq!(
        host.record(&id).expect("record").state(),
        PluginState::Approved
    );
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

    let updated = host
        .quarantine(fixture.artifact(id.as_str(), b"v2", &["observe"]), NOW + 2)
        .expect("quarantine v2");
    assert_eq!(updated.state(), PluginState::Quarantined);
    assert!(matches!(
        approval_v1.check_covers(updated, "work", &device),
        Err(ApprovalGap::ArtifactDigestChanged | ApprovalGap::ManifestDigestChanged)
    ));
    let approval_v2 = host
        .approve(&id, "work", &device, &allow, true, NOW + 3)
        .expect("approve v2");

    let expanded = host
        .quarantine(
            fixture.artifact(id.as_str(), b"v3", &["observe", "plan-command"]),
            NOW + 4,
        )
        .expect("quarantine expanded");
    assert_eq!(expanded.state(), PluginState::Quarantined);
    assert!(matches!(
        approval_v2.check_covers(expanded, "work", &device),
        Err(ApprovalGap::CapabilitiesExpanded { .. })
    ));
}

#[test]
fn quarantine_policy_and_confirmation_gate_activation() {
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

    let error = host
        .enable(
            &id,
            &approval,
            "work",
            &device,
            &policy(Decision::RequireConfirmation),
            true,
            NOW + 5,
        )
        .expect_err("ordinary Host has no sandbox runner");
    assert_eq!(error.code(), "plugin.host.sandbox_unavailable");
    assert_eq!(
        host.record(&id).expect("record").state(),
        PluginState::Approved
    );
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
    let error = host
        .enable(&id, &approval, "work", &device, &allow, true, NOW + 2)
        .expect_err("ordinary Host has no sandbox runner");
    assert_eq!(error.code(), "plugin.host.sandbox_unavailable");
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
        .any(|event| event.to() == PluginState::Approved));

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

#[test]
fn revoked_plugin_cannot_be_replaced_by_a_resubmitted_artifact() {
    let fixture = Fixture::new();
    let mut host = fixture.host(fixture.registry());
    let id = PluginId::parse("com.example.revoked-resubmission").expect("id");

    host.quarantine(
        fixture.artifact(id.as_str(), b"original", &["observe"]),
        NOW,
    )
    .expect("quarantine");
    host.revoke_publisher(fixture.signer.public().ed25519, NOW + 1);
    let audit_before = host.audit_for(&id).len();

    let record = host
        .quarantine(
            fixture.artifact(id.as_str(), b"resubmitted", &["observe"]),
            NOW + 2,
        )
        .expect("revoked record remains addressable");

    assert_eq!(record.state(), PluginState::Revoked);
    assert_eq!(
        host.record(&id).expect("record").state(),
        PluginState::Revoked
    );
    assert_eq!(host.audit_for(&id).len(), audit_before);
}
