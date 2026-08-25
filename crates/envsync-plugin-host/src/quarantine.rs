//! 插件入口制品的验签、quarantine、审批和撤销。
//!
//! 此模块处理主动内容的第一道 Host 边界：入口制品必须先与 manifest 中被签名的摘要匹配，
//! 再经过受信任发布者验签，之后才可写进不可执行的 quarantine。启用仍要经过 policy 和
//! 明确确认；任何验证失败都只产生阻断记录，绝不把不可信字节写入 runtime。

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use envsync_core::bundles::{
    publisher_fingerprint, publisher_namespace, PublisherRegistry, PublisherStatus,
};
use envsync_crypto::device::{verify, DevicePublic, Signature};
use envsync_domain::id::Digest32;
use envsync_domain::{DeviceProfile, Risk};
use envsync_plugin_api::{PluginCapability, PluginId, PluginManifest, PluginManifestError};
use envsync_policy::{Decision, Operation, PolicyFacts, PolicySet, ResourceKind};

/// 插件签名的域分隔标签。
///
/// 它与 Agent Bundle、成员事件和设备快照使用不同的标签，因而签给其他对象的签名不能被
/// 重放为插件签名。
pub const PLUGIN_SIGNATURE_DOMAIN: &str = "envsync-plugin";

const PLUGIN_MANIFEST_DIGEST_DOMAIN: &str = "envsync:plugin-manifest:v1";
const QUARANTINE_DIR_MODE: u32 = 0o700;
const QUARANTINE_FILE_MODE: u32 = 0o600;
const RUNTIME_FILE_MODE: u32 = 0o500;

/// 插件在 Host 上的生命周期状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginState {
    /// 已验证并写入不可执行 quarantine，尚未获用户批准。
    Quarantined,
    /// 已获当前 profile 的批准，但尚未创建可执行 runtime copy。
    Approved,
    /// 已创建 runtime copy 并允许后续受 sandbox 的 runner 启动。
    Enabled,
    /// 制品摘要、签名或发布者信任检查失败，或启用前信任已失效。
    Blocked,
    /// 发布者已撤销；这是不可自动恢复的降级状态。
    Revoked,
}

impl PluginState {
    /// 返回稳定的审计状态名称。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Quarantined => "quarantined",
            Self::Approved => "approved",
            Self::Enabled => "enabled",
            Self::Blocked => "blocked",
            Self::Revoked => "revoked",
        }
    }
}

/// Host 接收的单入口插件制品。
///
/// v1 只允许一个入口文件。`PluginArtifact` 不表示入口已经可信：调用方仍必须交给
/// [`PluginHost::quarantine`] 检查摘要、发布者和签名。
pub struct PluginArtifact {
    manifest: PluginManifest,
    entrypoint: Vec<u8>,
}

impl PluginArtifact {
    /// 用已解析的 manifest 与原始入口字节构造制品。
    pub fn new(manifest: PluginManifest, entrypoint: Vec<u8>) -> Self {
        Self {
            manifest,
            entrypoint,
        }
    }

    /// 返回制品声明的 manifest。
    pub fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
}

/// 已隔离插件的当前记录。
///
/// 该值不实现 `Debug`，以免绝对 quarantine/runtime 路径被意外写入日志。
#[derive(Clone)]
pub struct PluginRecord {
    id: PluginId,
    manifest_digest: Digest32,
    artifact_digest: [u8; 32],
    signer: [u8; 32],
    capabilities: BTreeSet<PluginCapability>,
    state: PluginState,
    quarantined_entry: Option<PathBuf>,
    runtime_entry: Option<PathBuf>,
}

impl PluginRecord {
    /// 返回插件标识。
    pub fn id(&self) -> &PluginId {
        &self.id
    }

    /// 返回当前生命周期状态。
    pub const fn state(&self) -> PluginState {
        self.state
    }

    /// 返回 quarantine 中的入口路径；阻断制品没有此路径。
    pub fn quarantined_entry(&self) -> Option<&Path> {
        self.quarantined_entry.as_deref()
    }

    /// 返回 runtime 中的入口路径；未启用或已阻断制品可能没有此路径。
    pub fn runtime_entry(&self) -> Option<&Path> {
        self.runtime_entry.as_deref()
    }

    /// 返回发布者的短指纹，而不是原始公钥。
    pub fn signer_fingerprint(&self) -> String {
        publisher_fingerprint(&self.signer)
    }
}

/// 一次用户批准，绑定内容、权限、profile 与发布者。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginApproval {
    id: PluginId,
    manifest_digest: Digest32,
    artifact_digest: [u8; 32],
    capabilities: BTreeSet<PluginCapability>,
    profile: String,
    signer: [u8; 32],
    approved_at_unix_ms: u64,
}

impl PluginApproval {
    /// 检查这次批准是否覆盖给定记录在目标 profile 上的启用。
    pub fn check_covers(&self, record: PluginRecord, profile: &str) -> Result<(), ApprovalGap> {
        if self.id != record.id {
            return Err(ApprovalGap::DifferentPlugin);
        }
        if self.signer != record.signer {
            return Err(ApprovalGap::SignerChanged);
        }
        if self.profile != profile {
            return Err(ApprovalGap::ProfileChanged);
        }
        let added: BTreeSet<PluginCapability> = record
            .capabilities
            .difference(&self.capabilities)
            .copied()
            .collect();
        if !added.is_empty() {
            return Err(ApprovalGap::CapabilitiesExpanded { added });
        }
        if self.artifact_digest != record.artifact_digest {
            return Err(ApprovalGap::ArtifactDigestChanged);
        }
        if self.manifest_digest != record.manifest_digest {
            return Err(ApprovalGap::ManifestDigestChanged);
        }
        Ok(())
    }

    /// 返回批准创建时刻（Unix 毫秒）。
    pub const fn approved_at_unix_ms(&self) -> u64 {
        self.approved_at_unix_ms
    }
}

/// 一次批准不再覆盖记录的原因。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ApprovalGap {
    /// 批准针对的是另一个插件。
    #[error("批准属于另一个插件")]
    DifferentPlugin,
    /// 发布者变更。
    #[error("插件发布者已变更")]
    SignerChanged,
    /// 目标 profile 变更。
    #[error("插件批准不属于当前 profile")]
    ProfileChanged,
    /// manifest 内容变更。
    #[error("插件 manifest 已变更")]
    ManifestDigestChanged,
    /// 入口制品字节变更。
    #[error("插件入口制品已变更")]
    ArtifactDigestChanged,
    /// 新版本声明了未被批准的 capability。
    #[error("插件声明了新增 capability")]
    CapabilitiesExpanded {
        /// 新增的 capability 集合。
        added: BTreeSet<PluginCapability>,
    },
}

/// Host 记录的一次状态变化。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginAuditEvent {
    from: Option<PluginState>,
    to: PluginState,
    at_unix_ms: u64,
}

impl PluginAuditEvent {
    /// 返回迁移前状态；首次记录为 `None`。
    pub const fn from(&self) -> Option<PluginState> {
        self.from
    }

    /// 返回迁移后状态。
    pub const fn to(&self) -> PluginState {
        self.to
    }

    /// 返回记录时刻（Unix 毫秒）。
    pub const fn at_unix_ms(&self) -> u64 {
        self.at_unix_ms
    }
}

/// 一次发布者撤销的汇总。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationOutcome {
    affected: usize,
}

impl RevocationOutcome {
    /// 返回被标为 revoked 的插件数量。
    pub const fn affected(&self) -> usize {
        self.affected
    }
}

/// 插件 Host 的安全错误。
///
/// 所有变体都避免保存不可信入口字节和本机绝对路径，因此可以安全地转成稳定错误码或写入
/// 脱敏诊断。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HostError {
    /// manifest 本身不符合 API 契约。
    #[error(transparent)]
    Manifest(#[from] PluginManifestError),
    /// 请求的插件不存在。
    #[error("插件记录不存在")]
    UnknownPlugin,
    /// 当前状态不允许此操作。
    #[error("插件当前状态不允许此操作")]
    InvalidState,
    /// 旧批准不覆盖当前插件记录。
    #[error("插件批准已失效：{0}")]
    ApprovalStale(#[from] ApprovalGap),
    /// policy 拒绝了前进迁移。
    #[error("策略拒绝插件启用")]
    PolicyDenied,
    /// policy 要求确认，但调用方没有给出确认。
    #[error("插件启用需要确认")]
    ConfirmationRequired,
    /// staging 后的入口字节与已签名摘要不一致。
    #[error("插件入口制品摘要不匹配")]
    ArtifactTampered,
    /// 隔离根或其分段不是安全的真实目录/文件。
    #[error("插件隔离路径不安全")]
    UnsafePath,
    /// 同一 manifest 已经存在 staging/runtime 目录。
    #[error("插件制品已经存在")]
    AlreadyStaged,
    /// 文件系统操作失败；绝不包含路径。
    #[error("插件文件系统操作失败：{operation}")]
    Io {
        /// 正在执行的固定操作名。
        operation: &'static str,
        /// 底层错误类别。
        kind: std::io::ErrorKind,
    },
}

impl HostError {
    /// 返回稳定、机器可读且不含敏感内容的错误码。
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Manifest(error) => error.code(),
            Self::UnknownPlugin => "plugin.host.unknown_plugin",
            Self::InvalidState => "plugin.host.invalid_state",
            Self::ApprovalStale(_) => "plugin.host.approval_stale",
            Self::PolicyDenied => "plugin.host.policy_denied",
            Self::ConfirmationRequired => "plugin.host.confirmation_required",
            Self::ArtifactTampered => "plugin.host.artifact_tampered",
            Self::UnsafePath => "plugin.host.unsafe_path",
            Self::AlreadyStaged => "plugin.host.already_staged",
            Self::Io { .. } => "plugin.host.io",
        }
    }

    fn io(operation: &'static str, error: &std::io::Error) -> Self {
        Self::Io {
            operation,
            kind: error.kind(),
        }
    }
}

/// 受 Host 控制的插件隔离仓和生命周期。
pub struct PluginHost {
    quarantine_root: PathBuf,
    runtime_root: PathBuf,
    publishers: PublisherRegistry,
    records: BTreeMap<PluginId, PluginRecord>,
    audit: BTreeMap<PluginId, Vec<PluginAuditEvent>>,
}

impl PluginHost {
    /// 打开或创建 Host 控制的 quarantine 和 runtime 根。
    ///
    /// 两个根的父目录必须已存在且不是符号链接；这避免了从不可信路径隐式创建任意层级。
    pub fn open(
        quarantine_root: impl AsRef<Path>,
        runtime_root: impl AsRef<Path>,
        publishers: PublisherRegistry,
    ) -> Result<Self, HostError> {
        let quarantine_root = open_root(quarantine_root.as_ref())?;
        let runtime_root = open_root(runtime_root.as_ref())?;
        Ok(Self {
            quarantine_root,
            runtime_root,
            publishers,
            records: BTreeMap::new(),
            audit: BTreeMap::new(),
        })
    }

    /// 校验并写入一份制品到不可执行 quarantine。
    ///
    /// 摘要、发布者或签名失败不是调用错误，而是一个可审计的 `Blocked` 记录；这些路径不会
    /// 写入任何入口文件。
    pub fn quarantine(
        &mut self,
        artifact: PluginArtifact,
        now_unix_ms: u64,
    ) -> Result<PluginRecord, HostError> {
        let id = artifact.manifest.id().clone();
        let record = match self.verify_artifact(&artifact)? {
            Verification::Blocked => self.blocked_record(&artifact)?,
            Verification::Trusted {
                manifest_digest,
                artifact_digest,
            } => {
                let staged_entry = self.stage_entry(&artifact, manifest_digest)?;
                PluginRecord {
                    id: id.clone(),
                    manifest_digest,
                    artifact_digest,
                    signer: artifact.manifest.publisher().public_key,
                    capabilities: artifact.manifest.capabilities().clone(),
                    state: PluginState::Quarantined,
                    quarantined_entry: Some(staged_entry),
                    runtime_entry: None,
                }
            }
        };

        self.disarm_existing_runtime(&id);
        self.replace_record(record.clone(), now_unix_ms);
        Ok(record)
    }

    /// 对一份已隔离制品创建绑定的批准。
    pub fn approve(
        &mut self,
        id: &PluginId,
        profile_name: &str,
        profile: &DeviceProfile,
        policy: &PolicySet,
        confirmed: bool,
        now_unix_ms: u64,
    ) -> Result<PluginApproval, HostError> {
        let record = self
            .records
            .get(id)
            .cloned()
            .ok_or(HostError::UnknownPlugin)?;
        if record.state != PluginState::Quarantined {
            return Err(HostError::InvalidState);
        }
        self.enforce_policy(&record, profile, policy, confirmed)?;

        let approval = PluginApproval {
            id: record.id.clone(),
            manifest_digest: record.manifest_digest,
            artifact_digest: record.artifact_digest,
            capabilities: record.capabilities.clone(),
            profile: profile_name.to_owned(),
            signer: record.signer,
            approved_at_unix_ms: now_unix_ms,
        };
        self.set_state(id, PluginState::Approved, now_unix_ms)?;
        Ok(approval)
    }

    /// 在批准仍覆盖记录且 policy 允许时创建 runtime copy。
    ///
    /// 参数保持平铺，调用方必须在每次启用时显式提供批准、profile、策略、确认与时钟，
    /// 避免把安全上下文藏进一个可被误复用的可选配置对象。
    #[allow(
        clippy::too_many_arguments,
        reason = "安全上下文必须在每次启用调用中显式出现"
    )]
    pub fn enable(
        &mut self,
        id: &PluginId,
        approval: &PluginApproval,
        profile_name: &str,
        profile: &DeviceProfile,
        policy: &PolicySet,
        confirmed: bool,
        now_unix_ms: u64,
    ) -> Result<(), HostError> {
        let record = self
            .records
            .get(id)
            .cloned()
            .ok_or(HostError::UnknownPlugin)?;
        if record.state != PluginState::Approved {
            return Err(HostError::InvalidState);
        }
        approval.check_covers(record.clone(), profile_name)?;
        if self.publishers.status(&record.signer) != PublisherStatus::Trusted {
            self.set_state(id, PluginState::Blocked, now_unix_ms)?;
            return Err(HostError::ArtifactTampered);
        }
        self.enforce_policy(&record, profile, policy, confirmed)?;

        let staged = record.quarantined_entry().ok_or(HostError::InvalidState)?;
        let entrypoint = fs::read(staged).map_err(|error| HostError::io("read_staged", &error))?;
        if artifact_digest(&entrypoint) != record.artifact_digest {
            self.set_state(id, PluginState::Blocked, now_unix_ms)?;
            return Err(HostError::ArtifactTampered);
        }
        let runtime_entry = self.write_runtime_entry(&record, &entrypoint)?;
        let current = self.records.get_mut(id).ok_or(HostError::UnknownPlugin)?;
        current.runtime_entry = Some(runtime_entry);
        self.set_state(id, PluginState::Enabled, now_unix_ms)
    }

    /// 撤销一把发布者公钥并立即禁用受影响插件。
    ///
    /// 这是止损动作，因此不会经过 policy；任何 I/O 失败都不能阻止状态降级。
    pub fn revoke_publisher(&mut self, publisher: [u8; 32], now_unix_ms: u64) -> RevocationOutcome {
        self.publishers.revoke(publisher);
        let affected_ids: Vec<PluginId> = self
            .records
            .iter()
            .filter_map(|(id, record)| {
                (record.signer == publisher && record.state != PluginState::Revoked)
                    .then_some(id.clone())
            })
            .collect();
        for id in &affected_ids {
            self.disarm_existing_runtime(id);
            let _ = self.set_state(id, PluginState::Revoked, now_unix_ms);
        }
        RevocationOutcome {
            affected: affected_ids.len(),
        }
    }

    /// 返回指定插件的当前记录。
    pub fn record(&self, id: &PluginId) -> Option<&PluginRecord> {
        self.records.get(id)
    }

    /// 返回指定插件的 append-only 状态审计记录。
    pub fn audit_for(&self, id: &PluginId) -> &[PluginAuditEvent] {
        self.audit.get(id).map(Vec::as_slice).unwrap_or(&[])
    }

    fn verify_artifact(&self, artifact: &PluginArtifact) -> Result<Verification, HostError> {
        let manifest = artifact.manifest();
        let manifest_digest = manifest_digest(manifest)?;
        let actual_artifact_digest = artifact_digest(&artifact.entrypoint);
        if actual_artifact_digest != *manifest.entrypoint_digest().as_bytes() {
            return Ok(Verification::Blocked);
        }
        if self.publishers.status(&manifest.publisher().public_key) != PublisherStatus::Trusted {
            return Ok(Verification::Blocked);
        }

        let public = DevicePublic {
            x25519: [0_u8; 32],
            ed25519: manifest.publisher().public_key,
        };
        let signature = Signature::from_bytes(manifest.signature().value);
        let payload = manifest.signing_payload()?;
        if verify(
            &public,
            PLUGIN_SIGNATURE_DOMAIN,
            publisher_namespace(),
            &payload,
            &signature,
        )
        .is_err()
        {
            return Ok(Verification::Blocked);
        }
        Ok(Verification::Trusted {
            manifest_digest,
            artifact_digest: actual_artifact_digest,
        })
    }

    fn blocked_record(&self, artifact: &PluginArtifact) -> Result<PluginRecord, HostError> {
        Ok(PluginRecord {
            id: artifact.manifest.id().clone(),
            manifest_digest: manifest_digest(artifact.manifest())?,
            artifact_digest: artifact_digest(&artifact.entrypoint),
            signer: artifact.manifest.publisher().public_key,
            capabilities: artifact.manifest.capabilities().clone(),
            state: PluginState::Blocked,
            quarantined_entry: None,
            runtime_entry: None,
        })
    }

    fn stage_entry(
        &self,
        artifact: &PluginArtifact,
        manifest_digest: Digest32,
    ) -> Result<PathBuf, HostError> {
        let directory = create_artifact_dir(
            &self.quarantine_root,
            artifact.manifest.id(),
            manifest_digest,
        )?;
        write_entry(
            &directory,
            artifact.manifest.entrypoint().as_str(),
            &artifact.entrypoint,
            QUARANTINE_FILE_MODE,
        )
    }

    fn write_runtime_entry(
        &self,
        record: &PluginRecord,
        entrypoint: &[u8],
    ) -> Result<PathBuf, HostError> {
        let directory =
            create_artifact_dir(&self.runtime_root, &record.id, record.manifest_digest)?;
        let staged_path = record.quarantined_entry().ok_or(HostError::InvalidState)?;
        let relative = staged_path
            .strip_prefix(
                self.quarantine_root
                    .join(record.id.as_str())
                    .join(record.manifest_digest.to_hex()),
            )
            .map_err(|_| HostError::UnsafePath)?;
        let relative = relative.to_str().ok_or(HostError::UnsafePath)?;
        write_entry(&directory, relative, entrypoint, RUNTIME_FILE_MODE)
    }

    fn enforce_policy(
        &self,
        record: &PluginRecord,
        profile: &DeviceProfile,
        policy: &PolicySet,
        confirmed: bool,
    ) -> Result<(), HostError> {
        let declared = capability_names(&record.capabilities);
        let signer = record.signer_fingerprint();
        let facts = PolicyFacts::new(
            ResourceKind::Plugin,
            Operation::Enable,
            Risk::High,
            profile.os,
        )
        .with_profile(profile)
        .with_declared_capabilities(&declared)
        .with_signer(&signer);
        match policy.evaluate(&facts).decision {
            Decision::Allow => Ok(()),
            Decision::Deny => Err(HostError::PolicyDenied),
            Decision::RequireConfirmation if confirmed => Ok(()),
            Decision::RequireConfirmation => Err(HostError::ConfirmationRequired),
        }
    }

    fn replace_record(&mut self, record: PluginRecord, now_unix_ms: u64) {
        let id = record.id.clone();
        let from = self
            .records
            .insert(id.clone(), record.clone())
            .map(|old| old.state);
        self.audit.entry(id).or_default().push(PluginAuditEvent {
            from,
            to: record.state,
            at_unix_ms: now_unix_ms,
        });
    }

    fn set_state(
        &mut self,
        id: &PluginId,
        to: PluginState,
        now_unix_ms: u64,
    ) -> Result<(), HostError> {
        let record = self.records.get_mut(id).ok_or(HostError::UnknownPlugin)?;
        let from = record.state;
        record.state = to;
        self.audit
            .entry(id.clone())
            .or_default()
            .push(PluginAuditEvent {
                from: Some(from),
                to,
                at_unix_ms: now_unix_ms,
            });
        Ok(())
    }

    fn disarm_existing_runtime(&self, id: &PluginId) {
        if let Some(path) = self.records.get(id).and_then(PluginRecord::runtime_entry) {
            let _ = strip_execute_bits(path);
        }
    }
}

enum Verification {
    Blocked,
    Trusted {
        manifest_digest: Digest32,
        artifact_digest: [u8; 32],
    },
}

fn manifest_digest(manifest: &PluginManifest) -> Result<Digest32, HostError> {
    let payload = manifest.signing_payload()?;
    Ok(Digest32::domain_hash(
        PLUGIN_MANIFEST_DIGEST_DOMAIN,
        &payload,
    ))
}

fn artifact_digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn capability_names(capabilities: &BTreeSet<PluginCapability>) -> BTreeSet<String> {
    capabilities
        .iter()
        .map(|capability| match capability {
            PluginCapability::Observe => "observe",
            PluginCapability::Render => "render",
            PluginCapability::PlanCommand => "plan-command",
            PluginCapability::Verify => "verify",
        })
        .map(str::to_owned)
        .collect()
}

fn open_root(root: &Path) -> Result<PathBuf, HostError> {
    let root = root.to_path_buf();
    match fs::symlink_metadata(&root) {
        Ok(_) => ensure_real_dir(&root)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = root.parent().ok_or(HostError::UnsafePath)?;
            ensure_real_dir(parent)?;
            match fs::create_dir(&root) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    ensure_real_dir(&root)?;
                }
                Err(error) => return Err(HostError::io("create_root", &error)),
            }
        }
        Err(error) => return Err(HostError::io("stat_root", &error)),
    }
    set_dir_mode(&root)?;
    Ok(root)
}

fn create_artifact_dir(
    root: &Path,
    id: &PluginId,
    manifest_digest: Digest32,
) -> Result<PathBuf, HostError> {
    let plugin_dir = ensure_child_dir(root, id.as_str())?;
    let digest_name = manifest_digest.to_hex();
    let directory = plugin_dir.join(&digest_name);
    match fs::symlink_metadata(&directory) {
        Ok(_) => return Err(HostError::AlreadyStaged),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(HostError::io("stat_artifact_dir", &error)),
    }
    match fs::create_dir(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(HostError::AlreadyStaged)
        }
        Err(error) => return Err(HostError::io("create_artifact_dir", &error)),
    }
    set_dir_mode(&directory)?;
    Ok(directory)
}

fn ensure_child_dir(parent: &Path, segment: &str) -> Result<PathBuf, HostError> {
    ensure_real_dir(parent)?;
    let child = parent.join(segment);
    match fs::symlink_metadata(&child) {
        Ok(_) => ensure_real_dir(&child)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match fs::create_dir(&child) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    ensure_real_dir(&child)?;
                }
                Err(error) => return Err(HostError::io("create_dir", &error)),
            }
            set_dir_mode(&child)?;
        }
        Err(error) => return Err(HostError::io("stat_dir", &error)),
    }
    Ok(child)
}

fn ensure_real_dir(path: &Path) -> Result<(), HostError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| HostError::io("stat_dir", &error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(HostError::UnsafePath);
    }
    Ok(())
}

fn write_entry(
    root: &Path,
    entrypoint: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<PathBuf, HostError> {
    let mut parent = root.to_path_buf();
    let mut segments = entrypoint.split('/').peekable();
    while let Some(segment) = segments.next() {
        if segments.peek().is_some() {
            parent = ensure_child_dir(&parent, segment)?;
        } else {
            let path = parent.join(segment);
            write_file(&path, bytes, mode)?;
            return Ok(path);
        }
    }
    Err(HostError::UnsafePath)
}

fn write_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), HostError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode & !0o111);
    }
    let mut file = options
        .open(path)
        .map_err(|error| HostError::io("create_file", &error))?;
    file.write_all(bytes)
        .map_err(|error| HostError::io("write_file", &error))?;
    file.sync_all()
        .map_err(|error| HostError::io("sync_file", &error))?;
    set_file_mode(path, mode)
}

fn set_dir_mode(path: &Path) -> Result<(), HostError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(QUARANTINE_DIR_MODE))
            .map_err(|error| HostError::io("chmod_dir", &error))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn set_file_mode(path: &Path, mode: u32) -> Result<(), HostError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777))
            .map_err(|error| HostError::io("chmod_file", &error))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

fn strip_execute_bits(path: &Path) -> Result<(), HostError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| HostError::io("stat_file", &error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(HostError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(metadata.permissions().mode() & !0o111),
        )
        .map_err(|error| HostError::io("chmod_file", &error))?;
    }
    Ok(())
}
