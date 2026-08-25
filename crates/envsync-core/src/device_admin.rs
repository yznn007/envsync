//! 设备管理：身份、邀请、加入、清单与工作区恢复。
//!
//! 撤销与随之而来的密钥轮换在 [`crate::rotation`]；这里负责其余四件事。
//!
//! ## 设备身份存在哪里
//!
//! 两把私钥分别写进系统安全存储的
//! [`SecurePurpose::DeviceKemKey`]（X25519）与
//! [`SecurePurpose::DeviceSigningKey`]（Ed25519），都是**工作区级**坐标
//! （account 名里的设备段是占位符 `-`）。原因很直白：要构造 `DeviceId` 就得先有两把
//! 公钥，而公钥要从私钥算出来——用 `DeviceId` 去给自己的私钥编址是个死循环。
//!
//! ## 邀请对象里没有任何私有材料
//!
//! [`DeviceInvitation`] 只包含：工作区、邀请者设备、genesis 对象标识、当前链头与纪元、
//! 一次性挑战、有效期和**管理员签名**。它可以走任意不受信任的通道（聊天、邮件、二维码）
//! 传给新设备，泄露它的后果仅仅是「别人知道有这么个工作区」——它既不能用来解密任何
//! 东西，也不能用来把自己加进成员链（加入动作是管理员在 [`invite`] 里签的）。
//!
//! 一次性挑战的作用不是认证，而是**让每一份邀请都是不同的对象**：没有它的话，同一个
//! 管理员在同一毫秒邀请同一台设备会产出字节相同的两份邀请，审计日志里就分不出这是两次
//! 操作还是一次重放。
//!
//! ## 加入流程
//!
//! ```text
//! 新设备: device init            → 生成身份，打印公开材料
//! 管理员: device invite <公开材料> → 链上追加 AddMember + 发一份当前纪元信封 + 产出邀请
//! 新设备: device join <邀请>      → 从 genesis 完整验链 → 验邀请签名 → 打开信封
//!                                  → 建立初始反回滚检查点
//! ```
//!
//! 新设备**不信任**后端给的链头，它信任的是邀请里那个 genesis 对象标识：链必须从那个
//! genesis 完整延伸到当前头，中间任何一环不合法都拒绝。

use std::collections::BTreeMap;
use std::path::Path;

use envsync_backend::gist_bundle::{
    unpack as unpack_gist_bundle, GistBundleBootstrap, GistBundleError, GistBundleObject,
    GistBundleVerifier, UnpackedGistBundle,
};
use envsync_crypto::device::{verify, DeviceKeypair, DevicePublic, Signature};
use envsync_crypto::envelope::{open_envelope, KeyEnvelope};
use envsync_crypto::recovery::{Argon2Params, RecoveryPackage, RecoveryPhrase};
use envsync_crypto::suite::{DataKey, KeyEpoch, Plaintext};
use envsync_domain::cbor::{encode, CborCodec, CborError, Value};
use envsync_domain::id::{DeviceId, Digest32, WorkspaceId};
use envsync_domain::membership::{
    DevicePublicBytes, MemberRole, MembershipAction, MembershipEvent, MembershipState,
};
use envsync_domain::object::{ObjectId, ObjectKind};
use envsync_platform::secure_store::{SecureKey, SecurePurpose, SecureStore};

use crate::checkpoint::Checkpoint;
use crate::error::{CoreError, CoreResult};
use crate::membership;
use crate::vault::{KeyRing, VaultDeps, VaultError, VaultService};

/// 邀请对象的格式版本。
pub const INVITATION_FORMAT_VERSION: u32 = 1;

/// 邀请签名使用的用途标签。
///
/// 它进入 [`envsync_crypto::device::signing_input`] 的待签结构，因此一枚邀请签名无法
/// 被当作成员事件签名或快照签名复用。
pub const INVITATION_SIGNATURE_DOMAIN: &str = "device-invitation";

/// 一次性挑战的字节数。
pub const INVITATION_CHALLENGE_LEN: usize = 32;

/// 邀请的默认有效期：24 小时。
///
/// 邀请本身不含秘密，设上限不是为了防泄露，而是为了让「链头」这条信息不至于陈旧到
/// 毫无意义——一份两个月前的邀请里写的链头，新设备拿去比对只会白白报错。
pub const INVITATION_DEFAULT_TTL_MS: u64 = 24 * 60 * 60 * 1000;

/// 管理员签发的设备邀请。
///
/// **不含任何私有材料**，见模块文档。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInvitation {
    /// 格式版本。
    pub format_version: u32,
    /// 工作区标识。
    pub workspace: WorkspaceId,
    /// 签发邀请的管理员设备。
    pub inviter: DeviceId,
    /// 被邀请的设备。
    pub subject: DeviceId,
    /// 被授予的角色。
    pub role: MemberRole,
    /// genesis 事件的对象标识：新设备的信任根。
    pub genesis: ObjectId,
    /// 签发时已验证的成员链头摘要。
    pub membership_head: Digest32,
    /// 该链头所在的 sequence。
    pub membership_sequence: u64,
    /// 签发时的密钥纪元。
    pub key_epoch: u64,
    /// 一次性挑战，保证每份邀请都是不同的对象。
    pub challenge: [u8; INVITATION_CHALLENGE_LEN],
    /// 签发时刻（Unix 毫秒）。
    pub created_at_unix_ms: u64,
    /// 过期时刻（Unix 毫秒）。
    pub expires_at_unix_ms: u64,
    /// 管理员对 [`DeviceInvitation::signing_payload`] 的 Ed25519 签名。
    pub signature: Vec<u8>,
}

impl DeviceInvitation {
    /// 待签的 canonical 字节：**除签名之外**的全部字段。
    pub fn signing_payload(&self) -> Vec<u8> {
        encode(&Value::Array(vec![
            Value::Uint(self.format_version as u64),
            self.workspace.to_value(),
            self.inviter.to_value(),
            self.subject.to_value(),
            self.role.to_value(),
            Value::Text(self.genesis.to_string()),
            self.membership_head.to_value(),
            Value::Uint(self.membership_sequence),
            Value::Uint(self.key_epoch),
            Value::Bytes(self.challenge.to_vec()),
            Value::Uint(self.created_at_unix_ms),
            Value::Uint(self.expires_at_unix_ms),
        ]))
    }

    /// 邀请对象在后端中的标识。
    pub fn object_id(&self) -> ObjectId {
        ObjectId::for_bytes(ObjectKind::Blob, &self.to_canonical_vec())
    }
}

impl CborCodec for DeviceInvitation {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Uint(self.format_version as u64),
            self.workspace.to_value(),
            self.inviter.to_value(),
            self.subject.to_value(),
            self.role.to_value(),
            Value::Text(self.genesis.to_string()),
            self.membership_head.to_value(),
            Value::Uint(self.membership_sequence),
            Value::Uint(self.key_epoch),
            Value::Bytes(self.challenge.to_vec()),
            Value::Uint(self.created_at_unix_ms),
            Value::Uint(self.expires_at_unix_ms),
            Value::Bytes(self.signature.clone()),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        if items.len() != 13 {
            return Err(CborError::ArityMismatch);
        }
        let format_version = u32::from_value(&items[0])?;
        if format_version != INVITATION_FORMAT_VERSION {
            return Err(CborError::UnsupportedFormatVersion {
                found: format_version,
                supported: INVITATION_FORMAT_VERSION,
            });
        }
        Ok(DeviceInvitation {
            format_version,
            workspace: WorkspaceId::from_value(&items[1])?,
            inviter: DeviceId::from_value(&items[2])?,
            subject: DeviceId::from_value(&items[3])?,
            role: MemberRole::from_value(&items[4])?,
            genesis: items[5]
                .as_text()?
                .parse::<ObjectId>()
                .map_err(|error| CborError::InvalidValue(error.to_string()))?,
            membership_head: Digest32::from_value(&items[6])?,
            membership_sequence: items[7].as_uint()?,
            key_epoch: items[8].as_uint()?,
            challenge: <[u8; INVITATION_CHALLENGE_LEN]>::from_value(&items[9])?,
            created_at_unix_ms: items[10].as_uint()?,
            expires_at_unix_ms: items[11].as_uint()?,
            signature: Vec::<u8>::from_value(&items[12])?,
        })
    }
}

/// 经过邀请锚定验证、但尚未持久化的 Gist Bundle 当前纪元信任材料。
///
/// 它只由 [`verify_gist_bootstrap_for_invitation`] 构造。其内部 `DataKey` 不对调用方借出；
/// 只能由 [`Self::unpack`] 用于同一份 bundle 的完整 digest、签名与 AEAD 验证。验证失败时
/// 该对象连同候选密钥一起被销毁；只有成功时才会把 `DataKey` 随已验证 bundle 一起交出。
pub struct GistBootstrapTrust {
    workspace: WorkspaceId,
    epoch: KeyEpoch,
    data_key: DataKey,
    trusted_signers: BTreeMap<DeviceId, DevicePublic>,
}

impl std::fmt::Debug for GistBootstrapTrust {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GistBootstrapTrust")
            .field("workspace", &self.workspace)
            .field("epoch", &self.epoch)
            .field("trusted_signer_count", &self.trusted_signers.len())
            .finish_non_exhaustive()
    }
}

impl GistBootstrapTrust {
    /// 已验证的工作区标识。
    pub fn workspace(&self) -> WorkspaceId {
        self.workspace
    }

    /// 已验证的当前密钥纪元。
    pub fn epoch(&self) -> KeyEpoch {
        self.epoch
    }

    /// 验证并解开同一份 Gist Bundle，成功时交出已认证对象与当前数据密钥。
    ///
    /// 这条方法消费 `self`，从类型上禁止在完整解包成功前把候选密钥用于其他对象或写入
    /// 安全存储。返回的 `UnpackedGistBundle` 已通过 outer digest、成员链公钥验签、AEAD 认证
    /// 和 Snapshot/Vault 完整闭包检查。
    pub fn unpack(self, encoded: &str) -> Result<(UnpackedGistBundle, DataKey), GistBundleError> {
        let unpacked = {
            let verifier = GistBundleVerifier::from_m2(
                Some(self.workspace),
                Some(&self.data_key),
                Some(self.epoch),
                Some(self.trusted_signers.clone()),
            )?;
            unpack_gist_bundle(encoded, &verifier)?
        };
        Ok((unpacked, self.data_key))
    }
}

/// 用设备邀请锚定并验证 Gist 外层 bootstrap，取得仅供一次完整解包使用的候选信任材料。
///
/// Gist 公开 bootstrap 不是信任根：它在本函数中必须提供从邀请里的 genesis 到当前头的
/// 完整成员链，邀请签名必须与签发时的链锚点相符，而目标设备只能打开当前纪元中发给自己
/// 的 HPKE 信封。返回值仍不可直接持久化；必须对同一 bundle 调用
/// [`GistBootstrapTrust::unpack`]，它成功后才会一并交出已认证对象和可持久化的当前密钥。
pub fn verify_gist_bootstrap_for_invitation(
    invitation: &DeviceInvitation,
    bootstrap: &GistBundleBootstrap,
    device: &DeviceKeypair,
    now_unix_ms: u64,
) -> CoreResult<GistBootstrapTrust> {
    if bootstrap.workspace != invitation.workspace {
        return Err(gist_bootstrap_error("Gist 引导区属于另一个工作区"));
    }

    let (genesis, events) = gist_membership_chain(bootstrap, invitation.genesis)?;
    let state = validate_invitation_chain(
        invitation,
        bootstrap.workspace,
        device.device_id(),
        now_unix_ms,
        invitation.genesis,
        &genesis,
        &events,
    )?;
    gist_bootstrap_trust(bootstrap, state, device)
}

/// 用本地反回滚 checkpoint 锚定 Gist bootstrap，供已加入设备取得轮换后的当前纪元密钥。
///
/// 设备先用已验证 checkpoint 中的成员链摘要、sequence 和最小密钥纪元约束外层引导区；只有
/// bootstrap 给出的链严格延续这个锚点、设备仍是当前成员并含有发给本机的当前信封时，才会
/// 返回临时 [`GistBootstrapTrust`]。与邀请路径一样，返回值只能通过
/// [`GistBootstrapTrust::unpack`] 用于同一份 bundle，成功后才会交出新纪元 `DataKey`。
pub fn verify_gist_bootstrap_for_checkpoint(
    checkpoint: &Checkpoint,
    expected_genesis: ObjectId,
    bootstrap: &GistBundleBootstrap,
    device: &DeviceKeypair,
) -> CoreResult<GistBootstrapTrust> {
    if bootstrap.workspace != checkpoint.workspace {
        return Err(gist_bootstrap_error("Gist 引导区属于另一个工作区"));
    }
    let (genesis, events) = gist_membership_chain(bootstrap, expected_genesis)?;
    let state = membership::verify_membership_chain(&genesis, &events, bootstrap.workspace)
        .map_err(|_| gist_bootstrap_error("Gist 引导成员链无效"))?;
    validate_checkpoint_anchor(checkpoint, &genesis, &events, &state)?;
    gist_bootstrap_trust(bootstrap, state, device)
}

/// 设备清单里的一行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSummary {
    /// 设备标识。
    pub device: DeviceId,
    /// 当前角色。
    pub role: MemberRole,
    /// 加入时所在的 sequence。
    pub added_at_sequence: u64,
    /// 是否为本机。
    pub is_self: bool,
    /// 该设备是否持有当前纪元的信封。
    ///
    /// 为 `false` 说明它读不了新内容——正常情况下只会出现在「轮换还没做完」的窗口里。
    pub has_current_envelope: bool,
}

// ---------------------------------------------------------------------------
// 身份
// ---------------------------------------------------------------------------

/// 生成一次性挑战。
///
/// 随机数直接来自 [`rand_core::OsRng`]，与密码学层同源。它不是密钥材料——它的作用只是
/// 让每份邀请都是不同的对象，因此失败时报的是「系统随机数源不可用」而不是某个 Vault
/// 语义错误。
fn fresh_challenge() -> CoreResult<[u8; INVITATION_CHALLENGE_LEN]> {
    use rand_core::RngCore;
    let mut challenge = [0u8; INVITATION_CHALLENGE_LEN];
    rand_core::OsRng
        .try_fill_bytes(&mut challenge)
        .map_err(|_| CoreError::Crypto(envsync_crypto::CryptoError::Rng))?;
    Ok(challenge)
}

/// 某个工作区的设备签名私钥坐标。
fn signing_key(workspace: WorkspaceId) -> SecureKey {
    SecureKey::workspace_scoped(workspace, SecurePurpose::DeviceSigningKey)
}

/// 某个工作区的设备 KEM 私钥坐标。
fn kem_key(workspace: WorkspaceId) -> SecureKey {
    SecureKey::workspace_scoped(workspace, SecurePurpose::DeviceKemKey)
}

/// 生成本设备在该工作区的身份并写进安全存储。
///
/// 已经存在身份时**不覆盖**，直接返回既有的那一个：覆盖等于把这台设备踢出所有已发布的
/// 信封，而且没有任何办法撤销这个动作。
pub fn init_device(
    secure: &dyn SecureStore,
    workspace: WorkspaceId,
) -> CoreResult<(DeviceKeypair, bool)> {
    if let Some(existing) = load_device(secure, workspace)? {
        return Ok((existing, false));
    }
    let keypair = DeviceKeypair::generate()?;
    let secret = keypair.export_secret_bytes();
    secure.put(&kem_key(workspace), &secret[..32])?;
    // 两条记录分开写：任何一条失败都会让 `load_device` 返回 `None`，从而在下一次
    // `device init` 时被干净地重建，而不是留下半把可用的身份。
    secure.put(&signing_key(workspace), &secret[32..])?;
    Ok((keypair, true))
}

/// 从安全存储读回本设备在该工作区的身份。
///
/// 只有**两把私钥都在**才算有身份。任何一把读取失败都直接上抛（不伪装成 `None`）：
/// 「读不到」被误判成「没有」会让上层生成一把新身份，旧身份连同它能解开的一切就此消失。
pub fn load_device(
    secure: &dyn SecureStore,
    workspace: WorkspaceId,
) -> CoreResult<Option<DeviceKeypair>> {
    let (Some(kem), Some(signing)) = (
        secure.get(&kem_key(workspace))?,
        secure.get(&signing_key(workspace))?,
    ) else {
        return Ok(None);
    };
    let kem_bytes = <[u8; 32]>::try_from(kem.expose()).map_err(|_| {
        CoreError::Invariant("安全存储里的设备 KEM 私钥长度不是 32 字节".to_owned())
    })?;
    let signing_bytes = <[u8; 32]>::try_from(signing.expose())
        .map_err(|_| CoreError::Invariant("安全存储里的设备签名私钥长度不是 32 字节".to_owned()))?;
    Ok(Some(DeviceKeypair::from_secret_bytes(
        kem_bytes,
        signing_bytes,
    )?))
}

/// 删除本设备在该工作区的身份，返回是否真的删掉了东西。
///
/// # 危险
///
/// 删除之后本机再也无法解密任何内容，也无法签任何事件。它只应该出现在「这台设备要被
/// 报废」的流程里，并且必须先在别处完成撤销。
pub fn forget_device(secure: &dyn SecureStore, workspace: WorkspaceId) -> CoreResult<bool> {
    let kem = secure.delete(&kem_key(workspace))?;
    let signing = secure.delete(&signing_key(workspace))?;
    Ok(kem || signing)
}

// ---------------------------------------------------------------------------
// 清单
// ---------------------------------------------------------------------------

/// 列出工作区当前的全部成员设备。
pub fn list_devices(service: &VaultService) -> CoreResult<Vec<DeviceSummary>> {
    let state = service.membership()?;
    let me = service.device_id();
    let epoch = KeyEpoch::new(state.epoch);
    let holders = envelope_recipients(service, epoch)?;
    Ok(state
        .members
        .values()
        .map(|record| DeviceSummary {
            device: record.device,
            role: record.role,
            added_at_sequence: record.added_at_sequence,
            is_self: record.device == me,
            has_current_envelope: holders.contains(&record.device),
        })
        .collect())
}

/// 索引里当前纪元信封的收件设备集合。
fn envelope_recipients(
    service: &VaultService,
    epoch: KeyEpoch,
) -> CoreResult<std::collections::BTreeSet<DeviceId>> {
    let mut out = std::collections::BTreeSet::new();
    for object in &service.index().envelopes {
        let bytes = service.read_object(*object)?;
        let envelope = envsync_crypto::envelope::KeyEnvelope::from_canonical_slice(&bytes)?;
        if envelope.epoch() == epoch {
            out.insert(envelope.recipient());
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// 邀请与加入
// ---------------------------------------------------------------------------

/// 邀请一台设备加入工作区。
///
/// 做三件事，顺序不可换：
///
/// 1. 在成员链上追加 `AddMember`（这一步之后，那台设备就是成员了）；
/// 2. 用当前纪元的数据密钥给它封一份信封（这一步之后，它才**读得了**内容）；
/// 3. 产出一份带管理员签名的邀请对象，交给对方走 `device join`。
///
/// 先加成员再发信封：反过来的话，后端上会短暂出现一份发给「还不是成员」的设备的信封，
/// 任何做链校验的实现都会把它当成异常。
pub fn invite(
    service: &mut VaultService,
    subject_public: DevicePublic,
    role: MemberRole,
    ttl_ms: u64,
) -> CoreResult<DeviceInvitation> {
    service.require_admin()?;
    subject_public.validate()?;
    let subject = subject_public.device_id();
    let now = service.clock().now_unix_ms();

    let state = service.membership()?.clone();
    let mut index = service.index_clone();
    if !state.contains(&subject) {
        let event = membership::append(
            &state,
            service.keypair(),
            MembershipAction::AddMember {
                subject,
                public: DevicePublicBytes::from_parts(
                    subject_public.x25519,
                    subject_public.ed25519,
                ),
                role,
            },
            service.workspace(),
            now,
        )?;
        let object = service.put_membership_event(&event)?;
        index.membership.push(object);

        let genesis = service.genesis()?.clone();
        let mut events = service.events().to_vec();
        events.push(event.clone());
        let next_state =
            membership::verify_membership_chain(&genesis, &events, service.workspace())?;
        service.record_event(event, next_state);
    }

    // 给新设备发一份当前纪元的信封。已经有的话（重复邀请）不必再发。
    let ring = service.load_keyring()?;
    let epoch = ring.current_epoch();
    if !envelope_recipients(service, epoch)?.contains(&subject) {
        let envelope = service.publish_envelope(&subject_public, epoch, ring.current_key()?)?;
        index.envelopes.push(envelope);
    }
    index.epoch = service.membership()?.epoch;
    service.publish(index)?;

    let genesis_object = service.genesis_object().ok_or(VaultError::NotInitialized)?;
    let state = service.membership()?;
    let mut invitation = DeviceInvitation {
        format_version: INVITATION_FORMAT_VERSION,
        workspace: service.workspace(),
        inviter: service.device_id(),
        subject,
        role,
        genesis: genesis_object,
        membership_head: state.head,
        membership_sequence: state.sequence,
        key_epoch: state.epoch,
        challenge: fresh_challenge()?,
        created_at_unix_ms: now,
        expires_at_unix_ms: now.saturating_add(ttl_ms),
        signature: Vec::new(),
    };
    let signature = service.keypair().sign(
        INVITATION_SIGNATURE_DOMAIN,
        service.workspace(),
        &invitation.signing_payload(),
    )?;
    invitation.signature = signature.as_bytes().to_vec();
    Ok(invitation)
}

fn invitation_error(reason: &'static str) -> CoreError {
    VaultError::InvitationInvalid { reason }.into()
}

fn gist_bootstrap_error(reason: &'static str) -> CoreError {
    VaultError::GistBootstrapInvalid { reason }.into()
}

/// 校验一份邀请绑定的完整成员链，并返回当前链状态。
///
/// `genesis_object` 由调用方的可信对象目录或 Gist bootstrap 提供；它必须与邀请中的
/// genesis 标识一致。签发者权限与签名在**邀请锚点**处验证，目标设备成员资格则必须在
/// 当前链状态仍然有效：这样撤销目标设备会立即生效，而后来撤销签发管理员不会追溯性地
/// 使其已经有效签发的邀请失效。
fn validate_invitation_chain(
    invitation: &DeviceInvitation,
    workspace: WorkspaceId,
    local_device: DeviceId,
    now_unix_ms: u64,
    genesis_object: ObjectId,
    genesis: &MembershipEvent,
    events: &[MembershipEvent],
) -> CoreResult<MembershipState> {
    if invitation.format_version != INVITATION_FORMAT_VERSION {
        return Err(invitation_error("格式版本不受支持"));
    }
    if invitation.workspace != workspace {
        return Err(invitation_error("邀请属于另一个工作区"));
    }
    if invitation.expires_at_unix_ms < invitation.created_at_unix_ms {
        return Err(invitation_error("邀请有效期非法"));
    }
    if now_unix_ms > invitation.expires_at_unix_ms {
        return Err(invitation_error("邀请已过期"));
    }
    if invitation.subject != local_device {
        return Err(invitation_error("邀请不是发给本设备的"));
    }
    if genesis_object != invitation.genesis
        || membership::membership_object_id(genesis) != genesis_object
    {
        return Err(invitation_error("后端上的 genesis 与邀请中的信任根不符"));
    }

    let state = membership::verify_membership_chain(genesis, events, workspace)
        .map_err(|_| invitation_error("成员链无效"))?;
    let anchor_count = usize::try_from(invitation.membership_sequence)
        .map_err(|_| invitation_error("邀请成员链锚点非法"))?;
    let anchor_event = if invitation.membership_sequence == 0 {
        genesis
    } else {
        events
            .get(anchor_count.saturating_sub(1))
            .filter(|event| event.sequence == invitation.membership_sequence)
            .ok_or_else(|| invitation_error("邀请成员链锚点不符"))?
    };
    if anchor_event.digest() != invitation.membership_head
        || anchor_event.epoch != invitation.key_epoch
    {
        return Err(invitation_error("邀请成员链锚点不符"));
    }
    let anchor_state = membership::verify_membership_chain(
        genesis,
        events
            .get(..anchor_count)
            .ok_or_else(|| invitation_error("邀请成员链锚点不符"))?,
        workspace,
    )
    .map_err(|_| invitation_error("成员链无效"))?;
    let inviter = anchor_state
        .member(&invitation.inviter)
        .ok_or_else(|| invitation_error("邀请签发者不是锚点成员"))?;
    if !inviter.role.can_administer() {
        return Err(invitation_error("邀请签发者在锚点不是管理员"));
    }
    let signature =
        <[u8; envsync_crypto::suite::SIGNATURE_LEN]>::try_from(invitation.signature.as_slice())
            .map_err(|_| invitation_error("签名长度不符"))?;
    verify(
        &DevicePublic {
            x25519: inviter.public.x25519(),
            ed25519: inviter.public.ed25519(),
        },
        INVITATION_SIGNATURE_DOMAIN,
        workspace,
        &invitation.signing_payload(),
        &Signature::from_bytes(signature),
    )
    .map_err(|_| invitation_error("邀请签名验证失败"))?;
    if !state.contains(&invitation.subject) {
        return Err(invitation_error("本设备已不在当前成员链"));
    }
    Ok(state)
}

fn gist_membership_chain(
    bootstrap: &GistBundleBootstrap,
    expected_genesis: ObjectId,
) -> CoreResult<(MembershipEvent, Vec<MembershipEvent>)> {
    if bootstrap.membership.is_empty() {
        return Err(gist_bootstrap_error("Gist 引导区缺少成员链"));
    }
    let mut records = BTreeMap::new();
    for object in &bootstrap.membership {
        if !gist_object_matches(object, ObjectKind::MembershipEvent) {
            return Err(gist_bootstrap_error("Gist 引导成员记录非法"));
        }
        let event = MembershipEvent::from_canonical_slice(&object.bytes)
            .map_err(|_| gist_bootstrap_error("Gist 引导成员记录非法"))?;
        if event.workspace != bootstrap.workspace
            || membership::membership_object_id(&event) != object.id
            || records.insert(object.id, event).is_some()
        {
            return Err(gist_bootstrap_error("Gist 引导成员记录非法"));
        }
    }
    let genesis = records
        .remove(&expected_genesis)
        .ok_or_else(|| gist_bootstrap_error("Gist 引导区缺少信任根"))?;
    let mut events = records.into_values().collect::<Vec<_>>();
    events.sort_by_key(|event| event.sequence);
    Ok((genesis, events))
}

fn gist_recipient_envelope(
    bootstrap: &GistBundleBootstrap,
    recipient: DeviceId,
) -> CoreResult<KeyEnvelope> {
    if bootstrap.envelopes.is_empty() {
        return Err(gist_bootstrap_error("Gist 引导区缺少当前密钥信封"));
    }
    let mut ids = BTreeMap::new();
    let mut selected = None;
    for object in &bootstrap.envelopes {
        if !gist_object_matches(object, ObjectKind::KeyEnvelope)
            || ids.insert(object.id, ()).is_some()
        {
            return Err(gist_bootstrap_error("Gist 引导密钥信封非法"));
        }
        let envelope = KeyEnvelope::from_canonical_slice(&object.bytes)
            .map_err(|_| gist_bootstrap_error("Gist 引导密钥信封非法"))?;
        if envelope.workspace() != bootstrap.workspace || envelope.epoch() != bootstrap.epoch {
            return Err(gist_bootstrap_error("Gist 引导密钥信封非法"));
        }
        if envelope.recipient() == recipient && selected.replace(envelope).is_some() {
            return Err(gist_bootstrap_error("Gist 引导区存在重复的本机密钥信封"));
        }
    }
    selected.ok_or_else(|| gist_bootstrap_error("Gist 引导区没有发给本设备的当前密钥信封"))
}

fn gist_object_matches(object: &GistBundleObject, expected_kind: ObjectKind) -> bool {
    object.id.kind == expected_kind && object.id.verifies(&object.bytes)
}

fn validate_checkpoint_anchor(
    checkpoint: &Checkpoint,
    genesis: &MembershipEvent,
    events: &[MembershipEvent],
    state: &MembershipState,
) -> CoreResult<()> {
    let anchor_count = usize::try_from(checkpoint.membership_sequence)
        .map_err(|_| gist_bootstrap_error("本地成员链锚点非法"))?;
    let anchor_event = if checkpoint.membership_sequence == 0 {
        genesis
    } else {
        events
            .get(anchor_count.saturating_sub(1))
            .filter(|event| event.sequence == checkpoint.membership_sequence)
            .ok_or_else(|| gist_bootstrap_error("Gist 成员链未延续本地锚点"))?
    };
    if anchor_event.digest() != checkpoint.membership_digest {
        return Err(gist_bootstrap_error("Gist 成员链与本地锚点分叉"));
    }
    if state.epoch < checkpoint.key_epoch {
        return Err(gist_bootstrap_error("Gist 引导区回退了密钥纪元"));
    }
    Ok(())
}

fn gist_bootstrap_trust(
    bootstrap: &GistBundleBootstrap,
    state: MembershipState,
    device: &DeviceKeypair,
) -> CoreResult<GistBootstrapTrust> {
    if state.epoch != bootstrap.epoch.get() {
        return Err(gist_bootstrap_error("Gist 引导区密钥纪元与成员链不符"));
    }
    if !state.contains(&bootstrap.signer) {
        return Err(gist_bootstrap_error("Gist Bundle 签名者不是当前成员"));
    }
    if !state.contains(&device.device_id()) {
        return Err(gist_bootstrap_error("本设备不是当前成员"));
    }

    let envelope = gist_recipient_envelope(bootstrap, device.device_id())?;
    let data_key = open_envelope(device, &envelope)
        .map_err(|_| gist_bootstrap_error("Gist 引导密钥信封无效"))?;
    let trusted_signers = state
        .members
        .iter()
        .map(|(device, record)| {
            (
                *device,
                DevicePublic {
                    x25519: record.public.x25519(),
                    ed25519: record.public.ed25519(),
                },
            )
        })
        .collect();

    Ok(GistBootstrapTrust {
        workspace: bootstrap.workspace,
        epoch: bootstrap.epoch,
        data_key,
        trusted_signers,
    })
}

/// 用一份邀请加入工作区，并建立本机的初始反回滚检查点。
///
/// 检查顺序刻意是「便宜的先做」：格式 → 工作区 → 有效期 → 信任根 → 链验证 → 邀请签名
/// → 自己是不是成员 → 打开信封 → 写检查点。任何一步失败都不会在本机留下痕迹。
pub fn join(
    deps: VaultDeps,
    state_dir: &Path,
    invitation: &DeviceInvitation,
) -> CoreResult<VaultService> {
    if invitation.format_version != INVITATION_FORMAT_VERSION {
        return Err(invitation_error("格式版本不受支持"));
    }
    if invitation.workspace != deps.workspace {
        return Err(invitation_error("邀请属于另一个工作区"));
    }
    let now = deps.clock.now_unix_ms();
    if invitation.expires_at_unix_ms < invitation.created_at_unix_ms {
        return Err(invitation_error("邀请有效期非法"));
    }
    if now > invitation.expires_at_unix_ms {
        return Err(invitation_error("邀请已过期"));
    }
    let checkpoints = std::sync::Arc::clone(&deps.checkpoints);
    let clock = std::sync::Arc::clone(&deps.clock);
    let workspace = deps.workspace;

    let service = VaultService::open(deps, state_dir)?;
    let genesis_object = service.genesis_object().ok_or(VaultError::NotInitialized)?;
    let state = validate_invitation_chain(
        invitation,
        workspace,
        service.device_id(),
        now,
        genesis_object,
        service.genesis()?,
        service.events(),
    )?;

    // 拿到当前纪元的数据密钥。拿不到就说明管理员还没给本设备发信封，此时**不**建立
    // 检查点：一个读不了任何内容的信任根只会让后续操作以更难懂的方式失败。
    service.adopt_envelope()?;

    let head = service.head();
    let snapshot = head.head.ok_or(VaultError::IndexInconsistent {
        detail: "工作区没有头快照",
    })?;
    // 首次建立信任根：`check_advance(None, _)` 一律放行，背书来自上面刚验过的邀请签名。
    crate::checkpoint::advance(
        checkpoints.as_ref(),
        &Checkpoint {
            workspace,
            revision: head.revision,
            snapshot,
            membership_digest: state.head,
            membership_sequence: state.sequence,
            key_epoch: state.epoch,
            updated_at_unix_ms: clock.now_unix_ms(),
        },
    )?;
    Ok(service)
}

// ---------------------------------------------------------------------------
// 工作区恢复
// ---------------------------------------------------------------------------

/// [`create_recovery`] 的结果。
///
/// [`RecoveryPhrase`] 只能被展示**一次**（见
/// [`envsync_crypto::recovery::RecoveryPhrase::display_once`]），因此这里把它原样交还
/// 给调用方，由界面层决定怎么展示与提示抄写。
pub struct RecoveryOutcome {
    /// 恢复短语；只能展示一次。
    pub phrase: RecoveryPhrase,
    /// 恢复包在后端中的对象标识。
    pub package: ObjectId,
    /// 恢复包覆盖的纪元列表。
    pub epochs: Vec<u64>,
}

/// 生成恢复短语并把当前密钥环封成恢复包。
///
/// 恢复包同时写进后端（供其他设备取用）与本机安全存储（供离线恢复）。包本身是
/// Argon2id + AEAD 密文，放在不受信任的后端上是安全的。
pub fn create_recovery(service: &mut VaultService) -> CoreResult<RecoveryOutcome> {
    service.require_member()?;
    let ring = service.load_keyring()?;
    let epochs = ring.epochs();
    let phrase = RecoveryPhrase::generate()?;
    let payload = ring.to_secret_bytes();
    let package = RecoveryPackage::create(
        &phrase,
        Argon2Params::recommended(),
        &Plaintext::from_slice(&payload),
    )?;

    let bytes = package.to_canonical_vec();
    let object = ObjectId::for_bytes(ObjectKind::Blob, &bytes);
    service.write_object(object, &bytes)?;
    service.secure().put(
        &SecureKey::workspace_scoped(service.workspace(), SecurePurpose::RecoveryIdentity),
        &bytes,
    )?;

    let mut index = service.index_clone();
    index.recovery = Some(object);
    service.publish(index)?;

    Ok(RecoveryOutcome {
        phrase,
        package: object,
        epochs,
    })
}

/// 用恢复短语还原工作区密钥环。
///
/// 恢复包优先从本机安全存储读取，读不到再回后端索引指向的对象。口令错误只会得到一个
/// 统一的 [`envsync_crypto::CryptoError::Authentication`]——不给攻击者区分「短语错了」
/// 和「包被改了」的 oracle。
pub fn restore_recovery(service: &VaultService, phrase_text: &str) -> CoreResult<Vec<u64>> {
    let phrase = RecoveryPhrase::parse(phrase_text)?;
    let stored = service.secure().get(&SecureKey::workspace_scoped(
        service.workspace(),
        SecurePurpose::RecoveryIdentity,
    ))?;
    let bytes = match stored {
        Some(bytes) => bytes.expose().to_vec(),
        None => {
            let object = service
                .index()
                .recovery
                .ok_or(VaultError::IndexInconsistent {
                    detail: "工作区还没有创建过恢复包",
                })?;
            service.read_object(object)?
        }
    };
    let package = RecoveryPackage::from_canonical_slice(&bytes)?;
    let payload = package.open(&phrase)?;
    let restored = KeyRing::from_secret_bytes(payload.expose())?;
    let epochs = restored.epochs();
    // `payload` 与 `restored` 都在离开作用域时清零；返回的只有纪元号这类公开元数据。
    service.store_keyring(&restored)?;
    Ok(epochs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use envsync_backend::gist_bundle::{inspect_bootstrap, pack, GistBundleSigner};
    use envsync_crypto::envelope::seal_envelope;
    use envsync_crypto::vault::{VaultIndex, VAULT_INDEX_METADATA_KEY};
    use envsync_domain::{SnapshotBody, SnapshotId, StateRoot, WorkspaceRef};
    use envsync_platform::InMemorySecureStore;

    fn gist_bootstrap_fixture() -> (String, DeviceInvitation, DeviceKeypair, DataKey) {
        let workspace = WorkspaceId::generate();
        let admin = DeviceKeypair::generate().expect("生成管理员设备");
        let subject = DeviceKeypair::generate().expect("生成被邀请设备");
        let genesis = membership::create_genesis(&admin, workspace, 100).expect("生成 genesis");
        let initial =
            membership::verify_membership_chain(&genesis, &[], workspace).expect("验证 genesis");
        let subject_public = subject.public();
        let add_subject = membership::append(
            &initial,
            &admin,
            MembershipAction::AddMember {
                subject: subject.device_id(),
                public: DevicePublicBytes::from_parts(
                    subject_public.x25519,
                    subject_public.ed25519,
                ),
                role: MemberRole::Member,
            },
            workspace,
            101,
        )
        .expect("加入设备");
        let state = membership::verify_membership_chain(
            &genesis,
            std::slice::from_ref(&add_subject),
            workspace,
        )
        .expect("验证成员链");
        let data_key = DataKey::generate().expect("生成数据密钥");
        let recipient_envelope =
            seal_envelope(&subject_public, workspace, KeyEpoch::INITIAL, &data_key)
                .expect("生成收件信封");

        let genesis_bytes = genesis.to_canonical_vec();
        let genesis_id = membership::membership_object_id(&genesis);
        let add_bytes = add_subject.to_canonical_vec();
        let add_id = membership::membership_object_id(&add_subject);
        let envelope_bytes = recipient_envelope.to_canonical_vec();
        let envelope_id = ObjectId::for_bytes(ObjectKind::KeyEnvelope, &envelope_bytes);
        let mut index = VaultIndex::empty(workspace, state.epoch);
        index.membership = vec![genesis_id, add_id];
        index.envelopes = vec![envelope_id];
        let index_bytes = index.to_canonical_vec();
        let index_id = ObjectId::for_bytes(ObjectKind::Blob, &index_bytes);
        let root = StateRoot::empty();
        let mut metadata = BTreeMap::new();
        metadata.insert(VAULT_INDEX_METADATA_KEY.to_owned(), index_id.to_string());
        let snapshot = SnapshotBody::new(
            workspace,
            Vec::new(),
            root.id(),
            admin.device_id(),
            102,
            metadata,
        )
        .expect("构造头快照");
        let reference = WorkspaceRef::initial(workspace).advance(snapshot.id());
        let encoded = pack(
            &reference,
            vec![
                GistBundleObject::new(ObjectId::from(snapshot.id()), snapshot.to_canonical_vec()),
                GistBundleObject::new(ObjectId::from(root.id()), root.to_canonical_vec()),
                GistBundleObject::new(index_id, index_bytes),
                GistBundleObject::new(genesis_id, genesis_bytes),
                GistBundleObject::new(add_id, add_bytes),
                GistBundleObject::new(envelope_id, envelope_bytes),
            ],
            &GistBundleSigner::from_m2(Some(&data_key), Some(KeyEpoch::INITIAL), Some(&admin))
                .expect("构造 Bundle 签名器"),
        )
        .expect("打包 Gist Bundle");

        let mut invitation = DeviceInvitation {
            format_version: INVITATION_FORMAT_VERSION,
            workspace,
            inviter: admin.device_id(),
            subject: subject.device_id(),
            role: MemberRole::Member,
            genesis: genesis_id,
            membership_head: state.head,
            membership_sequence: state.sequence,
            key_epoch: state.epoch,
            challenge: [7u8; INVITATION_CHALLENGE_LEN],
            created_at_unix_ms: 102,
            expires_at_unix_ms: 200,
            signature: Vec::new(),
        };
        invitation.signature = admin
            .sign(
                INVITATION_SIGNATURE_DOMAIN,
                workspace,
                &invitation.signing_payload(),
            )
            .expect("签发邀请")
            .as_bytes()
            .to_vec();
        (encoded, invitation, subject, data_key)
    }

    fn rotated_gist_bootstrap_fixture() -> (
        String,
        Checkpoint,
        ObjectId,
        DeviceKeypair,
        DeviceKeypair,
        DataKey,
    ) {
        let workspace = WorkspaceId::generate();
        let admin = DeviceKeypair::generate().expect("生成管理员设备");
        let survivor = DeviceKeypair::generate().expect("生成保留设备");
        let revoked = DeviceKeypair::generate().expect("生成待撤销设备");
        let genesis = membership::create_genesis(&admin, workspace, 100).expect("生成 genesis");
        let initial =
            membership::verify_membership_chain(&genesis, &[], workspace).expect("验证 genesis");
        let survivor_public = survivor.public();
        let add_survivor = membership::append(
            &initial,
            &admin,
            MembershipAction::AddMember {
                subject: survivor.device_id(),
                public: DevicePublicBytes::from_parts(
                    survivor_public.x25519,
                    survivor_public.ed25519,
                ),
                role: MemberRole::Member,
            },
            workspace,
            101,
        )
        .expect("加入保留设备");
        let state_after_survivor = membership::verify_membership_chain(
            &genesis,
            std::slice::from_ref(&add_survivor),
            workspace,
        )
        .expect("验证第一段成员链");
        let revoked_public = revoked.public();
        let add_revoked = membership::append(
            &state_after_survivor,
            &admin,
            MembershipAction::AddMember {
                subject: revoked.device_id(),
                public: DevicePublicBytes::from_parts(
                    revoked_public.x25519,
                    revoked_public.ed25519,
                ),
                role: MemberRole::Member,
            },
            workspace,
            102,
        )
        .expect("加入待撤销设备");
        let state_before_revoke = membership::verify_membership_chain(
            &genesis,
            &[add_survivor.clone(), add_revoked.clone()],
            workspace,
        )
        .expect("验证撤销前成员链");
        let revoke = membership::append(
            &state_before_revoke,
            &admin,
            MembershipAction::Revoke {
                subject: revoked.device_id(),
            },
            workspace,
            103,
        )
        .expect("撤销设备并推进纪元");
        let events = vec![add_survivor.clone(), add_revoked.clone(), revoke.clone()];
        let state = membership::verify_membership_chain(&genesis, &events, workspace)
            .expect("验证当前成员链");
        assert_eq!(state.epoch, 2);

        let data_key = DataKey::generate().expect("生成轮换后的数据密钥");
        let current_epoch = KeyEpoch::new(state.epoch);
        let survivor_envelope =
            seal_envelope(&survivor_public, workspace, current_epoch, &data_key)
                .expect("给保留设备生成当前信封");
        let envelope_bytes = survivor_envelope.to_canonical_vec();
        let envelope_id = ObjectId::for_bytes(ObjectKind::KeyEnvelope, &envelope_bytes);
        let genesis_id = membership::membership_object_id(&genesis);
        let membership_records = vec![
            (genesis_id, genesis.to_canonical_vec()),
            (
                membership::membership_object_id(&add_survivor),
                add_survivor.to_canonical_vec(),
            ),
            (
                membership::membership_object_id(&add_revoked),
                add_revoked.to_canonical_vec(),
            ),
            (
                membership::membership_object_id(&revoke),
                revoke.to_canonical_vec(),
            ),
        ];
        let mut index = VaultIndex::empty(workspace, state.epoch);
        index.membership = membership_records.iter().map(|(id, _)| *id).collect();
        index.envelopes = vec![envelope_id];
        let index_bytes = index.to_canonical_vec();
        let index_id = ObjectId::for_bytes(ObjectKind::Blob, &index_bytes);
        let root = StateRoot::empty();
        let mut metadata = BTreeMap::new();
        metadata.insert(VAULT_INDEX_METADATA_KEY.to_owned(), index_id.to_string());
        let snapshot = SnapshotBody::new(
            workspace,
            Vec::new(),
            root.id(),
            admin.device_id(),
            104,
            metadata,
        )
        .expect("构造轮换后的头快照");
        let reference = WorkspaceRef::initial(workspace).advance(snapshot.id());
        let mut objects = vec![
            GistBundleObject::new(ObjectId::from(snapshot.id()), snapshot.to_canonical_vec()),
            GistBundleObject::new(ObjectId::from(root.id()), root.to_canonical_vec()),
            GistBundleObject::new(index_id, index_bytes),
            GistBundleObject::new(envelope_id, envelope_bytes),
        ];
        objects.extend(
            membership_records
                .into_iter()
                .map(|(id, bytes)| GistBundleObject::new(id, bytes)),
        );
        let encoded = pack(
            &reference,
            objects,
            &GistBundleSigner::from_m2(Some(&data_key), Some(current_epoch), Some(&admin))
                .expect("构造轮换后的 Bundle 签名器"),
        )
        .expect("打包轮换后的 Gist Bundle");
        let checkpoint = Checkpoint {
            workspace,
            revision: 1,
            snapshot: SnapshotId::of(b"pre-rotation-snapshot"),
            membership_digest: state_after_survivor.head,
            membership_sequence: state_after_survivor.sequence,
            key_epoch: state_after_survivor.epoch,
            updated_at_unix_ms: 102,
        };
        (encoded, checkpoint, genesis_id, survivor, revoked, data_key)
    }

    #[test]
    fn init_device_is_idempotent_and_persists_both_keys() {
        let store = InMemorySecureStore::new();
        let workspace = WorkspaceId::generate();
        assert!(load_device(&store, workspace).expect("读取").is_none());

        let (first, created) = init_device(&store, workspace).expect("生成身份");
        assert!(created);
        let (second, created_again) = init_device(&store, workspace).expect("再次生成");
        assert!(!created_again, "已有身份不得被覆盖");
        assert_eq!(first.device_id(), second.device_id());

        let loaded = load_device(&store, workspace).expect("读取").expect("存在");
        assert_eq!(loaded.device_id(), first.device_id());

        // account 名里只有工作区、设备占位与用途，没有任何密钥材料。
        let names = store.account_names();
        assert!(names.iter().any(|name| name.ends_with("/device-kem-key")));
        assert!(names
            .iter()
            .any(|name| name.ends_with("/device-signing-key")));
    }

    #[test]
    fn forget_device_removes_both_keys() {
        let store = InMemorySecureStore::new();
        let workspace = WorkspaceId::generate();
        init_device(&store, workspace).expect("生成身份");
        assert!(forget_device(&store, workspace).expect("删除"));
        assert!(!forget_device(&store, workspace).expect("再次删除"));
        assert!(load_device(&store, workspace).expect("读取").is_none());
    }

    #[test]
    fn invitation_round_trips_and_signing_payload_excludes_the_signature() {
        let invitation = DeviceInvitation {
            format_version: INVITATION_FORMAT_VERSION,
            workspace: WorkspaceId::generate(),
            inviter: DeviceId::derive(b"inviter"),
            subject: DeviceId::derive(b"subject"),
            role: MemberRole::Member,
            genesis: ObjectId::for_bytes(ObjectKind::MembershipEvent, b"genesis"),
            membership_head: Digest32::domain_hash("test", b"head"),
            membership_sequence: 3,
            key_epoch: 2,
            challenge: [7u8; INVITATION_CHALLENGE_LEN],
            created_at_unix_ms: 1_700_000_000_000,
            expires_at_unix_ms: 1_700_000_086_400_000,
            signature: vec![9u8; 64],
        };
        let bytes = invitation.to_canonical_vec();
        assert_eq!(
            DeviceInvitation::from_canonical_slice(&bytes).expect("还原"),
            invitation
        );

        // 换一枚签名不改变待签内容——否则签名就把自己也签进去了。
        let mut tampered = invitation.clone();
        tampered.signature = vec![1u8; 64];
        assert_eq!(tampered.signing_payload(), invitation.signing_payload());
        assert_ne!(tampered.object_id(), invitation.object_id());
    }

    #[test]
    fn gist_bootstrap_uses_the_invitation_anchor_before_adopting_the_current_key() {
        let (encoded, invitation, subject, expected_key) = gist_bootstrap_fixture();
        let bootstrap = inspect_bootstrap(&encoded).expect("读取未验证引导区");
        let trust = verify_gist_bootstrap_for_invitation(&invitation, &bootstrap, &subject, 150)
            .expect("邀请锚定验证成功");
        assert_eq!(trust.workspace(), invitation.workspace);
        assert_eq!(trust.epoch(), KeyEpoch::INITIAL);

        let (unpacked, adopted_key) = trust
            .unpack(&encoded)
            .expect("完整 Bundle 通过验签、认证和闭包后才交出数据密钥");
        assert_eq!(unpacked.reference.workspace, invitation.workspace);
        assert!(adopted_key == expected_key);
    }

    #[test]
    fn gist_bootstrap_rejects_a_chain_without_the_invitation_anchor() {
        let (encoded, invitation, subject, _) = gist_bootstrap_fixture();
        let mut bootstrap = inspect_bootstrap(&encoded).expect("读取未验证引导区");
        bootstrap
            .membership
            .retain(|object| object.id != invitation.genesis);

        let error = verify_gist_bootstrap_for_invitation(&invitation, &bootstrap, &subject, 150)
            .expect_err("没有邀请信任根不得打开候选信封");
        assert_eq!(error.code(), "vault.gist_bootstrap_invalid");
    }

    #[test]
    fn gist_bootstrap_uses_a_checkpoint_to_adopt_a_rotated_epoch() {
        let (encoded, checkpoint, genesis, survivor, _, expected_key) =
            rotated_gist_bootstrap_fixture();
        let bootstrap = inspect_bootstrap(&encoded).expect("读取未验证引导区");
        let trust =
            verify_gist_bootstrap_for_checkpoint(&checkpoint, genesis, &bootstrap, &survivor)
                .expect("成员链严格延续 checkpoint 后可取得当前信封");
        assert_eq!(trust.epoch(), KeyEpoch::new(2));

        let (unpacked, adopted_key) = trust
            .unpack(&encoded)
            .expect("当前纪元必须通过完整 Bundle 验证");
        assert_eq!(unpacked.epoch, KeyEpoch::new(2));
        assert!(adopted_key == expected_key);
    }

    #[test]
    fn gist_bootstrap_never_reenables_a_revoked_checkpoint_holder() {
        let (encoded, checkpoint, genesis, _, revoked, _) = rotated_gist_bootstrap_fixture();
        let bootstrap = inspect_bootstrap(&encoded).expect("读取未验证引导区");

        let error =
            verify_gist_bootstrap_for_checkpoint(&checkpoint, genesis, &bootstrap, &revoked)
                .expect_err("被撤销设备不得从公开 bootstrap 取得当前密钥");
        assert_eq!(error.code(), "vault.gist_bootstrap_invalid");
    }
}
