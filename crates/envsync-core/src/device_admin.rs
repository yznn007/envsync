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

use std::path::Path;

use envsync_crypto::device::{verify, DeviceKeypair, DevicePublic, Signature};
use envsync_crypto::recovery::{Argon2Params, RecoveryPackage, RecoveryPhrase};
use envsync_crypto::suite::{KeyEpoch, Plaintext};
use envsync_domain::cbor::{encode, CborCodec, CborError, Value};
use envsync_domain::id::{DeviceId, Digest32, WorkspaceId};
use envsync_domain::membership::{DevicePublicBytes, MemberRole, MembershipAction};
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
        let next_state = membership::verify_membership_chain(&genesis, &events)?;
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
        return Err(VaultError::InvitationInvalid {
            reason: "格式版本不受支持",
        }
        .into());
    }
    if invitation.workspace != deps.workspace {
        return Err(VaultError::InvitationInvalid {
            reason: "邀请属于另一个工作区",
        }
        .into());
    }
    let now = deps.clock.now_unix_ms();
    if now > invitation.expires_at_unix_ms {
        return Err(VaultError::InvitationInvalid {
            reason: "邀请已过期",
        }
        .into());
    }
    let checkpoints = std::sync::Arc::clone(&deps.checkpoints);
    let clock = std::sync::Arc::clone(&deps.clock);
    let workspace = deps.workspace;

    let service = VaultService::open(deps, state_dir)?;
    if service.device_id() != invitation.subject {
        return Err(VaultError::InvitationInvalid {
            reason: "邀请不是发给本设备的",
        }
        .into());
    }
    // 信任根：链必须从**邀请里写的那个 genesis** 延伸而来。后端声称的 genesis 不作数。
    if service.genesis_object() != Some(invitation.genesis) {
        return Err(VaultError::InvitationInvalid {
            reason: "后端上的 genesis 与邀请中的信任根不符",
        }
        .into());
    }
    // `VaultService::open` 已经从 genesis 完整回放并验证了整条链，这里只需要用验证结果
    // 判断「签发者当时是不是管理员」。
    let state = service.membership()?;
    let inviter = state
        .member(&invitation.inviter)
        .ok_or(VaultError::InvitationInvalid {
            reason: "邀请签发者不是当前成员",
        })?;
    if !inviter.role.can_administer() {
        return Err(VaultError::InvitationInvalid {
            reason: "邀请签发者不是管理员",
        }
        .into());
    }
    let signature =
        <[u8; envsync_crypto::suite::SIGNATURE_LEN]>::try_from(invitation.signature.as_slice())
            .map_err(|_| VaultError::InvitationInvalid {
                reason: "签名长度不符",
            })?;
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
    .map_err(|_| VaultError::InvitationInvalid {
        reason: "邀请签名验证失败",
    })?;
    if !state.contains(&invitation.subject) {
        return Err(VaultError::InvitationInvalid {
            reason: "本设备尚未被加入成员链",
        }
        .into());
    }

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
    use envsync_platform::InMemorySecureStore;

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
}
