//! Vault 索引背书：让「后端交给我的这份索引，确实出自本工作区的一台成员设备」可验证。
//!
//! M2 之前，[`envsync_domain::SnapshotSignature`] 对象被写进后端，却**从来没有人读**。
//! 于是整条读路径上没有任何一处能回答「这份 Vault 索引是谁做的」：后端可以凭空造一份
//! 索引（改成员名单、把某条秘密指向自己的密封对象），只要结构自洽就会被接受。
//!
//! 本模块补上那一环。
//!
//! # 背书覆盖的是**索引对象标识**，不是快照标识
//!
//! 直觉上应该签快照。但快照签名放不进快照本身：
//!
//! ```text
//! 签名覆盖快照标识 → 签名要存起来 → 存哪儿？
//!   存成独立对象  → 对象是内容寻址的，标识 = hash(签名字节)
//!                   读者不知道签名字节，也就算不出该去读哪个对象；
//!                   把这个标识写回快照元数据 → 快照标识随之改变 → 签名失效（循环）
//!   存进快照元数据 → 元数据进快照标识 → 签名覆盖快照标识 → 循环
//! ```
//!
//! 还有第二个、更硬的约束：**一次普通 `envsync sync` 必须不能让 Vault 失效**。M0/M1 的
//! 发布路径没有设备签名密钥（它用的是配置里种子派生的 `DeviceId`，与成员链上的密码学
//! 设备标识根本不是同一个身份），却会在同一条 Ref 上发布新的头快照。如果背书绑定快照
//! 标识，那么每一次普通同步都会把背书打断，读路径只能二选一：要么拒绝（`sync` 之后
//! Vault 直接不可用），要么放行（背书形同虚设）。
//!
//! 因此背书覆盖的是 `(用途标签, 工作区, 索引对象标识)`：
//!
//! * 索引对象是内容寻址的，覆盖它的标识等于覆盖它的**全部内容**——成员链、信封、
//!   每一条 [`crate::vault::SecretRef`]；
//! * 索引对象标识是**工作区级**的元数据，普通同步只是把它原样继承过去（见
//!   [`crate::vault::WORKSPACE_METADATA_PREFIX`]），因此背书跟着一起继承，不会被打断。
//!
//! # 它挡得住什么、挡不住什么
//!
//! 挡得住：伪造索引（改名单、改指向、改纪元）——攻击者没有任何成员的私钥。
//!
//! 挡不住：把一份**旧的、真实签过的**索引重新挂到一个新 revision 上。这一层由反回滚
//! 检查点负责：revision / 成员链 sequence / 密钥纪元三条线都必须单调。**残留风险**：
//! 检查点不覆盖「索引里的秘密条目」，因此攻击者仍可能把秘密条目回退到同一纪元、同一
//! 成员链 sequence 的某个旧版本。要堵住它需要给索引本身加一条单调计数，那会让普通同步
//! 重新需要签名密钥——留待后续里程碑权衡。
//!
//! # 编码
//!
//! 背书是一段 ASCII 文本，放在快照元数据里（见
//! [`crate::vault::VAULT_ATTESTATION_METADATA_KEY`]）：
//!
//! ```text
//! ed25519:<设备标识 64 位小写十六进制>:<签名 128 位小写十六进制>
//! ```
//!
//! 刻意用文本而不是再套一层 CBOR：元数据的值类型就是 `String`，而这三段全是公开材料，
//! 多一层编码只会多一个解析失败面。

use envsync_crypto::device::{verify, DeviceKeypair, DevicePublic, Signature};
use envsync_crypto::suite::SIGNATURE_LEN;
use envsync_domain::id::{DeviceId, WorkspaceId};
use envsync_domain::membership::MembershipState;
use envsync_domain::object::ObjectId;

/// 索引背书使用的用途标签。
///
/// 它进入 [`envsync_crypto::device::signing_input`] 的待签结构，因此一枚索引背书无法被
/// 当作成员事件签名、邀请签名或快照签名复用。
pub const VAULT_ATTESTATION_DOMAIN: &str = "vault-index";

/// 真实签名时使用的算法标记。
pub const ATTESTATION_ALGORITHM: &str = "ed25519";

/// M0 兼容路径使用的「未签名」标记。
///
/// 只有**尚未建立成员链**的工作区才允许出现它：那种工作区上没有任何设备身份，也就
/// 没有任何一把可以用来签名的密钥。一旦 `vault create` 建立了成员链，读路径就不再接受
/// 它（见 [`verify_index_attestation`]）。
pub const ATTESTATION_ALGORITHM_NONE: &str = "none";

/// 背书校验失败。
///
/// 所有变体都只描述结构：设备标识是公开材料，可以出现；密钥材料与秘密值不会出现。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AttestationError {
    /// 工作区已建立成员链，头快照上却没有背书。
    #[error("头快照缺少 Vault 索引背书：本工作区已建立成员链，未签名的头不予接受")]
    Missing,

    /// 背书文本的形状不对（段数、算法标记、十六进制长度）。
    #[error("Vault 索引背书格式非法：{reason}")]
    Malformed {
        /// 静态原因，不回显任何内容。
        reason: &'static str,
    },

    /// 签发者不是当前成员链上的设备。
    #[error("Vault 索引背书的签发设备 {device} 不是本工作区的当前成员")]
    SignerNotAMember {
        /// 签发设备。
        device: DeviceId,
    },

    /// 签名本身验不过。
    #[error("Vault 索引背书的签名验证失败")]
    SignatureInvalid,
}

impl AttestationError {
    /// 稳定的机器可读错误码，用于 CLI 的 JSON 契约。
    ///
    /// 四个变体共用一个码：对调用方而言它们的补救动作完全相同（这份头不可信，别用），
    /// 而把「缺签名」和「签名错」分成两个码，等于免费告诉攻击者他卡在哪一步。
    pub fn code(&self) -> &'static str {
        "snapshot.signature_invalid"
    }
}

/// 待签内容：索引对象标识的规范文本形式。
///
/// 用 `ObjectId` 的 `Display`（`<kind>/<hex>`）而不是裸摘要：种类也进签名，避免有人把
/// 一个别的种类、恰好同摘要的对象标识塞进来。
fn payload(index: ObjectId) -> Vec<u8> {
    index.to_string().into_bytes()
}

/// 用本设备私钥给一份索引签一条背书。
pub fn sign_index_attestation(
    device: &DeviceKeypair,
    workspace: WorkspaceId,
    index: ObjectId,
) -> Result<String, envsync_crypto::CryptoError> {
    let signature = device.sign(VAULT_ATTESTATION_DOMAIN, workspace, &payload(index))?;
    Ok(format!(
        "{ATTESTATION_ALGORITHM}:{}:{}",
        device.device_id().to_hex(),
        hex_lower(signature.as_bytes())
    ))
}

/// 校验一条背书，返回签发设备。
///
/// # 两条路径
///
/// * `members` 为 `None`：工作区**尚未建立成员链**（还没跑过 `vault create`）。此时接受
///   缺失的背书，也接受 `algorithm == "none"` 的占位背书——没有成员链就没有可用来签名
///   的身份，要求签名等于要求一件不可能的事。
/// * `members` 为 `Some`：工作区**已建立成员链**。背书必须存在、必须是 `ed25519`、
///   必须由当前成员链上的设备签出、必须覆盖 `workspace` 与 `index`。
pub fn verify_index_attestation(
    raw: Option<&str>,
    workspace: WorkspaceId,
    index: ObjectId,
    members: Option<&MembershipState>,
) -> Result<Option<DeviceId>, AttestationError> {
    let Some(members) = members else {
        // 没有成员链：M0 兼容路径。这里刻意不去解析 `raw`——不存在的信任根验不出任何
        // 东西，假装验过一遍只会给读者一个错误的安全感。
        return Ok(None);
    };
    let Some(raw) = raw else {
        return Err(AttestationError::Missing);
    };

    let mut parts = raw.split(':');
    let (Some(algorithm), Some(device_hex), Some(signature_hex), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AttestationError::Malformed {
            reason: "应当是 `算法:设备:签名` 三段",
        });
    };
    if algorithm == ATTESTATION_ALGORITHM_NONE {
        // 已建立成员链的工作区上，`none` 不是「兼容」，是「没签」。
        return Err(AttestationError::Missing);
    }
    if algorithm != ATTESTATION_ALGORITHM {
        return Err(AttestationError::Malformed {
            reason: "算法标记不受支持",
        });
    }

    let device = device_hex
        .parse::<DeviceId>()
        .map_err(|_| AttestationError::Malformed {
            reason: "设备标识不是合法的十六进制摘要",
        })?;
    let bytes = decode_hex(signature_hex).ok_or(AttestationError::Malformed {
        reason: "签名不是合法的十六进制串",
    })?;
    let bytes = <[u8; SIGNATURE_LEN]>::try_from(bytes.as_slice()).map_err(|_| {
        AttestationError::Malformed {
            reason: "签名长度不符",
        }
    })?;

    // 先确认签发者现在**仍然**是成员：一台已被撤销的设备签过的旧背书不该继续生效。
    let record = members
        .member(&device)
        .ok_or(AttestationError::SignerNotAMember { device })?;
    let public = DevicePublic {
        x25519: record.public.x25519(),
        ed25519: record.public.ed25519(),
    };
    verify(
        &public,
        VAULT_ATTESTATION_DOMAIN,
        workspace,
        &payload(index),
        &Signature::from_bytes(bytes),
    )
    .map_err(|_| AttestationError::SignatureInvalid)?;
    Ok(Some(device))
}

/// 小写十六进制编码。
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// 小写十六进制解码；长度为奇数或含非十六进制字符时返回 `None`。
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::membership::{create_genesis, verify_membership_chain};
    use envsync_domain::object::ObjectKind;

    fn fixture() -> (WorkspaceId, DeviceKeypair, MembershipState, ObjectId) {
        let workspace = WorkspaceId::generate();
        let device = DeviceKeypair::generate().expect("生成设备");
        let genesis = create_genesis(&device, workspace, 1_700_000_000_000).expect("genesis");
        let state = verify_membership_chain(&genesis, &[], workspace).expect("链有效");
        let index = ObjectId::for_bytes(ObjectKind::Blob, b"vault-index");
        (workspace, device, state, index)
    }

    #[test]
    fn a_fresh_attestation_verifies_and_names_the_signer() {
        let (workspace, device, state, index) = fixture();
        let raw = sign_index_attestation(&device, workspace, index).expect("签名");
        assert_eq!(
            verify_index_attestation(Some(&raw), workspace, index, Some(&state)).expect("校验"),
            Some(device.device_id())
        );
    }

    #[test]
    fn an_attestation_never_covers_another_index_or_workspace() {
        let (workspace, device, state, index) = fixture();
        let raw = sign_index_attestation(&device, workspace, index).expect("签名");

        let other_index = ObjectId::for_bytes(ObjectKind::Blob, b"another-index");
        assert_eq!(
            verify_index_attestation(Some(&raw), workspace, other_index, Some(&state)).unwrap_err(),
            AttestationError::SignatureInvalid
        );

        let other_workspace = WorkspaceId::generate();
        assert_eq!(
            verify_index_attestation(Some(&raw), other_workspace, index, Some(&state)).unwrap_err(),
            AttestationError::SignatureInvalid
        );
    }

    #[test]
    fn a_signer_outside_the_chain_is_rejected() {
        let (workspace, _device, state, index) = fixture();
        let stranger = DeviceKeypair::generate().expect("生成设备");
        let raw = sign_index_attestation(&stranger, workspace, index).expect("签名");
        assert_eq!(
            verify_index_attestation(Some(&raw), workspace, index, Some(&state)).unwrap_err(),
            AttestationError::SignerNotAMember {
                device: stranger.device_id()
            }
        );
    }

    #[test]
    fn a_chain_bearing_workspace_never_accepts_a_missing_or_none_attestation() {
        let (workspace, _device, state, index) = fixture();
        assert_eq!(
            verify_index_attestation(None, workspace, index, Some(&state)).unwrap_err(),
            AttestationError::Missing
        );
        assert_eq!(
            verify_index_attestation(Some("none::"), workspace, index, Some(&state)).unwrap_err(),
            AttestationError::Missing
        );
    }

    #[test]
    fn a_chainless_workspace_still_accepts_an_unsigned_head() {
        let (workspace, _device, _state, index) = fixture();
        assert_eq!(
            verify_index_attestation(None, workspace, index, None).expect("兼容路径"),
            None
        );
    }

    #[test]
    fn malformed_shapes_are_rejected_before_any_curve_arithmetic() {
        let (workspace, device, state, index) = fixture();
        let good = sign_index_attestation(&device, workspace, index).expect("签名");
        let cases = [
            "",
            "ed25519",
            "ed25519:abc",
            "ed25519:abc:def:ghi",
            "rsa:00:00",
        ];
        for case in cases {
            assert!(
                verify_index_attestation(Some(case), workspace, index, Some(&state)).is_err(),
                "`{case}` 应当被拒绝"
            );
        }
        // 正向对照：合法的那一条必须通过，否则上面全是空转。
        assert!(verify_index_attestation(Some(&good), workspace, index, Some(&state)).is_ok());
    }

    #[test]
    fn the_error_code_is_a_single_stable_string() {
        assert_eq!(
            AttestationError::Missing.code(),
            "snapshot.signature_invalid"
        );
        assert_eq!(
            AttestationError::SignatureInvalid.code(),
            "snapshot.signature_invalid"
        );
    }
}
