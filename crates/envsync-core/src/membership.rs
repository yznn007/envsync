//! 成员事件链的验证器与编排 API。
//!
//! 领域层（[`envsync_domain::membership`]）只定义结构与编码；**判定一条链是否可信**
//! 发生在这里，因为这一步需要密码学。
//!
//! ## [`verify_membership_chain`] 是纯函数
//!
//! 它不读网络、不读数据库、不看时钟。输入是「我已经信任的 genesis」加上「后端声称的
//! 后续事件」，输出要么是一个可信的 [`MembershipState`]，要么是一个说明**哪一条
//! 事件、因为什么原因**被拒绝的 [`MembershipError`]。把这一步做成纯函数的意义在于：
//! 它可以被完整地做成攻击路径测试矩阵，而不需要搭出后端和数据库。
//!
//! ## 检查顺序（便宜的先做）
//!
//! ```text
//! 1. 结构限制：事件总数上限、genesis 形状、格式版本
//! 2. 逐事件：workspace → sequence（分叉/重复/回退/跳号）→ previous 链接
//!            → epoch 单调性与「只有撤销能推进纪元」
//!            → actor 解析（未知 / 已撤销）→ 验签 → 角色授权
//!            → 动作语义（重复 genesis、主体校验、最后一个管理员）
//! ```
//!
//! 曲线运算（验签）刻意排在最后一批：任何结构性问题都应该在做昂贵计算之前被拒绝。
//!
//! ## 密钥纪元规则
//!
//! * 非撤销事件**必须**保持纪元不变；
//! * 撤销事件**必须**把纪元恰好 `+1`。
//!
//! 双向都强制的好处是：纪元号变成了「撤销发生过多少次」的计数器，攻击者既不能悄悄
//! 前进纪元（骗设备去等一个不存在的新信封），也不能撤销设备却不轮换密钥（让已撤销
//! 设备继续能读新内容）。
//!
//! ## 持久化分工
//!
//! 成员事件对象本身保存在 Backend（[`envsync_domain::object::ObjectKind::MembershipEvent`]）；
//! SQLite 只保存**已验证**的链头与纪元（见 `envsync_storage::membership`）。本地
//! trusted checkpoint 必须在数据库事务提交**之后**才推进——顺序反过来的话，进程在
//! 两步之间崩溃就会留下「检查点已前进、链头却没落库」的不可恢复状态。

use std::collections::{BTreeMap, BTreeSet};

use envsync_crypto::device::{verify, DeviceKeypair, DevicePublic, Signature};
use envsync_crypto::CryptoError;
use envsync_domain::cbor::CborCodec;
use envsync_domain::id::{DeviceId, Digest32, WorkspaceId};
use envsync_domain::membership::{
    DevicePublicBytes, MemberRecord, MemberRole, MembershipAction, MembershipEvent,
    MembershipEventError, MembershipState, GENESIS_EPOCH, MAX_MEMBERSHIP_EVENTS,
    MEMBERSHIP_EVENT_FORMAT_VERSION, SIGNATURE_LEN,
};
use envsync_domain::object::{ObjectId, ObjectKind};

/// 成员事件签名使用的用途标签。
///
/// 它进入 [`envsync_crypto::device::signing_input`] 的待签结构，因此一枚成员事件的
/// 签名无法被当作快照签名或信封签名复用。
pub const MEMBERSHIP_SIGNATURE_DOMAIN: &str = "membership-event";

/// 成员链验证与编排错误。
///
/// 每个变体都带上出问题的 `sequence`，让「链的第几条事件坏了」在日志和 CLI 输出里
/// 一目了然。错误只描述结构，不携带密钥材料。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MembershipError {
    /// 事件数量超过 [`MAX_MEMBERSHIP_EVENTS`]，在做任何密码学运算前拒绝。
    #[error("成员链事件数量 {found} 超过上限 {limit}")]
    TooManyEvents {
        /// 上限。
        limit: usize,
        /// 实际数量（含 genesis）。
        found: usize,
    },

    /// 事件的结构性校验失败。
    #[error("sequence {sequence} 的事件结构非法：{source}")]
    Event {
        /// 出问题的事件位置。
        sequence: u64,
        /// 具体的结构性问题。
        #[source]
        source: MembershipEventError,
    },

    /// 第一条事件不是 genesis。
    #[error("成员链的第一条事件必须是 sequence 0 的 Genesis")]
    GenesisMissing,

    /// genesis 使用了错误的初始纪元。
    #[error("genesis 的密钥纪元必须是 {expected}，实际 {found}")]
    GenesisEpoch {
        /// 期望的纪元。
        expected: u64,
        /// 实际纪元。
        found: u64,
    },

    /// genesis 的签发者与被登记的管理员不是同一台设备。
    #[error("genesis 必须由被登记的管理员自己签名")]
    GenesisActorMismatch,

    /// genesis 之外出现了第二个 Genesis 动作。
    #[error("sequence {sequence} 出现了重复的 Genesis 动作")]
    DuplicateGenesis {
        /// 出问题的事件位置。
        sequence: u64,
    },

    /// 事件属于另一个工作区。
    #[error("sequence {sequence} 的事件属于另一个工作区")]
    WorkspaceMismatch {
        /// 出问题的事件位置。
        sequence: u64,
    },

    /// 同一个 sequence 上出现了两个**不同**的事件（链分叉）。
    #[error("sequence {sequence} 出现分叉：同一位置存在两个不同的事件")]
    ForkDetected {
        /// 分叉位置。
        sequence: u64,
    },

    /// 同一个事件被重复提交。
    #[error("sequence {sequence} 的事件重复出现")]
    DuplicateSequence {
        /// 重复位置。
        sequence: u64,
    },

    /// 出现了比当前链头更旧的事件（旧事件重放）。
    #[error("sequence 回退：链头在 {head}，却收到 sequence {found} 的旧事件")]
    SequenceRollback {
        /// 当前链头位置。
        head: u64,
        /// 收到的事件位置。
        found: u64,
    },

    /// sequence 不连续。
    #[error("sequence 不连续：期望 {expected}，实际 {found}")]
    SequenceGap {
        /// 期望的下一个位置。
        expected: u64,
        /// 实际收到的位置。
        found: u64,
    },

    /// `previous` 摘要与前一事件不符（断链）。
    #[error("sequence {sequence} 的 previous 摘要与前一事件不符")]
    ChainBroken {
        /// 出问题的事件位置。
        sequence: u64,
    },

    /// 密钥纪元回退。
    #[error("sequence {sequence} 的密钥纪元从 {current} 回退到 {found}")]
    EpochRollback {
        /// 出问题的事件位置。
        sequence: u64,
        /// 当前纪元。
        current: u64,
        /// 事件中的纪元。
        found: u64,
    },

    /// 密钥纪元跳跃超过 1。
    #[error("sequence {sequence} 的密钥纪元从 {current} 跳到 {found}，一次最多 +1")]
    EpochJump {
        /// 出问题的事件位置。
        sequence: u64,
        /// 当前纪元。
        current: u64,
        /// 事件中的纪元。
        found: u64,
    },

    /// 非撤销事件推进了密钥纪元。
    #[error("sequence {sequence} 是 `{action}` 动作，不允许推进密钥纪元")]
    EpochAdvancedWithoutRevocation {
        /// 出问题的事件位置。
        sequence: u64,
        /// 该事件的动作短名。
        action: &'static str,
    },

    /// 撤销事件没有推进密钥纪元。
    #[error("sequence {sequence} 撤销了设备却没有把密钥纪元推进到 {expected}")]
    RevocationMustRotateEpoch {
        /// 出问题的事件位置。
        sequence: u64,
        /// 应该达到的纪元。
        expected: u64,
    },

    /// 签发者不是本链上的已知设备。
    #[error("sequence {sequence} 的签发者 {device} 不是本工作区的成员")]
    ActorUnknown {
        /// 出问题的事件位置。
        sequence: u64,
        /// 签发者设备。
        device: DeviceId,
    },

    /// 签发者是已被撤销的设备。
    #[error("sequence {sequence} 的签发者 {device} 已被撤销")]
    ActorRevoked {
        /// 出问题的事件位置。
        sequence: u64,
        /// 签发者设备。
        device: DeviceId,
    },

    /// 签发者不是管理员。
    #[error("sequence {sequence} 的签发者 {device} 不是管理员，无权变更成员关系")]
    ActorNotAdmin {
        /// 出问题的事件位置。
        sequence: u64,
        /// 签发者设备。
        device: DeviceId,
    },

    /// 成员登记的公钥不是合法的曲线点。
    #[error("sequence {sequence} 中的设备公钥非法")]
    PublicKeyInvalid {
        /// 出问题的事件位置。
        sequence: u64,
    },

    /// 签名验证失败：签名被篡改，或者签名者不是事件声称的 `actor`。
    #[error("sequence {sequence} 的签名验证失败")]
    SignatureInvalid {
        /// 出问题的事件位置。
        sequence: u64,
    },

    /// 被添加的设备已经是成员。
    #[error("sequence {sequence} 尝试添加已存在的成员 {device}")]
    MemberAlreadyExists {
        /// 出问题的事件位置。
        sequence: u64,
        /// 相关设备。
        device: DeviceId,
    },

    /// 动作的主体不是当前成员。
    #[error("sequence {sequence} 的主体 {device} 不是当前成员")]
    SubjectNotMember {
        /// 出问题的事件位置。
        sequence: u64,
        /// 相关设备。
        device: DeviceId,
    },

    /// 提升一个已经是管理员的设备。
    #[error("sequence {sequence} 的主体 {device} 已经是管理员")]
    AlreadyAdmin {
        /// 出问题的事件位置。
        sequence: u64,
        /// 相关设备。
        device: DeviceId,
    },

    /// 撤销会让工作区失去最后一个管理员。
    #[error("sequence {sequence} 会撤销最后一个管理员，工作区将无法再变更成员关系")]
    LastAdminRevoked {
        /// 出问题的事件位置。
        sequence: u64,
    },

    /// 密码学层错误（签名生成失败等）。
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl MembershipError {
    /// 稳定的机器可读错误码，用于 CLI 的 JSON 契约。
    ///
    /// 这些字符串属于对外契约的一部分，只能新增、不能重命名。
    pub fn code(&self) -> &'static str {
        match self {
            MembershipError::TooManyEvents { .. } => "membership.too_many_events",
            MembershipError::Event { .. } => "membership.malformed_event",
            MembershipError::GenesisMissing => "membership.genesis_missing",
            MembershipError::GenesisEpoch { .. } => "membership.genesis_epoch",
            MembershipError::GenesisActorMismatch => "membership.genesis_actor_mismatch",
            MembershipError::DuplicateGenesis { .. } => "membership.duplicate_genesis",
            MembershipError::WorkspaceMismatch { .. } => "membership.workspace_mismatch",
            MembershipError::ForkDetected { .. } => "membership.fork",
            MembershipError::DuplicateSequence { .. } => "membership.duplicate_sequence",
            MembershipError::SequenceRollback { .. } => "membership.sequence_rollback",
            MembershipError::SequenceGap { .. } => "membership.sequence_gap",
            MembershipError::ChainBroken { .. } => "membership.chain_broken",
            MembershipError::EpochRollback { .. } => "membership.epoch_rollback",
            MembershipError::EpochJump { .. } => "membership.epoch_jump",
            MembershipError::EpochAdvancedWithoutRevocation { .. } => {
                "membership.epoch_without_revocation"
            }
            MembershipError::RevocationMustRotateEpoch { .. } => {
                "membership.revocation_no_rotation"
            }
            MembershipError::ActorUnknown { .. } => "membership.actor_unknown",
            MembershipError::ActorRevoked { .. } => "membership.actor_revoked",
            MembershipError::ActorNotAdmin { .. } => "membership.actor_not_admin",
            MembershipError::PublicKeyInvalid { .. } => "membership.public_key_invalid",
            MembershipError::SignatureInvalid { .. } => "membership.signature_invalid",
            MembershipError::MemberAlreadyExists { .. } => "membership.member_exists",
            MembershipError::SubjectNotMember { .. } => "membership.subject_not_member",
            MembershipError::AlreadyAdmin { .. } => "membership.already_admin",
            MembershipError::LastAdminRevoked { .. } => "membership.last_admin",
            MembershipError::Crypto(_) => "membership.crypto",
        }
    }
}

/// 成员事件在 Backend 中的对象标识。
///
/// 成员事件是不可变对象，内容摘要即键；同一条事件在任何设备上算出来的标识相同。
pub fn membership_object_id(event: &MembershipEvent) -> ObjectId {
    ObjectId::for_bytes(ObjectKind::MembershipEvent, &event.to_canonical_vec())
}

/// 链回放器：持有正在成长的状态，以及**仅用于错误分类**的已撤销设备集合。
///
/// 已撤销设备集合刻意不进入 [`MembershipState`]：状态里出现「曾经的成员」很容易被
/// 调用方误当成「还是成员」。它只在这里存在，用来把「陌生设备」和「已撤销设备」这
/// 两种同样要拒绝、但运维含义完全不同的情况区分开。
struct ChainReplay {
    workspace: WorkspaceId,
    state: MembershipState,
    revoked: BTreeSet<DeviceId>,
}

impl ChainReplay {
    /// 校验 genesis 并建立初始状态。
    ///
    /// `expected_workspace` 是**本地**工作区标识。genesis 的 `workspace` 必须与它相等：
    /// 否则整条链是从别处搬来的，即便它自身完全自洽也不该被读进来。
    fn start(
        genesis: &MembershipEvent,
        expected_workspace: WorkspaceId,
    ) -> Result<Self, MembershipError> {
        structural_check(genesis)?;
        // 工作区比对排在最前面：一条外来链在做任何曲线运算之前就该被拒绝，而且报出来的
        // 位置就是第一条事件（sequence 0），不会因为「链自身自洽」而一路读到尾。
        if genesis.workspace != expected_workspace {
            return Err(MembershipError::WorkspaceMismatch {
                sequence: genesis.sequence,
            });
        }
        if !genesis.is_genesis() {
            return Err(MembershipError::GenesisMissing);
        }
        if genesis.epoch != GENESIS_EPOCH {
            return Err(MembershipError::GenesisEpoch {
                expected: GENESIS_EPOCH,
                found: genesis.epoch,
            });
        }
        let MembershipAction::Genesis { subject, public } = genesis.action else {
            // `is_genesis` 已经保证了动作形状，这里只是让绑定成为不可反驳的。
            return Err(MembershipError::GenesisMissing);
        };
        // genesis 是链的信任根：它只能由被登记的那台设备自己签名，否则「谁是第一个
        // 管理员」就不是自证的了。
        if genesis.actor != subject {
            return Err(MembershipError::GenesisActorMismatch);
        }
        verify_event_signature(genesis, &public)?;

        let mut members = BTreeMap::new();
        members.insert(
            subject,
            MemberRecord {
                device: subject,
                public,
                role: MemberRole::Admin,
                added_at_sequence: 0,
            },
        );
        Ok(ChainReplay {
            workspace: genesis.workspace,
            state: MembershipState {
                members,
                epoch: genesis.epoch,
                head: genesis.digest(),
                sequence: 0,
            },
            revoked: BTreeSet::new(),
        })
    }

    /// 校验并应用一条后继事件。
    fn apply(&mut self, event: &MembershipEvent) -> Result<(), MembershipError> {
        structural_check(event)?;
        let sequence = event.sequence;

        // 1) 跨工作区混入。签名本身也绑定 workspace，但显式检查能给出更准确的诊断。
        if event.workspace != self.workspace {
            return Err(MembershipError::WorkspaceMismatch { sequence });
        }

        // 2) sequence：分叉 / 重复 / 回退 / 跳号，四种情况分别报错。
        let head_sequence = self.state.sequence;
        if sequence == head_sequence {
            return Err(if event.digest() == self.state.head {
                MembershipError::DuplicateSequence { sequence }
            } else {
                MembershipError::ForkDetected { sequence }
            });
        }
        if sequence < head_sequence {
            return Err(MembershipError::SequenceRollback {
                head: head_sequence,
                found: sequence,
            });
        }
        let expected = head_sequence + 1;
        if sequence != expected {
            return Err(MembershipError::SequenceGap {
                expected,
                found: sequence,
            });
        }

        // 3) 链接。`structural_check` 已保证非 genesis 事件一定带 previous。
        if event.previous != Some(self.state.head) {
            return Err(MembershipError::ChainBroken { sequence });
        }

        // 4) 密钥纪元：只有撤销能推进，且一次恰好 +1。
        self.check_epoch(event)?;

        // 5) 签发者：先解析成员记录（同时区分「陌生」与「已撤销」），再验签，
        //    最后才看角色——验签失败的事件不应该继续暴露授权逻辑的分支。
        let actor = self.resolve_actor(event)?;
        verify_event_signature(event, &actor.public)?;
        if !actor.role.can_administer() {
            return Err(MembershipError::ActorNotAdmin {
                sequence,
                device: event.actor,
            });
        }

        // 6) 动作语义。
        self.apply_action(event)?;

        self.state.epoch = event.epoch;
        self.state.head = event.digest();
        self.state.sequence = sequence;
        Ok(())
    }

    fn check_epoch(&self, event: &MembershipEvent) -> Result<(), MembershipError> {
        let sequence = event.sequence;
        let current = self.state.epoch;
        if event.epoch < current {
            return Err(MembershipError::EpochRollback {
                sequence,
                current,
                found: event.epoch,
            });
        }
        if event.epoch > current + 1 {
            return Err(MembershipError::EpochJump {
                sequence,
                current,
                found: event.epoch,
            });
        }
        match (event.action.is_revoke(), event.epoch == current + 1) {
            (true, true) | (false, false) => Ok(()),
            (true, false) => Err(MembershipError::RevocationMustRotateEpoch {
                sequence,
                expected: current + 1,
            }),
            (false, true) => Err(MembershipError::EpochAdvancedWithoutRevocation {
                sequence,
                action: event.action.kind(),
            }),
        }
    }

    fn resolve_actor(&self, event: &MembershipEvent) -> Result<MemberRecord, MembershipError> {
        match self.state.members.get(&event.actor) {
            Some(record) => Ok(record.clone()),
            None if self.revoked.contains(&event.actor) => Err(MembershipError::ActorRevoked {
                sequence: event.sequence,
                device: event.actor,
            }),
            None => Err(MembershipError::ActorUnknown {
                sequence: event.sequence,
                device: event.actor,
            }),
        }
    }

    fn apply_action(&mut self, event: &MembershipEvent) -> Result<(), MembershipError> {
        let sequence = event.sequence;
        match event.action {
            MembershipAction::Genesis { .. } => Err(MembershipError::DuplicateGenesis { sequence }),
            MembershipAction::AddMember {
                subject,
                public,
                role,
            } => {
                if self.state.members.contains_key(&subject) {
                    return Err(MembershipError::MemberAlreadyExists {
                        sequence,
                        device: subject,
                    });
                }
                // 公钥必须是合法曲线点：否则这台设备将来根本无法被验签，等于往链上写
                // 了一条永远不能行使权限的记录。
                device_public(&public)
                    .map_err(|_| MembershipError::PublicKeyInvalid { sequence })?;
                // 重新加入一台曾被撤销的设备是**管理员的显式决定**（例如设备找回），
                // 这里放行，只把它从「已撤销」集合里移除，让后续错误分类保持准确。
                self.revoked.remove(&subject);
                self.state.members.insert(
                    subject,
                    MemberRecord {
                        device: subject,
                        public,
                        role,
                        added_at_sequence: sequence,
                    },
                );
                Ok(())
            }
            MembershipAction::Promote { subject } => {
                let record = self.state.members.get_mut(&subject).ok_or(
                    MembershipError::SubjectNotMember {
                        sequence,
                        device: subject,
                    },
                )?;
                if record.role.can_administer() {
                    return Err(MembershipError::AlreadyAdmin {
                        sequence,
                        device: subject,
                    });
                }
                record.role = MemberRole::Admin;
                Ok(())
            }
            MembershipAction::Revoke { subject } => {
                if !self.state.members.contains_key(&subject) {
                    return Err(MembershipError::SubjectNotMember {
                        sequence,
                        device: subject,
                    });
                }
                // 先算「撤销之后还剩几个管理员」，再决定是否放行：工作区必须**永远**
                // 至少有一个管理员，否则成员关系将永久冻结，只能走灾难恢复。
                let removed_admin = self.state.is_admin(&subject);
                if removed_admin && self.state.admin_count() <= 1 {
                    return Err(MembershipError::LastAdminRevoked { sequence });
                }
                self.state.members.remove(&subject);
                self.revoked.insert(subject);
                Ok(())
            }
        }
    }
}

/// 事件的结构性校验，把领域层错误包装上位置信息。
fn structural_check(event: &MembershipEvent) -> Result<(), MembershipError> {
    event.validate().map_err(|source| MembershipError::Event {
        sequence: event.sequence,
        source,
    })
}

/// 把领域层保存的 64 字节还原成密码学层的公钥类型，并校验曲线点合法。
fn device_public(bytes: &DevicePublicBytes) -> Result<DevicePublic, CryptoError> {
    let public = DevicePublic {
        x25519: bytes.x25519(),
        ed25519: bytes.ed25519(),
    };
    public.validate()?;
    Ok(public)
}

/// 用给定公钥验证事件签名。
///
/// 「签名者不是 actor 声称的设备」这条攻击路径不需要单独判断：验签用的公钥来自
/// **链上登记的 actor 记录**，换一台设备来签就必然验不过。
fn verify_event_signature(
    event: &MembershipEvent,
    public: &DevicePublicBytes,
) -> Result<(), MembershipError> {
    let sequence = event.sequence;
    let public =
        device_public(public).map_err(|_| MembershipError::PublicKeyInvalid { sequence })?;
    let bytes = <[u8; SIGNATURE_LEN]>::try_from(event.signature.as_slice()).map_err(|_| {
        MembershipError::Event {
            sequence,
            source: MembershipEventError::SignatureLength {
                expected: SIGNATURE_LEN,
                found: event.signature.len(),
            },
        }
    })?;
    verify(
        &public,
        MEMBERSHIP_SIGNATURE_DOMAIN,
        event.workspace,
        &event.signing_payload(),
        &Signature::from_bytes(bytes),
    )
    .map_err(|_| MembershipError::SignatureInvalid { sequence })
}

/// 从一个**已信任的 genesis** 出发回放整条链，返回可信的成员状态。
///
/// 这是纯函数：不做任何 I/O，不看时钟。`events` 必须是 genesis 之后的后继事件，按链上
/// 顺序排列；`genesis` 本身**不要**重复放进 `events`。
///
/// # `expected_workspace` 为什么是必填参数
///
/// M2 早期的版本只保证「链内各事件的 workspace 与 genesis 一致」。那条不变量是**自洽**
/// 的，不是**正确**的：把工作区 A 的整条链原样搬进工作区 B 的后端，它照样自洽，于是会被
/// 完整读进来，只剩「本设备不在这条链上」这一层兜底。兜底能挡住写操作，却挡不住读操作
/// 把一份外来的成员名单、纪元和信封当成本工作区的事实。
///
/// 因此工作区标识现在是**输入**而不是从链上推出来的：任何一条事件的 `workspace` 不等于
/// 期望值都立即拒绝，genesis 也不例外——外来链在第一条事件上就被拦住。
///
/// # 安全性
///
/// 调用方必须保证 `genesis` 确实是本设备信任的那一个（首次加入工作区时由管理员签名的
/// invitation 建立，之后由本地安全存储固定下来）。本函数只能证明「这条链从给定的
/// genesis 合法延伸而来、且属于期望的工作区」，无法证明「这个 genesis 是对的」。
///
/// # 示例
///
/// ```
/// use envsync_core::membership::{append, create_genesis, verify_membership_chain};
/// use envsync_crypto::device::DeviceKeypair;
/// use envsync_domain::id::WorkspaceId;
/// use envsync_domain::membership::{MemberRole, MembershipAction};
///
/// let workspace = WorkspaceId::generate();
/// let admin = DeviceKeypair::generate()?;
/// let laptop = DeviceKeypair::generate()?;
///
/// let genesis = create_genesis(&admin, workspace, 1_700_000_000_000)?;
/// let state = verify_membership_chain(&genesis, &[], workspace)?;
/// assert_eq!(state.len(), 1);
///
/// let public = envsync_domain::membership::DevicePublicBytes::from_parts(
///     laptop.public().x25519,
///     laptop.public().ed25519,
/// );
/// let add = append(
///     &state,
///     &admin,
///     MembershipAction::AddMember {
///         subject: laptop.device_id(),
///         public,
///         role: MemberRole::Member,
///     },
///     workspace,
///     1_700_000_000_001,
/// )?;
/// let state = verify_membership_chain(&genesis, std::slice::from_ref(&add), workspace)?;
/// assert!(state.contains(&laptop.device_id()));
///
/// // 换一个工作区标识去验同一条链：第一条事件就被拒绝。
/// let elsewhere = WorkspaceId::generate();
/// assert!(verify_membership_chain(&genesis, &[], elsewhere).is_err());
/// # Ok::<(), envsync_core::membership::MembershipError>(())
/// ```
pub fn verify_membership_chain(
    genesis: &MembershipEvent,
    events: &[MembershipEvent],
    expected_workspace: WorkspaceId,
) -> Result<MembershipState, MembershipError> {
    // 结构限制先行：超长输入在做任何曲线运算之前就被拒绝。
    let total = events.len().saturating_add(1);
    if total > MAX_MEMBERSHIP_EVENTS {
        return Err(MembershipError::TooManyEvents {
            limit: MAX_MEMBERSHIP_EVENTS,
            found: total,
        });
    }
    let mut replay = ChainReplay::start(genesis, expected_workspace)?;
    for event in events {
        replay.apply(event)?;
    }
    Ok(replay.state)
}

/// 创建工作区的 genesis 事件：把 `keypair` 登记为唯一管理员。
///
/// 返回 `Result` 而不是裸事件，是因为签名依赖密码学层，理论上可能失败；把失败藏进
/// `expect` 会让「签名失败」变成一次 panic。
pub fn create_genesis(
    keypair: &DeviceKeypair,
    workspace: WorkspaceId,
    now_ms: u64,
) -> Result<MembershipEvent, MembershipError> {
    let public = public_bytes(keypair);
    let device = keypair.device_id();
    let event = sign_event(
        keypair,
        MembershipEvent {
            format_version: MEMBERSHIP_EVENT_FORMAT_VERSION,
            workspace,
            sequence: 0,
            previous: None,
            epoch: GENESIS_EPOCH,
            actor: device,
            action: MembershipAction::Genesis {
                subject: device,
                public,
            },
            created_at_unix_ms: now_ms,
            signature: Vec::new(),
        },
    )?;
    // 自检：刚生成的 genesis 必须能通过验证器。这条断言把「构造」和「验证」两条
    // 代码路径钉在一起，任何一侧漂移都会立刻暴露。
    ChainReplay::start(&event, workspace)?;
    Ok(event)
}

/// 在已验证状态之上追加一条事件。
///
/// 事件的 `sequence`、`previous` 与 `epoch` 全部由 `state` 推导，调用方无法指定——
/// 这些字段一旦可以由外部指定，就等于把链的不变量交给了调用点去维护。
///
/// 生成后会立刻用同一套转移规则做一次自检，因此本函数**不会**产出一条验证器会拒绝的
/// 事件。唯一的例外：`state` 不携带「已撤销设备」集合，因此本地状态已经不认识的签发者
/// 一律报 [`MembershipError::ActorUnknown`]，而不是 `ActorRevoked`；这只影响诊断措辞，
/// 不影响是否放行。
pub fn append(
    state: &MembershipState,
    actor: &DeviceKeypair,
    action: MembershipAction,
    workspace: WorkspaceId,
    now_ms: u64,
) -> Result<MembershipEvent, MembershipError> {
    let epoch = if action.is_revoke() {
        state.epoch + 1
    } else {
        state.epoch
    };
    let event = sign_event(
        actor,
        MembershipEvent {
            format_version: MEMBERSHIP_EVENT_FORMAT_VERSION,
            workspace,
            sequence: state.sequence + 1,
            previous: Some(state.head),
            epoch,
            actor: actor.device_id(),
            action,
            created_at_unix_ms: now_ms,
            signature: Vec::new(),
        },
    )?;
    // 用与验证器完全相同的转移规则做一次 dry run：宁可在本机失败，也不要把一条会被
    // 所有其他设备拒绝的事件发布到后端。
    let mut dry_run = ChainReplay {
        workspace,
        state: state.clone(),
        revoked: BTreeSet::new(),
    };
    dry_run.apply(&event)?;
    Ok(event)
}

/// 把设备的公开材料转成领域层使用的 64 字节形式。
pub fn public_bytes(keypair: &DeviceKeypair) -> DevicePublicBytes {
    let public = keypair.public();
    DevicePublicBytes::from_parts(public.x25519, public.ed25519)
}

/// 对事件的待签内容签名，并把签名写回事件。
fn sign_event(
    keypair: &DeviceKeypair,
    mut event: MembershipEvent,
) -> Result<MembershipEvent, MembershipError> {
    let signature = keypair.sign(
        MEMBERSHIP_SIGNATURE_DOMAIN,
        event.workspace,
        &event.signing_payload(),
    )?;
    event.signature = signature.as_bytes().to_vec();
    Ok(event)
}

/// 已验证链头的紧凑表示，供本地持久化与检查点使用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedHead {
    /// 链头摘要。
    pub digest: Digest32,
    /// 链头所在的 sequence。
    pub sequence: u64,
    /// 链头生效时的密钥纪元。
    pub epoch: u64,
}

impl From<&MembershipState> for VerifiedHead {
    fn from(state: &MembershipState) -> Self {
        VerifiedHead {
            digest: state.head,
            sequence: state.sequence,
            epoch: state.epoch,
        }
    }
}
