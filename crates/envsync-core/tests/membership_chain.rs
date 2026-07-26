//! 成员事件链的攻击路径矩阵。
//!
//! 每一条「必须拒绝」的路径都有独立的测试，并且断言的是**具体的错误变体**——只断言
//! `is_err()` 会让「因为别的原因失败了」蒙混过关，那正是安全测试最容易出现的假阳性。
//!
//! 构造攻击事件时统一走 [`forge`]：它用真实私钥重新签名，因此除非测试的就是签名本身，
//! 否则每条被拒绝的事件都带着**合法签名**——这样断言的确实是授权/结构规则，而不是
//! 「签名恰好不对」。

use envsync_core::membership::{
    append, create_genesis, membership_object_id, public_bytes, verify_membership_chain,
    MembershipError, MEMBERSHIP_SIGNATURE_DOMAIN,
};
use envsync_crypto::device::DeviceKeypair;
use envsync_domain::cbor::CborCodec;
use envsync_domain::id::{Digest32, WorkspaceId};
use envsync_domain::membership::{
    MemberRole, MembershipAction, MembershipEvent, MembershipState, GENESIS_EPOCH,
    MAX_MEMBERSHIP_EVENTS,
};
use envsync_domain::object::ObjectKind;

/// 用真实私钥给（可能已被篡改的）事件重新签名。
fn forge(mut event: MembershipEvent, keypair: &DeviceKeypair) -> MembershipEvent {
    event.signature = keypair
        .sign(
            MEMBERSHIP_SIGNATURE_DOMAIN,
            event.workspace,
            &event.signing_payload(),
        )
        .expect("签名成功")
        .as_bytes()
        .to_vec();
    event
}

/// 一个装配好的测试场景：admin 是 genesis 管理员，laptop / phone 是候选设备。
struct Fixture {
    workspace: WorkspaceId,
    admin: DeviceKeypair,
    laptop: DeviceKeypair,
    phone: DeviceKeypair,
    genesis: MembershipEvent,
}

impl Fixture {
    fn new() -> Self {
        let workspace = WorkspaceId::generate();
        let admin = DeviceKeypair::generate().expect("生成管理员设备");
        let laptop = DeviceKeypair::generate().expect("生成笔记本设备");
        let phone = DeviceKeypair::generate().expect("生成手机设备");
        let genesis = create_genesis(&admin, workspace, 1_700_000_000_000).expect("创建 genesis");
        Fixture {
            workspace,
            admin,
            laptop,
            phone,
            genesis,
        }
    }

    fn state(&self, events: &[MembershipEvent]) -> MembershipState {
        verify_membership_chain(&self.genesis, events, self.workspace).expect("链应当有效")
    }

    /// 由管理员签发一条「添加成员」事件。
    fn add(
        &self,
        events: &[MembershipEvent],
        device: &DeviceKeypair,
        role: MemberRole,
    ) -> MembershipEvent {
        let state = self.state(events);
        append(
            &state,
            &self.admin,
            MembershipAction::AddMember {
                subject: device.device_id(),
                public: public_bytes(device),
                role,
            },
            self.workspace,
            1_700_000_000_100 + events.len() as u64,
        )
        .expect("追加事件")
    }
}

// ---------------------------------------------------------------------------
// 正常路径
// ---------------------------------------------------------------------------

#[test]
fn genesis_creates_exactly_one_admin() {
    let fixture = Fixture::new();
    let state = fixture.state(&[]);

    assert_eq!(state.len(), 1);
    assert_eq!(state.admin_count(), 1);
    assert_eq!(state.sequence, 0);
    assert_eq!(state.epoch, GENESIS_EPOCH);
    assert_eq!(state.head, fixture.genesis.digest());
    assert!(state.is_admin(&fixture.admin.device_id()));

    let record = state
        .member(&fixture.admin.device_id())
        .expect("管理员在册");
    assert_eq!(record.added_at_sequence, 0);
    assert_eq!(record.public, public_bytes(&fixture.admin));
}

#[test]
fn admin_can_add_promote_and_revoke() {
    let fixture = Fixture::new();
    let add = fixture.add(&[], &fixture.laptop, MemberRole::Member);
    let mut chain = vec![add];

    let state = fixture.state(&chain);
    assert!(state.contains(&fixture.laptop.device_id()));
    assert!(!state.is_admin(&fixture.laptop.device_id()));
    assert_eq!(state.epoch, GENESIS_EPOCH, "添加成员不轮换密钥");
    assert_eq!(state.sequence, 1);

    // 提升为管理员。
    let promote = append(
        &state,
        &fixture.admin,
        MembershipAction::Promote {
            subject: fixture.laptop.device_id(),
        },
        fixture.workspace,
        1_700_000_000_200,
    )
    .expect("提升成员");
    chain.push(promote);
    let state = fixture.state(&chain);
    assert_eq!(state.admin_count(), 2);

    // 新管理员可以撤销原管理员；撤销必须把纪元推进到 2。
    let revoke = append(
        &state,
        &fixture.laptop,
        MembershipAction::Revoke {
            subject: fixture.admin.device_id(),
        },
        fixture.workspace,
        1_700_000_000_300,
    )
    .expect("撤销设备");
    chain.push(revoke);

    let state = fixture.state(&chain);
    assert!(!state.contains(&fixture.admin.device_id()));
    assert_eq!(state.admin_count(), 1);
    assert_eq!(state.epoch, GENESIS_EPOCH + 1, "撤销必须轮换密钥纪元");
    assert_eq!(state.sequence, 3);
    assert_eq!(state.head, chain[2].digest());
}

#[test]
fn events_are_content_addressed_objects() {
    let fixture = Fixture::new();
    let object = membership_object_id(&fixture.genesis);
    assert_eq!(object.kind, ObjectKind::MembershipEvent);
    assert!(object.verifies(&fixture.genesis.to_canonical_vec()));
}

// ---------------------------------------------------------------------------
// 攻击路径：链结构
// ---------------------------------------------------------------------------

#[test]
fn broken_chain_link_is_rejected() {
    let fixture = Fixture::new();
    let mut add = fixture.add(&[], &fixture.laptop, MemberRole::Member);
    // previous 指向一个不存在的摘要，然后用真实私钥重新签名。
    add.previous = Some(Digest32::domain_hash("attacker", b"not the genesis"));
    let add = forge(add, &fixture.admin);

    assert!(matches!(
        verify_membership_chain(&fixture.genesis, &[add], fixture.workspace),
        Err(MembershipError::ChainBroken { sequence: 1 })
    ));
}

#[test]
fn fork_at_the_same_sequence_is_rejected() {
    let fixture = Fixture::new();
    let first = fixture.add(&[], &fixture.laptop, MemberRole::Member);
    // 同一个 sequence 上的第二条**不同**事件：典型的链分叉。
    let second = fixture.add(&[], &fixture.phone, MemberRole::Member);
    assert_eq!(first.sequence, second.sequence);
    assert_ne!(first.digest(), second.digest());

    assert!(matches!(
        verify_membership_chain(&fixture.genesis, &[first, second], fixture.workspace),
        Err(MembershipError::ForkDetected { sequence: 1 })
    ));
}

#[test]
fn duplicated_event_at_the_same_sequence_is_rejected() {
    let fixture = Fixture::new();
    let add = fixture.add(&[], &fixture.laptop, MemberRole::Member);

    assert!(matches!(
        verify_membership_chain(&fixture.genesis, &[add.clone(), add], fixture.workspace),
        Err(MembershipError::DuplicateSequence { sequence: 1 })
    ));
}

#[test]
fn replaying_an_old_event_is_rejected() {
    let fixture = Fixture::new();
    let first = fixture.add(&[], &fixture.laptop, MemberRole::Member);
    let second = fixture.add(
        std::slice::from_ref(&first),
        &fixture.phone,
        MemberRole::Member,
    );

    // 后端在最新事件之后又塞回一条更旧的事件。
    let chain = vec![first.clone(), second, first];
    assert!(matches!(
        verify_membership_chain(&fixture.genesis, &chain, fixture.workspace),
        Err(MembershipError::SequenceRollback { head: 2, found: 1 })
    ));
}

#[test]
fn sequence_gaps_are_rejected() {
    let fixture = Fixture::new();
    let mut add = fixture.add(&[], &fixture.laptop, MemberRole::Member);
    add.sequence = 5;
    let add = forge(add, &fixture.admin);

    assert!(matches!(
        verify_membership_chain(&fixture.genesis, &[add], fixture.workspace),
        Err(MembershipError::SequenceGap {
            expected: 1,
            found: 5
        })
    ));
}

#[test]
fn a_second_genesis_is_rejected() {
    let fixture = Fixture::new();
    let state = fixture.state(&[]);
    let mut second = fixture.add(&[], &fixture.laptop, MemberRole::Member);
    second.action = MembershipAction::Genesis {
        subject: fixture.laptop.device_id(),
        public: public_bytes(&fixture.laptop),
    };
    second.previous = Some(state.head);
    let second = forge(second, &fixture.admin);

    assert!(matches!(
        verify_membership_chain(&fixture.genesis, &[second], fixture.workspace),
        Err(MembershipError::DuplicateGenesis { sequence: 1 })
    ));
}

#[test]
fn cross_workspace_events_are_rejected() {
    let fixture = Fixture::new();
    let other_workspace = WorkspaceId::generate();
    let mut add = fixture.add(&[], &fixture.laptop, MemberRole::Member);
    add.workspace = other_workspace;
    // 用真实私钥为**另一个工作区**重新签名：签名本身完全合法。
    let add = forge(add, &fixture.admin);

    assert!(matches!(
        verify_membership_chain(&fixture.genesis, &[add], fixture.workspace),
        Err(MembershipError::WorkspaceMismatch { sequence: 1 })
    ));
}

/// 把工作区 A 的**整条链**（含 genesis）原样塞进工作区 B。
///
/// 与 [`cross_workspace_events_are_rejected`] 的区别是它没有任何「拼接痕迹」：链自身
/// 完全自洽，genesis 也是真的。挡住它的只能是「链的 workspace 必须等于本地工作区」这一条
/// 显式比对——因此这里断言拒绝发生在 **sequence 0**，而不是链中间的某处。
#[test]
fn an_entire_foreign_chain_is_rejected_at_its_very_first_event() {
    let foreign = Fixture::new();
    let local = Fixture::new();
    assert_ne!(foreign.workspace, local.workspace);

    let add = foreign.add(&[], &foreign.laptop, MemberRole::Member);
    // 正向对照：这条链在**它自己的**工作区里完全合法。
    assert_eq!(
        verify_membership_chain(
            &foreign.genesis,
            std::slice::from_ref(&add),
            foreign.workspace
        )
        .expect("外来链在自己的工作区里有效")
        .len(),
        2
    );

    assert!(matches!(
        verify_membership_chain(&foreign.genesis, &[add], local.workspace),
        Err(MembershipError::WorkspaceMismatch { sequence: 0 })
    ));
}

#[test]
fn oversized_chains_are_rejected_before_any_crypto() {
    let fixture = Fixture::new();
    let add = fixture.add(&[], &fixture.laptop, MemberRole::Member);
    // 结构限制先于逐事件验证：这里的事件全是同一条，验证器根本不该走到验签。
    let flood = vec![add; MAX_MEMBERSHIP_EVENTS];

    assert!(matches!(
        verify_membership_chain(&fixture.genesis, &flood, fixture.workspace),
        Err(MembershipError::TooManyEvents {
            limit: MAX_MEMBERSHIP_EVENTS,
            ..
        })
    ));
}

// ---------------------------------------------------------------------------
// 攻击路径：密钥纪元
// ---------------------------------------------------------------------------

#[test]
fn future_epoch_jump_is_rejected() {
    let fixture = Fixture::new();
    let state = fixture.state(&[]);
    let mut revoke = append(
        &state,
        &fixture.admin,
        MembershipAction::AddMember {
            subject: fixture.laptop.device_id(),
            public: public_bytes(&fixture.laptop),
            role: MemberRole::Member,
        },
        fixture.workspace,
        1,
    )
    .expect("构造事件");
    // 一次跳三个纪元：让设备去等一个永远不会出现的信封。
    revoke.epoch = GENESIS_EPOCH + 3;
    let revoke = forge(revoke, &fixture.admin);

    assert!(matches!(
        verify_membership_chain(&fixture.genesis, &[revoke], fixture.workspace),
        Err(MembershipError::EpochJump {
            sequence: 1,
            current: 1,
            found: 4
        })
    ));
}

#[test]
fn advancing_the_epoch_without_a_revocation_is_rejected() {
    let fixture = Fixture::new();
    let mut add = fixture.add(&[], &fixture.laptop, MemberRole::Member);
    add.epoch = GENESIS_EPOCH + 1;
    let add = forge(add, &fixture.admin);

    assert!(matches!(
        verify_membership_chain(&fixture.genesis, &[add], fixture.workspace),
        Err(MembershipError::EpochAdvancedWithoutRevocation {
            sequence: 1,
            action: "add_member"
        })
    ));
}

#[test]
fn revoking_without_rotating_the_epoch_is_rejected() {
    let fixture = Fixture::new();
    let add = fixture.add(&[], &fixture.laptop, MemberRole::Member);
    let state = fixture.state(std::slice::from_ref(&add));
    let mut revoke = append(
        &state,
        &fixture.admin,
        MembershipAction::Revoke {
            subject: fixture.laptop.device_id(),
        },
        fixture.workspace,
        2,
    )
    .expect("构造撤销事件");
    // 撤销设备却不轮换密钥：被撤销的设备将继续能读新内容。
    revoke.epoch = GENESIS_EPOCH;
    let revoke = forge(revoke, &fixture.admin);

    assert!(matches!(
        verify_membership_chain(&fixture.genesis, &[add, revoke], fixture.workspace),
        Err(MembershipError::RevocationMustRotateEpoch {
            sequence: 2,
            expected: 2
        })
    ));
}

#[test]
fn rolling_the_epoch_back_is_rejected() {
    let fixture = Fixture::new();
    let add = fixture.add(&[], &fixture.laptop, MemberRole::Member);
    let state = fixture.state(std::slice::from_ref(&add));
    let revoke = append(
        &state,
        &fixture.admin,
        MembershipAction::Revoke {
            subject: fixture.laptop.device_id(),
        },
        fixture.workspace,
        2,
    )
    .expect("撤销");
    let state = fixture.state(&[add.clone(), revoke.clone()]);
    assert_eq!(state.epoch, 2);

    let mut later = append(
        &state,
        &fixture.admin,
        MembershipAction::AddMember {
            subject: fixture.phone.device_id(),
            public: public_bytes(&fixture.phone),
            role: MemberRole::Member,
        },
        fixture.workspace,
        3,
    )
    .expect("构造事件");
    later.epoch = GENESIS_EPOCH;
    let later = forge(later, &fixture.admin);

    assert!(matches!(
        verify_membership_chain(&fixture.genesis, &[add, revoke, later], fixture.workspace),
        Err(MembershipError::EpochRollback {
            sequence: 3,
            current: 2,
            found: 1
        })
    ));
}

// ---------------------------------------------------------------------------
// 攻击路径：签名与授权
// ---------------------------------------------------------------------------

#[test]
fn a_tampered_signature_is_rejected() {
    let fixture = Fixture::new();
    let mut add = fixture.add(&[], &fixture.laptop, MemberRole::Member);
    add.signature[0] ^= 0x01;

    assert!(matches!(
        verify_membership_chain(&fixture.genesis, &[add], fixture.workspace),
        Err(MembershipError::SignatureInvalid { sequence: 1 })
    ));
}

#[test]
fn signing_with_another_device_key_is_rejected() {
    let fixture = Fixture::new();
    let add = fixture.add(&[], &fixture.laptop, MemberRole::Member);
    // actor 字段仍然声称是管理员，但签名来自攻击者的私钥。
    let attacker = DeviceKeypair::generate().expect("生成攻击者设备");
    let add = forge(add, &attacker);

    assert!(matches!(
        verify_membership_chain(&fixture.genesis, &[add], fixture.workspace),
        Err(MembershipError::SignatureInvalid { sequence: 1 })
    ));
}

#[test]
fn a_revoked_actor_cannot_sign_further_events() {
    let fixture = Fixture::new();
    // laptop 先成为管理员，然后被 admin 撤销。
    let add = fixture.add(&[], &fixture.laptop, MemberRole::Admin);
    let state = fixture.state(std::slice::from_ref(&add));
    let revoke = append(
        &state,
        &fixture.admin,
        MembershipAction::Revoke {
            subject: fixture.laptop.device_id(),
        },
        fixture.workspace,
        2,
    )
    .expect("撤销 laptop");
    let state = fixture.state(&[add.clone(), revoke.clone()]);

    // 已撤销的 laptop 仍然持有私钥，于是伪造一条「把自己加回来」的事件。
    let forged = append(
        &state,
        &fixture.admin,
        MembershipAction::AddMember {
            subject: fixture.phone.device_id(),
            public: public_bytes(&fixture.phone),
            role: MemberRole::Admin,
        },
        fixture.workspace,
        3,
    )
    .expect("构造事件");
    let mut forged = forged;
    forged.actor = fixture.laptop.device_id();
    let forged = forge(forged, &fixture.laptop);

    match verify_membership_chain(&fixture.genesis, &[add, revoke, forged], fixture.workspace) {
        Err(MembershipError::ActorRevoked { sequence, device }) => {
            assert_eq!(sequence, 3);
            assert_eq!(device, fixture.laptop.device_id());
        }
        other => panic!("期望 ActorRevoked，实际：{other:?}"),
    }
}

#[test]
fn an_unknown_actor_is_rejected() {
    let fixture = Fixture::new();
    let mut add = fixture.add(&[], &fixture.laptop, MemberRole::Member);
    let stranger = DeviceKeypair::generate().expect("生成陌生设备");
    add.actor = stranger.device_id();
    let add = forge(add, &stranger);

    match verify_membership_chain(&fixture.genesis, &[add], fixture.workspace) {
        Err(MembershipError::ActorUnknown { sequence, device }) => {
            assert_eq!(sequence, 1);
            assert_eq!(device, stranger.device_id());
        }
        other => panic!("期望 ActorUnknown，实际：{other:?}"),
    }
}

#[test]
fn a_plain_member_cannot_add_promote_or_revoke() {
    let fixture = Fixture::new();
    let add = fixture.add(&[], &fixture.laptop, MemberRole::Member);
    let state = fixture.state(std::slice::from_ref(&add));

    // laptop 是普通成员，三种成员变更动作都必须被拒绝。
    let attempts = [
        MembershipAction::AddMember {
            subject: fixture.phone.device_id(),
            public: public_bytes(&fixture.phone),
            role: MemberRole::Member,
        },
        MembershipAction::Promote {
            subject: fixture.laptop.device_id(),
        },
        MembershipAction::Revoke {
            subject: fixture.admin.device_id(),
        },
    ];

    for action in attempts {
        let kind = action.kind();
        // 本地 append 已经会拒绝——它跑的是同一套转移规则。
        let local = append(&state, &fixture.laptop, action, fixture.workspace, 2);
        match local {
            Err(MembershipError::ActorNotAdmin { sequence, device }) => {
                assert_eq!(sequence, 2, "{kind}");
                assert_eq!(device, fixture.laptop.device_id(), "{kind}");
            }
            other => panic!("{kind}：期望 ActorNotAdmin，实际：{other:?}"),
        }
    }

    // 就算攻击者绕过 append，直接把管理员签发的事件改成由 laptop 签发并用真实私钥
    // 重新签名，验证器同样拒绝——授权判定依据的是链上登记的角色，不是事件自称的身份。
    let mut forged = append(
        &state,
        &fixture.admin,
        MembershipAction::AddMember {
            subject: fixture.phone.device_id(),
            public: public_bytes(&fixture.phone),
            role: MemberRole::Admin,
        },
        fixture.workspace,
        2,
    )
    .expect("管理员签发是合法的");
    forged.actor = fixture.laptop.device_id();
    let forged = forge(forged, &fixture.laptop);
    assert!(matches!(
        verify_membership_chain(&fixture.genesis, &[add, forged], fixture.workspace),
        Err(MembershipError::ActorNotAdmin { sequence: 2, .. })
    ));
}

#[test]
fn the_last_admin_cannot_be_revoked() {
    let fixture = Fixture::new();
    // 先加一个普通成员，保证 members 非空但只有一个管理员。
    let add = fixture.add(&[], &fixture.laptop, MemberRole::Member);
    let state = fixture.state(std::slice::from_ref(&add));
    assert_eq!(state.admin_count(), 1);

    // 管理员撤销自己 = 工作区永久失去成员管理能力。
    let attempt = append(
        &state,
        &fixture.admin,
        MembershipAction::Revoke {
            subject: fixture.admin.device_id(),
        },
        fixture.workspace,
        2,
    );
    assert!(matches!(
        attempt,
        Err(MembershipError::LastAdminRevoked { sequence: 2 })
    ));

    // 直接伪造同样的事件，验证器一样拒绝。
    let mut forged = append(
        &state,
        &fixture.admin,
        MembershipAction::Revoke {
            subject: fixture.laptop.device_id(),
        },
        fixture.workspace,
        2,
    )
    .expect("撤销普通成员是允许的");
    forged.action = MembershipAction::Revoke {
        subject: fixture.admin.device_id(),
    };
    let forged = forge(forged, &fixture.admin);
    assert!(matches!(
        verify_membership_chain(&fixture.genesis, &[add, forged], fixture.workspace),
        Err(MembershipError::LastAdminRevoked { sequence: 2 })
    ));
}

// ---------------------------------------------------------------------------
// 攻击路径：genesis 本身
// ---------------------------------------------------------------------------

#[test]
fn genesis_must_be_self_signed_by_the_admin_it_registers() {
    let fixture = Fixture::new();
    let mut genesis = fixture.genesis.clone();
    // 换成另一台设备当 actor：genesis 就不再是自证的了。
    genesis.actor = fixture.laptop.device_id();
    let genesis = forge(genesis, &fixture.laptop);

    assert!(matches!(
        verify_membership_chain(&genesis, &[], fixture.workspace),
        Err(MembershipError::GenesisActorMismatch)
    ));
}

#[test]
fn genesis_must_use_the_initial_epoch() {
    let fixture = Fixture::new();
    let mut genesis = fixture.genesis.clone();
    genesis.epoch = 7;
    let genesis = forge(genesis, &fixture.admin);

    assert!(matches!(
        verify_membership_chain(&genesis, &[], fixture.workspace),
        Err(MembershipError::GenesisEpoch {
            expected: 1,
            found: 7
        })
    ));
}

#[test]
fn a_non_genesis_first_event_is_rejected() {
    let fixture = Fixture::new();
    let add = fixture.add(&[], &fixture.laptop, MemberRole::Member);
    // 把一条普通事件当作 genesis 传进去。
    assert!(matches!(
        verify_membership_chain(&add, &[], fixture.workspace),
        Err(MembershipError::Event { sequence: 1, .. }) | Err(MembershipError::GenesisMissing)
    ));
}

#[test]
fn a_tampered_genesis_signature_is_rejected() {
    let fixture = Fixture::new();
    let mut genesis = fixture.genesis.clone();
    genesis.signature[63] ^= 0x80;

    assert!(matches!(
        verify_membership_chain(&genesis, &[], fixture.workspace),
        Err(MembershipError::SignatureInvalid { sequence: 0 })
    ));
}

// ---------------------------------------------------------------------------
// 编排 API 的自洽性
// ---------------------------------------------------------------------------

#[test]
fn append_never_produces_an_event_the_verifier_would_reject() {
    let fixture = Fixture::new();
    let mut chain = Vec::new();
    for (index, device) in [&fixture.laptop, &fixture.phone].into_iter().enumerate() {
        let event = fixture.add(&chain, device, MemberRole::Member);
        // 每一步都必须能被独立验证。
        chain.push(event);
        let state =
            verify_membership_chain(&fixture.genesis, &chain, fixture.workspace).expect("链有效");
        assert_eq!(state.sequence as usize, index + 1);
        assert_eq!(state.len(), index + 2);
    }
}

#[test]
fn duplicate_members_are_rejected() {
    let fixture = Fixture::new();
    let add = fixture.add(&[], &fixture.laptop, MemberRole::Member);
    let state = fixture.state(std::slice::from_ref(&add));

    match append(
        &state,
        &fixture.admin,
        MembershipAction::AddMember {
            subject: fixture.laptop.device_id(),
            public: public_bytes(&fixture.laptop),
            role: MemberRole::Admin,
        },
        fixture.workspace,
        2,
    ) {
        Err(MembershipError::MemberAlreadyExists { sequence, device }) => {
            assert_eq!(sequence, 2);
            assert_eq!(device, fixture.laptop.device_id());
        }
        other => panic!("期望 MemberAlreadyExists，实际：{other:?}"),
    }
}

#[test]
fn promoting_a_non_member_or_an_existing_admin_is_rejected() {
    let fixture = Fixture::new();
    let state = fixture.state(&[]);

    assert!(matches!(
        append(
            &state,
            &fixture.admin,
            MembershipAction::Promote {
                subject: fixture.laptop.device_id(),
            },
            fixture.workspace,
            1,
        ),
        Err(MembershipError::SubjectNotMember { sequence: 1, .. })
    ));

    assert!(matches!(
        append(
            &state,
            &fixture.admin,
            MembershipAction::Promote {
                subject: fixture.admin.device_id(),
            },
            fixture.workspace,
            1,
        ),
        Err(MembershipError::AlreadyAdmin { sequence: 1, .. })
    ));
}

#[test]
fn error_codes_are_stable_and_unique_per_variant() {
    let fixture = Fixture::new();
    let mut add = fixture.add(&[], &fixture.laptop, MemberRole::Member);
    add.signature[0] ^= 0xff;
    let error =
        verify_membership_chain(&fixture.genesis, &[add], fixture.workspace).expect_err("应当失败");
    assert_eq!(error.code(), "membership.signature_invalid");
    // 错误信息里不得出现签名或公钥字节。
    let rendered = error.to_string();
    assert!(rendered.contains("签名验证失败"), "{rendered}");
}
