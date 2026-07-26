//! 反回滚检查点的攻击矩阵。
//!
//! 场景统一是：设备已经接受了 revision 12，随后**后端被攻击者控制**，开始变着花样
//! 递送旧状态。每一种花样各一个测试，并且断言到具体的错误变体。
//!
//! 另外两组测试覆盖 M2 任务 9 步骤 3 的生命周期场景：
//!
//! * 新设备通过**管理员签名的 invitation** 建立初始检查点；
//! * 恢复身份建立新纪元之后，旧设备一律要求重新授权。

use envsync_core::checkpoint::{
    advance, check_advance, Checkpoint, CheckpointError, CheckpointStore, InMemoryCheckpointStore,
    SqliteCheckpointStore,
};
use envsync_core::membership::{
    append, create_genesis, public_bytes, verify_membership_chain, MembershipError,
};
use envsync_crypto::device::DeviceKeypair;
use envsync_domain::id::{Digest32, SnapshotId, WorkspaceId};
use envsync_domain::membership::{MemberRole, MembershipAction, MembershipEvent, MembershipState};
use tempfile::TempDir;

/// 已被本设备接受的检查点：revision 12、成员链 sequence 3、密钥纪元 2。
fn accepted(workspace: WorkspaceId) -> Checkpoint {
    Checkpoint {
        workspace,
        revision: 12,
        snapshot: SnapshotId::of(b"snapshot-at-revision-12"),
        membership_digest: Digest32::domain_hash("test:membership", b"head-3"),
        membership_sequence: 3,
        key_epoch: 2,
        updated_at_unix_ms: 1_700_000_000_000,
    }
}

/// 装好一个「已经接受 revision 12」的存储。
fn store_at_revision_12() -> (WorkspaceId, InMemoryCheckpointStore, Checkpoint) {
    let workspace = WorkspaceId::generate();
    let store = InMemoryCheckpointStore::new();
    let current = accepted(workspace);
    advance(&store, &current).expect("首次建立信任根");
    (workspace, store, current)
}

// ---------------------------------------------------------------------------
// 回滚攻击矩阵
// ---------------------------------------------------------------------------

#[test]
fn a_lower_revision_is_blocked() {
    let (_, store, current) = store_at_revision_12();
    let rolled_back = Checkpoint {
        revision: 11,
        snapshot: SnapshotId::of(b"snapshot-at-revision-11"),
        ..current
    };

    match advance(&store, &rolled_back) {
        Err(error @ CheckpointError::RevisionRollback { .. }) => {
            assert!(error.is_rollback_attack());
            assert_eq!(error.code(), "checkpoint.revision_rollback");
            assert!(matches!(
                error,
                CheckpointError::RevisionRollback {
                    current: 12,
                    candidate: 11
                }
            ));
        }
        other => panic!("期望 RevisionRollback，实际：{other:?}"),
    }
    // 被拒绝的推进不得留下任何痕迹。
    assert_eq!(store.load(current.workspace).expect("读取"), Some(current));
}

#[test]
fn a_different_snapshot_at_the_same_revision_is_blocked() {
    let (_, store, current) = store_at_revision_12();
    let forked = Checkpoint {
        snapshot: SnapshotId::of(b"another snapshot claiming revision 12"),
        ..current
    };

    assert!(matches!(
        advance(&store, &forked),
        Err(CheckpointError::SnapshotForked { revision: 12 })
    ));
    assert_eq!(store.load(current.workspace).expect("读取"), Some(current));
}

#[test]
fn an_older_membership_head_is_blocked_even_when_the_revision_advances() {
    let (_, store, current) = store_at_revision_12();
    // 后端老老实实地把 revision 推到 13，却把成员链头换回撤销发生之前的那一条——
    // 目的就是让本设备继续给已撤销设备发信封。
    let stale_members = Checkpoint {
        revision: 13,
        snapshot: SnapshotId::of(b"snapshot-at-revision-13"),
        membership_digest: Digest32::domain_hash("test:membership", b"head-2"),
        membership_sequence: 2,
        ..current
    };

    assert!(matches!(
        advance(&store, &stale_members),
        Err(CheckpointError::MembershipRollback {
            current: 3,
            candidate: 2
        })
    ));
    assert_eq!(store.load(current.workspace).expect("读取"), Some(current));
}

#[test]
fn a_forked_membership_head_at_the_same_sequence_is_blocked() {
    let (_, store, current) = store_at_revision_12();
    // sequence 相同、摘要不同：后端在同一个位置给了两条互不相容的成员链。
    let forked = Checkpoint {
        revision: 13,
        snapshot: SnapshotId::of(b"snapshot-at-revision-13"),
        membership_digest: Digest32::domain_hash("test:membership", b"impostor-3"),
        ..current
    };

    assert!(matches!(
        advance(&store, &forked),
        Err(CheckpointError::MembershipForked { sequence: 3 })
    ));
}

#[test]
fn an_older_key_epoch_is_blocked() {
    let (_, store, current) = store_at_revision_12();
    // 纪元退回撤销之前：已撤销设备将重新能够解密新秘密。
    let stale_epoch = Checkpoint {
        revision: 13,
        snapshot: SnapshotId::of(b"snapshot-at-revision-13"),
        membership_digest: Digest32::domain_hash("test:membership", b"head-4"),
        membership_sequence: 4,
        key_epoch: 1,
        ..current
    };

    assert!(matches!(
        advance(&store, &stale_epoch),
        Err(CheckpointError::KeyEpochRollback {
            current: 2,
            candidate: 1
        })
    ));
    assert_eq!(store.load(current.workspace).expect("读取"), Some(current));
}

#[test]
fn a_genuine_advance_is_accepted() {
    let (workspace, store, current) = store_at_revision_12();
    let next = Checkpoint {
        revision: 13,
        snapshot: SnapshotId::of(b"snapshot-at-revision-13"),
        membership_digest: Digest32::domain_hash("test:membership", b"head-4"),
        membership_sequence: 4,
        key_epoch: 3,
        updated_at_unix_ms: current.updated_at_unix_ms + 1_000,
        ..current
    };
    advance(&store, &next).expect("合法前进");
    assert_eq!(store.load(workspace).expect("读取"), Some(next));
}

#[test]
fn replaying_the_same_head_is_idempotent() {
    let (workspace, store, current) = store_at_revision_12();
    advance(&store, &current).expect("同一个头可以重复接受");
    assert_eq!(store.load(workspace).expect("读取"), Some(current));
}

#[test]
fn the_same_revision_with_a_diverging_epoch_is_blocked() {
    let (_, store, current) = store_at_revision_12();
    // 快照与 revision 都一样，纪元却更高：后端在同一个位置给了自相矛盾的元数据。
    let diverged = Checkpoint {
        key_epoch: 3,
        ..current
    };
    assert!(matches!(
        advance(&store, &diverged),
        Err(CheckpointError::Diverged { revision: 12 })
    ));
}

#[test]
fn a_checkpoint_from_another_workspace_is_blocked() {
    let (_, store, current) = store_at_revision_12();
    let elsewhere = Checkpoint {
        workspace: WorkspaceId::generate(),
        revision: 99,
        ..current
    };
    // 直接调 check_advance：advance 会按候选的 workspace 去 load，读到空值反而放行。
    assert!(matches!(
        check_advance(Some(&current), &elsewhere),
        Err(CheckpointError::WorkspaceMismatch)
    ));
    let _ = store;
}

#[test]
fn only_an_explicit_reset_can_lower_the_trust_root() {
    let (workspace, store, current) = store_at_revision_12();
    let rolled_back = Checkpoint {
        revision: 1,
        snapshot: SnapshotId::of(b"ancient"),
        membership_digest: Digest32::domain_hash("test:membership", b"head-0"),
        membership_sequence: 0,
        key_epoch: 1,
        ..current
    };
    assert!(advance(&store, &rolled_back).is_err());

    // 只有显式 reset（灾难恢复）能重置信任根。
    store.reset(workspace).expect("重置信任根");
    assert_eq!(store.load(workspace).expect("读取"), None);
    advance(&store, &rolled_back).expect("重置之后接受任意状态");
    assert_eq!(store.load(workspace).expect("读取"), Some(rolled_back));
}

// ---------------------------------------------------------------------------
// SQLite 审计副本
// ---------------------------------------------------------------------------

#[test]
fn the_sqlite_audit_copy_enforces_the_same_rules() {
    let dir = TempDir::new().expect("临时目录");
    let store = SqliteCheckpointStore::open(dir.path().join("journal.db")).expect("打开审计副本");
    let workspace = WorkspaceId::generate();
    let current = accepted(workspace);

    advance(&store, &current).expect("建立信任根");
    assert_eq!(store.load(workspace).expect("读取"), Some(current));

    let rolled_back = Checkpoint {
        revision: 11,
        ..current
    };
    assert!(advance(&store, &rolled_back)
        .expect_err("必须阻塞")
        .is_rollback_attack());

    // 重开数据库后检查点仍在——它是持久的高水位线，不是进程内缓存。
    drop(store);
    let reopened =
        SqliteCheckpointStore::open(dir.path().join("journal.db")).expect("重开审计副本");
    assert_eq!(reopened.load(workspace).expect("读取"), Some(current));

    reopened.reset(workspace).expect("重置");
    assert_eq!(reopened.load(workspace).expect("读取"), None);
}

// ---------------------------------------------------------------------------
// 克隆与灾难恢复
// ---------------------------------------------------------------------------

/// 从已信任的 genesis 与全部事件推导出一个检查点。
fn checkpoint_from(
    state: &MembershipState,
    workspace: WorkspaceId,
    revision: u64,
    snapshot: SnapshotId,
    now_ms: u64,
) -> Checkpoint {
    Checkpoint {
        workspace,
        revision,
        snapshot,
        membership_digest: state.head,
        membership_sequence: state.sequence,
        key_epoch: state.epoch,
        updated_at_unix_ms: now_ms,
    }
}

#[test]
fn a_new_device_bootstraps_its_checkpoint_from_an_admin_signed_invitation() {
    let workspace = WorkspaceId::generate();
    let admin = DeviceKeypair::generate().expect("管理员设备");
    let newcomer = DeviceKeypair::generate().expect("新设备");

    // 管理员建链，并签发一条把新设备加进来的 invitation 事件。
    let genesis = create_genesis(&admin, workspace, 1_000).expect("genesis");
    let admin_state = verify_membership_chain(&genesis, &[]).expect("链有效");
    let invitation = append(
        &admin_state,
        &admin,
        MembershipAction::AddMember {
            subject: newcomer.device_id(),
            public: public_bytes(&newcomer),
            role: MemberRole::Member,
        },
        workspace,
        1_100,
    )
    .expect("签发 invitation");

    // 新设备侧：genesis 与 invitation 由带外渠道送达，先验链再建检查点。
    let store = InMemoryCheckpointStore::new();
    assert_eq!(
        store.load(workspace).expect("读取"),
        None,
        "新设备没有信任根"
    );

    let state = verify_membership_chain(&genesis, std::slice::from_ref(&invitation))
        .expect("invitation 必须由管理员签名且延伸自 genesis");
    assert!(state.contains(&newcomer.device_id()));

    let initial = checkpoint_from(&state, workspace, 5, SnapshotId::of(b"head-5"), 1_200);
    advance(&store, &initial).expect("首次建立信任根总是被接受");
    assert_eq!(store.load(workspace).expect("读取"), Some(initial));

    // 信任根一旦建立，后端就再也无法把这台设备拉回更早的状态。
    let earlier = Checkpoint {
        revision: 4,
        snapshot: SnapshotId::of(b"head-4"),
        ..initial
    };
    assert!(advance(&store, &earlier)
        .expect_err("必须阻塞")
        .is_rollback_attack());

    // 伪造的 invitation（不是管理员签的）根本过不了链验证这一关。
    let attacker = DeviceKeypair::generate().expect("攻击者设备");
    let mut forged = invitation.clone();
    forged.actor = attacker.device_id();
    forged.signature = attacker
        .sign(
            envsync_core::membership::MEMBERSHIP_SIGNATURE_DOMAIN,
            workspace,
            &forged.signing_payload(),
        )
        .expect("签名")
        .as_bytes()
        .to_vec();
    assert!(matches!(
        verify_membership_chain(&genesis, &[forged]),
        Err(MembershipError::ActorUnknown { .. })
    ));
}

#[test]
fn recovery_starts_a_new_epoch_and_forces_old_devices_to_re_authorise() {
    let workspace = WorkspaceId::generate();
    let admin = DeviceKeypair::generate().expect("管理员设备");
    let old_device = DeviceKeypair::generate().expect("旧设备");
    let recovery = DeviceKeypair::generate().expect("恢复身份");

    let genesis = create_genesis(&admin, workspace, 1_000).expect("genesis");
    let mut chain: Vec<MembershipEvent> = Vec::new();

    // 旧设备原本是工作区成员。
    let state = verify_membership_chain(&genesis, &chain).expect("链有效");
    chain.push(
        append(
            &state,
            &admin,
            MembershipAction::AddMember {
                subject: old_device.device_id(),
                public: public_bytes(&old_device),
                role: MemberRole::Member,
            },
            workspace,
            1_100,
        )
        .expect("加入旧设备"),
    );

    let store = InMemoryCheckpointStore::new();
    let state = verify_membership_chain(&genesis, &chain).expect("链有效");
    let before = checkpoint_from(&state, workspace, 10, SnapshotId::of(b"head-10"), 1_150);
    advance(&store, &before).expect("建立信任根");
    assert_eq!(before.key_epoch, 1);

    // 恢复流程：用恢复身份重建一台管理员设备，并撤销全部旧设备。
    let state = verify_membership_chain(&genesis, &chain).expect("链有效");
    chain.push(
        append(
            &state,
            &admin,
            MembershipAction::AddMember {
                subject: recovery.device_id(),
                public: public_bytes(&recovery),
                role: MemberRole::Admin,
            },
            workspace,
            1_200,
        )
        .expect("登记恢复身份"),
    );
    let state = verify_membership_chain(&genesis, &chain).expect("链有效");
    chain.push(
        append(
            &state,
            &recovery,
            MembershipAction::Revoke {
                subject: old_device.device_id(),
            },
            workspace,
            1_300,
        )
        .expect("撤销旧设备"),
    );

    let after = verify_membership_chain(&genesis, &chain).expect("链有效");
    assert!(
        !after.contains(&old_device.device_id()),
        "旧设备必须失去成员资格"
    );
    assert_eq!(after.epoch, 2, "撤销建立了新的密钥纪元");

    let recovered = checkpoint_from(&after, workspace, 11, SnapshotId::of(b"head-11"), 1_400);
    advance(&store, &recovered).expect("推进到恢复后的状态");

    // 旧设备（或替它说话的后端）拿着撤销前的检查点回来，必须被挡住：它得重新走
    // invitation 流程才能回到工作区。
    assert!(advance(&store, &before)
        .expect_err("撤销前的状态必须被拒绝")
        .is_rollback_attack());

    // 旧设备用自己的私钥继续签事件同样无效。
    match append(
        &after,
        &old_device,
        MembershipAction::Promote {
            subject: old_device.device_id(),
        },
        workspace,
        1_500,
    ) {
        Err(MembershipError::ActorUnknown { device, .. }) => {
            assert_eq!(device, old_device.device_id());
        }
        other => panic!("期望旧设备失去签发权，实际：{other:?}"),
    }
}
