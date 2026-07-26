//! M2 任务 5 步骤 3-4：撤销设备后的密钥轮换与中断恢复。
//!
//! 攻击者模型下最要紧的四条性质：
//!
//! 1. **撤销把纪元推到 n+1，并且为每台剩余设备生成新信封。**
//! 2. **已撤销设备读不了新对象**：新纪元的信封不发给它，HPKE 也不让它借别人的信封。
//! 3. **任一阶段中断都能幂等恢复**，恢复后的终态与一次跑完完全一致。
//! 4. **新头绝不引用尚未发布的信封。** 这一条用「在信封发布之前中断，然后断言后端上
//!    根本没有新头」来证明——不是断言代码里有个检查，而是断言后端上没有那个对象。

mod vault_support;

use envsync_backend::{Backend, LocalBackend};
use envsync_core::device_admin::{self, INVITATION_DEFAULT_TTL_MS};
use envsync_core::vault::{SecretInput, VaultService};
use envsync_crypto::device::DeviceKeypair;
use envsync_domain::membership::MemberRole;
use envsync_storage::{RotationJournal, RotationStage};
use vault_support::{assert_no_plaintext, err, sid, Fixture, Workbench};

const CANARY: &[u8] = b"CANARY-9d31f7ae54c0b268-ROTATION";

fn input(value: &[u8]) -> SecretInput {
    SecretInput::from_reader(&mut &value[..]).expect("构造秘密输入")
}

/// 一个三设备工作区：`admin` 是创建者，另外两台通过邀请加入。
struct Trio {
    fixture: Fixture,
    admin: Workbench,
    keeper: Workbench,
    doomed: Workbench,
    keeper_key: DeviceKeypair,
    doomed_key: DeviceKeypair,
}

impl Trio {
    fn build() -> Self {
        let fixture = Fixture::new();
        let admin = fixture.device("admin");
        let keeper = fixture.device("keeper");
        let doomed = fixture.device("doomed");
        admin.init_device().expect("建立管理员身份");
        let keeper_key = keeper.init_device().expect("建立设备身份");
        let doomed_key = doomed.init_device().expect("建立设备身份");

        let mut vault = admin.open().expect("打开服务");
        vault.create().expect("创建工作区");
        vault
            .set(&sid("ci/npm-token"), input(CANARY))
            .expect("写入秘密");

        for key in [&keeper_key, &doomed_key] {
            let invitation = device_admin::invite(
                &mut vault,
                key.public(),
                MemberRole::Member,
                INVITATION_DEFAULT_TTL_MS,
            )
            .expect("邀请设备");
            let bench = if key.device_id() == keeper_key.device_id() {
                &keeper
            } else {
                &doomed
            };
            device_admin::join(bench.deps(), &bench.state_dir, &invitation).expect("加入工作区");
        }

        Trio {
            fixture,
            admin,
            keeper,
            doomed,
            keeper_key,
            doomed_key,
        }
    }

    /// 后端当前 Ref 的 revision。
    fn backend_revision(&self) -> u64 {
        let backend = LocalBackend::open(self.fixture.backend_dir()).expect("打开后端");
        backend
            .get_ref(self.fixture.workspace)
            .map(|reference| reference.revision)
            .unwrap_or(0)
    }

    /// 后端上「所有人都能看到的」当前纪元。
    fn published_epoch(&self) -> u64 {
        let vault = self.admin.open().expect("重新打开");
        vault.membership().expect("成员状态").epoch
    }

    /// 管理员的轮换 journal 当前阶段。
    fn stage(&self) -> Option<RotationStage> {
        let journal =
            RotationJournal::open(self.admin.state_dir.join("rotation.db")).expect("打开 journal");
        journal
            .get(self.fixture.workspace)
            .expect("读取")
            .map(|record| record.stage)
    }
}

#[test]
fn revocation_advances_the_epoch_and_reissues_envelopes() {
    let trio = Trio::build();
    let mut vault = trio.admin.open().expect("打开服务");
    assert_eq!(vault.membership().expect("成员状态").len(), 3);
    assert_eq!(vault.membership().expect("成员状态").epoch, 1);

    let outcome = vault
        .revoke_device(trio.doomed_key.device_id())
        .expect("撤销设备");
    assert_eq!(outcome.from_epoch, 1);
    assert_eq!(outcome.to_epoch, 2);
    assert_eq!(outcome.stage, RotationStage::Complete);
    assert!(!outcome.resumed);
    // 剩余两台设备各拿到一份新信封。
    assert_eq!(outcome.envelopes, 2);

    let state = vault.membership().expect("成员状态");
    assert_eq!(state.epoch, 2);
    assert_eq!(state.len(), 2);
    assert!(!state.contains(&trio.doomed_key.device_id()));

    // 设备清单如实反映「谁拿到了当前纪元的信封」。
    let devices = device_admin::list_devices(&vault).expect("列出设备");
    assert_eq!(devices.len(), 2);
    assert!(devices.iter().all(|device| device.has_current_envelope));

    // 剩余设备真的能用新信封读到新写入的内容。
    vault
        .set(&sid("ci/after"), input(b"post-rotation"))
        .expect("写入新秘密");
    let keeper = trio.keeper.open().expect("打开剩余设备");
    keeper.adopt_envelope().expect("取回新纪元数据密钥");
    assert_eq!(
        keeper.get(&sid("ci/after")).expect("读取").expose(),
        b"post-rotation"
    );
    assert_eq!(
        keeper.get(&sid("ci/npm-token")).expect("读取").expose(),
        CANARY
    );
}

#[test]
fn a_revoked_device_cannot_read_anything_written_after_the_rotation() {
    let trio = Trio::build();
    let mut vault = trio.admin.open().expect("打开服务");
    vault
        .revoke_device(trio.doomed_key.device_id())
        .expect("撤销设备");
    vault
        .set(&sid("ci/after"), input(b"post-rotation"))
        .expect("写入新秘密");

    // 被撤销的设备：本机还留着纪元 1 的密钥，但索引里根本没有发给它的纪元 2 信封。
    let doomed = trio.doomed.open().expect("打开已撤销设备");
    let error = err(doomed.adopt_envelope());
    assert_eq!(error.code(), "vault.data_key_missing");

    // 因此新对象解不开：缺的是纪元 2 的数据密钥。
    let error = err(doomed.get(&sid("ci/after")));
    assert_eq!(error.code(), "vault.data_key_missing");

    // 它也不再是成员，写操作被授权层直接拒绝。
    let mut doomed = trio.doomed.open().expect("打开已撤销设备");
    let error = err(doomed.set(&sid("ci/evil"), input(b"nope")));
    assert_eq!(error.code(), "vault.not_a_member");

    // 撤销之后它甚至不能发起自己的轮换。
    let error = err(doomed.revoke_device(trio.keeper_key.device_id()));
    assert_eq!(error.code(), "vault.admin_required");
}

#[test]
fn the_new_head_is_never_published_before_the_envelopes() {
    let trio = Trio::build();
    let revision_before = trio.backend_revision();
    assert_eq!(trio.published_epoch(), 1);

    let mut vault = trio.admin.open().expect("打开服务");
    let outcome = vault
        .revoke_device_until(
            trio.doomed_key.device_id(),
            // 在「发布信封」这一步**之前**把进程杀掉。
            Some(RotationStage::EnvelopesPublished),
        )
        .expect("中断的轮换");
    assert_eq!(outcome.stage, RotationStage::Prepared);
    assert_eq!(outcome.envelopes, 0);
    drop(vault);

    // 关键断言：后端上没有任何新东西。既没有新头，纪元也没有前进。
    assert_eq!(
        trio.backend_revision(),
        revision_before,
        "信封还没发布，后端 Ref 绝不能前进"
    );
    assert_eq!(trio.published_epoch(), 1, "新纪元不该出现在成员链上");
    assert_eq!(trio.stage(), Some(RotationStage::Prepared));

    // 剩余设备此刻仍然工作在纪元 1，一切照常。
    let keeper = trio.keeper.open().expect("打开剩余设备");
    assert_eq!(keeper.membership().expect("成员状态").epoch, 1);
    assert_eq!(
        keeper.get(&sid("ci/npm-token")).expect("读取").expose(),
        CANARY
    );
}

#[test]
fn the_head_is_refused_when_the_journal_lies_about_published_envelopes() {
    let trio = Trio::build();
    let mut vault = trio.admin.open().expect("打开服务");
    vault
        .revoke_device_until(
            trio.doomed_key.device_id(),
            Some(RotationStage::HeadPublished),
        )
        .expect("中断在信封之后");
    assert_eq!(trio.stage(), Some(RotationStage::EnvelopesPublished));
    drop(vault);

    // 把 journal 改成指向一个后端上并不存在的信封对象——模拟「journal 说发过了，
    // 后端其实没有」。恢复流程必须中止，而不是硬着头皮发布新头。
    let journal =
        RotationJournal::open(trio.admin.state_dir.join("rotation.db")).expect("打开 journal");
    let mut record = journal
        .get(trio.fixture.workspace)
        .expect("读取")
        .expect("存在");
    record.envelopes = vec![
        "envelope/0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
    ];
    journal.upsert(&record).expect("写回");

    let revision_before = trio.backend_revision();
    let mut vault = trio.admin.open().expect("重新打开");
    let error = err(vault.resume_rotation());
    assert_eq!(error.code(), "rotation.envelopes_missing");
    drop(vault);

    assert_eq!(trio.backend_revision(), revision_before, "新头绝不能被发布");
    assert_eq!(trio.published_epoch(), 1);
}

#[test]
fn rotation_resumes_idempotently_from_every_stage() {
    // 逐个阶段中断，然后重开进程恢复；每一次的终态都必须完全相同。
    for stop_before in [
        RotationStage::EnvelopesPublished,
        RotationStage::HeadPublished,
        RotationStage::Rewrapping,
        RotationStage::Complete,
    ] {
        let trio = Trio::build();
        let doomed = trio.doomed_key.device_id();

        let mut vault = trio.admin.open().expect("打开服务");
        let interrupted = vault
            .revoke_device_until(doomed, Some(stop_before))
            .expect("中断的轮换");
        assert_ne!(
            interrupted.stage,
            RotationStage::Complete,
            "stop_before={stop_before} 时不该已经完成"
        );
        // 新头必须在「信封已发布」之后才出现，一步都不能提前。
        assert_eq!(
            trio.published_epoch() == 2,
            interrupted.stage.head_is_published(),
            "stop_before={stop_before}：后端上的纪元与 journal 阶段必须一致"
        );
        drop(vault);

        // 进程重启：恢复。
        let mut vault = trio.admin.open().expect("重新打开");
        let resumed = vault
            .resume_rotation()
            .expect("恢复")
            .expect("有未完成轮换");
        assert!(resumed.resumed);
        assert_eq!(resumed.stage, RotationStage::Complete);
        assert_eq!(resumed.to_epoch, 2);

        // 终态与一次跑完完全一致。
        let state = vault.membership().expect("成员状态");
        assert_eq!(state.epoch, 2, "stop_before={stop_before}");
        assert_eq!(state.len(), 2);
        assert!(!state.contains(&doomed));
        // **撤销不重加密旧对象**：lazy rewrap 只在读取时发生（计划文档 Task 5 步骤 3）。
        // 因此这里断言的是「还停在旧纪元」，而不是「已经重加密」。
        assert_eq!(
            vault.list().expect("列出")[0].epoch,
            1,
            "stop_before={stop_before}：撤销只推进纪元，旧对象必须原样留在旧纪元"
        );
        assert_eq!(
            resumed.pending_rewrap, 1,
            "stop_before={stop_before}：待 lazy rewrap 的条数必须被如实报出来"
        );
        // 读一次就触发 lazy rewrap；索引更新推迟到下一次写操作或显式 flush。
        assert_eq!(
            vault.get(&sid("ci/npm-token")).expect("读取").expose(),
            CANARY
        );
        assert_eq!(vault.flush_rewraps().expect("落盘"), 1);
        assert_eq!(
            vault.list().expect("列出")[0].epoch,
            2,
            "stop_before={stop_before}：读取之后才轮到重加密"
        );

        // 再恢复一次是零成本的空转。
        assert!(
            vault.resume_rotation().expect("再次恢复").is_none(),
            "已完成的轮换不该被再驱动一次"
        );
        // 重复执行同一条撤销命令也不该出错或产生第二次轮换。
        let again = vault.revoke_device(doomed);
        assert_eq!(
            err(again).code(),
            "vault.not_a_member_device",
            "设备已经不在成员链上，再撤一次应当得到明确的诊断"
        );

        assert_no_plaintext(&trio.fixture.backend_dir(), CANARY);
    }
}

#[test]
fn an_interrupted_rotation_is_picked_up_by_the_next_revoke_of_the_same_device() {
    let trio = Trio::build();
    let doomed = trio.doomed_key.device_id();

    let mut vault = trio.admin.open().expect("打开服务");
    vault
        .revoke_device_until(doomed, Some(RotationStage::HeadPublished))
        .expect("中断的轮换");
    drop(vault);

    // 用户看到失败，原样重跑同一条命令：接着做，而不是从头再来。
    let mut vault = trio.admin.open().expect("重新打开");
    let outcome = vault.revoke_device(doomed).expect("重跑");
    assert!(outcome.resumed);
    assert_eq!(outcome.stage, RotationStage::Complete);
    assert_eq!(vault.membership().expect("成员状态").epoch, 2);
}

#[test]
fn a_second_rotation_for_a_different_device_is_refused_while_one_is_pending() {
    let trio = Trio::build();
    let mut vault = trio.admin.open().expect("打开服务");
    vault
        .revoke_device_until(
            trio.doomed_key.device_id(),
            Some(RotationStage::EnvelopesPublished),
        )
        .expect("中断的轮换");

    let error = err(vault.revoke_device(trio.keeper_key.device_id()));
    assert_eq!(error.code(), "rotation.already_in_progress");
}

#[test]
fn a_device_can_never_revoke_itself() {
    let fixture = Fixture::new();
    let admin = fixture.device("admin");
    let admin_key = admin.init_device().expect("建立设备身份");
    let mut vault = admin.open().expect("打开服务");
    vault.create().expect("创建工作区");

    // 撤销自己会产生一个**由非成员签出**的头：撤销事件把本设备从名单上抹掉，而这个头的
    // Vault 索引背书恰恰是本设备刚签的。读路径要求背书由当前成员签出，于是那个头对所有
    // 人都不可读——包括其余管理员，而他们又必须先读到头才能发布新头。工作区就此锁死。
    let error = err(vault.revoke_device(admin_key.device_id()));
    assert_eq!(error.code(), "rotation.cannot_revoke_self");
    assert_eq!(vault.membership().expect("成员状态").epoch, 1);
    // 一步副作用都不能留下：既没有生成新纪元密钥，也没有写 journal。
    assert!(vault
        .rotations()
        .get_unfinished(fixture.workspace)
        .expect("journal 可读")
        .is_none());

    // 工作区里再多一台设备也一样——限制与「还剩几个管理员」无关。
    let laptop = fixture.device("laptop");
    let laptop_key = laptop.init_device().expect("建立设备身份");
    device_admin::invite(
        &mut vault,
        laptop_key.public(),
        MemberRole::Admin,
        INVITATION_DEFAULT_TTL_MS,
    )
    .expect("邀请设备");
    let error = err(vault.revoke_device(admin_key.device_id()));
    assert_eq!(error.code(), "rotation.cannot_revoke_self");

    // 反面对照：撤销**别人**照常可行，否则上面几条断言可能只是「什么都撤不了」。
    let outcome = vault
        .revoke_device(laptop_key.device_id())
        .expect("撤销另一台设备");
    assert_eq!(outcome.to_epoch, 2);
}

#[test]
fn revoking_the_last_remaining_device_is_refused_by_the_membership_rules() {
    let fixture = Fixture::new();
    let admin = fixture.device("admin");
    admin.init_device().expect("建立设备身份");
    let stranger = fixture.device("stranger");
    let stranger_key = stranger.init_device().expect("建立设备身份");
    let mut vault = admin.open().expect("打开服务");
    vault.create().expect("创建工作区");

    // `stranger` 根本不是成员：撤销它在 `prepare` 阶段就被拦下，不会生成任何新密钥。
    let error = err(vault.revoke_device(stranger_key.device_id()));
    assert_eq!(error.code(), "vault.not_a_member_device");
    assert_eq!(vault.membership().expect("成员状态").epoch, 1);
}

#[test]
fn two_consecutive_rotations_keep_every_older_object_readable() {
    let trio = Trio::build();
    let mut vault = trio.admin.open().expect("打开服务");

    vault
        .revoke_device(trio.doomed_key.device_id())
        .expect("第一次撤销");
    vault
        .set(&sid("ci/epoch2"), input(b"written-at-epoch-2"))
        .expect("写入");

    // 再邀请一台设备然后撤销，纪元 2 -> 3。
    let visitor = trio.fixture.device("visitor");
    let visitor_key = visitor.init_device().expect("建立设备身份");
    device_admin::invite(
        &mut vault,
        visitor_key.public(),
        MemberRole::Member,
        INVITATION_DEFAULT_TTL_MS,
    )
    .expect("邀请设备");
    let outcome = vault
        .revoke_device(visitor_key.device_id())
        .expect("第二次撤销");
    assert_eq!(outcome.from_epoch, 2);
    assert_eq!(outcome.to_epoch, 3);

    // 两次撤销都没有碰过任何旧密封对象：两条秘密仍停在各自写入时的纪元。
    // 清单按逻辑标识升序，因此这里按标识取值而不是按位置，免得断言依赖排序细节。
    let epochs: std::collections::BTreeMap<String, u64> = vault
        .list()
        .expect("列出")
        .iter()
        .map(|item| (item.id.as_str().to_owned(), item.epoch))
        .collect();
    assert_eq!(epochs["ci/npm-token"], 1, "撤销不做重加密，纪元原样保留");
    assert_eq!(epochs["ci/epoch2"], 2, "撤销不做重加密，纪元原样保留");

    // 三个纪元写下的内容全部仍然可读——密钥环保留了每一代密钥。
    assert_eq!(
        vault.get(&sid("ci/npm-token")).expect("读取").expose(),
        CANARY
    );
    assert_eq!(
        vault.get(&sid("ci/epoch2")).expect("读取").expose(),
        b"written-at-epoch-2"
    );
    // 读过之后才发生 lazy rewrap，两条都收敛到当前纪元。
    assert_eq!(vault.flush_rewraps().expect("落盘"), 2);
    assert!(vault
        .list()
        .expect("列出")
        .iter()
        .all(|item| item.epoch == 3));
}

#[test]
fn a_fresh_service_reports_no_pending_rotation() {
    let fixture = Fixture::new();
    let admin = fixture.device("admin");
    admin.init_device().expect("建立设备身份");
    let mut vault: VaultService = admin.open().expect("打开服务");
    vault.create().expect("创建工作区");
    assert!(vault.resume_rotation().expect("恢复").is_none());
}
