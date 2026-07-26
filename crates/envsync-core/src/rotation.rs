//! 可恢复的密钥轮换编排。
//!
//! 撤销一台设备不是「从名单里划掉一行」，而是一次跨越后端、安全存储和本地 journal 的
//! 状态迁移：
//!
//! ```text
//! prepared → envelopes_published → head_published → rewrapping → complete
//! ```
//!
//! 进程可能在任何两步之间被杀死；[`drive`] 保证从**任何**阶段恢复都能得到同一个终态。
//!
//! ## 唯一不可颠倒的顺序：信封先于新头
//!
//! 新头（推进纪元的 `Revoke` 事件 + 新快照）一旦发布，工作区的纪元就是 `n+1`。此时若
//! 信封还没发布，剩余设备拿不到 `n+1` 的数据密钥，工作区会卡在「所有人都读不了新内容」
//! 的状态——而这是后端上的既成事实，重试无法自愈。
//!
//! 反过来「信封发布了、新头还没发」是完全安全的：多出来的信封只是几个没人引用的不可变
//! 对象，下一次恢复原样复用它们。
//!
//! 因此 [`drive`] 在进入 [`RotationStage::HeadPublished`] **之前**会实际回后端确认每个
//! 信封对象都在（[`RotationSteps::envelopes_present`]），不在就以
//! [`RotationError::EnvelopesMissing`] 中止。这不是断言，是运行期检查：journal 说
//! 「发过了」而后端说「没有」时，可信的是后端。
//!
//! ## 幂等靠的是「一切可重放」
//!
//! * 新纪元的数据密钥在 `prepared` 阶段就写进密钥环，并且
//!   [`crate::vault::KeyRing::insert`] **已存在不覆盖**；
//! * 信封、成员事件、密封对象都是内容寻址的不可变对象，重复写入是幂等的；
//! * `Revoke` 事件的创建时刻固定在 journal 的 `event_created_at_unix_ms`，因此每次重放
//!   都签出**字节完全相同**的事件，摘要不变、链头不变；
//! * 快照发布在内容未变时直接跳过 CAS，不会白白推进 revision。
//!
//! ## 撤销之后旧设备读不到新内容
//!
//! 新纪元的信封只发给剩余设备。被撤销的那台既拿不到 `n+1` 的数据密钥（HPKE 信封绑定
//! 收件设备，换一台设备打开会得到 [`envsync_crypto::CryptoError::RecipientMismatch`]），
//! 也无法伪造成员事件（它已经从成员链上消失，签名会被
//! [`crate::membership::MembershipError::ActorUnknown`] 拒绝）。
//!
//! ## 撤销**不**重加密旧对象（lazy rewrap）
//!
//! `rewrapping` 阶段只做一件事：把「还停在旧纪元的秘密」列进
//! [`RotationRecord::pending_rewrap`]。旧密封对象原样留在后端上，直到某台仍有权限的
//! 设备**读到**它时，才用新纪元密钥重新密封（[`crate::vault::VaultService::get`]），
//! 索引在下一次写操作或 [`crate::vault::VaultService::flush_rewraps`] 时更新。
//!
//! 为什么不在撤销时一次性重加密完：
//!
//! * **可恢复性。** eager 重加密要在一次操作里重写整个 Vault，中途失败会留下一半新、
//!   一半旧的索引；lazy 的每一步都是幂等的单对象操作。
//! * **撤销的延迟不该随 Vault 大小增长。** 一个装着上千条秘密的工作区，撤销一台设备
//!   本该是一次链上事件加几份信封，而不是一轮全量重写。
//! * **它换不来任何安全属性。** 被撤销的设备手里仍然留着旧纪元的数据密钥，后端上的旧
//!   密封对象是不可变的、它本来就已经拿到过——重加密**追不回已经发出去的密文**。撤销
//!   给的是前向保密（读不到**新**内容），不是追溯保密。rewrap 的价值只是让「当前有效
//!   密钥集合」逐渐收敛到一把，与安全边界无关。详见
//!   `docs/security/vault-format.md` §5.2。

use envsync_crypto::suite::KeyEpoch;
use envsync_domain::id::DeviceId;
use envsync_domain::membership::MembershipAction;
use envsync_domain::object::ObjectId;
use envsync_storage::rotation::{RotationJournal, RotationRecord, RotationStage};

use crate::error::{CoreError, CoreResult};
use crate::membership;
use crate::vault::{VaultError, VaultService};

/// 轮换编排错误。
///
/// 与其余核心层错误一致：只描述结构，不携带密钥材料。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RotationError {
    /// journal 声称信封已发布，后端上却找不到。
    ///
    /// 出现它时**新头一定还没有发布**——这正是本模块存在的意义。
    #[error("轮换中止：journal 记录的信封在后端上不存在，拒绝在此基础上发布新头")]
    EnvelopesMissing,

    /// 剩余设备为空：撤销之后工作区将没有任何成员。
    ///
    /// 成员链的「最后一个管理员」规则本应先拦下它，这里是第二道闸。
    #[error("轮换中止：撤销之后工作区将没有任何设备")]
    NoRecipients,

    /// journal 里的纪元与当前成员链不一致。
    #[error("轮换 journal 与成员链不一致：journal 说从纪元 {journal} 出发，链上却是 {chain}")]
    EpochMismatch {
        /// journal 记录的起始纪元。
        journal: u64,
        /// 成员链当前的纪元。
        chain: u64,
    },

    /// 已经有一次进行中的轮换，且撤销目标不同。
    #[error("已有一次进行中的轮换（撤销设备 {pending}），请先完成它")]
    AlreadyInProgress {
        /// 进行中那次轮换的撤销目标。
        pending: DeviceId,
    },

    /// 撤销目标是本设备自己。
    ///
    /// 这不是一条谨慎起见的限制，而是一条**必要**的限制，见
    /// [`VaultService::revoke_device`] 的文档。
    #[error("不能撤销本设备自己；请在另一台管理员设备上撤销它，本机随后用 `envsync device forget` 清理身份")]
    CannotRevokeSelf,
}

impl RotationError {
    /// 稳定的机器可读错误码，用于 CLI 的 JSON 契约。
    pub fn code(&self) -> &'static str {
        match self {
            RotationError::EnvelopesMissing => "rotation.envelopes_missing",
            RotationError::NoRecipients => "rotation.no_recipients",
            RotationError::EpochMismatch { .. } => "rotation.epoch_mismatch",
            RotationError::AlreadyInProgress { .. } => "rotation.already_in_progress",
            RotationError::CannotRevokeSelf => "rotation.cannot_revoke_self",
        }
    }
}

/// 一次轮换（或恢复）的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationOutcome {
    /// 被撤销的设备。
    pub revoked: DeviceId,
    /// 轮换前的纪元。
    pub from_epoch: u64,
    /// 轮换后的纪元。
    pub to_epoch: u64,
    /// 停下时所处的阶段。正常完成时为 [`RotationStage::Complete`]。
    pub stage: RotationStage,
    /// 收到新信封的设备数量。
    pub envelopes: usize,
    /// 仍停留在旧纪元、等待 lazy rewrap 的秘密条数。
    ///
    /// 它**不是**待办事项清单上的一个警报：这些秘密现在就能正常读写，只是密封所用的
    /// 数据密钥还是旧纪元的那一把，会在下一次被读到时顺手换掉（见模块文档）。
    pub pending_rewrap: usize,
    /// 本次调用是不是在恢复一次先前被中断的轮换。
    pub resumed: bool,
}

/// 轮换的四个副作用步骤。
///
/// 把它抽成 trait 的目的不是可替换性，而是**让状态机本身可以被单独读懂**：
/// [`drive`] 里没有任何后端细节，只有「先做什么、做完写什么、什么条件下拒绝前进」。
pub trait RotationSteps {
    /// 给每个剩余设备封装并发布新纪元的信封，返回对象标识的文本形式。
    ///
    /// 必须幂等：重复调用可以产生新的对象（HPKE 临时密钥是随机的），但不得产生任何
    /// 需要清理的副作用。
    fn publish_envelopes(&mut self, record: &RotationRecord) -> CoreResult<Vec<String>>;

    /// 确认这批信封对象**确实**在后端上。
    fn envelopes_present(&self, envelopes: &[String]) -> CoreResult<bool>;

    /// 发布推进纪元的成员事件与新快照头，并把密钥环的当前纪元指针推到新纪元。
    ///
    /// 必须幂等：链上已经到达目标纪元时直接返回成功。
    fn publish_head(&mut self, record: &RotationRecord) -> CoreResult<()>;

    /// 计算「还有哪些秘密停留在旧纪元」。
    ///
    /// 结果只被**记录**下来，不会在轮换过程中被处理：重加密按 lazy 策略发生在读取时，
    /// 见模块文档。
    fn stale_secrets(&self, record: &RotationRecord) -> CoreResult<Vec<String>>;
}

/// 驱动状态机直到 `stop_before` 指定的阶段之前，或直到 [`RotationStage::Complete`]。
///
/// `stop_before` 为 `None` 时一路跑到底。给它一个值等价于「在进入这个阶段之前把进程
/// 杀掉」——这是**唯一**需要它的场景：测试中断恢复。它不会跳过任何检查，只是提前
/// 返回，因此「中断后 journal 与后端的状态」与真实崩溃完全一致。
///
/// `resuming` 只影响 [`RotationOutcome::resumed`] 这一个纯汇报字段：它回答「本次调用
/// 开始时 journal 里是不是已经有一条进行中的记录」。这个问题状态机自己答不了——
/// 一次刚被中断在 `prepared` 的轮换，与一次全新的轮换，记录长得一模一样。
///
/// # 错误
///
/// * [`RotationError::EnvelopesMissing`]：journal 说信封发过了，后端上却没有。此时
///   **新头一定还没有发布**，重试是安全的。
pub fn drive<S>(
    steps: &mut S,
    journal: &RotationJournal,
    now_ms: u64,
    mut record: RotationRecord,
    stop_before: Option<RotationStage>,
    resuming: bool,
) -> CoreResult<RotationOutcome>
where
    S: RotationSteps,
{
    while let Some(next) = record.stage.next() {
        if stop_before == Some(next) {
            break;
        }
        match next {
            RotationStage::Prepared => {
                // `next()` 永远不会回到起点；写出来只是让匹配是穷尽的。
                return Err(CoreError::Invariant(
                    "轮换状态机不可能倒退回 prepared".to_owned(),
                ));
            }
            RotationStage::EnvelopesPublished => {
                record.envelopes = steps.publish_envelopes(&record)?;
            }
            RotationStage::HeadPublished => {
                // 关键闸门：新头绝不能引用尚未发布的信封。信任后端而不是 journal。
                if !steps.envelopes_present(&record.envelopes)? {
                    return Err(RotationError::EnvelopesMissing.into());
                }
                steps.publish_head(&record)?;
            }
            RotationStage::Rewrapping => {
                // 只登记，不动手：旧对象按 lazy rewrap 在被读到时才重新密封。
                record.pending_rewrap = steps.stale_secrets(&record)?;
            }
            RotationStage::Complete => {
                // 轮换到此为止。清单在上一阶段已经算好，这里不重算——重算会把
                // 「轮换期间别人恰好读了一条秘密」变成清单抖动，而清单是要落 journal 的。
            }
        }
        record.stage = next;
        record.updated_at_unix_ms = now_ms;
        // 先做副作用、再落 journal。反过来的话，journal 会声称某一步已完成而后端上
        // 什么都没有——恢复流程就会在错误的前提上继续。
        journal.upsert(&record)?;
    }

    Ok(RotationOutcome {
        revoked: record.revoked_device,
        from_epoch: record.from_epoch,
        to_epoch: record.to_epoch,
        stage: record.stage,
        envelopes: record.envelopes.len(),
        pending_rewrap: record.pending_rewrap.len(),
        resumed: resuming,
    })
}

impl VaultService {
    /// 撤销一台设备并轮换工作区数据密钥。
    ///
    /// 已有未完成的轮换时**自动接着做**，而不是重新开始：这让「撤销失败后重跑同一条
    /// 命令」成为正确的补救动作。
    ///
    /// # 为什么不能撤销本设备自己
    ///
    /// 成员链本身允许一个管理员撤销自己（只要工作区还剩至少一个管理员）。但那一步会
    /// 产生一个**由非成员签出**的头快照：撤销事件把本设备从名单上抹掉，而这个头的
    /// Vault 索引背书恰恰是本设备刚刚签的（见 [`crate::attestation`]）。读路径要求背书
    /// 由**当前**成员签出，于是这个头对**所有人**都不可读——包括其余管理员，而他们
    /// 又必须先读到头才能发布新头。工作区就此永久锁死，只能走灾难恢复。
    ///
    /// 因此这里直接拒绝。正确做法是在另一台管理员设备上撤销它，本机随后用
    /// `envsync device forget` 清理身份。
    pub fn revoke_device(&mut self, subject: DeviceId) -> CoreResult<RotationOutcome> {
        self.revoke_device_until(subject, None)
    }

    /// 撤销并轮换，但在进入 `stop_before` 阶段之前停下。
    ///
    /// 只有中断恢复测试需要 `stop_before`；生产路径请用
    /// [`VaultService::revoke_device`]。
    pub fn revoke_device_until(
        &mut self,
        subject: DeviceId,
        stop_before: Option<RotationStage>,
    ) -> CoreResult<RotationOutcome> {
        if subject == self.device_id() {
            return Err(RotationError::CannotRevokeSelf.into());
        }
        let resuming = self.rotations().get_unfinished(self.workspace())?.is_some();
        let record = self.prepare_rotation(subject)?;
        let now = self.clock().now_unix_ms();
        let journal = RotationJournal::open(self.rotations().database_path())?;
        drive(self, &journal, now, record, stop_before, resuming)
    }

    /// 恢复一次被中断的轮换；没有未完成的轮换时返回 `None`。
    ///
    /// 任何需要用到当前纪元的操作都可以先调用它——它在没有半成品时是零成本的。
    pub fn resume_rotation(&mut self) -> CoreResult<Option<RotationOutcome>> {
        let Some(record) = self.rotations().get_unfinished(self.workspace())? else {
            return Ok(None);
        };
        let now = self.clock().now_unix_ms();
        let journal = RotationJournal::open(self.rotations().database_path())?;
        Ok(Some(drive(self, &journal, now, record, None, true)?))
    }

    /// 建立（或取回）一次轮换的 `prepared` 记录。
    ///
    /// 新纪元的数据密钥在这里生成并写进密钥环。密钥先落安全存储、journal 后写：反过来
    /// 的话，进程崩在两步之间就会留下一条指向不存在密钥的 journal 记录。
    fn prepare_rotation(&mut self, subject: DeviceId) -> CoreResult<RotationRecord> {
        if let Some(existing) = self.rotations().get_unfinished(self.workspace())? {
            if existing.revoked_device != subject {
                return Err(RotationError::AlreadyInProgress {
                    pending: existing.revoked_device,
                }
                .into());
            }
            let chain_epoch = self.membership()?.epoch;
            // 链已经推进到目标纪元时，journal 的 from_epoch 自然会比链低一格——那是
            // 「新头已发布」的正常状态，不是不一致。
            if chain_epoch != existing.from_epoch && chain_epoch != existing.to_epoch {
                return Err(RotationError::EpochMismatch {
                    journal: existing.from_epoch,
                    chain: chain_epoch,
                }
                .into());
            }
            return Ok(existing);
        }

        self.require_admin()?;
        let state = self.membership()?;
        if !state.contains(&subject) {
            return Err(VaultError::NotAMemberDevice { device: subject }.into());
        }
        let from_epoch = state.epoch;
        let to_epoch = from_epoch + 1;
        let recipients = self.recipients_except(subject)?;
        if recipients.is_empty() {
            return Err(RotationError::NoRecipients.into());
        }

        let mut ring = self.load_keyring()?;
        if !ring.contains(KeyEpoch::new(to_epoch)) {
            ring.insert(
                KeyEpoch::new(to_epoch),
                envsync_crypto::suite::DataKey::generate()?,
            );
            self.store_keyring(&ring)?;
        }

        let now = self.clock().now_unix_ms();
        let record = RotationRecord {
            workspace: self.workspace(),
            from_epoch,
            to_epoch,
            revoked_device: subject,
            stage: RotationStage::Prepared,
            recipients,
            envelopes: Vec::new(),
            pending_rewrap: Vec::new(),
            event_created_at_unix_ms: now,
            started_at_unix_ms: now,
            updated_at_unix_ms: now,
        };
        self.rotations().upsert(&record)?;
        Ok(record)
    }
}

impl RotationSteps for VaultService {
    fn publish_envelopes(&mut self, record: &RotationRecord) -> CoreResult<Vec<String>> {
        let epoch = KeyEpoch::new(record.to_epoch);
        let ring = self.load_keyring()?;
        let key = ring.key(epoch)?;
        let mut out = Vec::with_capacity(record.recipients.len());
        for device in &record.recipients {
            let public = self.member_public(*device)?;
            out.push(self.publish_envelope(&public, epoch, key)?.to_string());
        }
        Ok(out)
    }

    fn envelopes_present(&self, envelopes: &[String]) -> CoreResult<bool> {
        if envelopes.is_empty() {
            return Ok(false);
        }
        let mut ids = Vec::with_capacity(envelopes.len());
        for text in envelopes {
            let id = text.parse::<ObjectId>().map_err(|_| {
                CoreError::from(VaultError::IndexInconsistent {
                    detail: "轮换 journal 里的信封对象标识无法解析",
                })
            })?;
            ids.push(id);
        }
        self.objects_present(&ids)
    }

    fn publish_head(&mut self, record: &RotationRecord) -> CoreResult<()> {
        let epoch = KeyEpoch::new(record.to_epoch);
        if self.membership()?.epoch == record.to_epoch {
            // 新头已经发布过（上一次运行崩在了写 journal 之前）。只补上密钥环指针。
            let mut ring = self.load_keyring()?;
            ring.promote(epoch)?;
            self.store_keyring(&ring)?;
            return Ok(());
        }

        let state = self.membership()?.clone();
        let event = membership::append(
            &state,
            self.keypair(),
            MembershipAction::Revoke {
                subject: record.revoked_device,
            },
            self.workspace(),
            // 固定时刻：重放必须签出字节完全相同的事件。
            record.event_created_at_unix_ms,
        )?;
        let object = self.put_membership_event(&event)?;

        let genesis = self.genesis()?.clone();
        let mut events = self.events().to_vec();
        events.push(event.clone());
        let next_state = membership::verify_membership_chain(&genesis, &events, self.workspace())?;

        let mut index = self.index_clone();
        index.membership.push(object);
        index.epoch = next_state.epoch;
        // 新纪元的信封整体替换旧的：索引里只保留“当前纪元谁能读”，历史信封留在后端上
        // 但不再被引用。
        index.envelopes = record
            .envelopes
            .iter()
            .map(|text| {
                text.parse::<ObjectId>().map_err(|_| {
                    CoreError::from(VaultError::IndexInconsistent {
                        detail: "轮换 journal 里的信封对象标识无法解析",
                    })
                })
            })
            .collect::<CoreResult<Vec<_>>>()?;

        self.record_event(event, next_state);
        self.publish(index)?;

        // 指针最后才推：先推指针再发布的话，中途失败会让本机用一把别人还拿不到的密钥
        // 去加密新秘密。
        let mut ring = self.load_keyring()?;
        ring.promote(epoch)?;
        self.store_keyring(&ring)?;
        Ok(())
    }

    fn stale_secrets(&self, record: &RotationRecord) -> CoreResult<Vec<String>> {
        Ok(self.stale_secret_ids(record.to_epoch))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envsync_domain::id::WorkspaceId;

    /// 只记录调用顺序的假步骤实现，用来单独验证状态机本身。
    #[derive(Default)]
    struct Recorder {
        calls: Vec<&'static str>,
        envelopes_on_backend: bool,
        /// `stale_secrets` 拿的是 `&self`（它是纯查询），因此计数要用内部可变性。
        stale_calls: std::cell::Cell<usize>,
    }

    impl RotationSteps for Recorder {
        fn publish_envelopes(&mut self, _record: &RotationRecord) -> CoreResult<Vec<String>> {
            self.calls.push("envelopes");
            Ok(vec!["envelope/aa".to_owned()])
        }
        fn envelopes_present(&self, _envelopes: &[String]) -> CoreResult<bool> {
            Ok(self.envelopes_on_backend)
        }
        fn publish_head(&mut self, _record: &RotationRecord) -> CoreResult<()> {
            self.calls.push("head");
            Ok(())
        }
        fn stale_secrets(&self, _record: &RotationRecord) -> CoreResult<Vec<String>> {
            self.stale_calls.set(self.stale_calls.get() + 1);
            Ok(vec!["ci/npm-token".to_owned()])
        }
    }

    fn record(workspace: WorkspaceId) -> RotationRecord {
        RotationRecord {
            workspace,
            from_epoch: 1,
            to_epoch: 2,
            revoked_device: DeviceId::derive(b"revoked"),
            stage: RotationStage::Prepared,
            recipients: vec![DeviceId::derive(b"keeper")],
            envelopes: Vec::new(),
            pending_rewrap: Vec::new(),
            event_created_at_unix_ms: 1,
            started_at_unix_ms: 1,
            updated_at_unix_ms: 1,
        }
    }

    fn journal() -> (tempfile::TempDir, RotationJournal) {
        let dir = tempfile::tempdir().expect("临时目录");
        let journal = RotationJournal::open(dir.path().join("rotation.db")).expect("打开");
        (dir, journal)
    }

    #[test]
    fn stages_run_in_order_and_stop_before_is_honoured() {
        let (_dir, journal) = journal();
        let workspace = WorkspaceId::generate();
        let mut steps = Recorder {
            envelopes_on_backend: true,
            ..Recorder::default()
        };
        let outcome = drive(
            &mut steps,
            &journal,
            2,
            record(workspace),
            Some(RotationStage::HeadPublished),
            false,
        )
        .expect("推进");
        assert_eq!(outcome.stage, RotationStage::EnvelopesPublished);
        assert_eq!(steps.calls, ["envelopes"]);

        // 从 journal 里读回来继续，顺序仍然正确且不重复做已完成的步骤。
        let resumed = journal.get(workspace).expect("读取").expect("存在");
        let outcome = drive(&mut steps, &journal, 3, resumed, None, true).expect("恢复");
        assert_eq!(outcome.stage, RotationStage::Complete);
        assert!(outcome.resumed);
        // 状态机**不**调用任何重加密步骤：`rewrapping` 只登记清单，`complete` 什么都不做。
        assert_eq!(steps.calls, ["envelopes", "head"]);
        assert_eq!(steps.stale_calls.get(), 1, "清单只该被算一次");
        assert_eq!(
            outcome.pending_rewrap, 1,
            "停留在旧纪元的秘密必须被如实报出来"
        );
    }

    #[test]
    fn head_is_refused_when_envelopes_are_not_on_the_backend() {
        let (_dir, journal) = journal();
        let workspace = WorkspaceId::generate();
        // journal 声称发过信封，后端却说没有——必须中止，而不是硬着头皮发新头。
        let mut record = record(workspace);
        record.stage = RotationStage::EnvelopesPublished;
        record.envelopes = vec!["envelope/aa".to_owned()];
        let mut steps = Recorder {
            envelopes_on_backend: false,
            ..Recorder::default()
        };
        let error = drive(&mut steps, &journal, 4, record, None, false).unwrap_err();
        assert_eq!(error.code(), "rotation.envelopes_missing");
        assert!(steps.calls.is_empty(), "新头绝不能被发布");
    }
}
