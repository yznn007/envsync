//! 多设备同步编排：fetch → 合并基 → 三方合并 → 投影 → 计划 → 显式应用。
//!
//! ```text
//! fetch          把远端 Ref 与其可达对象拉进本地草稿库（不碰用户文件）
//! merge_states   求本地草稿头与远端头的合并基，逐资源三方合并
//!                ├─ 干净 → 生成 parents = [local, remote] 的合并快照
//!                └─ 冲突 → 只写 ConflictStore，**不**生成快照
//! build_plan     目标状态先经 Profile 投影，再生成不可变计划
//! apply_plan     显式应用；存在未解决冲突时直接拒绝
//! ```
//!
//! ## 为什么冲突时什么都不做
//!
//! 合并冲突意味着「两台设备对同一份内容有不同的意图」，这只能由人来裁决。此时：
//!
//! * **不**生成快照——否则一个未经裁决的结果会成为共享历史的一部分；
//! * **不**推进远端 Ref；
//! * **不**改任何本地文件；
//! * 冲突 marker 绝不写进用户内容（[`crate::merge`] 保证）。
//!
//! 调用方看到的是 [`CoreError::Conflicted`]，CLI 把它映射成退出码 13。
//!
//! ## 合并基
//!
//! 沿 [`SnapshotBody::parents`] 逐层回溯求最近公共祖先：先收集本地一侧的全部祖先，
//! 再从远端一侧按**广度优先**推进，第一个落在祖先集合里的快照就是合并基。广度优先
//! 保证「最近」，`BTreeSet` 与排序后的 parents 保证结果确定。

use std::collections::{BTreeSet, VecDeque};

use envsync_backend::{Backend, BackendError};
use envsync_domain::{
    Blob, BlobId, CborCodec, Conflict, ConflictId, ConflictKind, DesiredDisposition, DeviceId,
    ObjectId, ObjectKind, ResourceEntry, ResourceId, SnapshotBody, SnapshotId, SnapshotSignature,
    StateRoot, StateRootId, WorkspaceId, CONFLICT_FORMAT_VERSION,
};
use envsync_storage::{ConflictRecord, ConflictState, ConflictStore, DraftStore};

use crate::error::{CoreError, CoreResult};
use crate::merge::{merge, MergeInput, MergeResult};
use crate::ports::Clock;

/// 回溯合并基时允许访问的最大快照数。
///
/// 历史来自远端，属于不可信输入：没有上限的图遍历是一个现成的资源耗尽面。触碰上限
/// 时报错而不是「猜一个基」——猜错会让三方合并把别人的改动当成删除。
pub const MAX_HISTORY_WALK: usize = 10_000;

/// `fetch` 的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOutcome {
    /// 远端当前 revision；从未发布过时为 `0`。
    pub revision: u64,
    /// 远端当前头。
    pub head: Option<SnapshotId>,
    /// 本次真正拉进草稿库的对象数量。
    pub objects: usize,
    /// 本地是否已经拥有远端头的全部可达对象。
    pub up_to_date: bool,
}

/// 合并的总体结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeKind {
    /// 远端没有新内容，或本地已经领先。
    AlreadyUpToDate,
    /// 本地是远端的祖先：直接采用远端状态，无需生成新快照。
    FastForward,
    /// 真正做了三方合并并生成了合并快照。
    Merged,
    /// 出现需要人工裁决的冲突；没有生成任何快照。
    Conflicted,
}

impl MergeKind {
    /// 稳定的机器可读名称。
    pub fn as_str(self) -> &'static str {
        match self {
            MergeKind::AlreadyUpToDate => "already_up_to_date",
            MergeKind::FastForward => "fast_forward",
            MergeKind::Merged => "merged",
            MergeKind::Conflicted => "conflicted",
        }
    }
}

/// `merge_states` 的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeOutcome {
    /// 总体结论。
    pub kind: MergeKind,
    /// 本地一侧的头（草稿头）。
    pub local: Option<SnapshotId>,
    /// 远端一侧的头。
    pub remote: Option<SnapshotId>,
    /// 合并基；没有共同祖先时为 `None`。
    pub base: Option<SnapshotId>,
    /// 合并后的目标快照；冲突时为 `None`。
    pub merged: Option<SnapshotId>,
    /// 合并后的 State Root；冲突时为 `None`。
    pub state_root: Option<StateRootId>,
    /// 本次登记的冲突，按标识升序。
    pub conflicts: Vec<ConflictId>,
    /// 参与合并的资源数量。
    pub resources: usize,
}

impl MergeOutcome {
    /// 是否存在需要人工裁决的冲突。
    pub fn is_conflicted(&self) -> bool {
        !self.conflicts.is_empty()
    }
}

/// 合并所需的全部协作者。
///
/// 用一个显式的上下文而不是 `&EnvSyncService`，是为了让合并逻辑可以在测试里脱离
/// 完整服务被单独驱动，同时明确它**只**触碰对象库与冲突索引——绝不碰用户文件。
pub struct MergeContext<'a> {
    /// 工作区标识。
    pub workspace: WorkspaceId,
    /// 本设备标识（合并快照的作者）。
    pub device: DeviceId,
    /// 设备显示名，写进快照元数据。
    pub device_name: &'a str,
    /// 本地草稿库。
    pub drafts: &'a DraftStore,
    /// 远端后端。
    pub backend: &'a dyn Backend,
    /// 冲突索引。
    pub conflicts: &'a ConflictStore,
    /// 时钟。
    pub clock: &'a dyn Clock,
}

impl MergeContext<'_> {
    /// 先查草稿库再查后端读取对象。
    pub fn read_object(&self, id: ObjectId) -> CoreResult<Vec<u8>> {
        if let Some(bytes) = self.drafts.get(id)? {
            return Ok(bytes);
        }
        match self.backend.get_object(id) {
            Ok(bytes) => Ok(bytes),
            Err(BackendError::ObjectNotFound(_)) => Err(CoreError::MissingObject(id.to_string())),
            Err(error) => Err(error.into()),
        }
    }

    /// 读取快照主体。
    pub fn snapshot(&self, id: SnapshotId) -> CoreResult<SnapshotBody> {
        let bytes = self.read_object(ObjectId::from(id))?;
        Ok(SnapshotBody::from_canonical_slice(&bytes)?)
    }

    /// 读取某个快照的 State Root。
    pub fn state_of(&self, id: SnapshotId) -> CoreResult<StateRoot> {
        let body = self.snapshot(id)?;
        let bytes = self.read_object(ObjectId::from(body.state_root))?;
        Ok(StateRoot::from_canonical_slice(&bytes)?)
    }

    /// 读取 Blob 内容。
    fn blob(&self, id: BlobId) -> CoreResult<Vec<u8>> {
        self.read_object(ObjectId::from(id))
    }
}

/// 把远端头可达的全部对象拉进本地草稿库。
///
/// 只做「复制对象」，不改 Ref、不碰用户文件、不生成快照：`fetch` 之后本机的可见
/// 行为应当完全不变，变化只发生在下一次 `merge` 与 `plan`。
pub fn fetch(
    context: &MergeContext<'_>,
    remote: Option<SnapshotId>,
    revision: u64,
) -> CoreResult<FetchOutcome> {
    let Some(head) = remote else {
        return Ok(FetchOutcome {
            revision,
            head: None,
            objects: 0,
            up_to_date: true,
        });
    };

    let mut objects = 0usize;
    let mut copy = |id: ObjectId| -> CoreResult<()> {
        if context.drafts.has(id)? {
            return Ok(());
        }
        let bytes = match context.backend.get_object(id) {
            Ok(bytes) => bytes,
            Err(BackendError::ObjectNotFound(_)) => {
                return Err(CoreError::MissingObject(id.to_string()))
            }
            Err(error) => return Err(error.into()),
        };
        context.drafts.put(id, &bytes)?;
        objects += 1;
        Ok(())
    };

    copy(ObjectId::from(head))?;
    let body = context.snapshot(head)?;
    copy(ObjectId::from(body.state_root))?;
    let state = context.state_of(head)?;
    for entry in state.entries.values() {
        if let Some(blob) = entry.blob {
            copy(ObjectId::from(blob))?;
        }
    }

    Ok(FetchOutcome {
        revision,
        head: Some(head),
        objects,
        up_to_date: objects == 0,
    })
}

/// 求两个快照的最近公共祖先。
///
/// 返回 `None` 表示两侧没有共同历史（例如各自独立初始化过工作区）；此时调用方应当
/// 按「无 base 的三方合并」处理，即双方都是新增。
pub fn find_merge_base(
    context: &MergeContext<'_>,
    local: SnapshotId,
    remote: SnapshotId,
) -> CoreResult<Option<SnapshotId>> {
    let ancestors = ancestors_of(context, local)?;
    let mut queue: VecDeque<SnapshotId> = VecDeque::new();
    let mut seen: BTreeSet<SnapshotId> = BTreeSet::new();
    queue.push_back(remote);
    let mut visited = 0usize;

    while let Some(current) = queue.pop_front() {
        if !seen.insert(current) {
            continue;
        }
        visited += 1;
        if visited > MAX_HISTORY_WALK {
            return Err(history_too_long());
        }
        if ancestors.contains(&current) {
            return Ok(Some(current));
        }
        // parents 在 `SnapshotBody::new` 中已排序去重，因此入队顺序是确定的。
        for parent in context.snapshot(current)?.parents {
            queue.push_back(parent);
        }
    }
    Ok(None)
}

/// 收集某个快照的全部祖先（含自身）。
fn ancestors_of(context: &MergeContext<'_>, head: SnapshotId) -> CoreResult<BTreeSet<SnapshotId>> {
    let mut seen: BTreeSet<SnapshotId> = BTreeSet::new();
    let mut queue: VecDeque<SnapshotId> = VecDeque::new();
    queue.push_back(head);
    while let Some(current) = queue.pop_front() {
        if !seen.insert(current) {
            continue;
        }
        if seen.len() > MAX_HISTORY_WALK {
            return Err(history_too_long());
        }
        for parent in context.snapshot(current)?.parents {
            queue.push_back(parent);
        }
    }
    Ok(seen)
}

fn history_too_long() -> CoreError {
    CoreError::ManualInterventionRequired(format!(
        "快照历史超过 {MAX_HISTORY_WALK} 个节点，拒绝继续回溯合并基"
    ))
}

/// 合并本地草稿头与远端头。
///
/// 干净合并会把新的 Blob、State Root、Snapshot 写进**草稿库**并设置草稿头；远端
/// Ref 不在这里推进——发布只发生在显式 `apply`。
pub fn merge_states(
    context: &MergeContext<'_>,
    local: Option<SnapshotId>,
    remote: Option<SnapshotId>,
) -> CoreResult<MergeOutcome> {
    let outcome = |kind: MergeKind, base, merged, state_root, resources| MergeOutcome {
        kind,
        local,
        remote,
        base,
        merged,
        state_root,
        conflicts: Vec::new(),
        resources,
    };

    let (Some(local_head), Some(remote_head)) = (local, remote) else {
        // 一侧为空时无需合并：没有本地草稿就直接用远端头，没有远端头就保持本地。
        return Ok(match (local, remote) {
            (None, Some(remote_head)) => {
                let state = context.state_of(remote_head)?;
                outcome(
                    MergeKind::FastForward,
                    None,
                    Some(remote_head),
                    Some(state.id()),
                    state.len(),
                )
            }
            (local_head, _) => outcome(MergeKind::AlreadyUpToDate, None, local_head, None, 0),
        });
    };

    if local_head == remote_head {
        return Ok(outcome(
            MergeKind::AlreadyUpToDate,
            Some(local_head),
            Some(local_head),
            None,
            0,
        ));
    }

    let base = find_merge_base(context, local_head, remote_head)?;
    if base == Some(local_head) {
        // 本地是远端的祖先：远端已经包含本地的全部内容。
        let state = context.state_of(remote_head)?;
        return Ok(outcome(
            MergeKind::FastForward,
            base,
            Some(remote_head),
            Some(state.id()),
            state.len(),
        ));
    }
    if base == Some(remote_head) {
        // 本地已经领先，远端没有新东西。
        return Ok(outcome(
            MergeKind::AlreadyUpToDate,
            base,
            Some(local_head),
            None,
            0,
        ));
    }

    let base_state = match base {
        Some(id) => context.state_of(id)?,
        None => StateRoot::empty(),
    };
    let ours = context.state_of(local_head)?;
    let theirs = context.state_of(remote_head)?;

    let mut merged_entries: Vec<ResourceEntry> = Vec::new();
    let mut new_blobs: Vec<Blob> = Vec::new();
    let mut conflicts: BTreeSet<ConflictId> = BTreeSet::new();

    // 三侧资源的并集，按标识升序：合并结果因此与输入顺序无关。
    let mut resources: BTreeSet<&ResourceId> = BTreeSet::new();
    resources.extend(base_state.entries.keys());
    resources.extend(ours.entries.keys());
    resources.extend(theirs.entries.keys());
    let resource_count = resources.len();

    for resource in resources {
        let base_entry = base_state.get(resource);
        let ours_entry = ours.get(resource);
        let theirs_entry = theirs.get(resource);

        match merge_resource(
            context,
            resource,
            base_entry,
            ours_entry,
            theirs_entry,
            &mut new_blobs,
        )? {
            ResourceMerge::Keep(Some(entry)) => merged_entries.push(entry),
            ResourceMerge::Keep(None) => {}
            ResourceMerge::Conflict(conflict) => {
                conflicts.insert(record_conflict(context, &conflict)?);
            }
        }
    }

    if !conflicts.is_empty() {
        // 有冲突就什么都不产出：不写快照、不设草稿头、不碰用户文件。
        return Ok(MergeOutcome {
            kind: MergeKind::Conflicted,
            local,
            remote,
            base,
            merged: None,
            state_root: None,
            conflicts: conflicts.into_iter().collect(),
            resources: resource_count,
        });
    }

    let state = StateRoot::from_entries(merged_entries)
        .map_err(|error| CoreError::Domain(error.to_string()))?;
    let state_bytes = state.to_canonical_vec();
    let state_id = state.id();

    for blob in &new_blobs {
        context
            .drafts
            .put(ObjectId::from(blob.id()), blob.bytes())?;
    }
    context.drafts.put(ObjectId::from(state_id), &state_bytes)?;

    // 工作区级元数据（M2 起是 Vault 索引指针与背书）必须跨合并存活，理由与 `capture`
    // 完全相同：它描述的是「这个工作区现在是什么样」，不是「这一次合并做了什么」。
    //
    // 两侧都可能带着它，取值规则是**远端优先**：本地草稿头的那一份来自 capture 当时的
    // 基线，而远端头是刚从后端读到的。冲突时选后者，代价最多是丢掉一次本机尚未发布的
    // Vault 变更（它下一次 Vault 发布会自己写回去），而反过来会把别人已经发布的 Vault
    // 变更盖掉——那是不可逆的。
    let mut metadata =
        crate::vault::inherited_workspace_metadata(&context.snapshot(local_head)?.metadata);
    metadata.extend(crate::vault::inherited_workspace_metadata(
        &context.snapshot(remote_head)?.metadata,
    ));
    metadata.insert("device_name".to_owned(), context.device_name.to_owned());
    metadata.insert("format".to_owned(), "envsync/m1".to_owned());
    metadata.insert("merge".to_owned(), "three_way".to_owned());

    let body = SnapshotBody::new(
        context.workspace,
        vec![local_head, remote_head],
        state_id,
        context.device,
        context.clock.now_unix_ms(),
        metadata,
    )
    .map_err(|error| CoreError::Domain(error.to_string()))?;
    let body_bytes = body.to_canonical_vec();
    let snapshot_id = body.id();
    context
        .drafts
        .put(ObjectId::from(snapshot_id), &body_bytes)?;

    let signature = SnapshotSignature::unsigned(snapshot_id, context.device);
    let signature_bytes = signature.to_canonical_vec();
    context.drafts.put(
        ObjectId::for_bytes(ObjectKind::SnapshotSignature, &signature_bytes),
        &signature_bytes,
    )?;
    context.drafts.set_head_draft(snapshot_id)?;

    Ok(MergeOutcome {
        kind: MergeKind::Merged,
        local,
        remote,
        base,
        merged: Some(snapshot_id),
        state_root: Some(state_id),
        conflicts: Vec::new(),
        resources: resource_count,
    })
}

/// 单个资源的合并结论。
enum ResourceMerge {
    /// 已确定结果：`None` 表示该资源在合并结果中不存在。
    Keep(Option<ResourceEntry>),
    /// 需要人工裁决。
    Conflict(Conflict),
}

/// 三方合并单个资源。
fn merge_resource(
    context: &MergeContext<'_>,
    resource: &ResourceId,
    base: Option<&ResourceEntry>,
    ours: Option<&ResourceEntry>,
    theirs: Option<&ResourceEntry>,
    new_blobs: &mut Vec<Blob>,
) -> CoreResult<ResourceMerge> {
    // 条目级快速路径：与内容无关，先把三种「无需看字节」的情况解决掉。
    if ours == theirs {
        return Ok(ResourceMerge::Keep(ours.cloned()));
    }
    if base == ours {
        return Ok(ResourceMerge::Keep(theirs.cloned()));
    }
    if base == theirs {
        return Ok(ResourceMerge::Keep(ours.cloned()));
    }

    // 双方都改了。元数据（模式、策略、处置）不一致时无法机械合并：写入语义本身
    // 有分歧，任何一侧都可能让另一侧的文件被错误改写。
    if let (Some(ours_entry), Some(theirs_entry)) = (ours, theirs) {
        if ours_entry.mode != theirs_entry.mode
            || ours_entry.policy != theirs_entry.policy
            || ours_entry.disposition != theirs_entry.disposition
        {
            return Ok(ResourceMerge::Conflict(Conflict {
                format_version: CONFLICT_FORMAT_VERSION,
                resource: resource.clone(),
                kind: ConflictKind::IncompatiblePolicy,
                base: base.and_then(|entry| entry.blob),
                ours: ours_entry.blob,
                theirs: theirs_entry.blob,
                diagnostics: vec!["双方对写入模式或策略的声明不一致".to_owned()],
            }));
        }
    }

    let base_bytes = blob_bytes(context, base)?;
    let ours_bytes = blob_bytes(context, ours)?;
    let theirs_bytes = blob_bytes(context, theirs)?;
    let format = ours
        .or(theirs)
        .and_then(|entry| entry.policy.structured_format);

    let input = MergeInput {
        resource,
        base: base_bytes.as_deref(),
        ours: ours_bytes.as_deref(),
        theirs: theirs_bytes.as_deref(),
    };
    let result = merge(&input, format).map_err(CoreError::Merge)?;

    let template = ours.or(theirs).ok_or_else(|| {
        CoreError::Invariant(format!("资源 {resource} 在三侧都不存在却进入了合并"))
    })?;

    match result {
        MergeResult::Clean { bytes, .. } => {
            let blob = Blob::new(bytes);
            let mut entry = template.clone();
            entry.disposition = DesiredDisposition::Managed;
            entry.blob = Some(blob.id());
            new_blobs.push(blob);
            Ok(ResourceMerge::Keep(Some(entry)))
        }
        MergeResult::Deleted => Ok(ResourceMerge::Keep(None)),
        MergeResult::Conflict(conflict) => {
            // 用户可能早就裁决过同一个冲突：冲突是内容寻址的，同样的三侧内容必然
            // 得到同一个标识，因此这里可以直接复用既有决定，让同步继续走完。
            match resolved_entry(context, &conflict, template)? {
                Some(resolution) => Ok(ResourceMerge::Keep(resolution)),
                None => Ok(ResourceMerge::Conflict(conflict)),
            }
        }
    }
}

/// 查询该冲突是否已被裁决；已裁决则返回应当采用的条目。
///
/// 外层 `Option` 区分「有裁决 / 无裁决」，内层区分「保留内容 / 确认删除」。
fn resolved_entry(
    context: &MergeContext<'_>,
    conflict: &Conflict,
    template: &ResourceEntry,
) -> CoreResult<Option<Option<ResourceEntry>>> {
    let id = conflict.id();
    let Some(record) = context.conflicts.get(id)? else {
        return Ok(None);
    };
    if record.state != ConflictState::Resolved {
        return Ok(None);
    }
    Ok(Some(match record.resolved_blob {
        Some(blob) => {
            let mut entry = template.clone();
            entry.disposition = DesiredDisposition::Managed;
            entry.blob = Some(blob);
            Some(entry)
        }
        // `Delete` 是用户显式确认的删除，是唯一可以让资源消失的裁决。
        None => None,
    }))
}

/// 登记冲突：对象进草稿库，索引进冲突表。
fn record_conflict(context: &MergeContext<'_>, conflict: &Conflict) -> CoreResult<ConflictId> {
    let bytes = conflict.to_canonical_vec();
    let id = conflict.id();
    context.drafts.put(ObjectId::from(id), &bytes)?;
    Ok(context.conflicts.record(context.workspace, conflict)?)
}

/// 读取条目对应的内容；条目不存在或没有内容时返回 `None`。
fn blob_bytes(
    context: &MergeContext<'_>,
    entry: Option<&ResourceEntry>,
) -> CoreResult<Option<Vec<u8>>> {
    match entry.and_then(|entry| entry.blob) {
        Some(blob) => Ok(Some(context.blob(blob)?)),
        None => Ok(None),
    }
}

/// 冲突详情：本地索引 + 不可变冲突对象。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictDetail {
    /// 本地索引记录（状态、解决方式等可变事实）。
    pub record: ConflictRecord,
    /// 内容寻址的冲突对象（三侧摘要与诊断）。
    pub conflict: Conflict,
}
