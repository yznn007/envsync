//! 本地草稿对象存储的行为测试。
//!
//! 覆盖：内容寻址往返、写入与读取两端的摘要校验、计划存取、草稿头，
//! 以及草稿表与 journal 表共存互不干扰。

use envsync_domain::cbor::CborCodec;
use envsync_domain::id::{Digest32, ResourceId, SnapshotId, WorkspaceId};
use envsync_domain::object::{ObjectId, ObjectKind};
use envsync_domain::plan::{
    Action, ActionKind, ActionTarget, BackupPolicy, Plan, Risk, RollbackCapability, VerifyRule,
};
use envsync_domain::snapshot::WorkspaceRef;
use envsync_domain::{BlobId, DeviceId};
use envsync_storage::draft::{DraftError, DraftStore, DATABASE_FILE_NAME};
use envsync_storage::journal::{Journal, OperationState};
use tempfile::TempDir;

/// 构造一个测试用计划。
fn sample_plan(resource: &str) -> Plan {
    let workspace = WorkspaceId::generate();
    let snapshot = SnapshotId::of(resource.as_bytes());
    let after = Digest32::domain_hash("test:after", resource.as_bytes());
    let action = Action {
        resource: ResourceId::parse(resource).expect("资源标识合法"),
        kind: ActionKind::CreateFile,
        target: ActionTarget {
            root: "home".into(),
            segments: vec![".zshrc".into()],
        },
        expected_before: None,
        expected_after: Some(after),
        content: Some(BlobId::of(resource.as_bytes())),
        risk: Risk::Low,
        backup: BackupPolicy::NotApplicable,
        rollback: RollbackCapability::Exact,
        unix_mode: Some(0o600),
        secret: false,
        verify: VerifyRule::ExpectDigest(after),
    };
    Plan::new(
        workspace,
        DeviceId::derive(b"test-device"),
        snapshot,
        0,
        WorkspaceRef::initial(workspace).advance(snapshot),
        vec![],
        vec![action],
        vec![],
        1_700_000_000_000,
    )
}

#[test]
fn objects_round_trip_through_the_draft_store() {
    let dir = TempDir::new().expect("临时目录");
    let store = DraftStore::open(dir.path()).expect("打开草稿库");
    assert_eq!(
        store.database_path(),
        dir.path().join(DATABASE_FILE_NAME).as_path()
    );

    let blob = b"export EDITOR=nvim\n".as_slice();
    let blob_id = ObjectId::for_bytes(ObjectKind::Blob, blob);
    let state = b"canonical-state-root-bytes".as_slice();
    let state_id = ObjectId::for_bytes(ObjectKind::StateRoot, state);

    assert!(!store.has(blob_id).expect("查询存在性"));
    assert_eq!(store.get(blob_id).expect("读取缺失对象"), None);

    store.put(blob_id, blob).expect("写入 Blob");
    store.put(state_id, state).expect("写入 State Root");

    assert!(store.has(blob_id).expect("查询存在性"));
    assert_eq!(store.get(blob_id).expect("读取"), Some(blob.to_vec()));
    assert_eq!(store.get(state_id).expect("读取"), Some(state.to_vec()));

    // 内容寻址：重复写入相同内容是幂等的。
    store.put(blob_id, blob).expect("重复写入");
    let listed = store.list().expect("列出对象");
    assert_eq!(listed.len(), 2);
    assert!(listed.contains(&blob_id));
    assert!(listed.contains(&state_id));

    // 重开草稿库后内容仍在。
    drop(store);
    let reopened = DraftStore::open(dir.path()).expect("重新打开草稿库");
    assert_eq!(reopened.get(blob_id).expect("读取"), Some(blob.to_vec()));
}

#[test]
fn put_rejects_bytes_that_do_not_match_the_object_id() {
    let dir = TempDir::new().expect("临时目录");
    let store = DraftStore::open(dir.path()).expect("打开草稿库");

    let claimed = ObjectId::for_bytes(ObjectKind::Blob, b"the real content");
    match store.put(claimed, b"something else entirely") {
        Err(DraftError::DigestMismatch { object }) => {
            assert_eq!(object, claimed.to_string());
        }
        other => panic!("期望 DigestMismatch，实际：{other:?}"),
    }
    assert!(
        !store.has(claimed).expect("查询存在性"),
        "被拒绝的内容不得落库"
    );

    // 种类也参与域分隔：同样的字节换个种类标识也不通过。
    let wrong_kind = ObjectId {
        kind: ObjectKind::Snapshot,
        digest: ObjectId::for_bytes(ObjectKind::Blob, b"payload").digest,
    };
    assert!(matches!(
        store.put(wrong_kind, b"payload"),
        Err(DraftError::DigestMismatch { .. })
    ));
}

#[test]
fn get_reports_corruption_instead_of_returning_tampered_bytes() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join(DATABASE_FILE_NAME);
    let store = DraftStore::open(dir.path()).expect("打开草稿库");

    let original = b"# managed by envsync\n".as_slice();
    let id = ObjectId::for_bytes(ObjectKind::Blob, original);
    store.put(id, original).expect("写入");
    drop(store);

    // 绕过草稿库直接改坏存储，模拟外部工具误写或磁盘位翻转。
    let raw = rusqlite::Connection::open(&path).expect("直接打开数据库");
    raw.execute(
        "UPDATE objects SET bytes = ?1 WHERE object_id = ?2",
        rusqlite::params![b"tampered".as_slice(), id.to_string()],
    )
    .expect("篡改内容");
    drop(raw);

    let store = DraftStore::open(dir.path()).expect("重新打开草稿库");
    // has 只看是否存在，因此仍返回 true；真正的防线在 get 上。
    assert!(store.has(id).expect("查询存在性"));
    match store.get(id) {
        Err(DraftError::Corruption { object }) => assert_eq!(object, id.to_string()),
        other => panic!("期望 Corruption，实际：{other:?}"),
    }
}

#[test]
fn plans_and_head_draft_round_trip() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join(DATABASE_FILE_NAME);
    let store = DraftStore::open(dir.path()).expect("打开草稿库");

    let plan = sample_plan("shell/zsh/main");
    let plan_id = store.put_plan(&plan).expect("保存计划");
    assert_eq!(plan_id, plan.id());

    let other = sample_plan("git/config");
    store.put_plan(&other).expect("保存第二个计划");

    // 计划标识不存在时返回 None，而不是报错。
    assert!(store
        .get_plan(envsync_domain::PlanId::of(b"nope"))
        .expect("查询缺失计划")
        .is_none());

    assert_eq!(store.head_draft().expect("读取草稿头"), None);
    let head = SnapshotId::of(b"draft-head");
    store.set_head_draft(head).expect("设置草稿头");

    drop(store);
    let store = DraftStore::open(dir.path()).expect("重新打开草稿库");

    let restored = store
        .get_plan(plan_id)
        .expect("读取计划")
        .expect("计划存在");
    assert_eq!(restored, plan);
    assert_eq!(restored.id(), plan_id);
    assert_eq!(store.list_plans().expect("列出计划").len(), 2);
    assert_eq!(store.head_draft().expect("读取草稿头"), Some(head));

    // 草稿头可覆盖，也可清除。
    let next = SnapshotId::of(b"draft-head-2");
    store.set_head_draft(next).expect("覆盖草稿头");
    assert_eq!(store.head_draft().expect("读取草稿头"), Some(next));
    store.clear_head_draft().expect("清除草稿头");
    assert_eq!(store.head_draft().expect("读取草稿头"), None);

    // 计划字节被改坏时同样返回 Corruption，而不是把脏计划交出去。
    drop(store);
    let raw = rusqlite::Connection::open(&path).expect("直接打开数据库");
    raw.execute(
        "UPDATE plans SET bytes = ?1 WHERE plan_id = ?2",
        rusqlite::params![other.to_canonical_vec(), plan_id.to_string()],
    )
    .expect("篡改计划");
    drop(raw);
    let store = DraftStore::open(dir.path()).expect("重新打开草稿库");
    assert!(matches!(
        store.get_plan(plan_id),
        Err(DraftError::Corruption { .. })
    ));
}

#[test]
fn draft_tables_and_journal_tables_coexist_in_one_database() {
    let dir = TempDir::new().expect("临时目录");
    let store = DraftStore::open(dir.path()).expect("打开草稿库");

    let blob = b"shared database".as_slice();
    let blob_id = ObjectId::for_bytes(ObjectKind::Blob, blob);
    store.put(blob_id, blob).expect("写入草稿对象");
    let plan = sample_plan("shell/zsh/main");
    let plan_id = store.put_plan(&plan).expect("保存计划");
    store
        .set_head_draft(SnapshotId::of(b"head"))
        .expect("设置草稿头");

    // journal 直接使用同一个数据库文件：schema 相同，迁移幂等。
    let mut journal = Journal::open(store.database_path()).expect("在同一库上打开 journal");
    let record = journal.begin(&plan).expect("登记操作");
    journal
        .transition(record.operation, OperationState::Preflighted)
        .expect("迁移状态");

    // 双方各自的数据都完好。
    assert_eq!(journal.list_unfinished().expect("查询未完成").len(), 1);
    assert_eq!(
        journal.actions(record.operation).expect("查询动作").len(),
        1
    );
    assert_eq!(store.get(blob_id).expect("读取对象"), Some(blob.to_vec()));
    assert_eq!(
        store.get_plan(plan_id).expect("读取计划"),
        Some(plan.clone())
    );
    assert_eq!(
        store.head_draft().expect("读取草稿头"),
        Some(SnapshotId::of(b"head"))
    );

    // journal 侧删除操作不会波及草稿表。
    assert!(journal.prune_operation(record.operation).expect("删除操作"));
    assert_eq!(store.list().expect("列出对象").len(), 1);
    assert_eq!(store.list_plans().expect("列出计划").len(), 1);

    // 两个连接的诊断一致。
    assert_eq!(
        store.diagnostics().expect("草稿库诊断").schema_version,
        journal.diagnostics().expect("journal 诊断").schema_version
    );
}
