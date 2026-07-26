//! M2 存储层：迁移到当前 schema、成员索引、检查点审计副本与轮换 journal。
//!
//! 关注三件事：
//!
//! 1. **升级不能损坏 M0/M1 数据。** 用真正的 0001 + 0002 脚本手工搭出一个 schema 2 的
//!    库、写入 journal / 草稿 / 冲突数据，再让当前版本去打开它。断言用
//!    `SCHEMA_VERSION` 而不是写死的数字：后续里程碑还会继续加迁移脚本，而这条测试
//!    关心的性质不随版本号改变。
//! 2. **成员索引只接受链头的合法延伸。** 断层、断链、重复登记各有明确行为。
//! 3. **检查点审计副本是纯存取。** 它自己不做单调性判定——判定在
//!    `envsync_core::checkpoint::check_advance`，这里只验证读写往返与删除。
//!
//! 本 crate 不依赖 `envsync-core`，因此这里的成员事件是手工拼出来的（签名字段填任意
//! 64 字节）：存储层本来就不验签，验签属于 core。

use std::path::Path;

use envsync_domain::cbor::CborCodec;
use envsync_domain::id::{BlobId, Digest32, PlanId, SnapshotId, WorkspaceId};
use envsync_domain::membership::{
    DevicePublicBytes, MemberRole, MembershipAction, MembershipEvent, GENESIS_EPOCH,
    MEMBERSHIP_EVENT_FORMAT_VERSION, SIGNATURE_LEN,
};
use envsync_domain::object::{ObjectId, ObjectKind};
use envsync_storage::checkpoints::{CheckpointAudit, CheckpointRecord};
use envsync_storage::conflicts::ConflictStore;
use envsync_storage::journal::{Journal, OperationState};
use envsync_storage::membership::{MembershipIndex, MembershipStoreError};
use envsync_storage::{DraftStore, SCHEMA_VERSION};
use rusqlite::Connection;
use tempfile::TempDir;

/// M0 与 M1 的迁移脚本；测试直接内嵌，保证「旧库」与当年真正产生的库完全一致。
const MIGRATION_0001: &str = include_str!("../migrations/0001_journal.sql");
const MIGRATION_0002: &str = include_str!("../migrations/0002_profiles_conflicts.sql");

fn workspace() -> WorkspaceId {
    "0d9b6d0e-2f45-4a10-9a1e-2b3c4d5e6f70"
        .parse()
        .expect("固定 UUID 合法")
}

fn operation() -> String {
    "6f1d2f2c-6d8d-4a2f-9a3e-7c1b0d5e4a91".to_owned()
}

/// 构造一份确定性的「公开材料」。存储层不做密码学，因此不需要真实曲线点。
fn public(seed: u8) -> DevicePublicBytes {
    DevicePublicBytes::from_parts([seed; 32], [seed.wrapping_add(0x40); 32])
}

/// genesis 事件。
fn genesis_event() -> MembershipEvent {
    let admin = public(1);
    MembershipEvent {
        format_version: MEMBERSHIP_EVENT_FORMAT_VERSION,
        workspace: workspace(),
        sequence: 0,
        previous: None,
        epoch: GENESIS_EPOCH,
        actor: admin.device_id(),
        action: MembershipAction::Genesis {
            subject: admin.device_id(),
            public: admin,
        },
        created_at_unix_ms: 1_700_000_000_000,
        signature: vec![1u8; SIGNATURE_LEN],
    }
}

/// 在 `previous` 之后追加一条「添加成员」事件。
fn add_member_event(previous: &MembershipEvent, seed: u8) -> MembershipEvent {
    let device = public(seed);
    MembershipEvent {
        format_version: MEMBERSHIP_EVENT_FORMAT_VERSION,
        workspace: previous.workspace,
        sequence: previous.sequence + 1,
        previous: Some(previous.digest()),
        epoch: previous.epoch,
        actor: public(1).device_id(),
        action: MembershipAction::AddMember {
            subject: device.device_id(),
            public: device,
            role: MemberRole::Member,
        },
        created_at_unix_ms: previous.created_at_unix_ms + 10,
        signature: vec![seed; SIGNATURE_LEN],
    }
}

/// 在 `previous` 之后追加一条撤销事件（纪元 +1）。
fn revoke_event(previous: &MembershipEvent, seed: u8) -> MembershipEvent {
    MembershipEvent {
        format_version: MEMBERSHIP_EVENT_FORMAT_VERSION,
        workspace: previous.workspace,
        sequence: previous.sequence + 1,
        previous: Some(previous.digest()),
        epoch: previous.epoch + 1,
        actor: public(1).device_id(),
        action: MembershipAction::Revoke {
            subject: public(seed).device_id(),
        },
        created_at_unix_ms: previous.created_at_unix_ms + 10,
        signature: vec![seed; SIGNATURE_LEN],
    }
}

/// 手工搭出一个 schema 版本为 2 的 M1 数据库，并写入 M0/M1 各一份数据。
fn build_m1_database(path: &Path) {
    let connection = Connection::open(path).expect("创建 M1 数据库");
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_meta (
                 key   TEXT NOT NULL PRIMARY KEY,
                 value TEXT NOT NULL
             ) STRICT;",
        )
        .expect("建 schema_meta");
    connection.execute_batch(MIGRATION_0001).expect("执行 0001");
    connection.execute_batch(MIGRATION_0002).expect("执行 0002");
    connection
        .execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', '2')",
            [],
        )
        .expect("写入版本 2");

    connection
        .execute(
            "INSERT INTO operations (operation_id, plan_id, snapshot_id, workspace_id, revision, \
             state, created_at_unix_ms, updated_at_unix_ms, error_code, error_message) \
             VALUES (?1, ?2, ?3, ?4, 7, 'applying', 1700000000000, 1700000000001, NULL, NULL)",
            rusqlite::params![
                operation(),
                PlanId::of(b"m1-plan").to_hex(),
                SnapshotId::of(b"m1-snapshot").to_hex(),
                workspace().to_string(),
            ],
        )
        .expect("写入 operation");
    connection
        .execute(
            "INSERT INTO objects (object_id, bytes) VALUES (?1, ?2)",
            rusqlite::params![
                ObjectId::from(BlobId::of(b"m1-blob")).to_string(),
                b"m1-blob".to_vec()
            ],
        )
        .expect("写入草稿对象");
    connection
        .execute(
            "INSERT INTO conflicts (conflict_id, workspace_id, resource_id, kind, base_blob, \
             ours_blob, theirs_blob, state, resolution_choice, resolved_blob, \
             created_at_unix_ms, resolved_at_unix_ms) \
             VALUES (?1, ?2, 'git/config', 'text_overlap', NULL, NULL, NULL, 'open', NULL, \
             NULL, 1700000000002, NULL)",
            rusqlite::params![
                Digest32::domain_hash("test:conflict", b"m1").to_hex(),
                workspace().to_string(),
            ],
        )
        .expect("写入冲突");
    connection
        .execute(
            "INSERT INTO profiles (device_id, os, arch, hostname, tags, capabilities, \
             updated_at_unix_ms) VALUES ('abc', 'linux', 'x86_64', 'dev-01', '[]', '[]', \
             1700000000003)",
            [],
        )
        .expect("写入 profile");
}

fn raw_schema_version(path: &Path) -> String {
    let connection = Connection::open(path).expect("打开数据库");
    connection
        .query_row(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .expect("读取版本号")
}

fn table_exists(path: &Path, table: &str) -> bool {
    let connection = Connection::open(path).expect("打开数据库");
    connection
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get::<_, String>(0),
        )
        .is_ok()
}

// ---------------------------------------------------------------------------
// 迁移
// ---------------------------------------------------------------------------

#[test]
fn m1_database_upgrades_to_the_current_schema_without_losing_data() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");
    build_m1_database(&path);
    assert_eq!(raw_schema_version(&path), "2");

    let journal = Journal::open(&path).expect("升级并打开");
    // 断言的是「升级到本实现支持的版本」，而不是某个写死的数字：M3 之后
    // `SCHEMA_VERSION` 会继续前进，而这条测试关心的性质（M0/M1 数据不丢）不随之改变。
    assert_eq!(journal.schema_version().expect("版本"), SCHEMA_VERSION);
    assert!(journal.diagnostics().expect("诊断").is_durable());

    // M0 数据完好。
    let record = journal
        .operation(operation().parse().expect("UUID"))
        .expect("查询")
        .expect("仍存在");
    assert_eq!(record.state, OperationState::Applying);
    assert_eq!(record.revision, 7);
    let drafts = DraftStore::open_database(&path).expect("打开草稿库");
    assert_eq!(
        drafts
            .get(ObjectId::from(BlobId::of(b"m1-blob")))
            .expect("读取"),
        Some(b"m1-blob".to_vec())
    );

    // M1 数据完好。
    let conflicts = ConflictStore::open(&path).expect("打开冲突索引");
    assert_eq!(conflicts.list_open(workspace()).expect("列出").len(), 1);

    // M2 新表就位且为空。
    assert!(table_exists(&path, "membership_events"));
    assert!(table_exists(&path, "membership_head"));
    assert!(table_exists(&path, "checkpoints"));
    assert!(table_exists(&path, "rotations"));
    let index = MembershipIndex::open(&path).expect("打开成员索引");
    assert_eq!(index.head(workspace()).expect("链头"), None);
    let audit = CheckpointAudit::open(&path).expect("打开检查点");
    assert_eq!(audit.list().expect("列出"), vec![]);
}

#[test]
fn a_brand_new_database_starts_at_the_current_schema_and_reopening_is_idempotent() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");
    for _ in 0..3 {
        let index = MembershipIndex::open(&path).expect("打开");
        assert_eq!(
            index.diagnostics().expect("诊断").schema_version,
            SCHEMA_VERSION
        );
    }
    assert_eq!(raw_schema_version(&path), SCHEMA_VERSION.to_string());
}

#[test]
fn a_failed_v3_migration_rolls_back_completely() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");
    build_m1_database(&path);

    // 外部工具留下一张同名但结构不同的表：`CREATE TABLE IF NOT EXISTS` 会被静默跳过。
    {
        let connection = Connection::open(&path).expect("打开数据库");
        connection
            .execute(
                "CREATE TABLE membership_head (unrelated TEXT NOT NULL) STRICT",
                [],
            )
            .expect("插入冲突表");
    }

    assert!(Journal::open(&path).is_err(), "迁移后校验必须失败");
    // 版本号没有前进，同一事务里建出来的其他新表被整体回滚。
    assert_eq!(raw_schema_version(&path), "2");
    assert!(!table_exists(&path, "membership_events"));
    assert!(!table_exists(&path, "checkpoints"));
    // 旧数据完好。
    let connection = Connection::open(&path).expect("打开数据库");
    let operations: i64 = connection
        .query_row("SELECT count(*) FROM operations", [], |row| row.get(0))
        .expect("统计");
    assert_eq!(operations, 1);

    // 清掉占位表后可以正常升级——失败是干净的、可重试的。
    connection
        .execute("DROP TABLE membership_head", [])
        .expect("清理");
    drop(connection);
    let journal = Journal::open(&path).expect("重试升级");
    assert_eq!(journal.schema_version().expect("版本"), SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// 成员索引
// ---------------------------------------------------------------------------

#[test]
fn membership_index_round_trips_events_and_head() {
    let dir = TempDir::new().expect("临时目录");
    let index = MembershipIndex::open(dir.path().join("journal.db")).expect("打开成员索引");
    let workspace = workspace();

    let genesis = genesis_event();
    let add = add_member_event(&genesis, 2);
    let revoke = revoke_event(&add, 2);

    let digest = index
        .append_verified_at(workspace, &genesis, 100)
        .expect("登记 genesis");
    assert_eq!(digest, genesis.digest());
    index
        .append_verified_at(workspace, &add, 110)
        .expect("登记 add");
    index
        .append_verified_at(workspace, &revoke, 120)
        .expect("登记 revoke");

    let head = index.head(workspace).expect("链头").expect("存在");
    assert_eq!(head.workspace, workspace);
    assert_eq!(head.digest, revoke.digest());
    assert_eq!(head.sequence, 2);
    assert_eq!(head.epoch, GENESIS_EPOCH + 1);
    assert_eq!(head.verified_at_unix_ms, 120);

    let events = index.events(workspace).expect("列出事件");
    assert_eq!(events.len(), 3);
    assert_eq!(
        events.iter().map(|e| e.sequence).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert_eq!(
        events
            .iter()
            .map(|e| e.action_kind.as_str())
            .collect::<Vec<_>>(),
        vec!["genesis", "add_member", "revoke"]
    );
    assert_eq!(events[1].subject, public(2).device_id());
    assert_eq!(events[1].actor, public(1).device_id());
    assert_eq!(
        events[1].object,
        ObjectId::for_bytes(ObjectKind::MembershipEvent, &add.to_canonical_vec())
    );
    assert_eq!(events[2].epoch, GENESIS_EPOCH + 1);

    // 另一个工作区互不干扰。
    let other = WorkspaceId::generate();
    assert_eq!(index.head(other).expect("链头"), None);
    assert!(index.events(other).expect("列出").is_empty());

    // 重开数据库后状态仍在。
    drop(index);
    let reopened = MembershipIndex::open(dir.path().join("journal.db")).expect("重开");
    assert_eq!(
        reopened
            .head(workspace)
            .expect("链头")
            .expect("存在")
            .digest,
        revoke.digest()
    );
}

#[test]
fn appending_the_same_event_twice_is_idempotent() {
    let dir = TempDir::new().expect("临时目录");
    let index = MembershipIndex::open(dir.path().join("journal.db")).expect("打开");
    let workspace = workspace();
    let genesis = genesis_event();

    index
        .append_verified_at(workspace, &genesis, 100)
        .expect("首次登记");
    index
        .append_verified_at(workspace, &genesis, 999)
        .expect("重复登记应当幂等");

    assert_eq!(index.events(workspace).expect("列出").len(), 1);
    // 幂等路径不改动任何行，包括验证时间。
    assert_eq!(
        index
            .head(workspace)
            .expect("链头")
            .expect("存在")
            .verified_at_unix_ms,
        100
    );
}

#[test]
fn only_a_successor_of_the_current_head_can_be_appended() {
    let dir = TempDir::new().expect("临时目录");
    let index = MembershipIndex::open(dir.path().join("journal.db")).expect("打开");
    let workspace = workspace();
    let genesis = genesis_event();
    let add = add_member_event(&genesis, 2);
    let far = add_member_event(&add, 3);

    // 空库只接受 sequence 0。
    assert!(matches!(
        index.append_verified_at(workspace, &add, 100),
        Err(MembershipStoreError::NotSuccessor { found: 1, .. })
    ));

    index
        .append_verified_at(workspace, &genesis, 100)
        .expect("登记 genesis");

    // 跳号被拒绝。
    assert!(matches!(
        index.append_verified_at(workspace, &far, 110),
        Err(MembershipStoreError::NotSuccessor { found: 2, .. })
    ));

    // sequence 正确但 previous 指错：断链。
    let mut broken = add.clone();
    broken.previous = Some(Digest32::domain_hash("attacker", b"not the genesis"));
    assert!(matches!(
        index.append_verified_at(workspace, &broken, 110),
        Err(MembershipStoreError::ChainBroken { sequence: 1 })
    ));

    // 被拒绝的登记不留痕迹。
    assert_eq!(index.events(workspace).expect("列出").len(), 1);
    assert_eq!(
        index.head(workspace).expect("链头").expect("存在").sequence,
        0
    );

    // 合法后继照常接受。
    index
        .append_verified_at(workspace, &add, 110)
        .expect("登记合法后继");
    assert_eq!(
        index.head(workspace).expect("链头").expect("存在").sequence,
        1
    );
}

#[test]
fn a_malformed_event_is_rejected_before_touching_the_database() {
    let dir = TempDir::new().expect("临时目录");
    let index = MembershipIndex::open(dir.path().join("journal.db")).expect("打开");
    let mut genesis = genesis_event();
    genesis.signature = vec![0u8; 8];

    assert!(matches!(
        index.append_verified_at(workspace(), &genesis, 100),
        Err(MembershipStoreError::MalformedEvent(_))
    ));
    assert_eq!(index.head(workspace()).expect("链头"), None);
}

#[test]
fn reset_trust_root_clears_only_the_given_workspace() {
    let dir = TempDir::new().expect("临时目录");
    let index = MembershipIndex::open(dir.path().join("journal.db")).expect("打开");
    let mine = workspace();
    let theirs = WorkspaceId::generate();

    let genesis = genesis_event();
    index
        .append_verified_at(mine, &genesis, 100)
        .expect("登记本工作区");
    index
        .append_verified_at(theirs, &genesis, 100)
        .expect("登记另一个工作区");

    index.reset_trust_root(mine).expect("重置信任根");
    assert_eq!(index.head(mine).expect("链头"), None);
    assert!(index.events(mine).expect("列出").is_empty());
    // 另一个工作区不受影响。
    assert!(index.head(theirs).expect("链头").is_some());

    // 重置之后可以从任意 genesis 重新开始——这正是它危险的地方。
    index
        .append_verified_at(mine, &genesis, 200)
        .expect("重新建立信任根");
    assert_eq!(
        index
            .head(mine)
            .expect("链头")
            .expect("存在")
            .verified_at_unix_ms,
        200
    );
}

// ---------------------------------------------------------------------------
// 检查点审计副本
// ---------------------------------------------------------------------------

fn record(workspace: WorkspaceId, revision: u64) -> CheckpointRecord {
    CheckpointRecord {
        workspace,
        revision,
        snapshot: SnapshotId::of(format!("head-{revision}").as_bytes()),
        membership_digest: Digest32::domain_hash("test:membership", b"head"),
        membership_sequence: 3,
        key_epoch: 2,
        updated_at_unix_ms: 1_700_000_000_000 + revision,
    }
}

#[test]
fn checkpoint_audit_round_trips_and_overwrites() {
    let dir = TempDir::new().expect("临时目录");
    let audit = CheckpointAudit::open(dir.path().join("journal.db")).expect("打开");
    let workspace = workspace();
    let other = WorkspaceId::generate();

    assert_eq!(audit.get(workspace).expect("读取"), None);

    let first = record(workspace, 12);
    audit.upsert(&first).expect("写入");
    assert_eq!(audit.get(workspace).expect("读取"), Some(first));

    // 审计副本自己不做单调性判定：判定在 core，这里是纯覆盖写。
    let next = record(workspace, 13);
    audit.upsert(&next).expect("覆盖写");
    assert_eq!(audit.get(workspace).expect("读取"), Some(next));

    audit.upsert(&record(other, 4)).expect("另一个工作区");
    assert_eq!(audit.list().expect("列出").len(), 2);

    // 重开数据库后仍在。
    drop(audit);
    let reopened = CheckpointAudit::open(dir.path().join("journal.db")).expect("重开");
    assert_eq!(reopened.get(workspace).expect("读取"), Some(next));

    reopened.delete(workspace).expect("删除");
    assert_eq!(reopened.get(workspace).expect("读取"), None);
    assert_eq!(reopened.list().expect("列出").len(), 1);
}

#[test]
fn all_m2_stores_can_share_one_database_file() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");
    let workspace = workspace();

    let journal = Journal::open(&path).expect("journal");
    let conflicts = ConflictStore::open(&path).expect("冲突索引");
    let index = MembershipIndex::open(&path).expect("成员索引");
    let audit = CheckpointAudit::open(&path).expect("检查点");

    index
        .append_verified_at(workspace, &genesis_event(), 100)
        .expect("登记 genesis");
    audit.upsert(&record(workspace, 1)).expect("写入检查点");

    assert_eq!(journal.schema_version().expect("版本"), SCHEMA_VERSION);
    assert!(conflicts.list_open(workspace).expect("列出").is_empty());
    assert!(index.head(workspace).expect("链头").is_some());
    assert!(audit.get(workspace).expect("读取").is_some());
}
