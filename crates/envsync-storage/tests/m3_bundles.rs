//! M3 存储层：迁移到 v6 与 Agent Bundle 记录的往返。
//!
//! 关注三件事：
//!
//! 1. **升级不能损坏 M0–M2 数据。** 用真正的 0001–0005 脚本手工搭出一个 schema 5 的
//!    库、写入 journal / 草稿 / 冲突 / 成员 / 检查点 / 轮换数据，再让当前版本去打开它。
//! 2. **`bundles` 与 `bundle_files` 是纯存取。** 状态机判定在
//!    `envsync_core::bundles`，这里只验证读写往返、按状态与按发布者查询、级联删除。
//! 3. **文件清单是全量替换语义。** 升级后旧版本里存在、新版本里已删除的路径不能残留。

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use envsync_domain::agent_bundle::{BundleId, BundleState};
use envsync_domain::id::{BlobId, DeviceId, Digest32, PlanId, SnapshotId, WorkspaceId};
use envsync_domain::object::ObjectId;
use envsync_storage::bundles::{BundleRecord, BundleStore};
use envsync_storage::checkpoints::CheckpointAudit;
use envsync_storage::journal::Journal;
use envsync_storage::rotation::RotationJournal;
use envsync_storage::{DraftStore, SCHEMA_VERSION};
use rusqlite::Connection;
use tempfile::TempDir;

/// M0–M2 的迁移脚本；测试直接内嵌，保证「旧库」与当年真正产生的库完全一致。
const MIGRATION_0001: &str = include_str!("../migrations/0001_journal.sql");
const MIGRATION_0002: &str = include_str!("../migrations/0002_profiles_conflicts.sql");
const MIGRATION_0003: &str = include_str!("../migrations/0003_membership.sql");
const MIGRATION_0004: &str = include_str!("../migrations/0004_checkpoints.sql");
const MIGRATION_0005: &str = include_str!("../migrations/0005_rotation.sql");

fn workspace() -> WorkspaceId {
    "0d9b6d0e-2f45-4a10-9a1e-2b3c4d5e6f70"
        .parse()
        .expect("固定 UUID 合法")
}

fn bundle_id(text: &str) -> BundleId {
    BundleId::parse(text).expect("固定 Bundle 标识合法")
}

fn digest(label: &str) -> Digest32 {
    Digest32::domain_hash("test:m3-bundles", label.as_bytes())
}

/// 手工搭出一个 schema 版本为 5 的 M2 数据库，并写入各里程碑各一份数据。
fn build_m2_database(path: &Path) {
    let connection = Connection::open(path).expect("创建 M2 数据库");
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_meta (
                 key   TEXT NOT NULL PRIMARY KEY,
                 value TEXT NOT NULL
             ) STRICT;",
        )
        .expect("建 schema_meta");
    for script in [
        MIGRATION_0001,
        MIGRATION_0002,
        MIGRATION_0003,
        MIGRATION_0004,
        MIGRATION_0005,
    ] {
        connection.execute_batch(script).expect("执行迁移脚本");
    }
    connection
        .execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', '5')",
            [],
        )
        .expect("写入版本 5");

    connection
        .execute(
            "INSERT INTO operations (operation_id, plan_id, snapshot_id, workspace_id, revision, \
             state, created_at_unix_ms, updated_at_unix_ms, error_code, error_message) \
             VALUES (?1, ?2, ?3, ?4, 9, 'applying', 1700000000000, 1700000000001, NULL, NULL)",
            rusqlite::params![
                "6f1d2f2c-6d8d-4a2f-9a3e-7c1b0d5e4a91",
                PlanId::of(b"m2-plan").to_hex(),
                SnapshotId::of(b"m2-snapshot").to_hex(),
                workspace().to_string(),
            ],
        )
        .expect("写入 operation");
    connection
        .execute(
            "INSERT INTO objects (object_id, bytes) VALUES (?1, ?2)",
            rusqlite::params![
                ObjectId::from(BlobId::of(b"m2-blob")).to_string(),
                b"m2-blob".to_vec()
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
            rusqlite::params![digest("conflict").to_hex(), workspace().to_string()],
        )
        .expect("写入冲突");
    connection
        .execute(
            "INSERT INTO checkpoints (workspace_id, revision, snapshot_id, membership_digest, \
             membership_sequence, key_epoch, updated_at_unix_ms) \
             VALUES (?1, 9, ?2, ?3, 3, 1, 1700000000003)",
            rusqlite::params![
                workspace().to_string(),
                SnapshotId::of(b"m2-snapshot").to_hex(),
                digest("membership").to_hex(),
            ],
        )
        .expect("写入检查点");
    connection
        .execute(
            "INSERT INTO rotations (workspace_id, from_epoch, to_epoch, revoked_device, stage, \
             recipients, envelopes, pending_rewrap, event_created_at_unix_ms, \
             started_at_unix_ms, updated_at_unix_ms) \
             VALUES (?1, 1, 2, ?2, 'prepared', '[]', '[]', '[]', 1700000000004, \
             1700000000004, 1700000000004)",
            rusqlite::params![
                workspace().to_string(),
                DeviceId::derive(b"revoked-device").to_hex(),
            ],
        )
        .expect("写入轮换记录");
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

fn count(path: &Path, table: &str) -> i64 {
    let connection = Connection::open(path).expect("打开数据库");
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .expect("计数")
}

// ---------------------------------------------------------------------------
// 迁移
// ---------------------------------------------------------------------------

#[test]
fn m2_database_upgrades_to_v6_without_losing_data() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");
    build_m2_database(&path);
    assert_eq!(raw_schema_version(&path), "5");

    // 打开一次即完成迁移。
    let journal = Journal::open(&path).expect("打开并迁移");
    assert_eq!(journal.schema_version().expect("版本"), SCHEMA_VERSION);
    assert_eq!(SCHEMA_VERSION, 6);
    drop(journal);

    // M0–M2 的每一张表都还在，而且行数没变。
    for table in [
        "operations",
        "objects",
        "conflicts",
        "checkpoints",
        "rotations",
    ] {
        assert_eq!(count(&path, table), 1, "表 {table} 的数据丢失了");
    }
    // 新表已建好且为空。
    assert_eq!(count(&path, "bundles"), 0);
    assert_eq!(count(&path, "bundle_files"), 0);

    // 各个 store 都能在升级后的库上正常工作。
    let drafts = DraftStore::open_database(&path).expect("打开草稿库");
    assert_eq!(
        drafts
            .get(ObjectId::from(BlobId::of(b"m2-blob")))
            .expect("读取草稿对象"),
        Some(b"m2-blob".to_vec())
    );
    let rotations = RotationJournal::open(&path).expect("打开轮换 journal");
    assert!(rotations.get(workspace()).expect("读取").is_some());
    let audit = CheckpointAudit::open(&path).expect("打开检查点审计副本");
    assert!(audit.get(workspace()).expect("读取").is_some());
}

#[test]
fn repeated_open_is_idempotent_at_v6() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");
    for _ in 0..3 {
        let store = BundleStore::open(&path).expect("打开");
        assert_eq!(
            store.diagnostics().expect("诊断").schema_version,
            SCHEMA_VERSION
        );
    }
    assert_eq!(raw_schema_version(&path), SCHEMA_VERSION.to_string());
}

// ---------------------------------------------------------------------------
// 往返
// ---------------------------------------------------------------------------

fn sample_record(state: BundleState) -> BundleRecord {
    BundleRecord {
        bundle: bundle_id("com.example.my-agent"),
        version: "1.2.3".to_owned(),
        manifest_digest: digest("manifest"),
        publisher_key: [7u8; 32],
        state,
        approved_capabilities: BTreeSet::from(["agents".to_owned(), "skills".to_owned()]),
        approved_at_unix_ms: Some(1_700_000_100_000),
        blocked_reason: None,
        updated_at_unix_ms: 1_700_000_100_000,
    }
}

fn sample_files() -> BTreeMap<String, Digest32> {
    BTreeMap::from([
        ("agents/main.md".to_owned(), digest("agents/main.md")),
        ("skills/pdf/SKILL.md".to_owned(), digest("skills/pdf")),
    ])
}

#[test]
fn bundle_record_round_trips_with_its_file_list() {
    let dir = TempDir::new().expect("临时目录");
    let mut store = BundleStore::open(dir.path().join("journal.db")).expect("打开");

    let record = sample_record(BundleState::Approved);
    let files = sample_files();
    store.upsert(&record, &files).expect("写入");

    let loaded = store.get(&record.bundle).expect("读取").expect("存在");
    assert_eq!(loaded, record);
    assert_eq!(store.files(&record.bundle).expect("读取清单"), files);
}

#[test]
fn upserting_replaces_the_whole_file_list() {
    let dir = TempDir::new().expect("临时目录");
    let mut store = BundleStore::open(dir.path().join("journal.db")).expect("打开");

    let record = sample_record(BundleState::Inspected);
    store.upsert(&record, &sample_files()).expect("写入 v1");

    // v2 删掉了 skill，只剩一个文件：清单必须整份被替换，而不是叠加。
    let next_files = BTreeMap::from([("agents/main.md".to_owned(), digest("agents/main.md.v2"))]);
    let next = BundleRecord {
        version: "2.0.0".to_owned(),
        manifest_digest: digest("manifest.v2"),
        ..record.clone()
    };
    store.upsert(&next, &next_files).expect("写入 v2");

    assert_eq!(store.files(&record.bundle).expect("读取清单"), next_files);
    let loaded = store.get(&record.bundle).expect("读取").expect("存在");
    assert_eq!(loaded.version, "2.0.0");
    assert_eq!(loaded.manifest_digest, digest("manifest.v2"));
}

#[test]
fn records_can_be_listed_by_state_and_by_publisher() {
    let dir = TempDir::new().expect("临时目录");
    let mut store = BundleStore::open(dir.path().join("journal.db")).expect("打开");

    let enabled = BundleRecord {
        bundle: bundle_id("com.example.alpha"),
        state: BundleState::Enabled,
        ..sample_record(BundleState::Enabled)
    };
    let blocked = BundleRecord {
        bundle: bundle_id("com.example.beta"),
        publisher_key: [9u8; 32],
        state: BundleState::Blocked,
        approved_capabilities: BTreeSet::new(),
        approved_at_unix_ms: None,
        blocked_reason: Some("发布者公钥已被撤销".to_owned()),
        ..sample_record(BundleState::Blocked)
    };
    store.upsert(&enabled, &sample_files()).expect("写入 alpha");
    store.upsert(&blocked, &BTreeMap::new()).expect("写入 beta");

    let by_state = store
        .list_by_state(BundleState::Enabled)
        .expect("按状态查询");
    assert_eq!(by_state.len(), 1);
    assert_eq!(by_state[0].bundle, enabled.bundle);

    let by_publisher = store.list_by_publisher(&[9u8; 32]).expect("按发布者查询");
    assert_eq!(by_publisher.len(), 1);
    assert_eq!(by_publisher[0].bundle, blocked.bundle);
    assert_eq!(
        by_publisher[0].blocked_reason.as_deref(),
        Some("发布者公钥已被撤销")
    );

    assert_eq!(store.list().expect("全量列出").len(), 2);
}

#[test]
fn deleting_a_bundle_cascades_to_its_file_list() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");
    let mut store = BundleStore::open(&path).expect("打开");

    let record = sample_record(BundleState::Enabled);
    store.upsert(&record, &sample_files()).expect("写入");
    assert_eq!(count(&path, "bundle_files"), 2);

    assert!(store.delete(&record.bundle).expect("删除"));
    assert!(store.get(&record.bundle).expect("读取").is_none());
    assert!(store.files(&record.bundle).expect("读取清单").is_empty());
    assert_eq!(count(&path, "bundle_files"), 0);

    // 再删一次是幂等的：返回 false，不报错。
    assert!(!store.delete(&record.bundle).expect("再次删除"));
}

#[test]
fn approved_states_require_an_approval_timestamp() {
    let dir = TempDir::new().expect("临时目录");
    let mut store = BundleStore::open(dir.path().join("journal.db")).expect("打开");

    // `approved` 却没有批准时刻：数据库层的 CHECK 必须挡住它。
    let broken = BundleRecord {
        approved_at_unix_ms: None,
        ..sample_record(BundleState::Approved)
    };
    let error = store
        .upsert(&broken, &BTreeMap::new())
        .expect_err("必须被 CHECK 拒绝");
    assert_eq!(error.code(), "bundle_store.sqlite");
}

#[test]
fn an_unknown_state_string_is_rejected_rather_than_guessed() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");
    {
        let mut store = BundleStore::open(&path).expect("打开");
        store
            .upsert(&sample_record(BundleState::Enabled), &BTreeMap::new())
            .expect("写入");
    }
    // 绕过 Rust 直接改库：CHECK 约束会先拦住它，这本身就是我们要的性质。
    let connection = Connection::open(&path).expect("打开数据库");
    let outcome = connection.execute(
        "UPDATE bundles SET state = 'half-enabled' WHERE bundle_id = ?1",
        rusqlite::params!["com.example.my-agent"],
    );
    assert!(outcome.is_err(), "CHECK 约束必须拒绝未知状态");
}
