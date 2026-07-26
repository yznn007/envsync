//! M1 存储层的迁移与冲突索引测试。
//!
//! 这里最关心两件事：
//!
//! 1. **升级不能损坏 M0 数据。** 测试用真正的 0001 脚本手工搭出一个 schema 1 的库、
//!    写入操作/动作/收据，再让当前版本去打开它。
//! 2. **迁移失败必须整体回滚。** 失败场景不是人为注入的假错误，而是一个真实存在的
//!    危险：迁移脚本用 `CREATE TABLE IF NOT EXISTS`，若外部工具留下同名但结构不同的
//!    表，建表会被静默跳过。断言此时版本号不前进、旧表原封不动、新表不残留。

use std::path::Path;

use envsync_domain::id::{
    BlobId, ConflictId, Digest32, OperationId, PlanId, ResourceId, SnapshotId, WorkspaceId,
};
use envsync_domain::object::{Conflict, ConflictKind, ObjectId, CONFLICT_FORMAT_VERSION};
use envsync_domain::profile::{ConflictResolution, ProfileError, ResolutionChoice};
use envsync_storage::conflicts::{ConflictError, ConflictState, ConflictStore};
use envsync_storage::journal::{ActionState, Journal, JournalError, OperationState};
use envsync_storage::{DraftStore, SCHEMA_VERSION};
use rusqlite::Connection;
use tempfile::TempDir;

/// M0 的迁移脚本；测试直接内嵌它，以保证「旧库」与当年真正产生的库完全一致。
const MIGRATION_0001: &str = include_str!("../migrations/0001_journal.sql");

/// 固定的测试用操作标识，方便跨连接断言。
fn operation_id() -> OperationId {
    "6f1d2f2c-6d8d-4a2f-9a3e-7c1b0d5e4a91"
        .parse()
        .expect("固定 UUID 合法")
}

/// 固定的测试用工作区标识。
fn workspace_id() -> WorkspaceId {
    "0d9b6d0e-2f45-4a10-9a1e-2b3c4d5e6f70"
        .parse()
        .expect("固定 UUID 合法")
}

/// 手工搭出一个 schema 版本为 1 的 M0 数据库，并写入一条完整的操作记录。
fn build_m0_database(path: &Path) {
    let connection = Connection::open(path).expect("创建 M0 数据库");
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_meta (
                 key   TEXT NOT NULL PRIMARY KEY,
                 value TEXT NOT NULL
             ) STRICT;",
        )
        .expect("建 schema_meta");
    connection.execute_batch(MIGRATION_0001).expect("执行 0001");
    connection
        .execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', '1')",
            [],
        )
        .expect("写入版本 1");

    let operation = operation_id().to_string();
    connection
        .execute(
            "INSERT INTO operations (operation_id, plan_id, snapshot_id, workspace_id, revision, \
             state, created_at_unix_ms, updated_at_unix_ms, error_code, error_message) \
             VALUES (?1, ?2, ?3, ?4, 7, 'applying', 1700000000000, 1700000000001, NULL, NULL)",
            rusqlite::params![
                operation,
                PlanId::of(b"m0-plan").to_hex(),
                SnapshotId::of(b"m0-snapshot").to_hex(),
                workspace_id().to_string(),
            ],
        )
        .expect("写入 operation");
    connection
        .execute(
            "INSERT INTO actions (operation_id, ordinal, resource_id, target, kind, state, \
             expected_before_digest, expected_after_digest, error_code, error_message) \
             VALUES (?1, 0, 'shell/zsh/main', ?2, 'replace_file', 'applied', ?3, ?4, NULL, NULL)",
            rusqlite::params![
                operation,
                r#"{"root":"home","segments":[".zshrc"]}"#,
                Digest32::domain_hash("test:before", b"zsh").to_hex(),
                Digest32::domain_hash("test:after", b"zsh").to_hex(),
            ],
        )
        .expect("写入 action");
    connection
        .execute(
            "INSERT INTO receipts (operation_id, ordinal, resource_id, backup_path, \
             original_digest, applied_digest, guarantee, created_at_unix_ms) \
             VALUES (?1, 0, 'shell/zsh/main', '/backup/zshrc', ?2, ?3, 'exact', 1700000000002)",
            rusqlite::params![
                operation,
                Digest32::domain_hash("test:before", b"zsh").to_hex(),
                Digest32::domain_hash("test:after", b"zsh").to_hex(),
            ],
        )
        .expect("写入 receipt");
    connection
        .execute(
            "INSERT INTO objects (object_id, bytes) VALUES (?1, ?2)",
            rusqlite::params![
                ObjectId::from(BlobId::of(b"m0-blob")).to_string(),
                b"m0-blob".to_vec()
            ],
        )
        .expect("写入草稿对象");
}

/// 读取数据库中记录的 schema 版本（绕开迁移逻辑，直接看表）。
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

/// 数据库中是否存在给定名字的表。
fn table_exists(path: &Path, table: &str) -> bool {
    let connection = Connection::open(path).expect("打开数据库");
    let found: Option<String> = connection
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )
        .ok();
    found.is_some()
}

#[test]
fn m0_database_upgrades_to_v2_without_losing_data() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");
    build_m0_database(&path);
    assert_eq!(raw_schema_version(&path), "1");

    let journal = Journal::open(&path).expect("升级并打开");
    assert_eq!(journal.schema_version().expect("版本"), 2);
    assert_eq!(SCHEMA_VERSION, 2);

    // M0 数据必须一字不差地留在原处。
    let record = journal
        .operation(operation_id())
        .expect("查询 operation")
        .expect("operation 仍存在");
    assert_eq!(record.state, OperationState::Applying);
    assert_eq!(record.revision, 7);
    assert_eq!(record.workspace, workspace_id());

    let actions = journal.actions(operation_id()).expect("查询 actions");
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].resource.as_str(), "shell/zsh/main");
    assert_eq!(actions[0].state, ActionState::Applied);
    assert_eq!(actions[0].target.root, "home");

    let receipts = journal.receipts(operation_id()).expect("查询 receipts");
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].receipt.backup_path.as_deref(),
        Some("/backup/zshrc")
    );

    // 未完成操作依然可以被恢复流程发现。
    assert_eq!(journal.list_unfinished().expect("未完成").len(), 1);

    // 草稿对象也没丢。
    let drafts = DraftStore::open_database(&path).expect("打开草稿库");
    assert_eq!(
        drafts
            .get(ObjectId::from(BlobId::of(b"m0-blob")))
            .expect("读取草稿对象"),
        Some(b"m0-blob".to_vec())
    );

    // 新表已经就位。
    assert!(table_exists(&path, "profiles"));
    assert!(table_exists(&path, "conflicts"));
}

#[test]
fn failed_migration_rolls_back_completely() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");
    build_m0_database(&path);

    // 模拟外部工具（或更早的实验版本）留下一张同名但结构不同的表：
    // 迁移脚本的 `CREATE TABLE IF NOT EXISTS profiles` 会被静默跳过。
    {
        let connection = Connection::open(&path).expect("打开数据库");
        connection
            .execute("CREATE TABLE profiles (unrelated TEXT NOT NULL) STRICT", [])
            .expect("插入冲突表");
    }

    match Journal::open(&path) {
        Err(JournalError::Corrupt(message)) => {
            assert!(
                message.contains("profiles"),
                "错误信息应指出出问题的表：{message}"
            );
        }
        other => panic!("期望迁移后校验失败，实际：{:?}", other.map(|_| "Ok")),
    }

    // 版本号没有前进。
    assert_eq!(raw_schema_version(&path), "1");
    // 同一事务里已经建出来的新表被整体回滚，没有半成品残留。
    assert!(!table_exists(&path, "conflicts"));
    // 旧数据完好无损。
    let connection = Connection::open(&path).expect("打开数据库");
    let operations: i64 = connection
        .query_row("SELECT count(*) FROM operations", [], |row| row.get(0))
        .expect("统计 operations");
    let receipts: i64 = connection
        .query_row("SELECT count(*) FROM receipts", [], |row| row.get(0))
        .expect("统计 receipts");
    assert_eq!((operations, receipts), (1, 1));

    // 把占位表清掉之后，同一个库可以正常升级——说明失败是干净的、可重试的。
    connection.execute("DROP TABLE profiles", []).expect("清理");
    drop(connection);
    let journal = Journal::open(&path).expect("重试升级");
    assert_eq!(journal.schema_version().expect("版本"), SCHEMA_VERSION);
    assert_eq!(journal.list_unfinished().expect("未完成").len(), 1);
}

#[test]
fn repeated_open_is_idempotent() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");

    for _ in 0..3 {
        let journal = Journal::open(&path).expect("打开");
        assert_eq!(journal.schema_version().expect("版本"), SCHEMA_VERSION);
        assert!(journal.diagnostics().expect("诊断").is_durable());
    }
    // 从 M0 库升级后再重复打开同样幂等。
    let upgraded = dir.path().join("upgraded.db");
    build_m0_database(&upgraded);
    for _ in 0..3 {
        let journal = Journal::open(&upgraded).expect("打开");
        assert_eq!(journal.schema_version().expect("版本"), SCHEMA_VERSION);
    }
    assert_eq!(raw_schema_version(&upgraded), SCHEMA_VERSION.to_string());
}

#[test]
fn schema_version_newer_than_supported_is_still_rejected() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");
    Journal::open(&path).expect("首次打开");

    let raw = Connection::open(&path).expect("直接打开数据库");
    raw.execute(
        "UPDATE schema_meta SET value = ?1 WHERE key = 'schema_version'",
        [(SCHEMA_VERSION + 1).to_string()],
    )
    .expect("篡改版本号");
    drop(raw);

    match Journal::open(&path) {
        Err(JournalError::SchemaTooNew { found, supported }) => {
            assert_eq!(found, SCHEMA_VERSION + 1);
            assert_eq!(supported, SCHEMA_VERSION);
        }
        other => panic!("期望 SchemaTooNew，实际：{:?}", other.map(|_| "Ok")),
    }
}

#[test]
fn profiles_table_accepts_a_device_profile_row() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");
    Journal::open(&path).expect("打开");

    let connection = Connection::open(&path).expect("直接打开数据库");
    connection
        .execute(
            "INSERT INTO profiles (device_id, os, arch, hostname, tags, capabilities, \
             updated_at_unix_ms) VALUES ('abc', 'windows', 'x86_64', 'build-01', \
             '[\"work\"]', '[\"pwsh\"]', 1700000000000)",
            [],
        )
        .expect("写入 profile");
    let tags: String = connection
        .query_row(
            "SELECT tags FROM profiles WHERE device_id = 'abc'",
            [],
            |row| row.get(0),
        )
        .expect("读回 profile");
    assert_eq!(tags, "[\"work\"]");
}

/// 构造一个测试用冲突对象。
fn sample_conflict(resource: &str) -> Conflict {
    Conflict {
        format_version: CONFLICT_FORMAT_VERSION,
        resource: ResourceId::parse(resource).expect("资源标识合法"),
        kind: ConflictKind::TextOverlap,
        base: Some(BlobId::of(b"base")),
        ours: Some(BlobId::of(b"ours")),
        theirs: Some(BlobId::of(b"theirs")),
        diagnostics: vec!["行 10-12".into()],
    }
}

#[test]
fn conflict_store_round_trips_record_get_list_and_resolve() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");
    let store = ConflictStore::open(&path).expect("打开冲突索引");
    let drafts = DraftStore::open_database(&path).expect("打开草稿库");
    let workspace = workspace_id();
    let other_workspace = WorkspaceId::generate();

    let first = sample_conflict("git/config");
    let second = sample_conflict("shell/zsh/main");
    let first_id = store.record_at(workspace, &first, 10).expect("登记 1");
    let second_id = store.record_at(workspace, &second, 20).expect("登记 2");
    // 另一个工作区的冲突不应出现在本工作区的列表里。
    store
        .record_at(other_workspace, &sample_conflict("terminal/wezterm"), 30)
        .expect("登记 3");

    assert_eq!(first_id, first.id());
    assert_eq!(
        store.state(first_id).expect("状态"),
        Some(ConflictState::Open)
    );

    let record = store.get(first_id).expect("查询").expect("存在");
    assert_eq!(record.conflict, first_id);
    assert_eq!(record.workspace, workspace);
    assert_eq!(record.resource, first.resource);
    assert_eq!(record.kind, ConflictKind::TextOverlap);
    assert_eq!(record.base, first.base);
    assert_eq!(record.ours, first.ours);
    assert_eq!(record.theirs, first.theirs);
    assert_eq!(record.state, ConflictState::Open);
    assert_eq!(record.choice, None);
    assert_eq!(record.resolved_blob, None);
    assert_eq!(record.created_at_unix_ms, 10);
    assert_eq!(record.resolved_at_unix_ms, None);

    let open = store.list_open(workspace).expect("列出未解决");
    assert_eq!(
        open.iter().map(|item| item.conflict).collect::<Vec<_>>(),
        vec![first_id, second_id]
    );

    // 结果 Blob 必须先存在于本地对象表。
    let merged = BlobId::of(b"merged content");
    drafts
        .put(ObjectId::from(merged), b"merged content")
        .expect("写入结果 Blob");

    let resolution = ConflictResolution::with_blob(
        first_id,
        ResolutionChoice::Manual,
        merged,
        1_700_000_000_000,
    );
    store.resolve(first_id, &resolution).expect("解决冲突");

    let resolved = store.get(first_id).expect("查询").expect("存在");
    assert_eq!(resolved.state, ConflictState::Resolved);
    assert_eq!(resolved.choice, Some(ResolutionChoice::Manual));
    assert_eq!(resolved.resolved_blob, Some(merged));
    assert_eq!(resolved.resolved_at_unix_ms, Some(1_700_000_000_000));

    // 已解决的冲突从未解决列表中消失。
    let open = store.list_open(workspace).expect("列出未解决");
    assert_eq!(
        open.iter().map(|item| item.conflict).collect::<Vec<_>>(),
        vec![second_id]
    );

    // 重复解决被拒绝。
    assert!(matches!(
        store.resolve(first_id, &resolution),
        Err(ConflictError::NotOpen { .. })
    ));

    // 状态在重开数据库后仍然可读。
    drop(store);
    let reopened = ConflictStore::open(&path).expect("重开冲突索引");
    assert_eq!(
        reopened.state(first_id).expect("状态"),
        Some(ConflictState::Resolved)
    );
}

#[test]
fn recording_the_same_conflict_twice_is_idempotent() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");
    let store = ConflictStore::open(&path).expect("打开冲突索引");
    let workspace = workspace_id();
    let conflict = sample_conflict("git/config");

    let first = store.record_at(workspace, &conflict, 10).expect("登记");
    let again = store
        .record_at(workspace, &conflict, 999)
        .expect("重复登记");
    assert_eq!(first, again);
    assert_eq!(store.list_open(workspace).expect("列出").len(), 1);
    // 重复登记不会改写既有行。
    assert_eq!(
        store
            .get(first)
            .expect("查询")
            .expect("存在")
            .created_at_unix_ms,
        10
    );

    // 已经解决的冲突不会被重新登记打开——否则用户的决定会被静默丢弃。
    let store2 = ConflictStore::open(&path).expect("再开一个连接");
    let drafts = DraftStore::open_database(&path).expect("打开草稿库");
    let blob = BlobId::of(b"chosen");
    drafts.put(ObjectId::from(blob), b"chosen").expect("写入");
    store
        .resolve(
            first,
            &ConflictResolution::with_blob(first, ResolutionChoice::Ours, blob, 1),
        )
        .expect("解决");
    store2
        .record_at(workspace, &conflict, 42)
        .expect("再次登记");
    assert_eq!(
        store.state(first).expect("状态"),
        Some(ConflictState::Resolved)
    );
}

#[test]
fn resolving_with_a_missing_blob_is_rejected() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");
    let store = ConflictStore::open(&path).expect("打开冲突索引");
    let workspace = workspace_id();
    let conflict = sample_conflict("git/config");
    let id = store.record_at(workspace, &conflict, 10).expect("登记");

    let missing = BlobId::of(b"never stored");
    let resolution =
        ConflictResolution::with_blob(id, ResolutionChoice::Theirs, missing, 1_700_000_000_000);
    match store.resolve(id, &resolution) {
        Err(ConflictError::InvalidResolution(ProfileError::ResolutionBlobUnknown { blob })) => {
            assert_eq!(blob, missing.to_hex());
        }
        other => panic!("期望拒绝不存在的 Blob，实际：{other:?}"),
    }
    // 冲突仍然是未解决的：拒绝必须不留下任何痕迹。
    assert_eq!(store.state(id).expect("状态"), Some(ConflictState::Open));
    assert_eq!(store.list_open(workspace).expect("列出").len(), 1);
}

#[test]
fn resolution_must_target_the_conflict_being_resolved() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");
    let store = ConflictStore::open(&path).expect("打开冲突索引");
    let workspace = workspace_id();
    let id = store
        .record_at(workspace, &sample_conflict("git/config"), 10)
        .expect("登记");

    let elsewhere = ConflictId::of(b"another conflict");
    let resolution = ConflictResolution::delete(elsewhere, 1);
    assert!(matches!(
        store.resolve(id, &resolution),
        Err(ConflictError::ConflictMismatch { .. })
    ));

    // 未登记的冲突无法解决。
    assert!(matches!(
        store.resolve(elsewhere, &ConflictResolution::delete(elsewhere, 1)),
        Err(ConflictError::UnknownConflict(_))
    ));
}

#[test]
fn delete_resolution_needs_no_blob_and_supersede_closes_a_conflict() {
    let dir = TempDir::new().expect("临时目录");
    let path = dir.path().join("journal.db");
    let store = ConflictStore::open(&path).expect("打开冲突索引");
    let workspace = workspace_id();

    let deleted = store
        .record_at(workspace, &sample_conflict("git/config"), 10)
        .expect("登记");
    store
        .resolve(deleted, &ConflictResolution::delete(deleted, 5))
        .expect("确认删除");
    let record = store.get(deleted).expect("查询").expect("存在");
    assert_eq!(record.choice, Some(ResolutionChoice::Delete));
    assert_eq!(record.resolved_blob, None);

    let stale = store
        .record_at(workspace, &sample_conflict("shell/zsh/main"), 20)
        .expect("登记");
    store.supersede(stale).expect("标记为已取代");
    assert_eq!(
        store.state(stale).expect("状态"),
        Some(ConflictState::Superseded)
    );
    assert!(store.list_open(workspace).expect("列出").is_empty());
    // 终态不会回到 open。
    assert!(matches!(
        store.supersede(stale),
        Err(ConflictError::NotOpen { .. })
    ));
}
