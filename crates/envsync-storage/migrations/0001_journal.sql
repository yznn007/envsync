-- EnvSync 本地存储 schema 0001：操作日志 + 本地草稿对象。
--
-- 该文件由 `src/migrations.rs` 通过 `include_str!` 内嵌，并在**一个事务**中整体执行；
-- 所有语句都写成 `IF NOT EXISTS` 形式，因此即使被重复执行也不会出错（迁移幂等）。
--
-- 设计取舍：
--
-- * 全部使用 `STRICT` 表：让 SQLite 在写入时就拒绝类型不符的值，而不是等到 Rust 侧
--   读取时才发现，崩溃恢复的事实来源不应该容忍类型漂移。
-- * 标识符（OperationId/PlanId/SnapshotId/WorkspaceId/ResourceId）统一存 TEXT，
--   摘要统一存小写十六进制 TEXT。这样任何普通 sqlite3 客户端都能直接排查 journal，
--   不需要先跑 EnvSync 才能读懂数据。
-- * `receipts.backup_path` 只存字符串：storage crate **不依赖** platform crate，
--   收据里不出现任何平台路径类型。
-- * 外键一律 `ON DELETE CASCADE`：删除一个 operation 必然连带删除它的动作与收据，
--   不允许出现孤儿行。

-- 操作：一次 apply 事务的完整生命周期。
-- `state` 的取值与合法迁移由 Rust 侧 `OperationState` 强制，数据库只负责持久化。
CREATE TABLE IF NOT EXISTS operations (
    operation_id       TEXT    NOT NULL PRIMARY KEY,
    plan_id            TEXT    NOT NULL,
    snapshot_id        TEXT    NOT NULL,
    workspace_id       TEXT    NOT NULL,
    revision           INTEGER NOT NULL,
    state              TEXT    NOT NULL,
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    error_code         TEXT,
    error_message      TEXT
) STRICT;

-- 按状态查询未完成操作是恢复流程的第一步，必须走索引而不是全表扫描。
CREATE INDEX IF NOT EXISTS idx_operations_state
    ON operations (state, updated_at_unix_ms);

-- 按工作区回溯历史操作。
CREATE INDEX IF NOT EXISTS idx_operations_workspace
    ON operations (workspace_id, created_at_unix_ms);

-- 动作：计划中的单个写入意图，`ordinal` 即计划中的应用顺序。
-- 回滚必须按 `ordinal` 逆序进行，因此这个序号是持久化契约的一部分。
CREATE TABLE IF NOT EXISTS actions (
    operation_id           TEXT    NOT NULL
        REFERENCES operations (operation_id) ON DELETE CASCADE,
    ordinal                INTEGER NOT NULL,
    resource_id            TEXT    NOT NULL,
    target                 TEXT    NOT NULL,
    kind                   TEXT    NOT NULL,
    state                  TEXT    NOT NULL,
    expected_before_digest TEXT,
    expected_after_digest  TEXT,
    error_code             TEXT,
    error_message          TEXT,
    PRIMARY KEY (operation_id, ordinal)
) STRICT;

-- 同一个操作里，同一资源的同一种动作只能出现一次。
-- 否则恢复时无法判断“这条动作到底应用过没有”，会导致重复写入。
CREATE UNIQUE INDEX IF NOT EXISTS idx_actions_resource_kind
    ON actions (operation_id, resource_id, kind);

-- 收据：动作实际应用后的可回滚证据。
-- 除了指向 operations 的外键，还有一条指向 actions 的复合外键：
-- 收据只能属于确实存在的动作，避免恢复时读到无主收据。
CREATE TABLE IF NOT EXISTS receipts (
    operation_id       TEXT    NOT NULL
        REFERENCES operations (operation_id) ON DELETE CASCADE,
    ordinal            INTEGER NOT NULL,
    resource_id        TEXT    NOT NULL,
    backup_path        TEXT,
    original_digest    TEXT,
    applied_digest     TEXT,
    guarantee          TEXT    NOT NULL,
    created_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (operation_id, ordinal),
    FOREIGN KEY (operation_id, ordinal)
        REFERENCES actions (operation_id, ordinal) ON DELETE CASCADE
) STRICT;

-- 本地草稿对象：capture 产生的 Blob / State Root / Snapshot 先落在这里，
-- 只有 publish 时才上传到 Backend，避免未发布的内容污染后端 CAS。
-- `object_id` 是 `种类/十六进制摘要` 的文本形式，因此天然带域分隔。
CREATE TABLE IF NOT EXISTS objects (
    object_id TEXT NOT NULL PRIMARY KEY,
    bytes     BLOB NOT NULL
) STRICT;

-- 本地草稿计划：以 canonical CBOR 字节存放，键为 PlanId 的十六进制。
CREATE TABLE IF NOT EXISTS plans (
    plan_id TEXT NOT NULL PRIMARY KEY,
    bytes   BLOB NOT NULL
) STRICT;

-- 草稿元数据键值表，目前只用来记录 `head_draft`（本地草稿头快照）。
-- 刻意与 `schema_meta` 分开：schema 元数据属于迁移机制，草稿头属于业务数据。
CREATE TABLE IF NOT EXISTS draft_meta (
    key   TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
