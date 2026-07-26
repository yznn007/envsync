-- EnvSync 本地存储 schema 0002：设备 Profile 索引 + 合并冲突索引。
--
-- 该文件由 `src/migrations.rs` 通过 `include_str!` 内嵌，并与 0001 在**同一个事务**中
-- 执行；所有语句都是 `IF NOT EXISTS` 形式，因此重复执行不会出错（迁移幂等）。
--
-- 设计取舍：
--
-- * 与 0001 一致，全部使用 `STRICT` 表：类型不符在写入时就被拒绝。
-- * **冲突对象本身是内容寻址的**（`Conflict` 的 canonical CBOR 存在 `objects` 表或
--   Backend 里），这张表只保存*索引与状态*：谁、哪个资源、指向哪些 Blob、解决到
--   哪一步。诊断正文（`Conflict::diagnostics`）刻意**不**落库：它属于不可变对象的
--   一部分，复制一份进关系表就会出现两个可能不一致的事实来源。
-- * 时间列统一用 `_unix_ms` 后缀的 INTEGER，与 0001 的命名保持一致。
-- * 状态与解决方式的合法取值用 CHECK 约束固定在数据库一侧。Rust 侧同样有枚举，
--   两道防线的目的不同：Rust 防止本程序写错，CHECK 防止外部工具写坏。

-- 设备 Profile：投影所需的设备属性快照。
-- `tags` 与 `capabilities` 存 JSON 数组文本（元素为已 trim 的非空字符串，升序排列）。
-- 之所以不拆成子表：Profile 总是被整体读写，从不按标签做关系查询，拆表只会增加
-- 一次写入的事务面积。
CREATE TABLE IF NOT EXISTS profiles (
    device_id          TEXT NOT NULL PRIMARY KEY,
    os                 TEXT NOT NULL,
    arch               TEXT NOT NULL,
    hostname           TEXT,
    tags               TEXT NOT NULL DEFAULT '[]',
    capabilities       TEXT NOT NULL DEFAULT '[]',
    updated_at_unix_ms INTEGER NOT NULL
) STRICT;

-- 合并冲突索引。
--
-- `conflict_id` 就是冲突对象的内容摘要，因此重复登记同一个冲突天然幂等，
-- 也保证“同样的冲突在任何设备上都是同一行”。
--
-- 状态机：open -> resolved（用户做出决定）
--         open -> superseded（该冲突已被新的合并结果取代，不需要再处理）
-- 终态不允许回到 open：已经解决的冲突若再次出现，那是一个**新的**冲突对象。
CREATE TABLE IF NOT EXISTS conflicts (
    conflict_id         TEXT    NOT NULL PRIMARY KEY,
    workspace_id        TEXT    NOT NULL,
    resource_id         TEXT    NOT NULL,
    kind                TEXT    NOT NULL,
    base_blob           TEXT,
    ours_blob           TEXT,
    theirs_blob         TEXT,
    state               TEXT    NOT NULL
        CHECK (state IN ('open', 'resolved', 'superseded')),
    resolution_choice   TEXT
        CHECK (resolution_choice IS NULL
               OR resolution_choice IN ('ours', 'theirs', 'manual', 'delete')),
    resolved_blob       TEXT,
    created_at_unix_ms  INTEGER NOT NULL,
    resolved_at_unix_ms INTEGER,
    -- 只有 resolved 状态才能带解决方式；反过来，resolved 必须带解决方式和时间。
    CHECK ((state = 'resolved'
            AND resolution_choice IS NOT NULL
            AND resolved_at_unix_ms IS NOT NULL)
           OR (state <> 'resolved'
               AND resolution_choice IS NULL
               AND resolved_blob IS NULL
               AND resolved_at_unix_ms IS NULL)),
    -- ours/theirs/manual 必须指向结果 Blob；delete 表示确认删除，不能带 Blob。
    CHECK (resolution_choice IS NULL
           OR (resolution_choice = 'delete' AND resolved_blob IS NULL)
           OR (resolution_choice <> 'delete' AND resolved_blob IS NOT NULL))
) STRICT;

-- 「列出某个工作区的未解决冲突」是同步流程每次都会做的查询，必须走索引。
CREATE INDEX IF NOT EXISTS idx_conflicts_workspace_state
    ON conflicts (workspace_id, state, created_at_unix_ms);

-- 按资源回溯冲突历史（含已解决的）。
CREATE INDEX IF NOT EXISTS idx_conflicts_resource
    ON conflicts (resource_id, created_at_unix_ms);
