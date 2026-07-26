-- EnvSync 本地存储 schema 0003：设备成员签名链的本地索引与已验证链头。
--
-- 该文件由 `src/migrations.rs` 通过 `include_str!` 内嵌，并与前序脚本在**同一个事务**
-- 中执行；所有语句都是 `IF NOT EXISTS` 形式，因此重复执行不会出错（迁移幂等）。
--
-- 设计取舍：
--
-- * 与 0001/0002 一致，全部使用 `STRICT` 表。
-- * **成员事件本身是内容寻址的不可变对象**，完整的 canonical CBOR 存在 Backend
--   （`ObjectKind::MembershipEvent`）里。这两张表只保存*索引*与*已验证的结论*：
--   哪条 sequence、摘要是什么、对应哪个对象、做了什么动作。事件正文刻意**不**落库，
--   否则同一条事件会有两个可能不一致的事实来源。
-- * 签名同样不落库：验签只能在拿到完整事件对象时进行，把签名单独抄一份进关系表，
--   只会让人误以为可以「查表验签」。
-- * 只有**通过 `verify_membership_chain` 的事件**才允许写进来。写入是「链头前进」这
--   一个原子动作：插入事件行与更新链头在同一个事务里完成，不存在「事件写进去了、
--   链头没动」的中间态。
-- * 时间列统一用 `_unix_ms` 后缀的 INTEGER，与前序脚本保持一致。

-- 已验证的成员事件索引。
--
-- 主键是 `(workspace_id, sequence)`：同一个工作区的同一个位置只能有一条事件。
-- 这条约束是**数据库一侧的反分叉保护**——即使 Rust 侧的验证器出现回归，两个不同的
-- 事件也无法同时落在同一个 sequence 上。
--
-- `event_digest` 是事件的 canonical 摘要（覆盖整个事件，含签名），后继事件的
-- `previous` 指向的就是它；它上面另有唯一索引，杜绝同一条事件被登记到两个位置。
CREATE TABLE IF NOT EXISTS membership_events (
    workspace_id       TEXT    NOT NULL,
    sequence           INTEGER NOT NULL CHECK (sequence >= 0),
    event_digest       TEXT    NOT NULL,
    object_id          TEXT    NOT NULL,
    epoch              INTEGER NOT NULL CHECK (epoch >= 1),
    actor              TEXT    NOT NULL,
    action_kind        TEXT    NOT NULL
        CHECK (action_kind IN ('genesis', 'add_member', 'promote', 'revoke')),
    subject            TEXT    NOT NULL,
    created_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, sequence),
    -- sequence 0 当且仅当 genesis：链的信任根不能藏在中间某个位置。
    CHECK ((sequence = 0 AND action_kind = 'genesis')
           OR (sequence > 0 AND action_kind <> 'genesis'))
) STRICT;

-- 同一条事件不能被登记到两个不同的位置。
CREATE UNIQUE INDEX IF NOT EXISTS idx_membership_events_digest
    ON membership_events (workspace_id, event_digest);

-- 「这台设备参与过哪些成员变更」是审计与排查时的常用查询。
CREATE INDEX IF NOT EXISTS idx_membership_events_subject
    ON membership_events (workspace_id, subject, sequence);

-- 已验证的链头。
--
-- 每个工作区**只有一行**：它就是「本机验证到哪里了」这个事实本身。
-- 注意它不是信任根——信任根（genesis 摘要 + 反回滚检查点）的权威副本在系统安全存储，
-- 这张表和 `checkpoints` 一样只是审计副本。
--
-- `head_digest` 必须能在 `membership_events` 中找到对应行，由 Rust 侧在同一个事务里
-- 保证；这里不用外键，因为外键的目标列是 `(workspace_id, event_digest)` 唯一索引，
-- 而 SQLite 的外键在这种复合唯一索引上会让每次写入都多做一次查表，收益不抵成本。
CREATE TABLE IF NOT EXISTS membership_head (
    workspace_id        TEXT    NOT NULL PRIMARY KEY,
    head_digest         TEXT    NOT NULL,
    sequence            INTEGER NOT NULL CHECK (sequence >= 0),
    epoch               INTEGER NOT NULL CHECK (epoch >= 1),
    verified_at_unix_ms INTEGER NOT NULL
) STRICT;
