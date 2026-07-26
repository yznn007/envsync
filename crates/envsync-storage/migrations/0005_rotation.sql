-- EnvSync 本地存储 schema 0005：可恢复的密钥轮换 journal。
--
-- 该文件由 `src/migrations.rs` 通过 `include_str!` 内嵌，并与前序脚本在**同一个事务**
-- 中执行；所有语句都是 `IF NOT EXISTS` 形式，因此重复执行不会出错（迁移幂等）。
--
-- ## 为什么轮换需要一个 journal
--
-- 撤销一台设备要做四件互相依赖的事：生成新纪元的数据密钥、给每个剩余设备发一份新
-- 信封、发布推进纪元的成员事件（新头）、把旧纪元的秘密逐步重加密。进程可能在任何一步
-- 之间被杀死。没有 journal 的话，重启后既不知道做到哪儿了，也无法判断「后端上已经
-- 有的东西」是自己上次写的还是别人写的。
--
-- ## 阶段顺序是安全约束，不只是流程
--
-- ```text
-- prepared → envelopes_published → head_published → rewrapping → complete
-- ```
--
-- `envelopes_published` **必须**早于 `head_published`。新头把工作区的密钥纪元推到
-- n+1；如果此时信封还没发布，剩余设备就拿不到 n+1 的数据密钥，整个工作区会卡在
-- 「所有人都读不了新内容」的状态，而且这个状态无法靠重试自愈——它是后端上的既成
-- 事实。反过来「信封发布了但新头还没发」是完全安全的：多出来的信封只是几个没人引用
-- 的不可变对象，下一次恢复会原样复用它们。
--
-- ## 幂等恢复靠的是「一切可重放」
--
-- * 新纪元的数据密钥在 `prepared` 阶段就写进系统安全存储的密钥环，恢复时读回来，
--   不会每次重试都生成一把新的；
-- * 信封与成员事件都是内容寻址的不可变对象，重复写入是幂等的；
-- * 成员事件的 `created_at_unix_ms` 固定为本表的 `event_created_at_unix_ms`，
--   因此每次重放都签出**字节完全相同**的事件，摘要不变、链头不变。
--
-- 每个工作区至多有一次进行中的轮换，因此 `workspace_id` 就是主键：并发发起第二次
-- 轮换会覆盖（而不是并列）第一次，避免出现两条互相矛盾的恢复路径。

-- 进行中的（或最近一次完成的）密钥轮换。
CREATE TABLE IF NOT EXISTS rotations (
    workspace_id            TEXT    NOT NULL PRIMARY KEY,
    from_epoch              INTEGER NOT NULL CHECK (from_epoch >= 1),
    to_epoch                INTEGER NOT NULL CHECK (to_epoch >= 2),
    revoked_device          TEXT    NOT NULL,
    stage                   TEXT    NOT NULL
        CHECK (stage IN ('prepared', 'envelopes_published', 'head_published',
                         'rewrapping', 'complete')),
    -- JSON 数组：剩余 active 设备的十六进制标识，顺序即发放信封的顺序。
    recipients              TEXT    NOT NULL,
    -- JSON 数组：已经写进后端的信封对象标识（`kind/digest` 文本形式）。
    envelopes               TEXT    NOT NULL,
    -- JSON 数组：尚未用新密钥重加密的秘密逻辑标识。
    pending_rewrap          TEXT    NOT NULL,
    -- 成员事件的创建时刻。固定下来才能让重放签出字节相同的事件。
    event_created_at_unix_ms INTEGER NOT NULL,
    started_at_unix_ms      INTEGER NOT NULL,
    updated_at_unix_ms      INTEGER NOT NULL,
    -- 纪元一次只能 +1；这与成员链验证器的规则一致，在数据库一侧再钉一次。
    CHECK (to_epoch = from_epoch + 1)
) STRICT;

-- 「这台设备是在哪次轮换里被撤销的」是审计与排查时的常用查询。
CREATE INDEX IF NOT EXISTS idx_rotations_revoked_device
    ON rotations (revoked_device);
