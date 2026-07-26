-- EnvSync 本地存储 schema 0004：反回滚检查点的**审计副本**。
--
-- 该文件由 `src/migrations.rs` 通过 `include_str!` 内嵌，并与前序脚本在**同一个事务**
-- 中执行；语句是 `IF NOT EXISTS` 形式，因此重复执行不会出错（迁移幂等）。
--
-- ## 这不是权威副本
--
-- 检查点的**权威副本保存在系统安全存储**（macOS Keychain / Windows Credential
-- Manager / Linux Secret Service）。这张表只是审计副本，方便 `envsync doctor`、事后
-- 排查与支持流程查看「本机认为自己到哪儿了」。
--
-- 两份不一致时**以安全存储为准并告警**：这个 SQLite 文件躺在用户目录里，任何本地
-- 进程都能改写；把它当权威等于把反回滚保护拱手让人。尤其不能出现「SQLite 里的检查点
-- 更旧，于是把安全存储里的降下来」这种逻辑——那是一条免费的回滚通道。
--
-- ## 为什么有 membership_sequence
--
-- 摘要之间没有顺序。只拿到两个 `membership_digest`，本地无法判断哪个更新。因此这里
-- 额外记录已验证链头所在的 sequence，使「旧 membership head」成为可判定的条件：
-- sequence 更小即阻塞；sequence 相同但摘要不同即分叉。链的**延续性**由
-- `verify_membership_chain` 负责，检查点只做单调性判定。

-- 每个工作区一行的反回滚高水位线。
--
-- 四个维度都必须单调：revision、snapshot（同 revision 下必须一致）、
-- membership（sequence + digest）、key_epoch。任何一个回退都说明后端在撒谎。
CREATE TABLE IF NOT EXISTS checkpoints (
    workspace_id        TEXT    NOT NULL PRIMARY KEY,
    revision            INTEGER NOT NULL CHECK (revision >= 0),
    snapshot_id         TEXT    NOT NULL,
    membership_digest   TEXT    NOT NULL,
    membership_sequence INTEGER NOT NULL CHECK (membership_sequence >= 0),
    key_epoch           INTEGER NOT NULL CHECK (key_epoch >= 1),
    updated_at_unix_ms  INTEGER NOT NULL
) STRICT;
