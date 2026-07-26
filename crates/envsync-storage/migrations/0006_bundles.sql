-- EnvSync 本地存储 schema 0006：Agent Bundle 的隔离状态与文件清单。
--
-- 该文件由 `src/migrations.rs` 通过 `include_str!` 内嵌，并与前序脚本在**同一个事务**
-- 中执行；所有语句都是 `IF NOT EXISTS` 形式，因此重复执行不会出错（迁移幂等）。
--
-- ## 这张表记录的是「本机对某个 Bundle 的信任决定」
--
-- Bundle 的内容不在数据库里：它躺在不可执行的 quarantine 根下，由
-- `envsync_core::bundles` 写入。这里只记录判定结果——处在哪个隔离状态、批准过哪些
-- 能力、被谁签名、因何被阻断。因此这张表即使被完整读走也不泄露任何秘密：
-- `secret_refs` 是逻辑标识而不是值，`publisher_key` 是公钥。
--
-- ## 为什么 `approved_capabilities` 要单独存
--
-- 批准绑定的是四元组 `(manifest 摘要, 能力集, 目标 Profile, signer)`，而不是「这个
-- Bundle 我信了」。Bundle 升级后 manifest 摘要必然变化，新版本可能**多声明**几项
-- 能力；如果只记「已批准」这一个布尔值，新增能力就会随升级静默生效。把当时批准的
-- 能力集原样存下来，升级时才能算出差集并要求重新审核。
--
-- 判定逻辑一律在 `envsync_core::bundles` 里，本层只做存取——与 `rotations`、
-- `checkpoints` 的分工一致：判定散落到存储实现里只会产生互不一致的安全边界。
--
-- ## 状态取值由 `CHECK` 钉死
--
-- 状态字符串是 `envsync_domain::agent_bundle::BundleState` 的持久化契约，只能新增、
-- 不能重命名。数据库一侧再钉一次，是为了让「外部工具直接改库」这条路径也撞上约束
-- 而不是让程序读到一个它不认识的状态。

-- 每个 Bundle 在本机的隔离状态。
--
-- 主键是 `bundle_id`：同一个 Bundle 在一台设备上只有一份信任决定。升级是对同一行的
-- 更新（连带 `version` 与 `manifest_digest` 一起变），而不是并列出第二行——两行互相
-- 矛盾的信任决定没有任何正确的解释方式。
CREATE TABLE IF NOT EXISTS bundles (
    bundle_id              TEXT    NOT NULL PRIMARY KEY,
    -- semver 文本；比较由 Rust 侧做，SQLite 不理解 semver 序。
    version                TEXT    NOT NULL,
    -- canonical manifest 的域分隔摘要，64 位小写十六进制。
    manifest_digest        TEXT    NOT NULL,
    -- 发布者 Ed25519 公钥，64 位小写十六进制。
    publisher_key          TEXT    NOT NULL,
    state                  TEXT    NOT NULL
        CHECK (state IN ('downloaded', 'inspected', 'approved', 'enabled',
                         'blocked', 'revoked')),
    -- JSON 数组：批准时刻 manifest 声明的能力集合，已排序去重。
    -- 未批准时是空数组 `[]` 而不是 NULL：空集合与「没有这个概念」是两件事。
    approved_capabilities  TEXT    NOT NULL DEFAULT '[]',
    -- 批准时刻（Unix 毫秒）；从未批准时为 NULL。
    approved_at            INTEGER,
    -- 阻断原因；未被阻断时为 NULL。只放结构化描述，不放文件正文或秘密。
    blocked_reason         TEXT,
    updated_at_unix_ms     INTEGER NOT NULL,
    -- `approved` 与 `enabled` 蕴含「批准发生过」，因此批准时刻不得缺席。
    -- 反过来不成立：批准之后被阻断的 Bundle 仍然保留批准时刻，那是审计要看的历史。
    --
    -- 刻意**不**约束 `approved_capabilities` 非空：一个什么能力都不声明的 Bundle
    -- 被批准后，它的能力集合就是空集，那是合法状态而不是「没批准过」。
    CHECK (state NOT IN ('approved', 'enabled') OR approved_at IS NOT NULL)
) STRICT;

-- 「哪些 Bundle 正在生效」是审计与 `envsync doctor` 的第一个问题。
CREATE INDEX IF NOT EXISTS idx_bundles_state
    ON bundles (state);

-- 「这个发布者签过哪些 Bundle」——撤销一把发布者密钥时需要一次性找出全部受影响项。
CREATE INDEX IF NOT EXISTS idx_bundles_publisher_key
    ON bundles (publisher_key);

-- Bundle 的文件清单：manifest 里 `files` 的持久化副本。
--
-- 存它是为了让「本机磁盘上的 quarantine 内容有没有被改过」这个问题不必依赖后端：
-- 重新哈希 quarantine 目录并与本表比对即可。
--
-- `ON DELETE CASCADE` 保证删掉一个 Bundle 时它的文件清单不会变成无主数据；
-- 外键在 `migrations.rs` 的 `PRAGMA foreign_keys=ON` 下逐连接生效。
CREATE TABLE IF NOT EXISTS bundle_files (
    bundle_id  TEXT NOT NULL REFERENCES bundles (bundle_id) ON DELETE CASCADE,
    -- Bundle 根下的相对路径，以 `/` 分隔；合法性由
    -- `envsync_domain::agent_bundle::validate_bundle_path` 保证。
    path       TEXT NOT NULL,
    -- 内容摘要，64 位小写十六进制。
    digest     TEXT NOT NULL,
    PRIMARY KEY (bundle_id, path)
) STRICT;

-- 「哪个 Bundle 声称拥有这条路径」——排查两个 Bundle 抢同一个渲染目标时用。
CREATE INDEX IF NOT EXISTS idx_bundle_files_path
    ON bundle_files (path);
