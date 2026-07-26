//! 数据库打开、连接 PRAGMA 与 schema 迁移。
//!
//! journal 是崩溃恢复的**事实来源**，因此这里的每个决定都偏向“宁可慢，不可丢”：
//!
//! * `journal_mode=WAL`：读不阻塞写，恢复流程可以在 apply 进行时安全地读 journal；
//!   WAL 同时保证进程崩溃后数据库仍可自动恢复到一致状态。
//! * `foreign_keys=ON`：SQLite 默认**关闭**外键，必须逐连接显式打开，
//!   否则收据可以指向不存在的动作，恢复算法会读到无主数据。
//! * `busy_timeout=5000`：CLI 与桌面端可能同时打开同一个库，短暂的写锁竞争
//!   应该等待而不是立刻失败。
//! * `synchronous=FULL`：**刻意不使用 NORMAL**。在 WAL 下 NORMAL 只在 checkpoint
//!   时 fsync，机器掉电可能丢掉最近若干次事务。对普通应用这是划算的取舍，但 journal
//!   记录的是“我已经动过用户的文件了”——丢掉最后一条记录意味着丢掉备份指针，
//!   恢复时既无法继续也无法回滚。因此这里用每次提交都 fsync 换取可恢复性。
//!
//! 迁移策略：`schema_meta` 表记录 `schema_version`。版本相同则直接返回（幂等）；
//! 版本更低则在一个事务里执行迁移脚本并写入新版本号；版本**更高**则拒绝打开，
//! 返回 [`JournalError::SchemaTooNew`]——旧版本程序改写新 schema 会造成不可逆的数据损坏。

use std::path::Path;

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::journal::JournalError;

/// 本版本支持的 schema 版本号。
pub const SCHEMA_VERSION: u32 = 1;

/// `schema_meta` 中记录 schema 版本的键名。
pub const SCHEMA_VERSION_KEY: &str = "schema_version";

/// 期望的 `PRAGMA synchronous` 数值：2 即 `FULL`。
const SYNCHRONOUS_FULL: i64 = 2;

/// 期望的 `PRAGMA busy_timeout` 毫秒数。
const BUSY_TIMEOUT_MS: i64 = 5_000;

/// 0001 迁移脚本，编译期内嵌，避免运行时依赖外部文件。
const MIGRATION_0001: &str = include_str!("../migrations/0001_journal.sql");

/// 连接层运行时诊断，供 `envsync doctor` 与测试断言使用。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageDiagnostics {
    /// 当前 journal 模式，正常应为 `wal`。
    pub journal_mode: String,
    /// 外键约束是否已启用。
    pub foreign_keys: bool,
    /// 忙等待超时（毫秒）。
    pub busy_timeout_ms: i64,
    /// `synchronous` 级别，2 表示 `FULL`。
    pub synchronous: i64,
    /// 数据库中记录的 schema 版本。
    pub schema_version: u32,
}

impl StorageDiagnostics {
    /// 是否满足 EnvSync 对持久化保证的全部要求。
    pub fn is_durable(&self) -> bool {
        self.journal_mode.eq_ignore_ascii_case("wal")
            && self.foreign_keys
            && self.busy_timeout_ms >= BUSY_TIMEOUT_MS
            && self.synchronous >= SYNCHRONOUS_FULL
    }
}

/// 打开（必要时创建）数据库，设置 PRAGMA 并把 schema 迁移到当前版本。
///
/// 重复调用是安全的：迁移幂等，PRAGMA 逐连接重新设置。
pub(crate) fn open_database(path: &Path) -> Result<Connection, JournalError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let connection = Connection::open(path)?;
    configure(&connection)?;
    migrate(&connection)?;
    tracing::debug!(path = %path.display(), "已打开 EnvSync 本地数据库");
    Ok(connection)
}

/// 设置并校验连接级 PRAGMA。
fn configure(connection: &Connection) -> Result<(), JournalError> {
    // `journal_mode` 会返回一行结果，必须用 query_row 而不是 execute。
    let mode: String = connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(JournalError::PragmaRejected {
            pragma: "journal_mode",
            expected: "wal".to_owned(),
            actual: mode,
        });
    }

    // 这三个 PRAGMA 都不返回结果集，直接批量执行。
    connection.execute_batch(
        "PRAGMA foreign_keys=ON;
         PRAGMA busy_timeout=5000;
         PRAGMA synchronous=FULL;",
    )?;

    // 不信任“设置成功即生效”：逐项读回校验，避免在只读介质或旧版本 SQLite 上静默降级。
    let foreign_keys = read_pragma_i64(connection, "foreign_keys")?;
    if foreign_keys != 1 {
        return Err(JournalError::PragmaRejected {
            pragma: "foreign_keys",
            expected: "1".to_owned(),
            actual: foreign_keys.to_string(),
        });
    }
    let busy_timeout = read_pragma_i64(connection, "busy_timeout")?;
    if busy_timeout != BUSY_TIMEOUT_MS {
        return Err(JournalError::PragmaRejected {
            pragma: "busy_timeout",
            expected: BUSY_TIMEOUT_MS.to_string(),
            actual: busy_timeout.to_string(),
        });
    }
    let synchronous = read_pragma_i64(connection, "synchronous")?;
    if synchronous < SYNCHRONOUS_FULL {
        return Err(JournalError::PragmaRejected {
            pragma: "synchronous",
            expected: SYNCHRONOUS_FULL.to_string(),
            actual: synchronous.to_string(),
        });
    }
    Ok(())
}

/// 读取一个返回单个整数的 PRAGMA。
fn read_pragma_i64(connection: &Connection, pragma: &str) -> Result<i64, JournalError> {
    let sql = format!("PRAGMA {pragma}");
    Ok(connection.query_row(&sql, [], |row| row.get(0))?)
}

/// 把 schema 迁移到 [`SCHEMA_VERSION`]。
fn migrate(connection: &Connection) -> Result<(), JournalError> {
    // schema_meta 必须先于版本判断存在，因此它不属于任何一个版本化迁移脚本。
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_meta (
             key   TEXT NOT NULL PRIMARY KEY,
             value TEXT NOT NULL
         ) STRICT;",
    )?;

    match read_schema_version(connection)? {
        Some(found) if found > SCHEMA_VERSION => {
            // 旧版本程序绝不能改写新 schema：宁可拒绝打开，也不能损坏用户数据。
            return Err(JournalError::SchemaTooNew {
                found,
                supported: SCHEMA_VERSION,
            });
        }
        Some(found) if found == SCHEMA_VERSION => return Ok(()),
        _ => {}
    }

    // 建表与版本号写入必须原子：否则中途崩溃会留下“表建了一半，版本号却已更新”。
    let transaction = connection.unchecked_transaction()?;
    transaction.execute_batch(MIGRATION_0001)?;
    transaction.execute(
        "INSERT INTO schema_meta (key, value) VALUES (?1, ?2)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        rusqlite::params![SCHEMA_VERSION_KEY, SCHEMA_VERSION.to_string()],
    )?;
    transaction.commit()?;
    tracing::debug!(version = SCHEMA_VERSION, "schema 已迁移到当前版本");
    Ok(())
}

/// 读取数据库中记录的 schema 版本；表存在但没有记录时返回 `None`。
pub(crate) fn read_schema_version(connection: &Connection) -> Result<Option<u32>, JournalError> {
    let raw: Option<String> = connection
        .query_row(
            "SELECT value FROM schema_meta WHERE key = ?1",
            [SCHEMA_VERSION_KEY],
            |row| row.get(0),
        )
        .optional()?;
    match raw {
        None => Ok(None),
        Some(text) => text.parse::<u32>().map(Some).map_err(|_| {
            JournalError::Corrupt(format!("schema_meta 中的 schema_version 非法：`{text}`"))
        }),
    }
}

/// 采集连接层诊断。
pub(crate) fn read_diagnostics(
    connection: &Connection,
) -> Result<StorageDiagnostics, JournalError> {
    Ok(StorageDiagnostics {
        journal_mode: connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?,
        foreign_keys: read_pragma_i64(connection, "foreign_keys")? == 1,
        busy_timeout_ms: read_pragma_i64(connection, "busy_timeout")?,
        synchronous: read_pragma_i64(connection, "synchronous")?,
        schema_version: read_schema_version(connection)?.unwrap_or(0),
    })
}
