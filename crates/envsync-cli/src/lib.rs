#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

//! # envsync
//!
//! EnvSync 的命令行界面：解析参数、调用 [`envsync_core`] 的应用服务、把结果渲染成
//! 人类可读文本或单行 JSON，并把核心层错误映射成稳定的退出码。
//!
//! ## 为什么这是一个库
//!
//! 二进制目标（`src/main.rs`）只有一行：调用 [`run`]。真正的实现放在库里，是为了让
//! 集成测试能够**在进程内注入依赖**。`tests/vault_cli.rs` 的脱敏 golden 测试需要一个
//! 内存安全存储替身——生产路径只认
//! [`envsync_platform::secure_store::open_system_store`]，而 CI 上没有系统凭据库。
//! 通过子进程调用二进制是没法注入的，于是那组测试直接调用
//! [`crate::vault_cli`] 里的命令函数，并断言它们**渲染出来的字节**里没有 canary。
//!
//! 注入入口 [`vault_cli::VaultContext::with_stores`] 挂在 `test-support` feature 下，
//! 而该 feature 由 `[dev-dependencies]` 中对自身的引用打开：`cargo test` 会开，
//! `cargo build` 不会。也就是说「测试替身跑进生产二进制」在编译期就不可能。
//!
//! ## 退出码
//!
//! | 码 | 含义 |
//! |---|---|
//! | 0 | 成功 |
//! | 1 | 一般错误 |
//! | 2 | 用法错误（缺参数、参数非法），由 clap 产生 |
//! | 10 | 后端 CAS 冲突，别的设备先发布了 |
//! | 11 | 计划失效或不存在，需要重新 `plan` |
//! | 12 | 策略阻塞，计划里有阻塞诊断 |
//! | 13 | 存在未解决的合并冲突；本地文件与远端 Ref 都没有被改动 |
//! | 14 | **检测到后端回滚或分叉**；必须中止排查，不要重试（M2） |
//! | 15 | 系统安全存储不可用/被锁定/被拒绝；**绝不**回退到明文存储（M2） |
//! | 20 | 已发布但本地未收敛，需要 `recover` 或 `rollback` |
//!
//! 退出码只由 [`envsync_core::CoreError`] 的判定方法派生，不看错误文本，因此错误信息
//! 可以随时改写而不破坏脚本。
//!
//! ## 三条输出约束
//!
//! 1. `--json` 时 stdout 只有一行 JSON，日志与诊断一律写 stderr；
//! 2. 所有输出都过一遍 [`output`] 里的脱敏器；
//! 3. **秘密值只有一条出路**：`envsync vault get --output <文件>`，或显式的
//!    `--output stdout --allow-non-tty`。除此之外的任何路径——包括
//!    `--json`、日志、错误、诊断——都不会出现秘密值。

pub mod cli;
pub mod commands;
pub mod output;
pub mod vault_cli;

pub use cli::run;
