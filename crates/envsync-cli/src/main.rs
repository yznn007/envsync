//! `envsync` 可执行文件入口。
//!
//! 真正的实现全部在同名的库目标里（[`envsync_cli`]）：把参数解析、命令实现与输出渲染
//! 放进 lib，是为了让**集成测试可以在进程内注入依赖**——最典型的就是
//! `tests/vault_cli.rs` 里那组脱敏 golden 测试，它需要一个内存安全存储替身，而通过
//! 子进程调用二进制是没法注入的。
//!
//! 这个文件因此刻意只有一行逻辑。

fn main() -> std::process::ExitCode {
    envsync_cli::run()
}
