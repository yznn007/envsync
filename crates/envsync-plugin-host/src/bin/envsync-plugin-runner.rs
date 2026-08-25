//! test-only Unix 插件 runner。
//!
//! 它只接受 Host 构造的内存上限和绝对入口路径；在建立独立进程组、设置地址空间上限后
//! 以精确路径执行入口。该二进制由 `test-support` feature 限制，不能代表生产 sandbox。

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

#[cfg(unix)]
fn main() {
    if let Err(error) = run() {
        eprintln!("envsync plugin runner setup failed: {}", error.code());
        std::process::exit(64);
    }
}

#[cfg(unix)]
fn run() -> Result<(), RunnerSetupError> {
    use std::ffi::{CString, OsStr};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    use nix::sys::resource::{rlim_t, setrlimit, Resource};
    use nix::unistd::{execv, getpgrp, getpid, setpgid, Pid};

    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(OsStr::new("--memory-bytes")) {
        return Err(RunnerSetupError::Arguments);
    }
    let memory_bytes = args
        .next()
        .and_then(|value| value.into_string().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .and_then(|value| rlim_t::try_from(value).ok())
        .ok_or(RunnerSetupError::Arguments)?;
    if args.next().as_deref() != Some(OsStr::new("--")) {
        return Err(RunnerSetupError::Arguments);
    }
    let entrypoint = args
        .next()
        .map(PathBuf::from)
        .ok_or(RunnerSetupError::Arguments)?;
    if args.next().is_some() || !entrypoint.is_absolute() {
        return Err(RunnerSetupError::Arguments);
    }
    let entrypoint =
        CString::new(entrypoint.as_os_str().as_bytes()).map_err(|_| RunnerSetupError::Arguments)?;

    // 父 Host 可能已经在 spawn 后抢先把 runner 放入以其 PID 命名的进程组。这里先
    // 检查，避免对已是组长的进程重复 setpgid；否则由 runner 自己建立该组。
    if getpgrp() != getpid() {
        setpgid(Pid::from_raw(0), Pid::from_raw(0)).map_err(|_| RunnerSetupError::ProcessGroup)?;
    }
    setrlimit(Resource::RLIMIT_AS, memory_bytes, memory_bytes)
        .map_err(|_| RunnerSetupError::MemoryLimit)?;
    execv(&entrypoint, &[entrypoint.as_c_str()]).map_err(|_| RunnerSetupError::Exec)?;
    unreachable!("execv only returns on error")
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum RunnerSetupError {
    Arguments,
    ProcessGroup,
    MemoryLimit,
    Exec,
}

#[cfg(unix)]
impl RunnerSetupError {
    const fn code(self) -> &'static str {
        match self {
            Self::Arguments => "plugin.host.runner_arguments",
            Self::ProcessGroup => "plugin.host.runner_process_group",
            Self::MemoryLimit => "plugin.host.runner_memory_limit",
            Self::Exec => "plugin.host.runner_exec",
        }
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("envsync plugin runner requires Unix");
    std::process::exit(64);
}
