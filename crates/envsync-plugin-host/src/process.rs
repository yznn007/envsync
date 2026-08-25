//! test-only runner 的受控进程和单会话 RPC 边界。
//!
//! 生产构建不会编译此模块。支持 `RLIMIT_AS` 的 Unix 平台上，Host 为每个会话建立空 cwd、
//! 清空环境和标准 I/O 管道；stdout/stderr 共用一个原子输出预算，失败时终止整个进程组。

#[cfg(all(unix, not(target_os = "macos")))]
use std::io::{self, Read, Write};
#[cfg(all(unix, not(target_os = "macos")))]
use std::path::Path;
#[cfg(all(unix, not(target_os = "macos")))]
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
#[cfg(all(unix, not(target_os = "macos")))]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(all(unix, not(target_os = "macos")))]
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
#[cfg(all(unix, not(target_os = "macos")))]
use std::sync::Arc;
#[cfg(all(unix, not(target_os = "macos")))]
use std::thread::{self, JoinHandle};
#[cfg(all(unix, not(target_os = "macos")))]
use std::time::{Duration, Instant};

#[cfg(all(unix, not(target_os = "macos")))]
use envsync_plugin_api::{
    read_frame, write_frame, PluginMethod, PluginRpcError, RequestId, ResourceLimits, RpcMessage,
    RpcRequest, RpcResponse, SchemaVersion,
};
#[cfg(all(unix, not(target_os = "macos")))]
use nix::sys::signal::{killpg, Signal};
#[cfg(all(unix, not(target_os = "macos")))]
use nix::unistd::{setpgid, Pid};

#[cfg(all(unix, not(target_os = "macos")))]
use crate::HostError;

#[cfg(all(unix, not(target_os = "macos")))]
const SHUTDOWN_GRACE: Duration = Duration::from_millis(250);
#[cfg(all(unix, not(target_os = "macos")))]
const OUTPUT_READ_CHUNK: usize = 4096;

/// 一个由 test-only runner 启动的插件 RPC 会话。
///
/// 会话持有子进程、所有标准 I/O 管道及空 cwd 的生命周期。每次调用以 manifest 声明的
/// runtime deadline 为上限；任一失败会 kill 整个 runner 进程组并回收所有 reader 线程。
#[cfg(all(unix, not(target_os = "macos")))]
pub struct PluginSession {
    child: Child,
    stdin: Option<ChildStdin>,
    events: Receiver<ProcessEvent>,
    readers: Vec<JoinHandle<()>>,
    limits: ResourceLimits,
    pending_frame: Option<RpcMessage>,
    closed: bool,
    _cwd: tempfile::TempDir,
}

#[cfg(all(unix, not(target_os = "macos")))]
impl PluginSession {
    pub(crate) fn spawn(
        runner: &Path,
        entrypoint: &Path,
        limits: ResourceLimits,
    ) -> Result<Self, HostError> {
        let cwd =
            tempfile::tempdir().map_err(|error| HostError::io("create_session_cwd", &error))?;
        let mut command = Command::new(runner);
        command
            .arg("--memory-bytes")
            .arg(limits.max_memory_bytes.to_string())
            .arg("--")
            .arg(entrypoint)
            .env_clear()
            .env("ENVSYNC_PLUGIN_PROTOCOL", "stdio-v1")
            .current_dir(cwd.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| HostError::io("spawn_runner", &error))?;
        if let Ok(raw_pid) = i32::try_from(child.id()) {
            let pid = Pid::from_raw(raw_pid);
            let _ = setpgid(pid, pid);
        }

        let (stdin, stdout, stderr) =
            match (child.stdin.take(), child.stdout.take(), child.stderr.take()) {
                (Some(stdin), Some(stdout), Some(stderr)) => (stdin, stdout, stderr),
                _ => {
                    terminate_child(&mut child);
                    return Err(HostError::Protocol);
                }
            };
        let budget = Arc::new(OutputBudget::new(limits.max_output_bytes));
        let (sender, events) = mpsc::sync_channel(4);
        let readers = vec![
            spawn_stdout_reader(stdout, Arc::clone(&budget), sender.clone()),
            spawn_stderr_reader(stderr, budget, sender),
        ];
        Ok(Self {
            child,
            stdin: Some(stdin),
            events,
            readers,
            limits,
            pending_frame: None,
            closed: false,
            _cwd: cwd,
        })
    }

    /// 写入一个 request，并在 manifest 的运行时限内读取 ID 完全相同的一条 response。
    pub fn call(&mut self, request: RpcRequest) -> Result<RpcResponse, HostError> {
        if self.closed {
            return Err(HostError::InvalidState);
        }
        let deadline =
            Instant::now() + Duration::from_millis(u64::from(self.limits.max_runtime_ms));
        self.write_request(RpcMessage::Request(request.clone()), deadline)?;
        self.read_response(&request, deadline)
    }

    /// 请求插件自行关闭，并在固定宽限期后回收整个进程组。
    pub fn shutdown(&mut self) -> Result<(), HostError> {
        if self.closed {
            return Ok(());
        }
        let request = RpcRequest::new(
            SchemaVersion::new(1, 0),
            RequestId::parse("shutdown").expect("固定 shutdown request ID 合法"),
            PluginMethod::Shutdown,
            serde_json::Value::Null,
        )
        .expect("固定 shutdown request 合法");
        match self.call(request) {
            Ok(_) if self.wait_for_exit(Instant::now() + SHUTDOWN_GRACE) => Ok(()),
            Ok(_) => {
                self.terminate();
                Err(HostError::ShutdownTimeout)
            }
            Err(HostError::Timeout) => Err(HostError::ShutdownTimeout),
            Err(error) => Err(error),
        }
    }

    fn write_request(&mut self, message: RpcMessage, deadline: Instant) -> Result<(), HostError> {
        let stdin = self.stdin.take().ok_or(HostError::InvalidState)?;
        let (completion_sender, completion) = mpsc::sync_channel(1);
        let writer = thread::spawn(move || {
            let mut stdin = stdin;
            let written = write_frame(&mut stdin, &message).is_ok() && stdin.flush().is_ok();
            let _ = completion_sender.send((stdin, written));
        });

        loop {
            match completion.try_recv() {
                Ok((stdin, true)) => {
                    self.stdin = Some(stdin);
                    let _ = writer.join();
                    return Ok(());
                }
                Ok((stdin, false)) => {
                    self.stdin = Some(stdin);
                    self.terminate();
                    let _ = writer.join();
                    return Err(HostError::ProcessExited);
                }
                Err(TryRecvError::Disconnected) => {
                    self.terminate();
                    let _ = writer.join();
                    return Err(HostError::ProcessExited);
                }
                Err(TryRecvError::Empty) => {}
            }
            match self.events.try_recv() {
                Ok(ProcessEvent::Frame(message)) if self.pending_frame.is_none() => {
                    self.pending_frame = Some(message);
                }
                Ok(ProcessEvent::Frame(_)) => {
                    self.terminate();
                    let _ = writer.join();
                    return Err(HostError::Protocol);
                }
                Ok(ProcessEvent::ProcessExited) if self.pending_frame.is_some() => {}
                Ok(event) => {
                    let error = event.error();
                    self.terminate();
                    let _ = writer.join();
                    return Err(error);
                }
                Err(TryRecvError::Disconnected) => {
                    self.terminate();
                    let _ = writer.join();
                    return Err(HostError::ProcessExited);
                }
                Err(TryRecvError::Empty) => {}
            }
            if Instant::now() >= deadline {
                self.terminate();
                let _ = writer.join();
                return Err(HostError::Timeout);
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn read_response(
        &mut self,
        request: &RpcRequest,
        deadline: Instant,
    ) -> Result<RpcResponse, HostError> {
        let now = Instant::now();
        if now >= deadline {
            return self.fail(HostError::Timeout);
        }
        if let Some(message) = self.pending_frame.take() {
            return self.validate_response(message, request);
        }
        match self
            .events
            .recv_timeout(deadline.saturating_duration_since(now))
        {
            Ok(ProcessEvent::Frame(message)) => self.validate_response(message, request),
            Ok(event) => self.fail(event.error()),
            Err(mpsc::RecvTimeoutError::Timeout) => self.fail(HostError::Timeout),
            Err(mpsc::RecvTimeoutError::Disconnected) => self.fail(HostError::ProcessExited),
        }
    }

    fn validate_response(
        &mut self,
        message: RpcMessage,
        request: &RpcRequest,
    ) -> Result<RpcResponse, HostError> {
        let Some(response) = message.response() else {
            return self.fail(HostError::Protocol);
        };
        if response.id() != request.id() {
            return self.fail(HostError::Protocol);
        }
        Ok(response.clone())
    }

    fn wait_for_exit(&mut self, deadline: Instant) -> bool {
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => {
                    self.terminate();
                    return true;
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
                Ok(None) | Err(_) => return false,
            }
        }
    }

    fn fail<T>(&mut self, error: HostError) -> Result<T, HostError> {
        self.terminate();
        Err(error)
    }

    fn terminate(&mut self) {
        if self.closed {
            return;
        }
        self.stdin.take();
        terminate_child(&mut self.child);
        self.closed = true;
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
impl Drop for PluginSession {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
enum ProcessEvent {
    Frame(RpcMessage),
    Protocol,
    OutputLimit,
    ProcessExited,
}

#[cfg(all(unix, not(target_os = "macos")))]
impl ProcessEvent {
    fn error(self) -> HostError {
        match self {
            Self::Frame(_) | Self::Protocol => HostError::Protocol,
            Self::OutputLimit => HostError::OutputLimit,
            Self::ProcessExited => HostError::ProcessExited,
        }
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
struct OutputBudget {
    limit: u64,
    consumed: AtomicU64,
    exceeded: AtomicBool,
}

#[cfg(all(unix, not(target_os = "macos")))]
impl OutputBudget {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            consumed: AtomicU64::new(0),
            exceeded: AtomicBool::new(false),
        }
    }

    fn consume(&self, bytes: usize) -> bool {
        let bytes = u64::try_from(bytes).expect("usize fits u64");
        loop {
            let consumed = self.consumed.load(Ordering::Acquire);
            let Some(updated) = consumed.checked_add(bytes) else {
                return false;
            };
            if updated > self.limit {
                return false;
            }
            if self
                .consumed
                .compare_exchange(consumed, updated, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    fn mark_exceeded(&self) {
        self.exceeded.store(true, Ordering::Release);
    }

    fn exceeded(&self) -> bool {
        self.exceeded.load(Ordering::Acquire)
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
struct BudgetedReader<R> {
    inner: R,
    budget: Arc<OutputBudget>,
}

#[cfg(all(unix, not(target_os = "macos")))]
impl<R> BudgetedReader<R> {
    fn new(inner: R, budget: Arc<OutputBudget>) -> Self {
        Self { inner, budget }
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
impl<R: Read> Read for BudgetedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let read = self
            .inner
            .read(&mut buffer[..buffer.len().min(OUTPUT_READ_CHUNK)])?;
        if read == 0 {
            return Ok(0);
        }
        if self.budget.consume(read) {
            Ok(read)
        } else {
            self.budget.mark_exceeded();
            Err(io::Error::other("plugin output limit"))
        }
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn spawn_stdout_reader(
    stdout: ChildStdout,
    budget: Arc<OutputBudget>,
    sender: SyncSender<ProcessEvent>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BudgetedReader::new(stdout, budget.clone());
        loop {
            match read_frame(&mut reader) {
                Ok(message) => {
                    if !send_event(&sender, ProcessEvent::Frame(message)) {
                        return;
                    }
                }
                Err(error) => {
                    let event = if budget.exceeded() {
                        ProcessEvent::OutputLimit
                    } else if matches!(error, PluginRpcError::TruncatedFrame) {
                        ProcessEvent::ProcessExited
                    } else {
                        ProcessEvent::Protocol
                    };
                    let _ = send_event(&sender, event);
                    return;
                }
            }
        }
    })
}

#[cfg(all(unix, not(target_os = "macos")))]
fn spawn_stderr_reader(
    stderr: ChildStderr,
    budget: Arc<OutputBudget>,
    sender: SyncSender<ProcessEvent>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BudgetedReader::new(stderr, budget.clone());
        let mut discard = [0_u8; 8192];
        loop {
            match reader.read(&mut discard) {
                Ok(0) => return,
                Ok(_) => {}
                Err(_) => {
                    let event = if budget.exceeded() {
                        ProcessEvent::OutputLimit
                    } else {
                        ProcessEvent::ProcessExited
                    };
                    let _ = send_event(&sender, event);
                    return;
                }
            }
        }
    })
}

#[cfg(all(unix, not(target_os = "macos")))]
fn send_event(sender: &SyncSender<ProcessEvent>, event: ProcessEvent) -> bool {
    sender.try_send(event).is_ok()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn terminate_child(child: &mut Child) {
    if let Ok(raw_pid) = i32::try_from(child.id()) {
        let _ = killpg(Pid::from_raw(raw_pid), Signal::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// macOS 和非 Unix 的 test-support 占位类型；无法创建或使用会话。
#[cfg(any(not(unix), target_os = "macos"))]
pub struct PluginSession {
    _private: (),
}
