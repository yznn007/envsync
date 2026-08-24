use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct RequestRecord {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl RequestRecord {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

impl fmt::Debug for RequestRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_names: Vec<&str> = self.headers.keys().map(|name| name.as_str()).collect();
        f.debug_struct("RequestRecord")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("headers", &header_names)
            .field("body_len", &self.body.len())
            .finish()
    }
}

#[derive(Clone)]
pub enum ResponseBody {
    Empty,
    Bytes(Vec<u8>),
    File(PathBuf),
}

impl fmt::Debug for ResponseBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("ResponseBody::Empty"),
            Self::Bytes(bytes) => f
                .debug_tuple("ResponseBody::Bytes")
                .field(&format_args!("<{} bytes>", bytes.len()))
                .finish(),
            Self::File(_) => f
                .debug_tuple("ResponseBody::File")
                .field(&"<redacted path>")
                .finish(),
        }
    }
}

impl ResponseBody {
    pub fn bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(bytes.into())
    }

    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self::File(path.into())
    }

    fn into_bytes(self) -> io::Result<Vec<u8>> {
        match self {
            ResponseBody::Empty => Ok(Vec::new()),
            ResponseBody::Bytes(bytes) => Ok(bytes),
            ResponseBody::File(path) => fs::read(path),
        }
    }
}

#[derive(Clone)]
pub struct ResponseSpec {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: ResponseBody,
    pub delay: Option<Duration>,
    pub disconnect: bool,
}

impl fmt::Debug for ResponseSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_names: Vec<&str> = self.headers.keys().map(|name| name.as_str()).collect();
        f.debug_struct("ResponseSpec")
            .field("status", &self.status)
            .field("headers", &header_names)
            .field("body", &self.body)
            .field("delay", &self.delay)
            .field("disconnect", &self.disconnect)
            .finish()
    }
}

impl ResponseSpec {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: BTreeMap::new(),
            body: ResponseBody::Empty,
            delay: None,
            disconnect: false,
        }
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .insert(name.into().to_ascii_lowercase(), value.into());
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = ResponseBody::bytes(body);
        self
    }

    pub fn body_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.body = ResponseBody::file(path);
        self
    }

    pub fn delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    pub fn disconnect(mut self) -> Self {
        self.disconnect = true;
        self
    }
}

pub struct MockGithub {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<RequestRecord>>>,
    responses: Arc<Mutex<VecDeque<ResponseSpec>>>,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MockGithub {
    pub fn start() -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let responses = Arc::new(Mutex::new(VecDeque::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let thread_requests = Arc::clone(&requests);
        let thread_responses = Arc::clone(&responses);
        let thread_shutdown = Arc::clone(&shutdown);

        let handle = thread::spawn(move || {
            while !thread_shutdown.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let request = match read_request(&mut stream) {
                            Ok(request) => request,
                            Err(_) => continue,
                        };
                        thread_requests.lock().expect("request log").push(request);

                        let response = thread_responses
                            .lock()
                            .expect("response queue")
                            .pop_front()
                            .unwrap_or_else(|| ResponseSpec::new(500));

                        if let Some(delay) = response.delay {
                            thread::sleep(delay);
                        }

                        if response.disconnect {
                            let _ = stream.shutdown(Shutdown::Both);
                            continue;
                        }

                        let (status, body) = match response.body.into_bytes() {
                            Ok(body) => (response.status, body),
                            Err(_) => (500, Vec::new()),
                        };
                        let _ = write_response(&mut stream, status, &response.headers, &body);
                        let _ = stream.flush();
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            addr,
            requests,
            responses,
            shutdown,
            handle: Some(handle),
        })
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn enqueue(&self, response: ResponseSpec) {
        self.responses
            .lock()
            .expect("response queue")
            .push_back(response);
    }

    pub fn requests(&self) -> Vec<RequestRecord> {
        self.requests.lock().expect("request log").clone()
    }

    pub fn wait_for_requests(&self, expected: usize, timeout: Duration) -> Vec<RequestRecord> {
        let deadline = Instant::now() + timeout;
        loop {
            let snapshot = self.requests();
            if snapshot.len() >= expected {
                return snapshot;
            }
            if Instant::now() >= deadline {
                return snapshot;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for MockGithub {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> io::Result<RequestRecord> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if find_header_end(&buffer).is_some() {
            break;
        }
        if buffer.len() > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request headers too large",
            ));
        }
    }

    let header_end = match find_header_end(&buffer) {
        Some(end) => end,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "missing request headers",
            ))
        }
    };
    let head = &buffer[..header_end];
    let body_start = header_end + 4;

    let mut lines = head.split(|byte| *byte == b'\n');
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request line"))?;
    let request_line = trim_cr(request_line);
    let request_line = String::from_utf8(request_line.to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request line is not utf-8"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing method"))?;
    let path = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing path"))?;

    let mut headers = BTreeMap::new();
    for line in lines {
        let line = trim_cr(line);
        if line.is_empty() {
            continue;
        }
        let line = String::from_utf8(line.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "header is not utf-8"))?;
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }

    let mut body = buffer[body_start..].to_vec();
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    while body.len() < content_length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);

    Ok(RequestRecord {
        method: method.to_owned(),
        path: path.to_owned(),
        headers,
        body,
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn trim_cr(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(b"\r").unwrap_or(bytes)
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    headers: &BTreeMap<String, String>,
    body: &[u8],
) -> io::Result<()> {
    let mut response = Vec::new();
    response
        .extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status, status_text(status)).as_bytes());
    response.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    response.extend_from_slice(b"connection: close\r\n");
    for (name, value) in headers {
        response.extend_from_slice(name.as_bytes());
        response.extend_from_slice(b": ");
        response.extend_from_slice(value.as_bytes());
        response.extend_from_slice(b"\r\n");
    }
    response.extend_from_slice(b"\r\n");
    response.extend_from_slice(body);
    stream.write_all(&response)
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        412 => "Precondition Failed",
        _ => "OK",
    }
}
