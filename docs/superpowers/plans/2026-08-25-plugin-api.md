# Plugin API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** 交付 envsync-plugin-api，以严格校验的插件 manifest 和长度前缀、版本化 JSON-RPC 作为第三方插件与隔离 Host 之间的唯一数据边界。

**Architecture:** 新 crate 只依赖 serde、semver、base64 和标准 I/O；它不启动插件、不读取路径、不验证 publisher trust，也不接触 Vault。manifest.rs 负责不可信安装元数据的类型化校验与确定性签名 payload，rpc.rs 负责 8 MiB 上限的帧编解码、协议版本与封闭方法集合；Task 10 使用这些已校验值执行隔离、验签、quarantine 和 capability 再授权。

**Tech Stack:** Rust 2021、serde/serde_json、semver、base64、thiserror、标准库 Read/Write。

---

## 文件结构

- Cargo.toml：将 API crate 加入 workspace，复用统一依赖版本。
- crates/envsync-plugin-api/Cargo.toml：最小独立 crate，不依赖 core、platform、storage 或 adapters。
- crates/envsync-plugin-api/src/lib.rs：crate lint、模块入口和稳定 re-export。
- crates/envsync-plugin-api/src/manifest.rs：manifest 值对象、解析、校验、签名 payload 与安全错误码。
- crates/envsync-plugin-api/src/rpc.rs：协议版本、请求 ID、封闭方法、JSON-RPC 消息与 frame I/O。
- crates/envsync-plugin-api/tests/compatibility.rs：manifest 拒绝清单、协议兼容性和 byte-level golden frame。
- crates/envsync-plugin-api/tests/fixtures/initialize-request-v1.0.json：固定初始化请求 payload。
- crates/envsync-plugin-api/tests/fixtures/describe-response-v1.1.json：固定 describe 成功响应。

### Task 1: 建立并实现 manifest（原 M4 Task 1/2 合并为一个原子 TDD 任务）

**Files:**

- Modify: Cargo.toml
- Create: crates/envsync-plugin-api/Cargo.toml
- Create: crates/envsync-plugin-api/src/lib.rs
- Create: crates/envsync-plugin-api/tests/compatibility.rs

- [ ] **Step 1: 建立最小可编译 crate 骨架并把它加入 workspace**

在根 Cargo.toml 的 members 中加入 crates/envsync-plugin-api。创建以下 manifest，依赖只能是协议和校验所需的库：

~~~toml
[package]
name = "envsync-plugin-api"
description = "EnvSync 插件 manifest 与版本化 RPC 契约"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true

[dependencies]
base64.workspace = true
semver.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
~~~

创建暂时只声明模块的 src/lib.rs：

~~~rust
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod manifest;
~~~

- [ ] **Step 2: 写 manifest 失败测试与可复用合法 fixture**

在 tests/compatibility.rs 中先引入还不存在的 PluginManifest、PluginCatalog 和 PluginManifestError，以及 `use base64::Engine;`，并提供一个完整的合法 JSON：

~~~rust
fn valid_manifest_json() -> serde_json::Value {
    serde_json::json!({
        "id": "com.example.calendar",
        "version": "1.2.0",
        "publisher": {
            "id": "com.example",
            "public_key": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
        },
        "api": ">=1.0.0, <2.0.0",
        "entrypoint": "bin/plugin",
        "targets": ["linux"],
        "capabilities": ["observe", "render"],
        "limits": {
            "max_runtime_ms": 5000,
            "max_memory_bytes": 67_108_864,
            "max_output_bytes": 1_048_576,
        },
        "signature": {
            "algorithm": "ed25519",
            "value": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 64]),
        },
    })
}

#[test]
fn manifest_rejects_unsafe_entrypoints_unknown_capabilities_and_incompatible_api() {
    for (field, value, code) in [
        ("entrypoint", serde_json::json!("/etc/passwd"), "plugin.manifest.invalid_entrypoint"),
        ("entrypoint", serde_json::json!("bin/../escape"), "plugin.manifest.invalid_entrypoint"),
        ("capabilities", serde_json::json!(["observe", "network.raw"]), "plugin.manifest.unknown_capability"),
        ("api", serde_json::json!("^2.0.0"), "plugin.manifest.incompatible_api"),
    ] {
        let mut json = valid_manifest_json();
        json[field] = value;
        let error = PluginManifest::from_json_value(json).expect_err("必须拒绝不可信 manifest");
        assert_eq!(error.code(), code);
    }
}

#[test]
fn catalog_rejects_duplicate_normalized_plugin_ids() {
    let first = PluginManifest::from_json_value(valid_manifest_json()).expect("合法 manifest");
    let second = PluginManifest::from_json_value(valid_manifest_json()).expect("合法 manifest");
    let error = PluginCatalog::new(vec![first, second]).expect_err("同 ID 不能同时安装");
    assert_eq!(error.code(), "plugin.manifest.duplicate_id");
}
~~~

补充独立断言：合法 manifest 可读取 ID、版本、entrypoint 与 signing payload；非法 semver、零值/越界 resource limit、错误长度的 public key/signature、空 target 与 Windows 盘符均有稳定 error code。

- [ ] **Step 3: 运行红灯测试**

运行：

~~~bash
cargo test -p envsync-plugin-api --test compatibility
~~~

预期：编译失败，提示 manifest 模块或 PluginManifest 尚未定义；不得以 ignore、空断言或放宽测试绕过。

- [ ] **Step 4: 保留红灯状态，不单独提交无法编译的 workspace**

不要提交此时的红灯骨架。立即继续本任务的实现步骤，使最终 commit 始终保持 workspace 可编译、可测试；红灯命令与失败原因记入实现报告即可。

#### 后续步骤：实现严格 manifest 值对象与签名 payload

**Files:**

- Create: crates/envsync-plugin-api/src/manifest.rs
- Modify: crates/envsync-plugin-api/src/lib.rs
- Modify: crates/envsync-plugin-api/tests/compatibility.rs

- [ ] **Step 1: 定义公开类型与稳定错误码**

在 manifest.rs 定义并文档化以下接口：

~~~rust
pub const HOST_PLUGIN_API_VERSIONS: [semver::Version; 2] = [
    semver::Version::new(1, 0, 0),
    semver::Version::new(1, 1, 0),
];

pub struct PluginManifest {
    id: PluginId,
    version: semver::Version,
    publisher: Publisher,
    api: semver::VersionReq,
    entrypoint: PluginEntrypoint,
    targets: std::collections::BTreeSet<PluginTarget>,
    capabilities: std::collections::BTreeSet<PluginCapability>,
    limits: ResourceLimits,
    signature: PluginSignature,
}
pub struct PluginCatalog {
    by_id: std::collections::BTreeMap<PluginId, PluginManifest>,
}
pub struct PluginId(String);
pub struct Publisher { pub id: String, pub public_key: [u8; 32] }
pub struct PluginEntrypoint(String);
pub struct PluginSignature { pub algorithm: SignatureAlgorithm, pub value: [u8; 64] }
pub enum SignatureAlgorithm { Ed25519 }
pub enum PluginTarget { Macos, Windows, Linux, WasiP2 }
pub enum PluginCapability { Observe, Render, PlanCommand, Verify }
pub struct ResourceLimits {
    pub max_runtime_ms: u32,
    pub max_memory_bytes: u64,
    pub max_output_bytes: u64,
}
#[non_exhaustive]
pub enum PluginManifestError {
    InvalidId, InvalidSemver, InvalidEntrypoint, DuplicateId, UnknownCapability,
    IncompatibleApi, InvalidLimit, InvalidSignature, InvalidTarget,
}
~~~

实现 PluginManifestError::code()，至少包括 plugin.manifest.invalid_id、invalid_semver、invalid_entrypoint、duplicate_id、unknown_capability、incompatible_api、invalid_limit、invalid_signature 与 invalid_target。每个 Display 只说明字段和结构原因，不能回显 signature 或完整输入 JSON。

- [ ] **Step 2: 实现 ID、entrypoint、版本、capability 与限制校验**

实现 PluginId::parse 和 PluginEntrypoint::parse。路径检查必须逐段扫描，不能依赖当前平台的 Path 行为：拒绝空串、/ 开头、反斜杠、NUL、冒号、.、.. 与空段；仅允许由普通段通过 / 连接的相对路径。PluginManifest::from_json_value 必须先反序列化为私有 Raw 类型，再逐字段构造值对象，不能让未验证 String 进入公开结构。

限制常量为：

~~~rust
const MIN_RUNTIME_MS: u32 = 100;
const MAX_RUNTIME_MS: u32 = 30_000;
const MIN_MEMORY_BYTES: u64 = 1024 * 1024;
const MAX_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
const MIN_OUTPUT_BYTES: u64 = 1024;
pub const MAX_RPC_FRAME_BYTES: usize = 8 * 1024 * 1024;
~~~

capabilities 和 targets 反序列化为封闭 enum；空 target/capability 集合或重复项目均拒绝。api 用 semver::VersionReq 解析，并要求至少匹配 HOST_PLUGIN_API_VERSIONS 中一个版本。

- [ ] **Step 3: 实现 publisher/signature 与确定性 payload**

对 publisher.public_key 与 signature.value 使用 URL_SAFE_NO_PAD base64url 解码并严格要求 32/64 字节。PluginManifest::signing_payload() 构造一个不含 signature 的私有 UnsignedManifest，所有集合用 BTreeSet、字段以声明顺序由 serde_json::to_vec 输出。它返回 JSON bytes，供 Host 在固定插件签名 domain 下验签；本 crate 不调用 crypto verifier。

PluginCatalog::new 将已验证 manifest 的 PluginId 放入 BTreeMap，第二次插入同 ID 返回 duplicate_id，禁止后者覆盖前者。

- [ ] **Step 4: 导出 API 并让 manifest 测试转绿**

在 lib.rs re-export：

~~~rust
pub use manifest::{
    PluginCapability, PluginCatalog, PluginEntrypoint, PluginId, PluginManifest,
    PluginManifestError, PluginSignature, PluginTarget, Publisher, ResourceLimits,
    SignatureAlgorithm, HOST_PLUGIN_API_VERSIONS,
};
~~~

运行：

~~~bash
cargo fmt --all --check
cargo test -p envsync-plugin-api --test compatibility manifest_
cargo clippy -p envsync-plugin-api --all-targets -- -D warnings
~~~

预期：所有 manifest 合约通过，Clippy 无 warning。

- [ ] **Step 5: 提交 manifest 实现**

~~~bash
git add Cargo.toml crates/envsync-plugin-api
git commit -m "feat(plugins): 定义严格插件 manifest"
~~~

### Task 2: 添加并实现版本化 RPC（原 M4 Task 3/4 合并为一个原子 TDD 任务）

**Files:**

- Modify: crates/envsync-plugin-api/src/lib.rs
- Modify: crates/envsync-plugin-api/tests/compatibility.rs
- Create: crates/envsync-plugin-api/tests/fixtures/initialize-request-v1.0.json
- Create: crates/envsync-plugin-api/tests/fixtures/describe-response-v1.1.json

- [ ] **Step 1: 写固定 JSON fixture**

initialize-request-v1.0.json 必须是：

~~~json
{"jsonrpc":"2.0","schema_version":{"major":1,"minor":0},"id":"request-0001","method":"initialize","params":{"supported_minors":[0,1]}}
~~~

describe-response-v1.1.json 必须是：

~~~json
{"jsonrpc":"2.0","schema_version":{"major":1,"minor":1},"id":"request-0001","result":{"name":"calendar"}}
~~~

- [ ] **Step 2: 写 frame 与兼容性红灯合约**

扩展 compatibility.rs，导入未来的 decode_frame、encode_frame、read_frame、write_frame、PluginMethod、PluginRpcError、RpcMessage、SchemaVersion 与 MAX_RPC_FRAME_BYTES。至少写入：

~~~rust
#[test]
fn golden_initialize_frame_is_length_prefixed_and_round_trips() {
    let json = include_bytes!("fixtures/initialize-request-v1.0.json");
    let message = RpcMessage::from_json_slice(json).expect("fixture 合法");
    let frame = encode_frame(&message).expect("可编码");
    assert_eq!(&frame[..4], &(json.len() as u32).to_be_bytes());
    let decoded = decode_frame(&frame).expect("frame 可读");
    assert_eq!(decoded.request().expect("request").method(), PluginMethod::Initialize);
    assert_eq!(decoded.schema_version(), SchemaVersion::new(1, 0));
}

#[test]
fn supported_minors_ignore_extensions_but_unknown_methods_and_versions_fail() {
    let mut value: serde_json::Value = serde_json::from_slice(
        include_bytes!("fixtures/describe-response-v1.1.json"),
    ).expect("fixture JSON");
    value["future_extension"] = serde_json::json!({"safe": true});
    assert!(RpcMessage::from_json_value(value).is_ok());

    for (method, version, code) in [
        ("erase-everything", serde_json::json!({"major": 1, "minor": 1}), "plugin.rpc.unknown_method"),
        ("describe", serde_json::json!({"major": 2, "minor": 0}), "plugin.rpc.unsupported_version"),
        ("describe", serde_json::json!({"major": 1, "minor": 2}), "plugin.rpc.unsupported_version"),
    ] {
        let request = request_json(method, version);
        assert_eq!(RpcMessage::from_json_value(request).unwrap_err().code(), code);
    }
}
~~~

添加长度安全测试：仅放入 MAX_RPC_FRAME_BYTES + 1 的 4 字节 prefix 而不分配大 body，断言在读取 body 前返回 plugin.rpc.frame_too_large；分别断言 truncated prefix/body、非 UTF-8、错误 jsonrpc、缺失 ID、batch array、同时含 result/error、两个响应字段均缺失与尾随 bytes。

- [ ] **Step 3: 运行红灯测试**

~~~bash
cargo test -p envsync-plugin-api --test compatibility golden_
~~~

预期：无法解析 RPC API 或断言失败；不得在测试中使用真实子进程、sleep 或超过上限的实际 8 MiB 分配。

- [ ] **Step 4: 保留红灯状态，不单独提交不完整协议**

不要在缺少 rpc.rs 的状态下提交。继续同一任务的实现步骤，在最终 green gate 后一次提交完整协议。

#### 后续步骤：实现帧编解码、版本策略与完整验证

**Files:**

- Create: crates/envsync-plugin-api/src/rpc.rs
- Modify: crates/envsync-plugin-api/src/lib.rs（在 rpc.rs 完整实现后才加入 pub mod rpc）
- Modify: crates/envsync-plugin-api/tests/compatibility.rs

- [ ] **Step 1: 定义封闭协议模型**

在 rpc.rs 定义并文档化：

~~~rust
pub const MAX_RPC_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const SUPPORTED_SCHEMA_MAJOR: u16 = 1;
pub const MIN_SUPPORTED_SCHEMA_MINOR: u16 = 0;
pub const MAX_SUPPORTED_SCHEMA_MINOR: u16 = 1;

pub struct SchemaVersion { pub major: u16, pub minor: u16 }
pub struct RequestId(String);
pub enum PluginMethod { Initialize, Describe, Observe, Render, PlanCommand, Verify, Shutdown }
pub struct RpcRequest {
    schema_version: SchemaVersion,
    id: RequestId,
    method: PluginMethod,
    params: serde_json::Value,
}
pub struct RpcResponse {
    schema_version: SchemaVersion,
    id: RequestId,
    result: Result<serde_json::Value, RpcErrorObject>,
}
pub enum RpcMessage { Request(RpcRequest), Response(RpcResponse) }
pub struct RpcErrorObject { pub code: String, pub message: String, pub data: Option<serde_json::Value> }
#[non_exhaustive]
pub enum PluginRpcError {
    FrameTooLarge, TruncatedFrame, LengthMismatch, InvalidUtf8, InvalidJson,
    InvalidRequest, UnsupportedVersion, UnknownMethod, InvalidResponse,
}
~~~

SchemaVersion::validate_supported 只接受 (1, 0) 和 (1, 1)。RequestId::parse 仅接受 1..=64 字节 ASCII 字母、数字、- 与 _；拒绝空、空白、NUL 和任意 JSON number/null ID。PluginMethod 用精确字符串映射，未知值不应落入 Other(String) 变体。

- [ ] **Step 2: 实现 JSON shape 校验与 minor 兼容规则**

先将输入 parse 为 serde_json::Value，拒绝顶层 array。验证 jsonrpc == "2.0"、schema_version、id 和 request/response 的互斥字段，再将已验证字段反序列化到私有 Raw 结构；不能在 serde untagged 的宽松分支中把 request 错当 response。

有 method 时只能是 request；没有 method 时必须有且仅有 result 或 error。版本校验通过后忽略顶层未知 extension fields；未知 method 和未支持 major/minor 仍立即失败。通用 response 只校验 envelope；Host 按 request ID 将 initialize response 关联回 initialize request 后，使用公开的 parse_initialize_result helper 检查 selected_schema_version 属于支持集合。任何 params、result 或 error.data 保持 serde_json::Value，不执行路径、命令或 env 解释。

- [ ] **Step 3: 实现 bounded frame I/O**

实现：

~~~rust
pub fn encode_frame(message: &RpcMessage) -> Result<Vec<u8>, PluginRpcError>;
pub fn decode_frame(frame: &[u8]) -> Result<RpcMessage, PluginRpcError>;
pub fn parse_initialize_result(result: &serde_json::Value)
    -> Result<SchemaVersion, PluginRpcError>;
impl RpcMessage {
    pub fn from_json_slice(json: &[u8]) -> Result<Self, PluginRpcError>;
    pub fn from_json_value(value: serde_json::Value) -> Result<Self, PluginRpcError>;
}
pub fn read_frame<R: std::io::Read>(reader: &mut R) -> Result<RpcMessage, PluginRpcError>;
pub fn write_frame<W: std::io::Write>(
    writer: &mut W,
    message: &RpcMessage,
) -> Result<(), PluginRpcError>;
~~~

encode_frame 对 serde_json::to_vec 的结果检查 <= MAX_RPC_FRAME_BYTES，使用 u32::to_be_bytes 写 4 字节前缀；read_frame 先 read_exact 4 字节，转换为 usize 后检查上限，再分配精确大小 Vec 并 read_exact；decode_frame 要求 slice 恰为 4 + declared_len，多一个字节也拒绝。所有 std::io::Error 只映射为分类错误，不把底层任意文本、路径或 payload 传入 Display。

- [ ] **Step 4: 导出 API、运行完整 crate 门禁**

在 lib.rs re-export manifest 与 RPC 的全部公共类型、四个 frame 函数与 parse_initialize_result。补齐 fixture 断言：1.0/1.1 的 frame round-trip、支持 minor 的 extension 忽略、未知 method/version 拒绝、frame 长度安全、response 异或条件、write/read round-trip，以及关联后的 initialize result 版本检查。

~~~bash
cargo fmt --all --check
cargo test -p envsync-plugin-api
cargo clippy -p envsync-plugin-api --all-targets -- -D warnings
git diff --check
~~~

预期：全部 exit 0，compatibility 测试不启动子进程、网络或真实插件。

- [ ] **Step 5: 提交完整插件 API**

~~~bash
git add Cargo.toml crates/envsync-plugin-api
git commit -m "feat(plugins): 定义插件 manifest 与 RPC"
~~~

## 计划自检

- M4 Task 9 的 manifest 字段、绝对/穿越 entrypoint、重复 ID、未知 capability、不兼容 API、资源限制与签名均映射到 Task 1。
- 长度前缀 JSON-RPC、七个封闭方法、schema version、request ID、8 MiB 上限、两个 minor、未知字段与未知 method/version 的差异均映射到 Task 2。
- Task 10 的隔离/授权职责明确不在本 crate，避免本计划错误扩大为进程 Host 实现。
- 本文每一步均有明确实现与验证内容；所有新公开类型均在 Task 1 或 Task 2 定义，并且所有测试命令有明确通过条件。
