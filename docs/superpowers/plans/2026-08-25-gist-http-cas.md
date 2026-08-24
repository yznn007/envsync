# GitHub Gist HTTP 传输与弱 CAS 实施计划

> **执行方式：** 当前工作区直接执行；不调用真实 GitHub，不读取或写入账号凭据。

**目标：** 在既有密封 `gist_bundle` 格式之上，交付一个同步的 GitHub Gist HTTP
传输层。它创建、读取和发布一个工作区的唯一密封文件，并用 ETag 加后读校验实现
“检测竞争的弱 CAS”；绝不声称 Gist 具备 `Backend` trait 所需的强 CAS。

**架构：** `crates/envsync-backend/src/gist.rs` 只传输 base64url 的 sealed bundle，不解密、
不访问 Vault、不写本地状态。调用方从 Vault 解析 `SecretRef` 后，把 `Plaintext` 和该
`SecretId` 一起构造成零化的 `GistCredentials`；后续 core 编排层再负责验签、解包和持久化。
因此本任务不改 `envsync-core` 的 `BackendConfig` 或通用 `Backend` trait：两者的对象级强
CAS 语义与 Gist 的单文件、服务端非原子更新模型不相容。

**技术栈：** `reqwest` blocking + rustls，`serde_json`，测试中的标准库 TCP mock。所有网络
操作都在单元/集成测试本地回环端口完成。

---

## Task 1: 先增加红灯测试与本地 GitHub mock

**文件：**

- 修改：`Cargo.toml`
- 修改：`crates/envsync-backend/Cargo.toml`
- 新建：`crates/envsync-backend/tests/support/mock_github.rs`
- 新建：`crates/envsync-backend/tests/gist_backend.rs`

1. 在工作区依赖声明 `reqwest = { version = "0.13", default-features = false, features =
   ["blocking", "json", "rustls"] }`，后端 crate 使用 workspace 依赖；保留现有
   `serde_json` workspace 版本。
2. 建立可脚本化的 `MockGithub`：在 `127.0.0.1:0` 监听、按顺序发出预设 HTTP 响应并记录
   每个请求的 method/path/header/body；支持断开连接、延迟响应和 raw 文件路径。mock 仅解析
   测试需要的 HTTP/1.1，不将 token 或完整 bundle 输出到失败信息。
3. 为一个合法的最小 bundle fixture 复用 `gist_bundle` 的 `pack`，构造 revision 1 与
   revision 2（不同 head）。测试绝不以伪造的明文字符串替代 bundle，以免绕过
   `inspect()` 的 wire-format 约束。
4. 先写以下失败测试：

   - `create_then_read_then_publish_sends_expected_contract`：`POST /gists` 的 body 为 secret
     （`public: false`）Gist、唯一 `envsync-<workspace>.bundle` 文件；secret Gist 不被索引或
     搜索，但 URL 持有者仍可读取；内容保密依赖 sealed bundle，不能把它作为访问控制。
     `GET /gists/<id>` 保存 ETag；`PATCH` 带
     `If-Match`，成功后再 `GET`，并且新 bundle bytes、revision 与 head 都一致。
   - `descriptor_explicitly_reports_weak_cas`：`kind == "gist"` 且
     `supports_strong_cas == false`。
   - `stale_or_old_verify_read_is_a_conflict_and_does_not_retry_patch`：PATCH 成功或 412 后的
     验证读取若仍是旧 revision/head（或不同 bundle bytes），返回 `gist.cas_conflict`，且
     mock 只看到一次 PATCH。
   - `unknown_patch_result_is_resolved_by_get_never_a_blind_patch_retry`：断线或 5xx 后先 GET；
     GET 已是候选 bytes 则成功，否则冲突；都不得追加 PATCH。
   - `read_maps_auth_forbidden_not_found_timeout_and_bounded_response_errors`：401、普通 403、404、
     socket timeout 和超过上限的 body 分别映射为稳定安全的错误码。
   - `read_uses_uncredentialed_allowed_raw_url_for_truncated_file`：`truncated: true` 时从
     `raw_url` 取完整文件；raw GET 不带 `Authorization`，非允许 host/scheme/query 的 raw URL
     被拒绝。
   - `only_get_is_rate_retried`：GET 的 429/`Retry-After` 经过注入的假 sleeper 后重试；POST/PATCH
     的限流直接返回，不会重放非幂等写。
   - `credentials_debug_errors_and_logs_are_redacted`：token、SecretId、API URL、错误 body 不出现在
     `Debug`/`Display` 或 tracing 记录中；可关联的日志字段只允许 GitHub request ID。

运行（应先失败）：

```bash
cargo test -p envsync-backend --test gist_backend
```

## Task 2: 建立受限的公开 API 与安全类型

**文件：**

- 新建：`crates/envsync-backend/src/gist.rs`
- 修改：`crates/envsync-backend/src/lib.rs`

1. 导出 `pub mod gist` 以及有限的公开类型：`GistBackend`、`GistCredentials`、`GistId`、
   `GistRevision`、`GistBundleRecord`、`GistError`。
2. `GistCredentials::from_vault(secret_ref: SecretId, plaintext: Plaintext)` 只接受 Vault 所用的
   敏感明文包装；拒绝空值、非 UTF-8、控制字符和超长 token，并将值保存在
   `Zeroizing<String>`。手写 `Debug`，两个字段都输出 `<redacted>`。
3. `GistId` 验证长度和 ASCII 标识符字符集；对外只提供 `as_str()` 供上层安全持久化，
   手写 `Debug` 为 `<redacted>`。ETag 同样只保留在私有 `GistRevision` 字段内。
4. `GistBundleRecord` 保存 encoded bundle 与 `GistRevision`；`Debug` 只显示未验证 header 的
   workspace/revision/head/epoch 和长度，绝不显示 bundle text、Gist ID 或 ETag。
5. `GistBackend::github()` 指向固定 `https://api.github.com/`；测试和 GitHub Enterprise 使用
   `with_api_base()`。只接受 HTTPS；仅当 host 是 loopback 时允许 HTTP，且拒绝 userinfo、
   query、fragment 与非绝对路径。客户端禁用自动 redirect，避免认证 header 跨 origin。
6. 暴露三个操作：

   ```rust
   create(&self, credentials: &GistCredentials, encoded: &str)
       -> Result<GistBundleRecord, GistError>;
   read(&self, credentials: &GistCredentials, gist: &GistId, workspace: WorkspaceId)
       -> Result<GistBundleRecord, GistError>;
   compare_and_swap(&self, credentials: &GistCredentials,
                    expected: &GistRevision, encoded: &str)
       -> Result<GistBundleRecord, GistError>;
   ```

   每次接受的 encoded 内容都先受 `gist_bundle::inspect()` 的大小、canonical 和 header 校验；
   `compare_and_swap` 还要求 workspace 不变、revision 恰好递增 1，并保存候选的完整 bytes
   用于后读判定。

## Task 3: 实现 HTTP 解析、限制与脱敏错误

**文件：**

- 修改：`crates/envsync-backend/src/gist.rs`
- 修改：`crates/envsync-backend/Cargo.toml`

1. 用 `Url::path_segments_mut()` 构造 `/gists` 和 `/gists/<id>`，不拼接 user 输入；客户端设置
   `reqwest::retry::never()`，先禁用 reqwest 对 protocol NACK 的隐式重放，再由本模块显式控制
   GET 重试；所有 API
   请求固定 `Accept: application/vnd.github+json`、`X-GitHub-Api-Version: 2022-11-28`、
   `User-Agent: envsync` 和 `Authorization: Bearer <vault token>`。
2. POST body 固定为 `public: false`（GitHub 的 secret Gist，而非访问控制）、
   稳定 description 与从已检查 header 派生的唯一文件名。
   POST 成功后只从结构化 JSON 取 id，返回由候选 bundle 构造的**待确认**记录；调用方须显式
   `read()` 取得 authoritative ETag、bundle bytes 和 header。这样 `create` 不会隐式增加一次
   GET，且未确认记录不得作为 `compare_and_swap` 的 expected revision。创建未知结果绝不重试。
3. 读取 JSON 时最多读取 `MAX_ENCODED_BUNDLE_LEN + 128 KiB`；只从预期文件名取 `content`。
   `truncated: false` 但 content 缺失、文件不存在、非 UTF-8、超过 bundle 上限或结构不合法
   都返回不回显正文的安全错误。
4. `truncated: true` 时解析 `raw_url`，仅允许与 API 同 origin 的 Enterprise/回环地址，或默认
   GitHub 的 `https://gist.githubusercontent.com`；禁止 userinfo/query/fragment，raw GET 不带
   token、不跟随 redirect，并使用同一大小上限和 `inspect()` 校验。
5. 在每个响应中抽取可选 `X-GitHub-Request-Id`；tracing 只写这一字段。`GistError` 保存的
   operation 为静态字符串、status、有限 observed revision 与 request id，绝不保存 URL、
   request/response header、token 或 response body。
6. 401→`gist.authentication`、非限流 403→`gist.forbidden`、404→`gist.not_found`、超时→
   `gist.timeout`、大 body→`gist.response_too_large`，其余 status→`gist.http_status`。为每种
   错误实现稳定 `code()`。

## Task 4: 先补弱 CAS、限流与不确定结果的红灯合约

**文件：**

- 修改：`crates/envsync-backend/tests/gist_backend.rs`

1. 在不改生产实现的前提下，为 `compare_and_swap()` 增加本地 mock 合约：成功 PATCH 后必须
   GET 验证且返回新 ETag；PATCH 返回 412、断线或 5xx 后均只能 GET 一次；验证读到候选的
   **完整相同 bytes** 时成功，读到旧/其他 bundle 时为 `gist.cas_conflict`，验证请求本身失败
   时为 `gist.update_outcome_unknown`。每个失败路径都断言 PATCH 恰好一次，绝不盲重发。
2. 增加 GET 429 + `Retry-After: 0` 后重试一次的合约；零延迟确保红灯测试不真实 sleep。
   增加 POST 429 和 PATCH 429 合约，二者必须返回 `gist.rate_limited` 且不重放写请求。
3. 覆盖 PATCH 的 `If-Match`、secret（`public: false`）单文件 body、验证读得到的新 ETag，以及错误 `Debug`/
   `Display` 不回显 mock 的 response body、URL 或 token。测试只使用 `MockGithub` 的回环端口。
4. 运行 `cargo test -p envsync-backend --test gist_backend`，记录当前预期红灯；测试不得用
   `#[ignore]`、sleep、真实 GitHub 或伪造 bundle 绕过 `gist_bundle::inspect()`。

## Task 5: 实现弱 CAS 与受控重试

**文件：**

- 修改：`crates/envsync-backend/src/gist.rs`

1. `read()` 在成功响应中保存 ETag；缺少 ETag 返回 `gist.missing_etag`，不能把无版本读取带入
   发布流程。
2. `compare_and_swap()` 仅发送一次 `PATCH /gists/<id>`，body 替换唯一文件，header 带
   `If-Match: <expected ETag>`。无论 PATCH 返回 2xx、412、连接错误或 5xx 的不确定结果，
   都只做一次 `GET`：

   - 已读到候选 bundle 的完全相同 bytes，返回新的 `GistBundleRecord`；
   - 读到其他 bytes/revision/head，返回 `GistError::CasConflict { expected, observed }`；
   - 无法判定，返回 `gist.update_outcome_unknown`，绝不重发 PATCH。

   这样 ETag 只是降低竞争窗口，后读的实际 bundle 才是成功条件；`descriptor()` 明确报告
   `supports_strong_cas: false`。
3. 抽出内部 `Sleeper`，生产实现调用 `thread::sleep`，测试注入记录 duration 的假实现。
   仅 `GET` 可对 429 或带 `Retry-After`/`X-RateLimit-Remaining: 0` 的限流响应重试，最多两次；
   优先 `Retry-After`，其次 `X-RateLimit-Reset`，不确定或超出 60 秒时返回
   `gist.rate_limited` 让调度层稍后再试。POST/PATCH 永不自动重试。实现时用内部单元测试
   向 Sleeper 注入记录 duration 的 fake，避免集成测试依赖真实等待。
4. 让 Task 4 的全部合约转绿；失败没有任何 `GistBackend` 内部可变缓存可被误当成已发布状态。
   一并修正 Task 3 遗留的 `create` 过时注释。

## Task 6: 更新文档、运行全量门禁并提交

**文件：**

- 修改：`docs/backends/gist.md`
- 修改：`docs/superpowers/plans/2026-07-24-envsync-m4-desktop-gist-plugins.md`

1. 在 Gist 文档增加“HTTP 与凭据”章节：fine-grained token 只需 Gists write、token 用
   Vault `SecretRef` 注入、Gist 永远是 secret（`public: false`，不被索引或搜索但不构成访问
   控制）、5 MiB bundle 与截断 raw 读取策略、ETag 是弱 CAS、冲突必须由上层重新同步解决。
   记录不进行真实 GitHub 调用的测试边界。
2. 将 M4 Task 8 的检查项标为完成，并说明它不接入通用 `Backend` trait 的原因。
3. 运行：

   ```bash
   cargo fmt --check
   cargo test -p envsync-backend --test gist_backend
   cargo test -p envsync-backend --test gist_bundle
   cargo test --workspace -q
   cargo clippy --workspace --all-targets -- -D warnings
   git diff --check
   ```

4. 检查工作树，只暂存本任务相关文件，提交：

   ```bash
   git commit -m "feat(backend): 添加 GitHub Gist 后端"
   ```

## 参考

- GitHub Gist API 的 create/read/update、token scope 与 1 MiB `content` 截断规则：
  https://docs.github.com/en/rest/gists/gists
- GitHub REST 的条件读取、rate limit header 和 `Retry-After` 处理：
  https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api
