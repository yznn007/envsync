# Task 3 报告：Gist HTTP 创建、读取、响应边界与安全错误

## 范围

仅修改以下生产文件：

- `crates/envsync-backend/src/gist.rs`
- `crates/envsync-backend/Cargo.toml`

并新增本报告。工作树原有的 `docs/superpowers/plans/2026-08-25-gist-http-cas.md` 改动未读取进暂存区、未被修改。

## 实现

- 将 `serde_json` 从 dev-dependency 移至常规 dependency。
- `create` 先 `inspect()` 候选 Bundle，以 `Url::path_segments_mut()` 创建 `POST /gists`，发送 private、固定描述和唯一 workspace 文件名的 JSON。成功时只解析响应 `id`，返回携带候选 bytes/header、私有 ETag 为 `None` 的待确认记录；不发出内部读取、也不重试。
- `read` 以 `GET /gists/<id>` 读取目标文件，要求 authoritative ETag，按预期唯一文件名解析 JSON，并在 `inspect()` 后校验 workspace。
- 所有 API 请求固定发送 GitHub Accept/API version/User-Agent/Authorization header；客户端禁用 redirect 和 reqwest 自动重试。Task 4 才实现限流下的显式 GET 重试与 CAS PATCH。
- 每个响应先提取并有界保存 `X-GitHub-Request-Id`，tracing 只记录该字段。错误仅保存静态 operation、status、有限 revision 数值槽和有界 request id；`Display`/`Debug` 不回显 URL、token、header 或 body。
- JSON 与 raw body 均先检查 `Content-Length`，再通过 `Read::take(limit + 1)` 有界读取；上限为 `MAX_ENCODED_BUNDLE_LEN + 128 KiB`。原始 Bundle 文本超过自身 5 MiB 上限也被拒绝。
- `truncated: true` 仅接受 Enterprise/loopback API 同 origin，或公共 GitHub 的 `https://gist.githubusercontent.com`；拒绝 userinfo、query、fragment。raw GET 不带 Authorization，沿用禁重定向客户端。
- 增加安全且稳定的错误映射：认证、禁止、未找到、限流、超时、传输、HTTP 状态、响应过大、无效响应、缺 ETag、无效 raw URL、待确认 revision 等。
- `compare_and_swap` 保留既有本地 Bundle/workspace/revision 校验与 `gist.not_implemented`，并额外拒绝没有 ETag 的待确认 revision（`gist.unconfirmed_revision`）。

## 设计要点

创建结果不被当作已读取版本：POST 返回的 Gist ID 可以用于调用方显式 GET，但不能用于 CAS。这样避免 create 隐式请求、也避免将没有 authoritative ETag 的远端状态发布出去。

远端正文、URL、认证材料和完整 headers 都不进入错误对象的可渲染路径。仅有 GitHub request id 被接受为可关联信息，且长度限制为 256 个可打印 ASCII 字符。

## 验证命令与输出

### `cargo fmt --check`

退出码：`0`。

### `cargo test -p envsync-backend --lib`

退出码：`0`。

```text
running 16 tests
test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### `cargo test -p envsync-backend --test gist_backend`

退出码：`101`。

```text
running 11 tests
9 passed; 2 failed

create_then_read_then_publish_sends_expected_contract
  发布新版 bundle: GistError { code: "gist.not_implemented" }

old_verify_read_after_patch_is_a_cas_conflict_without_patch_retry
  断言预期 gist.cas_conflict 失败
```

其余 9 个集成测试均通过，包括认证/禁止/不存在映射、缺 ETag、超时、前置 Content-Length 拒绝、真正的有界读取、raw URL allow-list、raw 无 Authorization 与错误脱敏。两项失败均要求 Task 4 的 PATCH、读后验证和 `gist.cas_conflict`，按任务限制未实现。

### 自审

`git diff --check` 退出码为 `0`。复核确认没有修改集成测试、mock、计划或其他文档；提交只包含本任务的两个授权生产文件及本报告。

## 复审修复：raw URL origin 约束与 create 合同

### 修复内容

- 收紧 `validate_raw_url`：默认 API base `https://api.github.com/` 仅允许
  `https://gist.githubusercontent.com`；任何非默认 base（含 GHE 与 loopback mock）仅允许与已验证 API base 完全同 origin 的 raw URL。原有的 userinfo、query 与 fragment 拒绝规则保持不变。
- 增加 loopback API base 返回 `https://gist.githubusercontent.com/...` 的回归集成测试：返回
  `gist.invalid_raw_url`，并断言 MockGithub 仅收到初始 `GET /gists/gist-123`，没有 raw 第二请求。
- 将过时的 gist.rs 单元测试名称改为
  `create_rejects_invalid_bundle_before_http_and_redacts_it`，准确表达其断言：非法 Bundle 在 HTTP 前拒绝，且错误中不回显正文。
- 新增独立 create 合同测试：成功创建仅发送一个 `POST /gists`，请求为私有、仅含预期 Bundle 文件、携带固定 GitHub Accept/API version/User-Agent/Authorization headers，且不隐式 GET。该测试不依赖 CAS/PATCH。

### 验证

`cargo fmt --check`：退出码 `0`。

`cargo test -p envsync-backend --lib`：退出码 `0`，16 passed。

`cargo test -p envsync-backend --test gist_backend`：退出码 `101`；11 passed、2 failed。
新增 raw URL 回归与 create 合同测试均通过。以下两项仍是 Task 4 才实现的 PATCH/CAS 行为，按 Task 3 边界保留预期红灯：

- `create_then_read_then_publish_sends_expected_contract`：当前 `compare_and_swap` 返回 `gist.not_implemented`。
- `old_verify_read_after_patch_is_a_cas_conflict_without_patch_retry`：当前尚未实现 PATCH、读后验证及 `gist.cas_conflict`。

未实现 PATCH/CAS 或限流重试；未使用真实网络，集成测试仅使用本机 MockGithub。
