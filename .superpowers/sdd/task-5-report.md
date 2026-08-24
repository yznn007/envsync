# EnvSync M4 Task 5 Report

## 设计

- `GistBackend` 的公开构造 API 保持不变，内部新增私有 `Sleeper` 依赖；生产实现使用 `thread::sleep`，`gist.rs` 单元测试通过 fake sleeper 记录 duration。
- API `GET /gists/<id>` 的成功响应必须包含合法 ETag；缺失 ETag 返回 `gist.missing_etag`，避免把无版本读取带入发布流程。
- 只对 API GET 的限流响应做受控重试，最多两次总尝试。`Retry-After` 数字秒优先，其次 `X-RateLimit-Reset` Unix 秒；只有可解析且不超过 60 秒的 delay 才 sleep/retry，`Retry-After: 0` 会立即重试。POST/PATCH 不自动重放。
- `compare_and_swap` 在本地检查 candidate bundle、workspace、revision 和已确认 ETag 后，只发送一次 `PATCH /gists/<id>`，body 只替换目标文件，header 使用 `If-Match: <expected ETag>`。
- PATCH 的 2xx、412、transport error、5xx 都只跟一次 verification GET。验证读到的完整 bytes 等于 candidate 才成功并返回验证 GET 的新 ETag；读到同 workspace 的其他合法 bundle bytes 返回 `gist.cas_conflict`；验证无法读到有效记录返回 `gist.update_outcome_unknown`。
- PATCH 429 直接返回 `gist.rate_limited`，不重放 PATCH，也不做 verification GET。401、普通 403、404、其他确定性 4xx 保留安全 status 错误。
- `descriptor()` 继续明确报告 `supports_strong_cas: false`，因为最终成功条件来自后读 bytes，而不是 GitHub ETag 的强 CAS 语义。

## 实现

- 修改 `crates/envsync-backend/src/gist.rs`：
  - 新增 `Sleeper` trait、`ThreadSleeper` 生产实现，以及私有 `sleeper: Arc<dyn Sleeper>` 字段。
  - 新增 `read_api`/`parse_gist_response`，让公开 `read()` 和 CAS verification 共用解析逻辑，同时只让公开读取开启 GET 限流重试。
  - 新增 `bounded_retry_delay`、`parse_retry_after`、`is_read_rate_limited`，实现 `Retry-After` 和 `X-RateLimit-Reset` 的 60 秒边界。
  - 实现 `compare_and_swap` 的单次 PATCH、`If-Match`、PATCH 状态分流和 `verify_after_patch`。
  - 新增安全错误码 `gist.cas_conflict` 和 `gist.update_outcome_unknown`；错误 Display/Debug 不包含响应 body、URL、token 或 ETag。
  - 修正 `create` 的过时“仅本地校验”注释。
  - 新增内部单元测试 `rate_limit_retry_uses_injected_sleeper`，证明 fake sleeper 被调用并记录 duration。

## 命令输出

### `cargo fmt --check`

Exit code: 0

```text
```

### `cargo test -p envsync-backend --lib`

Exit code: 0

```text
    Blocking waiting for file lock on package cache
    Blocking waiting for file lock on package cache
    Blocking waiting for file lock on package cache
    Blocking waiting for file lock on build directory
   Compiling envsync-backend v0.1.0 (/Users/Apple/Projects/envsync-local/.worktrees/m4-view-api/crates/envsync-backend)
    Finished `test` profile [optimized + debuginfo] target(s) in 2.81s
     Running unittests src/lib.rs (target/debug/deps/envsync_backend-e68183772ea0cf10)

running 17 tests
test gist::tests::gist_id_has_a_narrow_syntax_and_never_debugs_its_value ... ok
test git::tests::branch_names_are_restricted ... ok
test gist::tests::credentials_reject_unsafe_tokens_and_redact_all_sensitive_values ... ok
test gist::tests::api_base_refuses_unsafe_urls_without_echoing_them ... ok
test gist::tests::bundle_record_debug_shows_only_allowed_header_fields_and_length ... ok
test git::tests::tree_paths_reject_traversal ... ok
test git::tests::tree_paths_accept_layout_paths ... ok
test git_auth::tests::accepts_the_three_supported_kinds ... ok
test git_auth::tests::debug_never_prints_secret_id ... ok
test git_auth::tests::local_paths_never_leak_into_logs ... ok
test git_auth::tests::rejects_other_auth_forms ... ok
test git_auth::tests::scp_style_ssh_remotes_are_accepted ... ok
test gist::tests::create_rejects_invalid_bundle_before_http_and_redacts_it ... ok
test gist::tests::api_base_requires_trailing_slash_for_path_segments ... ok
test gist::tests::backend_debug_redacts_the_controlled_api_base ... ok
test gist::tests::rate_limit_retry_uses_injected_sleeper ... ok
test gist::tests::github_uses_the_gist_backend_descriptor ... ok

test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

### `cargo test -p envsync-backend --test gist_backend`

Exit code: 0

```text
    Blocking waiting for file lock on package cache
    Blocking waiting for file lock on package cache
    Blocking waiting for file lock on package cache
   Compiling envsync-backend v0.1.0 (/Users/Apple/Projects/envsync-local/.worktrees/m4-view-api/crates/envsync-backend)
    Finished `test` profile [optimized + debuginfo] target(s) in 2.18s
     Running tests/gist_backend.rs (target/debug/deps/gist_backend-69c722ff649df1c5)

running 25 tests
test cas_patch_429_is_rate_limited_and_never_replays_patch ... ok
test cas_5xx_verifies_old_bundle_once_and_reports_conflict_without_leaks ... ok
test cas_5xx_with_failed_verification_reports_unknown_once_without_leaks ... ok
test cas_verifies_other_valid_bundle_as_conflict_once ... ok
test cas_412_verifies_candidate_once_and_reports_published ... ok
test cas_412_with_failed_verification_reports_unknown_once ... ok
test cas_disconnect_verifies_candidate_once_and_reports_published ... ok
test cas_disconnect_with_failed_verification_reports_unknown_once ... ok
test cas_verifies_same_ref_different_ciphertext_as_conflict_once ... ok
test create_429_is_rate_limited_and_never_replays_post ... ok
test descriptor_explicitly_reports_weak_cas ... ok
test create_sends_one_private_post_without_implicit_read ... ok
test cas_success_verifies_complete_candidate_and_returns_new_etag ... ok
test support::mock_github::tests::request_record_debug_redacts_path ... ok
test loopback_api_rejects_public_github_raw_url_without_following_it ... ok
test read_rejects_missing_etag_before_returning_unusable_revision ... ok
test read_retries_once_after_zero_retry_after_without_real_wait ... ok
test read_transport_failure_is_safe ... ok
test old_verify_read_after_patch_is_a_cas_conflict_without_patch_retry ... ok
test truncated_gist_file_uses_allowed_uncredentialed_raw_url ... ok
test create_then_read_then_publish_sends_expected_contract ... ok
test read_maps_auth_forbidden_and_not_found_to_safe_codes ... ok
test truncated_gist_rejects_untrusted_raw_url_without_following_it ... ok
test read_rejects_oversized_response_before_json_parsing ... ok
test read_timeout_is_reported_without_echoing_endpoint ... ok

test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.25s
```

### `git diff --check`

Exit code: 0

```text
```

## 网络声明

未调用真实 GitHub。所有 HTTP 行为验证均使用现有 `127.0.0.1` `MockGithub`；`GistBackend::github()` 的单元测试只构造默认后端，不发送网络请求。
