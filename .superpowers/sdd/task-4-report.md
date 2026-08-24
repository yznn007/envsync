# M4 Gist Task 4：CAS、限流与不确定结果红灯合约报告

## 范围

仅修改 `crates/envsync-backend/tests/gist_backend.rs`，新增本地 `MockGithub`
回环测试；所有 bundle 均由既有 `sealed_bundles` / `sealed_bundle` fixture 生成并经
生产 `gist_bundle::inspect()` 路径使用。未修改生产代码、`MockGithub`、Cargo 文件、计划或
其他文档。测试没有 `#[ignore]`、真实网络请求或测试内 sleep。

## 新增合约

- CAS 成功：`GET → PATCH → GET`，PATCH 带 `If-Match: "v1"`、私有单文件 body，验证读取
  返回候选完整 bytes 和新 ETag（`"v2"`）。
- PATCH 412 后验证候选、PATCH 断线后验证候选：均确认已发布；每个分支断言恰好一次 PATCH。
- PATCH 5xx 后验证旧 bundle：返回 `gist.cas_conflict`；PATCH 5xx 后验证失败：返回
  `gist.update_outcome_unknown`。二者均断言请求顺序和单次 PATCH，并以受控 sentinel 检查
  `Display` / `Debug` 不泄漏 response body；未知结果还检查不泄漏回环 URL。
- GET 429 + `Retry-After: 0`：只额外重试一次 GET，不使用真实等待。
- POST 429 和 PATCH 429：返回 `gist.rate_limited`，并分别断言没有 POST/PATCH 写请求重放；
  错误脱敏使用受控 sentinel。

既有的成功发布和旧 bundle 验证冲突测试保持不变。

## 验证结果

执行时间：2026-08-25（Asia/Shanghai）

`cargo fmt --check`

- 通过。

`cargo test -p envsync-backend --test gist_backend`

- 总计：21；通过：12；失败：9；忽略：0；过滤：0。
- 预期红灯：
  1. `cas_success_verifies_complete_candidate_and_returns_new_etag`：Task 3 的
     `compare_and_swap()` 在本地 bundle 校验后直接返回 `gist.not_implemented`，尚未发送
     PATCH 或验证 GET。
  2. `cas_412_verifies_candidate_once_and_reports_published`：同上，缺少 PATCH 412 后的单次
     验证读取与已发布判定。
  3. `cas_disconnect_verifies_candidate_once_and_reports_published`：同上，缺少断线后的单次
     验证读取与已发布判定。
  4. `cas_5xx_verifies_old_bundle_once_and_reports_conflict_without_leaks`：同上，当前返回
     `gist.not_implemented`，而合约要求验证旧 bundle 后返回 `gist.cas_conflict`。
  5. `cas_5xx_with_failed_verification_reports_unknown_once_without_leaks`：同上，当前返回
     `gist.not_implemented`，而合约要求返回 `gist.update_outcome_unknown`。
  6. `cas_patch_429_is_rate_limited_and_never_replays_patch`：CAS 尚未发起 PATCH，当前返回
     `gist.not_implemented`，而合约要求 `gist.rate_limited` 且只发一次 PATCH。
  7. `read_retries_once_after_zero_retry_after_without_real_wait`：`read()` 将 429 直接映射为
     `gist.rate_limited`，尚未按 `Retry-After: 0` 重试一次。
  8. `create_then_read_then_publish_sends_expected_contract`（既有）：CAS 尚未实现，发布阶段
     返回 `gist.not_implemented`。
  9. `old_verify_read_after_patch_is_a_cas_conflict_without_patch_retry`（既有）：CAS 尚未实现，
     因而未产生要求的 GET、PATCH、GET 验证序列与 `gist.cas_conflict`。

失败均为预期的功能红灯；不存在 fixture 无效、HTTP 超时或真实等待导致的失败。

## Important 缺口修复补充

- CAS 成功测试扩展为连续两次 `GET → PATCH → GET`：第一轮验证读取返回 `"v2"`，其
  `GistBundleRecord` 随即用于第二轮 CAS；第二个 PATCH 必须携带 `If-Match: "v2"`。
  revision 3 由既有 `sealed_bundle` 路径生成，未伪造 bundle。
- `GET 429 + Retry-After: 0` 记录 `Instant`，仍严格要求恰好两次 GET，并要求总耗时低于
  500ms，以捕获固定真实退避而不给 CI 造成脆弱时序。
- 新增 PATCH 412 后验证 GET 失败、PATCH 断线后验证 GET 失败；两者均要求
  `gist.update_outcome_unknown` 与严格 `GET → PATCH → GET` 序列，PATCH 恰好一次。
- 新增验证读取得到第三个、有效但并非候选或旧 bundle 的 `gist.cas_conflict` 覆盖。
- CAS 5xx、POST 429、PATCH 429 均补充 response-body sentinel、回环 mock endpoint、
  `test-token` 在 `Display` / `Debug` 中均不得出现的断言；保留原有错误码与单次写请求
  断言。移除了成功 CAS 中已由完整请求序列辅助函数覆盖的重复 GET 方法断言。

## 本次验证结果

执行时间：2026-08-25（Asia/Shanghai）

`cargo fmt --check`

- 通过。

`cargo test -p envsync-backend --test gist_backend`

- 总计：24；通过：12；失败：12；忽略：0；过滤：0。
- 预期红灯：
  1. `cas_success_verifies_complete_candidate_and_returns_new_etag`：CAS 未实现；因此不能
     验证确认读取返回的新 ETag 被保存并用于第二次 PATCH。
  2. `cas_412_verifies_candidate_once_and_reports_published`、
     `cas_disconnect_verifies_candidate_once_and_reports_published`：CAS 未实现，缺少
     PATCH 不确定结果后的单次验证读取与确认发布。
  3. `cas_412_with_failed_verification_reports_unknown_once`、
     `cas_disconnect_with_failed_verification_reports_unknown_once`、
     `cas_5xx_with_failed_verification_reports_unknown_once_without_leaks`：CAS 未实现，当前
     返回 `gist.not_implemented`，而合约要求 `gist.update_outcome_unknown`。
  4. `old_verify_read_after_patch_is_a_cas_conflict_without_patch_retry`、
     `cas_verifies_other_valid_bundle_as_conflict_once`、
     `cas_5xx_verifies_old_bundle_once_and_reports_conflict_without_leaks`：CAS 未实现，未在
     验证读取得到旧/其他有效 bundle 后返回 `gist.cas_conflict`。
  5. `cas_patch_429_is_rate_limited_and_never_replays_patch`：CAS 未发起 PATCH，当前返回
     `gist.not_implemented`，而合约要求 `gist.rate_limited` 且不重放写请求。
  6. `create_then_read_then_publish_sends_expected_contract`：既有集成合约因 CAS 未实现而在
     发布阶段失败。
  7. `read_retries_once_after_zero_retry_after_without_real_wait`：`read()` 仍将 429 直接映射
     为 `gist.rate_limited`，尚未按 `Retry-After: 0` 立即额外 GET 一次。

所有失败均为预期生产功能红灯；未发现测试编译失败、无效 fixture、Mock 超时或真实等待。

## 红灯合约复审修复（Critical / Important / Minor）

- 连续 CAS 现在精确断言五个请求：初始 `GET`、第一轮 `PATCH → GET`、第二轮
  `PATCH → GET`。第二轮使用专门的两请求 helper，明确检查其 PATCH 的
  `If-Match: "v2"`，不再把两请求切片传给要求 `GET → PATCH → GET` 的 helper。
- 新增同一真实 `sealed_bundle` / `pack` 路径的重封装覆盖：候选与验证读取 bundle 的
  `workspace`、`revision`、`head` 完全相同，且显式确认 ciphertext bytes 不同；该合法
  但非完整字节相同的验证结果必须是 `gist.cas_conflict`。未伪造文本。
- `Retry-After: 0` 的总耗时上限由 500ms 收紧为 `< 75ms`。聚焦红灯测试在本机 mock
  调度下完成约 20ms；75ms 留出回环调度余量，同时固定 100ms 或 250ms backoff 必然超限。
  Task 5 将以 fake Sleeper 覆盖内部精确等待；本集成测试继续只防止实质真实等待。
- 澄清 PATCH body 合约：PATCH 仅更新一个目标文件，且不得携带 `public` 或改变 Gist
  可见性；它**不是**要求 PATCH body 包含 `public: false`。`public: false` 只属于创建
  私有 Gist 的 POST 合约。

## 复审后验证结果

执行时间：2026-08-25（Asia/Shanghai）

`cargo fmt --check`

- 通过（退出码 0）。

聚焦测量：

- `cargo test -p envsync-backend --test gist_backend
  truncated_gist_file_uses_allowed_uncredentialed_raw_url -- --exact --nocapture` 通过；测试自身
  完成时间为 0.02s（两次本机 MockGithub GET）。
- 新增 `cas_verifies_same_ref_different_ciphertext_as_conflict_once` 的聚焦红灯在 0.02s
  完成；它先验证同 ref 真实重封装的不同 bytes，再因现有 CAS 返回
  `gist.not_implemented` 而失败。75ms 门槛相对该本机基线保留余量，并会拒绝 100ms/250ms
  的固定真实等待。

`cargo test -p envsync-backend --test gist_backend`

- 总计：25；通过：12；失败：13；忽略：0；过滤：0；测试执行时间：0.24s。
- 精确预期红灯：
  - `cas_success_verifies_complete_candidate_and_returns_new_etag`、
    `cas_412_verifies_candidate_once_and_reports_published`、
    `cas_disconnect_verifies_candidate_once_and_reports_published`、
    `cas_412_with_failed_verification_reports_unknown_once`、
    `cas_disconnect_with_failed_verification_reports_unknown_once`：CAS 仍返回
    `gist.not_implemented`，尚未完成 PATCH 后验证。
  - `old_verify_read_after_patch_is_a_cas_conflict_without_patch_retry`、
    `cas_verifies_other_valid_bundle_as_conflict_once`、
    `cas_verifies_same_ref_different_ciphertext_as_conflict_once`、
    `cas_5xx_verifies_old_bundle_once_and_reports_conflict_without_leaks`：CAS 仍返回
    `gist.not_implemented`，尚未将验证读取的非候选完整 bytes 映射为
    `gist.cas_conflict`。
  - `cas_5xx_with_failed_verification_reports_unknown_once_without_leaks`：CAS 仍返回
    `gist.not_implemented`，尚未将失败验证映射为 `gist.update_outcome_unknown`。
  - `cas_patch_429_is_rate_limited_and_never_replays_patch`：CAS 尚未发送 PATCH，当前返回
    `gist.not_implemented`，尚未映射为 `gist.rate_limited`。
  - `create_then_read_then_publish_sends_expected_contract`：发布步骤仍返回
    `gist.not_implemented`。
  - `read_retries_once_after_zero_retry_after_without_real_wait`：GET 429 当前直接返回
    `gist.rate_limited`，尚未立即重试一次。

除上述生产实现缺口外，未出现测试编译失败、fixture 无效、Mock 超时、真实网络或测试内
sleep。
