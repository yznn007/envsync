# Task 1 核心红灯测试报告

## 交付内容

- 新增 `crates/envsync-backend/tests/gist_backend.rs`，仅包含三项 Gist HTTP 合约测试：
  1. create/read/update 的 `POST`、`GET`、`PATCH`、`GET` 请求顺序与认证、私有 Gist JSON、文件名、`If-Match`、最终 bundle bytes。
  2. descriptor 的 `kind == "gist"` 与弱 CAS 标识。
  3. PATCH 返回 200 后验证 GET 仍为旧 bundle 时的 `gist.cas_conflict`，并断言仅一个 PATCH。
- 两个 revision 均由真实 `gist_bundle::pack` 生成；断言不回显 token 或完整 bundle 文本。

## 验证

- `rustfmt --check --config skip_children=true crates/envsync-backend/tests/gist_backend.rs`：通过。
- `cargo fmt --check`：RED。该命令还检查既有的 `crates/envsync-backend/tests/support/mock_github.rs`，报告 4 处格式差异；根据任务限制未修改该文件。
- `cargo test -p envsync-backend --test gist_backend`：RED（退出码 101）。精确阻塞输出：

```text
error: failed to select a version for `reqwest`.
    ... required by package `envsync-backend v0.1.0 (/Users/Apple/Projects/envsync-local/.worktrees/m4-view-api/crates/envsync-backend)`
    ... which satisfies path dependency `envsync-backend` (locked to 0.1.0) of package `envsync-desktop v0.1.0 (/Users/Apple/Projects/envsync-local/.worktrees/m4-view-api/apps/desktop)`
versions that meet the requirements `^0.13` (locked to 0.13.4) are: 0.13.4

package `envsync-backend` depends on `reqwest` with feature `rustls-tls` but `reqwest` does not have that feature.
help: available features: __native-tls, __native-tls-alpn, __rustls, __rustls-aws-lc-rs, __tls, blocking, brotli, charset, cookies, default, default-tls, deflate, form, gzip, hickory-dns, http2, http3, json, multipart, native-tls, native-tls-no-alpn, native-tls-vendored, native-tls-vendored-no-alpn, query, rustls, rustls-no-provider, socks, stream, system-proxy, zstd

failed to select a version for `reqwest` which could resolve this conflict
```

该解析失败发生在编译测试前，因此当前不能观察预期的缺少生产 `gist` 模块错误。Cargo 文件按任务限制未修改。
