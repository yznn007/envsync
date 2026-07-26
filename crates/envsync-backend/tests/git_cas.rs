//! `GitBackend` 的远端 CAS 与认证隔离测试。
//!
//! 这里守护两组性质：
//!
//! 1. **发布是 CAS 的**——并发发布至多一方成功，失败方拿到真实的 observed revision，
//!    远端历史不会被改写（绝不 force push）；
//! 2. **凭据不进入 EnvSync**——只接受三种认证方式，URL 里带 password/token 一律拒绝，
//!    任何日志或错误信息都不会复述凭据。

use std::path::PathBuf;

use envsync_backend::git::DEFAULT_BRANCH;
use envsync_backend::git_auth::{redacted_remote, remote_host, validate_remote_url};
use envsync_backend::{Backend, BackendError, GitAuth, GitBackend, GitConfig};
use envsync_domain::{SnapshotId, WorkspaceId, WorkspaceRef};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// 测试脚手架
// ---------------------------------------------------------------------------

/// 一个临时的裸远端仓库。
struct Remote {
    /// 持有临时目录，drop 时清理。
    dir: TempDir,
    /// 裸仓库路径，直接当作 remote URL 使用。
    path: PathBuf,
}

impl Remote {
    /// 建立一个空的裸远端。
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("创建临时目录");
        let path = dir.path().join("remote.git");
        git2::Repository::init_bare(&path).expect("初始化裸远端");
        Remote { dir, path }
    }

    /// 远端 URL（本地路径形式）。
    fn url(&self) -> String {
        self.path.to_str().expect("路径可转为 UTF-8").to_owned()
    }

    /// 用独立的 cache 目录打开一个后端，模拟「另一台设备」。
    fn open(&self, cache: &str) -> GitBackend {
        GitBackend::open(GitConfig::new(
            self.url(),
            self.dir.path().join(cache),
            GitAuth::SshAgent,
        ))
        .expect("打开后端")
    }

    /// 远端受信分支当前指向的提交。
    fn branch_head(&self) -> Option<git2::Oid> {
        let repo = git2::Repository::open_bare(&self.path).expect("打开远端");
        repo.refname_to_id(&format!("refs/heads/{DEFAULT_BRANCH}"))
            .ok()
    }

    /// 某个提交的第一个父提交。
    fn parent_of(&self, commit: git2::Oid) -> Option<git2::Oid> {
        let repo = git2::Repository::open_bare(&self.path).expect("打开远端");
        let commit = repo.find_commit(commit).expect("读提交");
        commit.parent_id(0).ok()
    }
}

/// 在给定工作区上发布首个快照，返回基线 Ref。
fn publish_base(backend: &GitBackend, workspace: WorkspaceId) -> WorkspaceRef {
    let base = WorkspaceRef::initial(workspace).advance(SnapshotId::of(b"base"));
    backend
        .compare_and_swap_ref(workspace, 0, &base)
        .expect("首次发布");
    base
}

// ---------------------------------------------------------------------------
// 并发发布
// ---------------------------------------------------------------------------

#[test]
fn concurrent_publish_from_the_same_revision_has_exactly_one_winner() {
    let remote = Remote::new();
    let workspace = WorkspaceId::generate();

    let alpha = remote.open("cache-alpha");
    let base = publish_base(&alpha, workspace);
    let base_commit = remote.branch_head().expect("基线提交");

    // 第二台设备用**独立的** cache clone，从同一个 revision 出发。
    let beta = remote.open("cache-beta");
    assert_eq!(beta.get_ref(workspace).expect("读 Ref").revision, 1);

    let from_alpha = base.advance(SnapshotId::of(b"from-alpha"));
    let from_beta = base.advance(SnapshotId::of(b"from-beta"));

    let alpha_result = alpha.compare_and_swap_ref(workspace, 1, &from_alpha);
    let winner_commit = remote.branch_head().expect("胜者提交");
    let beta_result = beta.compare_and_swap_ref(workspace, 1, &from_beta);

    // 恰好一个成功。
    let successes = [&alpha_result, &beta_result]
        .iter()
        .filter(|result| result.is_ok())
        .count();
    assert_eq!(successes, 1, "{alpha_result:?} / {beta_result:?}");
    alpha_result.expect("先到者成功");

    // 失败方拿到的是真实的远端 revision，而不是「不知道」。
    let err = beta_result.expect_err("后到者必须失败");
    assert_eq!(err.code(), "backend.cas_conflict");
    assert!(
        matches!(
            err,
            BackendError::CasConflict {
                expected: 1,
                observed: 2
            }
        ),
        "{err:?}"
    );

    // 没有 force push：远端头还是胜者的提交，且它的父提交仍是基线（历史未被改写）。
    assert_eq!(remote.branch_head(), Some(winner_commit));
    assert_eq!(remote.parent_of(winner_commit), Some(base_commit));
    assert_eq!(
        alpha.get_ref(workspace).expect("读 Ref").head,
        from_alpha.head
    );
}

#[test]
fn the_loser_can_retry_on_the_refreshed_revision() {
    let remote = Remote::new();
    let workspace = WorkspaceId::generate();

    let alpha = remote.open("cache-alpha");
    let base = publish_base(&alpha, workspace);
    let beta = remote.open("cache-beta");
    assert_eq!(beta.get_ref(workspace).expect("读 Ref").revision, 1);

    let from_alpha = base.advance(SnapshotId::of(b"from-alpha"));
    alpha
        .compare_and_swap_ref(workspace, 1, &from_alpha)
        .expect("胜者发布");
    let winner_commit = remote.branch_head().expect("胜者提交");

    beta.compare_and_swap_ref(workspace, 1, &base.advance(SnapshotId::of(b"from-beta")))
        .expect_err("旧 revision 必须失败");

    // 重新 fetch 后基于新 revision 重试。
    let observed = beta.get_ref(workspace).expect("读 Ref");
    assert_eq!(observed.revision, 2);
    assert_eq!(observed.head, from_alpha.head);

    let retry = observed.advance(SnapshotId::of(b"from-beta-retry"));
    beta.compare_and_swap_ref(workspace, 2, &retry)
        .expect("基于新 revision 重试必须成功");

    let published = alpha.get_ref(workspace).expect("读 Ref");
    assert_eq!(published.revision, 3);
    assert_eq!(published.head, retry.head);
    // 重试是在胜者提交之上追加，而不是覆盖。
    let head_commit = remote.branch_head().expect("最新提交");
    assert_eq!(remote.parent_of(head_commit), Some(winner_commit));
}

#[test]
fn a_non_force_push_cannot_rewrite_the_remote_branch() {
    // 这条测试断言的是 `supports_strong_cas == true` 所依赖的**环境前提**：非
    // fast-forward 的更新会被拒绝。GitBackend 自己保证「永远不带 `+`、永远不 force」，
    // 「至多一方成功」则由这条前提兜底。
    let remote = Remote::new();
    let workspace = WorkspaceId::generate();
    let backend = remote.open("cache");
    publish_base(&backend, workspace);
    let head = remote.branch_head().expect("基线提交");

    // 另造一个与远端历史完全无关的提交。
    let scratch_dir = tempfile::tempdir().expect("临时目录");
    let scratch = git2::Repository::init_bare(scratch_dir.path()).expect("初始化仓库");
    let tree = scratch
        .find_tree(
            git2::Index::new()
                .expect("内存 index")
                .write_tree_to(&scratch)
                .expect("写空 tree"),
        )
        .expect("读 tree");
    let signature =
        git2::Signature::new("Rogue", "rogue@example.com", &git2::Time::new(0, 0)).expect("签名");
    let rogue = scratch
        .commit(None, &signature, &signature, "rogue\n", &tree, &[])
        .expect("提交");

    let mut rogue_remote = scratch
        .remote_anonymous(&remote.url())
        .expect("打开 remote");
    // refspec 没有前导 `+`，与 GitBackend 的写法一致。
    let result = rogue_remote.push(&[format!("{rogue}:refs/heads/{DEFAULT_BRANCH}")], None);
    assert!(result.is_err(), "非 fast-forward 的 push 必须被拒绝");
    assert_eq!(remote.branch_head(), Some(head), "远端历史不得被改写");
}

// ---------------------------------------------------------------------------
// 认证配置
// ---------------------------------------------------------------------------

#[test]
fn accepts_the_three_supported_auth_kinds() {
    for (index, auth) in [
        GitAuth::parse("ssh-agent", None).expect("ssh-agent"),
        GitAuth::parse("credential-helper", None).expect("credential-helper"),
        GitAuth::parse("token-secret-ref", Some("envsync:git-remote")).expect("token-secret-ref"),
    ]
    .into_iter()
    .enumerate()
    {
        let remote = Remote::new();
        let config = GitConfig::new(
            remote.url(),
            remote.dir.path().join(format!("cache-{index}")),
            auth,
        );
        GitBackend::open(config).expect("三种认证方式都必须被接受");
    }
}

#[test]
fn rejects_any_other_auth_configuration() {
    for (kind, secret) in [
        ("password", Some("hunter2")),
        ("basic", Some("dXNlcjpwYXNz")),
        ("netrc", None),
        ("token", Some("ghp_example")),
        ("", None),
    ] {
        let err = GitAuth::parse(kind, secret).expect_err(kind);
        assert_eq!(err.code(), "backend.unsupported", "{kind}");
    }
    // secret 引用必须是引用形态，不能是 token 原文。
    assert!(GitAuth::parse("token-secret-ref", Some("gh p/token=")).is_err());
    assert!(GitAuth::parse("token-secret-ref", Some("")).is_err());
    assert!(GitAuth::parse("token-secret-ref", None).is_err());
    // 非 token 认证不接受 secret 引用，避免用户误以为能顺手塞个密码。
    assert!(GitAuth::parse("ssh-agent", Some("anything")).is_err());
}

#[test]
fn rejects_remote_urls_that_carry_credentials() {
    for url in [
        "https://user:password@example.com/envsync/dotfiles.git",
        "https://token@example.com/envsync/dotfiles.git",
        "ssh://user:password@example.com/envsync/dotfiles.git",
        "user:password@example.com:envsync/dotfiles.git",
    ] {
        let err = validate_remote_url(url).expect_err(url);
        assert_eq!(err.code(), "backend.unsupported", "{url}");
    }
}

#[test]
fn rejects_remote_urls_that_carry_a_token_query_string() {
    for url in [
        "https://example.com/envsync/dotfiles.git?access_token=secret",
        "https://example.com/envsync/dotfiles.git?private_token=secret",
        "ssh://example.com/envsync/dotfiles.git?token=secret",
    ] {
        let err = validate_remote_url(url).expect_err(url);
        assert_eq!(err.code(), "backend.unsupported", "{url}");
    }
}

#[test]
fn rejects_unencrypted_transports() {
    for url in [
        "http://example.com/envsync/dotfiles.git",
        "git://example.com/envsync/dotfiles.git",
    ] {
        assert!(validate_remote_url(url).is_err(), "{url}");
    }
    // 允许的形态。
    validate_remote_url("https://example.com/envsync/dotfiles.git").expect("https");
    validate_remote_url("ssh://git@example.com/envsync/dotfiles.git").expect("ssh");
    validate_remote_url("git@example.com:envsync/dotfiles.git").expect("scp 风格 ssh");
}

// ---------------------------------------------------------------------------
// 脱敏
// ---------------------------------------------------------------------------

/// 只要这串字符出现在任何面向用户的文本里，就说明凭据泄漏了。
const CANARY: &str = "c4n4rytokenvalue";

#[test]
fn credentials_never_appear_in_redacted_output_or_errors() {
    let cache = tempfile::tempdir().expect("临时目录");
    let urls = [
        format!("https://user:{CANARY}@example.com/envsync/dotfiles.git"),
        format!("https://{CANARY}@example.com/envsync/dotfiles.git"),
        format!("https://example.com/envsync/dotfiles.git?access_token={CANARY}"),
        format!("ssh://user:{CANARY}@example.com/envsync/dotfiles.git"),
        format!("user:{CANARY}@example.com:envsync/dotfiles.git"),
    ];

    for url in &urls {
        // 脱敏输出必须干净，且仍然保留可定位的 host。
        let redacted = redacted_remote(url);
        assert!(!redacted.contains(CANARY), "脱敏后仍含 canary：{redacted}");
        assert!(!remote_host(url).contains(CANARY));
        assert!(redacted.contains("example.com"), "{redacted}");

        // 配置层的拒绝错误不得复述 URL。
        let err = validate_remote_url(url).expect_err(url);
        assert!(!err.to_string().contains(CANARY), "{err}");
        assert!(!format!("{err:?}").contains(CANARY), "{err:?}");

        // 后端入口同样拒绝，且错误、Debug 输出都不含 canary。
        let config = GitConfig::new(url.clone(), cache.path().join("cache"), GitAuth::SshAgent);
        assert!(!format!("{config:?}").contains(CANARY), "{config:?}");
        let err = GitBackend::open(config).expect_err(url);
        assert!(!err.to_string().contains(CANARY), "{err}");
        assert!(!format!("{err:?}").contains(CANARY), "{err:?}");
        assert!(!err_source_chain(&err).contains(CANARY));
    }
}

#[test]
fn secret_references_never_appear_in_debug_output() {
    let auth = GitAuth::TokenSecretRef {
        secret_id: CANARY.to_owned(),
    };
    assert!(!format!("{auth:?}").contains(CANARY));

    let remote = Remote::new();
    let config = GitConfig::new(remote.url(), remote.dir.path().join("cache"), auth);
    assert!(!format!("{config:?}").contains(CANARY));
    let backend = GitBackend::open(config).expect("打开后端");
    assert!(!format!("{backend:?}").contains(CANARY));
}

/// 把错误及其 source 链拼成一个字符串，便于整体断言。
fn err_source_chain(err: &BackendError) -> String {
    let mut text = err.to_string();
    let mut source = std::error::Error::source(err);
    while let Some(current) = source {
        text.push(' ');
        text.push_str(&current.to_string());
        source = current.source();
    }
    text
}
