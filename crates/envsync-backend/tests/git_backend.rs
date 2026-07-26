//! `GitBackend` 的集成测试：对象布局与本地 round trip。
//!
//! 这些用例守护四条不变量：Git tree 里的对象字节与 `LocalBackend` 完全一致、Ref 只能通过
//! CAS 前进、提交是确定性的且不含本机信息、任何不属于 EnvSync 布局的远端分支都会被拒绝。

use std::path::{Path, PathBuf};

use envsync_backend::git::{validate_tree_path, DEFAULT_BRANCH, FORMAT_MARKER};
use envsync_backend::{Backend, BackendError, GitAuth, GitBackend, GitConfig, LocalBackend};
use envsync_domain::{ObjectId, ObjectKind, SnapshotId, WorkspaceId, WorkspaceRef};
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

    /// 在远端上新建一个 cache 目录，返回打开后的后端。
    fn open(&self, cache: &str) -> Result<GitBackend, BackendError> {
        GitBackend::open(GitConfig::new(
            self.url(),
            self.dir.path().join(cache),
            GitAuth::SshAgent,
        ))
    }

    /// 远端受信分支当前指向的提交。
    fn branch_head(&self) -> Option<git2::Oid> {
        let repo = git2::Repository::open_bare(&self.path).expect("打开远端");
        repo.refname_to_id(&format!("refs/heads/{DEFAULT_BRANCH}"))
            .ok()
    }

    /// 直接在远端分支上造一个提交，用于模拟「别人写坏了布局」。
    fn seed(&self, files: &[(&str, &[u8])]) {
        let repo = git2::Repository::open_bare(&self.path).expect("打开远端");
        let mut index = git2::Index::new().expect("内存 index");
        for (path, bytes) in files {
            let oid = repo.blob(bytes).expect("写 blob");
            index
                .add(&index_entry(path, oid, bytes.len()))
                .expect("加 index");
        }
        let tree_oid = index.write_tree_to(&repo).expect("写 tree");
        let tree = repo.find_tree(tree_oid).expect("读 tree");
        let signature =
            git2::Signature::new("Seed", "seed@example.com", &git2::Time::new(0, 0)).expect("签名");
        let commit = repo
            .commit(None, &signature, &signature, "seed\n", &tree, &[])
            .expect("提交");
        repo.reference(
            &format!("refs/heads/{DEFAULT_BRANCH}"),
            commit,
            true,
            "seed",
        )
        .expect("建分支");
    }

    /// 读出远端分支最新提交的信息。
    fn head_message(&self) -> String {
        let repo = git2::Repository::open_bare(&self.path).expect("打开远端");
        let head = self.branch_head().expect("分支存在");
        let commit = repo.find_commit(head).expect("读提交");
        commit.message().unwrap_or_default().to_owned()
    }
}

/// 构造一条 index 记录（与实现内部使用的形状一致）。
fn index_entry(path: &str, oid: git2::Oid, len: usize) -> git2::IndexEntry {
    git2::IndexEntry {
        ctime: git2::IndexTime::new(0, 0),
        mtime: git2::IndexTime::new(0, 0),
        dev: 0,
        ino: 0,
        mode: 0o100_644,
        uid: 0,
        gid: 0,
        file_size: len as u32,
        id: oid,
        flags: 0,
        flags_extended: 0,
        path: path.as_bytes().to_vec(),
    }
}

/// 构造一个 Blob 对象标识。
fn blob(bytes: &[u8]) -> ObjectId {
    ObjectId::for_bytes(ObjectKind::Blob, bytes)
}

/// 对象在 tree 中的路径。
fn object_tree_path(id: ObjectId) -> String {
    let hex = id.hex();
    format!(
        ".envsync/objects/{}/{}.{}",
        &hex[..2],
        &hex[2..],
        id.kind.as_str()
    )
}

/// Ref 在 tree 中的路径。
fn ref_tree_path(workspace: WorkspaceId) -> String {
    format!(".envsync/refs/{workspace}.cbor")
}

// ---------------------------------------------------------------------------
// 自述
// ---------------------------------------------------------------------------

#[test]
fn describes_itself_as_a_strong_cas_git_backend() {
    let remote = Remote::new();
    let backend = remote.open("cache").expect("打开后端");
    let descriptor = backend.describe();
    assert_eq!(descriptor.kind, "git");
    assert!(descriptor.supports_strong_cas);
}

// ---------------------------------------------------------------------------
// 对象存储
// ---------------------------------------------------------------------------

#[test]
fn put_and_get_object_round_trips_and_is_idempotent() {
    let remote = Remote::new();
    let backend = remote.open("cache").expect("打开后端");
    let bytes = b"alias ll='ls -alF'\n";
    let id = blob(bytes);

    assert!(!backend.has_object(id).expect("存在性检查"));
    backend.put_object(id, bytes).expect("首次写入");
    backend.put_object(id, bytes).expect("重复写入必须成功");
    backend.put_object(id, bytes).expect("再次重复写入仍然成功");

    assert_eq!(backend.get_object(id).expect("读回"), bytes.as_slice());
    assert!(backend.has_object(id).expect("存在性检查"));
    assert_eq!(
        backend.list_objects(&id.hex()[..2]).expect("列举"),
        vec![id]
    );
}

#[test]
fn object_bytes_are_identical_to_the_local_backend() {
    let remote = Remote::new();
    let backend = remote.open("cache").expect("打开后端");
    let local_dir = tempfile::tempdir().expect("临时目录");
    let local = LocalBackend::open(local_dir.path()).expect("打开本地后端");

    let bytes = b"export EDITOR=nvim\n";
    let id = blob(bytes);
    backend.put_object(id, bytes).expect("写入 Git 后端");
    local.put_object(id, bytes).expect("写入本地后端");

    // 两个后端读出的字节必须逐字节相同，对象才能在后端之间直接搬运。
    assert_eq!(
        backend.get_object(id).expect("读 Git"),
        local.get_object(id).expect("读本地")
    );

    // 并且 Git tree 里真的落在了约定路径上。
    let repo = git2::Repository::open_bare(&remote.path).expect("打开远端");
    let head = remote.branch_head().expect("分支存在");
    let tree = repo
        .find_commit(head)
        .expect("读提交")
        .tree()
        .expect("读 tree");
    let entry = tree
        .get_path(Path::new(&object_tree_path(id)))
        .expect("对象在约定路径上");
    let object = entry.to_object(&repo).expect("读对象");
    assert_eq!(object.as_blob().expect("是 blob").content(), bytes);
}

#[test]
fn put_object_rejects_bytes_that_do_not_match_id() {
    let remote = Remote::new();
    let backend = remote.open("cache").expect("打开后端");
    let id = blob(b"the real content");

    let err = backend
        .put_object(id, b"a different content")
        .expect_err("摘要不符必须失败");
    assert_eq!(err.code(), "corruption");
    assert!(matches!(err, BackendError::Corruption { .. }));
    // 失败的写入不得在远端留下任何提交。
    assert!(remote.branch_head().is_none());
}

#[test]
fn get_object_rejects_tampered_remote_content() {
    let remote = Remote::new();
    let id = blob(b"the real content");
    // 远端上的路径正确，内容却被换掉：重算摘要必须发现。
    remote.seed(&[
        (".envsync/format", FORMAT_MARKER.as_bytes()),
        (&object_tree_path(id), b"tampered"),
    ]);

    let backend = remote.open("cache").expect("打开后端");
    let err = backend.get_object(id).expect_err("损坏对象不得返回内容");
    assert_eq!(err.code(), "corruption");
}

#[test]
fn get_object_reports_missing_objects() {
    let remote = Remote::new();
    let backend = remote.open("cache").expect("打开后端");
    let err = backend
        .get_object(blob(b"never written"))
        .expect_err("对象不存在");
    assert_eq!(err.code(), "object_not_found");
    assert_eq!(backend.list_objects("ab").expect("列举空后端"), Vec::new());
}

// ---------------------------------------------------------------------------
// Ref 与 CAS
// ---------------------------------------------------------------------------

#[test]
fn get_ref_on_empty_backend_reports_ref_not_found() {
    let remote = Remote::new();
    let backend = remote.open("cache").expect("打开后端");
    let workspace = WorkspaceId::generate();

    let err = backend.get_ref(workspace).expect_err("尚未发布过快照");
    assert_eq!(err.code(), "ref_not_found");
    assert!(matches!(err, BackendError::RefNotFound(id) if id == workspace));
}

#[test]
fn first_publish_only_accepts_expected_revision_zero() {
    let remote = Remote::new();
    let backend = remote.open("cache").expect("打开后端");
    let workspace = WorkspaceId::generate();
    let next = WorkspaceRef::initial(workspace).advance(SnapshotId::of(b"first"));

    let err = backend
        .compare_and_swap_ref(workspace, 1, &next)
        .expect_err("首次发布只接受 revision 0");
    assert!(
        matches!(
            err,
            BackendError::CasConflict {
                expected: 1,
                observed: 0
            }
        ),
        "{err:?}"
    );

    backend
        .compare_and_swap_ref(workspace, 0, &next)
        .expect("首次发布");
    assert_eq!(backend.get_ref(workspace).expect("读回").revision, 1);
}

#[test]
fn wrong_expected_revision_reports_the_observed_one() {
    let remote = Remote::new();
    let backend = remote.open("cache").expect("打开后端");
    let workspace = WorkspaceId::generate();

    let first = WorkspaceRef::initial(workspace).advance(SnapshotId::of(b"first"));
    backend
        .compare_and_swap_ref(workspace, 0, &first)
        .expect("首次发布");
    let second = first.advance(SnapshotId::of(b"second"));
    backend
        .compare_and_swap_ref(workspace, 1, &second)
        .expect("第二次发布");

    // 用过期的 revision 重放：必须带回真实的 observed。
    let stale = first.advance(SnapshotId::of(b"stale"));
    let err = backend
        .compare_and_swap_ref(workspace, 1, &stale)
        .expect_err("过期 revision 必须被拒");
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
    assert_eq!(backend.get_ref(workspace).expect("读回").head, second.head);
}

#[test]
fn revision_must_strictly_increase() {
    let remote = Remote::new();
    let backend = remote.open("cache").expect("打开后端");
    let workspace = WorkspaceId::generate();
    let first = WorkspaceRef::initial(workspace).advance(SnapshotId::of(b"first"));
    backend
        .compare_and_swap_ref(workspace, 0, &first)
        .expect("首次发布");

    // revision 与当前相同：非法后继。
    let sideways = WorkspaceRef {
        revision: 1,
        head: Some(SnapshotId::of(b"sideways")),
        ..first
    };
    let err = backend
        .compare_and_swap_ref(workspace, 1, &sideways)
        .expect_err("revision 未递增");
    assert_eq!(err.code(), "invalid_ref");
}

#[test]
fn rejects_a_ref_belonging_to_another_workspace() {
    let remote = Remote::new();
    let backend = remote.open("cache").expect("打开后端");
    let workspace = WorkspaceId::generate();
    let other = WorkspaceId::generate();
    let next = WorkspaceRef::initial(other).advance(SnapshotId::of(b"x"));

    let err = backend
        .compare_and_swap_ref(workspace, 0, &next)
        .expect_err("工作区不匹配");
    assert_eq!(err.code(), "invalid_ref");
}

#[test]
fn rejects_non_canonical_ref_bytes_on_the_remote() {
    let remote = Remote::new();
    let workspace = WorkspaceId::generate();
    // 一段合法 CBOR 但非 canonical 编码（0x19 0x00 0x01 用两字节编码了 1）的垃圾内容。
    remote.seed(&[
        (".envsync/format", FORMAT_MARKER.as_bytes()),
        (&ref_tree_path(workspace), &[0x84, 0x19, 0x00, 0x01]),
    ]);

    let backend = remote.open("cache").expect("打开后端");
    let err = backend
        .get_ref(workspace)
        .expect_err("非 canonical Ref 必须被拒");
    assert!(
        matches!(err.code(), "codec" | "invalid_ref"),
        "意外的错误码：{}",
        err.code()
    );
}

// ---------------------------------------------------------------------------
// 持久化与重开
// ---------------------------------------------------------------------------

#[test]
fn reopening_with_a_fresh_cache_sees_the_same_snapshot() {
    let remote = Remote::new();
    let workspace = WorkspaceId::generate();
    let bytes = b"set -o vi\n";
    let id = blob(bytes);
    let snapshot = SnapshotId::of(b"published");

    {
        let backend = remote.open("cache-a").expect("打开后端");
        backend.put_object(id, bytes).expect("写对象");
        let next = WorkspaceRef::initial(workspace).advance(snapshot);
        backend
            .compare_and_swap_ref(workspace, 0, &next)
            .expect("发布");
    }

    // 全新的 cache 目录：只有当对象和 Ref 都真的落到了远端，下面才读得出来。
    let reopened = remote.open("cache-b").expect("重新打开后端");
    assert_eq!(reopened.get_object(id).expect("读对象"), bytes.as_slice());
    let reference = reopened.get_ref(workspace).expect("读 Ref");
    assert_eq!(reference.revision, 1);
    assert_eq!(reference.head, Some(snapshot));
}

// ---------------------------------------------------------------------------
// 布局与格式标记
// ---------------------------------------------------------------------------

#[test]
fn open_fails_when_the_format_marker_does_not_match() {
    let remote = Remote::new();
    remote.seed(&[(".envsync/format", b"envsync-git-format=99\n")]);

    let err = remote.open("cache").expect_err("格式标记不匹配");
    assert_eq!(err.code(), "format_mismatch");
    assert!(matches!(err, BackendError::FormatMismatch { .. }));
}

#[test]
fn open_fails_when_the_branch_is_not_an_envsync_layout() {
    let remote = Remote::new();
    remote.seed(&[("README.md", b"someone else's branch\n")]);

    let err = remote.open("cache").expect_err("分支不是 EnvSync 布局");
    assert_eq!(err.code(), "format_mismatch");
}

#[test]
fn rejects_directory_traversal_in_tree_paths() {
    // 布局路径全部由已校验的标识拼出，穿越只可能来自实现 bug；这里直接测校验函数。
    for path in [
        ".envsync/objects/../../../etc/passwd",
        ".envsync/../../secrets.cbor",
        "../.envsync/refs/x.cbor",
        "/absolute/path",
        ".envsync/refs/./x.cbor",
    ] {
        let err = validate_tree_path(path).expect_err(path);
        assert_eq!(err.code(), "invalid_prefix", "{path}");
    }
    validate_tree_path(&object_tree_path(blob(b"ok"))).expect("正常对象路径");
    validate_tree_path(&ref_tree_path(WorkspaceId::generate())).expect("正常 Ref 路径");
}

#[test]
fn open_rejects_a_branch_name_that_is_not_a_valid_ref() {
    let remote = Remote::new();
    let config = GitConfig::new(
        remote.url(),
        remote.dir.path().join("cache"),
        GitAuth::SshAgent,
    )
    .with_branch("../evil");
    let err = GitBackend::open(config).expect_err("非法分支名");
    assert_eq!(err.code(), "unsupported");
}

// ---------------------------------------------------------------------------
// 提交内容
// ---------------------------------------------------------------------------

#[test]
fn ref_commit_message_carries_only_workspace_revision_and_snapshot() {
    let remote = Remote::new();
    let backend = remote.open("cache").expect("打开后端");
    let workspace = WorkspaceId::generate();
    let snapshot = SnapshotId::of(b"published");
    let next = WorkspaceRef::initial(workspace).advance(snapshot);
    backend
        .compare_and_swap_ref(workspace, 0, &next)
        .expect("发布");

    let message = remote.head_message();
    assert_eq!(
        message,
        format!(
            "envsync ref\n\nworkspace={workspace}\nrevision=1\nsnapshot={}\n",
            snapshot.to_hex()
        )
    );
    // 不含路径、不含本机信息。
    assert!(!message.contains('/'));
    assert!(!message.contains("cache"));

    let repo = git2::Repository::open_bare(&remote.path).expect("打开远端");
    let commit = repo
        .find_commit(remote.branch_head().expect("分支存在"))
        .expect("读提交");
    assert_eq!(commit.author().name(), Some("EnvSync"));
    assert_eq!(commit.author().email(), Some("envsync@localhost"));
    // 确定性时间戳：固定为 Unix 纪元，不泄漏用户作息。
    assert_eq!(commit.time().seconds(), 0);
    assert_eq!(commit.time().offset_minutes(), 0);
}

#[test]
fn identical_content_produces_identical_commits() {
    let workspace = WorkspaceId::generate();
    let bytes = b"identical bytes\n";
    let id = blob(bytes);
    let snapshot = SnapshotId::of(b"same");

    let publish = |remote: &Remote| {
        let backend = remote.open("cache").expect("打开后端");
        backend.put_object(id, bytes).expect("写对象");
        let next = WorkspaceRef::initial(workspace).advance(snapshot);
        backend
            .compare_and_swap_ref(workspace, 0, &next)
            .expect("发布");
        remote.branch_head().expect("分支存在")
    };

    let first = Remote::new();
    let second = Remote::new();
    // 相同内容、相同顺序 → 相同 commit OID。固定署名与固定时间戳的直接后果。
    assert_eq!(publish(&first), publish(&second));
}
