//! `LocalBackend` 的集成测试。
//!
//! 这些用例守护三条不变量：对象内容寻址不可破坏、Ref 只能通过 CAS 前进、任何中断都
//! 不会让后端进入「读不出完整数据」的状态。

use std::fs;
use std::path::PathBuf;

use envsync_backend::{Backend, BackendDescriptor, BackendError, LocalBackend};
use envsync_domain::{ObjectId, ObjectKind, SnapshotId, WorkspaceId, WorkspaceRef};
use tempfile::TempDir;

/// 在临时目录中打开一个后端。
fn backend() -> (TempDir, LocalBackend) {
    let dir = tempfile::tempdir().expect("创建临时目录");
    let backend = LocalBackend::open(dir.path()).expect("打开后端");
    (dir, backend)
}

/// 测试专用：直接算出对象在磁盘上的路径，用于模拟外部篡改。
fn object_file(root: &std::path::Path, id: ObjectId) -> PathBuf {
    let hex = id.hex();
    root.join("objects")
        .join(&hex[..2])
        .join(format!("{}.{}", &hex[2..], id.kind.as_str()))
}

/// 构造一个 Blob 对象标识。
fn blob(bytes: &[u8]) -> ObjectId {
    ObjectId::for_bytes(ObjectKind::Blob, bytes)
}

// ---------------------------------------------------------------------------
// 对象存储
// ---------------------------------------------------------------------------

#[test]
fn put_object_is_idempotent() {
    let (_dir, backend) = backend();
    let bytes = b"alias ll='ls -alF'\n";
    let id = blob(bytes);

    backend.put_object(id, bytes).expect("首次写入");
    backend.put_object(id, bytes).expect("重复写入必须成功");
    backend.put_object(id, bytes).expect("再次重复写入仍然成功");

    assert_eq!(backend.get_object(id).expect("读回"), bytes.as_slice());
    assert!(backend.has_object(id).expect("存在性检查"));
}

#[test]
fn put_object_rejects_bytes_that_do_not_match_id() {
    let (_dir, backend) = backend();
    let id = blob(b"the real content");

    let err = backend
        .put_object(id, b"a different content")
        .expect_err("同一标识写入不同内容必须失败");
    assert_eq!(err.code(), "corruption");
    assert!(matches!(err, BackendError::Corruption { .. }));
    // 失败的写入不得留下任何对象。
    assert!(!backend.has_object(id).expect("存在性检查"));
}

#[test]
fn put_object_detects_existing_object_with_different_content() {
    let (dir, backend) = backend();
    let bytes = b"canonical content";
    let id = blob(bytes);
    backend.put_object(id, bytes).expect("首次写入");

    // 模拟磁盘上的对象被外部改写：此时内容寻址已被破坏。
    fs::write(object_file(dir.path(), id), b"tampered").expect("篡改对象文件");

    let err = backend
        .put_object(id, bytes)
        .expect_err("已存在的对象内容不同必须报损坏");
    assert_eq!(err.code(), "corruption");
    // 后端绝不覆盖：磁盘上仍然是被篡改的内容，交由维护流程处理。
    assert_eq!(
        fs::read(object_file(dir.path(), id)).expect("读取对象文件"),
        b"tampered"
    );
}

#[test]
fn get_object_verifies_digest_and_never_returns_corrupt_bytes() {
    let (dir, backend) = backend();
    let bytes = b"export PATH=$HOME/bin:$PATH\n";
    let id = blob(bytes);
    backend.put_object(id, bytes).expect("写入");

    fs::write(object_file(dir.path(), id), b"evil payload").expect("篡改对象文件");

    let err = backend.get_object(id).expect_err("损坏对象不能返回内容");
    assert_eq!(err.code(), "corruption");
    assert!(matches!(err, BackendError::Corruption { id: got, .. } if got == id));
}

#[test]
fn get_object_missing_returns_object_not_found() {
    let (_dir, backend) = backend();
    let id = blob(b"never stored");

    let err = backend.get_object(id).expect_err("不存在的对象");
    assert_eq!(err.code(), "object_not_found");
    assert!(matches!(err, BackendError::ObjectNotFound(got) if got == id));
    assert!(!backend.has_object(id).expect("存在性检查"));
}

#[test]
fn list_objects_filters_by_digest_prefix() {
    let (dir, backend) = backend();
    let first = blob(b"one");
    let second = blob(b"two");
    backend.put_object(first, b"one").expect("写入 one");
    backend.put_object(second, b"two").expect("写入 two");

    let all = backend.list_objects("").expect("列出全部");
    assert!(all.contains(&first) && all.contains(&second));
    assert_eq!(all.len(), 2);

    let exact = backend.list_objects(&first.hex()).expect("按完整摘要过滤");
    assert_eq!(exact, vec![first]);

    let shard = backend
        .list_objects(&first.hex()[..2])
        .expect("按分片前缀过滤");
    assert!(shard.contains(&first));

    // 残留的临时文件不会被当成对象。
    let hex = first.hex();
    fs::write(
        dir.path().join("objects").join(&hex[..2]).join(".tmp-abc"),
        b"junk",
    )
    .expect("写入残留临时文件");
    assert_eq!(backend.list_objects("").expect("重新列出").len(), 2);
}

#[test]
fn list_objects_rejects_escaping_prefix() {
    let (_dir, backend) = backend();

    for bad in [
        "..",
        ".",
        "ab/cd",
        "../../etc",
        "ab.",
        "a/b",
        "AB",
        "zz",
        "\\",
    ] {
        let err = backend
            .list_objects(bad)
            .err()
            .unwrap_or_else(|| panic!("前缀 `{bad}` 必须被拒绝"));
        assert_eq!(err.code(), "invalid_prefix", "前缀 `{bad}`");
        assert!(matches!(err, BackendError::InvalidPrefix { .. }));
    }

    // 超过摘要长度的前缀同样被拒绝。
    let err = backend
        .list_objects(&"a".repeat(65))
        .expect_err("超长前缀必须被拒绝");
    assert_eq!(err.code(), "invalid_prefix");
}

// ---------------------------------------------------------------------------
// Ref 与 CAS
// ---------------------------------------------------------------------------

#[test]
fn get_ref_before_first_publish_reports_ref_not_found() {
    let (_dir, backend) = backend();
    let workspace = WorkspaceId::generate();

    let err = backend.get_ref(workspace).expect_err("尚未发布");
    assert_eq!(err.code(), "ref_not_found");
    assert!(matches!(err, BackendError::RefNotFound(got) if got == workspace));
}

#[test]
fn first_cas_only_accepts_expected_revision_zero() {
    let (_dir, backend) = backend();
    let workspace = WorkspaceId::generate();
    let next = WorkspaceRef::initial(workspace).advance(SnapshotId::of(b"head-1"));

    let err = backend
        .compare_and_swap_ref(workspace, 1, &next)
        .expect_err("首次发布不接受非 0 的期望 revision");
    assert_eq!(err.code(), "cas_conflict");
    assert!(matches!(
        err,
        BackendError::CasConflict {
            expected: 1,
            observed: 0
        }
    ));
    // 失败的 CAS 不得留下任何 Ref。
    assert_eq!(
        backend.get_ref(workspace).unwrap_err().code(),
        "ref_not_found"
    );

    backend
        .compare_and_swap_ref(workspace, 0, &next)
        .expect("expected_revision 0 必须成功");
    assert_eq!(backend.get_ref(workspace).expect("读回 Ref"), next);
}

#[test]
fn stale_expected_revision_returns_conflict_with_observed_revision() {
    let (_dir, backend) = backend();
    let workspace = WorkspaceId::generate();
    let first = WorkspaceRef::initial(workspace).advance(SnapshotId::of(b"head-1"));
    let second = first.advance(SnapshotId::of(b"head-2"));
    backend
        .compare_and_swap_ref(workspace, 0, &first)
        .expect("第一次发布");
    backend
        .compare_and_swap_ref(workspace, 1, &second)
        .expect("第二次发布");

    let third = second.advance(SnapshotId::of(b"head-3"));
    let err = backend
        .compare_and_swap_ref(workspace, 1, &third)
        .expect_err("过期的期望 revision 必须冲突");
    assert!(matches!(
        err,
        BackendError::CasConflict {
            expected: 1,
            observed: 2
        }
    ));
    // 冲突不改变后端状态。
    assert_eq!(backend.get_ref(workspace).expect("读回 Ref"), second);
}

#[test]
fn non_monotonic_or_foreign_ref_is_rejected() {
    let (_dir, backend) = backend();
    let workspace = WorkspaceId::generate();
    let first = WorkspaceRef::initial(workspace).advance(SnapshotId::of(b"head-1"));
    backend
        .compare_and_swap_ref(workspace, 0, &first)
        .expect("第一次发布");

    // revision 没有前进：期望值与实际一致，但 next 不是合法后继。
    let err = backend
        .compare_and_swap_ref(workspace, 1, &first)
        .expect_err("revision 必须严格递增");
    assert_eq!(err.code(), "invalid_ref");
    assert!(matches!(err, BackendError::InvalidRef { .. }));

    // 另一个工作区的 Ref 不能写进本工作区。
    let other = WorkspaceId::generate();
    let foreign = WorkspaceRef::initial(other).advance(SnapshotId::of(b"head-x"));
    let err = backend
        .compare_and_swap_ref(workspace, 1, &foreign)
        .expect_err("工作区不匹配必须被拒绝");
    assert_eq!(err.code(), "invalid_ref");

    // 两次失败都不改变后端状态。
    assert_eq!(backend.get_ref(workspace).expect("读回 Ref"), first);
}

#[test]
fn concurrent_cas_has_exactly_one_winner() {
    let (_dir, backend) = backend();
    let workspace = WorkspaceId::generate();
    let base = WorkspaceRef::initial(workspace).advance(SnapshotId::of(b"base"));
    backend
        .compare_and_swap_ref(workspace, 0, &base)
        .expect("发布基准 Ref");

    let left = base.advance(SnapshotId::of(b"left"));
    let right = base.advance(SnapshotId::of(b"right"));

    let (left_result, right_result) = std::thread::scope(|scope| {
        let left_handle = scope.spawn(|| backend.compare_and_swap_ref(workspace, 1, &left));
        let right_handle = scope.spawn(|| backend.compare_and_swap_ref(workspace, 1, &right));
        (
            left_handle.join().expect("左线程未 panic"),
            right_handle.join().expect("右线程未 panic"),
        )
    });

    let winners = usize::from(left_result.is_ok()) + usize::from(right_result.is_ok());
    assert_eq!(winners, 1, "两个并发发布必须恰好有一个成功");

    let (winner, loser) = if left_result.is_ok() {
        (&left, right_result.expect_err("右线程必须冲突"))
    } else {
        (&right, left_result.expect_err("左线程必须冲突"))
    };
    assert!(
        matches!(
            loser,
            BackendError::CasConflict {
                expected: 1,
                observed: _
            }
        ),
        "并发失败方必须收到 CAS 冲突：{loser:?}"
    );
    assert_eq!(&backend.get_ref(workspace).expect("读回 Ref"), winner);
}

#[test]
fn leftover_temp_files_do_not_disturb_ref_reads() {
    let (dir, backend) = backend();
    let workspace = WorkspaceId::generate();
    let first = WorkspaceRef::initial(workspace).advance(SnapshotId::of(b"head-1"));
    backend
        .compare_and_swap_ref(workspace, 0, &first)
        .expect("第一次发布");

    // 模拟「Ref 替换写到一半被中断」：refs 目录里留下半截临时文件。
    let refs = dir.path().join("refs");
    fs::write(refs.join(".tmp-1a2b3c"), b"\xff\xfe half written").expect("写入残留临时文件");
    fs::write(refs.join(".tmp-deadbeef"), b"").expect("写入空的残留临时文件");

    // 旧 Ref 依然完整可读，且不受残留文件影响。
    assert_eq!(backend.get_ref(workspace).expect("读回旧 Ref"), first);

    // 后续 CAS 仍然正常前进到新 Ref。
    let second = first.advance(SnapshotId::of(b"head-2"));
    backend
        .compare_and_swap_ref(workspace, 1, &second)
        .expect("残留文件不阻碍新的发布");
    assert_eq!(backend.get_ref(workspace).expect("读回新 Ref"), second);
}

// ---------------------------------------------------------------------------
// 打开与自述
// ---------------------------------------------------------------------------

#[test]
fn open_rejects_directory_with_wrong_format_marker() {
    let dir = tempfile::tempdir().expect("创建临时目录");
    fs::write(dir.path().join("format"), "envsync-backend-format=2\n").expect("写入错误的格式标记");

    let err = LocalBackend::open(dir.path()).expect_err("格式版本不对必须失败");
    assert_eq!(err.code(), "format_mismatch");
    assert!(matches!(err, BackendError::FormatMismatch { .. }));
}

#[test]
fn open_is_idempotent_and_writes_format_marker() {
    let dir = tempfile::tempdir().expect("创建临时目录");
    LocalBackend::open(dir.path()).expect("首次打开");
    LocalBackend::open(dir.path()).expect("重复打开");

    assert_eq!(
        fs::read_to_string(dir.path().join("format")).expect("读取格式标记"),
        "envsync-backend-format=1\n"
    );
    for sub in ["objects", "refs", "locks"] {
        assert!(dir.path().join(sub).is_dir(), "缺少目录 {sub}");
    }
}

#[test]
fn errors_never_leak_absolute_paths() {
    let (dir, backend) = backend();
    let root = dir.path().to_string_lossy().into_owned();

    let missing = backend.get_object(blob(b"absent")).unwrap_err().to_string();
    let no_ref = backend
        .get_ref(WorkspaceId::generate())
        .unwrap_err()
        .to_string();
    let bad_prefix = backend.list_objects("../etc").unwrap_err().to_string();

    for message in [missing, no_ref, bad_prefix] {
        assert!(
            !message.contains(&root),
            "错误信息泄露了后端根路径：{message}"
        );
    }
}

#[test]
fn backend_is_object_safe_and_self_describing() {
    let (_dir, backend) = backend();

    fn describe(backend: &dyn Backend) -> BackendDescriptor {
        backend.describe()
    }

    let descriptor = describe(&backend);
    assert_eq!(descriptor.kind, "local");
    assert!(descriptor.supports_strong_cas);
}
