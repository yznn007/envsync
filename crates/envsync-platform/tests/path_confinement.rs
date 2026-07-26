//! 任务 5 的验收测试：能力约束的安全读取与路径边界。
//!
//! 这些测试全部在临时授权根内执行，绝不使用不受约束的绝对路径。

use std::path::{Path, PathBuf};

use envsync_domain::{ObservedState, ResourceId, ResourcePolicy};
use envsync_platform::capability::{AuthorizedRoot, RelativeTarget, RootRegistry, TargetError};
use envsync_platform::reader::FileReader;
use envsync_platform::PlatformError;

/// 构造一个临时授权根。
fn authorized_root() -> (tempfile::TempDir, AuthorizedRoot) {
    let dir = tempfile::tempdir().expect("创建临时目录");
    let root = AuthorizedRoot::open("home", dir.path()).expect("打开授权根");
    (dir, root)
}

/// 在临时目录内写一个文件，返回它的绝对路径（仅测试内部使用）。
fn write_file(base: &Path, relative: &str, content: &[u8]) -> PathBuf {
    let path = base.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("创建父目录");
    }
    std::fs::write(&path, content).expect("写入测试文件");
    path
}

fn resource() -> ResourceId {
    ResourceId::parse("shell/zsh/main").expect("资源标识合法")
}

/// 校验错误信息里没有绝对路径。
fn assert_no_absolute_path(text: &str) {
    assert!(
        !text.contains(std::path::MAIN_SEPARATOR),
        "错误信息不得包含路径分隔符：{text}"
    );
    assert!(
        !text.contains("/tmp") && !text.contains("C:\\"),
        "错误信息不得包含绝对路径：{text}"
    );
}

#[test]
fn reads_regular_file_inside_authorized_root() {
    let (dir, root) = authorized_root();
    write_file(dir.path(), ".config/envsync/demo.toml", b"key = 1\n");

    let target = RelativeTarget::parse(".config/envsync/demo.toml").unwrap();
    let outcome =
        FileReader::read_bytes(&root, &target, &ResourcePolicy::default()).expect("读取成功");

    assert_eq!(outcome.bytes, b"key = 1\n");
    assert_eq!(outcome.size, 8);
    assert_eq!(outcome.digest, FileReader::content_digest(b"key = 1\n"));
    assert!(outcome.mtime_unix_ms.is_some(), "常见文件系统都提供 mtime");

    let observation = FileReader::observe(
        &root,
        &target,
        &resource(),
        &ResourcePolicy::default(),
        1_700_000_000_000,
    );
    let present = match &observation.state {
        ObservedState::Present(file) => file,
        other => panic!("期望 present，实际 {}", other.kind()),
    };
    assert_eq!(present.content_digest, outcome.digest);
    assert_eq!(present.size, 8);
    assert_eq!(observation.observed_at_unix_ms, 1_700_000_000_000);
    assert_eq!(observation.resource, resource());
}

#[test]
fn rejects_absolute_dotdot_nul_drive_unc_and_device_names() {
    let cases: &[(&str, TargetError)] = &[
        ("/etc/passwd", TargetError::Absolute),
        ("../../etc/passwd", TargetError::DotSegment),
        ("a/../../b", TargetError::DotSegment),
        ("bad\0name", TargetError::NulByte),
        ("C:/Windows/System32/config", TargetError::DriveLetter),
        ("//server/share/file", TargetError::UncPrefix),
        ("\\\\server\\share\\file", TargetError::UncPrefix),
        ("CON", TargetError::ReservedDeviceName("CON".to_owned())),
        ("NUL", TargetError::ReservedDeviceName("NUL".to_owned())),
        ("PRN", TargetError::ReservedDeviceName("PRN".to_owned())),
        ("AUX", TargetError::ReservedDeviceName("AUX".to_owned())),
        (
            "sub/COM1.txt",
            TargetError::ReservedDeviceName("COM1.txt".to_owned()),
        ),
        (
            "sub/lpt9",
            TargetError::ReservedDeviceName("lpt9".to_owned()),
        ),
    ];

    for (text, expected) in cases {
        match RelativeTarget::parse(text) {
            Err(PlatformError::InvalidTarget(actual)) => {
                assert_eq!(&actual, expected, "目标 {text:?} 的拒绝原因不符");
                assert_no_absolute_path(&actual.to_string());
            }
            other => panic!("目标 {text:?} 应当被拒绝，实际 {other:?}"),
        }
    }
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_intermediate_directory() {
    let (dir, root) = authorized_root();
    // 真实内容放在授权根之外，模拟“中间目录是通往根外的符号链接”。
    let outside = tempfile::tempdir().expect("创建外部目录");
    std::fs::write(outside.path().join("secret.txt"), b"outside\n").expect("写入外部文件");
    std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).expect("创建目录符号链接");

    let target = RelativeTarget::parse("link/secret.txt").unwrap();
    let error = FileReader::read_bytes(&root, &target, &ResourcePolicy::default()).unwrap_err();
    match &error {
        PlatformError::SymlinkRejected { index, segment, .. } => {
            assert_eq!(*index, 0);
            assert_eq!(segment, "link");
        }
        other => panic!("期望 SymlinkRejected，实际 {other:?}"),
    }
    assert_no_absolute_path(&error.to_string());

    let observation =
        FileReader::observe(&root, &target, &resource(), &ResourcePolicy::default(), 1);
    match &observation.state {
        ObservedState::Excluded { reason } => assert_no_absolute_path(reason),
        other => panic!("符号链接穿越应当是 excluded，实际 {}", other.kind()),
    }
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_final_file_even_inside_root() {
    let (dir, root) = authorized_root();
    write_file(dir.path(), "real.txt", b"real\n");
    // 即使链接目标就在授权根内也拒绝：符号链接的指向随时可能被改到根外。
    std::os::unix::fs::symlink(dir.path().join("real.txt"), dir.path().join("alias.txt"))
        .expect("创建文件符号链接");

    let target = RelativeTarget::parse("alias.txt").unwrap();
    let error = FileReader::read_bytes(&root, &target, &ResourcePolicy::default()).unwrap_err();
    match &error {
        PlatformError::SymlinkRejected { segment, index, .. } => {
            assert_eq!(segment, "alias.txt");
            assert_eq!(*index, 0);
        }
        other => panic!("期望 SymlinkRejected，实际 {other:?}"),
    }
    assert_no_absolute_path(&error.to_string());
}

#[test]
fn missing_target_is_absent_not_unreadable() {
    let (_dir, root) = authorized_root();

    for text in ["missing.txt", "missing-dir/missing.txt"] {
        let target = RelativeTarget::parse(text).unwrap();
        let observation =
            FileReader::observe(&root, &target, &resource(), &ResourcePolicy::default(), 7);
        assert_eq!(
            observation.state,
            ObservedState::Absent,
            "目标 {text} 应当是 absent"
        );

        let error = FileReader::read_bytes(&root, &target, &ResourcePolicy::default()).unwrap_err();
        assert!(error.is_not_found(), "缺失应当是 NotFound，实际 {error:?}");
    }
}

#[cfg(unix)]
#[test]
fn permission_error_is_unreadable_not_absent() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, root) = authorized_root();
    let path = write_file(dir.path(), "locked.txt", b"secret\n");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("清空权限位");

    // 以 root 运行时权限位不生效，此断言无意义，直接跳过（不需要任何 unsafe 检测手段）。
    if std::fs::File::open(&path).is_ok() {
        eprintln!("跳过：当前用户可以绕过权限位（很可能以 root 运行）");
        return;
    }

    let target = RelativeTarget::parse("locked.txt").unwrap();
    let observation =
        FileReader::observe(&root, &target, &resource(), &ResourcePolicy::default(), 11);
    match &observation.state {
        ObservedState::Unreadable { reason } => assert_no_absolute_path(reason),
        other => panic!("权限错误绝不能伪装成 {}", other.kind()),
    }

    let error = FileReader::read_bytes(&root, &target, &ResourcePolicy::default()).unwrap_err();
    assert_eq!(error.io_kind(), Some(std::io::ErrorKind::PermissionDenied));
    assert!(!error.is_not_found(), "权限错误不得被当成 NotFound");
    assert_no_absolute_path(&error.to_string());
}

#[test]
fn oversized_target_errors_without_truncating() {
    let (dir, root) = authorized_root();
    let content = vec![b'x'; 4096];
    write_file(dir.path(), "big.bin", &content);

    let policy = ResourcePolicy {
        max_bytes: 1024,
        ..ResourcePolicy::default()
    };
    let target = RelativeTarget::parse("big.bin").unwrap();
    let error = FileReader::read_bytes(&root, &target, &policy).unwrap_err();
    match error {
        PlatformError::TooLarge { limit, actual } => {
            assert_eq!(limit, 1024);
            assert_eq!(actual, 4096);
        }
        other => panic!("期望 TooLarge，实际 {other:?}"),
    }

    // 观察时降级为 unreadable，绝不是 present（那会让计划以为自己知道文件内容）。
    let observation = FileReader::observe(&root, &target, &resource(), &policy, 3);
    match &observation.state {
        ObservedState::Unreadable { reason } => {
            assert!(reason.contains("4096"), "reason 应说明实际大小：{reason}");
            assert_no_absolute_path(reason);
        }
        other => panic!("超限应当是 unreadable，实际 {}", other.kind()),
    }

    // 文件本身没有被截断。
    assert_eq!(
        std::fs::metadata(dir.path().join("big.bin")).unwrap().len(),
        4096
    );

    // 放宽上限后可以完整读出，证明失败路径没有破坏内容。
    let relaxed = ResourcePolicy::default();
    let outcome = FileReader::read_bytes(&root, &target, &relaxed).expect("放宽上限后可读");
    assert_eq!(outcome.bytes.len(), 4096);
}

#[test]
fn directory_target_is_unreadable() {
    let (dir, root) = authorized_root();
    std::fs::create_dir_all(dir.path().join("some-dir")).expect("创建目录");

    let target = RelativeTarget::parse("some-dir").unwrap();
    let error = FileReader::read_bytes(&root, &target, &ResourcePolicy::default()).unwrap_err();
    assert!(matches!(error, PlatformError::NotAFile { .. }), "{error:?}");
    assert_no_absolute_path(&error.to_string());

    let observation =
        FileReader::observe(&root, &target, &resource(), &ResourcePolicy::default(), 5);
    assert_eq!(observation.state.kind(), "unreadable");
}

#[test]
fn unregistered_root_alias_is_rejected() {
    let (dir, root) = authorized_root();
    let mut registry = RootRegistry::new();
    registry.insert(root);
    assert_eq!(registry.len(), 1);
    assert_eq!(registry.aliases().collect::<Vec<_>>(), vec!["home"]);
    assert!(registry.get("home").is_ok());

    let error = registry.get("work").unwrap_err();
    assert!(
        matches!(error, PlatformError::UnknownRoot { .. }),
        "{error:?}"
    );
    assert_no_absolute_path(&error.to_string());
    drop(dir);
}

#[test]
fn root_must_be_an_existing_directory() {
    let dir = tempfile::tempdir().expect("创建临时目录");
    let file = write_file(dir.path(), "not-a-dir", b"x");

    let error = AuthorizedRoot::open("home", &file).unwrap_err();
    assert!(
        matches!(error, PlatformError::RootNotDirectory { .. }),
        "{error:?}"
    );
    assert_no_absolute_path(&error.to_string());

    let missing = AuthorizedRoot::open("home", &dir.path().join("nope")).unwrap_err();
    assert!(
        matches!(missing, PlatformError::RootUnavailable { .. }),
        "{missing:?}"
    );
    assert_no_absolute_path(&missing.to_string());
}

#[test]
fn resolved_path_never_leaks_absolute_path_in_debug() {
    let (dir, root) = authorized_root();
    write_file(dir.path(), "sub/file.txt", b"x");
    let target = RelativeTarget::parse("sub/file.txt").unwrap();
    let resolved = root.resolve(&target).expect("解析成功");

    assert_eq!(resolved.file_name(), "file.txt");
    assert_eq!(resolved.file_index(), 1);
    assert_eq!(resolved.display_target(), "home:sub/file.txt");
    // 绝对路径只通过显式 API 暴露，Debug 输出里没有。
    assert!(resolved.absolute_path().is_absolute());
    let debug = format!("{resolved:?}");
    assert!(
        !debug.contains(dir.path().to_str().unwrap()),
        "Debug 输出泄露了绝对路径：{debug}"
    );
    assert!(!format!("{root:?}").contains(dir.path().to_str().unwrap()));
}
