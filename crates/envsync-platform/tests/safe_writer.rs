//! 任务 9 的验收测试：安全写入、备份、删除与回滚收据。
//!
//! 所有写入都发生在临时授权根内；生产代码不接受不受约束的绝对路径。

use std::path::{Path, PathBuf};

use envsync_domain::{Digest32, OperationId, ResourceId, RollbackCapability};
use envsync_platform::capability::{AuthorizedRoot, RelativeTarget};
use envsync_platform::reader::FileReader;
use envsync_platform::writer::{
    DeleteRequest, FaultInjection, Receipt, SafeWriter, WriteRequest, TEMP_FILE_PREFIX,
};
use envsync_platform::PlatformError;

/// 测试夹具：一个授权根 + 一个独立的备份根。
struct Fixture {
    _root_dir: tempfile::TempDir,
    _backup_dir: tempfile::TempDir,
    root: AuthorizedRoot,
    backup_root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root_dir = tempfile::tempdir().expect("创建授权根目录");
        let backup_dir = tempfile::tempdir().expect("创建备份根目录");
        let root = AuthorizedRoot::open("home", root_dir.path()).expect("打开授权根");
        Fixture {
            backup_root: backup_dir.path().to_path_buf(),
            root,
            _root_dir: root_dir,
            _backup_dir: backup_dir,
        }
    }

    fn base(&self) -> &Path {
        self.root.path()
    }

    fn writer(&self) -> SafeWriter {
        SafeWriter::new(self.backup_root.clone())
    }

    fn writer_with_faults(&self, faults: FaultInjection) -> SafeWriter {
        self.writer().with_fault_injection(faults)
    }

    fn seed(&self, relative: &str, content: &[u8]) -> Digest32 {
        let path = self.base().join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("创建父目录");
        }
        std::fs::write(&path, content).expect("写入种子文件");
        FileReader::content_digest(content)
    }

    fn read(&self, relative: &str) -> Vec<u8> {
        std::fs::read(self.base().join(relative)).expect("读取目标文件")
    }

    fn exists(&self, relative: &str) -> bool {
        self.base().join(relative).exists()
    }
}

fn resource() -> ResourceId {
    ResourceId::parse("shell/zsh/main").expect("资源标识合法")
}

fn target(text: &str) -> RelativeTarget {
    RelativeTarget::parse(text).expect("相对目标合法")
}

/// 列出目录中遗留的临时文件。
fn temp_files(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("列目录")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(TEMP_FILE_PREFIX))
        })
        .collect();
    found.sort();
    found
}

fn write_request<'a>(
    operation: OperationId,
    resource: &'a ResourceId,
    root: &'a AuthorizedRoot,
    target: &'a RelativeTarget,
    content: &'a [u8],
    expected_before: Option<Digest32>,
) -> WriteRequest<'a> {
    WriteRequest {
        operation,
        resource,
        root,
        target,
        content,
        expected_before,
        unix_mode: None,
        secret: false,
    }
}

#[test]
fn temp_file_does_not_change_target_before_rename() {
    let fixture = Fixture::new();
    let original = fixture.seed("app.conf", b"original\n");
    let resource = resource();
    let target = target("app.conf");
    let operation = OperationId::generate();

    let writer = fixture.writer_with_faults(FaultInjection {
        fail_before_rename: true,
        ..FaultInjection::default()
    });
    let error = writer
        .apply_write(&write_request(
            operation,
            &resource,
            &fixture.root,
            &target,
            b"replacement\n",
            Some(original),
        ))
        .unwrap_err();
    assert!(
        matches!(error, PlatformError::FaultInjected { stage } if stage == "before_rename"),
        "{error:?}"
    );

    // 目标一个字节都没变。
    assert_eq!(fixture.read("app.conf"), b"original\n");

    // 新内容确实已经在同一个目录里 staged 好了，只是还没有替换目标。
    let staged = temp_files(fixture.base());
    assert_eq!(staged.len(), 1, "应当恰好有一个同目录临时文件：{staged:?}");
    assert_eq!(std::fs::read(&staged[0]).unwrap(), b"replacement\n");
}

#[test]
fn successful_replace_matches_digest_and_permissions() {
    let fixture = Fixture::new();
    let original = fixture.seed("app.conf", b"original\n");
    let resource = resource();
    let target = target("app.conf");
    let operation = OperationId::generate();
    let writer = fixture.writer();

    let mut request = write_request(
        operation,
        &resource,
        &fixture.root,
        &target,
        b"replacement\n",
        Some(original),
    );
    request.unix_mode = Some(0o640);

    let receipt = writer.apply_write(&request).expect("写入成功");

    assert_eq!(fixture.read("app.conf"), b"replacement\n");
    assert_eq!(
        receipt.applied_digest,
        Some(FileReader::content_digest(b"replacement\n"))
    );
    assert_eq!(receipt.original_digest, Some(original));
    assert_eq!(receipt.guarantee, RollbackCapability::Exact);
    assert_eq!(receipt.resource, resource);
    assert!(
        temp_files(fixture.base()).is_empty(),
        "临时文件应当已被 rename 掉"
    );

    // verify 用同一套读取逻辑复核。
    writer
        .verify(&fixture.root, &target, receipt.applied_digest)
        .expect("verify 通过");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(fixture.base().join("app.conf"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o640, "权限应当来自请求");
    }
}

#[cfg(unix)]
#[test]
fn secret_resource_defaults_to_owner_only_mode() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let resource = resource();
    let target = target("token.env");
    let writer = fixture.writer();

    let mut request = write_request(
        OperationId::generate(),
        &resource,
        &fixture.root,
        &target,
        b"TOKEN=abc\n",
        None,
    );
    request.secret = true;
    writer.apply_write(&request).expect("写入秘密资源成功");

    let mode = std::fs::metadata(fixture.base().join("token.env"))
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(mode, 0o600, "秘密资源未指定 mode 时默认 0o600");
}

#[test]
fn original_file_is_backed_up_to_deterministic_path() {
    let fixture = Fixture::new();
    let original = fixture.seed("nested/app.conf", b"original\n");
    let resource = resource();
    let target = target("nested/app.conf");
    let operation = OperationId::generate();
    let writer = fixture.writer();

    let receipt = writer
        .apply_write(&write_request(
            operation,
            &resource,
            &fixture.root,
            &target,
            b"replacement\n",
            Some(original),
        ))
        .expect("写入成功");

    let expected = writer.backup_path_for(operation, &resource);
    assert_eq!(receipt.backup_path.as_deref(), Some(expected.as_path()));
    assert_eq!(
        expected,
        fixture
            .backup_root
            .join(operation.to_filename())
            .join("shell__zsh__main")
    );
    assert_eq!(std::fs::read(&expected).unwrap(), b"original\n");
    assert_eq!(
        FileReader::content_digest(&std::fs::read(&expected).unwrap()),
        original
    );
}

#[test]
fn creating_new_file_records_absent_original() {
    let fixture = Fixture::new();
    let resource = resource();
    let target = target("brand-new.conf");
    let writer = fixture.writer();

    let receipt = writer
        .apply_write(&write_request(
            OperationId::generate(),
            &resource,
            &fixture.root,
            &target,
            b"new\n",
            None,
        ))
        .expect("创建新文件成功");

    assert_eq!(receipt.original_digest, None);
    assert_eq!(receipt.backup_path, None);
    assert_eq!(fixture.read("brand-new.conf"), b"new\n");
}

#[test]
fn delete_always_backs_up_first() {
    let fixture = Fixture::new();
    let original = fixture.seed("obsolete.conf", b"bye\n");
    let resource = resource();
    let target = target("obsolete.conf");
    let operation = OperationId::generate();
    let writer = fixture.writer();

    let receipt = writer
        .apply_delete(&DeleteRequest {
            operation,
            resource: &resource,
            root: &fixture.root,
            target: &target,
            expected_before: Some(original),
        })
        .expect("删除成功");

    assert!(!fixture.exists("obsolete.conf"), "目标应当已被删除");
    let backup = receipt.backup_path.clone().expect("删除必须留下备份");
    assert_eq!(backup, writer.backup_path_for(operation, &resource));
    assert_eq!(std::fs::read(&backup).unwrap(), b"bye\n");
    assert_eq!(receipt.original_digest, Some(original));
    assert_eq!(receipt.applied_digest, None);
}

#[test]
fn deleting_missing_target_is_idempotent_success() {
    let fixture = Fixture::new();
    let resource = resource();
    let target = target("never-existed.conf");
    let operation = OperationId::generate();
    let writer = fixture.writer();

    let request = DeleteRequest {
        operation,
        resource: &resource,
        root: &fixture.root,
        target: &target,
        expected_before: None,
    };
    let first = writer.apply_delete(&request).expect("首次删除幂等成功");
    let second = writer.apply_delete(&request).expect("重复删除同样成功");

    assert_eq!(first, second);
    assert_eq!(first.backup_path, None);
    assert_eq!(first.original_digest, None);
    assert_eq!(first.applied_digest, None);
    assert!(!fixture.backup_root.join(operation.to_filename()).exists());
}

#[test]
fn stale_digest_before_write_is_rejected() {
    let fixture = Fixture::new();
    fixture.seed("app.conf", b"current\n");
    let resource = resource();
    let target = target("app.conf");
    let writer = fixture.writer();
    let stale = FileReader::content_digest(b"what the plan saw\n");

    let error = writer
        .apply_write(&write_request(
            OperationId::generate(),
            &resource,
            &fixture.root,
            &target,
            b"new\n",
            Some(stale),
        ))
        .unwrap_err();

    match error {
        PlatformError::StaleObservation { expected, actual } => {
            assert_eq!(expected, Some(stale));
            assert_eq!(actual, Some(FileReader::content_digest(b"current\n")));
        }
        other => panic!("期望 StaleObservation，实际 {other:?}"),
    }
    assert_eq!(fixture.read("app.conf"), b"current\n", "失败不得改动目标");
    assert!(temp_files(fixture.base()).is_empty());
}

#[test]
fn expecting_absent_but_target_exists_is_stale() {
    let fixture = Fixture::new();
    fixture.seed("app.conf", b"surprise\n");
    let resource = resource();
    let target = target("app.conf");
    let writer = fixture.writer();

    let error = writer
        .apply_write(&write_request(
            OperationId::generate(),
            &resource,
            &fixture.root,
            &target,
            b"new\n",
            None,
        ))
        .unwrap_err();
    assert!(
        matches!(
            error,
            PlatformError::StaleObservation {
                expected: None,
                actual: Some(_)
            }
        ),
        "{error:?}"
    );
    assert_eq!(fixture.read("app.conf"), b"surprise\n");
}

#[test]
fn rollback_restores_original_bytes() {
    let fixture = Fixture::new();
    let original = fixture.seed("app.conf", b"original\n");
    let resource = resource();
    let target = target("app.conf");
    let writer = fixture.writer();

    let receipt = writer
        .apply_write(&write_request(
            OperationId::generate(),
            &resource,
            &fixture.root,
            &target,
            b"replacement\n",
            Some(original),
        ))
        .expect("写入成功");
    assert_eq!(fixture.read("app.conf"), b"replacement\n");

    writer
        .rollback(&receipt, &fixture.root, &target)
        .expect("回滚成功");
    assert_eq!(fixture.read("app.conf"), b"original\n");
    writer
        .verify(&fixture.root, &target, Some(original))
        .expect("回滚后 verify 通过");
    assert!(temp_files(fixture.base()).is_empty());
}

#[test]
fn rollback_of_created_file_removes_it() {
    let fixture = Fixture::new();
    let resource = resource();
    let target = target("created.conf");
    let writer = fixture.writer();

    let receipt = writer
        .apply_write(&write_request(
            OperationId::generate(),
            &resource,
            &fixture.root,
            &target,
            b"created\n",
            None,
        ))
        .expect("创建成功");
    writer
        .rollback(&receipt, &fixture.root, &target)
        .expect("回滚成功");

    assert!(!fixture.exists("created.conf"), "回滚应当删除新建文件");
    writer
        .verify(&fixture.root, &target, None)
        .expect("回滚后目标不存在");
}

#[test]
fn rollback_refused_when_target_changed_after_apply() {
    let fixture = Fixture::new();
    let original = fixture.seed("app.conf", b"original\n");
    let resource = resource();
    let target = target("app.conf");
    let writer = fixture.writer();

    let receipt = writer
        .apply_write(&write_request(
            OperationId::generate(),
            &resource,
            &fixture.root,
            &target,
            b"replacement\n",
            Some(original),
        ))
        .expect("写入成功");

    // 用户在应用之后又改了这个文件：回滚会抹掉他的修改，必须拒绝。
    std::fs::write(fixture.base().join("app.conf"), b"user edit\n").expect("模拟用户修改");

    let error = writer
        .rollback(&receipt, &fixture.root, &target)
        .unwrap_err();
    assert!(
        matches!(error, PlatformError::RollbackRefused { .. }),
        "{error:?}"
    );
    assert_eq!(
        fixture.read("app.conf"),
        b"user edit\n",
        "拒绝后现场必须原样保留"
    );
    assert!(!error.to_string().contains(std::path::MAIN_SEPARATOR));
}

#[test]
fn rollback_refused_when_backup_is_missing() {
    let fixture = Fixture::new();
    let original = fixture.seed("app.conf", b"original\n");
    let resource = resource();
    let target = target("app.conf");
    let writer = fixture.writer();

    let receipt = writer
        .apply_write(&write_request(
            OperationId::generate(),
            &resource,
            &fixture.root,
            &target,
            b"replacement\n",
            Some(original),
        ))
        .expect("写入成功");

    std::fs::remove_file(receipt.backup_path.as_ref().unwrap()).expect("删除备份");
    let error = writer
        .rollback(&receipt, &fixture.root, &target)
        .unwrap_err();
    assert!(
        matches!(error, PlatformError::RollbackRefused { .. }),
        "{error:?}"
    );
    assert_eq!(fixture.read("app.conf"), b"replacement\n", "保留可诊断状态");

    // 收据里根本没有备份路径时同样拒绝。
    let orphan = Receipt {
        backup_path: None,
        ..receipt.clone()
    };
    assert!(matches!(
        writer.rollback(&orphan, &fixture.root, &target),
        Err(PlatformError::RollbackRefused { .. })
    ));
}

#[test]
fn rollback_refused_when_backup_content_is_corrupted() {
    let fixture = Fixture::new();
    let original = fixture.seed("app.conf", b"original\n");
    let resource = resource();
    let target = target("app.conf");
    let writer = fixture.writer();

    let receipt = writer
        .apply_write(&write_request(
            OperationId::generate(),
            &resource,
            &fixture.root,
            &target,
            b"replacement\n",
            Some(original),
        ))
        .expect("写入成功");

    std::fs::write(receipt.backup_path.as_ref().unwrap(), b"corrupted\n").expect("篡改备份");
    let error = writer
        .rollback(&receipt, &fixture.root, &target)
        .unwrap_err();
    assert!(
        matches!(error, PlatformError::RollbackRefused { .. }),
        "{error:?}"
    );
    assert_eq!(fixture.read("app.conf"), b"replacement\n");
}

#[test]
fn injected_rename_failure_keeps_target_and_backup_as_evidence() {
    let fixture = Fixture::new();
    let original = fixture.seed("app.conf", b"original\n");
    let resource = resource();
    let target = target("app.conf");
    let operation = OperationId::generate();

    let writer = fixture.writer_with_faults(FaultInjection {
        fail_before_rename: true,
        ..FaultInjection::default()
    });
    let error = writer
        .apply_write(&write_request(
            operation,
            &resource,
            &fixture.root,
            &target,
            b"replacement\n",
            Some(original),
        ))
        .unwrap_err();
    assert!(
        matches!(error, PlatformError::FaultInjected { .. }),
        "{error:?}"
    );

    // 可恢复证据三件套：目标原样、备份完好、临时文件仍在。
    assert_eq!(fixture.read("app.conf"), b"original\n");
    let backup = writer.backup_path_for(operation, &resource);
    assert!(backup.exists(), "备份必须保留");
    assert_eq!(std::fs::read(&backup).unwrap(), b"original\n");
    assert_eq!(temp_files(fixture.base()).len(), 1);

    // 换一个没有注入故障的 writer 重放同一动作，应当照常成功。
    let healthy = fixture.writer();
    healthy
        .apply_write(&write_request(
            operation,
            &resource,
            &fixture.root,
            &target,
            b"replacement\n",
            Some(original),
        ))
        .expect("重放成功");
    assert_eq!(fixture.read("app.conf"), b"replacement\n");
}

#[test]
fn injected_staging_failure_cleans_up_and_leaves_no_backup() {
    let fixture = Fixture::new();
    let original = fixture.seed("app.conf", b"original\n");
    let resource = resource();
    let target = target("app.conf");
    let operation = OperationId::generate();

    let writer = fixture.writer_with_faults(FaultInjection {
        fail_after_temp_write: true,
        ..FaultInjection::default()
    });
    let error = writer
        .apply_write(&write_request(
            operation,
            &resource,
            &fixture.root,
            &target,
            b"replacement\n",
            Some(original),
        ))
        .unwrap_err();
    assert!(
        matches!(error, PlatformError::FaultInjected { .. }),
        "{error:?}"
    );

    assert_eq!(fixture.read("app.conf"), b"original\n");
    assert!(
        temp_files(fixture.base()).is_empty(),
        "staging 失败应当清理临时文件"
    );
    assert!(!writer.backup_path_for(operation, &resource).exists());
}

#[test]
fn injected_delete_failure_keeps_backup() {
    let fixture = Fixture::new();
    let original = fixture.seed("obsolete.conf", b"bye\n");
    let resource = resource();
    let target = target("obsolete.conf");
    let operation = OperationId::generate();

    let writer = fixture.writer_with_faults(FaultInjection {
        fail_before_rename: true,
        ..FaultInjection::default()
    });
    let error = writer
        .apply_delete(&DeleteRequest {
            operation,
            resource: &resource,
            root: &fixture.root,
            target: &target,
            expected_before: Some(original),
        })
        .unwrap_err();
    assert!(
        matches!(error, PlatformError::FaultInjected { .. }),
        "{error:?}"
    );

    assert_eq!(fixture.read("obsolete.conf"), b"bye\n", "删除未发生");
    assert!(
        writer.backup_path_for(operation, &resource).exists(),
        "备份必须在删除之前完成并保留"
    );
}

#[test]
fn writes_are_confined_to_the_authorized_root() {
    let fixture = Fixture::new();
    let resource = resource();
    let writer = fixture.writer();

    // 文本层就被拒绝，根本不会碰文件系统。
    assert!(matches!(
        RelativeTarget::parse("../escape.conf"),
        Err(PlatformError::InvalidTarget(_))
    ));

    // 中间目录是符号链接时，写入同样被拒绝。
    #[cfg(unix)]
    {
        let outside = tempfile::tempdir().expect("创建外部目录");
        std::os::unix::fs::symlink(outside.path(), fixture.base().join("link"))
            .expect("创建目录符号链接");
        let target = target("link/pwned.conf");
        let error = writer
            .apply_write(&write_request(
                OperationId::generate(),
                &resource,
                &fixture.root,
                &target,
                b"pwned\n",
                None,
            ))
            .unwrap_err();
        assert!(
            matches!(error, PlatformError::SymlinkRejected { .. }),
            "{error:?}"
        );
        assert!(
            !outside.path().join("pwned.conf").exists(),
            "绝不能写到根外"
        );
    }
    #[cfg(not(unix))]
    let _ = (&writer, &resource);
}

#[test]
fn oversized_content_is_rejected_before_touching_target() {
    let fixture = Fixture::new();
    let original = fixture.seed("app.conf", b"original\n");
    let resource = resource();
    let target = target("app.conf");
    let writer = fixture.writer().with_max_bytes(16);

    let error = writer
        .apply_write(&write_request(
            OperationId::generate(),
            &resource,
            &fixture.root,
            &target,
            &[b'x'; 64],
            Some(original),
        ))
        .unwrap_err();
    assert!(
        matches!(
            error,
            PlatformError::TooLarge {
                limit: 16,
                actual: 64
            }
        ),
        "{error:?}"
    );
    assert_eq!(fixture.read("app.conf"), b"original\n");
    assert!(temp_files(fixture.base()).is_empty());
}

#[test]
fn verify_reports_mismatch_without_leaking_paths() {
    let fixture = Fixture::new();
    let original = fixture.seed("app.conf", b"original\n");
    let target = target("app.conf");
    let writer = fixture.writer();

    writer
        .verify(&fixture.root, &target, Some(original))
        .expect("摘要一致");

    let error = writer
        .verify(&fixture.root, &target, Some(Digest32::ZERO))
        .unwrap_err();
    assert!(
        matches!(error, PlatformError::VerificationFailed { .. }),
        "{error:?}"
    );
    assert!(!error.to_string().contains(std::path::MAIN_SEPARATOR));
}
