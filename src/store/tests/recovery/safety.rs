use std::io;

use super::super::*;

#[test]
fn cleanup_failure_keeps_recoverable_file_and_reports_path() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let file = ".noirpass-quarantine-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-1.gpg";
    let path = store.secrets_dir.join(file);
    fs::write(&path, b"ciphertext").unwrap();

    let err = Store::remove_recovery_file(&path, "metadata deletion committed", |_| {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "injected cleanup failure",
        ))
    })
    .unwrap_err();

    assert!(err.to_string().contains("metadata deletion committed"));
    assert!(err.to_string().contains(path.to_string_lossy().as_ref()));
    assert!(path.exists());
    assert_eq!(
        store.check_integrity().unwrap().recovery_secret_files,
        vec![file.to_string()]
    );
}

#[test]
fn recovery_symlink_is_rejected_without_reading_target() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside_ciphertext = outside.path().join("ciphertext.gpg");
    fs::write(&outside_ciphertext, b"outside ciphertext").unwrap();
    let outside_before = fs::read(&outside_ciphertext).unwrap();
    let recovery = store
        .secrets_dir
        .join(".noirpass-backup-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-0123456789abcdef.gpg");
    std::os::unix::fs::symlink(&outside_ciphertext, &recovery).unwrap();

    assert!(store.recover_interrupted_operations().is_err());
    assert_eq!(fs::read(&outside_ciphertext).unwrap(), outside_before);
    assert!(
        fs::symlink_metadata(recovery)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn startup_recovery_rejects_symlinked_secrets_directory_without_reading_target() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside_marker = outside.path().join("keep.txt");
    fs::write(&outside_marker, b"outside").unwrap();
    let secrets = store.secrets_dir.clone();
    fs::remove_dir(&secrets).unwrap();
    std::os::unix::fs::symlink(outside.path(), &secrets).unwrap();

    assert!(store.recover_interrupted_operations().is_err());
    assert_eq!(fs::read(&outside_marker).unwrap(), b"outside");
    assert!(
        fs::symlink_metadata(secrets)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}
