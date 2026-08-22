use super::super::{
    KEYS_DIR, LIFECYCLE_LOCK_FILE, LifecycleLock, SECRETS_DIR, config_path, deinit,
    init_from_bytes, recipient_cert_path,
};
use crate::gpg::test_support::TestGnupg;
use crate::store::Store;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::time::{Duration, Instant};

#[test]
fn deinit_removes_known_state_and_preserves_unknown_files() {
    let gnupg = TestGnupg::new();
    let tmp = tempfile::tempdir().unwrap();
    init_from_bytes(tmp.path(), &gnupg.export_public_binary()).unwrap();

    let item_id = "0123456789abcdef0123456789abcdef";
    let recovery = format!(".noirpass-create-{item_id}-0123456789abcdef.gpg");
    drop(Store::open(tmp.path()).unwrap());
    fs::create_dir_all(tmp.path().join(SECRETS_DIR)).unwrap();
    fs::write(
        tmp.path().join(SECRETS_DIR).join(format!("{item_id}.gpg")),
        b"secret",
    )
    .unwrap();
    fs::write(tmp.path().join(SECRETS_DIR).join(recovery), b"recovery").unwrap();
    fs::write(tmp.path().join(SECRETS_DIR).join("keep.txt"), b"unrelated").unwrap();
    fs::write(
        tmp.path()
            .join(KEYS_DIR)
            .join(".noirpass-tmp-0123456789abcdef"),
        b"temporary",
    )
    .unwrap();
    fs::write(
        tmp.path().join(".noirpass-tmp-0123456789abcdef"),
        b"temporary",
    )
    .unwrap();
    fs::write(tmp.path().join("keep.txt"), b"unrelated").unwrap();

    deinit(tmp.path()).unwrap();

    assert!(!config_path(tmp.path()).exists());
    assert!(!recipient_cert_path(tmp.path()).exists());
    assert!(!tmp.path().join("index.redb").exists());
    assert!(
        !tmp.path()
            .join(SECRETS_DIR)
            .join(format!("{item_id}.gpg"))
            .exists()
    );
    assert!(
        !tmp.path()
            .join(SECRETS_DIR)
            .join(format!(".noirpass-create-{item_id}-0123456789abcdef.gpg"))
            .exists()
    );
    assert!(tmp.path().join(SECRETS_DIR).join("keep.txt").exists());
    assert!(tmp.path().join("keep.txt").exists());
    assert!(
        !tmp.path()
            .join(KEYS_DIR)
            .join(".noirpass-tmp-0123456789abcdef")
            .exists()
    );
    assert!(!tmp.path().join(".noirpass-tmp-0123456789abcdef").exists());
}

#[test]
fn lifecycle_lock_rejects_symlinked_lock_file() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside_file = outside.path().join("outside");
    fs::write(&outside_file, b"outside").unwrap();
    symlink(&outside_file, tmp.path().join(LIFECYCLE_LOCK_FILE)).unwrap();

    let err = LifecycleLock::acquire(tmp.path()).unwrap_err();

    assert!(err.to_string().contains("symlink"));
    assert_eq!(fs::read(outside_file).unwrap(), b"outside");
}

#[test]
fn lifecycle_contender_does_not_normalize_permissions_before_flock() {
    let tmp = tempfile::tempdir().unwrap();
    let lock_path = tmp.path().join(LIFECYCLE_LOCK_FILE);
    let owner = LifecycleLock::acquire(tmp.path()).unwrap();
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();

    let contender_path = tmp.path().to_path_buf();
    let contender = std::thread::spawn(move || LifecycleLock::acquire(&contender_path));
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut open_descriptors = 0;
    while Instant::now() < deadline {
        open_descriptors = fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|entry| fs::read_link(entry.path()).is_ok_and(|path| path == lock_path))
            .count();
        if open_descriptors >= 2 {
            break;
        }
        std::thread::yield_now();
    }
    let mode_while_contended = fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;

    drop(owner);
    let contender = contender.join().unwrap().unwrap();
    drop(contender);
    let mode_after_acquisition = fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;

    assert!(open_descriptors >= 2);
    assert_eq!(mode_while_contended, 0o644);
    assert_eq!(mode_after_acquisition, 0o600);
}

#[test]
fn lifecycle_contender_does_not_normalize_directory_permissions_before_flock() {
    let tmp = tempfile::tempdir().unwrap();
    let store_path = tmp.path().join("store");
    let owner = LifecycleLock::acquire(&store_path).unwrap();
    assert_eq!(
        fs::metadata(&store_path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    fs::set_permissions(&store_path, fs::Permissions::from_mode(0o750)).unwrap();

    let lock_path = store_path.join(LIFECYCLE_LOCK_FILE);
    let contender_path = store_path.clone();
    let contender = std::thread::spawn(move || LifecycleLock::acquire(&contender_path));
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut open_descriptors = 0;
    while Instant::now() < deadline {
        open_descriptors = fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|entry| fs::read_link(entry.path()).is_ok_and(|path| path == lock_path))
            .count();
        if open_descriptors >= 2 {
            break;
        }
        std::thread::yield_now();
    }
    let mode_while_contended = fs::metadata(&store_path).unwrap().permissions().mode() & 0o777;

    drop(owner);
    let contender = contender.join().unwrap().unwrap();
    drop(contender);
    let mode_after_acquisition = fs::metadata(&store_path).unwrap().permissions().mode() & 0o777;

    assert!(open_descriptors >= 2);
    assert_eq!(mode_while_contended, 0o750);
    assert_eq!(mode_after_acquisition, 0o700);
}
