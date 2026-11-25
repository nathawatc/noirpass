use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use crate::common::noirpass_command;

use noirpass::store::Store;
use sequoia_openpgp::cert::CertBuilder;
use sequoia_openpgp::serialize::Serialize;
use tempfile::{TempDir, tempdir};

pub(super) const ITEM_ID: &str = "0123456789abcdef0123456789abcdef";
pub(super) const RECOVERY: &str =
    ".noirpass-create-0123456789abcdef0123456789abcdef-0123456789abcdef.gpg";
pub(super) const CONFIG_TMP: &str = ".noirpass-tmp-0123456789abcdef";

pub(super) fn seeded_store() -> TempDir {
    let store = tempdir().unwrap();
    fs::create_dir(store.path().join("keys")).unwrap();
    fs::create_dir(store.path().join("secrets")).unwrap();
    fs::write(
        store.path().join("config.toml"),
        "version = 1\nrecipient_fingerprint = \"test\"\nrecipient_cert = \"keys/recipient.pgp\"\nidle_exit = 300\n",
    )
    .unwrap();
    fs::write(store.path().join("keys/recipient.pgp"), b"recipient").unwrap();
    fs::write(
        store.path().join("keys/.noirpass-tmp-0123456789abcdef"),
        b"temporary",
    )
    .unwrap();
    drop(Store::open(store.path()).unwrap());
    fs::write(
        store.path().join("secrets").join(format!("{ITEM_ID}.gpg")),
        b"ciphertext",
    )
    .unwrap();
    fs::write(store.path().join("secrets").join(RECOVERY), b"recovery").unwrap();
    fs::write(store.path().join("secrets/keep.txt"), b"unrelated").unwrap();
    fs::write(store.path().join(CONFIG_TMP), b"temporary").unwrap();
    fs::write(store.path().join("keep.txt"), b"unrelated").unwrap();
    store
}

pub(super) fn write_recipient(store: &Path, file_name: &str, userid: &str) -> PathBuf {
    let (cert, _) = CertBuilder::new()
        .add_userid(userid)
        .add_storage_encryption_subkey()
        .generate()
        .unwrap();
    let mut bytes = Vec::new();
    cert.serialize(&mut bytes).unwrap();
    let path = store.join(file_name);
    fs::write(&path, bytes).unwrap();
    path
}

pub(super) fn run_init(store: &Path, recipient: &Path) -> Output {
    noirpass_command()
        .arg("--store-dir")
        .arg(store)
        .args(["init", "--recipient"])
        .arg(recipient)
        .output()
        .unwrap()
}

pub(super) fn run_piped(store: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut child = noirpass_command()
        .arg("--store-dir")
        .arg(store)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

pub(super) fn assert_intact(snapshot: &[(PathBuf, Vec<u8>)]) {
    for (path, bytes) in snapshot {
        assert_eq!(
            fs::read(path).unwrap(),
            bytes.as_slice(),
            "changed {}",
            path.display()
        );
    }
}

pub(super) fn snapshot(store: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    [
        "config.toml",
        "keys/recipient.pgp",
        "keys/.noirpass-tmp-0123456789abcdef",
        "index.redb",
        &format!("secrets/{ITEM_ID}.gpg"),
        &format!("secrets/{RECOVERY}"),
        "secrets/keep.txt",
        CONFIG_TMP,
        "keep.txt",
    ]
    .into_iter()
    .map(|relative| {
        let path = store.join(relative);
        (path.clone(), fs::read(path).unwrap())
    })
    .collect()
}
