//! End-to-end integration tests.
//!
//! One shared fixture (built once per test process) provides:
//! an ephemeral `GNUPGHOME` with an empty-passphrase key, a private
//! `dbus-daemon --session`, and the real `noirpass` daemon binary
//! (`CARGO_BIN_EXE_noirpass`, so `cargo llvm-cov` instruments it and its
//! coverage is collected when it exits gracefully).
//!
//! All Secret Service scenarios run sequentially inside a single orchestrator
//! test (`end_to_end`): environment variables are process-global, the daemon
//! is shared, and running scenarios in-order lets the final teardown SIGTERM
//! the daemon *before* the test process exits so its coverage profile is
//! flushed deterministically. The idle-exit scenario runs as a separate test
//! against its own private bus and store, so it can run in parallel.
//!
//! A background "reaper" shell watches the test process and kills the
//! spawned daemons if the tests abort early, so nothing leaks on failure.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use noirpass::crypto::DhHandshake;
use noirpass::session::Secret as WireSecret;
use noirpass::store::{CollectionMeta, ItemMeta, Store};
use redb::{Database, TableDefinition};
use zbus::export::futures_core::Stream;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

const SERVICE_NAME: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SERVICE_IFACE: &str = "org.freedesktop.Secret.Service";
const COLLECTION_IFACE: &str = "org.freedesktop.Secret.Collection";
const NO_SESSION_ERROR: &str = "org.freedesktop.Secret.Error.NoSession";
const UNKNOWN_OBJECT_ERROR: &str = "org.freedesktop.DBus.Error.UnknownObject";

// --- fixture ----------------------------------------------------------------

struct Harness {
    gnupg_home: PathBuf,
    store_dir: PathBuf,
    fake_gpg_dir: PathBuf,
    fake_gpg_log: PathBuf,
    bus_address: String,
    dbus_pid: u32,
    daemon: Mutex<Child>,
    _keep: Vec<tempfile::TempDir>,
}

static HARNESS: OnceLock<Harness> = OnceLock::new();

fn harness() -> &'static Harness {
    HARNESS.get_or_init(Harness::init)
}

/// Generate an empty-passphrase key in a fresh, hermetic `GNUPGHOME`.
fn setup_gnupg(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(dir.join("gpg-agent.conf"), "allow-loopback-pinentry\n").unwrap();
    let status = Command::new("gpg")
        .args(["--batch", "--no-tty", "--homedir"])
        .arg(dir)
        .args([
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-gen-key",
            "noirpass e2e <e2e@t>",
            "default",
            "default",
            "never",
        ])
        .status()
        .expect("spawn gpg");
    assert!(status.success(), "gpg --quick-gen-key failed");
}

fn secret_fingerprint(dir: &Path) -> String {
    let output = Command::new("gpg")
        .args(["--batch", "--no-tty", "--homedir"])
        .arg(dir)
        .args(["--list-secret-keys", "--with-colons"])
        .output()
        .expect("spawn gpg --list-secret-keys");
    assert!(output.status.success(), "gpg --list-secret-keys failed");
    let text = String::from_utf8_lossy(&output.stdout);
    let mut seen_sec = false;
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        match fields.first().copied() {
            Some("sec") => seen_sec = true,
            Some("fpr") if seen_sec => {
                if let Some(fpr) = fields.get(9)
                    && !fpr.is_empty()
                {
                    return (*fpr).to_string();
                }
            }
            _ => {}
        }
    }
    panic!("no test secret key fingerprint")
}

fn export_public_cert(dir: &Path) -> Vec<u8> {
    let fingerprint = secret_fingerprint(dir);
    let output = Command::new("gpg")
        .args(["--batch", "--no-tty", "--homedir"])
        .arg(dir)
        .args(["--armor", "--export", &fingerprint])
        .output()
        .expect("spawn gpg --export");
    assert!(output.status.success(), "gpg --export failed");
    output.stdout
}

fn init_noirpass_store(store: &Path, recipient: &[u8]) {
    let recipient_path = store.join("recipient.asc");
    std::fs::write(&recipient_path, recipient).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .arg("--store-dir")
        .arg(store)
        .arg("init")
        .arg("--recipient")
        .arg(&recipient_path)
        .output()
        .expect("spawn noirpass init");
    assert!(
        output.status.success(),
        "noirpass init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn init_noirpass_store_from_stdin(store: &Path, recipient: &[u8]) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .arg("--store-dir")
        .arg(store)
        .arg("init")
        .arg("--recipient")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn noirpass init stdin");
    child.stdin.as_mut().unwrap().write_all(recipient).unwrap();
    let status = child.wait().expect("wait noirpass init stdin");
    assert!(status.success(), "noirpass init --recipient - failed");
}

fn fake_gpg_dir() -> (tempfile::TempDir, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("gpg.log");
    let script = format!(
        "#!/bin/sh\necho gpg-spawn >> '{}'\nexit 99\n",
        log.display()
    );
    let gpg = dir.path().join("gpg");
    std::fs::write(&gpg, script).unwrap();
    std::fs::set_permissions(&gpg, std::fs::Permissions::from_mode(0o755)).unwrap();
    (dir, log)
}

/// Spawn a private session bus and return `(child, address)`.
fn spawn_dbus_daemon() -> (Child, String) {
    let mut child = Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn dbus-daemon");
    let stdout = child.stdout.take().expect("dbus-daemon stdout");
    let mut address = String::new();
    BufReader::new(stdout)
        .read_line(&mut address)
        .expect("read dbus address");
    let address = address.trim().to_string();
    assert!(!address.is_empty(), "dbus-daemon printed no address");
    (child, address)
}

/// Spawn the real daemon binary against `bus`/`gnupg`/`store`.
fn spawn_daemon(
    bus: &str,
    gnupg: &Path,
    store: &Path,
    idle_exit: &str,
    fake_gpg_dir: Option<&Path>,
) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_noirpass"));
    cmd.arg("--store-dir").arg(store);
    if !idle_exit.is_empty() {
        cmd.args(["--idle-exit", idle_exit]);
    }
    cmd.env("DBUS_SESSION_BUS_ADDRESS", bus)
        .env("GNUPGHOME", gnupg)
        .env("RUST_LOG", "info");
    if let Some(fake_gpg_dir) = fake_gpg_dir {
        let old_path = std::env::var_os("PATH").unwrap_or_default();
        let mut paths = vec![fake_gpg_dir.to_path_buf()];
        paths.extend(std::env::split_paths(&old_path));
        cmd.env("PATH", std::env::join_paths(paths).unwrap());
    }
    cmd.spawn().expect("spawn noirpass daemon")
}

/// Poll (via `dbus-send`) until `org.freedesktop.secrets` has an owner.
fn wait_for_name(bus: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let out = Command::new("dbus-send")
            .arg(format!("--bus={bus}"))
            .args([
                "--print-reply",
                "--dest=org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus.NameHasOwner",
                &format!("string:{SERVICE_NAME}"),
            ])
            .output()
            .expect("spawn dbus-send");
        if String::from_utf8_lossy(&out.stdout).contains("boolean true") {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("daemon did not claim {SERVICE_NAME} within 10s");
}

/// Wait for a child to exit, with a timeout.
fn wait_with_timeout(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status;
        }
        assert!(Instant::now() < deadline, "process did not exit in time");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn sigterm(pid: u32) {
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
}

impl Harness {
    fn init() -> Self {
        let gnupg_tmp = tempfile::tempdir().unwrap();
        setup_gnupg(gnupg_tmp.path());
        let recipient = export_public_cert(gnupg_tmp.path());

        let (dbus, bus_address) = spawn_dbus_daemon();
        let dbus_pid = dbus.id();
        // The dbus-daemon Child is intentionally leaked (statics never drop);
        // the reaper below cleans it up when the test process exits.
        std::mem::forget(dbus);

        // SAFETY: called once, from the OnceLock initializer, before any test
        // creates a zbus/oo7 connection or reads these variables. The other
        // test thread is blocked on the OnceLock during this call.
        unsafe {
            std::env::set_var("DBUS_SESSION_BUS_ADDRESS", &bus_address);
            std::env::set_var("GNUPGHOME", gnupg_tmp.path());
        }

        let store_tmp = tempfile::tempdir().unwrap();
        init_noirpass_store(store_tmp.path(), &recipient);
        let (fake_gpg_tmp, fake_gpg_log) = fake_gpg_dir();
        let fake_gpg_dir = fake_gpg_tmp.path().to_path_buf();
        let daemon = spawn_daemon(
            &bus_address,
            gnupg_tmp.path(),
            store_tmp.path(),
            "-1",
            Some(&fake_gpg_dir),
        );
        wait_for_name(&bus_address);

        let gnupg_home = gnupg_tmp.path().to_path_buf();
        let store_dir = store_tmp.path().to_path_buf();

        // Reaper: if the test process dies (success or abort), terminate the
        // daemon (SIGTERM, so it flushes coverage), the private bus and the
        // gpg-agent. `pkill -f` on the unique store path survives daemon
        // restarts (the pid changes; the command line does not).
        let test_pid = std::process::id();
        // Note the `[-]-store-dir` character class: it stops `pkill -f` from
        // matching (and killing) the reaper's own command line, which embeds
        // this very pattern.
        let script = format!(
            "while kill -0 {test_pid} 2>/dev/null; do sleep 0.5; done; \
             pkill -TERM -f -- '[-]-store-dir {store}' 2>/dev/null; \
             kill -TERM {dbus_pid} 2>/dev/null; \
             gpgconf --homedir '{gnupg}' --kill gpg-agent 2>/dev/null; true",
            store = store_dir.display(),
            gnupg = gnupg_home.display(),
        );
        #[allow(
            clippy::zombie_processes,
            reason = "the reaper must outlive the test process by design"
        )]
        Command::new("sh")
            .args(["-c", &script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn reaper");

        Self {
            gnupg_home,
            store_dir,
            fake_gpg_dir,
            fake_gpg_log,
            bus_address,
            dbus_pid,
            daemon: Mutex::new(daemon),
            _keep: vec![gnupg_tmp, store_tmp, fake_gpg_tmp],
        }
    }

    /// SIGTERM the daemon and assert it exits cleanly.
    fn stop_daemon(&self) {
        let mut child = self.daemon.lock().unwrap();
        sigterm(child.id());
        let status = wait_with_timeout(&mut child, Duration::from_secs(10));
        assert!(status.success(), "daemon exited with {status}");
    }

    /// Start a fresh daemon on the same bus and store, waiting for the name.
    fn respawn_daemon(&self) {
        let fresh = spawn_daemon(
            &self.bus_address,
            &self.gnupg_home,
            &self.store_dir,
            "-1",
            Some(&self.fake_gpg_dir),
        );
        *self.daemon.lock().unwrap() = fresh;
        wait_for_name(&self.bus_address);
    }
}

// --- small async helpers -----------------------------------------------------

/// `StreamExt::next` without a futures-util dependency.
async fn next_event<S: Stream>(mut stream: Pin<&mut S>) -> Option<S::Item> {
    std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await
}

async fn service_proxy(conn: &zbus::Connection) -> zbus::Proxy<'static> {
    zbus::Proxy::new(conn, SERVICE_NAME, SERVICE_PATH, SERVICE_IFACE)
        .await
        .expect("service proxy")
}

/// Last path segment = the store id of an item/collection object.
fn object_id(path: &str) -> String {
    path.rsplit('/').next().unwrap().to_string()
}

fn attrs(case: &str) -> Vec<(String, String)> {
    vec![
        ("app".to_string(), "noirpass-e2e".to_string()),
        ("case".to_string(), case.to_string()),
    ]
}

fn assert_method_error(err: &zbus::Error, expected: &str) {
    match err {
        zbus::Error::MethodError(name, _, _) => assert_eq!(name.as_str(), expected),
        other => panic!("expected {expected}, got {other}"),
    }
}

// --- scenarios ----------------------------------------------------------------

/// Scenario 1: encrypted (DH) session roundtrip through oo7.
async fn s1_encrypted_roundtrip() {
    let service = oo7::dbus::Service::encrypted().await.expect("encrypted");
    let collection = service.default_collection().await.expect("default");

    let a = attrs("s1");
    let item = collection
        .create_item("s1-label", &a, oo7::Secret::text("s1 secret"), true, None)
        .await
        .expect("create_item");

    assert_eq!(item.label().await.unwrap(), "s1-label");
    assert!(!item.is_locked().await.unwrap());
    assert_eq!(item.secret().await.unwrap().as_bytes(), b"s1 secret");

    let found = collection.search_items(&a).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].secret().await.unwrap().as_bytes(), b"s1 secret");

    item.delete(None).await.unwrap();
    assert!(collection.search_items(&a).await.unwrap().is_empty());
}

/// Scenario 2: plain session roundtrip through oo7.
async fn s2_plain_roundtrip() {
    let service = oo7::dbus::Service::plain().await.expect("plain");
    let collection = service.default_collection().await.expect("default");

    let a = attrs("s2");
    let item = collection
        .create_item("s2-label", &a, oo7::Secret::text("s2 secret"), true, None)
        .await
        .expect("create_item");
    assert_eq!(item.secret().await.unwrap().as_bytes(), b"s2 secret");
    item.delete(None).await.unwrap();
}

/// Scenario 3: replace semantics — replace=true updates in place,
/// replace=false creates a second item with identical attributes.
async fn s3_replace_semantics() {
    let service = oo7::dbus::Service::encrypted().await.unwrap();
    let collection = service.default_collection().await.unwrap();
    let a = attrs("s3");

    let first = collection
        .create_item("s3-one", &a, oo7::Secret::text("v1"), true, None)
        .await
        .unwrap();
    let second = collection
        .create_item("s3-two", &a, oo7::Secret::text("v2"), true, None)
        .await
        .unwrap();
    // Same item path (in-place replace), updated secret and label.
    assert_eq!(first.path(), second.path());
    let found = collection.search_items(&a).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].secret().await.unwrap().as_bytes(), b"v2");
    assert_eq!(found[0].label().await.unwrap(), "s3-two");

    // replace = false with the same attributes creates a distinct item.
    let third = collection
        .create_item("s3-three", &a, oo7::Secret::text("v3"), false, None)
        .await
        .unwrap();
    assert_ne!(third.path(), second.path());
    let found = collection.search_items(&a).await.unwrap();
    assert_eq!(found.len(), 2);

    for item in found {
        item.delete(None).await.unwrap();
    }
}

/// Scenario 4: alias handling, including the raw `/` conventions.
async fn s4_aliases() {
    let service = oo7::dbus::Service::plain().await.unwrap();
    let collection = service
        .create_collection("s4-col", None, None)
        .await
        .unwrap();
    let col_path = OwnedObjectPath::from(collection.path().to_owned());

    let conn = zbus::Connection::session().await.unwrap();
    let proxy = service_proxy(&conn).await;

    // Unknown alias reads as "/".
    let unknown: OwnedObjectPath = proxy.call("ReadAlias", &("s4-alias",)).await.unwrap();
    assert_eq!(unknown.as_str(), "/");

    // Set → resolves; set "/" → removed.
    proxy
        .call::<_, _, ()>("SetAlias", &("s4-alias", &col_path))
        .await
        .unwrap();
    let resolved: OwnedObjectPath = proxy.call("ReadAlias", &("s4-alias",)).await.unwrap();
    assert_eq!(resolved, col_path);

    let root = OwnedObjectPath::try_from("/").unwrap();
    proxy
        .call::<_, _, ()>("SetAlias", &("s4-alias", &root))
        .await
        .unwrap();
    let removed: OwnedObjectPath = proxy.call("ReadAlias", &("s4-alias",)).await.unwrap();
    assert_eq!(removed.as_str(), "/");

    // Aliasing a non-existent collection is NoSuchObject.
    let bogus =
        OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/doesnotexist").unwrap();
    let err = proxy
        .call::<_, _, ()>("SetAlias", &("s4-alias", &bogus))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("NoSuchObject"),
        "unexpected error: {err}"
    );

    collection.delete(None).await.unwrap();
}

/// Scenario 5: collection lifecycle — creation, listing, cascading delete
/// (D-Bus objects and on-disk `.gpg` files both disappear).
async fn s5_collection_lifecycle() {
    let h = harness();
    let service = oo7::dbus::Service::encrypted().await.unwrap();
    let collection = service
        .create_collection("s5-col", None, None)
        .await
        .unwrap();

    let mut labels = Vec::new();
    for c in service.collections().await.unwrap() {
        labels.push(c.label().await.unwrap());
    }
    assert!(labels.contains(&"s5-col".to_string()), "labels: {labels:?}");

    let i1 = collection
        .create_item("s5-a", &attrs("s5"), oo7::Secret::text("a"), false, None)
        .await
        .unwrap();
    let i2 = collection
        .create_item("s5-b", &attrs("s5"), oo7::Secret::text("b"), false, None)
        .await
        .unwrap();

    let f1 = h
        .store_dir
        .join("secrets")
        .join(format!("{}.gpg", object_id(i1.path())));
    let f2 = h
        .store_dir
        .join("secrets")
        .join(format!("{}.gpg", object_id(i2.path())));
    assert!(f1.exists() && f2.exists(), "secret files must exist");

    collection.delete(None).await.unwrap();

    assert!(!f1.exists() && !f2.exists(), "secret files must be removed");
    // The items are unreachable through search.
    let conn = zbus::Connection::session().await.unwrap();
    let proxy = service_proxy(&conn).await;
    let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = proxy
        .call(
            "SearchItems",
            &(HashMap::from([("case".to_string(), "s5".to_string())]),),
        )
        .await
        .unwrap();
    assert!(unlocked.is_empty() && locked.is_empty());
    // And the collection is gone from the listing.
    let mut labels = Vec::new();
    for c in service.collections().await.unwrap() {
        labels.push(c.label().await.unwrap());
    }
    assert!(!labels.contains(&"s5-col".to_string()));
}

/// Scenario 6: bulk `GetSecrets` under both session algorithms, plus the
/// `NoSession` error for an unknown session path.
async fn s6_get_secrets_bulk() {
    let service = oo7::dbus::Service::encrypted().await.unwrap();
    let collection = service.default_collection().await.unwrap();

    let mut paths = Vec::new();
    let mut expected = HashMap::new();
    for idx in 1..=3u8 {
        let a = vec![
            ("case".to_string(), "s6".to_string()),
            ("idx".to_string(), idx.to_string()),
        ];
        let secret = format!("s6 secret {idx}");
        let item = collection
            .create_item(
                &format!("s6-{idx}"),
                &a,
                oo7::Secret::text(&secret),
                true,
                None,
            )
            .await
            .unwrap();
        let path = OwnedObjectPath::from(item.path().to_owned());
        expected.insert(path.clone(), secret.into_bytes());
        paths.push(path);
    }

    let conn = zbus::Connection::session().await.unwrap();
    let proxy = service_proxy(&conn).await;

    // Plain session: values come back as raw plaintext.
    let (_, plain_session): (OwnedValue, OwnedObjectPath) = proxy
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();
    let secrets: HashMap<OwnedObjectPath, WireSecret> = proxy
        .call("GetSecrets", &(&paths, &plain_session))
        .await
        .unwrap();
    assert_eq!(secrets.len(), 3);
    for (path, secret) in &secrets {
        assert!(secret.parameters.is_empty());
        assert_eq!(&secret.value, &expected[path]);
        assert_eq!(secret.content_type, "text/plain");
    }

    // A mismatched collection component must not resolve by item id alone.
    let (_, item_id) = noirpass::service::parse_item_path(paths[0].as_str()).unwrap();
    let mismatched_path = OwnedObjectPath::try_from(format!(
        "/org/freedesktop/secrets/collection/not_the_owner/{item_id}"
    ))
    .unwrap();
    let mismatched_paths = vec![mismatched_path];
    let mismatched: HashMap<OwnedObjectPath, WireSecret> = proxy
        .call("GetSecrets", &(&mismatched_paths, &plain_session))
        .await
        .unwrap();
    assert!(mismatched.is_empty());

    // DH session: drive the client side with the library's own handshake.
    let client = DhHandshake::generate();
    let (server_pub, dh_session): (OwnedValue, OwnedObjectPath) = proxy
        .call(
            "OpenSession",
            &(
                "dh-ietf1024-sha256-aes128-cbc-pkcs7",
                Value::from(client.public_bytes()),
            ),
        )
        .await
        .unwrap();
    let server_pub = Vec::<u8>::try_from(server_pub).unwrap();
    let cipher = client.derive(&server_pub).unwrap();
    let secrets: HashMap<OwnedObjectPath, WireSecret> = proxy
        .call("GetSecrets", &(&paths, &dh_session))
        .await
        .unwrap();
    assert_eq!(secrets.len(), 3);
    for (path, secret) in &secrets {
        let plaintext = cipher.decrypt(&secret.parameters, &secret.value).unwrap();
        assert_eq!(&plaintext[..], &expected[path][..]);
    }

    // Unknown session → org.freedesktop.Secret.Error.NoSession.
    let ghost = OwnedObjectPath::try_from("/org/freedesktop/secrets/session/s999999").unwrap();
    let err = proxy
        .call::<_, _, HashMap<OwnedObjectPath, WireSecret>>("GetSecrets", &(&paths, &ghost))
        .await
        .unwrap_err();
    assert_method_error(&err, NO_SESSION_ERROR);

    let ghost_proxy =
        zbus::Proxy::new(&conn, SERVICE_NAME, ghost, "org.freedesktop.Secret.Session")
            .await
            .unwrap();
    let err = ghost_proxy
        .call::<_, _, ()>("Close", &())
        .await
        .unwrap_err();
    assert_method_error(&err, UNKNOWN_OBJECT_ERROR);

    delete_items(paths).await;
}

async fn delete_items(paths: Vec<OwnedObjectPath>) {
    for path in paths {
        let conn = zbus::Connection::session().await.unwrap();
        let proxy = zbus::Proxy::new(&conn, SERVICE_NAME, path, "org.freedesktop.Secret.Item")
            .await
            .unwrap();
        let _: OwnedObjectPath = proxy.call("Delete", &()).await.unwrap();
    }
}

async fn assert_foreign_item_operations_rejected(
    attacker: &zbus::Connection,
    collection_path: &OwnedObjectPath,
    item_path: &OwnedObjectPath,
    session: &OwnedObjectPath,
) {
    let attacker_item = zbus::Proxy::new(
        attacker,
        SERVICE_NAME,
        item_path.clone(),
        "org.freedesktop.Secret.Item",
    )
    .await
    .unwrap();
    let err = attacker_item
        .call::<_, _, (WireSecret,)>("GetSecret", &(&session,))
        .await
        .unwrap_err();
    assert_method_error(&err, NO_SESSION_ERROR);

    let foreign_secret = WireSecret {
        session: session.clone(),
        parameters: Vec::new(),
        value: b"foreign session value".to_vec(),
        content_type: "text/plain".to_string(),
    };
    let err = attacker_item
        .call::<_, _, ()>("SetSecret", &(&foreign_secret,))
        .await
        .unwrap_err();
    assert_method_error(&err, NO_SESSION_ERROR);

    let attacker_collection = zbus::Proxy::new(
        attacker,
        SERVICE_NAME,
        collection_path.clone(),
        COLLECTION_IFACE,
    )
    .await
    .unwrap();
    let properties: HashMap<String, OwnedValue> = HashMap::new();
    let err = attacker_collection
        .call::<_, _, (OwnedObjectPath, OwnedObjectPath)>(
            "CreateItem",
            &(&properties, &foreign_secret, false),
        )
        .await
        .unwrap_err();
    assert_method_error(&err, NO_SESSION_ERROR);
}

/// Scenario 6b: session handles belong only to opening D-Bus sender.
async fn s6b_cross_client_session_rejected() {
    let service = oo7::dbus::Service::encrypted().await.unwrap();
    let collection = service.default_collection().await.unwrap();
    let collection_path = OwnedObjectPath::from(collection.path().to_owned());
    let item = collection
        .create_item(
            "s6b-label",
            &attrs("s6b"),
            oo7::Secret::text("isolated session value"),
            true,
            None,
        )
        .await
        .unwrap();
    let item_path = OwnedObjectPath::from(item.path().to_owned());

    let owner = zbus::Connection::session().await.unwrap();
    let attacker = zbus::Connection::session().await.unwrap();
    assert_ne!(owner.unique_name(), attacker.unique_name());
    let owner_service = service_proxy(&owner).await;
    let attacker_service = service_proxy(&attacker).await;
    let (_, session): (OwnedValue, OwnedObjectPath) = owner_service
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();

    let owner_item = zbus::Proxy::new(
        &owner,
        SERVICE_NAME,
        item_path.clone(),
        "org.freedesktop.Secret.Item",
    )
    .await
    .unwrap();
    let _: (WireSecret,) = owner_item
        .call("GetSecret", &(&session,))
        .await
        .expect("session owner must retrieve item");

    assert_foreign_item_operations_rejected(&attacker, &collection_path, &item_path, &session)
        .await;

    let requested_items = vec![item_path.clone()];
    let err = attacker_service
        .call::<_, _, HashMap<OwnedObjectPath, WireSecret>>(
            "GetSecrets",
            &(&requested_items, &session),
        )
        .await
        .unwrap_err();
    assert_method_error(&err, NO_SESSION_ERROR);

    let attacker_session = zbus::Proxy::new(
        &attacker,
        SERVICE_NAME,
        session.clone(),
        "org.freedesktop.Secret.Session",
    )
    .await
    .unwrap();
    let err = attacker_session
        .call::<_, _, ()>("Close", &())
        .await
        .unwrap_err();
    assert_method_error(&err, NO_SESSION_ERROR);

    let secrets: HashMap<OwnedObjectPath, WireSecret> = owner_service
        .call("GetSecrets", &(&requested_items, &session))
        .await
        .unwrap();
    assert_eq!(secrets.len(), 1, "owner's session must remain usable");

    let owner_session = zbus::Proxy::new(
        &owner,
        SERVICE_NAME,
        session.clone(),
        "org.freedesktop.Secret.Session",
    )
    .await
    .unwrap();
    owner_session.call::<_, _, ()>("Close", &()).await.unwrap();
    let err = owner_session
        .call::<_, _, ()>("Close", &())
        .await
        .unwrap_err();
    assert_method_error(&err, UNKNOWN_OBJECT_ERROR);
    let closed = owner_service
        .call::<_, _, HashMap<OwnedObjectPath, WireSecret>>(
            "GetSecrets",
            &(&requested_items, &session),
        )
        .await
        .unwrap_err();
    assert_method_error(&closed, NO_SESSION_ERROR);
    item.delete(None).await.unwrap();
}

/// Scenario 7: persistence — SIGTERM the daemon, respawn on the same store,
/// and prove the at-rest `OpenPGP` encryption still decrypts via `gpg-agent`.
async fn s7_persistence_across_restart() {
    let h = harness();
    let a = attrs("s7");
    {
        let service = oo7::dbus::Service::encrypted().await.unwrap();
        let collection = service.default_collection().await.unwrap();
        collection
            .create_item(
                "s7-label",
                &a,
                oo7::Secret::text("survives restarts"),
                true,
                None,
            )
            .await
            .unwrap();
    }

    // The blocking stop/wait/respawn dance runs off the async threads.
    tokio::task::spawn_blocking(move || {
        h.stop_daemon();
        h.respawn_daemon();
    })
    .await
    .unwrap();

    // Fresh service handle (old sessions died with the old daemon).
    let service = oo7::dbus::Service::encrypted().await.unwrap();
    let collection = service.default_collection().await.unwrap();
    let found = collection.search_items(&a).await.unwrap();
    assert_eq!(found.len(), 1, "item must survive a daemon restart");
    assert_eq!(
        found[0].secret().await.unwrap().as_bytes(),
        b"survives restarts"
    );
    found[0].delete(None).await.unwrap();
}

/// Scenario 8: a real libsecret client (`secret-tool`) stores and looks up.
#[cfg(feature = "secret-tool-smoke")]
async fn secret_service_available_at(address: &str) -> bool {
    let Ok(builder) = zbus::connection::Builder::address(address) else {
        return false;
    };
    let Ok(connection) = builder.build().await else {
        return false;
    };
    let Ok(proxy) = zbus::fdo::DBusProxy::new(&connection).await else {
        return false;
    };
    let name = zbus::names::BusName::try_from(SERVICE_NAME).expect("valid service bus name");
    proxy.name_has_owner(name).await.unwrap_or(false)
}

#[cfg(feature = "secret-tool-smoke")]
async fn secret_tool_smoke_environment_available(address: Option<&str>) -> bool {
    let Some(address) = address.filter(|address| !address.is_empty()) else {
        return false;
    };
    if !secret_service_available_at(address).await {
        return false;
    }
    Command::new("secret-tool")
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(feature = "secret-tool-smoke")]
async fn s8_secret_tool_smoke() {
    let address = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
    if !secret_tool_smoke_environment_available(address.as_deref()).await {
        eprintln!("scenario 8 skipped: session bus, Secret Service, or secret-tool unavailable");
        return;
    }

    let store = tokio::task::spawn_blocking(|| {
        let mut child = Command::new("secret-tool")
            .args(["store", "--label=smoke", "sm", "ke"])
            .stdin(Stdio::piped())
            .spawn()?;
        let stdin = child.stdin.as_mut().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "secret-tool stdin unavailable",
            )
        })?;
        stdin.write_all(b"hunter2\n")?;
        child.wait()
    })
    .await
    .expect("secret-tool store task panicked")
    .expect("secret-tool store failed to execute");
    assert!(store.success(), "secret-tool store failed");

    let lookup = tokio::task::spawn_blocking(|| {
        Command::new("secret-tool")
            .args(["lookup", "sm", "ke"])
            .output()
    })
    .await
    .expect("secret-tool lookup task panicked")
    .expect("secret-tool lookup failed to execute");
    assert!(lookup.status.success(), "secret-tool lookup failed");
    assert_eq!(
        String::from_utf8_lossy(&lookup.stdout).trim(),
        "hunter2",
        "lookup must return the stored secret"
    );
}

#[cfg(feature = "secret-tool-smoke")]
#[tokio::test]
async fn optional_secret_tool_smoke_skips_unavailable_environment() {
    assert!(!secret_tool_smoke_environment_available(None).await);

    let dir = tempfile::tempdir().unwrap();
    let missing_socket = dir.path().join("missing-session-bus");
    let address = format!("unix:path={}", missing_socket.display());

    assert!(!secret_tool_smoke_environment_available(Some(&address)).await);
}

/// Scenario 10: `CollectionCreated` and `ItemCreated` signals fire.
async fn s10_signals() {
    let conn = zbus::Connection::session().await.unwrap();
    let proxy = service_proxy(&conn).await;
    let created_stream = proxy.receive_signal("CollectionCreated").await.unwrap();
    let mut created_stream = std::pin::pin!(created_stream);

    let service = oo7::dbus::Service::plain().await.unwrap();
    let collection = service
        .create_collection("s10-col", None, None)
        .await
        .unwrap();
    let col_path = OwnedObjectPath::from(collection.path().to_owned());

    let msg = tokio::time::timeout(Duration::from_secs(10), next_event(created_stream.as_mut()))
        .await
        .expect("timed out waiting for CollectionCreated")
        .expect("signal stream ended");
    let (created,): (OwnedObjectPath,) = msg.body().deserialize().unwrap();
    assert_eq!(created, col_path);

    // ItemCreated on the collection object.
    let col_proxy = zbus::Proxy::new(&conn, SERVICE_NAME, col_path.clone(), COLLECTION_IFACE)
        .await
        .unwrap();
    let item_stream = col_proxy.receive_signal("ItemCreated").await.unwrap();
    let mut item_stream = std::pin::pin!(item_stream);

    let item = collection
        .create_item(
            "s10-item",
            &attrs("s10"),
            oo7::Secret::text("x"),
            true,
            None,
        )
        .await
        .unwrap();
    let item_path = OwnedObjectPath::from(item.path().to_owned());

    let msg = tokio::time::timeout(Duration::from_secs(10), next_event(item_stream.as_mut()))
        .await
        .expect("timed out waiting for ItemCreated")
        .expect("signal stream ended");
    let (created,): (OwnedObjectPath,) = msg.body().deserialize().unwrap();
    assert_eq!(created, item_path);

    collection.delete(None).await.unwrap();
}

// --- orchestrator --------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_to_end() {
    // Force fixture setup (bus + daemon + GNUPGHOME env) before any scenario.
    harness();

    eprintln!("scenario 1: encrypted session roundtrip");
    s1_encrypted_roundtrip().await;
    eprintln!("scenario 2: plain session roundtrip");
    s2_plain_roundtrip().await;
    eprintln!("scenario 3: replace semantics");
    s3_replace_semantics().await;
    eprintln!("scenario 4: aliases");
    s4_aliases().await;
    eprintln!("scenario 5: collection lifecycle");
    s5_collection_lifecycle().await;
    eprintln!("scenario 6: bulk GetSecrets");
    s6_get_secrets_bulk().await;
    eprintln!("scenario 6b: cross-client session rejection");
    s6b_cross_client_session_rejected().await;
    eprintln!("scenario 7: persistence across restart");
    s7_persistence_across_restart().await;
    #[cfg(feature = "secret-tool-smoke")]
    {
        eprintln!("scenario 8: secret-tool smoke");
        s8_secret_tool_smoke().await;
    }
    eprintln!("scenario 10: signals");
    s10_signals().await;
    eprintln!("scenario 11: no daemon gpg spawn");
    daemon_runtime_does_not_spawn_gpg();

    // Graceful teardown before the process exits: SIGTERM (asserts a clean
    // exit and flushes the daemon's coverage profile), then stop the bus and
    // agent. The reaper is the fallback for panics before this point.
    eprintln!("teardown");
    tokio::task::spawn_blocking(|| {
        let h = harness();
        h.stop_daemon();
        sigterm(h.dbus_pid);
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(&h.gnupg_home)
            .args(["--kill", "gpg-agent"])
            .status();
    })
    .await
    .unwrap();
}

fn daemon_runtime_does_not_spawn_gpg() {
    let h = harness();
    assert!(
        !h.fake_gpg_log.exists(),
        "daemon spawned gpg: {}",
        std::fs::read_to_string(&h.fake_gpg_log).unwrap_or_default()
    );
}

/// Scenario 9: a daemon with `idle_exit = 0` in `config.toml` exits after its
/// client disconnects. Runs on a private bus + store so it cannot disturb `end_to_end`.
#[tokio::test]
async fn idle_exit_daemon_exits() {
    let h = harness(); // shared hermetic GNUPGHOME (env is process-global anyway)

    let (mut dbus, address) = spawn_dbus_daemon();
    let store = tempfile::tempdir().unwrap();
    let cert = export_public_cert(&h.gnupg_home);
    init_noirpass_store(store.path(), &cert);
    let config_path = store.path().join("config.toml");
    let mut config = std::fs::read_to_string(&config_path).unwrap();
    assert!(config.contains("idle_exit = 300"));
    config = config.replace("idle_exit = 300", "idle_exit = 0");
    std::fs::write(config_path, config).unwrap();
    let mut daemon = spawn_daemon(
        &address,
        &h.gnupg_home,
        store.path(),
        "",
        Some(&h.fake_gpg_dir),
    );
    wait_for_name(&address);

    // Open a session and drop the client without calling Session.Close. The
    // leaked session must not block idle-exit once NameOwnerChanged reaps it.
    {
        let conn = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let proxy = service_proxy(&conn).await;
        let (_output, session): (OwnedValue, OwnedObjectPath) = proxy
            .call("OpenSession", &("plain", Value::from("")))
            .await
            .unwrap();
        assert!(
            session
                .as_str()
                .starts_with("/org/freedesktop/secrets/session/s")
        );
    }

    let status = tokio::task::spawn_blocking(move || {
        wait_with_timeout(&mut daemon, Duration::from_secs(10))
    })
    .await
    .unwrap();
    assert!(
        status.success(),
        "daemon should idle-exit cleanly after client disconnect, got {status}"
    );
    assert!(
        !h.fake_gpg_log.exists(),
        "daemon spawned gpg during idle-exit test: {}",
        std::fs::read_to_string(&h.fake_gpg_log).unwrap_or_default()
    );

    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();
}

#[tokio::test]
async fn disconnect_unregisters_owned_session() {
    let h = harness();
    let (mut dbus, address) = spawn_dbus_daemon();
    let store = tempfile::tempdir().unwrap();
    let cert = export_public_cert(&h.gnupg_home);
    init_noirpass_store(store.path(), &cert);
    let mut daemon = spawn_daemon(
        &address,
        &h.gnupg_home,
        store.path(),
        "-1",
        Some(&h.fake_gpg_dir),
    );
    wait_for_name(&address);

    let session = {
        let owner = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let proxy = service_proxy(&owner).await;
        let (_, session): (OwnedValue, OwnedObjectPath) = proxy
            .call("OpenSession", &("plain", Value::from("")))
            .await
            .unwrap();
        session
    };

    let observer = zbus::connection::Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let session_proxy = zbus::Proxy::new(
        &observer,
        SERVICE_NAME,
        session,
        "org.freedesktop.Secret.Session",
    )
    .await
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let err = session_proxy
            .call::<_, _, ()>("Close", &())
            .await
            .unwrap_err();
        match &err {
            zbus::Error::MethodError(name, _, _) if name.as_str() == UNKNOWN_OBJECT_ERROR => break,
            zbus::Error::MethodError(name, _, _)
                if name.as_str() == NO_SESSION_ERROR && Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            _ => panic!("session object survived owner disconnect: {err}"),
        }
    }

    sigterm(daemon.id());
    assert!(wait_with_timeout(&mut daemon, Duration::from_secs(10)).success());
    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();
}

#[tokio::test]
async fn stale_session_path_is_not_reissued_after_restart() {
    let h = harness();
    let (mut dbus, address) = spawn_dbus_daemon();
    let store = tempfile::tempdir().unwrap();
    let cert = export_public_cert(&h.gnupg_home);
    init_noirpass_store(store.path(), &cert);
    let mut daemon = spawn_daemon(
        &address,
        &h.gnupg_home,
        store.path(),
        "-1",
        Some(&h.fake_gpg_dir),
    );
    wait_for_name(&address);

    let conn = zbus::connection::Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let proxy = service_proxy(&conn).await;
    let (_, stale): (OwnedValue, OwnedObjectPath) = proxy
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();

    sigterm(daemon.id());
    assert!(wait_with_timeout(&mut daemon, Duration::from_secs(10)).success());
    daemon = spawn_daemon(
        &address,
        &h.gnupg_home,
        store.path(),
        "-1",
        Some(&h.fake_gpg_dir),
    );
    wait_for_name(&address);

    let no_items: Vec<OwnedObjectPath> = Vec::new();
    let before_new = proxy
        .call::<_, _, HashMap<OwnedObjectPath, WireSecret>>("GetSecrets", &(&no_items, &stale))
        .await
        .unwrap_err();
    assert_method_error(&before_new, NO_SESSION_ERROR);

    let stale_object = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        stale.clone(),
        "org.freedesktop.Secret.Session",
    )
    .await
    .unwrap();
    let err = stale_object
        .call::<_, _, ()>("Close", &())
        .await
        .unwrap_err();
    assert_method_error(&err, UNKNOWN_OBJECT_ERROR);

    let (_, replacement): (OwnedValue, OwnedObjectPath) = proxy
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();
    let stale_after_new = proxy
        .call::<_, _, HashMap<OwnedObjectPath, WireSecret>>("GetSecrets", &(&no_items, &stale))
        .await;

    let replacement_session = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        replacement.clone(),
        "org.freedesktop.Secret.Session",
    )
    .await
    .unwrap();
    replacement_session
        .call::<_, _, ()>("Close", &())
        .await
        .unwrap();
    sigterm(daemon.id());
    assert!(wait_with_timeout(&mut daemon, Duration::from_secs(10)).success());
    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();

    assert_ne!(stale, replacement, "daemon reissued stale session path");
    let err = stale_after_new.unwrap_err();
    assert_method_error(&err, NO_SESSION_ERROR);
}

#[test]
fn cli_lists_deletes_and_repairs_stale_items() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let present = store
        .create_item(
            &collection.id,
            "present secret",
            HashMap::from([("service".to_string(), "present".to_string())]),
            "text/plain",
            b"ciphertext",
        )
        .unwrap();
    let missing = store
        .create_item(
            &collection.id,
            "missing secret",
            HashMap::from([("service".to_string(), "missing".to_string())]),
            "text/plain",
            b"ciphertext",
        )
        .unwrap();
    std::fs::remove_file(
        dir.path()
            .join("secrets")
            .join(format!("{}.gpg", missing.id)),
    )
    .unwrap();
    drop(store);

    let listed = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .arg("--store-dir")
        .arg(dir.path())
        .arg("list")
        .output()
        .expect("spawn noirpass list");
    assert!(
        listed.status.success(),
        "list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&listed.stdout),
        String::from_utf8_lossy(&listed.stderr)
    );
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(stdout.contains(&present.id));
    assert!(stdout.contains(&missing.id));
    assert!(stdout.contains("ciphertext: missing"));

    let checked = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .arg("--store-dir")
        .arg(dir.path())
        .args(["check", "--yes"])
        .output()
        .expect("spawn noirpass check");
    assert!(
        checked.status.success(),
        "check failed: stdout={} stderr={}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    assert!(String::from_utf8_lossy(&checked.stdout).contains("store health: repaired"));

    let store = Store::open_existing(dir.path()).unwrap();
    assert!(store.get_item(&present.id).is_ok());
    assert!(store.get_item(&missing.id).is_err());
    drop(store);

    let deleted = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .arg("--store-dir")
        .arg(dir.path())
        .arg("delete")
        .arg(&present.id)
        .arg("--yes")
        .output()
        .expect("spawn noirpass delete");
    assert!(
        deleted.status.success(),
        "delete failed: stdout={} stderr={}",
        String::from_utf8_lossy(&deleted.stdout),
        String::from_utf8_lossy(&deleted.stderr)
    );
    assert!(String::from_utf8_lossy(&deleted.stdout).contains(&present.id));

    let store = Store::open_existing(dir.path()).unwrap();
    assert!(store.search_items(&HashMap::new()).unwrap().is_empty());
    assert!(store.check_integrity().unwrap().is_healthy());
}

#[test]
fn cli_rejects_mismatched_item_id_without_deleting_valid_item() {
    const ITEMS: TableDefinition<&str, &[u8]> = TableDefinition::new("items");
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let valid_b = store
        .create_item(
            &collection.id,
            "valid-b",
            HashMap::new(),
            "text/plain",
            b"ciphertext-b",
        )
        .unwrap();
    let key_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let corrupt = ItemMeta {
        label: "corrupt-a".to_string(),
        ..valid_b.clone()
    };
    drop(store);
    let db = Database::open(dir.path().join("index.redb")).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut items = txn.open_table(ITEMS).unwrap();
        let bytes = serde_json::to_vec(&corrupt).unwrap();
        items.insert(key_a, bytes.as_slice()).unwrap();
    }
    txn.commit().unwrap();
    drop(db);

    let listed = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .arg("--store-dir")
        .arg(dir.path())
        .arg("list")
        .output()
        .expect("spawn noirpass list");
    assert!(
        !listed.status.success(),
        "list must reject mismatched item ids"
    );

    let deleted = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .arg("--store-dir")
        .arg(dir.path())
        .arg("delete")
        .arg(key_a)
        .arg("--yes")
        .output()
        .expect("spawn noirpass delete");

    assert!(!deleted.status.success());
    let store = Store::open_existing(dir.path()).unwrap();
    assert_eq!(store.get_item(&valid_b.id).unwrap(), valid_b);
    assert_eq!(
        store.read_secret_file(&valid_b.id).unwrap(),
        b"ciphertext-b"
    );
    assert_eq!(store.check_integrity().unwrap().corrupt_items.len(), 1);
}

#[test]
fn cli_check_repairs_noncanonical_item_key() {
    const ITEMS: TableDefinition<&str, &[u8]> = TableDefinition::new("items");
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let metadata = ItemMeta {
        id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        collection: collection.id,
        label: "bad-key".to_string(),
        attributes: HashMap::new(),
        content_type: "text/plain".to_string(),
        ciphertext_sha256: None,
        created: 1,
        modified: 1,
    };
    drop(store);
    let db = Database::open(dir.path().join("index.redb")).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut items = txn.open_table(ITEMS).unwrap();
        let bytes = serde_json::to_vec(&metadata).unwrap();
        items.insert("bad-key", bytes.as_slice()).unwrap();
    }
    txn.commit().unwrap();
    drop(db);

    let checked = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .arg("--store-dir")
        .arg(dir.path())
        .args(["check", "--yes"])
        .output()
        .expect("spawn noirpass check");

    assert!(
        checked.status.success(),
        "check failed: stdout={} stderr={}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    let store = Store::open_existing(dir.path()).unwrap();
    assert!(store.check_integrity().unwrap().is_healthy());
}

#[test]
fn cli_check_recovers_quarantined_ciphertext_before_repair() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let item = store
        .create_item(
            &collection.id,
            "recoverable",
            HashMap::new(),
            "text/plain",
            b"recoverable-ciphertext",
        )
        .unwrap();
    let canonical = dir.path().join("secrets").join(format!("{}.gpg", item.id));
    let quarantine = dir.path().join("secrets").join(format!(
        ".noirpass-quarantine-{}-0000000000000001.gpg",
        item.id
    ));
    std::fs::rename(&canonical, &quarantine).unwrap();
    drop(store);

    let checked = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .arg("--store-dir")
        .arg(dir.path())
        .args(["check", "--yes"])
        .output()
        .expect("spawn noirpass check");

    assert!(
        checked.status.success(),
        "check failed: stdout={} stderr={}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    let store = Store::open_existing(dir.path()).unwrap();
    assert_eq!(store.get_item(&item.id).unwrap(), item);
    assert_eq!(
        store.read_secret_file(&item.id).unwrap(),
        b"recoverable-ciphertext"
    );
    assert!(!quarantine.exists());
    assert!(store.check_integrity().unwrap().is_healthy());
}

#[test]
fn daemon_recovers_pending_backup_and_quarantine() {
    let h = harness();
    let cert = export_public_cert(&h.gnupg_home);
    for kind in ["backup", "quarantine"] {
        let (mut dbus, address) = spawn_dbus_daemon();
        let store_dir = tempfile::tempdir().unwrap();
        init_noirpass_store(store_dir.path(), &cert);
        let store = Store::open_existing(store_dir.path()).unwrap();
        let collection = store.ensure_default().unwrap();
        let item = store
            .create_item(
                &collection.id,
                kind,
                HashMap::new(),
                "text/plain",
                b"old-ciphertext",
            )
            .unwrap();
        let canonical = store_dir
            .path()
            .join("secrets")
            .join(format!("{}.gpg", item.id));
        let recovery = store_dir
            .path()
            .join("secrets")
            .join(format!(".noirpass-{kind}-{}-0000000000000001.gpg", item.id));
        std::fs::rename(&canonical, &recovery).unwrap();
        if kind == "backup" {
            std::fs::write(&canonical, b"uncommitted-new-ciphertext").unwrap();
        }
        drop(store);

        let mut daemon = spawn_daemon(
            &address,
            &h.gnupg_home,
            store_dir.path(),
            "-1",
            Some(&h.fake_gpg_dir),
        );
        wait_for_name(&address);
        assert_eq!(std::fs::read(&canonical).unwrap(), b"old-ciphertext");
        assert!(!recovery.exists());

        sigterm(daemon.id());
        assert!(wait_with_timeout(&mut daemon, Duration::from_secs(10)).success());
        dbus.kill().expect("kill private dbus-daemon");
        let _ = dbus.wait();
    }
}

#[test]
fn daemon_rejects_path_unsafe_collection_identity() {
    const COLLECTIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("collections");
    let h = harness();
    let (mut dbus, address) = spawn_dbus_daemon();
    let store = tempfile::tempdir().unwrap();
    let cert = export_public_cert(&h.gnupg_home);
    init_noirpass_store(store.path(), &cert);
    let db = Database::open(store.path().join("index.redb")).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut collections = txn.open_table(COLLECTIONS).unwrap();
        let metadata = CollectionMeta {
            id: "bad-key".to_string(),
            label: "corrupt".to_string(),
            created: 1,
            modified: 1,
        };
        let bytes = serde_json::to_vec(&metadata).unwrap();
        collections.insert("bad-key", bytes.as_slice()).unwrap();
    }
    txn.commit().unwrap();
    drop(db);
    let mut daemon = spawn_daemon(
        &address,
        &h.gnupg_home,
        store.path(),
        "-1",
        Some(&h.fake_gpg_dir),
    );

    let status = wait_with_timeout(&mut daemon, Duration::from_secs(10));
    assert!(
        !status.success(),
        "daemon must reject corrupt collection ids"
    );
    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();
}

#[test]
fn daemon_rejects_store_with_missing_index() {
    let h = harness();
    let (mut dbus, address) = spawn_dbus_daemon();
    let store = tempfile::tempdir().unwrap();
    let cert = export_public_cert(&h.gnupg_home);
    init_noirpass_store(store.path(), &cert);
    std::fs::remove_file(store.path().join("index.redb")).unwrap();

    let mut daemon = spawn_daemon(
        &address,
        &h.gnupg_home,
        store.path(),
        "-1",
        Some(&h.fake_gpg_dir),
    );
    let status = wait_with_timeout(&mut daemon, Duration::from_secs(10));

    assert!(!status.success(), "daemon must reject broken store");
    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();
}

#[test]
fn cli_init_rejects_store_with_missing_index() {
    let h = harness();
    let store = tempfile::tempdir().unwrap();
    let cert = export_public_cert(&h.gnupg_home);
    init_noirpass_store(store.path(), &cert);
    std::fs::write(store.path().join("secrets/existing.gpg"), b"ciphertext").unwrap();
    std::fs::remove_file(store.path().join("index.redb")).unwrap();
    let recipient_path = store.path().join("recipient.asc");
    std::fs::write(&recipient_path, &cert).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .arg("--store-dir")
        .arg(store.path())
        .arg("init")
        .arg("--recipient")
        .arg(&recipient_path)
        .output()
        .expect("spawn noirpass init broken store");

    assert!(!output.status.success(), "init must reject broken store");
    assert!(
        !store.path().join("index.redb").exists(),
        "init must not recreate missing index over existing secret files"
    );
}

#[test]
fn cli_init_invalid_recipient_does_not_create_store() {
    let store = tempfile::tempdir().unwrap();
    let recipient_path = store.path().join("not-openpgp.asc");
    std::fs::write(&recipient_path, b"not openpgp").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .arg("--store-dir")
        .arg(store.path())
        .arg("init")
        .arg("--recipient")
        .arg(&recipient_path)
        .output()
        .expect("spawn noirpass init invalid recipient");

    assert!(!output.status.success(), "init must reject invalid cert");
    assert!(
        !store.path().join("index.redb").exists(),
        "invalid init must not create index"
    );
    assert!(
        !store.path().join("secrets").exists(),
        "invalid init must not create secrets dir"
    );
}

#[test]
fn daemon_rejects_recipient_without_matching_secret_key() {
    let h = harness();
    let other_gnupg = tempfile::tempdir().unwrap();
    setup_gnupg(other_gnupg.path());
    let other_cert = export_public_cert(other_gnupg.path());
    let (mut dbus, address) = spawn_dbus_daemon();
    let store = tempfile::tempdir().unwrap();
    init_noirpass_store(store.path(), &other_cert);

    let status_output = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .arg("--store-dir")
        .arg(store.path())
        .arg("status")
        .env("GNUPGHOME", &h.gnupg_home)
        .output()
        .expect("spawn noirpass status wrong recipient");
    assert!(
        !status_output.status.success(),
        "status must reject recipient that cannot be decrypted by this GNUPGHOME"
    );
    assert!(
        String::from_utf8_lossy(&status_output.stderr).contains("no available GnuPG secret key")
    );

    let mut daemon = spawn_daemon(
        &address,
        &h.gnupg_home,
        store.path(),
        "-1",
        Some(&h.fake_gpg_dir),
    );
    let status = wait_with_timeout(&mut daemon, Duration::from_secs(10));

    assert!(
        !status.success(),
        "daemon must reject recipient that cannot be decrypted by this GNUPGHOME"
    );
    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();
    let _ = Command::new("gpgconf")
        .arg("--homedir")
        .arg(other_gnupg.path())
        .args(["--kill", "gpg-agent"])
        .status();
}

#[test]
fn cli_init_stdin_and_status_exit_codes() {
    let gnupg = tempfile::tempdir().unwrap();
    setup_gnupg(gnupg.path());
    let cert = export_public_cert(gnupg.path());
    let store = tempfile::tempdir().unwrap();

    let uninitialized = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .arg("--store-dir")
        .arg(store.path())
        .arg("status")
        .output()
        .expect("spawn noirpass status uninitialized");
    assert!(!uninitialized.status.success());
    assert!(
        String::from_utf8_lossy(&uninitialized.stderr).contains("run noirpass init --recipient")
    );

    init_noirpass_store_from_stdin(store.path(), &cert);

    let usable = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .arg("--store-dir")
        .arg(store.path())
        .arg("status")
        .env("GNUPGHOME", gnupg.path())
        .output()
        .expect("spawn noirpass status initialized");
    assert!(
        usable.status.success(),
        "status failed: stdout={} stderr={}",
        String::from_utf8_lossy(&usable.stdout),
        String::from_utf8_lossy(&usable.stderr)
    );
    let stdout = String::from_utf8_lossy(&usable.stdout);
    assert!(stdout.contains("initialized: yes"));
    assert!(stdout.contains("fingerprint matches: yes"));
    assert!(stdout.contains("cert has encryption-capable key: yes"));

    let (fake_gpg_tmp, _fake_gpg_log) = fake_gpg_dir();
    let (mut dbus, address) = spawn_dbus_daemon();
    let mut daemon = spawn_daemon(
        &address,
        gnupg.path(),
        store.path(),
        "-1",
        Some(fake_gpg_tmp.path()),
    );
    wait_for_name(&address);

    let live = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .arg("--store-dir")
        .arg(store.path())
        .arg("status")
        .env("GNUPGHOME", gnupg.path())
        .output()
        .expect("spawn noirpass status with running daemon");
    assert!(
        live.status.success(),
        "status with running daemon failed: stdout={} stderr={}",
        String::from_utf8_lossy(&live.stdout),
        String::from_utf8_lossy(&live.stderr)
    );

    sigterm(daemon.id());
    let _ = wait_with_timeout(&mut daemon, Duration::from_secs(10));
    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();
}
