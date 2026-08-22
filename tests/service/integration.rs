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

use std::path::PathBuf;
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use noirpass::crypto::DhHandshake;
use noirpass::service::session::Secret as WireSecret;
use noirpass::store::{CollectionMeta, Store};
use redb::{Database, TableDefinition};
use zbus::export::futures_core::Stream;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

use super::common::{
    export_public_cert, fake_gpg_dir, init_noirpass_store, record_daemon_pid, setup_gnupg, sigterm,
    spawn_daemon, spawn_dbus_daemon, wait_for_name, wait_with_timeout,
};

const SERVICE_NAME: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SERVICE_IFACE: &str = "org.freedesktop.Secret.Service";
const COLLECTION_IFACE: &str = "org.freedesktop.Secret.Collection";
const ITEM_IFACE: &str = "org.freedesktop.Secret.Item";
const PROPERTIES_IFACE: &str = "org.freedesktop.DBus.Properties";
const INVALID_ARGS_ERROR: &str = "org.freedesktop.DBus.Error.InvalidArgs";
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
    daemon_pid_file: PathBuf,
    daemon: Mutex<Child>,
    _keep: Vec<tempfile::TempDir>,
}

static HARNESS: OnceLock<Harness> = OnceLock::new();

fn harness() -> &'static Harness {
    HARNESS.get_or_init(Harness::init)
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

        let daemon_pid_tmp = tempfile::tempdir().unwrap();
        let daemon_pid_file = daemon_pid_tmp.path().join("daemon.pid");

        // The high-level oo7/zbus session helpers used by scenarios read
        // DBUS_SESSION_BUS_ADDRESS from process environment, so child-only injection cannot
        // configure them. This one shared fixture sets it before dependent tests begin.
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
        record_daemon_pid(&daemon_pid_file, &daemon);
        wait_for_name(&bus_address);

        let gnupg_home = gnupg_tmp.path().to_path_buf();
        let store_dir = store_tmp.path().to_path_buf();

        // Reaper: if the test process dies (success or abort), terminate the
        // exact fixture-owned daemon PID (SIGTERM, so it flushes coverage), the
        // private bus, and the test-owned gpg-agent. The PID file is updated
        // when the harness respawns its daemon.
        let test_pid = std::process::id();
        let script = format!(
            "while kill -0 {test_pid} 2>/dev/null; do sleep 0.5; done; \\
             if test -r '{pid_file}'; then \\
               IFS= read -r daemon_pid < '{pid_file}' || daemon_pid=; \\
               case \"$daemon_pid\" in \\
                 ''|*[!0-9]*) ;; \\
                 *) kill -TERM \"$daemon_pid\" 2>/dev/null ;; \\
               esac; \\
             fi; \\
             kill -TERM {dbus_pid} 2>/dev/null; \\
             gpgconf --homedir '{gnupg}' --kill gpg-agent 2>/dev/null; true",
            pid_file = daemon_pid_file.display(),
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
            daemon_pid_file,
            daemon: Mutex::new(daemon),
            _keep: vec![gnupg_tmp, store_tmp, fake_gpg_tmp, daemon_pid_tmp],
        }
    }

    /// SIGTERM the daemon and assert it exits cleanly.
    fn stop_daemon(&self) {
        let mut child = self.daemon.lock().unwrap();
        sigterm(child.id());
        let status = wait_with_timeout(&mut child, Duration::from_secs(10));
        std::fs::write(&self.daemon_pid_file, "").expect("clear daemon pid");
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
        record_daemon_pid(&self.daemon_pid_file, &fresh);
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

async fn next_property_change<S>(
    stream: Pin<&mut S>,
    expected_interface: &str,
) -> (String, OwnedValue)
where
    S: Stream<Item = zbus::Message>,
{
    let message = tokio::time::timeout(Duration::from_secs(10), next_event(stream))
        .await
        .expect("timed out waiting for PropertiesChanged")
        .expect("PropertiesChanged stream ended");
    let (interface, changed, invalidated): (String, HashMap<String, OwnedValue>, Vec<String>) =
        message.body().deserialize().unwrap();
    assert_eq!(interface, expected_interface);
    assert!(invalidated.is_empty());
    assert_eq!(changed.len(), 1);
    changed.into_iter().next().unwrap()
}

async fn next_invalidated_properties<S>(
    stream: Pin<&mut S>,
    expected_interface: &str,
) -> Vec<String>
where
    S: Stream<Item = zbus::Message>,
{
    let message = tokio::time::timeout(Duration::from_secs(10), next_event(stream))
        .await
        .expect("timed out waiting for invalidated PropertiesChanged")
        .expect("invalidated PropertiesChanged stream ended");
    let (interface, changed, invalidated): (String, HashMap<String, OwnedValue>, Vec<String>) =
        message.body().deserialize().unwrap();
    assert_eq!(interface, expected_interface);
    assert!(changed.is_empty());
    invalidated
}

async fn next_property_name<S>(stream: Pin<&mut S>) -> String
where
    S: Stream<Item = zbus::Message>,
{
    next_property_change(stream, ITEM_IFACE).await.0
}

async fn assert_no_signal<S>(stream: Pin<&mut S>, description: &str)
where
    S: Stream<Item = zbus::Message>,
{
    assert!(
        tokio::time::timeout(Duration::from_millis(250), next_event(stream))
            .await
            .is_err(),
        "unexpected {description}"
    );
}

async fn next_item_changed<S>(stream: Pin<&mut S>, expected: &OwnedObjectPath)
where
    S: Stream<Item = zbus::Message>,
{
    let message = tokio::time::timeout(Duration::from_secs(10), next_event(stream))
        .await
        .expect("timed out waiting for ItemChanged")
        .expect("ItemChanged stream ended");
    let (item,): (OwnedObjectPath,) = message.body().deserialize().unwrap();
    assert_eq!(&item, expected);
}

async fn locked_property(proxy: &zbus::Proxy<'_>, interface: &str) -> bool {
    let value: OwnedValue = proxy
        .call::<_, _, OwnedValue>("Get", &(interface, "Locked"))
        .await
        .expect("Locked property");
    bool::try_from(value).expect("Locked property must be boolean")
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

fn collection_properties(label: Option<&str>) -> HashMap<String, OwnedValue> {
    let Some(label) = label else {
        return HashMap::new();
    };
    HashMap::from([(
        "org.freedesktop.Secret.Collection.Label".to_string(),
        Value::from(label).try_to_owned().unwrap(),
    )])
}

fn item_properties(label: &str, case: &str) -> HashMap<String, OwnedValue> {
    HashMap::from([
        (
            "org.freedesktop.Secret.Item.Label".to_string(),
            Value::from(label).try_to_owned().unwrap(),
        ),
        (
            "org.freedesktop.Secret.Item.Attributes".to_string(),
            Value::from(attrs(case).into_iter().collect::<HashMap<_, _>>())
                .try_to_owned()
                .unwrap(),
        ),
    ])
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

/// Scenario 3: strict `plain` session and Secret parameter validation.
#[allow(
    clippy::too_many_lines,
    reason = "one private-bus scenario covers strict session and Secret validation"
)]
async fn s3_plain_protocol_validation() {
    let conn = zbus::Connection::session().await.unwrap();
    let service = service_proxy(&conn).await;

    let (output, session): (OwnedValue, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();
    assert_eq!(String::try_from(output).unwrap(), "");

    let err = service
        .call::<_, _, (OwnedValue, OwnedObjectPath)>(
            "OpenSession",
            &("plain", Value::from("non-empty")),
        )
        .await
        .unwrap_err();
    assert_method_error(&err, INVALID_ARGS_ERROR);

    let err = service
        .call::<_, _, (OwnedValue, OwnedObjectPath)>(
            "OpenSession",
            &("plain", Value::from(vec![1_u8])),
        )
        .await
        .unwrap_err();
    assert_method_error(&err, INVALID_ARGS_ERROR);

    let (collection_path, prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call(
            "CreateCollection",
            &(collection_properties(Some("s3-plain-protocol")), ""),
        )
        .await
        .unwrap();
    assert_eq!(prompt.as_str(), "/");
    let collection = zbus::Proxy::new(&conn, SERVICE_NAME, collection_path, COLLECTION_IFACE)
        .await
        .unwrap();

    let item_properties = HashMap::from([(
        "org.freedesktop.Secret.Item.Label".to_string(),
        Value::from("s3-initial").try_to_owned().unwrap(),
    )]);
    let initial_secret = WireSecret {
        session: session.clone(),
        parameters: Vec::new(),
        value: Zeroizing::new(b"initial secret".to_vec()),
        content_type: "text/plain".to_string(),
    };
    let (item_path, prompt): (OwnedObjectPath, OwnedObjectPath) = collection
        .call("CreateItem", &(&item_properties, &initial_secret, false))
        .await
        .unwrap();
    assert_eq!(prompt.as_str(), "/");

    let item = zbus::Proxy::new(&conn, SERVICE_NAME, item_path.clone(), ITEM_IFACE)
        .await
        .unwrap();
    let (before,): (WireSecret,) = item.call("GetSecret", &(&session,)).await.unwrap();
    assert!(before.parameters.is_empty());
    assert_eq!(before.value.as_slice(), b"initial secret");

    let rejected_update = WireSecret {
        session: session.clone(),
        parameters: vec![1_u8],
        value: Zeroizing::new(b"must not replace".to_vec()),
        content_type: "text/custom".to_string(),
    };
    let err = item
        .call::<_, _, ()>("SetSecret", &(&rejected_update,))
        .await
        .unwrap_err();
    assert_method_error(&err, INVALID_ARGS_ERROR);

    let (after,): (WireSecret,) = item.call("GetSecret", &(&session,)).await.unwrap();
    assert_eq!(after, before);

    let before_items: Vec<OwnedObjectPath> = collection.get_property("Items").await.unwrap();
    assert_eq!(before_items, vec![item_path.clone()]);
    let rejected_create = WireSecret {
        session: session.clone(),
        parameters: vec![2_u8],
        value: Zeroizing::new(b"must not create".to_vec()),
        content_type: "text/plain".to_string(),
    };
    let empty_properties: HashMap<String, OwnedValue> = HashMap::new();
    let err = collection
        .call::<_, _, (OwnedObjectPath, OwnedObjectPath)>(
            "CreateItem",
            &(&empty_properties, &rejected_create, false),
        )
        .await
        .unwrap_err();
    assert_method_error(&err, INVALID_ARGS_ERROR);
    let after_items: Vec<OwnedObjectPath> = collection.get_property("Items").await.unwrap();
    assert_eq!(after_items, before_items);

    item.call::<_, _, OwnedObjectPath>("Delete", &())
        .await
        .unwrap();
    collection
        .call::<_, _, OwnedObjectPath>("Delete", &())
        .await
        .unwrap();
    let session_proxy = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        session,
        "org.freedesktop.Secret.Session",
    )
    .await
    .unwrap();
    session_proxy.call::<_, _, ()>("Close", &()).await.unwrap();
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
        assert_eq!(secret.value.as_slice(), expected[path].as_slice());
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
        let plaintext = cipher
            .decrypt(&secret.parameters, secret.value.as_slice())
            .unwrap();
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
        value: Zeroizing::new(b"foreign session value".to_vec()),
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
    use std::io::Write as _;

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

/// Scenario 11: lock methods preserve Noirpass's always-unlocked semantics.
async fn s11_lock_semantics() {
    let service = oo7::dbus::Service::plain().await.unwrap();
    let collection = service
        .create_collection("s11-lock", None, None)
        .await
        .unwrap();
    let item = collection
        .create_item(
            "s11-item",
            &attrs("s11"),
            oo7::Secret::text("always unlocked"),
            true,
            None,
        )
        .await
        .unwrap();
    let collection_path = OwnedObjectPath::from(collection.path().to_owned());
    let item_path = OwnedObjectPath::from(item.path().to_owned());

    let conn = zbus::Connection::session().await.unwrap();
    let service_proxy = service_proxy(&conn).await;
    let collection_properties = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        collection_path.clone(),
        PROPERTIES_IFACE,
    )
    .await
    .unwrap();
    let item_properties =
        zbus::Proxy::new(&conn, SERVICE_NAME, item_path.clone(), PROPERTIES_IFACE)
            .await
            .unwrap();

    assert!(!locked_property(&item_properties, "org.freedesktop.Secret.Item").await);
    let (locked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service_proxy
        .call("Lock", &(vec![item_path.clone()],))
        .await
        .unwrap();
    assert!(locked.is_empty());
    assert_eq!(prompt.as_str(), "/");
    assert!(!locked_property(&item_properties, "org.freedesktop.Secret.Item").await);

    assert!(!locked_property(&collection_properties, COLLECTION_IFACE).await);
    let (locked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service_proxy
        .call("Lock", &(vec![collection_path.clone()],))
        .await
        .unwrap();
    assert!(locked.is_empty());
    assert_eq!(prompt.as_str(), "/");
    assert!(!locked_property(&collection_properties, COLLECTION_IFACE).await);

    let (locked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service_proxy
        .call("Lock", &(vec![collection_path.clone(), item_path.clone()],))
        .await
        .unwrap();
    assert!(locked.is_empty());
    assert_eq!(prompt.as_str(), "/");

    let (unlocked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service_proxy
        .call("Unlock", &(vec![item_path.clone()],))
        .await
        .unwrap();
    assert_eq!(unlocked, vec![item_path]);
    assert_eq!(prompt.as_str(), "/");

    collection.delete(None).await.unwrap();
}

/// Scenario 12: item mutations emit required property and collection signals.
#[allow(
    clippy::too_many_lines,
    reason = "one private-bus scenario covers every item mutation notification path"
)]
async fn s12_item_mutation_signals() {
    let h = harness();
    let service = oo7::dbus::Service::plain().await.unwrap();
    let collection = service
        .create_collection("s12-mutations", None, None)
        .await
        .unwrap();
    let attributes = attrs("s12");
    let item = collection
        .create_item(
            "s12-initial",
            &attributes,
            oo7::Secret::text("initial secret"),
            true,
            None,
        )
        .await
        .unwrap();
    let collection_path = OwnedObjectPath::from(collection.path().to_owned());
    let item_path = OwnedObjectPath::from(item.path().to_owned());

    let conn = zbus::Connection::session().await.unwrap();
    let service_proxy = service_proxy(&conn).await;
    let item_proxy = zbus::Proxy::new(&conn, SERVICE_NAME, item_path.clone(), ITEM_IFACE)
        .await
        .unwrap();
    let item_properties =
        zbus::Proxy::new(&conn, SERVICE_NAME, item_path.clone(), PROPERTIES_IFACE)
            .await
            .unwrap();
    let collection_proxy = zbus::Proxy::new(
        &conn,
        SERVICE_NAME,
        collection_path.clone(),
        COLLECTION_IFACE,
    )
    .await
    .unwrap();
    let (_, session): (OwnedValue, OwnedObjectPath) = service_proxy
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();

    // SetSecret emits ItemChanged and Modified.
    let mut item_changed = std::pin::pin!(
        collection_proxy
            .receive_signal("ItemChanged")
            .await
            .unwrap()
    );
    let mut properties_changed = std::pin::pin!(
        item_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let secret = WireSecret {
        session: session.clone(),
        parameters: Vec::new(),
        value: Zeroizing::new(b"changed secret".to_vec()),
        content_type: "text/plain".to_string(),
    };
    item_proxy
        .call::<_, _, ()>("SetSecret", &(&secret,))
        .await
        .unwrap();
    assert_eq!(
        next_property_name(properties_changed.as_mut()).await,
        "Modified"
    );
    assert_no_signal(
        properties_changed.as_mut(),
        "duplicate SetSecret property signal",
    )
    .await;
    next_item_changed(item_changed.as_mut(), &item_path).await;
    assert_no_signal(item_changed.as_mut(), "duplicate SetSecret ItemChanged").await;

    // Label setter emits one explicit Label signal plus Modified and ItemChanged.
    let mut item_changed = std::pin::pin!(
        collection_proxy
            .receive_signal("ItemChanged")
            .await
            .unwrap()
    );
    let mut properties_changed = std::pin::pin!(
        item_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    item_proxy.set_property("Label", "s12-label").await.unwrap();
    let label_names = vec![
        next_property_name(properties_changed.as_mut()).await,
        next_property_name(properties_changed.as_mut()).await,
    ];
    assert_eq!(label_names, ["Label", "Modified"]);
    assert_no_signal(
        properties_changed.as_mut(),
        "duplicate Label property signal",
    )
    .await;
    next_item_changed(item_changed.as_mut(), &item_path).await;
    assert_no_signal(item_changed.as_mut(), "duplicate Label ItemChanged").await;

    // Attributes setter emits one explicit Attributes signal plus Modified and ItemChanged.
    let mut item_changed = std::pin::pin!(
        collection_proxy
            .receive_signal("ItemChanged")
            .await
            .unwrap()
    );
    let mut properties_changed = std::pin::pin!(
        item_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let replacement_attributes = HashMap::from([
        ("app".to_string(), "noirpass-e2e".to_string()),
        ("case".to_string(), "s12-updated".to_string()),
    ]);
    item_proxy
        .set_property("Attributes", replacement_attributes.clone())
        .await
        .unwrap();
    let attribute_names = vec![
        next_property_name(properties_changed.as_mut()).await,
        next_property_name(properties_changed.as_mut()).await,
    ];
    assert_eq!(attribute_names, ["Attributes", "Modified"]);
    assert_no_signal(
        properties_changed.as_mut(),
        "duplicate Attributes property signal",
    )
    .await;
    next_item_changed(item_changed.as_mut(), &item_path).await;
    assert_no_signal(item_changed.as_mut(), "duplicate Attributes ItemChanged").await;

    // Replacement emits one Label, one Modified, ItemChanged, but not ItemCreated.
    let mut item_changed = std::pin::pin!(
        collection_proxy
            .receive_signal("ItemChanged")
            .await
            .unwrap()
    );
    let mut item_created = std::pin::pin!(
        collection_proxy
            .receive_signal("ItemCreated")
            .await
            .unwrap()
    );
    let mut properties_changed = std::pin::pin!(
        item_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let replacement = collection
        .create_item(
            "s12-replaced",
            &replacement_attributes,
            oo7::Secret::text("replaced secret"),
            true,
            None,
        )
        .await
        .unwrap();
    assert_eq!(replacement.path(), item.path());
    let replacement_names = vec![
        next_property_name(properties_changed.as_mut()).await,
        next_property_name(properties_changed.as_mut()).await,
    ];
    assert_eq!(replacement_names, ["Label", "Modified"]);
    assert_no_signal(
        properties_changed.as_mut(),
        "duplicate replacement property signal",
    )
    .await;
    next_item_changed(item_changed.as_mut(), &item_path).await;
    assert_no_signal(item_changed.as_mut(), "duplicate replacement ItemChanged").await;
    assert!(
        tokio::time::timeout(
            Duration::from_millis(250),
            next_event(item_created.as_mut())
        )
        .await
        .is_err(),
        "replacement must not emit ItemCreated"
    );

    // A failed persistence mutation emits no property or ItemChanged signals.
    let mut item_changed = std::pin::pin!(
        collection_proxy
            .receive_signal("ItemChanged")
            .await
            .unwrap()
    );
    let mut properties_changed = std::pin::pin!(
        item_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let secrets_dir = h.store_dir.join("secrets");
    let hidden_secrets_dir = h.store_dir.join("s12-secrets-hidden");
    std::fs::rename(&secrets_dir, &hidden_secrets_dir).unwrap();
    std::fs::write(&secrets_dir, b"not a directory").unwrap();
    let failed_secret = WireSecret {
        session,
        parameters: Vec::new(),
        value: Zeroizing::new(b"must not persist".to_vec()),
        content_type: "text/plain".to_string(),
    };
    let failure = item_proxy
        .call::<_, _, ()>("SetSecret", &(&failed_secret,))
        .await;
    std::fs::remove_file(&secrets_dir).unwrap();
    std::fs::rename(&hidden_secrets_dir, &secrets_dir).unwrap();
    assert!(failure.is_err(), "SetSecret persistence must fail");
    assert!(
        tokio::time::timeout(
            Duration::from_millis(250),
            next_event(properties_changed.as_mut())
        )
        .await
        .is_err(),
        "failed persistence must not emit PropertiesChanged"
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(250),
            next_event(item_changed.as_mut())
        )
        .await
        .is_err(),
        "failed persistence must not emit ItemChanged"
    );

    collection.delete(None).await.unwrap();
}

/// Scenario 13: reusing an existing alias applies an optional collection label
/// without changing collection membership or the alias target.
#[allow(
    clippy::too_many_lines,
    reason = "one private-bus scenario covers every CreateCollection alias/property case"
)]
async fn s13_existing_alias_collection() {
    let conn = zbus::Connection::session().await.unwrap();
    let service = service_proxy(&conn).await;
    let initial_count: Vec<OwnedObjectPath> = service.get_property("Collections").await.unwrap();

    let (initial_path, prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call(
            "CreateCollection",
            &(
                collection_properties(Some("s13-initial")),
                "s13-existing-alias",
            ),
        )
        .await
        .unwrap();
    assert_eq!(prompt.as_str(), "/");
    assert_eq!(
        service
            .call::<_, _, OwnedObjectPath>("ReadAlias", &("s13-existing-alias",))
            .await
            .unwrap(),
        initial_path
    );

    let collection = zbus::Proxy::new(&conn, SERVICE_NAME, initial_path.clone(), COLLECTION_IFACE)
        .await
        .unwrap();
    let collection_properties_proxy =
        zbus::Proxy::new(&conn, SERVICE_NAME, initial_path.clone(), PROPERTIES_IFACE)
            .await
            .unwrap();
    let service_properties = zbus::Proxy::new(&conn, SERVICE_NAME, SERVICE_PATH, PROPERTIES_IFACE)
        .await
        .unwrap();
    let initial_label: String = collection.get_property("Label").await.unwrap();
    assert_eq!(initial_label, "s13-initial");
    let initial_modified: u64 = collection.get_property("Modified").await.unwrap();

    // Existing alias + supplied Label updates the existing collection in place.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let mut collection_properties_changed = std::pin::pin!(
        collection_properties_proxy
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut collection_changed =
        std::pin::pin!(service.receive_signal("CollectionChanged").await.unwrap());
    let mut collection_created =
        std::pin::pin!(service.receive_signal("CollectionCreated").await.unwrap());
    let mut service_properties_changed = std::pin::pin!(
        service_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let (returned_path, prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call(
            "CreateCollection",
            &(
                collection_properties(Some("s13-updated")),
                "s13-existing-alias",
            ),
        )
        .await
        .unwrap();
    assert_eq!(returned_path, initial_path);
    assert_eq!(prompt.as_str(), "/");
    assert_eq!(
        service
            .call::<_, _, OwnedObjectPath>("ReadAlias", &("s13-existing-alias",))
            .await
            .unwrap(),
        initial_path
    );
    let (label_name, label_value) =
        next_property_change(collection_properties_changed.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(label_name, "Label");
    assert_eq!(String::try_from(label_value).unwrap(), "s13-updated");
    let (modified_name, modified_value) =
        next_property_change(collection_properties_changed.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(modified_name, "Modified");
    let modified_after: u64 = collection.get_property("Modified").await.unwrap();
    assert_eq!(u64::try_from(modified_value).unwrap(), modified_after);
    assert!(modified_after > initial_modified);
    assert_eq!(
        collection.get_property::<String>("Label").await.unwrap(),
        "s13-updated"
    );
    let changed_message = tokio::time::timeout(
        Duration::from_secs(10),
        next_event(collection_changed.as_mut()),
    )
    .await
    .expect("timed out waiting for CollectionChanged")
    .expect("CollectionChanged stream ended");
    let (changed_path,): (OwnedObjectPath,) = changed_message.body().deserialize().unwrap();
    assert_eq!(changed_path, initial_path);
    assert_no_signal(
        collection_created.as_mut(),
        "CollectionCreated for existing alias",
    )
    .await;
    assert_no_signal(
        service_properties_changed.as_mut(),
        "Service.Collections change for existing alias",
    )
    .await;
    let after_update_count: Vec<OwnedObjectPath> =
        service.get_property("Collections").await.unwrap();
    assert_eq!(after_update_count.len(), initial_count.len() + 1);
    assert!(after_update_count.contains(&initial_path));

    // Existing alias + no Label is a no-op, including timestamps and signals.
    let unchanged_label: String = collection.get_property("Label").await.unwrap();
    let unchanged_modified: u64 = collection.get_property("Modified").await.unwrap();
    let mut collection_properties_changed = std::pin::pin!(
        collection_properties_proxy
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut collection_changed =
        std::pin::pin!(service.receive_signal("CollectionChanged").await.unwrap());
    let mut collection_created =
        std::pin::pin!(service.receive_signal("CollectionCreated").await.unwrap());
    let mut service_properties_changed = std::pin::pin!(
        service_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let (returned_path, prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call::<_, _, (OwnedObjectPath, OwnedObjectPath)>(
            "CreateCollection",
            &(HashMap::<String, OwnedValue>::new(), "s13-existing-alias"),
        )
        .await
        .unwrap();
    assert_eq!(returned_path, initial_path);
    assert_eq!(prompt.as_str(), "/");
    assert_eq!(
        collection.get_property::<String>("Label").await.unwrap(),
        unchanged_label
    );
    assert_eq!(
        collection.get_property::<u64>("Modified").await.unwrap(),
        unchanged_modified
    );
    assert_no_signal(
        collection_properties_changed.as_mut(),
        "PropertiesChanged for absent Label",
    )
    .await;
    assert_no_signal(
        collection_changed.as_mut(),
        "CollectionChanged for absent Label",
    )
    .await;
    assert_no_signal(
        collection_created.as_mut(),
        "CollectionCreated for absent Label",
    )
    .await;
    assert_no_signal(
        service_properties_changed.as_mut(),
        "Service.Collections change for absent Label",
    )
    .await;

    // Existing alias + explicit empty Label must mutate the label.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let modified_before_empty: u64 = collection.get_property("Modified").await.unwrap();
    let mut collection_properties_changed = std::pin::pin!(
        collection_properties_proxy
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut collection_changed =
        std::pin::pin!(service.receive_signal("CollectionChanged").await.unwrap());
    let mut collection_created =
        std::pin::pin!(service.receive_signal("CollectionCreated").await.unwrap());
    let mut service_properties_changed = std::pin::pin!(
        service_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let (returned_path, prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call(
            "CreateCollection",
            &(collection_properties(Some("")), "s13-existing-alias"),
        )
        .await
        .unwrap();
    assert_eq!(returned_path, initial_path);
    assert_eq!(prompt.as_str(), "/");
    let (label_name, label_value) =
        next_property_change(collection_properties_changed.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(label_name, "Label");
    assert_eq!(String::try_from(label_value).unwrap(), "");
    let (modified_name, _) =
        next_property_change(collection_properties_changed.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(modified_name, "Modified");
    assert_eq!(
        collection.get_property::<String>("Label").await.unwrap(),
        ""
    );
    assert!(collection.get_property::<u64>("Modified").await.unwrap() > modified_before_empty);
    let changed_message = tokio::time::timeout(
        Duration::from_secs(10),
        next_event(collection_changed.as_mut()),
    )
    .await
    .expect("timed out waiting for empty-label CollectionChanged")
    .expect("empty-label CollectionChanged stream ended");
    let (changed_path,): (OwnedObjectPath,) = changed_message.body().deserialize().unwrap();
    assert_eq!(changed_path, initial_path);
    assert_no_signal(
        collection_created.as_mut(),
        "CollectionCreated for empty Label",
    )
    .await;
    assert_no_signal(
        service_properties_changed.as_mut(),
        "Service.Collections change for empty Label",
    )
    .await;

    // Alias absent keeps normal creation behavior and grows Collections.
    let before_new_count: Vec<OwnedObjectPath> = service.get_property("Collections").await.unwrap();
    let mut collection_created =
        std::pin::pin!(service.receive_signal("CollectionCreated").await.unwrap());
    let mut service_properties_changed = std::pin::pin!(
        service_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let (new_path, prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call(
            "CreateCollection",
            &(collection_properties(Some("s13-no-alias")), ""),
        )
        .await
        .unwrap();
    assert_ne!(new_path, initial_path);
    assert_eq!(prompt.as_str(), "/");
    let new_collection = zbus::Proxy::new(&conn, SERVICE_NAME, new_path.clone(), COLLECTION_IFACE)
        .await
        .unwrap();
    assert_eq!(
        new_collection
            .get_property::<String>("Label")
            .await
            .unwrap(),
        "s13-no-alias"
    );
    let created_message = tokio::time::timeout(
        Duration::from_secs(10),
        next_event(collection_created.as_mut()),
    )
    .await
    .expect("timed out waiting for alias-absent CollectionCreated")
    .expect("alias-absent CollectionCreated stream ended");
    let (created_path,): (OwnedObjectPath,) = created_message.body().deserialize().unwrap();
    assert_eq!(created_path, new_path);
    let (interface, changed, invalidated): (String, HashMap<String, OwnedValue>, Vec<String>) =
        tokio::time::timeout(
            Duration::from_secs(10),
            next_event(service_properties_changed.as_mut()),
        )
        .await
        .expect("timed out waiting for alias-absent Collections change")
        .expect("alias-absent Collections stream ended")
        .body()
        .deserialize()
        .unwrap();
    assert_eq!(interface, SERVICE_IFACE);
    assert!(invalidated.is_empty());
    assert_eq!(changed.len(), 1);
    assert!(changed.contains_key("Collections"));
    let after_new_count: Vec<OwnedObjectPath> = service.get_property("Collections").await.unwrap();
    assert_eq!(after_new_count.len(), before_new_count.len() + 1);
    assert!(after_new_count.contains(&new_path));

    for path in [initial_path, new_path] {
        let collection = zbus::Proxy::new(&conn, SERVICE_NAME, path, COLLECTION_IFACE)
            .await
            .unwrap();
        collection
            .call::<_, _, OwnedObjectPath>("Delete", &())
            .await
            .unwrap();
    }
}

/// Scenario 14: collection properties and membership stay coherent across
/// canonical and alias object paths, including alias target changes.
#[allow(
    clippy::too_many_lines,
    reason = "one private-bus scenario covers collection and alias notification semantics"
)]
async fn s14_collection_alias_notifications() {
    let conn = zbus::Connection::session().await.unwrap();
    let service = service_proxy(&conn).await;

    let (a_path, prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call(
            "CreateCollection",
            &(collection_properties(Some("s14-a")), "s14_alias"),
        )
        .await
        .unwrap();
    assert_eq!(prompt.as_str(), "/");
    let (b_path, prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call(
            "CreateCollection",
            &(collection_properties(Some("s14-b")), ""),
        )
        .await
        .unwrap();
    assert_eq!(prompt.as_str(), "/");

    let alias_path = noirpass::service::alias_path("s14_alias").unwrap();
    let canonical = zbus::Proxy::new(&conn, SERVICE_NAME, a_path.clone(), COLLECTION_IFACE)
        .await
        .unwrap();
    let alias = zbus::Proxy::new(&conn, SERVICE_NAME, alias_path.clone(), COLLECTION_IFACE)
        .await
        .unwrap();
    let other = zbus::Proxy::new(&conn, SERVICE_NAME, b_path.clone(), COLLECTION_IFACE)
        .await
        .unwrap();
    let canonical_properties =
        zbus::Proxy::new(&conn, SERVICE_NAME, a_path.clone(), PROPERTIES_IFACE)
            .await
            .unwrap();
    let alias_properties =
        zbus::Proxy::new(&conn, SERVICE_NAME, alias_path.clone(), PROPERTIES_IFACE)
            .await
            .unwrap();
    let service_properties = zbus::Proxy::new(&conn, SERVICE_NAME, SERVICE_PATH, PROPERTIES_IFACE)
        .await
        .unwrap();

    // Canonical Label setter fans out Label and Modified exactly once to every
    // served path, then reports the canonical CollectionChanged path.
    let initial_modified: u64 = canonical.get_property("Modified").await.unwrap();
    let _: String = alias.get_property("Label").await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let mut canonical_changes = std::pin::pin!(
        canonical_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut alias_changes = std::pin::pin!(
        alias_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut collection_changed =
        std::pin::pin!(service.receive_signal("CollectionChanged").await.unwrap());
    canonical
        .set_property("Label", "s14-canonical-label")
        .await
        .unwrap();

    let (name, value) = next_property_change(canonical_changes.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(name, "Label");
    assert_eq!(String::try_from(value).unwrap(), "s14-canonical-label");
    let (name, value) = next_property_change(canonical_changes.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(name, "Modified");
    let modified_after: u64 = canonical.get_property("Modified").await.unwrap();
    assert_eq!(u64::try_from(value).unwrap(), modified_after);
    assert!(modified_after > initial_modified);
    assert_no_signal(canonical_changes.as_mut(), "duplicate canonical Label").await;

    let (name, value) = next_property_change(alias_changes.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(name, "Label");
    assert_eq!(String::try_from(value).unwrap(), "s14-canonical-label");
    let (name, _) = next_property_change(alias_changes.as_mut(), COLLECTION_IFACE).await;
    assert_eq!(name, "Modified");
    assert_no_signal(alias_changes.as_mut(), "duplicate alias Label").await;
    assert_eq!(
        alias.get_property::<String>("Label").await.unwrap(),
        "s14-canonical-label"
    );

    let message = tokio::time::timeout(
        Duration::from_secs(10),
        next_event(collection_changed.as_mut()),
    )
    .await
    .expect("timed out waiting for canonical CollectionChanged")
    .expect("canonical CollectionChanged stream ended");
    let (changed_path,): (OwnedObjectPath,) = message.body().deserialize().unwrap();
    assert_eq!(changed_path, a_path);

    // Label setter through alias has identical canonical fanout and signal
    // path semantics.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let mut canonical_changes = std::pin::pin!(
        canonical_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut alias_changes = std::pin::pin!(
        alias_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut collection_changed =
        std::pin::pin!(service.receive_signal("CollectionChanged").await.unwrap());
    alias
        .set_property("Label", "s14-alias-label")
        .await
        .unwrap();
    for changes in [&mut canonical_changes, &mut alias_changes] {
        let (name, value) = next_property_change(changes.as_mut(), COLLECTION_IFACE).await;
        assert_eq!(name, "Label");
        assert_eq!(String::try_from(value).unwrap(), "s14-alias-label");
        let (name, _) = next_property_change(changes.as_mut(), COLLECTION_IFACE).await;
        assert_eq!(name, "Modified");
        assert_no_signal(changes.as_mut(), "duplicate alias-set Label").await;
    }
    assert_eq!(
        canonical.get_property::<String>("Label").await.unwrap(),
        "s14-alias-label"
    );
    let message = tokio::time::timeout(
        Duration::from_secs(10),
        next_event(collection_changed.as_mut()),
    )
    .await
    .expect("timed out waiting for alias-set CollectionChanged")
    .expect("alias-set CollectionChanged stream ended");
    let (changed_path,): (OwnedObjectPath,) = message.body().deserialize().unwrap();
    assert_eq!(changed_path, a_path);

    // Existing-alias CreateCollection label update reuses same fanout without
    // changing collection membership.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let mut canonical_changes = std::pin::pin!(
        canonical_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut alias_changes = std::pin::pin!(
        alias_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut collection_changed =
        std::pin::pin!(service.receive_signal("CollectionChanged").await.unwrap());
    let mut collection_created =
        std::pin::pin!(service.receive_signal("CollectionCreated").await.unwrap());
    let mut service_properties_changed = std::pin::pin!(
        service_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let (returned, prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call(
            "CreateCollection",
            &(
                collection_properties(Some("s14-existing-alias")),
                "s14_alias",
            ),
        )
        .await
        .unwrap();
    assert_eq!(returned, a_path);
    assert_eq!(prompt.as_str(), "/");
    for changes in [&mut canonical_changes, &mut alias_changes] {
        let (name, value) = next_property_change(changes.as_mut(), COLLECTION_IFACE).await;
        assert_eq!(name, "Label");
        assert_eq!(String::try_from(value).unwrap(), "s14-existing-alias");
        let (name, _) = next_property_change(changes.as_mut(), COLLECTION_IFACE).await;
        assert_eq!(name, "Modified");
        assert_no_signal(changes.as_mut(), "duplicate existing-alias Label").await;
    }
    let message = tokio::time::timeout(
        Duration::from_secs(10),
        next_event(collection_changed.as_mut()),
    )
    .await
    .expect("timed out waiting for existing-alias CollectionChanged")
    .expect("existing-alias CollectionChanged stream ended");
    let (changed_path,): (OwnedObjectPath,) = message.body().deserialize().unwrap();
    assert_eq!(changed_path, a_path);
    assert_no_signal(
        collection_created.as_mut(),
        "CollectionCreated for existing alias",
    )
    .await;
    assert_no_signal(
        service_properties_changed.as_mut(),
        "Collections change for existing alias",
    )
    .await;

    // Item membership changes fan out to canonical and alias paths. Replace
    // keeps membership unchanged and therefore emits no Items change.
    let (_, session): (OwnedValue, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Value::from("")))
        .await
        .unwrap();
    let mut initial_items: Vec<OwnedObjectPath> = canonical.get_property("Items").await.unwrap();
    assert!(initial_items.is_empty());
    initial_items = alias.get_property("Items").await.unwrap();
    assert!(initial_items.is_empty());

    let first_properties = item_properties("s14-first", "s14-first");
    let first_secret = WireSecret {
        session: session.clone(),
        parameters: Vec::new(),
        value: Zeroizing::new(b"s14-first-secret".to_vec()),
        content_type: "text/plain".to_string(),
    };
    let mut canonical_items_changed = std::pin::pin!(
        canonical_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut alias_items_changed = std::pin::pin!(
        alias_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let (first_path, _): (OwnedObjectPath, OwnedObjectPath) = canonical
        .call("CreateItem", &(&first_properties, &first_secret, false))
        .await
        .unwrap();
    for changes in [&mut canonical_items_changed, &mut alias_items_changed] {
        let (name, value) = next_property_change(changes.as_mut(), COLLECTION_IFACE).await;
        assert_eq!(name, "Items");
        assert_eq!(
            Vec::<OwnedObjectPath>::try_from(value).unwrap(),
            vec![first_path.clone()]
        );
        assert_no_signal(changes.as_mut(), "duplicate create Items").await;
    }

    let second_properties = item_properties("s14-second", "s14-second");
    let second_secret = WireSecret {
        session: session.clone(),
        parameters: Vec::new(),
        value: Zeroizing::new(b"s14-second-secret".to_vec()),
        content_type: "text/plain".to_string(),
    };
    let mut canonical_items_changed = std::pin::pin!(
        canonical_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut alias_items_changed = std::pin::pin!(
        alias_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let (second_path, _): (OwnedObjectPath, OwnedObjectPath) = alias
        .call("CreateItem", &(&second_properties, &second_secret, false))
        .await
        .unwrap();
    let mut expected_items = vec![first_path.clone(), second_path.clone()];
    expected_items.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    for changes in [&mut canonical_items_changed, &mut alias_items_changed] {
        let (name, value) = next_property_change(changes.as_mut(), COLLECTION_IFACE).await;
        assert_eq!(name, "Items");
        let mut actual = Vec::<OwnedObjectPath>::try_from(value).unwrap();
        actual.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        assert_eq!(actual, expected_items);
        assert_no_signal(changes.as_mut(), "duplicate alias-create Items").await;
    }

    let first_item = zbus::Proxy::new(&conn, SERVICE_NAME, first_path.clone(), ITEM_IFACE)
        .await
        .unwrap();
    let mut canonical_items_changed = std::pin::pin!(
        canonical_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    let mut alias_items_changed = std::pin::pin!(
        alias_properties
            .receive_signal("PropertiesChanged")
            .await
            .unwrap()
    );
    first_item
        .call::<_, _, OwnedObjectPath>("Delete", &())
        .await
        .unwrap();
    for changes in [&mut canonical_items_changed, &mut alias_items_changed] {
        let (name, value) = next_property_change(changes.as_mut(), COLLECTION_IFACE).await;
        assert_eq!(name, "Items");
        assert_eq!(
            Vec::<OwnedObjectPath>::try_from(value).unwrap(),
            vec![second_path.clone()]
        );
        assert_no_signal(changes.as_mut(), "duplicate delete Items").await;
    }

    {
        let second_item_properties =
            zbus::Proxy::new(&conn, SERVICE_NAME, second_path.clone(), PROPERTIES_IFACE)
                .await
                .unwrap();
        let mut item_changed =
            std::pin::pin!(canonical.receive_signal("ItemChanged").await.unwrap());
        let mut item_properties_changed = std::pin::pin!(
            second_item_properties
                .receive_signal("PropertiesChanged")
                .await
                .unwrap()
        );
        let mut canonical_items_changed = std::pin::pin!(
            canonical_properties
                .receive_signal("PropertiesChanged")
                .await
                .unwrap()
        );
        let mut alias_items_changed = std::pin::pin!(
            alias_properties
                .receive_signal("PropertiesChanged")
                .await
                .unwrap()
        );
        let replacement_properties = item_properties("s14-replaced", "s14-second");
        let replacement_secret = WireSecret {
            session: session.clone(),
            parameters: Vec::new(),
            value: Zeroizing::new(b"s14-replaced-secret".to_vec()),
            content_type: "text/plain".to_string(),
        };
        let (replacement_path, _): (OwnedObjectPath, OwnedObjectPath) = alias
            .call(
                "CreateItem",
                &(&replacement_properties, &replacement_secret, true),
            )
            .await
            .unwrap();
        assert_eq!(replacement_path, second_path);
        assert_eq!(
            next_property_name(item_properties_changed.as_mut()).await,
            "Label"
        );
        assert_eq!(
            next_property_name(item_properties_changed.as_mut()).await,
            "Modified"
        );
        next_item_changed(item_changed.as_mut(), &second_path).await;
        assert_no_signal(canonical_items_changed.as_mut(), "Items for replacement").await;
        assert_no_signal(alias_items_changed.as_mut(), "alias Items for replacement").await;
        let items: Vec<OwnedObjectPath> = canonical.get_property("Items").await.unwrap();
        assert_eq!(items, vec![second_path.clone()]);
    }

    // Repoint A -> B: same alias object stays registered, but only its four
    // target-dependent properties are invalidated. No collection signal fires.
    let _: Vec<OwnedObjectPath> = alias.get_property("Items").await.unwrap();
    let _: String = alias.get_property("Label").await.unwrap();
    let _: u64 = alias.get_property("Created").await.unwrap();
    let _: u64 = alias.get_property("Modified").await.unwrap();
    let other_items: Vec<OwnedObjectPath> = other.get_property("Items").await.unwrap();
    assert!(other_items.is_empty());
    {
        let mut alias_changes = std::pin::pin!(
            alias_properties
                .receive_signal("PropertiesChanged")
                .await
                .unwrap()
        );
        let mut collection_changed =
            std::pin::pin!(service.receive_signal("CollectionChanged").await.unwrap());
        let mut service_properties_changed = std::pin::pin!(
            service_properties
                .receive_signal("PropertiesChanged")
                .await
                .unwrap()
        );
        service
            .call::<_, _, ()>("SetAlias", &("s14_alias", &b_path))
            .await
            .unwrap();
        let mut invalidated =
            next_invalidated_properties(alias_changes.as_mut(), COLLECTION_IFACE).await;
        invalidated.sort();
        assert_eq!(invalidated, ["Created", "Items", "Label", "Modified"]);
        assert_no_signal(
            alias_changes.as_mut(),
            "duplicate alias repoint invalidation",
        )
        .await;
        assert_eq!(
            alias.get_property::<String>("Label").await.unwrap(),
            "s14-b"
        );
        assert_eq!(
            alias
                .get_property::<Vec<OwnedObjectPath>>("Items")
                .await
                .unwrap(),
            other_items
        );
        assert_eq!(
            alias.get_property::<u64>("Created").await.unwrap(),
            other.get_property::<u64>("Created").await.unwrap()
        );
        assert_eq!(
            alias.get_property::<u64>("Modified").await.unwrap(),
            other.get_property::<u64>("Modified").await.unwrap()
        );
        assert_no_signal(
            collection_changed.as_mut(),
            "CollectionChanged for alias repoint",
        )
        .await;
        assert_no_signal(
            service_properties_changed.as_mut(),
            "Collections change for alias repoint",
        )
        .await;
    }

    // B -> B is idempotent and emits no alias invalidation.
    {
        let mut alias_changes = std::pin::pin!(
            alias_properties
                .receive_signal("PropertiesChanged")
                .await
                .unwrap()
        );
        service
            .call::<_, _, ()>("SetAlias", &("s14_alias", &b_path))
            .await
            .unwrap();
        assert_no_signal(
            alias_changes.as_mut(),
            "alias invalidation for idempotent SetAlias",
        )
        .await;
    }

    // Clearing alias removes object and preserves ReadAlias's root convention.
    let root = OwnedObjectPath::try_from("/").unwrap();
    service
        .call::<_, _, ()>("SetAlias", &("s14_alias", &root))
        .await
        .unwrap();
    let resolved: OwnedObjectPath = service.call("ReadAlias", &("s14_alias",)).await.unwrap();
    assert_eq!(resolved.as_str(), "/");
    assert!(alias.get_property::<String>("Label").await.is_err());

    canonical
        .call::<_, _, OwnedObjectPath>("Delete", &())
        .await
        .unwrap();
    other
        .call::<_, _, OwnedObjectPath>("Delete", &())
        .await
        .unwrap();
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
    eprintln!("scenario 3: strict plain protocol validation");
    s3_plain_protocol_validation().await;
    eprintln!("scenario 3b: replace semantics");
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
    eprintln!("scenario 11: lock semantics");
    s11_lock_semantics().await;
    eprintln!("scenario 12: item mutation signals");
    s12_item_mutation_signals().await;
    eprintln!("scenario 13: existing alias collection creation");
    s13_existing_alias_collection().await;
    eprintln!("scenario 14: collection and alias notifications");
    Box::pin(s14_collection_alias_notifications()).await;
    eprintln!("scenario 14: no daemon gpg spawn");
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

#[tokio::test]
async fn rejected_plain_open_session_does_not_register_session() {
    let h = harness();
    let (mut dbus, address) = spawn_dbus_daemon();
    let store = tempfile::tempdir().unwrap();
    let cert = export_public_cert(&h.gnupg_home);
    init_noirpass_store(store.path(), &cert);
    let mut daemon = spawn_daemon(
        &address,
        &h.gnupg_home,
        store.path(),
        "0",
        Some(&h.fake_gpg_dir),
    );
    wait_for_name(&address);

    let conn = zbus::connection::Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let proxy = service_proxy(&conn).await;
    let err = proxy
        .call::<_, _, (OwnedValue, OwnedObjectPath)>(
            "OpenSession",
            &("plain", Value::from("non-empty")),
        )
        .await
        .unwrap_err();
    assert_method_error(&err, INVALID_ARGS_ERROR);
    drop(proxy);

    // Keep connection alive while daemon decides idle exit. A registered session
    // would keep daemon alive; successful exit proves rejected call registered none.
    let status = tokio::task::spawn_blocking(move || {
        wait_with_timeout(&mut daemon, Duration::from_secs(10))
    })
    .await
    .unwrap();
    assert!(
        status.success(),
        "daemon should idle-exit without rejected session, got {status}"
    );
    drop(conn);

    dbus.kill().expect("kill private dbus-daemon");
    let _ = dbus.wait();
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
            .create_or_replace_item(
                &collection.id,
                kind,
                HashMap::new(),
                "text/plain",
                b"old-ciphertext",
                false,
            )
            .unwrap()
            .0;
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
fn daemon_rejects_recipient_without_matching_secret_key() {
    let h = harness();
    let other_gnupg = tempfile::tempdir().unwrap();
    setup_gnupg(other_gnupg.path());
    let other_cert = export_public_cert(other_gnupg.path());
    let (mut dbus, address) = spawn_dbus_daemon();
    let store = tempfile::tempdir().unwrap();
    init_noirpass_store(store.path(), &other_cert);

    let status_output = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
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
