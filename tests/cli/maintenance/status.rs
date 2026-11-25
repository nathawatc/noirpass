use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use noirpass::store::Store;

use crate::common::{export_public_cert, init_noirpass_store, noirpass_command, setup_gnupg};

#[test]
fn cli_status_finds_agent_for_gnupg_home_spellings() {
    for spelling in ["plain", "slash", "dot", "tilde"] {
        // Each spelling starts its own agent; an agent for the plain spelling
        // must not hide a wrong hash for the absolute /. spelling.
        let fixture = tempfile::tempdir().unwrap();
        let home = fixture.path().join("gnupg");
        fs::create_dir(&home).unwrap();
        let mut agent_home = home.into_os_string();
        match spelling {
            "slash" => agent_home.push("/"),
            "dot" => agent_home.push("/."),
            _ => {}
        }
        let agent_home = PathBuf::from(agent_home);
        let _agent = setup_gnupg(&agent_home);
        let cert = export_public_cert(&agent_home);
        let store = fixture.path().join("store");
        fs::create_dir(&store).unwrap();
        init_noirpass_store(&store, &cert);
        let selected = if spelling == "tilde" {
            PathBuf::from("~/gnupg")
        } else {
            agent_home
        };
        let output = noirpass_command()
            .arg("--store-dir")
            .arg(&store)
            .arg("status")
            .env("HOME", fixture.path())
            .env("GNUPGHOME", selected)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{spelling}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn cli_status_rejects_missing_ciphertext_without_repairing() {
    let gnupg = tempfile::tempdir().unwrap();
    let _agent = setup_gnupg(gnupg.path());
    let cert = export_public_cert(gnupg.path());
    let dir = tempfile::tempdir().unwrap();
    init_noirpass_store(dir.path(), &cert);

    let store = Store::open(dir.path()).unwrap();
    let collection = store.ensure_default().unwrap();
    let item = store
        .create_or_replace_item(
            &collection.id,
            "missing ciphertext",
            HashMap::new(),
            "text/plain",
            b"ciphertext",
            false,
        )
        .unwrap()
        .0;
    drop(store);

    let index_before = fs::read(dir.path().join("index.redb")).unwrap();
    let ciphertext = dir.path().join(format!("secrets/{}.gpg", item.id));
    fs::remove_file(&ciphertext).unwrap();

    let output = noirpass_command()
        .arg("--store-dir")
        .arg(dir.path())
        .arg("status")
        .env("GNUPGHOME", gnupg.path())
        .output()
        .expect("spawn noirpass status with missing ciphertext");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("store integrity"));
    assert_eq!(
        fs::read(dir.path().join("index.redb")).unwrap(),
        index_before
    );
    assert!(!ciphertext.exists());
}

#[test]
fn cli_default_store_dir_precedence_and_fail_closed() {
    let fixture = tempfile::tempdir().unwrap();
    let cli_dir = fixture.path().join("cli-store");
    let env_dir = fixture.path().join("env-store");
    let xdg_dir = fixture.path().join("xdg");
    let home_dir = fixture.path().join("home");

    let cli_wins = noirpass_command()
        .arg("--store-dir")
        .arg(&cli_dir)
        .arg("status")
        .env("NOIRPASS_STORE", &env_dir)
        .env("XDG_DATA_HOME", &xdg_dir)
        .env("HOME", &home_dir)
        .output()
        .unwrap();
    assert!(!cli_wins.status.success());
    assert!(
        String::from_utf8_lossy(&cli_wins.stdout)
            .contains(&format!("data directory: {}", cli_dir.display()))
    );

    let env_wins = noirpass_command()
        .arg("status")
        .env("NOIRPASS_STORE", &env_dir)
        .env("XDG_DATA_HOME", &xdg_dir)
        .env("HOME", &home_dir)
        .output()
        .unwrap();
    assert!(!env_wins.status.success());
    assert!(
        String::from_utf8_lossy(&env_wins.stdout)
            .contains(&format!("data directory: {}", env_dir.display()))
    );

    let xdg_wins = noirpass_command()
        .arg("status")
        .env("XDG_DATA_HOME", &xdg_dir)
        .env("HOME", &home_dir)
        .output()
        .unwrap();
    assert!(!xdg_wins.status.success());
    assert!(
        String::from_utf8_lossy(&xdg_wins.stdout)
            .contains(&format!("data directory: {}", xdg_dir.join("noirpass").display()))
    );

    let relative_xdg_falls_back_to_home = noirpass_command()
        .arg("status")
        .env("XDG_DATA_HOME", "relative-xdg")
        .env("HOME", &home_dir)
        .output()
        .unwrap();
    assert!(!relative_xdg_falls_back_to_home.status.success());
    assert!(
        String::from_utf8_lossy(&relative_xdg_falls_back_to_home.stdout).contains(&format!(
            "data directory: {}",
            home_dir.join(".local/share/noirpass").display()
        ))
    );

    for (xdg, home) in [
        (None, None),
        (None, Some("")),
        (None, Some("relative-home")),
        (Some("relative-xdg"), Some("relative-home")),
    ] {
        let mut cmd = noirpass_command();
        cmd.arg("status").current_dir(fixture.path());
        match xdg {
            Some(v) => cmd.env("XDG_DATA_HOME", v),
            None => cmd.env_remove("XDG_DATA_HOME"),
        };
        match home {
            Some(v) => cmd.env("HOME", v),
            None => cmd.env_remove("HOME"),
        };
        let output = cmd.output().unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("default store directory"),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!fixture.path().join("noirpass").exists());
        assert!(!fixture.path().join(".local").exists());
    }
}

#[test]
fn cli_rejects_idle_exit_with_subcommand() {
    let dir = tempfile::tempdir().unwrap();
    let output = noirpass_command()
        .arg("--store-dir")
        .arg(dir.path())
        .args(["--idle-exit", "60", "status"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--idle-exit"));
}
