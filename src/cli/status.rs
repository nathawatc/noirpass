use std::path::Path;

use noirpass::config::{Status, load_recipient, status};
use noirpass::gpg::Gpg;

pub(super) async fn run(store_dir: &Path) -> noirpass::Result<()> {
    let mut status = status(store_dir);
    if status.usable() {
        match load_recipient(store_dir).and_then(|recipient| Gpg::from_cert(recipient.cert)) {
            Ok(gpg) => {
                if let Err(err) = gpg.ensure_recipient_secret_available().await {
                    status.errors.push(err.to_string());
                }
            }
            Err(err) => status.errors.push(err.to_string()),
        }
    }
    print_status(&status);
    if status.usable() {
        return Ok(());
    }
    std::process::exit(1);
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn opt_yes_no(value: Option<bool>) -> &'static str {
    value.map_or("unknown", yes_no)
}

fn print_status(status: &Status) {
    println!("data directory: {}", status.data_dir.display());
    println!("initialized: {}", yes_no(status.usable()));
    println!("config.toml present: {}", yes_no(status.config_present));
    println!(
        "recipient cert present: {}",
        yes_no(status.recipient_cert_present)
    );
    println!(
        "configured recipient fingerprint: {}",
        status
            .configured_fingerprint
            .as_deref()
            .unwrap_or("unknown")
    );
    println!(
        "actual cert fingerprint: {}",
        status.actual_fingerprint.as_deref().unwrap_or("unknown")
    );
    println!(
        "fingerprint matches: {}",
        opt_yes_no(status.fingerprint_matches)
    );
    println!(
        "cert has encryption-capable key: {}",
        opt_yes_no(status.cert_has_encryption_key)
    );
    for err in &status.errors {
        eprintln!("error: {err}");
    }
}
