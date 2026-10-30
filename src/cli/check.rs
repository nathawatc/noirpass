use std::collections::HashMap;
use std::path::Path;

use noirpass::store::{Store, is_valid_item_id};

use super::confirm;

pub(super) fn run(store_dir: &Path, yes: bool) -> noirpass::Result<bool> {
    let store = Store::open_existing(store_dir)?;
    store.recover_interrupted_operations()?;
    if check_and_repair(&store, yes)? {
        return Ok(true);
    }
    std::process::exit(1);
}

#[allow(
    clippy::too_many_lines,
    reason = "linear reporting and repair keep each integrity category paired with its action"
)]
fn check_and_repair(store: &Store, assume_yes: bool) -> noirpass::Result<bool> {
    let report = store.check_integrity()?;
    if report.is_healthy() {
        println!("store health: ok");
        return Ok(true);
    }

    let mut collections = HashMap::new();
    for item in &report.missing_secret_items {
        if let Ok(collection) = store.get_collection(&item.metadata.collection) {
            collections.insert(collection.id, collection.label);
        }
    }

    for collection in &report.corrupt_collections {
        eprintln!(
            "corrupt collection entry: {} ({})",
            collection.table_key, collection.error
        );
    }
    for item in &report.missing_secret_items {
        eprintln!(
            "missing ciphertext: {} label={} collection={}",
            item.table_key,
            serde_json::to_string(&item.metadata.label)?,
            collections
                .get(&item.metadata.collection)
                .map_or(item.metadata.collection.as_str(), String::as_str)
        );
    }
    for item in &report.corrupt_items {
        eprintln!("corrupt redb entry: {} ({})", item.table_key, item.error);
    }
    for item in &report.ciphertext_mismatches {
        eprintln!(
            "ciphertext digest mismatch: {} label={} (kept)",
            item.table_key,
            serde_json::to_string(&item.metadata.label)?
        );
    }
    for item in &report.items_with_invalid_collection {
        eprintln!(
            "item with invalid collection: {} ({}) (kept)",
            item.table_key, item.error
        );
    }
    for (alias, collection) in &report.corrupt_aliases {
        eprintln!("corrupt alias: {alias} targets missing collection {collection}");
    }
    for (alias, collection) in &report.aliases_with_corrupt_collection {
        eprintln!("alias with corrupt collection: {alias} targets {collection} (kept)");
    }
    for file in &report.orphan_secret_files {
        eprintln!("orphan ciphertext: {file} (kept; inspect before manual deletion)");
    }
    for file in &report.recovery_secret_files {
        eprintln!("recoverable ciphertext: {file} (kept; inspect before manual deletion)");
    }

    let mut declined = 0usize;
    for item in report.missing_secret_items {
        if confirm(
            &format!(
                "delete stale redb entry {} with label {}?",
                item.table_key,
                serde_json::to_string(&item.metadata.label)?
            ),
            assume_yes,
        )? {
            store.delete_item(&item.table_key)?;
            println!("deleted stale entry: {}", item.table_key);
        } else {
            declined += 1;
        }
    }
    for item in report.corrupt_items {
        if confirm(
            &format!("delete corrupt redb entry {}?", item.table_key),
            assume_yes,
        )? {
            if is_valid_item_id(&item.table_key) {
                store.delete_item(&item.table_key)?;
            } else {
                store.delete_item_metadata(&item.table_key)?;
            }
            println!("deleted corrupt entry: {}", item.table_key);
        } else {
            declined += 1;
        }
    }

    for (alias, _) in report.corrupt_aliases {
        if confirm(&format!("delete corrupt alias {alias}?"), assume_yes)? {
            store.set_alias(&alias, None)?;
            println!("deleted corrupt alias: {alias}");
        } else {
            declined += 1;
        }
    }

    let remaining = store.check_integrity()?;
    if remaining.is_healthy() {
        println!("store health: repaired");
        return Ok(true);
    }
    eprintln!(
        concat!(
            "store health: needs attention ({} corrupt collections, {} missing ciphertext, ",
            "{} corrupt items, {} ciphertext mismatches, {} items with invalid collections, ",
            "{} corrupt aliases, {} aliases with corrupt collections, {} orphan ciphertext, ",
            "{} recoverable ciphertext, {} repair declined)"
        ),
        remaining.corrupt_collections.len(),
        remaining.missing_secret_items.len(),
        remaining.corrupt_items.len(),
        remaining.ciphertext_mismatches.len(),
        remaining.items_with_invalid_collection.len(),
        remaining.corrupt_aliases.len(),
        remaining.aliases_with_corrupt_collection.len(),
        remaining.orphan_secret_files.len(),
        remaining.recovery_secret_files.len(),
        declined
    );
    Ok(false)
}
