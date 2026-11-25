use std::collections::HashMap;
use std::path::Path;

use noirpass::store::{ItemMeta, Store};

pub(super) fn run(store_dir: &Path) -> noirpass::Result<()> {
    let store = Store::open_existing(store_dir)?;
    store.recover_interrupted_operations()?;
    print_items(&store)
}

fn print_items(store: &Store) -> noirpass::Result<()> {
    let items = store.search_items(&HashMap::new())?;
    if items.is_empty() {
        println!("no secrets");
        return Ok(());
    }

    let collections: HashMap<String, String> = store
        .list_collections()?
        .into_iter()
        .map(|collection| (collection.id, collection.label))
        .collect();

    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            println!();
        }
        let missing_ciphertext = !store.has_secret_file(&item.id)?;
        print_item(item, &collections, missing_ciphertext)?;
    }
    Ok(())
}

fn print_item(
    item: &ItemMeta,
    collections: &HashMap<String, String>,
    missing_ciphertext: bool,
) -> noirpass::Result<()> {
    let collection_label = collections
        .get(&item.collection)
        .map_or("<missing collection>", String::as_str);
    println!("id: {}", item.id);
    println!("label: {}", serde_json::to_string(&item.label)?);
    println!(
        "collection: {} ({})",
        serde_json::to_string(collection_label)?,
        item.collection
    );
    println!("attributes: {}", serde_json::to_string(&item.attributes)?);
    let ciphertext_state = if missing_ciphertext {
        "missing"
    } else {
        "present"
    };
    println!("ciphertext: {ciphertext_state}");
    Ok(())
}
