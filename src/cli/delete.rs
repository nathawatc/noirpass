use std::path::Path;

use noirpass::store::Store;

use super::confirm;

pub(super) fn run(store_dir: &Path, id: &str, yes: bool) -> noirpass::Result<()> {
    let store = Store::open_existing(store_dir)?;
    store.recover_interrupted_operations()?;
    let item = store.get_item(id)?;
    if confirm(
        &format!(
            "delete secret {} with label {}?",
            id,
            serde_json::to_string(&item.label)?
        ),
        yes,
    )? {
        store.delete_item(id)?;
        println!("deleted: {id}");
    } else {
        println!("not deleted: {id}");
    }
    Ok(())
}
