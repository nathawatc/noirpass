use std::path::Path;

use noirpass::config::deinit;

use super::confirm_terminal;

pub(super) fn run(store_dir: &Path) -> noirpass::Result<()> {
    eprintln!(
        "WARNING: This will permanently delete all Noirpass data,\nincluding encrypted secrets, metadata, configuration,\nand recipient information."
    );
    if !confirm_interactive("Continue?")? {
        println!("deinitialization cancelled");
        return Ok(());
    }

    eprintln!("This operation cannot be undone.");
    if !confirm_interactive("Are you sure you want to permanently delete the Noirpass store?")? {
        println!("deinitialization cancelled");
        return Ok(());
    }

    deinit(store_dir)?;
    println!("deinitialized: yes");
    println!("data directory: {}", store_dir.display());
    Ok(())
}

fn confirm_interactive(prompt: &str) -> noirpass::Result<bool> {
    confirm_terminal(
        prompt,
        "deinitialization requires an interactive terminal; piped confirmation is not accepted",
    )
}
