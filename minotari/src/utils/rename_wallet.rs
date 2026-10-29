use crate::db::{self, init_db};
use anyhow::Context;
use std::path::Path;

/// Renames a wallet account in the database.
///
/// # Parameters
///
/// * `database_file` - Path to the SQLite database file
/// * `current_name` - The current friendly name of the account
/// * `new_name` - The desired new friendly name
pub fn rename_wallet(database_file: &Path, current_name: &str, new_name: &str) -> Result<(), anyhow::Error> {
    let pool = init_db(database_file.to_path_buf()).context("Failed to initialize database")?;
    let mut conn = pool.get().context("Failed to get DB connection from pool")?;

    let tx = conn.transaction()?;

    db::update_account_name(&tx, current_name, new_name)?;

    tx.commit()?;

    Ok(())
}
