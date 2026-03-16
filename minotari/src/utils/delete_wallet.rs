use std::path::Path;

use crate::db::{self, init_db};
use anyhow::Context;

/// Deletes a wallet account and all its associated data from the database.
///
/// This operation is performed within a transaction to ensure atomicity.
///
/// # Parameters
///
/// * `database_file` - Path to the SQLite database file
/// * `account_name` - The friendly name of the account to delete
pub fn delete_wallet(database_file: &Path, account_name: &str) -> Result<(), anyhow::Error> {
    let pool = init_db(database_file.to_path_buf()).context("Failed to initialize database")?;
    let mut conn = pool.get().context("Failed to get DB connection from pool")?;

    let tx = conn.transaction()?;

    db::delete_account(&tx, account_name)?;

    tx.commit()?;

    Ok(())
}
