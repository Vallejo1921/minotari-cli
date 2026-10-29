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

    // BEGIN IMMEDIATE: the deletion looks the account up before rewriting every table
    // that references it, and a deferred read->write upgrade can fail with
    // SQLITE_BUSY_SNAPSHOT in WAL mode, which `busy_timeout` does not retry.
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

    db::delete_account(&tx, account_name)?;

    tx.commit()?;

    Ok(())
}
