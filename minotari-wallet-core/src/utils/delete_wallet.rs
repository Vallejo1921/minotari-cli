use std::path::Path;

use crate::db::{self, WalletDbError, init_db};
use crate::session;
use anyhow::Context;
use rusqlite::Connection;

/// Deletes a wallet account and all its associated data from the database, and locks its key
/// session.
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
    delete_wallet_with_conn(&mut conn, account_name)
}

/// Like [`delete_wallet`], on an open connection.
pub fn delete_wallet_with_conn(conn: &mut Connection, account_name: &str) -> Result<(), anyhow::Error> {
    // Held through the commit so no unlock can re-store the session from the old row.
    let mut session_changes = session::changes_guard();
    session_changes.record_lock(account_name);
    // BEGIN IMMEDIATE: the deletion looks the account up before rewriting every table
    // that references it, and a deferred read->write upgrade can fail with
    // SQLITE_BUSY_SNAPSHOT in WAL mode, which `busy_timeout` does not retry.
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

    let account = db::get_account_by_name(&tx, account_name)?
        .ok_or_else(|| WalletDbError::InvalidInput(format!("Account '{}' not found", account_name)))?;
    db::delete_account(&tx, account_name)?;

    tx.commit()?;
    session::remove_session_for(&account);

    Ok(())
}
