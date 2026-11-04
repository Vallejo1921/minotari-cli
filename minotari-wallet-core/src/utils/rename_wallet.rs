use crate::db::{self, WalletDbError, init_db};
use crate::session;
use anyhow::Context;
use rusqlite::Connection;
use std::path::Path;

/// Renames a wallet account in the database and locks its key session.
///
/// # Parameters
///
/// * `database_file` - Path to the SQLite database file
/// * `current_name` - The current friendly name of the account
/// * `new_name` - The desired new friendly name
pub fn rename_wallet(database_file: &Path, current_name: &str, new_name: &str) -> Result<(), anyhow::Error> {
    let pool = init_db(database_file.to_path_buf()).context("Failed to initialize database")?;
    let mut conn = pool.get().context("Failed to get DB connection from pool")?;
    rename_wallet_with_conn(&mut conn, current_name, new_name)
}

/// Like [`rename_wallet`], on an open connection.
pub fn rename_wallet_with_conn(conn: &mut Connection, current_name: &str, new_name: &str) -> Result<(), anyhow::Error> {
    // Held through the commit so no unlock can re-store the session from the old row.
    let mut session_changes = session::changes_guard();
    session_changes.record_lock(current_name);
    session_changes.record_lock(new_name);
    // BEGIN IMMEDIATE: the rename reads before it writes; see `delete_wallet_with_conn`.
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

    let account = db::get_account_by_name(&tx, current_name)?
        .ok_or_else(|| WalletDbError::InvalidInput(format!("Account '{}' not found", current_name)))?;
    db::update_account_name(&tx, current_name, new_name)?;

    tx.commit()?;
    session::remove_session_for(&account);

    Ok(())
}
