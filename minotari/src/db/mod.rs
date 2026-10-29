//! Database layer for wallet data persistence using SQLite.
//!
//! This module provides the complete database interface for the Minotari wallet,
//! handling all persistent storage including accounts, outputs, transactions,
//! and blockchain scanning state.
//!
//! # Database Schema
//!
//! The database consists of several interconnected tables:
//!
//! - **accounts** - Encrypted wallet keys and account metadata
//! - **outputs** - Detected UTXOs with confirmation status
//! - **inputs** - Spent outputs (transaction inputs)
//! - **balance_changes** - Transaction history with credits and debits
//! - **wallet_events** - Timeline of wallet activity
//! - **scanned_tip_blocks** - Scanning progress and reorg detection
//! - **pending_transactions** - Transactions being constructed
//! - **completed_transactions** - Broadcasted transactions and their status
//! - **displayed_transactions** - User-friendly transaction view
//!
//! # Migrations
//!
//! Database migrations are managed by rusqlite_migration and automatically applied on initialization.
//! Migration files are located in the `migrations/` directory.
//!
//! # Usage Example
//!
//! ```ignore
//! use minotari::db::{init_db, get_accounts, get_balance};
//! use std::path::PathBuf;
//!
//! # fn example() -> Result<(), anyhow::Error> {
//! // Initialize database and run migrations
//! let pool = init_db(PathBuf::from("wallet.db"))?;
//! let conn = pool.get()?;
//!
//! // Query accounts
//! let accounts = get_accounts(&conn, None)?;
//!
//! // Check balance (account_id = 1)
//! let balance = get_balance(&conn, 1)?;
//! println!("Available: {} µT", balance.available);
//! # Ok(())
//! # }
//! ```

use std::path::PathBuf;
use std::sync::LazyLock;
use std::{env::current_dir, fs};

use include_dir::{Dir, include_dir};
use log::{debug, error, info};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use rusqlite_migration::Migrations;

mod error;
pub use error::{WalletDbError, WalletDbResult};

mod accounts;
pub use accounts::{
    AccountBalance, AccountRow, change_passphrase, create_account, delete_account, get_account_by_name, get_accounts,
    get_balance, update_account_name,
};

mod scanned_tip_blocks;
pub use scanned_tip_blocks::{
    LatestScannedBlock, delete_scanned_tip_blocks_from_height, get_latest_scanned_block_with_timestamp,
    get_latest_scanned_tip_block_by_account, get_scanned_tip_block_hash_at_height, get_scanned_tip_blocks_by_account,
    insert_scanned_tip_block, prune_scanned_tip_blocks,
};

mod outputs;
pub use outputs::{
    ChangeOutputToRevert, DbOutput, DbWalletOutput, UnresolvedSpentOutput, clear_dead_lock,
    confirm_unconfirmed_change_output, fetch_outputs_by_lock_request_id, fetch_unspent_outputs,
    get_active_outputs_from_height, get_change_output_hash_for_request, get_output_by_id,
    get_output_hashes_mined_in_block, get_output_hashes_spent_in_block, get_output_info_by_hash,
    get_output_info_by_hash_for_account, get_output_lock_request_id, get_output_spend, get_output_totals_for_account,
    get_total_unspent_balance, get_unconfirmed_outputs, get_unresolved_spent_unconfirmed_outputs, insert_output,
    insert_spent_output_if_not_exists, insert_unconfirmed_change_output, is_lock_holder_live, lock_output,
    mark_change_output_rejected, mark_output_confirmed, record_spender_of_inputs, relock_inputs_for_revived_send,
    resolve_spent_unconfirmed_with_inputs, restore_change_of_rejected_send, revert_change_outputs_from_height,
    revert_rejected_change_output, soft_delete_outputs_from_height, soft_delete_unconfirmed_change_output,
    unlock_outputs_for_request, unlock_outputs_for_request as unlock_outputs_for_pending_transaction,
    update_output_status,
};

mod pending_transactions;
pub use pending_transactions::{
    PendingTransaction, PendingTransactionRecord, cancel_pending_transactions_by_ids,
    check_if_transaction_is_expired_by_idempotency_key, claim_pending_transaction_for_broadcast,
    create_pending_transaction, expire_and_unlock_pending_transaction, find_expired_pending_transactions,
    find_pending_transaction_by_idempotency_key, find_pending_transaction_record_by_idempotency_key,
    locked_funds_for_pending_transaction, update_pending_transaction_status, update_pending_transaction_status_if,
};

mod completed_transactions;
pub use completed_transactions::{
    CompletedTransaction, CompletedTransactionStatus, create_completed_transaction, get_completed_transaction_by_id,
    get_completed_transaction_by_payref, get_completed_transaction_to_match, get_completed_transactions_by_account,
    get_completed_transactions_by_status, get_last_broadcast_error, get_pending_completed_transactions,
    get_scan_rejected_pending_tx_ids_from_height, keep_rejected_after_reorg, mark_completed_transaction_as_broadcasted,
    mark_completed_transaction_as_confirmed, mark_completed_transaction_as_mined_unconfirmed,
    mark_completed_transaction_as_rejected, mark_completed_transaction_as_rejected_in_block,
    record_failed_broadcast_attempt, record_last_broadcast_error, reset_mined_completed_transactions_from_height,
    revert_completed_transaction_to_completed, update_completed_transaction_status,
};

mod events;
pub use events::{DbWalletEvent, get_events_by_account_id, insert_wallet_event};

mod webhooks;
pub use webhooks::{delete_webhooks_older_than, enqueue_webhook, fetch_due_webhooks, update_webhook_status};

mod balance_changes;
pub use balance_changes::{
    get_all_active_balance_changes_by_account_id, get_all_balance_changes_by_account_id,
    get_balance_change_id_by_input, get_balance_change_id_by_output, insert_balance_change,
    insert_balance_change_if_not_exists,
};

mod inputs;
pub use inputs::{DbInput, get_input_by_id, insert_input, soft_delete_inputs_from_height};

mod burn_proofs;
pub use burn_proofs::{
    DbBurnProof, NewBurnProof, get_burn_proof_by_output_hash, get_pending_burn_proofs, insert_burn_proof,
    mark_burn_proof_complete,
};

mod payref_history;
pub use payref_history::{
    get_transaction_id_by_historical_payref, save_completed_transaction_payrefs_before_reorg,
    save_displayed_transaction_payrefs_before_reorg, save_payref_history,
};

mod displayed_transactions;
pub use displayed_transactions::{
    find_pending_outbound_by_output_hash, get_displayed_transaction_by_id, get_displayed_transactions_by_account,
    get_displayed_transactions_by_payref, get_displayed_transactions_by_status,
    get_displayed_transactions_excluding_reorged, get_displayed_transactions_from_height,
    get_displayed_transactions_needing_confirmation_update, get_displayed_transactions_paginated,
    insert_displayed_transaction, mark_displayed_transaction_rejected, mark_displayed_transactions_reorganized,
    mark_displayed_transactions_reorganized_and_return, reset_displayed_transaction_to_pending,
    update_displayed_transaction_confirmations, update_displayed_transaction_mined,
    update_displayed_transaction_status,
};

const DB_POOL_SIZE: u32 = 5;

pub type SqlitePool = Pool<SqliteConnectionManager>;

static MIGRATIONS_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/migrations");

static MIGRATIONS: LazyLock<Migrations<'static>> = LazyLock::new(|| {
    Migrations::from_directory(&MIGRATIONS_DIR).expect("Failed to load migrations from embedded directory")
});

/// Initializes the SQLite database and runs migrations.
///
/// This function:
/// 1. Resolves the database path (handles relative paths)
/// 2. Creates parent directories if they don't exist
/// 3. Creates the database file if it doesn't exist
/// 4. Creates a connection pool with up to 5 connections
/// 5. Runs all pending migrations from `migrations/` directory
///
/// # Parameters
///
/// * `db_path` - Path to the SQLite database file (relative or absolute)
///
/// # Returns
///
/// Returns a `SqlitePool` ready for use, or an error if:
/// - The path is invalid
/// - Directory creation fails
/// - Database file creation fails
/// - Connection fails
/// - Migrations fail
///
/// # Example
///
/// ```ignore
/// use minotari::db::init_db;
/// use std::path::PathBuf;
///
/// # fn example() -> Result<(), anyhow::Error> {
/// // Initialize database in current directory
/// let pool = init_db(PathBuf::from("wallet.db"))?;
///
/// // Or use absolute path
/// let pool = init_db(PathBuf::from("/path/to/wallet.db"))?;
/// # Ok(())
/// # }
/// ```
pub fn init_db(db_path: PathBuf) -> WalletDbResult<SqlitePool> {
    debug!(path:? = db_path; "Initializing database");

    let mut path = db_path;
    if path.is_relative() {
        path = current_dir()?.join(path);
    }

    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Invalid database file path"))?;
    fs::create_dir_all(parent)?;

    match connect_and_migrate(&path) {
        Ok(pool) => Ok(pool),
        Err(e) => {
            error!(
                error:% = e,
                path:? = &path;
                "Database migration failed. Please, remove database manually"
            );
            Err(WalletDbError::Unexpected(
                "Unexpected error occurred. It is possibly a migration from sqlx that has failed. Consider removing database file and try again".to_string(),
            ))
        },
    }
}

fn connect_and_migrate(path: &PathBuf) -> WalletDbResult<SqlitePool> {
    debug!(path:? = path; "Connecting to database");
    let manager = SqliteConnectionManager::file(path).with_init(|c| {
        // WAL mode: Allows concurrent reads and writes (crucial for connection pooling).
        // synchronous NORMAL: Optimized performance; safe from app crashes in WAL mode.
        // foreign_keys ON: Enforces table relationships (SQLite defaults to OFF).
        // busy_timeout: Prevents "database is locked" errors by waiting up to 5s for locks to clear.
        c.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        Ok(())
    });
    let pool = Pool::builder().max_size(DB_POOL_SIZE).build(manager)?;
    let mut conn = pool.get()?;

    attempt_sqlx_adoption(&mut conn).ok();

    debug!("Applying migrations");
    MIGRATIONS.to_latest(&mut conn)?;

    Ok(pool)
}

/// Attempts to detect if the database was managed by sqlx and updates the
/// user_version PRAGMA to match the number of applied migrations, allowing
/// rusqlite_migration to pick up where sqlx left off.
fn attempt_sqlx_adoption(conn: &mut Connection) -> WalletDbResult<()> {
    let table_exists: bool = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_sqlx_migrations'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false);

    if table_exists {
        let count: i32 = conn.query_row("SELECT count(*) FROM _sqlx_migrations", [], |row| row.get(0))?;

        if count > 0 {
            let pragma_sql = format!("PRAGMA user_version = {}", count);
            conn.execute(&pragma_sql, [])?;

            info!(count = count; "Migrated from sqlx: updated user_version");
        }

        conn.execute("DROP TABLE _sqlx_migrations", [])?;
    }

    Ok(())
}
