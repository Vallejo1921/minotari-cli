//! Transaction history querying and management.
//!
//! This module provides services for loading, filtering, and emitting transaction
//! history data. It serves as the primary interface for accessing historical
//! transaction records stored in the database.
//!
//! # Overview
//!
//! The [`TransactionHistoryService`] provides various methods for querying
//! transaction history:
//!
//! - Load all transactions for an account
//! - Filter by status (pending, confirmed, etc.)
//! - Paginated queries for large histories
//! - Emit transactions as events for UI updates
//!
//! # Usage Patterns
//!
//! ## Loading Transaction History
//!
//! ```rust,ignore
//! let service = TransactionHistoryService::new(db_pool);
//!
//! // Load all transactions
//! let all_txs = service.load_all_transactions(account_id).await?;
//!
//! // Load only confirmed transactions
//! let confirmed = service.load_transactions_by_status(
//!     account_id,
//!     TransactionDisplayStatus::Confirmed,
//! ).await?;
//! ```
//!
//! ## Paginated Loading
//!
//! ```rust,ignore
//! // Load first page of 50 transactions
//! let page1 = service.load_transactions_paginated(account_id, 50, 0).await?;
//!
//! // Load second page
//! let page2 = service.load_transactions_paginated(account_id, 50, 50).await?;
//! ```
//!
//! ## Event Emission
//!
//! For UI integration, transactions can be emitted as events:
//!
//! ```rust,ignore
//! service.load_and_emit(account_id, |event| {
//!     // Handle DisplayedTransactionsEvent
//!     ui.update_transactions(event.transactions);
//! }).await?;
//! ```

use crate::db::{self, SqlitePool, WalletDbError};
use crate::models::Id;
use crate::scan::DisplayedTransactionsEvent;
use crate::transactions::{DisplayedTransaction, ProcessorError, TransactionDisplayStatus};
use log::debug;
use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;

/// Errors that can occur during transaction history operations.
///
/// This enum captures the various failure modes when querying or processing
/// transaction history data.
#[derive(Debug, thiserror::Error)]
pub enum TransactionHistoryError {
    /// Transaction processing failed.
    ///
    /// Occurs when transforming raw database records into displayable transactions.
    #[error("Processing error: {0}")]
    ProcessingError(#[from] ProcessorError),

    /// DB execution failed
    #[error("Database execution error: {0}")]
    DbError(#[from] WalletDbError),
}

/// Service for querying and managing transaction history.
///
/// `TransactionHistoryService` provides a high-level API for accessing
/// transaction history stored in the database. It supports various query
/// patterns including filtering, pagination, and event emission for UI updates.
///
/// # Thread Safety
///
/// This service can be safely shared across threads by cloning, as it uses
/// a connection pool internally.
///
/// # Example
///
/// ```rust,ignore
/// use minotari::transactions::TransactionHistoryService;
///
/// let service = TransactionHistoryService::new(db_pool);
///
/// // Load recent transactions for display
/// let transactions = service.load_transactions_excluding_reorged(account_id).await?;
///
/// for tx in transactions {
///     println!("{}: {} ({})", tx.id, tx.amount, tx.status);
/// }
/// ```
pub struct TransactionHistoryService {
    db_pool: SqlitePool,
}

impl TransactionHistoryService {
    /// Creates a new `TransactionHistoryService` with the given database pool.
    ///
    /// # Arguments
    ///
    /// * `db_pool` - SQLite connection pool for database operations
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let service = TransactionHistoryService::new(db_pool);
    /// ```
    pub fn new(db_pool: SqlitePool) -> Self {
        Self { db_pool }
    }

    fn get_connection(&self) -> Result<PooledConnection<SqliteConnectionManager>, TransactionHistoryError> {
        self.db_pool
            .get()
            .map_err(|e| TransactionHistoryError::DbError(WalletDbError::ConnectionError(e)))
    }

    /// Loads all transactions for the specified account.
    ///
    /// Returns all transactions including reorganized ones. For user-facing
    /// display, prefer [`load_transactions_excluding_reorged`](Self::load_transactions_excluding_reorged).
    ///
    /// # Arguments
    ///
    /// * `account_id` - The account ID to load transactions for
    ///
    /// # Returns
    ///
    /// A vector of all [`DisplayedTransaction`] records for the account,
    /// ordered by timestamp (most recent first).
    ///
    /// # Errors
    ///
    /// Returns [`TransactionHistoryError::Database`] if the query fails.
    pub fn load_all_transactions(&self, account_id: Id) -> Result<Vec<DisplayedTransaction>, TransactionHistoryError> {
        debug!(account_id = account_id; "Loading all transactions");
        let conn = self.get_connection()?;
        let transactions = db::get_displayed_transactions_by_account(&conn, account_id)?;
        Ok(transactions)
    }

    /// Loads transactions excluding those affected by chain reorganizations.
    ///
    /// This is the preferred method for user-facing displays as it filters out
    /// transactions that were invalidated by blockchain reorganizations.
    ///
    /// # Arguments
    ///
    /// * `account_id` - The account ID to load transactions for
    ///
    /// # Returns
    ///
    /// A vector of valid [`DisplayedTransaction`] records, excluding any
    /// that were reorganized out of the canonical chain.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionHistoryError::Database`] if the query fails.
    pub fn load_transactions_excluding_reorged(
        &self,
        account_id: Id,
    ) -> Result<Vec<DisplayedTransaction>, TransactionHistoryError> {
        debug!(account_id = account_id; "Loading transactions excluding reorged");
        let conn = self.get_connection()?;
        let transactions = db::get_displayed_transactions_excluding_reorged(&conn, account_id)?;
        Ok(transactions)
    }

    /// Loads transactions filtered by display status.
    ///
    /// # Arguments
    ///
    /// * `account_id` - The account ID to load transactions for
    /// * `status` - The status to filter by (Pending, Unconfirmed, Confirmed, etc.)
    ///
    /// # Returns
    ///
    /// A vector of [`DisplayedTransaction`] records matching the specified status.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionHistoryError::Database`] if the query fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Get all pending transactions
    /// let pending = service.load_transactions_by_status(
    ///     account_id,
    ///     TransactionDisplayStatus::Pending,
    /// ).await?;
    /// ```
    pub fn load_transactions_by_status(
        &self,
        account_id: Id,
        status: TransactionDisplayStatus,
    ) -> Result<Vec<DisplayedTransaction>, TransactionHistoryError> {
        debug!(
            account_id = account_id,
            status:? = status;
            "Loading transactions by status"
        );
        let conn = self.get_connection()?;
        let transactions = db::get_displayed_transactions_by_status(&conn, account_id, status)?;
        Ok(transactions)
    }

    /// Loads a single transaction by its ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The unique transaction identifier
    ///
    /// # Returns
    ///
    /// Returns `Some(DisplayedTransaction)` if found, `None` if no transaction
    /// exists with the given ID.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionHistoryError::Database`] if the query fails.
    pub fn load_transaction_by_id(&self, id: &str) -> Result<Option<DisplayedTransaction>, TransactionHistoryError> {
        let conn = self.get_connection()?;
        let transaction = db::get_displayed_transaction_by_id(&conn, id)?;
        Ok(transaction)
    }

    /// Loads transactions with pagination support.
    ///
    /// Use this method for efficient loading of large transaction histories
    /// in paginated UI views.
    ///
    /// # Arguments
    ///
    /// * `account_id` - The account ID to load transactions for
    /// * `limit` - Maximum number of transactions to return
    /// * `offset` - Number of transactions to skip (for pagination)
    ///
    /// # Returns
    ///
    /// A vector of up to `limit` [`DisplayedTransaction`] records,
    /// starting from the `offset` position.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionHistoryError::Database`] if the query fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Load transactions in pages of 20
    /// let page_size = 20;
    /// let page_number = 0;
    ///
    /// let transactions = service.load_transactions_paginated(
    ///     account_id,
    ///     page_size,
    ///     page_number * page_size,
    /// ).await?;
    /// ```
    pub fn load_transactions_paginated(
        &self,
        account_id: Id,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DisplayedTransaction>, TransactionHistoryError> {
        debug!(
            account_id = account_id,
            limit = limit,
            offset = offset;
            "Loading transactions paginated"
        );
        let conn = self.get_connection()?;
        let transactions = db::get_displayed_transactions_paginated(&conn, account_id, limit, offset)?;
        Ok(transactions)
    }

    /// Loads all transactions and emits them as a single event.
    ///
    /// Useful for initial UI synchronization where all transactions
    /// need to be loaded and displayed at once.
    ///
    /// # Arguments
    ///
    /// * `account_id` - The account ID to load transactions for
    /// * `emit_fn` - Callback function that receives the transaction event
    ///
    /// # Returns
    ///
    /// The total number of transactions loaded and emitted.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionHistoryError`] if loading fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let count = service.load_and_emit(account_id, |event| {
    ///     for tx in event.transactions {
    ///         ui.add_transaction(tx);
    ///     }
    /// }).await?;
    ///
    /// println!("Loaded {} transactions", count);
    /// ```
    pub fn load_and_emit<F>(&self, account_id: Id, emit_fn: F) -> Result<usize, TransactionHistoryError>
    where
        F: FnOnce(DisplayedTransactionsEvent),
    {
        let transactions = self.load_all_transactions(account_id)?;
        let count = transactions.len();

        if !transactions.is_empty() {
            emit_fn(DisplayedTransactionsEvent {
                account_id,
                transactions,
                block_height: None,
                is_initial_sync: true,
            });
        }

        Ok(count)
    }

    /// Loads all transactions and emits them in chunks.
    ///
    /// Useful for progressive loading where transactions should be displayed
    /// incrementally rather than all at once, improving perceived performance
    /// for large histories.
    ///
    /// # Arguments
    ///
    /// * `account_id` - The account ID to load transactions for
    /// * `chunk_size` - Number of transactions per chunk
    /// * `emit_fn` - Callback function called for each chunk
    ///
    /// # Returns
    ///
    /// The total number of transactions processed across all chunks.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionHistoryError`] if loading fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let total = service.emit_in_chunks(account_id, 50, |event| {
    ///     // Each chunk of 50 transactions triggers this callback
    ///     ui.append_transactions(event.transactions);
    /// }).await?;
    /// ```
    pub fn emit_in_chunks<F>(
        &self,
        account_id: Id,
        chunk_size: usize,
        mut emit_fn: F,
    ) -> Result<usize, TransactionHistoryError>
    where
        F: FnMut(DisplayedTransactionsEvent),
    {
        let all_transactions = self.load_all_transactions(account_id)?;
        let total = all_transactions.len();

        for chunk in all_transactions.chunks(chunk_size) {
            emit_fn(DisplayedTransactionsEvent {
                account_id,
                transactions: chunk.to_vec(),
                block_height: None,
                is_initial_sync: true,
            });
        }

        Ok(total)
    }
}
