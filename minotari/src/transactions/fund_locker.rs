//! UTXO locking mechanism for transaction construction.
//!
//! This module provides functionality to temporarily lock UTXOs (Unspent Transaction Outputs)
//! during transaction construction, preventing double-spending scenarios where the same
//! outputs might be selected for multiple concurrent transactions.
//!
//! # Overview
//!
//! When creating a transaction, the wallet must:
//! 1. Select appropriate UTXOs to cover the transaction amount plus fees
//! 2. Lock those UTXOs to prevent other transactions from using them
//! 3. Either complete the transaction (consuming the UTXOs) or release the lock on failure
//!
//! The [`FundLocker`] handles steps 1 and 2, with automatic expiration to handle step 3
//! in case of failures or timeouts.
//!
//! # Idempotency
//!
//! Lock operations support idempotency keys, allowing clients to safely retry requests
//! without accidentally locking additional funds. If a lock request with the same
//! idempotency key already exists, the original result is returned.

use chrono::{Duration, Utc};
use log::info;
use tari_transaction_components::tari_amount::MicroMinotari;
use uuid::Uuid;

use crate::{
    api::types::LockFundsResult,
    db::{self, SqlitePool},
    log::mask_amount,
    transactions::input_selector::InputSelector,
};

/// Manages temporary locking of UTXOs during transaction construction.
///
/// `FundLocker` ensures that UTXOs selected for a transaction cannot be used
/// by other concurrent transactions, preventing double-spending within the wallet.
/// Locks are time-limited and automatically expire if the transaction is not
/// completed within the specified duration.
///
/// # Thread Safety
///
/// `FundLocker` uses database-level locking and can be safely shared across
/// threads via cloning (which clones the underlying connection pool).
///
/// # Example
///
/// ```rust,ignore
/// use minotari::transactions::fund_locker::FundLocker;
/// use tari_transaction_components::tari_amount::MicroMinotari;
///
/// let locker = FundLocker::new(db_pool);
///
/// // Lock funds for a transaction
/// let result = locker.lock(
///     account_id,
///     MicroMinotari(1_000_000),  // amount to send
///     1,                         // number of outputs
///     MicroMinotari(5),          // fee per gram
///     None,                      // use default output size estimate
///     Some("unique-key".into()), // idempotency key
///     300,                       // lock for 5 minutes
/// ).await?;
///
/// // Use result.utxos to build the transaction
/// ```
pub struct FundLocker {
    db_pool: SqlitePool,
}

impl FundLocker {
    /// Creates a new `FundLocker` with the given database connection pool.
    ///
    /// # Arguments
    ///
    /// * `db_pool` - SQLite connection pool for database operations
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let locker = FundLocker::new(db_pool);
    /// ```
    pub fn new(db_pool: SqlitePool) -> Self {
        Self { db_pool }
    }

    /// Locks UTXOs for a pending transaction.
    ///
    /// Selects unspent outputs sufficient to cover the requested amount plus estimated
    /// transaction fees, then locks them in the database with an expiration time.
    /// If an idempotency key is provided and a matching pending transaction exists,
    /// returns the existing lock result without creating a new one.
    ///
    /// # Arguments
    ///
    /// * `account_id` - The account whose UTXOs should be locked
    /// * `amount` - The amount to be sent (excluding fees)
    /// * `num_outputs` - Number of transaction outputs (typically 1 for recipient + optional change)
    /// * `fee_per_gram` - Fee rate in MicroMinotari per gram of transaction weight
    /// * `estimated_output_size` - Optional override for output size estimation; if `None`,
    ///   uses default calculation based on standard output features
    /// * `idempotency_key` - Optional unique key for idempotent operations; if provided and
    ///   a matching lock exists, returns the existing result
    /// * `seconds_to_lock_utxos` - Duration in seconds before the lock expires
    ///
    /// # Returns
    ///
    /// Returns a [`LockFundsResult`] containing:
    /// - The selected UTXOs
    /// - Whether a change output is required
    /// - Total value of selected UTXOs
    /// - Fee calculations with and without change output
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Database connection fails
    /// - Insufficient funds are available
    /// - UTXO selection fails due to serialization errors
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let result = locker.lock(
    ///     account_id,
    ///     MicroMinotari(500_000),
    ///     1,
    ///     MicroMinotari(5),
    ///     None,
    ///     Some("tx-123".to_string()),
    ///     600, // 10 minute lock
    /// ).await?;
    ///
    /// println!("Locked {} UTXOs worth {}", result.utxos.len(), result.total_value);
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn lock(
        &self,
        account_id: i64,
        amount: MicroMinotari,
        num_outputs: usize,
        fee_per_gram: MicroMinotari,
        estimated_output_size: Option<usize>,
        idempotency_key: Option<String>,
        seconds_to_lock_utxos: u64,
        confirmation_window: u64,
    ) -> Result<LockFundsResult, anyhow::Error> {
        info!(
            target: "audit",
            account_id = account_id,
            amount = &*mask_amount(amount);
            "Locking funds"
        );
        let mut conn = self.db_pool.get()?;
        if let Some(idempotency_key_str) = &idempotency_key
            && let Some(response) =
                db::find_pending_transaction_locked_funds_by_idempotency_key(&conn, idempotency_key_str, account_id)?
        {
            info!(
                target: "audit",
                idempotency_key = idempotency_key_str.as_str();
                "Found existing pending transaction lock"
            );
            return Ok(response);
        }

        let input_selector = InputSelector::new(account_id, confirmation_window);
        let utxo_selection =
            input_selector.fetch_unspent_outputs(&conn, amount, num_outputs, fee_per_gram, estimated_output_size)?;

        let transaction = conn.transaction()?;

        let expires_at = Utc::now() + Duration::seconds(seconds_to_lock_utxos as i64);
        let idempotency_key = idempotency_key.unwrap_or_else(|| Uuid::new_v4().to_string());
        let pending_tx_id = db::create_pending_transaction(
            &transaction,
            &idempotency_key,
            account_id,
            utxo_selection.requires_change_output,
            utxo_selection.total_value,
            utxo_selection.fee_without_change,
            utxo_selection.fee_with_change,
            expires_at,
        )?;

        for utxo in &utxo_selection.utxos {
            db::lock_output(&transaction, utxo.id, &pending_tx_id, expires_at)?;
        }

        transaction.commit()?;

        info!(
            target: "audit",
            utxos_count = utxo_selection.utxos.len(),
            total_value = &*mask_amount(utxo_selection.total_value);
            "Funds locked successfully"
        );

        Ok(LockFundsResult {
            utxos: utxo_selection.utxos.iter().map(|utxo| utxo.output.clone()).collect(),
            requires_change_output: utxo_selection.requires_change_output,
            total_value: utxo_selection.total_value,
            fee_without_change: utxo_selection.fee_without_change,
            fee_with_change: utxo_selection.fee_with_change,
        })
    }
}
