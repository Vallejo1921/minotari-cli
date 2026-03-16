//! Transaction monitoring for broadcast, mining, and confirmation.
//!
//! This module provides infrastructure for tracking outbound transactions
//! through their lifecycle from broadcast to final confirmation. It handles:
//!
//! - Rebroadcasting transactions that haven't been picked up
//! - Detecting when transactions are mined
//! - Tracking confirmation progress
//! - Updating transaction display status for UI
//!
//! # Transaction States
//!
//! Transactions progress through these states:
//!
//! ```text
//! Completed --> Broadcast --> MinedUnconfirmed --> MinedConfirmed
//!     |             |
//!     +-> Rejected <+
//! ```
//!
//! - **Completed**: Transaction is signed and ready for broadcast
//! - **Broadcast**: Transaction has been submitted to the network
//! - **MinedUnconfirmed**: Transaction found in a block but not yet confirmed
//! - **MinedConfirmed**: Transaction has sufficient confirmations
//! - **Rejected**: Transaction was rejected by the network
//!
//! # Confirmation Requirements
//!
//! Transactions require [`REQUIRED_CONFIRMATIONS`] (currently 3) blocks
//! before being considered confirmed. This provides protection against
//! short chain reorganizations.
//!
//! # Usage
//!
//! ```rust,ignore
//! use minotari::transactions::monitor::{TransactionMonitor, MonitoringState};
//!
//! // Initialize monitoring state
//! let state = MonitoringState::new();
//! state.initialize(&mut conn, account_id).await?;
//!
//! // Create monitor
//! let monitor = TransactionMonitor::new(state.clone());
//!
//! // Check and update transactions during each sync cycle
//! let result = monitor.monitor_if_needed(
//!     &wallet_client,
//!     &mut conn,
//!     account_id,
//!     current_chain_height,
//! ).await?;
//!
//! // Handle events
//! for event in result.wallet_events {
//!     handle_wallet_event(event);
//! }
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, anyhow};
use log::{info, warn};
use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use tari_common_types::payment_reference::generate_payment_reference;
use tari_common_types::types::FixedHash;
use tari_transaction_components::rpc::models::{TxLocation, TxSubmissionRejectionReason};

use crate::db::{
    self, CompletedTransaction, CompletedTransactionStatus, SqlitePool, get_pending_completed_transactions,
    mark_completed_transaction_as_broadcasted, mark_completed_transaction_as_confirmed,
    mark_completed_transaction_as_mined_unconfirmed, mark_completed_transaction_as_rejected,
};
use crate::http::WalletHttpClient;
use crate::models::{WalletEvent, WalletEventType};
use crate::transactions::{DisplayedTransaction, TransactionDisplayStatus};
use crate::webhooks::{WebhookTriggerConfig, utils::trigger_webhook_with_balance};
use tari_transaction_components::transaction_components::Transaction;
use tari_utilities::ByteArray;

/// Maximum number of times to attempt broadcasting a transaction before giving up.
const MAX_BROADCAST_ATTEMPTS: i32 = 10;

/// Results from a monitoring cycle.
///
/// Contains both wallet events (for logging/notifications) and updated
/// displayed transactions (for UI updates).
#[derive(Debug, Default)]
pub struct MonitoringResult {
    /// Wallet events generated during monitoring (broadcasts, confirmations, rejections).
    pub wallet_events: Vec<WalletEvent>,
    /// Transactions whose display status was updated.
    pub updated_displayed_transactions: Vec<DisplayedTransaction>,
}

impl MonitoringResult {
    /// Extends this result with events and transactions from another result.
    fn extend(&mut self, other: MonitoringResult) {
        self.wallet_events.extend(other.wallet_events);
        self.updated_displayed_transactions
            .extend(other.updated_displayed_transactions);
    }
}

/// Thread-safe state tracking for pending outbound transactions.
///
/// `MonitoringState` tracks whether there are pending outbound transactions
/// that need monitoring. It uses atomic operations for thread-safe access
/// and can be shared across multiple tasks via cloning.
///
/// # Usage Pattern
///
/// 1. Initialize on startup by checking the database for pending transactions
/// 2. Signal when a new transaction is broadcast
/// 3. Check before running monitoring to avoid unnecessary work
/// 4. Clear when all pending transactions reach terminal states
///
/// # Example
///
/// ```rust,ignore
/// let state = MonitoringState::new();
///
/// // Initialize from database
/// state.initialize(&mut conn, account_id).await?;
///
/// // Signal when broadcasting a new transaction
/// state.signal_transaction_broadcast();
///
/// // Check if monitoring is needed
/// if state.has_pending_outbound() {
///     // Run monitoring...
/// }
/// ```
#[derive(Clone)]
pub struct MonitoringState {
    has_pending_outbound: Arc<AtomicBool>,
}

impl Default for MonitoringState {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitoringState {
    /// Creates a new `MonitoringState` with no pending transactions.
    ///
    /// Call [`initialize`](Self::initialize) to sync with database state.
    pub fn new() -> Self {
        Self {
            has_pending_outbound: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Initializes the state from the database.
    ///
    /// Checks for any pending completed transactions and sets the internal
    /// flag accordingly. Should be called on startup.
    ///
    /// # Arguments
    ///
    /// * `conn` - Database connection
    /// * `account_id` - The account to check for pending transactions
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn initialize(&self, conn: &Connection, account_id: i64) -> Result<()> {
        let pending = get_pending_completed_transactions(conn, account_id)?;
        self.has_pending_outbound.store(!pending.is_empty(), Ordering::SeqCst);
        Ok(())
    }

    /// Signals that a new transaction has been broadcast.
    ///
    /// Call this after successfully broadcasting a transaction to ensure
    /// the monitor will check for its confirmation.
    pub fn signal_transaction_broadcast(&self) {
        self.has_pending_outbound.store(true, Ordering::SeqCst);
    }

    /// Returns whether there are pending outbound transactions.
    ///
    /// If `false`, monitoring can be skipped to save resources.
    pub fn has_pending_outbound(&self) -> bool {
        self.has_pending_outbound.load(Ordering::SeqCst)
    }

    /// Clears the pending outbound flag.
    ///
    /// Called internally when all pending transactions have reached
    /// terminal states (confirmed or rejected).
    fn clear_pending_outbound(&self) {
        self.has_pending_outbound.store(false, Ordering::SeqCst);
    }
}

/// Groups pending transactions by their current status.
///
/// Used internally to process transactions in the appropriate order:
/// completed transactions need broadcasting, broadcast transactions need
/// mining detection, and mined transactions need confirmation tracking.
struct PendingTransactionsByStatus {
    /// Transactions that are signed but not yet broadcast.
    completed: Vec<CompletedTransaction>,
    /// Transactions that have been broadcast but not yet mined.
    broadcast: Vec<CompletedTransaction>,
    /// Transactions that are mined but not yet confirmed.
    mined_unconfirmed: Vec<CompletedTransaction>,
}

impl PendingTransactionsByStatus {
    /// Categorizes transactions by their status.
    ///
    /// Filters out terminal states (confirmed, rejected, canceled) as
    /// they don't need further monitoring.
    fn from_transactions(transactions: Vec<CompletedTransaction>) -> Self {
        let mut result = Self {
            completed: Vec::new(),
            broadcast: Vec::new(),
            mined_unconfirmed: Vec::new(),
        };

        for tx in transactions {
            match tx.status {
                CompletedTransactionStatus::Completed => result.completed.push(tx),
                CompletedTransactionStatus::Broadcast => result.broadcast.push(tx),
                CompletedTransactionStatus::MinedUnconfirmed => result.mined_unconfirmed.push(tx),
                CompletedTransactionStatus::MinedConfirmed
                | CompletedTransactionStatus::Rejected
                | CompletedTransactionStatus::Canceled => {},
            }
        }

        result
    }

    /// Returns the total count of transactions still needing monitoring.
    fn remaining_count(&self) -> usize {
        self.completed.len() + self.broadcast.len() + self.mined_unconfirmed.len()
    }
}

/// Monitors pending transactions through broadcast, mining, and confirmation.
///
/// `TransactionMonitor` is responsible for tracking outbound transactions
/// and updating their status as they progress through the blockchain.
/// It coordinates with the network to:
///
/// - Rebroadcast transactions that haven't been picked up by miners
/// - Detect when transactions appear in blocks
/// - Track confirmation depth until transactions are considered final
/// - Handle rejections and update displayed transactions
///
/// # Usage
///
/// The monitor should be called periodically during sync cycles:
///
/// ```rust,ignore
/// let monitor = TransactionMonitor::new(monitoring_state);
///
/// // During each sync cycle
/// let result = monitor.monitor_if_needed(
///     &wallet_client,
///     &mut conn,
///     account_id,
///     current_chain_height,
/// ).await?;
///
/// // Process results
/// for event in result.wallet_events {
///     log::info!("Transaction event: {:?}", event);
/// }
///
/// for tx in result.updated_displayed_transactions {
///     ui.update_transaction(tx);
/// }
/// ```
///
/// # Performance
///
/// The monitor checks [`MonitoringState::has_pending_outbound`] before doing
/// expensive network queries. When no pending transactions exist, monitoring
/// is essentially a no-op.
pub struct TransactionMonitor {
    state: MonitoringState,
    required_confirmations: u64,
    webhook_config: Option<WebhookTriggerConfig>,
}

impl TransactionMonitor {
    /// Creates a new `TransactionMonitor` with the given state.
    ///
    /// # Arguments
    ///
    /// * `state` - Shared monitoring state for tracking pending transactions
    pub fn new(
        state: MonitoringState,
        required_confirmations: u64,
        webhook_config: Option<WebhookTriggerConfig>,
    ) -> Self {
        Self {
            state,
            required_confirmations,
            webhook_config,
        }
    }

    fn get_connection(pool: &SqlitePool) -> Result<PooledConnection<SqliteConnectionManager>, anyhow::Error> {
        pool.get().map_err(|e| anyhow!("Failed to get DB connection: {}", e))
    }

    fn persist_event(&self, conn: &Connection, account_id: i64, event: &WalletEvent) -> Result<()> {
        let event_id = db::insert_wallet_event(conn, account_id, event)?;
        if let Some(config) = &self.webhook_config {
            trigger_webhook_with_balance(conn, account_id, event_id, event, config)?;
        }
        Ok(())
    }

    /// Returns whether there are pending outbound transactions to monitor.
    ///
    /// Delegates to [`MonitoringState::has_pending_outbound`].
    pub fn has_pending_outbound(&self) -> bool {
        self.state.has_pending_outbound()
    }

    /// Monitors pending transactions and returns status updates.
    ///
    /// This is the main entry point for transaction monitoring. It performs:
    ///
    /// 1. Updates confirmation counts for displayed transactions
    /// 2. If pending outbound transactions exist:
    ///    - Rebroadcasts completed transactions
    ///    - Checks broadcast transactions for mining
    ///    - Checks mined transactions for confirmation
    ///
    /// # Arguments
    ///
    /// * `wallet_client` - HTTP client for network queries
    /// * `db_pool` - Database pool
    /// * `account_id` - The account to monitor
    /// * `current_chain_height` - Current blockchain height for confirmation calculations
    ///
    /// # Returns
    ///
    /// Returns a [`MonitoringResult`] containing:
    /// - Wallet events for broadcasts, confirmations, and rejections
    /// - Updated displayed transactions for UI refresh
    ///
    /// # Errors
    ///
    /// Returns an error if database or network operations fail.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let result = monitor.monitor_if_needed(
    ///     &wallet_client,
    ///     &db_pool,
    ///     account_id,
    ///     chain_height,
    /// ).await?;
    ///
    /// if !result.wallet_events.is_empty() {
    ///     log::info!("Processed {} transaction events", result.wallet_events.len());
    /// }
    /// ```
    pub async fn monitor_if_needed(
        &self,
        wallet_client: &WalletHttpClient,
        db_pool: &SqlitePool,
        account_id: i64,
        current_chain_height: u64,
    ) -> Result<MonitoringResult> {
        let mut result = {
            let conn = Self::get_connection(db_pool)?;
            MonitoringResult {
                updated_displayed_transactions: self.update_displayed_transaction_confirmations(
                    &conn,
                    account_id,
                    current_chain_height,
                )?,
                ..Default::default()
            }
        };

        if self.state.has_pending_outbound() {
            let pending_transactions = {
                let conn = Self::get_connection(db_pool)?;
                get_pending_completed_transactions(&conn, account_id)?
            };

            if pending_transactions.is_empty() {
                self.state.clear_pending_outbound();
            } else {
                let by_status = PendingTransactionsByStatus::from_transactions(pending_transactions);
                let initial_count = by_status.remaining_count();

                let pending_result = self
                    .process_pending_transactions(wallet_client, db_pool, account_id, current_chain_height, by_status)
                    .await?;

                result.extend(pending_result);

                let terminal_transitions = result
                    .wallet_events
                    .iter()
                    .filter(|e| {
                        matches!(
                            e.event_type,
                            WalletEventType::TransactionConfirmed { .. } | WalletEventType::TransactionRejected { .. }
                        )
                    })
                    .count();

                if terminal_transitions >= initial_count {
                    self.state.clear_pending_outbound();
                }
            }
        }

        Ok(result)
    }

    /// Updates confirmation counts for displayed transactions.
    ///
    /// Finds transactions that need confirmation updates and recalculates
    /// their confirmation depth based on the current chain height.
    fn update_displayed_transaction_confirmations(
        &self,
        conn: &Connection,
        account_id: i64,
        current_chain_height: u64,
    ) -> Result<Vec<DisplayedTransaction>> {
        let transactions_needing_update = db::get_displayed_transactions_needing_confirmation_update(conn, account_id)?;

        if transactions_needing_update.is_empty() {
            return Ok(Vec::new());
        }

        let mut updated_transactions = Vec::new();

        for mut displayed_tx in transactions_needing_update {
            let new_confirmations = current_chain_height.saturating_sub(displayed_tx.blockchain.block_height);

            if new_confirmations != displayed_tx.blockchain.confirmations {
                displayed_tx.blockchain.confirmations = new_confirmations;

                let new_status = self.determine_status_from_confirmations(new_confirmations);
                if displayed_tx.status != new_status
                    && matches!(
                        displayed_tx.status,
                        TransactionDisplayStatus::Pending | TransactionDisplayStatus::Unconfirmed
                    )
                {
                    displayed_tx.status = new_status;
                }

                db::update_displayed_transaction_confirmations(conn, &displayed_tx)?;

                updated_transactions.push(displayed_tx);
            }
        }

        Ok(updated_transactions)
    }

    /// Determines the display status based on confirmation count.
    ///
    /// - 0 confirmations: Pending
    /// - 1 to REQUIRED_CONFIRMATIONS-1: Unconfirmed
    /// - REQUIRED_CONFIRMATIONS or more: Confirmed
    fn determine_status_from_confirmations(&self, confirmations: u64) -> TransactionDisplayStatus {
        if confirmations >= self.required_confirmations {
            TransactionDisplayStatus::Confirmed
        } else if confirmations > 0 {
            TransactionDisplayStatus::Unconfirmed
        } else {
            TransactionDisplayStatus::Pending
        }
    }

    /// Processes all pending transactions grouped by status.
    ///
    /// Handles each category appropriately:
    /// - Completed: Attempt to broadcast
    /// - Broadcast: Check if mined
    /// - MinedUnconfirmed: Check confirmation depth
    async fn process_pending_transactions(
        &self,
        wallet_client: &WalletHttpClient,
        db_pool: &SqlitePool,
        account_id: i64,
        current_chain_height: u64,
        by_status: PendingTransactionsByStatus,
    ) -> Result<MonitoringResult> {
        let mut result = MonitoringResult::default();

        result.extend(
            self.rebroadcast_completed_transactions(wallet_client, db_pool, account_id, by_status.completed)
                .await?,
        );

        let broadcast_events = self
            .check_broadcast_for_mining(wallet_client, db_pool, account_id, by_status.broadcast)
            .await?;
        result.wallet_events.extend(broadcast_events);

        let confirmation_events =
            self.check_confirmation_status(db_pool, account_id, current_chain_height, by_status.mined_unconfirmed)?;
        result.wallet_events.extend(confirmation_events);

        Ok(result)
    }

    async fn rebroadcast_completed_transactions(
        &self,
        wallet_client: &WalletHttpClient,
        db_pool: &SqlitePool,
        account_id: i64,
        transactions: Vec<CompletedTransaction>,
    ) -> Result<MonitoringResult> {
        let mut result = MonitoringResult::default();

        for tx in transactions {
            let conn = Self::get_connection(db_pool)?;
            if tx.broadcast_attempts >= MAX_BROADCAST_ATTEMPTS {
                warn!(
                    target: "audit",
                    id = tx.id.to_string().as_str();
                    "Transaction exceeded max broadcast attempts"
                );
                let reason = format!("Exceeded {} broadcast attempts", MAX_BROADCAST_ATTEMPTS);
                mark_completed_transaction_as_rejected(&conn, tx.id, &reason)?;
                db::unlock_outputs_for_pending_transaction(&conn, &tx.pending_tx_id)?;

                if let Some(rejected_displayed_tx) = db::mark_displayed_transaction_rejected(&conn, tx.id)? {
                    result.updated_displayed_transactions.push(rejected_displayed_tx);
                }

                let event = WalletEvent {
                    id: 0,
                    account_id,
                    event_type: WalletEventType::TransactionRejected { tx_id: tx.id, reason },
                    description: format!("Transaction {} exceeded broadcast attempts", tx.id),
                };
                self.persist_event(&conn, account_id, &event)?;
                result.wallet_events.push(event);
                continue;
            }

            match Self::broadcast_transaction(wallet_client, &tx).await {
                Ok(()) => {
                    info!(
                        target: "audit",
                        id = tx.id.to_string().as_str();
                        "Rebroadcasting transaction"
                    );
                    mark_completed_transaction_as_broadcasted(&conn, tx.id, tx.broadcast_attempts + 1)?;

                    let event = WalletEvent {
                        id: 0,
                        account_id,
                        event_type: WalletEventType::TransactionBroadcast {
                            tx_id: tx.id,
                            kernel_excess: tx.kernel_excess.clone(),
                        },
                        description: format!("Transaction {} broadcast", tx.id),
                    };
                    self.persist_event(&conn, account_id, &event)?;
                    result.wallet_events.push(event);
                },
                Err(reason) => {
                    warn!(
                        target: "audit",
                        id = tx.id.to_string().as_str(),
                        reason:% = reason;
                        "Transaction rejected on rebroadcast"
                    );
                    mark_completed_transaction_as_rejected(&conn, tx.id, &reason)?;
                    db::unlock_outputs_for_pending_transaction(&conn, &tx.pending_tx_id)?;

                    if let Some(rejected_displayed_tx) = db::mark_displayed_transaction_rejected(&conn, tx.id)? {
                        result.updated_displayed_transactions.push(rejected_displayed_tx);
                    }

                    let event = WalletEvent {
                        id: 0,
                        account_id,
                        event_type: WalletEventType::TransactionRejected { tx_id: tx.id, reason },
                        description: format!("Transaction {} rejected", tx.id),
                    };
                    self.persist_event(&conn, account_id, &event)?;
                    result.wallet_events.push(event);
                },
            }
        }

        Ok(result)
    }

    async fn check_broadcast_for_mining(
        &self,
        wallet_client: &WalletHttpClient,
        db_pool: &SqlitePool,
        account_id: i64,
        transactions: Vec<CompletedTransaction>,
    ) -> Result<Vec<WalletEvent>> {
        let mut events = Vec::new();

        for tx in transactions {
            if let Some((block_height, block_hash)) = Self::find_kernel_on_chain(wallet_client, &tx).await? {
                info!(
                    target: "audit",
                    id = tx.id.to_string().as_str(),
                    height = block_height;
                    "Transaction mined (unconfirmed)"
                );
                let conn = Self::get_connection(db_pool)?;
                mark_completed_transaction_as_mined_unconfirmed(&conn, tx.id, block_height as i64, &block_hash)?;

                let event = WalletEvent {
                    id: 0,
                    account_id,
                    event_type: WalletEventType::TransactionUnconfirmed {
                        tx_id: tx.id,
                        mined_height: block_height,
                        confirmations: 0,
                    },
                    description: format!("Transaction {} mined at height {}", tx.id, block_height),
                };
                self.persist_event(&conn, account_id, &event)?;
                events.push(event);
            }
        }

        Ok(events)
    }

    fn check_confirmation_status(
        &self,
        db_pool: &SqlitePool,
        account_id: i64,
        current_height: u64,
        transactions: Vec<CompletedTransaction>,
    ) -> Result<Vec<WalletEvent>> {
        let mut events = Vec::new();

        for tx in transactions {
            let mined_height = match tx.mined_height {
                Some(h) => h as u64,
                None => continue,
            };

            let confirmations = current_height.saturating_sub(mined_height);
            if confirmations >= self.required_confirmations {
                info!(
                    target: "audit",
                    id = tx.id.to_string().as_str(),
                    confirmations = confirmations;
                    "Transaction confirmed"
                );
                let mined_block_hash = tx
                    .mined_block_hash
                    .ok_or_else(|| anyhow!("Block hash missing for a mined tx: {}", tx.id))
                    .and_then(|b| FixedHash::try_from(b).map_err(|e| e.into()))?;

                let sent_output_hash = tx
                    .sent_output_hash
                    .as_ref()
                    .ok_or_else(|| anyhow!("Sent output hash missing for a mined tx: {}", tx.id))
                    .and_then(|h| hex::decode(h).map_err(|e| e.into()))
                    .and_then(|b| FixedHash::try_from(b).map_err(|e| e.into()))?;

                let payref = hex::encode(generate_payment_reference(&mined_block_hash, &sent_output_hash));

                let conn = Self::get_connection(db_pool)?;
                mark_completed_transaction_as_confirmed(&conn, tx.id, current_height as i64, payref)?;

                let event = WalletEvent {
                    id: 0,
                    account_id,
                    event_type: WalletEventType::TransactionConfirmed {
                        tx_id: tx.id,
                        mined_height,
                        confirmation_height: current_height,
                    },
                    description: format!("Transaction {} confirmed", tx.id),
                };
                self.persist_event(&conn, account_id, &event)?;
                events.push(event);
            }
        }

        Ok(events)
    }

    async fn broadcast_transaction(wallet_client: &WalletHttpClient, tx: &CompletedTransaction) -> Result<(), String> {
        let transaction: Transaction =
            serde_json::from_slice(&tx.serialized_transaction).map_err(|e| format!("Deserialization failed: {}", e))?;

        let response = wallet_client
            .submit_transaction(transaction)
            .await
            .map_err(|e| format!("Broadcast failed: {}", e))?;

        if response.accepted || response.rejection_reason == TxSubmissionRejectionReason::AlreadyMined {
            Ok(())
        } else {
            Err(format!("Transaction rejected: {}", response.rejection_reason))
        }
    }

    async fn find_kernel_on_chain(
        wallet_client: &WalletHttpClient,
        tx: &CompletedTransaction,
    ) -> Result<Option<(u64, Vec<u8>)>> {
        let transaction: Transaction =
            serde_json::from_slice(&tx.serialized_transaction).map_err(|e| anyhow!("Deserialization failed: {}", e))?;

        let kernel = transaction
            .body()
            .kernels()
            .first()
            .ok_or_else(|| anyhow!("Transaction has no kernel"))?;

        let excess_sig_nonce = kernel.excess_sig.get_compressed_public_nonce().as_bytes();
        let excess_sig = kernel.excess_sig.get_signature().as_bytes();

        let response = wallet_client
            .transaction_query(excess_sig_nonce, excess_sig)
            .await
            .map_err(|e| anyhow!("Transaction query failed: {}", e))?;

        match response.location {
            TxLocation::Mined => {
                let height = response
                    .mined_height
                    .ok_or_else(|| anyhow!("Mined transaction missing height"))?;
                let hash = response
                    .mined_header_hash
                    .ok_or_else(|| anyhow!("Mined transaction missing block hash"))?;
                Ok(Some((height, hash)))
            },
            _ => Ok(None),
        }
    }
}
