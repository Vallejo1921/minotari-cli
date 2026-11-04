//! Transaction monitoring for broadcast, mining, and confirmation.
//!
//! This module provides infrastructure for tracking outbound transactions
//! through their lifecycle from broadcast to final confirmation. It handles:
//!
//! - Rebroadcasting transactions that haven't been picked up
//! - Asking the node whether broadcast transactions are still in its mempool
//! - Tracking confirmation progress
//! - Updating transaction display status for UI
//!
//! The monitor does not detect that a transaction was mined: the wallet's own
//! block scan does that (see `BlockProcessor::match_sends`), so the node is
//! never asked twice. The scan coordinator runs the monitor once a scan pass
//! is caught up or has reached its block limit.
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
//! - **Rejected**: The wallet's scan saw the transaction's inputs spent by a
//!   different transaction. The node's answers never reject a transaction: one
//!   the node keeps not accepting stays Completed/Broadcast with its inputs
//!   locked and is retried less often (stalled)
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
//! use minotari_wallet_core::transactions::monitor::{TransactionMonitor, MonitoringState};
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
use chrono::Utc;
use log::{info, trace, warn};
use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{Connection, TransactionBehavior};
use tari_common_types::payment_reference::generate_payment_reference;
use tari_common_types::types::FixedHash;
use tari_transaction_components::rpc::models::{TxLocation, TxQueryResponse, TxSubmissionRejectionReason};

use crate::db::{
    self, CompletedTransaction, CompletedTransactionStatus, SqlitePool, get_pending_completed_transactions,
    mark_completed_transaction_as_broadcasted, mark_completed_transaction_as_confirmed,
    mark_completed_transaction_as_mined_unconfirmed,
};
use crate::http::{HttpError, WalletHttpClient};
use crate::log::sanitize_node_text;
use crate::models::{WalletEvent, WalletEventType};
use crate::transactions::{DisplayedTransaction, TransactionDisplayStatus};
use crate::webhooks::{WebhookTriggerConfig, utils::trigger_webhook_with_balance};
use tari_transaction_components::transaction_components::Transaction;
use tari_utilities::ByteArray;

/// Number of broadcasts in a row the node may not accept before a send counts
/// as stalled. A stalled send is not given up: it keeps its inputs locked and is
/// retried every [`STALLED_REBROADCAST_INTERVAL_SECS`] instead of every pass.
pub const MAX_BROADCAST_ATTEMPTS: i32 = 10;

/// How long a stalled send waits between rebroadcasts.
const STALLED_REBROADCAST_INTERVAL_SECS: i64 = 60 * 60;

/// What the node answered when a transaction was submitted to it.
enum SubmitOutcome {
    /// Accepted into the mempool, or already mined.
    Accepted,
    /// Not accepted, for any reason the node gives (including a double spend or
    /// a failed validation) or an error answer. The node's word alone never
    /// rejects a send: only the wallet's scan can show its inputs went elsewhere.
    NotAccepted(String),
}

/// A request to the base node failed (as opposed to the database).
///
/// The monitor logs it, leaves that transaction as it is and carries on with
/// the others; the next pass asks the node again.
#[derive(Debug, thiserror::Error)]
#[error("Base node request failed: {0}")]
pub struct NodeRequestError(pub String);

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
/// completed transactions need broadcasting, broadcast transactions need a
/// mempool check, and mined transactions need confirmation tracking.
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
        self.completed
            .len()
            .saturating_add(self.broadcast.len())
            .saturating_add(self.mined_unconfirmed.len())
    }
}

/// Monitors pending transactions through broadcast, mining, and confirmation.
///
/// `TransactionMonitor` is responsible for tracking outbound transactions
/// and updating their status as they progress through the blockchain.
/// It coordinates with the network to:
///
/// - Rebroadcast transactions that haven't been picked up by miners, or that
///   dropped out of the node's mempool
/// - Track confirmation depth until transactions are considered final
/// - Update displayed transactions
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

    /// Returns whether there are pending outbound transactions, re-reading the
    /// database when the flag is clear.
    ///
    /// Sends can be made while a scan runs (by the API, the CLI, or an
    /// embedding application), and nothing signals them to this monitor. The
    /// scan only recognises a send in a block while this flag is set, so it is
    /// refreshed before each batch is processed; a send already in a fetched
    /// block was recorded before it was broadcast, so it is seen here.
    pub fn refresh_pending_outbound(&self, db_pool: &SqlitePool, account_id: i64) -> Result<bool> {
        if !self.state.has_pending_outbound() {
            let conn = Self::get_connection(db_pool)?;
            self.state.initialize(&conn, account_id)?;
        }
        Ok(self.state.has_pending_outbound())
    }

    /// Monitors pending transactions and returns status updates.
    ///
    /// This is the main entry point for transaction monitoring. It performs:
    ///
    /// 1. Updates confirmation counts for mined displayed transactions (DB only)
    /// 2. If pending outbound transactions exist:
    ///    - Moves `MinedUnconfirmed` transactions to `MinedConfirmed` at depth (DB only)
    ///    - Rebroadcasts `Completed` transactions
    ///    - Asks the node whether each `Broadcast` transaction is still in its
    ///      mempool, and rebroadcasts it if the node no longer has it. A
    ///      transaction the node reports as mined is left to the block scan.
    ///
    /// When nothing is pending, no request is made to the node.
    ///
    /// # Arguments
    ///
    /// * `wallet_client` - HTTP client for network queries
    /// * `db_pool` - Database pool
    /// * `account_id` - The account to monitor
    /// * `current_chain_height` - The height the account has been scanned to
    ///
    /// # Returns
    ///
    /// Returns a [`MonitoringResult`] containing:
    /// - Wallet events for broadcasts, confirmations, and rejections
    /// - Updated displayed transactions for UI refresh
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails. A failed request to the
    /// node is logged and leaves that transaction for the next pass; it does not
    /// stop the other transactions from being monitored.
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

        if self.refresh_pending_outbound(db_pool, account_id)? {
            let pending_transactions = {
                let conn = Self::get_connection(db_pool)?;
                get_pending_completed_transactions(&conn, account_id)?
            };

            if pending_transactions.is_empty() {
                self.state.clear_pending_outbound();
            } else {
                let by_status = PendingTransactionsByStatus::from_transactions(pending_transactions);
                let initial_count = by_status.remaining_count();

                let confirmation_events = self.check_confirmation_status(
                    db_pool,
                    account_id,
                    current_chain_height,
                    by_status.mined_unconfirmed,
                )?;
                result.wallet_events.extend(confirmation_events);

                result.extend(
                    self.rebroadcast_completed_transactions(wallet_client, db_pool, account_id, by_status.completed)
                        .await?,
                );

                result.extend(
                    self.check_broadcast_in_mempool(
                        wallet_client,
                        db_pool,
                        account_id,
                        current_chain_height,
                        by_status.broadcast,
                    )
                    .await?,
                );

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
            let locked_diff = displayed_tx.lock_height.saturating_sub(current_chain_height);

            if new_confirmations != displayed_tx.blockchain.confirmations {
                displayed_tx.blockchain.confirmations = new_confirmations;

                let new_status = self.determine_status_from_confirmations(new_confirmations, locked_diff);
                if displayed_tx.status != new_status
                    && matches!(
                        displayed_tx.status,
                        TransactionDisplayStatus::Pending
                            | TransactionDisplayStatus::Unconfirmed
                            | TransactionDisplayStatus::Locked
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
    fn determine_status_from_confirmations(&self, confirmations: u64, locked_diff: u64) -> TransactionDisplayStatus {
        if confirmations >= self.required_confirmations {
            if locked_diff > 0 {
                TransactionDisplayStatus::Locked
            } else {
                TransactionDisplayStatus::Confirmed
            }
        } else if confirmations > 0 {
            TransactionDisplayStatus::Unconfirmed
        } else {
            TransactionDisplayStatus::Pending
        }
    }

    /// Rebroadcasts `Completed` transactions (signed but not yet accepted by the node).
    async fn rebroadcast_completed_transactions(
        &self,
        wallet_client: &WalletHttpClient,
        db_pool: &SqlitePool,
        account_id: i64,
        transactions: Vec<CompletedTransaction>,
    ) -> Result<MonitoringResult> {
        let mut result = MonitoringResult::default();
        for tx in transactions {
            let outcome = self
                .rebroadcast(wallet_client, db_pool, account_id, &tx, &mut result)
                .await;
            Self::skip_on_node_error(outcome)?;
        }
        Ok(result)
    }

    /// Lets the monitor carry on with the next transaction after a failed node
    /// request for it.
    ///
    /// The failure is logged and the transaction is left as it is; the next pass asks the
    /// node again. One transaction the node cannot answer for must not stop every
    /// other transaction and account from being monitored. Any other error (a
    /// database failure) is returned.
    fn skip_on_node_error(outcome: Result<()>) -> Result<()> {
        match outcome {
            Err(e) if e.downcast_ref::<NodeRequestError>().is_some() => {
                warn!(
                    target: "audit",
                    error:% = e;
                    "Base node request failed; leaving the transaction for the next pass"
                );
                Ok(())
            },
            other => other,
        }
    }

    /// Asks the node about every `Broadcast` transaction.
    ///
    /// - In the mempool: nothing to do yet.
    /// - Not stored (dropped from the mempool, or never seen): rebroadcast it, or
    ///   retry it less often once the node has not accepted it
    ///   [`MAX_BROADCAST_ATTEMPTS`] times in a row (stalled).
    /// - Mined at or below `scanned_height`: the scan has already passed that
    ///   block without recognising the send (for example a send made before
    ///   the scan could match sends), so it never will. It is marked mined at
    ///   the height and block the node reports.
    /// - Mined above `scanned_height`, or without a height and block hash:
    ///   ignored. The block scan marks it mined when it scans that block.
    ///
    /// A transaction that cannot be decoded is logged and skipped.
    async fn check_broadcast_in_mempool(
        &self,
        wallet_client: &WalletHttpClient,
        db_pool: &SqlitePool,
        account_id: i64,
        scanned_height: u64,
        transactions: Vec<CompletedTransaction>,
    ) -> Result<MonitoringResult> {
        let mut result = MonitoringResult::default();

        for tx in transactions {
            let Some(transaction) = Self::decode_transaction(&tx) else {
                continue;
            };
            let response = match Self::query_transaction(wallet_client, &transaction).await {
                Ok(Some(response)) => response,
                Ok(None) => continue,
                Err(e) => {
                    Self::skip_on_node_error(Err(e))?;
                    continue;
                },
            };
            match response.location {
                TxLocation::InMempool => {},
                TxLocation::Mined => {
                    let (Some(mined_height), Some(mined_block_hash)) =
                        (response.mined_height, response.mined_header_hash)
                    else {
                        continue;
                    };
                    if mined_height > scanned_height {
                        continue;
                    }
                    let Ok(mined_block_hash) = FixedHash::try_from(mined_block_hash) else {
                        warn!(
                            target: "audit",
                            "Node reported a malformed block hash for a mined transaction; leaving it to the scan"
                        );
                        continue;
                    };
                    // The wallet recorded the block it scanned at that height (unless
                    // it has been pruned since): the node's block must be the same one.
                    let mut conn = Self::get_connection(db_pool)?;
                    if let Some(scanned_hash) =
                        db::get_scanned_tip_block_hash_at_height(&conn, account_id, mined_height)?
                        && scanned_hash != mined_block_hash.to_vec()
                    {
                        warn!(
                            target: "audit",
                            height = mined_height;
                            "Node reports the transaction mined in a block the wallet did not scan; leaving it to the scan"
                        );
                        continue;
                    }
                    info!(
                        target: "audit",
                        height = mined_height;
                        "Transaction mined in a block the scan has already passed (unconfirmed)"
                    );
                    trace!(
                        target: "audit",
                        id = tx.id.to_string().as_str();
                        "Transaction mined in a block the scan has already passed (unconfirmed)"
                    );
                    let event = WalletEvent {
                        id: 0,
                        account_id,
                        event_type: WalletEventType::TransactionUnconfirmed {
                            tx_id: tx.id,
                            mined_height,
                            confirmations: 0,
                        },
                        description: format!("Transaction {} mined at height {}", tx.id, mined_height),
                    };
                    // The status and its event go in together.
                    let db_tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                    #[allow(clippy::cast_possible_wrap)]
                    mark_completed_transaction_as_mined_unconfirmed(
                        &db_tx,
                        tx.id,
                        mined_height as i64,
                        mined_block_hash.as_slice(),
                    )?;
                    self.persist_event(&db_tx, account_id, &event)?;
                    db_tx.commit()?;
                    result.wallet_events.push(event);
                },
                TxLocation::NotStored | TxLocation::None => {
                    info!(target: "audit", "Broadcast transaction is not in the mempool");
                    trace!(
                        target: "audit",
                        id = tx.id.to_string().as_str();
                        "Broadcast transaction is not in the mempool"
                    );
                    let outcome = self
                        .rebroadcast(wallet_client, db_pool, account_id, &tx, &mut result)
                        .await;
                    Self::skip_on_node_error(outcome)?;
                },
            }
        }

        Ok(result)
    }

    /// Submits `tx` to the node again.
    ///
    /// - Accepted (or already mined): the send is `Broadcast` and its count of
    ///   broadcasts not accepted goes back to 0.
    /// - Not accepted, whatever the reason: that count goes up and the send is
    ///   left as it is, inputs still locked, change still `UNCONFIRMED`. When the
    ///   count reaches [`MAX_BROADCAST_ATTEMPTS`] the send is stalled and a
    ///   persisted `TransactionStalled` is emitted.
    ///
    /// The node's answer never rejects a send or releases its inputs. A stalled
    /// send is retried only every [`STALLED_REBROADCAST_INTERVAL_SECS`].
    async fn rebroadcast(
        &self,
        wallet_client: &WalletHttpClient,
        db_pool: &SqlitePool,
        account_id: i64,
        tx: &CompletedTransaction,
        result: &mut MonitoringResult,
    ) -> Result<()> {
        if tx.broadcast_attempts >= MAX_BROADCAST_ATTEMPTS {
            let since_last_try = Utc::now().signed_duration_since(tx.updated_at).num_seconds();
            if since_last_try < STALLED_REBROADCAST_INTERVAL_SECS {
                return Ok(());
            }
        }

        let Some(transaction) = Self::decode_transaction(tx) else {
            return Ok(());
        };

        // A failed request (node unreachable, HTTP error) is a `NodeRequestError`
        // and leaves the transaction as it is.
        match Self::broadcast_transaction(wallet_client, transaction).await? {
            SubmitOutcome::Accepted => {
                info!(target: "audit", "Rebroadcasting transaction");
                trace!(
                    target: "audit",
                    id = tx.id.to_string().as_str();
                    "Rebroadcasting transaction"
                );
                let event = WalletEvent {
                    id: 0,
                    account_id,
                    event_type: WalletEventType::TransactionBroadcast {
                        tx_id: tx.id,
                        kernel_excess: tx.kernel_excess.clone(),
                    },
                    description: format!("Transaction {} broadcast", tx.id),
                };
                // The status and its event go in together. An accepted broadcast
                // does not count towards the stall limit.
                let mut conn = Self::get_connection(db_pool)?;
                let db_tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                if !mark_completed_transaction_as_broadcasted(&db_tx, tx.id, 0)? {
                    // The user may have abandoned the send while the node was
                    // answering. Its inputs are released, so surface this known
                    // double-spend risk instead of hiding it in an info log.
                    if db::get_completed_transaction_by_id(&db_tx, tx.id)?.is_some_and(|send| {
                        send.status == db::CompletedTransactionStatus::Rejected
                            && send.last_rejected_reason.as_deref()
                                == Some(crate::transactions::abandon::ABANDONED_REASON)
                    }) {
                        let warning = WalletEvent {
                            id: 0,
                            account_id,
                            event_type: WalletEventType::TransactionAcceptedAfterAbandon { tx_id: tx.id },
                            description: format!(
                                "WARNING: Transaction {} was accepted after abandonment; its inputs were released. Do not spend them again until the chain is reconciled",
                                tx.id
                            ),
                        };
                        self.persist_event(&db_tx, account_id, &warning)?;
                        db_tx.commit()?;
                        result.wallet_events.push(warning);
                    }
                    return Ok(());
                }
                self.persist_event(&db_tx, account_id, &event)?;
                db_tx.commit()?;
                result.wallet_events.push(event);
                Ok(())
            },
            SubmitOutcome::NotAccepted(reason) => {
                let reason = sanitize_node_text(&reason);
                let attempts = tx.broadcast_attempts.saturating_add(1);
                warn!(
                    target: "audit",
                    attempts = attempts,
                    reason:% = reason;
                    "Transaction not accepted on rebroadcast; will try again"
                );
                let stalled_event = (attempts == MAX_BROADCAST_ATTEMPTS).then(|| WalletEvent {
                    id: 0,
                    account_id,
                    event_type: WalletEventType::TransactionStalled {
                        tx_id: tx.id,
                        failed_broadcast_attempts: attempts,
                        node_reason: Some(reason.clone()),
                    },
                    description: format!(
                        "Transaction {} not accepted by the node after {} tries; retrying less often",
                        tx.id, attempts
                    ),
                });
                // The count and the stall event go in together.
                let mut conn = Self::get_connection(db_pool)?;
                let db_tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                if !db::record_failed_broadcast_attempt(&db_tx, tx.id, attempts, &reason)? {
                    return Ok(());
                }
                if let Some(event) = &stalled_event {
                    self.persist_event(&db_tx, account_id, event)?;
                }
                db_tx.commit()?;
                if let Some(event) = stalled_event {
                    warn!(
                        target: "audit",
                        "Transaction stalled: the node keeps not accepting it"
                    );
                    result.wallet_events.push(event);
                }
                Ok(())
            },
        }
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
                // A row whose hashes cannot be decoded is logged and skipped: an
                // error here would fail every pass, for every account.
                let mined_block_hash = tx.mined_block_hash.clone().and_then(|b| FixedHash::try_from(b).ok());
                let sent_output_hash = tx
                    .sent_output_hash
                    .as_ref()
                    .and_then(|h| hex::decode(h).ok())
                    .and_then(|b| FixedHash::try_from(b).ok());
                let (Some(mined_block_hash), Some(sent_output_hash)) = (mined_block_hash, sent_output_hash) else {
                    warn!(
                        target: "audit",
                        "Mined transaction has a missing or malformed block or sent output hash; cannot confirm it"
                    );
                    continue;
                };
                info!(
                    target: "audit",
                    confirmations = confirmations;
                    "Transaction confirmed"
                );
                trace!(
                    target: "audit",
                    id = tx.id.to_string().as_str();
                    "Transaction confirmed"
                );

                let payref = hex::encode(generate_payment_reference(&mined_block_hash, &sent_output_hash));

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
                // The status and its event go in together.
                let mut conn = Self::get_connection(db_pool)?;
                let db_tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                #[allow(clippy::cast_possible_wrap)]
                mark_completed_transaction_as_confirmed(&db_tx, tx.id, current_height as i64, payref)?;
                self.persist_event(&db_tx, account_id, &event)?;
                db_tx.commit()?;
                events.push(event);
            }
        }

        Ok(events)
    }

    /// Decodes the stored transaction, or logs and returns `None` if it cannot
    /// be decoded, so one bad row does not stop the monitor for every other one.
    fn decode_transaction(tx: &CompletedTransaction) -> Option<Transaction> {
        match serde_json::from_slice(&tx.serialized_transaction) {
            Ok(transaction) => Some(transaction),
            Err(e) => {
                warn!(
                    target: "audit",
                    error:% = e;
                    "Cannot decode stored transaction; skipping it"
                );
                None
            },
        }
    }

    /// Submits `transaction` to the node and says what it answered.
    ///
    /// Any reason the node gives for not accepting it, and an error answer, is
    /// "not accepted". A request that did not get an answer from the node
    /// (unreachable, HTTP error) is a [`NodeRequestError`].
    async fn broadcast_transaction(
        wallet_client: &WalletHttpClient,
        transaction: Transaction,
    ) -> Result<SubmitOutcome> {
        let response = match wallet_client.submit_transaction(transaction).await {
            Ok(response) => response,
            Err(e) if e.downcast_ref::<HttpError>().is_some() => {
                return Err(NodeRequestError(sanitize_node_text(&format!("Broadcast failed: {}", e))).into());
            },
            // The node answered with an error, or the transaction is too large to send.
            Err(e) => return Ok(SubmitOutcome::NotAccepted(format!("Broadcast failed: {}", e))),
        };

        if response.accepted || response.rejection_reason == TxSubmissionRejectionReason::AlreadyMined {
            return Ok(SubmitOutcome::Accepted);
        }
        Ok(SubmitOutcome::NotAccepted(format!(
            "Transaction not accepted: {}",
            response.rejection_reason
        )))
    }

    /// Asks the node where `transaction` is, by its kernel signature.
    ///
    /// A failed request is a [`NodeRequestError`]. A transaction without a
    /// kernel cannot be looked up; it is logged and `None` is returned.
    async fn query_transaction(
        wallet_client: &WalletHttpClient,
        transaction: &Transaction,
    ) -> Result<Option<TxQueryResponse>> {
        let Some(kernel) = transaction.body().kernels().first() else {
            warn!(
                target: "audit",
                "Stored transaction has no kernel; skipping it"
            );
            return Ok(None);
        };

        let excess_sig_nonce = kernel.excess_sig.get_compressed_public_nonce().as_bytes();
        let excess_sig = kernel.excess_sig.get_signature().as_bytes();

        let response = wallet_client
            .transaction_query(excess_sig_nonce, excess_sig)
            .await
            .map_err(|e| NodeRequestError(sanitize_node_text(&format!("Transaction query failed: {}", e))))?;

        Ok(Some(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{create_account, get_account_by_name, get_displayed_transaction_by_id, init_db};
    use crate::transactions::idempotency::{IdempotencyBinding, IdempotencyOperation, RequestFingerprint};
    use crate::transactions::{BlockchainInfo, TransactionDetails, TransactionDirection, TransactionSource};
    use chrono::Utc;
    use rusqlite::named_params;
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_common_types::transaction::TxId;
    use tari_common_types::types::{ComAndPubSignature, CompressedPublicKey, CompressedSignature, PrivateKey};
    use tari_script::{ExecutionStack, TariScript};
    use tari_transaction_components::MicroMinotari;
    use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
    use tari_transaction_components::key_manager::{KeyManager, TariKeyId, TransactionKeyManagerInterface};
    use tari_transaction_components::transaction_components::{
        EncryptedData, MemoField, OutputFeatures, TransactionKernel, TransactionOutputVersion, WalletOutput,
        covenants::Covenant,
    };
    use tempfile::TempDir;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_pool(name: &str) -> (SqlitePool, i64, TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let pool = init_db(dir.path().join(name)).expect("init db");
        let conn = pool.get().expect("conn");
        let seeds = CipherSeed::random();
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(seeds).unwrap());
        create_account(&conn, "default", &wallet, "password").unwrap();
        let account_id = get_account_by_name(&conn, "default").unwrap().unwrap().id;
        (pool, account_id, dir)
    }

    fn pending_send(account_id: i64, id: u64, block_height: u64) -> DisplayedTransaction {
        DisplayedTransaction {
            id: TxId::from(id),
            direction: TransactionDirection::Outgoing,
            source: TransactionSource::Transfer,
            status: TransactionDisplayStatus::Pending,
            amount: MicroMinotari::from(1_000),
            message: None,
            counterparty: None,
            blockchain: BlockchainInfo {
                block_height,
                timestamp: chrono::Utc::now().naive_utc(),
                confirmations: 0,
                block_hash: FixedHash::zero(),
            },
            fee: None,
            details: TransactionDetails {
                account_id,
                total_credit: MicroMinotari::from(0),
                total_debit: MicroMinotari::from(1_000),
                inputs: Vec::new(),
                outputs: Vec::new(),
                output_type: None,
                coinbase_extra: None,
                memo_hex: None,
                sent_output_hashes: Vec::new(),
                sent_payrefs: Vec::new(),
            },
            lock_height: 0,
        }
    }

    fn status_of(conn: &Connection, id: u64) -> TransactionDisplayStatus {
        get_displayed_transaction_by_id(conn, &TxId::from(id).to_string())
            .expect("query")
            .expect("row exists")
            .status
    }

    #[test]
    fn an_unmined_displayed_send_stays_pending_at_any_chain_height() {
        // An unmined send has block_height 0, so `tip - 0` would count it as deeply
        // confirmed. It must stay Pending until the scan sees it in a block.
        let (pool, account_id, _dir) = test_pool("unmined.db");
        let conn = pool.get().expect("conn");
        db::insert_displayed_transaction(&conn, &pending_send(account_id, 1, 0)).expect("insert");
        let monitor = TransactionMonitor::new(MonitoringState::new(), 3, None);

        for height in [1, 3, 10, 1_000_000] {
            let updated = monitor
                .update_displayed_transaction_confirmations(&conn, account_id, height)
                .expect("update");
            assert!(updated.is_empty(), "nothing may change at height {height}");
            assert_eq!(status_of(&conn, 1), TransactionDisplayStatus::Pending);
        }
    }

    #[test]
    fn a_mined_displayed_send_moves_to_confirmed_as_the_scanned_height_rises() {
        let (pool, account_id, _dir) = test_pool("mined.db");
        let conn = pool.get().expect("conn");
        db::insert_displayed_transaction(&conn, &pending_send(account_id, 2, 100)).expect("insert");
        let monitor = TransactionMonitor::new(MonitoringState::new(), 3, None);

        monitor
            .update_displayed_transaction_confirmations(&conn, account_id, 100)
            .expect("update");
        assert_eq!(status_of(&conn, 2), TransactionDisplayStatus::Pending);

        monitor
            .update_displayed_transaction_confirmations(&conn, account_id, 101)
            .expect("update");
        assert_eq!(status_of(&conn, 2), TransactionDisplayStatus::Unconfirmed);

        monitor
            .update_displayed_transaction_confirmations(&conn, account_id, 103)
            .expect("update");
        assert_eq!(status_of(&conn, 2), TransactionDisplayStatus::Confirmed);
    }

    fn test_wallet_output(value: u64, hash_byte: u8) -> WalletOutput {
        WalletOutput::new_from_parts(
            TransactionOutputVersion::default(),
            MicroMinotari::from(value),
            TariKeyId::default(),
            OutputFeatures::default(),
            TariScript::default(),
            ExecutionStack::default(),
            TariKeyId::default(),
            CompressedPublicKey::default(),
            ComAndPubSignature::default(),
            0,
            Covenant::default(),
            EncryptedData::default(),
            MicroMinotari::from(0),
            None,
            MemoField::new_empty(),
            FixedHash::from([hash_byte; 32]),
            Default::default(),
        )
    }

    /// A wallet with one recorded send: an input locked to it, a completed
    /// transaction in `status` after `broadcast_attempts`, an `UNCONFIRMED`
    /// change row and a pending displayed transaction.
    struct SendFixture {
        pool: SqlitePool,
        account_id: i64,
        tx_id: TxId,
        request_id: String,
        input_output_id: i64,
        _dir: TempDir,
    }

    fn send_fixture(name: &str, broadcast_attempts: i32) -> SendFixture {
        let dir = tempfile::tempdir().expect("temp dir");
        let pool = init_db(dir.path().join(name)).expect("init db");
        let conn = pool.get().expect("conn");
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
        create_account(&conn, "default", &wallet, "password").unwrap();
        let account_id = get_account_by_name(&conn, "default").unwrap().unwrap().id;
        let view_key = KeyManager::new(wallet).unwrap().get_private_view_key();

        let binding = IdempotencyBinding::new(
            Some("send".to_string()),
            IdempotencyOperation::SendTransaction,
            RequestFingerprint::new(IdempotencyOperation::SendTransaction),
        );
        let request_id = db::create_pending_transaction(
            &conn,
            "send",
            &binding,
            account_id,
            true,
            MicroMinotari(0),
            MicroMinotari(0),
            MicroMinotari(0),
            Utc::now() + chrono::Duration::hours(1),
        )
        .expect("pending transaction");

        let input = test_wallet_output(10_000, 1);
        let input_output_id = db::insert_output(
            &conn,
            account_id,
            &view_key,
            input.output_hash().to_vec(),
            &input,
            10,
            &FixedHash::from([10u8; 32]),
            1_700_000_000,
            None,
            None,
            FixedHash::zero(),
            false,
        )
        .expect("input");
        db::lock_output(&conn, input_output_id, &request_id, Utc::now()).expect("lock");

        let transaction = Transaction::new(
            Vec::new(),
            Vec::new(),
            vec![TransactionKernel::default()],
            PrivateKey::default(),
            PrivateKey::default(),
        );
        let tx_id = TxId::from(1u64);
        db::create_completed_transaction(
            &conn,
            account_id,
            &request_id,
            &[],
            &serde_json::to_vec(&transaction).expect("serialize"),
            Some(hex::encode([9u8; 32])),
            tx_id,
        )
        .expect("completed");
        mark_completed_transaction_as_broadcasted(&conn, tx_id, broadcast_attempts).expect("broadcast");

        db::insert_unconfirmed_change_output(&conn, account_id, &view_key, &request_id, &test_wallet_output(3_000, 3))
            .expect("change");
        db::insert_displayed_transaction(&conn, &pending_send(account_id, 1, 0)).expect("displayed");

        drop(conn);
        SendFixture {
            pool,
            account_id,
            tx_id,
            request_id,
            input_output_id,
            _dir: dir,
        }
    }

    fn monitor_for(fixture: &SendFixture) -> TransactionMonitor {
        let state = MonitoringState::new();
        let conn = fixture.pool.get().expect("conn");
        state.initialize(&conn, fixture.account_id).expect("initialize");
        TransactionMonitor::new(state, 3, None)
    }

    async fn node_reporting(location: &str) -> MockServer {
        node_answering(serde_json::json!({
            "location": location,
            "mined_height": null,
            "mined_header_hash": null,
            "mined_timestamp": null,
        }))
        .await
    }

    async fn node_reporting_mined_at(height: u64) -> MockServer {
        node_answering(serde_json::json!({
            "location": "Mined",
            "mined_height": height,
            "mined_header_hash": vec![8u8; 32],
            "mined_timestamp": 1_700_000_000u64,
        }))
        .await
    }

    async fn node_answering(query_response: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(query_response))
            .mount(&server)
            .await;
        server
    }

    async fn failing_submissions(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(ResponseTemplate::new(500))
            .mount(server)
            .await;
    }

    fn set_status(fixture: &SendFixture, status: CompletedTransactionStatus) {
        let conn = fixture.pool.get().expect("conn");
        db::update_completed_transaction_status(&conn, fixture.tx_id, status).expect("status");
    }

    async fn expect_submissions(server: &MockServer, count: u64) {
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "accepted": true, "rejection_reason": "None", "is_synced": true },
                "error": null,
                "id": "1",
            })))
            .expect(count)
            .mount(server)
            .await;
    }

    fn client(server: &MockServer) -> WalletHttpClient {
        WalletHttpClient::new(server.uri().parse().expect("url")).expect("client")
    }

    fn completed(fixture: &SendFixture) -> CompletedTransaction {
        let conn = fixture.pool.get().expect("conn");
        db::get_completed_transaction_by_id(&conn, fixture.tx_id)
            .expect("query")
            .expect("exists")
    }

    /// The input's status and whether it is still locked to a request.
    fn input_state(fixture: &SendFixture) -> (String, bool) {
        let conn = fixture.pool.get().expect("conn");
        conn.query_row(
            "SELECT status, locked_by_request_id FROM outputs WHERE id = :id",
            named_params! { ":id": fixture.input_output_id },
            |row| Ok((row.get(0)?, row.get::<_, Option<String>>(1)?.is_some())),
        )
        .expect("input")
    }

    /// The change row's status and whether it is soft-deleted.
    fn change_state(fixture: &SendFixture) -> (String, bool) {
        let conn = fixture.pool.get().expect("conn");
        conn.query_row(
            "SELECT status, deleted_at FROM outputs WHERE created_by_request_id = :req",
            named_params! { ":req": fixture.request_id },
            |row| Ok((row.get(0)?, row.get::<_, Option<String>>(1)?.is_some())),
        )
        .expect("change")
    }

    #[tokio::test]
    async fn a_broadcast_transaction_in_the_mempool_is_left_alone() {
        let fixture = send_fixture("in_mempool.db", 1);
        let server = node_reporting("InMempool").await;
        expect_submissions(&server, 0).await;

        let result = monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("monitor");

        let completed = completed(&fixture);
        assert_eq!(completed.status, CompletedTransactionStatus::Broadcast);
        assert_eq!(completed.broadcast_attempts, 1);
        assert!(result.wallet_events.is_empty());
    }

    #[tokio::test]
    async fn a_broadcast_transaction_dropped_from_the_mempool_is_rebroadcast() {
        let fixture = send_fixture("not_stored.db", 1);
        let server = node_reporting("NotStored").await;
        expect_submissions(&server, 1).await;

        let result = monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("monitor");

        let completed = completed(&fixture);
        assert_eq!(completed.status, CompletedTransactionStatus::Broadcast);
        assert_eq!(completed.broadcast_attempts, 0, "an accepted broadcast does not count");
        assert!(
            result
                .wallet_events
                .iter()
                .any(|e| matches!(e.event_type, WalletEventType::TransactionBroadcast { .. }))
        );
    }

    #[tokio::test]
    async fn a_stalled_transaction_is_not_rejected_and_waits_before_the_next_try() {
        // The node has not accepted it MAX_BROADCAST_ATTEMPTS times in a row, the
        // last try just now.
        let fixture = send_fixture("stalled.db", MAX_BROADCAST_ATTEMPTS);
        let server = node_reporting("NotStored").await;
        expect_submissions(&server, 0).await;

        let result = monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("monitor");

        let completed = completed(&fixture);
        assert_eq!(completed.status, CompletedTransactionStatus::Broadcast);
        assert_eq!(completed.broadcast_attempts, MAX_BROADCAST_ATTEMPTS);
        assert_eq!(input_state(&fixture), ("LOCKED".to_string(), true));
        assert_eq!(change_state(&fixture), ("UNCONFIRMED".to_string(), false));
        let conn = fixture.pool.get().expect("conn");
        let displayed = get_displayed_transaction_by_id(&conn, &fixture.tx_id.to_string())
            .expect("query")
            .expect("displayed");
        assert_ne!(displayed.status, TransactionDisplayStatus::Rejected);
        assert!(
            !result
                .wallet_events
                .iter()
                .any(|e| matches!(e.event_type, WalletEventType::TransactionRejected { .. }))
        );
    }

    #[tokio::test]
    async fn a_stalled_transaction_is_tried_again_after_the_back_off() {
        let fixture = send_fixture("stalled_retry.db", MAX_BROADCAST_ATTEMPTS);
        {
            let conn = fixture.pool.get().expect("conn");
            conn.execute(
                "UPDATE completed_transactions SET updated_at = :then",
                named_params! { ":then": Utc::now() - chrono::Duration::hours(2) },
            )
            .expect("age the last try");
        }
        let server = node_reporting("NotStored").await;
        expect_submissions(&server, 1).await;

        monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("monitor");

        // Accepted this time: no longer stalled.
        let completed = completed(&fixture);
        assert_eq!(completed.status, CompletedTransactionStatus::Broadcast);
        assert_eq!(completed.broadcast_attempts, 0);
    }

    #[tokio::test]
    async fn a_send_the_node_keeps_refusing_becomes_stalled_with_an_event() {
        let fixture = send_fixture("becomes_stalled.db", MAX_BROADCAST_ATTEMPTS - 1);
        let server = node_reporting("NotStored").await;
        submissions_answered(&server, refused_with("FeeTooLow")).await;

        let result = monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("monitor");

        let completed = completed(&fixture);
        assert_eq!(completed.status, CompletedTransactionStatus::Broadcast);
        assert_eq!(completed.broadcast_attempts, MAX_BROADCAST_ATTEMPTS);
        assert_eq!(input_state(&fixture), ("LOCKED".to_string(), true));
        assert!(result.wallet_events.iter().any(|e| matches!(
            &e.event_type,
            WalletEventType::TransactionStalled { tx_id, failed_broadcast_attempts, node_reason }
                if *tx_id == fixture.tx_id
                    && *failed_broadcast_attempts == MAX_BROADCAST_ATTEMPTS
                    && node_reason.as_deref().is_some_and(|r| r.to_lowercase().contains("fee"))
        )));
        let conn = fixture.pool.get().expect("conn");
        let kept = db::get_last_broadcast_error(&conn, fixture.tx_id).expect("query");
        assert!(
            kept.is_some_and(|r| r.to_lowercase().contains("fee")),
            "the node's answer is kept"
        );
        let stored = db::get_events_by_account_id(&conn, fixture.account_id, 10, 0).expect("events");
        assert!(stored.iter().any(|e| e.event_type == "TransactionStalled"));
    }

    #[tokio::test]
    async fn an_accepted_rebroadcast_after_abandon_emits_a_warning_event() {
        let fixture = send_fixture("accepted_after_abandon.db", 1);
        let server = node_reporting("NotStored").await;
        let pool = fixture.pool.clone();
        let tx_id = fixture.tx_id;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(move |_: &wiremock::Request| {
                let conn = pool.get().expect("conn");
                db::mark_completed_transaction_as_rejected(
                    &conn,
                    tx_id,
                    crate::transactions::abandon::ABANDONED_REASON,
                )
                .expect("abandon during request");
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "result": { "accepted": true, "rejection_reason": "None", "is_synced": true },
                    "error": null,
                    "id": "1",
                }))
            })
            .expect(1)
            .mount(&server)
            .await;

        let result = monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("monitor");
        assert_eq!(completed(&fixture).status, CompletedTransactionStatus::Rejected);
        assert!(result.wallet_events.iter().any(|event| matches!(
            event.event_type,
            WalletEventType::TransactionAcceptedAfterAbandon { tx_id: warned } if warned == fixture.tx_id
        )));
        let conn = fixture.pool.get().expect("conn");
        let events = db::get_events_by_account_id(&conn, fixture.account_id, 10, 0).expect("events");
        assert!(
            events
                .iter()
                .any(|event| event.event_type == "TransactionAcceptedAfterAbandon")
        );
    }

    #[tokio::test]
    async fn a_refused_rebroadcast_after_abandon_does_not_stall() {
        let fixture = send_fixture("refused_after_abandon.db", MAX_BROADCAST_ATTEMPTS - 1);
        let server = node_reporting("NotStored").await;
        let pool = fixture.pool.clone();
        let tx_id = fixture.tx_id;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(move |_: &wiremock::Request| {
                let conn = pool.get().expect("conn");
                db::mark_completed_transaction_as_rejected(
                    &conn,
                    tx_id,
                    crate::transactions::abandon::ABANDONED_REASON,
                )
                .expect("abandon during request");
                ResponseTemplate::new(200).set_body_json(refused_with("FeeTooLow"))
            })
            .expect(1)
            .mount(&server)
            .await;

        let result = monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("monitor");
        let completed = completed(&fixture);
        assert_eq!(completed.status, CompletedTransactionStatus::Rejected);
        assert_eq!(completed.broadcast_attempts, MAX_BROADCAST_ATTEMPTS - 1);
        assert!(
            !result
                .wallet_events
                .iter()
                .any(|event| matches!(event.event_type, WalletEventType::TransactionStalled { .. }))
        );
    }

    #[tokio::test]
    async fn a_successful_rebroadcast_does_not_use_up_the_attempts() {
        let fixture = send_fixture("accepted_near_cap.db", MAX_BROADCAST_ATTEMPTS - 1);
        let server = node_reporting("NotStored").await;
        expect_submissions(&server, 1).await;

        monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("monitor");

        assert_eq!(completed(&fixture).broadcast_attempts, 0);
    }

    #[tokio::test]
    async fn a_transaction_the_node_reports_mined_above_the_scanned_height_is_left_to_the_scan() {
        let fixture = send_fixture("mined_above.db", 1);
        let server = node_reporting_mined_at(101).await;
        expect_submissions(&server, 0).await;

        let result = monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("monitor");

        let completed = completed(&fixture);
        assert_eq!(completed.status, CompletedTransactionStatus::Broadcast);
        assert_eq!(completed.mined_height, None);
        assert!(result.wallet_events.is_empty());
    }

    #[tokio::test]
    async fn a_transaction_reported_mined_without_a_height_is_left_to_the_scan() {
        let fixture = send_fixture("mined_no_height.db", 1);
        let server = node_reporting("Mined").await;
        expect_submissions(&server, 0).await;

        monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("monitor");

        assert_eq!(completed(&fixture).status, CompletedTransactionStatus::Broadcast);
    }

    #[tokio::test]
    async fn a_transaction_mined_in_a_block_the_scan_already_passed_is_marked_mined() {
        let fixture = send_fixture("mined_below.db", 1);
        let server = node_reporting_mined_at(100).await;
        expect_submissions(&server, 0).await;

        let result = monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("monitor");

        let completed = completed(&fixture);
        assert_eq!(completed.status, CompletedTransactionStatus::MinedUnconfirmed);
        assert_eq!(completed.mined_height, Some(100));
        assert_eq!(completed.mined_block_hash, Some(vec![8u8; 32]));
        assert!(result.wallet_events.iter().any(|e| matches!(
            e.event_type,
            WalletEventType::TransactionUnconfirmed { tx_id, mined_height: 100, confirmations: 0 } if tx_id == fixture.tx_id
        )));
        let conn = fixture.pool.get().expect("conn");
        let stored = db::get_events_by_account_id(&conn, fixture.account_id, 10, 0).expect("events");
        assert!(stored.iter().any(|e| e.event_type == "TransactionUnconfirmed"));
    }

    #[tokio::test]
    async fn a_failed_submission_of_a_dropped_transaction_leaves_it_unchanged() {
        let fixture = send_fixture("submit_fails_broadcast.db", 1);
        let server = node_reporting("NotStored").await;
        failing_submissions(&server).await;

        monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("a node failure does not fail the pass");

        let completed = completed(&fixture);
        assert_eq!(completed.status, CompletedTransactionStatus::Broadcast);
        assert_eq!(completed.broadcast_attempts, 1);
        assert_eq!(input_state(&fixture), ("LOCKED".to_string(), true));
        assert_eq!(change_state(&fixture), ("UNCONFIRMED".to_string(), false));
    }

    #[tokio::test]
    async fn a_failed_rebroadcast_of_a_completed_transaction_leaves_it_unchanged() {
        let fixture = send_fixture("submit_fails_completed.db", 1);
        set_status(&fixture, CompletedTransactionStatus::Completed);
        let server = MockServer::start().await;
        failing_submissions(&server).await;

        monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("a node failure does not fail the pass");

        let completed = completed(&fixture);
        assert_eq!(completed.status, CompletedTransactionStatus::Completed);
        assert_eq!(completed.broadcast_attempts, 1);
        assert_eq!(input_state(&fixture), ("LOCKED".to_string(), true));
        assert_eq!(change_state(&fixture), ("UNCONFIRMED".to_string(), false));
    }

    #[tokio::test]
    async fn an_undecodable_stored_transaction_is_skipped_not_fatal() {
        let fixture = send_fixture("undecodable.db", 1);
        {
            let conn = fixture.pool.get().expect("conn");
            conn.execute("UPDATE completed_transactions SET serialized_transaction = x'00ff'", [])
                .expect("corrupt");
        }
        // No mocks: a request for the undecodable transaction would fail the test.
        let server = MockServer::start().await;

        monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("the monitor pass still succeeds");
        assert_eq!(completed(&fixture).status, CompletedTransactionStatus::Broadcast);
        assert!(server.received_requests().await.unwrap_or_default().is_empty());
    }

    /// A transaction serialized by tari 6.0.1-pre.2 (before the 6.2.0-pre.1 bump),
    /// built and signed by that release's `TransactionBuilder`. Rows written by
    /// earlier releases must still decode, or neither the scan nor the monitor
    /// can recognise those sends.
    #[test]
    fn a_transaction_stored_by_tari_6_0_1_pre_2_still_decodes() {
        let stored = include_bytes!("test_data/transaction_v6_0_1_pre_2.json");
        let transaction: Transaction = serde_json::from_slice(stored).expect("decodes under the current tari");
        assert_eq!(transaction.body().inputs().len(), 3);
        assert_eq!(transaction.body().outputs().len(), 2);
        assert_eq!(transaction.body().kernels().len(), 1);
        for input in transaction.body().inputs() {
            assert_ne!(input.output_hash(), FixedHash::zero());
        }
        // Re-encoding gives the same document, so nothing was dropped or renamed.
        // The only difference is `body.sorted`, an in-memory flag that is not
        // read back from JSON.
        let mut original: serde_json::Value = serde_json::from_slice(stored).expect("json");
        let mut reencoded = serde_json::to_value(&transaction).expect("encode");
        for document in [&mut original, &mut reencoded] {
            if let Some(body) = document.get_mut("body").and_then(|b| b.as_object_mut()) {
                body.remove("sorted");
            }
        }
        assert_eq!(original, reencoded);
    }

    #[tokio::test]
    async fn a_mined_transaction_is_confirmed_at_depth_without_asking_the_node() {
        let fixture = send_fixture("confirm.db", 1);
        {
            let conn = fixture.pool.get().expect("conn");
            db::mark_completed_transaction_as_mined_unconfirmed(&conn, fixture.tx_id, 100, &[7u8; 32]).expect("mined");
        }
        // No mocks: any request to the node fails the test.
        let server = MockServer::start().await;
        let monitor = monitor_for(&fixture);

        monitor
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 102)
            .await
            .expect("monitor");
        assert_eq!(completed(&fixture).status, CompletedTransactionStatus::MinedUnconfirmed);

        let result = monitor
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 103)
            .await
            .expect("monitor");
        let completed = completed(&fixture);
        assert_eq!(completed.status, CompletedTransactionStatus::MinedConfirmed);
        assert!(completed.sent_payref.is_some());
        assert!(
            result
                .wallet_events
                .iter()
                .any(|e| matches!(e.event_type, WalletEventType::TransactionConfirmed { .. }))
        );
        assert!(server.received_requests().await.unwrap_or_default().is_empty());
    }

    #[tokio::test]
    async fn a_failed_mempool_query_leaves_the_transaction_unchanged() {
        let fixture = send_fixture("node_down.db", 1);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/transactions"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("a node failure does not fail the pass");
        let completed = completed(&fixture);
        assert_eq!(completed.status, CompletedTransactionStatus::Broadcast);
        assert_eq!(completed.broadcast_attempts, 1);
    }

    /// Records a second `Broadcast` send on the fixture's account whose kernel
    /// signature is `[sig_byte; 32]`, so the node can answer for it separately.
    fn record_second_send(fixture: &SendFixture, sig_byte: u8) -> TxId {
        let conn = fixture.pool.get().expect("conn");
        let binding = IdempotencyBinding::new(
            Some("second".to_string()),
            IdempotencyOperation::SendTransaction,
            RequestFingerprint::new(IdempotencyOperation::SendTransaction),
        );
        let request_id = db::create_pending_transaction(
            &conn,
            "second",
            &binding,
            fixture.account_id,
            true,
            MicroMinotari(0),
            MicroMinotari(0),
            MicroMinotari(0),
            Utc::now() + chrono::Duration::hours(1),
        )
        .expect("pending transaction");

        let input = test_wallet_output(10_000, 20);
        let input_id = db::insert_output(
            &conn,
            fixture.account_id,
            &PrivateKey::default(),
            input.output_hash().to_vec(),
            &input,
            10,
            &FixedHash::from([10u8; 32]),
            1_700_000_000,
            None,
            None,
            FixedHash::zero(),
            false,
        )
        .expect("input");
        db::lock_output(&conn, input_id, &request_id, Utc::now()).expect("lock");

        let kernel = TransactionKernel {
            excess_sig: CompressedSignature::new(
                CompressedPublicKey::new(&[sig_byte; 32]),
                PrivateKey::from_canonical_bytes(&[sig_byte; 32]).expect("canonical scalar"),
            ),
            ..Default::default()
        };
        let transaction = Transaction::new(
            Vec::new(),
            Vec::new(),
            vec![kernel],
            PrivateKey::default(),
            PrivateKey::default(),
        );
        let tx_id = TxId::from(2u64);
        db::create_completed_transaction(
            &conn,
            fixture.account_id,
            &request_id,
            &[],
            &serde_json::to_vec(&transaction).expect("serialize"),
            None,
            tx_id,
        )
        .expect("completed");
        mark_completed_transaction_as_broadcasted(&conn, tx_id, 1).expect("broadcast");
        tx_id
    }

    #[tokio::test]
    async fn a_node_error_for_one_transaction_does_not_stop_the_others() {
        let fixture = send_fixture("two_sends.db", 1);
        let second = record_second_send(&fixture, 2);

        let server = MockServer::start().await;
        // The node answers for the second send: it is no longer in the mempool.
        Mock::given(method("GET"))
            .and(path("/transactions"))
            .and(query_param("excess_sig_sig", hex::encode([2u8; 32])))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "location": "NotStored",
                "mined_height": null,
                "mined_header_hash": null,
                "mined_timestamp": null,
            })))
            .with_priority(1)
            .mount(&server)
            .await;
        // Every other query (the first send) fails.
        Mock::given(method("GET"))
            .and(path("/transactions"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        expect_submissions(&server, 1).await;

        monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("a node failure does not fail the pass");

        assert_eq!(
            completed(&fixture).broadcast_attempts,
            1,
            "the failed one is left as it was"
        );
        let conn = fixture.pool.get().expect("conn");
        let second = db::get_completed_transaction_by_id(&conn, second)
            .expect("query")
            .expect("exists");
        assert_eq!(second.status, CompletedTransactionStatus::Broadcast);
        assert_eq!(
            second.broadcast_attempts, 0,
            "the other one is still rebroadcast (and accepted)"
        );
    }

    #[tokio::test]
    async fn a_malformed_block_hash_from_the_node_leaves_the_transaction_to_the_scan() {
        let fixture = send_fixture("bad_node_hash.db", 1);
        let server = node_answering(serde_json::json!({
            "location": "Mined",
            "mined_height": 100,
            "mined_header_hash": [1, 2, 3, 4, 5],
            "mined_timestamp": 1_700_000_000u64,
        }))
        .await;
        expect_submissions(&server, 0).await;

        monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("monitor");

        let completed = completed(&fixture);
        assert_eq!(completed.status, CompletedTransactionStatus::Broadcast);
        assert_eq!(completed.mined_block_hash, None);
    }

    #[tokio::test]
    async fn a_mined_row_with_a_malformed_block_hash_is_skipped_and_others_still_confirm() {
        let fixture = send_fixture("bad_row_hash.db", 1);
        let second = record_second_send(&fixture, 2);
        {
            let conn = fixture.pool.get().expect("conn");
            db::mark_completed_transaction_as_mined_unconfirmed(&conn, fixture.tx_id, 100, &[7u8; 32]).expect("mined");
            db::mark_completed_transaction_as_mined_unconfirmed(&conn, second, 100, &[1, 2, 3, 4, 5])
                .expect("mined with a bad hash");
        }
        // No mocks: both rows are mined, so the node must not be asked.
        let server = MockServer::start().await;

        monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 103)
            .await
            .expect("a malformed row does not fail the pass");

        assert_eq!(completed(&fixture).status, CompletedTransactionStatus::MinedConfirmed);
        let conn = fixture.pool.get().expect("conn");
        let second = db::get_completed_transaction_by_id(&conn, second)
            .expect("query")
            .expect("exists");
        assert_eq!(second.status, CompletedTransactionStatus::MinedUnconfirmed);
    }

    fn record_scanned_block(fixture: &SendFixture, height: i64, hash: [u8; 32]) {
        let conn = fixture.pool.get().expect("conn");
        db::insert_scanned_tip_block(&conn, fixture.account_id, height, &hash).expect("tip");
    }

    #[tokio::test]
    async fn a_mined_report_matching_the_scanned_block_is_accepted() {
        let fixture = send_fixture("mined_matching_tip.db", 1);
        record_scanned_block(&fixture, 100, [8u8; 32]);
        let server = node_reporting_mined_at(100).await;

        monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("monitor");

        assert_eq!(completed(&fixture).status, CompletedTransactionStatus::MinedUnconfirmed);
    }

    #[tokio::test]
    async fn a_mined_report_for_a_block_the_wallet_did_not_scan_is_left_to_the_scan() {
        let fixture = send_fixture("mined_other_block.db", 1);
        // The wallet scanned a different block at that height.
        record_scanned_block(&fixture, 100, [5u8; 32]);
        let server = node_reporting_mined_at(100).await;

        monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("monitor");

        let completed = completed(&fixture);
        assert_eq!(completed.status, CompletedTransactionStatus::Broadcast);
        assert_eq!(completed.mined_height, None);
    }

    #[tokio::test]
    async fn a_stall_that_fails_part_way_leaves_nothing_half_done() {
        // Make the last write of the stall (its event) fail. The attempt count
        // and the event go in together, so neither is recorded.
        let fixture = send_fixture("stall_atomic.db", MAX_BROADCAST_ATTEMPTS - 1);
        {
            let conn = fixture.pool.get().expect("conn");
            conn.execute_batch(
                "CREATE TRIGGER fail_events BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )
            .expect("trigger");
        }
        let server = node_reporting("NotStored").await;
        submissions_answered(&server, refused_with("FeeTooLow")).await;

        let error = monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await;
        assert!(error.is_err(), "a database failure fails the pass");

        let completed = completed(&fixture);
        assert_eq!(completed.status, CompletedTransactionStatus::Broadcast);
        assert_eq!(completed.broadcast_attempts, MAX_BROADCAST_ATTEMPTS - 1);
        assert_eq!(input_state(&fixture), ("LOCKED".to_string(), true));
        assert_eq!(change_state(&fixture), ("UNCONFIRMED".to_string(), false));
    }

    async fn submissions_answered(server: &MockServer, body: serde_json::Value) {
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(server)
            .await;
    }

    fn refused_with(reason: &str) -> serde_json::Value {
        serde_json::json!({
            "result": { "accepted": false, "rejection_reason": reason, "is_synced": true },
            "error": null,
            "id": "1",
        })
    }

    #[tokio::test]
    async fn a_transient_refusal_counts_an_attempt_and_keeps_the_send() {
        for reason in ["FeeTooLow", "Orphan", "TimeLocked", "ValidatorNodeSlotTaken"] {
            let fixture = send_fixture(&format!("transient_{reason}.db"), 1);
            let server = node_reporting("NotStored").await;
            submissions_answered(&server, refused_with(reason)).await;

            monitor_for(&fixture)
                .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
                .await
                .expect("monitor");

            let completed = completed(&fixture);
            assert_eq!(completed.status, CompletedTransactionStatus::Broadcast, "{reason}");
            assert_eq!(completed.broadcast_attempts, 2, "{reason}");
            assert_eq!(input_state(&fixture), ("LOCKED".to_string(), true), "{reason}");
            assert_eq!(change_state(&fixture), ("UNCONFIRMED".to_string(), false), "{reason}");
        }
    }

    #[tokio::test]
    async fn an_error_answer_to_a_completed_rebroadcast_counts_an_attempt_and_keeps_the_send() {
        let fixture = send_fixture("error_answer.db", 1);
        set_status(&fixture, CompletedTransactionStatus::Completed);
        let server = MockServer::start().await;
        submissions_answered(
            &server,
            serde_json::json!({ "result": null, "error": "mempool full", "id": "1" }),
        )
        .await;

        monitor_for(&fixture)
            .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
            .await
            .expect("monitor");

        let completed = completed(&fixture);
        assert_eq!(completed.status, CompletedTransactionStatus::Completed);
        assert_eq!(completed.broadcast_attempts, 2);
        assert_eq!(input_state(&fixture), ("LOCKED".to_string(), true));
    }

    #[tokio::test]
    async fn a_double_spend_or_failed_validation_refusal_does_not_reject_the_send() {
        // Only the wallet's own scan may reject a send; the node's word does not.
        for reason in ["DoubleSpend", "ValidationFailed"] {
            let fixture = send_fixture(&format!("refused_{reason}.db"), 1);
            let server = node_reporting("NotStored").await;
            submissions_answered(&server, refused_with(reason)).await;

            monitor_for(&fixture)
                .monitor_if_needed(&client(&server), &fixture.pool, fixture.account_id, 100)
                .await
                .expect("monitor");

            let completed = completed(&fixture);
            assert_eq!(completed.status, CompletedTransactionStatus::Broadcast, "{reason}");
            assert_eq!(completed.broadcast_attempts, 2, "{reason}");
            assert_eq!(input_state(&fixture), ("LOCKED".to_string(), true), "{reason}");
            assert_eq!(change_state(&fixture), ("UNCONFIRMED".to_string(), false), "{reason}");
        }
    }
}

#[cfg(test)]
mod stalled_event_tests {
    use crate::models::WalletEventType;

    #[test]
    fn a_stalled_event_stored_without_a_reason_still_reads() {
        // Events written before `node_reason` existed have no such field.
        let stored = r#"{"TransactionStalled":{"tx_id":7,"failed_broadcast_attempts":10}}"#;
        let event: WalletEventType = serde_json::from_str(stored).expect("old event reads");
        assert!(matches!(
            event,
            WalletEventType::TransactionStalled {
                failed_broadcast_attempts: 10,
                node_reason: None,
                ..
            }
        ));
    }
}
