//! High-level transaction management and broadcasting.
//!
//! This module provides the [`TransactionSender`] which orchestrates the complete
//! transaction lifecycle from creation through broadcast. It handles:
//!
//! - Transaction validation and idempotency
//! - UTXO selection and locking
//! - Transaction building and preparation for signing
//! - Broadcasting signed transactions to the network
//! - Creating displayable transaction records for UI
//!
//! # Transaction Flow
//!
//! The typical transaction flow using `TransactionSender` is:
//!
//! 1. Create a `TransactionSender` for an account
//! 2. Call [`start_new_transaction`](TransactionSender::start_new_transaction) to prepare an unsigned transaction
//! 3. Sign the transaction externally (e.g., with a hardware wallet)
//! 4. Call [`finalize_transaction_and_broadcast`](TransactionSender::finalize_transaction_and_broadcast) to submit
//!
//! # Idempotency
//!
//! Transactions are identified by idempotency keys, allowing safe retries.
//! If a transaction with the same idempotency key exists, the existing
//! transaction data is returned rather than creating a duplicate.
//!
//! A key only earns that replay when it was issued for this same request; a key
//! replayed with different parameters, or one whose transaction is completed,
//! expired or cancelled, is refused as an
//! [`IdempotencyConflict`](crate::transactions::idempotency::IdempotencyConflict).
//! The check runs inside the same `BEGIN IMMEDIATE` transaction that takes the
//! reservation, so a concurrent retry is served the original *reservation*
//! rather than losing a race to the unique-key index.
//!
//! It is not served the original unsigned transaction. Nothing persists that, so
//! a replay rebuilds one with a fresh `TxId` over the same inputs, and two
//! callers can end up holding structurally different transactions spending the
//! identical UTXOs. Only one of them may broadcast:
//! [`finalize_transaction_and_broadcast`](TransactionSender::finalize_transaction_and_broadcast)
//! claims the reservation with a conditional update and refuses whoever did not
//! win it.
//!
//! # Example
//!
//! ```rust,ignore
//! use minotari::transactions::manager::TransactionSender;
//!
//! // Create sender for an account
//! let mut sender = TransactionSender::new(
//!     db_pool,
//!     "my_account".to_string(),
//!     password,
//!     Network::MainNet,
//! ).await?;
//!
//! // Start a new transaction
//! let unsigned = sender.start_new_transaction(
//!     "idempotency-key-123".to_string(),
//!     recipient,
//!     300, // 5 minute lock
//! ).await?;
//!
//! // Sign externally...
//! let signed = sign_transaction(unsigned)?;
//!
//! // Broadcast to network
//! let sent = sender.finalize_transaction_and_broadcast(
//!     signed,
//!     grpc_address,
//! ).await?;
//! if !sent.accepted_by_node {
//!     // Recorded and pending: it will be rebroadcast; do not send it again.
//! }
//! ```

use anyhow::anyhow;
use chrono::Utc;
use log::{error, info, warn};
use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use tari_common::configuration::Network;
use tari_common_types::types::FixedHash;
use tari_common_types::{
    tari_address::{TariAddress, TariAddressFeatures},
    transaction::TxId,
};
use tari_transaction_components::offline_signing::models::SignedTransaction;
use tari_transaction_components::rpc::models::{TxSubmissionRejectionReason, TxSubmissionResponse};
use tari_transaction_components::transaction_components::OutputType;
use tari_transaction_components::{
    MicroMinotari, TransactionBuilder,
    consensus::ConsensusConstantsBuilder,
    key_manager::{KeyManager, TransactionKeyManagerInterface},
    offline_signing::{
        PaymentRecipient,
        models::{PrepareOneSidedTransactionForSigningResult, SignedOneSidedTransactionResult},
        prepare_one_sided_transaction_for_signing,
    },
    transaction_components::{OutputFeatures, WalletOutput},
};
use tari_utilities::ByteArray;

use crate::db::DbWalletOutput;
use crate::models::OutputStatus;
use crate::transactions::TransactionOutput;
use crate::{
    db::{self, AccountRow, SqlitePool, WalletDbError},
    http::WalletHttpClient,
    log::mask_amount,
    models::PendingTransactionStatus,
    transactions::{
        displayed_transaction_processor::{
            DisplayedTransaction, DisplayedTransactionBuilder, TransactionDirection, TransactionDisplayStatus,
            TransactionInput, TransactionSource,
        },
        fund_locker::{check_replay_allowed, lock_expiry_at, validate_fee_per_gram},
        idempotency::{IdempotencyBinding, IdempotencyConflict, IdempotencyOperation, RequestFingerprint},
        input_selector::{InputSelector, UtxoSelection, map_change_required_error},
        one_sided_transaction::{Recipient, check_memos_and_estimate_output_size, recipient_memo},
    },
};
use zeroize::Zeroizing;

/// Whether this send took the reservation it is working on, or replayed onto one
/// an earlier request took.
///
/// A replay does not own those UTXOs. Expiring the reservation and unlocking
/// them on failure would free inputs the request that created it is still
/// holding an unsigned transaction over — and, because the unlocker only ever
/// revisits `Pending` rows, nothing would put them back.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Reservation {
    /// This send created the pending transaction and owns its UTXOs.
    #[default]
    Created,
    /// This send replayed an idempotency key onto a reservation someone else took.
    Replayed,
}

/// Represents a transaction being processed through the send flow.
///
/// `ProcessedTransaction` tracks the state of a transaction as it moves
/// through the creation, signing, and broadcast phases. It holds the
/// idempotency key, recipient details, and selected UTXOs.
///
/// # Lifecycle
///
/// 1. Created with [`new`](Self::new) when starting a transaction
/// 2. Updated with transaction ID once pending transaction is created
/// 3. UTXOs are populated during selection
/// 4. Used to build the final [`DisplayedTransaction`] after broadcast
#[derive(Default)]
pub struct ProcessedTransaction {
    /// The database ID of the pending transaction (set after creation).
    id: Option<String>,
    /// Unique key for idempotent transaction handling.
    idempotency_key: String,
    /// The recipient of this transaction.
    recipient: Recipient,
    /// How long to lock UTXOs before they expire.
    seconds_to_lock_utxos: u64,
    /// The UTXOs selected for this transaction.
    selected_utxos: Vec<DbWalletOutput>,
    /// Whether this send took the reservation or replayed onto an existing one.
    reservation: Reservation,
}

impl ProcessedTransaction {
    /// Creates a new `ProcessedTransaction` with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `id` - Optional existing transaction ID (for resuming)
    /// * `idempotency_key` - Unique key for this transaction
    /// * `recipient` - The transaction recipient
    /// * `seconds_to_lock_utxos` - Lock duration for selected UTXOs
    pub fn new(id: Option<String>, idempotency_key: String, recipient: Recipient, seconds_to_lock_utxos: u64) -> Self {
        Self {
            id,
            idempotency_key,
            recipient,
            seconds_to_lock_utxos,
            selected_utxos: Vec::new(),
            reservation: Reservation::Created,
        }
    }

    /// Whether this send may expire the reservation and release its UTXOs.
    ///
    /// Only the request that created a reservation may tear it down; see
    /// [`Reservation`].
    fn owns_reservation(&self) -> bool {
        self.reservation == Reservation::Created
    }

    /// Returns the transaction ID, or an empty string if not yet assigned.
    pub fn id(&self) -> &str {
        self.id.as_deref().unwrap_or("")
    }

    /// Updates the transaction ID after the pending transaction is created.
    pub fn update_id(&mut self, id: String) {
        self.id = Some(id);
    }

    /// Binds this transaction's idempotency key to the payment it describes.
    ///
    /// Without the recipient in the fingerprint, replaying the key with a
    /// different address would return this transaction's reserved UTXOs and
    /// build a payment to whoever the replay named.
    fn idempotency_binding(&self, account_id: i64) -> IdempotencyBinding {
        let operation = IdempotencyOperation::SendTransaction;
        IdempotencyBinding::new(
            Some(self.idempotency_key.clone()),
            operation,
            RequestFingerprint::new(operation)
                .field("account_id", account_id.to_le_bytes())
                .field("recipient_address", self.recipient.address.to_base58())
                .field("recipient_amount", self.recipient.amount.as_u64().to_le_bytes())
                .optional_field("recipient_payment_id", self.recipient.payment_id.as_deref())
                .field("seconds_to_lock_utxos", self.seconds_to_lock_utxos.to_le_bytes()),
        )
    }
}

/// Orchestrates the complete transaction send flow.
///
/// `TransactionSender` handles the full lifecycle of sending a transaction:
/// validation, UTXO selection, transaction building, and broadcasting.
/// It maintains state across the multi-step process and supports idempotent
/// operations for safe retries.
///
/// # Architecture
///
/// The sender coordinates several components:
/// - [`InputSelector`]: Selects UTXOs and calculates fees
/// - Database: Stores pending transactions and locks
/// - [`WalletHttpClient`]: Broadcasts to the network
///
/// # Thread Safety
///
/// `TransactionSender` is not thread-safe due to mutable internal state.
/// Use a single sender per transaction flow.
///
/// # Example
///
/// ```rust,ignore
/// let mut sender = TransactionSender::new(
///     db_pool,
///     "account_name".to_string(),
///     password,
///     Network::MainNet,
/// ).await?;
///
/// // Prepare unsigned transaction
/// let unsigned = sender.start_new_transaction(
///     idempotency_key,
///     recipient,
///     lock_duration,
/// ).await?;
///
/// // After signing externally...
/// let result = sender.finalize_transaction_and_broadcast(
///     signed,
///     grpc_address,
/// ).await?;
/// ```
pub struct TransactionSender {
    /// Database connection pool.
    pub db_pool: SqlitePool,
    /// The network for consensus rules.
    pub network: Network,
    /// The sender's account.
    pub account: AccountRow,
    /// Password for key manager access.
    pub password: Zeroizing<String>,
    /// The transaction currently being processed.
    pub processed_transactions: ProcessedTransaction,
    /// Fee rate for this transaction.
    pub fee_per_gram: MicroMinotari,
    pub confirmation_window: u64,
}

impl TransactionSender {
    /// Creates a new `TransactionSender` for the specified account.
    ///
    /// Loads the account from the database and initializes the sender
    /// with default fee settings.
    ///
    /// # Arguments
    ///
    /// * `db_pool` - SQLite connection pool
    /// * `account_name` - Name of the sending account
    /// * `password` - Password to decrypt the account's key manager
    /// * `network` - The Tari network (MainNet, TestNet, etc.)
    /// * `confirmation_window` - The confirmation window
    ///
    /// # Returns
    ///
    /// Returns a configured `TransactionSender` ready to process transactions.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Database connection fails
    /// - Account with the given name is not found
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let sender = TransactionSender::new(
    ///     db_pool,
    ///     "my_wallet".to_string(),
    ///     "secure_password".to_string(),
    ///     Network::MainNet,
    /// ).await?;
    /// ```
    pub fn new(
        db_pool: SqlitePool,
        account_name: String,
        password: Zeroizing<String>,
        network: Network,
        confirmation_window: u64,
    ) -> Result<Self, anyhow::Error> {
        let connection = db_pool.get()?;
        let account_of_processed_transaction: AccountRow = db::get_account_by_name(&connection, &account_name)?
            .ok_or_else(|| anyhow!("Account with name '{}' not found", account_name))?;

        Ok(Self {
            db_pool,
            network,
            account: account_of_processed_transaction,
            password,
            processed_transactions: ProcessedTransaction::default(),
            fee_per_gram: MicroMinotari(5),
            confirmation_window,
        })
    }

    /// Acquires a database connection from the pool.
    fn get_connection(&self) -> Result<PooledConnection<SqliteConnectionManager>, anyhow::Error> {
        self.db_pool
            .get()
            .map_err(|e| anyhow::anyhow!("Failed to acquire database connection: {}", e))
    }

    /// Checks what this sender can decide without reading the database.
    ///
    /// The idempotency key used to be checked here too, on its own connection.
    /// That read is now part of `create_or_find_pending_transaction`'s write
    /// transaction, because a check outside it can be overtaken between the read
    /// and the insert that acts on it.
    fn validate_transaction_creation_request(&self) -> Result<TariAddress, anyhow::Error> {
        validate_fee_per_gram(self.fee_per_gram)?;
        let sender_address = self.account.get_address(self.network, &self.password)?;
        if !sender_address
            .features()
            .contains(TariAddressFeatures::create_one_sided_only())
        {
            return Err(anyhow!("The sender address does not support one-sided transactions."));
        }

        Ok(sender_address)
    }

    /// Fails when this send's reservation has outlived its lock.
    ///
    /// A predicate only: it used to write the row to `Expired` here, before the
    /// caller's error handler had decided whether this send owns the reservation
    /// at all. A replay would then mark someone else's row `Expired` and, having
    /// no right to unlock it, leave it that way — and the unlocker only ever
    /// revisits `Pending` rows, so those UTXOs stayed locked for good. Leaving
    /// the write to `release_unclaimed_reservation` keeps status and unlock in
    /// one transaction and behind one ownership check.
    fn check_if_transaction_expired(
        &self,
        conn: &Connection,
        processed_transaction: &ProcessedTransaction,
    ) -> Result<(), anyhow::Error> {
        let is_expired = db::check_if_transaction_is_expired_by_idempotency_key(
            conn,
            &processed_transaction.idempotency_key,
            self.account.id,
        )?;

        if is_expired {
            return Err(anyhow!("The transaction has expired."));
        }

        Ok(())
    }

    /// Selects UTXOs covering the requested amount plus fees.
    ///
    /// Takes the connection from the caller rather than pulling a fresh one from
    /// the pool: the selection is only meaningful when it runs inside the same
    /// write transaction that goes on to lock the chosen outputs.
    fn create_utxo_selection(
        &self,
        connection: &Connection,
        processed_transaction: &ProcessedTransaction,
        estimated_output_size: Option<usize>,
    ) -> Result<UtxoSelection, anyhow::Error> {
        let amount = processed_transaction.recipient.amount;
        let num_outputs = 1;

        let input_selector = InputSelector::new(self.account.id, self.confirmation_window);
        let utxo_selection = input_selector.fetch_unspent_outputs(
            connection,
            amount,
            num_outputs,
            self.fee_per_gram,
            estimated_output_size,
        )?;
        Ok(utxo_selection)
    }

    /// Replays this request's idempotency key onto its reservation, or takes a
    /// fresh one.
    ///
    /// Both the idempotency read and the UTXO selection happen inside one
    /// `BEGIN IMMEDIATE` transaction. Reading the key outside it left a gap in
    /// which a concurrent request with the same key could commit its own row:
    /// both callers saw "no record", both fell through, and the loser hit the
    /// `UNIQUE (account_id, idempotency_key)` index and got a hard "already
    /// exists" instead of the replay a retry is entitled to.
    fn create_or_find_pending_transaction(
        &self,
        connection: &mut Connection,
        processed_transaction: &mut ProcessedTransaction,
        estimated_output_size: Option<usize>,
    ) -> Result<String, anyhow::Error> {
        // `seconds_to_lock_utxos` is untrusted (JSON body / CLI argument), so use
        // the checked helper: `Utc::now() + Duration::seconds(..)` panics on
        // overflow. See `MAX_SECONDS_TO_LOCK_UTXOS`.
        let expires_at = lock_expiry_at(Utc::now(), processed_transaction.seconds_to_lock_utxos)?;
        let binding = processed_transaction.idempotency_binding(self.account.id);
        let key = processed_transaction.idempotency_key.clone();

        // BEGIN IMMEDIATE takes the database's write lock before we look at any
        // row, so nothing else — another CLI process, the daemon's scan loop,
        // the unlocker — can claim this key or spend one of the selected UTXOs
        // between reading and writing. Without it the selection is a stale read
        // and `lock_output`'s conditional update loses the race.
        let transaction = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        // The key alone does not entitle this request to an existing
        // reservation: it must be the same operation with the same recipient and
        // amount, and the reservation must still be live. A completed or expired
        // key is refused here rather than surfacing later as a build failure on
        // a zero-input transaction.
        if let Some(record) =
            db::find_pending_transaction_record_by_idempotency_key(&transaction, &key, self.account.id)?
        {
            check_replay_allowed(&record, &binding, &key)?;
            processed_transaction.reservation = Reservation::Replayed;
            return Ok(record.id);
        }

        let utxo_selection = self.create_utxo_selection(&transaction, processed_transaction, estimated_output_size)?;

        let pending_tx_id = match db::create_pending_transaction(
            &transaction,
            &key,
            &binding,
            self.account.id,
            utxo_selection.requires_change_output,
            utxo_selection.total_value,
            utxo_selection.fee_without_change,
            utxo_selection.fee_with_change,
            expires_at,
        ) {
            Ok(pending_tx_id) => pending_tx_id,
            // The write lock above should have kept anyone else out, but if a
            // row for this key does exist the caller is still a retry and is
            // owed its reservation, not a bare "already exists".
            Err(WalletDbError::DuplicateEntry(_)) => {
                let record =
                    db::find_pending_transaction_record_by_idempotency_key(&transaction, &key, self.account.id)?
                        .ok_or_else(|| anyhow!("Idempotency key '{key}' collided with a row that cannot be read"))?;
                check_replay_allowed(&record, &binding, &key)?;
                processed_transaction.reservation = Reservation::Replayed;
                return Ok(record.id);
            },
            Err(e) => return Err(e.into()),
        };

        // A failed lock means the output is no longer ours to reserve; `?` skips
        // the commit below so the pending transaction and every lock taken so
        // far roll back together.
        for utxo in &utxo_selection.utxos {
            db::lock_output(&transaction, utxo.id, &pending_tx_id, expires_at)?;
        }

        transaction.commit()?;

        if processed_transaction.selected_utxos.is_empty() {
            processed_transaction.selected_utxos = utxo_selection.utxos.clone();
        }

        Ok(pending_tx_id)
    }

    /// Returns the builder together with the key manager it was built around: the payload the builder is handed to
    /// is signed with that same key manager, so both halves have to come from one call.
    fn prepare_transaction_builder(
        &self,
        locked_utxos: Vec<WalletOutput>,
    ) -> Result<(TransactionBuilder<KeyManager>, KeyManager), anyhow::Error> {
        let key_manager = self.account.get_key_manager(&self.password)?;
        let consensus_constants = ConsensusConstantsBuilder::new(self.network).build();
        let mut tx_builder = TransactionBuilder::new(consensus_constants, key_manager.clone(), self.network)?;

        tx_builder.with_fee_per_gram(self.fee_per_gram);
        // Every send carries a change output, so the wallet's scan can see it land.
        tx_builder.with_change_required();

        for utxo in &locked_utxos {
            tx_builder.with_input(utxo.clone())?;
        }

        Ok((tx_builder, key_manager))
    }

    /// Starts a new transaction and returns an unsigned transaction for signing.
    ///
    /// This method performs the complete preparation phase:
    /// 1. Validates the transaction request (idempotency, address capabilities)
    /// 2. Creates or finds an existing pending transaction
    /// 3. Selects and locks UTXOs
    /// 4. Builds the transaction for offline signing
    ///
    /// # Arguments
    ///
    /// * `idempotency_key` - Unique key for this transaction; retries with the
    ///   same key will return the existing transaction
    /// * `recipient` - The payment recipient details
    /// * `seconds_to_lock_utxo` - How long to lock the selected UTXOs
    ///
    /// # Returns
    ///
    /// Returns a [`PrepareOneSidedTransactionForSigningResult`] containing the
    /// unsigned transaction ready for external signing.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A completed transaction with the same idempotency key exists
    /// - The sender address does not support one-sided transactions
    /// - Insufficient funds are available
    /// - Transaction building fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let unsigned = sender.start_new_transaction(
    ///     "payment-123".to_string(),
    ///     Recipient {
    ///         address: recipient_address,
    ///         amount: MicroMinotari(1_000_000),
    ///         payment_id: Some("Invoice #456".to_string()),
    ///     },
    ///     300, // 5 minute lock
    /// ).await?;
    /// ```
    pub fn start_new_transaction(
        &mut self,
        idempotency_key: String,
        recipient: Recipient,
        seconds_to_lock_utxo: u64,
    ) -> Result<PrepareOneSidedTransactionForSigningResult, anyhow::Error> {
        info!(
            target: "audit",
            idempotency_key = idempotency_key.as_str(),
            amount = &*mask_amount(recipient.amount);
            "Starting new transaction"
        );
        // One connection for the whole flow. Taking a fresh one at each step instead meant a
        // single send held three at once — this one, another in
        // `create_or_find_pending_transaction`, a third in `create_pending_transaction` — so
        // concurrent senders deadlocked on a pool smaller than three times their number, each
        // holding connections it could not finish without one more.
        let mut connection = self.get_connection()?;

        let mut processed_transaction =
            ProcessedTransaction::new(None, idempotency_key, recipient.clone(), seconds_to_lock_utxo);

        let sender_address = self.validate_transaction_creation_request()?;
        // Selection has to charge for the memo this send will actually carry. Left at the
        // default, a long payment id is weight nobody reserved inputs for, and the send fails
        // at build time with the funds already locked. A payment id that cannot fit at all is
        // refused here, before anything is locked and outside the write lock.
        let estimated_output_size =
            check_memos_and_estimate_output_size(std::slice::from_ref(&recipient), &sender_address)?;

        let pending_transaction_id = self.create_or_find_pending_transaction(
            &mut connection,
            &mut processed_transaction,
            Some(estimated_output_size),
        )?;
        processed_transaction.update_id(pending_transaction_id);

        let result: Result<PrepareOneSidedTransactionForSigningResult, anyhow::Error> = (|| {
            let mut utxo_selection = processed_transaction.selected_utxos.clone();
            if utxo_selection.is_empty() {
                let db_utxo_selection = db::fetch_outputs_by_lock_request_id(&connection, processed_transaction.id())?;
                utxo_selection = db_utxo_selection;
            }
            let utxos = utxo_selection.into_iter().map(|db_out| db_out.output).collect();

            let (tx_builder, key_manager) = self.prepare_transaction_builder(utxos)?;

            let tx_id = TxId::new_random();

            let payment_id = recipient.memo()?;
            let output_features = OutputFeatures::default();

            let payment_recipient = PaymentRecipient {
                amount: recipient.amount,
                output_features: output_features.clone(),
                address: recipient.address.clone(),
                payment_id: recipient_memo(payment_id.clone(), &sender_address, &recipient.address)?,
            };

            let res = prepare_one_sided_transaction_for_signing(
                &key_manager,
                tx_id,
                tx_builder,
                &[payment_recipient],
                payment_id,
                sender_address,
            )
            .map_err(map_change_required_error)?;

            Ok(res)
        })();

        match result {
            Ok(res) => {
                self.processed_transactions = processed_transaction;
                Ok(res)
            },
            Err(e) => {
                warn!(target: "audit", error:% = e; "Transaction creation failed");
                // Only tear down a reservation this send actually took. A replay
                // was handed someone else's, and that someone may still be
                // building an unsigned transaction over the very UTXOs this
                // would release.
                self.release_unclaimed_reservation(&connection, &processed_transaction);
                Err(e)
            },
        }
    }

    /// Finalizes a signed transaction and broadcasts it to the network.
    ///
    /// This method completes the transaction flow by:
    /// 1. Verifying the transaction hasn't expired
    /// 2. Recording the completed transaction in the database
    /// 3. Broadcasting to the network via the wallet HTTP client
    /// 4. Creating a [`DisplayedTransaction`] for immediate UI display
    ///
    /// # Arguments
    ///
    /// * `signed_transaction` - The signed transaction result from external signing
    /// * `grpc_address` - Address of the wallet gRPC server for broadcasting
    ///
    /// # Returns
    ///
    /// Returns a [`FinalizedSend`]: the [`DisplayedTransaction`] for immediate
    /// display while awaiting confirmation, whether the node accepted the first
    /// broadcast, and, when it did not, a note for the user.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The transaction lock has expired
    /// - The reservation is no longer this request's to broadcast, because
    ///   another send already completed or released it
    ///   ([`IdempotencyConflict`])
    /// - Transaction serialization fails
    /// - Database operations fail
    ///
    /// # When the node does not accept it
    ///
    /// Once the signed transaction is recorded, the send is the wallet's to see
    /// through. If the node refuses it (for any reason) or cannot be reached,
    /// this still returns `Ok` (with `accepted_by_node: false` and
    /// [`NOT_YET_ACCEPTED_NOTE`]) and the pending displayed transaction: the send
    /// stays `Completed` with its inputs locked and its change recorded, and the
    /// transaction monitor rebroadcasts it. An error here would invite the
    /// caller to send again, paying twice. The node's answer is logged on the
    /// audit target. Only the wallet's own scan can reject a send (its inputs
    /// spent by a different transaction).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // After signing the transaction externally
    /// let sent = sender.finalize_transaction_and_broadcast(
    ///     signed_result,
    ///     "http://localhost:18080".to_string(),
    /// ).await?;
    ///
    /// println!("Transaction {} recorded", sent.displayed_transaction.id);
    /// if let Some(note) = &sent.note {
    ///     println!("{note}");
    /// }
    /// ```
    pub async fn finalize_transaction_and_broadcast(
        &self,
        signed_transaction_result: SignedOneSidedTransactionResult,
        grpc_address: String,
    ) -> Result<FinalizedSend, anyhow::Error> {
        let connection = self.get_connection()?;
        let processed_transaction = &self.processed_transactions;
        let account_id = self.account.id;

        info!(
            target: "audit",
            id = processed_transaction.id();
            "Finalizing and broadcasting transaction"
        );

        self.check_if_transaction_expired(&connection, processed_transaction)
            .inspect_err(|e| {
                warn!(target: "audit", error:% = e; "Transaction finalization preparation failed");
                self.release_unclaimed_reservation(&connection, processed_transaction);
            })?;

        // Extract transaction info from the signed result for building DisplayedTransaction
        let tx_info = &signed_transaction_result.request.info;
        let actual_fee = tx_info.fee;
        let kernel_excess = signed_transaction_result
            .signed_transaction
            .transaction
            .body()
            .kernels()
            .first()
            .map(|k| k.excess.as_bytes().to_vec())
            .unwrap_or_default();

        let serialized_transaction = serde_json::to_vec(&signed_transaction_result.signed_transaction.transaction)
            .inspect_err(|e| {
                warn!(target: "audit", error:% = e; "Transaction finalization preparation failed");
                self.release_unclaimed_reservation(&connection, processed_transaction);
            })
            .map_err(|e| anyhow!("Failed to serialize transaction: {}", e))?;

        let sent_output_hash = signed_transaction_result
            .signed_transaction
            .sent_hashes
            .first()
            .map(hex::encode);

        // The node's address is checked before anything is recorded: once the
        // send is recorded, no failure may be reported as an error (see below).
        let wallet_http_client = grpc_address
            .parse()
            .map_err(|e| anyhow!("Invalid base node URL: {}", e))
            .and_then(WalletHttpClient::new)
            .inspect_err(|e| {
                warn!(target: "audit", error:% = e; "Transaction finalization preparation failed");
                self.release_unclaimed_reservation(&connection, processed_transaction);
            })?;

        let completed_tx_id = signed_transaction_result.signed_transaction.tx_id;
        let signed_transaction = signed_transaction_result.signed_transaction.clone();
        // The change output's view key comes from the key manager, whose
        // decryption (Argon2) is slow: it is done before the write transaction
        // is opened, so the write lock is not held while it runs.
        let view_key = match &signed_transaction.change_output {
            Some(_) => Some(
                self.account
                    .get_key_manager(&self.password)
                    .inspect_err(|e| {
                        warn!(target: "audit", error:% = e; "Transaction finalization preparation failed");
                        self.release_unclaimed_reservation(&connection, processed_transaction);
                    })?
                    .get_private_view_key(),
            ),
            None => None,
        };
        // The claim (`PENDING` -> `COMPLETED`), the completed transaction and its
        // change output go in one write transaction. Committed separately, the
        // request was `COMPLETED` with no completed transaction until the record
        // landed, so the lock-liveness check took its locks for dead: abandoning
        // another send could drop its lock on that send's change, and a reorg
        // could release its inputs, while it was about to be broadcast. The
        // wallet's scan recognises the send by its change output (status
        // `UNCONFIRMED` until it is seen in a block).
        let record_result = (|| -> Result<(), anyhow::Error> {
            // `new_unchecked`: only a shared connection is available here, and
            // no transaction is open on it.
            let transaction =
                rusqlite::Transaction::new_unchecked(&connection, rusqlite::TransactionBehavior::Immediate)?;
            self.claim_for_broadcast(&transaction, processed_transaction)?;
            db::create_completed_transaction(
                &transaction,
                account_id,
                processed_transaction.id(),
                &kernel_excess,
                &serialized_transaction,
                sent_output_hash,
                completed_tx_id,
            )?;
            if let (Some(change_output), Some(view_key)) = (&signed_transaction.change_output, &view_key) {
                db::insert_unconfirmed_change_output(
                    &transaction,
                    account_id,
                    view_key,
                    processed_transaction.id(),
                    change_output,
                )?;
            }
            transaction.commit()?;
            Ok(())
        })();
        // A failed claim or record rolled back with the transaction: the
        // reservation is as it was (`PENDING` unless another request claimed or
        // released it), and is released like any failure before the claim.
        record_result.inspect_err(|e| {
            warn!(target: "audit", error:% = e; "Transaction finalization preparation failed");
            self.release_unclaimed_reservation(&connection, processed_transaction);
        })?;

        // From here on the send is recorded: it is seen through whatever happens
        // (the monitor rebroadcasts it, the scan settles it), so nothing below is
        // reported as an error; that would invite the caller to pay twice.
        let response = wallet_http_client
            .submit_transaction(signed_transaction_result.signed_transaction.transaction)
            .await;

        let mut first_broadcast = record_first_broadcast(Some(&connection), completed_tx_id, response);

        // Build and save DisplayedTransaction for immediate UI display
        let displayed_transaction =
            self.build_pending_displayed_transaction(processed_transaction, &signed_transaction, actual_fee)?;

        if let Err(e) = db::insert_displayed_transaction(&connection, &displayed_transaction) {
            warn!(
                target: "audit",
                id = completed_tx_id.to_string().as_str(),
                error:% = e;
                "Could not save the displayed transaction for a recorded send; the scan will add it"
            );
            first_broadcast.local_record_lagging = true;
        }

        Ok(FinalizedSend::new(displayed_transaction, first_broadcast))
    }

    /// Build a DisplayedTransaction for a pending (just broadcasted) transaction.
    ///
    /// This creates a transaction representation that can be immediately displayed
    /// in the UI while waiting for the scanner to detect it on-chain.
    fn build_pending_displayed_transaction(
        &self,
        processed_tx: &ProcessedTransaction,
        signed_transaction: &SignedTransaction,
        fee: MicroMinotari,
    ) -> Result<DisplayedTransaction, anyhow::Error> {
        let recipient = &processed_tx.recipient;
        let now = Utc::now().naive_utc();

        // Build inputs from selected UTXOs
        let mut credit: MicroMinotari = 0.into();
        let mut debit: MicroMinotari = 0.into();
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();

        for input in &processed_tx.selected_utxos {
            inputs.push(TransactionInput {
                output_hash: input.output.output_hash(),
                amount: input.output.value(),
                mined_in_block_hash: FixedHash::default(),
                matched_output_id: input.id,
            });
            debit = debit
                .checked_add(input.output.value())
                .ok_or_else(|| anyhow!("Total value of selected inputs overflows"))?;
        }
        let mut lock_height = 0;
        for output in &signed_transaction.outputs {
            if output.max_lock_height() > lock_height {
                lock_height = output.max_lock_height();
            }
            outputs.push(TransactionOutput {
                hash: output.output_hash(),
                amount: output.value(),
                status: OutputStatus::Unspent,
                mined_in_block_height: 0,
                mined_in_block_hash: FixedHash::default(),
                output_type: OutputType::Standard,
                is_change: false,
            });
        }
        if let Some(change) = &signed_transaction.change_output {
            outputs.push(TransactionOutput {
                hash: change.output_hash(),
                amount: change.value(),
                status: OutputStatus::Unspent,
                mined_in_block_height: 0,
                mined_in_block_hash: FixedHash::default(),
                output_type: OutputType::Standard,
                is_change: true,
            });
            // The change output is the only credit, so it is assigned rather than summed.
            credit = change.value();
        }

        // Record the bytes the output carries, which an address's embedded id may have replaced,
        // not what was typed. The scan keeps this row, so it is what the history shows for good.
        let sent_memo = recipient.payment_id_bytes().filter(|bytes| !bytes.is_empty());
        let message = sent_memo.clone().and_then(|bytes| String::from_utf8(bytes).ok());
        let memo_hex = sent_memo.map(hex::encode);
        let tx = DisplayedTransactionBuilder::new()
            .account_id(self.account.id)
            .direction(TransactionDirection::Outgoing)
            .status(TransactionDisplayStatus::Pending)
            .lock_height(lock_height)
            .source(TransactionSource::OneSided)
            .credits_and_debits(credit, debit)
            .message(message)
            .memo_hex(memo_hex)
            .counterparty(Some(recipient.address.clone()))
            .blockchain_info(0, FixedHash::default(), now, 0) // No block height yet
            .fee(Some(fee))
            .inputs(inputs)
            .outputs(outputs)
            .sent_output_hashes(signed_transaction.sent_hashes.clone())
            .build(signed_transaction.tx_id)
            .map_err(|e| anyhow!("Failed to build displayed transaction: {}", e))?;

        Ok(tx)
    }

    /// Takes exclusive ownership of this send's reservation for broadcast.
    ///
    /// A replay is handed the original *reservation*, not the original unsigned
    /// transaction — nothing persists that, so it rebuilds one with a fresh
    /// `TxId` over the same inputs. Two sends can therefore hold structurally
    /// different transactions spending the identical UTXOs, and only one may go
    /// out: the conditional `Pending → Completed` update decides which. Without
    /// it both recorded a completed transaction and broadcast conflicting
    /// spends, because the expiry check ignores rows that are no longer
    /// `Pending` and so reported an already-completed reservation as fine.
    ///
    /// The loser gets an [`IdempotencyConflict`] — a 409 — and, crucially, the
    /// reservation is left untouched: its UTXOs belong to the winner.
    fn claim_for_broadcast(
        &self,
        connection: &Connection,
        processed_transaction: &ProcessedTransaction,
    ) -> Result<(), anyhow::Error> {
        let Some(status) = db::claim_pending_transaction_for_broadcast(connection, processed_transaction.id())? else {
            return Ok(());
        };

        let key = processed_transaction.idempotency_key.clone();
        let operation = IdempotencyOperation::SendTransaction;
        let conflict = match status {
            PendingTransactionStatus::Completed => IdempotencyConflict::AlreadyCompleted { key, operation },
            status => IdempotencyConflict::NoLongerActive {
                key,
                operation,
                status: status.to_string(),
            },
        };
        warn!(
            target: "audit",
            id = processed_transaction.id(),
            error:% = conflict;
            "Refusing to broadcast a reservation this request does not hold"
        );
        Err(conflict.into())
    }

    /// Cleans up after a failure that happened before this send claimed the
    /// reservation for broadcast, or rolled its claim back with the record
    /// that failed (see `finalize_transaction_and_broadcast`).
    ///
    /// Two things must hold before tearing one down, and they are different
    /// questions:
    ///
    /// * this send must have created the reservation rather than replayed onto
    ///   one that belongs to a request still in flight; and
    /// * the reservation must still be `Pending`. A *creator* can lose the
    ///   broadcast claim to a replayer — it is a coin flip, not a narrow race —
    ///   and the winner's transaction is then on the network over these inputs.
    ///   Expiring the row on the strength of "I created it" would hand them
    ///   straight back to the next send.
    fn release_unclaimed_reservation(&self, connection: &Connection, processed_transaction: &ProcessedTransaction) {
        if !processed_transaction.owns_reservation() {
            warn!(
                target: "audit",
                id = processed_transaction.id();
                "Leaving a replayed reservation locked for the request that created it"
            );
            return;
        }

        match db::expire_and_unlock_pending_transaction(connection, processed_transaction.id()) {
            Ok(true) => {},
            Ok(false) => warn!(
                target: "audit",
                id = processed_transaction.id();
                "Leaving a reservation that is no longer pending to whoever claimed it"
            ),
            Err(e) => {
                error!(target: "audit", error:% = e; "Failed to expire and unlock pending transaction during cleanup")
            },
        }
    }
}

/// Records what the node answered to a send's first broadcast.
///
/// Accepted: the send is `Broadcast`. Already mined: it is left `Completed`
/// for the scan to find. Anything else (the node refused it, for whatever
/// reason, or could not be asked) leaves it `Completed` with its inputs
/// locked and its change `UNCONFIRMED`: the node's word never rejects a send.
/// The transaction monitor rebroadcasts it, and only the wallet's own scan can
/// show its inputs went elsewhere. A refusal counts as one broadcast the node
/// did not accept; a request that got no answer does not.
///
/// The node's answer (sanitised) is kept as the send's `last_broadcast_error`
/// until a broadcast is accepted.
///
/// This never fails: it runs once the send is recorded, and an error would
/// invite the caller to send again. A database failure (or no `connection` at
/// all) is logged and reported as `local_record_lagging`: the monitor and the
/// scan bring the record up to date.
///
/// Returns whether the node took it (accepted, or already mined), its answer
/// when it did not, and the note for the user (see [`FirstBroadcast::note`]).
pub fn record_first_broadcast(
    connection: Option<&Connection>,
    completed_tx_id: TxId,
    response: Result<TxSubmissionResponse, anyhow::Error>,
) -> FirstBroadcast {
    let (mut first_broadcast, recorded) = match response {
        Ok(submission) if submission.accepted => {
            info!(
                target: "audit",
                id = completed_tx_id.to_string().as_str();
                "Transaction accepted by network"
            );
            // An accepted broadcast does not count towards the stall limit.
            let recorded =
                connection.map(|conn| db::mark_completed_transaction_as_broadcasted(conn, completed_tx_id, 0));
            (FirstBroadcast::accepted(), recorded)
        },
        Ok(submission) if submission.rejection_reason == TxSubmissionRejectionReason::AlreadyMined => {
            info!(
                target: "audit",
                id = completed_tx_id.to_string().as_str();
                "Transaction already mined by network"
            );
            (FirstBroadcast::accepted(), Some(Ok(())))
        },
        Ok(submission) => {
            let reason =
                crate::log::sanitize_node_text(&format!("Transaction not accepted: {}", submission.rejection_reason));
            warn!(
                target: "audit",
                id = completed_tx_id.to_string().as_str(),
                reason:% = reason;
                "Transaction not accepted by the network yet; it is recorded and will be rebroadcast"
            );
            let recorded =
                connection.map(|conn| db::record_failed_broadcast_attempt(conn, completed_tx_id, 1, &reason));
            (FirstBroadcast::not_accepted(reason), recorded)
        },
        Err(e) => {
            // The error can carry text from the node; it is logged and kept.
            let reason = crate::log::sanitize_node_text(&e.to_string());
            warn!(
                target: "audit",
                id = completed_tx_id.to_string().as_str(),
                reason:% = reason;
                "Transaction submission failed; it is recorded and will be rebroadcast"
            );
            let recorded = connection.map(|conn| db::record_last_broadcast_error(conn, completed_tx_id, &reason));
            (FirstBroadcast::not_accepted(reason), recorded)
        },
    };

    match recorded {
        Some(Ok(())) => {},
        Some(Err(e)) => {
            warn!(
                target: "audit",
                id = completed_tx_id.to_string().as_str(),
                error:% = e;
                "Could not record the node's answer for a recorded send; the monitor and scan will catch up"
            );
            first_broadcast.local_record_lagging = true;
        },
        None => {
            warn!(
                target: "audit",
                id = completed_tx_id.to_string().as_str();
                "No database connection to record the node's answer for a recorded send; the monitor and scan will \
                 catch up"
            );
            first_broadcast.local_record_lagging = true;
        },
    }
    first_broadcast
}

/// What a send's first broadcast found, from [`record_first_broadcast`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstBroadcast {
    /// Whether the node took the send (accepted, or already mined).
    pub accepted_by_node: bool,
    /// The node's answer (sanitised) when it did not take it.
    pub node_reason: Option<String>,
    /// The wallet could not record all of it locally (a database failure after
    /// the send was recorded). The send itself is recorded; its status catches
    /// up through the monitor and the scan.
    pub local_record_lagging: bool,
}

impl FirstBroadcast {
    fn accepted() -> Self {
        Self {
            accepted_by_node: true,
            node_reason: None,
            local_record_lagging: false,
        }
    }

    fn not_accepted(reason: String) -> Self {
        Self {
            accepted_by_node: false,
            node_reason: Some(reason),
            local_record_lagging: false,
        }
    }

    /// What to tell the user: [`NOT_YET_ACCEPTED_NOTE`] when the node did not
    /// take the send, [`RECORD_LAGGING_NOTE`] when it did but the wallet could
    /// not record everything, nothing otherwise.
    pub fn note(&self) -> Option<String> {
        if !self.accepted_by_node {
            Some(NOT_YET_ACCEPTED_NOTE.to_string())
        } else if self.local_record_lagging {
            Some(RECORD_LAGGING_NOTE.to_string())
        } else {
            None
        }
    }
}

/// The result of [`TransactionSender::finalize_transaction_and_broadcast`].
#[derive(Debug, Clone)]
pub struct FinalizedSend {
    /// The send as shown in the history, pending until the scan sees it mined.
    pub displayed_transaction: DisplayedTransaction,
    /// Whether the node accepted the first broadcast (or already had it mined).
    /// When `false` the send is still recorded and is rebroadcast automatically;
    /// it must not be sent again.
    pub accepted_by_node: bool,
    /// Set when the node has not accepted the send yet:
    /// [`NOT_YET_ACCEPTED_NOTE`].
    pub note: Option<String>,
    /// The node's answer (sanitised) when it did not accept the send.
    pub node_reason: Option<String>,
}

impl FinalizedSend {
    /// The result for a recorded send, as its first broadcast found it.
    pub fn new(displayed_transaction: DisplayedTransaction, first_broadcast: FirstBroadcast) -> Self {
        Self {
            displayed_transaction,
            accepted_by_node: first_broadcast.accepted_by_node,
            note: first_broadcast.note(),
            node_reason: first_broadcast.node_reason,
        }
    }
}

/// What to tell the caller when the node took a recorded send but the wallet
/// could not record all of it yet.
pub const RECORD_LAGGING_NOTE: &str = "The node accepted the transaction. The wallet could not update its local \
     record yet; it will catch up. Do not send it again.";

/// What to tell the caller when the node did not take a recorded send.
pub const NOT_YET_ACCEPTED_NOTE: &str = "The transaction is recorded but the node has not accepted it yet. \
     It will be rebroadcast automatically. Do not send it again.";

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_wrap)]
    #![allow(clippy::cast_lossless)]
    #![allow(clippy::cast_possible_truncation)]
    #![allow(clippy::indexing_slicing)]

    use std::{
        str::FromStr,
        sync::{Arc, Barrier},
        time::Duration,
    };

    use r2d2_sqlite::SqliteConnectionManager;
    use rusqlite::named_params;
    use tari_common_types::{
        seeds::cipher_seed::CipherSeed,
        tari_address::TariAddress,
        types::{ComAndPubSignature, CompressedPublicKey, PrivateKey},
    };
    use tari_script::{ExecutionStack, TariScript};
    use tari_transaction_components::transaction_components::{MemoField, memo_field::TxType};
    use tari_transaction_components::{
        key_manager::{
            TariKeyId,
            wallet_types::{SeedWordsWallet, WalletType},
        },
        transaction_components::{EncryptedData, TransactionOutputVersion, covenants::Covenant},
    };
    use tempfile::tempdir;

    use super::*;
    use crate::{
        db::{create_account, get_account_by_name, init_db, insert_scanned_tip_block},
        tasks::unlocker::TransactionUnlocker,
    };

    /// A send must make do with one database connection.
    ///
    /// The pool here holds exactly one, so a sender that reaches for a second cannot get it and
    /// fails on the checkout timeout. That is what used to happen in production too, just at a
    /// larger scale: each send held three connections at once, so concurrent senders exhausted
    /// any pool smaller than three times their number and then deadlocked, every one of them
    /// holding connections it could not finish without one more.
    #[test]
    fn a_send_needs_only_one_database_connection() {
        let temp = tempdir().expect("temp dir");
        let path = temp.path().join("test.db");

        // Create and migrate the database, then reopen it with a single-connection pool.
        {
            let pool = init_db(path.clone()).expect("init db");
            let conn = pool.get().expect("get conn");
            let wallet =
                WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).expect("construct wallet"));
            create_account(&conn, "test", &wallet, "pass").expect("create account");
            let account = get_account_by_name(&conn, "test")
                .expect("get account")
                .expect("account exists");
            insert_scanned_tip_block(&conn, account.id, 200, &[0u8; 32]).expect("insert tip block");
        }

        let pool = r2d2::Pool::builder()
            .max_size(1)
            .connection_timeout(Duration::from_secs(2))
            .build(SqliteConnectionManager::file(&path))
            .expect("build single-connection pool");

        let password = Zeroizing::new("pass".to_string());
        let mut sender = TransactionSender::new(pool, "test".to_string(), password.clone(), Network::LocalNet, 3)
            .expect("build sender");
        let recipient = Recipient {
            address: sender
                .account
                .get_address(Network::LocalNet, &password)
                .expect("account address"),
            amount: MicroMinotari(1_000),
            payment_id: None,
        };

        // The send has no funds to spend, so it is expected to fail — but on the wallet's own
        // terms. Failing for want of a connection is the regression.
        if let Err(e) = sender.start_new_transaction("idempotency-key".to_string(), recipient, 300) {
            let message = e.to_string();
            assert!(
                !message.contains("Failed to acquire database connection"),
                "the send wanted a second connection: {message}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Idempotency
    // -----------------------------------------------------------------------

    const PASSWORD: &str = "pass";

    /// A [`WalletOutput`] worth `value`, distinguished from its siblings by `hash_seed`.
    fn test_wallet_output(value: u64, hash_seed: u8) -> WalletOutput {
        let mut hash = FixedHash::default();
        hash[0] = hash_seed;
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
            hash,
            Default::default(),
        )
    }

    /// Inserts a spendable output row directly, bypassing the scanner.
    fn insert_test_output(conn: &Connection, account_id: i64, output_hash_byte: u8, value: u64, mined_height: u64) {
        let output = test_wallet_output(value, output_hash_byte);
        let wallet_output_json = serde_json::to_string(&output).expect("serialize WalletOutput");
        conn.execute(
            r#"
            INSERT INTO outputs (
                account_id, tx_id, output_hash, mined_in_block_height, mined_in_block_hash,
                value, mined_timestamp, wallet_output_json, status, confirmed_height,
                confirmed_hash, is_burn, maturity
            ) VALUES (
                :account_id, :tx_id, :output_hash, :height, :block_hash,
                :value, :mined_ts, :json, :status, :confirmed_height,
                :confirmed_hash, 0, :maturity
            )
            "#,
            named_params! {
                ":account_id": account_id,
                ":tx_id": output_hash_byte as i64,
                ":output_hash": vec![output_hash_byte; 32],
                ":height": mined_height as i64,
                ":block_hash": vec![output_hash_byte; 32],
                ":value": value as i64,
                ":mined_ts": Utc::now(),
                ":json": wallet_output_json,
                ":status": "UNSPENT",
                ":confirmed_height": mined_height as i64,
                ":confirmed_hash": vec![output_hash_byte; 32],
                ":maturity": 0,
            },
        )
        .expect("insert test output");
    }

    /// A migrated database holding one account with `output_count` spendable UTXOs.
    fn setup_funded_wallet(output_count: usize) -> (SqlitePool, tempfile::TempDir) {
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("test.db")).expect("init db");
        let conn = pool.get().expect("get conn");

        let wallet =
            WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).expect("construct wallet"));
        create_account(&conn, "test", &wallet, PASSWORD).expect("create account");
        let account = get_account_by_name(&conn, "test")
            .expect("get account")
            .expect("account exists");
        insert_scanned_tip_block(&conn, account.id, 200, &[0u8; 32]).expect("insert tip block");

        // Mined at 100 with tip 200, so a confirmation window of 100 makes them spendable.
        for i in 0..output_count {
            insert_test_output(&conn, account.id, (i + 1) as u8, (i as u64 + 1) * 1_000_000, 100);
        }

        drop(conn);
        (pool, temp)
    }

    fn sender_for(pool: &SqlitePool) -> TransactionSender {
        TransactionSender::new(
            pool.clone(),
            "test".to_string(),
            Zeroizing::new(PASSWORD.to_string()),
            Network::LocalNet,
            100,
        )
        .expect("build sender")
    }

    /// A pay-to-self request under `key`. `amount` stands in for the whole body:
    /// changing it models a client replaying the key with different parameters.
    fn request(sender: &TransactionSender, key: &str, amount: u64) -> ProcessedTransaction {
        let address = sender
            .account
            .get_address(Network::LocalNet, &sender.password)
            .expect("account address");
        ProcessedTransaction::new(
            None,
            key.to_string(),
            Recipient {
                address,
                amount: MicroMinotari(amount),
                payment_id: None,
            },
            3600,
        )
    }

    /// Runs the reservation step the way `start_new_transaction` does.
    fn reserve(sender: &TransactionSender, pool: &SqlitePool, key: &str, amount: u64) -> Result<String, anyhow::Error> {
        let mut processed_transaction = request(sender, key, amount);
        let mut connection = pool.get().expect("conn");
        sender.create_or_find_pending_transaction(&mut connection, &mut processed_transaction, None)
    }

    fn conflict(err: &anyhow::Error) -> &IdempotencyConflict {
        err.downcast_ref::<IdempotencyConflict>()
            .unwrap_or_else(|| panic!("expected an IdempotencyConflict, got: {err}"))
    }

    fn count(pool: &SqlitePool, sql: &str) -> i64 {
        pool.get()
            .expect("conn")
            .query_row(sql, [], |row| row.get(0))
            .expect("count query")
    }

    fn pending_transaction_count(pool: &SqlitePool) -> i64 {
        count(pool, "SELECT COUNT(*) FROM pending_transactions")
    }

    fn locked_output_count(pool: &SqlitePool) -> i64 {
        count(pool, "SELECT COUNT(*) FROM outputs WHERE status = 'LOCKED'")
    }

    /// Forces the pending transaction under `key` into `status`.
    fn set_status(pool: &SqlitePool, key: &str, status: PendingTransactionStatus) {
        let conn = pool.get().expect("conn");
        let id: String = conn
            .query_row(
                "SELECT id FROM pending_transactions WHERE idempotency_key = :key",
                named_params! { ":key": key },
                |row| row.get(0),
            )
            .expect("pending transaction exists");
        db::update_pending_transaction_status(&conn, &id, status).expect("update status");
    }

    fn status_of(pool: &SqlitePool, key: &str) -> PendingTransactionStatus {
        let status: String = pool
            .get()
            .expect("conn")
            .query_row(
                "SELECT status FROM pending_transactions WHERE idempotency_key = :key",
                named_params! { ":key": key },
                |row| row.get(0),
            )
            .expect("pending transaction exists");
        PendingTransactionStatus::from_str(&status).expect("known status")
    }

    /// Pushes a reservation's lock into the past, the way a slow offline signer does.
    fn backdate_expiry(pool: &SqlitePool, key: &str) {
        pool.get()
            .expect("conn")
            .execute(
                "UPDATE pending_transactions SET expires_at = :expired WHERE idempotency_key = :key",
                named_params! {
                    ":expired": Utc::now() - chrono::TimeDelta::hours(1),
                    ":key": key,
                },
            )
            .expect("backdate expiry");
    }

    #[test]
    fn an_exact_retry_replays_the_original_reservation() {
        let (pool, _temp) = setup_funded_wallet(3);
        let sender = sender_for(&pool);

        let first = reserve(&sender, &pool, "k", 1_000).expect("first reservation");
        let retry = reserve(&sender, &pool, "k", 1_000).expect("a retry is idempotent");

        assert_eq!(first, retry, "a retry must land on the original reservation");
        assert_eq!(pending_transaction_count(&pool), 1);
    }

    /// Two callers presenting one key must both be served the same reservation.
    ///
    /// The idempotency read used to happen before the write transaction opened,
    /// so both callers saw "no record" and both fell through. The loser then hit
    /// the `UNIQUE (account_id, idempotency_key)` index and was told its key
    /// already existed — a hard failure for what is by definition a retry.
    #[test]
    fn concurrent_requests_with_one_key_share_one_reservation() {
        let (pool, _temp) = setup_funded_wallet(6);
        let barrier = Arc::new(Barrier::new(2));

        let handles: Vec<_> = (0..2)
            .map(|_| {
                let pool = pool.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let sender = sender_for(&pool);
                    let mut processed_transaction = request(&sender, "k", 1_000);
                    // Hold the connection before lining up, so the race is over the
                    // database's write lock and not over the pool.
                    let mut connection = pool.get().expect("conn");
                    barrier.wait();
                    sender.create_or_find_pending_transaction(&mut connection, &mut processed_transaction, None)
                })
            })
            .collect();

        let ids: Vec<String> = handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .expect("thread")
                    .expect("a concurrent retry must replay, not collide")
            })
            .collect();

        assert_eq!(ids[0], ids[1], "both callers must land on one reservation");
        assert_eq!(pending_transaction_count(&pool), 1, "only one reservation may be taken");
    }

    #[test]
    fn a_completed_key_cannot_be_replayed() {
        // The UTXOs behind the key are already spent by a broadcast transaction,
        // so handing them back would build something that can never confirm.
        let (pool, _temp) = setup_funded_wallet(3);
        let sender = sender_for(&pool);

        reserve(&sender, &pool, "k", 1_000).expect("initial reservation");
        set_status(&pool, "k", PendingTransactionStatus::Completed);

        let err = reserve(&sender, &pool, "k", 1_000).expect_err("a completed key must not be replayable");
        assert!(
            matches!(conflict(&err), IdempotencyConflict::AlreadyCompleted { .. }),
            "expected an already-completed conflict, got: {err}",
        );
    }

    /// A key whose reservation is gone must say so.
    ///
    /// The unlocker clears `locked_by_request_id` when it expires a lock, so
    /// replaying such a key used to sail past the idempotency check, find no
    /// locked outputs, and fail obscurely while building a zero-input
    /// transaction.
    #[test]
    fn a_key_whose_reservation_is_gone_reports_why() {
        for status in [PendingTransactionStatus::Expired, PendingTransactionStatus::Cancelled] {
            let (pool, _temp) = setup_funded_wallet(3);
            let sender = sender_for(&pool);

            reserve(&sender, &pool, "k", 1_000).expect("initial reservation");
            set_status(&pool, "k", status.clone());

            let err = reserve(&sender, &pool, "k", 1_000).expect_err("a dead reservation cannot be replayed");
            assert!(
                matches!(conflict(&err), IdempotencyConflict::NoLongerActive { .. }),
                "expected a no-longer-active conflict for {status}, got: {err}",
            );
        }
    }

    #[test]
    fn replaying_a_key_with_a_different_payment_is_rejected() {
        // Same key, different amount: serving that replay would build a payment
        // the original client never asked for out of its reserved UTXOs.
        let (pool, _temp) = setup_funded_wallet(3);
        let sender = sender_for(&pool);

        let original = reserve(&sender, &pool, "k", 1_000).expect("original reservation");
        let reserved = locked_output_count(&pool);

        let err = reserve(&sender, &pool, "k", 2_000).expect_err("a replay with a different request must be refused");
        assert!(
            matches!(conflict(&err), IdempotencyConflict::RequestMismatch { .. }),
            "expected a request mismatch, got: {err}",
        );

        assert_eq!(
            locked_output_count(&pool),
            reserved,
            "the original reservation must survive the replay"
        );
        assert_eq!(
            reserve(&sender, &pool, "k", 1_000).expect("the original client can still retry"),
            original,
        );
    }

    // -----------------------------------------------------------------------
    // Ownership of a replayed reservation
    // -----------------------------------------------------------------------

    /// A replay that fails afterwards must not tear down the original reservation.
    ///
    /// The failure handler cannot tell the two apart on its own: before the
    /// reservation was marked, a replay that hit any transient error — a busy
    /// database, a decode failure — expired the row and unlocked the UTXOs while
    /// the request that created it was still holding an unsigned transaction
    /// over them.
    #[test]
    fn a_failing_replay_leaves_the_original_reservation_alone() {
        let (pool, _temp) = setup_funded_wallet(3);
        let sender = sender_for(&pool);

        let mut owner = request(&sender, "k", 1_000);
        let reservation_id = sender
            .create_or_find_pending_transaction(&mut pool.get().expect("conn"), &mut owner, None)
            .expect("original reservation");
        owner.update_id(reservation_id.clone());
        let locked = locked_output_count(&pool);
        assert!(locked > 0, "the original reservation must have locked something");
        assert!(owner.owns_reservation(), "the creator owns its reservation");

        let mut replayer = request(&sender, "k", 1_000);
        let replayed_id = sender
            .create_or_find_pending_transaction(&mut pool.get().expect("conn"), &mut replayer, None)
            .expect("replay");
        replayer.update_id(replayed_id.clone());
        assert_eq!(replayed_id, reservation_id);
        assert!(!replayer.owns_reservation(), "a replay must not claim ownership");

        sender.release_unclaimed_reservation(&pool.get().expect("conn"), &replayer);
        assert_eq!(
            status_of(&pool, "k"),
            PendingTransactionStatus::Pending,
            "a replay's failure must leave the reservation live",
        );
        assert_eq!(
            locked_output_count(&pool),
            locked,
            "a replay's failure must leave the original UTXOs locked",
        );

        // The request that created it still can release it, and when it does the
        // row and the outputs move together.
        sender.release_unclaimed_reservation(&pool.get().expect("conn"), &owner);
        assert_eq!(status_of(&pool, "k"), PendingTransactionStatus::Expired);
        assert_eq!(
            locked_output_count(&pool),
            0,
            "expiring a reservation must release its UTXOs in the same breath",
        );
    }

    // -----------------------------------------------------------------------
    // Claiming a reservation for broadcast
    // -----------------------------------------------------------------------

    #[test]
    fn only_one_caller_can_claim_a_reservation_for_broadcast() {
        let (pool, _temp) = setup_funded_wallet(3);
        let sender = sender_for(&pool);

        let mut processed_transaction = request(&sender, "k", 1_000);
        let id = sender
            .create_or_find_pending_transaction(&mut pool.get().expect("conn"), &mut processed_transaction, None)
            .expect("reservation");
        processed_transaction.update_id(id);

        sender
            .claim_for_broadcast(&pool.get().expect("conn"), &processed_transaction)
            .expect("the first caller takes the reservation");
        assert_eq!(status_of(&pool, "k"), PendingTransactionStatus::Completed);

        let err = sender
            .claim_for_broadcast(&pool.get().expect("conn"), &processed_transaction)
            .expect_err("a second broadcast of one reservation must be refused");
        assert!(
            matches!(conflict(&err), IdempotencyConflict::AlreadyCompleted { .. }),
            "expected an already-completed conflict, got: {err}",
        );
    }

    /// A reservation that was released cannot be broadcast either.
    ///
    /// The expiry check only looks at rows that are still `Pending`, so a
    /// `Cancelled` or `Expired` row read as "not expired" and sailed through to
    /// `create_completed_transaction` and the network.
    #[test]
    fn a_released_reservation_cannot_be_broadcast() {
        for status in [PendingTransactionStatus::Expired, PendingTransactionStatus::Cancelled] {
            let (pool, _temp) = setup_funded_wallet(3);
            let sender = sender_for(&pool);

            let mut processed_transaction = request(&sender, "k", 1_000);
            let id = sender
                .create_or_find_pending_transaction(&mut pool.get().expect("conn"), &mut processed_transaction, None)
                .expect("reservation");
            processed_transaction.update_id(id);
            set_status(&pool, "k", status.clone());

            let err = sender
                .claim_for_broadcast(&pool.get().expect("conn"), &processed_transaction)
                .expect_err("a released reservation cannot be broadcast");
            assert!(
                matches!(conflict(&err), IdempotencyConflict::NoLongerActive { .. }),
                "expected a no-longer-active conflict for {status}, got: {err}",
            );
            assert_eq!(
                status_of(&pool, "k"),
                status,
                "a refused claim must not move the reservation on",
            );
        }
    }

    /// The refused caller must get no further than the conflict.
    ///
    /// `claim_for_broadcast` runs before `create_completed_transaction` and
    /// before the network call, so a refusal is what stops the second send from
    /// recording a duplicate completed transaction over the same inputs — the
    /// index on `pending_tx_id` is not unique and would happily take it.
    #[test]
    fn a_refused_claim_records_no_completed_transaction() {
        let (pool, _temp) = setup_funded_wallet(3);
        let sender = sender_for(&pool);

        let mut processed_transaction = request(&sender, "k", 1_000);
        let id = sender
            .create_or_find_pending_transaction(&mut pool.get().expect("conn"), &mut processed_transaction, None)
            .expect("reservation");
        processed_transaction.update_id(id);

        sender
            .claim_for_broadcast(&pool.get().expect("conn"), &processed_transaction)
            .expect("first claim");
        let locked = locked_output_count(&pool);

        sender
            .claim_for_broadcast(&pool.get().expect("conn"), &processed_transaction)
            .expect_err("second claim");

        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM completed_transactions"),
            0,
            "a refused claim must not record a completed transaction",
        );
        assert_eq!(
            locked_output_count(&pool),
            locked,
            "a refused claim must leave the winner's UTXOs alone",
        );
    }

    /// Concurrent claims on one reservation: exactly one wins.
    #[test]
    fn concurrent_claims_resolve_to_a_single_broadcast() {
        let (pool, _temp) = setup_funded_wallet(3);

        let reservation_id = {
            let sender = sender_for(&pool);
            let mut processed_transaction = request(&sender, "k", 1_000);
            sender
                .create_or_find_pending_transaction(&mut pool.get().expect("conn"), &mut processed_transaction, None)
                .expect("reservation")
        };

        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let pool = pool.clone();
                let barrier = Arc::clone(&barrier);
                let reservation_id = reservation_id.clone();
                std::thread::spawn(move || {
                    let sender = sender_for(&pool);
                    let mut processed_transaction = request(&sender, "k", 1_000);
                    processed_transaction.update_id(reservation_id);
                    let connection = pool.get().expect("conn");
                    barrier.wait();
                    sender.claim_for_broadcast(&connection, &processed_transaction)
                })
            })
            .collect();

        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread"))
            .collect();
        assert_eq!(
            outcomes.iter().filter(|outcome| outcome.is_ok()).count(),
            1,
            "exactly one caller may broadcast a reservation",
        );
    }

    // -----------------------------------------------------------------------
    // Expired reservations
    // -----------------------------------------------------------------------

    /// A replay must not expire a reservation it does not own.
    ///
    /// The expiry check used to write the row to `Expired` itself, before the
    /// error handler had decided whether this send owns it. A replay therefore
    /// marked someone else's row `Expired` and then — correctly — declined to
    /// unlock it. Nothing recovered those UTXOs: the unlocker only revisits
    /// `Pending` rows, and no completed transaction existed to unlock from.
    #[test]
    fn a_replay_must_not_expire_a_reservation_it_does_not_own() {
        let (pool, _temp) = setup_funded_wallet(3);
        let sender = sender_for(&pool);

        let mut owner = request(&sender, "k", 1_000);
        let id = sender
            .create_or_find_pending_transaction(&mut pool.get().expect("conn"), &mut owner, None)
            .expect("reservation");
        owner.update_id(id);
        let locked = locked_output_count(&pool);
        assert!(locked > 0, "the reservation must have locked something");

        // The signer took longer than the lock.
        backdate_expiry(&pool, "k");

        let mut replayer = request(&sender, "k", 1_000);
        let replayed_id = sender
            .create_or_find_pending_transaction(&mut pool.get().expect("conn"), &mut replayer, None)
            .expect("replay");
        replayer.update_id(replayed_id);
        assert!(!replayer.owns_reservation());

        // The sequence `finalize_transaction_and_broadcast` runs at its head.
        let connection = pool.get().expect("conn");
        sender
            .check_if_transaction_expired(&connection, &replayer)
            .expect_err("the lock has expired");
        sender.release_unclaimed_reservation(&connection, &replayer);

        assert_eq!(
            status_of(&pool, "k"),
            PendingTransactionStatus::Pending,
            "a replay must leave the row for its owner and the unlocker",
        );
        assert_eq!(locked_output_count(&pool), locked, "the UTXOs must still be reserved");
        assert_eq!(
            db::find_expired_pending_transactions(&connection)
                .expect("scan for expired")
                .len(),
            1,
            "the unlocker must still be able to recover this reservation",
        );

        // And the request that created it still releases both halves together.
        sender
            .check_if_transaction_expired(&connection, &owner)
            .expect_err("the lock has expired");
        sender.release_unclaimed_reservation(&connection, &owner);
        assert_eq!(status_of(&pool, "k"), PendingTransactionStatus::Expired);
        assert_eq!(locked_output_count(&pool), 0, "the owner's release frees the UTXOs");
    }

    /// The unlocker must not act on a reservation claimed after it was listed.
    ///
    /// Its `SELECT` runs in autocommit and each row is then handled in its own
    /// write transaction, so a send can claim one in the gap. Expiring it then
    /// returned the inputs of a broadcast transaction to `Unspent`, free for the
    /// next send to spend again.
    #[test]
    fn the_unlocker_skips_a_reservation_claimed_after_it_was_listed() {
        let (pool, _temp) = setup_funded_wallet(3);
        let sender = sender_for(&pool);

        let mut processed_transaction = request(&sender, "k", 1_000);
        let id = sender
            .create_or_find_pending_transaction(&mut pool.get().expect("conn"), &mut processed_transaction, None)
            .expect("reservation");
        processed_transaction.update_id(id);
        let locked = locked_output_count(&pool);
        backdate_expiry(&pool, "k");

        // The unlocker lists it while it is still expired and pending.
        let connection = pool.get().expect("conn");
        let listed = db::find_expired_pending_transactions(&connection).expect("scan for expired");
        assert_eq!(listed.len(), 1, "the reservation is due for unlocking");

        // A send claims it and broadcasts before the loop reaches the row.
        sender
            .claim_for_broadcast(&pool.get().expect("conn"), &processed_transaction)
            .expect("claim");

        for tx in listed {
            assert!(
                !TransactionUnlocker::expire_and_unlock(&connection, &tx.id).expect("unlock pass"),
                "the unlocker must decline a reservation that is no longer pending",
            );
        }

        assert_eq!(
            status_of(&pool, "k"),
            PendingTransactionStatus::Completed,
            "the unlocker must not overwrite a claimed reservation",
        );
        assert_eq!(
            locked_output_count(&pool),
            locked,
            "the inputs of a broadcast transaction must stay locked",
        );
    }

    /// A creator that loses the broadcast claim must leave the winner alone.
    ///
    /// Which of the two sends holding transactions over one reservation returns
    /// from its signer first is a coin flip, so the creator losing is ordinary,
    /// not a narrow race. Its cleanup guard used to ask only "did I create
    /// this?" — still true — and so expired the row and released the inputs of
    /// the replayer's transaction while that transaction was on the network.
    #[test]
    fn a_creator_that_loses_the_claim_leaves_the_winner_alone() {
        let (pool, _temp) = setup_funded_wallet(3);
        let sender = sender_for(&pool);

        let mut creator = request(&sender, "k", 1_000);
        let id = sender
            .create_or_find_pending_transaction(&mut pool.get().expect("conn"), &mut creator, None)
            .expect("reservation");
        creator.update_id(id);
        let locked = locked_output_count(&pool);
        assert!(locked > 0, "the reservation must have locked something");

        let mut replayer = request(&sender, "k", 1_000);
        let replayed_id = sender
            .create_or_find_pending_transaction(&mut pool.get().expect("conn"), &mut replayer, None)
            .expect("replay");
        replayer.update_id(replayed_id);
        assert!(creator.owns_reservation(), "the creator still reads as the owner");
        assert!(!replayer.owns_reservation());

        // The replayer's signer returns first, so it wins the broadcast.
        sender
            .claim_for_broadcast(&pool.get().expect("conn"), &replayer)
            .expect("the replayer claims the reservation");

        // The creator returns second: refused, and then must not clean up.
        let connection = pool.get().expect("conn");
        let err = sender
            .claim_for_broadcast(&connection, &creator)
            .expect_err("the creator lost the claim");
        assert!(
            matches!(conflict(&err), IdempotencyConflict::AlreadyCompleted { .. }),
            "expected an already-completed conflict, got: {err}",
        );
        sender.release_unclaimed_reservation(&connection, &creator);

        assert_eq!(
            status_of(&pool, "k"),
            PendingTransactionStatus::Completed,
            "the winner's reservation must stand",
        );
        assert_eq!(
            locked_output_count(&pool),
            locked,
            "the inputs of a broadcast transaction must stay locked",
        );
    }

    // -----------------------------------------------------------------------
    // First broadcast
    // -----------------------------------------------------------------------

    struct RecordedSend {
        pool: SqlitePool,
        tx_id: TxId,
        input_id: i64,
        request_id: String,
        _dir: tempfile::TempDir,
    }

    /// A signed send as `finalize_transaction_and_broadcast` records it before
    /// submitting: completed transaction, input locked, change `UNCONFIRMED`.
    fn recorded_send() -> RecordedSend {
        let (pool, dir) = setup_funded_wallet(1);
        let conn = pool.get().expect("conn");
        let account = get_account_by_name(&conn, "test").expect("query").expect("account");
        let binding = IdempotencyBinding::new(
            Some("first".to_string()),
            IdempotencyOperation::SendTransaction,
            RequestFingerprint::new(IdempotencyOperation::SendTransaction),
        );
        let request_id = db::create_pending_transaction(
            &conn,
            "first",
            &binding,
            account.id,
            true,
            MicroMinotari(0),
            MicroMinotari(0),
            MicroMinotari(0),
            Utc::now() + chrono::Duration::hours(1),
        )
        .expect("pending");
        let input_id: i64 = conn
            .query_row(
                "SELECT id FROM outputs WHERE account_id = :account_id",
                named_params! { ":account_id": account.id },
                |row| row.get(0),
            )
            .expect("input");
        db::lock_output(&conn, input_id, &request_id, Utc::now()).expect("lock");
        let tx_id = TxId::from(7u64);
        db::create_completed_transaction(&conn, account.id, &request_id, &[], b"{}", None, tx_id).expect("completed");
        db::insert_unconfirmed_change_output(
            &conn,
            account.id,
            &tari_common_types::types::PrivateKey::default(),
            &request_id,
            &test_wallet_output(500, 99),
        )
        .expect("change");
        drop(conn);
        RecordedSend {
            pool,
            tx_id,
            input_id,
            request_id,
            _dir: dir,
        }
    }

    fn not_accepted(reason: TxSubmissionRejectionReason) -> TxSubmissionResponse {
        TxSubmissionResponse {
            accepted: false,
            rejection_reason: reason,
            is_synced: true,
            details: None,
        }
    }

    /// The send's status and attempt count, its input's status and lock, and
    /// whether its change is still an active `UNCONFIRMED` row.
    fn send_state(send: &RecordedSend) -> (String, i32, String, Option<String>, bool) {
        let conn = send.pool.get().expect("conn");
        let completed = db::get_completed_transaction_by_id(&conn, send.tx_id)
            .expect("query")
            .expect("completed");
        let (input_status, lock): (String, Option<String>) = conn
            .query_row(
                "SELECT status, locked_by_request_id FROM outputs WHERE id = :id",
                named_params! { ":id": send.input_id },
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("input");
        let change_kept: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM outputs WHERE created_by_request_id = :req AND status = 'UNCONFIRMED' \
                 AND deleted_at IS NULL",
                named_params! { ":req": send.request_id },
                |row| row.get(0),
            )
            .expect("change");
        (
            completed.status.to_string(),
            completed.broadcast_attempts,
            input_status,
            lock,
            change_kept == 1,
        )
    }

    #[test]
    fn a_first_broadcast_the_node_refuses_leaves_the_send_to_be_rebroadcast() {
        for reason in [
            TxSubmissionRejectionReason::DoubleSpend,
            TxSubmissionRejectionReason::ValidationFailed,
            TxSubmissionRejectionReason::FeeTooLow,
        ] {
            let send = recorded_send();
            {
                let conn = send.pool.get().expect("conn");
                record_first_broadcast(Some(&*conn), send.tx_id, Ok(not_accepted(reason.clone())));
            }
            let (status, attempts, input_status, lock, change_kept) = send_state(&send);
            assert_eq!(status, "completed", "{reason}");
            assert_eq!(attempts, 1, "{reason}");
            assert_eq!(input_status, "LOCKED", "{reason}");
            assert_eq!(lock.as_deref(), Some(send.request_id.as_str()), "{reason}");
            assert!(change_kept, "{reason}");
        }
    }

    #[test]
    fn a_first_broadcast_that_fails_leaves_the_send_to_be_rebroadcast() {
        let send = recorded_send();
        {
            let conn = send.pool.get().expect("conn");
            record_first_broadcast(
                Some(&*conn),
                send.tx_id,
                Err(anyhow!("Broadcast failed: connection refused")),
            );
        }
        let (status, attempts, input_status, lock, change_kept) = send_state(&send);
        assert_eq!(status, "completed");
        assert_eq!(attempts, 0, "no answer from the node is not counted");
        assert_eq!(input_status, "LOCKED");
        assert_eq!(lock.as_deref(), Some(send.request_id.as_str()));
        assert!(change_kept);
    }

    #[test]
    fn an_accepted_first_broadcast_is_broadcast_and_not_counted() {
        let send = recorded_send();
        {
            let conn = send.pool.get().expect("conn");
            let accepted = TxSubmissionResponse {
                accepted: true,
                rejection_reason: TxSubmissionRejectionReason::None,
                is_synced: true,
                details: None,
            };
            record_first_broadcast(Some(&*conn), send.tx_id, Ok(accepted));
        }
        let (status, attempts, ..) = send_state(&send);
        assert_eq!(status, "broadcast");
        assert_eq!(attempts, 0);
    }

    fn pending_displayed(tx_id: TxId) -> DisplayedTransaction {
        DisplayedTransaction {
            id: tx_id,
            direction: TransactionDirection::Outgoing,
            source: TransactionSource::OneSided,
            status: TransactionDisplayStatus::Pending,
            amount: MicroMinotari::from(1_000),
            message: None,
            counterparty: None,
            blockchain: crate::transactions::BlockchainInfo {
                block_height: 0,
                timestamp: Utc::now().naive_utc(),
                confirmations: 0,
                block_hash: FixedHash::zero(),
            },
            fee: None,
            details: crate::transactions::TransactionDetails {
                account_id: 1,
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

    #[test]
    fn a_send_the_node_refuses_tells_the_caller_it_is_pending() {
        let send = recorded_send();
        let accepted = {
            let conn = send.pool.get().expect("conn");
            record_first_broadcast(
                Some(&*conn),
                send.tx_id,
                Ok(not_accepted(TxSubmissionRejectionReason::DoubleSpend)),
            )
        };
        let sent = FinalizedSend::new(pending_displayed(send.tx_id), accepted);
        assert!(!sent.accepted_by_node);
        assert_eq!(sent.note.as_deref(), Some(NOT_YET_ACCEPTED_NOTE));
        assert!(NOT_YET_ACCEPTED_NOTE.contains("Do not send it again"));
        let reason = sent.node_reason.expect("the node's answer");
        assert!(reason.contains("Double Spend"), "got: {reason}");

        // Kept on the send, and cleared once a broadcast is accepted.
        let conn = send.pool.get().expect("conn");
        assert_eq!(
            db::get_last_broadcast_error(&conn, send.tx_id).expect("query"),
            Some(reason)
        );
        db::mark_completed_transaction_as_broadcasted(&conn, send.tx_id, 0).expect("accepted later");
        assert_eq!(db::get_last_broadcast_error(&conn, send.tx_id).expect("query"), None);
    }

    #[test]
    fn a_send_the_node_accepts_carries_no_note() {
        let send = recorded_send();
        let accepted = {
            let conn = send.pool.get().expect("conn");
            let accepted = TxSubmissionResponse {
                accepted: true,
                rejection_reason: TxSubmissionRejectionReason::None,
                is_synced: true,
                details: None,
            };
            record_first_broadcast(Some(&*conn), send.tx_id, Ok(accepted))
        };
        let sent = FinalizedSend::new(pending_displayed(send.tx_id), accepted);
        assert!(sent.accepted_by_node);
        assert_eq!(sent.note, None);
        assert_eq!(sent.node_reason, None);
    }

    /// A send prepared by `start_new_transaction`, with a stand-in signed result
    /// (finalising only records and submits it; nothing checks the signature).
    fn prepared_send(pool: &SqlitePool) -> (TransactionSender, SignedOneSidedTransactionResult) {
        let mut sender = sender_for(pool);
        let recipient = Recipient {
            address: sender
                .account
                .get_address(Network::LocalNet, &Zeroizing::new(PASSWORD.to_string()))
                .expect("address"),
            amount: MicroMinotari(1_000),
            payment_id: None,
        };
        let prepared = sender
            .start_new_transaction("finalise".to_string(), recipient, 300)
            .expect("prepare");
        let signed = SignedOneSidedTransactionResult {
            version: prepared.version.clone(),
            signed_transaction: SignedTransaction {
                transaction: tari_transaction_components::transaction_components::Transaction::new(
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    tari_common_types::types::PrivateKey::default(),
                    tari_common_types::types::PrivateKey::default(),
                ),
                sent_hashes: Vec::new(),
                outputs: Vec::new(),
                change_hashes: Vec::new(),
                change_output: None,
                tx_id: prepared.tx_id,
            },
            request: prepared,
        };
        (sender, signed)
    }

    /// The recipient's output memo names the sender, so the recipient's wallet can show who paid
    /// it; the change memo stays the plain payment id.
    #[test]
    fn the_recipient_memo_carries_the_sender_address() {
        let (pool, _temp) = setup_funded_wallet(3);
        let mut sender = sender_for(&pool);
        let sender_address = sender
            .account
            .get_address(Network::LocalNet, &Zeroizing::new(PASSWORD.to_string()))
            .expect("address");
        let other = TariAddress::new_dual_address_with_default_features(
            CompressedPublicKey::from_secret_key(&PrivateKey::from(7u64)),
            CompressedPublicKey::from_secret_key(&PrivateKey::from(9u64)),
            Network::LocalNet,
        )
        .expect("address");
        let recipient = Recipient {
            address: other,
            amount: MicroMinotari(1_000),
            payment_id: Some("invoice-42".to_string()),
        };
        let prepared = sender
            .start_new_transaction("sender-address".to_string(), recipient, 300)
            .expect("prepare");

        let memo = &prepared.info.recipients[0].payment_id;
        assert_eq!(memo.claimed_sender_address(), Some(sender_address));
        assert_eq!(memo.payment_id_as_bytes(), b"invoice-42".to_vec());
        assert_eq!(memo.get_type(), TxType::PaymentToOther);
        assert_eq!(prepared.info.payment_id.claimed_sender_address(), None);
    }

    /// An exchange deposit address embeds its reference as raw bytes, which need not be text.
    /// The output must carry those exact bytes, whatever message the sender typed.
    #[test]
    fn an_address_payment_id_is_sent_as_its_bytes() {
        let (pool, _temp) = setup_funded_wallet(3);
        let mut sender = sender_for(&pool);
        let embedded = vec![0x9c, 0xf1, 0x03, 0x00, 0xff, 0x80, 0x01, 0x00];
        let deposit = TariAddress::new_dual_address_with_default_features(
            CompressedPublicKey::from_secret_key(&PrivateKey::from(7u64)),
            CompressedPublicKey::from_secret_key(&PrivateKey::from(9u64)),
            Network::LocalNet,
        )
        .expect("address")
        .with_memo_field_payment_id(embedded.clone())
        .expect("payment id");
        let recipient = Recipient {
            address: deposit,
            amount: MicroMinotari(1_000),
            payment_id: Some("typed message".to_string()),
        };
        let prepared = sender
            .start_new_transaction("binary-payment-id".to_string(), recipient, 300)
            .expect("prepare");

        assert_eq!(prepared.info.recipients[0].payment_id.payment_id_as_bytes(), embedded);
        assert_eq!(prepared.info.payment_id.payment_id_as_bytes(), embedded);
    }

    /// The history row records the bytes that went on chain: the scan keeps this row, so a
    /// typed message an address's embedded id replaced would otherwise show for good.
    #[test]
    fn the_pending_record_shows_the_payment_id_that_was_sent() {
        let (pool, _temp) = setup_funded_wallet(3);
        let sender = sender_for(&pool);
        let address = TariAddress::new_dual_address_with_default_features(
            CompressedPublicKey::from_secret_key(&PrivateKey::from(7u64)),
            CompressedPublicKey::from_secret_key(&PrivateKey::from(9u64)),
            Network::LocalNet,
        )
        .expect("address");
        let signed = SignedTransaction {
            transaction: tari_transaction_components::transaction_components::Transaction::new(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                tari_common_types::types::PrivateKey::default(),
                tari_common_types::types::PrivateKey::default(),
            ),
            sent_hashes: Vec::new(),
            outputs: Vec::new(),
            change_hashes: Vec::new(),
            change_output: None,
            tx_id: TxId::new_random(),
        };
        let record = |address: TariAddress| {
            let recipient = Recipient {
                address,
                amount: MicroMinotari(1_000),
                payment_id: Some("typed message".to_string()),
            };
            let processed = ProcessedTransaction::new(None, "history".to_string(), recipient, 300);
            let tx = sender
                .build_pending_displayed_transaction(&processed, &signed, MicroMinotari(10))
                .expect("record");
            (tx.message, tx.details.memo_hex)
        };

        let binary = vec![0x9c, 0xf1, 0x03, 0xff];
        assert_eq!(
            record(address.with_memo_field_payment_id(binary.clone()).expect("payment id")),
            (None, Some(hex::encode(&binary)))
        );
        assert_eq!(
            record(
                address
                    .with_memo_field_payment_id(b"DEP-42".to_vec())
                    .expect("payment id")
            ),
            (Some("DEP-42".to_string()), Some(hex::encode(b"DEP-42")))
        );
        assert_eq!(
            record(address),
            (Some("typed message".to_string()), Some(hex::encode(b"typed message")))
        );
    }

    /// An embedded id too long for the memos is refused before any UTXO is locked.
    #[test]
    fn an_address_payment_id_that_cannot_fit_locks_nothing() {
        let (pool, _temp) = setup_funded_wallet(3);
        let mut sender = sender_for(&pool);
        let deposit = TariAddress::new_dual_address_with_default_features(
            CompressedPublicKey::from_secret_key(&PrivateKey::from(7u64)),
            CompressedPublicKey::from_secret_key(&PrivateKey::from(9u64)),
            Network::LocalNet,
        )
        .expect("address")
        .with_memo_field_payment_id(vec![0xff; 256])
        .expect("payment id");
        let recipient = Recipient {
            address: deposit,
            amount: MicroMinotari(1_000),
            payment_id: None,
        };

        sender
            .start_new_transaction("too-long".to_string(), recipient, 300)
            .expect_err("a payment id that cannot fit must be refused");
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM outputs WHERE status = 'LOCKED'"), 0);
    }

    #[tokio::test]
    async fn a_bad_node_url_fails_before_anything_is_recorded() {
        let (pool, _temp) = setup_funded_wallet(3);
        let (sender, signed) = prepared_send(&pool);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM outputs WHERE status = 'LOCKED'"), 1);

        sender
            .finalize_transaction_and_broadcast(signed, "not a url".to_string())
            .await
            .expect_err("a bad node URL is an error");

        // Nothing recorded, and the reservation handed back.
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM completed_transactions"), 0);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM outputs WHERE status = 'LOCKED'"), 0);
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM pending_transactions WHERE status = 'PENDING'"
            ),
            0
        );
    }

    /// A record that fails takes the claim down with it: the request is never
    /// `COMPLETED` without its completed transaction (the lock-liveness check
    /// would take its locks for dead), and the reservation is released as for
    /// any failure before the claim.
    #[tokio::test]
    async fn a_failed_record_rolls_the_claim_back() {
        let (pool, _temp) = setup_funded_wallet(3);
        let (sender, signed) = prepared_send(&pool);
        pool.get()
            .expect("conn")
            .execute_batch(
                "CREATE TRIGGER no_record BEFORE INSERT ON completed_transactions \
                 BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )
            .expect("trigger");

        sender
            .finalize_transaction_and_broadcast(signed, "http://127.0.0.1:1".to_string())
            .await
            .expect_err("a failed record is an error: nothing was sent");

        assert_eq!(count(&pool, "SELECT COUNT(*) FROM completed_transactions"), 0);
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM pending_transactions WHERE status = 'COMPLETED'"
            ),
            0,
            "the claim rolled back with the record"
        );
        // This send created the reservation: it is released.
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM pending_transactions WHERE status = 'EXPIRED'"
            ),
            1
        );
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM outputs WHERE status = 'LOCKED'"), 0);
    }

    /// Even when the cleanup fails too, the failed record leaves no request
    /// `COMPLETED` without its completed transaction: the claim was never
    /// committed on its own, so the reservation is still `PENDING`, for the
    /// unlocker to expire.
    #[tokio::test]
    async fn a_failed_record_never_leaves_a_claim_without_its_transaction() {
        let (pool, _temp) = setup_funded_wallet(3);
        let (sender, signed) = prepared_send(&pool);
        pool.get()
            .expect("conn")
            .execute_batch(
                "CREATE TRIGGER no_record BEFORE INSERT ON completed_transactions \
                 BEGIN SELECT RAISE(ABORT, 'disk full'); END; \
                 CREATE TRIGGER no_expiry BEFORE UPDATE OF status ON pending_transactions \
                 WHEN NEW.status = 'EXPIRED' BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )
            .expect("triggers");

        sender
            .finalize_transaction_and_broadcast(signed, "http://127.0.0.1:1".to_string())
            .await
            .expect_err("a failed record is an error: nothing was sent");

        assert_eq!(count(&pool, "SELECT COUNT(*) FROM completed_transactions"), 0);
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM pending_transactions WHERE status = 'PENDING'"
            ),
            1,
            "the claim was never committed on its own"
        );
    }

    #[tokio::test]
    async fn a_database_failure_after_the_send_is_recorded_is_not_an_error() {
        let (pool, _temp) = setup_funded_wallet(3);
        let (sender, signed) = prepared_send(&pool);
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "accepted": true, "rejection_reason": "None", "is_synced": true },
                "error": null,
                "id": "1",
            })))
            .mount(&server)
            .await;
        // Everything after recording the send fails to write.
        pool.get()
            .expect("conn")
            .execute_batch(
                "CREATE TRIGGER no_display BEFORE INSERT ON displayed_transactions \
                 BEGIN SELECT RAISE(ABORT, 'disk full'); END; \
                 CREATE TRIGGER no_status BEFORE UPDATE ON completed_transactions \
                 BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )
            .expect("triggers");

        let sent = sender
            .finalize_transaction_and_broadcast(signed, server.uri())
            .await
            .expect("a recorded send is never an error");

        assert!(sent.accepted_by_node);
        assert_eq!(sent.note.as_deref(), Some(RECORD_LAGGING_NOTE));
        assert!(RECORD_LAGGING_NOTE.contains("Do not send it again"));
        // The send itself is recorded, inputs still locked.
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM completed_transactions"), 1);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM outputs WHERE status = 'LOCKED'"), 1);
    }
}
