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
//! let displayed_tx = sender.finalize_transaction_and_broadcast(
//!     signed,
//!     grpc_address,
//! ).await?;
//! ```

use anyhow::anyhow;
use chrono::{Duration, Utc};
use log::{error, info, warn};
use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;
use tari_common::configuration::Network;
use tari_common_types::types::FixedHash;
use tari_common_types::{tari_address::TariAddressFeatures, transaction::TxId};
use tari_transaction_components::offline_signing::models::SignedTransaction;
use tari_transaction_components::rpc::models::TxSubmissionRejectionReason;
use tari_transaction_components::transaction_components::OutputType;
use tari_transaction_components::{
    MicroMinotari, TransactionBuilder,
    consensus::ConsensusConstantsBuilder,
    key_manager::KeyManager,
    offline_signing::{
        PaymentRecipient,
        models::{PrepareOneSidedTransactionForSigningResult, SignedOneSidedTransactionResult},
        prepare_one_sided_transaction_for_signing,
    },
    transaction_components::{MemoField, OutputFeatures, WalletOutput, memo_field::TxType},
};
use tari_utilities::ByteArray;

use crate::db::DbWalletOutput;
use crate::models::OutputStatus;
use crate::transactions::TransactionOutput;
use crate::{
    db::{self, AccountRow, SqlitePool},
    http::WalletHttpClient,
    log::mask_amount,
    models::PendingTransactionStatus,
    transactions::{
        displayed_transaction_processor::{
            DisplayedTransaction, DisplayedTransactionBuilder, TransactionDirection, TransactionDisplayStatus,
            TransactionInput, TransactionSource,
        },
        input_selector::{InputSelector, UtxoSelection},
        one_sided_transaction::Recipient,
    },
};

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
        }
    }

    /// Returns the transaction ID, or an empty string if not yet assigned.
    pub fn id(&self) -> &str {
        self.id.as_deref().unwrap_or("")
    }

    /// Updates the transaction ID after the pending transaction is created.
    pub fn update_id(&mut self, id: String) {
        self.id = Some(id);
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
    pub password: String,
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
        password: String,
        network: Network,
        confirmation_window: u64,
    ) -> Result<Self, anyhow::Error> {
        let connection = db_pool.get()?;
        let account_of_processed_transaction: AccountRow = db::get_account_by_name(&connection, &account_name)?
            .ok_or_else(|| anyhow!("Account with name '{}' not found", &account_name))?;

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

    fn validate_transaction_creation_request(
        &mut self,
        processed_transaction: &ProcessedTransaction,
    ) -> Result<(), anyhow::Error> {
        let conn = self.get_connection()?;
        if db::check_if_transaction_was_already_completed_by_idempotency_key(
            &conn,
            &processed_transaction.idempotency_key,
            self.account.id,
        )? {
            return Err(anyhow!(
                "A pending transaction with the same idempotency key already exists"
            ));
        }

        let sender_address = self.account.get_address(self.network, &self.password)?;
        if !sender_address
            .features()
            .contains(TariAddressFeatures::create_one_sided_only())
        {
            return Err(anyhow!("The sender address does not support one-sided transactions."));
        }

        Ok(())
    }

    fn check_if_transaction_expired(&self, processed_transaction: &ProcessedTransaction) -> Result<(), anyhow::Error> {
        let conn = self.get_connection()?;
        let is_expired = db::check_if_transaction_is_expired_by_idempotency_key(
            &conn,
            &processed_transaction.idempotency_key,
            self.account.id,
        )?;

        if is_expired {
            db::update_pending_transaction_status(
                &conn,
                processed_transaction.id(),
                PendingTransactionStatus::Expired,
            )?;
            return Err(anyhow!("The transaction has expired."));
        }

        Ok(())
    }

    fn create_utxo_selection(
        &self,
        processed_transaction: &ProcessedTransaction,
    ) -> Result<UtxoSelection, anyhow::Error> {
        let connection = self.get_connection()?;
        let amount = processed_transaction.recipient.amount;
        let num_outputs = 1;
        let estimated_output_size = None;

        let input_selector = InputSelector::new(self.account.id, self.confirmation_window);
        let utxo_selection = input_selector.fetch_unspent_outputs(
            &connection,
            amount,
            num_outputs,
            self.fee_per_gram,
            estimated_output_size,
        )?;
        Ok(utxo_selection)
    }

    fn create_pending_transaction(
        &self,
        processed_transaction: &mut ProcessedTransaction,
    ) -> Result<String, anyhow::Error> {
        let connection = self.get_connection()?;

        let expires_at = Utc::now() + Duration::seconds(processed_transaction.seconds_to_lock_utxos as i64);
        let utxo_selection = self.create_utxo_selection(processed_transaction)?;

        let pending_tx_id = db::create_pending_transaction(
            &connection,
            &processed_transaction.idempotency_key,
            self.account.id,
            utxo_selection.requires_change_output,
            utxo_selection.total_value,
            utxo_selection.fee_without_change,
            utxo_selection.fee_with_change,
            expires_at,
        )?;

        for utxo in &utxo_selection.utxos {
            db::lock_output(&connection, utxo.id, &pending_tx_id, expires_at)?;
        }

        if processed_transaction.selected_utxos.is_empty() {
            processed_transaction.selected_utxos = utxo_selection.utxos.clone();
        }

        Ok(pending_tx_id)
    }

    fn create_or_find_pending_transaction(
        &self,
        processed_transaction: &mut ProcessedTransaction,
    ) -> Result<String, anyhow::Error> {
        let connection = self.get_connection()?;

        let response = db::find_pending_transaction_by_idempotency_key(
            &connection,
            &processed_transaction.idempotency_key,
            self.account.id,
        )?;
        if let Some(pending_tx) = response {
            Ok(pending_tx.id.to_string())
        } else {
            let pending_tx_id = self.create_pending_transaction(processed_transaction)?;
            Ok(pending_tx_id)
        }
    }
    fn prepare_transaction_builder(
        &self,
        locked_utxos: Vec<WalletOutput>,
    ) -> Result<TransactionBuilder<KeyManager>, anyhow::Error> {
        let key_manager = self.account.get_key_manager(&self.password)?;
        let consensus_constants = ConsensusConstantsBuilder::new(self.network).build();
        let mut tx_builder = TransactionBuilder::new(consensus_constants, key_manager.clone(), self.network)?;

        tx_builder.with_fee_per_gram(self.fee_per_gram);

        for utxo in &locked_utxos {
            tx_builder.with_input(utxo.clone())?;
        }

        Ok(tx_builder)
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
        let connection = self.get_connection()?;

        let mut processed_transaction =
            ProcessedTransaction::new(None, idempotency_key, recipient.clone(), seconds_to_lock_utxo);

        self.validate_transaction_creation_request(&processed_transaction)?;

        let pending_transaction_id = self.create_or_find_pending_transaction(&mut processed_transaction)?;
        processed_transaction.update_id(pending_transaction_id.clone());

        let result: Result<PrepareOneSidedTransactionForSigningResult, anyhow::Error> = (|| {
            let mut utxo_selection = processed_transaction.selected_utxos.clone();
            if utxo_selection.is_empty() {
                let db_utxo_selection = db::fetch_outputs_by_lock_request_id(&connection, processed_transaction.id())?;
                utxo_selection = db_utxo_selection;
            }
            let utxos = utxo_selection.into_iter().map(|db_out| db_out.output).collect();

            let tx_builder = self.prepare_transaction_builder(utxos)?;

            let sender_address = self.account.get_address(self.network, &self.password)?;
            let tx_id = TxId::new_random();

            let payment_id = match &recipient.payment_id {
                Some(s) => MemoField::new_open_from_string(s, TxType::PaymentToOther).map_err(|e| anyhow!(e))?,
                None => MemoField::new_empty(),
            };
            let output_features = OutputFeatures::default();

            let payment_recipient = PaymentRecipient {
                amount: recipient.amount,
                output_features: output_features.clone(),
                address: recipient.address.clone(),
                payment_id: payment_id.clone(),
            };

            let res = prepare_one_sided_transaction_for_signing(
                tx_id,
                tx_builder,
                &[payment_recipient],
                payment_id,
                sender_address,
            )?;

            Ok(res)
        })();

        match result {
            Ok(res) => {
                self.processed_transactions = processed_transaction;
                Ok(res)
            },
            Err(e) => {
                warn!(target: "audit", error:% = e; "Transaction creation failed, unlocking funds");
                self.fail_and_unlock_pending_transaction(&connection, &pending_transaction_id);
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
    /// Returns a [`DisplayedTransaction`] representing the broadcasted transaction,
    /// suitable for immediate display in the UI while awaiting confirmation.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The transaction lock has expired
    /// - Transaction serialization fails
    /// - The network rejects the transaction
    /// - Database operations fail
    ///
    /// # Network Rejection
    ///
    /// If the network rejects the transaction, the error reason is recorded
    /// and the transaction is marked as rejected in the database. The locked
    /// UTXOs are also released.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // After signing the transaction externally
    /// let displayed_tx = sender.finalize_transaction_and_broadcast(
    ///     signed_result,
    ///     "http://localhost:18080".to_string(),
    /// ).await?;
    ///
    /// println!("Transaction {} broadcasted!", displayed_tx.id);
    /// ```
    pub async fn finalize_transaction_and_broadcast(
        &self,
        signed_transaction_result: SignedOneSidedTransactionResult,
        grpc_address: String,
    ) -> Result<DisplayedTransaction, anyhow::Error> {
        let connection = self.get_connection()?;
        let processed_transaction = &self.processed_transactions;
        let account_id = self.account.id;

        info!(
            target: "audit",
            id = processed_transaction.id();
            "Finalizing and broadcasting transaction"
        );

        self.check_if_transaction_expired(processed_transaction)
            .inspect_err(|e| {
                warn!(target: "audit", error:% = e; "Transaction finalization preparation failed");
                self.fail_and_unlock_pending_transaction(&connection, processed_transaction.id());
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
                self.fail_and_unlock_pending_transaction(&connection, processed_transaction.id());
            })
            .map_err(|e| anyhow!("Failed to serialize transaction: {}", e))?;

        let sent_output_hash = signed_transaction_result
            .signed_transaction
            .sent_hashes
            .first()
            .map(hex::encode);

        db::update_pending_transaction_status(
            &connection,
            processed_transaction.id(),
            crate::models::PendingTransactionStatus::Completed,
        )
        .inspect_err(|e| {
            warn!(target: "audit", error:% = e; "Transaction finalization preparation failed");
            self.fail_and_unlock_pending_transaction(&connection, processed_transaction.id());
        })?;
        let completed_tx_id = signed_transaction_result.signed_transaction.tx_id;
        let signed_transaction = signed_transaction_result.signed_transaction.clone();
        db::create_completed_transaction(
            &connection,
            account_id,
            processed_transaction.id(),
            &kernel_excess,
            &serialized_transaction,
            sent_output_hash,
            completed_tx_id,
        )
        .inspect_err(|e| {
            warn!(target: "audit", error:% = e; "Transaction finalization preparation failed");
            self.fail_and_unlock_pending_transaction(&connection, processed_transaction.id());
        })?;

        let wallet_http_client = WalletHttpClient::new(grpc_address.parse()?)?;
        let response = wallet_http_client
            .submit_transaction(signed_transaction_result.signed_transaction.transaction)
            .await;

        if let Err(e) = response {
            warn!(
                target: "audit",
                id = processed_transaction.id(),
                reason:% = e;
                "Transaction submission failed"
            );
            db::mark_completed_transaction_as_rejected(
                &connection,
                completed_tx_id,
                &format!("Transaction submission failed: {}", e),
            )?;
            self.fail_and_unlock_pending_transaction(&connection, processed_transaction.id());

            return Err(anyhow!("Transaction submission failed: {}", e));
        }
        let submission_response = response.expect("Already checked for Err above");

        if submission_response.accepted {
            info!(
                target: "audit",
                id = completed_tx_id.to_string().as_str();
                "Transaction accepted by network"
            );
            db::mark_completed_transaction_as_broadcasted(&connection, completed_tx_id, 1)?;
        } else if submission_response.rejection_reason != TxSubmissionRejectionReason::AlreadyMined {
            warn!(
                target: "audit",
                id = completed_tx_id.to_string().as_str(),
                reason:% = submission_response.rejection_reason;
                "Transaction rejected by network"
            );
            db::mark_completed_transaction_as_rejected(
                &connection,
                completed_tx_id,
                &submission_response.rejection_reason.to_string(),
            )?;
            self.fail_and_unlock_pending_transaction(&connection, processed_transaction.id());

            return Err(anyhow!(
                "Transaction was not accepted by the network: {}",
                submission_response.rejection_reason
            ));
        }

        // Build and save DisplayedTransaction for immediate UI display
        let displayed_transaction =
            self.build_pending_displayed_transaction(processed_transaction, &signed_transaction, actual_fee)?;

        db::insert_displayed_transaction(&connection, &displayed_transaction)?;

        Ok(displayed_transaction)
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
            debit += input.output.value();
        }

        for output in &signed_transaction.outputs {
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
            credit += change.value();
        }

        let tx = DisplayedTransactionBuilder::new()
            .account_id(self.account.id)
            .direction(TransactionDirection::Outgoing)
            .status(TransactionDisplayStatus::Pending)
            .source(TransactionSource::OneSided)
            .credits_and_debits(credit, debit)
            .message(recipient.payment_id.clone())
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

    fn fail_and_unlock_pending_transaction(
        &self,
        connection: &PooledConnection<SqliteConnectionManager>,
        pending_tx_id: &str,
    ) {
        if let Err(e) =
            db::update_pending_transaction_status(connection, pending_tx_id, PendingTransactionStatus::Expired)
        {
            error!(target: "audit", error:% = e; "Failed to update pending transaction status during cleanup");
        }

        if let Err(e) = db::unlock_outputs_for_request(connection, pending_tx_id) {
            error!(target: "audit", error:% = e; "Failed to unlock outputs during cleanup");
        }
    }
}
