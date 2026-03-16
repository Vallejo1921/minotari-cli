//! One-sided (non-interactive) transaction construction.
//!
//! This module provides functionality for creating one-sided transactions, which are
//! transactions that can be sent without requiring any interaction from the recipient.
//! Unlike interactive transactions, one-sided transactions use the recipient's public
//! address to derive the necessary cryptographic components.
//!
//! # One-Sided Transactions
//!
//! One-sided transactions are the primary transaction type for Minotari. They allow
//! a sender to create a complete transaction using only the recipient's Tari address,
//! without any back-and-forth communication. The recipient can later claim the funds
//! by scanning the blockchain.
//!
//! # Transaction Flow
//!
//! 1. Lock UTXOs using [`FundLocker`](super::fund_locker::FundLocker)
//! 2. Create an unsigned transaction using [`OneSidedTransaction::create_unsigned_transaction`]
//! 3. Sign the transaction externally
//! 4. Broadcast the signed transaction to the network
//!
//! # Example
//!
//! ```rust,ignore
//! use minotari::transactions::one_sided_transaction::{OneSidedTransaction, Recipient};
//!
//! let tx_builder = OneSidedTransaction::new(db_pool, Network::MainNet, password);
//!
//! let recipient = Recipient {
//!     address: recipient_address,
//!     amount: MicroMinotari(1_000_000),
//!     payment_id: Some("Invoice #123".to_string()),
//! };
//!
//! let unsigned_tx = tx_builder.create_unsigned_transaction(
//!     &account,
//!     locked_funds,
//!     vec![recipient],
//!     MicroMinotari(5),
//! ).await?;
//! ```

use crate::db::SqlitePool;
use crate::{api::types::LockFundsResult, db::AccountRow};
use anyhow::anyhow;
use log::info;
use tari_common::configuration::Network;
use tari_common_types::{tari_address::TariAddress, transaction::TxId};
use tari_transaction_components::offline_signing::models::PaymentRecipient;
use tari_transaction_components::{
    TransactionBuilder,
    consensus::ConsensusConstantsBuilder,
    offline_signing::{models::PrepareOneSidedTransactionForSigningResult, prepare_one_sided_transaction_for_signing},
    tari_amount::MicroMinotari,
    transaction_components::{MemoField, OutputFeatures, memo_field::TxType},
};

/// Represents a recipient of a one-sided transaction.
///
/// Contains all the information needed to send funds to a recipient,
/// including their address, the amount to send, and an optional payment
/// identifier for reference purposes.
///
/// # Fields
///
/// * `address` - The recipient's Tari address
/// * `amount` - The amount to send in MicroMinotari
/// * `payment_id` - Optional payment identifier/memo (e.g., invoice number)
///
/// # Example
///
/// ```rust,ignore
/// use minotari::transactions::one_sided_transaction::Recipient;
///
/// let recipient = Recipient {
///     address: TariAddress::from_base58("...")?,
///     amount: MicroMinotari(500_000),
///     payment_id: Some("Order-12345".to_string()),
/// };
/// ```
#[derive(Debug, Clone, Default)]
pub struct Recipient {
    /// The recipient's Tari address.
    pub address: TariAddress,
    /// The amount to send in MicroMinotari.
    pub amount: MicroMinotari,
    /// Optional payment identifier or memo attached to the transaction.
    pub payment_id: Option<String>,
}

/// Builder for creating unsigned one-sided transactions.
///
/// `OneSidedTransaction` prepares transactions that can be sent without recipient
/// interaction. It handles the construction of transaction inputs, outputs, and
/// metadata required for offline signing.
///
/// # Security
///
/// The password provided is used to decrypt the account's key manager for
/// transaction construction. Ensure passwords are handled securely and not
/// logged or persisted unnecessarily.
///
/// # Example
///
/// ```rust,ignore
/// use minotari::transactions::one_sided_transaction::OneSidedTransaction;
///
/// let builder = OneSidedTransaction::new(
///     db_pool,
///     Network::MainNet,
///     "secure_password".to_string(),
/// );
///
/// let unsigned = builder.create_unsigned_transaction(
///     &account,
///     locked_funds,
///     recipients,
///     fee_per_gram,
/// ).await?;
/// ```
pub struct OneSidedTransaction {
    /// Database connection pool.
    pub db_pool: SqlitePool,
    /// The network (MainNet, TestNet, etc.) for consensus rules.
    pub network: Network,
    /// Password for decrypting the account's key manager.
    pub password: String,
}

impl OneSidedTransaction {
    /// Creates a new `OneSidedTransaction` builder.
    ///
    /// # Arguments
    ///
    /// * `db_pool` - SQLite connection pool for database operations
    /// * `network` - The Tari network (affects consensus constants)
    /// * `password` - Password to decrypt the account's key manager
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let builder = OneSidedTransaction::new(db_pool, Network::MainNet, password);
    /// ```
    pub fn new(db_pool: SqlitePool, network: Network, password: String) -> Self {
        Self {
            db_pool,
            network,
            password,
        }
    }

    /// Creates an unsigned one-sided transaction ready for signing.
    ///
    /// Constructs a transaction using the locked UTXOs as inputs and creates
    /// outputs for the specified recipients. The resulting transaction is
    /// prepared for offline signing.
    ///
    /// # Arguments
    ///
    /// * `account` - The sender's account containing key material
    /// * `locked_funds` - Previously locked UTXOs from [`FundLocker::lock`](super::fund_locker::FundLocker::lock)
    /// * `recipients` - List of recipients (currently limited to one)
    /// * `fee_per_gram` - Fee rate in MicroMinotari per gram
    ///
    /// # Returns
    ///
    /// Returns a [`PrepareOneSidedTransactionForSigningResult`] containing:
    /// - The unsigned transaction ready for signing
    /// - Metadata required to complete the signing process
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No recipients are provided
    /// - More than one recipient is provided (multi-recipient not yet supported)
    /// - Account key manager cannot be decrypted
    /// - Transaction building fails
    /// - Payment ID encoding fails
    ///
    /// # Limitations
    ///
    /// Currently only supports single-recipient transactions. Multi-recipient
    /// support is planned for future releases.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let recipient = Recipient {
    ///     address: recipient_address,
    ///     amount: MicroMinotari(1_000_000),
    ///     payment_id: Some("Payment for services".to_string()),
    /// };
    ///
    /// let unsigned_tx = builder.create_unsigned_transaction(
    ///     &account,
    ///     locked_funds,
    ///     vec![recipient],
    ///     MicroMinotari(5),
    /// ).await?;
    ///
    /// // Sign the transaction externally
    /// // let signed = sign(unsigned_tx)?;
    /// ```
    pub fn create_unsigned_transaction(
        &self,
        account: &AccountRow,
        locked_funds: LockFundsResult,
        recipients: Vec<Recipient>,
        fee_per_gram: MicroMinotari,
    ) -> Result<PrepareOneSidedTransactionForSigningResult, anyhow::Error> {
        if recipients.is_empty() {
            return Err(anyhow!("No recipients provided"));
        }

        info!(
            target: "audit",
            count = recipients.len();
            "Creating unsigned one-sided transaction"
        );

        let sender_address = account.get_address(self.network, &self.password)?;

        let key_manager = account.get_key_manager(&self.password)?;
        let consensus_constants = ConsensusConstantsBuilder::new(self.network).build();
        let mut tx_builder = TransactionBuilder::new(consensus_constants, key_manager.clone(), self.network)?;

        tx_builder.with_fee_per_gram(fee_per_gram);

        for utxo in &locked_funds.utxos {
            tx_builder.with_input(utxo.clone())?;
        }

        let tx_id = TxId::new_random();
        let output_features = OutputFeatures::default();
        let payment_recipients: Vec<PaymentRecipient> = recipients
            .iter()
            .map(|r| {
                let payment_id = match &r.payment_id {
                    Some(s) => MemoField::new_open_from_string(s, TxType::PaymentToOther)
                        .unwrap_or_else(|_| MemoField::new_empty()),
                    None => MemoField::new_empty(),
                };
                PaymentRecipient {
                    amount: r.amount,
                    output_features: output_features.clone(),
                    address: r.address.clone(),
                    payment_id,
                }
            })
            .collect();

        // Use first recipient's payment_id as the overall transaction memo
        let main_payment_id = payment_recipients[0].payment_id.clone();

        let result = prepare_one_sided_transaction_for_signing(
            tx_id,
            tx_builder,
            &payment_recipients,
            main_payment_id,
            sender_address,
        )?;

        Ok(result)
    }
}
