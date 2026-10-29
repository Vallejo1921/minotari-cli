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
use crate::transactions::fee_estimator::{estimated_output_size_for_payment_id, measure_output_size};
use crate::transactions::fund_locker::validate_fee_per_gram;
use crate::transactions::idempotency::{IdempotencyBinding, IdempotencyOperation, RequestFingerprint};
use crate::transactions::input_selector::map_change_required_error;
use crate::{api::types::LockFundsResult, db::AccountRow};
use anyhow::anyhow;
use log::info;
use tari_common::configuration::Network;
use tari_common_types::{
    tari_address::{TariAddress, TariAddressFeatures},
    transaction::TxId,
    types::FixedHash,
};
use tari_script::script;
use tari_transaction_components::offline_signing::models::PaymentRecipient;
use tari_transaction_components::{
    TransactionBuilder,
    consensus::ConsensusConstantsBuilder,
    offline_signing::{models::PrepareOneSidedTransactionForSigningResult, prepare_one_sided_transaction_for_signing},
    tari_amount::MicroMinotari,
    transaction_components::{MemoField, OutputFeatures, memo_field::TxType},
};
use zeroize::Zeroizing;

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

impl Recipient {
    /// The payment id bytes the output carries. When the address has the payment id feature,
    /// its embedded id replaces `payment_id`, as the console wallet does: exchanges put the
    /// deposit reference in the address, and it can be any bytes, not only text.
    pub fn payment_id_bytes(&self) -> Option<Vec<u8>> {
        if self.address.features().contains(TariAddressFeatures::PAYMENT_ID) {
            Some(self.address.get_memo_field_payment_id_bytes())
        } else {
            self.payment_id.as_ref().map(|s| s.as_bytes().to_vec())
        }
    }

    /// The plain memo for this recipient, before [`recipient_memo`] adds the sender address.
    pub fn memo(&self) -> Result<MemoField, anyhow::Error> {
        match self.payment_id_bytes() {
            Some(bytes) => MemoField::new_open(bytes, TxType::PaymentToOther).map_err(|e| anyhow!(e)),
            None => Ok(MemoField::new_empty()),
        }
    }
}

/// The memo a recipient's output carries: the payment id, with the sender's address on it.
///
/// A one-sided payment has no handshake, so the encrypted memo is the only place the recipient's
/// wallet can learn who paid it. Without the address every wallet shows the sender as the
/// all-zero default address. This matches what the console wallet writes: fee zero, sender
/// one-sided, and `PaymentToSelf` when paying our own address.
///
/// Only the recipient's memo gets the address. The change memo is built by the transaction
/// builder from the plain payment id.
pub fn recipient_memo(
    payment_id: MemoField,
    sender_address: &TariAddress,
    recipient_address: &TariAddress,
) -> Result<MemoField, anyhow::Error> {
    let tx_type = if recipient_address == sender_address {
        TxType::PaymentToSelf
    } else {
        TxType::PaymentToOther
    };
    payment_id
        .add_sender_address(sender_address.clone(), true, MicroMinotari::zero(), Some(tx_type))
        .map_err(|e| anyhow!("Payment id does not fit alongside the sender address: {e}"))
}

/// Builds every memo a send to `recipients` will carry and returns the per-output size input
/// selection has to charge for them.
///
/// Call this before locking funds. A payment id embedded in an address can be up to 256 bytes,
/// more than a memo holds once the sender address goes in with it, and the unsigned-transaction
/// paths do not release their lock when the build fails. The change memo is the tightest: the
/// builder writes it at signing time with the first recipient's address, which carries the
/// embedded id a second time. It is built here the way `create_change_memo` builds it.
pub fn check_memos_and_estimate_output_size(
    recipients: &[Recipient],
    sender_address: &TariAddress,
) -> Result<usize, anyhow::Error> {
    let first = recipients.first().ok_or_else(|| anyhow!("No recipients provided"))?;
    let mut memos = recipients
        .iter()
        .map(|r| recipient_memo(r.memo()?, sender_address, &r.address))
        .collect::<Result<Vec<_>, _>>()?;
    // The builder records one sent hash per recipient output, and none past two.
    let sent_hashes = if recipients.len() <= 2 { recipients.len() } else { 0 };
    memos.push(
        MemoField::new_transaction_info(
            first.address.clone(),
            MicroMinotari::zero(),
            MicroMinotari::zero(),
            true,
            TxType::PaymentToOther,
            vec![FixedHash::zero(); sent_hashes],
            first.payment_id_bytes().unwrap_or_default(),
        )
        .map_err(|e| anyhow!("Payment id does not fit in the change output's memo: {e}"))?,
    );

    let longest = recipients
        .iter()
        .map(|r| r.payment_id_bytes().map_or(0, |bytes| bytes.len()))
        .max()
        .unwrap_or(0);
    let script = script!(PushPubKey(Box::default())).map_err(|e| anyhow!("Failed to build the default script: {e}"))?;
    memos
        .iter()
        .try_fold(estimated_output_size_for_payment_id(longest)?, |size, memo| {
            Ok(size.max(measure_output_size(&OutputFeatures::default(), &script, memo)?))
        })
}

/// Binds an idempotency key to an unsigned-transaction request.
///
/// The recipients are the whole point of the binding. Without them, replaying a
/// client's key with a different `recipients` list would return that client's
/// locked UTXOs and build an unsigned transaction paying whoever the replay
/// named. Every caller of `create_unsigned_transaction` must build its binding
/// here so no entry point can forget a field.
pub fn unsigned_transaction_binding(
    idempotency_key: Option<String>,
    account_id: i64,
    recipients: &[Recipient],
    fee_per_gram: MicroMinotari,
    seconds_to_lock_utxos: u64,
    confirmation_window: u64,
) -> IdempotencyBinding {
    let operation = IdempotencyOperation::CreateUnsignedTransaction;
    let mut fingerprint = RequestFingerprint::new(operation)
        .field("account_id", account_id.to_le_bytes())
        .field("fee_per_gram", fee_per_gram.as_u64().to_le_bytes())
        .field("seconds_to_lock_utxos", seconds_to_lock_utxos.to_le_bytes())
        .field("confirmation_window", confirmation_window.to_le_bytes())
        // Bound the list itself, so dropping or appending a recipient cannot be
        // hidden by the remaining entries hashing the same.
        .field("recipient_count", (recipients.len() as u64).to_le_bytes());
    for recipient in recipients {
        fingerprint = fingerprint
            .field("recipient_address", recipient.address.to_base58())
            .field("recipient_amount", recipient.amount.as_u64().to_le_bytes())
            .optional_field("recipient_payment_id", recipient.payment_id.as_deref());
    }
    IdempotencyBinding::new(idempotency_key, operation, fingerprint)
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
    pub password: Zeroizing<String>,
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
    pub fn new(db_pool: SqlitePool, network: Network, password: Zeroizing<String>) -> Self {
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
        validate_fee_per_gram(fee_per_gram)?;

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
        // Every send carries a change output, so the wallet's scan can see it land.
        tx_builder.with_change_required();

        for utxo in &locked_funds.utxos {
            tx_builder.with_input(utxo.clone())?;
        }

        let tx_id = TxId::new_random();
        let output_features = OutputFeatures::default();
        let payment_recipients = recipients
            .iter()
            .map(|r| {
                Ok(PaymentRecipient {
                    amount: r.amount,
                    output_features: output_features.clone(),
                    address: r.address.clone(),
                    payment_id: recipient_memo(r.memo()?, &sender_address, &r.address)?,
                })
            })
            .collect::<Result<Vec<_>, anyhow::Error>>()?;

        // Use first recipient's payment_id, without the sender address, as the overall transaction memo
        let main_payment_id = recipients.first().expect("Already checked").memo()?;

        let result = prepare_one_sided_transaction_for_signing(
            &key_manager,
            tx_id,
            tx_builder,
            &payment_recipients,
            main_payment_id,
            sender_address,
        )
        .map_err(map_change_required_error)?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use tari_common_types::types::{CompressedPublicKey, PrivateKey};
    use tari_transaction_components::offline_signing::{
        ConfirmationMode, PayloadSummary, present_payload_summary, sign_locked_transaction,
    };

    use super::*;
    use crate::transactions::{burn::tests::setup_funded_account, fund_locker::FundLocker};

    const FEE: MicroMinotari = MicroMinotari(5);

    fn deposit(payment_id_len: usize) -> Recipient {
        Recipient {
            address: TariAddress::new_dual_address_with_default_features(
                CompressedPublicKey::from_secret_key(&PrivateKey::from(7u64)),
                CompressedPublicKey::from_secret_key(&PrivateKey::from(9u64)),
                Network::LocalNet,
            )
            .expect("address")
            .with_memo_field_payment_id(vec![0xff; payment_id_len])
            .expect("payment id"),
            amount: MicroMinotari(1_000),
            payment_id: None,
        }
    }

    /// The whole send without the check: lock, build the unsigned transaction, sign it.
    fn signs(recipient: Recipient) -> bool {
        let (pool, account, _temp) = setup_funded_account(1_000_000);
        let mut conn = pool.get().expect("conn");
        let recipients = vec![recipient];
        let binding = unsigned_transaction_binding(None, account.id, &recipients, FEE, 3600, 100);
        let locked = FundLocker::new()
            .lock(
                &mut conn,
                account.id,
                MicroMinotari(1_000),
                1,
                FEE,
                None,
                binding,
                3600,
                100,
            )
            .expect("lock");
        let one_sided = OneSidedTransaction::new(pool.clone(), Network::LocalNet, Zeroizing::new("pass".to_string()));
        let Ok(prepared) = one_sided.create_unsigned_transaction(&account, locked, recipients, FEE) else {
            return false;
        };
        let summary = PayloadSummary::from_one_sided(prepared);
        let confirmation = present_payload_summary(
            &summary,
            ConfirmationMode::NonInteractive,
            &mut std::io::sink(),
            &mut std::io::empty(),
        )
        .expect("summary");
        let key_manager = account.get_key_manager("pass").expect("key manager");
        sign_locked_transaction(
            &key_manager,
            ConsensusConstantsBuilder::new(Network::LocalNet).build(),
            Network::LocalNet,
            summary.confirm(confirmation).expect("confirm"),
        )
        .map_err(map_change_required_error)
        .is_ok()
    }

    /// The check has to refuse exactly the embedded ids the signer cannot build, so a send it
    /// lets through never fails with funds already locked, and none it refuses would have worked.
    #[test]
    fn the_memo_check_matches_what_signing_can_build() {
        let (_pool, account, _temp) = setup_funded_account(1_000_000);
        let sender_address = account
            .get_address(Network::LocalNet, &Zeroizing::new("pass".to_string()))
            .expect("address");
        let passes_check = |r: Recipient| check_memos_and_estimate_output_size(&[r], &sender_address).is_ok();

        assert!(passes_check(deposit(8)));
        assert!(
            !passes_check(deposit(256)),
            "the largest id an address holds cannot fit"
        );
        let longest = (0..=256)
            .rev()
            .find(|&len| passes_check(deposit(len)))
            .expect("some id fits");
        assert!(
            signs(deposit(longest)),
            "the check let through an id that cannot be signed"
        );
        assert!(!signs(deposit(longest + 1)), "the check refused an id that signs");
    }
}
