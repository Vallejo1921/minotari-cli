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
use crate::transactions::fee_estimator::one_sided_output_sizes;
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
    types::CompressedPublicKey,
};
use tari_transaction_components::offline_signing::models::PaymentRecipient;
use tari_transaction_components::{
    TransactionBuilder,
    consensus::ConsensusConstantsBuilder,
    offline_signing::{models::PrepareOneSidedTransactionForSigningResult, prepare_one_sided_transaction_for_signing},
    tari_amount::MicroMinotari,
    transaction_components::{MAX_TRANSACTION_OUTPUTS, MemoField, OutputFeatures, memo_field::TxType},
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

    /// Its payment id as a plain memo: the transaction-level memo, which the
    /// change memo carries.
    pub fn payment_memo(&self) -> Result<MemoField, anyhow::Error> {
        match self.payment_id_bytes() {
            Some(bytes) => MemoField::new_open(bytes, TxType::PaymentToOther).map_err(|e| anyhow!(e)),
            None => Ok(MemoField::new_empty()),
        }
    }

    /// The memo this recipient's output carries: its payment id with the
    /// sender's address on it ([`recipient_memo`]).
    pub fn output_memo(&self, sender_address: &TariAddress) -> Result<MemoField, anyhow::Error> {
        recipient_memo(self.payment_memo()?, sender_address, &self.address)
    }
}

/// An address shaped like every account's own on `network` (dual, one-sided,
/// no payment id; see `AccountRow::get_address`), for measuring the memos that
/// carry the sender's address without decrypting the wallet. An address's size
/// does not depend on its keys.
pub fn sender_address_for_sizing(network: Network) -> Result<TariAddress, anyhow::Error> {
    TariAddress::new_dual_address(
        CompressedPublicKey::default(),
        CompressedPublicKey::default(),
        network,
        TariAddressFeatures::create_one_sided_only(),
        None,
    )
    .map_err(|e| anyhow!("Failed to build an address for sizing: {e}"))
}

/// Checks `recipients` for a send and returns the sum of their amounts.
///
/// Fails when the list is empty or longer than a transaction can carry
/// alongside its change output, any amount is zero, the sum overflows, or a
/// payment id does not fit in its recipient's memo or the change memo. The
/// same address may appear more than once; it receives one output per entry.
pub fn total_recipient_amount(recipients: &[Recipient], network: Network) -> Result<MicroMinotari, anyhow::Error> {
    if recipients.is_empty() {
        return Err(anyhow!("No recipients provided"));
    }
    // One output is kept for the change.
    let max_recipients = MAX_TRANSACTION_OUTPUTS.saturating_sub(1);
    if recipients.len() > max_recipients {
        return Err(anyhow!("Too many recipients: at most {max_recipients} are allowed"));
    }
    let mut total = MicroMinotari::zero();
    for recipient in recipients {
        if recipient.amount == MicroMinotari::zero() {
            return Err(anyhow!("Recipient amount must be greater than zero"));
        }
        total = total
            .checked_add(recipient.amount)
            .ok_or_else(|| anyhow!("Total amount of the recipients overflows"))?;
    }
    // Builds every memo the send will carry, so a payment id that does not fit fails here.
    one_sided_output_sizes(recipients, network)?;
    Ok(total)
}

/// Fails when any recipient's address is for a network other than `network`:
/// a payment there could never be received.
pub fn check_recipient_networks(recipients: &[Recipient], network: Network) -> Result<(), anyhow::Error> {
    for recipient in recipients {
        let address_network = recipient.address.network();
        if address_network != network {
            return Err(anyhow!(
                "Recipient address is for {address_network}, but this wallet is on {network}"
            ));
        }
    }
    Ok(())
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
    send_all: bool,
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
    if send_all {
        fingerprint = fingerprint.field("send_all", [1u8]);
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
    /// * `recipients` - List of recipients, one output each
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
    /// - Account key manager cannot be decrypted
    /// - Transaction building fails
    /// - Payment ID encoding fails
    ///
    /// # Memos
    ///
    /// Each recipient's output carries that recipient's own `payment_id`. The
    /// transaction-level memo (kept in the change output) is the first
    /// recipient's `payment_id`.
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
        let mut payment_recipients = Vec::with_capacity(recipients.len());
        for r in &recipients {
            payment_recipients.push(PaymentRecipient {
                amount: r.amount,
                output_features: output_features.clone(),
                address: r.address.clone(),
                payment_id: r.output_memo(&sender_address)?,
            });
        }

        // Use first recipient's payment_id, without the sender address, as the overall transaction memo
        let main_payment_id = recipients.first().expect("Already checked").payment_memo()?;

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
    use super::*;

    fn recipient(payment_id: Option<String>) -> Recipient {
        Recipient {
            address: TariAddress::default(),
            amount: MicroMinotari(1_000),
            payment_id,
        }
    }

    #[test]
    fn a_send_may_have_one_recipient_fewer_than_a_transaction_has_outputs() {
        let most = vec![recipient(None); MAX_TRANSACTION_OUTPUTS - 1];
        assert_eq!(
            total_recipient_amount(&most, Network::MainNet).expect("allowed"),
            MicroMinotari(1_000 * (MAX_TRANSACTION_OUTPUTS as u64 - 1))
        );
        let too_many = vec![recipient(None); MAX_TRANSACTION_OUTPUTS];
        let err = total_recipient_amount(&too_many, Network::MainNet).expect_err("no room for change");
        assert!(err.to_string().contains("Too many recipients"), "got: {err}");
    }

    #[test]
    fn a_recipient_on_another_network_is_refused() {
        let on = |network| Recipient {
            address: TariAddress::new_dual_address(
                tari_common_types::types::CompressedPublicKey::default(),
                tari_common_types::types::CompressedPublicKey::default(),
                network,
                tari_common_types::tari_address::TariAddressFeatures::create_one_sided_only(),
                None,
            )
            .expect("address"),
            amount: MicroMinotari(1_000),
            payment_id: None,
        };
        check_recipient_networks(&[on(Network::LocalNet)], Network::LocalNet).expect("same network");
        let err = check_recipient_networks(&[on(Network::LocalNet), on(Network::MainNet)], Network::LocalNet)
            .expect_err("another network");
        assert!(err.to_string().contains("this wallet is on"), "got: {err}");
    }

    /// Sizing with the stand-in sender address measures the same memo size as
    /// the account's real address, for a send to another wallet and to itself.
    #[test]
    fn the_sizing_sender_address_measures_like_a_real_one() {
        let real = TariAddress::new_dual_address(
            CompressedPublicKey::from_secret_key(&tari_common_types::types::PrivateKey::from(7u64)),
            CompressedPublicKey::from_secret_key(&tari_common_types::types::PrivateKey::from(9u64)),
            Network::MainNet,
            TariAddressFeatures::create_one_sided_only(),
            None,
        )
        .expect("address");
        let stand_in = sender_address_for_sizing(Network::MainNet).expect("stand-in");
        for to in [TariAddress::default(), real.clone()] {
            let recipient = Recipient {
                address: to,
                amount: MicroMinotari(1_000),
                payment_id: Some("invoice-1".to_string()),
            };
            assert_eq!(
                recipient.output_memo(&stand_in).unwrap().get_size(),
                recipient.output_memo(&real).unwrap().get_size()
            );
        }
    }

    /// A payment id that fits neither memo is refused, not sent without its memo.
    #[test]
    fn a_payment_id_too_long_for_a_memo_is_refused() {
        total_recipient_amount(&[recipient(Some("invoice-1".to_string()))], Network::MainNet).expect("fits");
        total_recipient_amount(&[recipient(Some("x".repeat(300)))], Network::MainNet)
            .expect_err("too long for any memo");
        // Fits a recipient's open memo, but not the change memo, which also holds an address and a hash.
        let long = "x".repeat(200);
        assert!(MemoField::new_open_from_string(&long, TxType::PaymentToOther).is_ok());
        total_recipient_amount(&[recipient(Some(long))], Network::MainNet).expect_err("too long for the change memo");
    }

    fn deposit(payment_id_len: usize) -> Recipient {
        use tari_common_types::types::PrivateKey;
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

    /// The whole send without the pre-lock check: lock, build the unsigned transaction, sign it.
    fn signs(recipient: Recipient) -> bool {
        use crate::transactions::{burn::tests::setup_funded_account, fund_locker::FundLocker};
        use tari_transaction_components::offline_signing::{
            ConfirmationMode, PayloadSummary, present_payload_summary, sign_locked_transaction,
        };

        let fee = MicroMinotari(5);
        let (pool, account, _temp) = setup_funded_account(1_000_000);
        let mut conn = pool.get().expect("conn");
        let recipients = vec![recipient];
        let binding = unsigned_transaction_binding(None, account.id, &recipients, fee, 3600, 100, false);
        let locked = FundLocker::new()
            .lock(
                &mut conn,
                account.id,
                MicroMinotari(1_000),
                1,
                fee,
                None,
                binding,
                3600,
                100,
            )
            .expect("lock");
        let one_sided = OneSidedTransaction::new(pool.clone(), Network::LocalNet, Zeroizing::new("pass".to_string()));
        let Ok(prepared) = one_sided.create_unsigned_transaction(&account, locked, recipients, fee) else {
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

    /// An address's embedded id is counted twice in the change memo (in the address and as the
    /// payment id), and the change memo is only built at signing. The pre-lock check has to
    /// refuse exactly the ids signing cannot build, so nothing it lets through fails with the
    /// funds locked and nothing it refuses would have worked.
    #[test]
    fn the_pre_lock_check_matches_what_signing_can_build_for_embedded_ids() {
        let passes_check = |r: Recipient| total_recipient_amount(&[r], Network::LocalNet).is_ok();
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

    /// An embedded id replaces the typed payment id, as its exact bytes, text or not.
    #[test]
    fn an_address_payment_id_replaces_the_typed_one_as_its_bytes() {
        let embedded = vec![0x9c, 0xf1, 0x03, 0x00, 0xff, 0x80, 0x01, 0x00];
        let mut r = deposit(0);
        r.address = r
            .address
            .with_memo_field_payment_id(embedded.clone())
            .expect("payment id");
        r.payment_id = Some("typed message".to_string());
        assert_eq!(r.payment_id_bytes(), Some(embedded.clone()));
        assert_eq!(r.payment_memo().expect("memo").payment_id_as_bytes(), embedded);
        assert_eq!(
            recipient(Some("typed".into())).payment_id_bytes(),
            Some(b"typed".to_vec())
        );
    }
}
