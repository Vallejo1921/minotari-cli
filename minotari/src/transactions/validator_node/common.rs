//! Shared helpers for validator node pay-to-self transaction construction.
//!
//! Both VN operations (registration and exit) lock the consensus-required
//! minimum deposit and build a single pay-to-self output with operation-specific
//! [`OutputFeatures`]. This module extracts that common pattern.

use anyhow::anyhow;
use log::info;
use rusqlite::Connection;
use tari_common::configuration::Network;
use tari_common_types::transaction::TxId;
use tari_transaction_components::{
    TransactionBuilder,
    consensus::ConsensusConstantsBuilder,
    offline_signing::{
        models::{PaymentRecipient, PrepareOneSidedTransactionForSigningResult},
        prepare_one_sided_transaction_for_signing,
    },
    tari_amount::MicroMinotari,
    transaction_components::{MemoField, OutputFeatures, memo_field::TxType},
};

use crate::{
    db::AccountRow,
    transactions::{
        fund_locker::FundLocker,
        idempotency::{IdempotencyBinding, IdempotencyOperation, RequestFingerprint},
        input_selector::map_change_required_error,
    },
};

/// Locks the VN registration deposit and prepares a pay-to-self transaction for signing.
///
/// Used by both VN operations (registration and exit) which share the same
/// transaction shape: one output sent back to the sender, carrying operation-specific
/// `output_features`.
///
/// `operation` both names the transaction in the audit log and scopes the
/// idempotency key, so a registration key cannot be redeemed for an exit.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_vn_pay_to_self_tx(
    account: &AccountRow,
    conn: &mut Connection,
    network: Network,
    password: &str,
    output_features: OutputFeatures,
    fee_per_gram: MicroMinotari,
    payment_id: Option<&str>,
    idempotency_key: Option<String>,
    seconds_to_lock: u64,
    confirmation_window: u64,
    operation: IdempotencyOperation,
) -> Result<PrepareOneSidedTransactionForSigningResult, anyhow::Error> {
    let consensus_constants = ConsensusConstantsBuilder::new(network).build();
    let deposit_amount = consensus_constants.validator_node_registration_min_deposit_amount();

    info!(
        target: "audit",
        deposit_amount = deposit_amount.as_u64();
        "Creating {} transaction", operation.description()
    );

    // `output_features` carries everything that distinguishes one VN operation
    // from another — the node public key, its signature, the claim key, the max
    // epoch — so hashing its canonical encoding binds the
    // key to the specific node action being requested.
    let encoded_features = serde_json::to_vec(&output_features)
        .map_err(|e| anyhow!("Failed to encode validator node output features: {}", e))?;
    let idempotency = IdempotencyBinding::new(
        idempotency_key,
        operation,
        RequestFingerprint::new(operation)
            .field("account_id", account.id.to_le_bytes())
            .field("deposit_amount", deposit_amount.as_u64().to_le_bytes())
            .field("output_features", encoded_features)
            .field("fee_per_gram", fee_per_gram.as_u64().to_le_bytes())
            .optional_field("payment_id", payment_id)
            .field("seconds_to_lock", seconds_to_lock.to_le_bytes())
            .field("confirmation_window", confirmation_window.to_le_bytes()),
    );

    let sender_address = account.get_address(network, password)?;
    let fund_locker = FundLocker::new();
    let locked_funds = fund_locker.lock(
        conn,
        account.id,
        deposit_amount,
        1,
        fee_per_gram,
        None,
        idempotency,
        seconds_to_lock,
        confirmation_window,
    )?;

    let key_manager = account.get_key_manager(password)?;
    let mut tx_builder = TransactionBuilder::new(consensus_constants, key_manager.clone(), network)?;
    tx_builder.with_fee_per_gram(fee_per_gram);
    // Every send carries a change output, so the wallet's scan can see it land.
    tx_builder.with_change_required();
    for utxo in &locked_funds.utxos {
        tx_builder.with_input(utxo.clone())?;
    }

    let tx_id = TxId::new_random();
    let memo = payment_id
        .and_then(|s| MemoField::new_open_from_string(s, TxType::PaymentToOther).ok())
        .unwrap_or_default();

    let payment_recipient = PaymentRecipient {
        amount: deposit_amount,
        output_features,
        address: sender_address.clone(),
        payment_id: memo.clone(),
    };

    prepare_one_sided_transaction_for_signing(
        &key_manager,
        tx_id,
        tx_builder,
        &[payment_recipient],
        memo,
        sender_address,
    )
    .map_err(map_change_required_error)
}
