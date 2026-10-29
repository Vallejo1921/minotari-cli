//! Validator node registration transaction construction.
//!
//! This module provides functionality for creating validator node registration
//! transactions on the Tari base layer. The registration embeds the validator
//! node's public key and signature into a pay-to-self transaction with special
//! [`OutputFeatures`], locking a minimum deposit defined by consensus constants.
//!
//! # Pattern
//!
//! The caller pre-computes the [`ValidatorNodeSignature`] on the validator node
//! side, then passes the public key and signature to the wallet for transaction
//! construction. Only [`WalletType::SeedWords`] wallets are supported.
//!
//! # Flow
//!
//! 1. Validate the pre-computed [`ValidatorNodeSignature`]
//! 2. Build [`OutputFeatures::for_validator_node_registration`]
//! 3. Lock the deposit UTXOs via [`FundLocker`] and prepare the transaction for signing

use anyhow::anyhow;
use rusqlite::Connection;
use tari_common::configuration::Network;
use tari_common_types::{
    epoch::VnEpoch,
    types::{CompressedPublicKey, CompressedSignature, PrivateKey},
};
use tari_transaction_components::{
    key_manager::wallet_types::WalletType,
    offline_signing::models::PrepareOneSidedTransactionForSigningResult,
    tari_amount::MicroMinotari,
    transaction_components::{OutputFeatures, ValidatorNodeSignature},
};

use super::common::build_vn_pay_to_self_tx;
use crate::db::AccountRow;
use crate::transactions::idempotency::IdempotencyOperation;

/// Parameters for validator node registration
///
/// The `validator_node_signature` must be pre-computed by the validator node using
/// [`ValidatorNodeSignature::sign_for_registration`] with the node's private key.
pub struct ValidatorNodeRegistrationParams {
    /// The validator node's public key (the signing key used to create `validator_node_signature`).
    pub validator_node_public_key: CompressedPublicKey,
    /// Pre-computed Schnorr signature over `(network | vn_pk | nonce | sidechain_pk? | claim_pk | max_epoch)`.
    pub validator_node_signature: CompressedSignature,
    /// Public key used to claim validator node rewards.
    pub claim_public_key: CompressedPublicKey,
    /// Maximum epoch for replay protection.
    pub max_epoch: VnEpoch,
    /// Fee rate in MicroMinotari per gram.
    pub fee_per_gram: MicroMinotari,
    /// Optional payment memo attached to the transaction.
    pub payment_id: Option<String>,
    /// Optional sidechain deployment private key. If provided, derives the sidechain public key
    /// included in the signature message and creates a [`SideChainId`] proof.
    pub sidechain_deployment_key: Option<PrivateKey>,
}

/// Creates an unsigned validator node registration transaction.
///
/// The returned [`PrepareOneSidedTransactionForSigningResult`] can be written to a
/// file for external signing, following the same flow as [`CreateUnsignedTransaction`].
///
/// # Errors
///
/// Returns an error if:
/// - The account is not a [`WalletType::SeedWords`] wallet
/// - The validator node signature is invalid
/// - There are insufficient funds for the consensus-required deposit
/// - Transaction construction fails
#[allow(clippy::too_many_arguments)]
pub fn create_validator_node_registration_tx(
    account: &AccountRow,
    params: ValidatorNodeRegistrationParams,
    conn: &mut Connection,
    network: Network,
    password: &str,
    idempotency_key: Option<String>,
    seconds_to_lock: u64,
    confirmation_window: u64,
) -> Result<PrepareOneSidedTransactionForSigningResult, anyhow::Error> {
    let wallet_type = account.decrypt_wallet_type(password)?;
    if !matches!(wallet_type, WalletType::SeedWords(_)) {
        return Err(anyhow!(
            "Validator node registration requires a SeedWords wallet, not a view-only wallet"
        ));
    }

    let vn_sig = ValidatorNodeSignature::new(params.validator_node_public_key, params.validator_node_signature);
    let sidechain_pk = params
        .sidechain_deployment_key
        .as_ref()
        .map(CompressedPublicKey::from_secret_key);
    if !vn_sig.is_valid_registration_signature_for(
        network.as_byte(),
        sidechain_pk.as_ref(),
        &params.claim_public_key,
        params.max_epoch,
    ) {
        return Err(anyhow!("Invalid validator node registration signature"));
    }

    let output_features = OutputFeatures::for_validator_node_registration(
        vn_sig,
        params.claim_public_key,
        params.sidechain_deployment_key.as_ref(),
        params.max_epoch,
    );

    build_vn_pay_to_self_tx(
        account,
        conn,
        network,
        password,
        output_features,
        params.fee_per_gram,
        params.payment_id.as_deref(),
        idempotency_key,
        seconds_to_lock,
        confirmation_window,
        IdempotencyOperation::ValidatorNodeRegistration,
    )
}
