//! Validator node exit transaction construction.
//!
//! This module provides functionality for creating validator node exit
//! transactions on the Tari base layer. The exit embeds the validator
//! node's public key and signature into a pay-to-self transaction with special
//! [`OutputFeatures`], locking the consensus-required minimum deposit.
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
//! 2. Build [`OutputFeatures::for_validator_node_exit`]
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

/// Parameters for validator node exit
///
/// The `validator_node_signature` must be pre-computed by the validator node using
/// [`ValidatorNodeSignature::sign_for_exit`] with the node's private key.
pub struct ValidatorNodeExitParams {
    /// The validator node's public key (the signing key used to create `validator_node_signature`).
    pub validator_node_public_key: CompressedPublicKey,
    /// Pre-computed Schnorr signature over
    /// `(network | vn_pk | nonce | sidechain_pk? | activation_epoch | max_epoch)`.
    pub validator_node_signature: CompressedSignature,
    /// Activation epoch of the registration being exited. Binds the exit to that registration so it
    /// cannot be replayed against a later re-registration of the same validator node.
    pub activation_epoch: VnEpoch,
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

/// Creates an unsigned validator node exit transaction.
///
/// The returned [`PrepareOneSidedTransactionForSigningResult`] is signed and broadcast
/// by the caller, following the same flow as [`create_validator_node_registration_tx`].
///
/// # Errors
///
/// Returns an error if:
/// - The account is not a [`WalletType::SeedWords`] wallet
/// - The validator node signature is invalid
/// - There are insufficient funds for the consensus-required deposit
/// - Transaction construction fails
#[allow(clippy::too_many_arguments)]
pub fn create_validator_node_exit_tx(
    account: &AccountRow,
    params: ValidatorNodeExitParams,
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
            "Validator node exit requires a SeedWords wallet, not a view-only wallet"
        ));
    }

    let vn_sig = ValidatorNodeSignature::new(params.validator_node_public_key, params.validator_node_signature);
    let sidechain_pk = params
        .sidechain_deployment_key
        .as_ref()
        .map(CompressedPublicKey::from_secret_key);
    if !vn_sig.is_valid_exit_signature_for(
        network.as_byte(),
        sidechain_pk.as_ref(),
        params.activation_epoch,
        params.max_epoch,
    ) {
        return Err(anyhow!("Invalid validator node exit signature"));
    }

    let output_features = OutputFeatures::for_validator_node_exit(
        vn_sig,
        params.sidechain_deployment_key.as_ref(),
        params.activation_epoch,
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
        IdempotencyOperation::ValidatorNodeExit,
    )
}
