//! Burn transaction construction.
//!
//! Creates a burn transaction that destroys L1 funds and produces a
//! [`NewBurnProof`] that can later be combined with a burn output proof
//! to form a complete L2 claim proof.
//!
//! # Flow
//!
//! 1. Lock UTXOs via [`FundLocker`]
//! 2. Derive the stealth claim key `C` for the recipient (see [`burn_claim_material`])
//! 3. Build a burn output with [`OutputFeatures::create_burn_confidential_output`] carrying `C`
//! 4. Set burn kernel features on the transaction
//! 5. Build + sign the transaction using the wallet key manager
//! 6. Generate the ownership proof (Schnorr signature over the commitment and `C`)
//! 7. Return the signed [`Transaction`] and a [`NewBurnProof`] for DB storage

use anyhow::anyhow;
use log::info;
use rusqlite::Connection;
use tari_common::configuration::Network;
use tari_common_types::{
    tari_address::{TariAddress, TariAddressFeatures},
    transaction::TxId,
    types::{CompressedPublicKey, CompressedSignature, PrivateKey},
};
use tari_script::script;
use tari_transaction_components::{
    MicroMinotari, TransactionBuilder,
    consensus::ConsensusConstantsBuilder,
    fee::recipient_output_features_and_scripts_size,
    key_manager::{KeyManager, SecretTransactionKeyManagerInterface, TariKeyId, TransactionKeyManagerInterface},
    transaction_builder::PendingOutput,
    transaction_components::{
        KernelFeatures, OutputFeatures, WalletOutput, WalletOutputBuilder,
        memo_field::{MemoField, TxType},
    },
};
use tari_utilities::{ByteArray, hex::Hex};

use crate::{
    db::{AccountRow, NewBurnProof},
    models::PendingTransactionStatus,
    transactions::{
        fee_estimator::{estimated_output_size_for_payment_id, measure_output_size},
        fund_locker::FundLocker,
        idempotency::{IdempotencyBinding, IdempotencyConflict, IdempotencyOperation, RequestFingerprint},
        input_selector::map_change_required_error,
    },
};

/// Result returned from a successful burn transaction build.
pub struct BurnTxResult {
    /// The fully signed transaction, ready to broadcast.
    pub transaction: tari_transaction_components::transaction_components::Transaction,
    /// Output hash of the burn output (used to link the burn_proofs DB record).
    pub output_hash: tari_common_types::types::FixedHash,
    /// Partial proof data to persist in the `burn_proofs` table.
    pub new_burn_proof: NewBurnProof,
    /// The generated tx_id.
    pub tx_id: TxId,
    /// The burn's change output. Written to `outputs` as `UNCONFIRMED` by
    /// [`persist_burn_records`] so the wallet's scan can see the burn land.
    pub change_output: Option<WalletOutput>,
    /// The account's private view key, needed to derive the change output's `tx_id`.
    pub view_key: PrivateKey,
}

/// Parameters for a burn transaction.
pub struct BurnTxParams {
    pub account_id: i64,
    pub amount: MicroMinotari,
    /// The L2 account key the burn is claimable by. Required: [`create_burn_tx`] refuses to
    /// build a burn nobody can claim.
    pub claim_public_key: Option<CompressedPublicKey>,
    /// Optional sidechain deployment key for L2 template burns.
    pub sidechain_deployment_key: Option<PrivateKey>,
    pub fee_per_gram: MicroMinotari,
    pub payment_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub seconds_to_lock: u64,
    pub confirmation_window: u64,
}

impl BurnTxParams {
    /// Binds this burn's idempotency key to the burn it was issued for.
    ///
    /// A burn is irreversible, so the binding matters twice over: it stops a key
    /// minted at `/lock_funds` from being redeemed here (which would broadcast a
    /// burn over UTXOs the client only meant to reserve), and it stops a burn
    /// key from being replayed with a different amount or a different L2 claim
    /// key.
    fn idempotency_binding(&self) -> IdempotencyBinding {
        let operation = IdempotencyOperation::BurnFunds;
        let fingerprint = RequestFingerprint::new(operation)
            .field("account_id", self.account_id.to_le_bytes())
            .field("amount", self.amount.as_u64().to_le_bytes())
            .optional_field("claim_public_key", self.claim_public_key.as_ref().map(|k| k.to_hex()))
            // The deployment key decides which sidechain may claim the burn, so
            // it is part of the request even though it is a secret. Only its
            // derived public key is hashed; the fingerprint is stored in the
            // database and read back in error paths.
            .optional_field(
                "sidechain_deployment_public_key",
                self.sidechain_deployment_key
                    .as_ref()
                    .map(|k| CompressedPublicKey::from_secret_key(k).to_hex()),
            )
            .field("fee_per_gram", self.fee_per_gram.as_u64().to_le_bytes())
            .optional_field("payment_id", self.payment_id.as_deref())
            .field("seconds_to_lock", self.seconds_to_lock.to_le_bytes())
            .field("confirmation_window", self.confirmation_window.to_le_bytes());
        IdempotencyBinding::new(self.idempotency_key.clone(), operation, fingerprint)
    }
}

/// Builds, signs, and returns a burn transaction along with its partial proof data.
///
/// A `claim_public_key` must be supplied, as this function is designed to
/// always produce a burn proof.
pub fn create_burn_tx(
    account: &AccountRow,
    conn: &mut Connection,
    network: Network,
    password: &str,
    params: BurnTxParams,
) -> Result<BurnTxResult, anyhow::Error> {
    let Some(claim_public_key) = params.claim_public_key.as_ref() else {
        return Err(anyhow!("claim_public_key is required to generate a burn proof"));
    };
    // The claim key is the only route back to these funds, and a burn cannot be
    // undone. `CompressedPublicKey::from_canonical_bytes` accepts the Ristretto
    // identity element (32 zero bytes) — a valid point that nobody holds the secret
    // scalar for — so an all-zero claim key parses cleanly and produces a burn proof
    // that can never be redeemed. Refuse it here, before anything is built, rather
    // than at claim time when the money is already gone.
    if crate::utils::crypto::is_identity_public_key(claim_public_key) {
        return Err(anyhow!(
            "claim_public_key is the identity element; a burn to it could never be claimed"
        ));
    }

    let consensus_constants = ConsensusConstantsBuilder::new(network).build();

    info!(
        target: "audit",
        amount = params.amount.as_u64(),
        account_id = params.account_id;
        "Creating burn transaction"
    );

    let sender_address = account.get_address(network, password)?;
    let sidechain_id = params
        .sidechain_deployment_key
        .as_ref()
        .map(CompressedPublicKey::from_secret_key);

    // The on-chain features carry the stealth claim key C, which does not exist until the
    // output's keys do; P stands in for it here because the two are the same size.
    let output_features = OutputFeatures::create_burn_confidential_output(
        claim_public_key.clone(),
        params.sidechain_deployment_key.as_ref(),
    );

    let memo = params
        .payment_id
        .as_deref()
        .and_then(|s| MemoField::new_open_from_string(s, TxType::Burn).ok())
        .unwrap_or_else(|| MemoField::new_open_from_string("", TxType::Burn).unwrap_or_default());

    // The burn output is built by hand rather than from a recipient spec, so the script is ours to
    // choose; it is needed both to measure the output for the reservation and to build it.
    let burn_script = script!(Nop)?;
    let weight_params = *consensus_constants.transaction_weight_params();

    // Measure before locking, not after. A burn output carries the claim key and the sidechain
    // key in its features, so it is materially larger than the generic estimate; selection that
    // charged the generic size would lock inputs that cannot cover the real fee, and the burn
    // would fail at build time with the funds already reserved. The change output is measured
    // too, because selection charges one size for every output it plans.
    let burn_output_size = measure_output_size(&output_features, &burn_script, &memo)?;
    let change_output_size = estimated_output_size_for_payment_id(params.payment_id.as_deref().map_or(0, str::len))?;
    let estimated_output_size = burn_output_size.max(change_output_size);

    let fund_locker = FundLocker::new();
    let locked_funds = fund_locker.lock(
        conn,
        account.id,
        params.amount,
        1,
        params.fee_per_gram,
        Some(estimated_output_size),
        params.idempotency_binding(),
        params.seconds_to_lock,
        params.confirmation_window,
    )?;

    // The burn output brings its own sender offset key (below), so the change output's key is
    // the only one the reservation mints, and the key manager refuses to blind the input script
    // keys with none at all. A burn that leaves no change therefore cannot be built: say so now
    // and hand the inputs back, rather than fail on an opaque key manager error with the funds
    // locked until the reservation expires.
    if !locked_funds.requires_change_output {
        release_reservation(conn, account.id, params.idempotency_key.as_deref())?;
        return Err(anyhow!(
            "Burning {} leaves no change output, and an L2 burn needs one; adjust the amount",
            params.amount
        ));
    }

    let key_manager = account.get_key_manager(password)?;

    // Assemble the transaction.
    let mut tx_builder = TransactionBuilder::new(consensus_constants, key_manager.clone(), network)?;
    tx_builder.with_fee_per_gram(params.fee_per_gram);
    // Every send carries a change output, so the wallet's scan can see it land.
    tx_builder.with_change_required();
    tx_builder.with_kernel_features(KernelFeatures::create_burn());
    tx_builder.with_tx_type(TxType::Burn);
    tx_builder.with_memo(memo.clone());

    for utxo in &locked_funds.utxos {
        tx_builder.with_input(utxo.clone())?;
    }

    // The burn output's sender offset key `r` is derived from its commitment mask rather than
    // taken from the builder's reservation, so the proof can be rebuilt from the seed alone if
    // the `burn_proofs` row is lost before the claim is made. The stealth claim key C and the
    // ownership proof both hang off `r`, so they come next.
    let (commitment_mask_key, _script_key) = key_manager.get_next_commitment_mask_and_script_key()?;
    let sender_offset_key = key_manager.derive_burn_sender_offset_key(&commitment_mask_key.key_id)?;
    let (stealth_claim_public_key, ownership_proof) = burn_claim_material(
        &key_manager,
        &sender_offset_key.key_id,
        &commitment_mask_key.key_id,
        params.amount.as_u64(),
        claim_public_key,
        sidechain_id.as_ref(),
    )?;
    let output_features = OutputFeatures::create_burn_confidential_output(
        stealth_claim_public_key,
        params.sidechain_deployment_key.as_ref(),
    );

    // A key the builder did not mint is a key it cannot subtract from the script offset, so its
    // contribution is registered by hand. Ristretto scalar arithmetic: this cannot overflow.
    #[allow(clippy::arithmetic_side_effects)]
    let negated_r = PrivateKey::default() - key_manager.get_private_key(&sender_offset_key.key_id)?;
    tx_builder.with_host_derived_partial_script_offset(negated_r);

    // The encrypted data in the burn output is DH-encrypted to P with `r`, so the L2 wallet can
    // decrypt it with R and its account secret.
    let recovery_key_id = TariKeyId::DHEncryptedData {
        public_key: claim_public_key.clone(),
        private_key: sender_offset_key.key_id.clone().into(),
    };

    // Build the burn output with explicit key material (not stealth-address derivation).
    let burn_output = WalletOutputBuilder::new(params.amount, commitment_mask_key.key_id.clone())
        .with_features(output_features)
        .with_script(burn_script)
        .with_input_data(Default::default())
        .with_sender_offset_public_key(sender_offset_key.pub_key.clone())
        .with_script_key(TariKeyId::Zero)
        .with_minimum_value_promise(MicroMinotari::zero())
        .encrypt_data_for_recovery(&key_manager, Some(&recovery_key_id), memo.clone())?
        .sign_metadata_signature(&key_manager, &sender_offset_key.key_id)?
        .try_build(&key_manager)?;

    let output_hash = burn_output.output_hash();
    let commitment = burn_output.commitment().clone();

    // The reservation is where the fee and the change decision are made, so the burn output is
    // declared to it by value and weight, but as one that brings its own sender offset key. The
    // only key the reservation mints is then the change output's, and it refuses to blind the
    // input script keys with no key at all: an L2 burn that consumes its inputs exactly, leaving
    // no change, cannot be built.
    let pending_burn_output = PendingOutput::custom_sender_offset(
        params.amount,
        recipient_output_features_and_scripts_size(
            &weight_params,
            burn_output.features(),
            burn_output.script(),
            burn_output.covenant(),
            &memo,
        )?,
    );
    tx_builder
        .reserve_sender_offset_keys(&[pending_burn_output])
        .map_err(map_change_required_error)?;

    // Default address used as placeholder — burn outputs have no real "recipient".
    tx_builder.add_recipient(
        TariAddress::new_dual_address(
            key_manager.get_view_key().pub_key,
            sender_address.public_spend_key().clone(),
            network,
            TariAddressFeatures::create_one_sided_only(),
            None,
        )?,
        burn_output,
        sender_offset_key.key_id,
        Some(recovery_key_id),
    )?;

    let finalized = tx_builder.build()?;

    let kernel = finalized
        .transaction
        .body
        .kernels()
        .iter()
        .find(|k| k.features.is_burned())
        .ok_or_else(|| anyhow!("No burn kernel found in transaction"))?;

    // The proof records the recipient's P (the L2 wallet finds its account by it) alongside the
    // ownership proof, which is over C.
    let new_burn_proof = NewBurnProof {
        account_id: params.account_id,
        output_hash,
        commitment: commitment.as_bytes().to_vec(),
        claim_public_key: claim_public_key.to_hex(),
        ownership_proof_nonce: ownership_proof.get_compressed_public_nonce().as_bytes().to_vec(),
        ownership_proof_sig: ownership_proof.get_signature().as_bytes().to_vec(),
        kernel_excess: kernel.excess.as_bytes().to_vec(),
        kernel_excess_nonce: kernel.excess_sig.get_compressed_public_nonce().as_bytes().to_vec(),
        kernel_excess_sig: kernel.excess_sig.get_signature().as_bytes().to_vec(),
        sender_offset_public_key: sender_offset_key.pub_key.as_bytes().to_vec(),
        encrypted_data: finalized
            .sent_outputs
            .first()
            .map(|op| op.output.encrypted_data().to_byte_vec())
            .unwrap_or_default(),
        value: params.amount.as_u64(),
        kernel_fee: kernel.fee.as_u64(),
        kernel_lock_height: kernel.lock_height,
    };

    Ok(BurnTxResult {
        transaction: finalized.transaction,
        output_hash,
        new_burn_proof,
        tx_id: finalized.tx_id,
        change_output: finalized.change,
        view_key: key_manager.get_private_view_key(),
    })
}

/// The claim material for a burn to the L2 account key `P`: the on-wire claim key
/// `C = H(r·P)·G + P`, where `r` is the burn output's sender offset secret, and the ownership
/// proof, a Schnorr signature by the commitment mask over the commitment and `C`.
///
/// The L2 wallet claims with `s = H(R·p) + p`, so the signer of its claim transaction is `C`,
/// and L2 validators bind the ownership proof to that signer. A proof over the raw `P` fails
/// verification on every L2 node, and since a burn cannot be undone the funds would be gone,
/// so `P` itself never goes on the wire.
fn burn_claim_material(
    key_manager: &KeyManager,
    sender_offset_key_id: &TariKeyId,
    commitment_mask_key_id: &TariKeyId,
    amount: u64,
    claim_public_key: &CompressedPublicKey,
    sidechain_id: Option<&CompressedPublicKey>,
) -> Result<(CompressedPublicKey, CompressedSignature), anyhow::Error> {
    let stealth_claim_public_key =
        key_manager.compute_stealth_claim_public_key(sender_offset_key_id, claim_public_key)?;
    let ownership_proof = key_manager.generate_burn_claim_signature(
        commitment_mask_key_id,
        amount,
        &stealth_claim_public_key,
        sidechain_id,
    )?;
    Ok((stealth_claim_public_key, ownership_proof))
}

/// Gives back the inputs a burn reserved but will not spend.
///
/// The reservation is found by its idempotency key, which both callers supply. Without one the
/// lock simply runs out on its own.
fn release_reservation(conn: &Connection, account_id: i64, idempotency_key: Option<&str>) -> Result<(), anyhow::Error> {
    let Some(key) = idempotency_key else {
        return Ok(());
    };
    if let Some(record) = crate::db::find_pending_transaction_record_by_idempotency_key(conn, key, account_id)? {
        crate::db::expire_and_unlock_pending_transaction(conn, &record.id)?;
    }
    Ok(())
}

/// Persists all DB records for a completed burn transaction.
///
/// Inserts the burn proof, then completes the reservation the burn was built
/// against and creates a completed-transaction record. A reservation that is no
/// longer live aborts the whole thing, rolling the proof back with it: see
/// [`claim_burn_reservation`].
///
/// All three writes go in one `IMMEDIATE` transaction and every error is propagated.
/// They are not independent bookkeeping: the pending transaction is what holds this
/// burn's UTXOs locked, and the completed-transaction row is what the monitor and the
/// unlocker use to release them once the burn is mined. Committing the proof while
/// dropping either of the others — which is what logging and continuing did — leaves
/// the inputs reserved against a pending transaction that never completes, so those
/// UTXOs are stranded for good. The caller must see the failure *before* it
/// broadcasts, since the burn itself cannot be undone.
///
/// Call this before broadcasting the transaction so the proof is never lost.
pub fn persist_burn_records(
    conn: &mut Connection,
    result: &BurnTxResult,
    account_id: i64,
    idempotency_key: &str,
) -> Result<(), anyhow::Error> {
    let kernel_excess = result
        .transaction
        .body
        .kernels()
        .iter()
        .find(|k| k.features.is_burned())
        .map(|k| k.excess.as_bytes().to_vec())
        .unwrap_or_default();
    let serialized_tx =
        serde_json::to_vec(&result.transaction).map_err(|e| anyhow!("Failed to serialize transaction: {}", e))?;
    let sent_output_hash = Some(hex::encode(result.output_hash));

    // BEGIN IMMEDIATE: this reads the pending transaction and then rewrites it, and a
    // deferred read->write upgrade can fail with SQLITE_BUSY_SNAPSHOT in WAL mode,
    // which `busy_timeout` does not retry.
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

    crate::db::insert_burn_proof(&tx, &result.new_burn_proof)
        .map_err(|e| anyhow!("Failed to insert burn proof: {}", e))?;

    let pending_tx_id = claim_burn_reservation(&tx, account_id, idempotency_key)?;

    crate::db::update_pending_transaction_status(&tx, &pending_tx_id, PendingTransactionStatus::Completed)
        .map_err(|e| anyhow!("Failed to complete pending transaction for burn: {}", e))?;

    crate::db::create_completed_transaction(
        &tx,
        account_id,
        &pending_tx_id,
        &kernel_excess,
        &serialized_tx,
        sent_output_hash,
        result.tx_id,
    )
    .map_err(|e| anyhow!("Failed to record completed transaction for burn: {}", e))?;

    if let Some(change_output) = &result.change_output {
        crate::db::insert_unconfirmed_change_output(&tx, account_id, &result.view_key, &pending_tx_id, change_output)
            .map_err(|e| anyhow!("Failed to record the change output for burn: {}", e))?;
    }

    tx.commit()?;

    Ok(())
}

/// Finds the reservation this burn was built against, and refuses if it is gone.
///
/// A missing reservation used to be a warning: the proof was committed, `Ok(())`
/// went back, and both callers broadcast regardless. But `create_burn_tx` locks
/// the deposit under this key, so the row existed moments ago and can only have
/// moved since — the daemon's unlocker expiring a short lock while the burn was
/// being signed is enough. Its outputs are then `Unspent` again, and broadcasting
/// destroys funds the wallet believes it still has, with no completed-transaction
/// row for the monitor to find and nothing that can be undone.
///
/// The status is read without a filter so the caller learns *why* rather than
/// being told the key does not exist.
fn claim_burn_reservation(conn: &Connection, account_id: i64, idempotency_key: &str) -> Result<String, anyhow::Error> {
    let record = crate::db::find_pending_transaction_record_by_idempotency_key(conn, idempotency_key, account_id)
        .map_err(|e| anyhow!("Failed to look up pending transaction for burn: {}", e))?
        .ok_or_else(|| {
            anyhow!(
                "Burn has no reservation under idempotency key '{}'; nothing was broadcast",
                idempotency_key
            )
        })?;

    if record.status != PendingTransactionStatus::Pending {
        let key = idempotency_key.to_string();
        let operation = IdempotencyOperation::BurnFunds;
        return Err(match record.status {
            PendingTransactionStatus::Completed => IdempotencyConflict::AlreadyCompleted { key, operation },
            status => IdempotencyConflict::NoLongerActive {
                key,
                operation,
                status: status.to_string(),
            },
        }
        .into());
    }

    Ok(record.id)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        db::{SqlitePool, create_account, get_account_by_name, init_db},
        transactions::idempotency::IdempotencyConflict,
    };
    use chrono::{TimeDelta, Utc};
    use rusqlite::named_params;
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
    use tempfile::tempdir;

    const KEY: &str = "burn-key";

    /// A migrated database holding one account and one live burn reservation.
    fn setup_reservation() -> (SqlitePool, i64, tempfile::TempDir) {
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("test.db")).expect("init db");
        let conn = pool.get().expect("get conn");

        let wallet =
            WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).expect("construct wallet"));
        create_account(&conn, "test", &wallet, "pass").expect("create account");
        let account_id = get_account_by_name(&conn, "test")
            .expect("get account")
            .expect("account exists")
            .id;

        let operation = IdempotencyOperation::BurnFunds;
        let binding = IdempotencyBinding::new(Some(KEY.to_string()), operation, RequestFingerprint::new(operation));
        crate::db::create_pending_transaction(
            &conn,
            KEY,
            &binding,
            account_id,
            false,
            MicroMinotari(1_000),
            MicroMinotari(0),
            MicroMinotari(0),
            Utc::now() + TimeDelta::hours(1),
        )
        .expect("create reservation");

        drop(conn);
        (pool, account_id, temp)
    }

    fn pending_id(pool: &SqlitePool) -> String {
        pool.get()
            .expect("conn")
            .query_row(
                "SELECT id FROM pending_transactions WHERE idempotency_key = :key",
                named_params! { ":key": KEY },
                |row| row.get(0),
            )
            .expect("reservation exists")
    }

    fn conflict(err: &anyhow::Error) -> &IdempotencyConflict {
        err.downcast_ref::<IdempotencyConflict>()
            .unwrap_or_else(|| panic!("expected an IdempotencyConflict, got: {err}"))
    }

    #[test]
    fn a_live_reservation_is_claimed_for_the_burn() {
        let (pool, account_id, _temp) = setup_reservation();

        assert_eq!(
            claim_burn_reservation(&pool.get().expect("conn"), account_id, KEY).expect("the reservation is live"),
            pending_id(&pool),
        );
    }

    /// A reservation released before the burn is persisted must abort it.
    ///
    /// The missing-row case used to be a warning: the proof was committed and
    /// both callers broadcast anyway. With the reservation gone its outputs are
    /// `Unspent` again, so the burn destroyed funds the wallet still believed it
    /// held, with no completed-transaction row and nothing to undo.
    #[test]
    fn a_reservation_released_before_the_burn_aborts_it() {
        for status in [PendingTransactionStatus::Expired, PendingTransactionStatus::Cancelled] {
            let (pool, account_id, _temp) = setup_reservation();
            let conn = pool.get().expect("conn");
            crate::db::update_pending_transaction_status(&conn, &pending_id(&pool), status.clone())
                .expect("release the reservation");

            let err = claim_burn_reservation(&conn, account_id, KEY)
                .expect_err("a released reservation must not be burned against");
            assert!(
                matches!(conflict(&err), IdempotencyConflict::NoLongerActive { .. }),
                "expected a no-longer-active conflict for {status}, got: {err}",
            );
        }
    }

    #[test]
    fn an_already_completed_burn_is_not_persisted_twice() {
        let (pool, account_id, _temp) = setup_reservation();
        let conn = pool.get().expect("conn");
        crate::db::update_pending_transaction_status(&conn, &pending_id(&pool), PendingTransactionStatus::Completed)
            .expect("complete the reservation");

        let err = claim_burn_reservation(&conn, account_id, KEY).expect_err("a completed burn cannot be repeated");
        assert!(
            matches!(conflict(&err), IdempotencyConflict::AlreadyCompleted { .. }),
            "expected an already-completed conflict, got: {err}",
        );
    }

    #[test]
    fn a_burn_without_any_reservation_aborts() {
        let (pool, account_id, _temp) = setup_reservation();
        pool.get()
            .expect("conn")
            .execute("DELETE FROM pending_transactions", [])
            .expect("drop the reservation");

        claim_burn_reservation(&pool.get().expect("conn"), account_id, KEY)
            .expect_err("a burn with no reservation must not be broadcast");
    }

    /// A funded account whose one UTXO is real: its keys live in the account's key manager, so
    /// the builder can sign it and the finished transaction can be checked the way a node would.
    pub(crate) fn setup_funded_account(value: u64) -> (SqlitePool, AccountRow, tempfile::TempDir) {
        use tari_transaction_components::test_helpers::{TestParams, create_wallet_output_with_data};

        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("test.db")).expect("init db");
        let conn = pool.get().expect("get conn");
        let wallet =
            WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).expect("construct wallet"));
        create_account(&conn, "test", &wallet, "pass").expect("create account");
        let account = get_account_by_name(&conn, "test")
            .expect("get account")
            .expect("account exists");
        crate::db::insert_scanned_tip_block(&conn, account.id, 200, &[0u8; 32]).expect("tip block");

        let key_manager = account.get_key_manager("pass").expect("key manager");
        let output = create_wallet_output_with_data(
            script!(Nop).expect("script"),
            OutputFeatures::default(),
            &TestParams::new(&key_manager),
            MicroMinotari(value),
            &key_manager,
        )
        .expect("output");
        conn.execute(
            r#"
            INSERT INTO outputs (
                account_id, tx_id, output_hash, mined_in_block_height, mined_in_block_hash, value,
                mined_timestamp, wallet_output_json, status, confirmed_height, confirmed_hash, is_burn, maturity
            ) VALUES (:account_id, 1, :hash, 100, :hash, :value, :mined_ts, :json, 'UNSPENT', 100, :hash, 0, 0)
            "#,
            named_params! {
                ":account_id": account.id,
                ":hash": output.output_hash().to_vec(),
                ":value": i64::try_from(value).expect("value fits i64"),
                ":mined_ts": Utc::now(),
                ":json": serde_json::to_string(&output).expect("serialize output"),
            },
        )
        .expect("insert output");
        drop(conn);
        (pool, account, temp)
    }

    /// The whole burn, checked as a node would: with `r` registered by hand, the inputs' script
    /// keys and the outputs' sender offset keys must still balance against the script offset.
    #[test]
    fn a_built_burn_balances_its_script_offset_with_the_host_derived_sender_offset() {
        use tari_common_types::types::UncompressedPublicKey as PublicKey;
        use tari_crypto::keys::PublicKey as _;
        use tari_transaction_components::transaction_components::OutputType;

        let (pool, account, _temp) = setup_funded_account(1_000_000);
        let mut conn = pool.get().expect("conn");
        let claim_public_key = KeyManager::new_random()
            .expect("l2 wallet")
            .get_random_key(None, None)
            .expect("account key")
            .pub_key;
        let params = BurnTxParams {
            account_id: account.id,
            amount: MicroMinotari(10_000),
            claim_public_key: Some(claim_public_key.clone()),
            sidechain_deployment_key: None,
            fee_per_gram: MicroMinotari(5),
            payment_id: None,
            idempotency_key: Some(KEY.to_string()),
            seconds_to_lock: 3600,
            confirmation_window: 100,
        };

        let result = create_burn_tx(&account, &mut conn, Network::LocalNet, "pass", params).expect("burn builds");

        let tx = &result.transaction;
        let sum = |keys: Vec<CompressedPublicKey>| {
            keys.iter()
                .map(|k| k.to_public_key().expect("point"))
                .fold(PublicKey::default(), |acc, k| &acc + &k)
        };
        let inputs = sum(tx
            .body
            .inputs()
            .iter()
            .map(|i| i.run_script(None).expect("script key"))
            .collect());
        let outputs = sum(tx
            .body
            .outputs()
            .iter()
            .map(|o| o.sender_offset_public_key.clone())
            .collect());
        assert_eq!(
            &inputs - &outputs,
            PublicKey::from_secret_key(&tx.script_offset),
            "script offset does not balance: the host-derived r is missing or counted twice"
        );

        let burn = tx
            .body
            .outputs()
            .iter()
            .find(|o| o.features.output_type == OutputType::Burn)
            .expect("burn output");
        assert_eq!(
            result.new_burn_proof.sender_offset_public_key,
            burn.sender_offset_public_key.as_bytes().to_vec(),
            "the proof's R must be the burn output's"
        );
        assert_eq!(result.new_burn_proof.claim_public_key, claim_public_key.to_hex());
        assert_eq!(tx.body.outputs().len(), 2, "an L2 burn relies on its change output");
    }

    /// What an L2 validator checks: the commitment mask signed the commitment together with the
    /// claim transaction's signer, which is the stealth key `C`, not the recipient's `P`.
    #[test]
    fn the_ownership_proof_binds_the_stealth_claim_key_not_the_recipient_key() {
        use tari_common_types::types::{CommitmentFactory, CompressedCommitment};
        use tari_crypto::commitment::HomomorphicCommitmentFactory;
        use tari_transaction_components::key_manager::ConfidentialOutputHasher;

        let key_manager = KeyManager::new_random().expect("key manager");
        let (mask, _script_key) = key_manager.get_next_commitment_mask_and_script_key().expect("keys");
        // `r` comes from the mask, so the seed alone rebuilds it, and with it C and the proof.
        let sender_offset = key_manager.derive_burn_sender_offset_key(&mask.key_id).expect("r");
        let again = key_manager
            .derive_burn_sender_offset_key(&mask.key_id)
            .expect("r again");
        assert_eq!(sender_offset.pub_key, again.pub_key, "r must be a function of the mask");
        let recipient = key_manager.get_random_key(None, None).expect("recipient").pub_key;
        let amount = 1_000u64;

        let (stealth_claim_public_key, ownership_proof) = burn_claim_material(
            &key_manager,
            &sender_offset.key_id,
            &mask.key_id,
            amount,
            &recipient,
            None,
        )
        .expect("claim material");
        assert_ne!(
            stealth_claim_public_key, recipient,
            "the recipient's key must never go on the wire"
        );

        let mask_secret = key_manager.get_private_key(&mask.key_id).expect("mask secret");
        let commitment =
            CompressedCommitment::from_commitment(CommitmentFactory::default().commit_value(&mask_secret, amount));
        let mask_public_key = CompressedPublicKey::from_secret_key(&mask_secret)
            .to_public_key()
            .expect("mask pk");
        let sidechain_id: Option<&CompressedPublicKey> = None;
        let message_over = |claimant: &CompressedPublicKey| {
            ConfidentialOutputHasher::new("commitment_signature")
                .chain(&commitment)
                .chain(claimant)
                .chain(&sidechain_id)
                .finalize()
        };
        let signature = ownership_proof.to_schnorr_signature().expect("decompress signature");

        assert!(signature.verify(&mask_public_key, message_over(&stealth_claim_public_key)));
        assert!(
            !signature.verify(&mask_public_key, message_over(&recipient)),
            "a proof over the raw recipient key is exactly what L2 rejects"
        );
    }
}
