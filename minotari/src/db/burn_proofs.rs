use log::info;
use rusqlite::{Connection, named_params};
use serde::Deserialize;
use serde_rusqlite::from_rows;
use tari_common_types::types::FixedHash;

use crate::db::error::{WalletDbError, WalletDbResult};

/// Status values for a burn proof record. `pending_merkle` predates the burn output proof and now means the record is
/// waiting for its burn output proof.
pub const BURN_PROOF_STATUS_PENDING_MERKLE: &str = "pending_merkle";
pub const BURN_PROOF_STATUS_COMPLETE: &str = "complete";

/// Data needed to create a burn proof record after a burn transaction is broadcast.
pub struct NewBurnProof {
    pub account_id: i64,
    pub output_hash: FixedHash,
    pub commitment: Vec<u8>,
    pub claim_public_key: String,
    pub ownership_proof_nonce: Vec<u8>,
    pub ownership_proof_sig: Vec<u8>,
    pub kernel_excess: Vec<u8>,
    pub kernel_excess_nonce: Vec<u8>,
    pub kernel_excess_sig: Vec<u8>,
    pub sender_offset_public_key: Vec<u8>,
    pub encrypted_data: Vec<u8>,
    pub value: u64,
    pub kernel_fee: u64,
    pub kernel_lock_height: u64,
}

/// A burn proof record fetched from the database.
///
/// The `kernel_*` fields and `sender_offset_public_key` are vestigial: the claim proof is now built from the burn
/// output proof, which carries the output. They are kept to avoid a migration.
#[derive(Debug, Deserialize)]
pub struct DbBurnProof {
    pub id: i64,
    pub account_id: i64,
    pub output_hash: FixedHash,
    pub commitment: Vec<u8>,
    pub claim_public_key: String,
    pub ownership_proof_nonce: Vec<u8>,
    pub ownership_proof_sig: Vec<u8>,
    pub kernel_excess: Vec<u8>,
    pub kernel_excess_nonce: Vec<u8>,
    pub kernel_excess_sig: Vec<u8>,
    pub sender_offset_public_key: Vec<u8>,
    pub encrypted_data: Vec<u8>,
    pub value: i64,
    pub kernel_fee: i64,
    pub kernel_lock_height: i64,
    pub status: String,
}

pub fn insert_burn_proof(conn: &Connection, proof: &NewBurnProof) -> WalletDbResult<i64> {
    info!(
        target: "audit",
        account_id = proof.account_id;
        "DB: Inserting burn proof"
    );

    #[allow(clippy::cast_possible_wrap)]
    let value = proof.value as i64;
    #[allow(clippy::cast_possible_wrap)]
    let kernel_fee = proof.kernel_fee as i64;
    #[allow(clippy::cast_possible_wrap)]
    let kernel_lock_height = proof.kernel_lock_height as i64;

    conn.execute(
        r#"
        INSERT INTO burn_proofs (
            account_id, output_hash, commitment, claim_public_key,
            ownership_proof_nonce, ownership_proof_sig,
            kernel_excess, kernel_excess_nonce, kernel_excess_sig,
            sender_offset_public_key, encrypted_data, value,
            kernel_fee, kernel_lock_height, status
        )
        VALUES (
            :account_id, :output_hash, :commitment, :claim_public_key,
            :ownership_proof_nonce, :ownership_proof_sig,
            :kernel_excess, :kernel_excess_nonce, :kernel_excess_sig,
            :sender_offset_public_key, :encrypted_data, :value,
            :kernel_fee, :kernel_lock_height, :status
        )
        "#,
        named_params! {
            ":account_id": proof.account_id,
            ":output_hash": proof.output_hash.as_slice(),
            ":commitment": &proof.commitment,
            ":claim_public_key": &proof.claim_public_key,
            ":ownership_proof_nonce": &proof.ownership_proof_nonce,
            ":ownership_proof_sig": &proof.ownership_proof_sig,
            ":kernel_excess": &proof.kernel_excess,
            ":kernel_excess_nonce": &proof.kernel_excess_nonce,
            ":kernel_excess_sig": &proof.kernel_excess_sig,
            ":sender_offset_public_key": &proof.sender_offset_public_key,
            ":encrypted_data": &proof.encrypted_data,
            ":value": value,
            ":kernel_fee": kernel_fee,
            ":kernel_lock_height": kernel_lock_height,
            ":status": BURN_PROOF_STATUS_PENDING_MERKLE,
        },
    )?;

    Ok(conn.last_insert_rowid())
}

pub fn get_burn_proof_by_output_hash(
    conn: &Connection,
    output_hash: &FixedHash,
) -> WalletDbResult<Option<DbBurnProof>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, account_id, output_hash, commitment, claim_public_key,
               ownership_proof_nonce, ownership_proof_sig,
               kernel_excess, kernel_excess_nonce, kernel_excess_sig,
               sender_offset_public_key, encrypted_data, value,
               kernel_fee, kernel_lock_height, status
        FROM burn_proofs
        WHERE output_hash = :output_hash
        "#,
    )?;

    let rows = stmt.query(named_params! { ":output_hash": output_hash.as_slice() })?;
    let result: Option<DbBurnProof> = from_rows(rows).next().transpose()?;
    Ok(result)
}

pub fn get_pending_burn_proofs(conn: &Connection) -> WalletDbResult<Vec<DbBurnProof>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, account_id, output_hash, commitment, claim_public_key,
               ownership_proof_nonce, ownership_proof_sig,
               kernel_excess, kernel_excess_nonce, kernel_excess_sig,
               sender_offset_public_key, encrypted_data, value,
               kernel_fee, kernel_lock_height, status
        FROM burn_proofs
        WHERE status = :status
        ORDER BY created_at ASC
        "#,
    )?;

    let rows = stmt.query(named_params! { ":status": BURN_PROOF_STATUS_PENDING_MERKLE })?;
    let results: Vec<DbBurnProof> = from_rows(rows).collect::<Result<Vec<_>, _>>()?;
    Ok(results)
}

pub fn mark_burn_proof_complete(conn: &Connection, id: i64) -> WalletDbResult<()> {
    info!(target: "audit", burn_proof_id = id; "DB: Marking burn proof complete");

    conn.execute(
        r#"
        UPDATE burn_proofs
        SET status = :status, updated_at = CURRENT_TIMESTAMP
        WHERE id = :id
        "#,
        named_params! {
            ":status": BURN_PROOF_STATUS_COMPLETE,
            ":id": id,
        },
    )
    .map_err(WalletDbError::from)?;

    Ok(())
}
