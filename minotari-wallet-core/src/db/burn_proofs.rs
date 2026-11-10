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

/// Completed rows whose claim file should be present. The worker uses this to
/// recover a crash between committing completion and publishing the file.
pub fn get_completed_burn_proof_files(conn: &Connection) -> WalletDbResult<Vec<(i64, String, Vec<u8>)>> {
    let mut stmt =
        conn.prepare_cached("SELECT id, claim_public_key, commitment FROM burn_proofs WHERE status = :complete")?;
    let rows = stmt.query_map(named_params! { ":complete": BURN_PROOF_STATUS_COMPLETE }, |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

/// Makes a completed proof eligible for regeneration when its file is absent.
pub fn reset_completed_burn_proof_for_missing_file(conn: &Connection, id: i64) -> WalletDbResult<bool> {
    let updated = conn.execute(
        "UPDATE burn_proofs SET status = :pending, mined_height = NULL, updated_at = CURRENT_TIMESTAMP \
         WHERE id = :id AND status = :complete",
        named_params! {
            ":pending": BURN_PROOF_STATUS_PENDING_MERKLE,
            ":complete": BURN_PROOF_STATUS_COMPLETE,
            ":id": id,
        },
    )?;
    Ok(updated == 1)
}

/// Remembers which scanned block a pending proof needs. The scanner keeps that
/// block hash across pruning so a later rescan can verify an old proof.
pub fn remember_pending_burn_proof_height(conn: &Connection, id: i64, mined_height: u64) -> WalletDbResult<()> {
    let mined_height = i64::try_from(mined_height)
        .map_err(|_| WalletDbError::InvalidInput("Burn proof height exceeds SQLite range".to_string()))?;
    conn.execute(
        "UPDATE burn_proofs SET mined_height = :height WHERE id = :id AND status = :pending",
        named_params! {
            ":height": mined_height,
            ":id": id,
            ":pending": BURN_PROOF_STATUS_PENDING_MERKLE,
        },
    )?;
    Ok(())
}

/// Confirms that a just-published file still belongs to the accepted chain.
pub fn burn_proof_is_current_complete(
    conn: &Connection,
    id: i64,
    mined_height: u64,
    expected_generation: i64,
) -> WalletDbResult<bool> {
    let mined_height = i64::try_from(mined_height)
        .map_err(|_| WalletDbError::InvalidInput("Burn proof height exceeds SQLite range".to_string()))?;
    let current: i64 = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM burn_proofs b JOIN accounts a ON a.id = b.account_id \
         WHERE b.id = :id AND b.status = :complete AND b.mined_height = :height \
           AND a.burn_proof_reorg_generation = :generation)",
        named_params! {
            ":id": id,
            ":complete": BURN_PROOF_STATUS_COMPLETE,
            ":height": mined_height,
            ":generation": expected_generation,
        },
        |row| row.get(0),
    )?;
    Ok(current == 1)
}

/// The account rollback generation and highest block the scanner has recorded.
pub fn burn_proof_scan_state(conn: &Connection, account_id: i64) -> WalletDbResult<(i64, Option<u64>)> {
    let (generation, scanned_height): (i64, Option<i64>) = conn.query_row(
        "SELECT a.burn_proof_reorg_generation, (SELECT MAX(height) FROM scanned_tip_blocks WHERE account_id = a.id) \
         FROM accounts a WHERE a.id = :account_id",
        named_params! { ":account_id": account_id },
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((generation, scanned_height.map(|height| height as u64)))
}

pub fn advance_burn_proof_reorg_generation(conn: &Connection, account_id: i64) -> WalletDbResult<()> {
    conn.execute(
        "UPDATE accounts SET burn_proof_reorg_generation = burn_proof_reorg_generation + 1 WHERE id = :account_id",
        named_params! { ":account_id": account_id },
    )?;
    Ok(())
}

/// Marks a burn proof complete, recording the height of the block it proves the burn in.
pub fn mark_burn_proof_complete(conn: &Connection, id: i64, mined_height: u64) -> WalletDbResult<()> {
    info!(target: "audit", burn_proof_id = id, height = mined_height; "DB: Marking burn proof complete");

    #[allow(clippy::cast_possible_wrap)]
    let mined_height = mined_height as i64;
    conn.execute(
        r#"
        UPDATE burn_proofs
        SET status = :status, mined_height = :mined_height, updated_at = CURRENT_TIMESTAMP
        WHERE id = :id
        "#,
        named_params! {
            ":status": BURN_PROOF_STATUS_COMPLETE,
            ":mined_height": mined_height,
            ":id": id,
        },
    )
    .map_err(WalletDbError::from)?;

    Ok(())
}

/// Completes only a pending proof whose account has not rolled back while the
/// worker fetched it, and whose block has been covered by the scanner.
pub fn mark_burn_proof_complete_if_current(
    conn: &Connection,
    id: i64,
    mined_height: u64,
    block_hash: &[u8],
    expected_generation: i64,
) -> WalletDbResult<bool> {
    let mined_height = i64::try_from(mined_height)
        .map_err(|_| WalletDbError::InvalidInput("Burn proof height exceeds SQLite range".to_string()))?;
    let updated = conn.execute(
        "UPDATE burn_proofs SET status = :complete, mined_height = :height, updated_at = CURRENT_TIMESTAMP \
         WHERE id = :id AND status = :pending AND EXISTS ( \
           SELECT 1 FROM accounts a WHERE a.id = burn_proofs.account_id \
           AND a.burn_proof_reorg_generation = :generation \
           AND EXISTS (SELECT 1 FROM scanned_tip_blocks s WHERE s.account_id = a.id \
             AND s.height = :height AND s.hash = :block_hash) \
         )",
        named_params! {
            ":complete": BURN_PROOF_STATUS_COMPLETE,
            ":pending": BURN_PROOF_STATUS_PENDING_MERKLE,
            ":height": mined_height,
            ":block_hash": block_hash,
            ":generation": expected_generation,
            ":id": id,
        },
    )?;
    Ok(updated == 1)
}

/// Puts back to pending every complete burn proof of `account_id` taken from a block at or above `height`, which a
/// reorg has rolled back. The worker fetches them again (and rewrites their files) from the new chain. Returns how
/// many were reset.
pub fn reset_burn_proofs_from_height(conn: &Connection, account_id: i64, height: u64) -> WalletDbResult<usize> {
    #[allow(clippy::cast_possible_wrap)]
    let height = height as i64;
    let reset = conn.execute(
        r#"
        UPDATE burn_proofs
        SET status = :pending, mined_height = NULL, updated_at = CURRENT_TIMESTAMP
        WHERE account_id = :account_id AND status = :complete
          AND (mined_height IS NULL OR mined_height >= :height)
        "#,
        named_params! {
            ":pending": BURN_PROOF_STATUS_PENDING_MERKLE,
            ":complete": BURN_PROOF_STATUS_COMPLETE,
            ":account_id": account_id,
            ":height": height,
        },
    )?;
    if reset > 0 {
        info!(target: "audit", account_id = account_id, count = reset; "DB: Burn proofs reset to pending by reorg");
    }
    Ok(reset)
}

/// File identifiers for completed proofs invalidated by a rollback.
pub fn burn_proof_files_from_height(
    conn: &Connection,
    account_id: i64,
    height: u64,
) -> WalletDbResult<Vec<(String, Vec<u8>)>> {
    let height = i64::try_from(height)
        .map_err(|_| WalletDbError::InvalidInput("Rollback height exceeds SQLite range".to_string()))?;
    let mut stmt = conn.prepare_cached(
        "SELECT claim_public_key, commitment FROM burn_proofs \
         WHERE account_id = :account_id AND status = :complete \
           AND (mined_height IS NULL OR mined_height >= :height)",
    )?;
    let rows = stmt.query_map(
        named_params! {
            ":account_id": account_id,
            ":complete": BURN_PROOF_STATUS_COMPLETE,
            ":height": height,
        },
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};

    use super::*;
    use crate::db::{
        create_account, get_account_by_name, get_scanned_tip_block_hash_at_height, init_db, insert_scanned_tip_block,
        prune_scanned_tip_blocks,
    };

    fn new_proof(account_id: i64, hash_byte: u8) -> NewBurnProof {
        NewBurnProof {
            account_id,
            output_hash: FixedHash::from([hash_byte; 32]),
            commitment: vec![hash_byte; 32],
            claim_public_key: "00".repeat(32),
            ownership_proof_nonce: vec![0u8; 32],
            ownership_proof_sig: vec![0u8; 32],
            kernel_excess: vec![0u8; 32],
            kernel_excess_nonce: vec![0u8; 32],
            kernel_excess_sig: vec![0u8; 32],
            sender_offset_public_key: vec![0u8; 32],
            encrypted_data: vec![1, 2, 3],
            value: 1_000,
            kernel_fee: 10,
            kernel_lock_height: 0,
        }
    }

    #[test]
    fn a_reorg_resets_only_the_proofs_taken_from_rolled_back_blocks() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pool = init_db(dir.path().join("burn.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
        create_account(&conn, "default", &wallet, "password").unwrap();
        let account_id = get_account_by_name(&conn, "default").unwrap().unwrap().id;

        let below = insert_burn_proof(&conn, &new_proof(account_id, 1)).unwrap();
        let at = insert_burn_proof(&conn, &new_proof(account_id, 2)).unwrap();
        let above = insert_burn_proof(&conn, &new_proof(account_id, 3)).unwrap();
        mark_burn_proof_complete(&conn, below, 99).unwrap();
        mark_burn_proof_complete(&conn, at, 100).unwrap();
        mark_burn_proof_complete(&conn, above, 101).unwrap();

        assert_eq!(reset_burn_proofs_from_height(&conn, account_id, 100).unwrap(), 2);

        let pending: Vec<i64> = get_pending_burn_proofs(&conn).unwrap().iter().map(|p| p.id).collect();
        assert_eq!(pending, vec![at, above]);
    }

    #[test]
    fn a_reorg_resets_legacy_complete_proofs_without_a_mined_height() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pool = init_db(dir.path().join("burn.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
        create_account(&conn, "default", &wallet, "password").unwrap();
        let account_id = get_account_by_name(&conn, "default").unwrap().unwrap().id;
        let legacy = insert_burn_proof(&conn, &new_proof(account_id, 4)).unwrap();
        conn.execute("UPDATE burn_proofs SET status = 'complete' WHERE id = ?1", [legacy])
            .unwrap();

        assert_eq!(burn_proof_files_from_height(&conn, account_id, 100).unwrap().len(), 1);
        assert_eq!(reset_burn_proofs_from_height(&conn, account_id, 100).unwrap(), 1);
        assert_eq!(get_pending_burn_proofs(&conn).unwrap().first().unwrap().id, legacy);
    }

    #[test]
    fn a_completed_proof_with_a_missing_file_can_be_regenerated() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pool = init_db(dir.path().join("burn.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
        create_account(&conn, "default", &wallet, "password").unwrap();
        let account_id = get_account_by_name(&conn, "default").unwrap().unwrap().id;
        let id = insert_burn_proof(&conn, &new_proof(account_id, 5)).unwrap();
        mark_burn_proof_complete(&conn, id, 100).unwrap();

        assert_eq!(get_completed_burn_proof_files(&conn).unwrap().first().unwrap().0, id);
        assert!(reset_completed_burn_proof_for_missing_file(&conn, id).unwrap());
        assert!(!reset_completed_burn_proof_for_missing_file(&conn, id).unwrap());
        assert_eq!(get_pending_burn_proofs(&conn).unwrap().first().unwrap().id, id);
    }

    #[test]
    fn a_rescan_retains_the_block_hash_needed_by_an_old_pending_proof() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pool = init_db(dir.path().join("burn.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
        create_account(&conn, "default", &wallet, "password").unwrap();
        let account_id = get_account_by_name(&conn, "default").unwrap().unwrap().id;
        let proof_id = insert_burn_proof(&conn, &new_proof(account_id, 6)).unwrap();
        conn.execute("UPDATE burn_proofs SET mined_height = 5 WHERE id = ?1", [proof_id])
            .unwrap();
        insert_scanned_tip_block(&conn, account_id, 5, &[5u8; 32]).unwrap();
        insert_scanned_tip_block(&conn, account_id, 6, &[6u8; 32]).unwrap();

        prune_scanned_tip_blocks(&conn, account_id, 1_007).unwrap();
        assert_eq!(
            get_scanned_tip_block_hash_at_height(&conn, account_id, 5).unwrap(),
            Some(vec![5u8; 32])
        );
        assert_eq!(
            get_scanned_tip_block_hash_at_height(&conn, account_id, 6).unwrap(),
            None
        );
    }

    #[test]
    fn an_in_flight_proof_cannot_complete_after_a_rollback() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pool = init_db(dir.path().join("burn.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
        create_account(&conn, "default", &wallet, "password").unwrap();
        let account_id = get_account_by_name(&conn, "default").unwrap().unwrap().id;
        let proof_id = insert_burn_proof(&conn, &new_proof(account_id, 1)).unwrap();

        // The worker fetched the proof before the scanner reached its block.
        let (generation, scanned_height) = burn_proof_scan_state(&conn, account_id).unwrap();
        assert_eq!(scanned_height, None);
        assert!(!mark_burn_proof_complete_if_current(&conn, proof_id, 100, &[1u8; 32], generation).unwrap());

        insert_scanned_tip_block(&conn, account_id, 100, &[1u8; 32]).unwrap();
        assert!(!mark_burn_proof_complete_if_current(&conn, proof_id, 100, &[2u8; 32], generation).unwrap());
        assert!(mark_burn_proof_complete_if_current(&conn, proof_id, 100, &[1u8; 32], generation).unwrap());
        reset_burn_proofs_from_height(&conn, account_id, 100).unwrap();
        advance_burn_proof_reorg_generation(&conn, account_id).unwrap();

        // Even if the scanner catches up on the replacement chain, this old
        // in-flight worker cannot publish its proof from the old chain.
        assert!(!mark_burn_proof_complete_if_current(&conn, proof_id, 100, &[1u8; 32], generation).unwrap());
        let (new_generation, _) = burn_proof_scan_state(&conn, account_id).unwrap();
        assert_ne!(new_generation, generation);
        assert!(mark_burn_proof_complete_if_current(&conn, proof_id, 100, &[1u8; 32], new_generation).unwrap());
    }
}
