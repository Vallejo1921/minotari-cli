//! Background task that fetches burn output proofs for confirmed burn outputs
//! and writes complete [`CompleteClaimBurnProof`] JSON files to disk.
//!
//! # Flow
//!
//! 1. Poll `burn_proofs` table for records with `status = 'pending_merkle'`
//! 2. For each, call `/generate_burn_output_proof` on the base node with the burn commitment
//! 3. Check the proof is for the expected output, then assemble [`CompleteClaimBurnProof`] from the stored partial
//!    proof and the burn output proof
//! 4. Write `{claim_public_key}-{commitment_hex}.json` to `burn_proofs_dir`
//! 5. Mark the DB record as `complete`

use std::{path::PathBuf, time::Duration};

use log::{error, info, warn};
use reqwest::StatusCode;
use tari_common::configuration::Network;
use tari_common_types::types::{CompressedPublicKey, FixedHash, PrivateKey};
use tari_crypto::ristretto::CompressedRistrettoSchnorr;
use tari_sidechain::{BurnClaimProof, BurnOutputProof, CompleteClaimBurnProof};
use tari_transaction_components::{
    consensus::ConsensusManager, transaction_components::burn_output_proof::OutputHashPreimageExt,
};
use tari_utilities::byte_array::ByteArray;
use tokio::{fs, sync::broadcast, task::JoinHandle, time::interval};

use crate::{
    db::{DbBurnProof, SqlitePool, get_pending_burn_proofs, mark_burn_proof_complete},
    http::{HttpError, WalletHttpClient},
};

const LOG_TARGET: &str = "wallet::tasks::burn_proof_worker";
const POLL_INTERVAL_SECS: u64 = 60;

pub struct BurnProofWorker {
    db_pool: SqlitePool,
    client: WalletHttpClient,
    burn_proofs_dir: PathBuf,
    consensus_manager: ConsensusManager,
}

impl BurnProofWorker {
    pub fn new(db_pool: SqlitePool, client: WalletHttpClient, burn_proofs_dir: PathBuf, network: Network) -> Self {
        Self {
            db_pool,
            client,
            burn_proofs_dir,
            consensus_manager: ConsensusManager::builder(network).build(),
        }
    }

    pub fn run(self, mut shutdown_rx: broadcast::Receiver<()>) -> JoinHandle<Result<(), anyhow::Error>> {
        tokio::spawn(async move {
            info!(target: LOG_TARGET, "Burn proof worker started.");
            let mut ticker = interval(Duration::from_secs(POLL_INTERVAL_SECS));

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Err(e) = self.process_pending_proofs().await {
                            error!(target: LOG_TARGET, error:% = e; "Error processing pending burn proofs");
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!(target: LOG_TARGET, "Burn proof worker received shutdown signal. Exiting gracefully.");
                        break;
                    }
                }
            }

            info!(target: LOG_TARGET, "Burn proof worker has shut down.");
            Ok(())
        })
    }

    async fn process_pending_proofs(&self) -> Result<(), anyhow::Error> {
        // Fetch pending proofs and immediately release the connection before any await.
        let pending = {
            let conn = self.db_pool.get()?;
            get_pending_burn_proofs(&conn)?
        };

        if pending.is_empty() {
            return Ok(());
        }

        info!(
            target: LOG_TARGET,
            count = pending.len();
            "Processing pending burn proofs"
        );

        for proof in pending {
            let proof_id = proof.id;
            if let Err(e) = self.process_single_proof(&proof).await {
                if is_pruned_block_error(&e) {
                    error!(
                        target: LOG_TARGET,
                        burn_proof_id = proof_id,
                        error:% = e;
                        "The base node has pruned the block containing this burn and cannot prove it. Connect to an \
                         archival base node to complete the burn proof — will retry next cycle"
                    );
                    continue;
                }
                warn!(
                    target: LOG_TARGET,
                    burn_proof_id = proof_id,
                    error:% = e;
                    "Failed to process burn proof — will retry next cycle"
                );
            }
        }

        Ok(())
    }

    async fn process_single_proof(&self, proof: &DbBurnProof) -> Result<(), anyhow::Error> {
        let output_proof = self.client.get_burn_output_proof(&proof.commitment).await?.proof;

        check_output_proof(&proof.output_hash, &output_proof)?;

        // Convert the burn's L1 block height to its epoch so an L2 claimant can defer the claim until L2 has synced
        // past it.
        let mined_in_epoch = height_to_epoch(&self.consensus_manager, output_proof.block_height);

        let complete_proof = assemble_complete_proof(proof, output_proof, mined_in_epoch)?;

        write_proof_file(
            &self.burn_proofs_dir,
            &proof.claim_public_key,
            &proof.commitment,
            &complete_proof,
        )
        .await?;

        // Mark complete — get a fresh connection after the await.
        let conn = self.db_pool.get()?;
        mark_burn_proof_complete(&conn, proof.id)?;

        Ok(())
    }
}

/// Converts an L1 block height to its VN epoch (`height / vn_epoch_length`).
fn height_to_epoch(consensus_manager: &ConsensusManager, height: u64) -> u64 {
    consensus_manager
        .consensus_constants(height)
        .block_height_to_epoch(height)
        .as_u64()
}

/// Returns true if the base node could not produce the proof because it has pruned the block the burn was mined in.
fn is_pruned_block_error(err: &anyhow::Error) -> bool {
    matches!(
        err.downcast_ref::<HttpError>(),
        Some(HttpError::ServerError { status, .. }) if *status == StatusCode::GONE
    )
}

/// Checks that the proof is for the expected burn output. The claim verifier checks the proof against the block
/// header, but a proof for another output is useless, so reject it here.
fn check_output_proof(expected_output_hash: &FixedHash, output_proof: &BurnOutputProof) -> Result<(), anyhow::Error> {
    let proof_output_hash = output_proof.output.hash()?;
    if proof_output_hash != *expected_output_hash {
        return Err(anyhow::anyhow!(
            "Base node returned a burn output proof for output {} instead of {}",
            proof_output_hash,
            expected_output_hash
        ));
    }
    Ok(())
}

fn assemble_complete_proof(
    proof: &DbBurnProof,
    output_proof: BurnOutputProof,
    mined_in_epoch: u64,
) -> Result<CompleteClaimBurnProof, anyhow::Error> {
    let nonce = CompressedPublicKey::from_canonical_bytes(&proof.ownership_proof_nonce)
        .map_err(|e| anyhow::anyhow!("Invalid ownership_proof_nonce: {}", e))?;
    let sig_scalar = PrivateKey::from_canonical_bytes(&proof.ownership_proof_sig)
        .map_err(|e| anyhow::anyhow!("Invalid ownership_proof_sig: {}", e))?;
    let ownership_proof = CompressedRistrettoSchnorr::new(nonce, sig_scalar);

    let burn_public_key = CompressedPublicKey::from_canonical_bytes(
        &hex::decode(&proof.claim_public_key).map_err(|e| anyhow::anyhow!("Invalid claim_public_key hex: {}", e))?,
    )
    .map_err(|e| anyhow::anyhow!("Invalid claim_public_key: {}", e))?;

    Ok(CompleteClaimBurnProof {
        claim_proof: BurnClaimProof {
            burn_public_key,
            ownership_proof,
            output_proof,
            value: proof.value as u64,
        },
        encrypted_data: proof.encrypted_data.clone(),
        mined_in_epoch,
    })
}

async fn write_proof_file(
    burn_proofs_dir: &PathBuf,
    claim_public_key_hex: &str,
    commitment: &[u8],
    proof: &CompleteClaimBurnProof,
) -> Result<(), anyhow::Error> {
    fs::create_dir_all(burn_proofs_dir).await?;

    let filename = format!("{}-{}.json", claim_public_key_hex, hex::encode(commitment));
    let path = burn_proofs_dir.join(&filename);

    let json = serde_json::to_vec_pretty(proof)?;
    fs::write(&path, &json).await?;

    info!(
        target: LOG_TARGET,
        path = &*path.display().to_string();
        "Wrote complete burn proof file"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use tari_sidechain::{MmrInclusionProof, OutputHashPreimage};
    use tari_transaction_components::transaction_components::TransactionOutput;

    use super::*;

    /// Build a `DbBurnProof` where every byte-array field holds 32 zero bytes.
    ///
    /// The Ristretto identity element serialises as 32 zero bytes, so all
    /// compressed-point fields are valid and `assemble_complete_proof` will
    /// succeed without hitting a curve-decode error.
    fn make_test_db_proof() -> DbBurnProof {
        DbBurnProof {
            id: 1,
            account_id: 1,
            output_hash: FixedHash::default(),
            commitment: vec![0u8; 32],
            // 64 hex chars = 32 zero bytes (Ristretto identity)
            claim_public_key: "00".repeat(32),
            ownership_proof_nonce: vec![0u8; 32],
            ownership_proof_sig: vec![0u8; 32],
            kernel_excess: vec![0u8; 32],
            kernel_excess_nonce: vec![0u8; 32],
            kernel_excess_sig: vec![0u8; 32],
            sender_offset_public_key: vec![0u8; 32],
            encrypted_data: vec![0xAB, 0xCD, 0xEF],
            value: 1_000_000,
            kernel_fee: 250,
            kernel_lock_height: 0,
            status: "pending_merkle".to_string(),
        }
    }

    fn make_test_output_proof() -> BurnOutputProof {
        let mmr_proof = MmrInclusionProof {
            leaf_index: 0,
            mmr_size: 1,
            path: vec![],
            peaks: vec![],
        };
        BurnOutputProof {
            block_hash: tari_sidechain::FixedHash::default(),
            block_height: 1,
            output: OutputHashPreimage::from(&TransactionOutput::default()),
            normal_output_proof: mmr_proof.clone(),
            normal_output_mr: tari_sidechain::FixedHash::default(),
            block_output_proof: mmr_proof,
        }
    }

    #[test]
    fn test_assemble_complete_proof_success() {
        let proof = make_test_db_proof();
        let output_proof = make_test_output_proof();

        let result = assemble_complete_proof(&proof, output_proof.clone(), 7);
        assert!(result.is_ok(), "Expected Ok but got: {:?}", result.err());

        let complete = result.unwrap();
        assert_eq!(complete.claim_proof.value, 1_000_000);
        assert_eq!(complete.encrypted_data, vec![0xAB, 0xCD, 0xEF]);
        assert_eq!(complete.mined_in_epoch, 7);
        assert_eq!(complete.claim_proof.output_proof, output_proof);
    }

    #[test]
    fn test_assemble_complete_proof_value_preserved() {
        let mut proof = make_test_db_proof();
        proof.value = 999_999;

        let result = assemble_complete_proof(&proof, make_test_output_proof(), 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().claim_proof.value, 999_999);
    }

    #[test]
    fn test_assemble_complete_proof_encrypted_data_preserved() {
        let mut proof = make_test_db_proof();
        proof.encrypted_data = vec![0x11, 0x22, 0x33, 0x44];

        let result = assemble_complete_proof(&proof, make_test_output_proof(), 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().encrypted_data, vec![0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn test_assemble_complete_proof_invalid_claim_public_key_hex() {
        let mut proof = make_test_db_proof();
        proof.claim_public_key = "not-valid-hex".to_string();

        let result = assemble_complete_proof(&proof, make_test_output_proof(), 0);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("claim_public_key"),
            "Error should mention claim_public_key, got: {err}"
        );
    }

    #[test]
    fn test_assemble_complete_proof_invalid_ownership_proof_nonce() {
        let mut proof = make_test_db_proof();
        proof.ownership_proof_nonce = vec![]; // wrong length — definitely invalid

        let result = assemble_complete_proof(&proof, make_test_output_proof(), 0);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("ownership_proof_nonce"),
            "Error should mention ownership_proof_nonce, got: {err}"
        );
    }

    #[test]
    fn test_check_output_proof_accepts_matching_output() {
        let output_proof = make_test_output_proof();
        let expected = output_proof.output.hash().unwrap();

        assert!(check_output_proof(&expected, &output_proof).is_ok());
    }

    #[test]
    fn test_check_output_proof_rejects_other_output() {
        let output_proof = make_test_output_proof();

        let err = check_output_proof(&FixedHash::from([1u8; 32]), &output_proof).unwrap_err();
        assert!(err.to_string().contains("instead of"), "Unexpected error: {err}");
    }

    #[test]
    fn test_height_to_epoch() {
        let consensus_manager = ConsensusManager::builder(Network::LocalNet).build();
        let epoch_length = consensus_manager.consensus_constants(0).epoch_length();

        assert_eq!(height_to_epoch(&consensus_manager, 0), 0);
        assert_eq!(height_to_epoch(&consensus_manager, epoch_length - 1), 0);
        assert_eq!(height_to_epoch(&consensus_manager, epoch_length), 1);
        assert_eq!(height_to_epoch(&consensus_manager, 5 * epoch_length + 1), 5);
    }

    #[test]
    fn test_is_pruned_block_error() {
        let gone = anyhow::Error::from(HttpError::ServerError {
            status: StatusCode::GONE,
            body: String::new(),
        });
        let not_found = anyhow::Error::from(HttpError::ServerError {
            status: StatusCode::NOT_FOUND,
            body: String::new(),
        });

        assert!(is_pruned_block_error(&gone));
        assert!(!is_pruned_block_error(&not_found));
        assert!(!is_pruned_block_error(&anyhow::anyhow!("other")));
    }

    #[test]
    fn test_complete_proof_json_round_trip() {
        let complete = assemble_complete_proof(&make_test_db_proof(), make_test_output_proof(), 3).unwrap();
        let json = serde_json::to_string(&complete).unwrap();
        let parsed: CompleteClaimBurnProof = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mined_in_epoch, 3);
        assert_eq!(parsed.claim_proof.output_proof, complete.claim_proof.output_proof);
    }
}
