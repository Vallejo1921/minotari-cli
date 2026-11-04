//! Where complete burn claim proof files live on disk.

use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

use tokio::fs;

pub fn proof_file_path(burn_proofs_dir: &Path, claim_public_key_hex: &str, commitment: &[u8]) -> PathBuf {
    burn_proofs_dir.join(format!("{}-{}.json", claim_public_key_hex, hex::encode(commitment)))
}

/// Removes a proof file; a file that is already gone is not an error.
pub async fn remove_proof_file(
    burn_proofs_dir: &Path,
    claim_public_key_hex: &str,
    commitment: &[u8],
) -> Result<(), anyhow::Error> {
    match fs::remove_file(proof_file_path(burn_proofs_dir, claim_public_key_hex, commitment)).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
