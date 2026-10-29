-- Create burn_proofs table to track L2 burn claim proofs
-- status values: 'pending_merkle' (burn tx confirmed, awaiting merkle proof) | 'complete' (proof file written)
CREATE TABLE burn_proofs (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    output_hash BLOB NOT NULL,
    commitment BLOB NOT NULL,
    claim_public_key TEXT NOT NULL,
    ownership_proof_nonce BLOB NOT NULL,
    ownership_proof_sig BLOB NOT NULL,
    kernel_excess BLOB NOT NULL,
    kernel_excess_nonce BLOB NOT NULL,
    kernel_excess_sig BLOB NOT NULL,
    sender_offset_public_key BLOB NOT NULL,
    encrypted_data BLOB NOT NULL,
    value INTEGER NOT NULL,
    kernel_fee INTEGER NOT NULL DEFAULT 0,
    kernel_lock_height INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending_merkle',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id)
);

CREATE UNIQUE INDEX idx_burn_proofs_output_hash ON burn_proofs(output_hash);
CREATE INDEX idx_burn_proofs_status ON burn_proofs(status);
