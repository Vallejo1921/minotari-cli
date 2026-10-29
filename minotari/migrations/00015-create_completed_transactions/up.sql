-- Create the completed_transactions table
CREATE TABLE completed_transactions (
    id TEXT PRIMARY KEY NOT NULL,
    account_id INTEGER NOT NULL,
    pending_tx_id TEXT NOT NULL,
    status TEXT NOT NULL,
    last_rejected_reason TEXT,
    kernel_excess BLOB NOT NULL,
    sent_payref TEXT,
    mined_height INTEGER,
    mined_block_hash BLOB,
    confirmation_height INTEGER,
    broadcast_attempts INTEGER NOT NULL DEFAULT 0,
    serialized_transaction BLOB NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id),
    FOREIGN KEY (pending_tx_id) REFERENCES pending_transactions(id)
);

CREATE INDEX idx_completed_transactions_account_id ON completed_transactions(account_id);
CREATE INDEX idx_completed_transactions_pending_tx_id ON completed_transactions(pending_tx_id);
CREATE INDEX idx_completed_transactions_status ON completed_transactions(status);
CREATE INDEX idx_completed_transactions_account_status ON completed_transactions(account_id, status);
CREATE INDEX idx_completed_transactions_mined_height ON completed_transactions(mined_height);
