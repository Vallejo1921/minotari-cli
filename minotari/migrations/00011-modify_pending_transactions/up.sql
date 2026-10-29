-- Add migration script here

-- Rename the existing pending_transactions table
ALTER TABLE pending_transactions RENAME TO old_pending_transactions;

-- Create the new pending_transactions table with the updated schema
CREATE TABLE pending_transactions (
    id TEXT PRIMARY KEY NOT NULL,
    account_id INTEGER NOT NULL,
    idempotency_key TEXT NOT NULL,
    status TEXT NOT NULL,
    unsigned_tx_json TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id),
    UNIQUE (account_id, idempotency_key)
);

-- Copy data from the old table to the new table
INSERT INTO pending_transactions (id, account_id, idempotency_key, status, unsigned_tx_json, expires_at, created_at)
SELECT id, account_id, idempotency_key, status, '', expires_at, created_at
FROM old_pending_transactions;

-- Drop the old table
DROP TABLE old_pending_transactions;

-- Recreate the index
CREATE INDEX idx_pending_transactions_status_expires_at ON pending_transactions(status, expires_at);
