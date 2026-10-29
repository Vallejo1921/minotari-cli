-- Add migration script here

-- Create a table to track requests for unsigned transactions and the UTXOs they lock.
-- This allows us to time-out and release locks if the client fails to execute the transaction.
CREATE TABLE pending_transactions (
    -- It's a UUID stored as TEXT.
    id TEXT PRIMARY KEY NOT NULL,

    -- This key is provided by the client to ensure idempotency of the creation request.
    idempotency_key TEXT NOT NULL UNIQUE,

    -- Foreign key to the account (wallet) this transaction belongs to.
    account_id INTEGER NOT NULL,

    -- The status of this request: 'PENDING', 'FULFILLED', 'EXPIRED'.
    status TEXT NOT NULL,

    -- The unsigned transaction data itself, ready to be sent to the client.
    unsigned_tx_blob BLOB NOT NULL,

    -- The timestamp when the locks on the associated UTXOs should be automatically released.
    expires_at TIMESTAMP NOT NULL,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (account_id) REFERENCES accounts(id)
);

-- Create an index to efficiently query for expired transactions that need to be unlocked.
CREATE INDEX idx_pending_transactions_status_expires_at ON pending_transactions(status, expires_at);
