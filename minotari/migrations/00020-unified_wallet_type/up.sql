-- Wipe all dependent data (foreign key cleanup)
DELETE FROM balance_changes;
DELETE FROM completed_transactions;
DELETE FROM inputs;
DELETE FROM pending_transactions;
DELETE FROM outputs;
DELETE FROM scanned_tip_blocks;
DELETE FROM events;
DELETE FROM displayed_transactions;

-- Drop the old accounts table
DROP TABLE accounts;

-- Create the new clean schema
CREATE TABLE accounts (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    friendly_name TEXT NOT NULL UNIQUE,
    fingerprint BLOB NOT NULL UNIQUE,
    encrypted_wallet BLOB NOT NULL,
    cipher_nonce BLOB NOT NULL,
    salt BLOB NOT NULL,
    birthday INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
