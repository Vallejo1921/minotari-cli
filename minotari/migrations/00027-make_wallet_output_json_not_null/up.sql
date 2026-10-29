-- Make wallet_output_json NOT NULL
-- This requires recreating the outputs table since SQLite doesn't support ALTER COLUMN

-- First drop dependent objects
DROP INDEX IF EXISTS idx_outputs_output_hash_active;
DROP INDEX IF EXISTS idx_outputs_account_mined_height_active;
DROP INDEX IF EXISTS idx_outputs_status_active;
DROP INDEX IF EXISTS idx_outputs_account_status_active;
DROP INDEX IF EXISTS idx_outputs_account_confirmed_active;
DROP INDEX IF EXISTS idx_outputs_tx_id_active;

-- Create new table with NOT NULL constraint
CREATE TABLE outputs_new (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    tx_id INTEGER NOT NULL,
    output_hash blob NOT NULL,
    mined_in_block_hash blob NOT NULL,
    mined_in_block_height INTEGER NOT NULL,
    value INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    wallet_output_json TEXT NOT NULL,
    mined_timestamp TIMESTAMP NOT NULL,
    confirmed_height INTEGER,
    confirmed_hash BLOB,
    memo_parsed TEXT,
    memo_hex TEXT,
    status TEXT NOT NULL DEFAULT 'UNSPENT',
    locked_at TIMESTAMP,
    locked_by_request_id TEXT,
    deleted_at TIMESTAMP,
    deleted_in_block_height INTEGER,
    payment_reference TEXT,
    FOREIGN KEY (account_id) REFERENCES accounts(id)
);

-- Copy data from old table (only rows with non-null wallet_output_json)
INSERT INTO outputs_new (
    id, account_id, tx_id, output_hash, mined_in_block_hash, mined_in_block_height,
    value, created_at, wallet_output_json, mined_timestamp, confirmed_height,
    confirmed_hash, memo_parsed, memo_hex, status, locked_at, locked_by_request_id,
    deleted_at, deleted_in_block_height, payment_reference
)
SELECT
    id, account_id, tx_id, output_hash, mined_in_block_hash, mined_in_block_height,
    value, created_at, wallet_output_json, mined_timestamp, confirmed_height,
    confirmed_hash, memo_parsed, memo_hex, status, locked_at, locked_by_request_id,
    deleted_at, deleted_in_block_height, payment_reference
FROM outputs
WHERE wallet_output_json IS NOT NULL;

-- Drop old table
DROP TABLE outputs;

-- Rename new table
ALTER TABLE outputs_new RENAME TO outputs;

-- Recreate indexes
CREATE UNIQUE INDEX idx_outputs_output_hash_active ON outputs(output_hash) WHERE deleted_at IS NULL;
CREATE INDEX idx_outputs_account_mined_height_active ON outputs(account_id, mined_in_block_height) WHERE deleted_at IS NULL;
CREATE INDEX idx_outputs_status_active ON outputs(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_outputs_account_status_active ON outputs(account_id, status) WHERE deleted_at IS NULL;
CREATE INDEX idx_outputs_account_confirmed_active ON outputs(account_id) WHERE confirmed_height IS NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX idx_outputs_tx_id_active ON outputs(tx_id) WHERE deleted_at IS NULL;

