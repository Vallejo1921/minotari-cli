CREATE TABLE sqlite_sequence(name,seq);
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
CREATE TABLE outputs (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    tx_id INTEGER NOT NULL,
    output_hash blob NOT NULL,
    mined_in_block_hash blob NOT NULL,
    mined_in_block_height INTEGER NOT NULL,
    value INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, 
    wallet_output_json TEXT, 
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
CREATE TABLE scanned_tip_blocks (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    hash Blob NOT NULL,
    height INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id)
);
CREATE TABLE inputs (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    output_id INTEGER NOT NULL,
    mined_in_block_hash blob NOT NULL,
    mined_in_block_height INTEGER NOT NULL,
    mined_timestamp TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, 
    deleted_at TIMESTAMP, 
    deleted_in_block_height INTEGER,
    FOREIGN KEY (output_id) REFERENCES outputs(id),
    FOREIGN KEY (account_id) REFERENCES accounts(id)
);
CREATE TABLE events (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    description TEXT NOT NULL,
    data_json TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id)
);
CREATE TABLE balance_changes (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    caused_by_output_id INTEGER,
    caused_by_input_id INTEGER,
    description TEXT NOT NULL,
    balance_debit INTEGER NOT NULL,
    balance_credit INTEGER NOT NULL,
    effective_date TIMESTAMP NOT NULL,
    effective_height INTEGER NOT NULL,
    claimed_recipient_address TEXT,
    claimed_sender_address TEXT,
    memo_parsed TEXT,
    memo_hex TEXT,
    claimed_fee INTEGER,
    claimed_amount INTEGER,
    is_reversal BOOLEAN NOT NULL DEFAULT FALSE,
    reversal_of_balance_change_id INTEGER REFERENCES balance_changes(id),
    is_reversed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id),
    FOREIGN KEY (caused_by_output_id) REFERENCES outputs(id),
    FOREIGN KEY (caused_by_input_id) REFERENCES inputs(id)
);
CREATE TABLE pending_transactions (
    id TEXT PRIMARY KEY NOT NULL,
    account_id INTEGER NOT NULL,
    idempotency_key TEXT NOT NULL,
    status TEXT NOT NULL,
    requires_change_output BOOLEAN NOT NULL DEFAULT FALSE,
    total_value INTEGER NOT NULL DEFAULT 0,
    fee_without_change INTEGER NOT NULL DEFAULT 0,
    fee_with_change INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id),
    UNIQUE (account_id, idempotency_key)
);
CREATE TABLE completed_transactions (
    id INTEGER PRIMARY KEY NOT NULL,
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
    sent_output_hash TEXT,
    serialized_transaction BLOB NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id),
    FOREIGN KEY (pending_tx_id) REFERENCES pending_transactions(id)
);
CREATE TABLE displayed_transactions (
    id TEXT PRIMARY KEY NOT NULL,
    account_id INTEGER NOT NULL,
    direction TEXT NOT NULL,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    amount INTEGER NOT NULL,
    block_height INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    transaction_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    payref TEXT
);
CREATE INDEX idx_scanned_tip_blocks_account_height ON scanned_tip_blocks(account_id, height DESC);
CREATE UNIQUE INDEX idx_scanned_tip_blocks_account_height_hash ON scanned_tip_blocks(account_id, height, hash);
CREATE INDEX idx_balance_changes_account_height ON balance_changes(account_id, effective_height);
CREATE INDEX idx_balance_changes_reversal_of ON balance_changes(reversal_of_balance_change_id) WHERE reversal_of_balance_change_id IS NOT NULL;
CREATE INDEX idx_balance_changes_is_reversed ON balance_changes(is_reversed) WHERE is_reversed = TRUE;
CREATE UNIQUE INDEX idx_outputs_output_hash_active ON outputs(output_hash) WHERE deleted_at IS NULL;
CREATE INDEX idx_outputs_account_mined_height_active ON outputs(account_id, mined_in_block_height) WHERE deleted_at IS NULL;
CREATE INDEX idx_outputs_status_active ON outputs(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_outputs_account_status_active ON outputs(account_id, status) WHERE deleted_at IS NULL;
CREATE INDEX idx_outputs_account_confirmed_active ON outputs(account_id) WHERE confirmed_height IS NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX idx_outputs_tx_id_active ON outputs(tx_id) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_inputs_output_id_unique_active ON inputs(output_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_inputs_account_mined_height_active ON inputs(account_id, mined_in_block_height) WHERE deleted_at IS NULL;
CREATE INDEX idx_pending_transactions_status_expires_at ON pending_transactions(status, expires_at);
CREATE INDEX idx_completed_transactions_account_id ON completed_transactions(account_id);
CREATE INDEX idx_completed_transactions_pending_tx_id ON completed_transactions(pending_tx_id);
CREATE INDEX idx_completed_transactions_status ON completed_transactions(status);
CREATE INDEX idx_completed_transactions_account_status ON completed_transactions(account_id, status);
CREATE INDEX idx_completed_transactions_mined_height ON completed_transactions(mined_height);
CREATE INDEX idx_displayed_transactions_account_id ON displayed_transactions(account_id);
CREATE INDEX idx_displayed_transactions_status ON displayed_transactions(status);
CREATE INDEX idx_displayed_transactions_block_height ON displayed_transactions(block_height);
CREATE INDEX idx_displayed_transactions_account_status ON displayed_transactions(account_id, status);
CREATE INDEX idx_displayed_transactions_account_height ON displayed_transactions(account_id, block_height DESC);
CREATE INDEX idx_displayed_transactions_payref ON displayed_transactions(payref);
