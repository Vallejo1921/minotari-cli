-- Track historical payment references that become stale after block reorgs.
-- When a reorg moves a transaction to a different block, the payref changes.
-- This table preserves old payrefs so lookups by stale payrefs still resolve.
-- This is a record table so duplicates are allowed: every observed stale
-- (tx_id, old_payref) pair is appended and the newest record wins on lookup.
CREATE TABLE IF NOT EXISTS payref_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    transaction_id BIGINT NOT NULL,
    old_payref TEXT NOT NULL,
    output_hash TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (account_id) REFERENCES accounts(id)
);

CREATE INDEX idx_payref_history_lookup ON payref_history (account_id, old_payref);
