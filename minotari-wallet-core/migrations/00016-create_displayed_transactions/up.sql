-- Create displayed_transactions table to cache user-friendly transaction representations
CREATE TABLE IF NOT EXISTS displayed_transactions (
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
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_displayed_transactions_account_id ON displayed_transactions(account_id);
CREATE INDEX IF NOT EXISTS idx_displayed_transactions_status ON displayed_transactions(status);
CREATE INDEX IF NOT EXISTS idx_displayed_transactions_block_height ON displayed_transactions(block_height);
CREATE INDEX IF NOT EXISTS idx_displayed_transactions_account_status ON displayed_transactions(account_id, status);
CREATE INDEX IF NOT EXISTS idx_displayed_transactions_account_height ON displayed_transactions(account_id, block_height DESC);
