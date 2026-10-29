-- Add migration script here
CREATE INDEX IF NOT EXISTS idx_balance_changes_account_height ON balance_changes(account_id, effective_height);
CREATE INDEX IF NOT EXISTS idx_inputs_account_mined_height ON inputs(account_id, mined_in_block_height);

-- Drop redundant index
DROP INDEX IF EXISTS idx_balance_changes_account_id;
