-- Optimization for calculating locked balances and filtering by status per account
CREATE INDEX IF NOT EXISTS idx_outputs_account_status_active
ON outputs(account_id, status)
WHERE deleted_at IS NULL;

-- Optimization for unconfirmed checks
CREATE INDEX IF NOT EXISTS idx_outputs_account_confirmed_active
ON outputs(account_id)
WHERE confirmed_height IS NULL AND deleted_at IS NULL;
