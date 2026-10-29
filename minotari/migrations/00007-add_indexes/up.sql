-- Add migration script here
CREATE INDEX IF NOT EXISTS idx_scanned_tip_blocks_account_height ON scanned_tip_blocks(account_id, height DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_outputs_output_hash ON outputs(output_hash);
CREATE INDEX IF NOT EXISTS idx_outputs_account_mined_height ON outputs(account_id, mined_in_block_height);
CREATE INDEX IF NOT EXISTS idx_balance_changes_account_id ON balance_changes(account_id);
CREATE INDEX IF NOT EXISTS idx_inputs_output_id ON inputs(output_id);
