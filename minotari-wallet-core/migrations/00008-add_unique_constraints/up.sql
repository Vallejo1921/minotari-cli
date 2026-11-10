-- Add migration script here
CREATE UNIQUE INDEX IF NOT EXISTS idx_inputs_output_id_unique ON inputs(output_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scanned_tip_blocks_account_height_hash ON scanned_tip_blocks(account_id, height, hash);
