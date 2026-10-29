-- Add soft delete columns to outputs table
ALTER TABLE outputs ADD COLUMN deleted_at TIMESTAMP;
ALTER TABLE outputs ADD COLUMN deleted_in_block_height INTEGER;

-- Drop existing unique index on outputs
DROP INDEX IF EXISTS idx_outputs_output_hash;

-- Create new partial unique index on outputs for active records
CREATE UNIQUE INDEX IF NOT EXISTS idx_outputs_output_hash_active ON outputs(output_hash) WHERE deleted_at IS NULL;

-- Update existing indexes on outputs to be partial
DROP INDEX IF EXISTS idx_outputs_account_mined_height;
CREATE INDEX IF NOT EXISTS idx_outputs_account_mined_height_active ON outputs(account_id, mined_in_block_height) WHERE deleted_at IS NULL;

DROP INDEX IF EXISTS idx_outputs_status;
CREATE INDEX IF NOT EXISTS idx_outputs_status_active ON outputs(status) WHERE deleted_at IS NULL;


-- Add soft delete columns to inputs table
ALTER TABLE inputs ADD COLUMN deleted_at TIMESTAMP;
ALTER TABLE inputs ADD COLUMN deleted_in_block_height INTEGER;

-- Drop existing unique index on inputs
DROP INDEX IF EXISTS idx_inputs_output_id_unique;

-- Create new partial unique index on inputs for active records
CREATE UNIQUE INDEX IF NOT EXISTS idx_inputs_output_id_unique_active ON inputs(output_id) WHERE deleted_at IS NULL;

-- Update existing indexes on inputs to be partial
DROP INDEX IF EXISTS idx_inputs_account_mined_height;
CREATE INDEX IF NOT EXISTS idx_inputs_account_mined_height_active ON inputs(account_id, mined_in_block_height) WHERE deleted_at IS NULL;

-- Drop non-unique index on inputs_output_id as it's covered by the new unique partial index
DROP INDEX IF EXISTS idx_inputs_output_id;
