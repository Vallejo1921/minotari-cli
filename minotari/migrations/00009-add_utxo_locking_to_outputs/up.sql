-- Add migration script here

-- Add status and locking information to the outputs table.
-- 'status' will be one of 'UNSPENT', 'LOCKED', 'SPENT'.
-- This column will be the definitive state for the payment creation logic.
ALTER TABLE outputs ADD COLUMN status TEXT NOT NULL DEFAULT 'UNSPENT';
ALTER TABLE outputs ADD COLUMN locked_at TIMESTAMP;

-- This column will hold a reference to the pending transaction request that locked this output.
-- It's a TEXT field to store a UUID from the pending_transactions table.
-- Note: SQLite does not support adding a FOREIGN KEY constraint via ALTER TABLE.
-- The relationship will be maintained by the application logic.
ALTER TABLE outputs ADD COLUMN locked_by_request_id TEXT;

-- After adding the columns, we need to update the status of all existing outputs
-- that have already been spent (i.e., have a corresponding entry in the `inputs` table).
-- This ensures the new state is consistent with the old on-chain reality.
UPDATE outputs
SET status = 'SPENT'
WHERE id IN (SELECT output_id FROM inputs);

-- Create an index on the new status column, as it will be heavily used in queries
-- to find available UTXOs for payment creation.
CREATE INDEX idx_outputs_status ON outputs(status);