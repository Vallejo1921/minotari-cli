-- Links a send's change output to the send that created it.
--
-- The change output of a send is written at send time with status 'UNCONFIRMED'
-- (sentinel values in the NOT NULL mined_* columns) so the wallet's own block
-- scan can recognise the send when it lands. `created_by_request_id` holds the
-- `pending_transactions.id` of that send (the same value inputs carry in
-- `locked_by_request_id`). It is NULL for every output found by the scan alone.

ALTER TABLE outputs ADD COLUMN created_by_request_id TEXT;

CREATE INDEX idx_outputs_created_by_request_id ON outputs(created_by_request_id)
    WHERE created_by_request_id IS NOT NULL;
