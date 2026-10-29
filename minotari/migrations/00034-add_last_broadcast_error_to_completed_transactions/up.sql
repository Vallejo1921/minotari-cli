-- The base node's answer to the last broadcast it did not accept (sanitised),
-- cleared when a broadcast is accepted. Kept apart from `last_rejected_reason`,
-- which is only set when the send is rejected: a send the node has not accepted
-- yet is still pending.

ALTER TABLE completed_transactions ADD COLUMN last_broadcast_error TEXT;
