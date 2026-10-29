-- Bind idempotency keys to the operation and request body that issued them.
--
-- A key on its own only says "this is a retry"; it does not say a retry *of
-- what*. Storing the operation and a fingerprint of the request lets the fund
-- locker refuse to hand a cached UTXO reservation to a replay that carries
-- different recipients, a different amount, or that arrives at a different
-- endpoint entirely.
--
-- Rows written before this migration have no recorded scope. The empty string
-- is used as that "unknown" marker: it can never equal a real fingerprint (a
-- fingerprint is always 64 hex characters) or a real operation name, so a
-- legacy row can only ever be reported as a conflict, never replayed onto.
ALTER TABLE pending_transactions ADD COLUMN operation TEXT NOT NULL DEFAULT '';
ALTER TABLE pending_transactions ADD COLUMN request_hash TEXT NOT NULL DEFAULT '';
