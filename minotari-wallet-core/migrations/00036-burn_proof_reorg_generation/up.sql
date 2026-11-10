-- Incremented with every account rollback so an in-flight proof worker cannot
-- complete a proof fetched before that rollback.
ALTER TABLE accounts ADD COLUMN burn_proof_reorg_generation INTEGER NOT NULL DEFAULT 0;
