-- The height of the block the burn's proof was taken from, set when the proof
-- is completed. A reorg from that height puts the proof back to pending so it
-- is fetched again from the new chain. NULL for proofs completed before this.

ALTER TABLE burn_proofs ADD COLUMN mined_height INTEGER;
