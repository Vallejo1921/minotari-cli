-- Track output maturity (the minimum block height at which the UTXO can be spent).
-- Coinbase outputs and time-locked outputs have a non-zero maturity; standard
-- outputs have maturity = 0 and are spendable as soon as they are confirmed.

ALTER TABLE outputs ADD COLUMN maturity INTEGER NOT NULL DEFAULT 0;

-- Backfill maturity for existing rows from the persisted wallet output JSON.
-- json_extract is part of SQLite's JSON1 extension which rusqlite enables by default.
-- Rows where extraction fails fall back to 0, which matches the column default.
UPDATE outputs
SET maturity = COALESCE(json_extract(wallet_output_json, '$.features.maturity'), 0)
WHERE wallet_output_json IS NOT NULL;

CREATE INDEX idx_outputs_maturity ON outputs(maturity);
