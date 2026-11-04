-- Add reversal tracking fields to balance_changes table
-- is_reversal: indicates if this balance change is a reversal of another
-- reversal_of_balance_change_id: foreign key to the original balance change being reversed
-- is_reversed: indicates if this balance change has been reversed (soft deleted)

ALTER TABLE balance_changes ADD COLUMN is_reversal BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE balance_changes ADD COLUMN reversal_of_balance_change_id INTEGER REFERENCES balance_changes(id);
ALTER TABLE balance_changes ADD COLUMN is_reversed BOOLEAN NOT NULL DEFAULT FALSE;

-- Index to efficiently find reversals and reversed balance changes
CREATE INDEX idx_balance_changes_reversal_of ON balance_changes(reversal_of_balance_change_id) WHERE reversal_of_balance_change_id IS NOT NULL;
CREATE INDEX idx_balance_changes_is_reversed ON balance_changes(is_reversed) WHERE is_reversed = TRUE;

