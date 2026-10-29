-- Add payref column to displayed_transactions table
-- This stores the payment references (sent_payrefs from TransactionDetails) as a JSON array

ALTER TABLE displayed_transactions
ADD COLUMN payref TEXT;

-- Index for querying by payment reference
CREATE INDEX IF NOT EXISTS idx_displayed_transactions_payref ON displayed_transactions(payref);
