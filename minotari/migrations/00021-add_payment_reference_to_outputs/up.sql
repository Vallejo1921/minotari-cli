-- Add payment_reference column to outputs table
-- This stores the PaymentReference computed from block_hash and output_hash

ALTER TABLE outputs
ADD COLUMN payment_reference TEXT;
