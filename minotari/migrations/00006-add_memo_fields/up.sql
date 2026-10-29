-- Add migration script here

ALTER TABLE outputs
ADD COLUMN memo_parsed TEXT;

ALTER TABLE outputs
ADD COLUMN memo_hex TEXT;