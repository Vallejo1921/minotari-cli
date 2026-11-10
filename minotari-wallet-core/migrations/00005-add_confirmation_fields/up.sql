-- Add migration script here

ALTER TABLE outputs
ADD COLUMN confirmed_height INTEGER;

ALTER TABLE outputs
ADD COLUMN confirmed_hash BLOB;
