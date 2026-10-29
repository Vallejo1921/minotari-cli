-- Add is_burn flag to outputs to exclude burn outputs from balance calculations
ALTER TABLE outputs ADD COLUMN is_burn INTEGER NOT NULL DEFAULT 0;
