-- Add migration script here

ALTER TABLE outputs 
add wallet_output_json TEXT;

ALTER TABLE outputs
    add mined_timestamp TIMESTAMP NOT NULL;