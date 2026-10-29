-- Add migration script here
 CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            friendly_name TEXT NOT NULL UNIQUE,
            unencrypted_view_key_hash blob NOT NULL UNIQUE,
            encrypted_view_private_key blob NOT NULL,
            encrypted_spend_public_key blob NOT NULL,
            cipher_nonce blob NOT NULL,
            birthday INTEGER NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scanned_tip_blocks (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            hash Blob NOT NULL,
            height INTEGER NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (account_id) REFERENCES accounts(id)
        );

        CREATE TABLE IF NOT EXISTS outputs (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            output_hash blob NOT NULL,
            mined_in_block_hash blob NOT NULL,
            mined_in_block_height INTEGER NOT NULL,
            value INTEGER NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (account_id) REFERENCES accounts(id)
        );
     