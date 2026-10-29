create table if not exists inputs (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    output_id INTEGER NOT NULL,
    mined_in_block_hash blob NOT NULL,
    mined_in_block_height INTEGER NOT NULL,
    mined_timestamp TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (output_id) REFERENCES outputs(id),
    FOREIGN KEY (account_id) REFERENCES accounts(id)
)

