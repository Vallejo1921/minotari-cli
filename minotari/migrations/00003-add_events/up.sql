-- Add migration script here
create table if not exists events (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    description TEXT NOT NULL,
    data_json TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id)
);

create table if not exists balance_changes (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    caused_by_output_id INTEGER,
    caused_by_input_id INTEGER,
    description TEXT NOT NULL,
    balance_debit INTEGER NOT NULL,
    balance_credit INTEGER NOT NULL,
    effective_date TIMESTAMP NOT NULL,
    effective_height INTEGER NOT NULL,
    claimed_recipient_address TEXT,
    claimed_sender_address TEXT,
    memo_parsed TEXT,
    memo_hex TEXT,
    claimed_fee INTEGER,
    claimed_amount INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id),
    FOREIGN KEY (caused_by_output_id) REFERENCES outputs(id),
    FOREIGN KEY (caused_by_input_id) REFERENCES inputs(id)
)