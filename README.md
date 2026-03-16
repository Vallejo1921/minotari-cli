# Minotari CLI Wallet Example

A command-line lightweight wallet implementation for the Tari blockchain
network. This wallet uses view-only keys to scan the blockchain for
transactions without requiring a full node.

## Project Structure

This repository is organized as a Cargo workspace:

- **minotari/**: Main CLI wallet application
- **integration-tests/**: Cucumber BDD integration tests with real base node

## Features

- **View-Only Wallet**: Import and manage wallets using view keys and spend
  public keys
- **Blockchain Scanning**: Efficiently scan the blockchain for outputs and track
  confirmations
- **Balance Tracking**: Monitor account balances with detailed transaction history
- **Reorg Detection**: Automatically detects and handles blockchain reorganizations
- **Encrypted Storage**: Wallet keys are encrypted using XChaCha20-Poly1305
- **SQLite Database**: All wallet data stored in a local SQLite database with migrations
- **Memo Support**: Parse and display payment memos attached to transactions
- **Multi-Account**: Support for multiple wallet accounts in a single database
- **Webhooks**: Real-time HTTP notifications for wallet events (outputs, confirmations, etc.)

## Build

You can build the application using the standard Rust toolchain:

```bash
cargo build --release
```

### Prerequisites

- Rust toolchain (2024 edition)

## Usage

### Logging and Privacy

To protect user privacy, the wallet masks Personally Identifiable Information (PII) such as addresses and transaction amounts in the application logs by default.

#### Reveal PII
If you are debugging and need to see the full, unmasked data, you can set the `REVEAL_PII` environment variable:

```bash
# Reveal full addresses and amounts in logs
REVEAL_PII=true cargo run --bin minotari -- scan [ARGS]
```

**Supported values for `REVEAL_PII`:** `true`, `1`.

#### Advanced Logging Configuration
The application comes with an embedded logging configuration. However, you can override this by placing a `log4rs.yml` file in the application's working directory. 

The application supports a custom encoder kind called `structured_console`, which renders structured log attributes (key-value pairs) as colorized text in the console.

**Example `log4rs.yml`:**
```yaml
appenders:
  stdout:
    kind: console
    encoder:
      kind: structured_console
      pattern: "{d(%Y-%m-%d %H:%M:%S)} {h({l}):5} {m}"

root:
  level: info
  appenders:
    - stdout
```

#### Running with Docker
If running inside a Docker container, you can mount your custom configuration file:

```bash
docker run -v $(pwd)/log4rs.yml:/app/log4rs.yml minotari-wallet scan [ARGS]
```

### Import a Wallet

Import a wallet using your view private key and spend public key:

```bash
cargo run --bin minotari -- import-view-key \
  --view-private-key <HEX_VIEW_KEY> \
  --spend-public-key <HEX_SPEND_KEY> \
  --password <PASSWORD> \
  --database-file data/wallet.db \
  --birthday <BLOCK_HEIGHT>
```

**Parameters:**

- `--view-private-key`: Your view private key in hexadecimal format
- `--spend-public-key`: Your spend public key in hexadecimal format
- `--password`: Password to encrypt the wallet (minimum 32 characters recommended)
- `--database-file`: Path to the SQLite database file (default: `data/wallet.db`)
- `--birthday`: Block height to start scanning from (default: `0`)

### Scan the Blockchain

Scan the blockchain for transactions:

```bash
cargo run --bin minotari -- scan \
  --password <PASSWORD> \
  --base-url https://rpc.tari.com \
  --database-file data/wallet.db \
  --max-blocks-to-scan 100 \
  --batch-size 10
```

**Parameters:**

- `--password`: Password used to decrypt the wallet
- `--base-url`: Tari RPC endpoint URL (default: `https://rpc.tari.com`)
- `--database-file`: Path to the database file (default: `data/wallet.db`)
- `--account-name`: Optional account name to scan (scans all accounts if not specified)
- `--max-blocks-to-scan`: Maximum number of blocks to scan per run (default: `50`)
- `--batch-size`: Number of blocks to scan per batch (default: `1`)

### Check Balance

View your wallet balance:

```bash
cargo run --bin minotari -- balance \
  --database-file data/wallet.db \
  --account-name default
```

**Parameters:**

- `--database-file`: Path to the database file (default: `data/wallet.db`)
- `--account-name`: Optional account name (shows all accounts if not specified)

## Database

The wallet uses SQLite to store:

- **Accounts**: Encrypted wallet keys and metadata
- **Outputs**: Detected outputs with confirmation status
- **Inputs**: Spent outputs (inputs to transactions)
- **Balance Changes**: Detailed transaction history with credits/debits
- **Wallet Events**: Timeline of wallet activity
- **Scanned Blocks**: Track scanning progress and detect reorgs

### Initialization and Migrations

The database is initialized automatically when the application starts. 
- If the database file does not exist, it will be created.
- Database migrations are embedded in the binary and applied automatically on startup.
- If you are moving from an older version that used `sqlx`, the system will attempt to adopt the existing database by updating the `user_version` and removing the legacy `_sqlx_migrations` table.

### Reset

To reset the database, simply remove the database file and its associated WAL files:

```bash
# Manual Reset
rm data/wallet.db*
```

The application will recreate the schema automatically on the next run.

## Security

- Wallet keys are encrypted with XChaCha20-Poly1305 using a user-provided password
- Private keys never leave your local machine
- View-only scanning means the wallet cannot spend funds
- Passwords are padded to 32 characters for encryption (ensure strong passwords)
- PII Masking: By default, logs redact transaction amounts and truncate addresses (e.g., `abcd12...wxyz34`) to prevent sensitive data from leaking into log files.

## Architecture

### Key Components

- **`src/main.rs`**: CLI interface and core scanning logic
- **`src/log/`**: Structured logging implementation and PII masking utilities.
- **`src/db/`**: Database layer with SQLite queries
  - `mod.rs`: Connection pooling and automatic migration logic
  - `accounts.rs`: Account management
  - `outputs.rs`: Output tracking and confirmations
  - `inputs.rs`: Input (spent output) tracking
  - `balance_changes.rs`: Transaction history
  - `events.rs`: Wallet event log
  - `scanned_tip_blocks.rs`: Scan progress and reorg detection
- **`src/models/mod.rs`**: Data models and types

### Scanning Process

1. Load encrypted wallet keys from database
2. Decrypt keys using password
3. Check for blockchain reorganizations
4. Scan blocks in batches starting from last scanned height
5. Detect outputs belonging to the wallet
6. Track confirmations (6 blocks required)
7. Parse memos and payment information
8. Update balance changes and generate events

### OpenAPI Specification

The OpenAPI specification (`openapi.json`) is generated from the API
definitions. If the API changes, you need to regenerate the `openapi.json` file
using the following command:

```bash
cargo run --bin generate-openapi
```

## Dependencies

- **lightweight_wallet_libs**: Tari blockchain scanning library
- **rusqlite**: Synchronous SQLite database access
- **rusqlite_migration**: Automatic migration management
- **chacha20poly1305**: Encryption for wallet keys
- **clap**: Command-line argument parsing
- **tokio**: Async runtime

## Testing

The project includes a comprehensive Cucumber BDD integration testing suite that covers all major features.

The tests are located in a separate package (`integration-tests/`) within the workspace:

```bash
# Run all integration tests from workspace root
cargo test -p integration-tests

# Run from the integration-tests directory
cd integration-tests
cargo test
```

See [integration-tests/README.md](integration-tests/README.md) for detailed testing documentation.

## Contributing
