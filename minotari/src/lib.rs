//! Minotari: A lightweight view-only wallet for the Tari blockchain.
//!
//! This library provides a complete implementation of a view-only wallet that can scan
//! the Tari blockchain for transactions without requiring a full node or the ability to
//! spend funds. It uses view keys to detect outputs belonging to the wallet and tracks
//! confirmations, balances, and transaction history.
//!
//! # Features
//!
//! - **View-Only Wallet**: Import and manage wallets using view keys and spend public keys
//! - **Blockchain Scanning**: Efficiently scan the blockchain for outputs with configurable batch sizes
//! - **Balance Tracking**: Monitor account balances with detailed transaction history
//! - **Reorg Detection**: Automatically detects and handles blockchain reorganizations
//! - **Encrypted Storage**: Wallet keys are encrypted using XChaCha20-Poly1305
//! - **SQLite Database**: All wallet data stored locally with automatic migrations
//! - **Memo Support**: Parse and display payment memos attached to transactions
//! - **Multi-Account**: Support for multiple wallet accounts in a single database
//! - **HTTP API**: RESTful API with Swagger UI documentation for wallet operations
//! - **Event System**: Real-time wallet events for output detection, confirmations, and reorgs
//!
//! # Architecture
//!
//! The library is organized into the following modules:
//!
//! - [`api`]: OpenAPI specification and documentation for the HTTP API
//! - [`daemon`]: Background daemon mode for continuous blockchain scanning
//! - [`db`]: Database layer with SQLite queries for accounts, outputs, inputs, and balance changes
//! - [`http`]: HTTP server and REST API endpoints for wallet operations
//! - [`log`]: Log handling
//! - [`models`]: Data models including wallet events, balance changes, and output statuses
//! - [`scan`]: Core blockchain scanning logic with batch processing and reorg handling
//! - [`tasks`]: Background task management for periodic operations
//! - [`transactions`]: Transaction history service and display formatting
//! - [`utils`]: Utility functions for wallet initialization and key management
//! - [`webhooks`]: Webhook management
//!
//! # Getting Started
//!
//! ## Initializing a Wallet
//!
//! Use [`init_with_view_key`] to import a view-only wallet:
//!
//! ```ignore
//! use minotari::utils::init_wallet::init_with_view_key;
//! use std::path::Path;
//!
//! # fn example() -> anyhow::Result<()> {
//! // Import a view-only wallet
//! init_with_view_key(
//!     "view_private_key_hex",
//!     "spend_public_key_hex",
//!     "secure_password",
//!     Path::new("wallet.db"),
//!     0,         // birthday height
//!     Some("default"),
//! )?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Scanning the Blockchain
//!
//! Use the [`Scanner`] to scan for outputs:
//!
//! ```ignore
//! use minotari::{Scanner, ScanMode};
//! use std::path::PathBuf;
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Create and run scanner
//! let (events, more_blocks) = Scanner::new(
//!     "password",
//!     "https://rpc.tari.com",
//!     PathBuf::from("wallet.db"),
//!     100, // batch_size
//! )
//! .mode(ScanMode::Full)
//! .run()
//! .await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Checking Balance
//!
//! Use [`get_balance`] to retrieve current wallet balance:
//!
//! ```ignore
//! use minotari::{get_balance, init_db};
//! use std::path::PathBuf;
//!
//! # fn example() -> anyhow::Result<()> {
//! let db = init_db(PathBuf::from("wallet.db"))?;
//! let conn = db.get()?;
//! let balance = get_balance(&conn, 1)?;  // account_id = 1
//! println!("Available balance: {} µT", balance.available);
//! # Ok(())
//! # }
//! ```
//!
//! # Security Considerations
//!
//! - Wallet keys are encrypted with XChaCha20-Poly1305 using a user-provided password
//! - Private keys never leave the local machine
//! - View-only scanning means the wallet cannot spend funds
//! - Passwords should be at least 32 characters for optimal security
//!
//! # Database Schema
//!
//! The wallet uses SQLite to store:
//!
//! - **Accounts**: Encrypted wallet keys and metadata
//! - **Outputs**: Detected outputs with confirmation status
//! - **Inputs**: Spent outputs (inputs to transactions)
//! - **Balance Changes**: Detailed transaction history with credits/debits
//! - **Wallet Events**: Timeline of wallet activity
//! - **Scanned Blocks**: Track scanning progress and detect reorgs
//!
//! Database migrations are handled automatically via SQLx.

pub mod api;
pub mod cli;
pub mod config;
pub mod daemon;
pub mod db;
pub mod http;
pub mod log;
pub mod models;
pub mod scan;
pub mod tasks;
pub mod transactions;
pub mod utils;
pub mod webhooks;

pub use crate::api::ApiDoc;
pub use crate::db::{get_accounts, get_balance, init_db};
pub use crate::models::WalletEvent;
pub use crate::scan::types::ScanError;
pub use crate::scan::{BlockProcessedEvent, PauseReason, ProcessingEvent, ScanMode, ScanStatusEvent, Scanner};
pub use crate::transactions::{DisplayedTransaction, TransactionHistoryService};
