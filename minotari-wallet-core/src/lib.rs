//! Minotari wallet core: the view-only wallet library behind the `minotari` CLI and daemon.
//!
//! It holds the database layer, blockchain scanning, transaction building and history,
//! the wallet HTTP client and message signing, with no server, CLI or OpenSSL dependencies.
//!
//! # Features
//!
//! - `http` (default): scan over the base node HTTP API.
//! - `grpc`: also enable gRPC scanning in `minotari-scanning`.
//! - `utoipa`: derive `utoipa::ToSchema` on API-facing types, for the daemon's OpenAPI docs.

// Unit tests may use plain arithmetic; production code is still checked because
// `clippy::arithmetic_side_effects` is linted on the non-test build of this crate.
// (clippy has no `allow-arithmetic-side-effects-in-tests` option.)
#![cfg_attr(test, allow(clippy::arithmetic_side_effects))]

pub mod db;
pub mod http;
pub mod log;
pub mod models;
pub mod scan;
pub mod session;
pub mod signing;
pub mod transactions;
pub mod utils;
pub mod webhooks;

pub use crate::db::{get_accounts, get_balance, init_db};
pub use crate::models::WalletEvent;
pub use crate::scan::types::ScanError;
pub use crate::scan::{BlockProcessedEvent, EventReceiver, ProcessingEvent, ScanMode, ScanStatusEvent, Scanner};
pub use crate::signing::{SigningError, sign_message, sign_message_unlocked, sign_message_with_seed, verify_message};
pub use crate::transactions::{DisplayedTransaction, TransactionHistoryService};
