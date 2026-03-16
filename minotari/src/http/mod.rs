//! HTTP client module for Tari blockchain RPC communication.
//!
//! This module provides a complete HTTP client implementation for interacting with
//! Tari base node RPC endpoints. It handles transaction submission, blockchain state
//! queries, and connection management with built-in retry logic and latency tracking.
//!
//! # Architecture
//!
//! The module is organized into several components:
//!
//! - [`WalletHttpClient`] - High-level client for wallet-to-node communication
//! - [`HttpError`] - Error types for HTTP operations
//! - Response types ([`TipInfoResponse`], [`TxSubmissionResponse`], [`TxQueryResponse`])
//!   for deserializing RPC responses
//!
//! # Features
//!
//! - **Automatic Retries**: Configurable exponential backoff retry policy for transient failures
//! - **Latency Tracking**: Built-in measurement of request round-trip times
//! - **Transaction Size Validation**: Pre-flight checks to ensure transactions fit within RPC limits
//! - **JSON-RPC Support**: Full support for the Tari JSON-RPC 2.0 protocol
//!
//! # Example
//!
//! ```rust,no_run
//! use url::Url;
//! use minotari::http::WalletHttpClient;
//!
//! # async fn example() -> Result<(), anyhow::Error> {
//! // Create a client connected to a local base node
//! let base_url = Url::parse("http://localhost:18142")?;
//! let client = WalletHttpClient::new(base_url)?;
//!
//! // Check if the node is online and synced
//! if client.is_online().await {
//!     let tip_info = client.get_tip_info().await?;
//!     if tip_info.is_synced {
//!         println!("Node is synced at height {:?}",
//!             tip_info.metadata.map(|m| m.best_block_height()));
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Error Handling
//!
//! All operations return [`Result`] types with appropriate error information.
//! The [`HttpError`] enum provides specific error variants for different failure modes:
//!
//! - Network failures (connection refused, timeouts)
//! - Server errors (4xx/5xx responses)
//! - Serialization errors (malformed JSON)
//! - URL parsing errors

mod error;
mod http_client;
mod types;
mod utils;
mod wallet_http_client;

pub use error::HttpError;
pub use types::*;
pub use wallet_http_client::WalletHttpClient;
