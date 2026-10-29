//! Blockchain scanning infrastructure for wallet synchronization.
//!
//! This module provides the core functionality for scanning the Tari blockchain to detect
//! wallet-relevant outputs, track spending, handle chain reorganizations, and emit events
//! for real-time UI updates.
//!
//! # Architecture Overview
//!
//! The scanning system is built around several key components:
//!
//! - **[`Scanner`]**: The main entry point for blockchain scanning operations. Configurable
//!   for different scanning modes (full sync, partial sync, continuous monitoring).
//!
//! - **[`BlockProcessor`]**: Processes individual blocks, detecting outputs owned by the
//!   wallet, tracking inputs (spent outputs), and managing confirmation tracking.
//!
//! - **Reorg Handling**: The [`reorg`] submodule provides mechanisms to detect and recover
//!   from blockchain reorganizations by rolling back affected outputs and transactions.
//!
//! - **Event System**: The [`events`] submodule defines event types and traits for
//!   communicating scan progress and detected activity to subscribers.
//!
//! # Scanning Modes
//!
//! The scanner supports three operational modes via [`ScanMode`]:
//!
//! - **Full**: Scans from the wallet birthday to chain tip, then stops.
//! - **Partial**: Scans a limited number of blocks, useful for incremental syncing.
//! - **Continuous**: Scans to tip, then polls for new blocks at configurable intervals.
//!
//! # Event-Driven Updates
//!
//! The scanning system can emit events through the [`EventSender`] trait:
//!
//! - [`ProcessingEvent::BlockProcessed`] - Emitted after each block is processed
//! - [`ProcessingEvent::ScanStatus`] - Progress updates and status changes
//! - [`ProcessingEvent::TransactionsReady`] - Newly detected transactions
//! - [`ProcessingEvent::ReorgDetected`] - Chain reorganization detected and handled
//!
//! # Continuous Mode Event Contract
//!
//! Events are per account (`account_id`). A Continuous scan repeats one cycle
//! until it is cancelled:
//!
//! 1. While blocks remain, for every batch: `MoreBlocksAvailable`, then
//!    `BlockProcessed` / `TransactionsReady` for wallet activity, then
//!    `Progress { current_height, tip_height, .. }`. The tip is read once per
//!    pass, so `current_height / tip_height` drives a progress bar; `tip_height`
//!    is never below `current_height`.
//! 2. Caught up: post-scan `TransactionsUpdated` / `TransactionsReady`
//!    (`is_initial_sync: false`) for confirmation and status changes, then
//!    `Completed { final_height, .. }`, then `Waiting { resume_in }` (the poll
//!    interval). The scanner is idle until the next poll.
//! 3. After each poll, and every `reorg_check_interval` blocks while scanning,
//!    the stored tip blocks are checked against the chain. A reorg sends
//!    `ReorgDetected`: blocks from `reorg_from_height` were rolled back, the
//!    `cancelled_transaction_ids` and `reorganized_displayed_transactions` are
//!    affected, and scanning resumes at `new_height`, mid-pass included. A
//!    reorg below every stored block resumes at the account's birthday. If the
//!    birthday lookup fails, returns a height above the chain tip, or is
//!    cancelled, `new_height` is 0: the scan stopped (with that error, or
//!    cancelled) before choosing a resume height, and the next run resumes from
//!    the birthday. A reorg found when the scan starts is reported the same
//!    way. A node that keeps reporting reorgs without letting the scan get
//!    further fails the scan with `ScanError::Intermittent`.
//!
//! `Started` is not sent. Cancelling the token stops the scan without waiting
//! on the node: the startup reorg checks and birthday lookups, block
//! downloads, tip reads, reorg checks and the poll sleep are all interrupted.
//! It sends `Paused { reason: Cancelled }` for every account prepared so far
//! (none if it is cancelled during startup) and returns `more_blocks == true`.
//! The one wait that is not interrupted is the end-of-pass transaction monitor,
//! so its updates are always reported; a cancel that arrives first skips it,
//! and its node requests are bounded by the HTTP client's timeout and retries.
//! Blocks are only written after a whole batch arrives, and a reorg rollback is
//! a single database transaction, so a cancelled scan leaves the database at
//! the last fully processed batch. The scanner's background download tasks
//! stop as soon as the scan drops its stream. Dropping the scan future stops it
//! the same way, without the `Paused` event.
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use crate::scan::{Scanner, ScanMode};
//! use std::time::Duration;
//!
//! // Create a scanner for continuous monitoring
//! let scanner = Scanner::new("password", "http://localhost:18142", "wallet.db", 100)
//!     .account("default")
//!     .mode(ScanMode::Continuous { poll_interval: Duration::from_secs(30) })
//!     .processing_threads(4);
//!
//! // Run with event channel for real-time updates
//! let (event_rx, scan_future) = scanner.run_with_events();
//!
//! // Process events in a separate task
//! tokio::spawn(async move {
//!     while let Some(event) = event_rx.recv().await {
//!         // Handle scan events
//!     }
//! });
//!
//! // Run the scan
//! let (events, more_blocks) = scan_future.await?;
//! ```
//!
//! # Reorg Detection
//!
//! The scanner periodically checks for chain reorganizations by comparing stored block
//! hashes against the current chain. When a reorg is detected:
//!
//! 1. Affected blocks are identified by comparing stored hashes with chain state
//! 2. Outputs mined in reorged blocks are soft-deleted
//! 3. Related pending transactions are cancelled
//! 4. Balance changes are reversed
//! 5. Scanning resumes from the fork point
//!
//! # Error Handling
//!
//! The module distinguishes between:
//!
//! - **Fatal errors**: Unrecoverable issues (database corruption, invalid keys)
//! - **Intermittent errors**: Temporary network issues with retry logic
//! - **Timeout errors**: Scan operations that exceed configured limits
//!
//! Retry behavior is configurable via [`ScanRetryConfig`].

pub mod block_event_accumulator;
pub mod block_processor;
pub mod events;
pub mod reorg;
pub mod scan_db_handler;
pub mod types;

mod builder;
mod config;
mod coordinator;
mod rescan;
mod scanner_state_manager;

pub use builder::Scanner;
pub use config::DEFAULT_FAST_SYNC_SAFETY_BUFFER;
pub use config::ScanMode;
pub use config::ScanRetryConfig;
pub use config::ScanTimeoutConfig;
pub use rescan::{rescan, rescan_with_events, rollback_account_to_height};
pub use types::ScanError;

pub use block_processor::MemoInfo;
pub use events::*;
