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
//! # Terminal Events
//!
//! Every run that returns `Ok` ends with exactly one terminal
//! [`ScanStatusEvent`] per scanned account. A scanner limited to an account
//! name that does not exist returns an error instead; one with no account
//! filter on a wallet without accounts returns `Ok` with no events.
//!
//! - `Completed { final_height, .. }`: the scan reached the chain tip (Full,
//!   Partial, FastSync) or its end height (backfill).
//! - `Cancelled { last_scanned_height, .. }`: the cancel token fired.
//! - `BudgetExhausted { last_scanned_height, tip_height, .. }`: the
//!   [`Scanner::deadline`] passed or `ScanMode::Partial { max_blocks }` were
//!   scanned before the tip (Continuous: the deadline passed, even when caught
//!   up). The two can be combined; the first limit reached stops the scan.
//!
//! The terminal event and `ReorgDetected` always reach a bounded channel,
//! even after a cancel: they wait for room, so the consumer must keep reading
//! (or drop the receiver) for a cancelled scan to finish. Other events that do
//! not fit after a cancel are dropped. The deadline is checked between batches
//! and does not cut short a download or a wait for room already in progress. A run that returns an error sends none. The next run
//! resumes after `last_scanned_height`, except a history backfill, which
//! always restarts from the birthday: a deadline shorter than the whole
//! backfill makes no lasting progress.
//!
//! # Resource Controls
//!
//! [`Scanner::processing_threads`] sizes the output detection pool,
//! [`Scanner::event_buffer`] bounds the event channel (the scan waits for a
//! slow consumer instead of buffering), and [`Scanner::deadline`] caps the
//! time. Separate `Scanner`s can scan different accounts at the same time.
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
//!    `Waiting { resume_in }` (the poll interval, cut short by a deadline).
//!    The scanner is idle until the next poll. A deadline that has passed
//!    ends the scan here with `BudgetExhausted` instead.
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
//! It sends `Cancelled` for every account (at the last block stored for it if
//! it is cancelled during startup) and returns `more_blocks == true`.
//! The one wait that is not interrupted is the end-of-pass transaction monitor,
//! so its updates are always reported; a cancel that arrives first skips it,
//! and its node requests are bounded by the HTTP client's timeout and retries.
//! Blocks are only written after a whole batch arrives, and a reorg rollback is
//! a single database transaction, so a cancelled scan leaves the database at
//! the last fully processed batch. The scanner's background download tasks
//! stop as soon as the scan drops its stream. Dropping the scan future stops it
//! the same way, without the `Cancelled` event.
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
//!     .processing_threads(1)
//!     .event_buffer(Some(256));
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
mod scanner_state_manager;

pub use builder::Scanner;
pub use config::DEFAULT_FAST_SYNC_SAFETY_BUFFER;
pub use config::ScanMode;
pub use config::ScanRetryConfig;
pub use config::ScanTimeoutConfig;
pub use types::ScanError;

pub use block_processor::MemoInfo;
pub use events::*;
