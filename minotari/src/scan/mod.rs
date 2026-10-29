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
mod scanner_state_manager;

pub use builder::Scanner;
pub use config::DEFAULT_FAST_SYNC_SAFETY_BUFFER;
pub use config::ScanMode;
pub use config::ScanRetryConfig;
pub use config::ScanTimeoutConfig;
pub use types::ScanError;

pub use block_processor::MemoInfo;
pub use events::*;
