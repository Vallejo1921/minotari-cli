//! Event types and traits for blockchain scanning notifications.
//!
//! This module defines the event system used by the scanner to communicate
//! progress, detected activity, and status changes to subscribers. Events
//! are emitted through implementations of the [`EventSender`] trait.
//!
//! # Event Categories
//!
//! - **Block Events** ([`BlockProcessedEvent`]): Emitted after each block is processed
//! - **Status Events** ([`ScanStatusEvent`]): Progress updates and lifecycle changes
//! - **Transaction Events** ([`DisplayedTransactionsEvent`], [`TransactionsUpdatedEvent`]):
//!   Newly detected or updated transactions
//! - **Reorg Events** ([`ReorgDetectedEvent`]): Chain reorganization notifications
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use tokio::sync::mpsc;
//! use crate::scan::{ChannelEventSender, ProcessingEvent};
//!
//! let (tx, mut rx) = mpsc::unbounded_channel();
//! let sender = ChannelEventSender::new(tx);
//!
//! // In event handler
//! while let Some(event) = rx.recv().await {
//!     match event {
//!         ProcessingEvent::BlockProcessed(e) => {
//!             println!("Block {} processed: {} outputs", e.height, e.outputs_detected.len());
//!         }
//!         ProcessingEvent::ScanStatus(s) => {
//!             println!("Status: {:?}", s);
//!         }
//!         ProcessingEvent::ReorgDetected(r) => {
//!             println!("Reorg! Rolled back {} blocks", r.blocks_rolled_back);
//!         }
//!         _ => {}
//!     }
//! }
//! ```

use std::time::Duration;

use crate::models::Id;
use crate::transactions::DisplayedTransaction;
use tari_common_types::types::FixedHash;
use tari_transaction_components::MicroMinotari;
use tari_transaction_components::transaction_components::WalletOutput;

/// Top-level event enum for all scanner notifications.
///
/// This enum wraps all possible events emitted during blockchain scanning,
/// allowing consumers to handle them uniformly through a single channel.
#[derive(Debug, Clone)]
pub enum ProcessingEvent {
    /// A block has been fully processed.
    BlockProcessed(BlockProcessedEvent),

    /// Scan status has changed (started, progress, completed, paused, etc.).
    ScanStatus(ScanStatusEvent),

    /// New transactions are ready for display.
    TransactionsReady(DisplayedTransactionsEvent),

    /// Existing transactions have been updated (e.g., confirmations).
    TransactionsUpdated(TransactionsUpdatedEvent),

    /// A blockchain reorganization was detected and handled.
    ReorgDetected(ReorgDetectedEvent),
}

#[derive(Debug, Clone)]
pub struct DisplayedTransactionsEvent {
    pub account_id: i64,
    pub transactions: Vec<DisplayedTransaction>,
    pub block_height: Option<u64>,
    pub is_initial_sync: bool,
}

#[derive(Debug, Clone)]
pub struct TransactionsUpdatedEvent {
    pub account_id: i64,
    pub updated_transactions: Vec<DisplayedTransaction>,
}

#[derive(Debug, Clone)]
pub struct BlockProcessedEvent {
    pub account_id: i64,
    pub height: u64,
    pub block_hash: Vec<u8>,
    pub outputs_detected: Vec<DetectedOutput>,
    pub inputs_spent: Vec<SpentInput>,
    pub balance_changes: Vec<BalanceChangeSummary>,
}

#[derive(Debug, Clone)]
pub struct DetectedOutput {
    pub height: u64,
    pub mined_in_block_hash: FixedHash,
    pub output: WalletOutput,
}

#[derive(Debug, Clone)]
pub struct SpentInput {
    pub output_id: Id,
    pub mined_in_block: FixedHash,
    pub mined_in_block_height: u64,
    pub output: WalletOutput,
}

#[derive(Debug, Clone)]
pub struct ConfirmedOutput {
    pub hash: FixedHash,
    pub original_height: u64,
    pub confirmation_height: u64,
}

#[derive(Debug, Clone)]
pub struct BalanceChangeSummary {
    pub credit: MicroMinotari,
    pub debit: MicroMinotari,
    pub description: String,
}

#[derive(Debug, Clone)]
pub enum ScanStatusEvent {
    Started {
        account_id: i64,
        from_height: u64,
    },
    Progress {
        account_id: i64,
        current_height: u64,
        blocks_scanned: u64,
    },
    MoreBlocksAvailable {
        account_id: i64,
        last_scanned_height: u64,
    },
    Completed {
        account_id: i64,
        final_height: u64,
        total_blocks_scanned: u64,
    },
    Waiting {
        account_id: i64,
        resume_in: Duration,
    },
    Paused {
        account_id: i64,
        last_scanned_height: u64,
        reason: PauseReason,
    },
    FastSyncPhaseStarted {
        account_id: i64,
        phase: FastSyncPhase,
        from_height: u64,
        to_height: Option<u64>,
    },
    FastSyncPhaseCompleted {
        account_id: i64,
        phase: FastSyncPhase,
    },
}

#[derive(Debug, Clone)]
pub enum PauseReason {
    MaxBlocksReached { limit: u64 },
    Cancelled,
}

/// Identifies which phase of a fast sync operation is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastSyncPhase {
    /// Phase 1: Fast scan from birthday to (tip - safety_buffer), unspent UTXOs only.
    FastUtxoScan,
    /// Phase 2: Full scan of recent blocks from (tip - safety_buffer) to tip.
    RecentFullScan,
    /// Phase 3: Full history backfill from birthday to (tip - safety_buffer).
    HistoryBackfill,
}

#[derive(Debug, Clone)]
pub struct ReorgDetectedEvent {
    pub account_id: i64,
    pub reorg_from_height: u64,
    pub new_height: u64,
    pub blocks_rolled_back: u64,
    pub invalidated_output_hashes: Vec<FixedHash>,
    pub cancelled_transaction_ids: Vec<String>,
    pub reorganized_displayed_transactions: Vec<DisplayedTransaction>,
}

pub trait EventSender: Send + Sync {
    fn send(&self, event: ProcessingEvent) -> bool;
}

#[derive(Debug, Clone, Default)]
pub struct NoopEventSender;

impl EventSender for NoopEventSender {
    fn send(&self, _event: ProcessingEvent) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
pub struct ChannelEventSender {
    sender: tokio::sync::mpsc::UnboundedSender<ProcessingEvent>,
}

impl ChannelEventSender {
    pub fn new(sender: tokio::sync::mpsc::UnboundedSender<ProcessingEvent>) -> Self {
        Self { sender }
    }
}

impl EventSender for ChannelEventSender {
    fn send(&self, event: ProcessingEvent) -> bool {
        self.sender.send(event).is_ok()
    }
}
