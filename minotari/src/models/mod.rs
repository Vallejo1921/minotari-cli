//! Data models and type definitions for the wallet.
//!
//! This module contains the core data structures used throughout the wallet,
//! including wallet events, balance changes, and transaction statuses.
//!
//! # Key Types
//!
//! - [`WalletEvent`] - Events generated during wallet operations (outputs, confirmations, reorgs)
//! - [`WalletEventType`] - Enum of all possible wallet event types
//! - [`ScannedTipBlock`] - Represents a scanned blockchain tip for reorg detection
//! - [`BalanceChange`] - Represents a credit or debit to the wallet balance
//! - [`OutputStatus`] - Status of a UTXO (unconfirmed, confirmed, locked, spent)
//! - [`PendingTransactionStatus`] - Status of transactions being constructed
//!
//! # Event System
//!
//! Wallet events provide a timeline of all wallet activity and are used for:
//! - Tracking output detection and confirmation
//! - Detecting and handling blockchain reorganizations
//! - Monitoring transaction lifecycle (broadcast, mined, confirmed, rejected)
//! - Providing audit trail and transaction history

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use tari_common_types::tari_address::TariAddress;
use tari_common_types::transaction::TxId;
use tari_common_types::types::FixedHash;
use tari_transaction_components::MicroMinotari;

pub mod output_status;
pub use output_status::OutputStatus;
pub mod pending_transactions_status;
pub use pending_transactions_status::PendingTransactionStatus;

/// Database primary key type (SQLite integer).
pub type Id = i64;

/// Represents a scanned blockchain tip for reorg detection.
///
/// Each account maintains a history of recently scanned block hashes
/// to detect blockchain reorganizations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedTipBlock {
    pub id: Id,
    #[allow(dead_code)]
    pub account_id: Id,
    pub height: u64,
    pub hash: Vec<u8>,
}

/// A wallet event representing a significant occurrence in the wallet's history.
///
/// Events are stored in the database and provide an audit trail of all
/// wallet activity including outputs, transactions, and blockchain events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletEvent {
    #[allow(dead_code)]
    pub id: Id,
    #[allow(dead_code)]
    pub account_id: Id,
    /// The specific type and details of the event
    pub event_type: WalletEventType,
    /// Human-readable description of the event
    pub description: String,
}

/// Types of events that can occur in the wallet.
///
/// Each variant contains relevant data for that event type, such as
/// block heights, hashes, transaction IDs, and memos.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletEventType {
    BlockRolledBack {
        height: u64,
        block_hash: Vec<u8>,
    },
    OutputDetected {
        hash: FixedHash,
        block_height: u64,
        block_hash: Vec<u8>,
        memo_parsed: Option<String>,
        memo_hex: Option<String>,
    },
    OutputConfirmed {
        hash: FixedHash,
        block_height: u64,
        confirmation_height: u64,
        memo_parsed: Option<String>,
        memo_hex: Option<String>,
    },
    OutputRolledBack {
        hash: FixedHash,
        original_block_height: u64,
        rolled_back_at_height: u64,
    },
    PendingTransactionCancelled {
        tx_id: String,
        reason: String,
    },
    TransactionBroadcast {
        tx_id: TxId,
        kernel_excess: Vec<u8>,
    },
    TransactionUnconfirmed {
        tx_id: TxId,
        mined_height: u64,
        confirmations: u64,
    },
    TransactionConfirmed {
        tx_id: TxId,
        mined_height: u64,
        confirmation_height: u64,
    },
    TransactionRejected {
        tx_id: TxId,
        reason: String,
    },
    TransactionReorged {
        tx_id: TxId,
        original_mined_height: u64,
    },
    /// The node has not accepted a send after `MAX_BROADCAST_ATTEMPTS` tries.
    /// Not terminal: the send stays as it is, inputs locked, and is retried less
    /// often; only the wallet's own scan can show it will never land.
    TransactionStalled {
        tx_id: TxId,
        failed_broadcast_attempts: i32,
        /// The node's answer to the last try (sanitised), if it gave one.
        #[serde(default)]
        node_reason: Option<String>,
    },
}

impl WalletEventType {
    /// Returns a string key representing the event type (without data).
    ///
    /// This is useful for filtering and categorizing events in the database.
    pub fn to_key_string(&self) -> String {
        match &self {
            WalletEventType::BlockRolledBack { .. } => "BlockRolledBack".to_string(),
            WalletEventType::OutputDetected { .. } => "OutputDetected".to_string(),
            WalletEventType::OutputConfirmed { .. } => "OutputConfirmed".to_string(),
            WalletEventType::OutputRolledBack { .. } => "OutputRolledBack".to_string(),
            WalletEventType::PendingTransactionCancelled { .. } => "PendingTransactionCancelled".to_string(),
            WalletEventType::TransactionBroadcast { .. } => "TransactionBroadcast".to_string(),
            WalletEventType::TransactionUnconfirmed { .. } => "TransactionUnconfirmed".to_string(),
            WalletEventType::TransactionConfirmed { .. } => "TransactionConfirmed".to_string(),
            WalletEventType::TransactionRejected { .. } => "TransactionRejected".to_string(),
            WalletEventType::TransactionReorged { .. } => "TransactionReorged".to_string(),
            WalletEventType::TransactionStalled { .. } => "TransactionStalled".to_string(),
        }
    }
}

/// Represents a change to the wallet balance (credit or debit).
///
/// Balance changes are created when:
/// - Outputs are detected (credit)
/// - Outputs are confirmed (updates)
/// - Inputs are spent (debit)
/// - Transactions are broadcasted (fee debit)
///
/// Each balance change links to either an output or input and includes
/// metadata like memos, addresses, and claimed amounts from the transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceChange {
    /// Account this balance change belongs to
    pub account_id: Id,
    /// ID of the output that caused this change (for credits)
    pub caused_by_output_id: Option<Id>,
    /// ID of the input that caused this change (for debits)
    pub caused_by_input_id: Option<Id>,
    /// Human-readable description of the change
    pub description: String,
    /// Amount credited to the balance (in µT)
    pub balance_credit: MicroMinotari,
    /// Amount debited from the balance (in µT)
    pub balance_debit: MicroMinotari,
    /// Timestamp when the change becomes effective
    pub effective_date: NaiveDateTime,
    /// Block height when the change becomes effective
    pub effective_height: u64,
    /// Recipient address from transaction metadata
    pub claimed_recipient_address: Option<TariAddress>,
    /// Sender address from transaction metadata
    pub claimed_sender_address: Option<TariAddress>,
    /// Parsed memo text
    pub memo_parsed: Option<String>,
    /// Raw memo
    pub memo_hex: Option<String>,
    /// Transaction fee from metadata
    pub claimed_fee: Option<MicroMinotari>,
    /// Transaction amount from metadata
    pub claimed_amount: Option<MicroMinotari>,
    /// Whether this balance change is a reversal of another balance change (e.g., due to reorg)
    #[serde(default)]
    pub is_reversal: bool,
    /// The ID of the original balance change that this reverses (if is_reversal is true)
    pub reversal_of_balance_change_id: Option<Id>,
    /// Whether this balance change has been reversed (e.g., due to reorg)
    #[serde(default)]
    pub is_reversed: bool,
}

impl BalanceChange {
    /// Returns true if this balance change is a credit.
    pub fn is_credit(&self) -> bool {
        self.balance_credit > MicroMinotari::from(0)
    }

    /// Returns true if this balance change is a debit.
    pub fn is_debit(&self) -> bool {
        self.balance_debit > MicroMinotari::from(0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    /// The unique ID of the event in the wallet DB
    pub event_id: i64,
    /// The specific type of event (string representation)
    pub event_type: String,
    /// ISO 8601 Timestamp
    pub created_at: String,
    /// Snapshot of the account balance at the time of the event
    pub balance: Option<WebhookBalanceSnapshot>,
    /// The actual event data
    pub data: WalletEventType,
}

/// A simplified balance view for the webhook payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookBalanceSnapshot {
    pub available: u64,
    pub pending_incoming: u64,
    pub pending_outgoing: u64,
}
