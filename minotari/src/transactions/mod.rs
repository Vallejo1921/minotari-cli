//! Transaction management and processing for the Minotari wallet.
//!
//! This module provides comprehensive transaction handling capabilities including:
//!
//! - **Transaction Creation**: Build and prepare one-sided transactions for signing
//! - **Fund Locking**: Lock UTXOs to prevent double-spending during transaction construction
//! - **Input Selection**: Intelligent UTXO selection with fee calculation
//! - **Transaction History**: Query and manage historical transaction records
//! - **Transaction Monitoring**: Track pending transactions through broadcast, mining, and confirmation
//!
//! # Architecture
//!
//! The transaction system is organized into several cooperating components:
//!
//! ```text
//! +-------------------+     +------------------+     +-------------------+
//! | TransactionSender |---->| InputSelector    |---->| FundLocker        |
//! +-------------------+     +------------------+     +-------------------+
//!         |                         |                        |
//!         v                         v                        v
//! +-------------------+     +------------------+     +-------------------+
//! | OneSidedTransaction|    | UtxoSelection    |     | Database (UTXOs)  |
//! +-------------------+     +------------------+     +-------------------+
//!         |
//!         v
//! +-------------------+     +------------------+
//! | TransactionMonitor|---->| WalletHttpClient |
//! +-------------------+     +------------------+
//! ```
//!
//! # Transaction Lifecycle
//!
//! 1. **Selection**: [`InputSelector`] selects appropriate UTXOs and calculates fees
//! 2. **Locking**: [`FundLocker`] locks selected UTXOs with an expiration time
//! 3. **Building**: [`OneSidedTransaction`] or [`TransactionSender`] constructs the transaction
//! 4. **Signing**: External signing is performed on the prepared transaction
//! 5. **Broadcasting**: The signed transaction is submitted to the network
//! 6. **Monitoring**: [`TransactionMonitor`] tracks confirmation status
//!
//! # Key Types
//!
//! - [`DisplayedTransaction`]: User-facing transaction representation for UI display
//! - [`TransactionHistoryService`]: Service for querying transaction history
//! - [`TransactionMonitor`]: Monitors pending transactions for confirmation
//! - [`MonitoringState`]: Thread-safe state tracking for pending outbound transactions
//!
//! # Example
//!
//! ```rust,ignore
//! use minotari::transactions::{TransactionHistoryService, TransactionMonitor};
//!
//! // Load transaction history for an account
//! let history_service = TransactionHistoryService::new(db_pool.clone());
//! let transactions = history_service.load_all_transactions(account_id).await?;
//!
//! // Monitor pending transactions
//! let monitor = TransactionMonitor::new(monitoring_state);
//! let result = monitor.monitor_if_needed(&client, &mut conn, account_id, chain_height).await?;
//! ```
//!
//! # Modules
//!
//! - [`displayed_transaction_processor`]: Processes raw blockchain data into displayable transactions
//! - [`fee_estimator`]: Estimates fees
//! - [`fund_locker`]: Manages UTXO locking for transaction construction
//! - [`input_selector`]: Implements UTXO selection algorithms with fee estimation
//! - [`manager`]: High-level transaction creation and broadcasting
//! - [`monitor`]: Tracks transaction lifecycle from broadcast to confirmation
//! - [`one_sided_transaction`]: Builds one-sided (non-interactive) transactions
//! - [`transaction_history`]: Provides transaction history querying capabilities

pub mod displayed_transaction_processor;
pub mod fee_estimator;
pub mod fund_locker;
pub mod input_selector;
pub mod manager;
pub mod monitor;
pub mod one_sided_transaction;
pub mod transaction_history;

pub use displayed_transaction_processor::{
    BlockchainInfo, CounterpartyInfo, DisplayedTransaction, DisplayedTransactionBuilder, DisplayedTransactionProcessor,
    FeeInfo, ProcessorError, TransactionDetails, TransactionDirection, TransactionDisplayStatus, TransactionInput,
    TransactionOutput, TransactionSource,
};
pub use monitor::{MonitoringResult, MonitoringState, TransactionMonitor};
pub use transaction_history::{TransactionHistoryError, TransactionHistoryService};
