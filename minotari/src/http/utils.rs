//! Utility functions for HTTP operations.
//!
//! This module provides helper functions used by the HTTP client layer,
//! primarily for validating transactions before submission to the network.
//!
//! # Transaction Size Limits
//!
//! The Tari RPC protocol has a maximum frame size of 4 MB. To ensure
//! transactions can be transmitted successfully (with room for coinbase
//! data and protocol overhead), this module enforces a conservative
//! size limit on transactions before submission.

use tari_transaction_components::transaction_components::Transaction;

/// Maximum RPC frame size (4 MB).
///
/// This is the hard limit imposed by the Tari RPC protocol.
const RPC_MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;

/// Size margin reserved for frame overhead and coinbase transactions.
///
/// This margin accounts for:
/// - 10 KB for RPC frame overhead (headers, metadata)
/// - 2 MB buffer for coinbase transaction data
///
/// The generous margin ensures transactions can be submitted reliably
/// even when combined with other data in the RPC frame.
const SIZE_MARGIN: usize = (1024 * 10) + (2 * 1024 * 1024);

/// Maximum allowed transaction size after accounting for margin.
///
/// Transactions larger than this (~1.99 MB) will be rejected before
/// submission to avoid RPC frame size errors.
const MAX_TRANSACTION_SIZE: usize = RPC_MAX_FRAME_SIZE - SIZE_MARGIN;

/// Error indicating a transaction exceeds the maximum allowed size.
///
/// This error is returned by [`check_transaction_size`] when a transaction
/// is too large to be submitted via the RPC protocol.
///
/// # Fields
///
/// * `got` - The actual size of the serialized transaction in bytes
/// * `max_allowed` - The maximum allowed size in bytes
///
/// # Example
///
/// ```rust,ignore
/// use minotari::http::utils::TransactionTooLargeError;
///
/// let err = TransactionTooLargeError {
///     got: 3_000_000,
///     max_allowed: 1_990_656,
/// };
/// println!("{}", err);
/// // Output: "Transaction too large: got 3000000 bytes, max allowed is 1990656 bytes"
/// ```
#[derive(Debug, Clone)]
pub struct TransactionTooLargeError {
    /// The actual size of the serialized transaction in bytes.
    pub got: usize,

    /// The maximum allowed transaction size in bytes.
    pub max_allowed: usize,
}

impl std::fmt::Display for TransactionTooLargeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Transaction too large: got {} bytes, max allowed is {} bytes",
            self.got, self.max_allowed
        )
    }
}

impl std::error::Error for TransactionTooLargeError {}

/// Validates that a transaction is within the allowed size limits.
///
/// This function serializes the transaction to JSON and checks that the
/// resulting size does not exceed the RPC frame size limit (minus overhead).
/// It should be called before submitting transactions to prevent RPC errors.
///
/// # Arguments
///
/// * `transaction` - The transaction to validate
///
/// # Returns
///
/// Returns `Ok(())` if the transaction size is acceptable.
///
/// # Errors
///
/// Returns [`TransactionTooLargeError`] if:
/// - The transaction cannot be serialized to JSON
/// - The serialized size exceeds [`MAX_TRANSACTION_SIZE`] (~1.99 MB)
///
/// # Example
///
/// ```rust,ignore
/// use tari_transaction_components::transaction_components::Transaction;
/// use minotari::http::utils::check_transaction_size;
///
/// fn submit_transaction(tx: &Transaction) -> Result<(), anyhow::Error> {
///     // Validate size before submitting
///     check_transaction_size(tx)?;
///
///     // Proceed with submission...
///     Ok(())
/// }
/// ```
///
/// # Performance
///
/// This function serializes the entire transaction to compute its size,
/// which involves memory allocation proportional to the transaction size.
/// For very large transactions, this may have noticeable overhead.
pub fn check_transaction_size(transaction: &Transaction) -> Result<(), TransactionTooLargeError> {
    let serialized = serde_json::to_vec(transaction).map_err(|_| TransactionTooLargeError {
        got: 0,
        max_allowed: MAX_TRANSACTION_SIZE,
    })?;

    let size = serialized.len();

    if size > MAX_TRANSACTION_SIZE {
        Err(TransactionTooLargeError {
            got: size,
            max_allowed: MAX_TRANSACTION_SIZE,
        })
    } else {
        Ok(())
    }
}
