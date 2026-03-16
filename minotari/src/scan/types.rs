use thiserror::Error;

use crate::{db::WalletDbError, scan::block_processor::BlockProcessorError};

/// Errors that can occur during blockchain scanning operations.
///
/// This enum distinguishes between different error severities to enable
/// appropriate retry and recovery strategies.
#[derive(Debug, Error)]
pub enum ScanError {
    /// An unrecoverable error that should stop scanning entirely.
    ///
    /// Examples include database corruption, invalid cryptographic keys,
    /// or critical configuration errors.
    #[error("Fatal error: {0}")]
    Fatal(#[from] anyhow::Error),

    /// A temporary error that may resolve with retries.
    ///
    /// Examples include network connectivity issues, temporary server
    /// unavailability, or rate limiting responses.
    #[error("Intermittent error: {0}")]
    Intermittent(String),

    /// The scan operation exceeded the configured timeout after all retry attempts.
    ///
    /// The contained value indicates the number of retry attempts made.
    #[error("Scan timed out after {0} retries")]
    Timeout(u32),

    /// DB execution failed
    #[error("Database execution error: {0}")]
    DbError(#[from] WalletDbError),
}

impl From<BlockProcessorError> for ScanError {
    fn from(e: BlockProcessorError) -> Self {
        ScanError::Fatal(e.into())
    }
}

/// Result of waiting for the next poll cycle in continuous scanning mode.
pub enum ContinuousWaitResult {
    /// Continue scanning from the specified height.
    Continue { resume_height: u64 },
    /// Scanning was cancelled via the cancellation token.
    Cancelled,
}
