use std::time::Duration;

/// Default timeout for individual scan operations (5 minutes).
pub const DEFAULT_SCAN_TIMEOUT: Duration = Duration::from_secs(60 * 5);

/// Default number of retries after timeout before giving up.
pub const DEFAULT_MAX_TIMEOUT_RETRIES: u32 = 3;

/// Default number of retries after errors before giving up.
pub const DEFAULT_MAX_ERROR_RETRIES: u32 = 3;

/// Default base for exponential backoff on errors (in seconds).
pub const DEFAULT_ERROR_BACKOFF_BASE_SECS: u64 = 2;

/// Default number of days to offset from wallet birthday when calculating start height.
pub const DEFAULT_SCANNING_OFFSET_DAYS: u64 = 2;

pub const OPTIMAL_SCANNING_THREADS: usize = 0; // Based on num_cpus

/// Default safety buffer for fast sync mode (approximately 24 hours of blocks).
/// Blocks within this distance from the tip are scanned fully rather than fast-synced.
pub const DEFAULT_FAST_SYNC_SAFETY_BUFFER: u64 = 720;

/// Configuration for scan operation timeouts.
///
/// This is a simplified configuration struct for controlling timeout behavior.
/// For more comprehensive retry control, use [`ScanRetryConfig`] instead.
///
/// # Example
///
/// ```rust,ignore
/// use std::time::Duration;
/// use crate::scan::ScanTimeoutConfig;
///
/// let config = ScanTimeoutConfig {
///     timeout: Duration::from_secs(120),
///     max_retries: 5,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ScanTimeoutConfig {
    /// Maximum duration for a single scan batch operation.
    pub timeout: Duration,
    /// Maximum number of retry attempts after timeout.
    pub max_retries: u32,
}

impl Default for ScanTimeoutConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_SCAN_TIMEOUT,
            max_retries: DEFAULT_MAX_TIMEOUT_RETRIES,
        }
    }
}

/// Specifies the operational mode for blockchain scanning.
///
/// The scan mode determines how the scanner behaves after processing blocks
/// and whether it should continue polling for new blocks.
///
/// # Example
///
/// ```rust,ignore
/// use std::time::Duration;
/// use crate::scan::ScanMode;
///
/// // Scan at most 1000 blocks
/// let partial = ScanMode::Partial { max_blocks: 1000 };
///
/// // Scan all blocks to chain tip
/// let full = ScanMode::Full;
///
/// // Continuously monitor with 30-second polling
/// let continuous = ScanMode::Continuous {
///     poll_interval: Duration::from_secs(30),
/// };
/// ```
#[derive(Debug, Clone)]
pub enum ScanMode {
    /// Scan a limited number of blocks, then stop.
    ///
    /// Useful for incremental synchronization or testing. The scanner will
    /// return `more_blocks = true` if the chain tip was not reached.
    Partial {
        /// Maximum number of blocks to scan before stopping.
        max_blocks: u64,
    },

    /// Scan all blocks from the starting height to the chain tip, then stop.
    ///
    /// This is the default mode for initial wallet synchronization.
    Full,

    /// Scan to chain tip, then poll for new blocks at regular intervals.
    ///
    /// This mode is designed for real-time wallet monitoring. After reaching
    /// the chain tip, the scanner waits for the specified interval before
    /// checking for new blocks. Supports graceful cancellation via
    /// [`CancellationToken`].
    Continuous {
        /// Duration to wait between scan cycles after reaching chain tip.
        poll_interval: Duration,
    },

    /// Three-phase fast synchronization mode.
    ///
    /// Optimized for wallets that are far behind the chain tip:
    ///
    /// 1. **Fast UTXO scan**: Scans from birthday to `tip - safety_buffer` asking
    ///    the base node for unspent UTXOs only (`exclude_spent=true`). This skips
    ///    already-spent outputs for much faster initial sync.
    /// 2. **Recent full scan**: Full scan from `tip - safety_buffer` to tip with
    ///    complete output and input processing.
    /// 3. **History backfill**: Full scan from birthday to `tip - safety_buffer`
    ///    to fill in complete transaction history (spent outputs, inputs, balance
    ///    changes). Uses idempotent inserts to skip already-recorded data.
    FastSync {
        /// Number of blocks from chain tip that define the boundary between
        /// fast scanning and full scanning. Defaults to [`DEFAULT_FAST_SYNC_SAFETY_BUFFER`] (720).
        safety_buffer: u64,
    },
}

/// Comprehensive configuration for scan retry behavior.
///
/// Controls how the scanner handles both timeouts and errors during blockchain
/// scanning operations. Uses exponential backoff for error retries to avoid
/// overwhelming recovering servers.
///
/// # Retry Strategy
///
/// - **Timeout retries**: Immediate retry when a scan batch times out
/// - **Error retries**: Exponential backoff (base^retry_count seconds) for errors
///
/// # Example
///
/// ```rust,ignore
/// use std::time::Duration;
/// use crate::scan::ScanRetryConfig;
///
/// let config = ScanRetryConfig {
///     timeout: Duration::from_secs(300),
///     max_timeout_retries: 3,
///     max_error_retries: 5,
///     error_backoff_base_secs: 2, // 2s, 4s, 8s, 16s, 32s
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ScanRetryConfig {
    /// Maximum duration for a single scan batch operation.
    pub timeout: Duration,
    /// Maximum number of retry attempts after timeout before returning [`ScanError::Timeout`].
    pub max_timeout_retries: u32,
    /// Maximum number of retry attempts after errors before returning [`ScanError::Intermittent`].
    pub max_error_retries: u32,
    /// Base value (in seconds) for exponential backoff calculation on errors.
    ///
    /// The actual delay is calculated as `base^min(retry_count, 5)` seconds.
    pub error_backoff_base_secs: u64,
}

impl Default for ScanRetryConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_SCAN_TIMEOUT,
            max_timeout_retries: DEFAULT_MAX_TIMEOUT_RETRIES,
            max_error_retries: DEFAULT_MAX_ERROR_RETRIES,
            error_backoff_base_secs: DEFAULT_ERROR_BACKOFF_BASE_SECS,
        }
    }
}

impl From<ScanTimeoutConfig> for ScanRetryConfig {
    fn from(config: ScanTimeoutConfig) -> Self {
        Self {
            timeout: config.timeout,
            max_timeout_retries: config.max_retries,
            max_error_retries: DEFAULT_MAX_ERROR_RETRIES,
            error_backoff_base_secs: DEFAULT_ERROR_BACKOFF_BASE_SECS,
        }
    }
}
