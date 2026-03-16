//! Core blockchain scanner implementation.
//!
//! This module contains the [`Scanner`] builder and the main scanning loop logic
//! for synchronizing wallet state with the blockchain.

use lightweight_wallet_libs::{HttpBlockchainScanner, ScanConfig, scanning::BlockchainScanner};
use log::{info, warn};
use rusqlite::Connection;
use std::{path::PathBuf, time::Duration};
use tari_transaction_components::key_manager::{KeyManager, TransactionKeyManagerInterface};
use tari_utilities::ByteArray;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use thiserror::Error;

use crate::{
    db::{self, AccountRow, SqlitePool, WalletDbError},
    http::WalletHttpClient,
    models::WalletEvent,
    scan::{
        block_processor::BlockProcessorError,
        events::{
            ChannelEventSender, EventSender, NoopEventSender, PauseReason, ProcessingEvent, ReorgDetectedEvent,
            ScanStatusEvent, TransactionsUpdatedEvent,
        },
        reorg,
        scan_db_handler::ScanDbHandler,
    },
    transactions::{MonitoringState, TransactionMonitor},
};

/// Unix timestamp for the genesis epoch used in birthday calculations.
const BIRTHDAY_GENESIS_FROM_UNIX_EPOCH: u64 = 1640995200; // seconds to 2022-01-01 00:00:00 UTC;

/// Default timeout for individual scan operations (5 minutes).
const DEFAULT_SCAN_TIMEOUT: Duration = Duration::from_secs(60 * 5);

/// Default number of retries after timeout before giving up.
const DEFAULT_MAX_TIMEOUT_RETRIES: u32 = 3;

/// Default number of retries after errors before giving up.
const DEFAULT_MAX_ERROR_RETRIES: u32 = 3;

/// Default base for exponential backoff on errors (in seconds).
const DEFAULT_ERROR_BACKOFF_BASE_SECS: u64 = 2;

/// Default number of days to offset from wallet birthday when calculating start height.
const DEFAULT_SCANNING_OFFSET_DAYS: u64 = 2;

const MAX_BACKOFF_EXPONENT: u32 = 5;
const MAX_BACKOFF_SECONDS: u64 = 60;
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

/// Internal context holding state for an active scanning session.
///
/// This struct aggregates all the components needed during a scan operation,
/// including the blockchain scanner, account information, and monitoring state.
struct ScanContext {
    /// The HTTP-based blockchain scanner for fetching blocks.
    scanner: HttpBlockchainScanner<KeyManager>,
    /// Database ID of the account being scanned.
    account_id: i64,
    /// The account's view key bytes for output detection.
    account_view_key: Vec<u8>,
    /// Configuration for the scan operation (start height, batch size).
    scan_config: ScanConfig,
    /// Number of blocks between reorg checks during scanning.
    reorg_check_interval: u64,
    /// HTTP client for additional wallet operations.
    wallet_client: WalletHttpClient,
    /// Monitor for tracking pending transaction confirmations.
    transaction_monitor: TransactionMonitor,
}

impl ScanContext {
    /// Updates the starting height for the next scan batch.
    fn set_start_height(&mut self, height: u64) {
        self.scan_config = self.scan_config.clone().with_start_height(height);
    }

    /// Scans blocks with timeout and retry handling.
    ///
    /// This method wraps the underlying scanner's `scan_blocks` operation with
    /// configurable timeout and retry logic. It handles both timeout errors
    /// (retries immediately) and scan errors (exponential backoff).
    ///
    /// # Returns
    ///
    /// Returns a tuple of (scanned_blocks, more_blocks_available) on success.
    ///
    /// # Errors
    ///
    /// Returns [`ScanError::Timeout`] if max timeout retries exceeded, or
    /// [`ScanError::Intermittent`] if max error retries exceeded.
    async fn scan_blocks_with_timeout(
        &mut self,
        retry_config: &ScanRetryConfig,
    ) -> Result<(Vec<lightweight_wallet_libs::BlockScanResult>, bool), ScanError> {
        let mut timeout_retries = 0;
        let mut error_retries = 0;

        loop {
            match timeout(retry_config.timeout, self.scanner.scan_blocks(&self.scan_config)).await {
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(e)) => {
                    error_retries += 1;
                    let error_msg = e.to_string();
                    warn!(
                        error = &*error_msg,
                        retry = error_retries,
                        max = retry_config.max_error_retries;
                        "Blockchain scan failed"
                    );

                    if error_retries >= retry_config.max_error_retries {
                        return Err(ScanError::Intermittent(error_msg));
                    }

                    // Exponential backoff for error retries
                    let backoff_secs = retry_config
                        .error_backoff_base_secs
                        .pow(error_retries.min(MAX_BACKOFF_EXPONENT))
                        .min(MAX_BACKOFF_SECONDS);
                    info!(
                        seconds = backoff_secs;
                        "Waiting before retrying..."
                    );
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                },
                Err(_elapsed) => {
                    timeout_retries += 1;
                    warn!(
                        retry = timeout_retries,
                        max = retry_config.max_timeout_retries;
                        "scan_blocks timed out"
                    );

                    if timeout_retries >= retry_config.max_timeout_retries {
                        return Err(ScanError::Timeout(timeout_retries));
                    }
                },
            }
        }
    }
}

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

/// Emits a reorg detection event and returns the new resume height.
///
/// This helper function constructs and sends a [`ReorgDetectedEvent`] through
/// the provided event sender, encapsulating all relevant reorg information.
fn emit_reorg_event<E: EventSender>(
    event_sender: &E,
    account_id: i64,
    reorg_info: reorg::ReorgInformation,
    resume_height: u64,
) -> u64 {
    event_sender.send(ProcessingEvent::ReorgDetected(ReorgDetectedEvent {
        account_id,
        reorg_from_height: reorg_info.rolled_back_from_height,
        new_height: resume_height,
        blocks_rolled_back: reorg_info.rolled_back_blocks_count,
        invalidated_output_hashes: reorg_info.invalidated_output_hashes,
        cancelled_transaction_ids: reorg_info.cancelled_transaction_ids,
        reorganized_displayed_transactions: reorg_info.reorganized_displayed_transactions,
    }));
    resume_height
}

/// Result of waiting for the next poll cycle in continuous scanning mode.
enum ContinuousWaitResult {
    /// Continue scanning from the specified height.
    Continue { resume_height: u64 },
    /// Scanning was cancelled via the cancellation token.
    Cancelled,
}

/// Waits for the next poll cycle in continuous scanning mode.
///
/// This function handles the inter-poll waiting period, checking for reorgs
/// at the start of each new cycle. It respects cancellation tokens for graceful
/// shutdown support.
///
/// # Arguments
///
/// * `scanner_context` - Mutable reference to the scan context
/// * `conn` - Database connection for reorg checks
/// * `event_sender` - Event sender for status updates
/// * `poll_interval` - Duration to wait between scan cycles
/// * `last_scanned_height` - The height of the last successfully scanned block
/// * `cancel_token` - Optional cancellation token for shutdown
///
/// # Returns
///
/// Returns [`ContinuousWaitResult::Continue`] with the height to resume from,
/// or [`ContinuousWaitResult::Cancelled`] if cancellation was requested.
async fn wait_for_next_poll_cycle<E: EventSender>(
    scanner_context: &mut ScanContext,
    db_handler: &ScanDbHandler,
    event_sender: &E,
    poll_interval: Duration,
    last_scanned_height: u64,
    cancel_token: Option<&CancellationToken>,
) -> Result<ContinuousWaitResult, ScanError> {
    event_sender.send(ProcessingEvent::ScanStatus(ScanStatusEvent::Waiting {
        account_id: scanner_context.account_id,
        resume_in: poll_interval,
    }));

    if let Some(token) = cancel_token {
        tokio::select! {
            _ = tokio::time::sleep(poll_interval) => {}
            _ = token.cancelled() => {
                event_sender.send(ProcessingEvent::ScanStatus(ScanStatusEvent::Paused {
                    account_id: scanner_context.account_id,
                    last_scanned_height,
                    reason: PauseReason::Cancelled,
                }));
                return Ok(ContinuousWaitResult::Cancelled);
            }
        }
    } else {
        tokio::time::sleep(poll_interval).await;
    }

    let mut conn = db_handler.get_connection().await?;

    let reorg_result = reorg::handle_reorgs(&mut scanner_context.scanner, &mut conn, scanner_context.account_id)
        .await
        .map_err(ScanError::Fatal)?;

    let mut resume_height = last_scanned_height;

    if let Some(reorg_info) = reorg_result.reorg_information {
        warn!(
            old_height = last_scanned_height,
            new_height = reorg_result.resume_height;
            "Reorg detected at poll cycle start. Resetting height."
        );
        resume_height = emit_reorg_event(
            event_sender,
            scanner_context.account_id,
            reorg_info,
            reorg_result.resume_height,
        );
    }

    event_sender.send(ProcessingEvent::ScanStatus(ScanStatusEvent::Started {
        account_id: scanner_context.account_id,
        from_height: resume_height,
    }));

    scanner_context.set_start_height(resume_height);

    Ok(ContinuousWaitResult::Continue { resume_height })
}

/// Prepares a scan context for an account.
///
/// Initializes the blockchain scanner, handles any pending reorgs, calculates
/// the starting height based on wallet birthday, and sets up transaction monitoring.
///
/// # Arguments
///
/// * `account` - The account row from the database
/// * `password` - Password for decrypting the account's key manager
/// * `base_url` - Base URL for the blockchain node HTTP API
/// * `batch_size` - Number of blocks to fetch per scan batch
/// * `processing_threads` - Number of parallel threads for output detection
/// * `reorg_check_interval` - Blocks between reorg checks
/// * `monitoring_state` - State for transaction monitoring
/// * `conn` - Database connection
///
/// # Errors
///
/// Returns [`ScanError::Fatal`] for key decryption or database errors,
/// or [`ScanError::Intermittent`] for scanner initialization failures.
#[allow(clippy::too_many_arguments)]
async fn prepare_account_scan(
    account: &AccountRow,
    password: &str,
    base_url: &str,
    batch_size: u64,
    processing_threads: usize,
    scanning_offset: u64,
    reorg_check_interval: u64,
    monitoring_state: MonitoringState,
    conn: &mut Connection,
    required_confirmations: u64,
) -> Result<ScanContext, ScanError> {
    let key_manager = account.get_key_manager(password)?;
    let account_view_key = key_manager.get_private_view_key().as_bytes().to_vec();

    let mut scanner = HttpBlockchainScanner::new(base_url.to_string(), vec![key_manager.clone()], processing_threads)
        .await
        .map_err(|e| ScanError::Intermittent(e.to_string()))?;

    let reorg_result = reorg::handle_reorgs(&mut scanner, conn, account.id)
        .await
        .map_err(ScanError::Fatal)?;

    let mut start_height = reorg_result.resume_height;

    let wallet_client = WalletHttpClient::new(
        base_url
            .parse()
            .map_err(|e| ScanError::Fatal(anyhow::anyhow!("{}", e)))?,
    )
    .map_err(ScanError::Fatal)?;

    if start_height == 0 {
        let timestamp =
            (account.birthday as u64).saturating_sub(scanning_offset) * 24 * 60 * 60 + BIRTHDAY_GENESIS_FROM_UNIX_EPOCH;
        start_height = wallet_client
            .get_height_at_time(timestamp)
            .await
            .map_err(ScanError::Fatal)?;
    };

    let scan_config = ScanConfig::default()
        .with_start_height(start_height)
        .with_batch_size(batch_size);

    monitoring_state
        .initialize(conn, account.id)
        .map_err(ScanError::Fatal)?;

    let transaction_monitor = TransactionMonitor::new(monitoring_state, required_confirmations);

    Ok(ScanContext {
        scanner,
        account_id: account.id,
        account_view_key,
        scan_config,
        reorg_check_interval,
        wallet_client,
        transaction_monitor,
    })
}

/// Executes the main scanning loop for an account.
///
/// This is the core scanning logic that iterates through blocks, processes them,
/// handles reorgs, and manages continuous polling. It coordinates between the
/// block processor, transaction monitor, and event system.
///
/// # Arguments
///
/// * `scanner_context` - Mutable context for the scanning session
/// * `conn` - Database connection pool
/// * `event_sender` - Channel for emitting scan events
/// * `mode` - The scanning mode (Full, Partial, or Continuous)
/// * `retry_config` - Configuration for retry behavior
/// * `cancel_token` - Optional token for cancellation support
///
/// # Returns
///
/// Returns a tuple of (wallet_events, more_blocks_available). The `more_blocks`
/// flag indicates whether scanning was paused before reaching chain tip.
///
/// # Event Emission
///
/// This function emits various events during execution:
/// - `ScanStatus::Started` at the beginning
/// - `ScanStatus::Progress` after each batch
/// - `ScanStatus::Completed` when reaching tip
/// - `ScanStatus::Paused` when stopping early
/// - `ScanStatus::MoreBlocksAvailable` when more blocks exist
async fn run_scan_loop<E: EventSender + Clone + Send + 'static>(
    scanner_context: &mut ScanContext,
    pool: &SqlitePool,
    event_sender: E,
    mode: &ScanMode,
    retry_config: &ScanRetryConfig,
    cancel_token: Option<&CancellationToken>,
    required_confirmations: u64,
) -> Result<(Vec<WalletEvent>, bool), ScanError> {
    info!(
        target: "audit",
        account_id = scanner_context.account_id,
        start_height = scanner_context.scan_config.start_height;
        "Starting scan for account"
    );
    let db_handler = ScanDbHandler::new(pool.clone(), required_confirmations);
    let mut all_events = Vec::new();
    let mut total_scanned: u64 = 0;
    let mut blocks_since_reorg_check: u64 = 0;
    let initial_height = scanner_context.scan_config.start_height;
    let mut last_scanned_height = initial_height;

    event_sender.send(ProcessingEvent::ScanStatus(ScanStatusEvent::Started {
        account_id: scanner_context.account_id,
        from_height: initial_height,
    }));

    loop {
        if let ScanMode::Partial { max_blocks } = mode
            && total_scanned >= *max_blocks
        {
            event_sender.send(ProcessingEvent::ScanStatus(ScanStatusEvent::Paused {
                account_id: scanner_context.account_id,
                last_scanned_height,
                reason: PauseReason::MaxBlocksReached { limit: *max_blocks },
            }));
            return Ok((all_events, true));
        }

        if let Some(token) = cancel_token
            && token.is_cancelled()
        {
            event_sender.send(ProcessingEvent::ScanStatus(ScanStatusEvent::Paused {
                account_id: scanner_context.account_id,
                last_scanned_height,
                reason: PauseReason::Cancelled,
            }));
            return Ok((all_events, true));
        }

        let (scanned_blocks, more_blocks) = scanner_context.scan_blocks_with_timeout(retry_config).await?;
        let batch_size = scanned_blocks.len();
        total_scanned += batch_size as u64;

        if scanned_blocks.is_empty() || !more_blocks {
            event_sender.send(ProcessingEvent::ScanStatus(ScanStatusEvent::Completed {
                account_id: scanner_context.account_id,
                final_height: last_scanned_height,
                total_blocks_scanned: total_scanned,
            }));

            if let ScanMode::Continuous { poll_interval } = mode {
                match wait_for_next_poll_cycle(
                    scanner_context,
                    &db_handler,
                    &event_sender,
                    *poll_interval,
                    last_scanned_height,
                    cancel_token,
                )
                .await?
                {
                    ContinuousWaitResult::Cancelled => return Ok((all_events, false)),
                    ContinuousWaitResult::Continue { resume_height } => {
                        last_scanned_height = resume_height;
                        total_scanned = 0;
                        continue;
                    },
                }
            }
            return Ok((all_events, false));
        }

        let has_pending_outbound = scanner_context.transaction_monitor.has_pending_outbound();
        let processing_events = db_handler
            .process_blocks(
                scanned_blocks.clone(),
                scanner_context.account_id,
                scanner_context.account_view_key.clone(),
                event_sender.clone(),
                has_pending_outbound,
            )
            .await?;

        all_events.extend(processing_events);

        if let Some(last_block) = scanned_blocks.last() {
            last_scanned_height = last_block.height;
            blocks_since_reorg_check += batch_size as u64;

            let monitor_result = scanner_context
                .transaction_monitor
                .monitor_if_needed(
                    &scanner_context.wallet_client,
                    pool,
                    scanner_context.account_id,
                    last_scanned_height,
                )
                .await
                .map_err(ScanError::Fatal)?;

            all_events.extend(monitor_result.wallet_events);

            if !monitor_result.updated_displayed_transactions.is_empty() {
                event_sender.send(ProcessingEvent::TransactionsUpdated(TransactionsUpdatedEvent {
                    account_id: scanner_context.account_id,
                    updated_transactions: monitor_result.updated_displayed_transactions,
                }));
            }
        }

        if more_blocks && blocks_since_reorg_check >= scanner_context.reorg_check_interval {
            let mut conn = db_handler.get_connection().await?;
            let reorg_result =
                reorg::handle_reorgs(&mut scanner_context.scanner, &mut conn, scanner_context.account_id)
                    .await
                    .map_err(ScanError::Fatal)?;

            if let Some(reorg_info) = reorg_result.reorg_information {
                warn!(
                    target: "audit",
                    old_height = last_scanned_height,
                    new_height = reorg_result.resume_height;
                    "Reorg detected during scan. Resetting height."
                );
                last_scanned_height = emit_reorg_event(
                    &event_sender,
                    scanner_context.account_id,
                    reorg_info,
                    reorg_result.resume_height,
                );
                scanner_context.set_start_height(reorg_result.resume_height);
            }
            blocks_since_reorg_check = 0;
        }

        db_handler
            .prune_tips(scanner_context.account_id, last_scanned_height)
            .await?;

        event_sender.send(ProcessingEvent::ScanStatus(ScanStatusEvent::Progress {
            account_id: scanner_context.account_id,
            current_height: last_scanned_height,
            blocks_scanned: total_scanned,
        }));

        if more_blocks {
            event_sender.send(ProcessingEvent::ScanStatus(ScanStatusEvent::MoreBlocksAvailable {
                account_id: scanner_context.account_id,
                last_scanned_height,
            }));
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
}

/// Builder for configuring and executing blockchain scanning operations.
///
/// The `Scanner` provides a fluent API for configuring all aspects of blockchain
/// scanning, from basic parameters to advanced retry and timeout settings.
///
/// # Example
///
/// ```rust,ignore
/// use std::time::Duration;
/// use crate::scan::{Scanner, ScanMode};
/// use tokio_util::sync::CancellationToken;
///
/// let cancel_token = CancellationToken::new();
///
/// let scanner = Scanner::new("wallet_password", "http://localhost:18142", "wallet.db", 100)
///     .account("primary")
///     .mode(ScanMode::Continuous {
///         poll_interval: Duration::from_secs(30),
///     })
///     .processing_threads(4)
///     .reorg_check_interval(500)
///     .scan_timeout(Duration::from_secs(300))
///     .max_timeout_retries(5)
///     .cancel_token(cancel_token.clone());
///
/// // Run without events
/// let (events, more_blocks) = scanner.run().await?;
///
/// // Or run with real-time events
/// let (event_rx, scan_future) = scanner.run_with_events();
/// ```
///
/// # Thread Safety
///
/// The `Scanner` is not designed to be shared across threads. Create separate
/// scanner instances for concurrent scanning of different accounts.
pub struct Scanner {
    /// Password for decrypting account key managers.
    password: String,
    /// Base URL for the blockchain node HTTP API.
    base_url: String,
    /// Path to the SQLite database file.
    database_file: PathBuf,
    /// Optional account name filter. If `None`, scans all accounts.
    account_name: Option<String>,
    /// Number of blocks to fetch per scan batch.
    batch_size: u64,
    /// Number of parallel threads for output detection.
    processing_threads: usize,
    /// Number of days to offset birthday scanning by.
    scanning_offset: u64,
    /// Number of blocks between periodic reorg checks.
    reorg_check_interval: u64,
    /// Scanning mode (Full, Partial, or Continuous).
    mode: ScanMode,
    /// Retry configuration for timeouts and errors.
    retry_config: ScanRetryConfig,
    /// Optional cancellation token for graceful shutdown.
    cancel_token: Option<CancellationToken>,
    /// Required confirmations
    required_confirmations: u64,
}

impl Scanner {
    /// Creates a new scanner with essential configuration.
    ///
    /// # Arguments
    ///
    /// * `password` - Password for decrypting account key managers
    /// * `base_url` - Base URL for the blockchain node HTTP API (e.g., "http://localhost:18142")
    /// * `database_file` - Path to the SQLite database file
    /// * `batch_size` - Number of blocks to fetch per scan batch (recommended: 50-200)
    ///
    /// # Defaults
    ///
    /// - Processing threads: 8
    /// - Reorg check interval: 1000 blocks
    /// - Mode: [`ScanMode::Full`]
    /// - Retry config: Default values
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let scanner = Scanner::new("password", "http://localhost:18142", "wallet.db", 100);
    /// ```
    pub fn new(
        password: &str,
        base_url: &str,
        database_file: PathBuf,
        batch_size: u64,
        required_confirmations: u64,
    ) -> Self {
        Self {
            password: password.to_string(),
            base_url: base_url.to_string(),
            database_file,
            account_name: None,
            batch_size,
            processing_threads: 8,
            scanning_offset: DEFAULT_SCANNING_OFFSET_DAYS,
            reorg_check_interval: 1000,
            mode: ScanMode::Full,
            retry_config: ScanRetryConfig::default(),
            cancel_token: None,
            required_confirmations,
        }
    }

    /// Restricts scanning to a specific account by name.
    ///
    /// If not called, all accounts in the database will be scanned sequentially.
    ///
    /// # Arguments
    ///
    /// * `name` - The account name to scan
    pub fn account(mut self, name: &str) -> Self {
        self.account_name = Some(name.to_string());
        self
    }

    /// Sets the scanning mode.
    ///
    /// See [`ScanMode`] for available options.
    pub fn mode(mut self, mode: ScanMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets the number of parallel threads for output detection.
    ///
    /// Higher values can improve scan speed but increase CPU usage.
    /// Recommended range: 4-16 threads depending on hardware.
    ///
    /// # Arguments
    ///
    /// * `threads` - Number of parallel processing threads
    pub fn processing_threads(mut self, threads: usize) -> Self {
        self.processing_threads = threads;
        self
    }

    /// Sets the interval (in blocks) between reorg checks during scanning.
    ///
    /// Lower values detect reorgs faster but may increase overhead.
    /// Higher values are more efficient but may process more blocks before
    /// detecting a reorg.
    ///
    /// # Arguments
    ///
    /// * `interval` - Number of blocks between reorg checks
    pub fn reorg_check_interval(mut self, interval: u64) -> Self {
        self.reorg_check_interval = interval;
        self
    }

    /// Sets timeout configuration using the simplified [`ScanTimeoutConfig`].
    ///
    /// This is converted to a [`ScanRetryConfig`] internally.
    pub fn timeout_config(mut self, config: ScanTimeoutConfig) -> Self {
        self.retry_config = config.into();
        self
    }

    /// Sets the full retry configuration.
    ///
    /// For comprehensive control over timeout and error retry behavior.
    pub fn retry_config(mut self, config: ScanRetryConfig) -> Self {
        self.retry_config = config;
        self
    }

    /// Sets the timeout duration for individual scan batch operations.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum duration for a single scan batch
    pub fn scan_timeout(mut self, timeout: Duration) -> Self {
        self.retry_config.timeout = timeout;
        self
    }

    /// Sets the maximum number of timeout retries.
    ///
    /// # Deprecated
    ///
    /// Use [`max_timeout_retries`](Self::max_timeout_retries) instead.
    pub fn max_scan_retries(mut self, retries: u32) -> Self {
        self.retry_config.max_timeout_retries = retries;
        self
    }

    /// Sets the maximum number of retry attempts after timeouts.
    ///
    /// When a scan batch exceeds the configured timeout, it will be retried
    /// up to this many times before returning [`ScanError::Timeout`].
    pub fn max_timeout_retries(mut self, retries: u32) -> Self {
        self.retry_config.max_timeout_retries = retries;
        self
    }

    /// Sets the maximum number of retry attempts after errors.
    ///
    /// When a scan batch fails with an error, it will be retried with
    /// exponential backoff up to this many times before returning
    /// [`ScanError::Intermittent`].
    pub fn max_error_retries(mut self, retries: u32) -> Self {
        self.retry_config.max_error_retries = retries;
        self
    }

    /// Sets the base value for exponential backoff on error retries.
    ///
    /// The actual delay is calculated as `base^min(retry_count, 5)` seconds.
    ///
    /// # Arguments
    ///
    /// * `secs` - Base value in seconds for backoff calculation
    pub fn error_backoff_base_secs(mut self, secs: u64) -> Self {
        self.retry_config.error_backoff_base_secs = secs;
        self
    }

    /// Sets a cancellation token for graceful shutdown support.
    ///
    /// When the token is cancelled, the scanner will stop at the next
    /// convenient point and return with the results processed so far.
    ///
    /// # Arguments
    ///
    /// * `token` - A [`CancellationToken`] for shutdown signaling
    pub fn cancel_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = Some(token);
        self
    }

    /// Runs the scanner without real-time event streaming.
    ///
    /// # Returns
    ///
    /// Returns a tuple of:
    /// - `Vec<WalletEvent>` - All wallet events detected during scanning
    /// - `bool` - `true` if more blocks are available (scanning was paused early)
    ///
    /// # Errors
    ///
    /// Returns [`ScanError`] on fatal errors, timeout exhaustion, or
    /// intermittent errors after max retries.
    pub async fn run(self) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        self.run_internal(NoopEventSender).await
    }

    /// Runs the scanner with real-time event streaming.
    ///
    /// Returns an unbounded channel receiver for events and a future that
    /// drives the scan. The caller should spawn a task to consume events
    /// from the receiver while awaiting the scan future.
    ///
    /// # Returns
    ///
    /// A tuple of:
    /// - `UnboundedReceiver<ProcessingEvent>` - Channel for receiving scan events
    /// - `Future` - The scan operation future
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let (event_rx, scan_future) = scanner.run_with_events();
    ///
    /// // Spawn event handler
    /// tokio::spawn(async move {
    ///     while let Some(event) = event_rx.recv().await {
    ///         match event {
    ///             ProcessingEvent::BlockProcessed(e) => println!("Block {}", e.height),
    ///             ProcessingEvent::ScanStatus(s) => println!("Status: {:?}", s),
    ///             _ => {}
    ///         }
    ///     }
    /// });
    ///
    /// // Run the scan
    /// let result = scan_future.await?;
    /// ```
    #[allow(clippy::type_complexity)]
    pub fn run_with_events(
        self,
    ) -> (
        mpsc::UnboundedReceiver<ProcessingEvent>,
        impl std::future::Future<Output = Result<(Vec<WalletEvent>, bool), ScanError>>,
    ) {
        let (tx, rx) = mpsc::unbounded_channel();
        let event_sender = ChannelEventSender::new(tx);
        let future = self.run_internal(event_sender);
        (rx, future)
    }

    /// Internal implementation that accepts any event sender.
    async fn run_internal<E: EventSender + Clone + Send + 'static>(
        self,
        event_sender: E,
    ) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        let pool = db::init_db(self.database_file.clone())?;
        let mut conn = pool.get().map_err(|e| ScanError::DbError(e.into()))?;
        let mut all_events = Vec::new();
        let mut any_more_blocks = false;

        let accounts = db::get_accounts(&conn, self.account_name.as_deref())?;
        for account in accounts {
            let monitoring_state = MonitoringState::new();

            let mut scan_context = prepare_account_scan(
                &account,
                &self.password,
                &self.base_url,
                self.batch_size,
                self.processing_threads,
                self.scanning_offset,
                self.reorg_check_interval,
                monitoring_state,
                &mut conn,
                self.required_confirmations,
            )
            .await?;

            let (events, more_blocks) = run_scan_loop(
                &mut scan_context,
                &pool,
                event_sender.clone(),
                &self.mode,
                &self.retry_config,
                self.cancel_token.as_ref(),
                self.required_confirmations,
            )
            .await?;

            all_events.extend(events);
            any_more_blocks = any_more_blocks || more_blocks;
        }

        Ok((all_events, any_more_blocks))
    }
}
