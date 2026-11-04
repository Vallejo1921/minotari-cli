use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    ScanMode, WalletEvent, db,
    scan::{
        EventReceiver,
        config::{DEFAULT_SCANNING_OFFSET_DAYS, OPTIMAL_SCANNING_THREADS, ScanRetryConfig, ScanTimeoutConfig},
        coordinator::ScanCoordinator,
        events::EventChannel,
        types::ScanError,
    },
    webhooks::WebhookTriggerConfig,
};
use zeroize::Zeroizing;

/// Builder for configuring and executing blockchain scanning operations.
///
/// The `Scanner` provides a fluent API for configuring all aspects of blockchain
/// scanning, from basic parameters to advanced retry and timeout settings.
///
/// # Example
///
/// ```rust,ignore
/// use std::time::{Duration, Instant};
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
///     .processing_threads(1)
///     .event_buffer(Some(256))
///     .deadline(Instant::now() + Duration::from_secs(240))
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
    password: Zeroizing<String>,
    /// Base URL for the blockchain node HTTP API.
    base_url: String,
    /// Path to the SQLite database file.
    database_file: PathBuf,
    /// Optional account name filter. If `None`, scans all accounts.
    account_name: Option<String>,
    /// Number of blocks to fetch per scan batch.
    batch_size: u64,
    /// Number of parallel threads for output detection; 0 picks one per CPU, less two.
    processing_threads: usize,
    /// Size of the event channel; `None` is unbounded.
    event_buffer: Option<usize>,
    /// The scan stops at the first batch boundary after this instant.
    deadline: Option<Instant>,
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
    /// Webhook Configuration
    webhook_config: Option<WebhookTriggerConfig>,
    burn_proofs_dir: Option<PathBuf>,
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
    /// - Processing threads: one per CPU, less two (at least one)
    /// - Event channel: unbounded
    /// - Deadline: none
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
            password: Zeroizing::new(password.to_string()),
            base_url: base_url.to_string(),
            database_file,
            account_name: None,
            batch_size,
            processing_threads: OPTIMAL_SCANNING_THREADS,
            event_buffer: None,
            deadline: None,
            scanning_offset: DEFAULT_SCANNING_OFFSET_DAYS,
            reorg_check_interval: 1000,
            mode: ScanMode::Full,
            retry_config: ScanRetryConfig::default(),
            cancel_token: None,
            required_confirmations,
            webhook_config: None,
            burn_proofs_dir: None,
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

    /// Sets the number of threads in the scan's output detection pool.
    ///
    /// Higher values can improve scan speed but increase CPU usage. `0` (the
    /// default) uses one thread per CPU, less two, and at least one. Use `1`
    /// to keep a background scan light.
    ///
    /// # Arguments
    ///
    /// * `threads` - Number of parallel processing threads
    pub fn processing_threads(mut self, threads: usize) -> Self {
        self.processing_threads = threads;
        self
    }

    /// Sets the size of the event channel returned by [`run_with_events`](Self::run_with_events).
    ///
    /// `Some(n)` holds at most `n` events: when it is full the scan waits for
    /// the consumer, so a slow consumer slows the scan instead of growing
    /// memory. Cancelling stops the wait; events that do not fit after a cancel
    /// are dropped, except the terminal event and `ReorgDetected`, which still
    /// wait for room: after a cancel the consumer must keep reading (or drop the
    /// receiver) for the scan to finish. `None` (the default) is unbounded.
    pub fn event_buffer(mut self, size: Option<usize>) -> Self {
        self.event_buffer = size;
        self
    }

    /// Stops the scan at the first batch boundary after `deadline`.
    ///
    /// The deadline is checked between batches: it does not interrupt a block
    /// download, a node request or a wait for room in a bounded event channel
    /// that is already in progress, so a scan can run past it by that much.
    ///
    /// The scan then ends with [`ScanStatusEvent::BudgetExhausted`](crate::ScanStatusEvent::BudgetExhausted)
    /// (or `Completed` if a Full or Partial scan had reached the tip) and the
    /// next run resumes from the last scanned height. A history backfill
    /// ([`run_backfill`](Self::run_backfill)) is the exception: it always
    /// restarts from the birthday, so a deadline shorter than the whole
    /// backfill makes no lasting progress. It can be combined with
    /// [`ScanMode::Partial`]: the scan stops at whichever limit comes first.
    pub fn deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
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

    /// Sets webhook configuration
    pub fn webhook_config(mut self, config: WebhookTriggerConfig) -> Self {
        self.webhook_config = Some(config);
        self
    }

    /// Directory containing completed burn claim proof files to invalidate on rollback.
    pub fn burn_proofs_dir(mut self, dir: PathBuf) -> Self {
        self.burn_proofs_dir = Some(dir);
        self
    }

    async fn run_internal(self, events: EventChannel) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        let pool = db::init_db(self.database_file.clone())?;
        let conn = pool.get().map_err(|e| ScanError::DbError(e.into()))?;

        let accounts = accounts_to_scan(&conn, self.account_name.as_deref())?;
        let coordinator = ScanCoordinator::new(
            pool,
            self.base_url,
            events,
            self.retry_config,
            self.required_confirmations,
            self.webhook_config,
            self.processing_threads,
            self.reorg_check_interval,
            self.batch_size,
        )?
        .with_burn_proofs_dir(self.burn_proofs_dir)
        .with_deadline(self.deadline);

        coordinator
            .run(
                accounts,
                &self.password,
                self.mode,
                self.scanning_offset,
                self.cancel_token,
            )
            .await
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
        self.run_internal(EventChannel::None).await
    }

    /// Runs the scanner with real-time event streaming.
    ///
    /// Returns a receiver for events (bounded if [`event_buffer`](Self::event_buffer)
    /// is set) and a future that drives the scan. The caller should spawn a task to consume events
    /// from the receiver while awaiting the scan future.
    ///
    /// # Returns
    ///
    /// A tuple of:
    /// - `EventReceiver` - Channel for receiving scan events
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
        EventReceiver,
        impl std::future::Future<Output = Result<(Vec<WalletEvent>, bool), ScanError>>,
    ) {
        let (events, receiver) = self.event_channel();
        let future = self.run_internal(events);
        (receiver, future)
    }

    /// Runs the history backfill phase independently.
    ///
    /// This scans from each account's birthday to `backfill_to_height` using full
    /// block processing with idempotent inserts. Newly discovered outputs are marked
    /// `SpentUnconfirmed` and then verified against the base node.
    ///
    /// Call this after a fast sync has completed and the wallet is already usable.
    /// The backfill fills in complete transaction history (spent outputs, inputs,
    /// balance changes) for the period that was fast-synced. A cancelled or
    /// out-of-time backfill does not resume: the next one starts from the birthday.
    pub async fn run_backfill(self, backfill_to_height: u64) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        self.run_backfill_internal(backfill_to_height, EventChannel::None).await
    }

    /// Runs the history backfill with real-time event streaming.
    #[allow(clippy::type_complexity)]
    pub fn run_backfill_with_events(
        self,
        backfill_to_height: u64,
    ) -> (
        EventReceiver,
        impl std::future::Future<Output = Result<(Vec<WalletEvent>, bool), ScanError>>,
    ) {
        let (events, receiver) = self.event_channel();
        let future = self.run_backfill_internal(backfill_to_height, events);
        (receiver, future)
    }

    fn event_channel(&self) -> (EventChannel, EventReceiver) {
        match self.event_buffer {
            Some(size) => {
                // A tokio channel needs room for at least one event.
                let (sender, receiver) = mpsc::channel(size.max(1));
                let events = EventChannel::Bounded {
                    sender,
                    cancel: self.cancel_token.clone(),
                };
                (events, EventReceiver::Bounded(receiver))
            },
            None => {
                let (sender, receiver) = mpsc::unbounded_channel();
                (EventChannel::Unbounded(sender), EventReceiver::Unbounded(receiver))
            },
        }
    }

    async fn run_backfill_internal(
        self,
        backfill_to_height: u64,
        events: EventChannel,
    ) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        let pool = db::init_db(self.database_file.clone())?;
        let conn = pool.get().map_err(|e| ScanError::DbError(e.into()))?;

        let accounts = accounts_to_scan(&conn, self.account_name.as_deref())?;
        let coordinator = ScanCoordinator::new(
            pool,
            self.base_url,
            events,
            self.retry_config,
            self.required_confirmations,
            self.webhook_config,
            self.processing_threads,
            self.reorg_check_interval,
            self.batch_size,
        )?
        .with_burn_proofs_dir(self.burn_proofs_dir)
        .with_deadline(self.deadline);

        coordinator
            .run_backfill(
                accounts,
                &self.password,
                backfill_to_height,
                self.scanning_offset,
                self.cancel_token,
            )
            .await
    }
}

/// The accounts a scan covers. A named account that does not exist is an
/// error, so a scan never ends without a terminal event for the account asked for.
fn accounts_to_scan(conn: &rusqlite::Connection, name: Option<&str>) -> Result<Vec<db::AccountRow>, ScanError> {
    let accounts = db::get_accounts(conn, name)?;
    if name.is_some() && accounts.is_empty() {
        // The name stays out of the error: scan errors are logged.
        return Err(ScanError::DbError(db::WalletDbError::InvalidInput(
            "The account to scan was not found".to_string(),
        )));
    }
    Ok(accounts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scanning_an_unknown_account_is_an_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let database_file = dir.path().join("wallet.db");
        db::init_db(database_file.clone()).expect("init db");

        let scanner =
            || Scanner::new("password", "http://127.0.0.1:1", database_file.clone(), 10, 3).account("missing");
        let run = scanner().run().await;
        assert!(matches!(
            run,
            Err(ScanError::DbError(db::WalletDbError::InvalidInput(_)))
        ));
        let (_, scan) = scanner().run_with_events();
        assert!(matches!(
            scan.await,
            Err(ScanError::DbError(db::WalletDbError::InvalidInput(_)))
        ));
        let backfill = scanner().run_backfill(100).await;
        assert!(matches!(
            backfill,
            Err(ScanError::DbError(db::WalletDbError::InvalidInput(_)))
        ));
    }
}
