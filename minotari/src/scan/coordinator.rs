use std::{collections::VecDeque, sync::Arc};

use lightweight_wallet_libs::{HttpBlockchainScanner, ScanConfig, scanning::BlockchainScanner};
use log::{info, warn};
use tari_common_types::{seeds::cipher_seed::BIRTHDAY_GENESIS_FROM_UNIX_EPOCH, types::PrivateKey};
use tari_transaction_components::key_manager::KeyManager;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::{
    PauseReason, ScanStatusEvent,
    db::{AccountRow, SqlitePool},
    http::WalletHttpClient,
    models::WalletEvent,
    scan::{
        DisplayedTransactionsEvent, ReorgDetectedEvent, ScanError, ScanMode, ScanRetryConfig, TransactionsUpdatedEvent,
        block_processor::BlockProcessor,
        config::{MAX_BACKOFF_EXPONENT, MAX_BACKOFF_SECONDS, OPTIMAL_SCANNING_THREADS},
        events::{EventSender, ProcessingEvent},
        reorg,
        scan_db_handler::ScanDbHandler,
        scanner_state_manager::ScannerStateManager,
    },
    transactions::{MonitoringResult, MonitoringState, TransactionMonitor},
    webhooks::WebhookTriggerConfig,
};
use tari_transaction_components::key_manager::TransactionKeyManagerInterface;

const MAX_CONTINUOUS_BUFFERED_EVENTS: usize = 10_000;

/// Represents an account that is part of the current global scan session.
/// This is an internal state object and should not be exposed publicly.
pub(crate) struct AccountSyncTarget {
    pub(crate) account: AccountRow,
    pub(crate) key_manager: KeyManager,
    pub(crate) view_key: PrivateKey,
    pub(crate) next_block_to_scan: u64,
    pub(crate) transaction_monitor: TransactionMonitor,
}

pub struct ScanCoordinator<E: EventSender> {
    pool: SqlitePool,
    base_url: String,
    client: WalletHttpClient,
    event_sender: E,
    retry_config: ScanRetryConfig,
    required_confirmations: u64,
    webhook_config: Option<WebhookTriggerConfig>,
    processing_threads: usize,
    reorg_check_interval: u64,
    batch_size: u64,
}

impl<E: EventSender + Clone + Send + 'static> ScanCoordinator<E> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: SqlitePool,
        base_url: String,
        event_sender: E,
        retry_config: ScanRetryConfig,
        required_confirmations: u64,
        webhook_config: Option<WebhookTriggerConfig>,
        processing_threads: usize,
        reorg_check_interval: u64,
        batch_size: u64,
    ) -> Result<Self, ScanError> {
        let client = WalletHttpClient::new(
            base_url
                .parse()
                .map_err(|e| ScanError::Fatal(anyhow::anyhow!("Invalid Base URL: {}", e)))?,
        )
        .map_err(ScanError::Fatal)?;
        Ok(Self {
            pool,
            base_url,
            client,
            event_sender,
            retry_config,
            required_confirmations,
            webhook_config,
            processing_threads,
            reorg_check_interval,
            batch_size,
        })
    }

    /// The main entry point for the multi-account scan.
    pub async fn run(
        &self,
        accounts: Vec<AccountRow>,
        password: &str,
        mode: ScanMode,
        scanning_offset: u64,
        cancel_token: Option<CancellationToken>,
    ) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        if accounts.is_empty() {
            return Ok((Vec::new(), false));
        }

        let mut conn = self.pool.get().map_err(|e| ScanError::DbError(e.into()))?;

        let first_km = accounts[0].get_key_manager(password)?;
        let mut shared_reorg_scanner = self.create_reorg_scanner(first_km).await?;

        let mut sync_targets = Vec::with_capacity(accounts.len());

        for account in accounts {
            let target = self
                .prepare_target(
                    account,
                    password,
                    &self.client,
                    scanning_offset,
                    &mut conn,
                    &mut shared_reorg_scanner,
                )
                .await?;
            sync_targets.push(target);
        }

        if let ScanMode::FastSync { safety_buffer } = mode {
            return self
                .run_fast_sync(sync_targets, safety_buffer, scanning_offset, cancel_token, &mut shared_reorg_scanner)
                .await;
        }

        self.unified_scan_loop(sync_targets, mode, cancel_token).await
    }

    /// Prepares a scan context for an account.
    async fn prepare_target(
        &self,
        account: AccountRow,
        password: &str,
        wallet_client: &WalletHttpClient,
        scanning_offset: u64,
        conn: &mut rusqlite::Connection,
        scanner: &mut HttpBlockchainScanner<KeyManager>,
    ) -> Result<AccountSyncTarget, ScanError> {
        let key_manager = account.get_key_manager(password)?;
        let view_key = key_manager.get_private_view_key();

        let reorg_result = reorg::handle_reorgs(scanner, conn, account.id, self.webhook_config.clone())
            .await
            .map_err(ScanError::Fatal)?;

        let mut next_block = reorg_result.resume_height;

        if next_block == 0 {
            // Use birthday logic
            let timestamp = (account.birthday as u64).saturating_sub(scanning_offset) * 24 * 60 * 60
                + BIRTHDAY_GENESIS_FROM_UNIX_EPOCH;
            next_block = wallet_client
                .get_height_at_time(timestamp)
                .await
                .map_err(ScanError::Fatal)?;
        }

        let monitor_state = MonitoringState::new();
        monitor_state.initialize(conn, account.id).map_err(ScanError::Fatal)?;

        let transaction_monitor =
            TransactionMonitor::new(monitor_state, self.required_confirmations, self.webhook_config.clone());

        Ok(AccountSyncTarget {
            account,
            key_manager,
            view_key,
            next_block_to_scan: next_block,
            transaction_monitor,
        })
    }

    async fn unified_scan_loop(
        &self,
        mut targets: Vec<AccountSyncTarget>,
        mode: ScanMode,
        cancel_token: Option<CancellationToken>,
    ) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        let mut all_events = VecDeque::new();
        let max_buffered_events = match mode {
            ScanMode::Continuous { .. } => Some(MAX_CONTINUOUS_BUFFERED_EVENTS),
            _ => None,
        };
        let all_accounts: Vec<(i64, PrivateKey)> = targets
            .iter()
            .map(|target| (target.account.id, target.view_key.clone()))
            .collect();
        let block_processor = BlockProcessor::with_event_sender(
            all_accounts,
            self.event_sender.clone(),
            false,
            self.required_confirmations,
        );
        let mut db_handler = ScanDbHandler::new(self.pool.clone(), block_processor);
        let mut total_scanned_globally: u64 = 0;
        let mut blocks_since_reorg_check: u64 = 0;

        let mut state_manager = ScannerStateManager::new();

        loop {
            if let Some(token) = &cancel_token
                && token.is_cancelled()
            {
                return self.handle_pause(&targets, PauseReason::Cancelled, all_events);
            }

            let global_next_block = targets.iter().map(|t| t.next_block_to_scan).min().unwrap_or(0);

            // Determine which accounts are active at this height
            let active_account_ids: Vec<i64> = targets
                .iter()
                .filter(|target| target.next_block_to_scan == global_next_block)
                .map(|target| target.account.id)
                .collect();

            let next_horizon_height = targets
                .iter()
                .map(|t| t.next_block_to_scan)
                .filter(|&h| h > global_next_block)
                .min();

            let end_height = next_horizon_height.map(|h| h.saturating_sub(1));

            let effective_batch_size = next_horizon_height
                .map(|h| h.saturating_sub(global_next_block).min(self.batch_size))
                .unwrap_or(self.batch_size);

            let (scanner, scanner_config) = state_manager
                .get_scanner_and_config(
                    &active_account_ids,
                    global_next_block,
                    end_height,
                    effective_batch_size,
                    &targets,
                    &self.base_url,
                    self.processing_threads,
                )
                .await?;

            let (scanned_blocks, mut more_blocks) = self.scan_blocks_with_timeout(scanner, &scanner_config).await?;

            // Go on, if we stopped on artificial horizon
            if let Some(horizon) = next_horizon_height
                && let Some(last_block) = scanned_blocks.last()
                && last_block.height >= horizon.saturating_sub(1)
            {
                more_blocks = true;
            }

            if more_blocks {
                for account_id in &active_account_ids {
                    self.event_sender
                        .send(ProcessingEvent::ScanStatus(ScanStatusEvent::MoreBlocksAvailable {
                            account_id: *account_id,
                            last_scanned_height: global_next_block.saturating_sub(1),
                        }));
                }
            }

            let mut max_new_height_in_batch = global_next_block;
            let is_batch_empty = scanned_blocks.is_empty();

            if !is_batch_empty {
                let shared_blocks = Arc::new(scanned_blocks);

                for account_id in &active_account_ids {
                    let Some(target) = targets.iter_mut().find(|target| target.account.id == *account_id) else {
                        return Err(ScanError::Fatal(anyhow::anyhow!(
                            "Unknown active account id: {}",
                            account_id
                        )));
                    };

                    let events = db_handler
                        .process_blocks(
                            shared_blocks.clone(),
                            *account_id,
                            target.transaction_monitor.has_pending_outbound(),
                            self.webhook_config.clone(),
                            target.next_block_to_scan,
                        )
                        .await?;
                    Self::push_events_with_limit(&mut all_events, events, max_buffered_events);
                    if let Some(last) = shared_blocks.last() {
                        target.next_block_to_scan = last.height + 1;
                    }
                    if let Some(last) = shared_blocks.last()
                        && last.height >= target.next_block_to_scan
                    {
                        if last.height > max_new_height_in_batch {
                            max_new_height_in_batch = last.height;
                        }

                        let monitor_res = target
                            .transaction_monitor
                            .monitor_if_needed(&self.client, &self.pool, target.account.id, last.height)
                            .await
                            .map_err(ScanError::Fatal)?;

                        Self::push_events_with_limit(
                            &mut all_events,
                            monitor_res.wallet_events.clone(),
                            max_buffered_events,
                        );
                        self.emit_monitor_events(target.account.id, last.height, monitor_res);

                        db_handler.prune_tips(target.account.id, last.height).await?;

                        self.event_sender
                            .send(ProcessingEvent::ScanStatus(ScanStatusEvent::Progress {
                                account_id: target.account.id,
                                current_height: last.height,
                                blocks_scanned: total_scanned_globally,
                            }));
                    }
                }
            }

            let new_blocks_count = if is_batch_empty {
                0
            } else {
                (max_new_height_in_batch.saturating_sub(global_next_block)) + 1
            };

            blocks_since_reorg_check += new_blocks_count;
            total_scanned_globally += new_blocks_count;

            if blocks_since_reorg_check >= self.reorg_check_interval {
                self.check_global_reorgs(&mut targets, &db_handler, scanner).await?;
                blocks_since_reorg_check = 0;
            }

            // Handle Partial scan limits
            if let ScanMode::Partial { max_blocks } = mode
                && total_scanned_globally >= max_blocks
            {
                return self.handle_pause(
                    &targets,
                    PauseReason::MaxBlocksReached { limit: max_blocks },
                    all_events,
                );
            }

            if is_batch_empty || !more_blocks {
                for account_id in &active_account_ids {
                    let Some(target) = targets.iter().find(|target| target.account.id == *account_id) else {
                        return Err(ScanError::Fatal(anyhow::anyhow!(
                            "Unknown active account id: {}",
                            account_id
                        )));
                    };
                    self.event_sender
                        .send(ProcessingEvent::ScanStatus(ScanStatusEvent::Completed {
                            account_id: target.account.id,
                            final_height: target.next_block_to_scan.saturating_sub(1),
                            total_blocks_scanned: total_scanned_globally,
                        }));
                }

                if let ScanMode::Continuous { poll_interval } = mode {
                    self.wait_for_next_poll_cycle(&mut targets, &db_handler, poll_interval, &cancel_token, scanner)
                        .await?;
                    continue;
                }

                return Ok((all_events.into_iter().collect(), false));
            }
        }
    }

    fn push_events_with_limit(
        all_events: &mut VecDeque<WalletEvent>,
        events: Vec<WalletEvent>,
        max_buffered_events: Option<usize>,
    ) {
        all_events.extend(events);
        if let Some(limit) = max_buffered_events {
            while all_events.len() > limit {
                all_events.pop_front();
            }
        }
    }

    async fn check_global_reorgs(
        &self,
        targets: &mut [AccountSyncTarget],
        db_handler: &ScanDbHandler<E>,
        scanner: &mut HttpBlockchainScanner<KeyManager>,
    ) -> Result<(), ScanError> {
        if targets.is_empty() {
            return Ok(());
        }

        let mut conn = db_handler.get_connection().await?;

        for target in targets {
            let res = reorg::handle_reorgs(scanner, &mut conn, target.account.id, self.webhook_config.clone())
                .await
                .map_err(ScanError::Fatal)?;

            if let Some(info) = res.reorg_information {
                self.emit_reorg_event(target.account.id, info, res.resume_height);
                target.next_block_to_scan = res.resume_height;
            }
        }
        Ok(())
    }

    async fn wait_for_next_poll_cycle(
        &self,
        targets: &mut [AccountSyncTarget],
        db_handler: &ScanDbHandler<E>,
        interval: std::time::Duration,
        cancel: &Option<CancellationToken>,
        scanner: &mut HttpBlockchainScanner<KeyManager>,
    ) -> Result<(), ScanError> {
        for target in targets.iter_mut() {
            target.next_block_to_scan = target.next_block_to_scan.saturating_sub(1);

            self.event_sender
                .send(ProcessingEvent::ScanStatus(ScanStatusEvent::Waiting {
                    account_id: target.account.id,
                    resume_in: interval,
                }));
        }

        if let Some(token) = cancel {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {},
                _ = token.cancelled() => return Ok(()),
            }
        } else {
            tokio::time::sleep(interval).await;
        }

        self.check_global_reorgs(targets, db_handler, scanner).await
    }

    fn handle_pause(
        &self,
        targets: &[AccountSyncTarget],
        reason: PauseReason,
        events: VecDeque<WalletEvent>,
    ) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        for t in targets {
            self.event_sender
                .send(ProcessingEvent::ScanStatus(ScanStatusEvent::Paused {
                    account_id: t.account.id,
                    last_scanned_height: t.next_block_to_scan.saturating_sub(1),
                    reason: reason.clone(),
                }));
        }
        Ok((events.into_iter().collect(), true))
    }

    fn emit_monitor_events(&self, account_id: i64, height: u64, res: MonitoringResult) {
        if !res.updated_displayed_transactions.is_empty() {
            self.event_sender
                .send(ProcessingEvent::TransactionsUpdated(TransactionsUpdatedEvent {
                    account_id,
                    updated_transactions: res.updated_displayed_transactions.clone(),
                }));
            self.event_sender
                .send(ProcessingEvent::TransactionsReady(DisplayedTransactionsEvent {
                    account_id,
                    transactions: res.updated_displayed_transactions,
                    block_height: Some(height),
                    is_initial_sync: false,
                }));
        }
    }

    async fn scan_blocks_with_timeout(
        &self,
        scanner: &mut HttpBlockchainScanner<KeyManager>,
        config: &ScanConfig,
    ) -> Result<(Vec<lightweight_wallet_libs::BlockScanResult>, bool), ScanError> {
        let mut timeout_retries = 0;
        let mut error_retries = 0;

        loop {
            match timeout(self.retry_config.timeout, scanner.scan_blocks(config)).await {
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(e)) => {
                    error_retries += 1;
                    let error_msg = e.to_string();
                    warn!(
                        error = &*error_msg,
                        retry = error_retries,
                        max = self.retry_config.max_error_retries;
                        "Blockchain scan failed"
                    );
                    if error_retries >= self.retry_config.max_error_retries {
                        return Err(ScanError::Intermittent(e.to_string()));
                    }
                    let exponent = error_retries.min(MAX_BACKOFF_EXPONENT);
                    let backoff_secs = self
                        .retry_config
                        .error_backoff_base_secs
                        .pow(exponent)
                        .min(MAX_BACKOFF_SECONDS);
                    info!(
                        seconds = backoff_secs;
                        "Waiting before retrying..."
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                },
                Err(_) => {
                    timeout_retries += 1;
                    warn!(
                        retry = timeout_retries,
                        max = self.retry_config.max_timeout_retries;
                        "scan_blocks timed out"
                    );
                    if timeout_retries >= self.retry_config.max_timeout_retries {
                        return Err(ScanError::Timeout(timeout_retries));
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                },
            }
        }
    }

    fn emit_reorg_event(&self, account_id: i64, reorg_info: reorg::ReorgInformation, resume_height: u64) {
        self.event_sender
            .send(ProcessingEvent::ReorgDetected(ReorgDetectedEvent {
                account_id,
                reorg_from_height: reorg_info.rolled_back_from_height,
                new_height: resume_height,
                blocks_rolled_back: reorg_info.rolled_back_blocks_count,
                invalidated_output_hashes: reorg_info.invalidated_output_hashes,
                cancelled_transaction_ids: reorg_info.cancelled_transaction_ids,
                reorganized_displayed_transactions: reorg_info.reorganized_displayed_transactions,
            }));
    }

    async fn create_reorg_scanner(
        &self,
        key_manager: KeyManager,
    ) -> Result<HttpBlockchainScanner<KeyManager>, ScanError> {
        HttpBlockchainScanner::new(self.base_url.clone(), vec![key_manager], OPTIMAL_SCANNING_THREADS)
            .await
            .map_err(|e| ScanError::Intermittent(e.to_string()))
    }

    /// Executes the three-phase fast synchronisation process.
    ///
    /// **Phase 1 – Unspent UTXO sync** (birthday → `fast_sync_target_height`):
    ///   Scans from each account's birthday up to `tip − safety_buffer`,
    ///   retrieving the unspent UTXO set at that height. This phase quickly
    ///   establishes the wallet's approximate current balance without processing
    ///   the most volatile recent blocks.
    ///
    /// **Phase 2 – Recent full scan** (`fast_sync_target_height` → tip):
    ///   Performs a complete scan of the remaining recent blocks up to the chain
    ///   tip. After this phase the wallet balance is fully accurate.
    ///
    /// **Phase 3 – Full history scan** (birthday → tip):
    ///   Re-scans the entire chain from each account's birthday to build
    ///   the complete transaction and spending history. This phase fills in any
    ///   history that Phase 1 may not have fully captured.
    ///
    /// Phases 1 and 2 are run as a single continuous pass (birthday → tip) using
    /// the existing [`unified_scan_loop`]. Phase 3 then resets each account to
    /// its birthday and performs a second full pass to ensure complete history.
    async fn run_fast_sync(
        &self,
        sync_targets: Vec<AccountSyncTarget>,
        safety_buffer: u64,
        scanning_offset: u64,
        cancel_token: Option<CancellationToken>,
        scanner: &mut HttpBlockchainScanner<KeyManager>,
    ) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        // Determine the fast-sync target height (tip − safety_buffer).
        let tip_info = scanner
            .get_tip_info()
            .await
            .map_err(|e| ScanError::Fatal(anyhow::anyhow!("Failed to get tip info for fast sync: {}", e)))?;

        let tip_height = tip_info.best_block_height;
        let fast_sync_target_height = tip_height.saturating_sub(safety_buffer);

        info!(
            tip_height = tip_height,
            fast_sync_target_height = fast_sync_target_height,
            safety_buffer = safety_buffer;
            "Fast sync: starting Phase 1 (birthday → fast_sync_target_height) \
             and Phase 2 (fast_sync_target_height → tip) as a single continuous pass"
        );

        // Capture the data needed to reconstruct Phase 3 targets BEFORE Phase 1+2
        // consumes `sync_targets`. We compute each account's birthday height here so
        // that Phase 3 can start from the correct position.
        const SECONDS_PER_DAY: u64 = 86_400;
        let mut phase3_seed: Vec<(AccountRow, KeyManager, PrivateKey, u64)> = Vec::new();
        for target in &sync_targets {
            let timestamp = (target.account.birthday as u64).saturating_sub(scanning_offset) * SECONDS_PER_DAY
                + tari_common_types::seeds::cipher_seed::BIRTHDAY_GENESIS_FROM_UNIX_EPOCH;
            let birthday_height = self
                .client
                .get_height_at_time(timestamp)
                .await
                .map_err(ScanError::Fatal)?;
            phase3_seed.push((
                target.account.clone(),
                target.key_manager.clone(),
                target.view_key.clone(),
                birthday_height,
            ));
        }

        // Phase 1 + 2: Scan from birthday to fast_sync_target_height (unspent UTXO sync),
        // then continue to tip (recent full scan). These are run as one continuous pass.
        let (mut all_events, _) = self
            .unified_scan_loop(sync_targets, ScanMode::Full, cancel_token.clone())
            .await?;

        // Check for cancellation before starting Phase 3.
        if let Some(token) = &cancel_token {
            if token.is_cancelled() {
                info!("Fast sync cancelled before Phase 3 (history scan)");
                return Ok((all_events, false));
            }
        }

        info!(
            fast_sync_target_height = fast_sync_target_height;
            "Fast sync: starting Phase 3 (full history scan from birthday → tip)"
        );

        // Phase 3: Full history scan.
        // Reconstruct targets with `next_block_to_scan` reset to each account's birthday
        // so the history scan covers the complete range.
        let conn = self.pool.get().map_err(|e| ScanError::DbError(e.into()))?;
        let mut history_targets = Vec::with_capacity(phase3_seed.len());
        for (account, key_manager, view_key, birthday_height) in phase3_seed {
            let monitor_state = MonitoringState::new();
            monitor_state.initialize(&conn, account.id).map_err(ScanError::Fatal)?;
            let transaction_monitor =
                TransactionMonitor::new(monitor_state, self.required_confirmations, self.webhook_config.clone());
            history_targets.push(AccountSyncTarget {
                account,
                key_manager,
                view_key,
                next_block_to_scan: birthday_height,
                transaction_monitor,
            });
        }
        drop(conn);

        let (history_events, _) = self
            .unified_scan_loop(history_targets, ScanMode::Full, cancel_token)
            .await?;

        all_events.extend(history_events);

        info!("Fast sync complete");
        Ok((all_events, false))
    }
}
