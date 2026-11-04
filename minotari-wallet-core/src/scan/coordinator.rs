use log::{info, trace, warn};
use minotari_scanning::{HttpBlockchainScanner, scanning::BlockchainScanner};
use std::{collections::VecDeque, path::PathBuf, sync::Arc, time::Instant};
use tari_common_types::{seeds::cipher_seed::BIRTHDAY_GENESIS_FROM_UNIX_EPOCH, types::PrivateKey};
use tari_transaction_components::key_manager::KeyManager;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    ScanStatusEvent,
    db::{self, AccountRow, SqlitePool, WalletDbError},
    http::WalletHttpClient,
    models::{OutputStatus, WalletEvent},
    scan::{
        DisplayedTransactionsEvent, ReorgDetectedEvent, ScanError, ScanMode, ScanRetryConfig, TransactionsUpdatedEvent,
        block_processor::BlockProcessor,
        config::OPTIMAL_SCANNING_THREADS,
        events::{ChannelEventSender, EventChannel, FastSyncPhase, ProcessingEvent},
        reorg,
        scan_db_handler::ScanDbHandler,
        scanner_state_manager::ScannerStateManager,
    },
    transactions::{MonitoringResult, MonitoringState, TransactionMonitor, monitor::NodeRequestError},
    webhooks::WebhookTriggerConfig,
};
use tari_transaction_components::key_manager::TransactionKeyManagerInterface;
use tari_utilities::hex::Hex;

const MAX_CONTINUOUS_BUFFERED_EVENTS: usize = 10_000;
/// Mid-pass rewinds in a row that may end no higher than the one before.
const MAX_REWINDS_WITHOUT_PROGRESS: u32 = 3;

/// Why a pass of the scan loop stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanStop {
    /// The scan reached the chain tip (or its end height).
    CaughtUp,
    /// The cancel token fired.
    Cancelled,
    /// `ScanMode::Partial` scanned its `max_blocks`.
    BlockLimit,
    /// The deadline passed.
    Deadline,
    /// The deadline of a Continuous scan passed. Never reported as `Completed`.
    ContinuousDeadline,
}

impl ScanStop {
    /// Whether the post-scan monitor runs when the scan stops this way.
    ///
    /// Transactions can only change state when there is a new tip, so the
    /// monitor runs once per pass rather than per batch: when the scan is
    /// caught up and when it stops at its block limit. A cancelled scan, or
    /// one out of time, stops without it.
    fn runs_post_scan(self) -> bool {
        match self {
            ScanStop::CaughtUp | ScanStop::BlockLimit => true,
            ScanStop::Cancelled | ScanStop::Deadline | ScanStop::ContinuousDeadline => false,
        }
    }
}

/// Represents an account that is part of the current global scan session.
/// This is an internal state object and should not be exposed publicly.
pub(crate) struct AccountSyncTarget {
    pub(crate) account: AccountRow,
    pub(crate) key_manager: KeyManager,
    pub(crate) view_key: PrivateKey,
    pub(crate) next_block_to_scan: u64,
    pub(crate) transaction_monitor: TransactionMonitor,
}

pub struct ScanCoordinator {
    pool: SqlitePool,
    base_url: String,
    client: WalletHttpClient,
    events: EventChannel,
    retry_config: ScanRetryConfig,
    required_confirmations: u64,
    webhook_config: Option<WebhookTriggerConfig>,
    processing_threads: usize,
    reorg_check_interval: u64,
    batch_size: u64,
    burn_proofs_dir: Option<PathBuf>,
    deadline: Option<Instant>,
}

impl ScanCoordinator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: SqlitePool,
        base_url: String,
        events: EventChannel,
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
            events,
            retry_config,
            required_confirmations,
            webhook_config,
            processing_threads,
            reorg_check_interval,
            batch_size,
            burn_proofs_dir: None,
            deadline: None,
        })
    }

    pub fn with_burn_proofs_dir(mut self, dir: Option<PathBuf>) -> Self {
        self.burn_proofs_dir = dir;
        self
    }

    pub fn with_deadline(mut self, deadline: Option<Instant>) -> Self {
        self.deadline = deadline;
        self
    }

    fn deadline_passed(&self) -> bool {
        self.deadline.is_some_and(|deadline| Instant::now() >= deadline)
    }

    /// Whether the deadline has passed with some account still below `end_height`.
    /// A deadline that passes on the batch reaching the end does not stop the
    /// scan, so it finishes the normal way.
    fn deadline_short_of(&self, targets: &[AccountSyncTarget], end_height: u64) -> bool {
        self.deadline_passed() && targets.iter().any(|target| target.next_block_to_scan <= end_height)
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
        let account_ids: Vec<i64> = accounts.iter().map(|account| account.id).collect();

        let first_km = accounts
            .first()
            .expect("is already checked")
            .get_key_manager(password)?;
        let Some(shared_reorg_scanner) = unless_cancelled(&cancel_token, self.create_reorg_scanner(first_km)).await
        else {
            return self.cancelled_at_startup(&account_ids).await;
        };
        let mut shared_reorg_scanner = shared_reorg_scanner?;

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
                    &cancel_token,
                )
                .await?;
            let Some(target) = target else {
                return self.cancelled_at_startup(&account_ids).await;
            };
            sync_targets.push(target);
        }

        match mode {
            ScanMode::FastSync { safety_buffer } => self.run_fast_sync(sync_targets, safety_buffer, cancel_token).await,
            _ => {
                self.unified_scan_loop(sync_targets, mode, scanning_offset, cancel_token)
                    .await
            },
        }
    }

    /// Resolves the block height corresponding to an account's birthday.
    ///
    /// Used to determine where a scan should begin when there is no existing
    /// scan state to resume from (and by the backfill, which always rescans from
    /// the birthday regardless of how far the fast-sync cursor advanced).
    async fn birthday_height(
        &self,
        account: &AccountRow,
        scanning_offset: u64,
        wallet_client: &WalletHttpClient,
    ) -> Result<u64, ScanError> {
        let timestamp = birthday_timestamp(account.birthday as u64, scanning_offset)?;
        wallet_client
            .get_height_at_time(timestamp)
            .await
            .map_err(ScanError::Fatal)
    }

    /// Prepares a scan context for an account, or returns `None` if `cancel` fires first.
    #[allow(clippy::too_many_arguments)]
    async fn prepare_target(
        &self,
        account: AccountRow,
        password: &str,
        wallet_client: &WalletHttpClient,
        scanning_offset: u64,
        conn: &mut rusqlite::Connection,
        scanner: &mut HttpBlockchainScanner<KeyManager>,
        cancel: &Option<CancellationToken>,
    ) -> Result<Option<AccountSyncTarget>, ScanError> {
        let key_manager = account.get_key_manager(password)?;
        let view_key = key_manager.get_private_view_key();
        let reorg_result = unless_cancelled(
            cancel,
            reorg::handle_reorgs(scanner, conn, account.id, self.webhook_config.clone()),
        )
        .await;
        let Some(reorg_result) = reorg_result else {
            return Ok(None);
        };
        let reorg_result = reorg_result.map_err(ScanError::Fatal)?;

        let next_block = match reorg_result.reorg_information {
            Some(info) => {
                let resume_height = self
                    .report_rollback(
                        &account,
                        info,
                        reorg_result.resume_height,
                        scanning_offset,
                        wallet_client,
                        scanner,
                        cancel,
                    )
                    .await?;
                let Some(resume_height) = resume_height else {
                    return Ok(None);
                };
                resume_height
            },
            // Use birthday logic
            None if reorg_result.resume_height == 0 => {
                let birthday =
                    unless_cancelled(cancel, self.birthday_height(&account, scanning_offset, wallet_client)).await;
                let Some(birthday) = birthday else {
                    return Ok(None);
                };
                birthday?
            },
            None => reorg_result.resume_height,
        };

        let monitor_state = MonitoringState::new();
        monitor_state.initialize(conn, account.id).map_err(ScanError::Fatal)?;

        let transaction_monitor =
            TransactionMonitor::new(monitor_state, self.required_confirmations, self.webhook_config.clone());

        Ok(Some(AccountSyncTarget {
            account,
            key_manager,
            view_key,
            next_block_to_scan: next_block,
            transaction_monitor,
        }))
    }

    #[allow(clippy::too_many_lines)]
    async fn unified_scan_loop(
        &self,
        mut targets: Vec<AccountSyncTarget>,
        mode: ScanMode,
        scanning_offset: u64,
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
        let (block_events_tx, mut block_events) = mpsc::unbounded_channel();
        let block_processor = BlockProcessor::with_event_sender(
            all_accounts,
            ChannelEventSender::new(block_events_tx),
            false,
            self.required_confirmations,
        );
        let mut db_handler = ScanDbHandler::new(self.pool.clone(), block_processor);
        let mut total_scanned_globally: u64 = 0;
        let mut blocks_since_reorg_check: u64 = 0;

        let mut state_manager = ScannerStateManager::new();
        // The tip is read once per pass: at the start and after each poll.
        let mut tip_height = 0;
        let mut refresh_tip = true;
        // A node that reports a reorg at every check must not keep the scan rescanning.
        let mut rewind_high_water: u64 = 0;
        let mut rewinds_without_progress: u32 = 0;
        let deadline_stop = match mode {
            ScanMode::Continuous { .. } => ScanStop::ContinuousDeadline,
            _ => ScanStop::Deadline,
        };
        loop {
            if let Some(token) = &cancel_token
                && token.is_cancelled()
            {
                return self
                    .stop_scan(
                        &targets,
                        ScanStop::Cancelled,
                        tip_height,
                        total_scanned_globally,
                        all_events,
                    )
                    .await;
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

            let mut end_height = next_horizon_height.map(|h| h.saturating_sub(1));
            if let ScanMode::Partial { max_blocks } = mode {
                let max_height_to_scan = global_next_block
                    .saturating_add(max_blocks)
                    .saturating_sub(total_scanned_globally);
                end_height = match end_height {
                    Some(h) => Some(h.min(max_height_to_scan)),
                    None => Some(max_height_to_scan),
                };
            }

            let effective_batch_size = next_horizon_height
                .map(|h| h.saturating_sub(global_next_block).min(self.batch_size))
                .unwrap_or(self.batch_size);

            let scanner_and_config = unless_cancelled(
                &cancel_token,
                state_manager.get_scanner_and_config(
                    &active_account_ids,
                    global_next_block,
                    end_height,
                    effective_batch_size,
                    &targets,
                    &self.base_url,
                    self.processing_threads,
                    &self.retry_config,
                ),
            )
            .await;
            let Some(scanner_and_config) = scanner_and_config else {
                return self
                    .stop_scan(
                        &targets,
                        ScanStop::Cancelled,
                        tip_height,
                        total_scanned_globally,
                        all_events,
                    )
                    .await;
            };
            let (scanner, scanner_config) = scanner_and_config?;
            if refresh_tip {
                let Some(tip) = unless_cancelled(&cancel_token, scanner.get_tip_info()).await else {
                    return self
                        .stop_scan(
                            &targets,
                            ScanStop::Cancelled,
                            tip_height,
                            total_scanned_globally,
                            all_events,
                        )
                        .await;
                };
                tip_height = tip
                    .map_err(|e| ScanError::Intermittent(e.to_string()))?
                    .best_block_height;
                refresh_tip = false;
            }
            let mut utxo_stream = scanner
                .scan_blocks(&scanner_config)
                .await
                .map_err(|e| ScanError::Intermittent(e.to_string()))?;
            let mut is_batch_empty = false;
            let mut max_new_height_in_batch = 0;
            let mut scanned_in_pass = false;
            loop {
                // Cancelling must not wait for a slow or retrying block download.
                let Some(response) = unless_cancelled(&cancel_token, utxo_stream.recv()).await else {
                    return self
                        .stop_scan(
                            &targets,
                            ScanStop::Cancelled,
                            tip_height,
                            total_scanned_globally,
                            all_events,
                        )
                        .await;
                };
                let Some(response) = response else {
                    break;
                };
                let scanned_blocks = response.map_err(|e| ScanError::Intermittent(e.to_string()))?;
                let new_blocks_count = scanned_blocks.len() as u64;
                is_batch_empty = scanned_blocks.is_empty();
                // Go on, if we stopped on artificial horizon
                if is_batch_empty {
                    break;
                }

                for account_id in &active_account_ids {
                    self.events
                        .send(ProcessingEvent::ScanStatus(ScanStatusEvent::MoreBlocksAvailable {
                            account_id: *account_id,
                            last_scanned_height: global_next_block.saturating_sub(1),
                        }))
                        .await;
                }

                max_new_height_in_batch = global_next_block;
                scanned_in_pass = true;

                let shared_blocks = Arc::new(scanned_blocks);

                for account_id in &active_account_ids {
                    let Some(target) = targets.iter_mut().find(|target| target.account.id == *account_id) else {
                        return Err(ScanError::Fatal(anyhow::anyhow!(
                            "Unknown active account id: {}",
                            account_id
                        )));
                    };

                    let has_pending_outbound = target
                        .transaction_monitor
                        .refresh_pending_outbound(&self.pool, target.account.id)
                        .map_err(ScanError::Fatal)?;
                    let events = db_handler
                        .process_blocks(
                            shared_blocks.clone(),
                            *account_id,
                            has_pending_outbound,
                            self.webhook_config.clone(),
                            target.next_block_to_scan,
                        )
                        .await?;
                    self.forward_block_events(&mut block_events).await;
                    Self::push_events_with_limit(&mut all_events, events, max_buffered_events);
                    if let Some(last) = shared_blocks.last() {
                        target.next_block_to_scan = next_block_height(last.height)?;

                        if last.height > max_new_height_in_batch {
                            max_new_height_in_batch = last.height;
                        }

                        db_handler.prune_tips(target.account.id, last.height).await?;

                        self.events
                            .send(ProcessingEvent::ScanStatus(ScanStatusEvent::Progress {
                                account_id: target.account.id,
                                current_height: last.height,
                                tip_height: tip_height.max(last.height),
                                blocks_scanned: total_scanned_globally,
                            }))
                            .await;
                    }
                }

                blocks_since_reorg_check = blocks_since_reorg_check.saturating_add(new_blocks_count);
                total_scanned_globally = total_scanned_globally.saturating_add(new_blocks_count);

                if blocks_since_reorg_check >= self.reorg_check_interval {
                    let rewound = self
                        .check_global_reorgs(&mut targets, &db_handler, scanner, scanning_offset, &cancel_token)
                        .await?;
                    blocks_since_reorg_check = 0;
                    // The stream still continues from the old heights: rescan from the fork.
                    if rewound {
                        if max_new_height_in_batch > rewind_high_water {
                            rewind_high_water = max_new_height_in_batch;
                            rewinds_without_progress = 0;
                        }
                        rewinds_without_progress = rewinds_without_progress.saturating_add(1);
                        if rewinds_without_progress > MAX_REWINDS_WITHOUT_PROGRESS {
                            return Err(ScanError::Intermittent(format!(
                                "Base node reported a reorg at every check without the scan getting past height \
                                 {rewind_high_water}"
                            )));
                        }
                        refresh_tip = true;
                        break;
                    }
                }

                if let Some(token) = &cancel_token
                    && token.is_cancelled()
                {
                    return self
                        .stop_scan(
                            &targets,
                            ScanStop::Cancelled,
                            tip_height,
                            total_scanned_globally,
                            all_events,
                        )
                        .await;
                }
                // A Partial scan that reached its block limit on this batch ends
                // through the block limit path below, which runs the post-scan monitor.
                let block_limit_reached =
                    matches!(mode, ScanMode::Partial { max_blocks } if total_scanned_globally >= max_blocks);
                if !block_limit_reached && self.deadline_short_of(&targets, tip_height) {
                    info!(last_scanned_block = max_new_height_in_batch; "Scan deadline reached");
                    return self
                        .stop_scan(&targets, deadline_stop, tip_height, total_scanned_globally, all_events)
                        .await;
                }
            }
            if let ScanMode::Partial { max_blocks } = mode
                && total_scanned_globally >= max_blocks
            {
                info!(last_scanned_block = max_new_height_in_batch; "Scan completed successfully up to stop height");
                self.finish_pass(&targets, ScanStop::BlockLimit, &mut all_events, max_buffered_events)
                    .await?;
                return self
                    .stop_scan(
                        &targets,
                        ScanStop::BlockLimit,
                        tip_height,
                        total_scanned_globally,
                        all_events,
                    )
                    .await;
            }
            if is_batch_empty {
                if let Some(token) = &cancel_token
                    && token.is_cancelled()
                {
                    return self
                        .stop_scan(
                            &targets,
                            ScanStop::Cancelled,
                            tip_height,
                            total_scanned_globally,
                            all_events,
                        )
                        .await;
                }
                // The pass stopped below an account further ahead: scan on from
                // there. Blocks were scanned, so the lagging cursors moved up.
                if next_horizon_height.is_some() && scanned_in_pass {
                    continue;
                }
                // Settle pending transactions before reporting completion, and
                // before `wait_for_next_poll_cycle` moves the cursor back a block.
                self.finish_pass(&targets, ScanStop::CaughtUp, &mut all_events, max_buffered_events)
                    .await?;

                if let ScanMode::Continuous { poll_interval } = mode {
                    if self.deadline_passed() {
                        return self
                            .stop_scan(
                                &targets,
                                ScanStop::ContinuousDeadline,
                                tip_height,
                                total_scanned_globally,
                                all_events,
                            )
                            .await;
                    }
                    // Wake up at the deadline rather than sleep past it.
                    let poll_interval = match self.deadline {
                        Some(deadline) => poll_interval.min(deadline.saturating_duration_since(Instant::now())),
                        None => poll_interval,
                    };
                    self.wait_for_next_poll_cycle(
                        &mut targets,
                        &db_handler,
                        poll_interval,
                        &cancel_token,
                        scanner,
                        scanning_offset,
                    )
                    .await?;
                    refresh_tip = true;
                    continue;
                }

                return self
                    .stop_scan(
                        &targets,
                        ScanStop::CaughtUp,
                        tip_height,
                        total_scanned_globally,
                        all_events,
                    )
                    .await;
            }
        }
    }

    /// Sends on the events the block processor emitted for the last batch.
    async fn forward_block_events(&self, block_events: &mut mpsc::UnboundedReceiver<ProcessingEvent>) {
        while let Ok(event) = block_events.try_recv() {
            self.events.send(event).await;
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

    /// Rolls back reorged accounts and moves their cursors to the fork. Returns
    /// whether any cursor moved. A cancel stops the check; the caller then sees
    /// the cancelled token.
    async fn check_global_reorgs(
        &self,
        targets: &mut [AccountSyncTarget],
        db_handler: &ScanDbHandler<ChannelEventSender>,
        scanner: &mut HttpBlockchainScanner<KeyManager>,
        scanning_offset: u64,
        cancel: &Option<CancellationToken>,
    ) -> Result<bool, ScanError> {
        let mut rewound = false;
        if targets.is_empty() {
            return Ok(rewound);
        }

        for target in targets {
            // The connection is released before the reorg is reported, which can
            // wait on a slow consumer.
            let mut conn = db_handler.get_connection().await?;
            let res = unless_cancelled(
                cancel,
                reorg::handle_reorgs(scanner, &mut conn, target.account.id, self.webhook_config.clone()),
            )
            .await;
            drop(conn);
            let Some(res) = res else {
                return Ok(rewound);
            };
            let res = res.map_err(ScanError::Fatal)?;

            if let Some(info) = res.reorg_information {
                let resume_height = self
                    .report_rollback(
                        &target.account,
                        info,
                        res.resume_height,
                        scanning_offset,
                        &self.client,
                        scanner,
                        cancel,
                    )
                    .await?;
                let Some(resume_height) = resume_height else {
                    return Ok(rewound);
                };
                target.next_block_to_scan = resume_height;
                rewound = true;
            }
        }
        Ok(rewound)
    }

    async fn wait_for_next_poll_cycle(
        &self,
        targets: &mut [AccountSyncTarget],
        db_handler: &ScanDbHandler<ChannelEventSender>,
        interval: std::time::Duration,
        cancel: &Option<CancellationToken>,
        scanner: &mut HttpBlockchainScanner<KeyManager>,
        scanning_offset: u64,
    ) -> Result<(), ScanError> {
        for target in targets.iter() {
            self.events
                .send(ProcessingEvent::ScanStatus(ScanStatusEvent::Waiting {
                    account_id: target.account.id,
                    resume_in: interval,
                }))
                .await;
        }

        // A cancel here is picked up at the top of the scan loop, with every
        // cursor still just past the last scanned block.
        if unless_cancelled(cancel, tokio::time::sleep(interval)).await.is_none() {
            return Ok(());
        }
        let before: Vec<u64> = targets.iter().map(|target| target.next_block_to_scan).collect();
        self.check_global_reorgs(targets, db_handler, scanner, scanning_offset, cancel)
            .await?;
        if cancel.as_ref().is_some_and(|token| token.is_cancelled()) {
            return Ok(());
        }
        // Rescan the last block of every account the reorg check did not move.
        for (target, height) in targets.iter_mut().zip(before) {
            if target.next_block_to_scan == height {
                target.next_block_to_scan = height.saturating_sub(1);
            }
        }
        Ok(())
    }

    /// Sends each account's terminal event and returns the scan result.
    async fn stop_scan(
        &self,
        targets: &[AccountSyncTarget],
        stop: ScanStop,
        tip_height: u64,
        total_blocks_scanned: u64,
        events: VecDeque<WalletEvent>,
    ) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        let more_blocks = self
            .send_terminal_events(targets, stop, tip_height, total_blocks_scanned)
            .await;
        Ok((events.into_iter().collect(), more_blocks))
    }

    /// Sends one terminal event per account and returns whether blocks remain.
    ///
    /// A Full or Partial budget stop at or past `tip_height` is reported as `Completed`.
    async fn send_terminal_events(
        &self,
        targets: &[AccountSyncTarget],
        stop: ScanStop,
        tip_height: u64,
        total_blocks_scanned: u64,
    ) -> bool {
        let mut more_blocks = false;
        for target in targets {
            let account_id = target.account.id;
            let last_scanned_height = target.next_block_to_scan.saturating_sub(1);
            let event = match stop {
                ScanStop::Cancelled => {
                    more_blocks = true;
                    ScanStatusEvent::Cancelled {
                        account_id,
                        last_scanned_height,
                    }
                },
                ScanStop::ContinuousDeadline => {
                    more_blocks = true;
                    ScanStatusEvent::BudgetExhausted {
                        account_id,
                        last_scanned_height,
                        tip_height,
                    }
                },
                ScanStop::BlockLimit | ScanStop::Deadline if last_scanned_height < tip_height => {
                    more_blocks = true;
                    ScanStatusEvent::BudgetExhausted {
                        account_id,
                        last_scanned_height,
                        tip_height,
                    }
                },
                _ => ScanStatusEvent::Completed {
                    account_id,
                    final_height: last_scanned_height,
                    total_blocks_scanned,
                },
            };
            self.events.send_always(ProcessingEvent::ScanStatus(event)).await;
        }
        more_blocks
    }

    /// Reports a scan cancelled before every account was prepared, each at the
    /// last block stored for it.
    async fn cancelled_at_startup(&self, account_ids: &[i64]) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        let mut heights = Vec::with_capacity(account_ids.len());
        {
            let conn = self.pool.get().map_err(|e| ScanError::DbError(e.into()))?;
            for account_id in account_ids {
                let last_scanned_height =
                    db::get_latest_scanned_tip_block_by_account(&conn, *account_id)?.map_or(0, |block| block.height);
                heights.push((*account_id, last_scanned_height));
            }
        }
        for (account_id, last_scanned_height) in heights {
            self.events
                .send_always(ProcessingEvent::ScanStatus(ScanStatusEvent::Cancelled {
                    account_id,
                    last_scanned_height,
                }))
                .await;
        }
        Ok((Vec::new(), true))
    }

    /// Runs the post-scan monitor if the scan pass stopped in a way that calls
    /// for it (see [`ScanStop::runs_post_scan`]), buffering its wallet events.
    async fn finish_pass(
        &self,
        targets: &[AccountSyncTarget],
        stop: ScanStop,
        all_events: &mut VecDeque<WalletEvent>,
        max_buffered_events: Option<usize>,
    ) -> Result<(), ScanError> {
        if !stop.runs_post_scan() {
            return Ok(());
        }
        let events = self.run_post_scan(targets).await?;
        Self::push_events_with_limit(all_events, events, max_buffered_events);
        Ok(())
    }

    /// Runs the transaction monitor for every account at the height it has been
    /// scanned to, after a scan pass.
    ///
    /// The block scan has already marked mined sends; this updates displayed
    /// transaction confirmations, confirms mined transactions at depth,
    /// rebroadcasts `Completed` transactions and asks the node about the mempool
    /// status of `Broadcast` ones. Its events are emitted (see
    /// [`Self::emit_monitor_events`]) and its wallet events returned.
    ///
    /// A failed node request does not fail the pass: the monitor logs it and
    /// leaves that transaction for the next cycle, and every other transaction
    /// and account is still monitored, so the scan still reports `Completed` or
    /// pauses normally and a Continuous scan keeps running. Should a node error
    /// still reach this point, it is logged and the next account is monitored.
    /// A database failure is [`ScanError::Fatal`].
    async fn run_post_scan(&self, targets: &[AccountSyncTarget]) -> Result<Vec<WalletEvent>, ScanError> {
        let mut wallet_events = Vec::new();
        for target in targets {
            let scanned_height = target.next_block_to_scan.saturating_sub(1);
            let monitor_res = match target
                .transaction_monitor
                .monitor_if_needed(&self.client, &self.pool, target.account.id, scanned_height)
                .await
            {
                Ok(monitor_res) => monitor_res,
                Err(e) if e.downcast_ref::<NodeRequestError>().is_some() => {
                    warn!(
                        account_id = target.account.id,
                        error:% = e;
                        "Base node request failed while monitoring transactions; retrying next cycle"
                    );
                    continue;
                },
                Err(e) => return Err(ScanError::Fatal(e)),
            };

            wallet_events.extend(monitor_res.wallet_events.clone());
            self.emit_monitor_events(target.account.id, scanned_height, monitor_res)
                .await;
        }
        Ok(wallet_events)
    }

    /// Sends the displayed transactions the monitor updated.
    ///
    /// They go out twice: as [`ProcessingEvent::TransactionsUpdated`] and as
    /// [`ProcessingEvent::TransactionsReady`] with `is_initial_sync: false`.
    /// Consumers that treat `TransactionsReady` as "new transactions found" see
    /// every monitor update (a confirmation count, a status change) as a new
    /// transaction and must de-duplicate. This is the library's public event
    /// contract and is kept as is.
    async fn emit_monitor_events(&self, account_id: i64, height: u64, res: MonitoringResult) {
        if !res.updated_displayed_transactions.is_empty() {
            self.events
                .send(ProcessingEvent::TransactionsUpdated(TransactionsUpdatedEvent {
                    account_id,
                    updated_transactions: res.updated_displayed_transactions.clone(),
                }))
                .await;
            self.events
                .send(ProcessingEvent::TransactionsReady(DisplayedTransactionsEvent {
                    account_id,
                    transactions: res.updated_displayed_transactions,
                    block_height: Some(height),
                    is_initial_sync: false,
                }))
                .await;
        }
    }

    /// Reports a committed rollback and returns the height to resume from, or
    /// `None` if `cancel` fired first.
    ///
    /// A fork below every stored tip block (`resume_height == 0`) resumes at the
    /// birthday, which must not be above the chain tip. If that lookup fails or
    /// is cancelled, the reorg is still reported, with `new_height: 0`: the
    /// rolled back tip blocks are gone, so it could not be reported later.
    #[allow(clippy::too_many_arguments)]
    async fn report_rollback(
        &self,
        account: &AccountRow,
        info: reorg::ReorgInformation,
        resume_height: u64,
        scanning_offset: u64,
        wallet_client: &WalletHttpClient,
        scanner: &mut HttpBlockchainScanner<KeyManager>,
        cancel: &Option<CancellationToken>,
    ) -> Result<Option<u64>, ScanError> {
        if let Some(dir) = &self.burn_proofs_dir {
            for (claim_public_key, commitment) in &info.invalidated_burn_proof_files {
                if let Err(error) =
                    crate::transactions::burn::proof_files::remove_proof_file(dir, claim_public_key, commitment).await
                {
                    warn!(error:% = error; "Could not remove invalidated burn proof file");
                }
            }
        }
        if resume_height != 0 {
            self.emit_reorg_event(account.id, info, resume_height).await;
            return Ok(Some(resume_height));
        }
        let lookup = async {
            let birthday = self.birthday_height(account, scanning_offset, wallet_client).await?;
            let tip = scanner
                .get_tip_info()
                .await
                .map_err(|e| ScanError::Intermittent(e.to_string()))?
                .best_block_height;
            if birthday > tip {
                return Err(ScanError::Intermittent(format!(
                    "Base node reported birthday height {birthday} above its tip {tip}"
                )));
            }
            Ok(birthday)
        };
        match unless_cancelled(cancel, lookup).await {
            Some(Ok(birthday)) => {
                self.emit_reorg_event(account.id, info, birthday).await;
                Ok(Some(birthday))
            },
            Some(Err(e)) => {
                self.emit_reorg_event(account.id, info, 0).await;
                Err(e)
            },
            None => {
                self.emit_reorg_event(account.id, info, 0).await;
                Ok(None)
            },
        }
    }

    async fn emit_reorg_event(&self, account_id: i64, reorg_info: reorg::ReorgInformation, resume_height: u64) {
        self.events
            .send_always(ProcessingEvent::ReorgDetected(ReorgDetectedEvent {
                account_id,
                reorg_from_height: reorg_info.rolled_back_from_height,
                new_height: resume_height,
                blocks_rolled_back: reorg_info.rolled_back_blocks_count,
                invalidated_output_hashes: reorg_info.invalidated_output_hashes,
                cancelled_transaction_ids: reorg_info.cancelled_transaction_ids,
                reorganized_displayed_transactions: reorg_info.reorganized_displayed_transactions,
            }))
            .await;
    }

    /// Runs the three-phase fast sync strategy.
    #[allow(clippy::too_many_lines)]
    async fn run_fast_sync(
        &self,
        mut targets: Vec<AccountSyncTarget>,
        safety_buffer: u64,
        cancel_token: Option<CancellationToken>,
    ) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        let mut all_events = Vec::new();

        // Get chain tip to compute fast_sync_target
        let tip_response = self.client.get_tip_info().await.map_err(ScanError::Fatal)?;
        let tip_height = tip_response
            .metadata
            .as_ref()
            .map(|m| m.best_block_height())
            .unwrap_or(0);
        let fast_sync_target = tip_height.saturating_sub(safety_buffer);

        info!(
            tip = tip_height,
            fast_sync_target = fast_sync_target,
            safety_buffer = safety_buffer;
            "Starting fast sync"
        );

        // --- Phase 1: Fast UTXO scan (birthday -> fast_sync_target, exclude_spent=true) ---
        for target in &targets {
            self.events
                .send(ProcessingEvent::ScanStatus(ScanStatusEvent::FastSyncPhaseStarted {
                    account_id: target.account.id,
                    phase: FastSyncPhase::FastUtxoScan,
                    from_height: target.next_block_to_scan,
                    to_height: Some(fast_sync_target),
                }))
                .await;
        }

        let (events, stop, fast_scanned) = self
            .fast_sync_loop(&mut targets, fast_sync_target, tip_height, &cancel_token)
            .await?;
        all_events.extend(events);
        if stop != ScanStop::CaughtUp {
            let more_blocks = self
                .send_terminal_events(&targets, stop, tip_height, fast_scanned)
                .await;
            return Ok((all_events, more_blocks));
        }

        for target in &targets {
            self.events
                .send(ProcessingEvent::ScanStatus(ScanStatusEvent::FastSyncPhaseCompleted {
                    account_id: target.account.id,
                    phase: FastSyncPhase::FastUtxoScan,
                }))
                .await;
        }

        // Phase 1 ended on its last batch after the deadline: do not start phase 2.
        // A phase 1 with nothing to scan does not count, or the scan could never progress.
        if fast_scanned > 0 && self.deadline_short_of(&targets, tip_height) {
            let more_blocks = self
                .send_terminal_events(&targets, ScanStop::Deadline, tip_height, fast_scanned)
                .await;
            return Ok((all_events, more_blocks));
        }

        // --- Phase 2: Recent full scan (fast_sync_target -> tip) ---
        // Targets already have next_block_to_scan set to fast_sync_target + 1
        // from Phase 1, so no reset needed.
        for target in &targets {
            self.events
                .send(ProcessingEvent::ScanStatus(ScanStatusEvent::FastSyncPhaseStarted {
                    account_id: target.account.id,
                    phase: FastSyncPhase::RecentFullScan,
                    from_height: fast_sync_target,
                    to_height: None,
                }))
                .await;
        }

        // Phase 2 uses the same simple loop pattern as fast_sync_loop but without
        // exclude_spent, effectively doing a full scan of recent blocks.
        let (events, stop, recent_scanned) = self
            .recent_full_scan_loop(&mut targets, tip_height, &cancel_token)
            .await?;
        all_events.extend(events);
        let total_scanned = fast_scanned.saturating_add(recent_scanned);
        if stop != ScanStop::CaughtUp {
            let more_blocks = self
                .send_terminal_events(&targets, stop, tip_height, total_scanned)
                .await;
            return Ok((all_events, more_blocks));
        }

        for target in &targets {
            self.events
                .send(ProcessingEvent::ScanStatus(ScanStatusEvent::FastSyncPhaseCompleted {
                    account_id: target.account.id,
                    phase: FastSyncPhase::RecentFullScan,
                }))
                .await;
        }

        info!("Fast sync completed (wallet is now usable; run backfill separately for full history)");
        let more_blocks = self
            .send_terminal_events(&targets, ScanStop::CaughtUp, tip_height, total_scanned)
            .await;
        Ok((all_events, more_blocks))
    }

    /// Runs the history backfill phase separately.
    ///
    /// Scans from each account's birthday to `backfill_to_height` with full block
    /// processing (outputs + inputs) using backfill mode (OR IGNORE for duplicates,
    /// SpentUnconfirmed status for new outputs). After scanning, resolves
    /// SpentUnconfirmed outputs by checking inputs and verifying against the base node.
    pub async fn run_backfill(
        &self,
        accounts: Vec<AccountRow>,
        password: &str,
        backfill_to_height: u64,
        scanning_offset: u64,
        cancel_token: Option<CancellationToken>,
    ) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        if accounts.is_empty() {
            return Ok((Vec::new(), false));
        }

        let mut conn = self.pool.get().map_err(|e| ScanError::DbError(e.into()))?;
        let account_ids: Vec<i64> = accounts.iter().map(|account| account.id).collect();

        let first_km = accounts
            .first()
            .expect("is already checked")
            .get_key_manager(password)?;
        let mut shared_reorg_scanner = self.create_reorg_scanner(first_km).await?;

        let mut targets = Vec::with_capacity(accounts.len());
        for account in accounts {
            let target = self
                .prepare_target(
                    account,
                    password,
                    &self.client,
                    scanning_offset,
                    &mut conn,
                    &mut shared_reorg_scanner,
                    &cancel_token,
                )
                .await?;
            let Some(mut target) = target else {
                return self.cancelled_at_startup(&account_ids).await;
            };

            // Backfill always rescans from the account birthday. prepare_target
            // resumes from the last scanned tip block, which after a fast sync
            // sits at (or near) the chain tip — that is past backfill_to_height,
            // so without this reset the backfill range would be empty and no
            // history would be filled in. Idempotent (OR IGNORE) inserts in
            // backfill mode make rescanning already-recorded blocks safe.
            target.next_block_to_scan = self
                .birthday_height(&target.account, scanning_offset, &self.client)
                .await?;
            targets.push(target);
        }

        let mut all_events = Vec::new();

        for target in &targets {
            self.events
                .send(ProcessingEvent::ScanStatus(ScanStatusEvent::FastSyncPhaseStarted {
                    account_id: target.account.id,
                    phase: FastSyncPhase::HistoryBackfill,
                    from_height: target.next_block_to_scan,
                    to_height: Some(backfill_to_height),
                }))
                .await;
        }

        let (events, stop, total_scanned) = self
            .backfill_loop(&mut targets, backfill_to_height, &cancel_token)
            .await?;
        all_events.extend(events);
        if stop != ScanStop::CaughtUp {
            let more_blocks = self
                .send_terminal_events(&targets, stop, backfill_to_height, total_scanned)
                .await;
            return Ok((all_events, more_blocks));
        }

        // Resolve SpentUnconfirmed outputs:
        // 1. Mark outputs with matching inputs as Spent
        // 2. Verify remaining outputs against the base node
        for target in &targets {
            let unresolved = {
                let conn = self.pool.get().map_err(|e| ScanError::DbError(e.into()))?;
                let marked_spent = crate::db::resolve_spent_unconfirmed_with_inputs(&conn, target.account.id)
                    .map_err(ScanError::DbError)?;
                info!(
                    account_id = target.account.id,
                    marked_spent = marked_spent;
                    "Resolved SpentUnconfirmed outputs with matching inputs"
                );
                crate::db::get_unresolved_spent_unconfirmed_outputs(&conn, target.account.id)
                    .map_err(ScanError::DbError)?
            };

            if !unresolved.is_empty() {
                info!(
                    account_id = target.account.id,
                    count = unresolved.len();
                    "Verifying remaining SpentUnconfirmed outputs against base node"
                );
                self.verify_spent_unconfirmed_outputs(target, &unresolved).await?;
            }

            self.events
                .send(ProcessingEvent::ScanStatus(ScanStatusEvent::FastSyncPhaseCompleted {
                    account_id: target.account.id,
                    phase: FastSyncPhase::HistoryBackfill,
                }))
                .await;
        }

        info!("History backfill completed");
        let more_blocks = self
            .send_terminal_events(&targets, ScanStop::CaughtUp, backfill_to_height, total_scanned)
            .await;
        Ok((all_events, more_blocks))
    }

    /// Phase 1: Fast sync loop scanning only unspent outputs.
    async fn fast_sync_loop(
        &self,
        targets: &mut [AccountSyncTarget],
        end_height: u64,
        tip_height: u64,
        cancel_token: &Option<CancellationToken>,
    ) -> Result<(Vec<WalletEvent>, ScanStop, u64), ScanError> {
        let mut all_events = Vec::new();
        let mut state_manager = ScannerStateManager::new();
        let mut total_scanned = 0u64;

        let all_accounts: Vec<(i64, PrivateKey)> = targets
            .iter()
            .map(|target| (target.account.id, target.view_key.clone()))
            .collect();
        let (block_events_tx, mut block_events) = mpsc::unbounded_channel();
        let mut block_processor = BlockProcessor::with_event_sender(
            all_accounts,
            ChannelEventSender::new(block_events_tx),
            false,
            self.required_confirmations,
        );
        // This phase scans with `exclude_inputs`, so no send can be matched here.
        block_processor.set_inputs_excluded(true);
        let mut db_handler = ScanDbHandler::new(self.pool.clone(), block_processor);

        let global_next_block = targets.iter().map(|t| t.next_block_to_scan).min().unwrap_or(0);
        let active_account_ids: Vec<i64> = targets
            .iter()
            .filter(|t| t.next_block_to_scan <= end_height)
            .map(|t| t.account.id)
            .collect();

        if active_account_ids.is_empty() || global_next_block > end_height {
            return Ok((all_events, ScanStop::CaughtUp, 0));
        }

        let (scanner, mut scanner_config) = state_manager
            .get_scanner_and_config(
                &active_account_ids,
                global_next_block,
                Some(end_height),
                self.batch_size,
                targets,
                &self.base_url,
                self.processing_threads,
                &self.retry_config,
            )
            .await?;

        // Set exclude_spent and exclude_inputs for fast sync
        scanner_config.exclude_spent = true;
        scanner_config.exclude_inputs = true;

        let mut utxo_stream = scanner
            .scan_blocks(&scanner_config)
            .await
            .map_err(|e| ScanError::Intermittent(e.to_string()))?;

        let mut stop = ScanStop::CaughtUp;
        while let Some(response) = utxo_stream.recv().await {
            if let Some(token) = cancel_token
                && token.is_cancelled()
            {
                stop = ScanStop::Cancelled;
                break;
            }

            let scanned_blocks = response.map_err(|e| ScanError::Intermittent(e.to_string()))?;
            if scanned_blocks.is_empty() {
                break;
            }
            total_scanned = total_scanned.saturating_add(scanned_blocks.len() as u64);

            let shared_blocks = Arc::new(scanned_blocks);

            for account_id in &active_account_ids {
                let Some(target) = targets.iter_mut().find(|t| t.account.id == *account_id) else {
                    continue;
                };

                let events = db_handler
                    .process_blocks(
                        shared_blocks.clone(),
                        *account_id,
                        false,
                        self.webhook_config.clone(),
                        target.next_block_to_scan,
                    )
                    .await?;
                self.forward_block_events(&mut block_events).await;
                all_events.extend(events);

                if let Some(last) = shared_blocks.last() {
                    target.next_block_to_scan = next_block_height(last.height)?;

                    self.events
                        .send(ProcessingEvent::ScanStatus(ScanStatusEvent::Progress {
                            account_id: target.account.id,
                            current_height: last.height,
                            tip_height: tip_height.max(last.height),
                            blocks_scanned: total_scanned,
                        }))
                        .await;
                }
            }

            // Past the deadline, stop at this batch: out of budget if an account is
            // still below the end, otherwise done (the rest of the stream is past it).
            if self.deadline_passed() {
                if self.deadline_short_of(targets, end_height) {
                    stop = ScanStop::Deadline;
                }
                break;
            }
        }

        Ok((all_events, stop, total_scanned))
    }

    /// Phase 2: Full scan of recent blocks from fast_sync_target to tip.
    async fn recent_full_scan_loop(
        &self,
        targets: &mut [AccountSyncTarget],
        tip_height: u64,
        cancel_token: &Option<CancellationToken>,
    ) -> Result<(Vec<WalletEvent>, ScanStop, u64), ScanError> {
        let mut all_events = Vec::new();
        let mut state_manager = ScannerStateManager::new();
        let mut total_scanned = 0u64;

        let all_accounts: Vec<(i64, PrivateKey)> = targets
            .iter()
            .map(|target| (target.account.id, target.view_key.clone()))
            .collect();
        let (block_events_tx, mut block_events) = mpsc::unbounded_channel();
        let block_processor = BlockProcessor::with_event_sender(
            all_accounts,
            ChannelEventSender::new(block_events_tx),
            false,
            self.required_confirmations,
        );
        let mut db_handler = ScanDbHandler::new(self.pool.clone(), block_processor);

        let global_next_block = targets.iter().map(|t| t.next_block_to_scan).min().unwrap_or(0);
        let active_account_ids: Vec<i64> = targets.iter().map(|t| t.account.id).collect();

        let (scanner, scanner_config) = state_manager
            .get_scanner_and_config(
                &active_account_ids,
                global_next_block,
                None, // scan to tip
                self.batch_size,
                targets,
                &self.base_url,
                self.processing_threads,
                &self.retry_config,
            )
            .await?;

        let mut utxo_stream = scanner
            .scan_blocks(&scanner_config)
            .await
            .map_err(|e| ScanError::Intermittent(e.to_string()))?;

        let mut stop = ScanStop::CaughtUp;
        while let Some(response) = utxo_stream.recv().await {
            if let Some(token) = cancel_token
                && token.is_cancelled()
            {
                stop = ScanStop::Cancelled;
                break;
            }

            let scanned_blocks = response.map_err(|e| ScanError::Intermittent(e.to_string()))?;
            if scanned_blocks.is_empty() {
                break;
            }
            total_scanned = total_scanned.saturating_add(scanned_blocks.len() as u64);

            let shared_blocks = Arc::new(scanned_blocks);

            for account_id in &active_account_ids {
                let Some(target) = targets.iter_mut().find(|t| t.account.id == *account_id) else {
                    continue;
                };

                let has_pending_outbound = target
                    .transaction_monitor
                    .refresh_pending_outbound(&self.pool, target.account.id)
                    .map_err(ScanError::Fatal)?;
                let events = db_handler
                    .process_blocks(
                        shared_blocks.clone(),
                        *account_id,
                        has_pending_outbound,
                        self.webhook_config.clone(),
                        target.next_block_to_scan,
                    )
                    .await?;
                self.forward_block_events(&mut block_events).await;
                all_events.extend(events);

                if let Some(last) = shared_blocks.last() {
                    target.next_block_to_scan = next_block_height(last.height)?;

                    self.events
                        .send(ProcessingEvent::ScanStatus(ScanStatusEvent::Progress {
                            account_id: target.account.id,
                            current_height: last.height,
                            tip_height: tip_height.max(last.height),
                            blocks_scanned: total_scanned,
                        }))
                        .await;
                }
            }

            // Past the deadline, stop at this batch: out of budget if an account is
            // still below the end, otherwise done (the rest of the stream is past it).
            if self.deadline_passed() {
                if self.deadline_short_of(targets, tip_height) {
                    stop = ScanStop::Deadline;
                }
                break;
            }
        }

        // The end of the fast sync: settle pending transactions once, at the
        // height each account reached. Not when cancelled or out of time.
        if stop.runs_post_scan() {
            all_events.extend(self.run_post_scan(targets).await?);
        }

        Ok((all_events, stop, total_scanned))
    }

    /// Phase 3: Backfill loop scanning full blocks with OR IGNORE for existing data.
    async fn backfill_loop(
        &self,
        targets: &mut [AccountSyncTarget],
        end_height: u64,
        cancel_token: &Option<CancellationToken>,
    ) -> Result<(Vec<WalletEvent>, ScanStop, u64), ScanError> {
        let mut all_events = Vec::new();
        let mut state_manager = ScannerStateManager::new();
        let mut total_scanned = 0u64;

        let all_accounts: Vec<(i64, PrivateKey)> = targets
            .iter()
            .map(|target| (target.account.id, target.view_key.clone()))
            .collect();
        let (block_events_tx, mut block_events) = mpsc::unbounded_channel();
        let mut block_processor = BlockProcessor::with_event_sender(
            all_accounts,
            ChannelEventSender::new(block_events_tx),
            false,
            self.required_confirmations,
        );
        block_processor.set_backfill_mode(true);
        let mut db_handler = ScanDbHandler::new(self.pool.clone(), block_processor);

        let global_next_block = targets.iter().map(|t| t.next_block_to_scan).min().unwrap_or(0);
        let active_account_ids: Vec<i64> = targets
            .iter()
            .filter(|t| t.next_block_to_scan <= end_height)
            .map(|t| t.account.id)
            .collect();

        if active_account_ids.is_empty() || global_next_block > end_height {
            return Ok((all_events, ScanStop::CaughtUp, 0));
        }

        let (scanner, scanner_config) = state_manager
            .get_scanner_and_config(
                &active_account_ids,
                global_next_block,
                Some(end_height),
                self.batch_size,
                targets,
                &self.base_url,
                self.processing_threads,
                &self.retry_config,
            )
            .await?;

        let mut utxo_stream = scanner
            .scan_blocks(&scanner_config)
            .await
            .map_err(|e| ScanError::Intermittent(e.to_string()))?;

        let mut stop = ScanStop::CaughtUp;
        while let Some(response) = utxo_stream.recv().await {
            if let Some(token) = cancel_token
                && token.is_cancelled()
            {
                stop = ScanStop::Cancelled;
                break;
            }

            let scanned_blocks = response.map_err(|e| ScanError::Intermittent(e.to_string()))?;
            if scanned_blocks.is_empty() {
                break;
            }
            total_scanned = total_scanned.saturating_add(scanned_blocks.len() as u64);

            let shared_blocks = Arc::new(scanned_blocks);

            for account_id in &active_account_ids {
                let Some(target) = targets.iter_mut().find(|t| t.account.id == *account_id) else {
                    continue;
                };

                let events = db_handler
                    .process_blocks(
                        shared_blocks.clone(),
                        *account_id,
                        false,
                        self.webhook_config.clone(),
                        target.next_block_to_scan,
                    )
                    .await?;
                self.forward_block_events(&mut block_events).await;
                all_events.extend(events);

                if let Some(last) = shared_blocks.last() {
                    target.next_block_to_scan = next_block_height(last.height)?;

                    self.events
                        .send(ProcessingEvent::ScanStatus(ScanStatusEvent::Progress {
                            account_id: target.account.id,
                            current_height: last.height,
                            tip_height: end_height.max(last.height),
                            blocks_scanned: total_scanned,
                        }))
                        .await;
                }
            }

            // Past the deadline, stop at this batch: out of budget if an account is
            // still below the end, otherwise done (the rest of the stream is past it).
            if self.deadline_passed() {
                if self.deadline_short_of(targets, end_height) {
                    stop = ScanStop::Deadline;
                }
                break;
            }
        }

        Ok((all_events, stop, total_scanned))
    }

    /// Verifies remaining SpentUnconfirmed outputs against the base node using
    /// the `get_utxos_deleted_info` endpoint. If `spent_in_header` is present,
    /// the output is confirmed Spent and an input record + debit balance change
    /// are created so the balance sums correctly. Otherwise it's marked Unspent.
    async fn verify_spent_unconfirmed_outputs(
        &self,
        target: &AccountSyncTarget,
        unresolved: &[crate::db::UnresolvedSpentOutput],
    ) -> Result<(), ScanError> {
        use std::collections::HashMap;

        let hash_to_output: HashMap<Vec<u8>, &crate::db::UnresolvedSpentOutput> =
            unresolved.iter().map(|o| (o.output_hash.clone(), o)).collect();

        let all_output_hashes: Vec<Vec<u8>> = unresolved.iter().map(|o| o.output_hash.clone()).collect();

        // Phase 1: Collect all network results before touching the database
        enum VerifyAction {
            ConfirmSpent {
                output_id: i64,
                value: u64,
                spent_height: u64,
                spent_block_hash: Vec<u8>,
            },
            MarkUnspent {
                output_id: i64,
            },
        }

        let mut actions = Vec::new();

        for output_hashes in all_output_hashes.chunks(50) {
            let response = self
                .client
                .get_utxos_deleted_info(output_hashes.to_vec())
                .await
                .map_err(|e| ScanError::Intermittent(format!("Failed to query UTXO deleted info: {}", e)))?;

            for utxo_info in &response.utxos {
                let Some(output) = hash_to_output.get(&utxo_info.utxo_hash) else {
                    continue;
                };

                if let Some((spent_height, spent_block_hash)) = &utxo_info.spent_in_header {
                    actions.push(VerifyAction::ConfirmSpent {
                        output_id: output.output_id,
                        value: output.value,
                        spent_height: *spent_height,
                        spent_block_hash: spent_block_hash.clone(),
                    });
                } else if utxo_info.found_in_header.is_some() {
                    actions.push(VerifyAction::MarkUnspent {
                        output_id: output.output_id,
                    });
                } else {
                    trace!(
                        account = &*target.account.friendly_name,
                        output_hash = &*utxo_info.utxo_hash.to_hex();
                        "Output unknown by base node, status kept as SpentUnconfirmed"
                    );
                }
            }
        }

        // Phase 2: Apply all DB writes in a single transaction so a mid-loop
        // failure cannot leave a half-written spend (an input without its debit
        // balance change, or a status update without a matching input).
        let mut conn = self.pool.get().map_err(|e| ScanError::DbError(e.into()))?;
        // BEGIN IMMEDIATE for the same reason as everywhere else in this crate: a
        // deferred read->write upgrade can fail with SQLITE_BUSY_SNAPSHOT in WAL
        // mode, which `busy_timeout` does not retry.
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| ScanError::DbError(WalletDbError::from(e)))?;
        let mut marked_unspent = 0u64;
        let mut confirmed_spent = 0u64;

        for action in &actions {
            match action {
                VerifyAction::ConfirmSpent {
                    output_id,
                    value,
                    spent_height,
                    spent_block_hash,
                } => {
                    let input_id = crate::db::insert_input(
                        &tx,
                        target.account.id,
                        *output_id,
                        *spent_height,
                        spent_block_hash,
                        0, // timestamp not available from deleted info
                    )
                    .map_err(ScanError::DbError)?;

                    let change = crate::models::BalanceChange {
                        account_id: target.account.id,
                        caused_by_output_id: None,
                        caused_by_input_id: Some(input_id),
                        description: "Output spent (verified by base node)".to_string(),
                        balance_credit: 0.into(),
                        balance_debit: (*value).into(),
                        effective_date: chrono::Utc::now().naive_utc(),
                        effective_height: *spent_height,
                        claimed_recipient_address: None,
                        claimed_sender_address: None,
                        memo_hex: None,
                        memo_parsed: None,
                        claimed_fee: None,
                        claimed_amount: None,
                        is_reversal: false,
                        reversal_of_balance_change_id: None,
                        is_reversed: false,
                    };
                    crate::db::insert_balance_change(&tx, &change).map_err(ScanError::DbError)?;

                    crate::db::update_output_status(&tx, *output_id, OutputStatus::Spent)
                        .map_err(ScanError::DbError)?;
                    confirmed_spent = confirmed_spent.saturating_add(1);
                },
                VerifyAction::MarkUnspent { output_id } => {
                    crate::db::update_output_status(&tx, *output_id, OutputStatus::Unspent)
                        .map_err(ScanError::DbError)?;
                    marked_unspent = marked_unspent.saturating_add(1);
                },
            }
        }

        tx.commit().map_err(|e| ScanError::DbError(WalletDbError::from(e)))?;

        info!(
            account_id = target.account.id,
            marked_unspent = marked_unspent,
            confirmed_spent = confirmed_spent;
            "Verified SpentUnconfirmed outputs against base node"
        );

        Ok(())
    }

    async fn create_reorg_scanner(
        &self,
        key_manager: KeyManager,
    ) -> Result<HttpBlockchainScanner<KeyManager>, ScanError> {
        HttpBlockchainScanner::new(self.base_url.clone(), vec![key_manager], OPTIMAL_SCANNING_THREADS)
            .await
            .map_err(|e| ScanError::Intermittent(e.to_string()))
    }
}

/// Unix timestamp (seconds) of the wallet birthday, moved back by `scanning_offset` days.
///
/// `birthday_days` counts days since `BIRTHDAY_GENESIS_FROM_UNIX_EPOCH`. Returns an error
/// instead of overflowing when the stored birthday is out of range (e.g. a negative value
/// read back from the database).
fn birthday_timestamp(birthday_days: u64, scanning_offset: u64) -> Result<u64, ScanError> {
    const SECONDS_PER_DAY: u64 = 24 * 60 * 60;
    let days = birthday_days.saturating_sub(scanning_offset);
    days.checked_mul(SECONDS_PER_DAY)
        .and_then(|seconds| seconds.checked_add(BIRTHDAY_GENESIS_FROM_UNIX_EPOCH))
        .ok_or_else(|| {
            ScanError::Fatal(anyhow::anyhow!(
                "Wallet birthday of {birthday_days} days is out of range"
            ))
        })
}

/// Awaits `future`, or returns `None` if `cancel` fires first.
async fn unless_cancelled<T>(cancel: &Option<CancellationToken>, future: impl Future<Output = T>) -> Option<T> {
    match cancel {
        Some(token) => tokio::select! {
            output = future => Some(output),
            () = token.cancelled() => None,
        },
        None => Some(future.await),
    }
}

/// Height of the block after `height`.
///
/// Returns an error instead of overflowing if a base node reports a block at `u64::MAX`.
fn next_block_height(height: u64) -> Result<u64, ScanError> {
    height
        .checked_add(1)
        .ok_or_else(|| ScanError::Fatal(anyhow::anyhow!("Block height {height} has no next block height")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{
        create_account, get_account_by_name, get_displayed_transaction_by_id, get_scanned_tip_blocks_by_account,
        init_db, insert_displayed_transaction, insert_scanned_tip_block,
    };
    use crate::transactions::idempotency::{IdempotencyBinding, IdempotencyOperation, RequestFingerprint};
    use crate::transactions::{
        BlockchainInfo, DisplayedTransaction, TransactionDetails, TransactionDirection, TransactionDisplayStatus,
        TransactionSource,
    };
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_common_types::transaction::TxId;
    use tari_common_types::types::FixedHash;
    use tari_transaction_components::MicroMinotari;
    use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
    use tari_transaction_components::rpc::models::{
        BlockUtxoInfo, SyncUtxosByBlockResponseV0, SyncUtxosByBlockResponseV1,
    };
    use tari_transaction_components::transaction_components::{Transaction, TransactionKernel};
    use tempfile::TempDir;
    use tokio::sync::mpsc::UnboundedReceiver;
    use wiremock::{MockServer, Request, Respond, ResponseTemplate};

    #[test]
    fn birthday_timestamp_applies_offset_in_days() {
        let timestamp = birthday_timestamp(10, 3).unwrap();
        assert_eq!(timestamp, 7 * 24 * 60 * 60 + BIRTHDAY_GENESIS_FROM_UNIX_EPOCH);
    }

    #[test]
    fn birthday_timestamp_offset_larger_than_birthday_is_genesis() {
        let timestamp = birthday_timestamp(2, 5).unwrap();
        assert_eq!(timestamp, BIRTHDAY_GENESIS_FROM_UNIX_EPOCH);
    }

    #[test]
    fn birthday_timestamp_out_of_range_is_error() {
        // A negative birthday cast to u64 becomes huge; this used to overflow.
        let result = birthday_timestamp(-1i64 as u64, 0);
        assert!(matches!(result, Err(ScanError::Fatal(_))));
    }

    #[test]
    fn next_block_height_increments() {
        assert_eq!(next_block_height(41).unwrap(), 42);
    }

    #[test]
    fn next_block_height_at_max_is_error() {
        assert!(matches!(next_block_height(u64::MAX), Err(ScanError::Fatal(_))));
    }

    #[test]
    fn the_post_scan_monitor_runs_when_caught_up_or_at_the_block_limit_but_not_when_cancelled() {
        assert!(ScanStop::CaughtUp.runs_post_scan());
        assert!(ScanStop::BlockLimit.runs_post_scan());
        assert!(!ScanStop::Cancelled.runs_post_scan());
        assert!(!ScanStop::Deadline.runs_post_scan());
    }

    /// The hash the mock chain gives the block at `height`.
    fn block_hash(height: u64) -> Vec<u8> {
        let mut hash = vec![0x5A; 32];
        hash.splice(0..8, height.to_be_bytes());
        hash
    }

    fn height_of(hash_hex: &str) -> u64 {
        let bytes = hex::decode(hash_hex).expect("hex hash");
        let mut height = [0u8; 8];
        height.copy_from_slice(bytes.get(0..8).expect("hash is 32 bytes"));
        u64::from_be_bytes(height)
    }

    fn query_param(request: &Request, name: &str) -> String {
        request
            .url
            .query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.to_string())
            .expect("query parameter")
    }

    /// The hash the mock chain gives the block at `height` once it is reorged out.
    fn forked_block_hash(height: u64) -> Vec<u8> {
        let mut hash = vec![0xA5; 32];
        hash.splice(0..8, height.to_be_bytes());
        hash
    }

    /// A base node whose chain has empty blocks up to `tip`. Blocks at or above
    /// `fork_from` have forked hashes. `fork_on_header: Some((height, from))`
    /// forks from `from` when the header at `height` is first asked for. Block
    /// downloads take `download_delay`, tip requests hang while `slow_tip` and
    /// header requests while `slow_headers`. The birthday is at `BIRTHDAY_HEIGHT`;
    /// its lookup fails if `fail_birthday` and hangs while `slow_birthday`.
    /// `refork_from: Some(from)` forks the chain anew from `from` whenever a
    /// header at or above it is asked for.
    struct MockChain {
        tip: u64,
        fork_from: Arc<AtomicU64>,
        fork_on_header: Option<(u64, u64)>,
        download_delay: Duration,
        slow_tip: Arc<AtomicBool>,
        slow_headers: Arc<AtomicBool>,
        fail_birthday: bool,
        slow_birthday: Arc<AtomicBool>,
        refork_from: Option<u64>,
        forks: AtomicU64,
    }

    const BIRTHDAY_HEIGHT: u64 = 1450;

    fn hang_while(flag: &AtomicBool) -> Duration {
        if flag.load(Ordering::SeqCst) {
            Duration::from_secs(20)
        } else {
            Duration::ZERO
        }
    }

    impl MockChain {
        fn new(tip: u64) -> Self {
            Self {
                tip,
                fork_from: Arc::new(AtomicU64::new(u64::MAX)),
                fork_on_header: None,
                download_delay: Duration::ZERO,
                slow_tip: Arc::new(AtomicBool::new(false)),
                slow_headers: Arc::new(AtomicBool::new(false)),
                fail_birthday: false,
                slow_birthday: Arc::new(AtomicBool::new(false)),
                refork_from: None,
                forks: AtomicU64::new(0),
            }
        }

        fn hash(&self, height: u64) -> Vec<u8> {
            if height >= self.fork_from.load(Ordering::SeqCst) {
                let mut hash = forked_block_hash(height);
                let forks = self.forks.load(Ordering::SeqCst);
                if forks > 0 {
                    hash.splice(8..16, forks.to_be_bytes());
                }
                hash
            } else {
                block_hash(height)
            }
        }
    }

    impl Respond for MockChain {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            match request.url.path() {
                "/get_height_at_time" if self.fail_birthday => ResponseTemplate::new(400),
                "/get_height_at_time" => ResponseTemplate::new(200)
                    .set_body_json(BIRTHDAY_HEIGHT)
                    .set_delay(hang_while(&self.slow_birthday)),
                "/get_tip_info" => {
                    let delay = hang_while(&self.slow_tip);
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({
                            "metadata": {
                                "best_block_height": self.tip,
                                "best_block_hash": self.hash(self.tip),
                                "accumulated_difficulty": "0x0",
                                "pruning_horizon": 0,
                                "pruned_height": 0,
                                "timestamp": 0,
                            },
                            "is_synced": true,
                        }))
                        .set_delay(delay)
                },
                "/get_header_by_height" => {
                    let height: u64 = query_param(request, "height").parse().expect("height");
                    if let Some((trigger, from)) = self.fork_on_header
                        && height == trigger
                    {
                        self.fork_from.store(from, Ordering::SeqCst);
                    }
                    if let Some(from) = self.refork_from
                        && height >= from
                    {
                        self.fork_from.store(from, Ordering::SeqCst);
                        self.forks.fetch_add(1, Ordering::SeqCst);
                    }
                    if height > self.tip {
                        return ResponseTemplate::new(404);
                    }
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({
                            "height": height,
                            "hash": self.hash(height),
                            "timestamp": 1_700_000_000u64,
                        }))
                        .set_delay(hang_while(&self.slow_headers))
                },
                "/sync_utxos_by_block" => {
                    let start = height_of(&query_param(request, "start_header_hash"));
                    let limit: u64 = query_param(request, "limit").parse().expect("limit");
                    let last = (start + limit - 1).min(self.tip);
                    let mut blocks = Vec::new();
                    for height in start..=last {
                        blocks.push(BlockUtxoInfo {
                            header_hash: self.hash(height),
                            height,
                            outputs: Vec::new(),
                            inputs: Vec::new(),
                            mined_timestamp: 1_700_000_000,
                        });
                    }
                    let next_header_to_scan = if last < self.tip {
                        self.hash(last + 1)
                    } else {
                        Vec::new()
                    };
                    let response = SyncUtxosByBlockResponseV1::from(SyncUtxosByBlockResponseV0 {
                        blocks,
                        has_next_page: false,
                        next_header_to_scan,
                    });
                    ResponseTemplate::new(200)
                        .set_body_json(response)
                        .set_delay(self.download_delay)
                },
                _ => ResponseTemplate::new(404),
            }
        }
    }

    struct Setup {
        coordinator: ScanCoordinator,
        events: UnboundedReceiver<ProcessingEvent>,
        pool: SqlitePool,
        account_id: i64,
        server: MockServer,
        _dir: TempDir,
    }

    /// A wallet scanned to `scanned_to` (with an old tip block at height 1
    /// that pruning should remove) on a chain whose tip is `tip`, holding a
    /// displayed send mined at `scanned_to - 100` that is still `Pending`.
    async fn setup(scanned_to: u64, tip: u64) -> Setup {
        setup_chain(scanned_to, MockChain::new(tip), 1_000).await
    }

    async fn setup_chain(scanned_to: u64, chain: MockChain, reorg_check_interval: u64) -> Setup {
        let server = MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(chain)
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().expect("temp dir");
        let pool = init_db(dir.path().join("coordinator.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
        create_account(&conn, "default", &wallet, "password").unwrap();
        let account = get_account_by_name(&conn, "default").unwrap().unwrap();

        insert_scanned_tip_block(&conn, account.id, 1, &block_hash(1)).expect("old tip");
        #[allow(clippy::cast_possible_wrap)]
        insert_scanned_tip_block(&conn, account.id, scanned_to as i64, &block_hash(scanned_to)).expect("tip");
        insert_displayed_transaction(&conn, &mined_pending_send(account.id, scanned_to - 100)).expect("displayed");
        drop(conn);

        let (sender, events) = tokio::sync::mpsc::unbounded_channel();
        let coordinator = new_coordinator(&pool, &server, EventChannel::Unbounded(sender), reorg_check_interval);

        Setup {
            coordinator,
            events,
            pool,
            account_id: account.id,
            server,
            _dir: dir,
        }
    }

    /// A coordinator scanning 10 blocks per batch with one processing thread.
    fn new_coordinator(
        pool: &SqlitePool,
        server: &MockServer,
        events: EventChannel,
        reorg_check_interval: u64,
    ) -> ScanCoordinator {
        ScanCoordinator::new(
            pool.clone(),
            server.uri(),
            events,
            ScanRetryConfig {
                timeout: std::time::Duration::from_secs(5),
                max_timeout_retries: 1,
                max_error_retries: 1,
                error_backoff_base_secs: 1,
            },
            3,
            None,
            1,
            reorg_check_interval,
            10,
        )
        .expect("coordinator")
    }

    fn mined_pending_send(account_id: i64, block_height: u64) -> DisplayedTransaction {
        DisplayedTransaction {
            id: TxId::from(1u64),
            direction: TransactionDirection::Outgoing,
            source: TransactionSource::OneSided,
            status: TransactionDisplayStatus::Pending,
            amount: MicroMinotari::from(1_000),
            message: None,
            counterparty: None,
            blockchain: BlockchainInfo {
                block_height,
                timestamp: chrono::Utc::now().naive_utc(),
                confirmations: 0,
                block_hash: FixedHash::zero(),
            },
            fee: None,
            details: TransactionDetails {
                account_id,
                total_credit: MicroMinotari::from(0),
                total_debit: MicroMinotari::from(1_000),
                inputs: Vec::new(),
                outputs: Vec::new(),
                output_type: None,
                coinbase_extra: None,
                memo_hex: None,
                sent_output_hashes: Vec::new(),
                sent_payrefs: Vec::new(),
            },
            lock_height: 0,
        }
    }

    fn account(pool: &SqlitePool) -> AccountRow {
        let conn = pool.get().expect("conn");
        get_account_by_name(&conn, "default").expect("query").expect("account")
    }

    fn drain(events: &mut UnboundedReceiver<ProcessingEvent>) -> Vec<ProcessingEvent> {
        let mut drained = Vec::new();
        while let Ok(event) = events.try_recv() {
            drained.push(event);
        }
        drained
    }

    fn position(events: &[ProcessingEvent], matches: impl Fn(&ProcessingEvent) -> bool) -> Option<usize> {
        events.iter().position(matches)
    }

    fn displayed_status(pool: &SqlitePool) -> TransactionDisplayStatus {
        let conn = pool.get().expect("conn");
        get_displayed_transaction_by_id(&conn, &TxId::from(1u64).to_string())
            .expect("query")
            .expect("displayed")
            .status
    }

    #[tokio::test]
    async fn a_full_scan_prunes_tips_reports_progress_and_runs_the_post_scan_monitor_when_caught_up() {
        let mut setup = setup(1500, 1505).await;

        let (_, more_blocks) = setup
            .coordinator
            .run(vec![account(&setup.pool)], "password", ScanMode::Full, 0, None)
            .await
            .expect("scan");
        assert!(!more_blocks);
        let events = drain(&mut setup.events);

        // Per batch: progress is reported and old tip blocks are pruned.
        assert!(
            events.iter().any(|e| matches!(
                e,
                ProcessingEvent::ScanStatus(ScanStatusEvent::Progress {
                    current_height: 1505,
                    ..
                })
            )),
            "a Progress event must be emitted for a non-empty batch"
        );
        let conn = setup.pool.get().expect("conn");
        let tips = get_scanned_tip_blocks_by_account(&conn, setup.account_id).expect("tips");
        assert!(tips.iter().all(|t| t.height != 1), "the old tip block must be pruned");
        assert!(tips.iter().any(|t| t.height == 1505));

        // Caught up: the monitor ran at the scanned height before completion was reported.
        assert_eq!(displayed_status(&setup.pool), TransactionDisplayStatus::Confirmed);
        let updated = position(&events, |e| matches!(e, ProcessingEvent::TransactionsUpdated(_)))
            .expect("the post-scan monitor must emit the updated transaction");
        let completed = position(&events, |e| {
            matches!(e, ProcessingEvent::ScanStatus(ScanStatusEvent::Completed { .. }))
        })
        .expect("completed");
        assert!(updated < completed, "monitor events come before Completed");
        assert_eq!(terminal_count(&events), 1);
    }

    fn max_tip_height(pool: &SqlitePool, account_id: i64) -> u64 {
        let conn = pool.get().expect("conn");
        let tips = get_scanned_tip_blocks_by_account(&conn, account_id).expect("tips");
        tips.iter().map(|t| t.height).max().expect("a tip")
    }

    #[tokio::test]
    async fn a_scan_past_its_deadline_stops_after_one_batch_and_the_next_run_resumes_there() {
        let mut setup = setup(1500, 1600).await;
        setup.coordinator.deadline = Some(Instant::now());

        let (_, more_blocks) = setup
            .coordinator
            .run(vec![account(&setup.pool)], "password", ScanMode::Full, 0, None)
            .await
            .expect("scan");
        assert!(more_blocks);
        let events = drain(&mut setup.events);
        assert_eq!(terminal_count(&events), 1);
        let stopped_at = events
            .iter()
            .find_map(|e| match e {
                ProcessingEvent::ScanStatus(ScanStatusEvent::BudgetExhausted {
                    last_scanned_height,
                    tip_height,
                    ..
                }) => Some((*last_scanned_height, *tip_height)),
                _ => None,
            })
            .expect("budget exhausted");
        assert_eq!(stopped_at, (1510, 1600), "one batch of 10 blocks is scanned");
        assert_eq!(max_tip_height(&setup.pool, setup.account_id), 1510);

        setup.coordinator.deadline = None;
        setup
            .coordinator
            .run(vec![account(&setup.pool)], "password", ScanMode::Full, 0, None)
            .await
            .expect("scan");
        let events = drain(&mut setup.events);
        assert!(events.iter().any(|e| matches!(
            e,
            ProcessingEvent::ScanStatus(ScanStatusEvent::MoreBlocksAvailable {
                last_scanned_height: 1510,
                ..
            })
        )));
        assert!(events.iter().any(|e| matches!(
            e,
            ProcessingEvent::ScanStatus(ScanStatusEvent::Completed { final_height: 1600, .. })
        )));
        assert_eq!(terminal_count(&events), 1);
    }

    fn is_phase_completed(event: &ProcessingEvent) -> bool {
        matches!(
            event,
            ProcessingEvent::ScanStatus(ScanStatusEvent::FastSyncPhaseCompleted { .. })
        )
    }

    fn budget_exhausted_tip(events: &[ProcessingEvent]) -> Option<u64> {
        events.iter().find_map(|e| match e {
            ProcessingEvent::ScanStatus(ScanStatusEvent::BudgetExhausted { tip_height, .. }) => Some(*tip_height),
            _ => None,
        })
    }

    const FAST_SYNC: ScanMode = ScanMode::FastSync { safety_buffer: 20 };
    const BACKFILL_TO: u64 = 1520;

    /// Runs `scan` and cancels it once the (slow) block download has been asked for.
    async fn cancel_during_download(
        setup: &Setup,
        token: &CancellationToken,
        scan: impl Future<Output = Result<(Vec<WalletEvent>, bool), ScanError>>,
    ) -> bool {
        let cancel = cancel_once_requested(&setup.server, "/sync_utxos_by_block", 0, token);
        let (result, _) = tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(scan, cancel) })
            .await
            .expect("the scan stops when cancelled");
        let (_, more_blocks) = result.expect("a cancelled scan is not an error");
        more_blocks
    }

    fn slow_download_chain() -> MockChain {
        let mut chain = MockChain::new(1600);
        chain.download_delay = Duration::from_millis(500);
        chain
    }

    #[tokio::test]
    async fn a_fast_sync_completes_once_after_both_phases() {
        let mut setup = setup(1500, 1600).await;

        let (_, more_blocks) = setup
            .coordinator
            .run(vec![account(&setup.pool)], "password", FAST_SYNC, 0, None)
            .await
            .expect("scan");
        assert!(!more_blocks);
        let events = drain(&mut setup.events);

        assert_eq!(terminal_count(&events), 1);
        let completed = position(&events, |e| {
            matches!(
                e,
                ProcessingEvent::ScanStatus(ScanStatusEvent::Completed { final_height: 1600, .. })
            )
        })
        .expect("completed");
        assert_eq!(events.iter().filter(|e| is_phase_completed(e)).count(), 2);
        let last_phase = events.iter().rposition(is_phase_completed).expect("phase completed");
        assert!(last_phase < completed, "Completed comes after the phases");
    }

    #[tokio::test]
    async fn a_fast_sync_past_its_deadline_ends_out_of_budget() {
        let mut setup = setup(1500, 1600).await;
        setup.coordinator.deadline = Some(Instant::now());

        let (_, more_blocks) = setup
            .coordinator
            .run(vec![account(&setup.pool)], "password", FAST_SYNC, 0, None)
            .await
            .expect("scan");
        assert!(more_blocks);
        let events = drain(&mut setup.events);
        assert_eq!(terminal_count(&events), 1);
        assert_eq!(budget_exhausted_tip(&events), Some(1600));
    }

    #[tokio::test]
    async fn a_fast_sync_whose_deadline_passes_at_the_end_of_phase_one_does_not_start_phase_two() {
        let mut setup = setup(1500, 1600).await;
        setup.coordinator.deadline = Some(Instant::now());
        // Phase 1 covers 1501..=1510, one batch; the tip is at 1600.
        let mode = ScanMode::FastSync { safety_buffer: 90 };

        let (_, more_blocks) = setup
            .coordinator
            .run(vec![account(&setup.pool)], "password", mode, 0, None)
            .await
            .expect("scan");
        assert!(more_blocks);
        let events = drain(&mut setup.events);

        let progress: Vec<u64> = events
            .iter()
            .filter_map(|e| match e {
                ProcessingEvent::ScanStatus(ScanStatusEvent::Progress { current_height, .. }) => Some(*current_height),
                _ => None,
            })
            .collect();
        assert_eq!(progress, vec![1510], "exactly one batch is scanned");
        assert!(
            !events.iter().any(|e| matches!(
                e,
                ProcessingEvent::ScanStatus(ScanStatusEvent::FastSyncPhaseStarted {
                    phase: FastSyncPhase::RecentFullScan,
                    ..
                })
            )),
            "phase 2 never starts"
        );
        assert_eq!(terminal_count(&events), 1);
        assert_eq!(budget_exhausted_tip(&events), Some(1600));
    }

    #[tokio::test]
    async fn a_fast_sync_past_its_deadline_with_phase_one_done_still_scans_a_phase_two_batch() {
        // Phase 1 ends at 1510, below where the wallet already is.
        let mut setup = setup(1550, 1600).await;
        setup.coordinator.deadline = Some(Instant::now());
        let mode = ScanMode::FastSync { safety_buffer: 90 };

        let (_, more_blocks) = setup
            .coordinator
            .run(vec![account(&setup.pool)], "password", mode, 0, None)
            .await
            .expect("scan");
        assert!(more_blocks);
        let events = drain(&mut setup.events);

        assert!(events.iter().any(|e| matches!(
            e,
            ProcessingEvent::ScanStatus(ScanStatusEvent::FastSyncPhaseStarted {
                phase: FastSyncPhase::RecentFullScan,
                ..
            })
        )));
        let progress: Vec<u64> = events
            .iter()
            .filter_map(|e| match e {
                ProcessingEvent::ScanStatus(ScanStatusEvent::Progress { current_height, .. }) => Some(*current_height),
                _ => None,
            })
            .collect();
        assert_eq!(progress, vec![1560], "exactly one phase 2 batch is scanned");
        assert_eq!(terminal_count(&events), 1);
        assert_eq!(budget_exhausted_tip(&events), Some(1600));
    }

    #[tokio::test]
    async fn a_cancelled_fast_sync_reports_cancelled_once() {
        let mut setup = setup_chain(1500, slow_download_chain(), 1_000).await;
        let token = CancellationToken::new();

        let scan = setup.coordinator.run(
            vec![account(&setup.pool)],
            "password",
            FAST_SYNC,
            0,
            Some(token.clone()),
        );
        assert!(cancel_during_download(&setup, &token, scan).await);
        let events = drain(&mut setup.events);
        assert_eq!(terminal_count(&events), 1);
        assert!(events.iter().any(is_cancelled));
    }

    #[tokio::test]
    async fn a_backfill_completes_once_after_its_phase() {
        let mut setup = setup(1500, 1600).await;

        let (_, more_blocks) = setup
            .coordinator
            .run_backfill(vec![account(&setup.pool)], "password", BACKFILL_TO, 0, None)
            .await
            .expect("backfill");
        assert!(!more_blocks);
        let events = drain(&mut setup.events);

        assert_eq!(terminal_count(&events), 1);
        // The mock chain serves whole pages, so the scan can end past BACKFILL_TO.
        let completed = position(&events, |e| {
            matches!(
                e,
                ProcessingEvent::ScanStatus(ScanStatusEvent::Completed { final_height, .. }) if *final_height >= BACKFILL_TO
            )
        })
        .expect("completed");
        let phase = position(&events, is_phase_completed).expect("phase completed");
        assert!(phase < completed, "Completed comes after the phase");
    }

    #[tokio::test]
    async fn a_backfill_past_its_deadline_ends_out_of_budget() {
        let mut setup = setup(1500, 1600).await;
        setup.coordinator.deadline = Some(Instant::now());

        let (_, more_blocks) = setup
            .coordinator
            .run_backfill(vec![account(&setup.pool)], "password", BACKFILL_TO, 0, None)
            .await
            .expect("backfill");
        assert!(more_blocks);
        let events = drain(&mut setup.events);
        assert_eq!(terminal_count(&events), 1);
        assert_eq!(budget_exhausted_tip(&events), Some(BACKFILL_TO));
        assert!(!events.iter().any(is_phase_completed));
    }

    #[tokio::test]
    async fn a_backfill_whose_deadline_passes_on_its_last_batch_still_finishes() {
        let mut setup = setup(1500, 1600).await;
        setup.coordinator.deadline = Some(Instant::now());
        // Inside the first 10-block batch from the birthday (1450).
        let backfill_to = 1455;

        let (_, more_blocks) = setup
            .coordinator
            .run_backfill(vec![account(&setup.pool)], "password", backfill_to, 0, None)
            .await
            .expect("backfill");
        assert!(!more_blocks);
        let events = drain(&mut setup.events);

        assert_eq!(terminal_count(&events), 1);
        let phase = position(&events, is_phase_completed).expect("the backfill's resolve step and phase end run");
        let completed = position(&events, |e| {
            matches!(e, ProcessingEvent::ScanStatus(ScanStatusEvent::Completed { .. }))
        })
        .expect("completed");
        assert!(phase < completed);
    }

    #[tokio::test]
    async fn a_full_scan_whose_deadline_passes_on_its_last_batch_still_runs_the_post_scan_monitor() {
        let mut setup = setup(1500, 1505).await;
        setup.coordinator.deadline = Some(Instant::now());

        let (_, more_blocks) = setup
            .coordinator
            .run(vec![account(&setup.pool)], "password", ScanMode::Full, 0, None)
            .await
            .expect("scan");
        assert!(!more_blocks);
        let events = drain(&mut setup.events);

        assert_eq!(terminal_count(&events), 1);
        assert!(events.iter().any(|e| matches!(
            e,
            ProcessingEvent::ScanStatus(ScanStatusEvent::Completed { final_height: 1505, .. })
        )));
        assert_eq!(
            displayed_status(&setup.pool),
            TransactionDisplayStatus::Confirmed,
            "the post-scan monitor ran"
        );
    }

    #[tokio::test]
    async fn a_partial_scan_whose_deadline_passes_on_its_block_limit_still_runs_the_post_scan_monitor() {
        let mut setup = setup(1500, 1600).await;
        setup.coordinator.deadline = Some(Instant::now());

        let (_, more_blocks) = setup
            .coordinator
            .run(
                vec![account(&setup.pool)],
                "password",
                ScanMode::Partial { max_blocks: 10 },
                0,
                None,
            )
            .await
            .expect("scan");
        assert!(more_blocks, "the scan stopped before the tip");
        let events = drain(&mut setup.events);

        assert_eq!(terminal_count(&events), 1);
        assert_ne!(displayed_status(&setup.pool), TransactionDisplayStatus::Pending);
        let updated = position(&events, |e| matches!(e, ProcessingEvent::TransactionsUpdated(_)))
            .expect("the post-scan monitor must emit the updated transaction");
        let exhausted = position(&events, |e| {
            matches!(
                e,
                ProcessingEvent::ScanStatus(ScanStatusEvent::BudgetExhausted { tip_height: 1600, .. })
            )
        })
        .expect("budget exhausted");
        assert!(updated < exhausted);
    }

    #[tokio::test]
    async fn a_full_scan_of_accounts_at_different_heights_takes_both_to_the_tip() {
        let mut setup = setup(1500, 1600).await;
        let accounts = {
            let conn = setup.pool.get().expect("conn");
            let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
            create_account(&conn, "second", &wallet, "password").unwrap();
            let second = get_account_by_name(&conn, "second").unwrap().unwrap();
            insert_scanned_tip_block(&conn, second.id, 1550, &block_hash(1550)).expect("tip");
            vec![get_account_by_name(&conn, "default").unwrap().unwrap(), second]
        };
        let account_ids: Vec<i64> = accounts.iter().map(|account| account.id).collect();

        let (_, more_blocks) = setup
            .coordinator
            .run(accounts, "password", ScanMode::Full, 0, None)
            .await
            .expect("scan");
        assert!(!more_blocks);
        let events = drain(&mut setup.events);

        assert_eq!(terminal_count(&events), 2, "one terminal event per account");
        for account_id in account_ids {
            let completed_at_tip = events
                .iter()
                .filter(|e| {
                    matches!(
                        e,
                        ProcessingEvent::ScanStatus(ScanStatusEvent::Completed { account_id: id, final_height: 1600, .. })
                            if *id == account_id
                    )
                })
                .count();
            assert_eq!(completed_at_tip, 1, "account {account_id} completes at the tip");
            assert_eq!(max_tip_height(&setup.pool, account_id), 1600);
        }
    }

    #[tokio::test]
    async fn a_cancelled_backfill_reports_cancelled_once() {
        let mut setup = setup_chain(1500, slow_download_chain(), 1_000).await;
        let token = CancellationToken::new();

        let scan = setup.coordinator.run_backfill(
            vec![account(&setup.pool)],
            "password",
            BACKFILL_TO,
            0,
            Some(token.clone()),
        );
        assert!(cancel_during_download(&setup, &token, scan).await);
        let events = drain(&mut setup.events);
        assert_eq!(terminal_count(&events), 1);
        assert!(events.iter().any(is_cancelled));
    }

    #[tokio::test]
    async fn a_bounded_event_channel_delivers_every_event_in_order_to_a_slow_consumer() {
        let setup = setup(1500, 1550).await;
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let coordinator = new_coordinator(
            &setup.pool,
            &setup.server,
            EventChannel::Bounded { sender, cancel: None },
            1_000,
        );

        let scan = async {
            let result = coordinator
                .run(vec![account(&setup.pool)], "password", ScanMode::Full, 0, None)
                .await;
            drop(coordinator);
            result
        };
        let consume = async {
            let mut events = Vec::new();
            while let Some(event) = receiver.recv().await {
                assert!(receiver.len() <= 2, "the channel holds at most its capacity");
                events.push(event);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            events
        };
        let (result, events) = tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(scan, consume) })
            .await
            .expect("the scan finishes");
        result.expect("scan");

        let heights: Vec<u64> = events
            .iter()
            .filter_map(|e| match e {
                ProcessingEvent::ScanStatus(ScanStatusEvent::Progress { current_height, .. }) => Some(*current_height),
                _ => None,
            })
            .collect();
        assert_eq!(heights, vec![1510, 1520, 1530, 1540, 1550]);
        let blocks = events
            .iter()
            .filter(|e| matches!(e, ProcessingEvent::BlockProcessed(_)))
            .count();
        assert_eq!(blocks, 50, "every block is reported");
        assert!(matches!(
            events.last(),
            Some(ProcessingEvent::ScanStatus(ScanStatusEvent::Completed {
                final_height: 1550,
                ..
            }))
        ));
        assert_eq!(terminal_count(&events), 1);
    }

    #[tokio::test]
    async fn cancelling_a_scan_blocked_on_a_full_event_channel_stops_it() {
        let setup = setup(1500, 1600).await;
        let token = CancellationToken::new();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let coordinator = new_coordinator(
            &setup.pool,
            &setup.server,
            EventChannel::Bounded {
                sender,
                cancel: Some(token.clone()),
            },
            1_000,
        );

        let scan = async {
            let result = coordinator
                .run(
                    vec![account(&setup.pool)],
                    "password",
                    ScanMode::Full,
                    0,
                    Some(token.clone()),
                )
                .await;
            (result, std::time::Instant::now())
        };
        // Read nothing until the channel is full and the scan waits on it, then
        // cancel and read every event up to the terminal one.
        let cancel_then_drain = async {
            while receiver.capacity() > 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            token.cancel();
            let cancelled_at = std::time::Instant::now();
            let mut events = Vec::new();
            while let Some(event) = receiver.recv().await {
                let terminal = is_cancelled(&event);
                events.push(event);
                if terminal {
                    break;
                }
            }
            (cancelled_at, events)
        };
        let ((result, stopped_at), (cancelled_at, mut events)) =
            tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(scan, cancel_then_drain) })
                .await
                .expect("the scan stops when cancelled");
        let (_, more_blocks) = result.expect("a cancelled scan is not an error");
        assert!(more_blocks);
        assert!(
            stopped_at.duration_since(cancelled_at) < Duration::from_secs(2),
            "cancelling must not wait for the block download or the full channel"
        );
        while let Ok(event) = receiver.try_recv() {
            events.push(event);
        }
        assert_eq!(events.iter().filter(|e| is_cancelled(e)).count(), 1);
        assert_eq!(terminal_count(&events), 1);
        assert!(
            max_tip_height(&setup.pool, setup.account_id) <= 1510,
            "the scan stops within one batch"
        );
    }

    #[tokio::test]
    async fn a_partial_scan_runs_the_post_scan_monitor_when_it_reaches_its_block_limit() {
        let mut setup = setup(1500, 1600).await;

        let (_, more_blocks) = setup
            .coordinator
            .run(
                vec![account(&setup.pool)],
                "password",
                ScanMode::Partial { max_blocks: 2 },
                0,
                None,
            )
            .await
            .expect("scan");
        assert!(more_blocks, "the scan paused before the tip");
        let events = drain(&mut setup.events);

        assert_ne!(displayed_status(&setup.pool), TransactionDisplayStatus::Pending);
        let updated = position(&events, |e| matches!(e, ProcessingEvent::TransactionsUpdated(_)))
            .expect("the post-scan monitor must emit the updated transaction");
        let exhausted = position(&events, |e| {
            matches!(
                e,
                ProcessingEvent::ScanStatus(ScanStatusEvent::BudgetExhausted { tip_height: 1600, .. })
            )
        })
        .expect("budget exhausted");
        assert!(updated < exhausted, "monitor events come before the terminal event");
        assert_eq!(terminal_count(&events), 1);
    }

    /// Records a send for `account_id`, in `Broadcast` with a kernel the node can
    /// be asked about, and returns its id.
    fn record_broadcast_send(conn: &rusqlite::Connection, account_id: i64, id: u64) -> TxId {
        let key = format!("send-{id}");
        let binding = IdempotencyBinding::new(
            Some(key.clone()),
            IdempotencyOperation::SendTransaction,
            RequestFingerprint::new(IdempotencyOperation::SendTransaction),
        );
        let request_id = crate::db::create_pending_transaction(
            conn,
            &key,
            &binding,
            account_id,
            true,
            MicroMinotari(0),
            MicroMinotari(0),
            MicroMinotari(0),
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .expect("pending transaction");
        let transaction = Transaction::new(
            Vec::new(),
            Vec::new(),
            vec![TransactionKernel::default()],
            PrivateKey::default(),
            PrivateKey::default(),
        );
        let tx_id = TxId::from(id);
        crate::db::create_completed_transaction(
            conn,
            account_id,
            &request_id,
            &[],
            &serde_json::to_vec(&transaction).expect("serialize"),
            Some(hex::encode([9u8; 32])),
            tx_id,
        )
        .expect("completed");
        crate::db::mark_completed_transaction_as_broadcasted(conn, tx_id, 1).expect("broadcast");
        tx_id
    }

    #[tokio::test]
    async fn a_node_error_for_one_account_does_not_stop_the_others_or_the_scan() {
        // The mock chain does not answer `/transactions`, so asking about the
        // first account's broadcast send fails. The second account's mined send
        // must still be confirmed, and the scan must still complete.
        let mut setup = setup(1500, 1505).await;
        let (first_send, second_send, second_id) = {
            let conn = setup.pool.get().expect("conn");
            let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
            create_account(&conn, "second", &wallet, "password").unwrap();
            let second = get_account_by_name(&conn, "second").unwrap().unwrap();
            insert_scanned_tip_block(&conn, second.id, 1500, &block_hash(1500)).expect("tip");

            let first_send = record_broadcast_send(&conn, setup.account_id, 1);
            let second_send = record_broadcast_send(&conn, second.id, 2);
            crate::db::mark_completed_transaction_as_mined_unconfirmed(&conn, second_send, 1400, &[7u8; 32])
                .expect("mined");
            (first_send, second_send, second.id)
        };

        let accounts = {
            let conn = setup.pool.get().expect("conn");
            vec![
                get_account_by_name(&conn, "default").unwrap().unwrap(),
                get_account_by_name(&conn, "second").unwrap().unwrap(),
            ]
        };
        setup
            .coordinator
            .run(accounts, "password", ScanMode::Full, 0, None)
            .await
            .expect("a node error does not fail the scan");
        let events = drain(&mut setup.events);

        let conn = setup.pool.get().expect("conn");
        let first = crate::db::get_completed_transaction_by_id(&conn, first_send)
            .expect("query")
            .expect("first");
        assert_eq!(first.status, crate::db::CompletedTransactionStatus::Broadcast);
        let second = crate::db::get_completed_transaction_by_id(&conn, second_send)
            .expect("query")
            .expect("second");
        assert_eq!(
            second.status,
            crate::db::CompletedTransactionStatus::MinedConfirmed,
            "the second account is still monitored"
        );
        assert!(
            events.iter().any(|e| matches!(
                e,
                ProcessingEvent::ScanStatus(ScanStatusEvent::Completed { account_id, .. }) if *account_id == second_id
            )),
            "the scan still reports Completed"
        );
    }

    const POLL_INTERVAL: Duration = Duration::from_millis(200);

    fn is_waiting(event: &ProcessingEvent) -> bool {
        matches!(event, ProcessingEvent::ScanStatus(ScanStatusEvent::Waiting { .. }))
    }

    fn terminal_count(events: &[ProcessingEvent]) -> usize {
        events
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    ProcessingEvent::ScanStatus(
                        ScanStatusEvent::Completed { .. }
                            | ScanStatusEvent::Cancelled { .. }
                            | ScanStatusEvent::BudgetExhausted { .. }
                    )
                )
            })
            .count()
    }

    fn is_cancelled(event: &ProcessingEvent) -> bool {
        matches!(event, ProcessingEvent::ScanStatus(ScanStatusEvent::Cancelled { .. }))
    }

    /// Runs a continuous scan, handing each event to `on_event` until it returns
    /// `true`, then cancels the scan and returns every event it sent.
    async fn run_continuous_until(
        setup: &mut Setup,
        mut on_event: impl FnMut(&ProcessingEvent) -> bool,
    ) -> Vec<ProcessingEvent> {
        let token = CancellationToken::new();
        let scan = setup.coordinator.run(
            vec![account(&setup.pool)],
            "password",
            ScanMode::Continuous {
                poll_interval: POLL_INTERVAL,
            },
            0,
            Some(token.clone()),
        );
        let events = &mut setup.events;
        let watch = async {
            let mut seen = Vec::new();
            while let Some(event) = events.recv().await {
                let stop = on_event(&event);
                seen.push(event);
                if stop {
                    token.cancel();
                    break;
                }
            }
            seen
        };
        let ((_, more_blocks), mut seen) = tokio::time::timeout(Duration::from_secs(30), async {
            let (result, seen) = tokio::join!(scan, watch);
            (result.expect("scan"), seen)
        })
        .await
        .expect("the continuous scan stops when cancelled");
        assert!(more_blocks, "a cancelled scan reports that it paused");
        seen.extend(drain(events));
        seen
    }

    #[tokio::test]
    async fn a_continuous_scan_reports_progress_then_caught_up_then_stops_when_cancelled() {
        let mut setup = setup(1500, 1505).await;

        let events = run_continuous_until(&mut setup, is_waiting).await;

        let progress = position(&events, |e| {
            matches!(
                e,
                ProcessingEvent::ScanStatus(ScanStatusEvent::Progress {
                    current_height: 1505,
                    tip_height: 1505,
                    ..
                })
            )
        })
        .expect("progress up to the tip");
        let waiting = position(&events, is_waiting).expect("waiting for the next poll");
        let cancelled = position(&events, is_cancelled).expect("cancelled");
        assert!(progress < waiting && waiting < cancelled);
        // Caught up is `Waiting`; the only terminal event is the cancel.
        assert_eq!(terminal_count(&events), 1);
        assert!(
            events.iter().any(|e| matches!(
                e,
                ProcessingEvent::ScanStatus(ScanStatusEvent::Cancelled {
                    last_scanned_height: 1505,
                    ..
                })
            )),
            "a cancel during the poll wait reports the tip as scanned"
        );
    }

    #[tokio::test]
    async fn a_continuous_scan_past_its_deadline_ends_out_of_budget_not_completed() {
        let mut setup = setup(1500, 1505).await;
        setup.coordinator.deadline = Some(Instant::now() + POLL_INTERVAL);

        let (_, more_blocks) = tokio::time::timeout(
            Duration::from_secs(30),
            setup.coordinator.run(
                vec![account(&setup.pool)],
                "password",
                ScanMode::Continuous {
                    poll_interval: POLL_INTERVAL * 10,
                },
                0,
                None,
            ),
        )
        .await
        .expect("the deadline stops the continuous scan")
        .expect("scan");
        assert!(more_blocks);
        let events = drain(&mut setup.events);
        assert_eq!(terminal_count(&events), 1);
        assert!(events.iter().any(|e| matches!(
            e,
            ProcessingEvent::ScanStatus(ScanStatusEvent::BudgetExhausted {
                last_scanned_height: 1505,
                tip_height: 1505,
                ..
            })
        )));
    }

    #[tokio::test]
    async fn a_continuous_scan_reports_a_reorg_found_between_polls_and_rescans_the_new_block() {
        let chain = MockChain::new(1505);
        let fork_from = chain.fork_from.clone();
        let mut setup = setup_chain(1500, chain, 1_000).await;

        // Fork the tip block while the scan waits for its first poll, and stop
        // at the wait that follows the reorg.
        let mut reorged = false;
        let events = run_continuous_until(&mut setup, |event| {
            if matches!(event, ProcessingEvent::ReorgDetected(_)) {
                reorged = true;
            }
            if is_waiting(event) {
                fork_from.store(1505, Ordering::SeqCst);
                return reorged;
            }
            false
        })
        .await;

        let reorg = events
            .iter()
            .find_map(|e| match e {
                ProcessingEvent::ReorgDetected(reorg) => Some(reorg),
                _ => None,
            })
            .expect("a ReorgDetected event");
        assert_eq!(reorg.account_id, setup.account_id);
        assert_eq!(reorg.reorg_from_height, 1505);
        assert_eq!(reorg.new_height, 1505);
        assert_eq!(reorg.blocks_rolled_back, 1);

        let conn = setup.pool.get().expect("conn");
        let tips = get_scanned_tip_blocks_by_account(&conn, setup.account_id).expect("tips");
        let tip = tips.iter().find(|t| t.height == 1505).expect("the tip is rescanned");
        assert_eq!(tip.hash, forked_block_hash(1505), "the rescanned tip is the new block");
    }

    async fn count_requests(server: &MockServer, path: &str) -> usize {
        let requests = server.received_requests().await.unwrap_or_default();
        requests.iter().filter(|r| r.url.path() == path).count()
    }

    /// Cancels `token` once the server has had more than `seen` requests for
    /// `path`, and returns when it did.
    async fn cancel_once_requested(
        server: &MockServer,
        path: &str,
        seen: usize,
        token: &CancellationToken,
    ) -> std::time::Instant {
        while count_requests(server, path).await <= seen {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        token.cancel();
        std::time::Instant::now()
    }

    fn continuous_scan<'a>(
        coordinator: &'a ScanCoordinator,
        pool: &SqlitePool,
        token: &CancellationToken,
    ) -> impl Future<Output = Result<(Vec<WalletEvent>, bool), ScanError>> + 'a {
        coordinator.run(
            vec![account(pool)],
            "password",
            ScanMode::Continuous {
                poll_interval: POLL_INTERVAL,
            },
            0,
            Some(token.clone()),
        )
    }

    #[tokio::test]
    async fn cancelling_a_continuous_scan_mid_batch_stops_it_and_its_download_tasks() {
        let mut chain = MockChain::new(1600);
        chain.download_delay = Duration::from_secs(3);
        let mut setup = setup_chain(1500, chain, 1_000).await;

        let token = CancellationToken::new();
        let scan = continuous_scan(&setup.coordinator, &setup.pool, &token);
        let cancel = cancel_once_requested(&setup.server, "/sync_utxos_by_block", 0, &token);
        let (result, cancelled_at) = tokio::join!(scan, cancel);
        let (_, more_blocks) = result.expect("a cancelled scan is not an error");
        assert!(more_blocks);
        assert!(
            cancelled_at.elapsed() < Duration::from_secs(1),
            "cancelling must not wait for the block download"
        );

        // Had the download task outlived the scan, it would ask for the next page
        // once the slow one answered.
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert_eq!(count_requests(&setup.server, "/sync_utxos_by_block").await, 1);

        let events = drain(&mut setup.events);
        assert!(events.iter().any(is_cancelled));
        assert_eq!(terminal_count(&events), 1);
        let conn = setup.pool.get().expect("conn");
        let tips = get_scanned_tip_blocks_by_account(&conn, setup.account_id).expect("tips");
        assert_eq!(
            tips.iter().map(|t| t.height).max(),
            Some(1500),
            "nothing from the cancelled batch is written"
        );
    }

    #[tokio::test]
    async fn cancelling_a_continuous_scan_while_it_reads_the_tip_stops_it() {
        let chain = MockChain::new(1505);
        let slow_tip = chain.slow_tip.clone();
        let mut setup = setup_chain(1500, chain, 1_000).await;

        let token = CancellationToken::new();
        let scan = continuous_scan(&setup.coordinator, &setup.pool, &token);
        let server = &setup.server;
        let events = &mut setup.events;
        // Make the tip read after the first poll hang, and cancel while it does.
        let cancel = async {
            while let Some(event) = events.recv().await {
                if is_waiting(&event) {
                    break;
                }
            }
            slow_tip.store(true, Ordering::SeqCst);
            let seen = count_requests(server, "/get_tip_info").await;
            cancel_once_requested(server, "/get_tip_info", seen, &token).await
        };
        let (result, cancelled_at) =
            tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(scan, cancel) })
                .await
                .expect("the scan stops when cancelled");
        let (_, more_blocks) = result.expect("a cancelled scan is not an error");
        assert!(more_blocks);
        assert!(
            cancelled_at.elapsed() < Duration::from_secs(2),
            "cancelling must not wait for the tip"
        );
        assert!(drain(events).iter().any(is_cancelled));
    }

    #[tokio::test]
    async fn a_reorg_found_mid_pass_rescans_from_the_fork_and_the_scan_completes() {
        // Reorg checks run after every 10-block page. The one after the page
        // ending at 1530 finds the chain forked from 1525.
        let mut chain = MockChain::new(1560);
        chain.fork_on_header = Some((1530, 1525));
        let mut setup = setup_chain(1500, chain, 10).await;

        let (_, more_blocks) = setup
            .coordinator
            .run(vec![account(&setup.pool)], "password", ScanMode::Full, 0, None)
            .await
            .expect("the scan survives the reorg");
        assert!(!more_blocks);
        let events = drain(&mut setup.events);

        let reorg = events
            .iter()
            .find_map(|e| match e {
                ProcessingEvent::ReorgDetected(reorg) => Some(reorg),
                _ => None,
            })
            .expect("a ReorgDetected event");
        assert_eq!(reorg.reorg_from_height, 1525);
        assert_eq!(reorg.new_height, 1525);
        assert!(events.iter().any(|e| matches!(
            e,
            ProcessingEvent::ScanStatus(ScanStatusEvent::Completed { final_height: 1560, .. })
        )));

        let conn = setup.pool.get().expect("conn");
        let tips = get_scanned_tip_blocks_by_account(&conn, setup.account_id).expect("tips");
        for height in [1525, 1560] {
            let tip = tips.iter().find(|t| t.height == height).expect("scanned tip");
            assert_eq!(
                tip.hash,
                forked_block_hash(height),
                "block {height} is from the new chain"
            );
        }
    }

    #[tokio::test]
    async fn cancelling_a_scan_while_its_startup_reorg_check_hangs_stops_it() {
        let chain = MockChain::new(1505);
        chain.slow_headers.store(true, Ordering::SeqCst);
        let mut setup = setup_chain(1500, chain, 1_000).await;

        let token = CancellationToken::new();
        let scan = continuous_scan(&setup.coordinator, &setup.pool, &token);
        let cancel = cancel_once_requested(&setup.server, "/get_header_by_height", 0, &token);
        let (result, cancelled_at) =
            tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(scan, cancel) })
                .await
                .expect("the scan stops when cancelled");
        let (_, more_blocks) = result.expect("a cancelled scan is not an error");
        assert!(more_blocks);
        assert!(
            cancelled_at.elapsed() < Duration::from_secs(2),
            "cancelling must not wait for the startup reorg check"
        );
        // The account is reported at the last block stored for it.
        let events = drain(&mut setup.events);
        assert!(events.iter().any(|e| matches!(
            e,
            ProcessingEvent::ScanStatus(ScanStatusEvent::Cancelled {
                last_scanned_height: 1500,
                ..
            })
        )));
        assert_eq!(terminal_count(&events), 1);
    }

    fn first_reorg(events: &[ProcessingEvent]) -> &ReorgDetectedEvent {
        events
            .iter()
            .find_map(|e| match e {
                ProcessingEvent::ReorgDetected(reorg) => Some(reorg),
                _ => None,
            })
            .expect("a ReorgDetected event")
    }

    /// Asserts a scan of a chain with its tip at 1500 rolled every stored block
    /// back and rescanned from the birthday.
    fn assert_rescanned_from_birthday(setup: &Setup, events: &[ProcessingEvent]) {
        let reorg = first_reorg(events);
        assert_eq!(reorg.reorg_from_height, 0, "every stored block was reorged out");
        assert_eq!(reorg.new_height, BIRTHDAY_HEIGHT, "the scan resumes at the birthday");
        assert!(events.iter().any(|e| matches!(
            e,
            ProcessingEvent::ScanStatus(ScanStatusEvent::Completed { final_height: 1500, .. })
        )));
        let conn = setup.pool.get().expect("conn");
        let tips = get_scanned_tip_blocks_by_account(&conn, setup.account_id).expect("tips");
        assert!(
            tips.iter().all(|t| t.height >= BIRTHDAY_HEIGHT),
            "nothing below the birthday is scanned"
        );
        let birthday = tips
            .iter()
            .find(|t| t.height == BIRTHDAY_HEIGHT)
            .expect("birthday block");
        assert_eq!(birthday.hash, forked_block_hash(BIRTHDAY_HEIGHT));
    }

    #[tokio::test]
    async fn a_reorg_below_every_stored_block_mid_pass_rescans_from_the_birthday() {
        let mut chain = MockChain::new(1500);
        chain.fork_on_header = Some((1490, 0));
        let mut setup = setup_chain(1480, chain, 10).await;

        setup
            .coordinator
            .run(vec![account(&setup.pool)], "password", ScanMode::Full, 0, None)
            .await
            .expect("the scan survives the reorg");
        let events = drain(&mut setup.events);
        assert_rescanned_from_birthday(&setup, &events);
    }

    #[tokio::test]
    async fn a_reorg_below_every_stored_block_at_startup_rescans_from_the_birthday() {
        let chain = MockChain::new(1500);
        chain.fork_from.store(0, Ordering::SeqCst);
        let mut setup = setup_chain(1480, chain, 1_000).await;

        setup
            .coordinator
            .run(vec![account(&setup.pool)], "password", ScanMode::Full, 0, None)
            .await
            .expect("scan");
        let events = drain(&mut setup.events);
        assert_rescanned_from_birthday(&setup, &events);
    }

    /// Runs a full scan that rolls back every stored block, with the birthday
    /// lookup failing, and checks the reorg is still reported.
    async fn assert_reorg_reported_when_the_birthday_lookup_fails(mut chain: MockChain, reorg_check_interval: u64) {
        chain.fail_birthday = true;
        assert_reorg_reported_when_no_resume_height_is_found(chain, 1480, reorg_check_interval).await;
    }

    async fn assert_reorg_reported_when_no_resume_height_is_found(
        chain: MockChain,
        scanned_to: u64,
        reorg_check_interval: u64,
    ) {
        let mut setup = setup_chain(scanned_to, chain, reorg_check_interval).await;

        let result = setup
            .coordinator
            .run(vec![account(&setup.pool)], "password", ScanMode::Full, 0, None)
            .await;
        assert!(result.is_err(), "the scan stops without a resume height");

        let events = drain(&mut setup.events);
        let reorg = first_reorg(&events);
        assert_eq!(reorg.reorg_from_height, 0);
        assert_eq!(reorg.new_height, 0, "no resume height was chosen");
    }

    #[tokio::test]
    async fn a_reorg_below_every_stored_block_at_startup_is_reported_when_the_birthday_lookup_fails() {
        let chain = MockChain::new(1500);
        chain.fork_from.store(0, Ordering::SeqCst);
        assert_reorg_reported_when_the_birthday_lookup_fails(chain, 1_000).await;
    }

    #[tokio::test]
    async fn a_reorg_below_every_stored_block_mid_pass_is_reported_when_the_birthday_lookup_fails() {
        let mut chain = MockChain::new(1500);
        chain.fork_on_header = Some((1490, 0));
        assert_reorg_reported_when_the_birthday_lookup_fails(chain, 10).await;
    }

    #[tokio::test]
    async fn a_birthday_above_the_tip_after_a_reorg_below_every_stored_block_fails_closed() {
        let chain = MockChain::new(BIRTHDAY_HEIGHT - 10);
        chain.fork_from.store(0, Ordering::SeqCst);
        assert_reorg_reported_when_no_resume_height_is_found(chain, BIRTHDAY_HEIGHT - 20, 1_000).await;
    }

    #[tokio::test]
    async fn cancelling_while_the_birthday_lookup_after_a_full_rollback_hangs_still_reports_the_reorg() {
        let chain = MockChain::new(1500);
        chain.fork_from.store(0, Ordering::SeqCst);
        chain.slow_birthday.store(true, Ordering::SeqCst);
        let mut setup = setup_chain(1480, chain, 1_000).await;

        let token = CancellationToken::new();
        let scan = continuous_scan(&setup.coordinator, &setup.pool, &token);
        let cancel = cancel_once_requested(&setup.server, "/get_height_at_time", 0, &token);
        let (result, cancelled_at) =
            tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(scan, cancel) })
                .await
                .expect("the scan stops when cancelled");
        let (_, more_blocks) = result.expect("a cancelled scan is not an error");
        assert!(more_blocks);
        assert!(
            cancelled_at.elapsed() < Duration::from_secs(2),
            "cancelling must not wait for the birthday lookup"
        );
        let events = drain(&mut setup.events);
        let reorg = first_reorg(&events);
        assert_eq!(reorg.reorg_from_height, 0);
        assert_eq!(reorg.new_height, 0, "no resume height was chosen");
    }

    #[tokio::test]
    async fn a_node_reporting_a_reorg_at_every_check_stops_the_scan_with_an_error() {
        let mut chain = MockChain::new(1500);
        chain.refork_from = Some(1485);
        let mut setup = setup_chain(1480, chain, 10).await;

        let result = tokio::time::timeout(
            Duration::from_secs(30),
            setup
                .coordinator
                .run(vec![account(&setup.pool)], "password", ScanMode::Full, 0, None),
        )
        .await
        .expect("the scan does not rescan forever");
        assert!(matches!(result, Err(ScanError::Intermittent(_))), "{result:?}");
        let reorgs = drain(&mut setup.events)
            .iter()
            .filter(|e| matches!(e, ProcessingEvent::ReorgDetected(_)))
            .count();
        assert_eq!(reorgs, MAX_REWINDS_WITHOUT_PROGRESS as usize + 2);
    }
}
