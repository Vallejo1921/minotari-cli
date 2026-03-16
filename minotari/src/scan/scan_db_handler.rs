use crate::{
    ScanError, WalletEvent,
    db::{SqlitePool, WalletDbError, prune_scanned_tip_blocks},
    scan::{EventSender, block_processor::BlockProcessor},
    webhooks::WebhookTriggerConfig,
};
use log::{debug, error};
use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::TransactionBehavior;
use std::sync::Arc;

pub struct ScanDbHandler<E: EventSender + Clone + Send + 'static> {
    pool: SqlitePool,
    block_processor: Option<BlockProcessor<E>>,
}

impl<E: EventSender + Clone + Send + 'static> ScanDbHandler<E> {
    pub fn new(pool: SqlitePool, block_processor: BlockProcessor<E>) -> Self {
        Self {
            pool,
            block_processor: Some(block_processor),
        }
    }

    pub async fn get_connection(&self) -> Result<PooledConnection<SqliteConnectionManager>, ScanError> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || pool.get().map_err(WalletDbError::from))
            .await
            .map_err(|e| {
                let err = anyhow::anyhow!("DB connection task failed: {}", e);
                error!("DB connection task failed: {}", e);
                ScanError::Fatal(err)
            })?
            .map_err(ScanError::DbError)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn process_blocks(
        &mut self,
        blocks: Arc<Vec<lightweight_wallet_libs::BlockScanResult>>,
        target_account_id: i64,
        has_pending_outbound: bool,
        webhook_config: Option<WebhookTriggerConfig>,
        next_block_to_scan: u64,
    ) -> Result<Vec<WalletEvent>, ScanError> {
        if blocks.is_empty() {
            return Ok(Vec::new());
        }

        debug!(
            count = blocks.len(),
            account_id = target_account_id;
            "Processing scanned blocks in DB task"
        );

        let pool = self.pool.clone();
        let mut block_processor = self
            .block_processor
            .take()
            .ok_or_else(|| ScanError::Fatal(anyhow::anyhow!("BlockProcessor not initialized")))?;

        block_processor.set_has_pending_outbound(has_pending_outbound);
        block_processor.set_webhook_config(webhook_config);

        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(WalletDbError::from)?;

            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(WalletDbError::from)?;
            let mut processor = block_processor;

            for block in blocks.iter() {
                if block.height < next_block_to_scan {
                    continue;
                }

                processor
                    .process_block(&tx, block, target_account_id)
                    .map_err(|e| WalletDbError::Unexpected(e.to_string()))?;
            }

            let events = processor.take_wallet_events();
            tx.commit().map_err(WalletDbError::from)?;

            Ok::<(Vec<WalletEvent>, BlockProcessor<E>), WalletDbError>((events, processor))
        })
        .await
        .map_err(|e| {
            let err = anyhow::anyhow!("Block processing task failed: {}", e);
            error!("Block processing task failed: {}", e);
            ScanError::Fatal(err)
        })?
        .map_err(ScanError::from)
        .map(|(events, processor)| {
            self.block_processor = Some(processor);
            events
        })
    }

    pub async fn prune_tips(&self, account_id: i64, height: u64) -> Result<(), ScanError> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool.get().map_err(WalletDbError::from)?;
            prune_scanned_tip_blocks(&conn, account_id, height)
        })
        .await
        .map_err(|e| {
            let err = anyhow::anyhow!("Pruning task failed: {}", e);
            error!("Pruning task failed: {}", e);
            ScanError::Fatal(err)
        })?
        .map_err(ScanError::DbError)
    }
}
