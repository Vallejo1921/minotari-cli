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
        blocks: Arc<Vec<minotari_scanning::BlockScanResult>>,
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

            // Heights must arrive in an unbroken run starting at `next_block_to_scan`.
            // `block.height` is taken as the current chain tip for this account: it
            // decides which outputs have reached the confirmation depth, which
            // coinbases have matured, and which UTXOs the input selector will hand
            // out. A base node that answers with a block claiming a height far ahead
            // of the last one therefore ages every pending output to "confirmed and
            // mature" in one step, and the wallet goes on to spend funds that were
            // never confirmed. A skipped height is the mirror image: the outputs and
            // inputs in it are never recorded, so the balance is wrong and the reorg
            // check has no hash to compare that height against.
            //
            // A repeat of the previous height is legitimate and must be allowed: a
            // block with more outputs than the node's chunk size is split across
            // several `BlockScanResult`s that all carry the same height.
            let mut last_height: Option<u64> = None;

            for block in blocks.iter() {
                // The base node never truncates a block: it sends every chunk of a
                // block before checking the page limit. When a page fills up it
                // drops the last block whole and starts the next page at it; a
                // first block larger than a page is sent whole, over-filling the
                // page. So results behind the resume point are never the rest of
                // a block and are skipped.
                if block.height < next_block_to_scan {
                    continue;
                }

                let permitted = match last_height {
                    None => block.height == next_block_to_scan,
                    Some(last) => block.height == last || block.height == last.saturating_add(1),
                };
                if !permitted {
                    return Err(WalletDbError::Unexpected(format!(
                        "Base node returned a non-contiguous block batch for account {}: expected height {}, got {}",
                        target_account_id,
                        last_height.map_or(next_block_to_scan, |h| h.saturating_add(1)),
                        block.height
                    )));
                }
                last_height = Some(block.height);

                processor
                    .process_block(&tx, block, target_account_id)
                    .map_err(|e| WalletDbError::Unexpected(e.to_string()))?;
            }

            // Match the wallet's sends in the last block of the batch. The node
            // sends blocks whole (see above), so that block is complete; still,
            // defensively, a mismatch there does not reject a send until the
            // scan has moved past the block.
            processor
                .match_sends(&tx, false)
                .map_err(|e| WalletDbError::Unexpected(e.to_string()))?;

            // Blocks below the last one of this batch have been moved past, so
            // they are complete: decide the sends whose inputs were spent there
            // that an earlier batch's last block left undecided.
            if let Some(last) = last_height {
                processor
                    .settle_sends_in_passed_blocks(&tx, target_account_id, last)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{create_account, get_account_by_name, init_db};
    use crate::scan::events::NoopEventSender;
    use minotari_scanning::BlockScanResult;
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_common_types::types::FixedHash;
    use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
    use tari_transaction_components::key_manager::{KeyManager, TransactionKeyManagerInterface};
    use tempfile::TempDir;

    fn block(height: u64) -> BlockScanResult {
        BlockScanResult {
            height,
            #[allow(clippy::cast_possible_truncation)]
            block_hash: FixedHash::from([height as u8; 32]),
            wallet_outputs: Vec::new(),
            inputs: Vec::new(),
            mined_timestamp: 1_700_000_000,
        }
    }

    fn handler(name: &str) -> (ScanDbHandler<NoopEventSender>, i64, TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let pool = init_db(dir.path().join(name)).expect("init db");
        let conn = pool.get().expect("conn");

        let seeds = CipherSeed::random();
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(seeds).unwrap());
        create_account(&conn, "default", &wallet, "password").unwrap();
        let account = get_account_by_name(&conn, "default").unwrap().unwrap();
        let view_key = KeyManager::new(wallet).unwrap().get_private_view_key();
        drop(conn);

        let processor = BlockProcessor::with_event_sender(vec![(account.id, view_key)], NoopEventSender, false, 3);
        (ScanDbHandler::new(pool, processor), account.id, dir)
    }

    #[tokio::test]
    async fn a_batch_that_skips_ahead_is_refused() {
        // `block.height` is treated as the chain tip: it drives confirmation depth and
        // coinbase maturity. A node that jumps the height forward would age every
        // pending output to "confirmed and mature" in one step, and the wallet would
        // then spend outputs that were never confirmed.
        let (mut handler, account_id, _dir) = handler("gap.db");

        let blocks = Arc::new(vec![block(100), block(1_000_000)]);
        let err = handler
            .process_blocks(blocks, account_id, false, None, 100)
            .await
            .expect_err("a height gap must abort the batch");
        assert!(
            err.to_string().contains("non-contiguous"),
            "the error should name the cause, got: {err}"
        );
    }

    #[tokio::test]
    async fn a_batch_that_does_not_start_where_the_scan_resumes_is_refused() {
        let (mut handler, account_id, _dir) = handler("start.db");

        let blocks = Arc::new(vec![block(105), block(106)]);
        let err = handler
            .process_blocks(blocks, account_id, false, None, 100)
            .await
            .expect_err("a batch starting past the resume height must abort");
        assert!(err.to_string().contains("non-contiguous"), "got: {err}");
    }

    #[tokio::test]
    async fn a_contiguous_batch_is_processed_including_repeated_heights() {
        // A block with more outputs than the node's chunk size arrives as several
        // results carrying the same height, so repeats are legitimate.
        let (mut handler, account_id, _dir) = handler("ok.db");

        let blocks = Arc::new(vec![block(100), block(100), block(101), block(102)]);
        handler
            .process_blocks(blocks, account_id, false, None, 100)
            .await
            .expect("a contiguous batch is accepted");

        // Blocks already behind the resume point are skipped, not rejected.
        let blocks = Arc::new(vec![block(99), block(103)]);
        handler
            .process_blocks(blocks, account_id, false, None, 103)
            .await
            .expect("already-scanned blocks are skipped");
    }
}
