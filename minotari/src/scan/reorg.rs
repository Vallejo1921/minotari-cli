use crate::{
    db::{self, get_active_outputs_from_height},
    models::{PendingTransactionStatus, WalletEvent, WalletEventType},
    transactions::DisplayedTransaction,
    webhooks::{WebhookTriggerConfig, utils::trigger_webhook_with_balance},
};
use anyhow::anyhow;
use log::{debug, info, warn};
use minotari_scanning::{HttpBlockchainScanner, scanning::BlockchainScanner};
use rusqlite::Connection;
use std::collections::HashSet;
use tari_common_types::types::FixedHash;
use tari_transaction_components::key_manager::KeyManager;
use tari_transaction_components::transaction_components::Transaction;

/// Result of a reorg check operation.
#[derive(Debug, Clone)]
pub struct ReorgResult {
    pub resume_height: u64,
    pub reorg_information: Option<ReorgInformation>,
}

/// Details about a detected reorg.
#[derive(Debug, Clone)]
pub struct ReorgInformation {
    pub rolled_back_from_height: u64,
    pub rolled_back_blocks_count: u64,
    pub invalidated_output_hashes: Vec<FixedHash>,
    pub cancelled_transaction_ids: Vec<String>,
    pub reorganized_displayed_transactions: Vec<DisplayedTransaction>,
}

pub async fn handle_reorgs(
    scanner: &mut HttpBlockchainScanner<KeyManager>,
    conn: &mut Connection,
    account_id: i64,
    webhook_config: Option<WebhookTriggerConfig>,
) -> Result<ReorgResult, anyhow::Error> {
    let last_blocks = db::get_scanned_tip_blocks_by_account(conn, account_id)?;

    if last_blocks.is_empty() {
        return Ok(ReorgResult {
            resume_height: 0,
            reorg_information: None,
        });
    }
    let mut reorg_start_height = 0;
    let mut is_reorg_detected = false;

    for block in &last_blocks {
        let chain_block = scanner
            .get_header_by_height(block.height)
            .await
            .map_err(|e| anyhow!("Failed to get header by height: {}", e))?;

        if let Some(chain_block) = chain_block {
            if chain_block.hash == block.hash {
                // Found the fork point. All blocks after this height are reorged.
                reorg_start_height = block
                    .height
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("Block height {} has no next block height", block.height))?;
                break;
            } else {
                // This block is reorged.
                is_reorg_detected = true;
            }
        } else {
            // Block no longer exists on chain, it's reorged.
            is_reorg_detected = true;
        }
    }
    if is_reorg_detected {
        warn!(
            target: "audit",
            account_id = account_id,
            rollback_height = reorg_start_height;
            "REORG DETECTED. Rolling back chain state."
        );
        // BEGIN IMMEDIATE: the rollback reads the rows it is about to rewrite, so a
        // deferred transaction would start as a reader and then try to upgrade to a
        // writer. In WAL mode that upgrade fails with SQLITE_BUSY_SNAPSHOT if another
        // connection committed in the meantime — an error `busy_timeout` never retries,
        // surfacing as "database is locked" and aborting the reorg recovery halfway
        // through the scan loop. Taking the write lock up front makes the rollback
        // wait for its turn instead.
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let reorg_info = rollback_from_height(&tx, account_id, reorg_start_height, webhook_config)?;
        tx.commit()?;
        Ok(ReorgResult {
            resume_height: reorg_start_height,
            reorg_information: Some(reorg_info),
        })
    } else {
        debug!("No reorgs detected.");
        let tip_height = last_blocks.first().expect("is already checked").height;
        let resume_height = tip_height
            .checked_add(1)
            .ok_or_else(|| anyhow!("Block height {tip_height} has no next block height"))?;
        Ok(ReorgResult {
            resume_height,
            reorg_information: None,
        })
    }
}

pub fn rollback_from_height(
    tx: &Connection,
    account_id: i64,
    reorg_start_height: u64,
    webhook_config: Option<WebhookTriggerConfig>,
) -> Result<ReorgInformation, anyhow::Error> {
    let mut generated_events: Vec<(i64, WalletEvent)> = Vec::new();

    // 1. Log BlockRolledBack events
    let rolled_back_blocks = db::get_scanned_tip_blocks_by_account(tx, account_id)?
        .into_iter()
        .filter(|b| b.height >= reorg_start_height)
        .collect::<Vec<_>>();

    let blocks_rolled_back = rolled_back_blocks.len() as u64;

    for block in rolled_back_blocks {
        let event = WalletEvent {
            id: 0,
            account_id,
            event_type: WalletEventType::BlockRolledBack {
                height: block.height,
                block_hash: block.hash,
            },
            description: format!("Block at height {} was rolled back due to reorg", block.height),
        };
        let event_id = db::insert_wallet_event(tx, account_id, &event)?;
        generated_events.push((event_id, event));
    }

    // 2. Get outputs that will be affected to log OutputRolledBack events
    let affected_outputs = get_active_outputs_from_height(tx, account_id, reorg_start_height)?;

    let mut cancelled_pending_tx_ids = HashSet::new();
    let mut invalidated_output_hashes = Vec::new();

    for output_row in &affected_outputs {
        let output_hash = FixedHash::try_from(output_row.output_hash.as_slice())?;
        invalidated_output_hashes.push(output_hash);

        let event = WalletEvent {
            id: 0,
            account_id,
            event_type: WalletEventType::OutputRolledBack {
                hash: output_hash,
                original_block_height: output_row.mined_in_block_height as u64,
                rolled_back_at_height: reorg_start_height,
            },
            description: format!(
                "Output {:x?} at height {} was rolled back due to reorg",
                output_row.output_hash, output_row.mined_in_block_height
            ),
        };
        let event_id = db::insert_wallet_event(tx, account_id, &event)?;
        generated_events.push((event_id, event));

        if let Some(request_id) = &output_row.locked_by_request_id {
            cancelled_pending_tx_ids.insert(request_id.clone());
        }
    }

    // A send's change output is not soft-deleted with the other outputs: it goes
    // back to `UNCONFIRMED`, because the send is reverted and rebroadcast below
    // and the scan recognises it by this row. It is still reported as rolled back.
    let reverted_change_outputs = db::revert_change_outputs_from_height(tx, account_id, reorg_start_height)?;
    for output_row in &reverted_change_outputs {
        let output_hash = FixedHash::try_from(output_row.output_hash.as_slice())?;
        invalidated_output_hashes.push(output_hash);

        let event = WalletEvent {
            id: 0,
            account_id,
            event_type: WalletEventType::OutputRolledBack {
                hash: output_hash,
                original_block_height: output_row.mined_in_block_height as u64,
                rolled_back_at_height: reorg_start_height,
            },
            description: format!(
                "Output {:x?} at height {} was rolled back due to reorg",
                output_row.output_hash, output_row.mined_in_block_height
            ),
        };
        let event_id = db::insert_wallet_event(tx, account_id, &event)?;
        generated_events.push((event_id, event));
    }

    // 3. Cancel pending transactions linked to reorged outputs
    let cancelled_transaction_ids: Vec<String> = cancelled_pending_tx_ids.into_iter().collect();
    if !cancelled_transaction_ids.is_empty() {
        db::cancel_pending_transactions_by_ids(tx, &cancelled_transaction_ids, PendingTransactionStatus::Cancelled)?;

        for tx_id in &cancelled_transaction_ids {
            let event = WalletEvent {
                id: 0,
                account_id,
                event_type: WalletEventType::PendingTransactionCancelled {
                    tx_id: tx_id.clone(),
                    reason: "Transaction cancelled due to blockchain reorg".to_string(),
                },
                description: format!("Pending transaction {} cancelled due to reorg", tx_id),
            };
            let event_id = db::insert_wallet_event(tx, account_id, &event)?;
            generated_events.push((event_id, event));
        }
    }

    // 4. Soft delete dependent data and create reversal balance changes
    db::soft_delete_inputs_from_height(tx, account_id, reorg_start_height)?;
    db::soft_delete_outputs_from_height(tx, account_id, reorg_start_height)?;
    db::delete_scanned_tip_blocks_from_height(tx, account_id, reorg_start_height)?;

    // Save displayed transaction payrefs to history before they get overwritten on re-mine
    let saved_displayed_payrefs =
        db::save_displayed_transaction_payrefs_before_reorg(tx, account_id, reorg_start_height)?;
    if saved_displayed_payrefs > 0 {
        info!(
            target: "audit",
            count = saved_displayed_payrefs;
            "Saved displayed transaction payref(s) to history before reorg"
        );
    }

    let mut reorganized_displayed_transactions =
        db::mark_displayed_transactions_reorganized_and_return(tx, account_id, reorg_start_height)?;

    // Save old payrefs to history before they are cleared by the reset
    let saved_payrefs = db::save_completed_transaction_payrefs_before_reorg(tx, account_id, reorg_start_height)?;
    if saved_payrefs > 0 {
        info!(
            target: "audit",
            count = saved_payrefs;
            "Saved payref(s) to history before reorg reset"
        );
    }

    // Sends the scan rejected (inputs spent by a different transaction) in a
    // rolled-back block are revived, if their inputs can be theirs again: the
    // inputs are locked to the send again, the change goes back to
    // `UNCONFIRMED` and the displayed transaction to an unmined `Pending` (so
    // the scan matches it when the send is mined rather than adding a second
    // entry; it replaces any copy already reported as reorganized), the reset
    // below makes the send `Completed` to be rebroadcast, and a
    // `TransactionReorged` event is emitted. A send whose inputs are now locked
    // by another send or spent in a block still on the chain stays `Rejected`.
    let scan_rejected = db::get_scan_rejected_pending_tx_ids_from_height(tx, account_id, reorg_start_height)?;
    for (pending_tx_id, completed_tx_id) in &scan_rejected {
        let Some(completed) = db::get_completed_transaction_by_id(tx, *completed_tx_id)? else {
            continue;
        };
        let input_hashes: Option<Vec<FixedHash>> =
            serde_json::from_slice::<Transaction>(&completed.serialized_transaction)
                .ok()
                .map(|t| t.body().inputs().iter().map(|i| i.output_hash()).collect());
        let revived = match &input_hashes {
            Some(input_hashes) => db::relock_inputs_for_revived_send(tx, account_id, pending_tx_id, input_hashes)?,
            None => false,
        };
        if !revived {
            warn!(
                target: "audit",
                id = completed_tx_id.to_string().as_str();
                "Reorg removed the block a send was rejected in, but its inputs are no longer its own; keeping it rejected"
            );
            db::keep_rejected_after_reorg(
                tx,
                *completed_tx_id,
                "inputs spent by a different transaction (still, after reorg)",
            )?;
            // Its displayed transaction may have just been marked reorganized
            // with its block; it is still rejected.
            if let Some(displayed) = db::mark_displayed_transaction_rejected(tx, *completed_tx_id)? {
                reorganized_displayed_transactions.retain(|d| d.id != displayed.id);
                reorganized_displayed_transactions.push(displayed);
            }
            continue;
        }

        db::revert_rejected_change_output(tx, pending_tx_id)?;
        if let Some(displayed) = db::reset_displayed_transaction_to_pending(tx, *completed_tx_id)? {
            reorganized_displayed_transactions.retain(|d| d.id != displayed.id);
            reorganized_displayed_transactions.push(displayed);
        }

        #[allow(clippy::cast_sign_loss)]
        let original_mined_height = completed.mined_height.unwrap_or(0) as u64;
        let event = WalletEvent {
            id: 0,
            account_id,
            event_type: WalletEventType::TransactionReorged {
                tx_id: *completed_tx_id,
                original_mined_height,
            },
            description: format!(
                "Transaction {} is no longer rejected: the block at height {} it was rejected in was rolled back",
                completed_tx_id, original_mined_height
            ),
        };
        let event_id = db::insert_wallet_event(tx, account_id, &event)?;
        generated_events.push((event_id, event));
    }

    let affected_count = db::reset_mined_completed_transactions_from_height(tx, account_id, reorg_start_height)?;
    if affected_count > 0 {
        info!(
            target: "audit",
            count = affected_count;
            "Reset completed transaction(s) to Completed status due to reorg"
        );
    }

    if let Some(config) = webhook_config {
        for (event_id, event) in generated_events {
            trigger_webhook_with_balance(tx, account_id, event_id, &event, &config)?;
        }
    }

    Ok(ReorgInformation {
        rolled_back_from_height: reorg_start_height,
        rolled_back_blocks_count: blocks_rolled_back,
        invalidated_output_hashes,
        cancelled_transaction_ids,
        reorganized_displayed_transactions,
    })
}
