use log::{debug, warn};
use rusqlite::{Connection, named_params};
use serde::Deserialize;
use serde_rusqlite::from_rows;

use crate::db::error::WalletDbResult;
use crate::models::ScannedTipBlock;

const RECENT_BLOCKS_TO_KEEP: u64 = 1000;
const OLD_BLOCKS_PRUNING_INTERVAL: u64 = 500;

#[derive(Deserialize)]
struct ScannedTipBlockRow {
    pub id: i64,
    pub account_id: i64,
    pub height: i64,
    pub hash: Vec<u8>,
}

#[derive(Deserialize)]
struct ScannedTipBlockWithTimestampRow {
    pub height: i64,
    pub hash: Vec<u8>,
    pub created_at: String,
}

/// Information about the latest scanned block including timestamp.
#[derive(Debug, Clone)]
pub struct LatestScannedBlock {
    pub height: u64,
    pub hash: Vec<u8>,
    pub scanned_at: String,
}

pub fn get_scanned_tip_blocks_by_account(conn: &Connection, account_id: i64) -> WalletDbResult<Vec<ScannedTipBlock>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, account_id, height, hash
        FROM scanned_tip_blocks
        WHERE account_id = :account_id
        ORDER BY height DESC
        "#,
    )?;

    let rows = stmt.query(named_params! { ":account_id": account_id })?;
    let result = from_rows::<ScannedTipBlock>(rows).collect::<Result<Vec<_>, _>>()?;

    Ok(result)
}

pub fn get_latest_scanned_tip_block_by_account(
    conn: &Connection,
    account_id: i64,
) -> WalletDbResult<Option<ScannedTipBlock>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, account_id, height, hash
        FROM scanned_tip_blocks
        WHERE account_id = :account_id
        ORDER BY height DESC
        LIMIT 1
        "#,
    )?;

    let rows = stmt.query(named_params! { ":account_id": account_id })?;
    let row = from_rows::<ScannedTipBlockRow>(rows).next().transpose()?;

    Ok(row.map(|r| ScannedTipBlock {
        id: r.id,
        account_id: r.account_id,
        height: r.height as u64,
        hash: r.hash,
    }))
}

/// Retrieves the latest scanned block for an account including the timestamp.
///
/// # Parameters
///
/// * `conn` - Database connection
/// * `account_id` - The account to query
///
/// # Returns
///
/// The latest scanned block with height, hash, and timestamp, or None if no blocks scanned.
pub fn get_latest_scanned_block_with_timestamp(
    conn: &Connection,
    account_id: i64,
) -> WalletDbResult<Option<LatestScannedBlock>> {
    debug!(
        account_id = account_id;
        "DB: Get latest scanned block with timestamp"
    );

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT height, hash, created_at
        FROM scanned_tip_blocks
        WHERE account_id = :account_id
        ORDER BY height DESC
        LIMIT 1
        "#,
    )?;

    let rows = stmt.query(named_params! { ":account_id": account_id })?;
    let row = from_rows::<ScannedTipBlockWithTimestampRow>(rows).next().transpose()?;

    Ok(row.map(|r| LatestScannedBlock {
        height: r.height as u64,
        hash: r.hash,
        scanned_at: r.created_at,
    }))
}

pub fn insert_scanned_tip_block(conn: &Connection, account_id: i64, height: i64, hash: &[u8]) -> WalletDbResult<()> {
    debug!(
        account_id = account_id,
        height = height;
        "DB: Inserting scanned tip block"
    );

    conn.execute(
        r#"
        INSERT OR IGNORE INTO scanned_tip_blocks (account_id, height, hash)
        VALUES (:account_id, :height, :hash)
        "#,
        named_params! {
            ":account_id": account_id,
            ":height": height,
            ":hash": hash
        },
    )?;

    Ok(())
}

pub fn delete_scanned_tip_blocks_from_height(conn: &Connection, account_id: i64, height: u64) -> WalletDbResult<()> {
    warn!(
        target: "audit",
        account_id = account_id,
        height = height;
        "DB: Deleting scanned tip blocks (Reorg)"
    );

    let height = height as i64;
    conn.execute(
        r#"
        DELETE FROM scanned_tip_blocks
        WHERE account_id = :account_id AND height >= :height
        "#,
        named_params! {
            ":account_id": account_id,
            ":height": height
        },
    )?;

    Ok(())
}

pub fn prune_scanned_tip_blocks(conn: &Connection, account_id: i64, current_tip_height: u64) -> WalletDbResult<()> {
    debug!(
        account_id = account_id,
        tip = current_tip_height;
        "DB: Pruning scanned tip blocks"
    );

    // Keep the last RECENT_BLOCKS_TO_KEEP blocks
    let min_height_for_recent = current_tip_height.saturating_sub(RECENT_BLOCKS_TO_KEEP) as i64;
    let interval = OLD_BLOCKS_PRUNING_INTERVAL as i64;

    // Delete blocks older than min_height_for_recent that are not at the pruning interval
    conn.execute(
        r#"
        DELETE FROM scanned_tip_blocks
        WHERE account_id = :account_id
          AND height < :min_height
          AND height >= 0
          AND (height % :interval != 0)
        "#,
        named_params! {
            ":account_id": account_id,
            ":min_height": min_height_for_recent,
            ":interval": interval
        },
    )?;

    Ok(())
}
