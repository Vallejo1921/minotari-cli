use std::fmt;
use std::str::FromStr;

use crate::db::error::WalletDbResult;
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use rusqlite::{Connection, OptionalExtension, Row, named_params};
use tari_common_types::transaction::TxId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletedTransactionStatus {
    Completed,
    Broadcast,
    MinedUnconfirmed,
    MinedConfirmed,
    Rejected,
    Canceled,
}

impl fmt::Display for CompletedTransactionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompletedTransactionStatus::Completed => write!(f, "completed"),
            CompletedTransactionStatus::Broadcast => write!(f, "broadcast"),
            CompletedTransactionStatus::MinedUnconfirmed => write!(f, "mined_unconfirmed"),
            CompletedTransactionStatus::MinedConfirmed => write!(f, "mined_confirmed"),
            CompletedTransactionStatus::Rejected => write!(f, "rejected"),
            CompletedTransactionStatus::Canceled => write!(f, "canceled"),
        }
    }
}

impl FromStr for CompletedTransactionStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "completed" => Ok(CompletedTransactionStatus::Completed),
            "broadcast" => Ok(CompletedTransactionStatus::Broadcast),
            "mined_unconfirmed" => Ok(CompletedTransactionStatus::MinedUnconfirmed),
            "mined_confirmed" => Ok(CompletedTransactionStatus::MinedConfirmed),
            "rejected" => Ok(CompletedTransactionStatus::Rejected),
            "canceled" => Ok(CompletedTransactionStatus::Canceled),
            _ => Err(format!("Unknown status: {}", s)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompletedTransaction {
    pub id: TxId,
    pub pending_tx_id: String,
    pub account_id: i64,
    pub status: CompletedTransactionStatus,
    pub last_rejected_reason: Option<String>,
    pub kernel_excess: Vec<u8>,
    pub sent_payref: Option<String>,
    pub sent_output_hash: Option<String>,
    pub mined_height: Option<i64>,
    pub mined_block_hash: Option<Vec<u8>>,
    pub confirmation_height: Option<i64>,
    pub broadcast_attempts: i32,
    pub serialized_transaction: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn map_row(row: &Row) -> Result<CompletedTransaction, rusqlite::Error> {
    let status_str: String = row.get("status")?;
    let status =
        CompletedTransactionStatus::from_str(&status_str).map_err(|_| rusqlite::Error::ExecuteReturnedResults)?;
    let id: i64 = row.get("id")?;
    Ok(CompletedTransaction {
        id: TxId::from(id as u64),
        account_id: row.get("account_id")?,
        pending_tx_id: row.get("pending_tx_id")?,
        status,
        last_rejected_reason: row.get("last_rejected_reason")?,
        kernel_excess: row.get("kernel_excess")?,
        sent_payref: row.get("sent_payref")?,
        sent_output_hash: row.get("sent_output_hash")?,
        mined_height: row.get("mined_height")?,
        mined_block_hash: row.get("mined_block_hash")?,
        confirmation_height: row.get("confirmation_height")?,
        broadcast_attempts: row.get("broadcast_attempts")?,
        serialized_transaction: row.get("serialized_transaction")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

pub fn create_completed_transaction(
    conn: &Connection,
    account_id: i64,
    pending_tx_id: &str,
    kernel_excess: &[u8],
    serialized_transaction: &[u8],
    sent_output_hash: Option<String>,
    tx_id: TxId,
) -> WalletDbResult<()> {
    debug!(
        account_id = account_id,
        pending_id = pending_tx_id;
        "DB: Creating completed transaction"
    );

    let id = tx_id.as_i64_wrapped();
    let status_str = CompletedTransactionStatus::Completed.to_string();

    conn.execute(
        r#"
        INSERT INTO completed_transactions (
            id,
            account_id,
            pending_tx_id,
            status,
            kernel_excess,
            serialized_transaction,
            sent_output_hash
        )
        VALUES (
            :id,
            :account_id,
            :pending_id,
            :status,
            :kernel_excess,
            :serialized_tx,
            :sent_hash
        )
        "#,
        named_params! {
            ":id": tx_id.as_i64_wrapped(),
            ":account_id": account_id,
            ":pending_id": pending_tx_id,
            ":status": status_str,
            ":kernel_excess": kernel_excess,
            ":serialized_tx": serialized_transaction,
            ":sent_hash": sent_output_hash
        },
    )?;

    info!(
        target: "audit",
        id = id.to_string().as_str(),
        account_id = account_id,
        pending_id = pending_tx_id;
        "DB: Transaction Completed"
    );

    Ok(())
}

pub fn get_completed_transaction_by_id(conn: &Connection, tx_id: TxId) -> WalletDbResult<Option<CompletedTransaction>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, account_id, pending_tx_id, status, last_rejected_reason, kernel_excess, 
               sent_payref, sent_output_hash, mined_height, mined_block_hash, confirmation_height, 
               broadcast_attempts, serialized_transaction, created_at, updated_at
        FROM completed_transactions
        WHERE id = :id
        "#,
    )?;

    let result = stmt
        .query_row(named_params! { ":id": tx_id.as_i64_wrapped() }, map_row)
        .optional()?;

    Ok(result)
}

/// The send recorded for `pending_tx_id` that the block scan may still find
/// mined, if any: `Completed`, `Broadcast`, or `Rejected` by the monitor (no
/// `mined_height`; the node may still have mined it).
///
/// Used by the block scan to recognise one of the wallet's own sends when its
/// inputs are spent in a block. A send the scan itself rejected has a
/// `mined_height` and is not returned.
pub fn get_completed_transaction_to_match(
    conn: &Connection,
    account_id: i64,
    pending_tx_id: &str,
) -> WalletDbResult<Option<CompletedTransaction>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, account_id, pending_tx_id, status, last_rejected_reason, kernel_excess,
               sent_payref, sent_output_hash, mined_height, mined_block_hash, confirmation_height,
               broadcast_attempts, serialized_transaction, created_at, updated_at
        FROM completed_transactions
        WHERE account_id = :account_id
          AND pending_tx_id = :pending_tx_id
          AND (status IN (:completed, :broadcast) OR (status = :rejected AND mined_height IS NULL))
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )?;

    let result = stmt
        .query_row(
            named_params! {
                ":account_id": account_id,
                ":pending_tx_id": pending_tx_id,
                ":completed": CompletedTransactionStatus::Completed.to_string(),
                ":broadcast": CompletedTransactionStatus::Broadcast.to_string(),
                ":rejected": CompletedTransactionStatus::Rejected.to_string(),
            },
            map_row,
        )
        .optional()?;

    Ok(result)
}

pub fn get_completed_transactions_by_status(
    conn: &Connection,
    account_id: i64,
    status: CompletedTransactionStatus,
) -> WalletDbResult<Vec<CompletedTransaction>> {
    let status_str = status.to_string();

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, account_id, pending_tx_id, status, last_rejected_reason, kernel_excess, 
               sent_payref, sent_output_hash, mined_height, mined_block_hash, confirmation_height, 
               broadcast_attempts, serialized_transaction, created_at, updated_at
        FROM completed_transactions
        WHERE account_id = :account_id AND status = :status
        "#,
    )?;

    let rows = stmt.query_map(
        named_params! {
            ":account_id": account_id,
            ":status": status_str
        },
        map_row,
    )?;

    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn update_completed_transaction_status(
    conn: &Connection,
    tx_id: TxId,
    status: CompletedTransactionStatus,
) -> WalletDbResult<()> {
    debug!(
        id = tx_id.to_string().as_str(),
        status:% = status;
        "DB: Updating completed tx status"
    );

    let status_str = status.to_string();
    let now = Utc::now();

    conn.execute(
        r#"
        UPDATE completed_transactions
        SET status = :status, updated_at = :now
        WHERE id = :id
        "#,
        named_params! {
            ":status": status_str,
            ":now": now,
            ":id": tx_id.as_i64_wrapped()
        },
    )?;

    Ok(())
}

/// Marks a send `Broadcast` (the node accepted it).
///
/// `attempts` is the send's `broadcast_attempts`: the number of broadcasts in a
/// row the node did not accept, so an accepted broadcast passes 0.
pub fn mark_completed_transaction_as_broadcasted(conn: &Connection, tx_id: TxId, attempts: i32) -> WalletDbResult<()> {
    let id = tx_id.to_string();
    info!(
        target: "audit",
        id = id.as_str(),
        attempts = attempts;
        "DB: Marking completed tx as broadcasted"
    );

    let status = CompletedTransactionStatus::Broadcast.to_string();
    let now = Utc::now();

    conn.execute(
        r#"
        UPDATE completed_transactions
        SET status = :status, broadcast_attempts = :attempts, last_broadcast_error = NULL, updated_at = :now
        WHERE id = :id
        "#,
        named_params! {
            ":status": status,
            ":attempts": attempts,
            ":now": now,
            ":id": tx_id.as_i64_wrapped()
        },
    )?;

    Ok(())
}

pub fn mark_completed_transaction_as_mined_unconfirmed(
    conn: &Connection,
    tx_id: TxId,
    block_height: i64,
    block_hash: &[u8],
) -> WalletDbResult<()> {
    let id = tx_id.to_string();
    info!(
        target: "audit",
        id = id.as_str(),
        height = block_height;
        "DB: Transaction Mined (Unconfirmed)"
    );

    let status = CompletedTransactionStatus::MinedUnconfirmed.to_string();
    let now = Utc::now();

    conn.execute(
        r#"
        UPDATE completed_transactions
        SET status = :status, mined_height = :height, mined_block_hash = :hash, last_rejected_reason = NULL,
            updated_at = :now
        WHERE id = :id
        "#,
        named_params! {
            ":status": status,
            ":height": block_height,
            ":hash": block_hash,
            ":now": now,
            ":id": tx_id.as_i64_wrapped()
        },
    )?;

    Ok(())
}

/// Counts a broadcast attempt the node did not accept this time (fee too low,
/// orphan, time-locked, ...), leaving the send's status as it is, and keeps the
/// node's answer (`reason`, already sanitised) as `last_broadcast_error`.
pub fn record_failed_broadcast_attempt(
    conn: &Connection,
    tx_id: TxId,
    attempts: i32,
    reason: &str,
) -> WalletDbResult<()> {
    conn.execute(
        r#"
        UPDATE completed_transactions
        SET broadcast_attempts = :attempts, last_broadcast_error = :reason, updated_at = :now
        WHERE id = :id
        "#,
        named_params! {
            ":attempts": attempts,
            ":reason": reason,
            ":now": Utc::now(),
            ":id": tx_id.as_i64_wrapped()
        },
    )?;
    Ok(())
}

/// Keeps why a broadcast got no answer (`reason`, already sanitised) as
/// `last_broadcast_error`, without counting it as an attempt.
pub fn record_last_broadcast_error(conn: &Connection, tx_id: TxId, reason: &str) -> WalletDbResult<()> {
    conn.execute(
        r#"
        UPDATE completed_transactions
        SET last_broadcast_error = :reason, updated_at = :now
        WHERE id = :id
        "#,
        named_params! {
            ":reason": reason,
            ":now": Utc::now(),
            ":id": tx_id.as_i64_wrapped()
        },
    )?;
    Ok(())
}

/// The node's answer to the send's last broadcast it did not accept, if any.
pub fn get_last_broadcast_error(conn: &Connection, tx_id: TxId) -> WalletDbResult<Option<String>> {
    let reason: Option<Option<String>> = conn
        .query_row(
            "SELECT last_broadcast_error FROM completed_transactions WHERE id = :id",
            named_params! { ":id": tx_id.as_i64_wrapped() },
            |row| row.get(0),
        )
        .optional()?;
    Ok(reason.flatten())
}

pub fn mark_completed_transaction_as_confirmed(
    conn: &Connection,
    tx_id: TxId,
    confirmation_height: i64,
    sent_payref: String,
) -> WalletDbResult<()> {
    let id = tx_id.to_string();
    info!(
        target: "audit",
        id = id.as_str(),
        height = confirmation_height;
        "DB: Transaction Confirmed"
    );

    let status = CompletedTransactionStatus::MinedConfirmed.to_string();
    let now = Utc::now();

    conn.execute(
        r#"
        UPDATE completed_transactions
        SET status = :status, confirmation_height = :height, sent_payref = :payref, updated_at = :now
        WHERE id = :id
        "#,
        named_params! {
            ":status": status,
            ":height": confirmation_height,
            ":payref": sent_payref,
            ":now": now,
            ":id": tx_id.as_i64_wrapped()
        },
    )?;

    Ok(())
}

pub fn revert_completed_transaction_to_completed(conn: &Connection, tx_id: TxId) -> WalletDbResult<()> {
    warn!(
        target: "audit",
        id = tx_id.to_string().as_str();
        "DB: Reverting transaction to completed state (Reorg)"
    );

    let status = CompletedTransactionStatus::Completed.to_string();
    let now = Utc::now();

    conn.execute(
        r#"
        UPDATE completed_transactions
        SET status = :status, mined_height = NULL, mined_block_hash = NULL, 
            confirmation_height = NULL, sent_payref = NULL, broadcast_attempts = 0, updated_at = :now
        WHERE id = :id
        "#,
        named_params! {
            ":status": status,
            ":now": now,
            ":id": tx_id.as_i64_wrapped()
        },
    )?;

    Ok(())
}

/// Resets every transaction the block scan settled at or above `reorg_height`
/// back to `Completed`, so the monitor rebroadcasts it.
///
/// That covers mined transactions (`MinedUnconfirmed`/`MinedConfirmed`) and
/// transactions the scan rejected because their inputs were spent by a
/// different transaction (`Rejected` with a `mined_height`; see
/// [`mark_completed_transaction_as_rejected_in_block`]). A `Rejected` row
/// without a `mined_height` was rejected by the node and is left alone.
pub fn reset_mined_completed_transactions_from_height(
    conn: &Connection,
    account_id: i64,
    reorg_height: u64,
) -> WalletDbResult<u64> {
    warn!(
        account_id = account_id,
        height = reorg_height;
        "DB: Resetting mined transactions from height (Reorg)"
    );

    let status_completed = CompletedTransactionStatus::Completed.to_string();
    let status_unconfirmed = CompletedTransactionStatus::MinedUnconfirmed.to_string();
    let status_confirmed = CompletedTransactionStatus::MinedConfirmed.to_string();
    let status_rejected = CompletedTransactionStatus::Rejected.to_string();
    #[allow(clippy::cast_possible_wrap)]
    let height = reorg_height as i64;
    let now = Utc::now();

    let rows_affected = conn.execute(
        r#"
        UPDATE completed_transactions
        SET status = :status_completed, mined_height = NULL, mined_block_hash = NULL,
            confirmation_height = NULL, sent_payref = NULL, last_rejected_reason = NULL,
            broadcast_attempts = 0, updated_at = :now
        WHERE account_id = :account_id
          AND status IN (:status_unconfirmed, :status_confirmed, :status_rejected)
          AND mined_height >= :height
        "#,
        named_params! {
            ":status_completed": status_completed,
            ":now": now,
            ":account_id": account_id,
            ":status_unconfirmed": status_unconfirmed,
            ":status_confirmed": status_confirmed,
            ":status_rejected": status_rejected,
            ":height": height
        },
    )?;

    Ok(rows_affected as u64)
}

pub fn mark_completed_transaction_as_rejected(
    conn: &Connection,
    tx_id: TxId,
    reject_reason: &str,
) -> WalletDbResult<()> {
    let id = tx_id.to_string();
    warn!(
        id = id.as_str(),
        reason = reject_reason;
        "DB: Transaction Rejected"
    );

    let status_str = CompletedTransactionStatus::Rejected.to_string();
    let now = Utc::now();

    conn.execute(
        r#"
        UPDATE completed_transactions
        SET status = :status, last_rejected_reason = :reason, updated_at = :now
        WHERE id = :id
        "#,
        named_params! {
            ":status": status_str,
            ":reason": reject_reason,
            ":now": now,
            ":id": tx_id.as_i64_wrapped()
        },
    )?;

    Ok(())
}

/// Marks a send `Rejected` because the block scan saw its inputs spent by a
/// different transaction in the block at `block_height`.
///
/// The block is recorded in `mined_height`/`mined_block_hash` so that a reorg
/// past that block can revert the rejection (see
/// [`reset_mined_completed_transactions_from_height`]).
pub fn mark_completed_transaction_as_rejected_in_block(
    conn: &Connection,
    tx_id: TxId,
    reject_reason: &str,
    block_height: i64,
    block_hash: &[u8],
) -> WalletDbResult<()> {
    warn!(
        target: "audit",
        id = tx_id.to_string().as_str(),
        height = block_height,
        reason = reject_reason;
        "DB: Transaction Rejected (inputs spent in a block)"
    );

    conn.execute(
        r#"
        UPDATE completed_transactions
        SET status = :status, last_rejected_reason = :reason, mined_height = :height,
            mined_block_hash = :hash, updated_at = :now
        WHERE id = :id
        "#,
        named_params! {
            ":status": CompletedTransactionStatus::Rejected.to_string(),
            ":reason": reject_reason,
            ":height": block_height,
            ":hash": block_hash,
            ":now": Utc::now(),
            ":id": tx_id.as_i64_wrapped()
        },
    )?;

    Ok(())
}

/// Keeps a send the scan rejected `Rejected` after a reorg removed the block
/// it was rejected in, because its inputs are now spent or locked elsewhere.
///
/// The block is forgotten (`mined_height`/`mined_block_hash` cleared) so the
/// reorg's reset leaves the send alone; like a send the monitor rejected, the
/// scan can still find it mined later.
pub fn keep_rejected_after_reorg(conn: &Connection, tx_id: TxId, reason: &str) -> WalletDbResult<()> {
    conn.execute(
        r#"
        UPDATE completed_transactions
        SET mined_height = NULL, mined_block_hash = NULL, last_rejected_reason = :reason, updated_at = :now
        WHERE id = :id
        "#,
        named_params! {
            ":reason": reason,
            ":now": Utc::now(),
            ":id": tx_id.as_i64_wrapped()
        },
    )?;
    Ok(())
}

/// `(pending transaction id, transaction id)` of the sends the block scan
/// rejected in a block at or above `height` (see
/// [`mark_completed_transaction_as_rejected_in_block`]).
pub fn get_scan_rejected_pending_tx_ids_from_height(
    conn: &Connection,
    account_id: i64,
    height: u64,
) -> WalletDbResult<Vec<(String, TxId)>> {
    #[allow(clippy::cast_possible_wrap)]
    let height = height as i64;
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT pending_tx_id, id
        FROM completed_transactions
        WHERE account_id = :account_id
          AND status = :status_rejected
          AND mined_height >= :height
        "#,
    )?;

    let rows = stmt.query_map(
        named_params! {
            ":account_id": account_id,
            ":status_rejected": CompletedTransactionStatus::Rejected.to_string(),
            ":height": height,
        },
        |row| {
            let pending_tx_id: String = row.get(0)?;
            let id: i64 = row.get(1)?;
            Ok((pending_tx_id, TxId::from(id as u64)))
        },
    )?;

    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn get_pending_completed_transactions(
    conn: &Connection,
    account_id: i64,
) -> WalletDbResult<Vec<CompletedTransaction>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, account_id, pending_tx_id, status, last_rejected_reason, kernel_excess,
               sent_payref, sent_output_hash, mined_height, mined_block_hash, confirmation_height,
               broadcast_attempts, serialized_transaction, created_at, updated_at
        FROM completed_transactions
        WHERE account_id = :account_id
          AND status NOT IN ('mined_confirmed', 'rejected', 'canceled')
        ORDER BY created_at ASC
        "#,
    )?;

    let rows = stmt.query_map(named_params! { ":account_id": account_id }, map_row)?;

    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// Retrieves all completed transactions for an account with pagination.
///
/// Returns transactions ordered by creation time (most recent first).
///
/// # Parameters
///
/// * `conn` - Database connection
/// * `account_id` - The account to query transactions for
/// * `limit` - Maximum number of transactions to return
/// * `offset` - Number of transactions to skip for pagination
///
/// # Returns
///
/// A vector of completed transactions, or an error if the query fails.
pub fn get_completed_transactions_by_account(
    conn: &Connection,
    account_id: i64,
    limit: i64,
    offset: i64,
) -> WalletDbResult<Vec<CompletedTransaction>> {
    debug!(
        account_id = account_id,
        limit = limit,
        offset = offset;
        "DB: Fetching completed transactions with pagination"
    );

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, account_id, pending_tx_id, status, last_rejected_reason, kernel_excess,
               sent_payref, sent_output_hash, mined_height, mined_block_hash, confirmation_height,
               broadcast_attempts, serialized_transaction, created_at, updated_at
        FROM completed_transactions
        WHERE account_id = :account_id
        ORDER BY created_at DESC, id DESC
        LIMIT :limit OFFSET :offset
        "#,
    )?;

    let rows = stmt.query_map(
        named_params! {
            ":account_id": account_id,
            ":limit": limit,
            ":offset": offset
        },
        map_row,
    )?;

    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// Retrieves a completed transaction by its payment reference.
///
/// The sent_payref field is populated when a transaction is confirmed.
///
/// # Parameters
///
/// * `conn` - Database connection
/// * `account_id` - The account to query transactions for
/// * `payref` - The payment reference to search for
///
/// # Returns
///
/// The completed transaction if found, or None if no match.
pub fn get_completed_transaction_by_payref(
    conn: &Connection,
    account_id: i64,
    payref: &str,
) -> WalletDbResult<Option<CompletedTransaction>> {
    debug!(
        account_id = account_id,
        payref = payref;
        "DB: Fetching completed transaction by payref"
    );

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, account_id, pending_tx_id, status, last_rejected_reason, kernel_excess,
               sent_payref, sent_output_hash, mined_height, mined_block_hash, confirmation_height,
               broadcast_attempts, serialized_transaction, created_at, updated_at
        FROM completed_transactions
        WHERE account_id = :account_id AND sent_payref = :payref
        "#,
    )?;

    let result = stmt
        .query_row(
            named_params! {
                ":account_id": account_id,
                ":payref": payref
            },
            map_row,
        )
        .optional()?;

    Ok(result)
}
