use std::str::FromStr;

use crate::db::error::{WalletDbError, WalletDbResult};
use crate::log::mask_amount;
use crate::transactions::idempotency::IdempotencyBinding;
use crate::{
    db::completed_transactions::CompletedTransactionStatus,
    db::outputs::{fetch_outputs_by_lock_request_id, unlock_outputs_for_request},
    models::PendingTransactionStatus,
    transactions::fund_locker::LockFundsResult,
};
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use rusqlite::{Connection, OptionalExtension, ToSql, named_params};
use serde::Deserialize;
use serde_rusqlite::from_rows;
use tari_transaction_components::tari_amount::MicroMinotari;
use uuid::Uuid;

pub struct PendingTransaction {
    pub id: Uuid,
    pub account_id: i64,
    pub status: PendingTransactionStatus,
    pub requires_change_output: bool,
    pub total_value: MicroMinotari,
    pub fee_without_change: MicroMinotari,
    pub fee_with_change: MicroMinotari,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Creates the pending transaction that owns a UTXO reservation.
///
/// `binding` records *what* the key was issued for: its operation and a
/// fingerprint of the originating request. Both are persisted so a later replay
/// of `idempotency_key` can be checked against them rather than being handed
/// this reservation on the strength of the key alone — see
/// [`crate::transactions::idempotency`].
#[allow(clippy::too_many_arguments)]
pub fn create_pending_transaction(
    conn: &Connection,
    idempotency_key: &str,
    binding: &IdempotencyBinding,
    account_id: i64,
    requires_change_output: bool,
    total_value: MicroMinotari,
    fee_without_change: MicroMinotari,
    fee_with_change: MicroMinotari,
    expires_at: DateTime<Utc>,
) -> WalletDbResult<String> {
    info!(
        target: "audit",
        account_id = account_id,
        operation = binding.operation().as_str(),
        total_value = &*mask_amount(total_value);
        "DB: Creating pending transaction"
    );

    let id: String = Uuid::new_v4().to_string();
    let status_pending = PendingTransactionStatus::Pending.to_string();
    #[allow(clippy::cast_possible_wrap)]
    let total_value = total_value.as_u64() as i64;
    #[allow(clippy::cast_possible_wrap)]
    let fee_without_change = fee_without_change.as_u64() as i64;
    #[allow(clippy::cast_possible_wrap)]
    let fee_with_change = fee_with_change.as_u64() as i64;

    let res = conn.execute(
        r#"
        INSERT INTO pending_transactions (
            id,
            idempotency_key,
            operation,
            request_hash,
            account_id,
            status,
            requires_change_output,
            total_value,
            fee_without_change,
            fee_with_change,
            expires_at
        )
        VALUES (
            :id,
            :key,
            :operation,
            :request_hash,
            :acc_id,
            :status,
            :change,
            :val,
            :fee_no_change,
            :fee_change,
            :expires
        )
        "#,
        named_params! {
            ":id": id,
            ":key": idempotency_key,
            ":operation": binding.operation().as_str(),
            ":request_hash": binding.request_hash(),
            ":acc_id": account_id,
            ":status": status_pending,
            ":change": requires_change_output,
            ":val": total_value,
            ":fee_no_change": fee_without_change,
            ":fee_change": fee_with_change,
            ":expires": expires_at,
        },
    );

    match res {
        Ok(_) => Ok(id),
        Err(e) => {
            // Match the UNIQUE violation specifically, not every constraint:
            // reporting a foreign-key failure as a duplicate idempotency key
            // sends the caller looking for a replay that does not exist.
            if let rusqlite::Error::SqliteFailure(err, _) = &e
                && err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
            {
                warn!("DB: Duplicate pending transaction attempted");
                return Err(WalletDbError::DuplicateEntry(format!(
                    "Pending transaction with idempotency key '{}' already exists",
                    idempotency_key
                )));
            }
            Err(WalletDbError::Rusqlite(e))
        },
    }
}

/// Claims a reservation for broadcast, but only while it is still `PENDING`.
///
/// Returns `None` once this caller owns the broadcast, or the status that
/// blocked the claim. The guard is the `WHERE status = :pending` clause rather
/// than a preceding read, because a separate read can be overtaken between the
/// check and the update: two sends holding transactions over one reservation
/// would then both record a completed transaction and broadcast conflicting
/// spends of the same inputs.
pub fn claim_pending_transaction_for_broadcast(
    conn: &Connection,
    id: &str,
) -> WalletDbResult<Option<PendingTransactionStatus>> {
    if update_pending_transaction_status_if(
        conn,
        id,
        &PendingTransactionStatus::Pending,
        PendingTransactionStatus::Completed,
    )? {
        return Ok(None);
    }

    // Nothing moved: the row is either gone or already past `PENDING`. Read back
    // which, so the caller can say why it is being refused.
    let status: Option<String> = conn
        .query_row(
            "SELECT status FROM pending_transactions WHERE id = :id",
            named_params! { ":id": id },
            |row| row.get(0),
        )
        .optional()?;
    let status = status.ok_or_else(|| WalletDbError::InvalidInput("No such pending transaction".to_string()))?;

    Ok(Some(
        PendingTransactionStatus::from_str(&status).map_err(WalletDbError::Decoding)?,
    ))
}

#[derive(Deserialize, Debug)]
pub struct ExpiredTransaction {
    pub id: String,
}

pub fn find_expired_pending_transactions(conn: &Connection) -> WalletDbResult<Vec<ExpiredTransaction>> {
    let status_pending = PendingTransactionStatus::Pending.to_string();

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id
        FROM pending_transactions
        WHERE status = :status AND expires_at < CURRENT_TIMESTAMP
        "#,
    )?;

    let rows = stmt.query(named_params! { ":status": status_pending })?;
    let results = from_rows::<ExpiredTransaction>(rows).collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Moves a pending transaction to `status`, but only from `expected`.
///
/// Returns whether the row moved. Use this wherever the decision to write was
/// taken from an earlier, separate read: the unlocker lists expired rows in
/// autocommit and then acts on them one write transaction at a time, so a
/// reservation can be claimed for broadcast in the gap. Expiring it then would
/// release the inputs of a transaction that is already on the network.
pub fn update_pending_transaction_status_if(
    conn: &Connection,
    id: &str,
    expected: &PendingTransactionStatus,
    status: PendingTransactionStatus,
) -> WalletDbResult<bool> {
    debug!(
        expected:% = expected,
        status:% = status;
        "DB: Updating pending transaction status if unchanged"
    );

    let moved = conn.execute(
        r#"
        UPDATE pending_transactions
        SET status = :status
        WHERE id = :id AND status = :expected
        "#,
        named_params! {
            ":status": status.to_string(),
            ":id": id,
            ":expected": expected.to_string(),
        },
    )?;

    Ok(moved > 0)
}

/// Expires a reservation and releases its UTXOs, but only while it is still `PENDING`.
///
/// Returns whether it acted. Both halves go in one write transaction: run
/// separately, a failure between them left an `EXPIRED` row over `LOCKED`
/// outputs, and `find_expired_pending_transactions` only ever revisits `PENDING`
/// rows, so nothing came back for them.
///
/// The `PENDING` guard is what makes this safe to call on a decision taken
/// earlier. The unlocker lists expired rows in autocommit; a finalizing send
/// decides to clean up before it knows whether it won the broadcast claim. In
/// both cases the row may have moved to `COMPLETED` in between, and expiring it
/// then would hand back the inputs of a transaction that is already on the
/// network.
///
/// `new_unchecked` because callers reach this holding the connection through
/// `?`-chains that borrow it immutably. What it gives up is rusqlite's detection
/// of a nested transaction, and no call site has one open.
pub fn expire_and_unlock_pending_transaction(conn: &Connection, id: &str) -> WalletDbResult<bool> {
    let transaction = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;

    if !update_pending_transaction_status_if(
        &transaction,
        id,
        &PendingTransactionStatus::Pending,
        PendingTransactionStatus::Expired,
    )? {
        return Ok(false);
    }

    unlock_outputs_for_request(&transaction, id)?;
    transaction.commit()?;

    Ok(true)
}

pub fn update_pending_transaction_status(
    conn: &Connection,
    id: &str,
    status: PendingTransactionStatus,
) -> WalletDbResult<()> {
    debug!(
        status:% = status;
        "DB: Updating pending transaction status"
    );

    let status_str = status.to_string();
    conn.execute(
        r#"
        UPDATE pending_transactions
        SET status = :status
        WHERE id = :id
        "#,
        named_params! {
            ":status": status_str,
            ":id": id
        },
    )?;

    Ok(())
}

/// Everything the fund locker needs to decide what an idempotency key may do.
///
/// Deliberately carries the row's `status`, `operation` and `request_hash` as
/// well as the reservation itself: whether a replay may be served is a decision
/// about all four together, and a lookup that filtered on status or scope in SQL
/// would report "no such key" for a key that does exist under a different
/// scope — which is exactly the case that must be rejected loudly.
pub struct PendingTransactionRecord {
    /// The pending transaction's id, which is also the lock request id.
    pub id: String,
    pub status: PendingTransactionStatus,
    /// The operation this key was issued for; empty for rows written before
    /// idempotency keys were scoped.
    pub operation: String,
    /// Fingerprint of the originating request; empty for pre-scoping rows.
    pub request_hash: String,
    pub requires_change_output: bool,
    pub total_value: MicroMinotari,
    pub fee_without_change: MicroMinotari,
    pub fee_with_change: MicroMinotari,
}

/// Looks up the pending transaction for an idempotency key, whatever its state.
///
/// Returns rows in *any* status, because a completed or expired key must
/// produce a conflict rather than silently falling through to a fresh
/// reservation under a key the wallet has already spent.
pub fn find_pending_transaction_record_by_idempotency_key(
    conn: &Connection,
    idempotency_key: &str,
    account_id: i64,
) -> WalletDbResult<Option<PendingTransactionRecord>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT
            id,
            status,
            operation,
            request_hash,
            requires_change_output,
            total_value,
            fee_without_change,
            fee_with_change
        FROM pending_transactions
        WHERE idempotency_key = :key AND account_id = :acc_id
        "#,
    )?;

    #[derive(Deserialize)]
    struct PendingTransactionRow {
        id: String,
        status: String,
        operation: String,
        request_hash: String,
        requires_change_output: bool,
        total_value: i64,
        fee_without_change: i64,
        fee_with_change: i64,
    }

    let rows = stmt.query(named_params! {
        ":key": idempotency_key,
        ":acc_id": account_id,
    })?;

    let row = from_rows::<PendingTransactionRow>(rows).next().transpose()?;

    match row {
        Some(row) => {
            let status = PendingTransactionStatus::from_str(&row.status).map_err(WalletDbError::Decoding)?;
            Ok(Some(PendingTransactionRecord {
                id: row.id,
                status,
                operation: row.operation,
                request_hash: row.request_hash,
                requires_change_output: row.requires_change_output,
                total_value: MicroMinotari::from(row.total_value as u64),
                fee_without_change: MicroMinotari::from(row.fee_without_change as u64),
                fee_with_change: MicroMinotari::from(row.fee_with_change as u64),
            }))
        },
        None => Ok(None),
    }
}

/// Rebuilds the [`LockFundsResult`] a pending transaction is currently holding.
///
/// Only meaningful for a record whose scope has already been checked against the
/// caller's binding; see
/// [`FundLocker::lock`](crate::transactions::fund_locker::FundLocker::lock).
pub fn locked_funds_for_pending_transaction(
    conn: &Connection,
    record: &PendingTransactionRecord,
) -> WalletDbResult<LockFundsResult> {
    let utxos = fetch_outputs_by_lock_request_id(conn, &record.id)?;
    Ok(LockFundsResult {
        utxos: utxos.into_iter().map(|db_out| db_out.output).collect(),
        requires_change_output: record.requires_change_output,
        total_value: record.total_value,
        fee_without_change: record.fee_without_change,
        fee_with_change: record.fee_with_change,
        reservation_id: record.id.clone(),
        created_reservation: false,
        send_all_skipped: None,
    })
}

pub fn find_pending_transaction_by_idempotency_key(
    conn: &Connection,
    idempotency_key: &str,
    account_id: i64,
) -> WalletDbResult<Option<PendingTransaction>> {
    let status_pending = PendingTransactionStatus::Pending.to_string();

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT
            id,
            account_id,
            status,
            requires_change_output,
            total_value,
            fee_without_change,
            fee_with_change,
            expires_at,
            created_at
        FROM pending_transactions
        WHERE idempotency_key = :key AND account_id = :acc_id AND status = :status
        "#,
    )?;

    let result = stmt
        .query_row(
            named_params! {
                ":key": idempotency_key,
                ":acc_id": account_id,
                ":status": status_pending
            },
            |row| {
                let id_str: String = row.get("id")?;
                let status_str: String = row.get("status")?;
                let total_val: i64 = row.get("total_value")?;
                let fee_no: i64 = row.get("fee_without_change")?;
                let fee_with: i64 = row.get("fee_with_change")?;

                Ok(PendingTransaction {
                    id: Uuid::parse_str(&id_str).map_err(|_| rusqlite::Error::ExecuteReturnedResults)?,
                    account_id: row.get("account_id")?,
                    status: PendingTransactionStatus::from_str(&status_str)
                        .map_err(|_| rusqlite::Error::ExecuteReturnedResults)?,
                    requires_change_output: row.get("requires_change_output")?,
                    total_value: MicroMinotari::from(total_val as u64),
                    fee_without_change: MicroMinotari::from(fee_no as u64),
                    fee_with_change: MicroMinotari::from(fee_with as u64),
                    expires_at: row.get("expires_at")?,
                    created_at: row.get("created_at")?,
                })
            },
        )
        .optional()?;

    Ok(result)
}

pub fn check_if_transaction_is_expired_by_idempotency_key(
    conn: &Connection,
    idempotency_key: &str,
    account_id: i64,
) -> WalletDbResult<bool> {
    let status_pending = PendingTransactionStatus::Pending.to_string();

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT 1
        FROM pending_transactions
        WHERE idempotency_key = :key 
          AND account_id = :acc_id 
          AND status = :status 
          AND expires_at < CURRENT_TIMESTAMP
        LIMIT 1
        "#,
    )?;

    let exists: Option<i32> = stmt
        .query_row(
            named_params! {
                ":key": idempotency_key,
                ":acc_id": account_id,
                ":status": status_pending
            },
            |row| row.get(0),
        )
        .optional()?;

    Ok(exists.is_some())
}

pub fn cancel_pending_transactions_by_ids(
    conn: &Connection,
    ids: &[String],
    status: PendingTransactionStatus,
) -> WalletDbResult<()> {
    if ids.is_empty() {
        return Ok(());
    }

    warn!(
        target: "audit",
        count = ids.len(),
        new_status:% = status;
        "DB: Cancelling pending transactions"
    );

    let status_str = status.to_string();

    let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let query_str = format!(
        "UPDATE pending_transactions SET status = ? WHERE id IN ({})",
        placeholders
    );

    let mut params: Vec<&dyn ToSql> = Vec::with_capacity(ids.len().saturating_add(1));
    params.push(&status_str);
    for id in ids {
        params.push(id);
    }

    conn.execute(&query_str, params.as_slice())?;

    // A cancelled request with no completed transaction in play will not land:
    // its inputs are released (else those not removed with the reorged blocks
    // would stay `LOCKED` for it for good) and its change output dropped. One
    // that was signed and recorded as a completed transaction still in play
    // (not rejected or cancelled) keeps its locks and its change: the reorg
    // resets it to be rebroadcast, and the scan finds it by that change when
    // it lands again.
    for id in ids {
        let in_play: i64 = conn.query_row(
            r#"
            SELECT COUNT(*) FROM completed_transactions
            WHERE pending_tx_id = :id AND status NOT IN (:rejected, :canceled)
            "#,
            named_params! {
                ":id": id,
                ":rejected": CompletedTransactionStatus::Rejected.to_string(),
                ":canceled": CompletedTransactionStatus::Canceled.to_string(),
            },
            |row| row.get(0),
        )?;
        if in_play == 0 {
            // Also soft-deletes its unconfirmed change output.
            unlock_outputs_for_request(conn, id)?;
        }
    }

    Ok(())
}
