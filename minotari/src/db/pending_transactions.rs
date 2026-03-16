use std::str::FromStr;

use crate::db::error::{WalletDbError, WalletDbResult};
use crate::log::mask_amount;
use crate::{
    api::types::LockFundsResult, db::outputs::fetch_outputs_by_lock_request_id, models::PendingTransactionStatus,
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

#[allow(clippy::too_many_arguments)]
pub fn create_pending_transaction(
    conn: &Connection,
    idempotency_key: &str,
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
        idempotency_key = idempotency_key,
        total_value = &*mask_amount(total_value);
        "DB: Creating pending transaction"
    );

    let id: String = Uuid::new_v4().to_string();
    let status_pending = PendingTransactionStatus::Pending.to_string();
    let total_value = total_value.as_u64() as i64;
    let fee_without_change = fee_without_change.as_u64() as i64;
    let fee_with_change = fee_with_change.as_u64() as i64;

    let res = conn.execute(
        r#"
        INSERT INTO pending_transactions (
            id,
            idempotency_key,
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
            if let rusqlite::Error::SqliteFailure(err, _) = &e
                && err.code == rusqlite::ErrorCode::ConstraintViolation
            {
                warn!(
                    idempotency_key = idempotency_key;
                    "DB: Duplicate pending transaction attempted"
                );
                return Err(WalletDbError::DuplicateEntry(format!(
                    "Pending transaction with idempotency key '{}' already exists",
                    idempotency_key
                )));
            }
            Err(WalletDbError::Rusqlite(e))
        },
    }
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

pub fn update_pending_transaction_status(
    conn: &Connection,
    id: &str,
    status: PendingTransactionStatus,
) -> WalletDbResult<()> {
    debug!(
        id = id,
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

pub fn find_pending_transaction_locked_funds_by_idempotency_key(
    conn: &Connection,
    idempotency_key: &str,
    account_id: i64,
) -> WalletDbResult<Option<LockFundsResult>> {
    let status_pending = PendingTransactionStatus::Pending.to_string();

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT
            id,
            requires_change_output,
            total_value,
            fee_without_change,
            fee_with_change
        FROM pending_transactions
        WHERE idempotency_key = :key AND account_id = :acc_id AND status = :status
        "#,
    )?;

    #[derive(Deserialize)]
    struct LockFundsRow {
        id: String,
        requires_change_output: bool,
        total_value: i64,
        fee_without_change: i64,
        fee_with_change: i64,
    }

    let rows = stmt.query(named_params! {
        ":key": idempotency_key,
        ":acc_id": account_id,
        ":status": status_pending
    })?;

    let row = from_rows::<LockFundsRow>(rows).next().transpose()?;

    match row {
        Some(row) => {
            let utxos = fetch_outputs_by_lock_request_id(conn, &row.id)?;
            Ok(Some(LockFundsResult {
                utxos: utxos.into_iter().map(|db_out| db_out.output).collect(),
                requires_change_output: row.requires_change_output,
                total_value: MicroMinotari::from(row.total_value as u64),
                fee_without_change: MicroMinotari::from(row.fee_without_change as u64),
                fee_with_change: MicroMinotari::from(row.fee_with_change as u64),
            }))
        },
        None => Ok(None),
    }
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

pub fn check_if_transaction_was_already_completed_by_idempotency_key(
    conn: &Connection,
    idempotency_key: &str,
    account_id: i64,
) -> WalletDbResult<bool> {
    let status_completed = PendingTransactionStatus::Completed.to_string();

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT 1
        FROM pending_transactions
        WHERE idempotency_key = :key AND account_id = :acc_id AND status = :status
        LIMIT 1
        "#,
    )?;

    let exists: Option<i32> = stmt
        .query_row(
            named_params! {
                ":key": idempotency_key,
                ":acc_id": account_id,
                ":status": status_completed
            },
            |row| row.get(0),
        )
        .optional()?;

    Ok(exists.is_some())
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

    let mut params: Vec<&dyn ToSql> = Vec::with_capacity(ids.len() + 1);
    params.push(&status_str);
    for id in ids {
        params.push(id);
    }

    conn.execute(&query_str, params.as_slice())?;

    Ok(())
}
