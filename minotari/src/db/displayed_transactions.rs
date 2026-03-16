use crate::db::error::{WalletDbError, WalletDbResult};
use crate::log::mask_amount;
use crate::models::Id;
use crate::transactions::{DisplayedTransaction, TransactionDisplayStatus};
use crate::utils::timestamp::{current_db_timestamp, format_timestamp};
use log::{debug, info, warn};
use rusqlite::{Connection, OptionalExtension, named_params};
use serde::Deserialize;
use serde_rusqlite::from_rows;
use tari_common_types::transaction::TxId;
use tari_common_types::types::FixedHash;

#[derive(Deserialize)]
struct TransactionJsonRow {
    transaction_json: String,
}

#[derive(Deserialize)]
struct TransactionIdJsonRow {
    id: String,
    transaction_json: String,
}

fn serialize_tx(tx: &DisplayedTransaction) -> WalletDbResult<String> {
    serde_json::to_string(tx).map_err(WalletDbError::SerdeJson)
}

fn process_json_rows(
    mut rows: impl Iterator<Item = Result<TransactionJsonRow, serde_rusqlite::Error>>,
) -> WalletDbResult<Vec<DisplayedTransaction>> {
    rows.try_fold(Vec::new(), |mut acc, row| {
        let json = row?.transaction_json;
        if let Ok(tx) = serde_json::from_str(&json) {
            acc.push(tx);
        }
        Ok::<_, serde_rusqlite::Error>(acc)
    })
    .map_err(WalletDbError::from)
}

pub fn insert_displayed_transaction(conn: &Connection, transaction: &DisplayedTransaction) -> WalletDbResult<()> {
    let id = transaction.id.to_string();
    debug!(
        id = id.as_str(),
        amount = &*mask_amount(transaction.amount),
        status:? = transaction.status;
        "DB: Inserting displayed transaction"
    );

    let direction = format!("{:?}", transaction.direction).to_lowercase();
    let source = format!("{:?}", transaction.source).to_lowercase();
    let status = format!("{:?}", transaction.status).to_lowercase();
    let timestamp = format_timestamp(transaction.blockchain.timestamp);

    let transaction_json = serialize_tx(transaction)?;
    let now = current_db_timestamp();
    let payref = Some(serde_json::to_string(&transaction.details.sent_payrefs)?);

    conn.execute(
        r#"
        INSERT INTO displayed_transactions (
            id, account_id, direction, source, status, amount, block_height,
            timestamp, transaction_json, payref, created_at, updated_at
        )
        VALUES (
            :id, :account_id, :direction, :source, :status, :amount, :block_height,
            :timestamp, :json, :payref, :created_at, :updated_at
        )
        ON CONFLICT(id) DO UPDATE SET
            status = excluded.status,
            transaction_json = excluded.transaction_json,
            payref = excluded.payref,
            updated_at = excluded.updated_at
        "#,
        named_params! {
            ":id": transaction.id.to_string(),
            ":account_id": transaction.details.account_id,
            ":direction": direction,
            ":source": source,
            ":status": status,
            ":amount": transaction.amount.as_u64() as i64,
            ":block_height": transaction.blockchain.block_height as i64,
            ":timestamp": timestamp,
            ":json": transaction_json,
            ":payref": payref,
            ":created_at": now,
            ":updated_at": now,
        },
    )?;

    Ok(())
}

pub fn get_displayed_transactions_by_account(
    conn: &Connection,
    account_id: Id,
) -> WalletDbResult<Vec<DisplayedTransaction>> {
    debug!(
        account_id = account_id;
        "DB: Get displayed transactions"
    );

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT transaction_json
        FROM displayed_transactions
        WHERE account_id = :account_id
        ORDER BY block_height DESC, timestamp DESC
        "#,
    )?;

    let rows = stmt.query(named_params! { ":account_id": account_id })?;
    process_json_rows(from_rows::<TransactionJsonRow>(rows))
}

pub fn get_displayed_transactions_by_status(
    conn: &Connection,
    account_id: Id,
    status: TransactionDisplayStatus,
) -> WalletDbResult<Vec<DisplayedTransaction>> {
    let status_str = format!("{:?}", status).to_lowercase();

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT transaction_json
        FROM displayed_transactions
        WHERE account_id = :account_id AND status = :status
        ORDER BY block_height DESC, timestamp DESC
        "#,
    )?;

    let rows = stmt.query(named_params! {
        ":account_id": account_id,
        ":status": status_str
    })?;

    process_json_rows(from_rows::<TransactionJsonRow>(rows))
}

pub fn get_displayed_transactions_from_height(
    conn: &Connection,
    account_id: Id,
    from_height: u64,
) -> WalletDbResult<Vec<DisplayedTransaction>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT transaction_json
        FROM displayed_transactions
        WHERE account_id = :account_id AND block_height >= :height
        ORDER BY block_height DESC, timestamp DESC
        "#,
    )?;

    let rows = stmt.query(named_params! {
        ":account_id": account_id,
        ":height": from_height as i64
    })?;

    process_json_rows(from_rows::<TransactionJsonRow>(rows))
}

pub fn update_displayed_transaction_status(
    conn: &Connection,
    id: &str,
    new_status: TransactionDisplayStatus,
    updated_transaction: &DisplayedTransaction,
) -> WalletDbResult<bool> {
    debug!(
        id = id,
        new_status:? = new_status;
        "DB: Updating displayed transaction status"
    );

    let status_str = format!("{:?}", new_status).to_lowercase();
    let transaction_json = serialize_tx(updated_transaction)?;

    let rows_affected = conn.execute(
        r#"
        UPDATE displayed_transactions
        SET status = :status, transaction_json = :json, updated_at = :now
        WHERE id = :id
        "#,
        named_params! {
            ":status": status_str,
            ":json": transaction_json,
            ":now": current_db_timestamp(),
            ":id": id
        },
    )?;

    Ok(rows_affected > 0)
}

pub fn mark_displayed_transactions_reorganized(
    conn: &Connection,
    account_id: Id,
    from_height: u64,
) -> WalletDbResult<u64> {
    warn!(
        account_id:? = account_id,
        from_height = from_height;
        "DB: Marking displayed transactions as reorganized"
    );

    let status_str = format!("{:?}", TransactionDisplayStatus::Reorganized).to_lowercase();
    let now = current_db_timestamp();

    let rows_to_update = {
        let mut stmt = conn.prepare_cached(
            r#"
            SELECT id, transaction_json
            FROM displayed_transactions
            WHERE account_id = :account_id AND block_height >= :height
            "#,
        )?;

        let rows = stmt.query(named_params! {
            ":account_id": account_id,
            ":height": from_height as i64
        })?;

        from_rows::<TransactionIdJsonRow>(rows).collect::<Result<Vec<_>, _>>()?
    };

    let mut updated_count = 0u64;

    for row in rows_to_update {
        if let Ok(mut tx) = serde_json::from_str::<DisplayedTransaction>(&row.transaction_json) {
            tx.status = TransactionDisplayStatus::Reorganized;
            let updated_json = serialize_tx(&tx)?;

            conn.execute(
                r#"
                UPDATE displayed_transactions
                SET status = :status, transaction_json = :json, updated_at = :now
                WHERE id = :id
                "#,
                named_params! {
                    ":status": status_str,
                    ":json": updated_json,
                    ":now": now,
                    ":id": row.id
                },
            )?;

            updated_count += 1;
        }
    }

    Ok(updated_count)
}

pub fn get_displayed_transaction_by_id(conn: &Connection, id: &str) -> WalletDbResult<Option<DisplayedTransaction>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT transaction_json
        FROM displayed_transactions
        WHERE id = :id
        "#,
    )?;

    let row: Option<String> = stmt.query_row(named_params! { ":id": id }, |r| r.get(0)).optional()?;

    Ok(row.and_then(|json| serde_json::from_str(&json).ok()))
}

/// Find an existing pending outbound transaction that matches the given output hash.
/// Used by BlockProcessor to detect if a scanned transaction already has a pending record.
pub fn find_pending_outbound_by_output_hash(
    conn: &Connection,
    account_id: Id,
    output_hash: &FixedHash,
) -> WalletDbResult<Option<DisplayedTransaction>> {
    let pending_status = format!("{:?}", TransactionDisplayStatus::Pending).to_lowercase();
    let outgoing_direction = "outgoing";

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT transaction_json
        FROM displayed_transactions
        WHERE account_id = :account_id AND status = :status AND direction = :direction
        "#,
    )?;

    let rows = stmt.query(named_params! {
        ":account_id": account_id,
        ":status": pending_status,
        ":direction": outgoing_direction
    })?;

    let found = from_rows::<TransactionJsonRow>(rows)
        .filter_map(|res| res.ok())
        .filter_map(|r| serde_json::from_str::<DisplayedTransaction>(&r.transaction_json).ok())
        .find(|tx| {
            tx.details.sent_output_hashes.contains(output_hash)
                || tx.details.inputs.iter().any(|input| &input.output_hash == output_hash)
        });

    Ok(found)
}

/// Update an existing displayed transaction with blockchain info when it's mined.
pub fn update_displayed_transaction_mined(conn: &Connection, tx: &DisplayedTransaction) -> WalletDbResult<bool> {
    let id = tx.id.to_string();
    info!(
        target: "audit",
        id = id.as_str(),
        height = tx.blockchain.block_height;
        "DB: Displayed Transaction Mined"
    );

    let status_str = format!("{:?}", tx.status).to_lowercase();
    let transaction_json = serialize_tx(tx)?;
    let payref = Some(serde_json::to_string(&tx.details.sent_payrefs)?);

    let rows_affected = conn.execute(
        r#"
        UPDATE displayed_transactions
        SET status = :status, block_height = :height, transaction_json = :json, payref = :payref, updated_at = :now
        WHERE id = :id
        "#,
        named_params! {
            ":status": status_str,
            ":height": tx.blockchain.block_height as i64,
            ":json": transaction_json,
            ":payref": payref,
            ":now": current_db_timestamp(),
            ":id": id
        },
    )?;

    Ok(rows_affected > 0)
}

pub fn get_displayed_transactions_paginated(
    conn: &Connection,
    account_id: Id,
    limit: i64,
    offset: i64,
) -> WalletDbResult<Vec<DisplayedTransaction>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT transaction_json
        FROM displayed_transactions
        WHERE account_id = :account_id
        ORDER BY block_height DESC, timestamp DESC
        LIMIT :limit OFFSET :offset
        "#,
    )?;

    let rows = stmt.query(named_params! {
        ":account_id": account_id,
        ":limit": limit,
        ":offset": offset
    })?;

    process_json_rows(from_rows::<TransactionJsonRow>(rows))
}

/// Returns transactions where current_tip_height - block_height < required_confirmations.
pub fn get_displayed_transactions_needing_confirmation_update(
    conn: &Connection,
    account_id: Id,
) -> WalletDbResult<Vec<DisplayedTransaction>> {
    let pending_status = format!("{:?}", TransactionDisplayStatus::Pending).to_lowercase();
    let unconfirmed_status = format!("{:?}", TransactionDisplayStatus::Unconfirmed).to_lowercase();

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT transaction_json
        FROM displayed_transactions
        WHERE account_id = :account_id
          AND status IN (:s1, :s2)
        "#,
    )?;

    let rows = stmt.query(named_params! {
        ":account_id": account_id,
        ":s1": pending_status,
        ":s2": unconfirmed_status
    })?;

    process_json_rows(from_rows::<TransactionJsonRow>(rows))
}

pub fn update_displayed_transaction_confirmations(
    conn: &Connection,
    transaction: &DisplayedTransaction,
) -> WalletDbResult<bool> {
    let status_str = format!("{:?}", transaction.status).to_lowercase();
    let transaction_json = serialize_tx(transaction)?;

    let rows_affected = conn.execute(
        r#"
        UPDATE displayed_transactions
        SET status = :status, transaction_json = :json, updated_at = :now
        WHERE id = :id
        "#,
        named_params! {
            ":status": status_str,
            ":json": transaction_json,
            ":now": current_db_timestamp(),
            ":id": transaction.id.to_string()
        },
    )?;

    Ok(rows_affected > 0)
}

pub fn mark_displayed_transaction_rejected(
    conn: &Connection,
    tx_id: TxId,
) -> WalletDbResult<Option<DisplayedTransaction>> {
    warn!(
        target: "audit",
        id = tx_id.to_string().as_str();
        "DB: Marking displayed transaction as rejected"
    );

    let status_str = format!("{:?}", TransactionDisplayStatus::Rejected).to_lowercase();
    let now = current_db_timestamp();

    let mut stmt = conn.prepare_cached("SELECT transaction_json FROM displayed_transactions WHERE id = :id")?;

    let json_row: Option<String> = stmt
        .query_row(named_params! { ":id": tx_id.to_string() }, |r| r.get(0))
        .optional()?;

    let Some(json) = json_row else {
        return Ok(None);
    };

    let mut tx: DisplayedTransaction = serde_json::from_str(&json)?;

    tx.status = TransactionDisplayStatus::Rejected;
    let updated_json = serialize_tx(&tx)?;

    conn.execute(
        r#"
        UPDATE displayed_transactions
        SET status = :status, transaction_json = :json, updated_at = :now
        WHERE id = :id
        "#,
        named_params! {
            ":status": status_str,
            ":json": updated_json,
            ":now": now,
            ":id": tx_id.to_string()
        },
    )?;

    Ok(Some(tx))
}

pub fn get_displayed_transactions_excluding_reorged(
    conn: &Connection,
    account_id: Id,
) -> WalletDbResult<Vec<DisplayedTransaction>> {
    let reorged_status = format!("{:?}", TransactionDisplayStatus::Reorganized).to_lowercase();

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT transaction_json
        FROM displayed_transactions
        WHERE account_id = :account_id AND status != :reorged
        ORDER BY block_height DESC, timestamp DESC
        "#,
    )?;

    let rows = stmt.query(named_params! {
        ":account_id": account_id,
        ":reorged": reorged_status
    })?;

    process_json_rows(from_rows::<TransactionJsonRow>(rows))
}

pub fn mark_displayed_transactions_reorganized_and_return(
    conn: &Connection,
    account_id: Id,
    from_height: u64,
) -> WalletDbResult<Vec<DisplayedTransaction>> {
    let status_str = format!("{:?}", TransactionDisplayStatus::Reorganized).to_lowercase();
    let now = current_db_timestamp();

    let rows_to_update = {
        let mut stmt = conn.prepare_cached(
            r#"
            SELECT id, transaction_json
            FROM displayed_transactions
            WHERE account_id = :account_id AND block_height >= :height AND status != :status
            "#,
        )?;

        let rows = stmt.query(named_params! {
            ":account_id": account_id,
            ":height": from_height as i64,
            ":status": status_str
        })?;

        from_rows::<TransactionIdJsonRow>(rows).collect::<Result<Vec<_>, _>>()?
    };

    let mut updated_transactions = Vec::with_capacity(rows_to_update.len());

    for row in rows_to_update {
        if let Ok(mut tx) = serde_json::from_str::<DisplayedTransaction>(&row.transaction_json) {
            tx.status = TransactionDisplayStatus::Reorganized;
            let updated_json = serialize_tx(&tx)?;

            conn.execute(
                r#"
                UPDATE displayed_transactions
                SET status = :status, transaction_json = :json, updated_at = :now
                WHERE id = :id
                "#,
                named_params! {
                    ":status": status_str,
                    ":json": updated_json,
                    ":now": now,
                    ":id": row.id
                },
            )?;

            updated_transactions.push(tx);
        }
    }

    Ok(updated_transactions)
}

/// Retrieves displayed transactions that contain a specific payment reference.
///
/// The payref column stores a JSON array of payment references. This function
/// searches for transactions where the payref column contains the specified
/// payment reference string.
///
/// # Parameters
///
/// * `conn` - Database connection
/// * `account_id` - The account to query transactions for
/// * `payref` - The payment reference to search for
///
/// # Returns
///
/// A vector of displayed transactions that contain the payment reference.
pub fn get_displayed_transactions_by_payref(
    conn: &Connection,
    account_id: Id,
    payref: &str,
) -> WalletDbResult<Vec<DisplayedTransaction>> {
    debug!(
        account_id = account_id,
        payref = payref;
        "DB: Fetching displayed transactions by payref"
    );

    // The payref column stores a JSON array, so we use LIKE to search within it
    // We search for the payref as a substring since it's stored as JSON
    let search_pattern = format!("%{}%", payref);

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT transaction_json
        FROM displayed_transactions
        WHERE account_id = :account_id AND payref LIKE :pattern
        ORDER BY block_height DESC, timestamp DESC
        "#,
    )?;

    let rows = stmt.query(named_params! {
        ":account_id": account_id,
        ":pattern": search_pattern
    })?;

    process_json_rows(from_rows::<TransactionJsonRow>(rows))
}
