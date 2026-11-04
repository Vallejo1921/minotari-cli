use crate::db::error::{WalletDbError, WalletDbResult};
use crate::log::mask_amount;
use crate::models::Id;
use crate::transactions::{DisplayedTransaction, TransactionDisplayStatus};
use crate::utils::timestamp::{current_db_timestamp, format_timestamp};
use log::{debug, info, trace, warn};
use rusqlite::{Connection, OptionalExtension, named_params};
use serde::Deserialize;
use serde_rusqlite::from_rows;
use tari_common_types::transaction::TxId;
use tari_common_types::types::FixedHash;
use tari_utilities::hex::Hex;

/// Upper bound on rows a single payref lookup may return.
///
/// A payment reference identifies one payment, so a handful of matches is already
/// generous; the cap exists so a malformed or hostile query cannot make the wallet
/// load and serialize every transaction it has.
const MAX_PAYREF_MATCHES: i64 = 100;

/// Escapes the LIKE metacharacters in `value` so it matches only itself.
///
/// Pairs with `ESCAPE '\'` on the query. The backslash must be escaped first,
/// otherwise the backslashes this function introduces would themselves be escaped.
fn escape_like_pattern(value: &str) -> String {
    value.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

/// Serialize the transaction's payrefs to the denormalized `payref` column as a
/// JSON array of hex strings. This matches the hex form used by the `LIKE`
/// payref lookup and the reorg-history parser (which reads `Vec<String>`).
fn payrefs_to_column_json(transaction: &DisplayedTransaction) -> WalletDbResult<String> {
    let hexes: Vec<String> = transaction.details.sent_payrefs.iter().map(FixedHash::to_hex).collect();
    Ok(serde_json::to_string(&hexes)?)
}

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
    trace!(
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
    let payref = Some(payrefs_to_column_json(transaction)?);
    #[allow(clippy::cast_possible_wrap)]
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
    #[allow(clippy::cast_possible_wrap)]
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
    trace!(
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
        #[allow(clippy::cast_possible_wrap)]
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

            updated_count = updated_count.saturating_add(1);
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
        height = tx.blockchain.block_height;
        "DB: Displayed Transaction Mined"
    );
    trace!(
        target: "audit",
        id = id.as_str();
        "DB: Displayed Transaction Mined"
    );

    let status_str = format!("{:?}", tx.status).to_lowercase();
    let transaction_json = serialize_tx(tx)?;
    let payref = Some(payrefs_to_column_json(tx)?);

    #[allow(clippy::cast_possible_wrap)]
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

/// Returns mined transactions that are still pending, unconfirmed or locked.
///
/// Rows with `block_height = 0` are unmined (a send that has not been seen in a
/// block yet). Counting their confirmations as `tip - 0` would mark them Confirmed
/// at once, so they are left to the scan, which sets `block_height` when the
/// transaction is mined.
pub fn get_displayed_transactions_needing_confirmation_update(
    conn: &Connection,
    account_id: Id,
) -> WalletDbResult<Vec<DisplayedTransaction>> {
    let pending_status = format!("{:?}", TransactionDisplayStatus::Pending).to_lowercase();
    let unconfirmed_status = format!("{:?}", TransactionDisplayStatus::Unconfirmed).to_lowercase();
    let locked_status = format!("{:?}", TransactionDisplayStatus::Locked).to_lowercase();

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT transaction_json
        FROM displayed_transactions
        WHERE account_id = :account_id
          AND status IN (:s1, :s2, :s3)
          AND block_height > 0
        "#,
    )?;

    let rows = stmt.query(named_params! {
        ":account_id": account_id,
        ":s1": pending_status,
        ":s2": unconfirmed_status,
        ":s3": locked_status
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

/// Puts a send's displayed transaction back to an unmined `Pending`, for a
/// reorg that undid the scan's rejection of it.
///
/// Its block height goes back to 0, so the monitor does not count
/// confirmations for it, and the scan matches it again (it only matches
/// `Pending` rows) when the send is mined, instead of adding a second entry.
/// Returns the updated transaction, or `None` if there is none.
pub fn reset_displayed_transaction_to_pending(
    conn: &Connection,
    tx_id: TxId,
) -> WalletDbResult<Option<DisplayedTransaction>> {
    let json_row: Option<String> = conn
        .query_row(
            "SELECT transaction_json FROM displayed_transactions WHERE id = :id",
            named_params! { ":id": tx_id.to_string() },
            |r| r.get(0),
        )
        .optional()?;
    let Some(json) = json_row else {
        return Ok(None);
    };

    let mut tx: DisplayedTransaction = serde_json::from_str(&json)?;
    tx.status = TransactionDisplayStatus::Pending;
    tx.blockchain.block_height = 0;
    tx.blockchain.confirmations = 0;
    tx.blockchain.block_hash = FixedHash::zero();

    conn.execute(
        r#"
        UPDATE displayed_transactions
        SET status = :status, block_height = 0, transaction_json = :json, updated_at = :now
        WHERE id = :id
        "#,
        named_params! {
            ":status": format!("{:?}", TransactionDisplayStatus::Pending).to_lowercase(),
            ":json": serialize_tx(&tx)?,
            ":now": current_db_timestamp(),
            ":id": tx_id.to_string(),
        },
    )?;

    Ok(Some(tx))
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

        #[allow(clippy::cast_possible_wrap)]
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
    trace!(
        account_id = account_id,
        payref = payref;
        "DB: Fetching displayed transactions by payref"
    );

    // The payref column stores a JSON array, so we use LIKE to search within it: we
    // look for the payref as a substring of the serialized array.
    //
    // `payref` comes straight off the URL path. Binding it as a parameter stops SQL
    // injection but not *pattern* injection: `%` and `_` are wildcards inside a LIKE
    // pattern, so a payref of `%` matches every row and returns the account's entire
    // transaction history to a caller who knows no payment reference at all. Escape
    // the wildcards so the pattern only ever matches the literal payref, and bound
    // the result set so one request cannot ask the wallet to serialize an unbounded
    // number of transactions.
    let search_pattern = format!("%{}%", escape_like_pattern(payref));

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT transaction_json
        FROM displayed_transactions
        WHERE account_id = :account_id AND payref LIKE :pattern ESCAPE '\'
        ORDER BY block_height DESC, timestamp DESC
        LIMIT :limit
        "#,
    )?;

    let rows = stmt.query(named_params! {
        ":account_id": account_id,
        ":pattern": search_pattern,
        ":limit": MAX_PAYREF_MATCHES,
    })?;

    process_json_rows(from_rows::<TransactionJsonRow>(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{create_account, get_account_by_name, init_db};
    use crate::transactions::{BlockchainInfo, TransactionDetails, TransactionDirection, TransactionSource};
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_transaction_components::MicroMinotari;
    use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
    use tempfile::tempdir;

    fn create_test_account(conn: &Connection) -> i64 {
        let seeds = CipherSeed::random();
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(seeds).unwrap());
        create_account(conn, "default", &wallet, "password").unwrap();
        get_account_by_name(conn, "default").unwrap().unwrap().id
    }

    /// A transaction whose only payref is `payref_byte` repeated 32 times.
    fn transaction_with_payref(account_id: Id, id: u64, payref_byte: u8) -> DisplayedTransaction {
        DisplayedTransaction {
            id: TxId::from(id),
            direction: TransactionDirection::Incoming,
            source: TransactionSource::OneSided,
            status: TransactionDisplayStatus::Confirmed,
            amount: MicroMinotari::from(1_000),
            message: None,
            counterparty: None,
            blockchain: BlockchainInfo {
                block_height: 100,
                timestamp: chrono::Utc::now().naive_utc(),
                confirmations: 5,
                block_hash: FixedHash::zero(),
            },
            fee: None,
            details: TransactionDetails {
                account_id,
                total_credit: MicroMinotari::from(1_000),
                total_debit: MicroMinotari::from(0),
                inputs: Vec::new(),
                outputs: Vec::new(),
                output_type: None,
                coinbase_extra: None,
                memo_hex: None,
                sent_output_hashes: Vec::new(),
                sent_payrefs: vec![FixedHash::from([payref_byte; 32])],
            },
            lock_height: 0,
        }
    }

    #[test]
    fn a_wildcard_payref_does_not_return_the_whole_history() {
        // The payref arrives as a URL path segment and is interpolated into a LIKE
        // pattern. Binding it as a parameter stops SQL injection but not pattern
        // injection: `%` is a LIKE wildcard, so a caller who knows no payment
        // reference at all could ask for `%` and be handed every transaction on the
        // account.
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("payref.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account_id = create_test_account(&conn);

        insert_displayed_transaction(&conn, &transaction_with_payref(account_id, 1, 0xAA)).expect("insert 1");
        insert_displayed_transaction(&conn, &transaction_with_payref(account_id, 2, 0xBB)).expect("insert 2");

        let all = get_displayed_transactions_by_payref(&conn, account_id, "%").expect("query");
        assert!(all.is_empty(), "a bare wildcard must match nothing, got {}", all.len());

        let underscores = get_displayed_transactions_by_payref(&conn, account_id, &"_".repeat(64)).expect("query");
        assert!(
            underscores.is_empty(),
            "`_` must not act as a single-character wildcard"
        );

        // A real payref still resolves.
        let target = "aa".repeat(32);
        let found = get_displayed_transactions_by_payref(&conn, account_id, &target).expect("query");
        assert_eq!(found.len(), 1, "the literal payref must still match its transaction");
        assert_eq!(found.first().expect("one match").id, TxId::from(1_u64));
    }
}
