use crate::db::balance_changes::{
    get_balance_change_id_by_output, insert_balance_change, mark_balance_change_as_reversed,
};
use crate::db::completed_transactions::CompletedTransactionStatus;
use crate::db::error::{WalletDbError, WalletDbResult};
use crate::log::mask_amount;
use crate::models::BalanceChange;
use crate::models::OutputStatus;
use crate::models::PendingTransactionStatus;
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use rusqlite::{Connection, OptionalExtension, named_params};
use serde::Deserialize;
use serde_rusqlite::from_rows;
use tari_common_types::payment_reference::PaymentReference;
use tari_common_types::transaction::TxId;
use tari_common_types::types::FixedHash;
use tari_common_types::types::PrivateKey;
use tari_transaction_components::MicroMinotari;
use tari_transaction_components::transaction_components::WalletOutput;
use tari_transaction_components::utxo_selection::UtxoValue;
use tari_utilities::ByteArray;

#[allow(clippy::too_many_arguments)]
pub fn insert_output(
    conn: &Connection,
    account_id: i64,
    account_view_key: &PrivateKey,
    output_hash: Vec<u8>,
    output: &WalletOutput,
    block_height: u64,
    block_hash: &FixedHash,
    mined_timestamp: u64,
    memo_parsed: Option<String>,
    memo_hex: Option<String>,
    payment_reference: PaymentReference,
    is_burn: bool,
) -> WalletDbResult<i64> {
    info!(
        target: "audit",
        account_id = account_id,
        value = &*mask_amount(output.value()),
        height = block_height;
        "DB: Inserting output"
    );

    let tx_id = TxId::new_deterministic(account_view_key.as_bytes(), &output.output_hash()).as_i64_wrapped();

    let output_json = serde_json::to_string(&output)?;

    #[allow(clippy::cast_possible_wrap)]
    let mined_timestamp_dt = DateTime::<Utc>::from_timestamp(mined_timestamp as i64, 0)
        .ok_or_else(|| WalletDbError::Decoding(format!("Invalid mined timestamp: {}", mined_timestamp)))?;

    #[allow(clippy::cast_possible_wrap)]
    let block_height = block_height as i64;
    #[allow(clippy::cast_possible_wrap)]
    let value = output.value().as_u64() as i64;
    #[allow(clippy::cast_possible_wrap)]
    let maturity = output.features().maturity as i64;
    let payment_reference_hex = hex::encode(payment_reference.as_slice());

    conn.execute(
        r#"
       INSERT INTO outputs (
            account_id,
            tx_id,
            output_hash,
            mined_in_block_height,
            mined_in_block_hash,
            value,
            mined_timestamp,
            wallet_output_json,
            memo_parsed,
            memo_hex,
            payment_reference,
            is_burn,
            maturity
       )
       VALUES (
            :account_id,
            :tx_id,
            :output_hash,
            :block_height,
            :block_hash,
            :value,
            :mined_timestamp,
            :output_json,
            :memo_parsed,
            :memo_hex,
            :payment_reference,
            :is_burn,
            :maturity
       )
        "#,
        named_params! {
            ":account_id": account_id,
            ":tx_id": tx_id,
            ":output_hash": output_hash,
            ":block_height": block_height,
            ":block_hash": block_hash.as_slice(),
            ":value": value,
            ":mined_timestamp": mined_timestamp_dt,
            ":output_json": output_json,
            ":memo_parsed": memo_parsed,
            ":memo_hex": memo_hex,
            ":payment_reference": payment_reference_hex,
            ":is_burn": is_burn,
            ":maturity": maturity,
        },
    )?;

    Ok(conn.last_insert_rowid())
}

/// Inserts an output with `SpentUnconfirmed` status using `INSERT OR IGNORE`.
/// Used during backfill to avoid duplicate outputs in a single atomic statement.
/// Returns `Some(id)` if inserted, `None` if the output already existed.
#[allow(clippy::too_many_arguments)]
pub fn insert_spent_output_if_not_exists(
    conn: &Connection,
    account_id: i64,
    account_view_key: &PrivateKey,
    output_hash: Vec<u8>,
    output: &WalletOutput,
    block_height: u64,
    block_hash: &FixedHash,
    mined_timestamp: u64,
    memo_parsed: Option<String>,
    memo_hex: Option<String>,
    payment_reference: PaymentReference,
    is_burn: bool,
) -> WalletDbResult<Option<i64>> {
    let tx_id = TxId::new_deterministic(account_view_key.as_bytes(), &output.output_hash()).as_i64_wrapped();
    let output_json = serde_json::to_string(&output)?;

    #[allow(clippy::cast_possible_wrap)]
    let mined_timestamp_dt = DateTime::<Utc>::from_timestamp(mined_timestamp as i64, 0)
        .ok_or_else(|| WalletDbError::Decoding(format!("Invalid mined timestamp: {}", mined_timestamp)))?;

    #[allow(clippy::cast_possible_wrap)]
    let block_height = block_height as i64;
    #[allow(clippy::cast_possible_wrap)]
    let value = output.value().as_u64() as i64;
    let payment_reference_hex = hex::encode(payment_reference.as_slice());
    let status = OutputStatus::SpentUnconfirmed.to_string();

    conn.execute(
        r#"
       INSERT OR IGNORE INTO outputs (
            account_id,
            tx_id,
            output_hash,
            mined_in_block_height,
            mined_in_block_hash,
            value,
            mined_timestamp,
            wallet_output_json,
            memo_parsed,
            memo_hex,
            payment_reference,
            is_burn,
            status
       )
       VALUES (
            :account_id,
            :tx_id,
            :output_hash,
            :block_height,
            :block_hash,
            :value,
            :mined_timestamp,
            :output_json,
            :memo_parsed,
            :memo_hex,
            :payment_reference,
            :is_burn,
            :status
       )
        "#,
        named_params! {
            ":account_id": account_id,
            ":tx_id": tx_id,
            ":output_hash": output_hash,
            ":block_height": block_height,
            ":block_hash": block_hash.as_slice(),
            ":value": value,
            ":mined_timestamp": mined_timestamp_dt,
            ":output_json": output_json,
            ":memo_parsed": memo_parsed,
            ":memo_hex": memo_hex,
            ":payment_reference": payment_reference_hex,
            ":is_burn": is_burn,
            ":status": status,
        },
    )?;

    if conn.changes() == 0 {
        Ok(None)
    } else {
        Ok(Some(conn.last_insert_rowid()))
    }
}

/// Writes the change output of a send at send time, with status `UNCONFIRMED`.
///
/// The wallet's own block scan recognises a send by its change output (see
/// [`confirm_unconfirmed_change_output`]), so the row has to exist before the
/// send lands. It is linked to the send through `created_by_request_id`
/// (`pending_transactions.id`, the value the send's inputs carry in
/// `locked_by_request_id`).
///
/// The output has not been mined, so the NOT NULL `mined_*` columns hold
/// sentinel values: height 0, an empty block hash and the epoch as timestamp.
/// `tx_id` uses the same deterministic formula as [`insert_output`], so the scan
/// finds the same row. Senders that assemble a transaction outside
/// `TransactionManager` should call this after recording the completed
/// transaction.
pub fn insert_unconfirmed_change_output(
    conn: &Connection,
    account_id: i64,
    account_view_key: &PrivateKey,
    pending_tx_id: &str,
    output: &WalletOutput,
) -> WalletDbResult<i64> {
    info!(
        target: "audit",
        account_id = account_id,
        value = &*mask_amount(output.value());
        "DB: Inserting unconfirmed change output"
    );

    let output_hash = output.output_hash();
    let tx_id = TxId::new_deterministic(account_view_key.as_bytes(), &output_hash).as_i64_wrapped();
    let output_json = serde_json::to_string(&output)?;
    let mined_timestamp = DateTime::<Utc>::from_timestamp(0, 0)
        .ok_or_else(|| WalletDbError::Unexpected("Epoch timestamp is out of range".to_string()))?;

    let memo_bytes = output.payment_id().get_payment_id();
    let (memo_parsed, memo_hex) = if memo_bytes.is_empty() {
        (None, None)
    } else {
        (
            Some(String::from_utf8_lossy(&memo_bytes).to_string()),
            Some(hex::encode(&memo_bytes)),
        )
    };

    #[allow(clippy::cast_possible_wrap)]
    let value = output.value().as_u64() as i64;
    #[allow(clippy::cast_possible_wrap)]
    let maturity = output.features().maturity as i64;
    let status = OutputStatus::Unconfirmed.to_string();
    let empty_block_hash: Vec<u8> = Vec::new();

    conn.execute(
        r#"
       INSERT INTO outputs (
            account_id,
            tx_id,
            output_hash,
            mined_in_block_height,
            mined_in_block_hash,
            value,
            mined_timestamp,
            wallet_output_json,
            memo_parsed,
            memo_hex,
            payment_reference,
            is_burn,
            maturity,
            status,
            created_by_request_id
       )
       VALUES (
            :account_id,
            :tx_id,
            :output_hash,
            0,
            :block_hash,
            :value,
            :mined_timestamp,
            :output_json,
            :memo_parsed,
            :memo_hex,
            NULL,
            0,
            :maturity,
            :status,
            :request_id
       )
        "#,
        named_params! {
            ":account_id": account_id,
            ":tx_id": tx_id,
            ":output_hash": output_hash.to_vec(),
            ":block_hash": empty_block_hash,
            ":value": value,
            ":mined_timestamp": mined_timestamp,
            ":output_json": output_json,
            ":memo_parsed": memo_parsed,
            ":memo_hex": memo_hex,
            ":maturity": maturity,
            ":status": status,
            ":request_id": pending_tx_id,
        },
    )?;

    Ok(conn.last_insert_rowid())
}

/// Turns a send's change output, written at send time, into a mined output.
///
/// When the scan finds an output that already has an active `UNCONFIRMED` (or
/// `REJECTED`) row with the same hash, the row is updated in place: its mined
/// fields, payment reference and memo are set and its status becomes
/// `new_status`. Inserting a second row would violate the active unique index
/// on `output_hash`. A `REJECTED` row is updated too: the output exists on
/// chain, so it is real whatever the wallet concluded before.
///
/// A change output that a reorg reverted to `UNCONFIRMED` while a later send
/// had it locked as an input goes back to `LOCKED`, not `new_status`, but only
/// while that send can still land (its reservation pending, or it is completed
/// or broadcast). A lock left by a send that is gone is dropped, so the change
/// can never be stranded `LOCKED` for a dead request.
///
/// Returns the row id, or `None` when there was no such row and the caller
/// should insert the output as usual.
#[allow(clippy::too_many_arguments)]
pub fn confirm_unconfirmed_change_output(
    conn: &Connection,
    account_id: i64,
    output_hash: &FixedHash,
    block_height: u64,
    block_hash: &FixedHash,
    mined_timestamp: u64,
    memo_parsed: Option<String>,
    memo_hex: Option<String>,
    payment_reference: PaymentReference,
    new_status: OutputStatus,
) -> WalletDbResult<Option<i64>> {
    #[allow(clippy::cast_possible_wrap)]
    let mined_timestamp_dt = DateTime::<Utc>::from_timestamp(mined_timestamp as i64, 0)
        .ok_or_else(|| WalletDbError::Decoding(format!("Invalid mined timestamp: {}", mined_timestamp)))?;
    #[allow(clippy::cast_possible_wrap)]
    let block_height = block_height as i64;

    let live = lock_holder_is_live_sql("outputs.locked_by_request_id");
    let output_id: Option<i64> = conn
        .query_row(
            &format!(
                r#"
            UPDATE outputs
            SET mined_in_block_height = :block_height,
                mined_in_block_hash = :block_hash,
                mined_timestamp = :mined_timestamp,
                memo_parsed = :memo_parsed,
                memo_hex = :memo_hex,
                payment_reference = :payment_reference,
                status = CASE WHEN {live} THEN :locked ELSE :new_status END,
                locked_by_request_id = CASE WHEN {live} THEN locked_by_request_id ELSE NULL END,
                locked_at = CASE WHEN {live} THEN locked_at ELSE NULL END
            WHERE account_id = :account_id
              AND output_hash = :output_hash
              AND status IN (:unconfirmed, :rejected)
              AND deleted_at IS NULL
            RETURNING id
            "#
            ),
            named_params! {
                ":block_height": block_height,
                ":block_hash": block_hash.as_slice(),
                ":mined_timestamp": mined_timestamp_dt,
                ":memo_parsed": memo_parsed,
                ":memo_hex": memo_hex,
                ":payment_reference": hex::encode(payment_reference.as_slice()),
                ":new_status": new_status.to_string(),
                ":locked": OutputStatus::Locked.to_string(),
                ":account_id": account_id,
                ":output_hash": output_hash.as_slice(),
                ":unconfirmed": OutputStatus::Unconfirmed.to_string(),
                ":rejected": OutputStatus::Rejected.to_string(),
            },
            |row| row.get(0),
        )
        .optional()?;

    if let Some(id) = output_id {
        info!(
            target: "audit",
            account_id = account_id,
            output_id = id,
            height = block_height;
            "DB: Unconfirmed change output found in a block"
        );
    }

    Ok(output_id)
}

/// SQL condition that holds while the request whose id is `request_id_sql`
/// can still land, so a lock it holds on an output is live: its reservation is
/// `PENDING`, or its send is `completed` or `broadcast`.
///
/// The one definition of a live lock: [`is_lock_holder_live`],
/// [`clear_dead_lock`] and [`confirm_unconfirmed_change_output`] all use it.
fn lock_holder_is_live_sql(request_id_sql: &str) -> String {
    format!(
        "(EXISTS (SELECT 1 FROM pending_transactions p WHERE p.id = {req} AND p.status = '{pending}') \
         OR EXISTS (SELECT 1 FROM completed_transactions c WHERE c.pending_tx_id = {req} \
         AND c.status IN ('{completed}', '{broadcast}')))",
        req = request_id_sql,
        pending = PendingTransactionStatus::Pending,
        completed = CompletedTransactionStatus::Completed,
        broadcast = CompletedTransactionStatus::Broadcast,
    )
}

/// Whether request `request_id` can still land, so a lock it holds is live:
/// its reservation is `PENDING`, or its send is `completed` or `broadcast`.
pub fn is_lock_holder_live(conn: &Connection, request_id: &str) -> WalletDbResult<bool> {
    let live: bool = conn.query_row(
        &format!("SELECT {}", lock_holder_is_live_sql(":req")),
        named_params! { ":req": request_id },
        |row| row.get(0),
    )?;
    Ok(live)
}

/// Drops the lock on output `output_id` if the request holding it can no
/// longer land (see [`is_lock_holder_live`]); a `LOCKED` output becomes
/// `UNSPENT`. A live lock is left alone.
///
/// Returns whether a lock was dropped.
pub fn clear_dead_lock(conn: &Connection, output_id: i64) -> WalletDbResult<bool> {
    let live = lock_holder_is_live_sql("outputs.locked_by_request_id");
    let cleared = conn.execute(
        &format!(
            r#"
            UPDATE outputs
            SET status = CASE WHEN status = :locked THEN :unspent ELSE status END,
                locked_by_request_id = NULL,
                locked_at = NULL
            WHERE id = :id AND locked_by_request_id IS NOT NULL AND NOT {live}
            "#
        ),
        named_params! {
            ":id": output_id,
            ":locked": OutputStatus::Locked.to_string(),
            ":unspent": OutputStatus::Unspent.to_string(),
        },
    )?;
    if cleared > 0 {
        warn!(
            target: "audit",
            output_id = output_id;
            "DB: Dropped a lock held by a request that can no longer land"
        );
    }
    Ok(cleared > 0)
}

/// Soft-deletes the `UNCONFIRMED` change output of a send that will not be
/// broadcast (failed, cancelled or expired before it went out, or rejected).
pub fn soft_delete_unconfirmed_change_output(conn: &Connection, created_by_request_id: &str) -> WalletDbResult<()> {
    let deleted = conn.execute(
        r#"
        UPDATE outputs
        SET deleted_at = :now
        WHERE created_by_request_id = :req_id
          AND status = :unconfirmed
          AND deleted_at IS NULL
        "#,
        named_params! {
            ":now": Utc::now(),
            ":req_id": created_by_request_id,
            ":unconfirmed": OutputStatus::Unconfirmed.to_string(),
        },
    )?;

    if deleted > 0 {
        info!(
            target: "audit",
            "DB: Soft deleted unconfirmed change output"
        );
    }

    Ok(())
}

/// The change output of the send with `created_by_request_id`, if it has one,
/// including one soft-deleted when the send was rejected.
pub fn get_change_output_hash_for_request(
    conn: &Connection,
    created_by_request_id: &str,
) -> WalletDbResult<Option<FixedHash>> {
    let hash: Option<Vec<u8>> = conn
        .query_row(
            r#"
            SELECT output_hash
            FROM outputs
            WHERE created_by_request_id = :req_id
            ORDER BY id DESC
            LIMIT 1
            "#,
            named_params! { ":req_id": created_by_request_id },
            |row| row.get(0),
        )
        .optional()?;

    match hash {
        Some(bytes) => Ok(Some(
            FixedHash::try_from(bytes).map_err(|e| WalletDbError::Decoding(e.to_string()))?,
        )),
        None => Ok(None),
    }
}

/// The request (`pending_transactions.id`) that has this output locked, if any.
pub fn get_output_lock_request_id(conn: &Connection, output_id: i64) -> WalletDbResult<Option<String>> {
    let request_id: Option<Option<String>> = conn
        .query_row(
            "SELECT locked_by_request_id FROM outputs WHERE id = :id",
            named_params! { ":id": output_id },
            |row| row.get(0),
        )
        .optional()?;
    Ok(request_id.flatten())
}

/// If `output_hash` is the change output of a send the monitor rejected (no
/// `mined_height`), gets its change row ready to be found by the scan and
/// returns the send's `(pending transaction id, transaction id)`.
///
/// The change output appearing in a block is proof the send landed after all:
/// its hash is unique to the send. Rejecting the send soft-deleted the change
/// row (or, for a send kept rejected after a reorg, left it `REJECTED`). A
/// soft-deleted row is restored as `UNCONFIRMED`, so the scan updates it in
/// place and the change stays the send's change (`created_by_request_id`),
/// which a reorg then reverts rather than deletes. Nothing is restored if an
/// active row with that hash already exists.
pub fn restore_change_of_rejected_send(
    conn: &Connection,
    account_id: i64,
    output_hash: &FixedHash,
) -> WalletDbResult<Option<(String, TxId)>> {
    let row: Option<(i64, String, i64, bool)> = conn
        .query_row(
            r#"
            SELECT o.id, o.created_by_request_id, c.id, o.deleted_at IS NOT NULL
            FROM outputs o
            JOIN completed_transactions c ON c.pending_tx_id = o.created_by_request_id
            WHERE o.account_id = :account_id
              AND o.output_hash = :hash
              AND o.created_by_request_id IS NOT NULL
              AND (o.deleted_at IS NOT NULL OR o.status = :rejected_output)
              AND c.status = :rejected_tx
              AND c.mined_height IS NULL
            ORDER BY o.deleted_at IS NULL DESC, o.id DESC
            LIMIT 1
            "#,
            named_params! {
                ":account_id": account_id,
                ":hash": output_hash.as_slice(),
                ":rejected_output": OutputStatus::Rejected.to_string(),
                ":rejected_tx": crate::db::CompletedTransactionStatus::Rejected.to_string(),
            },
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((output_id, request_id, completed_id, is_deleted)) = row else {
        return Ok(None);
    };

    if is_deleted {
        let active: i64 = conn.query_row(
            "SELECT COUNT(*) FROM outputs WHERE output_hash = :hash AND deleted_at IS NULL",
            named_params! { ":hash": output_hash.as_slice() },
            |row| row.get(0),
        )?;
        if active > 0 {
            return Ok(None);
        }
        conn.execute(
            "UPDATE outputs SET deleted_at = NULL, status = :unconfirmed WHERE id = :id",
            named_params! { ":unconfirmed": OutputStatus::Unconfirmed.to_string(), ":id": output_id },
        )?;
    }

    info!(
        target: "audit",
        "DB: Change output of a rejected send found in a block"
    );
    #[allow(clippy::cast_sign_loss)]
    Ok(Some((request_id, TxId::from(completed_id as u64))))
}

/// Where the scan saw the wallet's output `output_hash` spent: the height and
/// block hash of its active input record, if it has one.
pub fn get_output_spend(
    conn: &Connection,
    account_id: i64,
    output_hash: &FixedHash,
) -> WalletDbResult<Option<(u64, Vec<u8>)>> {
    let spend: Option<(i64, Vec<u8>)> = conn
        .query_row(
            r#"
            SELECT i.mined_in_block_height, i.mined_in_block_hash
            FROM inputs i
            JOIN outputs o ON i.output_id = o.id
            WHERE o.account_id = :account_id
              AND o.output_hash = :hash
              AND o.deleted_at IS NULL
              AND i.deleted_at IS NULL
            "#,
            named_params! { ":account_id": account_id, ":hash": output_hash.as_slice() },
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    #[allow(clippy::cast_sign_loss)]
    Ok(spend.map(|(height, hash)| (height as u64, hash)))
}

/// Hashes of the wallet's outputs the scan saw spent in the block at `height`
/// with `block_hash` (active input records).
pub fn get_output_hashes_spent_in_block(
    conn: &Connection,
    account_id: i64,
    height: u64,
    block_hash: &[u8],
) -> WalletDbResult<Vec<FixedHash>> {
    #[allow(clippy::cast_possible_wrap)]
    let height = height as i64;
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT o.output_hash
        FROM inputs i
        JOIN outputs o ON i.output_id = o.id
        WHERE o.account_id = :account_id
          AND o.deleted_at IS NULL
          AND i.deleted_at IS NULL
          AND i.mined_in_block_height = :height
          AND i.mined_in_block_hash = :hash
        "#,
    )?;
    let rows = stmt.query_map(
        named_params! { ":account_id": account_id, ":height": height, ":hash": block_hash },
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    let mut hashes = Vec::new();
    for row in rows {
        hashes.push(FixedHash::try_from(row?).map_err(|e| WalletDbError::Decoding(e.to_string()))?);
    }
    Ok(hashes)
}

/// Hashes of the wallet's active outputs mined in the block at `height` with
/// `block_hash`.
pub fn get_output_hashes_mined_in_block(
    conn: &Connection,
    account_id: i64,
    height: u64,
    block_hash: &[u8],
) -> WalletDbResult<Vec<FixedHash>> {
    #[allow(clippy::cast_possible_wrap)]
    let height = height as i64;
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT output_hash
        FROM outputs
        WHERE account_id = :account_id
          AND deleted_at IS NULL
          AND mined_in_block_height = :height
          AND mined_in_block_hash = :hash
        "#,
    )?;
    let rows = stmt.query_map(
        named_params! { ":account_id": account_id, ":height": height, ":hash": block_hash },
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    let mut hashes = Vec::new();
    for row in rows {
        hashes.push(FixedHash::try_from(row?).map_err(|e| WalletDbError::Decoding(e.to_string()))?);
    }
    Ok(hashes)
}

/// Records `pending_tx_id` as the holder of the wallet's outputs it spent in a
/// block (`locked_by_request_id` on the `SPENT` rows for `input_hashes`).
///
/// An input released by one send and locked by another can be spent by the
/// first after all; the lock then names the wrong send. Reading it back (the
/// scan matching a re-mine, a reorg reviving a send) must find the real spender.
pub fn record_spender_of_inputs(
    conn: &Connection,
    account_id: i64,
    pending_tx_id: &str,
    input_hashes: &[FixedHash],
) -> WalletDbResult<()> {
    for input_hash in input_hashes {
        conn.execute(
            r#"
            UPDATE outputs
            SET locked_by_request_id = :req_id
            WHERE account_id = :account_id AND output_hash = :hash AND status = :spent AND deleted_at IS NULL
            "#,
            named_params! {
                ":req_id": pending_tx_id,
                ":account_id": account_id,
                ":hash": input_hash.as_slice(),
                ":spent": OutputStatus::Spent.to_string(),
            },
        )?;
    }
    Ok(())
}

/// Locks a send's inputs to it again, for a reorg that undid the scan's
/// rejection of the send.
///
/// The rejection released the inputs it still had locked, and the reorg undid
/// the spend of the others. Each input must now be either free (`UNSPENT`, not
/// locked), still locked to this send, or `SPENT` only by an input record the
/// reorg removed. Then all are locked to the send and `true` is returned. If any
/// input is locked by another request, spent in a block that is still on the
/// chain, or unknown, nothing is changed and `false` is returned: the send
/// cannot be revived.
pub fn relock_inputs_for_revived_send(
    conn: &Connection,
    account_id: i64,
    pending_tx_id: &str,
    input_hashes: &[FixedHash],
) -> WalletDbResult<bool> {
    let unspent = OutputStatus::Unspent.to_string();
    let locked = OutputStatus::Locked.to_string();
    let spent = OutputStatus::Spent.to_string();

    let mut output_ids = Vec::new();
    for input_hash in input_hashes {
        let row: Option<(i64, String, Option<String>)> = conn
            .query_row(
                r#"
                SELECT id, status, locked_by_request_id
                FROM outputs
                WHERE account_id = :account_id AND output_hash = :hash AND deleted_at IS NULL
                "#,
                named_params! { ":account_id": account_id, ":hash": input_hash.as_slice() },
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((output_id, status, locked_by)) = row else {
            return Ok(false);
        };

        let free = status == unspent && locked_by.is_none();
        let ours = locked_by.as_deref() == Some(pending_tx_id) && (status == locked || status == spent);
        // Spent only in the rolled-back blocks, and not by another send: an input
        // another send had locked and spent belongs to that send, which the reorg
        // resets to be rebroadcast with it.
        let locked_by_us_or_nobody = locked_by.is_none() || locked_by.as_deref() == Some(pending_tx_id);
        let spent_in_removed_block = status == spent && locked_by_us_or_nobody && {
            let active_spends: i64 = conn.query_row(
                "SELECT COUNT(*) FROM inputs WHERE output_id = :id AND deleted_at IS NULL",
                named_params! { ":id": output_id },
                |row| row.get(0),
            )?;
            active_spends == 0
        };
        let still_spent_on_chain = status == spent && !spent_in_removed_block;
        if still_spent_on_chain || !(free || ours || spent_in_removed_block) {
            return Ok(false);
        }
        output_ids.push(output_id);
    }

    for output_id in output_ids {
        conn.execute(
            r#"
            UPDATE outputs
            SET status = :locked, locked_by_request_id = :req_id, locked_at = :now
            WHERE id = :id
            "#,
            named_params! {
                ":locked": locked.as_str(),
                ":req_id": pending_tx_id,
                ":now": Utc::now(),
                ":id": output_id,
            },
        )?;
    }
    Ok(true)
}

/// Marks the `UNCONFIRMED` change output of a send `REJECTED`: the send's
/// inputs were spent by a different transaction, so the change will never exist.
pub fn mark_change_output_rejected(conn: &Connection, created_by_request_id: &str) -> WalletDbResult<()> {
    warn!(
        target: "audit",
        "DB: Marking unconfirmed change output rejected"
    );
    conn.execute(
        r#"
        UPDATE outputs
        SET status = :rejected
        WHERE created_by_request_id = :req_id AND status = :unconfirmed AND deleted_at IS NULL
        "#,
        named_params! {
            ":rejected": OutputStatus::Rejected.to_string(),
            ":req_id": created_by_request_id,
            ":unconfirmed": OutputStatus::Unconfirmed.to_string(),
        },
    )?;
    Ok(())
}

/// Turns a `REJECTED` change output back into `UNCONFIRMED`, for a send whose
/// rejection a reorg undid.
pub fn revert_rejected_change_output(conn: &Connection, created_by_request_id: &str) -> WalletDbResult<()> {
    conn.execute(
        r#"
        UPDATE outputs
        SET status = :unconfirmed
        WHERE created_by_request_id = :req_id AND status = :rejected AND deleted_at IS NULL
        "#,
        named_params! {
            ":unconfirmed": OutputStatus::Unconfirmed.to_string(),
            ":req_id": created_by_request_id,
            ":rejected": OutputStatus::Rejected.to_string(),
        },
    )?;
    Ok(())
}

#[derive(Deserialize)]
pub struct ChangeOutputToRevert {
    pub id: i64,
    pub output_hash: Vec<u8>,
    pub mined_in_block_height: i64,
    pub value: i64,
}

/// Turns the change outputs of sends mined at or above `height` back into
/// `UNCONFIRMED`, for a reorg.
///
/// A send's change output must survive a reorg: the send itself is reverted to
/// `Completed` and rebroadcast, and the scan recognises it again by this row.
/// So instead of being soft-deleted like other outputs (see
/// [`soft_delete_outputs_from_height`]), it gets its sentinel `mined_*` values
/// back and loses its payment reference and confirmation. Its credit is
/// reversed exactly as a soft-deleted output's would be.
///
/// Returns the reverted rows so the caller can report them as rolled back.
pub fn revert_change_outputs_from_height(
    conn: &Connection,
    account_id: i64,
    height: u64,
) -> WalletDbResult<Vec<ChangeOutputToRevert>> {
    warn!(
        target: "audit",
        account_id = account_id,
        height = height;
        "DB: Reverting mined change outputs to unconfirmed (Reorg)"
    );
    #[allow(clippy::cast_possible_wrap)]
    let height_i64 = height as i64;
    let now = Utc::now();

    let outputs_to_revert = {
        let mut stmt = conn.prepare_cached(
            r#"
            SELECT id, output_hash, mined_in_block_height, value
            FROM outputs
            WHERE account_id = :account_id
              AND created_by_request_id IS NOT NULL
              AND mined_in_block_height >= :height
              AND deleted_at IS NULL
              AND status NOT IN (:unconfirmed, :rejected)
            "#,
        )?;
        let rows = stmt.query(named_params! {
            ":account_id": account_id,
            ":height": height_i64,
            ":unconfirmed": OutputStatus::Unconfirmed.to_string(),
            ":rejected": OutputStatus::Rejected.to_string(),
        })?;
        from_rows::<ChangeOutputToRevert>(rows).collect::<Result<Vec<_>, _>>()?
    };

    let epoch = DateTime::<Utc>::from_timestamp(0, 0)
        .ok_or_else(|| WalletDbError::Unexpected("Epoch timestamp is out of range".to_string()))?;
    let empty_block_hash: Vec<u8> = Vec::new();

    for output_row in &outputs_to_revert {
        let original_balance_change_id = get_balance_change_id_by_output(conn, output_row.id)?;
        if let Some(original_id) = original_balance_change_id {
            mark_balance_change_as_reversed(conn, original_id)?;
        }

        let balance_change = BalanceChange {
            account_id,
            caused_by_output_id: Some(output_row.id),
            caused_by_input_id: None,
            description: format!(
                "Reversal: Change output found in blockchain scan (reorg at height {})",
                height
            ),
            balance_credit: 0.into(),
            balance_debit: (output_row.value as u64).into(),
            effective_date: now.naive_utc(),
            effective_height: height,
            claimed_recipient_address: None,
            claimed_sender_address: None,
            memo_parsed: None,
            memo_hex: None,
            claimed_fee: None,
            claimed_amount: None,
            is_reversal: true,
            reversal_of_balance_change_id: original_balance_change_id,
            is_reversed: false,
        };
        insert_balance_change(conn, &balance_change)?;

        conn.execute(
            r#"
            UPDATE outputs
            SET status = :unconfirmed,
                mined_in_block_height = 0,
                mined_in_block_hash = :block_hash,
                mined_timestamp = :epoch,
                payment_reference = NULL,
                confirmed_height = NULL,
                confirmed_hash = NULL
            WHERE id = :id
            "#,
            named_params! {
                ":unconfirmed": OutputStatus::Unconfirmed.to_string(),
                ":block_hash": empty_block_hash,
                ":epoch": epoch,
                ":id": output_row.id,
            },
        )?;
    }

    Ok(outputs_to_revert)
}

pub fn get_output_info_by_hash(
    conn: &Connection,
    output_hash: &FixedHash,
) -> WalletDbResult<Option<(i64, TxId, WalletOutput)>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, tx_id, wallet_output_json
        FROM outputs
        WHERE output_hash = :output_hash AND deleted_at IS NULL
        "#,
    )?;

    let rows = stmt.query(named_params! { ":output_hash": output_hash.as_slice() })?;
    let row: Option<WalletOutputRow> = from_rows(rows).next().transpose()?;
    let data = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    let output: WalletOutput = serde_json::from_str(&data.wallet_output_json)?;

    let tx_id = TxId::from(data.tx_id as u64);

    Ok(Some((data.id, tx_id, output)))
}

pub fn get_output_info_by_hash_for_account(
    conn: &Connection,
    account_id: i64,
    output_hash: &FixedHash,
) -> WalletDbResult<Option<(i64, TxId, WalletOutput)>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, tx_id, wallet_output_json
        FROM outputs
        WHERE account_id = :account_id AND output_hash = :output_hash AND deleted_at IS NULL
        "#,
    )?;

    let rows = stmt.query(named_params! {
        ":account_id": account_id,
        ":output_hash": output_hash.as_slice(),
    })?;
    let row: Option<WalletOutputRow> = from_rows(rows).next().transpose()?;
    let data = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    let output: WalletOutput = serde_json::from_str(&data.wallet_output_json)?;

    let tx_id = TxId::from(data.tx_id as u64);

    Ok(Some((data.id, tx_id, output)))
}

#[derive(Deserialize)]
pub struct UnconfirmedOutputRow {
    pub output_hash: FixedHash,
    pub mined_in_block_height: i64,
    pub memo_parsed: Option<String>,
    pub memo_hex: Option<String>,
    pub tx_id: i64,
    pub is_burn: i64,
}

pub fn get_unconfirmed_outputs(
    conn: &Connection,
    account_id: i64,
    current_height: u64,
    confirmation_blocks: u64,
) -> WalletDbResult<Vec<UnconfirmedOutputRow>> {
    let min_height_to_confirm = current_height.saturating_sub(confirmation_blocks);
    #[allow(clippy::cast_possible_wrap)]
    let min_height = min_height_to_confirm as i64;

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT output_hash, mined_in_block_height, memo_parsed, memo_hex, tx_id, is_burn
        FROM outputs o
        WHERE o.account_id = :account_id
          AND o.mined_in_block_height <= :min_height
          AND o.confirmed_height IS NULL
          AND o.deleted_at IS NULL
          AND o.status NOT IN (:unconfirmed, :rejected)
        "#,
    )?;

    // `UNCONFIRMED` and `REJECTED` change outputs were never mined; their
    // height 0 is a sentinel, not a depth to confirm.
    let rows = stmt.query(named_params! {
        ":account_id": account_id,
        ":min_height": min_height,
        ":unconfirmed": OutputStatus::Unconfirmed.to_string(),
        ":rejected": OutputStatus::Rejected.to_string(),
    })?;

    let result_rows: Vec<UnconfirmedOutputRow> = from_rows(rows).collect::<Result<Vec<_>, _>>()?;
    Ok(result_rows)
}

pub fn mark_output_confirmed(
    conn: &Connection,
    output_hash: &FixedHash,
    confirmed_height: u64,
    confirmed_hash: &[u8],
) -> WalletDbResult<()> {
    info!(
        target: "audit",
        height = confirmed_height;
        "DB: Output Confirmed"
    );

    #[allow(clippy::cast_possible_wrap)]
    let confirmed_height = confirmed_height as i64;
    conn.execute(
        r#"
        UPDATE outputs
        SET confirmed_height = :height, confirmed_hash = :hash
        WHERE output_hash = :output_hash
        "#,
        named_params! {
            ":height": confirmed_height,
            ":hash": confirmed_hash,
            ":output_hash": output_hash.to_vec(),
        },
    )?;

    Ok(())
}

#[derive(Deserialize)]
struct OutputToDelete {
    id: i64,
    value: i64,
}

/// Soft-deletes the outputs mined at or above `height` and reverses their credits, for a reorg.
///
/// A send's change output (`created_by_request_id` set) is not deleted; see
/// [`revert_change_outputs_from_height`].
pub fn soft_delete_outputs_from_height(conn: &Connection, account_id: i64, height: u64) -> WalletDbResult<()> {
    warn!(
        target: "audit",
        account_id = account_id,
        height = height;
        "DB: Soft deleting outputs (Reorg)"
    );
    #[allow(clippy::cast_possible_wrap)]
    let height_i64 = height as i64;
    let now = Utc::now();

    let outputs_to_delete = {
        let mut stmt = conn.prepare_cached(
            r#"
            SELECT id, value
            FROM outputs
            WHERE account_id = :account_id AND mined_in_block_height >= :height AND deleted_at IS NULL
              AND status NOT IN (:unconfirmed, :rejected)
              AND created_by_request_id IS NULL
            "#,
        )?;

        let rows = stmt.query(named_params! {
            ":account_id": account_id,
            ":height": height_i64,
            ":unconfirmed": OutputStatus::Unconfirmed.to_string(),
            ":rejected": OutputStatus::Rejected.to_string(),
        })?;

        from_rows::<OutputToDelete>(rows).collect::<Result<Vec<_>, _>>()?
    };

    for output_row in outputs_to_delete {
        // Find and mark the original balance change as reversed
        let original_balance_change_id = get_balance_change_id_by_output(conn, output_row.id)?;
        if let Some(original_id) = original_balance_change_id {
            mark_balance_change_as_reversed(conn, original_id)?;
        }

        let balance_change = BalanceChange {
            account_id,
            caused_by_output_id: Some(output_row.id),
            caused_by_input_id: None,
            description: format!("Reversal: Output found in blockchain scan (reorg at height {})", height),
            balance_credit: 0.into(),
            balance_debit: (output_row.value as u64).into(),
            effective_date: now.naive_utc(),
            effective_height: height,
            claimed_recipient_address: None,
            claimed_sender_address: None,
            memo_parsed: None,
            memo_hex: None,
            claimed_fee: None,
            claimed_amount: None,
            is_reversal: true,
            reversal_of_balance_change_id: original_balance_change_id,
            is_reversed: false,
        };
        insert_balance_change(conn, &balance_change)?;
    }

    conn.execute(
        r#"
        UPDATE outputs
        SET deleted_at = :now, deleted_in_block_height = :height, payment_reference = NULL
        WHERE account_id = :account_id AND mined_in_block_height >= :height AND deleted_at IS NULL
          AND status NOT IN (:unconfirmed, :rejected)
          AND created_by_request_id IS NULL
        "#,
        named_params! {
            ":now": now,
            ":height": height_i64,
            ":account_id": account_id,
            ":unconfirmed": OutputStatus::Unconfirmed.to_string(),
            ":rejected": OutputStatus::Rejected.to_string(),
        },
    )?;

    Ok(())
}

/// Marks `SpentUnconfirmed` outputs that have a matching input as `Spent`.
/// Returns the number of outputs marked as spent.
pub fn resolve_spent_unconfirmed_with_inputs(conn: &Connection, account_id: i64) -> WalletDbResult<u64> {
    let spent_unconfirmed = OutputStatus::SpentUnconfirmed.to_string();
    let spent = OutputStatus::Spent.to_string();

    let marked_spent = conn.execute(
        r#"
        UPDATE outputs
        SET status = :spent_status
        WHERE account_id = :account_id
          AND status = :spent_unconfirmed_status
          AND deleted_at IS NULL
          AND id IN (
              SELECT output_id FROM inputs WHERE deleted_at IS NULL
          )
        "#,
        named_params! {
            ":spent_status": spent,
            ":account_id": account_id,
            ":spent_unconfirmed_status": spent_unconfirmed,
        },
    )? as u64;

    info!(
        target: "audit",
        account_id = account_id,
        marked_spent = marked_spent;
        "Resolved SpentUnconfirmed outputs with matching inputs"
    );

    Ok(marked_spent)
}

/// Returned data for an unresolved SpentUnconfirmed output.
pub struct UnresolvedSpentOutput {
    pub output_id: i64,
    pub output_hash: Vec<u8>,
    pub mined_in_block_height: u64,
    pub value: u64,
}

/// Returns info for remaining `SpentUnconfirmed` outputs that have no matching input.
/// These need to be verified against the base node.
pub fn get_unresolved_spent_unconfirmed_outputs(
    conn: &Connection,
    account_id: i64,
) -> WalletDbResult<Vec<UnresolvedSpentOutput>> {
    let spent_unconfirmed = OutputStatus::SpentUnconfirmed.to_string();

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, output_hash, mined_in_block_height, value
        FROM outputs
        WHERE account_id = :account_id
          AND status = :status
          AND deleted_at IS NULL
        ORDER BY mined_in_block_height
        "#,
    )?;

    let rows = stmt.query_map(
        named_params! {
            ":account_id": account_id,
            ":status": spent_unconfirmed,
        },
        |row| {
            Ok(UnresolvedSpentOutput {
                output_id: row.get(0)?,
                output_hash: row.get(1)?,
                mined_in_block_height: row.get::<_, i64>(2).map(|h| h as u64)?,
                value: row.get::<_, i64>(3).map(|v| v as u64)?,
            })
        },
    )?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row?);
    }

    Ok(results)
}

pub fn update_output_status(conn: &Connection, output_id: i64, status: OutputStatus) -> WalletDbResult<()> {
    debug!(
        output_id = output_id,
        status:% = status;
        "DB: Updating output status"
    );

    let status_str = status.to_string();
    conn.execute(
        r#"
        UPDATE outputs
        SET status = :status
        WHERE id = :id
        "#,
        named_params! {
            ":status": status_str,
            ":id": output_id
        },
    )?;

    Ok(())
}

/// Reserves an output for `locked_by_request_id`, but only if it is still `Unspent`.
///
/// The `AND status = :unspent_status` clause makes this a compare-and-swap: the
/// row transitions `Unspent → Locked` exactly once, no matter how many writers
/// race for it. The result of that comparison is the whole point of the
/// statement, so a no-op update is reported as
/// [`WalletDbError::OutputLockConflict`] rather than being swallowed — silently
/// returning `Ok(())` on zero rows would hand the caller a UTXO that some other
/// writer already owns, and both would go on to spend it.
///
/// Callers should run this inside the same write transaction that selected the
/// output, so that a conflict rolls back the whole reservation.
pub fn lock_output(
    conn: &Connection,
    output_id: i64,
    locked_by_request_id: &str,
    locked_at: DateTime<Utc>,
) -> WalletDbResult<()> {
    info!(
        target: "audit",
        output_id = output_id;
        "DB: Locking output"
    );

    let locked_status = OutputStatus::Locked.to_string();
    let unspent_status = OutputStatus::Unspent.to_string();

    let rows_locked = conn.execute(
        r#"
        UPDATE outputs
        SET status = :locked_status, locked_by_request_id = :req_id, locked_at = :locked_at
        WHERE id = :id and status = :unspent_status
        "#,
        named_params! {
            ":locked_status": locked_status,
            ":req_id": locked_by_request_id,
            ":locked_at": locked_at,
            ":id": output_id,
            ":unspent_status": unspent_status,
        },
    )?;

    if rows_locked == 0 {
        warn!(
            target: "audit",
            output_id = output_id;
            "DB: Output is no longer unspent; lock lost the race"
        );
        return Err(WalletDbError::OutputLockConflict {
            output_id,
            request_id: locked_by_request_id.to_string(),
        });
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbWalletOutput {
    pub id: i64,
    pub tx_id: TxId,
    pub output: WalletOutput,
}

impl UtxoValue for DbWalletOutput {
    fn value(&self) -> MicroMinotari {
        self.output.value()
    }
}

#[derive(Deserialize, Debug)]
struct WalletOutputRow {
    id: i64,
    tx_id: i64,
    wallet_output_json: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DbOutput {
    pub id: i64,
    pub account_id: i64,
    pub output_hash: Vec<u8>,
    pub mined_in_block_hash: Vec<u8>,
    pub mined_in_block_height: i64,
    pub value: i64,
    pub created_at: chrono::NaiveDateTime,
    pub wallet_output_json: Option<String>,
    pub mined_timestamp: chrono::NaiveDateTime,
    pub confirmed_height: Option<i64>,
    pub confirmed_hash: Option<Vec<u8>>,
    pub memo_parsed: Option<String>,
    pub memo_hex: Option<String>,
    pub status: String,
    pub locked_at: Option<chrono::NaiveDateTime>,
    pub locked_by_request_id: Option<String>,
    pub deleted_at: Option<chrono::NaiveDateTime>,
    pub deleted_in_block_height: Option<i64>,
    pub payment_reference: Option<String>,
    pub maturity: i64,
}

impl DbOutput {
    pub fn to_wallet_output(&self) -> WalletDbResult<WalletOutput> {
        let output_str = self
            .wallet_output_json
            .as_ref()
            .ok_or_else(|| WalletDbError::Unexpected("Output JSON is null".to_string()))?;
        let output: WalletOutput = serde_json::from_str(output_str)?;
        Ok(output)
    }
}

pub fn get_output_by_id(conn: &Connection, output_id: i64) -> WalletDbResult<Option<DbOutput>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, account_id, output_hash, mined_in_block_hash, mined_in_block_height,
               value, created_at, wallet_output_json, mined_timestamp, confirmed_height,
               confirmed_hash, memo_parsed, memo_hex, status, locked_at, locked_by_request_id,
               deleted_at, deleted_in_block_height, payment_reference, maturity
        FROM outputs
        WHERE id = :id
        "#,
    )?;

    let rows = stmt.query(named_params! { ":id": output_id })?;
    let output: Option<DbOutput> = from_rows(rows).next().transpose()?;
    Ok(output)
}

pub fn fetch_unspent_outputs(
    conn: &Connection,
    account_id: i64,
    min_height: u64,
    tip_height: u64,
) -> WalletDbResult<Vec<DbWalletOutput>> {
    let unspent_status = OutputStatus::Unspent.to_string();
    #[allow(clippy::cast_possible_wrap)]
    let min_height_i64 = min_height as i64;
    // Clamp to i64::MAX so very-large `tip_height` values do not wrap to a
    // negative i64 (which would invert the maturity comparison).
    #[allow(clippy::cast_possible_wrap)]
    let tip_height_i64 = tip_height.min(i64::MAX as u64) as i64;

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, tx_id, wallet_output_json
        FROM outputs
        WHERE account_id = :account_id
          AND status = :unspent_status
          AND mined_in_block_height <= :min_height
          AND maturity >= 0
          AND maturity <= :tip_height
          AND deleted_at IS NULL
          AND is_burn = 0
        ORDER BY value DESC
        "#,
    )?;

    let rows = stmt.query(named_params! {
        ":account_id": account_id,
        ":unspent_status": unspent_status,
        ":min_height": min_height_i64,
        ":tip_height": tip_height_i64,
    })?;
    let raw_rows: Vec<WalletOutputRow> = from_rows(rows).collect::<Result<Vec<_>, _>>()?;

    let mut outputs = Vec::new();
    for row in raw_rows {
        let output: WalletOutput = serde_json::from_str(&row.wallet_output_json)?;
        outputs.push(DbWalletOutput {
            id: row.id,
            tx_id: TxId::from(row.tx_id as u64),
            output,
        });
    }
    Ok(outputs)
}

pub fn unlock_outputs_for_request(conn: &Connection, locked_by_request_id: &str) -> WalletDbResult<()> {
    debug!("DB: Unlocking outputs for request");

    let unspent_status = OutputStatus::Unspent.to_string();
    let locked_status = OutputStatus::Locked.to_string();

    conn.execute(
        r#"
        UPDATE outputs
        SET status = :unspent, locked_at = NULL, locked_by_request_id = NULL
        WHERE locked_by_request_id = :req_id AND status = :locked
        "#,
        named_params! {
            ":unspent": unspent_status,
            ":req_id": locked_by_request_id,
            ":locked": locked_status
        },
    )?;

    // An input of this request can be another send's change output that a reorg
    // turned back into `UNCONFIRMED` (see `revert_change_outputs_from_height`), and
    // that send may since have been rejected (`REJECTED`). Release that lock too,
    // or the change would come back `LOCKED` for a request that no longer exists
    // when it is mined again.
    conn.execute(
        r#"
        UPDATE outputs
        SET locked_at = NULL, locked_by_request_id = NULL
        WHERE locked_by_request_id = :req_id AND status IN (:unconfirmed, :rejected)
        "#,
        named_params! {
            ":req_id": locked_by_request_id,
            ":unconfirmed": OutputStatus::Unconfirmed.to_string(),
            ":rejected": OutputStatus::Rejected.to_string(),
        },
    )?;

    // A send whose inputs are handed back will not land, so neither will its
    // change output.
    soft_delete_unconfirmed_change_output(conn, locked_by_request_id)?;

    Ok(())
}

pub fn fetch_outputs_by_lock_request_id(
    conn: &Connection,
    locked_by_request_id: &str,
) -> WalletDbResult<Vec<DbWalletOutput>> {
    let mut stmt =
        conn.prepare_cached("SELECT id, tx_id, wallet_output_json FROM outputs WHERE locked_by_request_id = :req_id")?;

    let rows = stmt.query(named_params! { ":req_id": locked_by_request_id })?;
    let raw_rows: Vec<WalletOutputRow> = from_rows(rows).collect::<Result<Vec<_>, _>>()?;

    let mut outputs = Vec::new();
    for row in raw_rows {
        let output: WalletOutput = serde_json::from_str(&row.wallet_output_json)?;
        outputs.push(DbWalletOutput {
            id: row.id,
            tx_id: TxId::from(row.tx_id as u64),
            output,
        });
    }
    Ok(outputs)
}

#[derive(Deserialize)]
struct OutputTotalsRow {
    locked_val: i64,
    unconfirmed_val: i64,
    pending_change_val: i64,
    immature_val: i64,
    available_val: i64,
}

/// Disjoint UTXO total breakdown for an account, in MicroMinotari.
///
/// Every non-spent, non-burn, non-deleted, non-rejected output is counted in
/// exactly one of `locked`, `unconfirmed`, `immature` or `available`.
/// Precedence (matching the SQL CASE order):
/// 1. `status = LOCKED`                                              → `locked`
/// 2. else `status = UNCONFIRMED` (a send's change, not yet mined)   → `unconfirmed`
/// 3. else `confirmed_height IS NULL`                                → `unconfirmed`
/// 4. else `maturity > tip_height` (or wrapped negative)             → `immature`
/// 5. else                                                           → `available`
///
/// `REJECTED` change outputs are never counted.
///
/// `unavailable = locked + unconfirmed + immature` (the funds the user has but
/// cannot spend right now), except that an `UNCONFIRMED` change output is left
/// out of `unavailable`: it is pending-incoming only, and is not yet part of
/// the balance-change ledger that `unavailable` is subtracted from.
#[derive(Debug, Clone, Copy)]
pub struct OutputTotals {
    pub available: MicroMinotari,
    pub unconfirmed: MicroMinotari,
    pub locked: MicroMinotari,
    pub immature: MicroMinotari,
    pub unavailable: MicroMinotari,
}

/// Retrieves UTXO total breakdowns for an account. `tip_height` is the latest
/// scanned chain tip; an output is `immature` when its maturity is in the
/// future (or wrapped negative due to the u64→i64 cast on insert).
pub fn get_output_totals_for_account(
    conn: &Connection,
    account_id: i64,
    tip_height: u64,
) -> WalletDbResult<OutputTotals> {
    let locked_status = OutputStatus::Locked.to_string();
    let unspent_status = OutputStatus::Unspent.to_string();
    // See `fetch_unspent_outputs` for the rationale behind clamping.
    #[allow(clippy::cast_possible_wrap)]
    let tip_height_i64 = tip_height.min(i64::MAX as u64) as i64;

    // Each non-spent, non-burn, non-deleted output falls into exactly one
    // bucket via the precedence baked into the nested CASE expressions.
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT
            COALESCE(SUM(CASE
                WHEN status = :locked THEN value
                ELSE 0
            END), 0) as locked_val,
            COALESCE(SUM(CASE
                WHEN status = :locked THEN 0
                WHEN status = :unconfirmed_change THEN 0
                WHEN confirmed_height IS NULL THEN value
                ELSE 0
            END), 0) as unconfirmed_val,
            COALESCE(SUM(CASE
                WHEN status = :unconfirmed_change THEN value
                ELSE 0
            END), 0) as pending_change_val,
            COALESCE(SUM(CASE
                WHEN status = :locked THEN 0
                WHEN status = :unconfirmed_change THEN 0
                WHEN confirmed_height IS NULL THEN 0
                WHEN maturity < 0 OR maturity > :tip_height THEN value
                ELSE 0
            END), 0) as immature_val,
            COALESCE(SUM(CASE
                WHEN status = :unspent
                     AND confirmed_height IS NOT NULL
                     AND maturity >= 0
                     AND maturity <= :tip_height
                THEN value
                ELSE 0
            END), 0) as available_val
        FROM outputs
        WHERE account_id = :account_id AND deleted_at IS NULL AND is_burn = 0 AND status != :rejected
        "#,
    )?;

    let rows = stmt.query(named_params! {
        ":locked": locked_status,
        ":unspent": unspent_status,
        ":unconfirmed_change": OutputStatus::Unconfirmed.to_string(),
        ":rejected": OutputStatus::Rejected.to_string(),
        ":account_id": account_id,
        ":tip_height": tip_height_i64,
    })?;

    let result = from_rows::<OutputTotalsRow>(rows)
        .next()
        .ok_or_else(|| WalletDbError::Unexpected("Aggregate query returned no rows".to_string()))??;

    let locked: MicroMinotari = (result.locked_val as u64).into();
    let mined_unconfirmed: MicroMinotari = (result.unconfirmed_val as u64).into();
    let pending_change: MicroMinotari = (result.pending_change_val as u64).into();
    let immature: MicroMinotari = (result.immature_val as u64).into();
    let available: MicroMinotari = (result.available_val as u64).into();
    let unconfirmed = mined_unconfirmed.saturating_add(pending_change);
    let unavailable = locked.saturating_add(mined_unconfirmed).saturating_add(immature);

    Ok(OutputTotals {
        available,
        unconfirmed,
        locked,
        immature,
        unavailable,
    })
}

#[derive(Deserialize)]
pub struct ReorgOutputInfo {
    pub output_hash: Vec<u8>,
    pub mined_in_block_height: i64,
    pub locked_by_request_id: Option<String>,
}

/// Active outputs mined at or above `height`, which a reorg soft-deletes.
///
/// A send's change output (`created_by_request_id` set) is left out: a reorg
/// reverts it instead (see [`revert_change_outputs_from_height`]).
pub fn get_active_outputs_from_height(
    conn: &Connection,
    account_id: i64,
    height: u64,
) -> WalletDbResult<Vec<ReorgOutputInfo>> {
    #[allow(clippy::cast_possible_wrap)]
    let height_i64 = height as i64;

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT output_hash, mined_in_block_height, locked_by_request_id
        FROM outputs
        WHERE account_id = :account_id
          AND mined_in_block_height >= :height
          AND deleted_at IS NULL
          AND status NOT IN (:unconfirmed, :rejected)
          AND created_by_request_id IS NULL
        "#,
    )?;

    let rows = stmt.query(named_params! {
        ":account_id": account_id,
        ":height": height_i64,
        ":unconfirmed": OutputStatus::Unconfirmed.to_string(),
        ":rejected": OutputStatus::Rejected.to_string(),
    })?;

    let results = from_rows::<ReorgOutputInfo>(rows).collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Sum of unspent, mature outputs for an account, in MicroMinotari.
///
/// Outputs whose maturity exceeds `tip_height` are excluded so the caller
/// cannot mistake immature funds for spendable balance.
pub fn get_total_unspent_balance(conn: &Connection, account_id: i64, tip_height: u64) -> WalletDbResult<u64> {
    let unspent_status = OutputStatus::Unspent.to_string();
    // See `fetch_unspent_outputs` for the rationale behind clamping.
    #[allow(clippy::cast_possible_wrap)]
    let tip_height_i64 = tip_height.min(i64::MAX as u64) as i64;

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT COALESCE(SUM(value), 0)
        FROM outputs
        WHERE account_id = :account_id
          AND status = :unspent_status
          AND maturity >= 0
          AND maturity <= :tip_height
          AND deleted_at IS NULL
          AND is_burn = 0
        "#,
    )?;

    let total: i64 = stmt.query_row(
        named_params! {
            ":account_id": account_id,
            ":unspent_status": unspent_status,
            ":tip_height": tip_height_i64,
        },
        |row| row.get(0),
    )?;

    // Output values are never negative, so a negative sum cannot happen.
    Ok(u64::try_from(total).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::cast_lossless)]
    #![allow(clippy::cast_possible_wrap)]
    #![allow(clippy::too_many_arguments)]
    use super::*;
    use crate::db::{create_account, get_account_by_name, init_db};
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
    use tempfile::tempdir;

    /// Insert a synthetic outputs row directly. Avoids constructing a real
    /// `WalletOutput` (which requires keys and ranges) so we can assert the
    /// SQL filter logic in isolation.
    fn insert_synthetic_output(
        conn: &Connection,
        account_id: i64,
        output_hash: u8,
        value: u64,
        mined_in_block_height: u64,
        confirmed: bool,
        status: OutputStatus,
        maturity: i64,
    ) {
        let confirmed_height: Option<i64> = if confirmed {
            Some(mined_in_block_height as i64)
        } else {
            None
        };
        let confirmed_hash: Option<Vec<u8>> = if confirmed { Some(vec![1u8; 32]) } else { None };
        conn.execute(
            r#"
            INSERT INTO outputs (
                account_id, tx_id, output_hash, mined_in_block_height, mined_in_block_hash, value,
                mined_timestamp, wallet_output_json, status, confirmed_height, confirmed_hash,
                is_burn, maturity
            ) VALUES (
                :account_id, :tx_id, :output_hash, :height, :block_hash, :value,
                :mined_ts, :json, :status, :confirmed_height, :confirmed_hash,
                0, :maturity
            )
            "#,
            named_params! {
                ":account_id": account_id,
                ":tx_id": output_hash as i64,
                ":output_hash": vec![output_hash; 32],
                ":height": mined_in_block_height as i64,
                ":block_hash": vec![output_hash; 32],
                ":value": value as i64,
                ":mined_ts": Utc::now(),
                ":json": "{}",
                ":status": status.to_string(),
                ":confirmed_height": confirmed_height,
                ":confirmed_hash": confirmed_hash,
                ":maturity": maturity,
            },
        )
        .expect("insert synthetic output");
    }

    fn create_test_account(conn: &Connection) -> i64 {
        let seeds = CipherSeed::random();
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(seeds).unwrap());
        create_account(conn, "default", &wallet, "password").unwrap();
        get_account_by_name(conn, "default").unwrap().unwrap().id
    }

    #[test]
    fn unspent_balance_excludes_immature() {
        // Verifies the maturity filter on the spendable-balance aggregate.
        // (`fetch_unspent_outputs` deserializes `wallet_output_json`, which we
        // can't forge cheaply; the totals query uses the same SQL filter so
        // exercising it here is sufficient.)
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("maturity.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account_id = create_test_account(&conn);

        // Mature spendable output (maturity 50 ≤ tip 150).
        insert_synthetic_output(&conn, account_id, 1, 1_000, 100, true, OutputStatus::Unspent, 50);
        // Immature output (maturity 200 > tip 150).
        insert_synthetic_output(&conn, account_id, 2, 5_000, 100, true, OutputStatus::Unspent, 200);
        // Output that matures exactly at the tip — must still be selectable.
        insert_synthetic_output(&conn, account_id, 3, 2_000, 100, true, OutputStatus::Unspent, 150);

        let total = get_total_unspent_balance(&conn, account_id, 150).expect("total");
        assert_eq!(total, 1_000 + 2_000, "immature 5_000 µT must be excluded");

        // Advance the tip past the immature maturity height; it now becomes spendable.
        let total_after_tip = get_total_unspent_balance(&conn, account_id, 200).expect("total");
        assert_eq!(total_after_tip, 1_000 + 5_000 + 2_000);
    }

    #[test]
    fn output_totals_partition_is_disjoint() {
        // Verifies that every output falls into exactly one of available /
        // locked / unconfirmed / immature, with precedence locked >
        // unconfirmed > immature > available, and that
        // `unavailable = locked + unconfirmed + immature`.
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("maturity_totals.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account_id = create_test_account(&conn);

        // Confirmed, mature, unspent — `available` (1_000).
        insert_synthetic_output(&conn, account_id, 1, 1_000, 50, true, OutputStatus::Unspent, 0);
        // Confirmed, immature, unspent — `immature` (4_000).
        insert_synthetic_output(&conn, account_id, 2, 4_000, 50, true, OutputStatus::Unspent, 500);
        // Unconfirmed, mature, unspent — `unconfirmed` (2_000).
        insert_synthetic_output(&conn, account_id, 3, 2_000, 99, false, OutputStatus::Unspent, 0);
        // Locked, mature, confirmed — `locked` (8_000).
        insert_synthetic_output(&conn, account_id, 4, 8_000, 50, true, OutputStatus::Locked, 0);
        // Locked + unconfirmed + immature — only the highest-precedence bucket
        // (locked) gets credit (16_000).
        insert_synthetic_output(&conn, account_id, 5, 16_000, 99, false, OutputStatus::Locked, 500);

        let totals = get_output_totals_for_account(&conn, account_id, 100).expect("totals");
        assert_eq!(totals.available, MicroMinotari::from(1_000));
        assert_eq!(totals.unconfirmed, MicroMinotari::from(2_000));
        assert_eq!(totals.immature, MicroMinotari::from(4_000));
        assert_eq!(totals.locked, MicroMinotari::from(8_000 + 16_000));
        assert_eq!(totals.unavailable, MicroMinotari::from(2_000 + 4_000 + 8_000 + 16_000));
        // Sanity: every non-spent output was credited exactly once.
        assert_eq!(
            totals.available.saturating_add(totals.unavailable),
            MicroMinotari::from(1_000 + 2_000 + 4_000 + 8_000 + 16_000),
        );
    }

    #[test]
    fn negative_maturity_is_treated_as_immature() {
        // `WalletOutput.features().maturity` is u64 but the column is i64; values
        // above i64::MAX wrap to a negative i64 on insert. Such outputs must be
        // treated as immature (never spendable) rather than slipping through the
        // `maturity <= tip` comparison.
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("maturity_wrap.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account_id = create_test_account(&conn);

        // Spendable output (small positive maturity).
        insert_synthetic_output(&conn, account_id, 1, 1_000, 50, true, OutputStatus::Unspent, 10);
        // Wrapped maturity (originally u64::MAX → -1 after `as i64`).
        insert_synthetic_output(&conn, account_id, 2, 9_000, 50, true, OutputStatus::Unspent, -1);
        // Another wrap representative.
        insert_synthetic_output(&conn, account_id, 3, 5_000, 50, true, OutputStatus::Unspent, i64::MIN);

        let total = get_total_unspent_balance(&conn, account_id, u64::MAX).expect("total");
        assert_eq!(
            total, 1_000,
            "wrapped-negative maturities must be excluded even at tip = u64::MAX"
        );

        let totals = get_output_totals_for_account(&conn, account_id, u64::MAX).expect("totals");
        // Both wrapped rows count as immature (and unavailable). The non-wrapped
        // row has small positive maturity so it is `available`.
        assert_eq!(totals.available, MicroMinotari::from(1_000));
        assert_eq!(totals.immature, MicroMinotari::from(9_000 + 5_000));
        assert_eq!(totals.unavailable, MicroMinotari::from(9_000 + 5_000));
    }

    /// Read back the `(status, locked_by_request_id)` pair for an output.
    fn output_lock_state(conn: &Connection, output_id: i64) -> (String, Option<String>) {
        conn.query_row(
            "SELECT status, locked_by_request_id FROM outputs WHERE id = :id",
            named_params! { ":id": output_id },
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read output lock state")
    }

    fn only_output_id(conn: &Connection, account_id: i64) -> i64 {
        conn.query_row(
            "SELECT id FROM outputs WHERE account_id = :account_id",
            named_params! { ":account_id": account_id },
            |row| row.get(0),
        )
        .expect("read output id")
    }

    #[test]
    fn lock_output_rejects_an_output_that_is_no_longer_unspent() {
        // The conditional UPDATE matches no row when the output has already been
        // spent. Reporting success there would hand the caller a UTXO that is
        // gone, so it must be an error.
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("lock_conflict.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account_id = create_test_account(&conn);

        insert_synthetic_output(&conn, account_id, 1, 1_000, 50, true, OutputStatus::Spent, 0);
        let output_id = only_output_id(&conn, account_id);

        let err = lock_output(&conn, output_id, "req-1", Utc::now()).expect_err("spent output cannot be locked");
        assert!(
            matches!(&err, WalletDbError::OutputLockConflict { output_id: id, request_id } if *id == output_id && request_id == "req-1"),
            "expected OutputLockConflict, got: {err}"
        );

        // The losing request must not have stamped its id onto the row.
        let (status, locked_by) = output_lock_state(&conn, output_id);
        assert_eq!(status, OutputStatus::Spent.to_string());
        assert_eq!(locked_by, None);
    }

    #[test]
    fn only_one_request_can_lock_an_output() {
        // Two requests racing for the same UTXO: the first wins, the second is
        // told it lost rather than being allowed to believe it owns the output.
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("lock_race.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account_id = create_test_account(&conn);

        insert_synthetic_output(&conn, account_id, 1, 1_000, 50, true, OutputStatus::Unspent, 0);
        let output_id = only_output_id(&conn, account_id);

        lock_output(&conn, output_id, "req-winner", Utc::now()).expect("first lock succeeds");
        let err = lock_output(&conn, output_id, "req-loser", Utc::now()).expect_err("second lock is refused");
        assert!(matches!(err, WalletDbError::OutputLockConflict { .. }), "got: {err}");

        // Ownership still belongs to the winner.
        let (status, locked_by) = output_lock_state(&conn, output_id);
        assert_eq!(status, OutputStatus::Locked.to_string());
        assert_eq!(locked_by.as_deref(), Some("req-winner"));
    }

    #[test]
    fn a_lock_conflict_rolls_back_the_whole_reservation() {
        // Callers lock a set of outputs inside one write transaction. If any
        // single lock loses its race the transaction must not commit, otherwise
        // the caller gets a half-reserved selection it will still try to spend.
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("lock_rollback.db")).expect("init db");
        let mut conn = pool.get().expect("conn");
        let account_id = create_test_account(&conn);

        insert_synthetic_output(&conn, account_id, 1, 1_000, 50, true, OutputStatus::Unspent, 0);
        insert_synthetic_output(&conn, account_id, 2, 2_000, 50, true, OutputStatus::Spent, 0);
        let mut ids: Vec<i64> = conn
            .prepare("SELECT id FROM outputs WHERE account_id = :account_id ORDER BY id")
            .expect("prepare")
            .query_map(named_params! { ":account_id": account_id }, |row| row.get(0))
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("collect ids");
        ids.sort_unstable();
        let (unspent_id, spent_id) = (ids[0], ids[1]);

        let transaction = conn.transaction().expect("begin");
        lock_output(&transaction, unspent_id, "req-1", Utc::now()).expect("first output locks");
        lock_output(&transaction, spent_id, "req-1", Utc::now()).expect_err("second output is already spent");
        drop(transaction); // no commit → rollback

        let (status, locked_by) = output_lock_state(&conn, unspent_id);
        assert_eq!(
            status,
            OutputStatus::Unspent.to_string(),
            "the successful lock must roll back with the failed one"
        );
        assert_eq!(locked_by, None);
    }

    #[test]
    fn rejected_change_is_never_counted_and_unconfirmed_change_is_only_pending_incoming() {
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("change_totals.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account_id = create_test_account(&conn);

        // A spendable output, plus a send's change in each of the two new states.
        insert_synthetic_output(&conn, account_id, 1, 1_000, 50, true, OutputStatus::Unspent, 0);
        insert_synthetic_output(&conn, account_id, 2, 300, 0, false, OutputStatus::Unconfirmed, 0);
        insert_synthetic_output(&conn, account_id, 3, 7_000, 0, false, OutputStatus::Rejected, 0);

        let totals = get_output_totals_for_account(&conn, account_id, 100).expect("totals");
        assert_eq!(totals.available, MicroMinotari::from(1_000));
        assert_eq!(totals.locked, MicroMinotari::from(0));
        assert_eq!(totals.immature, MicroMinotari::from(0));
        // The unconfirmed change shows as pending-incoming...
        assert_eq!(totals.unconfirmed, MicroMinotari::from(300));
        // ...but is not in the ledger yet, so it must not reduce `available`.
        assert_eq!(totals.unavailable, MicroMinotari::from(0));

        assert_eq!(get_total_unspent_balance(&conn, account_id, 100).expect("total"), 1_000);

        // Neither state is ever confirmed by the scan's depth check: height 0 is a sentinel.
        let to_confirm = get_unconfirmed_outputs(&conn, account_id, 1_000, 3).expect("unconfirmed outputs");
        assert!(to_confirm.is_empty(), "sentinel rows must not be confirmed");
    }

    #[test]
    fn unconfirmed_and_rejected_change_is_never_selected_or_locked() {
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("change_select.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account_id = create_test_account(&conn);

        insert_synthetic_output(&conn, account_id, 2, 300, 0, false, OutputStatus::Unconfirmed, 0);
        insert_synthetic_output(&conn, account_id, 3, 7_000, 0, false, OutputStatus::Rejected, 0);

        let selectable = fetch_unspent_outputs(&conn, account_id, 1_000, 1_000).expect("fetch");
        assert!(selectable.is_empty(), "change rows must never be selectable");

        let ids: Vec<i64> = conn
            .prepare("SELECT id FROM outputs WHERE account_id = :account_id")
            .expect("prepare")
            .query_map(named_params! { ":account_id": account_id }, |row| row.get(0))
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("ids");
        assert_eq!(ids.len(), 2);
        for id in ids {
            let result = lock_output(&conn, id, "request", Utc::now());
            assert!(
                matches!(result, Err(WalletDbError::OutputLockConflict { .. })),
                "output {id} must not be lockable"
            );
        }
    }

    #[test]
    fn unlocking_a_request_soft_deletes_its_unconfirmed_change() {
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("change_cleanup.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account_id = create_test_account(&conn);

        insert_synthetic_output(&conn, account_id, 2, 300, 0, false, OutputStatus::Unconfirmed, 0);
        conn.execute(
            "UPDATE outputs SET created_by_request_id = 'request-1' WHERE account_id = :account_id",
            named_params! { ":account_id": account_id },
        )
        .expect("link change to request");

        unlock_outputs_for_request(&conn, "other-request").expect("unlock other");
        let active: i64 = conn
            .query_row("SELECT COUNT(*) FROM outputs WHERE deleted_at IS NULL", [], |row| {
                row.get(0)
            })
            .expect("count");
        assert_eq!(active, 1, "another request's cleanup must not touch this change");

        unlock_outputs_for_request(&conn, "request-1").expect("unlock");
        let active: i64 = conn
            .query_row("SELECT COUNT(*) FROM outputs WHERE deleted_at IS NULL", [], |row| {
                row.get(0)
            })
            .expect("count");
        assert_eq!(active, 0, "the change of a send that will not land is soft-deleted");
    }

    #[test]
    fn unlocking_a_request_releases_a_reverted_change_output_it_had_locked() {
        // Send A's change C was mined, locked as an input by send B, then turned
        // back into `UNCONFIRMED` by a reorg. If B is then released, C must not
        // come back `LOCKED` for B when it is mined again.
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("reverted_change_lock.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account_id = create_test_account(&conn);

        insert_synthetic_output(&conn, account_id, 2, 300, 0, false, OutputStatus::Unconfirmed, 0);
        conn.execute(
            "UPDATE outputs SET created_by_request_id = 'send-a', locked_by_request_id = 'send-b', locked_at = :now",
            named_params! { ":now": Utc::now() },
        )
        .expect("lock reverted change to B");

        unlock_outputs_for_request(&conn, "send-b").expect("release B");

        let (status, lock): (String, Option<String>) = conn
            .query_row(
                "SELECT status, locked_by_request_id FROM outputs WHERE deleted_at IS NULL",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("change row is still active");
        assert_eq!(status, "UNCONFIRMED");
        assert_eq!(lock, None, "B's lock is released");

        let found = confirm_unconfirmed_change_output(
            &conn,
            account_id,
            &FixedHash::from([2u8; 32]),
            60,
            &FixedHash::from([60u8; 32]),
            1_700_000_000,
            None,
            None,
            FixedHash::zero(),
            OutputStatus::Unspent,
        )
        .expect("confirm");
        assert!(found.is_some());
        let status: String = conn
            .query_row("SELECT status FROM outputs", [], |row| row.get(0))
            .expect("status");
        assert_eq!(
            status, "UNSPENT",
            "re-mined change is spendable, not locked to a dead request"
        );
    }

    #[test]
    fn a_rejected_change_releases_the_lock_of_a_released_request_and_never_comes_back_locked_for_it() {
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("rejected_change_lock.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account_id = create_test_account(&conn);

        // A rejected change, still locked by a send that is gone.
        insert_synthetic_output(&conn, account_id, 2, 300, 0, false, OutputStatus::Rejected, 0);
        conn.execute(
            "UPDATE outputs SET created_by_request_id = 'send-x', locked_by_request_id = 'send-y', locked_at = :now",
            named_params! { ":now": Utc::now() },
        )
        .expect("lock");

        unlock_outputs_for_request(&conn, "send-y").expect("release y");
        let lock: Option<String> = conn
            .query_row("SELECT locked_by_request_id FROM outputs", [], |row| row.get(0))
            .expect("lock");
        assert_eq!(lock, None);

        // Even with a stale lock left behind, a mined change is not restored as
        // LOCKED for a request that is no longer live.
        conn.execute("UPDATE outputs SET locked_by_request_id = 'dead-request'", [])
            .expect("stale lock");
        confirm_unconfirmed_change_output(
            &conn,
            account_id,
            &FixedHash::from([2u8; 32]),
            60,
            &FixedHash::from([60u8; 32]),
            1_700_000_000,
            None,
            None,
            FixedHash::zero(),
            OutputStatus::Unspent,
        )
        .expect("confirm");
        let (status, lock): (String, Option<String>) = conn
            .query_row("SELECT status, locked_by_request_id FROM outputs", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .expect("row");
        assert_eq!(status, "UNSPENT");
        assert_eq!(lock, None);
    }
}
