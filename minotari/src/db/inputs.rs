use crate::db::balance_changes::{
    get_balance_change_id_by_input, insert_balance_change, mark_balance_change_as_reversed,
};
use crate::db::error::{WalletDbError, WalletDbResult};
use crate::models::BalanceChange;
use chrono::{DateTime, NaiveDateTime, Utc};
use log::{debug, warn};
use rusqlite::{Connection, named_params};
use serde::Deserialize;
use serde_rusqlite::from_rows;

#[derive(Debug, Clone, Deserialize)]
pub struct DbInput {
    pub id: i64,
    pub account_id: i64,
    pub output_id: i64,
    pub mined_in_block_hash: Vec<u8>,
    pub mined_in_block_height: i64,
    pub mined_timestamp: NaiveDateTime,
    pub created_at: NaiveDateTime,
    pub deleted_at: Option<NaiveDateTime>,
    pub deleted_in_block_height: Option<i64>,
}

pub fn get_input_by_id(conn: &Connection, input_id: i64) -> WalletDbResult<Option<DbInput>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, account_id, output_id, mined_in_block_hash, mined_in_block_height,
               mined_timestamp, created_at, deleted_at, deleted_in_block_height
        FROM inputs
        WHERE id = :id
        "#,
    )?;

    let rows = stmt.query(named_params! { ":id": input_id })?;
    let input: Option<DbInput> = from_rows(rows).next().transpose()?;
    Ok(input)
}

pub fn insert_input(
    conn: &Connection,
    account_id: i64,
    output_id: i64,
    mined_in_block_height: u64,
    mined_in_block_hash: &[u8],
    mined_timestamp: u64,
) -> WalletDbResult<i64> {
    debug!(
        target: "audit",
        account_id = account_id,
        output_id = output_id,
        height = mined_in_block_height;
        "DB: Inserting input"
    );

    #[allow(clippy::cast_possible_wrap)]
    let timestamp = DateTime::<Utc>::from_timestamp(mined_timestamp as i64, 0)
        .ok_or_else(|| WalletDbError::Decoding(format!("Invalid mined timestamp: {}", mined_timestamp)))?;
    #[allow(clippy::cast_possible_wrap)]
    let mined_in_block_height = mined_in_block_height as i64;

    conn.execute(
        r#"
       INSERT OR IGNORE INTO inputs (
            account_id,
            output_id,
            mined_in_block_height,
            mined_in_block_hash,
            mined_timestamp
       )
       VALUES (
            :account_id,
            :output_id,
            :block_height,
            :block_hash,
            :timestamp
       ) 
        "#,
        named_params! {
            ":account_id": account_id,
            ":output_id": output_id,
            ":block_height": mined_in_block_height,
            ":block_hash": mined_in_block_hash,
            ":timestamp": timestamp
        },
    )?;

    let input_id: i64 = conn.query_row(
        "SELECT id FROM inputs WHERE output_id = :output_id AND deleted_at IS NULL",
        named_params! { ":output_id": output_id },
        |row| row.get(0),
    )?;

    Ok(input_id)
}

#[derive(Deserialize)]
struct InputToDelete {
    input_id: i64,
    output_id: i64,
    output_value: i64,
}

pub fn soft_delete_inputs_from_height(conn: &Connection, account_id: i64, height: u64) -> WalletDbResult<()> {
    warn!(
        target: "audit",
        account_id = account_id,
        height = height;
        "DB: Soft deleting inputs (Reorg)"
    );
    #[allow(clippy::cast_possible_wrap)]
    let height_i64 = height as i64;
    let now = Utc::now();

    let inputs_with_output_values = {
        let mut stmt = conn.prepare_cached(
            r#"
            SELECT i.id as input_id, o.id as output_id, o.value as output_value
            FROM inputs i
            JOIN outputs o ON i.output_id = o.id
            WHERE i.account_id = :account_id
              AND i.mined_in_block_height >= :height
              AND i.deleted_at IS NULL
            "#,
        )?;

        let rows = stmt.query(named_params! {
            ":account_id": account_id,
            ":height": height_i64
        })?;

        from_rows::<InputToDelete>(rows).collect::<Result<Vec<_>, _>>()?
    };

    for row in inputs_with_output_values {
        // Find and mark the original balance change as reversed
        let original_balance_change_id = get_balance_change_id_by_input(conn, row.input_id)?;
        if let Some(original_id) = original_balance_change_id {
            mark_balance_change_as_reversed(conn, original_id)?;
        }

        let balance_change = BalanceChange {
            account_id,
            caused_by_output_id: Some(row.output_id),
            caused_by_input_id: Some(row.input_id),
            description: format!("Reversal: Input spent as input (reorg at height {})", height),
            balance_credit: (row.output_value as u64).into(), // Reversing a debit, so credit the value back
            balance_debit: 0.into(),
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
        UPDATE inputs
        SET deleted_at = :now, deleted_in_block_height = :height
        WHERE account_id = :account_id AND mined_in_block_height >= :height AND deleted_at IS NULL
        "#,
        named_params! {
            ":now": now,
            ":height": height_i64,
            ":account_id": account_id
        },
    )?;

    Ok(())
}
