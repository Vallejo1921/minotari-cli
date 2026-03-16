use crate::db::error::{WalletDbError, WalletDbResult};
use crate::log::mask_amount;
use crate::models::BalanceChange;
use log::debug;
use rusqlite::{Connection, OptionalExtension, named_params};
use serde::Deserialize;
use serde_rusqlite::from_rows;

pub fn insert_balance_change(conn: &Connection, change: &BalanceChange) -> WalletDbResult<i64> {
    debug!(
        target: "audit",
        account_id = change.account_id,
        credit = &*mask_amount(change.balance_credit),
        debit = &*mask_amount(change.balance_debit),
        is_reversal = change.is_reversal;
        "DB: Inserting balance change"
    );

    let balance_credit = change.balance_credit.as_u64() as i64;
    let balance_debit = change.balance_debit.as_u64() as i64;
    let effective_height = change.effective_height as i64;
    let claimed_fee = change.claimed_fee.map(|v| v.as_u64() as i64);
    let claimed_amount = change.claimed_amount.map(|v| v.as_u64() as i64);

    conn.execute(
        r#"
       INSERT INTO balance_changes (
         account_id,
         caused_by_output_id,
         caused_by_input_id,
         description,
         balance_credit,
         balance_debit,
         effective_date,
         effective_height,
         claimed_recipient_address,
         claimed_sender_address,
         memo_parsed,
         memo_hex,
         claimed_fee,
         claimed_amount,
         is_reversal,
         reversal_of_balance_change_id,
         is_reversed)
         VALUES (
            :account_id,
            :caused_by_output_id,
            :caused_by_input_id,
            :description,
            :balance_credit,
            :balance_debit,
            :effective_date,
            :effective_height,
            :claimed_recipient_address,
            :claimed_sender_address,
            :memo_parsed,
            :memo_hex,
            :claimed_fee,
            :claimed_amount,
            :is_reversal,
            :reversal_of_balance_change_id,
            :is_reversed
         )
        "#,
        named_params! {
            ":account_id": change.account_id,
            ":caused_by_output_id": change.caused_by_output_id,
            ":caused_by_input_id": change.caused_by_input_id,
            ":description": change.description,
            ":balance_credit": balance_credit,
            ":balance_debit": balance_debit,
            ":effective_date": change.effective_date,
            ":effective_height": effective_height,
            ":claimed_recipient_address": change.claimed_recipient_address.as_ref().map(|v| v.to_base58()),
            ":claimed_sender_address": change.claimed_sender_address.as_ref().map(|v| v.to_base58()),
            ":memo_parsed": change.memo_parsed,
            ":memo_hex": change.memo_hex,
            ":claimed_fee": claimed_fee,
            ":claimed_amount": claimed_amount,
            ":is_reversal": change.is_reversal,
            ":reversal_of_balance_change_id": change.reversal_of_balance_change_id,
            ":is_reversed": change.is_reversed,
        },
    )?;

    let id = conn.last_insert_rowid();
    Ok(id)
}

pub fn get_all_balance_changes_by_account_id(conn: &Connection, account_id: i64) -> WalletDbResult<Vec<BalanceChange>> {
    debug!(
        account_id = account_id;
        "DB: Fetching all balance changes"
    );

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT 
            account_id,
            caused_by_output_id,
            caused_by_input_id,
            description,
            balance_credit,
            balance_debit,
            REPLACE(effective_date, ' ', 'T') as effective_date,
            effective_height,
            claimed_recipient_address,
            claimed_sender_address,
            memo_parsed,
            memo_hex,
            claimed_fee,
            claimed_amount,
            is_reversal,
            reversal_of_balance_change_id,
            is_reversed
        FROM balance_changes
        WHERE account_id = :account_id
        ORDER BY effective_height ASC, id ASC
        "#,
    )?;

    let rows = stmt.query(named_params! { ":account_id": account_id })?;
    let results: Vec<BalanceChange> = from_rows::<BalanceChange>(rows).collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

// ignores all balance changes that have been reversed
pub fn get_all_active_balance_changes_by_account_id(
    conn: &Connection,
    account_id: i64,
) -> WalletDbResult<Vec<BalanceChange>> {
    debug!(
        account_id = account_id;
        "DB: Fetching all balance changes"
    );

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT
            account_id,
            caused_by_output_id,
            caused_by_input_id,
            description,
            balance_credit,
            balance_debit,
            REPLACE(effective_date, ' ', 'T') as effective_date,
            effective_height,
            claimed_recipient_address,
            claimed_sender_address,
            memo_parsed,
            memo_hex,
            claimed_fee,
            claimed_amount,
            is_reversal,
            reversal_of_balance_change_id,
            is_reversed
        FROM balance_changes
        WHERE account_id = :account_id AND is_reversed = FALSE AND is_reversal = FALSE
        ORDER BY effective_height ASC, id ASC
        "#,
    )?;

    let rows = stmt.query(named_params! { ":account_id": account_id })?;
    let results: Vec<BalanceChange> = from_rows::<BalanceChange>(rows).collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

#[derive(Debug, Default, Deserialize)]
pub struct DbBalanceAggregates {
    pub total_credits: Option<i64>,
    pub total_debits: Option<i64>,
    pub max_height: Option<i64>,
    pub max_date: Option<chrono::NaiveDateTime>,
}

pub fn get_balance_aggregates_for_account(conn: &Connection, account_id: i64) -> WalletDbResult<DbBalanceAggregates> {
    let mut stmt = conn.prepare_cached(
        r#"
            SELECT
              SUM(balance_credit) as total_credits,
              SUM(balance_debit) as total_debits,
              MAX(effective_height) as max_height,
              REPLACE(MAX(effective_date), ' ', 'T') as max_date
            FROM balance_changes
            WHERE account_id = :account_id
        "#,
    )?;

    let rows = stmt.query(named_params! { ":account_id": account_id })?;
    let result = from_rows::<DbBalanceAggregates>(rows)
        .next()
        .ok_or_else(|| WalletDbError::Unexpected("Aggregate query returned no rows".to_string()))??;
    Ok(result)
}

/// Get the balance change ID for an output (non-reversal balance changes only)
pub fn get_balance_change_id_by_output(conn: &Connection, output_id: i64) -> WalletDbResult<Option<i64>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id
        FROM balance_changes
        WHERE caused_by_output_id = :output_id
          AND is_reversal = FALSE
          AND is_reversed = FALSE
        ORDER BY id DESC
        LIMIT 1
        "#,
    )?;

    let id: Option<i64> = stmt
        .query_row(named_params! { ":output_id": output_id }, |row| row.get(0))
        .optional()?;

    Ok(id)
}

/// Get the balance change ID for an input (non-reversal balance changes only)
pub fn get_balance_change_id_by_input(conn: &Connection, input_id: i64) -> WalletDbResult<Option<i64>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id
        FROM balance_changes
        WHERE caused_by_input_id = :input_id
          AND is_reversal = FALSE
          AND is_reversed = FALSE
        ORDER BY id DESC
        LIMIT 1
        "#,
    )?;

    let id: Option<i64> = stmt
        .query_row(named_params! { ":input_id": input_id }, |row| row.get(0))
        .optional()?;

    Ok(id)
}

/// Mark a balance change as reversed
pub fn mark_balance_change_as_reversed(conn: &Connection, balance_change_id: i64) -> WalletDbResult<()> {
    debug!(
        balance_change_id = balance_change_id;
        "DB: Marking balance change as reversed"
    );

    conn.execute(
        r#"
        UPDATE balance_changes
        SET is_reversed = TRUE
        WHERE id = :id
        "#,
        named_params! { ":id": balance_change_id },
    )?;

    Ok(())
}
