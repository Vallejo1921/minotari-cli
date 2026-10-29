use crate::db::error::{WalletDbError, WalletDbResult};
use crate::log::mask_amount;
use crate::models::BalanceChange;
use log::debug;
use rusqlite::{Connection, OptionalExtension, named_params};
use serde::Deserialize;
use serde_rusqlite::from_rows;

#[allow(clippy::cast_possible_wrap)]
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
    // Unlike the credit/debit above, these two come from the sender-controlled memo and are never validated against
    // the commitment, so they can be any u64. SQLite integers are signed, and a wrapping `as i64` cast would persist a
    // negative that no longer deserialises back into `MicroMinotari`, breaking every later read of this account's
    // balance changes. Saturate instead: these are unverified claims kept for display only, and no real amount comes
    // anywhere near `i64::MAX`.
    let claimed_fee = change
        .claimed_fee
        .map(|v| i64::try_from(v.as_u64()).unwrap_or(i64::MAX));
    let claimed_amount = change
        .claimed_amount
        .map(|v| i64::try_from(v.as_u64()).unwrap_or(i64::MAX));

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

/// Inserts a balance change only if one does not already exist for the given output or input.
/// Used during backfill to avoid duplicate balance entries (balance_changes has no unique constraint).
/// Returns `Some(id)` if inserted, `None` if a matching record already existed.
pub fn insert_balance_change_if_not_exists(conn: &Connection, change: &BalanceChange) -> WalletDbResult<Option<i64>> {
    // Check by output_id or input_id to see if this balance change was already recorded
    if let Some(output_id) = change.caused_by_output_id
        && get_balance_change_id_by_output(conn, output_id)?.is_some()
    {
        return Ok(None);
    }
    if let Some(input_id) = change.caused_by_input_id
        && get_balance_change_id_by_input(conn, input_id)?.is_some()
    {
        return Ok(None);
    }

    let id = insert_balance_change(conn, change)?;
    Ok(Some(id))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{create_account, get_account_by_name, init_db};
    use chrono::Utc;
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

    fn credit_change(account_id: i64, claimed_amount: u64, claimed_fee: u64) -> BalanceChange {
        BalanceChange {
            account_id,
            caused_by_output_id: None,
            caused_by_input_id: None,
            description: "test".to_string(),
            balance_credit: MicroMinotari::from(1),
            balance_debit: MicroMinotari::from(0),
            effective_date: Utc::now().naive_utc(),
            effective_height: 50,
            claimed_recipient_address: None,
            claimed_sender_address: None,
            memo_parsed: None,
            memo_hex: None,
            claimed_fee: Some(MicroMinotari::from(claimed_fee)),
            claimed_amount: Some(MicroMinotari::from(claimed_amount)),
            is_reversal: false,
            reversal_of_balance_change_id: None,
            is_reversed: false,
        }
    }

    fn stored_claims(conn: &Connection, id: i64) -> (i64, i64) {
        conn.query_row(
            "SELECT claimed_amount, claimed_fee FROM balance_changes WHERE id = :id",
            named_params! { ":id": id },
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read back claims")
    }

    #[test]
    fn hostile_claimed_amount_is_never_stored_negative() {
        // `claimed_amount`/`claimed_fee` are copied out of a sender-controlled memo without validation, so they can be
        // any u64. SQLite integers are signed, so a wrapping cast would persist a negative — a value that is not a
        // valid `MicroMinotari` and that no reader can make sense of.
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("claims.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account_id = create_test_account(&conn);

        let hostile = insert_balance_change(&conn, &credit_change(account_id, u64::MAX, u64::MAX)).expect("insert");
        assert_eq!(stored_claims(&conn, hostile), (i64::MAX, i64::MAX));

        // Ordinary claims are still stored exactly.
        let ordinary = insert_balance_change(&conn, &credit_change(account_id, 1_234, 56)).expect("insert");
        assert_eq!(stored_claims(&conn, ordinary), (1_234, 56));
    }
}
