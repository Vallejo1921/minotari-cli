use crate::db::error::WalletDbResult;
use log::{debug, warn};
use rusqlite::{Connection, OptionalExtension, named_params};
use tari_common_types::transaction::TxId;

/// Save an old payref to the history table before it is cleared during a reorg.
/// This allows lookups by stale payrefs to still resolve to the correct transaction.
///
/// `TxId` is a `u64`; SQLite does not support unsigned 64-bit integers, so the
/// id is stored as the wrapping `i64` (`TxId::as_i64_wrapped`) and converted
/// back on read. This matches how `completed_transactions.id` is persisted.
pub fn save_payref_history(
    conn: &Connection,
    account_id: i64,
    transaction_id: TxId,
    old_payref: &str,
    output_hash: Option<&str>,
) -> WalletDbResult<()> {
    debug!(
        account_id = account_id,
        transaction_id = transaction_id.to_string().as_str(),
        old_payref = old_payref;
        "DB: Saving payref to history"
    );

    conn.execute(
        r#"
        INSERT INTO payref_history (account_id, transaction_id, old_payref, output_hash)
        VALUES (:account_id, :transaction_id, :old_payref, :output_hash)
        "#,
        named_params! {
            ":account_id": account_id,
            ":transaction_id": transaction_id.as_i64_wrapped(),
            ":old_payref": old_payref,
            ":output_hash": output_hash,
        },
    )?;

    Ok(())
}

/// Look up a transaction id by a historical (stale) payref.
/// Returns the most-recently-saved match, if any.
pub fn get_transaction_id_by_historical_payref(
    conn: &Connection,
    account_id: i64,
    payref: &str,
) -> WalletDbResult<Option<TxId>> {
    debug!(
        account_id = account_id,
        payref = payref;
        "DB: Looking up historical payref"
    );

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT transaction_id
        FROM payref_history
        WHERE account_id = :account_id AND old_payref = :payref
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )?;

    let result = stmt
        .query_row(
            named_params! {
                ":account_id": account_id,
                ":payref": payref
            },
            |row| row.get::<_, i64>(0),
        )
        .optional()?;

    #[allow(clippy::cast_sign_loss)]
    Ok(result.map(|id| TxId::from(id as u64)))
}

/// Save historical payrefs for displayed transactions being reorganized.
/// Called before the displayed transaction payref column gets overwritten on re-mine.
pub fn save_displayed_transaction_payrefs_before_reorg(
    conn: &Connection,
    account_id: i64,
    reorg_height: u64,
) -> WalletDbResult<u64> {
    warn!(
        account_id = account_id,
        height = reorg_height;
        "DB: Saving displayed transaction payrefs before reorg"
    );

    #[allow(clippy::cast_possible_wrap)]
    let height = reorg_height as i64;

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, payref
        FROM displayed_transactions
        WHERE account_id = :account_id
          AND payref IS NOT NULL
          AND block_height >= :height
        "#,
    )?;

    // `displayed_transactions.id` is the stringified form of the `TxId`.
    let rows = stmt.query_map(
        named_params! {
            ":account_id": account_id,
            ":height": height
        },
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )?;

    let mut count = 0u64;
    for row in rows {
        let (tx_id_str, payref_json) = row?;
        let tx_id = match tx_id_str.parse::<u64>().map(TxId::from) {
            Ok(id) => id,
            Err(e) => {
                warn!(
                    id = tx_id_str.as_str(),
                    error = e.to_string().as_str();
                    "DB: Skipping displayed tx with unparsable id while saving payref history"
                );
                continue;
            },
        };
        // payref column stores a JSON array of payref strings
        if let Ok(payrefs) = serde_json::from_str::<Vec<String>>(&payref_json) {
            for payref in payrefs {
                if !payref.is_empty() {
                    save_payref_history(conn, account_id, tx_id, &payref, None)?;
                    count = count.saturating_add(1);
                }
            }
        }
    }

    Ok(count)
}

/// Save historical payrefs for all completed transactions being reset during a reorg.
/// Called before `reset_mined_completed_transactions_from_height` clears the payrefs.
pub fn save_completed_transaction_payrefs_before_reorg(
    conn: &Connection,
    account_id: i64,
    reorg_height: u64,
) -> WalletDbResult<u64> {
    warn!(
        account_id = account_id,
        height = reorg_height;
        "DB: Saving completed transaction payrefs before reorg"
    );

    #[allow(clippy::cast_possible_wrap)]
    let height = reorg_height as i64;

    let status_unconfirmed = "mined_unconfirmed".to_string();
    let status_confirmed = "mined_confirmed".to_string();

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, sent_payref, sent_output_hash
        FROM completed_transactions
        WHERE account_id = :account_id
          AND sent_payref IS NOT NULL
          AND (status = :status_unconfirmed OR status = :status_confirmed)
          AND mined_height >= :height
        "#,
    )?;

    // `completed_transactions.id` is stored as the wrapping i64 of the TxId.
    let rows = stmt.query_map(
        named_params! {
            ":account_id": account_id,
            ":status_unconfirmed": status_unconfirmed,
            ":status_confirmed": status_confirmed,
            ":height": height
        },
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        },
    )?;

    let mut count = 0u64;
    for row in rows {
        let (tx_id_i64, payref, output_hash) = row?;
        #[allow(clippy::cast_sign_loss)]
        let tx_id = TxId::from(tx_id_i64 as u64);
        save_payref_history(conn, account_id, tx_id, &payref, output_hash.as_deref())?;
        count = count.saturating_add(1);
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    use super::*;
    use crate::db::{
        create_account, get_account_by_name, get_displayed_transaction_by_id, init_db, insert_displayed_transaction,
    };
    use crate::transactions::{
        DisplayedTransactionBuilder, TransactionDirection, TransactionDisplayStatus, TransactionSource,
    };
    use chrono::NaiveDateTime;
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_common_types::types::FixedHash;
    use tari_transaction_components::MicroMinotari;
    use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
    use tempfile::tempdir;

    fn mock_fixed_hash(seed: u8) -> FixedHash {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        FixedHash::from(bytes)
    }

    fn seed_displayed_transaction(conn: &Connection, account_id: i64, tx_id: TxId, block_height: u64) {
        let timestamp =
            NaiveDateTime::parse_from_str("2025-01-15 10:00:00", "%Y-%m-%d %H:%M:%S").expect("valid timestamp");
        let tx = DisplayedTransactionBuilder::new()
            .account_id(account_id)
            .source(TransactionSource::Transfer)
            .status(TransactionDisplayStatus::Confirmed)
            .credits_and_debits(MicroMinotari::from(1_000), MicroMinotari::from(0))
            .blockchain_info(block_height, mock_fixed_hash(1), timestamp, 10)
            .inputs(vec![])
            .outputs(vec![])
            .build(tx_id)
            .expect("displayed transaction builds");
        // Sanity: builder populated an Incoming direction via credits_and_debits.
        assert_eq!(tx.direction, TransactionDirection::Incoming);
        insert_displayed_transaction(conn, &tx).expect("insert displayed transaction");
    }

    #[test]
    fn historical_payref_lookup_round_trips_for_displayed_transactions() {
        // Covers the db half of `api_get_displayed_transactions_by_payref`'s
        // history fallback: after a reorg clears the live payref column on
        // `displayed_transactions`, looking up the stale payref through
        // `payref_history` must still resolve back to the original row via
        // `get_displayed_transaction_by_id`. This is the displayed-path
        // counterpart of the completed-path cucumber scenario and asserts
        // behaviour end-to-end against the real SQLite schema.
        let temp = tempdir().expect("temp dir");
        let db_path = temp.path().join("payref_history_displayed.db");
        let pool = init_db(db_path).expect("init db");
        let conn = pool.get().expect("get connection");

        let seeds = CipherSeed::random();
        let seed_wallet = SeedWordsWallet::construct_new(seeds).unwrap();
        let wallet_type = WalletType::SeedWords(seed_wallet);
        let password = "correct horse battery staple";
        create_account(&conn, "default", &wallet_type, password).expect("create account");
        let account = get_account_by_name(&conn, "default")
            .expect("query account")
            .expect("account exists");

        let tx_id = TxId::from(424242u64);
        seed_displayed_transaction(&conn, account.id, tx_id, 500);

        let stale = "stale_payref_after_reorg";
        save_payref_history(&conn, account.id, tx_id, stale, None).expect("save history row");

        // 1. Historical lookup resolves the stale payref to the original TxId.
        let resolved = get_transaction_id_by_historical_payref(&conn, account.id, stale)
            .expect("history lookup succeeds")
            .expect("history row found");
        assert_eq!(resolved, tx_id);

        // 2. The resolved TxId fetches the real displayed row. This is the same
        //    chain `api_get_displayed_transactions_by_payref` performs when the
        //    primary `get_displayed_transactions_by_payref` lookup misses.
        let fetched = get_displayed_transaction_by_id(&conn, &resolved.to_string())
            .expect("fetch by id succeeds")
            .expect("displayed transaction exists");
        assert_eq!(fetched.id, tx_id);
        assert_eq!(fetched.blockchain.block_height, 500);

        // 3. An unrelated payref returns None so the handler can emit a 404.
        let missing =
            get_transaction_id_by_historical_payref(&conn, account.id, "never_seen").expect("history lookup ok");
        assert!(missing.is_none());
    }

    #[test]
    fn historical_payref_lookup_returns_most_recent_on_duplicates() {
        // The schema intentionally allows duplicate (account, tx_id, payref)
        // rows so every observed stale payref is appended. Verify `ORDER BY
        // created_at DESC LIMIT 1` picks the newest row. We write two rows
        // pointing at different TxIds and assert the second one wins.
        let temp = tempdir().expect("temp dir");
        let db_path = temp.path().join("payref_history_duplicates.db");
        let pool = init_db(db_path).expect("init db");
        let conn = pool.get().expect("get connection");

        let seeds = CipherSeed::random();
        let seed_wallet = SeedWordsWallet::construct_new(seeds).unwrap();
        let wallet_type = WalletType::SeedWords(seed_wallet);
        create_account(&conn, "default", &wallet_type, "pw").expect("create account");
        let account = get_account_by_name(&conn, "default").unwrap().unwrap();

        let first = TxId::from(1u64);
        let second = TxId::from(2u64);
        let stale = "collision_payref";

        save_payref_history(&conn, account.id, first, stale, None).unwrap();
        // SQLite's `datetime('now')` default has second-level precision, so we
        // bump created_at explicitly to guarantee ordering without sleeping.
        save_payref_history(&conn, account.id, second, stale, None).unwrap();
        conn.execute(
            "UPDATE payref_history SET created_at = datetime('now', '+1 second') \
             WHERE transaction_id = ?1",
            [second.as_i64_wrapped()],
        )
        .expect("bump created_at");

        let winner = get_transaction_id_by_historical_payref(&conn, account.id, stale)
            .expect("history lookup")
            .expect("row exists");
        assert_eq!(winner, second, "most-recent row should win the ORDER BY");
    }
}
