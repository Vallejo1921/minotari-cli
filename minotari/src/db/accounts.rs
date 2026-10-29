use log::{debug, info, warn};
use rusqlite::{Connection, named_params};
use serde::{Deserialize, Serialize};
use serde_rusqlite::from_rows;
use tari_common::configuration::Network;
use tari_common_types::{
    seeds::{
        mnemonic::{Mnemonic, MnemonicLanguage},
        seed_words::SeedWords,
    },
    tari_address::{TariAddress, TariAddressFeatures},
};
use tari_transaction_components::MicroMinotari;
use tari_transaction_components::key_manager::{KeyManager, wallet_types::WalletType};
use utoipa::ToSchema;

use crate::db::error::{WalletDbError, WalletDbResult};
use crate::db::outputs::get_output_totals_for_account;
use crate::db::scanned_tip_blocks::get_latest_scanned_tip_block_by_account;
use crate::utils::{
    crypto::{decrypt_data, encrypt_data},
    fingerprint::calculate_fingerprint,
    timestamp::format_timestamp,
};
use crate::{db::balance_changes::get_balance_aggregates_for_account, utils::crypto::FullEncryptedData};
use tari_utilities::hex::Hex;
use utoipa::openapi::{Object, Schema, Type};
use zeroize::Zeroizing;

pub fn micro_minotari_schema() -> Schema {
    Schema::Object(
        Object::builder()
            .property("amount", Schema::Object(Object::with_type(Type::Integer)))
            .build(),
    )
}

pub fn create_account(
    conn: &Connection,
    friendly_name: &str,
    wallet: &WalletType,
    password: &str,
) -> WalletDbResult<()> {
    info!(
        target: "audit",
        account = friendly_name;
        "DB: Creating new account"
    );

    let fingerprint = calculate_fingerprint(wallet);
    let birthday = i64::from(wallet.get_birthday().unwrap_or(0));
    // The serialized wallet holds the cipher seed / view key in the clear. Keep it in a
    // buffer that wipes itself so the only long-lived copy is the encrypted one.
    let wallet_json = Zeroizing::new(
        serde_json::to_string(wallet).map_err(|e| WalletDbError::Unexpected(format!("Serialization failed: {}", e)))?,
    );

    let encrypted_data = encrypt_data(wallet_json.as_bytes(), password)
        .map_err(|e| WalletDbError::Unexpected(format!("Encryption failed: {}", e)))?;

    conn.execute(
        r#"
        INSERT INTO accounts (
            friendly_name,
            fingerprint,
            encrypted_wallet,
            cipher_nonce,
            salt,
            birthday
        )
        VALUES (
            :name,
            :fingerprint,
            :enc_wallet,
            :nonce,
            :salt,
            :birthday
        )
        "#,
        named_params! {
            ":name": friendly_name,
            ":fingerprint": fingerprint,
            ":enc_wallet": encrypted_data.ciphertext,
            ":nonce": encrypted_data.nonce,
            ":salt": encrypted_data.salt_bytes,
            ":birthday": birthday,
        },
    )?;

    Ok(())
}

pub fn get_account_by_name(conn: &Connection, friendly_name: &str) -> WalletDbResult<Option<AccountRow>> {
    debug!(
        account = friendly_name;
        "DB: Fetching account by name"
    );

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, 
            friendly_name, 
            fingerprint,
            encrypted_wallet,
            cipher_nonce,
            salt,
            birthday
        FROM accounts
        WHERE friendly_name = :name
        "#,
    )?;

    let rows = stmt.query(named_params! { ":name": friendly_name })?;
    let row = from_rows::<AccountRow>(rows).next().transpose()?;

    Ok(row)
}

pub fn get_accounts(conn: &Connection, friendly_name: Option<&str>) -> WalletDbResult<Vec<AccountRow>> {
    if let Some(name) = friendly_name {
        debug!(
            account = name;
            "DB: Listing accounts with filter"
        );
        let mut stmt = conn.prepare_cached(
            r#"
            SELECT id, 
              friendly_name, 
              fingerprint,
              encrypted_wallet,
              cipher_nonce,
              salt,
              birthday
            FROM accounts
            WHERE friendly_name = :name
            ORDER BY friendly_name
            "#,
        )?;
        let rows = stmt.query(named_params! { ":name": name })?;
        let results = from_rows::<AccountRow>(rows).collect::<Result<Vec<_>, _>>()?;
        Ok(results)
    } else {
        debug!("DB: Listing all accounts");
        let mut stmt = conn.prepare_cached(
            r#"
            SELECT id, 
              friendly_name, 
              fingerprint,
              encrypted_wallet,
              cipher_nonce,
              salt,
              birthday
            FROM accounts
            ORDER BY friendly_name
            "#,
        )?;
        let rows = stmt.query(named_params! {})?;
        let results = from_rows::<AccountRow>(rows).collect::<Result<Vec<_>, _>>()?;
        Ok(results)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountRow {
    pub id: i64,
    pub friendly_name: String,
    pub fingerprint: Vec<u8>,
    pub encrypted_wallet: Vec<u8>,
    pub cipher_nonce: Vec<u8>,
    pub salt: Vec<u8>,
    pub birthday: i64,
}

impl AccountRow {
    pub fn decrypt_wallet_type(&self, password: &str) -> WalletDbResult<WalletType> {
        let encrypted_data = FullEncryptedData {
            ciphertext: &self.encrypted_wallet,
            nonce: &self.cipher_nonce,
            salt_bytes: &self.salt,
        };
        let plaintext_bytes = decrypt_data(&encrypted_data, password).map_err(|e| {
            warn!(error:? = e; "DB: Failed to decrypt wallet");
            WalletDbError::DecryptionFailed("Failed to decrypt wallet data".to_string())
        })?;

        let wallet: WalletType = serde_json::from_slice(&plaintext_bytes)
            .map_err(|e| WalletDbError::Decoding(format!("Failed to deserialize wallet JSON: {}", e)))?;

        // The fingerprint column is the only record of *which* wallet this row is
        // supposed to hold. AEAD tells us the ciphertext was not tampered with under
        // this password, but nothing stops an encrypted_wallet/cipher_nonce/salt triple
        // belonging to a different account from being swapped into this row — the
        // decryption still succeeds and the wallet silently starts scanning, addressing
        // and spending under someone else's keys. Writing the fingerprint and never
        // checking it makes that swap invisible, so check it on every load.
        self.verify_fingerprint(&wallet)?;

        Ok(wallet)
    }

    /// Checks that the decrypted wallet is the one this row claims to hold.
    ///
    /// Rows written before the `fingerprint` column existed may carry an empty value;
    /// those are accepted (there is nothing to compare against) rather than locking the
    /// operator out of a legitimate wallet.
    fn verify_fingerprint(&self, wallet: &WalletType) -> WalletDbResult<()> {
        if self.fingerprint.is_empty() {
            return Ok(());
        }

        let expected = calculate_fingerprint(wallet);
        if expected != self.fingerprint {
            warn!(
                target: "audit",
                account = &*self.friendly_name;
                "DB: Wallet fingerprint mismatch — stored key material does not belong to this account"
            );
            return Err(WalletDbError::DecryptionFailed(format!(
                "Wallet fingerprint mismatch for account '{}': the stored key material does not belong to this account",
                self.friendly_name
            )));
        }

        Ok(())
    }

    pub fn get_address(&self, network: Network, password: &str) -> WalletDbResult<TariAddress> {
        let wallet = self.decrypt_wallet_type(password)?;

        let view_public_key = wallet.get_public_view_key();
        let spend_public_key = wallet.get_public_spend_key();

        let address = TariAddress::new_dual_address(
            view_public_key,
            spend_public_key,
            network,
            TariAddressFeatures::create_one_sided_only(),
            None,
        )
        .map_err(|e| WalletDbError::Unexpected(format!("Failed to generate address: {}", e)))?;

        Ok(address)
    }

    pub fn get_address_with_payment_id(
        &self,
        network: Network,
        password: &str,
        payment_id: &[u8],
    ) -> WalletDbResult<TariAddress> {
        let wallet = self.decrypt_wallet_type(password)?;

        let view_public_key = wallet.get_public_view_key();
        let spend_public_key = wallet.get_public_spend_key();

        let address = TariAddress::new_dual_address(
            view_public_key,
            spend_public_key,
            network,
            TariAddressFeatures::create_one_sided_only(),
            Some(payment_id.to_vec()),
        )
        .map_err(|e| WalletDbError::Unexpected(format!("Failed to generate address with payment ID: {}", e)))?;

        Ok(address)
    }

    pub fn get_key_manager(&self, password: &str) -> WalletDbResult<KeyManager> {
        let wallet = self.decrypt_wallet_type(password)?;
        let key_manager = KeyManager::new(wallet)
            .map_err(|e| WalletDbError::Unexpected(format!("Failed to create key manager: {}", e)))?;

        Ok(key_manager)
    }

    pub fn get_seed_words(&self, password: &str) -> WalletDbResult<Option<SeedWords>> {
        let wallet = self.decrypt_wallet_type(password)?;

        match wallet {
            WalletType::SeedWords(seed_wallet) => {
                let cipher_seed = seed_wallet.cipher_seed();
                let mnemonic = cipher_seed.to_mnemonic(MnemonicLanguage::English, None).map_err(|e| {
                    warn!(error:? = e; "DB: Failed to convert seed to mnemonic");
                    WalletDbError::Unexpected(format!("Failed to generate mnemonic: {}", e))
                })?;
                Ok(Some(mnemonic))
            },
            _ => Ok(None),
        }
    }

    /// Returns `(private view key hex, public spend key hex)`.
    ///
    /// The view key is a secret — it reveals the whole transaction history — so it is
    /// handed back in a buffer that wipes itself rather than as a plain `String` left
    /// in the heap after printing.
    pub fn get_keys_hex(&self, password: &str) -> WalletDbResult<(Zeroizing<String>, String)> {
        let wallet = self.decrypt_wallet_type(password)?;

        let view_key = wallet.get_view_key();
        let spend_key = wallet.get_public_spend_key();

        Ok((Zeroizing::new(view_key.to_hex()), spend_key.to_hex()))
    }
}

#[derive(Debug, Clone, ToSchema, Serialize)]
pub struct AccountBalance {
    /// The total balance of the account (Total Credits - Total Debits).
    #[schema(schema_with = micro_minotari_schema)]
    pub total: MicroMinotari,
    /// The portion of the total balance that is currently spendable.
    #[schema(schema_with = micro_minotari_schema)]
    pub available: MicroMinotari,
    /// The portion of the balance that is locked.
    #[schema(schema_with = micro_minotari_schema)]
    pub locked: MicroMinotari,
    /// The amount from incoming transactions that have not yet been confirmed.
    #[schema(schema_with = micro_minotari_schema)]
    pub unconfirmed: MicroMinotari,
    /// The portion of the balance that is mined but still subject to an output
    /// maturity (e.g. coinbase rewards) and therefore not yet spendable.
    #[schema(schema_with = micro_minotari_schema)]
    pub immature: MicroMinotari,
    /// The total sum of all incoming (credit) transactions.
    #[schema(schema_with = micro_minotari_schema)]
    pub total_credits: Option<MicroMinotari>,
    /// The total sum of all outgoing (debit) transactions.
    #[schema(schema_with = micro_minotari_schema)]
    pub total_debits: Option<MicroMinotari>,
    /// The maximum blockchain height among all transactions for this account.
    ///
    /// Will be `None` if the account has no transactions.
    pub max_height: Option<i64>,
    /// The timestamp of the most recent transaction.
    ///
    /// The string is in ISO 8601 format. Will be `None` if the
    /// account has no transactions.
    pub max_date: Option<String>,
}

/// Reads the three sources a balance is derived from under one consistent snapshot.
///
/// `total` comes from the `balance_changes` ledger while `locked`/`unconfirmed`/
/// `immature` come from the `outputs` table and `tip_height` from
/// `scanned_tip_blocks`. Read on three separate WAL snapshots, a scan committing
/// between them can be observed half-applied: the credit for a new output is
/// visible in the ledger while the output row that makes it `unconfirmed` is not,
/// and `available = total - unavailable` reports funds that cannot be spent. That
/// same number is copied into every webhook payload, so a consumer acting on it
/// would act on a balance the wallet never actually had.
///
/// A deferred read transaction pins one snapshot for all three reads. When the
/// caller is already inside a transaction (webhook enrichment runs inside the scan's
/// write transaction) the snapshot is pinned already and this is a plain read.
pub fn get_balance(conn: &Connection, account_id: i64) -> WalletDbResult<AccountBalance> {
    if !conn.is_autocommit() {
        return get_balance_in_snapshot(conn, account_id);
    }

    conn.execute_batch("BEGIN DEFERRED")?;
    let result = get_balance_in_snapshot(conn, account_id);
    // Release the snapshot on both paths; the read transaction wrote nothing, so
    // rolling back and committing are equivalent.
    if let Err(e) = conn.execute_batch("COMMIT") {
        warn!(error:% = e; "DB: Failed to close balance read transaction");
    }
    result
}

fn get_balance_in_snapshot(conn: &Connection, account_id: i64) -> WalletDbResult<AccountBalance> {
    debug!(
        account_id = account_id;
        "DB: Calculating account balance"
    );
    let history_agg = get_balance_aggregates_for_account(conn, account_id)?;
    let tip_height = get_latest_scanned_tip_block_by_account(conn, account_id)?
        .map(|b| b.height)
        .unwrap_or(0);
    let totals = get_output_totals_for_account(conn, account_id, tip_height)?;

    let total_credits: MicroMinotari = (history_agg.total_credits.unwrap_or_default() as u64).into();
    let total_debits: MicroMinotari = (history_agg.total_debits.unwrap_or_default() as u64).into();
    let total_balance = total_credits.saturating_sub(total_debits);

    // Derive `available` from the ledger so it stays in sync with `total` even when
    // the `outputs` table and the balance-change ledger drift (e.g. during reorg
    // recovery, or in tests that seed only one side). `totals.available` is the
    // direct outputs-table view and is exposed separately on `OutputTotals`.
    let available_balance = total_balance.saturating_sub(totals.unavailable);

    let max_date_str = history_agg.max_date.map(format_timestamp);

    Ok(AccountBalance {
        total: total_balance,
        available: available_balance,
        locked: totals.locked,
        unconfirmed: totals.unconfirmed,
        immature: totals.immature,
        total_credits: Some(total_credits),
        total_debits: Some(total_debits),
        max_height: history_agg.max_height,
        max_date: max_date_str,
    })
}

pub fn delete_account(conn: &Connection, friendly_name: &str) -> WalletDbResult<()> {
    info!(
        target: "audit",
        account = friendly_name;
        "DB: Deleting account and all associated data"
    );

    let account = get_account_by_name(conn, friendly_name)?
        .ok_or_else(|| WalletDbError::InvalidInput(format!("Account '{}' not found", friendly_name)))?;
    let account_id = account.id;

    // `webhook_queue` does not carry an account_id; it references `events(id)`, so its
    // rows have to go before the events they point at. (The FK is ON DELETE SET NULL,
    // which would otherwise leave this account's undelivered payloads queued forever
    // with no way to tell whose they were.)
    debug!(account_id = account_id; "Deleting from webhook_queue");
    conn.execute(
        "DELETE FROM webhook_queue WHERE event_id IN (SELECT id FROM events WHERE account_id = :id)",
        named_params! { ":id": account_id },
    )?;

    // The order of table deletion is important to respect foreign key constraints.
    // The tables are ordered from child to parent. Every table holding an
    // `account_id` REFERENCES accounts(id) must appear here: `PRAGMA foreign_keys`
    // is ON, so a single omitted table makes the final `DELETE FROM accounts` fail
    // with a constraint violation and the account can never be deleted.
    let tables_to_clear = [
        "balance_changes",
        "inputs",
        "outputs",
        "completed_transactions",
        "pending_transactions",
        "scanned_tip_blocks",
        "events",
        "displayed_transactions",
        "burn_proofs",
        "payref_history",
    ];

    for table_name in tables_to_clear {
        debug!(account_id = account_id, table = table_name; "Deleting from {}", table_name);
        let query = format!("DELETE FROM {} WHERE account_id = :id", table_name);
        conn.execute(&query, named_params! { ":id": account_id })?;
    }

    debug!(account_id = account_id; "Deleting account record");
    let deleted = conn.execute(
        "DELETE FROM accounts WHERE id = :id",
        named_params! { ":id": account_id },
    )?;
    if deleted == 0 {
        return Err(WalletDbError::Unexpected(format!(
            "Account '{}' was not deleted",
            friendly_name
        )));
    }

    info!(target: "audit", account = friendly_name; "Account successfully deleted");

    Ok(())
}

pub fn update_account_name(conn: &Connection, current_name: &str, new_name: &str) -> WalletDbResult<()> {
    info!(
        target: "audit",
        current_name = current_name,
        new_name = new_name;
        "DB: Renaming account"
    );

    // Check if the new name is already taken
    if get_account_by_name(conn, new_name)?.is_some() {
        return Err(WalletDbError::InvalidInput(format!(
            "An account with the name '{}' already exists",
            new_name
        )));
    }

    let affected_rows = match conn.execute(
        "UPDATE accounts SET friendly_name = :new_name WHERE friendly_name = :current_name",
        named_params! {
            ":new_name": new_name,
            ":current_name": current_name,
        },
    ) {
        Ok(rows) => rows,
        Err(rusqlite::Error::SqliteFailure(err, _)) if err.code == rusqlite::ErrorCode::ConstraintViolation => {
            return Err(WalletDbError::InvalidInput(format!(
                "An account with the name '{}' already exists",
                new_name
            )));
        },
        Err(e) => return Err(e.into()),
    };

    if affected_rows == 0 {
        return Err(WalletDbError::InvalidInput(format!(
            "Account '{}' not found",
            current_name
        )));
    }

    Ok(())
}

/// Re-encrypts an account's key material under `new_password`, with a fresh salt and nonce.
///
/// A wrong `old_password` returns [`WalletDbError::DecryptionFailed`] and writes nothing.
///
/// Copies or backups of the database made before the change still open with the old passphrase.
/// Any daemon, scanner or other process using the old passphrase on this database must be
/// stopped and restarted with the new one, or its decrypts will fail.
///
/// Only `account_name` is re-encrypted; other accounts in the database keep their own
/// passphrase. Scanners and daemons that open every account with one password need all of
/// them on the same passphrase, so call this once per account.
pub fn change_passphrase(
    conn: &mut Connection,
    account_name: &str,
    old_password: &str,
    new_password: &str,
) -> WalletDbResult<()> {
    info!(
        target: "audit",
        account = account_name;
        "DB: Changing account passphrase"
    );

    // `secure_delete` is turned on for the rewrite only; put the connection back as it was.
    let previous_secure_delete: i64 = conn.pragma_query_value(None, "secure_delete", |row| row.get(0))?;
    let result = rewrite_encrypted_wallet(conn, account_name, old_password, new_password);
    if let Err(e) = conn.pragma_update(None, "secure_delete", previous_secure_delete) {
        warn!(error:% = e; "DB: Failed to restore secure_delete after passphrase change");
    }
    result
}

fn rewrite_encrypted_wallet(
    conn: &mut Connection,
    account_name: &str,
    old_password: &str,
    new_password: &str,
) -> WalletDbResult<()> {
    // The encrypted wallet is the only field `encrypt_data` writes. Read and rewrite it under
    // the write lock so a concurrent change cannot be lost.
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

    let account = get_account_by_name(&tx, account_name)?
        .ok_or_else(|| WalletDbError::InvalidInput(format!("Account '{}' not found", account_name)))?;
    let wallet = account.decrypt_wallet_type(old_password)?;
    // Sized well above any wallet's JSON so the buffer never reallocates and leaves a copy behind.
    let mut wallet_json = Zeroizing::new(Vec::with_capacity(16 * 1024));
    serde_json::to_writer(&mut *wallet_json, &wallet)
        .map_err(|e| WalletDbError::Unexpected(format!("Serialization failed: {}", e)))?;
    let encrypted_data = encrypt_data(&wallet_json, new_password)
        .map_err(|e| WalletDbError::Unexpected(format!("Encryption failed: {}", e)))?;

    // Overwrite the freed pages that held the old ciphertext instead of leaving them in the file.
    tx.pragma_update(None, "secure_delete", true)?;
    tx.execute(
        "UPDATE accounts SET encrypted_wallet = :enc_wallet, cipher_nonce = :nonce, salt = :salt WHERE id = :id",
        named_params! {
            ":enc_wallet": encrypted_data.ciphertext,
            ":nonce": encrypted_data.nonce,
            ":salt": encrypted_data.salt_bytes,
            ":id": account.id,
        },
    )?;
    tx.commit()?;

    info!(
        target: "audit",
        account = account_name;
        "DB: Account passphrase changed"
    );

    // Move the old ciphertext out of the WAL. The change is already committed, so a checkpoint
    // that is busy or fails only delays this.
    match conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get::<_, i64>(0)) {
        Ok(0) => {},
        Ok(_) => warn!("DB: WAL checkpoint after passphrase change was busy"),
        Err(e) => warn!(error:% = e; "DB: WAL checkpoint after passphrase change failed"),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{NewBurnProof, init_db, insert_burn_proof, save_payref_history};
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_common_types::types::FixedHash;
    use tempfile::tempdir;

    fn make_wallet() -> WalletType {
        let seeds = CipherSeed::random();
        WalletType::SeedWords(
            tari_transaction_components::key_manager::wallet_types::SeedWordsWallet::construct_new(seeds).unwrap(),
        )
    }

    fn new_account(conn: &Connection, name: &str) -> AccountRow {
        create_account(conn, name, &make_wallet(), "password").unwrap();
        get_account_by_name(conn, name).unwrap().unwrap()
    }

    #[test]
    fn an_account_is_deletable_even_once_it_owns_burn_proofs_and_payref_history() {
        // `PRAGMA foreign_keys` is ON, so any table referencing accounts(id) that the
        // deletion forgets makes `DELETE FROM accounts` fail on a constraint. Deleting
        // a wallet then becomes impossible for exactly the accounts that have been used.
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("delete.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account = new_account(&conn, "doomed");

        insert_burn_proof(
            &conn,
            &NewBurnProof {
                account_id: account.id,
                output_hash: FixedHash::zero(),
                commitment: vec![0u8; 32],
                claim_public_key: "00".repeat(32),
                ownership_proof_nonce: vec![0u8; 32],
                ownership_proof_sig: vec![0u8; 32],
                kernel_excess: vec![0u8; 32],
                kernel_excess_nonce: vec![0u8; 32],
                kernel_excess_sig: vec![0u8; 32],
                sender_offset_public_key: vec![0u8; 32],
                encrypted_data: vec![1, 2, 3],
                value: 1_000,
                kernel_fee: 10,
                kernel_lock_height: 0,
            },
        )
        .expect("insert burn proof");

        save_payref_history(&conn, account.id, 42_u64.into(), "deadbeef", None).expect("save payref history");

        delete_account(&conn, "doomed").expect("account is deletable");
        assert!(get_account_by_name(&conn, "doomed").unwrap().is_none());

        let burn_proofs: i64 = conn
            .query_row("SELECT COUNT(*) FROM burn_proofs", [], |r| r.get(0))
            .unwrap();
        let payrefs: i64 = conn
            .query_row("SELECT COUNT(*) FROM payref_history", [], |r| r.get(0))
            .unwrap();
        assert_eq!((burn_proofs, payrefs), (0, 0), "child rows must go with the account");
    }

    #[test]
    fn a_wallet_swapped_into_another_accounts_row_is_refused() {
        // The ciphertext is authenticated, but nothing binds it to *this* row. Copying
        // another account's (encrypted_wallet, nonce, salt) triple over this one still
        // decrypts cleanly under the same password — and the wallet would go on to
        // scan, address and spend under someone else's keys. The fingerprint column
        // exists to catch exactly that, so it has to be checked on load.
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("fingerprint.db")).expect("init db");
        let conn = pool.get().expect("conn");

        let victim = new_account(&conn, "victim");
        let attacker = new_account(&conn, "attacker");

        victim.decrypt_wallet_type("password").expect("own wallet loads");

        conn.execute(
            "UPDATE accounts SET encrypted_wallet = :w, cipher_nonce = :n, salt = :s WHERE id = :id",
            named_params! {
                ":w": attacker.encrypted_wallet,
                ":n": attacker.cipher_nonce,
                ":s": attacker.salt,
                ":id": victim.id,
            },
        )
        .expect("swap key material");

        let swapped = get_account_by_name(&conn, "victim").unwrap().unwrap();
        let err = swapped
            .decrypt_wallet_type("password")
            .expect_err("foreign key material must be rejected");
        assert!(
            matches!(&err, WalletDbError::DecryptionFailed(m) if m.contains("fingerprint")),
            "expected a fingerprint mismatch, got: {err}"
        );
    }

    #[test]
    fn change_passphrase_re_encrypts_under_the_new_password_only() {
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("passphrase.db")).expect("init db");
        let mut conn = pool.get().expect("conn");
        let before = new_account(&conn, "main");
        let address = before.get_address(Network::LocalNet, "password").unwrap();

        change_passphrase(&mut conn, "main", "password", "new password").expect("passphrase changes");
        let secure_delete: i64 = conn.pragma_query_value(None, "secure_delete", |r| r.get(0)).unwrap();
        assert_eq!(secure_delete, 0, "secure_delete is restored after the change");

        let after = get_account_by_name(&conn, "main").unwrap().unwrap();
        assert_ne!(after.salt, before.salt, "a fresh salt is drawn");
        assert_ne!(after.cipher_nonce, before.cipher_nonce, "a fresh nonce is drawn");
        assert!(matches!(
            after.decrypt_wallet_type("password"),
            Err(WalletDbError::DecryptionFailed(_))
        ));
        assert_eq!(after.get_address(Network::LocalNet, "new password").unwrap(), address);

        // The account can still sign with the new password.
        let signature = crate::signing::sign_message(&after, "new password", "hello").expect("signs");
        assert!(crate::signing::verify_message(&address, "hello", &signature).unwrap());
    }

    #[test]
    fn change_passphrase_with_a_wrong_old_password_changes_nothing() {
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("passphrase.db")).expect("init db");
        let mut conn = pool.get().expect("conn");
        let before = new_account(&conn, "main");

        let err = change_passphrase(&mut conn, "main", "wrong", "new password").expect_err("wrong old password");
        assert!(matches!(err, WalletDbError::DecryptionFailed(_)), "got: {err}");
        let secure_delete: i64 = conn.pragma_query_value(None, "secure_delete", |r| r.get(0)).unwrap();
        assert_eq!(secure_delete, 0, "the connection's secure_delete is left as it was");

        let after = get_account_by_name(&conn, "main").unwrap().unwrap();
        assert_eq!(after.encrypted_wallet, before.encrypted_wallet);
        assert_eq!(after.cipher_nonce, before.cipher_nonce);
        assert_eq!(after.salt, before.salt);
        after.decrypt_wallet_type("password").expect("old password still works");
    }

    #[test]
    fn a_legacy_row_without_a_fingerprint_still_loads() {
        // Rows written before the column was populated have nothing to compare
        // against; they must not be treated as tampered with.
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("legacy.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account = new_account(&conn, "legacy");

        conn.execute(
            "UPDATE accounts SET fingerprint = :f WHERE id = :id",
            named_params! { ":f": Vec::<u8>::new(), ":id": account.id },
        )
        .expect("clear fingerprint");

        get_account_by_name(&conn, "legacy")
            .unwrap()
            .unwrap()
            .decrypt_wallet_type("password")
            .expect("legacy row still loads");
    }
}
