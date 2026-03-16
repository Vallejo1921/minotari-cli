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
use crate::utils::{
    crypto::{decrypt_data, encrypt_data},
    fingerprint::calculate_fingerprint,
    timestamp::format_timestamp,
};
use crate::{db::balance_changes::get_balance_aggregates_for_account, utils::crypto::FullEncryptedData};
use tari_utilities::hex::Hex;
use utoipa::openapi::{Object, Schema, Type};

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
    let birthday = wallet.get_birthday().unwrap_or(0) as i64;
    let wallet_json =
        serde_json::to_string(wallet).map_err(|e| WalletDbError::Unexpected(format!("Serialization failed: {}", e)))?;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

        Ok(wallet)
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

    pub fn get_keys_hex(&self, password: &str) -> WalletDbResult<(String, String)> {
        let wallet = self.decrypt_wallet_type(password)?;

        let view_key = wallet.get_view_key();
        let spend_key = wallet.get_public_spend_key();

        Ok((view_key.to_hex(), spend_key.to_hex()))
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

pub fn get_balance(conn: &Connection, account_id: i64) -> WalletDbResult<AccountBalance> {
    debug!(
        account_id = account_id;
        "DB: Calculating account balance"
    );
    let history_agg = get_balance_aggregates_for_account(conn, account_id)?;
    let (locked_amount, unconfirmed_amount, locked_and_unconfirmed_amount) =
        get_output_totals_for_account(conn, account_id)?;

    let total_credits: MicroMinotari = (history_agg.total_credits.unwrap_or_default() as u64).into();
    let total_debits: MicroMinotari = (history_agg.total_debits.unwrap_or_default() as u64).into();
    let total_balance = total_credits.saturating_sub(total_debits);

    let unavailable_balance = locked_amount
        .saturating_add(unconfirmed_amount)
        .saturating_sub(locked_and_unconfirmed_amount);
    let available_balance = total_balance.saturating_sub(unavailable_balance);

    let max_date_str = history_agg.max_date.map(format_timestamp);

    Ok(AccountBalance {
        total: total_balance,
        available: available_balance,
        locked: locked_amount,
        unconfirmed: unconfirmed_amount,
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

    // The order of table deletion is important to respect foreign key constraints.
    // The tables are ordered from child to parent.
    let tables_to_clear = [
        "balance_changes",
        "inputs",
        "outputs",
        "completed_transactions",
        "pending_transactions",
        "scanned_tip_blocks",
        "events",
        "displayed_transactions",
    ];

    for table_name in tables_to_clear {
        debug!(account_id = account_id, table = table_name; "Deleting from {}", table_name);
        let query = format!("DELETE FROM {} WHERE account_id = :id", table_name);
        conn.execute(&query, named_params! { ":id": account_id })?;
    }

    debug!(account_id = account_id; "Deleting account record");
    conn.execute(
        "DELETE FROM accounts WHERE id = :id",
        named_params! { ":id": account_id },
    )?;

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
