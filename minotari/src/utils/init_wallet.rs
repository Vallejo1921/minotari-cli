//! Utility functions for wallet initialization and key management.
//!
//! This module provides helper functions for initializing new wallet accounts
//! with encrypted key storage. It handles password padding, key encryption,
//! and database initialization.

use std::{path::Path, str::FromStr};

use crate::utils::crypto::{is_identity_public_key, parse_private_key_hex};
use crate::{db, init_db};
use anyhow::Context;
use tari_common::configuration::Network;
use tari_common_types::{
    seeds::cipher_seed::CipherSeed,
    tari_address::{TariAddress, TariAddressFeatures},
    types::{CompressedPublicKey, PrivateKey},
};
use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, SpendWallet, ViewWallet, WalletType};
use tari_utilities::hex::Hex;

/// Initializes a new wallet account with view and spend keys.
///
/// This function creates a new wallet account by:
/// 1. Decoding the provided hex-encoded keys
/// 2. Padding the password to 32 bytes if necessary
/// 3. Encrypting both keys using XChaCha20-Poly1305
/// 4. Generating a hash of the view key to prevent duplicates
/// 5. Storing the encrypted keys in the database
///
/// # Parameters
///
/// * `view_private_key` - Hex-encoded view private key
/// * `spend_public_key` - Hex-encoded spend public key
/// * `password` - Password for encrypting the keys (will be padded to 32 bytes)
/// * `database_file` - Path to the SQLite database file
/// * `birthday` - Block height to start scanning from (0 to scan entire chain)
/// * `friendly_name` - Optional account name (defaults to "default")
///
/// # Returns
///
/// Returns `Ok(())` on success or an error if:
/// - Keys cannot be decoded from hex
/// - Encryption fails
/// - Database operations fail
/// - Account with same view key already exists
///
/// # Security
///
/// - Keys are encrypted using XChaCha20-Poly1305 with a random nonce
/// - Passwords shorter than 32 bytes are padded with zeros
/// - Passwords longer than 32 bytes are truncated
/// - View key hash prevents duplicate account creation
///
/// # Example
///
/// ```ignore
/// use minotari::utils::init_wallet::init_with_view_key;
/// use std::path::Path;
///
/// # fn example() -> Result<(), anyhow::Error> {
/// init_with_view_key(
///     "a0b1c2d3e4f5...",  // view_private_key (hex)
///     "b1c2d3e4f5a0...",  // spend_public_key (hex)
///     "my_secure_password",
///     Path::new("wallet.db"),
///     0,                   // birthday height
///     Some("my_wallet"),   // account name
/// )?;
/// # Ok(())
/// # }
/// ```
///
///
pub fn init_with_view_key(
    view_private_key: &str,
    spend_public_key: &str,
    password: &str,
    database_file: &Path,
    birthday: u16,
    friendly_name: Option<&str>,
) -> Result<(), anyhow::Error> {
    let view_key = PrivateKey::from_hex(view_private_key).map_err(|_| anyhow::anyhow!("Invalid hex for view key"))?;
    let spend_key =
        CompressedPublicKey::from_hex(spend_public_key).map_err(|_| anyhow::anyhow!("Invalid hex for spend key"))?;

    let view_wallet = ViewWallet::new(spend_key, view_key, Some(birthday));
    let wallet_enum = WalletType::ViewWallet(view_wallet);

    save_wallet_to_db(wallet_enum, password, database_file, friendly_name)
}

/// Initializes a spendable wallet account from its private view and spend keys.
///
/// The spend public key is derived from `spend_private_key`. If `expected_address` is given
/// (base58, emoji or hex), its network, view key and spend key must match the derived ones,
/// so a mistyped key is caught before the account is saved.
///
/// `birthday` is in days since the birthday genesis, as the account stores it; see
/// [`crate::utils::height`] to convert a height or date.
///
/// Returns the account's one-sided address on `network`.
#[allow(clippy::too_many_arguments)]
pub fn init_with_spend_and_view_keys(
    view_private_key: &str,
    spend_private_key: &str,
    password: &str,
    database_file: &Path,
    birthday: u16,
    network: Network,
    expected_address: Option<&str>,
    friendly_name: Option<&str>,
) -> Result<TariAddress, anyhow::Error> {
    let view_key = parse_private_key_hex(view_private_key).context("Invalid view key")?;
    let spend_key = parse_private_key_hex(spend_private_key).context("Invalid spend key")?;

    let wallet = WalletType::SpendWallet(SpendWallet::new(spend_key, view_key, Some(birthday)));
    // A zero private key gives the identity public key, which anyone can view or spend with.
    if is_identity_public_key(&wallet.get_public_view_key()) || is_identity_public_key(&wallet.get_public_spend_key()) {
        return Err(anyhow::anyhow!("A private key of zero is not a usable wallet key"));
    }
    // With equal keys, whoever holds the view key can also spend.
    if wallet.get_public_view_key() == wallet.get_public_spend_key() {
        return Err(anyhow::anyhow!("The view key and the spend key must differ"));
    }
    let address = TariAddress::new_dual_address(
        wallet.get_public_view_key(),
        wallet.get_public_spend_key(),
        network,
        TariAddressFeatures::create_one_sided_only(),
        None,
    )?;

    if let Some(expected) = expected_address {
        let expected = TariAddress::from_str(expected).map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;
        if expected.network() != network {
            return Err(anyhow::anyhow!(
                "Address is for network {}, not {}",
                expected.network(),
                network
            ));
        }
        if expected.public_spend_key() != address.public_spend_key()
            || expected.public_view_key() != address.public_view_key()
        {
            return Err(anyhow::anyhow!("The keys do not belong to the given address"));
        }
    }

    save_wallet_to_db(wallet, password, database_file, friendly_name)?;
    Ok(address)
}

// Initializes a new wallet account using a Seed (CipherSeed).
///
/// This is the full wallet type which can sign transactions.
///
/// # Parameters
///
/// * `cipher_seed` - The seed containing entropy and birthday.
/// * `password` - Password for encrypting the wallet.
/// * `database_file` - Path to the SQLite database file.
/// * `friendly_name` - Optional account name (defaults to "default").
pub fn init_with_seed_words(
    cipher_seed: CipherSeed,
    password: &str,
    database_file: &Path,
    friendly_name: Option<&str>,
) -> Result<(), anyhow::Error> {
    let seed_wallet =
        SeedWordsWallet::construct_new(cipher_seed).map_err(|e| anyhow::anyhow!("Invalid seed: {}", e))?;
    let wallet_enum = WalletType::SeedWords(seed_wallet);

    save_wallet_to_db(wallet_enum, password, database_file, friendly_name)
}

fn save_wallet_to_db(
    wallet: WalletType,
    password: &str,
    database_file: &Path,
    friendly_name: Option<&str>,
) -> Result<(), anyhow::Error> {
    let pool = init_db(database_file.to_path_buf()).context("Failed to initialize database")?;
    let conn = pool.get().context("Failed to get DB connection from pool")?;

    let name = friendly_name.unwrap_or("default");

    db::create_account(&conn, name, &wallet, password)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transactions::burn::{BurnTxParams, create_burn_tx};
    use chrono::Utc;
    use rusqlite::named_params;
    use tari_script::script;
    use tari_transaction_components::{
        MicroMinotari,
        test_helpers::{TestParams, create_wallet_output_with_data},
        transaction_components::OutputFeatures,
    };

    /// A seed wallet's private (view, spend) keys, as hex.
    fn keys_of(seed: &CipherSeed) -> (String, String) {
        let wallet = SeedWordsWallet::construct_new(seed.clone()).unwrap();
        (wallet.view_key().to_hex(), wallet.spend_key().to_hex())
    }

    fn account(database_file: &Path, name: &str) -> db::AccountRow {
        let pool = init_db(database_file.to_path_buf()).unwrap();
        let conn = pool.get().unwrap();
        db::get_account_by_name(&conn, name).unwrap().unwrap()
    }

    #[test]
    fn a_wallet_restored_from_its_keys_matches_the_seed_wallet_and_can_spend() {
        let temp = tempfile::tempdir().unwrap();
        let seed_db = temp.path().join("seed.db");
        let keys_db = temp.path().join("keys.db");
        let seed = CipherSeed::random();
        let (view_key, spend_key) = keys_of(&seed);

        init_with_seed_words(seed.clone(), "pass", &seed_db, Some("seed")).unwrap();
        let seed_address = account(&seed_db, "seed")
            .get_address(Network::LocalNet, "pass")
            .unwrap();

        let address = init_with_spend_and_view_keys(
            &view_key,
            &spend_key,
            "pass",
            &keys_db,
            seed.birthday(),
            Network::LocalNet,
            Some(&seed_address.to_base58()),
            Some("keys"),
        )
        .expect("restore from keys");
        assert_eq!(address, seed_address);

        let restored = account(&keys_db, "keys");
        assert_eq!(restored.get_address(Network::LocalNet, "pass").unwrap(), seed_address);
        assert_eq!(restored.birthday, i64::from(seed.birthday()));

        let signature = crate::signing::sign_message(&restored, "pass", "hello").expect("signs");
        assert!(crate::signing::verify_message(&seed_address, "hello", &signature).unwrap());

        // Fund the account with one real output and build (and sign) a transaction spending it.
        let pool = init_db(keys_db.clone()).unwrap();
        let mut conn = pool.get().unwrap();
        db::insert_scanned_tip_block(&conn, restored.id, 200, &[0u8; 32]).unwrap();
        let key_manager = restored.get_key_manager("pass").unwrap();
        let output = create_wallet_output_with_data(
            script!(Nop).unwrap(),
            OutputFeatures::default(),
            &TestParams::new(&key_manager),
            MicroMinotari(1_000_000),
            &key_manager,
        )
        .unwrap();
        conn.execute(
            r#"
            INSERT INTO outputs (
                account_id, tx_id, output_hash, mined_in_block_height, mined_in_block_hash, value,
                mined_timestamp, wallet_output_json, status, confirmed_height, confirmed_hash, is_burn, maturity
            ) VALUES (:account_id, 1, :hash, 100, :hash, 1000000, :mined_ts, :json, 'UNSPENT', 100, :hash, 0, 0)
            "#,
            named_params! {
                ":account_id": restored.id,
                ":hash": output.output_hash().to_vec(),
                ":mined_ts": Utc::now(),
                ":json": serde_json::to_string(&output).unwrap(),
            },
        )
        .unwrap();

        let claim_public_key = WalletType::new_random().unwrap().get_public_spend_key();
        let params = BurnTxParams {
            account_id: restored.id,
            amount: MicroMinotari(10_000),
            claim_public_key: Some(claim_public_key),
            sidechain_deployment_key: None,
            fee_per_gram: MicroMinotari(5),
            payment_id: None,
            idempotency_key: Some("restored-key".to_string()),
            seconds_to_lock: 3600,
            confirmation_window: 100,
        };
        let result = create_burn_tx(&restored, &mut conn, Network::LocalNet, "pass", params).expect("builds");
        assert_eq!(result.transaction.body.inputs().len(), 1);
    }

    #[test]
    fn a_zero_or_repeated_private_key_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let database_file = temp.path().join("keys.db");
        let (view_key, spend_key) = keys_of(&CipherSeed::random());
        let zero = "00".repeat(32);

        let cases = [
            ("zero-view", &zero, &spend_key),
            ("zero-spend", &view_key, &zero),
            ("same-keys", &spend_key, &spend_key),
        ];
        for (name, view, spend) in cases {
            let result = init_with_spend_and_view_keys(
                view,
                spend,
                "pass",
                &database_file,
                0,
                Network::LocalNet,
                None,
                Some(name),
            );
            assert!(result.is_err(), "{name} must be refused");
        }

        let pool = init_db(database_file).unwrap();
        let conn = pool.get().unwrap();
        assert!(db::get_accounts(&conn, None).unwrap().is_empty());
    }

    #[test]
    fn keys_that_do_not_match_the_given_address_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let database_file = temp.path().join("keys.db");
        let (view_key, spend_key) = keys_of(&CipherSeed::random());
        let (_, other_spend_key) = keys_of(&CipherSeed::random());

        let address = init_with_spend_and_view_keys(
            &view_key,
            &spend_key,
            "pass",
            &database_file,
            0,
            Network::LocalNet,
            None,
            Some("first"),
        )
        .unwrap();

        let wrong_spend = init_with_spend_and_view_keys(
            &view_key,
            &other_spend_key,
            "pass",
            &database_file,
            0,
            Network::LocalNet,
            Some(&address.to_base58()),
            Some("second"),
        );
        assert!(wrong_spend.is_err());

        let wrong_network = init_with_spend_and_view_keys(
            &view_key,
            &spend_key,
            "pass",
            &database_file,
            0,
            Network::MainNet,
            Some(&address.to_base58()),
            Some("third"),
        );
        assert!(wrong_network.is_err());

        let pool = init_db(database_file).unwrap();
        let conn = pool.get().unwrap();
        assert!(db::get_account_by_name(&conn, "second").unwrap().is_none());
        assert!(db::get_account_by_name(&conn, "third").unwrap().is_none());
    }
}
