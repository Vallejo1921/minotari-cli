//! Utility functions for wallet initialization and key management.
//!
//! This module provides helper functions for initializing new wallet accounts
//! with encrypted key storage. It handles password padding, key encryption,
//! and database initialization.

use std::path::Path;

use crate::{db, init_db};
use anyhow::Context;
use tari_common_types::{
    seeds::cipher_seed::CipherSeed,
    types::{CompressedPublicKey, PrivateKey},
};
use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, ViewWallet, WalletType};
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
