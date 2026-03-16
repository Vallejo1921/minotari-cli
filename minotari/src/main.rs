//! Minotari Wallet CLI Application
//!
//! A command-line interface for managing Tari wallets with support for view-key
//! based operations, blockchain scanning, and transaction creation.
//!
//! # Overview
//!
//! This application provides a lightweight wallet implementation for the Tari
//! cryptocurrency network. It supports:
//!
//! - **Wallet Creation**: Generate new wallets with optional password encryption
//! - **View Key Import**: Import existing wallets using view and spend keys
//! - **Blockchain Scanning**: Detect incoming transactions and track wallet balance
//! - **Transaction Creation**: Build unsigned one-sided transactions
//! - **Fund Locking**: Reserve UTXOs for pending transactions
//! - **Daemon Mode**: Continuous blockchain monitoring with REST API
//!
//! # Security Model
//!
//! The wallet uses view-key based scanning, which allows detecting incoming
//! transactions without exposing spending capability. Sensitive data (view keys,
//! seed words) can be encrypted using XChaCha20-Poly1305 with a user-provided
//! password.
//!
//! # Usage Examples
//!
//! Create a new encrypted wallet:
//! ```bash
//! tari create-address --password "my_secure_password" --output-file wallet.json
//! ```
//!
//! Scan the blockchain for transactions:
//! ```bash
//! tari scan --password "my_password" --database-file wallet.db
//! ```
//!
//! Run the wallet daemon with API server:
//! ```bash
//! tari daemon --password "my_password" --api-port 9000
//! ```
//!
//! # Data Storage
//!
//! - Wallet credentials are stored in JSON files (optionally encrypted)
//! - Transaction and balance data is stored in a SQLite database
//! - Default data directory is `./data/`

use std::{
    fs::{self, create_dir_all},
    path::{Path, PathBuf},
};

use anyhow::anyhow;
use chacha20poly1305::{
    AeadCore, Key, KeyInit, XChaCha20Poly1305,
    aead::{Aead, OsRng},
};
use clap::Parser;
use log::info;
use minotari::{
    ScanError,
    api::accounts::LockFundsRequest,
    cli::{ApplyArgs, Cli, Commands},
    config::{defaults::WalletConfig, loader::load_configuration},
    daemon,
    db::{self, WalletDbError, get_accounts, get_balance, init_db},
    log::{init_logging, mask_string},
    models::WalletEvent,
    scan::{self, reorg::rollback_from_height},
    transactions::{
        fund_locker::FundLocker,
        one_sided_transaction::{OneSidedTransaction, Recipient},
    },
    utils,
    webhooks::WebhookTriggerConfig,
};
use std::str::FromStr;
use tari_common::{DefaultConfigLoader, configuration::Network};
use tari_common_types::{
    seeds::{
        cipher_seed::CipherSeed,
        mnemonic::{Mnemonic, MnemonicLanguage},
        seed_words::SeedWords,
    },
    tari_address::{TariAddress, TariAddressFeatures},
};
use tari_crypto::compressed_key::CompressedKey;
use tari_transaction_components::key_manager::KeyManager;
use tari_transaction_components::key_manager::TransactionKeyManagerInterface;
use tari_transaction_components::key_manager::wallet_types::SeedWordsWallet;
use tari_transaction_components::key_manager::wallet_types::WalletType;
use tari_transaction_components::tari_amount::MicroMinotari;
use tari_utilities::byte_array::ByteArray;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    init_logging();
    let cli = Cli::parse();
    let config_obj = load_configuration(&cli.config, cli.network)?;
    let mut wallet_config = WalletConfig::load_from(&config_obj)?;

    match cli.command {
        Commands::CreateAddress { password, output_file } => {
            info!(target: "audit", "Creating new address...");

            let seeds = CipherSeed::random();
            let birthday = seeds.birthday();
            let seed_words = seeds.to_mnemonic(MnemonicLanguage::English, None)?.join(" ");
            let seed_wallet = SeedWordsWallet::construct_new(seeds).map_err(|_| anyhow::anyhow!("Invalid seeds"))?;
            let wallet = WalletType::SeedWords(seed_wallet);
            let key_manager = KeyManager::new(wallet)?;

            let view_key = key_manager.get_private_view_key();
            let spend_key = key_manager.get_spend_key();

            let public_view_key = CompressedKey::from_secret_key(&view_key);

            let tari_address = TariAddress::new_dual_address(
                public_view_key,
                spend_key.pub_key.clone(),
                Network::MainNet,
                TariAddressFeatures::create_one_sided_only(),
                None,
            )?;
            info!(
                target: "audit",
                address:% = tari_address;
                "New address generated"
            );

            let wallet_data = if let Some(password) = password {
                let password = if password.len() < 32 {
                    format!("{:0<32}", password)
                } else {
                    password[..32].to_string()
                };
                let key_bytes: [u8; 32] = password
                    .as_bytes()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Password must be 32 bytes"))?;
                let key = Key::from(key_bytes);
                let cipher = XChaCha20Poly1305::new(&key);

                let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
                let encrypted_view_key = cipher.encrypt(&nonce, view_key.as_bytes())?;
                let encrypted_spend_key = cipher.encrypt(&nonce, spend_key.pub_key.as_bytes())?;

                let encrypted_seed_words = cipher.encrypt(&nonce, seed_words.reveal().as_bytes())?;

                serde_json::json!({
                    "address": tari_address.to_base58(),
                    "encrypted_view_key": hex::encode(encrypted_view_key),
                    "encrypted_spend_key": hex::encode(encrypted_spend_key),
                    "encrypted_seed_words": hex::encode(encrypted_seed_words),
                    "nonce": hex::encode(nonce),
                    "birthday": birthday,
                })
            } else {
                serde_json::json!({
                    "address": tari_address.to_base58(),
                    "view_key": hex::encode(view_key.as_bytes()),
                    "spend_key": hex::encode(spend_key.pub_key.as_bytes()),
                    "seed_words": seed_words.reveal().clone(),
                    "birthday": birthday,
                })
            };
            std::fs::create_dir_all(std::path::Path::new(&output_file).parent().unwrap())?;
            std::fs::write(output_file, serde_json::to_string_pretty(&wallet_data)?)?;
            info!("Wallet data written to file.");
            Ok(())
        },
        Commands::ImportViewKey {
            view_private_key,
            spend_public_key,
            security,
            db,
            birthday,
        } => {
            info!(
                target: "audit",
                view_key = &*mask_string(&view_private_key),
                spend_key = &*mask_string(&spend_public_key);
                "Importing wallet"
            );

            wallet_config.apply_database(&db);

            init_with_view_key(
                &view_private_key,
                &spend_public_key,
                &security.password,
                &wallet_config.database_path,
                birthday,
            )
        },
        Commands::Create {
            security,
            db,
            account,
            seed_words,
        } => {
            info!(target: "audit", "Initializing Seed Words Wallet...");

            wallet_config.apply_database(&db);
            wallet_config.apply_account(&account);

            let cipher_seed = match seed_words {
                Some(words_str) => {
                    info!("Restoring from provided seed words...");
                    let mnemonic =
                        SeedWords::from_str(&words_str).map_err(|e| anyhow!("Invalid seed words format: {}", e))?;
                    CipherSeed::from_mnemonic(&mnemonic, None)?
                },
                None => {
                    info!("Generating new random seed...");
                    CipherSeed::random()
                },
            };

            utils::init_wallet::init_with_seed_words(
                cipher_seed,
                &security.password,
                &wallet_config.database_path,
                wallet_config.account_name.as_deref(),
            )?;

            info!("Wallet initialized successfully");
            Ok(())
        },

        Commands::ShowSeedWords { security, db, account } => {
            info!("Retrieving seed words...");

            wallet_config.apply_database(&db);
            wallet_config.apply_account(&account);

            let pool = init_db(wallet_config.database_path.clone())?;
            let conn = pool.get()?;

            let name = wallet_config.account_name.as_deref().unwrap_or("default");
            let account =
                db::get_account_by_name(&conn, name)?.ok_or_else(|| anyhow!("Account '{}' not found", name))?;

            match account.get_seed_words(&security.password)? {
                Some(words) => {
                    let seed_words = words.join(" ");
                    println!("---------------------------------------------------------");
                    println!("Wallet: {}", account.friendly_name);
                    println!("Seed Words: {}", seed_words.reveal());
                    println!("---------------------------------------------------------");
                    println!("WARNING: Keep these words safe. Anyone with them can spend your funds.");
                },
                None => {
                    println!(
                        "Account '{}' does not have seed words (It might be a View-Only or Ledger wallet).",
                        name
                    );
                },
            }
            Ok(())
        },
        Commands::ShowKeys { security, db, account } => {
            info!("Retrieving wallet keys...");

            wallet_config.apply_database(&db);
            wallet_config.apply_account(&account);

            let pool = init_db(wallet_config.database_path.clone())?;
            let conn = pool.get()?;

            let name = wallet_config.account_name.as_deref().unwrap_or("default");
            let account =
                db::get_account_by_name(&conn, name)?.ok_or_else(|| anyhow!("Account '{}' not found", name))?;

            let (view_key_hex, spend_key_hex) = account.get_keys_hex(&security.password)?;

            println!("---------------------------------------------------------");
            println!("Wallet           : {}", account.friendly_name);
            println!("Private View Key : {}", view_key_hex);
            println!("Public Spend Key : {}", spend_key_hex);
            println!("---------------------------------------------------------");
            println!("WARNING: Keep your private view key safe. Anyone with it can see your transaction history.");
            Ok(())
        },
        Commands::Scan {
            security,
            node,
            db,
            account,
            max_blocks_to_scan,
            fast_sync,
            fast_sync_safety_buffer,
        } => {
            info!("Scanning blockchain...");

            wallet_config.apply_node(&node);
            wallet_config.apply_database(&db);
            wallet_config.apply_account(&account);

            let (events, _more_blocks_to_scan) = if fast_sync {
                let safety_buffer = fast_sync_safety_buffer
                    .or(wallet_config.fast_sync_safety_buffer)
                    .unwrap_or(scan::DEFAULT_FAST_SYNC_SAFETY_BUFFER);
                info!(safety_buffer = safety_buffer; "Fast sync enabled");
                fast_sync_scan(&security.password, &wallet_config, safety_buffer, wallet_config.account_name.as_deref())
                    .await?
            } else {
                scan(
                    &security.password,
                    &wallet_config,
                    max_blocks_to_scan,
                    wallet_config.account_name.as_deref(),
                )
                .await?
            };
            info!(event_count = events.len(); "Scan complete");
            Ok(())
        },
        Commands::ReScan {
            security,
            node,
            db,
            account_name,
            rescan_from_height,
        } => {
            info!(target: "audit", height = rescan_from_height; "Rolling back to block and scanning blockchain");

            wallet_config.apply_node(&node);
            wallet_config.apply_database(&db);

            let webhook_url = wallet_config.webhook.url.clone();
            let send_only_event_types = wallet_config.webhook.send_only_event_types.clone();
            let webhook_trigger_config = webhook_url.map(|url| WebhookTriggerConfig {
                url,
                send_only_event_types: send_only_event_types.clone(),
            });

            let (events, _more_blocks_to_scan) = rescan(
                &security.password,
                &wallet_config,
                &account_name,
                rescan_from_height,
                webhook_trigger_config,
            )
            .await?;
            info!(event_count = events.len(); "Re-scan complete");
            Ok(())
        },
        Commands::Daemon {
            security,
            node,
            db,
            scan_interval_secs,
            api_port,
        } => {
            info!("Starting Tari wallet daemon...");

            wallet_config.apply_node(&node);
            wallet_config.apply_database(&db);

            let webhook_url = wallet_config.webhook.url.clone();
            let webhook_secret = wallet_config.webhook.secret.clone();
            let send_only_event_types = wallet_config.webhook.send_only_event_types.clone();

            let max_blocks_to_scan = u64::MAX;
            let daemon = daemon::Daemon::new(
                security.password,
                wallet_config.base_url,
                wallet_config.database_path,
                max_blocks_to_scan,
                wallet_config.batch_size,
                scan_interval_secs,
                api_port,
                wallet_config.network,
                wallet_config.confirmation_window,
                webhook_url,
                webhook_secret,
                send_only_event_types,
            );
            daemon.run().await?;
            Ok(())
        },
        Commands::Balance { db, account } => {
            info!("Fetching balance...");

            wallet_config.apply_database(&db);
            wallet_config.apply_account(&account);

            handle_balance(&wallet_config)?;
            Ok(())
        },
        Commands::CreateUnsignedTransaction {
            account_name,
            recipient,
            output_file,
            security,
            db,
            tx,
            seconds_to_lock,
        } => {
            info!("Creating unsigned transaction...");

            wallet_config.apply_database(&db);
            wallet_config.apply_transaction(&tx);

            handle_create_unsigned_transaction(
                recipient,
                wallet_config.database_path.clone(),
                account_name,
                wallet_config.network,
                security.password,
                tx.idempotency_key,
                seconds_to_lock,
                wallet_config.confirmation_window,
                output_file,
            )
        },
        Commands::LockFunds {
            account_name,
            output_file,
            db,
            amount,
            num_outputs,
            fee_per_gram,
            estimated_output_size,
            seconds_to_lock_utxos,
            tx,
        } => {
            info!("Locking funds...");

            wallet_config.apply_database(&db);
            wallet_config.apply_transaction(&tx);

            let confirmation_window = tx.confirmation_window.or(Some(wallet_config.confirmation_window));

            let request = LockFundsRequest {
                amount,
                num_outputs: Some(num_outputs),
                fee_per_gram: Some(fee_per_gram),
                estimated_output_size,
                seconds_to_lock_utxos,
                idempotency_key: tx.idempotency_key,
                confirmation_window,
            };
            handle_lock_funds(wallet_config.database_path.clone(), account_name, output_file, request)
        },
        Commands::Delete { db, account } => {
            let name = account.account_name.as_deref().unwrap_or("default");
            info!(target: "audit", account = name; "Deleting wallet...");

            wallet_config.apply_database(&db);

            utils::delete_wallet::delete_wallet(&wallet_config.database_path, name)?;
            println!("Wallet account '{}' deleted successfully.", name);
            Ok(())
        },
    }
}

fn handle_balance(config: &WalletConfig) -> Result<(), anyhow::Error> {
    let pool = init_db(config.database_path.clone())?;
    let conn = pool.get()?;
    let accounts = get_accounts(&conn, config.account_name.as_deref())?;
    for account in accounts {
        let agg_result = get_balance(&conn, account.id)?;
        println!(
            "Balance at height {}({}): {}",
            agg_result.max_height.unwrap_or(0),
            agg_result.max_date.unwrap_or_else(|| "N/A".to_string()),
            agg_result.total,
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_create_unsigned_transaction(
    recipient: Vec<String>,
    database_file: PathBuf,
    account_name: String,
    network: Network,
    password: String,
    idempotency_key: Option<String>,
    seconds_to_lock: u64,
    confirmation_window: u64,
    output_file: String,
) -> Result<(), anyhow::Error> {
    let recipients: Result<Vec<Recipient>, anyhow::Error> = recipient
        .into_iter()
        .map(|r_str| {
            let parts: Vec<&str> = r_str.split("::").collect();
            if parts.len() < 2 || parts.len() > 3 {
                return Err(anyhow!(
                    "Invalid recipient format. Expected 'address::amount' or 'address::amount::payment_id'"
                ));
            }
            let address = TariAddress::from_str(parts[0])?;
            let amount = MicroMinotari::from_str(parts[1])?;
            let payment_id = if parts.len() == 3 {
                Some(parts[2].to_string())
            } else {
                None
            };
            Ok(Recipient {
                address,
                amount,
                payment_id,
            })
        })
        .collect();
    let recipients = recipients?;
    let pool = init_db(database_file)?;
    let conn = pool.get()?;
    let account =
        db::get_account_by_name(&conn, &account_name)?.ok_or_else(|| anyhow!("Account not found: {}", account_name))?;

    let amount = recipients.iter().map(|r| r.amount).sum();
    let num_outputs = recipients.len();
    let fee_per_gram = MicroMinotari(5);
    let estimated_output_size = None;

    let lock_amount = FundLocker::new(pool.clone());
    let locked_funds = lock_amount
        .lock(
            account.id,
            amount,
            num_outputs,
            fee_per_gram,
            estimated_output_size,
            idempotency_key,
            seconds_to_lock,
            confirmation_window,
        )
        .map_err(|e| anyhow!("Failed to lock funds: {}", e))?;

    let one_sided_tx = OneSidedTransaction::new(pool.clone(), network, password.clone());
    let result = one_sided_tx
        .create_unsigned_transaction(&account, locked_funds, recipients, fee_per_gram)
        .map_err(|e| anyhow!("Failed to create an unsigned transaction: {}", e))?;

    create_dir_all(Path::new(&output_file).parent().unwrap())?;
    fs::write(output_file, serde_json::to_string_pretty(&result)?)?;

    info!(target:"audit", "Unsigned transaction written to file.");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_lock_funds(
    database_file: PathBuf,
    account_name: String,
    output_file: String,
    request: LockFundsRequest,
) -> Result<(), anyhow::Error> {
    let pool = init_db(database_file)?;
    let conn = pool.get()?;
    let account =
        db::get_account_by_name(&conn, &account_name)?.ok_or_else(|| anyhow!("Account not found: {}", account_name))?;
    let lock_amount = FundLocker::new(pool.clone());
    let result = lock_amount
        .lock(
            account.id,
            request.amount,
            request.num_outputs.expect("must be present"),
            request.fee_per_gram.expect("must be present"),
            request.estimated_output_size,
            request.idempotency_key,
            request.seconds_to_lock_utxos.expect("must be present"),
            request.confirmation_window.expect("must be present"),
        )
        .map_err(|e| anyhow!("Failed to lock funds: {}", e))?;

    create_dir_all(Path::new(&output_file).parent().unwrap())?;
    fs::write(output_file, serde_json::to_string_pretty(&result)?)?;

    info!(target:"audit", "Locked funds output written to file.");
    Ok(())
}

async fn scan(
    password: &str,
    config: &WalletConfig,
    max_blocks: u64,
    account_name: Option<&str>,
) -> Result<(Vec<WalletEvent>, bool), ScanError> {
    let mut scanner = scan::Scanner::new(
        password,
        &config.base_url,
        config.database_path.clone(),
        config.batch_size,
        config.confirmation_window,
    )
    .mode(scan::ScanMode::Partial { max_blocks });

    if let Some(name) = account_name {
        scanner = scanner.account(name);
    }

    if let Some(url) = &config.webhook.url {
        let trigger_config = WebhookTriggerConfig {
            url: url.clone(),
            send_only_event_types: config.webhook.send_only_event_types.clone(),
        };
        scanner = scanner.webhook_config(trigger_config);
    }

    scanner.run().await
}

async fn fast_sync_scan(
    password: &str,
    config: &WalletConfig,
    safety_buffer: u64,
    account_name: Option<&str>,
) -> Result<(Vec<WalletEvent>, bool), ScanError> {
    let mut scanner = scan::Scanner::new(
        password,
        &config.base_url,
        config.database_path.clone(),
        config.batch_size,
        config.confirmation_window,
    )
    .mode(scan::ScanMode::FastSync { safety_buffer });

    if let Some(name) = account_name {
        scanner = scanner.account(name);
    }

    if let Some(url) = &config.webhook.url {
        let trigger_config = WebhookTriggerConfig {
            url: url.clone(),
            send_only_event_types: config.webhook.send_only_event_types.clone(),
        };
        scanner = scanner.webhook_config(trigger_config);
    }

    scanner.run().await
}

async fn rescan(
    password: &str,
    config: &WalletConfig,
    account_name: &str,
    rescan_from_height: u64,
    webhook_config: Option<WebhookTriggerConfig>,
) -> Result<(Vec<WalletEvent>, bool), ScanError> {
    let db_file_clone = config.database_path.clone();
    let account_name_clone = account_name.to_string();

    let webhook_config_cloned = webhook_config.clone();
    tokio::task::spawn_blocking(move || {
        let pool = init_db(db_file_clone).map_err(|e| format!("Failed to init db: {}", e))?;

        let conn = pool.get().map_err(|e| format!("Failed to get connection: {}", e))?;

        let account = db::get_account_by_name(&conn, &account_name_clone)
            .map_err(|e| format!("DB error querying account: {}", e))?
            .ok_or_else(|| format!("Account not found: {}", account_name_clone))?;

        rollback_from_height(&conn, account.id, rescan_from_height, webhook_config_cloned)
            .map_err(|e| format!("Rollback failed: {}", e))?;

        Ok::<(), String>(())
    })
    .await
    .map_err(|e| ScanError::DbError(WalletDbError::Unexpected(format!("Task join error: {}", e))))?
    .map_err(|e| ScanError::DbError(WalletDbError::Unexpected(e)))?;

    let max_blocks_to_scan = u64::MAX;
    let mut scanner = scan::Scanner::new(
        password,
        &config.base_url,
        config.database_path.clone(),
        config.batch_size,
        config.confirmation_window,
    )
    .mode(scan::ScanMode::Partial {
        max_blocks: max_blocks_to_scan,
    });
    if let Some(cfg) = webhook_config {
        scanner = scanner.webhook_config(cfg);
    }
    scanner = scanner.account(account_name);
    scanner.run().await
}

fn init_with_view_key(
    view_private_key: &str,
    spend_public_key: &str,
    password: &str,
    database_file: &Path,
    birthday: u16,
) -> Result<(), anyhow::Error> {
    utils::init_wallet::init_with_view_key(
        view_private_key,
        spend_public_key,
        password,
        database_file,
        birthday,
        None,
    )
}
