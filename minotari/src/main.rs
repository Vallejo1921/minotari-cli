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

// Unit tests may use plain arithmetic; production code is still checked because
// `clippy::arithmetic_side_effects` is linted on the non-test build of this crate.
// (clippy has no `allow-arithmetic-side-effects-in-tests` option.)
#![cfg_attr(test, allow(clippy::arithmetic_side_effects))]

use std::{
    fs::{self, create_dir_all},
    path::{Path, PathBuf},
};

use anyhow::anyhow;
use clap::Parser;
use log::info;
use minotari::{
    ScanError,
    api::{ApiAuth, accounts::LockFundsRequest, auth::API_TOKEN_ENV_VAR, resolve_api_token},
    cli::{ApplyArgs, Cli, Commands, DaemonArgs},
    commands::{abandon_send, burn::handle_burn_funds, validator_nodes},
    config::{defaults::WalletConfig, loader::load_configuration},
    daemon::{self, ApiServerConfig},
    db::{self, get_accounts, get_balance, init_db},
    log::{init_logging, mask_string},
    migrate::{MigrationOptions, run_migration},
    models::WalletEvent,
    scan, signing,
    transactions::{
        fee_estimator::{estimated_output_size_for_recipients, one_sided_output_sizes},
        fund_locker::{FundLocker, release_reservation},
        idempotency::{IdempotencyBinding, IdempotencyOperation, RequestFingerprint},
        input_selector::InputSelector,
        one_sided_transaction::{
            OneSidedTransaction, Recipient, check_recipient_networks, total_recipient_amount,
            unsigned_transaction_binding,
        },
    },
    utils::{self, crypto::PasswordCipher},
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
use zeroize::Zeroizing;

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    init_logging();
    let cli = Cli::parse();
    let config_obj = load_configuration(&cli.config, cli.network)?;
    let mut wallet_config = WalletConfig::load_from(&config_obj)?;
    // A config file setting `confirmation_window = 0` would let the wallet spend
    // outputs from the block it is still scanning.
    wallet_config.enforce_minimum_confirmation_window();

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
                // Each field gets its own nonce: XChaCha20 is a stream cipher, so encrypting two
                // messages under the same (key, nonce) pair would xor them into a shared keystream.
                let cipher = PasswordCipher::new(&password)?;

                let (encrypted_view_key, view_key_nonce) = cipher.encrypt(view_key.as_bytes())?;
                let (encrypted_spend_key, spend_key_nonce) = cipher.encrypt(spend_key.pub_key.as_bytes())?;
                let (encrypted_seed_words, seed_words_nonce) = cipher.encrypt(seed_words.reveal().as_bytes())?;

                serde_json::json!({
                    "address": tari_address.to_base58(),
                    "encrypted_view_key": hex::encode(encrypted_view_key),
                    "view_key_nonce": hex::encode(view_key_nonce),
                    "encrypted_spend_key": hex::encode(encrypted_spend_key),
                    "spend_key_nonce": hex::encode(spend_key_nonce),
                    "encrypted_seed_words": hex::encode(encrypted_seed_words),
                    "seed_words_nonce": hex::encode(seed_words_nonce),
                    "salt": hex::encode(cipher.salt()),
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
            println!("Private View Key : {}", view_key_hex.as_str());
            println!("Public Spend Key : {}", spend_key_hex);
            println!("---------------------------------------------------------");
            println!("WARNING: Keep your private view key safe. Anyone with it can see your transaction history.");
            Ok(())
        },
        Commands::SignMessage {
            security,
            db,
            account,
            message,
        } => {
            wallet_config.apply_database(&db);
            wallet_config.apply_account(&account);

            let pool = init_db(wallet_config.database_path.clone())?;
            let conn = pool.get()?;

            let name = wallet_config.account_name.as_deref().unwrap_or("default");
            let account =
                db::get_account_by_name(&conn, name)?.ok_or_else(|| anyhow!("Account '{}' not found", name))?;

            println!("{}", signing::sign_message(&account, &security.password, &message)?);
            Ok(())
        },
        Commands::VerifyMessage {
            address,
            message,
            signature,
        } => {
            let address = TariAddress::from_base58(&address)?;
            if signing::verify_message(&address, &message, &signature)? {
                println!("Signature is valid for the spend key of {}", address.to_base58());
                Ok(())
            } else {
                Err(anyhow!("Signature is invalid"))
            }
        },
        Commands::Scan {
            security,
            node,
            db,
            account,
            max_blocks_to_scan,
        } => {
            info!("Scanning blockchain...");

            wallet_config.apply_node(&node);
            wallet_config.apply_database(&db);
            wallet_config.apply_account(&account);

            let (events, _more_blocks_to_scan) = scan(
                &security.password,
                &wallet_config,
                max_blocks_to_scan,
                wallet_config.account_name.as_deref(),
            )
            .await?;
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

            let (events, _more_blocks_to_scan) = scan::rescan(
                &security.password,
                &wallet_config,
                &account_name,
                rescan_from_height,
                scan::ScanMode::Partial { max_blocks: u64::MAX },
                None,
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
            api_bind_address,
            api_token,
            api_disable_auth,
        } => {
            info!("Starting Tari wallet daemon...");

            wallet_config.apply_node(&node);
            wallet_config.apply_database(&db);
            // Kept separate so the precedence stays CLI > environment > config file;
            // `apply_daemon` folds the CLI value into the config, which would otherwise
            // make the two indistinguishable.
            let cli_api_token = api_token.clone();
            wallet_config.apply_daemon(&DaemonArgs {
                scan_interval_secs,
                api_port,
                api_bind_address,
                api_token,
                api_disable_auth,
            });

            // Disabling authentication wins over any configured token: it is the more
            // explicit instruction, and resolving a token here would only mislead the
            // operator into thinking it is being enforced.
            let api_auth = if wallet_config.api_disable_auth {
                ApiAuth::Disabled
            } else {
                let (api_token, generated_token) =
                    resolve_api_token(cli_api_token.as_deref(), wallet_config.api_token.as_deref())?;
                if let Some(token) = &generated_token {
                    // Printed rather than logged: the log file is long-lived and often
                    // shipped elsewhere, and this secret unlocks fund-moving endpoints.
                    eprintln!(
                        "\n\
                         ============================================================\n\
                         No API token configured, so one was generated for this run:\n\
                         \n    {token}\n\n\
                         Send it with every API request:\n\
                         \n    Authorization: Bearer {token}\n\n\
                         Set {API_TOKEN_ENV_VAR} or `api_token` in config.toml to keep\n\
                         a stable token across restarts.\n\
                         ============================================================\n",
                        token = token.as_str()
                    );
                }
                ApiAuth::Required(api_token)
            };

            let webhook_url = wallet_config.webhook.url.clone();
            let webhook_secret = wallet_config.webhook.secret.clone();
            let send_only_event_types = wallet_config.webhook.send_only_event_types.clone();
            let burn_proofs_dir = wallet_config.effective_burn_proofs_dir();

            let max_blocks_to_scan = u64::MAX;
            let daemon = daemon::Daemon::new(
                Zeroizing::new(security.password),
                wallet_config.base_url,
                wallet_config.database_path,
                max_blocks_to_scan,
                wallet_config.batch_size,
                wallet_config.scan_interval_secs,
                ApiServerConfig {
                    bind_address: wallet_config.api_bind_address,
                    port: wallet_config.api_port,
                    auth: api_auth,
                },
                wallet_config.network,
                wallet_config.confirmation_window,
                webhook_url,
                webhook_secret,
                send_only_event_types,
                burn_proofs_dir,
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
            send_all,
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
                send_all,
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
        Commands::RegisterValidatorNode {
            security,
            node,
            db,
            tx,
            account_name,
            vn_public_key,
            vn_sig_nonce,
            vn_sig,
            claim_public_key,
            max_epoch,
            fee_per_gram,
            payment_id,
            sidechain_deployment_key,
            seconds_to_lock,
        } => {
            info!(target: "audit", account = account_name.as_str(); "Registering validator node...");

            wallet_config.apply_node(&node);
            wallet_config.apply_database(&db);
            wallet_config.apply_transaction(&tx);

            validator_nodes::handle_register_validator_node(
                vn_public_key,
                vn_sig_nonce,
                vn_sig,
                claim_public_key,
                max_epoch,
                fee_per_gram,
                payment_id,
                sidechain_deployment_key,
                wallet_config.database_path.clone(),
                account_name,
                wallet_config.network,
                security.password,
                tx.idempotency_key,
                seconds_to_lock,
                wallet_config.confirmation_window,
                wallet_config.base_url,
            )
            .await
        },
        Commands::SubmitValidatorNodeExit {
            security,
            node,
            db,
            tx,
            account_name,
            vn_public_key,
            vn_sig_nonce,
            vn_sig,
            activation_epoch,
            max_epoch,
            fee_per_gram,
            payment_id,
            sidechain_deployment_key,
            seconds_to_lock,
        } => {
            info!(target: "audit", account = account_name.as_str(); "Submitting validator node exit...");

            wallet_config.apply_node(&node);
            wallet_config.apply_database(&db);
            wallet_config.apply_transaction(&tx);

            validator_nodes::handle_submit_validator_node_exit(
                vn_public_key,
                vn_sig_nonce,
                vn_sig,
                activation_epoch,
                max_epoch,
                fee_per_gram,
                payment_id,
                sidechain_deployment_key,
                wallet_config.database_path.clone(),
                account_name,
                wallet_config.network,
                security.password,
                tx.idempotency_key,
                seconds_to_lock,
                wallet_config.confirmation_window,
                wallet_config.base_url,
            )
            .await
        },
        Commands::AbandonSend {
            db,
            account,
            tx_id,
            force,
            accept_unreconcilable,
        } => {
            let name = account.account_name.as_deref().unwrap_or("default");
            info!(target: "audit", account = name, tx_id = tx_id; "Abandoning send...");

            wallet_config.apply_database(&db);
            let webhook_trigger_config = wallet_config.webhook.url.clone().map(|url| WebhookTriggerConfig {
                url,
                send_only_event_types: wallet_config.webhook.send_only_event_types.clone(),
            });

            abandon_send::handle_abandon_send(
                wallet_config.database_path.clone(),
                name,
                tx_id,
                force,
                accept_unreconcilable,
                webhook_trigger_config,
            )
        },
        Commands::Delete { db, account } => {
            let name = account.account_name.as_deref().unwrap_or("default");
            info!(target: "audit", account = name; "Deleting wallet...");

            wallet_config.apply_database(&db);

            utils::delete_wallet::delete_wallet(&wallet_config.database_path, name)?;
            println!("Wallet account '{}' deleted successfully.", name);
            Ok(())
        },

        Commands::MigrateFromConsoleWallet {
            source_db,
            source_password,
            security,
            db,
            account_name,
            dry_run,
        } => {
            info!(
                target: "audit",
                source = source_db.display().to_string().as_str(),
                account = account_name.as_str(),
                dry_run = dry_run;
                "Migrating from console wallet"
            );

            wallet_config.apply_database(&db);

            let report = tokio::task::spawn_blocking(move || {
                run_migration(MigrationOptions {
                    source_db_path: source_db,
                    source_passphrase: source_password,
                    destination_db_path: wallet_config.database_path,
                    destination_passphrase: security.password,
                    account_name,
                    dry_run,
                })
            })
            .await
            .map_err(|e| anyhow!("Migration task join error: {}", e))??;

            println!("---------------------------------------------------------");
            if report.dry_run {
                println!("Migration DRY-RUN complete (nothing was written):");
            } else {
                println!("Migration complete:");
            }
            println!("  Account name           : {}", report.account_name);
            println!("  Outputs migrated       : {}", report.outputs_migrated);
            println!("    Unspent              : {}", report.unspent_outputs_count);
            println!("    Spent                : {}", report.spent_outputs_count);
            println!("  Outputs skipped        : {}", report.outputs_skipped);
            println!("  Transactions migrated  : {}", report.displayed_transactions_migrated);
            println!(
                "    With matched outputs : {}",
                report.displayed_transactions_with_matched_outputs
            );
            println!("  Source balance         : {} uT", report.source_balance.as_u64());
            println!("  Imported balance       : {} uT", report.net_balance().as_u64());
            println!(
                "  Balance match          : {}",
                if report.balance_match { "YES" } else { "NO" }
            );
            if let Some(h) = report.scan_tip_height {
                println!("  Resumed scan tip       : block {}", h);
            } else {
                println!("  Resumed scan tip       : none (full scan will be required)");
            }
            println!("---------------------------------------------------------");
            if !report.balance_match && !report.dry_run {
                return Err(anyhow!(
                    "Migration balance mismatch: source = {} uT, imported = {} uT. \
                     Re-run with --dry-run to investigate.",
                    report.source_balance.as_u64(),
                    report.net_balance().as_u64()
                ));
            }
            Ok(())
        },

        Commands::BurnFunds {
            security,
            db,
            tx,
            burn,
            node,
            account_name,
            amount,
            claim_public_key,
            sidechain_deployment_key,
            fee_per_gram,
            payment_id,
            seconds_to_lock,
        } => {
            info!(target: "audit", "Burning funds...");

            wallet_config.apply_database(&db);
            wallet_config.apply_transaction(&tx);
            wallet_config.apply_node(&node);
            wallet_config.apply_burn(&burn);

            handle_burn_funds(
                account_name,
                amount,
                claim_public_key,
                fee_per_gram,
                payment_id,
                sidechain_deployment_key,
                wallet_config.database_path.clone(),
                wallet_config.network,
                security.password,
                tx.idempotency_key,
                seconds_to_lock,
                wallet_config.confirmation_window,
                wallet_config.base_url.clone(),
            )
            .await
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
    send_all: bool,
    database_file: PathBuf,
    account_name: String,
    network: Network,
    password: String,
    idempotency_key: Option<String>,
    seconds_to_lock: u64,
    confirmation_window: u64,
    output_file: String,
) -> Result<(), anyhow::Error> {
    if send_all && recipient.len() != 1 {
        return Err(anyhow!("--send-all takes exactly one recipient"));
    }
    let recipients: Result<Vec<Recipient>, anyhow::Error> = recipient
        .into_iter()
        .map(|r_str| {
            let parts: Vec<&str> = r_str.split("::").collect();
            if send_all {
                // The amount is worked out from the inputs once they are locked.
                if parts.len() > 2 {
                    return Err(anyhow!(
                        "Invalid recipient format for --send-all. Expected 'address' or 'address::payment_id'"
                    ));
                }
                return Ok(Recipient {
                    address: TariAddress::from_str(parts.first().expect("split yields at least one part"))?,
                    amount: MicroMinotari::zero(),
                    payment_id: parts.get(1).map(|s| s.to_string()),
                });
            }
            if parts.len() < 2 || parts.len() > 3 {
                return Err(anyhow!(
                    "Invalid recipient format. Expected 'address::amount' or 'address::amount::payment_id'"
                ));
            }
            let address = TariAddress::from_str(parts.first().expect("Already checked"))?;
            let amount = MicroMinotari::from_str(parts.get(1).expect("Already checked"))?;
            let payment_id = if parts.len() == 3 {
                Some(parts.get(2).expect("Already checked").to_string())
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
    let mut recipients = recipients?;
    check_recipient_networks(&recipients, network)?;
    let pool = init_db(database_file)?;
    // One connection for the whole command; `lock` uses this one rather than taking a
    // second from the pool.
    let mut conn = pool.get()?;
    let account =
        db::get_account_by_name(&conn, &account_name)?.ok_or_else(|| anyhow!("Account not found: {}", account_name))?;

    // Refuse an empty list, a zero amount or an overflowing total before anything is locked.
    let amount = if send_all {
        MicroMinotari::zero()
    } else {
        total_recipient_amount(&recipients, network)?
    };
    let num_outputs = recipients.len();
    let fee_per_gram = MicroMinotari(5);
    // Charge for the memos this send will carry; anything smaller reserves inputs that cannot
    // pay the fee the builder lands on.
    let estimated_output_size = Some(estimated_output_size_for_recipients(&recipients)?);

    // Same binding the REST endpoint builds, so a key means the same thing
    // whichever way the request arrives.
    let idempotency = unsigned_transaction_binding(
        idempotency_key,
        account.id,
        &recipients,
        fee_per_gram,
        seconds_to_lock,
        confirmation_window,
        send_all,
    );
    let lock_amount = FundLocker::new();
    let locked_funds = if send_all {
        let (recipient_output_size, change_output_size) = one_sided_output_sizes(&recipients, network)?;
        lock_amount.lock_all(
            &mut conn,
            account.id,
            network,
            fee_per_gram,
            recipient_output_size,
            change_output_size,
            idempotency,
            seconds_to_lock,
            confirmation_window,
        )
    } else {
        lock_amount.lock(
            &mut conn,
            account.id,
            amount,
            num_outputs,
            fee_per_gram,
            estimated_output_size,
            idempotency,
            seconds_to_lock,
            confirmation_window,
        )
    }
    .map_err(|e| anyhow!("Failed to lock funds: {}", e))?;

    let reservation_id = locked_funds.reservation_id.clone();
    let created_reservation = locked_funds.created_reservation;
    // Not known on a replay: the counts are not stored.
    let send_all_skipped = locked_funds.send_all_skipped;
    let written = (|| -> Result<(), anyhow::Error> {
        if send_all {
            let input_selector = InputSelector::new(account.id, confirmation_window);
            let amount =
                input_selector.send_all_amount(locked_funds.total_value, locked_funds.fee_with_change, fee_per_gram)?;
            input_selector.audit_send_all(
                &reservation_id,
                amount,
                locked_funds.fee_with_change,
                locked_funds.utxos.len(),
            );
            for recipient in &mut recipients {
                recipient.amount = amount;
            }
        }

        let one_sided_tx = OneSidedTransaction::new(pool.clone(), network, Zeroizing::new(password.clone()));
        let result = one_sided_tx
            .create_unsigned_transaction(&account, locked_funds, recipients, fee_per_gram)
            .map_err(|e| anyhow!("Failed to create an unsigned transaction: {}", e))?;

        if let Some(parent) = Path::new(&output_file).parent() {
            create_dir_all(parent)?;
        }
        fs::write(&output_file, serde_json::to_string_pretty(&result)?)?;
        Ok(())
    })();
    // A reservation this command took is no use to anyone once its send failed.
    if written.is_err() && created_reservation {
        release_reservation(&conn, &reservation_id);
    }
    written?;

    if let Some(skipped) = send_all_skipped
        && (skipped.skipped_dust > 0 || skipped.skipped_over_cap > 0)
    {
        eprintln!(
            "Warning: this send-all left spendable outputs behind. {} did not fit in one transaction; \
             run send-all again to sweep them. {} are dust, worth less than they cost to spend, and are \
             never worth sending.",
            skipped.skipped_over_cap, skipped.skipped_dust
        );
    }

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
    // One connection for the whole command; `lock` uses this one rather than taking a
    // second from the pool.
    let mut conn = pool.get()?;
    let account =
        db::get_account_by_name(&conn, &account_name)?.ok_or_else(|| anyhow!("Account not found: {}", account_name))?;
    let num_outputs = request.num_outputs.expect("must be present");
    let fee_per_gram = request.fee_per_gram.expect("must be present");
    let seconds_to_lock_utxos = request.seconds_to_lock_utxos.expect("must be present");
    let confirmation_window = request.confirmation_window.expect("must be present");
    // Mirrors the fingerprint built by `api_lock_funds`, so the same key and the
    // same parameters mean the same reservation from either entry point.
    let idempotency = IdempotencyBinding::new(
        request.idempotency_key,
        IdempotencyOperation::LockFunds,
        RequestFingerprint::new(IdempotencyOperation::LockFunds)
            .field("account_id", account.id.to_le_bytes())
            .field("amount", request.amount.as_u64().to_le_bytes())
            .field("num_outputs", (num_outputs as u64).to_le_bytes())
            .field("fee_per_gram", fee_per_gram.as_u64().to_le_bytes())
            .optional_field(
                "estimated_output_size",
                request.estimated_output_size.map(|s| (s as u64).to_le_bytes()),
            )
            .field("seconds_to_lock_utxos", seconds_to_lock_utxos.to_le_bytes())
            .field("confirmation_window", confirmation_window.to_le_bytes()),
    );
    let lock_amount = FundLocker::new();
    let result = lock_amount
        .lock(
            &mut conn,
            account.id,
            request.amount,
            num_outputs,
            fee_per_gram,
            request.estimated_output_size,
            idempotency,
            seconds_to_lock_utxos,
            confirmation_window,
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
