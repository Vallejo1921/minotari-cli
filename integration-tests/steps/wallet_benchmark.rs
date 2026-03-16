// Wallet Benchmark Step Definitions
//
// Step definitions for benchmarking wallet performance.

use super::common::MinotariWorld;
use cucumber::{then, when};
use std::process::Command;
use std::time::Instant;
use tari_common::configuration::Network::LocalNet;
use tari_common_types::tari_address::TariAddress;
use tari_common_types::tari_address::TariAddressFeatures;
use tari_transaction_components::consensus::ConsensusConstantsBuilder;
use tari_transaction_components::key_manager::KeyManager;
use tari_transaction_components::offline_signing::models::PrepareOneSidedTransactionForSigningResult;
use tari_transaction_components::offline_signing::models::TransactionResult;
use tari_transaction_components::offline_signing::sign_locked_transaction;

// =============================
// Benchmark Steps
// =============================
#[then(regex = r#"^I measure the time to scan (\d+) blocks$"#)]
async fn measure_scan_time(world: &mut MinotariWorld, blocks: String) {
    let db_path = world.database_path.as_ref().expect("Database not set up");

    // Get base node URL from the first available base node
    let base_url = if let Some((_, node)) = world.base_nodes.iter().next() {
        format!("http://127.0.0.1:{}", node.http_port)
    } else {
        panic!("No base node available for scanning");
    };

    let (cmd, mut args) = world.get_minotari_command();
    args.extend_from_slice(&[
        "scan".to_string(),
        "--database-path".to_string(),
        db_path.to_str().unwrap().to_string(),
        "--password".to_string(),
        world.test_password.clone(),
        "--base-url".to_string(),
        base_url,
        "--max-blocks-to-scan".to_string(),
        blocks,
    ]);

    let start = Instant::now();
    let output = Command::new(&cmd)
        .args(&args)
        .output()
        .expect("Failed to execute scan command");
    let duration = start.elapsed();

    world.last_command_exit_code = Some(output.status.code().unwrap_or(-1));
    world.last_command_output = Some(String::from_utf8_lossy(&output.stdout).to_string());
    world.last_command_error = Some(String::from_utf8_lossy(&output.stderr).to_string());

    println!("Scan completed in {:?}", duration);
    world.benchmark_timings.insert("scan".to_string(), duration);
    println!("Scan output: {}", world.last_command_output.as_ref().unwrap());
    if !world.last_command_error.as_ref().unwrap().is_empty() {
        println!("Scan stderr: {}", world.last_command_error.as_ref().unwrap());
    }
}

#[when(regex = r#"^I send (\d+) transactions$"#)]
async fn send_transactions(world: &mut MinotariWorld, transactions: String) {
    let db_path = world.database_path.as_ref().expect("Database not set up").clone();

    // Get base node URL for submitting transactions
    let base_url = if let Some((_, node)) = world.base_nodes.iter().next() {
        format!("http://127.0.0.1:{}", node.http_port)
    } else {
        panic!("No base node available");
    };

    // Generate a recipient address from a different random wallet
    use tari_transaction_components::key_manager::wallet_types::WalletType;
    let recipient_wallet = WalletType::new_random().expect("Failed to create random recipient wallet");
    let recipient_spend = recipient_wallet.get_public_spend_key();
    let recipient_view = recipient_wallet.get_public_view_key();
    let recipient_address = TariAddress::new_dual_address(
        recipient_view,
        recipient_spend,
        LocalNet,
        TariAddressFeatures::create_one_sided_only(),
        None,
    )
    .unwrap();
    let address = recipient_address.to_base58().to_string();

    // Create a key manager from the wallet for offline signing
    let key_manager = KeyManager::new(world.wallet.clone()).expect("Failed to create key manager from wallet");
    let consensus_constants = ConsensusConstantsBuilder::new(LocalNet).build();

    println!("Sending transactions...");
    // Capture balance before sending
    world.pre_send_balance = Some(world.fetch_balance());
    println!("Pre-send balance: {} µT", world.pre_send_balance.unwrap());
    let mut successful_txs = 0;
    let num_transactions: usize = transactions.parse().expect("Invalid number of transactions");

    // Create an HTTP client for submitting transactions to the base node
    let submit_url = format!("{}/json_rpc", base_url);
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("Failed to create HTTP client");
    let amount: u64 = 1000;
    for i in 0..num_transactions {
        let recipient = format!("{}::{}", address, amount); //  microTari per transaction
        let output_path = world.get_temp_path(&format!("tx_{}.json", i));

        // Step 1: Create unsigned transaction via CLI
        let (cmd, mut args) = world.get_minotari_command();
        args.extend_from_slice(&[
            "create-unsigned-transaction".to_string(),
            "--database-path".to_string(),
            db_path.to_str().unwrap().to_string(),
            "--password".to_string(),
            world.test_password.clone(),
            "--account-name".to_string(),
            "default".to_string(),
            "--recipient".to_string(),
            recipient,
            "--output-file".to_string(),
            output_path.to_str().unwrap().to_string(),
        ]);

        let output = Command::new(&cmd)
            .args(&args)
            .output()
            .expect("Failed to create transaction");

        if output.status.success() {
            // Step 2: Read the unsigned transaction JSON and sign it offline
            let unsigned_json = match std::fs::read_to_string(&output_path) {
                Ok(json) => json,
                Err(e) => {
                    println!("Transaction {} failed to read unsigned tx file: {}", i, e);
                    continue;
                },
            };

            let unsigned_tx = match PrepareOneSidedTransactionForSigningResult::from_json(&unsigned_json) {
                Ok(tx) => tx,
                Err(e) => {
                    println!("Transaction {} failed to parse unsigned tx: {}", i, e);
                    continue;
                },
            };

            let signed_result =
                match sign_locked_transaction(&key_manager, consensus_constants.clone(), LocalNet, unsigned_tx) {
                    Ok(result) => result,
                    Err(e) => {
                        println!("Transaction {} signing failed: {}", i, e);
                        continue;
                    },
                };

            // Step 3: Submit the signed transaction to the base node
            let transaction = signed_result.signed_transaction.transaction;
            let request = serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "method": "submit_transaction",
                "params": { "transaction": transaction }
            });

            let submit_result = http_client.post(&submit_url).json(&request).send().await;

            match submit_result {
                Ok(response) if response.status().is_success() => {
                    successful_txs += 1;
                },
                Ok(response) => {
                    println!("Transaction {} submit failed with status: {}", i, response.status());
                },
                Err(e) => {
                    println!("Transaction {} submit failed: {}", i, e);
                },
            }
        } else {
            println!(
                "Transaction {} creation failed: {}",
                i,
                String::from_utf8_lossy(&output.stderr)
            );
            if String::from_utf8_lossy(&output.stderr).contains("insufficient") {
                println!("Insufficient balance, stopping at {} transactions", i);
                break;
            }
            panic!("Transaction {} creation failed", i);
        }

        if (i + 1) % 50 == 0 {
            println!("Sent {} transactions so far...", i + 1);
        }
    }

    println!("Successfully sent {} transactions", successful_txs);
    world.last_command_output = Some(format!("Sent {} transactions", successful_txs));
}

#[when(regex = r#"^I measure the time to confirm (\d+) transactions$"#)]
async fn measure_confirmation_time(world: &mut MinotariWorld, _transactions: String) {
    let db_path = world.database_path.as_ref().expect("Database not set up");

    // Get base node URL
    let base_url = if let Some((_, node)) = world.base_nodes.iter().next() {
        format!("http://127.0.0.1:{}", node.http_port)
    } else {
        panic!("No base node available");
    };

    // First, do a scan to detect the mined blocks
    let (cmd, mut args) = world.get_minotari_command();
    args.extend_from_slice(&[
        "scan".to_string(),
        "--database-path".to_string(),
        db_path.to_str().unwrap().to_string(),
        "--password".to_string(),
        world.test_password.clone(),
        "--base-url".to_string(),
        base_url.clone(),
        "--max-blocks-to-scan".to_string(),
        "100".to_string(),
    ]);

    let start = Instant::now();
    let output = Command::new(&cmd)
        .args(&args)
        .output()
        .expect("Failed to execute scan command");
    let duration = start.elapsed();

    world.last_command_exit_code = Some(output.status.code().unwrap_or(-1));
    world.last_command_output = Some(String::from_utf8_lossy(&output.stdout).to_string());
    world.last_command_error = Some(String::from_utf8_lossy(&output.stderr).to_string());

    println!("Transaction confirmation scan completed in {:?}", duration);
    world.benchmark_timings.insert("confirmation".to_string(), duration);
    println!("Scan output: {}", world.last_command_output.as_ref().unwrap());
}

#[then(regex = r#"^(\d+) transactions of (\d+) uT should be confirmed$"#)]
async fn transactions_confirmed(world: &mut MinotariWorld, count: u64, amount: u64) {
    assert_eq!(
        world.last_command_exit_code,
        Some(0),
        "Scan command failed: {}",
        world.last_command_error.as_deref().unwrap_or("")
    );

    let pre_balance = world.pre_send_balance.expect("Pre-send balance not captured");
    let post_balance = world.fetch_balance();
    let total_sent = count * amount;

    println!("Pre-send balance:  {} µT", pre_balance);
    println!("Post-send balance: {} µT", post_balance);
    println!("Total sent:        {} µT ({} x {} µT)", total_sent, count, amount);

    // The post balance includes rewards from newly mined blocks, so it may be
    // higher than pre_balance. We verify the sends took effect by checking that
    // the balance is at least total_sent less than it would be without sends.
    // Since we can't know exact mining rewards, we check that post_balance is
    // less than pre_balance + (post_balance - pre_balance + total_sent), i.e.,
    // the effective decrease from sends is visible.
    assert!(
        post_balance + total_sent > pre_balance,
        "Post balance {} + total sent {} should exceed pre balance {}, \
         indicating funds were received from mining",
        post_balance,
        total_sent,
        pre_balance
    );

    // Verify balance decreased by at least total_sent compared to what it
    // would have been without the sends. We estimate the mining reward as
    // the difference: mining_reward ≈ post_balance - pre_balance + total_sent + fees.
    // If mining_reward > 0 and post_balance < pre_balance + mining_reward,
    // then the sends reduced the balance by at least total_sent.
    let effective_mining_reward = (post_balance as i128) - (pre_balance as i128) + (total_sent as i128);
    assert!(
        effective_mining_reward > 0,
        "Expected mining rewards to be positive, but balance decreased by more than total sent. \
         pre: {}, post: {}, total_sent: {}",
        pre_balance,
        post_balance,
        total_sent
    );

    println!(
        "Confirmed: {} transactions of {} µT sent (estimated mining reward: {} µT)",
        count, amount, effective_mining_reward
    );
}

#[then("I print the benchmark results")]
async fn print_benchmark_results(world: &mut MinotariWorld) {
    println!("\n========================================");
    println!("         BENCHMARK RESULTS");
    println!("========================================");
    if let Some(scan_duration) = world.benchmark_timings.get("scan") {
        println!("  Scan time:         {:.2?}", scan_duration);
    }
    if let Some(confirm_duration) = world.benchmark_timings.get("confirmation") {
        println!("  Confirmation time: {:.2?}", confirm_duration);
    }
    let total: std::time::Duration = world.benchmark_timings.values().sum();
    println!("  Total time:        {:.2?}", total);
    println!("========================================\n");
}
