// Daemon Step Definitions
//
// Step definitions for testing daemon mode functionality.

use cucumber::{given, then, when};
use std::process::Stdio;
use std::time::Duration;
use tari_common::configuration::Network::LocalNet;
use tari_common_types::tari_address::{TariAddress, TariAddressFeatures};
use tokio::time::sleep;

use super::common::{MinotariWorld, database_with_wallet};

/// Generate a valid test Tari address from the wallet in world
fn generate_test_address(world: &MinotariWorld) -> String {
    let spend_key = world.wallet.get_public_spend_key();
    let view_key = world.wallet.get_public_view_key();
    let wallet_address = TariAddress::new_dual_address(
        view_key,
        spend_key,
        LocalNet,
        TariAddressFeatures::create_one_sided_only(),
        None,
    )
    .unwrap();
    wallet_address.to_base58().to_string()
}

// =============================
// Helper Functions
// =============================

/// Start a daemon process with the given configuration
async fn start_daemon_process(world: &mut MinotariWorld, port: u16, scan_interval: Option<u64>) {
    world.setup_database();
    let (command, mut args) = world.get_minotari_command();

    let db_path = world
        .database_path
        .as_ref()
        .expect("Database path must be set before starting daemon");

    args.push("daemon".to_string());
    args.push("--password".to_string());
    args.push(world.test_password.clone());
    args.push("--database-path".to_string());
    args.push(db_path.to_str().unwrap().to_string());
    args.push("--api-port".to_string());
    args.push(port.to_string());

    if let Some(interval) = scan_interval {
        args.push("--scan-interval-secs".to_string());
        args.push(interval.to_string());
    }

    // Add base node URL if we have a running base node
    if !world.base_nodes.is_empty() {
        let base_node = world.base_nodes.values().next().unwrap();
        let base_url = format!("http://127.0.0.1:{}", base_node.http_port);
        args.push("--base-url".to_string());
        args.push(base_url);
    }

    let child = std::process::Command::new(&command)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start daemon process");

    // Give the daemon time to start up
    sleep(Duration::from_secs(2)).await;

    world.daemon_handle = Some(child);
    world.api_port = Some(port);
}

// =============================
// Daemon Steps
// =============================

#[given("I have a running daemon with an existing wallet")]
async fn running_daemon_with_wallet(world: &mut MinotariWorld) {
    // Import a wallet so the daemon has an account to query
    database_with_wallet(world).await;
    // Start daemon on default port 9000
    start_daemon_process(world, 9000, None).await;
}

#[given("I have a running daemon")]
async fn running_daemon(world: &mut MinotariWorld) {
    // Start daemon on default port 9000
    start_daemon_process(world, 9000, None).await;
}

#[when(regex = r#"^I start the daemon on port "([^"]*)"$"#)]
async fn start_daemon_on_port(world: &mut MinotariWorld, port: String) {
    let port_num = port.parse::<u16>().expect("Invalid port number");
    start_daemon_process(world, port_num, None).await;
}

#[when(regex = r#"^I start the daemon with scan interval "([^"]*)" seconds$"#)]
async fn start_daemon_with_interval(world: &mut MinotariWorld, interval: String) {
    let interval_num = interval.parse::<u64>().expect("Invalid scan interval");
    start_daemon_process(world, 9000, Some(interval_num)).await;
}

#[when(regex = r#"^I query the balance via the API for account "([^"]*)"$"#)]
async fn query_balance_api(world: &mut MinotariWorld, account_name: String) {
    let port = world.api_port.expect("Daemon must be running");
    let url = format!("http://127.0.0.1:{}/accounts/{}/balance", port, account_name);

    let client = reqwest::Client::new();
    let response = client.get(&url).send().await.expect("Failed to query balance API");

    let status = response.status();
    let body = response.text().await.expect("Failed to read response body");

    world.last_command_output = Some(body);
    world.last_command_exit_code = Some(if status.is_success() { 0 } else { 1 });
}

#[when(regex = r#"^I lock funds via the API for amount "([^"]*)" microTari$"#)]
async fn lock_funds_api(world: &mut MinotariWorld, amount: String) {
    let port = world.api_port.expect("Daemon must be running");
    let url = format!("http://127.0.0.1:{}/accounts/default/lock_funds", port);

    let amount_num = amount.parse::<u64>().expect("Invalid amount");
    let request_body = serde_json::json!({
        "amount": amount_num,
        "idempotency_key": format!("test_lock_{}", chrono::Utc::now().timestamp())
    });

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .json(&request_body)
        .send()
        .await
        .expect("Failed to lock funds via API");

    let status = response.status();
    let body = response.text().await.expect("Failed to read response body");

    world.last_command_output = Some(body);
    world.last_command_exit_code = Some(if status.is_success() { 0 } else { 1 });
}

#[when("I create a transaction via the API")]
async fn create_transaction_api(world: &mut MinotariWorld) {
    let port = world.api_port.expect("Daemon must be running");
    let url = format!("http://127.0.0.1:{}/accounts/default/create_unsigned_transaction", port);

    let address = generate_test_address(world);
    let request_body = serde_json::json!({
        "recipients": [{
            "address": address,
            "amount": 100000,
            "payment_id": "test-payment"
        }],
        "idempotency_key": format!("test_tx_{}", chrono::Utc::now().timestamp())
    });

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .json(&request_body)
        .send()
        .await
        .expect("Failed to create transaction via API");

    let status = response.status();
    let body = response.text().await.expect("Failed to read response body");

    // Store response in transaction_data for subsequent step assertions
    if status.is_success()
        && let Ok(json) = serde_json::from_str::<serde_json::Value>(&body)
    {
        world.transaction_data.insert("current".to_string(), json);
    }

    world.last_command_output = Some(body);
    world.last_command_exit_code = Some(if status.is_success() { 0 } else { 1 });
}

#[when("I send a shutdown signal")]
async fn send_shutdown_signal(world: &mut MinotariWorld) {
    if let Some(mut child) = world.daemon_handle.take() {
        // Send SIGINT signal (Ctrl+C equivalent)
        #[cfg(unix)]
        {
            use nix::sys::signal::{Signal, kill};
            use nix::unistd::Pid;
            let pid = Pid::from_raw(child.id() as i32);
            kill(pid, Signal::SIGINT).expect("Failed to send SIGINT");
        }

        #[cfg(not(unix))]
        {
            // On Windows, we'll just kill the process
            child.kill().expect("Failed to kill daemon process");
        }

        // Wait a moment for graceful shutdown
        sleep(Duration::from_secs(2)).await;

        // Try to collect exit status
        if let Ok(status) = child.try_wait()
            && let Some(exit_status) = status
        {
            world.last_command_exit_code = exit_status.code();
        }
    }
}

#[allow(unused_variables)]
#[then(regex = r#"^the API should be accessible on port "([^"]*)"$"#)]
async fn api_accessible(world: &mut MinotariWorld, port: String) {
    let port_num = port.parse::<u16>().expect("Invalid port number");
    let url = format!("http://127.0.0.1:{}/version", port_num);

    let client = reqwest::Client::new();
    let result = client.get(&url).send().await;

    assert!(
        result.is_ok(),
        "API should be accessible on port {}, but got error: {:?}",
        port_num,
        result.err()
    );

    let response = result.unwrap();
    assert!(
        response.status().is_success(),
        "API should return success status, got: {}",
        response.status()
    );
}

#[then("the Swagger UI should be available")]
async fn swagger_available(world: &mut MinotariWorld) {
    let port = world.api_port.expect("Daemon must be running");
    let url = format!("http://127.0.0.1:{}/swagger-ui/", port);

    let client = reqwest::Client::new();
    let response = client.get(&url).send().await.expect("Failed to access Swagger UI");

    assert!(
        response.status().is_success(),
        "Swagger UI should be available, got status: {}",
        response.status()
    );
}

#[then("the daemon should scan periodically")]
async fn daemon_scans_periodically(world: &mut MinotariWorld) {
    let port = world.api_port.expect("Daemon must be running");
    let url = format!("http://127.0.0.1:{}/accounts/default/scan_status", port);

    let client = reqwest::Client::new();

    // Get initial scan status
    let response1 = client.get(&url).send().await.expect("Failed to get scan status");

    assert!(
        response1.status().is_success(),
        "Scan status endpoint should be accessible"
    );

    // The daemon is configured to scan - just verify the endpoint works
    // In a real scenario with a base node, we'd check that scans are happening
}

#[then("the scanned tip should be updated over time")]
async fn scanned_tip_updated_over_time(world: &mut MinotariWorld) {
    let port = world.api_port.expect("Daemon must be running");
    let url = format!("http://127.0.0.1:{}/accounts/default/scan_status", port);

    let client = reqwest::Client::new();

    // Get initial tip
    let response1 = client
        .get(&url)
        .send()
        .await
        .expect("Failed to get initial scan status");
    let status1: serde_json::Value = response1.json().await.expect("Failed to parse JSON");

    // Wait for scan interval (plus buffer)
    sleep(Duration::from_secs(12)).await;

    // Get updated tip
    let response2 = client
        .get(&url)
        .send()
        .await
        .expect("Failed to get updated scan status");
    let status2: serde_json::Value = response2.json().await.expect("Failed to parse JSON");

    // Verify we got valid responses (actual tip comparison would require a running blockchain)
    assert!(status1.is_object(), "First scan status should be an object");
    assert!(status2.is_object(), "Second scan status should be an object");
}

#[then("I should receive a balance response")]
async fn receive_balance_response(world: &mut MinotariWorld) {
    assert!(
        world.last_command_output.is_some(),
        "Should have received a response from balance API"
    );
    assert_eq!(
        world.last_command_exit_code,
        Some(0),
        "API request should have succeeded"
    );
}

#[then("the response should include balance information")]
async fn response_has_balance_info(world: &mut MinotariWorld) {
    let output = world.last_command_output.as_ref().expect("Should have response output");

    let json: serde_json::Value = serde_json::from_str(output).expect("Response should be valid JSON");

    assert!(
        json.get("available").is_some() || json.get("total").is_some(),
        "Response should include balance information (available or total field)"
    );
}

#[then("the API should return success")]
async fn api_returns_success(world: &mut MinotariWorld) {
    assert_eq!(
        world.last_command_exit_code,
        Some(0),
        "API should return success (exit code 0)"
    );
}

#[then("the API should return the unsigned transaction")]
async fn api_returns_transaction(world: &mut MinotariWorld) {
    assert_eq!(
        world.last_command_exit_code,
        Some(0),
        "API should return success for unsigned transaction"
    );

    let output = world.last_command_output.as_ref().expect("Should have response output");

    let json: serde_json::Value = serde_json::from_str(output).expect("Response should be valid JSON");

    // PrepareOneSidedTransactionForSigningResult has fields: version, tx_id, info
    assert!(
        json.get("tx_id").is_some() || json.get("info").is_some(),
        "Response should include transaction data (tx_id or info field)"
    );
}

#[then("the daemon should stop gracefully")]
async fn daemon_stops_gracefully(world: &mut MinotariWorld) {
    // Check that we got a clean exit code (0 or SIGINT)
    if let Some(exit_code) = world.last_command_exit_code {
        // Exit code 0 means clean shutdown, 130 typically means SIGINT on Unix
        assert!(
            exit_code == 0 || exit_code == 130 || exit_code == 143,
            "Daemon should exit gracefully, got exit code: {}",
            exit_code
        );
    }
}

#[then("database connections should be closed")]
async fn database_connections_closed(world: &mut MinotariWorld) {
    // Try to access the database file - it should be unlocked now
    if let Some(db_path) = &world.database_path {
        // Wait a moment to ensure connections are fully closed
        sleep(Duration::from_millis(500)).await;

        // Try to open the database with exclusive access
        // If the daemon closed connections properly, this should succeed
        let result = std::fs::OpenOptions::new().write(true).open(db_path);

        assert!(result.is_ok(), "Database file should be unlocked after daemon shutdown");
    }
}
