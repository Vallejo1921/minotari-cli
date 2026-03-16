// Wallet Creation Step Definitions
//
// Step definitions for testing wallet creation functionality, including
// creating new addresses with and without encryption.

use cucumber::{then, when};
use std::fs;
use std::process::Command;

use super::common::MinotariWorld;

// =============================
// Wallet Creation Steps
// =============================

#[when("I create a new address without a password")]
async fn create_address_without_password(world: &mut MinotariWorld) {
    let output_file = world.get_temp_path("wallet.json");
    let (cmd, mut args) = world.get_minotari_command();
    args.extend_from_slice(&[
        "create-address".to_string(),
        "--output-file".to_string(),
        output_file.to_str().unwrap().to_string(),
    ]);

    let output = Command::new(&cmd)
        .args(&args)
        .output()
        .expect("Failed to execute command");

    world.last_command_exit_code = Some(output.status.code().unwrap_or(-1));
    world.last_command_output = Some(String::from_utf8_lossy(&output.stdout).to_string());
    world.last_command_error = Some(String::from_utf8_lossy(&output.stderr).to_string());
    world.output_file = Some(output_file);
}

#[when(regex = r#"^I create a new address with password "([^"]*)"$"#)]
async fn create_address_with_password(world: &mut MinotariWorld, password: String) {
    let output_file = world.get_temp_path("wallet.json");
    let (cmd, mut args) = world.get_minotari_command();
    args.extend_from_slice(&[
        "create-address".to_string(),
        "--password".to_string(),
        password,
        "--output-file".to_string(),
        output_file.to_str().unwrap().to_string(),
    ]);

    let output = Command::new(&cmd)
        .args(&args)
        .output()
        .expect("Failed to execute command");

    world.last_command_exit_code = Some(output.status.code().unwrap_or(-1));
    world.last_command_output = Some(String::from_utf8_lossy(&output.stdout).to_string());
    world.last_command_error = Some(String::from_utf8_lossy(&output.stderr).to_string());
    world.output_file = Some(output_file);
}

#[when(regex = r#"^I create a new address with output file "([^"]*)"$"#)]
async fn create_address_with_output_file(world: &mut MinotariWorld, filename: String) {
    let output_file = world.get_temp_path(&filename);
    let (cmd, mut args) = world.get_minotari_command();
    args.extend_from_slice(&[
        "create-address".to_string(),
        "--output-file".to_string(),
        output_file.to_str().unwrap().to_string(),
    ]);

    let output = Command::new(&cmd)
        .args(&args)
        .output()
        .expect("Failed to execute command");

    world.last_command_exit_code = Some(output.status.code().unwrap_or(-1));
    world.last_command_output = Some(String::from_utf8_lossy(&output.stdout).to_string());
    world.last_command_error = Some(String::from_utf8_lossy(&output.stderr).to_string());
    world.output_file = Some(output_file);
}

#[then("the wallet file should be created")]
async fn wallet_file_created(world: &mut MinotariWorld) {
    let output_file = world.output_file.as_ref().expect("Output file not set");
    assert!(output_file.exists(), "Wallet file was not created");

    let content = fs::read_to_string(output_file).expect("Failed to read wallet file");
    let wallet_data: serde_json::Value = serde_json::from_str(&content).expect("Failed to parse wallet JSON");
    world.wallet_data = Some(wallet_data);
}

#[then(regex = r#"^the file "([^"]*)" should exist$"#)]
async fn file_exists(world: &mut MinotariWorld, filename: String) {
    let file_path = world.get_temp_path(&filename);
    assert!(file_path.exists(), "File {} does not exist", filename);

    let content = fs::read_to_string(&file_path).expect("Failed to read wallet file");
    let wallet_data: serde_json::Value = serde_json::from_str(&content).expect("Failed to parse wallet JSON");
    world.wallet_data = Some(wallet_data);
}

#[then("the wallet should contain a valid address")]
async fn wallet_has_address(world: &mut MinotariWorld) {
    let wallet_data = world.wallet_data.as_ref().expect("Wallet data not loaded");
    let address = wallet_data.get("address").expect("Address field missing");
    assert!(address.is_string(), "Address is not a string");
    assert!(!address.as_str().unwrap().is_empty(), "Address is empty");
}

#[then("the wallet should contain view and spend keys")]
async fn wallet_has_keys(world: &mut MinotariWorld) {
    let wallet_data = world.wallet_data.as_ref().expect("Wallet data not loaded");
    assert!(
        wallet_data.get("view_key").is_some() || wallet_data.get("encrypted_view_key").is_some(),
        "No view key found"
    );
    assert!(
        wallet_data.get("spend_key").is_some() || wallet_data.get("encrypted_spend_key").is_some(),
        "No spend key found"
    );
}

#[then("the wallet should contain seed words")]
async fn wallet_has_seed_words(world: &mut MinotariWorld) {
    let wallet_data = world.wallet_data.as_ref().expect("Wallet data not loaded");
    assert!(
        wallet_data.get("seed_words").is_some() || wallet_data.get("encrypted_seed_words").is_some(),
        "No seed words found"
    );
}

#[then("the wallet should contain encrypted view key")]
async fn wallet_has_encrypted_view_key(world: &mut MinotariWorld) {
    let wallet_data = world.wallet_data.as_ref().expect("Wallet data not loaded");
    assert!(
        wallet_data.get("encrypted_view_key").is_some(),
        "Encrypted view key not found"
    );
}

#[then("the wallet should contain encrypted spend key")]
async fn wallet_has_encrypted_spend_key(world: &mut MinotariWorld) {
    let wallet_data = world.wallet_data.as_ref().expect("Wallet data not loaded");
    assert!(
        wallet_data.get("encrypted_spend_key").is_some(),
        "Encrypted spend key not found"
    );
}

#[then("the wallet should contain encrypted seed words")]
async fn wallet_has_encrypted_seed_words(world: &mut MinotariWorld) {
    let wallet_data = world.wallet_data.as_ref().expect("Wallet data not loaded");
    assert!(
        wallet_data.get("encrypted_seed_words").is_some(),
        "Encrypted seed words not found"
    );
}

#[then("the wallet should contain a nonce")]
async fn wallet_has_nonce(world: &mut MinotariWorld) {
    let wallet_data = world.wallet_data.as_ref().expect("Wallet data not loaded");
    assert!(
        wallet_data.get("nonce").is_some(),
        "Nonce not found in encrypted wallet"
    );
}
