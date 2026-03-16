// Common World Definition and Utilities for Cucumber BDD Tests
//
// This module contains the shared state object (MinotariWorld) and common
// step definitions used across multiple test scenarios.

use cucumber::{World, given};
use indexmap::IndexMap;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use tari_transaction_components::key_manager::wallet_types::WalletType;
use tari_utilities::hex::Hex;
use tempfile::TempDir;
// Import the base node process from the test support library
#[path = "../src/lib.rs"]
pub mod test_support; // Make this public so other modules can access it
use test_support::BaseNodeProcess;

// =============================
// World Definition
// =============================

#[derive(Debug, World)]
#[world(init = Self::new)]
pub struct MinotariWorld {
    pub temp_dir: Option<TempDir>,
    pub database_path: Option<PathBuf>,
    pub output_file: Option<PathBuf>,
    pub wallet_data: Option<serde_json::Value>,
    pub last_command_output: Option<String>,
    pub last_command_error: Option<String>,
    pub last_command_exit_code: Option<i32>,
    pub wallet: WalletType,
    pub test_password: String,
    pub daemon_handle: Option<std::process::Child>,
    pub api_port: Option<u16>,
    pub locked_funds: HashMap<String, serde_json::Value>,
    pub transaction_data: HashMap<String, serde_json::Value>,
    // Base node infrastructure
    pub base_nodes: IndexMap<String, BaseNodeProcess>,
    pub assigned_ports: IndexMap<u64, u64>,
    pub current_base_dir: Option<PathBuf>,
    pub seed_nodes: Vec<String>,
    pub benchmark_timings: HashMap<String, std::time::Duration>,
    pub pre_send_balance: Option<u64>,
}

impl MinotariWorld {
    pub fn new() -> Self {
        // Create a temp base directory for this test session
        let base_dir = std::env::temp_dir().join(format!("minotari_cli_test_{}", std::process::id()));
        std::fs::create_dir_all(&base_dir).ok();
        let wallet = WalletType::new_random().unwrap(); // Initialize with default wallet type, can be overridden in specific tests

        // Automatically setup temp directory for test isolation
        let temp_dir = TempDir::new().expect("Failed to create temp directory");

        Self {
            temp_dir: Some(temp_dir),
            database_path: None,
            output_file: None,
            wallet_data: None,
            last_command_output: None,
            last_command_error: None,
            last_command_exit_code: None,
            wallet,
            test_password: "test_password_minimum_32_chars_long_for_encryption".to_string(),
            daemon_handle: None,
            api_port: None,
            locked_funds: HashMap::new(),
            transaction_data: HashMap::new(),
            base_nodes: IndexMap::new(),
            assigned_ports: IndexMap::new(),
            current_base_dir: Some(base_dir),
            seed_nodes: Vec::new(),
            benchmark_timings: HashMap::new(),
            pre_send_balance: None,
        }
    }

    pub fn setup_temp_dir(&mut self) {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        self.temp_dir = Some(temp_dir);
    }

    /// Get the path to the minotari binary.
    ///
    /// The binary is expected to have been built by `ensure_minotari_binary_built()`
    /// in the cucumber test runner before any scenarios execute. This method simply
    /// locates the built binary (release or debug) and returns the command to invoke it.
    pub fn get_minotari_command(&self) -> (String, Vec<String>) {
        let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
            .map(|p| std::path::PathBuf::from(p).parent().unwrap().to_path_buf())
            .unwrap_or_else(|_| std::env::current_dir().unwrap().parent().unwrap().to_path_buf());

        let release_binary = workspace_root.join("target/release/minotari");
        let debug_binary = workspace_root.join("target/debug/minotari");

        if release_binary.exists() {
            (release_binary.to_string_lossy().to_string(), vec![])
        } else if debug_binary.exists() {
            (debug_binary.to_string_lossy().to_string(), vec![])
        } else {
            panic!(
                "minotari binary not found at {:?} or {:?}. \
                 The binary should have been built by ensure_minotari_binary_built() \
                 in the cucumber test runner.",
                release_binary, debug_binary
            );
        }
    }

    pub fn get_temp_path(&self, filename: &str) -> PathBuf {
        self.temp_dir
            .as_ref()
            .expect("Temp directory not set up")
            .path()
            .join(filename)
    }

    pub fn setup_database(&mut self) {
        if self.temp_dir.is_none() {
            self.setup_temp_dir();
        }
        let db_path = self.get_temp_path("test_wallet.db");
        self.database_path = Some(db_path);
    }

    pub fn cleanup(&mut self) {
        if let Some(mut child) = self.daemon_handle.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // Base nodes are dropped automatically via their Drop impl
        self.base_nodes.clear();
        self.temp_dir = None;
    }

    /// Parse the balance amount from the last command output
    pub fn parse_balance_from_output(&self) -> Option<u64> {
        let output = self.last_command_output.as_ref()?;

        // Look for pattern like "1,000,000 µT" or "18462.816327 T"
        // Balance format: "Balance at height X(date): Y µT" or "Balance at height X(date): Y T"
        let micro_tari_re = cucumber::codegen::Regex::new(r":\s*([\d,.]+)\s+µT").ok()?;
        let tari_re = cucumber::codegen::Regex::new(r":\s*([\d,.]+)\s+T\b").ok()?;
        let mut tari_value = false;
        let captures = match micro_tari_re.captures(output) {
            Some(caps) => caps,
            None => {
                // Try the Tari pattern if microTari pattern didn't match
                tari_value = true;
                tari_re.captures(output)?
            },
        };
        let balance_str = captures.get(1)?.as_str();

        // Remove commas and parse as f64 to handle decimal values
        let balance_str = balance_str.replace(',', "");
        let balance_f64: f64 = balance_str.parse().ok()?;
        let balance_micro_tari = if tari_value {
            // Convert from Tari to microTari (1 T = 1,000,000 µT)
            (balance_f64 * 1_000_000.0).round() as u64
        } else {
            balance_f64.round() as u64
        };
        Some(balance_micro_tari)
    }

    pub fn all_seed_nodes(&self) -> &[String] {
        &self.seed_nodes
    }

    /// Run the balance command and return the balance in microTari
    pub fn fetch_balance(&mut self) -> u64 {
        let db_path = self.database_path.as_ref().expect("Database not set up").clone();
        let (cmd, mut args) = self.get_minotari_command();
        args.extend_from_slice(&[
            "balance".to_string(),
            "--database-path".to_string(),
            db_path.to_str().unwrap().to_string(),
            "--account-name".to_string(),
            "default".to_string(),
        ]);

        let output = std::process::Command::new(&cmd)
            .args(&args)
            .output()
            .expect("Failed to execute balance command");

        self.last_command_output = Some(String::from_utf8_lossy(&output.stdout).to_string());
        self.parse_balance_from_output().expect("Could not parse balance")
    }
}

impl Drop for MinotariWorld {
    fn drop(&mut self) {
        self.cleanup();
    }
}

// =============================
// Common Step Definitions
// =============================

#[given("I have a test database")]
async fn setup_database(world: &mut MinotariWorld) {
    world.setup_database();
}

#[given("I have a test database with an existing wallet")]
pub async fn database_with_wallet(world: &mut MinotariWorld) {
    world.setup_database();
    let db_path = world.database_path.as_ref().expect("Database not set up");
    let (cmd, mut args) = world.get_minotari_command();
    args.extend_from_slice(&[
        "import-view-key".to_string(),
        "--view-private-key".to_string(),
        world.wallet.get_view_key().to_hex(),
        "--spend-public-key".to_string(),
        world.wallet.get_public_spend_key().to_hex(),
        "--password".to_string(),
        world.test_password.clone(),
        "--database-path".to_string(),
        db_path.to_str().unwrap().to_string(),
    ]);

    let _ = Command::new(&cmd)
        .args(&args)
        .output()
        .expect("Failed to set up test wallet");
}

#[given("I have a test database with multiple accounts")]
async fn database_with_multiple_accounts(world: &mut MinotariWorld) {
    database_with_wallet(world).await;
}

#[given("I have a test database with a new wallet")]
async fn database_with_new_wallet(world: &mut MinotariWorld) {
    database_with_wallet(world).await;
}
