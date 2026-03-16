use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tari_common::{SubConfigPath, configuration::Network};

use crate::cli::{AccountArgs, ApplyArgs, DatabaseArgs, NodeArgs, TransactionArgs};

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct WebhookConfig {
    /// The HTTP endpoint to post events to
    pub url: Option<String>,
    /// The secret key used for HMAC signing
    pub secret: Option<String>,
    /// Optional list of event types to send. If None, all events are sent.
    pub send_only_event_types: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WalletConfig {
    pub network: Network,
    pub base_url: String,
    pub database_path: PathBuf,
    pub batch_size: u64,
    pub scan_interval_secs: u64,
    pub api_port: u16,
    pub confirmation_window: u64,
    pub account_name: Option<String>,
    pub webhook: WebhookConfig,
    /// Safety buffer (in blocks) for fast sync.
    ///
    /// The fast-sync target height is `tip - fast_sync_safety_buffer`.
    /// If not set, the default value of 720 blocks (approximately 12 hours on mainnet) is used.
    pub fast_sync_safety_buffer: Option<u64>,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            network: Network::MainNet,
            base_url: "https://rpc.tari.com".to_string(),
            database_path: PathBuf::from("data/wallet.db"),
            batch_size: 25,
            scan_interval_secs: 60,
            api_port: 9000,
            confirmation_window: 3,
            account_name: None,
            webhook: WebhookConfig::default(),
            fast_sync_safety_buffer: None,
        }
    }
}

impl SubConfigPath for WalletConfig {
    fn main_key_prefix() -> &'static str {
        "wallet"
    }
}

impl ApplyArgs for WalletConfig {
    fn apply_database(&mut self, args: &DatabaseArgs) {
        if let Some(database_path) = &args.database_path {
            self.database_path = database_path.clone();
        }
    }

    fn apply_node(&mut self, args: &NodeArgs) {
        if let Some(base_url) = &args.base_url {
            self.base_url = base_url.clone();
        }
        if let Some(batch_size) = args.batch_size {
            self.batch_size = batch_size;
        }
    }

    fn apply_account(&mut self, args: &AccountArgs) {
        if let Some(account_name) = &args.account_name {
            self.account_name = Some(account_name.clone());
        }
    }

    fn apply_transaction(&mut self, args: &TransactionArgs) {
        if let Some(confirmation_window) = args.confirmation_window {
            self.confirmation_window = confirmation_window;
        }
    }
}
