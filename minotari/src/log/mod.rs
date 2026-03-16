pub mod structured_console_encoder;

use std::path::Path;
use std::sync::OnceLock;

use crate::log::structured_console_encoder::StructuredConsoleEncoderDeserializer;
use log::{debug, info};
use log4rs::{
    Config,
    config::{Deserializers, RawConfig},
};
use tari_transaction_components::MicroMinotari;

/// Initializes logging
pub fn init_logging() {
    let mut deserializers = Deserializers::default();
    deserializers.insert("structured_console", StructuredConsoleEncoderDeserializer);

    let config_path = "log4rs.yml";
    let path = Path::new(config_path);

    if path.exists() {
        match log4rs::init_file(path, deserializers) {
            Ok(_) => {
                info!(
                    path = config_path;
                    "Logging initialized from external configuration"
                );
                return;
            },
            Err(e) => {
                panic!("Failed to load external log4rs.yml: {}", e);
            },
        }
    }

    let yaml_content = include_str!("../../resources/default_log4rs.yml");
    let raw_config: RawConfig =
        serde_yaml::from_str(yaml_content).expect("Embedded logging configuration is invalid YAML");

    let (appenders, errors) = raw_config.appenders_lossy(&deserializers);
    if !errors.is_empty() {
        panic!("Errors parsing embedded appenders: {:?}", errors);
    }

    let config = Config::builder()
        .appenders(appenders)
        .loggers(raw_config.loggers())
        .build(raw_config.root())
        .expect("Failed to build logging config");

    log4rs::init_config(config).expect("Failed to initialize logging from embedded config");

    debug!("Logging initialized from embedded defaults (no external log4rs.yml found)");
}

fn reveal_pii() -> bool {
    static REVEAL_PII_CACHE: OnceLock<bool> = OnceLock::new();

    *REVEAL_PII_CACHE.get_or_init(|| {
        std::env::var("REVEAL_PII")
            .map(|v| {
                let val = v.to_lowercase();
                val == "true" || val == "1"
            })
            .unwrap_or(false)
    })
}

/// Masks a string (like an address) showing only start and end characters.
/// If REVEAL_PII is true, returns the original string.
pub fn mask_string(s: &str) -> String {
    if reveal_pii() {
        return s.to_string();
    }

    if s.len() <= 12 {
        return "***".to_string();
    }
    let start: String = s.chars().take(6).collect();
    let end: String = s.chars().rev().take(6).collect::<Vec<_>>().into_iter().rev().collect();
    format!("{start}...{end}")
}

/// Returns a redacted placeholder for amounts.
/// If REVEAL_PII is true, returns the actual amount.
pub fn mask_amount(amount: MicroMinotari) -> String {
    if reveal_pii() {
        return amount.to_string();
    }

    "<REDACTED>".to_string()
}
