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

/// Most characters kept of text that came from a base node.
const MAX_NODE_TEXT_CHARS: usize = 256;

/// Makes text that came from a base node (an error message, a rejection
/// reason) safe to log, store and send on in webhooks: control characters are
/// dropped, so the node cannot forge log lines with newlines or escape codes,
/// and at most 256 characters are kept.
pub fn sanitize_node_text(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(MAX_NODE_TEXT_CHARS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_text_loses_control_characters_and_is_truncated() {
        let forged = "rejected\n2026-10-14 INFO audit: Transaction confirmed\u{1b}[31m\t";
        let clean = sanitize_node_text(forged);
        assert!(!clean.chars().any(char::is_control), "got: {clean:?}");
        assert!(clean.starts_with("rejected2026-10-14 INFO audit"));

        let long = "x".repeat(10_000);
        assert_eq!(sanitize_node_text(&long).chars().count(), 256);
        assert_eq!(sanitize_node_text("DoubleSpend"), "DoubleSpend");
    }
}
