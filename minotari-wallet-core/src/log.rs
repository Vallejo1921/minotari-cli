//! Log helpers that keep personal data and node-supplied text out of logs.

use std::sync::OnceLock;

use tari_transaction_components::MicroMinotari;

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

    /// The `.rs` files under `dir`, recursively.
    fn rust_files(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                rust_files(&path, files);
                continue;
            }
            if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }

    /// The text of the macro call whose arguments start at `args`, up to its closing parenthesis.
    fn macro_args(args: &str) -> &str {
        let mut depth = 1;
        for (index, c) in args.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {},
            }
            if depth == 0 {
                return &args[..index];
            }
        }
        args
    }

    #[test]
    fn no_log_above_trace_names_a_payment_reference_or_wallet_name() {
        let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        rust_files(&crate_dir.join("src"), &mut files);
        rust_files(&crate_dir.join("../minotari-scanning/src"), &mut files);
        rust_files(&crate_dir.join("../minotari/src"), &mut files);

        let forbidden = ["payref", "payment_ref", "friendly_name"];
        let mut found = Vec::new();
        for file in &files {
            let source = std::fs::read_to_string(file).expect("read source");
            for level in ["debug", "info", "warn", "error"] {
                let call = format!("{level}!(");
                for (start, _) in source.match_indices(&call) {
                    let preceding = source[..start].chars().last();
                    if preceding.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                        continue;
                    }
                    let args = macro_args(&source[start + call.len()..]).to_lowercase();
                    if forbidden.iter().any(|word| args.contains(word)) {
                        let line = source[..start].lines().count() + 1;
                        found.push(format!("{}:{line}", file.display()));
                    }
                }
            }
        }
        assert!(found.is_empty(), "log these at trace! or drop the field: {found:#?}");
    }

    #[test]
    fn key_audit_events_are_logged_at_info() {
        let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        rust_files(&crate_dir.join("src"), &mut files);
        rust_files(&crate_dir.join("../minotari/src"), &mut files);
        let mut info_audit_calls = Vec::new();
        for file in &files {
            let source = std::fs::read_to_string(file).expect("read source");
            for (start, _) in source.match_indices("info!(") {
                let args = macro_args(&source[start + "info!(".len()..]);
                if args.contains("target: \"audit\"") {
                    info_audit_calls.push(args.to_string());
                }
            }
        }

        for event in [
            "DB: Deleting account and all associated data",
            "API: Burn transaction recorded",
            "Burn transaction broadcasted",
            "Transaction accepted by network",
        ] {
            assert!(
                info_audit_calls.iter().any(|args| args.contains(event)),
                "the audit event {event:?} must stay at info"
            );
        }
    }
}
