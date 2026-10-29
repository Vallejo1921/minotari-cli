//! Top-level orchestrator for the console-wallet -> minotari-cli migration.
//!
//! ```text
//!   ConsoleWalletReader  +-> derive cipher seed from password
//!                        +-> reads outputs, completed_transactions, scanned_blocks
//!                                       v
//!   output_converter     reconstructs WalletOutput per row
//!                                       v
//!   migrator (this file) writes:
//!     1. account + key manager (and derives the view key once for tx_id
//!        derivation, matching what the scan path does)
//!     2. every migratable output, plus a per-output balance_change
//!     3. for each completed_transactions row, a displayed_transaction
//!        enriched with the matching outputs (received + spent) by tx_id
//!     4. the scan tip marker so subsequent scans resume from there
//! ```
//!
//! `outputs` are the source of truth for value: the displayed-transaction
//! totals are computed from the matched outputs, and the legacy
//! `completed_transactions.amount` column is used only as a fallback when a
//! transaction has no matched outputs (orphan metadata).
//!
//! `completed_transactions` is the source of truth for transaction identity:
//! the legacy `tx_id` is the user-facing display id, and the row's status,
//! direction, fee, and counterparty fields drive the displayed transaction's
//! metadata. This avoids having to reconstruct transaction grouping from
//! output scripts the way the runtime scanner does.
//!
//! All inserts happen inside a single SQLite transaction. If any step fails
//! the whole thing rolls back, leaving the destination wallet untouched.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, anyhow};
use chrono::{DateTime, Utc};
use log::info;
use rusqlite::{Connection, named_params};
use tari_common_types::{
    seeds::cipher_seed::CipherSeed, tari_address::TariAddress, transaction::TxId, types::FixedHash,
};
use tari_transaction_components::MicroMinotari;
use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
use tari_transaction_components::key_manager::{KeyManager, TransactionKeyManagerInterface};
use tari_transaction_components::transaction_components::memo_field::MemoField;
use tari_utilities::ByteArray;

use crate::db::{self, init_db};
use crate::models::{BalanceChange, Id, OutputStatus};

use super::console_db::{ConsoleCompletedTxRow, ConsoleScannedTip, ConsoleWalletReader};
use super::output_converter::{ConvertedOutput, LegacyOutputStatus, convert_output};
use super::tx_converter::{MatchedOutput, MatchedOutputs, convert_transaction};

/// Inputs to a migration run.
#[derive(Clone, Debug)]
pub struct MigrationOptions {
    /// Path to the legacy console wallet's SQLite file.
    pub source_db_path: PathBuf,
    /// Passphrase that unlocks the legacy wallet.
    pub source_passphrase: String,
    /// Path to the new minotari-cli SQLite file. Created if missing; the
    /// account is added alongside any existing accounts.
    pub destination_db_path: PathBuf,
    /// Passphrase used to encrypt the new account's wallet blob.
    pub destination_passphrase: String,
    /// Friendly name to give the new account.
    pub account_name: String,
    /// When true, the migration runs through the same transaction but rolls
    /// back instead of committing. Lets the caller validate the migration is
    /// possible (balance match, no schema violations) without touching the
    /// destination wallet.
    pub dry_run: bool,
}

impl Default for MigrationOptions {
    fn default() -> Self {
        Self {
            source_db_path: PathBuf::new(),
            source_passphrase: String::new(),
            destination_db_path: PathBuf::new(),
            destination_passphrase: String::new(),
            account_name: String::new(),
            dry_run: false,
        }
    }
}

/// Summary returned to the caller for display / testing.
#[derive(Debug, Default)]
pub struct MigrationReport {
    pub account_name: String,
    pub outputs_migrated: usize,
    pub outputs_skipped: usize,
    pub unspent_outputs_count: usize,
    pub spent_outputs_count: usize,
    pub balance_credit: MicroMinotari,
    pub balance_debit: MicroMinotari,
    pub displayed_transactions_migrated: usize,
    /// Number of `displayed_transactions` rows that had at least one output
    /// in either the received or spent list pulled from the source `outputs`
    /// table. The remainder are orphan completed-transaction rows whose
    /// values fall back to the legacy `amount` column.
    pub displayed_transactions_with_matched_outputs: usize,
    pub scan_tip_height: Option<u64>,
    /// Sum of unspent values read from the source wallet. Computed before
    /// any writes; lets the caller cross-check `net_balance()` matches.
    pub source_balance: MicroMinotari,
    /// True iff `net_balance() == source_balance`. Useful as a single
    /// migration health check, especially in `--dry-run` mode.
    pub balance_match: bool,
    /// True iff the migration was a `dry_run` and was rolled back.
    pub dry_run: bool,
}

impl MigrationReport {
    pub fn net_balance(&self) -> MicroMinotari {
        self.balance_credit.saturating_sub(self.balance_debit)
    }
}

/// Run the migration end-to-end. Returns a report on success.
///
/// Steps:
/// 1. Open the source DB and decrypt the cipher seed using the source passphrase.
/// 2. Open / create the destination DB and run its migrations.
/// 3. Open a write transaction on the destination DB.
/// 4. Create the destination account, then derive its view key (so output
///    `tx_id`s match what the scan path would compute).
/// 5. Migrate each output and emit a per-output balance_change. Index every
///    output by its legacy `received_in_tx_id` / `spent_in_tx_id` so the
///    next step can join them with completed-transactions.
/// 6. For each completed_transactions row, build a `displayed_transactions`
///    row enriched with the matching outputs and inputs.
/// 7. Set the scan tip so the new wallet does not re-scan ground the console
///    wallet already covered.
/// 8. Commit, or roll back on any error along the way.
pub fn run_migration(options: MigrationOptions) -> Result<MigrationReport, anyhow::Error> {
    if options.source_db_path == options.destination_db_path {
        return Err(anyhow!("Source and destination database paths cannot be the same"));
    }

    info!(
        target: "audit",
        source = options.source_db_path.display().to_string().as_str(),
        dest = options.destination_db_path.display().to_string().as_str(),
        account = options.account_name.as_str();
        "Starting console-wallet -> minotari-cli migration"
    );

    // 1. Open source DB and authenticate.
    let (reader, cipher_seed) = ConsoleWalletReader::open(&options.source_db_path, &options.source_passphrase)
        .context("Failed to open and authenticate the source console wallet")?;

    // 2. Read all source data eagerly. The dataset is bounded by the user's
    //    own UTXO set / transaction history and easily fits in memory; this
    //    keeps the destination write transaction short-lived.
    let outputs = reader.read_outputs().context("Failed to read source outputs")?;
    let transactions = reader
        .read_completed_transactions()
        .context("Failed to read source completed_transactions")?;
    let scan_tip = reader
        .read_latest_scanned_block()
        .context("Failed to read source scanned_blocks")?;
    drop(reader); // close source DB before we touch the destination

    // 3. Initialise destination DB and run migrations.
    let pool = init_db(options.destination_db_path.clone())
        .map_err(|e| anyhow!("Failed to initialise destination database: {e}"))?;
    let mut conn = pool.get().context("Failed to get destination DB connection")?;

    // 4. Single transaction for the whole migration. We use IMMEDIATE so the
    //    write lock is acquired up-front, making the duplicate-name check
    //    below atomic vs any concurrent writer.
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .context("Failed to start migration transaction")?;

    // Reject duplicate account names; checked inside the transaction so a
    // concurrent writer can't race in between the check and create_account.
    if db::get_account_by_name(&tx, &options.account_name)
        .map_err(|e| anyhow!("Lookup of existing account failed: {e}"))?
        .is_some()
    {
        return Err(anyhow!(
            "Destination already has an account named '{}'; refusing to overwrite",
            options.account_name
        ));
    }

    let mut report = migrate_in_transaction(&tx, &cipher_seed, &options, &outputs, &transactions, &scan_tip)?;
    report.balance_match = report.net_balance() == report.source_balance;
    report.dry_run = options.dry_run;

    if options.dry_run {
        // Drop the transaction without committing. The destination DB is
        // unchanged; the caller has a populated report for validation.
        drop(tx);
        info!(
            target: "audit",
            outputs = report.outputs_migrated,
            skipped = report.outputs_skipped,
            balance = report.net_balance().as_u64(),
            balance_match = report.balance_match;
            "Dry-run migration rolled back"
        );
    } else {
        tx.commit().context("Failed to commit migration transaction")?;
        info!(
            target: "audit",
            outputs = report.outputs_migrated,
            skipped = report.outputs_skipped,
            unspent = report.unspent_outputs_count,
            displayed = report.displayed_transactions_migrated,
            with_outputs = report.displayed_transactions_with_matched_outputs,
            balance = report.net_balance().as_u64(),
            balance_match = report.balance_match;
            "Migration committed"
        );
    }

    Ok(report)
}

fn migrate_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    cipher_seed: &CipherSeed,
    options: &MigrationOptions,
    outputs: &[super::console_db::ConsoleOutputRow],
    transactions: &[ConsoleCompletedTxRow],
    scan_tip: &Option<ConsoleScannedTip>,
) -> Result<MigrationReport, anyhow::Error> {
    let mut report = MigrationReport {
        account_name: options.account_name.clone(),
        ..Default::default()
    };

    // 4a. Create the new account from the recovered seed.
    let seed_wallet = SeedWordsWallet::construct_new(cipher_seed.clone())
        .map_err(|e| anyhow!("Failed to construct SeedWordsWallet from migrated seed: {e}"))?;
    let wallet_type = WalletType::SeedWords(seed_wallet);
    db::create_account(tx, &options.account_name, &wallet_type, &options.destination_passphrase)
        .map_err(|e| anyhow!("Failed to create destination account: {e}"))?;

    let account_id: i64 = tx
        .query_row(
            "SELECT id FROM accounts WHERE friendly_name = ?1",
            [&options.account_name],
            |r| r.get(0),
        )
        .context("Failed to look up newly-created account id")?;

    // 4b. Derive the view key once for output tx_id derivation. Using the
    //     same `TxId::new_deterministic(view_key, output_hash)` formula the
    //     scan path uses means a freshly-scanned wallet and a migrated wallet
    //     end up with identical `outputs.tx_id` values for the same outputs.
    let key_manager = KeyManager::new(wallet_type)
        .map_err(|e| anyhow!("Failed to construct KeyManager for the migrated account: {e}"))?;
    let view_key = key_manager.get_private_view_key();
    let view_key_bytes = view_key.as_bytes().to_vec();

    // Indexes used by step 6. Built incrementally during step 5 so we touch
    // each output exactly once.
    let mut received_outputs_by_tx_id: HashMap<u64, Vec<MatchedOutput>> = HashMap::new();
    let mut spent_outputs_by_tx_id: HashMap<u64, Vec<MatchedOutput>> = HashMap::new();

    // 5. Outputs.
    for raw in outputs {
        let converted = match convert_output(raw)? {
            None => {
                report.outputs_skipped = report.outputs_skipped.saturating_add(1);
                continue;
            },
            Some(c) => c,
        };

        // Pre-track the unspent value as the source-of-truth balance BEFORE
        // any insert, so we can cross-check the imported balance below
        // regardless of any insert-side accounting bug.
        if converted.legacy_status.is_unspent() {
            report.source_balance = report.source_balance.saturating_add(converted.value);
        }

        let inserted_id = insert_converted_output(tx, account_id, &converted, &view_key_bytes)?;
        report.outputs_migrated = report.outputs_migrated.saturating_add(1);

        // Index for the displayed-transactions join in step 6.
        let matched_for_indexes = MatchedOutput {
            hash: converted.output_hash,
            value: converted.value,
            mined_height: converted.mined_height,
            mined_block_hash: converted.mined_block_hash,
            destination_output_id: inserted_id,
            // Read from the source `outputs.output_type` column so the
            // displayed-transaction view can distinguish coinbase / burn /
            // standard outputs correctly. Previously hardcoded to Standard.
            output_type: converted.output_type,
            lock_height: converted.lock_height,
        };
        if let Some(rx_id) = converted.received_in_tx_id {
            received_outputs_by_tx_id
                .entry(rx_id)
                .or_default()
                .push(matched_for_indexes.clone());
        }
        if let Some(sx_id) = converted.spent_in_tx_id {
            spent_outputs_by_tx_id
                .entry(sx_id)
                .or_default()
                .push(matched_for_indexes);
        }

        // Pull the recipient / sender / fee / memo out of the output's
        // MemoField once and reuse the same claimed-fields struct for both
        // the credit and (if applicable) the debit balance_change. Saves
        // a re-decode and keeps the two sides consistent.
        let memo_claims = ClaimedMemoFields::extract(converted.wallet_output.payment_id());

        // Balance changes: credit on receive, debit on spend. Keeping these
        // per-output (rather than per-transaction) matches what the runtime
        // ledger expects: each balance_change is linked to a specific
        // output or input id.
        if converted.legacy_status.is_unspent() {
            report.unspent_outputs_count = report.unspent_outputs_count.saturating_add(1);
            insert_credit_balance_change(tx, account_id, &converted, inserted_id, &memo_claims)?;
            report.balance_credit = report.balance_credit.saturating_add(converted.value);
        } else if converted.legacy_status.is_spent() {
            report.spent_outputs_count = report.spent_outputs_count.saturating_add(1);
            // For spent outputs we need both a credit (the receive) and a
            // debit (the spend). The pair keeps the balance arithmetic
            // consistent and lets the user see a historical trail.
            insert_credit_balance_change(tx, account_id, &converted, inserted_id, &memo_claims)?;
            report.balance_credit = report.balance_credit.saturating_add(converted.value);
            insert_input_for_spent_output(tx, account_id, &converted, inserted_id)?;
            let input_id = tx.last_insert_rowid();
            insert_debit_balance_change(tx, account_id, &converted, input_id, &memo_claims)?;
            report.balance_debit = report.balance_debit.saturating_add(converted.value);
        } else {
            //clippy
        }
    }

    // 6. Completed transactions -> displayed_transactions, joined with the
    //    outputs indexed in step 5. Preserves the console wallet's random
    //    tx_id values as the user-facing ID.
    for raw_tx in transactions {
        let tx_id = raw_tx.tx_id as u64;
        let received = received_outputs_by_tx_id.remove(&tx_id).unwrap_or_default();
        let spent = spent_outputs_by_tx_id.remove(&tx_id).unwrap_or_default();
        let matched = MatchedOutputs { received, spent };
        let had_matched = !matched.is_empty();

        let converted = convert_transaction(raw_tx, account_id, &matched)?;
        // Hard-fail rather than skip: a partial transaction history is worse
        // than aborting and letting the user re-attempt.
        db::insert_displayed_transaction(tx, &converted.display).with_context(|| {
            format!(
                "Failed to migrate displayed transaction with legacy tx_id {}",
                raw_tx.tx_id
            )
        })?;
        report.displayed_transactions_migrated = report.displayed_transactions_migrated.saturating_add(1);
        if had_matched {
            report.displayed_transactions_with_matched_outputs =
                report.displayed_transactions_with_matched_outputs.saturating_add(1);
        }
    }

    // 7. Scan tip. Avoids re-scanning the chain from genesis on the next
    //    `tari scan` invocation.
    if let Some(tip) = scan_tip {
        let height = i64::try_from(tip.height).unwrap_or(i64::MAX);
        tx.execute(
            "INSERT INTO scanned_tip_blocks (account_id, height, hash) VALUES (:account_id, :height, :hash)",
            named_params! {
                ":account_id": account_id,
                ":height": height,
                ":hash": tip.header_hash,
            },
        )
        .context("Failed to insert scanned_tip_blocks marker")?;
        report.scan_tip_height = Some(tip.height);
    }

    Ok(report)
}

/// Derive the destination `outputs.tx_id` from the account view key and the
/// output hash, matching the scan path's
/// `TxId::new_deterministic(view_key, output_hash)` exactly. This ensures a
/// migrated wallet and a scan-built wallet store the same `tx_id` for the
/// same output, so cross-references between them stay consistent.
fn deterministic_tx_id(view_key_bytes: &[u8], output_hash: &FixedHash) -> Id {
    TxId::new_deterministic(view_key_bytes, output_hash).as_i64_wrapped()
}

fn insert_converted_output(
    tx: &Connection,
    account_id: i64,
    converted: &ConvertedOutput,
    view_key_bytes: &[u8],
) -> Result<i64, anyhow::Error> {
    let output_json =
        serde_json::to_string(&converted.wallet_output).context("Failed to serialise migrated WalletOutput as JSON")?;
    #[allow(clippy::cast_possible_wrap)]
    let value_i64 = converted.value.as_u64() as i64;
    let height_i64 = i64::try_from(converted.mined_height).unwrap_or(i64::MAX);
    let mined_dt = DateTime::<Utc>::from_naive_utc_and_offset(converted.mined_timestamp, Utc);
    let tx_id = deterministic_tx_id(view_key_bytes, &converted.output_hash);

    // Per maintainer feedback (round 2) on PR #121:
    //   * Spent / SpentMinedUnconfirmed are both mined-in-block spends -
    //     the source wallet has them as spent on chain, so the destination
    //     row is Spent in either case.
    //   * Encumbered{ToBeSpent,ShortTerm*} are pre-broadcast intents with
    //     no transaction actually linked to them, so they should NOT carry
    //     over as Locked - that caused issues in the destination wallet's
    //     accounting. Mark them Unspent and let the new wallet's normal
    //     reservation flow re-lock them if the user actually spends them.
    let status_label = match converted.legacy_status {
        LegacyOutputStatus::Spent | LegacyOutputStatus::SpentMinedUnconfirmed => OutputStatus::Spent.to_string(),
        _ => OutputStatus::Unspent.to_string(),
    };

    tx.execute(
        r#"
        INSERT INTO outputs (
            account_id, tx_id, output_hash, mined_in_block_height,
            mined_in_block_hash, value, mined_timestamp, wallet_output_json,
            status
        ) VALUES (
            :account_id, :tx_id, :hash, :height, :block_hash, :value,
            :ts, :json, :status
        )
        "#,
        named_params! {
            ":account_id": account_id,
            ":tx_id": tx_id,
            ":hash": converted.output_hash.as_slice(),
            ":height": height_i64,
            ":block_hash": converted.mined_block_hash.as_slice(),
            ":value": value_i64,
            ":ts": mined_dt,
            ":json": output_json,
            ":status": status_label,
        },
    )
    .context("Failed to insert migrated output")?;

    Ok(tx.last_insert_rowid())
}

/// Memo-derived claim fields shared between the credit and debit
/// `balance_change` rows for one output. Built once from the output's
/// `MemoField` and reused, so the two halves of a spent-output's
/// ledger trail show the same counterparty / memo / fee.
struct ClaimedMemoFields {
    recipient_address: Option<TariAddress>,
    sender_address: Option<TariAddress>,
    memo_parsed: Option<String>,
    memo_hex: Option<String>,
    fee: Option<MicroMinotari>,
}

impl ClaimedMemoFields {
    fn extract(memo: &MemoField) -> Self {
        // Gate on the raw payment-id bytes rather than the parsed string:
        // `MemoField::Empty::payment_id_as_string()` returns the variant's
        // Display rendering ("Empty"-style), not "". The bytes-level check
        // is the only thing that distinguishes "no user memo" from "memo
        // with content".
        let raw = memo.payment_id_as_bytes();
        let (memo_parsed, memo_hex) = if raw.is_empty() {
            (None, None)
        } else {
            (Some(memo.payment_id_as_string()), Some(hex::encode(&raw)))
        };

        Self {
            // Only the `AddressAndData` MemoField variant carries a
            // sender; the others return None. Same story for recipient
            // on `TransactionInfo`.
            recipient_address: memo.get_recipient_address(),
            sender_address: memo.claimed_sender_address(),
            memo_parsed,
            memo_hex,
            fee: memo.get_fee(),
        }
    }
}

fn insert_credit_balance_change(
    tx: &Connection,
    account_id: i64,
    converted: &ConvertedOutput,
    output_id: i64,
    claims: &ClaimedMemoFields,
) -> Result<(), anyhow::Error> {
    let change = BalanceChange {
        account_id,
        caused_by_output_id: Some(output_id),
        caused_by_input_id: None,
        description: "migrated from console wallet".to_string(),
        balance_credit: converted.value,
        balance_debit: MicroMinotari::from(0),
        effective_date: converted.mined_timestamp,
        effective_height: converted.mined_height,
        claimed_recipient_address: claims.recipient_address.clone(),
        claimed_sender_address: claims.sender_address.clone(),
        memo_parsed: claims.memo_parsed.clone(),
        memo_hex: claims.memo_hex.clone(),
        claimed_fee: claims.fee,
        claimed_amount: Some(converted.value),
        is_reversal: false,
        reversal_of_balance_change_id: None,
        is_reversed: false,
    };
    db::insert_balance_change(tx, &change).map_err(|e| anyhow!("Failed to insert credit balance_change: {e}"))?;
    Ok(())
}

fn insert_input_for_spent_output(
    tx: &Connection,
    account_id: i64,
    converted: &ConvertedOutput,
    output_id: i64,
) -> Result<(), anyhow::Error> {
    // We use the *spent* event's block info if we had it, otherwise we fall
    // back to the original mined block. The console wallet doesn't track the
    // exact spent-block separately on the output row, so this is the best we
    // have without re-scanning.
    let mined_dt = DateTime::<Utc>::from_naive_utc_and_offset(converted.mined_timestamp, Utc);
    tx.execute(
        r#"
        INSERT INTO inputs (
            account_id, output_id, mined_in_block_height,
            mined_in_block_hash, mined_timestamp
        ) VALUES (
            :account_id, :output_id, :height, :block_hash, :ts
        )
        "#,
        named_params! {
            ":account_id": account_id,
            ":output_id": output_id,
            ":height": i64::try_from(converted.mined_height).unwrap_or(i64::MAX),
            ":block_hash": converted.mined_block_hash.as_slice(),
            ":ts": mined_dt,
        },
    )
    .context("Failed to insert input row for spent output")?;
    Ok(())
}

fn insert_debit_balance_change(
    tx: &Connection,
    account_id: i64,
    converted: &ConvertedOutput,
    input_id: i64,
    claims: &ClaimedMemoFields,
) -> Result<(), anyhow::Error> {
    let change = BalanceChange {
        account_id,
        caused_by_output_id: None,
        caused_by_input_id: Some(input_id),
        description: "migrated spent (debit) from console wallet".to_string(),
        balance_credit: MicroMinotari::from(0),
        balance_debit: converted.value,
        effective_date: converted.mined_timestamp,
        effective_height: converted.mined_height,
        claimed_recipient_address: claims.recipient_address.clone(),
        claimed_sender_address: claims.sender_address.clone(),
        memo_parsed: claims.memo_parsed.clone(),
        memo_hex: claims.memo_hex.clone(),
        claimed_fee: claims.fee,
        claimed_amount: Some(converted.value),
        is_reversal: false,
        reversal_of_balance_change_id: None,
        is_reversed: false,
    };
    db::insert_balance_change(tx, &change).map_err(|e| anyhow!("Failed to insert debit balance_change: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod deterministic_tx_id_tests {
    //! Direct unit tests for the new view-key-aware tx_id derivation. The
    //! key correctness invariant: same (view_key, output_hash) always
    //! produces the same tx_id, and different output hashes produce
    //! different ids.
    use tari_common_types::types::FixedHash;

    use super::deterministic_tx_id;

    fn hash(seed: u8) -> FixedHash {
        FixedHash::from([seed; 32])
    }

    #[test]
    fn deterministic_across_calls() {
        let view_key = [0xCDu8; 32];
        let h = hash(0x7F);
        let a = deterministic_tx_id(&view_key, &h);
        let b = deterministic_tx_id(&view_key, &h);
        assert_eq!(a, b, "same inputs must produce the same tx_id");
    }

    #[test]
    fn different_hashes_produce_different_ids() {
        let view_key = [0xABu8; 32];
        let a = deterministic_tx_id(&view_key, &hash(0x01));
        let b = deterministic_tx_id(&view_key, &hash(0x02));
        assert_ne!(a, b, "distinct output hashes must produce distinct tx_ids");
    }

    #[test]
    fn different_view_keys_produce_different_ids_for_same_hash() {
        let h = hash(0xAA);
        let a = deterministic_tx_id(&[0x11u8; 32], &h);
        let b = deterministic_tx_id(&[0x22u8; 32], &h);
        assert_ne!(
            a, b,
            "the same output hash under different view keys must produce different tx_ids",
        );
    }
}

#[cfg(test)]
mod claimed_memo_fields_tests {
    //! Verify the MemoField -> balance_change claim-field extraction is
    //! covering the variants the migrator actually encounters and zeroing
    //! the audit fields cleanly on empty memos.

    use super::ClaimedMemoFields;
    use tari_transaction_components::transaction_components::memo_field::MemoField;

    #[test]
    fn empty_memo_yields_all_none_claims() {
        let memo = MemoField::new_empty();
        let claims = ClaimedMemoFields::extract(&memo);
        assert!(claims.recipient_address.is_none());
        assert!(claims.sender_address.is_none());
        assert!(
            claims.memo_parsed.is_none(),
            "empty memo must surface as None, not Some(\"\")"
        );
        assert!(
            claims.memo_hex.is_none(),
            "empty memo bytes must surface as None, not Some(\"\")"
        );
        assert!(claims.fee.is_none());
    }

    #[test]
    fn raw_memo_surfaces_in_parsed_and_hex_fields() {
        // Raw is the most permissive variant; it forces the migrator's
        // empty-vs-non-empty filtering to do real work.
        let memo = MemoField::new_raw(b"trade fill 42".to_vec()).expect("memo fits");
        let claims = ClaimedMemoFields::extract(&memo);
        assert!(claims.memo_parsed.is_some());
        assert!(
            claims.memo_parsed.as_deref().unwrap().contains("trade fill 42")
                || !claims.memo_parsed.as_deref().unwrap().is_empty(),
            "raw memo must produce a non-empty parsed string"
        );
        assert!(claims.memo_hex.is_some(), "raw memo bytes must produce a hex string");
        // Raw variant has no address or fee fields.
        assert!(claims.recipient_address.is_none());
        assert!(claims.sender_address.is_none());
        assert!(claims.fee.is_none());
    }
}
