//! Rescanning an account from a given height.

use std::path::PathBuf;

use log::{info, trace, warn};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{
    WalletEvent,
    config::defaults::WalletConfig,
    db::{self, WalletDbError, init_db},
    scan::{EventReceiver, ScanError, ScanMode, Scanner, reorg::rollback_from_height},
    webhooks::WebhookTriggerConfig,
};

/// Rolls `account_name` back to `from_height`, then scans the chain again from there.
///
/// Every block, output and input the account recorded at or above `from_height` is rolled
/// back first, so the scan finds them again. With [`ScanMode::Continuous`] the scan keeps
/// following the chain once it has caught up, until `cancel_token` is cancelled; use
/// [`rescan_with_events`] to see its progress as it happens.
///
/// The rollback is committed before the scan runs. If the scan fails, or the future is dropped,
/// the account stays rolled back until a later scan covers that range again.
///
/// Stop any other scanner on this account (another `Scanner`, the daemon, or another process)
/// before calling this: a running scanner keeps its own next height and will not rescan the
/// rolled-back range. To turn the rescan into the live sync, use [`rescan_with_events`] with
/// [`ScanMode::Continuous`].
pub async fn rescan(
    password: &str,
    config: &WalletConfig,
    account_name: &str,
    from_height: u64,
    mode: ScanMode,
    cancel_token: Option<CancellationToken>,
) -> Result<(Vec<WalletEvent>, bool), ScanError> {
    let scanner = rollback_and_build_scanner(password, config, account_name, from_height, mode, cancel_token).await?;
    scanner.run().await
}

/// Like [`rescan`], but streams the scan's events as they happen.
///
/// The rollback runs before this returns. Drive the returned future to scan, and read the
/// receiver alongside it.
///
/// The rollback is committed before the scan runs. If the scan fails, or the future is dropped,
/// the account stays rolled back until a later scan covers that range again.
///
/// Stop any other scanner on this account (another `Scanner`, the daemon, or another process)
/// before calling this: a running scanner keeps its own next height and will not rescan the
/// rolled-back range. To turn the rescan into the live sync, use [`rescan_with_events`] with
/// [`ScanMode::Continuous`].
#[allow(clippy::type_complexity)]
pub async fn rescan_with_events(
    password: &str,
    config: &WalletConfig,
    account_name: &str,
    from_height: u64,
    mode: ScanMode,
    cancel_token: Option<CancellationToken>,
) -> Result<
    (
        EventReceiver,
        impl Future<Output = Result<(Vec<WalletEvent>, bool), ScanError>> + use<>,
    ),
    ScanError,
> {
    let scanner = rollback_and_build_scanner(password, config, account_name, from_height, mode, cancel_token).await?;
    Ok(scanner.run_with_events())
}

async fn rollback_and_build_scanner(
    password: &str,
    config: &WalletConfig,
    account_name: &str,
    from_height: u64,
    mode: ScanMode,
    cancel_token: Option<CancellationToken>,
) -> Result<Scanner, ScanError> {
    let webhook_config = config.webhook.url.clone().map(|url| WebhookTriggerConfig {
        url,
        send_only_event_types: config.webhook.send_only_event_types.clone(),
    });

    rollback_account_to_height(
        config.database_path.clone(),
        password,
        account_name,
        from_height,
        webhook_config.clone(),
        config.effective_burn_proofs_dir(),
    )
    .await?;

    let mut scanner = Scanner::new(
        password,
        &config.base_url,
        config.database_path.clone(),
        config.batch_size,
        config.confirmation_window,
    )
    .mode(mode)
    .account(account_name)
    .burn_proofs_dir(config.effective_burn_proofs_dir());
    if let Some(cfg) = webhook_config {
        scanner = scanner.webhook_config(cfg);
    }
    if let Some(token) = cancel_token {
        scanner = scanner.cancel_token(token);
    }
    Ok(scanner)
}

/// Rolls `account_name` back so its next scan starts at `from_height`.
///
/// The password is checked first, so a wrong one leaves the account untouched. Use this
/// instead of [`rescan`] to drive the scan yourself, e.g. with [`Scanner::run_with_events`].
///
/// The rollback is committed when this returns. If the scan that follows fails or never runs,
/// the account stays rolled back until a later scan covers that range again.
///
/// Stop any other scanner on this account (another `Scanner`, the daemon, or another process)
/// before calling this: a running scanner keeps its own next height and will not rescan the
/// rolled-back range. To turn the rescan into the live sync, use [`rescan_with_events`] with
/// [`ScanMode::Continuous`].
/// `burn_proofs_dir` is used to remove claim files invalidated by the rollback.
pub async fn rollback_account_to_height(
    database_path: PathBuf,
    password: &str,
    account_name: &str,
    from_height: u64,
    webhook_config: Option<WebhookTriggerConfig>,
    burn_proofs_dir: PathBuf,
) -> Result<(), ScanError> {
    // The DB stores heights as i64; a larger height would wrap negative and roll back everything.
    if i64::try_from(from_height).is_err() {
        return Err(ScanError::DbError(WalletDbError::InvalidInput(format!(
            "Rescan height {} is out of range",
            from_height
        ))));
    }

    let password = Zeroizing::new(password.to_string());
    let account_name = account_name.to_string();

    tokio::task::spawn_blocking(move || {
        let pool = init_db(database_path)?;
        let mut conn = pool.get()?;

        // Check the password inside the write transaction, so a concurrent passphrase change
        // cannot slip in between the check and the rollback.
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let account = db::get_account_by_name(&tx, &account_name)?
            .ok_or_else(|| WalletDbError::InvalidInput(format!("Account not found: {}", account_name)))?;
        account.verify_passphrase(&password)?;

        info!(
            target: "audit",
            from_height = from_height;
            "Rolling account back for a rescan"
        );
        trace!(
            target: "audit",
            account = &*account_name;
            "Rolling account back for a rescan"
        );
        let info = rollback_from_height(&tx, account.id, from_height, webhook_config)
            .map_err(|e| WalletDbError::Unexpected(format!("Rollback failed: {}", e)))?;
        tx.commit()?;

        for (claim_public_key, commitment) in info.invalidated_burn_proof_files {
            if let Err(error) = std::fs::remove_file(crate::transactions::burn::proof_files::proof_file_path(
                &burn_proofs_dir,
                &claim_public_key,
                &commitment,
            )) && error.kind() != std::io::ErrorKind::NotFound
            {
                warn!(error:% = error; "Could not remove invalidated burn proof file");
            }
        }

        Ok::<(), WalletDbError>(())
    })
    .await
    .map_err(|e| ScanError::DbError(WalletDbError::Unexpected(format!("Task join error: {}", e))))?
    .map_err(ScanError::DbError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{create_account, get_account_by_name};
    use crate::scan::{ProcessingEvent, ScanStatusEvent};
    use std::time::Duration;
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_script::script;
    use tari_transaction_components::{
        MicroMinotari,
        key_manager::wallet_types::{SeedWordsWallet, WalletType},
        rpc::models::{
            BlockUtxoInfo, GetUtxosByBlockResponse, MinimalUtxoSyncInfo, SyncUtxosByBlockResponseV0,
            SyncUtxosByBlockResponseV1,
        },
        test_helpers::{TestParams, create_wallet_output_with_data},
        transaction_components::{OutputFeatures, TransactionOutput},
    };
    use tari_utilities::ByteArray;
    use wiremock::{MockServer, Request, Respond, ResponseTemplate};

    const PASSWORD: &str = "password";
    const TIP: u64 = 20;
    const OUTPUT_HEIGHT: u64 = 15;

    fn block_hash(height: u64) -> Vec<u8> {
        let mut hash = vec![0x5A; 32];
        hash.splice(0..8, height.to_be_bytes());
        hash
    }

    fn height_of(hash_hex: &str) -> u64 {
        let bytes = hex::decode(hash_hex).expect("hex hash");
        let mut height = [0u8; 8];
        height.copy_from_slice(bytes.get(0..8).expect("hash is 32 bytes"));
        u64::from_be_bytes(height)
    }

    fn query_param(request: &Request, name: &str) -> String {
        request
            .url
            .query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.to_string())
            .expect("query parameter")
    }

    /// A base node whose chain runs to `TIP`, with one wallet output mined at `OUTPUT_HEIGHT`.
    struct MockChain {
        output: TransactionOutput,
    }

    impl Respond for MockChain {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            match request.url.path() {
                "/get_tip_info" => ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "metadata": {
                        "best_block_height": TIP,
                        "best_block_hash": block_hash(TIP),
                        "accumulated_difficulty": "0",
                        "pruned_height": 0,
                        "timestamp": 0,
                    }
                })),
                "/get_height_at_time" => ResponseTemplate::new(200).set_body_json(0u64),
                "/get_header_by_height" => {
                    let height: u64 = query_param(request, "height").parse().expect("height");
                    if height > TIP {
                        return ResponseTemplate::new(404);
                    }
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "height": height,
                        "hash": block_hash(height),
                        "timestamp": 1_700_000_000u64,
                    }))
                },
                "/sync_utxos_by_block" => {
                    let start = height_of(&query_param(request, "start_header_hash"));
                    let limit: u64 = query_param(request, "limit").parse().expect("limit");
                    let last = (start + limit - 1).min(TIP);
                    let mut blocks = Vec::new();
                    for height in start..=last {
                        let mut outputs = Vec::new();
                        if height == OUTPUT_HEIGHT {
                            outputs.push(MinimalUtxoSyncInfo {
                                output_hash: self.output.hash().to_vec(),
                                commitment: self.output.commitment.as_bytes().to_vec(),
                                encrypted_data: self.output.encrypted_data.as_bytes().to_vec(),
                                sender_offset_public_key: self.output.sender_offset_public_key.as_bytes().to_vec(),
                            });
                        }
                        blocks.push(BlockUtxoInfo {
                            header_hash: block_hash(height),
                            height,
                            outputs,
                            inputs: Vec::new(),
                            mined_timestamp: 1_700_000_000,
                        });
                    }
                    let next_header_to_scan = if last < TIP { block_hash(last + 1) } else { Vec::new() };
                    ResponseTemplate::new(200).set_body_json(SyncUtxosByBlockResponseV1::from(
                        SyncUtxosByBlockResponseV0 {
                            blocks,
                            has_next_page: false,
                            next_header_to_scan,
                        },
                    ))
                },
                "/get_utxos_by_block" => {
                    let height = height_of(&query_param(request, "header_hash"));
                    let outputs = if height == OUTPUT_HEIGHT {
                        vec![self.output.clone()]
                    } else {
                        Vec::new()
                    };
                    ResponseTemplate::new(200).set_body_json(GetUtxosByBlockResponse {
                        header_hash: block_hash(height),
                        height,
                        outputs,
                        mined_timestamp: 1_700_000_000,
                    })
                },
                _ => ResponseTemplate::new(404),
            }
        }
    }

    struct Setup {
        config: WalletConfig,
        output_hash: Vec<u8>,
        _server: MockServer,
        _dir: tempfile::TempDir,
    }

    async fn setup() -> Setup {
        let dir = tempfile::tempdir().expect("temp dir");
        let database_path = dir.path().join("rescan.db");
        let pool = init_db(database_path.clone()).expect("init db");
        let conn = pool.get().expect("conn");
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
        create_account(&conn, "default", &wallet, PASSWORD).unwrap();
        let key_manager = get_account_by_name(&conn, "default")
            .unwrap()
            .unwrap()
            .get_key_manager(PASSWORD)
            .unwrap();
        let output = create_wallet_output_with_data(
            script!(Nop).unwrap(),
            OutputFeatures::default(),
            &TestParams::new(&key_manager),
            MicroMinotari(1_000_000),
            &key_manager,
        )
        .unwrap()
        .to_transaction_output()
        .unwrap();

        let server = MockServer::start().await;
        let output_hash = output.hash().to_vec();
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(MockChain { output })
            .mount(&server)
            .await;

        let config = WalletConfig {
            base_url: server.uri(),
            database_path,
            batch_size: 5,
            burn_proofs_dir: Some(dir.path().join("burn_proofs")),
            ..WalletConfig::default()
        };
        Setup {
            config,
            output_hash,
            _server: server,
            _dir: dir,
        }
    }

    /// (active, rolled back) rows for `output_hash`.
    fn output_rows(config: &WalletConfig, output_hash: &[u8]) -> (i64, i64) {
        let pool = init_db(config.database_path.clone()).unwrap();
        let conn = pool.get().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FILTER (WHERE deleted_at IS NULL), COUNT(*) FILTER (WHERE deleted_at IS NOT NULL)
             FROM outputs WHERE output_hash = ?1",
            [output_hash],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    }

    fn full_rescan() -> ScanMode {
        ScanMode::Partial { max_blocks: u64::MAX }
    }

    #[tokio::test]
    async fn rollback_removes_the_invalidated_claim_file() {
        let setup = setup().await;
        let pool = init_db(setup.config.database_path.clone()).unwrap();
        let conn = pool.get().unwrap();
        let account_id = get_account_by_name(&conn, "default").unwrap().unwrap().id;
        let claim_public_key = "ab".repeat(32);
        let commitment = vec![7u8; 32];
        conn.execute(
            "INSERT INTO burn_proofs (account_id, output_hash, commitment, claim_public_key, \
             ownership_proof_nonce, ownership_proof_sig, kernel_excess, kernel_excess_nonce, kernel_excess_sig, \
             sender_offset_public_key, encrypted_data, value, status, mined_height) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?5, ?5, ?5, ?5, ?5, 1000, 'complete', 10)",
            rusqlite::params![account_id, vec![8u8; 32], commitment, claim_public_key, vec![0u8; 32]],
        )
        .unwrap();
        drop(conn);

        let dir = setup.config.effective_burn_proofs_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = crate::transactions::burn::proof_files::proof_file_path(&dir, &claim_public_key, &commitment);
        std::fs::write(&path, "old orphaned claim").unwrap();

        rollback_account_to_height(setup.config.database_path.clone(), PASSWORD, "default", 10, None, dir)
            .await
            .unwrap();

        assert!(!path.exists());
        let conn = pool.get().unwrap();
        let status: String = conn
            .query_row("SELECT status FROM burn_proofs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(status, "pending_merkle");
    }

    #[tokio::test]
    async fn rollback_continues_claim_cleanup_after_one_file_cannot_be_removed() {
        let setup = setup().await;
        let pool = init_db(setup.config.database_path.clone()).unwrap();
        let conn = pool.get().unwrap();
        let account_id = get_account_by_name(&conn, "default").unwrap().unwrap().id;
        let dir = setup.config.effective_burn_proofs_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let mut paths = Vec::new();
        for byte in [7u8, 8u8] {
            let claim_public_key = format!("{byte:02x}").repeat(32);
            let commitment = vec![byte; 32];
            conn.execute(
                "INSERT INTO burn_proofs (account_id, output_hash, commitment, claim_public_key, \
                 ownership_proof_nonce, ownership_proof_sig, kernel_excess, kernel_excess_nonce, kernel_excess_sig, \
                 sender_offset_public_key, encrypted_data, value, status, mined_height) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?5, ?5, ?5, ?5, ?5, 1000, 'complete', 10)",
                rusqlite::params![account_id, vec![byte; 32], commitment, claim_public_key, vec![0u8; 32]],
            )
            .unwrap();
            paths.push(crate::transactions::burn::proof_files::proof_file_path(
                &dir,
                &claim_public_key,
                &commitment,
            ));
        }
        drop(conn);
        std::fs::create_dir_all(paths.first().unwrap()).unwrap();
        std::fs::write(paths.last().unwrap(), "old orphaned claim").unwrap();

        rollback_account_to_height(setup.config.database_path.clone(), PASSWORD, "default", 10, None, dir)
            .await
            .expect("a file removal error must not hide a committed rollback");
        assert!(!paths.last().unwrap().exists(), "later claim files are still removed");
        let conn = pool.get().unwrap();
        let pending: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM burn_proofs WHERE status = 'pending_merkle'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending, 2);
    }

    #[tokio::test]
    async fn outputs_above_the_rescan_height_are_rolled_back_and_found_again() {
        let setup = setup().await;
        rescan(PASSWORD, &setup.config, "default", 0, full_rescan(), None)
            .await
            .expect("first scan");
        assert_eq!(output_rows(&setup.config, &setup.output_hash), (1, 0));

        rescan(PASSWORD, &setup.config, "default", 10, full_rescan(), None)
            .await
            .expect("rescan");
        assert_eq!(
            output_rows(&setup.config, &setup.output_hash),
            (1, 1),
            "the output is rolled back, then found again"
        );

        // Rescanning above the output leaves it alone.
        rescan(
            PASSWORD,
            &setup.config,
            "default",
            OUTPUT_HEIGHT + 1,
            full_rescan(),
            None,
        )
        .await
        .expect("rescan above the output");
        assert_eq!(output_rows(&setup.config, &setup.output_hash), (1, 1));
    }

    #[tokio::test]
    async fn a_height_beyond_i64_is_refused_without_rolling_anything_back() {
        let setup = setup().await;
        rescan(PASSWORD, &setup.config, "default", 0, full_rescan(), None)
            .await
            .expect("first scan");

        let err = rescan(PASSWORD, &setup.config, "default", u64::MAX, full_rescan(), None)
            .await
            .expect_err("out-of-range height");
        assert!(
            matches!(err, ScanError::DbError(WalletDbError::InvalidInput(_))),
            "got: {err}"
        );
        assert_eq!(output_rows(&setup.config, &setup.output_hash), (1, 0));
    }

    #[tokio::test]
    async fn a_wrong_password_rolls_nothing_back() {
        let setup = setup().await;
        rescan(PASSWORD, &setup.config, "default", 0, full_rescan(), None)
            .await
            .expect("first scan");

        rescan("wrong", &setup.config, "default", 10, full_rescan(), None)
            .await
            .expect_err("wrong password");
        assert_eq!(output_rows(&setup.config, &setup.output_hash), (1, 0));
    }

    #[tokio::test]
    async fn a_continuous_rescan_streams_events_and_stops_on_its_cancel_token() {
        let setup = setup().await;
        let cancel_token = CancellationToken::new();
        let (mut events, scan) = rescan_with_events(
            PASSWORD,
            &setup.config,
            "default",
            0,
            ScanMode::Continuous {
                poll_interval: Duration::from_millis(100),
            },
            Some(cancel_token.clone()),
        )
        .await
        .expect("rollback");
        let scan = tokio::spawn(scan);

        // The output is reported as found, then the caught-up scan waits for the next poll.
        let mut output_found = false;
        while let Some(event) = tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("an event within 10 s")
        {
            match event {
                ProcessingEvent::BlockProcessed(block) if !block.outputs_detected.is_empty() => {
                    assert_eq!(block.height, OUTPUT_HEIGHT);
                    output_found = true;
                },
                ProcessingEvent::ScanStatus(ScanStatusEvent::Waiting { .. }) => break,
                _ => {},
            }
        }
        assert!(output_found, "the rescan streams the found output");
        assert_eq!(output_rows(&setup.config, &setup.output_hash), (1, 0));
        assert!(!scan.is_finished(), "a continuous rescan keeps following the chain");

        cancel_token.cancel();
        tokio::time::timeout(Duration::from_secs(10), scan)
            .await
            .expect("the scan stops once cancelled")
            .expect("task joins")
            .expect("a cancelled scan ends cleanly");
    }
}
