//! Burn funds endpoint handler.

use axum::{
    Json,
    extract::{Path, State},
};
use log::{info, trace, warn};
use serde::{Deserialize, Serialize};
use tari_common_types::transaction::TxId;
use tari_transaction_components::{tari_amount::MicroMinotari, transaction_components::Transaction};

use crate::{
    api::{AppState, error::ApiError},
    db::{SqlitePool, get_account_by_name},
    http::WalletHttpClient,
    transactions::{
        burn::{BurnTxParams, create_burn_tx, persist_burn_records},
        fund_locker::{validate_fee_per_gram, validate_seconds_to_lock},
        manager::{FirstBroadcast, record_first_broadcast},
    },
    utils::crypto::{parse_claimable_public_key_hex, parse_private_key_hex},
};

use super::params::{
    DEFAULT_FEE_PER_GRAM, DEFAULT_SECONDS_TO_LOCK_UTXOS, WalletParams, default_fee_per_gram,
    default_seconds_to_lock_utxos,
};

/// Request body for burning funds and generating an L2 claim proof.
///
/// # JSON Example
///
/// ```json
/// {
///   "amount": 1000000,
///   "claim_public_key": "a3f9...",
///   "fee_per_gram": 5,
///   "payment_id": "optional memo",
///   "seconds_to_lock": 86400
/// }
/// ```
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct BurnFundsRequest {
    /// Amount to burn in MicroMinotari.
    #[schema(value_type = u64)]
    pub amount: MicroMinotari,

    /// L2 claim public key in hex. Required to generate a burn proof for L2 claiming.
    pub claim_public_key: Option<String>,

    /// Sidechain deployment key in hex, for L2 template burns.
    pub sidechain_deployment_key: Option<String>,

    /// Fee per gram in MicroMinotari (default: 5).
    #[schema(value_type = u64)]
    #[serde(default = "default_fee_per_gram")]
    #[schema(default = 5)]
    pub fee_per_gram: Option<MicroMinotari>,

    /// Optional payment memo attached to the transaction.
    pub payment_id: Option<String>,

    /// Optional idempotency key to prevent duplicate burn requests.
    ///
    /// The key is bound to this burn's parameters and to the burn operation
    /// itself, so a key issued elsewhere (for example at `lock_funds`) cannot be
    /// redeemed here, and reusing a burn key with different parameters is
    /// rejected with 409 Conflict.
    pub idempotency_key: Option<String>,

    /// Seconds to lock input UTXOs (default: 86400 = 24 h, max: 31536000 = 365 days).
    #[serde(default = "default_seconds_to_lock_utxos")]
    #[schema(default = 86_400, maximum = 31_536_000)]
    pub seconds_to_lock: Option<u64>,
}

/// Response returned after a successful burn transaction.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BurnFundsResponse {
    /// Transaction ID assigned to the burn transaction.
    pub tx_id: String,
    /// Hex-encoded output hash of the burn output.
    ///
    /// The daemon will use this to track when the proof is ready.
    pub output_hash: String,
    /// Whether the base node accepted the burn on its first broadcast (or
    /// already had it mined). When `false` the burn is still recorded and will
    /// be rebroadcast automatically: it must not be sent again.
    pub accepted_by_node: bool,
    /// Set when the node has not accepted the burn yet; says it is recorded,
    /// will be rebroadcast and must not be sent again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The node's answer (sanitised) when it did not accept the burn.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_reason: Option<String>,
}

impl BurnFundsResponse {
    /// The response for a recorded burn, as its first broadcast found it.
    fn new(tx_id: String, output_hash: String, first_broadcast: FirstBroadcast) -> Self {
        Self {
            tx_id,
            output_hash,
            accepted_by_node: first_broadcast.accepted_by_node,
            note: first_broadcast.note(),
            node_reason: first_broadcast.node_reason,
        }
    }
}

/// Broadcasts a recorded burn for the first time and records the node's answer.
///
/// Returns what the node said. This never fails: the burn is recorded and the
/// transaction monitor rebroadcasts it if needed, and an error would invite the
/// caller to burn again. A database failure here is logged and reported as
/// `local_record_lagging` (see [`record_first_broadcast`]).
async fn broadcast_recorded_burn(
    pool: SqlitePool,
    client: &WalletHttpClient,
    transaction: Transaction,
    tx_id: TxId,
) -> FirstBroadcast {
    let response = client.submit_transaction(transaction).await;

    let recorded = tokio::task::spawn_blocking(move || match pool.get() {
        Ok(conn) => record_first_broadcast(Some(&*conn), tx_id, response),
        Err(e) => {
            warn!(target: "audit", error:% = e; "No database connection after a burn was recorded");
            record_first_broadcast(None, tx_id, response)
        },
    })
    .await;
    match recorded {
        Ok(first_broadcast) => first_broadcast,
        Err(e) => {
            warn!(target: "audit", error:% = e; "Recording a burn's first broadcast failed; the monitor will catch up");
            FirstBroadcast {
                accepted_by_node: false,
                node_reason: None,
                local_record_lagging: true,
                accepted_after_abandon: false,
            }
        },
    }
}

/// Builds the client for the base node, before anything is recorded: once the
/// burn is recorded no failure may be reported as an error.
fn base_node_client(base_node_url: &str) -> Result<WalletHttpClient, ApiError> {
    let url = base_node_url
        .parse()
        .map_err(|e| ApiError::InternalServerError(format!("Invalid base node URL: {}", e)))?;
    WalletHttpClient::new(url).map_err(|e| ApiError::InternalServerError(e.to_string()))
}

/// Burns funds from an account and records a partial burn proof for L2 claiming.
///
/// Creates a burn transaction, broadcasts it, and stores the partial proof in the
/// database. The daemon's `BurnProofWorker` will automatically fetch the burn
/// output proof once the transaction is confirmed and write the complete
/// `CompleteClaimBurnProof` JSON file to the configured `burn_proofs_dir`.
///
/// # Path Parameters
///
/// - `name`: The account to burn funds from
///
/// # Request Body
///
/// See [`BurnFundsRequest`] for the complete schema.
///
/// # Response
///
/// Returns a [`BurnFundsResponse`] with:
/// - `tx_id`: the transaction ID
/// - `output_hash`: hex-encoded output hash (use this to identify the proof file)
/// - `accepted_by_node`: whether the node accepted the first broadcast
/// - `note`: when it did not, that the burn is recorded, will be rebroadcast
///   automatically and must not be sent again
/// - `node_reason`: when it did not, the node's answer
///
/// A burn the node refuses (or cannot be reached for) once it is recorded is
/// still a success: it stays pending with its inputs locked and the wallet
/// rebroadcasts it.
///
/// # Errors
///
/// - `400 Bad Request`: invalid `claim_public_key` or `sidechain_deployment_key` hex
/// - `404 Not Found`: account does not exist
/// - `500`: insufficient funds, or other internal error
///
/// # Example Request
///
/// ```bash
/// curl -X POST http://127.0.0.1:9000/accounts/default/burn \
///   -H "Authorization: Bearer $MINOTARI_API_TOKEN" \
///   -H "Content-Type: application/json" \
///   -d '{"amount": 1000000, "claim_public_key": "a3f9..."}'
/// ```
#[utoipa::path(
    post,
    path = "/accounts/{name}/burn",
    request_body = BurnFundsRequest,
    responses(
        (status = 200, description = "Burn transaction recorded (and broadcast unless `accepted_by_node` is false)", body = BurnFundsResponse),
        (status = 400, description = "Invalid request parameters", body = ApiError),
        (status = 404, description = "Account not found", body = ApiError),
        (status = 409, description = "Idempotency key reused for a different request", body = ApiError),
        (status = 500, description = "Burn failed", body = ApiError),
    ),
    params(
        ("name" = String, Path, description = "Name of the account to burn from"),
    )
)]
pub async fn api_burn_funds(
    State(app_state): State<AppState>,
    Path(WalletParams { name }): Path<WalletParams>,
    Json(body): Json<BurnFundsRequest>,
) -> Result<Json<BurnFundsResponse>, ApiError> {
    info!(
        target: "audit",
        amount = body.amount.as_u64();
        "API: Burn funds request"
    );
    trace!(
        target: "audit",
        account = &*name;
        "API: Burn funds request"
    );

    let pool = app_state.db_pool.clone();
    let network = app_state.network;
    let password = app_state.password.clone();
    let fee_per_gram = body.fee_per_gram.unwrap_or(DEFAULT_FEE_PER_GRAM);
    // Checked before anything is locked or recorded.
    let client = base_node_client(&app_state.base_node_url)?;
    let seconds_to_lock = body.seconds_to_lock.unwrap_or(DEFAULT_SECONDS_TO_LOCK_UTXOS);
    // Reject an out-of-range duration as a client error before doing any work.
    validate_seconds_to_lock(seconds_to_lock)?;
    validate_fee_per_gram(fee_per_gram)?;
    let confirmation_window = app_state.required_confirmations;
    let idempotency_key = body.idempotency_key.clone();
    let amount = body.amount;

    let (result, tx_id, output_hash) = tokio::task::spawn_blocking(move || {
        let claim_public_key = body
            .claim_public_key
            .as_deref()
            .map(parse_claimable_public_key_hex)
            .transpose()
            .map_err(|e| ApiError::BadRequest(format!("Invalid claim_public_key: {}", e)))?;

        let sidechain_deployment_key = body
            .sidechain_deployment_key
            .as_deref()
            .map(parse_private_key_hex)
            .transpose()
            .map_err(|e| ApiError::BadRequest(format!("Invalid sidechain_deployment_key: {}", e)))?;

        let idempotency_key = idempotency_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let mut conn = pool.get().map_err(|e| ApiError::DbError(e.to_string()))?;
        let account = get_account_by_name(&conn, &name)
            .map_err(|e| ApiError::DbError(e.to_string()))?
            .ok_or_else(|| ApiError::AccountNotFound(name.clone()))?;

        let params = BurnTxParams {
            account_id: account.id,
            amount,
            claim_public_key,
            sidechain_deployment_key,
            fee_per_gram,
            payment_id: body.payment_id.clone(),
            idempotency_key: Some(idempotency_key.clone()),
            seconds_to_lock,
            confirmation_window,
        };

        // An idempotency key replayed onto a burn that is already completed, or
        // onto a reservation that has since been released, is a client error:
        // 409, not a 500 inviting a retry that can never succeed. `DbError` here
        // reported "your reservation was released" as a server fault.
        let result = create_burn_tx(&account, &mut conn, network, &password, params)
            .map_err(|e| ApiError::from_transaction_error(e, ApiError::FailedToBurnFunds))?;

        persist_burn_records(&mut conn, &result, account.id, &idempotency_key)
            .map_err(|e| ApiError::from_transaction_error(e, ApiError::DbError))?;

        let tx_id = result.tx_id;
        let output_hash = result.output_hash;

        Ok::<_, ApiError>((result, tx_id, output_hash))
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    let first_broadcast = broadcast_recorded_burn(app_state.db_pool.clone(), &client, result.transaction, tx_id).await;

    info!(
        target: "audit",
        accepted_by_node = first_broadcast.accepted_by_node;
        "API: Burn transaction recorded"
    );
    trace!(
        target: "audit",
        tx_id = &*tx_id.to_string(),
        output_hash = &*hex::encode(output_hash);
        "API: Burn transaction recorded"
    );

    Ok(Json(BurnFundsResponse::new(
        tx_id.to_string(),
        hex::encode(output_hash),
        first_broadcast,
    )))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use crate::db::{create_account, init_db};
    use crate::transactions::idempotency::{IdempotencyBinding, IdempotencyOperation, RequestFingerprint};
    use chrono::Utc;
    use rusqlite::named_params;
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_common_types::types::PrivateKey;
    use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    struct RecordedBurn {
        pool: SqlitePool,
        tx_id: TxId,
        input_id: i64,
        _dir: TempDir,
    }

    /// A burn as `persist_burn_records` leaves it before the first broadcast:
    /// completed transaction, input locked to it.
    fn recorded_burn() -> RecordedBurn {
        let dir = tempfile::tempdir().expect("temp dir");
        let pool = init_db(dir.path().join("burn.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
        create_account(&conn, "default", &wallet, "password").unwrap();
        let account = get_account_by_name(&conn, "default").unwrap().unwrap();
        let binding = IdempotencyBinding::new(
            Some("burn".to_string()),
            IdempotencyOperation::BurnFunds,
            RequestFingerprint::new(IdempotencyOperation::BurnFunds),
        );
        let request_id = crate::db::create_pending_transaction(
            &conn,
            "burn",
            &binding,
            account.id,
            true,
            MicroMinotari(0),
            MicroMinotari(0),
            MicroMinotari(0),
            Utc::now() + chrono::Duration::hours(1),
        )
        .expect("pending");
        conn.execute(
            r#"
            INSERT INTO outputs (
                account_id, tx_id, output_hash, mined_in_block_height, mined_in_block_hash, value,
                mined_timestamp, wallet_output_json, status, confirmed_height, is_burn, maturity
            ) VALUES (:account_id, 1, :hash, 10, :hash, 10000, :ts, '{}', 'UNSPENT', 10, 0, 0)
            "#,
            named_params! { ":account_id": account.id, ":hash": vec![1u8; 32], ":ts": Utc::now() },
        )
        .expect("input");
        let input_id = conn.last_insert_rowid();
        crate::db::lock_output(&conn, input_id, &request_id, Utc::now()).expect("lock");
        let tx_id = TxId::from(5u64);
        crate::db::create_completed_transaction(&conn, account.id, &request_id, &[], b"{}", None, tx_id)
            .expect("completed");
        drop(conn);
        RecordedBurn {
            pool,
            tx_id,
            input_id,
            _dir: dir,
        }
    }

    async fn node_answering(accepted: bool, reason: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "accepted": accepted, "rejection_reason": reason, "is_synced": true },
                "error": null,
                "id": "1",
            })))
            .mount(&server)
            .await;
        server
    }

    fn empty_transaction() -> Transaction {
        Transaction::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            PrivateKey::default(),
            PrivateKey::default(),
        )
    }

    #[tokio::test]
    async fn a_burn_the_node_refuses_is_a_success_marked_pending() {
        let burn = recorded_burn();
        let server = node_answering(false, "DoubleSpend").await;

        let client = base_node_client(&server.uri()).expect("client");
        let first = broadcast_recorded_burn(burn.pool.clone(), &client, empty_transaction(), burn.tx_id).await;
        assert!(!first.accepted_by_node);

        let response = BurnFundsResponse::new(burn.tx_id.to_string(), "00".to_string(), first);
        let body = serde_json::to_value(&response).expect("json");
        assert_eq!(body["accepted_by_node"], false);
        let note = body["note"].as_str().expect("a pending note");
        assert!(note.contains("Do not send it again"), "got: {note}");
        let reason = body["node_reason"].as_str().expect("the node's answer");
        assert!(reason.contains("Double Spend"), "got: {reason}");

        // Still recorded, inputs still locked, for the monitor to rebroadcast.
        let conn = burn.pool.get().expect("conn");
        let completed = crate::db::get_completed_transaction_by_id(&conn, burn.tx_id)
            .expect("query")
            .expect("completed");
        assert_eq!(completed.status, crate::db::CompletedTransactionStatus::Completed);
        let input_status: String = conn
            .query_row(
                "SELECT status FROM outputs WHERE id = :id",
                named_params! { ":id": burn.input_id },
                |row| row.get(0),
            )
            .expect("input");
        assert_eq!(input_status, "LOCKED");
    }

    #[tokio::test]
    async fn an_accepted_burn_has_no_pending_note() {
        let burn = recorded_burn();
        let server = node_answering(true, "None").await;

        let client = base_node_client(&server.uri()).expect("client");
        let first = broadcast_recorded_burn(burn.pool.clone(), &client, empty_transaction(), burn.tx_id).await;
        assert!(first.accepted_by_node);

        let body = serde_json::to_value(BurnFundsResponse::new(burn.tx_id.to_string(), "00".to_string(), first))
            .expect("json");
        assert_eq!(body["accepted_by_node"], true);
        assert!(body.get("note").is_none(), "no note when accepted");
        assert!(body.get("node_reason").is_none(), "no reason when accepted");

        let conn = burn.pool.get().expect("conn");
        let completed = crate::db::get_completed_transaction_by_id(&conn, burn.tx_id)
            .expect("query")
            .expect("completed");
        assert_eq!(completed.status, crate::db::CompletedTransactionStatus::Broadcast);
    }

    #[tokio::test]
    async fn a_database_failure_after_the_burn_is_recorded_is_still_a_success() {
        let burn = recorded_burn();
        burn.pool
            .get()
            .expect("conn")
            .execute_batch(
                "CREATE TRIGGER no_status BEFORE UPDATE ON completed_transactions \
                 BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )
            .expect("trigger");
        let server = node_answering(true, "None").await;
        let client = base_node_client(&server.uri()).expect("client");

        let first = broadcast_recorded_burn(burn.pool.clone(), &client, empty_transaction(), burn.tx_id).await;
        assert!(first.accepted_by_node);
        assert!(first.local_record_lagging);

        let body = serde_json::to_value(BurnFundsResponse::new(burn.tx_id.to_string(), "00".to_string(), first))
            .expect("json");
        assert_eq!(body["accepted_by_node"], true);
        let note = body["note"].as_str().expect("a note that the record lags");
        assert!(note.contains("Do not send it again"), "got: {note}");
    }

    #[test]
    fn a_bad_node_url_is_refused_before_anything_is_recorded() {
        // The handler builds this client before creating or recording the burn.
        assert!(matches!(
            base_node_client("not a url"),
            Err(ApiError::InternalServerError(_))
        ));
    }
}
