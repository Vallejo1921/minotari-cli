//! Abandon-send endpoint handler.

use axum::{
    Json,
    extract::{Path, State},
};
use log::{info, trace};
use serde::{Deserialize, Serialize};
use tari_common_types::transaction::TxId;
use utoipa::IntoParams;

use crate::{
    api::{AppState, error::ApiError},
    db::get_account_by_name,
    transactions::abandon::{AbandonSendError, abandon_send},
};

/// Path parameters naming a send of an account.
#[derive(Debug, Deserialize, IntoParams, utoipa::ToSchema)]
pub struct SendParams {
    /// The unique name identifying the wallet account.
    pub name: String,
    /// The send's transaction id.
    pub tx_id: u64,
}

/// Request body for abandoning a send.
#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub struct AbandonSendRequest {
    /// Abandon the send even though it is not stalled yet (the node has not
    /// refused it 10 times in a row). Defaults to `false`.
    #[serde(default)]
    pub force: bool,
    /// Abandon the send even though it has no change output. The wallet
    /// recognises an abandoned send that is mined after all by its change
    /// output; without one, if it is mined, it stays `rejected` in the wallet
    /// while its inputs show as spent. Defaults to `false`.
    #[serde(default)]
    pub accept_unreconcilable: bool,
}

/// Response returned after abandoning a send.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AbandonSendResponse {
    /// The abandoned send's transaction id.
    pub tx_id: String,
    /// The send's status now (`rejected`).
    pub status: String,
    /// What abandoning means for the user. It differs for a send without a
    /// change output (abandoned with `accept_unreconcilable`).
    pub note: String,
}

/// Abandons a send the base node has not accepted, releasing its inputs.
///
/// Only a send that is `completed` or `broadcast` (not mined) can be abandoned.
/// Unless `force` is set it must also be stalled: the node has not accepted it
/// 10 times in a row. A send any of whose inputs is already spent on chain, or
/// whose change output has already been seen on chain, cannot be abandoned;
/// the wallet's scan settles it.
///
/// A send without a change output is refused unless `accept_unreconcilable` is
/// set: the wallet recognises a send mined after all by its change output, so
/// such a send, if mined, stays `rejected` in the wallet.
///
/// The send is marked `rejected` ("abandoned by user"), its inputs released,
/// its change output kept as rejected, its displayed transaction rejected and a
/// `TransactionRejected` event recorded.
///
/// **This does not unsend it.** If a node still holds the transaction it can
/// still be mined; the wallet's scan then marks it mined after all (if it has a
/// change output), and a send made with the released funds in the meantime
/// fails.
///
/// # Errors
///
/// - `404 Not Found`: account or send does not exist
/// - `409 Conflict`: the send is mined or rejected already, is not stalled
///   (and `force` is not set), an input is already spent on chain, its change
///   output is already seen on chain (the send appears to have landed; wait
///   for the scan), its change output is an input of another send, or it has
///   no change output (and `accept_unreconcilable` is not set)
/// - `500`: database error
#[utoipa::path(
    post,
    path = "/accounts/{name}/completed_transactions/{tx_id}/abandon",
    request_body = AbandonSendRequest,
    responses(
        (status = 200, description = "Send abandoned", body = AbandonSendResponse),
        (status = 404, description = "Account or send not found", body = ApiError),
        (status = 409, description = "The send cannot be abandoned", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    params(
        ("name" = String, Path, description = "Name of the account"),
        ("tx_id" = u64, Path, description = "Transaction id of the send to abandon"),
    )
)]
pub async fn api_abandon_send(
    State(app_state): State<AppState>,
    Path(SendParams { name, tx_id }): Path<SendParams>,
    Json(body): Json<AbandonSendRequest>,
) -> Result<Json<AbandonSendResponse>, ApiError> {
    let pool = app_state.db_pool.clone();
    let tx_id = TxId::from(tx_id);

    let abandoned = tokio::task::spawn_blocking(move || {
        let mut conn = pool.get().map_err(|e| ApiError::DbError(e.to_string()))?;
        let account = get_account_by_name(&conn, &name)
            .map_err(|e| ApiError::DbError(e.to_string()))?
            .ok_or_else(|| ApiError::AccountNotFound(name.clone()))?;
        abandon_send(
            &mut conn,
            account.id,
            tx_id,
            body.force,
            body.accept_unreconcilable,
            None,
        )
        .map_err(|e| match e {
            AbandonSendError::NotFound(_) => ApiError::NotFound(e.to_string()),
            AbandonSendError::Db(db) => ApiError::DbError(db.to_string()),
            other => ApiError::Conflict(other.to_string()),
        })
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    info!(
        target: "audit",
        reconcilable = abandoned.reconcilable;
        "API: Send abandoned"
    );
    trace!(
        target: "audit",
        tx_id = tx_id.to_string().as_str();
        "API: Send abandoned"
    );

    Ok(Json(AbandonSendResponse {
        tx_id: tx_id.to_string(),
        status: "rejected".to_string(),
        note: abandoned.note().to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{create_account, init_db};
    use crate::transactions::idempotency::{IdempotencyBinding, IdempotencyOperation, RequestFingerprint};
    use chrono::Utc;
    use tari_common::configuration::Network;
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_transaction_components::MicroMinotari;
    use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
    use zeroize::Zeroizing;

    /// An app with one account holding one broadcast send (id 9), not stalled
    /// and without a change output.
    fn app_with_a_send() -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let pool = init_db(dir.path().join("api_abandon.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
        create_account(&conn, "default", &wallet, "password").unwrap();
        let account = get_account_by_name(&conn, "default").unwrap().unwrap();
        let binding = IdempotencyBinding::new(
            Some("send".to_string()),
            IdempotencyOperation::SendTransaction,
            RequestFingerprint::new(IdempotencyOperation::SendTransaction),
        );
        let request_id = crate::db::create_pending_transaction(
            &conn,
            "send",
            &binding,
            account.id,
            true,
            MicroMinotari(0),
            MicroMinotari(0),
            MicroMinotari(0),
            Utc::now() + chrono::Duration::hours(1),
        )
        .expect("pending");
        crate::db::create_completed_transaction(&conn, account.id, &request_id, &[], b"{}", None, TxId::from(9u64))
            .expect("completed");
        crate::db::mark_completed_transaction_as_broadcasted(&conn, TxId::from(9u64), 1).expect("broadcast");
        drop(conn);
        let state = AppState {
            db_pool: pool,
            network: Network::LocalNet,
            password: Zeroizing::new("password".to_string()),
            required_confirmations: 3,
            base_node_url: "http://127.0.0.1:1".to_string(),
        };
        (state, dir)
    }

    async fn call(
        state: &AppState,
        tx_id: u64,
        force: bool,
        accept_unreconcilable: bool,
    ) -> Result<Json<AbandonSendResponse>, ApiError> {
        api_abandon_send(
            State(state.clone()),
            Path(SendParams {
                name: "default".to_string(),
                tx_id,
            }),
            Json(AbandonSendRequest {
                force,
                accept_unreconcilable,
            }),
        )
        .await
    }

    #[tokio::test]
    async fn a_send_that_is_not_stalled_is_a_conflict_unless_forced() {
        let (state, _dir) = app_with_a_send();

        assert!(matches!(call(&state, 9, false, true).await, Err(ApiError::Conflict(_))));

        let Json(response) = call(&state, 9, true, true).await.expect("abandoned with force");
        assert_eq!(response.status, "rejected");
        assert!(response.note.contains("still holds the transaction"));

        // Abandoned already: a conflict.
        assert!(matches!(call(&state, 9, true, true).await, Err(ApiError::Conflict(_))));
    }

    #[tokio::test]
    async fn a_send_without_change_is_a_conflict_unless_accepted_as_unreconcilable() {
        let (state, _dir) = app_with_a_send();

        match call(&state, 9, true, false).await {
            Err(ApiError::Conflict(message)) => assert!(message.contains("no change output"), "{message}"),
            other => panic!("expected a conflict, got {other:?}"),
        }

        let Json(response) = call(&state, 9, true, true).await.expect("abandoned");
        assert_eq!(response.status, "rejected");
        assert_eq!(response.note, crate::transactions::abandon::UNRECONCILABLE_ABANDON_NOTE);
    }

    #[tokio::test]
    async fn an_unknown_send_is_not_found() {
        let (state, _dir) = app_with_a_send();
        assert!(matches!(
            call(&state, 12345, true, true).await,
            Err(ApiError::NotFound(_))
        ));
    }
}
