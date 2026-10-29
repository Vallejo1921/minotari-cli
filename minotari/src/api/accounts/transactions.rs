//! Transaction listing and lookup endpoint handlers.

use axum::{
    Json,
    extract::{Path, Query, State},
};
use log::debug;

use crate::{
    api::{AppState, error::ApiError, types::CompletedTransactionResponse},
    db::{
        get_account_by_name, get_completed_transaction_by_id, get_completed_transaction_by_payref,
        get_completed_transactions_by_account, get_displayed_transaction_by_id, get_displayed_transactions_by_payref,
        get_displayed_transactions_paginated, get_transaction_id_by_historical_payref,
    },
    transactions::DisplayedTransaction,
};

use super::params::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, PaginationParams, PayrefParams, WalletParams};

/// Retrieves completed transactions for a specified account with pagination.
///
/// Returns a paginated list of completed transactions for the account, including
/// their status, mined block information, and confirmation details. Transactions
/// are ordered by creation time (most recent first).
///
/// # Path Parameters
///
/// - `name`: The unique account name to query
///
/// # Query Parameters
///
/// - `limit`: Maximum number of transactions to return (default: 50, max: 1000)
/// - `offset`: Number of transactions to skip for pagination (default: 0)
///
/// # Response
///
/// Returns a list of [`CompletedTransactionResponse`] objects, each containing:
/// - Transaction ID and status
/// - Kernel excess (hex encoded)
/// - Mining and confirmation details
/// - Creation and update timestamps
///
/// # Errors
///
/// - [`ApiError::AccountNotFound`]: The specified account does not exist
/// - [`ApiError::DbError`]: Database connection or query failure
///
/// # Example Request
///
/// ```bash
/// # Get first 50 completed transactions (default)
/// curl -X GET http://127.0.0.1:9000/accounts/default/completed_transactions \
///   -H "Authorization: Bearer $MINOTARI_API_TOKEN"
///
/// # Get 100 transactions starting from offset 50
/// curl -X GET "http://127.0.0.1:9000/accounts/default/completed_transactions?limit=100&offset=50" \
///   -H "Authorization: Bearer $MINOTARI_API_TOKEN"
/// ```
///
/// # Example Response
///
/// ```json
/// [
///   {
///     "id": "550e8400-e29b-41d4-a716-446655440000",
///     "pending_tx_id": "661e8400-e29b-41d4-a716-446655440001",
///     "account_id": 1,
///     "status": "mined_confirmed",
///     "last_rejected_reason": null,
///     "kernel_excess_hex": "abc123...",
///     "sent_payref": "payref-123",
///     "sent_output_hash": "def456...",
///     "mined_height": 12345,
///     "mined_block_hash_hex": "789abc...",
///     "confirmation_height": 12350,
///     "broadcast_attempts": 1,
///     "created_at": "2024-01-15T10:30:00Z",
///     "updated_at": "2024-01-15T10:35:00Z"
///   }
/// ]
/// ```
#[utoipa::path(
    get,
    path = "/accounts/{name}/completed_transactions",
    responses(
        (status = 200, description = "Completed transactions retrieved successfully", body = Vec<CompletedTransactionResponse>),
        (status = 404, description = "Account not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    params(
        ("name" = String, Path, description = "Name of the account to retrieve completed transactions for"),
        ("limit" = Option<i64>, Query, description = "Maximum number of transactions to return (default: 50, max: 1000)"),
        ("offset" = Option<i64>, Query, description = "Number of transactions to skip for pagination (default: 0)"),
    )
)]
pub async fn api_get_completed_transactions(
    State(app_state): State<AppState>,
    Path(WalletParams { name }): Path<WalletParams>,
    Query(pagination): Query<PaginationParams>,
) -> Result<Json<Vec<CompletedTransactionResponse>>, ApiError> {
    // Apply defaults and constraints
    let limit = pagination.limit.unwrap_or(DEFAULT_PAGE_LIMIT).min(MAX_PAGE_LIMIT);
    let offset = pagination.offset.unwrap_or(0).max(0);

    debug!(
        account = &*name,
        limit = limit,
        offset = offset;
        "API: Get completed transactions request"
    );

    let pool = app_state.db_pool.clone();
    let name = name.clone();

    let transactions = tokio::task::spawn_blocking(move || {
        let conn = pool.get().map_err(|e| ApiError::DbError(e.to_string()))?;

        let account = get_account_by_name(&conn, &name)
            .map_err(|e| ApiError::DbError(e.to_string()))?
            .ok_or_else(|| ApiError::AccountNotFound(name.clone()))?;

        get_completed_transactions_by_account(&conn, account.id, limit, offset)
            .map_err(|e| ApiError::DbError(e.to_string()))
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    // Convert to API response type
    let response: Vec<CompletedTransactionResponse> = transactions
        .into_iter()
        .map(CompletedTransactionResponse::from)
        .collect();

    Ok(Json(response))
}

/// Retrieves displayed transactions for a specified account with pagination.
///
/// Returns a paginated list of user-friendly transactions for the account,
/// including incoming and outgoing transactions with their status, amounts,
/// and blockchain information. Transactions are ordered by block height
/// (most recent first).
///
/// # Path Parameters
///
/// - `name`: The unique account name to query
///
/// # Query Parameters
///
/// - `limit`: Maximum number of transactions to return (default: 50, max: 1000)
/// - `offset`: Number of transactions to skip for pagination (default: 0)
///
/// # Response
///
/// Returns a list of [`DisplayedTransaction`] objects, each containing:
/// - Transaction ID, direction (incoming/outgoing), and source
/// - Status (pending, unconfirmed, confirmed, cancelled, etc.)
/// - Amount and formatted display amount
/// - Counterparty information (if available)
/// - Blockchain details (block height, timestamp, confirmations)
/// - Fee information (for outgoing transactions)
/// - Detailed input/output information
///
/// # Errors
///
/// - [`ApiError::AccountNotFound`]: The specified account does not exist
/// - [`ApiError::DbError`]: Database connection or query failure
///
/// # Example Request
///
/// ```bash
/// # Get first 50 displayed transactions (default)
/// curl -X GET http://127.0.0.1:9000/accounts/default/displayed_transactions \
///   -H "Authorization: Bearer $MINOTARI_API_TOKEN"
///
/// # Get 100 transactions starting from offset 50
/// curl -X GET "http://127.0.0.1:9000/accounts/default/displayed_transactions?limit=100&offset=50" \
///   -H "Authorization: Bearer $MINOTARI_API_TOKEN"
/// ```
#[utoipa::path(
    get,
    path = "/accounts/{name}/displayed_transactions",
    responses(
        (status = 200, description = "Displayed transactions retrieved successfully", body = Vec<DisplayedTransaction>),
        (status = 404, description = "Account not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    params(
        ("name" = String, Path, description = "Name of the account to retrieve displayed transactions for"),
        ("limit" = Option<i64>, Query, description = "Maximum number of transactions to return (default: 50, max: 1000)"),
        ("offset" = Option<i64>, Query, description = "Number of transactions to skip for pagination (default: 0)"),
    )
)]
pub async fn api_get_displayed_transactions(
    State(app_state): State<AppState>,
    Path(WalletParams { name }): Path<WalletParams>,
    Query(pagination): Query<PaginationParams>,
) -> Result<Json<Vec<DisplayedTransaction>>, ApiError> {
    // Apply defaults and constraints
    let limit = pagination.limit.unwrap_or(DEFAULT_PAGE_LIMIT).min(MAX_PAGE_LIMIT);
    let offset = pagination.offset.unwrap_or(0).max(0);

    debug!(
        account = &*name,
        limit = limit,
        offset = offset;
        "API: Get displayed transactions request"
    );

    let pool = app_state.db_pool.clone();
    let name = name.clone();

    let transactions = tokio::task::spawn_blocking(move || {
        let conn = pool.get().map_err(|e| ApiError::DbError(e.to_string()))?;

        let account = get_account_by_name(&conn, &name)
            .map_err(|e| ApiError::DbError(e.to_string()))?
            .ok_or_else(|| ApiError::AccountNotFound(name.clone()))?;

        get_displayed_transactions_paginated(&conn, account.id, limit, offset)
            .map_err(|e| ApiError::DbError(e.to_string()))
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    Ok(Json(transactions))
}

/// Retrieves a completed transaction by its payment reference.
///
/// Returns a completed transaction that matches the specified payment reference.
/// The payment reference is typically assigned when a transaction is confirmed
/// on the blockchain.
///
/// # Path Parameters
///
/// - `name`: The unique account name to query
/// - `payref`: The payment reference to search for
///
/// # Response
///
/// Returns a [`CompletedTransactionResponse`] object if found, containing:
/// - Transaction ID and status
/// - Kernel excess (hex encoded)
/// - Mining and confirmation details
/// - Creation and update timestamps
///
/// # Errors
///
/// - [`ApiError::AccountNotFound`]: The specified account does not exist
/// - [`ApiError::NotFound`]: No transaction found with the given payment reference
/// - [`ApiError::DbError`]: Database connection or query failure
///
/// # Example Request
///
/// ```bash
/// curl -X GET http://127.0.0.1:9000/accounts/default/completed_transactions/by_payref/my-payment-ref-123 \
///   -H "Authorization: Bearer $MINOTARI_API_TOKEN"
/// ```
#[utoipa::path(
    get,
    path = "/accounts/{name}/completed_transactions/by_payref/{payref}",
    responses(
        (status = 200, description = "Completed transaction retrieved successfully", body = CompletedTransactionResponse),
        (status = 404, description = "Account or transaction not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    params(
        ("name" = String, Path, description = "Name of the account to retrieve transaction from"),
        ("payref" = String, Path, description = "Payment reference to search for"),
    )
)]
pub async fn api_get_completed_transaction_by_payref(
    State(app_state): State<AppState>,
    Path(PayrefParams { name, payref }): Path<PayrefParams>,
) -> Result<Json<CompletedTransactionResponse>, ApiError> {
    debug!(
        account = &*name,
        payref = &*payref;
        "API: Get completed transaction by payref request"
    );

    let pool = app_state.db_pool.clone();
    let name = name.clone();

    let transaction = tokio::task::spawn_blocking(move || {
        let conn = pool.get().map_err(|e| ApiError::DbError(e.to_string()))?;

        let account = get_account_by_name(&conn, &name)
            .map_err(|e| ApiError::DbError(e.to_string()))?
            .ok_or_else(|| ApiError::AccountNotFound(name.clone()))?;

        // Primary lookup against the live payref column.
        if let Some(tx) = get_completed_transaction_by_payref(&conn, account.id, &payref)
            .map_err(|e| ApiError::DbError(e.to_string()))?
        {
            return Ok(tx);
        }

        // Fallback to the payref history table. The db layer only owns the
        // single-table lookup — assembling the cross-table fallback lives in
        // the api so that behaviour is explicit at the caller level (mirrors
        // the console wallet pattern at
        // applications/minotari_console_wallet/src/grpc/wallet_grpc_server.rs).
        debug!(
            account_id = account.id,
            payref = &*payref;
            "API: Primary completed payref lookup missed, checking history table"
        );

        let historical_tx_id = get_transaction_id_by_historical_payref(&conn, account.id, &payref)
            .map_err(|e| ApiError::DbError(e.to_string()))?;

        if let Some(tx_id) = historical_tx_id
            && let Some(tx) =
                get_completed_transaction_by_id(&conn, tx_id).map_err(|e| ApiError::DbError(e.to_string()))?
        {
            return Ok(tx);
        }

        Err(ApiError::NotFound(format!(
            "No completed transaction found with payref: {}",
            payref
        )))
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    Ok(Json(CompletedTransactionResponse::from(transaction)))
}

/// Retrieves displayed transactions by payment reference.
///
/// Returns displayed transactions that contain the specified payment reference.
/// This searches within the payment references stored in each transaction.
///
/// # Path Parameters
///
/// - `name`: The unique account name to query
/// - `payref`: The payment reference to search for
///
/// # Response
///
/// Returns a list of [`DisplayedTransaction`] objects that contain the payment reference.
///
/// # Errors
///
/// - [`ApiError::AccountNotFound`]: The specified account does not exist
/// - [`ApiError::DbError`]: Database connection or query failure
///
/// # Example Request
///
/// ```bash
/// curl -X GET http://127.0.0.1:9000/accounts/default/displayed_transactions/by_payref/my-payment-ref-123 \
///   -H "Authorization: Bearer $MINOTARI_API_TOKEN"
/// ```
#[utoipa::path(
    get,
    path = "/accounts/{name}/displayed_transactions/by_payref/{payref}",
    responses(
        (status = 200, description = "Displayed transactions retrieved successfully", body = Vec<DisplayedTransaction>),
        (status = 404, description = "Account not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    params(
        ("name" = String, Path, description = "Name of the account to retrieve transactions from"),
        ("payref" = String, Path, description = "Payment reference to search for"),
    )
)]
pub async fn api_get_displayed_transactions_by_payref(
    State(app_state): State<AppState>,
    Path(PayrefParams { name, payref }): Path<PayrefParams>,
) -> Result<Json<Vec<DisplayedTransaction>>, ApiError> {
    debug!(
        account = &*name,
        payref = &*payref;
        "API: Get displayed transactions by payref request"
    );

    let pool = app_state.db_pool.clone();
    let name = name.clone();

    let transactions = tokio::task::spawn_blocking(move || {
        let conn = pool.get().map_err(|e| ApiError::DbError(e.to_string()))?;

        let account = get_account_by_name(&conn, &name)
            .map_err(|e| ApiError::DbError(e.to_string()))?
            .ok_or_else(|| ApiError::AccountNotFound(name.clone()))?;

        // Primary lookup against the displayed_transactions.payref column.
        let results = get_displayed_transactions_by_payref(&conn, account.id, &payref)
            .map_err(|e| ApiError::DbError(e.to_string()))?;
        if !results.is_empty() {
            return Ok::<_, ApiError>(results);
        }

        // Fallback to payref history (same rationale as the completed path).
        debug!(
            account_id = account.id,
            payref = &*payref;
            "API: Primary displayed payref lookup missed, checking history table"
        );

        let historical_tx_id = get_transaction_id_by_historical_payref(&conn, account.id, &payref)
            .map_err(|e| ApiError::DbError(e.to_string()))?;

        if let Some(tx_id) = historical_tx_id
            && let Some(tx) = get_displayed_transaction_by_id(&conn, &tx_id.to_string())
                .map_err(|e| ApiError::DbError(e.to_string()))?
        {
            return Ok(vec![tx]);
        }

        Ok(vec![])
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    Ok(Json(transactions))
}
