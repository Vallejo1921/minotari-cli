//! Account management API endpoint handlers.
//!
//! This module provides HTTP endpoint handlers for account-related operations
//! in the Minotari wallet REST API. It includes functionality for:
//!
//! - Querying account balances
//! - Retrieving wallet events
//! - Locking funds for transaction preparation
//! - Creating unsigned transactions for one-sided payments
//!
//! All endpoints follow RESTful conventions and return JSON responses.
//! Error responses use the [`ApiError`] type for consistent error formatting.
//!
//! # Endpoint Overview
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET | `/accounts/{name}/balance` | Retrieve account balance |
//! | GET | `/accounts/{name}/events` | Retrieve wallet events |
//! | POST | `/accounts/{name}/lock_funds` | Lock UTXOs for spending |
//! | POST | `/accounts/{name}/create_unsigned_transaction` | Create unsigned transaction |
//!
//! # Example Usage
//!
//! ```bash
//! # Get account balance
//! curl -X GET http://localhost:8080/accounts/default/balance
//!
//! # Get wallet events
//! curl -X GET http://localhost:8080/accounts/default/events
//!
//! # Lock funds for a transaction
//! curl -X POST http://localhost:8080/accounts/default/lock_funds \
//!   -H "Content-Type: application/json" \
//!   -d '{"amount": 1000000}'
//! ```

use axum::{
    Json,
    extract::{Path, Query, State},
};
use log::{debug, info};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use utoipa::{
    IntoParams,
    openapi::{ObjectBuilder, Schema, Type, schema::SchemaType},
};

use super::error::ApiError;
use crate::{
    api::{
        AppState,
        types::{
            AddressResponse, AddressWithPaymentIdResponse, CompletedTransactionResponse, FeeEstimateResponse,
            FeePriorityResponse, LockFundsResult, ScanStatusResponse, TariAddressBase58, VersionResponse,
        },
    },
    db::{
        AccountBalance, DbWalletEvent, get_account_by_name, get_balance, get_completed_transaction_by_payref,
        get_completed_transactions_by_account, get_displayed_transactions_by_payref,
        get_displayed_transactions_paginated, get_events_by_account_id, get_latest_scanned_block_with_timestamp,
    },
    log::mask_amount,
    transactions::{
        DisplayedTransaction,
        fee_estimator::{FeeEstimator, FeePriority},
        fund_locker::FundLocker,
        one_sided_transaction::{OneSidedTransaction, Recipient},
    },
};
use tari_transaction_components::tari_amount::MicroMinotari;

/// Returns the default lock duration for UTXOs.
///
/// UTXOs are locked for 24 hours (86,400 seconds) by default to prevent
/// double-spending while a transaction is being prepared and broadcast.
fn default_seconds_to_lock_utxos() -> Option<u64> {
    Some(86400)
}

/// Returns the default number of outputs for a transaction.
///
/// Defaults to 1 output, which is suitable for simple single-recipient
/// transactions.
fn default_num_outputs() -> Option<usize> {
    Some(1)
}

/// Returns the default fee per gram for transactions.
///
/// The default fee is 5 MicroMinotari per gram, which provides a reasonable
/// balance between transaction confirmation speed and cost.
fn default_fee_per_gram() -> Option<MicroMinotari> {
    Some(MicroMinotari(5))
}

fn confirmation_window_schema() -> Schema {
    ObjectBuilder::new()
        .schema_type(SchemaType::new(Type::Integer))
        .description(Some("Number of confirmations required"))
        .build()
        .into()
}

/// Default number of items per page for paginated endpoints.
const DEFAULT_PAGE_LIMIT: i64 = 50;

/// Maximum number of items that can be requested per page.
const MAX_PAGE_LIMIT: i64 = 1000;

/// Query parameters for pagination.
///
/// Used to control the number of results returned and offset for paginated
/// endpoints.
#[derive(Debug, Deserialize, IntoParams)]
pub struct PaginationParams {
    /// Maximum number of items to return (default: 50, max: 1000)
    pub limit: Option<i64>,
    /// Number of items to skip for pagination (default: 0)
    pub offset: Option<i64>,
}

/// Path parameters for wallet/account identification.
///
/// Used to extract the account name from URL path segments in account-related
/// endpoints.
///
/// # Example
///
/// For a request to `/accounts/my_wallet/balance`, the `name` field would
/// contain `"my_wallet"`.
#[derive(Debug, Deserialize, IntoParams, utoipa::ToSchema)]
pub struct WalletParams {
    /// The unique name identifying the wallet account.
    name: String,
}

/// Request body for locking funds in preparation for a transaction.
///
/// This request reserves (locks) a specified amount of funds from the account's
/// available UTXOs. Locked funds cannot be used in other transactions until
/// either the lock expires or the transaction is completed/cancelled.
///
/// # JSON Example
///
/// ```json
/// {
///   "amount": 1000000,
///   "num_outputs": 2,
///   "fee_per_gram": 5,
///   "estimated_output_size": 1024,
///   "seconds_to_lock_utxos": 3600,
///   "idempotency_key": "unique-request-id-12345"
/// }
/// ```
///
/// # Minimal Request
///
/// Only `amount` is required; all other fields have sensible defaults:
///
/// ```json
/// {
///   "amount": 1000000
/// }
/// ```
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct LockFundsRequest {
    /// The total amount to lock in MicroMinotari (1 Minotari = 1,000,000 MicroMinotari).
    ///
    /// This should cover the intended transaction amount plus any expected fees.
    #[schema(value_type = u64)]
    pub amount: MicroMinotari,

    /// Number of outputs to create in the transaction.
    ///
    /// Defaults to 1. Increase this when sending to multiple recipients or when
    /// the transaction requires multiple output UTXOs.
    #[serde(default = "default_num_outputs")]
    #[schema(default = "1")]
    pub num_outputs: Option<usize>,

    /// Fee per gram for the transaction in MicroMinotari.
    ///
    /// Defaults to 5 MicroMinotari. Higher fees may result in faster confirmation
    /// during periods of high network congestion.
    #[schema(value_type = u64)]
    #[serde(default = "default_fee_per_gram")]
    #[schema(default = "5")]
    pub fee_per_gram: Option<MicroMinotari>,

    /// Estimated size of each output in bytes.
    ///
    /// Used for fee calculation. If not provided, a default estimate is used
    /// based on standard output sizes.
    pub estimated_output_size: Option<usize>,

    /// Duration in seconds to keep the UTXOs locked.
    ///
    /// Defaults to 86,400 seconds (24 hours). After this period, locked UTXOs
    /// are automatically released if the transaction was not completed.
    #[serde(default = "default_seconds_to_lock_utxos")]
    #[schema(default = "86400")]
    pub seconds_to_lock_utxos: Option<u64>,

    /// Optional idempotency key to prevent duplicate requests.
    ///
    /// If provided, subsequent requests with the same key will return the
    /// cached result from the original request rather than locking additional
    /// funds.
    pub idempotency_key: Option<String>,

    /// Number of confirmations required before spending locked UTXOs.
    #[schema(schema_with = confirmation_window_schema)]
    pub confirmation_window: Option<u64>,
}

/// Represents a single recipient in a transaction request.
///
/// Each recipient specifies a destination address and the amount to send.
/// An optional payment ID can be included for tracking or identification
/// purposes.
///
/// # JSON Example
///
/// ```json
/// {
///   "address": "f4FxMqKAPDMqAjh6hTpC...",
///   "amount": 500000,
///   "payment_id": "invoice-2024-001"
/// }
/// ```
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RecipientRequest {
    /// The recipient's Tari address in Base58 encoding.
    ///
    /// Must be a valid Tari address for the current network (mainnet, testnet, etc.).
    address: TariAddressBase58,

    /// The amount to send to this recipient in MicroMinotari.
    #[schema(value_type = u64)]
    amount: MicroMinotari,

    /// Optional payment identifier for transaction tracking.
    ///
    /// This can be used to associate the payment with an invoice, order, or
    /// other business reference. The payment ID is included in the transaction
    /// metadata.
    payment_id: Option<String>,
}

/// Request body for creating an unsigned transaction.
///
/// Creates a one-sided transaction that can be signed externally. This is
/// useful for cold wallet setups or multi-signature workflows where the
/// signing key is not available on the server.
///
/// # JSON Example
///
/// ```json
/// {
///   "recipients": [
///     {
///       "address": "f4FxMqKAPDMqAjh6hTpC...",
///       "amount": 500000,
///       "payment_id": "order-123"
///     },
///     {
///       "address": "f5GxNrLBPEMrBki7iTqD...",
///       "amount": 300000
///     }
///   ],
///   "seconds_to_lock_utxos": 7200,
///   "idempotency_key": "tx-request-abc123"
/// }
/// ```
///
/// # Notes
///
/// - The total amount sent equals the sum of all recipient amounts
/// - Transaction fees are calculated automatically based on transaction size
/// - UTXOs are locked during transaction creation to prevent double-spending
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateTransactionRequest {
    /// List of recipients for the transaction.
    ///
    /// At least one recipient must be specified. Each recipient includes an
    /// address and amount, with an optional payment ID.
    recipients: Vec<RecipientRequest>,

    /// Duration in seconds to keep the input UTXOs locked.
    ///
    /// Defaults to 86,400 seconds (24 hours). The lock prevents the same UTXOs
    /// from being used in multiple transactions while the unsigned transaction
    /// is being signed and broadcast.

    #[serde(default = "default_seconds_to_lock_utxos")]
    #[schema(default = "86400")]
    seconds_to_lock_utxos: Option<u64>,

    /// Optional idempotency key to prevent duplicate transactions.
    ///
    /// If the same key is used in multiple requests, subsequent requests will
    /// return the original transaction rather than creating a new one.
    idempotency_key: Option<String>,

    #[schema(schema_with = confirmation_window_schema)]
    pub confirmation_window: Option<u64>,
}

fn default_one_usize() -> usize {
    1
}

// Request body for fee estimation.
///
/// Calculates estimated fees for a transaction based on current mempool conditions
/// and available UTXOs.
///
/// # JSON Example
///
/// ```json
/// {
///   "amount": 1000000,
///   "num_outputs": 2,
///   "estimated_output_size": 500
/// }
/// ```
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct EstimateFeeRequest {
    /// The amount to send in MicroMinotari.
    #[schema(value_type = u64)]
    pub amount: MicroMinotari,

    /// Number of outputs in the transaction (default: 1).
    #[serde(default = "default_one_usize")]
    #[schema(default = "1")]
    pub num_outputs: usize,

    /// Number of confirmations required for inputs.
    #[schema(schema_with = confirmation_window_schema)]
    pub confirmation_window: Option<u64>,

    /// Estimated size of each output in bytes.
    pub estimated_output_size: Option<usize>,
}

/// Retrieves the wallet version information.
///
/// Returns the version and name of the wallet software. This endpoint does not
/// require authentication and can be used for health checks or compatibility
/// verification.
///
/// # Response
///
/// Returns a [`VersionResponse`] object containing:
/// - The semantic version string
/// - The package name
///
/// # Example Response
///
/// ```json
/// {
///   "version": "0.1.0",
///   "name": "minotari"
/// }
/// ```
#[utoipa::path(
    get,
    path = "/version",
    responses(
        (status = 200, description = "Version information retrieved successfully", body = VersionResponse),
    ),
)]
pub async fn api_get_version() -> Json<VersionResponse> {
    debug!("API: Get version request");

    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        name: env!("CARGO_PKG_NAME").to_string(),
    })
}

/// Retrieves the current balance for a specified account.
///
/// Returns the account's available balance, pending incoming transactions,
/// and locked funds. This endpoint is useful for displaying wallet status
/// or checking available funds before initiating a transaction.
///
/// # Path Parameters
///
/// - `name`: The unique account name to query
///
/// # Response
///
/// Returns an [`AccountBalance`] object containing:
/// - Available (spendable) balance
/// - Pending incoming balance
/// - Locked balance (reserved for pending transactions)
///
/// # Errors
///
/// - [`ApiError::AccountNotFound`]: The specified account does not exist
/// - [`ApiError::DbError`]: Database connection or query failure
///
/// # Example Response
///
/// ```json
/// {
///   "available": 10000000,
///   "pending_incoming": 500000,
///   "locked": 200000
/// }
/// ```
#[utoipa::path(
    get,
    path = "/accounts/{name}/balance",
    responses(
        (status = 200, description = "Account balance retrieved successfully", body = AccountBalance),
        (status = 404, description = "Account not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    params(
        ("name" = String, Path, description = "Name of the account to retrieve balance for"),
    )
)]
pub async fn api_get_balance(
    State(app_state): State<AppState>,
    Path(WalletParams { name }): Path<WalletParams>,
) -> Result<Json<AccountBalance>, ApiError> {
    debug!(
        account = &*name;
        "API: Get balance request"
    );

    let pool = app_state.db_pool.clone();
    let name = name.clone();

    let balance = tokio::task::spawn_blocking(move || {
        let conn = pool.get().map_err(|e| ApiError::DbError(e.to_string()))?;

        let account = get_account_by_name(&conn, &name)
            .map_err(|e| ApiError::DbError(e.to_string()))?
            .ok_or_else(|| ApiError::AccountNotFound(name.clone()))?;

        get_balance(&conn, account.id).map_err(|e| ApiError::DbError(e.to_string()))
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    Ok(Json(balance))
}

/// Retrieves the Tari address for a specified account.
///
/// Returns the account's Tari address in Base58 format along with the emoji ID
/// representation. This address can be shared with others to receive payments.
///
/// # Path Parameters
///
/// - `name`: The unique account name to query
///
/// # Response
///
/// Returns an [`AddressResponse`] object containing:
/// - The address in Base58 encoding
/// - The emoji ID representation
///
/// # Errors
///
/// - [`ApiError::AccountNotFound`]: The specified account does not exist
/// - [`ApiError::DbError`]: Database connection or query failure
///
/// # Example Response
///
/// ```json
/// {
///   "address": "f4FxMqKAPDMqAjh6hTpCnLKfEu3MmS7NRu2YmKZPvZHc2K",
///   "emoji_id": "🎉🌟🚀..."
/// }
/// ```
#[utoipa::path(
    get,
    path = "/accounts/{name}/address",
    responses(
        (status = 200, description = "Account address retrieved successfully", body = AddressResponse),
        (status = 404, description = "Account not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    params(
        ("name" = String, Path, description = "Name of the account to retrieve address for"),
    )
)]
pub async fn api_get_address(
    State(app_state): State<AppState>,
    Path(WalletParams { name }): Path<WalletParams>,
) -> Result<Json<AddressResponse>, ApiError> {
    debug!(
        account = &*name;
        "API: Get address request"
    );

    let pool = app_state.db_pool.clone();
    let name = name.clone();
    let network = app_state.network;
    let password = app_state.password.clone();

    let address_response = tokio::task::spawn_blocking(move || {
        let conn = pool.get().map_err(|e| ApiError::DbError(e.to_string()))?;

        let account = get_account_by_name(&conn, &name)
            .map_err(|e| ApiError::DbError(e.to_string()))?
            .ok_or_else(|| ApiError::AccountNotFound(name.clone()))?;

        let address = account
            .get_address(network, &password)
            .map_err(|e| ApiError::InternalServerError(format!("Failed to get address: {}", e)))?;

        Ok::<_, ApiError>(AddressResponse {
            address: address.to_base58(),
            emoji_id: address.to_emoji_string(),
        })
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    Ok(Json(address_response))
}

/// Request body for creating an address with a payment ID.
///
/// # JSON Example
///
/// ```json
/// {
///   "payment_id_hex": "696e766f6963652d3132333435"
/// }
/// ```
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreatePaymentIdAddressRequest {
    /// The payment ID to embed in the address, hex encoded.
    ///
    /// This should be a hex-encoded byte string (e.g., "696e766f6963652d3132333435" for "invoice-12345").
    /// Maximum length is 256 bytes when decoded.
    pub payment_id_hex: String,
}

/// Creates a Tari address with an embedded payment ID for a specified account.
///
/// Generates a new address that includes a payment ID, which can be used to
/// identify specific transactions or invoices. When someone sends funds to
/// this address, the payment ID will be included in the transaction.
///
/// # Path Parameters
///
/// - `name`: The unique account name
///
/// # Request Body
///
/// See [`CreatePaymentIdAddressRequest`] for the complete request schema.
///
/// # Response
///
/// Returns an [`AddressWithPaymentIdResponse`] object containing:
/// - The address with embedded payment ID in Base58 encoding
/// - The emoji ID representation
/// - The original payment ID
///
/// # Errors
///
/// - [`ApiError::AccountNotFound`]: The specified account does not exist
/// - [`ApiError::DbError`]: Database connection or query failure
/// - [`ApiError::InternalServerError`]: Failed to generate the address
///
/// # Example Request
///
/// ```bash
/// curl -X POST http://localhost:8080/accounts/default/address_with_payment_id \
///   -H "Content-Type: application/json" \
///   -d '{"payment_id": "696e766f6963652d3132333435"}'
/// ```
///
/// # Example Response
///
/// ```json
/// {
///   "address": "f4FxMqKAPDMqAjh6hTpCnLKfEu3MmS7NRu2YmKZPvZHc2K",
///   "emoji_id": "🎉🌟🚀...",
///   "payment_id_hex": "696e766f6963652d3132333435"
/// }
/// ```
#[utoipa::path(
    post,
    path = "/accounts/{name}/address_with_payment_id",
    request_body = CreatePaymentIdAddressRequest,
    responses(
        (status = 200, description = "Address with payment ID created successfully", body = AddressWithPaymentIdResponse),
        (status = 400, description = "Bad request", body = ApiError),
        (status = 404, description = "Account not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    params(
        ("name" = String, Path, description = "Name of the account to create address for"),
    )
)]
pub async fn api_create_address_with_payment_id(
    State(app_state): State<AppState>,
    Path(WalletParams { name }): Path<WalletParams>,
    Json(body): Json<CreatePaymentIdAddressRequest>,
) -> Result<Json<AddressWithPaymentIdResponse>, ApiError> {
    // Decode the hex payment ID
    let payment_id_bytes = hex::decode(&body.payment_id_hex)
        .map_err(|e| ApiError::BadRequest(format!("Invalid hex in payment_id_hex: {}", e)))?;

    info!(
        target: "audit",
        account = &*name,
        payment_id_hex = &*body.payment_id_hex;
        "API: Create address with payment ID request"
    );

    let pool = app_state.db_pool.clone();
    let name = name.clone();
    let network = app_state.network;
    let password = app_state.password.clone();
    let payment_id_hex = body.payment_id_hex.clone();

    let address_response = tokio::task::spawn_blocking(move || {
        let conn = pool.get().map_err(|e| ApiError::DbError(e.to_string()))?;

        let account = get_account_by_name(&conn, &name)
            .map_err(|e| ApiError::DbError(e.to_string()))?
            .ok_or_else(|| ApiError::AccountNotFound(name.clone()))?;

        let address = account
            .get_address_with_payment_id(network, &password, &payment_id_bytes)
            .map_err(|e| ApiError::InternalServerError(format!("Failed to create address with payment ID: {}", e)))?;

        Ok::<_, ApiError>(AddressWithPaymentIdResponse {
            address: address.to_base58(),
            emoji_id: address.to_emoji_string(),
            payment_id_hex,
        })
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    Ok(Json(address_response))
}

/// Retrieves the scan status for a specified account.
///
/// Returns information about the last scanned block, including the block height,
/// block hash, and the timestamp when the scan occurred. This is useful for
/// monitoring the wallet's synchronization progress with the blockchain.
///
/// # Path Parameters
///
/// - `name`: The unique account name to query
///
/// # Response
///
/// Returns a [`ScanStatusResponse`] object containing:
/// - Last scanned block height
/// - Last scanned block hash (hex encoded)
/// - Timestamp when the block was scanned
///
/// # Errors
///
/// - [`ApiError::AccountNotFound`]: The specified account does not exist
/// If no blocks have been scanned yet, returns a response with default values (height 0, empty hash and timestamp).
/// - [`ApiError::DbError`]: Database connection or query failure
///
/// # Example Response
///
/// ```json
/// {
///   "last_scanned_height": 12345,
///   "last_scanned_block_hash": "abc123def456...",
///   "scanned_at": "2024-01-15 10:30:00"
/// }
/// ```
#[utoipa::path(
    get,
    path = "/accounts/{name}/scan_status",
    responses(
        (status = 200, description = "Scan status retrieved successfully", body = ScanStatusResponse),
        (status = 404, description = "Account not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    params(
        ("name" = String, Path, description = "Name of the account to retrieve scan status for"),
    )
)]
pub async fn api_get_scan_status(
    State(app_state): State<AppState>,
    Path(WalletParams { name }): Path<WalletParams>,
) -> Result<Json<ScanStatusResponse>, ApiError> {
    debug!(
        account = &*name;
        "API: Get scan status request"
    );

    let pool = app_state.db_pool.clone();
    let name = name.clone();

    let scan_status = tokio::task::spawn_blocking(move || {
        let conn = pool.get().map_err(|e| ApiError::DbError(e.to_string()))?;

        let account = get_account_by_name(&conn, &name)
            .map_err(|e| ApiError::DbError(e.to_string()))?
            .ok_or_else(|| ApiError::AccountNotFound(name.clone()))?;

        get_latest_scanned_block_with_timestamp(&conn, account.id).map_err(|e| ApiError::DbError(e.to_string()))
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    let response = match scan_status {
        Some(block) => ScanStatusResponse::from(block),
        None => ScanStatusResponse {
            last_scanned_height: 0,
            last_scanned_block_hash: String::new(),
            scanned_at: String::new(),
        },
    };

    Ok(Json(response))
}

/// Retrieves wallet events for a specified account with pagination.
///
/// Returns a paginated list of events that have occurred for the account, including
/// output detection, confirmation, transaction broadcasts, and blockchain
/// reorganizations. Events are ordered by creation time (most recent first).
///
/// # Path Parameters
///
/// - `name`: The unique account name to query
///
/// # Query Parameters
///
/// - `limit`: Maximum number of events to return (default: 50, max: 1000)
/// - `offset`: Number of events to skip for pagination (default: 0)
///
/// # Response
///
/// Returns a list of [`DbWalletEvent`] objects, each containing:
/// - Event ID and type
/// - Human-readable description
/// - JSON data with event-specific details
/// - Creation timestamp
///
/// # Errors
///
/// - [`ApiError::AccountNotFound`]: The specified account does not exist
/// - [`ApiError::DbError`]: Database connection or query failure
///
/// # Example Request
///
/// ```bash
/// # Get first 50 events (default)
/// curl -X GET http://localhost:8080/accounts/default/events
///
/// # Get 100 events starting from offset 50
/// curl -X GET "http://localhost:8080/accounts/default/events?limit=100&offset=50"
/// ```
///
/// # Example Response
///
/// ```json
/// [
///   {
///     "id": 42,
///     "account_id": 1,
///     "event_type": "OutputDetected",
///     "description": "Detected output at height 12345",
///     "data_json": "{\"hash\":\"abc...\",\"block_height\":12345}",
///     "created_at": "2024-01-15T10:30:00"
///   }
/// ]
/// ```
#[utoipa::path(
    get,
    path = "/accounts/{name}/events",
    responses(
        (status = 200, description = "Account events retrieved successfully", body = Vec<DbWalletEvent>),
        (status = 404, description = "Account not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    params(
        ("name" = String, Path, description = "Name of the account to retrieve events for"),
        ("limit" = Option<i64>, Query, description = "Maximum number of events to return (default: 50, max: 1000)"),
        ("offset" = Option<i64>, Query, description = "Number of events to skip for pagination (default: 0)"),
    )
)]
pub async fn api_get_events(
    State(app_state): State<AppState>,
    Path(WalletParams { name }): Path<WalletParams>,
    Query(pagination): Query<PaginationParams>,
) -> Result<Json<Vec<DbWalletEvent>>, ApiError> {
    // Apply defaults and constraints
    let limit = pagination.limit.unwrap_or(DEFAULT_PAGE_LIMIT).min(MAX_PAGE_LIMIT);
    let offset = pagination.offset.unwrap_or(0).max(0);

    debug!(
        account = &*name,
        limit = limit,
        offset = offset;
        "API: Get events request"
    );

    let pool = app_state.db_pool.clone();
    let name = name.clone();

    let events = tokio::task::spawn_blocking(move || {
        let conn = pool.get().map_err(|e| ApiError::DbError(e.to_string()))?;

        let account = get_account_by_name(&conn, &name)
            .map_err(|e| ApiError::DbError(e.to_string()))?
            .ok_or_else(|| ApiError::AccountNotFound(name.clone()))?;

        get_events_by_account_id(&conn, account.id, limit, offset).map_err(|e| ApiError::DbError(e.to_string()))
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    Ok(Json(events))
}

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
/// curl -X GET http://localhost:8080/accounts/default/completed_transactions
///
/// # Get 100 transactions starting from offset 50
/// curl -X GET "http://localhost:8080/accounts/default/completed_transactions?limit=100&offset=50"
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
/// curl -X GET http://localhost:8080/accounts/default/displayed_transactions
///
/// # Get 100 transactions starting from offset 50
/// curl -X GET "http://localhost:8080/accounts/default/displayed_transactions?limit=100&offset=50"
/// ```
///
/// # Example Response
///
/// ```json
/// [
///   {
///     "id": "tx-123",
///     "direction": "incoming",
///     "source": "transfer",
///     "status": "confirmed",
///     "amount": 1000000,
///     "amount_display": "1.000000 XTM",
///     "message": null,
///     "counterparty": {
///       "address": "f4FxMqKAPDMqAjh6hTpC...",
///       "address_emoji": "🎉🌟...",
///       "label": null
///     },
///     "blockchain": {
///       "block_height": 12345,
///       "timestamp": "2024-01-15T10:30:00",
///       "confirmations": 10
///     },
///     "fee": null,
///     "details": {
///       "account_id": 1,
///       "total_credit": 1000000,
///       "total_debit": 0,
///       "inputs": [],
///       "outputs": [...]
///     }
///   }
/// ]
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

/// Locks funds from an account for transaction preparation.
///
/// This endpoint reserves UTXOs totaling at least the requested amount,
/// preventing them from being used in other transactions. This is typically
/// the first step in creating a transaction, ensuring funds are available
/// and reserved before constructing the transaction.
///
/// # Path Parameters
///
/// - `name`: The account name to lock funds from
///
/// # Request Body
///
/// See [`LockFundsRequest`] for the complete request schema.
///
/// # Response
///
/// Returns a [`LockFundsResult`] containing:
/// - The selected UTXOs to use as inputs
/// - Whether a change output is required
/// - Total value of locked UTXOs
/// - Fee estimates with and without change
///
/// # Errors
///
/// - [`ApiError::AccountNotFound`]: The specified account does not exist
/// - [`ApiError::FailedToLockFunds`]: Insufficient funds or UTXO selection failure
/// - [`ApiError::DbError`]: Database connection or query failure
///
/// # Example
///
/// ```bash
/// curl -X POST http://localhost:8080/accounts/default/lock_funds \
///   -H "Content-Type: application/json" \
///   -d '{"amount": 1000000, "num_outputs": 1}'
/// ```
///
/// # Notes
///
/// - Locked UTXOs are automatically released after the configured timeout
/// - Use the `idempotency_key` to safely retry failed requests
/// - The actual locked amount may exceed the requested amount due to UTXO granularity
#[utoipa::path(
    post,
    path = "/accounts/{name}/lock_funds",
    request_body = LockFundsRequest,
    responses(
        (status = 200, description = "Funds locked successfully", body = LockFundsResult),
        (status = 400, description = "Bad request", body = ApiError),
        (status = 404, description = "Account not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    params(
        ("name" = String, Path, description = "Name of the account to lock funds from"),
    )
)]
pub async fn api_lock_funds(
    State(app_state): State<AppState>,
    Path(WalletParams { name }): Path<WalletParams>,
    Json(body): Json<LockFundsRequest>,
) -> Result<Json<LockFundsResult>, ApiError> {
    info!(
        target: "audit",
        account = &*name,
        amount = &*mask_amount(body.amount.0.into()),
        idempotency_key:? = body.idempotency_key;
        "API: Lock funds request"
    );

    let pool = app_state.db_pool.clone();
    let name = name.clone();
    let default_confirmations = app_state.required_confirmations;

    let response = tokio::task::spawn_blocking(move || {
        let conn = pool.get().map_err(|e| ApiError::DbError(e.to_string()))?;

        let account = get_account_by_name(&conn, &name)
            .map_err(|e| ApiError::DbError(e.to_string()))?
            .ok_or_else(|| ApiError::AccountNotFound(name.clone()))?;

        let lock_amount = FundLocker::new(pool);
        let confirmation_window = body.confirmation_window.unwrap_or(default_confirmations);
        lock_amount
            .lock(
                account.id,
                body.amount,
                body.num_outputs.expect("must be defaulted"),
                body.fee_per_gram.expect("must be defaulted"),
                body.estimated_output_size,
                body.idempotency_key,
                body.seconds_to_lock_utxos.expect("must be defaulted"),
                confirmation_window,
            )
            .map_err(|e| ApiError::FailedToLockFunds(e.to_string()))
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    Ok(Json(response))
}

/// Creates an unsigned one-sided transaction for external signing.
///
/// This endpoint constructs a complete transaction ready for signing, including
/// input selection, output creation, and fee calculation. The transaction is
/// returned in an unsigned state, allowing it to be signed by an external
/// key management system or hardware wallet.
///
/// # Path Parameters
///
/// - `name`: The account name to send funds from
///
/// # Request Body
///
/// See [`CreateTransactionRequest`] for the complete request schema.
///
/// # Response
///
/// Returns a JSON object containing the unsigned transaction data, including:
/// - Transaction inputs (selected UTXOs)
/// - Transaction outputs (recipient outputs and change)
/// - Fee information
/// - Data required for signing
///
/// # Errors
///
/// - [`ApiError::AccountNotFound`]: The specified account does not exist
/// - [`ApiError::FailedToLockFunds`]: Insufficient funds or UTXO selection failure
/// - [`ApiError::FailedCreateUnsignedTx`]: Transaction construction failure
/// - [`ApiError::DbError`]: Database connection or query failure
///
/// # Example
///
/// ```bash
/// curl -X POST http://localhost:8080/accounts/default/create_unsigned_transaction \
///   -H "Content-Type: application/json" \
///   -d '{
///     "recipients": [
///       {"address": "f4FxMqKAPDMqAjh6hTpC...", "amount": 1000000}
///     ]
///   }'
/// ```
///
/// # Workflow
///
/// 1. Client calls this endpoint to create an unsigned transaction
/// 2. Server locks required UTXOs and constructs the transaction
/// 3. Client signs the transaction externally
/// 4. Client broadcasts the signed transaction to the network
///
/// # Notes
///
/// - This creates a one-sided transaction (no recipient interaction required)
/// - UTXOs are automatically locked for the configured duration
/// - Fee is calculated at 5 MicroMinotari per gram
/// - Change outputs are created automatically when necessary
#[utoipa::path(
    post,
    path = "/accounts/{name}/create_unsigned_transaction",
    request_body = CreateTransactionRequest,
    responses(
        (status = 200, description = "Unsigned transaction created successfully", body = JsonValue),
        (status = 400, description = "Bad request", body = ApiError),
        (status = 404, description = "Account not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    params(
        ("name" = String, Path, description = "Name of the account to create transaction for"),
    )
)]
pub async fn api_create_unsigned_transaction(
    State(app_state): State<AppState>,
    Path(WalletParams { name }): Path<WalletParams>,
    Json(body): Json<CreateTransactionRequest>,
) -> Result<Json<JsonValue>, ApiError> {
    info!(
        target: "audit",
        account = &*name,
        recipient_count = body.recipients.len(),
        idempotency_key:? = body.idempotency_key;
        "API: Create unsigned transaction request"
    );

    let pool = app_state.db_pool.clone();
    let name = name.clone();
    let network = app_state.network;
    let password = app_state.password.clone();
    let default_confirmations = app_state.required_confirmations;

    let recipients: Vec<Recipient> = body
        .recipients
        .iter()
        .map(|r| Recipient {
            address: r.address.0.clone(),
            amount: r.amount,
            payment_id: r.payment_id.clone(),
        })
        .collect();

    let result = tokio::task::spawn_blocking(move || {
        let conn = pool.get().map_err(|e| ApiError::DbError(e.to_string()))?;

        let account = get_account_by_name(&conn, &name)
            .map_err(|e| ApiError::DbError(e.to_string()))?
            .ok_or_else(|| ApiError::AccountNotFound(name.clone()))?;

        let amount = recipients.iter().map(|r| r.amount).sum();
        let num_outputs = recipients.len();
        let fee_per_gram = MicroMinotari(5);
        let estimated_output_size = None;
        let seconds_to_lock_utxos = body.seconds_to_lock_utxos.unwrap_or(86400); // 24 hours

        let confirmation_window = body.confirmation_window.unwrap_or(default_confirmations);
        let lock_amount = FundLocker::new(pool.clone());
        let locked_funds = lock_amount
            .lock(
                account.id,
                amount,
                num_outputs,
                fee_per_gram,
                estimated_output_size,
                body.idempotency_key,
                seconds_to_lock_utxos,
                confirmation_window,
            )
            .map_err(|e| ApiError::FailedToLockFunds(e.to_string()))?;
        let one_sided_tx = OneSidedTransaction::new(pool, network, password);
        one_sided_tx
            .create_unsigned_transaction(&account, locked_funds, recipients, fee_per_gram)
            .map_err(|e| ApiError::FailedCreateUnsignedTx(e.to_string()))
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    Ok(Json(serde_json::to_value(result)?))
}

/// Path parameters for payref lookup.
///
/// Used to extract the payment reference from URL path segments.
#[derive(Debug, Deserialize, IntoParams, utoipa::ToSchema)]
pub struct PayrefParams {
    /// The unique name identifying the wallet account.
    name: String,
    /// The payment reference to search for.
    payref: String,
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
/// curl -X GET http://localhost:8080/accounts/default/completed_transactions/by_payref/my-payment-ref-123
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

        get_completed_transaction_by_payref(&conn, account.id, &payref)
            .map_err(|e| ApiError::DbError(e.to_string()))?
            .ok_or_else(|| ApiError::NotFound(format!("No completed transaction found with payref: {}", payref)))
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
/// curl -X GET http://localhost:8080/accounts/default/displayed_transactions/by_payref/my-payment-ref-123
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

        get_displayed_transactions_by_payref(&conn, account.id, &payref).map_err(|e| ApiError::DbError(e.to_string()))
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    Ok(Json(transactions))
}

/// Estimates transaction fees based on current network conditions.
///
/// Calculates fee estimates for Slow, Medium, and Fast priority levels by analyzing
/// the mempool state and selecting appropriate UTXOs for the requested amount.
///
/// # Path Parameters
///
/// - `name`: The account name to estimate fees for
///
/// # Request Body
///
/// See [`EstimateFeeRequest`] for the complete request schema.
///
/// # Response
///
/// Returns a list of [`FeeEstimateResponse`] objects for different priorities.
///
/// # Errors
///
/// - [`ApiError::AccountNotFound`]: The specified account does not exist
/// - [`ApiError::InternalServerError`]: Failed to query base node or calculate fees
/// - [`ApiError::DbError`]: Database connection or query failure
///
/// # Example Request
///
/// ```bash
/// curl -X POST http://localhost:8080/accounts/default/estimate_fees \
///   -H "Content-Type: application/json" \
///   -d '{"amount": 1000000}'
/// ```
#[utoipa::path(
    post,
    path = "/accounts/{name}/estimate_fees",
    request_body = EstimateFeeRequest,
    responses(
        (status = 200, description = "Fees estimated successfully", body = Vec<FeeEstimateResponse>),
        (status = 400, description = "Bad request", body = ApiError),
        (status = 404, description = "Account not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    params(
        ("name" = String, Path, description = "Name of the account to estimate fees for"),
    )
)]
pub async fn api_estimate_fees(
    State(app_state): State<AppState>,
    Path(WalletParams { name }): Path<WalletParams>,
    Json(body): Json<EstimateFeeRequest>,
) -> Result<Json<Vec<FeeEstimateResponse>>, ApiError> {
    debug!(
        account = &*name,
        amount = &*mask_amount(body.amount.0.into());
        "API: Estimate fees request"
    );

    let pool = app_state.db_pool.clone();
    let base_url = app_state.base_node_url.clone();
    let default_confirmations = app_state.required_confirmations;
    let name = name.clone();

    let estimator = FeeEstimator::new(pool, base_url);
    let confirmation_window = body.confirmation_window.unwrap_or(default_confirmations);

    let estimates = estimator
        .estimate_fees(
            &name,
            body.amount,
            body.num_outputs,
            confirmation_window,
            body.estimated_output_size,
        )
        .await
        .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

    let response: Vec<FeeEstimateResponse> = estimates
        .into_iter()
        .map(|est| FeeEstimateResponse {
            priority: match est.priority {
                FeePriority::Slow => FeePriorityResponse::Slow,
                FeePriority::Medium => FeePriorityResponse::Medium,
                FeePriority::Fast => FeePriorityResponse::Fast,
            },
            fee_per_gram: est.fee_per_gram,
            estimated_fee: est.estimated_fee,
            total_amount_required: est.total_amount_required,
            input_count: est.input_count,
        })
        .collect();

    Ok(Json(response))
}
