//! Balance, address, scan status, and version endpoint handlers.

use axum::{
    Json,
    extract::{Path, State},
};
use log::{debug, info, trace};
use serde::Deserialize;

use crate::{
    api::{
        AppState,
        error::ApiError,
        types::{AddressResponse, AddressWithPaymentIdResponse, ScanStatusResponse, VersionResponse},
    },
    db::{AccountBalance, get_account_by_name, get_balance, get_latest_scanned_block_with_timestamp},
};

use super::params::WalletParams;

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
    trace!(
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
    trace!(
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
/// curl -X POST http://127.0.0.1:9000/accounts/default/address_with_payment_id \
///   -H "Authorization: Bearer $MINOTARI_API_TOKEN" \
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

    info!(target: "audit", "API: Create address with payment ID request");
    trace!(
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
    trace!(
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
