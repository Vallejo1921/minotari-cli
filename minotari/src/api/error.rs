//! API error types and HTTP response conversion.
//!
//! This module defines the error types used throughout the REST API layer.
//! All errors implement [`IntoResponse`] for automatic conversion to HTTP
//! responses with appropriate status codes and JSON error bodies.
//!
//! # Error Response Format
//!
//! All API errors return a JSON response with the following structure:
//!
//! ```json
//! {
//!   "error": "Human-readable error message"
//! }
//! ```
//!
//! # HTTP Status Codes
//!
//! | Error Type | HTTP Status |
//! |------------|-------------|
//! | [`ApiError::InternalServerError`] | 500 Internal Server Error |
//! | [`ApiError::DbError`] | 500 Internal Server Error |
//! | [`ApiError::AccountNotFound`] | 404 Not Found |
//! | [`ApiError::FailedToLockFunds`] | 500 Internal Server Error |
//! | [`ApiError::FailedCreateUnsignedTx`] | 500 Internal Server Error |
//!
//! # Example
//!
//! ```rust,ignore
//! use crate::api::error::ApiError;
//!
//! fn get_account(name: &str) -> Result<Account, ApiError> {
//!     find_account(name)
//!         .ok_or_else(|| ApiError::AccountNotFound(name.to_string()))
//! }
//! ```

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use log::{error, warn};
use serde_json::json;
use thiserror::Error;
use utoipa::ToSchema;

use crate::db::WalletDbError;

/// Represents all possible errors returned by the REST API.
///
/// Each variant corresponds to a specific error condition that can occur
/// during API request processing. The error type automatically converts
/// to an appropriate HTTP response with a JSON error body.
///
/// # Error Handling Pattern
///
/// API handlers typically use the `?` operator with this error type:
///
/// ```rust,ignore
/// pub async fn handler() -> Result<Json<Data>, ApiError> {
///     let data = fetch_data().await?; // Errors automatically convert to ApiError
///     Ok(Json(data))
/// }
/// ```
///
/// # Serialization
///
/// When serialized to JSON for API responses, errors produce:
///
/// ```json
/// {
///   "error": "Error message here"
/// }
/// ```
#[derive(Debug, Error, ToSchema)]
pub enum ApiError {
    /// A general internal server error with a descriptive message.
    ///
    /// Used for unexpected errors that don't fit other categories.
    /// Returns HTTP 500 Internal Server Error.
    #[error("Internal server error: {0}")]
    #[allow(dead_code)]
    InternalServerError(String),

    /// A database operation failed.
    ///
    /// This includes connection failures, query errors, and constraint
    /// violations. Returns HTTP 500 Internal Server Error.
    ///
    /// # Example Causes
    ///
    /// - Database connection pool exhausted
    /// - SQL query syntax error
    /// - Foreign key constraint violation
    #[error("Database error: {0}")]
    DbError(String),

    /// The requested account was not found.
    ///
    /// The contained string is the account name that was not found.
    /// Returns HTTP 404 Not Found.
    ///
    /// # Example
    ///
    /// ```json
    /// {
    ///   "error": "Account 'nonexistent' not found"
    /// }
    /// ```
    #[error("Account not found: {0}")]
    AccountNotFound(String),

    /// A requested resource was not found.
    ///
    /// Used for generic not found errors beyond just accounts.
    /// Returns HTTP 404 Not Found.
    ///
    /// # Example
    ///
    /// ```json
    /// {
    ///   "error": "No blocks have been scanned yet"
    /// }
    /// ```
    #[error("{0}")]
    NotFound(String),

    /// A bad request error for invalid input.
    ///
    /// Used when the client sends invalid data in the request.
    /// Returns HTTP 400 Bad Request.
    ///
    /// # Example
    ///
    /// ```json
    /// {
    ///   "error": "Invalid hex in payment_id_hex: Invalid character"
    /// }
    /// ```
    #[error("{0}")]
    BadRequest(String),

    /// Failed to lock funds for a transaction.
    ///
    /// This typically occurs when there are insufficient available funds
    /// or when UTXO selection fails. Returns HTTP 500 Internal Server Error.
    ///
    /// # Common Causes
    ///
    /// - Insufficient balance in the account
    /// - All UTXOs are already locked by other pending transactions
    /// - UTXO selection algorithm could not find suitable inputs
    #[error("Failed to lock funds: {0}")]
    FailedToLockFunds(String),

    /// Failed to create an unsigned transaction.
    ///
    /// This occurs during transaction construction after funds have been
    /// locked. Returns HTTP 500 Internal Server Error.
    ///
    /// # Common Causes
    ///
    /// - Invalid recipient address format
    /// - Transaction size exceeds limits
    /// - Cryptographic operation failure
    #[error("Failed to create an unsigned transaction: {0}")]
    FailedCreateUnsignedTx(String),
}

/// Converts database errors into API errors.
///
/// All database errors are wrapped as [`ApiError::DbError`] with the
/// original error message preserved for debugging purposes.
impl From<WalletDbError> for ApiError {
    fn from(err: WalletDbError) -> Self {
        ApiError::DbError(err.to_string())
    }
}

/// Converts JSON serialization errors into API errors.
///
/// JSON errors typically occur during response serialization and are
/// wrapped as [`ApiError::InternalServerError`].
///
/// # Example
///
/// ```rust,ignore
/// let json = serde_json::to_value(data)?; // Converts to ApiError on failure
/// ```
impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        ApiError::InternalServerError(format!("JSON serialization error: {}", err))
    }
}

/// Converts API errors into HTTP responses.
///
/// This implementation allows [`ApiError`] to be used directly as the error
/// type in Axum handler return types. Each error variant maps to an
/// appropriate HTTP status code and produces a JSON response body.
///
/// # Response Format
///
/// All errors produce a JSON response with the following structure:
///
/// ```json
/// {
///   "error": "Human-readable error description"
/// }
/// ```
///
/// # Status Code Mapping
///
/// | Error Variant | HTTP Status Code |
/// |---------------|------------------|
/// | `InternalServerError` | 500 |
/// | `DbError` | 500 |
/// | `AccountNotFound` | 404 |
/// | `NotFound` | 404 |
/// | `BadRequest` | 400 |
/// | `FailedToLockFunds` | 500 |
/// | `FailedCreateUnsignedTx` | 500 |
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            ApiError::InternalServerError(msg) => {
                error!(error = msg.as_str(); "API: Internal Server Error");
                (StatusCode::INTERNAL_SERVER_ERROR, msg.clone())
            },
            ApiError::DbError(e) => {
                error!(error = e.as_str(); "API: Database Error");
                (StatusCode::INTERNAL_SERVER_ERROR, e.clone())
            },
            ApiError::AccountNotFound(name) => {
                warn!(account = name.as_str(); "API: Account Not Found");
                (StatusCode::NOT_FOUND, format!("Account '{}' not found", name))
            },
            ApiError::NotFound(msg) => {
                warn!(message = msg.as_str(); "API: Not Found");
                (StatusCode::NOT_FOUND, msg.clone())
            },
            ApiError::BadRequest(msg) => {
                warn!(message = msg.as_str(); "API: Bad Request");
                (StatusCode::BAD_REQUEST, msg.clone())
            },
            ApiError::FailedToLockFunds(e) => {
                error!(target: "audit", error = e.as_str(); "API: Failed to lock funds");
                (StatusCode::INTERNAL_SERVER_ERROR, e.clone())
            },
            ApiError::FailedCreateUnsignedTx(e) => {
                error!(target: "audit", error = e.as_str(); "API: Failed to create unsigned transaction");
                (StatusCode::INTERNAL_SERVER_ERROR, e.clone())
            },
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}
