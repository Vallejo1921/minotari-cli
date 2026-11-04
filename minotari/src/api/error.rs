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
use log::{error, trace, warn};
use serde_json::json;
use thiserror::Error;
use utoipa::ToSchema;

use crate::{
    db::WalletDbError,
    transactions::{
        fund_locker::{FeePerGramTooLow, InvalidLockDuration},
        idempotency::IdempotencyConflict,
    },
};

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

    /// The request conflicts with something the wallet has already recorded.
    ///
    /// Returned when an idempotency key is replayed with a different operation
    /// or a different request body, or when it belongs to a transaction that is
    /// already completed or no longer active. Returns HTTP 409 Conflict.
    ///
    /// # Example
    ///
    /// ```json
    /// {
    ///   "error": "idempotency key 'abc' was already used for a different unsigned transaction request; a key may only be retried with the exact request that created it"
    /// }
    /// ```
    #[error("{0}")]
    Conflict(String),

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

    /// Failed to build or broadcast a burn transaction.
    ///
    /// This occurs during burn transaction construction or network submission.
    /// Returns HTTP 500 Internal Server Error.
    ///
    /// # Common Causes
    ///
    /// - Insufficient balance
    /// - Invalid claim public key
    /// - Base node rejected the transaction
    #[error("Failed to burn funds: {0}")]
    FailedToBurnFunds(String),
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

impl ApiError {
    /// Converts a fund-moving failure into an API error.
    ///
    /// An [`IdempotencyConflict`] anywhere in the chain is the client replaying
    /// a key that does not belong to this request — a 409, not a 500. Routing
    /// it through `fallback` would report a server fault and invite the client
    /// to retry the very request that was just refused.
    pub fn from_transaction_error(err: anyhow::Error, fallback: impl FnOnce(String) -> ApiError) -> ApiError {
        if let Some(too_low) = err.downcast_ref::<FeePerGramTooLow>() {
            return ApiError::BadRequest(too_low.to_string());
        }
        match err.downcast::<IdempotencyConflict>() {
            Ok(conflict) => ApiError::Conflict(conflict.to_string()),
            Err(err) => fallback(err.to_string()),
        }
    }
}

/// Converts an idempotency conflict into a client error.
///
/// The key names a request the wallet has already seen and this is not it, so
/// 409 Conflict is the honest status: retrying unchanged will never succeed.
impl From<IdempotencyConflict> for ApiError {
    fn from(err: IdempotencyConflict) -> Self {
        ApiError::Conflict(err.to_string())
    }
}

/// Converts an out-of-range UTXO lock duration into a client error.
///
/// The value comes straight from the request body, so a 400 is the honest
/// status code: nothing is wrong on the server.
impl From<InvalidLockDuration> for ApiError {
    fn from(err: InvalidLockDuration) -> Self {
        ApiError::BadRequest(err.to_string())
    }
}

/// Converts a fee per gram the base node would not accept into a client error.
impl From<FeePerGramTooLow> for ApiError {
    fn from(err: FeePerGramTooLow) -> Self {
        ApiError::BadRequest(err.to_string())
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
/// | `Conflict` | 409 |
/// | `FailedToLockFunds` | 500 |
/// | `FailedCreateUnsignedTx` | 500 |
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            ApiError::InternalServerError(msg) => {
                error!("API: Internal Server Error");
                (StatusCode::INTERNAL_SERVER_ERROR, msg.clone())
            },
            ApiError::DbError(e) => {
                error!("API: Database Error");
                (StatusCode::INTERNAL_SERVER_ERROR, e.clone())
            },
            ApiError::AccountNotFound(name) => {
                warn!("API: Account Not Found");
                (StatusCode::NOT_FOUND, format!("Account '{}' not found", name))
            },
            ApiError::NotFound(msg) => {
                warn!("API: Not Found");
                (StatusCode::NOT_FOUND, msg.clone())
            },
            ApiError::BadRequest(msg) => {
                warn!("API: Bad Request");
                (StatusCode::BAD_REQUEST, msg.clone())
            },
            ApiError::Conflict(msg) => {
                warn!(target: "audit", "API: Conflict");
                (StatusCode::CONFLICT, msg.clone())
            },
            ApiError::FailedToLockFunds(e) => {
                error!(target: "audit", "API: Failed to lock funds");
                (StatusCode::INTERNAL_SERVER_ERROR, e.clone())
            },
            ApiError::FailedCreateUnsignedTx(e) => {
                error!(target: "audit", "API: Failed to create unsigned transaction");
                (StatusCode::INTERNAL_SERVER_ERROR, e.clone())
            },
            ApiError::FailedToBurnFunds(e) => {
                error!(target: "audit", "API: Failed to burn funds");
                (StatusCode::INTERNAL_SERVER_ERROR, e.clone())
            },
        };
        // Messages can name a wallet, payment reference or transaction; only the kind is logged above.
        trace!(message = error_message.as_str(); "API: Error message");

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transactions::fund_locker::validate_fee_per_gram;
    use tari_transaction_components::tari_amount::MicroMinotari;

    #[test]
    fn a_fee_per_gram_below_the_minimum_is_a_bad_request() {
        let too_low = validate_fee_per_gram(MicroMinotari(0)).expect_err("too low");
        assert!(matches!(ApiError::from(too_low), ApiError::BadRequest(_)));
        let through_a_lock = ApiError::from_transaction_error(too_low.into(), ApiError::FailedToLockFunds);
        assert!(
            matches!(through_a_lock, ApiError::BadRequest(_)),
            "got {through_a_lock:?}"
        );
    }
}
