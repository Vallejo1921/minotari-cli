//! Error types for HTTP client operations.
//!
//! This module defines the [`HttpError`] enum which encompasses all possible
//! failure modes when communicating with Tari base node RPC endpoints.

use thiserror::Error;

/// Errors that can occur during HTTP client operations.
///
/// This enum provides specific error variants for different failure modes,
/// enabling callers to handle errors appropriately based on their type.
/// All variants implement [`std::error::Error`] and [`std::fmt::Display`]
/// through the `thiserror` derive macro.
///
/// # Error Categories
///
/// - **Network errors**: [`RequestFailed`](HttpError::RequestFailed),
///   [`MiddlewareError`](HttpError::MiddlewareError)
/// - **Server errors**: [`ServerError`](HttpError::ServerError)
/// - **Client errors**: [`UrlError`](HttpError::UrlError),
///   [`UnsupportedMethod`](HttpError::UnsupportedMethod),
///   [`JsonError`](HttpError::JsonError)
///
/// # Example
///
/// ```rust,no_run
/// use minotari::http::HttpError;
///
/// fn handle_error(err: HttpError) {
///     match err {
///         HttpError::ServerError { status, body } => {
///             eprintln!("Server returned {}: {}", status, body);
///         }
///         HttpError::RequestFailed(e) => {
///             eprintln!("Network error: {}", e);
///         }
///         _ => eprintln!("Other error: {}", err),
///     }
/// }
/// ```
#[derive(Debug, Error)]
pub enum HttpError {
    /// The HTTP request failed due to a network or connection error.
    ///
    /// This typically indicates connectivity issues such as:
    /// - Connection refused (server not running)
    /// - Connection timeout
    /// - DNS resolution failure
    /// - TLS/SSL handshake errors
    // The underlying errors can quote what the node sent (a response body, a
    // fragment of malformed JSON), so their text is sanitised when shown.
    #[error("Request failed: {}", crate::log::sanitize_node_text(&.0.to_string()))]
    RequestFailed(#[from] reqwest::Error),

    /// An error occurred in the HTTP middleware layer.
    ///
    /// The middleware handles retry logic and other cross-cutting concerns.
    /// This error may indicate that all retry attempts have been exhausted.
    #[error("Middleware error: {}", crate::log::sanitize_node_text(&.0.to_string()))]
    MiddlewareError(#[from] reqwest_middleware::Error),

    /// The server returned a non-success HTTP status code.
    ///
    /// Contains both the HTTP status code and the response body for debugging.
    /// Common scenarios include:
    /// - `400 Bad Request`: Malformed request or invalid parameters
    /// - `404 Not Found`: Unknown RPC method or endpoint
    /// - `500 Internal Server Error`: Server-side processing error
    #[error("Server error {status}: {}", crate::log::sanitize_node_text(body))]
    ServerError {
        /// The HTTP status code returned by the server.
        status: reqwest::StatusCode,
        /// The response body, which may contain error details.
        body: String,
    },

    /// Failed to parse or construct a URL.
    ///
    /// This error occurs when joining the base URL with a path produces
    /// an invalid URL, or when the base URL itself is malformed.
    #[error("URL parse error: {0}")]
    UrlError(#[from] url::ParseError),

    /// The requested HTTP method is not supported.
    ///
    /// Currently, only `GET` and `POST` methods are supported.
    /// Attempting to use other methods (PUT, DELETE, PATCH, etc.)
    /// will result in this error.
    #[error("Unsupported HTTP method")]
    UnsupportedMethod,

    /// Failed to serialize or deserialize JSON data.
    ///
    /// This error can occur during:
    /// - Serializing the request body to JSON
    /// - Deserializing the response body from JSON
    ///
    /// Common causes include schema mismatches between the client
    /// and server or malformed JSON in the response.
    #[error("JSON serialization error: {}", crate::log::sanitize_node_text(&.0.to_string()))]
    JsonError(#[from] serde_json::Error),
}
