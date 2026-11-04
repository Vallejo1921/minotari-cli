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
/// use minotari_wallet_core::http::HttpError;
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
    #[error("Request failed: {}", error_text(.0))]
    RequestFailed(reqwest::Error),

    /// An error occurred in the HTTP middleware layer.
    ///
    /// The middleware handles retry logic and other cross-cutting concerns.
    /// This error may indicate that all retry attempts have been exhausted.
    #[error("Middleware error: {}", error_text(.0))]
    MiddlewareError(reqwest_middleware::Error),

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

    /// The node sent more bytes than this endpoint allows.
    #[error("Node response body exceeds the {limit} byte limit")]
    ResponseTooLarge { limit: usize },
}

// The reqwest error is stored without its URL and is not exposed as a
// `source()`, so chain printing (`{:#}`) cannot show the query string either.
impl From<reqwest::Error> for HttpError {
    fn from(error: reqwest::Error) -> Self {
        HttpError::RequestFailed(error.without_url())
    }
}

impl From<reqwest_middleware::Error> for HttpError {
    fn from(error: reqwest_middleware::Error) -> Self {
        match error {
            reqwest_middleware::Error::Reqwest(error) => {
                HttpError::MiddlewareError(reqwest_middleware::Error::Reqwest(error.without_url()))
            },
            other => HttpError::MiddlewareError(other),
        }
    }
}

/// The error and its causes (connection refused, timeout, ...) as one sanitised
/// line without URLs. The causes are shown here because the error is not
/// exposed as a `source()`.
fn error_text(error: &(dyn std::error::Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(error) = cause {
        text.push_str(": ");
        text.push_str(&error.to_string());
        cause = error.source();
    }
    without_url(&text)
}

/// Sanitised error text without the ` for url (...)` reqwest adds: request
/// query strings carry kernel signatures and commitments.
fn without_url(text: &str) -> String {
    let mut text = text.to_string();
    while let Some(start) = text.find(" for url (") {
        let end = text[start..]
            .find(')')
            .map_or(text.len(), |close| start.saturating_add(close).saturating_add(1));
        text.replace_range(start..end, "");
    }
    crate::log::sanitize_node_text(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_failed_request_shows_its_cause_but_not_its_url() {
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("client");
        let error = client
            .get("http://127.0.0.1:1/transactions?excess_sig_sig=abcd")
            .send()
            .await
            .expect_err("nothing listens on port 1");
        let text = HttpError::from(error).to_string();
        assert!(
            text.starts_with("Request failed: error sending request: "),
            "got: {text}"
        );
        assert!(
            text.len() > "Request failed: error sending request: ".len(),
            "the cause is shown: {text}"
        );
        assert!(!text.contains("abcd") && !text.contains("127.0.0.1"), "got: {text}");
    }

    #[test]
    fn error_text_loses_the_request_url() {
        let text = "error sending request for url (http://node/transactions?excess_sig_sig=abcd): timed out";
        assert_eq!(without_url(text), "error sending request: timed out");
    }
}
