//! Low-level HTTP client with retry logic and latency tracking.
//!
//! This module provides the internal [`HttpClient`] struct that handles
//! the actual HTTP communication. It is not exposed publicly; use
//! [`WalletHttpClient`](super::WalletHttpClient) for high-level operations.

use std::time::{Duration, Instant};

use log::debug;
use reqwest::Method;
use serde::de::DeserializeOwned;
use tokio::sync::RwLock;
use url::Url;

use super::error::HttpError;

/// Default request timeout in seconds.
///
/// Requests that do not complete within this duration will fail.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Default maximum number of retry attempts for transient failures.
///
/// The client uses exponential backoff between retries.
const DEFAULT_MAX_RETRIES: u32 = 3;

/// Low-level HTTP client for Tari base node communication.
///
/// This struct wraps a `reqwest` client with middleware for automatic retries
/// using exponential backoff. It also tracks the latency of the most recent
/// request for monitoring purposes.
///
/// # Thread Safety
///
/// `HttpClient` is safe to share across threads. The latency tracking uses
/// an async `RwLock` to allow concurrent reads while ensuring safe updates.
///
/// # Retry Behavior
///
/// Transient failures (network timeouts, 5xx errors) are automatically retried
/// using exponential backoff. The default configuration allows up to 3 retries.
/// Non-transient errors (4xx responses, parse errors) are not retried.
pub(crate) struct HttpClient {
    /// The base URL for all requests (e.g., `http://localhost:18142`).
    base_url: Url,
    /// The underlying HTTP client with retry middleware.
    client: reqwest_middleware::ClientWithMiddleware,
    /// Tracks the most recent request latency and when it was recorded.
    last_latency: RwLock<Option<(Duration, Instant)>>,
}

impl HttpClient {
    /// Creates a new HTTP client with default configuration.
    ///
    /// Uses the default timeout of 30 seconds and 3 maximum retries.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL for the Tari base node RPC endpoint
    ///
    /// # Returns
    ///
    /// Returns a configured `HttpClient` instance, or an error if the
    /// underlying HTTP client could not be initialized.
    ///
    /// # Errors
    ///
    /// Returns an error if the reqwest client fails to build (e.g., due to
    /// TLS backend initialization failure).
    pub fn new(base_url: Url) -> Result<Self, anyhow::Error> {
        Self::with_config(base_url, DEFAULT_MAX_RETRIES, Duration::from_secs(DEFAULT_TIMEOUT_SECS))
    }

    /// Creates a new HTTP client with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL for the Tari base node RPC endpoint
    /// * `max_retries` - Maximum number of retry attempts for transient failures.
    ///   Set to 0 to disable retries.
    /// * `timeout` - Maximum duration to wait for a response before timing out
    ///
    /// # Returns
    ///
    /// Returns a configured `HttpClient` instance, or an error if the
    /// underlying HTTP client could not be initialized.
    ///
    /// # Errors
    ///
    /// Returns an error if the reqwest client fails to build.
    pub fn with_config(base_url: Url, max_retries: u32, timeout: Duration) -> Result<Self, anyhow::Error> {
        let retry_policy = reqwest_retry::policies::ExponentialBackoff::builder().build_with_max_retries(max_retries);

        let inner_client = reqwest::Client::builder().timeout(timeout).build()?;

        let client = reqwest_middleware::ClientBuilder::new(inner_client)
            .with(reqwest_retry::RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        Ok(Self {
            base_url,
            client,
            last_latency: RwLock::new(None),
        })
    }

    /// Returns a reference to the base URL.
    ///
    /// This can be used to inspect or display the server address.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Sends an HTTP request and deserializes the JSON response.
    ///
    /// This method handles the full request lifecycle:
    /// 1. Constructs the full URL by joining the base URL with the path
    /// 2. Builds the request with the appropriate method and body
    /// 3. Sends the request (with automatic retries for transient failures)
    /// 4. Records the request latency
    /// 5. Validates the response status
    /// 6. Deserializes the response body as JSON
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to deserialize the response into. Must implement
    ///   [`DeserializeOwned`].
    ///
    /// # Arguments
    ///
    /// * `method` - The HTTP method (GET or POST)
    /// * `path` - The URL path to append to the base URL (e.g., `/get_tip_info`)
    /// * `body` - Optional JSON body for POST requests
    ///
    /// # Returns
    ///
    /// Returns the deserialized response on success.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError`] in the following cases:
    /// - [`HttpError::UrlError`] - Invalid path that cannot be joined with base URL
    /// - [`HttpError::UnsupportedMethod`] - Method other than GET or POST
    /// - [`HttpError::JsonError`] - Failed to serialize body or deserialize response
    /// - [`HttpError::RequestFailed`] - Network error during request
    /// - [`HttpError::MiddlewareError`] - Retry middleware error
    /// - [`HttpError::ServerError`] - Server returned non-success status code
    pub async fn send_request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T, HttpError> {
        let start = Instant::now();
        let url = self.base_url.join(path)?;

        debug!(
            method = method.as_str(),
            url:% = url;
            "HTTP: Sending request"
        );

        let req = match method {
            Method::GET => self.client.get(url),
            Method::POST => {
                let req = self.client.post(url);
                if let Some(body) = body {
                    req.body(serde_json::to_string(&body)?)
                        .header("Content-Type", "application/json")
                } else {
                    req
                }
            },
            _ => return Err(HttpError::UnsupportedMethod),
        };

        let resp = req.send().await?;
        let latency = start.elapsed();
        self.update_latency(latency).await;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read response body".into());
            return Err(HttpError::ServerError { status, body });
        }

        Ok(resp.json().await?)
    }

    /// Updates the stored latency measurement.
    ///
    /// Called internally after each successful request to track response times.
    async fn update_latency(&self, duration: Duration) {
        debug!(
            latency:? = duration;
            "HTTP: Request completed"
        );
        *self.last_latency.write().await = Some((duration, Instant::now()));
    }

    /// Returns the latency of the most recent request.
    ///
    /// This can be used for monitoring and diagnostics to track
    /// the responsiveness of the base node.
    ///
    /// # Returns
    ///
    /// Returns `Some(duration)` if a request has been made, or `None` if
    /// no requests have been sent yet.
    pub async fn get_latency(&self) -> Option<Duration> {
        self.last_latency.read().await.map(|(d, _)| d)
    }
}
