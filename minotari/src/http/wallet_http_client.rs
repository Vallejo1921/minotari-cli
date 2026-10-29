//! High-level HTTP client for wallet-to-base-node communication.
//!
//! This module provides the [`WalletHttpClient`] struct, which is the primary
//! interface for wallets to interact with Tari base nodes via HTTP/JSON-RPC.
//!
//! # Overview
//!
//! The `WalletHttpClient` wraps the low-level HTTP client and provides
//! domain-specific methods for common wallet operations:
//!
//! - Checking node connectivity and sync status
//! - Submitting transactions to the network
//! - Querying transaction status by signature
//!
//! # Example
//!
//! ```rust,no_run
//! use url::Url;
//! use minotari::http::WalletHttpClient;
//!
//! # async fn example() -> Result<(), anyhow::Error> {
//! let client = WalletHttpClient::new(Url::parse("http://localhost:18142")?)?;
//!
//! // Check connectivity
//! if client.is_online().await {
//!     let tip = client.get_tip_info().await?;
//!     println!("Chain height: {:?}", tip.metadata.map(|m| m.best_block_height()));
//! }
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

use log::{debug, info, warn};
use reqwest::Method;
use tari_transaction_components::MicroMinotari;
use tari_transaction_components::rpc::models::{
    FeePerGramStat, GetUtxosDeletedInfoRequest, GetUtxosDeletedInfoResponse, TipInfoResponse, TxQueryResponse,
    TxSubmissionResponse,
};
use tari_transaction_components::transaction_components::Transaction;
use tari_utilities::hex::to_hex;
use url::Url;

use crate::http::utils::check_transaction_size;
use crate::http::{GetMempoolFeePerGramStatsResponse, JsonRpcResponse};

use super::http_client::HttpClient;

/// HTTP client for wallet operations against a Tari base node.
///
/// This client provides high-level methods for common wallet operations,
/// handling the details of HTTP communication, JSON-RPC protocol, and
/// error handling internally.
///
/// # Features
///
/// - **Automatic Retries**: Transient failures are automatically retried
///   with exponential backoff
/// - **Latency Tracking**: Request latencies are tracked for monitoring
/// - **Size Validation**: Transactions are validated against RPC size limits
///   before submission
///
/// # Thread Safety
///
/// `WalletHttpClient` is safe to share across threads and can be used
/// from multiple async tasks concurrently.
///
/// # Example
///
/// ```rust,no_run
/// use std::time::Duration;
/// use url::Url;
/// use minotari::http::WalletHttpClient;
///
/// # async fn example() -> Result<(), anyhow::Error> {
/// // Create with custom timeout and retry settings
/// let client = WalletHttpClient::with_config(
///     Url::parse("http://localhost:18142")?,
///     5,  // max retries
///     Duration::from_secs(60),  // timeout
/// )?;
///
/// // Check if the node is reachable and synced
/// let tip_info = client.get_tip_info().await?;
/// if tip_info.is_synced {
///     println!("Node is ready for transactions");
/// }
/// # Ok(())
/// # }
/// ```
pub struct WalletHttpClient {
    /// The underlying HTTP client that handles request/response processing.
    http_client: HttpClient,
}

impl WalletHttpClient {
    /// Creates a new wallet HTTP client with default configuration.
    ///
    /// Uses default settings of 30 second timeout and 3 retry attempts.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the Tari base node HTTP RPC endpoint
    ///   (e.g., `http://localhost:18142`)
    ///
    /// # Returns
    ///
    /// Returns a configured `WalletHttpClient` instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be initialized (e.g.,
    /// TLS backend initialization failure).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use url::Url;
    /// use minotari::http::WalletHttpClient;
    ///
    /// let client = WalletHttpClient::new(
    ///     Url::parse("http://localhost:18142").unwrap()
    /// ).unwrap();
    /// ```
    pub fn new(base_url: Url) -> Result<Self, anyhow::Error> {
        let http_client = HttpClient::new(base_url)?;
        Ok(Self { http_client })
    }

    /// Creates a new wallet HTTP client with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the Tari base node HTTP RPC endpoint
    /// * `max_retries` - Maximum number of retry attempts for transient failures.
    ///   Set to 0 to disable retries.
    /// * `timeout` - Maximum duration to wait for a response
    ///
    /// # Returns
    ///
    /// Returns a configured `WalletHttpClient` instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be initialized.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use std::time::Duration;
    /// use url::Url;
    /// use minotari::http::WalletHttpClient;
    ///
    /// // Client with longer timeout for slow connections
    /// let client = WalletHttpClient::with_config(
    ///     Url::parse("http://localhost:18142").unwrap(),
    ///     5,  // more retries
    ///     Duration::from_secs(120),  // 2 minute timeout
    /// ).unwrap();
    /// ```
    pub fn with_config(base_url: Url, max_retries: u32, timeout: Duration) -> Result<Self, anyhow::Error> {
        let http_client = HttpClient::with_config(base_url, max_retries, timeout)?;
        Ok(Self { http_client })
    }

    /// Returns the base node address as a string.
    ///
    /// This is useful for logging and displaying the configured endpoint.
    ///
    /// # Returns
    ///
    /// The base URL as a string (e.g., `"http://localhost:18142/"`).
    pub fn get_address(&self) -> String {
        self.http_client.base_url().to_string()
    }

    /// Retrieves the current blockchain tip information from the base node.
    ///
    /// This method queries the `/get_tip_info` endpoint to get information
    /// about the current state of the blockchain, including block height
    /// and synchronization status.
    ///
    /// # Returns
    ///
    /// Returns [`TipInfoResponse`] containing the chain metadata and sync status.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The node is unreachable
    /// - The request times out
    /// - The response cannot be parsed
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use url::Url;
    /// use minotari::http::WalletHttpClient;
    ///
    /// # async fn example() -> Result<(), anyhow::Error> {
    /// let client = WalletHttpClient::new(Url::parse("http://localhost:18142")?)?;
    ///
    /// let tip = client.get_tip_info().await?;
    /// if let Some(metadata) = tip.metadata {
    ///     println!("Current height: {}", metadata.best_block_height());
    ///     println!("Accumulated difficulty: {}", metadata.accumulated_difficulty());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_tip_info(&self) -> Result<TipInfoResponse, anyhow::Error> {
        debug!("HTTP: Requesting tip info from base node");
        let response = self
            .http_client
            .send_request(Method::GET, "/get_tip_info", None)
            .await?;
        Ok(response)
    }

    /// Checks if the base node is online and reachable.
    ///
    /// This is a convenience method that attempts to fetch tip info
    /// and returns `true` if successful, `false` otherwise.
    ///
    /// # Returns
    ///
    /// - `true` if the node responded successfully
    /// - `false` if the request failed for any reason
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use url::Url;
    /// use minotari::http::WalletHttpClient;
    ///
    /// # async fn example() -> Result<(), anyhow::Error> {
    /// let client = WalletHttpClient::new(Url::parse("http://localhost:18142")?)?;
    ///
    /// if client.is_online().await {
    ///     println!("Base node is reachable");
    /// } else {
    ///     println!("Cannot connect to base node");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn is_online(&self) -> bool {
        match self.get_tip_info().await {
            Ok(_) => {
                debug!("Base node is online");
                true
            },
            Err(e) => {
                warn!(
                    error:? = e;
                    "Base node is offline"
                );
                false
            },
        }
    }

    /// Returns the latency of the most recent HTTP request.
    ///
    /// This can be used to monitor the responsiveness of the base node
    /// connection and detect network issues.
    ///
    /// # Returns
    ///
    /// - `Some(duration)` - The round-trip time of the last request
    /// - `None` - No requests have been made yet
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use url::Url;
    /// use minotari::http::WalletHttpClient;
    ///
    /// # async fn example() -> Result<(), anyhow::Error> {
    /// let client = WalletHttpClient::new(Url::parse("http://localhost:18142")?)?;
    ///
    /// // Make a request first
    /// let _ = client.get_tip_info().await;
    ///
    /// // Check latency
    /// if let Some(latency) = client.get_last_request_latency().await {
    ///     println!("Last request took {:?}", latency);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_last_request_latency(&self) -> Option<Duration> {
        self.http_client.get_latency().await
    }

    /// Submits a transaction to the network via the base node.
    ///
    /// This method validates the transaction size, constructs a JSON-RPC
    /// request, and submits it to the base node's `/json_rpc` endpoint.
    ///
    /// # Arguments
    ///
    /// * `transaction` - The transaction to submit
    ///
    /// # Returns
    ///
    /// Returns [`TxSubmissionResponse`] indicating whether the transaction
    /// was accepted and the node's sync status.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The transaction exceeds the maximum size limit (~1.99 MB)
    /// - The node is unreachable
    /// - The JSON-RPC request fails
    /// - The node rejects the transaction (error message included)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use url::Url;
    /// use minotari::http::WalletHttpClient;
    /// use tari_transaction_components::transaction_components::Transaction;
    ///
    /// # async fn example(transaction: Transaction) -> Result<(), anyhow::Error> {
    /// let client = WalletHttpClient::new(Url::parse("http://localhost:18142")?)?;
    ///
    /// let result = client.submit_transaction(transaction).await?;
    /// if result.accepted {
    ///     println!("Transaction accepted!");
    /// } else {
    ///     println!("Transaction rejected: {}", result.rejection_reason);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Transaction Validation
    ///
    /// Before submission, the transaction is serialized and its size is
    /// checked against the RPC frame limit. This prevents submission of
    /// transactions that would fail due to size constraints.
    pub async fn submit_transaction(&self, transaction: Transaction) -> Result<TxSubmissionResponse, anyhow::Error> {
        info!(target: "audit", "HTTP: Submitting transaction");

        check_transaction_size(&transaction).map_err(|e| anyhow::anyhow!(e.to_string()))?;

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "method": "submit_transaction",
            "params": { "transaction": transaction }
        });

        let response: JsonRpcResponse<TxSubmissionResponse> = self
            .http_client
            .send_request(Method::POST, "/json_rpc", Some(request))
            .await?;

        match response.result {
            Some(result) => {
                info!(target: "audit", "HTTP: Transaction submitted successfully");
                Ok(result)
            },
            None => {
                let error_msg = crate::log::sanitize_node_text(response.error.as_deref().unwrap_or("Unknown error"));
                warn!(
                    target: "audit",
                    reason = &*error_msg;
                    "HTTP: Transaction submission failed"
                );
                Err(anyhow::anyhow!("Transaction submission failed: {}", error_msg))
            },
        }
    }

    /// Queries the status of a transaction by its excess signature.
    ///
    /// This method queries the `/transactions` endpoint to check whether
    /// a transaction has been mined, is in the mempool, or is unknown.
    ///
    /// # Arguments
    ///
    /// * `excess_sig_nonce` - The public nonce component of the excess signature
    /// * `excess_sig` - The signature component of the excess signature
    ///
    /// # Returns
    ///
    /// Returns [`TxQueryResponse`] containing the transaction's location
    /// and mining details if applicable.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The node is unreachable
    /// - The request times out
    /// - The response cannot be parsed
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use url::Url;
    /// use minotari::http::{WalletHttpClient};
    /// use tari_transaction_components::rpc::models::TxLocation;
    /// # async fn example() -> Result<(), anyhow::Error> {
    /// let client = WalletHttpClient::new(Url::parse("http://localhost:18142")?)?;
    ///
    /// let nonce = vec![0u8; 32];  // Example nonce bytes
    /// let sig = vec![0u8; 64];    // Example signature bytes
    ///
    /// let result = client.transaction_query(&nonce, &sig).await?;
    /// match result.location {
    ///     TxLocation::Mined => {
    ///         println!("Transaction mined at height {:?}", result.mined_height);
    ///     }
    ///     TxLocation::InMempool => {
    ///         println!("Transaction is pending in mempool");
    ///     }
    ///     TxLocation::None => {
    ///         println!("Transaction not found");
    ///     }
    ///     _ => {}
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Query Parameters
    ///
    /// The signature components are hex-encoded and passed as query
    /// parameters to the `/transactions` endpoint.
    pub async fn transaction_query(
        &self,
        excess_sig_nonce: &[u8],
        excess_sig: &[u8],
    ) -> Result<TxQueryResponse, anyhow::Error> {
        let excess_sig_nonce_hex = to_hex(excess_sig_nonce);
        let excess_sig_hex = to_hex(excess_sig);
        debug!(
            nonce = &*excess_sig_nonce_hex,
            sig = &*excess_sig_hex;
            "HTTP: Querying transaction"
        );

        let path = format!(
            "/transactions?excess_sig_nonce={}&excess_sig_sig={}",
            excess_sig_nonce_hex, excess_sig_hex
        );

        let response = self.http_client.send_request(Method::GET, &path, None).await?;

        debug!("HTTP: Transaction query successful");
        Ok(response)
    }

    pub async fn get_height_at_time(&self, epoch_time: u64) -> Result<u64, anyhow::Error> {
        debug!(
            time = epoch_time;
            "HTTP: Requesting block height at time"
        );
        let path = format!("/get_height_at_time?time={}", epoch_time);

        let response = self.http_client.send_request::<u64>(Method::GET, &path, None).await?;

        debug!("HTTP: Requesting block height successful");
        Ok(response)
    }

    /// Fetches the proof that a burn output was mined, by the burn output's commitment.
    ///
    /// Called after a burn transaction reaches sufficient confirmations to produce
    /// the [`BurnOutputProof`](tari_common_types::burn_proof::BurnOutputProof) needed for the complete burn claim
    /// proof. A pruned base node can only produce the proof within its pruning horizon.
    pub async fn get_burn_output_proof(
        &self,
        commitment: &[u8],
    ) -> Result<tari_transaction_components::rpc::models::GenerateBurnOutputProofResponse, anyhow::Error> {
        let path = format!("/generate_burn_output_proof?commitment={}", to_hex(commitment));
        let response = self.http_client.send_request(Method::GET, &path, None).await?;
        Ok(response)
    }

    pub async fn get_mempool_fee_per_gram_stats(&self, count: u64) -> Result<Vec<FeePerGramStat>, anyhow::Error> {
        debug!(
            count = count;
            "Requesting mempool fee per gram stats"
        );

        let path = format!("/get_mempool_fee_per_gram_stats?count={count}");

        let response = self
            .http_client
            .send_request::<GetMempoolFeePerGramStatsResponse>(Method::GET, &path, None)
            .await?;

        let stats: Vec<FeePerGramStat> = response
            .stats
            .into_iter()
            .map(|s| FeePerGramStat {
                order: s.order,
                min_fee_per_gram: MicroMinotari::from(s.min_fee_per_gram),
                avg_fee_per_gram: MicroMinotari::from(s.avg_fee_per_gram),
                max_fee_per_gram: MicroMinotari::from(s.max_fee_per_gram),
            })
            .collect();

        Ok(stats)
    }

    /// Queries the base node for the spent/unspent status of specific UTXOs.
    ///
    /// For each output hash, the response indicates whether the output was found on chain
    /// and whether it has been spent. Used during fast sync to verify `SpentUnconfirmed` outputs.
    pub async fn get_utxos_deleted_info(
        &self,
        output_hashes: Vec<Vec<u8>>,
    ) -> Result<GetUtxosDeletedInfoResponse, anyhow::Error> {
        debug!(
            count = output_hashes.len();
            "HTTP: Querying deleted info for UTXOs"
        );

        let request = GetUtxosDeletedInfoRequest {
            hashes: output_hashes,
            must_include_header: Vec::new(),
        };

        let body = serde_json::to_value(request)?;

        let response = self
            .http_client
            .send_request(Method::POST, "/get_utxos_deleted_info", Some(body))
            .await?;

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_common_types::types::PrivateKey;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn a_node_error_message_is_sanitised_before_it_is_used() {
        let server = MockServer::start().await;
        let forged = format!(
            "bad\n2026-10-14 INFO audit: Transaction confirmed\u{1b}[0m{}",
            "x".repeat(1_000)
        );
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": null,
                "error": forged,
                "id": "1",
            })))
            .mount(&server)
            .await;
        let client = WalletHttpClient::new(server.uri().parse().expect("url")).expect("client");
        let transaction = Transaction::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            PrivateKey::default(),
            PrivateKey::default(),
        );

        let error = client
            .submit_transaction(transaction)
            .await
            .expect_err("the node answered with an error")
            .to_string();
        assert!(!error.chars().any(char::is_control), "got: {error:?}");
        assert!(error.chars().count() < 300, "the node's text is truncated");
    }
}
