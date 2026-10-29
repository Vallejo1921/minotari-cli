//! HTTP-based blockchain scanner implementation
//!
//! This module provides an HTTP implementation of the `BlockchainScanner` trait
//! that connects to a Tari base node via HTTP API to scan for wallet outputs.

// Native targets use reqwest
use crate::{
    BlockHeaderInfo,
    errors::{WalletError, WalletResult},
    http::models::{HttpBlockHeader, HttpTipInfoResponse, IncompleteScannedOutput, ScanningOutputStruct},
    scanning::{BlockScanResult, InProgressScan, ScanConfig, TipInfo, interface::BlockchainScanner},
};
use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use log::{debug, error, info, warn};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use reqwest::Client;
use std::{sync::RwLock, time::Duration};
use tari_common_types::types::FixedHash;
use tari_node_components::blocks::Block;
use tari_transaction_components::{
    key_manager::TransactionKeyManagerInterface,
    rpc::models::{BlockUtxoInfo, GetUtxosByBlockResponse, SyncUtxosByBlockResponseV0, SyncUtxosByBlockResponseV1},
};
use tari_utilities::hex::Hex;
use tokio::sync::mpsc;
use tokio::time::timeout;
const SYNC_UTXOS_BY_BLOCK_PAGE_LIMIT: u64 = 50;
const HTTP2_INITIAL_WINDOW_SIZE: u32 = 4 * 1024 * 1024;
const HTTP2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const HTTP2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_BACKOFF_EXPONENT: u32 = 5;
pub const MAX_BACKOFF_SECONDS: u64 = 60;

/// Largest response body the scanner will read, after decompression.
///
/// The client asks for `gzip`, so reqwest inflates the body transparently and the
/// `Content-Length` the server advertises says nothing about how much memory the
/// response will actually take. A few hundred KiB of gzip expands to gigabytes, and
/// `response.json()` / `response.text()` will happily buffer all of it until the
/// process is killed. Bodies are therefore read chunk by chunk — post-decompression
/// — and abandoned once they cross this line.
///
/// 256 MiB is far above any legitimate reply: a `sync_utxos_by_block` page is capped
/// at 50 blocks and the node chunks large blocks itself.
const MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;

/// Number of pages the scanner will accept for a single starting header before it
/// gives up on the peer.
///
/// The download loop keeps requesting the next page for as long as the node answers
/// `has_next_page: true`. Nothing else bounds it: a node that always sets the flag
/// (whether broken or hostile) keeps the wallet paging and buffering blocks forever,
/// never reaching the tip. There is a guard against the node returning the same
/// *header* twice, but none against it returning pages without end. One header covers
/// at most a few hundred blocks in practice, so this ceiling is only ever reached by
/// a peer that is not making progress.
const MAX_PAGES_PER_HEADER: u64 = 10_000;

/// Reads a response body, refusing to buffer more than [`MAX_RESPONSE_BYTES`].
///
/// Bodies arrive already decompressed (the client negotiates `gzip`), so the cap is
/// on the inflated size — which is the size that actually costs memory and the one an
/// attacker controls independently of the bytes on the wire.
async fn read_body_capped(response: reqwest::Response, what: &str) -> WalletResult<Vec<u8>> {
    let mut response = response;
    let mut body = Vec::new();

    loop {
        let chunk = response.chunk().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Failed to read {what} response body: {e}"
            )))
        })?;
        let Some(chunk) = chunk else { break };

        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(WalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "{what} response body exceeds the {MAX_RESPONSE_BYTES} byte limit"
                )),
            ));
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

/// Reads a response body under the size cap and decodes it as UTF-8, lossily.
///
/// Used for diagnostics (error bodies) and for the small JSON replies parsed with
/// `serde_json::from_str`.
async fn read_body_text_capped(response: reqwest::Response, what: &str) -> WalletResult<String> {
    let bytes = read_body_capped(response, what).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Best-effort read of an error response body, for logging only.
async fn read_error_body(response: reqwest::Response) -> String {
    read_body_text_capped(response, "error").await.unwrap_or_default()
}

/// HTTP client for connecting to Tari base node
#[derive(Clone)]
pub struct HttpBlockchainScanner<KM> {
    /// HTTP client for making requests (native targets)
    client: Client,
    /// Base URL for the HTTP API
    base_url: String,
    /// Request timeout (native targets only)
    timeout: Duration,
    key_managers: Vec<KM>,
    current_in_progress: InProgressScan,
    thread_count: usize,
    max_error_retries: u32,
    error_backoff_base_secs: u64,
}

impl<KM> HttpBlockchainScanner<KM>
where
    KM: TransactionKeyManagerInterface,
{
    /// Create a new HTTP scanner with the given base URL
    pub async fn new(base_url: String, key_managers: Vec<KM>, number_processing_threads: usize) -> WalletResult<Self> {
        let timeout = Duration::from_secs(30);
        let max_error_retries = 3;
        let error_backoff_base_secs = 2;
        Self::with_timeout(
            base_url,
            timeout,
            key_managers,
            number_processing_threads,
            max_error_retries,
            error_backoff_base_secs,
        )
        .await
    }

    /// Create a new HTTP scanner with custom timeout (native only)
    pub async fn with_timeout(
        base_url: String,
        timeout: Duration,
        key_managers: Vec<KM>,
        number_processing_threads: usize,
        max_error_retries: u32,
        error_backoff_base_secs: u64,
    ) -> WalletResult<Self> {
        let thread_count = if number_processing_threads > 0 {
            number_processing_threads
        } else {
            (num_cpus::get().saturating_sub(2)).max(1)
        };
        if key_managers.is_empty() {
            return Err(WalletError::ConfigurationError(
                "At least one key manager must be specified".to_string(),
            ));
        }

        let client = Client::builder()
            .http2_initial_stream_window_size(HTTP2_INITIAL_WINDOW_SIZE)
            .http2_initial_connection_window_size(HTTP2_INITIAL_WINDOW_SIZE)
            .tcp_nodelay(true)
            .http2_keep_alive_interval(HTTP2_KEEP_ALIVE_INTERVAL)
            .http2_keep_alive_timeout(HTTP2_KEEP_ALIVE_TIMEOUT)
            .http2_keep_alive_while_idle(true)
            .timeout(timeout)
            .build()
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Failed to create HTTP client: {e}"
                )))
            })?;

        // Test the connection
        let test_url = format!("{base_url}/get_tip_info");
        let response = client.get(&test_url).send().await;
        if response.is_err() {
            let body = match response {
                Ok(resp) => read_error_body(resp).await,
                Err(e) => e.to_string(),
            };
            warn!("Connection test failed, response body: {body}");
            return Err(WalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!("Failed to connect to {base_url}")),
            ));
        }

        Ok(Self {
            client,
            base_url,
            timeout,
            key_managers,
            current_in_progress: InProgressScan::new_empty(),
            thread_count,
            max_error_retries,
            error_backoff_base_secs,
        })
    }

    async fn sync_utxos_by_block(
        &self,
        start_header_hash: &str,
        limit: u64,
        page: u64,
        exclude_spent: bool,
        exclude_inputs: bool,
    ) -> WalletResult<SyncUtxosByBlockResponseV0> {
        let mut timeout_retries: u32 = 0;
        let mut error_retries: u32 = 0;

        loop {
            match timeout(
                self.timeout,
                self.sync_utxos_by_block_http_call(start_header_hash, limit, page, exclude_spent, exclude_inputs),
            )
            .await
            {
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(e)) => {
                    error_retries = error_retries.saturating_add(1);
                    let error_msg = e.to_string();
                    warn!(
                        error = &*error_msg,
                        retry = error_retries,
                        max = self.max_error_retries;
                        "Sync utxos by block scan failed"
                    );
                    if error_retries >= self.max_error_retries {
                        return Err(e);
                    }
                    let exponent = error_retries.min(MAX_BACKOFF_EXPONENT);
                    let backoff_secs = self.error_backoff_base_secs.pow(exponent).min(MAX_BACKOFF_SECONDS);
                    info!(
                        seconds = backoff_secs;
                        "Waiting before retrying..."
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                },
                Err(_) => {
                    timeout_retries = timeout_retries.saturating_add(1);
                    warn!(
                        retry = timeout_retries,
                        max = self.max_error_retries;
                        "sync  timed out"
                    );
                    if timeout_retries >= self.max_error_retries {
                        return Err(WalletError::Timeout(format!("Failed after {timeout_retries}")));
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                },
            }
        }
    }

    /// Sync UTXOs by block
    async fn sync_utxos_by_block_http_call(
        &self,
        start_header_hash: &str,
        limit: u64,
        page: u64,
        exclude_spent: bool,
        exclude_inputs: bool,
    ) -> WalletResult<SyncUtxosByBlockResponseV0> {
        let url = format!("{}/sync_utxos_by_block", self.base_url);
        let version = 1;
        let response = self
            .client
            .get(&url)
            .query(&[
                ("start_header_hash", start_header_hash),
                ("limit", &limit.to_string()),
                ("page", &page.to_string()),
                ("version", &version.to_string()),
                ("exclude_spent", &exclude_spent.to_string()),
                ("exclude_inputs", &exclude_inputs.to_string()),
            ])
            .send()
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "HTTP request failed: {e}"
                )))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = read_error_body(response).await;
            warn!("HTTP error response body: {}", body);
            return Err(WalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!("HTTP error: {status}")),
            ));
        }

        let body = read_body_capped(response, "sync_utxos_by_block").await?;
        let sync_response_v1: SyncUtxosByBlockResponseV1 = serde_json::from_slice(&body).map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Failed to parse response: {e}"
            )))
        })?;

        let sync_response = sync_response_v1.into();

        Ok(sync_response)
    }

    async fn get_utxos_by_block_http_call(&self, current_header_hash: &str) -> WalletResult<GetUtxosByBlockResponse> {
        let url = format!("{}/get_utxos_by_block", self.base_url);

        let response = self
            .client
            .get(&url)
            .query(&[("header_hash", current_header_hash)])
            .send()
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "HTTP request failed: {e}"
                )))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = read_error_body(response).await;
            warn!("HTTP error response body: {}", body);
            return Err(WalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!("HTTP error: {status}")),
            ));
        }

        let body_text = read_body_text_capped(response, "get_utxos_by_block").await?;
        let sync_response: GetUtxosByBlockResponse = serde_json::from_str(&body_text).map_err(|e| {
            warn!("Failed to parse response body: {}", body_text);
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Failed to parse response: {e}"
            )))
        })?;

        Ok(sync_response)
    }

    async fn get_utxos_by_block(&self, current_header_hash: &str) -> WalletResult<GetUtxosByBlockResponse> {
        let mut timeout_retries: u32 = 0;
        let mut error_retries: u32 = 0;

        loop {
            match timeout(self.timeout, self.get_utxos_by_block_http_call(current_header_hash)).await {
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(e)) => {
                    error_retries = error_retries.saturating_add(1);
                    let error_msg = e.to_string();
                    warn!(
                        error = &*error_msg,
                        retry = error_retries,
                        max = self.max_error_retries;
                        "get utxos by block failed"
                    );
                    if error_retries >= self.max_error_retries {
                        return Err(e);
                    }
                    let exponent = error_retries.min(MAX_BACKOFF_EXPONENT);
                    let backoff_secs = self.error_backoff_base_secs.pow(exponent).min(MAX_BACKOFF_SECONDS);
                    info!(
                        seconds = backoff_secs;
                        "Waiting before retrying..."
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                },
                Err(_) => {
                    timeout_retries = timeout_retries.saturating_add(1);
                    warn!(
                        retry = timeout_retries,
                        max = self.max_error_retries;
                        "get utxos by block timed out"
                    );
                    if timeout_retries >= self.max_error_retries {
                        return Err(WalletError::Timeout(format!("Failed after {timeout_retries}")));
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                },
            }
        }
    }

    /// Create a scan config with wallet keys for block scanning
    pub const fn create_scan_config_with_wallet_keys(
        &self,
        start_height: u64,
        end_height: Option<u64>,
    ) -> WalletResult<ScanConfig> {
        Ok(ScanConfig {
            start_height,
            end_height,
            batch_size: Some(50),
            request_timeout: self.timeout,
            exclude_spent: false,
            exclude_inputs: false,
        })
    }

    /// Scan for regular recoverable outputs using encrypted data decryption
    fn scan_for_recoverable_output(
        &self,
        output: &ScanningOutputStruct,
    ) -> WalletResult<Option<IncompleteScannedOutput>> {
        for (index, key_manager) in self.key_managers.iter().enumerate() {
            if let Some((commitment_mask, value, memo, _provenance)) = key_manager.try_output_key_recovery(
                &output.commitment,
                &output.encrypted_data,
                &output.sender_offset_public_key,
            )? {
                let output = IncompleteScannedOutput::new(output, value, commitment_mask, memo, index)?;
                return Ok(Some(output));
            }
        }
        Ok(None)
    }

    /// Fetch block range using the `sync_utxos_by_block` endpoint
    #[allow(clippy::cognitive_complexity)]
    async fn fetch_block_range(&mut self) -> WalletResult<(Vec<BlockUtxoInfo>, bool)> {
        let start_height = self.current_in_progress.get_config().map_or(0, |c| c.start_height);
        let exclude_spent = self.current_in_progress.get_config().is_some_and(|c| c.exclude_spent);
        let exclude_inputs = self.current_in_progress.get_config().is_some_and(|c| c.exclude_inputs);

        // Get the starting header hash
        let mut more_blocks = true;
        let current_header_hash = if let Some(h) = self.current_in_progress.get_header() {
            h.clone()
        } else {
            let Some(start_header) = self.get_header_by_height(start_height).await? else {
                return Err(WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Failed to get header at height {start_height}"
                    )),
                ));
            };
            let current_header_hash = start_header.hash.to_hex();
            self.current_in_progress.set_next_request(current_header_hash.clone());
            current_header_hash
        };

        let mut all_blocks = Vec::new();

        debug!("Starting fetch_block_range from height {} ", start_height);
        let limit = self
            .current_in_progress
            .get_config()
            .and_then(|c| c.batch_size)
            .unwrap_or(SYNC_UTXOS_BY_BLOCK_PAGE_LIMIT);
        let page = self.current_in_progress.page();
        // Paging is driven entirely by the node's `has_next_page` flag, so a node that
        // never clears it keeps this loop running forever. Stop asking after
        // MAX_PAGES_PER_HEADER pages against the same starting header rather than
        // paging (and buffering) without end.
        if page >= MAX_PAGES_PER_HEADER {
            self.current_in_progress.clear();
            return Err(WalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Base node returned more than {MAX_PAGES_PER_HEADER} pages for header \
                     {current_header_hash} without advancing; aborting scan"
                )),
            ));
        }
        let sync_response = self
            .sync_utxos_by_block(&current_header_hash, limit, page, exclude_spent, exclude_inputs)
            .await?;
        if sync_response.blocks.is_empty() {
            debug!("No more blocks available from base node");
            return Ok((Vec::new(), false));
        }
        let mut has_next_page = sync_response.has_next_page;
        let next_header_to_scan = sync_response.next_header_to_scan.clone();
        let blocks_to_process = sync_response.blocks.into_iter();

        // Add all blocks from this response
        for block in blocks_to_process {
            if let Some(end_height) = self.current_in_progress.get_config().and_then(|c| c.end_height)
                && block.height > end_height
            {
                debug!("Reached end height {}, stopping fetch", end_height);
                self.current_in_progress.clear();
                more_blocks = false;
                has_next_page = false;
            }
            all_blocks.push(block);
        }
        self.current_in_progress.increment_page();

        if !has_next_page && self.current_in_progress.is_active() {
            // we are done scanning this batch of blocks, we need to request the next header, and we have not
            // reached some end goal
            if next_header_to_scan.is_empty() {
                debug!("No next header to scan, ending fetch");
                more_blocks = false;
                self.current_in_progress.clear();
            } else {
                let next_header_to_scan_hex = next_header_to_scan.to_hex();
                debug!("Setting next header to scan: {}", next_header_to_scan_hex);
                // Safeguard against infinite loops if the server returns the same hash
                if next_header_to_scan_hex == self.current_in_progress.get_header().cloned().unwrap_or_default() {
                    debug!("Next header is the same as the current one, stopping to prevent infinite loop.");
                    more_blocks = false;
                    self.current_in_progress.clear();
                } else {
                    self.current_in_progress.set_next_request(next_header_to_scan_hex);
                }
            }
        }

        debug!("Fetched {} blocks for range {}", all_blocks.len(), start_height,);

        Ok((all_blocks, more_blocks))
    }

    pub fn update_scan_config(&mut self, config: &ScanConfig) -> WalletResult<()> {
        debug!(
            "String new scan, scanning from: {} to  {:?}",
            config.start_height, config.end_height
        );
        self.current_in_progress = InProgressScan::new(config.clone());
        Ok(())
    }

    pub fn clear_in_progress_scan(&mut self) {
        self.current_in_progress.clear();
    }

    async fn get_tip_info_http_call(&mut self) -> WalletResult<TipInfo> {
        let url = format!("{}/get_tip_info", self.base_url);

        // Native implementation using reqwest
        let response = self.client.get(&url).send().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "HTTP request failed: {e}"
            )))
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = read_error_body(response).await;
            warn!("HTTP error response body: {}", body);
            return Err(WalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!("HTTP error: {status}")),
            ));
        }

        let body_text = read_body_text_capped(response, "get_tip_info").await?;

        let tip_response: HttpTipInfoResponse = serde_json::from_str(&body_text).map_err(|e| {
            warn!("Failed to parse response body: {}", body_text);
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Failed to parse response: {e}"
            )))
        })?;

        Ok(TipInfo {
            best_block_height: tip_response.metadata.best_block_height,
            best_block_hash: FixedHash::try_from(tip_response.metadata.best_block_hash)
                .map_err(|e| WalletError::ConversionError(e.to_string()))?,
            accumulated_difficulty: tip_response.metadata.accumulated_difficulty,
            pruned_height: tip_response.metadata.pruned_height,
            timestamp: tip_response.metadata.timestamp,
        })
    }

    async fn get_header_by_height_http_call(&mut self, height: u64) -> WalletResult<Option<BlockHeaderInfo>> {
        use tari_utilities::epoch_time::EpochTime;

        let url = format!("{}/get_header_by_height?height={}", self.base_url, height);

        let response = self.client.get(&url).send().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "HTTP request failed: {e}"
            )))
        })?;

        if !response.status().is_success() {
            if response.status() == 404 {
                return Ok(None);
            }
            let status = response.status();
            let body = read_error_body(response).await;
            warn!("HTTP error response body: {}", body);
            return Err(WalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!("HTTP error: {status}")),
            ));
        }

        let body = read_body_text_capped(response, "get_header_by_height").await?;

        let header_response: HttpBlockHeader = serde_json::from_str(&body).map_err(|e| {
            warn!("Failed to parse response body: {}", body);
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Failed to parse response: {e}"
            )))
        })?;

        Ok(Some(BlockHeaderInfo {
            height: header_response.height,
            hash: FixedHash::try_from(header_response.hash).map_err(|e| WalletError::ConversionError(e.to_string()))?,
            timestamp: EpochTime::from(header_response.timestamp),
        }))
    }
}

#[allow(clippy::too_many_lines)]
#[async_trait]
impl<KM> BlockchainScanner for HttpBlockchainScanner<KM>
where
    KM: TransactionKeyManagerInterface,
{
    async fn scan_blocks(
        &mut self,
        config: &ScanConfig,
    ) -> WalletResult<mpsc::Receiver<WalletResult<Vec<BlockScanResult>>>> {
        if let Some(end_height) = config.end_height
            && config.start_height > end_height
        {
            return Err(WalletError::OperationNotSupported(
                "start_height cannot be greater than end_height".to_string(),
            ));
        }

        let (send_scan_result, mut rec_scan_result) = mpsc::channel(1000);
        let (send_download, rec_download) = mpsc::channel(1000);
        self.update_scan_config(config)?;
        let mut download_scanner = self.clone();
        let scan_config = config.clone();
        // Download task: fetch raw blocks and forward them to the processing task
        // via `send_scan_result` ONLY. It must never send directly to
        // `send_download`, otherwise its completion signal can overtake the
        // slower processing task's results on that shared channel and truncate
        // the scan. When this task finishes it simply drops `send_scan_result`,
        // which the processing task observes as end-of-input.
        // Both tasks stop as soon as the receiver of their output is dropped.
        tokio::spawn(async move {
            let tip_res = tokio::select! {
                tip_res = download_scanner.get_tip_info() => tip_res,
                () = send_scan_result.closed() => return,
            };
            let tip = match tip_res {
                Ok(tip) => tip,
                Err(e) => {
                    error!("Failed to get tip info: {}", e);
                    // An error, not an empty result, so the consumer does not take it as caught up.
                    let _unused = send_scan_result.send(Err(e)).await;
                    return;
                },
            };
            if scan_config.start_height > tip.best_block_height {
                debug!(
                    "Tip height {} is less than requested start height {}, returning empty results",
                    tip.best_block_height, scan_config.start_height
                );
                // Nothing to fetch: dropping `send_scan_result` lets the
                // processing task emit the terminal empty batch in order.
                return;
            }
            loop {
                let fetch_res = tokio::select! {
                    fetch_res = download_scanner.fetch_block_range() => fetch_res,
                    () = send_scan_result.closed() => return,
                };
                let more_blocks = match fetch_res {
                    Ok((http_blocks, more_blocks)) => {
                        if let Err(e) = send_scan_result.send(Ok(http_blocks)).await {
                            error!("Failed to send download result with error: {}", e);
                            return;
                        };
                        more_blocks
                    },
                    Err(e) => {
                        // Route the error through the processing task so it is
                        // ordered after any results already in flight.
                        let _unused = send_scan_result.send(Err(e)).await.inspect_err(|e| {
                            error!("Failed to send download result with error: {}", e);
                        });
                        return;
                    },
                };

                if !more_blocks {
                    break;
                }
            }
            debug!("Finished downloading blocks");
            // Drop `send_scan_result` (by returning) to signal end-of-input to
            // the processing task, which emits the terminal empty batch.
        });
        let thread_count = self.thread_count;
        let processing_scanner = self.clone();
        tokio::spawn(async move {
            let processing_pool = match rayon::ThreadPoolBuilder::new()
                .num_threads(thread_count)
                .build()
                .map_err(|e| WalletError::ConfigurationError(format!("Failed to build thread pool: {e}")))
            {
                Ok(pool) => pool,
                Err(e) => {
                    let _unused = send_download.send(Err(e)).await.inspect_err(|e| {
                        error!("Failed to send download result with error: {}", e);
                    });
                    return;
                },
            };
            loop {
                let http_blocks_res = tokio::select! {
                    http_blocks_res = rec_scan_result.recv() => match http_blocks_res {
                        Some(http_blocks_res) => http_blocks_res,
                        None => break,
                    },
                    () = send_download.closed() => return,
                };
                let errors = RwLock::new(Vec::new());
                let results = RwLock::new(Vec::new());
                let http_blocks = match http_blocks_res {
                    Ok(http_blocks) => http_blocks,
                    Err(e) => {
                        let _unused = send_download.send(Err(e)).await.inspect_err(|e| {
                            error!("Failed to send download error with error: {}", e);
                        });
                        return;
                    },
                };
                let pool_scanner = processing_scanner.clone();
                processing_pool.install(|| {
                    http_blocks.into_par_iter().for_each(|http_block| {
                        let mut wallet_outputs = Vec::new();

                        let header_hash = match FixedHash::try_from(http_block.header_hash.clone()) {
                            Ok(h) => h,
                            Err(e) => {
                                errors
                                    .write()
                                    .expect("write lock should not be poisoned")
                                    .push(WalletError::ConversionError(e.to_string()));
                                return;
                            },
                        };
                        for output in &http_block.outputs {
                            let scanned_output = match output.clone().try_into() {
                                Ok(o) => o,
                                Err(e) => {
                                    errors.write().expect("write lock should not be poisoned").push(e);
                                    continue;
                                },
                            };
                            match pool_scanner.scan_for_recoverable_output(&scanned_output) {
                                Ok(Some(wallet_output)) => {
                                    wallet_outputs.push(wallet_output);
                                },
                                Ok(None) => {},
                                Err(e) => {
                                    errors.write().expect("write lock should not be poisoned").push(e);
                                },
                            }
                        }

                        results.write().expect("lock should not be poisoned").push((
                            BlockScanResult {
                                height: http_block.height,
                                block_hash: header_hash,
                                wallet_outputs: Vec::new(),
                                inputs: http_block
                                    .inputs
                                    .into_iter()
                                    .map(|i| FixedHash::try_from(i).unwrap_or_default())
                                    .collect(),
                                mined_timestamp: http_block.mined_timestamp,
                            },
                            wallet_outputs,
                        ));
                    });
                });
                let first_error = errors.read().expect("...").first().cloned();
                if let Some(e) = first_error {
                    if let Err(err) = send_download.send(Err(e)).await {
                        error!("Failed to send download error with error: {}", err);
                    };
                    return;
                }
                let results = results.into_inner().expect("Lock should not be poisoned");
                let network_results = results
                    .into_iter()
                    .map(|(mut block, wallet_outputs)| {
                        let scanner = processing_scanner.clone();
                        async move {
                            if wallet_outputs.is_empty() {
                                return Ok(block);
                            }
                            let block_response = scanner.get_utxos_by_block(&block.block_hash.to_hex()).await?;
                            for output in &wallet_outputs {
                                if let Some(index) = block_response
                                    .outputs
                                    .iter()
                                    .position(|o| *o.encrypted_data() == output.encrypted_data)
                                {
                                    let tx_output =
                                        block_response.outputs.get(index).expect("should exist").clone();
                                    let output_hash = output.output_hash;
                                    let final_output_optional = output.to_wallet_output(
                                        tx_output,
                                        scanner
                                            .key_managers
                                            .get(output.key_manager_index)
                                            .expect("should exist"),
                                    )?;
                                    if let Some(final_output) = final_output_optional {
                                        block.wallet_outputs.push((
                                            output_hash,
                                            final_output,
                                            output.key_manager_index,
                                        ))
                                    }
                                }
                            }
                            Ok(block)
                        }
                    })
                    .collect::<FuturesUnordered<_>>()  // concurrent, not sequential
                    .collect::<Vec<_>>();
                let network_results = tokio::select! {
                    network_results = network_results => network_results,
                    () = send_download.closed() => return,
                };
                let mut final_results = Vec::new();
                for r in network_results {
                    match r {
                        Ok(block_result) => final_results.push(block_result),
                        Err(e) => {
                            send_download.send(Err(e)).await.ok();
                            return;
                        },
                    }
                }

                final_results.sort_by_key(|a| a.height);

                debug!(
                    "HTTP batch completed, found {} blocks with wallet outputs",
                    final_results.len(),
                );
                let _unused = send_download.send(Ok(final_results)).await.inspect_err(|e| {
                    error!("Failed to send download error with error: {}", e);
                });
            }
            // All fetched batches have been processed and forwarded. Emit the
            // terminal empty batch now, from the same task that sends results,
            // so the consumer only sees "end of stream" AFTER every real block.
            let _unused = send_download.send(Ok(Vec::new())).await.inspect_err(|e| {
                error!("Failed to send terminal download result with error: {}", e);
            });
            debug!("HTTP scan completed");
        });

        Ok(rec_download)
    }

    async fn get_tip_info(&mut self) -> WalletResult<TipInfo> {
        let mut timeout_retries: u32 = 0;
        let mut error_retries: u32 = 0;

        loop {
            match timeout(self.timeout, self.get_tip_info_http_call()).await {
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(e)) => {
                    error_retries = error_retries.saturating_add(1);
                    let error_msg = e.to_string();
                    warn!(
                        error = &*error_msg,
                        retry = error_retries,
                        max = self.max_error_retries;
                        "get tip failed"
                    );
                    if error_retries >= self.max_error_retries {
                        return Err(e);
                    }
                    let exponent = error_retries.min(MAX_BACKOFF_EXPONENT);
                    let backoff_secs = self.error_backoff_base_secs.pow(exponent).min(MAX_BACKOFF_SECONDS);
                    info!(
                        seconds = backoff_secs;
                        "Waiting before retrying..."
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                },
                Err(_) => {
                    timeout_retries = timeout_retries.saturating_add(1);
                    warn!(
                        retry = timeout_retries,
                        max = self.max_error_retries;
                        "get tip timed out"
                    );
                    if timeout_retries >= self.max_error_retries {
                        return Err(WalletError::Timeout(format!("Failed after {timeout_retries}")));
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                },
            }
        }
    }

    async fn get_blocks_by_heights(&mut self, heights: Vec<u64>) -> WalletResult<Vec<Block>> {
        let mut blocks = Vec::new();

        for height in heights {
            if let Some(block) = self.get_block_by_height(height).await? {
                blocks.push(block);
            }
        }

        Ok(blocks)
    }

    async fn get_block_by_height(&mut self, _height: u64) -> WalletResult<Option<Block>> {
        // method does not exit
        Ok(None)
    }

    async fn get_header_by_height(&mut self, height: u64) -> WalletResult<Option<BlockHeaderInfo>> {
        let mut timeout_retries: u32 = 0;
        let mut error_retries: u32 = 0;

        loop {
            match timeout(self.timeout, self.get_header_by_height_http_call(height)).await {
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(e)) => {
                    error_retries = error_retries.saturating_add(1);
                    let error_msg = e.to_string();
                    warn!(
                        error = &*error_msg,
                        retry = error_retries,
                        max = self.max_error_retries;
                        "get header by height failed"
                    );
                    if error_retries >= self.max_error_retries {
                        return Err(e);
                    }
                    let exponent = error_retries.min(MAX_BACKOFF_EXPONENT);
                    let backoff_secs = self.error_backoff_base_secs.pow(exponent).min(MAX_BACKOFF_SECONDS);
                    info!(
                        seconds = backoff_secs;
                        "Waiting before retrying..."
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                },
                Err(_) => {
                    timeout_retries = timeout_retries.saturating_add(1);
                    warn!(
                        retry = timeout_retries,
                        max = self.max_error_retries;
                        "get header by height timed out"
                    );
                    if timeout_retries >= self.max_error_retries {
                        return Err(WalletError::Timeout(format!("Failed after {timeout_retries}")));
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                },
            }
        }
    }
}
