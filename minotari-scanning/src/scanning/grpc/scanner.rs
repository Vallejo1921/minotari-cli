//! GRPC-based blockchain scanner implementation
//!
//! This module provides a GRPC implementation of the `BlockchainScanner` trait
//! that connects to a Tari base node via GRPC to scan for wallet outputs.
//!
//! ## Wallet Key Integration
//!
//! The GRPC scanner supports wallet key integration for identifying outputs that belong
//! to a specific wallet.

use std::{sync::RwLock, time::Duration};

use crate::{
    BlockHeaderInfo,
    errors::{WalletError, WalletResult},
    scanning::{BlockScanResult, InProgressScan, ScanConfig, TipInfo, interface::BlockchainScanner},
};
use async_trait::async_trait;
use minotari_app_grpc::tari_rpc;
use primitive_types::U512;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use tari_common_types::types::FixedHash;
use tari_node_components::blocks::Block;
use tari_transaction_components::{
    key_manager::TransactionKeyManagerInterface,
    transaction_components::{TransactionInput, TransactionKernel, TransactionOutput, WalletOutput},
};
use tokio::sync::mpsc;
use tonic::{Request, transport::Channel};
use tracing::debug;
use tracing::log::error;

/// Hard upper bound on the number of block heights requested in a single `get_blocks` call.
///
/// The scan range is derived from the tip height claimed by the base node, which is untrusted. A
/// node claiming a tip near `u64::MAX` would otherwise make us build a height vector of that size,
/// which aborts the process (allocation failure is not unwindable).
const MAX_HEIGHTS_PER_REQUEST: u64 = 1000;

/// Number of heights requested per `get_blocks` call when the scan config does not specify one.
const DEFAULT_HEIGHTS_PER_REQUEST: u64 = 100;

/// Widest `accumulated_difficulty` we can represent, in bytes.
///
/// The field arrives as an unbounded protobuf `bytes` value and `U512::from_big_endian` asserts
/// that the slice fits in 64 bytes, so an over-long value from an untrusted base node would panic
/// the scanner instead of surfacing as an error.
const MAX_ACCUMULATED_DIFFICULTY_BYTES: usize = 64;

/// Number of heights to request per `get_blocks` call for the given configured batch size.
fn heights_per_request(batch_size: Option<u64>) -> u64 {
    match batch_size {
        Some(size) if size > 0 => size.min(MAX_HEIGHTS_PER_REQUEST),
        _ => DEFAULT_HEIGHTS_PER_REQUEST,
    }
}

/// Inclusive end height of the chunk starting at `chunk_start`, never exceeding `end_height`.
fn chunk_end_height(chunk_start: u64, end_height: u64, heights_per_request: u64) -> u64 {
    chunk_start
        .saturating_add(heights_per_request.saturating_sub(1))
        .min(end_height)
}

/// Decimal representation of a big-endian `accumulated_difficulty` reported by a base node.
///
/// Leading zero bytes carry no magnitude and are stripped before the width check, so a padded but
/// otherwise representable value is still accepted. Anything wider than
/// [`MAX_ACCUMULATED_DIFFICULTY_BYTES`] is rejected rather than passed to `U512::from_big_endian`,
/// which would panic on it.
fn parse_accumulated_difficulty(bytes: &[u8]) -> WalletResult<String> {
    let significant = bytes
        .iter()
        .position(|byte| *byte != 0)
        .and_then(|first| bytes.get(first..))
        .unwrap_or_default();

    if significant.len() > MAX_ACCUMULATED_DIFFICULTY_BYTES {
        return Err(WalletError::ScanningError(
            crate::errors::ScanningError::ScanDataCorruption(format!(
                "Accumulated difficulty is {} bytes wide, the maximum is {MAX_ACCUMULATED_DIFFICULTY_BYTES}",
                significant.len()
            )),
        ));
    }

    Ok(U512::from_big_endian(significant).to_string())
}

/// GRPC client for connecting to Tari base node
#[derive(Clone)]
pub struct GrpcBlockchainScanner<KM> {
    /// GRPC channel to the base node
    client: tari_rpc::base_node_client::BaseNodeClient<Channel>,
    /// Connection timeout
    timeout: Duration,
    /// key manager used for the keys
    pub key_managers: Vec<KM>,
    current_in_progress: InProgressScan,
    number_processing_threads: usize,
}

impl<KM> GrpcBlockchainScanner<KM>
where
    KM: TransactionKeyManagerInterface,
{
    /// Create a new GRPC scanner with the given base URL
    pub async fn new(base_url: String, key_managers: Vec<KM>, number_processing_threads: usize) -> WalletResult<Self> {
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
        let timeout = Duration::from_secs(30);
        let channel = Channel::from_shared(base_url.clone())
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Invalid URL: {e}"
                )))
            })?
            .timeout(timeout)
            .connect()
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Connection failed: {e}"
                )))
            })?;

        // Set message size limits on the client to handle large blocks (16MB should be sufficient)
        let client = tari_rpc::base_node_client::BaseNodeClient::new(channel)
            .max_decoding_message_size(16 * 1024 * 1024) // 16MB
            .max_encoding_message_size(16 * 1024 * 1024); // 16MB

        Ok(Self {
            client,
            timeout,
            key_managers,
            current_in_progress: InProgressScan::new_empty(),
            number_processing_threads: thread_count,
        })
    }

    /// Create a new GRPC scanner with custom timeout
    pub async fn with_timeout(
        base_url: String,
        timeout: Duration,
        key_managers: Vec<KM>,
        number_processing_threads: usize,
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

        let channel = Channel::from_shared(base_url.clone())
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Invalid URL: {e}"
                )))
            })?
            .timeout(timeout)
            .connect()
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Connection failed: {e}"
                )))
            })?;

        // Set message size limits on the client to handle large blocks (16MB should be sufficient)
        let client = tari_rpc::base_node_client::BaseNodeClient::new(channel)
            .max_decoding_message_size(16 * 1024 * 1024) // 16MB
            .max_encoding_message_size(16 * 1024 * 1024); // 16MB

        Ok(Self {
            client,
            timeout,
            key_managers,
            current_in_progress: InProgressScan::new_empty(),
            number_processing_threads: thread_count,
        })
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
            batch_size: Some(100),
            request_timeout: self.timeout,
            exclude_spent: false,
            exclude_inputs: false,
        })
    }

    /// Scan for regular recoverable outputs using encrypted data decryption
    pub fn scan_for_recoverable_output(
        &self,
        output: &TransactionOutput,
    ) -> WalletResult<Option<(WalletOutput, usize)>> {
        for (index, key_manager) in self.key_managers.iter().enumerate() {
            if let Some((commitment_mask, value, memo, _provenance)) = key_manager.try_output_key_recovery(
                &output.commitment,
                &output.encrypted_data,
                &output.sender_offset_public_key,
            )? {
                return WalletOutput::new_imported(value, commitment_mask, memo, output.clone(), key_manager)
                    .map_or_else(|_| Ok(None), |wallet_output| Ok(Some((wallet_output, index))));
            }
        }
        Ok(None)
    }

    /// Get all outputs from a specific block
    pub async fn get_outputs_from_block(&mut self, block_height: u64) -> WalletResult<Vec<TransactionOutput>> {
        // Get the block at the specified height
        let request = tari_rpc::GetBlocksRequest {
            heights: vec![block_height],
        };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        if let Some(grpc_block) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Stream error: {e}"
            )))
        })? && let Some(block) = grpc_block.block
        {
            let tari_block: Block = block.try_into()?;
            return Ok(tari_block.dissolve().2);
        }

        Ok(Vec::new())
    }

    /// Get all inputs from a specific block
    pub async fn get_inputs_from_block(&mut self, block_height: u64) -> WalletResult<Vec<TransactionInput>> {
        // Get the block at the specified height
        let request = tari_rpc::GetBlocksRequest {
            heights: vec![block_height],
        };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        if let Some(grpc_block) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Stream error: {e}"
            )))
        })? && let Some(block) = grpc_block.block
        {
            let tari_block: Block = block.try_into()?;
            return Ok(tari_block.dissolve().1);
        }

        Ok(Vec::new())
    }

    /// Get all kernels from a specific block
    pub async fn get_kernels_from_block(&mut self, block_height: u64) -> WalletResult<Vec<TransactionKernel>> {
        // Get the block at the specified height
        let request = tari_rpc::GetBlocksRequest {
            heights: vec![block_height],
        };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        if let Some(grpc_block) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Stream error: {e}"
            )))
        })? && let Some(block) = grpc_block.block
        {
            let tari_block: Block = block.try_into()?;
            return Ok(tari_block.dissolve().3);
        }

        Ok(Vec::new())
    }

    /// Get complete block data including outputs, inputs, and kernels
    pub async fn get_complete_block_data(&mut self, block_height: u64) -> WalletResult<Option<Block>> {
        // Get the block at the specified height
        let request = tari_rpc::GetBlocksRequest {
            heights: vec![block_height],
        };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        if let Some(grpc_block) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Stream error: {e}"
            )))
        })? && let Some(block) = grpc_block.block
        {
            let tari_block: Block = block.try_into()?;
            return Ok(Some(tari_block));
        }

        Ok(None)
    }

    /// Scan a single block for wallet outputs using the provided entropy
    pub async fn scan_block(&mut self, block_height: u64) -> WalletResult<Vec<(WalletOutput, usize)>> {
        let mut wallet_outputs = Vec::new();

        // Get all outputs from the block
        let outputs = self.get_outputs_from_block(block_height).await?;

        if outputs.is_empty() {
            return Ok(wallet_outputs);
        }

        // Process each output
        for output in &outputs {
            if let Some(found_wallet_outputs) = self.scan_for_recoverable_output(output)? {
                wallet_outputs.push(found_wallet_outputs);
            }
        }

        Ok(wallet_outputs)
    }

    /// Get blocks by their heights in a batch
    pub async fn get_blocks_by_heights(&mut self, heights: Vec<u64>) -> WalletResult<Vec<Block>> {
        if heights.is_empty() {
            return Ok(Vec::new());
        }

        let request = tari_rpc::GetBlocksRequest { heights };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        let mut blocks = Vec::new();
        while let Some(grpc_block) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "GRPC stream error: {e}"
            )))
        })? {
            if let Some(block) = grpc_block.block {
                let tari_block: Block = block.try_into()?;
                blocks.push(tari_block);
            }
        }

        Ok(blocks)
    }

    /// Request the blocks in the inclusive height range `chunk_start..=chunk_end` and return the
    /// response stream.
    ///
    /// The caller is responsible for keeping the range bounded, see [`MAX_HEIGHTS_PER_REQUEST`].
    async fn open_blocks_stream(
        client: &mut tari_rpc::base_node_client::BaseNodeClient<Channel>,
        chunk_start: u64,
        chunk_end: u64,
    ) -> WalletResult<tonic::Streaming<tari_rpc::HistoricalBlock>> {
        debug!("Requesting blocks {} to {} from the base node", chunk_start, chunk_end);
        let heights: Vec<u64> = (chunk_start..=chunk_end).collect();
        let request = tari_rpc::GetBlocksRequest { heights };
        let stream = client
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();
        Ok(stream)
    }

    /// Convert GRPC tip info to lightweight tip info
    fn convert_tip_info(grpc_tip: &tari_rpc::TipInfoResponse) -> WalletResult<TipInfo> {
        let metadata = grpc_tip.metadata.as_ref();

        let accumulated_difficulty = match metadata {
            Some(m) => parse_accumulated_difficulty(&m.accumulated_difficulty)?,
            None => String::new(),
        };

        Ok(TipInfo {
            best_block_height: metadata.map_or(0, |m| m.best_block_height),
            best_block_hash: FixedHash::try_from(metadata.map(|m| m.best_block_hash.clone()).unwrap_or_default())
                .unwrap_or_default(),
            accumulated_difficulty,
            pruned_height: metadata.map_or(0, |m| m.pruned_height),
            timestamp: metadata.map_or(0, |m| m.timestamp),
        })
    }

    pub async fn update_scan_config(&mut self, config: &ScanConfig) -> WalletResult<()> {
        debug!(
            "String new scan, scanning from: {} to  {:?}",
            config.start_height, config.end_height
        );
        if let Some(end_height) = config.end_height {
            let tip_info = self.get_tip_info().await?;
            if end_height > tip_info.best_block_height {
                debug!(
                    "End height is higher than current tip height, will only scan to tip {:?}",
                    tip_info.best_block_height
                );
            }
            let adjusted_config = ScanConfig {
                start_height: config.start_height,
                end_height: None,
                batch_size: config.batch_size,
                request_timeout: config.request_timeout,
                exclude_spent: config.exclude_spent,
                exclude_inputs: config.exclude_inputs,
            };
            self.current_in_progress = InProgressScan::new(adjusted_config);
            return Ok(());
        }
        self.current_in_progress = InProgressScan::new(config.clone());
        Ok(())
    }

    pub fn clear_in_progress_scan(&mut self) {
        self.current_in_progress.clear();
    }
}

#[allow(clippy::too_many_lines)]
#[async_trait]
impl<KM> BlockchainScanner for GrpcBlockchainScanner<KM>
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

        let (send_scan_result, rec_scan_result) = mpsc::channel(1000);
        self.update_scan_config(config).await?;
        let download_scanner = self.clone();
        let tip_info = self.get_tip_info().await?;
        let end_height = std::cmp::min(
            config.end_height.unwrap_or(tip_info.best_block_height),
            tip_info.best_block_height,
        );
        if config.start_height > end_height {
            debug!(
                "Nothing to scan, start height {} is beyond the end height {}",
                config.start_height, end_height
            );
            return Ok(rec_scan_result);
        }
        // `end_height` is bounded by the tip height claimed by the base node, which is untrusted and
        // can be arbitrarily large. Request the range in fixed size chunks so that the vector of
        // heights sent to the node always stays small, regardless of what the node claims.
        let heights_per_request = heights_per_request(config.batch_size);
        let mut chunk_end = chunk_end_height(config.start_height, end_height, heights_per_request);
        let mut client = self.client.clone();
        let mut stream = Self::open_blocks_stream(&mut client, config.start_height, chunk_end).await?;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.number_processing_threads)
            .build()
            .map_err(|e| WalletError::ConfigurationError(format!("Failed to build thread pool: {e}")))?;
        let config = config.clone();
        tokio::spawn(async move {
            let mut blocks_in_chunk = 0u64;
            loop {
                let grpc_block_response = stream.message().await;
                let grpc_block = match grpc_block_response {
                    Ok(Some(block_response)) => block_response,
                    Err(e) => {
                        let _unused = send_scan_result
                            .send(Err(WalletError::GrpcError(e.to_string())))
                            .await
                            .inspect_err(|e| {
                                error!("Failed to send download result with error: {}", e);
                            });
                        return;
                    },
                    Ok(None) => {
                        // The current chunk is exhausted, continue with the next one. A chunk that
                        // returned nothing means the node cannot serve this range, so stop there
                        // instead of walking to a tip height it only claims to have.
                        if chunk_end >= end_height || blocks_in_chunk == 0 {
                            return;
                        }
                        let chunk_start = chunk_end.saturating_add(1);
                        chunk_end = chunk_end_height(chunk_start, end_height, heights_per_request);
                        blocks_in_chunk = 0;
                        stream = match Self::open_blocks_stream(&mut client, chunk_start, chunk_end).await {
                            Ok(stream) => stream,
                            Err(e) => {
                                let _unused = send_scan_result.send(Err(e)).await.inspect_err(|e| {
                                    error!("Failed to send download result with error: {}", e);
                                });
                                return;
                            },
                        };
                        continue;
                    },
                };
                blocks_in_chunk = blocks_in_chunk.saturating_add(1);
                let tari_block: Block = match grpc_block.block.map(|b| b.try_into()) {
                    Some(Ok(block)) => block,
                    Some(Err(e)) => {
                        let _unused = send_scan_result
                            .send(Err(WalletError::GrpcError(e.to_string())))
                            .await
                            .inspect_err(|e| {
                                error!("Failed to send download result with error: {}", e);
                            });
                        return;
                    },
                    None => {
                        return;
                    },
                };
                let errors = RwLock::new(Vec::new());
                let wallet_outputs = RwLock::new(Vec::new());
                pool.install(|| {
                    tari_block.body.outputs().par_iter().for_each(|output| {
                        match download_scanner.scan_for_recoverable_output(output) {
                            Ok(Some((wallet_output, index))) => {
                                wallet_outputs.write().expect("wallet_outputs lock poisoned").push((
                                    output.hash(),
                                    wallet_output,
                                    index,
                                ));
                            },
                            Ok(None) => {},
                            Err(e) => {
                                errors.write().expect("wallet_outputs lock poisoned").push(e);
                            },
                        }
                    });
                });

                let inputs = if config.exclude_inputs {
                    Vec::new()
                } else {
                    tari_block
                        .body
                        .inputs()
                        .iter()
                        .map(tari_transaction_components::transaction_components::TransactionInput::output_hash)
                        .collect()
                };

                let block_res = BlockScanResult {
                    height: tari_block.header.height,
                    block_hash: tari_block.hash(),
                    wallet_outputs: wallet_outputs.into_inner().expect("wallet_outputs lock poisoned"),
                    inputs,
                    mined_timestamp: tari_block.header.timestamp.as_u64(),
                };
                let _unused = send_scan_result.send(Ok(vec![block_res])).await.inspect_err(|e| {
                    error!("Failed to send scan error with error: {}", e);
                });
            }
        });

        Ok(rec_scan_result)
    }

    async fn get_tip_info(&mut self) -> WalletResult<TipInfo> {
        let request = Request::new(tari_rpc::Empty {});

        let response = self.client.clone().get_tip_info(request).await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "GRPC error: {e}"
            )))
        })?;

        let tip_info = response.into_inner();
        Self::convert_tip_info(&tip_info)
    }

    async fn get_blocks_by_heights(&mut self, heights: Vec<u64>) -> WalletResult<Vec<Block>> {
        if heights.is_empty() {
            return Ok(Vec::new());
        }

        let request = tari_rpc::GetBlocksRequest { heights };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        let mut blocks = Vec::new();
        while let Some(grpc_block) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "GRPC stream error: {e}"
            )))
        })? {
            if let Some(block) = grpc_block.block {
                let tari_block: Block = block.try_into()?;
                blocks.push(tari_block);
            }
        }

        Ok(blocks)
    }

    async fn get_block_by_height(&mut self, height: u64) -> WalletResult<Option<Block>> {
        let blocks = self.get_blocks_by_heights(vec![height]).await?;
        Ok(blocks.into_iter().next())
    }

    async fn get_header_by_height(&mut self, height: u64) -> WalletResult<Option<BlockHeaderInfo>> {
        let block = self.get_block_by_height(height).await?;
        if let Some(b) = block {
            Ok(Some(BlockHeaderInfo {
                height: b.header.height,
                hash: b.hash(),
                timestamp: b.header.timestamp,
            }))
        } else {
            Ok(None)
        }
    }
}

/// Builder for creating GRPC blockchain scanners
pub struct GrpcScannerBuilder<KM> {
    base_url: Option<String>,
    timeout: Option<Duration>,
    key_managers: Vec<KM>,
    number_processing_threads: usize,
}

impl<KM> Default for GrpcScannerBuilder<KM>
where
    KM: TransactionKeyManagerInterface,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<KM> GrpcScannerBuilder<KM>
where
    KM: TransactionKeyManagerInterface,
{
    /// Create a new builder
    pub const fn new() -> Self {
        Self {
            base_url: None,
            timeout: None,
            key_managers: Vec::new(),
            number_processing_threads: 8,
        }
    }

    /// Set the base URL for the GRPC connection
    #[must_use]
    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = Some(base_url);
        self
    }

    /// Set the timeout for GRPC operations
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    #[must_use]
    pub const fn with_processing_threads(mut self, number_processing_threads: usize) -> Self {
        self.number_processing_threads = number_processing_threads;
        self
    }

    /// Set the key manager for wallet key integration
    #[must_use]
    pub fn with_key_manager(mut self, key_manager: KM) -> Self {
        self.key_managers.push(key_manager);
        self
    }

    /// Build the GRPC scanner
    pub async fn build(self) -> WalletResult<GrpcBlockchainScanner<KM>> {
        let base_url = self
            .base_url
            .ok_or_else(|| WalletError::ConfigurationError("Base URL not specified".to_string()))?;

        if self.key_managers.is_empty() {
            return Err(WalletError::ConfigurationError(
                "No Key managers not specified".to_string(),
            ));
        }

        match self.timeout {
            Some(timeout) => {
                GrpcBlockchainScanner::with_timeout(
                    base_url,
                    timeout,
                    self.key_managers,
                    self.number_processing_threads,
                )
                .await
            },
            None => GrpcBlockchainScanner::new(base_url, self.key_managers, self.number_processing_threads).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_HEIGHTS_PER_REQUEST, MAX_ACCUMULATED_DIFFICULTY_BYTES, MAX_HEIGHTS_PER_REQUEST, chunk_end_height,
        heights_per_request, parse_accumulated_difficulty,
    };

    #[test]
    fn heights_per_request_uses_the_configured_batch_size() {
        assert_eq!(heights_per_request(Some(1)), 1);
        assert_eq!(heights_per_request(Some(50)), 50);
        assert_eq!(
            heights_per_request(Some(MAX_HEIGHTS_PER_REQUEST)),
            MAX_HEIGHTS_PER_REQUEST
        );
    }

    #[test]
    fn heights_per_request_falls_back_to_the_default() {
        assert_eq!(heights_per_request(None), DEFAULT_HEIGHTS_PER_REQUEST);
        assert_eq!(heights_per_request(Some(0)), DEFAULT_HEIGHTS_PER_REQUEST);
    }

    #[test]
    fn heights_per_request_is_capped() {
        assert_eq!(heights_per_request(Some(u64::MAX)), MAX_HEIGHTS_PER_REQUEST);
        assert_eq!(
            heights_per_request(Some(MAX_HEIGHTS_PER_REQUEST + 1)),
            MAX_HEIGHTS_PER_REQUEST
        );
    }

    #[test]
    fn chunk_end_height_covers_a_full_chunk() {
        assert_eq!(chunk_end_height(0, 1_000, 100), 99);
        assert_eq!(chunk_end_height(100, 1_000, 100), 199);
        assert_eq!(chunk_end_height(10, 10, 1), 10);
    }

    #[test]
    fn chunk_end_height_is_clamped_to_the_end_height() {
        assert_eq!(chunk_end_height(950, 1_000, 100), 1_000);
        assert_eq!(chunk_end_height(1_000, 1_000, 100), 1_000);
    }

    /// A base node claiming a tip near `u64::MAX` must not translate into a huge height vector.
    #[test]
    fn chunk_end_height_does_not_overflow_for_a_bogus_tip() {
        let heights_per_request = heights_per_request(Some(u64::MAX));
        let chunk_end = chunk_end_height(0, u64::MAX, heights_per_request);
        assert_eq!(chunk_end, MAX_HEIGHTS_PER_REQUEST - 1);
        assert_eq!(chunk_end_height(u64::MAX - 1, u64::MAX, heights_per_request), u64::MAX);
        assert_eq!(chunk_end_height(u64::MAX, u64::MAX, heights_per_request), u64::MAX);
    }

    /// Walking the chunks must always make progress and terminate on the end height.
    #[test]
    fn chunks_tile_the_whole_range() {
        let (start, end, per_request) = (7_u64, 1_009_u64, 100_u64);
        let mut chunk_start = start;
        let mut covered = 0_u64;
        loop {
            let chunk_end = chunk_end_height(chunk_start, end, per_request);
            assert!(chunk_end >= chunk_start);
            assert!(chunk_end - chunk_start < per_request);
            covered += chunk_end - chunk_start + 1;
            if chunk_end >= end {
                break;
            }
            chunk_start = chunk_end + 1;
        }
        assert_eq!(covered, end - start + 1);
    }

    #[test]
    fn accumulated_difficulty_is_parsed_as_big_endian() {
        assert_eq!(parse_accumulated_difficulty(&[]).unwrap(), "0");
        assert_eq!(parse_accumulated_difficulty(&[0; 64]).unwrap(), "0");
        assert_eq!(parse_accumulated_difficulty(&[1, 0]).unwrap(), "256");
        assert_eq!(parse_accumulated_difficulty(&[0, 0, 0, 1, 0]).unwrap(), "256");
        assert_eq!(
            parse_accumulated_difficulty(&[0xff; MAX_ACCUMULATED_DIFFICULTY_BYTES]).unwrap(),
            primitive_types::U512::MAX.to_string()
        );
    }

    /// An over-long value from an untrusted base node must be an error, never a panic.
    #[test]
    fn accumulated_difficulty_wider_than_a_u512_is_rejected() {
        let too_wide = vec![0xff; MAX_ACCUMULATED_DIFFICULTY_BYTES + 1];
        let err = parse_accumulated_difficulty(&too_wide).unwrap_err();
        assert!(err.to_string().contains("65 bytes wide"), "unexpected error: {err}");

        // The protobuf field is unbounded, so the oversize case is not limited to one stray byte.
        assert!(parse_accumulated_difficulty(&vec![0xff; 16 * 1024 * 1024]).is_err());
    }

    /// Zero padding is insignificant, so a padded but representable value must still be accepted.
    #[test]
    fn accumulated_difficulty_ignores_leading_zero_padding() {
        let mut padded = vec![0; 128];
        padded.extend_from_slice(&[0xff; MAX_ACCUMULATED_DIFFICULTY_BYTES]);
        assert_eq!(
            parse_accumulated_difficulty(&padded).unwrap(),
            primitive_types::U512::MAX.to_string()
        );
    }
}
