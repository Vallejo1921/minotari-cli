//! Background daemon mode for continuous blockchain scanning.
//!
//! This module provides the [`Daemon`] struct that orchestrates long-running wallet operations,
//! including periodic blockchain scanning, API server hosting, and background task management.
//!
//! # Features
//!
//! - **Periodic Scanning**: Automatically scans the blockchain at configurable intervals
//! - **API Server**: Runs an HTTP API server for wallet operations
//! - **Background Tasks**: Manages transaction unlocker and other periodic tasks
//! - **Graceful Shutdown**: Handles Ctrl+C signals and coordinates shutdown across all tasks
//! - **Error Recovery**: Distinguishes between fatal and intermittent errors, retrying when appropriate
//!
//! # Usage Example
//!
//! ```ignore
//! use minotari::daemon::Daemon;
//! use tari_common::configuration::Network;
//! use std::path::PathBuf;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let (token, _generated) = minotari::api::resolve_api_token(None, None)?;
//! let auth = minotari::api::ApiAuth::Required(token);
//! let daemon = Daemon::new(
//!     "password".to_string(),
//!     "https://rpc.tari.com".to_string(),
//!     PathBuf::from("wallet.db"),
//!     100,    // max_blocks per scan
//!     10,     // batch_size
//!     60,     // scan_interval_secs
//!     ApiServerConfig { bind_address: "127.0.0.1".to_string(), port: 3000, auth },
//!     Network::Esmeralda,
//! );
//!
//! daemon.run().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Architecture
//!
//! The daemon coordinates three main components:
//!
//! 1. **Scanner Loop**: Periodically scans the blockchain for new outputs
//! 2. **API Server**: Serves HTTP endpoints for wallet operations
//! 3. **Transaction Unlocker**: Automatically unlocks expired transaction locks
//!
//! All components listen for shutdown signals and terminate gracefully.

use std::{path::PathBuf, time::Duration};

use anyhow::anyhow;
use log::{error, info, warn};
use tokio::{signal, sync::broadcast, time::sleep};

use tari_common::configuration::Network;

use crate::{
    api::{self, ApiAuth},
    db,
    http::WalletHttpClient,
    scan::{self, ScanError, ScanMode},
    tasks::{burn_proof_worker::BurnProofWorker, unlocker::TransactionUnlocker},
    webhooks::{
        WebhookTriggerConfig,
        worker::{WebhookWorker, WebhookWorkerConfig},
    },
};
use zeroize::Zeroizing;

/// How the daemon's REST API is exposed.
///
/// Bundled into one struct so the bind address and the authentication that guards
/// it are always configured together - how far the API reaches and who may call it
/// are one decision, not two.
#[derive(Debug, Clone)]
pub struct ApiServerConfig {
    /// Interface to bind, e.g. `127.0.0.1` (default) or `0.0.0.0`.
    pub bind_address: String,
    /// TCP port to bind.
    pub port: u16,
    /// Token every caller must present, or [`ApiAuth::Disabled`].
    pub auth: ApiAuth,
}

impl ApiServerConfig {
    /// Socket address to bind, as `<address>:<port>`.
    ///
    /// A bare IPv6 address is wrapped in brackets, since `::1:9000` is itself a
    /// valid IPv6 address and would otherwise be parsed as one rather than as an
    /// address and a port.
    fn socket_addr(&self) -> String {
        let address = self.host();
        if address.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]:{}", address, self.port)
        } else {
            format!("{}:{}", address, self.port)
        }
    }

    /// Whether the API will be reachable from outside this host.
    ///
    /// A hostname that does not parse as an IP is treated as network-exposed:
    /// it resolves through DNS and we cannot assume it is loopback.
    fn is_network_exposed(&self) -> bool {
        match self.host().parse::<std::net::IpAddr>() {
            Ok(ip) => !ip.is_loopback(),
            Err(_) => true,
        }
    }

    /// The configured address with any surrounding IPv6 brackets removed, so
    /// `::1` and `[::1]` are treated as the same address.
    fn host(&self) -> &str {
        let address = self.bind_address.trim();
        address
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(address)
    }
}

/// Daemon for running the wallet in continuous background mode.
///
/// The daemon orchestrates multiple concurrent tasks including blockchain scanning,
/// API server hosting, and transaction management. It handles graceful shutdown
/// and error recovery for long-running operation.
pub struct Daemon {
    /// Held for the daemon's whole lifetime, so it lives in a buffer that wipes
    /// itself on shutdown rather than being left in freed heap memory.
    password: Zeroizing<String>,
    base_url: String,
    database_file: PathBuf,
    max_blocks: u64,
    batch_size: u64,
    scan_interval: Duration,
    api: ApiServerConfig,
    network: Network,
    required_confirmations: u64,
    webhook_config: WebhookWorkerConfig,
    webhook_trigger_config: Option<WebhookTriggerConfig>,
    burn_proofs_dir: PathBuf,
}

impl Daemon {
    /// Creates a new daemon instance with the specified configuration.
    ///
    /// # Parameters
    ///
    /// * `password` - Password for decrypting wallet keys
    /// * `base_url` - Base URL of the Tari RPC endpoint (e.g., "<https://rpc.tari.com>")
    /// * `database_file` - Path to the SQLite database file
    /// * `max_blocks` - Maximum number of blocks to scan per iteration
    /// * `batch_size` - Number of blocks to scan per batch
    /// * `scan_interval_secs` - Seconds to wait between scan cycles
    /// * `api` - Bind address, port and authentication for the HTTP API server
    /// * `network` - Tari network configuration (Esmeralda, Nextnet, Mainnet, etc.)
    /// * `required_confirmations` - Required confirmations
    /// * `webhook_url` - Webhook URL
    /// * `webhook_secret` - Webhook signing secret
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        password: Zeroizing<String>,
        base_url: String,
        database_file: PathBuf,
        max_blocks: u64,
        batch_size: u64,
        scan_interval_secs: u64,
        api: ApiServerConfig,
        network: Network,
        required_confirmations: u64,
        webhook_url: Option<String>,
        webhook_secret: Option<String>,
        send_only_event_types: Option<Vec<String>>,
        burn_proofs_dir: PathBuf,
    ) -> Self {
        let webhook_worker_config = WebhookWorkerConfig {
            enabled: webhook_url.is_some() && webhook_secret.is_some(),
            secret: webhook_secret.map(Zeroizing::new),
            send_only_event_types: send_only_event_types.clone(),
        };
        let webhook_trigger_config = webhook_url.map(|url| WebhookTriggerConfig {
            url,
            send_only_event_types,
        });

        Self {
            password,
            base_url,
            database_file,
            max_blocks,
            batch_size,
            scan_interval: Duration::from_secs(scan_interval_secs),
            api,
            network,
            required_confirmations,
            webhook_config: webhook_worker_config,
            webhook_trigger_config,
            burn_proofs_dir,
        }
    }

    /// Runs the daemon until a shutdown signal is received.
    ///
    /// This method starts all daemon components and blocks until Ctrl+C is pressed
    /// or a fatal error occurs. It coordinates:
    ///
    /// - Blockchain scanner loop (periodic scanning)
    /// - HTTP API server (wallet operations)
    /// - Transaction unlocker task (background cleanup)
    /// - Graceful shutdown on SIGINT (Ctrl+C)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on graceful shutdown or `Err(ScanError)` if a fatal error occurs.
    ///
    /// # Errors
    ///
    /// - `ScanError::Fatal` - Database connection failures, API binding errors, or task panics
    /// - Scanner errors are handled internally with retry logic for intermittent failures
    pub async fn run(&self) -> Result<(), ScanError> {
        info!("Daemon started. Press Ctrl+C to stop.");

        let (shutdown_tx, _) = broadcast::channel(1);

        let db_pool = db::init_db(self.database_file.clone())?;

        let unlocker = TransactionUnlocker::new(db_pool.clone());
        let unlocker_task_handle = unlocker.run(shutdown_tx.subscribe());

        let http_client = WalletHttpClient::new(
            self.base_url
                .parse()
                .map_err(|e| ScanError::Fatal(anyhow!("Invalid base URL '{}': {}", self.base_url, e)))?,
        )?;
        let burn_proof_worker =
            BurnProofWorker::new(db_pool.clone(), http_client, self.burn_proofs_dir.clone(), self.network);
        let burn_proof_handle = burn_proof_worker.run(shutdown_tx.subscribe());

        let webhook_worker = std::sync::Arc::new(WebhookWorker::new(db_pool.clone(), self.webhook_config.clone()));
        let worker_rx = shutdown_tx.subscribe();
        let webhook_handle = tokio::spawn(async move {
            webhook_worker.run(worker_rx).await;
        });

        let router = api::create_router(
            db_pool.clone(),
            self.network,
            self.password.clone(),
            self.required_confirmations,
            self.base_url.clone(),
            self.api.auth.clone(),
        );
        let addr = self.api.socket_addr();
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|e| ScanError::Fatal(anyhow!("Failed to bind API server to {}: {}", addr, e)))?;

        let authenticated = !self.api.auth.is_disabled();
        if self.api.is_network_exposed() {
            warn!(
                target: "audit",
                address = &*addr,
                authenticated = authenticated;
                "API server is bound to a non-loopback address and is reachable from the network. Ensure access is \
                 restricted (firewall or TLS-terminating reverse proxy)."
            );
        }
        if !authenticated {
            // Loud on both channels: this is the one configuration in which anyone
            // who can reach the port can drain the wallet.
            warn!(
                target: "audit",
                address = &*addr;
                "API authentication is DISABLED. Every endpoint, including burn and transaction creation, will \
                 answer any caller that can reach this address."
            );
            eprintln!(
                "WARNING: API authentication is disabled ({addr}). Anyone who can reach this address can spend from \
                 this wallet. Remove `--api-disable-auth` / `api_disable_auth` to re-enable it."
            );
        }
        info!(
            address = &*addr,
            authenticated = authenticated;
            "API server listening"
        );

        let mut shutdown_rx_api = shutdown_tx.subscribe();
        let api_server_handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    shutdown_rx_api.recv().await.ok();
                })
                .await
                .unwrap();
        });

        let shutdown_rx_scanner = shutdown_tx.subscribe();

        let shutdown_tx_clone = shutdown_tx.clone();
        let ctrlc_handle = tokio::spawn(async move {
            signal::ctrl_c().await.expect("Failed to listen for ctrl_c");
            info!("Received shutdown signal, stopping all tasks...");
            let _ = shutdown_tx_clone.send(());
            Ok::<(), ()>(())
        });

        // HttpBlockchainScanner is marked as "NOT Send", so it is not possible to launch it in a new thread.
        // #[async_trait(?Send)]
        // impl<KM> BlockchainScanner for HttpBlockchainScanner<KM>
        let scanner_res = self.scan_and_sleep_loop(shutdown_rx_scanner).await;

        if let Err(e) = scanner_res {
            if shutdown_tx.send(()).is_err() {
                error!("Failed to send shutdown signal. All tasks may not have received it.");
            }
            return Err(e);
        }

        if shutdown_tx.send(()).is_err() {
            error!("Failed to send shutdown signal. All tasks may not have received it.");
        }

        let join_res = tokio::try_join!(
            api_server_handle,
            unlocker_task_handle,
            burn_proof_handle,
            webhook_handle,
            ctrlc_handle
        )
        .map_err(|e| ScanError::Fatal(anyhow!("A task panicked during shutdown: {}", e)))?;

        let (_api_res, _unlocker_res, _burn_proof_res, _webhook_res, _ctrlc_res) = join_res;

        info!("Daemon stopped gracefully.");
        Ok(())
    }

    /// Performs a single scan cycle followed by a sleep interval.
    ///
    /// Scans up to `max_blocks` in batches of `batch_size`, then sleeps for
    /// `scan_interval` before returning. This method is called repeatedly by
    /// the scan loop.
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Scan completed successfully and sleep finished
    /// - `Err(ScanError)` - Scan failed with a fatal or intermittent error
    async fn scan_and_sleep(&self) -> Result<(), ScanError> {
        info!("Starting wallet scan...");
        let mut scanner = scan::Scanner::new(
            &self.password,
            &self.base_url,
            self.database_file.clone(),
            self.batch_size,
            self.required_confirmations,
        )
        .mode(ScanMode::Partial {
            max_blocks: self.max_blocks,
        });
        if let Some(cfg) = &self.webhook_trigger_config {
            scanner = scanner.webhook_config(cfg.clone());
        }

        let result = scanner.run().await;
        match result {
            Ok((events, _are_there_more_blocks_to_scan)) => {
                info!(event_count = events.len(); "Scan completed successfully");
            },
            Err(e) => {
                error!(error:% = e; "Scan failed");
                return Err(e);
            },
        }

        sleep(self.scan_interval).await;
        Ok(())
    }

    /// Main scanning loop that runs until shutdown or fatal error.
    ///
    /// This loop continuously calls `scan_and_sleep()` while listening for shutdown signals.
    /// It distinguishes between error types:
    ///
    /// - **Fatal errors**: Immediately propagate and trigger shutdown
    /// - **Intermittent errors**: Log and retry after the scan interval
    /// - **Timeout errors**: Log retry count and continue after interval
    ///
    /// # Parameters
    ///
    /// * `shutdown_rx` - Broadcast receiver for shutdown signals from other tasks
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Shutdown signal received, exiting gracefully
    /// - `Err(ScanError::Fatal)` - Fatal error occurred, daemon should stop
    async fn scan_and_sleep_loop(&self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<(), ScanError> {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Scanner task received shutdown signal. Exiting gracefully.");
                    break;
                }
                res = self.scan_and_sleep() => {
                    if let Err(e) = res {
                        match &e {
                            ScanError::Fatal(_) => {
                                error!(error:% = e; "A fatal error occurred during the scan cycle");
                                return Err(e);
                            },
                            ScanError::Intermittent(err_msg) => {
                                warn!(error:% = err_msg; "An intermittent error occurred during the scan cycle");
                                if self.wait_for_next_cycle(&mut shutdown_rx).await {
                                    return Ok(());
                                }
                            },
                            ScanError::DbError(err_msg) => {
                                error!(error:% = err_msg; "A DB error occurred during the scan cycle");
                                return Err(e);
                            },
                            ScanError::Timeout(retries) => {
                                warn!(retries = retries; "Scan timed out, will retry after interval");
                                if self.wait_for_next_cycle(&mut shutdown_rx).await {
                                    return Ok(());
                                }
                            },
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Sleeps for `scan_interval`, but returns `true` immediately if a shutdown signal arrives first.
    async fn wait_for_next_cycle(&self, shutdown_rx: &mut broadcast::Receiver<()>) -> bool {
        tokio::select! {
            _ = sleep(self.scan_interval) => false,
            _ = shutdown_rx.recv() => {
                info!("Scanner task received shutdown signal. Exiting gracefully.");
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(bind_address: &str) -> ApiServerConfig {
        ApiServerConfig {
            bind_address: bind_address.to_string(),
            port: 9000,
            auth: ApiAuth::Required(crate::api::ApiToken::new("daemon-test-token-0123456789").unwrap()),
        }
    }

    #[test]
    fn loopback_addresses_are_not_network_exposed() {
        assert!(!config("127.0.0.1").is_network_exposed());
        assert!(!config("127.0.0.2").is_network_exposed());
        assert!(!config("::1").is_network_exposed());
    }

    #[test]
    fn routable_and_unresolved_addresses_are_network_exposed() {
        assert!(config("0.0.0.0").is_network_exposed());
        assert!(config("192.168.1.10").is_network_exposed());
        assert!(config("::").is_network_exposed());
        // A hostname could resolve anywhere, so it is treated as exposed.
        assert!(config("wallet.internal").is_network_exposed());
    }

    #[test]
    fn socket_addr_joins_address_and_port() {
        assert_eq!(config("127.0.0.1").socket_addr(), "127.0.0.1:9000");
        assert_eq!(config("localhost").socket_addr(), "localhost:9000");
    }

    #[test]
    fn socket_addr_brackets_ipv6_addresses() {
        assert_eq!(config("::1").socket_addr(), "[::1]:9000");
        assert_eq!(config("::").socket_addr(), "[::]:9000");
        // Already bracketed input is left alone rather than double-wrapped.
        assert_eq!(config("[::1]").socket_addr(), "[::1]:9000");
    }

    #[test]
    fn socket_addr_parses_as_a_socket_address() {
        for address in ["127.0.0.1", "0.0.0.0", "::1", "::"] {
            let addr = config(address).socket_addr();
            assert!(
                addr.parse::<std::net::SocketAddr>().is_ok(),
                "{addr} should parse as a socket address"
            );
        }
    }
}
