//   Copyright 2022. The Tari Project
//
//   Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
//   following conditions are met:
//
//   1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
//   disclaimer.
//
//   2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
//   following disclaimer in the documentation and/or other materials provided with the distribution.
//
//   3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
//   products derived from this software without specific prior written permission.
//
//   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//   INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//   WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
//   USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Base Node Process Management for Integration Testing
//!
//! This module spawns and manages actual Tari base node processes for integration testing.
//! Based on the tari/integration_tests implementation.
use std::path::Path;
use std::{
    convert::TryInto,
    fmt::{Debug, Formatter},
    net::TcpListener,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use minotari_app_utilities::identity_management::save_as_json;
use minotari_node::{BaseNodeConfig, GrpcMethod, MetricsConfig, run_base_node};
use minotari_node_grpc_client::BaseNodeGrpcClient;
use rand::Rng; // Add Rng trait for gen_range
use rand::rngs::OsRng;
use tari_common::{
    MAX_GRPC_MESSAGE_SIZE,
    configuration::{CommonConfig, MultiaddrList},
    network_check::set_network_if_choice_valid,
};
use tari_common_sqlite::connection::DbConnectionUrl;
use tari_common_types::tari_address::TariAddress;
use tari_comms::{NodeIdentity, multiaddr::Multiaddr, peer_manager::PeerFeatures};
use tari_comms_dht::DhtConfig;
use tari_p2p::{Network, PeerSeedsConfig, TransportType, auto_update::AutoUpdateConfig};
use tari_shutdown::Shutdown;
use tokio::task;
use tonic::transport::Channel;

/// A running base node process
#[derive(Clone)]
pub struct BaseNodeProcess {
    pub name: String,
    pub port: u64,
    pub grpc_port: u64,
    pub http_port: u64,
    pub identity: NodeIdentity,
    pub temp_dir_path: PathBuf,
    pub is_seed_node: bool,
    pub config: BaseNodeConfig,
    pub kill_signal: Shutdown,
}

impl Drop for BaseNodeProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

impl Debug for BaseNodeProcess {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BaseNodeProcess")
            .field("name", &self.name)
            .field("port", &self.port)
            .field("grpc_port", &self.grpc_port)
            .field("http_port", &self.http_port)
            .field("identity", &self.identity)
            .field("temp_dir_path", &self.temp_dir_path)
            .field("is_seed_node", &self.is_seed_node)
            .finish()
    }
}

impl BaseNodeProcess {
    /// Get a GRPC client to this base node
    pub async fn get_grpc_client(&self) -> anyhow::Result<BaseNodeGrpcClient<Channel>> {
        Ok(
            BaseNodeGrpcClient::connect(format!("http://127.0.0.1:{}", self.grpc_port))
                .await?
                .max_encoding_message_size(MAX_GRPC_MESSAGE_SIZE)
                .max_decoding_message_size(MAX_GRPC_MESSAGE_SIZE),
        )
    }

    /// Get the current chain tip height
    pub async fn get_tip_height(&self) -> anyhow::Result<u64> {
        let mut client = self.get_grpc_client().await?;
        let tip_info = client.get_tip_info(minotari_node_grpc_client::grpc::Empty {}).await?;
        Ok(tip_info.into_inner().metadata.unwrap().best_block_height)
    }

    /// Mine blocks on this node using SHA3 mining
    pub async fn mine_blocks(&self, num_blocks: u64, wallet_payment_address: &TariAddress) -> anyhow::Result<()> {
        use minotari_app_grpc::tari_rpc::{
            GetNewBlockWithCoinbasesRequest, NewBlockCoinbase, NewBlockTemplateRequest, PowAlgo, pow_algo::PowAlgos,
        };

        let mut client = self.get_grpc_client().await?;

        for _ in 0..num_blocks {
            // Get new block template
            let template_req = NewBlockTemplateRequest {
                algo: Some(PowAlgo {
                    pow_algo: PowAlgos::Sha3x.into(),
                }),
                max_weight: 0,
            };
            let template_response = client.get_new_block_template(template_req).await.unwrap().into_inner();
            let block_template = template_response.new_block_template.clone().unwrap();
            let miner_data = template_response.miner_data.unwrap();
            let amount = miner_data.reward + miner_data.total_fees;
            let request = GetNewBlockWithCoinbasesRequest {
                new_template: Some(block_template),
                coinbases: vec![NewBlockCoinbase {
                    address: wallet_payment_address.to_base58(),
                    value: amount,
                    stealth_payment: false,
                    revealed_value_proof: true,
                    coinbase_extra: Vec::new(),
                }],
            };
            let new_block = client.get_new_block_with_coinbases(request).await.unwrap().into_inner();

            let new_block = new_block.block.unwrap();

            match client.submit_block(new_block).await {
                Ok(_) => (),
                Err(e) => panic!("The block should have been valid, {e}"),
            }
        }

        Ok(())
    }

    /// Wait for this node to reach a specific height
    pub async fn wait_for_height(&self, height: u64, timeout_secs: u64) -> anyhow::Result<()> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        loop {
            let current_height = self.get_tip_height().await?;
            if current_height >= height {
                return Ok(());
            }

            if start.elapsed() > timeout {
                anyhow::bail!(
                    "Timeout waiting for height {}, current height: {}",
                    height,
                    current_height
                );
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Kill the base node process
    pub fn kill(&mut self) {
        self.kill_signal.trigger();

        // Wait for ports to be released
        loop {
            if TcpListener::bind(("127.0.0.1", self.port.try_into().unwrap())).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        loop {
            if TcpListener::bind(("127.0.0.1", self.grpc_port.try_into().unwrap())).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Spawn a base node with default configuration
pub async fn spawn_base_node(
    temp_base_dir: &Path,
    assigned_ports: &mut indexmap::IndexMap<u64, u64>,
    base_nodes: &mut indexmap::IndexMap<String, BaseNodeProcess>,
    is_seed_node: bool,
    bn_name: String,
    seed_node_names: Vec<String>,
) -> BaseNodeProcess {
    spawn_base_node_with_config(
        temp_base_dir,
        assigned_ports,
        base_nodes,
        is_seed_node,
        bn_name,
        seed_node_names,
        BaseNodeConfig::default(),
    )
    .await
}

/// Spawn a base node with custom configuration
#[allow(clippy::too_many_lines)]
pub async fn spawn_base_node_with_config(
    temp_base_dir: &Path,
    assigned_ports: &mut indexmap::IndexMap<u64, u64>,
    base_nodes: &mut indexmap::IndexMap<String, BaseNodeProcess>,
    is_seed_node: bool,
    bn_name: String,
    seed_node_names: Vec<String>,
    mut base_node_config: BaseNodeConfig,
) -> BaseNodeProcess {
    unsafe {
        std::env::set_var("TARI_NETWORK", "localnet");
    }
    set_network_if_choice_valid(Network::LocalNet).unwrap();

    let port: u64;
    let grpc_port: u64;
    let http_port: u64;
    let temp_dir_path: PathBuf;
    let base_node_identity: NodeIdentity;

    if let Some(node_ps) = base_nodes.get(&bn_name) {
        port = node_ps.port;
        grpc_port = node_ps.grpc_port;
        http_port = node_ps.http_port;
        temp_dir_path = node_ps.temp_dir_path.clone();
        base_node_config = node_ps.config.clone();
        base_node_identity = node_ps.identity.clone();
    } else {
        // Each spawned base node will use different ports
        port = get_port(assigned_ports, 18000..18499).unwrap();
        grpc_port = get_port(assigned_ports, 18500..18999).unwrap();
        http_port = get_port(assigned_ports, 19000..19499).unwrap();

        // Create a new temporary directory
        temp_dir_path = temp_base_dir
            .join("base_nodes")
            .join(format!("{}_grpc_port_{}", bn_name.clone(), grpc_port));

        let base_node_address = Multiaddr::from_str(&format!("/ip4/127.0.0.1/tcp/{port}")).unwrap();
        base_node_identity = NodeIdentity::random(&mut OsRng, base_node_address, PeerFeatures::COMMUNICATION_NODE);
        save_as_json(temp_dir_path.join("base_node.json"), &base_node_identity).unwrap();
    };

    println!("Base node identity: {base_node_identity}");
    let identity = base_node_identity.clone();

    let shutdown = Shutdown::new();
    let process = BaseNodeProcess {
        name: bn_name.clone(),
        port,
        grpc_port,
        http_port,
        identity,
        temp_dir_path: temp_dir_path.clone(),
        is_seed_node,
        config: base_node_config.clone(),
        kill_signal: shutdown.clone(),
    };

    let name_cloned = bn_name.clone();

    // Get peer addresses from seed nodes
    let peer_addresses: Vec<String> = seed_node_names
        .iter()
        .filter_map(|peer_name| {
            base_nodes
                .get(peer_name)
                .map(|node| node.identity.to_peer().to_short_string())
        })
        .collect();

    let mut common_config = CommonConfig::default();
    common_config.base_path = temp_dir_path.clone();

    task::spawn(async move {
        let mut base_node_config = minotari_node::ApplicationConfig {
            common: common_config,
            auto_update: AutoUpdateConfig::default(),
            base_node: base_node_config,
            metrics: MetricsConfig::default(),
            peer_seeds: PeerSeedsConfig {
                peer_seeds: peer_addresses.into(),
                dns_seeds_use_dnssec: false,
                ..Default::default()
            },
        };

        println!("Using base_node temp_dir: {}", temp_dir_path.clone().display());
        base_node_config.base_node.network = Network::LocalNet;
        base_node_config.base_node.grpc_enabled = true;
        base_node_config.base_node.grpc_address = Some(format!("/ip4/127.0.0.1/tcp/{grpc_port}").parse().unwrap());
        base_node_config.base_node.report_grpc_error = true;
        base_node_config.base_node.metadata_auto_ping_interval = Duration::from_secs(3);
        base_node_config.base_node.http_wallet_query_service.port = http_port.try_into().unwrap();
        base_node_config.base_node.http_wallet_query_service.listen_ip = Some("127.0.0.1".to_string().parse().unwrap());
        base_node_config.base_node.http_wallet_query_service.external_address =
            Some(format!("http://127.0.0.1:{http_port}").parse().unwrap());

        base_node_config.base_node.data_dir = temp_dir_path.to_path_buf();
        base_node_config.base_node.identity_file = PathBuf::from("base_node_id.json");
        base_node_config.base_node.tor_identity_file = PathBuf::from("base_node_tor_id.json");
        base_node_config.base_node.max_randomx_vms = 1;

        base_node_config.base_node.lmdb_path = temp_dir_path.to_path_buf();
        base_node_config.base_node.p2p.transport.transport_type = TransportType::Tcp;
        base_node_config.base_node.p2p.transport.tcp.listener_address =
            format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();
        base_node_config.base_node.p2p.public_addresses = MultiaddrList::from(vec![
            base_node_config.base_node.p2p.transport.tcp.listener_address.clone(),
        ]);
        base_node_config.base_node.p2p.allow_test_addresses = true;
        base_node_config.base_node.p2p.dht = DhtConfig::default_local_test();
        base_node_config.base_node.p2p.dht.database_url = DbConnectionUrl::file(format!("{port}-dht.sqlite"));
        base_node_config.base_node.p2p.dht.network_discovery.enabled = true;
        base_node_config
            .base_node
            .p2p
            .dht
            .network_discovery
            .max_seed_peer_sync_count = 1;
        base_node_config
            .base_node
            .p2p
            .dht
            .network_discovery
            .seed_peer_min_initial_sync_peers_needed = 1;
        base_node_config
            .base_node
            .p2p
            .dht
            .network_discovery
            .min_successful_seed_contacts_for_early_exit = 1;
        base_node_config.base_node.p2p.dht.network_discovery.bootstrap_timeout = Duration::from_secs(5);
        base_node_config.base_node.p2p.dht.connectivity.update_interval = Duration::from_secs(2);
        base_node_config
            .base_node
            .p2p
            .dht
            .connectivity
            .random_pool_refresh_interval = Duration::from_secs(2);
        base_node_config.base_node.storage.orphan_storage_capacity = 10;
        if base_node_config.base_node.storage.pruning_horizon != 0 {
            base_node_config.base_node.storage.pruning_interval = 1;
        };
        base_node_config.base_node.grpc_server_allow_methods = GrpcMethod::ALL_VARIANTS.to_vec().into();

        // Hierarchically set the base path for all configs
        base_node_config.base_node.set_base_path(temp_dir_path.clone());

        base_node_config
            .base_node
            .state_machine
            .blocks_behind_before_considered_lagging = 1;
        base_node_config.base_node.state_machine.time_before_considered_lagging = Duration::from_secs(3);
        base_node_config.base_node.state_machine.initial_sync_peer_count = 1;
        base_node_config
            .base_node
            .state_machine
            .blockchain_sync_config
            .num_initial_sync_rounds_seed_bootstrap = 1;

        println!(
            "Initializing base node: name={name_cloned}; port={port}; grpc_port={grpc_port}; \
             is_seed_node={is_seed_node}, http_port={http_port}"
        );

        let result = run_base_node(shutdown, Arc::new(base_node_identity), Arc::new(base_node_config)).await;
        if let Err(e) = result {
            eprintln!("Base node error: {e:?}");
        }
    });

    // Wait for services to start
    wait_for_service(http_port).await;
    wait_for_service(port).await;
    wait_for_service(grpc_port).await;

    process
}

/// Get an available port from a range
fn get_port(assigned_ports: &mut indexmap::IndexMap<u64, u64>, range: std::ops::Range<u16>) -> Option<u64> {
    let min = range.clone().min().expect("A minimum possible port number");
    let max = range.max().expect("A maximum possible port number");

    loop {
        let port = loop {
            let port = rand::thread_rng().gen_range(min..max);
            if !assigned_ports.contains_key(&u64::from(port)) {
                break port;
            }
        };

        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            assigned_ports.insert(u64::from(port), u64::from(port));
            return Some(u64::from(port));
        }
    }
}

/// Wait for a service to start on the given port
async fn wait_for_service(port: u64) {
    // The idea is that if the port is taken it means the service is running.
    // If the port is not taken the service hasn't come up yet
    let max_tries = 4 * 60;
    let mut attempts = 0;

    loop {
        if TcpListener::bind(("127.0.0.1", u16::try_from(port).unwrap())).is_err() {
            return;
        }

        if attempts >= max_tries {
            panic!("Service on port {port} never started");
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
        attempts += 1;
    }
}
