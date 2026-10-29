//! Conversions between dates, block heights and the wallet birthday.
//!
//! An account stores its birthday as days since [`BIRTHDAY_GENESIS_FROM_UNIX_EPOCH`], not as a
//! block height. The helpers here convert a date or a height to that unit.

use tari_common::configuration::Network;
use tari_common_types::seeds::cipher_seed::{BIRTHDAY_GENESIS_FROM_UNIX_EPOCH, SECONDS_PER_DAY};
use url::Url;

use crate::http::WalletHttpClient;

/// Average target time between blocks, across all proof-of-work algorithms.
pub const TARGET_BLOCK_TIME_SECS: u64 = 120;

/// Unix time of the genesis block of `network`.
pub fn genesis_timestamp(network: Network) -> u64 {
    match network {
        Network::MainNet => 1_746_511_200,                      // 2025-05-06 06:00:00 UTC
        Network::NextNet | Network::Esmeralda => 1_746_770_400, // 2025-05-09 06:00:00 UTC
        Network::StageNet | Network::Igor => 1_710_136_800,     // 2024-03-11 06:00:00 UTC
        Network::LocalNet => 1_708_408_860,                     // 2024-02-20 06:01:00 UTC
    }
}

/// Asks the base node at `base_url` for the height of the block mined at `epoch_secs`.
pub async fn height_at_time(base_url: &str, epoch_secs: u64) -> Result<u64, anyhow::Error> {
    let client = WalletHttpClient::new(Url::parse(base_url)?)?;
    client.get_height_at_time(epoch_secs).await
}

/// Estimates the height of the block mined at `epoch_secs` without asking a node.
///
/// Assumes every block took [`TARGET_BLOCK_TIME_SECS`]. Real blocks run slightly slower, so the
/// estimate drifts above the real height by a few percent over time. Before using it as a
/// restore or rescan start, subtract a margin (or ask the node with [`height_at_time`]), or
/// blocks with incoming outputs may be skipped.
pub fn estimate_height_at_time(network: Network, epoch_secs: u64) -> u64 {
    epoch_secs.saturating_sub(genesis_timestamp(network)) / TARGET_BLOCK_TIME_SECS
}

/// The account birthday (days since the birthday genesis) for a wallet created at `epoch_secs`.
pub fn birthday_from_time(epoch_secs: u64) -> u16 {
    let days = epoch_secs.saturating_sub(BIRTHDAY_GENESIS_FROM_UNIX_EPOCH) / SECONDS_PER_DAY;
    u16::try_from(days).unwrap_or(u16::MAX)
}

/// The account birthday (days since the birthday genesis) for a wallet whose first block is `height`.
///
/// The block time is estimated offline at [`TARGET_BLOCK_TIME_SECS`] per block. Real blocks have
/// mostly run slower, which makes the birthday early, but early mainnet blocks ran slightly
/// faster, so it can land up to about a day late. The scanner starts a couple of days before
/// the birthday, which absorbs that.
pub fn birthday_from_height(network: Network, height: u64) -> u16 {
    let estimated_time = genesis_timestamp(network).saturating_add(height.saturating_mul(TARGET_BLOCK_TIME_SECS));
    birthday_from_time(estimated_time)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (unix time, height reported by a mainnet node), taken from rpc.tari.com.
    const MAINNET_HEIGHTS: [(u64, u64); 3] = [
        (1_751_328_000, 40_194),  // 2025-07-01
        (1_767_225_600, 170_622), // 2026-01-01
        (1_788_220_800, 335_339), // 2026-09-01
    ];

    #[test]
    fn the_offline_estimate_is_within_five_percent_of_the_node() {
        for (time, node_height) in MAINNET_HEIGHTS {
            let estimate = estimate_height_at_time(Network::MainNet, time);
            let tolerance = node_height / 20;
            assert!(
                estimate.abs_diff(node_height) <= tolerance,
                "estimate {estimate} for {time} is more than {tolerance} from {node_height}"
            );
        }
    }

    #[test]
    fn a_time_before_genesis_estimates_height_zero() {
        assert_eq!(estimate_height_at_time(Network::MainNet, 0), 0);
        assert_eq!(
            estimate_height_at_time(Network::MainNet, genesis_timestamp(Network::MainNet)),
            0
        );
    }

    #[test]
    fn birthday_from_time_counts_whole_days_since_the_birthday_genesis() {
        assert_eq!(birthday_from_time(0), 0);
        assert_eq!(birthday_from_time(BIRTHDAY_GENESIS_FROM_UNIX_EPOCH), 0);
        assert_eq!(
            birthday_from_time(BIRTHDAY_GENESIS_FROM_UNIX_EPOCH + 10 * SECONDS_PER_DAY + 5),
            10
        );
        assert_eq!(birthday_from_time(u64::MAX), u16::MAX);
    }

    #[test]
    fn birthday_from_height_is_not_after_the_real_date_of_known_mainnet_blocks() {
        assert_eq!(
            birthday_from_height(Network::MainNet, 0),
            birthday_from_time(genesis_timestamp(Network::MainNet))
        );
        for (time, node_height) in MAINNET_HEIGHTS {
            assert!(birthday_from_height(Network::MainNet, node_height) <= birthday_from_time(time));
        }
    }
}
