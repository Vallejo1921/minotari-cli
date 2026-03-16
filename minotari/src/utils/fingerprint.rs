use tari_crypto::{hash_domain, hashing::DomainSeparatedHasher};
use tari_transaction_components::key_manager::wallet_types::{KeyDigest, WalletType};
use tari_utilities::ByteArray;

hash_domain!(KeyManagerDomain, "com.tari.base_layer.key_manager", 1);

pub const WALLET_FINGERPRINT_LABEL: &str = "wallet_identity_fingerprint";

/// Generates a deterministic, unique fingerprint for this wallet.
/// This is used to prevent duplicate entries in the database.
pub fn calculate_fingerprint(wallet_type: &WalletType) -> Vec<u8> {
    let public_spend = wallet_type.get_public_spend_key();
    let public_view = wallet_type.get_public_view_key();

    // If it's a Ledger, the account index makes it a unique "wallet"
    // even if the root keys are the same.
    let account_index = wallet_type.get_ledger_details().map(|l| l.account).unwrap_or(0);

    let hash = DomainSeparatedHasher::<KeyDigest, KeyManagerDomain>::new_with_label(WALLET_FINGERPRINT_LABEL)
        .chain(public_spend.as_bytes())
        .chain(public_view.as_bytes())
        .chain(account_index.to_le_bytes())
        .finalize();

    hash.as_ref().to_vec()
}
