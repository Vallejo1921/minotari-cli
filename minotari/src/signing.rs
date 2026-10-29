//! Wallet message signing and verification.
//!
//! Messages are signed with the wallet's spend private key using a Schnorr signature
//! under the `WalletMessageSigningDomain` tag. The signature is serialized as
//! `"<signature_hex>|<public_nonce_hex>"` and verified against the spend public key of
//! a Tari address. The signature binds only the spend key and the message bytes.

use std::str::FromStr;

use tari_common_types::{
    seeds::{cipher_seed::CipherSeed, mnemonic::Mnemonic, seed_words::SeedWords},
    tari_address::TariAddress,
    types::{PrivateKey, UncompressedPublicKey, WalletMessageSchnorrSignature},
};
use tari_transaction_components::key_manager::{
    KeyManager, TransactionKeyManagerInterface,
    wallet_types::{SeedWordsWallet, WalletType},
};
use tari_utilities::hex::Hex;
use thiserror::Error;

use crate::db::{AccountRow, WalletDbError};

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("View-only wallets cannot sign messages")]
    ViewOnlyWallet,
    #[error("Invalid seed words: {0}")]
    InvalidSeedWords(String),
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    #[error("signature must be in '<signature_hex>|<public_nonce_hex>' format")]
    MalformedSignature,
    #[error("invalid signature component")]
    InvalidSignatureComponent,
    #[error("invalid public nonce")]
    InvalidPublicNonce,
    #[error("Signing failed: {0}")]
    KeyManager(String),
    #[error(transparent)]
    Db(#[from] WalletDbError),
}

/// Signs `message` with the account's spend key, returning `"<sig_hex>|<nonce_hex>"`.
///
/// The nonce is random, so signing the same message twice gives different (both valid)
/// signatures.
pub fn sign_message(account: &AccountRow, password: &str, message: &str) -> Result<String, SigningError> {
    let wallet = account.decrypt_wallet_type(password)?;
    if matches!(wallet, WalletType::ViewWallet(_)) {
        return Err(SigningError::ViewOnlyWallet);
    }
    let key_manager = KeyManager::new(wallet).map_err(|e| SigningError::KeyManager(e.to_string()))?;
    sign_with_key_manager(&key_manager, message)
}

/// Signs `message` with the spend key derived from space-separated `seed_words`.
pub fn sign_message_with_seed(seed_words: &str, message: &str) -> Result<String, SigningError> {
    let mnemonic = SeedWords::from_str(seed_words).map_err(|e| SigningError::InvalidSeedWords(e.to_string()))?;
    let cipher_seed =
        CipherSeed::from_mnemonic(&mnemonic, None).map_err(|e| SigningError::InvalidSeedWords(e.to_string()))?;
    let seed_wallet =
        SeedWordsWallet::construct_new(cipher_seed).map_err(|e| SigningError::InvalidSeedWords(e.to_string()))?;
    let key_manager =
        KeyManager::new(WalletType::SeedWords(seed_wallet)).map_err(|e| SigningError::KeyManager(e.to_string()))?;
    sign_with_key_manager(&key_manager, message)
}

/// Verifies a `"<sig_hex>|<nonce_hex>"` signature over `message` against the spend key
/// of `address`.
///
/// Returns `Ok(false)` for a well-formed but wrong signature, and an error for malformed
/// input (wrong number of `|` parts or undecodable hex).
///
/// A valid signature proves control of the address's spend key only, not its view key,
/// network or features. Verifiers should put a unique nonce (and the address, network or
/// purpose where relevant) inside the message to prevent replay.
pub fn verify_message(address: &TariAddress, message: &str, signature: &str) -> Result<bool, SigningError> {
    let public_key = address
        .public_spend_key()
        .to_public_key()
        .map_err(|e| SigningError::InvalidAddress(e.to_string()))?;

    // Exactly two parts: `split_once` would accept "a|b|c".
    let mut parts = signature.split('|');
    let (sig_hex, nonce_hex) = match (parts.next(), parts.next(), parts.next()) {
        (Some(sig), Some(nonce), None) => (sig, nonce),
        _ => return Err(SigningError::MalformedSignature),
    };
    let scalar = PrivateKey::from_hex(sig_hex).map_err(|_| SigningError::InvalidSignatureComponent)?;
    let nonce = UncompressedPublicKey::from_hex(nonce_hex).map_err(|_| SigningError::InvalidPublicNonce)?;

    let sig = WalletMessageSchnorrSignature::new(nonce, scalar);
    Ok(sig.verify(&public_key, message.as_bytes()))
}

fn sign_with_key_manager(key_manager: &KeyManager, message: &str) -> Result<String, SigningError> {
    let sig = key_manager
        .sign_message_with_spend_key(message.as_bytes(), None)
        .map_err(|e| SigningError::KeyManager(e.to_string()))?;
    // Wire order is scalar first, nonce second.
    Ok(format!(
        "{}|{}",
        sig.get_signature().to_hex(),
        sig.get_public_nonce().to_hex()
    ))
}

#[cfg(test)]
mod tests {
    use tari_common::configuration::Network;
    use tari_common_types::types::CompressedPublicKey;
    use tari_crypto::ristretto::RistrettoSecretKey;
    use tari_transaction_components::key_manager::wallet_types::ViewWallet;
    use tari_utilities::ByteArray;

    use super::*;
    use crate::db::{create_account, get_account_by_name, init_db};

    // Produced by cw_tari_wallet `api::signing::sign_message` (commit a2fafb9).
    const CW_SEED_WORDS: &str = "scare bottom good nuclear zone target today train favorite spend spoil scrub people inject enter glare scare curve fish board october depth nuclear short";
    const CW_SEED_ADDRESS: &str =
        "12GkeRHzGPdJd1CEorwPKkxDLeNwtJPiSaffMRawLq6T61LhUFyohGHYpEGPpH8JQkdxAiF7TSouC7XNdK1DAdtHxEz";
    const CW_SEED_MESSAGE: &str = "minotari cw golden vector";
    const CW_SEED_SIGNATURE: &str = "3d0c2d5be78456ade27f4b1da0f08742b44765b473b064325c36b3c905583e04|6cd8d68110fe9d1f299883a0216d9537090ed3941622ceb611d0aebc286b234b";

    // cw `verifies_reference_tari_signature`: spend key [42, 0, ...], view key [7, 0, ...].
    const CW_FIXED_KEY_ADDRESS: &str =
        "1275wmA8j3bwNkY4hWGyjkq3ccB2EDZC4DEApYn1MP3B6E3Y6tsTcj8pnxPTkT3hW68wU5kZbJdjmFgkWwfPgj5QuQY";
    const CW_FIXED_KEY_MESSAGE: &str = "Tari message signing cross-compat vector";
    const CW_FIXED_KEY_SIGNATURE: &str = "63d1199d278eab8eb2ec05844be2e4cd3c89518bd75bcf5fdfc5b06ea09dc704|862705ed9c05b18e2729a3dc0991c68d4f576ea5f1db6c45deb8d6639c10065b";

    fn address(base58: &str) -> TariAddress {
        TariAddress::from_base58(base58).expect("valid address")
    }

    fn seed_address(seed_words: &str) -> TariAddress {
        let mnemonic = SeedWords::from_str(seed_words).unwrap();
        let seed = CipherSeed::from_mnemonic(&mnemonic, None).unwrap();
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(seed).unwrap());
        TariAddress::new_dual_address_with_default_features(
            wallet.get_public_view_key(),
            wallet.get_public_spend_key(),
            Network::MainNet,
        )
        .unwrap()
    }

    #[test]
    fn verifies_cw_fixed_key_vector() {
        let addr = address(CW_FIXED_KEY_ADDRESS);
        assert!(verify_message(&addr, CW_FIXED_KEY_MESSAGE, CW_FIXED_KEY_SIGNATURE).unwrap());
        assert!(!verify_message(&addr, "tampered", CW_FIXED_KEY_SIGNATURE).unwrap());
    }

    #[test]
    fn verifies_cw_seed_words_vector() {
        let addr = address(CW_SEED_ADDRESS);
        assert!(verify_message(&addr, CW_SEED_MESSAGE, CW_SEED_SIGNATURE).unwrap());
        // The lib derives the same spend key from the seed words as cw does.
        assert_eq!(seed_address(CW_SEED_WORDS).public_spend_key(), addr.public_spend_key());
    }

    #[test]
    fn seed_round_trip_and_failures() {
        let addr = seed_address(CW_SEED_WORDS);
        let sig = sign_message_with_seed(CW_SEED_WORDS, "hello").unwrap();
        assert!(verify_message(&addr, "hello", &sig).unwrap());

        // Random nonce: a second signature differs but still verifies.
        let sig2 = sign_message_with_seed(CW_SEED_WORDS, "hello").unwrap();
        assert_ne!(sig, sig2);
        assert!(verify_message(&addr, "hello", &sig2).unwrap());

        assert!(!verify_message(&addr, "HELLO", &sig).unwrap());
        assert!(!verify_message(&address(CW_FIXED_KEY_ADDRESS), "hello", &sig).unwrap());

        // Pair one signature's scalar with the other's nonce: well-formed but invalid.
        let (_, nonce_hex) = sig.split_once('|').unwrap();
        let (sig2_hex, _) = sig2.split_once('|').unwrap();
        let tampered = format!("{sig2_hex}|{nonce_hex}");
        assert!(!verify_message(&addr, "hello", &tampered).unwrap());
    }

    #[test]
    fn sign_output_is_two_64_char_hex_halves() {
        let sig = sign_message_with_seed(CW_SEED_WORDS, "m").unwrap();
        let parts: Vec<&str> = sig.split('|').collect();
        assert_eq!(parts.len(), 2);
        for part in parts {
            assert_eq!(part.len(), 64);
            assert!(part.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn malformed_signatures_error() {
        let addr = address(CW_SEED_ADDRESS);
        for bad in ["", "abc", "a|b|c"] {
            assert!(matches!(
                verify_message(&addr, "m", bad),
                Err(SigningError::MalformedSignature)
            ));
        }
        let (sig_hex, nonce_hex) = CW_SEED_SIGNATURE.split_once('|').unwrap();
        assert!(matches!(
            verify_message(&addr, "m", &format!("zz|{nonce_hex}")),
            Err(SigningError::InvalidSignatureComponent)
        ));
        assert!(matches!(
            verify_message(&addr, "m", &format!("{sig_hex}|zz")),
            Err(SigningError::InvalidPublicNonce)
        ));
    }

    #[test]
    fn invalid_seed_words_error() {
        assert!(matches!(
            sign_message_with_seed("not a mnemonic", "m"),
            Err(SigningError::InvalidSeedWords(_))
        ));
    }

    #[test]
    fn account_round_trip_and_view_only_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let pool = init_db(dir.path().join("signing.db")).unwrap();
        let conn = pool.get().unwrap();

        let seed = CipherSeed::random();
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(seed).unwrap());
        create_account(&conn, "full", &wallet, "password").unwrap();
        let full = get_account_by_name(&conn, "full").unwrap().unwrap();
        let full_address = full.get_address(Network::MainNet, "password").unwrap();

        let sig = sign_message(&full, "password", "hello").unwrap();
        assert!(verify_message(&full_address, "hello", &sig).unwrap());

        let mut view_key_bytes = [0u8; 32];
        view_key_bytes[0] = 7;
        let view_key = RistrettoSecretKey::from_canonical_bytes(&view_key_bytes).unwrap();
        let view_wallet = WalletType::ViewWallet(ViewWallet::new(
            CompressedPublicKey::from_secret_key(&view_key),
            view_key,
            None,
        ));
        create_account(&conn, "view", &view_wallet, "password").unwrap();
        let view = get_account_by_name(&conn, "view").unwrap().unwrap();
        assert!(matches!(
            sign_message(&view, "password", "hello"),
            Err(SigningError::ViewOnlyWallet)
        ));
    }
}
