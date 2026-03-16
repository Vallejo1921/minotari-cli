use anyhow::anyhow;
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{SaltString, rand_core::OsRng},
};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit},
};

fn derive_key(password: &str, salt: &[u8]) -> Result<Key, anyhow::Error> {
    let params = Params::default();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;
    Ok(Key::from(key_bytes))
}

#[derive(Debug, Clone)]
pub struct FullEncryptedData<S = Vec<u8>> {
    pub ciphertext: S,
    pub nonce: S,
    pub salt_bytes: S,
}

/// Encrypts data using XChaCha20-Poly1305.
pub fn encrypt_data(data: &[u8], password: &str) -> Result<FullEncryptedData, anyhow::Error> {
    let salt_string = SaltString::generate(&mut OsRng);
    let salt_bytes = salt_string.as_str().as_bytes();

    let key = derive_key(password, salt_bytes)?;
    let cipher = XChaCha20Poly1305::new(&key);

    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    Ok(FullEncryptedData {
        ciphertext,
        nonce: nonce.to_vec(),
        salt_bytes: salt_bytes.to_vec(),
    })
}

/// Decrypts data using XChaCha20-Poly1305.
pub fn decrypt_data<S: AsRef<[u8]>>(data: &FullEncryptedData<S>, password: &str) -> Result<Vec<u8>, anyhow::Error> {
    let salt = data.salt_bytes.as_ref();
    let key = derive_key(password, salt)?;
    let cipher = XChaCha20Poly1305::new(&key);

    let nonce_slice = data.nonce.as_ref();
    let nonce_bytes: &[u8; 24] = nonce_slice.try_into().map_err(|_| anyhow!("Nonce must be 24 bytes"))?;

    let xnonce = XNonce::from(*nonce_bytes);

    let plaintext = cipher
        .decrypt(&xnonce, data.ciphertext.as_ref())
        .map_err(|e| anyhow!("Decryption failed: {}", e))?;

    Ok(plaintext)
}
