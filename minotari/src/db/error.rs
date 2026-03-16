use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletDbError {
    #[error("Database connection error: {0}")]
    ConnectionError(#[from] r2d2::Error),

    #[error("Database execution error: {0}")]
    Rusqlite(#[from] rusqlite::Error),

    #[error("Migration error: {0}")]
    Migration(#[from] rusqlite_migration::Error),

    #[error("Serialization/Deserialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("Row mapping error: {0}")]
    SerdeRusqlite(#[from] serde_rusqlite::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Cryptography error: {0}")]
    Crypt(String),

    #[error("Decoding error: {0}")]
    Decoding(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Duplicate entry: {0}")]
    DuplicateEntry(String),

    #[error("Key decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Unexpected error: {0}")]
    Unexpected(String),
}

// Convenience alias
pub type WalletDbResult<T> = Result<T, WalletDbError>;
