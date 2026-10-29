use crate::db::WalletDbError;

#[derive(Debug, thiserror::Error)]
pub enum ProcessorError {
    /// DB execution failed
    #[error("Database execution error: {0}")]
    DbError(#[from] WalletDbError),

    #[error("Failed to parse output data: {0}")]
    ParseError(String),

    #[error("Missing data: {0}")]
    MissingError(String),
}
