//! API request and response types for the Minotari wallet REST API.
//!
//! This module contains the data structures used for serializing and
//! deserializing API request bodies and response payloads. It includes
//! wrapper types for proper JSON representation of Tari-specific types.
//!
//! # Key Types
//!
//! - [`TariAddressBase58`]: Wrapper for Tari addresses with Base58 serialization
//! - [`LockFundsResult`]: Response type for the lock funds endpoint
//!
//! # Serialization Format
//!
//! All types in this module use JSON serialization via Serde. Numeric amounts
//! are represented as unsigned 64-bit integers (MicroMinotari), and addresses
//! use Base58 encoding for human-readable representation.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use tari_common_types::tari_address::TariAddress;
use tari_common_types::transaction::TxId;
use tari_transaction_components::{tari_amount::MicroMinotari, transaction_components::WalletOutput};
use utoipa::openapi::{Object, Schema, Type};

/// A wrapper type for [`TariAddress`] with Base58 serialization.
///
/// This type provides JSON serialization and deserialization of Tari addresses
/// using Base58 encoding, which is the standard human-readable format for
/// Tari addresses.
///
/// # Serialization
///
/// When serialized to JSON, the address is represented as a Base58-encoded string:
///
/// ```json
/// "f4FxMqKAPDMqAjh6hTpCnLKfEu3MmS7NRu2YmKZPvZHc2K"
/// ```
///
/// # Deserialization
///
/// When deserializing from JSON, the string is parsed as a Base58-encoded
/// Tari address. Invalid addresses will result in a deserialization error.
///
/// # Example
///
/// ```rust,ignore
/// use crate::api::types::TariAddressBase58;
///
/// #[derive(Deserialize)]
/// struct Request {
///     recipient: TariAddressBase58,
/// }
///
/// // JSON: {"recipient": "f4FxMqKAPDMqAjh6hTpC..."}
/// ```
#[derive(Debug, Clone, PartialEq, Eq, utoipa::ToSchema)]
#[schema(value_type = String)]
pub struct TariAddressBase58(pub TariAddress);

/// Result of a successful fund locking operation.
///
/// This structure is returned by the `/accounts/{name}/lock_funds` endpoint
/// and contains all the information needed to construct a transaction using
/// the locked UTXOs.
///
/// # JSON Example
///
/// ```json
/// {
///   "utxos": [...],
///   "requires_change_output": true,
///   "total_value": 1500000,
///   "fee_without_change": 250,
///   "fee_with_change": 500
/// }
/// ```
///
/// # Usage
///
/// The locked UTXOs should be used as inputs for the transaction. If
/// `requires_change_output` is `true`, a change output must be created
/// to return excess funds. The appropriate fee (`fee_with_change` or
/// `fee_without_change`) should be used based on whether a change output
/// is included.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct LockFundsResult {
    /// The UTXOs that have been locked for this transaction.
    ///
    /// These outputs are reserved and cannot be used by other transactions
    /// until the lock expires or is released. Each UTXO contains the
    /// cryptographic data needed to spend it.
    #[schema(value_type = Vec<Object>)]
    pub utxos: Vec<WalletOutput>,

    /// Indicates whether a change output is required.
    ///
    /// If `true`, the total value of locked UTXOs exceeds the requested
    /// amount plus fees, and a change output should be created to return
    /// the excess to the wallet.
    pub requires_change_output: bool,

    /// The total value of all locked UTXOs in MicroMinotari.
    ///
    /// This is the sum of the values of all UTXOs in the `utxos` field.
    /// It will be greater than or equal to the requested amount plus the
    /// applicable fee.
    #[schema(value_type = u64)]
    pub total_value: MicroMinotari,

    /// The transaction fee if no change output is created.
    ///
    /// Use this fee when `requires_change_output` is `false`, or when
    /// intentionally burning the excess as a donation to miners.
    #[schema(value_type = u64)]
    pub fee_without_change: MicroMinotari,

    /// The transaction fee if a change output is included.
    ///
    /// This fee is higher than `fee_without_change` because the change
    /// output adds to the transaction size. Use this fee when
    /// `requires_change_output` is `true`.
    #[schema(value_type = u64)]
    pub fee_with_change: MicroMinotari,

    /// The pending transaction holding these UTXOs. Not sent to clients.
    #[serde(skip)]
    pub reservation_id: String,

    /// Whether this call took the reservation rather than replaying an
    /// existing one. Only then may the caller release it when the send fails
    /// (see `release_reservation`). Not sent to clients.
    #[serde(skip)]
    pub created_reservation: bool,

    /// For a send-all reservation this call took, how many spendable outputs
    /// it left behind. `None` for an exact send, and on a replay: the counts
    /// are not stored, and recounting now could describe other outputs. Not
    /// sent to clients as part of this type.
    #[serde(skip)]
    pub send_all_skipped: Option<SendAllSkipped>,
}

/// How many spendable outputs a send-all left behind: the `send_all` field of
/// a send-all's `create_unsigned_transaction` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
pub struct SendAllSkipped {
    /// Outputs worth no more than they cost to spend; never worth spending.
    pub skipped_dust: usize,
    /// Outputs that did not fit one transaction (count, weight or bytes);
    /// another send-all can sweep them.
    pub skipped_over_cap: usize,
}

pub fn tx_id_schema() -> Schema {
    Schema::Object(
        Object::builder()
            .property("Tx_id", Schema::Object(Object::with_type(Type::Integer)))
            .build(),
    )
}

/// API response type for a completed transaction.
///
/// This structure represents a completed transaction in the API response.
/// It contains all the relevant transaction details for display and tracking.
///
/// # JSON Example
///
/// ```json
/// {
///   "id": "550e8400-e29b-41d4-a716-446655440000",
///   "pending_tx_id": "661e8400-e29b-41d4-a716-446655440001",
///   "account_id": 1,
///   "status": "broadcast",
///   "last_rejected_reason": null,
///   "kernel_excess_hex": "abc123...",
///   "sent_payref": null,
///   "sent_output_hash": "def456...",
///   "mined_height": null,
///   "mined_block_hash_hex": null,
///   "confirmation_height": null,
///   "broadcast_attempts": 1,
///   "created_at": "2024-01-15T10:30:00Z",
///   "updated_at": "2024-01-15T10:31:00Z"
/// }
/// ```
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct CompletedTransactionResponse {
    /// Unique identifier for this completed transaction
    #[schema(schema_with = tx_id_schema)]
    pub id: TxId,
    /// Reference to the original pending transaction
    pub pending_tx_id: String,
    /// Account this transaction belongs to
    pub account_id: i64,
    /// Current status of the transaction (completed, broadcast, mined_unconfirmed, mined_confirmed, rejected, canceled)
    pub status: String,
    /// Reason for rejection if the transaction was rejected
    pub last_rejected_reason: Option<String>,
    /// Kernel excess in hexadecimal encoding
    pub kernel_excess_hex: String,
    /// Payment reference if the transaction has been confirmed
    pub sent_payref: Option<String>,
    /// Output hash for the sent transaction
    pub sent_output_hash: Option<String>,
    /// Block height where the transaction was mined (if mined)
    pub mined_height: Option<i64>,
    /// Block hash where the transaction was mined (hex encoded, if mined)
    pub mined_block_hash_hex: Option<String>,
    /// Block height where the transaction was confirmed (if confirmed)
    pub confirmation_height: Option<i64>,
    /// Number of broadcasts in a row the node did not accept (0 once one is
    /// accepted). At 10 or more the transaction is stalled: still pending, inputs
    /// locked, rebroadcast less often.
    pub broadcast_attempts: i32,
    /// Timestamp when the transaction was created
    pub created_at: String,
    /// Timestamp when the transaction was last updated
    pub updated_at: String,
}

impl From<crate::db::CompletedTransaction> for CompletedTransactionResponse {
    fn from(tx: crate::db::CompletedTransaction) -> Self {
        Self {
            id: tx.id,
            pending_tx_id: tx.pending_tx_id,
            account_id: tx.account_id,
            status: tx.status.to_string(),
            last_rejected_reason: tx.last_rejected_reason,
            kernel_excess_hex: hex::encode(&tx.kernel_excess),
            sent_payref: tx.sent_payref,
            sent_output_hash: tx.sent_output_hash,
            mined_height: tx.mined_height,
            mined_block_hash_hex: tx.mined_block_hash.map(|h| hex::encode(&h)),
            confirmation_height: tx.confirmation_height,
            broadcast_attempts: tx.broadcast_attempts,
            created_at: tx.created_at.to_rfc3339(),
            updated_at: tx.updated_at.to_rfc3339(),
        }
    }
}

/// API response type for the scan status endpoint.
///
/// Contains information about the last scanned block including height,
/// block hash, and the timestamp when it was scanned.
///
/// # JSON Example
///
/// ```json
/// {
///   "last_scanned_height": 12345,
///   "last_scanned_block_hash": "abc123def456...",
///   "scanned_at": "2024-01-15 10:30:00"
/// }
/// ```
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct ScanStatusResponse {
    /// The height of the last scanned block
    pub last_scanned_height: u64,
    /// The hash of the last scanned block (hex encoded)
    pub last_scanned_block_hash: String,
    /// Timestamp when this block was scanned
    pub scanned_at: String,
}

impl From<crate::db::LatestScannedBlock> for ScanStatusResponse {
    fn from(block: crate::db::LatestScannedBlock) -> Self {
        Self {
            last_scanned_height: block.height,
            last_scanned_block_hash: hex::encode(&block.hash),
            scanned_at: block.scanned_at,
        }
    }
}

/// API response type for an account address.
///
/// Contains the Tari address in Base58 format along with the emoji ID representation.
///
/// # JSON Example
///
/// ```json
/// {
///   "address": "f4FxMqKAPDMqAjh6hTpCnLKfEu3MmS7NRu2YmKZPvZHc2K",
///   "emoji_id": "🎉🌟🚀..."
/// }
/// ```
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct AddressResponse {
    /// The Tari address in Base58 encoding
    pub address: String,
    /// The emoji representation of the address
    pub emoji_id: String,
}

/// API response type for an address with payment ID.
///
/// Contains the Tari address with embedded payment ID in Base58 format,
/// along with the emoji ID representation and the original payment ID in hex.
///
/// # JSON Example
///
/// ```json
/// {
///   "address": "f4FxMqKAPDMqAjh6hTpCnLKfEu3MmS7NRu2YmKZPvZHc2K",
///   "emoji_id": "🎉🌟🚀...",
///   "payment_id_hex": "696e766f6963652d3132333435"
/// }
/// ```
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct AddressWithPaymentIdResponse {
    /// The Tari address with embedded payment ID in Base58 encoding
    pub address: String,
    /// The emoji representation of the address
    pub emoji_id: String,
    /// The payment ID that was embedded in the address (hex encoded)
    pub payment_id_hex: String,
}

/// API response type for the wallet version.
///
/// Contains version information about the wallet software.
///
/// # JSON Example
///
/// ```json
/// {
///   "version": "0.1.0",
///   "name": "minotari"
/// }
/// ```
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct VersionResponse {
    /// The semantic version of the wallet (e.g., "0.1.0")
    pub version: String,
    /// The name of the wallet package
    pub name: String,
}

/// Serializes a [`TariAddressBase58`] to its Base58 string representation.
///
/// # Output Format
///
/// The address is serialized as a plain string in Base58 encoding:
///
/// ```json
/// "f4FxMqKAPDMqAjh6hTpCnLKfEu3MmS7NRu2YmKZPvZHc2K"
/// ```
impl Serialize for TariAddressBase58 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_base58())
    }
}

/// Deserializes a [`TariAddressBase58`] from a Base58 string.
///
/// # Input Format
///
/// Expects a valid Tari address in Base58 encoding:
///
/// ```json
/// "f4FxMqKAPDMqAjh6hTpCnLKfEu3MmS7NRu2YmKZPvZHc2K"
/// ```
///
/// # Errors
///
/// Returns a deserialization error if:
/// - The string is not valid Base58 encoding
/// - The decoded data is not a valid Tari address
/// - The address checksum is invalid
impl<'de> Deserialize<'de> for TariAddressBase58 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        TariAddress::from_base58(&s)
            .map(TariAddressBase58)
            .map_err(de::Error::custom)
    }
}

/// Priority level for fee estimation.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub enum FeePriorityResponse {
    /// Low fee, slower confirmation time
    Slow,
    /// Medium fee, average confirmation time
    Medium,
    /// High fee, faster confirmation time
    Fast,
}

/// API response type for fee estimation.
///
/// Contains the estimated fee details for a specific priority level.
///
/// # JSON Example
///
/// ```json
/// {
///   "priority": "Medium",
///   "fee_per_gram": 5,
///   "estimated_fee": 500,
///   "total_amount_required": 1000500,
///   "input_count": 2
/// }
/// ```
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct FeeEstimateResponse {
    /// The priority level for this estimate
    pub priority: FeePriorityResponse,
    /// The fee per gram used for calculation
    #[schema(value_type = u64)]
    pub fee_per_gram: MicroMinotari,
    /// The total estimated fee in MicroMinotari
    #[schema(value_type = u64)]
    pub estimated_fee: MicroMinotari,
    /// The total amount required (sent amount + fee) in MicroMinotari
    #[schema(value_type = u64)]
    pub total_amount_required: MicroMinotari,
    /// The number of input UTXOs selected
    pub input_count: usize,
}
