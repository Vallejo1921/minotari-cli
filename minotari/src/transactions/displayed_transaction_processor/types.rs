use crate::models::{Id, OutputStatus};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use tari_common_types::payment_reference::PaymentReference;
use tari_common_types::tari_address::TariAddress;
use tari_common_types::transaction::TxId;
use tari_common_types::types::FixedHash;
use tari_transaction_components::MicroMinotari;
use tari_transaction_components::transaction_components::{CoinBaseExtra, OutputType};
use utoipa::ToSchema;
use utoipa::openapi::{Object, Schema, Type};

pub fn tx_id_schema() -> Schema {
    Schema::Object(
        Object::builder()
            .property("Tx_id", Schema::Object(Object::with_type(Type::Integer)))
            .build(),
    )
}

pub fn micro_minotari_schema() -> Schema {
    Schema::Object(
        Object::builder()
            .property("amount", Schema::Object(Object::with_type(Type::Integer)))
            .build(),
    )
}

pub fn output_type_schema() -> Schema {
    Schema::Object(
        Object::builder()
            .property("Output type", Schema::Object(Object::with_type(Type::String)))
            .build(),
    )
}

pub fn coinbase_schema() -> Schema {
    Schema::Object(
        Object::builder()
            .property("Coinbase extra", Schema::Object(Object::with_type(Type::String)))
            .build(),
    )
}

// I create a custom function to generate schema for `Owner`.
fn tari_address_schema() -> Schema {
    Schema::Object(
        Object::builder()
            .property("TariAddress", Schema::Object(Object::with_type(Type::String)))
            .build(),
    )
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TransactionDirection {
    Incoming,
    Outgoing,
}

impl TransactionDirection {
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::Incoming => "Received",
            Self::Outgoing => "Sent",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransactionSource {
    Transfer,
    Coinbase,
    OneSided,
    Unknown,
}

impl TransactionSource {
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::Transfer => "Transfer",
            Self::Coinbase => "Mining Reward",
            Self::OneSided => "One-sided Payment",
            Self::Unknown => "Transaction",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TransactionDisplayStatus {
    Pending,
    Unconfirmed,
    Confirmed,
    Cancelled,
    Reorganized,
    Rejected,
    Locked,
}

impl TransactionDisplayStatus {
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Unconfirmed => "Unconfirmed",
            Self::Confirmed => "Confirmed",
            Self::Cancelled => "Cancelled",
            Self::Reorganized => "Reorganized",
            Self::Rejected => "Rejected",
            Self::Locked => "Locked",
        }
    }
}

/// User-friendly transaction representation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DisplayedTransaction {
    #[schema(schema_with = tx_id_schema)]
    pub id: TxId,
    pub direction: TransactionDirection,
    pub source: TransactionSource,
    pub status: TransactionDisplayStatus,
    /// Net amount in microTari (always positive, use direction for sign).
    #[schema(schema_with = micro_minotari_schema)]
    pub amount: MicroMinotari,
    pub message: Option<String>,
    #[schema(schema_with = tari_address_schema)]
    pub counterparty: Option<TariAddress>,
    pub blockchain: BlockchainInfo,
    /// Fee information (only populated for outgoing transactions).
    pub fee: Option<FeeInfo>,
    pub details: TransactionDetails,
    pub lock_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CounterpartyInfo {
    pub address: String,
    pub address_emoji: Option<String>,
    /// User-defined alias from address book.
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BlockchainInfo {
    pub block_height: u64,
    #[schema(value_type = String)]
    pub timestamp: NaiveDateTime,
    pub confirmations: u64,
    pub block_hash: FixedHash,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FeeInfo {
    #[schema(schema_with = micro_minotari_schema)]
    pub amount: MicroMinotari,
}

/// Advanced transaction details.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TransactionDetails {
    #[schema(value_type = i64)]
    pub account_id: Id,
    #[schema(schema_with = micro_minotari_schema)]
    pub total_credit: MicroMinotari,
    #[schema(schema_with = micro_minotari_schema)]
    pub total_debit: MicroMinotari,
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    #[schema(schema_with = output_type_schema)]
    pub output_type: Option<OutputType>,
    /// Extra data for coinbase transactions.
    #[schema(schema_with = coinbase_schema)]
    pub coinbase_extra: Option<CoinBaseExtra>,
    pub memo_hex: Option<String>,
    /// Hashes of outputs sent in this transaction (hex encoded).
    /// Used to match pending broadcasted transactions with scanned ones.
    pub sent_output_hashes: Vec<FixedHash>,
    /// Payment references for this transaction, serialized as hex strings so
    /// they are human-usable and match the hex form used by the payref lookup
    /// and reorg-history APIs.
    #[serde(with = "payref_hex_vec")]
    #[schema(value_type = Vec<String>)]
    pub sent_payrefs: Vec<PaymentReference>,
}

/// Serde helper that (de)serializes a list of [`PaymentReference`]s as hex
/// strings. `PaymentReference` is a `FixedHash`, whose default (transparent)
/// serialization is a byte array — but the payref column, the `LIKE` lookup,
/// the reorg-history parser (which expects `Vec<String>`) and the public API
/// all operate on hex, so this keeps every representation consistent.
pub mod payref_hex_vec {
    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeSeq};
    use tari_common_types::payment_reference::PaymentReference;
    use tari_common_types::types::FixedHash;
    use tari_utilities::hex::Hex;

    pub fn serialize<S: Serializer>(payrefs: &[PaymentReference], serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(payrefs.len()))?;
        for payref in payrefs {
            seq.serialize_element(&payref.to_hex())?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<PaymentReference>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|h| FixedHash::from_hex(&h).map_err(serde::de::Error::custom))
            .collect()
    }
}

/// A transaction input (spent UTXO).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TransactionInput {
    pub output_hash: FixedHash,
    #[schema(schema_with = micro_minotari_schema)]
    pub amount: MicroMinotari,
    /// ID of the matched output in our database (if found).
    #[schema(value_type = i64)]
    pub matched_output_id: Id,
    pub mined_in_block_hash: FixedHash,
}

/// A transaction output (created UTXO).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TransactionOutput {
    pub hash: FixedHash,
    #[schema(schema_with = micro_minotari_schema)]
    pub amount: MicroMinotari,
    pub status: OutputStatus,
    pub mined_in_block_height: u64,
    pub mined_in_block_hash: FixedHash,
    #[schema(schema_with = output_type_schema)]
    pub output_type: OutputType,
    pub is_change: bool,
}
