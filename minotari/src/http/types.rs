//! Type definitions for Tari base node RPC responses.
//!
//! This module contains the data structures used to deserialize JSON responses
//! from the Tari base node RPC API. These types model the blockchain state,
//! transaction submission results, and transaction query responses.
//!
//! # Overview
//!
//! The main types in this module are:
//!
//! - [`JsonRpcResponse`] - Generic wrapper for JSON-RPC 2.0 responses
//!
//! # JSON-RPC Protocol
//!
//! The Tari base node uses JSON-RPC 2.0 for certain operations. Responses
//! are wrapped in [`JsonRpcResponse`] which contains either a `result` or
//! an `error` field, along with a request `id` for correlation.

use serde::{Deserialize, Serialize};

/// Generic wrapper for JSON-RPC 2.0 responses.
///
/// This struct represents the standard JSON-RPC 2.0 response format used
/// by the Tari base node for certain RPC methods (e.g., `submit_transaction`).
///
/// # Type Parameters
///
/// * `T` - The type of the successful result payload
///
/// # Fields
///
/// According to the JSON-RPC 2.0 specification, either `result` or `error`
/// should be present (but not both) in a valid response.
///
/// # Example
///
/// ```rust
/// use minotari::http::JsonRpcResponse;
/// use serde_json::json;
///
/// let json = json!({
///     "result": { "accepted": true },
///     "error": null,
///     "id": "1"
/// });
///
/// let response: JsonRpcResponse<serde_json::Value> =
///     serde_json::from_value(json).unwrap();
/// assert!(response.result.is_some());
/// assert!(response.error.is_none());
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse<T> {
    /// The successful result of the RPC call, if any.
    ///
    /// This field is `Some` when the request succeeded and `None` when
    /// an error occurred.
    pub result: Option<T>,

    /// Error message if the RPC call failed.
    ///
    /// This field is `Some` when the request failed and `None` on success.
    pub error: Option<String>,

    /// The request identifier, used to match responses with requests.
    ///
    /// This should match the `id` field from the corresponding request.
    pub id: String,
}

#[derive(serde::Deserialize)]
pub struct FeePerGramStatResponse {
    pub order: u64,
    pub min_fee_per_gram: u64,
    pub avg_fee_per_gram: u64,
    pub max_fee_per_gram: u64,
}

#[derive(serde::Deserialize)]
pub struct GetMempoolFeePerGramStatsResponse {
    pub stats: Vec<FeePerGramStatResponse>,
}
