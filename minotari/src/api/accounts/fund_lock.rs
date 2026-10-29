//! Fund locking and unsigned transaction creation endpoint handlers.

use axum::{
    Json,
    extract::{Path, State},
};
use log::info;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use tari_transaction_components::tari_amount::MicroMinotari;

use crate::{
    api::{
        AppState,
        error::ApiError,
        types::{LockFundsResult, TariAddressBase58},
    },
    db::get_account_by_name,
    log::mask_amount,
    transactions::{
        fund_locker::{FundLocker, MAX_SECONDS_TO_LOCK_UTXOS, validate_fee_per_gram, validate_seconds_to_lock},
        idempotency::{IdempotencyBinding, IdempotencyOperation, RequestFingerprint},
        one_sided_transaction::{
            OneSidedTransaction, Recipient, check_memos_and_estimate_output_size, unsigned_transaction_binding,
        },
    },
};

use super::params::{
    DEFAULT_FEE_PER_GRAM, DEFAULT_NUM_OUTPUTS, DEFAULT_SECONDS_TO_LOCK_UTXOS, WalletParams, confirmation_window_schema,
    default_fee_per_gram, default_num_outputs, default_seconds_to_lock_utxos, resolve_confirmation_window,
};

/// `utoipa`'s `maximum = ..` only accepts a literal, so it cannot reference
/// [`MAX_SECONDS_TO_LOCK_UTXOS`] directly. Fail the build if the two drift.
const _: () = assert!(
    MAX_SECONDS_TO_LOCK_UTXOS == 31_536_000,
    "OpenAPI `maximum` annotations for seconds_to_lock_utxos must match MAX_SECONDS_TO_LOCK_UTXOS",
);

/// Request body for locking funds in preparation for a transaction.
///
/// This request reserves (locks) a specified amount of funds from the account's
/// available UTXOs. Locked funds cannot be used in other transactions until
/// either the lock expires or the transaction is completed/cancelled.
///
/// # JSON Example
///
/// ```json
/// {
///   "amount": 1000000,
///   "num_outputs": 2,
///   "fee_per_gram": 5,
///   "estimated_output_size": 1024,
///   "seconds_to_lock_utxos": 3600,
///   "idempotency_key": "unique-request-id-12345"
/// }
/// ```
///
/// # Minimal Request
///
/// Only `amount` is required; all other fields have sensible defaults:
///
/// ```json
/// {
///   "amount": 1000000
/// }
/// ```
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct LockFundsRequest {
    /// The total amount to lock in MicroMinotari (1 Minotari = 1,000,000 MicroMinotari).
    ///
    /// This should cover the intended transaction amount plus any expected fees.
    #[schema(value_type = u64)]
    pub amount: MicroMinotari,

    /// Number of outputs to create in the transaction.
    ///
    /// Defaults to 1. Increase this when sending to multiple recipients or when
    /// the transaction requires multiple output UTXOs.
    #[serde(default = "default_num_outputs")]
    #[schema(default = 1)]
    pub num_outputs: Option<usize>,

    /// Fee per gram for the transaction in MicroMinotari.
    ///
    /// Defaults to 5 MicroMinotari. Higher fees may result in faster confirmation
    /// during periods of high network congestion.
    #[schema(value_type = u64)]
    #[serde(default = "default_fee_per_gram")]
    #[schema(default = 5)]
    pub fee_per_gram: Option<MicroMinotari>,

    /// Estimated size of each output in bytes.
    ///
    /// Used for fee calculation. If not provided, a default estimate is used
    /// based on standard output sizes.
    pub estimated_output_size: Option<usize>,

    /// Duration in seconds to keep the UTXOs locked.
    ///
    /// Defaults to 86,400 seconds (24 hours) and may not exceed 31,536,000
    /// seconds (365 days). After this period, locked UTXOs are automatically
    /// released if the transaction was not completed.
    #[serde(default = "default_seconds_to_lock_utxos")]
    #[schema(default = 86_400, maximum = 31_536_000)]
    pub seconds_to_lock_utxos: Option<u64>,

    /// Optional idempotency key to prevent duplicate requests.
    ///
    /// If provided, a later request with the same key returns the cached result
    /// from the original request rather than locking additional funds.
    ///
    /// The key is bound to this request: reusing it with any field changed, or
    /// at a different endpoint, is rejected with 409 Conflict instead of
    /// returning the original lock. A key whose transaction has completed or
    /// expired cannot be reused either.
    pub idempotency_key: Option<String>,

    /// Number of confirmations required before spending locked UTXOs.
    #[schema(schema_with = confirmation_window_schema)]
    pub confirmation_window: Option<u64>,
}

/// Represents a single recipient in a transaction request.
///
/// Each recipient specifies a destination address and the amount to send.
/// An optional payment ID can be included for tracking or identification
/// purposes.
///
/// # JSON Example
///
/// ```json
/// {
///   "address": "f4FxMqKAPDMqAjh6hTpC...",
///   "amount": 500000,
///   "payment_id": "invoice-2024-001"
/// }
/// ```
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RecipientRequest {
    /// The recipient's Tari address in Base58 encoding.
    ///
    /// Must be a valid Tari address for the current network (mainnet, testnet, etc.).
    address: TariAddressBase58,

    /// The amount to send to this recipient in MicroMinotari.
    #[schema(value_type = u64)]
    amount: MicroMinotari,

    /// Optional payment identifier for transaction tracking.
    ///
    /// This can be used to associate the payment with an invoice, order, or
    /// other business reference. The payment ID is included in the transaction
    /// metadata, unless the address embeds a payment ID of its own: that one is
    /// sent instead, as the console wallet does.
    payment_id: Option<String>,
}

/// Request body for creating an unsigned transaction.
///
/// Creates a one-sided transaction that can be signed externally. This is
/// useful for cold wallet setups or multi-signature workflows where the
/// signing key is not available on the server.
///
/// # JSON Example
///
/// ```json
/// {
///   "recipients": [
///     {
///       "address": "f4FxMqKAPDMqAjh6hTpC...",
///       "amount": 500000,
///       "payment_id": "order-123"
///     },
///     {
///       "address": "f5GxNrLBPEMrBki7iTqD...",
///       "amount": 300000
///     }
///   ],
///   "seconds_to_lock_utxos": 7200,
///   "idempotency_key": "tx-request-abc123"
/// }
/// ```
///
/// # Notes
///
/// - The total amount sent equals the sum of all recipient amounts
/// - Transaction fees are calculated automatically based on transaction size
/// - UTXOs are locked during transaction creation to prevent double-spending
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateTransactionRequest {
    /// List of recipients for the transaction.
    ///
    /// At least one recipient must be specified. Each recipient includes an
    /// address and amount, with an optional payment ID.
    recipients: Vec<RecipientRequest>,

    /// Duration in seconds to keep the input UTXOs locked.
    ///
    /// Defaults to 86,400 seconds (24 hours) and may not exceed 31,536,000
    /// seconds (365 days). The lock prevents the same UTXOs from being used in
    /// multiple transactions while the unsigned transaction is being signed and
    /// broadcast.
    #[serde(default = "default_seconds_to_lock_utxos")]
    #[schema(default = 86_400, maximum = 31_536_000)]
    seconds_to_lock_utxos: Option<u64>,

    /// Optional idempotency key to prevent duplicate transactions.
    ///
    /// Reusing the key returns the original transaction rather than creating a
    /// new one. The key is bound to the recipients, amounts and payment ids
    /// below: a request that reuses the key with a different recipient list is
    /// rejected with 409 Conflict, never served from the original lock.
    idempotency_key: Option<String>,

    #[schema(schema_with = confirmation_window_schema)]
    pub confirmation_window: Option<u64>,
}

/// Locks funds from an account for transaction preparation.
///
/// This endpoint reserves UTXOs totaling at least the requested amount,
/// preventing them from being used in other transactions. This is typically
/// the first step in creating a transaction, ensuring funds are available
/// and reserved before constructing the transaction.
///
/// # Path Parameters
///
/// - `name`: The account name to lock funds from
///
/// # Request Body
///
/// See [`LockFundsRequest`] for the complete request schema.
///
/// # Response
///
/// Returns a [`LockFundsResult`] containing:
/// - The selected UTXOs to use as inputs
/// - Whether a change output is required
/// - Total value of locked UTXOs
/// - Fee estimates with and without change
///
/// # Errors
///
/// - [`ApiError::AccountNotFound`]: The specified account does not exist
/// - [`ApiError::FailedToLockFunds`]: Insufficient funds or UTXO selection failure
/// - [`ApiError::DbError`]: Database connection or query failure
///
/// # Example
///
/// ```bash
/// curl -X POST http://127.0.0.1:9000/accounts/default/lock_funds \
///   -H "Authorization: Bearer $MINOTARI_API_TOKEN" \
///   -H "Content-Type: application/json" \
///   -d '{"amount": 1000000, "num_outputs": 1}'
/// ```
///
/// # Notes
///
/// - Locked UTXOs are automatically released after the configured timeout
/// - Use the `idempotency_key` to safely retry failed requests
/// - The actual locked amount may exceed the requested amount due to UTXO granularity
#[utoipa::path(
    post,
    path = "/accounts/{name}/lock_funds",
    request_body = LockFundsRequest,
    responses(
        (status = 200, description = "Funds locked successfully", body = LockFundsResult),
        (status = 400, description = "Bad request", body = ApiError),
        (status = 404, description = "Account not found", body = ApiError),
        (status = 409, description = "Idempotency key reused for a different request", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    params(
        ("name" = String, Path, description = "Name of the account to lock funds from"),
    )
)]
pub async fn api_lock_funds(
    State(app_state): State<AppState>,
    Path(WalletParams { name }): Path<WalletParams>,
    Json(body): Json<LockFundsRequest>,
) -> Result<Json<LockFundsResult>, ApiError> {
    info!(
        target: "audit",
        account = &*name,
        amount = &*mask_amount(body.amount.0.into()),
        idempotency_key:? = body.idempotency_key;
        "API: Lock funds request"
    );

    let pool = app_state.db_pool.clone();
    let name = name.clone();
    let default_confirmations = app_state.required_confirmations;

    // An explicit `null` in the body bypasses `#[serde(default)]`, so fall back
    // to the defaults here rather than unwrapping.
    let num_outputs = body.num_outputs.unwrap_or(DEFAULT_NUM_OUTPUTS);
    let fee_per_gram = body.fee_per_gram.unwrap_or(DEFAULT_FEE_PER_GRAM);
    let seconds_to_lock_utxos = body.seconds_to_lock_utxos.unwrap_or(DEFAULT_SECONDS_TO_LOCK_UTXOS);
    // Reject an out-of-range duration or a fee the node would not accept as a
    // client error before doing any work.
    validate_seconds_to_lock(seconds_to_lock_utxos)?;
    validate_fee_per_gram(fee_per_gram)?;

    let response = tokio::task::spawn_blocking(move || {
        // One connection for the whole request: the account lookup and the lock share it,
        // so nothing is held idle while `lock` waits on its mutex.
        let mut conn = pool.get().map_err(|e| ApiError::DbError(e.to_string()))?;

        let account = get_account_by_name(&conn, &name)
            .map_err(|e| ApiError::DbError(e.to_string()))?
            .ok_or_else(|| ApiError::AccountNotFound(name.clone()))?;

        let lock_amount = FundLocker::new();
        let confirmation_window = resolve_confirmation_window(body.confirmation_window, default_confirmations)?;
        // Every field below changes which UTXOs get reserved or for how long, so
        // all of them are bound to the key: a replay that alters any of them is
        // a different request and must not inherit this reservation.
        let idempotency = IdempotencyBinding::new(
            body.idempotency_key,
            IdempotencyOperation::LockFunds,
            RequestFingerprint::new(IdempotencyOperation::LockFunds)
                .field("account_id", account.id.to_le_bytes())
                .field("amount", body.amount.as_u64().to_le_bytes())
                .field("num_outputs", (num_outputs as u64).to_le_bytes())
                .field("fee_per_gram", fee_per_gram.as_u64().to_le_bytes())
                .optional_field(
                    "estimated_output_size",
                    body.estimated_output_size.map(|s| (s as u64).to_le_bytes()),
                )
                .field("seconds_to_lock_utxos", seconds_to_lock_utxos.to_le_bytes())
                .field("confirmation_window", confirmation_window.to_le_bytes()),
        );
        lock_amount
            .lock(
                &mut conn,
                account.id,
                body.amount,
                num_outputs,
                fee_per_gram,
                body.estimated_output_size,
                idempotency,
                seconds_to_lock_utxos,
                confirmation_window,
            )
            .map_err(|e| ApiError::from_transaction_error(e, ApiError::FailedToLockFunds))
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    Ok(Json(response))
}

/// Creates an unsigned one-sided transaction for external signing.
///
/// This endpoint constructs a complete transaction ready for signing, including
/// input selection, output creation, and fee calculation. The transaction is
/// returned in an unsigned state, allowing it to be signed by an external
/// key management system or hardware wallet.
///
/// # Path Parameters
///
/// - `name`: The account name to send funds from
///
/// # Request Body
///
/// See [`CreateTransactionRequest`] for the complete request schema.
///
/// # Response
///
/// Returns a JSON object containing the unsigned transaction data, including:
/// - Transaction inputs (selected UTXOs)
/// - Transaction outputs (recipient outputs and change)
/// - Fee information
/// - Data required for signing
///
/// # Errors
///
/// - [`ApiError::AccountNotFound`]: The specified account does not exist
/// - [`ApiError::FailedToLockFunds`]: Insufficient funds or UTXO selection failure
/// - [`ApiError::FailedCreateUnsignedTx`]: Transaction construction failure
/// - [`ApiError::DbError`]: Database connection or query failure
///
/// # Example
///
/// ```bash
/// curl -X POST http://127.0.0.1:9000/accounts/default/create_unsigned_transaction \
///   -H "Authorization: Bearer $MINOTARI_API_TOKEN" \
///   -H "Content-Type: application/json" \
///   -d '{
///     "recipients": [
///       {"address": "f4FxMqKAPDMqAjh6hTpC...", "amount": 1000000}
///     ]
///   }'
/// ```
///
/// # Workflow
///
/// 1. Client calls this endpoint to create an unsigned transaction
/// 2. Server locks required UTXOs and constructs the transaction
/// 3. Client signs the transaction externally
/// 4. Client broadcasts the signed transaction to the network
///
/// # Notes
///
/// - This creates a one-sided transaction (no recipient interaction required)
/// - UTXOs are automatically locked for the configured duration
/// - Fee is calculated at 5 MicroMinotari per gram
/// - Change outputs are created automatically when necessary
#[utoipa::path(
    post,
    path = "/accounts/{name}/create_unsigned_transaction",
    request_body = CreateTransactionRequest,
    responses(
        (status = 200, description = "Unsigned transaction created successfully", body = JsonValue),
        (status = 400, description = "Bad request", body = ApiError),
        (status = 404, description = "Account not found", body = ApiError),
        (status = 409, description = "Idempotency key reused for a different request", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    params(
        ("name" = String, Path, description = "Name of the account to create transaction for"),
    )
)]
pub async fn api_create_unsigned_transaction(
    State(app_state): State<AppState>,
    Path(WalletParams { name }): Path<WalletParams>,
    Json(body): Json<CreateTransactionRequest>,
) -> Result<Json<JsonValue>, ApiError> {
    info!(
        target: "audit",
        account = &*name,
        recipient_count = body.recipients.len(),
        idempotency_key:? = body.idempotency_key;
        "API: Create unsigned transaction request"
    );

    let pool = app_state.db_pool.clone();
    let name = name.clone();
    let network = app_state.network;
    let password = app_state.password.clone();
    let default_confirmations = app_state.required_confirmations;

    let recipients: Vec<Recipient> = body
        .recipients
        .iter()
        .map(|r| Recipient {
            address: r.address.0.clone(),
            amount: r.amount,
            payment_id: r.payment_id.clone(),
        })
        .collect();

    let seconds_to_lock_utxos = body.seconds_to_lock_utxos.unwrap_or(DEFAULT_SECONDS_TO_LOCK_UTXOS);
    // Reject an out-of-range duration as a client error before doing any work.
    validate_seconds_to_lock(seconds_to_lock_utxos)?;

    let result = tokio::task::spawn_blocking(move || {
        // One connection for the whole request; see `api_lock_funds`.
        let mut conn = pool.get().map_err(|e| ApiError::DbError(e.to_string()))?;

        let account = get_account_by_name(&conn, &name)
            .map_err(|e| ApiError::DbError(e.to_string()))?
            .ok_or_else(|| ApiError::AccountNotFound(name.clone()))?;

        let amount = recipients.iter().map(|r| r.amount).sum();
        let num_outputs = recipients.len();
        let fee_per_gram = DEFAULT_FEE_PER_GRAM;
        // Checked before locking: a payment id that cannot fit would otherwise fail the build
        // with the funds reserved. It is the request's payment id or address at fault, so a 400.
        let sender_address = account
            .get_address(network, &password)
            .map_err(|e| ApiError::FailedCreateUnsignedTx(e.to_string()))?;
        let estimated_output_size = Some(
            check_memos_and_estimate_output_size(&recipients, &sender_address)
                .map_err(|e| ApiError::BadRequest(e.to_string()))?,
        );

        let confirmation_window = resolve_confirmation_window(body.confirmation_window, default_confirmations)?;
        // Bind the key to the recipients this request names. A replay carrying
        // different recipients is rejected here rather than being handed the
        // original request's locked UTXOs to pay them out of.
        let idempotency = unsigned_transaction_binding(
            body.idempotency_key,
            account.id,
            &recipients,
            fee_per_gram,
            seconds_to_lock_utxos,
            confirmation_window,
        );
        let lock_amount = FundLocker::new();
        let locked_funds = lock_amount
            .lock(
                &mut conn,
                account.id,
                amount,
                num_outputs,
                fee_per_gram,
                estimated_output_size,
                idempotency,
                seconds_to_lock_utxos,
                confirmation_window,
            )
            .map_err(|e| ApiError::from_transaction_error(e, ApiError::FailedToLockFunds))?;
        let one_sided_tx = OneSidedTransaction::new(pool, network, password);
        one_sided_tx
            .create_unsigned_transaction(&account, locked_funds, recipients, fee_per_gram)
            .map_err(|e| ApiError::FailedCreateUnsignedTx(e.to_string()))
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    Ok(Json(serde_json::to_value(result)?))
}
