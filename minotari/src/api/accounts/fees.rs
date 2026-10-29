//! Fee estimation endpoint handler.

use axum::{
    Json,
    extract::{Path, State},
};
use log::debug;
use serde::Deserialize;
use tari_transaction_components::tari_amount::MicroMinotari;

use crate::{
    api::{
        AppState,
        error::ApiError,
        types::{FeeEstimateResponse, FeePriorityResponse},
    },
    log::mask_amount,
    transactions::fee_estimator::{FeeEstimator, FeePriority},
};

use super::params::{WalletParams, confirmation_window_schema, resolve_confirmation_window};

fn default_one_usize() -> usize {
    1
}

// Request body for fee estimation.
///
/// Calculates estimated fees for a transaction based on current mempool conditions
/// and available UTXOs.
///
/// # JSON Example
///
/// ```json
/// {
///   "amount": 1000000,
///   "num_outputs": 2,
///   "estimated_output_size": 500
/// }
/// ```
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct EstimateFeeRequest {
    /// The amount to send in MicroMinotari.
    #[schema(value_type = u64)]
    pub amount: MicroMinotari,

    /// Number of outputs in the transaction (default: 1).
    #[serde(default = "default_one_usize")]
    #[schema(default = 1)]
    pub num_outputs: usize,

    /// Number of confirmations required for inputs.
    #[schema(schema_with = confirmation_window_schema)]
    pub confirmation_window: Option<u64>,

    /// Estimated size of each output in bytes.
    pub estimated_output_size: Option<usize>,
}

/// Estimates transaction fees based on current network conditions.
///
/// Calculates fee estimates for Slow, Medium, and Fast priority levels by analyzing
/// the mempool state and selecting appropriate UTXOs for the requested amount.
///
/// # Path Parameters
///
/// - `name`: The account name to estimate fees for
///
/// # Request Body
///
/// See [`EstimateFeeRequest`] for the complete request schema.
///
/// # Response
///
/// Returns a list of [`FeeEstimateResponse`] objects for different priorities.
///
/// # Errors
///
/// - [`ApiError::AccountNotFound`]: The specified account does not exist
/// - [`ApiError::InternalServerError`]: Failed to query base node or calculate fees
/// - [`ApiError::DbError`]: Database connection or query failure
///
/// # Example Request
///
/// ```bash
/// curl -X POST http://127.0.0.1:9000/accounts/default/estimate_fees \
///   -H "Authorization: Bearer $MINOTARI_API_TOKEN" \
///   -H "Content-Type: application/json" \
///   -d '{"amount": 1000000}'
/// ```
#[utoipa::path(
    post,
    path = "/accounts/{name}/estimate_fees",
    request_body = EstimateFeeRequest,
    responses(
        (status = 200, description = "Fees estimated successfully", body = Vec<FeeEstimateResponse>),
        (status = 400, description = "Bad request", body = ApiError),
        (status = 404, description = "Account not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    params(
        ("name" = String, Path, description = "Name of the account to estimate fees for"),
    )
)]
pub async fn api_estimate_fees(
    State(app_state): State<AppState>,
    Path(WalletParams { name }): Path<WalletParams>,
    Json(body): Json<EstimateFeeRequest>,
) -> Result<Json<Vec<FeeEstimateResponse>>, ApiError> {
    debug!(
        account = &*name,
        amount = &*mask_amount(body.amount.0.into());
        "API: Estimate fees request"
    );

    let pool = app_state.db_pool.clone();
    let base_url = app_state.base_node_url.clone();
    let default_confirmations = app_state.required_confirmations;
    let name = name.clone();

    let estimator = FeeEstimator::new(pool, base_url);
    let confirmation_window = resolve_confirmation_window(body.confirmation_window, default_confirmations)?;

    let estimates = estimator
        .estimate_fees(
            &name,
            body.amount,
            body.num_outputs,
            confirmation_window,
            body.estimated_output_size,
        )
        .await
        .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

    let response: Vec<FeeEstimateResponse> = estimates
        .into_iter()
        .map(|est| FeeEstimateResponse {
            priority: match est.priority {
                FeePriority::Slow => FeePriorityResponse::Slow,
                FeePriority::Medium => FeePriorityResponse::Medium,
                FeePriority::Fast => FeePriorityResponse::Fast,
            },
            fee_per_gram: est.fee_per_gram,
            estimated_fee: est.estimated_fee,
            total_amount_required: est.total_amount_required,
            input_count: est.input_count,
        })
        .collect();

    Ok(Json(response))
}
