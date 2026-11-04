//! Wallet events endpoint handler.

use axum::{
    Json,
    extract::{Path, Query, State},
};
use log::trace;

use crate::{
    api::{AppState, error::ApiError},
    db::{DbWalletEvent, get_account_by_name, get_events_by_account_id},
};

use super::params::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, PaginationParams, WalletParams};

/// Retrieves wallet events for a specified account with pagination.
///
/// Returns a paginated list of events that have occurred for the account, including
/// output detection, confirmation, transaction broadcasts, and blockchain
/// reorganizations. Events are ordered by creation time (most recent first).
///
/// # Path Parameters
///
/// - `name`: The unique account name to query
///
/// # Query Parameters
///
/// - `limit`: Maximum number of events to return (default: 50, max: 1000)
/// - `offset`: Number of events to skip for pagination (default: 0)
///
/// # Response
///
/// Returns a list of [`DbWalletEvent`] objects, each containing:
/// - Event ID and type
/// - Human-readable description
/// - JSON data with event-specific details
/// - Creation timestamp
///
/// # Errors
///
/// - [`ApiError::AccountNotFound`]: The specified account does not exist
/// - [`ApiError::DbError`]: Database connection or query failure
///
/// # Example Request
///
/// ```bash
/// # Get first 50 events (default)
/// curl -X GET http://127.0.0.1:9000/accounts/default/events \
///   -H "Authorization: Bearer $MINOTARI_API_TOKEN"
///
/// # Get 100 events starting from offset 50
/// curl -X GET "http://127.0.0.1:9000/accounts/default/events?limit=100&offset=50" \
///   -H "Authorization: Bearer $MINOTARI_API_TOKEN"
/// ```
///
/// # Example Response
///
/// ```json
/// [
///   {
///     "id": 42,
///     "account_id": 1,
///     "event_type": "OutputDetected",
///     "description": "Detected output at height 12345",
///     "data_json": "{\"hash\":\"abc...\",\"block_height\":12345}",
///     "created_at": "2024-01-15T10:30:00"
///   }
/// ]
/// ```
#[utoipa::path(
    get,
    path = "/accounts/{name}/events",
    responses(
        (status = 200, description = "Account events retrieved successfully", body = Vec<DbWalletEvent>),
        (status = 404, description = "Account not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    params(
        ("name" = String, Path, description = "Name of the account to retrieve events for"),
        ("limit" = Option<i64>, Query, description = "Maximum number of events to return (default: 50, max: 1000)"),
        ("offset" = Option<i64>, Query, description = "Number of events to skip for pagination (default: 0)"),
    )
)]
pub async fn api_get_events(
    State(app_state): State<AppState>,
    Path(WalletParams { name }): Path<WalletParams>,
    Query(pagination): Query<PaginationParams>,
) -> Result<Json<Vec<DbWalletEvent>>, ApiError> {
    // Apply defaults and constraints
    let limit = pagination.limit.unwrap_or(DEFAULT_PAGE_LIMIT).min(MAX_PAGE_LIMIT);
    let offset = pagination.offset.unwrap_or(0).max(0);

    trace!(
        account = &*name,
        limit = limit,
        offset = offset;
        "API: Get events request"
    );

    let pool = app_state.db_pool.clone();
    let name = name.clone();

    let events = tokio::task::spawn_blocking(move || {
        let conn = pool.get().map_err(|e| ApiError::DbError(e.to_string()))?;

        let account = get_account_by_name(&conn, &name)
            .map_err(|e| ApiError::DbError(e.to_string()))?
            .ok_or_else(|| ApiError::AccountNotFound(name.clone()))?;

        get_events_by_account_id(&conn, account.id, limit, offset).map_err(|e| ApiError::DbError(e.to_string()))
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    Ok(Json(events))
}
