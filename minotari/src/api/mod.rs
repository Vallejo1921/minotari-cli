//! RESTful HTTP API for wallet operations.
//!
//! This module provides a web API for interacting with the Minotari wallet, including
//! balance queries, fund locking, and unsigned transaction creation. The API is documented
//! using OpenAPI (Swagger) specifications and includes interactive documentation.
//!
//! # API Endpoints
//!
//! The API exposes the following endpoints:
//!
//! - `GET /version` - Retrieve wallet version information
//! - `GET /accounts/{name}/balance` - Retrieve account balance
//! - `GET /accounts/{name}/address` - Retrieve account Tari address
//! - `POST /accounts/{name}/address_with_payment_id` - Create address with embedded payment ID
//! - `GET /accounts/{name}/scan_status` - Retrieve last scanned block height and timestamp
//! - `GET /accounts/{name}/events` - Retrieve all wallet events for an account
//! - `GET /accounts/{name}/completed_transactions` - Retrieve all completed transactions for an account
//! - `GET /accounts/{name}/completed_transactions/by_payref/{payref}` - Retrieve completed transaction by payment reference
//! - `GET /accounts/{name}/displayed_transactions` - Retrieve all displayed transactions for an account
//! - `GET /accounts/{name}/displayed_transactions/by_payref/{payref}` - Retrieve displayed transactions by payment reference
//! - `POST /accounts/{name}/lock_funds` - Lock UTXOs for transaction creation
//! - `POST /accounts/{name}/create_unsigned_transaction` - Create an unsigned one-sided transaction
//! - `GET /swagger-ui` - Interactive Swagger UI documentation
//! - `GET /openapi.json` - OpenAPI specification in JSON format
//!
//! # Authentication
//!
//! Every route above requires the daemon's API token, sent as `Authorization: Bearer <token>`
//! or `X-API-Key: <token>`; see [`auth`]. Requests without a valid token are answered with
//! `401 Unauthorized` before any handler runs. Operators can opt out entirely with
//! `--api-disable-auth`, which is off by default.
//!
//! # OpenAPI Documentation
//!
//! The API is fully documented using the OpenAPI 3.0 specification via the `utoipa` crate.
//! All endpoints, request/response schemas, and error types are automatically included in
//! the generated documentation accessible through Swagger UI.
//!
//! # Usage Example
//!
//! ```ignore
//! use minotari::api::{create_router, resolve_api_token};
//! use minotari::init_db;
//! use tari_common::configuration::Network;
//! use std::path::PathBuf;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let db_pool = init_db(PathBuf::from("wallet.db"))?;
//! let network = Network::Esmeralda;
//! let password = zeroize::Zeroizing::new("secure_password".to_string());
//! // `generated` is `Some` when no token was configured - show it to the operator.
//! let (api_token, generated) = resolve_api_token(None, None)?;
//!
//! let router = create_router(db_pool, network, password, 3, "https://rpc.tari.com".to_string(), api_token);
//!
//! // Serve with axum
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
//! axum::serve(listener, router).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Security Considerations
//!
//! - **Every route requires an API token by default**, including `/openapi.json` and the Swagger UI.
//!   The API can spend funds and exposes the full financial history of the wallet, so it should not
//!   answer an unauthenticated caller. See [`auth`] for how the token is configured and presented,
//!   and for the `--api-disable-auth` opt-out.
//! - The daemon binds loopback by default; binding a routable interface exposes the API to the network
//!   and should only be done behind a reverse proxy that terminates TLS.
//! - The password stored in [`AppState`] is used to decrypt wallet keys for transaction operations
//! - Fund locking prevents double-spending by temporarily reserving UTXOs
//! - Idempotency keys can be used to prevent duplicate operations
//! - All API errors are properly typed and do not leak sensitive information

use axum::{Router, extract::FromRef, middleware, routing::get, routing::post};
use log::info;
use tari_common::configuration::Network;
use utoipa::{
    Modify, OpenApi,
    openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme},
};
use utoipa_swagger_ui::SwaggerUi;
use zeroize::Zeroizing;

use crate::db::SqlitePool;

pub mod accounts;
pub mod auth;
mod error;
pub mod types;

pub use auth::{ApiAuth, ApiToken, ApiTokenError, resolve_api_token};

/// Application state shared across all API handlers.
///
/// This state is cloned for each request and provides access to the database,
/// network configuration, and wallet password for decrypting keys.
///
/// # Fields
///
/// * `db_pool` - SQLite connection pool for database operations
/// * `network` - Tari network configuration (Esmeralda, Nextnet, Mainnet, etc.)
/// * `password` - Password for decrypting wallet keys (held in memory for the daemon's
///   lifetime, so it is kept in a buffer that wipes itself when the state is dropped)
#[derive(Clone)]
pub struct AppState {
    pub db_pool: SqlitePool,
    pub network: Network,
    pub password: Zeroizing<String>,
    pub required_confirmations: u64,
    pub base_node_url: String,
}

impl FromRef<AppState> for SqlitePool {
    fn from_ref(state: &AppState) -> Self {
        state.db_pool.clone()
    }
}

/// OpenAPI documentation structure for the Minotari wallet API.
///
/// This struct is used by `utoipa` to generate the complete OpenAPI specification,
/// which includes all API endpoints, request/response schemas, and component definitions.
///
/// The generated specification is served at `/openapi.json` and powers the Swagger UI
/// at `/swagger-ui`.
///
/// # Registered Components
///
/// ## Paths (Endpoints)
/// - `/version` - Get wallet version information
/// - `/accounts/{name}/balance` - Get account balance
/// - `/accounts/{name}/address` - Get account address
/// - `/accounts/{name}/address_with_payment_id` - Create address with payment ID
/// - `/accounts/{name}/scan_status` - Get last scanned block info
/// - `/accounts/{name}/events` - Get wallet events
/// - `/accounts/{name}/completed_transactions` - Get completed transactions
/// - `/accounts/{name}/completed_transactions/by_payref/{payref}` - Get completed transaction by payment reference
/// - `/accounts/{name}/displayed_transactions` - Get displayed transactions
/// - `/accounts/{name}/displayed_transactions/by_payref/{payref}` - Get displayed transactions by payment reference
/// - `/accounts/{name}/lock_funds` - Lock funds for transaction
/// - `/accounts/{name}/create_unsigned_transaction` - Create unsigned transaction
///
/// ## Schemas
/// - `VersionResponse` - Wallet version information
/// - `AccountBalance` - Balance information with available/pending amounts
/// - `AddressResponse` - Account address in Base58 with emoji ID
/// - `AddressWithPaymentIdResponse` - Address with embedded payment ID
/// - `DbWalletEvent` - Wallet event record with type, description and data
/// - `CompletedTransactionResponse` - Completed transaction details
/// - `ApiError` - Standardized error responses
/// - `WalletParams` - Account name path parameter
/// - `LockFundsRequest` - Request body for fund locking
/// - `CreateTransactionRequest` - Request body for transaction creation
/// - `RecipientRequest` - Transaction recipient details
/// - `LockFundsResult` - Response from fund locking operation
/// - `TariAddressBase58` - Base58-encoded Tari address
/// - `FeeEstimateResponse` - Fee estimation result
/// - `FeePriorityResponse` - Fee priority enumeration
/// - `EstimateFeeRequest` - Request body for fee estimation
#[derive(OpenApi)]
#[openapi(
    paths(
        accounts::api_get_version,
        accounts::api_get_balance,
        accounts::api_get_address,
        accounts::api_create_address_with_payment_id,
        accounts::api_get_scan_status,
        accounts::api_get_events,
        accounts::api_get_completed_transactions,
        accounts::api_get_completed_transaction_by_payref,
        accounts::api_get_displayed_transactions,
        accounts::api_get_displayed_transactions_by_payref,
        accounts::api_lock_funds,
        accounts::api_create_unsigned_transaction,
        accounts::api_estimate_fees,
        accounts::api_burn_funds,
        accounts::api_abandon_send,
    ),
    components(
        schemas(
            crate::db::AccountBalance,
            crate::db::DbWalletEvent,
            error::ApiError,
            accounts::WalletParams,
            accounts::LockFundsRequest,
            accounts::CreateTransactionRequest,
            accounts::CreatePaymentIdAddressRequest,
            accounts::RecipientRequest,
            accounts::EstimateFeeRequest,
            crate::api::types::LockFundsResult,
            crate::api::types::TariAddressBase58,
            crate::api::types::CompletedTransactionResponse,
            crate::api::types::ScanStatusResponse,
            crate::api::types::AddressResponse,
            crate::api::types::AddressWithPaymentIdResponse,
            crate::api::types::VersionResponse,
            crate::api::types::FeeEstimateResponse,
            crate::api::types::FeePriorityResponse,
            accounts::BurnFundsRequest,
            accounts::AbandonSendRequest,
            accounts::AbandonSendResponse,
            accounts::BurnFundsResponse,
            crate::transactions::DisplayedTransaction,
            crate::transactions::TransactionDirection,
            crate::transactions::TransactionSource,
            crate::transactions::TransactionDisplayStatus,
            crate::transactions::CounterpartyInfo,
            crate::transactions::BlockchainInfo,
            crate::transactions::FeeInfo,
            crate::transactions::TransactionDetails,
            crate::transactions::TransactionInput,
            crate::transactions::TransactionOutput,
            crate::models::OutputStatus,
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "minotari-cli", description = "Minotari CLI API"),
    )
)]
pub struct ApiDoc;

/// Documents the API token requirement on every operation in the spec.
///
/// The two schemes are alternatives: a request satisfying either one is
/// authenticated, matching what [`auth::require_api_token`] enforces.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some("Wallet API token, sent as 'Authorization: Bearer <token>'"))
                    .build(),
            ),
        );
        components.add_security_scheme(
            "api_key",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                "X-API-Key",
                "Wallet API token, sent as 'X-API-Key: <token>'",
            ))),
        );
        openapi.security = Some(vec![
            utoipa::openapi::security::SecurityRequirement::new("bearer_token", Vec::<String>::new()),
            utoipa::openapi::security::SecurityRequirement::new("api_key", Vec::<String>::new()),
        ]);
    }
}

/// Creates and configures the API router with all endpoints and middleware.
///
/// This function sets up the complete Axum router with:
/// - All API endpoints for account operations
/// - Swagger UI at `/swagger-ui` for interactive API documentation
/// - OpenAPI specification at `/openapi.json`
/// - An API token check in front of every route, including the documentation routes,
///   unless the caller passes [`ApiAuth::Disabled`]
/// - Shared application state containing database pool, network, and password
///
/// # Parameters
///
/// * `db_pool` - SQLite connection pool for database access
/// * `network` - Tari network configuration (Esmeralda, Nextnet, Mainnet, etc.)
/// * `password` - Password for decrypting wallet keys (kept in memory for API operations)
/// * `required_confirmations` - Confirmations before an output is considered spendable
/// * `base_node_url` - Base node used to broadcast transactions
/// * `api_auth` - Token every caller must present, or [`ApiAuth::Disabled`]; see [`auth`]
///
/// # Returns
///
/// An Axum `Router` ready to be served with `axum::serve()`.
///
/// # Example
///
/// ```ignore
/// use minotari::api::{ApiAuth, create_router};
/// use minotari::init_db;
/// use tari_common::configuration::Network;
/// use std::path::PathBuf;
///
/// # async fn example() -> anyhow::Result<()> {
/// let db_pool = init_db(PathBuf::from("wallet.db"))?;
/// let (api_token, _generated) = minotari::api::resolve_api_token(None, None)?;
/// let router = create_router(
///     db_pool,
///     Network::Esmeralda,
///     Zeroizing::new("password".to_string()),
///     3,
///     "https://rpc.tari.com".to_string(),
///     ApiAuth::Required(api_token),
/// );
///
/// let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
/// axum::serve(listener, router).await?;
/// # Ok(())
/// # }
/// ```
pub fn create_router(
    db_pool: SqlitePool,
    network: Network,
    password: Zeroizing<String>,
    required_confirmations: u64,
    base_node_url: String,
    api_auth: ApiAuth,
) -> Router {
    info!(
        network:% = network,
        authenticated = !api_auth.is_disabled();
        "Creating API router"
    );

    let app_state = AppState {
        db_pool,
        network,
        password,
        required_confirmations,
        base_node_url,
    };

    let router = Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/openapi.json", ApiDoc::openapi()))
        .route("/version", get(accounts::api_get_version))
        .route("/accounts/{name}/balance", get(accounts::api_get_balance))
        .route("/accounts/{name}/address", get(accounts::api_get_address))
        .route(
            "/accounts/{name}/address_with_payment_id",
            post(accounts::api_create_address_with_payment_id),
        )
        .route("/accounts/{name}/scan_status", get(accounts::api_get_scan_status))
        .route("/accounts/{name}/events", get(accounts::api_get_events))
        .route(
            "/accounts/{name}/completed_transactions",
            get(accounts::api_get_completed_transactions),
        )
        .route(
            "/accounts/{name}/completed_transactions/by_payref/{payref}",
            get(accounts::api_get_completed_transaction_by_payref),
        )
        .route(
            "/accounts/{name}/displayed_transactions",
            get(accounts::api_get_displayed_transactions),
        )
        .route(
            "/accounts/{name}/displayed_transactions/by_payref/{payref}",
            get(accounts::api_get_displayed_transactions_by_payref),
        )
        .route("/accounts/{name}/lock_funds", post(accounts::api_lock_funds))
        .route(
            "/accounts/{name}/create_unsigned_transaction",
            post(accounts::api_create_unsigned_transaction),
        )
        .route("/accounts/{name}/estimate_fees", post(accounts::api_estimate_fees))
        .route("/accounts/{name}/burn", post(accounts::api_burn_funds))
        .route(
            "/accounts/{name}/completed_transactions/{tx_id}/abandon",
            post(accounts::api_abandon_send),
        );

    let router = match api_auth {
        // Layered last so it wraps every route above, the Swagger UI and `/openapi.json`
        // included: an anonymous caller cannot even enumerate the endpoints.
        ApiAuth::Required(token) => router.layer(middleware::from_fn_with_state(token, auth::require_api_token)),
        // Explicitly opted out of by the operator; the daemon warns about this at startup.
        ApiAuth::Disabled => router,
    };

    router.with_state(app_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use tower::ServiceExt;

    const TEST_TOKEN: &str = "router-test-token-0123456789";

    /// A router backed by a throwaway database. The `TempDir` is returned so the
    /// caller keeps it alive for the duration of the test.
    fn router_with(api_auth: ApiAuth) -> (Router, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db_pool = crate::db::init_db(dir.path().join("wallet.db")).unwrap();
        let router = create_router(
            db_pool,
            Network::LocalNet,
            Zeroizing::new("password".to_string()),
            3,
            "http://127.0.0.1:9999".to_string(),
            api_auth,
        );
        (router, dir)
    }

    fn router() -> (Router, tempfile::TempDir) {
        router_with(ApiAuth::Required(ApiToken::new(TEST_TOKEN).unwrap()))
    }

    async fn status_of(uri: &str, token: Option<&str>) -> StatusCode {
        let mut request = Request::builder().uri(uri);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let (router, _dir) = router();
        router
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    /// The OpenAPI document is an endpoint map for an API that can spend funds;
    /// it must not be readable without the token.
    #[tokio::test]
    async fn documentation_routes_require_the_token() {
        for uri in ["/openapi.json", "/swagger-ui/"] {
            assert_eq!(status_of(uri, None).await, StatusCode::UNAUTHORIZED, "{uri}");
            assert_ne!(
                status_of(uri, Some(TEST_TOKEN)).await,
                StatusCode::UNAUTHORIZED,
                "{uri}"
            );
        }
    }

    #[tokio::test]
    async fn wallet_routes_require_the_token() {
        for uri in [
            "/version",
            "/accounts/default/balance",
            "/accounts/default/address",
            "/accounts/default/events",
            "/accounts/default/completed_transactions",
            "/accounts/default/displayed_transactions",
        ] {
            assert_eq!(status_of(uri, None).await, StatusCode::UNAUTHORIZED, "{uri}");
            assert_eq!(
                status_of(uri, Some("wrong-token-0123456789")).await,
                StatusCode::UNAUTHORIZED,
                "{uri}"
            );
        }
    }

    #[tokio::test]
    async fn fund_moving_routes_require_the_token() {
        let body = r#"{"amount":1000,"claim_public_key":"00"}"#;
        for uri in [
            "/accounts/default/burn",
            "/accounts/default/lock_funds",
            "/accounts/default/create_unsigned_transaction",
        ] {
            let (router, _dir) = router();
            let response = router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(uri)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    #[tokio::test]
    async fn a_valid_token_reaches_the_handler() {
        assert_eq!(status_of("/version", Some(TEST_TOKEN)).await, StatusCode::OK);
    }

    /// The opt-out really does remove the check - otherwise operators who set it
    /// would be left guessing why their unauthenticated client still fails.
    #[tokio::test]
    async fn disabling_auth_serves_requests_without_a_token() {
        for uri in ["/version", "/openapi.json", "/accounts/default/events"] {
            let (router, _dir) = router_with(ApiAuth::Disabled);
            let status = router
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status();
            assert_ne!(status, StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    /// With auth disabled a stray `Authorization` header must not turn into a
    /// rejection, since nothing is being checked.
    #[tokio::test]
    async fn disabling_auth_ignores_any_presented_token() {
        let (router, _dir) = router_with(ApiAuth::Disabled);
        let status = router
            .oneshot(
                Request::builder()
                    .uri("/version")
                    .header(header::AUTHORIZATION, "Bearer irrelevant-token-value")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status();
        assert_eq!(status, StatusCode::OK);
    }
}
