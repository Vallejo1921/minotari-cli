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
//! # OpenAPI Documentation
//!
//! The API is fully documented using the OpenAPI 3.0 specification via the `utoipa` crate.
//! All endpoints, request/response schemas, and error types are automatically included in
//! the generated documentation accessible through Swagger UI.
//!
//! # Usage Example
//!
//! ```ignore
//! use minotari::api::create_router;
//! use minotari::init_db;
//! use tari_common::configuration::Network;
//! use std::path::PathBuf;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let db_pool = init_db(PathBuf::from("wallet.db"))?;
//! let network = Network::Esmeralda;
//! let password = "secure_password".to_string();
//!
//! let router = create_router(db_pool, network, password);
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
//! - The password stored in [`AppState`] is used to decrypt wallet keys for transaction operations
//! - Fund locking prevents double-spending by temporarily reserving UTXOs
//! - Idempotency keys can be used to prevent duplicate operations
//! - All API errors are properly typed and do not leak sensitive information

use axum::{Router, extract::FromRef, routing::get, routing::post};
use log::info;
use tari_common::configuration::Network;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::db::SqlitePool;

pub mod accounts;
mod error;
pub mod types;

/// Application state shared across all API handlers.
///
/// This state is cloned for each request and provides access to the database,
/// network configuration, and wallet password for decrypting keys.
///
/// # Fields
///
/// * `db_pool` - SQLite connection pool for database operations
/// * `network` - Tari network configuration (Esmeralda, Nextnet, Mainnet, etc.)
/// * `password` - Password for decrypting wallet keys (stored in memory)
#[derive(Clone)]
pub struct AppState {
    pub db_pool: SqlitePool,
    pub network: Network,
    pub password: String,
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
    tags(
        (name = "minotari-cli", description = "Minotari CLI API"),
    )
)]
pub struct ApiDoc;

/// Creates and configures the API router with all endpoints and middleware.
///
/// This function sets up the complete Axum router with:
/// - All API endpoints for account operations
/// - Swagger UI at `/swagger-ui` for interactive API documentation
/// - OpenAPI specification at `/openapi.json`
/// - Shared application state containing database pool, network, and password
///
/// # Parameters
///
/// * `db_pool` - SQLite connection pool for database access
/// * `network` - Tari network configuration (Esmeralda, Nextnet, Mainnet, etc.)
/// * `password` - Password for decrypting wallet keys (kept in memory for API operations)
///
/// # Returns
///
/// An Axum `Router` ready to be served with `axum::serve()`.
///
/// # Example
///
/// ```ignore
/// use minotari::api::create_router;
/// use minotari::init_db;
/// use tari_common::configuration::Network;
/// use std::path::PathBuf;
///
/// # async fn example() -> anyhow::Result<()> {
/// let db_pool = init_db(PathBuf::from("wallet.db"))?;
/// let router = create_router(db_pool, Network::Esmeralda, "password".to_string(), 3);
///
/// let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
/// axum::serve(listener, router).await?;
/// # Ok(())
/// # }
/// ```
pub fn create_router(
    db_pool: SqlitePool,
    network: Network,
    password: String,
    required_confirmations: u64,
    base_node_url: String,
) -> Router {
    info!(
        network:% = network;
        "Creating API router"
    );

    let app_state = AppState {
        db_pool,
        network,
        password,
        required_confirmations,
        base_node_url,
    };

    Router::new()
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
        .with_state(app_state)
}
