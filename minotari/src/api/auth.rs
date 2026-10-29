//! Authentication for the wallet REST API.
//!
//! By default every endpoint served by the daemon - including the OpenAPI
//! document and the Swagger UI - is behind a bearer token. The API can move
//! funds (burn, lock, build transactions) and exposes the full financial history
//! of the wallet, so it must not be reachable by an unauthenticated caller on the
//! LAN or the internet.
//!
//! # Presenting the token
//!
//! Either of these headers is accepted:
//!
//! ```text
//! Authorization: Bearer <token>
//! X-API-Key: <token>
//! ```
//!
//! Anything else is answered with `401 Unauthorized` before the request reaches
//! a handler.
//!
//! # Where the token comes from
//!
//! [`resolve_api_token`] picks the first of:
//!
//! 1. `--api-token` on the command line,
//! 2. the `MINOTARI_API_TOKEN` environment variable,
//! 3. `api_token` in the `[wallet]` section of `config.toml`,
//! 4. a freshly generated random token, printed to stderr at startup.
//!
//! # Disabling authentication
//!
//! `--api-disable-auth` (or `api_disable_auth = true` in `config.toml`) drops the
//! token check entirely, leaving every endpoint (including the fund-moving ones)
//! open to anyone who can reach the port. It defaults to `false` and is only
//! appropriate for local development against a throwaway wallet. Combined with a
//! non-loopback `api_bind_address` it hands the wallet to the whole network, so
//! the daemon warns loudly on both stderr and the audit log when it is used.

use std::env;

use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use log::warn;
use rand::{Rng, distributions::Alphanumeric, thread_rng};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

/// Environment variable read by [`resolve_api_token`].
pub const API_TOKEN_ENV_VAR: &str = "MINOTARI_API_TOKEN";

/// Header accepted as an alternative to `Authorization: Bearer <token>`.
pub const API_KEY_HEADER: &str = "x-api-key";

/// Shortest token accepted from an operator. Generated tokens are longer.
pub const MIN_TOKEN_LEN: usize = 16;

/// Length of a generated token, in alphanumeric characters (~190 bits).
const GENERATED_TOKEN_LEN: usize = 32;

/// Errors produced while configuring the API token.
#[derive(Debug, Error)]
pub enum ApiTokenError {
    #[error(
        "API token is too short: {0} characters, minimum is {min}. Use a long random token, or omit it entirely and \
         one will be generated for you.",
        min = MIN_TOKEN_LEN
    )]
    TooShort(usize),
}

/// A configured API token, held as a SHA-256 digest rather than in the clear.
///
/// Comparison against a presented token is done over the digests in constant
/// time, so a caller cannot learn the token byte-by-byte from response timings.
#[derive(Clone)]
pub struct ApiToken {
    digest: [u8; 32],
}

impl std::fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the digest: it is a verifier for a low-entropy-by-comparison
        // secret and logging it would let an observer brute-force the token offline.
        f.write_str("ApiToken(<redacted>)")
    }
}

impl ApiToken {
    /// Creates a token from an operator-supplied secret.
    ///
    /// # Errors
    ///
    /// Returns [`ApiTokenError::TooShort`] if the secret is shorter than
    /// [`MIN_TOKEN_LEN`] characters.
    /// Surrounding whitespace is stripped before the secret is hashed, matching
    /// the trim applied to presented tokens. A stray space or newline in the
    /// config file or environment would otherwise make every request fail with
    /// nothing to point at.
    pub fn new(token: &str) -> Result<Self, ApiTokenError> {
        let token = token.trim();
        if token.len() < MIN_TOKEN_LEN {
            return Err(ApiTokenError::TooShort(token.len()));
        }
        Ok(Self::from_secret(token))
    }

    /// Generates a random token, returning the verifier and the plaintext.
    ///
    /// The plaintext is the only copy: it must be shown to the operator once
    /// and is zeroized when dropped.
    pub fn generate() -> (Self, Zeroizing<String>) {
        let token: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(GENERATED_TOKEN_LEN)
            .map(char::from)
            .collect();
        let token = Zeroizing::new(token);
        (Self::from_secret(&token), token)
    }

    fn from_secret(token: &str) -> Self {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&Sha256::digest(token.as_bytes()));
        Self { digest }
    }

    /// Constant-time check of a presented token against the configured one.
    pub fn matches(&self, presented: &str) -> bool {
        let presented = Sha256::digest(presented.as_bytes());
        presented[..].ct_eq(&self.digest[..]).into()
    }
}

/// Whether the API checks a token, and which one.
///
/// Modelled as an enum rather than an `Option<ApiToken>` so that serving the API
/// without authentication is always a deliberate, greppable choice and never the
/// result of a `None` slipping through.
#[derive(Debug, Clone)]
pub enum ApiAuth {
    /// Every request must present [`ApiToken`]. This is the default.
    Required(ApiToken),
    /// The token check is switched off; every endpoint answers anyone who can
    /// reach the port. Only ever set from an explicit operator opt-in.
    Disabled,
}

impl ApiAuth {
    /// Whether the token check is switched off.
    pub fn is_disabled(&self) -> bool {
        matches!(self, ApiAuth::Disabled)
    }
}

/// Resolves the API token from the CLI argument, the environment, or the config
/// file, generating one if none was supplied.
///
/// The second element of the returned pair is `Some` only when a token was
/// generated; the caller is expected to show it to the operator, since it is
/// otherwise unrecoverable.
///
/// # Errors
///
/// Returns [`ApiTokenError::TooShort`] if the configured token is too short. A
/// weak token is treated as a configuration error rather than silently
/// accepted, because the API it guards can spend funds.
pub fn resolve_api_token(
    cli_token: Option<&str>,
    config_token: Option<&str>,
) -> Result<(ApiToken, Option<Zeroizing<String>>), ApiTokenError> {
    let env_token = env::var(API_TOKEN_ENV_VAR).ok();
    resolve_from_sources(cli_token, env_token.as_deref(), config_token)
}

/// The precedence rule itself, with the environment passed in so it can be
/// exercised without mutating process-wide state.
fn resolve_from_sources(
    cli_token: Option<&str>,
    env_token: Option<&str>,
    config_token: Option<&str>,
) -> Result<(ApiToken, Option<Zeroizing<String>>), ApiTokenError> {
    match cli_token.or(env_token).or(config_token) {
        Some(token) => Ok((ApiToken::new(token)?, None)),
        None => {
            let (token, plaintext) = ApiToken::generate();
            Ok((token, Some(plaintext)))
        },
    }
}

/// Axum middleware that rejects any request without a valid API token.
///
/// Applied to the whole router, so it also covers `/openapi.json` and the
/// Swagger UI - endpoint discovery is not free to an anonymous caller.
pub async fn require_api_token(State(token): State<ApiToken>, request: Request, next: Next) -> Response {
    let presented = presented_token(request.headers());

    match presented {
        Some(presented) if token.matches(&presented) => next.run(request).await,
        Some(_) => {
            warn!(
                target: "audit",
                method:% = request.method(),
                path = request.uri().path();
                "API: rejected request with an invalid API token"
            );
            unauthorized("Invalid API token")
        },
        None => {
            warn!(
                target: "audit",
                method:% = request.method(),
                path = request.uri().path();
                "API: rejected request with no API token"
            );
            unauthorized("Missing API token. Send 'Authorization: Bearer <token>' or 'X-API-Key: <token>'.")
        },
    }
}

/// Extracts the token from `Authorization: Bearer <token>` or `X-API-Key`.
fn presented_token(headers: &HeaderMap) -> Option<Zeroizing<String>> {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(strip_bearer_prefix);

    let token = match bearer {
        Some(token) => token,
        None => headers.get(API_KEY_HEADER).and_then(|value| value.to_str().ok())?,
    };

    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    Some(Zeroizing::new(token.to_string()))
}

/// Strips a case-insensitive `Bearer ` scheme prefix, per RFC 7235.
fn strip_bearer_prefix(value: &str) -> Option<&str> {
    let value = value.trim_start();
    let (scheme, rest) = value.split_at_checked(6)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    if !rest.starts_with(' ') {
        return None;
    }
    Some(rest.trim_start())
}

fn unauthorized(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        Json(json!({ "error": message })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, http::Request, routing::get};
    use tower::ServiceExt;

    const TEST_TOKEN: &str = "test-token-0123456789";

    fn test_router() -> Router {
        let token = ApiToken::new(TEST_TOKEN).unwrap();
        Router::new()
            .route("/protected", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(token, require_api_token))
    }

    async fn status_for(request: Request<Body>) -> StatusCode {
        test_router().oneshot(request).await.unwrap().status()
    }

    #[test]
    fn token_shorter_than_the_minimum_is_rejected() {
        assert!(matches!(ApiToken::new("short"), Err(ApiTokenError::TooShort(5))));
        assert!(ApiToken::new(&"a".repeat(MIN_TOKEN_LEN)).is_ok());
    }

    #[test]
    fn only_the_configured_token_matches() {
        let token = ApiToken::new(TEST_TOKEN).unwrap();
        assert!(token.matches(TEST_TOKEN));
        assert!(!token.matches("test-token-012345678"));
        assert!(!token.matches("test-token-0123456789 "));
        assert!(!token.matches(""));
    }

    #[test]
    fn surrounding_whitespace_in_the_configured_token_is_ignored() {
        // Presented tokens are trimmed, so a configured token with stray
        // whitespace has to be trimmed too or it could never be matched.
        let token = ApiToken::new(&format!("  {TEST_TOKEN}\n")).unwrap();
        assert!(token.matches(TEST_TOKEN));

        // Trimming applies to the length check as well, so padding cannot be
        // used to sneak a short token past the minimum.
        assert!(matches!(ApiToken::new("  short  "), Err(ApiTokenError::TooShort(5))));
    }

    #[test]
    fn generated_tokens_are_random_and_long_enough() {
        let (first, first_plain) = ApiToken::generate();
        let (_, second_plain) = ApiToken::generate();
        assert_eq!(first_plain.len(), GENERATED_TOKEN_LEN);
        assert_ne!(*first_plain, *second_plain);
        assert!(first.matches(&first_plain));
        assert!(!first.matches(&second_plain));
    }

    #[test]
    fn debug_output_does_not_leak_the_token() {
        let token = ApiToken::new(TEST_TOKEN).unwrap();
        assert_eq!(format!("{:?}", token), "ApiToken(<redacted>)");
    }

    #[test]
    fn resolution_prefers_cli_then_environment_then_config() {
        let env_token = "env-token-0123456789";
        let config_token = "config-token-0123456789";

        let (token, generated) = resolve_from_sources(Some(TEST_TOKEN), Some(env_token), Some(config_token)).unwrap();
        assert!(token.matches(TEST_TOKEN));
        assert!(generated.is_none());

        let (token, _) = resolve_from_sources(None, Some(env_token), Some(config_token)).unwrap();
        assert!(token.matches(env_token));

        let (token, _) = resolve_from_sources(None, None, Some(config_token)).unwrap();
        assert!(token.matches(config_token));
    }

    #[test]
    fn a_token_is_generated_when_none_is_configured() {
        let (token, generated) = resolve_from_sources(None, None, None).unwrap();
        let generated = generated.expect("a token should have been generated");
        assert!(token.matches(&generated));
    }

    #[test]
    fn a_weak_configured_token_is_a_configuration_error() {
        assert!(resolve_from_sources(None, None, Some("weak")).is_err());
        assert!(resolve_from_sources(None, Some("weak"), None).is_err());
        assert!(resolve_from_sources(Some("weak"), None, None).is_err());
    }

    #[tokio::test]
    async fn requests_without_a_token_are_rejected() {
        let request = Request::builder().uri("/protected").body(Body::empty()).unwrap();
        assert_eq!(status_for(request).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn requests_with_a_wrong_token_are_rejected() {
        let request = Request::builder()
            .uri("/protected")
            .header(header::AUTHORIZATION, "Bearer not-the-right-token")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_for(request).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bearer_scheme_is_case_insensitive() {
        for scheme in ["Bearer", "bearer", "BEARER"] {
            let request = Request::builder()
                .uri("/protected")
                .header(header::AUTHORIZATION, format!("{scheme} {TEST_TOKEN}"))
                .body(Body::empty())
                .unwrap();
            assert_eq!(status_for(request).await, StatusCode::OK, "scheme {scheme}");
        }
    }

    #[tokio::test]
    async fn the_api_key_header_is_accepted() {
        let request = Request::builder()
            .uri("/protected")
            .header(API_KEY_HEADER, TEST_TOKEN)
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_for(request).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_non_bearer_authorization_header_is_rejected() {
        let request = Request::builder()
            .uri("/protected")
            .header(header::AUTHORIZATION, format!("Basic {TEST_TOKEN}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_for(request).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unauthorized_responses_advertise_the_scheme() {
        let request = Request::builder().uri("/protected").body(Body::empty()).unwrap();
        let response = test_router().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
    }
}
