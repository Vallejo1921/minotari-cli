//! Binding idempotency keys to the request that issued them.
//!
//! # Why a bare key is not enough
//!
//! An idempotency key on its own is just a client-chosen string. Every
//! fund-moving entry point in this wallet reaches [`FundLocker::lock`] with one,
//! and the lock short-circuits when a pending transaction for that key already
//! exists — handing back the UTXOs the *original* request reserved.
//!
//! If the key is not tied to the request that created it, that short-circuit is
//! an attack:
//!
//! * **Body swap.** Replay a client's key at `/create_unsigned_transaction`
//!   with different `recipients`. The cached lock is returned, the recipients
//!   are taken from the *replayed* body, and the wallet builds an unsigned
//!   transaction paying the attacker out of the victim's reserved UTXOs.
//! * **Operation swap.** The key namespace was shared across every endpoint, so
//!   a key issued at `/lock_funds` could be replayed at `/burn`. The burn takes
//!   the cached lock and broadcasts a burn — irreversibly destroying funds the
//!   client only meant to reserve.
//!
//! # The binding
//!
//! An [`IdempotencyBinding`] carries three things: the client's key, the
//! [`IdempotencyOperation`] it was issued for, and a [`RequestFingerprint`] over
//! every request field that determines what the wallet actually does. Both the
//! operation and the fingerprint are stored alongside the pending transaction.
//!
//! On replay the stored pair is compared with the incoming one. A key may only
//! short-circuit into a lock created by *the same operation with the same
//! parameters*; anything else is an [`IdempotencyConflict`] (HTTP 409), never a
//! silent hand-back of someone else's UTXOs.
//!
//! # Building a fingerprint
//!
//! Include every field that changes where the money goes or how much of it
//! moves. Omitting one re-opens the body-swap hole for that field, so err
//! towards including too much: the cost of an over-strict fingerprint is a
//! client having to pick a new key, and the cost of an under-strict one is
//! funds paid to an attacker.
//!
//! ```rust,ignore
//! let binding = IdempotencyBinding::new(
//!     body.idempotency_key,
//!     IdempotencyOperation::LockFunds,
//!     RequestFingerprint::new(IdempotencyOperation::LockFunds)
//!         .field("account_id", account.id.to_le_bytes())
//!         .field("amount", body.amount.as_u64().to_le_bytes())
//!         .field("num_outputs", num_outputs.to_le_bytes()),
//! );
//! ```
//!
//! [`FundLocker::lock`]: crate::transactions::fund_locker::FundLocker::lock

use std::fmt;

use tari_crypto::{hash_domain, hashing::DomainSeparatedHasher};
use tari_transaction_components::key_manager::wallet_types::KeyDigest;
use thiserror::Error;

hash_domain!(
    IdempotencyDomain,
    "com.tari.minotari_cli.idempotency_request_fingerprint",
    1
);

/// Label separating request fingerprints from any other use of the domain.
const REQUEST_FINGERPRINT_LABEL: &str = "request_fingerprint";

/// The operation an idempotency key was issued for.
///
/// Stored with the pending transaction so a key minted at one endpoint cannot
/// be redeemed at another. Without this, a `/lock_funds` key replayed at
/// `/burn` would short-circuit onto the reserved UTXOs and broadcast a burn
/// over them.
///
/// The string form is persisted, so existing variants' strings must not change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdempotencyOperation {
    /// `POST /accounts/{name}/lock_funds` and the `lock-funds` CLI command.
    LockFunds,
    /// `POST /accounts/{name}/create_unsigned_transaction` and the
    /// `create-unsigned-transaction` CLI command.
    CreateUnsignedTransaction,
    /// The full send flow driven by
    /// [`TransactionSender`](crate::transactions::manager::TransactionSender).
    SendTransaction,
    /// `POST /accounts/{name}/burn` and the `burn-funds` CLI command.
    BurnFunds,
    /// Validator node registration.
    ValidatorNodeRegistration,
    /// Validator node exit.
    ValidatorNodeExit,
}

impl IdempotencyOperation {
    /// The persisted form. Changing an existing string invalidates stored rows.
    pub const fn as_str(self) -> &'static str {
        match self {
            IdempotencyOperation::LockFunds => "lock_funds",
            IdempotencyOperation::CreateUnsignedTransaction => "create_unsigned_transaction",
            IdempotencyOperation::SendTransaction => "send_transaction",
            IdempotencyOperation::BurnFunds => "burn_funds",
            IdempotencyOperation::ValidatorNodeRegistration => "validator_node_registration",
            IdempotencyOperation::ValidatorNodeExit => "validator_node_exit",
        }
    }

    /// Human-readable name used in log lines and error messages.
    pub const fn description(self) -> &'static str {
        match self {
            IdempotencyOperation::LockFunds => "fund lock",
            IdempotencyOperation::CreateUnsignedTransaction => "unsigned transaction",
            IdempotencyOperation::SendTransaction => "transaction send",
            IdempotencyOperation::BurnFunds => "burn",
            IdempotencyOperation::ValidatorNodeRegistration => "validator node registration",
            IdempotencyOperation::ValidatorNodeExit => "validator node exit",
        }
    }
}

impl fmt::Display for IdempotencyOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A domain-separated hash over the request fields that decide what the wallet does.
///
/// Fields are fed in as `(name, value)` pairs and each part is length-prefixed
/// before hashing, so no two different field lists can collide by re-splitting
/// the same bytes: `field("a", "bc")` and `field("ab", "c")` hash differently,
/// as do `[("a", "b"), ("c", "d")]` and `[("a", "bcd")]`.
///
/// The operation is mixed in at construction, so the same parameters submitted
/// to two different endpoints never produce the same fingerprint.
pub struct RequestFingerprint {
    hasher: DomainSeparatedHasher<KeyDigest, IdempotencyDomain>,
}

impl RequestFingerprint {
    /// Starts a fingerprint for `operation`.
    pub fn new(operation: IdempotencyOperation) -> Self {
        let fingerprint = Self {
            hasher: DomainSeparatedHasher::new_with_label(REQUEST_FINGERPRINT_LABEL),
        };
        fingerprint.field("operation", operation.as_str())
    }

    /// Mixes one named request field into the fingerprint.
    ///
    /// Both the name and the value are length-prefixed, so the result depends on
    /// the exact field list and not merely on the concatenated bytes.
    #[must_use]
    pub fn field(self, name: &str, value: impl AsRef<[u8]>) -> Self {
        let value = value.as_ref();
        Self {
            hasher: self
                .hasher
                .chain((name.len() as u64).to_le_bytes())
                .chain(name.as_bytes())
                .chain((value.len() as u64).to_le_bytes())
                .chain(value),
        }
    }

    /// Mixes in a field that may be absent.
    ///
    /// An absent field is distinguished from a present-but-empty one, so
    /// `payment_id: null` and `payment_id: ""` do not share a fingerprint.
    #[must_use]
    pub fn optional_field(self, name: &str, value: Option<impl AsRef<[u8]>>) -> Self {
        match value {
            Some(value) => self.field(name, value).field("__present", [1u8]),
            None => self.field(name, []).field("__present", [0u8]),
        }
    }

    /// Finishes the hash and returns it hex-encoded for storage.
    pub fn finish(self) -> String {
        hex::encode(self.hasher.finalize().as_ref())
    }
}

/// An idempotency key together with the operation and request it is bound to.
///
/// Construct one at the request boundary and hand it to
/// [`FundLocker::lock`](crate::transactions::fund_locker::FundLocker::lock),
/// which enforces the binding before returning any cached lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyBinding {
    /// The client-supplied key, if any. When absent the caller gets a fresh
    /// random key and no replay is possible.
    key: Option<String>,
    operation: IdempotencyOperation,
    request_hash: String,
}

impl IdempotencyBinding {
    /// Binds `key` to `operation` and the request described by `fingerprint`.
    pub fn new(key: Option<String>, operation: IdempotencyOperation, fingerprint: RequestFingerprint) -> Self {
        Self {
            key,
            operation,
            request_hash: fingerprint.finish(),
        }
    }

    /// The client-supplied key, if one was provided.
    pub fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }

    /// The operation this key was issued for.
    pub fn operation(&self) -> IdempotencyOperation {
        self.operation
    }

    /// The hex-encoded fingerprint of the originating request.
    pub fn request_hash(&self) -> &str {
        &self.request_hash
    }

    /// Checks a stored `(operation, request_hash)` pair against this binding.
    ///
    /// Returns an error when the stored pair was written by a different
    /// operation or a different request body — the case where returning the
    /// cached lock would hand this caller UTXOs reserved for someone else's
    /// request.
    pub fn check_matches(&self, stored_operation: &str, stored_request_hash: &str) -> Result<(), IdempotencyConflict> {
        if stored_operation != self.operation.as_str() {
            return Err(IdempotencyConflict::OperationMismatch {
                key: self.key_for_error(),
                stored_operation: stored_operation.to_string(),
                requested_operation: self.operation,
            });
        }
        if stored_request_hash != self.request_hash {
            return Err(IdempotencyConflict::RequestMismatch {
                key: self.key_for_error(),
                operation: self.operation,
            });
        }
        Ok(())
    }

    /// The key to name in an error. Conflicts can only arise once a key was
    /// supplied, so the fallback is unreachable in practice.
    fn key_for_error(&self) -> String {
        self.key.clone().unwrap_or_else(|| "<none>".to_string())
    }
}

/// An idempotency key was replayed in a way that is not a retry of the original request.
///
/// Every variant is a client error: the key identifies a request the wallet has
/// already seen, and this one is not it. Callers at a request boundary should
/// map these to HTTP 409 Conflict.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdempotencyConflict {
    /// The key was issued for a different endpoint.
    #[error(
        "idempotency key '{key}' was already used for a '{stored_operation}' request and cannot be reused for a \
         '{requested_operation}' request; use a new key"
    )]
    OperationMismatch {
        key: String,
        stored_operation: String,
        requested_operation: IdempotencyOperation,
    },

    /// The key was issued for this endpoint but with different parameters.
    #[error(
        "idempotency key '{key}' was already used for a different {operation} request; a key may only be retried with \
         the exact request that created it"
    )]
    RequestMismatch {
        key: String,
        operation: IdempotencyOperation,
    },

    /// The key belongs to a transaction that has already been broadcast.
    ///
    /// Its UTXOs are spent, so re-locking them or handing them back would
    /// produce a transaction that can never confirm.
    #[error("idempotency key '{key}' belongs to a {operation} request that has already been completed; use a new key")]
    AlreadyCompleted {
        key: String,
        operation: IdempotencyOperation,
    },

    /// The key belongs to a lock that expired or was cancelled.
    ///
    /// The reservation is gone, so this cannot be served as a retry. A fresh
    /// key gets a fresh lock.
    #[error(
        "idempotency key '{key}' belongs to a {operation} request that is no longer active (status {status}); use a \
         new key"
    )]
    NoLongerActive {
        key: String,
        operation: IdempotencyOperation,
        status: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint_of(operation: IdempotencyOperation, amount: u64, recipient: &str) -> String {
        RequestFingerprint::new(operation)
            .field("amount", amount.to_le_bytes())
            .field("recipient", recipient)
            .finish()
    }

    #[test]
    fn identical_requests_share_a_fingerprint() {
        assert_eq!(
            fingerprint_of(IdempotencyOperation::LockFunds, 1_000, "alice"),
            fingerprint_of(IdempotencyOperation::LockFunds, 1_000, "alice"),
        );
    }

    #[test]
    fn a_changed_field_changes_the_fingerprint() {
        // The body-swap attack: same key, different recipient.
        assert_ne!(
            fingerprint_of(IdempotencyOperation::LockFunds, 1_000, "alice"),
            fingerprint_of(IdempotencyOperation::LockFunds, 1_000, "mallory"),
        );
        assert_ne!(
            fingerprint_of(IdempotencyOperation::LockFunds, 1_000, "alice"),
            fingerprint_of(IdempotencyOperation::LockFunds, 1_001, "alice"),
        );
    }

    #[test]
    fn the_same_request_under_a_different_operation_differs() {
        // The operation-swap attack: a /lock_funds key replayed at /burn.
        assert_ne!(
            fingerprint_of(IdempotencyOperation::LockFunds, 1_000, "alice"),
            fingerprint_of(IdempotencyOperation::BurnFunds, 1_000, "alice"),
        );
    }

    #[test]
    fn field_boundaries_cannot_be_shifted() {
        // Without length prefixes these would hash the same bytes in the same
        // order, letting an attacker move a byte from one field into the next.
        let split = RequestFingerprint::new(IdempotencyOperation::LockFunds)
            .field("a", "bc")
            .finish();
        let shifted = RequestFingerprint::new(IdempotencyOperation::LockFunds)
            .field("ab", "c")
            .finish();
        assert_ne!(split, shifted);

        let two_fields = RequestFingerprint::new(IdempotencyOperation::LockFunds)
            .field("x", "ab")
            .field("y", "cd")
            .finish();
        let one_field = RequestFingerprint::new(IdempotencyOperation::LockFunds)
            .field("x", "abycd")
            .finish();
        assert_ne!(two_fields, one_field);
    }

    #[test]
    fn an_absent_field_differs_from_an_empty_one() {
        let absent = RequestFingerprint::new(IdempotencyOperation::BurnFunds)
            .optional_field("payment_id", None::<&str>)
            .finish();
        let empty = RequestFingerprint::new(IdempotencyOperation::BurnFunds)
            .optional_field("payment_id", Some(""))
            .finish();
        assert_ne!(absent, empty);
    }

    #[test]
    fn a_binding_accepts_only_its_own_operation_and_request() {
        let binding = IdempotencyBinding::new(
            Some("key-1".to_string()),
            IdempotencyOperation::LockFunds,
            RequestFingerprint::new(IdempotencyOperation::LockFunds).field("amount", 1_000u64.to_le_bytes()),
        );

        binding
            .check_matches(binding.operation().as_str(), binding.request_hash())
            .expect("an exact retry is allowed");

        assert!(matches!(
            binding.check_matches(IdempotencyOperation::BurnFunds.as_str(), binding.request_hash()),
            Err(IdempotencyConflict::OperationMismatch { .. }),
        ));
        assert!(matches!(
            binding.check_matches(IdempotencyOperation::LockFunds.as_str(), "deadbeef"),
            Err(IdempotencyConflict::RequestMismatch { .. }),
        ));
    }

    #[test]
    fn a_binding_without_a_key_still_carries_its_scope() {
        let binding = IdempotencyBinding::new(
            None,
            IdempotencyOperation::BurnFunds,
            RequestFingerprint::new(IdempotencyOperation::BurnFunds),
        );
        assert_eq!(binding.key(), None);
        assert_eq!(binding.operation(), IdempotencyOperation::BurnFunds);
        assert!(!binding.request_hash().is_empty());
    }
}
