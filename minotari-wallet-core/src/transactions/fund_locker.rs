//! UTXO locking mechanism for transaction construction.
//!
//! This module provides functionality to temporarily lock UTXOs (Unspent Transaction Outputs)
//! during transaction construction, preventing double-spending scenarios where the same
//! outputs might be selected for multiple concurrent transactions.
//!
//! # Overview
//!
//! When creating a transaction, the wallet must:
//! 1. Select appropriate UTXOs to cover the transaction amount plus fees
//! 2. Lock those UTXOs to prevent other transactions from using them
//! 3. Either complete the transaction (consuming the UTXOs) or release the lock on failure
//!
//! The [`FundLocker`] handles steps 1 and 2, with automatic expiration to handle step 3
//! in case of failures or timeouts.
//!
//! # Idempotency
//!
//! Lock operations support idempotency keys, allowing clients to safely retry requests
//! without accidentally locking additional funds. If a lock request with the same
//! idempotency key already exists, the original result is returned.
//!
//! A key alone is not enough to authorise that short-circuit. Every caller must
//! supply an [`IdempotencyBinding`], which ties the key to the operation and the
//! exact request that created the lock; a replay that does not match is rejected
//! as an [`IdempotencyConflict`] instead of being handed the reservation. See
//! [`crate::transactions::idempotency`] for what that prevents.

use chrono::{DateTime, TimeDelta, Utc};
use log::{error, info, warn};
use rusqlite::Connection;
use std::sync::Mutex;
use tari_common::configuration::Network;
use tari_transaction_components::tari_amount::MicroMinotari;
use tari_transaction_components::transaction_components::WalletOutput;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    db::{self, PendingTransactionRecord},
    log::mask_amount,
    models::PendingTransactionStatus,
    transactions::{
        idempotency::{IdempotencyBinding, IdempotencyConflict},
        input_selector::InputSelector,
    },
};

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
#[derive(Debug, serde::Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct LockFundsResult {
    /// The UTXOs that have been locked for this transaction.
    ///
    /// These outputs are reserved and cannot be used by other transactions
    /// until the lock expires or is released. Each UTXO contains the
    /// cryptographic data needed to spend it.
    #[cfg_attr(feature = "utoipa", schema(value_type = Vec<Object>))]
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
    #[cfg_attr(feature = "utoipa", schema(value_type = u64))]
    pub total_value: MicroMinotari,

    /// The transaction fee if no change output is created.
    ///
    /// Use this fee when `requires_change_output` is `false`, or when
    /// intentionally burning the excess as a donation to miners.
    #[cfg_attr(feature = "utoipa", schema(value_type = u64))]
    pub fee_without_change: MicroMinotari,

    /// The transaction fee if a change output is included.
    ///
    /// This fee is higher than `fee_without_change` because the change
    /// output adds to the transaction size. Use this fee when
    /// `requires_change_output` is `true`.
    #[cfg_attr(feature = "utoipa", schema(value_type = u64))]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct SendAllSkipped {
    /// Outputs worth no more than they cost to spend; never worth spending.
    pub skipped_dust: usize,
    /// Outputs that did not fit one transaction (count, weight or bytes);
    /// another send-all can sweep them.
    pub skipped_over_cap: usize,
}

/// Upper bound, in seconds, on how long UTXOs may be locked (365 days).
///
/// `seconds_to_lock_utxos` reaches us straight from a JSON request body or a
/// CLI argument, so it must be treated as untrusted. Adding an unbounded
/// number of seconds to `Utc::now()` pushes the result past the range chrono
/// can represent, and chrono's `Add` impl *panics* on overflow. Because that
/// arithmetic used to run while [`FUND_LOCK_MUTEX`] was held, a single request
/// such as `{"seconds_to_lock_utxos": 10000000000000}` poisoned the mutex for
/// the lifetime of the process and bricked every subsequent fund-moving
/// request. Bounding the input keeps the arithmetic total.
pub const MAX_SECONDS_TO_LOCK_UTXOS: u64 = 365 * 24 * 60 * 60;

/// The caller asked for a UTXO lock duration that cannot be honoured.
///
/// Callers at a request boundary should map this to a client error (HTTP 400)
/// rather than an internal failure: the value is invalid input, not a fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("seconds_to_lock_utxos must not exceed {MAX_SECONDS_TO_LOCK_UTXOS} seconds (365 days), got {0}")]
pub struct InvalidLockDuration(pub u64);

/// Rejects lock durations outside the range this wallet is willing to honour.
///
/// Use this at request boundaries to fail fast, before any database work or
/// lock acquisition, so that a bad value can never reach the critical section.
pub fn validate_seconds_to_lock(seconds_to_lock_utxos: u64) -> Result<(), InvalidLockDuration> {
    if seconds_to_lock_utxos > MAX_SECONDS_TO_LOCK_UTXOS {
        return Err(InvalidLockDuration(seconds_to_lock_utxos));
    }
    Ok(())
}

/// The lowest fee per gram the wallet sends with.
///
/// A base node's mempool refuses a transaction whose total fee is below its
/// `min_fee` (`UnconfirmedPoolConfig`, 50 µT by default in tari_core
/// 6.2.0-pre.1). It sets no per-gram minimum, but the smallest send this wallet
/// makes (one input, a recipient output and a change output) weighs well over 50
/// grams, so 1 µT per gram always clears it, while 0 never does. A send at 0 would
/// be signed, recorded and then never accepted.
pub const MIN_FEE_PER_GRAM: MicroMinotari = MicroMinotari(1);

/// A fee per gram below [`MIN_FEE_PER_GRAM`].
///
/// Like [`InvalidLockDuration`], callers map this to a client error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("fee_per_gram must be at least {minimum} µT per gram (a base node will not accept less), got {fee_per_gram}")]
pub struct FeePerGramTooLow {
    pub fee_per_gram: MicroMinotari,
    pub minimum: MicroMinotari,
}

/// Rejects a fee per gram the base node would not accept, before anything is
/// locked or signed.
pub fn validate_fee_per_gram(fee_per_gram: MicroMinotari) -> Result<(), FeePerGramTooLow> {
    if fee_per_gram < MIN_FEE_PER_GRAM {
        return Err(FeePerGramTooLow {
            fee_per_gram,
            minimum: MIN_FEE_PER_GRAM,
        });
    }
    Ok(())
}

/// Computes when a UTXO lock taken at `now` should expire.
///
/// This is total: every step that chrono would panic on (out-of-range
/// `TimeDelta`, out-of-range `DateTime`) is handled with its checked
/// counterpart, so an absurd `seconds_to_lock_utxos` yields an error instead of
/// unwinding through a held mutex.
pub fn lock_expiry_at(now: DateTime<Utc>, seconds_to_lock_utxos: u64) -> Result<DateTime<Utc>, InvalidLockDuration> {
    validate_seconds_to_lock(seconds_to_lock_utxos)?;
    let seconds = i64::try_from(seconds_to_lock_utxos).map_err(|_| InvalidLockDuration(seconds_to_lock_utxos))?;
    let delta = TimeDelta::try_seconds(seconds).ok_or(InvalidLockDuration(seconds_to_lock_utxos))?;
    now.checked_add_signed(delta)
        .ok_or(InvalidLockDuration(seconds_to_lock_utxos))
}

/// Global mutex that serializes all [`FundLocker::lock`] calls.
///
/// Without it two concurrent requests in this process could both pass the
/// idempotency check, select the same set of "unspent" outputs, and then race to
/// lock them. Serialising the critical section (idempotency check → UTXO
/// selection → pending-transaction creation → output locking) eliminates the
/// race described in <https://github.com/anomalyco/minotari-cli/issues/125>.
///
/// This mutex is **process-local**, so it is not on its own sufficient: a second
/// CLI invocation running against the same database file has its own copy. The
/// cross-process guarantee comes from doing the selection and the locking inside
/// one `BEGIN IMMEDIATE` transaction (see [`FundLocker::lock`]), backed by the
/// conditional update in [`db::lock_output`], which refuses to reserve an output
/// that is no longer unspent.
static FUND_LOCK_MUTEX: Mutex<()> = Mutex::new(());

/// What an idempotency key is entitled to on the current request.
enum Replay {
    /// Nothing is reserved under this key; select and lock UTXOs as normal.
    Fresh,
    /// This request is an exact retry of the one that took the reservation, so
    /// it gets that reservation back.
    Existing(Box<LockFundsResult>),
}

/// Decides whether `binding`'s key may short-circuit onto `record`.
///
/// The key by itself proves nothing: it is a client-chosen string, and the
/// stored reservation was taken for whatever request first presented it. So the
/// stored scope is checked against this request's before any UTXO is handed
/// back, and a key whose transaction is already completed — or expired, or
/// cancelled — is refused outright rather than being quietly treated as a
/// brand-new request.
///
/// Lives here rather than inside [`resolve_replay`] because
/// [`TransactionSender`](crate::transactions::manager::TransactionSender)
/// replays onto the pending transaction's id instead of its locked funds, and
/// the two paths must agree on what a key is entitled to.
pub(crate) fn check_replay_allowed(
    record: &PendingTransactionRecord,
    binding: &IdempotencyBinding,
    key: &str,
) -> Result<(), anyhow::Error> {
    // Rejects a replay carrying different recipients or amounts, a replay
    // arriving at a different endpoint, and — because their stored scope is the
    // empty string — any row written before scopes were recorded.
    binding.check_matches(&record.operation, &record.request_hash)?;

    match record.status {
        PendingTransactionStatus::Pending => Ok(()),
        // The UTXOs behind this key are already spent by a broadcast
        // transaction. Re-locking them would build a transaction that can never
        // confirm; handing them back would be worse.
        PendingTransactionStatus::Completed => Err(IdempotencyConflict::AlreadyCompleted {
            key: key.to_string(),
            operation: binding.operation(),
        }
        .into()),
        // Expired or cancelled: the reservation is gone. Falling through to a
        // fresh selection would collide with the unique (account, key) index
        // anyway, so say plainly why.
        ref status => Err(IdempotencyConflict::NoLongerActive {
            key: key.to_string(),
            operation: binding.operation(),
            status: status.to_string(),
        }
        .into()),
    }
}

/// Resolves what `binding`'s key is entitled to, reading the stored reservation
/// through `conn`.
///
/// A request without a key is always [`Replay::Fresh`]: nothing to replay onto.
fn resolve_replay(conn: &Connection, binding: &IdempotencyBinding, account_id: i64) -> Result<Replay, anyhow::Error> {
    let Some(key) = binding.key() else {
        return Ok(Replay::Fresh);
    };
    let Some(record) = db::find_pending_transaction_record_by_idempotency_key(conn, key, account_id)? else {
        return Ok(Replay::Fresh);
    };

    check_replay_allowed(&record, binding, key)?;

    info!(
        target: "audit",
        operation = binding.operation().as_str();
        "Found existing pending transaction lock"
    );
    Ok(Replay::Existing(Box::new(db::locked_funds_for_pending_transaction(
        conn, &record,
    )?)))
}

/// Manages temporary locking of UTXOs during transaction construction.
///
/// `FundLocker` ensures that UTXOs selected for a transaction cannot be used
/// by other concurrent transactions, preventing double-spending within the wallet.
/// Locks are time-limited and automatically expire if the transaction is not
/// completed within the specified duration.
///
/// # Thread Safety
///
/// A global [`Mutex`] serialises all [`lock`](FundLocker::lock) calls so that
/// the idempotency check, UTXO selection, pending-transaction creation, and
/// output locking happen atomically with respect to other threads.  The struct
/// itself can be safely shared across threads via cloning.
///
/// # Example
///
/// ```rust,ignore
/// use minotari_wallet_core::transactions::fund_locker::FundLocker;
/// use tari_transaction_components::tari_amount::MicroMinotari;
///
/// let locker = FundLocker::new(db_pool);
///
/// // Lock funds for a transaction
/// let result = locker.lock(
///     account_id,
///     MicroMinotari(1_000_000),  // amount to send
///     1,                         // number of outputs
///     MicroMinotari(5),          // fee per gram
///     None,                      // use default output size estimate
///     IdempotencyBinding::new(   // key, bound to this operation and request
///         Some("unique-key".into()),
///         IdempotencyOperation::LockFunds,
///         RequestFingerprint::new(IdempotencyOperation::LockFunds)
///             .field("amount", 1_000_000u64.to_le_bytes()),
///     ),
///     300,                       // lock for 5 minutes
/// ).await?;
///
/// // Use result.utxos to build the transaction
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct FundLocker;

impl FundLocker {
    /// Creates a new `FundLocker`.
    ///
    /// It holds no state: [`FundLocker::lock`] works on the connection its caller
    /// passes in. See that method for why it does not take one from the pool itself.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let locker = FundLocker::new();
    /// ```
    pub fn new() -> Self {
        Self
    }

    /// Locks UTXOs for a pending transaction.
    ///
    /// # Why the connection is a parameter
    ///
    /// This call serialises on a process-wide mutex, so a caller can be queued here for as
    /// long as the busiest request ahead of it takes. Taking a connection from the pool as
    /// well — at either end of that wait — is what starves the pool:
    ///
    /// * acquiring it *before* the mutex means every queued caller pins a connection while
    ///   doing nothing, so the pool has to be as large as the number of concurrent callers;
    /// * acquiring it *after* the mutex means blocking on checkout while holding the mutex,
    ///   which is safe only for as long as no caller anywhere holds a connection across this
    ///   call — an unwritten rule that three API handlers already broke.
    ///
    /// Taking the caller's connection avoids both. The caller already has one (it looked up
    /// the account with it), the mutex holder arrives holding everything it needs and so
    /// never blocks on another resource, and no caller can accidentally hold a second
    /// connection because there is nowhere to put it. One connection per in-flight request,
    /// enforced by the signature rather than by convention.
    ///
    /// Selects unspent outputs sufficient to cover the requested amount plus estimated
    /// transaction fees, then locks them in the database with an expiration time.
    /// If an idempotency key is provided and a matching pending transaction exists,
    /// returns the existing lock result without creating a new one.
    ///
    /// # Arguments
    ///
    /// * `account_id` - The account whose UTXOs should be locked
    /// * `amount` - The amount to be sent (excluding fees)
    /// * `num_outputs` - Number of transaction outputs (typically 1 for recipient + optional change)
    /// * `fee_per_gram` - Fee rate in MicroMinotari per gram of transaction weight
    /// * `estimated_output_size` - Optional override for output size estimation; if `None`,
    ///   uses default calculation based on standard output features
    /// * `idempotency` - The client's idempotency key bound to the operation and request that
    ///   issued it. A key only returns an existing lock when the operation *and* the request
    ///   fingerprint match what that lock was created for
    /// * `seconds_to_lock_utxos` - Duration in seconds before the lock expires;
    ///   must not exceed [`MAX_SECONDS_TO_LOCK_UTXOS`]
    ///
    /// # Returns
    ///
    /// Returns a [`LockFundsResult`] containing:
    /// - The selected UTXOs
    /// - Whether a change output is required
    /// - Total value of selected UTXOs
    /// - Fee calculations with and without change output
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `seconds_to_lock_utxos` exceeds [`MAX_SECONDS_TO_LOCK_UTXOS`]
    ///   ([`InvalidLockDuration`])
    /// - The idempotency key was already used for a different operation or a different
    ///   request, or belongs to a transaction that is completed or no longer active
    ///   ([`IdempotencyConflict`])
    /// - Database connection fails
    /// - Insufficient funds are available
    /// - UTXO selection fails due to serialization errors
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let result = locker.lock(
    ///     account_id,
    ///     MicroMinotari(500_000),
    ///     1,
    ///     MicroMinotari(5),
    ///     None,
    ///     binding, // an `IdempotencyBinding` built from the request
    ///     600, // 10 minute lock
    /// ).await?;
    ///
    /// println!("Locked {} UTXOs worth {}", result.utxos.len(), result.total_value);
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn lock(
        &self,
        conn: &mut Connection,
        account_id: i64,
        amount: MicroMinotari,
        num_outputs: usize,
        fee_per_gram: MicroMinotari,
        estimated_output_size: Option<usize>,
        idempotency: IdempotencyBinding,
        seconds_to_lock_utxos: u64,
        confirmation_window: u64,
    ) -> Result<LockFundsResult, anyhow::Error> {
        let selection = Selection::Amount {
            amount,
            num_outputs,
            estimated_output_size,
        };
        Self::lock_selection(
            conn,
            account_id,
            selection,
            fee_per_gram,
            idempotency,
            seconds_to_lock_utxos,
            confirmation_window,
        )
    }

    /// Locks every spendable, unlocked UTXO for a send-all to one recipient.
    ///
    /// The same as [`lock`](Self::lock), but selects with
    /// [`InputSelector::select_all`]; the recipient's amount is then
    /// [`InputSelector::send_all_amount`] of the result's `total_value` and
    /// `fee_with_change`. The output sizes are the exact ones from
    /// [`one_sided_output_sizes`](crate::transactions::fee_estimator::one_sided_output_sizes).
    #[allow(clippy::too_many_arguments)]
    pub fn lock_all(
        &self,
        conn: &mut Connection,
        account_id: i64,
        network: Network,
        fee_per_gram: MicroMinotari,
        recipient_output_size: usize,
        change_output_size: usize,
        idempotency: IdempotencyBinding,
        seconds_to_lock_utxos: u64,
        confirmation_window: u64,
    ) -> Result<LockFundsResult, anyhow::Error> {
        let selection = Selection::All {
            network,
            recipient_output_size,
            change_output_size,
        };
        Self::lock_selection(
            conn,
            account_id,
            selection,
            fee_per_gram,
            idempotency,
            seconds_to_lock_utxos,
            confirmation_window,
        )
    }

    fn lock_selection(
        conn: &mut Connection,
        account_id: i64,
        selection: Selection,
        fee_per_gram: MicroMinotari,
        idempotency: IdempotencyBinding,
        seconds_to_lock_utxos: u64,
        confirmation_window: u64,
    ) -> Result<LockFundsResult, anyhow::Error> {
        let amount = match selection {
            Selection::Amount { amount, .. } => amount,
            Selection::All { .. } => MicroMinotari::zero(),
        };
        info!(
            target: "audit",
            account_id = account_id,
            operation = idempotency.operation().as_str(),
            amount = &*mask_amount(amount),
            send_all = matches!(selection, Selection::All { .. });
            "Locking funds"
        );
        // Reject an out-of-range lock duration before touching the database or
        // the global mutex, so untrusted input can never reach the critical
        // section (see `MAX_SECONDS_TO_LOCK_UTXOS`).
        validate_seconds_to_lock(seconds_to_lock_utxos)?;
        validate_fee_per_gram(fee_per_gram)?;
        // Fast idempotency check (without the global mutex).  If the pending
        // transaction already exists we can return immediately without waiting
        // for any concurrent `lock()` call to finish.  A key that does not match
        // the stored scope fails here, before any UTXO is looked at.
        if let Replay::Existing(response) = resolve_replay(conn, &idempotency, account_id)? {
            return Ok(*response);
        }

        // Acquire the global mutex so that the idempotency re-check, UTXO
        // selection, and database transaction are all serialised.  This
        // prevents a concurrent request from seeing the same "unspent" UTXOs
        // and creating a duplicate pending transaction.
        //
        // The mutex guards no in-memory state — it is a `Mutex<()>` whose only
        // job is mutual exclusion — and the critical section's only durable
        // side effects happen inside a database transaction that rolls back if
        // it is not committed. A panic in a previous caller therefore leaves
        // nothing inconsistent behind, so recover from poisoning instead of
        // propagating it: unwrapping here would turn one panicking request into
        // a permanent, process-wide outage of every fund-moving endpoint.
        let _guard = FUND_LOCK_MUTEX.lock().unwrap_or_else(|poisoned| {
            warn!(
                target: "audit",
                "Fund locker mutex was poisoned by a previous panic; recovering"
            );
            poisoned.into_inner()
        });
        // Re-check idempotency now that we hold the mutex.  The first thread
        // that passed the fast-path check above may have created the pending
        // transaction while we were waiting for the lock; if so we return its
        // result rather than selecting UTXOs a second time.
        if let Replay::Existing(response) = resolve_replay(conn, &idempotency, account_id)? {
            return Ok(*response);
        }

        // BEGIN IMMEDIATE: acquire the write lock up front rather than upgrading
        // a read->write inside the transaction. Under concurrent writers in WAL
        // mode (e.g. the background unlocker task), a deferred transaction can
        // dead-lock with SQLITE_BUSY_SNAPSHOT — surfaced as "database is locked"
        // — which busy_timeout will not retry.
        //
        // Taking the write lock *before* selecting outputs is what makes the
        // selection trustworthy across processes. `FUND_LOCK_MUTEX` only
        // serialises threads in this process; a second CLI invocation or the
        // daemon's own scan loop is a different process entirely. Holding the
        // database's single write lock for the whole select → lock sequence is
        // the only thing that stops another writer from spending or reserving
        // one of these outputs in between.
        let transaction = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        // Re-check idempotency once more inside the write transaction: a
        // concurrent writer may have created the pending transaction after our
        // check above but before we acquired the write lock.
        if let Replay::Existing(response) = resolve_replay(&transaction, &idempotency, account_id)? {
            return Ok(*response);
        }

        let input_selector = InputSelector::new(account_id, confirmation_window);
        let (utxo_selection, send_all_skipped) = match selection {
            Selection::Amount {
                amount,
                num_outputs,
                estimated_output_size,
            } => (
                input_selector.fetch_unspent_outputs(
                    &transaction,
                    amount,
                    num_outputs,
                    fee_per_gram,
                    estimated_output_size,
                )?,
                None,
            ),
            Selection::All {
                network,
                recipient_output_size,
                change_output_size,
            } => {
                let all = input_selector.select_all(
                    &transaction,
                    network,
                    fee_per_gram,
                    recipient_output_size,
                    change_output_size,
                )?;
                all.audit_if_partial(account_id);
                let skipped = SendAllSkipped {
                    skipped_dust: all.skipped_dust,
                    skipped_over_cap: all.skipped_over_cap,
                };
                (all.selection, Some(skipped))
            },
        };

        // Already validated above; `lock_expiry_at` is total, so a surprising
        // value returns an error rather than panicking under the held mutex.
        let expires_at = lock_expiry_at(Utc::now(), seconds_to_lock_utxos)?;
        // No client key means no replay is possible, so any unique key will do.
        let idempotency_key = idempotency
            .key()
            .map_or_else(|| Uuid::new_v4().to_string(), str::to_string);
        let pending_tx_id = db::create_pending_transaction(
            &transaction,
            &idempotency_key,
            &idempotency,
            account_id,
            utxo_selection.requires_change_output,
            utxo_selection.total_value,
            utxo_selection.fee_without_change,
            utxo_selection.fee_with_change,
            expires_at,
        )?;

        // Each lock is a conditional `Unspent → Locked` update. Under the write
        // lock taken above these cannot fail, but the check is not redundant: if
        // one ever does, `?` propagates before `commit()` and the whole
        // reservation — pending transaction included — rolls back, rather than
        // returning UTXOs this caller does not own.
        for utxo in &utxo_selection.utxos {
            db::lock_output(&transaction, utxo.id, &pending_tx_id, expires_at)?;
        }

        transaction.commit()?;

        info!(
            target: "audit",
            utxos_count = utxo_selection.utxos.len(),
            total_value = &*mask_amount(utxo_selection.total_value);
            "Funds locked successfully"
        );

        Ok(LockFundsResult {
            utxos: utxo_selection.utxos.iter().map(|utxo| utxo.output.clone()).collect(),
            requires_change_output: utxo_selection.requires_change_output,
            total_value: utxo_selection.total_value,
            fee_without_change: utxo_selection.fee_without_change,
            fee_with_change: utxo_selection.fee_with_change,
            reservation_id: pending_tx_id,
            created_reservation: true,
            send_all_skipped,
        })
    }
}

/// Hands back the UTXOs of a reservation a send took and then failed to use.
///
/// Only call it for a [`LockFundsResult`] whose `created_reservation` is set: a
/// replayed reservation belongs to the request that took it. A reservation that is no
/// longer pending is left to whoever moved it on.
pub fn release_reservation(conn: &Connection, reservation_id: &str) {
    match db::expire_and_unlock_pending_transaction(conn, reservation_id) {
        Ok(true) => info!(
            target: "audit",
            "Released the reservation of a failed send"
        ),
        Ok(false) => warn!(
            target: "audit",
            "Leaving a reservation that is no longer pending to whoever claimed it"
        ),
        Err(e) => error!(
            target: "audit",
            error:% = e;
            "Failed to release the reservation of a failed send"
        ),
    }
}

/// What [`FundLocker`] selects: enough for an amount, or everything spendable.
#[derive(Debug, Clone, Copy)]
enum Selection {
    Amount {
        amount: MicroMinotari,
        num_outputs: usize,
        estimated_output_size: Option<usize>,
    },
    All {
        network: Network,
        recipient_output_size: usize,
        change_output_size: usize,
    },
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_wrap)]
    #![allow(clippy::cast_lossless)]
    #![allow(clippy::cast_possible_truncation)]
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use crate::{
        db::{SqlitePool, create_account, get_account_by_name, init_db, insert_scanned_tip_block},
        transactions::idempotency::{IdempotencyOperation, RequestFingerprint},
    };
    use anyhow::Error;
    use rusqlite::named_params;
    use std::collections::HashSet;
    use tari_common_types::{
        seeds::cipher_seed::CipherSeed,
        types::{ComAndPubSignature, CompressedPublicKey, FixedHash},
    };
    use tari_script::{ExecutionStack, TariScript};
    use tari_transaction_components::{
        key_manager::{
            TariKeyId,
            wallet_types::{SeedWordsWallet, WalletType},
        },
        transaction_components::{
            EncryptedData, MemoField, OutputFeatures, TransactionOutputVersion, WalletOutput, covenants::Covenant,
        },
    };
    use tempfile::tempdir;

    /// Create a [`WalletOutput`] with the given value and hash seed, plus
    /// default parameters suitable for testing.
    fn test_wallet_output(value: u64, hash_seed: u8) -> WalletOutput {
        let mut hash = FixedHash::default();
        hash[0] = hash_seed;
        WalletOutput::new_from_parts(
            TransactionOutputVersion::default(),
            MicroMinotari::from(value),
            TariKeyId::default(),
            OutputFeatures::default(),
            TariScript::default(),
            ExecutionStack::default(),
            TariKeyId::default(),
            CompressedPublicKey::default(),
            ComAndPubSignature::default(),
            0,
            Covenant::default(),
            EncryptedData::default(),
            MicroMinotari::from(0),
            None,
            MemoField::new_empty(),
            hash,
            Default::default(),
        )
    }

    /// Insert a test output row directly into the database.
    fn insert_test_output(conn: &Connection, account_id: i64, output_hash_byte: u8, value: u64, mined_height: u64) {
        let output = test_wallet_output(value, output_hash_byte);
        let wallet_output_json = serde_json::to_string(&output).expect("serialize WalletOutput");
        conn.execute(
            r#"
            INSERT INTO outputs (
                account_id, tx_id, output_hash, mined_in_block_height, mined_in_block_hash,
                value, mined_timestamp, wallet_output_json, status, confirmed_height,
                confirmed_hash, is_burn, maturity
            ) VALUES (
                :account_id, :tx_id, :output_hash, :height, :block_hash,
                :value, :mined_ts, :json, :status, :confirmed_height,
                :confirmed_hash, 0, :maturity
            )
            "#,
            named_params! {
                ":account_id": account_id,
                ":tx_id": output_hash_byte as i64,
                ":output_hash": vec![output_hash_byte; 32],
                ":height": mined_height as i64,
                ":block_hash": vec![output_hash_byte; 32],
                ":value": value as i64,
                ":mined_ts": Utc::now(),
                ":json": wallet_output_json,
                ":status": "UNSPENT",
                ":confirmed_height": mined_height as i64,
                ":confirmed_hash": vec![output_hash_byte; 32],
                ":maturity": 0,
            },
        )
        .expect("insert test output");
    }

    /// Create a fresh in-memory database, initialize it, create a test
    /// account, and seed a set of spendable UTXOs.  Returns the pool,
    /// connection, and account id.
    fn setup_test_env(output_count: usize, value_per_output: u64) -> (SqlitePool, i64, tempfile::TempDir) {
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("test.db")).expect("init db");
        let conn = pool.get().expect("get conn");

        let seeds = CipherSeed::random();
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(seeds).expect("construct wallet"));
        create_account(&conn, "test", &wallet, "pass").expect("create account");
        let account = get_account_by_name(&conn, "test")
            .expect("get account")
            .expect("account exists");
        let account_id = account.id;

        // Insert a scanned tip block so `InputSelector` sees a non-zero tip
        insert_scanned_tip_block(&conn, account_id, 200, &[0u8; 32]).expect("insert tip block");

        // Insert spendable outputs
        for i in 0..output_count {
            insert_test_output(
                &conn,
                account_id,
                (i + 1) as u8,
                (i as u64 + 1) * value_per_output,
                100, // mined at block 100 → eligible with window=100, tip=200
            );
        }

        drop(conn);
        (pool, account_id, temp)
    }

    /// A lock-funds binding for `key` over a request identified by `amount`.
    ///
    /// `amount` stands in for the whole request body: two calls with the same
    /// key and the same `amount` are retries of one request, and changing it
    /// models a client replaying the key with a different body.
    fn test_binding(key: Option<&str>, amount: u64) -> IdempotencyBinding {
        scoped_test_binding(key, IdempotencyOperation::LockFunds, amount)
    }

    /// As [`test_binding`], but for a caller claiming to be a different operation.
    fn scoped_test_binding(key: Option<&str>, operation: IdempotencyOperation, amount: u64) -> IdempotencyBinding {
        IdempotencyBinding::new(
            key.map(str::to_string),
            operation,
            RequestFingerprint::new(operation).field("amount", amount.to_le_bytes()),
        )
    }

    /// Locks 100_000 µT under `binding`, with everything else held constant.
    fn lock_with(pool: &SqlitePool, account_id: i64, binding: IdempotencyBinding) -> Result<LockFundsResult, Error> {
        FundLocker::new().lock(
            &mut pool.get().expect("conn"),
            account_id,
            MicroMinotari(100_000),
            1,
            MicroMinotari(1),
            Some(1000),
            binding,
            3600,
            100,
        )
    }

    /// Only the call that took a reservation is told its id, and releasing it
    /// hands its UTXOs back; a replay is never told it.
    #[test]
    fn a_reservation_the_caller_took_can_be_released() {
        let (pool, account_id, _temp) = setup_test_env(3, 500_000);
        let locked = lock_with(&pool, account_id, test_binding(Some("k"), 1)).expect("lock");
        assert!(locked.created_reservation, "this call took it");
        let id = locked.reservation_id.clone();
        let replay = lock_with(&pool, account_id, test_binding(Some("k"), 1)).expect("replay");
        assert!(!replay.created_reservation);
        assert_eq!(replay.reservation_id, id);

        let conn = pool.get().expect("conn");
        release_reservation(&conn, &id);
        let locked_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM outputs WHERE status = 'LOCKED'", [], |row| {
                row.get(0)
            })
            .expect("count");
        assert_eq!(locked_count, 0);
        let status: String = conn
            .query_row("SELECT status FROM pending_transactions", [], |row| row.get(0))
            .expect("status");
        assert_eq!(status, "EXPIRED");
    }

    /// Callers in the shape of every real one: hold a connection, then lock.
    ///
    /// This is what the API handlers and CLI commands do — they look an account up before
    /// they can lock anything, so they are already holding a connection when they call. With
    /// `lock` taking a connection of its own, that shape starved the pool: every caller
    /// pinned one connection and needed a second, so a pool of five deadlocked on five
    /// callers and every one of them failed on the checkout timeout.
    ///
    /// Twenty callers against a pool of five must all get an answer. Some will legitimately
    /// run out of funds; none may fail for want of a connection.
    #[test]
    fn concurrent_callers_holding_a_connection_do_not_exhaust_the_pool() {
        let (_pool, account_id, temp) = setup_test_env(5, 500_000);

        // A pool far smaller than the number of callers: with one connection per caller this
        // is merely a queue, and the test finishes; with two it is a deadlock.
        let pool = r2d2::Pool::builder()
            .max_size(5)
            .connection_timeout(std::time::Duration::from_secs(10))
            .build(r2d2_sqlite::SqliteConnectionManager::file(temp.path().join("test.db")))
            .expect("build pool");

        let failures: Vec<String> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..20)
                .map(|i| {
                    let pool = pool.clone();
                    scope.spawn(move || {
                        // The handler shape: take a connection, look something up with it,
                        // then lock with that same connection still in hand.
                        let mut conn = pool.get().map_err(|e| e.to_string())?;
                        let _unused = get_account_by_name(&conn, "test").map_err(|e| e.to_string())?;
                        FundLocker::new()
                            .lock(
                                &mut conn,
                                account_id,
                                MicroMinotari(100_000),
                                1,
                                MicroMinotari(1),
                                Some(1000),
                                test_binding(None, i),
                                3600,
                                100,
                            )
                            .map(|_| ())
                            .map_err(|e| e.to_string())
                    })
                })
                .collect();
            handles
                .into_iter()
                .filter_map(|h| h.join().expect("thread").err())
                .collect()
        });

        assert!(
            !failures.iter().any(|e| e.contains("timed out waiting for connection")),
            "callers starved the pool: {failures:?}"
        );
    }

    /// The set of outputs currently reserved in the database, by value.
    ///
    /// The seeded outputs have distinct values, so a value identifies a row.
    fn locked_values(pool: &SqlitePool) -> HashSet<i64> {
        pool.get()
            .expect("conn")
            .prepare("SELECT value FROM outputs WHERE status = 'LOCKED'")
            .expect("prepare")
            .query_map([], |row| row.get::<_, i64>(0))
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("collect")
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    fn concurrent_lock_calls_select_disjoint_utxos() {
        let (pool, account_id, _temp) = setup_test_env(5, 500_000);

        let pool2 = pool.clone();
        let handle_a = std::thread::spawn(move || {
            let locker = FundLocker::new();
            locker.lock(
                &mut pool.get().expect("conn"),
                account_id,
                MicroMinotari(100_000),
                1,
                MicroMinotari(1),
                Some(1000),
                test_binding(None, 1),
                3600,
                100, // confirmation_window = 100 → tip(200) − 100 = 100 ≥ mined(100)
            )
        });
        let handle_b = std::thread::spawn(move || {
            let locker = FundLocker::new();
            locker.lock(
                &mut pool2.get().expect("conn"),
                account_id,
                MicroMinotari(100_000),
                1,
                MicroMinotari(1),
                Some(1000),
                test_binding(None, 1),
                3600,
                100,
            )
        });

        let res_a = handle_a.join().expect("thread A panicked");
        let res_b = handle_b.join().expect("thread B panicked");

        let result_a = res_a.expect("lock A succeeded");
        let result_b = res_b.expect("lock B succeeded");

        // Each call must have locked at least one UTXO
        assert!(!result_a.utxos.is_empty(), "A got at least one UTXO");
        assert!(!result_b.utxos.is_empty(), "B got at least one UTXO");

        // The two result sets must not share any UTXO (identified by its hash)
        let hashes_a: HashSet<FixedHash> = result_a.utxos.iter().map(|u| u.output_hash()).collect();
        let hashes_b: HashSet<FixedHash> = result_b.utxos.iter().map(|u| u.output_hash()).collect();

        let intersection: HashSet<_> = hashes_a.intersection(&hashes_b).copied().collect();
        assert!(
            intersection.is_empty(),
            "Concurrent lock calls selected overlapping UTXOs: {intersection:?}",
        );
    }

    #[test]
    fn idempotency_key_returns_same_result_concurrently() {
        let (pool, account_id, _temp) = setup_test_env(3, 1_000_000);

        let key = "concurrent-idempotency-key".to_string();
        let pool2 = pool.clone();
        let key2 = key.clone();

        let handle_a = std::thread::spawn(move || {
            let locker = FundLocker::new();
            locker.lock(
                &mut pool.get().expect("conn"),
                account_id,
                MicroMinotari(200_000),
                1,
                MicroMinotari(1),
                Some(1000),
                test_binding(Some(&key), 1),
                3600,
                100,
            )
        });
        let handle_b = std::thread::spawn(move || {
            let locker = FundLocker::new();
            locker.lock(
                &mut pool2.get().expect("conn"),
                account_id,
                MicroMinotari(200_000),
                1,
                MicroMinotari(1),
                Some(1000),
                test_binding(Some(&key2), 1),
                3600,
                100,
            )
        });

        let res_a = handle_a.join().expect("thread A panicked");
        let res_b = handle_b.join().expect("thread B panicked");

        let result_a = res_a.expect("lock A succeeded");
        let result_b = res_b.expect("lock B succeeded");

        // Both should see the same locked funds (same UTXOs, same totals)
        let hashes_a: HashSet<FixedHash> = result_a.utxos.iter().map(|u| u.output_hash()).collect();
        let hashes_b: HashSet<FixedHash> = result_b.utxos.iter().map(|u| u.output_hash()).collect();

        assert_eq!(
            hashes_a, hashes_b,
            "Idempotent concurrent calls must return identical UTXO sets",
        );
        assert_eq!(result_a.total_value, result_b.total_value);
        assert_eq!(result_a.requires_change_output, result_b.requires_change_output);
    }

    #[test]
    fn mutex_serialises_lock_calls() {
        // Verify that the global `FUND_LOCK_MUTEX` serialises callers:
        // two concurrent `lock()` calls on the *same* account both succeed
        // without overlapping UTXO sets (each sees a disjoint set of UTXOs
        // because the first call's side-effects are visible to the second).
        //
        // This is already exercised by `concurrent_lock_calls_select_disjoint_utxos`
        // above; this test adds a second scenario using a different account to
        // ensure the mutex does not prevent different accounts from making
        // progress (though in practice they share the global lock).
        let (pool_a, account_a, _temp_a) = setup_test_env(3, 1_000_000);
        let (pool_b, account_b, _temp_b) = setup_test_env(3, 1_000_000);

        let _pool_a2 = pool_a.clone();
        let _pool_b2 = pool_b.clone();

        let h_a = std::thread::spawn(move || {
            FundLocker::new().lock(
                &mut pool_a.get().expect("conn"),
                account_a,
                MicroMinotari(200_000),
                1,
                MicroMinotari(1),
                Some(1000),
                test_binding(None, 1),
                3600,
                100,
            )
        });
        let h_b = std::thread::spawn(move || {
            FundLocker::new().lock(
                &mut pool_b.get().expect("conn"),
                account_b,
                MicroMinotari(200_000),
                1,
                MicroMinotari(1),
                Some(1000),
                test_binding(None, 1),
                3600,
                100,
            )
        });

        let r_a = h_a.join().expect("thread A panicked").expect("lock A ok");
        let r_b = h_b.join().expect("thread B panicked").expect("lock B ok");

        // Both should succeed (no double-spend errors) and select at least one UTXO
        assert!(!r_a.utxos.is_empty(), "A got UTXOs");
        assert!(!r_b.utxos.is_empty(), "B got UTXOs");
    }

    #[test]
    fn locked_utxos_are_committed_as_locked_and_are_not_selectable_again() {
        // The result the caller receives must match what is durably reserved in
        // the database: every returned UTXO is LOCKED under this request's id,
        // and no later call can select it again.
        let (pool, account_id, _temp) = setup_test_env(2, 1_000_000);
        let locker = FundLocker::new();

        let first = locker
            .lock(
                &mut pool.get().expect("conn"),
                account_id,
                MicroMinotari(100_000),
                1,
                MicroMinotari(1),
                Some(1000),
                test_binding(None, 1),
                3600,
                100,
            )
            .expect("first lock");

        // The seeded outputs have distinct values, so value identifies the row.
        let conn = pool.get().expect("conn");
        let locked_values: HashSet<i64> = conn
            .prepare("SELECT value FROM outputs WHERE status = 'LOCKED' AND locked_by_request_id IS NOT NULL")
            .expect("prepare")
            .query_map([], |row| row.get::<_, i64>(0))
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("collect");

        assert_eq!(
            locked_values.len(),
            first.utxos.len(),
            "exactly the returned UTXOs should be reserved",
        );
        for utxo in &first.utxos {
            assert!(
                locked_values.contains(&(utxo.value().as_u64() as i64)),
                "returned UTXO is not LOCKED in the database",
            );
        }

        // A second lock must pick from what is left, never from the reserved set.
        let second = locker
            .lock(
                &mut pool.get().expect("conn"),
                account_id,
                MicroMinotari(100_000),
                1,
                MicroMinotari(1),
                Some(1000),
                test_binding(None, 1),
                3600,
                100,
            )
            .expect("second lock");
        let first_hashes: HashSet<FixedHash> = first.utxos.iter().map(|u| u.output_hash()).collect();
        for utxo in &second.utxos {
            assert!(
                !first_hashes.contains(&utxo.output_hash()),
                "second lock handed back an already-reserved UTXO",
            );
        }
    }

    #[test]
    fn a_failed_lock_leaves_no_pending_transaction_behind() {
        // Selection happens inside the write transaction, so when it fails
        // (here: nothing left to select) nothing at all is committed.
        let (pool, account_id, _temp) = setup_test_env(1, 1_000_000);
        let locker = FundLocker::new();

        locker
            .lock(
                &mut pool.get().expect("conn"),
                account_id,
                MicroMinotari(500_000),
                1,
                MicroMinotari(1),
                Some(1000),
                test_binding(None, 1),
                3600,
                100,
            )
            .expect("first lock consumes the only UTXO");

        locker
            .lock(
                &mut pool.get().expect("conn"),
                account_id,
                MicroMinotari(500_000),
                1,
                MicroMinotari(1),
                Some(1000),
                test_binding(Some("doomed-key"), 1),
                3600,
                100,
            )
            .expect_err("no spendable UTXOs remain");

        let conn = pool.get().expect("conn");
        let doomed: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pending_transactions WHERE idempotency_key = :key",
                named_params! { ":key": "doomed-key" },
                |row| row.get(0),
            )
            .expect("count pending transactions");
        assert_eq!(doomed, 0, "a failed lock must not leave a pending transaction");
    }

    // -----------------------------------------------------------------------
    // Lock duration bounds
    // -----------------------------------------------------------------------

    #[test]
    fn lock_expiry_accepts_durations_up_to_the_maximum() {
        let now = Utc::now();

        for seconds in [0, 1, 86_400, MAX_SECONDS_TO_LOCK_UTXOS] {
            let expires_at = lock_expiry_at(now, seconds).expect("duration within bounds is accepted");
            assert_eq!(
                expires_at - now,
                TimeDelta::try_seconds(seconds as i64).expect("representable"),
                "expiry for {seconds}s"
            );
        }
    }

    #[test]
    fn lock_expiry_rejects_out_of_range_durations_instead_of_panicking() {
        let now = Utc::now();

        // The value from the original report: large enough that
        // `Utc::now() + Duration::seconds(..)` overflows chrono's `DateTime`
        // range and panics.
        assert_eq!(
            lock_expiry_at(now, 10_000_000_000_000),
            Err(InvalidLockDuration(10_000_000_000_000))
        );
        // Just past the bound.
        assert_eq!(
            lock_expiry_at(now, MAX_SECONDS_TO_LOCK_UTXOS + 1),
            Err(InvalidLockDuration(MAX_SECONDS_TO_LOCK_UTXOS + 1))
        );
        // Would wrap to a negative offset under the old `as i64` cast, silently
        // producing an expiry in the past.
        assert_eq!(lock_expiry_at(now, u64::MAX), Err(InvalidLockDuration(u64::MAX)));
        assert_eq!(
            lock_expiry_at(now, i64::MAX as u64 + 1),
            Err(InvalidLockDuration(i64::MAX as u64 + 1))
        );
    }

    #[test]
    fn lock_rejects_out_of_range_duration_without_poisoning_the_mutex() {
        let (pool, account_id, _temp) = setup_test_env(3, 1_000_000);
        let locker = FundLocker::new();

        let err = locker
            .lock(
                &mut pool.get().expect("conn"),
                account_id,
                MicroMinotari(100_000),
                1,
                MicroMinotari(1),
                Some(1000),
                test_binding(None, 1),
                10_000_000_000_000,
                100,
            )
            .expect_err("absurd lock duration is rejected");
        assert!(
            err.downcast_ref::<InvalidLockDuration>().is_some(),
            "expected InvalidLockDuration, got: {err}"
        );

        // The rejected request must not have bricked the locker: a well-formed
        // request afterwards still succeeds.  Before the fix, the panic above
        // poisoned `FUND_LOCK_MUTEX` and every later call died at the `.expect`.
        let result = locker
            .lock(
                &mut pool.get().expect("conn"),
                account_id,
                MicroMinotari(100_000),
                1,
                MicroMinotari(1),
                Some(1000),
                test_binding(None, 1),
                3600,
                100,
            )
            .expect("subsequent lock still works");
        assert!(!result.utxos.is_empty(), "subsequent lock selected UTXOs");
    }

    #[test]
    fn lock_survives_a_poisoned_mutex() {
        // Poison the global mutex the way a panic inside the critical section
        // would, then assert that `lock()` still makes progress rather than
        // failing for the lifetime of the process.
        let poisoner = std::thread::spawn(|| {
            let _guard = FUND_LOCK_MUTEX.lock().expect("acquire");
            panic!("simulated panic while holding the fund lock");
        });
        assert!(poisoner.join().is_err(), "poisoning thread panicked as intended");
        assert!(FUND_LOCK_MUTEX.is_poisoned(), "mutex is poisoned");

        let (pool, account_id, _temp) = setup_test_env(3, 1_000_000);
        let result = FundLocker::new()
            .lock(
                &mut pool.get().expect("conn"),
                account_id,
                MicroMinotari(100_000),
                1,
                MicroMinotari(1),
                Some(1000),
                test_binding(None, 1),
                3600,
                100,
            )
            .expect("lock recovers from a poisoned mutex");
        assert!(!result.utxos.is_empty(), "lock selected UTXOs after recovery");
    }

    // -----------------------------------------------------------------------
    // Idempotency key scoping
    // -----------------------------------------------------------------------

    fn conflict(err: &Error) -> &IdempotencyConflict {
        err.downcast_ref::<IdempotencyConflict>()
            .unwrap_or_else(|| panic!("expected an IdempotencyConflict, got: {err}"))
    }

    #[test]
    fn an_exact_retry_returns_the_original_reservation() {
        let (pool, account_id, _temp) = setup_test_env(3, 1_000_000);

        let first = lock_with(&pool, account_id, test_binding(Some("k"), 1)).expect("first lock");
        let retry = lock_with(&pool, account_id, test_binding(Some("k"), 1)).expect("retry is idempotent");

        let first_hashes: HashSet<FixedHash> = first.utxos.iter().map(|u| u.output_hash()).collect();
        let retry_hashes: HashSet<FixedHash> = retry.utxos.iter().map(|u| u.output_hash()).collect();
        assert_eq!(first_hashes, retry_hashes, "a retry gets the same UTXOs back");
        assert_eq!(first.total_value, retry.total_value);
        assert_eq!(
            locked_values(&pool).len(),
            first.utxos.len(),
            "a retry must not reserve anything further",
        );
    }

    #[test]
    fn replaying_a_key_with_a_different_request_is_rejected() {
        // The reported attack: take a client's key, resend it with a different
        // body, and collect the UTXOs the client reserved. The changed body must
        // make the key unusable rather than short-circuit onto that reservation.
        let (pool, account_id, _temp) = setup_test_env(3, 1_000_000);

        let victim = lock_with(&pool, account_id, test_binding(Some("k"), 1)).expect("victim's lock");
        let reserved = locked_values(&pool);

        let err = lock_with(&pool, account_id, test_binding(Some("k"), 2))
            .expect_err("a replay with a different request must not be served");
        assert!(
            matches!(conflict(&err), IdempotencyConflict::RequestMismatch { .. }),
            "expected a request mismatch, got: {err}",
        );

        // The victim's reservation is untouched: same rows, still locked to it.
        assert_eq!(
            locked_values(&pool),
            reserved,
            "the original lock must survive the replay"
        );
        let retry = lock_with(&pool, account_id, test_binding(Some("k"), 1)).expect("the victim can still retry");
        let victim_hashes: HashSet<FixedHash> = victim.utxos.iter().map(|u| u.output_hash()).collect();
        let retry_hashes: HashSet<FixedHash> = retry.utxos.iter().map(|u| u.output_hash()).collect();
        assert_eq!(victim_hashes, retry_hashes);
    }

    #[test]
    fn a_key_cannot_be_redeemed_at_a_different_operation() {
        // A `/lock_funds` key replayed at `/burn` used to hand the burn the
        // reserved UTXOs and destroy them.
        let (pool, account_id, _temp) = setup_test_env(3, 1_000_000);

        lock_with(&pool, account_id, test_binding(Some("k"), 1)).expect("lock_funds reservation");
        let reserved = locked_values(&pool);

        let err = lock_with(
            &pool,
            account_id,
            scoped_test_binding(Some("k"), IdempotencyOperation::BurnFunds, 1),
        )
        .expect_err("a lock_funds key must not be redeemable as a burn");
        assert!(
            matches!(conflict(&err), IdempotencyConflict::OperationMismatch { .. }),
            "expected an operation mismatch, got: {err}",
        );
        assert_eq!(locked_values(&pool), reserved, "the reservation must be untouched");
    }

    #[test]
    fn a_completed_key_cannot_be_replayed() {
        // Once the transaction is broadcast its inputs are spent. Replaying the
        // key must fail rather than hand back UTXOs that no longer exist.
        let (pool, account_id, _temp) = setup_test_env(3, 1_000_000);

        lock_with(&pool, account_id, test_binding(Some("k"), 1)).expect("initial lock");
        let conn = pool.get().expect("conn");
        let pending_id: String = conn
            .query_row(
                "SELECT id FROM pending_transactions WHERE idempotency_key = :key",
                named_params! { ":key": "k" },
                |row| row.get(0),
            )
            .expect("pending transaction exists");
        crate::db::update_pending_transaction_status(&conn, &pending_id, PendingTransactionStatus::Completed)
            .expect("mark completed");
        drop(conn);

        let err = lock_with(&pool, account_id, test_binding(Some("k"), 1))
            .expect_err("a completed key must not be replayable");
        assert!(
            matches!(conflict(&err), IdempotencyConflict::AlreadyCompleted { .. }),
            "expected an already-completed conflict, got: {err}",
        );
    }

    #[test]
    fn an_expired_key_reports_why_instead_of_colliding() {
        let (pool, account_id, _temp) = setup_test_env(3, 1_000_000);

        lock_with(&pool, account_id, test_binding(Some("k"), 1)).expect("initial lock");
        let conn = pool.get().expect("conn");
        let pending_id: String = conn
            .query_row(
                "SELECT id FROM pending_transactions WHERE idempotency_key = :key",
                named_params! { ":key": "k" },
                |row| row.get(0),
            )
            .expect("pending transaction exists");
        crate::db::update_pending_transaction_status(&conn, &pending_id, PendingTransactionStatus::Expired)
            .expect("mark expired");
        drop(conn);

        let err =
            lock_with(&pool, account_id, test_binding(Some("k"), 1)).expect_err("an expired key cannot be reused");
        assert!(
            matches!(conflict(&err), IdempotencyConflict::NoLongerActive { .. }),
            "expected a no-longer-active conflict, got: {err}",
        );
    }

    #[test]
    fn a_legacy_row_without_a_recorded_scope_is_never_replayed_onto() {
        // Rows written before scopes existed carry empty strings. Their key must
        // not be usable, because there is nothing to check the request against.
        let (pool, account_id, _temp) = setup_test_env(3, 1_000_000);

        lock_with(&pool, account_id, test_binding(Some("k"), 1)).expect("initial lock");
        let conn = pool.get().expect("conn");
        conn.execute(
            "UPDATE pending_transactions SET operation = '', request_hash = '' WHERE idempotency_key = :key",
            named_params! { ":key": "k" },
        )
        .expect("blank the scope the way a pre-migration row would be");
        drop(conn);

        let err = lock_with(&pool, account_id, test_binding(Some("k"), 1))
            .expect_err("a row with no recorded scope cannot be matched");
        assert!(
            matches!(conflict(&err), IdempotencyConflict::OperationMismatch { .. }),
            "expected an operation mismatch, got: {err}",
        );
    }

    #[test]
    fn requests_without_a_key_never_share_a_reservation() {
        // Each keyless request gets its own generated key, so two of them must
        // select disjoint UTXOs rather than collapsing onto one reservation.
        let (pool, account_id, _temp) = setup_test_env(3, 1_000_000);

        let first = lock_with(&pool, account_id, test_binding(None, 1)).expect("first lock");
        let second = lock_with(&pool, account_id, test_binding(None, 1)).expect("second lock");

        let first_hashes: HashSet<FixedHash> = first.utxos.iter().map(|u| u.output_hash()).collect();
        for utxo in &second.utxos {
            assert!(
                !first_hashes.contains(&utxo.output_hash()),
                "a keyless request reused another request's reservation",
            );
        }
    }

    #[test]
    fn a_fee_below_the_minimum_is_refused_before_anything_is_locked() {
        let (pool, account_id, _temp) = setup_test_env(1, 1_000_000);

        let error = FundLocker::new()
            .lock(
                &mut pool.get().expect("conn"),
                account_id,
                MicroMinotari(500_000),
                1,
                MicroMinotari(0),
                Some(1000),
                test_binding(Some("zero-fee"), 1),
                3600,
                100,
            )
            .expect_err("a zero fee per gram is refused");
        assert_eq!(
            error.downcast_ref::<FeePerGramTooLow>(),
            Some(&FeePerGramTooLow {
                fee_per_gram: MicroMinotari(0),
                minimum: MIN_FEE_PER_GRAM,
            })
        );

        // Nothing was reserved or locked.
        let conn = pool.get().expect("conn");
        let pending: i64 = conn
            .query_row("SELECT COUNT(*) FROM pending_transactions", [], |row| row.get(0))
            .expect("count");
        assert_eq!(pending, 0);
        let locked: i64 = conn
            .query_row("SELECT COUNT(*) FROM outputs WHERE status = 'LOCKED'", [], |row| {
                row.get(0)
            })
            .expect("count");
        assert_eq!(locked, 0);

        assert!(validate_fee_per_gram(MIN_FEE_PER_GRAM).is_ok());
    }
}
