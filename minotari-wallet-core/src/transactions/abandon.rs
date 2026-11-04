//! Abandoning a send the base node has not accepted.
//!
//! The node's answers never reject a send (see [`crate::transactions::monitor`]):
//! a send it keeps refusing stays pending, its inputs locked, and is rebroadcast
//! less often once stalled. [`abandon_send`] lets the user give such a send up
//! and get its inputs back.
//!
//! Abandoning does not unsend anything. If a node still holds the signed
//! transaction it can still be mined; the wallet's scan then finds its change
//! output and marks it mined (`MinedUnconfirmed`) after all. A send without a
//! change output cannot be recognised that way, so it is only abandoned when
//! the caller accepts that (`accept_unreconcilable`).

use log::warn;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use tari_common_types::transaction::TxId;
use tari_transaction_components::transaction_components::Transaction;
use thiserror::Error;

use crate::{
    db::{self, CompletedTransactionStatus, WalletDbError},
    models::{OutputStatus, WalletEvent, WalletEventType},
    transactions::{DisplayedTransaction, monitor::MAX_BROADCAST_ATTEMPTS},
    webhooks::{WebhookTriggerConfig, utils::trigger_webhook_with_balance},
};

/// The rejection reason recorded for an abandoned send.
pub const ABANDONED_REASON: &str = "abandoned by user";

/// What abandoning a send with a change output does not do.
pub const ABANDON_NOTE: &str = "The send is abandoned and its inputs are released. If a node still holds the \
     transaction it can still be mined: the wallet will then show it as mined, and a send made with the released \
     funds in the meantime will fail.";

/// What abandoning a send without a change output does not do.
pub const UNRECONCILABLE_ABANDON_NOTE: &str = "The send is abandoned and its inputs are released. WARNING: it has \
     no change output, so if a node still holds the transaction and it is mined, the wallet will NOT show it as \
     mined: it stays rejected while its inputs show as spent, and a send made with the released funds in the \
     meantime will fail.";

/// Why a send cannot be abandoned.
#[derive(Debug, Error)]
pub enum AbandonSendError {
    #[error("No send {0} in this account")]
    NotFound(TxId),
    #[error("Send {tx_id} is {status}; only a send that is not mined yet (completed or broadcast) can be abandoned")]
    NotPending { tx_id: TxId, status: String },
    #[error(
        "Send {tx_id} is not stalled ({attempts} broadcasts in a row not accepted, stalled at {MAX_BROADCAST_ATTEMPTS}); \
         pass force to abandon it anyway"
    )]
    NotStalled { tx_id: TxId, attempts: i32 },
    #[error("An input of send {tx_id} has already been spent on chain; the wallet's scan settles it")]
    InputSpent { tx_id: TxId },
    #[error("The change of send {tx_id} is an input of another send ({by}); abandon or settle that send first")]
    ChangeInUse { tx_id: TxId, by: String },
    #[error(
        "The change of send {tx_id} has already been seen on chain: the send appears to have landed; \
         wait for the wallet's scan to settle it"
    )]
    ChangeAlreadyMined { tx_id: TxId },
    #[error(
        "Send {tx_id} has no change output, so the wallet could not recognise it if it is mined after all; \
         refusing. Pass accept_unreconcilable to abandon it anyway"
    )]
    NoChangeOutput { tx_id: TxId },
    #[error(transparent)]
    Db(#[from] WalletDbError),
}

impl From<rusqlite::Error> for AbandonSendError {
    fn from(e: rusqlite::Error) -> Self {
        AbandonSendError::Db(WalletDbError::from(e))
    }
}

/// What abandoning a send did.
#[derive(Debug, Clone)]
pub struct AbandonedSend {
    /// The persisted `TransactionRejected` event.
    pub event: WalletEvent,
    /// The send's displayed transaction, now rejected, if it has one.
    pub displayed_transaction: Option<DisplayedTransaction>,
    /// Whether the send has a change output, by which the scan recognises it
    /// if it is mined after all.
    pub reconcilable: bool,
}

impl AbandonedSend {
    /// What abandoning this send does not do: [`ABANDON_NOTE`], or
    /// [`UNRECONCILABLE_ABANDON_NOTE`] for a send without a change output.
    pub fn note(&self) -> &'static str {
        if self.reconcilable {
            ABANDON_NOTE
        } else {
            UNRECONCILABLE_ABANDON_NOTE
        }
    }
}

/// Gives up a send the node has not accepted, and hands its inputs back.
///
/// Only a send that is `Completed` or `Broadcast` can be abandoned. Unless
/// `force` is set it must also be stalled: the node has not accepted it
/// [`MAX_BROADCAST_ATTEMPTS`] times in a row. A send any of whose inputs has
/// already been seen spent on chain is refused: the scan settles it. So is a
/// send whose change output is an input of another send that can still land
/// (a lock left by one that cannot is dropped), and one whose change output has
/// already been seen on chain (the send appears to have landed).
///
/// The scan recognises an abandoned send that is mined after all by its change
/// output. A send without one is refused ([`AbandonSendError::NoChangeOutput`])
/// unless `accept_unreconcilable` is set: if it is mined after all, it stays
/// rejected in the wallet.
///
/// In one write transaction: the send is marked `Rejected` ("abandoned by
/// user"), its change output `REJECTED` (kept, so the scan can still recognise
/// the send if it is mined after all), its inputs still locked are released,
/// its displayed transaction rejected, and a `TransactionRejected` event
/// persisted (with its webhook when `webhook_config` is given).
///
/// The original transaction can still be mined if a node holds it; the scan
/// then marks it `MinedUnconfirmed` (when it has a change output). A released
/// input spent again in the meantime then loses to it.
pub fn abandon_send(
    conn: &mut Connection,
    account_id: i64,
    tx_id: TxId,
    force: bool,
    accept_unreconcilable: bool,
    webhook_config: Option<&WebhookTriggerConfig>,
) -> Result<AbandonedSend, AbandonSendError> {
    let db_tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let send = match db::get_completed_transaction_by_id(&db_tx, tx_id)? {
        Some(send) if send.account_id == account_id => send,
        _ => return Err(AbandonSendError::NotFound(tx_id)),
    };
    if !matches!(
        send.status,
        CompletedTransactionStatus::Completed | CompletedTransactionStatus::Broadcast
    ) {
        return Err(AbandonSendError::NotPending {
            tx_id,
            status: send.status.to_string(),
        });
    }
    if !force && send.broadcast_attempts < MAX_BROADCAST_ATTEMPTS {
        return Err(AbandonSendError::NotStalled {
            tx_id,
            attempts: send.broadcast_attempts,
        });
    }

    // Refuse if the chain already spent any of its inputs: then the send either
    // landed or lost to another transaction, and the scan decides which.
    if let Ok(transaction) = serde_json::from_slice::<Transaction>(&send.serialized_transaction) {
        for input in transaction.body().inputs() {
            if db::get_output_spend(&db_tx, account_id, &input.output_hash())?.is_some() {
                return Err(AbandonSendError::InputSpent { tx_id });
            }
        }
    }
    let spent_inputs: i64 = db_tx.query_row(
        r#"
        SELECT COUNT(*) FROM outputs o
        WHERE o.locked_by_request_id = :req AND o.status = 'SPENT' AND o.deleted_at IS NULL
          AND EXISTS (SELECT 1 FROM inputs i WHERE i.output_id = o.id AND i.deleted_at IS NULL)
        "#,
        rusqlite::named_params! { ":req": send.pending_tx_id },
        |row| row.get(0),
    )?;
    if spent_inputs > 0 {
        return Err(AbandonSendError::InputSpent { tx_id });
    }

    // The scan recognises the send by its change output if it is mined after
    // all; it must still be unconfirmed (no real mined data), or the send has
    // landed already.
    let change: Option<(i64, String, i64, Option<String>)> = db_tx
        .query_row(
            r#"
            SELECT id, status, mined_in_block_height, locked_by_request_id
            FROM outputs WHERE created_by_request_id = :req AND deleted_at IS NULL
            "#,
            rusqlite::named_params! { ":req": send.pending_tx_id },
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let reconcilable = change.is_some();
    match change {
        None if !accept_unreconcilable => return Err(AbandonSendError::NoChangeOutput { tx_id }),
        None => {},
        Some((change_id, status, mined_height, change_lock)) => {
            if status != OutputStatus::Unconfirmed.to_string() || mined_height != 0 {
                return Err(AbandonSendError::ChangeAlreadyMined { tx_id });
            }
            // It may be an input of a later send (a reorg made it unconfirmed
            // again). Rejecting it would strand that send, and its lock with it.
            // A lock left by a request that can no longer land holds nothing:
            // it is dropped, so the rejected change does not carry it.
            if let Some(by) = change_lock
                && by != send.pending_tx_id
            {
                if db::is_lock_holder_live(&db_tx, &by)? {
                    return Err(AbandonSendError::ChangeInUse { tx_id, by });
                }
                db::clear_dead_lock(&db_tx, change_id)?;
            }
        },
    }

    warn!(
        target: "audit",
        reconcilable = reconcilable;
        "Send abandoned by user; its inputs are released"
    );
    db::mark_completed_transaction_as_rejected(&db_tx, tx_id, ABANDONED_REASON)?;
    // Before the release, which soft-deletes an `UNCONFIRMED` change: the change
    // is kept, `REJECTED`, so the scan can still recognise the send by it.
    db::mark_change_output_rejected(&db_tx, &send.pending_tx_id)?;
    db::unlock_outputs_for_request(&db_tx, &send.pending_tx_id)?;
    // An input a reorg un-spent (its spend record removed) is still marked
    // `SPENT`; it is not spent on chain, so it is handed back too.
    db_tx.execute(
        r#"
        UPDATE outputs
        SET status = 'UNSPENT', locked_by_request_id = NULL, locked_at = NULL
        WHERE locked_by_request_id = :req AND status = 'SPENT' AND deleted_at IS NULL
          AND NOT EXISTS (SELECT 1 FROM inputs i WHERE i.output_id = outputs.id AND i.deleted_at IS NULL)
        "#,
        rusqlite::named_params! { ":req": send.pending_tx_id },
    )?;
    let displayed_transaction = db::mark_displayed_transaction_rejected(&db_tx, tx_id)?;

    let mut event = WalletEvent {
        id: 0,
        account_id,
        event_type: WalletEventType::TransactionRejected {
            tx_id,
            reason: ABANDONED_REASON.to_string(),
        },
        description: format!("Transaction {} abandoned by user", tx_id),
    };
    let event_id = db::insert_wallet_event(&db_tx, account_id, &event)?;
    if let Some(config) = webhook_config {
        trigger_webhook_with_balance(&db_tx, account_id, event_id, &event, config)?;
    }
    event.id = event_id;

    db_tx.commit()?;
    Ok(AbandonedSend {
        event,
        displayed_transaction,
        reconcilable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{SqlitePool, create_account, get_account_by_name, init_db};
    use crate::transactions::idempotency::{IdempotencyBinding, IdempotencyOperation, RequestFingerprint};
    use crate::transactions::{
        BlockchainInfo, TransactionDetails, TransactionDirection, TransactionDisplayStatus, TransactionSource,
    };
    use chrono::Utc;
    use rusqlite::named_params;
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_common_types::types::{ComAndPubSignature, CompressedPublicKey, FixedHash, PrivateKey};
    use tari_script::{ExecutionStack, TariScript};
    use tari_transaction_components::MicroMinotari;
    use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
    use tari_transaction_components::key_manager::{KeyManager, TariKeyId, TransactionKeyManagerInterface};
    use tari_transaction_components::transaction_components::{
        EncryptedData, MemoField, OutputFeatures, TransactionInput, TransactionOutputVersion, WalletOutput,
        covenants::Covenant,
    };
    use tempfile::TempDir;

    fn test_wallet_output(value: u64, hash_byte: u8) -> WalletOutput {
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
            FixedHash::from([hash_byte; 32]),
            Default::default(),
        )
    }

    struct Send {
        pool: SqlitePool,
        account_id: i64,
        tx_id: TxId,
        request_id: String,
        input_id: i64,
        _dir: TempDir,
    }

    /// A broadcast send that the node has not accepted `attempts` times in a
    /// row: one input locked to it, an `UNCONFIRMED` change, a pending entry.
    fn send_with_attempts(attempts: i32) -> Send {
        let dir = tempfile::tempdir().expect("temp dir");
        let pool = init_db(dir.path().join("abandon.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
        create_account(&conn, "default", &wallet, "password").unwrap();
        let account_id = get_account_by_name(&conn, "default").unwrap().unwrap().id;
        let view_key = KeyManager::new(wallet).unwrap().get_private_view_key();

        let binding = IdempotencyBinding::new(
            Some("send".to_string()),
            IdempotencyOperation::SendTransaction,
            RequestFingerprint::new(IdempotencyOperation::SendTransaction),
        );
        let request_id = db::create_pending_transaction(
            &conn,
            "send",
            &binding,
            account_id,
            true,
            MicroMinotari(0),
            MicroMinotari(0),
            MicroMinotari(0),
            Utc::now() + chrono::Duration::hours(1),
        )
        .expect("pending");
        let input = test_wallet_output(10_000, 1);
        let input_id = db::insert_output(
            &conn,
            account_id,
            &view_key,
            input.output_hash().to_vec(),
            &input,
            10,
            &FixedHash::from([10u8; 32]),
            1_700_000_000,
            None,
            None,
            FixedHash::zero(),
            false,
        )
        .expect("input");
        db::lock_output(&conn, input_id, &request_id, Utc::now()).expect("lock");
        let transaction = Transaction::new(
            vec![TransactionInput::new_with_output_hash(
                input.output_hash(),
                ExecutionStack::default(),
                ComAndPubSignature::default(),
            )],
            Vec::new(),
            Vec::new(),
            PrivateKey::default(),
            PrivateKey::default(),
        );
        let tx_id = TxId::from(1u64);
        db::create_completed_transaction(
            &conn,
            account_id,
            &request_id,
            &[],
            &serde_json::to_vec(&transaction).expect("serialize"),
            None,
            tx_id,
        )
        .expect("completed");
        db::mark_completed_transaction_as_broadcasted(&conn, tx_id, attempts).expect("broadcast");
        db::insert_unconfirmed_change_output(&conn, account_id, &view_key, &request_id, &test_wallet_output(3_000, 3))
            .expect("change");
        db::insert_displayed_transaction(
            &conn,
            &DisplayedTransaction {
                id: tx_id,
                direction: TransactionDirection::Outgoing,
                source: TransactionSource::OneSided,
                status: TransactionDisplayStatus::Pending,
                amount: MicroMinotari::from(1_000),
                message: None,
                counterparty: None,
                blockchain: BlockchainInfo {
                    block_height: 0,
                    timestamp: Utc::now().naive_utc(),
                    confirmations: 0,
                    block_hash: FixedHash::zero(),
                },
                fee: None,
                details: TransactionDetails {
                    account_id,
                    total_credit: MicroMinotari::from(0),
                    total_debit: MicroMinotari::from(1_000),
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                    output_type: None,
                    coinbase_extra: None,
                    memo_hex: None,
                    sent_output_hashes: Vec::new(),
                    sent_payrefs: Vec::new(),
                },
                lock_height: 0,
            },
        )
        .expect("displayed");
        drop(conn);
        Send {
            pool,
            account_id,
            tx_id,
            request_id,
            input_id,
            _dir: dir,
        }
    }

    fn abandon(send: &Send, force: bool) -> Result<AbandonedSend, AbandonSendError> {
        abandon_send(
            &mut send.pool.get().expect("conn"),
            send.account_id,
            send.tx_id,
            force,
            false,
            None,
        )
    }

    fn abandon_unreconcilable(send: &Send) -> Result<AbandonedSend, AbandonSendError> {
        abandon_send(
            &mut send.pool.get().expect("conn"),
            send.account_id,
            send.tx_id,
            true,
            true,
            None,
        )
    }

    fn input_row(send: &Send) -> (String, Option<String>) {
        let conn = send.pool.get().expect("conn");
        conn.query_row(
            "SELECT status, locked_by_request_id FROM outputs WHERE id = :id",
            named_params! { ":id": send.input_id },
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("input")
    }

    fn remove_change(send: &Send) {
        let conn = send.pool.get().expect("conn");
        conn.execute(
            "DELETE FROM outputs WHERE created_by_request_id = :req",
            named_params! { ":req": send.request_id },
        )
        .expect("delete change");
    }

    fn status_of(send: &Send) -> CompletedTransactionStatus {
        let conn = send.pool.get().expect("conn");
        db::get_completed_transaction_by_id(&conn, send.tx_id)
            .expect("query")
            .expect("exists")
            .status
    }

    /// The input's status and lock, and the change's status and whether it is active.
    fn rows(send: &Send) -> ((String, Option<String>), (String, bool)) {
        let conn = send.pool.get().expect("conn");
        let input = conn
            .query_row(
                "SELECT status, locked_by_request_id FROM outputs WHERE id = :id",
                named_params! { ":id": send.input_id },
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("input");
        let change = conn
            .query_row(
                "SELECT status, deleted_at IS NULL FROM outputs WHERE created_by_request_id = :req",
                named_params! { ":req": send.request_id },
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("change");
        (input, change)
    }

    #[test]
    fn a_rebroadcast_landing_after_the_abandon_does_not_revive_the_send() {
        let send = send_with_attempts(MAX_BROADCAST_ATTEMPTS);
        abandon(&send, false).expect("abandon");

        // The monitor's in-flight rebroadcast is accepted by the node and lands now.
        let conn = send.pool.get().expect("conn");
        let updated = db::mark_completed_transaction_as_broadcasted(&conn, send.tx_id, 0).expect("update");
        drop(conn);

        assert!(!updated);
        assert_eq!(status_of(&send), CompletedTransactionStatus::Rejected);
        assert_eq!(input_row(&send), ("UNSPENT".to_string(), None));
    }

    #[test]
    fn a_stalled_send_is_abandoned_and_its_inputs_released() {
        let send = send_with_attempts(MAX_BROADCAST_ATTEMPTS);

        let abandoned = abandon(&send, false).expect("abandon");

        assert_eq!(status_of(&send), CompletedTransactionStatus::Rejected);
        let conn = send.pool.get().expect("conn");
        let completed = db::get_completed_transaction_by_id(&conn, send.tx_id).unwrap().unwrap();
        assert_eq!(completed.last_rejected_reason.as_deref(), Some(ABANDONED_REASON));
        assert_eq!(completed.mined_height, None);
        let ((input_status, input_lock), (change_status, change_active)) = rows(&send);
        assert_eq!(input_status, "UNSPENT");
        assert_eq!(input_lock, None);
        assert_eq!(change_status, "REJECTED");
        assert!(change_active, "the change is kept so the scan can still find the send");
        assert_eq!(
            abandoned.displayed_transaction.map(|d| d.status),
            Some(TransactionDisplayStatus::Rejected)
        );
        assert!(matches!(
            &abandoned.event.event_type,
            WalletEventType::TransactionRejected { reason, .. } if reason == ABANDONED_REASON
        ));
        let stored = db::get_events_by_account_id(&conn, send.account_id, 10, 0).expect("events");
        assert!(stored.iter().any(|e| e.event_type == "TransactionRejected"));
    }

    #[test]
    fn a_send_that_is_not_stalled_needs_force() {
        let send = send_with_attempts(1);
        assert!(matches!(
            abandon(&send, false),
            Err(AbandonSendError::NotStalled { attempts: 1, .. })
        ));
        assert_eq!(status_of(&send), CompletedTransactionStatus::Broadcast);
        assert_eq!(rows(&send).0.0, "LOCKED");

        abandon(&send, true).expect("abandon with force");
        assert_eq!(status_of(&send), CompletedTransactionStatus::Rejected);
    }

    #[test]
    fn a_send_whose_input_is_spent_on_chain_cannot_be_abandoned() {
        let send = send_with_attempts(MAX_BROADCAST_ATTEMPTS);
        {
            let conn = send.pool.get().expect("conn");
            db::insert_input(&conn, send.account_id, send.input_id, 50, &[5u8; 32], 1_700_000_000).expect("spend");
            db::update_output_status(&conn, send.input_id, crate::models::OutputStatus::Spent).expect("spent");
        }
        assert!(matches!(abandon(&send, true), Err(AbandonSendError::InputSpent { .. })));
        assert_eq!(status_of(&send), CompletedTransactionStatus::Broadcast);
    }

    #[test]
    fn a_mined_or_rejected_send_cannot_be_abandoned() {
        let send = send_with_attempts(MAX_BROADCAST_ATTEMPTS);
        {
            let conn = send.pool.get().expect("conn");
            db::mark_completed_transaction_as_mined_unconfirmed(&conn, send.tx_id, 50, &[5u8; 32]).expect("mined");
        }
        assert!(matches!(abandon(&send, true), Err(AbandonSendError::NotPending { .. })));

        let rejected = send_with_attempts(MAX_BROADCAST_ATTEMPTS);
        abandon(&rejected, false).expect("abandon");
        assert!(matches!(
            abandon(&rejected, true),
            Err(AbandonSendError::NotPending { .. })
        ));
    }

    #[test]
    fn another_accounts_send_is_not_found() {
        let send = send_with_attempts(MAX_BROADCAST_ATTEMPTS);
        assert!(matches!(
            abandon_send(
                &mut send.pool.get().expect("conn"),
                send.account_id + 1,
                send.tx_id,
                true,
                false,
                None
            ),
            Err(AbandonSendError::NotFound(_))
        ));
    }

    #[test]
    fn a_send_whose_change_is_already_mined_cannot_be_abandoned() {
        // The scan saw the change in a block: the send landed.
        let send = send_with_attempts(MAX_BROADCAST_ATTEMPTS);
        {
            let conn = send.pool.get().expect("conn");
            conn.execute(
                "UPDATE outputs SET status = 'UNSPENT', mined_in_block_height = 50 WHERE created_by_request_id = :req",
                named_params! { ":req": send.request_id },
            )
            .expect("mine change");
        }
        assert!(matches!(
            abandon(&send, true),
            Err(AbandonSendError::ChangeAlreadyMined { .. })
        ));
        assert_eq!(status_of(&send), CompletedTransactionStatus::Broadcast);
        assert_eq!(input_row(&send).0, "LOCKED");

        // Still flagged unconfirmed but with real mined data: refused too.
        let send = send_with_attempts(MAX_BROADCAST_ATTEMPTS);
        {
            let conn = send.pool.get().expect("conn");
            conn.execute(
                "UPDATE outputs SET mined_in_block_height = 50 WHERE created_by_request_id = :req",
                named_params! { ":req": send.request_id },
            )
            .expect("mined height");
        }
        assert!(matches!(
            abandon(&send, true),
            Err(AbandonSendError::ChangeAlreadyMined { .. })
        ));
        assert_eq!(status_of(&send), CompletedTransactionStatus::Broadcast);
    }

    #[test]
    fn a_send_without_change_is_refused_unless_accepted_as_unreconcilable() {
        let send = send_with_attempts(MAX_BROADCAST_ATTEMPTS);
        remove_change(&send);

        assert!(matches!(
            abandon(&send, true),
            Err(AbandonSendError::NoChangeOutput { .. })
        ));
        assert_eq!(status_of(&send), CompletedTransactionStatus::Broadcast);
        assert_eq!(input_row(&send).0, "LOCKED");

        let abandoned = abandon_unreconcilable(&send).expect("abandon, accepting it is unreconcilable");
        assert!(!abandoned.reconcilable);
        assert_eq!(abandoned.note(), UNRECONCILABLE_ABANDON_NOTE);
        assert_eq!(status_of(&send), CompletedTransactionStatus::Rejected);
        assert_eq!(input_row(&send), ("UNSPENT".to_string(), None));
    }

    #[test]
    fn a_send_with_change_gets_the_reconcilable_note() {
        let send = send_with_attempts(MAX_BROADCAST_ATTEMPTS);
        let abandoned = abandon_unreconcilable(&send).expect("the flag does not matter when there is change");
        assert!(abandoned.reconcilable);
        assert_eq!(abandoned.note(), ABANDON_NOTE);
    }

    fn lock_change(send: &Send, by: &str) {
        let conn = send.pool.get().expect("conn");
        conn.execute(
            "UPDATE outputs SET locked_by_request_id = :by, locked_at = :now WHERE created_by_request_id = :req",
            named_params! { ":by": by, ":now": Utc::now(), ":req": send.request_id },
        )
        .expect("lock change");
    }

    fn change_lock(send: &Send) -> (String, Option<String>) {
        let conn = send.pool.get().expect("conn");
        conn.query_row(
            "SELECT status, locked_by_request_id FROM outputs WHERE created_by_request_id = :req",
            named_params! { ":req": send.request_id },
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("change")
    }

    #[test]
    fn a_change_locked_by_a_dead_request_is_freed_and_the_send_abandoned() {
        // The change was an input of a request that no longer exists.
        let send = send_with_attempts(MAX_BROADCAST_ATTEMPTS);
        lock_change(&send, "request-that-is-gone");

        abandon(&send, true).expect("a dead lock does not block abandoning");
        assert_eq!(status_of(&send), CompletedTransactionStatus::Rejected);
        assert_eq!(change_lock(&send), ("REJECTED".to_string(), None));
    }

    #[test]
    fn a_change_locked_by_a_live_reservation_is_in_use() {
        let send = send_with_attempts(MAX_BROADCAST_ATTEMPTS);
        let binding = IdempotencyBinding::new(
            Some("next".to_string()),
            IdempotencyOperation::SendTransaction,
            RequestFingerprint::new(IdempotencyOperation::SendTransaction),
        );
        let next = db::create_pending_transaction(
            &send.pool.get().expect("conn"),
            "next",
            &binding,
            send.account_id,
            true,
            MicroMinotari(0),
            MicroMinotari(0),
            MicroMinotari(0),
            Utc::now() + chrono::Duration::hours(1),
        )
        .expect("live reservation");
        lock_change(&send, &next);

        assert!(matches!(
            abandon(&send, true),
            Err(AbandonSendError::ChangeInUse { by, .. }) if by == next
        ));
        assert_eq!(status_of(&send), CompletedTransactionStatus::Broadcast);
        assert_eq!(change_lock(&send), ("UNCONFIRMED".to_string(), Some(next)));
    }
}
