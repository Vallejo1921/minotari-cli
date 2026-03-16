use crate::db::{self, WalletDbResult};
use crate::models::{WalletEvent, WebhookBalanceSnapshot, WebhookPayload};
use crate::webhooks::WebhookTriggerConfig;
use chrono::Utc;
use log::warn;
use rusqlite::Connection;

/// Enriches an event with the current account balance and enqueues it for webhook delivery.
///
/// This function should be called inside the same transaction that created the event
/// to ensure data consistency.
pub fn trigger_webhook_with_balance(
    conn: &Connection,
    account_id: i64,
    event_id: i64,
    event: &WalletEvent,
    config: &WebhookTriggerConfig,
) -> WalletDbResult<()> {
    let event_key = event.event_type.to_key_string();

    if let Some(allowed_events) = &config.send_only_event_types
        && !allowed_events.is_empty()
        && !allowed_events.contains(&event_key)
    {
        return Ok(());
    }

    let balance = db::get_balance(conn, account_id)?;

    let snapshot = WebhookBalanceSnapshot {
        available: balance.available.0,
        pending_incoming: balance.unconfirmed.0,
        pending_outgoing: balance.locked.0,
    };

    let payload = WebhookPayload {
        event_id,
        event_type: event.event_type.to_key_string(),
        created_at: Utc::now().to_rfc3339(),
        balance: Some(snapshot),
        data: event.event_type.clone(),
    };

    let payload_json = serde_json::to_string(&payload).map_err(|e| {
        warn!("Failed to serialize webhook payload: {}", e);
        crate::db::WalletDbError::Unexpected(format!("Serialization error: {}", e))
    })?;

    db::enqueue_webhook(conn, Some(event_id), &payload.event_type, &payload_json, &config.url)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{create_account, get_account_by_name, init_db, insert_balance_change, insert_wallet_event};
    use crate::models::{BalanceChange, WalletEvent, WalletEventType};
    use r2d2::PooledConnection;
    use r2d2_sqlite::SqliteConnectionManager;
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_common_types::types::FixedHash;
    use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
    use tari_transaction_components::tari_amount::MicroMinotari;
    use tempfile::tempdir;

    fn create_test_account(conn: &PooledConnection<SqliteConnectionManager>, name: &str) -> db::AccountRow {
        let seeds = CipherSeed::random();
        let wallet_type = WalletType::SeedWords(SeedWordsWallet::construct_new(seeds).unwrap());
        create_account(conn, name, &wallet_type, "password").unwrap();
        get_account_by_name(conn, name).unwrap().unwrap()
    }

    #[test]
    fn test_trigger_webhook_captures_correct_balance() {
        // Setup DB and Account
        let temp_dir = tempdir().unwrap();
        let pool = init_db(temp_dir.path().join("test_trigger.db")).unwrap();
        let conn = pool.get().unwrap();

        let account = create_test_account(&conn, "boss_account");

        // Setup Balance: 10,000 µT total, 2,000 µT spent = 8,000 µT Available
        let now = Utc::now().naive_utc();

        // Credit
        insert_balance_change(
            &conn,
            &BalanceChange {
                account_id: account.id,
                caused_by_output_id: None,
                caused_by_input_id: None,
                description: "Initial deposit".into(),
                balance_credit: MicroMinotari::from(10_000),
                balance_debit: MicroMinotari::from(0),
                effective_date: now,
                effective_height: 10,
                claimed_recipient_address: None,
                claimed_sender_address: None,
                memo_parsed: None,
                memo_hex: None,
                claimed_fee: None,
                claimed_amount: None,
                is_reversal: false,
                reversal_of_balance_change_id: None,
                is_reversed: false,
            },
        )
        .unwrap();

        // Debit
        insert_balance_change(
            &conn,
            &BalanceChange {
                account_id: account.id,
                caused_by_output_id: None,
                caused_by_input_id: None,
                description: "Coffee purchase".into(),
                balance_credit: MicroMinotari::from(0),
                balance_debit: MicroMinotari::from(2_000),
                effective_date: now,
                effective_height: 11,
                claimed_recipient_address: None,
                claimed_sender_address: None,
                memo_parsed: None,
                memo_hex: None,
                claimed_fee: None,
                claimed_amount: None,
                is_reversal: false,
                reversal_of_balance_change_id: None,
                is_reversed: false,
            },
        )
        .unwrap();

        // Setup Event
        let event = WalletEvent {
            id: 0,
            account_id: account.id,
            event_type: WalletEventType::TransactionConfirmed {
                tx_id: 12345_u64.into(),
                mined_height: 11,
                confirmation_height: 14,
            },
            description: "Confirmed!".into(),
        };
        let event_id = insert_wallet_event(&conn, account.id, &event).unwrap();

        // Execution: Trigger the webhook
        let webhook_url = "https://hooks.slack.com/services/T000/B000/XXXX";
        let config = WebhookTriggerConfig {
            url: webhook_url.to_string(),
            send_only_event_types: None,
        };

        trigger_webhook_with_balance(&conn, account.id, event_id, &event, &config).unwrap();

        // Assertions: Check the queue
        let mut stmt = conn.prepare("SELECT payload FROM webhook_queue").unwrap();
        let payload_json: String = stmt.query_row([], |r| r.get(0)).unwrap();

        // Parse the generated JSON to verify fields
        let parsed: serde_json::Value = serde_json::from_str(&payload_json).unwrap();

        assert_eq!(parsed["event_id"], event_id);
        assert_eq!(parsed["event_type"], "TransactionConfirmed");

        // Verify the Balance Snapshot logic
        // total(10000) - debit(2000) = 8000
        assert_eq!(parsed["balance"]["available"], 8_000);
        assert_eq!(parsed["balance"]["pending_incoming"], 0);
        assert_eq!(parsed["balance"]["pending_outgoing"], 0);

        // Verify the data payload contains the tx_id
        assert_eq!(parsed["data"]["TransactionConfirmed"]["tx_id"], 12345);
    }

    #[test]
    fn test_trigger_webhook_filtering() {
        let temp_dir = tempdir().unwrap();
        let pool = init_db(temp_dir.path().join("test_filtering.db")).unwrap();
        let conn = pool.get().unwrap();

        let account = create_test_account(&conn, "boss_account");
        let account_id = account.id;

        // Define a config that ONLY allows 'TransactionConfirmed'
        let config = WebhookTriggerConfig {
            url: "http://example.com".to_string(),
            send_only_event_types: Some(vec!["TransactionConfirmed".to_string()]),
        };

        // 1. Create an event that should be BLOCKED (OutputDetected)
        let blocked_event = WalletEvent {
            id: 0,
            account_id,
            event_type: WalletEventType::OutputDetected {
                hash: FixedHash::zero(),
                block_height: 10,
                block_hash: vec![],
                memo_parsed: None,
                memo_hex: None,
            },
            description: "Found output".into(),
        };
        let blocked_id = insert_wallet_event(&conn, account_id, &blocked_event).unwrap();

        // Attempt trigger
        trigger_webhook_with_balance(&conn, account_id, blocked_id, &blocked_event, &config).unwrap();

        // Verify queue is EMPTY
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM webhook_queue", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "Blocked event should not be queued");

        // 2. Create an event that should be ALLOWED (TransactionConfirmed)
        let allowed_event = WalletEvent {
            id: 0,
            account_id,
            event_type: WalletEventType::TransactionConfirmed {
                tx_id: 999_u64.into(),
                mined_height: 12,
                confirmation_height: 15,
            },
            description: "Confirmed transaction".into(),
        };
        let allowed_id = insert_wallet_event(&conn, account_id, &allowed_event).unwrap();

        // Attempt trigger
        trigger_webhook_with_balance(&conn, account_id, allowed_id, &allowed_event, &config).unwrap();

        // Verify queue has ONE item
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM webhook_queue", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "Allowed event should be queued");

        // Verify it is the correct event
        let event_type: String = conn
            .query_row("SELECT event_type FROM webhook_queue LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(event_type, "TransactionConfirmed");
    }
}
