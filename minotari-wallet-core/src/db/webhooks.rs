use crate::db::WalletDbResult;
use crate::webhooks::models::{WebhookQueueItem, WebhookStatus};
use chrono::NaiveDateTime;
use log::debug;
use rusqlite::{Connection, named_params};

/// Inserts a new webhook into the queue.
///
/// This is should be called within the same transaction that inserts the `WalletEvent`
pub fn enqueue_webhook(
    conn: &Connection,
    event_id: Option<i64>,
    event_type: &str,
    payload: &str,
    target_url: &str,
) -> WalletDbResult<i64> {
    debug!(
        event_type = event_type,
        target_url = target_url;
        "DB: Enqueuing webhook"
    );

    conn.execute(
        r#"
        INSERT INTO webhook_queue (
            event_id,
            event_type,
            payload,
            target_url,
            status,
            attempt_count,
            next_retry_at,
            created_at
        ) VALUES (
            :event_id,
            :event_type,
            :payload,
            :target_url,
            :status,
            0,
            datetime('now'),
            datetime('now')
        )
        "#,
        named_params! {
            ":event_id": event_id,
            ":event_type": event_type,
            ":payload": payload,
            ":target_url": target_url,
            ":status": WebhookStatus::Pending.to_string(),
        },
    )?;

    Ok(conn.last_insert_rowid())
}

/// Fetches webhooks that are ready to be processed.
///
/// This includes:
/// 1. New items (`pending`)
/// 2. Failed items ready for retry (`failed` AND `next_retry_at` <= now)
pub fn fetch_due_webhooks(conn: &Connection, limit: i64) -> WalletDbResult<Vec<WebhookQueueItem>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT
            id,
            event_id,
            event_type,
            payload,
            target_url,
            status,
            attempt_count,
            REPLACE(next_retry_at, ' ', 'T') as next_retry_at,
            REPLACE(created_at, ' ', 'T') as created_at,
            last_error
        FROM webhook_queue
        WHERE status IN ('pending', 'failed')
          AND next_retry_at <= datetime('now')
        ORDER BY next_retry_at ASC
        LIMIT :limit
        "#,
    )?;

    let rows = stmt.query_map(named_params! { ":limit": limit }, |row| {
        let status_str: String = row.get(5)?;
        let status = status_str.parse().unwrap_or(WebhookStatus::Failed); // Fallback safe

        Ok(WebhookQueueItem {
            id: row.get(0)?,
            event_id: row.get(1)?,
            event_type: row.get(2)?,
            payload: row.get(3)?,
            target_url: row.get(4)?,
            status,
            attempt_count: row.get(6)?,
            next_retry_at: row.get(7)?,
            created_at: row.get(8)?,
            last_error: row.get(9)?,
        })
    })?;

    let mut items = Vec::new();
    for row in rows {
        items.push(row?);
    }

    Ok(items)
}

/// Updates the status of a webhook after a delivery attempt.
///
/// Use this to mark as `Success`, `PermanentFailure`, or schedule a retry
/// by updating `status`, `attempt_count`, and `next_retry_at`.
pub fn update_webhook_status(
    conn: &Connection,
    id: i64,
    status: WebhookStatus,
    attempt_count: i32,
    next_retry_at: NaiveDateTime,
    last_error: Option<&str>,
) -> WalletDbResult<()> {
    debug!(
        id = id,
        status:% = status,
        attempt = attempt_count;
        "DB: Updating webhook status"
    );

    conn.execute(
        r#"
        UPDATE webhook_queue
        SET status = :status,
            attempt_count = :attempt_count,
            next_retry_at = :next_retry_at,
            last_error = :last_error
        WHERE id = :id
        "#,
        named_params! {
            ":id": id,
            ":status": status.to_string(),
            ":attempt_count": attempt_count,
            ":next_retry_at": next_retry_at.to_string(),
            ":last_error": last_error,
        },
    )?;

    Ok(())
}

/// Delete old webhooks
pub fn delete_webhooks_older_than(conn: &Connection, timestamp: NaiveDateTime) -> WalletDbResult<usize> {
    let count = conn.execute(
        "DELETE FROM webhook_queue WHERE created_at < :timestamp",
        named_params! { ":timestamp": timestamp.to_string() },
    )?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    use super::*;
    use crate::db::{create_account, get_account_by_name, init_db, insert_wallet_event};
    use crate::models::{WalletEvent, WalletEventType};
    use crate::webhooks::models::WebhookStatus;
    use chrono::{Duration, Utc};
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
    use tempfile::tempdir;

    #[test]
    fn test_webhook_queue_lifecycle() {
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let db_path = temp_dir.path().join("test_webhook_lifecycle.db");
        let pool = init_db(db_path).expect("Failed to init DB");
        let conn = pool.get().expect("Failed to get connection");
        let password = "very_secure_password_123";

        let seeds = CipherSeed::random();
        let seed_wallet = SeedWordsWallet::construct_new(seeds).unwrap();
        let wallet_type = WalletType::SeedWords(seed_wallet);

        create_account(&conn, "test_account", &wallet_type, password).expect("Failed to create account");
        let account = get_account_by_name(&conn, "test_account")
            .unwrap()
            .expect("Account not found");

        let event_type = WalletEventType::OutputDetected {
            hash: [0u8; 32].into(),
            block_height: 100,
            block_hash: vec![1u8; 32],
            memo_parsed: Some("Test Memo".to_string()),
            memo_hex: None,
        };
        let event = WalletEvent {
            id: 0,
            account_id: account.id,
            event_type: event_type.clone(),
            description: "Detected test output".to_string(),
        };

        let event_id = insert_wallet_event(&conn, account.id, &event).expect("Failed to insert event");

        // Enqueue Webhook
        let payload = r#"{"amount": 1000}"#;
        let target_url = "https://api.example.com/webhook";
        let webhook_id = enqueue_webhook(&conn, Some(event_id), &event_type.to_key_string(), payload, target_url)
            .expect("Failed to enqueue");

        // Verification Cycle: Immediate Fetch
        let items = fetch_due_webhooks(&conn, 10).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, webhook_id);
        assert_eq!(items[0].event_id, Some(event_id));

        // Cycle: Mark Failed with Future Retry (Should not be fetched)
        let future_retry = Utc::now().naive_utc() + Duration::hours(1);
        update_webhook_status(
            &conn,
            webhook_id,
            WebhookStatus::Failed,
            1,
            future_retry,
            Some("Transient Error"),
        )
        .unwrap();

        let items = fetch_due_webhooks(&conn, 10).unwrap();
        assert!(items.is_empty(), "Should not fetch items with future retry date");

        // Cycle: Mark Failed with Past Retry (Should be fetched)
        let past_retry = Utc::now().naive_utc() - Duration::minutes(1);
        update_webhook_status(
            &conn,
            webhook_id,
            WebhookStatus::Failed,
            1,
            past_retry,
            Some("Transient Error"),
        )
        .unwrap();

        let items = fetch_due_webhooks(&conn, 10).unwrap();
        assert_eq!(items.len(), 1, "Should fetch items when retry date has passed");

        // Cycle: Success (Should be ignored)
        update_webhook_status(
            &conn,
            webhook_id,
            WebhookStatus::Success,
            2,
            Utc::now().naive_utc(),
            None,
        )
        .unwrap();

        let items = fetch_due_webhooks(&conn, 10).unwrap();
        assert!(items.is_empty(), "Successful webhooks should not be fetched");
    }
}
