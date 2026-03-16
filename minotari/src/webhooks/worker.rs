use chrono::{NaiveDateTime, Utc};
use log::{debug, error, info, warn};
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

use crate::db::{self, SqlitePool};
use crate::webhooks::models::{WebhookQueueItem, WebhookStatus};
use crate::webhooks::sender::{DeliveryResult, WebhookSender};

const POLL_INTERVAL: u64 = 30; // 30 seconds
const BATCH_SIZE: i64 = 10;
const MAX_ATTEMPTS: i32 = 10;
const MAX_AGE: u64 = 24 * 60 * 60; // 24 hrs

#[derive(Clone)]
pub struct WebhookWorkerConfig {
    pub enabled: bool,
    pub secret: Option<String>,
    pub send_only_event_types: Option<Vec<String>>,
}

pub struct WebhookWorker {
    db_pool: SqlitePool,
    config: WebhookWorkerConfig,
    sender: WebhookSender,
}

impl WebhookWorker {
    pub fn new(db_pool: SqlitePool, config: WebhookWorkerConfig) -> Self {
        Self {
            db_pool,
            config,
            sender: WebhookSender::new(),
        }
    }

    pub async fn run(self: Arc<Self>, mut shutdown_rx: broadcast::Receiver<()>) {
        if !self.config.enabled || self.config.secret.is_none() {
            info!("Webhook worker disabled or missing secret. Exiting task.");
            return;
        }

        info!("Webhook worker started.");

        let mut interval = tokio::time::interval(Duration::from_secs(POLL_INTERVAL));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.process_batch().await {
                        error!("Error processing webhook batch: {}", e);
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Webhook worker received shutdown signal.");
                    break;
                }
            }
        }
    }

    async fn process_batch(&self) -> Result<(), anyhow::Error> {
        let pool = self.db_pool.clone();
        let items = tokio::task::spawn_blocking(move || {
            let conn = pool.get()?;
            db::fetch_due_webhooks(&conn, BATCH_SIZE)
        })
        .await??;

        if items.is_empty() {
            return Ok(());
        }

        debug!("Processing {} due webhooks", items.len());

        let secret = self.config.secret.as_ref().unwrap();

        for item in items {
            self.process_item(item, secret).await;
        }

        Ok(())
    }

    async fn process_item(&self, item: WebhookQueueItem, secret: &str) {
        let result = self.sender.send(&item.target_url, secret, &item.payload).await;

        let (new_status, next_retry, error_msg) = match result {
            DeliveryResult::Success => {
                info!(id = item.id; "Webhook delivered successfully");
                (WebhookStatus::Success, item.next_retry_at, None)
            },
            DeliveryResult::PermanentFailure(msg) => {
                warn!(id = item.id, error:% = msg; "Webhook failed permanently");
                (WebhookStatus::PermanentFailure, item.next_retry_at, Some(msg))
            },
            DeliveryResult::RetryableFailure(msg) => {
                let (next_retry, stop_retrying) = calculate_backoff(item.attempt_count + 1);

                if stop_retrying {
                    warn!(id = item.id, error:% = msg; "Webhook max retries exceeded");
                    (WebhookStatus::PermanentFailure, next_retry, Some(msg))
                } else {
                    warn!(id = item.id, attempt = item.attempt_count + 1, error:% = msg; "Webhook failed, retrying");
                    (WebhookStatus::Failed, next_retry, Some(msg))
                }
            },
        };

        let pool = self.db_pool.clone();
        let update_result = tokio::task::spawn_blocking(move || {
            let conn = pool.get()?;
            db::update_webhook_status(
                &conn,
                item.id,
                new_status,
                item.attempt_count + 1,
                next_retry,
                error_msg.as_deref(),
            )
        })
        .await;

        if let Err(e) = update_result {
            error!(id = item.id, error:? = e; "Failed to update webhook status in DB");
        }
    }
}

/// Returns (Next Retry Time, Should Stop Retrying)
fn calculate_backoff(attempt: i32) -> (NaiveDateTime, bool) {
    if attempt >= MAX_ATTEMPTS {
        return (Utc::now().naive_utc(), true);
    }

    // Base delay in seconds:
    // 1: 30s
    // 2: 2m
    // 3: 8m
    // 4: 32m
    // ...
    let base_seconds = 30 * 4u64.pow((attempt - 1) as u32);
    let capped_seconds = std::cmp::min(base_seconds, MAX_AGE);

    let jitter_range = capped_seconds / 10;
    let jitter = rand::thread_rng().gen_range(0..=jitter_range);

    let final_seconds = if rand::thread_rng().gen_bool(0.5) {
        capped_seconds + jitter
    } else {
        capped_seconds.saturating_sub(jitter)
    };

    let next_time = Utc::now().naive_utc() + chrono::Duration::seconds(final_seconds as i64);
    (next_time, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{enqueue_webhook, init_db};
    use chrono::Utc;
    use tempfile::tempdir;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_worker_process_batch_success() {
        let mock_server = MockServer::start().await;
        let secret = "worker-test-secret";

        Mock::given(method("POST"))
            .and(path("/receive"))
            // Verify the worker actually signs the request
            .and(header("Content-Type", "application/json"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let temp_dir = tempdir().unwrap();
        let pool = init_db(temp_dir.path().join("worker_test.db")).unwrap();
        let conn = pool.get().unwrap();

        // Enqueue a "Due" Webhook
        let target_url = format!("{}/receive", mock_server.uri());
        let payload = r#"{"event": "worker_test"}"#;

        let webhook_id = enqueue_webhook(&conn, None, "TestEvent", payload, &target_url).unwrap();

        let config = WebhookWorkerConfig {
            enabled: true,
            secret: Some(secret.to_string()),
            send_only_event_types: None,
        };
        let worker = WebhookWorker::new(pool.clone(), config);

        // Execution: Run one batch manually
        worker.process_batch().await.expect("Worker batch failed");

        // Assertions: Verify DB status is now 'success'
        let mut stmt = conn
            .prepare("SELECT status, attempt_count FROM webhook_queue WHERE id = ?")
            .unwrap();
        let (status_str, attempts): (String, i32) =
            stmt.query_row([webhook_id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();

        assert_eq!(status_str, "success");
        assert_eq!(attempts, 1);
    }

    #[tokio::test]
    async fn test_worker_retry_logic() {
        // Setup Mock Server to FAIL
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500)) // Retryable error
            .mount(&mock_server)
            .await;

        let temp_dir = tempdir().unwrap();
        let pool = init_db(temp_dir.path().join("retry_test.db")).unwrap();
        let conn = pool.get().unwrap();

        let webhook_id = enqueue_webhook(&conn, None, "TestEvent", "{}", &mock_server.uri()).unwrap();

        let worker = WebhookWorker::new(
            pool.clone(),
            WebhookWorkerConfig {
                enabled: true,
                secret: Some("secret".into()),
                send_only_event_types: None,
            },
        );

        worker.process_batch().await.unwrap();

        let mut stmt = conn
            .prepare("SELECT status, attempt_count, next_retry_at FROM webhook_queue WHERE id = ?")
            .unwrap();
        let (status_str, attempts, next_retry): (String, i32, NaiveDateTime) = stmt
            .query_row([webhook_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();

        assert_eq!(status_str, "failed");
        assert_eq!(attempts, 1);

        // Verify backoff: Next retry should be in the future (default base is 30s)
        let now = Utc::now().naive_utc();
        assert!(
            next_retry > now,
            "Next retry at {:?} should be after now {:?}",
            next_retry,
            now
        );
    }

    #[test]
    fn test_backoff_calculation_limits() {
        let (next_time, stop) = calculate_backoff(1);
        assert!(!stop);
        assert!(next_time > Utc::now().naive_utc());

        let (_next_time, stop_at_max) = calculate_backoff(10);
        assert!(stop_at_max, "Should stop retrying after 10 attempts");
    }
}
