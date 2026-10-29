use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookTriggerConfig {
    pub url: String,
    pub send_only_event_types: Option<Vec<String>>,
}

/// Represents the status of a webhook delivery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebhookStatus {
    /// Waiting to be processed or currently being processed
    Pending,
    /// Successfully delivered (2xx response)
    Success,
    /// Transient failure (network, 5xx), will be retried
    Failed,
    /// Permanent failure (4xx, max retries exceeded), will not be retried
    PermanentFailure,
}

impl fmt::Display for WebhookStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WebhookStatus::Pending => write!(f, "pending"),
            WebhookStatus::Success => write!(f, "success"),
            WebhookStatus::Failed => write!(f, "failed"),
            WebhookStatus::PermanentFailure => write!(f, "permanent_failure"),
        }
    }
}

impl FromStr for WebhookStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(WebhookStatus::Pending),
            "success" => Ok(WebhookStatus::Success),
            "failed" => Ok(WebhookStatus::Failed),
            "permanent_failure" => Ok(WebhookStatus::PermanentFailure),
            _ => Err(format!("Invalid webhook status: {}", s)),
        }
    }
}

/// Represents an item in the webhook queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookQueueItem {
    pub id: i64,
    pub event_id: Option<i64>,
    pub event_type: String,
    pub payload: String,
    pub target_url: String,
    pub status: WebhookStatus,
    pub attempt_count: i32,
    pub next_retry_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
    pub last_error: Option<String>,
}
