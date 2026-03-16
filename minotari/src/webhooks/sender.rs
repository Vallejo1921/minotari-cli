use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::Sha256;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const HTTP_TIMEOUT: u64 = 20;

type HmacSha256 = Hmac<Sha256>;

/// Result of a delivery attempt
#[derive(Debug)]
pub enum DeliveryResult {
    Success,
    /// 5xx errors or network issues (should retry)
    RetryableFailure(String),
    /// 4xx errors or signing issues (should stop)
    PermanentFailure(String),
}

pub struct WebhookSender {
    client: Client,
}

impl Default for WebhookSender {
    fn default() -> Self {
        Self::new()
    }
}

impl WebhookSender {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(HTTP_TIMEOUT))
            .user_agent("minotari-wallet/1.0")
            .build()
            .expect("Failed to build HTTP client");

        Self { client }
    }

    /// Sends a signed webhook payload to the target URL.
    pub async fn send(&self, url: &str, secret: &str, payload: &str) -> DeliveryResult {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        // Generate Signature (HMAC-SHA256)
        // Format: t=TIMESTAMP,v1=SIGNATURE
        let signature = match self.sign_payload(secret, now, payload) {
            Ok(s) => s,
            Err(e) => return DeliveryResult::PermanentFailure(format!("Signing error: {}", e)),
        };

        let request = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header("X-Minotari-Signature", signature)
            .header("X-Minotari-Timestamp", now.to_string())
            .body(payload.to_string());

        match request.send().await {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    DeliveryResult::Success
                } else if status.is_client_error() {
                    // 400-499: The receiver rejected us
                    let body = response
                        .text()
                        .await
                        .unwrap_or_default()
                        .chars()
                        .take(200)
                        .collect::<String>();
                    DeliveryResult::PermanentFailure(format!("Client Error {}: {}", status, body))
                } else {
                    // 500-599: Server error
                    DeliveryResult::RetryableFailure(format!("Server Error {}", status))
                }
            },
            Err(e) => {
                // Network timeout, DNS error, connection refused
                DeliveryResult::RetryableFailure(format!("Network Error: {}", e))
            },
        }
    }

    /// Generates the HMAC-SHA256 signature.
    fn sign_payload(&self, secret: &str, timestamp: u64, payload: &str) -> Result<String, String> {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| "Invalid key length".to_string())?;

        let to_sign = format!("{}.{}", timestamp, payload);
        mac.update(to_sign.as_bytes());

        let result = mac.finalize();
        let code_bytes = result.into_bytes();
        let sig_hex = hex::encode(code_bytes);

        Ok(format!("t={},v1={}", timestamp, sig_hex))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    type HmacSha256 = Hmac<Sha256>;

    #[tokio::test]
    async fn test_send_webhook_success_with_valid_signature() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/webhook"))
            .and(header("Content-Type", "application/json"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let sender = WebhookSender::new();
        let secret = "my_super_secret_key";
        let payload = r#"{"event":"test"}"#;
        let target_url = format!("{}/webhook", mock_server.uri());

        let result = sender.send(&target_url, secret, payload).await;

        assert!(matches!(result, DeliveryResult::Success));

        let requests = mock_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];

        let sig_header = request.headers.get("X-Minotari-Signature").unwrap().to_str().unwrap();
        let ts_header = request.headers.get("X-Minotari-Timestamp").unwrap().to_str().unwrap();

        // Verify Signature format: t=TIMESTAMP,v1=SIGNATURE
        let parts: Vec<&str> = sig_header.split(',').collect();
        assert_eq!(parts.len(), 2);
        assert!(parts[0].starts_with("t="));
        assert!(parts[1].starts_with("v1="));

        let timestamp = &parts[0][2..];
        let signature_hex = &parts[1][3..];

        // Ensure timestamp in header matches the one in the signature
        assert_eq!(timestamp, ts_header);

        // Cryptographic Verification
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        let to_sign = format!("{}.{}", timestamp, payload);
        mac.update(to_sign.as_bytes());
        let expected_sig = hex::encode(mac.finalize().into_bytes());

        assert_eq!(signature_hex, expected_sig, "HMAC signature mismatch!");
    }

    #[tokio::test]
    async fn test_send_webhook_retryable_failure() {
        let mock_server = MockServer::start().await;

        // Return 500 Internal Server Error
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let sender = WebhookSender::new();
        let result = sender.send(&mock_server.uri(), "secret", "{}").await;

        // Should be Retryable
        assert!(matches!(result, DeliveryResult::RetryableFailure(_)));
    }

    #[tokio::test]
    async fn test_send_webhook_permanent_failure() {
        let mock_server = MockServer::start().await;

        // Return 400 Bad Request
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&mock_server)
            .await;

        let sender = WebhookSender::new();
        let result = sender.send(&mock_server.uri(), "secret", "{}").await;

        // Should be Permanent
        assert!(matches!(result, DeliveryResult::PermanentFailure(_)));
    }
}
