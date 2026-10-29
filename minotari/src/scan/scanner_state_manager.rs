use crate::scan::ScanRetryConfig;
use crate::{ScanError, scan::coordinator::AccountSyncTarget};
use minotari_scanning::{HttpBlockchainScanner, ScanConfig};
use tari_transaction_components::key_manager::KeyManager;

pub struct ScannerStateManager {
    scanner: Option<HttpBlockchainScanner<KeyManager>>,
    active_account_ids: Vec<i64>,
    scan_config: ScanConfig,
}

impl ScannerStateManager {
    pub fn new() -> Self {
        Self {
            scanner: None,
            active_account_ids: Vec::new(),
            scan_config: ScanConfig::default(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn get_scanner_and_config(
        &mut self,
        new_active_account_ids: &[i64],
        new_start_height: u64,
        new_end_height: Option<u64>,
        batch_size: u64,
        all_targets: &[AccountSyncTarget],
        base_url: &str,
        processing_threads: usize,
        retry_config: &ScanRetryConfig,
    ) -> Result<(&mut HttpBlockchainScanner<KeyManager>, ScanConfig), ScanError> {
        // Only recreate scanner if accounts change
        if self.scanner.is_none() || self.active_account_ids != new_active_account_ids {
            let active_key_managers: Vec<KeyManager> = new_active_account_ids
                .iter()
                .map(|account_id| {
                    all_targets
                        .iter()
                        .find(|target| target.account.id == *account_id)
                        .map(|target| target.key_manager.clone())
                        .ok_or_else(|| ScanError::Fatal(anyhow::anyhow!("Unknown active account id: {}", account_id)))
                })
                .collect::<Result<Vec<_>, _>>()?;

            let new_scanner = HttpBlockchainScanner::with_timeout(
                base_url.to_string(),
                retry_config.timeout,
                active_key_managers,
                processing_threads,
                retry_config.max_error_retries,
                retry_config.error_backoff_base_secs,
            )
            .await
            .map_err(|e| ScanError::Intermittent(e.to_string()))?;

            self.scanner = Some(new_scanner);
            self.active_account_ids = new_active_account_ids.to_vec();
        }

        // Always update the config to the last known height.
        // This ensures the scanner always starts at a valid, existing block.
        self.scan_config = ScanConfig::default()
            .with_start_height(new_start_height)
            .with_batch_size(batch_size)
            .with_exclude_spent(false)
            .with_exclude_inputs(false);
        self.scan_config.end_height = new_end_height;

        let scanner = self
            .scanner
            .as_mut()
            .ok_or_else(|| ScanError::Fatal(anyhow::anyhow!("Scanner was not initialized")))?;

        Ok((scanner, self.scan_config.clone()))
    }
}
