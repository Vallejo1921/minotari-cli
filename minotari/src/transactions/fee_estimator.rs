use anyhow::{Result, anyhow};
use log::debug;
use tari_script::TariScript;
use tari_transaction_components::helpers::borsh::SerializedSize;
use tari_transaction_components::{
    fee::Fee,
    tari_amount::MicroMinotari,
    transaction_components::{OutputFeatures, covenants::Covenant},
    weight::TransactionWeight,
};

use crate::http::WalletHttpClient;
use crate::{
    db::{self, AccountRow, SqlitePool},
    transactions::input_selector::InputSelector,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeePriority {
    Slow,
    Medium,
    Fast,
}

#[derive(Debug, Clone)]
pub struct FeeEstimateResult {
    pub priority: FeePriority,
    pub fee_per_gram: MicroMinotari,
    pub estimated_fee: MicroMinotari,
    pub total_amount_required: MicroMinotari,
    pub input_count: usize,
}

pub struct FeeEstimator {
    db_pool: SqlitePool,
    base_url: String,
    fee_calc: Fee,
}

impl FeeEstimator {
    pub fn new(db_pool: SqlitePool, base_url: String) -> Self {
        Self {
            db_pool,
            base_url,
            fee_calc: Fee::new(TransactionWeight::latest()),
        }
    }

    pub async fn estimate_fees(
        &self,
        account_name: &str,
        amount: MicroMinotari,
        num_outputs: usize,
        confirmation_window: u64,
        estimated_output_size: Option<usize>,
    ) -> Result<Vec<FeeEstimateResult>> {
        let conn = self.db_pool.get()?;

        let account: AccountRow = db::get_account_by_name(&conn, account_name)?
            .ok_or_else(|| anyhow!("Account with name '{}' not found", account_name))?;

        let client = WalletHttpClient::new(self.base_url.parse()?)?;
        let (fast_fee, medium_fee, slow_fee) = match client.get_mempool_fee_per_gram_stats(3).await {
            Ok(stats) if !stats.is_empty() => {
                // Fast: Average of the 1st block (next block)
                let fast = stats.first().unwrap().avg_fee_per_gram;
                // Medium: Average of the 2nd block (if exists)
                let medium = stats.get(1).unwrap_or(&stats[0]).avg_fee_per_gram;
                // Slow: Minimum of the deepest block we got
                let slow = stats.last().unwrap().min_fee_per_gram;

                (fast, medium, slow)
            },
            _ => (MicroMinotari::from(10), MicroMinotari::from(5), MicroMinotari::from(1)),
        };

        let input_selector = InputSelector::new(account.id, confirmation_window);

        let selection =
            input_selector.fetch_unspent_outputs(&conn, amount, num_outputs, fast_fee, estimated_output_size)?;

        let input_count = selection.utxos.len();
        let total_outputs = if selection.requires_change_output {
            num_outputs + 1
        } else {
            num_outputs
        };

        let output_size = match estimated_output_size {
            Some(sz) => sz,
            None => get_default_features_and_scripts_size()?,
        };

        let results = [
            (FeePriority::Slow, slow_fee),
            (FeePriority::Medium, medium_fee),
            (FeePriority::Fast, fast_fee),
        ]
        .into_iter()
        .map(|(priority, fee_per_gram)| {
            self.calculate_single_estimate(priority, fee_per_gram, amount, input_count, total_outputs, output_size)
        })
        .collect();

        debug!(
            account = account_name,
            inputs = input_count;
            "Calculated fee estimates"
        );

        Ok(results)
    }

    fn calculate_single_estimate(
        &self,
        priority: FeePriority,
        fee_per_gram: MicroMinotari,
        amount: MicroMinotari,
        input_count: usize,
        output_count: usize,
        output_size: usize,
    ) -> FeeEstimateResult {
        let fee = self
            .fee_calc
            .calculate(fee_per_gram, 1, input_count, output_count, output_size * output_count);

        FeeEstimateResult {
            priority,
            fee_per_gram,
            estimated_fee: fee,
            total_amount_required: amount + fee,
            input_count,
        }
    }
}

pub fn get_default_features_and_scripts_size() -> Result<usize> {
    let fee_calc = Fee::new(TransactionWeight::latest());

    let get_size = |res: Result<usize, _>| res.map_err(|e| anyhow!("Serialization error: {}", e));
    let output_features_size = get_size(OutputFeatures::default().get_serialized_size())?;
    let tari_script_size = get_size(TariScript::default().get_serialized_size())?;
    let covenant_size = get_size(Covenant::default().get_serialized_size())?;

    Ok(fee_calc
        .weighting()
        .round_up_features_and_scripts_size(output_features_size + tari_script_size + covenant_size))
}
