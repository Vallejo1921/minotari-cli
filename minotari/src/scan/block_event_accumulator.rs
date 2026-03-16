use crate::BlockProcessedEvent;
use crate::models::BalanceChange;
use crate::scan::{BalanceChangeSummary, DetectedOutput, SpentInput};

/// Accumulates events and data for a single block during processing.
///
/// This struct collects all outputs, inputs, confirmations, and balance changes
/// detected while processing a block, then builds them into a single
/// [`BlockProcessedEvent`] for emission.
pub struct BlockEventAccumulator {
    /// Account ID for the block being processed.
    pub account_id: i64,
    /// Block height.
    pub height: u64,
    /// Block hash bytes.
    pub block_hash: Vec<u8>,
    debit_balance_changes: Vec<(BalanceChange, SpentInput)>,
    credit_balance_changes: Vec<(BalanceChange, DetectedOutput)>,
}

impl BlockEventAccumulator {
    /// Creates a new accumulator for the given block.
    pub fn new(account_id: i64, height: u64, block_hash: Vec<u8>) -> Self {
        Self {
            account_id,
            height,
            block_hash,
            debit_balance_changes: Vec::new(),
            credit_balance_changes: Vec::new(),
        }
    }

    pub fn total_changes(&self) -> usize {
        self.debit_balance_changes.len() + self.credit_balance_changes.len()
    }

    pub fn debit_balance_changes(&self) -> &[(BalanceChange, SpentInput)] {
        &self.debit_balance_changes
    }

    pub fn credit_balance_changes(&self) -> &[(BalanceChange, DetectedOutput)] {
        &self.credit_balance_changes
    }

    /// Adds a debit balance change to the accumulator.
    pub fn add_debit_change(&mut self, change: BalanceChange, input: SpentInput) {
        self.debit_balance_changes.push((change.clone(), input));
    }

    /// Adds a credit balance change to the accumulator.
    pub fn add_credit_change(&mut self, change: BalanceChange, output: DetectedOutput) {
        self.credit_balance_changes.push((change.clone(), output));
    }

    pub fn is_empty(&self) -> bool {
        self.debit_balance_changes.is_empty() && self.credit_balance_changes.is_empty()
    }

    /// Consumes the accumulator and builds the final [`BlockProcessedEvent`].
    pub fn into_event(self) -> BlockProcessedEvent {
        let mut outputs_detected = Vec::new();
        let mut inputs_spent = Vec::new();
        let mut balance_changes = Vec::new();
        for credit in self.credit_balance_changes {
            outputs_detected.push(credit.1);
            balance_changes.push(BalanceChangeSummary {
                credit: credit.0.balance_credit,
                debit: credit.0.balance_debit,
                description: credit.0.description.clone(),
            });
        }

        for debit in self.debit_balance_changes {
            inputs_spent.push(debit.1);
            balance_changes.push(BalanceChangeSummary {
                credit: debit.0.balance_credit,
                debit: debit.0.balance_debit,
                description: debit.0.description.clone(),
            });
        }

        BlockProcessedEvent {
            account_id: self.account_id,
            height: self.height,
            block_hash: self.block_hash,
            outputs_detected,
            inputs_spent,
            balance_changes,
        }
    }
}
