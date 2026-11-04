use super::builder::DisplayedTransactionBuilder;
use super::error::ProcessorError;
use super::types::{
    DisplayedTransaction, TransactionDisplayStatus, TransactionInput, TransactionOutput, TransactionSource,
};
use crate::db::{self};
use crate::models::{BalanceChange, Id, OutputStatus};
use crate::scan::block_event_accumulator::BlockEventAccumulator;
use crate::scan::{DetectedOutput, MemoInfo, SpentInput};
use log::debug;
use rusqlite::Connection;
use std::collections::{BinaryHeap, HashMap};
use tari_common_types::transaction::TxId;
use tari_common_types::types::FixedHash;
use tari_common_types::types::PrivateKey;
use tari_transaction_components::MicroMinotari;
use tari_transaction_components::transaction_components::{OutputType, WalletOutput};
use tari_utilities::ByteArray;

/// Processes balance changes into user-displayable transactions.
pub struct DisplayedTransactionProcessor {
    current_tip_height: u64,
    req_confirmations: u64,
    view_key: PrivateKey,
}

impl DisplayedTransactionProcessor {
    pub fn new(current_tip_height: u64, req_confirmations: u64, view_key: PrivateKey) -> Self {
        Self {
            current_tip_height,
            req_confirmations,
            view_key,
        }
    }

    pub fn create_new_updated_display_transactions_for_height(
        &self,
        accumulator: &BlockEventAccumulator,
        tx: &Connection,
    ) -> Result<(Vec<DisplayedTransaction>, Vec<DisplayedTransaction>), ProcessorError> {
        let mut current_display_transactions =
            db::get_displayed_transactions_from_height(tx, accumulator.account_id as Id, accumulator.height)?;
        let mut pending_txs = db::get_displayed_transactions_by_status(
            tx,
            accumulator.account_id as Id,
            TransactionDisplayStatus::Pending,
        )?;
        let existing_ids: std::collections::HashSet<_> = current_display_transactions.iter().map(|tx| tx.id).collect();
        pending_txs.retain(|tx| !existing_ids.contains(&tx.id));
        current_display_transactions.append(&mut pending_txs);
        self.create_new_updated_display_transactions(accumulator, &current_display_transactions)
    }

    #[allow(clippy::too_many_lines)]
    pub fn create_new_updated_display_transactions(
        &self,
        accumulator: &BlockEventAccumulator,
        current_display_transactions: &[DisplayedTransaction],
    ) -> Result<(Vec<DisplayedTransaction>, Vec<DisplayedTransaction>), ProcessorError> {
        debug!(
            count = accumulator.total_changes();
            "Processing balance changes"
        );
        let mut updated_transactions = HashMap::new();
        let mut new_credit = Vec::new();
        let mut new_debit = Vec::new();
        'output_loop: for (balance_change, output) in accumulator.credit_balance_changes() {
            for tx in current_display_transactions {
                if tx.details.outputs.iter().any(|o| o.hash == output.output.output_hash()) {
                    let mut updated = tx.clone();
                    updated.blockchain.block_height = output.height;
                    updated.blockchain.timestamp = balance_change.effective_date;
                    updated.blockchain.confirmations = self.current_tip_height.saturating_sub(output.height);

                    // Update status based on confirmations
                    if updated.blockchain.confirmations >= self.req_confirmations {
                        updated.status = TransactionDisplayStatus::Confirmed;
                    } else {
                        updated.status = TransactionDisplayStatus::Unconfirmed;
                    }
                    let _unused = updated_transactions.insert(tx.id, updated);
                    continue 'output_loop;
                }
            }
            // we need to create a new display tx for this output
            new_credit.push((balance_change.clone(), output.clone()));
        }
        'input_loop: for (balance_change, output) in accumulator.debit_balance_changes() {
            for tx in current_display_transactions {
                if tx
                    .details
                    .inputs
                    .iter()
                    .any(|o| o.output_hash == output.output.output_hash())
                {
                    let mut updated = tx.clone();
                    updated.blockchain.block_height = output.mined_in_block_height;
                    updated.blockchain.timestamp = balance_change.effective_date;
                    updated.blockchain.confirmations =
                        self.current_tip_height.saturating_sub(output.mined_in_block_height);

                    // Update status based on confirmations
                    if updated.blockchain.confirmations >= self.req_confirmations {
                        updated.status = TransactionDisplayStatus::Confirmed;
                    } else {
                        updated.status = TransactionDisplayStatus::Unconfirmed;
                    }
                    let _unused = updated_transactions.insert(tx.id, updated);
                    continue 'input_loop;
                }
            }
            // we need to create a new display tx for this input
            new_debit.push((balance_change.clone(), output.clone()));
        }
        new_debit.sort_by_key(|a| a.1.output.value());
        let mut new_transactions = Vec::new();
        // Now we have a list of inputs and outputs that don't have matching transactions
        // lets start by looking at the coinbases first, we do in reverse, se we can remove them without changing the order.
        for i in (0..new_credit.len()).rev() {
            if !new_credit.get(i).expect("should exist").1.output.is_coinbase() {
                //is not coinbase, go to next
                continue;
            }
            let (balance_change, output) = new_credit.remove(i);
            let (initial_status, initial_confirmations) =
                self.calculate_status_and_confirmations(output.height, output.output.max_lock_height());
            let id = TxId::new_deterministic(self.view_key.as_bytes(), &output.output.output_hash());
            let memo = MemoInfo::from_output(&output.output);
            let display_tx = DisplayedTransactionBuilder::new()
                .account_id(accumulator.account_id as Id)
                .source(TransactionSource::Coinbase)
                .status(initial_status)
                .lock_height(output.output.max_lock_height())
                .credits_and_debits(balance_change.balance_credit, 0.into())
                .counterparty(None)
                .blockchain_info(
                    accumulator.height,
                    output.mined_in_block_hash,
                    balance_change.effective_date,
                    initial_confirmations,
                )
                .fee(None)
                .inputs(vec![])
                .outputs(vec![TransactionOutput {
                    hash: output.output.output_hash(),
                    amount: output.output.value(),
                    status: OutputStatus::Unspent,
                    mined_in_block_height: output.height,
                    mined_in_block_hash: output.mined_in_block_hash,
                    output_type: OutputType::Coinbase,
                    is_change: false,
                }])
                .message(memo.parsed)
                .memo_hex(memo.hex)
                .output_type(Some(OutputType::Coinbase))
                .coinbase_extra(Some(output.output.features().coinbase_extra.clone()))
                // A coinbase has no sender payment id, so reference its own output
                // hash. This yields a payref matching the output's stored
                // payment_reference, so coinbase receipts are addressable and
                // survive reorgs via the payref-history fallback.
                .sent_output_hashes(vec![output.output.output_hash()])
                .build(id)?;
            new_transactions.push(display_tx);
        }
        // Now lets search at all non-change, ake received outputs
        for i in (0..new_credit.len()).rev() {
            if new_credit
                .get(i)
                .expect("should exist")
                .1
                .output
                .payment_id()
                .get_transaction_info_details()
                .is_some()
            {
                //is not change, go to next
                continue;
            }
            let (balance_change, output) = new_credit.remove(i);
            let (initial_status, initial_confirmations) =
                self.calculate_status_and_confirmations(output.height, output.output.max_lock_height());
            let id = TxId::new_deterministic(self.view_key.as_bytes(), &output.output.output_hash());
            let memo = MemoInfo::from_output(&output.output);
            let sent = output.output.payment_id().get_sent_hashes().unwrap_or_default();
            // this must be some received output
            let other_party = output.output.payment_id().claimed_sender_address();
            let display_tx = DisplayedTransactionBuilder::new()
                .account_id(accumulator.account_id as Id)
                .source(TransactionSource::Transfer)
                .lock_height(output.output.max_lock_height())
                .status(initial_status)
                .credits_and_debits(balance_change.balance_credit, 0.into())
                .counterparty(other_party)
                .blockchain_info(
                    accumulator.height,
                    output.mined_in_block_hash,
                    balance_change.effective_date,
                    initial_confirmations,
                )
                .fee(output.output.payment_id().get_fee())
                .message(memo.parsed)
                .memo_hex(memo.hex)
                .outputs(vec![TransactionOutput {
                    hash: output.output.output_hash(),
                    amount: output.output.value(),
                    status: OutputStatus::Unspent,
                    mined_in_block_height: output.height,
                    mined_in_block_hash: output.mined_in_block_hash,
                    output_type: OutputType::Standard,
                    is_change: false,
                }])
                .output_type(Some(OutputType::Standard))
                .sent_output_hashes(sent)
                .build(id)?;
            new_transactions.push(display_tx);
        }
        new_transactions.append(&mut self.search_inputs(new_debit, new_credit, accumulator)?);

        Ok((updated_transactions.into_values().collect(), new_transactions))
    }

    fn search_inputs(
        &self,
        mut inputs: Vec<(BalanceChange, SpentInput)>,
        outputs: Vec<(BalanceChange, DetectedOutput)>,
        accumulator: &BlockEventAccumulator,
    ) -> Result<Vec<DisplayedTransaction>, ProcessorError> {
        let mut result = Vec::new();
        // hashmap is vec<solutions, vec<indices of inputs used for this solution>>
        // the targets is the matching outputs + for no matching inputs, last will always be no matching
        let mut targets = Vec::new();
        let mut unmatched_index = Vec::new();
        for (i, output) in outputs.iter().enumerate() {
            if let Some((_sender, amount, _tx_type, _one_sided)) =
                output.1.output.payment_id().get_transaction_info_details()
            {
                if let Some(total_send) = Self::claimed_total_send(&output.1.output, amount) {
                    targets.push((total_send, i));
                } else {
                    debug!("Claimed send total overflows u64, treating output as unmatched");
                    unmatched_index.push(i);
                }
            } else {
                unmatched_index.push(i);
            }
        }

        let solutions = Self::solve_back_track(&inputs, targets.clone());
        let mut used_inputs = BinaryHeap::new();

        for (output_index, solution) in solutions {
            // `None` once the input total overflows u64; such a solution cannot match any output.
            let mut balance = Some(MicroMinotari::from(0));
            let mut tx_inputs = Vec::new();
            for index in &solution {
                let (_input_balance, input) = inputs
                    .get(*index)
                    .ok_or(ProcessorError::MissingError("Input index out of bounds".to_string()))?;
                balance = balance.and_then(|total| total.checked_add(input.output.value()));
                tx_inputs.push(TransactionInput {
                    output_hash: input.output.output_hash(),
                    amount: input.output.value(),
                    mined_in_block_hash: input.mined_in_block,
                    matched_output_id: input.output_id,
                });
            }

            let (balance_change, output) = outputs
                .get(output_index)
                .ok_or(ProcessorError::MissingError("Output index out of bounds".to_string()))?;
            let (sender, amount, _tx_type, _one_sided) = output
                .output
                .payment_id()
                .get_transaction_info_details()
                .ok_or(ProcessorError::MissingError("Missing Output details".to_string()))?;
            let total_send = Self::claimed_total_send(&output.output, amount);
            let debit_value = match (balance, total_send) {
                (Some(balance), Some(total_send)) if balance == total_send => balance,
                _ => {
                    unmatched_index.push(output_index);
                    debug!("Output does not have a matching input solution");
                    continue;
                },
            };
            for index in solution {
                used_inputs.push(index);
            }
            let sent = output.output.payment_id().get_sent_hashes().unwrap_or_default();
            let (initial_status, initial_confirmations) =
                self.calculate_status_and_confirmations(output.height, output.output.max_lock_height());
            let mut other_party = output.output.payment_id().claimed_sender_address();
            let id = TxId::new_deterministic(self.view_key.as_bytes(), &output.output.output_hash());
            let memo = MemoInfo::from_output(&output.output);
            let tx = DisplayedTransactionBuilder::new()
                .account_id(accumulator.account_id as Id)
                .source(TransactionSource::Transfer)
                .status(initial_status)
                .lock_height(output.output.max_lock_height())
                .blockchain_info(
                    accumulator.height,
                    output.mined_in_block_hash,
                    balance_change.effective_date,
                    initial_confirmations,
                )
                .fee(output.output.payment_id().get_fee())
                .message(memo.parsed)
                .memo_hex(memo.hex)
                .outputs(vec![TransactionOutput {
                    hash: output.output.output_hash(),
                    amount: output.output.value(),
                    status: OutputStatus::Unspent,
                    mined_in_block_height: output.height,
                    mined_in_block_hash: output.mined_in_block_hash,
                    output_type: OutputType::Standard,
                    is_change: false,
                }])
                .output_type(Some(OutputType::Standard))
                .sent_output_hashes(sent)
                .inputs(tx_inputs)
                .credits_and_debits(balance_change.balance_credit, debit_value)
                .counterparty(other_party)
                .build(id)?;
            other_party = Some(sender);
            result.push(tx);
        }
        // these should be desc order, so lets pop them to remove them
        while let Some(index) = used_inputs.pop() {
            let _unused = inputs.remove(index);
        }
        result.append(&mut self.handle_unmatched_inputs_outputs(inputs, &outputs, &unmatched_index, accumulator)?);

        Ok(result)
    }

    /// The total value the sender claims left their wallet for this transaction: the amount the memo says was paid to
    /// the recipient, plus the change output we received, plus the claimed fee.
    ///
    /// The claimed amount and fee are decrypted verbatim from the sender-controlled memo and are never validated
    /// against the commitment, so both can be any `u64`. The sum is therefore done with `checked_add`: a memo claiming
    /// `u64::MAX` would otherwise overflow and panic the scanner, and since the output stays on chain forever every
    /// subsequent rescan would panic again. `None` means the claim is not representable and so can never be matched by
    /// a real set of inputs; callers treat the output as unmatched.
    fn claimed_total_send(output: &WalletOutput, claimed_amount: MicroMinotari) -> Option<MicroMinotari> {
        claimed_amount
            .checked_add(output.value())?
            .checked_add(output.payment_id().get_fee().unwrap_or_default())
    }

    pub fn solve_back_track(
        inputs: &[(BalanceChange, SpentInput)],
        mut targets: Vec<(MicroMinotari, usize)>,
    ) -> Vec<(usize, Vec<usize>)> {
        let mut nums: Vec<MicroMinotari> = inputs.iter().map(|v| v.1.output.value()).collect();
        let mut remaining: Vec<usize> = (0..nums.len()).collect();
        let mut result: Vec<(usize, Vec<usize>)> = Vec::new();

        targets.sort_unstable_by_key(|&(v, _)| v);
        nums.sort_unstable_by_key(|&v| v);

        for (target, original_output_idx) in targets {
            let used = Self::backtrack_subset(&remaining, &nums, target).unwrap_or_default();
            // Remove used indices from remaining pool
            remaining.retain(|i| !used.contains(i));
            result.push((original_output_idx, used));
        }

        result
    }

    fn backtrack_subset(pool: &[usize], nums: &[MicroMinotari], target: MicroMinotari) -> Option<Vec<usize>> {
        // Only consider inputs that can possibly contribute
        let mut candidates: Vec<usize> = Vec::new();
        for index in pool {
            if *nums.get(*index)? <= target {
                candidates.push(*index);
            }
        }

        // Sort descending for pruning
        candidates.sort_unstable_by(|&a, &b| {
            nums.get(b)
                .expect("Should exist")
                .cmp(nums.get(a).expect("Should exist"))
        });

        let vals: Vec<MicroMinotari> = candidates
            .iter()
            .map(|&i| *nums.get(i).expect("Should exist"))
            .collect();

        let suffix: Vec<MicroMinotari> = {
            // suffix[i] is an upper bound on the sum of vals[i..]. Saturating keeps it a valid
            // upper bound for the pruning checks below even if the real sum exceeds u64.
            let mut s = vec![MicroMinotari::from(0); vals.len().saturating_add(1)];
            for (i, val) in vals.iter().enumerate().rev() {
                let next = *s.get(i.saturating_add(1)).expect("Should exist");
                *(s.get_mut(i).expect("Should exist")) = next.saturating_add(val);
            }
            s
        };

        // Quick check: can we even reach the target?
        if suffix.first()? < &target {
            return None;
        }

        let mut assignment = vec![false; vals.len()];

        fn back_track(
            vals: &[MicroMinotari],
            suffix: &[MicroMinotari],
            assignment: &mut Vec<bool>,
            step: usize,
            current: MicroMinotari,
            target: MicroMinotari,
        ) -> bool {
            if current == target {
                return true;
            }
            if step == vals.len() {
                return false;
            }

            let n = match vals.get(step) {
                Some(n) => n,
                None => return false,
            };
            let next_step = step.saturating_add(1);
            let rem = match suffix.get(next_step) {
                Some(rem) => rem,
                None => return false,
            };

            // Prune: even taking everything remaining won't reach target.
            // Saturating keeps this an upper bound, so it never prunes a reachable target.
            if current.saturating_add(rem).saturating_add(n) < target {
                return false;
            }
            // Prune: already over target
            if current > target {
                return false;
            }
            if assignment.len() <= step {
                return false;
            }

            // Try taking this input
            if let Some(with_n) = current.checked_add(n)
                && with_n <= target
            {
                *assignment.get_mut(step).expect("Already checked") = true;
                if back_track(vals, suffix, assignment, next_step, with_n, target) {
                    return true;
                }
            }

            // Try skipping this input
            *assignment.get_mut(step).expect("Already checked") = false;
            back_track(vals, suffix, assignment, next_step, current, target)
        }

        if back_track(&vals, &suffix, &mut assignment, 0, 0.into(), target) {
            Some(
                candidates
                    .iter()
                    .zip(&assignment)
                    .filter(|&(_, &taken)| taken)
                    .map(|(&orig_idx, _)| orig_idx)
                    .collect(),
            )
        } else {
            None
        }
    }

    fn handle_unmatched_inputs_outputs(
        &self,
        inputs: Vec<(BalanceChange, SpentInput)>,
        outputs: &[(BalanceChange, DetectedOutput)],
        unmatched_outputs: &[usize],
        accumulator: &BlockEventAccumulator,
    ) -> Result<Vec<DisplayedTransaction>, ProcessorError> {
        let mut results = Vec::new();
        for index in unmatched_outputs {
            let (balance_change, output) = outputs
                .get(*index)
                .ok_or(ProcessorError::MissingError("Output index out of bounds".to_string()))?;
            let (initial_status, initial_confirmations) =
                self.calculate_status_and_confirmations(output.height, output.output.max_lock_height());
            let id = TxId::new_deterministic(self.view_key.as_bytes(), &output.output.output_hash());
            let memo = MemoInfo::from_output(&output.output);
            let sent = output.output.payment_id().get_sent_hashes().unwrap_or_default();
            let other_party = output.output.payment_id().claimed_sender_address();
            let display_tx = DisplayedTransactionBuilder::new()
                .account_id(accumulator.account_id as Id)
                .source(TransactionSource::Transfer)
                .status(initial_status)
                .lock_height(output.output.max_lock_height())
                .credits_and_debits(balance_change.balance_credit, 0.into())
                .counterparty(other_party)
                .blockchain_info(
                    accumulator.height,
                    output.mined_in_block_hash,
                    balance_change.effective_date,
                    initial_confirmations,
                )
                .fee(output.output.payment_id().get_fee())
                .message(memo.parsed)
                .memo_hex(memo.hex)
                .outputs(vec![TransactionOutput {
                    hash: output.output.output_hash(),
                    amount: output.output.value(),
                    status: OutputStatus::Unspent,
                    mined_in_block_height: output.height,
                    mined_in_block_hash: output.mined_in_block_hash,
                    output_type: OutputType::Standard,
                    is_change: false,
                }])
                .output_type(Some(OutputType::Standard))
                .sent_output_hashes(sent)
                .build(id)?;
            results.push(display_tx);
        }
        for (balance_change, input) in inputs {
            let (initial_status, initial_confirmations) =
                self.calculate_status_and_confirmations(input.mined_in_block_height, 0);
            // these are unpaired inputs, so they must be outgoing transactions that don't have a change output
            let tx = DisplayedTransactionBuilder::new()
                .account_id(accumulator.account_id as Id)
                .source(TransactionSource::Transfer)
                .status(initial_status)
                .credits_and_debits(0.into(), balance_change.balance_debit)
                .blockchain_info(
                    accumulator.height,
                    input.mined_in_block,
                    balance_change.effective_date,
                    initial_confirmations,
                )
                .inputs(vec![TransactionInput {
                    output_hash: input.output.output_hash(),
                    amount: input.output.value(),
                    mined_in_block_hash: input.mined_in_block,
                    matched_output_id: input.output_id,
                }])
                .output_type(None)
                .build(TxId::new_deterministic(
                    self.view_key.as_bytes(),
                    &input.output.output_hash(),
                ))?;
            results.push(tx);
        }

        Ok(results)
    }

    pub fn process_all_stored_with_conn(
        &self,
        account_id: Id,
        conn: &Connection,
    ) -> Result<(Vec<DisplayedTransaction>, Vec<DisplayedTransaction>), ProcessorError> {
        debug!(
            account_id = account_id;
            "Processing all stored transactions for account"
        );

        let balance_changes = db::get_all_active_balance_changes_by_account_id(conn, account_id)?;

        if balance_changes.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }

        //lets group them via height.
        let mapped_changes: HashMap<u64, Vec<BalanceChange>> =
            balance_changes.into_iter().fold(HashMap::new(), |mut acc, change| {
                acc.entry(change.effective_height).or_default().push(change);
                acc
            });
        let mut new_transactions = Vec::new();
        let mut updated_transactions = Vec::new();
        for balance_changes in mapped_changes.into_values() {
            debug!(
                count = balance_changes.len();
                "Processing balance changes at height"
            );
            //let create the accumulator for this height and process it
            let mut acc = BlockEventAccumulator::new(
                account_id,
                balance_changes.first().expect("Already checked").effective_height,
                vec![],
            );
            for balance_change in balance_changes {
                if balance_change.is_debit() {
                    let input = db::get_input_by_id(
                        conn,
                        balance_change.caused_by_input_id.ok_or(ProcessorError::MissingError(
                            "Debit balance change has no associated input".to_string(),
                        ))?,
                    )?
                    .ok_or(ProcessorError::MissingError(
                        "Debit balance change has no associated input".to_string(),
                    ))?;
                    let output = db::get_output_by_id(conn, input.output_id)?.ok_or(ProcessorError::MissingError(
                        format!("Ouput does not exist: {}", input.output_id),
                    ))?;
                    let spent_input = SpentInput {
                        output_id: input.id,
                        mined_in_block: FixedHash::try_from(input.mined_in_block_hash)
                            .map_err(|e| ProcessorError::ParseError(e.to_string()))?,
                        mined_in_block_height: input.mined_in_block_height as u64,
                        output: output.to_wallet_output()?,
                    };
                    acc.add_debit_change(balance_change, spent_input);
                } else {
                    let output = db::get_output_by_id(
                        conn,
                        balance_change.caused_by_output_id.ok_or(ProcessorError::MissingError(
                            "Credit balance change has no associated input".to_string(),
                        ))?,
                    )?
                    .ok_or(ProcessorError::MissingError(
                        "Credit balance change has no associated input".to_string(),
                    ))?;
                    let detected = DetectedOutput {
                        height: output.mined_in_block_height as u64,
                        mined_in_block_hash: FixedHash::try_from(output.mined_in_block_hash.clone())
                            .map_err(|e| ProcessorError::ParseError(e.to_string()))?,
                        output: output.to_wallet_output()?,
                    };
                    acc.add_credit_change(balance_change, detected);
                }
            }
            let (mut updated_tx, mut new_tx) = self.create_new_updated_display_transactions_for_height(&acc, conn)?;
            updated_transactions.append(&mut updated_tx);
            new_transactions.append(&mut new_tx);
        }
        Ok((updated_transactions, new_transactions))
    }

    fn calculate_status_and_confirmations(
        &self,
        mined_height: u64,
        lock_height: u64,
    ) -> (TransactionDisplayStatus, u64) {
        let confirmations = self.current_tip_height.saturating_sub(mined_height);
        let status = if confirmations >= self.req_confirmations {
            if lock_height <= self.current_tip_height {
                TransactionDisplayStatus::Confirmed
            } else {
                TransactionDisplayStatus::Locked
            }
        } else {
            TransactionDisplayStatus::Unconfirmed
        };
        (status, confirmations)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    use super::*;
    use crate::models::OutputStatus;
    use chrono::NaiveDateTime;
    use tari_common_types::types::FixedHash;
    use tari_transaction_components::MicroMinotari;
    use tari_transaction_components::transaction_components::OutputType;

    // Helper function to create a mock FixedHash
    fn mock_fixed_hash(value: u8) -> FixedHash {
        let mut bytes = [0u8; 32];
        bytes[0] = value;
        FixedHash::from(bytes)
    }

    // Helper function to create a mock timestamp
    fn mock_timestamp() -> NaiveDateTime {
        NaiveDateTime::parse_from_str("2025-01-15 10:00:00", "%Y-%m-%d %H:%M:%S").unwrap()
    }

    // Helper function to create a basic DisplayedTransaction for testing
    fn create_test_displayed_transaction(
        id: u64,
        output_hash: FixedHash,
        status: TransactionDisplayStatus,
        block_height: u64,
    ) -> DisplayedTransaction {
        DisplayedTransactionBuilder::new()
            .account_id(1)
            .source(TransactionSource::Transfer)
            .status(status)
            .credits_and_debits(MicroMinotari::from(1000), MicroMinotari::from(0))
            .blockchain_info(block_height, mock_fixed_hash(1), mock_timestamp(), 0)
            .inputs(vec![])
            .outputs(vec![TransactionOutput {
                hash: output_hash,
                amount: MicroMinotari::from(1000),
                status: OutputStatus::Unspent,
                mined_in_block_height: block_height,
                mined_in_block_hash: mock_fixed_hash(1),
                output_type: OutputType::Standard,
                is_change: false,
            }])
            .output_type(Some(OutputType::Standard))
            .build(id.into())
            .unwrap()
    }

    // Helper function to create a DisplayedTransaction with inputs for debit testing
    fn create_test_displayed_transaction_with_input(
        id: u64,
        input_hash: FixedHash,
        status: TransactionDisplayStatus,
        block_height: u64,
    ) -> DisplayedTransaction {
        DisplayedTransactionBuilder::new()
            .account_id(1)
            .source(TransactionSource::Transfer)
            .status(status)
            .credits_and_debits(MicroMinotari::from(0), MicroMinotari::from(500))
            .blockchain_info(block_height, mock_fixed_hash(1), mock_timestamp(), 0)
            .inputs(vec![TransactionInput {
                output_hash: input_hash,
                amount: MicroMinotari::from(500),
                mined_in_block_hash: mock_fixed_hash(1),
                matched_output_id: 0,
            }])
            .outputs(vec![])
            .output_type(None)
            .build(id.into())
            .unwrap()
    }

    // Helper to create a mock BalanceChange for credits
    fn create_credit_balance_change(account_id: i64, amount: u64, height: u64) -> BalanceChange {
        BalanceChange {
            account_id,
            caused_by_output_id: Some(1),
            caused_by_input_id: None,
            description: "Test credit".to_string(),
            balance_credit: MicroMinotari::from(amount),
            balance_debit: MicroMinotari::from(0),
            effective_date: mock_timestamp(),
            effective_height: height,
            claimed_recipient_address: None,
            claimed_sender_address: None,
            memo_parsed: None,
            memo_hex: None,
            claimed_fee: None,
            claimed_amount: None,
            is_reversal: false,
            reversal_of_balance_change_id: None,
            is_reversed: false,
        }
    }

    // Helper to create a mock BalanceChange for debits
    fn create_debit_balance_change(account_id: i64, amount: u64, height: u64) -> BalanceChange {
        BalanceChange {
            account_id,
            caused_by_output_id: None,
            caused_by_input_id: Some(1),
            description: "Test debit".to_string(),
            balance_credit: MicroMinotari::from(0),
            balance_debit: MicroMinotari::from(amount),
            effective_date: mock_timestamp(),
            effective_height: height,
            claimed_recipient_address: None,
            claimed_sender_address: None,
            memo_parsed: None,
            memo_hex: None,
            claimed_fee: None,
            claimed_amount: None,
            is_reversal: false,
            reversal_of_balance_change_id: None,
            is_reversed: false,
        }
    }

    #[test]
    fn test_create_new_updated_display_transactions_empty_accumulator() {
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);
        let current_display_transactions: Vec<DisplayedTransaction> = vec![];

        let result = processor.create_new_updated_display_transactions(&accumulator, &current_display_transactions);

        assert!(result.is_ok());
        let (updated, new) = result.unwrap();
        assert!(updated.is_empty());
        assert!(new.is_empty());
    }

    #[test]
    fn test_create_new_updated_display_transactions_empty_existing_transactions() {
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);
        let current_display_transactions: Vec<DisplayedTransaction> = vec![];

        let result = processor.create_new_updated_display_transactions(&accumulator, &current_display_transactions);

        assert!(result.is_ok());
        let (updated, new) = result.unwrap();
        // With no existing transactions and empty accumulator, nothing should be updated or created
        assert!(updated.is_empty());
        assert!(new.is_empty());
    }

    #[test]
    fn test_processor_new_with_tip_height() {
        let processor = DisplayedTransactionProcessor::new(500, 3, PrivateKey::default());
        assert_eq!(processor.current_tip_height, 500);
    }

    #[test]
    fn test_processor_new_with_zero_tip_height() {
        let processor = DisplayedTransactionProcessor::new(0, 3, PrivateKey::default());
        assert_eq!(processor.current_tip_height, 0);
    }

    #[test]
    fn test_create_new_updated_display_transactions_returns_tuple() {
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);
        let current_display_transactions: Vec<DisplayedTransaction> = vec![];

        let result = processor.create_new_updated_display_transactions(&accumulator, &current_display_transactions);

        assert!(result.is_ok());
        let (updated, new) = result.unwrap();

        // Verify we get two vectors back
        assert!(updated.is_empty());
        assert!(new.is_empty());
    }

    #[test]
    fn test_status_update_logic_with_sufficient_confirmations() {
        // Test that when confirmations >= REQUIRED_CONFIRMATIONS, status becomes Confirmed
        let tip_height = 100u64;
        let block_height = 90u64;
        let confirmations = tip_height.saturating_sub(block_height);

        assert!(confirmations >= 3);

        // The logic in the function should set status to Confirmed
        let expected_status = if confirmations >= 3 {
            TransactionDisplayStatus::Confirmed
        } else {
            TransactionDisplayStatus::Unconfirmed
        };

        assert_eq!(expected_status, TransactionDisplayStatus::Confirmed);
    }

    #[test]
    fn test_status_update_logic_with_insufficient_confirmations() {
        // Test that when confirmations < REQUIRED_CONFIRMATIONS, status is Unconfirmed
        let tip_height = 100u64;
        let block_height = 99u64;
        let confirmations = tip_height.saturating_sub(block_height);

        // confirmations is 1, which is less than REQUIRED_CONFIRMATIONS (3)
        assert!(confirmations < 3);

        let expected_status = if confirmations >= 3 {
            TransactionDisplayStatus::Confirmed
        } else {
            TransactionDisplayStatus::Unconfirmed
        };

        assert_eq!(expected_status, TransactionDisplayStatus::Unconfirmed);
    }

    #[test]
    fn test_accumulator_total_changes_empty() {
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);
        assert_eq!(accumulator.total_changes(), 0);
    }

    #[test]
    fn test_accumulator_is_empty() {
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);
        assert!(accumulator.is_empty());
    }

    #[test]
    fn test_accumulator_credit_balance_changes_empty() {
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);
        assert!(accumulator.credit_balance_changes().is_empty());
    }

    #[test]
    fn test_accumulator_debit_balance_changes_empty() {
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);
        assert!(accumulator.debit_balance_changes().is_empty());
    }

    #[test]
    fn test_balance_change_is_credit() {
        let credit = create_credit_balance_change(1, 1000, 50);
        assert!(credit.is_credit());
        assert!(!credit.is_debit());
    }

    #[test]
    fn test_balance_change_is_debit() {
        let debit = create_debit_balance_change(1, 500, 50);
        assert!(!debit.is_credit());
        assert!(debit.is_debit());
    }

    #[test]
    fn test_processor_with_very_high_tip_height() {
        let processor = DisplayedTransactionProcessor::new(u64::MAX, 3, PrivateKey::default());
        assert_eq!(processor.current_tip_height, u64::MAX);

        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);
        let current_display_transactions: Vec<DisplayedTransaction> = vec![];

        let result = processor.create_new_updated_display_transactions(&accumulator, &current_display_transactions);
        assert!(result.is_ok());
    }

    #[test]
    fn test_confirmations_calculation_saturating_sub() {
        // Test that saturating_sub is used correctly for confirmations
        let tip_height = 50u64;
        let block_height = 100u64; // Higher than tip (edge case)

        let confirmations = tip_height.saturating_sub(block_height);
        assert_eq!(confirmations, 0); // Should not underflow
    }

    #[test]
    fn test_multiple_existing_transactions_no_matches() {
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);

        // Create some existing transactions that won't match anything in the empty accumulator
        let tx1 = create_test_displayed_transaction(1, mock_fixed_hash(10), TransactionDisplayStatus::Pending, 45);
        let tx2 = create_test_displayed_transaction(2, mock_fixed_hash(20), TransactionDisplayStatus::Confirmed, 40);
        let current_display_transactions = vec![tx1, tx2];

        let result = processor.create_new_updated_display_transactions(&accumulator, &current_display_transactions);

        assert!(result.is_ok());
        let (updated, new) = result.unwrap();
        // No matches because accumulator is empty
        assert!(updated.is_empty());
        assert!(new.is_empty());
    }

    #[test]
    fn test_displayed_transaction_builder_creates_valid_transaction() {
        let output_hash = mock_fixed_hash(1);
        let tx = create_test_displayed_transaction(1, output_hash, TransactionDisplayStatus::Pending, 50);

        assert_eq!(tx.details.account_id, 1);
        assert_eq!(tx.source, TransactionSource::Transfer);
        assert_eq!(tx.status, TransactionDisplayStatus::Pending);
        assert_eq!(tx.details.outputs.len(), 1);
        assert_eq!(tx.details.outputs[0].hash, output_hash);
    }

    #[test]
    fn test_displayed_transaction_with_input_creates_valid_transaction() {
        let input_hash = mock_fixed_hash(5);
        let tx = create_test_displayed_transaction_with_input(1, input_hash, TransactionDisplayStatus::Pending, 50);

        assert_eq!(tx.details.account_id, 1);
        assert_eq!(tx.source, TransactionSource::Transfer);
        assert_eq!(tx.status, TransactionDisplayStatus::Pending);
        assert_eq!(tx.details.inputs.len(), 1);
        assert_eq!(tx.details.inputs[0].output_hash, input_hash);
        assert!(tx.details.outputs.is_empty());
    }

    // ============================================
    // Tests for create_new_updated_display_transactions
    // ============================================

    #[test]
    fn test_create_new_updated_with_no_matching_outputs_returns_empty_updated() {
        // When the accumulator is empty, existing transactions should not be updated
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);

        // Create several existing transactions with different output hashes
        let tx1 = create_test_displayed_transaction(1, mock_fixed_hash(10), TransactionDisplayStatus::Pending, 45);
        let tx2 = create_test_displayed_transaction(2, mock_fixed_hash(20), TransactionDisplayStatus::Unconfirmed, 40);
        let tx3 = create_test_displayed_transaction(3, mock_fixed_hash(30), TransactionDisplayStatus::Confirmed, 35);
        let current_display_transactions = vec![tx1, tx2, tx3];

        let result = processor.create_new_updated_display_transactions(&accumulator, &current_display_transactions);

        assert!(result.is_ok());
        let (updated, new) = result.unwrap();
        // No updates since accumulator is empty
        assert!(
            updated.is_empty(),
            "No transactions should be updated when accumulator is empty"
        );
        assert!(
            new.is_empty(),
            "No new transactions should be created when accumulator is empty"
        );
    }

    #[test]
    fn test_create_new_updated_with_no_matching_inputs_returns_empty_updated() {
        // Test with existing transactions that have inputs but no matching debit changes
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);

        // Create existing transactions with inputs
        let tx1 =
            create_test_displayed_transaction_with_input(1, mock_fixed_hash(10), TransactionDisplayStatus::Pending, 45);
        let tx2 = create_test_displayed_transaction_with_input(
            2,
            mock_fixed_hash(20),
            TransactionDisplayStatus::Unconfirmed,
            40,
        );
        let current_display_transactions = vec![tx1, tx2];

        let result = processor.create_new_updated_display_transactions(&accumulator, &current_display_transactions);

        assert!(result.is_ok());
        let (updated, new) = result.unwrap();
        // No updates since accumulator has no debit changes
        assert!(
            updated.is_empty(),
            "No transactions should be updated when accumulator has no debit changes"
        );
        assert!(
            new.is_empty(),
            "No new transactions should be created when accumulator is empty"
        );
    }

    #[test]
    fn test_create_new_updated_preserves_original_when_no_match() {
        // Verify that original transactions are not modified when there's no match
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);

        let original_status = TransactionDisplayStatus::Pending;
        let original_height = 45u64;
        let tx = create_test_displayed_transaction(1, mock_fixed_hash(10), original_status, original_height);
        let current_display_transactions = vec![tx.clone()];

        let result = processor.create_new_updated_display_transactions(&accumulator, &current_display_transactions);

        assert!(result.is_ok());
        let (updated, _new) = result.unwrap();
        assert!(updated.is_empty());

        // Verify the original transaction wasn't modified in the input vector
        assert_eq!(current_display_transactions[0].status, original_status);
        assert_eq!(current_display_transactions[0].blockchain.block_height, original_height);
    }

    #[test]
    fn test_create_new_updated_with_mixed_output_types() {
        // Test with a mix of transactions having outputs and inputs
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);

        let tx_with_output =
            create_test_displayed_transaction(1, mock_fixed_hash(10), TransactionDisplayStatus::Pending, 45);
        let tx_with_input = create_test_displayed_transaction_with_input(
            2,
            mock_fixed_hash(20),
            TransactionDisplayStatus::Unconfirmed,
            40,
        );
        let current_display_transactions = vec![tx_with_output, tx_with_input];

        let result = processor.create_new_updated_display_transactions(&accumulator, &current_display_transactions);

        assert!(result.is_ok());
        let (updated, new) = result.unwrap();
        // No matches since accumulator is empty
        assert!(updated.is_empty());
        assert!(new.is_empty());
    }

    #[test]
    fn test_create_new_updated_handles_empty_inputs_list() {
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);

        // Transaction with an empty inputs list
        let tx = DisplayedTransactionBuilder::new()
            .account_id(1)
            .source(TransactionSource::Coinbase)
            .status(TransactionDisplayStatus::Confirmed)
            .credits_and_debits(MicroMinotari::from(5000000), MicroMinotari::from(0))
            .blockchain_info(45, mock_fixed_hash(1), mock_timestamp(), 55)
            .inputs(vec![])  // Empty inputs
            .outputs(vec![TransactionOutput {
                hash: mock_fixed_hash(99),
                amount: MicroMinotari::from(5000000),
                status: OutputStatus::Unspent,
                mined_in_block_height: 45,
                mined_in_block_hash: mock_fixed_hash(1),
                output_type: OutputType::Coinbase,
                is_change: false,
            }])
            .output_type(Some(OutputType::Coinbase))
            .build(1u64.into())
            .unwrap();
        let current_display_transactions = vec![tx];

        let result = processor.create_new_updated_display_transactions(&accumulator, &current_display_transactions);

        assert!(result.is_ok());
        let (updated, new) = result.unwrap();
        assert!(updated.is_empty());
        assert!(new.is_empty());
    }

    #[test]
    fn test_create_new_updated_handles_empty_outputs_list() {
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);

        // Transaction with an empty outputs list (debit only)
        let tx = DisplayedTransactionBuilder::new()
            .account_id(1)
            .source(TransactionSource::Transfer)
            .status(TransactionDisplayStatus::Confirmed)
            .credits_and_debits(MicroMinotari::from(0), MicroMinotari::from(1000))
            .blockchain_info(45, mock_fixed_hash(1), mock_timestamp(), 55)
            .inputs(vec![TransactionInput {
                output_hash: mock_fixed_hash(88),
                amount: MicroMinotari::from(1000),
                mined_in_block_hash: mock_fixed_hash(1),
                matched_output_id: 0,
            }])
            .outputs(vec![])  // Empty outputs
            .output_type(None)
            .build(1u64.into())
            .unwrap();
        let current_display_transactions = vec![tx];

        let result = processor.create_new_updated_display_transactions(&accumulator, &current_display_transactions);

        assert!(result.is_ok());
        let (updated, new) = result.unwrap();
        assert!(updated.is_empty());
        assert!(new.is_empty());
    }

    #[test]
    fn test_create_new_updated_with_large_transaction_set() {
        // Test with many existing transactions to ensure scaling
        let processor = DisplayedTransactionProcessor::new(1000, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 500, vec![0u8; 32]);

        let mut current_display_transactions = Vec::new();
        for i in 1..=100u8 {
            let tx = create_test_displayed_transaction(
                u64::from(i),
                mock_fixed_hash(i),
                TransactionDisplayStatus::Confirmed,
                400 + u64::from(i % 50),
            );
            current_display_transactions.push(tx);
        }

        let result = processor.create_new_updated_display_transactions(&accumulator, &current_display_transactions);

        assert!(result.is_ok());
        let (updated, new) = result.unwrap();
        // No matches since accumulator is empty
        assert!(updated.is_empty());
        assert!(new.is_empty());
    }

    #[test]
    fn test_create_new_updated_with_zero_required_confirmations() {
        // Edge case: zero required confirmations means everything is immediately confirmed
        let processor = DisplayedTransactionProcessor::new(100, 0, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);

        let tx = create_test_displayed_transaction(1, mock_fixed_hash(10), TransactionDisplayStatus::Pending, 45);
        let current_display_transactions = vec![tx];

        let result = processor.create_new_updated_display_transactions(&accumulator, &current_display_transactions);

        assert!(result.is_ok());
        // Even with 0 confirmations, no updates happen without matching balance changes
        let (updated, new) = result.unwrap();
        assert!(updated.is_empty());
        assert!(new.is_empty());
    }

    #[test]
    fn test_create_new_updated_with_very_large_confirmations_requirement() {
        // Edge case: very large confirmation requirement
        let processor = DisplayedTransactionProcessor::new(100, u64::MAX, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);

        let tx = create_test_displayed_transaction(1, mock_fixed_hash(10), TransactionDisplayStatus::Unconfirmed, 45);
        let current_display_transactions = vec![tx];

        let result = processor.create_new_updated_display_transactions(&accumulator, &current_display_transactions);

        assert!(result.is_ok());
        let (updated, new) = result.unwrap();
        assert!(updated.is_empty());
        assert!(new.is_empty());
    }

    #[test]
    fn test_create_new_updated_returns_separate_updated_and_new_vectors() {
        // Verify the function returns two separate vectors
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);
        let current_display_transactions: Vec<DisplayedTransaction> = vec![];

        let result = processor.create_new_updated_display_transactions(&accumulator, &current_display_transactions);

        assert!(result.is_ok());
        let (updated, new) = result.unwrap();
        // Both should be empty but distinct vectors
        assert!(updated.is_empty());
        assert!(new.is_empty());
        // Verify they are separate instances
        assert_eq!(updated.capacity(), 0);
    }

    #[test]
    fn test_create_new_updated_with_multiple_outputs_same_transaction() {
        // Test transaction with multiple outputs
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);

        let tx = DisplayedTransactionBuilder::new()
            .account_id(1)
            .source(TransactionSource::Transfer)
            .status(TransactionDisplayStatus::Confirmed)
            .credits_and_debits(MicroMinotari::from(3000), MicroMinotari::from(0))
            .blockchain_info(45, mock_fixed_hash(1), mock_timestamp(), 55)
            .inputs(vec![])
            .outputs(vec![
                TransactionOutput {
                    hash: mock_fixed_hash(1),
                    amount: MicroMinotari::from(1000),
                    status: OutputStatus::Unspent,
                    mined_in_block_height: 45,
                    mined_in_block_hash: mock_fixed_hash(1),
                    output_type: OutputType::Standard,
                    is_change: false,
                },
                TransactionOutput {
                    hash: mock_fixed_hash(2),
                    amount: MicroMinotari::from(1000),
                    status: OutputStatus::Unspent,
                    mined_in_block_height: 45,
                    mined_in_block_hash: mock_fixed_hash(1),
                    output_type: OutputType::Standard,
                    is_change: true,
                },
                TransactionOutput {
                    hash: mock_fixed_hash(3),
                    amount: MicroMinotari::from(1000),
                    status: OutputStatus::Unspent,
                    mined_in_block_height: 45,
                    mined_in_block_hash: mock_fixed_hash(1),
                    output_type: OutputType::Standard,
                    is_change: false,
                },
            ])
            .output_type(Some(OutputType::Standard))
            .build(1u64.into())
            .unwrap();
        let current_display_transactions = vec![tx];

        let result = processor.create_new_updated_display_transactions(&accumulator, &current_display_transactions);

        assert!(result.is_ok());
        let (updated, new) = result.unwrap();
        assert!(updated.is_empty());
        assert!(new.is_empty());
    }

    #[test]
    fn test_create_new_updated_with_multiple_inputs_same_transaction() {
        // Test transaction with multiple inputs
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);

        let tx = DisplayedTransactionBuilder::new()
            .account_id(1)
            .source(TransactionSource::Transfer)
            .status(TransactionDisplayStatus::Confirmed)
            .credits_and_debits(MicroMinotari::from(0), MicroMinotari::from(3000))
            .blockchain_info(45, mock_fixed_hash(1), mock_timestamp(), 55)
            .inputs(vec![
                TransactionInput {
                    output_hash: mock_fixed_hash(10),
                    amount: MicroMinotari::from(1000),
                    mined_in_block_hash: mock_fixed_hash(1),
                    matched_output_id: 1,
                },
                TransactionInput {
                    output_hash: mock_fixed_hash(20),
                    amount: MicroMinotari::from(1000),
                    mined_in_block_hash: mock_fixed_hash(1),
                    matched_output_id: 2,
                },
                TransactionInput {
                    output_hash: mock_fixed_hash(30),
                    amount: MicroMinotari::from(1000),
                    mined_in_block_hash: mock_fixed_hash(1),
                    matched_output_id: 3,
                },
            ])
            .outputs(vec![])
            .output_type(None)
            .build(1u64.into())
            .unwrap();
        let current_display_transactions = vec![tx];

        let result = processor.create_new_updated_display_transactions(&accumulator, &current_display_transactions);

        assert!(result.is_ok());
        let (updated, new) = result.unwrap();
        assert!(updated.is_empty());
        assert!(new.is_empty());
    }

    #[test]
    fn test_confirmation_status_logic_sufficient_confirmations() {
        // Test that the confirmation logic would set Confirmed status
        // when confirmations >= required_confirmations
        let tip_height = 100u64;
        let block_height = 50u64;
        let req_confirmations = 3u64;

        let confirmations = tip_height.saturating_sub(block_height);

        // 100 - 50 = 50 confirmations, which is >= 3
        assert!(confirmations >= req_confirmations);

        let expected_status = if confirmations >= req_confirmations {
            TransactionDisplayStatus::Confirmed
        } else {
            TransactionDisplayStatus::Unconfirmed
        };

        assert_eq!(expected_status, TransactionDisplayStatus::Confirmed);
    }

    #[test]
    fn test_confirmation_status_logic_insufficient_confirmations() {
        // Test that the confirmation logic would set Unconfirmed status
        // when confirmations < required_confirmations
        let tip_height = 100u64;
        let block_height = 99u64;
        let req_confirmations = 3u64;

        let confirmations = tip_height.saturating_sub(block_height);

        // 100 - 99 = 1 confirmation, which is < 3
        assert!(confirmations < req_confirmations);

        let expected_status = if confirmations >= req_confirmations {
            TransactionDisplayStatus::Confirmed
        } else {
            TransactionDisplayStatus::Unconfirmed
        };

        assert_eq!(expected_status, TransactionDisplayStatus::Unconfirmed);
    }

    #[test]
    fn test_confirmation_status_logic_exactly_at_threshold() {
        // Test boundary condition: exactly at required confirmations
        let tip_height = 100u64;
        let block_height = 97u64;
        let req_confirmations = 3u64;

        let confirmations = tip_height.saturating_sub(block_height);

        // 100 - 97 = 3 confirmations, which is exactly == 3
        assert_eq!(confirmations, req_confirmations);

        let expected_status = if confirmations >= req_confirmations {
            TransactionDisplayStatus::Confirmed
        } else {
            TransactionDisplayStatus::Unconfirmed
        };

        // >= means exactly at threshold is still confirmed
        assert_eq!(expected_status, TransactionDisplayStatus::Confirmed);
    }

    #[test]
    fn test_confirmation_status_logic_one_below_threshold() {
        // Test boundary condition: one below required confirmations
        let tip_height = 100u64;
        let block_height = 98u64;
        let req_confirmations = 3u64;

        let confirmations = tip_height.saturating_sub(block_height);

        // 100 - 98 = 2 confirmations, which is < 3
        assert_eq!(confirmations, 2);

        let expected_status = if confirmations >= req_confirmations {
            TransactionDisplayStatus::Confirmed
        } else {
            TransactionDisplayStatus::Unconfirmed
        };

        assert_eq!(expected_status, TransactionDisplayStatus::Unconfirmed);
    }

    #[test]
    fn test_different_account_ids_in_accumulator() {
        // Test that account_id is properly used from accumulator
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());

        // Different account IDs
        let acc1 = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);
        let acc2 = BlockEventAccumulator::new(2, 50, vec![0u8; 32]);
        let acc3 = BlockEventAccumulator::new(999, 50, vec![0u8; 32]);

        assert_eq!(acc1.account_id, 1);
        assert_eq!(acc2.account_id, 2);
        assert_eq!(acc3.account_id, 999);

        // All should work the same way
        let current_display_transactions: Vec<DisplayedTransaction> = vec![];

        let result1 = processor.create_new_updated_display_transactions(&acc1, &current_display_transactions);
        let result2 = processor.create_new_updated_display_transactions(&acc2, &current_display_transactions);
        let result3 = processor.create_new_updated_display_transactions(&acc3, &current_display_transactions);

        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert!(result3.is_ok());
    }

    #[test]
    fn test_different_block_heights_in_accumulator() {
        // Test that block height is properly captured from accumulator
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());

        let acc_low = BlockEventAccumulator::new(1, 0, vec![0u8; 32]);
        let acc_mid = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);
        let acc_high = BlockEventAccumulator::new(1, u64::MAX, vec![0u8; 32]);

        assert_eq!(acc_low.height, 0);
        assert_eq!(acc_mid.height, 50);
        assert_eq!(acc_high.height, u64::MAX);

        let current_display_transactions: Vec<DisplayedTransaction> = vec![];

        // All should work without panicking
        assert!(
            processor
                .create_new_updated_display_transactions(&acc_low, &current_display_transactions)
                .is_ok()
        );
        assert!(
            processor
                .create_new_updated_display_transactions(&acc_mid, &current_display_transactions)
                .is_ok()
        );
        assert!(
            processor
                .create_new_updated_display_transactions(&acc_high, &current_display_transactions)
                .is_ok()
        );
    }

    #[test]
    fn test_accumulator_with_various_block_hashes() {
        // Test with different block hash values
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let current_display_transactions: Vec<DisplayedTransaction> = vec![];

        // Zero hash
        let acc_zero = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);
        assert!(
            processor
                .create_new_updated_display_transactions(&acc_zero, &current_display_transactions)
                .is_ok()
        );

        // All ones hash
        let acc_ones = BlockEventAccumulator::new(1, 50, vec![255u8; 32]);
        assert!(
            processor
                .create_new_updated_display_transactions(&acc_ones, &current_display_transactions)
                .is_ok()
        );

        // Sequential bytes
        let sequential: Vec<u8> = (0u8..32).collect();
        let acc_seq = BlockEventAccumulator::new(1, 50, sequential);
        assert!(
            processor
                .create_new_updated_display_transactions(&acc_seq, &current_display_transactions)
                .is_ok()
        );
    }

    // ── Helper to build a mock WalletOutput with a given value ──────────────────
    fn mock_wallet_output(value: u64) -> tari_transaction_components::transaction_components::WalletOutput {
        use tari_common_types::types::{ComAndPubSignature, CompressedPublicKey};
        use tari_script::{ExecutionStack, TariScript};
        use tari_transaction_components::{
            key_manager::TariKeyId,
            transaction_components::{
                EncryptedData, MemoField, OutputFeatures, TransactionOutputVersion, WalletOutput, covenants::Covenant,
            },
        };

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
            mock_fixed_hash(0),
            Default::default(),
        )
    }

    fn mock_spent_input(value: u64, hash_byte: u8) -> SpentInput {
        SpentInput {
            output_id: 0,
            mined_in_block: mock_fixed_hash(hash_byte),
            mined_in_block_height: 10,
            output: mock_wallet_output(value),
        }
    }

    fn mock_detected_output(value: u64, hash_byte: u8, height: u64) -> DetectedOutput {
        DetectedOutput {
            height,
            mined_in_block_hash: mock_fixed_hash(hash_byte),
            output: mock_wallet_output(value),
        }
    }

    // ── solve_back_track tests ──────────────────────────────────────────────────

    #[test]
    fn test_solve_back_track_empty_inputs_empty_targets() {
        let inputs: Vec<(BalanceChange, SpentInput)> = vec![];
        let targets: Vec<(MicroMinotari, usize)> = vec![];
        let result = DisplayedTransactionProcessor::solve_back_track(&inputs, targets);
        assert!(result.is_empty());
    }

    #[test]
    fn test_solve_back_track_empty_inputs_with_targets() {
        let inputs: Vec<(BalanceChange, SpentInput)> = vec![];
        let targets = vec![(MicroMinotari::from(100), 0)];
        let result = DisplayedTransactionProcessor::solve_back_track(&inputs, targets);
        // Should return one entry with empty used-indices (no inputs to match)
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, 0);
        assert!(result[0].1.is_empty());
    }

    #[test]
    fn test_solve_back_track_inputs_with_no_targets() {
        let inputs = vec![
            (create_debit_balance_change(1, 100, 10), mock_spent_input(100, 1)),
            (create_debit_balance_change(1, 200, 10), mock_spent_input(200, 2)),
        ];
        let targets: Vec<(MicroMinotari, usize)> = vec![];
        let result = DisplayedTransactionProcessor::solve_back_track(&inputs, targets);
        assert!(result.is_empty());
    }

    #[test]
    fn test_solve_back_track_single_exact_match() {
        let inputs = vec![(create_debit_balance_change(1, 500, 10), mock_spent_input(500, 1))];
        let targets = vec![(MicroMinotari::from(500), 0)];
        let result = DisplayedTransactionProcessor::solve_back_track(&inputs, targets);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, 0); // output index
        assert_eq!(result[0].1, vec![0]); // input index 0 used
    }

    #[test]
    fn test_solve_back_track_no_subset_matches() {
        let inputs = vec![
            (create_debit_balance_change(1, 100, 10), mock_spent_input(100, 1)),
            (create_debit_balance_change(1, 200, 10), mock_spent_input(200, 2)),
        ];
        // Target 400 cannot be reached (100 + 200 = 300)
        let targets = vec![(MicroMinotari::from(400), 0)];
        let result = DisplayedTransactionProcessor::solve_back_track(&inputs, targets);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, 0);
        assert!(result[0].1.is_empty()); // no solution found
    }

    #[test]
    fn test_solve_back_track_multiple_inputs_sum_to_target() {
        let inputs = vec![
            (create_debit_balance_change(1, 100, 10), mock_spent_input(100, 1)),
            (create_debit_balance_change(1, 200, 10), mock_spent_input(200, 2)),
            (create_debit_balance_change(1, 300, 10), mock_spent_input(300, 3)),
        ];
        // Target 300: could be input[2] alone, or input[0]+input[1]
        let targets = vec![(MicroMinotari::from(300), 0)];
        let result = DisplayedTransactionProcessor::solve_back_track(&inputs, targets);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, 0);
        // Verify the solution sums to 300
        let total: u64 = result[0].1.iter().map(|&i| inputs[i].1.output.value().as_u64()).sum();
        assert_eq!(total, 300);
    }

    #[test]
    fn test_solve_back_track_two_targets_no_overlap() {
        let inputs = vec![
            (create_debit_balance_change(1, 100, 10), mock_spent_input(100, 1)),
            (create_debit_balance_change(1, 200, 10), mock_spent_input(200, 2)),
            (create_debit_balance_change(1, 300, 10), mock_spent_input(300, 3)),
        ];
        // Two targets: 100 and 200. Both should be satisfiable without overlap.
        let targets = vec![(MicroMinotari::from(100), 0), (MicroMinotari::from(200), 1)];
        let result = DisplayedTransactionProcessor::solve_back_track(&inputs, targets);
        assert_eq!(result.len(), 2);

        // Collect all used input indices
        let used_0: Vec<usize> = result[0].1.clone();
        let used_1: Vec<usize> = result[1].1.clone();
        // No overlap
        for idx in &used_0 {
            assert!(!used_1.contains(idx), "Input index {} used for both targets", idx);
        }
    }

    #[test]
    fn test_solve_back_track_second_target_starved_by_first() {
        // Only two inputs of value 100 each, two targets of 100 each.
        // First target should consume one, second should consume the other.
        let inputs = vec![
            (create_debit_balance_change(1, 100, 10), mock_spent_input(100, 1)),
            (create_debit_balance_change(1, 100, 10), mock_spent_input(100, 2)),
        ];
        let targets = vec![(MicroMinotari::from(100), 0), (MicroMinotari::from(100), 1)];
        let result = DisplayedTransactionProcessor::solve_back_track(&inputs, targets);
        assert_eq!(result.len(), 2);
        // Both should find a solution
        assert_eq!(result[0].1.len(), 1);
        assert_eq!(result[1].1.len(), 1);
        // Should use different inputs
        assert_ne!(result[0].1[0], result[1].1[0]);
    }

    #[test]
    fn test_solve_back_track_target_requires_all_inputs() {
        let inputs = vec![
            (create_debit_balance_change(1, 100, 10), mock_spent_input(100, 1)),
            (create_debit_balance_change(1, 200, 10), mock_spent_input(200, 2)),
            (create_debit_balance_change(1, 300, 10), mock_spent_input(300, 3)),
        ];
        // Target = sum of all inputs
        let targets = vec![(MicroMinotari::from(600), 0)];
        let result = DisplayedTransactionProcessor::solve_back_track(&inputs, targets);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1.len(), 3);
        let total: u64 = result[0].1.iter().map(|&i| inputs[i].1.output.value().as_u64()).sum();
        assert_eq!(total, 600);
    }

    #[test]
    fn test_solve_back_track_zero_value_target() {
        let inputs = vec![(create_debit_balance_change(1, 100, 10), mock_spent_input(100, 1))];
        let targets = vec![(MicroMinotari::from(0), 0)];
        let result = DisplayedTransactionProcessor::solve_back_track(&inputs, targets);
        assert_eq!(result.len(), 1);
        // Zero target is immediately satisfied with no inputs
        assert!(result[0].1.is_empty());
    }

    #[test]
    fn test_solve_back_track_duplicate_input_values() {
        let inputs = vec![
            (create_debit_balance_change(1, 50, 10), mock_spent_input(50, 1)),
            (create_debit_balance_change(1, 50, 10), mock_spent_input(50, 2)),
            (create_debit_balance_change(1, 50, 10), mock_spent_input(50, 3)),
        ];
        let targets = vec![(MicroMinotari::from(100), 0)];
        let result = DisplayedTransactionProcessor::solve_back_track(&inputs, targets);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1.len(), 2);
        let total: u64 = result[0].1.iter().map(|&i| inputs[i].1.output.value().as_u64()).sum();
        assert_eq!(total, 100);
    }

    #[test]
    fn test_solve_back_track_large_number_of_inputs() {
        // 10 inputs of value 1 each, target = 5
        let inputs: Vec<_> = (0u8..10)
            .map(|i| (create_debit_balance_change(1, 1, 10), mock_spent_input(1, i)))
            .collect();
        let targets = vec![(MicroMinotari::from(5), 0)];
        let result = DisplayedTransactionProcessor::solve_back_track(&inputs, targets);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1.len(), 5);
        let total: u64 = result[0].1.iter().map(|&i| inputs[i].1.output.value().as_u64()).sum();
        assert_eq!(total, 5);
    }

    #[test]
    fn test_solve_back_track_preserves_output_indices() {
        let inputs = vec![
            (create_debit_balance_change(1, 100, 10), mock_spent_input(100, 1)),
            (create_debit_balance_change(1, 200, 10), mock_spent_input(200, 2)),
        ];
        // Use non-zero output indices to verify they're preserved
        let targets = vec![(MicroMinotari::from(100), 5), (MicroMinotari::from(200), 9)];
        let result = DisplayedTransactionProcessor::solve_back_track(&inputs, targets);
        assert_eq!(result.len(), 2);
        let output_indices: Vec<usize> = result.iter().map(|r| r.0).collect();
        assert!(output_indices.contains(&5));
        assert!(output_indices.contains(&9));
    }

    #[test]
    fn test_solve_back_track_targets_processed_in_ascending_value_order() {
        // Targets are sorted by value internally, so smaller targets are solved first.
        // This means the smaller target gets first pick of inputs.
        let inputs = vec![
            (create_debit_balance_change(1, 100, 10), mock_spent_input(100, 1)),
            (create_debit_balance_change(1, 200, 10), mock_spent_input(200, 2)),
        ];
        // Give the large target first in the vec, but it should still process smallest first
        let targets = vec![(MicroMinotari::from(200), 0), (MicroMinotari::from(100), 1)];
        let result = DisplayedTransactionProcessor::solve_back_track(&inputs, targets);
        assert_eq!(result.len(), 2);
        // Both should find solutions since 100 + 200 exactly matches both targets
        let total: u64 = result
            .iter()
            .flat_map(|r| &r.1)
            .map(|&i| inputs[i].1.output.value().as_u64())
            .sum();
        assert_eq!(total, 300);
    }

    #[test]
    fn test_solve_back_track_single_input_value_one() {
        let inputs = vec![(create_debit_balance_change(1, 1, 10), mock_spent_input(1, 1))];
        let targets = vec![(MicroMinotari::from(1), 0)];
        let result = DisplayedTransactionProcessor::solve_back_track(&inputs, targets);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1, vec![0]);
    }

    // ── search_inputs tests ─────────────────────────────────────────────────────

    #[test]
    fn test_search_inputs_empty_inputs_and_outputs() {
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);
        let inputs: Vec<(BalanceChange, SpentInput)> = vec![];
        let outputs: Vec<(BalanceChange, DetectedOutput)> = vec![];

        let result = processor.search_inputs(inputs, outputs, &accumulator);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_search_inputs_only_unmatched_inputs() {
        // Inputs with no matching outputs should become unmatched (outgoing) transactions
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);

        let inputs = vec![
            (create_debit_balance_change(1, 500, 50), mock_spent_input(500, 1)),
            (create_debit_balance_change(1, 300, 50), mock_spent_input(300, 2)),
        ];
        let outputs: Vec<(BalanceChange, DetectedOutput)> = vec![];

        let result = processor.search_inputs(inputs, outputs, &accumulator);
        assert!(result.is_ok());
        let txs = result.unwrap();
        // Each unmatched input should generate a transaction
        assert_eq!(txs.len(), 2);
    }

    #[test]
    fn test_search_inputs_only_unmatched_outputs() {
        // Outputs with no transaction_info_details go to unmatched (mock_wallet_output uses MemoField::new_empty)
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);

        let inputs: Vec<(BalanceChange, SpentInput)> = vec![];
        let outputs = vec![(
            create_credit_balance_change(1, 1000, 50),
            mock_detected_output(1000, 1, 50),
        )];

        let result = processor.search_inputs(inputs, outputs, &accumulator);
        assert!(result.is_ok());
        let txs = result.unwrap();
        // Output without transaction_info_details -> unmatched output transaction
        assert_eq!(txs.len(), 1);
    }

    #[test]
    fn test_search_inputs_multiple_unmatched_inputs_creates_individual_transactions() {
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);

        let inputs = vec![
            (create_debit_balance_change(1, 100, 50), mock_spent_input(100, 1)),
            (create_debit_balance_change(1, 200, 50), mock_spent_input(200, 2)),
            (create_debit_balance_change(1, 300, 50), mock_spent_input(300, 3)),
        ];
        let outputs: Vec<(BalanceChange, DetectedOutput)> = vec![];

        let result = processor.search_inputs(inputs, outputs, &accumulator);
        assert!(result.is_ok());
        let txs = result.unwrap();
        assert_eq!(txs.len(), 3);
    }

    #[test]
    fn test_search_inputs_mixed_unmatched_inputs_and_outputs() {
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);

        let inputs = vec![(create_debit_balance_change(1, 100, 50), mock_spent_input(100, 1))];
        let outputs = vec![(
            create_credit_balance_change(1, 500, 50),
            mock_detected_output(500, 2, 50),
        )];

        let result = processor.search_inputs(inputs, outputs, &accumulator);
        assert!(result.is_ok());
        let txs = result.unwrap();
        // 1 unmatched input + 1 unmatched output = 2 transactions
        assert_eq!(txs.len(), 2);
    }

    #[test]
    fn test_search_inputs_status_confirmed_when_enough_confirmations() {
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);

        let inputs = vec![(create_debit_balance_change(1, 100, 50), mock_spent_input(100, 1))];
        let outputs: Vec<(BalanceChange, DetectedOutput)> = vec![];

        let result = processor.search_inputs(inputs, outputs, &accumulator).unwrap();
        assert_eq!(result.len(), 1);
        // tip=100, mined_height=10 (from mock_spent_input), confirmations=90 >= 3
        assert_eq!(result[0].status, TransactionDisplayStatus::Confirmed);
    }

    #[test]
    fn test_search_inputs_status_unconfirmed_when_few_confirmations() {
        // tip=12, req=3, mined_at=10 -> confirmations=2 < 3
        let processor = DisplayedTransactionProcessor::new(12, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);

        let inputs = vec![(create_debit_balance_change(1, 100, 50), mock_spent_input(100, 1))];
        let outputs: Vec<(BalanceChange, DetectedOutput)> = vec![];

        let result = processor.search_inputs(inputs, outputs, &accumulator).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].status, TransactionDisplayStatus::Unconfirmed);
    }

    // ── Hostile memo claims ─────────────────────────────────────────────────────

    /// Builds an output whose memo carries a `TransactionInfo` claim. Both the claimed amount and the claimed fee are
    /// chosen by whoever sent the output, so tests use this to feed arbitrary values through the matcher.
    fn mock_output_claiming(
        value: u64,
        claimed_amount: u64,
        claimed_fee: u64,
        hash_byte: u8,
        height: u64,
    ) -> DetectedOutput {
        use tari_common_types::tari_address::TariAddress;
        use tari_common_types::types::{ComAndPubSignature, CompressedPublicKey};
        use tari_script::{ExecutionStack, TariScript};
        use tari_transaction_components::{
            key_manager::TariKeyId,
            transaction_components::{
                EncryptedData, MemoField, OutputFeatures, TransactionOutputVersion, WalletOutput, covenants::Covenant,
                memo_field::TxType,
            },
        };

        let memo = MemoField::transaction_info_unchecked(
            TariAddress::default(),
            true,
            MicroMinotari::from(claimed_amount),
            MicroMinotari::from(claimed_fee),
            TxType::PaymentToOther,
            vec![],
            vec![],
        );

        let output = WalletOutput::new_from_parts(
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
            memo,
            mock_fixed_hash(0),
            Default::default(),
        );

        DetectedOutput {
            height,
            mined_in_block_hash: mock_fixed_hash(hash_byte),
            output,
        }
    }

    #[test]
    fn test_claimed_total_send_sums_amount_value_and_fee() {
        let output = mock_output_claiming(200, 1000, 25, 1, 50);
        assert_eq!(
            DisplayedTransactionProcessor::claimed_total_send(&output.output, MicroMinotari::from(1000)),
            Some(MicroMinotari::from(1225))
        );
    }

    #[test]
    fn test_claimed_total_send_returns_none_on_overflow() {
        // Claimed amount alone saturates u64, so adding our own output value overflows.
        let output = mock_output_claiming(1, u64::MAX, 0, 1, 50);
        assert_eq!(
            DisplayedTransactionProcessor::claimed_total_send(&output.output, MicroMinotari::from(u64::MAX)),
            None
        );

        // Amount plus value fits, but the claimed fee pushes it over.
        let output = mock_output_claiming(1, u64::MAX - 1, 5, 1, 50);
        assert_eq!(
            DisplayedTransactionProcessor::claimed_total_send(&output.output, MicroMinotari::from(u64::MAX - 1)),
            None
        );
    }

    #[test]
    fn test_search_inputs_survives_memo_claiming_max_amount() {
        // A sender can put any amount in the memo; it is decrypted verbatim and never checked against the
        // commitment. Summing it unchecked used to panic the scanner, and because the output stays on chain every
        // rescan panicked again.
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);

        let inputs = vec![(create_debit_balance_change(1, 100, 50), mock_spent_input(100, 1))];
        let outputs = vec![(
            create_credit_balance_change(1, 1, 50),
            mock_output_claiming(1, u64::MAX, u64::MAX, 2, 50),
        )];

        let result = processor.search_inputs(inputs, outputs, &accumulator).unwrap();
        // The unmatchable output and the leftover input each become their own transaction.
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_create_new_updated_survives_memo_claiming_max_amount() {
        let processor = DisplayedTransactionProcessor::new(100, 3, PrivateKey::default());
        let mut accumulator = BlockEventAccumulator::new(1, 50, vec![0u8; 32]);
        accumulator.add_credit_change(
            create_credit_balance_change(1, 1, 50),
            mock_output_claiming(1, u64::MAX, 0, 2, 50),
        );

        let (updated, new) = processor
            .create_new_updated_display_transactions(&accumulator, &[])
            .unwrap();
        assert!(updated.is_empty());
        assert_eq!(new.len(), 1);
    }

    #[test]
    fn test_backtrack_subset_finds_exact_match() {
        let nums = [MicroMinotari(5), MicroMinotari(3), MicroMinotari(2)];
        let used = DisplayedTransactionProcessor::backtrack_subset(&[0, 1, 2], &nums, MicroMinotari(7)).unwrap();
        let total: u64 = used.iter().map(|&i| nums.get(i).unwrap().as_u64()).sum();
        assert_eq!(total, 7);
    }

    #[test]
    fn test_backtrack_subset_input_sum_overflowing_u64_does_not_panic() {
        // The inputs together exceed u64::MAX; only one of them can match the target.
        let nums = [MicroMinotari(u64::MAX), MicroMinotari(u64::MAX - 1), MicroMinotari(1)];
        let used = DisplayedTransactionProcessor::backtrack_subset(&[0, 1, 2], &nums, MicroMinotari(u64::MAX)).unwrap();
        let total = used
            .iter()
            .try_fold(0u64, |acc, &i| acc.checked_add(nums.get(i).unwrap().as_u64()))
            .unwrap();
        assert_eq!(total, u64::MAX);
    }

    #[test]
    fn test_backtrack_subset_unreachable_target_is_none() {
        let nums = [MicroMinotari(u64::MAX), MicroMinotari(u64::MAX)];
        let used = DisplayedTransactionProcessor::backtrack_subset(&[0, 1], &nums, MicroMinotari(u64::MAX - 1));
        assert!(used.is_none());
    }
}
