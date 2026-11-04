//! UTXO selection algorithms for transaction construction.
//!
//! This module implements the input selection logic used when constructing
//! transactions. It handles the complex task of selecting appropriate UTXOs
//! to cover the desired transaction amount plus fees, while minimizing waste
//! and determining whether a change output is needed.
//!
//! # Selection Strategy
//!
//! The current implementation uses a simple accumulator strategy:
//!
//! 1. Fetch all unspent outputs for the account, ordered by value
//! 2. Accumulate outputs until the total covers amount + fees
//! 3. Calculate whether a change output is needed based on exact matching
//!
//! # Fee Calculation
//!
//! Fees are calculated based on:
//! - Transaction weight (number of inputs and outputs)
//! - Output features and scripts size
//! - Current fee per gram rate
//!
//! The selector calculates fees both with and without a change output,
//! allowing the caller to choose the optimal strategy.
//!
//! # Example
//!
//! ```rust,ignore
//! use minotari_wallet_core::transactions::input_selector::InputSelector;
//!
//! let selector = InputSelector::new(account_id);
//!
//! let selection = selector.fetch_unspent_outputs(
//!     &mut conn,
//!     MicroMinotari(1_000_000), // amount to send
//!     1,                        // number of outputs
//!     MicroMinotari(5),         // fee per gram
//!     None,                     // use default output size
//! ).await?;
//!
//! println!("Selected {} UTXOs, total: {}", selection.utxos.len(), selection.total_value);
//! println!("Fee: {}", selection.fee());
//! ```

use log::{debug, info, trace, warn};
use rusqlite::Connection;
use tari_common::configuration::Network;
use tari_common_types::types::{ComAndPubSignature, FixedHash};
use tari_transaction_components::{
    TransactionBuilderError,
    consensus::ConsensusConstantsBuilder,
    fee::Fee,
    helpers::borsh::SerializedSize,
    tari_amount::MicroMinotari,
    transaction_components::{
        MAX_TRANSACTION_INPUTS, SpentOutput, TransactionInput, TransactionInputVersion, WalletOutput,
    },
    weight::TransactionWeight,
};
use thiserror::Error;

use crate::{
    db::{DbWalletOutput, WalletDbError, get_latest_scanned_tip_block_by_account},
    log::mask_amount,
    transactions::fee_estimator::estimated_output_size_for_send,
};
use tari_transaction_components::utxo_selection::branch_and_bound::branch_bound_builder::BranchAndBoundUtxoSelectionBuilder;
/// Errors that can occur during UTXO selection.
#[derive(Debug, Error)]
pub enum UtxoSelectionError {
    /// Failed to serialize transaction components for size calculation.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// The account does not have enough funds to cover the requested amount plus fees.
    ///
    /// This error includes both the available balance and the required amount
    /// to help users understand the shortfall.
    #[error("Not enough funds. Available: {available}, required: {required}")]
    InsufficientFunds {
        /// The total value of all available UTXOs.
        available: MicroMinotari,
        /// The amount needed (transaction amount + estimated fees).
        required: MicroMinotari,
    },

    /// The account has enough funds, but some are currently pending confirmation.
    #[error("Funds are pending. Available: {available}, Pending: {pending}, Required: {required}")]
    FundsPending {
        /// The total value of currently spendable UTXOs.
        available: MicroMinotari,
        /// The value of UTXOs that are unspent but not yet confirmed enough to spend.
        pending: MicroMinotari,
        /// The amount needed.
        required: MicroMinotari,
    },

    /// The funds cover the amount and fee, but not a change output as well (a
    /// change output must be worth at least what spending it would cost).
    ///
    /// Every send must carry a change output: the wallet's block scan can only
    /// see a send land through an output the wallet owns. Sending the whole
    /// balance (or an amount that leaves nothing over) is therefore refused.
    #[error("Not enough funds for a change output: needs {shortfall} more to create a change output")]
    ChangeNotAffordable {
        /// How much more is needed, on top of what was available, to create a change output.
        shortfall: MicroMinotari,
    },

    /// The inputs the payment needs do not fit in one transaction the network
    /// will relay and mine (too many, too heavy, or too many bytes).
    #[error(
        "The payment needs {selected} inputs, more than one transaction can hold (at most {limit}). Send a smaller \
         amount, or consolidate the wallet's outputs first"
    )]
    TooManyInputs {
        /// How many inputs the selection needed.
        selected: usize,
        /// How many of them fit: the fewer of the count and weight cap and what
        /// the relay byte budget holds.
        limit: usize,
    },

    /// DB execution failed
    #[error("Database execution error: {0}")]
    DbError(#[from] WalletDbError),

    /// General service error during UTXO selection (e.g., from the selection algorithm)
    #[error("UTXO selection service error: {0}")]
    ServiceError(String),
}

/// Result of UTXO selection for a transaction.
///
/// Contains the selected UTXOs along with fee calculations and metadata
/// about whether a change output is required.
///
/// # Fee Selection
///
/// The [`fee`](Self::fee) method returns the appropriate fee based on
/// whether a change output is needed. Use `fee_without_change` when the
/// selected UTXOs exactly match the required amount, or `fee_with_change`
/// when excess value must be returned as change.
#[derive(Debug)]
pub struct UtxoSelection {
    /// The selected unspent transaction outputs.
    pub utxos: Vec<DbWalletOutput>,

    /// Whether the selection requires a change output.
    ///
    /// Always `true`: every send carries a change output, and selection
    /// leaves change worth at least the fee to spend it as an input.
    pub requires_change_output: bool,

    /// Total value of all selected UTXOs.
    pub total_value: MicroMinotari,

    /// Calculated fee assuming no change output is needed.
    pub fee_without_change: MicroMinotari,

    /// Calculated fee including a change output.
    pub fee_with_change: MicroMinotari,
}

impl UtxoSelection {
    /// Returns the appropriate fee based on whether change is required.
    ///
    /// If [`requires_change_output`](Self::requires_change_output) is `true`,
    /// returns [`fee_with_change`](Self::fee_with_change); otherwise returns
    /// [`fee_without_change`](Self::fee_without_change).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let selection = selector.fetch_unspent_outputs(...).await?;
    /// let actual_fee = selection.fee();
    /// let change_amount = selection.total_value - amount - actual_fee;
    /// ```
    pub fn fee(&self) -> MicroMinotari {
        if self.requires_change_output {
            self.fee_with_change
        } else {
            self.fee_without_change
        }
    }
}

/// Selects UTXOs for transaction inputs with fee calculation.
///
/// `InputSelector` implements the UTXO selection algorithm used when
/// constructing transactions. It queries the database for available
/// outputs and selects a minimal set sufficient to cover the desired
/// amount plus transaction fees.
///
/// # Algorithm
///
/// The selector uses a greedy accumulation strategy:
/// 1. Query all unspent outputs for the account
/// 2. Iterate through outputs, accumulating value
/// 3. For each accumulated total, calculate fees with and without change
/// 4. Stop when the total covers amount + fees
///
/// # Example
///
/// ```rust,ignore
/// use minotari_wallet_core::transactions::input_selector::InputSelector;
///
/// let selector = InputSelector::new(account_id);
///
/// let selection = selector.fetch_unspent_outputs(
///     &mut conn,
///     MicroMinotari(500_000),
///     1,
///     MicroMinotari(5),
///     None,
/// ).await?;
///
/// if selection.requires_change_output {
///     println!("Change required: {}", selection.total_value - amount - selection.fee());
/// }
/// ```
pub struct InputSelector {
    account_id: i64,
    confirmation_window: u64,
    fee_calc: Fee,
}

impl InputSelector {
    /// Creates a new `InputSelector` for the specified account.
    ///
    /// Initializes the selector with the latest transaction weight rules
    /// for fee calculation.
    ///
    /// # Arguments
    ///
    /// * `account_id` - The account ID whose UTXOs will be selected
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let selector = InputSelector::new(account_id);
    /// ```
    pub fn new(account_id: i64, confirmation_window: u64) -> Self {
        Self {
            account_id,
            confirmation_window,
            fee_calc: Fee::new(TransactionWeight::latest()),
        }
    }

    /// Fetches and selects UTXOs sufficient to cover the requested amount plus fees.
    ///
    /// This method queries the database for unspent outputs and accumulates them
    /// until the total value covers the requested amount plus calculated transaction
    /// fees. It determines whether a change output is needed and calculates fees
    /// for both scenarios.
    ///
    /// # Arguments
    ///
    /// * `conn` - Database connection for querying UTXOs
    /// * `amount` - The amount to be sent (excluding fees)
    /// * `num_outputs` - Number of transaction outputs (recipient outputs, excluding change)
    /// * `fee_per_gram` - Fee rate in MicroMinotari per gram of transaction weight
    /// * `estimated_output_size` - Optional custom output size for fee calculation;
    ///   if `None`, uses default calculation from [`get_features_and_scripts_byte_size`](Self::get_features_and_scripts_byte_size)
    ///
    /// # Returns
    ///
    /// Returns a [`UtxoSelection`] containing:
    /// - The selected UTXOs
    /// - Whether a change output is required
    /// - Total value of selected UTXOs
    /// - Fee calculations with and without change
    ///
    /// # Errors
    ///
    /// Returns [`UtxoSelectionError::InsufficientFunds`] if the account balance
    /// cannot cover the requested amount plus fees.
    ///
    /// Returns [`UtxoSelectionError::DbError`] if the database query fails.
    ///
    /// Returns [`UtxoSelectionError::SerializationError`] if output size
    /// calculation fails (when `estimated_output_size` is `None`).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let selector = InputSelector::new(account_id);
    ///
    /// let selection = selector.fetch_unspent_outputs(
    ///     &mut conn,
    ///     MicroMinotari(1_000_000),
    ///     1,  // one recipient
    ///     MicroMinotari(5),
    ///     None,
    /// ).await?;
    ///
    /// // Calculate change amount if needed
    /// if selection.requires_change_output {
    ///     let change = selection.total_value - amount - selection.fee_with_change;
    ///     println!("Change: {}", change);
    /// }
    /// ```
    pub fn fetch_unspent_outputs(
        &self,
        conn: &Connection,
        amount: MicroMinotari,
        num_outputs: usize,
        fee_per_gram: MicroMinotari,
        estimated_output_size: Option<usize>,
    ) -> Result<UtxoSelection, UtxoSelectionError> {
        debug!(
            account_id = self.account_id,
            amount = &*mask_amount(amount);
            "Selecting UTXOs"
        );
        let tip_height = get_latest_scanned_tip_block_by_account(conn, self.account_id)?
            .map(|b| b.height)
            .unwrap_or(0);
        let min_height = tip_height.saturating_sub(self.confirmation_window);
        let totals = crate::db::get_output_totals_for_account(conn, self.account_id, tip_height)?;
        // `totals.available` is the disjoint spendable bucket (confirmed, mature, unspent, not locked).
        // `totals.unavailable` is locked + unconfirmed + immature — funds that exist but cannot be spent yet.
        let available_balance = totals.available;
        let pending = totals.unavailable;
        let total_including_pending = available_balance.saturating_add(pending);
        if available_balance <= amount && total_including_pending >= amount {
            warn!(
                target: "audit",
                available = &*mask_amount(available_balance),
                pending = &*mask_amount(pending),
                required = &*mask_amount(amount);
                "Insufficient funds for transaction (pending confirmations or maturity)"
            );
            return Err(UtxoSelectionError::FundsPending {
                available: available_balance,
                pending,
                required: amount,
            });
        }
        let uo = crate::db::fetch_unspent_outputs(conn, self.account_id, min_height, tip_height)?;

        let features_and_scripts_byte_size = match estimated_output_size {
            Some(sz) => sz,
            None => {
                estimated_output_size_for_send(0, num_outputs, &tari_common_types::tari_address::TariAddress::default())
                    .map_err(|err| UtxoSelectionError::SerializationError(err.to_string()))?
            },
        };

        let kernel_fee = self.fee_calc.calculate(fee_per_gram, 1, 0, 0, 0);
        let default_output_fee = self
            .fee_calc
            .calculate(fee_per_gram, 0, 0, 1, features_and_scripts_byte_size);
        // Every recipient output carries its own features and scripts.
        let outputs_byte_size = features_and_scripts_byte_size.checked_mul(num_outputs).ok_or_else(|| {
            UtxoSelectionError::ServiceError("Total output size overflows while selecting inputs".to_string())
        })?;
        let output_fee = self
            .fee_calc
            .calculate(fee_per_gram, 0, 0, num_outputs, outputs_byte_size);
        let input_fee = self.fee_calc.calculate(fee_per_gram, 0, 1, 0, 0);

        // Every send must carry a change output, so the change output's fee is
        // charged as one of the outputs, and the target is the amount plus the
        // smallest change worth keeping: what it costs to spend that change as an
        // input later (at least 1 µT), so the change is never dust. Whatever the
        // selector picks then leaves at least that much change after every fee.
        // The builder refuses (`with_change_required`) a transaction without
        // change, which it only does with less than 1 µT left, so it agrees. An
        // amount so large that the target overflows can never be funded.
        let min_change = self.min_change(fee_per_gram);
        let target_amount = amount
            .checked_add(kernel_fee)
            .and_then(|target| target.checked_add(min_change))
            .ok_or(UtxoSelectionError::InsufficientFunds {
                available: available_balance,
                required: amount.saturating_add(kernel_fee),
            })?;
        let total_output_fee = output_fee.checked_add(default_output_fee).ok_or_else(|| {
            UtxoSelectionError::ServiceError("Output fee plus change output fee overflows".to_string())
        })?;
        let bnb = BranchAndBoundUtxoSelectionBuilder::new(uo.clone())
            .with_target_amount(target_amount)
            .with_fee_per_input(input_fee)
            .with_total_output_fee(total_output_fee)
            .with_change_fee(MicroMinotari(0))
            .build()
            .map_err(|e| UtxoSelectionError::ServiceError(e.to_string()))?;

        let Some(selection) = bnb.search() else {
            // Tell "cannot afford the change output" apart from plain
            // insufficient funds: search again without the change requirement.
            let without_change = BranchAndBoundUtxoSelectionBuilder::new(uo)
                // Cannot overflow: `target_amount` above is larger.
                .with_target_amount(amount.saturating_add(kernel_fee))
                .with_fee_per_input(input_fee)
                .with_total_output_fee(output_fee)
                .with_change_fee(default_output_fee)
                .build()
                .map_err(|e| UtxoSelectionError::ServiceError(e.to_string()))?;
            if let Some(selection) = without_change.search() {
                let needed = selection
                    .final_target
                    .saturating_add(default_output_fee)
                    .saturating_add(min_change);
                let shortfall = needed.saturating_sub(selection.current_value);
                warn!(
                    target: "audit",
                    available = &*mask_amount(available_balance),
                    required = &*mask_amount(amount),
                    shortfall = &*mask_amount(shortfall);
                    "Insufficient funds for a change output"
                );
                return Err(UtxoSelectionError::ChangeNotAffordable { shortfall });
            }

            warn!(
                target: "audit",
                available = &*mask_amount(available_balance),
                required = &*mask_amount(amount);
                "Insufficient funds for transaction"
            );
            // the total is not enough to cover fees. So we just need to notify the user its not enough so we add 1 to it.
            return Err(UtxoSelectionError::InsufficientFunds {
                available: available_balance,
                required: amount.saturating_add(MicroMinotari(1)),
            });
        };
        let selected_amount = selection.current_value;
        let requires_change_output = true;
        // Computed rather than taken from `selection.final_fee`, which also
        // counts any dust the selector chose to burn; that dust becomes change.
        let fee_with_change = u64::try_from(selection.selected_utxos.len())
            .ok()
            .and_then(|count| input_fee.as_u64().checked_mul(count))
            .map(MicroMinotari)
            .and_then(|inputs_fee| inputs_fee.checked_add(kernel_fee))
            .and_then(|fee| fee.checked_add(total_output_fee))
            .ok_or_else(|| UtxoSelectionError::ServiceError("Transaction fee overflows".to_string()))?;
        let fee_without_change = fee_with_change.saturating_sub(default_output_fee);
        let utxos = selection.selected_utxos;
        // Charged per output as above: the recipients and the change.
        let total_outputs = num_outputs.saturating_add(1);
        let outputs_size = features_and_scripts_byte_size.saturating_mul(total_outputs);
        check_input_limits(
            &utxos,
            max_transaction_inputs(STRICTEST_NETWORK, total_outputs, outputs_size),
            input_body_byte_budget(total_outputs),
        )?;

        debug!(
            count = utxos.len(),
            total = &*mask_amount(selected_amount),
            change = requires_change_output;
            "UTXOs selected"
        );

        Ok(UtxoSelection {
            utxos,
            requires_change_output,
            total_value: selected_amount,
            fee_without_change,
            fee_with_change,
        })
    }

    /// The smallest change worth keeping: what spending it as an input later
    /// costs, and at least 1 µT. An output worth no more than this is dust.
    pub fn min_change(&self, fee_per_gram: MicroMinotari) -> MicroMinotari {
        self.fee_calc.calculate(fee_per_gram, 0, 1, 0, 0).max(MicroMinotari(1))
    }

    /// The fees, without and with the change output, of a send-all spending
    /// `input_count` inputs to one recipient output, given the exact sizes the
    /// builder charges (see
    /// [`one_sided_output_sizes`](crate::transactions::fee_estimator::one_sided_output_sizes)).
    pub fn send_all_fees(
        &self,
        input_count: usize,
        fee_per_gram: MicroMinotari,
        recipient_output_size: usize,
        change_output_size: usize,
    ) -> Result<(MicroMinotari, MicroMinotari), UtxoSelectionError> {
        let outputs_size = recipient_output_size
            .checked_add(change_output_size)
            .ok_or_else(|| UtxoSelectionError::ServiceError("Total output size overflows".to_string()))?;
        let fee_without_change = self
            .fee_calc
            .calculate(fee_per_gram, 1, input_count, 1, recipient_output_size);
        let fee_with_change = self.fee_calc.calculate(fee_per_gram, 1, input_count, 2, outputs_size);
        Ok((fee_without_change, fee_with_change))
    }

    /// What a send-all pays its recipient: everything selected less the fee
    /// with change and the minimum change.
    ///
    /// Every send carries a change output (the upstream offline signer sets
    /// `with_change_required` and refuses to sign without one), so a send-all
    /// keeps the minimum change rather than sweeping to zero. Fails when what
    /// is left for the recipient would be dust.
    pub fn send_all_amount(
        &self,
        total_value: MicroMinotari,
        fee_with_change: MicroMinotari,
        fee_per_gram: MicroMinotari,
    ) -> Result<MicroMinotari, UtxoSelectionError> {
        let min_change = self.min_change(fee_per_gram);
        let kept = fee_with_change.saturating_add(min_change);
        let amount = total_value.saturating_sub(kept);
        if amount <= min_change {
            return Err(UtxoSelectionError::InsufficientFunds {
                available: total_value,
                required: kept.saturating_add(min_change).saturating_add(MicroMinotari(1)),
            });
        }
        Ok(amount)
    }

    /// Records what the send-all holding `reservation_id` is about to pay, once
    /// its amount is known.
    pub fn audit_send_all(&self, reservation_id: &str, amount: MicroMinotari, fee: MicroMinotari, input_count: usize) {
        info!(
            target: "audit",
            account_id = self.account_id,
            amount = &*mask_amount(amount),
            fee = &*mask_amount(fee),
            input_count = input_count;
            "Send-all amount worked out"
        );
        trace!(target: "audit", reservation_id = reservation_id; "Send-all reservation");
    }

    /// Selects the spendable, unlocked outputs for a send-all to one recipient.
    ///
    /// Outputs worth no more than they cost to spend are skipped, and at most
    /// [`max_send_all_inputs`] are taken, largest first, and only as many as
    /// fit the base node's relay byte budget: more could not be signed, relayed
    /// or mined. A send-all over a wallet with more outputs than that is
    /// a partial sweep of its largest ones and can be repeated for the rest.
    /// Spending them together links them on chain.
    ///
    /// The fees are for the selected outputs, one recipient output and the
    /// change output. Fails when the recipient's share would be dust (see
    /// [`send_all_amount`](Self::send_all_amount)).
    pub fn select_all(
        &self,
        conn: &Connection,
        network: Network,
        fee_per_gram: MicroMinotari,
        recipient_output_size: usize,
        change_output_size: usize,
    ) -> Result<SendAllSelection, UtxoSelectionError> {
        self.select_all_up_to(
            conn,
            fee_per_gram,
            recipient_output_size,
            change_output_size,
            max_send_all_inputs(network, recipient_output_size, change_output_size),
        )
    }

    fn select_all_up_to(
        &self,
        conn: &Connection,
        fee_per_gram: MicroMinotari,
        recipient_output_size: usize,
        change_output_size: usize,
        max_inputs: usize,
    ) -> Result<SendAllSelection, UtxoSelectionError> {
        let tip_height = get_latest_scanned_tip_block_by_account(conn, self.account_id)?
            .map(|b| b.height)
            .unwrap_or(0);
        let min_height = tip_height.saturating_sub(self.confirmation_window);
        let spend_cost = self.min_change(fee_per_gram);
        let spendable = crate::db::fetch_unspent_outputs(conn, self.account_id, min_height, tip_height)?;
        let spendable_count = spendable.len();
        let mut candidates: Vec<DbWalletOutput> = spendable
            .into_iter()
            .filter(|utxo| utxo.output.value() > spend_cost)
            .collect();
        let skipped_dust = spendable_count.saturating_sub(candidates.len());
        candidates.sort_by_key(|utxo| std::cmp::Reverse(utxo.output.value()));
        let candidate_count = candidates.len();
        let utxos = take_inputs_within_limits(candidates, max_inputs, input_body_byte_budget(2))?;
        let skipped_over_cap = candidate_count.saturating_sub(utxos.len());

        let mut total_value = MicroMinotari::zero();
        for utxo in &utxos {
            total_value = total_value
                .checked_add(utxo.output.value())
                .ok_or_else(|| UtxoSelectionError::ServiceError("Total value of the outputs overflows".to_string()))?;
        }
        let (fee_without_change, fee_with_change) =
            self.send_all_fees(utxos.len(), fee_per_gram, recipient_output_size, change_output_size)?;
        self.send_all_amount(total_value, fee_with_change, fee_per_gram)?;

        debug!(
            count = utxos.len(),
            total = &*mask_amount(total_value);
            "All spendable UTXOs selected"
        );

        Ok(SendAllSelection {
            selection: UtxoSelection {
                utxos,
                requires_change_output: true,
                total_value,
                fee_without_change,
                fee_with_change,
            },
            skipped_dust,
            skipped_over_cap,
        })
    }
}

/// What [`InputSelector::select_all`] spends, and how many spendable outputs it
/// leaves behind.
#[derive(Debug)]
pub struct SendAllSelection {
    /// The outputs spent, with the send-all's fees.
    pub selection: UtxoSelection,
    /// Spendable outputs left out for being worth no more than they cost to spend.
    pub skipped_dust: usize,
    /// Spendable outputs left out for not fitting the count, weight or byte cap.
    pub skipped_over_cap: usize,
}

impl SendAllSelection {
    /// Warns on the audit target when the send-all leaves spendable outputs
    /// behind, so a partial sweep is never silent.
    pub fn audit_if_partial(&self, account_id: i64) {
        if self.skipped_dust > 0 || self.skipped_over_cap > 0 {
            warn!(
                target: "audit",
                account_id = account_id,
                spent = self.selection.utxos.len(),
                skipped_dust = self.skipped_dust,
                skipped_over_cap = self.skipped_over_cap;
                "Send-all leaves spendable outputs behind"
            );
        }
    }
}

/// The most inputs a send-all to one recipient may spend on `network`.
///
/// Bound by what a block can hold (the kernel, the recipient and change
/// outputs and the inputs must fit in `max_block_transaction_weight`, which
/// neither the builder nor the signer checks) and by
/// [`MAX_TRANSACTION_INPUTS`], which the signer does. Selection also keeps
/// the inputs within the relay byte budget, which may allow fewer.
pub fn max_send_all_inputs(network: Network, recipient_output_size: usize, change_output_size: usize) -> usize {
    max_transaction_inputs(network, 2, recipient_output_size.saturating_add(change_output_size))
}

/// The most inputs a transaction with `num_outputs` outputs, whose features
/// and scripts total `outputs_size`, may spend on `network`: as many as still
/// fit in `max_block_transaction_weight` next to the kernel and the outputs,
/// and no more than [`MAX_TRANSACTION_INPUTS`].
pub fn max_transaction_inputs(network: Network, num_outputs: usize, outputs_size: usize) -> usize {
    let constants = ConsensusConstantsBuilder::new(network).build();
    let weight = constants.transaction_weight_params();
    let fixed_weight = weight.calculate(1, 0, num_outputs, outputs_size);
    let by_weight = constants
        .max_block_transaction_weight()
        .saturating_sub(fixed_weight)
        .checked_div(weight.params().input_weight)
        .unwrap_or(0);
    usize::try_from(by_weight)
        .unwrap_or(usize::MAX)
        .min(MAX_TRANSACTION_INPUTS)
}

/// The network with the smallest block weight. Exact sends are bounded by it,
/// so the bound holds on every network without the selector knowing which.
const STRICTEST_NETWORK: Network = Network::MainNet;

/// The largest transaction body, borsh-serialized with hydrated inputs, a base
/// node relays: tari's `MAX_BLOCK_TEMPLATE_BODY_BYTES` (base_layer/core
/// mempool, checked by `check_body_size`), 5 MiB. Larger is never mined.
const MAX_RELAYED_BODY_BYTES: usize = 5 * 1024 * 1024;

/// Room kept in that budget per output. An output with its range proof and a
/// full memo serializes to well under this.
const BODY_BYTES_PER_OUTPUT: usize = 2 * 1024;

/// Room kept for the kernel, the encoding and headroom.
const BODY_BYTES_MARGIN: usize = 64 * 1024;

/// The body bytes left for the inputs of a transaction with `num_outputs` outputs.
fn input_body_byte_budget(num_outputs: usize) -> usize {
    MAX_RELAYED_BODY_BYTES
        .saturating_sub(BODY_BYTES_PER_OUTPUT.saturating_mul(num_outputs))
        .saturating_sub(BODY_BYTES_MARGIN)
}

/// The serialized size `output` will have as a hydrated transaction input.
///
/// The commitment, range proof hash and script signature are fixed-size, so
/// placeholders measure the same as the values the signer fills in.
pub fn hydrated_input_size(output: &WalletOutput) -> Result<usize, UtxoSelectionError> {
    let input = TransactionInput::new(
        TransactionInputVersion::get_current_version(),
        SpentOutput::OutputData {
            version: output.version(),
            features: output.features().clone(),
            commitment: output.commitment().clone(),
            script: output.script().clone(),
            sender_offset_public_key: output.sender_offset_public_key().clone(),
            covenant: output.covenant().clone(),
            encrypted_data: output.encrypted_data().clone(),
            metadata_signature: output.metadata_signature().clone(),
            rangeproof_hash: FixedHash::zero(),
            minimum_value_promise: output.minimum_value_promise(),
        },
        output.input_data().clone(),
        ComAndPubSignature::default(),
    );
    input
        .get_serialized_size()
        .map_err(|e| UtxoSelectionError::SerializationError(e.to_string()))
}

/// Takes `candidates` in order while there are fewer than `max_inputs` and
/// their hydrated size stays within `byte_budget`.
fn take_inputs_within_limits(
    candidates: Vec<DbWalletOutput>,
    max_inputs: usize,
    byte_budget: usize,
) -> Result<Vec<DbWalletOutput>, UtxoSelectionError> {
    let mut taken = Vec::new();
    let mut body_bytes = 0usize;
    for utxo in candidates {
        if taken.len() >= max_inputs {
            break;
        }
        let next = body_bytes.saturating_add(hydrated_input_size(&utxo.output)?);
        if next > byte_budget {
            break;
        }
        body_bytes = next;
        taken.push(utxo);
    }
    Ok(taken)
}

/// Fails with [`UtxoSelectionError::TooManyInputs`] when `utxos` are more than
/// `max_inputs` or their hydrated size is over `byte_budget`, naming how many
/// of them do fit.
fn check_input_limits(
    utxos: &[DbWalletOutput],
    max_inputs: usize,
    byte_budget: usize,
) -> Result<(), UtxoSelectionError> {
    let fitting = take_inputs_within_limits(utxos.to_vec(), max_inputs, byte_budget)?.len();
    if fitting < utxos.len() {
        warn!(
            target: "audit",
            selected = utxos.len(),
            limit = fitting;
            "Selected inputs do not fit in one transaction"
        );
        return Err(UtxoSelectionError::TooManyInputs {
            selected: utxos.len(),
            limit: fitting,
        });
    }
    Ok(())
}

/// Turns the transaction builder's refusal to build a transaction without a
/// change output into [`UtxoSelectionError::ChangeNotAffordable`].
///
/// Input selection already makes room for a change output, so this is a
/// backstop for when the builder's fee estimate comes out higher than the
/// selector's. Any other builder error is passed through unchanged.
pub fn map_change_required_error(error: TransactionBuilderError) -> anyhow::Error {
    match error {
        TransactionBuilderError::OfflineTransactionRequiresChange { remainder, change_fee } => {
            // The builder creates change only when `remainder - change_fee >= 1`.
            let shortfall = change_fee.saturating_add(MicroMinotari(1)).saturating_sub(remainder);
            UtxoSelectionError::ChangeNotAffordable { shortfall }.into()
        },
        other => other.into(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_wrap)]

    use super::*;
    use crate::db::{SqlitePool, create_account, get_account_by_name, init_db, insert_scanned_tip_block};
    use chrono::Utc;
    use rusqlite::named_params;
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_common_types::types::{ComAndPubSignature, CompressedPublicKey, FixedHash};
    use tari_script::{ExecutionStack, TariScript};
    use tari_transaction_components::key_manager::TariKeyId;
    use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
    use tari_transaction_components::transaction_components::{
        EncryptedData, MemoField, OutputFeatures, TransactionOutputVersion, WalletOutput, covenants::Covenant,
    };
    use tempfile::TempDir;

    fn test_wallet_output(value: u64, hash_seed: u8) -> WalletOutput {
        let hash = FixedHash::from([hash_seed; 32]);
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
            hash,
            Default::default(),
        )
    }

    /// An account holding one confirmed, spendable output of `value`.
    fn account_with_one_output(value: u64) -> (SqlitePool, i64, TempDir) {
        account_with_outputs(&[value])
    }

    /// An account holding a confirmed, spendable output of each of `values`.
    fn account_with_outputs(values: &[u64]) -> (SqlitePool, i64, TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let pool = init_db(dir.path().join("selector.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
        create_account(&conn, "default", &wallet, "password").unwrap();
        let account_id = get_account_by_name(&conn, "default").unwrap().unwrap().id;
        insert_scanned_tip_block(&conn, account_id, 200, &[0u8; 32]).expect("tip");

        for (i, value) in values.iter().enumerate() {
            let seed = u8::try_from(i + 1).expect("few outputs");
            let output = test_wallet_output(*value, seed);
            conn.execute(
                r#"
                INSERT INTO outputs (
                    account_id, tx_id, output_hash, mined_in_block_height, mined_in_block_hash,
                    value, mined_timestamp, wallet_output_json, status, confirmed_height,
                    confirmed_hash, is_burn, maturity
                ) VALUES (
                    :account_id, :tx_id, :hash, 100, :hash, :value, :ts, :json, 'UNSPENT', 100, :hash, 0, 0
                )
                "#,
                named_params! {
                    ":account_id": account_id,
                    ":tx_id": i64::from(seed),
                    ":hash": vec![seed; 32],
                    ":value": *value as i64,
                    ":ts": Utc::now(),
                    ":json": serde_json::to_string(&output).unwrap(),
                },
            )
            .expect("insert output");
        }
        drop(conn);
        (pool, account_id, dir)
    }

    fn select(pool: &SqlitePool, account_id: i64, amount: u64) -> Result<UtxoSelection, UtxoSelectionError> {
        let conn = pool.get().expect("conn");
        InputSelector::new(account_id, 100).fetch_unspent_outputs(
            &conn,
            MicroMinotari(amount),
            1,
            MicroMinotari(5),
            Some(1000),
        )
    }

    #[test]
    fn an_amount_that_overflows_with_the_kernel_fee_is_insufficient_funds() {
        let temp_dir = tempfile::tempdir().unwrap();
        let pool = crate::db::init_db(temp_dir.path().join("input_selector.db")).unwrap();
        let conn = pool.get().unwrap();
        let selector = InputSelector::new(1, 3);

        let result = selector.fetch_unspent_outputs(&conn, MicroMinotari(u64::MAX), 1, MicroMinotari(5), Some(100));

        match result {
            Err(UtxoSelectionError::InsufficientFunds { available, required }) => {
                assert_eq!(available, MicroMinotari(0));
                assert_eq!(required, MicroMinotari(u64::MAX));
            },
            other => panic!("expected InsufficientFunds, got {other:?}"),
        }
    }

    #[test]
    fn a_send_that_leaves_no_room_for_change_fails_with_a_typed_error() {
        let value = 1_000_000;
        let (pool, account_id, _dir) = account_with_one_output(value);

        // Walk the amount down from the whole balance. The first amount that
        // covers the fee must be refused because it cannot also pay for a
        // change output, not accepted without one.
        let mut amount = value - 1;
        let shortfall = loop {
            match select(&pool, account_id, amount) {
                Err(UtxoSelectionError::InsufficientFunds { .. }) => amount -= 1,
                Err(UtxoSelectionError::ChangeNotAffordable { shortfall }) => break shortfall,
                Err(e) => panic!("unexpected error: {e}"),
                Ok(selection) => panic!("selected without room for change: {selection:?}"),
            }
        };
        assert!(
            shortfall > MicroMinotari(0),
            "the shortfall must say how much more is needed"
        );
        let message = UtxoSelectionError::ChangeNotAffordable { shortfall }.to_string();
        assert!(message.contains("change output"), "got: {message}");

        // Sending `shortfall` less leaves exactly enough for a change output.
        let selection = select(&pool, account_id, amount - shortfall.as_u64()).expect("affordable with change");
        assert!(selection.requires_change_output);
        let change = selection.total_value - MicroMinotari(amount - shortfall.as_u64()) - selection.fee_with_change;
        let input_fee = Fee::new(TransactionWeight::latest()).calculate(MicroMinotari(5), 0, 1, 0, 0);
        assert!(input_fee > MicroMinotari(1));
        assert!(
            change >= input_fee,
            "change must be worth at least the {input_fee} it costs to spend, got {change}"
        );
    }

    #[test]
    fn a_send_all_takes_everything_but_the_fee_and_the_minimum_change() {
        let (pool, account_id, _dir) = account_with_one_output(1_000_000);
        let conn = pool.get().expect("conn");
        let selector = InputSelector::new(account_id, 100);
        let selection = selector
            .select_all(&conn, Network::LocalNet, MicroMinotari(5), 1000, 1000)
            .expect("selection")
            .selection;
        assert_eq!(selection.utxos.len(), 1);
        assert_eq!(selection.total_value, MicroMinotari(1_000_000));
        // Charged as the regular selector charges one recipient and change.
        let fee = Fee::new(TransactionWeight::latest()).calculate(MicroMinotari(5), 1, 1, 2, 2000);
        assert_eq!(selection.fee_with_change, fee);

        let amount = selector
            .send_all_amount(selection.total_value, selection.fee_with_change, MicroMinotari(5))
            .expect("amount");
        let min_change = selector.min_change(MicroMinotari(5));
        assert_eq!(amount, MicroMinotari(1_000_000) - fee - min_change);
    }

    /// Outputs worth no more than they cost to spend are left out of a send-all.
    #[test]
    fn a_send_all_skips_dust_inputs() {
        let selector = InputSelector::new(1, 100);
        let spend_cost = selector.min_change(MicroMinotari(5));
        let (pool, account_id, _dir) =
            account_with_outputs(&[300_000, spend_cost.as_u64(), 1_000_000, spend_cost.as_u64() + 1]);
        let conn = pool.get().expect("conn");
        let all = InputSelector::new(account_id, 100)
            .select_all(&conn, Network::LocalNet, MicroMinotari(5), 1000, 1000)
            .expect("selection");
        assert_eq!((all.skipped_dust, all.skipped_over_cap), (1, 0));
        let selection = all.selection;
        let values: Vec<u64> = selection.utxos.iter().map(|u| u.output.value().as_u64()).collect();
        assert_eq!(values, vec![1_000_000, 300_000, spend_cost.as_u64() + 1]);
        assert_eq!(
            selection.total_value,
            MicroMinotari(1_300_000) + spend_cost + MicroMinotari(1)
        );
        let (_, fee) = selector.send_all_fees(3, MicroMinotari(5), 1000, 1000).expect("fees");
        assert_eq!(selection.fee_with_change, fee);
    }

    /// A send-all takes at most the input cap, largest outputs first, and says
    /// how many it left behind.
    #[test]
    fn a_send_all_takes_the_largest_inputs_up_to_the_cap() {
        let (pool, account_id, _dir) = account_with_outputs(&[200_000, 900_000, 500_000, 700_000, 1]);
        let conn = pool.get().expect("conn");
        let all = InputSelector::new(account_id, 100)
            .select_all_up_to(&conn, MicroMinotari(5), 1000, 1000, 2)
            .expect("selection");
        assert_eq!((all.skipped_dust, all.skipped_over_cap), (1, 2));
        let selection = all.selection;
        let values: Vec<u64> = selection.utxos.iter().map(|u| u.output.value().as_u64()).collect();
        assert_eq!(values, vec![900_000, 700_000]);
        assert_eq!(selection.total_value, MicroMinotari(1_600_000));
    }

    /// On mainnet a block holds fewer inputs than a transaction may carry, so
    /// the send-all cap is the block weight's: exactly as many as still fit.
    #[test]
    fn the_send_all_input_cap_is_bound_by_mainnet_block_weight() {
        let (recipient_size, change_size) = (128, 256);
        let cap = max_send_all_inputs(Network::MainNet, recipient_size, change_size);
        assert!(cap < MAX_TRANSACTION_INPUTS, "cap {cap}");

        let constants = ConsensusConstantsBuilder::new(Network::MainNet).build();
        let weight = |inputs| {
            constants
                .transaction_weight_params()
                .calculate(1, inputs, 2, recipient_size + change_size)
        };
        assert!(weight(cap) <= constants.max_block_transaction_weight());
        assert!(weight(cap + 1) > constants.max_block_transaction_weight());
    }

    fn db_output(id: i64, value: u64) -> DbWalletOutput {
        DbWalletOutput {
            id,
            tx_id: tari_common_types::transaction::TxId::from(id as u64),
            output: test_wallet_output(value, 1),
        }
    }

    /// The relay byte budget binds before the mainnet weight cap: a send-all
    /// takes as many inputs as fit in it, and its body stays within it.
    #[test]
    fn the_send_all_input_cap_is_bound_by_the_relay_byte_budget() {
        let per_input = hydrated_input_size(&test_wallet_output(1_000, 1)).unwrap();
        let budget = input_body_byte_budget(2);
        let byte_cap = budget / per_input;
        let weight_cap = max_send_all_inputs(Network::MainNet, 128, 256);
        assert!(byte_cap < weight_cap, "byte cap {byte_cap}, weight cap {weight_cap}");

        let candidates: Vec<DbWalletOutput> = (0..weight_cap as i64).map(|id| db_output(id, 1_000)).collect();
        let taken = take_inputs_within_limits(candidates, weight_cap, budget).unwrap();
        assert_eq!(taken.len(), byte_cap);
        // The inputs, the two outputs and the kernel are within what a base node relays.
        assert!(taken.len() * per_input + 2 * BODY_BYTES_PER_OUTPUT + BODY_BYTES_MARGIN <= MAX_RELAYED_BODY_BYTES);
    }

    /// An exact send whose inputs do not fit one transaction is refused with a
    /// typed error; one within the limits is untouched.
    #[test]
    fn an_exact_send_over_the_input_limits_is_refused() {
        let utxos = vec![db_output(1, 1_000), db_output(2, 1_000), db_output(3, 1_000)];
        let per_input = hydrated_input_size(&test_wallet_output(1_000, 1)).unwrap();
        check_input_limits(&utxos, 3, 3 * per_input).expect("within the limits");
        // Over the count cap: the cap is what fits.
        match check_input_limits(&utxos, 2, 3 * per_input) {
            Err(UtxoSelectionError::TooManyInputs { selected: 3, limit: 2 }) => {},
            other => panic!("expected TooManyInputs, got {other:?}"),
        }
        // Over the byte budget, under the count cap: the budget is what fits, not the cap.
        match check_input_limits(&utxos, 10, 2 * per_input + 1) {
            Err(UtxoSelectionError::TooManyInputs { selected, limit }) => {
                assert_eq!((selected, limit), (3, 2));
                assert!(limit < selected);
            },
            other => panic!("expected TooManyInputs, got {other:?}"),
        }
        // More outputs leave room for fewer inputs.
        assert!(
            max_transaction_inputs(Network::MainNet, 500, 500 * 128) < max_transaction_inputs(Network::MainNet, 2, 256)
        );
        assert!(input_body_byte_budget(500) < input_body_byte_budget(2));
    }

    #[test]
    fn a_send_all_of_dust_is_refused() {
        let selector = InputSelector::new(1, 100);
        let min_change = selector.min_change(MicroMinotari(5));
        let (_, fee) = selector.send_all_fees(1, MicroMinotari(5), 1000, 1000).expect("fees");
        // Leaves exactly the dust threshold for the recipient.
        let total = fee + min_change + min_change;
        assert!(matches!(
            selector.send_all_amount(total, fee, MicroMinotari(5)),
            Err(UtxoSelectionError::InsufficientFunds { .. })
        ));
        assert_eq!(
            selector
                .send_all_amount(total + MicroMinotari(1), fee, MicroMinotari(5))
                .expect("amount"),
            min_change + MicroMinotari(1)
        );

        // Nothing to spend at all.
        let dir = tempfile::tempdir().expect("temp dir");
        let pool = init_db(dir.path().join("empty.db")).expect("init db");
        let conn = pool.get().expect("conn");
        assert!(matches!(
            selector.select_all(&conn, Network::LocalNet, MicroMinotari(5), 1000, 1000),
            Err(UtxoSelectionError::InsufficientFunds { .. })
        ));
    }

    #[test]
    fn every_selection_requires_a_change_output() {
        let (pool, account_id, _dir) = account_with_one_output(1_000_000);
        let selection = select(&pool, account_id, 10_000).expect("selection");
        assert!(selection.requires_change_output);
        assert_eq!(selection.fee(), selection.fee_with_change);
    }

    #[test]
    fn the_builder_refusing_to_build_without_change_maps_to_the_typed_error() {
        let error = map_change_required_error(TransactionBuilderError::OfflineTransactionRequiresChange {
            remainder: MicroMinotari(40),
            change_fee: MicroMinotari(100),
        });
        match error.downcast_ref::<UtxoSelectionError>() {
            Some(UtxoSelectionError::ChangeNotAffordable { shortfall }) => assert_eq!(*shortfall, MicroMinotari(61)),
            other => panic!("expected ChangeNotAffordable, got {other:?}"),
        }

        let other = map_change_required_error(TransactionBuilderError::MultipleBurnCommitments);
        assert!(other.downcast_ref::<UtxoSelectionError>().is_none());
    }

    #[test]
    fn a_builder_refusing_a_send_without_change_surfaces_as_change_not_affordable() {
        use tari_common::configuration::Network;
        use tari_common_types::tari_address::{TariAddress, TariAddressFeatures};
        use tari_common_types::types::PrivateKey;
        use tari_transaction_components::TransactionBuilder;
        use tari_transaction_components::consensus::ConsensusConstantsBuilder;
        use tari_transaction_components::key_manager::KeyManager;

        let value = 1_000_000;
        let recipient = TariAddress::new_dual_address(
            CompressedPublicKey::from_secret_key(&PrivateKey::from(7u64)),
            CompressedPublicKey::from_secret_key(&PrivateKey::from(9u64)),
            Network::LocalNet,
            TariAddressFeatures::create_one_sided_only(),
            None,
        )
        .expect("address");

        // Walk the amount down from the whole input, 100 µT at a time (well under
        // the fee of a change output), until the builder no longer says it is
        // spending more than it has: that amount leaves no room for change, and
        // with change required the builder refuses it.
        let key_manager = KeyManager::new_random().expect("key manager");
        let mut amount = value;
        let error = loop {
            let consensus_constants = ConsensusConstantsBuilder::new(Network::LocalNet).build();
            let mut builder =
                TransactionBuilder::new(consensus_constants, key_manager.clone(), Network::LocalNet).expect("builder");
            builder.with_fee_per_gram(MicroMinotari(5));
            builder.with_change_required();
            builder.with_input(test_wallet_output(value, 1)).expect("input");
            builder
                .add_stealth_recipient(
                    recipient.clone(),
                    MicroMinotari(amount),
                    OutputFeatures::default(),
                    MemoField::new_empty(),
                )
                .expect("recipient");
            match builder.reserve_sender_offset_keys(&[]) {
                Err(TransactionBuilderError::SpendingMoreThanAvailable { .. }) => amount -= 100,
                Err(e) => break e,
                Ok(_) => panic!("the builder accepted a send without change at {amount}"),
            }
        };
        assert!(
            matches!(error, TransactionBuilderError::OfflineTransactionRequiresChange { .. }),
            "got: {error}"
        );

        let mapped = map_change_required_error(error);
        match mapped.downcast_ref::<UtxoSelectionError>() {
            Some(UtxoSelectionError::ChangeNotAffordable { shortfall }) => assert!(*shortfall > MicroMinotari(0)),
            other => panic!("expected ChangeNotAffordable, got {other:?}"),
        }
    }

    /// Every place that builds a transaction must require a change output, and
    /// every builder call that can refuse a transaction for lack of change must
    /// map that refusal to `ChangeNotAffordable`. A new site that forgets either
    /// is caught here.
    #[test]
    fn every_transaction_builder_site_requires_change_and_maps_the_refusal() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let src = manifest_dir.join("src");
        let this_file = src.join("transactions").join("input_selector.rs");
        // The CLI's commands build transactions too.
        let mut dirs = vec![src, manifest_dir.join("../minotari/src")];
        let mut builder_sites = 0;
        let mut refusing_calls = 0;
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).expect("read dir") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    dirs.push(path);
                    continue;
                }
                // This file names the patterns below in its own test.
                if path.extension().and_then(|e| e.to_str()) != Some("rs") || path == this_file {
                    continue;
                }
                let source = std::fs::read_to_string(&path).expect("read source");
                let new_count = source.matches(" TransactionBuilder::new(").count();
                let required_count = source.matches(".with_change_required()").count();
                assert!(
                    required_count >= new_count,
                    "{} creates {} TransactionBuilder(s) but calls with_change_required {} time(s)",
                    path.display(),
                    new_count,
                    required_count
                );
                builder_sites += new_count;

                let calls = source.matches("prepare_one_sided_transaction_for_signing(").count()
                    + source.matches("sign_locked_transaction(").count()
                    + source.matches(".reserve_sender_offset_keys(").count();
                let mapped = source.matches(".map_err(map_change_required_error)").count();
                assert!(
                    mapped >= calls,
                    "{} has {} prepare/sign/reserve call(s) but maps {} with map_change_required_error",
                    path.display(),
                    calls,
                    mapped
                );
                refusing_calls += calls;
            }
        }
        assert!(
            builder_sites >= 4,
            "expected at least the four known builder sites, found {builder_sites}"
        );
        assert!(
            refusing_calls >= 5,
            "expected the three prepare, one sign and one reserve call, found {refusing_calls}"
        );
    }
}
