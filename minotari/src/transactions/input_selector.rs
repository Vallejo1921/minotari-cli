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
//! use minotari::transactions::input_selector::InputSelector;
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

use log::{debug, warn};
use rusqlite::Connection;
use tari_transaction_components::{fee::Fee, tari_amount::MicroMinotari, weight::TransactionWeight};
use thiserror::Error;

use crate::db::get_total_unspent_balance;
use crate::{
    db::{DbWalletOutput, WalletDbError, get_latest_scanned_tip_block_by_account},
    log::mask_amount,
    transactions::fee_estimator::get_default_features_and_scripts_size,
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
    /// `true` if the total value exceeds amount + fee, requiring change.
    /// `false` if the total exactly matches amount + fee.
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
/// use minotari::transactions::input_selector::InputSelector;
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
        let tip = get_latest_scanned_tip_block_by_account(conn, self.account_id)?;
        let min_height = tip
            .map(|b| b.height)
            .unwrap_or(0)
            .saturating_sub(self.confirmation_window);
        let (locked_amount, _unconfirmed_amount, _locked_and_unconfirmed_amount) =
            crate::db::get_output_totals_for_account(conn, self.account_id)?;
        let total_unspent_balance: MicroMinotari = get_total_unspent_balance(conn, self.account_id)?.into();
        let available_balance = total_unspent_balance.saturating_sub(locked_amount);
        if available_balance <= amount && total_unspent_balance >= amount {
            let pending = total_unspent_balance.saturating_sub(locked_amount);
            warn!(
                target: "audit",
                available = &*mask_amount(total_unspent_balance),
                pending = &*mask_amount(pending),
                required = &*mask_amount(amount);
                "Insufficient funds for transaction (pending confirmations)"
            );
            return Err(UtxoSelectionError::FundsPending {
                available: total_unspent_balance - locked_amount,
                pending,
                required: amount,
            });
        }
        let uo = crate::db::fetch_unspent_outputs(conn, self.account_id, min_height)?;

        let features_and_scripts_byte_size = match estimated_output_size {
            Some(sz) => sz,
            None => get_default_features_and_scripts_size()
                .map_err(|err| UtxoSelectionError::SerializationError(err.to_string()))?,
        };

        let kernel_fee = self.fee_calc.calculate(fee_per_gram, 1, 0, 0, 0);
        let default_output_fee = self
            .fee_calc
            .calculate(fee_per_gram, 0, 0, 1, features_and_scripts_byte_size);
        let output_fee = self
            .fee_calc
            .calculate(fee_per_gram, 0, 0, num_outputs, features_and_scripts_byte_size);
        let input_fee = self.fee_calc.calculate(fee_per_gram, 0, 1, 0, 0);
        let bnb = BranchAndBoundUtxoSelectionBuilder::new(uo)
            .with_target_amount(amount + kernel_fee)
            .with_fee_per_input(input_fee)
            .with_total_output_fee(output_fee)
            .with_change_fee(default_output_fee)
            .build()
            .map_err(|e| UtxoSelectionError::ServiceError(e.to_string()))?;

        let selection_result = bnb.search();

        if selection_result.is_none() {
            warn!(
                target: "audit",
                available = &*mask_amount(total_unspent_balance),
                required = &*mask_amount(amount);
                "Insufficient funds for transaction"
            );
            // the total is not enough to cover fees. So we just need to notify the user its not enough so we add 1 to it.
            return Err(UtxoSelectionError::InsufficientFunds {
                available: total_unspent_balance,
                required: amount + MicroMinotari(1),
            });
        }
        let selection = selection_result.expect("Selection should be valid here");
        let selected_amount = selection.current_value;
        let requires_change_output = selection.has_change;
        let final_fee = selection.final_fee + kernel_fee;
        let (fee_with_change, fee_without_change) = if requires_change_output {
            (final_fee, final_fee - default_output_fee)
        } else {
            (final_fee + default_output_fee, final_fee)
        };
        let utxos = selection.selected_utxos;

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
}
