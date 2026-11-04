use anyhow::{Result, anyhow};
use log::trace;
use tari_common::configuration::Network;
use tari_common_types::{
    tari_address::{MAX_PAYMENT_ID_SIZE, TariAddress},
    types::FixedHash,
};
use tari_script::{TariScript, script};
use tari_transaction_components::{
    fee::{Fee, recipient_output_features_and_scripts_size},
    helpers::borsh::SerializedSize,
    tari_amount::MicroMinotari,
    transaction_components::{
        OutputFeatures,
        covenants::Covenant,
        memo_field::{MemoField, TxType},
    },
    weight::TransactionWeight,
};

use crate::http::WalletHttpClient;
use crate::{
    db::{self, AccountRow, SqlitePool},
    transactions::{
        fund_locker::MIN_FEE_PER_GRAM,
        input_selector::InputSelector,
        one_sided_transaction::{Recipient, sender_address_for_sizing},
    },
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

/// What a send-all would cost and pay, from [`FeeEstimator::estimate_fees_send_all`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendAllEstimate {
    /// The fee, for every input, the recipient output and the change output.
    pub fee: MicroMinotari,
    /// What the recipient receives: the inputs' total less the fee and the minimum change.
    pub amount_after_fee: MicroMinotari,
    /// How many inputs the send-all spends (the selection of [`InputSelector::select_all`](crate::transactions::input_selector::InputSelector::select_all)).
    pub input_count: usize,
    /// Spendable outputs left behind for being worth no more than they cost to spend.
    pub skipped_dust: usize,
    /// Spendable outputs left behind for not fitting one transaction (count, weight or
    /// bytes); another send-all can sweep them.
    pub skipped_over_cap: usize,
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
                let fast = stats.first().expect("Already checked").avg_fee_per_gram;
                // Medium: Average of the 2nd block (if exists)
                let medium = stats
                    .get(1)
                    .unwrap_or(stats.first().expect("Already checked"))
                    .avg_fee_per_gram;
                // Slow: Minimum of the deepest block we got
                let slow = stats.last().expect("Already checked").min_fee_per_gram;

                (fast, medium, slow)
            },
            _ => (MicroMinotari::from(10), MicroMinotari::from(5), MicroMinotari::from(1)),
        };
        // The node's statistics use integer division and can come out as 0; never
        // recommend a fee the wallet refuses to send with.
        let fast_fee = fast_fee.max(MIN_FEE_PER_GRAM);
        let medium_fee = medium_fee.max(MIN_FEE_PER_GRAM);
        let slow_fee = slow_fee.max(MIN_FEE_PER_GRAM);

        let input_selector = InputSelector::new(account.id, confirmation_window);

        let selection =
            input_selector.fetch_unspent_outputs(&conn, amount, num_outputs, fast_fee, estimated_output_size)?;

        let input_count = selection.utxos.len();
        let total_outputs = if selection.requires_change_output {
            num_outputs
                .checked_add(1)
                .ok_or_else(|| anyhow!("Too many outputs to estimate a fee for"))?
        } else {
            num_outputs
        };

        let output_size = match estimated_output_size {
            Some(sz) => sz,
            None => estimated_output_size_for_send(0, num_outputs, &TariAddress::default())?,
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
        .collect::<Result<Vec<_>>>()?;

        trace!(
            account = account_name,
            inputs = input_count;
            "Calculated fee estimates"
        );

        Ok(results)
    }

    /// Quotes a send-all at `fee_per_gram`, computed exactly as
    /// [`TransactionSender::start_new_send_all_transaction`](crate::transactions::manager::TransactionSender::start_new_send_all_transaction)
    /// computes it.
    ///
    /// The fee is exactly what the offline signer will charge, so only the
    /// minimum change is left over. `network` bounds the inputs as for the send
    /// (see [`max_send_all_inputs`](crate::transactions::input_selector::max_send_all_inputs)).
    /// Fails when the recipient's share would be dust.
    pub fn estimate_fees_send_all(
        &self,
        account_name: &str,
        network: Network,
        address: &TariAddress,
        payment_id: Option<&str>,
        fee_per_gram: MicroMinotari,
        confirmation_window: u64,
    ) -> Result<SendAllEstimate> {
        let conn = self.db_pool.get()?;
        let account: AccountRow = db::get_account_by_name(&conn, account_name)?
            .ok_or_else(|| anyhow!("Account with name '{}' not found", account_name))?;

        let recipient = Recipient {
            address: address.clone(),
            amount: MicroMinotari::zero(),
            payment_id: payment_id.map(str::to_string),
        };
        let (recipient_output_size, change_output_size) = one_sided_output_sizes(&[recipient], network)?;
        let input_selector = InputSelector::new(account.id, confirmation_window);
        let selection =
            input_selector.select_all(&conn, network, fee_per_gram, recipient_output_size, change_output_size)?;
        let amount_after_fee = input_selector.send_all_amount(
            selection.selection.total_value,
            selection.selection.fee_with_change,
            fee_per_gram,
        )?;

        Ok(SendAllEstimate {
            fee: selection.selection.fee_with_change,
            amount_after_fee,
            input_count: selection.selection.utxos.len(),
            skipped_dust: selection.skipped_dust,
            skipped_over_cap: selection.skipped_over_cap,
        })
    }

    fn calculate_single_estimate(
        &self,
        priority: FeePriority,
        fee_per_gram: MicroMinotari,
        amount: MicroMinotari,
        input_count: usize,
        output_count: usize,
        output_size: usize,
    ) -> Result<FeeEstimateResult> {
        let total_output_size = output_size
            .checked_mul(output_count)
            .ok_or_else(|| anyhow!("Total output size overflows while estimating fee"))?;
        let fee = self
            .fee_calc
            .calculate(fee_per_gram, 1, input_count, output_count, total_output_size);
        let total_amount_required = amount
            .checked_add(fee)
            .ok_or_else(|| anyhow!("Amount plus fee overflows while estimating fee"))?;

        Ok(FeeEstimateResult {
            priority,
            fee_per_gram,
            estimated_fee: fee,
            total_amount_required,
            input_count,
        })
    }
}

/// Measure one output the way the transaction builder charges for it.
///
/// Upstream's `recipient_output_features_and_scripts_size` is the authority here: it counts
/// the features, the script, the covenant **and the memo carried in the output's encrypted
/// data**, then rounds up to the fee's gram boundary. Summing the first three by hand - which
/// is what this module used to do - silently drops the memo, which is usually the largest of
/// the four.
pub fn measure_output_size(features: &OutputFeatures, script: &TariScript, memo: &MemoField) -> Result<usize> {
    recipient_output_features_and_scripts_size(
        &TransactionWeight::latest(),
        features,
        script,
        &Covenant::default(),
        memo,
    )
    .map_err(|e| anyhow!("Failed to measure output size: {e}"))
}

/// A conservative per-output size for a payment whose memo carries `payment_id_len` bytes.
///
/// UTXO selection charges this once per output and once for change, so it must over-estimate
/// rather than under-estimate: a short answer locks inputs that cannot cover the fee the
/// builder later computes, and `reserve_sender_offset_keys` then fails the send *after* the
/// funds are reserved, leaving the user to wait out the lock. Over-estimating only makes the
/// change output slightly smaller than it needed to be.
///
/// The shape measured is the change output, which is the largest the builder emits on its own
/// account: a `PushPubKey` script and a `TransactionInfo` memo holding the recipient address,
/// one sent-output hash and the caller's payment id, padded to a 130-byte floor.
pub fn estimated_output_size_for_payment_id(payment_id_len: usize) -> Result<usize> {
    estimated_output_size_for_send(payment_id_len, 1, &TariAddress::default())
}

/// [`estimated_output_size_for_payment_id`] for a send to `num_recipients` recipients, the
/// first of them `first_recipient`.
///
/// The builder lists one sent-output hash per recipient in the change memo when there are at
/// most two, and none beyond that, so two recipients are measured with two hashes and any
/// other count with one. The change memo names the first recipient, and an address can embed
/// a payment id of its own, so it is measured with that address. `TariAddress::default()`
/// measures as a plain dual address, the larger plain form.
pub fn estimated_output_size_for_send(
    payment_id_len: usize,
    num_recipients: usize,
    first_recipient: &TariAddress,
) -> Result<usize> {
    let hash_count = num_recipients.clamp(1, 2);
    // The script the builder derives for a recipient, and for its own change output.
    let script = script!(PushPubKey(Box::default())).map_err(|e| anyhow!("Failed to build the default script: {e}"))?;

    // A change memo: the first recipient's address, the sent-output hashes and the payment id.
    let change_memo = |payment_id: Vec<u8>| {
        MemoField::new_transaction_info(
            first_recipient.clone(),
            MicroMinotari::zero(),
            MicroMinotari::zero(),
            true,
            TxType::PaymentToOther,
            vec![FixedHash::zero(); hash_count],
            payment_id,
        )
    };

    // A memo has a hard 256-byte ceiling, so a payment id past it cannot go in a change memo
    // at all, and a send carrying one is refused before anything is locked
    // (`total_recipient_amount`). Quote the ceiling for it, which no real output exceeds,
    // rather than refusing to quote.
    match change_memo(vec![0u8; payment_id_len]) {
        Ok(memo) => measure_output_size(&OutputFeatures::default(), &script, &memo),
        Err(_) => {
            let to_err = |e: std::io::Error| anyhow!("Failed to measure the largest output: {e}");
            let size = OutputFeatures::default()
                .get_serialized_size()
                .map_err(to_err)?
                .saturating_add(script.get_serialized_size().map_err(to_err)?)
                .saturating_add(Covenant::default().get_serialized_size().map_err(to_err)?)
                .saturating_add(MAX_PAYMENT_ID_SIZE);
            Ok(TransactionWeight::latest().round_up_features_and_scripts_size(size))
        },
    }
}

/// The per-output size to charge an exact send to `recipients`.
///
/// Selection has to charge for the memo this send will actually carry. Left at the
/// default, a long payment id is weight nobody reserved inputs for, and the send fails
/// at build time with the funds already locked. One size is charged for every output,
/// so quote the largest memo, and the change memo with the first recipient's address.
pub fn estimated_output_size_for_recipients(recipients: &[Recipient]) -> Result<usize> {
    let largest_payment_id = recipients
        .iter()
        .map(|r| r.payment_id_bytes().map_or(0, |bytes| bytes.len()))
        .max()
        .unwrap_or(0);
    let default_address = TariAddress::default();
    let first_recipient = recipients.first().map_or(&default_address, |r| &r.address);
    estimated_output_size_for_send(largest_payment_id, recipients.len(), first_recipient)
}

/// The exact features-and-scripts sizes the transaction builder charges a one-sided send to
/// `recipients`: the total of the recipients' own outputs, and the change output.
///
/// Each recipient output carries its own memo with the sender's address on it
/// ([`Recipient::output_memo`], measured with [`sender_address_for_sizing`]). The change memo names the first recipient,
/// carries its payment id and, for up to two recipients, every sent-output hash; its size does
/// not depend on any amount, so the sizes are known before the amounts are.
pub fn one_sided_output_sizes(recipients: &[Recipient], network: Network) -> Result<(usize, usize)> {
    let script = script!(PushPubKey(Box::default())).map_err(|e| anyhow!("Failed to build the default script: {e}"))?;
    let sender_address = sender_address_for_sizing(network)?;
    let mut recipients_size = 0usize;
    for recipient in recipients {
        let memo = recipient.output_memo(&sender_address)?;
        let size = measure_output_size(&OutputFeatures::default(), &script, &memo)?;
        recipients_size = recipients_size
            .checked_add(size)
            .ok_or_else(|| anyhow!("Total output size overflows"))?;
    }

    let first = recipients.first().ok_or_else(|| anyhow!("No recipients provided"))?;
    let hash_count = if recipients.len() <= 2 { recipients.len() } else { 0 };
    let change_memo = MemoField::new_transaction_info(
        first.address.clone(),
        MicroMinotari::zero(),
        MicroMinotari::zero(),
        true,
        TxType::PaymentToOther,
        vec![FixedHash::zero(); hash_count],
        first.payment_id_bytes().unwrap_or_default(),
    )
    .map_err(|e| anyhow!("Failed to build the change memo: {e}"))?;
    // Measured as the builder measures change: no covenant.
    let features_size = OutputFeatures::default()
        .get_serialized_size()
        .map_err(|e| anyhow!("Failed to measure the change output: {e}"))?;
    let script_size = script
        .get_serialized_size()
        .map_err(|e| anyhow!("Failed to measure the change output: {e}"))?;
    let change_size = features_size
        .saturating_add(script_size)
        .saturating_add(change_memo.get_size());
    let change_size = TransactionWeight::latest().round_up_features_and_scripts_size(change_size);
    Ok((recipients_size, change_size))
}

/// The per-output size to assume when even the payment id is unknown.
pub fn get_default_features_and_scripts_size() -> Result<usize> {
    estimated_output_size_for_payment_id(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_script::script;

    /// The estimate has to cover what the builder actually charges, or selection locks inputs
    /// that cannot pay the fee and the send dies after the funds are reserved.
    #[test]
    fn the_default_estimate_covers_a_one_sided_recipient_output() {
        let recipient_memo = MemoField::new_open_from_string("invoice-12345", TxType::PaymentToOther).unwrap();
        let recipient = measure_output_size(
            &OutputFeatures::default(),
            &script!(PushPubKey(Box::default())).unwrap(),
            &recipient_memo,
        )
        .unwrap();

        assert!(
            get_default_features_and_scripts_size().unwrap() >= recipient,
            "default estimate must not be smaller than a real recipient output"
        );
    }

    /// Recipient memos carry the sender's address (`recipient_memo`), and the estimate for every
    /// payment id length such a memo can hold has to cover that larger memo too.
    #[test]
    fn the_estimate_covers_a_recipient_memo_carrying_the_sender_address() {
        let sender = TariAddress::default();
        let recipient = TariAddress::default();
        for len in 0usize..=256 {
            let payment_id = "x".repeat(len);
            let Ok(open) = MemoField::new_open_from_string(&payment_id, TxType::PaymentToOther) else {
                continue;
            };
            let Ok(memo) = crate::transactions::one_sided_transaction::recipient_memo(open, &sender, &recipient) else {
                continue;
            };
            let output = measure_output_size(
                &OutputFeatures::default(),
                &script!(PushPubKey(Box::default())).unwrap(),
                &memo,
            )
            .unwrap();
            assert!(
                estimated_output_size_for_payment_id(len).unwrap() >= output,
                "estimate for a {len}-byte payment id must cover the recipient output"
            );
        }
    }

    /// The old implementation summed features + an *empty* script + covenant and stopped, which
    /// is where the under-estimate came from. Both missing terms have to be back.
    #[test]
    fn the_default_estimate_counts_the_script_and_the_memo() {
        let bare = measure_output_size(
            &OutputFeatures::default(),
            &TariScript::default(),
            &MemoField::new_empty(),
        )
        .unwrap();

        assert!(
            get_default_features_and_scripts_size().unwrap() > bare,
            "default estimate must count the script and the memo, not just features and covenant"
        );
    }

    /// A longer payment id is a bigger output, and selection has to be told so.
    #[test]
    fn a_longer_payment_id_raises_the_estimate() {
        let short = estimated_output_size_for_payment_id(0).unwrap();
        let long = estimated_output_size_for_payment_id(100).unwrap();
        assert!(long > short, "a 100-byte payment id must cost more than an empty one");
    }
    /// A payment id too long for a memo cannot be quoted exactly; the estimate falls back to
    /// the memo ceiling, which covers any output that can be built, instead of failing.
    #[test]
    fn an_oversized_payment_id_falls_back_to_the_ceiling() {
        let oversized = estimated_output_size_for_payment_id(4096).unwrap();
        for payment_id_len in [0, 100, 150] {
            assert!(oversized >= estimated_output_size_for_payment_id(payment_id_len).unwrap());
        }
        assert_eq!(oversized, estimated_output_size_for_payment_id(257).unwrap());
    }

    /// The change memo lists a sent-output hash per recipient for up to two recipients, so the
    /// per-output estimate must cover that change output, which one hash does not.
    #[test]
    fn the_estimate_covers_the_change_output_for_any_recipient_count() {
        let recipient = Recipient {
            address: TariAddress::default(),
            amount: MicroMinotari(1_000),
            payment_id: Some("invoice".to_string()),
        };
        for n in 1..=3 {
            let recipients = vec![recipient.clone(); n];
            let (_, change_size) = one_sided_output_sizes(&recipients, Network::MainNet).unwrap();
            assert!(
                estimated_output_size_for_send("invoice".len(), n, &TariAddress::default()).unwrap() >= change_size,
                "{n} recipients"
            );
        }
        let (_, two_recipient_change) =
            one_sided_output_sizes(&[recipient.clone(), recipient], Network::MainNet).unwrap();
        assert!(estimated_output_size_for_payment_id("invoice".len()).unwrap() < two_recipient_change);
    }

    fn test_estimator() -> (FeeEstimator, tempfile::TempDir) {
        let temp_dir = tempfile::tempdir().unwrap();
        let pool = db::init_db(temp_dir.path().join("fee_estimator.db")).unwrap();
        (FeeEstimator::new(pool, "http://127.0.0.1:1".to_string()), temp_dir)
    }

    #[test]
    fn a_single_estimate_adds_the_fee_to_the_amount() {
        let (estimator, _temp_dir) = test_estimator();
        let estimate = estimator
            .calculate_single_estimate(FeePriority::Slow, MicroMinotari(5), MicroMinotari(1_000), 1, 2, 100)
            .unwrap();
        assert!(estimate.estimated_fee > MicroMinotari(0));
        assert_eq!(
            estimate.total_amount_required,
            MicroMinotari(1_000) + estimate.estimated_fee
        );
    }

    #[test]
    fn a_single_estimate_rejects_an_amount_that_overflows_with_the_fee() {
        let (estimator, _temp_dir) = test_estimator();
        let result = estimator.calculate_single_estimate(
            FeePriority::Fast,
            MicroMinotari(5),
            MicroMinotari(u64::MAX),
            1,
            2,
            100,
        );
        assert!(result.is_err());
    }

    #[test]
    fn a_single_estimate_rejects_an_overflowing_output_size() {
        let (estimator, _temp_dir) = test_estimator();
        let result = estimator.calculate_single_estimate(
            FeePriority::Fast,
            MicroMinotari(5),
            MicroMinotari(1),
            1,
            2,
            usize::MAX,
        );
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn an_estimate_never_goes_below_the_minimum_fee_per_gram() {
        use crate::db::{create_account, get_account_by_name, init_db, insert_scanned_tip_block};
        use rusqlite::named_params;
        use tari_common_types::seeds::cipher_seed::CipherSeed;
        use tari_common_types::types::{ComAndPubSignature, CompressedPublicKey};
        use tari_script::ExecutionStack;
        use tari_transaction_components::key_manager::TariKeyId;
        use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
        use tari_transaction_components::transaction_components::{
            EncryptedData, TransactionOutputVersion, WalletOutput,
        };
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // A wallet with one confirmed output to estimate a send from.
        let dir = tempfile::tempdir().expect("temp dir");
        let pool = init_db(dir.path().join("fees.db")).expect("init db");
        {
            let conn = pool.get().expect("conn");
            let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
            create_account(&conn, "default", &wallet, "password").unwrap();
            let account_id = get_account_by_name(&conn, "default").unwrap().unwrap().id;
            insert_scanned_tip_block(&conn, account_id, 200, &[0u8; 32]).expect("tip");
            let output = WalletOutput::new_from_parts(
                TransactionOutputVersion::default(),
                MicroMinotari::from(1_000_000),
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
                FixedHash::from([1u8; 32]),
                Default::default(),
            );
            conn.execute(
                r#"
                INSERT INTO outputs (
                    account_id, tx_id, output_hash, mined_in_block_height, mined_in_block_hash, value,
                    mined_timestamp, wallet_output_json, status, confirmed_height, confirmed_hash, is_burn, maturity
                ) VALUES (:account_id, 1, :hash, 100, :hash, 1000000, :ts, :json, 'UNSPENT', 100, :hash, 0, 0)
                "#,
                named_params! {
                    ":account_id": account_id,
                    ":hash": vec![1u8; 32],
                    ":ts": chrono::Utc::now(),
                    ":json": serde_json::to_string(&output).unwrap(),
                },
            )
            .expect("output");
        }

        // The node's integer averages came out as 0.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get_mempool_fee_per_gram_stats"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "stats": [
                    { "order": 0, "min_fee_per_gram": 0, "avg_fee_per_gram": 0, "max_fee_per_gram": 0 },
                    { "order": 1, "min_fee_per_gram": 0, "avg_fee_per_gram": 0, "max_fee_per_gram": 0 },
                ]
            })))
            .mount(&server)
            .await;

        let estimates = FeeEstimator::new(pool, server.uri())
            .estimate_fees("default", MicroMinotari(10_000), 1, 100, None)
            .await
            .expect("estimate");
        assert_eq!(estimates.len(), 3);
        for estimate in estimates {
            assert_eq!(estimate.fee_per_gram, MIN_FEE_PER_GRAM, "{:?}", estimate.priority);
        }
    }
}
