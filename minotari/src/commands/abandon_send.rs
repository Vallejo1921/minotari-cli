//! `abandon-send` command handler.

use std::path::PathBuf;

use anyhow::anyhow;
use log::info;
use tari_common_types::transaction::TxId;

use crate::{
    db::{self, init_db},
    transactions::abandon::abandon_send,
    webhooks::WebhookTriggerConfig,
};

/// Abandons send `tx_id` of `account_name` and releases its inputs.
///
/// See [`abandon_send`]: the send must be completed or broadcast, and stalled
/// unless `force` is set; one without a change output only with
/// `accept_unreconcilable`. The original transaction can still be mined if a
/// node holds it; the wallet then marks it mined after all, if it has a change
/// output.
pub fn handle_abandon_send(
    database_file: PathBuf,
    account_name: &str,
    tx_id: u64,
    force: bool,
    accept_unreconcilable: bool,
    webhook_config: Option<WebhookTriggerConfig>,
) -> Result<(), anyhow::Error> {
    let pool = init_db(database_file)?;
    let mut conn = pool.get()?;
    let account =
        db::get_account_by_name(&conn, account_name)?.ok_or_else(|| anyhow!("Account '{}' not found", account_name))?;

    let tx_id = TxId::from(tx_id);
    let abandoned = abandon_send(
        &mut conn,
        account.id,
        tx_id,
        force,
        accept_unreconcilable,
        webhook_config.as_ref(),
    )?;

    info!(
        target: "audit",
        tx_id = tx_id.to_string().as_str(),
        reconcilable = abandoned.reconcilable;
        "Send abandoned"
    );
    println!("Send {}: {}", tx_id, abandoned.note());
    Ok(())
}
