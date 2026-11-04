use std::time::Duration;

use log::{error, info, trace};
use rusqlite::Connection;
use tokio::{sync::broadcast, task::JoinHandle, time::interval};

use crate::db::{self, SqlitePool};

pub struct TransactionUnlocker {
    db_pool: SqlitePool,
}

impl TransactionUnlocker {
    pub fn new(db_pool: SqlitePool) -> Self {
        Self { db_pool }
    }

    pub fn unlock_expired_transactions(conn: &Connection) -> Result<(), anyhow::Error> {
        // This listing runs in autocommit, so every row it returns is a decision
        // taken from a stale read: by the time the loop reaches one, a send may
        // have claimed it for broadcast. Each row is re-checked under its own
        // write lock rather than trusted from here.
        let expired_txs = db::find_expired_pending_transactions(conn)?;

        for tx in expired_txs {
            if Self::expire_and_unlock(conn, &tx.id)? {
                info!(target: "audit", "Transaction expired: unlocked funds");
                trace!(
                    target: "audit",
                    id = &*tx.id;
                    "Transaction expired: unlocked funds"
                );
            } else {
                info!(target: "audit", "Transaction was claimed after it was listed as expired; leaving its funds locked");
                trace!(
                    target: "audit",
                    id = &*tx.id;
                    "Transaction was claimed after it was listed as expired; leaving its funds locked"
                );
            }
        }

        Ok(())
    }

    /// Expires one reservation and releases its UTXOs, if it is still `Pending`.
    ///
    /// Returns whether it acted. The status guard is what makes the stale
    /// listing above safe: a reservation claimed for broadcast between the
    /// `SELECT` and this write is already `Completed`, and unlocking its outputs
    /// would hand the inputs of a transaction that is on the network back to the
    /// next send to spend again.
    pub(crate) fn expire_and_unlock(conn: &Connection, pending_tx_id: &str) -> Result<bool, anyhow::Error> {
        Ok(db::expire_and_unlock_pending_transaction(conn, pending_tx_id)?)
    }

    pub fn run(self, mut shutdown_rx: broadcast::Receiver<()>) -> JoinHandle<Result<(), anyhow::Error>> {
        tokio::spawn(async move {
            info!(target: "audit", "Transaction unlocker task started.");
            let mut interval = interval(Duration::from_secs(60));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let conn = self.db_pool.get()?;
                        if let Err(e) = Self::unlock_expired_transactions(&conn) {
                            error!(error:% = e; "Error unlocking expired transactions");
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!(target: "audit", "Transaction unlocker task received shutdown signal. Exiting gracefully.");
                        break;
                    }
                }
            }
            info!("Transaction unlocker task has shut down.");
            Ok(())
        })
    }
}
