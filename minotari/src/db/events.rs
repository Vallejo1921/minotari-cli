use chrono::NaiveDateTime;
use log::{debug, info};
use rusqlite::{Connection, named_params};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::WalletEvent;
use crate::db::error::WalletDbResult;

/// A database row representation of a wallet event.
///
/// This struct is used for deserializing wallet events from the database
/// and serializing them for API responses.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DbWalletEvent {
    /// Unique identifier for this event
    pub id: i64,
    /// Account this event belongs to
    pub account_id: i64,
    /// The type of event (e.g., "OutputDetected", "TransactionConfirmed")
    pub event_type: String,
    /// Human-readable description of the event
    pub description: String,
    /// JSON data containing event-specific details
    pub data_json: Option<String>,
    /// Timestamp when the event was created
    #[schema(value_type = String)]
    pub created_at: NaiveDateTime,
}

pub fn insert_wallet_event(conn: &Connection, account_id: i64, event: &WalletEvent) -> WalletDbResult<i64> {
    info!(
        target: "audit",
        account_id = account_id,
        event_type = &*event.event_type.to_key_string();
        "DB: Inserting wallet event"
    );

    let event_type = &event.event_type.to_key_string();
    let description = &event.description;
    let data_json = serde_json::to_value(&event.event_type)?.to_string();

    conn.execute(
        r#"
       INSERT INTO events (account_id, event_type, description, data_json)
         VALUES (:account_id, :event_type, :description, :data_json)
        "#,
        named_params! {
            ":account_id": account_id,
            ":event_type": event_type,
            ":description": description,
            ":data_json": data_json
        },
    )?;

    let event_id = conn.last_insert_rowid();

    Ok(event_id)
}

pub fn get_events_by_account_id(
    conn: &Connection,
    account_id: i64,
    limit: i64,
    offset: i64,
) -> WalletDbResult<Vec<DbWalletEvent>> {
    debug!(
        account_id = account_id,
        limit = limit,
        offset = offset;
        "DB: Fetching events with pagination"
    );

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT
            id,
            account_id,
            event_type,
            description,
            data_json,
            REPLACE(created_at, ' ', 'T') as created_at
        FROM events
        WHERE account_id = :account_id
        ORDER BY created_at DESC, id DESC
        LIMIT :limit OFFSET :offset
        "#,
    )?;

    let rows = stmt.query_map(
        named_params! {
            ":account_id": account_id,
            ":limit": limit,
            ":offset": offset
        },
        |row| {
            Ok(DbWalletEvent {
                id: row.get(0)?,
                account_id: row.get(1)?,
                event_type: row.get(2)?,
                description: row.get(3)?,
                data_json: row.get(4)?,
                created_at: row.get(5)?,
            })
        },
    )?;

    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}
