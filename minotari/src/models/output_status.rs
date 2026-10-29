use serde::{Deserialize, Serialize};
use std::str::FromStr;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub enum OutputStatus {
    Unspent,
    Locked,
    Spent,
    /// Output discovered during fast sync backfill that is known to be spent
    /// but whose spending input has not yet been processed. Once the backfill
    /// processes the corresponding input, the status transitions to `Spent`.
    SpentUnconfirmed,
    /// Change output of a send, written when the send is finalised and not yet
    /// seen in a block. Counts towards the pending-incoming (`unconfirmed`)
    /// balance only; it is never selected, locked or spent. Its `mined_*`
    /// columns hold sentinel values (height 0, empty hash, epoch timestamp)
    /// until the scan finds it and turns it `Unspent`.
    Unconfirmed,
    /// Change output of a send whose inputs were spent by a different
    /// transaction, so it will never exist on chain. Never counted in any
    /// balance and never selected.
    Rejected,
}

impl std::fmt::Display for OutputStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputStatus::Unspent => write!(f, "UNSPENT"),
            OutputStatus::Locked => write!(f, "LOCKED"),
            OutputStatus::Spent => write!(f, "SPENT"),
            OutputStatus::SpentUnconfirmed => write!(f, "SPENT_UNCONFIRMED"),
            OutputStatus::Unconfirmed => write!(f, "UNCONFIRMED"),
            OutputStatus::Rejected => write!(f, "REJECTED"),
        }
    }
}

impl FromStr for OutputStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "UNSPENT" => Ok(OutputStatus::Unspent),
            "LOCKED" => Ok(OutputStatus::Locked),
            "SPENT" => Ok(OutputStatus::Spent),
            "SPENT_UNCONFIRMED" => Ok(OutputStatus::SpentUnconfirmed),
            "UNCONFIRMED" => Ok(OutputStatus::Unconfirmed),
            "REJECTED" => Ok(OutputStatus::Rejected),
            _ => Err(format!("Invalid OutputStatus: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_status_round_trips_through_its_db_string() {
        let all = [
            (OutputStatus::Unspent, "UNSPENT"),
            (OutputStatus::Locked, "LOCKED"),
            (OutputStatus::Spent, "SPENT"),
            (OutputStatus::SpentUnconfirmed, "SPENT_UNCONFIRMED"),
            (OutputStatus::Unconfirmed, "UNCONFIRMED"),
            (OutputStatus::Rejected, "REJECTED"),
        ];
        for (status, db_string) in all {
            assert_eq!(status.to_string(), db_string);
            assert_eq!(OutputStatus::from_str(db_string), Ok(status));
        }
    }
}
