use serde::{Deserialize, Serialize};
use std::str::FromStr;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub enum OutputStatus {
    Unspent,
    Locked,
    Spent,
}

impl std::fmt::Display for OutputStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputStatus::Unspent => write!(f, "UNSPENT"),
            OutputStatus::Locked => write!(f, "LOCKED"),
            OutputStatus::Spent => write!(f, "SPENT"),
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
            _ => Err(format!("Invalid OutputStatus: {}", s)),
        }
    }
}
