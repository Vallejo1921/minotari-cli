use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PendingTransactionStatus {
    Pending,
    Completed,
    Cancelled,
    Expired,
}

impl std::fmt::Display for PendingTransactionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PendingTransactionStatus::Pending => write!(f, "PENDING"),
            PendingTransactionStatus::Completed => write!(f, "COMPLETED"),
            PendingTransactionStatus::Cancelled => write!(f, "CANCELLED"),
            PendingTransactionStatus::Expired => write!(f, "EXPIRED"),
        }
    }
}

impl FromStr for PendingTransactionStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PENDING" => Ok(PendingTransactionStatus::Pending),
            "COMPLETED" => Ok(PendingTransactionStatus::Completed),
            "CANCELLED" => Ok(PendingTransactionStatus::Cancelled),
            "EXPIRED" => Ok(PendingTransactionStatus::Expired),
            _ => Err(format!("Invalid PendingTransactionStatus: {}", s)),
        }
    }
}
