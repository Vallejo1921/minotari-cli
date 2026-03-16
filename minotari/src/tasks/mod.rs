//! Background tasks for periodic wallet maintenance.
//!
//! This module contains background tasks that run periodically to maintain
//! wallet state and handle cleanup operations.
//!
//! # Available Tasks
//!
//! - [`unlocker::TransactionUnlocker`] - Automatically unlocks expired transaction locks
//!
//! # Usage
//!
//! Tasks are typically started by the daemon and run in the background until
//! a shutdown signal is received.

pub mod unlocker;
