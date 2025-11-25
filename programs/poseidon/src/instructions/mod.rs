//! Instruction modules - Core program operations
//!
//! This module contains all instruction handlers for the privacy wallet.

pub mod init;
pub mod migrate;
pub mod deposit;
pub mod fetch;
pub mod withdraw;
pub mod emergency;

// Re-export all instruction handlers
pub use init::*;
pub use migrate::*;
pub use deposit::*;
pub use fetch::*;
pub use withdraw::*;
pub use emergency::*;
