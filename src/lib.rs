#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
//! SSH-only jump server for publishing and reaching SSH services through a relay.

mod app;
mod cli;
mod dns;
mod host_key;
mod messages;
mod registry;
mod ssh;
mod util;

#[cfg(test)]
mod tests;

/// Runs the jump server process.
pub use app::run;
