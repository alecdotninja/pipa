//! Command-line interface definitions.

use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;

/// Default maximum depth for followed CNAME chains.
pub(crate) const DEFAULT_CNAME_DEPTH: usize = 8;

/// Command-line configuration for the jump server.
#[derive(Debug, Parser)]
pub(crate) struct Cli {
    /// Socket addresses for the relay listener.
    #[arg(
        long,
        env = "JUMPSRV_RELAY_LISTEN",
        value_delimiter = ',',
        num_args = 1..,
        default_values = ["127.0.0.1:2222"]
    )]
    pub(crate) relay_listen: Vec<SocketAddr>,

    /// Socket addresses for the usage-only listener.
    #[arg(
        long,
        env = "JUMPSRV_USAGE_LISTEN",
        value_delimiter = ',',
        num_args = 1..,
        default_values = ["127.0.0.1:2223"]
    )]
    pub(crate) usage_listen: Vec<SocketAddr>,

    /// Public relay hostname used in generated instructions.
    #[arg(long, env = "JUMPSRV_RELAY_HOSTNAME", default_value = "pipa.sh")]
    pub(crate) relay_hostname: String,

    /// SQLite database path for persistent registrations.
    #[arg(long, env = "JUMPSRV_DATABASE", default_value = "pipa.sqlite3")]
    pub(crate) database: PathBuf,

    /// SSH host key file path.
    #[arg(
        long,
        env = "JUMPSRV_HOST_KEY",
        default_value = "pipa_host_ed25519_key"
    )]
    pub(crate) host_key: PathBuf,

    /// Maximum number of active tunnels per published hostname.
    #[arg(long, env = "JUMPSRV_MAX_TUNNELS_PER_PUBLISHER", default_value_t = 10)]
    pub(crate) max_tunnels_per_publisher: usize,

    /// Authentication rejection delay in seconds.
    #[arg(long, env = "JUMPSRV_AUTH_REJECTION_SECS", default_value_t = 1)]
    pub(crate) auth_rejection_secs: u64,

    /// Maximum CNAME resolution depth.
    #[arg(long, env = "JUMPSRV_CNAME_DEPTH", default_value_t = DEFAULT_CNAME_DEPTH)]
    pub(crate) cname_depth: usize,

    /// Enables JSON structured logs.
    #[arg(long, env = "JUMPSRV_JSON_LOGS")]
    pub(crate) json_logs: bool,
}
