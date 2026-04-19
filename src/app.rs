//! Process bootstrap, logging, and listener orchestration.

use std::{
    net::SocketAddr,
    sync::{atomic::AtomicU64, Arc},
    time::Duration,
};

use anyhow::Result;
use clap::Parser;
use russh::server;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::{
    cli::Cli,
    dns::DnsAliasResolver,
    host_key::load_or_generate_host_key,
    messages::Policy,
    registry::{RegistrationStore, Registry},
    ssh::{RelayServer, UsageServer},
};

/// Shared runtime state for the relay listener.
#[derive(Clone)]
pub(crate) struct AppState {
    /// Active route registry and persistent registrations.
    pub(crate) registry: Registry,
    /// Relay policy and message generation.
    pub(crate) policy: Arc<Policy>,
    /// DNS resolver for CNAME dispatch.
    pub(crate) resolver: DnsAliasResolver,
    /// Monotonic session identifier source.
    pub(crate) next_session_id: Arc<AtomicU64>,
}

/// Runs the application process.
pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.json_logs)?;

    let registrations = RegistrationStore::open(&cli.database)?;
    let host_key = load_or_generate_host_key(&cli.host_key)?;
    let policy = Arc::new(Policy {
        max_tunnels_per_publisher: cli.max_tunnels_per_publisher,
        relay_hostname: crate::util::normalize_domain(&cli.relay_hostname),
    });

    let config = Arc::new(server::Config {
        auth_rejection_time: Duration::from_secs(cli.auth_rejection_secs),
        auth_rejection_time_initial: Some(Duration::from_millis(100)),
        inactivity_timeout: None,
        keys: vec![host_key],
        ..Default::default()
    });

    let state = Arc::new(AppState {
        registry: Registry::new(registrations),
        policy,
        resolver: DnsAliasResolver::system(cli.cname_depth)?,
        next_session_id: Arc::new(AtomicU64::new(1)),
    });

    info!(
        relay_listen = ?cli.relay_listen,
        usage_listen = ?cli.usage_listen,
        "starting SSH-only jump server with separate relay and usage listeners"
    );

    let relay_server = RelayServer {
        state: state.clone(),
    };
    let usage_server = UsageServer {
        policy: state.policy.clone(),
    };

    tokio::try_join!(
        run_listeners(relay_server, config.clone(), cli.relay_listen),
        run_listeners(usage_server, config, cli.usage_listen),
    )?;
    Ok(())
}

/// Initializes tracing output from the environment.
fn init_logging(json: bool) -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "pipa=info,russh=warn".into());
    let subscriber = tracing_subscriber::fmt().with_env_filter(filter);
    if json {
        subscriber
            .json()
            .try_init()
            .map_err(|error| anyhow::anyhow!(error))?;
    } else {
        subscriber
            .try_init()
            .map_err(|error| anyhow::anyhow!(error))?;
    }
    Ok(())
}

/// Runs a single bound listener for a server implementation.
async fn run_listener<S>(
    mut server: S,
    config: Arc<server::Config>,
    listen: SocketAddr,
) -> Result<()>
where
    S: server::Server + Clone + Send + 'static,
    S::Handler: Send + 'static,
    <S::Handler as server::Handler>::Error: std::fmt::Debug + Send + 'static,
{
    let listener = TcpListener::bind(listen)
        .await
        .map_err(anyhow::Error::from)
        .map_err(|error| error.context(format!("binding {listen}")))?;

    loop {
        let (socket, peer) = listener.accept().await?;
        let handler = server.new_client(Some(peer));
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(error) = server::run_stream(config, socket, handler).await {
                warn!(%peer, ?error, "ssh session failed");
            }
        });
    }
}

/// Runs one server across all configured listener addresses.
async fn run_listeners<S>(
    server: S,
    config: Arc<server::Config>,
    listens: Vec<SocketAddr>,
) -> Result<()>
where
    S: server::Server + Clone + Send + 'static,
    S::Handler: Send + 'static,
    <S::Handler as server::Handler>::Error: std::fmt::Debug + Send + 'static,
{
    let mut tasks = tokio::task::JoinSet::new();
    for listen in listens {
        tasks.spawn(run_listener(server.clone(), config.clone(), listen));
    }

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error),
            Err(error) => return Err(anyhow::anyhow!("listener task failed: {error}")),
        }
    }

    Ok(())
}
