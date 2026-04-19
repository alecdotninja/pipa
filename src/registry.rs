//! In-memory active route tracking and persistent registration storage.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use rusqlite::{params, Connection, Error as SqlError, ErrorCode, OptionalExtension};
use russh::{server::Handle, ChannelId};
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::util::{random_label, random_token, token_hash};

/// Active route registry and persistent registration access.
#[derive(Clone)]
pub(crate) struct Registry {
    /// In-memory active publisher routes keyed by hostname.
    inner: Arc<tokio::sync::RwLock<RegistryInner>>,
    /// SQLite-backed registration store.
    registrations: RegistrationStore,
}

/// Mutable in-memory registry state.
#[derive(Default)]
struct RegistryInner {
    /// Currently active publisher routes keyed by registered hostname.
    active: HashMap<String, PublisherRoute>,
}

/// Active publisher route for a registered hostname.
#[derive(Clone)]
pub(crate) struct PublisherRoute {
    /// Relay session id that owns the route.
    pub(crate) session_id: u64,
    /// SHA-256 hash of the bearer publish token.
    pub(crate) token_hash: String,
    /// Handle back into the publisher SSH session.
    pub(crate) handle: Handle,
    /// Publisher peer socket address as seen by the relay.
    pub(crate) publisher_peer: Option<std::net::SocketAddr>,
    /// Host string that the publisher originally requested for remote forwarding.
    pub(crate) publisher_forward_host: String,
    /// Per-publisher tunnel limiter.
    pub(crate) tunnel_limiter: Arc<Semaphore>,
    /// Optional session channel for publisher status output.
    pub(crate) status_channel: Option<ChannelId>,
}

/// SQLite-backed persistent registration store.
#[derive(Clone)]
pub(crate) struct RegistrationStore {
    /// Shared SQLite connection protected by a mutex.
    conn: Arc<Mutex<Connection>>,
}

impl Registry {
    /// Creates a new registry with the provided persistent store.
    pub(crate) fn new(registrations: RegistrationStore) -> Self {
        Self {
            inner: Arc::new(tokio::sync::RwLock::new(RegistryInner::default())),
            registrations,
        }
    }

    /// Allocates a random hostname and unique publish token.
    pub(crate) async fn register_random_hostname_with_token(
        &self,
        suffix: &str,
    ) -> Result<(String, String)> {
        for _ in 0..128 {
            let token = random_token();
            let hashed_token = token_hash(&token);
            match self.register_random_hostname(suffix, &hashed_token).await {
                Ok(hostname) => return Ok((hostname, token)),
                Err(error) if is_publish_token_uniqueness_error(&error) => continue,
                Err(error) => return Err(error),
            }
        }

        anyhow::bail!("unable to allocate a unique publish token after repeated attempts")
    }

    /// Inserts or replaces an active publisher route.
    pub(crate) async fn insert(&self, hostname: String, route: PublisherRoute) {
        let mut inner = self.inner.write().await;
        let previous = inner.active.insert(hostname.clone(), route);
        info!(%hostname, "hostname allocated");
        drop(inner);

        if let Some(previous) = previous {
            tokio::spawn(async move {
                if let Some(status_channel) = previous.status_channel {
                    let _ = previous
                        .handle
                        .data(
                            status_channel,
                            crate::util::to_crlf(
                                "\
Another publish session claimed this hostname.

This session has been replaced and will stop publishing now.
",
                            ),
                        )
                        .await;
                    let _ = previous.handle.eof(status_channel).await;
                    let _ = previous.handle.close(status_channel).await;
                }
                let _ = previous
                    .handle
                    .cancel_forward_tcpip(
                        previous.publisher_forward_host.clone(),
                        crate::util::SSH_PORT,
                    )
                    .await;
                info!(
                    %hostname,
                    session_id = previous.session_id,
                    "replaced existing publisher route"
                );
            });
        }
    }

    /// Looks up the active route for a registered hostname.
    pub(crate) async fn get(&self, hostname: &str) -> Option<PublisherRoute> {
        let inner = self.inner.read().await;
        inner.active.get(hostname).cloned()
    }

    /// Removes the active route when the given session still owns it.
    pub(crate) async fn remove_if_current(&self, hostname: &str, session_id: u64) {
        let mut inner = self.inner.write().await;
        let should_remove = inner
            .active
            .get(hostname)
            .is_some_and(|route| session_id == 0 || route.session_id == session_id);
        if should_remove && inner.active.remove(hostname).is_some() {
            info!(%hostname, "route removed");
        }
    }

    /// Updates the publisher status channel if the session still owns the route.
    pub(crate) async fn set_status_channel_if_current(
        &self,
        hostname: &str,
        session_id: u64,
        status_channel: Option<ChannelId>,
    ) {
        let mut inner = self.inner.write().await;
        if let Some(route) = inner.active.get_mut(hostname) {
            if route.session_id == session_id {
                route.status_channel = status_channel;
            }
        }
    }

    /// Checks whether a hostname is authorized for the given token hash.
    pub(crate) async fn publisher_authorized(&self, hostname: &str, token_hash: &str) -> bool {
        self.registrations
            .publisher_authorized(hostname, token_hash)
            .unwrap_or_else(|error| {
                warn!(%hostname, ?error, "registration authorization lookup failed");
                false
            })
    }

    /// Resolves a registered hostname from a token hash.
    pub(crate) async fn hostname_for_token(&self, token_hash: &str) -> Option<String> {
        self.registrations
            .hostname_for_token(token_hash)
            .unwrap_or_else(|error| {
                warn!(%token_hash, ?error, "registration lookup by token failed");
                None
            })
    }

    /// Updates the last-published timestamp for a hostname.
    pub(crate) async fn touch_last_published_at(&self, hostname: &str) {
        if let Err(error) = self.registrations.touch_last_published_at(hostname) {
            warn!(%hostname, ?error, "failed to update last_published_at");
        }
    }

    /// Updates the last-tunnel timestamp for a hostname.
    pub(crate) async fn touch_last_tunnel_at(&self, hostname: &str) {
        if let Err(error) = self.registrations.touch_last_tunnel_at(hostname) {
            warn!(%hostname, ?error, "failed to update last_tunnel_at");
        }
    }

    /// Allocates a random unused hostname under the given suffix.
    pub(crate) async fn register_random_hostname(
        &self,
        suffix: &str,
        token_hash: &str,
    ) -> Result<String> {
        for _ in 0..128 {
            let hostname = format!("{}.{}", random_label(), suffix);
            if self.get(&hostname).await.is_some() {
                continue;
            }

            match self.registrations.register_hostname(&hostname, token_hash) {
                Ok(true) => {
                    info!(%hostname, "hostname registered");
                    return Ok(hostname);
                }
                Ok(false) => continue,
                Err(error) => return Err(error),
            }
        }

        anyhow::bail!("unable to allocate an unused hostname after repeated attempts")
    }

    /// Returns the registration timestamps for tests.
    #[cfg(test)]
    pub(crate) fn registration_timestamps(
        &self,
        hostname: &str,
    ) -> Result<(Option<i64>, Option<i64>)> {
        self.registrations.registration_timestamps(hostname)
    }
}

impl RegistrationStore {
    /// Opens the SQLite registration store at the given path.
    pub(crate) fn open(path: &PathBuf) -> Result<Self> {
        let conn = Connection::open(path)
            .map_err(anyhow::Error::from)
            .map(|conn| Self {
                conn: Arc::new(Mutex::new(conn)),
            })?;
        conn.init().map_err(|error| {
            error.context(format!(
                "opening SQLite registration database {}",
                path.display()
            ))
        })?;
        Ok(conn)
    }

    /// Creates an in-memory registration store for tests.
    #[cfg(test)]
    pub(crate) fn in_memory() -> Result<Self> {
        let store = Self {
            conn: Arc::new(Mutex::new(Connection::open_in_memory()?)),
        };
        store.init()?;
        Ok(store)
    }

    /// Initializes the database schema.
    fn init(&self) -> Result<()> {
        let conn = self.lock()?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS registrations (
                hostname TEXT PRIMARY KEY NOT NULL,
                publish_token_hash TEXT,
                created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                last_published_at INTEGER,
                last_tunnel_at INTEGER
            );
            DROP INDEX IF EXISTS registrations_publish_token_hash_idx;
            ",
        )?;

        if !has_column(&conn, "registrations", "publish_token_hash")? {
            conn.execute(
                "ALTER TABLE registrations ADD COLUMN publish_token_hash TEXT",
                [],
            )?;
        }
        if !has_column(&conn, "registrations", "last_published_at")? {
            conn.execute(
                "ALTER TABLE registrations ADD COLUMN last_published_at INTEGER",
                [],
            )?;
        }
        if !has_column(&conn, "registrations", "last_tunnel_at")? {
            conn.execute(
                "ALTER TABLE registrations ADD COLUMN last_tunnel_at INTEGER",
                [],
            )?;
        }

        let duplicate_token_count: i64 = conn.query_row(
            "
            SELECT COUNT(*) FROM (
                SELECT publish_token_hash
                FROM registrations
                WHERE publish_token_hash IS NOT NULL
                GROUP BY publish_token_hash
                HAVING COUNT(*) > 1
            )
            ",
            [],
            |row| row.get(0),
        )?;
        if duplicate_token_count > 0 {
            anyhow::bail!(
                "registration database contains duplicate publish tokens; clean duplicates before startup"
            );
        }

        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS registrations_publish_token_hash_uidx
                ON registrations(publish_token_hash)",
            [],
        )?;
        Ok(())
    }

    /// Inserts a new hostname registration.
    pub(crate) fn register_hostname(&self, hostname: &str, token_hash: &str) -> Result<bool> {
        let conn = self.lock()?;
        let changed = conn.execute(
            "INSERT INTO registrations (hostname, publish_token_hash) VALUES (?1, ?2)",
            params![hostname, token_hash],
        );
        match changed {
            Ok(changed) => Ok(changed == 1),
            Err(error) if is_hostname_uniqueness_error(&error) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// Checks whether a hostname is authorized for a token hash.
    pub(crate) fn publisher_authorized(&self, hostname: &str, token_hash: &str) -> Result<bool> {
        let conn = self.lock()?;
        let registered_token_hash = conn
            .query_row(
                "SELECT publish_token_hash FROM registrations WHERE hostname = ?1",
                params![hostname],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?;
        Ok(match registered_token_hash {
            Some(Some(registered)) => registered == token_hash,
            None => false,
            Some(None) => false,
        })
    }

    /// Resolves the hostname registered to a token hash.
    pub(crate) fn hostname_for_token(&self, token_hash: &str) -> Result<Option<String>> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT hostname FROM registrations WHERE publish_token_hash = ?1 LIMIT 1",
            params![token_hash],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(Into::into)
    }

    /// Updates `last_published_at` for a hostname.
    pub(crate) fn touch_last_published_at(&self, hostname: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE registrations SET last_published_at = unixepoch() WHERE hostname = ?1",
            params![hostname],
        )?;
        Ok(())
    }

    /// Updates `last_tunnel_at` for a hostname.
    pub(crate) fn touch_last_tunnel_at(&self, hostname: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE registrations SET last_tunnel_at = unixepoch() WHERE hostname = ?1",
            params![hostname],
        )?;
        Ok(())
    }

    /// Returns the tracked timestamps for a hostname in tests.
    #[cfg(test)]
    pub(crate) fn registration_timestamps(
        &self,
        hostname: &str,
    ) -> Result<(Option<i64>, Option<i64>)> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT last_published_at, last_tunnel_at FROM registrations WHERE hostname = ?1",
            params![hostname],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(Into::into)
    }

    /// Locks the shared SQLite connection.
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|error| anyhow::anyhow!("SQLite registration database lock poisoned: {error}"))
    }
}

/// Checks whether a SQLite table contains a named column.
fn has_column(conn: &Connection, table: &str, column_name: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for column in columns {
        if column? == column_name {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Checks whether a SQLite error is a hostname uniqueness violation.
pub(crate) fn is_hostname_uniqueness_error(error: &SqlError) -> bool {
    matches!(
        error,
        SqlError::SqliteFailure(failure, Some(message))
            if failure.code == ErrorCode::ConstraintViolation
                && message.contains("registrations.hostname")
    )
}

/// Checks whether an anyhow error wraps a publish token uniqueness violation.
pub(crate) fn is_publish_token_uniqueness_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<SqlError>().is_some_and(|error| {
        matches!(
            error,
            SqlError::SqliteFailure(failure, Some(message))
                if failure.code == ErrorCode::ConstraintViolation
                    && message.contains("registrations.publish_token_hash")
        )
    })
}
