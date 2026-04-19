//! SSH server implementations for the relay and usage listeners.

use std::{
    sync::atomic::Ordering,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use russh::{
    keys::{ssh_key, Certificate},
    server::{self, Auth, Msg, Session},
    Channel, ChannelId, ChannelMsg, Disconnect, Pty, Sig,
};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::{
    app::AppState,
    dns::{DnsAliasResolver, ResolvedHostname},
    messages::Policy,
    registry::{PublisherRoute, Registry},
    util::{
        hostname_syntax_allowed, normalize_domain, publish_token_from_user, to_crlf, SSH_PORT,
        SSH_PORT_OR_ALIAS,
    },
};

/// SSH server for the relay listener.
#[derive(Clone)]
pub(crate) struct RelayServer {
    /// Shared relay state.
    pub(crate) state: std::sync::Arc<AppState>,
}

/// SSH server for the usage-only listener.
#[derive(Clone)]
pub(crate) struct UsageServer {
    /// Policy and message generation for the usage listener.
    pub(crate) policy: std::sync::Arc<Policy>,
}

/// Per-connection handler for the relay listener.
#[derive(Clone)]
pub(crate) struct RelayHandler {
    /// Remote peer socket address.
    pub(crate) peer: Option<std::net::SocketAddr>,
    /// Active route registry and persistent registrations.
    pub(crate) registry: Registry,
    /// Relay policy and messages.
    pub(crate) policy: std::sync::Arc<Policy>,
    /// DNS resolver for CNAME dispatch.
    pub(crate) resolver: DnsAliasResolver,
    /// Current connection role.
    pub(crate) role: Role,
    /// Monotonic session identifier.
    pub(crate) session_id: u64,
    /// Registered hostname published by this session, if any.
    pub(crate) published_hostname: Option<String>,
    /// Hashed bearer token for this publisher, if any.
    pub(crate) publisher_token_hash: Option<String>,
    /// Session channel used for publisher status output.
    pub(crate) publisher_status_channel: Option<ChannelId>,
}

/// Per-connection handler for the usage listener.
#[derive(Clone)]
pub(crate) struct UsageHandler {
    /// Remote peer socket address.
    pub(crate) peer: Option<std::net::SocketAddr>,
    /// Policy and message generation.
    pub(crate) policy: std::sync::Arc<Policy>,
}

/// Authenticated role for a relay connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Role {
    /// Session has not yet identified as publisher or generic client.
    Unknown,
    /// Session authenticated with a valid publish token.
    Publisher,
    /// Session is a non-publisher client or setup user.
    Client,
}

impl server::Server for RelayServer {
    type Handler = RelayHandler;

    /// Builds a new relay handler for an accepted TCP connection.
    fn new_client(&mut self, peer: Option<std::net::SocketAddr>) -> RelayHandler {
        RelayHandler {
            peer,
            registry: self.state.registry.clone(),
            policy: self.state.policy.clone(),
            resolver: self.state.resolver.clone(),
            session_id: self.state.next_session_id.fetch_add(1, Ordering::Relaxed),
            role: Role::Unknown,
            published_hostname: None,
            publisher_token_hash: None,
            publisher_status_channel: None,
        }
    }

    /// Logs handler-level session errors.
    fn handle_session_error(&mut self, error: <Self::Handler as server::Handler>::Error) {
        warn!(?error, "ssh session error");
    }
}

impl server::Server for UsageServer {
    type Handler = UsageHandler;

    /// Builds a new usage handler for an accepted TCP connection.
    fn new_client(&mut self, peer: Option<std::net::SocketAddr>) -> UsageHandler {
        UsageHandler {
            peer,
            policy: self.policy.clone(),
        }
    }

    /// Logs handler-level session errors.
    fn handle_session_error(&mut self, error: <Self::Handler as server::Handler>::Error) {
        warn!(?error, "ssh session error");
    }
}

impl RelayHandler {
    /// Interprets a username as a publisher token and updates the role when valid.
    fn authenticate_publish_token(&mut self, user: &str) -> bool {
        let Some(token) = publish_token_from_user(user) else {
            return false;
        };

        self.role = Role::Publisher;
        self.publisher_token_hash = Some(crate::util::token_hash(token));
        true
    }

    /// Allocates a hostname and prints the registration output before closing.
    async fn register_and_close(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let (hostname, token) = match self
            .registry
            .register_random_hostname_with_token(&self.policy.relay_hostname)
            .await
        {
            Ok(allocation) => allocation,
            Err(error) => {
                warn!(peer = ?self.peer, ?error, "publisher registration failed");
                session.data(
                    channel,
                    to_crlf(&self.policy.messages().registration_failure()),
                )?;
                session.eof(channel)?;
                session.close(channel)?;
                return Ok(());
            }
        };
        let text = self
            .policy
            .messages()
            .registration_success(&hostname, &token);
        session.data(channel, to_crlf(&text))?;
        session.eof(channel)?;
        session.close(channel)?;
        info!(peer = ?self.peer, %hostname, "publisher registration created");
        Ok(())
    }

    /// Reports a publisher failure on the session channel and disconnects.
    fn fail_publisher_session(
        &mut self,
        session: &mut Session,
        detail: &str,
    ) -> Result<(), russh::Error> {
        let message = self.policy.messages().publish_failure_disconnect(detail);
        let text = self.policy.messages().publish_failure_session(detail);
        if let Some(channel) = self.publisher_status_channel {
            session.data(channel, to_crlf(&text))?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        session.disconnect(Disconnect::ByApplication, &message, "en")?;
        Ok(())
    }

    /// Disconnects a client route request with a short reason.
    fn fail_client_route(
        &mut self,
        session: &mut Session,
        detail: &str,
    ) -> Result<(), russh::Error> {
        session.disconnect(Disconnect::ByApplication, detail, "en")?;
        Ok(())
    }

    /// Resolves the hostname to publish for a forwarding request.
    async fn resolve_publish_hostname(
        &self,
        requested_address: &str,
        requested_port: u32,
    ) -> Result<Option<ResolvedHostname>> {
        let requested_address = normalize_domain(requested_address);
        if matches!(requested_address.as_str(), "" | "localhost")
            && SSH_PORT_OR_ALIAS.contains(&requested_port)
        {
            let Some(token_hash) = self.publisher_token_hash.as_deref() else {
                return Ok(None);
            };
            let Some(registered_hostname) = self.registry.hostname_for_token(token_hash).await
            else {
                return Ok(None);
            };
            return Ok(Some(ResolvedHostname {
                requested_hostname: "localhost".to_string(),
                registered_hostname,
                cname_chain: Vec::new(),
            }));
        }

        self.resolver
            .resolve_registered_hostname(&self.policy, &requested_address)
            .await
    }
}

impl server::Handler for RelayHandler {
    type Error = russh::Error;

    /// Suppresses the generic SSH authentication banner.
    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(None)
    }

    /// Accepts auth-none and upgrades to publisher role when the username is a token.
    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        if self.authenticate_publish_token(user) {
            info!(peer = ?self.peer, user, "publisher authenticated with bearer token");
            return Ok(Auth::Accept);
        }
        self.role = Role::Client;
        info!(peer = ?self.peer, user, "client authenticated with relay auth-none");
        Ok(Auth::Accept)
    }

    /// Accepts password auth and upgrades to publisher role when the username is a token.
    async fn auth_password(&mut self, user: &str, _password: &str) -> Result<Auth, Self::Error> {
        if self.authenticate_publish_token(user) {
            info!(peer = ?self.peer, user, "publisher authenticated with bearer token");
            return Ok(Auth::Accept);
        }
        self.role = Role::Client;
        info!(peer = ?self.peer, user, "client authenticated with relay password");
        Ok(Auth::Accept)
    }

    /// Accepts public-key offers so stock OpenSSH can proceed even though tokens are username-only.
    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        _public_key: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        if publish_token_from_user(user).is_some() {
            debug!(peer = ?self.peer, user, "publisher token user public key offered");
            return Ok(Auth::Accept);
        }
        self.role = Role::Client;
        Ok(Auth::Accept)
    }

    /// Accepts public-key auth and upgrades to publisher role when the username is a token.
    async fn auth_publickey(
        &mut self,
        user: &str,
        _public_key: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        if self.authenticate_publish_token(user) {
            info!(peer = ?self.peer, user, "publisher authenticated with bearer token");
            return Ok(Auth::Accept);
        }

        self.role = Role::Client;
        info!(peer = ?self.peer, user, "client authenticated with public key");
        Ok(Auth::Accept)
    }

    /// Accepts certificate auth and upgrades to publisher role when the username is a token.
    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        _certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        if self.authenticate_publish_token(user) {
            info!(peer = ?self.peer, user, "publisher authenticated with bearer token");
            return Ok(Auth::Accept);
        }

        self.role = Role::Client;
        info!(peer = ?self.peer, user, "client authenticated with OpenSSH certificate");
        Ok(Auth::Accept)
    }

    /// Accepts keyboard-interactive auth and upgrades to publisher role when the username is a token.
    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        _response: Option<server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        if self.authenticate_publish_token(user) {
            info!(peer = ?self.peer, user, "publisher authenticated with bearer token");
            return Ok(Auth::Accept);
        }
        self.role = Role::Client;
        info!(peer = ?self.peer, user, "client authenticated with relay keyboard-interactive");
        Ok(Auth::Accept)
    }

    /// Accepts session channels for registration and publisher status output.
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        info!(
            peer = ?self.peer,
            channel = ?channel.id(),
            "session channel accepted for one-shot instructions"
        );
        Ok(true)
    }

    /// Accepts PTY requests even though the relay never offers a real shell.
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    /// Handles shell requests as either publisher status or one-shot registration.
    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.role == Role::Publisher {
            self.publisher_status_channel = Some(channel);
            session.channel_success(channel)?;
            if let Some(hostname) = self.published_hostname.clone() {
                self.registry
                    .set_status_channel_if_current(&hostname, self.session_id, Some(channel))
                    .await;
                session.data(
                    channel,
                    to_crlf(&self.policy.messages().publisher_status_intro(&hostname)),
                )?;
            }
            return Ok(());
        }
        self.register_and_close(channel, session).await
    }

    /// Handles exec requests as one-shot registration unless this is a publisher status session.
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.role == Role::Publisher {
            session.channel_failure(channel)?;
            return Ok(());
        }
        self.register_and_close(channel, session).await
    }

    /// Rejects subsystems and falls back to registration output for non-publishers.
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.role == Role::Publisher {
            session.channel_failure(channel)?;
            return Ok(());
        }
        session.channel_failure(channel)?;
        self.register_and_close(channel, session).await
    }

    /// Rejects agent forwarding.
    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        session.channel_failure(channel)?;
        Ok(false)
    }

    /// Routes client `direct-tcpip` requests to active publishers.
    async fn channel_open_direct_tcpip(
        &mut self,
        client_channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        info!(
            peer = ?self.peer,
            host = host_to_connect,
            port = port_to_connect,
            originator_address,
            originator_port,
            "client connect attempt"
        );

        if port_to_connect != SSH_PORT {
            warn!(
                peer = ?self.peer,
                host = host_to_connect,
                port = port_to_connect,
                "route rejected: only port 22 is allowed"
            );
            self.fail_client_route(session, self.policy.messages().client_route_invalid_port())?;
            return Ok(false);
        }

        let requested_hostname = normalize_domain(host_to_connect);
        if !hostname_syntax_allowed(&requested_hostname) {
            warn!(
                peer = ?self.peer,
                host = host_to_connect,
                "route rejected: hostname syntax is invalid"
            );
            self.fail_client_route(
                session,
                self.policy.messages().client_route_invalid_hostname(),
            )?;
            return Ok(false);
        }

        let resolved = match self
            .resolver
            .resolve_registered_route(&self.registry, &self.policy, &requested_hostname)
            .await
        {
            Ok(Some(resolved)) => resolved,
            Ok(None) => {
                warn!(
                    peer = ?self.peer,
                    host = host_to_connect,
                    "route rejected: no active registered publisher after DNS resolution"
                );
                self.fail_client_route(
                    session,
                    self.policy.messages().client_route_no_publisher(),
                )?;
                return Ok(false);
            }
            Err(error) => {
                warn!(
                    peer = ?self.peer,
                    host = host_to_connect,
                    ?error,
                    "route rejected: DNS resolution failed"
                );
                self.fail_client_route(session, self.policy.messages().client_route_dns_failure())?;
                return Ok(false);
            }
        };

        let publisher_tunnel_permit =
            match resolved.route.tunnel_limiter.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    warn!(
                        host = host_to_connect,
                        registered_hostname = %resolved.registered_hostname,
                        "route rejected: publisher tunnel limit reached"
                    );
                    self.fail_client_route(session, self.policy.messages().client_route_limit())?;
                    return Ok(false);
                }
            };

        let requested_host = resolved.requested_hostname.clone();
        let registered_host = resolved.registered_hostname.clone();
        let cname_chain = resolved.cname_chain.clone();
        let client_peer = self.peer;
        let registry = self.registry.clone();
        let policy = self.policy.clone();
        let route = resolved.route;
        let client_ip = client_peer.map(|peer| peer.ip().to_string());
        let publisher_ip = route.publisher_peer.map(|peer| peer.ip().to_string());
        let origin = originator_address.to_owned();

        tokio::spawn(async move {
            let _publisher_tunnel_permit = publisher_tunnel_permit;
            let result = async {
                let publisher_channel = match route
                    .handle
                    .channel_open_forwarded_tcpip(
                        route.publisher_forward_host.clone(),
                        SSH_PORT,
                        origin,
                        originator_port,
                    )
                    .await
                {
                    Ok(channel) => channel,
                    Err(error) => {
                        let _ = client_channel.close().await;
                        return Err(error.into());
                    }
                };

                info!(
                    requested_hostname = %requested_host,
                    registered_hostname = %registered_host,
                    cname_chain = ?cname_chain,
                    client_peer = ?client_peer,
                    client_ip = client_ip.as_deref(),
                    publisher_peer = ?route.publisher_peer,
                    publisher_ip = publisher_ip.as_deref(),
                    publisher_token_hash = %route.token_hash,
                    "tunnel connected"
                );

                registry.touch_last_tunnel_at(&registered_host).await;
                if let Some(status_channel) = route.status_channel {
                    let _ = route
                        .handle
                        .data(
                            status_channel,
                            policy.messages().tunnel_notice(
                                SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                                client_ip.as_deref().unwrap_or("unknown"),
                                originator_port,
                                &requested_host,
                                &registered_host,
                            ),
                        )
                        .await;
                }

                bridge_channels(requested_host.clone(), client_channel, publisher_channel).await
            }
            .await;

            match result {
                Ok(()) => {
                    info!(
                        requested_hostname = %requested_host,
                        registered_hostname = %registered_host,
                        "route closed"
                    )
                }
                Err(error) => {
                    warn!(
                        requested_hostname = %requested_host,
                        registered_hostname = %registered_host,
                        ?error,
                        "route failed"
                    )
                }
            }
        });

        Ok(true)
    }

    /// Handles publisher `tcpip-forward` requests.
    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if !SSH_PORT_OR_ALIAS.contains(port) {
            warn!(peer = ?self.peer, address, port = *port, "publish rejected: only port 22 is allowed");
            self.fail_publisher_session(session, self.policy.messages().publish_invalid_port())?;
            return Ok(false);
        }

        let Some(token_hash) = self.publisher_token_hash.clone() else {
            warn!(peer = ?self.peer, address, "publish rejected: missing publisher token");
            self.fail_publisher_session(session, self.policy.messages().publish_missing_token())?;
            return Ok(false);
        };

        let resolved = match self.resolve_publish_hostname(address, *port).await {
            Ok(Some(resolved)) => resolved,
            Ok(None) => {
                warn!(
                    peer = ?self.peer,
                    address,
                    "publish rejected: hostname is outside service domain after DNS resolution"
                );
                self.fail_publisher_session(
                    session,
                    self.policy.messages().publish_hostname_mismatch(),
                )?;
                return Ok(false);
            }
            Err(error) => {
                warn!(peer = ?self.peer, address, ?error, "publish rejected: DNS resolution failed");
                self.fail_publisher_session(session, self.policy.messages().publish_dns_failure())?;
                return Ok(false);
            }
        };

        if !self
            .registry
            .publisher_authorized(&resolved.registered_hostname, &token_hash)
            .await
        {
            warn!(
                peer = ?self.peer,
                address,
                requested_hostname = %resolved.requested_hostname,
                registered_hostname = %resolved.registered_hostname,
                cname_chain = ?resolved.cname_chain,
                "publish rejected: hostname is not allocated or authorized for this publisher"
            );
            self.fail_publisher_session(
                session,
                self.policy.messages().publish_token_hostname_mismatch(),
            )?;
            return Ok(false);
        }

        if *port == 0 {
            *port = SSH_PORT;
        }

        let route = PublisherRoute {
            session_id: self.session_id,
            token_hash,
            handle: session.handle(),
            publisher_peer: self.peer,
            publisher_forward_host: resolved.requested_hostname.clone(),
            tunnel_limiter: std::sync::Arc::new(Semaphore::new(
                self.policy.max_tunnels_per_publisher,
            )),
            status_channel: self.publisher_status_channel,
        };

        self.registry
            .insert(resolved.registered_hostname.clone(), route)
            .await;
        self.registry
            .touch_last_published_at(&resolved.registered_hostname)
            .await;
        self.published_hostname = Some(resolved.registered_hostname.clone());

        if let Some(channel) = self.publisher_status_channel {
            session.data(
                channel,
                to_crlf(
                    &self
                        .policy
                        .messages()
                        .publisher_status_intro(&resolved.registered_hostname),
                ),
            )?;
        }

        info!(
            peer = ?self.peer,
            requested_hostname = %resolved.requested_hostname,
            registered_hostname = %resolved.registered_hostname,
            cname_chain = ?resolved.cname_chain,
            "route established for publisher"
        );
        Ok(true)
    }

    /// Removes the active route on publisher forward cancellation.
    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if SSH_PORT_OR_ALIAS.contains(&port) {
            let hostname = match self.resolve_publish_hostname(address, port).await {
                Ok(Some(resolved)) => resolved.registered_hostname,
                Ok(None) | Err(_) => normalize_domain(address),
            };
            self.registry
                .remove_if_current(&hostname, self.session_id)
                .await;
            info!(peer = ?self.peer, hostname = %hostname, "route removed by publisher");
            return Ok(true);
        }
        Ok(false)
    }

    /// Handles input on the publisher status channel, including Ctrl-C.
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.role == Role::Publisher
            && self.publisher_status_channel == Some(channel)
            && data.contains(&0x03)
        {
            info!(
                peer = ?self.peer,
                ?channel,
                "publisher status session interrupted by ctrl-c"
            );
            session.eof(channel)?;
            session.close(channel)?;
            return Ok(());
        }
        debug!(
            peer = ?self.peer,
            ?channel,
            "ignoring client data on relay-owned session channel"
        );
        Ok(())
    }

    /// Handles signals on the publisher status channel.
    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.role == Role::Publisher
            && self.publisher_status_channel == Some(channel)
            && matches!(signal, Sig::INT | Sig::TERM | Sig::HUP)
        {
            info!(
                peer = ?self.peer,
                ?channel,
                ?signal,
                "publisher status session closed by signal"
            );
            session.eof(channel)?;
            session.close(channel)?;
        }
        Ok(())
    }
}

impl server::Handler for UsageHandler {
    type Error = russh::Error;

    /// Suppresses the generic SSH authentication banner.
    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(None)
    }

    /// Accepts auth-none on the usage listener.
    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        info!(peer = ?self.peer, user, "client authenticated with usage auth-none");
        Ok(Auth::Accept)
    }

    /// Accepts password auth on the usage listener.
    async fn auth_password(&mut self, user: &str, _password: &str) -> Result<Auth, Self::Error> {
        info!(peer = ?self.peer, user, "client authenticated with usage password");
        Ok(Auth::Accept)
    }

    /// Accepts public-key offers on the usage listener.
    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _public_key: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    /// Accepts public-key auth on the usage listener.
    async fn auth_publickey(
        &mut self,
        user: &str,
        _public_key: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        info!(peer = ?self.peer, user, "client authenticated with usage public key");
        Ok(Auth::Accept)
    }

    /// Accepts certificate auth on the usage listener.
    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        _certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        info!(peer = ?self.peer, user, "client authenticated with usage OpenSSH certificate");
        Ok(Auth::Accept)
    }

    /// Accepts keyboard-interactive auth on the usage listener.
    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        _response: Option<server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        info!(
            peer = ?self.peer,
            user,
            "client authenticated with usage keyboard-interactive"
        );
        Ok(Auth::Accept)
    }

    /// Accepts session channels for one-shot usage output.
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        info!(
            peer = ?self.peer,
            channel = ?channel.id(),
            "usage session channel accepted"
        );
        Ok(true)
    }

    /// Accepts PTY requests on the usage listener.
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    /// Prints the usage text and closes the session.
    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!(peer = ?self.peer, ?channel, "printing usage directions and closing session");
        session.channel_success(channel)?;
        session.data(channel, to_crlf(&self.policy.messages().usage()))?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    /// Treats exec requests the same as shell requests.
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.shell_request(channel, session).await
    }

    /// Rejects subsystems and then prints the usage text.
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        self.shell_request(channel, session).await
    }

    /// Rejects agent forwarding.
    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        session.channel_failure(channel)?;
        Ok(false)
    }
}

impl Drop for RelayHandler {
    /// Removes the active route when the relay session drops.
    fn drop(&mut self) {
        if let Some(hostname) = self.published_hostname.take() {
            let registry = self.registry.clone();
            let session_id = self.session_id;
            tokio::spawn(async move {
                registry.remove_if_current(&hostname, session_id).await;
                info!(%hostname, "route removed after publisher disconnect");
            });
        }
    }
}

/// Bridges bytes between the client and publisher channels.
async fn bridge_channels(
    hostname: String,
    mut left: Channel<Msg>,
    mut right: Channel<Msg>,
) -> Result<()> {
    let mut left_eof = false;
    let mut right_eof = false;

    loop {
        tokio::select! {
            msg = left.wait(), if !left_eof => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        right.data(&data[..]).await?;
                    }
                    Some(ChannelMsg::Eof) | None => {
                        left_eof = true;
                        right.eof().await?;
                    }
                    Some(ChannelMsg::WindowAdjusted { .. }) => {}
                    Some(ChannelMsg::Close) => break,
                    Some(other) => debug!(%hostname, ?other, "ignored client channel message"),
                }
            }
            msg = right.wait(), if !right_eof => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        left.data(&data[..]).await?;
                    }
                    Some(ChannelMsg::Eof) | None => {
                        right_eof = true;
                        left.eof().await?;
                    }
                    Some(ChannelMsg::WindowAdjusted { .. }) => {}
                    Some(ChannelMsg::Close) => break,
                    Some(other) => debug!(%hostname, ?other, "ignored publisher channel message"),
                }
            }
            else => break,
        }

        if left_eof && right_eof {
            break;
        }
    }

    let _ = left.close().await;
    let _ = right.close().await;
    Ok(())
}
