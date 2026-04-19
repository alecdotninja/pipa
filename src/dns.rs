//! DNS and CNAME resolution for published hostnames.

use anyhow::{Context, Result};
use hickory_resolver::{
    error::{ResolveError, ResolveErrorKind},
    proto::rr::{RData, RecordType},
    TokioAsyncResolver,
};
use tracing::debug;

use crate::{
    messages::Policy,
    registry::{PublisherRoute, Registry},
    util::{fqdn, normalize_domain},
};

/// DNS resolver wrapper for following CNAME chains into relay hostnames.
#[derive(Clone)]
pub(crate) struct DnsAliasResolver {
    /// Async system-configured resolver.
    resolver: TokioAsyncResolver,
    /// Maximum number of chained CNAMEs to follow.
    max_depth: usize,
}

/// Resolved active route for a requested hostname.
#[derive(Clone)]
pub(crate) struct ResolvedRoute {
    /// Hostname requested by the client.
    pub(crate) requested_hostname: String,
    /// Registered hostname that owns the active route.
    pub(crate) registered_hostname: String,
    /// CNAME chain followed to resolve the registered hostname.
    pub(crate) cname_chain: Vec<String>,
    /// Active publisher route for the hostname.
    pub(crate) route: PublisherRoute,
}

/// Resolved registered hostname without the active route.
#[derive(Clone)]
pub(crate) struct ResolvedHostname {
    /// Hostname originally requested by the caller.
    pub(crate) requested_hostname: String,
    /// Registered hostname after following CNAMEs.
    pub(crate) registered_hostname: String,
    /// CNAME chain followed during resolution.
    pub(crate) cname_chain: Vec<String>,
}

impl DnsAliasResolver {
    /// Builds a resolver from the system DNS configuration.
    pub(crate) fn system(max_depth: usize) -> Result<Self> {
        Ok(Self {
            resolver: TokioAsyncResolver::tokio_from_system_conf()
                .context("creating DNS resolver from system configuration")?,
            max_depth,
        })
    }

    /// Resolves a requested hostname to an active registered route.
    pub(crate) async fn resolve_registered_route(
        &self,
        registry: &Registry,
        policy: &Policy,
        requested_hostname: &str,
    ) -> Result<Option<ResolvedRoute>> {
        let Some(resolved) = self
            .resolve_registered_hostname(policy, requested_hostname)
            .await?
        else {
            return Ok(None);
        };

        let Some(route) = registry.get(&resolved.registered_hostname).await else {
            return Ok(None);
        };

        Ok(Some(ResolvedRoute {
            requested_hostname: resolved.requested_hostname,
            registered_hostname: resolved.registered_hostname,
            cname_chain: resolved.cname_chain,
            route,
        }))
    }

    /// Resolves a requested hostname to a registered hostname in the relay namespace.
    pub(crate) async fn resolve_registered_hostname(
        &self,
        policy: &Policy,
        requested_hostname: &str,
    ) -> Result<Option<ResolvedHostname>> {
        let requested_hostname = normalize_domain(requested_hostname);
        if policy.hostname_allowed(&requested_hostname) {
            return Ok(Some(ResolvedHostname {
                requested_hostname: requested_hostname.clone(),
                registered_hostname: requested_hostname,
                cname_chain: Vec::new(),
            }));
        }

        let mut current = requested_hostname.clone();
        let mut chain = Vec::new();
        let max_depth = self.max_depth.max(1);

        for _ in 0..max_depth {
            match self.lookup_cname(&current).await? {
                Some(next) => {
                    if chain.iter().any(|seen| seen == &next) || next == current {
                        anyhow::bail!("CNAME loop while resolving {requested_hostname}");
                    }
                    chain.push(next.clone());
                    current = next;
                }
                None => {
                    if !policy.hostname_allowed(&current) {
                        debug!(
                            requested_hostname,
                            resolved_hostname = %current,
                            "DNS chain terminated outside the service domain"
                        );
                        return Ok(None);
                    }

                    return Ok(Some(ResolvedHostname {
                        requested_hostname,
                        registered_hostname: current,
                        cname_chain: chain,
                    }));
                }
            }
        }

        anyhow::bail!("CNAME depth exceeded while resolving {requested_hostname}")
    }

    /// Looks up a single CNAME target for a hostname.
    async fn lookup_cname(&self, hostname: &str) -> Result<Option<String>> {
        match self
            .resolver
            .lookup(fqdn(hostname), RecordType::CNAME)
            .await
        {
            Ok(lookup) => Ok(lookup
                .iter()
                .find_map(cname_target)
                .map(|name| normalize_domain(&name))),
            Err(error) if is_no_records(&error) => Ok(None),
            Err(error) => Err(error).with_context(|| format!("looking up CNAME for {hostname}")),
        }
    }
}

/// Extracts a CNAME target from a resolver record.
fn cname_target(record: &RData) -> Option<String> {
    match record {
        RData::CNAME(name) => Some(name.to_utf8()),
        _ => None,
    }
}

/// Checks whether a resolver error indicates missing records.
fn is_no_records(error: &ResolveError) -> bool {
    matches!(error.kind(), ResolveErrorKind::NoRecordsFound { .. })
}
