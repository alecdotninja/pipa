//! Regression tests for core hostname, token, and registration behavior.

use crate::{messages::Policy, registry::Registry, util::*};

/// Verifies that hostname policy matching stays inside the configured suffix.
#[test]
fn hostname_policy_stays_inside_domain() {
    let policy = Policy {
        max_tunnels_per_publisher: 10,
        relay_hostname: "pipa.sh".to_string(),
    };

    assert!(policy.hostname_allowed("abc.pipa.sh"));
    assert!(!policy.hostname_allowed("pipa.sh"));
    assert!(!policy.hostname_allowed("abc.pipa.sh.evil"));
    assert!(!policy.hostname_allowed("abc_pipa.sh"));
    assert!(!policy.hostname_allowed("-abc.pipa.sh"));
    assert!(!policy.hostname_allowed("abc-.pipa.sh"));
}

/// Verifies FQDN normalization and hostname syntax rules.
#[test]
fn fqdn_normalization_for_dns_queries() {
    assert_eq!(fqdn("Demo.Jump.Service."), "demo.jump.service.");
    assert!(hostname_syntax_allowed("ssh.example.com"));
    assert!(!hostname_syntax_allowed("ssh..example.com"));
    assert!(!hostname_syntax_allowed("_ssh.example.com"));
}

/// Verifies the usage text still includes the direct ProxyJump guidance.
#[test]
fn usage_text_contains_proxyjump_config() {
    let policy = Policy {
        max_tunnels_per_publisher: 10,
        relay_hostname: "pipa.sh".to_string(),
    };

    let usage = policy.messages().usage();
    assert!(!usage.contains("Host pipa-relay"));
    assert!(!usage.contains("User client"));
    assert!(usage.contains("ProxyJump pipa.sh"));
    assert!(usage.contains("Host *.pipa.sh"));
}

/// Verifies the relay banner preserves its exact ASCII art prefix.
#[test]
fn header_preserves_ascii_art_prefix() {
    let policy = Policy {
        max_tunnels_per_publisher: 10,
        relay_hostname: "pipa.sh".to_string(),
    };

    let header = policy.messages().header();
    let lines: Vec<_> = header.lines().collect();
    assert_eq!(
        lines[0],
        "           __                                    __"
    );
    assert_eq!(
        lines[1],
        "          |  \\                                  |  \\"
    );
    assert_eq!(
        lines[2],
        "  ______   \\$$  ______    ______        _______ | $$____"
    );
    assert!(!header.contains("\\\\"));
}

/// Verifies generated labels are safe DNS labels.
#[test]
fn random_labels_are_valid_host_labels() {
    let label = random_label();
    assert_eq!(label.len(), 10);
    assert!(label_bytes_allowed(&label));
}

/// Verifies generated tokens are accepted as SSH usernames.
#[test]
fn publish_tokens_are_valid_usernames() {
    let token = random_token();
    assert!(valid_publish_token(&token));
    assert_eq!(publish_token_from_user(&token), Some(token.as_str()));
    assert_eq!(publish_token_from_user("publish"), None);
    assert_eq!(publish_token_from_user("short"), None);
    assert_eq!(publish_token_from_user("aaaaaaaaaaaaaaaaaaaaaaa!"), None);
}

/// Verifies a registration only authorizes the token that created it.
#[tokio::test]
async fn persisted_registration_authorizes_only_that_token() {
    let registry = Registry::new(crate::registry::RegistrationStore::in_memory().unwrap());
    let token_a = token_hash("token-a");
    let token_b = token_hash("token-b");
    let hostname = registry
        .register_random_hostname("pipa.sh", &token_a)
        .await
        .unwrap();

    assert!(hostname.ends_with(".pipa.sh"));
    assert!(registry.publisher_authorized(&hostname, &token_a).await);
    assert!(!registry.publisher_authorized(&hostname, &token_b).await);
}

/// Verifies unknown hostnames never authorize a token.
#[tokio::test]
async fn unknown_registration_does_not_authorize_token() {
    let registry = Registry::new(crate::registry::RegistrationStore::in_memory().unwrap());
    assert!(
        !registry
            .publisher_authorized("missing.pipa.sh", &token_hash("registered-token"))
            .await
    );
}

/// Verifies the reverse lookup from token hash to hostname.
#[tokio::test]
async fn token_lookup_returns_registered_hostname() {
    let registry = Registry::new(crate::registry::RegistrationStore::in_memory().unwrap());
    let token = token_hash("token-a");
    let hostname = registry
        .register_random_hostname("pipa.sh", &token)
        .await
        .unwrap();

    assert_eq!(registry.hostname_for_token(&token).await, Some(hostname));
    assert_eq!(
        registry.hostname_for_token(&token_hash("missing")).await,
        None
    );
}

/// Verifies the registration timestamps are updated when touched.
#[tokio::test]
async fn registration_timestamps_update() {
    let registry = Registry::new(crate::registry::RegistrationStore::in_memory().unwrap());
    let token = token_hash("token-a");
    let hostname = registry
        .register_random_hostname("pipa.sh", &token)
        .await
        .unwrap();

    assert_eq!(
        registry.registration_timestamps(&hostname).unwrap(),
        (None, None)
    );

    registry.touch_last_published_at(&hostname).await;
    registry.touch_last_tunnel_at(&hostname).await;

    let (last_published_at, last_tunnel_at) = registry.registration_timestamps(&hostname).unwrap();
    assert!(last_published_at.is_some());
    assert!(last_tunnel_at.is_some());
}
