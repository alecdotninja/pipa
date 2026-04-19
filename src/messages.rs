//! User-facing text and policy-derived messaging.

use crate::util::hostname_syntax_allowed;

/// Relay policy configuration.
pub(crate) struct Policy {
    /// Maximum number of concurrent tunnels allowed per published hostname.
    pub(crate) max_tunnels_per_publisher: usize,
    /// Public relay hostname used in generated instructions and hostname validation.
    pub(crate) relay_hostname: String,
}

/// View over the user-facing messages derived from a policy.
pub(crate) struct Messages<'a> {
    /// Backing policy for dynamic message values.
    pub(crate) policy: &'a Policy,
}

impl Policy {
    /// Returns the message helper view for this policy.
    pub(crate) fn messages(&self) -> Messages<'_> {
        Messages { policy: self }
    }

    /// Checks whether a hostname belongs to the relay-managed namespace.
    pub(crate) fn hostname_allowed(&self, hostname: &str) -> bool {
        let hostname = hostname.trim_end_matches('.');
        if !hostname_syntax_allowed(hostname) {
            return false;
        }
        hostname.ends_with(&self.relay_hostname)
            && hostname.len() > self.relay_hostname.len() + 1
            && hostname.as_bytes()[hostname.len() - self.relay_hostname.len() - 1] == b'.'
    }
}

impl Messages<'_> {
    /// Returns the shared relay banner and abuse note.
    pub(crate) fn header(&self) -> String {
        format!(
            "\
           __                                    __
          |  \\                                  |  \\
  ______   \\$$  ______    ______        _______ | $$____
 /      \\ |  \\ /      \\  |      \\      /       \\| $$    \\
|  $$$$$$\\| $$|  $$$$$$\\  \\$$$$$$\\    |  $$$$$$$| $$$$$$$\\
| $$  | $$| $$| $$  | $$ /      $$     \\$$    \\ | $$  | $$
| $$__/ $$| $$| $$__/ $$|  $$$$$$$ __  _\\$$$$$$\\| $$  | $$
| $$    $$| $$| $$    $$ \\$$    $$|  \\|       $$| $$  | $$
| $$$$$$$  \\$$| $$$$$$$   \\$$$$$$$ \\$$ \\$$$$$$$  \\$$   \\$$
| $$          | $$
| $$          | $$
 \\$$           \\$$

Free public SSH relay at pipa.sh. Please play nice:

    - bandwidth per connection is limited
    - each published hostname can handle {limit} connections at a time
    - please respect other users
    - please don't do anything that would get me banned from OVH
",
            limit = self.policy.max_tunnels_per_publisher,
        )
    }

    /// Returns the usage instructions shown on the usage listener.
    pub(crate) fn usage(&self) -> String {
        format!(
            "\
{header}
This host is published through pipa.sh.

Add this to ~/.ssh/config:

    Host *.{relay_host}
        HostName %h
        ProxyJump {relay_host}

For a custom CNAME, add a section like this:

    Host ssh.example.com
        HostName %h
        ProxyJump {relay_host}

Then connect normally:

    $ ssh some-host.{relay_host}
",
            header = self.header(),
            relay_host = self.policy.relay_hostname,
        )
    }

    /// Returns the registration success message and publish instructions.
    pub(crate) fn registration_success(&self, hostname: &str, token: &str) -> String {
        format!(
            "\
{header}
Your relay hostname is ready:

  {hostname}

Run this on the machine that has the SSH server you want to publish:

  $ ssh -R 22:localhost:22 {token}@{relay_host}

Then clients connect like this:

  $ ssh {hostname}

Keep that publish command private. The token inside it controls this
hostname.

You can also point a custom domain at it with a CNAME record.
",
            header = self.header(),
            hostname = hostname,
            token = token,
            relay_host = self.policy.relay_hostname,
        )
    }

    /// Returns the registration failure message.
    pub(crate) fn registration_failure(&self) -> String {
        format!(
            "\
{header}
Registration failed.

pipa.sh could not save a hostname right now. Please try again.
",
            header = self.header(),
        )
    }

    /// Returns the publisher status stream intro after a hostname is actively published.
    pub(crate) fn publisher_status_intro(&self, registered_hostname: &str) -> String {
        format!(
            "\
{header}
Now publishing:

  {registered_hostname}

I will print one line below for each client connection.
",
            header = self.header(),
            registered_hostname = registered_hostname,
        )
    }

    /// Returns the plain disconnect text for a failed publish attempt.
    pub(crate) fn publish_failure_disconnect(&self, detail: &str) -> String {
        format!(
            "\
That publish command is not valid here.

{detail}

Get a fresh one with:

    $ ssh {relay_host}
",
            relay_host = self.policy.relay_hostname,
        )
    }

    /// Returns the full session text for a failed publish attempt.
    pub(crate) fn publish_failure_session(&self, detail: &str) -> String {
        format!(
            "\
{header}
{body}
",
            header = self.header(),
            body = self.publish_failure_disconnect(detail),
        )
    }

    /// Returns the detail for an invalid publish port.
    pub(crate) fn publish_invalid_port(&self) -> &'static str {
        "Use the printed command, or one of these forms:\n\
\n\
    -R 22:localhost:22\n\
    -R 0:localhost:22\n\
    -R hostname:22:localhost:22"
    }

    /// Returns the detail for a missing publish token.
    pub(crate) fn publish_missing_token(&self) -> &'static str {
        "This session is missing a valid publish token."
    }

    /// Returns the detail for a publish hostname mismatch.
    pub(crate) fn publish_hostname_mismatch(&self) -> &'static str {
        "That hostname does not match this token."
    }

    /// Returns the detail for a publish DNS failure.
    pub(crate) fn publish_dns_failure(&self) -> &'static str {
        "The relay could not resolve the hostname from that publish command."
    }

    /// Returns the detail for a token/hostname authorization mismatch.
    pub(crate) fn publish_token_hostname_mismatch(&self) -> &'static str {
        "That token is not allowed to publish that hostname."
    }

    /// Returns the route rejection text for invalid destination ports.
    pub(crate) fn client_route_invalid_port(&self) -> &'static str {
        "This relay only forwards SSH on port 22."
    }

    /// Returns the route rejection text for invalid destination hostnames.
    pub(crate) fn client_route_invalid_hostname(&self) -> &'static str {
        "That hostname is not valid for this relay."
    }

    /// Returns the route rejection text for missing active publishers.
    pub(crate) fn client_route_no_publisher(&self) -> &'static str {
        "No publisher is connected for this host right now. Make sure the\n\
publish command is still running on the other device."
    }

    /// Returns the route rejection text for DNS resolution failures.
    pub(crate) fn client_route_dns_failure(&self) -> &'static str {
        "The relay could not resolve that published hostname."
    }

    /// Returns the route rejection text for publisher connection limits.
    pub(crate) fn client_route_limit(&self) -> &'static str {
        "This published host is at its connection limit right now. Try again\n\
in a moment."
    }

    /// Returns a single publisher status line for a client connection.
    pub(crate) fn tunnel_notice(
        &self,
        unix_seconds: u64,
        client_ip: &str,
        originator_port: u32,
        requested_host: &str,
        registered_host: &str,
    ) -> String {
        format!(
            "[unix:{unix_seconds}] client={client_ip}:{originator_port} requested={requested_host} published={registered_host}\r\n",
            unix_seconds = unix_seconds,
            client_ip = client_ip,
            originator_port = originator_port,
            requested_host = requested_host,
            registered_host = registered_host,
        )
    }
}
