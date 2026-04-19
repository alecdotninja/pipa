# pipa.sh

Minimal Rust SSH jump server for exposing an SSH server behind NAT and reaching
it through standard OpenSSH `ProxyJump`.

You can use the public service directly by SSHing into `pipa.sh`. The relay
prints the next step when you register a host, when you publish it, and when a
new client lands on the service.

The relay never starts a shell and never dials arbitrary TCP destinations. It
exists only to connect a public SSH client to a live SSH server somewhere else.

## Quick Start

There are three normal steps:

1. SSH into `pipa.sh` to get a hostname and publish token.
2. Run the printed reverse SSH command on the machine behind NAT.
3. Connect as a client with normal SSH.

### 1. Register a hostname

```sh
ssh pipa.sh
```

The relay allocates a random hostname under `*.pipa.sh` and prints the exact
publish command for the next step.

Example:

```text
Your relay hostname is ready:

  x7k2m4q9pa.pipa.sh

Run this on the machine that has the SSH server you want to publish:

  ssh -R 22:localhost:22 fz6rvtz2w6aj76my5gjzqqum@pipa.sh
```

### 2. Publish from the machine behind NAT

Run the printed command on the machine that has the SSH server you want to
expose:

```sh
ssh -R 22:localhost:22 <token>@pipa.sh
```

If the session stays open, the hostname is live. The relay prints a short
status message and then one line per client connection.

If you want this to persist in the background, see
[`examples/systemd/pipa-publisher.service`](examples/systemd/pipa-publisher.service).

### 3. Connect as a client

After the publisher is live, clients connect normally:

```sh
ssh <hostname>.pipa.sh
```

The first time a client hits the service directly, it prints the `ProxyJump`
setup it expects:

```sshconfig
Host *.pipa.sh
  HostName %h
  ProxyJump pipa.sh
```

After that first setup, the only command most users need to remember is
`ssh <hostname>.pipa.sh`.

## Custom Domains

You can point your own hostname at a published `*.pipa.sh` hostname with a
CNAME:

```dns
ssh.example.com. 300 IN CNAME x7k2m4q9pa.pipa.sh.
```

The relay follows CNAMEs and routes only if the final hostname is a registered,
live publisher. The same rule applies to publisher authorization: the publisher
may use either the registered hostname or a CNAME that terminates there.

Client config for a custom hostname:

```sshconfig
Host ssh.example.com
  HostName %h
  ProxyJump pipa.sh
```

The CNAME chain limit defaults to `8` and can be changed with `--cname-depth`.

## What The Relay Enforces

- No shell, PTY, exec, SFTP, or agent forwarding on the relay.
- Normal shell attempts on `pipa.sh` allocate a random hostname, print a publish
  command, and close.
- Client-setup sessions print usage directions and close.
- Registrations are persisted in SQLite.
- Publishing is authorized by the generated bearer token.
- Client routing is limited to port `22`.
- Client routing is limited to registered hostnames under the relay namespace.
- Client routing stays live only while the matching publisher session is live.
- Per-publisher tunnel limits are enforced in process.

This is an SSH relay for hosts that are intentionally public. The published SSH
server remains responsible for host authentication, user authentication,
authorization, logging, and account policy.

## Authentication Model

Relay authentication is intentionally minimal in this prototype. Registration
and client-setup sessions may authenticate with SSH `none`, password,
keyboard-interactive, or public key. Those methods are only used to get a user
far enough to print instructions or allocate a hostname.

Publishing uses a generated bearer capability, not a normal account login. The
token itself is the SSH username, and possession of that token is sufficient to
publish the registered hostname. Treat the full publish command as a secret.

## Configuration

Defaults:

- Relay hostname: `pipa.sh`
- Published hostnames: `<random>.pipa.sh`
- SQLite database: `pipa.sqlite3`
- Relay host key: `pipa_host_ed25519_key`

Relevant options:

```sh
--relay-hostname pipa.sh
--database ./pipa.sqlite3
--host-key ./pipa_host_ed25519_key
```

`--relay-hostname` controls both the relay login hostname and the suffix used
for allocated hostnames. `--host-key` points at the relay SSH host key; the
server loads it if present or generates an Ed25519 key if it does not exist.

In deployment, point `pipa.sh` at the relay listener IP and point `*.pipa.sh`
at the usage listener IP. During routing, the relay only cares about the final
hostname after following any CNAMEs.

## Running Locally

This workspace uses current stable Rust for dependency compatibility:

```sh
cargo build
cargo test
```

Run locally:

```sh
cargo run -- \
  --relay-listen 127.0.0.1:2222 \
  --usage-listen 127.0.0.1:2223 \
  --relay-hostname pipa.sh \
  --max-tunnels-per-publisher 10 \
  --database ./pipa.sqlite3 \
  --host-key ./pipa_host_ed25519_key
```

Bind both IPv4 and IPv6 addresses by repeating the flag:

```sh
cargo run -- \
  --relay-listen 203.0.113.10:22 \
  --relay-listen '[2001:db8::10]:22' \
  --usage-listen 203.0.113.11:22 \
  --usage-listen '[2001:db8::11]:22' \
  --relay-hostname pipa.sh
```

Default in-process limit:

- `--max-tunnels-per-publisher 10`

The server does not enforce a global connection cap, global tunnel cap, or
bandwidth throttle. Handle those with firewall, traffic control, load balancer,
or host-level policy. Set a high file descriptor limit for production, for
example systemd `LimitNOFILE=1048576`.

For structured logs:

```sh
RUST_LOG=pipa=debug,russh=warn cargo run -- --json-logs
```

Each successful bridged tunnel emits a `tunnel connected` log event with
`client_ip`, `client_peer`, `publisher_ip`, `publisher_peer`,
`requested_hostname`, and `registered_hostname`.

## systemd Examples

Two example units are included:

- `examples/systemd/pipa.service`: hardened server-side unit for the relay host
- `examples/systemd/pipa-publisher.service`: user-level unit for keeping a
  publish session alive on the publishing machine

### Relay Server

Install the binary and unit:

```sh
make
sudo make install
sudo install -o root -g root -m 0644 examples/systemd/pipa.service /etc/systemd/system/pipa.service
sudo systemctl daemon-reload
```

Before starting it, edit the unit and replace the example listener addresses.
The listener env vars accept comma-separated address lists:

```ini
Environment=JUMPSRV_RELAY_LISTEN=203.0.113.10:22,[2001:db8::10]:22
Environment=JUMPSRV_USAGE_LISTEN=203.0.113.11:22,[2001:db8::11]:22
```

The unit runs with `DynamicUser=true`, stores state under `/var/lib/pipa`,
grants only `CAP_NET_BIND_SERVICE` for binding port 22, and uses a strict
filesystem, kernel, and device sandbox.

### Publisher Session

The example publisher unit is meant for `systemd --user`, not root. Install it
on the machine that is publishing its local SSH server:

```sh
mkdir -p ~/.config/systemd/user
cp examples/systemd/pipa-publisher.service ~/.config/systemd/user/
systemctl --user daemon-reload
```

Edit the unit and replace `PIPA_PUBLISH_TOKEN=replace-me` with the token from
the registration step. Then enable it:

```sh
systemctl --user enable --now pipa-publisher.service
```

If you want the publisher to stay up without an active login session, enable
lingering for that user:

```sh
loginctl enable-linger <user>
```

## Architecture

`russh` handles SSH protocol framing, authentication, channels, and flow
control. The pipa application adds policy, registration, and routing:

1. A user connects to the relay listener, normally `pipa.sh`.
2. The server allocates a random hostname under the relay hostname and stores
   it in SQLite.
3. The registration output includes a bearer-token publish command.
4. The publisher requests remote forwarding for port `22`.
5. The server validates the hostname, port, and token ownership, then stores
   the active route in memory.
6. A client connects through `ProxyJump`.
7. If necessary, the relay resolves CNAMEs until it reaches the registered
   hostname.
8. The relay opens a `forwarded-tcpip` channel back to the publisher and
   bridges traffic in both directions.
9. When the publisher disconnects, the active route is removed immediately. The
   registration remains in SQLite.

Code layout:

- `src/app.rs`: process bootstrap, logging, and listener startup
- `src/ssh.rs`: relay and usage SSH servers plus channel bridging
- `src/registry.rs`: SQLite registrations and in-memory active route tracking
- `src/dns.rs`: CNAME following and registered-host resolution
- `src/messages.rs`: user-facing text
- `src/util.rs`: shared constants and helpers
- `src/host_key.rs`: persistent SSH host-key loading and generation
- `src/tests.rs`: core unit and regression tests

Prototype limitation:

- SQLite is local-process storage. A multi-node deployment needs a shared
  registration service and coordinated active route discovery.

## Testing

Automated:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

Local integration smoke test:

```sh
./scripts/smoke-local.sh
```

The smoke test expects:

- `ssh`, `ssh-keyscan`, and `timeout`
- a reachable SSH server on `localhost:22`
- localhost SSH auth configured for your user or agent

The GitHub Actions workflow provisions a temporary local `sshd` before running
the smoke test. For local runs, provide your own SSH server on `localhost:22`.
