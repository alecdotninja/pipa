# pipa.sh

Minimal Rust SSH jump server for an SSH-only public NAT traversal prototype.

The server binds two SSH listeners:

- Relay listener: users register a persisted random hostname here, publishers attach a reverse SSH forward here, and OpenSSH `ProxyJump` uses this listener for `direct-tcpip` routing.
- Usage listener: users connect here to see client setup directions and the connection closes.

The relay never starts a shell and never dials arbitrary TCP destinations. If someone connects to either listener as if it were a normal shell server, it prints the relevant instructions and closes.

## What It Does

1. A user connects to the relay listener and gets a random hostname like `<random>.pipa.sh` plus a publish token.
2. A publisher runs the generated reverse SSH command from the machine that has `localhost:22`.
3. A client connects to the published hostname using standard OpenSSH `ProxyJump`.
4. The relay routes only to live publisher sessions that already connected back.

## Architecture

`russh` handles SSH protocol framing, authentication, channels, and flow control. The jump server code implements policy and userspace dispatch:

1. A user connects to the relay listener, normally `pipa.sh`.
2. The server allocates a random hostname under the relay hostname, normally `<random>.pipa.sh`, and stores it in SQLite.
3. The registration output includes a bearer-token publish command. The token itself is the SSH username.
4. The publisher requests remote forwarding:
   `<random>.pipa.sh:22 -> localhost:22`
   or a CNAME that terminates at that registered hostname.
5. The server validates the hostname, port, and persisted publisher ownership, then stores:
   `published hostname -> active publisher SSH session handle`.
6. A client connects to the relay listener via ProxyJump. OpenSSH sends a `direct-tcpip` channel for `<random>.pipa.sh:22`.
7. If the requested hostname is not directly live, the relay resolves DNS CNAMEs until there are no more CNAME records.
8. The relay checks that the final hostname is registered and live, opens a `forwarded-tcpip` channel back to the publisher, and bridges channel data in both directions.
9. When the publisher disconnects or cancels forwarding, the active route is removed immediately. The SQLite registration remains.

Code layout:

- `src/app.rs`: process bootstrap, logging, and listener startup.
- `src/ssh.rs`: relay and usage SSH servers plus channel bridging.
- `src/registry.rs`: SQLite registrations and in-memory active route tracking.
- `src/dns.rs`: CNAME following and registered-host resolution.
- `src/messages.rs`: all user-facing text.
- `src/util.rs`: shared constants and small helpers.
- `src/host_key.rs`: persistent SSH host-key loading and generation.
- `src/tests.rs`: core unit and regression tests.

## Trust Model

This is an SSH relay for hosts that are intentionally public. The relay is not the final authentication boundary for the published host. The final SSH server behind the publisher remains responsible for host authentication, user authentication, authorization, logging, and account policy.

The relay enforces:

- no shell, PTY, exec, SFTP, or agent forwarding on the relay
- normal shell attempts on the usage listener receive client setup text and close
- normal shell attempts on the relay listener allocate a random hostname, print a publish command, and close
- registrations are persisted in SQLite
- publishing is authorized by the bearer token generated at registration time; possession of that token is sufficient to publish for that hostname
- publisher remote-forward requests may use either the registered hostname or a CNAME that terminates there
- client routing only to port `22`
- client routing only to registered hostnames under the relay hostname namespace
- client routing through custom domains only when DNS CNAMEs terminate at a registered service hostname
- client routing only while a matching publisher connection is live
- per-publisher tunnel limits

### v1 Authentication Model

Relay authentication is intentionally minimal in this prototype. Registration and client setup sessions may authenticate with SSH `none`, password, keyboard-interactive, or public key. Those methods are only used to get a user far enough to print instructions or allocate a hostname.

Publishing uses a generated bearer capability, not an account login. The token itself is the SSH username, and possession of that token is sufficient to publish the registered hostname. Treat the full publish command as a secret. Anyone who obtains it can publish for that hostname until the registration is removed or rotated.

The relay remains separate from final host authentication. The published SSH server is still responsible for host keys, user authentication, authorization, logging, and account policy.

Prototype limitations:

- SQLite is local-process storage. A multi-node deployment needs a shared registration service and coordinated active route discovery.

## Hostnames

Defaults:

- Relay hostname: `pipa.sh`
- Published hostnames: `<random>.pipa.sh`
- SQLite database: `pipa.sqlite3`
- Relay host key: `pipa_host_ed25519_key`

In deployment, point `pipa.sh` at the relay listener IP and point `*.pipa.sh` at the usage listener IP. During CNAME routing, the relay cares only about the final hostname after following CNAMEs.

Relevant options:

```sh
--relay-hostname pipa.sh
--database ./pipa.sqlite3
--host-key ./pipa_host_ed25519_key
```

`--relay-hostname` controls both the relay login host and the suffix used for allocated hostnames and `Host *.<relay-hostname>` snippets. `--host-key` points at the relay SSH host key; the server loads it if present or generates an Ed25519 key if it does not exist.

## Development

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

The server does not enforce a global connection cap, global tunnel cap, or bandwidth throttle. Handle those with firewall, traffic control, load balancer, or host-level policy. Set a high file descriptor limit for production, for example systemd `LimitNOFILE=1048576`.

For structured logs:

```sh
RUST_LOG=pipa=debug,russh=warn cargo run -- --json-logs
```

Each successful bridged tunnel emits a `tunnel connected` log event with the normal tracing timestamp plus `client_ip`, `client_peer`, `publisher_ip`, `publisher_peer`, `requested_hostname`, and `registered_hostname`.

## User Flow

There are three normal user actions:

1. Read client setup from the usage listener.
2. Register a hostname on the relay listener.
3. Run the generated publish command from the machine that owns the target SSH server.

### Usage Listener

```sh
ssh anything@docs.pipa.sh
```

The usage listener accepts the login, prints a `ProxyJump` config example, sends EOF, and closes.

### Relay Registration

```sh
ssh anything@pipa.sh
```

The relay listener accepts the login, registers a random `*.pipa.sh` hostname in SQLite, prints a publish command, sends EOF, and closes.

Example registration output:

```text
Registered hostname:

  x7k2m4q9pa.pipa.sh

Publish your local SSH server with:

  ssh -R 22:localhost:22 fz6rvtz2w6aj76my5gjzqqum@pipa.sh

The publish token is the secret that controls this hostname. The command can be moved to another machine without moving the registration machine's SSH private key.
```

You can also use `-R 0:localhost:22`, `-R x7k2m4q9pa.pipa.sh:22:localhost:22`, or `-R x7k2m4q9pa.pipa.sh:0:localhost:22`. Explicit hostnames may also be custom CNAMEs that resolve through to the registered hostname.

### Publisher Setup

Register first:

```sh
ssh anything@pipa.sh
```

Then run the printed publish command:

```sh
ssh \
  -R 22:localhost:22 \
  fz6rvtz2w6aj76my5gjzqqum@pipa.sh
```

Publisher SSH config snippet:

```sshconfig
Host pipa-publisher
  HostName pipa.sh
  User fz6rvtz2w6aj76my5gjzqqum
  ExitOnForwardFailure yes
  RemoteForward 22 localhost:22
```

Connect with:

```sh
ssh pipa-publisher
```

When the session stays open, the relay prints:

- a welcome line confirming the published hostname
- one line per client connection, including a timestamp and the client IP seen by the relay

If you prefer a silent background publish session, you can still add `-N`, but then there is no terminal to receive these notices.

### Client ProxyJump Setup

Client SSH config snippet:

```sshconfig
Host *.pipa.sh
  HostName %h
  User your-user-on-the-published-host
  ProxyJump pipa.sh
```

Connect through the relay:

```sh
ssh x7k2m4q9pa.pipa.sh
```

The relay receives a `direct-tcpip` request for `x7k2m4q9pa.pipa.sh:22`, looks up the active publisher, and bridges the SSH handshake to the publisher's `localhost:22`.

## Custom Domains

Users may point their own SSH hostname at a published service hostname with a CNAME:

```dns
ssh.example.com. 300 IN CNAME x7k2m4q9pa.pipa.sh.
```

During relay routing, only the final DNS name after following CNAMEs matters:

1. Client requests `ssh.example.com:22` through ProxyJump.
2. Relay resolves `ssh.example.com -> x7k2m4q9pa.pipa.sh`.
3. Relay routes only if `x7k2m4q9pa.pipa.sh` is currently registered by a live publisher.

The same rule applies to publisher authorization. A publisher may use either the registered hostname in `-R` or a CNAME that terminates there.

Client config for a custom domain:

```sshconfig
Host ssh.example.com
  HostName ssh.example.com
  User your-user-on-the-published-host
  ProxyJump pipa.sh
```

The CNAME chain limit defaults to `8` and can be changed with `--cname-depth`.

## systemd Examples

Two systemd examples are included:

- `examples/systemd/pipa.service`: hardened server-side unit for the relay host
- `examples/systemd/pipa-publisher.service`: user-level unit for keeping a
  publish session alive on the publishing machine

### Relay Server

Install the binary and unit:

```sh
cargo build --release
sudo install -o root -g root -m 0755 target/release/pipa /usr/local/bin/pipa
sudo install -o root -g root -m 0644 examples/systemd/pipa.service /etc/systemd/system/pipa.service
sudo systemctl daemon-reload
```

Before starting it, edit the unit and replace the example listener addresses. The
listener env vars accept comma-separated address lists:

```ini
Environment=JUMPSRV_RELAY_LISTEN=203.0.113.10:22,[2001:db8::10]:22
Environment=JUMPSRV_USAGE_LISTEN=203.0.113.11:22,[2001:db8::11]:22
```

The unit runs with `DynamicUser=true`, stores state under `/var/lib/pipa`, grants only `CAP_NET_BIND_SERVICE` for binding port 22, and uses a strict filesystem/kernel/device sandbox. It intentionally does not use systemd `IPAddressDeny=any`: pipa must accept arbitrary client and publisher IPs, and CNAME routing needs DNS resolution. Enforce broader ingress, egress, and bandwidth policy with the host firewall, traffic control, or surrounding network policy.

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

## Test Plan

Automated:

```sh
cargo fmt -- --check
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

The GitHub Actions workflow provisions a temporary local `sshd` before
running the smoke test. For local runs, provide your own SSH server on
`localhost:22`.
- localhost SSH auth configured for your user or agent

Manual checks:

- Connecting to the usage listener with a normal shell session prints usage directions and closes.
- Connecting to the relay listener with a normal shell session prints a random hostname and publisher command.
- Restarting the server preserves SQLite registrations, but not live publisher routes.
- Publishing a registered hostname works only with the generated publish token.
- Publishing via a CNAME alias works only when the final CNAME target is the registered hostname for that token.
- Publishing with the wrong token, even for a known hostname, is rejected.
- Publishing a hostname outside `*.pipa.sh` is rejected.
- Publishing any port other than `22` is rejected.
- Client `ProxyJump` to an unpublished hostname fails.
- Client `ProxyJump` to a CNAME alias works only when the final CNAME target is a live registered hostname.
- Client `ProxyJump` to a published hostname reaches the publisher's local SSH server.
- Killing the publisher connection immediately removes the active route.
