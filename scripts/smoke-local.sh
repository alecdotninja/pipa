#!/usr/bin/env bash
set -euo pipefail

RELAY_HOSTNAME="${JUMPSRV_RELAY_HOSTNAME:-pipa.sh}"
DEFAULT_RELAY_PORT="$((20000 + RANDOM % 10000))"
RELAY_PORT="${JUMPSRV_RELAY_PORT:-$DEFAULT_RELAY_PORT}"
USAGE_PORT="${JUMPSRV_USAGE_PORT:-$((RELAY_PORT + 1))}"
KEY_DIR="$(mktemp -d)"
SERVER_LOG="$KEY_DIR/pipa.log"
REGISTER_LOG="$KEY_DIR/register.log"
PUBLISHER_LOG="$KEY_DIR/publisher.log"
SSH_CONFIG="$KEY_DIR/ssh_config"
DB="$KEY_DIR/pipa.sqlite3"
HOST_KEY="$KEY_DIR/pipa_host_ed25519_key"

cleanup() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "smoke test failed with status $status" >&2
    for log in "$SERVER_LOG" "$REGISTER_LOG" "$PUBLISHER_LOG"; do
      if [[ -s "$log" ]]; then
        echo "----- $log -----" >&2
        sed -n '1,200p' "$log" >&2
      fi
    done
  fi
  if [[ -n "${PUBLISHER_PID:-}" ]]; then
    kill "$PUBLISHER_PID" 2>/dev/null || true
  fi
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$KEY_DIR"
}
trap cleanup EXIT

cargo build

RUST_LOG=pipa=info,russh=warn \
  cargo run -- \
    --relay-listen "127.0.0.1:$RELAY_PORT" \
    --usage-listen "127.0.0.1:$USAGE_PORT" \
    --relay-hostname "$RELAY_HOSTNAME" \
    --database "$DB" \
    --host-key "$HOST_KEY" \
    >"$SERVER_LOG" 2>&1 &
SERVER_PID="$!"

for _ in {1..40}; do
  if ssh-keyscan -p "$RELAY_PORT" 127.0.0.1 >/dev/null 2>&1 &&
    ssh-keyscan -p "$USAGE_PORT" 127.0.0.1 >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

ssh -T \
  -F /dev/null \
  -p "$RELAY_PORT" \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  register@127.0.0.1 \
  >"$REGISTER_LOG" 2>&1 || true

HOSTNAME="$(grep -Eo "[a-z2-7]{10}\\.${RELAY_HOSTNAME//./\\.}" "$REGISTER_LOG" | head -1)"
PUBLISH_USER="$(grep -Eo "[a-z2-7]{12}@127\\.0\\.0\\.1|[a-z2-7]{12}@[^[:space:]]+" "$REGISTER_LOG" | head -1 | cut -d@ -f1)"
if [[ -z "$HOSTNAME" ]]; then
  echo "failed to register hostname" >&2
  cat "$REGISTER_LOG" >&2
  exit 1
fi
if [[ -z "$PUBLISH_USER" ]]; then
  echo "failed to extract publish token user" >&2
  cat "$REGISTER_LOG" >&2
  exit 1
fi

ssh -N \
  -F /dev/null \
  -p "$RELAY_PORT" \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o ExitOnForwardFailure=yes \
  -R 22:localhost:22 \
  "$PUBLISH_USER@127.0.0.1" \
  >"$PUBLISHER_LOG" 2>&1 &
PUBLISHER_PID="$!"

sleep 1

cat >"$SSH_CONFIG" <<CONFIG
Host relay-test
  HostName 127.0.0.1
  Port $RELAY_PORT
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR

Host *.$RELAY_HOSTNAME
  HostName %h
  Port 22
  User ${USER:-$(id -un)}
  ProxyJump relay-test
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  BatchMode yes
  LogLevel ERROR
CONFIG

timeout 15 ssh -F "$SSH_CONFIG" "$HOSTNAME" true

kill "$PUBLISHER_PID"
wait "$PUBLISHER_PID" 2>/dev/null || true
unset PUBLISHER_PID
sleep 1

if timeout 5 ssh -F "$SSH_CONFIG" "$HOSTNAME" true 2>/dev/null; then
  echo "expected unpublished route to fail after publisher disconnect" >&2
  exit 1
fi

echo "smoke test passed for $HOSTNAME"
