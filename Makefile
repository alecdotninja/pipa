DEV_DIR := .dev
DEV_DB := $(DEV_DIR)/pipa.sqlite3
DEV_HOST_KEY := $(DEV_DIR)/pipa_host_ed25519_key

RELAY_LISTEN ?= 127.0.0.1:2222
USAGE_LISTEN ?= 127.0.0.1:2223
RELAY_HOSTNAME ?= pipa.sh
MAX_TUNNELS_PER_PUBLISHER ?= 10
RUST_LOG ?= pipa=info,russh=warn

.PHONY: dev dev-setup fmt test clippy smoke clean-dev

dev: dev-setup
	RUST_LOG="$(RUST_LOG)" cargo run -- \
		--relay-listen "$(RELAY_LISTEN)" \
		--usage-listen "$(USAGE_LISTEN)" \
		--relay-hostname "$(RELAY_HOSTNAME)" \
		--max-tunnels-per-publisher "$(MAX_TUNNELS_PER_PUBLISHER)" \
		--database "$(DEV_DB)" \
		--host-key "$(DEV_HOST_KEY)"

dev-setup:
	mkdir -p "$(DEV_DIR)"

fmt:
	cargo fmt -- --check

test:
	cargo test

clippy:
	cargo clippy --all-targets -- -D warnings

smoke:
	./scripts/smoke-local.sh

clean-dev:
	rm -rf "$(DEV_DIR)"
