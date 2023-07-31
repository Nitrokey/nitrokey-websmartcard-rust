all: example

FEATURES=log-all,enable-logs

.PHONY: example setup-fedora ci setup-ubuntu usbip check bloat
example:
	env RUST_BACKTRACE=full RUST_LOG=debug cargo run --example udp_sim --features $(FEATURES)

usbip:
	env RUST_BACKTRACE=full RUST_LOG=debug cargo run --example usbip --features $(FEATURES)

bloat:
	cargo bloat --crates -n 100 --example usbip --features $(FEATURES)

setup-fedora:
	sudo dnf install llvm-devel clang-devel

ci:
	$(MAKE) check
	cargo build --example usbip --features $(FEATURES)
	-timeout 2 $(MAKE) usbip
	# TODO: run cargo test

check:
	cargo fmt --check
	cargo clippy -- -D warnings

setup-ubuntu:
	# git needed for the git_version crate
	sudo apt install -qy llvm libclang-dev make clang git

setup-ubuntu-docker:
	sudo apt install -qy sudo cargo make

## RR debuggging
zen_workaround.py:
	# https://github.com/rr-debugger/rr/wiki/Zen
	wget https://raw.githubusercontent.com/rr-debugger/rr/master/scripts/zen_workaround.py
	# Assuming here running under bash as the default shell. Inspect the script and update hash, if the verification fails.
	sha256sum -c <(echo 92d30b5ea40b3033e51b62acef17cbbd108657bd8d9cb12dbee7153eb248c5d5  zen_workaround.py)

.PHONY: debug-rr-setup debug-rr-record debug-rr
debug-rr-setup: zen_workaround.py
	# Run this once per boot. See docs, if you want it persistent.
	sudo sysctl kernel.perf_event_paranoid=1
	sudo python3 zen_workaround.py

debug-rr-record:
	# Record a single execution. Attach usbip sim in another terminal window.
	# Make sure the debug-rr-setup target was run already during this boot. Can be run multiple times.
	cargo build --example usbip --features rsa
	env RUST_LOG=debug RUST_BACKTRACE=1 rr record  ${CARGO_TARGET_DIR}/debug/examples/usbip

debug-rr:
	# Replay the last recording. Does not need debug-rr-setup to be run just for the replay.
	rr replay -d $(shell which rust-gdb)

.PHONY: tests
tests:
	cd ../nitrokey-webcrypt-tests/ && make FIDO2
