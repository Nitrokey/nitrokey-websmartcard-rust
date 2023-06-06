all: example

.PHONY: example setup-fedora ci setup-ubuntu usbip check
example:
	env RUST_BACKTRACE=full RUST_LOG=debug cargo run --example udp_sim --features log-all,enable-logs

usbip:
	env RUST_BACKTRACE=full RUST_LOG=debug cargo run --example usbip --features log-all,enable-logs,ctaphid-peek

setup-fedora:
	sudo dnf install llvm-devel clang-devel

ci:
	cargo test
	$(MAKE) check

check:
	cargo fmt --check
	cargo clippy

setup-ubuntu:
	# git needed for the git_version crate
	sudo apt install -qy llvm libclang-dev make clang git

setup-ubuntu-docker:
	sudo apt install -qy sudo cargo make