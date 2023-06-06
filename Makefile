all: example

.PHONY: example setup-fedora ci setup-ubuntu usbip
example:
	env RUST_BACKTRACE=full RUST_LOG=debug cargo run --example udp_sim --features log-all,enable-logs

usbip:
	env RUST_BACKTRACE=full RUST_LOG=debug cargo run --example usbip --features log-all,enable-logs,ctaphid-peek

setup-fedora:
	sudo dnf install llvm-devel clang-devel

ci:
	cargo test --verbose

setup-ubuntu:
	sudo apt install llvm libclang-dev make