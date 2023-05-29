all: example

.PHONY: example setup-fedora
example:
	env RUST_BACKTRACE=full RUST_LOG=debug cargo run --example udp_sim --features log-all,enable-logs

setup-fedora:
	sudo dnf install llvm-devel clang-devel