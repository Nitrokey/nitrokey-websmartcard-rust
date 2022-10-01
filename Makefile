all: example

.PHONY: example release
example:
	env RUST_BACKTRACE=full RUST_LOG=debug cargo run --example udp_sim --features log-all,enable-logs

release:
	 cargo build --example udp_sim --features log-all,enable-logs --release
