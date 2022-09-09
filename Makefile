all: example

.PHONY: example
example:
	env RUST_BACKTRACE=full RUST_LOG=debug cargo run --example udp_sim --features log-all,enable-logs
