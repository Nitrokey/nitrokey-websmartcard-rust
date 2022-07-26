# Nitrokey Webcrypt Rust

This is a Nitrokey Webcrypt Rust-rewrite.
See https://github.com/Nitrokey/nitrokey-webcrypt for the documentation of the commands and protocol.

## Running UDP Simulation

```bash
cargo run --example udp_sim
```

To show logs:
```bash
env RUST_BACKTRACE=full RUST_LOG=debug run --example udp_sim --features enable-logs
```

Tests are here:
- https://github.com/Nitrokey/nitrokey-webcrypt-tests

## Running USB-IP Simulation

Check out `nitrokey-webcrypt-usbip` project for the USB-IP simulation:
- https://github.com/Nitrokey/nitrokey-webcrypt-usbip

## Running on a hardware
Here is a working Nitrokey Webcrypt on a Nitrokey 3 firmware:
- https://github.com/Nitrokey/nitrokey-3-firmware/tree/nitrokey-webcrypt
