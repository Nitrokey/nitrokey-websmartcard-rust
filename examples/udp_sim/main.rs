#[macro_use]
extern crate delog;

use delog::log;
use heapless_bytes::{Bytes, Bytes32};

use webcrypt::{Options, RequestDetails, RequestSource, Webcrypt};

use crate::udp_server::UDPServer;

generate_macros!();

mod udp_server;

#[cfg(feature = "enable-logs")]
use pretty_env_logger::env_logger;
use trussed::types::Location;

mod virt;

fn main() {
    #[cfg(feature = "enable-logs")]
    env_logger::init();

    virt::with_ram_client("webcrypt", |client| {
        let mut w = webcrypt::Webcrypt::new_with_options(
            client,
            Options::new(Location::External, *b"1234", 10000),
        );

        let mut server = UDPServer::new();
        loop {
            let received = server.receive().unwrap();
            let output = Bytes::new();
            let input = Bytes::from_slice(received).unwrap();
            match w.bridge_u2f_to_webcrypt_raw(
                output,
                &input,
                RequestDetails {
                    source: RequestSource::RS_NOT_SET,
                    rpid: Bytes32::from_slice("UDP SIMULATION".as_ref()).unwrap(),
                    pin_auth: None,
                },
            ) {
                Ok(res) => {
                    server.send(&res).unwrap();
                }
                Err(e) => {
                    log::error!("Protocol error: {:?}", e);
                    server.send(&[e as u8]).unwrap();
                }
            }
        }
    });
}
