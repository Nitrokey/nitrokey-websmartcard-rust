#[macro_use]
extern crate delog;

use delog::log;
use heapless_bytes::{Bytes, Bytes32};
use trussed::types::PathBuf;

use webcrypt::{RequestDetails, RequestSource, Webcrypt, DEFAULT_ENCRYPTION_PIN};

use crate::udp_server::UDPServer;
use trussed::types::ClientContext;

generate_macros!();

mod platform;
mod udp_server;

#[cfg(feature = "enable-logs")]
use pretty_env_logger;

fn main() -> std::io::Result<()> {
    {
        #[cfg(feature = "enable-logs")]
        pretty_env_logger::init();

        log::info!("Initializing Trussed");
        let trussed_platform = platform::init_platform("state_file");
        let mut trussed_service = trussed::service::Service::new(trussed_platform);
        let trussed_client = trussed_service
            .try_as_new_client_ctx(ClientContext::new(
                PathBuf::from("webcrypt"),
                Some(DEFAULT_ENCRYPTION_PIN),
            ))
            .unwrap();
        log::info!("Initializing Webcrypt {}", webcrypt::GIT_VERSION);
        let mut w = Webcrypt::new(trussed_client);
        let mut server = UDPServer::new();

        loop {
            let received = server.receive().unwrap();
            let output = Bytes::new();
            let input = Bytes::from_slice(received).unwrap();
            let output = w
                .bridge_u2f_to_webcrypt_raw(
                    output,
                    &input,
                    RequestDetails {
                        source: RequestSource::RS_NOT_SET,
                        rpid: Bytes32::from_slice("UDP SIMULATION".as_ref()).unwrap(),
                        pin_auth: None,
                    },
                )
                .unwrap();
            server.send(&output).unwrap();
        }
    } // the socket is closed here
}
