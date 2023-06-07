#![no_std]

#[macro_use]
extern crate delog;

use heapless_bytes::Bytes;

generate_macros!();

mod commands;
mod commands_types;
mod constants;
mod ctap_app;
mod helpers;
// mod nfc_app;
mod openpgp;
mod rk_files;
mod state;
mod transport;
mod types;
mod wcstate;

pub const MAX_MESSAGE_LENGTH: usize = 1024;
#[cfg(feature = "transparent-encryption")]
pub const DEFAULT_ENCRYPTION_PIN: &str = "12345678";

pub type Message = Bytes<MAX_MESSAGE_LENGTH>;

fn cbor_serialize_message<T: serde::Serialize>(
    object: &T,
) -> Result<Message, ctap_types::serde::Error> {
    trussed::cbor_serialize_bytes(object)
}

pub use constants::GIT_VERSION;

pub type Webcrypt<C> = transport::Webcrypt<C>;
pub use types::RequestDetails;
pub use types::RequestSource;
