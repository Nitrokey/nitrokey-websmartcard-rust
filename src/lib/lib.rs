#![no_std]

#[macro_use]
extern crate delog;
delog::generate_macros!();

use heapless_bytes::Bytes;

mod commands;
mod commands_types;
mod constants;
mod ctap_app;
mod helpers;
// mod nfc_app;
mod openpgp;
mod options;
mod peeking;
mod rk_files;
mod state;
mod transport;
mod types;
mod wcstate;

pub use options::Options;
pub use peeking::Peeking;
pub use peeking::PeekingBypass;

pub const MAX_MESSAGE_LENGTH: usize = 800; // TODO required 1000 for the ping tests
const OUTPUT_BUFFER_SIZE_FOR_CBOR_SERIALIZATION: usize = MAX_MESSAGE_LENGTH;
#[cfg(feature = "transparent-encryption")]
pub const DEFAULT_ENCRYPTION_PIN: &str = "12345678";

pub type Message = Bytes<MAX_MESSAGE_LENGTH>;

pub use constants::GIT_VERSION;

pub use transport::Webcrypt;
pub use types::RequestDetails;
pub use types::RequestSource;
