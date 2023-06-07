use crate::Message;
use heapless_bytes::{Bytes, Bytes32};
use trussed::{client, syscall};

pub fn hash<C>(trussed: &mut C, data: Message) -> Bytes<32>
where
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Chacha8Poly1305
        + client::HmacSha256
        + client::Sha256,
{
    use trussed::types::Mechanism;
    let hash = syscall!(trussed.hash(
        Mechanism::Sha256,
        Message::from_slice(data.as_slice()).unwrap()
    ))
    .hash;
    Bytes32::from_slice(hash.as_slice()).unwrap()
}

pub fn cbor_serialize_message<T: serde::Serialize>(
    object: &T,
) -> Result<Message, ctap_types::serde::Error> {
    trussed::cbor_serialize_bytes(object)
}
