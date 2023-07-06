use crate::Message;
use heapless_bytes::{Bytes, Bytes32};
use trussed::{client, syscall};

#[inline(never)]
pub fn hash<C>(trussed: &mut C, data: &[u8]) -> Result<Bytes<32>, ()>
where
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Chacha8Poly1305
        + client::HmacSha256
        + client::Sha256,
{
    use trussed::types::Mechanism;
    let hash = syscall!(trussed.hash(Mechanism::Sha256, Bytes::from_slice(data)?)).hash;
    Bytes32::from_slice(hash.as_slice())
}

pub fn cbor_serialize_message<T: serde::Serialize>(
    object: &T,
) -> Result<Message, ctap_types::serde::Error> {
    trussed::cbor_serialize_bytes(object)
}
