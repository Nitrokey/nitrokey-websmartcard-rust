use heapless_bytes::Bytes;
use serde::{Deserialize, Serialize};
use trussed::types::KeyId;
use trussed::{client, syscall};

#[derive(Serialize, Deserialize, Default)]
pub struct KeyFingerprint(Bytes<8>);

impl KeyFingerprint {
    // TODO
    // https://www.rfc-editor.org/rfc/rfc4880#section-12.2
    // https://crypto.stackexchange.com/a/32097
    pub fn from_public_key(trussed: &mut (impl client::Client), pk: Bytes<64>) -> Result<Self, ()> {
        todo!();
        Ok(Default::default())
    }
}

impl TryFrom<&[u8]> for KeyFingerprint {
    type Error = ();

    fn try_from(a: &[u8]) -> Result<KeyFingerprint, Self::Error> {
        Ok(KeyFingerprint(Bytes::from_slice(a)?))
    }
}

#[derive(Serialize, Deserialize)]
pub struct OpenPGPKey {
    pub key: KeyId,
    pub pubkey: Option<KeyId>,
    pub fingerprint: KeyFingerprint,
}

#[derive(Serialize, Deserialize)]
pub struct OpenPGPData {
    pub authentication: OpenPGPKey,
    pub encryption: OpenPGPKey,
    pub signing: OpenPGPKey,
}

impl OpenPGPKey {
    pub fn get_public_keyid(&self, trussed: &mut (impl client::Client + client::P256)) -> KeyId {
        match self.pubkey {
            Some(pk) => pk,
            None => {
                let pk =
                    syscall!(trussed
                        .derive_p256_public_key(self.key, trussed::types::Location::Volatile))
                    .key;
                // self.pubkey = Some(pk);
                pk
            }
        }
    }
    pub fn get_public_key_serialized(
        &self,
        trussed: &mut (impl client::Client + client::P256),
    ) -> Bytes<64> {
        let pubk = self.get_public_keyid(trussed);

        let serialized_raw_public_key =
            syscall!(trussed.serialize_p256_key(pubk, trussed::types::KeySerialization::Raw))
                .serialized_key;
        Bytes::<64>::from_slice(serialized_raw_public_key.as_slice()).unwrap()
    }
}

impl OpenPGPData {
    pub fn init(trussed: &mut (impl client::Client + client::P256)) -> Self {
        // let private_key =
        //     syscall!(trussed.generate_p256_private_key(trussed::types::Location::Internal)).key;
        // let public_key = syscall!(
        //     trussed.derive_p256_public_key(private_key, trussed::types::Location::Volatile)
        // )
        // .key;
        // let pkraw = Self::get_public_key_serialized(trussed, public_key);
        // let fing = KeyFingerprint::from_public_key(trussed, pkraw);

        OpenPGPData {
            authentication: OpenPGPKey {
                key:
                    syscall!(trussed.generate_p256_private_key(trussed::types::Location::Internal))
                        .key,
                pubkey: None,
                fingerprint: Default::default(),
            },
            encryption: OpenPGPKey {
                key:
                    syscall!(trussed.generate_p256_private_key(trussed::types::Location::Internal))
                        .key,
                pubkey: None,
                fingerprint: Default::default(),
            },
            signing: OpenPGPKey {
                key:
                    syscall!(trussed.generate_p256_private_key(trussed::types::Location::Internal))
                        .key,
                pubkey: None,
                fingerprint: Default::default(),
            },
        }
    }

    pub fn get_id_by_fingerprint(&self, f: KeyFingerprint) -> Option<KeyId> {
        for k in [&self.authentication, &self.encryption, &self.signing] {
            if k.fingerprint.0 == f.0 {
                return Some(k.key);
            }
        }
        None
    }
}
