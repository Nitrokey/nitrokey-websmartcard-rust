use heapless_bytes::Bytes;
use serde::{Deserialize, Serialize};
use trussed::types::KeyId;
use trussed::{client, syscall};

#[derive(Serialize, Deserialize, Default)]
pub struct KeyFingerprint(Bytes<32>);

impl TryFrom<&[u8]> for KeyFingerprint {
    type Error = ();

    fn try_from(a: &[u8]) -> Result<KeyFingerprint, Self::Error> {
        Ok(KeyFingerprint(Bytes::from_slice(a)?))
    }
}

#[derive(Serialize, Deserialize)]
pub struct OpenPGPKey {
    pub key: KeyId,
    pub fingerprint: KeyFingerprint,
}

#[derive(Serialize, Deserialize)]
pub struct OpenPGPData {
    pub main: OpenPGPKey,
    pub encryption: OpenPGPKey,
    pub signing: OpenPGPKey,
}

impl OpenPGPData {
    pub fn init(C: &mut (impl client::Client + client::P256)) -> Self {
        let private_key =
            syscall!(C.generate_p256_private_key(trussed::types::Location::Internal)).key;
        let public_key =
            syscall!(C.derive_p256_public_key(private_key, trussed::types::Location::Volatile)).key;

        OpenPGPData {
            main: OpenPGPKey {
                key: private_key,
                fingerprint: Default::default(),
            },
            encryption: OpenPGPKey {
                key: private_key,
                fingerprint: Default::default(),
            },
            signing: OpenPGPKey {
                key: private_key,
                fingerprint: Default::default(),
            },
        }
    }

    pub fn get_id_by_fingerprint(&self, f: KeyFingerprint) -> Option<KeyId> {
        for k in [&self.main, &self.encryption, &self.signing] {
            if k.fingerprint.0 == f.0 {
                return Some(k.key);
            }
        }
        None
    }
}
