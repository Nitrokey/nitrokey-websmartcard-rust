use heapless_bytes::Bytes;
use serde::{Deserialize, Serialize};
use trussed::types::KeyId;

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
    pub fn get_id_by_fingerprint(&self, f: KeyFingerprint) -> Option<KeyId> {
        for k in [&self.main, &self.encryption, &self.signing] {
            if k.fingerprint.0 == f.0 {
                return Some(k.key);
            }
        }
        None
    }
}
