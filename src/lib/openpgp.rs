use crate::commands_types::{DataBytes, ResultW};
use crate::types::Error;
use crate::types::Error::InternalError;
use heapless_bytes::Bytes;
use serde::{Deserialize, Serialize};
use trussed::key::Kind;
use trussed::types::{KeyId, Mechanism};
use trussed::{client, syscall, try_syscall};

#[derive(Serialize, Deserialize, Default)]
pub struct KeyFingerprint(Bytes<8>);

impl KeyFingerprint {
    // TODO
    // https://www.rfc-editor.org/rfc/rfc4880#section-12.2
    // https://crypto.stackexchange.com/a/32097
    pub fn from_public_key(_trussed: &mut impl client::Client, _pk: Bytes<64>) -> Result<Self, ()> {
        todo!();
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
    pub key_mechanism: Mechanism,
}

#[derive(Serialize, Deserialize)]
pub struct OpenPGPData {
    pub authentication: OpenPGPKey,
    pub encryption: OpenPGPKey,
    pub signing: OpenPGPKey,
    pub date: Bytes<32>,
}

impl OpenPGPKey {
    pub fn clear(&self, trussed: &mut impl client::Client) -> Result<(), trussed::Error> {
        // TODO: set self.key to None after removal
        try_syscall!(trussed.delete(self.key))?;
        if self.pubkey.is_some() {
            try_syscall!(trussed.delete(self.pubkey.unwrap()))?;
        }
        Ok(())
    }

    pub fn get_public_keyid(&self, trussed: &mut (impl client::Client + client::P256)) -> KeyId {
        match self.pubkey {
            Some(pk) => pk,
            None => {
                syscall!(
                    trussed.derive_p256_public_key(self.key, trussed::types::Location::Volatile)
                )
                .key
            }
        }
    }
    pub fn get_public_key_serialized(
        &mut self,
        trussed: &mut (impl client::Client + client::P256),
    ) -> Bytes<64> {
        let pubk = self.get_public_keyid(trussed);
        // syscall!(trussed.delete(pubk));
        self.pubkey = Some(pubk);
        let serialized_raw_public_key =
            syscall!(trussed.serialize_p256_key(pubk, trussed::types::KeySerialization::Raw))
                .serialized_key;
        Bytes::<64>::from_slice(serialized_raw_public_key.as_slice()).unwrap()
    }
}

impl OpenPGPData {
    pub fn clear(&self, trussed: &mut impl client::Client) -> Result<(), trussed::Error> {
        self.signing.clear(trussed)?;
        self.encryption.clear(trussed)?;
        self.authentication.clear(trussed)?;
        Ok(())
    }

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
                key_mechanism: Mechanism::P256,
            },
            encryption: OpenPGPKey {
                key:
                    syscall!(trussed.generate_p256_private_key(trussed::types::Location::Internal))
                        .key,
                pubkey: None,
                fingerprint: Default::default(),
                key_mechanism: Mechanism::P256,
            },
            signing: OpenPGPKey {
                key:
                    syscall!(trussed.generate_p256_private_key(trussed::types::Location::Internal))
                        .key,
                pubkey: None,
                fingerprint: Default::default(),
                key_mechanism: Mechanism::P256,
            },
            date: Default::default(),
        }
    }

    pub fn import(
        trussed: &mut (impl client::Client + client::P256),
        auth: DataBytes,
        sign: DataBytes,
        enc: DataBytes,
        date: DataBytes,
    ) -> ResultW<Self> {
        use trussed::types::Location;

        Ok(OpenPGPData {
            authentication: OpenPGPKey {
                key: {
                    try_syscall!(trussed.unsafe_inject_shared_key(
                        auth.as_slice(),
                        Location::Internal,
                        #[cfg(feature = "inject-any-key")]
                        Kind::P256
                    ))
                    .map_err(|_| Error::FailedLoadingData)?
                    .key
                },
                pubkey: None,
                fingerprint: Default::default(),
                key_mechanism: Mechanism::P256,
            },
            encryption: OpenPGPKey {
                key: {
                    try_syscall!(trussed.unsafe_inject_shared_key(
                        enc.as_slice(),
                        Location::Internal,
                        #[cfg(feature = "inject-any-key")]
                        Kind::P256
                    ))
                    .map_err(|_| Error::FailedLoadingData)?
                    .key
                },
                pubkey: None,
                fingerprint: Default::default(),
                key_mechanism: Mechanism::P256,
            },
            signing: OpenPGPKey {
                key: {
                    try_syscall!(trussed.unsafe_inject_shared_key(
                        sign.as_slice(),
                        Location::Internal,
                        #[cfg(feature = "inject-any-key")]
                        Kind::P256
                    ))
                    .map_err(|_| Error::FailedLoadingData)?
                    .key
                },
                pubkey: None,
                fingerprint: Default::default(),
                key_mechanism: Mechanism::P256,
            },
            date: Bytes::<32>::from_slice(&date).map_err(|_| InternalError)?,
        })
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
