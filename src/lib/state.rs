// Copyright (C) 2020 SoloKeys
// SPDX-License-Identifier: MIT

// Imported from the https://github.com/solokeys/fido-authenticator/ project
// Unused implementation is removed
// TODO Consider importing PersistentState from fido-authenticator directly if needed

use ctap_types::Error;
use trussed::types::PathBuf;

use trussed::{
    client, syscall, try_syscall,
    types::{KeyId, Location},
    Client as TrussedClient,
};
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct State {
    pub persistent: PersistentState,
}

impl State {
    #[inline(never)]
    pub fn new(location: Location) -> Self {
        Self {
            persistent: PersistentState::new(location),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PersistentState {
    #[serde(skip)]
    initialised: bool,
    key_encryption_key: Option<KeyId>,
    key_wrapping_key: Option<KeyId>,
    location: Location,
}

impl PersistentState {
    #[inline(never)]
    fn new(location: Location) -> PersistentState {
        PersistentState {
            initialised: false,
            key_encryption_key: None,
            key_wrapping_key: None,
            location,
        }
    }
}

impl PersistentState {
    const FILENAME: &'static [u8] = b"persistent-state.cbor";

    #[inline(never)]
    pub fn load<T: client::Client + client::Chacha8Poly1305>(
        trussed: &mut T,
        location: Location,
    ) -> Result<Self> {
        // TODO: add "exists_file" method instead?
        let result = try_syscall!(trussed.read_file(location, PathBuf::from(Self::FILENAME),))
            .map_err(|_| Error::Other);

        if result.is_err() {
            info!("err loading: {:?}", result.err().unwrap());
            return Err(Error::Other);
        }

        let data = result.unwrap().data;

        let result = trussed::cbor_deserialize(&data);

        if result.is_err() {
            info!("err deser'ing: {:?}", result.err().unwrap());
            info!("{}", hex_str!(&data));
            return Err(Error::Other);
        }

        result.map_err(|_| Error::Other)
    }

    #[inline(never)]
    pub fn save<T: TrussedClient>(&self, trussed: &mut T) -> Result<()> {
        let data = crate::helpers::cbor_serialize_message(self).unwrap();

        syscall!(trussed.write_file(
            self.location,
            PathBuf::from(Self::FILENAME),
            heapless_bytes::Bytes::from_slice(data.as_slice()).unwrap(),
            None,
        ));
        Ok(())
    }

    #[inline(never)]
    pub fn reset<T: TrussedClient>(&mut self, trussed: &mut T) -> Result<()> {
        if let Some(key) = self.key_encryption_key {
            syscall!(trussed.delete(key));
        }
        if let Some(key) = self.key_wrapping_key {
            syscall!(trussed.delete(key));
        }
        self.key_encryption_key = None;
        self.key_wrapping_key = None;
        self.save(trussed)
    }

    #[inline(never)]
    pub fn load_if_not_initialised<T: client::Client + client::Chacha8Poly1305>(
        &mut self,
        trussed: &mut T,
    ) {
        if !self.initialised {
            match Self::load(trussed, self.location) {
                Ok(previous_self) => {
                    info!("loaded previous state!");
                    *self = previous_self
                }
                Err(_err) => {
                    info!("error with previous state! {:?}", _err);
                }
            }
            self.initialised = true;
        }
    }

    #[inline(never)]
    pub fn key_encryption_key<T: client::Client + client::Chacha8Poly1305>(
        &mut self,
        trussed: &mut T,
    ) -> Result<KeyId> {
        match self.key_encryption_key {
            Some(key) => Ok(key),
            None => self.rotate_key_encryption_key(trussed),
        }
    }

    #[inline(never)]
    pub fn rotate_key_encryption_key<T: client::Client + client::Chacha8Poly1305>(
        &mut self,
        trussed: &mut T,
    ) -> Result<KeyId> {
        debug_now!("Rotating encryption key");
        if let Some(key) = self.key_encryption_key {
            syscall!(trussed.delete(key));
        }
        let key = syscall!(trussed.generate_chacha8poly1305_key(self.location)).key;
        self.key_encryption_key = Some(key);
        self.save(trussed)?;
        Ok(key)
    }

    #[inline(never)]
    pub fn key_wrapping_key<T: client::Client + client::Chacha8Poly1305>(
        &mut self,
        trussed: &mut T,
    ) -> Result<KeyId> {
        match self.key_wrapping_key {
            Some(key) => Ok(key),
            None => self.rotate_key_wrapping_key(trussed),
        }
    }

    #[inline(never)]
    pub fn rotate_key_wrapping_key<T: client::Client + client::Chacha8Poly1305>(
        &mut self,
        trussed: &mut T,
    ) -> Result<KeyId> {
        self.load_if_not_initialised(trussed);
        if let Some(key) = self.key_wrapping_key {
            syscall!(trussed.delete(key));
        }
        let key = syscall!(trussed.generate_chacha8poly1305_key(self.location)).key;
        self.key_wrapping_key = Some(key);
        self.save(trussed)?;
        Ok(key)
    }
}
