#![allow(non_camel_case_types)]

use heapless_bytes::{Bytes, Bytes32, Bytes64};
use trussed::{
    client, syscall, try_syscall,
    types::{KeyId, Location},
};

// use std::borrow::Borrow;
use crate::constants::RESIDENT_KEY_COUNT;
use crate::types::Error;
use crate::Message;
use trussed::key::Kind;
use trussed::types::PathBuf;

type ResidentKeyID = u8;

type MasterKeyRawBytes = Bytes32;

/// Configurable fields with defaults
#[derive(Serialize, Deserialize)]
pub struct WebcryptConfiguration {
    /// ask for confirmation for Webcrypt commands
    pub confirmation: u8,
}

impl Default for WebcryptConfiguration {
    fn default() -> Self {
        Self { confirmation: 1 }
    }
}

use crate::commands_types::ExpectedSessionToken;
use crate::openpgp::OpenPGPData;
use cbor_smol::{cbor_deserialize, cbor_serialize};
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize)]
pub struct WebcryptPIN {
    pin: Option<Bytes64>,
    counter: u8,
}

impl WebcryptPIN {
    pub fn get_counter(&self) -> u8 {
        self.counter
    }

    pub fn decrease_counter(&mut self) -> Result<(), Error> {
        if self.counter == 0 {
            log::info!("Counter PIN used up");
            return Err(Error::NotAllowed);
        }
        self.counter -= 1;
        Ok(())
    }

    pub fn check_pin(&mut self, pin: Bytes64) -> Result<bool, Error> {
        if self.pin.is_none() {
            log::info!("PIN not set");
            return Err(Error::NotAllowed);
        }
        if self.counter == 0 {
            log::info!("Counter PIN used up");
            return Err(Error::NotAllowed);
        }
        self.decrease_counter()?;

        log::info!("Counter PIN value: {:?}", self.counter);

        // TODO use side-channels safe comparison library, e.g. subtle
        if pin != self.pin.as_ref().unwrap() {
            return Err(Error::InvalidPin);
        }
        self.counter = 8;

        Ok(true)
    }

    fn validate_pin(&self, pin: &Bytes64) -> Result<(), Error> {
        let l = pin.len();
        if !(4..=64).contains(&l) {
            Err(Error::NotAllowed)
        } else {
            Ok(())
        }
    }

    pub fn set_pin(&mut self, pin: Bytes64) -> Result<bool, Error> {
        if self.pin.is_some() {
            return Err(Error::NotAllowed);
        }
        self.validate_pin(&pin)?;
        self.pin = Some(pin);
        self.counter = 8;
        Ok(true)
    }
    pub fn change_pin(&mut self, pin: Bytes64, new_pin: Bytes64) -> Result<bool, Error> {
        if self.pin.is_none() {
            return Err(Error::NotAllowed);
        }
        self.validate_pin(&new_pin)?;
        self.check_pin(pin)?;
        self.pin = Some(new_pin);
        Ok(true)
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct WebcryptState {
    initialized_tag: u8,
    version: u8,
    pub resident_keys: heapless::Vec<ResidentKeyID, RESIDENT_KEY_COUNT>,
    master_key: Option<KeyId>,
    master_key_raw: Option<MasterKeyRawBytes>,
    pub configuration: WebcryptConfiguration,
    pub pin: WebcryptPIN,
    pub openpgp_data: Option<OpenPGPData>,
}

#[derive(Default)]
pub struct WebcryptSession {
    temporary_password_token: Option<Bytes32>,

    // todo: make a getter
    pub rp_id_hash: Option<Bytes32>,
}

impl WebcryptSession {
    pub(crate) fn reset(&mut self) {
        self.logout();
    }

    pub fn is_open(&self) -> bool {
        self.temporary_password_token.is_some()
    }

    pub(crate) fn logout(&mut self) {
        self.temporary_password_token = None;
        self.rp_id_hash = None;
    }

    fn set_token(&mut self, token: Bytes32, rp_id_hash: Bytes<32>) {
        self.temporary_password_token = Some(token);
        self.rp_id_hash = Some(rp_id_hash);
    }

    fn get_new_token<C: trussed::Client>(&mut self, trussed: &mut C) -> Bytes32 {
        let b = syscall!(trussed.random_bytes(32)).bytes;
        Bytes32::from_slice(b.as_slice()).unwrap()
    }

    pub fn login<C: trussed::Client>(
        &mut self,
        pin: Bytes64,
        trussed: &mut C,
        rp_id_hash: &Bytes<32>,
        state: &mut WebcryptState,
    ) -> Result<Bytes32, Error> {
        let tp: Bytes32 = if state.pin.check_pin(pin)? {
            self.get_new_token(trussed)
        } else {
            log::info!("PIN invalid");
            return Err(Error::InvalidPin);
        };
        self.set_token(tp.clone(), rp_id_hash.clone());
        Ok(tp)
    }

    pub fn check_token(&self, token: Bytes32) -> bool {
        match &self.temporary_password_token {
            None => false,
            Some(current) => token == current,
        }
    }

    pub fn check_token_res(&self, token: ExpectedSessionToken) -> Result<(), ()> {
        #[cfg(feature = "no-authentication")]
        return Ok(());

        let token = match token {
            None => {
                return Err(());
            }
            Some(token) => token,
        };

        // TODO should allow empty tokens, if user was verified through CTAP2 already
        match &self.temporary_password_token {
            None => Err(()),
            Some(current) => {
                if token == current {
                    Ok(())
                } else {
                    log::warn!("Token invalid: {:?}, expected: {:?}", token, current);
                    Err(())
                }
            }
        }
    }
}

const STATE_FILE_PATH: &[u8; 10] = b"wcrk/state";

impl WebcryptState {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn reset<C>(&mut self, t: &mut C)
    where
        C: client::Client,
    {
        log::info!("Resetting state");
        self.pin = Default::default();
        if let Some(x) = &self.openpgp_data {
            if let Err(e) = x.clear(t) {
                log::error!("Failed resetting state: {:?}", e);
            }
        }
        self.openpgp_data = None;
        self.initialize(t);
    }

    pub fn initialize<C>(&mut self, t: &mut C)
    where
        C: client::Client,
    {
        self.initialized_tag = 0xA5_u8;

        self.rotate_key_master(t);
        self.save(t);
    }

    pub fn restore<C>(&mut self, t: &mut C, master: &Bytes32)
    where
        C: client::Client,
    {
        self.initialized_tag = 0xA5_u8;

        if let Some(key) = self.master_key {
            syscall!(t.delete(key));
        }
        // 2. set as key
        let key = syscall!(t.unsafe_inject_shared_key(
            master,
            Location::Internal,
            #[cfg(feature = "inject-any-key")]
            Kind::Shared(32)
        ))
        .key;
        self.master_key = Some(key);
        // 3. return it up to the caller
        self.save(t);
    }

    pub fn get_key_master<T>(&mut self, trussed: &mut T) -> Option<KeyId>
    where
        T: client::Client,
    {
        match self.master_key {
            Some(key) => Some(key),
            None => self.rotate_key_master(trussed),
        }
    }

    pub fn get_master_key_raw(&mut self) -> Option<MasterKeyRawBytes> {
        self.master_key_raw.take()
    }

    pub fn rotate_key_master<T>(&mut self, t: &mut T) -> Option<KeyId>
    where
        T: client::Client,
    {
        if let Some(key) = self.master_key {
            syscall!(t.delete(key));
        }

        log::info!("Rotating master key");
        // 1. get random data
        let data = syscall!(t.random_bytes(32)).bytes;
        self.master_key_raw = Some(data.to_bytes().unwrap());
        self.master_key = {
            if let Some(key) = self.master_key {
                syscall!(t.delete(key));
            }
            // 2. set as key
            let key = syscall!(t.unsafe_inject_shared_key(
                &data,
                Location::Internal,
                #[cfg(feature = "inject-any-key")]
                Kind::Shared(32)
            ))
            .key;
            // 3. return it up to the caller
            Some(key)
        };
        self.save(t);
        self.master_key
    }

    pub fn load<T>(&mut self, t: &mut T) -> Result<(), Error>
    where
        T: client::Client,
    {
        let state_ser =
            try_syscall!(t.read_file(Location::Internal, PathBuf::from(STATE_FILE_PATH)))
                .map_err(|_| Error::InternalError)?
                .data;
        log::info!("State file found. Loading.");

        // todo handle errors from the data corruption separately
        let w = self
            .deserialize(state_ser.as_slice())
            .map_err(|_| Error::InternalError)?;

        if !w.initialized() {
            log::info!("Found state not initialized. Aborting load.");
            return Err(Error::InternalError);
        }

        *self = w;
        // TODO test that
        log::info!("State loaded");
        Ok(())
    }

    fn deserialize(&self, data: &[u8]) -> Result<Self, Error> {
        if data.is_empty() {
            return Err(Error::InternalError);
        }
        cbor_deserialize(data).map_err(|_| Error::InternalError)
    }

    fn serialize(&self) -> Message {
        // TODO decide on memory limits
        let mut slice = [0u8; 2 * 1024];
        Message::from_slice(cbor_serialize(self, &mut slice).unwrap()).unwrap()
    }

    pub fn file_reset<T>(&self, t: &mut T)
    where
        T: client::Client,
    {
        let r = try_syscall!(t.remove_file(Location::Internal, PathBuf::from(STATE_FILE_PATH)));
        if r.is_ok() {
            log::info!("State removed");
        }
    }

    pub fn initialized(&self) -> bool {
        self.initialized_tag == 0xA5
    }

    pub fn save<T>(&self, t: &mut T)
    where
        T: client::Client,
    {
        log::info!("State save called");
        if !self.initialized() {
            log::info!("State not initialized, aborting");
            // abort save on uninitialized structure
            return;
        }
        // todo!();

        try_syscall!(t.write_file(
            Location::Internal,
            PathBuf::from(STATE_FILE_PATH),
            self.serialize(),
            None,
        ))
        .map_err(|_| Error::MemoryFull)
        .unwrap();
        log::info!("State saved");
    }

    pub fn logout(&mut self) {
        self.resident_keys = Default::default();
        self.master_key = None;
        self.master_key_raw = None;
        self.initialized_tag = 0;
    }
}
