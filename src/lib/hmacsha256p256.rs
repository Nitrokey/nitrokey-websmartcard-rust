// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

use serde::{Deserialize, Serialize};
use trussed::types::Message;
use trussed::{
    client::ClientError,
    key::{self, Kind},
    serde_extensions::{Extension, ExtensionClient, ExtensionImpl, ExtensionResult},
    service::{Keystore, ServiceResources},
    types::{Bytes, CoreContext, KeyId, Location, Mechanism},
    Error,
};

#[derive(Debug, Default)]
pub struct Backend {}

#[derive(Debug, Default)]
pub struct BackendContext {}

impl Backend {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Default)]
pub struct HmacSha256P256Extension;

#[derive(Debug, Deserialize, Serialize)]
#[allow(missing_docs)]
pub enum HmacSha256P256Request {
    DeriveFromHash(request::DeriveFromHash),
    InjectAnyKey(request::InjectAnyKey),
}

mod request {
    use super::*;
    use serde::{Deserialize, Serialize};
    use trussed::types::{KeyId, Location, Mechanism, Message};
    use trussed::Error;

    #[derive(Debug, Deserialize, Serialize)]
    pub struct DeriveFromHash {
        pub mechanism: Mechanism,
        pub key: KeyId,
        pub location: Location,
        pub data: Option<Message>,
    }

    impl TryFrom<HmacSha256P256Request> for DeriveFromHash {
        type Error = Error;
        fn try_from(request: HmacSha256P256Request) -> Result<Self, Self::Error> {
            match request {
                HmacSha256P256Request::DeriveFromHash(request) => Ok(request),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<DeriveFromHash> for HmacSha256P256Request {
        fn from(request: DeriveFromHash) -> Self {
            Self::DeriveFromHash(request)
        }
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct InjectAnyKey {
        pub location: Location,
        pub kind: Kind,
        // pub raw_key: SerializedKey,
        pub raw_key: Message,
    }

    impl TryFrom<HmacSha256P256Request> for InjectAnyKey {
        type Error = Error;
        fn try_from(request: HmacSha256P256Request) -> Result<Self, Self::Error> {
            match request {
                HmacSha256P256Request::InjectAnyKey(request) => Ok(request),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<InjectAnyKey> for HmacSha256P256Request {
        fn from(request: InjectAnyKey) -> Self {
            Self::InjectAnyKey(request)
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(missing_docs)]
pub enum HmacSha256P256Reply {
    DeriveFromHash(reply::DeriveFromHash),
    InjectAnyKey(reply::InjectAnyKey),
}

mod reply {
    use serde::{Deserialize, Serialize};
    use trussed::{types::KeyId, Error};

    use super::*;

    #[derive(Debug, Deserialize, Serialize)]
    #[non_exhaustive]
    pub struct DeriveFromHash {
        pub key: Option<KeyId>,
    }

    impl TryFrom<HmacSha256P256Reply> for DeriveFromHash {
        type Error = Error;
        fn try_from(reply: HmacSha256P256Reply) -> Result<Self, Self::Error> {
            match reply {
                HmacSha256P256Reply::DeriveFromHash(reply) => Ok(reply),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<DeriveFromHash> for HmacSha256P256Reply {
        fn from(reply: DeriveFromHash) -> Self {
            Self::DeriveFromHash(reply)
        }
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct InjectAnyKey {
        pub key: Option<KeyId>,
    }

    impl TryFrom<HmacSha256P256Reply> for InjectAnyKey {
        type Error = Error;
        fn try_from(reply: HmacSha256P256Reply) -> Result<Self, Self::Error> {
            match reply {
                HmacSha256P256Reply::InjectAnyKey(reply) => Ok(reply),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<InjectAnyKey> for HmacSha256P256Reply {
        fn from(reply: InjectAnyKey) -> Self {
            Self::InjectAnyKey(reply)
        }
    }
}

impl Extension for HmacSha256P256Extension {
    type Request = HmacSha256P256Request;
    type Reply = HmacSha256P256Reply;
}

pub fn derive_key_from_hash(
    keystore: &mut impl Keystore,
    request: &request::DeriveFromHash,
) -> Result<reply::DeriveFromHash, Error> {
    use hmac::{Hmac, Mac};
    type HmacSha256P256 = Hmac<sha2::Sha256>;

    let key_id = request.key;
    let key = keystore.load_key(key::Secrecy::Secret, None, &key_id)?;
    let shared_secret = key.material;

    let mut mac =
        HmacSha256P256::new_from_slice(shared_secret.as_ref()).map_err(|_| Error::InternalError)?;

    if let Some(data) = &request.data {
        mac.update(data);
    }
    let derived_key: [u8; 32] = mac.finalize().into_bytes().into();
    let key_id = keystore.store_key(
        request.location,
        key::Secrecy::Secret,
        key::Kind::P256, // TODO use mechanism/kind from the request
        &derived_key,
    )?;
    Ok(reply::DeriveFromHash { key: Some(key_id) })
}

pub fn inject_any_key(
    keystore: &mut impl Keystore,
    request: &request::InjectAnyKey,
) -> Result<reply::InjectAnyKey, Error> {
    let key_id = keystore.store_key(
        request.location,
        key::Secrecy::Secret,
        request.kind,
        &request.raw_key,
    )?;

    Ok(reply::InjectAnyKey { key: Some(key_id) })
}

impl ExtensionImpl<HmacSha256P256Extension> for Backend {
    fn extension_request<P: trussed::Platform>(
        &mut self,
        core_ctx: &mut CoreContext,
        _backend_ctx: &mut Self::Context,
        request: &HmacSha256P256Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<HmacSha256P256Reply, Error> {
        let keystore = &mut resources.keystore(core_ctx.path.clone())?;
        match request {
            HmacSha256P256Request::DeriveFromHash(request) => {
                derive_key_from_hash(keystore, request).map(Into::into)
            }
            HmacSha256P256Request::InjectAnyKey(request) => {
                inject_any_key(keystore, request).map(Into::into)
            }
        }
    }
}

type HmacSha256P256Result<'a, R, C> = ExtensionResult<'a, HmacSha256P256Extension, R, C>;

pub trait HmacSha256P256Client: ExtensionClient<HmacSha256P256Extension> {
    fn derive_from_hash(
        &mut self,
        mechanism: Mechanism,
        key: KeyId,
        location: Location,
        data: &[u8],
    ) -> HmacSha256P256Result<'_, reply::DeriveFromHash, Self> {
        let data = Bytes::from_slice(data).map_err(|_| ClientError::DataTooLarge)?;
        self.extension(request::DeriveFromHash {
            mechanism,
            key,
            location,
            data: Some(data),
        })
    }

    fn inject_any_key(
        &mut self,
        // raw_key: SerializedKey,
        raw_key: Message,
        location: Location,
        kind: Kind,
    ) -> HmacSha256P256Result<'_, reply::InjectAnyKey, Self> {
        self.extension(request::InjectAnyKey {
            location,
            kind,
            raw_key,
        })
    }
}

impl<C: ExtensionClient<HmacSha256P256Extension>> HmacSha256P256Client for C {}

impl trussed::backend::Backend for Backend {
    type Context = BackendContext;
}
