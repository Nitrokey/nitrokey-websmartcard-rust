use cbor_smol::cbor_deserialize;
pub use ctap_types::ctap1::Error as U2fError;
use heapless::Vec;

use heapless_bytes::{Bytes, Bytes32};
use trussed::api::reply::Encrypt;
use trussed::key::Kind;
use trussed::types::{KeyId, SerializedKey};

use trussed::types::PathBuf;
use trussed::{
    client, syscall, try_syscall,
    types::{KeySerialization, Location, Mechanism, SignatureSerialization},
};

#[cfg(feature = "rsa")]
use trussed_rsa_alloc::RsaImportFormat;

use crate::commands_types::*;
use crate::constants::GIT_VERSION;
use crate::constants::{WEBCRYPT_AVAILABLE_SLOTS_MAX, WEBCRYPT_VERSION};
use crate::rk_files::*;
use crate::transport::Webcrypt;
use crate::types::CommandID::{ChangePin, SetPin};
use crate::types::Error;

use crate::helpers::hash;
use crate::openpgp::OpenPGPData;
use crate::types::Error::{BadFormat, InternalError};
use crate::{Message, RequestSource};

type CommandResult = Result<(), Error>;

#[cfg(not(feature = "hmacsha256p256"))]
pub trait WebcryptTrussedClient:
    client::Client
    + client::P256
    + client::Chacha8Poly1305
    + client::HmacSha256
    + client::Sha256
    + client::Aes256Cbc
{
}

#[cfg(not(feature = "hmacsha256p256"))]
impl<
        C: client::Client
            + client::P256
            + client::Chacha8Poly1305
            + client::HmacSha256
            + client::Sha256
            + client::Aes256Cbc,
    > WebcryptTrussedClient for C
{
}

#[cfg(feature = "hmacsha256p256")]
pub trait WebcryptTrussedClient:
    client::Client
    + client::P256
    + client::Chacha8Poly1305
    + client::HmacSha256
    + client::Sha256
    + client::HmacSha256P256
    + client::Aes256Cbc
{
}

#[cfg(feature = "hmacsha256p256")]
impl<
        C: client::Client
            // + client::Rsa2048Pkcs1v15
            + client::P256
            + client::Chacha8Poly1305
            + client::HmacSha256
            + client::Sha256
            + client::HmacSha256P256
            + client::Aes256Cbc,
    > WebcryptTrussedClient for C
{
}

pub fn cmd_status<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    let git_version_bytes = Bytes::from_slice(GIT_VERSION[..].as_bytes()).unwrap();
    let resp = CommandStatusResponse {
        unlocked: w.session.is_open(),
        version: WEBCRYPT_VERSION,
        slots: WEBCRYPT_AVAILABLE_SLOTS_MAX,
        pin_attempts: w.state.pin.get_counter(),
        version_string: Some(git_version_bytes),
    };
    w.send_to_output(resp);
    Ok(())
}

pub fn cmd_test_ping<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    w.send_input_to_output();
    Ok(())
}

pub fn cmd_generate_key<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    let req: CommandGenerateRequest = w.get_input_deserialized().map_err(|_| Error::BadFormat)?;
    w.session
        .check_token_res(req.tp)
        .map_err(|_| Error::RequireAuthentication)?;

    // Generate a new P256 key pair.
    let private_key = syscall!(w.trussed.generate_p256_private_key(Location::Volatile)).key;
    let public_key = syscall!(w
        .trussed
        .derive_p256_public_key(private_key, Location::Volatile))
    .key;

    // public key
    let serialized_raw_public_key = syscall!(w
        .trussed
        .serialize_p256_key(public_key, KeySerialization::Raw))
    .serialized_key;

    let keyhandle_ser_enc = wrap_key_to_keyhandle(w, private_key)?;

    syscall!(w.trussed.delete(public_key));
    syscall!(w.trussed.delete(private_key));

    w.send_to_output({
        let mut pubkey = Bytes65::from_slice(serialized_raw_public_key.as_slice()).unwrap();
        // add identifier for uncompressed form - 0x04
        pubkey
            .insert(0, 0x04)
            .map_err(|_| Error::FailedLoadingData)?;
        CommandGenerateResponse {
            pubkey,
            keyhandle: KeyHandleSerialized::from_slice(&keyhandle_ser_enc[..]).unwrap(),
        }
    });

    Ok(())
}

pub fn wrap_key_to_keyhandle<C>(
    w: &mut Webcrypt<C>,
    private_key: KeyId,
) -> Result<KeyHandleSerialized, Error>
where
    C: WebcryptTrussedClient,
{
    let appid = w.session.rp_id_hash.clone().ok_or(Error::BadOrigin)?;

    // The wrapping operation is reused from the fido-authenticator crate.
    // 1. The private key is wrapped using a persistent wrapping key using ChaCha8-Poly1305 AEAD algorithm.
    // 2. The wrapped key is embedded into a KeyHandle data structure, containing additional metadata (RP ID, Usage Flags).
    // 3. The serialized KeyHandle structure is finally CBOR serialized and encrypted, resulting in a binary blob to be used with other commands.

    let wrapping_key = w
        .store
        .persistent
        .key_wrapping_key(&mut w.trussed)
        .map_err(|_| Error::FailedLoadingData)?;
    info!("wrapping u2f private key");
    let wrapped_key =
        syscall!(w
            .trussed
            .wrap_key_chacha8poly1305(wrapping_key, private_key, &appid))
        .wrapped_key;

    let nonce_2 = syscall!(w.trussed.random_bytes(12));
    let nonce = nonce_2.bytes.as_slice();
    let mut nonce_b = [0; 12];
    nonce_b.copy_from_slice(nonce);

    let kh = KeyHandle {
        appid: appid.clone(),
        wrapped_private_key: wrapped_key
            .to_bytes()
            .map_err(|_| Error::FailedLoadingData)?,
        nonce: Bytes::<12>::from_slice(nonce).unwrap(),
        usage_flags: None,
        mechanism: None,
    };

    let kek = w
        .store
        .persistent
        .key_encryption_key(&mut w.trussed)
        .map_err(|_| Error::FailedLoadingData)?;
    let keyhandle_ser = kh.ser();
    let encr =
        syscall!(w
            .trussed
            .encrypt_chacha8poly1305(kek, &keyhandle_ser, &appid, Some(&nonce_b)));
    let keyhandle_ser_enc: KeyHandleSerialized = trussed::cbor_serialize_bytes(&encr).unwrap();
    Ok(keyhandle_ser_enc)
}

pub fn cmd_sign<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    let req: CommandSignRequest = w.get_input_deserialized().map_err(|_| Error::BadFormat)?;
    w.session
        .check_token_res(req.tp)
        .map_err(|_| Error::RequireAuthentication)?;

    if !(req.keyhandle.len() > 0 && req.hash.len() > 0) {
        return Err(Error::FailedLoadingData);
    }

    let (key, mechanism, keyhandle_points_to_rk) = get_key_from_keyhandle(w, req.keyhandle)?;

    let signature = syscall!(w.trussed.sign(
        mechanism,
        key,
        req.hash.as_slice(),
        SignatureSerialization::Raw
    ))
    .signature;
    let signature = signature.to_bytes().expect("Too small target buffer");

    if !keyhandle_points_to_rk {
        syscall!(w.trussed.delete(key));
    }

    w.send_to_output({
        CommandSignResponse {
            inhash: req.hash,
            signature,
        }
    });

    Ok(())
}

fn get_key_from_keyhandle<C>(
    w: &mut Webcrypt<C>,
    keyhandle: KeyHandleSerialized,
) -> ResultW<(KeyId, Mechanism, bool)>
where
    C: WebcryptTrussedClient,
{
    if keyhandle.len() == 0 {
        return Err(BadFormat);
    }

    let res = if keyhandle.len() > 32 {
        // invalid keyhandle or lack of memory
        let (keyid, mechanism) = import_key_from_keyhandle(w, &keyhandle)?;
        (keyid, mechanism, false)
    } else {
        // this is RK
        let rp_id_hash = w.session.rp_id_hash.as_ref().unwrap();
        let cred_data = try_syscall!(w.trussed.read_file(
            Location::Internal,
            rk_path(
                rp_id_hash,
                &Bytes32::from_slice(keyhandle.as_slice()).unwrap()
            )
        ))
        .map_err(|_| Error::MemoryFull)?
        .data;
        let cred: CredentialData = cbor_deserialize(cred_data.as_slice()).unwrap();
        let mech = cred_to_mechanism(&cred);
        (cred.key_id, mech, true)
    };
    Ok(res)
}

fn cred_to_mechanism(cred: &CredentialData) -> Mechanism {
    let mech = match cred.algorithm {
        0 => Mechanism::P256,
        1 => Mechanism::Rsa2048Pkcs1v15,
        _ => Mechanism::P256,
    };
    mech
}

fn import_key_from_keyhandle<C>(
    w: &mut Webcrypt<C>,
    encrypted_serialized_keyhandle: &KeyHandleSerialized,
) -> Result<(KeyId, Mechanism), Error>
where
    C: WebcryptTrussedClient,
{
    // encr_ser -> encr struct -> decrypted serialized -> struct

    // The deserialization method of the keyhandle is resued from the fido-authenticator project.
    // 1. The encrypted keyhandle is decrypted and deserialized to a KeyHandle structure using persistent encryption key.
    // 2. From the resulting KeyHandle structure the wrapped private key is decrypted and deserialized
    // 3. Finally, the wrapped private key is imported to the volatile in-memory keystore, and used for the further operations.

    let appid = w.session.rp_id_hash.clone().ok_or(Error::BadOrigin)?;

    let encr_message: Encrypt = cbor_deserialize(encrypted_serialized_keyhandle.as_slice())
        .map_err(|_| Error::BadFormat)?;

    let kek = w
        .store
        .persistent
        .key_encryption_key(&mut w.trussed)
        .map_err(|_| Error::InternalError)?;
    let decrypted_serialized = try_syscall!(w.trussed.decrypt_chacha8poly1305(
        kek,
        &encr_message.ciphertext,
        &appid,
        &encr_message.nonce,
        &encr_message.tag,
    ));
    let decrypted_serialized = decrypted_serialized
        .map_err(|_| Error::InternalError)?
        .plaintext
        .ok_or(Error::BadOrigin)?;

    let key_handle: KeyHandle = KeyHandle::deser(decrypted_serialized);
    let keywrapped = key_handle.wrapped_private_key;

    if key_handle.appid != w.session.rp_id_hash.as_ref().unwrap() {
        return Err(Error::BadOrigin);
    }

    let wrapping_key = w
        .store
        .persistent
        .key_wrapping_key(&mut w.trussed)
        .map_err(|_| Error::InternalError)?;
    let key = syscall!(w.trussed.unwrap_key_chacha8poly1305(
        wrapping_key,
        &keywrapped,
        &appid,
        Location::Volatile,
    ))
    .key
    .ok_or(Error::InternalError)?;

    let m = key_handle.mechanism.unwrap_or(Mechanism::P256);

    Ok((key, m))
}

pub fn cmd_openpgp_generate<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    let _: CommandOpenPGPInitRequest = w
        .get_input_deserialized()
        .map_err(|_| Error::FailedLoadingData)?;

    w.state.openpgp_data = Some(OpenPGPData::init(&mut w.trussed));
    w.state.save(&mut w.trussed);
    Ok(())
}

pub fn cmd_openpgp_info<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    let _: CommandOpenPGPInfoRequest = w
        .get_input_deserialized()
        .map_err(|_| Error::FailedLoadingData)?;

    // FIXME remove -> initialize in a separate command
    // move to state initialization
    if w.state.openpgp_data.is_none() {
        w.state.openpgp_data = Some(OpenPGPData::init(&mut w.trussed));
        w.state.save(&mut w.trussed);
    }

    let openpgp_data = w
        .state
        .openpgp_data
        .as_mut()
        .ok_or(Error::FailedLoadingData)?;
    let encr_pubkey = DataBytes::from_slice(
        openpgp_data
            .encryption
            .get_public_key_serialized(&mut w.trussed)
            .as_slice(),
    )
    .map_err(|_| Error::FailedLoadingData)?;
    let auth_pubkey = DataBytes::from_slice(
        openpgp_data
            .authentication
            .get_public_key_serialized(&mut w.trussed)
            .as_slice(),
    )
    .map_err(|_| Error::FailedLoadingData)?;
    let sign_pubkey = DataBytes::from_slice(
        openpgp_data
            .signing
            .get_public_key_serialized(&mut w.trussed)
            .as_slice(),
    )
    .map_err(|_| Error::FailedLoadingData)?;

    // let sign_keyhandle = wrap_key_to_keyhandle(w, openpgp_data.signing.key)?;

    let date = DataBytes::from_slice(&openpgp_data.date).map_err(|_| Error::InternalError)?;
    w.send_to_output(CommandOpenPGPInfoResponse {
        encr_pubkey,
        auth_pubkey,
        sign_pubkey,
        date,
    });

    Ok(())
}

pub fn cmd_openpgp_import<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    let req = match w.get_input_deserialized() {
        Ok(x) => Ok(x),
        Err(e) => {
            log::error!("Deserialization error: {:?}", e);
            Err(e)
        }
    };

    let req: CommandOpenPGPImportRequest = req.map_err(|_| Error::BadFormat)?;
    w.session
        .check_token_res(req.tp)
        .map_err(|_| Error::RequireAuthentication)?;

    w.state.openpgp_data = Some(OpenPGPData::import(
        &mut w.trussed,
        req.auth_privkey,
        req.sign_privkey,
        req.encr_privkey,
        req.date.unwrap_or_default(),
    )?);
    w.state.save(&mut w.trussed);

    Ok(())
}

pub fn cmd_openpgp_sign<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    let req = match w.get_input_deserialized() {
        Ok(x) => Ok(x),
        Err(e) => {
            log::error!("Deserialization error: {:?}", e);
            Err(e)
        }
    };

    let req: CommandOpenPGPSignRequest = req.map_err(|_| Error::BadFormat)?;
    w.session
        .check_token_res(req.tp)
        .map_err(|_| Error::RequireAuthentication)?;

    // FIXME remove -> initialize in a separate command
    // move to state initialization
    if w.state.openpgp_data.is_none() {
        w.state.openpgp_data = Some(OpenPGPData::init(&mut w.trussed));
        w.state.save(&mut w.trussed);
    }

    let signature = try_syscall!(w.trussed.sign(
        Mechanism::P256,
        w.state.openpgp_data.as_ref().unwrap().signing.key,
        req.data.as_slice(),
        SignatureSerialization::Raw
    ))
    .map_err(|e| {
        log::error!("Signing error: {:?}", e);
        Error::FailedLoadingData
    })?
    .signature;
    let signature = signature.to_bytes().expect("Too small target buffer");

    w.send_to_output(CommandOpenPGPSignResponse { signature });

    Ok(())
}

pub fn cmd_openpgp_decrypt<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    let req = match w.get_input_deserialized() {
        Ok(x) => Ok(x),
        Err(e) => {
            log::error!("Deserialization error: {:?}", e);
            Err(e)
        }
    };

    let req: CommandOpenPGPDecryptRequest = req.map_err(|_| Error::BadFormat)?;
    w.session
        .check_token_res(req.tp)
        .map_err(|_| Error::RequireAuthentication)?;

    // FIXME remove -> initialize in a separate command
    // move to state initialization
    if w.state.openpgp_data.is_none() {
        w.state.openpgp_data = Some(OpenPGPData::init(&mut w.trussed));
        w.state.save(&mut w.trussed);
    }

    // TODO find via provided fingerprint if not, get from openpgp info struct, or use the first one
    // Currently check for the exact match of the held openpgp keys and their fingerprints
    // if provided, use keyhandle or just default encryption key
    let (kh_key, mech, is_rk) = if req.fingerprint.is_none() && req.keyhandle.is_none() {
        let open_pgpkey = &w
            .state
            .openpgp_data
            .as_ref()
            .ok_or(Error::FailedLoadingData)?
            .encryption;
        (open_pgpkey.key, open_pgpkey.key_mechanism, true)
    } else if req.fingerprint.is_some() {
        (
            w.state
                .openpgp_data
                .as_ref()
                .ok_or(Error::NotFound)?
                .get_id_by_fingerprint(
                    req.fingerprint
                        .unwrap()
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::FailedLoadingData)?,
                )
                .ok_or(Error::NotFound)?,
            Mechanism::P256,
            true,
        )
    } else {
        let keyhandle = req.keyhandle.unwrap();
        get_key_from_keyhandle(w, keyhandle)?
    };

    let agreed_shared_secret_id = {
        let ecc_key: Vec<u8, 64> = match req.eccekey.len() {
            65 => Vec::<u8, 64>::from_slice(&req.eccekey[1..65]).unwrap(),
            64 => Vec::<u8, 64>::from_slice(&req.eccekey[0..64]).unwrap(),
            _ => return Err(Error::FailedLoadingData),
        };

        // import incoming public key
        let ephem_pub_bin_key = try_syscall!(w.trussed.deserialize_p256_key(
            &ecc_key,
            trussed::types::KeySerialization::Raw,
            trussed::types::StorageAttributes::new()
                .set_persistence(trussed::types::Location::Volatile)
        ))
        .map_err(|_| Error::FailedLoadingData)?
        .key;

        // agree on shared secret
        try_syscall!(w.trussed.agree(
            Mechanism::P256,
            kh_key,
            ephem_pub_bin_key,
            trussed::types::StorageAttributes::new()
                .set_persistence(Location::Volatile)
                .set_serializable(true)
        ))
        .map_err(|_| Error::FailedLoadingData)?
        .shared_secret
    };

    let serialized_shared_secret = try_syscall!(w.trussed.serialize_key(
        Mechanism::SharedSecret,
        agreed_shared_secret_id,
        KeySerialization::Raw
    ))
    .map_err(|e| {
        log::error!("Deserialization error: {:?}", e);
        Error::InternalError
    })?;
    syscall!(w.trussed.delete(agreed_shared_secret_id));

    w.send_to_output(CommandOpenPGPDecryptResponse {
        data: DataBytes::from_slice(&serialized_shared_secret.serialized_key)
            .map_err(|_| Error::InternalError)?,
    });

    Ok(())
}

pub fn cmd_decrypt<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    let req = match w.get_input_deserialized() {
        Ok(x) => Ok(x),
        Err(e) => {
            log::error!("Deserialization error: {:?}", e);
            Err(e)
        }
    };

    let req: CommandDecryptRequest = req.map_err(|_| Error::BadFormat)?;
    w.session
        .check_token_res(req.tp.clone())
        .map_err(|_| Error::RequireAuthentication)?;

    let (kh_key, mech, is_rk) = get_key_from_keyhandle(w, req.keyhandle.clone())?;

    let decrypted = match mech {
        Mechanism::P256 => decrypt_ecc_p256(w, req, kh_key),
        Mechanism::Rsa2048Pkcs1v15 => decrypt_rsa(w, req, kh_key),
        _ => Err(InternalError),
    }?;

    if !is_rk {
        // FIXME introduce types to distinct derived and resident keys
        syscall!(w.trussed.delete(kh_key));
    }

    w.send_to_output(CommandDecryptResponse {
        data: Bytes::from_slice(decrypted.as_slice()).unwrap(),
    });

    Ok(())
}

fn decrypt_rsa<C>(
    w: &mut Webcrypt<C>,
    req: CommandDecryptRequest,
    kh_key: KeyId,
) -> ResultW<Message>
where
    C: WebcryptTrussedClient,
{
    if !(req.keyhandle.len() > 0
        && req.data.len() > 0
        && req.hmac.is_none()
        && req.eccekey.is_none())
    {
        return Err(Error::BadFormat);
    }
    // TODO HMAC?
    // let decrypted = try_syscall!(w.trussed.decrypt_Rsa2048Pkcs1v15(kh_key, &req.data))
    //     .map_err(|e| {
    //         log::error!("Decryption error: {:?}", e);
    //         Error::FailedLoadingData
    //     })?
    //     .plaintext
    //     .ok_or(InternalError)?;
    //
    // Ok(decrypted)
    Ok(Default::default())
}

fn decrypt_ecc_p256<C>(
    w: &mut Webcrypt<C>,
    req: CommandDecryptRequest,
    kh_key: KeyId,
) -> ResultW<Message>
where
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Aes256Cbc
        + client::HmacSha256
        + client::HmacSha256P256
        + client::Sha256
        + client::Chacha8Poly1305,
{
    let req_eccekey = req.eccekey.ok_or(BadFormat)?;
    let req_hmac = req.hmac.ok_or(BadFormat)?;
    if !(req.keyhandle.len() > 0
        && req_eccekey.len() > 0
        && req.data.len() > 0
        && req_hmac.len() > 0)
    {
        return Err(BadFormat);
    }

    let ecc_key: Vec<u8, 64> = match req_eccekey.len() {
        65 => Vec::<u8, 64>::from_slice(&req_eccekey[1..65]).unwrap(),
        64 => Vec::<u8, 64>::from_slice(&req_eccekey[0..64]).unwrap(),
        _ => return Err(Error::FailedLoadingData),
    };

    // import incoming public key
    let ephem_pub_bin_key = try_syscall!(w.trussed.deserialize_p256_key(
        &ecc_key,
        trussed::types::KeySerialization::Raw,
        trussed::types::StorageAttributes::new()
            .set_persistence(trussed::types::Location::Volatile)
    ))
    .map_err(|_| Error::FailedLoadingData)?
    .key;

    // agree on shared secret
    let shared_secret = try_syscall!(w.trussed.agree(
        Mechanism::P256,
        kh_key,
        ephem_pub_bin_key,
        trussed::types::StorageAttributes::new()
            .set_persistence(Location::Volatile)
            .set_serializable(true)
    ))
    .map_err(|_| Error::FailedLoadingData)?
    .shared_secret;

    // check HMAC
    // TODO DESIGN derive separate key for HMAC
    let encoded_ciphertext_len: [u8; 2] = (req.data.len() as u16).to_le_bytes();
    let mut data_to_hmac = Message::new(); // FIXME check length
    data_to_hmac.extend(req.data.clone());
    data_to_hmac.extend(req_eccekey);
    data_to_hmac.extend(encoded_ciphertext_len);
    data_to_hmac.extend(req.keyhandle);

    let calculated_hmac = try_syscall!(w.trussed.sign(
        Mechanism::HmacSha256,
        shared_secret,
        &data_to_hmac,
        SignatureSerialization::Raw
    ))
    .map_err(|_| Error::FailedLoadingData)?
    .signature;

    let hmac_correct = calculated_hmac == req_hmac;
    if !hmac_correct {
        // abort decryption on invalid hmac value
        return Err(Error::InvalidChecksum);
    }

    // TODO Webcrypt design: use separate symmetric key?
    // let symmetric_key = syscall!(
    //         w.trussed.derive_key(Mechanism::Sha256, shared_secret, None,
    //             trussed::types::StorageAttributes::new().set_persistence(Location::Volatile))
    //     ).key;

    // FIXME set the right type at first, instead of serializing and importing the key again
    // Related: https://github.com/trussed-dev/trussed/pull/43
    let serialized_shared_secret = try_syscall!(w.trussed.serialize_key(
        Mechanism::SharedSecret,
        shared_secret,
        KeySerialization::Raw
    ))
    .map_err(|e| {
        log::error!("Deserialization error: {:?}", e);
        Error::InternalError
    })?
    .serialized_key;
    let serialized_reimported = try_syscall!(w.trussed.unsafe_inject_shared_key(
        // &k.serialize(),
        serialized_shared_secret.as_slice(),
        Location::Internal,
        #[cfg(feature = "inject-any-key")]
        Kind::Symmetric(32)
    ))
    .map_err(|_| Error::FailedLoadingData)?
    .key;

    // decrypt with shared secret
    let decrypted = try_syscall!(w
        .trussed
        .decrypt_aes256cbc(serialized_reimported, &req.data))
    .map_err(|e| {
        log::error!("Decryption error: {:?}", e);
        Error::FailedLoadingData
    })?
    .plaintext
    .ok_or(Error::InternalError)?;

    syscall!(w.trussed.delete(shared_secret));
    syscall!(w.trussed.delete(serialized_reimported));
    syscall!(w.trussed.delete(ephem_pub_bin_key));
    Ok(decrypted
        .try_convert_into()
        .map_err(|_| Error::InternalError)?)
}

#[cfg(feature = "hmacsha256p256")]
pub fn cmd_generate_key_from_data<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    let req: CommandGenerateFromDataRequest =
        w.get_input_deserialized().map_err(|_| Error::BadFormat)?;
    w.session
        .check_token_res(req.tp)
        .map_err(|_| Error::RequireAuthentication)?;

    let kek = w.state.get_key_master(&mut w.trussed).unwrap();
    // TODO DESIGN decide whether rpid should be a part of the generated hash
    // let rpid = w.session.rp_id_hash.as_ref().unwrap();
    // req.hash
    //     .extend_from_slice(rpid.as_slice())
    //     .map_err(|_| Error::FailedLoadingData)?;
    let data_for_key = &req.hash[..];
    if req.hash.len() < 32 {
        return Err(Error::FailedLoadingData);
    }

    let derived_key = syscall!(
        // requires support on the trussed side
        w.trussed
            .hmacsha256p256_derive_key(kek, data_for_key, Location::Volatile)
    )
    .key;
    let private_key = derived_key;

    // public key
    let public_key = syscall!(w
        .trussed
        .derive_p256_public_key(private_key, Location::Volatile))
    .key;
    let serialized_raw_public_key = syscall!(w
        .trussed
        .serialize_p256_key(public_key, KeySerialization::Raw))
    .serialized_key;
    let keyhandle_ser_enc = wrap_key_to_keyhandle(w, private_key)?;

    syscall!(w.trussed.delete(public_key));
    syscall!(w.trussed.delete(private_key));

    w.send_to_output({
        let mut pubkey = Bytes65::from_slice(serialized_raw_public_key.as_slice()).unwrap();
        // add identifier for uncompressed form - 0x04
        pubkey
            .insert(0, 0x04)
            .map_err(|_| Error::FailedLoadingData)?;
        CommandGenerateResponse {
            pubkey,
            keyhandle: KeyHandleSerialized::from_slice(&keyhandle_ser_enc[..]).unwrap(),
        }
    });

    Ok(())
}

pub fn cmd_read_resident_key_public<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    let req: CommandReadResidentKeyRequest =
        w.get_input_deserialized().map_err(|_| Error::BadFormat)?;
    log::info!("WC cmd_read_resident_key_public {:?}", req);
    w.session
        .check_token_res(req.tp)
        .map_err(|_| Error::RequireAuthentication)?;

    // Get private keyid
    // let private_key = {
    //     let rp_id_hash = w.session.rp_id_hash.as_ref().unwrap();
    //     let cred_data = try_syscall!(w.trussed.read_file(
    //         Location::Internal,
    //         rk_path(
    //             rp_id_hash,
    //             &Bytes32::from_slice(req.keyhandle.as_slice()).unwrap()
    //         )
    //     ))
    //     .map_err(|_| Error::MemoryFull)? // TODO Change to Error::FailedLoadingData
    //     .data;
    //     let cred: CredentialData = cbor_deserialize(cred_data.as_slice()).unwrap();
    //     cred.key_id
    // };
    //
    // let public_key = try_syscall!(w
    //     .trussed
    //     .derive_p256_public_key(private_key, Location::Volatile))
    // .map_err(|_| Error::NotFound)?
    // .key;
    //
    // // generate keyhandle for the reply
    // let cred = CredentialData::new(private_key);
    // let serialized_credential = cred.serialize()?;
    // let credential_id_hash = syscall!(w.trussed.hash_sha256(serialized_credential.as_slice()))
    //     .hash
    //     .to_bytes()
    //     .unwrap();

    let (private_key, mech, is_rk) = get_key_from_keyhandle(w, req.keyhandle.clone())?;

    let kind = match mech {
        Mechanism::P256 => Kind::P256,
        Mechanism::Rsa2048Pkcs1v15 => Kind::Rsa2048,
        _ => todo!(),
    };
    let (public_key, serialized_raw_public_key) = get_public_key(w, kind, private_key)?;

    syscall!(w.trussed.delete(public_key));
    if !is_rk {
        // FIXME introduce types to distinct derived and resident keys
        syscall!(w.trussed.delete(private_key));
    }
    w.send_to_output({
        let mut pubkey = Message::from_slice(serialized_raw_public_key.as_slice()).unwrap();
        if kind == Kind::P256 {
            // add identifier for uncompressed form - 0x04
            pubkey.insert(0, 0x04).map_err(|_| InternalError)?;
        }
        CommandGenerateResidentKeyResponse {
            pubkey: pubkey.try_convert_into().map_err(|_| InternalError)?,
            keyhandle: req.keyhandle,
        }
    });

    Ok(())
}

pub fn cmd_login<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    // Check PIN and return temporary password for the further communication
    let req: CommandLoginRequest = w.get_input_deserialized().map_err(|_| Error::BadFormat)?;

    // hash rpid if the request is coming from FIDO2
    // TODO move hashing to transport
    let rpid = {
        let rpid = &w.req_details.as_ref().unwrap().rpid;
        if w.req_details.as_ref().unwrap().source == RequestSource::RS_FIDO2 {
            hash(
                &mut w.trussed,
                Message::from_slice(rpid.as_slice()).unwrap(),
            )
        } else {
            rpid.clone()
        }
    };

    #[cfg(feature = "transparent-encryption")]
    try_syscall!(w
        .trussed
        .set_client_context_pin(Bytes::from_slice(req.pin.as_slice()).unwrap()))
    .map_err(|_| Error::InternalError)?;

    // ignore loading errors for now
    log::info!("WC loading state");
    w.state
        .load(&mut w.trussed)
        // the cause might be in the corrupted storage as well (Error::FailedLoadingData),
        // but we can't differentiate at this point
        .map_err(|_| Error::InvalidPin)?;

    let login_result = w
        .session
        .login(req.pin, &mut w.trussed, &rpid, &mut w.state);
    w.state.save(&mut w.trussed);
    let tp = login_result?;

    w.send_to_output(CommandLoginResponse { tp });

    Ok(())
}

pub fn cmd_logout<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    let _: CommandLogoutRequest = w.get_input_deserialized().map_err(|_| Error::BadFormat)?;

    w.state.save(&mut w.trussed);
    // Clear session
    w.session.logout();
    w.state.logout();

    #[cfg(feature = "transparent-encryption")]
    try_syscall!(w
        .trussed
        .set_client_context_pin(Bytes::from_slice(b"invalid pin").unwrap()))
    .map_err(|_| Error::InternalError)?;

    Ok(())
}

pub fn cmd_factory_reset<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    // Call factory reset for Webcrypt, and for the associated services (like FIDO2) as well.

    // close session
    w.session.reset();

    // TODO call associated services

    // remove all generated RK
    syscall!(w.trussed.delete_all(Location::Internal));
    syscall!(w
        .trussed
        .remove_dir_all(Location::Internal, PathBuf::from("wcrk"),));

    #[cfg(feature = "transparent-encryption")]
    {
        let default_pin = Bytes::from_slice(crate::DEFAULT_ENCRYPTION_PIN.as_ref()).unwrap();
        try_syscall!(w.trussed.reset_pin(default_pin)).map_err(|_| Error::InternalError)?;
    }

    // delete persistent state
    // reset PIN
    w.state.reset(&mut w.trussed);
    w.store.persistent.reset(&mut w.trussed).unwrap();

    w.state.save(&mut w.trussed);

    Ok(())
}

pub fn cmd_configure<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    // Allow to set some configuration options, like when to require user touch confirmation
    // To decide: same handler for both setting and getting?

    let mut req: CommandConfigureRequest =
        w.get_input_deserialized().map_err(|_| Error::BadFormat)?;
    w.session
        .check_token_res(req.tp)
        .map_err(|_| Error::RequireAuthentication)?;

    if req.confirmation.is_some() {
        w.state.configuration.confirmation = req.confirmation.unwrap();
    }
    req.confirmation = Some(w.state.configuration.confirmation);
    req.tp = None;
    w.send_to_output(req);

    Ok(())
}

pub fn cmd_manage_pin<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    // To decide: same handler for both setting and changing?

    match w.current_command_id {
        SetPin => {
            let req: CommandSetPINRequest =
                w.get_input_deserialized().map_err(|_| Error::BadFormat)?;
            w.state.pin.set_pin(req.pin)?;

            #[cfg(feature = "transparent-encryption")]
            {
                try_syscall!(w.trussed.set_client_context_pin(
                    Bytes::from_slice(DEFAULT_ENCRYPTION_PIN.as_ref()).unwrap()
                ))
                .map_err(|_| Error::InternalError)?;
                try_syscall!(w.trussed.change_pin(req.pin.to_bytes().unwrap()))
                    .map_err(|_| Error::InternalError)?;
            }

            w.state.initialize(&mut w.trussed);
            Ok(())
        }
        ChangePin => {
            let req: CommandChangePINRequest =
                w.get_input_deserialized().map_err(|_| Error::BadFormat)?;
            w.state.pin.change_pin(req.pin, req.newpin)?;
            #[cfg(feature = "transparent-encryption")]
            try_syscall!(w
                .trussed
                .change_pin(Bytes::from_slice(req.newpin.as_slice()).unwrap()))
            .map_err(|_| Error::InternalError)?;

            Ok(())
        }
        _ => Err(Error::InvalidCommand),
    }
}

pub fn cmd_discover_resident_key<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    // Discover all RKs connected to this RP. Should be protected with PIN (L3 credprotect as of CTAP2.1).

    let req: CommandDiscoverResidentKeyRequest =
        w.get_input_deserialized().map_err(|_| Error::BadFormat)?;
    w.session
        .check_token_res(req.tp)
        .map_err(|_| Error::RequireAuthentication)?;

    // then store key, making it resident
    // let credential_id_hash = self.hash(credential_id.0.as_ref());
    // try_syscall!(self.trussed.write_file(
    //             Location::Internal,
    //             rk_path(&rp_id_hash, &credential_id_hash),
    //             serialized_credential,
    //             // user attribute for later easy lookup
    //             // Some(rp_id_hash.clone()),
    //             None,
    //         ))
    //     .map_err(|_| Error::KeyStoreFull)?;

    // w.trussed.read_file()
    // w.trussed.write_file()
    //             rk_path(&rp_id_hash, &credential_id_hash),

    let rp_id_hash = w.session.rp_id_hash.as_ref().unwrap();

    // first read
    let mut maybe_path =
        syscall!(w
            .trussed
            .read_dir_first(Location::Internal, rp_rk_dir(rp_id_hash), None,))
        .entry
        .map(|entry| PathBuf::try_from(entry.path()).unwrap());

    // following reads
    while let Some(path) = maybe_path {
        let _credential_data =
            syscall!(w.trussed.read_file(Location::Internal, path.clone(),)).data;

        maybe_path = syscall!(w.trussed.read_dir_next())
            .entry
            .map(|entry| PathBuf::try_from(entry.path()).unwrap());
    }

    // TODO finish

    // let res = {
    //     let num_credentials = w.state.runtime.remaining_credentials();
    //     let credential = w.state.runtime.pop_credential(&mut self.trussed);
    //     credential.map(|credential| (credential, num_credentials))
    // };

    Ok(())
}

pub fn cmd_write_resident_key<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient + client::Sha256,
{
    let req: CommandWriteResidentKeyRequest =
        w.get_input_deserialized().map_err(|_| Error::BadFormat)?;
    w.session
        .check_token_res(req.tp)
        .map_err(|_| Error::RequireAuthentication)?;

    let rp_id_hash = w.session.rp_id_hash.as_ref().unwrap();
    // write private key

    let kind = keytype_to_kind(&req.key_type);
    let mechanism = match kind {
        Kind::Rsa2048 => Mechanism::Rsa2048Pkcs1v15,
        Kind::P256 => Mechanism::P256,
        _ => {
            todo!()
        }
    };

    let private_key = {
        if req.rsa_e.is_none() {
            try_syscall!(w.trussed.unsafe_inject_key(
                mechanism,
                req.raw_key_data.ok_or(Error::BadFormat)?.as_slice(),
                Location::Internal,
                KeySerialization::Pkcs8Der
            ))
            .map_err(|_| Error::FailedLoadingData)?
            .key
        } else {
            let data = RsaImportFormat {
                e: &req.rsa_e.ok_or(Error::BadFormat)?,
                p: &req.rsa_p.ok_or(Error::BadFormat)?,
                q: &req.rsa_q.ok_or(Error::BadFormat)?,
            };
            try_syscall!(w.trussed.unsafe_inject_key(
                mechanism,
                &data.serialize().map_err(|_| Error::InternalError)?,
                Location::Internal,
                KeySerialization::RsaParts
            ))
            .map_err(|_| Error::FailedLoadingData)?
            .key
        }
    };
    // let public_key = try_syscall!(w
    //     .trussed
    //     .derive_p256_public_key(private_key, Location::Volatile))
    // .map_err(|_| Error::FailedLoadingData)?
    // .key;

    // write file

    let cred = CredentialData {
        key_id: private_key,
        algorithm: req.key_type.unwrap_or(0) as i32,
        creation_time: 0,
        allowed_use: 0,
    };
    let serialized_credential = cred.serialize()?;

    let credential_id_hash = syscall!(w.trussed.hash_sha256(serialized_credential.as_slice()))
        .hash
        .to_bytes()
        .unwrap();

    try_syscall!(w.trussed.write_file(
        Location::Internal,
        rk_path(rp_id_hash, &credential_id_hash),
        serialized_credential,
        None,
    ))
    .map_err(|_| Error::MemoryFull)?;

    // get public key
    let (public_key, serialized_raw_public_key) = get_public_key(w, kind, private_key)?;

    syscall!(w.trussed.delete(public_key));

    w.send_to_output({
        let mut pubkey = Message::from_slice(serialized_raw_public_key.as_slice()).unwrap();
        if kind == Kind::P256 {
            // add identifier for uncompressed form - 0x04
            pubkey.insert(0, 0x04).map_err(|_| Error::InternalError)?;
        }
        CommandWriteResidentKeyResponse {
            pubkey: pubkey.try_convert_into().map_err(|_| InternalError)?,
            keyhandle: Bytes::from_slice(credential_id_hash.as_slice()).unwrap(),
        }
    });

    Ok(())
}

fn keytype_to_kind(key_type: &KeyType) -> Kind {
    match key_type {
        None => Kind::P256,
        Some(kind) => match kind {
            0 => Kind::P256,
            1 => Kind::Rsa2048,
            _ => Kind::P256,
        },
    }
}

fn get_public_key<C>(
    w: &mut Webcrypt<C>,
    kind: Kind,
    private_key: KeyId,
) -> ResultW<(KeyId, SerializedKey)>
where
    C: WebcryptTrussedClient,
{
    use trussed::types::StorageAttributes;
    let (public_key, serialized_raw_public_key) = match kind {
        Kind::P256 => {
            let public_key = try_syscall!(w
                .trussed
                .derive_p256_public_key(private_key, Location::Volatile))
            .map_err(|_| Error::FailedLoadingData)?
            .key;

            let serialized_raw_public_key = syscall!(w
                .trussed
                .serialize_p256_key(public_key, KeySerialization::Raw))
            .serialized_key;
            (public_key, serialized_raw_public_key)
        }
        Kind::Rsa2048 => {
            let pk = syscall!(w.trussed.derive_key(
                Mechanism::Rsa2048Pkcs1v15,
                private_key,
                None,
                StorageAttributes::new().set_persistence(Location::Volatile)
            ))
            .key;
            let serialized_key = syscall!(w
                .trussed
                // .serialize_Rsa2048Pkcs1v15_key(pk, KeySerialization::RsaPkcs1)) // TODO check if this works
                .serialize_key(Mechanism::Rsa2048Pkcs1v15, pk, KeySerialization::Pkcs8Der))
            .serialized_key;
            (pk, serialized_key)
        }
        _ => todo!(),
    };
    Ok((public_key, serialized_raw_public_key))
}

pub fn cmd_generate_resident_key<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient + client::Sha256,
{
    // write the RK similarly, as done with FIDO2, potentially with some extensions

    let req: CommandGenerateResidentKeyRequest =
        w.get_input_deserialized().map_err(|_| Error::BadFormat)?;
    w.session
        .check_token_res(req.tp)
        .map_err(|_| Error::RequireAuthentication)?;

    // Generate a new P256 key pair.
    // Can fail with FilesystemWriteFailure, if the full capacity is reached
    let private_key = syscall!(w.trussed.generate_p256_private_key(Location::Internal)).key;
    let public_key = syscall!(w
        .trussed
        .derive_p256_public_key(private_key, Location::Volatile))
    .key;

    let cred = CredentialData::new(private_key);
    let serialized_credential = cred.serialize()?;

    let rp_id_hash = w.session.rp_id_hash.as_ref().unwrap();
    let credential_id_hash = syscall!(w.trussed.hash_sha256(serialized_credential.as_slice()))
        .hash
        .to_bytes()
        .unwrap();

    try_syscall!(w.trussed.write_file(
        Location::Internal,
        rk_path(rp_id_hash, &credential_id_hash),
        serialized_credential,
        None,
    ))
    .map_err(|_| Error::MemoryFull)?;

    // public key
    let serialized_raw_public_key = syscall!(w
        .trussed
        .serialize_p256_key(public_key, KeySerialization::Raw))
    .serialized_key;

    // let keyhandle_ser_enc = private_key.hex();

    syscall!(w.trussed.delete(public_key));

    w.send_to_output({
        let mut pubkey = Message::from_slice(serialized_raw_public_key.as_slice()).unwrap();
        // add identifier for uncompressed form - 0x04
        pubkey.insert(0, 0x04).map_err(|_| Error::InternalError)?;
        CommandGenerateResidentKeyResponse {
            pubkey: pubkey.try_convert_into().map_err(|_| InternalError)?,
            keyhandle: Bytes::from_slice(credential_id_hash.as_slice()).unwrap(),
        }
    });

    Ok(())
}

pub fn cmd_restore_from_seed<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    let req: CommandRestoreRequest = w.get_input_deserialized().map_err(|_| Error::BadFormat)?;
    w.session
        .check_token_res(req.tp)
        .map_err(|_| Error::RequireAuthentication)?;

    let master = &req.master;

    // TODO use salt
    // make tests happy by combining the master secret with salt
    // let master = {
    //     let mut master_salt: Bytes<40> = Default::default();
    //     master_salt.extend(req.master.iter().cloned());
    //     master_salt.extend(req.salt.iter().cloned());
    //     let master_hash = syscall!( w.trussed.hash(Mechanism::Sha256, master_salt.to_bytes().unwrap())).hash.to_bytes().unwrap();
    //     master_hash
    // };

    w.state.restore(&mut w.trussed, master);

    let hash = syscall!(w
        .trussed
        .hash(Mechanism::Sha256, req.master.to_bytes().unwrap()))
    .hash
    .to_bytes()
    .unwrap();

    w.send_to_output(CommandRestoreResponse { hash });

    Ok(())
}

pub fn cmd_initialize_seed<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: WebcryptTrussedClient,
{
    let req: CommandInitializeRequest = w.get_input_deserialized().map_err(|_| Error::BadFormat)?;
    w.session
        .check_token_res(req.tp)
        .map_err(|_| Error::RequireAuthentication)?;

    if req.entropy.is_some() && req.entropy.unwrap().len() > 0 {
        // todo!();
        return Err(Error::NotImplemented);
    }

    // Initialize / factory-reset the state
    w.state.initialize(&mut w.trussed);

    // TODO DESIGN to reconsider publishing raw key
    let master = w.state.get_master_key_raw().unwrap_or_default();
    w.send_to_output({
        CommandInitializeResponse {
            master,
            salt: Default::default(),
        }
    });

    Ok(())
}
