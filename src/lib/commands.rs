use cbor_smol::cbor_deserialize;
pub use ctap_types::ctap1::Error as U2fError;
use heapless::Vec;

use heapless_bytes::{Bytes, Bytes32};
use trussed::api::reply::Encrypt;
use trussed::key::Kind;
use trussed::types::KeyId;
use trussed::types::PathBuf;
use trussed::{
    client, syscall, try_syscall,
    types::{KeySerialization, Location, Mechanism, SignatureSerialization},
};
use ERROR_ID::ERR_INTERNAL_ERROR;

use crate::commands_types::*;
use crate::constants::GIT_VERSION;
use crate::constants::{WEBCRYPT_AVAILABLE_SLOTS_MAX, WEBCRYPT_VERSION};
use crate::rk_files::*;
use crate::transport::Webcrypt;
use crate::types::CommandID::{CHANGE_PIN, SET_PIN};
use crate::types::ERROR_ID;

use crate::helpers::hash;
use crate::openpgp::OpenPGPData;
use crate::types::ERROR_ID::{
    ERR_BAD_FORMAT, ERR_BAD_ORIGIN, ERR_FAILED_LOADING_DATA, ERR_INVALID_PIN, ERR_NOT_FOUND,
};
use crate::{Message, RequestSource, DEFAULT_ENCRYPTION_PIN};

type CommandResult = Result<(), ERROR_ID>;

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

pub fn cmd_status<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Chacha8Poly1305
        + client::HmacSha256
        + client::Sha256
        + client::HmacSha256P256
        + client::Aes256Cbc,
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
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Aes256Cbc
        + client::HmacSha256
        + client::HmacSha256P256
        + client::Sha256
        + client::Chacha8Poly1305,
{
    w.send_input_to_output();
    Ok(())
}

pub fn cmd_generate_key<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Aes256Cbc
        + client::HmacSha256
        + client::Sha256
        + client::HmacSha256P256
        + client::Chacha8Poly1305,
{
    let req: CommandGenerateRequest = w
        .get_input_deserialized()
        .map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;
    w.session
        .check_token_res(req.tp.unwrap())
        .map_err(|_| ERROR_ID::ERR_REQ_AUTH)?;

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
            .map_err(|_| ERROR_ID::ERR_FAILED_LOADING_DATA)?;
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
) -> Result<KeyHandleSerialized, ERROR_ID>
where
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Aes256Cbc
        + client::HmacSha256
        + client::HmacSha256P256
        + client::Chacha8Poly1305,
{
    let appid = w.session.rp_id_hash.clone().ok_or(ERR_BAD_ORIGIN)?;

    // The wrapping operation is reused from the fido-authenticator crate.
    // 1. The private key is wrapped using a persistent wrapping key using ChaCha20-Poly1305 AEAD algorithm.
    // 2. The wrapped key is embedded into a KeyHandle data structure, containing additional metadata (RP ID, Usage Flags).
    // 3. The serialized KeyHandle structure is finally CBOR serialized and encrypted, resulting in a binary blob to be used with other commands.

    let wrapping_key = w
        .store
        .persistent
        .key_wrapping_key(&mut w.trussed)
        .map_err(|_| ERROR_ID::ERR_FAILED_LOADING_DATA)?;
    debug!("wrapping u2f private key");
    let wrapped_key =
        syscall!(w
            .trussed
            .wrap_key_chacha8poly1305(wrapping_key, private_key, &appid,))
        .wrapped_key;

    let nonce_2 = syscall!(w.trussed.random_bytes(12));
    let nonce = nonce_2.bytes.as_slice();
    let mut nonce_b = [0; 12];
    nonce_b.copy_from_slice(nonce);

    let kh = KeyHandle {
        appid: appid.clone(),
        wrapped_private_key: wrapped_key
            .to_bytes()
            .map_err(|_| ERROR_ID::ERR_FAILED_LOADING_DATA)?,
        nonce: Bytes::<12>::from_slice(nonce).unwrap(),
        usage_flags: None,
    };

    let kek = w
        .store
        .persistent
        .key_encryption_key(&mut w.trussed)
        .map_err(|_| ERROR_ID::ERR_FAILED_LOADING_DATA)?;
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
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Aes256Cbc
        + client::HmacSha256
        + client::HmacSha256P256
        + client::Sha256
        + client::Chacha8Poly1305,
{
    let req: CommandSignRequest = w
        .get_input_deserialized()
        .map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;
    w.session
        .check_token_res(req.tp.unwrap())
        .map_err(|_| ERROR_ID::ERR_REQ_AUTH)?;

    if !(req.keyhandle.len() > 0 && req.hash.len() > 0) {
        return Err(ERR_FAILED_LOADING_DATA);
    }

    let (key, keyhandle_points_to_RK) = if req.keyhandle.len() > 32 {
        // invalid keyhandle or lack of memory
        (import_key_from_keyhandle(w, &req.keyhandle)?, false)
    } else {
        // this is RK
        let rp_id_hash = w.session.rp_id_hash.as_ref().unwrap();
        let cred_data = try_syscall!(w.trussed.read_file(
            Location::Internal,
            rk_path(
                rp_id_hash,
                &Bytes32::from_slice(req.keyhandle.as_slice()).unwrap()
            )
        ))
        .map_err(|_| ERROR_ID::ERR_MEMORY_FULL)?
        .data;
        let cred: CredentialData = cbor_deserialize(cred_data.as_slice()).unwrap();
        (cred.key_id, true)
    };

    let signature = syscall!(w.trussed.sign(
        Mechanism::P256,
        key,
        req.hash.as_slice(),
        SignatureSerialization::Raw
    ))
    .signature;
    let signature = signature.to_bytes().expect("Too small target buffer");

    if !keyhandle_points_to_RK {
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

fn import_key_from_keyhandle<C>(
    w: &mut Webcrypt<C>,
    encrypted_serialized_keyhandle: &KeyHandleSerialized,
) -> Result<KeyId, ERROR_ID>
where
    C: trussed::Client + client::Client + client::P256 + client::Chacha8Poly1305,
{
    // encr_ser -> encr struct -> decrypted serialized -> struct

    // The deserialization method of the keyhandle is resued from the fido-authenticator project.
    // 1. The encrypted keyhandle is decrypted and deserialized to a KeyHandle structure using persistent encryption key.
    // 2. From the resulting KeyHandle structure the wrapped private key is decrypted and deserialized
    // 3. Finally, the wrapped private key is imported to the volatile in-memory keystore, and used for the further operations.

    let appid = w.session.rp_id_hash.clone().ok_or(ERR_BAD_ORIGIN)?;

    let encr_message: Encrypt =
        trussed::cbor_deserialize(encrypted_serialized_keyhandle.as_slice())
            .map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;

    let kek = w
        .store
        .persistent
        .key_encryption_key(&mut w.trussed)
        .map_err(|_| ERROR_ID::ERR_INTERNAL_ERROR)?;
    let decrypted_serialized = try_syscall!(w.trussed.decrypt_chacha8poly1305(
        kek,
        &encr_message.ciphertext,
        &appid,
        &encr_message.nonce,
        &encr_message.tag,
    ));
    let decrypted_serialized = decrypted_serialized
        .map_err(|_| ERROR_ID::ERR_INTERNAL_ERROR)?
        .plaintext
        .ok_or(ERROR_ID::ERR_BAD_ORIGIN)?;

    let key_handle: KeyHandle = KeyHandle::deser(decrypted_serialized);
    let keywrapped = key_handle.wrapped_private_key;

    if key_handle.appid != w.session.rp_id_hash.as_ref().unwrap() {
        return Err(ERROR_ID::ERR_BAD_ORIGIN);
    }

    let wrapping_key = w
        .store
        .persistent
        .key_wrapping_key(&mut w.trussed)
        .map_err(|_| ERROR_ID::ERR_INTERNAL_ERROR)?;
    let key = syscall!(w.trussed.unwrap_key_chacha8poly1305(
        wrapping_key,
        &keywrapped,
        b"",
        Location::Volatile,
    ))
    .key
    .unwrap();
    Ok(key)
}

pub fn cmd_openpgp_generate<C>(w: &mut Webcrypt<C>) -> CommandResult
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
    let _: CommandOpenPGPInitRequest = w
        .get_input_deserialized()
        .map_err(|_| ERR_FAILED_LOADING_DATA)?;

    w.state.openpgp_data = Some(OpenPGPData::init(&mut w.trussed));
    w.state.save(&mut w.trussed);
    Ok(())
}

pub fn cmd_openpgp_info<C>(w: &mut Webcrypt<C>) -> CommandResult
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
    let _: CommandOpenPGPInfoRequest = w
        .get_input_deserialized()
        .map_err(|_| ERR_FAILED_LOADING_DATA)?;

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
        .ok_or(ERR_FAILED_LOADING_DATA)?;
    let encr_pubkey = DataBytes::from_slice(
        openpgp_data
            .encryption
            .get_public_key_serialized(&mut w.trussed)
            .as_slice(),
    )
    .map_err(|_| ERR_FAILED_LOADING_DATA)?;
    let auth_pubkey = DataBytes::from_slice(
        openpgp_data
            .authentication
            .get_public_key_serialized(&mut w.trussed)
            .as_slice(),
    )
    .map_err(|_| ERR_FAILED_LOADING_DATA)?;
    let sign_pubkey = DataBytes::from_slice(
        openpgp_data
            .signing
            .get_public_key_serialized(&mut w.trussed)
            .as_slice(),
    )
    .map_err(|_| ERR_FAILED_LOADING_DATA)?;

    // let sign_keyhandle = wrap_key_to_keyhandle(w, openpgp_data.signing.key)?;

    let date = DataBytes::from_slice(&openpgp_data.date).map_err(|_| ERR_INTERNAL_ERROR)?;
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
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Aes256Cbc
        + client::HmacSha256
        + client::HmacSha256P256
        + client::Sha256
        + client::Chacha8Poly1305,
{
    let req = match w.get_input_deserialized() {
        Ok(x) => Ok(x),
        Err(e) => {
            log::error!("Deserialization error: {:?}", e);
            Err(e)
        }
    };

    let req: CommandOpenPGPImportRequest = req.map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;
    w.session
        .check_token_res(req.tp.unwrap())
        .map_err(|_| ERROR_ID::ERR_REQ_AUTH)?;

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
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Aes256Cbc
        + client::HmacSha256
        + client::HmacSha256P256
        + client::Sha256
        + client::Chacha8Poly1305,
{
    let req = match w.get_input_deserialized() {
        Ok(x) => Ok(x),
        Err(e) => {
            log::error!("Deserialization error: {:?}", e);
            Err(e)
        }
    };

    let req: CommandOpenPGPSignRequest = req.map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;
    w.session
        .check_token_res(req.tp.unwrap())
        .map_err(|_| ERROR_ID::ERR_REQ_AUTH)?;

    // FIXME remove -> initialize in a separate command
    // move to state initialization
    if w.state.openpgp_data.is_none() {
        w.state.openpgp_data = Some(OpenPGPData::init(&mut w.trussed));
        w.state.save(&mut w.trussed);
    }

    let signature = syscall!(w.trussed.sign(
        Mechanism::P256,
        w.state.openpgp_data.as_ref().unwrap().signing.key,
        req.data.as_slice(),
        SignatureSerialization::Raw
    ))
    .signature;
    let signature = signature.to_bytes().expect("Too small target buffer");

    w.send_to_output(CommandOpenPGPSignResponse { signature });

    Ok(())
}

pub fn cmd_openpgp_decrypt<C>(w: &mut Webcrypt<C>) -> CommandResult
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
    let req = match w.get_input_deserialized() {
        Ok(x) => Ok(x),
        Err(e) => {
            log::error!("Deserialization error: {:?}", e);
            Err(e)
        }
    };

    let req: CommandOpenPGPDecryptRequest = req.map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;
    w.session
        .check_token_res(req.tp.unwrap())
        .map_err(|_| ERROR_ID::ERR_REQ_AUTH)?;

    // FIXME remove -> initialize in a separate command
    // move to state initialization
    if w.state.openpgp_data.is_none() {
        w.state.openpgp_data = Some(OpenPGPData::init(&mut w.trussed));
        w.state.save(&mut w.trussed);
    }

    // TODO find via provided fingerprint if not, get from openpgp info struct, or use the first one
    // Currently check for the exact match of the held openpgp keys and their fingerprints
    // if provided, use keyhandle or just default encryption key
    let kh_key = if req.fingerprint.is_none() && req.keyhandle.is_none() {
        w.state
            .openpgp_data
            .as_ref()
            .ok_or(ERR_FAILED_LOADING_DATA)?
            .encryption
            .key
    } else if req.fingerprint.is_some() {
        w.state
            .openpgp_data
            .as_ref()
            .ok_or(ERR_NOT_FOUND)?
            .get_id_by_fingerprint(
                req.fingerprint
                    .unwrap()
                    .as_slice()
                    .try_into()
                    .map_err(|_| ERR_FAILED_LOADING_DATA)?,
            )
            .ok_or(ERR_NOT_FOUND)?
    } else {
        let keyhandle = req.keyhandle.unwrap();
        // regular keyhandle unpacking below
        // TODO remove duplication / extract unpacking
        if keyhandle.len() > 32 {
            import_key_from_keyhandle(w, &keyhandle)?
        } else {
            let rp_id_hash = w.session.rp_id_hash.as_ref().unwrap();
            let cred_data = try_syscall!(w.trussed.read_file(
                Location::Internal,
                rk_path(
                    rp_id_hash,
                    &Bytes32::from_slice(keyhandle.as_slice()).unwrap()
                )
            ))
            .map_err(|_| ERROR_ID::ERR_MEMORY_FULL)?
            .data;
            let cred: CredentialData = cbor_deserialize(cred_data.as_slice()).unwrap();
            cred.key_id
        }
    };

    let agreed_shared_secret_id = {
        let ecc_key: Vec<u8, 64> = match req.eccekey.len() {
            65 => Vec::<u8, 64>::from_slice(&req.eccekey[1..65]).unwrap(),
            64 => Vec::<u8, 64>::from_slice(&req.eccekey[0..64]).unwrap(),
            _ => return Err(ERR_FAILED_LOADING_DATA),
        };

        // import incoming public key
        let ephem_pub_bin_key = try_syscall!(w.trussed.deserialize_p256_key(
            &ecc_key,
            trussed::types::KeySerialization::Raw,
            trussed::types::StorageAttributes::new()
                .set_persistence(trussed::types::Location::Volatile)
        ))
        .map_err(|_| ERROR_ID::ERR_FAILED_LOADING_DATA)?
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
        .map_err(|_| ERROR_ID::ERR_FAILED_LOADING_DATA)?
        .shared_secret;
        shared_secret
    };

    let serialized_shared_secret = try_syscall!(w.trussed.serialize_key(
        Mechanism::SharedSecret,
        agreed_shared_secret_id,
        KeySerialization::Raw
    ))
    .map_err(|e| {
        log::error!("Deserialization error: {:?}", e);
        ERR_INTERNAL_ERROR
    })?;
    syscall!(w.trussed.delete(agreed_shared_secret_id));

    w.send_to_output(CommandOpenPGPDecryptResponse {
        data: serialized_shared_secret.serialized_key,
    });

    Ok(())
}

pub fn cmd_decrypt<C>(w: &mut Webcrypt<C>) -> CommandResult
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
    let req = match w.get_input_deserialized() {
        Ok(x) => Ok(x),
        Err(e) => {
            log::error!("Deserialization error: {:?}", e);
            Err(e)
        }
    };

    let req: CommandDecryptRequest = req.map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;
    w.session
        .check_token_res(req.tp.unwrap())
        .map_err(|_| ERROR_ID::ERR_REQ_AUTH)?;

    if !(req.keyhandle.len() > 0
        && req.eccekey.len() > 0
        && req.data.len() > 0
        && req.hmac.len() > 0)
    {
        return Err(ERR_BAD_FORMAT);
    }

    let kh_key = if req.keyhandle.len() > 32 {
        import_key_from_keyhandle(w, &req.keyhandle)?
    } else {
        let rp_id_hash = w.session.rp_id_hash.as_ref().unwrap();
        let cred_data = try_syscall!(w.trussed.read_file(
            Location::Internal,
            rk_path(
                rp_id_hash,
                &Bytes32::from_slice(req.keyhandle.as_slice()).unwrap()
            )
        ))
        .map_err(|_| ERROR_ID::ERR_MEMORY_FULL)?
        .data;
        let cred: CredentialData = cbor_deserialize(cred_data.as_slice()).unwrap();
        cred.key_id
    };

    let ecc_key: Vec<u8, 64> = match req.eccekey.len() {
        65 => Vec::<u8, 64>::from_slice(&req.eccekey[1..65]).unwrap(),
        64 => Vec::<u8, 64>::from_slice(&req.eccekey[0..64]).unwrap(),
        _ => return Err(ERR_FAILED_LOADING_DATA),
    };

    // import incoming public key
    let ephem_pub_bin_key = try_syscall!(w.trussed.deserialize_p256_key(
        &ecc_key,
        trussed::types::KeySerialization::Raw,
        trussed::types::StorageAttributes::new()
            .set_persistence(trussed::types::Location::Volatile)
    ))
    .map_err(|_| ERROR_ID::ERR_FAILED_LOADING_DATA)?
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
    .map_err(|_| ERROR_ID::ERR_FAILED_LOADING_DATA)?
    .shared_secret;

    // check HMAC
    // TODO DESIGN derive separate key for HMAC
    let encoded_ciphertext_len: [u8; 2] = (req.data.len() as u16).to_le_bytes();
    let mut data_to_hmac = Message::new(); // FIXME check length
    data_to_hmac.extend(req.data.clone());
    data_to_hmac.extend(req.eccekey);
    data_to_hmac.extend(encoded_ciphertext_len);
    data_to_hmac.extend(req.keyhandle);

    let calculated_hmac = try_syscall!(w.trussed.sign(
        Mechanism::HmacSha256,
        shared_secret,
        &data_to_hmac,
        SignatureSerialization::Raw
    ))
    .map_err(|_| ERROR_ID::ERR_FAILED_LOADING_DATA)?
    .signature;

    let hmac_correct = calculated_hmac == req.hmac;
    if !hmac_correct {
        // abort decryption on invalid hmac value
        return Err(ERROR_ID::ERR_INVALID_CHECKSUM);
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
        ERR_INTERNAL_ERROR
    })?
    .serialized_key;
    let serialized_reimported = try_syscall!(w.trussed.unsafe_inject_shared_key(
        // &k.serialize(),
        serialized_shared_secret.as_slice(),
        Location::Internal,
        Kind::Symmetric(32)
    ))
    .map_err(|_| ERROR_ID::ERR_FAILED_LOADING_DATA)?
    .key;

    // decrypt with shared secret
    let decrypted = try_syscall!(w
        .trussed
        .decrypt_aes256cbc(serialized_reimported, &req.data))
    .map_err(|e| {
        log::error!("Decryption error: {:?}", e);
        ERROR_ID::ERR_FAILED_LOADING_DATA
    })?
    .plaintext
    .ok_or(ERR_INTERNAL_ERROR)?;

    syscall!(w.trussed.delete(kh_key));
    syscall!(w.trussed.delete(shared_secret));
    syscall!(w.trussed.delete(serialized_reimported));
    syscall!(w.trussed.delete(ephem_pub_bin_key));

    w.send_to_output(CommandDecryptResponse { data: decrypted });

    Ok(())
}

pub fn cmd_generate_key_from_data<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Aes256Cbc
        + client::HmacSha256
        + client::Sha256
        + client::HmacSha256P256
        + client::Chacha8Poly1305,
{
    let req: CommandGenerateFromDataRequest = w
        .get_input_deserialized()
        .map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;
    w.session
        .check_token_res(req.tp.unwrap())
        .map_err(|_| ERROR_ID::ERR_REQ_AUTH)?;

    let kek = w.state.get_key_master(&mut w.trussed).unwrap();
    // TODO DESIGN decide whether rpid should be a part of the generated hash
    // let rpid = w.session.rp_id_hash.as_ref().unwrap();
    // req.hash
    //     .extend_from_slice(rpid.as_slice())
    //     .map_err(|_| ERROR_ID::ERR_FAILED_LOADING_DATA)?;
    let data_for_key = &req.hash[..];
    if req.hash.len() < 32 {
        return Err(ERR_FAILED_LOADING_DATA);
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
            .map_err(|_| ERROR_ID::ERR_FAILED_LOADING_DATA)?;
        CommandGenerateResponse {
            pubkey,
            keyhandle: KeyHandleSerialized::from_slice(&keyhandle_ser_enc[..]).unwrap(),
        }
    });

    Ok(())
}

pub fn cmd_read_resident_key_public<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Aes256Cbc
        + client::Sha256
        + client::HmacSha256
        + client::HmacSha256P256
        + client::Chacha8Poly1305,
{
    let req: CommandReadResidentKeyRequest = w
        .get_input_deserialized()
        .map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;
    log::debug!("WC cmd_read_resident_key_public {:?}", req);
    w.session
        .check_token_res(req.tp.unwrap())
        .map_err(|_| ERROR_ID::ERR_REQ_AUTH)?;

    // Get private keyid
    let private_key = {
        let rp_id_hash = w.session.rp_id_hash.as_ref().unwrap();
        let cred_data = try_syscall!(w.trussed.read_file(
            Location::Internal,
            rk_path(
                rp_id_hash,
                &Bytes32::from_slice(req.keyhandle.as_slice()).unwrap()
            )
        ))
        .map_err(|_| ERROR_ID::ERR_MEMORY_FULL)? // TODO Change to ERR_FAILED_LOADING_DATA
        .data;
        let cred: CredentialData = cbor_deserialize(cred_data.as_slice()).unwrap();
        cred.key_id
    };

    let public_key = try_syscall!(w
        .trussed
        .derive_p256_public_key(private_key, Location::Volatile))
    .map_err(|_| ERROR_ID::ERR_NOT_FOUND)?
    .key;

    // generate keyhandle for the reply
    let cred = CredentialData::new(private_key);
    let serialized_credential = cred.serialize()?;
    let credential_id_hash = syscall!(w.trussed.hash_sha256(serialized_credential.as_slice()))
        .hash
        .to_bytes()
        .unwrap();

    // public key preparation
    let serialized_raw_public_key = syscall!(w
        .trussed
        .serialize_p256_key(public_key, KeySerialization::Raw))
    .serialized_key;

    syscall!(w.trussed.delete(public_key));

    w.send_to_output({
        let mut pubkey = Bytes65::from_slice(serialized_raw_public_key.as_slice()).unwrap();
        // add identifier for uncompressed form - 0x04
        pubkey
            .insert(0, 0x04)
            .map_err(|_| ERROR_ID::ERR_FAILED_LOADING_DATA)?;
        CommandGenerateResidentKeyResponse {
            pubkey,
            keyhandle: credential_id_hash,
        }
    });

    Ok(())
}

pub fn cmd_login<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Aes256Cbc
        + client::HmacSha256
        + client::Sha256
        + client::HmacSha256P256
        + client::Chacha8Poly1305,
{
    // Check PIN and return temporary password for the further communication
    let req: CommandLoginRequest = w
        .get_input_deserialized()
        .map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;

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

    try_syscall!(w
        .trussed
        .set_client_context_pin(Bytes::from_slice(req.pin.as_slice()).unwrap()))
    .map_err(|_| ERR_INTERNAL_ERROR)?;

    // 1. test cycle
    // 2. wrong pin login, set wrong PIN in the context => broken filesystem
    // 3. calling tests again
    // 4. this factory reset
    //

    // ignore loading errors for now
    log::debug!("WC loading state");
    let res = w
        .state
        .load(&mut w.trussed)
        // the cause might be in the corrupted storage as well (ERR_FAILED_LOADING_DATA),
        // but we can't differentiate at this point
        .map_err(|_| ERR_INVALID_PIN);
    if res.is_err() {
        w.state.pin.decrease_counter()?;
        res?
    }

    let tp = w
        .session
        .login(req.pin.clone(), &mut w.trussed, &rpid, &mut w.state)?;

    w.send_to_output(CommandLoginResponse { tp });

    Ok(())
}

pub fn cmd_logout<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Aes256Cbc
        + client::HmacSha256
        + client::Sha256
        + client::HmacSha256P256
        + client::Chacha8Poly1305,
{
    let _: CommandLogoutRequest = w
        .get_input_deserialized()
        .map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;

    w.state.save(&mut w.trussed);
    // Clear session
    w.session.logout();
    w.state.logout();
    try_syscall!(w
        .trussed
        .set_client_context_pin(Bytes::from_slice(b"invalid pin").unwrap()))
    .map_err(|_| ERR_INTERNAL_ERROR)?;

    Ok(())
}

pub fn cmd_factory_reset<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: trussed::Client,
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

    let default_pin = Bytes::from_slice(DEFAULT_ENCRYPTION_PIN.as_ref()).unwrap();
    try_syscall!(w.trussed.reset_pin(default_pin)).map_err(|_| ERR_INTERNAL_ERROR)?;

    // delete persistent state
    // reset PIN
    w.state.reset(&mut w.trussed);
    w.store.persistent.reset(&mut w.trussed).unwrap();

    w.state.save(&mut w.trussed);

    Ok(())
}

pub fn cmd_configure<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Aes256Cbc
        + client::Sha256
        + client::HmacSha256
        + client::HmacSha256P256
        + client::Chacha8Poly1305,
{
    // Allow to set some configuration options, like when to require user touch confirmation
    // To decide: same handler for both setting and getting?

    let mut req: CommandConfigureRequest = w
        .get_input_deserialized()
        .map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;
    w.session
        .check_token_res(req.tp.unwrap())
        .map_err(|_| ERROR_ID::ERR_REQ_AUTH)?;

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
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Aes256Cbc
        + client::Sha256
        + client::HmacSha256
        + client::HmacSha256P256
        + client::Chacha8Poly1305,
{
    // To decide: same handler for both setting and changing?

    match w.current_command_id {
        SET_PIN => {
            let req: CommandSetPINRequest = w
                .get_input_deserialized()
                .map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;
            w.state.pin.set_pin(req.pin.clone())?;

            try_syscall!(w.trussed.set_client_context_pin(
                Bytes::from_slice(DEFAULT_ENCRYPTION_PIN.as_ref()).unwrap()
            ))
            .map_err(|_| ERR_INTERNAL_ERROR)?;
            try_syscall!(w.trussed.change_pin(req.pin.to_bytes().unwrap()))
                .map_err(|_| ERR_INTERNAL_ERROR)?;

            w.state.initialize(&mut w.trussed);
            Ok(())
        }
        CHANGE_PIN => {
            let req: CommandChangePINRequest = w
                .get_input_deserialized()
                .map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;
            w.state.pin.change_pin(req.pin, req.newpin.clone())?;
            try_syscall!(w
                .trussed
                .change_pin(Bytes::from_slice(req.newpin.as_slice()).unwrap()))
            .map_err(|_| ERROR_ID::ERR_INTERNAL_ERROR)?;

            Ok(())
        }
        _ => Err(ERROR_ID::ERR_INVALID_COMMAND),
    }
}

pub fn cmd_discover_resident_key<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Aes256Cbc
        + client::Sha256
        + client::HmacSha256
        + client::HmacSha256P256
        + client::Chacha8Poly1305,
{
    // Discover all RKs connected to this RP. Should be protected with PIN (L3 credprotect as of CTAP2.1).

    let req: CommandDiscoverResidentKeyRequest = w
        .get_input_deserialized()
        .map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;
    w.session
        .check_token_res(req.tp.unwrap())
        .map_err(|_| ERROR_ID::ERR_REQ_AUTH)?;

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
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Aes256Cbc
        + client::HmacSha256
        + client::HmacSha256P256
        + client::Chacha8Poly1305
        + client::Sha256,
{
    let req: CommandWriteResidentKeyRequest = w
        .get_input_deserialized()
        .map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;
    w.session
        .check_token_res(req.tp.unwrap())
        .map_err(|_| ERROR_ID::ERR_REQ_AUTH)?;

    let private_key = try_syscall!(w.trussed.unsafe_inject_shared_key(
        // &k.serialize(),
        req.raw_key_data.as_slice(),
        Location::Internal,
        Kind::P256
    ))
    .map_err(|_| ERROR_ID::ERR_FAILED_LOADING_DATA)?
    .key;
    let public_key = try_syscall!(w
        .trussed
        .derive_p256_public_key(private_key, Location::Volatile))
    .map_err(|_| ERROR_ID::ERR_FAILED_LOADING_DATA)?
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
    .map_err(|_| ERROR_ID::ERR_MEMORY_FULL)?;

    // public key
    let serialized_raw_public_key = syscall!(w
        .trussed
        .serialize_p256_key(public_key, KeySerialization::Raw))
    .serialized_key;

    syscall!(w.trussed.delete(public_key));

    w.send_to_output({
        let mut pubkey = Bytes65::from_slice(serialized_raw_public_key.as_slice()).unwrap();
        // add identifier for uncompressed form - 0x04
        pubkey.insert(0, 0x04).map_err(|_| ERR_INTERNAL_ERROR)?;
        CommandWriteResidentKeyResponse {
            pubkey,
            keyhandle: credential_id_hash,
        }
    });

    Ok(())
}

pub fn cmd_generate_resident_key<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Aes256Cbc
        + client::HmacSha256
        + client::HmacSha256P256
        + client::Chacha8Poly1305
        + client::Sha256,
{
    // write the RK similarly, as done with FIDO2, potentially with some extensions

    let req: CommandGenerateResidentKeyRequest = w
        .get_input_deserialized()
        .map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;
    w.session
        .check_token_res(req.tp.unwrap())
        .map_err(|_| ERROR_ID::ERR_REQ_AUTH)?;

    // writing RKs
    //
    // if rk_requested {
    //     // serialization with all metadata
    //     let serialized_credential = credential.serialize()?;
    //
    //     // first delete any other RK cred with same RP + UserId if there is one.
    //     self.delete_resident_key_by_user_id(&rp_id_hash, &credential.user.id)
    //         .ok();
    //
    //     // then store key, making it resident
    //     let credential_id_hash = self.hash(credential_id.0.as_ref());
    //     try_syscall!(self.trussed.write_file(
    //             Location::Internal,
    //             rk_path(&rp_id_hash, &credential_id_hash),
    //             serialized_credential,
    //             // user attribute for later easy lookup
    //             // Some(rp_id_hash.clone()),
    //             None,
    //         ))
    //         .map_err(|_| Error::KeyStoreFull)?;
    // }

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
    .map_err(|_| ERROR_ID::ERR_MEMORY_FULL)?;

    // public key
    let serialized_raw_public_key = syscall!(w
        .trussed
        .serialize_p256_key(public_key, KeySerialization::Raw))
    .serialized_key;

    // let keyhandle_ser_enc = private_key.hex();

    syscall!(w.trussed.delete(public_key));

    w.send_to_output({
        let mut pubkey = Bytes65::from_slice(serialized_raw_public_key.as_slice()).unwrap();
        // add identifier for uncompressed form - 0x04
        pubkey.insert(0, 0x04).map_err(|_| ERR_INTERNAL_ERROR)?;
        CommandGenerateResidentKeyResponse {
            pubkey,
            keyhandle: credential_id_hash,
        }
    });

    Ok(())
}

pub fn cmd_restore_from_seed<C>(w: &mut Webcrypt<C>) -> CommandResult
where
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Aes256Cbc
        + client::HmacSha256
        + client::Sha256
        + client::HmacSha256P256
        + client::Chacha8Poly1305,
{
    let req: CommandRestoreRequest = w
        .get_input_deserialized()
        .map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;
    w.session
        .check_token_res(req.tp.unwrap())
        .map_err(|_| ERROR_ID::ERR_REQ_AUTH)?;

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
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Aes256Cbc
        + client::HmacSha256
        + client::Sha256
        + client::HmacSha256P256
        + client::Chacha8Poly1305,
{
    let req: CommandInitializeRequest = w
        .get_input_deserialized()
        .map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;
    w.session
        .check_token_res(req.tp.unwrap())
        .map_err(|_| ERROR_ID::ERR_REQ_AUTH)?;

    if req.entropy.is_some() && req.entropy.unwrap().len() > 0 {
        // todo!();
        return Err(ERROR_ID::ERR_NOT_IMPLEMENTED);
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
