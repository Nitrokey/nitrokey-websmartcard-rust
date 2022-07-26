use crate::helpers::hash;
use crate::transport::Webcrypt;
use crate::types::RequestSource::RS_FIDO2;
use crate::types::{RequestDetails, RequestSource};
use crate::Message;
use apdu_dispatch::app::Status;
use ctap_types::ctap1::{authenticate, Request as Request1, Response as Response1};
use ctap_types::ctap2::{get_assertion, Request, Response};
use ctap_types::{ctap1, ctap2};
use ctaphid_dispatch::app;
use heapless_bytes::Bytes;
use trussed::client;

#[inline(never)]
fn try_handle_ctap1<C>(
    w: &mut Webcrypt<C>,
    data: &[u8],
    response: &mut apdu_dispatch::response::Data,
) -> Result<(), Status>
where
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Chacha8Poly1305
        + client::Aes256Cbc
        + client::HmacSha256
        + client::HmacSha256P256
        + client::Sha256,
{
    let ctap_response = {
        let ctap_request = {
            let command = apdu_dispatch::Command::try_from(data)
                .map_err(|_| Status::IncorrectDataParameter)?;
            ctap1::Request::try_from(&command)?
        };

        match ctap_request {
            // Request1::Register(reg) => {
            //     log::info!("WC CTAP1.REG");
            //     Ok(Response1::Register(register::Response {
            //         header_byte: 0,
            //         public_key: Default::default(),
            //         key_handle: Default::default(),
            //         attestation_certificate: Default::default(),
            //         signature: Default::default(),
            //     }))
            // }
            Request1::Authenticate(auth) => {
                log::info!("WC CTAP1.AUTH");
                let output = Bytes::new();
                let data = auth.key_handle;
                let output = w
                    .bridge_u2f_to_webcrypt_raw(
                        output,
                        &data,
                        RequestDetails {
                            source: RequestSource::RS_U2F,
                            rpid: auth.app_id,
                            pin_auth: None,
                        },
                    )
                    .unwrap();
                Ok(Response1::Authenticate(authenticate::Response {
                    user_presence: 0,
                    count: 0,
                    signature: output,
                }))
            }
            _ => Err(Status::IncorrectDataParameter),
        }
    }?;

    ctap_response.serialize(response).ok();
    Ok(())
}

#[inline(never)]
fn handle_ctap1<C>(w: &mut Webcrypt<C>, data: &[u8], response: &mut apdu_dispatch::response::Data)
where
    C: trussed::Client
        + trussed::Client
        + client::P256
        + client::Chacha8Poly1305
        + client::Aes256Cbc
        + client::HmacSha256
        + client::HmacSha256P256
        + client::Sha256,
{
    log::info!("WC handle CTAP1");
    match try_handle_ctap1(w, data, response) {
        Ok(()) => {
            debug!("WC U2F response {} bytes", response.len());
            response.extend_from_slice(&[0x90, 0x00]).ok();
        }
        Err(status) => {
            let code: [u8; 2] = status.into();
            log::info!("WC CTAP1 error: {:?} ({})", status, hex_str!(&code));
            response.extend_from_slice(&code).ok();
        }
    }
    log::info!("WC end handle CTAP1");
}

#[inline(never)]
fn try_handle_ctap2<C>(
    w: &mut Webcrypt<C>,
    data: &[u8],
    response: &mut apdu_dispatch::response::Data,
) -> Result<(), u8>
where
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Chacha8Poly1305
        + client::Aes256Cbc
        + client::HmacSha256
        + client::HmacSha256P256
        + client::Sha256,
{
    let ctap_request = ctap2::Request::deserialize(data).map_err(|error| error as u8)?;

    let ctap_response = match ctap_request {
        // 0x2
        // Request::MakeCredential(request) => {
        //     log::info!("CTAP2.MC");
        //     Ok(Response::MakeCredential(
        //         self.make_credential(request).map_err(|e| {
        //             debug!("error: {:?}", e);
        //             e
        //         })?,
        //     ))
        // }

        // 0x1
        Request::GetAssertion(request) => {
            log::info!("WC CTAP2.GA");
            let output = Bytes::new();
            let data = request.allow_list.unwrap();
            let data = &data[0].id;
            let rpid_hash = hash(
                &mut w.trussed,
                Message::from_slice(request.rp_id.as_bytes()).unwrap(),
            );
            let output = w
                .bridge_u2f_to_webcrypt_raw(
                    output,
                    data,
                    RequestDetails {
                        // FIXME hash the full incoming rp_id before passing further, or otherwise only the first 32 bytes of the domain will be checked
                        // rpid: Bytes32::from_slice(&request.rp_id.as_bytes()[..32]).unwrap(),
                        rpid: rpid_hash,
                        source: RS_FIDO2,
                        pin_auth: request.pin_auth,
                    },
                )
                .unwrap();

            use ctap2::AuthenticatorDataFlags as Flags;
            let authenticator_data = ctap2::make_credential::AuthenticatorData {
                rp_id_hash: Bytes::from_slice(&[0u8; 32]).unwrap(),

                flags: {
                    let mut flags = Flags::USER_PRESENCE;
                    // if uv_performed {
                    //     flags |= Flags::USER_VERIFIED;
                    // }
                    flags |= Flags::ATTESTED_CREDENTIAL_DATA;
                    flags
                },

                sign_count: 0,

                attested_credential_data: {
                    let attested_credential_data = ctap2::make_credential::AttestedCredentialData {
                        aaguid: Bytes::from_slice(&[0u8; 16]).unwrap(),
                        credential_id: Bytes::from_slice(&[0u8; 255]).unwrap(),
                        credential_public_key: {
                            // FIXME replace with a properly serialized empty cose public key
                            let a = [
                                165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 101, 237, 165, 161, 37, 119,
                                194, 186, 232, 41, 67, 127, 227, 56, 112, 26, 16, 170, 163, 117,
                                225, 187, 91, 93, 225, 8, 222, 67, 156, 8, 85, 29, 34, 88, 32, 30,
                                82, 237, 117, 112, 17, 99, 247, 249, 228, 13, 223, 159, 52, 27, 61,
                                201, 186, 134, 10, 247, 224, 202, 124, 167, 233, 238, 205, 0, 132,
                                209, 156,
                            ];
                            Bytes::from_slice(&a).unwrap()
                        },
                    };
                    Some(attested_credential_data)
                },

                extensions: { None },
            };
            let serialized_auth_data = authenticator_data.serialize();

            Ok(Response::GetAssertion(get_assertion::Response {
                credential: None,
                auth_data: serialized_auth_data,
                signature: Bytes::<77>::from_slice(&output[..]).unwrap(),
                user: None,
                number_of_credentials: None,
            }))
        }

        _ => Err(0xFF), // FIXME set proper error on getting unhandled CTAP request code
    };

    ctap_response?.serialize(response);

    Ok(())
}

fn handle_ctap2<C>(
    authenticator: &mut Webcrypt<C>,
    data: &[u8],
    response: &mut apdu_dispatch::response::Data,
) where
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Chacha8Poly1305
        + client::Aes256Cbc
        + client::HmacSha256
        + client::HmacSha256P256
        + client::Sha256,
{
    log::info!("WC handle CTAP2");
    if let Err(error) = try_handle_ctap2(authenticator, data, response) {
        log::info!("WC CTAP2 error: {:02X}", error);
        response.push(error).ok();
    }
}

impl<C> app::App for Webcrypt<C>
where
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Chacha8Poly1305
        + client::Aes256Cbc
        + client::HmacSha256
        + client::HmacSha256P256
        + client::Sha256,
{
    fn commands(&self) -> &'static [app::Command] {
        &[app::Command::Cbor, app::Command::Msg]
    }

    #[inline(never)]
    fn call(
        &mut self,
        command: app::Command,
        request: &app::Message,
        response: &mut app::Message,
    ) -> app::AppResult {
        if request.is_empty() {
            log::info!("WC invalid request length in ctaphid.call");
            return Err(app::Error::InvalidLength);
        }

        match command {
            app::Command::Cbor => handle_ctap2(self, request, response),
            app::Command::Msg => handle_ctap1(self, request, response),
            _ => {
                log::info!("WC ctaphid trying to dispatch {:?}", command);
            }
        };
        Ok(())
    }
}
