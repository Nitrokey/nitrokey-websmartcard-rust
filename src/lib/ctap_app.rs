use crate::commands::WebcryptTrussedClient;
use apdu_dispatch::app as apdu;
use apdu_dispatch::app::Interface;
use apdu_dispatch::app::Status;
use apdu_dispatch::command::SIZE as APDU_SIZE;
use apdu_dispatch::iso7816::{Aid, App};
use ctap_types::ctap1::{authenticate, Request as Request1, Response as Response1};
use ctap_types::ctap2::{get_assertion, Request, Response};
use ctap_types::webauthn::PublicKeyCredentialUserEntity;
use ctap_types::{ctap1, ctap2};
use ctaphid_dispatch::app;
use ctaphid_dispatch::app as ctaphid;
use heapless_bytes::Bytes;

use crate::helpers::hash;
use crate::transport::Webcrypt;
use crate::types::RequestSource::RS_FIDO2;
use crate::types::{CtapSignatureSize, RequestDetails, RequestSource};

#[inline(never)]
fn try_handle_ctap1<C>(
    w: &mut Webcrypt<C>,
    data: &[u8],
    response: &mut apdu_dispatch::response::Data,
) -> Result<(), Status>
where
    C: WebcryptTrussedClient,
{
    let ctap_response = {
        let ctap_request = {
            let command = apdu_dispatch::Command::try_from(data)
                .map_err(|_| Status::IncorrectDataParameter)?;
            ctap1::Request::try_from(&command)?
        };

        match ctap_request {
            // Request1::Register(reg) => {
            //     info!("WC CTAP1.REG");
            //     Ok(Response1::Register(register::Response {
            //         header_byte: 0,
            //         public_key: Default::default(),
            //         key_handle: Default::default(),
            //         attestation_certificate: Default::default(),
            //         signature: Default::default(),
            //     }))
            // }
            Request1::Authenticate(auth) => {
                info!("WC CTAP1.AUTH");
                let output = Bytes::new();
                let data = auth.key_handle;
                let maybe_output = w.bridge_u2f_to_webcrypt_raw(
                    output,
                    &data,
                    RequestDetails {
                        rpid: auth.app_id,
                        source: RequestSource::RS_U2F,
                        pin_auth: None,
                    },
                );

                let output = match maybe_output {
                    Ok(res) => res,
                    Err(e) => {
                        error!("Protocol error: {:?}", e);
                        let mut res = CtapSignatureSize::new();
                        res.push(e as u8).unwrap();
                        res
                    }
                };
                Ok(Response1::Authenticate(authenticate::Response {
                    user_presence: 0x01,
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
    C: WebcryptTrussedClient,
{
    info!("WC handle CTAP1");
    match try_handle_ctap1(w, data, response) {
        Ok(()) => {
            info!("WC U2F response {} bytes", response.len());
            response.extend_from_slice(&[0x90, 0x00]).ok();
        }
        Err(status) => {
            let code: [u8; 2] = status.into();
            info!("WC CTAP1 error: {:?} ({:?})", status, code);
            response.extend_from_slice(&code).ok();
        }
    }
    info!("WC end handle CTAP1");
}

#[inline(never)]
fn try_handle_ctap2<C>(
    w: &mut Webcrypt<C>,
    data: &[u8],
    response: &mut apdu_dispatch::response::Data,
) -> Result<(), u8>
where
    C: WebcryptTrussedClient,
{
    let ctap_request = Request::deserialize(data).map_err(|error| error as u8)?;

    let ctap_response = match ctap_request {
        // 0x2
        // Request::MakeCredential(request) => {
        //     info!("CTAP2.MC");
        //     Ok(Response::MakeCredential(
        //         self.make_credential(request).map_err(|e| {
        //             debug!("error: {:?}", e);
        //             e
        //         })?,
        //     ))
        // }

        // 0x1
        Request::GetAssertion(request) => {
            info!("WC CTAP2.GA");
            let output = Bytes::new();
            let data = request.allow_list.unwrap();
            let data = &data[0].id;
            let rpid_hash = hash(&mut w.wc.trussed, request.rp_id.as_bytes())
                .map_err(|_| ctap2::Error::InvalidParameter as u8)?;
            let pin_auth = request
                .pin_auth
                .map(|s| Bytes::from_slice(s))
                .transpose()
                .map_err(|_| ctap2::Error::InvalidParameter as u8)?;
            let maybe_output = w.bridge_u2f_to_webcrypt_raw(
                output,
                data,
                RequestDetails {
                    rpid: rpid_hash.clone(),
                    source: RS_FIDO2,
                    pin_auth,
                },
            );

            let output = match maybe_output {
                Ok(res) => res,
                Err(e) => {
                    error!("Protocol error: {:?}", e);
                    let mut res = CtapSignatureSize::new();
                    res.push(e as u8).unwrap();
                    res
                }
            };

            use ctap2::AuthenticatorDataFlags as Flags;
            let authenticator_data = ctap2::make_credential::AuthenticatorData {
                rp_id_hash: rpid_hash,

                flags: {
                    let mut flags = Flags::USER_PRESENCE;
                    // if uv_performed {
                    flags |= Flags::USER_VERIFIED;
                    // }
                    // flags |= Flags::ATTESTED_CREDENTIAL_DATA;
                    flags
                },

                sign_count: 0,

                attested_credential_data: {
                    let _attested_credential_data =
                        ctap2::make_credential::AttestedCredentialData {
                            aaguid: Bytes::from_slice(&[1u8; 16]).unwrap(),
                            // credential_id: Bytes::from_slice(&[2u8; 255]).unwrap(),
                            credential_id: Bytes::from_slice(&data[..]).unwrap(),
                            credential_public_key: {
                                // FIXME replace with a properly serialized empty cose public key
                                let a = [
                                    165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 101, 237, 165, 161, 37,
                                    119, 194, 186, 232, 41, 67, 127, 227, 56, 112, 26, 16, 170,
                                    163, 117, 225, 187, 91, 93, 225, 8, 222, 67, 156, 8, 85, 29,
                                    34, 88, 32, 30, 82, 237, 117, 112, 17, 99, 247, 249, 228, 13,
                                    223, 159, 52, 27, 61, 201, 186, 134, 10, 247, 224, 202, 124,
                                    167, 233, 238, 205, 0, 132, 209, 156,
                                ];
                                Bytes::from_slice(&a).unwrap()
                            },
                        };
                    // Some(attested_credential_data)
                    None
                },

                extensions: { None },
            };
            let serialized_auth_data = authenticator_data.serialize();

            // let user = {
            //     PublicKeyCredentialUserEntity {
            //         id: Bytes::from_slice(&[3u8; 16]).unwrap(),
            //         icon: Some("icon".try_into().unwrap()),
            //         name: Some("name".try_into().unwrap()),
            //         display_name: Some("display".try_into().unwrap()),
            //     }
            // };

            let _user = {
                PublicKeyCredentialUserEntity {
                    id: Bytes::from_slice(&[3u8; 16]).unwrap(),
                    icon: None,
                    name: Some("name".try_into().unwrap()),
                    display_name: Some("display".try_into().unwrap()),
                }
            };

            Ok(Response::GetAssertion(get_assertion::Response {
                credential: None,
                auth_data: serialized_auth_data,
                signature: Bytes::<77>::from_slice(&output[..]).unwrap(),
                // user: Some(user),
                user: None,
                number_of_credentials: None,
                user_selected: None,
                large_blob_key: None,
            }))
        }

        _ => Err(0xFF), // FIXME set proper error on getting unhandled CTAP request code
    };

    ctap_response?.serialize(response);

    Ok(())
}

#[inline(never)]
fn handle_ctap2<C>(
    authenticator: &mut Webcrypt<C>,
    data: &[u8],
    response: &mut apdu_dispatch::response::Data,
) where
    C: WebcryptTrussedClient,
{
    info!("WC handle CTAP2");
    if let Err(error) = try_handle_ctap2(authenticator, data, response) {
        info!("WC CTAP2 error: {:02X}", error);
        response.push(error).ok();
    }
}
use trussed::interrupt::InterruptFlag;

impl<C> app::App<'static> for Webcrypt<C>
where
    C: WebcryptTrussedClient,
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
            info!("WC invalid request length in ctaphid.call");
            return Err(app::Error::InvalidLength);
        }

        match command {
            app::Command::Cbor => handle_ctap2(self, request, response),
            app::Command::Msg => handle_ctap1(self, request, response),
            _ => {
                info!("WC ctaphid trying to dispatch {:?}", command);
            }
        };
        Ok(())
    }

    fn interrupt(&self) -> Option<&'static InterruptFlag> {
        self.wc.trussed.interrupt()
    }
}

const SIZE: usize = APDU_SIZE;

impl<C> App for Webcrypt<C>
where
    C: WebcryptTrussedClient,
{
    fn aid(&self) -> Aid {
        // FIXME check if AID needs to be changed / unique for Webcrypt
        Aid::new(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01])
    }
}

impl<C> apdu::App<{ SIZE }, { SIZE }> for Webcrypt<C>
where
    C: WebcryptTrussedClient,
{
    fn select(
        &mut self,
        _interface: Interface,
        _apdu: &apdu::Command<{ SIZE }>,
        reply: &mut apdu::Data<{ apdu_dispatch::response::SIZE }>,
    ) -> apdu::Result {
        reply.extend_from_slice(b"U2F_V2").unwrap();
        Ok(())
    }

    fn deselect(&mut self) {}

    fn call(
        &mut self,
        interface: Interface,
        apdu: &apdu::Command<{ SIZE }>,
        response: &mut apdu::Data<{ apdu_dispatch::response::SIZE }>,
    ) -> apdu::Result {
        if interface != Interface::Contactless {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }

        let instruction: u8 = apdu.instruction().into();
        match instruction {
            #[allow(clippy::manual_range_patterns)]
            0x00 | 0x01 | 0x02 => handle_ctap1(self, apdu.data(), response), //self.call_authenticator_u2f(apdu, response),

            _ => {
                match ctaphid::Command::try_from(instruction) {
                    // 0x10
                    Ok(ctaphid::Command::Cbor) => handle_ctap2(self, apdu.data(), response),
                    Ok(ctaphid::Command::Msg) => handle_ctap1(self, apdu.data(), response),
                    Ok(ctaphid::Command::Deselect) => self.deselect(),
                    _ => {
                        info!("Unsupported ins for fido app {:02x}", instruction);
                        return Err(Status::InstructionNotSupportedOrInvalid);
                    }
                }
            }
        };
        Ok(())
    }

    #[cfg(feature = "apdu-peek")]
    fn peek(&self, apdu: Option<&apdu_dispatch::app::Command<SIZE>>) -> bool {
        match apdu {
            None => false,
            Some(apdu) => {
                let data = apdu.data();
                let data_len = data.len();
                if data_len < 7 {
                    return false;
                }

                for offset in 0..data_len - 5 {
                    if data[offset..=4 + offset] == [0x22, 0x8c, 0x27, 0x90, 0xF6] {
                        info!("NFC Found WC constant at offset {offset}");
                        return true;
                    }
                }
                false
            }
        }
    }
}

impl<C> crate::Peeking for Webcrypt<C>
where
    C: WebcryptTrussedClient,
{
    #[inline(never)]
    fn peek(&self, request: &ctaphid_dispatch::types::Message) -> bool {
        // let offset = 4 * 16 + 8;
        // let offset2 = 3 * 16 + 8;
        // let res = request.len() > 3 + offset
        //     && request[0 + offset..=2 + offset] == [0x22, 0x8c, 0x27]
        //     || request.len() > 3 + offset2
        //         && request[0 + offset2..=2 + offset2] == [0x22, 0x8c, 0x27];
        // res

        if request.len() < 7 {
            return false;
        }

        for offset in 1..request.len() - 5 {
            if request[offset..=4 + offset] == [0x22, 0x8c, 0x27, 0x90, 0xF6] {
                info!("Found WC constant at offset {offset}");
                return true;
            }
        }
        false
    }
}
