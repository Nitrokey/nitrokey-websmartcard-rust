use cbor_smol::{cbor_deserialize, cbor_serialize};

use serde::{Deserialize, Serialize};

use crate::commands::*;
use crate::state::State;
use crate::types::*;
use crate::types::{ExtWebcryptCmd, WebcryptRequest};
use crate::wcstate::{WebcryptSession, WebcryptState};

use crate::commands_types::WebcryptMessage;
use crate::{Message, Options};

#[allow(non_snake_case)]
pub struct Webcrypt<C: WebcryptTrussedClient> {
    WC_INPUT_BUFFER: WebcryptMessage,
    WC_OUTPUT_BUFFER: WebcryptMessage,
    pub(crate) wc: WebcryptInternal<C>,
}

impl<C: WebcryptTrussedClient> Webcrypt<C> {
    pub fn new_with_options(client: C, options: Options) -> Self {
        Self {
            WC_INPUT_BUFFER: Default::default(),
            WC_OUTPUT_BUFFER: Default::default(),
            wc: WebcryptInternal::new_with_options(client, options),
        }
    }

    /// The main transport function, gateway to the extension from the Webauthn perspective
    /// Decodes incoming request low-level packet data, and either saves it to the input buffer,
    /// triggers execution or allows reading output buffer.
    #[inline(never)]
    pub fn bridge_u2f_to_webcrypt_raw(
        &mut self,
        mut output: CtapSignatureSize,
        keyh: &[u8],
        req_details: RequestDetails,
    ) -> Result<CtapSignatureSize, Error> {
        let cmd = self.wc.get_webcrypt_cmd(keyh)?;
        info!(" in < cmd: {:?}", cmd);
        let ret = self.bridge_u2f_to_webcrypt(cmd, req_details)?;
        info!("out > ret: {:?}", ret);
        ret.log_hex();

        match ret {
            WebcryptResponseType::First(x) => {
                let v: Message = x.into();
                output.extend(v);
            }
            WebcryptResponseType::Next(x) => {
                output.extend(x.data.0);
            }
            WebcryptResponseType::Write(x) => {
                // TODO Err on x.result != success
                output.extend([x.result as u8]);
            }
        }
        info!("> outputH: {:?}", output.clone());
        Ok(output)
    }

    /// High level implementation
    /// Called from bridge_u2f_to_webcrypt_raw after initial deserialization
    #[inline(never)]
    pub fn bridge_u2f_to_webcrypt(
        &mut self,
        webcrypt_req: ExtWebcryptCmd,
        req_details: RequestDetails,
    ) -> Result<WebcryptResponseType, Error> {
        let operation = &webcrypt_req.command_id_transport;
        let mut output = WebcryptResult::default();
        match operation {
            TRANSPORT_CMD_ID::COMM_CMD_WRITE => {
                if webcrypt_req.packet_no.0 == 0 {
                    self.WC_INPUT_BUFFER.clear();
                    self.WC_OUTPUT_BUFFER.clear();
                    self.wc.req_details = Some(req_details);
                } else if self.wc.req_details != Some(req_details) {
                    // either method or host changes, while not writing the first packet, abort
                    return Ok(WebcryptResponseType::Write(ResponseWrite {
                        result: Error::BadOrigin,
                    }));
                }

                self.webcrypt_write_request(&output.cbor_payload, &webcrypt_req)?;

                output.status_code = Error::Success;
                let should_execute = webcrypt_req.is_final();
                if should_execute {
                    let mut tmp_buffer = self.WC_OUTPUT_BUFFER.clone();
                    let res = self.parse_execute(&mut tmp_buffer);
                    self.WC_OUTPUT_BUFFER = tmp_buffer;
                    match res {
                        Ok(res) => {
                            output.status_code = res.0;
                            self.wc.current_command_id = res.1;
                        }
                        Err(e) => {
                            output.status_code = e;
                            self.wc.current_command_id = CommandID::NotSetInvalid;
                        }
                    }
                }
                Ok(WebcryptResponseType::Write(ResponseWrite {
                    result: output.status_code,
                }))
            }

            TRANSPORT_CMD_ID::COMM_CMD_READ => {
                if self.wc.req_details != Some(req_details) {
                    // on bad request return first packet format
                    output.status_code = Error::BadOrigin;
                    output.cbor_payload = Default::default();
                    return Ok(WebcryptResponseType::First(ResponseReadFirst {
                        data_len: 3, // size (2) + commandID (1)
                        cmd_id: Default::default(),
                        data: CborPart(
                            output
                                .cbor_payload
                                .try_convert_into()
                                .map_err(|_| Error::InternalError)?,
                        ),
                    }));
                }

                output.status_code =
                    self.webcrypt_read_request(&mut output.cbor_payload, &webcrypt_req);
                info!("output status_code: {:?}", output.status_code);
                match webcrypt_req.packet_no.0 {
                    0 => {
                        Ok(WebcryptResponseType::First(ResponseReadFirst {
                            data_len: self.WC_OUTPUT_BUFFER.len() as u16 + 3, // +3, // size (2) + commandID (1)
                            cmd_id: self.wc.current_command_id,
                            data: CborPart(
                                output
                                    .cbor_payload
                                    .try_convert_into()
                                    .map_err(|_| Error::InternalError)?,
                            ),
                        }))
                    }
                    _ => Ok(WebcryptResponseType::Next(ResponseReadNext {
                        data: CborPart(
                            output
                                .cbor_payload
                                .try_convert_into()
                                .map_err(|_| Error::InternalError)?,
                        ),
                    })),
                }
            }
        }
    }

    #[inline(never)]
    fn webcrypt_read_request(&self, output: &mut WebcryptMessage, cmd: &ExtWebcryptCmd) -> Error {
        let offset = (u8::from(cmd.packet_no)) as usize * (cmd.chunk_size) as usize;
        let offset_right = offset + cmd.this_chunk_length as usize;
        let offset_right_clamp = offset_right.min(self.WC_OUTPUT_BUFFER.len());

        if self.WC_OUTPUT_BUFFER.len() == 0 {
            error!("No data available for read in the output buffer");
        }

        if offset >= self.WC_OUTPUT_BUFFER.len() {
            error!(
                "Requested offset bigger than available buffer length: {} > {}",
                offset,
                self.WC_OUTPUT_BUFFER.len()
            );
            return Error::FailedLoadingData;
        }

        output
            .extend_from_slice(&self.WC_OUTPUT_BUFFER[offset..offset_right_clamp])
            .unwrap();
        info!(
            "Read: [{}..{})({})/{} {:?}",
            offset,
            offset_right_clamp,
            output.len(),
            self.WC_OUTPUT_BUFFER.len(),
            output
        );
        Error::Success
    }

    #[inline(never)]
    fn webcrypt_write_request(
        &mut self,
        _output: &[u8],
        cmd: &ExtWebcryptCmd,
    ) -> Result<(), WebcryptError> {
        info!("Write");
        self.WC_INPUT_BUFFER
            .extend_from_slice(&cmd.data_first_byte)
            .map_err(|_| Error::TooLongRequest)?;
        Ok(())
    }

    #[inline(never)]
    pub fn get_request<'a, T: Deserialize<'a>>(message: &'a Message) -> Result<T, Error> {
        WebcryptInternal::<C>::get_input_deserialized_from_slice(message)
            .map_err(|_| Error::BadFormat)
    }

    #[inline(never)]
    fn parse_execute(&mut self, reply: &mut Message) -> Result<(Error, CommandID), Error> {
        reply.clear();
        let parsed: ResponseReadFirst = (&self.WC_INPUT_BUFFER).into();
        let id_u8 = parsed.cmd_id;
        let operation = id_u8;
        self.wc.current_command_id = operation;
        info!("Input buffer: {:?}", parsed);
        info!("Received operation: {:?} {:x?}", id_u8, operation);
        use CommandID::*;
        let res = match operation {
            Status => cmd_status(&mut self.wc, reply),
            Login => cmd_login(
                &mut self.wc,
                Self::get_request(&self.WC_INPUT_BUFFER)?,
                reply,
            ),
            Logout => cmd_logout(
                &mut self.wc,
                Self::get_request(&self.WC_INPUT_BUFFER)?,
                reply,
            ),
            FactoryReset => cmd_factory_reset(&mut self.wc, reply),
            // Proper command variant is selected inside the cmd_configure
            GetConfiguration | SetConfiguration => cmd_configure(
                &mut self.wc,
                Self::get_request(&self.WC_INPUT_BUFFER)?,
                reply,
            ),
            SetPin => cmd_manage_pin(
                &mut self.wc,
                Self::get_request(&self.WC_INPUT_BUFFER).map_err(|_| Error::InternalError)?, // TODO use BadFormat
                None,
                reply,
            ),
            ChangePin => cmd_manage_pin(
                &mut self.wc,
                None,
                Self::get_request(&self.WC_INPUT_BUFFER)?,
                reply,
            ),
            InitializeSeed => cmd_initialize_seed(
                &mut self.wc,
                Self::get_request(&self.WC_INPUT_BUFFER)?,
                reply,
            ),
            RestoreFromSeed => cmd_restore_from_seed(
                &mut self.wc,
                Self::get_request(&self.WC_INPUT_BUFFER)?,
                reply,
            ),

            GenerateKey => cmd_generate_key(
                &mut self.wc,
                Self::get_request(&self.WC_INPUT_BUFFER)?,
                reply,
            ),
            Sign => cmd_sign(
                &mut self.wc,
                Self::get_request(&self.WC_INPUT_BUFFER)?,
                reply,
            ),
            Decrypt => cmd_decrypt(
                &mut self.wc,
                Self::get_request(&self.WC_INPUT_BUFFER)?,
                reply,
            ),

            OpenPgpImport => cmd_openpgp_import(
                &mut self.wc,
                Self::get_request(&self.WC_INPUT_BUFFER)?,
                reply,
            ),
            OpenPgpSign => cmd_openpgp_sign(
                &mut self.wc,
                Self::get_request(&self.WC_INPUT_BUFFER)?,
                reply,
            ),
            OpenPgpDecrypt => cmd_openpgp_decrypt(
                &mut self.wc,
                Self::get_request(&self.WC_INPUT_BUFFER)?,
                reply,
            ),
            OpenPgpInfo => cmd_openpgp_info(
                &mut self.wc,
                Self::get_request(&self.WC_INPUT_BUFFER)?,
                reply,
            ),
            OpenPgpGenerate => cmd_openpgp_generate(
                &mut self.wc,
                Self::get_request(&self.WC_INPUT_BUFFER)?,
                reply,
            ),

            #[cfg(feature = "hmacsha256p256")]
            GenerateKeyFromData => cmd_generate_key_from_data(
                &mut self.wc,
                Self::get_request(&self.WC_INPUT_BUFFER)?,
                reply,
            ),

            ReadResidentKeyPublic => cmd_read_resident_key_public(
                &mut self.wc,
                Self::get_request(&self.WC_INPUT_BUFFER)?,
                reply,
            ),
            GenerateResidentKey => cmd_generate_resident_key(
                &mut self.wc,
                Self::get_request(&self.WC_INPUT_BUFFER)?,
                reply,
            ),
            DiscoverResidentKeys => cmd_discover_resident_key(
                &mut self.wc,
                Self::get_request(&self.WC_INPUT_BUFFER)?,
                reply,
            ),
            WriteResidentKey => cmd_write_resident_key(
                &mut self.wc,
                Self::get_request(&self.WC_INPUT_BUFFER)?,
                reply,
            ),

            TestPing => cmd_test_ping(&self.WC_INPUT_BUFFER, reply),
            #[cfg(feature = "test-commands")]
            TestClear => {
                todo!()
            }
            #[cfg(feature = "test-commands")]
            TestReboot => {
                todo!()
            }
            _ => Err(Error::InvalidCommand),
        };
        if res.is_err() {
            return Ok((res.err().unwrap(), operation));
        }
        Ok((Error::Success, operation))
    }
}

#[allow(non_snake_case)]
pub struct WebcryptInternal<C: WebcryptTrussedClient> {
    pub(crate) current_command_id: CommandID,
    pub(crate) trussed: C,
    pub(crate) state: WebcryptState,
    pub(crate) store: State,
    pub(crate) session: WebcryptSession,
    pub(crate) req_details: Option<RequestDetails>,
    pub(crate) options: Options,
}

pub type WebcryptError = Error;

impl<C> WebcryptInternal<C>
where
    C: WebcryptTrussedClient,
{
    #[inline(never)]
    pub fn new_with_options(client: C, options: Options) -> Self {
        WebcryptInternal {
            current_command_id: Default::default(),
            trussed: client,
            state: WebcryptState::new(options.location),
            store: State::new(options.location),
            session: Default::default(),
            req_details: None,
            options,
        }
    }

    #[inline(never)]
    fn get_webcrypt_cmd(&self, keyh: &[u8]) -> Result<ExtWebcryptCmd, WebcryptError> {
        let webcrypt: WebcryptRequest = keyh.try_into().map_err(|_| Error::BadFormat)?;
        webcrypt.try_into()
    }

    #[inline(never)]
    pub fn get_input_deserialized_from_slice<'a, T: Deserialize<'a>>(
        message: &'a Message,
    ) -> Result<T, cbor_smol::Error> {
        cbor_deserialize::<T>(&message[3..]).map_err(|e| {
            debug_now!("Input deserialization error: {:?}", e);
            e
        })
    }
}

#[inline(never)]
pub fn send_to_output<T: Serialize>(o: T, output: &mut Message) {
    // send data to output
    // limited to 256*8 bytes for now for a single write
    let mut buffer = [0u8; crate::OUTPUT_BUFFER_SIZE_FOR_CBOR_SERIALIZATION];
    let encoded = cbor_serialize(&o, &mut buffer).unwrap();
    info!("Encoded: {:?}", encoded);
    output.extend_from_slice(encoded).unwrap();
}
