use cbor_smol::{cbor_deserialize, cbor_serialize};

use serde::{Deserialize, Serialize};

use crate::commands::*;
use crate::state::State;
use crate::types::*;
use crate::types::{ExtWebcryptCmd, WebcryptRequest};
use crate::wcstate::{WebcryptSession, WebcryptState};

use crate::commands_types::WebcryptMessage;
use crate::{Bytes, Message, Options};

#[allow(non_snake_case)]
pub struct Webcrypt<C: WebcryptTrussedClient> {
    WC_INPUT_BUFFER: WebcryptMessage,
    WC_OUTPUT_BUFFER: WebcryptMessage,
    pub(crate) current_command_id: CommandID,
    pub(crate) trussed: C,
    pub(crate) state: WebcryptState,
    pub(crate) store: State,
    pub(crate) session: WebcryptSession,
    pub(crate) req_details: Option<RequestDetails>,
    pub(crate) options: Options,
}
pub type WebcryptError = Error;

impl<C> Webcrypt<C>
where
    C: WebcryptTrussedClient,
{
    #[inline(never)]
    pub fn new_with_options(client: C, options: Options) -> Self {
        Webcrypt {
            WC_INPUT_BUFFER: Default::default(),
            WC_OUTPUT_BUFFER: Default::default(),
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
    fn get_webcrypt_cmd(&self, keyh: &Bytes<255>) -> Result<ExtWebcryptCmd, WebcryptError> {
        let webcrypt: WebcryptRequest = keyh.try_into().map_err(|_| Error::BadFormat)?;
        webcrypt.try_into()
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
    fn parse_execute(&mut self) -> Result<(Error, CommandID), ()> {
        self.WC_OUTPUT_BUFFER.clear();
        let parsed: ResponseReadFirst = (&self.WC_INPUT_BUFFER).into();
        let id_u8 = parsed.cmd_id;
        let operation = id_u8;
        self.current_command_id = operation;
        info!("Input buffer: {:?}", parsed);
        info!("Received operation: {:?} {:x?}", id_u8, operation);
        use CommandID::*;
        let res = match operation {
            Status => cmd_status(self),
            Login => cmd_login(self),
            Logout => cmd_logout(self),
            FactoryReset => cmd_factory_reset(self),
            GetConfiguration => cmd_configure(self),
            SetConfiguration => cmd_configure(self),
            SetPin => cmd_manage_pin(self),
            ChangePin => cmd_manage_pin(self),
            InitializeSeed => cmd_initialize_seed(self),
            RestoreFromSeed => cmd_restore_from_seed(self),

            GenerateKey => cmd_generate_key(self),
            Sign => cmd_sign(self),
            Decrypt => cmd_decrypt(self),

            OpenPgpImport => cmd_openpgp_import(self),
            OpenPgpSign => cmd_openpgp_sign(self),
            OpenPgpDecrypt => cmd_openpgp_decrypt(self),
            OpenPgpInfo => cmd_openpgp_info(self),
            OpenPgpGenerate => cmd_openpgp_generate(self),

            #[cfg(feature = "hmacsha256p256")]
            GenerateKeyFromData => cmd_generate_key_from_data(self),

            ReadResidentKeyPublic => cmd_read_resident_key_public(self),
            GenerateResidentKey => cmd_generate_resident_key(self),
            DiscoverResidentKeys => cmd_discover_resident_key(self),
            WriteResidentKey => cmd_write_resident_key(self),

            TestPing => cmd_test_ping(self),
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

    #[inline(never)]
    pub fn get_input(&self) -> &[u8] {
        self.WC_INPUT_BUFFER.as_slice()
    }

    #[inline(never)]
    pub fn get_input_deserialized<'a, T: Deserialize<'a>>(&'a self) -> Result<T, cbor_smol::Error> {
        cbor_deserialize::<T>(&self.WC_INPUT_BUFFER[3..]).map_err(|e| {
            debug_now!("Input deserialization error: {:?}", e);
            e
        })
    }

    #[inline(never)]
    pub fn send_to_output<T: Serialize>(&mut self, o: T) {
        // send data to output
        // limited to 256*8 bytes for now for a single write
        let mut buffer = [0u8; 256 * 8];
        let encoded = cbor_serialize(&o, &mut buffer).unwrap();
        // info!("Encoded: {:?}", hex::encode(encoded));
        self.WC_OUTPUT_BUFFER.extend_from_slice(encoded).unwrap();
    }

    #[inline(never)]
    pub fn send_to_output_arr(&mut self, o: &WebcryptMessage) {
        info!("Clear write: {:?}", o);
        self.WC_OUTPUT_BUFFER.extend_from_slice(o).unwrap();
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
        // info!(
        //     "Read: [{}..{})({})/{} {:?}",
        //     offset,
        //     offset_right_clamp,
        //     output.len(),
        //     self.WC_OUTPUT_BUFFER.len(),
        //     hex::encode(output)
        // );
        Error::Success
    }
    /// The main transport function, gateway to the extension from the Webauthn perspective
    /// Decodes incoming request low-level packet data, and either saves it to the input buffer,
    /// triggers execution or allows reading output buffer.
    #[inline(never)]
    pub fn bridge_u2f_to_webcrypt_raw(
        &mut self,
        mut output: CtapSignatureSize,
        keyh: &Bytes<255>,
        req_details: RequestDetails,
    ) -> Result<CtapSignatureSize, Error> {
        let cmd = self.get_webcrypt_cmd(keyh)?;
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
        // info!("> outputH: {:?}", hex::encode(output.clone()));
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
                    self.req_details = Some(req_details);
                } else if self.req_details != Some(req_details) {
                    // either method or host changes, while not writing the first packet, abort
                    return Ok(WebcryptResponseType::Write(ResponseWrite {
                        result: Error::BadOrigin,
                    }));
                }

                self.webcrypt_write_request(&output.cbor_payload, &webcrypt_req)?;

                output.status_code = Error::Success;
                let should_execute = webcrypt_req.is_final();
                if should_execute {
                    let res = self.parse_execute().map_err(|_| Error::InternalError)?;
                    output.status_code = res.0;
                    self.current_command_id = res.1;
                }
                Ok(WebcryptResponseType::Write(ResponseWrite {
                    result: output.status_code,
                }))
            }

            TRANSPORT_CMD_ID::COMM_CMD_READ => {
                if self.req_details != Some(req_details) {
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
                            cmd_id: self.current_command_id,
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
    pub fn send_input_to_output(&mut self) {
        self.WC_OUTPUT_BUFFER
            .extend_from_slice(&self.WC_INPUT_BUFFER[3..])
            .unwrap();
    }
}
