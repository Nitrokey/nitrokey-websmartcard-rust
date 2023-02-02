use cbor_smol::{cbor_deserialize, cbor_serialize};

use serde::{Deserialize, Serialize};
use trussed::client;

use crate::commands::*;
use crate::state::State;
use crate::types::ERROR_ID::{ERR_BAD_ORIGIN, ERR_INVALID_COMMAND, ERR_SUCCESS};
use crate::types::*;
use crate::types::{ExtWebcryptCmd, WebcryptRequest};
use crate::wcstate::{WebcryptSession, WebcryptState};

use crate::{Bytes, Message};

#[allow(non_snake_case)]
pub struct Webcrypt<C> {
    WC_INPUT_BUFFER: Bytes<1024>,
    WC_OUTPUT_BUFFER: Bytes<1024>,
    pub current_command_id: CommandID,
    pub trussed: C,
    pub state: WebcryptState,
    pub store: State,
    pub session: WebcryptSession,
    pub req_details: Option<RequestDetails>,
}
use crate::helpers::min;

pub type WebcryptError = ERROR_ID;

impl<C> Webcrypt<C>
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
    pub fn new(_client: C) -> Self {
        Webcrypt {
            WC_INPUT_BUFFER: Default::default(),
            WC_OUTPUT_BUFFER: Default::default(),
            current_command_id: Default::default(),
            trussed: _client,
            state: WebcryptState::new(),
            store: State::new(),
            session: Default::default(),
            req_details: None,
        }
    }

    pub fn set_trussed_client(&mut self, _client: C) {}

    fn get_webcrypt_cmd(&self, keyh: &Bytes<255>) -> Result<ExtWebcryptCmd, WebcryptError> {
        let webcrypt: WebcryptRequest = keyh.try_into().map_err(|_| ERROR_ID::ERR_BAD_FORMAT)?;
        webcrypt.try_into()
    }

    fn webcrypt_write_request(
        &mut self,
        _output: &[u8],
        cmd: &ExtWebcryptCmd,
    ) -> Result<(), WebcryptError> {
        log::info!("Write");
        self.WC_INPUT_BUFFER.extend_from_slice(&cmd.data_first_byte);
        Ok(())
    }

    fn parse_execute(&mut self) -> Result<(ERROR_ID, CommandID), ()> {
        self.WC_OUTPUT_BUFFER.clear();
        let parsed: ResponseReadFirst = self.WC_INPUT_BUFFER.clone().into();
        let id_u8 = parsed.cmd_id;
        let operation = id_u8;
        self.current_command_id = operation;
        log::info!("Input buffer: {:?}", parsed);
        log::info!("Received operation: {:?} {:x?}", id_u8, operation);
        use CommandID::*;
        let res = match operation {
            STATUS => cmd_status(self),
            LOGIN => cmd_login(self),
            LOGOUT => cmd_logout(self),
            FACTORY_RESET => cmd_factory_reset(self),
            GET_CONFIGURATION => cmd_configure(self),
            SET_CONFIGURATION => cmd_configure(self),
            SET_PIN => cmd_manage_pin(self),
            CHANGE_PIN => cmd_manage_pin(self),
            INITIALIZE_SEED => cmd_initialize_seed(self),
            RESTORE_FROM_SEED => cmd_restore_from_seed(self),

            GENERATE_KEY => cmd_generate_key(self),
            SIGN => cmd_sign(self),
            DECRYPT => cmd_decrypt(self),

            OPENPGP_IMPORT => cmd_openpgp_import(self),
            OPENPGP_SIGN => cmd_openpgp_sign(self),
            OPENPGP_DECRYPT => cmd_openpgp_decrypt(self),
            OPENPGP_INFO => cmd_openpgp_info(self),
            OPENPGP_GENERATE => cmd_openpgp_generate(self),

            GENERATE_KEY_FROM_DATA => cmd_generate_key_from_data(self),

            READ_RESIDENT_KEY_PUBLIC => cmd_read_resident_key_public(self),
            GENERATE_RESIDENT_KEY => cmd_generate_resident_key(self),
            DISCOVER_RESIDENT_KEYS => cmd_discover_resident_key(self),
            WRITE_RESIDENT_KEY => cmd_write_resident_key(self),

            __MAX_SIZE => Err(ERR_INVALID_COMMAND),
            TEST_PING => cmd_test_ping(self),
            #[cfg(feature = "test-commands")]
            TEST_CLEAR => {
                todo!()
            }
            #[cfg(feature = "test-commands")]
            TEST_REBOOT => {
                todo!()
            }
            _ => Err(ERR_INVALID_COMMAND),
        };
        if res.is_err() {
            return Ok((res.err().unwrap(), operation));
        }
        Ok((ERR_SUCCESS, operation))
    }

    pub fn get_input(&self) -> &[u8] {
        self.WC_INPUT_BUFFER.as_slice()
    }

    pub fn get_input_deserialized<'a, T: Deserialize<'a>>(&'a self) -> Result<T, cbor_smol::Error> {
        cbor_deserialize::<T>(&self.WC_INPUT_BUFFER[3..])
    }

    pub fn send_to_output<T: Serialize>(&mut self, o: T) {
        // send data to output
        // limited to 256*8 bytes for now for a single write
        let mut buffer = [0u8; 256 * 8];
        let encoded = cbor_serialize(&o, &mut buffer).unwrap();
        log::info!("Encoded: {:?}", hex::encode(encoded));
        self.WC_OUTPUT_BUFFER.extend_from_slice(encoded);
    }

    pub fn send_to_output_arr(&mut self, o: &Bytes<1024>) {
        log::info!("Clear write: {:?}", o);
        self.WC_OUTPUT_BUFFER.extend_from_slice(o);
    }

    fn webcrypt_read_request(&self, output: &mut Bytes<1024>, cmd: &ExtWebcryptCmd) -> ERROR_ID {
        let offset = (u8::from(cmd.packet_no)) as usize * (cmd.chunk_size) as usize;
        let offset_right = offset + cmd.this_chunk_length as usize;
        let offset_right_clamp = min(offset_right, self.WC_OUTPUT_BUFFER.len() as usize);

        if self.WC_OUTPUT_BUFFER.len() == 0 {
            log::error!("No data available for read in the output buffer");
        }

        if offset >= self.WC_OUTPUT_BUFFER.len() {
            log::error!(
                "Requested offset bigger than available buffer length: {} > {}",
                offset,
                self.WC_OUTPUT_BUFFER.len()
            );
            return ERROR_ID::ERR_FAILED_LOADING_DATA;
        }

        output.extend_from_slice(&self.WC_OUTPUT_BUFFER[offset..offset_right_clamp]);
        log::info!(
            "Read: [{}..{})({})/{} {:?}",
            offset,
            offset_right_clamp,
            output.len(),
            self.WC_OUTPUT_BUFFER.len(),
            hex::encode(output)
        );
        ERROR_ID::ERR_SUCCESS
    }
    /// The main transport function, gateway to the extension from the Webauthn perspective
    /// Decodes incoming request low-level packet data, and either saves it to the input buffer,
    /// triggers execution or allows reading output buffer.
    pub fn bridge_u2f_to_webcrypt_raw(
        &mut self,
        mut output: CtapSignatureSize,
        keyh: &Bytes<255>,
        req_details: RequestDetails,
    ) -> Result<CtapSignatureSize, ERROR_ID> {
        let cmd = self.get_webcrypt_cmd(keyh)?;
        log::info!("< cmd: {:?}", cmd);
        let ret = self.bridge_u2f_to_webcrypt(cmd, req_details)?;
        log::info!("> ret: {:?}", ret);
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
        log::info!("> outputH: {:?}", hex::encode(output.clone()));
        Ok(output)
    }

    /// High level implementation
    /// Called from bridge_u2f_to_webcrypt_raw after initial deserialization
    pub fn bridge_u2f_to_webcrypt(
        &mut self,
        webcrypt_req: ExtWebcryptCmd,
        req_details: RequestDetails,
    ) -> Result<WebcryptResponseType, ERROR_ID> {
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
                        result: ERR_BAD_ORIGIN,
                    }));
                }

                self.webcrypt_write_request(&output.cbor_payload, &webcrypt_req)?;

                output.status_code = ERR_SUCCESS;
                let should_execute = webcrypt_req.is_final();
                if should_execute {
                    let res = self
                        .parse_execute()
                        .map_err(|_| ERROR_ID::ERR_INTERNAL_ERROR)?;
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
                    output.status_code = ERR_BAD_ORIGIN;
                    output.cbor_payload = Default::default();
                    return Ok(WebcryptResponseType::First(ResponseReadFirst {
                        data_len: 3, // size (2) + commandID (1)
                        cmd_id: Default::default(),
                        data: output.cbor_payload.into(),
                    }));
                }

                output.status_code =
                    self.webcrypt_read_request(&mut output.cbor_payload, &webcrypt_req);
                log::info!("output status_code: {:?}", output.status_code);
                match webcrypt_req.packet_no.0 {
                    0 => {
                        Ok(WebcryptResponseType::First(ResponseReadFirst {
                            data_len: self.WC_OUTPUT_BUFFER.len() as u16 + 3, // +3, // size (2) + commandID (1)
                            cmd_id: self.current_command_id,
                            data: output.cbor_payload.into(),
                        }))
                    }
                    _ => Ok(WebcryptResponseType::Next(ResponseReadNext {
                        data: output.cbor_payload.into(),
                    })),
                }
            }
        }
    }
    pub fn send_input_to_output(&mut self) {
        self.WC_OUTPUT_BUFFER
            .extend_from_slice(&self.WC_INPUT_BUFFER[3..]);
    }
}
