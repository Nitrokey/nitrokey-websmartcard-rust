#![allow(non_camel_case_types)]

use crate::types::ERROR_ID::ERR_BAD_FORMAT;
use crate::types::TRANSPORT_CMD_ID::COMM_CMD_WRITE;
use crate::{Bytes, Message};
use ctap_types::ctap2::PinAuth;
use heapless_bytes::Bytes32;
pub type CtapSignatureSize = Bytes<72>;

// pub const WR_PAYLOAD_SIZE: usize = 255 - 4 - 1;
pub const WEBCRYPT_CONSTANT: u8 = 0x22;

#[derive(Debug, Clone)]
pub struct WebcryptRequest {
    operation_webcrypt_constant: u8, // always =0x22
    tag_webcrypt_constant: u32,      // magic tag
    pub payload: Message,            // size == WR_PAYLOAD_SIZE
}

#[derive(Debug, Clone)]
pub struct ExtWebcryptCmd {
    pub command_id_transport: TRANSPORT_CMD_ID,
    pub packet_no: PacketNum,
    pub packet_count: PacketNum,
    pub chunk_size: u8,
    pub this_chunk_length: u8,
    // pub data_first_byte: [u8; 255 - 5 - 5],
    pub data_first_byte: Bytes<245>,
}

#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Debug, Clone)]
pub enum TRANSPORT_CMD_ID {
    // COMM_CMD_NOT_SET = 0x00,   // not set
    COMM_CMD_WRITE = 0x01, // send command
    COMM_CMD_READ = 0x02,  // receive result
}

impl From<u8> for TRANSPORT_CMD_ID {
    fn from(t: u8) -> TRANSPORT_CMD_ID {
        use TRANSPORT_CMD_ID::*;
        match t {
            0x01 => COMM_CMD_WRITE,
            0x02 => COMM_CMD_READ,
            _ => {
                panic!("invalid value: {t}")
            }
        }
    }
}

impl From<TRANSPORT_CMD_ID> for u8 {
    fn from(t: TRANSPORT_CMD_ID) -> u8 {
        t as u8
    }
}

#[repr(u8)]
#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub enum ERROR_ID {
    ERR_SUCCESS = 0x00,
    ERR_REQ_AUTH = 0xF0,
    ERR_INVALID_PIN = 0xF1,
    ERR_NOT_ALLOWED = 0xF2,
    ERR_BAD_FORMAT = 0xF3,
    ERR_USER_NOT_PRESENT = 0xF4,
    ERR_FAILED_LOADING_DATA = 0xF5,
    ERR_INVALID_CHECKSUM = 0xF6,
    ERR_ALREADY_IN_DATABASE = 0xF7,
    ERR_NOT_FOUND = 0xF8,
    ERR_ASSERT_FAILED = 0xF9,
    ERR_INTERNAL_ERROR = 0xFA,
    ERR_MEMORY_FULL = 0xFB,
    ERR_NOT_IMPLEMENTED = 0xFC,
    ERR_BAD_ORIGIN = 0xFD,
    ERR_NOT_SET = 0xFE,
    ERR_INVALID_COMMAND = 0xFF,
}

impl Default for ERROR_ID {
    fn default() -> Self {
        ERROR_ID::ERR_NOT_SET
    }
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CommandID {
    // TODO design discuss should it be non-zero, to avoid responding to empty messages
    /// Get Webcrypt's status
    STATUS = 0x00,
    /// Test command - just return the received data
    TEST_PING = 0x01,
    /// Test command - clear user data without confirmation
    TEST_CLEAR = 0x02,
    /// Test command - issue reboot command to the host, if configured
    TEST_REBOOT = 0x03,
    /// Unlock access through FIDO U2F. Available for FIDO U2F compatibility.  FIDO2 should use native PIN handling.
    LOGIN = 0x04,
    /// Lock access through FIDO U2F. Available for FIDO U2F compatibility.
    LOGOUT = 0x05,
    /// Action should be equal in effect to calling FIDO2 reset
    FACTORY_RESET = 0x06,
    /// Return PIN attempts' counter value. @DEPRECATED by STATUS command.
    PIN_ATTEMPTS = 0x07,
    /// Set user options, like when to ask for the touch confirmation or PIN
    SET_CONFIGURATION = 0x08,
    GET_CONFIGURATION = 0x09,
    SET_PIN = 0x0A,
    CHANGE_PIN = 0x0B,

    /// Initialize Webcrypt's secrets
    INITIALIZE_SEED = 0x10,
    /// Restore Webcrypt secrets from the provided data
    RESTORE_FROM_SEED = 0x11,
    /// Generate a key and return it to the callee as key handle
    GENERATE_KEY = 0x12,
    /// Sign data with key handle
    SIGN = 0x13,
    /// Decrypt data with key handle
    DECRYPT = 0x14,
    /// Generate a key from the provided data
    GENERATE_KEY_FROM_DATA = 0x15,

    /// Write a Resident Key from the provided data
    GENERATE_RESIDENT_KEY = 0x16,
    /// Read public key of the Resident Key
    READ_RESIDENT_KEY_PUBLIC = 0x17,
    /// Discover Resident Keys related to this RP
    DISCOVER_RESIDENT_KEYS = 0x18,
    /// Write RAW key as received from the RP
    WRITE_RESIDENT_KEY = 0x19,

    /// OPENPGP specific commands
    OPENPGP_DECRYPT = 0x20,
    OPENPGP_SIGN = 0x21,
    OPENPGP_INFO = 0x22,
    OPENPGP_IMPORT = 0x23,
    OPENPGP_GENERATE = 0x24,

    /// Implementation detail: default value
    /// Add map to From<u8> for CommandID, or you will get this value: 0xFE
    NOT_SET = 0xFE,
    /// Implementation detail: commands' total count
    __MAX_SIZE,
}

impl Default for CommandID {
    fn default() -> Self {
        CommandID::NOT_SET
    }
}

impl From<CommandID> for u8 {
    fn from(c: CommandID) -> Self {
        c as u8
    }
}

impl From<u8> for CommandID {
    // generated from the enum list with regexp
    fn from(c: u8) -> Self {
        use CommandID::*;
        match c {
            0x00 => STATUS,
            0x01 => TEST_PING,
            0x02 => TEST_CLEAR,
            0x03 => TEST_REBOOT,
            0x04 => LOGIN,
            0x05 => LOGOUT,
            0x06 => FACTORY_RESET,
            0x07 => PIN_ATTEMPTS,
            0x08 => SET_CONFIGURATION,
            0x09 => GET_CONFIGURATION,
            0x0A => SET_PIN,
            0x0B => CHANGE_PIN,
            0x10 => INITIALIZE_SEED,
            0x11 => RESTORE_FROM_SEED,
            0x12 => GENERATE_KEY,
            0x13 => SIGN,
            0x14 => DECRYPT,
            0x15 => GENERATE_KEY_FROM_DATA,
            0x16 => GENERATE_RESIDENT_KEY,
            0x17 => READ_RESIDENT_KEY_PUBLIC,
            0x18 => DISCOVER_RESIDENT_KEYS,
            0x19 => WRITE_RESIDENT_KEY,

            0x20 => OPENPGP_DECRYPT,
            0x21 => OPENPGP_SIGN,
            0x22 => OPENPGP_INFO,
            0x23 => OPENPGP_IMPORT,
            0x24 => OPENPGP_GENERATE,

            0xFE => NOT_SET,
            _ => NOT_SET,
        }
    }
}

#[repr(u8)]
#[derive(PartialEq)]
pub enum RequestSource {
    RS_NOT_SET = 0,
    RS_U2F,
    RS_FIDO2,
    RS_NFC,
    RS_BT,
    RS_MAX,
}

#[derive(PartialEq)]
pub struct RequestDetails {
    pub source: RequestSource,
    pub rpid: Bytes32,
    pub pin_auth: Option<PinAuth>,
}

impl From<Message> for WebcryptRequest {
    fn from(arr: Message) -> Self {
        let mut w = WebcryptRequest {
            operation_webcrypt_constant: arr[0],
            tag_webcrypt_constant: u32::from_le_bytes(arr[1..4].try_into().unwrap()),
            payload: Default::default(),
        };
        w.payload.extend_from_slice(&arr[5..]).unwrap();
        w
    }
}

impl From<&Bytes<255>> for WebcryptRequest {
    fn from(arr: &Bytes<255>) -> Self {
        let mut wc_magic_number = [0u8; 4]; // FIXME correct that
        for i in 0..4 {
            wc_magic_number[i] = arr[1 + i];
        }

        let mut w = WebcryptRequest {
            operation_webcrypt_constant: arr[0],
            tag_webcrypt_constant: u32::from_le_bytes(wc_magic_number),
            payload: Message::new(), // FIXME use type with size WR_PAYLOAD_SIZE
        };
        assert_eq!(w.operation_webcrypt_constant, WEBCRYPT_CONSTANT);
        assert_eq!(wc_magic_number[0], 0x8c);
        assert_eq!(wc_magic_number[1], 0x27);

        w.payload.extend_from_slice(&arr[5..]).unwrap(); // TODO fix magic number
        w
    }
}

impl TryFrom<WebcryptRequest> for ExtWebcryptCmd {
    type Error = ERROR_ID;

    fn try_from(webcrypt_request: WebcryptRequest) -> Result<Self, Self::Error> {
        // move to serde/nom
        // let mut rdr = Cursor::new(&webcrypt_request.payload);
        let data = webcrypt_request.payload;
        // U8 U8 U8 U8 U8 MESS
        let mut res = ExtWebcryptCmd {
            command_id_transport: data[0].into(),
            packet_no: PacketNum::try_from(data[1])?,
            packet_count: PacketNum::try_from(data[2])?,
            chunk_size: data[3],
            this_chunk_length: data[4],
            data_first_byte: Default::default(),
        };
        // res.data_first_byte.extend(webcrypt_request.payload[5..]); // TODO fix magic number
        for i in 5..data.len() {
            res.data_first_byte.push(data[i]);
        }
        Ok(res)
    }
}

impl TryFrom<ExtWebcryptCmd> for Message {
    type Error = ERROR_ID;

    fn try_from(a: ExtWebcryptCmd) -> Result<Self, Self::Error> {
        let mut res = Message::new();
        res.push(a.command_id_transport as u8);
        res.push(a.packet_no.into());
        res.push(a.packet_count.into());
        res.push(a.chunk_size);
        res.push(a.this_chunk_length);
        res.extend_from_slice(&a.data_first_byte);
        Ok(res)
    }
}

// impl From<WebcryptRequest<'_>> for &[u8] {
impl TryFrom<WebcryptRequest> for Message {
    type Error = ERROR_ID;

    fn try_from(a: WebcryptRequest) -> Result<Self, Self::Error> {
        let mut res = Message::new();
        res.push(a.operation_webcrypt_constant);
        res.push((a.tag_webcrypt_constant & 0xFF000000) as u8);
        res.push((a.tag_webcrypt_constant & 0xFF0000) as u8);
        res.push((a.tag_webcrypt_constant & 0xFF00) as u8);
        res.push((a.tag_webcrypt_constant & 0xFF) as u8);
        res.extend_from_slice(&a.payload);
        // &res[..]
        // let mut res2 = [0u8; 255];
        // res2.copy_from_slice(&res);
        // res2
        Ok(res)
    }
}

impl ExtWebcryptCmd {
    pub fn new_with_data(v: Message) -> Self {
        ExtWebcryptCmd {
            data_first_byte: Bytes::<245>::from_slice(&v).unwrap(),
            ..Self::new()
        }
    }

    pub fn new_with_data_packet(v: Message, p_no: u8, p_total: u8) -> Result<Self, ERROR_ID> {
        Ok(ExtWebcryptCmd {
            this_chunk_length: v.len() as u8,
            data_first_byte: Bytes::<245>::from_slice(&v).unwrap(),
            packet_no: p_no.try_into()?,
            packet_count: p_total.try_into()?,
            ..Self::new()
        })
    }

    pub fn new() -> Self {
        ExtWebcryptCmd {
            command_id_transport: COMM_CMD_WRITE,
            packet_no: 0.try_into().unwrap(),
            packet_count: 1.try_into().unwrap(),
            chunk_size: 200,
            this_chunk_length: 71,
            data_first_byte: Default::default(),
        }
    }

    pub fn is_final(&self) -> bool {
        self.packet_no == self.packet_count.get_previous()
    }
}

impl WebcryptRequest {
    pub fn new(payload: ExtWebcryptCmd) -> Result<Self, ERROR_ID> {
        Ok(WebcryptRequest {
            operation_webcrypt_constant: WEBCRYPT_CONSTANT,
            tag_webcrypt_constant: 0xABCDEFAB,
            payload: payload.try_into()?,
        })
    }
}

#[derive(Debug, Default)]
pub struct WebcryptResult {
    pub status_code: ERROR_ID,
    // pub reply_length: u16,
    pub cbor_payload: Message,
}

impl From<WebcryptResult> for Message {
    fn from(r: WebcryptResult) -> Self {
        let mut v = Message::new();
        v.push(r.status_code as u8);
        v.extend(r.cbor_payload);
        v
    }
}
//
// impl TryFrom<ExtWebcryptCmd> for WebcryptRequest{
//     type Error = std::io::Error;
//
//     fn try_from(value: ExtWebcryptCmd) -> Result<Self, Self::Error> {
//         Ok(WebcryptRequest {
//             operation_webcrypt_constant: WEBCRYPT_CONSTANT,
//             tag_webcrypt_constant: 0xABCDEFAB,
//             payload: value.try_into()?,
//         })
//     }
// }

#[derive(Default, Debug, Clone, Eq, PartialEq, Copy)]
pub struct PacketNum(pub u8);

const PACKET_NUM_MAX: u8 = 30;

impl PacketNum {
    pub fn get_previous(&self) -> Self {
        // TODO validate
        // TODO fail, for 0 case?
        PacketNum(match self.0 {
            0 => 0,
            _ => self.0 - 1,
        })
    }
}

impl TryFrom<u8> for PacketNum {
    type Error = ERROR_ID;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > PACKET_NUM_MAX {
            return Err(ERR_BAD_FORMAT);
        }
        Ok(PacketNum(value))
    }
}

impl From<PacketNum> for u8 {
    fn from(value: PacketNum) -> Self {
        value.0
    }
}

#[derive(Debug, Default)]
pub struct CborPart(pub Message);

impl From<Message> for CborPart {
    fn from(v: Message) -> Self {
        CborPart(v)
    }
}

// struct FirstPayloadPacket {
//     command: CommandID,
//     cbor_part: CborPart,
// }
//
// struct NextPayloadPacket {
//     cbor_part: CborPart,
// }
//
// struct CompletePayload {
//     first: FirstPayloadPacket,
//     next: Vec<NextPayloadPacket>,
// }

// this is response for the protocol WRITE command
#[derive(Debug)]
pub struct ResponseWrite {
    pub(crate) result: ERROR_ID,
}

// this is response for the protocol READ command
#[derive(Debug, Default)]
pub struct ResponseReadFirst {
    pub data_len: u16,
    pub cmd_id: CommandID,
    pub data: CborPart,
}

impl ResponseReadFirst {
    fn new() -> Self {
        ResponseReadFirst::default()
    }
}

impl From<Message> for ResponseReadFirst {
    fn from(v: Message) -> Self {
        let mut rr = ResponseReadFirst::new();
        rr.data_len = u16::from_le_bytes(v[0..2].try_into().unwrap());
        // rr.cmd_id = CommandID::rdr.read_u8();
        rr.cmd_id = v[2].into();
        // rr.data = Vec::from(v[3..]); // TODO
        rr
    }
}

impl From<ResponseReadFirst> for Message {
    fn from(r: ResponseReadFirst) -> Self {
        let mut v: Message = Bytes::new();
        v.push(((r.data_len >> 8) & 0xFF) as u8); // using little endian here
        v.push((r.data_len & 0xFF) as u8);
        v.push(r.cmd_id as u8);
        v.extend(r.data.0);
        v
    }
}

// this is response for the protocol READ command, subsequent packet
#[derive(Debug)]
pub struct ResponseReadNext {
    pub data: CborPart,
}

// this response contains the whole output buffer from the Webcrypt extension, fragmented over responses
// struct ResponseReadComplete {
//     first: ResponseReadFirst,
//     next: Vec<ResponseReadNext>,
// }

#[derive(Debug)]
pub enum WebcryptResponseType {
    First(ResponseReadFirst),
    Next(ResponseReadNext),
    Write(ResponseWrite),
}

// extern crate hex;

impl WebcryptResponseType {
    pub fn log_hex(&self) {
        match &self {
            WebcryptResponseType::First(_d) => {
                // log::info!(
                //     "WebcryptResponseType data: {:?}",
                //     hex::encode(_d.data.0.clone())
                // )
            }
            WebcryptResponseType::Next(_d) => {
                // log::info!(
                //     "WebcryptResponseType data: {:?}",
                //     hex::encode(_d.data.0.clone())
                // )
            }
            WebcryptResponseType::Write(_d) => {}
        }
    }
}
