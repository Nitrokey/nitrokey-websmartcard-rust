use apdu_dispatch::app::Interface;
use apdu_dispatch::command::SIZE as APDU_SIZE;
use apdu_dispatch::iso7816::Status;
use apdu_dispatch::iso7816::{Aid, App};
use apdu_dispatch::{app as apdu, iso7816, response::Data, Command};
use ctap_types::{serde::error::Error as SerdeError, Error};
use ctaphid_dispatch::{app as ctaphid, app};
use trussed::client;

use crate::Webcrypt;

const SIZE: usize = APDU_SIZE;

impl<C> App for Webcrypt<C>
where
    C: client::Aes256Cbc
        + client::Chacha8Poly1305
        + client::Client
        + client::HmacSha256
        + client::HmacSha256P256
        + client::P256
        + client::Sha256
        + app::App
        + trussed::Client,
{
    fn aid(&self) -> Aid {
        Aid::new(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01])
    }
}

impl<C> apdu::App<{ SIZE }, { SIZE }> for Webcrypt<C>
where
    C: trussed::Client
        + client::Client
        + client::P256
        + client::Chacha8Poly1305
        + client::Aes256Cbc
        + client::HmacSha256
        + client::HmacSha256P256
        + app::App
        + client::Sha256,
{
    fn select(
        &mut self,
        apdu: &apdu::Command<{ SIZE }>,
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
        reply: &mut apdu::Data<{ apdu_dispatch::response::SIZE }>,
    ) -> apdu::Result {
        if interface != apdu::Interface::Contactless {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }

        let instruction: u8 = apdu.instruction().into();
        Ok(match instruction {
            0x00 | 0x01 | 0x02 => super::handle_ctap1(self, apdu.data(), response), //self.call_authenticator_u2f(apdu, response),

            _ => {
                match ctaphid::Command::try_from(instruction) {
                    // 0x10
                    Ok(ctaphid::Command::Cbor) => super::handle_ctap2(self, apdu.data(), response),
                    Ok(ctaphid::Command::Msg) => super::handle_ctap1(self, apdu.data(), response),
                    Ok(ctaphid::Command::Deselect) => self.deselect(),
                    _ => {
                        info!("Unsupported ins for fido app {:02x}", instruction);
                        return Err(iso7816::Status::InstructionNotSupportedOrInvalid);
                    }
                }
            }
        })
    }
}
