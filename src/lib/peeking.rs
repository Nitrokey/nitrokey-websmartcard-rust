use ctaphid_dispatch::app::{App, Command, Error};
use heapless_bytes::Bytes;

pub trait Peeking {
    /// Allow application to peek into the incoming request to decide, whether it should take it over,
    /// or reject it.
    ///
    /// # Arguments
    ///
    /// * `request`: The raw ctaphid request, which will be analyzed
    ///
    /// returns: bool - false, if application rejects the request, true otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// fn peek(request: &ctaphid_dispatch::types::Message) -> bool {
    ///      if request.len() < 7 {
    ///          return false;
    ///      }
    ///      for offset in 1..request.len() - 5 {
    ///          if request[offset..=4 + offset] == [0x22, 0x8c, 0x27, 0x90, 0xF6] {
    ///              info!("Found expected constant at offset {offset}");
    ///              return true;
    ///          }
    ///      }
    ///      false
    ///  }
    /// ```
    fn peek(&self, request: &[u8]) -> bool;
}

pub struct PeekingBypass<'a, A, B> {
    /// The application to be run, if peeking app rejects the call
    fallback_app: A,
    /// The application peeking into request, and deciding if it should run
    peeking_app: B,
    // PhantomData is required here to have the lifetime parameter used
    phantom: core::marker::PhantomData<&'a A>,
}

impl<A, B> PeekingBypass<'_, A, B> {
    /// Create a new application wrapper, which could be used as an app itself.
    ///
    /// # Arguments
    ///
    /// * `fallback_app`: The application to be run, if peeking app rejects the call
    /// * `peeking_app`: The application peeking into request, and deciding if it should run
    ///
    /// returns: PeekingBypass<A, B>
    ///
    /// # Examples
    ///
    /// ```text
    /// struct Apps {
    ///     admin: admin_app::App<VirtClient, Reboot, AdminStatus>,
    ///     peeking_fido: PeekingBypass<'static, FidoAuthApp, WebcryptApp>,
    /// }
    ///  ....
    /// Apps {
    ///     admin,
    ///     peeking_fido: PeekingBypass::new(fido, webcrypt),
    /// }
    /// ```
    pub fn new(fallback_app: A, peeking_app: B) -> Self {
        PeekingBypass {
            fallback_app,
            peeking_app,
            phantom: Default::default(),
        }
    }
}

impl<'a, A: App<'a, N>, B: App<'a, N> + Peeking, const N: usize> App<'_, N>
    for PeekingBypass<'a, A, B>
{
    fn commands(&self) -> &'static [Command] {
        // TODO Ideally this would be constructed commands' list from the taken apps
        &[Command::Cbor, Command::Msg]
    }

    fn call(
        &mut self,
        command: Command,
        request: &[u8],
        response: &mut Bytes<N>,
    ) -> Result<(), Error> {
        if self.peeking_app.peek(request) {
            self.peeking_app.call(command, request, response)
        } else {
            self.fallback_app.call(command, request, response)
        }
    }
}
