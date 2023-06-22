use ctaphid_dispatch::app;
use ctaphid_dispatch::app::{AppResult, Command};

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
    fn peek(&self, request: &ctaphid_dispatch::types::Message) -> bool;
}

pub struct PeekingBypass<'a, A: app::App<'a>, B: app::App<'a> + Peeking> {
    /// The application to be run, if peeking app rejects the call
    fallback_app: A,
    /// The application peeking into request, and deciding if it should run
    peeking_app: B,
    // PhantomData is required here to have the lifetime parameter used
    phantom: core::marker::PhantomData<&'a A>,
}

impl<'a, A: app::App<'a>, B: app::App<'a> + Peeking> PeekingBypass<'a, A, B> {
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

impl<'a, A: app::App<'a>, B: app::App<'a> + Peeking> app::App<'_> for PeekingBypass<'a, A, B> {
    fn commands(&self) -> &'static [Command] {
        // TODO Ideally this would be constructed commands' list from the taken apps
        &[app::Command::Cbor, app::Command::Msg]
    }

    fn call(
        &mut self,
        command: Command,
        request: &app::Message,
        response: &mut app::Message,
    ) -> AppResult {
        if self.peeking_app.peek(request) {
            self.peeking_app.call(command, request, response)
        } else {
            self.fallback_app.call(command, request, response)
        }
    }
}
