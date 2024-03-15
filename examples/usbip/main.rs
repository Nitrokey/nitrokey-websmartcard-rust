// Copyright (C) 2023 Nitrokey GmbH
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Taken from: https://github.com/Nitrokey/nitrokey-3-firmware/tree/main/runners/usbip
use std::path::{Path, PathBuf};
const LOCATION_FOR_SIMULATION: Location = Location::Internal;

mod dispatch {
    use trussed_hkdf::HkdfExtension;
    use trussed_manage::ManageExtension;
    use trussed_staging::StagingBackend;
    use trussed_staging::StagingContext;
    use webcrypt::hmacsha256p256::HmacSha256P256Extension;

    use trussed::{
        api::{reply, request, Reply, Request},
        backend::{Backend as _, BackendId},
        error::Error,
        platform::Platform,
        serde_extensions::{ExtensionDispatch, ExtensionId, ExtensionImpl},
        service::ServiceResources,
        types::{Bytes, Context},
    };
    use trussed_auth::{AuthBackend, AuthContext, AuthExtension, MAX_HW_KEY_LEN};

    use crate::LOCATION_FOR_SIMULATION;
    #[cfg(feature = "rsa")]
    use trussed_rsa_alloc::SoftwareRsa;

    pub const BACKENDS: &[BackendId<Backend>] = &[
        #[cfg(feature = "rsa")]
        BackendId::Custom(Backend::Rsa),
        BackendId::Custom(Backend::Staging),
        BackendId::Custom(Backend::Auth),
        BackendId::Core,
    ];

    pub enum Backend {
        Auth,
        Staging,
        #[cfg(feature = "rsa")]
        Rsa,
        HmacShaP256,
    }

    pub enum Extension {
        Auth,
        HmacShaP256,
        Manage,
        Hkdf,
    }

    impl From<Extension> for u8 {
        fn from(extension: Extension) -> Self {
            match extension {
                Extension::Auth => 0,
                Extension::HmacShaP256 => 1,
                Extension::Manage => 2,
                Extension::Hkdf => 3,
            }
        }
    }

    impl TryFrom<u8> for Extension {
        type Error = Error;

        fn try_from(id: u8) -> Result<Self, Self::Error> {
            match id {
                0 => Ok(Extension::Auth),
                1 => Ok(Extension::HmacShaP256),
                2 => Ok(Extension::Manage),
                3 => Ok(Extension::Hkdf),
                _ => Err(Error::InternalError),
            }
        }
    }

    pub struct Dispatch {
        auth: AuthBackend,
        staging: StagingBackend,
        hmacsha256p256: webcrypt::hmacsha256p256::Backend,
    }

    #[derive(Default)]
    pub struct DispatchContext {
        auth: AuthContext,
        staging: StagingContext,
        hmacsha256p256: webcrypt::hmacsha256p256::BackendContext,
    }

    impl Dispatch {
        pub fn new() -> Self {
            Self {
                auth: AuthBackend::new(LOCATION_FOR_SIMULATION),
                staging: StagingBackend::new(),
                hmacsha256p256: webcrypt::hmacsha256p256::Backend::new(),
            }
        }

        pub fn with_hw_key(hw_key: Bytes<MAX_HW_KEY_LEN>) -> Self {
            Self {
                auth: AuthBackend::with_hw_key(LOCATION_FOR_SIMULATION, hw_key),
                staging: StagingBackend::new(),
                hmacsha256p256: webcrypt::hmacsha256p256::Backend::new(),
            }
        }
    }

    impl Default for Dispatch {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ExtensionDispatch for Dispatch {
        type BackendId = Backend;
        type Context = DispatchContext;
        type ExtensionId = Extension;

        fn core_request<P: Platform>(
            &mut self,
            backend: &Self::BackendId,
            ctx: &mut Context<Self::Context>,
            request: &Request,
            resources: &mut ServiceResources<P>,
        ) -> Result<Reply, Error> {
            match backend {
                Backend::Auth => {
                    self.auth
                        .request(&mut ctx.core, &mut ctx.backends.auth, request, resources)
                }
                #[cfg(feature = "rsa")]
                Backend::Rsa => SoftwareRsa.request(&mut ctx.core, &mut (), request, resources),
                Backend::Staging => self.staging.request(
                    &mut ctx.core,
                    &mut ctx.backends.staging,
                    request,
                    resources,
                ),
                Backend::HmacShaP256 => self.hmacsha256p256.request(
                    &mut ctx.core,
                    &mut ctx.backends.hmacsha256p256,
                    request,
                    resources,
                ),
            }
        }

        fn extension_request<P: Platform>(
            &mut self,
            backend: &Self::BackendId,
            extension: &Self::ExtensionId,
            ctx: &mut Context<Self::Context>,
            request: &request::SerdeExtension,
            resources: &mut ServiceResources<P>,
        ) -> Result<reply::SerdeExtension, Error> {
            match backend {
                Backend::Auth => match extension {
                    Extension::Auth => self.auth.extension_request_serialized(
                        &mut ctx.core,
                        &mut ctx.backends.auth,
                        request,
                        resources,
                    ),
                    _ => Err(Error::RequestNotAvailable),
                },
                #[cfg(feature = "rsa")]
                Backend::Rsa => Err(Error::RequestNotAvailable),
                // #[cfg(feature = "hmacsha256p256")]
                Backend::Staging => match extension {
                    Extension::Manage => {
                        ExtensionImpl::<ManageExtension>::extension_request_serialized(
                            &mut self.staging,
                            &mut ctx.core,
                            &mut ctx.backends.staging,
                            request,
                            resources,
                        )
                    }
                    _ => Err(Error::RequestNotAvailable),
                },
                Backend::HmacShaP256 => match extension {
                    Extension::HmacShaP256 => {
                        <webcrypt::hmacsha256p256::Backend as ExtensionImpl<
                            HmacSha256P256Extension,
                        >>::extension_request_serialized(
                            &mut self.hmacsha256p256,
                            &mut ctx.core,
                            &mut ctx.backends.hmacsha256p256,
                            request,
                            resources,
                        )
                    }
                    _ => Err(Error::RequestNotAvailable),
                },
            }
        }
    }

    impl ExtensionId<AuthExtension> for Dispatch {
        type Id = Extension;

        const ID: Self::Id = Self::Id::Auth;
    }

    impl ExtensionId<webcrypt::hmacsha256p256::HmacSha256P256Extension> for Dispatch {
        type Id = Extension;

        const ID: Self::Id = Self::Id::HmacShaP256;
    }

    impl ExtensionId<ManageExtension> for Dispatch {
        type Id = Extension;

        const ID: Self::Id = Self::Id::Manage;
    }

    impl ExtensionId<HkdfExtension> for Dispatch {
        type Id = Extension;

        const ID: Self::Id = Self::Id::Hkdf;
    }
}

#[cfg(feature = "ccid")]
use apdu_dispatch::command::SIZE as ApduCommandSize;

use clap::Parser;
use clap_num::maybe_hex;
use trussed::backend::BackendId;
use trussed::platform::{consent, reboot, ui};

use trussed::types::Location;
use trussed::{virt, ClientImplementation, Platform};
use trussed_usbip::ClientBuilder;

use usbd_ctaphid::constants::MESSAGE_SIZE;
use webcrypt::{debug, info, try_debug, try_info, try_warn, warn};
use webcrypt::{Options, PeekingBypass};

pub type FidoConfig = fido_authenticator::Config;
pub type VirtClient = ClientImplementation<
    trussed_usbip::Service<virt::Filesystem, dispatch::Dispatch>,
    dispatch::Dispatch,
>;

/// USP/IP based virtualization of the Nitrokey 3 / Solo2 device.
#[derive(Parser, Debug)]
#[clap(about, version, author)]
struct Args {
    /// USB Name string
    #[clap(short, long, default_value = "Webcrypt")]
    name: String,

    /// USB Manufacturer string
    #[clap(short, long, default_value = "Simulation")]
    manufacturer: String,

    /// USB Serial string
    #[clap(long, default_value = "SIM SIM SIM")]
    serial: String,

    /// Trussed state file
    #[clap(long, default_value = "trussed-state.bin")]
    state_file: PathBuf,

    /// FIDO attestation key
    #[clap(long)]
    fido_key: Option<PathBuf>,

    /// FIDO attestation cert
    #[clap(long)]
    fido_cert: Option<PathBuf>,

    /// USB VID id
    #[clap(short, long, parse(try_from_str=maybe_hex), default_value_t = 0x20a0)]
    vid: u16,
    /// USB PID id
    #[clap(short, long, parse(try_from_str=maybe_hex), default_value_t = 0x42b2)]
    pid: u16,
}

struct Reboot;

impl admin_app::Reboot for Reboot {
    fn reboot() -> ! {
        unimplemented!();
    }

    fn reboot_to_firmware_update() -> ! {
        unimplemented!();
    }

    fn reboot_to_firmware_update_destructive() -> ! {
        unimplemented!();
    }

    fn locked() -> bool {
        false
    }
}

#[repr(u8)]
#[derive(Debug)]
pub enum CustomStatus {
    ReverseHotpSuccess = 0,
    ReverseHotpError = 1,
    Unknown = 0xFF,
}

impl From<CustomStatus> for u8 {
    fn from(status: CustomStatus) -> Self {
        status as _
    }
}

impl TryFrom<u8> for CustomStatus {
    type Error = UnknownStatusError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ReverseHotpSuccess),
            1 => Ok(Self::ReverseHotpError),
            _ => Err(UnknownStatusError(value)),
        }
    }
}

pub struct UnknownStatusError(u8);

impl CustomStatus {}

#[derive(Debug)]
struct UserInterface {
    start_time: std::time::Instant,
    status: Option<ui::Status>,
}

impl UserInterface {
    fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
            status: None,
        }
    }
}

impl trussed::platform::UserInterface for UserInterface {
    /// Prompt user to type a word for confirmation
    fn check_user_presence(&mut self) -> consent::Level {
        // use std::io::Read as _;
        // This is not nice - we should "peek" and return Level::None
        // if there is no key pressed yet (unbuffered read from stdin).
        // Couldn't get this to work (without pulling in ncurses or similar).
        // std::io::stdin().bytes().next();
        consent::Level::Normal
    }

    fn set_status(&mut self, status: ui::Status) {
        debug!("Set status: {:?}", status);
        if let ui::Status::Custom(s) = status {
            let _cs: CustomStatus = CustomStatus::try_from(s).unwrap_or_else(|_| {
                warn!("Unsupported status value: {:?}", status);
                CustomStatus::Unknown
            });
            info!("Set status: [{}] {:?}", s, _cs);
        }

        if status == ui::Status::WaitingForUserPresence {
            info!(">>>> Received confirmation request. Confirming automatically.");
        }
        self.status = Some(status);
    }

    fn refresh(&mut self) {
        info!("Current status is: {:?}", self);
    }

    fn uptime(&mut self) -> core::time::Duration {
        self.start_time.elapsed()
    }

    fn reboot(&mut self, _to: reboot::To) -> ! {
        info!("Restart!  ({:?})", _to);
        std::process::exit(25);
    }
}

#[derive(Copy, Clone)]
pub enum Variant {
    Usbip,
    Lpc55,
    Nrf52,
}
impl From<Variant> for u8 {
    fn from(variant: Variant) -> Self {
        match variant {
            Variant::Usbip => 0,
            Variant::Lpc55 => 1,
            Variant::Nrf52 => 2,
        }
    }
}

pub struct AdminData {
    pub init_status: u8,
    pub ifs_blocks: u8,
    pub efs_blocks: u16,
    pub variant: Variant,
}
impl AdminData {
    pub fn new(variant: Variant) -> Self {
        Self {
            init_status: 0,
            ifs_blocks: u8::MAX,
            efs_blocks: u16::MAX,
            variant,
        }
    }
}

pub type AdminStatus = [u8; 5];
impl AdminData {
    fn encode(&self) -> AdminStatus {
        let efs_blocks = self.efs_blocks.to_be_bytes();
        [
            self.init_status,
            self.ifs_blocks,
            efs_blocks[0],
            efs_blocks[1],
            self.variant.into(),
        ]
    }
}

type FidoAuthApp = fido_authenticator::Authenticator<fido_authenticator::Conforming, VirtClient>;
type WebcryptApp = webcrypt::Webcrypt<VirtClient>;

struct Apps {
    admin: admin_app::App<VirtClient, Reboot, AdminStatus, ()>,
    peeking_fido: PeekingBypass<'static, FidoAuthApp, WebcryptApp>,
}

const MAX_RESIDENT_CREDENTIAL_COUNT: u32 = 50;

impl trussed_usbip::Apps<'static, VirtClient, dispatch::Dispatch> for Apps {
    type Data = ();
    fn new<B: ClientBuilder<VirtClient, dispatch::Dispatch>>(builder: &B, _data: ()) -> Self {
        let fido = fido_authenticator::Authenticator::new(
            builder.build("fido", &[BackendId::Core]),
            fido_authenticator::Conforming {},
            fido_authenticator::Config {
                max_msg_size: MESSAGE_SIZE,
                skip_up_timeout: None,
                max_resident_credential_count: Some(MAX_RESIDENT_CREDENTIAL_COUNT),
                large_blobs: None,
                nfc_transport: false,
            },
        );
        let data = AdminData::new(Variant::Usbip);
        let admin = admin_app::App::with_default_config(
            builder.build("admin", &[BackendId::Core]),
            [0; 16],
            0,
            "",
            data.encode(),
        );

        let webcrypt = webcrypt::Webcrypt::new_with_options(
            builder.build("webcrypt", dispatch::BACKENDS),
            Options::new(Location::External, *b"1234", 10000),
        );

        Self {
            admin,
            peeking_fido: PeekingBypass::new(fido, webcrypt),
        }
    }

    fn with_ctaphid_apps<T>(
        &mut self,
        f: impl FnOnce(&mut [&mut dyn ctaphid_dispatch::app::App<'static>]) -> T,
    ) -> T {
        f(&mut [&mut self.peeking_fido, &mut self.admin])
    }

    #[cfg(feature = "ccid")]
    fn with_ccid_apps<T>(
        &mut self,
        f: impl FnOnce(&mut [&mut dyn apdu_dispatch::app::App<ApduCommandSize, ApduCommandSize>]) -> T,
    ) -> T {
        f(&mut [])
    }
}

fn main() {
    pretty_env_logger::init();

    let args = Args::parse();

    let store = virt::Filesystem::new(args.state_file);
    let options = trussed_usbip::Options {
        manufacturer: Some(args.manufacturer),
        product: Some(args.name),
        serial_number: Some(args.serial),
        vid: args.vid,
        pid: args.pid,
    };

    info!("Initializing Trussed");
    trussed_usbip::Builder::new(store, options)
        .dispatch(dispatch::Dispatch::new())
        .init_platform(move |platform| {
            let ui: Box<dyn trussed::platform::UserInterface + Send + Sync> =
                Box::new(UserInterface::new());
            platform.user_interface().set_inner(ui);

            if let Some(fido_key) = &args.fido_key {
                store_file(platform, fido_key, "fido/sec/00");
            }
            if let Some(fido_cert) = &args.fido_cert {
                store_file(platform, fido_cert, "fido/x5c/00");
            }
        })
        .build::<Apps>()
        .exec(|_| ());
}

fn store_file(platform: &impl Platform, host_file: &Path, device_file: &str) {
    info!("Writing {} to file system", device_file);
    let data = std::fs::read(host_file).expect("failed to read file");
    trussed::store::store(
        platform.store(),
        LOCATION_FOR_SIMULATION,
        &trussed::types::PathBuf::from(device_file),
        &data,
    )
    .expect("failed to store file");
}
