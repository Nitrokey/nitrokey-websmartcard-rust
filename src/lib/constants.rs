pub const GIT_VERSION: &str = env!("CARGO_PKG_VERSION");

// TODO rename to not confuse with FIDO2 RKs
pub const RESIDENT_KEY_COUNT: usize = 50;
pub const WEBCRYPT_VERSION: u16 = 1;
pub const WEBCRYPT_AVAILABLE_SLOTS_MAX: u16 = 80;
