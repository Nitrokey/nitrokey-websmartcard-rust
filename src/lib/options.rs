use trussed::types::Location;

/// The options for the Webcrypt app.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Options {
    /// The storage location for the application data.
    pub location: Location,

    /// A serial number to be returned in OpenPGP commands
    pub serial_number: [u8; 4],

    /// A maximum number of credentials allowed to store
    pub max_resident_credentials_allowed: u16,
}

impl Options {
    /// Create new Options instance
    pub const fn new(
        location: Location,
        serial_number: [u8; 4],
        max_resident_credentials_allowed: u16,
    ) -> Self {
        Self {
            location,
            serial_number,
            max_resident_credentials_allowed,
        }
    }
}
