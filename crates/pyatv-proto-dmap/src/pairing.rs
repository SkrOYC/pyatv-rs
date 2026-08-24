//! DMAP pairing, in which the client acts as the server.
//!
//! Unlike every other protocol here, DMAP pairing has the Apple TV connect *to* us. pyatv starts a
//! small HTTP server on an ephemeral port, publishes an mDNS `_touch-remote._tcp.local.` service so
//! the device can find it, and shows the user a PIN. The device then calls back with an MD5 of the
//! pairing GUID interleaved with the PIN digits. See `docs/research/airplay-raop-dmap.md` §11.6.
//!
//! The MD5 input is built by writing each of the four PIN digits followed by a NUL byte, appended
//! to the pairing GUID — an odd construction that must be reproduced exactly.

use crate::Result;

/// The mDNS service pyatv publishes while waiting for the device to call back.
pub const REMOTE_SERVICE_TYPE: &str = "_touch-remote._tcp.local.";

/// The device type pyatv advertises. A spoof, and deliberately so.
pub const DEVICE_TYPE: &str = "iPhone";

/// Drives a DMAP pairing session.
#[derive(Debug)]
pub struct DmapPairing {
    /// Random 64-bit pairing GUID, uppercase hex without the `0x` prefix.
    pairing_guid: String,
    /// The PIN shown to the user.
    pin: u16,
    has_paired: bool,
}

impl DmapPairing {
    /// Start a session with a generated GUID and a PIN to display.
    #[must_use]
    pub fn new(pairing_guid: String, pin: u16) -> Self {
        Self {
            pairing_guid,
            pin,
            has_paired: false,
        }
    }

    /// The GUID this session will persist on success.
    #[must_use]
    pub fn pairing_guid(&self) -> &str {
        &self.pairing_guid
    }

    /// The PIN the user must enter on the device.
    #[must_use]
    pub fn pin(&self) -> u16 {
        self.pin
    }

    /// Whether the device has called back successfully.
    #[must_use]
    pub fn has_paired(&self) -> bool {
        self.has_paired
    }

    /// Start the callback listener and publish the mDNS service.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the listener cannot bind.
    // TODO(step-1): bind a tokio TCP listener on an ephemeral port, serve GET /pair, and register
    // _touch-remote._tcp via pyatv-mdns's publish path.
    pub async fn begin(&mut self) -> Result<()> {
        todo!("DmapPairing::begin")
    }

    /// Check a pairing code the device sent back.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Pairing`] if the digest does not match.
    // TODO(step-1): MD5 over `pairing_guid` followed by each PIN digit and a NUL byte, compared
    // case-insensitively against the received hex digest. See
    // docs/research/airplay-raop-dmap.md §11.6.
    pub fn verify_pairing_code(&mut self, received: &str) -> Result<()> {
        let _ = received;
        todo!("DmapPairing::verify_pairing_code")
    }
}
