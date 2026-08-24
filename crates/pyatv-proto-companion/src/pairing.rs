//! Companion pairing: HAP pair-setup and pair-verify over `PS_*`/`PV_*` frames.
//!
//! The exchange itself is identical to MRP's — the same `pyatv_pairing::srp_hap` state machine,
//! the same TLV8 payloads, the same M1 to M6 sequence. Only the envelope differs: Companion puts
//! the TLV8 in an OPACK dictionary under the key `_pd` inside a dedicated frame type, where MRP
//! wraps it in a `CryptoPairingMessage` protobuf. See `docs/research/mrp-companion.md` §4.3.

use pyatv_pairing::HapCredentials;

use crate::Result;
use crate::connection::CompanionConnection;

/// The OPACK dictionary key carrying TLV8 pairing data.
pub const PAIRING_DATA_KEY: &str = "_pd";

/// Drives a Companion pair-setup exchange.
#[derive(Debug)]
pub struct CompanionPairing {
    has_paired: bool,
}

impl CompanionPairing {
    /// Start pairing over an established connection.
    #[must_use]
    pub fn new(connection: &CompanionConnection) -> Self {
        let _ = connection;
        Self { has_paired: false }
    }

    /// Send M1 and wait for the device to display its PIN.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Pairing`] if the device refuses to begin.
    // TODO(step-1): send a PS_Start frame carrying TLV8 {Method: PairSetup, SeqNo: M1}.
    pub async fn begin(&mut self) -> Result<()> {
        todo!("CompanionPairing::begin")
    }

    /// Complete the exchange with the PIN the device displayed.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Pairing`] if the PIN is wrong or the device aborts.
    // TODO(step-1): drive pyatv_pairing::srp_hap::HapSrpClient through M3/M5 over PS_Next frames,
    // then derive and persist the long-term keys.
    pub async fn finish(&mut self, pin: u32) -> Result<HapCredentials> {
        let _ = pin;
        todo!("CompanionPairing::finish")
    }

    /// Whether the exchange has produced credentials.
    #[must_use]
    pub fn has_paired(&self) -> bool {
        self.has_paired
    }
}
