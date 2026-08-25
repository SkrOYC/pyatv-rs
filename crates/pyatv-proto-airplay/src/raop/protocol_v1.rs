//! The AirPlay 1 RAOP protocol: SDP `ANNOUNCE`, a `Transport` header, and unencrypted audio.
//!
//! Port of `AirPlayV1` (`pyatv/protocols/raop/protocols/airplayv1.py`). Three things distinguish it
//! from the AirPlay 2 path in [`super::protocol_v2`]:
//!
//! - **`ANNOUNCE` exists.** The stream format is advertised as SDP before `SETUP`, and only here —
//!   `airplayv2.py` never calls `announce()` at all.
//! - **`SETUP` negotiates through headers**, not a property list, and the receiver answers with a
//!   `Transport` header this module parses.
//! - **Audio is sent in the clear.** There is no cipher object on this class at all.
//!
//! The keepalive is also different: a single probe `POST /feedback` decides whether the receiver
//! supports it, and if so a **twenty-five second** loop starts — not AirPlay 2's two seconds.

use std::collections::HashMap;
use std::time::Duration;

use pyatv_pairing::HapCredentials;
use tokio::task::JoinHandle;

use crate::auth::PairVerifyProcedure;
use crate::raop::connection::{SharedConnection, with_connection};
use crate::raop::context::StreamContext;
use crate::raop::rtsp as raop_rtsp;
use crate::rtsp::AnnounceFormat;
use crate::{Error, Result};

/// How often the AirPlay 1 keepalive fires.
///
/// `KEEP_ALIVE_INTERVAL = 25` (`airplayv1.py:16`).
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(25);

/// The ports and session identifier an AirPlay 1 `SETUP` reply carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportPorts {
    /// `server_port` — where audio packets go. Required.
    pub server_port: u16,
    /// `control_port` — where sync packets go. Required.
    pub control_port: u16,
    /// `timing_port`, defaulting to zero when the receiver omits it.
    pub timing_port: u16,
}

/// Parse a `Transport` header into its bare tokens and its `key=value` pairs.
///
/// `parse_transport` (`airplayv1.py:24-34`): split on `;`, anything containing `=` becomes a pair
/// (split on the *first* `=` only), everything else is a bare parameter.
#[must_use]
pub fn parse_transport(transport: &str) -> (Vec<&str>, HashMap<&str, &str>) {
    let mut params = Vec::new();
    let mut options = HashMap::new();

    for option in transport.split(';') {
        match option.split_once('=') {
            Some((key, value)) => {
                options.insert(key, value);
            }
            None => params.push(option),
        }
    }

    (params, options)
}

/// Read the three ports out of a receiver's `Transport` header.
///
/// `server_port` and `control_port` are required — upstream indexes them directly and raises
/// `KeyError` if they are absent — while `timing_port` falls back to `0`
/// (`airplayv1.py:69-72`).
///
/// # Errors
///
/// Returns [`Error::Malformed`] if a required port is missing or is not a number.
pub fn transport_ports(transport: &str) -> Result<TransportPorts> {
    let (_, options) = parse_transport(transport);

    let port = |key: &str| -> Result<u16> {
        options
            .get(key)
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| Error::Malformed(format!("SETUP reply has no usable {key}")))
    };

    Ok(TransportPorts {
        server_port: port("server_port")?,
        control_port: port("control_port")?,
        timing_port: options
            .get("timing_port")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
    })
}

/// The AirPlay 1 streaming protocol.
#[derive(Debug, Default)]
pub struct AirPlayV1 {
    keep_alive: Option<JoinHandle<()>>,
}

impl Drop for AirPlayV1 {
    fn drop(&mut self) {
        self.teardown();
    }
}

impl AirPlayV1 {
    /// A protocol with no keepalive running.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pair-verify, `ANNOUNCE` and `SETUP`.
    ///
    /// `AirPlayV1.setup` (`airplayv1.py:47-79`). Pair-verify runs on **every** call; upstream has
    /// no verify-once optimisation and neither does this. It also deliberately does *not* enable
    /// transport encryption: legacy device authentication derives no session keys
    /// (`auth/legacy.py:101,108-113`), so the connection stays plaintext afterwards.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::NotAuthenticated`] if the receiver rejects the credentials,
    /// [`crate::Error::PasswordRequired`] if a password challenge cannot be answered,
    /// [`Error::Malformed`] if the `SETUP` reply omits a port, and [`crate::Error::Io`] on a
    /// transport failure.
    pub async fn setup(
        &mut self,
        connection: &SharedConnection,
        context: &mut StreamContext,
        credentials: &HapCredentials,
        password: Option<&str>,
        timing_port: u16,
        control_port: u16,
    ) -> Result<()> {
        let format = AnnounceFormat {
            bits_per_channel: u32::from(context.audio.sample_size),
            channels: u32::from(context.audio.channels),
            sample_rate: context.audio.sample_rate,
        };
        let transport_header = format!(
            "RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port={control_port};\
             timing_port={timing_port}"
        );

        let (transport, session) = with_connection(connection, async |rtsp, http| {
            let mut verifier = PairVerifyProcedure::new(credentials)?;
            verifier.verify_credentials(http).await?;

            raop_rtsp::announce(rtsp, http, format, password).await?;
            raop_rtsp::setup_transport(rtsp, http, &transport_header).await
        })
        .await?;

        let ports = transport_ports(&transport)?;
        context.server_port = ports.server_port;
        context.control_port = ports.control_port;
        context.timing_port = ports.timing_port;
        context.rtsp_session = session
            .as_deref()
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| Error::Malformed("SETUP reply has no Session header".to_owned()))?;

        tracing::debug!(
            control = ports.control_port,
            timing = ports.timing_port,
            server = ports.server_port,
            "remote RAOP ports negotiated"
        );

        Ok(())
    }

    /// Probe `/feedback` and, if the receiver answers `200`, keep the connection warm.
    ///
    /// `AirPlayV1.start_feedback` (`airplayv1.py:88-95`): the probe is sent with `allow_error`, and
    /// anything other than `200` means "keep-alive not supported" and starts no task at all.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the probe cannot be sent.
    pub async fn start_feedback(&mut self, connection: &SharedConnection) -> Result<()> {
        let supported = with_connection(connection, async |rtsp, http| {
            Ok(rtsp.feedback(http, true).await?.is_success())
        })
        .await?;

        if !supported {
            tracing::debug!("keep-alive not supported, not starting task");
            return Ok(());
        }

        let connection = connection.clone();
        self.keep_alive = Some(tokio::spawn(async move {
            tracing::debug!("starting keep-alive task");
            loop {
                tokio::time::sleep(KEEP_ALIVE_INTERVAL).await;

                let outcome = with_connection(&connection, async |rtsp, http| {
                    rtsp.feedback(http, false).await
                })
                .await;
                if let Err(error) = outcome {
                    tracing::debug!(%error, "feedback failed");
                }
            }
        }));

        Ok(())
    }

    /// Stop the keepalive.
    ///
    /// `AirPlayV1.teardown` (`airplayv1.py:81-86`).
    pub fn teardown(&mut self) {
        if let Some(keep_alive) = self.keep_alive.take() {
            keep_alive.abort();
        }
    }

    /// Build one audio packet.
    ///
    /// `AirPlayV1.send_audio_packet` (`airplayv1.py:111-117`): header and payload concatenated,
    /// nothing else. No cipher exists on this path.
    #[must_use]
    pub fn audio_packet(header: &[u8], audio: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(header.len() + audio.len());
        packet.extend_from_slice(header);
        packet.extend_from_slice(audio);
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::{AirPlayV1, KEEP_ALIVE_INTERVAL, parse_transport, transport_ports};

    /// The header the fake receiver answers with (`tests/fake_device/raop.py:429-437`).
    #[test]
    fn a_transport_header_splits_into_parameters_and_options() {
        let (params, options) = parse_transport(
            "RTP/AVP/UDP;unicast;mode=record;server_port=6000;control_port=6001;timing_port=6002",
        );

        assert_eq!(params, ["RTP/AVP/UDP", "unicast"]);
        assert_eq!(options.get("mode"), Some(&"record"));
        assert_eq!(options.get("server_port"), Some(&"6000"));
    }

    /// A value containing `=` keeps everything after the first one.
    #[test]
    fn only_the_first_equals_sign_splits_an_option() {
        let (_, options) = parse_transport("key=a=b");

        assert_eq!(options.get("key"), Some(&"a=b"));
    }

    #[test]
    fn the_three_ports_come_out_of_the_header() {
        let ports = transport_ports(
            "RTP/AVP/UDP;unicast;mode=record;server_port=6000;control_port=6001;timing_port=6002",
        )
        .expect("parses");

        assert_eq!(ports.server_port, 6000);
        assert_eq!(ports.control_port, 6001);
        assert_eq!(ports.timing_port, 6002);
    }

    /// `timing_port` defaults to zero; the other two do not default at all.
    #[test]
    fn a_missing_timing_port_defaults_to_zero() {
        let ports = transport_ports("server_port=6000;control_port=6001").expect("parses");

        assert_eq!(ports.timing_port, 0);
    }

    #[test]
    fn a_missing_required_port_is_an_error() {
        assert!(transport_ports("server_port=6000").is_err());
        assert!(transport_ports("control_port=6001").is_err());
        assert!(transport_ports("server_port=nope;control_port=1").is_err());
    }

    /// AirPlay 1 sends the payload in the clear, with nothing appended.
    #[test]
    fn an_audio_packet_is_the_header_followed_by_the_payload() {
        let packet = AirPlayV1::audio_packet(&[0x80, 0x60, 0, 1], &[0xAA, 0xBB]);

        assert_eq!(packet, [0x80, 0x60, 0, 1, 0xAA, 0xBB]);
    }

    /// Twenty-five seconds, not AirPlay 2's two.
    #[test]
    fn the_keep_alive_interval_matches_upstream() {
        assert_eq!(KEEP_ALIVE_INTERVAL.as_secs(), 25);
    }
}
