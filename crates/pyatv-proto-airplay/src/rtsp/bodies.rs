//! The plist and SDP bodies RTSP verbs carry.
//!
//! Split out of [`super`] because they are pure encodings with no session state: the binary
//! property list every AirPlay 2 body travels as (`pyatv/support/rtsp.py:287-289`,
//! `pyatv/support/http.py:221-232`) and the `ANNOUNCE` SDP template
//! (`pyatv/support/rtsp.py:25-35`).

use super::FRAMES_PER_PACKET;
use crate::{Error, Result};

/// Encode a property list as the binary plist AirPlay bodies use.
///
/// `plistlib.dumps(body, fmt=FMT_BINARY)` (`pyatv/support/rtsp.py:287-289`).
///
/// # Errors
///
/// Returns [`Error::Plist`] if the value cannot be serialised.
pub fn encode_plist(value: &plist::Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, value).map_err(|error| Error::Plist(error.to_string()))?;
    Ok(out)
}

/// Decode a binary property list body.
///
/// `decode_bplist_from_body` (`pyatv/support/http.py:221-232`).
///
/// # Errors
///
/// Returns [`Error::Plist`] if `body` is not a property list.
pub fn decode_plist(body: &[u8]) -> Result<plist::Value> {
    plist::from_bytes(body).map_err(|error| Error::Plist(error.to_string()))
}

/// The parameters an `ANNOUNCE` SDP body is built from.
///
/// Only these three are substituted into pyatv's `ANNOUNCE_PAYLOAD` template; the codec, payload
/// type and frames
/// per packet are literals in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnounceFormat {
    /// Bits per channel, i.e. `8 * bytes_per_channel`.
    pub bits_per_channel: u32,
    /// Channel count.
    pub channels: u32,
    /// Sample rate in Hz.
    pub sample_rate: u32,
}

/// Build the SDP body for an `ANNOUNCE` request.
///
/// `ANNOUNCE_PAYLOAD` (`pyatv/support/rtsp.py:25-35`), reproduced line for line including the
/// trailing CRLF on the last line. Note that the codec named in `rtpmap` is `L16` — raw 16-bit
/// linear PCM — even though the `fmtp` line follows ALAC's conventional field layout, and that the
/// `96 L16/44100/2` and `352` tokens are hardcoded upstream rather than templated on
/// [`AnnounceFormat`]: only `bits_per_channel`, `channels` and `sample_rate` are substituted,
/// which is why a receiver asking for something other than 44100/2 gets an internally inconsistent
/// body. That inconsistency is upstream's and is reproduced (`docs/research/rust-crates.md` §7,
/// `airplay-playurl-raop-port-spec.md` §11).
#[must_use]
pub fn announce_sdp(
    session_id: u32,
    local_ip: &str,
    remote_ip: &str,
    format: AnnounceFormat,
) -> String {
    let AnnounceFormat {
        bits_per_channel,
        channels,
        sample_rate,
    } = format;

    format!(
        "v=0\r\n\
         o=iTunes {session_id} 0 IN IP4 {local_ip}\r\n\
         s=iTunes\r\n\
         c=IN IP4 {remote_ip}\r\n\
         t=0 0\r\n\
         m=audio 0 RTP/AVP 96\r\n\
         a=rtpmap:96 L16/44100/2\r\n\
         a=fmtp:96 {FRAMES_PER_PACKET} 0 {bits_per_channel} 40 10 14 {channels} 255 0 0 \
         {sample_rate}\r\n"
    )
}

#[cfg(test)]
mod tests {
    use super::{decode_plist, encode_plist};

    /// Bodies go out as `bplist00`, not XML — the receiver rejects the XML form.
    #[test]
    fn plist_bodies_round_trip_as_binary() {
        let mut dictionary = plist::Dictionary::new();
        dictionary.insert(
            "isRemoteControlOnly".to_owned(),
            plist::Value::Boolean(true),
        );
        let value = plist::Value::Dictionary(dictionary);

        let encoded = encode_plist(&value).expect("encodes");
        assert!(encoded.starts_with(b"bplist00"));
        assert_eq!(decode_plist(&encoded).expect("decodes"), value);
    }

    /// A body that is not a property list is a decode error, not a panic.
    #[test]
    fn a_non_plist_body_is_an_error() {
        assert!(decode_plist(b"not a plist").is_err());
    }
}
