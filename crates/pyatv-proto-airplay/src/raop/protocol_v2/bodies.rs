//! The `SETUP` bodies the AirPlay 2 RAOP protocol sends, and the reply it reads ports out of.
//!
//! Split out of [`super`] so the wire shapes — which are almost entirely hardcoded literals
//! (`pyatv/protocols/raop/protocols/airplayv2.py:56-72,127-155`) — sit apart from the session
//! state machine that sends them, and can be asserted without one.

use crate::rtsp::FRAMES_PER_PACKET;
use crate::{Error, Result};

/// `audioFormat` in the audio-stream `SETUP`. Raw PCM; there is no branch that ever sends anything
/// else (`airplayv2.py:130`).
pub const AUDIO_FORMAT_PCM: u64 = 0x800;

/// `ct` — compression type `1`, "Raw PCM" (`airplayv2.py:134`).
pub const COMPRESSION_TYPE_PCM: u64 = 1;

/// `type` — the RTP payload type, `0x60` (`airplayv2.py:141`).
pub const STREAM_TYPE_AUDIO: u64 = 0x60;

/// `latencyMax` (`airplayv2.py:136`).
pub const LATENCY_MAX: u64 = 88_200;

/// `latencyMin` (`airplayv2.py:137`).
pub const LATENCY_MIN: u64 = 11_025;

/// `sr` in the audio-stream `SETUP`. Hardcoded upstream, not taken from the receiver's `sr` TXT
/// key (`airplayv2.py:140`).
pub const STREAM_SAMPLE_RATE: u64 = 44_100;

/// Build the base `SETUP` body.
///
/// `AirPlayV2._setup_base` (`airplayv2.py:56-72`), fifteen keys, all but `sessionUUID` and
/// `timingPort` hardcoded literals — including the `deviceID` and `macAddress`, which upstream does
/// **not** take from `InfoSettings` on this path even though it does on the tunnel path.
#[must_use]
pub fn base_setup_body(session_uuid: &str, timing_port: u16) -> plist::Value {
    let mut body = plist::Dictionary::new();
    body.insert("deviceID".to_owned(), "AA:BB:CC:DD:EE:FF".into());
    body.insert("sessionUUID".to_owned(), session_uuid.into());
    body.insert("timingPort".to_owned(), u64::from(timing_port).into());
    body.insert("timingProtocol".to_owned(), "NTP".into());
    body.insert("isMultiSelectAirPlay".to_owned(), true.into());
    body.insert("groupContainsGroupLeader".to_owned(), false.into());
    body.insert("macAddress".to_owned(), "AA:BB:CC:DD:EE:FF".into());
    body.insert("model".to_owned(), "iPhone14,3".into());
    body.insert("name".to_owned(), "pyatv".into());
    body.insert("osBuildVersion".to_owned(), "20F66".into());
    body.insert("osName".to_owned(), "iPhone OS".into());
    body.insert("osVersion".to_owned(), "16.5".into());
    body.insert("senderSupportsRelay".to_owned(), false.into());
    body.insert("sourceVersion".to_owned(), "690.7.1".into());
    body.insert("statsCollectionEnabled".to_owned(), false.into());
    plist::Value::Dictionary(body)
}

/// Build the audio-stream `SETUP` body.
///
/// `AirPlayV2.setup_audio_stream` (`airplayv2.py:127-149`): a one-element `streams` array whose
/// dictionary is a fixed literal apart from `controlPort`, `shk` and `streamConnectionID`. Nothing
/// in it is conditional on what the receiver advertised — not the codec, not the sample rate.
#[must_use]
pub fn audio_stream_setup_body(
    control_port: u16,
    shared_key: &[u8; 32],
    stream_connection_id: u32,
) -> plist::Value {
    let mut stream = plist::Dictionary::new();
    stream.insert("audioFormat".to_owned(), AUDIO_FORMAT_PCM.into());
    stream.insert("audioMode".to_owned(), "default".into());
    stream.insert("controlPort".to_owned(), u64::from(control_port).into());
    stream.insert("ct".to_owned(), COMPRESSION_TYPE_PCM.into());
    stream.insert("isMedia".to_owned(), true.into());
    stream.insert("latencyMax".to_owned(), LATENCY_MAX.into());
    stream.insert("latencyMin".to_owned(), LATENCY_MIN.into());
    stream.insert("shk".to_owned(), plist::Value::Data(shared_key.to_vec()));
    stream.insert("spf".to_owned(), u64::from(FRAMES_PER_PACKET).into());
    stream.insert("sr".to_owned(), STREAM_SAMPLE_RATE.into());
    stream.insert("type".to_owned(), STREAM_TYPE_AUDIO.into());
    stream.insert("supportsDynamicStreamID".to_owned(), false.into());
    stream.insert(
        "streamConnectionID".to_owned(),
        u64::from(stream_connection_id).into(),
    );

    let mut body = plist::Dictionary::new();
    body.insert(
        "streams".to_owned(),
        plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
    );
    plist::Value::Dictionary(body)
}

/// Read `controlPort` and `dataPort` out of the audio-stream `SETUP` reply.
///
/// `stream = resp["streams"][0]` (`airplayv2.py:151-155`).
///
/// # Errors
///
/// Returns [`Error::Plist`] if the reply has no first stream, or that stream omits either port.
pub fn audio_stream_ports(reply: &plist::Value) -> Result<(u16, u16)> {
    let stream = reply
        .as_dictionary()
        .and_then(|body| body.get("streams"))
        .and_then(plist::Value::as_array)
        .and_then(|streams| streams.first())
        .and_then(plist::Value::as_dictionary)
        .ok_or_else(|| Error::Plist("audio SETUP reply has no streams[0]".to_owned()))?;

    let port = |key: &str| -> Result<u16> {
        stream
            .get(key)
            .and_then(plist::Value::as_unsigned_integer)
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| Error::Plist(format!("audio SETUP reply has no usable {key}")))
    };

    Ok((port("controlPort")?, port("dataPort")?))
}

#[cfg(test)]
mod tests {
    use super::{
        AUDIO_FORMAT_PCM, COMPRESSION_TYPE_PCM, STREAM_TYPE_AUDIO, audio_stream_ports,
        audio_stream_setup_body, base_setup_body,
    };

    /// Fifteen keys, and `timingProtocol` is `NTP` — the one field that most obviously separates
    /// this from the remote-control tunnel's `SETUP`.
    #[test]
    fn the_base_setup_body_carries_pyatvs_fifteen_keys() {
        let body = base_setup_body("A-B-C", 6002);
        let dictionary = body.as_dictionary().expect("a dictionary");

        assert_eq!(
            setup_keys(&body),
            [
                "deviceID",
                "groupContainsGroupLeader",
                "isMultiSelectAirPlay",
                "macAddress",
                "model",
                "name",
                "osBuildVersion",
                "osName",
                "osVersion",
                "senderSupportsRelay",
                "sessionUUID",
                "sourceVersion",
                "statsCollectionEnabled",
                "timingPort",
                "timingProtocol",
            ]
        );
        assert_eq!(dictionary["timingProtocol"].as_string(), Some("NTP"));
        assert_eq!(dictionary["timingPort"].as_unsigned_integer(), Some(6002));
        assert_eq!(dictionary["sourceVersion"].as_string(), Some("690.7.1"));
        assert_eq!(
            dictionary["deviceID"].as_string(),
            Some("AA:BB:CC:DD:EE:FF")
        );
    }

    /// The audio stream is raw PCM at 44100, unconditionally.
    #[test]
    fn the_audio_stream_body_is_raw_pcm() {
        let body = audio_stream_setup_body(6001, &[0xAB; 32], 0xDEAD_BEEF);
        let stream = body.as_dictionary().expect("a dictionary")["streams"]
            .as_array()
            .expect("an array")[0]
            .as_dictionary()
            .expect("a dictionary");

        assert_eq!(
            stream["audioFormat"].as_unsigned_integer(),
            Some(AUDIO_FORMAT_PCM)
        );
        assert_eq!(
            stream["ct"].as_unsigned_integer(),
            Some(COMPRESSION_TYPE_PCM)
        );
        assert_eq!(
            stream["type"].as_unsigned_integer(),
            Some(STREAM_TYPE_AUDIO)
        );
        assert_eq!(stream["spf"].as_unsigned_integer(), Some(352));
        assert_eq!(stream["sr"].as_unsigned_integer(), Some(44_100));
        assert_eq!(stream["latencyMin"].as_unsigned_integer(), Some(11_025));
        assert_eq!(stream["latencyMax"].as_unsigned_integer(), Some(88_200));
        assert_eq!(stream["audioMode"].as_string(), Some("default"));
        assert_eq!(stream["isMedia"].as_boolean(), Some(true));
        assert_eq!(stream["supportsDynamicStreamID"].as_boolean(), Some(false));
        assert_eq!(
            stream["streamConnectionID"].as_unsigned_integer(),
            Some(0xDEAD_BEEF)
        );
        assert_eq!(stream["shk"].as_data(), Some(&[0xAB; 32][..]));
    }

    #[test]
    fn the_reply_ports_come_out_of_the_first_stream() {
        let mut stream = plist::Dictionary::new();
        stream.insert("controlPort".to_owned(), 7001u64.into());
        stream.insert("dataPort".to_owned(), 7002u64.into());
        let mut reply = plist::Dictionary::new();
        reply.insert(
            "streams".to_owned(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );

        assert_eq!(
            audio_stream_ports(&plist::Value::Dictionary(reply)).expect("parses"),
            (7001, 7002)
        );
    }

    #[test]
    fn a_reply_without_streams_is_an_error() {
        let reply = plist::Value::Dictionary(plist::Dictionary::new());

        assert!(audio_stream_ports(&reply).is_err());
    }

    fn setup_keys(body: &plist::Value) -> Vec<String> {
        let mut keys: Vec<String> = body
            .as_dictionary()
            .expect("a dictionary")
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    }
}
