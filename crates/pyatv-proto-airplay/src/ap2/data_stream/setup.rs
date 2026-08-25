//! The data-stream channel's RTSP `SETUP` body and the reply it produces.
//!
//! Port of `AP2Session._setup_data_channel`'s request dictionary and its `dataPort` lookup
//! (`pyatv/protocols/airplay/ap2_session.py:151-174`).

use crate::ap2::random_uuid;
use crate::rtsp::decode_plist;
use crate::{Error, Result};

/// `controlType` of the remote-control stream. A fixed literal whose semantics are opaque —
/// nothing in pyatv ever decodes it — but which must be sent byte-identical.
pub const CONTROL_TYPE: i64 = 2;

/// `type` of the remote-control stream, likewise a fixed opaque literal.
pub const STREAM_TYPE: i64 = 130;

/// `clientTypeUUID`, the constant that identifies this stream as *the* remote-control data stream.
///
/// Not configurable and not per-session: it is the same literal for every controller
/// (`ap2_session.py:168`).
pub const CLIENT_TYPE_UUID: &str = "1910A70F-DBC0-4242-AF95-115DB30604E1";

/// The per-session values that go into a data-stream `SETUP`.
///
/// `seed` is drawn once and used twice: it is sent in cleartext in the body *and* appended to the
/// `DataStream-Salt` HKDF salt, which is how both ends agree on the channel's keys. It has no
/// secrecy requirement — upstream draws it from Python's `random.randint`, not a CSPRNG
/// (`ap2_session.py:156`) — only a per-session uniqueness one, so this port takes it from the
/// system CSPRNG because that costs nothing.
///
/// `channel_id` and `client_uuid` are two **independently drawn** UUIDs, neither reused from the
/// event channel's `sessionUUID` (`ap2_session.py:163,165`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataStreamRequest {
    /// The 64-bit salt disambiguator.
    pub seed: u64,
    /// `channelID`.
    pub channel_id: String,
    /// `clientUUID`.
    pub client_uuid: String,
}

impl DataStreamRequest {
    /// Draw a fresh set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seed: rand::random(),
            channel_id: random_uuid(),
            client_uuid: random_uuid(),
        }
    }

    /// Build the `SETUP` body.
    ///
    /// The complete key set of the single `streams` element, in upstream's dict order
    /// (`ap2_session.py:158-172`). No other key is sent, and `streams` always carries exactly one
    /// entry.
    #[must_use]
    pub fn body(&self) -> plist::Value {
        let mut stream = plist::Dictionary::new();
        stream.insert("controlType".to_owned(), CONTROL_TYPE.into());
        stream.insert("channelID".to_owned(), self.channel_id.as_str().into());
        stream.insert("seed".to_owned(), self.seed.into());
        stream.insert("clientUUID".to_owned(), self.client_uuid.as_str().into());
        stream.insert("type".to_owned(), STREAM_TYPE.into());
        stream.insert("wantsDedicatedSocket".to_owned(), true.into());
        stream.insert("clientTypeUUID".to_owned(), CLIENT_TYPE_UUID.into());

        let mut body = plist::Dictionary::new();
        body.insert(
            "streams".to_owned(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        plist::Value::Dictionary(body)
    }
}

impl Default for DataStreamRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// What the receiver answers a data-stream `SETUP` with.
///
/// Upstream reads `streams[0].dataPort` and nothing else (`ap2_session.py:174`). A live tvOS 27
/// device answers a three-key `streams[0]`: `dataPort`, the `type: 130` echoed back, and a
/// `streamID` integer (`1` on a first stream) that appears nowhere in pyatv. Nothing here needs it
/// — the socket is identified by its port — so it is read past rather than captured, but it is
/// worth knowing the key exists before assuming a two-key reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataStreamSetup {
    /// `streams[0].dataPort`, the TCP port the controller dials for the data channel.
    pub data_port: u16,
}

impl DataStreamSetup {
    /// Read `streams[0].dataPort` out of a `SETUP` reply.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Plist`] if the reply is not a dictionary, has no non-empty `streams` array,
    /// or carries a `dataPort` that is not a 16-bit integer.
    pub fn from_plist(value: &plist::Value) -> Result<Self> {
        let stream = value
            .as_dictionary()
            .and_then(|it| it.get("streams"))
            .and_then(plist::Value::as_array)
            .and_then(|streams| streams.first())
            .and_then(plist::Value::as_dictionary)
            .ok_or_else(|| Error::Plist("SETUP reply has no streams[0]".to_owned()))?;

        let raw = stream
            .get("dataPort")
            .and_then(plist::Value::as_unsigned_integer)
            .ok_or_else(|| Error::Plist("streams[0] has no dataPort".to_owned()))?;

        Ok(Self {
            data_port: u16::try_from(raw)
                .map_err(|_| Error::Plist(format!("dataPort {raw} is not a TCP port")))?,
        })
    }

    /// Read the port out of a raw binary property list body.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Plist`] if `body` is not a property list carrying `streams[0].dataPort`.
    pub fn parse(body: &[u8]) -> Result<Self> {
        Self::from_plist(&decode_plist(body)?)
    }
}

#[cfg(test)]
mod tests {
    use super::{CLIENT_TYPE_UUID, DataStreamRequest, DataStreamSetup};
    use crate::rtsp::{decode_plist, encode_plist};

    fn stream_of(request: &DataStreamRequest) -> plist::Dictionary {
        request.body().as_dictionary().expect("a dictionary")["streams"]
            .as_array()
            .expect("an array")[0]
            .as_dictionary()
            .expect("a dictionary")
            .clone()
    }

    /// The key set is closed: seven keys on the single stream, no more and no fewer
    /// (`ap2_session.py:158-172`).
    #[test]
    fn the_stream_carries_exactly_pyatvs_seven_keys() {
        let stream = stream_of(&DataStreamRequest::new());

        let mut keys: Vec<&str> = stream.keys().map(String::as_str).collect();
        keys.sort_unstable();

        assert_eq!(
            keys,
            [
                "channelID",
                "clientTypeUUID",
                "clientUUID",
                "controlType",
                "seed",
                "type",
                "wantsDedicatedSocket",
            ]
        );
    }

    /// The three opaque literals, and `wantsDedicatedSocket` as a real boolean rather than `1`.
    #[test]
    fn the_stream_carries_the_fixed_literals() {
        let stream = stream_of(&DataStreamRequest::new());

        assert_eq!(stream["controlType"].as_signed_integer(), Some(2));
        assert_eq!(stream["type"].as_signed_integer(), Some(130));
        assert_eq!(stream["wantsDedicatedSocket"].as_boolean(), Some(true));
        assert_eq!(stream["clientTypeUUID"].as_string(), Some(CLIENT_TYPE_UUID));
    }

    /// `channelID` and `clientUUID` are independent draws, not the same value twice.
    #[test]
    fn the_two_uuids_are_drawn_independently() {
        let request = DataStreamRequest::new();
        assert_ne!(request.channel_id, request.client_uuid);
    }

    /// The body has to survive the binary plist encoder, including the 64-bit seed.
    #[test]
    fn the_body_round_trips_through_a_binary_plist() {
        let request = DataStreamRequest {
            seed: u64::MAX,
            channel_id: "A".to_owned(),
            client_uuid: "B".to_owned(),
        };
        let encoded = encode_plist(&request.body()).expect("encodes");

        assert!(encoded.starts_with(b"bplist00"));
        assert_eq!(decode_plist(&encoded).expect("decodes"), request.body());
    }

    #[test]
    fn a_reply_yields_the_data_port() {
        let mut stream = plist::Dictionary::new();
        stream.insert("dataPort".to_owned(), 49_500u64.into());
        let mut reply = plist::Dictionary::new();
        reply.insert(
            "streams".to_owned(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        let encoded = encode_plist(&plist::Value::Dictionary(reply)).expect("encodes");

        assert_eq!(
            DataStreamSetup::parse(&encoded).expect("parses"),
            DataStreamSetup { data_port: 49_500 }
        );
    }

    #[test]
    fn a_reply_without_streams_is_an_error() {
        let encoded =
            encode_plist(&plist::Value::Dictionary(plist::Dictionary::new())).expect("encodes");

        assert!(DataStreamSetup::parse(&encoded).is_err());
    }
}
