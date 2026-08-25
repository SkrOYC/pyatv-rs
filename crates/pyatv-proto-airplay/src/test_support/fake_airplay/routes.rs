//! Request routing for the fake AirPlay 2 receiver.
//!
//! Split out of [`super`] so the listener, its state and its options sit apart from the table of
//! verbs they serve. Mirrors how [`super::super::fake_raop`] is already laid out.

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use pyatv_pairing::hkdf_derive::{
    data_stream_salt,
    transport::{AIRPLAY_CONTROL, AIRPLAY_DATA_STREAM, AIRPLAY_EVENTS},
};
use pyatv_pairing::pairing::SessionKeys;
use pyatv_pairing::server::ReferenceAccessory;
use pyatv_pairing::{Tlv8, TlvValue};
use tokio::sync::Mutex;

use super::super::fake_bridge::serve_data_bridge;
use super::super::fake_channels::{bind_loopback, serve_data, serve_event};
use super::super::fake_play;
use super::{BPLIST, FakeOptions, FakeRequest, FakeState, TLV8};

/// Route one request, returning the wire response and the keys to encrypt with from then on.
pub(super) async fn handle(
    request: &FakeRequest,
    accessory: &Arc<Mutex<ReferenceAccessory>>,
    state: &Arc<FakeState>,
    options: &FakeOptions,
) -> (Vec<u8>, Option<SessionKeys>) {
    let cseq = request.header("CSeq").unwrap_or("1").to_owned();
    let hkp = request.header("X-Apple-HKP");

    match (request.method.as_str(), request.path.as_str()) {
        (_, "/pair-pin-start") => (response(200, "OK", &cseq, None, &[]), None),
        (_, "/pair-setup") => {
            let body = match hkp {
                // Both HAP and transient run the same handler; the accessory tells them apart from
                // the `Flags` TLV in M1, as `_m1_setup(transient=…)` does upstream.
                Some("3" | "4") => accessory.lock().await.handle_pair_setup(&request.body),
                _ => return (response(501, "Not implemented", &cseq, None, &[]), None),
            };
            match body {
                Ok(tlv) => (response(200, "OK", &cseq, Some(TLV8), &tlv), None),
                Err(error) => (response(500, &error.to_string(), &cseq, None, &[]), None),
            }
        }
        (_, "/pair-verify") => {
            if hkp != Some("3") {
                return (response(501, "Not implemented", &cseq, None, &[]), None);
            }
            let mut accessory = accessory.lock().await;
            match accessory.handle_pair_verify(&request.body) {
                Ok(tlv) => {
                    // The accessory's roles are the mirror of the controller's: its output key is
                    // derived with `Control-Read-…` and its input key with `Control-Write-…`
                    // (`airplay/server_auth.py:296-309`).
                    let keys = (sequence_number(&request.body) == Some(3))
                        .then(|| {
                            accessory
                                .encryption_keys(
                                    AIRPLAY_CONTROL.salt,
                                    AIRPLAY_CONTROL.read_info,
                                    AIRPLAY_CONTROL.write_info,
                                )
                                .ok()
                        })
                        .flatten();
                    (response(200, "OK", &cseq, Some(TLV8), &tlv), keys)
                }
                Err(error) => (response(500, &error.to_string(), &cseq, None, &[]), None),
            }
        }
        ("SETUP", _) => (setup(request, accessory, state, options, &cseq).await, None),
        ("RECORD", _) => {
            state.records.fetch_add(1, Ordering::SeqCst);
            (response(200, "OK", &cseq, None, &[]), None)
        }
        ("POST", "/feedback") => {
            state.feedbacks.fetch_add(1, Ordering::SeqCst);
            (response(200, "OK", &cseq, None, &[]), None)
        }
        ("GET", "/info") => (response(200, "OK", &cseq, Some(BPLIST), &info_body()), None),
        _ => match fake_play::handle(request, &state.play, options.play_mode).await {
            Some(reply) => (
                response(
                    reply.status,
                    reply.reason,
                    &cseq,
                    reply.content_type,
                    &reply.body,
                ),
                None,
            ),
            None => (response(404, "File not found", &cseq, None, &[]), None),
        },
    }
}

/// Answer a remote-control `SETUP`, allocating whichever channel it asked for.
async fn setup(
    request: &FakeRequest,
    accessory: &Arc<Mutex<ReferenceAccessory>>,
    state: &Arc<FakeState>,
    options: &FakeOptions,
    cseq: &str,
) -> Vec<u8> {
    if options.refuse_setup {
        return response(455, "Method Not Valid In This State", cseq, None, &[]);
    }

    let Ok(body) = plist::from_bytes::<plist::Value>(&request.body) else {
        return response(400, "Bad request", cseq, None, &[]);
    };
    let Some(dictionary) = body.as_dictionary() else {
        return response(400, "Bad request", cseq, None, &[]);
    };

    if let Some(seed) = dictionary
        .get("streams")
        .and_then(plist::Value::as_array)
        .and_then(|streams| streams.first())
        .and_then(plist::Value::as_dictionary)
        .and_then(|stream| stream.get("seed"))
        .and_then(plist::Value::as_unsigned_integer)
    {
        *state.data_setup.lock().await = Some(body.clone());

        // Unswapped on the controller's side, so mirrored here: the receiver writes with the key
        // the controller reads with (`ap2_session.py:176-184`).
        let keys = accessory
            .lock()
            .await
            .encryption_keys(
                &data_stream_salt(seed),
                AIRPLAY_DATA_STREAM.read_info,
                AIRPLAY_DATA_STREAM.write_info,
            )
            .expect("pair-verify must have completed before SETUP");

        let (listener, port) = bind_loopback().await;
        let state = Arc::clone(state);
        match options.data_bridge {
            Some(device) => {
                tokio::spawn(async move { serve_data_bridge(listener, keys, state, device).await });
            }
            None => {
                tokio::spawn(async move { serve_data(listener, keys, state).await });
            }
        }

        let mut stream = plist::Dictionary::new();
        stream.insert("dataPort".to_owned(), u64::from(port).into());
        let mut reply = plist::Dictionary::new();
        reply.insert(
            "streams".to_owned(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        return response(200, "OK", cseq, Some(BPLIST), &encode(&reply));
    }

    *state.event_setup.lock().await = Some(body.clone());

    // The controller derives this pair swapped, so this side derives it straight
    // (`ap2_session.py:140-148`).
    let keys = accessory
        .lock()
        .await
        .encryption_keys(
            AIRPLAY_EVENTS.salt,
            AIRPLAY_EVENTS.write_info,
            AIRPLAY_EVENTS.read_info,
        )
        .expect("pair-verify must have completed before SETUP");

    let (listener, port) = bind_loopback().await;
    let probe = options.event_probe.clone();
    let state_for_channel = Arc::clone(state);
    tokio::spawn(async move { serve_event(listener, keys, state_for_channel, probe).await });

    let mut reply = plist::Dictionary::new();
    reply.insert("eventPort".to_owned(), u64::from(port).into());
    if let Some(timing_port) = options.timing_port {
        reply.insert("timingPort".to_owned(), u64::from(timing_port).into());
    }
    if let Some(skip_record) = options.skip_record {
        reply.insert("skipRecord".to_owned(), skip_record.into());
    }
    response(200, "OK", cseq, Some(BPLIST), &encode(&reply))
}

/// A small stand-in for the twenty-seven-key `/info` a real receiver answers with.
fn info_body() -> Vec<u8> {
    let mut info = plist::Dictionary::new();
    info.insert("model".to_owned(), "AppleTV14,1".into());
    info.insert("name".to_owned(), "Fake".into());
    info.insert("protocolVersion".to_owned(), "1.1".into());
    encode(&info)
}

fn encode(dictionary: &plist::Dictionary) -> Vec<u8> {
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, &plist::Value::Dictionary(dictionary.clone()))
        .expect("encodes");
    out
}

/// Read the `SeqNo` out of a TLV8 body, so M3 can be told from M1.
fn sequence_number(body: &[u8]) -> Option<u8> {
    Tlv8::decode(body)
        .ok()?
        .get(TlvValue::SeqNo)
        .and_then(|value| value.first())
        .copied()
}

/// Rewrite a response's protocol token to the one the request used.
///
/// `format_response` builds every reply as `HttpResponse(request.protocol, request.version, …)`
/// (`server_auth.py:193-204,230-241,251-262`, `support/http.py:143-150`), so a receiver answers
/// `RTSP/1.0` to an RTSP request and `HTTP/1.1` to an HTTP one **on the same socket** — AirPlay 2
/// runs both over one connection. The tvOS 27 captures in
/// `docs/research/airplay-tunnel-auth-experiment-2026-08-24.md` show exactly that: `HTTP/1.1 200
/// OK` to `POST /pair-verify HTTP/1.1` (line 42) and `RTSP/1.0 200 OK` to `SETUP … RTSP/1.0`
/// (line 128).
///
/// [`response`] always writes `HTTP/1.1`, which is the shape pyatv's own client happens to accept
/// either way; answering as the device really does is what makes a client that has grown a
/// dependency on the constant fail here rather than on hardware.
pub(super) fn echo_protocol(response: Vec<u8>, protocol: &str) -> Vec<u8> {
    const DEFAULT: &[u8] = b"HTTP/1.1";

    if protocol.as_bytes() == DEFAULT || !response.starts_with(DEFAULT) {
        return response;
    }

    let mut out = protocol.as_bytes().to_vec();
    out.extend_from_slice(&response[DEFAULT.len()..]);
    out
}

/// Serialise a response the way `format_response` does (`pyatv/support/http.py:143-167`):
/// `Server` first, then the caller's headers, then `Content-Length` only for a non-empty body.
///
/// The protocol token is a placeholder that [`echo_protocol`] replaces with the request's.
fn response(
    code: u16,
    message: &str,
    cseq: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> Vec<u8> {
    let mut head =
        format!("HTTP/1.1 {code} {message}\r\nServer: pyatv-rs-fake/1.0\r\nCSeq: {cseq}\r\n");
    if let Some(content_type) = content_type {
        let _ = write!(head, "Content-Type: {content_type}\r\n");
    }
    if !body.is_empty() {
        let _ = write!(head, "Content-Length: {}\r\n", body.len());
    }
    head.push_str("\r\n");

    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}
