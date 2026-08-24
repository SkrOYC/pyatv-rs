//! XID allocation, correlation and event dispatch, driven over a loopback socket pair.

use std::time::Duration;

use pyatv_opack::{Value, opack};
use tokio::net::{TcpListener, TcpStream};

use super::{CompanionProtocol, MessageType};
use crate::codec::FrameCodec;
use crate::frame::FrameType;
use crate::message::Envelope;
use crate::{CompanionConnection, Error};

/// One end of a loopback pair, framed but with no device logic behind it.
struct Peer {
    stream: TcpStream,
    codec: FrameCodec,
}

impl Peer {
    async fn send(&mut self, frame_type: FrameType, value: &Value) {
        use tokio::io::AsyncWriteExt as _;

        let packed = pyatv_opack::pack(value).expect("the fixture must pack");
        let frame = self
            .codec
            .encode(frame_type, &packed)
            .expect("the fixture must frame");
        self.stream
            .write_all(&frame)
            .await
            .expect("the peer must accept the write");
    }

    async fn recv(&mut self) -> (FrameType, Value) {
        use tokio::io::AsyncReadExt as _;

        loop {
            if let Some(frame) = self.codec.next_frame().expect("the frame must decode") {
                let (value, _) = pyatv_opack::unpack(&frame.payload).expect("the body must unpack");
                return (frame.frame_type, value);
            }
            self.codec.reserve(1024);
            let read = self
                .stream
                .read_buf(self.codec.buffer_mut())
                .await
                .expect("the peer must stay connected");
            assert_ne!(read, 0, "the protocol closed the connection unexpectedly");
        }
    }
}

/// A protocol wired to a bare peer, with a pinned starting XID.
async fn pair(first_xid: u32) -> (CompanionProtocol, super::EventStream, Peer) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binding must work");
    let address = listener
        .local_addr()
        .expect("a bound listener has an address");

    let client = TcpStream::connect(address)
        .await
        .expect("connecting must work");
    let (server, _) = listener.accept().await.expect("accepting must work");

    let (protocol, events) =
        CompanionProtocol::with_xid(CompanionConnection::from_stream(address, client), first_xid);

    (
        protocol,
        events,
        Peer {
            stream: server,
            codec: FrameCodec::new(),
        },
    )
}

/// Build the response a device sends to a request, echoing `_i` and `_x`
/// (`fake_device/companion.py:309-318`).
fn response_to(request: &Value, content: Value) -> Value {
    opack! {
        "_i" => request.get("_i").and_then(Value::as_str).unwrap_or_default(),
        "_x" => request.get("_x").and_then(Value::as_u64).unwrap_or_default(),
        "_t" => MessageType::Response.code(),
        "_c" => content,
    }
}

/// The XID goes out on the wire and comes back on the response that resolves the call.
#[tokio::test]
async fn a_request_is_correlated_by_its_xid() {
    let (mut protocol, _events, mut peer) = pair(9000).await;

    let device = tokio::spawn(async move {
        let (frame_type, request) = peer.recv().await;
        assert_eq!(frame_type, FrameType::EOpack);
        assert_eq!(request.get("_x").and_then(Value::as_u64), Some(9000));
        assert_eq!(
            request.get("_i").and_then(Value::as_str),
            Some("_systemInfo")
        );
        assert_eq!(request.get("_t").and_then(Value::as_u64), Some(2));

        peer.send(
            FrameType::EOpack,
            &response_to(&request, opack! { "ok" => true }),
        )
        .await;
        peer
    });

    let response = protocol
        .send_command("_systemInfo", opack! {})
        .await
        .expect("the device answered");
    assert_eq!(response.xid, Some(9000));
    assert_eq!(
        response.content.get("ok").and_then(Value::as_bool),
        Some(true)
    );

    device.await.expect("the device task must finish");
}

/// Successive exchanges take successive XIDs, and every outbound frame carries one — including
/// events, which upstream's `send_opack` stamps even though nothing correlates them
/// (`protocol.py:181-183`).
#[tokio::test]
async fn xids_increment_and_every_outbound_frame_carries_one() {
    let (mut protocol, _events, mut peer) = pair(1).await;

    let device = tokio::spawn(async move {
        let mut seen = Vec::new();
        for _ in 0..2u8 {
            let (_, request) = peer.recv().await;
            seen.push(request.get("_x").and_then(Value::as_u64));
            peer.send(FrameType::EOpack, &response_to(&request, opack! {}))
                .await;
        }
        let (_, event) = peer.recv().await;
        seen.push(event.get("_x").and_then(Value::as_u64));
        assert_eq!(event.get("_t").and_then(Value::as_u64), Some(1));
        seen
    });

    protocol
        .send_command("_first", opack! {})
        .await
        .expect("first");
    protocol
        .send_command("_second", opack! {})
        .await
        .expect("second");
    protocol
        .send_event("_interest", opack! {})
        .await
        .expect("event");

    assert_eq!(
        device.await.expect("the device task must finish"),
        [Some(1), Some(2), Some(3)]
    );
}

/// A response for an XID nobody is waiting for is kept, and resolves the exchange that asks for it
/// later — where pyatv drops it with "No receiver for XID" (`protocol.py:231-232`).
/// A response for an XID this side never issued is dropped, not kept.
///
/// The stash used to accept any XID at all and never evict, so a peer — reachable before
/// pair-verify, since `PS_`/`PV_` frames are decoded in the clear — could grow it without limit
/// simply by answering XIDs nobody had asked about. Now only an issued-and-unresolved XID is kept.
#[tokio::test]
async fn a_response_for_an_xid_this_side_never_issued_is_dropped() {
    let (mut protocol, _events, mut peer) = pair(50).await;

    let device = tokio::spawn(async move {
        let (_, request) = peer.recv().await;

        // Three answers for XIDs the client has not handed out, then the real one.
        for xid in [900u64, 901, 902] {
            peer.send(
                FrameType::EOpack,
                &opack! {
                    "_i" => "_ghost",
                    "_x" => xid,
                    "_t" => MessageType::Response.code(),
                    "_c" => opack! {},
                },
            )
            .await;
        }
        peer.send(
            FrameType::EOpack,
            &response_to(&request, opack! { "which" => "real" }),
        )
        .await;
        peer
    });

    let response = protocol
        .send_command("_first", opack! {})
        .await
        .expect("the real answer must still arrive");
    assert_eq!(
        response.content.get("which").and_then(Value::as_str),
        Some("real")
    );
    assert!(
        protocol.stash.is_empty(),
        "unissued XIDs must be dropped, not stashed: {:?}",
        protocol.stash.keys().collect::<Vec<_>>()
    );

    device.await.expect("the device task must finish");
}

/// A response that arrives after its exchange timed out is dropped rather than accumulating.
///
/// Upstream leaks here too — a cancelled wait leaves its queue entry behind
/// (`docs/research/companion-port-spec.md` §12 finding 12) — and this port used to leak the same
/// way from the other side: the timed-out XID stayed correlatable forever, so every slow device
/// answer added a permanent map entry.
#[tokio::test]
async fn a_late_response_after_a_timeout_does_not_accumulate() {
    let (mut protocol, _events, mut peer) = pair(60).await;
    protocol.set_timeout(Duration::from_millis(50));

    let (request_sent, request) = tokio::sync::oneshot::channel();
    let device = tokio::spawn(async move {
        let (_, request) = peer.recv().await;
        let _ = request_sent.send(request);
        peer
    });

    let error = protocol
        .send_command("_slow", opack! {})
        .await
        .expect_err("a silent device must time out");
    assert!(matches!(error, Error::Timeout { .. }), "got {error}");
    assert!(protocol.outstanding.is_empty(), "the XID must be released");

    // The device finally answers, long after the caller gave up.
    let request = request.await.expect("the device recorded the request");
    let mut peer = device.await.expect("the device task must finish");
    peer.send(
        FrameType::EOpack,
        &response_to(&request, opack! { "which" => "late" }),
    )
    .await;

    protocol.poll_once().await.expect("the frame must be read");
    assert!(
        protocol.stash.is_empty(),
        "a late answer to a dead exchange must be dropped"
    );
}

/// Events arriving mid-exchange go to the channel and do not disturb the correlation.
#[tokio::test]
async fn events_are_delivered_without_interrupting_an_exchange() {
    let (mut protocol, mut events, mut peer) = pair(7).await;

    let device = tokio::spawn(async move {
        let (_, request) = peer.recv().await;
        peer.send(
            FrameType::EOpack,
            &opack! {
                "_i" => "_iMC",
                "_x" => 999u64,
                "_t" => MessageType::Event.code(),
                "_c" => opack! { "_mcF" => 3u64 },
            },
        )
        .await;
        peer.send(FrameType::EOpack, &response_to(&request, opack! {}))
            .await;
        peer
    });

    protocol
        .send_command("_systemInfo", opack! {})
        .await
        .expect("the response arrived");

    let event = events.recv().await.expect("the event must be delivered");
    assert_eq!(event.name, "_iMC");
    assert_eq!(event.content.get("_mcF").and_then(Value::as_u64), Some(3));

    device.await.expect("the device task must finish");
}

/// `_em`'s presence fails the exchange, and the code and domain survive into the error — where
/// pyatv reads only `_em` (`protocol.py:173-174`).
#[tokio::test]
async fn an_error_response_fails_the_exchange_with_its_code_and_domain() {
    let (mut protocol, _events, mut peer) = pair(1).await;

    let device = tokio::spawn(async move {
        let (_, request) = peer.recv().await;
        peer.send(
            FrameType::EOpack,
            &opack! {
                "_i" => request.get("_i").and_then(Value::as_str).unwrap_or_default(),
                "_x" => request.get("_x").and_then(Value::as_u64).unwrap_or_default(),
                "_t" => MessageType::Response.code(),
                "_ec" => 58822u64,
                "_ed" => "RPErrorDomain",
                "_em" => "No request handler",
            },
        )
        .await;
        peer
    });

    let error = protocol
        .send_command("_nope", opack! {})
        .await
        .expect_err("an _em must fail the exchange");

    match error {
        Error::Rejected {
            command,
            reason,
            code,
            domain,
        } => {
            assert_eq!(command, "_nope");
            assert_eq!(reason, "No request handler");
            assert_eq!(code, Some(58822));
            assert_eq!(domain.as_deref(), Some("RPErrorDomain"));
        }
        other => panic!("expected a rejection, got {other:?}"),
    }

    device.await.expect("the device task must finish");
}

/// The one asymmetry in the handshake: a `PS_Start` is answered with `PS_Next`
/// (`protocol.py:132-140`).
#[tokio::test]
async fn an_auth_exchange_awaits_the_next_variant_of_the_start_frame() {
    let (mut protocol, _events, mut peer) = pair(1).await;

    let device = tokio::spawn(async move {
        let (frame_type, request) = peer.recv().await;
        assert_eq!(frame_type, FrameType::PsStart);
        // Upstream stamps an XID onto auth frames too, even though nothing correlates them.
        assert!(request.get("_x").is_some());
        assert_eq!(request.get("_pwTy").and_then(Value::as_u64), Some(1));

        peer.send(FrameType::PsNext, &opack! { "_pd" => vec![2u8, 1, 2] })
            .await;
        peer
    });

    let response = protocol
        .exchange_auth(
            FrameType::PsStart,
            opack! { "_pd" => vec![1u8], "_pwTy" => 1u64 },
        )
        .await
        .expect("the device answered with PS_Next");
    assert!(response.get("_pd").is_some());

    device.await.expect("the device task must finish");
}

/// A frame of a type this port never handles is logged and skipped, not treated as the answer.
#[tokio::test]
async fn unhandled_frame_types_are_skipped() {
    let (mut protocol, _events, mut peer) = pair(1).await;

    let device = tokio::spawn(async move {
        let (_, request) = peer.recv().await;
        peer.send(FrameType::NoOp, &opack! {}).await;
        peer.send(
            FrameType::EOpack,
            &response_to(&request, opack! { "done" => true }),
        )
        .await;
        peer
    });

    let response = protocol
        .send_command("_ping", opack! {})
        .await
        .expect("the response arrived");
    assert_eq!(
        response.content.get("done").and_then(Value::as_bool),
        Some(true)
    );

    device.await.expect("the device task must finish");
}

/// A device that never answers fails on the deadline rather than hanging forever.
#[tokio::test]
async fn a_silent_device_times_out() {
    let (mut protocol, _events, mut peer) = pair(1).await;
    protocol.set_timeout(Duration::from_millis(50));

    let device = tokio::spawn(async move {
        let _ = peer.recv().await;
        // Hold the socket open without answering.
        tokio::time::sleep(Duration::from_millis(500)).await;
        peer
    });

    let error = protocol
        .send_command("_systemInfo", opack! {})
        .await
        .expect_err("a silent device must time out");
    assert!(matches!(error, Error::Timeout { .. }), "got {error:?}");

    device.abort();
}

/// `start` mirrors upstream's raise-if-already-started guard (`protocol.py:96-97`).
#[tokio::test]
async fn starting_twice_is_refused() {
    let (mut protocol, _events, _peer) = pair(1).await;

    protocol
        .start(None)
        .await
        .expect("the first start is a no-op without credentials");
    assert!(!protocol.is_encrypted());
    assert!(matches!(
        protocol.start(None).await,
        Err(Error::NotReady(_))
    ));
}

/// A payload that is not a dict is refused before anything reaches the socket.
#[tokio::test]
async fn a_non_dict_payload_is_refused() {
    let (mut protocol, _events, _peer) = pair(1).await;

    let error = protocol
        .exchange_opack(FrameType::EOpack, Value::from("not a dict"))
        .await
        .expect_err("only dicts may be sent");
    assert!(matches!(error, Error::Envelope(_)), "got {error:?}");
}

/// The envelope a request produces is exactly upstream's, keys and order included.
#[test]
fn a_request_envelope_matches_upstreams_shape() {
    let value = Envelope::request("_touchStart", opack! { "_tFl" => 0u64 }).to_value();
    assert_eq!(value.get("_i").and_then(Value::as_str), Some("_touchStart"));
    assert_eq!(value.get("_t").and_then(Value::as_u64), Some(2));
    assert!(value.get("_c").is_some());
    assert!(value.get("_x").is_none(), "the protocol layer owns the XID");
}
