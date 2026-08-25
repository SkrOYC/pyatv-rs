//! The AirPlay-tunnel transport, driven by an in-memory byte channel.
//!
//! The point of these tests is the claim the whole crate is built on: the protocol state machine,
//! the facades and the player-state model are transport-agnostic, and the tunnel differs from a
//! direct socket in exactly two observable ways — no MRP-level encryption, and no MRP pair-verify
//! (`docs/research/airplay-control-mrp-tunnel-port-spec.md` §7.1,
//! `pyatv/protocols/airplay/mrp_connection.py`).
//!
//! There is no AirPlay code here and no dependency on `pyatv-proto-airplay`: the seam is
//! [`ByteChannel`], which carries the decoded `data` blob and nothing else. The umbrella crate
//! implements it over the real data-stream channel.

use pyatv_proto_mrp::test_support as support;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use pyatv_core::consts::DeviceState;
use pyatv_core::{BaseService, Protocol};
use pyatv_proto_mrp::messages;
use pyatv_proto_mrp::protobuf::{extensions, protocol_message::Type};
use pyatv_proto_mrp::transport::tunnel::{
    ByteChannel, TunnelTransport, UNPREFIXED_MESSAGE_MARKER, decode_payload, encode_payload,
};
use pyatv_proto_mrp::{MrpMessage, MrpSetupOptions, MrpTransport, TransportEncryption, setup};

use support::fake_channels::LoopbackChannel;
use support::fake_messages as build;
use support::fake_state::{PLAYER_IDENTIFIER, PlayingState};

/// How long a poll waits before giving up.
const DEADLINE: Duration = Duration::from_secs(5);

/// A device standing in for the far end of an AirPlay data-stream channel.
///
/// It answers only what bring-up needs, which is all the tunnel path can be asked to do: everything
/// richer is already covered against the real socket in `mrp_functional.rs`.
async fn serve(channel: LoopbackChannel) {
    while let Ok(Some(blob)) = channel.recv().await {
        let Ok(messages) = decode_payload(&blob) else {
            return;
        };

        for raw in messages {
            let Ok(message) = MrpMessage::decode(raw) else {
                return;
            };
            let identifier = message.identifier().map(str::to_owned);

            let reply = match message.message_type_enum() {
                Some(Type::DeviceInfoMessage) => Some(build::device_info(
                    true,
                    None,
                    &[],
                    identifier.as_deref(),
                    false,
                )),
                Some(Type::ClientUpdatesConfigMessage) => {
                    // Answer, then push what is playing, exactly as the socket fixture does.
                    let ack = identifier
                        .as_deref()
                        .map(|it| build::bare(Type::UnknownMessage, Some(it)));
                    if let Some(ack) = ack {
                        let _ = channel.send(encode_payload(ack.bytes())).await;
                    }

                    let state = PlayingState {
                        playback_state: Some(
                            pyatv_proto_mrp::protobuf::playback_state::Enum::Playing,
                        ),
                        playback_rate: Some(1.0),
                        title: Some("tunnelled".to_owned()),
                        total_time: Some(60.0),
                        position: Some(5.0),
                        media_type: Some(build::VIDEO),
                        ..PlayingState::default()
                    };
                    let _ = channel
                        .send(encode_payload(
                            build::set_state(&state, PLAYER_IDENTIFIER).bytes(),
                        ))
                        .await;
                    Some(build::set_now_playing_client(Some(PLAYER_IDENTIFIER)))
                }
                Some(Type::GetKeyboardSessionMessage) => identifier.as_deref().map(build::keyboard),
                Some(Type::GenericMessage) => identifier
                    .as_deref()
                    .map(|it| build::bare(Type::UnknownMessage, Some(it))),
                Some(Type::CryptoPairingMessage) => {
                    panic!("a tunnel must never run MRP pair-verify")
                }
                _ => None,
            };

            if let Some(reply) = reply
                && channel.send(encode_payload(reply.bytes())).await.is_err()
            {
                return;
            }
        }
    }
}

/// The transport reports that encryption belongs to the layer below and refuses to install keys.
#[tokio::test]
async fn the_tunnel_delegates_encryption_and_refuses_mrp_keys() {
    let (client, _device) = LoopbackChannel::pair();
    let transport = TunnelTransport::new(client);

    assert_eq!(
        transport.encryption(),
        TransportEncryption::DelegatedToTunnel
    );
    assert!(
        !transport.encryption().needs_pair_verify(),
        "the tunnel must not pair-verify at the MRP layer"
    );
    assert!(!transport.is_encrypted(), "not at the MRP layer");
    assert!(
        transport.connected(),
        "`AirPlayMrpConnection.connected` is hardcoded true"
    );
    assert!(
        transport.enable_encryption([0x11; 32], [0x22; 32]).is_err(),
        "installing MRP keys on an already-encrypted channel must be refused"
    );
}

/// Outbound messages are variant-length-prefixed, which is what `encode_protobufs` does.
#[tokio::test]
async fn outbound_messages_are_length_prefixed() {
    let (client, device) = LoopbackChannel::pair();
    let transport = TunnelTransport::new(client);

    let message = messages::set_connection_state().expect("building the message");
    transport
        .send(&message)
        .await
        .expect("sending must succeed");

    let blob = device
        .recv()
        .await
        .expect("the peer must receive something")
        .expect("the channel must not be closed");
    assert_eq!(
        blob.as_ref(),
        encode_payload(message.bytes()).as_ref(),
        "the blob is exactly one length-prefixed message"
    );
    assert_eq!(
        usize::from(blob[0]),
        message.bytes().len(),
        "a short message's prefix is one byte"
    );
}

/// One `data` blob can carry several messages, and each is delivered separately.
#[tokio::test]
async fn a_batched_blob_yields_one_message_per_recv() {
    let (client, device) = LoopbackChannel::pair();
    let transport = TunnelTransport::new(client);

    let first = messages::set_connection_state().expect("building the message");
    let second = messages::get_keyboard_session();

    let mut blob = Vec::new();
    blob.extend_from_slice(&encode_payload(first.bytes()));
    blob.extend_from_slice(&encode_payload(second.bytes()));
    device
        .send(Bytes::from(blob))
        .await
        .expect("sending must succeed");

    let one = transport
        .recv()
        .await
        .expect("recv must succeed")
        .expect("a message must arrive");
    let two = transport
        .recv()
        .await
        .expect("recv must succeed")
        .expect("the second message must arrive without another blob");

    assert_eq!(one.message_type(), first.message_type());
    assert_eq!(two.message_type(), second.message_type());
}

/// The `0x08` heuristic: a blob that starts with the `type` tag has no length prefix at all.
#[tokio::test]
async fn an_unprefixed_blob_is_still_decoded() {
    let (client, device) = LoopbackChannel::pair();
    let transport = TunnelTransport::new(client);

    let message = messages::set_connection_state().expect("building the message");
    assert_eq!(
        message.bytes()[0],
        UNPREFIXED_MESSAGE_MARKER,
        "every ProtocolMessage starts with the `type` tag, which is what makes the heuristic work"
    );

    device
        .send(message.bytes().clone())
        .await
        .expect("sending must succeed");

    let received = transport
        .recv()
        .await
        .expect("recv must succeed")
        .expect("a message must arrive");
    assert_eq!(received.bytes(), message.bytes());
}

/// A closed channel is a clean end of stream, not an error.
#[tokio::test]
async fn a_closed_channel_ends_the_stream() {
    let (client, device) = LoopbackChannel::pair();
    let transport = TunnelTransport::new(client);
    drop(device);

    assert!(
        transport.recv().await.expect("recv must succeed").is_none(),
        "a dropped peer is a clean close"
    );
}

/// The whole stack — bring-up, player state, facades — over the tunnel, with no MRP crypto.
#[tokio::test]
async fn the_full_stack_runs_over_the_tunnel() {
    let (client, device) = LoopbackChannel::pair();
    tokio::spawn(serve(device));

    // A service with credentials, to prove they are ignored rather than merely absent: upstream
    // registers a dummy `MutableService(None, Protocol.MRP, ...)` with none at all
    // (`pyatv/protocols/airplay/__init__.py:241-244`), and the fixture panics if a
    // `CRYPTO_PAIRING_MESSAGE` ever arrives.
    let mut service = BaseService::new(Protocol::Mrp, 7000);
    service.credentials = Some(pyatv_pairing::server::CLIENT_CREDENTIALS.to_owned());

    let data = setup(
        Arc::new(TunnelTransport::new(client)),
        MrpSetupOptions::new(service),
    )
    .await
    .expect("setup over the tunnel must succeed");

    assert_eq!(data.protocol, Some(Protocol::Mrp));

    let metadata = data.metadata.as_ref().expect("Metadata is registered");
    let deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        let snapshot = metadata.playing().await.expect("playing() must not fail");
        if snapshot.title.as_deref() == Some("tunnelled") {
            assert_eq!(snapshot.device_state, DeviceState::Playing);
            assert_eq!(snapshot.total_time, Some(60));
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for the tunnelled now-playing state; got {snapshot:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    data.handle
        .as_ref()
        .expect("a teardown handle is registered")
        .close()
        .await
        .expect("closing must succeed");
}

/// A `DEVICE_INFO_MESSAGE` round trip proves the extension survives the tunnel's framing.
#[tokio::test]
async fn the_device_info_extension_survives_the_tunnel() {
    let (client, device) = LoopbackChannel::pair();
    tokio::spawn(serve(device));

    let transport = TunnelTransport::new(client);
    let message = messages::device_information(
        &pyatv_core::storage::InfoSettings::default(),
        "89B3D2B7-9D62-4A5C-9E48-2C4F2A0B1D33",
        false,
    )
    .expect("building DEVICE_INFO_MESSAGE");
    transport
        .send(&message)
        .await
        .expect("sending must succeed");

    let response = transport
        .recv()
        .await
        .expect("recv must succeed")
        .expect("the device must answer");
    let inner = response
        .inner(&extensions::DEVICE_INFO_MESSAGE)
        .expect("the extension must decode");
    assert_eq!(inner.name, support::fake_state::DEVICE_NAME);
}
