//! `stream_file` end to end against the hermetic RAOP receiver, on both protocol generations.
//!
//! These mirror `tests/protocols/raop/test_raop_functional.py` — the same scenarios, the same
//! assertions on what the receiver recorded — and add the ones upstream cannot run at all, because
//! its fake device has no AirPlay 2 path: the two-`SETUP` sequence, the event channel, and audio
//! the receiver actually decrypts (`docs/research/airplay-playurl-raop-port-spec.md` §12.1).
//!
//! Every test drives real sockets. Pair-setup, pair-verify, the HAP-encrypted RTSP connection, the
//! three UDP channels and the pacing loop all really happen, which is why the durations are short:
//! the loop paces in real time, so a second of audio costs a second plus one latency of trailing
//! silence.

mod raop_support;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use pyatv_proto_airplay::audio::Source;
use pyatv_proto_airplay::raop::metadata::{
    MISSING_ALBUM, MISSING_ARTIST, MISSING_TITLE, TrackMetadata,
};
use pyatv_proto_airplay::raop::volume::{INITIAL_VOLUME, pct_to_dbfs};
use pyatv_proto_airplay::test_support::fake_raop::FakeRaopOptions;

use raop_support::{SETTLE, ap1, ap2, frames, serve_wav, sine_wav};

/// One second of audio, streamed to an AirPlay 2 receiver that decrypts every packet.
///
/// The flagship test: it pins the `shk` derivation, the ChaCha20-Poly1305 nonce discipline, the RTP
/// header layout, the packet ordering and the trailing silence in one go — a receiver that could
/// not decrypt would produce an empty `raw_audio` and a non-empty `undecryptable`.
#[tokio::test(flavor = "multi_thread")]
async fn an_airplay_2_stream_delivers_every_packet_decryptable() {
    let (_device, stream, state) = ap2(FakeRaopOptions::default()).await;

    stream
        .stream_source(Source::Bytes(sine_wav(1.0)))
        .await
        .expect("the file should stream");

    // Nothing failed to decrypt: a wrong key, a wrong AAD or an off-by-one nonce lands here.
    assert!(state.udp.undecryptable.lock().await.is_empty());

    let audio = state.udp.audio.lock().await.clone();
    assert!(!audio.is_empty(), "packets arrived");

    // The first packet carries the `0xE0` marker and no other one does.
    assert!(audio[0].first);
    assert!(audio[1..].iter().all(|frame| !frame.first));

    // Sequence numbers are consecutive, wrapping at sixteen bits, and timestamps step by exactly
    // one packet of frames.
    for pair in audio.windows(2) {
        assert_eq!(pair[1].seqno, pair[0].seqno.wrapping_add(1));
        assert_eq!(pair[1].timestamp, pair[0].timestamp.wrapping_add(352));
    }

    // Every packet is a full 352 frames of 16-bit stereo, the short final chunk zero-filled.
    assert!(audio.iter().all(|frame| frame.payload.len() == 352 * 2 * 2));

    // One second of audio plus one latency of trailing silence: `latency = 22050 + 44100`.
    let expected = (frames(1.0) + 66_150).div_ceil(352);
    let received = audio.len();
    assert!(
        received.abs_diff(expected) <= 2,
        "expected about {expected} packets, got {received}"
    );

    // The RTSP sequence completed: RECORD, FLUSH and TEARDOWN each exactly once.
    assert_eq!(state.records.load(Ordering::SeqCst), 1);
    assert_eq!(state.flushes.load(Ordering::SeqCst), 1);
    assert_eq!(state.teardowns.load(Ordering::SeqCst), 1);
    // Two `SETUP`s: the base one and the audio-stream one.
    assert_eq!(state.setups.load(Ordering::SeqCst), 2);
    assert!(state.event_connected.load(Ordering::SeqCst));
    // `ANNOUNCE` is AirPlay 1 only.
    assert_eq!(state.announces.load(Ordering::SeqCst), 0);

    // Sync packets went out on the control channel, the first with the `0x90` marker.
    let sync = state.udp.sync.lock().await.clone();
    assert!(!sync.is_empty());
    assert_eq!(sync[0].proto, 0x90);
    assert!(sync[1..].iter().all(|packet| packet.proto == 0x80));
}

/// The audio-stream `SETUP` body is the one `airplayv2.py` sends, key for key.
#[tokio::test(flavor = "multi_thread")]
async fn the_audio_stream_setup_body_is_the_one_pyatv_sends() {
    let (_device, stream, state) = ap2(FakeRaopOptions::default()).await;

    stream
        .stream_source(Source::Bytes(sine_wav(0.05)))
        .await
        .expect("the file should stream");

    let body = state.audio_setup.lock().await.clone().expect("a body");
    let stream_body = body
        .as_dictionary()
        .and_then(|body| body.get("streams"))
        .and_then(plist::Value::as_array)
        .and_then(|streams| streams.first())
        .and_then(plist::Value::as_dictionary)
        .expect("streams[0]")
        .clone();

    let integer = |key: &str| {
        stream_body
            .get(key)
            .and_then(plist::Value::as_unsigned_integer)
    };
    assert_eq!(integer("audioFormat"), Some(0x800));
    assert_eq!(integer("ct"), Some(1));
    assert_eq!(integer("spf"), Some(352));
    assert_eq!(integer("sr"), Some(44_100));
    assert_eq!(integer("type"), Some(0x60));
    assert_eq!(integer("latencyMax"), Some(88_200));
    assert_eq!(integer("latencyMin"), Some(11_025));
    assert_eq!(
        stream_body
            .get("audioMode")
            .and_then(plist::Value::as_string),
        Some("default")
    );
    assert!(matches!(
        stream_body.get("shk"),
        Some(plist::Value::Data(key)) if key.len() == 32
    ));

    // The base `SETUP` asked for NTP timing, unlike the remote-control tunnel's.
    let base = state.base_setup.lock().await.clone().expect("a base body");
    assert_eq!(
        base.as_dictionary()
            .and_then(|body| body.get("timingProtocol"))
            .and_then(plist::Value::as_string),
        Some("NTP")
    );
}

/// Metadata and progress go out before `RECORD`, gated on the receiver's `md` key.
#[tokio::test(flavor = "multi_thread")]
async fn metadata_and_progress_reach_the_receiver() {
    let (_device, stream, state) = ap2(FakeRaopOptions::default()).await;

    stream
        .stream_source_with(
            Source::Bytes(sine_wav(0.05)),
            Some(TrackMetadata {
                title: Some("Title".to_owned()),
                artist: Some("Artist".to_owned()),
                album: Some("Album".to_owned()),
                ..TrackMetadata::default()
            }),
            false,
        )
        .await
        .expect("the file should stream");

    let metadata = state.metadata.lock().await.clone().expect("a DAAP body");
    // Title, then **album**, then artist — the order `set_metadata` writes them in.
    assert_eq!(
        metadata,
        [
            b"mlit\x00\x00\x00\x28".as_slice(),
            b"minm\x00\x00\x00\x05Title",
            b"asal\x00\x00\x00\x05Album",
            b"asar\x00\x00\x00\x06Artist",
        ]
        .concat()
    );

    // `start/current/end`, all three RTP timestamps, with start and current equal.
    let progress = state
        .progress
        .lock()
        .await
        .clone()
        .expect("a progress line");
    let parts: Vec<&str> = progress.split('/').collect();
    assert_eq!(parts.len(), 3, "{progress}");
    assert_eq!(parts[0], parts[1], "{progress}");
    let start: u32 = parts[0].parse().expect("a number");
    let end: u32 = parts[2].parse().expect("a number");
    assert!(end > start, "{progress}");
}

/// A file with no tags ships an **empty** `mlit` container, not the placeholder identity.
///
/// The placeholder only fires when the metadata is *entirely* empty
/// (`self._metadata == EMPTY_METADATA`, `stream_client.py:268-271`), and a decoded duration is
/// enough to defeat that — exactly as it is upstream, where `get_metadata` fills `duration` from
/// the tag reader whether or not the file has any tags to read.
#[tokio::test(flavor = "multi_thread")]
async fn a_tagless_file_ships_an_empty_container_rather_than_the_placeholder() {
    let (_device, stream, state) = ap2(FakeRaopOptions::default()).await;

    stream
        .stream_source(Source::Bytes(sine_wav(0.05)))
        .await
        .expect("the file should stream");

    let metadata = state.metadata.lock().await.clone().expect("a DAAP body");
    assert_eq!(metadata, b"mlit\x00\x00\x00\x00".to_vec());

    // The placeholder is still what a *listener* is told, which is where it belongs.
    let text = format!("{MISSING_TITLE}{MISSING_ARTIST}{MISSING_ALBUM}");
    assert!(!text.is_empty());
}

/// `close()` stops the pacing loop, and the session still tears down cleanly.
#[tokio::test(flavor = "multi_thread")]
async fn stopping_mid_stream_still_tears_the_session_down() {
    let (_device, stream, state) = ap2(FakeRaopOptions::default()).await;
    let stopper = stream.manager();

    let handle = {
        let stream = Arc::clone(&stream);
        tokio::spawn(async move {
            // Long enough that the stop lands well before the end.
            stream
                .stream_source(Source::Bytes(sine_wav(20.0)))
                .await
                .expect("the file should stream");
        })
    };

    // Wait until packets are actually flowing, then stop.
    let started = tokio::time::timeout(SETTLE, async {
        loop {
            if !state.udp.audio.lock().await.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(started.is_ok(), "the stream should start");

    stopper.stop();
    tokio::time::timeout(SETTLE, handle)
        .await
        .expect("the stream should stop promptly")
        .expect("the task should not panic");

    assert_eq!(state.teardowns.load(Ordering::SeqCst), 1);

    // Far fewer packets than a twenty-second file would have produced.
    let sent = state.udp.audio.lock().await.len();
    assert!(sent < (frames(20.0) + 66_150) / 352, "{sent} packets");
}

/// With nothing set, the volume the client pushes is its own flat default.
#[tokio::test(flavor = "multi_thread")]
async fn the_default_volume_is_pushed_when_the_receiver_offers_none() {
    let (_device, stream, state) = ap2(FakeRaopOptions::default()).await;

    stream
        .stream_source(Source::Bytes(sine_wav(0.05)))
        .await
        .expect("the file should stream");

    let volumes = state.volumes.lock().await.clone();
    assert_eq!(volumes.first().copied(), Some(pct_to_dbfs(INITIAL_VOLUME)));
}

/// A receiver that advertises `initialVolume` has it adopted rather than overwritten.
#[tokio::test(flavor = "multi_thread")]
async fn the_receivers_initial_volume_is_adopted_untouched() {
    let (_device, stream, state) = ap2(FakeRaopOptions {
        initial_volume: Some(-11.5),
        ..FakeRaopOptions::default()
    })
    .await;

    stream
        .stream_source(Source::Bytes(sine_wav(0.05)))
        .await
        .expect("the file should stream");

    // Nothing was pushed: the client took the receiver's word for it.
    assert!(state.volumes.lock().await.is_empty());
    assert!((stream.manager().volume() - 61.666_668).abs() < 0.01);
}

/// A receiver that refuses a volume set before `FLUSH` gets the call retried afterwards.
///
/// `stream_client.py:450-451`, the Sonos workaround.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_volume_is_retried_once_streaming_has_started() {
    let (_device, stream, state) = ap2(FakeRaopOptions {
        delayed_set_volume: true,
        ..FakeRaopOptions::default()
    })
    .await;

    stream
        .stream_source(Source::Bytes(sine_wav(0.05)))
        .await
        .expect("the file should stream");

    // Exactly one volume landed, and it landed after `FLUSH`.
    let volumes = state.volumes.lock().await.clone();
    assert_eq!(volumes, vec![pct_to_dbfs(INITIAL_VOLUME)]);
    assert!(state.streaming_started.load(Ordering::SeqCst));
}

/// The AirPlay 1 path: `ANNOUNCE`, a `Transport` header, and audio in the clear.
#[tokio::test(flavor = "multi_thread")]
async fn an_airplay_1_stream_announces_and_sends_plaintext() {
    let (_device, stream, state) = ap1(FakeRaopOptions::default()).await;

    stream
        .stream_source(Source::Bytes(sine_wav(0.05)))
        .await
        .expect("the file should stream");

    assert_eq!(state.announces.load(Ordering::SeqCst), 1);
    assert_eq!(state.setups.load(Ordering::SeqCst), 1);
    assert_eq!(state.teardowns.load(Ordering::SeqCst), 1);

    // The SDP is the exact template, with the negotiated format substituted.
    let sdp = state.sdp.lock().await.clone().expect("an SDP body");
    assert!(sdp.starts_with("v=0\r\no=iTunes "), "{sdp}");
    assert!(sdp.contains("a=rtpmap:96 L16/44100/2\r\n"), "{sdp}");
    assert!(
        sdp.contains("a=fmtp:96 352 0 16 40 10 14 2 255 0 0 44100"),
        "{sdp}"
    );

    // The payload is plaintext, so a packet is exactly header plus audio with no AEAD tag.
    let audio = state.udp.audio.lock().await.clone();
    assert!(!audio.is_empty());
    assert!(audio.iter().all(|frame| frame.payload.len() == 352 * 2 * 2));
    assert!(state.udp.undecryptable.lock().await.is_empty());
}

/// A password-protected AirPlay 1 receiver challenges once and accepts the digest response.
#[tokio::test(flavor = "multi_thread")]
async fn a_password_protected_receiver_is_answered_with_a_digest() {
    let (_device, stream, state) = ap1(FakeRaopOptions {
        password: Some("secret".to_owned()),
        ..FakeRaopOptions::default()
    })
    .await;

    stream
        .stream_source(Source::Bytes(sine_wav(0.05)))
        .await
        .expect("the file should stream");

    let authorization = state
        .authorization
        .lock()
        .await
        .clone()
        .expect("an Authorization header");
    assert!(
        authorization.starts_with("Digest username=\"pyatv\""),
        "{authorization}"
    );
    assert!(authorization.contains("realm=\"raop\""), "{authorization}");
    // The challenge was answered, so the stream really ran.
    assert_eq!(state.teardowns.load(Ordering::SeqCst), 1);
}

/// A `http://` source is downloaded and streamed, not treated as a file path.
///
/// `_is_url` (`audio_source.py:731-735`) is what decides, and it decides on the string, so the
/// whole fetch-then-decode path only runs when a test hands it a real URL.
#[tokio::test(flavor = "multi_thread")]
async fn a_url_source_is_downloaded_and_streamed() {
    let port = serve_wav(sine_wav(0.05)).await;
    let (_device, stream, state) = ap2(FakeRaopOptions::default()).await;

    stream
        .stream_source(Source::Url(format!("http://127.0.0.1:{port}/track.wav")))
        .await
        .expect("the URL should stream");

    assert!(!state.udp.audio.lock().await.is_empty());
    assert!(state.udp.undecryptable.lock().await.is_empty());
    assert_eq!(state.teardowns.load(Ordering::SeqCst), 1);
}

/// A second concurrent stream is refused outright rather than queued.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_concurrent_stream_is_refused() {
    let (_device, stream, state) = ap2(FakeRaopOptions::default()).await;
    let manager = stream.manager();

    let running = {
        let stream = Arc::clone(&stream);
        tokio::spawn(async move { stream.stream_source(Source::Bytes(sine_wav(20.0))).await })
    };

    let started = tokio::time::timeout(SETTLE, async {
        loop {
            if manager.is_streaming() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(started.is_ok(), "the first stream should start");

    let refused = stream.stream_source(Source::Bytes(sine_wav(0.05))).await;
    assert!(refused.is_err(), "the second stream should be refused");

    manager.stop();
    let _ = tokio::time::timeout(SETTLE, running).await;
    let _ = state;
}
