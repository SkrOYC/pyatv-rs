//! The per-session state every RAOP layer reads and writes.
//!
//! Port of `StreamContext` (`pyatv/protocols/raop/protocols/__init__.py:17-73`). One value per
//! streaming session, shared between the RTSP verbs, the pacing loop and the control channel's
//! sync task — which is why the sync packets stay coherent with what the audio socket has actually
//! sent.
//!
//! `event_port` is not reproduced: upstream declares and initialises it and then never reads or
//! writes it again anywhere in the RAOP package (`airplay-playurl-raop-port-spec.md` §14.1).

use std::sync::{Arc, Mutex};

use crate::raop::timing;
use crate::rtsp::FRAMES_PER_PACKET;

use super::AudioProperties;

/// Frames of latency the sender runs ahead of real time.
///
/// `latency = 22050 + sample_rate` (`protocols/__init__.py:28,51`) — half a second plus one full
/// second at the negotiated rate, so 66150 frames at 44100 Hz. It is also how much trailing
/// silence is sent after the real audio runs out, so the sync clock does not jump when playback
/// ends.
#[must_use]
pub const fn latency_for(sample_rate: u32) -> u32 {
    22_050 + sample_rate
}

/// One RAOP session's state.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamContext {
    /// Negotiated audio format, from the receiver's TXT record.
    pub audio: AudioProperties,
    /// `latency_for(sample_rate)`, recomputed on every [`StreamContext::reset`].
    pub latency: u32,
    /// RTP sequence number of the *next* packet. Randomised per session and wrapping at 16 bits.
    pub rtpseq: u16,
    /// RTP tick the session started at, `ntp2ts(ntp_now())`.
    pub start_ts: u64,
    /// RTP tick one past the last frame handed to the socket.
    pub head_ts: u64,
    /// Frames of trailing silence sent so far.
    pub padding_sent: u32,
    /// The receiver's audio port, `dataPort` on AirPlay 2 and `server_port` on AirPlay 1.
    pub server_port: u16,
    /// The receiver's control port, where sync packets go.
    pub control_port: u16,
    /// The receiver's timing port, if it named one.
    pub timing_port: u16,
    /// The `Session` header value the receiver assigned. Zero on the AirPlay 2 path, which never
    /// learns one — and which therefore really does send `Session: 0`.
    pub rtsp_session: u32,
    /// The RTP synchronisation source every audio packet header carries.
    ///
    /// `self.rtsp.session_id` (`stream_client.py:586`) — the *client's* random session identifier,
    /// drawn once by [`crate::rtsp::RtspSession::new`] and constant for the whole connection.
    /// Upstream reads it off the live `RtspSession` on every packet; this port copies it in here
    /// once at [`crate::raop::stream::StreamClient::initialize`] time instead, so the pacing loop
    /// never has to take the RTSP connection lock to build a header. Same value, no contention
    /// with the `/feedback` task or a concurrent volume change.
    pub ssrc: u32,
    /// Last known volume in dBFS, or `None` if nothing has set one.
    pub volume: Option<f32>,
}

impl Default for StreamContext {
    fn default() -> Self {
        let audio = AudioProperties::default();
        Self {
            latency: latency_for(audio.sample_rate),
            audio,
            rtpseq: 0,
            start_ts: 0,
            head_ts: 0,
            padding_sent: 0,
            server_port: 0,
            control_port: 0,
            timing_port: 0,
            rtsp_session: 0,
            ssrc: 0,
            volume: None,
        }
    }
}

impl StreamContext {
    /// Start a session's clocks.
    ///
    /// `StreamContext.reset` (`protocols/__init__.py:47-56`): a fresh random sequence number, the
    /// RTP clock anchored to the current NTP time, and the padding counter cleared. Called once at
    /// the start of `send_audio` and once again at teardown, so it runs twice per session.
    ///
    /// `volume`, `ssrc` and the negotiated ports deliberately survive: upstream's `reset` does not
    /// touch them either, which is what lets a volume set before streaming apply once it starts.
    pub fn reset(&mut self) {
        self.rtpseq = rand::random();
        self.start_ts = timing::ntp2ts(timing::ntp_now(), self.audio.sample_rate);
        self.head_ts = self.start_ts;
        self.latency = latency_for(self.audio.sample_rate);
        self.padding_sent = 0;
    }

    /// The RTP timestamp to stamp the next packet with.
    ///
    /// `head_ts - (start_ts - latency)` (`protocols/__init__.py:58-60`), i.e. the elapsed position
    /// shifted forward by the look-ahead. Truncated to 32 bits for the wire; upstream would raise
    /// `struct.error` after roughly twenty-seven hours of continuous streaming at 44100 Hz, and
    /// wrapping is the less surprising of the two failures.
    #[must_use]
    pub fn rtptime(&self) -> u32 {
        let elapsed = self.head_ts.saturating_sub(self.start_ts);
        #[allow(
            clippy::cast_possible_truncation,
            reason = "the wire field is 32 bits; see the doc comment for what wraps and when"
        )]
        (elapsed.wrapping_add(u64::from(self.latency)) as u32)
    }

    /// The same position without the look-ahead offset, which is what a sync packet carries.
    ///
    /// `context.rtptime - context.latency` (`stream_client.py:108`), algebraically just
    /// `head_ts - start_ts`.
    #[must_use]
    pub fn rtptime_without_latency(&self) -> u32 {
        self.rtptime().wrapping_sub(self.latency)
    }

    /// Playback position in seconds.
    ///
    /// `StreamContext.position` (`protocols/__init__.py:62-65`), which deliberately excludes the
    /// latency — the number a user sees is the true elapsed position, not the wire timestamp.
    #[must_use]
    pub fn position(&self) -> f64 {
        let elapsed = self.head_ts.saturating_sub(self.start_ts);
        #[allow(
            clippy::cast_precision_loss,
            reason = "milliseconds of playback are far below f64's exact-integer range"
        )]
        let millis = timing::ts2ms(elapsed, self.audio.sample_rate) as f64;
        millis / 1000.0
    }

    /// Bytes in one frame, i.e. one sample per channel.
    ///
    /// `frame_size` (`protocols/__init__.py:67-69`).
    #[must_use]
    pub fn frame_size(&self) -> usize {
        usize::from(self.audio.channels) * usize::from(self.audio.sample_size / 8)
    }

    /// Bytes in one full audio packet.
    ///
    /// `packet_size` (`protocols/__init__.py:71-73`): 1408 bytes for the usual 352 frames of
    /// 16-bit stereo.
    #[must_use]
    pub fn packet_size(&self) -> usize {
        FRAMES_PER_PACKET as usize * self.frame_size()
    }

    /// Advance the head clock and sequence number by one packet's worth of frames.
    ///
    /// `self.context.rtpseq = (self.context.rtpseq + 1) % (2**16)` and
    /// `self.context.head_ts += frames` (`stream_client.py:589-590`).
    pub fn advance(&mut self, frames: u32) {
        self.rtpseq = self.rtpseq.wrapping_add(1);
        self.head_ts += u64::from(frames);
    }

    /// Whether enough trailing silence has been sent to stop the stream.
    ///
    /// `if self.context.padding_sent >= self.context.latency: return 0` (`stream_client.py:555`).
    #[must_use]
    pub fn padding_complete(&self) -> bool {
        self.padding_sent >= self.latency
    }
}

/// A [`StreamContext`] shared between the pacing loop and the control channel's sync task.
///
/// A `std::sync::Mutex` rather than a `tokio::sync::Mutex` on purpose: every critical section here
/// is a handful of field reads with no `.await` inside, which is exactly the case the synchronous
/// primitive is for. Poisoning is recovered from rather than propagated — a panic in one of these
/// short sections cannot leave the context half-updated, because each one is a single assignment
/// or read.
#[derive(Debug, Clone, Default)]
pub struct SharedContext(Arc<Mutex<StreamContext>>);

impl SharedContext {
    /// Wrap an existing context.
    #[must_use]
    pub fn new(context: StreamContext) -> Self {
        Self(Arc::new(Mutex::new(context)))
    }

    /// Run `body` against the context.
    pub fn with<T>(&self, body: impl FnOnce(&mut StreamContext) -> T) -> T {
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        body(&mut guard)
    }

    /// A copy of the current state.
    #[must_use]
    pub fn snapshot(&self) -> StreamContext {
        self.with(|context| context.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::{SharedContext, StreamContext, latency_for};
    use crate::raop::AudioProperties;

    fn started() -> StreamContext {
        let mut context = StreamContext::default();
        context.reset();
        context
    }

    /// `22050 + sample_rate`, so 66150 at the usual rate.
    #[test]
    fn the_latency_is_half_a_second_plus_one_second_of_frames() {
        assert_eq!(latency_for(44_100), 66_150);
        assert_eq!(latency_for(48_000), 70_050);
    }

    /// 352 frames of 16-bit stereo is 1408 bytes.
    #[test]
    fn the_packet_size_follows_the_negotiated_format() {
        let context = StreamContext::default();

        assert_eq!(context.frame_size(), 4);
        assert_eq!(context.packet_size(), 1408);

        let mono = StreamContext {
            audio: AudioProperties {
                sample_rate: 44_100,
                channels: 1,
                sample_size: 16,
            },
            ..StreamContext::default()
        };
        assert_eq!(mono.frame_size(), 2);
        assert_eq!(mono.packet_size(), 704);
    }

    /// At the moment streaming starts, `head_ts == start_ts`, so the timestamp is exactly the
    /// latency and the sync packets' own field is zero.
    #[test]
    fn the_initial_timestamp_is_the_latency() {
        let context = started();

        assert_eq!(context.rtptime(), context.latency);
        assert_eq!(context.rtptime_without_latency(), 0);
        assert!((context.position() - 0.0).abs() < f64::EPSILON);
    }

    /// One second of frames advances the position by one second and the timestamp by 44100.
    #[test]
    fn advancing_moves_the_clock_and_the_sequence_number() {
        let mut context = started();
        let first_seqno = context.rtpseq;
        let latency = context.latency;

        for _ in 0..125 {
            context.advance(352);
        }

        assert_eq!(context.rtpseq, first_seqno.wrapping_add(125));
        assert_eq!(context.rtptime(), latency + 44_000);
        assert!((context.position() - 44_000.0 / 44_100.0).abs() < 0.001);
    }

    /// The sequence number wraps at sixteen bits rather than growing without bound.
    #[test]
    fn the_sequence_number_wraps_at_sixteen_bits() {
        let mut context = StreamContext {
            rtpseq: u16::MAX,
            ..StreamContext::default()
        };

        context.advance(352);

        assert_eq!(context.rtpseq, 0);
    }

    /// A reset re-anchors the clock but leaves the negotiated ports and volume alone.
    #[test]
    fn a_reset_keeps_the_ports_and_the_volume() {
        let mut context = StreamContext {
            server_port: 6000,
            control_port: 6001,
            rtsp_session: 1,
            ssrc: 0xDEAD_BEEF,
            volume: Some(-15.0),
            padding_sent: 100,
            ..StreamContext::default()
        };

        context.reset();

        assert_eq!(context.server_port, 6000);
        assert_eq!(context.control_port, 6001);
        assert_eq!(context.rtsp_session, 1);
        assert_eq!(context.ssrc, 0xDEAD_BEEF);
        assert_eq!(context.volume, Some(-15.0));
        assert_eq!(context.padding_sent, 0);
        assert!(context.start_ts > 0);
        assert_eq!(context.head_ts, context.start_ts);
    }

    /// Padding stops the stream once a full latency of silence has gone out.
    #[test]
    fn padding_completes_at_one_latency_of_silence() {
        let mut context = started();

        assert!(!context.padding_complete());
        context.padding_sent = context.latency - 1;
        assert!(!context.padding_complete());
        context.padding_sent = context.latency;
        assert!(context.padding_complete());
    }

    /// Both handles see the same state, which is what keeps the sync packets in step with the
    /// audio socket.
    #[test]
    fn a_shared_context_is_seen_by_every_clone() {
        let shared = SharedContext::new(started());
        let other = shared.clone();

        shared.with(|context| context.advance(352));

        assert_eq!(other.snapshot().rtptime(), shared.snapshot().rtptime());
        assert_eq!(other.snapshot().rtptime_without_latency(), 352);
    }
}
