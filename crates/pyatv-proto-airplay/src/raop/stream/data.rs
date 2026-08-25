//! The pacing loop and the teardown that follows it.
//!
//! Split out of [`super`] for size; upstream keeps `_stream_data`, `_send_packet` and
//! `send_audio`'s `finally` block in the same `StreamClient` as everything else
//! (`stream_client.py:459-593`). The `impl` block continues its parent's, so these still see the
//! private fields — that is exactly why they live in a *child* module rather than a sibling.

use std::sync::atomic::Ordering;

use crate::Result;
use crate::audio::AudioSource;
use crate::raop::connection::with_connection;
use crate::raop::net::AudioSender;
use crate::raop::pacing::{SlowCounter, Statistics};
use crate::raop::packets::AudioPacketHeader;
use crate::raop::rtsp as raop_rtsp;
use crate::rtsp::FRAMES_PER_PACKET;

use super::StreamClient;

impl StreamClient {
    /// The pacing loop.
    ///
    /// `_stream_data` (`stream_client.py:476-551`).
    pub(super) async fn stream_data(
        &mut self,
        source: &mut AudioSource,
        audio: &AudioSender,
    ) -> Result<()> {
        let sample_rate = self.context.snapshot().audio.sample_rate;
        let mut stats = Statistics::new(sample_rate);
        let mut slow = SlowCounter::default();

        self.playing.store(true, Ordering::SeqCst);
        while self.playing.load(Ordering::SeqCst) {
            let current_seqno = self.context.snapshot().rtpseq.wrapping_sub(1);

            let sent = self
                .send_packet(source, audio, stats.total_frames() == 0)
                .await?;
            if sent == 0 {
                break;
            }
            stats.tick(sent);

            let compensation = stats.compensation_packets();
            if compensation > 0 {
                tracing::debug!(
                    packets = compensation,
                    frames_behind = stats.frames_behind(),
                    "compensating"
                );
                let mut exhausted = false;
                for _ in 0..compensation {
                    let sent = self.send_packet(source, audio, false).await?;
                    stats.tick(sent);
                    if sent == 0 {
                        exhausted = true;
                        break;
                    }
                }
                if exhausted {
                    break;
                }
            }

            if stats.interval_completed() {
                let (elapsed, frames) = stats.new_interval();
                tracing::debug!(
                    frames,
                    elapsed,
                    total = stats.total_frames(),
                    expected = stats.expected_frame_count(),
                    "interval"
                );
            }

            match stats.sleep_for() {
                Some(sleep) => {
                    slow.on_time();
                    tokio::time::sleep(sleep).await;
                }
                None if slow.late(current_seqno) => {
                    tracing::warn!(seqno = current_seqno, "too slow to keep up");
                }
                None => tracing::debug!(seqno = current_seqno, "too slow to keep up"),
            }
        }

        tracing::debug!(elapsed = ?stats.elapsed(), "audio finished sending");
        Ok(())
    }

    /// Build and send one packet, returning how many frames it carried.
    ///
    /// `_send_packet` (`stream_client.py:553-593`). Two distinct paddings live here: a short final
    /// chunk of real audio is zero-filled to a full packet exactly once, and once the source is
    /// exhausted entirely, whole packets of silence are sent until one latency's worth has gone
    /// out — which is what keeps the sync clock coherent through the tail of playback.
    pub(super) async fn send_packet(
        &mut self,
        source: &mut AudioSource,
        audio: &AudioSender,
        first: bool,
    ) -> Result<u32> {
        let (packet_size, frame_size, rtpseq, rtptime, ssrc, complete) = {
            let context = self.context.snapshot();
            let ssrc =
                with_connection(&self.connection, async |rtsp, _| Ok(rtsp.session_id())).await?;
            (
                context.packet_size(),
                context.frame_size(),
                context.rtpseq,
                context.rtptime(),
                ssrc,
                context.padding_complete(),
            )
        };

        if complete {
            return Ok(0);
        }

        let mut frames = source.read_frames(FRAMES_PER_PACKET as usize).to_vec();
        let padding = if frames.is_empty() {
            frames = vec![0u8; packet_size];
            true
        } else {
            if frames.len() != packet_size {
                frames.resize(packet_size, 0);
            }
            false
        };

        let sent_frames = u32::try_from(frames.len() / frame_size.max(1)).unwrap_or(0);
        let header = AudioPacketHeader::new(first, rtpseq, rtptime, ssrc);
        let packet = self.protocol.audio_packet(&header, &frames)?;

        audio.send(&packet).await?;
        if let Some(control) = self.control.as_ref() {
            control.remember(rtpseq, packet);
        }

        self.context.with(|context| {
            if padding {
                context.padding_sent += sent_frames;
            }
            context.advance(sent_frames);
        });

        Ok(sent_frames)
    }

    /// `send_audio`'s `finally` block.
    ///
    /// `TEARDOWN`, then the backlog, the protocol and every socket (`stream_client.py:459-470`).
    /// Upstream's own comment marks this as misplaced — the connection ought to be reusable for a
    /// second file — and it is reproduced here rather than improved, because the facade above
    /// depends on a session that has streamed once being finished.
    pub(super) async fn finish(&mut self) -> Result<()> {
        self.playing.store(false, Ordering::SeqCst);

        if let Some(control) = self.control.as_mut() {
            control.stop_sync();
            control.clear_backlog();
        }

        let session = self.context.snapshot().rtsp_session;
        let teardown = with_connection(&self.connection, async |rtsp, http| {
            raop_rtsp::teardown(rtsp, http, session).await
        })
        .await;

        self.protocol.teardown();
        self.control = None;
        self.timing = None;

        teardown
    }
}
