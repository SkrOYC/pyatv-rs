//! The send-rate bookkeeping the streaming loop paces itself with.
//!
//! Port of `Statistics` (`stream_client.py:622-667`) and the three constants the loop around it
//! reads (`stream_client.py:41-47`). Split out from [`super::stream`] so the arithmetic can be
//! tested without a socket, a clock the test controls, or a receiver.

use std::time::Instant;

use crate::rtsp::FRAMES_PER_PACKET;

/// How many extra packets may be sent in one iteration to catch up.
///
/// `MAX_PACKETS_COMPENSATE = 3` (`stream_client.py:41`). A hard cap regardless of how far behind
/// the sender actually is, so a stalled thread cannot answer with a burst the receiver's buffer
/// cannot hold.
pub const MAX_PACKETS_COMPENSATE: u32 = 3;

/// How many consecutive late iterations pass before the log level is raised.
///
/// `SLOW_WARNING_THRESHOLD = 5` (`stream_client.py:47`). Purely observability: it never changes
/// packet timing and never drops a packet.
pub const SLOW_WARNING_THRESHOLD: u32 = 5;

/// Frames sent and time elapsed for one streaming session.
#[derive(Debug)]
pub struct Statistics {
    sample_rate: u32,
    start: Instant,
    interval_start: Instant,
    total_frames: u64,
    interval_frames: u64,
}

impl Statistics {
    /// Start counting from now.
    #[must_use]
    pub fn new(sample_rate: u32) -> Self {
        let now = Instant::now();
        Self {
            sample_rate,
            start: now,
            interval_start: now,
            total_frames: 0,
            interval_frames: 0,
        }
    }

    /// Frames sent so far.
    #[must_use]
    pub fn total_frames(&self) -> u64 {
        self.total_frames
    }

    /// How many frames *should* have been sent by now for the stream to be in real time.
    ///
    /// `int((monotonic_ns() - start_time_ns) / (10**9 / sample_rate))` (`stream_client.py:637`),
    /// recomputed on every read rather than cached.
    #[must_use]
    pub fn expected_frame_count(&self) -> u64 {
        let elapsed_nanos = self.start.elapsed().as_nanos();
        let nanos_per_frame = u128::from(1_000_000_000u64 / u64::from(self.sample_rate.max(1)));

        u64::try_from(elapsed_nanos / nanos_per_frame.max(1)).unwrap_or(u64::MAX)
    }

    /// How many frames behind real time the stream is. Zero when it is ahead.
    ///
    /// `frames_behind` (`stream_client.py:642`), saturated at zero: upstream's value goes negative
    /// while the sender is ahead of schedule, and the only place it is read compares it against
    /// [`FRAMES_PER_PACKET`], so the sign never matters.
    #[must_use]
    pub fn frames_behind(&self) -> u64 {
        self.expected_frame_count()
            .saturating_sub(self.total_frames)
    }

    /// How many catch-up packets to send now, if any.
    ///
    /// `if frames_behind >= FRAMES_PER_PACKET: max_packets = min(frames_behind / 352, 3)`
    /// (`stream_client.py:497-505`). A full packet's worth of lag is required before any
    /// compensation happens at all.
    #[must_use]
    pub fn compensation_packets(&self) -> u32 {
        let behind = self.frames_behind();
        if behind < u64::from(FRAMES_PER_PACKET) {
            return 0;
        }

        u32::try_from(behind / u64::from(FRAMES_PER_PACKET))
            .unwrap_or(MAX_PACKETS_COMPENSATE)
            .min(MAX_PACKETS_COMPENSATE)
    }

    /// Record frames handed to the socket.
    pub fn tick(&mut self, frames: u32) {
        self.total_frames += u64::from(frames);
        self.interval_frames += u64::from(frames);
    }

    /// Whether a second's worth of frames has been sent since the last interval boundary.
    ///
    /// `interval_completed` (`stream_client.py:650-651`).
    #[must_use]
    pub fn interval_completed(&self) -> bool {
        self.interval_frames >= u64::from(self.sample_rate)
    }

    /// Close the current interval, returning how long it took and how many frames it carried.
    pub fn new_interval(&mut self) -> (f64, u64) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.interval_start).as_secs_f64();
        self.interval_start = now;

        let frames = self.interval_frames;
        self.interval_frames = 0;
        (elapsed, frames)
    }

    /// How long to sleep before the next packet, or `None` when the sender is already late.
    ///
    /// `diff = total_frames / sample_rate - (monotonic() - initial_time)`
    /// (`stream_client.py:527-531`): "sleep until the wall clock catches up with how much audio we
    /// have conceptually sent". A non-positive difference means send immediately.
    #[must_use]
    pub fn sleep_for(&self) -> Option<std::time::Duration> {
        #[allow(
            clippy::cast_precision_loss,
            reason = "a frame count large enough to lose f64 precision is thousands of years"
        )]
        let audio_seconds = self.total_frames as f64 / f64::from(self.sample_rate.max(1));
        let elapsed = self.start.elapsed().as_secs_f64();
        let difference = audio_seconds - elapsed;

        (difference > 0.0).then(|| std::time::Duration::from_secs_f64(difference))
    }

    /// Total wall-clock time since the session started.
    #[must_use]
    pub fn elapsed(&self) -> std::time::Duration {
        self.start.elapsed()
    }
}

/// The consecutive-lateness counter that decides a log level.
///
/// `prev_slow_seqno`/`number_slow_seqno` (`stream_client.py:487-546`): the counter only advances
/// when this iteration's sequence number is exactly one past the previous late one, so a stream
/// that is late now and then never reaches the threshold — only a sustained shortfall does.
#[derive(Debug, Default)]
pub struct SlowCounter {
    previous: Option<u16>,
    consecutive: u32,
}

impl SlowCounter {
    /// Record an on-time iteration.
    pub fn on_time(&mut self) {
        self.consecutive = 0;
    }

    /// Record a late iteration for `seqno`, returning whether it should be logged as a warning.
    pub fn late(&mut self, seqno: u16) -> bool {
        if self.previous == Some(seqno.wrapping_sub(1)) {
            self.consecutive += 1;
        }
        self.previous = Some(seqno);

        self.consecutive >= SLOW_WARNING_THRESHOLD
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_PACKETS_COMPENSATE, SLOW_WARNING_THRESHOLD, SlowCounter, Statistics};

    #[test]
    fn the_constants_match_upstream() {
        assert_eq!(MAX_PACKETS_COMPENSATE, 3);
        assert_eq!(SLOW_WARNING_THRESHOLD, 5);
    }

    /// A brand-new session is not behind, so it never compensates on the first packet.
    #[test]
    fn a_fresh_session_is_not_behind() {
        let stats = Statistics::new(44_100);

        assert_eq!(stats.total_frames(), 0);
        assert_eq!(stats.compensation_packets(), 0);
    }

    /// Having sent an hour of audio in no time at all means the sender is far ahead, so there is
    /// nothing to compensate and the loop should sleep.
    #[test]
    fn a_sender_that_is_ahead_sleeps_and_does_not_compensate() {
        let mut stats = Statistics::new(44_100);
        stats.tick(44_100);

        assert_eq!(stats.frames_behind(), 0);
        assert_eq!(stats.compensation_packets(), 0);
        let sleep = stats.sleep_for().expect("a sender that is ahead sleeps");
        assert!(sleep.as_millis() > 900, "{sleep:?}");
    }

    /// The compensation burst is capped at three packets however far behind the sender is.
    #[test]
    fn compensation_is_capped_at_three_packets() {
        let stats = Statistics::new(44_100);
        std::thread::sleep(std::time::Duration::from_millis(60));

        // No frames sent at all, so roughly 2600 frames behind: eight packets' worth, capped.
        assert!(stats.frames_behind() >= 352);
        assert_eq!(stats.compensation_packets(), MAX_PACKETS_COMPENSATE);
    }

    /// An interval closes once a second's worth of frames has gone out.
    #[test]
    fn an_interval_completes_after_a_seconds_worth_of_frames() {
        let mut stats = Statistics::new(44_100);

        stats.tick(44_000);
        assert!(!stats.interval_completed());
        stats.tick(100);
        assert!(stats.interval_completed());

        let (_, frames) = stats.new_interval();
        assert_eq!(frames, 44_100);
        assert!(!stats.interval_completed());
        assert_eq!(stats.total_frames(), 44_100);
    }

    /// Only genuinely consecutive sequence numbers advance the counter.
    #[test]
    fn only_consecutive_late_packets_reach_the_warning_threshold() {
        let mut counter = SlowCounter::default();

        // First late packet has no predecessor, so it never counts.
        assert!(!counter.late(10));
        for seqno in 11..=14 {
            assert!(!counter.late(seqno), "seqno {seqno} warned too early");
        }
        assert!(counter.late(15), "the fifth consecutive late packet warns");
    }

    #[test]
    fn a_gap_in_the_sequence_does_not_advance_the_counter() {
        let mut counter = SlowCounter::default();

        for seqno in [10, 20, 30, 40, 50, 60] {
            assert!(!counter.late(seqno), "seqno {seqno} warned");
        }
    }

    #[test]
    fn an_on_time_iteration_clears_the_counter() {
        let mut counter = SlowCounter::default();

        for seqno in 10..=14 {
            counter.late(seqno);
        }
        counter.on_time();

        assert!(!counter.late(15));
    }
}
