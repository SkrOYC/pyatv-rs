//! The bounded backlog of sent audio packets, kept so lost ones can be resent.
//!
//! Port of `PacketFifo` (`pyatv/protocols/raop/fifo.py`, full file). Two of its properties are
//! easy to get wrong and are both reproduced:
//!
//! - **Eviction is by insertion order, not by sequence number.** Upstream deletes
//!   `list(self._items.keys())[0]` — Python's dict insertion order — so after the RTP sequence
//!   number wraps past 65535 the oldest *inserted* packet is dropped, not the numerically lowest.
//! - **Re-inserting a sequence number is an error, not an overwrite.** `__setitem__` raises
//!   `ValueError` when the key is already present.
//!
//! Individual removal does not exist at all: `__delitem__` raises `NotImplementedError`, so
//! packets leave only by eviction or [`PacketFifo::clear`].

use std::collections::VecDeque;

/// How many packets are kept for retransmission.
///
/// `PACKET_BACKLOG_SIZE = 1000` (`stream_client.py:44`) — roughly eight seconds of audio at 352
/// frames and 44100 Hz, and about 1.4 MB of memory.
pub const PACKET_BACKLOG_SIZE: usize = 1000;

/// An insertion-ordered, bounded map from RTP sequence number to the packet that was sent.
#[derive(Debug)]
pub struct PacketFifo {
    items: VecDeque<(u16, Vec<u8>)>,
    upper_limit: usize,
}

impl PacketFifo {
    /// A backlog holding at most `upper_limit` packets.
    #[must_use]
    pub fn new(upper_limit: usize) -> Self {
        Self {
            items: VecDeque::with_capacity(upper_limit.min(PACKET_BACKLOG_SIZE)),
            upper_limit,
        }
    }

    /// How many packets are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the backlog is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Record a sent packet, evicting the oldest inserted one if the limit is reached.
    ///
    /// Returns `false` without storing anything if `seqno` is already present, which is upstream's
    /// `ValueError`. A caller has no recovery for that beyond noticing it, and a stream should
    /// never produce it: the sequence number advances once per packet and the backlog holds far
    /// fewer than a wrap's worth.
    pub fn insert(&mut self, seqno: u16, packet: Vec<u8>) -> bool {
        if self.items.iter().any(|(index, _)| *index == seqno) {
            tracing::debug!(
                seqno,
                "refusing to overwrite a packet already in the backlog"
            );
            return false;
        }

        if self.items.len() + 1 > self.upper_limit {
            let _ = self.items.pop_front();
        }
        self.items.push_back((seqno, packet));
        true
    }

    /// Look a packet up by sequence number.
    #[must_use]
    pub fn get(&self, seqno: u16) -> Option<&[u8]> {
        self.items
            .iter()
            .find(|(index, _)| *index == seqno)
            .map(|(_, packet)| packet.as_slice())
    }

    /// Drop every packet.
    ///
    /// Called at the end of every `send_audio`, with the comment "Don't keep old packets around
    /// (big!)" (`stream_client.py:462`). The backlog does not survive across sessions.
    pub fn clear(&mut self) {
        self.items.clear();
    }
}

impl Default for PacketFifo {
    fn default() -> Self {
        Self::new(PACKET_BACKLOG_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::{PACKET_BACKLOG_SIZE, PacketFifo};

    #[test]
    fn packets_come_back_out_by_sequence_number() {
        let mut fifo = PacketFifo::new(4);

        assert!(fifo.insert(7, vec![1, 2, 3]));
        assert_eq!(fifo.get(7), Some(&[1, 2, 3][..]));
        assert_eq!(fifo.get(8), None);
        assert_eq!(fifo.len(), 1);
    }

    /// Eviction follows insertion order, so a wrapped sequence number does not protect a packet
    /// from being dropped and does not cause a numerically lower one to be dropped first.
    #[test]
    fn eviction_follows_insertion_order_not_sequence_order() {
        let mut fifo = PacketFifo::new(2);

        fifo.insert(65_534, vec![0xAA]);
        fifo.insert(65_535, vec![0xBB]);
        fifo.insert(0, vec![0xCC]);

        assert_eq!(fifo.get(65_534), None, "the first inserted was evicted");
        assert_eq!(fifo.get(65_535), Some(&[0xBB][..]));
        assert_eq!(fifo.get(0), Some(&[0xCC][..]));
        assert_eq!(fifo.len(), 2);
    }

    /// Re-inserting the same sequence number is refused rather than silently overwriting.
    #[test]
    fn a_duplicate_sequence_number_is_refused() {
        let mut fifo = PacketFifo::new(4);

        assert!(fifo.insert(1, vec![0xAA]));
        assert!(!fifo.insert(1, vec![0xBB]));
        assert_eq!(fifo.get(1), Some(&[0xAA][..]));
        assert_eq!(fifo.len(), 1);
    }

    #[test]
    fn clearing_empties_the_backlog() {
        let mut fifo = PacketFifo::default();

        fifo.insert(1, vec![0xAA]);
        fifo.clear();

        assert!(fifo.is_empty());
        assert_eq!(fifo.get(1), None);
    }

    #[test]
    fn the_default_limit_matches_upstream() {
        let mut fifo = PacketFifo::default();

        for seqno in 0..u16::try_from(PACKET_BACKLOG_SIZE + 10).expect("fits") {
            fifo.insert(seqno, vec![0]);
        }

        assert_eq!(fifo.len(), PACKET_BACKLOG_SIZE);
        assert_eq!(fifo.get(9), None);
        assert_eq!(fifo.get(10), Some(&[0][..]));
    }
}
