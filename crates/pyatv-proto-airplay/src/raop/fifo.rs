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
//!
//! # Why a map and a queue rather than one queue
//!
//! Upstream's `_items` is a Python `dict`, so `seqno in self.packet_backlog` is a hash lookup.
//! A single `VecDeque<(u16, _)>` reproduces the insertion order but turns every lookup into a
//! linear scan of up to [`PACKET_BACKLOG_SIZE`] entries — and the *only* caller is a retransmit
//! responder driven by unauthenticated datagrams, so a burst of requests would cost
//! `lost_packets * 1000` comparisons each. The pair here keeps upstream's two properties and
//! restores its complexity: the [`std::collections::HashMap`] answers lookups in constant time and
//! the [`VecDeque`] of keys preserves insertion order for eviction.

use std::collections::{HashMap, VecDeque};

use bytes::Bytes;

/// How many packets are kept for retransmission.
///
/// `PACKET_BACKLOG_SIZE = 1000` (`stream_client.py:44`) — roughly eight seconds of audio at 352
/// frames and 44100 Hz, and about 1.4 MB of memory.
pub const PACKET_BACKLOG_SIZE: usize = 1000;

/// An insertion-ordered, bounded map from RTP sequence number to the packet that was sent.
#[derive(Debug)]
pub struct PacketFifo {
    /// The packets themselves, looked up in constant time.
    items: HashMap<u16, Bytes>,
    /// The same keys in insertion order, so eviction can find the oldest one.
    order: VecDeque<u16>,
    upper_limit: usize,
}

impl PacketFifo {
    /// A backlog holding at most `upper_limit` packets.
    #[must_use]
    pub fn new(upper_limit: usize) -> Self {
        let capacity = upper_limit.min(PACKET_BACKLOG_SIZE);
        Self {
            items: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
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
    pub fn insert(&mut self, seqno: u16, packet: impl Into<Bytes>) -> bool {
        if self.items.contains_key(&seqno) {
            tracing::debug!(
                seqno,
                "refusing to overwrite a packet already in the backlog"
            );
            return false;
        }

        // A zero limit would otherwise store a packet it can never evict.
        if self.upper_limit == 0 {
            return false;
        }
        if self.items.len() + 1 > self.upper_limit
            && let Some(oldest) = self.order.pop_front()
        {
            let _ = self.items.remove(&oldest);
        }

        self.order.push_back(seqno);
        let _ = self.items.insert(seqno, packet.into());
        true
    }

    /// Look a packet up by sequence number.
    ///
    /// The returned [`Bytes`] shares the stored buffer, so answering a retransmission request
    /// costs a reference-count bump rather than a copy of the packet.
    #[must_use]
    pub fn get(&self, seqno: u16) -> Option<Bytes> {
        self.items.get(&seqno).cloned()
    }

    /// Drop every packet.
    ///
    /// Called at the end of every `send_audio`, with the comment "Don't keep old packets around
    /// (big!)" (`stream_client.py:462`). The backlog does not survive across sessions.
    pub fn clear(&mut self) {
        self.items.clear();
        self.order.clear();
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

    /// Compare a stored packet against the bytes it was inserted with.
    fn stored(fifo: &PacketFifo, seqno: u16) -> Option<Vec<u8>> {
        fifo.get(seqno).map(|packet| packet.to_vec())
    }

    #[test]
    fn packets_come_back_out_by_sequence_number() {
        let mut fifo = PacketFifo::new(4);

        assert!(fifo.insert(7, vec![1, 2, 3]));
        assert_eq!(stored(&fifo, 7), Some(vec![1, 2, 3]));
        assert_eq!(stored(&fifo, 8), None);
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

        assert_eq!(
            stored(&fifo, 65_534),
            None,
            "the first inserted was evicted"
        );
        assert_eq!(stored(&fifo, 65_535), Some(vec![0xBB]));
        assert_eq!(stored(&fifo, 0), Some(vec![0xCC]));
        assert_eq!(fifo.len(), 2);
    }

    /// Re-inserting the same sequence number is refused rather than silently overwriting.
    #[test]
    fn a_duplicate_sequence_number_is_refused() {
        let mut fifo = PacketFifo::new(4);

        assert!(fifo.insert(1, vec![0xAA]));
        assert!(!fifo.insert(1, vec![0xBB]));
        assert_eq!(stored(&fifo, 1), Some(vec![0xAA]));
        assert_eq!(fifo.len(), 1);
    }

    #[test]
    fn clearing_empties_the_backlog() {
        let mut fifo = PacketFifo::default();

        fifo.insert(1, vec![0xAA]);
        fifo.clear();

        assert!(fifo.is_empty());
        assert_eq!(stored(&fifo, 1), None);
    }

    #[test]
    fn the_default_limit_matches_upstream() {
        let mut fifo = PacketFifo::default();

        for seqno in 0..u16::try_from(PACKET_BACKLOG_SIZE + 10).expect("fits") {
            fifo.insert(seqno, vec![0]);
        }

        assert_eq!(fifo.len(), PACKET_BACKLOG_SIZE);
        assert_eq!(stored(&fifo, 9), None);
        assert_eq!(stored(&fifo, 10), Some(vec![0]));
    }

    /// The order queue and the map must stay the same size, or eviction would either leak entries
    /// or drop live ones. Filling well past the limit and re-checking both is the cheapest way to
    /// pin that.
    #[test]
    fn eviction_keeps_the_map_and_the_order_queue_in_step() {
        let mut fifo = PacketFifo::new(3);

        for seqno in 0..50u16 {
            assert!(fifo.insert(seqno, vec![0xEE]));
        }

        assert_eq!(fifo.len(), 3);
        assert_eq!(fifo.order.len(), fifo.items.len());
        assert_eq!(stored(&fifo, 46), None);
        for seqno in 47..50u16 {
            assert_eq!(stored(&fifo, seqno), Some(vec![0xEE]), "{seqno}");
        }
    }

    /// A degenerate limit stores nothing rather than growing without bound.
    #[test]
    fn a_zero_limit_stores_nothing() {
        let mut fifo = PacketFifo::new(0);

        assert!(!fifo.insert(1, vec![0xAA]));
        assert!(fifo.is_empty());
    }
}
