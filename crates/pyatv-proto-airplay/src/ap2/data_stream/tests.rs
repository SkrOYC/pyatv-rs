//! Unit tests for the data-stream channel, split out of `data_stream.rs` to keep that module
//! inside the workspace's size rule.
//!
//! The liveness tests here stand a real loopback peer up and speak the real HAP framing at it,
//! because the properties they assert — acknowledgements that keep flowing while the consumer is
//! asleep, a frame loop that keeps servicing writes while the inbound queue is full — only exist
//! once the frame loop, the two bounded queues and a socket are all in play at once.

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use pyatv_pairing::pairing::SessionKeys;
use pyatv_pairing::session::HapSession;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use super::{DataStreamChannel, INBOUND_QUEUE_DEPTH, SeqnoPolicy, frame, payload};

/// The full outbound stack, asserted against its parts rather than against a captured blob:
/// header, envelope and varint prefix all have to line up for the bytes to decode again.
#[test]
fn an_outbound_frame_unwraps_back_to_the_message() {
    let message = [0x08u8, 0x2A, 0x52, 0x01];

    let envelope =
        payload::encode_envelope(payload::encode_messages(&[&message])).expect("encodes");
    let wire = frame::encode_sync(0x1_2345_6789, &envelope);

    let mut buffer = bytes::BytesMut::from(&wire[..]);
    let decoded = frame::decode(&mut buffer)
        .expect("decodes")
        .expect("a frame");

    assert_eq!(decoded.header.seqno, 0x1_2345_6789);
    assert_eq!(decoded.header.message_type, frame::MESSAGE_TYPE_SYNC);
    assert_eq!(decoded.header.command, frame::COMMAND_COMM);
    assert!(decoded.header.wants_reply());

    let data = payload::decode_envelope(&decoded.payload).expect("an envelope");
    let messages = payload::decode_messages(&data).expect("splits");
    assert_eq!(messages.len(), 1);
    assert_eq!(&messages[0][..], &message[..]);
}

/// The default policy is upstream's: one seqno for the life of the channel.
#[test]
fn the_default_seqno_policy_is_fixed() {
    assert_eq!(SeqnoPolicy::default(), SeqnoPolicy::Fixed);
}

/// The contract the MRP protocol actor depends on: a reader parked in `recv_payload` holds the
/// inbound lock, and `close` must still complete and wake it. A `close` that took that lock
/// would deadlock against its own reader, which is exactly the shape of bug this asserts away.
#[tokio::test]
async fn closing_wakes_a_reader_parked_in_recv() {
    let (channel, _peer) = connected().await;
    let channel = Arc::new(channel);

    let reader = tokio::spawn({
        let channel = Arc::clone(&channel);
        async move { channel.recv_payload().await }
    });
    // Give the reader time to take the lock and park inside it.
    tokio::time::sleep(Duration::from_millis(50)).await;

    channel.close();

    let parked = tokio::time::timeout(Duration::from_secs(5), reader)
        .await
        .expect("close must wake a parked reader")
        .expect("the reader task must not panic");
    assert_eq!(parked, None, "a closed channel reads as end-of-stream");
}

/// A consumer that never drains must not stop the acknowledgements.
///
/// The regression: dispatching into the bounded inbound queue *before* writing the `rply` means a
/// full queue parks the frame loop, so the receiver stops being acknowledged and drops the tunnel.
/// Nothing here ever calls `recv_payload`, so the queue is full after
/// [`INBOUND_QUEUE_DEPTH`] frames and every frame after that exercises the dropped-payload path —
/// and every single one of them must still be answered.
#[tokio::test]
async fn a_consumer_that_never_drains_does_not_stop_the_acknowledgements() {
    let (_channel, mut peer) = connected().await;

    let sent = INBOUND_QUEUE_DEPTH + 16;
    for seqno in 0..sent {
        peer.send_sync(seqno as u64, b"a tunnelled payload").await;
    }

    let replies = peer.read_replies(sent).await;
    assert_eq!(
        replies.len(),
        sent,
        "every sync frame must be acknowledged even with nothing draining the queue"
    );
    for (index, seqno) in replies.iter().enumerate() {
        assert_eq!(
            *seqno, index as u64,
            "replies echo the incoming seqno in order"
        );
    }
}

/// A full inbound queue must not wedge the write side either.
///
/// Same deadlock seen from the other end: a frame loop parked on the inbound queue is a frame loop
/// that is not draining the outbound queue, so the MRP actor's next `send_payload` parks too — and
/// the actor is the only thing that would ever drain the inbound queue. Filling the queue and then
/// writing has to stay fast.
#[tokio::test]
async fn a_full_inbound_queue_does_not_wedge_the_write_side() {
    let (channel, mut peer) = connected().await;

    let flooded = INBOUND_QUEUE_DEPTH + 16;
    for seqno in 0..flooded {
        peer.send_sync(seqno as u64, b"a tunnelled payload").await;
    }
    // Wait until the loop has certainly filled the queue and started dropping.
    peer.read_replies(flooded).await;

    tokio::time::timeout(Duration::from_secs(2), channel.send_payload(b"outbound"))
        .await
        .expect("a full inbound queue must not park the writer")
        .expect("the write itself must succeed");
}

/// Fixed keys, so both ends of the loopback socket can derive the same session.
fn test_keys() -> SessionKeys {
    SessionKeys {
        shared_secret: Vec::new(),
        output_key: [7u8; 32],
        input_key: [9u8; 32],
    }
}

/// A channel and the peer on the other end of its socket.
async fn connected() -> (DataStreamChannel, Peer) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binding a loopback port must succeed in tests");
    let address = listener
        .local_addr()
        .expect("a bound listener must have an address");
    let accept = tokio::spawn(async move { listener.accept().await.map(|(stream, _)| stream) });

    let keys = test_keys();
    let channel = DataStreamChannel::connect(address, &keys, SeqnoPolicy::Fixed)
        .await
        .expect("dialling a listening loopback port must succeed");
    let stream = accept
        .await
        .expect("the accept task must not panic")
        .expect("the connection must be accepted");

    (channel, Peer::new(stream, &keys))
}

/// The receiver's end of the socket, speaking the same HAP framing in mirror image.
struct Peer {
    stream: TcpStream,
    session: HapSession,
    buffer: BytesMut,
}

impl Peer {
    /// The key roles are swapped relative to the controller: what it writes with, this reads with.
    fn new(stream: TcpStream, keys: &SessionKeys) -> Self {
        Self {
            stream,
            session: HapSession::new(&keys.input_key, &keys.output_key),
            buffer: BytesMut::new(),
        }
    }

    /// Push one `sync`/`comm` frame carrying `data` in the usual envelope.
    async fn send_sync(&mut self, seqno: u64, data: &[u8]) {
        let envelope =
            payload::encode_envelope(payload::encode_messages(&[data])).expect("encodes");
        let wire = frame::encode_sync(seqno, &envelope);
        let framed = self.session.encrypt(&wire).expect("sealing must succeed");
        self.stream
            .write_all(&framed)
            .await
            .expect("the peer write must succeed");
    }

    /// Read until `wanted` `rply` frames have arrived, returning their seqnos.
    async fn read_replies(&mut self, wanted: usize) -> Vec<u64> {
        let mut seqnos = Vec::with_capacity(wanted);

        let read = async {
            while seqnos.len() < wanted {
                while let Some(message) = frame::decode(&mut self.buffer).expect("frames decode") {
                    if message.header.message_type == frame::MESSAGE_TYPE_REPLY {
                        seqnos.push(message.header.seqno);
                    }
                }
                if seqnos.len() >= wanted {
                    break;
                }

                let mut chunk = [0u8; 8 * 1024];
                let read = self
                    .stream
                    .read(&mut chunk)
                    .await
                    .expect("the peer read must succeed");
                assert_ne!(read, 0, "the channel closed before answering");
                self.buffer.extend_from_slice(
                    &self
                        .session
                        .decrypt(&chunk[..read])
                        .expect("opening must succeed"),
                );
            }
            seqnos
        };

        tokio::time::timeout(Duration::from_secs(5), read)
            .await
            .expect("the acknowledgements must arrive")
    }
}
