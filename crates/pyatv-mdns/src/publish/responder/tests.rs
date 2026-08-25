//! Socket-level tests for [`Responder`], driven over a loopback socket pair.
//!
//! No multicast group and no port 5353: a "client" socket on `127.0.0.1:0` sends a query straight
//! at the responder's own ephemeral port and reads the datagram that comes back. Because the
//! client's source port is not 5353, every exchange here takes the RFC 6762 §6.7 legacy-unicast
//! path, which is also what a one-shot resolver on a real network does.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

use super::{Responder, publishable_addresses};
use crate::dns::{DnsMessage, QueryType};
use crate::publish::registration::{LEGACY_UNICAST_TTL, RESPONSE_FLAGS, ServiceRegistration};

const SERVICE_TYPE: &str = "_touch-remote._tcp.local";
const INSTANCE: &str = "0000000000000000000000000000000167774977";
const HOST: &str = "pyatv-rs.local";

/// Long enough that a loopback round trip cannot flake, short enough that a hang fails fast.
const REPLY_TIMEOUT: Duration = Duration::from_secs(2);

fn registration(port: u16) -> ServiceRegistration {
    ServiceRegistration::new(SERVICE_TYPE, INSTANCE, HOST, port)
        .with_address(Ipv4Addr::LOCALHOST)
        .with_property("DvNm", "pyatv remote")
        .with_property("Pair", "0000000000000001")
}

/// Stand a responder up on loopback and hand back a client socket aimed at it.
async fn pair() -> (Responder, UdpSocket, SocketAddr) {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("loopback bind");
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("loopback bind");

    let client_address = client.local_addr().expect("bound");
    let server_address = server.local_addr().expect("bound");

    // Anything the responder decides to multicast goes to the client instead, so the announcement
    // path is observable too.
    let responder = Responder::with_socket(server, client_address, registration(49_152));

    (responder, client, server_address)
}

/// Read one datagram, failing rather than hanging.
async fn receive(socket: &UdpSocket) -> DnsMessage {
    let mut buffer = vec![0u8; 9_000];
    let (length, _) = tokio::time::timeout(REPLY_TIMEOUT, socket.recv_from(&mut buffer))
        .await
        .expect("a reply should arrive")
        .expect("receive succeeds");
    DnsMessage::unpack(&buffer[..length]).expect("the responder emits decodable messages")
}

/// Drain the startup announcements so a test can look at the answer it asked for.
async fn drain_announcements(client: &UdpSocket) {
    for _ in 0..super::ANNOUNCE_COUNT {
        let announcement = receive(client).await;
        assert!(announcement.questions.is_empty());
        assert!(announcement.header().is_response());
    }
}

/// RFC 6762 §8.3: the service announces itself unsolicited, without being asked.
#[tokio::test]
async fn the_service_announces_itself_at_startup() {
    let (_responder, client, _) = pair().await;

    let first = receive(&client).await;
    assert_eq!(first.msg_id, 0);
    assert_eq!(first.flags, RESPONSE_FLAGS);
    assert_eq!(first.answers.len(), 4, "PTR, SRV, TXT and one A");
    assert_eq!(
        first.answers[0].rd.as_ptr_name(),
        Some(format!("{INSTANCE}.{SERVICE_TYPE}").as_str())
    );
}

/// A browse query gets the instance back, with everything needed to connect to it.
#[tokio::test]
async fn a_browse_query_is_answered_over_the_socket() {
    let (_responder, client, server) = pair().await;
    drain_announcements(&client).await;

    let query = DnsMessage::query(0x35FF, [SERVICE_TYPE], QueryType::PTR);
    client
        .send_to(&query.pack(), server)
        .await
        .expect("query sends");

    let response = receive(&client).await;

    // The client's source port is not 5353, so this is a legacy-unicast reply.
    assert_eq!(response.msg_id, 0x35FF);
    assert_eq!(response.questions, query.questions);
    assert_eq!(
        response.answers[0].rd.as_ptr_name(),
        Some(format!("{INSTANCE}.{SERVICE_TYPE}").as_str())
    );

    let srv = response
        .resources
        .iter()
        .find_map(|it| it.rd.as_srv())
        .expect("the SRV record comes along as an additional");
    assert_eq!(srv.port, 49_152);
    assert_eq!(srv.target, HOST);

    for record in response.answers.iter().chain(&response.resources) {
        assert!(record.ttl <= LEGACY_UNICAST_TTL);
    }
}

/// The exact response bytes for a fixed query, so an accidental re-encoding shows up as a diff.
#[tokio::test]
async fn the_response_bytes_are_stable() {
    let (_responder, client, server) = pair().await;
    drain_announcements(&client).await;

    let query = DnsMessage::query(0x0001, ["pyatv-rs.local"], QueryType::A);
    client
        .send_to(&query.pack(), server)
        .await
        .expect("query sends");

    let mut buffer = vec![0u8; 9_000];
    let (length, _) = tokio::time::timeout(REPLY_TIMEOUT, client.recv_from(&mut buffer))
        .await
        .expect("a reply should arrive")
        .expect("receive succeeds");

    assert_eq!(
        &buffer[..length],
        &[
            // Header: echoed ID, QR|AA, one question, one answer.
            0x00, 0x01, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            // Question: pyatv-rs.local A IN|QU.
            0x08, b'p', b'y', b'a', b't', b'v', b'-', b'r', b's', 0x05, b'l', b'o', b'c', b'a',
            b'l', 0x00, 0x00, 0x01, 0x80, 0x01,
            // Answer: pyatv-rs.local A IN|cache-flush, TTL 10, 127.0.0.1.
            0x08, b'p', b'y', b'a', b't', b'v', b'-', b'r', b's', 0x05, b'l', b'o', b'c', b'a',
            b'l', 0x00, 0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x04, 127, 0, 0, 1,
        ],
    );
}

/// A question about someone else's service produces no datagram at all.
#[tokio::test]
async fn an_unrelated_query_is_ignored() {
    let (_responder, client, server) = pair().await;
    drain_announcements(&client).await;

    let query = DnsMessage::query(2, ["_airplay._tcp.local"], QueryType::PTR);
    client
        .send_to(&query.pack(), server)
        .await
        .expect("query sends");

    let mut buffer = vec![0u8; 512];
    let outcome =
        tokio::time::timeout(Duration::from_millis(250), client.recv_from(&mut buffer)).await;
    assert!(outcome.is_err(), "nothing should have been answered");
}

/// Garbage on the wire must not stop the responder answering the next real query.
#[tokio::test]
async fn a_malformed_datagram_does_not_kill_the_responder() {
    let (_responder, client, server) = pair().await;
    drain_announcements(&client).await;

    client
        .send_to(b"not a dns message at all", server)
        .await
        .expect("garbage sends");

    let query = DnsMessage::query(3, [SERVICE_TYPE], QueryType::PTR);
    client
        .send_to(&query.pack(), server)
        .await
        .expect("query sends");

    assert_eq!(receive(&client).await.msg_id, 3);
}

/// RFC 6762 §10.1: withdrawing multicasts the record set with a zero TTL.
#[tokio::test]
async fn unregistering_sends_a_goodbye() {
    let (responder, client, _) = pair().await;
    drain_announcements(&client).await;

    responder.unregister().await.expect("goodbye sends");

    let goodbye = receive(&client).await;
    assert_eq!(goodbye.answers.len(), 4);
    for record in &goodbye.answers {
        assert_eq!(record.ttl, 0, "{record:?}");
    }
}

/// Dropping the handle stops the responder, so a pairing session cannot leak a live service.
#[tokio::test]
async fn dropping_the_responder_stops_it_answering() {
    let (responder, client, server) = pair().await;
    drain_announcements(&client).await;
    drop(responder);

    let query = DnsMessage::query(4, [SERVICE_TYPE], QueryType::PTR);
    // The socket is closed with the responder, so the send may or may not fail depending on
    // platform; either way nothing comes back.
    let _ = client.send_to(&query.pack(), server).await;

    let mut buffer = vec![0u8; 512];
    let outcome =
        tokio::time::timeout(Duration::from_millis(250), client.recv_from(&mut buffer)).await;
    assert!(outcome.is_err(), "a dropped responder should be silent");
}

/// Loopback is filtered out, matching pyatv's `get_private_addresses(include_loopback=False)`.
#[test]
fn publishable_addresses_exclude_loopback() {
    assert!(
        !publishable_addresses().contains(&Ipv4Addr::LOCALHOST),
        "127.0.0.1 is reachable by nothing on the network"
    );
}

/// The real thing, on the real group and the real port. Ignored by default: it needs a host that
/// permits binding 5353 and joining `224.0.0.251`, which CI containers usually do not.
#[tokio::test]
#[ignore = "needs multicast and port 5353; run with --ignored on a real network"]
async fn a_real_multicast_responder_answers_a_real_query() {
    let responder = Responder::bind(registration(49_152)).expect("bind 5353");

    let client = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .expect("client bind");
    let query = DnsMessage::query(0x35FF, [SERVICE_TYPE], QueryType::PTR);
    client
        .send_to(
            &query.pack(),
            SocketAddr::from((crate::mdns::MULTICAST_GROUP, crate::mdns::MDNS_PORT)),
        )
        .await
        .expect("query sends");

    let mut buffer = vec![0u8; 9_000];
    loop {
        let (length, _) = tokio::time::timeout(REPLY_TIMEOUT, client.recv_from(&mut buffer))
            .await
            .expect("a reply should arrive")
            .expect("receive succeeds");
        let Ok(message) = DnsMessage::unpack(&buffer[..length]) else {
            continue;
        };
        if message.msg_id == 0x35FF && message.header().is_response() {
            assert!(
                message
                    .answers
                    .iter()
                    .any(|it| it.rd.as_ptr_name() == Some(&format!("{INSTANCE}.{SERVICE_TYPE}")))
            );
            break;
        }
    }

    responder.unregister().await.expect("goodbye sends");
}
