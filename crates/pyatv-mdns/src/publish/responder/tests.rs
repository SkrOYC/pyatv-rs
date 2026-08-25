//! Socket-level tests for [`Responder`], driven over a loopback socket pair.
//!
//! No multicast group and no port 5353 for most of them: a "client" socket on `127.0.0.1:0` sends a
//! query straight at the responder's own ephemeral port and reads the datagram that comes back.
//! Because the client's source port is not 5353, those exchanges take the RFC 6762 §6.7
//! legacy-unicast path, which is also what a one-shot resolver on a real network does.
//!
//! The multicast path is the *other* branch of every decision this module makes — full TTLs, the
//! cache-flush bit, known-answer suppression, the §6 rate limit — and picking it turns entirely on
//! the query's source port being 5353. [`multicast_pair`] binds a client there so that branch is
//! exercised over a real socket too.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

use super::{MULTICAST_RATE_LIMIT, Responder, exclude_loopback, publishable_addresses};
use crate::dns::{CLASS_IN, DnsMessage, DnsQuestion, QueryType};
use crate::mdns::MDNS_PORT;
use crate::publish::registration::{
    CACHE_FLUSH, HOST_TTL, LEGACY_UNICAST_TTL, RESPONSE_FLAGS, SERVICE_TTL, ServiceRegistration,
};

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
            // Question: pyatv-rs.local A IN|QU. The QU bit is the *querier's*, echoed back
            // verbatim as RFC 6762 §6.7 requires the question section to be.
            0x08, b'p', b'y', b'a', b't', b'v', b'-', b'r', b's', 0x05, b'l', b'o', b'c', b'a',
            b'l', 0x00, 0x00, 0x01, 0x80, 0x01,
            // Answer: pyatv-rs.local A, class plain IN — **not** 0x8001. RFC 6762 §6.7 and §10.2:
            // a legacy resolver is not an mDNS cache and the cache-flush bit must not be set for
            // it. TTL 10, the legacy cap. 127.0.0.1.
            0x08, b'p', b'y', b'a', b't', b'v', b'-', b'r', b's', 0x05, b'l', b'o', b'c', b'a',
            b'l', 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x04, 127, 0, 0, 1,
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

// ---- The multicast path (source port 5353) ----

/// Stand a responder up on loopback with a client whose source port is 5353, so the responder reads
/// its queries as coming from a real mDNS implementation rather than a one-shot resolver.
///
/// The responder's `destination` is the client's address, so what it decides to "multicast" lands
/// on the client socket and can be read byte for byte without a multicast group being involved.
///
/// # Errors
///
/// Returns the bind error if `127.0.0.1:5353` cannot be taken. `mcast_socket` sets `SO_REUSEADDR`
/// and, where the platform has it, `SO_REUSEPORT`, so this normally succeeds even alongside a
/// system responder holding `0.0.0.0:5353`.
async fn multicast_pair() -> std::io::Result<(Responder, UdpSocket, SocketAddr)> {
    let client = crate::mdns::socket::mcast_socket(Some(Ipv4Addr::LOCALHOST), MDNS_PORT)?;
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;

    let client_address = client.local_addr()?;
    let server_address = server.local_addr()?;
    assert_eq!(
        client_address.port(),
        MDNS_PORT,
        "the source port is the whole point"
    );

    let responder = Responder::with_socket(server, client_address, registration(49_152));
    Ok((responder, client, server_address))
}

/// A question with QM (multicast-response) semantics: plain `IN`, no unicast-response bit. Every
/// query this crate's *scanner* builds sets QU, so this has to be spelled out.
fn multicast_question(name: &str, qtype: QueryType) -> DnsQuestion {
    DnsQuestion {
        qname: name.to_owned(),
        qtype,
        qclass: CLASS_IN,
    }
}

/// Assert that nothing at all comes back within a short window.
async fn expect_silence(client: &UdpSocket, why: &str) {
    let mut buffer = vec![0u8; 512];
    let outcome =
        tokio::time::timeout(Duration::from_millis(250), client.recv_from(&mut buffer)).await;
    assert!(outcome.is_err(), "{why}");
}

/// The multicast branch of every decision in this module, end to end over a socket.
///
/// # Why this is one test and not four
///
/// The branch is selected by the *querier's source port* being 5353, so exercising it means binding
/// `127.0.0.1:5353` — and only one socket can usefully hold it at a time. `SO_REUSEPORT` makes a
/// second bind succeed rather than fail, and the kernel then load-balances arriving datagrams
/// across the group, so two of these running concurrently would silently steal each other's
/// replies. One test binds it once and walks the phases in order; each phase's precondition is the
/// previous phase's postcondition, which is also why the §6 rate limit only has to be waited out
/// once.
#[tokio::test]
async fn the_multicast_path_answers_over_a_socket() {
    let (responder, client, server) = multicast_pair()
        .await
        .expect("binding 127.0.0.1:5353 should work with SO_REUSEADDR");
    drain_announcements(&client).await;

    // RFC 6762 §6: the announcements just multicast every record, so the responder owes them a
    // second of quiet before it will multicast any of them again.
    tokio::time::sleep(MULTICAST_RATE_LIMIT).await;

    let a_query = DnsMessage {
        questions: vec![multicast_question(HOST, QueryType::A)],
        ..DnsMessage::new(0x0001)
    };

    // ---- The response bytes, which differ from the legacy form in four ways ----
    client
        .send_to(&a_query.pack(), server)
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
            // Header: ID zero (RFC 6762 §18.1), QR|AA, *no* question section, one answer.
            0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            // Answer: pyatv-rs.local A IN|cache-flush (0x8001, which the legacy form must not
            // set), TTL 120 rather than the ten-second legacy cap, 127.0.0.1.
            0x08, b'p', b'y', b'a', b't', b'v', b'-', b'r', b's', 0x05, b'l', b'o', b'c', b'a',
            b'l', 0x00, 0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 127, 0, 0, 1,
        ],
    );

    // ---- RFC 6762 §6: that record may not go out again for a second ----
    client
        .send_to(&a_query.pack(), server)
        .await
        .expect("query sends");
    expect_silence(
        &client,
        "a record multicast a moment ago must not go out again",
    )
    .await;

    tokio::time::sleep(MULTICAST_RATE_LIMIT).await;
    client
        .send_to(&a_query.pack(), server)
        .await
        .expect("query sends");
    let refreshed = receive(&client).await;
    assert_eq!(
        refreshed.answers.len(),
        1,
        "and once it has rested, it does"
    );
    assert_eq!(refreshed.answers[0].ttl, HOST_TTL);

    // ---- RFC 6762 §7.1: a querier that already holds the answer is not sent it ----
    // The PTR record has not been touched since the announcements, so the rate limit is not what
    // would silence this one.
    let known = responder.registration().ptr_record(SERVICE_TTL);
    let suppressed = DnsMessage {
        questions: vec![multicast_question(SERVICE_TYPE, QueryType::PTR)],
        answers: vec![known],
        ..DnsMessage::new(2)
    };
    client
        .send_to(&suppressed.pack(), server)
        .await
        .expect("query sends");
    expect_silence(&client, "a known answer must be suppressed").await;

    // ---- RFC 6762 §5.4: QU is honoured while the records are fresh ----
    // The `A` record was multicast a moment ago and a quarter of its 120-second TTL is thirty
    // seconds, so the reply goes to the querier alone. It is still a full mDNS response, not a
    // §6.7 legacy one: zero ID, no questions, full TTL, cache-flush set.
    let qu_query = DnsMessage::query(0x35FF, [HOST], QueryType::A);
    client
        .send_to(&qu_query.pack(), server)
        .await
        .expect("query sends");

    let unicast = receive(&client).await;
    assert_eq!(unicast.msg_id, 0, "a QU answer is still an mDNS response");
    assert!(unicast.questions.is_empty());
    assert_eq!(unicast.answers[0].ttl, HOST_TTL, "not the legacy cap");
    assert_eq!(unicast.answers[0].qclass, CLASS_IN | CACHE_FLUSH);

    // A unicast answer reaches one cache, so it is not recorded as a multicast and the §6 rate
    // limit never starts: an immediate second QU question is answered too.
    client
        .send_to(&qu_query.pack(), server)
        .await
        .expect("query sends");
    assert_eq!(receive(&client).await.answers.len(), 1);
}

// ---- Address selection ----

/// Loopback is filtered out, matching pyatv's `get_private_addresses(include_loopback=False)`.
///
/// Asserted against an injected list, because a host with no non-loopback interface — a CI
/// container is exactly that — makes the real enumeration return an empty vector, which satisfies
/// "does not contain 127.0.0.1" without the filter existing at all.
#[test]
fn publishable_addresses_exclude_loopback() {
    let enumerated = vec![
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::new(10, 0, 10, 1),
        Ipv4Addr::new(127, 0, 0, 2),
        Ipv4Addr::new(169, 254, 3, 4),
        Ipv4Addr::new(192, 168, 1, 50),
    ];

    assert_eq!(
        exclude_loopback(enumerated),
        vec![
            Ipv4Addr::new(10, 0, 10, 1),
            Ipv4Addr::new(169, 254, 3, 4),
            Ipv4Addr::new(192, 168, 1, 50),
        ],
        "every 127/8 address goes, and the order of the rest is preserved"
    );

    // And the real thing agrees, on whatever this host has.
    assert!(!publishable_addresses().contains(&Ipv4Addr::LOCALHOST));
}

/// The real thing, on the real group and the real port. Ignored by default: it needs a host that
/// permits binding 5353 and joining `224.0.0.251`, which CI containers usually do not.
#[tokio::test]
#[ignore = "needs multicast and port 5353; run with --ignored on a real network"]
async fn a_real_multicast_responder_answers_a_real_query() {
    // One responder per interface, each publishing only its own address — see `Responder::bind`.
    let address = *publishable_addresses()
        .first()
        .expect("a real network has a non-loopback address");
    let responder =
        Responder::bind(address, registration(49_152).with_address(address)).expect("bind 5353");

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
