//! Building the query messages pyatv puts on the wire.
//!
//! Ports `create_service_queries` from `pyatv/core/mdns.py:79-92`, including its slice-window
//! off-by-one. See `docs/research/discovery-port-spec.md` §2.2.

use crate::dns::{DEFAULT_QUERY_ID, DnsMessage, DnsQuestion, QueryType};
use crate::service::SLEEP_PROXY_SERVICE;

/// How many service types pyatv intends to put in one query message.
///
/// From `SERVICES_PER_MSG = 3` (`pyatv/core/mdns.py:28`), whose docstring reads "Number of services
/// to include in each request". It is the loop *stride*; the slice window is one wider. See
/// [`create_service_queries`].
pub const SERVICES_PER_MSG: usize = 3;

/// Split `services` into the query messages pyatv would send for them.
///
/// Every message carries up to four service questions plus an unconditional
/// [`SLEEP_PROXY_SERVICE`] question, all with `qclass` `0x8001` (`IN` with the QU bit set, RFC 6762
/// section 5.4) and message id [`DEFAULT_QUERY_ID`] — pyatv never randomises or increments it.
///
/// # The window-of-4-on-a-stride-of-3 quirk
///
/// `pyatv/core/mdns.py:83-84` reads:
///
/// ```python
/// for i in range(math.ceil(len(services) / SERVICES_PER_MSG)):
///     service_chunk = services[i * SERVICES_PER_MSG : i * SERVICES_PER_MSG + 4]
/// ```
///
/// The loop advances by three but each slice takes **four** elements, so consecutive windows
/// overlap by one whenever another chunk follows. For `[A, B, C, D]` the round count is
/// `ceil(4/3) == 2`, message 0 carries `[A, B, C, D]` and message 1 carries `[D]` — `D` is asked
/// about twice. `SERVICES_PER_MSG = 3` and the docstring both say the window was meant to be three
/// wide, so this is almost certainly an upstream off-by-one
/// (`docs/research/discovery-port-spec.md` §2.2 and §9 both flag it).
///
/// It is reproduced deliberately. The question sets are what a responder sees, and pyatv's own
/// known-answer tests are written against them: `tests/core/test_mdns_functional.py:132-143`
/// asserts a request count of exactly `ceil(n/3)` for `n` of 1, 3, 4 and 7, which only holds
/// together with this window. Fixing it here would make this port send different traffic than the
/// implementation every captured device interaction was validated against, for no gain — the extra
/// question is harmless, and the duplicate answer is deduplicated by
/// [`ServiceParser`](super::ServiceParser) anyway.
///
/// # Examples
///
/// ```
/// use pyatv_mdns::dns::QueryType;
/// use pyatv_mdns::mdns::create_service_queries;
///
/// let services: Vec<String> = ["a", "b", "c", "d"].map(String::from).to_vec();
/// let queries = create_service_queries(&services, QueryType::PTR);
///
/// // ceil(4 / 3) == 2 messages ...
/// assert_eq!(queries.len(), 2);
/// // ... the first holding all four services, plus the sleep-proxy question ...
/// assert_eq!(queries[0].questions.len(), 5);
/// // ... and the second re-asking only the overlapped tail.
/// assert_eq!(queries[1].questions.len(), 2);
/// assert_eq!(queries[1].questions[0].qname, "d");
/// ```
#[must_use]
pub fn create_service_queries(services: &[String], qtype: QueryType) -> Vec<DnsMessage> {
    let rounds = services.len().div_ceil(SERVICES_PER_MSG);

    (0..rounds)
        .map(|round| {
            let start = round * SERVICES_PER_MSG;
            // The window is `+ 4`, not `+ SERVICES_PER_MSG`. See this function's documentation.
            let end = start.saturating_add(4).min(services.len());

            let mut message = DnsMessage::new(DEFAULT_QUERY_ID);
            message.questions = services[start..end]
                .iter()
                .map(|service| DnsQuestion::new(service.as_str(), qtype))
                .chain(std::iter::once(DnsQuestion::new(
                    SLEEP_PROXY_SERVICE,
                    qtype,
                )))
                .collect();
            message
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{SERVICES_PER_MSG, create_service_queries};
    use crate::dns::{DEFAULT_QUERY_ID, QCLASS_IN_UNICAST, QueryType};
    use crate::service::SLEEP_PROXY_SERVICE;

    fn services(count: usize) -> Vec<String> {
        (0..count).map(|i| format!("srv{i}._tcp.local")).collect()
    }

    /// `tests/core/test_mdns_functional.py:132-143` parametrises exactly these four cases.
    #[test]
    fn message_count_is_ceil_of_services_over_three() {
        for (count, expected) in [(1, 1), (3, 1), (4, 2), (7, 3)] {
            let queries = create_service_queries(&services(count), QueryType::PTR);
            assert_eq!(queries.len(), expected, "{count} services");
        }
    }

    /// No services means no messages at all — not one bare sleep-proxy query.
    #[test]
    fn no_services_produces_no_messages() {
        assert!(create_service_queries(&[], QueryType::PTR).is_empty());
    }

    /// Every message ends with the sleep-proxy question, whatever was asked for.
    #[test]
    fn every_message_appends_the_sleep_proxy_question() {
        let queries = create_service_queries(&services(7), QueryType::PTR);
        assert_eq!(queries.len(), 3);
        for query in &queries {
            let last = query.questions.last().expect("each message has questions");
            assert_eq!(last.qname, SLEEP_PROXY_SERVICE);
            assert_eq!(last.qtype, QueryType::PTR);
        }
    }

    /// The upstream off-by-one: stride three, window four, so windows overlap by one.
    #[test]
    fn windows_overlap_by_one_service() {
        let services = services(4);
        let queries = create_service_queries(&services, QueryType::PTR);

        let names = |index: usize| -> Vec<String> {
            queries[index]
                .questions
                .iter()
                .map(|question| question.qname.clone())
                .collect()
        };

        assert_eq!(
            names(0),
            vec![
                "srv0._tcp.local".to_owned(),
                "srv1._tcp.local".to_owned(),
                "srv2._tcp.local".to_owned(),
                "srv3._tcp.local".to_owned(),
                SLEEP_PROXY_SERVICE.to_owned(),
            ]
        );
        assert_eq!(
            names(1),
            vec!["srv3._tcp.local".to_owned(), SLEEP_PROXY_SERVICE.to_owned()],
        );
    }

    /// An exact multiple of the stride does not overlap: the window never reaches past the end.
    #[test]
    fn exact_multiples_do_not_overlap() {
        let services = services(6);
        let queries = create_service_queries(&services, QueryType::PTR);

        assert_eq!(queries.len(), 2);
        assert_eq!(queries[0].questions.len(), SERVICES_PER_MSG + 1 + 1);
        assert_eq!(queries[1].questions.len(), SERVICES_PER_MSG + 1);
        assert_eq!(queries[1].questions[0].qname, "srv3._tcp.local");
    }

    /// `tests/core/test_mdns.py:59-65`: id `0x35FF`, `PTR`, and `qclass == 0x8001` exactly.
    #[test]
    fn questions_carry_the_qu_bit_and_the_fixed_message_id() {
        let queries = create_service_queries(&services(1), QueryType::PTR);
        let query = &queries[0];

        assert_eq!(query.msg_id, DEFAULT_QUERY_ID);
        assert_eq!(query.msg_id, 0x35FF);
        for question in &query.questions {
            assert_eq!(question.qclass, QCLASS_IN_UNICAST);
            assert_eq!(question.qclass, 0x8001);
        }
        assert!(query.answers.is_empty());
        assert!(query.resources.is_empty());
    }

    /// The sleep-proxy follow-up in `datagram_received` re-queries with `ANY`, not `PTR`.
    #[test]
    fn qtype_is_threaded_through_to_every_question() {
        let queries = create_service_queries(&services(1), QueryType::ANY);
        for question in &queries[0].questions {
            assert_eq!(question.qtype, QueryType::ANY);
        }
    }
}
