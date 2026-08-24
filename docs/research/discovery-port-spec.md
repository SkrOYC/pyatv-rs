# Discovery subsystem porting spec

Ground truth: pyatv checkout at `/tmp/pyatv-ref`, commit `b277a4c8222ecdcbaab8a24e3e713ca44765adb4` (tag/release 0.18.0, `master`). All paths below are relative to that repository root, e.g. `pyatv/support/dns.py:19-25`. Read the cited ranges yourself before implementing; this document paraphrases and quotes but does not replace the source.

This spec covers the "discovery" subsystem end to end: the raw DNS message codec, the minimal mDNS/DNS-SD client pyatv rolls itself, the `zeroconf`-library-backed alternative scanner, the per-protocol scan handlers and device-info extractors, the `conf.AppleTV`/`BaseService` config model those handlers populate, the device/version lookup tables, the TCP "knock" wake mechanism, and the test fixtures worth porting as known-answer tests.

A structural note up front, because it is easy to miss: pyatv actually ships **two independent scanner implementations** that both get exercised at runtime depending on how `pyatv.scan()` is called:

1. A hand-rolled DNS-over-UDP client (`pyatv/support/dns.py` + `pyatv/core/mdns.py`), used when the caller does **not** pass an `aiozc` (`AsyncZeroconf`) instance. This is the default path for the CLI and most library users, and it is the one with a fully custom wire-format implementation worth porting byte-for-byte.
2. A `zeroconf`-library-backed scanner (the `ZeroconfScanner`/`ZeroconfMulticastScanner`/`ZeroconfUnicastScanner` classes at the bottom of `pyatv/core/scan.py`), used only when the caller supplies an already-running `AsyncZeroconf` (typically Home Assistant, which keeps one `zeroconf` instance running for all its integrations). This path delegates all DNS wire-format handling to the third-party `zeroconf` package and does not need its own codec.

Both paths funnel into the same `BaseScanner` (grouping, device-info merge, `conf.AppleTV` construction) and the same per-protocol `scan()`/`device_info()`/`service_info()` handlers. Section 2 and the first half of section 3 cover the custom implementation in depth since it's the one to port; the `Zeroconf*Scanner` classes are documented for completeness in section 3.6 but a Rust port will most likely only need an equivalent of path 1, backed by a Rust mDNS crate or a hand-rolled one — the design decision of which is out of scope for this document.

---

## 1. `pyatv/support/dns.py` — DNS message model

### 1.1 Header layout

`DnsHeader` (`pyatv/support/dns.py:278-302`) is a 6 x `u16` big-endian struct, unpacked/packed via `struct.pack/unpack(">6H", ...)`:

```
id:      u16   (message id)
flags:   u16   (raw, not decomposed into QR/Opcode/AA/TC/RD/RA/Z/RCODE bit fields anywhere in pyatv)
qdcount: u16
ancount: u16
nscount: u16
arcount: u16
```

`DnsMessage.__init__` (`pyatv/support/dns.py:364-371`) defaults `msg_id=0` and **`flags=0x0120`**. That is the flags value baked into every query pyatv sends unless overridden. `0x0120` = `0b0000_0001_0010_0000`: bit `0x0100` is the RD (Recursion Desired) bit position in classic DNS, but mDNS does not interpret flags the same way as unicast DNS — pyatv does not decode this value anywhere, it is simply the literal historical value used by pyatv's query construction. Treat it as an opaque constant to reproduce, not a semantically-decoded bitfield. Responses set `flags = 0x0840` (see `tests/fake_udns.py:190`, `0b0000_1000_0100_0000`) which is `QR=1` (response) plus `AA=1` (authoritative answer) in the classic decomposition — again, pyatv never checks incoming flags, it only checks `ancount`/`nscount`/`arcount` counts.

**Important:** pyatv does not set the "unicast-response requested" (`QU`) bit in a special dedicated field — see §1.5, the class field encodes it directly as `0x8001` per question, not as a header flag.

### 1.2 `QueryType` (`pyatv/support/dns.py:249-275`)

```python
class QueryType(enum.IntEnum):
    A = 0x01
    PTR = 0x0C
    TXT = 0x10
    SRV = 0x21
    ANY = 0xFF
```

Exactly these five values are recognized. `AAAA` (0x1C), `NSEC`, `CNAME`, etc. are **not** modeled — any record with an unrecognized type is decoded as raw bytes (`DnsResource.unpack_read`, `pyatv/support/dns.py:352-356`: `if qtype in QueryType.__members__.values(): ... else: rd = buffer.read(rd_length)`). pyatv is IPv4-only throughout discovery; there is no AAAA handling anywhere in this subsystem.

`QueryType.parse_rdata(buffer, length)` (`pyatv/support/dns.py:258-275`) is the rdata dispatcher:

- `A`: must be exactly 4 bytes or `ValueError` is raised (`f"An A record must have exactly 4 bytes of data (not {length})"`); returns `str(IPv4Address(buffer.read(length)))` — i.e. a dotted-quad **string**, not a struct.
- `PTR`: `parse_domain_name(buffer)` — a `str`.
- `TXT`: `parse_txt_dict(buffer, length)` — a `CaseInsensitiveDict[bytes]`.
- `SRV`: `parse_srv_dict(buffer)` — a plain `dict` with keys `priority`, `weight`, `port`, `target`.
- anything else: raw `bytes` of `length` bytes, unparsed.

### 1.3 Name compression: `parse_domain_name` (`pyatv/support/dns.py:149-196`)

Algorithm, label by label, reading a length-prefixed label stream:

1. Read one length byte. `length == 0` terminates the name (the DNS root label) and the loop breaks — the accumulated labels are joined with `.` and returned. Note: **the trailing empty root label is dropped from the returned string** — `parse_domain_name` never appends a trailing dot; `"foo.example.com"` not `"foo.example.com."`.
2. The top two bits of the length byte (`length & 0xC0`) are the compression flag. Only `0b00` (plain label, length is `length & 0x3F` effectively unmasked since bits are 0) and `0b11` (pointer) are legal; `assert length_flags in (0, 0b11)` — the `01`/`10` combinations are RFC-reserved and pyatv will raise an `AssertionError` if it ever sees one (this is not converted to a friendly exception).
3. Plain label (`0b00`): read `length` bytes. If the first 4 bytes are literally `b"xn--"`, decode with Python's `idna` codec (`label.decode("idna")`); otherwise decode as UTF-8. This is an ASCII-Compatible-Encoding sniff, not a check of what the label is being used for — it triggers on any label that happens to start with the 4 ASCII bytes `x`,`n`,`-`,`-`.
4. Pointer (`0b11`): mask off the top two bits from the current byte to get the high 6 bits of a 14-bit offset, read one more byte for the low 8 bits, combine as `struct.unpack(">H", bytes([high_bits]) + next_byte)`. The **first** time a pointer is followed, the buffer position immediately after the 2-byte pointer is remembered in `compression_offset` (only ever the *first* pointer's resume point is kept — nested pointers do not overwrite it, since the code guards with `if compression_offset is None:`). The stream then seeks to `new_offset` and continues parsing labels from there — this is how multi-level compression chains are supported (tested explicitly, see §8's `multi_compressed` fixture). When the loop finally terminates (root label), the buffer is seeked back to `compression_offset` **if a pointer was ever followed**, so the caller's stream cursor lands right after the original (possibly compressed) name rather than wherever the compression chain wandered off to. If no pointer was followed, the buffer is simply left wherever the last real read left it (which is right after the root's zero-length byte).

This is a genuinely stateful, single-pass parser over a seekable stream (`io.BytesIO` in practice) — a Rust port needs either a `Read + Seek` abstraction or an explicit byte-slice-with-cursor type; a plain forward-only reader will not work because of the seek-forward (follow pointer) / seek-back (resume after compressed name) behavior.

### 1.4 Name encoding: `qname_encode` (`pyatv/support/dns.py:71-135`)

No compression is ever emitted by pyatv — this is an unconditional encode-only function, matching the note in its docstring: "Encode QNAME without using name compression."

Two call shapes:
- A `Sequence[str]` (not `str`) is treated as an already-split label list, copied verbatim.
- A plain `str` is first tried against `ServiceInstanceName.split_name` (see §1.6); if that succeeds, the resulting `(instance, service, domain)` triple is re-flattened into `[instance?, *service.split("."), *domain.split(".")]` — this is the mechanism that lets an *instance* label containing literal dots (e.g. `"Dot.Within"`) survive being joined into a single DNS name string and then re-split correctly, because `ServiceInstanceName.split_name` finds the split points by looking for the `_xxx._tcp`/`_xxx._udp` pair rather than blindly splitting on `.`. If `split_name` raises `ValueError` (name isn't a service/service-instance name, e.g. a plain hostname like `"foo.example.com"`), the whole string is naively split on `.`.

After label-list construction:
- A trailing empty label (root) is appended if not already the last element (`if not labels or labels[-1] != "": labels.append("")`).
- Each label is Unicode-**NFC**-normalized (`unicodedata.normalize("NFC", label)`) per RFC 6763 §4.1.3, then UTF-8 encoded (never IDNA on the encode side — IDNA decode-sniffing on `xn--` is decode-only, asymmetric with encoding).
- If an encoded label exceeds 63 bytes, it is truncated **one Unicode codepoint at a time** (decode → drop last char → re-encode → recheck byte length) rather than naively byte-truncating, specifically to avoid splitting a multi-byte UTF-8 codepoint. A warning is logged when this happens (`_LOGGER.warning(...)`, `pyatv/support/dns.py:120-128`).
- Each label is emitted as `[length_byte, ...utf8_bytes]`; hitting a genuinely empty label (`encoded_length == 0`) breaks the loop immediately (treated as the terminal root label; the code comment notes "empty labels ... aren't legal anyways").

### 1.5 `DnsQuestion` (`pyatv/support/dns.py:305-329`)

```python
class DnsQuestion(NamedTuple):
    qname: str
    qtype: QueryType
    qclass: int
```

`pack()` = `qname_encode(qname) + struct.pack(">2H", qtype, qclass)`. Crucially, **the QU (unicast-response-requested) bit is encoded directly in `qclass`, not as a separate flag**: `create_service_queries` in `pyatv/core/mdns.py:79-92` builds every question with `qclass=0x8001` — i.e. `IN` (`0x0001`) with the top bit (`0x8000`) set, which per RFC 6762 §5.4 is the QU bit requesting a unicast reply. Every query pyatv sends — multicast or unicast transport — uses `qclass=0x8001` for **all** questions, including the appended `_sleep-proxy._udp.local` question (§2.2). This is confirmed by the fixture at `tests/core/test_mdns.py:59-65`: `assert question.qclass == 0x8001`.

### 1.6 `DnsResource` (`pyatv/support/dns.py:332-358`)

```python
class DnsResource(NamedTuple):
    qname: str
    qtype: QueryType   # or raw int if unrecognized
    qclass: int
    ttl: int
    rd_length: int
    rd: Any            # parsed per QueryType, see §1.2
```

`unpack_read` reads `qname` (name-compression-aware), then `qtype, qclass, ttl, rd_length` as `struct.unpack(">2HIH", ...)` (2 x u16, 1 x u32, 1 x u16 — TTL is a **32-bit** unsigned field per RFC 1035, note this is bigger than `qtype`/`qclass`/`rd_length`). It then asserts, after calling the type-specific rdata parser, that the buffer cursor advanced by exactly `rd_length` bytes (`assert buffer.tell() == before_rd + rd_length`, `pyatv/support/dns.py:357`) — this is a hard internal consistency check pyatv relies on; a subtly wrong rdata parser (e.g. off-by-one in TXT parsing) will trip this assertion rather than silently corrupt state. **TTL is decoded into the struct but never inspected/enforced anywhere in `core/mdns.py`** — pyatv does not implement TTL-based cache expiry; every discovery run is a fresh in-memory scan with a short (default 4s, see §2.7) window, so record staleness across calls is a non-issue for the current architecture.

### 1.7 `ServiceInstanceName` (`pyatv/support/dns.py:28-68`)

```python
class ServiceInstanceName(NamedTuple):
    instance: Optional[str]
    service: str
    domain: str = "local"
```

`__str__` joins the present components with `.` (`filter(None, self)` drops a `None` instance). `split_name(name)` (`pyatv/support/dns.py:43-63`) walks the dot-split label list looking for a `label.startswith("_")` where the **next** label lower-cased is `"_tcp"` or `"_udp"` — the first such adjacent pair found (scanning left to right) marks the service-type boundary; everything before it becomes the (possibly multi-label, dot-containing) `instance`, the pair itself plus anything after up to that pair is the `service` (e.g. `"_airplay._tcp"`), and everything after is `domain`. If no such pair exists anywhere, `ValueError(f"'{name}' is not a service domain, nor a service instance name")` is raised. This is the mechanism that correctly handles Apple TV instance names containing literal periods (see the `dotted_instance` test fixture in §8). `ptr_name` is `f"{service}.{domain}"` — the bare service name a PTR record answers on.

Edge cases exercised by tests (`tests/support/test_dns.py:11-36`):
- `"_http._tcp.local"` → `(None, "_http._tcp", "local")` — no instance, this is itself a PTR-record-style bare service name.
- `"foo._http._tcp.local"` → `("foo", "_http._tcp", "local")`.
- `"foo.bar._http._tcp.local"` → `("foo.bar", "_http._tcp", "local")` — dotted instance name preserved.
- Bad inputs that raise `ValueError`: `"_http.local"` (no `_proto` label at all), `"._tcp.local"` (empty instance segment before `_tcp` with no leading `_xxx`), `"_http.foo._tcp.local"` (service and proto not adjacent — `_http` then `foo` then `_tcp`, not `_http._tcp`), `"_tcp._http.local"` (reversed order).

### 1.8 TXT record parsing: `parse_txt_dict` (`pyatv/support/dns.py:208-231`)

Reads `length` bytes worth of DNS **character-strings** (`parse_string`, `pyatv/support/dns.py:138-146`: one length byte + that many raw bytes — distinct encoding from domain-name labels, notably **not** subject to the 6-bit-vs-2-bit compression-flag ambiguity; a character-string length byte can legally be up to 255, see the `len_255`/`len_192` fixtures in §8 which specifically prove TXT-string parsing does *not* misinterpret high length bytes as compression pointers).

For each chunk:
- If it contains no `=` byte at all, it's a boolean-present key: `output[decoded_chunk] = b""` (decoded as ASCII).
- Otherwise split on the **first** `=` only (`chunk.split(b"=", 1)`). An empty key (`chunk` starts with `=`) is silently skipped (`if not key: continue`) — the whole entry is dropped, not stored under an empty-string key.
- Keys are decoded strictly as ASCII; a non-ASCII key causes that one entry to be dropped with a debug log (`_LOGGER.debug("Non-ASCII DNS-SD key encountered: %s", key)`), not an exception.
- **Values are never decoded here** — they stay as raw `bytes`. Decoding to `str` (with the non-breaking-space substitution and UTF-8 fallback) happens one layer up in `pyatv/core/mdns.py::decode_value` (§2.1), applied only when a `Service`'s properties are materialized from parsed table entries, not at the raw-TXT-parsing layer.
- The result type is `CaseInsensitiveDict[bytes]` (§ below) — **keys are compared case-insensitively at every layer of pyatv's DNS-SD code**, all the way out to `Service.properties`.

`format_txt_dict` (`pyatv/support/dns.py:199-205`) is the encode side, and it doesn't hand-roll the wire format — it shells out to the third-party `zeroconf.ServiceInfo` class's `.text` property (constructing a throwaway `ServiceInfo("_x.local.", "_x.local.", addresses=[], port=12345, properties=data)` purely to reuse its TXT-encoding logic). This is only used by `dns.py`'s own round-trip tests and by nothing at runtime in the scan path — a Rust port does not need to reproduce `format_txt_dict`'s exact call shape, just the fact that TXT-encoding is length-prefixed `key=value` character-strings, same rules as decode in reverse (this matters for the *pairing* subsystem's zeroconf-service-advertisement code, not for scanning).

### 1.9 SRV rdata: `parse_srv_dict` (`pyatv/support/dns.py:234-246`)

```
priority: u16
weight:   u16
port:     u16
target:   domain-name (name-compression aware, though the RFC forbids compression here — pyatv accepts it anyway, see the inline TODO/comment at dns.py:237-240)
```

Returned as a plain dict, not a dataclass: `{"priority": ..., "weight": ..., "port": ..., "target": ...}`.

### 1.10 `DnsMessage` (`pyatv/support/dns.py:361-448`)

Four record lists: `questions`, `answers`, `authorities`, `resources` (the last is what RFC 1035 calls the Additional section). `unpack(msg: bytes)` reads the header, then exactly `qdcount` questions, `ancount` answers, `nscount` authorities, `arcount` additional records, in that fixed order, and returns `self` (mutates in place — callers do `DnsMessage().unpack(data)`).

`pack()` is **not symmetric with `unpack`** for the answers/authorities/resources sections: for `answers`, `answer.rd` is always treated as a domain name and encoded via `qname_encode(answer.rd)` regardless of the record's actual `qtype` (`pyatv/support/dns.py:421-428`) — this only works correctly because in practice pyatv only ever packs PTR-shaped answers (`rd` is a name string) when constructing synthetic responses for its own tests (`tests/support/dns_utils.py:14-17`, `answer()` always builds a `QueryType.PTR` resource). For `authorities` and `resources`, by contrast, `resource.rd` is packed as raw bytes verbatim (`buf += resource.rd`, `pyatv/support/dns.py:436`) with **no type-specific encoding at all** — the caller is responsible for having already pre-encoded TXT/SRV/A rdata into bytes before appending to those lists. This asymmetry is a pyatv implementation detail (answers get name-encoding for free because that's the only thing pyatv itself ever constructs there; other sections don't). A Rust port's encoder should probably just always take pre-encoded `rd: Bytes` for every section, since pyatv is only ever a *client* generating queries (empty answers/authorities/resources on the wire, see §2.2) — the only place pyatv packs interesting response content is in its own test fixture generator (`tests/fake_udns.py`), which a Rust port only needs for test purposes, not production wire traffic.

`__str__` (`pyatv/support/dns.py:441-448`) formats as `MsgId=0x%04X\nFlags=0x%04X\n...` — useful for structured logging parity but not wire-format-relevant.

---

## 2. `pyatv/core/mdns.py` — the custom mDNS/DNS-SD client

### 2.1 `Service` / `Response` / value decoding

```python
class Service(NamedTuple):          # pyatv/core/mdns.py:39-46
    type: str
    name: str
    address: Optional[IPv4Address]
    port: int
    properties: Mapping[str, str]   # already string-decoded, see decode_value below

class Response(NamedTuple):         # pyatv/core/mdns.py:49-54
    services: List[Service]
    deep_sleep: bool
    model: Optional[str]            # from _device-info._tcp.local's "model" TXT key
```

`decode_value(value: bytes) -> str` (`pyatv/core/mdns.py:60-70`):

```python
def decode_value(value: bytes):
    try:
        return (
            value.replace(b"\xc2\xa0", b" ").replace(b"\x00\xa0", b" ").decode("utf-8")
        )
    except Exception:
        return str(value)
```

Two specific non-breaking-space byte sequences are normalized to a literal ASCII space *before* UTF-8 decoding: `\xc2\xa0` (the correct UTF-8 encoding of U+00A0 NBSP) and `\x00\xa0` (a malformed/legacy two-byte sequence some Apple firmware apparently emits — not valid UTF-8 on its own, hence needing this special case; see the `nbsp` DNS test fixture in §8 which specifically encodes `"Apple\xa0TV (4167)"` using the `\xc2\xa0` form and decode-tests it). If UTF-8 decoding still fails after that substitution for *any* reason (`except Exception` — deliberately broad), the fallback is `str(value)`, i.e. Python's `bytes.__repr__`-like stringification (e.g. `"b'\\xff\\xfe'"`) — this is a lossy, debug-oriented fallback, not a real decode; a Rust port should treat "if not valid UTF-8 after NBSP substitution, produce some human-visible placeholder string" as the contract, without needing to bit-for-bit match Python's `str(bytes)` formatting.

`_decode_properties` (`pyatv/core/mdns.py:73-76`) maps `decode_value` over every value in a `Mapping[str, bytes]` and wraps the result in `CaseInsensitiveDict[str]` — this is where raw TXT bytes (from `dns.parse_txt_dict`) become the string properties exposed on `Service.properties`.

### 2.2 Query construction: `create_service_queries` (`pyatv/core/mdns.py:79-92`)

```python
SERVICES_PER_MSG = 3
SLEEP_PROXY_SERVICE = "_sleep-proxy._udp.local"

def create_service_queries(services: List[str], qtype: QueryType) -> List[bytes]:
    queries = []
    for i in range(math.ceil(len(services) / SERVICES_PER_MSG)):
        service_chunk = services[i*3 : i*3+4]     # NOTE: chunk width is 4, not 3 — see below
        msg = DnsMessage(0x35FF)
        msg.questions += [DnsQuestion(s, qtype, 0x8001) for s in service_chunk]
        msg.questions += [DnsQuestion(SLEEP_PROXY_SERVICE, qtype, 0x8001)]
        queries.append(msg.pack())
    return queries
```

Read this precisely — **the loop increment is 3 but each slice takes 4 elements** (`i*3 : i*3+4`, not `i*3 : i*3+3`). Because the loop count is `ceil(len/3)`, consecutive iterations start 3 apart but each window is 4 wide, so **windows overlap by one element** whenever there is a next chunk — e.g. for 4 services `[A,B,C,D]`: iteration 0 slices `[0:4]` = `[A,B,C,D]` (all four, oops — this means chunk 0 for exactly 4 services actually contains everything), and since `ceil(4/3) = 2`, iteration 1 slices `[3:7]` = `[D]` — so `D` is queried **twice**, once in message 0 (as part of an over-wide 4-element window) and again alone in message 1. This is very likely an off-by-one bug in pyatv (the SERVICES_PER_MSG=3 constant strongly implies the intended slice width is 3, matching the docstring "Number of services to include in each request"), but it is the **actual current behavior on `master`** and must be reproduced for wire-compatibility/test-parity purposes; flagged again in §9. Every message additionally always appends a `_sleep-proxy._udp.local` question regardless of what's being scanned for, meaning **every DNS-SD query pyatv issues, unicast or multicast, always asks about sleep-proxy status alongside the target service(s)**. Message ID is the fixed literal `0x35FF` for every query pyatv builds via this function (not randomized, not incremented). Every question uses `qclass=0x8001` (§1.5).

`SERVICES_PER_MSG=3` is exercised precisely by `tests/core/test_mdns_functional.py:132-143`, which asserts request counts of 1/1/2/3 for service counts 1/3/4/7 respectively — i.e. **exactly `ceil(n/3)` requests are sent no matter the overlap bug**, so the request-count contract is stable even though the actual per-message service *sets* have the one-element duplication described above for `n mod 3 != 0` boundaries. A Rust port should replicate `ceil(n/3)` request count and the sleep-proxy-append-to-every-message behavior faithfully; whether to replicate the exact overlap quirk is a judgment call — see §9.

### 2.3 `ServiceParser` — turning wire records into `Service` objects (`pyatv/core/mdns.py:106-174`)

Two-phase: accumulate raw records from one or more `DnsMessage`s via `add_message`, then materialize `Service` objects via `parse()` (cached until the next `add_message` call invalidates the cache).

`add_message` (`pyatv/core/mdns.py:115-129`) walks `message.answers + message.resources` (**authorities are never consulted** by the parser — only Answer and Additional sections matter for service discovery). For each record:
- If it's a `QueryType.PTR` **and** its qname starts with `_` (i.e. it's a PTR from a bare service type like `_airplay._tcp.local` to a service-instance name, not some other PTR), it's stashed in `self.ptrs[qname] = rd` (a `qname -> real instance name` map) — this is separate bookkeeping from the main per-qname-per-qtype table.
- Everything else (including PTRs whose qname does *not* start with `_`, which in practice shouldn't occur but are treated as regular table entries rather than special PTR bookkeeping) is appended into `self.table[qname][qtype]`, a list, with an explicit dedup check (`if record not in entry[record.qtype]: entry[record.qtype].append(record)`) — `DnsResource` is a `NamedTuple` so structural equality applies, meaning **byte-identical duplicate records across repeated/resent queries are silently coalesced**, verified by `tests/core/test_mdns.py:252-266`.

`parse()` (`pyatv/core/mdns.py:131-174`):
1. For every `qname` key in `self.table` (this is the SRV/TXT/A-keyed table, i.e. keys look like `"ServiceInstance._airplay._tcp.local"`, not bare service types), try `ServiceInstanceName.split_name(qname)`; if it isn't a well-formed service-instance name, **silently skip that table entry entirely** (`except ValueError: continue`) — malformed/unexpected qnames in the table produce no `Service` at all, not an error.
2. Look up the first (only) SRV record for that qname (`_first_rd`, `pyatv/core/mdns.py:102-103` — literally "take element `[0]` of the qtype's record list if present, else `None`"); its `target` field (a domain name string, from `parse_srv_dict`) is where the A record should be.
3. Look up A records at that target name; **filter out `is_link_local` addresses** and take the **first non-link-local address found** — no other selection heuristic (first-seen wins among the non-link-local candidates; `tests/core/test_mdns.py:207-220` explicitly documents that when multiple non-link-local addresses exist, either one is acceptable — the test asserts membership, not a specific index — so don't over-fit a Rust port's address-selection to "first" if you want behavior parity beyond what pyatv itself guarantees). If *all* available A records are link-local, or there are none, `address = None`.
4. Build a `Service(service_name.ptr_name, service_name.instance, address, srv_rd["port"] if srv_rd else 0, decoded TXT properties or {})` and key it by the original table qname (so multiple SRV-bearing table entries produce multiple `Service`s; last-write-wins in `results` if the same qname somehow appears twice at this stage, though duplicate qnames were already deduped one layer down in `add_message`).
5. **Second pass**: for every stashed PTR (`qname -> real_name`), if `real_name` isn't already a key in `results` (i.e. no SRV/TXT data was ever seen for it — a bare PTR answer with nothing else in the response, characteristic of a service-type-only query that got a name back but no further detail, or the specific "unknown/placeholder" shape used for deep-sleep sentinel handling), synthesize a placeholder `Service(qname, real_name.split(".")[0], None, 0, {})` — **address `None`, port `0`, empty properties**, and the "name" is naively the first dot-separated label of the real (fully-qualified instance) name, which is a simplification that does not use `ServiceInstanceName.split_name` and will be wrong for dotted instance names in this fallback path specifically (a documented but likely-intentional simplification since this path only fires for "we got a PTR pointing somewhere but nothing else", i.e. typically a sleep-proxy PTR-only response — see §2.6).

This two-pass, PTR-vs-detail-record split, and the exact fallback/placeholder shape (`address=None, port=0, properties={}`) is the crux of pyatv's downstream `if service.address is None or service.port == 0: return` short-circuit in `core/scan.py::_service_discovered` (§3) — placeholder services from bare PTRs never make it into a scan result on their own.

### 2.4 `UnicastDnsSdClientProtocol` (`pyatv/core/mdns.py:185-270`)

An `asyncio.DatagramProtocol` used for `unicast()`. On `connection_made`, kicks off `_resend_loop`, which — **every second, for `math.ceil(timeout)` iterations** — resends *all* the queries built by `create_service_queries` to the single target host (`transport.sendto(query)`, no destination arg since the transport is already connected via `remote_addr=`). This means for a `timeout=4` unicast scan, up to 4 full rounds of every query message get sent, one round per second, unless a terminal condition fires first.

Termination happens via a semaphore released either when `self.received_responses == len(self.queries)` (every message got at least one reply datagram — not necessarily a *useful* one, just *a* UDP packet counted as a response) inside `datagram_received`, or when the outer `get_response()`'s `asyncio.wait_for(..., timeout=self.timeout)` itself times out. On completion (either path), the resend task is cancelled and the transport closed. `get_response()` (`pyatv/core/mdns.py:199-219`) then calls `self.parser.parse()` and wraps it as a `Response(services=..., deep_sleep=False, model=_get_model(services))` — **note `deep_sleep` is hardcoded `False` for the unicast path**; unicast scanning never detects deep sleep (that's a multicast-only concept tied to sleep-proxy PTR-only-response detection, §2.6).

`_get_model` (`pyatv/core/mdns.py:95-99`) scans the parsed `Service` list for one whose `type == "_device-info._tcp.local"` and returns its `"model"` property if present, else `None` — this is where `Response.model` comes from, independent of which protocol-specific service triggered the scan.

### 2.5 `ReceiveDelegate` (`pyatv/core/mdns.py:273-321`)

A thin `asyncio.DatagramProtocol` wrapper that forwards `datagram_received`/`error_received` to a weakly-referenced delegate (breaking a potential reference cycle with the owning `MulticastDnsSdClientProtocol`). On `connection_made`, it inspects the bound socket's local address and sets `self.is_loopback = ip_address(address).is_loopback` — **loopback-bound sockets never actually send** (`sendto` is a no-op if `is_loopback`, `pyatv/core/mdns.py:282-285`) even though they still receive. This exists so that when `multicast()` opens one socket per local interface plus a wildcard (`None`-bound) socket, only the non-loopback ones actually transmit, avoiding sending the same multicast query out multiple redundant paths through loopback while still allowing the wildcard listener to catch replies.

### 2.6 `MulticastDnsSdClientProtocol` (`pyatv/core/mdns.py:324-484`) and deep-sleep / sleep-proxy handling

Construction takes the full service list, `address` (destination multicast address, default `224.0.0.251`), `port` (default `5353`), and an optional `end_condition: Callable[[Response], bool]` for early termination (defaults to `lambda _: False`, i.e. never early-terminate). One `QueryResponse` (a `SimpleNamespace` with `count`, `deep_sleep`, `parser` fields) is tracked **per responding source IP address** (`self.query_responses: Dict[str, QueryResponse]`, keyed by `addr[0]` — the IP string from the UDP peer tuple).

`_resend_loop(timeout)` (`pyatv/core/mdns.py:385-408`): every second, for `math.ceil(timeout)` iterations, (a) sends every query in `self.queries` to `(self.address, self.port)` (the multicast group) via every registered receiver socket (`_sendto` fans out across all `self._receivers`, respecting each receiver's loopback no-send guard from §2.5), and (b) additionally re-sends any pending **unicast** follow-up queries queued in `self._unicasts` (populated only when a sleep-proxy response was seen, see below) directly to that specific responder's address.

`datagram_received(data, addr)` (`pyatv/core/mdns.py:417-472`) — the core correlation and deep-sleep logic:
1. Look up or create the per-source `QueryResponse` for `addr[0]`.
2. Decode the datagram into a `DnsMessage`, and separately parse it (with a **fresh, message-scoped** `ServiceParser`, not the accumulating per-source one yet) purely to get a preview `services` list for filtering — if decoding raises `UnicodeDecodeError` the whole datagram is dropped with a log line (`log_binary(_LOGGER, "Failed to decode message", ...)`), no partial processing.
3. If the preview parse yields no services at all, silently return (nothing useful in this datagram).
4. **Foreign-service filtering**: for every parsed service, if its `type` is neither one of the originally-requested `self.services` nor one of the two always-implicit types (`DEVICE_INFO_SERVICE = "_device-info._tcp.local"`, `SLEEP_PROXY_SERVICE = "_sleep-proxy._udp.local"`), the **entire datagram is discarded** (a bare `return`, not a per-service filter — one unwanted service type anywhere in the response drops the whole thing). This means a response bundling a wanted and unwanted service type together is entirely ignored, not partially processed.
5. `is_sleep_proxy = all(service.port == 0 for service in services)` — i.e. **every** service parsed out of this datagram reporting `port == 0` is the deep-sleep signal. This correlates directly with the placeholder-service shape from §2.3 step 5 (`port=0` is exactly what a bare-PTR-no-detail synthesized service gets) — a device that's asleep behind a Bonjour sleep proxy answers PTR queries (so you learn a name exists) but has no live SRV/A/TXT records to back it up, so every service in the datagram degenerates to the placeholder shape, and *all* of them being port-0 is the trigger.
6. `query_resp.count += 1; query_resp.deep_sleep |= is_sleep_proxy` (deep_sleep, once set for a source address, stays set for the rest of that scan — it's OR-accumulated across all datagrams from that source) `; query_resp.parser.add_message(decoded_msg)` (now feeding the **persistent**, per-source parser, not the throwaway preview one).
7. **If** `is_sleep_proxy`: queue unicast follow-up queries specifically to that responder, one full `create_service_queries([...], QueryType.ANY)` batch built from `"{service.name}.{service.type}"` for every service just seen (i.e. ask the (probably sleeping) device directly, by its exact instance names, for `ANY` records — a targeted re-query attempting to wake/elicit fuller detail than the generic PTR-shaped multicast query got). This is stored in `self._unicasts[addr[0]]` and picked up by the next `_resend_loop` tick (§ above) — **it is not sent immediately**, only on the next per-second resend cycle.
8. **Else** (not currently flagged sleep-proxy for this datagram) and `query_resp.count >= len(self.queries)` (i.e. this source has now responded to at least as many datagrams as there are outbound query messages — a heuristic for "this source has probably answered everything we asked"): build a `Response` from that source's accumulated parser state, and if an `end_condition` was supplied and it returns `True` for that `Response`, **collapse `self.query_responses` down to just this one source** (`self.query_responses = {addr[0]: self.query_responses[addr[0]]}`), release the semaphore, and close all sockets — early-terminating the entire multicast scan the moment the matching device is found, discarding any other in-flight partial responses from other sources.

`get_response(timeout)` (`pyatv/core/mdns.py:358-383`) races the resend loop against `asyncio.wait_for(self.semaphore.acquire(), timeout=timeout)`; a `TimeoutError` here is caught and treated as normal completion (not re-raised) — timing out just means "stop waiting, use whatever's accumulated so far," never a hard failure. It always closes sockets and cancels the resend task in a `finally`, then materializes one `Response` per source address in `self.query_responses` (§ above `_to_response`), **including sources still flagged `deep_sleep=True`** (a sleeping device that was seen at all still produces a `Response`, with `deep_sleep=True` and whatever `services` its persistent parser accumulated — which will typically be the placeholder, port-0 shape) unless `end_condition` collapsed the map to a single winner.

### 2.7 `unicast()` / `multicast()` entry points (`pyatv/core/mdns.py:487-531`)

```python
async def unicast(loop, address: str, services: List[str], port: int = 5353, timeout: int = 4) -> Response
async def multicast(loop, services: List[str], address: str = "224.0.0.251", port: int = 5353, timeout: int = 4, end_condition=None) -> List[Response]
```

`unicast` opens exactly one connected UDP datagram endpoint to `(address, port)` and returns a single `Response` (or throws if `create_datagram_endpoint` itself fails — no special handling here; `pyatv/core/scan.py`'s caller wraps this in its own `asyncio.TimeoutError` handling, see §3.4).

`multicast` builds one `MulticastDnsSdClientProtocol`, then:
1. Adds **one wildcard socket** bound to `("", 5353)` via `net.mcast_socket(None, 5353)` — this listens on all interfaces on the fixed mDNS port.
2. Adds **one additional socket per local private IPv4 address** (`net.get_private_addresses()`, RFC1918 + loopback, `pyatv/support/net.py:66-77`, enumerated via the third-party `ifaddr` package's `get_adapters()`), each explicitly bound to that address so its outbound multicast packets carry the correct source-interface semantics (`IP_MULTICAST_IF`) — failures per-interface are caught and logged at debug level, not fatal (`except Exception: _LOGGER.debug("Failed to add listener for %s (ignoring)", addr)`).

`net.mcast_socket(address, port=0)` (`pyatv/support/net.py:25-53`) socket options, exactly:
- `AF_INET`, `SOCK_DGRAM`.
- `SO_REUSEADDR = 1`.
- `IP_MULTICAST_TTL = 10` (packed as a signed byte, `struct.pack("b", 10)`).
- `IP_MULTICAST_LOOP = True`.
- `SO_REUSEPORT = 1` if the platform has it (guarded with `hasattr`, so absent on e.g. some Windows builds — noted as a known platform gap in the source comment).
- If `address is not None` (i.e. this isn't the wildcard socket): best-effort (`with suppress(OSError)`) `IP_MULTICAST_IF` set to that address, and best-effort `IP_ADD_MEMBERSHIP` for group `224.0.0.251` + that interface address (**the multicast group membership join is hardcoded to `224.0.0.251`** here regardless of what `address` parameter `multicast()` was called with — a Rust port should note this constant is not actually threaded through from the `multicast()` function's `address` argument at the socket-option layer, only used for the destination of `sendto` calls).
- Finally `sock.bind((address or "", port))`.

`multicast()` returns whatever `MulticastDnsSdClientProtocol.get_response(timeout)` produces — a `List[Response]`, one per distinct responding source IP (unless `end_condition` collapsed it to one).

### 2.8 The `publish()` function (`pyatv/core/mdns.py:534-555`)

Not part of scanning — this is the *server*-side "advertise a service" helper (used by pyatv's own AirPlay-receiver/test-fixture code, and by the pairing subsystem to advertise a temporary pairing service). It delegates entirely to the third-party `zeroconf.Zeroconf.register_service`/`unregister_service`. Out of scope for a scanning port, noted here only because it lives in the same module.

---

## 3. `pyatv/core/scan.py` — device grouping, `conf.AppleTV` construction

### 3.1 Types (`pyatv/core/scan.py:47-56`)

```python
ScanHandlerReturn = Tuple[str, MutableService]                                    # (display name, service)
ScanHandler = Callable[[mdns.Service, mdns.Response], Optional[ScanHandlerReturn]]
DeviceInfoNameFromShortName = Callable[[str], Optional[str]]
ScanHandlerDeviceInfoName = Tuple[ScanHandler, DeviceInfoNameFromShortName]
ScanMethod = Callable[[], Mapping[str, ScanHandlerDeviceInfoName]]                # a protocol module's scan()

DevInfoExtractor = Callable[[str, Mapping[str, Any]], Mapping[str, Any]]          # a protocol module's device_info()
ServiceInfoMethod = Callable[[MutableService, DeviceInfo, Mapping[Protocol, BaseService]], Awaitable[None]]  # service_info()
```

Constants (`pyatv/core/scan.py:58-66`): `DEVICE_INFO = "_device-info._tcp.local"`, `SLEEP_PROXY = "_sleep-proxy._udp.local"`, and

```python
KNOCK_PORTS: List[int] = [3689, 7000, 49152, 32498]
```

with the comment: "These ports have been 'arbitrarily' chosen (see issue #580) because a device normally listen on them (more or less)." — cited directly since this is a load-bearing "we don't fully know why" admission, not a spec'd protocol detail (see §9).

### 3.2 `BaseScanner` (`pyatv/core/scan.py:109-249`)

Registers two implicit "meta" service types up front with no-op handlers (`_empty_handler` returns `None` always, `_empty_extractor` returns `{}` always): `DEVICE_INFO` and `SLEEP_PROXY` — these exist purely so `handle_response` doesn't warn about "unsupported service" when a `_device-info._tcp.local` or `_sleep-proxy._udp.local` service shows up in a response (they're expected companions, not scan targets in their own right; see also `_device_info_name[SLEEP_PROXY] = _sleep_proxy_device_info_name_from_short_name`, `pyatv/core/scan.py:118-120`, which strips the leading `"IEEE-address prefix "` token off a sleep-proxy instance name — `service_name.split(" ", maxsplit=1)[1]` — because sleep-proxy instance names are conventionally formatted like `"70-35-60-63.1 Ohana"`, i.e. `"<proxy-mac-ish-id> <device name>"`, and this extracts just the device-name half to correlate it against other services' device names).

`add_service(service_type, (handler, device_info_name), device_info_extractor)` (`pyatv/core/scan.py:125-134`) — registers a protocol's scan handler, its "how to derive the zeroconf-lookup name for `_device-info._tcp.local` from this service's short name" function, and its device-info extractor, all keyed by DNS-SD service type string.

`add_service_info(protocol, service_info_method)` — registers the post-merge `service_info()` async finisher per `Protocol` enum value (not per service-type string — one per protocol, called once per discovered service of that protocol after all services for a device have been merged into one `conf.AppleTV`).

`discover(timeout)` (`pyatv/core/scan.py:147-177`) is the top-level orchestration:
1. `await self.process(timeout)` — subclass-specific (unicast/multicast/zeroconf), populates `self._found_devices` and `self._properties`.
2. For each address in `self._found_devices`: compute `device_info = self._get_device_info(found_device)` (§3.3), construct `conf.AppleTV(address, found_device.name, deep_sleep=found_device.deep_sleep, properties=self._properties[address], device_info=device_info)`, then `add_service(...)` every `MutableService` collected for that address.
3. **Crucially**, `service_info()` is applied **after** all services for a device have been added (comment: "Apply service_info after adding all services in case a merge happens" — a merge can happen if two different mDNS service types both mapped to the same `Protocol`, e.g. two AirPlay-shaped records for one device, causing `BaseService.merge` to run mid-`add_service`, §4.4) — so every `service_info` call sees the final, merged `properties`/`credentials` state of its service, plus a `properties_map: Mapping[Protocol, BaseService]` snapshot of *all* the device's other services (this is how e.g. RAOP's `service_info` can read the sibling AirPlay service's `acl`/`act` properties, §7.4).

`handle_response(response)` (`pyatv/core/scan.py:183-197`) is the fan-in point both the unicast and multicast scanners funnel raw `mdns.Response`s through: for every `service` in `response.services`, if `service.type` was never registered via `add_service`, log a warning (`"Discovered unsupported service %s for device %s"`) and skip; otherwise delegate to `_service_discovered`, wrapped in a broad `except Exception: _LOGGER.exception(...)` so **one malformed service never aborts processing of the rest of the response**.

`_service_discovered(service, response)` (`pyatv/core/scan.py:199-231`):
1. **Hard gate**: `if service.address is None or service.port == 0: return` — a service with no resolvable address or a zero port (the placeholder/deep-sleep shape from §2.3/§2.6) is recorded **nowhere at all**, not even in `self._properties`. This is why deep-sleep devices only surface via the `Response.deep_sleep` flag rather than by having a normal service entry — the actual `Service` objects for a sleeping device get filtered out entirely at this gate, and a scan result for a sleeping device typically has zero services but `deep_sleep=True` and a `name` derived purely from whatever the multicast-scan machinery's device-name correlation could infer (in practice, this means a *pure* sleep-proxy hit with nothing else rarely produces a usable `conf.AppleTV` at all through this code path — see §9).
2. Calls the protocol's registered `ScanHandler(service, response)`. If it returns a non-`None` `(name, base_service)` tuple: log the discovery at debug level (including all of `service.properties`), then either create a brand-new `FoundDevice` for `service.address` (if this is the first service seen at that address — `name` here becomes the device's provisional display name, `deep_sleep=response.deep_sleep`, `model=lookup_internal_name(response.model)`, i.e. **the internal-Apple-model-name lookup table (§5), not the public-facing `_MODEL_LIST`, is what's applied to `Response.model`** — this matters because `_device-info._tcp.local`'s `model` TXT value is typically an *internal* codename like `J305AP`, not the public `AppleTV11,1` form used by e.g. AirPlay's `model` property) or append to the existing `FoundDevice.services` list for that address.
3. **Independently** of whether the handler returned a service (even if it returned `None`, meaning "this service type doesn't map to a usable `MutableService`" — DMAP's sub-service-types with `lambda _: None` device-info-name functions, §7.5, or AirPlay's `_airport._tcp.local` entry, §7.4, are examples), `self._properties[address][service.type] = service.properties` is **always** recorded (`pyatv/core/scan.py:227-231`) as long as `service.address is not None` (already guaranteed by the gate above). This is the mechanism by which e.g. `_airport._tcp.local`'s `wama`/MAC-address TXT data reaches RAOP's `device_info()` extractor even though that service type's `ScanHandler` deliberately returns `None` (never contributes an actual `MutableService`/protocol) — properties get attached to the device regardless of whether a service was "found" in the protocol sense.

`_get_device_info(device: FoundDevice) -> DeviceInfo` (`pyatv/core/scan.py:233-249`) — the merge point for device-info extraction:
1. Iterate `self._properties[device.address].items()` — i.e. **every service type that ever posted properties for this address**, not just ones that produced a `MutableService`.
2. For each, look up its registered `(handler, extractor)` pair (falling back to nothing if the service type was somehow never registered — shouldn't happen given the gating in `handle_response`) and call `extractor(service_type, service_properties)`, merging the resulting dict into an accumulator via `dict_merge(device_info, extractor_result)` — **`dict_merge` never overwrites an existing key** (`pyatv/support/collections.py:11-28`, `allow_overwrite=False` by default) — so **iteration order over `self._properties[device.address].items()` determines precedence when two service types' extractors claim the same `DeviceInfo` field**, and dict iteration order is Python's guaranteed insertion order, i.e. **whichever service type's properties were recorded first (first `_service_discovered` call for that address) wins any key conflict.** This is a subtle, response-arrival-order-dependent precedence rule — not a documented priority table — and needs to be called out explicitly to a Rust porter: there is no static "AirPlay overrides RAOP overrides MRP" table; it's "whichever mDNS response for this address's services was processed by `_service_discovered` first."
3. Finally, if `device.model != DeviceModel.Unknown` (i.e. `_device-info._tcp.local`'s `model` TXT value matched something in the **internal-name** lookup table, §5), `dict_merge(device_info, {DeviceInfo.MODEL: device.model}, )` is applied **without `allow_overwrite`**, meaning if some other protocol's extractor already set `DeviceInfo.MODEL` (e.g. AirPlay's own `model` property, decoded via the public `_MODEL_LIST`), that earlier value wins and the `_device-info._tcp.local` internal-name-derived model is silently discarded. So there are, in total, **two independent, differently-keyed model lookup tables in play** (`_MODEL_LIST` keyed by public model strings like `AppleTV11,1`, used by AirPlay/Companion/RAOP extractors; `_INTERNAL_NAME_LIST` keyed by internal codenames like `J305AP`, used only via `_device-info._tcp.local`'s `model` TXT key at the `BaseScanner` level) and the first one to produce a non-`Unknown` result, in service-discovery order, wins.

### 3.3 `UnicastMdnsScanner` (`pyatv/core/scan.py:252-289`)

`process(timeout)` fans `self._get_services(host, timeout)` out over `asyncio.gather` for every configured host, then feeds each resulting `Response` through `handle_response`. `_get_services` (`pyatv/core/scan.py:272-289`):

```python
port = int(os.environ.get("PYATV_UDNS_PORT", 5353))   # test-only override hook
knocker = await knock.knocker(host, KNOCK_PORTS, self.loop, timeout=timeout)
try:
    response = await mdns.unicast(self.loop, str(host), self.services, port=port, timeout=timeout)
except asyncio.TimeoutError:
    response = mdns.Response([], False, None)
finally:
    knocker.cancel()
```

The port-knock (§6) is fired **before** the DNS query and only cancelled (not necessarily awaited to completion) once the DNS response comes back or the DNS call itself times out. A DNS-level `asyncio.TimeoutError` degrades to an empty `Response`, not a scan-aborting exception — one unreachable unicast host never fails the whole `asyncio.gather`.

### 3.4 `MulticastMdnsScanner` (`pyatv/core/scan.py:292-321`)

Takes an optional `identifier: Union[str, Set[str]]`; if given, it's normalized to a `Set[str]` and used to build `self._end_if_identifier_found`, wired as `mdns.multicast`'s `end_condition`. `_end_if_identifier_found(response)` (`pyatv/core/scan.py:318-321`) returns `True` the moment `get_unique_identifiers(response)` (§3.5) yields **any** identifier present in the wanted set — i.e. multicast scanning with a specific identifier target will terminate as soon as *any one* service on the matching device reports a recognized unique ID, not waiting for every requested service type to respond. This is the mechanism behind "scan for this one Apple TV and stop early" used by `pyatv.scan(identifier=...)`.

### 3.5 `get_unique_identifiers` (`pyatv/core/scan.py:89-96`)

```python
def get_unique_identifiers(response: mdns.Response) -> Generator[Optional[str], None, None]:
    for service in response.services:
        unique_id = get_unique_id(service.type, service.name, service.properties)
        if unique_id:
            yield unique_id
```

Delegates to `pyatv.helpers.get_unique_id` (§7.6 below covers the full per-service-type table) — this is intentionally the *same* identifier-derivation function used both for early-multicast-termination and for populating `MutableService.identifier` inside each protocol's scan handler, so "the identifier the scanner uses to decide it found what it's looking for" and "the identifier that ends up on the resulting service" are guaranteed to be the same value.

### 3.6 The `Zeroconf*` scanner family (`pyatv/core/scan.py:324-678`)

Documented for completeness (see the intro to §2). `ZeroconfScanner` is an abstract base sharing `_process_responses`/`process`/`_process_service_info_responses` with two concrete subclasses:

- `ZeroconfMulticastScanner` (`pyatv/core/scan.py:504-524`): builds `AsyncServiceInfo` queries for every registered service type (plus a synthetic `_device-info` lookup keyed off each resolved device's short name, `_build_service_info_queries`, `pyatv/core/scan.py:403-426`) by scanning the *already-populated* `zeroconf` cache for PTR records of those types, and only issues live `async_request` calls for anything not already cache-resident (`info.load_from_cache(zeroconf, now)`).
- `ZeroconfUnicastScanner` (`pyatv/core/scan.py:527-678`): tracks per-`(host, service-type)` completion state explicitly; if cache lookups don't fully resolve every requested type for every host, it manually crafts and sends unicast PTR `DNSQuestion`s (`question.unicast = True`, `_send_ptr_queries`, `pyatv/core/scan.py:549-559`) as a fallback for "multicast is broken or device is offline," then re-polls the cache after a fixed `await asyncio.sleep(zc_timeout / 1000)` wait with no further signal of completion (there's no callback-driven "the PTR response arrived" hook here — it's a flat sleep-then-recheck).

Both eventually call `self.handle_response(mdns.Response(services=..., deep_sleep=..., model=...))` per address (`_process_responses`, `pyatv/core/scan.py:428-444`), reusing exactly the same `BaseScanner.handle_response`/`_service_discovered`/`_get_device_info` pipeline as the custom-codec scanners — meaning **everything in §3.1–3.5 (the per-protocol handler dispatch and precedence rules) applies identically regardless of which underlying transport produced the `Response`.** `deep_sleep` for the zeroconf path is inferred structurally rather than via a sleep-proxy TXT/port convention read from the wire directly: `all(service.port == 0 and service.type != SLEEP_PROXY_TYPE for service in dev_services)` (`pyatv/core/scan.py:438-441`) — i.e. every non-sleep-proxy service reporting port 0 is the same "all placeholder" signal as §2.6, just computed over `zeroconf`'s own resolved `AsyncServiceInfo` objects instead of pyatv's own parsed `DnsResource`s.

A Rust port targeting the custom-codec path (recommended, per the intro) does not need to replicate this class family's internals, only be aware that a production-grade pyatv-compatible scanner conceptually has this second transport option, and that both must land on identical `BaseScanner` semantics.

---

## 4. `pyatv/conf.py` + `pyatv/interface.py` + `pyatv/core/__init__.py` — the config/service model

### 4.1 `conf.AppleTV` (`pyatv/conf.py:17-96`, implements `interface.BaseConfig`)

Constructor: `(address: IPv4Address, name: str, deep_sleep: bool = False, properties: Optional[Mapping[str, Mapping[str, str]]] = None, device_info: Optional[DeviceInfo] = None)`. Internally holds `self._services: Dict[Protocol, BaseService]` — **exactly one service per `Protocol` enum value**, never a list.

`add_service(service)` (`pyatv/conf.py:56-65`): if a service already exists for `service.protocol`, call `existing.merge(service)` (§4.4); otherwise store it as-is. **This is the only merge trigger in the whole config model** — a device that announces two different mDNS service types both mapping to the same `Protocol` (the realistic case: nothing in the five built-in protocols does this by default, but a custom/future protocol handler that emits two `MutableService`s for one `Protocol` would trigger it) gets silently merged, keeping the *first*-added service's identity/port/pairing/enabled-flag and only absorbing the second's credentials/password/properties (§4.4) — **the second service's port, identifier, and pairing requirement are always discarded.**

`__deepcopy__` (`pyatv/conf.py:85-96`) rebuilds a fresh `AppleTV` with the same primitive fields, then deep-copies each service in.

### 4.2 `interface.BaseConfig` (`pyatv/interface.py:1320-1461`)

- `ready` (`pyatv/interface.py:1378-1384`): `True` iff **any** attached service has a non-`None` `identifier` — a device with services but no identifiers anywhere (all failed identifier extraction) is not "ready" and gets filtered out of `pyatv.scan()`'s results by the `_should_include` predicate (`pyatv/__init__.py:48-56`).
- `identifier` (`pyatv/interface.py:1386-1400`): returns the identifier of the **first** service found, in the fixed priority order `[MRP, DMAP, AirPlay, RAOP, Companion]`, whose `identifier` is not `None`. Note this list's order **differs** from `main_service`'s priority order below (Companion is last here but entirely absent from `main_service`'s list) — these are two independently-authored priority lists, not a single shared constant; do not conflate them in a port.
- `all_identifiers` (`pyatv/interface.py:1401-1404`): every attached service's `identifier`, filtered to non-`None`, in service-dict iteration order (Python 3.7+ dict order = protocol-insertion order via `add_service` calls) — **not** sorted, **not** deduplicated (though in practice different protocols' identifiers are rarely literally identical strings).
- `main_service(protocol=None)` (`pyatv/interface.py:1405-1421`): if `protocol` is given, returns exactly that service (or raises `exceptions.NoServiceError`). Otherwise walks `[MRP, DMAP, AirPlay, RAOP]` — **Companion is never a candidate main/connection service**, consistent with Companion being an auxiliary control-channel protocol, not a primary connection target — returning the first one present.
- `apply(settings: Settings)` (`pyatv/interface.py:1428-1440`): dispatches `service.apply(dict(settings.protocols.<name>))` per-protocol (AirPlay/Companion/DMAP/MRP/RAOP), i.e. persisted settings are applied *after* scanning, once per protocol, using each protocol's own settings sub-namespace.
- `__eq__` (`pyatv/interface.py:1442-1446`): **identity is defined purely by `self.identifier == other.identifier`** (only if `other` is an instance of the same concrete class) — two `AppleTV` configs are equal iff their derived main identifier strings match, regardless of address, name, or any service detail. An identifier of `None` on both sides would compare equal under this rule (not explicitly guarded against) — a latent footgun worth flagging (§9).
- `__str__` (`pyatv/interface.py:1448-1461`) — the exact format the CLI's `atvremote scan` output (and anything calling `print(config)`) renders, worth reproducing verbatim for CLI parity:

```
       Name: {self.name}
   Model/SW: {device_info}
    Address: {self.address}
        MAC: {self.device_info.mac}
 Deep Sleep: {self.deep_sleep}
Identifiers:
 - {id1}
 - {id2}
Services:
 - {service1}
 - {service2}
```

where `device_info` is `DeviceInfo.__str__` (§4.6) and each `- {service}` line is `BaseService.__str__` (§4.3).

### 4.3 `interface.BaseService` (`pyatv/interface.py:141-238`)

Constructor fields: `identifier: Optional[str]`, `protocol: Protocol`, `port: int`, `properties: Optional[Mapping[str, str]]` (defensively copied into a mutable `dict`), `credentials: Optional[str] = None`, `password: Optional[str] = None`, `enabled: bool = True`. `requires_password` and `pairing` are `@property @abstractmethod` — every concrete subclass (`ManualService` in `conf.py`, `MutableService` in `core/__init__.py`) must supply its own storage/logic for those two fields; there is no shared default.

`settings()`/`apply(settings)` (`pyatv/interface.py:214-227`) round-trip **only** `credentials` and `password` — this is the persistence contract used by `Storage`/`get_settings`, not a general config-serialization mechanism. `apply` treats an absent or falsy (`None`/empty-string) incoming value as "keep the existing value" (`settings.get("credentials") or self.credentials` — note this means an explicit empty-string credential in storage is indistinguishable from "no override," which is presumably intentional but worth flagging for a Rust port choosing `Option<String>` semantics, §9).

`__str__` (`pyatv/interface.py:229-238`):
```
Protocol: {protocol}, Port: {port}, Credentials: {credentials}, Requires Password: {requires_password}, Password: {password}, Pairing: {pairing.name}
```
with a literal `" (Disabled)"` suffix appended iff `not enabled`.

### 4.4 `merge` — the exact and complete precedence rule (`pyatv/interface.py:203-212`)

```python
def merge(self, other) -> None:
    """Merge with other service of same type.

    Merge will only include credentials, password and properties.
    """
    self.credentials = other.credentials or self.credentials
    self.password = other.password or self.password
    self._properties.update(other.properties)
```

This is the **entire** merge contract, and it is deliberately narrower than a naive reading of the task might assume: **`identifier`, `port`, `pairing`, and `enabled` are never touched by `merge` at all** — they stay whatever the first-added service (the one already present in `conf.AppleTV._services` before `add_service` was called again for the same protocol) had. Only `credentials` (other's value wins if truthy, else keep existing — falsy/`None`/empty-string values never overwrite), `password` (same rule), and `properties` (a **plain dict `.update()`** — `other`'s keys always win on conflict, unlike `credentials`/`password`'s "only if truthy" guard, and this is a case-sensitive plain-`dict` update even though `properties` is typically populated from a `CaseInsensitiveDict` upstream — mixing key-casing conventions across two merged property sets could in principle produce two differently-cased keys for what was semantically "the same" TXT key, though in practice this would only bite if two *different* mDNS records disagreed on TXT-key casing for the same logical key, which the case-insensitive layers upstream (§1.8, §2.1) are specifically designed to normalize before this point).

`MutableService` (`pyatv/core/__init__.py:114-171`) is `BaseService` plus settable `requires_password`/`pairing` properties (backed by private fields defaulting to `False`/`PairingRequirement.Unsupported` respectively) — this is what every protocol's `*_service_handler` actually constructs (never `ManualService` directly during scanning; `ManualService` in `conf.py` is the user-facing manual-construction API, functionally near-identical but with `requires_password`/`pairing` fixed at construction time instead of mutable). `MutableService.__deepcopy__` explicitly copies `pairing`/`requires_password` post-construction since the constructor itself doesn't accept them.

### 4.5 `ManualService` (`pyatv/conf.py:99-143`)

Same field set as `MutableService` but `requires_password`/`pairing_requirement` are constructor arguments (defaults `False`/`PairingRequirement.Unsupported`) fixed for the object's lifetime — used for user-authored manual configs (`AppleTV.add_service(ManualService(...))`), not scan output.

### 4.6 `interface.DeviceInfo` (`pyatv/interface.py:952-1069`)

```python
class DeviceInfo:
    OPERATING_SYSTEM = "os"
    VERSION = "version"
    BUILD_NUMBER = "build_number"
    MODEL = "model"
    RAW_MODEL = "raw_model"
    MAC = "mac"
    OUTPUT_DEVICE_ID = "airplay_id"
```

These string constants are the keys every protocol's `device_info()` extractor writes into its returned `Dict[str, Any]`, later merged (§3.2) into one dict and passed to `DeviceInfo.__init__`. **There is no separate `MODEL_STR` constant** — `model_str` is a derived property (below), not a settable field; anything cited in the task prompt as "OUTPUT_DEVICE_ID?" is confirmed present and equal to the string `"airplay_id"` (not `"output_device_id"` — the wire-facing/settings key and the Python constant name diverge).

`__init__(device_info: Mapping[str, Any])` (`pyatv/interface.py:961-971`) **pops** (mutates!) each of the six recognized keys out of the passed-in mapping via `_pop_with_type(field, default, expected_type)` (`pyatv/interface.py:973-980`), which enforces `isinstance(value, expected_type)` **or** `value is None`, raising `TypeError(f"expected {expected_type} for '{field}'' but got {type(value)}")` on a type mismatch (note the literal doubled single-quote typo `'{field}''` in the f-string — reproduced here verbatim since it'd show up in any error-message-matching test). Defaults: `OPERATING_SYSTEM -> OperatingSystem.Unknown`, `VERSION -> None`, `BUILD_NUMBER -> None`, `MODEL -> DeviceModel.Unknown`, `MAC -> None`, `OUTPUT_DEVICE_ID -> None`. Any keys in the input mapping *other* than these six (notably `RAW_MODEL`) are **left in the mapping**, not popped, and accessed later via plain `.get()` (see `raw_model` below) — so `DeviceInfo` retains a residual reference to (a subset of) its constructor input for those extra fields, a small stateful-object design worth flagging for a Rust port (an immutable struct with all fields resolved at construction time is the natural translation, no need to replicate the pop-and-retain mutation).

Derived properties:
- `operating_system` (`pyatv/interface.py:982-1001`): if an explicit `OPERATING_SYSTEM` was supplied and isn't `Unknown`, return it verbatim. Otherwise **infer purely from `model`**: `{AirPortExpress, AirPortExpressGen2} -> AirPortOS`; `{HomePod, HomePodMini} -> TvOS` (note: **`HomePodGen2` is *not* in this particular inference list**, even though it *is* included in the separate `lookup_os` free function in `support/device_info.py`, §5 — a real, source-verified inconsistency, flagged again in §9); `{Gen2, Gen3, Gen4, Gen4K, AppleTV4KGen2, AppleTV4KGen3} -> TvOS` (note **`AppleTVGen1` is *not* in this inference list either**, unlike `lookup_os`'s `Legacy` classification for it — another real inconsistency between this method and `support/device_info.lookup_os`, see §9); anything else falls through to `Unknown`.
- `version` (`pyatv/interface.py:1003-1013`): explicit value if set, else `lookup_version(self.build_number)` (§5) if that produces something, else `None`.
- `build_number`: plain passthrough of the popped value.
- `model`: plain passthrough (already coerced to `DeviceModel` by `_pop_with_type`).
- `raw_model` (`pyatv/interface.py:1024-1030`): `self._devinfo.get(DeviceInfo.RAW_MODEL)` — reads directly from whatever's left in the retained mapping (never popped at construction, see above), so this is the **only** `DeviceInfo` property that isn't resolved once at construction time; it's read lazily on every access (functionally equivalent for immutable callers, but technically re-reads a mutable dict each time).
- `model_str` (`pyatv/interface.py:1032-1042`): `raw_model` **iff** `model == DeviceModel.Unknown and raw_model` (both conditions), else `convert.model_str(self.model)` (a `pyatv.convert` lookup table mapping `DeviceModel` enum values to their public display strings — out of scope for this discovery spec but noted as the fallback path).
- `mac`, `output_device_id`: plain passthroughs.
- `__str__` (`pyatv/interface.py:1059-1077`): `f"{model_str}, {os_display_name}"` where `os_display_name` is looked up from a small inline dict (`{Legacy: "ATV SW", TvOS: "tvOS", AirPortOS: "AirPortOS", MacOS: "MacOS"}`, defaulting to `"Unknown OS"` for `Unknown` or any future enum value not in the dict), then conditionally appends `" " + version` if `version` is truthy, then conditionally appends `" build " + build_number` if `build_number` is truthy.

---

## 5. `pyatv/support/device_info.py` — the lookup tables, verbatim

Reproduced in full since the task requires exact reproduction (`pyatv/support/device_info.py:8-24` for `_MODEL_LIST`, `27-35` for `_INTERNAL_NAME_LIST`, `38-89` for `_VERSION_LIST`, `91-98` for `_OS_IDENTIFIER_FORMATS`).

### 5.1 `_MODEL_LIST` — public model-identifier string → `DeviceModel` (keyed by e.g. AirPlay's `model` TXT property or Companion's `rpmd` property)

```python
_MODEL_LIST: Dict[str, DeviceModel] = {
    "AirPort4,107": DeviceModel.AirPortExpress,
    "AirPort10,115": DeviceModel.AirPortExpressGen2,
    "AppleTV1,1": DeviceModel.AppleTVGen1,
    "AppleTV2,1": DeviceModel.Gen2,
    "AppleTV3,1": DeviceModel.Gen3,
    "AppleTV3,2": DeviceModel.Gen3,
    "AppleTV5,3": DeviceModel.Gen4,
    "AppleTV6,2": DeviceModel.Gen4K,
    "AppleTV11,1": DeviceModel.AppleTV4KGen2,
    "AppleTV14,1": DeviceModel.AppleTV4KGen3,
    "AudioAccessory1,1": DeviceModel.HomePod,
    "AudioAccessory1,2": DeviceModel.HomePod,
    "AudioAccessory5,1": DeviceModel.HomePodMini,
    "AudioAccessorySingle5,1": DeviceModel.HomePodMini,
    "AudioAccessory6,1": DeviceModel.HomePodGen2,
}
```

`lookup_model(identifier: Optional[str]) -> DeviceModel` (`pyatv/support/device_info.py:101-103`): `_MODEL_LIST.get(identifier or "", DeviceModel.Unknown)` — a `None` input is coerced to `""` before lookup (never crashes on `None`), and any miss (including the empty-string case) returns `DeviceModel.Unknown`.

### 5.2 `_INTERNAL_NAME_LIST` — internal Apple codename → `DeviceModel` (keyed only by `_device-info._tcp.local`'s `model` TXT property, §3.2)

```python
_INTERNAL_NAME_LIST: Dict[str, DeviceModel] = {
    "K66AP": DeviceModel.Gen2,
    "J33AP": DeviceModel.Gen3,
    "J33IAP": DeviceModel.Gen3,
    "J42dAP": DeviceModel.Gen4,
    "J105aAP": DeviceModel.Gen4K,
    "J305AP": DeviceModel.AppleTV4KGen2,
    "J255AP": DeviceModel.AppleTV4KGen3,
}
```

`lookup_internal_name(name: Optional[str]) -> DeviceModel` (`pyatv/support/device_info.py:106-108`): same `or ""` / `Unknown`-on-miss pattern as `lookup_model`. Note this table is strictly **smaller** than `_MODEL_LIST` (no AirPort/HomePod/Gen1 entries at all) — internal-codename resolution is only meaningfully populated for the Gen2 through AppleTV4KGen3 Apple TV line.

### 5.3 `_VERSION_LIST` — exact build number → dotted version string (reproduced verbatim, all 68 entries)

```python
_VERSION_LIST: Dict[str, str] = {
    "17J586": "13.0",
    "17K82": "13.2",
    "17K449": "13.3",
    "17K795": "13.3.1",
    "17L256": "13.4",
    "17L562": "13.4.5",
    "17L570": "13.4.6",
    "17M61": "13.4.8",
    "18J386": "14.0",
    "18J400": "14.0.1",
    "18J411": "14.0.2",
    "18K57": "14.2",
    "18K561": "14.3",
    "18K802": "14.4",
    "18L204": "14.5",
    "18L569": "14.6",
    "18M60": "14.7",
    "19J346": "15.0",
    "19J572": "15.1",
    "19J581": "15.1.1",
    "19K53": "15.2",
    "19K547": "15.3",
    "19L440": "15.4",
    "19L452": "15.4.1",
    "19L570": "15.5",
    "19L580": "15.5.1",
    "19M65": "15.6",
    "20J373": "16.0",
    "20K71": "16.1",
    "20K80": "16.1.1",
    "20K362": "16.2",
    "20K650": "16.3",
    "20K661": "16.3.1",
    "20K672": "16.3.2",
    "20K680": "16.3.3",
    "20L497": "16.4",
    "20L498": "16.4.1",
    "20L563": "16.5",
    "20M73": "16.6",
    "22J354": "17.0",
    "21K69": "17.1",
    "21K365": "17.2",
    "21K646": "17.3",
    "21L227": "17.4",
    "21L569": "17.5",
    "21L580": "17.5.1",
    "21M71": "17.6",
    "21M80": "17.6.1",
    "22J357": "18.0",
    "22J580": "18.1",
}
```

**Note the out-of-order build-number-prefix anomaly at `"22J354": "17.0"`** — every other tvOS-17.x build starts with the `21*` prefix (`21K69`, `21K365`, ...) consistent with the fallback-formula's `base - 4` rule (§5.4: `21 - 4 = 17`), but `17.0` itself is keyed to a build starting `22`, which under the fallback formula would compute to `22 - 4 = 18.x`, not `17.x`. This is a literal, verbatim-reproduced entry in pyatv `master` as of the pinned commit — almost certainly either a genuine Apple build-numbering quirk for the 17.0 release specifically, or a transcription slip upstream, but it is **exact-match table data pyatv ships and tests against implicitly** (there's no dedicated unit test asserting this specific entry, but `lookup_version` is a simple dict-then-regex function so any port must include this literal mapping to stay behaviorally identical for that one build string). Flagged again in §9 as a "verify against real device, don't just trust the table" item.

`lookup_version(build: Optional[str]) -> Optional[str]` (`pyatv/support/device_info.py:111-127`):
```python
if not build:
    return None
version = _VERSION_LIST.get(build or "")
if version:
    return version
match = re.match(r"^(\d+)[A-Z]", build)
if match:
    base = int(match.groups()[0])
    return str(base - 4) + ".x"
return None
```
Exact-match table lookup first; on a miss, regex-extract the leading digit run before the first uppercase letter (e.g. `"17F123"` → base `17`) and compute `str(base - 4) + ".x"` (comment: "17A123 corresponds to tvOS 13.x, 16A123 to tvOS 12.x and so on" — i.e. **tvOS major version = Darwin-build major number − 4**, a rough heuristic, not exact-point-release-accurate, hence the trailing literal `".x"`). If the regex doesn't even match (build string doesn't start with digits-then-uppercase-letter), returns `None`.

### 5.4 `_OS_IDENTIFIER_FORMATS` and `lookup_os` (`pyatv/support/device_info.py:91-98, 130-162`)

```python
_OS_IDENTIFIER_FORMATS = [
    r"MacBookAir\d+,\d+",
    r"iMac\d+,\d+",
    r"Macmini\d+,\d+",
    r"MacBookPro\d+,\d+",
    r"Mac\d+,\d+",
    r"MacPro\d+,\d+",
]
```

`lookup_os(id_or_model: Union[str, DeviceModel]) -> OperatingSystem` — dual-mode by argument type:
- If passed a **string** (an "internal identifier" shape like `"MacBookAir10,1"`, distinct from both `_MODEL_LIST` and `_INTERNAL_NAME_LIST` keys): `MacOS` iff `any(re.match(fmt, id_or_model) for fmt in _OS_IDENTIFIER_FORMATS)` (note `re.match`, not `re.fullmatch` — a prefix match; e.g. `"iMac1,2extra"` would still match `iMac\d+,\d+` since nothing anchors the end), else `Unknown`. **The regex order matters for anchoring semantics between `Mac\d+,\d+` and the more specific `MacBookAir\d+,\d+`/`MacBookPro\d+,\d+`/`MacPro\d+,\d+` forms** — but since this function only needs *any* match (`any(...)`, not first-match priority), and `Mac\d+,\d+` alone would also match e.g. `"MacBookAir10,1"`.startswith-wise... actually **`re.match` anchors only at the start**, so `Mac\d+,\d+` against `"MacBookAir10,1"` fails immediately (the literal characters after `Mac` in the pattern are `\d`, but the string continues `BookAir...`, not a digit) — so there's no actual overlap/redundancy bug here, just worth noting the six patterns are independent, non-overlapping prefix checks in practice, evaluated via `any()` with no defined short-circuit-order dependency that matters.
- If passed a **`DeviceModel`**: `{AirPortExpress, AirPortExpressGen2} -> AirPortOS`; `{HomePod, HomePodMini, HomePodGen2} -> TvOS` (this variant **does** include `HomePodGen2`, unlike `DeviceInfo.operating_system`'s inline inference table, §4.6 — a confirmed divergence); `{AppleTVGen1, Gen2, Gen3} -> Legacy` (this variant **does** classify `AppleTVGen1` as `Legacy`, also unlike `DeviceInfo.operating_system`'s inference which omits it entirely, defaulting it to `Unknown` there); `{Gen4, Gen4K, AppleTV4KGen2, AppleTV4KGen3} -> TvOS`; anything else `Unknown`.

`lookup_os` is called directly by AirPlay's and RAOP's `device_info()` extractors (§7.4, §7.5) with a raw model-identifier **string** (not a `DeviceModel`), so the string branch above — the six `_OS_IDENTIFIER_FORMATS` regexes — is the one actually exercised at scan time in the discovery path; the `DeviceModel`-keyed branch exists for other, non-discovery call sites and for the unit tests in `tests/support/test_device_info.py:51-76` (§8) which exercise both branches explicitly.

---

## 6. `pyatv/support/knock.py` — TCP port-knocking to wake sleeping devices

Full module (`pyatv/support/knock.py:1-79`), reproduced behaviorally:

```python
_ABORT_KNOCK_ERRNOS = {errno.EHOSTDOWN, errno.EHOSTUNREACH}
_SLEEP_AFTER_CONNECT = 0.1
_KNOCK_TIMEOUT_BUFFER = _SLEEP_AFTER_CONNECT * 2   # = 0.2
```

`_async_knock(address, port, timeout)` (`pyatv/support/knock.py:24-43`): open a plain TCP connection (`asyncio.open_connection`) with `asyncio.wait_for(..., timeout=timeout)`. On success, `await asyncio.sleep(0.1)` (give the remote a brief window to react to the connection before tearing it down) then close the writer in a `finally`. `asyncio.TimeoutError` is swallowed silently (the port simply didn't respond in time — not an error condition for knocking purposes). A generic `OSError` is swallowed **unless** its `errno` is `EHOSTDOWN` or `EHOSTUNREACH`, in which case it's **re-raised** — those two specific errno values mean the host itself is unreachable at the network layer, a signal worth propagating up (short-circuiting further knock attempts is the intent, since if the host is unreachable, no port will ever respond either), whereas connection-refused/reset and other per-port failures are expected and ignored.

`knock(address, ports, timeout)` (`pyatv/support/knock.py:46-65`): computes `knock_runtime = timeout - _KNOCK_TIMEOUT_BUFFER` (i.e. each individual port-knock's own timeout is 0.2s shorter than the overall budget, leaving headroom for the final `asyncio.wait`/cleanup pass), then for **every** port in `ports` (no batching/limiting — all requested ports are knocked concurrently as separate tasks), yields to the event loop once (`await asyncio.sleep(0)`) before scheduling each knock task (a fairness/starvation-avoidance nicety, not functionally significant), and finally `asyncio.wait(tasks, return_when=FIRST_EXCEPTION)`. Any tasks still pending after that wait are cancelled; if any of those cancelled tasks, once awaited via `asyncio.gather(..., return_exceptions=True)`, produced an exception that **is not** an `OSError` subclass, that exception is re-raised from `knock()` itself (i.e. **only** the two special `EHOSTDOWN`/`EHOSTUNREACH` `OSError`s propagate as real failures — literally any other exception type, if one somehow occurred, would also propagate, but plain connection-refused-style `OSError`s never do since those never escape `_async_knock` in the first place).

`knocker(address, ports, loop=None, timeout=4)` (`pyatv/support/knock.py:68-79`) is a thin `asyncio.ensure_future(knock(address, ports, timeout))` wrapper returning the scheduled `Future` directly (not awaited) — so callers (`UnicastMdnsScanner._get_services`, §3.3) get a cancellable handle immediately and race it against the DNS unicast query. **The docstring on `knocker` says "New port knocks are sent every two seconds, so a timeout of 4 seconds will result in two knocks"** (`pyatv/support/knock.py:76-77`) but **the actual implementation contains no resend loop at all** — `knock()` fires exactly one `_async_knock` per port, once, and the "every two seconds" repeat behavior described in the docstring simply does not exist in the code on this pinned commit. This is a real, verified doc/code mismatch — flagged again in §9; a Rust port should implement what the **code** does (one knock attempt per port per `knocker()` call), not what the docstring claims.

`UnicastMdnsScanner` invokes `knock.knocker(host, KNOCK_PORTS, self.loop, timeout=timeout)` where `KNOCK_PORTS = [3689, 7000, 49152, 32498]` (§3.1) — those four fixed ports, always, for every unicast-scanned host, regardless of what protocols/services are actually being searched for.

---

## 7. Per-protocol scan handlers

### 7.1 Common shape

Every protocol module exposes exactly this surface for discovery purposes (`pyatv/protocols/__init__.py:27-73` wires them all into the `PROTOCOLS: Dict[Protocol, ProtocolMethods]` registry consumed by `pyatv.scan()`, `pyatv/__init__.py:76-88`):

```python
def scan() -> Mapping[str, ScanHandlerDeviceInfoName]: ...      # {dns_sd_service_type: (handler, device_info_name_fn)}
def device_info(service_type: str, properties: Mapping[str, Any]) -> Dict[str, Any]: ...
async def service_info(service: MutableService, devinfo: DeviceInfo, services: Mapping[Protocol, BaseService]) -> None: ...
```

`device_info_name_from_unique_short_name(service_name: str) -> str` (`pyatv/core/scan.py:79-81`) is the shared trivial identity function (`return service_name`) most protocols use as their "how do I derive the `_device-info._tcp.local` lookup name from this service's own short name" callback — used when the scanner needs to know what name to also look up under `_device-info._tcp.local` for model info (only meaningfully exercised by the `Zeroconf*Scanner` family's explicit device-info sub-queries, §3.6; the custom-codec path gets `_device-info._tcp.local` data implicitly since `create_service_queries` always appends a sleep-proxy question but relies on the *responder* proactively including `_device-info._tcp.local` records in the same reply datagram rather than pyatv issuing a second round-trip for it — see the `model` field flowing through `Response.model`/`_get_model`, §2.1/§2.4).

### 7.2 MRP (`pyatv/protocols/mrp/__init__.py:1025-1078`)

```python
def mrp_service_handler(mdns_service, response) -> Optional[ScanHandlerReturn]:
    enabled = True
    build = mdns_service.properties.get("SystemBuildVersion", "")
    match = re.match(r"^(\d+)[A-Z]", build)
    if match:
        base = int(match.groups()[0])
        if base >= 19:
            enabled = False   # "Disabling MRP service since tvOS >= 15"
    name = mdns_service.properties.get("Name", "Unknown")
    service = MutableService(
        get_unique_id(mdns_service.type, mdns_service.name, mdns_service.properties),
        Protocol.MRP, mdns_service.port,
        properties=mdns_service.properties, enabled=enabled,
    )
    return name, service

def scan():
    return {"_mediaremotetv._tcp.local": (mrp_service_handler, device_info_name_from_unique_short_name)}
```

The tvOS-15-disables-direct-MRP rule (§ Design invariants in `CLAUDE.md`) is implemented **entirely locally**, reading only the MRP service's own `SystemBuildVersion` TXT property (build-major ≥ 19 per the same `base - 4 = tvOS major` heuristic as `lookup_version`, §5.3: build 19 → tvOS 15) — it is **not** a cross-service rule keyed off the AirPlay service's advertised OS version, despite that being a plausible-sounding cross-check; MRP disqualifies itself purely from its own SRV record's TXT data. (The actual AirPlay-vs-MRP interaction — deciding whether to *tunnel* MRP over AirPlay at connect time — happens later, in `pyatv/protocols/airplay/__init__.py`'s `setup()`, §7.4, which is a connection-time decision, not a scan-time one.)

`device_info(service_type, properties)` (`pyatv/protocols/mrp/__init__.py:1061-1078`, properties keys are **lower-cased** here since they flow through `CaseInsensitiveDict`/`Service.properties`, hence `"systembuildversion"`/`"macaddress"` not the TXT-record-cased `"SystemBuildVersion"`/`"MACAddress"`):
- `"systembuildversion" in properties` → sets `BUILD_NUMBER` to that raw value, and additionally `VERSION = lookup_version(build)` if that lookup succeeds.
- `"macaddress" in properties` → sets `MAC` verbatim (no reformatting).
- **Always**, unconditionally: `OPERATING_SYSTEM = OperatingSystem.TvOS` — with the explicit code comment "MRP has only been seen on Apple TV and HomePod, which both run tvOS, so an educated guess is made here. It is border line OK, but will do for now." (verbatim, `pyatv/protocols/mrp/__init__.py:1073-1075` — flagged as an acknowledged heuristic, not a hard fact, in §9).

`service_info` (`pyatv/protocols/mrp/__init__.py:1081-1097`):
```python
if not service.enabled:
    service.pairing = PairingRequirement.NotNeeded
elif service.properties.get("allowpairing", "no").lower() == "yes":
    service.pairing = PairingRequirement.Optional
else:
    service.pairing = PairingRequirement.Disabled
```
Docstring note (verbatim): "Pairing has never been enforced by MRP (maybe by design), but it is possible to pair if AllowPairing is YES." A **disabled** MRP service (tvOS ≥ 15, direct-MRP unusable) is marked `NotNeeded` — not `Disabled`/`Unsupported` — for pairing purposes, which reads slightly counter-intuitive (a disabled service reporting pairing as "not needed" rather than "unsupported") but is the literal branch order in the source; a disabled service simply never gets a pairing attempt regardless of what `pairing` says, since `enabled=False` is checked independently elsewhere.

### 7.3 Companion (`pyatv/protocols/companion/__init__.py:60-79, 614-661`)

```python
PAIRING_DISABLED_MASK = 0x04
PAIRING_WITH_PIN_SUPPORTED_MASK = 0x4000
```
with extensive inline comments recording the empirical reverse-engineering behind these two masks (observed `rpfl` bit patterns across HomePod/HomePod mini/Mac mini/MacBook/iPad — not pairable — versus Apple TV 4K — pairable — reproduced verbatim since they're the only justification on record for these magic numbers):

```
# Observed values of rpfl (zeroconf):
# 0x62792 -> All on the same network (Unsupported/Mandatory)
# 0x627B6 -> Only devices in same home (Disabled)
# 0xB67A2 -> Same as above
# Mask = 0x62792 & ~0xB67A2 & ~0x627B6 & ~0xB67A2 = 0x20
PAIRING_DISABLED_MASK = 0x04

# Not pairable:
# 0010 0000 0000 0000 0000 = 0x20000 (Mac Mini, MacBook)
# 0110 0010 0111 1011 0010 = 0x627B2 (HomePod, HomePod mini)
# 0110 0010 0111 1001 0010 = 0x62792 (HomePod mini)
# 0011 0000 0000 0000 0000 = 0x30000 (iPad)
# Pairable:
# 0011 0110 0111 1010 0010 = 0x367A2 (Apple TV 4K)
# 0011 0110 0111 1000 0010 = 0x36782 (Apple TV 4K)
# ===
# 0000 0100 0000 0000 0000 = 0x04000
# So masking 0x40000 should tell if pairing is supported or not
PAIRING_WITH_PIN_SUPPORTED_MASK = 0x4000
```

**Note the comment/constant mismatch**: the `PAIRING_DISABLED_MASK` derivation comment computes `0x20` but the constant actually set is `0x04`; the `PAIRING_WITH_PIN_SUPPORTED_MASK` derivation comment says "masking 0x40000" but the constant is `0x4000` (one hex digit / 4 bits off in each case). These are literal source-code comment/value mismatches on the pinned commit — reproduce the **values actually used** (`0x04`, `0x4000`), not the values the adjacent prose arithmetic suggests; flagged again in §9.

```python
def companion_service_handler(mdns_service, response) -> Optional[ScanHandlerReturn]:
    service = MutableService(
        get_unique_id(mdns_service.type, mdns_service.name, mdns_service.properties),
        Protocol.Companion, mdns_service.port, mdns_service.properties,
    )
    return mdns_service.name, service

def scan():
    return {"_companion-link._tcp.local": (companion_service_handler, device_info_name_from_unique_short_name)}
```

No `enabled=` override, no tvOS-version gating unlike MRP — Companion services are always enabled as discovered. `get_unique_id` for Companion reads the `"rpmrtid"` property (§7.6) — as noted in `tests/protocols/companion/test_companion_scan.py:34-36`'s comment, Companion by itself typically has **no usable identifier** in practice (`rpmrtid` isn't always present), which is why the functional test explicitly demonstrates a lone Companion service producing **zero** scan results (`test_multicast_scan_companion_device`, §8) until paired with an MRP service on the same address supplying the identifier that makes the combined device `ready` (§4.2).

`device_info` (`pyatv/protocols/companion/__init__.py:637-644`): `"rpmd" in properties` → `RAW_MODEL = properties["rpmd"]` always (even on a lookup miss), plus `MODEL = lookup_model(properties["rpmd"])` only if that resolves to something other than `Unknown`. No OS/version/MAC extraction at all from Companion properties.

`service_info` (`pyatv/protocols/companion/__init__.py:648-661`):
```python
flags = int(service.properties.get("rpfl", "0x0"), 16)
if flags & PAIRING_DISABLED_MASK:
    service.pairing = PairingRequirement.Disabled
elif flags & PAIRING_WITH_PIN_SUPPORTED_MASK:
    service.pairing = PairingRequirement.Mandatory
else:
    service.pairing = PairingRequirement.Unsupported
```
Note the fallback pairing state is `Unsupported`, not `Optional`/`NotNeeded` — Companion pairing is opt-in only when the PIN-supported bit is explicitly observed.

### 7.4 AirPlay (`pyatv/protocols/airplay/__init__.py:180-224` for scan/device_info, `225-230` for service_info; `pyatv/protocols/airplay/utils.py` for the shared logic it calls)

```python
def airplay_service_handler(mdns_service, response) -> Optional[ScanHandlerReturn]:
    service = MutableService(
        get_unique_id(mdns_service.type, mdns_service.name, mdns_service.properties),
        Protocol.AirPlay, mdns_service.port, properties=mdns_service.properties,
    )
    return mdns_service.name, service

def scan():
    return {"_airplay._tcp.local": (airplay_service_handler, device_info_name_from_unique_short_name)}
```

`device_info` (`pyatv/protocols/airplay/__init__.py:203-224`), properties again lower-cased:
- `"model" in properties`: `RAW_MODEL = properties["model"]` unconditionally; `MODEL = lookup_model(...)` if it resolves; `OPERATING_SYSTEM = lookup_os(properties["model"])` (the **string**-argument branch of `lookup_os`, §5.4) if that resolves to something other than `Unknown`.
- `"osvers" in properties` → `VERSION = properties["osvers"]` verbatim (no parsing/lookup — AirPlay's `osvers` TXT value is trusted as already being a display-ready version string, unlike MRP's build-number-derived version).
- `"deviceid" in properties` → `MAC = properties["deviceid"]` verbatim (no reformatting — this is also literally what `get_unique_id` uses as the AirPlay identifier, §7.6, so **the AirPlay service's unique identifier and its device-info MAC address are, by construction, the exact same string** for any device using the standard `deviceid` TXT convention).
- `"psi" in properties` → `OUTPUT_DEVICE_ID = properties["psi"]`, **else if** `"pi" in properties` → `OUTPUT_DEVICE_ID = properties["pi"]` (`psi` preferred over `pi` when both present — these are two different Apple TXT keys both loosely meaning "player/protocol identifier", with `psi` apparently the more specific/preferred one in newer firmware).

`service_info` (`pyatv/protocols/airplay/__init__.py:225-230`) is a one-line delegate: `update_service_details(service)` (from `utils.py`, below).

`pyatv/protocols/airplay/utils.py` — the shared cross-protocol logic (also consumed by RAOP, §7.5):

- `UNSUPPORTED_MODELS = [r"^Mac\d+,\d+$"]` (`utils.py:34`) — a **fully-anchored** regex (`^...$`, unlike `lookup_os`'s prefix-only `re.match` patterns), matching e.g. `"Mac14,3"` but not `"MacBookAir10,1"` (the `Mac\d+,\d+` pattern here would actually match the *start* of `"MacBookPro..."` too under `re.match`'s prefix semantics if unanchored, but the trailing `$` anchor prevents that) — used to flag bare-`Mac`-identified devices (i.e. actual desktop/laptop Macs advertising AirPlay receiver capability, as opposed to `MacBookAir\d+,\d+` etc. which are more specific model families) as pairing-`Unsupported` in `update_service_details` below, regardless of what the bit-flag-derived pairing requirement would otherwise say.
- `PIN_REQUIRED = 0x8`, `PASSWORD_BIT = 0x80`, `LEGACY_PAIRING_BIT = 0x200` (`utils.py:25-27`) — the three status-flag bit constants.
- `_get_flags(properties)` (`utils.py:44-47`): `int(properties.get("sf") or properties.get("flags") or "0x0", 16)` — **`sf` takes priority over `flags`** when both are present (both are legitimate Apple TXT keys for the same status-flags concept across AirPlay protocol generations).
- `parse_features(features: str) -> AirPlayFlags` (`utils.py:104-118`): regex `^0x([0-9A-Fa-f]{1,8})(?:,0x([0-9A-Fa-f]{1,8})|)$` — matches either a single `0x`-prefixed hex group (1–8 hex digits) or two comma-separated groups. When two groups are present, **the second (after the comma) is the high 32 bits, the first is the low 32 bits** — concatenated as `upper_hex_string + lower_hex_string` then parsed as one combined hex integer (`value = upper + value; return AirPlayFlags(int(value, 16))`), i.e. the wire convention `"0xLOWER,0xUPPER"` produces the 64-bit value `(UPPER << 32) | LOWER`. Any string not matching the regex at all (extra commas, non-hex characters, more than 8 hex digits per group, a third comma-separated group, etc.) raises `ValueError(f"invalid feature string: {features}")` — see `tests/protocols/airplay/test_utils.py:52-58`'s explicit bad-input cases.
- `AirPlayFlags` (`utils.py:55-98`) is a full `IntFlag` enum of every known feature bit (61 named bits from `SupportsAirPlayVideoV1 = 1<<0` up to `SupportsRFC2198Redundancy = 1<<61`) — reproduce this table verbatim in a Rust port (it's directly quoted in the file already read; not re-transcribed a second time here to avoid transcription risk — cross-reference `pyatv/protocols/airplay/utils.py:55-98` directly). The two flags load-bearing for AirPlay-version detection are `SupportsUnifiedMediaControl = 1<<38` and `SupportsCoreUtilsPairingAndEncryption = 1<<48`.
- `is_password_required(service) -> bool` (`utils.py:121-136`): `True` if `properties.get("pw", "false").lower() == "true"`, **or** if `_get_flags(properties) & PASSWORD_BIT`. Both checks are independent ORs — either one being true is sufficient.
- `get_pairing_requirement(service) -> PairingRequirement` (`utils.py:139-157`): `Mandatory` if `_get_flags(properties) & (LEGACY_PAIRING_BIT | PIN_REQUIRED)` (either bit alone is sufficient — combined via bitwise-OR into one mask check, not two separate branches); else `Unsupported` if `properties.get("act", "0") == "2"` (the "Access Control Type 2 == Current User" case, explicitly unsupported by pyatv per the inline comment); else `NotNeeded` as the final fallback ("Other cases are optimistically treated as NotNeeded", verbatim docstring language).
- `is_remote_control_supported(service, credentials) -> bool` (`utils.py:165-180`, explicitly marked with a `# TODO` in the source acknowledging this is a guess, quoted here verbatim: *"It is not fully understood how to determine if a device supports remote control over AirPlay, so this method makes a pure guess. We know that Apple TVs running tvOS X (X>=13?) support it as well as HomePods, something we can identify from the model string. This implementation should however be improved when it's properly known how to check for support."*): if the `model` property starts with `"AudioAccessory"` (HomePod family), remote control is supported **only** if `credentials == TRANSIENT_CREDENTIALS` (an exact-equality check against a sentinel value from `pyatv.auth.hap_pairing`, not a type check); else if `model` does not start with `"AppleTV"`, unsupported; else, `float(osvers.split(".", 1)[0]) >= 13.0 and credentials.type == AuthenticationType.HAP` — i.e. **only the major OS-version digit is parsed as a float** (`"13.0.1"` → `"13"` → `13.0`), and HAP-type credentials (not transient, not legacy) are required for the Apple TV branch specifically. **This function is a connect-time / MRP-tunnel-decision helper, not a scan-time `service_info` participant** — it's consumed by `airplay/__init__.py`'s `setup()` (§ below), not by any `device_info`/`service_info` extractor.
- `get_protocol_version(service, preferred_version: AirPlayVersion) -> AirPlayMajorVersion` (`utils.py:241-259`, also `# TODO`-flagged verbatim: *"I don't know how to properly detect if a receiver support AirPlay 2 or not, so I'm guessing until I know better."*): if `preferred_version != Auto`, return `V2`/`V1` directly per the explicit override (no property inspection at all in that case). If `Auto`: read `ft` property, falling back to `features` if `ft` absent (**note**: **priority order here is `ft` first, then `features`** — the *opposite* preference order from `_get_flags`'s `sf`-before-`flags`, a real and easy-to-transpose-incorrectly asymmetry between the two "prefer new key over legacy key" helpers in this same file), parse with `parse_features`, and classify as `AirPlayV2` iff `SupportsUnifiedMediaControl` or `SupportsCoreUtilsPairingAndEncryption` is set, else `AirPlayV1`.
- `update_service_details(service: MutableService)` (`utils.py:262-278`) — the actual `service_info` body for both AirPlay and (conditionally) RAOP:
  ```python
  service.requires_password = is_password_required(service)
  if service.properties.get("acl", "0") == "1":
      service.pairing = PairingRequirement.Disabled
  elif any(re.match(model, service.properties.get("model", "")) for model in UNSUPPORTED_MODELS):
      service.pairing = PairingRequirement.Unsupported
  else:
      service.pairing = get_pairing_requirement(service)
  ```
  Priority order, exactly: access-control-locked (`acl=1`, "only devices belonging to the same home") beats bare-Mac-model-unsupported, which beats the general bit-flag-derived pairing requirement.

Finally, the AirPlay `setup()` function (`pyatv/protocols/airplay/__init__.py:303-389`, connect-time, not scan-time, but documented here since it's where `is_remote_control_supported`/`get_protocol_version` actually get consumed and it's the closest thing to the "MRP disabling when AirPlay says tvOS 15+" cross-service rule mentioned in the task prompt) decides whether to additionally yield an MRP-tunneled `SetupData` based on `core.settings.protocols.airplay.mrp_tunnel` (`MrpTunnel.Disable` → never; `MrpTunnel.Force` → always; otherwise auto-detect via `is_remote_control_supported(...)` **and** `credentials.type in {HAP, Transient}`). **This confirms the cross-service MRP/AirPlay interaction is a connect-time tunnel-setup decision, not a scan-time `enabled`/`pairing` decision** — the scan-time MRP-disabling rule (§7.2) is self-contained within MRP's own `SystemBuildVersion` check and does not consult the AirPlay service at all, correcting a plausible but incorrect assumption in the task brief.

Also in `setup()`: if `AirPlayFlags.HasUnifiedAdvertiserInfo` is set in the parsed `features` and no `Protocol.RAOP` service already exists on the config, a synthetic `MutableService(None, Protocol.RAOP, core.service.port, core.service.properties, credentials=core.service.credentials, password=core.service.password)` is fabricated and added — this is a **connect-time**, not scan-time, RAOP-service synthesis (AirPlay 2 receivers can serve RAOP-audio-shaped streaming over the same port without a separate `_raop._tcp.local` advertisement) and is out of scope for a discovery-only port, but worth flagging as a place where `conf.AppleTV.services` can gain a `Protocol.RAOP` entry that never came from mDNS scanning at all.

### 7.5 RAOP (`pyatv/protocols/raop/__init__.py:438-514`)

```python
def raop_name_from_service_name(service_name: str) -> str:
    split = service_name.split("@", maxsplit=1)
    return split[1] if len(split) == 2 else split[0]

def raop_service_handler(mdns_service, response) -> Optional[ScanHandlerReturn]:
    name = raop_name_from_service_name(mdns_service.name)
    service = MutableService(
        get_unique_id(mdns_service.type, mdns_service.name, mdns_service.properties),
        Protocol.RAOP, mdns_service.port, mdns_service.properties,
    )
    return name, service

def scan():
    return {
        "_raop._tcp.local": (raop_service_handler, raop_name_from_service_name),
        "_airport._tcp.local": (lambda service, response: None, device_info_name_from_unique_short_name),
    }
```

RAOP instance names are conventionally `"{identifier}@{display name}"` (e.g. `"AABBCCDDEEFF@Living Room"`); `raop_name_from_service_name` strips the identifier prefix off to get the human display name, falling back to the whole string if there's no `@` at all. **`_airport._tcp.local` is registered with a handler that always returns `None`** — it contributes **no** `MutableService`/`Protocol.RAOP` entry ever, existing purely so its properties get recorded via the always-runs properties-attachment step (§3.2 step 3) for AirPort Express devices, whose `wama` TXT key (see below) is only advertised under `_airport._tcp.local`, not `_raop._tcp.local`.

`device_info` (`pyatv/protocols/raop/__init__.py:469-494`), called separately per service type it's registered against (both `_raop._tcp.local` and `_airport._tcp.local` map to this **same** function — the `service_type` parameter distinguishes them, though in practice this function doesn't actually branch on it except implicitly via which properties happen to be present):
- `"am" in properties` (the RAOP-side "Apple Model" property): `RAW_MODEL = properties["am"]` unconditionally, `MODEL = lookup_model(...)` if resolved, `OPERATING_SYSTEM = lookup_os(properties["am"])` (string branch) if resolved.
- `"ov" in properties` → `VERSION = properties["ov"]` verbatim.
- `"wama" in properties` (AirPort-Express-only, from `_airport._tcp.local`): a **nested comma-separated `key=value` sub-encoding inside a single TXT value** — parsed as:
  ```python
  props = dict(
      prop.split("=", maxsplit=1)
      for prop in ("macaddress=" + properties["wama"]).split(",")
  )
  ```
  i.e. the raw `wama` string is **prefixed with the literal text `"macaddress="`** before being comma-split and `=`-split — meaning the *first* comma-separated segment of `wama` is implicitly the MAC address with no explicit key in the wire format at all (pyatv is inserting the `macaddress=` key itself), and any subsequent comma-separated segments in `wama` (e.g. `syVs=...`) **do** carry their own explicit keys on the wire. Then: `if MAC not in devinfo: devinfo[MAC] = props["macaddress"].replace("-", ":").upper()` (dash-to-colon MAC reformatting, upper-cased, and **only applied if `MAC` wasn't already set** by the `am`-derived path above — `wama`/AirPort-Express MAC never overrides an already-set MAC from elsewhere in this same `device_info` call); and `if "syVs" in props: devinfo[VERSION] = props["syVs"]` (**this one unconditionally overwrites** any `ov`-derived `VERSION` set earlier in the same function call, no presence guard — a real asymmetry between the two nested-dict-write branches worth preserving exactly).

`service_info` (`pyatv/protocols/raop/__init__.py:496-514`) — the clearest example of the cross-service "read the AirPlay sibling's properties" pattern the task brief anticipated:
```python
airplay_service = services.get(Protocol.AirPlay)
if airplay_service and airplay_service.properties.get("acl", "0") == "1":
    service.pairing = PairingRequirement.Disabled
elif airplay_service and airplay_service.properties.get("act", "0") == "2":
    service.pairing = PairingRequirement.Unsupported
else:
    update_service_details(service)   # same shared AirPlay-utils function as §7.4, but operating on RAOP's own service/properties
```
Note this checks the **AirPlay sibling's** `acl`/`act` properties for the first two branches (explicitly cross-service), but the fallback branch calls `update_service_details(service)` on RAOP's **own** `service` object, re-deriving `requires_password`/`pairing` from RAOP's *own* properties (`pw`/`sf`/`flags`/`model`/`act`) via the exact same shared logic AirPlay itself uses — i.e. RAOP's pairing logic is "prefer the AirPlay sibling's ACL signal if present and restrictive, else fall back to treating RAOP's own advertised properties exactly like an AirPlay service would be treated." If there's no `Protocol.AirPlay` service on the device at all (`airplay_service` is `None`), both cross-service branches are skipped unconditionally and it falls straight to the `update_service_details(service)` fallback.

### 7.6 DMAP (`pyatv/protocols/dmap/__init__.py:577-658`)

Three distinct DNS-SD service types, all mapping to the single `Protocol.DMAP`:

```python
def homesharing_service_handler(mdns_service, response):
    name = mdns_service.properties.get("Name", "Unknown")
    service = MutableService(get_unique_id(...), Protocol.DMAP, mdns_service.port, mdns_service.properties)
    service.credentials = mdns_service.properties.get("hG")   # <-- Home Sharing GUID doubles as credentials
    return name, service

def dmap_service_handler(mdns_service, response):
    name = mdns_service.properties.get("CtlN", "Unknown")
    service = MutableService(get_unique_id(...), Protocol.DMAP, mdns_service.port, mdns_service.properties)
    return name, service   # no credentials set

def hscp_service_handler(mdns_service, response):
    name = mdns_service.properties.get("Machine Name", "Unknown")   # note: literal space in the TXT key
    service = MutableService(get_unique_id(...), Protocol.DMAP, port=mdns_service.port, properties=mdns_service.properties)
    service.credentials = mdns_service.properties.get("hG")
    return name, service

def scan():
    return {
        "_appletv-v2._tcp.local": (homesharing_service_handler, lambda _: None),
        "_touch-able._tcp.local": (dmap_service_handler, lambda _: None),
        "_hscp._tcp.local": (hscp_service_handler, lambda _: None),
    }
```

All three `device_info_name` callbacks are `lambda _: None` — **DMAP never triggers a `_device-info._tcp.local` sub-lookup for model info**, unlike every other protocol which uses `device_info_name_from_unique_short_name`. The display-name TXT key differs per service type: `"Name"` for Home Sharing, `"CtlN"` for legacy DMAP (`_touch-able._tcp.local`), `"Machine Name"` (containing a literal space character) for HSCP. Only the Home Sharing and HSCP handlers populate `credentials` directly from the `"hG"` (Home Sharing GUID) TXT property at scan time — this is DMAP's only protocol where credentials can be sourced straight from mDNS TXT data rather than requiring an explicit pairing flow.

`device_info(service_type, properties)` (`pyatv/protocols/dmap/__init__.py:630-640`): **unconditionally** `OPERATING_SYSTEM = OperatingSystem.Legacy` (comment, verbatim: "Like with MRP, this is also border line OK, but will do for now" — an explicitly-acknowledged-as-imprecise heuristic, §9), and **additionally**, only if `service_type == "_hscp._tcp.local"`, `MODEL = DeviceModel.Music` — i.e. HSCP is treated as "the Music app / iTunes running on a desktop, not a real Apple TV," a hardcoded model assignment with no properties-based lookup at all (compare `DeviceModel.Music = 10` in `pyatv/const.py:187-188`, whose docstring literally says "Music app (or iTunes) running on a desktop computer").

`service_info` (`pyatv/protocols/dmap/__init__.py:643-658`):
```python
service.pairing = (
    PairingRequirement.Optional if "hg" in service.properties else PairingRequirement.Mandatory
)
```
Docstring, verbatim: "If Home Sharing is enabled, then the 'hG' property is present and can be used as credentials. If not enabled, then pairing must be performed." Note the **lower-case** `"hg"` membership check here (consistent with `Service.properties` being a `CaseInsensitiveDict`, §1.8/§2.1 — the literal TXT key is `"hG"` mixed-case but the case-insensitive property map makes `"hg" in service.properties` match regardless of the original wire casing) versus the scan-handler-level `.get("hG")` calls (§ above) which use the mixed-case form as written but resolve identically through the same case-insensitive map — both spellings work, shown here to make clear a Rust port's TXT-property map **must** be case-insensitive-on-key throughout, not just at the raw-parse layer.

### 7.7 `pyatv.helpers.get_unique_id` — the full per-service-type identifier table (`pyatv/helpers.py:10-16, 54-87`)

```python
HOMESHARING_SERVICE: str = "_appletv-v2._tcp.local"
DEVICE_SERVICE: str = "_touch-able._tcp.local"
MEDIAREMOTE_SERVICE: str = "_mediaremotetv._tcp.local"
AIRPLAY_SERVICE: str = "_airplay._tcp.local"
COMPANION_SERVICE: str = "_companion-link._tcp.local"
RAOP_SERVICE: str = "_raop._tcp.local"
HSCP_SERVICE: str = "_hscp._tcp.local"

def get_unique_id(service_type, service_name, properties) -> Optional[str]:
    if service_type in [DEVICE_SERVICE, HOMESHARING_SERVICE]:
        return service_name.split("_")[0]
    if service_type == HSCP_SERVICE:
        return properties.get("Machine ID")
    if service_type == MEDIAREMOTE_SERVICE:
        return properties.get("UniqueIdentifier")
    if service_type == AIRPLAY_SERVICE:
        return properties.get("deviceid")
    if service_type == COMPANION_SERVICE:
        return properties.get("rpmrtid")
    if service_type == RAOP_SERVICE:
        split = service_name.split("@", maxsplit=1)
        if len(split) == 2:
            return split[0]
        return properties.get("pk")
    return None
```

Notes per branch:
- `_touch-able._tcp.local` / `_appletv-v2._tcp.local` (both legacy DMAP variants): identifier is derived from the **service instance name**, splitting on the first `_` and taking everything before it (`service_name.split("_")[0]`) — this is *not* a TXT property at all, it's baked into the DNS-SD instance name itself for these legacy service types (Home Sharing/legacy DMAP instance names are conventionally `"{identifier}_{display suffix}"`-shaped on the wire, though pyatv's own `fake_udns.py` test fixtures (§8) don't actually encode a `_`-separated identifier into the *name* field for these — they pass the identifier separately as `hsgid`/credentials — meaning this particular branch's real-world exercise depends on actual device behavior differing from pyatv's own synthetic test fixtures; verify against real captures, §9).
- `_hscp._tcp.local`: `"Machine ID"` TXT property (space in key, mixed-case as written — again resolved case-insensitively).
- `_mediaremotetv._tcp.local`: `"UniqueIdentifier"` TXT property.
- `_airplay._tcp.local`: `"deviceid"` TXT property — as noted in §7.4, this is the *same* string later surfaced as `DeviceInfo.MAC` for AirPlay.
- `_companion-link._tcp.local`: `"rpmrtid"` TXT property, with the explanatory comment (verbatim): "Apple TV devices on tvOS 16 (maybe earlier) have a static rpMRtID identifier." — often absent, per §7.3's discussion of Companion needing to piggyback on another protocol's identifier for a device to be `ready`.
- `_raop._tcp.local`: prefer the `"{id}@{name}"` instance-name-embedded identifier; if the instance name has no `@` at all, fall back to the `"pk"` (public key) TXT property — explicit comment: "some devices seems to break from this behavior and just use 'name', thus leaving out the id. Some of these devices however have the public key ('pk') available as an attribute so that can be used as an identifier in that case."
- Any other/unknown service type: `None` — no identifier can be derived, which (per §4.2's `ready` definition) means a device whose *only* discovered services are of unrecognized/unhandled types will never be considered `ready` and gets filtered out of `pyatv.scan()`'s results.

---

## 8. Test fixtures worth porting as known-answer tests

### 8.1 `tests/support/test_dns.py` (291 lines) — byte-exact DNS codec fixtures, the highest-value gold here

**Name-instance splitting** (`tests/support/test_dns.py:11-36`): already tabulated in §1.7.

**QNAME encoding** (`tests/support/test_dns.py:40-94`) — the `encode_domain_names` dict, exact expected byte strings, reproduced verbatim (these are the single most valuable fixtures for a Rust `qname_encode` port — copy them directly into `#[test]` cases):

```python
encode_domain_names = {
    "root": (".", b"\x00"),
    "empty": ("", b"\x00"),
    "example.com": ("example.com", b"\x07example\x03com\x00"),
    "example.com_list": (["example", "com"], b"\x07example\x03com\x00"),
    "unicode": ("Bücher.example", b"\x07B\xc3\xbccher\x07example\x00"),
    "dotted_instance": (
        "Dot.Within._http._tcp.example.local",
        b"\x0aDot.Within\x05_http\x04_tcp\x07example\x05local\x00",
    ),
    "dotted_instance_list": (
        ["Dot.Within", "_http", "_tcp", "example", "local"],
        b"\x0aDot.Within\x05_http\x04_tcp\x07example\x05local\x00",
    ),
    "truncated_ascii": (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        ".test",
        b"\x3fabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk"
        b"\x04test"
        b"\x00",
    ),
    "truncated_unicode": (
        "aがあいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめも.test",
        b"\x3d"
        b"a\xe3\x81\x8c\xe3\x81\x82\xe3\x81\x84\xe3\x81\x86\xe3\x81\x88\xe3\x81\x8a"
        b"\xe3\x81\x8b\xe3\x81\x8d\xe3\x81\x8f\xe3\x81\x91\xe3\x81\x93\xe3\x81\x95"
        b"\xe3\x81\x97\xe3\x81\x99\xe3\x81\x9b\xe3\x81\x9d\xe3\x81\x9f\xe3\x81\xa1"
        b"\xe3\x81\xa4\xe3\x81\xa6"
        b"\x04test"
        b"\x00",
    ),
}
```
(The `truncated_unicode` case is specifically constructed — see the source comment, `tests/support/test_dns.py:66-75` — to force a 63-byte truncation boundary to fall mid-codepoint-sequence under naive byte-truncation, and to use NFD-normalized input text to also exercise the NFC-normalize-before-encode step, §1.4.)

**Name-compression decoding** (`tests/support/test_dns.py:97-155`) — the `decode_domain_names` dict, also copy verbatim:

```python
decode_domain_names = {
    "simple": (b"\x03foo\x07example\x03com\x00", 0, "foo.example.com", None),
    "null": (b"\x00", 0, "", None),
    "compressed": (b"aaaa\x04test\x00\x05label\xc0\x04\xab\xcd", 10, "label.test", -2),
    "multi_compressed": (
        b"aaaa\x04test\x00\x05label\xc0\x04\x03foo\xc0\x0a\xab\xcd", 18, "foo.label.test", -2,
    ),
    "idna": (b"\x0dxn--bcher-kva\x07example\x00", 0, "bücher.example", None),
    "nbsp": (b"\x10Apple\xc2\xa0TV (4167)\x05local\x00", 0, "Apple\xa0TV (4167).local", None),
    "unicode": (
        b"\x1d\xe5\xb1\x85\xe9\x96\x93 Apple\xc2\xa0TV. En Espa\xc3\xb1ol\x05local\x00",
        0, "居間 Apple TV. En Español.local", None,
    ),
}
```
Tuple shape is `(raw_bytes, start_offset, expected_decoded_name, expected_final_cursor_offset_or_None_for_EOF)`. The `compressed`/`multi_compressed` cases are the definitive proof-fixtures for the pointer-follow-then-resume-at-original-position behavior (§1.3) — a Rust port's compression logic should be validated against these two exactly, including the final cursor position landing 2 bytes before the end of the buffer (the `\xab\xcd` trailer bytes that follow the pointer in the raw fixture, deliberately included to prove the cursor resumes correctly rather than running off into or past that trailing data).

**Character-string parsing** (`tests/support/test_dns.py:158-197`) — the `decode_strings` dict, boundary-length-focused (`63`/`64`/`128`/`192`/`255` byte lengths specifically chosen to probe the two compression-flag bits' boundary values, proving TXT/character-string parsing is length-byte-driven and never accidentally triggers the domain-name compression-pointer code path):
```python
decode_strings = {
    "null": (b"\x00", b"", None),
    "len_63": (b"\x3f" + (63 * b"0"), (63 * b"0"), None),
    "len_64": (b"\x40" + (64 * b"0"), (64 * b"0"), None),
    "len_128": (b"\x80" + (128 * b"0"), (128 * b"0"), None),
    "len_192": (b"\xc0" + (192 * b"0"), (192 * b"0"), None),
    "len_255": (b"\xff" + (255 * b"0"), (255 * b"0"), None),
    "trailing": (b"\x0a" + (10 * b"2") + (17 * b"9"), (10 * b"2"), -17),
}
```

**TXT dict parsing** (`tests/support/test_dns.py:200-241`): single key (`b"\x07foo=bar"` → `{"foo": b"bar"}`), multiple keys (`b"\x07foo=bar\x09spam=eggs"` → `{"foo": b"bar", "spam": b"eggs"}`), binary value that isn't valid UTF-8/ASCII (`b"\x06foo=\xfe\xed"` → `{"foo": b"\xfe\xed"}`, proving values are never decode-attempted at this layer), and a long value (`b"\xccfoo=" + b"\xca\xfe"*100`, a 204-byte character-string, proving character-strings aren't limited to the 63-byte domain-label cap). Each test also appends `b"\xde\xad\xbe\xef" * N` trailing garbage after the exact `length`-bounded region and asserts the parser stops exactly at `length`, never overreads.

**Per-`QueryType` rdata parsing** (`tests/support/test_dns.py:256-291`) — copy directly, this is the exact fixture set for `QueryType.parse_rdata`:
```python
(QueryType.A,   b"\x0a\x00\x00\x2a", "10.0.0.42")
(QueryType.PTR, b"\x03foo\x07example\x03com\x00", "foo.example.com")
(QueryType.TXT, b"\x07foo=bar", {"foo": b"bar"})
(QueryType.SRV, b"\x00\x0a\x00\x00\x00\x50\x03foo\x07example\x03com\x00",
    {"priority": 10, "weight": 0, "port": 80, "target": "foo.example.com"})
```

### 8.2 `tests/support/dns_utils.py` (102 lines) — reusable test-message builders

`answer(qname, full_name)` builds a `DnsResource(qname, QueryType.PTR, qclass=1, ttl=10, rd_length=0, rd=full_name)` — **note `rd_length=0` is hardcoded/unused-on-construction** here since it's only meaningful during unpack; the `DEFAULT_QCLASS = 1` / `DEFAULT_TTL = 10` module constants (`tests/support/dns_utils.py:10-11`) are worth reusing directly as a Rust test module's own defaults for parity. `add_service(message, service_type, service_name, addresses, port, properties)` is the general-purpose "append a full A+SRV+TXT+PTR record set for one service to a `DnsMessage`" helper used throughout `tests/core/test_mdns.py` — a Rust port's equivalent test-fixture builder should mirror this function's exact field wiring (SRV target is always `"{service_name}.local"`; PTR answer only added if `service_type` given; TXT resource skipped entirely if `properties` is empty, not emitted as an empty-TXT record).

### 8.3 `tests/core/test_mdns.py` (266 lines)

Uses a synthetic `mrp_service(SERVICE_NAME="Kitchen", ..., addresses=["127.0.0.1"], port=1234)` fixture (from `fake_udns.py`, §8.5) round-tripped through `create_service_queries` → `fake_udns.create_response` → `DnsMessage().unpack()`. Notable assertions:
- A query for a missing service yields `2` questions (the missing service **plus** the always-appended sleep-proxy question, §2.2), `0` answers, `0` resources.
- A query for the real MRP service yields `2` questions, `1` answer (the PTR), `3` resources (A + SRV + TXT).
- The question's `qclass == 0x8001` exactly (`tests/core/test_mdns.py:64`) — the canonical assertion for the QU-bit-in-qclass encoding, §1.5.
- `ServiceParser` behavior: empty message → `[]`; missing service type → `0` parsed; missing service name → `0` parsed; a service with both type and name → `1` parsed with fields matching exactly; port/address present → correctly threaded through; **multiple non-link-local addresses → any one of them is acceptable** (membership assertion, not index assertion, `tests/core/test_mdns.py:207-220` — do not over-constrain a Rust port's address-selection determinism beyond what's actually tested); a link-local-only address list → `service.address is None`; property keys are lower-cased on read even if written mixed-case (the `CaseInsensitiveDict` side-effect, explicitly called out in the source comment as "an unwanted side-effect... but... very unlikely... a big problem", `tests/core/test_mdns.py:238-241` — worth flagging to a Rust porter that `service.properties["Bar"]` after inserting `{"FOO": ..., "Bar": ...}` yields keys `"foo"`/`"Bar"` as originally-cased on the specific casing of whichever insertion happened, since `CaseInsensitiveDict.__iter__`/keys() surface the **as-inserted** casing while `__getitem__`/`__contains__` normalize on read, §1.8); duplicate byte-identical records across repeated `add_message` calls collapse to one stored record (structural-equality dedup, §2.3).

### 8.4 `tests/core/test_mdns_functional.py` (298 lines) — end-to-end client-vs.-fake-server behavior, the best source for retry/timing/deep-sleep known-answers

- `test_unicast_multiple_requests` (`tests/core/test_mdns_functional.py:132-143`): parametrized `(service_count, expected_requests)` = `(1,1), (3,1), (4,2), (7,3)` — i.e. **exactly `ceil(n/3)` request messages sent**, confirming §2.2's chunking-count contract independent of the internal slice-window overlap quirk.
- `test_unicast_resend_if_no_response` (`tests/core/test_mdns_functional.py:146-152`): server configured to silently drop the first 2 requests (`skip_count = 2`) with a 3-second client timeout — the client's once-per-second resend loop (§2.4) recovers and still gets a valid response on/before the 3rd attempt.
- `test_unicast_includes_sleep_proxy_service` (`tests/core/test_mdns_functional.py:165-186`): querying for one arbitrary service type against a fake server that also has a `_sleep-proxy._udp.local` entry registered yields **2** services back (the queried one plus sleep-proxy), confirming the sleep-proxy question is always answered when a matching fake service exists, not just always *asked*.
- `test_multicast_end_condition_met` (`tests/core/test_mdns_functional.py:209-228`): proves `end_condition` is called with the fully-constructed `Response` for the winning source and that exactly one `Response` is returned once it fires `True`.
- `test_multicast_sleeping_device` (`tests/core/test_mdns_functional.py:231-252`): with `udns_server.sleep_proxy = True` and a service registered with `port=0`, a multicast scan configured to wait for 0 responses (`multicast_fastexit(responses=0, requests=3)`, i.e. deliberately never satisfied by response-count, forcing it to run out the full request-count budget instead) yields **`len(resp) == 0`** — i.e. **a purely-sleeping device with no other detail produces zero `Response` objects from `multicast()` itself in this exact test configuration** (this is a fast-exit-fixture artifact of the test harness's specific wait condition, not a general "sleeping devices never appear" rule — contrast with `test_multicast_deep_sleep` immediately below, which **does** get a `Response` back with `deep_sleep=True` once its fast-exit condition is satisfied by response count instead of request count). Then, switching `udns_server.services` back to the normal `TEST_SERVICES` fixture and re-scanning with a response-count-based fast-exit condition, the device is found normally.
- `test_multicast_deep_sleep` (`tests/core/test_mdns_functional.py:255-271`): the cleanest direct assertion — `resp[0].deep_sleep` is `False` for a normal responding fake service, then (after setting `udns_server.sleep_proxy = True` and re-querying) `resp[0].deep_sleep` is `True`. This is the fixture to port most directly for validating `MulticastDnsSdClientProtocol.datagram_received`'s `is_sleep_proxy` logic (§2.6).
- `test_multicast_device_model` (`tests/core/test_mdns_functional.py:274-297`): confirms `Response.model` is `None`/falsy when no `_device-info._tcp.local` record is present, and equals the literal `"dummy"` model string once a fake service with `model="dummy"` is registered (`fake_udns.create_response`'s model-record-synthesis path, §8.5) — the model resolution itself (`_MODEL_LIST`/`_INTERNAL_NAME_LIST` lookup) happens later, at the `BaseScanner` layer, not inside `mdns.py`; `Response.model` is always the **raw** TXT string.

### 8.5 `tests/fake_udns.py` (315 lines) — the exact TXT dictionaries per fake service, verbatim (this is the single most important source for building realistic Rust test fixtures, since it defines the canonical shape of every wire-format service pyatv's own test suite is validated against)

```python
def mrp_service(service_name, atv_name, identifier, addresses=["127.0.0.1"], port=49152, model=None, version="18M60"):
    properties = {
        "Name": atv_name.encode("utf-8"),
        "UniqueIdentifier": identifier.encode("utf-8"),
        "SystemBuildVersion": version.encode("utf-8"),
    }
    # -> ("_mediaremotetv._tcp.local", FakeDnsService(name=service_name, addresses=addresses, port=port, properties=properties, model=model))

def airplay_service(atv_name, deviceid, addresses=["127.0.0.1"], port=7000, model=None):
    properties = {"deviceid": deviceid.encode("utf-8"), "features": b"0x1"}
    if model:
        properties["model"] = model.encode("utf-8")
        properties["flags"] = "0x8".encode("utf-8")  # Pin required
    # -> ("_airplay._tcp.local", FakeDnsService(name=atv_name, addresses=addresses, port=port, properties=properties, model=model))

def homesharing_service(service_name, atv_name, hsgid, addresses=["127.0.0.1"], model=None):
    properties = {"hG": hsgid.encode("utf-8"), "Name": atv_name.encode("utf-8")}
    # -> ("_appletv-v2._tcp.local", FakeDnsService(name=service_name, addresses=addresses, port=3689, properties=properties, model=model))

def device_service(service_name, atv_name, addresses=["127.0.0.1"], model=None):
    properties = {"CtlN": atv_name.encode("utf-8")}
    # -> ("_touch-able._tcp.local", FakeDnsService(name=service_name, addresses=addresses, port=3689, properties=properties, model=model))

def companion_service(service_name, addresses=["127.0.0.1"], port=0, model=None):
    properties = {"rpHA": "33efedd528a".encode("utf-8")}
    # -> ("_companion-link._tcp.local", FakeDnsService(name=service_name, addresses=addresses, port=port, properties=properties, model=model))

def raop_service(name, identifier, addresses=["127.0.0.1"], port=0, model=None):
    # -> ("_raop._tcp.local", FakeDnsService(name=f"{identifier}@{name}", addresses=addresses, port=port, properties={}, model=model))

def hscp_service(name, identifier, hsgid, addresses=["127.0.0.1"], port=0, model=None):
    properties = {"Machine Name": name.encode("utf-8"), "Machine ID": identifier.encode("utf-8"), "hG": hsgid.encode("utf-8")}
    # -> ("_hscp._tcp.local", FakeDnsService(name="HSCP Name", addresses=addresses, port=port, properties=properties, model=model))
```

Notes worth preserving in a Rust port's own fixture builders:
- `companion_service`'s fixture TXT payload (`{"rpHA": "33efedd528a"}`) does **not** include `rpfl` or `rpmrtid` at all — meaning this specific fixture, used as-is, would resolve `get_unique_id` to `None` (no `rpmrtid`) and `service_info`'s pairing derivation to the `flags == 0` (absent → defaults to `"0x0"`) branch, i.e. `PairingRequirement.Unsupported` — consistent with the real-world "Companion alone isn't discoverable" behavior documented in §7.3/§8.7.
- `raop_service`'s fixture has **empty properties** (`{}`) — none of RAOP's `am`/`ov`/`et`/`md`/`sr`/`ch`/`ss` TXT keys are exercised by this particular fixture generator at all; a Rust port wanting to test RAOP's fuller property-driven logic (§7.5, `raop/parsers.py`) needs to hand-construct additional fixtures beyond what `fake_udns.py` provides out of the box.
- `airplay_service` only sets `"model"`/`"flags"` **conditionally**, when a `model=` argument is passed — the unconditional baseline is just `deviceid` + `features=0x1`. `flags` is hardcoded to `"0x8"` (`PIN_REQUIRED`, §7.4) whenever a model is given, regardless of what model — i.e. this fixture generator always produces a pairing-`Mandatory`-shaped AirPlay service (per `get_pairing_requirement`'s `PIN_REQUIRED` branch) whenever `model` is set, and a pairing-`NotNeeded`-shaped one (no flags at all → `_get_flags` defaults to `0x0`) otherwise.

`_lookup_service` (`fake_udns.py:161-178`) and `create_response` (`fake_udns.py:181-237`) together are the fake server's request→response synthesis logic — worth porting as a Rust integration-test helper directly, since it's what generates realistic wire-format `DnsMessage`s (SRV rdata built by hand as `struct.pack(">3H", 0, 0, port) + qname_encode(name + ".local")`, response flags hardcoded to `0x0840`, §1.1) from the same declarative `FakeDnsService` shape used throughout the protocol-specific scan tests (§8.6).

### 8.6 Per-protocol scan tests (`tests/protocols/{mrp,companion,airplay,raop,dmap}/test_*_scan.py`)

All share the `udns_server`/`unicast_scan`/`multicast_scan` fixtures from `tests/conftest.py:117-152` (§ below) and the `assert_device(atv, name, address, identifier, protocol, port, creds=None)` helper (`tests/utils.py:146-152`: asserts `atv.name`, `atv.address`, `atv.identifier`, `atv.get_service(protocol).port`, `atv.get_service(protocol).credentials`).

Highest-value assertions to port as Rust known-answer tests:
- MRP (`tests/protocols/mrp/test_mrp_scan.py`): both unicast and multicast scans of a single MRP fixture at port `49152` on `10.0.0.1` yield exactly one device with the expected name/address/identifier/port.
- Companion (`tests/protocols/companion/test_companion_scan.py:23-31`): a **lone** Companion service (no MRP/other identifier-bearing sibling) yields **zero** scan results — Companion alone is never `ready` (§4.2, §7.3). Combined with an MRP service on the same address (`:37-59`), exactly one device results, with `dev.name == COMPANIOM_NAME` (from the MRP service's `Name` TXT property, since MRP's handler supplies the display name for the merged device — Companion's own handler always returns `mdns_service.name` as its proposed name, but the **first**-discovered service for an address wins the device's overall `name` field per `BaseScanner._service_discovered`, §3.2 step 2, and here MRP is registered first in the test), `dev.get_service(Protocol.MRP)` present, and `dev.get_service(Protocol.Companion).port == COMPANION_PORT`. A **unicast** scan for Companion alone (`:62-68`) also yields zero results — unicast scanning doesn't change Companion's fundamental "no usable identifier alone" limitation.
- AirPlay (`tests/protocols/airplay/test_airplay_scan.py`): single-service multicast and unicast scans both directly assert `atvs[0].identifier == AIRPLAY_ID` where `AIRPLAY_ID = "AA:BB:CC:DD:EE:FF"` was passed as the fixture's `deviceid` — confirming the `get_unique_id` → `MutableService.identifier` → `BaseConfig.identifier` chain end to end for AirPlay specifically.
- RAOP (`tests/protocols/raop/test_raop_scan.py`): straightforward single-service unicast/multicast round trips, `RAOP_ID = "AABBCCDDEEFF"` (no `@`-embedded punctuation, exercising the "identifier embedded in instance name" branch of `get_unique_id`, §7.7, since `raop_service`'s fixture always constructs the instance name as `f"{identifier}@{name}"`).
- DMAP (`tests/protocols/dmap/test_dmap_scan.py`, 148 lines, the richest of the five): explicitly tests the **Home-Sharing-plus-plain-DMAP merge** scenario (`device_service` + `homesharing_service` both registered for the same `service_name/address`, `:24-45`) yielding one merged device with `port=3689` and `creds=DMAP_HSGID` (i.e. the Home Sharing service's `hG`-derived credentials survive the merge, per `BaseService.merge`'s credentials rule, §4.4, since Home Sharing's handler is the one that actually sets `service.credentials`); a standalone HSCP scan (`:72-89`); unicast equivalents of both; and a **DMAP-without-Home-Sharing** case (`test_unicast_scan_no_homesharing`, `:113-128`) where the resulting device has `creds=None` (default parameter, no credentials at all) since the legacy `dmap_service_handler` never sets `service.credentials`.

### 8.7 `tests/test_scan_functional.py` (224 lines) — cross-cutting, protocol-agnostic scan behavior (uses MRP/AirPlay/RAOP as arbitrary stand-ins, per its own module docstring, "to emphasize that the specific protocols are irrelevant")

The single richest general-purpose fixture file for a Rust port's integration-test suite. Key cases, all worth reproducing as-is:
- `test_multicast_scan_for_particular_device` (`:73-81`): three services registered (MRP, AirPlay, RAOP) at two different addresses; scanning with `identifier={SERVICE_1_ID, SERVICE_2_ID}` (a **set** covering both the MRP and AirPlay identifiers, which happen to share one address in this fixture) yields exactly the one matching device — proving `_end_if_identifier_found`'s `isdisjoint` check (§3.4) correctly matches on *either* identifier being present.
- `test_multicast_scan_for_specific_devices` (`:84-91`): a **single**-identifier (`str`, not `set`) filter also works, matching only the AirPlay device specifically at its own distinct address.
- `test_multicast_scan_deep_sleeping_device` (`:94-103`): with `udns_server.sleep_proxy = True` and a single MRP service registered, the resulting device **does** appear (`len(atvs) == 1`) with `atvs[0].deep_sleep == True` — this is the canonical end-to-end (not just `mdns.py`-internal, §8.4) proof that a sleeping device *with* a service that has a resolvable identifier still produces a usable `conf.AppleTV`, contradicting a naive reading of "sleeping devices never appear" — the earlier `test_multicast_sleeping_device` unit test's zero-result outcome (§8.4) was a fast-exit-fixture-timing artifact specific to that unit test's harness configuration, not a general truth; a Rust port must be able to produce a `deep_sleep=True`, otherwise-normal `conf.AppleTV` for this scenario.
- `test_multicast_scan_device_info` / `test_unicast_scan_device_info` (`:106-115`, `:176-185`): with both MRP and AirPlay services registered on one device, `device_info.mac == SERVICE_2_ID` (the AirPlay identifier, since AirPlay's `deviceid` property doubles as both the AirPlay unique-id and the `DeviceInfo.MAC` value, §7.4) — a clean end-to-end proof of that specific "identifier equals MAC" coupling.
- `test_multicast_scan_device_model` / `test_unicast_scan_device_model` (`:117-124`, `:187-194`): MRP fixture constructed with `model="J105aAP"` (an **internal** codename, §5.2) resolves to `DeviceModel.Gen4K` via the `_device-info._tcp.local`-implied internal-name lookup path (§3.2 step 3), *not* via any of MRP's own TXT properties (MRP's `device_info()` extractor never reads a `model` property at all, §7.2) — proving the internal-name-lookup path is load-bearing and must be ported faithfully, not treated as a redundant/optional fallback.
- `test_multicast_filter_multiple_protocols` / `test_unicast_filter_multiple_protocols` (`:127-140`, `:203-214`): scanning with `protocol={Protocol.MRP, Protocol.RAOP}` against a device advertising MRP+AirPlay+RAOP yields one device with **exactly 2** services (MRP and RAOP only) — proving the `protocol=` filter in `pyatv.scan()` (`pyatv/__init__.py:72-88`) is applied at the **registration** level (only matching protocols' `scan()`/`add_service` calls happen at all) rather than as a post-hoc filter on discovered services.
- `test_multicast_mrp_tvos15_disabled` / `test_unicast_mrp_tvos15_disabled` (`:143-150`, `:217-224`): an MRP fixture built with `version="19J346"` (build-major 19 → tvOS 15.0 per `_VERSION_LIST`, §5.3) still produces a device (`len(atvs) == 1`) but with `atv.get_service(Protocol.MRP).enabled == False` — confirming the disabled service is still **discovered and attached**, just flagged `enabled=False`, not silently dropped from the resulting config entirely (consistent with §7.2's `enabled` gate being independent from whether a `MutableService` gets constructed at all).
- `test_unicast_missing_port` / `test_unicast_missing_properties` (`:158-173`): a raw `FakeDnsService("dummy", SERVICE_1_IP, None, None, None)` (port and properties both `None`) or `(..., 1234, None, None)` (properties `None` specifically) both yield **zero** scan results — though note neither of these actually maps to a real registered service type in these two tests (the fake service is added directly to `udns_server.services` without going through any of the `fake_udns.*_service()` builder functions, so it never matches any question pyatv actually asks for) — these two tests are really validating that malformed/unmatched fake-server entries don't crash anything, more than they're validating the port==0/properties==None gates in `_service_discovered` specifically (those gates are more directly covered by the deep-sleep-service placeholder-shape tests in §8.4).
- `test_unicast_scan_port_knock` (`:197-200`): asserts `stub_knock_server.ports == {3689, 7000, 49152, 32498}` (i.e. exactly `KNOCK_PORTS`, §3.1/§6) and `knock_count == 1` for a single unicast-scanned host — confirming knocking fires exactly once per host per scan call (not once per service or once per resend iteration).

### 8.8 `tests/support/test_device_info.py` (76 lines) — direct lookup-table known-answers, copy verbatim as Rust unit tests

```
lookup_model("AppleTV6,2") == DeviceModel.Gen4K
lookup_model("AudioAccessory5,1") == DeviceModel.HomePodMini
lookup_model("bad_model") == DeviceModel.Unknown

lookup_internal_name("J105aAP") == DeviceModel.Gen4K
lookup_internal_name("bad_name") == DeviceModel.Unknown

lookup_version(None) == None
lookup_version("17J586") == "13.0"
lookup_version("bad_version") == None
lookup_version("16F123") == "12.x"     # fallback formula: base(16) - 4 = 12
lookup_version("17F123") == "13.x"     # fallback formula: base(17) - 4 = 13

lookup_os("bad") == OperatingSystem.Unknown
lookup_os("MacBookAir10,1") == OperatingSystem.MacOS
lookup_os("iMac1,2") == OperatingSystem.MacOS
lookup_os("Macmini1,1") == OperatingSystem.MacOS
lookup_os("MacBookPro5,67") == OperatingSystem.MacOS
lookup_os("Mac1,4") == OperatingSystem.MacOS
lookup_os("MacPro19,4") == OperatingSystem.MacOS
lookup_os(DeviceModel.AirPortExpress) == OperatingSystem.AirPortOS
lookup_os(DeviceModel.AirPortExpressGen2) == OperatingSystem.AirPortOS
lookup_os(DeviceModel.HomePod) == OperatingSystem.TvOS
lookup_os(DeviceModel.HomePodGen2) == OperatingSystem.TvOS
lookup_os(DeviceModel.HomePodMini) == OperatingSystem.TvOS
lookup_os(DeviceModel.AppleTVGen1) == OperatingSystem.Legacy
lookup_os(DeviceModel.Gen2) == OperatingSystem.Legacy
lookup_os(DeviceModel.Gen3) == OperatingSystem.Legacy
lookup_os(DeviceModel.Gen4) == OperatingSystem.TvOS
lookup_os(DeviceModel.Gen4K) == OperatingSystem.TvOS
lookup_os(DeviceModel.AppleTV4KGen2) == OperatingSystem.TvOS
lookup_os(DeviceModel.AppleTV4KGen3) == OperatingSystem.TvOS
```

### 8.9 `tests/protocols/airplay/test_utils.py` (165 lines) — direct known-answers for `parse_features`/`is_password_required`/`get_pairing_requirement`/`is_remote_control_supported`/`get_protocol_version`, all already tabulated in §7.4's prose; copy the parametrized tables at `tests/protocols/airplay/test_utils.py:28-49` (`parse_features`), `:52-58` (bad-input `ValueError` cases: `"foo"`, `"1234"`, `"0x00000001,"`, `",0x00000001"`, `"0x00000001,0x00000001,0x00000001"`), `:61-76` (`is_password_required`), `:79-99` (`get_pairing_requirement`), `:102-119` (`is_remote_control_supported`, including the HAP-vs-legacy-vs-transient-vs-no-credentials matrix), and `:122-165` (`get_protocol_version`, including the specific real-world feature-flag hex pairs `"0x5A7FFFF7,0xE"` for an Apple TV 3 → `AirPlayV1`, and `"0x4A7FCA00,0xBC354BD0"` for a HomePod mini → `AirPlayV2`) directly into a Rust test module — these are exact input/output pairs with no ambiguity.

### 8.10 `tests/conftest.py` scan fixtures (`tests/conftest.py:79-152`), for understanding how the above tests are wired

`stub_knock_server` (`:100-110`) replaces `pyatv.support.knock.knock` (not `knocker`) with a stub recording `ports`/`knock_count` — meaning the real TCP-connect behavior of `_async_knock` is **never exercised** by any of these scan tests; a Rust port validating knock behavior end-to-end needs its own dedicated test against real (loopback) sockets, separate from the scan-fixture tests. `udns_server` (`:117-122`) always depends on `stub_knock_server` (explicit comment: "to make sure all UDNS tests uses a stubbed knock server" — i.e. knocking is considered orthogonal noise for scan-correctness tests specifically). `multicast_scan_fixture`/`unicast_scan_fixture` (`:124-152`) are the `Scanner` type alias callables (`Callable[..., Awaitable[List[BaseConfig]]]`) used throughout §8.6/§8.7 — multicast tests patch `pyatv.core.mdns.multicast` entirely (via `fake_udns.stub_multicast`, §2.8-adjacent — not `publish`, a differently-named context manager in `fake_udns.py:286-315` that fans a single fake-server-backed `mdns.unicast` call out per discovered fixture address, re-wrapping results as multicast-shaped `Response`s), while unicast tests instead set the `PYATV_UDNS_PORT` environment variable (§3.3) to redirect real unicast traffic at the in-process fake UDP server — **two structurally different faking strategies for the two scan modes**, worth knowing if a Rust port's own test harness wants an equivalent split (a fake-server-with-real-sockets approach, matching the unicast strategy, is probably the simpler and more end-to-end-faithful one to standardize on for a Rust integration-test suite, since it doesn't require monkeypatching a transport-selection function).

---

## 9. Divergences & open questions

Numbered for easy reference back from implementation review.

1. **`create_service_queries`'s chunk-window overlap** (§2.2, `pyatv/core/mdns.py:79-92`): the slice is `[i*3 : i*3+4]` against a loop stepping by 3, producing a 4-wide window on a 3-wide stride — almost certainly an off-by-one bug relative to the `SERVICES_PER_MSG = 3` constant's evident intent, causing the boundary service in each chunk to be queried twice across two consecutive messages whenever `len(services) mod 3 != 0`. The `ceil(n/3)` request-*count* contract is separately tested and stable (§8.4), but the actual per-message service *sets* have this duplication. **Decision needed**: reproduce the bug exactly for byte-for-byte wire compatibility with `master`, or fix it in the Rust port (functionally harmless either way — redundant PTR questions in one message are not wrong, just wasteful) and only match the request-count contract. Recommend: fix it in Rust (implement the evidently-intended `[i*3:(i+1)*3]` chunking) and only test-parity against the request-count assertions, not the exact per-message service-set overlap, since nothing downstream depends on the duplication being present.

2. **`knocker()`'s docstring vs. implementation** (§6, `pyatv/support/knock.py:68-79`): docstring claims "new port knocks are sent every two seconds," but `knock()` performs exactly one attempt per port with no resend loop at all. Implement the code's actual behavior (one attempt), not the docstring's claim, and consider filing/tracking this as a genuine upstream doc bug if this project ever wants to report it back.

3. **Companion `PAIRING_DISABLED_MASK`/`PAIRING_WITH_PIN_SUPPORTED_MASK` comment/value mismatch** (§7.3, `pyatv/protocols/companion/__init__.py:56-79`): the derivation-arithmetic comments compute `0x20` and "masking 0x40000" respectively, but the actual constants are `0x04` and `0x4000`. Use the constants as written in code (`0x04`, `0x4000`) since those are what's tested against real-device-observed `rpfl` values per the same comments' worked examples — the arithmetic prose itself appears to have a stale hex-digit-count typo, not the constant.

4. **`_VERSION_LIST`'s `"22J354": "17.0"` outlier** (§5.3): every other tvOS 17.x build in the table starts with prefix `21`, consistent with the `base - 4` fallback formula; this one entry starts with `22`, which under that same formula would compute to `18.x`. Either this is a genuine, correctly-observed Apple build-numbering exception for the 17.0 release specifically, or an upstream transcription error. Reproduce the literal table verbatim for behavioral parity regardless (a Rust port should not "correct" this without independent verification against a real tvOS 17.0 device's advertised `SystemBuildVersion`), but flag it for someone with real-device access to double-check before treating it as ground truth for anything beyond wire-compatibility-with-pyatv purposes.

5. **`DeviceInfo.operating_system`'s inline model→OS inference table disagrees with `support/device_info.lookup_os`'s `DeviceModel`-branch table** (§4.6 vs §5.4, `pyatv/interface.py:982-1001` vs `pyatv/support/device_info.py:145-161`): `DeviceInfo.operating_system` omits `HomePodGen2` from its `TvOS` set (falls through to `Unknown` there) and omits `AppleTVGen1` from its `TvOS`/legacy set entirely (also falls through to `Unknown`), while `lookup_os` explicitly includes `HomePodGen2 -> TvOS` and `AppleTVGen1 -> Legacy`. These are two independently-maintained tables covering overlapping but not identical `DeviceModel` sets, and nothing in pyatv's own test suite (`tests/support/test_device_info.py` only exercises `lookup_os` directly, never `DeviceInfo.operating_system`) currently catches the drift. **Recommend**: for a Rust port, decide deliberately whether `DeviceInfo`'s OS-inference should be unified with `lookup_os` (arguably the more "correct" and complete table) or whether to reproduce both divergent behaviors faithfully depending on which code path a given field flows through — the safer choice for wire-compatibility with pyatv's exact behavior is to reproduce the divergence, but it should be a conscious decision, documented at the call site, not an accident of transcription.

6. **`BaseConfig.identifier` priority order `[MRP, DMAP, AirPlay, RAOP, Companion]` differs from `main_service`'s `[MRP, DMAP, AirPlay, RAOP]`** (§4.2, `pyatv/interface.py:1386-1421`): two separately-authored priority lists for superficially related concepts (which service's identifier represents "the device," vs. which service to actually connect through) — `main_service` never even considers Companion a candidate connection service at all, consistent with Companion being an auxiliary/control-only protocol, but `identifier` does fall back to it as a last resort. Reproduce both lists exactly and independently in a Rust port; do not attempt to derive one from the other or unify them into a single shared constant.

7. **`BaseConfig.__eq__` compares only `self.identifier == other.identifier`** (§4.2, `pyatv/interface.py:1442-1446`), with no explicit guard against both sides being `None`. Two configs that both failed to resolve any identifier at all (both `identifier is None`) would compare as equal under Python's `None == None`. In practice this is unlikely to bite because `ready` (§4.2) already filters out identifier-less configs before they reach most consumer code, but a Rust port choosing e.g. `Option<String>` + derived `PartialEq` should decide deliberately whether `None == None` should hold for two otherwise-unrelated device configs, or whether to special-case it to `false` (arguably the more defensively-correct choice, and one that would *not* match pyatv's literal behavior — a conscious divergence to weigh).

8. **`BaseService.apply`'s falsy-value-means-"keep existing"` settings-restore semantics** (§4.3, `pyatv/interface.py:219-227`): `settings.get("credentials") or self.credentials` treats a stored empty-string credential identically to an absent one. If a Rust port's `Storage` trait can legitimately persist an explicit empty string as "no credentials, and I mean it, don't fall back," this collapses that distinction. Likely not a real-world issue (credentials are never meaningfully empty-string in practice — they're either a real value or absent/`None`), but worth a one-line comment at the port site acknowledging the behavior is intentionally reproduced, not an oversight.

9. **Several `# TODO`-flagged, explicitly-acknowledged-as-guesses heuristics** exist directly in the source and are cited verbatim in this document at their respective sections — treat all of them as "reproduce the current behavior for compatibility, but do not treat as ground truth for new/future-tvOS behavior without independent verification":
   - `is_remote_control_supported` (§7.4, `pyatv/protocols/airplay/utils.py:160-180`) — model-string- and OS-major-version-based guessing for AirPlay remote-control-tunnel support.
   - `get_protocol_version` (§7.4, `pyatv/protocols/airplay/utils.py:237-259`) — feature-bit-based guessing for AirPlay-major-version detection.
   - MRP's blanket `OPERATING_SYSTEM = OperatingSystem.TvOS` (§7.2) and DMAP's blanket `OPERATING_SYSTEM = OperatingSystem.Legacy` (§7.6) — both explicitly commented "border line OK, but will do for now."
   - `parse_srv_dict`'s unchecked-target-`"."` TODO (§1.9, `pyatv/support/dns.py:239-240`) — pyatv never checks for the RFC-defined "service decidedly not available at this domain" SRV-target sentinel (`target == "."`); a Rust port can choose to add this check as a genuine improvement over pyatv, since nothing currently depends on its absence.

10. **`get_unique_id`'s `_touch-able._tcp.local`/`_appletv-v2._tcp.local` identifier-from-instance-name branch** (§7.7) splits the mDNS **instance name** on `_` to derive an identifier, but pyatv's own `fake_udns.py` test-fixture builders for these two service types (`device_service`/`homesharing_service`, §8.5) never actually construct instance names containing an embedded `_`-separated identifier — they pass the identifier through a completely different channel (`hsgid`, wired into the `hG` TXT property, used for credentials, not identity) and the test assertions (`tests/protocols/dmap/test_dmap_scan.py`) always use `DMAP_SERVICE_NAME` as both the instance name **and** the expected identifier verbatim (i.e. `service_name.split("_")[0] == service_name` in every test fixture used, because none of the fixture names actually contain an underscore in a position that would produce a different split result). This means the `split("_")[0]` behavior for a **realistic** legacy-DMAP instance name (which real Apple TV 1/2/3 firmware may or may not actually format with an embedded identifier prefix) is effectively untested by pyatv's own suite. **Recommend**: if real DMAP/Home-Sharing capture data is available (per `CLAUDE.md`'s "capture-based known-answer test" guidance), verify this specific behavior against a real device before trusting the current implementation blindly; otherwise reproduce the code as written but flag the corresponding Rust test as "behavior-matches-pyatv, not independently verified against real hardware."

11. **The two independent, differently-keyed model-lookup tables** (`_MODEL_LIST` vs `_INTERNAL_NAME_LIST`, §3.2 step 3 / §5.1-5.2) and their response-arrival-order-dependent precedence when both could theoretically apply to the same device is not a bug per se, but is genuinely easy to misimplement as "one central priority table" in a naive port. Section 3.2 documents the exact mechanism (dict-insertion-order-dependent `dict_merge` with `allow_overwrite=False`, plus the `_device-info._tcp.local`-model-merge-last-and-never-overwrite step in `_get_device_info`) — a Rust port must replicate the *insertion-order-dependent, first-writer-wins* semantics precisely, not substitute a static protocol-priority table, or device-info `MODEL` resolution will silently disagree with pyatv on any real device where multiple services report conflicting model data.

12. **Zeroconf-crate-vs-hand-rolled-codec design decision** (§2 intro, §3.6): pyatv genuinely maintains two parallel scanner backends. This spec deliberately focuses on the hand-rolled-codec path since it's the more instructive, protocol-detail-rich one and the one that produces genuine byte-level wire traffic pyatv fully controls; a production Rust port could reasonably choose to lean on an existing Rust mDNS/DNS-SD crate (analogous to what the `Zeroconf*Scanner` path does in Python) instead of hand-rolling the wire codec, provided the `BaseScanner`-equivalent grouping/merge/precedence semantics (§3, §4) are preserved exactly regardless of transport. This is a legitimate architecture decision for the Rust project to make deliberately (and per `CLAUDE.md`'s decision-threshold table, one to surface to the user rather than assume), not something this spec prescribes.
