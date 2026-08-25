# DMAP/DAAP port spec — Step 7

Ground truth: `/tmp/pyatv-ref`, commit `b277a4c8222ecdcbaab8a24e3e713ca44765adb4` (tag/release `0.18.0`, `master`). All `path:line` citations below are relative to that checkout root and were re-read from source during this research pass, not recalled from training data. This document is the porting spec for the legacy DMAP/DAAP/DACP "Home Sharing" protocol (Apple TV gen 1–3, tvOS ≤ 12) — pyatv-rs Step 7.

Read first, and not duplicated here except where corrected: `docs/research/airplay-raop-dmap.md` §11 (the existing DMAP overview), `docs/research/discovery-port-spec.md` §7.6/§7.7/§8.5/§8.6 (DMAP's three mDNS scan handlers, `get_unique_id`, and the scan test fixtures — **already ported**, live at `crates/pyatv-mdns/src/scan/handlers/dmap.rs`, verified against source during this pass and matching pyatv exactly). This document covers what is *not* yet ported: the wire codec, the DAAP HTTP client state machine, the pairing responder (in which pyatv is the server), and the five public-facing interfaces (`RemoteControl`/`Metadata`/`PushUpdater`/`Features`/`Audio`).

Scaffold already in the tree, read before implementing so as not to duplicate it: `crates/pyatv-proto-dmap/src/{lib,error,tags,parser,pairing}.rs`. `tags.rs` and `parser.rs` are functionally complete for the read side (a `TAGS` table of 13 representative rows and a working TLV walker with unit tests); `pairing.rs` is a shell (`begin`/`verify_pairing_code` are both `todo!()`). There is no `daap.rs` yet, no `interfaces.rs`/`remote_control.rs`/`metadata.rs` etc., and no HTTP transport. Cargo.toml currently depends only on `bytes`, `pyatv-core`, `thiserror`, `tokio`, `tracing` — no HTTP client crate has been chosen yet (see §6).

---

## 0. Corrections to `docs/research/airplay-raop-dmap.md` §11

That report's DMAP section (lines 453–509) is accurate as far as it goes but compresses several details this spec expands, and gets two small things wrong or incomplete enough to flag explicitly before going further:

1. **§11.6 undersells the pairing hash construction as "PIN digits interleaved with zeros."** The precise algorithm, verified byte-for-byte against pyatv's own test fixtures in this pass (see §2.3 below), is: `MD5(pairing_guid_hex_uppercase_no_0x + PIN.zfill(4)[0] + "\x00" + PIN.zfill(4)[1] + "\x00" + PIN.zfill(4)[2] + "\x00" + PIN.zfill(4)[3] + "\x00")`, hex-digested lowercase, compared case-insensitively. The PIN is always treated as exactly 4 decimal digits via `str(pin).zfill(4)` (`pyatv/protocols/dmap/pairing.py:152`) — a PIN below 1000 is zero-padded on the left, not truncated or rejected. This spec's §2.3 gives four independently-verified known-answer vectors.
2. **§11.6's claim that pyatv "generates a random 64-bit pairing GUID"** is right about the bit width but omits that the encoding step (`hex(random.getrandbits(64))`) does **not** zero-pad to 16 hex digits — see §6's divergences for why this is a latent correctness gap in pyatv itself that a Rust port should not reproduce verbatim.
3. **§11.7's command list omits the exact wire bytes of the D-pad "virtual trackpad drag" gesture** and the fact that it takes exactly 7 `controlpromptentry` POSTs per arrow press, only the last of which the real device (and pyatv's own fake-device test harness) actually keys off of. §3.2 below gives the literal command strings.
4. **§11.3's header list is correct and already exhaustive** — verified against both `pyatv/protocols/dmap/daap.py:17-25` and the fake test device's independent `EXPECTED_HEADERS` copy at `tests/fake_device/dmap.py:17-25`, which are byte-identical dicts. No correction needed there; it is reproduced again in §1.3 only because §1 needs it inline for the retry/login sequencing discussion.
5. **§11.2 says "reproduce this table verbatim"** but does not include the table. §1.1 below is that table, all ~90 rows, transcribed directly from `pyatv/protocols/dmap/tag_definitions.py:24-124`.

---

## 1. `pyatv/protocols/dmap/{tags,parser,tag_definitions,daap}.py`

### 1.1 The full DMAP tag table, verbatim

Source: `pyatv/protocols/dmap/tag_definitions.py:24-124`. Every entry is `DmapTag(type, name)` where `type` is either the literal string `"container"` or one of six read functions from `tags.py` (§1.2). Reproduced here as `key → wire-type / dotted-name`, grouped exactly as pyatv orders them (recognized tags, then "yet unknown purpose" tags):

| Key | Type | Dotted name |
|---|---|---|
| `aelb` | bool | `com.apple.itunes.like-button` |
| `aels` | uint | `com.apple.itunes.liked-state` |
| `aeFP` | uint | `com.apple.itunes.req-fplay` |
| `aeGs` | bool | `com.apple.itunes.can-be-genius-seed` |
| `aeSV` | uint | `com.apple.itunes.music-sharing-version` |
| `apro` | uint | `daap.protocolversion` |
| `asai` | uint | `daap.songalbumid` |
| `asal` | string | `daap.songalbum` |
| `asar` | string | `daap.songartist` |
| `asgr` | uint | `com.apple.itunes.gapless-resy` |
| `astm` | uint | `daap.songtime` |
| `ated` | bool | `daap.supportsextradata` |
| `caar` | uint | `dacp.albumrepeat` |
| `caas` | uint | `dacp.albumshuffle` |
| `caci` | container | `dacp.controlint` |
| `cafe` | bool | `dacp.fullscreenenabled` |
| `cafs` | uint | `dacp.fullscreen` |
| `cana` | string | `daap.nowplayingartist` |
| `cang` | string | `dacp.nowplayinggenre` |
| `canl` | string | `daap.nowplayingalbum` |
| `cann` | string | `daap.nowplayingtrack` |
| `canp` | bytes | `daap.nowplayingid` |
| `cant` | uint | `dacp.remainingtime` |
| `capr` | uint | `dacp.protocolversion` |
| `caps` | uint | `dacp.playstatus` |
| `carp` | uint | `dacp.repeatstate` |
| `cash` | uint | `dacp.shufflestate` |
| `cast` | uint | `dacp.tracklength` |
| `casu` | uint | `dacp.su` |
| `cavc` | bool | `dacp.volumecontrollable` |
| `cave` | bool | `dacp.dacpvisualizerenabled` |
| `cavs` | uint | `dacp.visualizer` |
| `ceGS` | string | `com.apple.itunes.genius-selectable` |
| `ceQR` | container | `com.apple.itunes.playqueue-contents-response` |
| `ceSD` | bplist | `playing metadata` |
| `cmcp` | container | `dmcp.controlprompt` |
| `cmmk` | uint | `dmcp.mediakind` |
| `cmnm` | string | `dacp.devicename` |
| `cmpa` | container | `dacp.pairinganswer` |
| `cmpg` | uint | `dacp.pairingguid` |
| `cmpr` | uint | `dmcp.protocolversion` |
| `cmsr` | uint | `dmcp.serverrevision` |
| `cmst` | container | `dmcp.playstatus` |
| `cmty` | string | `dacp.devicetype` |
| `mdcl` | container | `dmap.dictionary` |
| `miid` | uint | `dmap.itemid` |
| `minm` | string | `dmap.itemname` |
| `mlcl` | container | `dmap.listing` |
| `mlid` | uint | `dmap.sessionid` |
| `mlit` | container | `dmap.listingitem` |
| `mlog` | container | `dmap.loginresponse` |
| `mpro` | uint | `dmap.protocolversion` |
| `mrco` | uint | `dmap.returnedcount` |
| `msal` | bool | `dmap.supportsautologout` |
| `msbr` | bool | `dmap.supportsbrowse` |
| `msdc` | uint | `dmap.databasescount` |
| `msed` | bool | `dmap.supportsedit` |
| `msex` | bool | `dmap.supportsextensions` |
| `msix` | bool | `dmap.supportsindex` |
| `mslr` | bool | `dmap.loginrequired` |
| `mspi` | bool | `dmap.supportspersistentids` |
| `msqy` | bool | `dmap.supportsquery` |
| `msrv` | container | `dmap.serverinforesponse` |
| `mstc` | uint | `dmap.utctime` |
| `mstm` | uint | `dmap.timeoutinterval` |
| `msto` | uint | `dmap.utcoffset` |
| `mstt` | uint | `dmap.status` |
| `msup` | bool | `dmap.supportsupdate` |
| `mtco` | uint | `dmap.containercount` |
| `aead` | bytes | unknown tag |
| `aeFR` | uint | unknown tag |
| `aeSX` | uint | unknown tag |
| `asse` | uint | unknown tag |
| `atCV` | uint | unknown tag |
| `atSV` | uint | unknown tag |
| `caks` | uint | unknown tag |
| `caov` | uint | unknown tag |
| `capl` | bytes | unknown tag |
| `casa` | uint | unknown tag |
| `casc` | uint | unknown tag |
| `cass` | uint | unknown tag |
| `ceQA` | uint | unknown tag |
| `ceQU` | bool | unknown tag |
| `ceMQ` | bool | unknown tag |
| `ceNQ` | uint | unknown tag |
| `ceNR` | bytes | unknown tag |
| `ceQu` | bool | unknown tag |
| `cmbe` | string | unknown tag |
| `cmcc` | string | unknown tag |
| `cmce` | string | unknown tag |
| `cmcv` | ignore | unknown tag |
| `cmik` | uint | unknown tag |
| `cmsb` | uint | unknown tag |
| `cmsc` | uint | unknown tag |
| `cmsp` | uint | unknown tag |
| `cmsv` | uint | unknown tag |
| `cmte` | string | unknown tag |
| `mscu` | uint | unknown tag |

That is 90 entries (55 with real dotted names, 35 marked "unknown tag" — note two of those, `cmbe` and `cmcc`, are load-bearing for remote-control input despite the "unknown" label; pyatv's own docs never resolved their DACP purpose beyond "control prompt entry / control prompt coordinates," but they are used constructively, see §3.2). Any key not in this table falls through to `lookup_tag`'s default (`pyatv/protocols/dmap/tag_definitions.py:127-132`):

```python
def lookup_tag(name):
    return next(
        (tag for tag_name, tag in _TAGS.items() if tag_name == name),
        DmapTag(_read_unknown, "unknown tag"),
    )
```

`_read_unknown(data, start, length)` (`tag_definitions.py:19-20`) logs `_LOGGER.warning("Unknown data: %s", str(data[start-8:start+length+8]))` (8 bytes of context on each side — deliberately over-reads into the surrounding header bytes for debug visibility) and implicitly returns `None` — an unrecognized tag's value in the parsed tree is always `None`, never an error, and the parser still advances correctly past it because the *length* field (not the type) drives cursor advancement (§1.2 below).

The Rust scaffold's `crates/pyatv-proto-dmap/src/tags.rs` `TAGS` constant currently holds 13 of these 90 rows (`cmst`, `caps`, `cann`, `cana`, `canl`, `cmsr`, `cmpg`, `cmpa`, `cmnm`, `cmty`, `mlcl`, `mlit`, `minm`) and has a `TODO(step-1)` marking the gap — filling it in with the remaining 77 rows above (mapping `read_bplist`→`TagType::Bplist`, `read_ignore`→`TagType::Ignore`, `read_bytes`→`TagType::Bytes`, everything else per the table) is a direct, low-risk mechanical task once this document exists.

### 1.2 The binary codec — containers, fixed-width ints, the "no per-tag width" quirk

Wire format (`pyatv/protocols/dmap/parser.py:1-9`, already documented in `docs/research/airplay-raop-dmap.md:461-464` and in the Rust scaffold's module doc):

```
+---------------+------------------+---------------------+
| Key (4 bytes) | Length (4 bytes) | Data (Length bytes)  |
+---------------+------------------+---------------------+
```

`Length` is always a 4-byte big-endian `u32`, unconditionally, for every tag including containers — `container_tag` is literally an alias for `raw_tag` on the encode side (`pyatv/protocols/dmap/tags.py:86-88`: `def container_tag(name, data): return raw_tag(name, data) # Same as raw`). There is no separate "this is a container, use a different length encoding" wire marker; containers are indistinguishable from opaque blobs on the wire, which is precisely why a type table external to the payload is required to parse at all (already the framing rationale documented in the scaffold's module doc, `crates/pyatv-proto-dmap/src/parser.rs:1-13`).

**The "tag-length quirk" the value-reader functions all share:** none of `read_uint`, `read_bool`, `read_str`, `read_bytes` are actually width-specific despite pyatv naming the *writer* functions `uint8_tag`/`uint16_tag`/`uint32_tag`/`uint64_tag` (`tags.py:39-64`). All four writers just pick a fixed byte count and call `to_bytes(N, byteorder="big")`; on the **read** side there is exactly one function, `read_uint`, used for every integer tag regardless of its "declared" width in the naming convention:

```python
def read_uint(data, start, length):
    """Extract a uint from a position in a sequence."""
    return int.from_bytes(data[start : start + length], byteorder="big")
```

(`pyatv/protocols/dmap/tags.py:12-14`.) The tag table (§1.1) records only that a tag *is* an integer, never which width — the actual width is whatever the `Length` field on the wire says it is, for every single message, every time. This means: (a) a conformant Rust decoder must treat every "uint" tag as "read `length` big-endian bytes into the widest integer type that fits" exactly the way the scaffold's `DmapValue::as_uint` already does (`crates/pyatv-proto-dmap/src/parser.rs:42-52`, folding byte-by-byte up to 8 bytes) — this is correct and needs no change; (b) a real device is free to send, say, a `caps` (`dacp.playstatus`) tag as 1, 2, or 4 bytes depending on firmware, and pyatv's own fake-device test harness exercises exactly this variability (`tags.uint32_tag("caps", ...)` in `tests/fake_device/dmap.py:238` vs. `tags.uint8_tag(...)` elsewhere in the same file for other uint tags, e.g. `carp`/`cash`/`cavc` at lines 268-274) — **do not hardcode per-tag integer widths anywhere in the Rust port**, not even as a "known width" fast path, since pyatv itself never assumes one.

`read_bool` (`tags.py:17-19`) is `read_uint(...) == 1` — i.e. boolean tags are *also* not fixed-width on the read side; any nonzero-length integer reading to exactly `1` is `True`, everything else (including a multi-byte `0x0001`) is `False` only if the resulting integer isn't `1` — a 2-byte `0x0001` (`= 1`) reads `True` just as validly as a 1-byte `0x01`. The scaffold's `DmapValue::as_bool` (`crates/pyatv-proto-dmap/src/parser.rs:62-67`) currently only matches the literal single-byte patterns `[0x00]`/`[0x01]` and returns `None` for anything else — this is a **behavioral gap** relative to pyatv: pyatv never returns "not a bool," it returns a bool unconditionally by treating "reads as the uint `1`" as the only truth-defining condition (any width, any non-1 value → `False`). Fix `as_bool` to delegate to `as_uint() == Some(1)` (or equivalent) rather than pattern-matching exact byte shapes, to match pyatv's actual semantics exactly (there is no known-answer test yet, but `tags.py:17-19` is unambiguous ground truth).

`read_str` (`tags.py:7-9`) is `data[start:start+length].decode("utf-8")` — byte length, not character count, matching the scaffold and `docs/research/airplay-raop-dmap.md:466` already. `read_bytes` (`tags.py:29-31`) renders as `"0x" + binascii.hexlify(...).decode("ascii")` — lowercase hex, no separators, confirmed against `tests/protocols/dmap/test_parser.py:74-78` (`"0x01aaff45"` for input `b"\x01\xaa\xff\x45"`). `read_bplist` (`tags.py:22-26`) is `plistlib.loads(data, fmt=FMT_BINARY)` — needs the `plist` crate already recommended in `docs/research/airplay-raop-dmap.md` §12 for the AirPlay/RAOP work; only one tag currently uses it (`ceSD`, "playing metadata"). `read_ignore` (`tags.py:34-36`) takes the same three args and returns nothing (`None`), used for exactly one tag (`cmcv`) that pyatv has chosen to discard rather than even log.

### 1.3 `_parse`/`parse`/`first`/`pprint` — the recursive descent parser

Source: `pyatv/protocols/dmap/parser.py:32-65`, full function:

```python
def _parse(data, data_len, tag_lookup, pos, ctx=None):
    if ctx is None:
        ctx = []
    if pos >= data_len:
        return ctx

    f_name = read_str(data, pos, 4)
    f_len = read_uint(data, pos + 4, 4)
    pos += 8

    tag = tag_lookup(f_name)
    if tag.type == "container":
        ctx.append({f_name: _parse(data, pos + f_len, tag_lookup, pos, ctx=[])})
    else:
        ctx.append({f_name: tag.type(data, pos, f_len)})

    return _parse(data, data_len, tag_lookup, pos + f_len, ctx)
```

Note the argument reordering on the container-recursion call: `_parse(data, pos + f_len, tag_lookup, pos, ctx=[])` binds `data_len = pos + f_len` (bounding the recursive walk to end exactly at the container's own end) and `pos = pos` (the *start* of the container's data, i.e. right after its own 8-byte header) — this is how nesting depth is achieved without any explicit stack: each container invocation gets a narrower `data_len` window and a fresh empty `ctx` accumulator, and the *tail* call (`_parse(data, data_len, tag_lookup, pos + f_len, ctx)`) continues the *current* level past this tag using the *original* `data_len`. `parse(data, tag_lookup)` (`parser.py:51-53`) is just the entry point: `_parse(data, len(data), tag_lookup, 0, [])`.

**Representation shape — this is the biggest structural divergence from the Rust scaffold and needs a deliberate decision, not a mechanical port.** pyatv's parsed value is a `list` of single-key `dict`s, e.g. `[{"cmst": [{"caps": 4}, {"cmsr": 12}]}]`, preserving repeated-key order exactly (each occurrence is its own list element/dict, never collapsed into a multi-value map) — the scaffold's `Vec<DmapValue>` (flat, one level, `key`+`data: Bytes` pairs, containers left unparsed until a second `parse()` call, per `crates/pyatv-proto-dmap/src/parser.rs:28-35`) is a *shallower* structure by design (documented rationale: "container data is returned unparsed; call `parse` again on it once the tag table says the tag is a container" — `parser.rs:73-74`). Both are legitimate designs, but the **path-based lookup helper pyatv relies on everywhere is not yet present in the scaffold** and needs to be built as a wrapper, not assumed away:

```python
def first(dmap_data, *path):
    """Look up a value given a path in some parsed DMAP data."""
    if not (path and isinstance(dmap_data, list)):
        return dmap_data

    for key in dmap_data:
        if path[0] in key:
            return first(key[path[0]], *path[1:])

    return None
```

(`parser.py:56-65`.) This is used pervasively and multi-level, e.g. `parser.first(playstatus, "cmst", "caps")` (`pyatv/protocols/dmap/__init__.py:114`, one of ~15 call sites in `build_playing_instance` alone). The scaffold's current `first(entries, key)` (`crates/pyatv-proto-dmap/src/parser.rs:117-119`) only supports a single flat key at the *current* level — it does not recurse through nested (already-typed) containers the way pyatv's does, because the scaffold's `DmapValue` doesn't carry recursively-typed children at all yet. **Before `daap.rs`/`interfaces.rs` can be written, the Rust port needs either (a) a fully-typed recursive tree type (mirroring pyatv's list-of-dicts shape, built by walking the tag table eagerly at parse time) with a `first(&self, path: &[&str]) -> Option<&DmapNode>`-shaped helper, or (b) a lazier scheme that keeps the scaffold's flat `Vec<DmapValue>` per level but adds a `first_path(entries, tag_table, &["cmst", "caps"]) -> Option<DmapValue>` free function that re-parses each container level on demand.** Given the module-size and sans-io-core conventions in the workspace's `rust-core-logic` skill, option (a) — an eager, fully-typed tree — is the more idiomatic fit and avoids repeatedly re-walking container bytes for the ~15 fields `build_playing_instance`-equivalent code needs per response; this is a design decision to make explicitly during implementation, not one this spec should quietly assume.

`pprint` (`parser.py:68-84`) is a debug-formatting helper (indented `key: value [type, name]` tree, special-cased to not descend into `bplist`-typed values even though they're technically `dict`/`list`-shaped after `plistlib.loads`) — useful for `tracing::debug!` parity but not wire-format-relevant; port only if debug ergonomics are wanted, not required for correctness.

### 1.4 `DaapRequester` — login, session, URL construction, headers, retry

Source: `pyatv/protocols/dmap/daap.py:75-185`, full class. This is the piece with no Rust scaffold at all yet.

**Required headers, exact set and casing** (`daap.py:17-25`, byte-identical to the independent fake-device copy at `tests/fake_device/dmap.py:17-25`):

```
Accept: */*
Accept-Encoding: gzip
Client-DAAP-Version: 3.13
Client-ATV-Sharing-Version: 1.2
Client-iTunes-Sharing-Version: 3.15
User-Agent: Remote/1021
Viewer-Only-Client: 1
```

plus, only for POST requests, `Content-Type: application/x-www-form-urlencoded` added to a **copy** of the base dict (`daap.py:123-124`, `headers = copy(_DMAP_HEADERS); headers["Content-Type"] = "application/x-www-form-urlencoded"`) — GET requests never carry a `Content-Type`. pyatv does not assert a specific header *order* on the wire (Python dicts are insertion-ordered and `aiohttp` will emit them in that order, but no test in the suite checks wire byte order of headers, only presence+value via `tests/fake_device/dmap.py:302-305`'s `_verify_headers`) — a Rust port is free to choose its own header emission order as long as all seven (eight for POST) are present with these exact names/values.

**Login** (`daap.py:87-104`):

```python
async def login(self):
    def _login_request():
        url = self._mkurl("login?[AUTH]&hasFP=1", session=False, login_id=True)
        return self.http.get_data(url, headers=_DMAP_HEADERS)

    resp = await self._do(_login_request, is_login=True)
    self._session_id = parser.first(resp, "mlog", "mlid")
    return self._session_id
```

`_mkurl` (`daap.py:154-170`) is the URL builder and credential-format dispatcher:

```python
def _mkurl(self, cmd, *args, session=True, login_id=False):
    url = cmd.format(*args)
    parameters = []
    if login_id:
        if re.match(r"0x[0-9A-Fa-f]{16}", self._login_id):
            parameters.append(f"pairing-guid={self._login_id}")
        elif re.match(r"[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}", self._login_id):
            parameters.append(f"hsgid={self._login_id}")
        else:
            raise exceptions.InvalidCredentialsError(f"invalid credentials: {self._login_id}")
    if session:
        parameters.insert(0, f"session-id={self._session_id}")
    return url.replace("[AUTH]", "&".join(parameters))
```

So the two exact login URLs are:

```
GET login?pairing-guid=0xXXXXXXXXXXXXXXXX&hasFP=1
GET login?hsgid=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX&hasFP=1
```

with credential type chosen purely by regex match on the stored credential string — `pairing-guid` requires the `0x` prefix plus **exactly** 16 hex digits (`re.match` only requires the pattern at the *start* of the string, so a longer/malformed suffix wouldn't be rejected here — but see §6 for why 16 digits is not actually guaranteed by pyatv's own GUID generator), `hsgid` requires the canonical 8-4-4-4-12 UUID hyphenation. Anything matching neither raises `InvalidCredentialsError` (mapped in the Rust scaffold's `error.rs` to `Error::Pairing`/`pyatv_core::Error::Pairing` today — confirm this mapping is still the intended one when `daap.rs` is written, since "invalid credentials" and "pairing failed" are semantically distinct in pyatv's own `exceptions.py:51-58`, where `InvalidCredentialsError` and `AuthenticationError` are different classes from `PairingError`).

Because `session=False` for the login call, `[AUTH]` becomes just the credential parameter (no `session-id=`, since none exists yet). For every other request `session=True, login_id=False` (defaults), so `[AUTH]` becomes exactly `session-id={id}` — a single parameter, `pairing-guid`/`hsgid` are **only ever sent on the login call itself**, never repeated on subsequent requests.

**Command URL templates**, verbatim (`pyatv/protocols/dmap/__init__.py:61-63`, plus the ones assembled inline elsewhere):

```
ctrl-int/1/playstatusupdate?[AUTH]&revision-number={0}
ctrl-int/1/nowplayingartwork?mw={width}&mh={height}&[AUTH]
ctrl-int/1/controlpromptentry?[AUTH]&prompt-id=0
ctrl-int/1/{cmd}?[AUTH]&prompt-id=0                          # cmd ∈ {play, playpause, pause, stop, nextitem, previtem, volumeup, volumedown}
ctrl-int/1/setproperty?{prop}={value}&[AUTH]                 # prop ∈ {dacp.playingtime, dacp.shufflestate, dacp.repeatstate}
```

(`ctrl_int_cmd`/`controlprompt_cmd`/`set_property`, `__init__.py:228-243`.) After `[AUTH]` substitution these become e.g. `ctrl-int/1/playstatusupdate?session-id=55555&revision-number=0`, `ctrl-int/1/play?session-id=55555&prompt-id=0`, `ctrl-int/1/setproperty?dacp.playingtime=45000&session-id=55555`. There is no separate `server-info` request method in `DaapRequester`/`BaseDmapAppleTV` despite it appearing as an informational entry in `docs/research/airplay-raop-dmap.md:501` — grep of `pyatv/protocols/dmap/__init__.py` and `daap.py` in this pass found no `server-info` call site anywhere in the actual client code; treat that line in the prior report as **unverified/likely stale** (possibly transcribed from the pyatv wire-capture docs rather than the client implementation) and do not budget porting effort for a `server-info` call unless a live capture later proves a real device requires it unprompted.

**`_do` — the complete retry/re-login/error-mapping state machine** (`daap.py:130-152`, full function, already summarized loosely in the prior report but here given exactly):

```python
async def _do(self, action, retry=True, is_login=False, is_daap=True):
    resp, status = await action()
    if is_daap:
        resp = parser.parse(resp, lookup_tag)

    self._log_response(action.log_text, resp, is_daap)
    if 200 <= status < 300:
        return resp

    if status == 500:
        raise exceptions.NotSupportedError("command not supported at this stage")

    if not is_login:
        await self.login()

    if retry:
        return await self._do(action, False, is_login=is_login, is_daap=is_daap)

    raise exceptions.AuthenticationError(f"failed to login: {status}")
```

Traced precisely, this produces three distinct behaviors depending on call site and status:

1. **2xx**: return parsed (or raw, for `daap_data=False` calls like artwork) body. Terminal, success.
2. **Exactly HTTP 500** on *any* call (login or not): raise `NotSupportedError` immediately, **no retry, no re-login attempt** — pyatv's own comment flags this mapping as a guess (`"Seems to be the case?"`, `daap.py:139`).
3. **Any other non-2xx status** (a login call: 4xx/5xx-other-than-500; a non-login call: same): if this wasn't already a login call, call `self.login()` first (which itself recurses through this same state machine with `is_login=True` and its own independent one-retry budget — see below), then, if `retry` is still `True` at this level (it is, on the first pass through any top-level call), recurse into `_do` **again with `retry=False` and the same `action`** — i.e. the *original failing request* (not the login) is re-issued exactly once, now carrying whatever new session id `login()` produced. If that second attempt also fails non-2xx-non-500, `retry` is now `False`, so the final `else` fires: `raise AuthenticationError(f"failed to login: {status}")` — note the message says "failed to login" even when the *original* action wasn't a login call at all; this exact string (`daap.py:152`) is not asserted by any test but is worth preserving for parity/log-grepping purposes.

**Exception classes raised, and their current Rust mapping status** — pyatv distinguishes several exception types across this state machine and `_mkurl` (`pyatv/exceptions.py:27-58`, confirmed by grep of the full file in this pass):

| pyatv exception | Raised where | Current `crates/pyatv-proto-dmap/src/error.rs` equivalent |
|---|---|---|
| `exceptions.NotSupportedError` | `_do`, HTTP 500 (`daap.py:141`) | none yet — would currently fall through to `Error::HttpStatus(500)` → `pyatv_core::Error::InvalidResponse`, which loses the "not supported at this stage" semantic pyatv's own callers may rely on (e.g. to distinguish "try again" from "this device will never support this") |
| `exceptions.AuthenticationError` | `_do`, retry budget exhausted (`daap.py:152`) | none yet — same `HttpStatus`/`InvalidResponse` fallback problem |
| `exceptions.InvalidCredentialsError` | `_mkurl`, credential string matches neither regex (`daap.py:165-167`) | mapped today via the generic `Error::Pairing` variant in the scaffold, but pyatv's own `InvalidCredentialsError` and `PairingError`/`AuthenticationError` are three *different* classes (`exceptions.py:23-58`) — conflating "malformed stored credential string" with "pairing exchange failed" loses information a caller might reasonably want to distinguish (e.g. to suggest re-pairing vs. checking a config file) |
| `exceptions.UnknownMediaKindError` / `exceptions.UnknownPlayStateError` | `daap.media_kind`/`daap.playstate`, out-of-table wire value (`daap.py:42`, `:61`) | none yet — needed once `build_playing_instance` is ported (§3.3/§3.4) |

None of these four are fatal gaps at the current scaffold stage (the crate has no `daap.rs` yet for any of them to matter), but `crates/pyatv-proto-dmap/src/error.rs`'s `Error` enum (currently `Malformed`, `TypeMismatch`, `HttpStatus`, `Pairing`, `Io`) will need at least `NotSupported(String)`, `Authentication(String)`, `InvalidCredentials(String)`, `UnknownMediaKind(u64)`, `UnknownPlayState(u64)` variants added before `daap.rs`/`__init__`-equivalent code can report errors with pyatv's own granularity — `pyatv_core::Error` already has `Authentication` and (per §1.4's citation) a distinct `Pairing` variant to map the first three onto correctly; only the last two (media-kind/play-state) have no obvious `pyatv_core::Error` home yet and may need a new `pyatv_core::Error::InvalidResponse`-shaped catch-all or a dedicated variant, a decision for whoever wires `daap.rs` up.

For a **login call specifically** (`is_login=True`): step 3's `if not is_login:` guard is `False`, so the implicit re-login-then-retry branch is skipped, and control falls straight to `if retry:` — meaning a failing login is retried **exactly once, by re-issuing the same login request**, not by trying to log in-to-log-in recursively. This matches `test_connect_failed` (`tests/protocols/dmap/test_dmap_functional.py:96-102`): `make_login_fail()` called **twice** before connecting, and the resulting `AuthenticationError` is only raised after both attempts are exhausted — confirming "one retry, same request, no infinite recursion."

`test_relogin_if_session_expired` (`tests/protocols/dmap/test_dmap_functional.py:106-116`) is the canonical known-answer for the **non-login retry-with-relogin** path: an already-connected client's artwork request gets `403` (`artwork_no_permission()`, `tests/fake_device/dmap.py:361-367`, which serves `status=403` with no body), the client transparently calls `login()` again (getting a **new** session id via `force_relogin(1234)`), retries the *original* artwork request with that new session id, and the retried request succeeds because `change_artwork(...)` was queued before the call — the caller (`atv.metadata.artwork()`) never sees an exception, the whole 403→relogin→retry sequence is fully internal.

`_assure_logged_in` (`daap.py:172-176`) is a cheap pre-check gating `get`/`post` (not `login` itself, which is called directly): `if self._session_id != 0: <already logged in, no-op> else: await self.login()` — i.e. the *first* `get`/`post` call after construction always triggers an eager login before the actual request goes out, subsequent calls skip straight to the request unless a `_do`-level 403/expiry later forces an implicit re-login. `_session_id` starts at `0` (`daap.py:85`) and `0` is therefore the sentinel "not logged in yet" value, never a real session id pyatv would treat as valid (a real device could in principle hand back session id `0`, which would be indistinguishable from "not logged in" to this check — not exercised by any test, flag as a latent edge case, not fixed here).

---

## 2. `pyatv/protocols/dmap/pairing.py` — pyatv as the pairing *server*

Source: `pyatv/protocols/dmap/pairing.py`, full 158-line file. This is the piece with the largest scaffold gap: `crates/pyatv-proto-dmap/src/pairing.rs` has the right shape (`DmapPairing::new`/`pairing_guid`/`pin`/`has_paired`) but both `begin()` and `verify_pairing_code()` are `todo!()`.

### 2.1 Role reversal and the `_touch-remote._tcp.local.` service

pyatv starts an `aiohttp.web.Application` with exactly one route (`GET /pair`, `pairing.py:47-48`), binds it on an OS-assigned ephemeral port via `unused_port()` (`pyatv/support/net.py`, not covered further here — a Rust equivalent is `TcpListener::bind(("0.0.0.0", 0))` and reading back the bound port), and for **every** address in `self._addresses` (default: `get_private_addresses(include_loopback=False)`, i.e. every private non-loopback IPv4 the host has, unless the caller passed an explicit `addresses=` kwarg) publishes the same `_touch-remote._tcp.local` service pointed at that address (`begin`, `pairing.py:74-85`):

```python
async def begin(self) -> None:
    port = unused_port()
    await self.runner.setup()
    self.site = web.TCPSite(self.runner, "0.0.0.0", port)
    await self.site.start()
    for ipaddr in self._addresses:
        await self._publish_service(ipaddr, port)
```

`_publish_service` (`pairing.py:104-124`):

```python
async def _publish_service(self, address: IPv4Address, port: int) -> None:
    props = {
        "DvNm": self._name,
        "RemV": "10000",
        "DvTy": "iPod",
        "RemN": "Remote",
        "txtvers": "1",
        "Pair": self._pairing_guid,
    }
    await mdns.publish(
        self._core.loop,
        mdns.Service("_touch-remote._tcp.local", f"{int(address):040d}", address, port, props),
        self._zeroconf,
    )
```

**TXT record set, exact keys and values** (already listed correctly in `docs/research/airplay-raop-dmap.md:96`, reproduced here with types spelled out):

| TXT key | Value | Notes |
|---|---|---|
| `DvNm` | display name string | the "Remote" app's device name, e.g. `"pyatv remote"`; caller-configurable via the `name=` kwarg, defaults to `core.settings.info.name` |
| `RemV` | `"10000"` | literal, hardcoded remote-protocol-version string |
| `DvTy` | `"iPod"` | literal, hardcoded device-type spoof — pyatv presents itself as an iPod Remote app, not as what it actually is |
| `RemN` | `"Remote"` | literal, hardcoded |
| `txtvers` | `"1"` | literal |
| `Pair` | pairing GUID, hex digits **without** `0x` prefix, uppercase | this is the value the real Apple TV/iTunes shows the user to type in, or uses directly as part of its own callback — see §2.2 |

**Instance name is unusual and worth calling out explicitly since no prior report mentions it**: `f"{int(address):040d}"` — the IPv4 address converted to its 32-bit integer form and zero-padded to a **40-digit decimal string** (e.g. `10.0.10.1` → `int` `167774977` → `"0000000000000000000000000000167774977"`, 40 characters). This is not a human-meaningful name and is never asserted against in any test in the suite (`tests/protocols/dmap/test_dmap_pairing.py` only checks TXT properties and the resolved `addresses` list, never the service/instance name) — a Rust port should reproduce this exact format for wire compatibility with anything that might parse the DNS-SD instance name, but it is **not load-bearing for pyatv's own test suite** and is a reasonable candidate to simplify if a future maintainer decides fidelity here doesn't matter (flag as a judgment call, not settled by this spec).

**One service is published per address**, all sharing the *same* port (the one `aiohttp` server instance listening on `0.0.0.0:<port>` handles requests regardless of which advertised address the Apple TV connects back through) — `test_zeroconf_custom_addresses` (`tests/protocols/dmap/test_dmap_pairing.py:108-116`) confirms `len(zeroconf.registered_services) == len(addresses)` for a multi-address case.

### 2.2 The `GET /pair` handler and PIN verification

Source: `pairing.py:126-158`, full handler:

```python
async def handle_request(self, request) -> None:
    service_name = request.rel_url.query["servicename"]
    received_code = request.rel_url.query["pairingcode"].lower()

    if self._verify_pin(received_code):
        cmpg = tags.uint64_tag("cmpg", int(self._pairing_guid, 16))
        cmnm = tags.string_tag("cmnm", self._name)
        cmty = tags.string_tag("cmty", "iPhone")
        response = tags.container_tag("cmpa", cmpg + cmnm + cmty)
        self._has_paired = True
        return web.Response(body=response)

    return web.Response(status=500)
```

Query string is `GET /pair?pairingcode=<hex>&servicename=<name>` — both parameters required, `pairingcode` is lower-cased before comparison (case-insensitive match against the locally-computed uppercase-produced-then-implicitly-compared digest — see below), `servicename` is read but **never used** for anything beyond the `_LOGGER.info` call (`pairing.py:130-132`) — it is not validated against the published service name, not checked for a match, purely informational/log-only in current pyatv. On success: HTTP 200 with a DMAP `cmpa` container body containing `cmpg` (uint64, the pairing GUID as a *number*, not the hex-string form), `cmnm` (string, pyatv's own configured display name — the *same* value published as `DvNm`), `cmty` (string, hardcoded literal `"iPhone"` — note this differs from the `"iPod"` used in the `DvTy` TXT key; pyatv identifies itself as an iPod in mDNS advertisement but as an iPhone in the pairing response body, and this divergence is in pyatv's own source, not a transcription error in this spec). On mismatch: bare HTTP 500, no body, no DMAP container at all.

**`_verify_pin` — the exact hash algorithm** (`pairing.py:145-158`, full function):

```python
def _verify_pin(self, received_code: str) -> bool:
    if self._pin_code is None:
        return True

    merged = StringIO()
    merged.write(self._pairing_guid)
    for char in str(self._pin_code).zfill(4):
        merged.write(char)
        merged.write("\x00")

    expected_code = hashlib.md5(merged.getvalue().encode()).hexdigest()
    return received_code == expected_code
```

`self._pairing_guid` here is already the **stripped, uppercase, `0x`-free** hex string (set once at construction, `pairing.py:53-55`: `(kwargs.get("pairing_guid", None) or _generate_random_guid())[2:].upper()` — the `[2:]` strips a two-character prefix that is `"0x"` before `.upper()` turns it into `"0X"`... **order matters here and is a subtlety worth spelling out**: `.upper()` is called *after* `[2:]` in the actual expression (`(kwargs.get(...) or _generate_random_guid())[2:].upper()`), so the slice removes the literal `"0x"` (lowercase, since both a caller-supplied guid string and `_generate_random_guid()`'s `hex(...)` output use lowercase `0x`) *before* upper-casing the remaining digits — the net effect (strip 2 chars, then uppercase) is the same regardless of order for this specific case, but do not assume `.upper()` happened first when reasoning about intermediate values in a port). PIN handling: `str(self._pin_code).zfill(4)` left-pads the PIN's *decimal string form* to at least 4 characters with `'0'` — for the default `PIN_CODE = 1234` this is a no-op (`"1234"`), but `PIN_CODE3 = 1` becomes `"0001"` (verified exact match against `PAIRING_CODE3` below).

**Algorithm, spelled out as an unambiguous byte recipe:**

```
input  = pairing_guid_hex_uppercase_no_0x_prefix
       + PIN_decimal_str[0] + "\x00"
       + PIN_decimal_str[1] + "\x00"
       + PIN_decimal_str[2] + "\x00"
       + PIN_decimal_str[3] + "\x00"
digest = MD5(input.encode("utf-8"))   -> lowercase hex string
match  = received_code.lower() == digest      # both sides already lowercase in practice
```

Note the `\x00` bytes are single NUL bytes, not zero-width/absent — `merged.write("\x00")` after every digit including the last one, so the total input length is `len(pairing_guid_hex) + 8` bytes (4 digit chars + 4 NUL bytes), not `+7`.

### 2.3 Independently-verified known-answer vectors

All four of the following were re-derived in this research pass with an independent MD5 implementation (Node's `crypto` module, not pyatv) and matched exactly against `tests/protocols/dmap/test_dmap_pairing.py:20-38` — safe to copy directly into Rust `#[test]` cases with full confidence:

```
guid=0000000000000001  pin=1234  -> 690E6FF61E0D7C747654A42AED17047D   (uppercase form; MD5 is case-insensitive as hex but pyatv compares lowercased)
guid=1234ABCDE56789FF  pin=5555  -> 58AD1D195B6DAA58AA2EA29DC25B81C3
guid=7D1324235F535AE7  pin=1     -> A34C3361C7D57D61CA41F62A8042F069   (PIN zero-padded to "0001")
```

(GUIDs shown already stripped of `0x` and uppercased, matching what `_verify_pin` actually concatenates; the test file's `PAIRING_GUID`/`PAIRING_GUID2`/`PAIRING_GUID3` constants carry the `0x` prefix as stored-credential form, e.g. `PAIRING_GUID = "0x0000000000000001"`, `PAIRING_CODE = "690E6FF61E0D7C747654A42AED17047D"`.) A fourth vector, exercising `_generate_random_guid()`'s exact `hex()`-then-strip-then-upper transform: `random.getrandbits(64) == 6558272190156386627` → `hex(...) = "0x5b03a9cf4a983143"` → stripped/uppercased `"5B03A9CF4A983143"` → with `PIN_CODE = 1234` produces digest `7AF2D0B8629DE3C704D40A14C9E8CB93`, matching `RANDOM_PAIRING_CODE` at `tests/protocols/dmap/test_dmap_pairing.py:37-38`. This vector is also useful as a cross-check that `hex(getrandbits(64))` and `int.to_string(16)`-equivalent Rust code (e.g. `format!("{:X}", value)`) agree on digit case and leading-zero behavior for a value that happens to need all 16 hex digits — see §6 for the case where it *doesn't* need all 16.

**`_pin_code is None` short-circuits to "accept any code"** (`pairing.py:147-148`) — this is the state when a caller never invoked `.pin(...)` before a pairing request arrives; `test_succesful_pairing_with_any_pin` (`tests/protocols/dmap/test_dmap_pairing.py:151-157`) confirms an arbitrary garbage string (`"invalid_pairing_code"`) still returns HTTP 200 in that state. A Rust port's `DmapPairing::verify_pairing_code` needs an explicit `Option<u16>`-shaped "PIN not yet set" state distinct from "PIN is set to some value," not just a sentinel numeric PIN — the current scaffold's `DmapPairing::new(pairing_guid: String, pin: u16)` constructor takes a non-optional `pin` and has no way to represent "no PIN configured yet" at all; this needs to become `Option<u16>` (or the `begin()`/`pin()` split needs restructuring so PIN can be set or left unset independently of construction, mirroring pyatv's `pin(pin: int)` being a separate post-construction call, `pairing.py:94-97`) before `verify_pairing_code` can be implemented correctly.

### 2.4 GUID generation, storage, and the credential round-trip

`_generate_random_guid()` (`pairing.py:28-29`): `hex(random.getrandbits(64)).upper()` — generates a uniform random 64-bit integer, converts to a lowercase-`0x`-prefixed hex string via Python's `hex()`, then uppercases the whole thing (yielding `0X` for the prefix, which is why the constructor's `[2:]` slice — applied to the *original*, not the upper-cased, string in the actual expression order noted in §2.2 — still correctly strips exactly 2 characters). On successful pairing, `finish()` (`pairing.py:87-92`) persists `service.credentials = "0x" + self._pairing_guid` (re-adding a **lowercase** literal `"0x"` prefix in front of the already-uppercase hex digits — so the final stored credential string is mixed-case by construction, e.g. `"0x0000000000000001"`, matching what `test_succesful_pairing` asserts: `assert service.credentials == PAIRING_GUID` where `PAIRING_GUID = "0x0000000000000001"`) and additionally writes the same string into `core.settings.protocols.dmap.credentials` for persistence across sessions. This stored form is exactly what `DaapRequester._mkurl`'s regex (§1.4) expects to match the `pairing-guid=0x[0-9A-Fa-f]{16}` pattern on subsequent logins — **the round-trip only works if the GUID happens to render as 16 hex digits**, which is the divergence flagged in §6.

### 2.5 The mDNS responder gap — what a Rust port actually needs to build

`mdns.publish()` in pyatv delegates entirely to the third-party `zeroconf` library's `Zeroconf.register_service()`/`unregister_service()` (`docs/research/discovery-port-spec.md:283-285`, already documented, not re-derived here) — pyatv itself has **no hand-rolled mDNS responder code**; it outsources RFC 6762/6763 responder duties (answering PTR/SRV/TXT/A queries for the service it just registered, including the standard mDNS probing/announcing dance on startup) to `zeroconf`.

**This has no equivalent in the Rust workspace yet.** `crates/pyatv-mdns` (verified in this pass, `crates/pyatv-mdns/src/lib.rs:1-20` plus a full file listing) has `browse`, `dns` (a hand-rolled sans-io DNS/DNS-SD codec, ported from `pyatv/support/dns.py` per `docs/research/discovery-port-spec.md` §1), `knock`, `mdns` (multicast/unicast *query* sending and *response* receiving), `scan`, and `service` modules — **there is no `publish`/`responder`/`advertise` module anywhere in the crate**, and `Cargo.toml` depends only on `if-addrs`, `pyatv-core`, `socket2`, `thiserror`, `tokio`, `unicode-normalization` — no mDNS-publishing crate at all. (The crate's own module doc, `lib.rs:5`, states "Backed by `mdns-sd`," which is **stale relative to the actual dependency list** — the crate that shipped is the hand-rolled-codec design `docs/research/discovery-port-spec.md`'s intro recommends as path 1, not the `mdns-sd`-backed path `docs/research/rust-crates.md` §2 originally proposed; flag this doc/code mismatch to whoever next touches `pyatv-mdns/src/lib.rs`'s module doc, it is out of scope to fix here.)

Building DMAP pairing therefore requires a **new, minimal mDNS responder** as a prerequisite, not a reuse of existing browse/scan machinery. Scoped narrowly to what `_touch-remote._tcp.local` publishing actually needs (this is *not* a general-purpose Zeroconf responder — pyatv's own usage is this narrow too, one service, a handful of TXT keys, no service updates after initial publish):

- **Records to answer, per RFC 6763 conventions** (pyatv/zeroconf's actual on-wire behavior was not captured live in this pass — this is derived from standard DNS-SD responder semantics, flagged as **not independently verified against a packet capture**, consistent with this project's stated "validate against reality" principle):
  - `PTR` for `_touch-remote._tcp.local` → `<instance-name>._touch-remote._tcp.local` (the `f"{int(address):040d}"` instance name from §2.1).
  - `SRV` for `<instance>._touch-remote._tcp.local` → `priority=0, weight=0, port=<ephemeral port>, target=<hostname>.local`.
  - `TXT` for `<instance>._touch-remote._tcp.local` → the six-key map from §2.1, encoded per the length-prefixed-character-string rules already fully specified in `docs/research/discovery-port-spec.md` §1.8 (decode side) / the note at line 134 that `format_txt_dict`'s encode side is "length-prefixed `key=value` character-strings, same rules as decode in reverse").
  - `A` for `<hostname>.local` → the IPv4 address being advertised (one per address in `self._addresses`, per §2.1).
- **Query-driven vs. announce-driven**: RFC 6762 responders both answer incoming queries for records they own *and* proactively multicast unsolicited announcements after startup (typically 2, one second apart) so already-listening clients pick up the new service without having to query. pyatv/zeroconf almost certainly does both (this is standard `zeroconf`-library behavior), but since the real Apple TV/iTunes side of this handshake is itself the one actively browsing (`_touch-remote._tcp` is a service iTunes/Apple TV's "add remote" UI browses for when the user opens the pairing screen), the **query-answering half is the one that must work correctly for interop; the announce half is a nice-to-have latency optimization**, not correctness-critical, and can reasonably be deferred or simplified in a first Rust implementation.
- **No general SRV/TXT record *updates* are needed** — pyatv publishes once at `begin()` and unpublishes at `close()` (`pairing.py:60-64`, `self._zeroconf.close()`); there is no "PIN changed, republish TXT" flow (`pin()` just updates in-memory state consulted at request-handling time, `pairing.py:94-97`, it does not touch the already-published `Pair` TXT value, which was fixed at `begin()` time from the constructor-time `pairing_guid`, not from anything `pin()` sets).
- **This responder is reusable beyond DMAP** — `docs/research/rust-crates.md:159` already flags "`mdns-sd`'s publish/registration path... hasn't been evaluated" as an open question for a *future* publish milestone (needed for e.g. a hypothetical Companion-link advertisement); building a minimal from-scratch responder for DMAP pairing now is a reasonable place to establish that capability for the whole workspace, but should be designed as a small, protocol-agnostic primitive in `pyatv-mdns` (e.g. `pyatv_mdns::respond::Responder`) rather than something private to `pyatv-proto-dmap`, given the dependency direction rule in `CLAUDE.md` ("protocol crates depend on `pyatv-core`") and the existing precedent of `pyatv-mdns` owning all DNS wire-format code.

### 2.6 Reusable primitives already in the workspace

Two of `pairing.py`'s supporting calls already have Rust equivalents elsewhere in the workspace, worth reusing rather than re-deriving:

- `get_private_addresses(include_loopback=False)` (`pyatv/support/net.py:66-77`, used at `pairing.py:23` as the default `self._addresses` when the caller doesn't pass an explicit list) is already ported as `pyatv_mdns::mdns::socket::private_ipv4_addresses()` (`crates/pyatv-mdns/src/mdns/socket.rs:97-127`, citing the same pyatv source range in its own doc comment). It currently returns *all* private IPv4 addresses with no loopback-exclusion parameter — confirm whether pyatv's `include_loopback=False` default needs an equivalent filter added, or whether `DmapPairing::begin` should just filter loopback addresses out itself before publishing (the latter is simpler and keeps `private_ipv4_addresses()`'s existing signature/tests untouched).
- `unused_port()` (`pyatv/support/net.py`, not read in full in this pass since its body is a one-liner OS-assigned-ephemeral-port bind-then-read-back) has no direct Rust port yet, but needs none as a separate function — `tokio::net::TcpListener::bind(("0.0.0.0", 0)).await?.local_addr()?.port()` is the direct equivalent and is simple enough to inline at the `DmapPairing::begin` call site rather than factoring out a shared helper, unless a second caller emerges elsewhere in the workspace.

---

## 3. `pyatv/protocols/dmap/__init__.py` — `setup()` and the five interfaces

Source: `pyatv/protocols/dmap/__init__.py`, full 717-line file (already read in entirety for this pass; §3.1-§3.6 below cover every class and function in it except the scan handlers, `device_info`, and `service_info`, which are documented in `docs/research/discovery-port-spec.md` §7.6 and already ported at `crates/pyatv-mdns/src/scan/handlers/dmap.rs`, verified matching in this pass).

### 3.1 `BaseDmapAppleTV` — the shared low-level client

`__init__.py:193-243`, full class. Wraps a `DaapRequester` and holds mutable session state (`playstatus_revision`, `latest_playstatus`, `latest_playing`, `latest_hash`) that every interface below reads. Five methods:

- `playstatus(use_revision=False, timeout=None)` (`:204-218`): builds `_PSU_CMD.format(self.playstatus_revision if use_revision else 0)`, does `daap.get(cmd_url, timeout=timeout)`, updates `self.playstatus_revision = parser.first(resp, "cmst", "cmsr")` from the response, stores `latest_playstatus`/`latest_playing` (built via `build_playing_instance`, §3.2 below)/`latest_hash` (`Playing.hash`, a content hash pyatv's `interface.Playing` computes itself — not DMAP-specific, out of scope here), returns the `Playing`.
- `artwork(width, height)` (`:220-226`): `_ARTWORK_CMD.format(width=width or 0, height=height or 0)`, `daap.get(url, daap_data=False)` (raw bytes, not DMAP-parsed — artwork responses are PNG), returns `None` if the body is exactly `b""` rather than an empty-but-non-`None` value.
- `ctrl_int_cmd(cmd)` / `controlprompt_cmd(cmd)` / `controlprompt_data(data)` / `set_property(prop, value)` (`:228-243`): thin URL-template wrappers over `daap.post(...)`, already given in full in §1.4.

### 3.2 `DmapRemoteControl` — button mapping and the D-pad drag-gesture trick

`__init__.py:247-392`, full class. Direct 1:1 button-to-command mappings:

| Method | Wire call |
|---|---|
| `play()` | `ctrl_int_cmd("play")` |
| `play_pause()` | `ctrl_int_cmd("playpause")` |
| `pause()` | `ctrl_int_cmd("pause")` |
| `stop()` | `ctrl_int_cmd("stop")` |
| `next()` | `ctrl_int_cmd("nextitem")` |
| `previous()` | `ctrl_int_cmd("previtem")` |
| `select()` | `controlprompt_cmd("select")` |
| `menu()` | `controlprompt_cmd("menu")` |
| `top_menu()` | `controlprompt_cmd("topmenu")` |
| `volume_up()` | `ctrl_int_cmd("volumeup")` |
| `volume_down()` | `ctrl_int_cmd("volumedown")` |

`controlprompt_cmd(cmd)` sends `tags.string_tag("cmbe", cmd) + tags.uint8_tag("cmcc", 0)` as the POST body to `ctrl-int/1/controlpromptentry?[AUTH]&prompt-id=0` — i.e. `cmbe` carries the literal command word (`"select"`/`"menu"`/`"topmenu"`) and `cmcc` is always the single byte `0x00` for these three. `home`/`suspend`/`wakeup` are **not overridden** by `DmapRemoteControl` at all — they inherit `interface.RemoteControl`'s base-class default, which unconditionally `raise exceptions.NotSupportedError()` (`pyatv/interface.py:292-...`, confirmed at the `up`/`down`/etc. base methods, same pattern applies to every method DMAP doesn't override) — confirmed end-to-end by `test_button_unsupported_raises` (`tests/protocols/dmap/test_dmap_functional.py:153-157`).

**`up`/`down`/`left`/`right` are not discrete key presses** — each is a scripted 7-step synthetic drag gesture over what pyatv's own code calls (via variable naming) a virtual trackpad, built by `_move(direction, time, point1, point2)` (`__init__.py:303-306`):

```python
@staticmethod
def _move(direction, time, point1, point2):
    data = f"touch{direction}&time={time}&point={point1},{point2}"
    return tags.uint8_tag("cmcc", 0x30) + tags.string_tag("cmbe", data)
```

Note the **tag order is reversed** relative to `controlprompt_cmd` — `cmcc` (now `0x30`, not `0x00`) is written *before* `cmbe` here, and `cmbe`'s payload is a composite string (`"touchDown&time=0&point=20,275"`-shaped), not a bare command word. All seven calls per direction go through `controlprompt_data(data)` (i.e. `daap.post(_CTRL_PROMPT_CMD, data=data)`, same URL as `controlprompt_cmd` but with the caller-built body instead of the two-tag `cmbe`+`cmcc` shape). Exact sequences, verbatim (`__init__.py:255-301`):

```
up():    Down time=0 point=20,275 → Move time=1 point=20,270 → Move time=2 point=20,265
       → Move time=3 point=20,260 → Move time=4 point=20,255 → Move time=5 point=20,250
       → Up   time=6 point=20,250

down():  Down time=0 point=20,250 → Move time=1 point=20,255 → Move time=2 point=20,260
       → Move time=3 point=20,265 → Move time=4 point=20,270 → Move time=5 point=20,275
       → Up   time=6 point=20,275

left():  Down time=0 point=75,100 → Move time=1 point=70,100 → Move time=3 point=65,100
       → Move time=4 point=60,100 → Move time=5 point=55,100 → Move time=6 point=50,100
       → Up   time=7 point=50,100

right(): Down time=0 point=50,100 → Move time=1 point=55,100 → Move time=3 point=60,100
       → Move time=4 point=65,100 → Move time=5 point=70,100 → Move time=6 point=75,100
       → Up   time=7 point=75,100
```

(Note `left`/`right` skip `time=2` — the source literally calls `self._move("Move", 3, ...)` right after `self._move("Down", 0, ...)` and `self._move("Move", 1, ...)`, i.e. `time` values `0,1,3,4,5,6,7` for those two directions, `0,1,2,3,4,5,6` for `up`/`down` — this is not a transcription error, it is what `__init__.py:279-301` literally contains, and it is exactly what a Rust port must reproduce, not "fix.") Each direction's fake-device-observable signature is only the **final** `"Up"` event's `time`/`point` values (`_convert_button` in `tests/fake_device/dmap.py:181-195` only classifies a gesture as `up`/`down`/`left`/`right` once `buttons_press_count == 6` — i.e. after the 7th POST since counting starts at the first — by pattern-matching the exact final `cmbe` string: `"touchUp&time=6&point=20,250"` = up, `"touchUp&time=6&point=20,275"` = down, `"touchUp&time=7&point=50,100"` = left, `"touchUp&time=7&point=75,100"` = right), but a real device may well be state-tracking the whole gesture, so the Rust port should send **all seven** POSTs per press, in order, exactly as above, not just the last one.

`skip_forward`/`skip_backward` (`__init__.py:356-378`) are not real DMAP commands — DMAP has no seek-relative primitive, so pyatv fetches current `playstatus().position`, computes a new absolute position (`+`/`- time_interval` if given and `>0`, else a hardcoded `_DEFAULT_SKIP_TIME = 10` seconds, `__init__.py:59`), and calls `set_position()` (`dacp.playingtime` in milliseconds, `pos * 1000`). If `current_position` is falsy (`None` or `0`), the skip is silently a no-op (no request sent at all — `if current_position:` guards the whole body). `set_shuffle` maps `ShuffleState.Off → wire 0`, **any other `ShuffleState` (including `Albums`) → wire `1`** (`state = 0 if shuffle_state == ShuffleState.Off else 1`, `__init__.py:387`) — DMAP's wire protocol has no distinct "shuffle by album" signal, and correspondingly the *read* side (`build_playing_instance`'s `shuffle()`, §3.5) always reports back `ShuffleState.Songs` for any nonzero `cash` value, never `Albums` — confirmed end-to-end by `test_shuffle_state_albums`/`test_set_shuffle_albums` (`tests/protocols/dmap/test_dmap_functional.py:167-181`): setting `Albums` and reading back always yields `Songs`. `set_repeat` sends `repeat_state.value` directly (`RepeatState.Off=0, Track=1, All=2`, `pyatv/const.py:75-86`) — no remapping needed, the enum's numeric value already matches `dacp.repeatstate`'s wire encoding 1:1.

### 3.3 `build_playing_instance` — DMAP field → `Playing` mapping

`__init__.py:105-190`, full function; already summarized at a field-name level in `docs/research/airplay-raop-dmap.md` (implicitly, via the tag table) but not spelled out as logic before. All reads go through `parser.first(playstatus, "cmst", <tag>)` (i.e. everything lives inside the outer `cmst` container — `dmcp.playstatus`):

- **`media_type()`**: if `caps` (device state) is falsy → `MediaType.Unknown` unconditionally, *before* even looking at `cmmk`. Else, if `cmmk` (media kind) is present, delegate to `daap.media_kind(cmmk)` (§3.4). Else (no `cmmk` field at all — legacy/partial responses), fall back to a heuristic: `MediaType.Music` if either `artist()` or `album()` is truthy, else `MediaType.Video`. This three-tier fallback (state-gate → explicit kind → artist/album heuristic → video default) must be reproduced in that exact order; swapping the order changes behavior for the "no `cmmk`, no artist/album, but something is loaded" case (video vs. unknown).
- **`device_state()`**: `daap.playstate(parser.first(playstatus, "cmst", "caps"))` — see §3.4 for the exact `caps` int → `DeviceState` table, including that `caps` absent (`None`) maps to `Idle`, not an error.
- **`title`/`artist`/`album`/`genre`**: direct string reads of `cann`/`cana`/`canl`/`cang`, `None` if absent (never raises).
- **`total_time()`**: `ms_to_s(parser.first(playstatus, "cmst", "cast"))`.
- **`position()`**: computed, **not** a direct read — `total = total_time(); remaining = ms_to_s(cant); if not total or not remaining: return None; return total - remaining`. Note this returns `None` (not `0`) whenever either `cast` or `cant` is missing/zero, and that DMAP reports `cant` as *remaining* time, not elapsed time — position is derived by subtraction, and a `cant` of exactly `0` (which is falsy in Python) is treated identically to "field absent," collapsing "no time remaining" and "field not sent" into the same `None`-position outcome. This is a real ambiguity in pyatv's own logic (a track at its very end and a response with no timing data at all are indistinguishable to this code) — reproduce it as-is rather than trying to "fix" it, since the fake-device tests are built against this exact behavior.
- **`shuffle()`**: `None`/`0` → `ShuffleState.Off`; anything else → `ShuffleState.Songs` unconditionally (see §3.2 — DMAP has no wire representation of "Albums" on read).
- **`repeat()`**: `None` → `RepeatState.Off`; otherwise `RepeatState(state)` — a direct `IntEnum`-style construction from the raw wire int, meaning a `carp` value outside `{0,1,2}` would raise a `ValueError` inside pyatv itself (not caught here) — a Rust port's equivalent `TryFrom<u8>` or similar should decide explicitly whether to propagate an error or clamp/default for out-of-range values, since pyatv's own behavior here is "let it crash," not graceful degradation.

### 3.4 `daap.media_kind` / `daap.playstate` / `daap.ms_to_s` — the exact lookup tables

Source: `pyatv/protocols/dmap/daap.py:31-72`, already given verbatim in full in §... (re-derive here since it's the single piece of DMAP business logic most amenable to direct known-answer porting, and the prior report didn't include it at all):

```python
def media_kind(kind):
    if kind in [1, 32770]: return MediaType.Unknown
    if kind in [3, 7, 11, 12, 13, 18, 32]: return MediaType.Video
    if kind in [2, 4, 10, 14, 17, 21, 36]: return MediaType.Music
    if kind in [8, 64]: return MediaType.TV
    raise exceptions.UnknownMediaKindError(f"Unknown media kind: {kind}")

def playstate(state):
    if state == 0 or state is None: return DeviceState.Idle
    if state == 1: return DeviceState.Loading
    if state == 2: return DeviceState.Stopped
    if state == 3: return DeviceState.Paused
    if state == 4: return DeviceState.Playing
    if state in (5, 6): return DeviceState.Seeking
    raise exceptions.UnknownPlayStateError(f"Unknown playstate: {state}")

def ms_to_s(time):
    if time is None: return 0
    if time >= (2**32 - 1): return 0    # sentinel "buffering"/invalid value
    return round(time / 1000.0)
```

The `2**32 - 1` sentinel in `ms_to_s` is a real-device quirk pyatv special-cases explicitly (comment: `"Happens in some special cases, just return 0"`) — a `cast`/`cant` value of exactly `4294967295` ms means "treat as zero," not "the track is 4.9 million years long." `round()` here is Python's banker's-rounding `round()`, not truncation — a Rust port using integer division (`time / 1000`) will disagree with pyatv on exact `.5`-millisecond-remainder boundaries (e.g. `time=1500` → Python `round(1.5) == 2` under banker's rounding since 2 is even, vs. naive truncating division giving `1`); this is a genuine, if narrow, precision-parity risk worth a `#[test]` pinning pyatv's actual behavior (verified live: `round(500/1000.0)=0`, `round(1500/1000.0)=2`, `round(2500/1000.0)=2` — Python 3's `round()` uses round-half-to-even, confirm against `tests/protocols/dmap/test_daap.py:118-131`'s existing cases, none of which happen to land on a `.5` boundary, so this specific edge is **not** covered by pyatv's own test suite and needs an independently-derived Rust test).

`MEDIA_KIND_*`/`PLAY_STATE_*` numeric constants are documented in `tests/protocols/dmap/test_daap.py:14-48` with citation comments back to `ITLibMediaItem.h`/a third-party DACP response reference — all 22 media-kind values and 7 play-state values are exercised as exact known-answer pairs in that file (`test_daap.py:54-131`), safe to port as a single parametrized Rust test table.

### 3.5 `DmapMetadata`, `DmapPushUpdater`, `DmapFeatures`, `DmapAudio`

- **`DmapMetadata`** (`__init__.py:395-446`): `artwork(width=512, height=None)` fetches `playing()` first purely to get `playing.hash` as a cache key (comment: "not ideal... but an identifier is needed"), checks a small LRU-ish `Cache(limit=4)` (`pyatv/support/cache.py`, generic, not DMAP-specific — port as a small bounded map if not already present elsewhere in the workspace, or reuse an existing one), and on a cache miss calls `apple_tv.artwork(width, height)`, wrapping a non-empty result as `ArtworkInfo(bytes=..., mimetype="image/png", width=-1, height=-1)` — **DMAP artwork responses never carry real dimensions**, `-1`/`-1` is a hardcoded sentinel, not a parsed value (comment: "In the future, extracting dimensions from PNG header should be feasible" — pyatv has not done this as of this commit). `artwork_id` returns `apple_tv.latest_hash` directly (not `playing.hash` freshly computed — a subtle distinction between "the hash from whenever `artwork()` was last awaited" vs. "the hash right now"). `device_id` is just the identifier passed in at construction (`core.config.identifier`).
- **`DmapPushUpdater`** (`__init__.py:448-524`): `start(initial_delay=0)` resets `apple_tv.playstatus_revision = 0` **unconditionally on every start**, even a restart (comment: "Always start with 0 to trigger an immediate response for the first request"), then spawns `_poller()`. `_poller` is an infinite loop: `playstatus(use_revision=True, timeout=0)` (`timeout=0` meaning "no client-side timeout, block indefinitely" — this is the long-poll block described in `docs/research/airplay-raop-dmap.md:491-493`), post the result to the listener, loop immediately (no delay between successful iterations — the *device's* long-poll hold is the only pacing). Three termination/error paths: `asyncio.CancelledError` → clean `break` (from `stop()`); `aiohttp.ClientError` (network/connection failure) → notify `listener.listener.connection_lost(ex)` via `loop.call_soon`, then `break` (poller does **not** restart itself on a connection error — the caller must call `start()` again); any other `Exception` → **does not break**, instead resets `playstatus_revision = 0` (forcing the next iteration's request to use `revision-number=0`, i.e. "ask for current state immediately" rather than continuing to long-poll from a possibly-stale revision) and calls `listener.playstatus_error(self, ex)`, then the `while True` loop continues — this is a self-healing retry-forever behavior for anything that isn't a hard connection loss, confirmed by `test_reset_revision_if_push_updates_fail` (`tests/protocols/dmap/test_dmap_functional.py:284-317`), whose own listener callback deliberately reconfigures fake-device state *inside* the `playstatus_error` callback to prove the very next poll iteration picks up the change. `_initial_delay` (only used on iterations after the first, via `if not first_call and self._initial_delay > 0: await asyncio.sleep(...)`) is a caller-provided backoff hint passed through `start(initial_delay=...)`, not consulted anywhere else in this file — its only current caller in the umbrella `pyatv` package (not read in this pass) would need checking before assuming its default of `0` is universal, but within `pyatv/protocols/dmap` itself it is always `0` unless the umbrella layer overrides it.
- **`DmapFeatures`** (`__init__.py:527-558`): three static feature-availability sets, given verbatim (already transcribed at `__init__.py:66-102`, reproduced here as the porting-relevant grouping):
  - **`_AVAILABLE_FEATURES`** (always `FeatureState.Available`, no device query): `Down, Left, Menu, Right, Select, TopMenu, Up`.
  - **`_UNKNOWN_FEATURES`** (always `FeatureState.Unknown` — "supported by the device but we don't know if available," pyatv's own comment): `Artwork, Next, Pause, Play, PlayPause, Previous, SetPosition, SetRepeat, SetShuffle, Stop, SkipForward, SkipBackward`.
  - **`_FIELD_FEATURES`** (availability derived from whether a specific `cmst`-nested field was present in the *most recent* `playstatus` response — `FeatureState.Unavailable` if no `playstatus` has ever been fetched yet, i.e. `self.apple_tv.latest_playstatus` is falsy): `Title→cann, Artist→cann` — **note**: re-reading `__init__.py:93-102` precisely, the actual mapping is `Title:("cmst","caps")` (not `cann`!), `Artist:("cmst","cann")`, `Album:("cmst","canl")`, `Genre:("cmst","cang")`, `TotalTime:("cmst","cast")`, `Position:("cmst","cant")`, `Shuffle:("cmst","cash")`, `Repeat:("cmst","carp")` — **`FeatureName.Title`'s availability is gated on the `caps` (play-state) field being present, not on a title-bearing field** — this looks like it could be a copy-paste artifact in pyatv itself (every other row's field matches its own semantic name; `Title` uniquely doesn't), but it is exactly what `_FIELD_FEATURES = {FeatureName.Title: ("cmst", "caps"), ...}` at `__init__.py:94` says, verified by re-reading the source directly in this pass — **reproduce it exactly as written, do not "fix" it to `cann`**, since doing so would silently diverge from pyatv's actual runtime behavior (a response with a `caps` field but no `cann` field would report `Title` as `Available` under real pyatv even though no title text exists — this is pyatv's bug to keep or fix upstream, not this port's call to make unilaterally).
  - `VolumeUp`/`VolumeDown` (handled separately, not via `_FIELD_FEATURES`): `FeatureState` from `_is_available(("cmst", "cavc"), expected_value=True)` — available only if the *most recent* playstatus response's `cavc` (`dacp.volumecontrollable`) field is present **and** equals `True` specifically (not just "present"), confirmed by the `expected_value` parameter's semantics in `_is_available` (`__init__.py:552-558`: `if not expected_value or expected_value == value: return Available` — i.e. `expected_value` acts as an optional equality filter, not just a presence check).
- **`DmapAudio`** (`__init__.py:561-574`): trivial two-method wrapper, `volume_up()`/`volume_down()` both just re-issue the same `ctrl_int_cmd("volumeup"/"volumedown")` that `DmapRemoteControl.volume_up`/`volume_down` already call — **the two interfaces send byte-identical requests for what looks like the same user action**, this is not a bug to fix, just a duplication pyatv itself has (both `RemoteControl.volume_up()` and `Audio.volume_up()` exist as separate public API surfaces that happen to do the same thing on DMAP; other protocols may differentiate them more meaningfully, out of scope here).

### 3.6 `setup()` — wiring, and the `FeatureName` set actually claimed

`__init__.py:660-717`, full function. Constructs one `HttpSession` (`pyatv/support/http.py:251-323`, backed by `aiohttp.ClientSession` — see §6 for what this means for the Rust HTTP client decision) pointed at `f"http://{core.config.address}:{core.service.port}/"`, one `DaapRequester(daap_http, core.service.credentials)` (note: the credential string is threaded straight from `BaseService.credentials` into the requester's `_login_id` at construction time — whatever format it's in, `_mkurl`'s regexes decide `pairing-guid` vs `hsgid` at *login* time, not construction time), one `BaseDmapAppleTV`, and the five interface objects from §3.1-§3.5.

`_connect()` (`:684-689`): `await requester.login()` then **immediately** `await apple_tv.playstatus()` before returning `True` — i.e. DMAP eagerly fetches full playback state as part of connecting (comment: "Retrieve initial state to have volume control state" — this primes `latest_playstatus` so `DmapFeatures`'s `VolumeUp`/`VolumeDown`/`_FIELD_FEATURES` checks aren't all `Unavailable` immediately after connect). A connection failure surfaces however `login()`/`playstatus()` already propagate errors (§1.4's `_do` state machine) — no additional wrapping here.

`_close()` (`:691-694`): stops the push updater, calls `core.device_listener.listener.connection_closed()`, returns an empty `set()` of pending tasks (the `SetupData.close` contract apparently allows returning tasks still needing to be awaited by the caller — DMAP has none).

`_device_info()` (`:696-704`): merges `device_info(service_type, properties)` (§ already covered, ported) across every `service_type in scan()` present in `core.config.properties` — this is protocol-internal, re-deriving what the scan-time merge already did, used for **live** device-info refresh after connect (as opposed to scan-time device-info, which is a separate code path in `core/scan.py` per `docs/research/discovery-port-spec.md` §3.2) — since `scan()` returns the same three DMAP service-type keys either way, this is a mechanical re-application, not new logic.

**`FeatureName` set claimed by the DMAP `SetupData`** (`:706-712`): the union of `{VolumeDown, VolumeUp}` ∪ `_AVAILABLE_FEATURES` ∪ `_UNKNOWN_FEATURES` ∪ `_FIELD_FEATURES.keys()` — i.e. every feature name DMAP has *any* opinion about (even if that opinion is just "`Unknown`") is claimed, so that `Relayer<Features>`'s priority-ordered fallback (per `docs/research/pyatv-architecture.md`, not re-derived here) knows DMAP is a candidate for these specific features at all. Everything **not** in this union — `Home, HomeHold, Suspend, WakeUp, PowerState, TurnOn, TurnOff, App`, per `test_unsupported_features` (`tests/protocols/dmap/test_dmap_functional.py:209-220`) — falls through to `FeatureState.Unsupported` by the base `Features.get_feature`'s default (not a DMAP-specific check; DMAP's `get_feature` returns `FeatureState.Unsupported` for exactly this reason at its own final `return` in `__init__.py:550`, matching `_is_available`'s and the three-tier `if` chain's fall-through).

`pair(core, **kwargs)` (`:715-717`): trivial, `return DmapPairingHandler(core, **kwargs)` — the `**kwargs` pass-through is how the `pairing_guid`/`name`/`addresses`/`zeroconf` test-injection points from §2 reach the handler; a Rust port's equivalent constructor should keep the same knobs configurable (at minimum `pairing_guid: Option<String>` for deterministic tests, and `addresses: Option<Vec<Ipv4Addr>>` for the same reason — `zeroconf` itself is Python-specific plumbing with no direct Rust equivalent, replaced by whatever responder API §2.5 lands on).

---

## 4. Test fixtures worth porting

### 4.1 `tests/fake_device/dmap.py` (448 lines) — the fake DMAP Apple TV

Full file read in this pass. Structure: `FakeDmapState` (mutable session/pairing/playback state, `DEVICE_IDENTIFIER = "75FBEEC773CFC563"`, `DEVICE_AUTH_KEY = "8F06696F2542D70DF59286C761695C485F815BE3D152849E1361282D46AB1493"`, `DEVICE_PIN = 2271` — a second, independently-usable known-device fixture beyond the pairing-test constants in §2.3, though this file's `DEVICE_CREDENTIALS = DEVICE_IDENTIFIER + ":" + DEVICE_AUTH_KEY` colon-joined form doesn't appear to be DMAP's own credential shape — cross-check against whichever protocol actually consumes it before assuming it's DMAP-relevant, it reads more like the general fake-device harness's shared identity constants than a DMAP-specific pairing-guid/hsgid pair); `FakeDmapService` (the actual `aiohttp` route handlers — `/login`, `/ctrl-int/1/playstatusupdate`, `/ctrl-int/1/controlpromptentry`, `/ctrl-int/1/nowplayingartwork`, `/ctrl-int/1/setproperty`, and one route per playback button); `FakeDmapUseCases` (test-authoring DSL: `change_volume_control`, `force_relogin`, `make_login_fail`, `change_artwork`, `artwork_no_permission`, `nothing_playing`, `server_closes_connection`, `example_video`/`video_playing`, `example_music`/`music_playing`, `media_is_loading`, `pairing_response`, `act_on_bonjour_services`).

Two request-level invariants worth porting as their own tests independent of any specific command:

- **`_verify_headers`** (`dmap.py:302-305`): every request handler calls this, asserting all seven `EXPECTED_HEADERS` keys are present with exact values — this is effectively free coverage of §1.4's header table on every single functional test, so a Rust integration-test harness built against a fake server should apply the equivalent check universally rather than per-test.
- **`_verify_auth_parameters`** (`dmap.py:310-329`): `check_login_id=True` (only on `/login`) asserts exactly one of `hsgid`/`pairing-guid` query params is present and matches the fixture's configured value, raising an assertion otherwise; `check_session=True` (the default, applied to every non-login route) asserts `session-id` matches the fixture's current session — this is the fake-server-side enforcement that makes `test_relogin_if_session_expired` meaningful (a stale `session-id` on a request after `force_relogin` would fail this check, which is why the *client* must actually pick up the new session id from `login()`'s response, not just resend the old one).

`handle_playstatus` (`dmap.py:211-278`) is the single most detail-dense handler — it conditionally emits up to ten different `cmst`-nested tags depending on which `PlayingResponse` fields are set (`caps` from either `playback_rate` — a three/four-way `math.isclose` dispatch to playstate ints `3/4/5/6` — or `paused` — boolean to `3`/`4` — or a raw `playstatus` int, checked in that priority order; `cann`/`cana`/`canl`/`cang` direct; `cast`+optionally `cant` computed as `(total_time - position) * 1000`; `cmmk`; `carp`/`cash` as `uint8`, not `uint32`; `cavc` from `state.volume_controls` **only if not `None`** even though the field type suggests boolean, note `self.state.volume_controls is not None` as the guard, meaning a falsy-but-set `False` still emits the tag); always finishes with `cmsr = playing.revision + 1` — i.e. **the server-reported revision is always exactly the client-visible `PlayingResponse.revision` plus one**, a fixed off-by-one relationship a Rust fake-server port must replicate for any push-update test to have the right revision-advancement semantics. `force_close` (checked first, before revision validation) closes the raw transport mid-request to simulate a hard connection drop — this is what drives `test_connection_lost`.

### 4.2 `tests/protocols/dmap/test_parser.py` (121 lines) — direct codec known-answers

Full parametrized coverage of `parse`/`first`/`pprint` against a local 13-entry test tag table (not the real `tag_definitions`) — every wire-type (`uint8/16/32/64` via the four `*_tag` writers, `bool`, `string` including an empty string, `bplist` round-trip via `plistlib`, `bytes` — the `"0x01aaff45"` known-answer already cited in §1.2 —, nested containers two levels deep, an `ignore`-typed tag confirmed to parse to `None`, and `pprint`'s exact indented-string output format) is exercised as a directly portable Rust test suite; `test_print_invalid_input_raises_exception` (`:119-121`) confirms `pprint` on non-`dict`/`list` input raises `InvalidDmapDataError` — only relevant if `pprint`'s debug-formatting gets ported at all (§1.3 flags it optional).

### 4.3 `tests/protocols/dmap/test_daap.py` (131 lines) — `media_kind`/`playstate`/`ms_to_s` known-answers

All 22 `media_kind` known-answer pairs and 7 `playstate` pairs (§3.4's tables), plus the three `ms_to_s` edge cases (`None→0`, `400→0` and `501→1` as sub-second rounding examples, `2**32-1→0` as the sentinel case) — copy `test_daap.py:54-131` directly into a Rust parametrized test module; these are exact input/output pairs with citations back to third-party DACP documentation pyatv itself cites (`test_daap.py:9-12`).

### 4.4 `tests/protocols/dmap/test_dmap_pairing.py` (193 lines) — the pairing state machine, full flow

Already the primary source for §2.3's known-answer vectors; additionally worth porting as integration-test scenarios: `test_zeroconf_service_published`/`test_zeroconf_custom_addresses` (§2.1's multi-address publish behavior), `test_succesful_pairing`/`test_pair_custom_pairing_guid` (full request→verify→response→credential-persisted round trip, including the assertion that `storage.settings[0].protocols.dmap.credentials` — not just the in-memory `service.credentials` — gets the new value, i.e. persistence-layer parity matters, not just in-process state), `test_successful_pairing_random_pairing_guid_generated` (the `mock_random` fixture monkey-patches `pairing.random.getrandbits` directly — a Rust port's equivalent test needs dependency-injectable randomness, e.g. an `Rng` parameter threaded through `DmapPairing::new` rather than a global RNG call, to make this test reproducible), `test_succesful_pairing_with_any_pin`/`test_succesful_pairing_with_pin_leadering_zeros` (§2.3's "PIN unset" and "PIN needs zero-padding" cases), `test_failed_pairing` (wrong code → HTTP 500, no body — assert absence of a `cmpa` container, not just the status).

### 4.5 `tests/protocols/dmap/test_dmap.py` (107 lines) and `test_dmap_scan.py`/functional scan tests

`test_dmap.py` is unit-level coverage of the (already-ported) scan handlers, `device_info`, and `service_info` — `test_service_info_pairing`'s three-way parametrization (`dmap_props={}`→`Mandatory`, `dmap_props={"hg":"test"}`→`Optional`, `mrp_props={"hg":"test"}` with empty `dmap_props`→`Mandatory` — i.e. a **sibling** MRP service having an `hg`-shaped property does **not** leak into DMAP's own pairing-requirement decision, only DMAP's *own* service properties matter here despite `service_info`'s signature taking the full `services: Mapping[Protocol, BaseService]` map) is worth double-checking against the already-ported `crates/pyatv-mdns/src/scan/handlers/dmap.rs:146-152`'s `service_info` implementation, which correctly reads only `service.property("hG")` (the service being finished, not the sibling map) — **this already matches**, no action needed, cited here only to close the loop on cross-checking the already-ported half against the fuller test file this pass read for the first time.

`test_dmap_scan.py` (already covered structurally by `docs/research/discovery-port-spec.md` §8.6) additionally documents the exact `homesharing_service_handler`/`dmap_service_handler` unit-level input/output shape (`mdns.Service(type, name, address, port, properties) → (name, MutableService)`), useful as direct Rust unit tests on the handler functions in isolation, separate from the full-scan integration tests already cited in the discovery spec.

---

## 5. Suggested module layout for the remaining scaffold work

Not prescriptive — a starting point consistent with the workspace's "keep source files well under 500 LoC, split by responsibility" rule (`CLAUDE.md`) and the crate's existing `pub mod error; pub mod pairing; pub mod parser; pub mod tags;` shape (`crates/pyatv-proto-dmap/src/lib.rs:11-14`). Given §1.3's finding that a typed, path-lookup-capable parse tree is needed before anything else can be written cleanly, a workable dependency order is:

1. **`parser.rs` extension** (or a new `tree.rs` alongside it): add the eager, fully-typed recursive structure discussed in §1.3, plus a `first(&self, path: &[&str]) -> Option<&Value>`-shaped helper matching `parser.first`'s multi-level semantics (`parser.py:56-65`). Fix `DmapValue::as_bool` per §1.2 in the same pass, since it's a one-line change directly motivated by this same read.
2. **`tags.rs` completion**: fill in the remaining 77 rows from §1.1's table — purely mechanical, no design decisions.
3. **`error.rs` extension**: add the five variants from the exception-mapping table in §1.4, needed by every subsequent module.
4. **`daap.rs`** (new): the HTTP transport decision from §6's divergence list, `DaapRequester`-equivalent login/get/post/`_do` state machine (§1.4), `media_kind`/`playstate`/`ms_to_s` (§3.4).
5. **`playing.rs`** (new, or folded into `daap.rs` if it stays small): `build_playing_instance`-equivalent (§3.3), consuming the typed tree from step 1.
6. **`interfaces.rs`** or a small `interfaces/` directory (`remote_control.rs`, `metadata.rs`, `push_updater.rs`, `features.rs`, `audio.rs` if any single file threatens the 500-LoC guideline — `DmapRemoteControl` alone, with the seven-step gesture tables from §3.2 written out, is a reasonable candidate to split out on its own): the five public interfaces from §3.2/§3.5, plus the `setup()`-equivalent wiring from §3.6.
7. **`pairing.rs` completion**: `begin()`/`verify_pairing_code()` per §2, blocked on the new mDNS responder primitive from §2.5 (`pyatv-mdns`, cross-crate work, do this first if it isn't already in flight for another protocol) and on the `DmapPairing` PIN-optionality restructuring flagged in §2.3.

Steps 1-3 have no cross-crate dependencies and can proceed immediately; steps 4-6 depend only on 1-3; step 7's `begin()` half is blocked on `pyatv-mdns` responder work but `verify_pairing_code()` itself is not (it's pure hashing, testable against §2.3's vectors in isolation today).

---

## 6. Divergences and open questions

1. **The pairing GUID is not guaranteed to render as 16 hex digits, but the login regex requires exactly 16.** `_generate_random_guid()` (§2.4) is `hex(random.getrandbits(64)).upper()[2:]` (order as written; net effect as analyzed in §2.2) — `hex()` never zero-pads, so any random 64-bit value whose top nibble (or more) is zero produces **fewer than 16 hex characters**. `DaapRequester._mkurl`'s credential-type regex (§1.4) is `re.match(r"0x[0-9A-Fa-f]{16}", self._login_id)` — a stored credential like `"0xF03A9CF4A983143"` (15 digits, would happen for roughly 1 in 16 random GUIDs) **fails this match**, falls through to the `hsgid` UUID-pattern check (also fails), and raises `InvalidCredentialsError` on the very next login attempt after a successful pairing — a real, reproducible bug in pyatv itself, not exercised by any test in the suite because none of the three test PIN/GUID fixtures (§2.3) happen to need leading-zero-truncation at the *GUID* level (only the *PIN*'s `zfill(4)` case is tested). **Decision for the Rust port**: reproduce pyatv's exact behavior (bug-compatible, for interop with anything that might depend on pyatv's specific persisted-credential string shape) versus always zero-pad the generated GUID to 16 hex digits (fixes the latent bug, changes the persisted credential string format, harmless for a fresh Rust-only install but not necessarily "the same bytes pyatv would have produced" if credential-format byte-parity with an existing pyatv config ever matters). Recommend zero-padding (fixing it) since nothing in the wire protocol or any external device depends on the *string width* of a client-generated random identifier — only the receiving Apple TV's own `Pair` TXT record and pairing-response `cmpg` value matter to interop, and both survive either choice — but flag this as a deliberate deviation from pyatv's literal behavior in a code comment when implemented, per this project's stated principle of validating against reality rather than blindly copying an unverified assumption.
2. **HTTP client choice is unresolved and matters more for DMAP than it first appears.** `docs/research/rust-crates.md` and `docs/research/airplay-raop-dmap.md` §12 both treat "RTSP/HTTP wire types" as a single hand-rolled-parser decision driven by AirPlay's non-conformant framing (RTSP verbs inside HTTP-shaped messages, binary-plist bodies) — and the existing `crates/pyatv-proto-airplay` codec (`crates/pyatv-proto-airplay/src/codec.rs:30`, `lib.rs:11`, `codec/parse.rs:7`) explicitly documents "Framing is `Content-Length` only. No chunked transfer encoding is used or accepted" as a deliberate simplification, because AirPlay/RAOP genuinely never sends chunked bodies in pyatv's own traffic. **DMAP is a different situation**: pyatv's DMAP client goes through `pyatv/support/http.py`'s `HttpSession`, which wraps a real `aiohttp.ClientSession` (`daap.py`'s imports, confirmed via `pyatv/support/http.py:251-323` read in this pass) — a full, spec-conformant HTTP/1.1 client that transparently handles whatever a real device sends, **including chunked `Transfer-Encoding` and gzip-compressed `Content-Encoding` responses** (the `Accept-Encoding: gzip` header in §1.4's required header set is a real request to the server that it *may* compress its response body, and `aiohttp` decompresses transparently if the server obliges — pyatv's own code never touches this decision or the decompression step itself). **This means reusing the AirPlay crate's `Content-Length`-only codec for DMAP is not safe by default** — if any real gen 1-3 Apple TV (or iTunes acting as a DAAP server, which some of DMAP's own client-facing design clearly anticipates supporting historically) ever sends a chunked or gzip-compressed response, a Content-Length-only Rust codec will misparse or return raw compressed bytes where DMAP TLV bytes are expected. No capture-based evidence either way was available in this research pass (no live device tested — consistent with this project's "validate against reality" principle, this is exactly the kind of claim that needs a capture, not an assumption). **Decision needed at implementation time, not resolved here**: either (a) confirm via a live gen 1-3 device or an iTunes DAAP server capture that chunked/gzip never actually occurs in practice for DMAP specifically (in which case the AirPlay codec's simplifying assumption can be safely extended to DMAP too, keeping the workspace's "one hand-rolled HTTP layer" design), or (b) pull in a real HTTP/1.1 client crate (e.g. `hyper` or `reqwest`, both explicitly *rejected* for AirPlay's use case in `docs/research/rust-crates.md:62` on different grounds — "does not expose raw framing" — that objection does not apply to DMAP, which is genuinely standard request/response HTTP with no raw-framing requirement) scoped to just the DMAP crate, accepting two different HTTP stacks in the workspace for two different reasons. Given DMAP only targets EOL hardware (gen 1-3, tvOS ≤ 12, no active Apple support), the actual risk-adjusted cost of guessing wrong here is low, but the decision should still be made explicitly and documented, not defaulted into by reusing whatever code happens to be nearest.
3. **The mDNS pairing responder (§2.5) is a net-new capability with no existing scaffold, prior art in this workspace, or independent wire verification** — the RFC 6762/6763 record set this spec proposes is derived from standard DNS-SD responder semantics and cross-checked against what pyatv's `zeroconf`-backed publish call declares it's registering (service type, TXT keys, addresses), but the actual on-the-wire *responder* behavior (probing, announcing, exact query-matching logic) was not captured live against a real Apple TV/iTunes client in this research pass. Treat §2.5's record enumeration as a strong starting point, not a verified spec, and prioritize the query-answering half (correctness-critical per §2.5) over the announce half (an optimization) if scope needs trimming.
4. **`build_playing_instance`'s `Title` feature-availability field mapping (§3.5, `_FIELD_FEATURES[FeatureName.Title] = ("cmst", "caps")`) reads like an upstream copy-paste bug** but was verified twice against the literal source in this pass (`pyatv/protocols/dmap/__init__.py:93-102`) and is not flagged as a known issue anywhere in pyatv's own changelog/comments that this research pass found. Reproduce as-is per this project's "port pyatv's actual behavior, don't silently fix it" default, but consider filing the observation upstream (or at minimum leaving an explicit `// NOTE: pyatv itself gates Title availability on caps, not cann — verified, not a transcription error` comment at the Rust call site) so a future contributor doesn't "helpfully" correct it out of sync with pyatv's real runtime behavior.
5. **`ms_to_s`'s Python banker's-rounding behavior (§3.4) has no test coverage at the exact `.5`-millisecond-remainder boundary** in pyatv's own suite — this is a narrow but real precision-parity risk for any Rust integer/floating rounding implementation that defaults to truncation or round-half-away-from-zero instead of round-half-to-even; needs an independently-authored Rust test since pyatv's own test suite doesn't pin this case.
6. **The scaffold's `DmapValue::as_bool` (§1.2) and `DmapPairing::new`'s non-optional `pin: u16` (§2.3) are both real, identified gaps relative to pyatv's actual semantics**, not stylistic preferences — fixing `as_bool` to `as_uint() == Some(1)` and restructuring `DmapPairing` to support an explicit "no PIN configured yet" state are both prerequisites for correctness, not polish, and should be treated as part of Step 7's critical path rather than optional follow-ups.
7. **This report did not independently verify any DMAP wire behavior against a real Apple TV 1/2/3 or an iTunes DAAP server** — every claim traces to pyatv source code and its own test suite (which is itself validated against `tests/fake_device/dmap.py`, a fake server pyatv's own maintainers wrote, not a real device capture). Given gen 1-3 Apple TVs and DMAP-era iTunes are now over a decade past any Apple support, live-hardware verification opportunities are shrinking; if a real device or iTunes instance is available during implementation, prioritize capturing at least one full login→playstatus→command→pairing sequence against it before considering Step 7 done, consistent with `CLAUDE.md`'s "validate against reality, not against pyatv's assumptions" directive and this project's established pattern (per `docs/research/airplay-tunnel-auth-experiment-2026-08-24.md`) of live-verifying protocol assumptions rather than trusting pyatv's `master` unconditionally.
