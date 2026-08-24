# Companion protocol: byte-level port specification

Ground truth: `/tmp/pyatv-ref`, pinned at commit `b277a4c8` (tag `v0.18.0` release commit — verified via `git log -1` in that checkout on 2026-08-24). Every claim below is grounded by re-reading the actual file at that commit; line numbers are cited as `path:line` or `path:line-line` and were captured directly from `cat -n` output during this research pass — re-verify against a fresh checkout if the upstream file has moved since. Do not implement any part of this crate from memory of pyatv's Python source; the wire-format details here (frame header, OPACK tag table, TLV pairing keys, exact numeric constants) are all copied verbatim from source, not recalled.

This document assumes the reader has already read:
- `/mnt/empty/canvas/docs/research/mrp-companion.md` §4 (Companion frame format and OPACK serialization) — the OPACK tag table, general Companion pairing shape, and session bring-up sequence are documented there and are **not repeated verbatim here** except where a correction is needed (§12).
- `/mnt/empty/canvas/docs/research/hap-pairing-port-spec.md` §4 (salt/info/key-role table), §5.4 (Companion transport framing), §9.2 (Companion pairing handler) — the shared HAP/SRP/TLV8 crypto core, the exact HKDF salt/info assignments for Companion's transport keys, and the Companion-specific pairing procedure walkthrough live there. This document treats those as ground truth and adds only Companion-specific detail (message envelope semantics beyond auth, the full API/command surface, the fake-device test harness, and the plist-payload/keyed-archiver helpers) that those two documents do not cover in full.

Companion has **zero Rust prior art** and its OPACK wire format has **no public specification anywhere** — `pyatv/support/opack.py` and pyatv's own test suite (`tests/support/test_opack.py`, `tests/protocols/companion/*`) are the only ground truth in existence. Treat every byte constant in this document as load-bearing.

---

## 0. Source file inventory

| File | Lines | Role |
|---|---|---|
| `pyatv/protocols/companion/connection.py` | 168 | TCP framing, `FrameType` enum, encryption boundary |
| `pyatv/protocols/companion/protocol.py` | 234 | Message envelope (`_i`/`_t`/`_x`/`_c`/`_em`), XID dispatch, `CompanionProtocol.start()` |
| `pyatv/protocols/companion/auth.py` | 170 | `CompanionPairSetupProcedure`, `CompanionPairVerifyProcedure` — the `_pd`/`_pwTy`/`_auTy` framing over PS_*/PV_* frames |
| `pyatv/protocols/companion/pairing.py` | 78 | `CompanionPairingHandler` — `begin()`/`pin()`/`finish()`, the public pairing-handler surface |
| `pyatv/protocols/companion/api.py` | 475 | `CompanionAPI` — every command (`HidCommand`, `MediaControlCommand`, `SystemStatus`, session bring-up, touch/keyboard/app/account calls) |
| `pyatv/protocols/companion/__init__.py` | 707 | Facade classes (`CompanionApps`, `CompanionPower`, `CompanionRemoteControl`, `CompanionAudio`, `CompanionKeyboard`, `CompanionTouchGestures`, `CompanionFeatures`, `CompanionUserAccounts`), scan/`rpfl` pairing-requirement logic, `SUPPORTED_FEATURES`, `setup()`/`pair()` entry points |
| `pyatv/protocols/companion/keyed_archiver.py` | 28 | Minimal `NSKeyedArchiver` plist reader (UID-reference following only, no general unarchiver) |
| `pyatv/protocols/companion/plist_payloads/rti_text_operations.py` | 147 | Hand-encoded `NSKeyedArchiver` binary-plist byte literals for `_tiC` text-input events |
| `pyatv/protocols/companion/server_auth.py` | 229 | Reference/test server-side auth implementation (`CompanionServerAuth`), used only by the fake device |
| `tests/fake_device/companion.py` | 593 | Hermetic fake Companion device — the second ground-truth source for exact request/response shapes |
| `tests/protocols/companion/test_companion_auth.py` | 95 | Pairing functional KATs |
| `tests/protocols/companion/test_companion_functional.py` | 423 | Full command-surface functional tests against the fake device |
| `tests/protocols/companion/test_companion_interface.py` | 61 | Keyboard-focus event-dispatch unit test |
| `tests/protocols/companion/test_companion.py` | 72 | `rpfl`/`rpmd` scan-time unit tests |
| `tests/protocols/companion/test_companion_scan.py` | 68 | mDNS scan-handler tests |
| `tests/protocols/companion/conftest.py` | 57 | Shared fixtures — `companion_device`/`companion_conf`/`companion_client`, wired to `CLIENT_CREDENTIALS` |
| `tests/support/test_opack.py` | 440 | OPACK codec KATs, including one `_systemInfo`-shaped golden round-trip |
| `pyatv/auth/server_auth.py` | 13 | Shared constants: `PIN_CODE = 1111`, `CLIENT_CREDENTIALS`, `SERVER_IDENTIFIER`, `PRIVATE_KEY = 32 * b"\xaa"` |
| `pyatv/auth/hap_srp.py` | 233 | `SRPAuthHandler` — shared SRP/HKDF/TLV mechanics referenced by `auth.py` |
| `pyatv/auth/hap_pairing.py` | 146 | `HapCredentials`, `AuthenticationType`, `parse_credentials`, `PairSetupProcedure`/`PairVerifyProcedure` ABCs |
| `pyatv/support/chacha20.py` | 106 | `Chacha20Cipher`/`Chacha20Cipher8byteNonce` — the AEAD wrapper Companion uses with `nonce_length=12` |

---

## 1. `pyatv/protocols/companion/connection.py` — frame layout and connection lifecycle

### 1.1 Frame header — confirmed exact

`HEADER_LENGTH = 4`, `AUTH_TAG_LENGTH = 16` (`connection.py:16-17`). Verbatim:

```python
def send(self, frame_type: FrameType, data: bytes) -> None:
    """Send message without waiting for a response."""
    if self.transport is None:
        raise exceptions.InvalidStateError("not connected")

    payload_length = len(data)
    if self._chacha and payload_length > 0:
        payload_length += AUTH_TAG_LENGTH
    header = bytes([frame_type.value]) + payload_length.to_bytes(3, byteorder="big")
    ...
    if self._chacha and len(data) > 0:
        data = self._chacha.encrypt(data, aad=header)
        ...
    self.transport.write(header + data)
```
(`connection.py:98-119`)

So the header is **1-byte frame type + 3-byte big-endian length** — this confirms and locks down what `mrp-companion.md` §4.2 already states; no correction needed here. The length field is the *plaintext* payload length **plus 16** when encryption is active and the payload is non-empty (the Poly1305 tag budget is added to the transmitted length before it is ever used as AAD — i.e. the AAD authenticates the post-tag-adjustment header, not a pre-adjustment one). When the payload is empty (`len(data) == 0`), the length field is `0` and the AEAD call is **skipped entirely**, even if `self._chacha` is set (`connection.py:104-106,115`) — an empty-payload frame (e.g. certain `NoOp`/keepalive uses) is sent in the clear, header included, with no ciphertext appended. A Rust port's encoder must special-case `data.is_empty()` the same way — do not force an AEAD call on a zero-length plaintext, since that would produce a byte sequence (ciphertext-of-nothing plus a 16-byte tag) the real peer never sends and may not expect.

Receive side (`data_received`, `connection.py:126-153`):

```python
def data_received(self, data):
    self._buffer += data
    while len(self._buffer) >= HEADER_LENGTH:
        payload_length = HEADER_LENGTH + int.from_bytes(
            self._buffer[1:HEADER_LENGTH], byteorder="big"
        )
        if len(self._buffer) < payload_length:
            break
        header = self._buffer[0:HEADER_LENGTH]
        payload = self._buffer[HEADER_LENGTH:payload_length]
        self._buffer = self._buffer[payload_length:]
        try:
            if self._chacha and len(payload) > 0:
                payload = self._chacha.decrypt(payload, aad=header)
            self._listener.frame_received(FrameType(header[0]), payload)
        except Exception:
            _LOGGER.exception("failed to handle frame")
```

Notes for the Rust port:
- `payload_length` here is **total frame size including the 4-byte header** (`HEADER_LENGTH + <declared payload length>`), not just the payload. A Rust decoder should compute `total = 4 + u32::from(be_bytes[1..4])` the same way (24-bit big-endian integer, top byte always zero since it comes from a `to_bytes(3, "big")` on the sender side — but nothing stops a malformed/hostile length field from setting the top byte if you parse it as a plain `u32` read of 4 bytes; parse exactly 3 bytes as a `u24`, not 4).
- `FrameType(header[0])` will raise `ValueError` in Python (caught by the broad `except Exception`, logged and dropped) if the byte doesn't match a known enum member. A Rust `TryFrom<u8>` should similarly treat unknown frame-type bytes as a recoverable per-frame error, not a fatal transport error — pyatv's behavior is to silently drop the one malformed frame and keep the connection alive.
- Buffering is a simple growable byte accumulator; partial frames (header not yet fully received, or payload not yet fully received) just leave `self._buffer` unmodified and wait for more `data_received` calls. No maximum frame size is enforced anywhere in this file — a 3-byte big-endian length field caps a single frame at `0xFFFFFF = 16,777,215` bytes, but nothing prevents a Rust implementation from needing to defend against a hostile/buggy length claim before allocating a receive buffer of that size; pyatv itself has no such guard (worth a deliberate decision in the port, flagged in §12).

### 1.2 `FrameType` enum — confirmed exact, full listing

`connection.py:21-40`:

```python
class FrameType(Enum):
    Unknown = 0
    NoOp = 1
    PS_Start = 3
    PS_Next = 4
    PV_Start = 5
    PV_Next = 6
    U_OPACK = 7
    E_OPACK = 8
    P_OPACK = 9
    PA_Req = 10
    PA_Rsp = 11
    SessionStartRequest = 16
    SessionStartResponse = 17
    SessionData = 18
    FamilyIdentityRequest = 32
    FamilyIdentityResponse = 33
    FamilyIdentityUpdate = 34
```

Value `2` is skipped, undocumented, no comment in source. Values `12-15`, `19-31`, `35+` are simply absent from the enum — pyatv has never needed them. A Rust port's `FrameType` enum should mirror exactly this sparse numbering (do not renumber/compact) since the numeric value is what's on the wire. `protocol.py:192-207` (`frame_received`) treats any frame type not in `_OPACK_FRAMES = [U_OPACK, E_OPACK, P_OPACK]` and not in `_AUTH_FRAMES = [PS_Start, PS_Next, PV_Start, PV_Next]` as simply logged-and-ignored — i.e. `NoOp`, `PA_Req`/`PA_Rsp`, `SessionStartRequest`/`SessionStartResponse`/`SessionData`, and the three `FamilyIdentity*` values are **never handled by pyatv's client at all**, at any layer. There is no code anywhere in `pyatv/protocols/companion/` that constructs or interprets `SessionStartRequest`/`SessionStartResponse`/`SessionData`/`PA_Req`/`PA_Rsp`/`FamilyIdentity*`/`NoOp` frames — despite the names strongly suggesting a session-management and multi-user-family-account sub-protocol exists on real devices, pyatv treats Companion purely as an OPACK-request/response/event channel wrapped in PS/PV pairing frames. **This is a real gap, not an oversight to silently work around**: flag explicitly in §12 as scope the Rust port should decide about deliberately (mirror pyatv's ignorance, or reverse-engineer these frame types independently — pyatv gives zero guidance on their payload shape).

### 1.3 Encryption enable and the nonce/AAD boundary

`connection.py:90-92`:
```python
def enable_encryption(self, output_key: bytes, input_key: bytes) -> None:
    """Enable encryption with the specified keys."""
    self._chacha = chacha20.Chacha20Cipher(output_key, input_key, nonce_length=12)
```
This is the **plain `Chacha20Cipher`** base class (not the `Chacha20Cipher8byteNonce` subclass), constructed with `nonce_length=12` explicitly. Per `chacha20.py:15,30-51` (§1.4 below), when `nonce_length == NONCE_LENGTH (12)`, `_pad_nonce` is **never invoked** by the nonce-getter properties (the `if nonce_length != NONCE_LENGTH:` guard at `chacha20.py:32,45` short-circuits) — so the nonce actually transmitted to the AEAD primitive is the **raw little-endian 12-byte counter**, with **no leading zero-byte padding at all**. This confirms `mrp-companion.md`'s claim precisely and is the detail most likely to be gotten wrong by a Rust port that reflexively reuses whatever nonce-construction helper it wrote for MRP's `Chacha20Cipher8byteNonce` (4-zero-byte-prefix + 8-byte counter) — Companion's nonce is a **different byte layout entirely**, not a parameterization of the same one at a different width; the 8-byte-counter variant always has a 4-zero-byte prefix baked into a fixed 12-byte struct pack (`chacha20.py:76-105`), whereas the 12-byte counter variant is `counter.to_bytes(12, "little")` with nothing prepended.

Counter values: `_out_counter`/`_in_counter` both start at `0` (`chacha20.py:19-20`), independent per direction, incremented by exactly `1` after every `encrypt`/`decrypt` call that used the auto-generated (non-explicit) nonce (`chacha20.py:53-73`). Auth-frame handshake messages (PS_Start/PS_Next/PV_Start/PV_Next TLV8 sub-payloads, §5) use **explicit fixed ASCII nonces** (`b"PS-Msg05"` etc.) via the **`Chacha20Cipher8byteNonce`** class inside `hap_srp.py`'s `step3`/`step4`/`verify1` — this is a **separate cipher object from the transport-level `Chacha20Cipher(nonce_length=12)`** constructed later by `CompanionConnection.enable_encryption`; the two never share counter state, confirming `hap-pairing-port-spec.md` §5.1's framing. Do not conflate "the cipher used to wrap the pairing TLV8 sub-payload inside PS-Msg05/06" with "the cipher used to encrypt the Companion frame body once pairing is complete" — they are two distinct `Chacha20Cipher`-family instances, constructed from different keys (SRP/X25519-session-key vs. the post-pair-verify HKDF transport keys) with different nonce shapes (8-byte-counter-with-zero-prefix, fixed-ASCII-nonce mode vs. bare-12-byte-counter mode).

AAD: **the 4-byte header itself** (`bytes([frame_type.value]) + payload_length.to_bytes(3, "big")`, the post-tag-adjustment version), on both send (`connection.py:116`, `data = self._chacha.encrypt(data, aad=header)`) and receive (`connection.py:149`, `payload = self._chacha.decrypt(payload, aad=header)`). This binds the ciphertext to its own declared frame-type-and-length, preventing a MITM from truncating/extending/retyping a frame without detection — confirmed exact, matching `mrp-companion.md` §4.2 and `hap-pairing-port-spec.md` §5.4.

### 1.4 `pyatv/support/chacha20.py` — full relevant excerpt (already reproduced in `hap-pairing-port-spec.md` §5.1, repeated here for the Companion-specific reading)

```python
NONCE_LENGTH = 12

class Chacha20Cipher:
    def __init__(self, out_key: bytes, in_key: bytes, nonce_length: int = 8) -> None:
        self._enc_out = ChaCha20Poly1305(out_key)
        self._enc_in = ChaCha20Poly1305(in_key)
        self._out_counter = 0
        self._in_counter = 0
        self._nonce_length = nonce_length

    @property
    def out_nonce(self) -> bytes:
        nonce_length = self._nonce_length
        nonce = self._out_counter.to_bytes(length=nonce_length, byteorder="little")
        if nonce_length != NONCE_LENGTH:
            return self._pad_nonce(nonce)
        return nonce
    # in_nonce is the symmetric decrypt-direction counterpart

    def _pad_nonce(self, nonce: bytes) -> bytes:
        return b"\x00" * (NONCE_LENGTH - len(nonce)) + nonce

    def encrypt(self, data, nonce=None, aad=None) -> bytes:
        if nonce is None:
            nonce = self.out_nonce
            self._out_counter += 1
        elif len(nonce) < NONCE_LENGTH:
            nonce = self._pad_nonce(nonce)
        return self._enc_out.encrypt(nonce, data, aad)
    # decrypt is the symmetric counterpart, using in_nonce/_in_counter/_enc_in
```
(`chacha20.py:9-73`, condensed — full file is 106 lines including the `Chacha20Cipher8byteNonce` subclass, which Companion's transport layer never touches). For Companion, `nonce_length=12` is passed explicitly at construction (`connection.py:92`), so `out_nonce`/`in_nonce` return `counter.to_bytes(12, "little")` unpadded, exactly matching `NONCE_LENGTH`. `ChaCha20Poly1305` here is `chacha20poly1305_reuseable.ChaCha20Poly1305Reusable` (`chacha20.py:7`) — a reusable-key wrapper needed only because of a PyCryptodome/`cryptography`-package API quirk; the Rust `chacha20poly1305` crate's standard `ChaCha20Poly1305` type needs no special "reusable" variant (confirmed already in both prior research docs).

### 1.5 Connection lifecycle, listener callbacks

- `CompanionConnection.__init__` (`connection.py:56-72`) takes `loop, host, port, device_listener` (the last is `Optional[StateProducer]`, used only for `connection_lost` propagation to the higher-level device-connection-state machine, not for any Companion-specific logic).
- `connect()` (`connection.py:79-81`): `await self.loop.create_connection(lambda: self, self.host, self.port)` — a bare `asyncio.Protocol`-based TCP client connect, no TLS, no application-layer handshake before the first PS/PV frame.
- `close()` (`connection.py:83-88`): idempotent, sets `self.transport = None` after calling `transport.close()`.
- `set_listener(listener: CompanionConnectionListener)` (`connection.py:94-96`) — the `CompanionConnectionListener` ABC (`connection.py:46-50`) has exactly one callback, `frame_received(frame_type, data)`; `CompanionProtocol` (§2) is the sole implementer.
- `connection_lost(exc)` (`connection.py:160-167`): on abnormal close (`exc` is not `None`), calls `self._device_listener.listener.connection_lost(exc)`; on clean close, calls `.connection_closed()`. This is plumbing into pyatv's generic `StateProducer`/device-listener machinery, not Companion-specific — a Rust port's connection abstraction should expose an equivalent "closed cleanly vs closed with error" signal to whatever supervises reconnection.
- No heartbeat/keepalive of any kind exists at the Companion transport layer (contrast with AirPlay's 2-second RTSP `FEEDBACK` heartbeat, `mrp-companion.md` §3.3 step 6). Nothing in `connection.py`, `protocol.py`, or `api.py` sends periodic traffic to keep a Companion connection alive. A Rust port should not invent one; if real-device idle-timeout behavior needs handling, that is new research, not something to port from pyatv (flagged in §12).

---

## 2. `pyatv/protocols/companion/protocol.py` — message envelope and dispatch

### 2.1 Envelope keys — confirmed exact

Every `E_OPACK`-carried request/response/event is an OPACK dict. Confirmed keys, cross-checked against `protocol.py`, `api.py`, and the fake device's `send_response`/`send_event`/`send_error` (`tests/fake_device/companion.py:309-344`):

| Key | Type | Present on | Meaning |
|---|---|---|---|
| `_i` | string | Request, Response, Event | Identifier — command name on request (e.g. `_systemInfo`), echoed back verbatim on the matching response (`send_response`, `companion.py:309-318`); event name on Event frames |
| `_t` | int | Request, Response, Event | `MessageType`: `Event = 1`, `Request = 2`, `Response = 3` (`protocol.py:54-59`) |
| `_x` | int | Request, Response | XID — see §2.2. **Never present on Event frames** (`api.py:247-265`, `_send_event` builds a dict with only `_i`/`_t`/`_c`, no `_x` is added anywhere in that path; confirmed also in the fake device's `send_event`, `companion.py:320-329`, which is passed an explicit `xid` value purely to reuse `send_to_client`'s envelope shape internally for logging/matching but the client-facing dict for events genuinely omits any XID-based correlation on the wire in normal operation — actually note: the fake device's own `send_event` **does** include `_x` in the dict it sends, `companion.py:320-329` sets `"_x": xid`; this is asymmetric with the real client's own outgoing events, which never set `_x` — the client-side omission is real, `_send_event`/`protocol.py`'s dispatch path for **incoming** events (`_handle_opack`, `protocol.py:217-232`) never reads `opack_data.get("_x")` for the `Event` branch at all, it only reads `_i`/`_c` — so whether the device includes `_x` on outbound events is irrelevant to the client, and the client itself never emits `_x` on outbound events either) |
| `_c` | dict | Request, Response, Event | Content — command-specific argument dict (request/event) or result dict (response) |
| `_em` | string | Response (error only) | Error message. Presence of this key is exactly how `_exchange_generic_opack` (`protocol.py:173-174`) detects failure: `if "_em" in unpacked_object: raise exceptions.ProtocolError(f"Command failed: {unpacked_object['_em']}")` — **the client never inspects `_ec` or `_ed`** despite the fake device sending both (see next row) |
| `_ec` | int | Response (error only, server→client) | Error code. Sent by the fake device (`send_error`, `companion.py:331-344`, default `code=1337`) but **never read by pyatv's real client code** — grepped `_ec` across `pyatv/protocols/companion/*.py`, zero read sites. A Rust port wanting parity with pyatv's *client* behavior does not need to parse this field for correctness, but should still model it in a typed response-envelope struct since a well-behaved Rust client ought to surface it in error messages even where pyatv's Python client silently drops it |
| `_ed` | string | Response (error only, server→client) | Error domain (fake device default `"RPErrorDomain"`, `companion.py:332`). Same story as `_ec` — sent by the (fake, and presumably real) server, never read by pyatv's client |

The `_pwTy`/`_auTy` keys are **not part of this envelope** — they are top-level sibling keys alongside `_pd` on auth frames only (§4), never combined with `_i`/`_t`/`_x`/`_c`.

### 2.2 XID allocation and request/response correlation

`protocol.py:89`: `self._xid: int = randint(0, 2**16)` — random seed at `CompanionProtocol.__init__` time, comment: `# Don't know range here, just use something`. This is **not** a `u16` range constraint on subsequent XIDs, only on the *initial* seed — the field is incremented by plain Python integer `+= 1` (`protocol.py:152,183`) with no modulus/wraparound applied anywhere in this file, so after enough exchanges the XID will exceed `2**16 - 1` and keep growing as an arbitrary-precision Python int. **A Rust port must decide the actual wire width** since this matters for OPACK encoding (§4.5's small-int/sized-int tag selection in `mrp-companion.md`): pyatv relies on OPACK's variable-width integer encoding to just emit whatever tag fits the current XID value's magnitude (`0x08`-`0x2F` inline for values 0-39, then `0x30`/`0x31`/... for larger), so there is no fixed-width wire contract for XID — a Rust `u32` or even `u64` counter, encoded through the same variable-width OPACK integer path, will interoperate correctly as long as the *encoder* doesn't truncate. Do not assume XIDs are always small numbers on the wire.

Two disjoint correlation strategies coexist in `_queues: Dict[FrameIdType, SharedData[Any]]` (`protocol.py:90`, `FrameIdType = Union[int, FrameType]`, `protocol.py:49`):
- **Auth frames** (`exchange_auth`, `protocol.py:125-141`): keyed by `FrameType` itself (`FrameType.PS_Next` or `FrameType.PV_Next` — see the `*_Start`→`*_Next` remapping quirk below), since "multiple authentication attempts cannot be made in parallel" (`protocol.py:46-48` comment). Only one auth exchange can be in flight; a second `exchange_auth` call before the first resolves would silently overwrite `self._queues[identifier]` (no guard against this in the code — not flagged upstream, low real-world risk since pairing is inherently sequential, but a Rust port using a `HashMap` keyed the same way should be aware there's no reentrancy protection here to preserve if faithfully porting, only to avoid regressing if adding a stricter API).
- **Regular OPACK requests** (`exchange_opack`, `protocol.py:143-153`): keyed by the integer XID, allowing many concurrent in-flight commands. `data["_x"] = self._xid; identifier = self._xid; self._xid += 1` — the XID is written into the outgoing dict **and** used as the dispatch key in the same call, confirmed exact.

`_exchange_generic_opack` (`protocol.py:155-176`) is the shared body: `send_opack(frame_type, data)` (adds `_x` if the dict doesn't already carry one — relevant for the `exchange_auth` path, which never sets `_x` at all, only for the `exchange_opack` path where `_x` was already set by the caller one line earlier, making the `if "_x" not in data` guard in `send_opack`, `protocol.py:181-183`, dead code for that call path specifically but live for any other direct `send_opack` caller such as `_send_command`/`_send_event`'s "Event" branch — wait, `_send_event` uses `self._protocol.send_opack` directly, not `exchange_opack`, and its dict never contains `_x`, so `send_opack`'s auto-XID-injection **does** fire for events too, meaning **every outbound frame through `send_opack`, including Events, silently gets an `_x` key added if missing** — correcting the table row above: the *dispatch mechanism* never expects `_x` on events, but `send_opack`'s own logic will unconditionally stamp one on if the caller didn't provide one, so real outbound Event frames from pyatv's client **do** carry an `_x` field on the wire, it is simply never used as a correlation key for events specifically). Then `self._queues[identifier] = SharedData()` (a single-shot future-like awaitable, `pyatv/support/collections.py`, not detailed further here as it is generic asyncio plumbing outside Companion's scope) and `await self._queues[identifier].wait(timeout)` with `DEFAULT_TIMEOUT = 5.0` seconds (`protocol.py:38`).

Response validation: `if not isinstance(unpacked_object, dict): raise ProtocolError(...)`, then the `_em`-presence check above. **A Rust port's XID-correlation table should be keyed on the same union-of-(u32-ish-int, FrameType-enum) shape**, or more idiomatically two separate maps (one for the single in-flight auth exchange, one `HashMap<u64, oneshot::Sender<_>>` for XID-keyed requests) — the two never collide by construction (auth frames are dispatched via `_handle_auth`, keyed purely by `frame_type`, entirely separate code path from `_handle_opack`'s XID lookup, `protocol.py:188-207`).

### 2.3 `*_Start`→`*_Next` response-frame-type quirk — confirmed exact

```python
async def exchange_auth(self, frame_type, data, timeout=DEFAULT_TIMEOUT):
    # Authentication frames have strange logic as *_Start is only used for first
    # message, then *_Next is used for remaining message (even response to first
    # message)
    if frame_type == FrameType.PS_Start:
        identifier = FrameType.PS_Next
    elif frame_type == FrameType.PV_Start:
        identifier = FrameType.PV_Next
    else:
        identifier = frame_type
    return await self._exchange_generic_opack(frame_type, data, identifier, timeout)
```
(`protocol.py:125-141`) — confirms `mrp-companion.md` §4.3's claim exactly. **The outbound `frame_type` for the very first message of each handshake is `PS_Start`/`PV_Start`, but the client registers itself in `self._queues` under `PS_Next`/`PV_Next` — because the device's reply to that first message always arrives typed `PS_Next`/`PV_Next` on the wire, never echoing back `*_Start`.** Every subsequent client→device message in the same handshake is itself sent as `*_Next` (both request and expected-response side), so from message 2 onward `identifier == frame_type` trivially. A Rust port's auth-frame dispatcher must special-case exactly this one asymmetry (first-frame-only outbound-type-differs-from-expected-response-type) rather than assuming request/response frame types always match.

### 2.4 `start()` sequence

```python
async def start(self):
    if self._is_started:
        raise exceptions.ProtocolError("Already started")
    self._is_started = True
    await self.connection.connect()
    if self.service.credentials:
        self.srp.pairing_id = parse_credentials(self.service.credentials).client_id
    await error_handler(self._setup_encryption, exceptions.AuthenticationError)

async def _setup_encryption(self):
    if self.service.credentials:
        credentials = parse_credentials(self.service.credentials)
        pair_verifier = CompanionPairVerifyProcedure(self, self.srp, credentials)
        await pair_verifier.verify_credentials()
        output_key, input_key = pair_verifier.encryption_keys(
            SRP_SALT, SRP_OUTPUT_INFO, SRP_INPUT_INFO
        )
        self.connection.enable_encryption(output_key, input_key)
```
(`protocol.py:94-123`) — `start()` is idempotent-guarded (raises if already started, does not silently no-op), connects the raw TCP socket first, **then** (only if credentials already exist — i.e. this is a normal post-pairing connection, not the pairing flow itself) restores `self.srp.pairing_id` from the persisted `client_id` and runs a full pair-verify before any OPACK traffic is possible. If `self.service.credentials` is falsy (no prior pairing), `_setup_encryption` is a no-op and the connection stays **unencrypted** — this is the code path `CompanionPairSetupProcedure.start_pairing()` relies on (§4): pairing's own `PS_Start`/`PS_Next` frames are sent in the clear (`self._chacha` is `None` throughout pair-setup, confirmed by `connection.py:104,115` guards being false when `self._chacha is None`), consistent with the standard HAP model where pair-*setup* establishes trust from nothing and therefore cannot itself be encrypted, while pair-*verify* (run on every subsequent connection once credentials exist) both authenticates and immediately yields the transport key.

`SRP_SALT = ""`, `SRP_OUTPUT_INFO = "ClientEncrypt-main"`, `SRP_INPUT_INFO = "ServerEncrypt-main"` (`protocol.py:40-42`) — already the ground truth documented exhaustively (including the role-swap-or-not analysis and the reference server's opposite-direction assignment) in `hap-pairing-port-spec.md` §4.3; not reproduced again here beyond confirming the literal string values against this file directly (byte-exact match).

**There is no `_systemInfo`/session-start step inside `protocol.py` itself** — `CompanionProtocol.start()` only gets the transport to an authenticated, encrypted state. The `_systemInfo`→`_touchStart`→`_sessionStart`→`TVRCSessionStart`→`_tiStart`→`subscribe_event("_iMC")` sequence quoted in `mrp-companion.md` §4.7 lives entirely in `CompanionAPI.connect()` (`api.py:135-159`, §3.1 below), a full layer above `CompanionProtocol` — confirming that `mrp-companion.md`'s existing description of the bring-up order is accurate but was describing the wrong module as the owner; `protocol.py` is transport+envelope only, `api.py` is command-catalogue+session-bring-up. No correction needed to the *sequence* itself, only a note that a Rust port's module boundary should place session bring-up in the API/client layer, mirroring pyatv's own separation, not in the transport/protocol layer.

**No heartbeats, no timeouts beyond the per-exchange 5-second `DEFAULT_TIMEOUT`.** Confirmed by exhaustive read of `protocol.py` — there is no periodic task, no idle-connection watchdog, nothing resembling AirPlay's `FEEDBACK` cadence anywhere in this file or in `api.py`.

### 2.5 Frame dispatch — `frame_received`/`_handle_auth`/`_handle_opack`

Already quoted verbatim above (§2.1 context) and in the earlier full-file read; key confirmed behaviors:
- Unknown/malformed OPACK top-level type (not a dict) is silently dropped with a debug log (`protocol.py:196-198`), not an error surfaced to any waiting exchange.
- `_handle_auth` (`protocol.py:209-215`): `self._queues.pop(frame_type)` — a `KeyError` (no one waiting) is caught and logged as a warning, not raised. Same pattern in `_handle_opack`'s XID branch (`protocol.py:227-232`), except there it's an explicit `if xid in self._queues` check rather than a try/except-KeyError, functionally equivalent.
- Any exception during `opack.unpack(data)` itself, or during dispatch, is caught by the outer `try/except Exception: _LOGGER.exception(...)` in `frame_received` (`protocol.py:204-205`) — a malformed incoming frame never crashes the connection, it's dropped with a logged stack trace. A Rust port should treat per-frame decode/dispatch failures as non-fatal to the connection (log-and-continue), matching this resilience posture.

---

## 3. `pyatv/protocols/companion/api.py` — command surface

### 3.1 `CompanionAPI.connect()` — session bring-up sequence, confirmed exact and complete

```python
async def connect(self):
    if self._protocol:
        return
    self._connection = CompanionConnection(...)
    self._protocol = CompanionProtocol(self._connection, SRPAuthHandler(), self.core.service)
    self._protocol.listener = self
    await self._protocol.start()

    await self.system_info()
    await self._touch_start()
    await self._session_start()
    await self._tv_rc_session_start()
    await self._text_input_start()

    await self.subscribe_event("_iMC")
```
(`api.py:135-159`) — idempotent-guarded on `self._protocol` truthiness (unlike `CompanionProtocol.start()`'s raise-if-already-started, this one just silently returns, since `connect()` here is called implicitly by every `_send_command`/`_send_event` invocation, `api.py:168,249`, so it must be safe to call repeatedly). Order confirmed **exactly**: `system_info` → `_touch_start` → `_session_start` → `_tv_rc_session_start` → `_text_input_start` → `subscribe_event("_iMC")`. This is a strict sequential `await` chain, not concurrent — a Rust port must preserve the ordering, since `_tv_rc_session_start`'s own docstring explains a real ordering dependency (`FetchAttentionState` is refused by `tvremoted` until a TV-Remote-Client session exists), and there is no evidence the other orderings are similarly load-bearing versus simply "this is the order pyatv's author wrote it in" — but since this is the *only* known-working sequence against real hardware, treat the whole chain as ordering-significant unless/until proven otherwise by a live-device experiment.

### 3.2 `system_info()` — exact payload

```python
async def system_info(self):
    creds = parse_credentials(self.core.service.credentials)
    info = self.core.settings.info
    await self._send_command(
        "_systemInfo",
        {
            "_bf": 0,
            "_cf": 512,
            "_clFl": 128,
            "_i": info.rp_id or info.device_id.replace(":", "").lower(),
            "_idsID": creds.client_id,
            "_pubID": info.device_id,
            "_sf": 256,
            "_sv": "170.18",
            "model": info.model,
            "name": info.name,
        },
    )
```
(`api.py:187-211`). Every numeric literal here (`_bf: 0`, `_cf: 512`, `_clFl: 128`, `_sf: 256`) is a **cargo-culted magic constant** — pyatv's own inline comment reads `# Bunch of semi-random values here...` (`api.py:193`) and per-field comments read `# Not really device id here, but better then anything...` (`_pubID`, `api.py:204`) and `# Status flags?` (`_sf`, `api.py:206`) and `# Software Version (I guess?)` (`_sv`, `api.py:207`). **A Rust port should send these exact literal values** rather than attempting to derive "more correct" ones — pyatv's own maintainers do not know what most of these mean, and changing them risks breaking interop with real devices that may pattern-match on these exact values. `_i` deserves special note: its own inline comment (`api.py:200-201`) reads `# A null "_i" stops the device from pushing TVSystemStatus (power state) events; fall back to a stable identifier.` — this field is **load-bearing for whether the device will push power-state events at all**, not cosmetic; a Rust port must never send a null/absent `_i` here. `creds.client_id` for `_idsID` requires credentials to already be set (`parse_credentials(self.core.service.credentials)` — will return `NO_CREDENTIALS`, i.e. an all-empty `HapCredentials`, if `self.core.service.credentials` is `None`, per `hap_pairing.py:127-129`; `_idsID` would then be sent as an empty `bytes` object, OPACK-encoded as `b"\x70"` — inline zero-length raw-byte-string tag — the empty-credentials case is not otherwise special-cased in `system_info()` itself, but note `setup()` in `__init__.py:665-668` refuses to even instantiate `CompanionAPI` if `core.service.credentials` is falsy, so in practice this path is unreachable through the normal facade — only exercised by unusual manual test/direct-API usage).

### 3.3 `_touch_start()`/`_touch_stop()`

```python
async def _touch_start(self) -> Mapping[str, Any]:
    self._base_timestamp = time.time_ns()
    return await self._send_command(
        "_touchStart", {"_height": TOUCHPAD_HEIGHT, "_tFl": 0, "_width": TOUCHPAD_WIDTH}
    )

async def _touch_stop(self) -> None:
    await self._send_command("_touchStop", {"_i": 1})
```
(`api.py:464-475`). `TOUCHPAD_WIDTH = TOUCHPAD_HEIGHT = 1000.0` (`api.py:88-89`, `float`, not `int` — OPACK-encodes as tag `0x36` float64, confirmed matching the general OPACK float table). `_tFl` (touch flags?) is always literal `0`, never otherwise set anywhere in pyatv. `_touchStop`'s `{"_i": 1}` payload is the **only place in the entire Companion module where `_i` is used as a content-dict key rather than the top-level envelope identifier field** — same key name, completely different meaning/scope (content-level `_i` here is some kind of session/touch-id, always literal `1`, never varied). A Rust port's typed request-builder must not conflate these two `_i` usages if it factors out a shared "identifier" concept — they are unrelated fields that happen to share a name because Apple's own key-naming convention is terse and reused across unrelated contexts.

`_base_timestamp = time.time_ns()` is reset every time `_touch_start()` runs (i.e. on every fresh `connect()`, since `_touch_start` is called unconditionally in the bring-up chain) — all subsequent `_hidT` events' `_ns` field (§3.6) are nanoseconds elapsed **since this touch-session start**, not since epoch, not since process start. A Rust port must track this per-connection baseline the same way, not use a single global/static baseline.

### 3.4 `_session_start()`/`_session_stop()` — the 64-bit composite SID

```python
async def _session_start(self) -> None:
    local_sid = randint(0, 2**32 - 1)
    resp = await self._send_command(
        "_sessionStart", {"_srvT": "com.apple.tvremoteservices", "_sid": local_sid}
    )
    content = resp.get("_c")
    if content is None:
        raise exceptions.ProtocolError("missing content")
    remote_sid = cast(Mapping[str, Any], resp["_c"])["_sid"]
    self.sid = (remote_sid << 32) | local_sid

async def _session_stop(self) -> None:
    await self._send_command(
        "_sessionStop", {"_srvT": "com.apple.tvremoteservices", "_sid": self.sid}
    )
```
(`api.py:213-245`). `local_sid` is a fresh random `u32` per connection. Request sends `_srvT: "com.apple.tvremoteservices"` (this exact literal, always — there is no other `_srvT` value used anywhere in pyatv's Companion code) plus `_sid: local_sid`. The device's response content's own `_sid` field (`remote_sid`) is bit-shifted into the **high 32 bits**, OR'd with the original `local_sid` in the **low 32 bits**, forming the composite session id used for every subsequent `_sessionStop` call and stored in `self.sid`. Confirmed exact against `mrp-companion.md`'s existing description — no correction needed, but note the **fake device's own reference implementation** (`tests/fake_device/companion.py:477-487`) hardcodes `remote_sid = 5555` unconditionally (`self.send_response(message, {"_sid": 5555})`) and validates `_sessionStop`'s composite against `(5555 << 32 | self.state.sid)` — i.e. the fake device does **not** implement the shift/OR logic generically, it special-cases the constant `5555` as its own remote SID, which is a useful literal for a Rust hermetic test-server counterpart aiming for behavioral parity with pyatv's own test fixture (not because `5555` has any protocol significance — it doesn't, it's an arbitrary test constant).

### 3.5 `_tv_rc_session_start()`

```python
async def _tv_rc_session_start(self) -> None:
    try:
        resp = await self._send_command("TVRCSessionStart", {"ProtocolVersionKey": "1.2"})
    except Exception as ex:
        _LOGGER.debug("TVRCSessionStart not supported: %s", ex)
```
(`api.py:227-239`). Identifier is `"TVRCSessionStart"` — note this is the **one command identifier in the entire module that does not start with an underscore**, and it is `PascalCase`/mixed rather than the `_lowerCamel` convention every other identifier (`_systemInfo`, `_touchStart`, `_sessionStart`, `_hidC`, `_mcc`, `_tiStart`, `_tiC`, `_interest`, `_launchApp`) follows. Content payload key is `ProtocolVersionKey` (also unconventional — `PascalCase`, not `_x`-style) with fixed literal value `"1.2"`. **Wrapped in a bare `try/except Exception`, not `except exceptions.ProtocolError` or similar narrower type** — meaning literally any failure (protocol error, timeout, connection drop mid-call) is swallowed at debug level and bring-up proceeds regardless. A Rust port implementing this step should treat its failure as non-fatal to `connect()` succeeding overall, matching this exact resilience posture — this is deliberate (per the docstring, older devices may not support this command at all) not an oversight.

### 3.6 `_text_input_start()`/`_text_input_stop()`/`text_input_command()`

```python
async def _text_input_start(self) -> Mapping[str, Any]:
    response = await self._send_command("_tiStart", {})
    await asyncio.gather(*self.dispatch("_tiStart", response.get("_c", {})))
    return response

async def _text_input_stop(self) -> None:
    await self._send_command("_tiStop", {})
```
(`api.py:401-407`). Both send an **empty content dict** `{}` — no arguments. `_tiStart`'s response content is dispatched to any listener registered for event-name `"_tiStart"` (note: this reuses the generic `MessageDispatcher`/event-listener machinery for what is actually a *request's response*, not a true server-pushed event — `CompanionKeyboard.__init__` (`__init__.py:498-501`) explicitly comments on this: `# _tiStart is actually a command that we forward the response of`). This is how `CompanionKeyboard._handle_text_input` learns about keyboard-focus state changes triggered by the client's own `_tiStart` call, in addition to genuine server-pushed `_tiStarted`/`_tiStopped` events.

`text_input_command()` (`api.py:409-452`) is the higher-level entry point used by all of `text_get`/`text_clear`/`text_append`/`text_set`:
```python
async def text_input_command(self, text, clear_previous_input=False):
    await self._text_input_stop()
    response = await self._text_input_start()
    ti_data = response.get("_c", {}).get("_tiD")
    if ti_data is None:
        return None
    session_uuid, current_text = keyed_archiver.read_archive_properties(
        ti_data, ["sessionUUID"], ["documentState", "docSt", "contextBeforeInput"]
    )
    ...
    if clear_previous_input:
        await self._send_event("_tiC", {"_tiV": 1, "_tiD": get_rti_clear_text_payload(session_uuid)})
        current_text = ""
    if text:
        await self._send_event("_tiC", {"_tiV": 1, "_tiD": get_rti_input_text_payload(session_uuid, text)})
        current_text += text
    return current_text
```
**Every text operation restarts the RTI session first** (`_text_input_stop()` then `_text_input_start()` unconditionally, even for a pure `text_get()` read with no mutation) — this is a deliberate freshness guarantee (source comment: `# restart the text input session so that we have up-to-date data`), not an optimization opportunity to skip in a Rust port; skipping the restart would risk stale `session_uuid`/text state. The `_tiD` response payload is an `NSKeyedArchiver`-encoded binary plist (**not** OPACK — this is the one place in the Companion protocol where a second, unrelated serialization format is nested inside the OPACK envelope's `_c` dict as a raw bytes value), decoded via the two-path-lookup helper in `keyed_archiver.py` (§5). `_tiC` is sent as an **Event** (`_send_event`, not `_send_command`/Request), carrying `_tiV: 1` ("RTI version"? never varied) and `_tiD` = a **separately hand-encoded** `NSKeyedArchiver` binary plist built by `plist_payloads/rti_text_operations.py` (§6) — note this is the client *constructing* an `NSKeyedArchiver` blob to send, the mirror operation of the *decoding* done by `keyed_archiver.py` on the way in; the two use completely different code (a generic UID-following reader vs. hand-written byte-literal templates), confirming pyatv never implemented a general-purpose `NSKeyedArchiver` encoder — it only ever emits two fixed shapes (clear vs. insert-text), pre-baked as literal Python dict/UID structures passed to `plistlib.dumps(..., fmt=FMT_BINARY)`.

### 3.7 `HidCommand` — full enum, confirmed exact

`api.py:35-56`:
```python
class HidCommand(Enum):
    Up = 1
    Down = 2
    Left = 3
    Right = 4
    Menu = 5
    Select = 6
    Home = 7
    VolumeUp = 8
    VolumeDown = 9
    Siri = 10
    Screensaver = 11
    Sleep = 12
    Wake = 13
    PlayPause = 14
    ChannelIncrement = 15
    ChannelDecrement = 16
    Guide = 17
    PageUp = 18
    PageDown = 19
```
Sent via `hid_command(down: bool, command: HidCommand)`:
```python
async def hid_command(self, down: bool, command: HidCommand) -> None:
    await self._send_command("_hidC", {"_hBtS": 1 if down else 2, "_hidC": command.value})
```
(`api.py:305-309`) — request identifier `_hidC`, content keys `_hBtS` (button state: `1` = down, `2` = up — **not** a boolean, an integer with exactly these two values) and `_hidC` (the `HidCommand` numeric value). This confirms `mrp-companion.md`'s table exactly and adds the down/up encoding it left implicit.

Not every `HidCommand` value is reachable from the public facade — cross-referencing `__init__.py`'s `CompanionRemoteControl`/`CompanionPower` classes:

| `HidCommand` | Reachable via | Notes |
|---|---|---|
| `Up`/`Down`/`Left`/`Right`/`Select`/`Menu`/`Home` | `RemoteControl.{up,down,left,right,select,menu,home}()` → `_press_button` | §3.7.1 |
| `VolumeUp`/`VolumeDown` | `RemoteControl.volume_up/down()` **and** `Audio.volume_up/down()` (both facades hit the same `HidCommand`, distinct call sites — `__init__.py:331-337` vs `__init__.py:475-487`) | Audio's variant additionally awaits a volume-change event (§3.7.2) |
| `PlayPause` | `RemoteControl.play_pause()` | single button, not `_press_button` composed of separate play/pause commands |
| `ChannelIncrement`/`ChannelDecrement` | `RemoteControl.channel_up/down()` | |
| `Screensaver` | `RemoteControl.screensaver()` | |
| `Guide` | `RemoteControl.guide()` | |
| `PageDown` | `RemoteControl.control_center()` — **note the name mismatch**: pyatv's `control_center()` facade method sends `HidCommand.PageDown`, not any control-center-specific command (`__init__.py:398-400`) | |
| `Sleep`/`Wake` | `Power.turn_off()`/`turn_on()` (`__init__.py:280-292`) — sent as a **single** `hid_command(False, HidCommand.Sleep)` / `hid_command(False, HidCommand.Wake)` call each, i.e. `down=False` (button-up state) **only**, no preceding down event — this is the one HID command pathway that does **not** follow the down-then-up pairing every other button press uses | |
| `Siri` | **Not reachable from any public facade class** — `HidCommand.Siri` is defined but never referenced anywhere else in `pyatv/protocols/companion/`. Grepped exhaustively; zero call sites. A Rust port should still model the enum value (for forward-compatibility / raw-API users) but should not expect pyatv's own client to ever emit it | |
| `PageUp` | **Not reachable from any public facade class.** Same situation as `Siri` — defined, never sent | |

### 3.7.1 `_press_button` — the InputAction-to-HID-sequence mapping

```python
async def _press_button(self, command, action=InputAction.SingleTap, delay=1):
    if action == InputAction.SingleTap:
        await self.api.hid_command(True, command)
        await self.api.hid_command(False, command)
    elif action == InputAction.Hold:
        await self.api.hid_command(True, command)
        await asyncio.sleep(delay)
        await self.api.hid_command(False, command)
    elif action == InputAction.DoubleTap:
        await self.api.hid_command(True, command)
        await self.api.hid_command(False, command)
        await self.api.hid_command(True, command)
        await self.api.hid_command(False, command)
    else:
        raise exceptions.NotSupportedError(f"unsupported input action: {action}")
```
(`__init__.py:402-425`, `RemoteControl`). `InputAction` (`pyatv/const.py:200-210`): `SingleTap = 0`, `DoubleTap = 1`, `Hold = 2`. `delay` defaults to `1` (second) for `Hold`. `DoubleTap` sends **two full down/up pairs back-to-back with no inter-press delay whatsoever** (no `asyncio.sleep` between the two pairs) — contrast with `TouchGestures.click()`'s own double-tap handling (§3.9), which is a structurally different code path (touch/HID-select-button click, not D-pad navigation) with its own timing.

### 3.7.2 Audio volume — event-gated round-trip

```python
async def volume_up(self) -> None:
    self._volume_event.clear()
    await self.api.hid_command(True, HidCommand.VolumeUp)
    await self.api.hid_command(False, HidCommand.VolumeUp)
    await asyncio.wait_for(self._volume_event.wait(), timeout=5.0)
```
(`__init__.py:475-480`, `CompanionAudio`, `volume_down()` is the symmetric counterpart). Unlike `RemoteControl.volume_up()` (fire-and-forget `_press_button`), `Audio.volume_up()`/`volume_down()` **block on an `_iMC` event round-trip** (`_volume_event: asyncio.Event`, set inside `_handle_control_flag_update`, `__init__.py:439-451`, when the pushed `_mcF` value has the `MediaControlFlags.Volume` bit set — the volume level itself is then re-fetched via a `_mcc: GetVolume` command, not read directly off the `_iMC` push). A Rust port's audio-volume API should model this as "send HID command, then await a subsequent `_iMC` event with the Volume bit set, with a 5-second timeout" — not a simple fire-and-forget.

`CompanionAudio.set_volume()` (`__init__.py:461-473`) instead sends `MediaControlCommand.SetVolume` directly (not a HID command) with content `{"_vol": level / 100.0}` (percent-to-fraction conversion), then awaits the same `_volume_event`.

### 3.8 `MediaControlCommand` — full enum, confirmed exact

`api.py:59-74`:
```python
class MediaControlCommand(Enum):
    Play = 1
    Pause = 2
    NextTrack = 3
    PreviousTrack = 4
    GetVolume = 5
    SetVolume = 6
    SkipBy = 7
    FastForwardBegin = 8
    FastForwardEnd = 9
    RewindBegin = 10
    RewindEnd = 11
    GetCaptionSettings = 12
    SetCaptionSettings = 13
```
Sent via:
```python
async def mediacontrol_command(self, command, args=None) -> Mapping[str, Any]:
    return await self._send_command("_mcc", {"_mcc": command.value, **(args or {})})
```
(`api.py:395-399`) — request identifier `_mcc`, content is `{"_mcc": <value>, **extra}`, i.e. the command's own numeric value is nested **inside** the content dict under the same key name `_mcc` as the outer identifier string, a second same-name-different-scope collision (compare §3.3's `_i` note) worth flagging for a Rust port's naming choices.

Facade reachability:

| `MediaControlCommand` | Reachable via | Extra args |
|---|---|---|
| `Play` | `RemoteControl.play()` | none |
| `Pause` | `RemoteControl.pause()` | none |
| `NextTrack` | `RemoteControl.next()` | none |
| `PreviousTrack` | `RemoteControl.previous()` | none |
| `SkipBy` | `RemoteControl.skip_forward(time_interval)`/`skip_backward(time_interval)` | `{"_skpS": float(...)}`, positive for forward, negated for backward; `_DEFAULT_SKIP_TIME = 10` (seconds) used when caller passes `0`/default (`__init__.py:82,359-380`); **cast to `float` explicitly** even for the negation case, source comment: `# float cast: opack fails with negative integers` — i.e. OPACK's integer encoding path apparently cannot represent a negative Python `int` correctly (or pyatv's encoder doesn't support it), so pyatv works around this by always sending a `float` for this specific field. **This is a real OPACK-encoder constraint the Rust port must independently verify and either fix properly (if the encoder can represent signed integers with sign-magnitude/two's-complement correctly) or replicate (force `f64` for any value that might go negative) — flagged prominently in §12** |
| `GetVolume`/`SetVolume` | `Audio.set_volume()`/`_handle_control_flag_update`'s internal `GetVolume` call (§3.7.2) | `SetVolume`: `{"_vol": level/100.0}`; `GetVolume`: no args, response read as `resp["_c"]["_vol"] * 100.0` |
| `FastForwardBegin`/`FastForwardEnd`/`RewindBegin`/`RewindEnd` | **Not reachable from any public facade class.** Defined, never called anywhere in `__init__.py` | |
| `GetCaptionSettings`/`SetCaptionSettings` | **Not reachable from any public facade class.** Same — defined, never called | |

### 3.9 Touch/HID event surface — `_hidT`, `swipe`, `action`, `click`

```python
async def hid_event(self, x: int, y: int, mode: TouchAction) -> None:
    x = min(max(x, 0), int(TOUCHPAD_WIDTH))
    y = min(max(y, 0), int(TOUCHPAD_HEIGHT))
    await self._send_event(
        identifier="_hidT",
        content={"_ns": (time.time_ns() - self._base_timestamp), "_tFg": 1, "_cx": x, "_tPh": mode.value, "_cy": y},
    )
```
(`api.py:311-326`, clamping logic restated from the two-line `max`/`min` calls at `api.py:313-316`). `TouchAction` (`pyatv/const.py:460-466`): `Press = 1`, `Hold = 3` (note: **not** `2` — value `2` is skipped, same "gap" pattern as `FrameType`), `Release = 4`, `Click = 5`. `_tFg` ("touch finger [id]"? never documented, always literal `1`) — single-finger touch is the only mode pyatv ever sends. `_ns` is nanoseconds elapsed since `_touch_start()`'s baseline (§3.3), an `int`. `_hidT` is sent as an **Event**, always, never a Request — no response is awaited.

`swipe(start_x, start_y, end_x, end_y, duration_ms)` (`api.py:328-362`): sends an initial `Press` at `(start_x, start_y)`, then interpolates intermediate `Hold` events every `TOUCHPAD_DELAY_MS = 16` ms (`api.py:90`) using a **time-remaining-weighted linear interpolation** (`x = x + (end_x - x) * TOUCHPAD_DELAY_MS_ns / (end_time_ns - current_time_ns)`, recomputed every tick rather than a fixed per-step delta — this means the step size grows as `current_time` approaches `end_time`, an artifact of the formula, not an intentional easing curve; a naive re-derivation might instead compute a fixed `(end - start) / num_steps` delta, which would produce a **different** intermediate trajectory and therefore different exact touch coordinates sent to the device — replicate the exact recomputed-every-tick formula if trajectory fidelity matters for interop, not just start/end point fidelity), then a final `Release` at the exact `(end_x, end_y)` (unclamped — note the final call uses the raw `end_x, end_y` parameters directly, `api.py:362`, not the clamped loop variables `x, y`, though `hid_event` itself clamps internally so the wire values end up bounded regardless).

`action(x, y, mode: TouchAction)` (`api.py:364-371`) is a thin pass-through to `hid_event` — the public `TouchGestures.action()` facade method's docstring (`__init__.py:560-567`) numbers the modes `1: press, 3: hold, 4: release`, matching the enum exactly (confirming the `2`-is-skipped gap is intentional/expected at the facade-documentation level too, not just an enum artifact).

`click(action: InputAction)` (`api.py:373-393`):
```python
async def click(self, action: InputAction):
    if action in [InputAction.SingleTap, InputAction.DoubleTap]:
        count = 1 if action == InputAction.SingleTap else 2
        for _i in range(count):
            await self._send_command("_hidC", {"_hBtS": 1, "_hidC": 6})
            await asyncio.sleep(0.02)
            await self._send_command("_hidC", {"_hBtS": 2, "_hidC": 6})
            await self.hid_event(int(TOUCHPAD_WIDTH), int(TOUCHPAD_HEIGHT), TouchAction.Click)
    else:  # Hold
        await self._send_command("_hidC", {"_hBtS": 1, "_hidC": 6})
        await asyncio.sleep(1)
        await self._send_command("_hidC", {"_hBtS": 2, "_hidC": 6})
        await self.hid_event(int(TOUCHPAD_WIDTH), int(TOUCHPAD_HEIGHT), TouchAction.Click)
```
`6` is `HidCommand.Select.value` — inlined as a raw literal here rather than referencing the enum (both are correct/equivalent, just an inconsistency in pyatv's own code style worth noting so a Rust port doesn't assume there's a *different* command being sent). Single/double tap: `20`ms between down and up (`asyncio.sleep(0.02)`), **for each of the `count` repetitions**, but **no inter-repetition delay** for double-tap (structurally identical omission to `_press_button`'s `DoubleTap` case, §3.7.1). Hold: `1` full second between down and up. **Every branch, including both tap variants, follows the `_hidC` down/up pair with exactly one `_hidT` `Click` event at the fixed coordinate `(1000, 1000)` — the touchpad's maximum corner, not the actual touch location** (there is no "location" concept for a D-pad-style select click; this is a fixed sentinel value pyatv always sends, not derived from any prior touch state). A Rust port must replicate this fixed-corner sentinel, not attempt to compute or omit a "real" location.

### 3.10 App / account commands

```python
async def launch_app(self, bundle_identifier_or_url: str) -> None:
    launch_command_key = "_urlS" if is_url_or_scheme(bundle_identifier_or_url) else "_bundleID"
    await self._send_command("_launchApp", {launch_command_key: bundle_identifier_or_url})

async def app_list(self) -> Mapping[str, Any]:
    return await self._send_command("FetchLaunchableApplicationsEvent", {})

async def switch_account(self, account_id: str) -> None:
    await self._send_command("SwitchUserAccountEvent", {"SwitchAccountID": account_id})

async def account_list(self) -> Mapping[str, Any]:
    return await self._send_command("FetchUserAccountsEvent", {})
```
(`api.py:279-303`). `is_url_or_scheme` (`pyatv/support/url.py:12-15`): `bool(urlparse(url).scheme)` — **note this is not `is_url`** (a separate, stricter helper requiring both `scheme` **and** `netloc`, `url.py:6-9`, never used by Companion) — `is_url_or_scheme` accepts a bare URL *scheme* with no authority component too (e.g. a string like `"myapp:"` with nothing after the colon would satisfy `urlparse` returning a non-empty `scheme`). This governs whether `_urlS` or `_bundleID` is chosen; a Rust port's equivalent classifier must match `urlparse`'s scheme-extraction semantics closely enough that the same set of input strings route to the same key — Python's `urlparse` accepts schemes matching `[a-zA-Z][a-zA-Z0-9+.-]*` followed by `:`; a Rust implementation using the `url` crate's `Url::parse` is **not** a drop-in equivalent since `url::Url::parse` requires a full valid URL (it will error on a bare `"myapp:"` scheme-only string in many cases) — this needs its own small scheme-sniffing helper mirroring `urlparse`'s looser grammar, not a full URL-parser dependency. Both event-identifier commands (`FetchLaunchableApplicationsEvent`, `SwitchUserAccountEvent`, `FetchUserAccountsEvent`) are, despite the `Event` suffix in their names, sent as ordinary **Requests** via `_send_command` (`_t: 2`), not as `_t: 1` Events — the naming is misleading; these are request/response commands like any other, the `Event` suffix is purely an Apple-side naming convention inherited into the wire identifier string, not a signal about pyatv's own `MessageType` usage.

`FetchLaunchableApplicationsEvent`'s response content is a **flat `{bundle_id: display_name}` dict** (`CompanionApps.app_list`, `__init__.py:168-175`: `[App(name, bundle_id) for bundle_id, name in content.items()]` — key is the bundle id, value is the display name, confirmed also by the fake device's `handle_fetchlaunchableapplicationsevent`, `tests/fake_device/companion.py:369-370`, which echoes back `self.state.installed_apps` verbatim, itself set via `FakeCompanionUseCases.set_installed_apps({bundle_id: name, ...})`, `companion.py:573-575`). `FetchUserAccountsEvent`'s response shape is the identical `{account_id: display_name}` pattern (`CompanionUserAccounts.account_list`, `__init__.py:190-197`).

### 3.11 `FetchAttentionState` — `SystemStatus`

```python
async def fetch_attention_state(self) -> SystemStatus:
    resp = await self._send_command("FetchAttentionState", {})
    content = resp.get("_c")
    if content is None:
        raise exceptions.ProtocolError("missing content")
    return SystemStatus(content["state"])
```
(`api.py:454-462`). `SystemStatus` (`api.py:77-85`):
```python
class SystemStatus(Enum):
    Unknown = 0x00  # NB: Not a valid protocol entry (only used here)
    Asleep = 0x01
    Screensaver = 0x02
    Awake = 0x03
    Idle = 0x04  # NB: Not verified
```
`Unknown`'s own comment explicitly states it is a **client-side-only sentinel, never sent by any device** — a Rust port's enum should model this the same way (e.g. as the default/uninitialized state, not a value ever expected to round-trip through `SystemStatus::try_from(u8)` against real wire bytes). `Idle`'s comment (`NB: Not verified`) flags it as speculative — pyatv's own author is not confident this value is correct; a Rust port should treat `0x04` as "believed but unconfirmed to mean Idle" and flag it the same way rather than asserting confidence pyatv itself doesn't have.

`CompanionPower._system_status_to_power_state` (`__init__.py:263-273`) maps `Asleep → PowerState.Off`; `{Screensaver, Awake, Idle} → PowerState.On`; anything else (i.e. only reachable if a raw wire value outside `0x01-0x04` somehow appeared, since `SystemStatus(content["state"])` would itself raise `ValueError` for a genuinely unknown wire value rather than falling through to this branch) → `PowerState.Unknown`. Two event names are subscribed for the same handler: `"SystemStatus"` and `"TVSystemStatus"` (`__init__.py:239-244`) — **both** independently `subscribe_event()`'d and **both** wired to the identical `_handle_system_status_update` callback; pyatv does not know a priori which event name a given device/tvOS version will actually push, so it defensively subscribes to both. `CompanionPower.initialize()` wraps the **initial** `fetch_attention_state()` call in a broad `try/except Exception` (`__init__.py:226-235`) with an explicit comment explaining that newer tvOS versions reply "No request handler" to `FetchAttentionState` (i.e. the fake device's `send_handler_not_supported` shape, `companion.py:346-348`, error code `58822` — matching `mrp-companion.md`'s note that the client never inspects error codes: this specific code value is never checked by pyatv's power-state-init logic either, only that *some* exception occurred) — subscription to the two event names proceeds **regardless of whether the initial fetch succeeded**, in its own separate `try/except` block (`__init__.py:239-246`), so a device that rejects `FetchAttentionState` outright can still deliver working live power-state updates via pushed events. A Rust port's `Power` initialization must not treat "initial fetch failed" as fatal to setting up live event subscriptions.

---

## 4. Companion pairing — `auth.py` + `pairing.py`, exact framing

This section is Companion-specific detail beyond what `hap-pairing-port-spec.md` §9.2 already covers exhaustively (procedure walkthrough, HKDF salts, the swap-or-not analysis, `# TODO`-flagged unverified checks). Read that section first; this restates only what is needed to make this document self-sufficient for someone implementing just the Companion crate, plus the parts §9.2 does not cover (the fake-device/server-side counterpart, and the undocumented tag-27 TLV).

### 4.1 `_pd`/`_pwTy`/`_auTy` — confirmed exact, full frame-by-frame payloads

`PAIRING_DATA_KEY = "_pd"` (`auth.py:19`). Pair-setup (`CompanionPairSetupProcedure`, `auth.py:39-118`):

| Step | Frame type sent | OPACK dict sent | TLV8 content of `_pd` |
|---|---|---|---|
| M1 | `PS_Start` | `{"_pd": <tlv>, "_pwTy": 1}` | `{Method: 0x00, SeqNo: 0x01}` |
| M3 | `PS_Next` | `{"_pd": <tlv>, "_pwTy": 1}` | `{SeqNo: 0x03, PublicKey: <SRP client pubkey A>, Proof: <SRP client proof M1>}` |
| M5 | `PS_Next` | `{"_pd": <tlv>, "_pwTy": 1}` | `{SeqNo: 0x05, EncryptedData: <ChaCha20-Poly1305("PS-Msg05")>}` |

`"_pwTy": 1` is sent on **every** pair-setup frame, all three (`auth.py:57-62,85-93,102-112`) — confirmed the literal integer `1` is unconditional and unvaried across the entire codebase (grepped every occurrence). Pair-verify (`CompanionPairVerifyProcedure`, `auth.py:121-164`):

| Step | Frame type sent | OPACK dict sent | TLV8 content of `_pd` |
|---|---|---|---|
| M1 | `PV_Start` | `{"_pd": <tlv>, "_auTy": 4}` | `{SeqNo: 0x01, PublicKey: <X25519 ephemeral pubkey>}` |
| M3 | `PV_Next` | `{"_pd": <tlv>}` (**no `_auTy` on this frame**) | `{SeqNo: 0x03, EncryptedData: <ChaCha20-Poly1305("PV-Msg03")>}` |

`"_auTy": 4` appears **only** on `PV_Start`, never repeated on `PV_Next` (`auth.py:139-144` vs `auth.py:153-160` — the second `exchange_auth` call's dict literal genuinely omits the key, confirmed by re-reading the exact source, not an oversight in this document). Both `_pwTy`/`_auTy` are write-only from the client's perspective — grepped every response-handling path in `auth.py`, `protocol.py`, neither key is ever read back off an incoming `resp` dict anywhere in pyatv.

### 4.2 The undocumented tag-27 (`0x1B`) TLV — server-only, present in `server_auth.py`, not in the client

`CompanionServerAuth._m1_setup` (`server_auth.py:144-153`):
```python
def _m1_setup(self, pairing_data):
    tlv = write_tlv({
        TlvValue.SeqNo: b"\x02",
        TlvValue.Salt: binascii.unhexlify(self.salt),
        TlvValue.PublicKey: binascii.unhexlify(self.session.public),
        27: b"\x01",
    })
    self.send_to_client(FrameType.PS_Next, {"_pd": tlv, "_pwTy": 1})
```
Raw integer key `27` (`0x1B`) is **not** a member of `TlvValue` (`pyatv/auth/hap_tlv8.py:13-34` — confirmed the full enum: `Method=0x00, Identifier=0x01, Salt=0x02, PublicKey=0x03, Proof=0x04, EncryptedData=0x05, SeqNo=0x06, Error=0x07, BackOff=0x08, Certificate=0x09, Signature=0x0A, Permissions=0x0B, FragmentData=0x0C, FragmentLast=0x0D, Name=0x11, Flags=0x13` — no `27`/`0x1B` entry exists). It is sent by pyatv's **reference/test server only**, in the M2 pair-setup response, with a fixed 1-byte value `b"\x01"`. It is **never read, checked, or even logged by the client side** (`auth.py`'s `_get_pairing_data`/pairing-procedure code paths only ever look up `TlvValue.Salt`/`TlvValue.PublicKey`/`TlvValue.Proof`/`TlvValue.EncryptedData`/`TlvValue.Error` — grepped, zero references to `27` or `0x1B` anywhere in `pyatv/protocols/companion/auth.py` or `pyatv/auth/hap_srp.py`). **This is best understood as pyatv's test server mimicking an observed extra TLV real Apple TV devices include in their M2 pair-setup response** (plausibly a capability/version-flags byte, given the value `0x01`, but pyatv gives zero interpretive guidance — no comment at all at this line) **that pyatv's own client simply ignores on the receive side.** A Rust port's TLV8 decoder must not choke on an unrecognized tag `27` in a real device's M2 response (the shared TLV8 codec already handles unknown tags gracefully by construction, per `hap-pairing-port-spec.md` §1 — `read_tlv` builds a generic `dict`/map keyed by raw tag byte, no fixed schema) — simply confirm the Rust port's TLV decoder is similarly permissive of unrecognized tags rather than erroring, and do not attempt to encode this tag on the client→server direction since pyatv's own client never does. **This corrects a misconception embedded in this task's own framing** (which speculated tag `0x1B` might be a "`Name`/`additional_data`" TLV) — it is not; `Name` is unambiguously `0x11` (§4.3 below, confirmed both in `hap_tlv8.py` and in `hap_srp.py`'s `step3`), and tag `27` has no name or documented purpose anywhere in pyatv at all.

### 4.3 The `Name` TLV (`0x11`) — display name, confirmed source and encoding

Not encoded in `auth.py` itself — inherited from the shared `SRPAuthHandler.step3()` (`pyatv/auth/hap_srp.py:165-205`, already reproduced in full in `mrp-companion.md` §2.8 and `hap-pairing-port-spec.md` §2.8):
```python
if name:
    tlv[TlvValue.Name] = opack.pack({"name": name})
```
`CompanionPairSetupProcedure.finish_pairing(username, pin_code, display_name)` (`auth.py:74-118`) passes `display_name` straight through to `self.srp.step3(name=display_name)` (`auth.py:100`) — no transformation. The caller is `CompanionPairingHandler.finish()` (`pairing.py:52-66`), which passes `self._name` — set from `kwargs.get("name", "pyatv")` at `CompanionPairingHandler.__init__` time (`pairing.py:24`). **The default display name, if the caller of `pyatv.pair(...)` never supplies one via `**kwargs["name"]`, is the literal string `"pyatv"`.** This is what a real device shows on-screen as the pairing requester's name during Companion pairing. **Companion pair-setup therefore always sends a `Name` TLV** (since `self._name` defaults to a non-empty string rather than `None`) — confirmed distinct from MRP, whose own pairing handler (per `hap-pairing-port-spec.md` §9.1) never passes a `display_name` at all, so MRP pair-setup never includes this TLV. A Rust port's Companion pairing API should expose a "display name" parameter defaulting to `"pyatv"` (or an equivalent project-branded default — a deliberate product decision, not a protocol requirement) to match this behavior, while being aware MRP's equivalent API should default to omitting the TLV entirely, not to the same string.

The `Name` TLV's *value* is itself an **OPACK-encoded** single-key dict `{"name": <the string>}` — nested serialization (OPACK inside a TLV8 value inside an OPACK-encoded frame payload), confirmed exact and already flagged as noteworthy in `mrp-companion.md` §2.8; repeated here because it is easy to miss that this is the **only** TLV8 value anywhere in the entire pairing handshake (Companion or MRP) that itself contains OPACK-encoded bytes rather than a raw binary blob (SRP public keys, proofs, encrypted-data ciphertexts are all raw bytes with no inner structure).

### 4.4 `CompanionPairingHandler` — `begin()`/`pin()`/`finish()`, confirmed exact

Already fully quoted in the file read above (`pairing.py:18-78`); key facts not to lose in porting:
- `begin()` (`pairing.py:45-50`): calls `self.pairing_procedure.start_pairing` through `error_handler(..., exceptions.PairingError)` — any exception raised inside `start_pairing()` (which itself calls `self.protocol.start()`, i.e. the raw TCP connect, so **connection failures surface as `PairingError`, not a lower-level connection exception**, at this layer) is wrapped/re-raised as `PairingError`.
- `pin(pin: int)` (`pairing.py:75-78`): `self.pin_code = str(pin).zfill(4)` — **always** zero-padded to (at least) 4 characters, e.g. PIN `42` becomes `"0042"`, PIN `123456` (a 6-digit PIN, which some devices do use) stays `"123456"` unchanged (`zfill` only pads, never truncates) — confirmed matching `hap-pairing-port-spec.md` §9.1/§9.2's identical claim for MRP; the exact same zero-pad-to-4 logic, not protocol-specific despite living in each protocol's own `pairing.py`.
- `finish()` (`pairing.py:52-68`): raises `PairingError("no pin given")` if `self.pin_code` is falsy (i.e. `pin()` was never called) **before** attempting any network I/O — a Rust port's finish/complete-pairing call should validate this precondition client-side too, matching pyatv's fail-fast behavior rather than sending a malformed request to the device. On success, `self.service.credentials = str(<HapCredentials>)` (the four-field colon-hex string, `hap_pairing.py:77-86`, already documented exhaustively in `hap-pairing-port-spec.md` §3.2) is set on **two** places: `self.service.credentials` (the live in-memory `BaseService`) **and** `self._settings.protocols.companion.credentials` (persisted settings storage) — both assignments happen unconditionally together (`pairing.py:58-67`), no partial-success state is possible from this method's own logic (though of course the underlying `finish_pairing` call itself can fail earlier and never reach these assignments at all, propagating as `PairingError` via `error_handler`).
- **Companion pairing does not perform a post-pairing pair-verify** inside `finish()` — confirmed explicitly in `hap-pairing-port-spec.md` §9.2 (`companion/pairing.py:52-68` — only `finish_pairing` runs; no `CompanionPairVerifyProcedure` construction anywhere in this file) and reconfirmed here by direct re-read: `pairing.py` imports only `CompanionPairSetupProcedure` (`pairing.py:10`), never `CompanionPairVerifyProcedure`. **This is the single most important divergence between MRP and Companion pairing success criteria** for a Rust port to get right: MRP's `finish()` is only considered successful if a *subsequent* pair-verify against the fresh credentials also succeeds (a stronger, immediate end-to-end check); Companion's `finish()` is considered successful the moment the SRP handshake (`step1`..`step4`) itself completes without error, with **no** immediate verification that the resulting credentials actually work for establishing an encrypted session. A Rust port choosing to be "stricter than pyatv" here (running an immediate pair-verify for Companion too, as a design choice) would diverge from pyatv's own observed behavior — a reasonable choice, but a **conscious** one to document, since it means a Rust client could report Companion pairing success in a scenario where pyatv itself would have reported it too (their success criteria would differ if the fresh credentials happen to be subtly wrong in a way SRP alone can't detect but pair-verify would) — flagged in §12.
- `device_provides_pin` (`pairing.py:70-73`): always `True`, hardcoded — confirmed matching `hap-pairing-port-spec.md` §9.3's cross-protocol claim (every `PairingHandler` in pyatv returns `True` here; pyatv never implements the "controller displays the PIN" HAP-alternative flow).

### 4.5 `rpfl` pairing-requirement logic and what `rpfl = 0x367A2` concludes

`companion_service_handler`/`service_info` (`__init__.py:614-660`), confirmed exact:
```python
PAIRING_DISABLED_MASK = 0x04
PAIRING_WITH_PIN_SUPPORTED_MASK = 0x4000

async def service_info(service, devinfo, services) -> None:
    flags = int(service.properties.get("rpfl", "0x0"), 16)
    if flags & PAIRING_DISABLED_MASK:
        service.pairing = PairingRequirement.Disabled
    elif flags & PAIRING_WITH_PIN_SUPPORTED_MASK:
        service.pairing = PairingRequirement.Mandatory
    else:
        service.pairing = PairingRequirement.Unsupported
```
**Note the TXT-record key is `rpfl`, lower-case, four letters** — this task's own framing (and, worth flagging, a plausible source of confusion for anyone skimming pyatv casually) referred to it as `rpFl`; the wire/property-dict key pyatv actually reads is the exact case-sensitive string `"rpfl"` (`__init__.py:654`), confirmed by both the production code and the parametrized test (`tests/protocols/companion/test_companion.py:57-72`, which uses `{"rpfl": "0x627B6"}` etc. as its fixture keys). A Rust port's mDNS TXT-record lookup must use the lowercase key, matching pyatv exactly (mDNS TXT keys are technically case-insensitive per RFC 6763 in principle, but pyatv's own dict lookup is a literal Python `dict.get` against whatever key casing the mDNS library handed it — verify the Rust mDNS crate's own TXT-key casing normalization behavior, since a mismatch here would silently always take the `.get("rpfl", "0x0")` default-value fallback path and misreport every real device as `Unsupported`).

Worked example for `rpfl = 0x367A2` (the value this repo's own target device advertises, per the task framing — cross-checked against pyatv's own source-comment sample data at `__init__.py:71-73`, which lists `0x367A2` verbatim as a "Pairable" example, specifically annotated `# Apple TV 4K`):

```
0x367A2 = 0011 0110 0111 1010 0010  (20 bits)
PAIRING_DISABLED_MASK        = 0x00004 = 0000 0000 0000 0000 0100
PAIRING_WITH_PIN_SUPPORTED   = 0x04000 = 0000 0100 0000 0000 0000

0x367A2 & 0x00004:
  ...0010 & ...0100 = 0000  → 0  (bit not set → not disabled)

0x367A2 & 0x04000:
  0011 0110 ... & 0000 0100 ... → 0000 0100 0000 0000 0000 = 0x4000  → nonzero (bit set)
```
So: `flags & PAIRING_DISABLED_MASK == 0` (first branch false) → falls through to `elif flags & PAIRING_WITH_PIN_SUPPORTED_MASK` → `0x367A2 & 0x4000 == 0x4000` (nonzero, truthy) → **`service.pairing = PairingRequirement.Mandatory`.** A Rust port scanning a device advertising `rpfl=0x367A2` must conclude Companion pairing is **mandatory** (PIN-based pairing is required and supported) before attempting to connect — this matches pyatv's own worked "Pairable" example in the source comment verbatim, giving high confidence this is correct pyatv behavior for that exact flag value, not just a mechanical bit-arithmetic exercise. Cross-checked against the parametrized unit test (`test_companion.py:57-72`): `{"rpfl": "0x36782"}` (a closely related sibling value from the same source comment's "Pairable" list, differing only in the low nibble) is asserted to produce `PairingRequirement.Mandatory` in the test suite directly — `0x36782`'s low 20 bits share the same `0x4000`-bit-set, `0x0004`-bit-clear pattern as `0x367A2`, confirming the worked arithmetic above by an independent, already-passing pyatv test rather than by manual bit arithmetic alone. `PairingRequirement.Disabled` is separately tested with `{"rpfl": "0x627B6"}` and `PairingRequirement.Unsupported` with both `{}` (missing key → the `"0x0"` default) and `{"rpfl": "0x0"}` explicitly (`test_companion.py:60-65`).

`PairingRequirement` enum, full listing (`pyatv/const.py:213-225`, only the four members relevant here are used by Companion — `NotNeeded`/`Optional` exist as enum members for other protocols' use but Companion's `service_info` only ever assigns `Disabled`/`Mandatory`/`Unsupported`, never `NotNeeded` or `Optional`): `Unsupported = 1`, `Disabled = 2`, `NotNeeded = 3`, `Optional = 4`, `Mandatory = 5` (member ordering/values confirmed via `const.py:213-225`, though the numeric values themselves are Python-internal and not part of any wire format — only relevant if a Rust port's own enum needs a stable discriminant for serialization elsewhere in the codebase).

`rpmd` (a separate, unrelated TXT key) drives `DeviceInfo.RAW_MODEL`/`DeviceInfo.MODEL` via `device_info()`/`lookup_model()` (`__init__.py:637-645`) — not a pairing-relevant field, included here only to avoid confusing the two similarly-named four-letter keys (`rpfl` = pairing flags, `rpmd` = raw model string) in a Rust port's TXT-record parsing code.

---

## 5. `pyatv/protocols/companion/keyed_archiver.py` — what it is and how it's used

Full file (28 lines), already reproduced verbatim above. It is **not** a general `NSKeyedArchiver` unarchiver — the module docstring says so explicitly: `"""Support for working with NSKeyedArchiver serialized data. In the absence of a robust NSKeyedArchiver implementation, read one or more properties from the archived plist by following UID references."""` (`keyed_archiver.py:1,10-12`).

```python
def read_archive_properties(archive, *paths: List[str]) -> Tuple[Optional[Any], ...]:
    data = plistlib.loads(archive)
    results = []
    objects = data["$objects"]
    for path in paths:
        element = data["$top"]
        try:
            for key in path:
                element = element[key]
                if isinstance(element, plistlib.UID):
                    element = objects[element]
            results.append(element)
        except (IndexError, KeyError):
            results.append(None)
    return tuple(results)
```
Algorithm: parse the outer structure as an ordinary (non-keyed-archiver-aware) binary plist via Python's stdlib `plistlib`, yielding a dict with (at minimum) `$top` and `$objects` top-level keys per the standard `NSKeyedArchiver` on-disk envelope shape. For each caller-supplied `path` (a list of dict keys to walk, e.g. `["sessionUUID"]` or `["documentState", "docSt", "contextBeforeInput"]`), start at `data["$top"]` and repeatedly index by each key in the path; **whenever the current element is a `plistlib.UID`** (Python's stdlib type representing an `NSKeyedArchiver` object-graph back-reference — a "pointer" into the flat `$objects` array), it is dereferenced by indexing `objects[element]` (note: `plistlib.UID` is directly usable as a list/array index in this expression because Python's `plistlib.UID` implements `__index__`, letting it be used anywhere an int is expected — a Rust port using a plist crate must find or hand-roll the equivalent "this is a UID wrapper type, treat its inner integer as an array index into `$objects`" semantics; do not assume a generic plist crate exposes this automatically, since `NSKeyedArchiver`'s UID-reference convention is an Apple-specific layer on top of plain binary-plist, not part of the base plist format itself). A missing key (`KeyError`) or an out-of-range UID index (`IndexError`) anywhere along a given path causes that path's result to be `None` rather than raising — **failures are per-path, independent**, one bad path does not prevent the other paths in the same call from succeeding.

Two call sites, both in `api.py` (§3.6): `keyed_archiver.read_archive_properties(ti_data, ["sessionUUID"], ["documentState", "docSt", "contextBeforeInput"])` (client reading its own `_tiStart` response) and, on the **fake device's** side (§7), `keyed_archiver.read_archive_properties(content, ["textOperations", "targetSessionUUID", "NS.uuidbytes"], ["textOperations", "textToAssert"], ["textOperations", "keyboardOutput", "insertionText"])` (server reading an incoming `_tiC` event's payload — i.e. the exact same reader is reused by the **server-side test fixture** to decode what the client sent, since both directions in this exchange are `NSKeyedArchiver`-encoded and pyatv never wrote a second implementation). This confirms `read_archive_properties` is a **bidirectional** utility despite living in a client-oriented module path — a Rust port structuring its crate boundaries (client-only vs. also-usable-by-a-hermetic-test-server code) should keep this reader similarly reusable on both sides, since the real protocol payload shape is identical regardless of direction.

Note the **field-name asymmetry between what the client reads and what the fake server's own state actually stores**: `_touch_start`/`_text_input_start`'s response path (client-side read) looks for `["documentState", "docSt", "contextBeforeInput"]`, while the fake device's own `rti_encoded_data` property (§7) constructs a plist whose *top-level* `$top` maps `"documentState"` → a UID pointing at an object with key `"docSt"` → a UID pointing at an object with key `"contextBeforeInput"` → the actual text string — i.e. the three-level path exists specifically because the fake device's hand-built plist has three nested wrapper objects each contributing one path segment; a Rust port's own hermetic test-server fixture should replicate this exact nesting shape (not flatten it) if it wants byte-compatible plist output against pyatv's own fake-device test suite for cross-validation purposes.

---

## 6. `plist_payloads/rti_text_operations.py` — hand-encoded `NSKeyedArchiver` payload templates

Already fully reproduced above (147 lines). Two functions, `get_rti_clear_text_payload(session_uuid: bytes) -> bytes` and `get_rti_input_text_payload(session_uuid: bytes, text: str) -> bytes`, both producing `plistlib.dumps(..., fmt=plistlib.PlistFormat.FMT_BINARY, sort_keys=False)` output matching the standard `NSKeyedArchiver` envelope shape (`$version: 100000`, `$archiver: "RTIKeyedArchiver"` — **note this is `RTIKeyedArchiver`, not the generic `NSKeyedArchiver` string** that a real `NSKeyedArchiver`-produced plist would carry in its own `$archiver` field; this is a Companion/RTI-service-specific archiver-class name, and a Rust port hand-constructing these payloads must emit this exact literal string, not the generic Apple-framework default, or a strict-parsing real device might reject the payload), `$top`, `$objects`).

Both functions build a **fixed, hand-numbered `plistlib.UID` object graph** — not a general encoder, a literal byte-for-byte template with the two variable inputs (`session_uuid`, and for the input-text variant, `text`) substituted into specific array slots. The UID numbering scheme differs subtly between the two functions (compare `$objects` index assignments in `get_rti_clear_text_payload`, `plist_payloads/rti_text_operations.py:37-74`, vs `get_rti_input_text_payload`, same file `:106-143` — the object ordering/count is not identical between the "clear" and "insert" shapes, since "clear" has an empty-string `textToAssert` slot that "insert" doesn't need, and "insert" has an `insertionText` slot that "clear" doesn't). A Rust port must **not** attempt to derive one generic encoder parameterized by "clear vs. insert" from these two functions — replicate each as its own fixed byte-template-with-substitution, exactly mirroring pyatv's own choice not to generalize this (the module docstring, `plist_payloads/rti_text_operations.py:1-5`, explicitly frames these as pre-encoded literals existing **because** there is no robust `NSKeyedArchiver` implementation to generate them dynamically — the same design rationale as `keyed_archiver.py`'s read-only, UID-following-only decoder).

Un-encoded conceptual shape (both docstrings spell this out, reproduced for clarity — this is documentation embedded in pyatv's own source, not independently verified structure): clear-text sends `{"textOperations": {"$class": RTITextOperations, "targetSessionUUID": {"$class": NSUUID, "NS.uuidbytes": <session_uuid>}, "keyboardOutput": {"$class": TIKeyboardOutput}, "textToAssert": ""}}`; input-text sends the same shape but with `"keyboardOutput": {"$class": TIKeyboardOutput, "insertionText": <text>}` and no `"textToAssert"` key at all (**not** an empty string — the key is entirely absent for the insert-text case, confirmed by the object graph literally not including a `textToAssert`/UID-pointing-at-empty-string pair in `get_rti_input_text_payload`'s `$objects` array, unlike `get_rti_clear_text_payload`'s explicit `""` at index 4).

---

## 7. Tests — `tests/fake_device/companion.py`, protocol tests, exact fixtures and byte vectors

### 7.1 `FakeCompanionService` — server-side wire handling, confirmed exact mirror of the client

`connection_made`/`connection_lost`/`enable_encryption`/`send_to_client`/`data_received` (`tests/fake_device/companion.py:239-308`) implement the **identical framing** as `CompanionConnection` (§1), independently re-derived rather than importing/reusing the client's own `connection.py` code — this is deliberate (a hermetic test fixture should not share implementation with the code under test) and gives a second independent confirmation of the frame-header/AAD/nonce-length=12 design: `payload_length = len(data) + (16 if self.chacha else 0)`, `header = bytes([frame_type.value]) + payload_length.to_bytes(3, "big")`, `chacha.encrypt(data, aad=header)` — byte-for-byte the same arithmetic as `connection.py:103-116`, confirming there is no client/server asymmetry in the framing itself (only in the pairing-role-specific SRP/HKDF derivations, already covered in `hap-pairing-port-spec.md` §4.3).

`handle_auth_frame`/`_m1_verify`/`_m3_verify`/`_m1_setup`/`_m3_setup`/`_m5_setup` (`server_auth.py:86-217`, shared by the fake Companion device via inheritance, `FakeCompanionService(CompanionServerAuth, asyncio.Protocol)`) — the request-dispatch mechanism `getattr(self, f"_m{seqno}_{suffix}")(pairing_data)` (`server_auth.py:97`) is worth noting for anyone building a Rust hermetic test-server counterpart: it is a **dynamic method-name dispatch keyed by the incoming TLV `SeqNo` value and whether the frame type indicates verify vs. setup** — a Rust equivalent should use an explicit `match` over `(FrameType, SeqNo)` rather than attempting reflection-based dispatch, but should preserve the same effective state-machine shape (M1/M3/M5 for setup, M1/M3 for verify, with M2/M4/M6 being the *responses* this fake server sends, not separately-dispatched incoming messages — the server never receives M2/M4/M6, only M1/M3/M5, matching the client only ever sending odd-numbered SeqNo values and the server only ever sending even-numbered ones, the standard SRP-exchange parity convention).

`FakeCompanionState` (`companion.py:83-113`) models exactly the mutable server-side state a Rust hermetic test-server needs: `system_status`, `active_app`/`open_url`, `installed_apps`/`available_accounts`, `has_paired`, `powered_on` (default `True`), `sid`, `system_info` (stores the **entire** last-received `_systemInfo` content dict verbatim, not just specific fields — useful for asserting a Rust client sent the exact expected literals from §3.2), `tv_rc_protocol_version`, `latest_button`, `media_control_flags` (default `MediaControlFlags.Volume`, i.e. `0x0100` — **not** `NoControls` — meaning a freshly-constructed fake device already advertises volume control support without any explicit test setup, a detail a Rust port's own equivalent fixture should replicate if aiming for identical default test behavior), `volume` (default `INITIAL_VOLUME = 10.0`), `duration` (default `INITIAL_DURATION = 10.0`), `rti_focus_state` (default `KeyboardFocusState.Focused`), `rti_text` (default `INITIAL_RTI_TEXT = "Fake Companion Keyboard Text"`).

### 7.2 Per-command fake-device handlers — confirmed exact request/response shapes

Handler dispatch: `handler_method_name = f"handle_{unpacked['_i'].lower()}"` (`companion.py:300`) — **the identifier is lowercased before method-name construction**, so `_hidC` dispatches to `handle__hidc` (note the double underscore — one from the identifier's own leading `_`, one from the `handle_` prefix, confirmed exact against the actual method name `handle__hidc`, `companion.py:380`), `_systemInfo` → `handle__systeminfo`, `TVRCSessionStart` → `handle_tvrcsessionstart` (single leading underscore here since the identifier itself has none, confirming the general pattern `handle_` + `lower(identifier)` with no special-casing for identifiers that already start with `_` — they simply end up double-underscore method names as a byproduct). Unrecognized identifiers fall through to `send_handler_not_supported` → `send_error(request, "No request handler", code=58822)` (`companion.py:301-304,346-348`) — this is the **exact error a real device produces for `FetchAttentionState` on newer tvOS** per §3.11's discussion, confirming the fake device's default-unsupported path is deliberately reused to simulate that specific real-world behavior rather than being purely a test-harness fallback.

Response envelope shapes, confirmed exact (`companion.py:309-344`):
```python
# success
{"_i": request["_i"], "_x": request["_x"], "_t": 3, "_c": content}
# event push
{"_i": identifier, "_x": xid, "_t": 1, "_c": content}
# error
{"_i": request["_i"], "_x": request["_x"], "_t": 3, "_ec": code, "_ed": domain, "_em": message}
```
`_t: 3` for both success and error responses (Response type, per §2.1's `MessageType` table) — the presence/absence of `_em` (not the `_t` value) is what distinguishes success from error, confirming §2.1's claim about the client's own detection mechanism from the server-emission side too.

Selected handler-specific confirmations not already covered in §3:
- `handle__hidc` (`companion.py:380-412`): tracks `self._pressed_buttons: Set[HidCommand]` — a button-**up** event for a button never seen **down** produces `send_error(message, f"Missing button DOWN for {button_code}")` (**except** for `Sleep`/`Wake`, which are handled in dedicated `elif` branches **before** the general down/up-tracking logic and never touch `_pressed_buttons` at all — confirming §3.7's note that Sleep/Wake are a structurally different, up-only pathway both client- and server-side). `VolumeUp`/`VolumeDown` button-ups additionally trigger `self.volume_changed(...)`, which both mutates `self.state.volume` (clamped `[0.0, 100.0]`) and pushes an `_iMC` event with the `Volume` flag OR'd into whatever `media_control_flags` already held — confirming a volume-affecting HID button press causes an **unsolicited** `_iMC` push from the fake device, independent of the `_mcc SetVolume` path (§3.7.2) which triggers the identical `volume_changed` call through a different entry point.
- `handle__touchstart` (`companion.py:414-434`): the fake device **validates** `width`/`height` are both truthy and within `(0, 1000]` inclusive-upper (`width > 1000` is an error, but the exact boundary condition `width == 1000` is accepted, confirmed by the `or width > 1000` structure, not `>=`) — sends `send_error(message, "Invalid touchpad width or height")` if not. A Rust port's own hermetic test-server (if building one for parity testing) should replicate this exact validation, and a Rust *client* should be aware a real/faithful-fake device may reject `_touchStart` if it ever sent something other than the fixed `1000.0`/`1000.0` from §3.3 (which it never does, in practice, but the validation exists nonetheless).
- `handle__sessionstart`/`handle__sessionstop` (`companion.py:477-487`): §3.4's `5555` constant confirmed exact from this file directly, plus the composite-SID validation for stop (`message["_c"]["_sid"] == (5555 << 32 | self.state.sid)`, else `send_error(message, "Invalid SID")`).
- `handle__interest` (`companion.py:497-508`): on `_regEvents` containing `"_iMC"` specifically, **immediately** pushes an `_iMC` event with the current `media_control_flags` (`companion.py:501-504`) as part of handling the subscription request itself — i.e. subscribing to `_iMC` synchronously triggers an initial state push from the fake device, matching real-device behavior pyatv's `CompanionFeatures`/`CompanionAudio` code implicitly depends on (both classes' initial state is populated by whatever `_iMC` event arrives first, and neither performs a separate explicit "fetch current media control flags" request — subscription-triggers-initial-push is the only mechanism by which they ever learn the current flags at all).
- `handle__tistart`/`handle__tistop` (`companion.py:510-531`): both **early-return with no response sent at all** if `message["_t"] != 2` (i.e. if the incoming frame's message type is not `Request` — since these are Request-only commands from the real client's perspective, this guards against — largely hypothetically, since pyatv's own client never does this — a misdirected Event-typed `_tiStart`/`_tiStop`). `handle__tistart`'s **three-way branch** is worth precise reproduction: (1) if `self.state.rti_text is None` (a test-usecase-settable "no keyboard available" sentinel, `FakeCompanionUseCases.set_rti_text(None)`), respond with empty content `{}` and register the client in `rti_clients` anyway; (2) if `self.state.rti_session_uuid is not None` (a session is already active — i.e. a **second** `_tiStart` without an intervening `_tiStop`), log a warning and **send no response at all** (this would hang a real client's `exchange_opack` call until its 5-second timeout, since the fake device deliberately does not reply in this case — confirming this is a scenario pyatv's own client-side logic (`text_input_command`'s always-`_tiStop`-before-`_tiStart` discipline, §3.6) is specifically designed to avoid triggering); (3) otherwise, assign a **fixed literal session UUID** `b"0123456789abcdef"` (`companion.py:519` — 16 raw ASCII bytes, not a randomly generated UUID; useful as a KAT for a Rust hermetic test-server aiming for byte-identical fixture behavior against pyatv's own test suite) and respond with `self.state.rti_encoded_data` (§5's `NSKeyedArchiver` plist).
- `handle__tic` (`companion.py:533-556`): early-returns if `message["_t"] != 1` (this one **is** an Event, matching §3.6's confirmation that `_tiC` is sent via `_send_event`) or if the decoded `session_uuid` doesn't match `self.state.rti_session_uuid` (silently ignored, no error sent — since `_tiC` is an Event with no response channel at all, there is nothing to reply with regardless). `text_to_assert == ""` (note: compared against the **string** `""`, not `is not None` — meaning a `textToAssert` value that decoded to `None` via `read_archive_properties`'s missing-path fallback, versus one that decoded to the literal empty string, are treated differently: only the literal-empty-string case clears `self.state.rti_text`) triggers a clear; a non-`None` `insertion_text` triggers `self.state.rti_text += insertion_text` — **both conditions can fire in the same call** (clear-then-append, not mutually exclusive `if`/`elif`), though in practice pyatv's own client (§3.6) only ever sends one or the other per `_tiC` event, never both TLVs' worth of information (clear vs. insert) in a single call.

### 7.3 `test_companion_auth.py` — pairing functional KATs

Already fully reproduced above (95 lines). Confirmed test names and exact assertions:
- `test_pairing_with_device`: full begin→pin→finish happy path, asserts `handle.has_paired`, `state.has_paired` (the **fake device's own** paired-flag, confirming the pairing round-trip genuinely completed against the fake server, not just the client believing it succeeded), and `service.credentials is not None`.
- `test_pairing_with_existing_credentials`: pre-seeds `service.credentials = CLIENT_CREDENTIALS` (the fixed KAT string from `pyatv/auth/server_auth.py`, §7.4) **before** pairing — asserts pairing still proceeds and succeeds normally, i.e. **re-pairing with stale/pre-existing credentials already present is not blocked or short-circuited** by pyatv's own pairing-handler logic (no "already paired" fast-path exists — `CompanionPairingHandler.__init__` never inspects `core.service.credentials` at all, confirmed by re-reading `pairing.py:21-33`).
- `test_pairing_no_pin`: `begin()` then `finish()` **without** ever calling `pin()` — asserts `PairingError` (confirms §4.4's fail-fast precondition check).
- `test_pairing_with_bad_pin`: `pin(PIN_CODE + 1)` (i.e. `1112` instead of the fake server's configured `1111`) — asserts `PairingError` on `finish()`, **and** asserts `state.has_paired` is `False` and `service.credentials is None` afterward, i.e. a failed pairing attempt leaves **no partial state** on either the client's `service.credentials` or the (fake) server's paired-flag — confirming the SRP wrong-PIN detection (`hap_srp.py`'s `step2`, "proofs do not match" — already documented in both prior research docs) actually prevents the exchange from proceeding far enough to reach any credential-persistence code path, on both ends.

### 7.4 `PIN_CODE`/`CLIENT_CREDENTIALS`/`SERVER_IDENTIFIER`/`PRIVATE_KEY` — the shared KAT constants

`pyatv/auth/server_auth.py`, full 13-line file, confirmed exact:
```python
PIN_CODE = 1111
CLIENT_IDENTIFIER = "4D797FD3-3538-427E-A47B-A32FC6CF3A6A"
CLIENT_CREDENTIALS = (
    "E734EA6C2B6257DE72355E472AA05A4C487E6B463C029ED306DF2F01B5636B58:"
    + "80FD8265B0748DA90BC5C5294DABE394D3D47199994AE96AC73EE45C783537B1:"
    + "35443739374644332D333533382D343237452D413437422D41333246433643463"
    + "3413641:34443739374644332D333533382D343237452D413437422D413332464"
    + "336434633413641"
)
SERVER_IDENTIFIER = "5D797FD3-3538-427E-A47B-A32FC6CF3A6A"
PRIVATE_KEY = 32 * b"\xaa"
```
This is **shared across all three protocols' test suites** (MRP, Companion, AirPlay all import from `pyatv.auth.server_auth`), not Companion-specific, but included here in full since it is directly exercised by every Companion pairing/functional test fixture (`conftest.py:10,45`, `test_companion_auth.py:10,48,66,88`). Decoding `CLIENT_CREDENTIALS` per the four-colon-field format (`hap_pairing.py:127-146`, §4 of `hap-pairing-port-spec.md`): field 3 (`atv_id`) and field 4 (`client_id`) are both the **hex encoding of an ASCII string that is itself the `SERVER_IDENTIFIER` UUID string** — i.e. `unhexlify("35443739374644332D333533382D343237452D413437422D413332464336434633413641")` decodes to the ASCII bytes `"5D797FD3-3538-427E-A47B-A32FC6CF3A6A"` (`SERVER_IDENTIFIER` itself, hex-encoded as raw ASCII bytes rather than as a 16-byte binary UUID — confirming `HapCredentials.atv_id`/`client_id` are treated as opaque byte-strings throughout pyatv, not parsed/validated as binary UUIDs anywhere, even though in practice they're often UUID-shaped ASCII strings). `PRIVATE_KEY = 32 * b"\xaa"` is the reference server's fixed (non-random, non-ephemeral) Ed25519-seed-and-X25519-scalar, already discussed exhaustively in `hap-pairing-port-spec.md` §6 — a Rust hermetic test-server counterpart must use this exact 32-byte value (all `0xAA` bytes) to produce byte-identical server identity/ephemeral keys for cross-validation against pyatv's own fixtures.

### 7.5 `tests/support/test_opack.py` — the `_systemInfo`-shaped golden round-trip, and a bug worth flagging

The `test_golden` test (`test_opack.py:397-440`, already reproduced in full above) builds a realistic `_systemInfo`-request-shaped nested dict (top-level `_i`/`_x`/`_btHP`/`_c`/`_t` envelope, with `_c` itself containing `_pubID`/`_sv`/`_bf`/`_siriInfo`/`_stA`/`_i`/`_clFl`/`_idsID`/`_hkUID`/`_dC`/`_sf`/`model`/`name` — note this is a **richer** `_systemInfo` shape than what `CompanionAPI.system_info()` itself actually sends (§3.2), including fields (`_btHP`, `_siriInfo`, `_stA`, `_hkUID`, `_dC`) pyatv's own client never populates — this test fixture is modeling what a **real device's** `_systemInfo` payload looks like, not what pyatv's client sends, useful as a reference for what additional fields a Rust port might eventually need to parse if it ever needs to *receive* a `_systemInfo`-shaped payload rather than only send one), then asserts:
```python
packed = pack(data)
unpacked = unpack(packed)
assert DeepDiff(unpacked, data, ignore_order=True)
```
**This assertion is inverted from what the test's own name and evident intent describe.** `DeepDiff(a, b)` returns a **truthy, non-empty diff object when `a` and `b` differ**, and an **empty (falsy) object when they are equal** — `deepdiff`'s own documented API contract, and the pattern used correctly by every *other* usage of `DeepDiff` throughout pyatv's test suite (e.g. `test_companion.py:54`: `assert not DeepDiff(...)`, `test_companion_functional.py:107`: `assert not DeepDiff(expected_apps, apps)`). `test_golden`'s `assert DeepDiff(unpacked, data, ignore_order=True)` — **with no leading `not`** — therefore only passes if `unpacked` and `data` **differ**, which is the opposite of what a "pack-then-unpack should round-trip to the original" golden test should assert. **This is a real, confirmed bug in pyatv's own test suite** (not a porting-ambiguity — the fix is unambiguous: it should read `assert not DeepDiff(...)`), independently discoverable by anyone running this exact test and inspecting whether it would actually catch a broken round-trip (it would not — a completely broken `pack`/`unpack` pair that always returns `unpacked != data` would make this test **pass**, and a perfectly correct pack/unpack pair would make it **fail**, unless the `_siriInfo.sharedDataProtoBuf` field — 512 raw `\x08` bytes — or one of the specific value types present (nested dict, `UUID`, list-of-`UUID`, large `bytes` blob) happens to trip some other pre-existing round-trip bug in pyatv's OPACK implementation that makes the two objects *genuinely* differ after round-tripping, which would then make this inverted assertion pass "for the wrong reason"). **A Rust port must not port this test's assertion polarity** — write the equivalent Rust golden-vector test as "pack then unpack round-trips back to the original structure" (the evidently intended behavior, consistent with every other OPACK round-trip expectation in this document and in `mrp-companion.md`'s own description of OPACK), not as "pack then unpack produces something different," and should independently verify with a corrected assertion whether pyatv's real OPACK implementation actually does round-trip this exact golden fixture correctly or not — this task's research pass did not execute the Python test suite to determine which case it is, only read the source and identified the assertion-polarity defect by static inspection; **flagged as an open question requiring dynamic verification before the Rust port's own OPACK crate treats this specific fixture as ground truth**, since it's currently ambiguous whether pyatv's OPACK actually handles this exact shape correctly.

### 7.6 `test_companion_interface.py`/`test_companion_scan.py`/`test_companion.py` — smaller confirmations

- `test_companion_interface.py` (61 lines, already reproduced): confirms `CompanionKeyboard._handle_text_input`'s focus-state dispatch is keyed purely on **presence of `_tiD` in the event data dict**, not on the event name (`"_tiStarted"` with `{"_tiD": b""}` → `Focused`; `"_tiStopped"` with `{}` → `Unfocused`) — i.e. even an empty-bytes `_tiD` value (falsy in a boolean sense, but still a **present key**) counts as "focused" per `"_tiD" in data` (`__init__.py:505-511`), not `data.get("_tiD")` truthiness. A Rust port's equivalent check must be "key present" (`.contains_key(...)` / pattern-match on `Some`, including `Some(empty)`), not "value truthy."
- `test_companion_scan.py` (68 lines): confirms Companion mDNS-scan alone never yields a discoverable device (`test_multicast_scan_companion_device`: `len(atvs) == 0`) — Companion has no unique identifier of its own in its mDNS advertisement and can only be attached to a device already discovered via another protocol (MRP in the test, `test_multicast_scan_mrp_with_companion`) that shares the same address; **and confirms unicast/host-scan also yields zero results for a bare Companion service** (`test_unicast_scan_comapnion`, `len(atvs) == 0` — note the test function's own name has a typo, `comapnion`, in pyatv's source itself, harmless but worth knowing if grepping for this test by name later). A Rust port's scan/merge logic must replicate this "Companion never anchors a device identity on its own" behavior — confirmed exact, not previously stated this explicitly in `mrp-companion.md`.
- `test_companion.py`: already covered in §4.5 (pairing-requirement worked examples) and confirms `device_info()`'s `rpmd`-driven model lookup separately (`DeviceModel.Gen4K` for `"AppleTV6,2"`, `DeviceInfo.RAW_MODEL` always set regardless of whether the model string is recognized).

---

## 8. `SUPPORTED_FEATURES`, `MEDIA_CONTROL_MAP`, and the `Features`/`Relayer` facade mapping

`__init__.py:106-157`, confirmed exact:

```python
class MediaControlFlags(IntFlag):
    NoControls = 0x0000
    Play = 0x0001
    Pause = 0x0002
    NextTrack = 0x0004
    PreviousTrack = 0x0008
    FastForward = 0x0010
    Rewind = 0x0020
    # ? = 0x0040
    # ? = 0x0080
    Volume = 0x0100
    SkipForward = 0x0200
    SkipBackward = 0x0400

MEDIA_CONTROL_MAP = {
    FeatureName.Play: MediaControlFlags.Play,
    FeatureName.Pause: MediaControlFlags.Pause,
    FeatureName.Next: MediaControlFlags.NextTrack,
    FeatureName.Previous: MediaControlFlags.PreviousTrack,
    FeatureName.Volume: MediaControlFlags.Volume,
    FeatureName.SetVolume: MediaControlFlags.Volume,
    FeatureName.SkipForward: MediaControlFlags.SkipForward,
    FeatureName.SkipBackward: MediaControlFlags.SkipBackward,
}
```
Note bits `0x0040`/`0x0080` are explicitly commented as unknown gaps in pyatv's own source (`__init__.py:97-98`) — real devices' `_mcF` values may set these bits, and pyatv simply ignores them (no `FeatureName` maps to them). `FastForward`/`Rewind` bits (`0x0010`/`0x0020`) exist in the flag enum but have **no corresponding `MEDIA_CONTROL_MAP` entry at all** — i.e. even if a device advertises fast-forward/rewind support via `_iMC`, pyatv's `CompanionFeatures.get_feature()` has no `FeatureName` that would ever report `Available` as a result (there is no `FeatureName.FastForward`-equivalent wired to this bit anywhere in `__init__.py`) — a real gap in pyatv's own feature surface, not a porting omission to silently "fix" without a deliberate product decision.

`CompanionFeatures.get_feature()` (`__init__.py:591-611`) resolution order, confirmed exact: (1) if `feature_name in MEDIA_CONTROL_MAP`, `Available` iff the corresponding bit is set in the last-received `_mcF` value (default `MediaControlFlags.NoControls` until the first `_iMC` event arrives — confirmed by `self._control_flags = MediaControlFlags.NoControls` at `__init__.py:584`, **not** the fake-device-default `Volume` bit from §7.1, which is a test-fixture-only default, not a client-side assumption); (2) if `feature_name == FeatureName.PowerState`, delegate to `CompanionPower.supports_power_updates` (itself `self._power_state is not PowerState.Unknown`, i.e. becomes `True` only after either a successful initial `fetch_attention_state()` or a first pushed `SystemStatus`/`TVSystemStatus` event, §3.11); (3) else if `feature_name in SUPPORTED_FEATURES`, unconditionally `Available` ("we don't have any way to verify it anyways", `__init__.py:606-609` comment — this is an honest admission that most of `SUPPORTED_FEATURES` is asserted, not measured); (4) else `Unavailable`.

`SUPPORTED_FEATURES` (`__init__.py:117-157`), confirmed exact full listing — apps (`AppList`, `LaunchApp`), accounts (`AccountList`, `SwitchAccount`), power (`PowerState`, `TurnOn`, `TurnOff` — note `PowerState` is listed in `SUPPORTED_FEATURES` **and** separately special-cased in branch (2) above; the special-case branch takes priority since it's checked first, so `PowerState`'s membership in the plain set is actually **dead** for resolution purposes, only relevant if `CompanionFeatures` were ever constructed without a `power` argument, which never happens in practice — worth noting for a Rust port that might otherwise wonder why `PowerState` appears in both places), D-pad (`Up`/`Down`/`Left`/`Right`/`Select`/`Menu`/`Home`), volume buttons (`VolumeUp`/`VolumeDown` — **note**: **not** `FeatureName.Volume`/`SetVolume`, those come from `MEDIA_CONTROL_MAP` instead, a different feature axis: "hardware volume buttons" vs. "absolute volume level get/set", both ultimately routed to `HidCommand.VolumeUp/Down` vs. `MediaControlCommand.GetVolume/SetVolume` respectively per §3), `PlayPause`, channel (`ChannelUp`/`ChannelDown`), `Screensaver`, `Guide`, `ControlCenter`, keyboard (`TextFocusState`/`TextGet`/`TextClear`/`TextAppend`/`TextSet`), touch (`Swipe`/`Action`/`Click`) — **plus** every key in `MEDIA_CONTROL_MAP` appended via `+ list(MEDIA_CONTROL_MAP.keys())` (`__init__.py:155-157`), meaning `Play`/`Pause`/`Next`/`Previous`/`Volume`/`SetVolume`/`SkipForward`/`SkipBackward` are members of `SUPPORTED_FEATURES` **too**, but since branch (1) of `get_feature()` intercepts any `MEDIA_CONTROL_MAP` member before branch (3) is ever reached, their presence in `SUPPORTED_FEATURES` is — again — dead for resolution purposes; it exists only because `SUPPORTED_FEATURES` is also consumed elsewhere as the crate-wide "what features does this protocol claim at all, regardless of live state" registration set (passed to `SetupData(..., SUPPORTED_FEATURES)`, `__init__.py:695-702`, which is how pyatv's cross-protocol `Relayer<T>` priority/registration system, per `mrp-companion.md`/`ARCHITECTURE.md`'s design-invariant notes, learns which protocols to even consult for a given `FeatureName`).

### 8.1 Facade class → API method mapping table

| Facade class | Interface | Backing `CompanionAPI` calls |
|---|---|---|
| `CompanionApps` | `Apps` | `app_list()` → `FetchLaunchableApplicationsEvent`; `launch_app()` → `_launchApp` |
| `CompanionUserAccounts` | `UserAccounts` | `account_list()` → `FetchUserAccountsEvent`; `switch_account()` → `SwitchUserAccountEvent` |
| `CompanionPower` | `Power` | `turn_on/off()` → `_hidC` Wake/Sleep; `power_state` ← `FetchAttentionState` + `SystemStatus`/`TVSystemStatus` events |
| `CompanionRemoteControl` | `RemoteControl` | D-pad/menu/home/volume/play-pause/channel/screensaver/guide/control-center → `_hidC`; play/pause/next/previous/skip → `_mcc` |
| `CompanionAudio` | `Audio` | `set_volume()`/`volume_up()`/`volume_down()` → `_mcc`(`SetVolume`)/`_hidC`(Volume Up/Down), gated on `_iMC` event round-trip |
| `CompanionKeyboard` | `Keyboard` | `text_get/clear/append/set()` → `_tiStop`+`_tiStart`+optional `_tiC` events, decoded via `keyed_archiver` |
| `CompanionTouchGestures` | `TouchGestures` | `swipe()`/`action()`/`click()` → `_hidT` events (+ `_hidC` Select for `click()`) |
| `CompanionFeatures` | `Features` | Pure local state resolution (§8), no direct wire calls of its own beyond the `_iMC` subscription already established by `CompanionAPI.connect()` |

`setup()` (`__init__.py:663-702`) — confirmed the **guard clause**: `if not core.service.credentials: ... return None` (`__init__.py:665-668`) — Companion is **entirely skipped** as a protocol (no `SetupData` yielded at all, not even a disabled/inert one) if no credentials are stored, meaning a Rust port's protocol-registration logic must treat "Companion with no credentials" as "Companion does not exist for this connection," not as "Companion exists but every call will fail" — this matches the general HAP-pairing-required-before-any-use model but is worth being explicit about since it affects `Relayer<T>` registration timing (a device only gains a Companion capability entry in the registry *after* successful pairing, never before, and the registry entry's absence-vs-presence is itself how pyatv signals "not paired" at the facade layer, rather than a runtime error raised from inside a paired-but-broken connection attempt).

---

## 9. `pyatv/protocols/companion/server_auth.py` — full reference server, for hermetic test-server parity

Already reproduced above in full (229 lines). Key facts beyond what §4.2/§7.1/§7.4 already extracted:

- `new_server_session(keys, pin)` (`server_auth.py:47-71`): constructs **two** separate `SRPContext` objects — one (`context`, with the PIN as password) purely to derive `(username, verifier, salt)` via `get_user_data_triplet()`, then a **second** `context_server` (no password argument at all — `SRPContext` without a `password` kwarg, since the server-side session doesn't need the plaintext password, only the pre-computed verifier) used to actually construct the `SRPServerSession(context_server, verifier, binascii.hexlify(keys.auth).decode())`. The third positional argument to `SRPServerSession` is the server's own **long-term private key** (`keys.auth`, i.e. the Ed25519 signing key's raw private bytes, reused here as an SRP-unrelated seed value analogous to the client's own seed-reuse quirk documented in `hap-pairing-port-spec.md` §6) — hex-encoded before passing to the `srptools` API, consistent with that library's hex-string convention used throughout.
- The server-side pairing state machine's `_m1_verify`/`_m3_verify`/`_m1_setup`/`_m3_setup`/`_m5_setup` methods are the **direct mirror** of the client-side `hap_srp.py`/`companion/auth.py` flow already documented exhaustively in `hap-pairing-port-spec.md` — this document does not re-derive that mirror image, only flags (§4.2) the one client-invisible detail (tag-27 TLV) that a straight read of the client-only files would miss.
- `CompanionServerAuth.__init__(device_name, unique_id=SERVER_IDENTIFIER, pin=PIN_CODE)` (`server_auth.py:77-84`) — defaults wire the shared KAT constants (§7.4) in directly; `FakeCompanionService.__init__` (`companion.py:230-233`) calls `super().__init__(DEVICE_NAME)` with **only** the `device_name` positional argument (`DEVICE_NAME = "Fake Companion ATV"`, `companion.py:24`), relying on `unique_id`/`pin`'s defaults — i.e. the fake device's identity/PIN in the whole test suite is always exactly `SERVER_IDENTIFIER`/`PIN_CODE` from `pyatv/auth/server_auth.py`, never overridden per-test.
- `_m5_setup`'s hardcoded `other` dict (`server_auth.py:190-197`: `altIRK`, `accountID`, `model: "AppleTV6,2"`, `wifiMAC`, `name: "Living Room"`, `mac`) is packed via `opack.pack(other)` and stored under **raw TLV tag `17`** (decimal, `= 0x11 = TlvValue.Name`) in the M6 response — **this is the same tag number as the client-only-used `Name` TLV (§4.3), but here it is the *server* populating it in its M5→M6 response, with a completely different payload shape** (a multi-key device-info dict, not a single `{"name": ...}` dict) — confirming `TlvValue.Name` (`0x11`) is overloaded/reused for "arbitrary OPACK-encoded auxiliary data" in both directions, not strictly a display-name-only field by protocol convention, even though pyatv's own *client* only ever uses it for the display name. **A Rust port's client-side pairing code does not need to parse this M6 `Name`/`17` field from a real device's response at all** (pyatv's own client never reads it — `step4` in `hap_srp.py` only extracts `Identifier`/`Signature`/`PublicKey` from the M6 TLV, confirmed already in both prior research docs) — this is purely test-fixture-side color pyatv's fake device emits to look more like a real accessory's M6 response, useful only if a Rust port later wants a hermetic test-server counterpart with equivalent fixture realism, not required for basic client interop.

---

## 10. `keyed_archiver.py`/plist round-trip — Rust crate implications (cross-reference to `mrp-companion.md` §5's crate table)

`mrp-companion.md` §5 already lists the `plist` crate (1.10.0 at time of that research) as a candidate and flags the open question of whether it supports `NSKeyedArchiver` UID-reference-following out of the box. This document's read of `keyed_archiver.py` (§5) and `plist_payloads/rti_text_operations.py` (§6) sharpens that open question into a concrete, bounded scope: pyatv itself never needs (a) general `NSKeyedArchiver` *decoding* (only "follow this exact list of UID-reference paths, tolerate missing ones") nor (b) general `NSKeyedArchiver` *encoding* (only "emit these two exact fixed byte-templates with two substitution points"). A Rust port has no protocol-correctness reason to implement a general-purpose `NSKeyedArchiver` codec for Companion — it only needs: (1) a binary-plist parser that exposes `$top`/`$objects` and a first-class "this value is a UID/back-reference" type (most plist crates that support Apple's binary plist format at all should expose UID as a distinct value variant, since it's part of the base `bplist00` type-tag space, not an `NSKeyedArchiver`-specific extension — verify this against whichever crate is chosen, since `mrp-companion.md`'s open-questions section flagged this as unconfirmed); (2) a small hand-written path-following reader mirroring `read_archive_properties` exactly (§5); (3) two hand-written byte-template encoders mirroring `get_rti_clear_text_payload`/`get_rti_input_text_payload` exactly (§6), constructed via whatever plist-serialization API the chosen crate exposes for building a `$version`/`$archiver`/`$top`/`$objects`-shaped binary plist with explicit UID values at explicit array positions — **not** via any higher-level "serialize this Rust struct as a keyed-archived object graph" abstraction, since pyatv's own reference implementation deliberately avoids exactly that kind of general encoder and a Rust port aiming for pyatv-parity should not build one either, only for the two fixed shapes actually used.

---

## 11. Cross-reference: differences from `mrp-companion.md` §4 confirmed correct (no corrections needed)

For completeness, the following claims in `mrp-companion.md` §4 were independently re-verified against source during this research pass and are **confirmed exact, no correction required**:
- §4.2 frame header layout, `FrameType` enum full listing (value `2` gap included), AAD = 4-byte header.
- §4.3 `_pd`/`_pwTy`(pair-setup)/`_auTy`(pair-verify) framing and the `*_Start`-response-is-always-`*_Next` quirk.
- §4.4 `SRP_SALT = ""`, `SRP_OUTPUT_INFO = "ClientEncrypt-main"`, `SRP_INPUT_INFO = "ServerEncrypt-main"`, and the plain-12-byte-counter nonce claim.
- §4.6 envelope key table (`_i`/`_t`/`_c`/`_x`/`_em`) — this document's §2.1 adds the previously-undocumented `_ec`/`_ed` fields and the `_x`-on-events wire-vs-dispatch nuance, but does not contradict anything §4.6 already stated.
- §4.7 session bring-up order (`system_info` → `_touch_start` → `_session_start` → `_tv_rc_session_start` → `_text_input_start` → `subscribe_event("_iMC")`) and the `_iMC`/`MediaControlFlags` gating description — confirmed exact; this document's §3.1-3.11 supersede §4.7 only in level of detail (exact payloads, exact response shapes), not in any factual correction.
- §4.8 `HidCommand`/`MediaControlCommand`/`SystemStatus` enum values — all confirmed byte-exact; this document's §3.7/§3.8 add the previously-undocumented facade-reachability table (which values are actually ever sent by pyatv's own client) and the exact down/up/hold timing.

No corrections to `mrp-companion.md` §4 were needed beyond the additions above — that section's Companion coverage was already accurate at the level of detail it targeted. This document exists to go one level deeper (exact payloads, response shapes, the full test-fixture behavior, and the pairing-framing details `hap-pairing-port-spec.md` §9.2 references but doesn't fully spell out for Companion specifically), not to fix errors in the existing report.

### 11.1 Correction to this task's own framing

As flagged in §4.2: the premise that TLV tag `0x1B` might be a `"Name"`/`"additional_data"` TLV is incorrect. `Name` is `0x11` (confirmed both client- and server-side, §4.3 and §9). Tag `27`/`0x1B` is a distinct, unnamed, server-only, client-ignored TLV with no documented purpose anywhere in pyatv (§4.2). Also: the TXT-record key governing pairing requirement is `rpfl` (lowercase, confirmed both in production code and test fixtures), not `rpFl` — §4.5.

---

## 12. Divergences, open questions, and explicit decisions the Rust port must make

1. **Undefined frame types (`NoOp`, `PA_Req`/`PA_Rsp`, `SessionStart*`/`SessionData`, `FamilyIdentity*`) have zero payload-shape documentation anywhere in pyatv** (§1.2). pyatv's client never constructs or parses any of them. Decide: mirror pyatv exactly (never send them, silently ignore if received — the current behavior by omission) or invest in independent reverse-engineering. Recommendation: mirror pyatv for the initial port (this is what "behavioral parity with pyatv" as stated in `CLAUDE.md`'s charter means), track as a documented gap, revisit only if a real-device capture shows these frame types in active use for the remote-control use case pyatv itself targets.

2. **No maximum frame size is enforced by pyatv's decoder** (§1.1) — a hostile or corrupted 3-byte length field can claim up to ~16MB for a single frame with nothing checking that against any sane bound before buffering. A Rust port should decide deliberately whether to add a sanity cap (recommended: yes, for a network-facing decoder, even though this diverges from pyatv's own unguarded behavior — this is exactly the kind of case `CLAUDE.md`'s "warn and propose alternatives" threshold calls for, since pyatv itself doesn't need this hardening as much given Python's different failure-mode characteristics for over-large allocations).

3. **XID width is unbounded in pyatv (arbitrary-precision Python int, no wraparound)** (§2.2). A Rust port must pick a concrete integer width (`u32` recommended, matching the reference server's own presumed range and giving ~4 billion in-flight-exchange headroom before wraparound) and decide wraparound behavior (recommended: wrapping increment, since OPACK's variable-width int encoding tolerates any magnitude but a real Rust `HashMap<XidType, _>`-based correlation table needs a concrete key type).

4. **The `_skpS` "must be float, not int, because OPACK fails on negative integers" workaround** (§3.8) needs independent verification against whatever Rust OPACK encoder this port builds: does the from-scratch Rust implementation actually have the same defect, or was this a `pyatv`-specific encoder limitation that doesn't need replicating? If the Rust OPACK encoder correctly round-trips negative integers, this workaround becomes unnecessary noise (though sending a `float` where pyatv sends a `float` is harmless either way for wire compatibility with real devices, so there's no interop reason to remove it even if unnecessary) — flagged as a design decision, not a mandatory replication, unlike most of this document's "replicate exactly" guidance.

5. **`test_golden`'s inverted `DeepDiff` assertion** (§7.5) makes it genuinely unclear, from static reading alone, whether pyatv's OPACK implementation correctly round-trips the specific golden fixture shape (nested dicts, `UUID`, list-of-`UUID`, 512-byte raw-bytes blob, mixed int/float/bool/string values). **This requires dynamically running pyatv's own test suite** (`cd /tmp/pyatv-ref && python -m pytest tests/support/test_opack.py -k test_golden -v` or equivalent, with the assertion's actual pass/fail behavior inspected, ideally by also manually correcting the assertion locally and re-running) before treating this fixture as a trustworthy Rust golden-vector test input. Do not port the assertion polarity as-is.

6. **Companion pairing's `finish()` does not immediately pair-verify the fresh credentials** (§4.4), unlike MRP. A Rust port must decide: match pyatv's weaker guarantee (recommended for parity — a Rust client reporting "paired" in exactly the same real-world scenarios pyatv does, no more no less, is safer for behavioral-parity testing against real devices) or add a stricter immediate-verify step (a reasonable independent improvement, but changes observable success/failure behavior relative to pyatv and should be a named, deliberate deviation if chosen, not an incidental one).

7. **No heartbeat/keepalive exists at the Companion transport layer** (§1.5, §2.4) — contrast AirPlay's mandatory 2-second `FEEDBACK` cadence. If real-device Companion connections are observed to time out or drop after some idle period in practice, that would be new research (a live-device capture), not something derivable from pyatv's source, since pyatv itself apparently never needed one (or never noticed if it did — Companion connections in pyatv's own usage pattern are typically kept busy by user-driven remote-control traffic, which may simply never go idle long enough in practice for this gap to matter).

8. **`FastForward`/`Rewind` `MediaControlFlags` bits have no corresponding `FeatureName`/facade surface at all in pyatv** (§8), and `MediaControlFlags` bits `0x0040`/`0x0080` are entirely unexplained even by pyatv's own source comments. A Rust port should decide whether to add first-class fast-forward/rewind remote-control methods (a genuine feature gap in pyatv, not merely an unported detail) as an intentional improvement, understanding this goes beyond "port pyatv's behavior" into "extend it" — a decision `CLAUDE.md`'s "ask before implementing" threshold likely applies to if scope is unclear, though it may also simply be deferred to a later milestone given `SkipBy`'s `MediaControlCommand.FastForwardBegin`/`FastForwardEnd`/`RewindBegin`/`RewindEnd` values already exist and are trivially wireable once a product decision is made.

9. **`is_url_or_scheme`'s exact grammar** (§3.10) needs a bespoke small Rust helper mirroring Python's `urlparse` scheme-extraction behavior — do not reach for the `url` crate's full `Url::parse` as a drop-in, since it rejects inputs Python's looser `urlparse` accepts (bare `scheme:` with no authority). Write and test this helper against a table of inputs pyatv would classify as "has a scheme" (bundle IDs like `com.apple.TVMusic` must classify as *not* having a URL scheme, despite containing dots — `urlparse("com.apple.TVMusic")` returns an empty `scheme` since there's no `:` at all, confirming bundle IDs are safe, but anything containing a literal `:` needs care, e.g. a bundle id that somehow contained a colon would misclassify, though this is not a realistic bundle-id shape in practice).

10. **Tag-27 (`0x1B`) TLV's actual meaning is unknown** (§4.2) — pyatv gives no interpretive guidance at all. If a Rust port ever wants to interpret (not just tolerate) this field from real device M2 responses, that requires new reverse-engineering (a real-device capture comparing behavior with the byte present vs. absent/different), not something derivable from pyatv's source.

11. **The `Name`/`0x11` TLV's server-response overload** (§9): pyatv's client never reads it, so this document cannot confirm what a real device actually sends there (the fake device's `other` dict, §9, is pyatv's own test author's guess at realistic shape, not a captured real value) — if a Rust port ever wants client-side parsing of this field (e.g. to learn `accountID`/`model`/`name` about the paired device from its own M6 response, which would be a genuinely useful capability pyatv itself never exploits), that also requires a real-device capture to confirm the actual field shape, not just pyatv's test-fixture guess.

12. **No maximum-frame-size / resource-exhaustion hardening anywhere in pyatv's Companion stack** generally (frame buffering, `_queues` dict with no eviction/expiry beyond the per-exchange timeout, no cap on concurrent in-flight XIDs) — standard "don't blindly port a reference client's lack of defensive limits into a hardened Rust implementation" caveat, consistent with `rust-core-logic` skill guidance on structured error handling and resource bounds; not specific to Companion, called out here only because this document's line-by-line reading surfaced several concrete unguarded spots (§1.1, item 2 above; the `_queues` dict itself never expires stale non-timing-out entries if a caller abandons a `SharedData().wait()` early via cancellation — verify this isn't a slow leak in long-lived Rust connections even though it's presumably fine in pyatv's own short-lived-per-`asyncio.Task` usage pattern).
