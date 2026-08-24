# HAP pairing subsystem: byte-level port specification

Ground truth: `/tmp/pyatv-ref`, commit `b277a4c8` (pyatv `master`). Every claim below is cited as `path:line-range` relative to that checkout's root. This document is the byte-level companion to `docs/research/crypto-pairing.md` (referred to below as "the research report"); read that first for the wire-protocol/crate-selection framing. This document exists to let an engineer port the HAP pairing/verify/transport stack without re-reading pyatv source, and to pin down every place the research report is imprecise or wrong.

Where the vendored `srptools==1.0.1` sdist at `/tmp/srptools-1.0.1` was available, its source is cited directly (path relative to that checkout, prefixed `srptools:`) — this is the actual dependency pyatv installs (`requirements/base.txt` pins `srptools`), not a guess about SRP library internals.

All Python excerpts below are copied verbatim from the cited lines; do not re-derive arithmetic from memory when porting — copy the excerpt, translate types, and write a KAT against it.

## 0. Executive orientation

Five files carry essentially all the logic:

- `pyatv/auth/hap_tlv8.py` — TLV8 codec + all tag/method/state/error constants.
- `pyatv/auth/hap_srp.py` — `SRPAuthHandler`: the HAP-profile SRP6a engine, Ed25519/X25519 key handling, HKDF derivations, pair-setup M1–M6 and pair-verify M1–M4 message bodies.
- `pyatv/auth/hap_pairing.py` — `HapCredentials`, `AuthenticationType`, credential string (de)serialization, the `PairSetupProcedure`/`PairVerifyProcedure` ABCs.
- `pyatv/auth/hap_session.py` + `pyatv/auth/hap_channel.py` — the **AirPlay-only** post-verify transport framing (1024-byte frames). MRP and Companion do **not** use this — see §4.0, a correction to the research report.
- `pyatv/auth/server_auth.py` + the three `pyatv/protocols/{mrp,companion,airplay}/server_auth.py` — the reference server (accessory) implementation pyatv's own test suite runs against, with fixed test constants (PIN, identifiers, private key) that make hermetic hand-computed KATs possible.

Two more files matter for the non-HAP path:

- `pyatv/protocols/airplay/srp.py` — `LegacySRPAuthHandler`/`AtvSRPContext`, the pre-HAP AirPlay 1 SRP-6a+AES-CTR/GCM device-auth profile. Genuinely different math, different session key, different signed payloads.
- `pyatv/protocols/airplay/auth/{__init__.py,hap.py,hap_transient.py,legacy.py}` — per-transport glue and `AuthenticationType` dispatch.

## 1. `pyatv/auth/hap_tlv8.py` — TLV8 codec

Full file: `pyatv/auth/hap_tlv8.py:1-158`.

### 1.1 `TlvValue` (`pyatv/auth/hap_tlv8.py:13-34`)

```python
class TlvValue(IntEnum):
    # Standardized keys
    Method = 0x00
    Identifier = 0x01
    Salt = 0x02
    PublicKey = 0x03
    Proof = 0x04
    EncryptedData = 0x05
    SeqNo = 0x06
    Error = 0x07
    BackOff = 0x08
    Certificate = 0x09
    Signature = 0x0A
    Permissions = 0x0B
    FragmentData = 0x0C
    FragmentLast = 0x0D

    # Apple internal(?)
    Name = 0x11
    Flags = 0x13
```

Note the gap: `0x0E`/`0x0F`/`0x10`/`0x12` are unassigned in pyatv (the HAP spec defines `0x0E` = Separator for list-pairing, which pyatv never emits/consumes and does not model — port note: if `ListPairing`/multi-item TLV lists are ever implemented, `Separator = 0x0E` must be added; pyatv has no code path that needs it today). `0x13` (`Flags`) only ever carries one bit in practice (§1.2). There is also an **undocumented raw tag `27` (0x1B)** used by the Companion server reference implementation in the pair-setup M2 response — not in this enum at all; see §5.2, it does not appear anywhere in the client code, only the accessory-role reference implementation, and pyatv makes no attempt to interpret it.

### 1.2 `Flags` (`pyatv/auth/hap_tlv8.py:37-40`)

```python
class Flags(IntEnum):
    TransientPairing = 0x10
```

Only ever set as a **single TLV entry of the raw `Flags` tag (`0x13`)**, one byte, big-endian-encoded via `int.to_bytes(Flags.TransientPairing.value, 1, byteorder="big")` (`pyatv/protocols/airplay/auth/hap_transient.py:54-56`; endianness is moot for a 1-byte value). Used **only** by the AirPlay transient pair-setup M1 (§6.5); MRP and Companion never set this flag anywhere in the codebase (verified: `grep -rn "TransientPairing" pyatv/` returns exactly this one call site plus the enum definition and the `hap_tlv8.py` docstring).

### 1.3 `ErrorCode` (`pyatv/auth/hap_tlv8.py:43-52`)

```python
class ErrorCode(IntEnum):
    Unknown = 0x01
    Authentication = 0x02
    BackOff = 0x03
    MaxPeers = 0x04
    MaxTries = 0x05
    Unavailable = 0x06
    Busy = 0x07
```

### 1.4 `Method` (`pyatv/auth/hap_tlv8.py:55-63`)

```python
class Method(IntEnum):
    PairSetup = 0x00
    PairSetupWithAuth = 0x01
    PairVerify = 0x02
    AddPairing = 0x03
    RemovePairing = 0x04
    ListPairing = 0x05
```

`AddPairing`/`RemovePairing`/`ListPairing`/`PairSetupWithAuth` are declared but **never used anywhere** in pyatv (verified: no reference outside this enum and `stringify`). Only `PairSetup` (`b"\x00"`, sent literally as the TLV value in every pair-setup M1, e.g. `pyatv/protocols/mrp/auth.py:42`) is actually transmitted; `PairVerify` is never transmitted either — pair-verify messages never include a `Method` TLV at all (the state machine is inferred from `SeqNo` alone, see §6).

### 1.5 `State` (`pyatv/auth/hap_tlv8.py:66-74`)

```python
class State(IntEnum):
    M1 = 0x01
    M2 = 0x02
    M3 = 0x03
    M4 = 0x04
    M5 = 0x05
    M6 = 0x06
```

Used as the value of the `SeqNo` TLV, always encoded as a **single raw byte** in pyatv's own writers (`b"\x01"`, `b"\x02"`, ...) — never actually the multi-byte little-endian form the decoder (`stringify`, §1.7) theoretically supports; the multi-byte path only matters when *reading* a value that could in principle be longer.

### 1.6 `read_tlv` / `write_tlv` (`pyatv/auth/hap_tlv8.py:77-123`)

```python
def read_tlv(data: bytes):
    def _parse(data, pos, size, result=None):
        if result is None:
            result = {}
        if pos >= size:
            return result
        tag = int(data[pos])
        length = data[pos + 1]
        value = data[pos + 2 : pos + 2 + length]
        if tag in result:
            result[tag] += value  # value > 255 is split up
        else:
            result[tag] = value
        return _parse(data, pos + 2 + length, size, result)
    return _parse(data, 0, len(data))


def write_tlv(data: dict):
    tlv = b""
    for key, value in data.items():
        tag = bytes([int(key)])
        length = len(value)
        pos = 0
        while pos < len(value):
            size = min(length, 255)
            tlv += tag
            tlv += bytes([size])
            tlv += value[pos : pos + size]
            pos += size
            length -= size
    return tlv
```

Exact semantics, byte-for-byte, to replicate:

- Entry layout: `1-byte tag | 1-byte length (0..=255) | length bytes of value`. No version/magic, no nesting (module docstring `pyatv/auth/hap_tlv8.py:3-4` states this explicitly: "this implementation only supports one level of value, i.e. no dicts in dicts").
- **Fragmentation**: a value longer than 255 bytes is written as consecutive entries under the **same tag**, each chunk exactly 255 bytes except the final (possibly shorter, possibly empty-looking but never actually zero unless the total length is an exact multiple of 255 — see the boundary case below) remainder chunk. `read_tlv` re-joins same-tag runs by `+=` concatenation (`hap_tlv8.py:94-95`) — it is **not** aware of fragmentation as a distinct concept; it just accumulates any repeated tag it encounters. **Corollary the research report did not spell out**: pyatv's TLV8 reader is not "segment-aware", it is "same-tag-adjacent-or-not accumulator". If two logically distinct entries with the same tag were ever placed non-adjacently by a well-behaved encoder they would still get merged by this reader; pyatv's own encoder never does this (it emits one tag's fragments back-to-back, `hap_tlv8.py:109-122` iterates `dict.items()` once per logical key), so in practice this is safe, but a Rust decoder that wants strict correctness should document that it trusts the *encoder's* contiguity guarantee rather than deriving contiguity from the wire format itself.
- **256-byte-exact boundary case**: if `len(value) == 255` exactly, the `while pos < len(value)` loop runs exactly once producing one 255-byte entry — **no trailing zero-length entry is emitted**. If `len(value) == 510` (two full 255-byte chunks), two 255-byte entries are emitted, again no zero-length trailer. A zero-length final fragment is only ever emitted if `len(value)` is a multiple of 255 **and** you keep going past that — but the loop condition `pos < len(value)` means it stops exactly when `pos == len(value)`, so **a multiple-of-255 length never produces a spurious trailing empty chunk**. Verified directly against the test fixture `LARGE_KEY_IN`/`LARGE_KEY_OUT` in §1.8 (256 bytes → 255 + 1, not 255 + 255 + 0).
- **Zero-length value bug** (not called out in the research report): if `value == b""`, `while pos < len(value)` (`0 < 0`) is `False` immediately — **the tag is not written at all**. `write_tlv({TlvValue.Error: b""})` produces `b""`, not `b"\x07\x00"`. Anywhere pyatv (or a Rust port) might want to signal "present but empty" (there is no such use today — `Error` values are always 1 byte, `SeqNo` always 1 byte, etc. — but a generic TLV8 encoder used elsewhere must not assume round-tripping an empty `bytes` value works). **A Rust port choosing to be "more correct" than pyatv here (i.e. emitting a genuine `tag,0x00` entry for empty values) will diverge from pyatv's own wire behavior and should not do so if byte-exact interop with pyatv-family accessories/controllers is a goal** — replicate the omission.
- `write_tlv` iterates `data.items()` in **insertion order** (a plain `dict` in Python 3.7+ is ordered) — the wire order of a multi-tag TLV blob is caller-controlled dict-construction order, not tag-numeric order. Every call site in pyatv constructs its dict literal in the exact order it wants on the wire (e.g. `{TlvValue.SeqNo: ..., TlvValue.PublicKey: ..., TlvValue.Proof: ...}` at `pyatv/protocols/mrp/auth.py:60-64`). A Rust port must use an **order-preserving map** (e.g. `Vec<(Tag, Vec<u8>)>` or `IndexMap`), not a `BTreeMap`, or the wire bytes will differ from pyatv's even though the semantic content is identical — this matters for byte-exact KATs and possibly for picky real accessories that parse positionally.
- `read_tlv` returns `Dict[int, bytes]` (tag → possibly-concatenated value); nothing in pyatv validates that the same 2-byte tag+length header appears validly-bounded — a truncated/malformed blob (`pos + 2 + length > size`) will silently slice past the end and Python's slicing just returns a short `bytes` (no exception). **A Rust port must decide deliberately whether to error on truncation**; pyatv does not.

### 1.7 `stringify` (`pyatv/auth/hap_tlv8.py:126-158`, debug/log-only, not wire format)

Not part of the wire protocol, only used for `_LOGGER`/exception messages (e.g. `_get_pairing_data`'s `exceptions.AuthenticationError(stringify(tlv))` at `pyatv/protocols/mrp/auth.py:20-22`), but worth porting for parity of error messages: `Method`, `SeqNo`, `Error` values are decoded **little-endian** via `int.from_bytes(value, byteorder="little")` (`hap_tlv8.py:145,148,151`) and rendered as the enum member name if recognized, else `hex(value)`. `BackOff` is rendered as `f"{seconds}s"` with the same little-endian decode (`hap_tlv8.py:153-155`). Every other tag is rendered as `f"{name}={len(value)}bytes"` (or `f"{hex(key)}={len(value)}bytes"` if the tag isn't in `TlvValue` at all, `hap_tlv8.py:142-143`).

### 1.8 `tests/auth/test_hap_tlv8.py` fixtures — verbatim

Full file: `tests/auth/test_hap_tlv8.py:1-119`. All hex below is exactly as it appears in the test source (Python byte-literal `\x` escapes rewritten as hex pairs for clarity; the underlying bytes are identical).

```python
SINGLE_KEY_IN = {10: b"123"}
SINGLE_KEY_OUT = b"\x0a\x03\x31\x32\x33"
# tag=0x0a (10, unassigned/custom), length=0x03, value="123" (ASCII 0x31 0x32 0x33)

DOUBLE_KEY_IN = OrderedDict([(1, b"111"), (4, b"222")])
DOUBLE_KEY_OUT = b"\x01\x03\x31\x31\x31\x04\x03\x32\x32\x32"
# tag=1 len=3 "111", then tag=4 len=3 "222" — confirms insertion-order-preserving encode

LARGE_KEY_IN = {2: b"\x31" * 256}
LARGE_KEY_OUT = b"\x02\xff" + b"\x31" * 255 + b"\x02\x01\x31"
# tag=2 (Salt) len=0xff(255) value=255*0x31, then tag=2 len=0x01 value=0x31
# — the >255-byte fragmentation KAT: 256 bytes -> 255-byte chunk + 1-byte chunk, same tag repeated
```

`test_write_single_key`/`test_write_two_keys`/`test_write_key_larger_than_255_bytes` assert `write_tlv(IN) == OUT` for the three fixtures above; `test_read_*` assert `read_tlv(OUT) == IN` (round-trip both directions) — `tests/auth/test_hap_tlv8.py:27-50`.

`stringify` fixtures (`tests/auth/test_hap_tlv8.py:53-119`), verbatim input/output pairs — port these as unit tests directly, they pin exact string formatting:

```python
stringify({TlvValue.Method: b"\x00"}) == "Method=PairSetup"
stringify({TlvValue.Method: b"\x02"}) == "Method=PairVerify"

stringify({TlvValue.SeqNo: b"\x01"}) == "SeqNo=M1"   # ... through \x06 == "SeqNo=M6"

stringify({TlvValue.Error: b"\x02"}) == "Error=Authentication"
stringify({TlvValue.Error: b"\x05"}) == "Error=MaxTries"

stringify({TlvValue.BackOff: b"\x02\x00"}) == "BackOff=2s"
stringify({TlvValue.BackOff: b"\x01\x00"}) == "BackOff=1s"

# For each of Identifier, Salt, PublicKey, Proof, EncryptedData, Certificate,
# Signature, Permissions, FragmentData, FragmentLast:
stringify({value: b"\x00\x01\x02\x03"}) == f"{value.name}=4bytes"

stringify({
    TlvValue.Method: b"\x00", TlvValue.SeqNo: b"\x01",
    TlvValue.Error: b"\x03", TlvValue.BackOff: b"\x01\x00",
}) == "Method=PairSetup, SeqNo=M1, Error=BackOff, BackOff=1s"

stringify({
    TlvValue.Method: b"\xaa", TlvValue.SeqNo: b"\xab",
    TlvValue.Error: b"\xac", 0xAD: b"\x01\x02\x03",
}) == "Method=0xaa, SeqNo=0xab, Error=0xac, 0xad=3bytes"
```

## 2. `pyatv/auth/hap_srp.py` — `SRPAuthHandler` (HAP SRP profile)

Full file: `pyatv/auth/hap_srp.py:1-233`.

### 2.1 `hkdf_expand` (`pyatv/auth/hap_srp.py:32-41`)

```python
def hkdf_expand(salt: str, info: str, shared_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt.encode(),
        info=info.encode(),
        backend=default_backend(),
    )
    return hkdf.derive(shared_secret)
```

HKDF-SHA512, 32-byte output, `salt`/`info` are Python `str.encode()` (UTF-8, always ASCII in practice), IKM = raw `shared_secret` bytes. This is the **one and only** derivation function used by the HAP profile (both pair-setup and pair-verify, all consumers) — see §4 for the full salt/info table across every call site.

### 2.2 `SRPAuthHandler.__init__` (`pyatv/auth/hap_srp.py:48-59`)

Generates a fresh `pairing_id = str(uuid.uuid4()).encode()` per handler instance — this is the **controller's per-pairing identifier**, sent as `TlvValue.Identifier` in pair-setup M5 (§2.6). It is regenerated every time a new `SRPAuthHandler` is constructed (i.e., every pairing attempt gets a fresh random UUID identifier, not a stable per-device identity — the stable identity is the Ed25519 keypair generated in `initialize()`, not this UUID).

### 2.3 `initialize()` (`pyatv/auth/hap_srp.py:66-82`)

```python
def initialize(self):
    self._signing_key = Ed25519PrivateKey.from_private_bytes(os.urandom(32))
    self._auth_private = self._signing_key.private_bytes(Raw, Raw, NoEncryption())
    self._auth_public = self._signing_key.public_key().public_bytes(Raw, Raw)
    self._verify_private = X25519PrivateKey.from_private_bytes(os.urandom(32))
    self._verify_public = self._verify_private.public_key()
    self._public_bytes = self._verify_public.public_bytes(Raw, Raw)
    return self._auth_public, self._public_bytes
```

- `_signing_key`/`_auth_private`/`_auth_public`: a **fresh 32-byte-random-seed Ed25519 keypair**, generated every call. `_auth_private` is the **raw 32-byte seed** (not PKCS8/DER), obtained by round-tripping through `cryptography`'s `Ed25519PrivateKey.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())` — this is functionally a no-op that just extracts the seed bytes back out; a Rust port using `ed25519-dalek`'s `SigningKey` directly from the 32 random bytes needs no equivalent round-trip.
- `_verify_private`/`_verify_public`/`_public_bytes`: a **fresh X25519 ephemeral keypair**, generated every call, discarded at the end of one pair-verify session. `_public_bytes` is the 32-byte raw public key sent as `TlvValue.PublicKey` in pair-verify M1.
- **Both keypairs are regenerated on every `initialize()` call** — for pair-setup this happens once per pairing attempt (`step1`), for pair-verify this happens once per verification (every reconnect calls `verify_credentials()` → `initialize()` again, e.g. `pyatv/protocols/mrp/auth.py:95-96`). The Ed25519 keypair generated during `initialize()` for a **pair-setup** flow becomes the controller's **persisted long-term identity** (stored as `ltsk` in `HapCredentials`, §3); the Ed25519 keypair generated during `initialize()` for a **pair-verify** flow is thrown away after `initialize()` returns — pair-verify only uses the caller-supplied `credentials.ltsk` (loaded from storage) for its actual signing (`verify1`, §2.4), the freshly-`initialize()`d `_signing_key`/`_auth_private`/`_auth_public` fields are simply unused dead weight during pair-verify (only `_verify_private`/`_verify_public`/`_public_bytes` matter there). **A Rust port's `initialize()` equivalent for pair-verify only strictly needs to generate the X25519 ephemeral pair**, but replicating the wasted Ed25519 generation exactly is harmless and keeps the code paths unified as pyatv does.

### 2.4 `verify1()` — pair-verify M2 processing + M3 construction (`pyatv/auth/hap_srp.py:84-124`)

```python
def verify1(self, credentials, session_pub_key, encrypted):
    self._shared = self._verify_private.exchange(X25519PublicKey.from_public_bytes(session_pub_key))
    session_key = hkdf_expand("Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", self._shared)
    chacha = chacha20.Chacha20Cipher8byteNonce(session_key, session_key)
    decrypted_tlv = read_tlv(chacha.decrypt(encrypted, nonce="PV-Msg02".encode()))

    identifier = decrypted_tlv[TlvValue.Identifier]
    signature = decrypted_tlv[TlvValue.Signature]
    if identifier != credentials.atv_id:
        raise exceptions.AuthenticationError("incorrect device response")

    info = session_pub_key + bytes(identifier) + self._public_bytes
    ltpk = Ed25519PublicKey.from_public_bytes(bytes(credentials.ltpk))
    try:
        ltpk.verify(bytes(signature), bytes(info))
    except InvalidSignature as ex:
        raise exceptions.AuthenticationError("signature error") from ex

    device_info = self._public_bytes + credentials.client_id + session_pub_key
    device_signature = Ed25519PrivateKey.from_private_bytes(credentials.ltsk).sign(device_info)

    tlv = write_tlv({TlvValue.Identifier: credentials.client_id, TlvValue.Signature: device_signature})
    return chacha.encrypt(tlv, nonce="PV-Msg03".encode())
```

Sequenced exactly:

1. ECDH: `self._shared = X25519(self._verify_private, session_pub_key)` — `session_pub_key` is the **accessory's** ephemeral X25519 public key received in the M2 response's `PublicKey` TLV.
2. Derive `session_key = HKDF-SHA512(salt="Pair-Verify-Encrypt-Salt", info="Pair-Verify-Encrypt-Info", ikm=shared)[0:32]`.
3. Build a `Chacha20Cipher8byteNonce(out_key=session_key, in_key=session_key)` — **the same 32-byte key used for both directions** at this stage (there is only one session key derived here; §5 below covers the nonce construction in detail).
4. Decrypt the M2 `EncryptedData` TLV payload with nonce `b"PV-Msg02"` (fixed, not counter-derived) → parse as a TLV8 blob → extract `Identifier` (device's persistent pairing id, must equal `credentials.atv_id` or the whole verify fails immediately with `AuthenticationError("incorrect device response")`) and `Signature`.
5. **Verify the device's signature.** The signed payload is `info = session_pub_key(32 bytes, accessory's ephemeral X25519 pubkey) || identifier(device's persisted id, variable length) || self._public_bytes(32 bytes, controller's own ephemeral X25519 pubkey)`. Verified against `credentials.ltpk` (the **accessory's** long-term Ed25519 public key, loaded from persisted credentials). **Field order matters exactly** — `accessory_ephemeral_pubkey || accessory_identifier || controller_ephemeral_pubkey`, i.e. "your key, your name, my key" from the accessory's perspective when it originally signed it.
6. **Construct the controller's own signature.** `device_info = self._public_bytes(controller's ephemeral X25519 pubkey) || credentials.client_id(controller's own persisted identifier) || session_pub_key(accessory's ephemeral X25519 pubkey)` — i.e. "my key, my name, your key", the mirror image of step 5's field order (own-key-first vs accessory-key-first is swapped between the two directions, not merely a relabeling — get this backwards and the accessory will reject the M3). Signed with `Ed25519PrivateKey.from_private_bytes(credentials.ltsk)` — the **controller's own** long-term Ed25519 private key (raw 32-byte seed), also loaded from persisted credentials.
7. Build TLV `{Identifier: credentials.client_id, Signature: device_signature}`, encrypt with the **same** `chacha`/`session_key` but nonce `b"PV-Msg03"` (still fixed, still same key), return as the M3 `EncryptedData`.

This entire method both **verifies inbound and produces outbound** in one call — there is no separate "verify only" step; a signature mismatch (step 5) or identifier mismatch (step 4) raises immediately and `verify_credentials()` never sends M3 at all.

### 2.5 `verify2()` — transport key derivation (`pyatv/auth/hap_srp.py:126-136`)

```python
def verify2(self, salt: str, output_info: str, input_info: str) -> Tuple[bytes, bytes]:
    output_key = hkdf_expand(salt, output_info, self._shared)
    input_key = hkdf_expand(salt, input_info, self._shared)
    return output_key, input_key
```

Called **after** `verify1()` (which sets `self._shared`), with protocol-specific `salt`/`output_info`/`input_info` strings supplied by the caller (§4 has the full table). Note this derives from the **raw X25519 ECDH output**, *not* from the `session_key` computed inside `verify1()` — `Pair-Verify-Encrypt-Salt`/`-Info` and the transport-key salts are two independent HKDF expansions of the same IKM (`self._shared`), not a chain.

### 2.6 `step1()` — pair-setup SRP context construction (`pyatv/auth/hap_srp.py:138-149`)

```python
def step1(self, pin):
    context = SRPContext(
        "Pair-Setup", str(pin),
        prime=constants.PRIME_3072, generator=constants.PRIME_3072_GEN,
        hash_func=hashlib.sha512,
    )
    self._session = SRPClientSession(context, binascii.hexlify(self._auth_private).decode())
```

- `SRPContext("Pair-Setup", str(pin), ...)`: username `I = "Pair-Setup"` (literal ASCII, not a real identity), password `P = str(pin)` (e.g. `"1111"`, decimal-string PIN, **not** zero-padded to a fixed width by this call — but see §6, every pairing-handler's `pin()` setter does `str(pin).zfill(4)` before it ever reaches here, so in practice it is always a 4-character string).
- `prime=PRIME_3072, generator=PRIME_3072_GEN="5"` — RFC 5054 3072-bit MODP group (`srptools/constants.py:37-49`, hex reproduced there, byte-identical to RustCrypto `srp::groups::G3072`).
- `hash_func=hashlib.sha512` — **every** hash in this SRP session (x, u, k, K, M1, M2) is SHA-512, not SHA-1.
- `SRPClientSession(context, private=binascii.hexlify(self._auth_private).decode())` — **the client's SRP ephemeral private exponent `a` is set to the hex encoding of the freshly-generated Ed25519 seed** (`self._auth_private` from `initialize()`, §2.3), *not* to a value `srptools` itself would randomly generate. This is the HAP-profile analog of the "reuse Ed25519 seed as SRP ephemeral" quirk the research report flagged for **legacy** AirPlay (§2.2 of that report) — **it is not exclusive to legacy AirPlay; the modern HAP profile does the exact same seed reuse.** This is a correction to the research report, which described the reuse only under the legacy-AirPlay section and implied it was a legacy-only oddity; it is present in `hap_srp.py` too, for every MRP/Companion/HAP-AirPlay pairing. See `srptools/client.py:9-25` (constructor: `if not private: self._this_private = ...generate...`; if `private` is given, `common.py:36-37` does `self._this_private = int_from_hex(private)`, skipping generation entirely) for confirmation this really does replace the ephemeral rather than merely seed a CSPRNG.

### 2.7 `step2()` — pair-setup M3 construction, and the SRP "proof verification" that is not one (`pyatv/auth/hap_srp.py:151-163`)

```python
def step2(self, atv_pub_key, atv_salt):
    pk_str = binascii.hexlify(atv_pub_key).decode()
    salt = binascii.hexlify(atv_salt).decode()
    self._session.process(pk_str, salt)
    if not self._session.verify_proof(self._session.key_proof_hash):
        raise exceptions.AuthenticationError("proofs do not match")
    pub_key = binascii.unhexlify(self._session.public)
    proof = binascii.unhexlify(self._session.key_proof)
    return pub_key, proof
```

**Critical correctness finding, not mentioned anywhere in the research report:** `self._session.process(pk_str, salt)` (`srptools/common.py:94-107`) computes the client's own `A`, `S`, `K`, `M1` (`key_proof`), and `M2` (`key_proof_hash`) purely from the accessory's public key and salt — nothing here compares against a value the accessory actually sent as *its* proof. Then `self._session.verify_proof(self._session.key_proof_hash)` — read `SRPClientSession.verify_proof` (`srptools/client.py:40-42`):

```python
def verify_proof(self, key_proof, base64=False):
    super(SRPClientSession, self).verify_proof(key_proof)
    return self._value_decode(key_proof, base64) == self.key_proof_hash
```

`self._session.key_proof_hash` is passed in as **both** the argument and compared against **itself** as `self.key_proof_hash` — this is a **tautological self-comparison that can never fail** (barring an exception mid-computation). `step2`'s signature (`atv_pub_key, atv_salt`) has **no parameter for an accessory-supplied proof value at all** — and confirmed by grepping every call site (`pyatv/protocols/mrp/auth.py:58`, `pyatv/protocols/companion/auth.py:80`, `pyatv/protocols/airplay/auth/hap.py:74`, `pyatv/protocols/airplay/auth/hap_transient.py:72`), none of them pass one either. **pyatv's pair-setup client code never actually validates the accessory's SRP key-proof (would-be M2 proof) during pair-setup.** See §8 for the fuller consequence (the M4 proof the accessory sends back is read into a local `atv_proof` variable and only logged, never compared) — this is the single most important correctness gap for the Rust port to consciously decide about (replicate the leniency, or add real verification and accept a possible interop difference if any real accessory relies on lenient clients — unlikely, but undocumented).

`pub_key`/`proof` returned are the client's own `A` (public ephemeral) and `M1` (key proof) as raw bytes, sent on the wire as `TlvValue.PublicKey`/`TlvValue.Proof` in pair-setup M3.

### 2.8 `step3()` — pair-setup M5 construction (`pyatv/auth/hap_srp.py:165-205`)

```python
def step3(self, name=None, additional_data=None):
    ios_device_x = hkdf_expand("Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info",
                                binascii.unhexlify(self._session.key))
    self._session_key = hkdf_expand("Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info",
                                     binascii.unhexlify(self._session.key))
    device_info = ios_device_x + self.pairing_id + self._auth_public
    device_signature = self._signing_key.sign(device_info)
    tlv = {
        TlvValue.Identifier: self.pairing_id,
        TlvValue.PublicKey: self._auth_public,
        TlvValue.Signature: device_signature,
    }
    if name:
        tlv[TlvValue.Name] = opack.pack({"name": name})
    if additional_data:
        tlv.update(additional_data)
    chacha = chacha20.Chacha20Cipher8byteNonce(self._session_key, self._session_key)
    encrypted_data = chacha.encrypt(write_tlv(tlv), nonce="PS-Msg05".encode())
    return encrypted_data
```

- `self._session.key` is `srptools`' hex-string SRP session key `K` (§2.9 below for its exact formula) — unhexlified to raw bytes before use as HKDF IKM, both here.
- `ios_device_x = HKDF-SHA512(salt="Pair-Setup-Controller-Sign-Salt", info="Pair-Setup-Controller-Sign-Info", ikm=K)`. This is the value the research report calls "iOSDeviceX".
- `self._session_key = HKDF-SHA512(salt="Pair-Setup-Encrypt-Salt", info="Pair-Setup-Encrypt-Info", ikm=K)` — this becomes the M5/M6 TLV-encryption key, stored on the handler for reuse in `step4()`.
- **Signed payload** for M5: `device_info = ios_device_x(32 bytes) || self.pairing_id(controller's UUID string bytes, from __init__) || self._auth_public(32 bytes, controller's freshly-generated Ed25519 public key)`, signed with `self._signing_key` (the same freshly-generated Ed25519 private key). Field order: HKDF-output, then identifier, then public key — same shape as the accessory's mirrored `Pair-Setup-Accessory-Sign-*` derivation in the server reference (§5.1).
- `tlv[TlvValue.Name]`, **only if `name` is truthy**, is not the raw string — it is an **OPACK-packed** single-key dict `{"name": name}` (`pyatv.support.opack.pack`, `hap_srp.py:193-196`) stored as the TLV value. This is unusual: every other value in this TLV is raw bytes, but `Name` is itself an OPACK-encoded blob nested inside the TLV entry. A Rust port must OPACK-encode this field specifically, not treat it as a plain UTF-8 string TLV. `name` comes from the pairing handler's `display_name` parameter (`finish_pairing(username, pin_code, display_name)`); MRP's pairing handler always passes `None` for it (`pyatv/protocols/mrp/pairing.py:63`, literal `None` fourth positional argument), so **MRP pair-setup never sends a `Name` TLV**; Companion's handler passes `self._name` (default `"pyatv"`, `pyatv/protocols/companion/pairing.py:24,64`), so **Companion pair-setup does send it**; AirPlay's handler passes `self._name` too (`pyatv/protocols/airplay/pairing.py:27,76`, defaulting to `core.settings.info.name`).
- `additional_data`, if given, is merged into the TLV dict with `dict.update` **after** the three mandatory keys and the optional `Name` — so its keys can in principle collide with and overwrite `Identifier`/`PublicKey`/`Signature`/`Name` if a caller supplied any of those tags again. **No call site in pyatv's own tree ever passes `additional_data`** (grep confirms `step3(` is only ever called with `name=` or no arguments at all) — this parameter exists but is currently dead in-tree; port it for API completeness but do not expect a KAT to exercise it.
- Encrypted with `Chacha20Cipher8byteNonce(self._session_key, self._session_key)` (same key both directions again), nonce `b"PS-Msg05"` (fixed).

### 2.9 `step4()` — pair-setup M6 processing (`pyatv/auth/hap_srp.py:207-233`)

```python
def step4(self, encrypted_data):
    chacha = chacha20.Chacha20Cipher8byteNonce(self._session_key, self._session_key)
    decrypted_tlv_bytes = chacha.decrypt(encrypted_data, nonce="PS-Msg06".encode())
    if not decrypted_tlv_bytes:
        raise exceptions.AuthenticationError("data decrypt failed")
    decrypted_tlv = read_tlv(decrypted_tlv_bytes)
    atv_identifier = decrypted_tlv[TlvValue.Identifier]
    atv_signature = decrypted_tlv[TlvValue.Signature]
    atv_pub_key = decrypted_tlv[TlvValue.PublicKey]
    # TODO: verify signature here
    return HapCredentials(atv_pub_key, self._auth_private, atv_identifier, self.pairing_id)
```

**Second major correctness gap, explicit in pyatv's own source as `# TODO: verify signature here` (`pyatv/auth/hap_srp.py:229`):** the accessory's Ed25519 signature over its `AccessoryX || accessoryPairingID || accessoryLTPK` payload (the mirror-image of §2.8's controller signature) is decoded (`atv_signature`) but **never checked against `atv_pub_key` at all**. Decryption success (AEAD tag verification, implicit in `chacha.decrypt` raising/returning empty on failure — see §5 for exact failure semantics of the underlying `chacha20poly1305_reuseable` binding) is the only cryptographic check performed on M6. A device that returns a garbage (but validly-shaped) TLV with an unrelated public key and an invalid signature over it would be silently accepted by pyatv as a paired accessory, **as long as the AEAD decryption of the outer envelope itself succeeds** (which it will, since that's keyed off the SRP-derived `self._session_key`, already established by the point M6 arrives). **A Rust port must decide deliberately whether to add real signature verification here** — doing so is strictly more secure and should not break interop with any real, correctly-implemented Apple TV or HomePod (they always send a valid signature; pyatv just never checks it), so there is no interop reason to omit it, only "match pyatv bug-for-bug" reasons, which are weak here. Recommend the port **does** verify, and documents the deviation from pyatv explicitly.

`HapCredentials(atv_pub_key, self._auth_private, atv_identifier, self.pairing_id)` — constructor argument order is `(ltpk, ltsk, atv_id, client_id)` (§3.1); here `ltpk=atv_pub_key` (**accessory's** long-term public key), `ltsk=self._auth_private` (**controller's own** long-term private key seed), `atv_id=atv_identifier` (**accessory's** persisted id), `client_id=self.pairing_id` (**controller's own** persisted id, the UUID from `__init__`). This confirms the research report's characterization in its own §7 (peer's pubkey + own privkey, not symmetric naming) — worth re-stating here as ground truth rather than inference: read directly off this constructor call, not reconstructed from the string format.

## 3. `pyatv/auth/hap_pairing.py` — credentials and procedure ABCs

Full file: `pyatv/auth/hap_pairing.py:1-147`.

### 3.1 `HapCredentials` (`pyatv/auth/hap_pairing.py:32-86`)

```python
class HapCredentials:
    def __init__(self, ltpk: bytes = b"", ltsk: bytes = b"", atv_id: bytes = b"", client_id: bytes = b"") -> None:
        self.ltpk = ltpk
        self.ltsk = ltsk
        self.atv_id = atv_id
        self.client_id = client_id
        self.type: AuthenticationType = self._get_auth_type()
```

Constructor argument order, always: `(ltpk, ltsk, atv_id, client_id)`.

`_get_auth_type()` (`hap_pairing.py:49-69`) — this is the **entire** classification logic, exhaustive, order matters (first match wins, and the checks are mutually exclusive by construction so order is actually irrelevant for well-formed inputs, but replicate the exact branch order for identical error behavior on malformed inputs):

```python
def _get_auth_type(self) -> AuthenticationType:
    if self.ltpk == b"" and self.ltsk == b"" and self.atv_id == b"" and self.client_id == b"":
        return AuthenticationType.Null
    if self.ltpk == b"transient":
        return AuthenticationType.Transient
    if self.ltpk == b"" and self.ltsk != b"" and self.atv_id == b"" and self.client_id != b"":
        return AuthenticationType.Legacy
    if self.ltpk and self.ltsk and self.atv_id and self.client_id:
        return AuthenticationType.HAP
    raise exceptions.InvalidCredentialsError("invalid credentials type")
```

Note the **literal ASCII bytes `b"transient"`** (9 bytes, not a random/generated marker) stored directly in the `ltpk` slot is the entire `Transient` sentinel — `TRANSIENT_CREDENTIALS = HapCredentials(b"transient")` (`hap_pairing.py:124`, positional first arg = `ltpk`). Any other field state that doesn't match one of the four patterns above (e.g. `ltpk` set but `ltsk` empty, in a "HAP-shaped but incomplete" way) raises `InvalidCredentialsError` from the constructor itself — this happens **eagerly**, at `HapCredentials()` construction time, not lazily when `.type` is accessed.

`__eq__` (`hap_pairing.py:71-75`) compares via `str(self) == str(other)` — i.e. equality is defined transitively through the hex string format (§3.2), not direct byte-field comparison; behaviorally identical for well-formed instances but means two `HapCredentials` with the same fields but different Python object identity round-trip-compare equal, which a Rust `#[derive(PartialEq)]` on the struct fields directly will also satisfy — no special `PartialEq` impl needed as long as the four `bytes` fields are compared, not the derived `type`.

### 3.2 `__str__`/`parse_credentials` (`hap_pairing.py:77-86`, `127-146`)

```python
def __str__(self) -> str:
    return ":".join([
        binascii.hexlify(self.ltpk).decode("utf-8"),
        binascii.hexlify(self.ltsk).decode("utf-8"),
        binascii.hexlify(self.atv_id).decode("utf-8"),
        binascii.hexlify(self.client_id).decode("utf-8"),
    ])
```

Always emits **exactly 4** colon-separated lowercase-hex fields, in this fixed order, **regardless of `AuthenticationType`** (a `Legacy`-typed credentials object, whose `ltpk`/`atv_id` are empty `bytes`, still serializes to a 4-field string with two empty segments — e.g. `":8ffa...:...:4142..."` with leading/interior empty hex segments — never a 2-field string on output). The **2-field shape only exists on the parsing side**, as a compatibility input format:

```python
def parse_credentials(detail_string):
    if detail_string is None:
        return NO_CREDENTIALS
    split = detail_string.split(":")
    if len(split) == 2:
        client_id = binascii.unhexlify(split[0])
        ltsk = binascii.unhexlify(split[1])
        return HapCredentials(b"", ltsk, b"", client_id)
    if len(split) == 4:
        ltpk, ltsk, atv_id, client_id = (binascii.unhexlify(s) for s in split)
        return HapCredentials(ltpk, ltsk, atv_id, client_id)
    raise exceptions.InvalidCredentialsError("invalid credentials: " + detail_string)
```

**This is a correction to the research report**, which states the 2-field shape is one of two shapes `HapCredentials.__str__` can *produce*. In fact `__str__` **only ever produces the 4-field form** — the 2-field form is a **parse-only legacy input compatibility path** (comment at `hap_pairing.py:134-135`: "Compatibility with 'legacy credentials' used by AirPlay where seed is stored as LTSK and identifier as client_id"). Once parsed, a 2-field string becomes a normal 4-field-internal `HapCredentials(b"", ltsk, b"", client_id)`, and if that same object were later re-serialized with `str()`, it would come back out as a 4-field string with two empty hex segments (`":ltsk_hex::client_id_hex"`), **not** the original 2-field string. Round-tripping a legacy credentials string through `parse_credentials` → `str()` is therefore **lossy in format but not in data** — the semantic fields survive, the compact 2-field wire format does not. A Rust port's `Display`/`FromStr` should replicate this asymmetry exactly (accept both 2- and 4-field on parse, always emit 4-field on format) if byte-exact config-file compatibility with existing pyatv-authored credential strings matters, which per top-level `CLAUDE.md` it explicitly does ("the on-disk/config string format itself should be replicated exactly").

Where legacy AirPlay's `LegacySRPAuthHandler` itself constructs its own credentials to return (§7.3's `AirPlayLegacyPairSetupProcedure.finish_pairing` just returns `self.srp.credentials`, which was passed in at construction as `new_credentials()` — `HapCredentials(b"", urandom(32), b"", urandom(8))`, `pyatv/protocols/airplay/srp.py:52-56`), it is **already** a `Legacy`-typed 4-field-internal object; the 2-field *string* form is purely a config-file/CLI convenience notation, never constructed by in-memory pyatv code paths, only by whatever wrote the string a user later pastes back in.

### 3.3 `NO_CREDENTIALS` / `TRANSIENT_CREDENTIALS` (`hap_pairing.py:123-124`)

```python
NO_CREDENTIALS = HapCredentials()             # all four fields empty -> AuthenticationType.Null
TRANSIENT_CREDENTIALS = HapCredentials(b"transient")  # ltpk=b"transient" -> AuthenticationType.Transient
```

`NO_CREDENTIALS.__str__()` is `"::::"`... actually four empty hex strings joined by three colons: `":::"` (three colons for four empty segments) — worth an explicit unit test in the port, this exact string is what ends up in, e.g., logs or a "no credentials" placeholder.

### 3.4 `AuthenticationType` (`hap_pairing.py:13-27`)

```python
class AuthenticationType(Enum):
    Null = auto()       # No authentication (just pass through).
    Legacy = auto()      # Legacy SRP based authentication.
    HAP = auto()          # Authentication based on HAP (Home-Kit).
    Transient = auto()    # Authentication based on transient HAP (Home-Kit).
```

Uses `enum.auto()` — the underlying integer values are **not** stable/meaningful (Python assigns 1, 2, 3, 4 in declaration order, but nothing in pyatv serializes this integer anywhere; it's purely an in-process discriminant). A Rust port's enum does not need to match these numerically, only the four named variants and their semantics.

### 3.5 `PairSetupProcedure`/`PairVerifyProcedure` ABCs (`hap_pairing.py:89-121`)

```python
class PairSetupProcedure(ABC):
    @abstractmethod
    async def start_pairing(self) -> None: ...
    @abstractmethod
    async def finish_pairing(self, username: str, pin_code: int, display_name: Optional[str]) -> HapCredentials: ...

class PairVerifyProcedure(ABC):
    @abstractmethod
    async def verify_credentials(self) -> bool: ...
    @abstractmethod
    def encryption_keys(self, salt: str, output_info: str, input_info: str) -> Tuple[bytes, bytes]: ...
```

`verify_credentials()`'s `bool` return is semantically "did this produce usable transport encryption keys" — `True` for HAP/transient (X25519-based keys always exist after a successful verify), `False` for `NullPairVerifyProcedure` (no credentials at all, §7.1) and for **both** `AirPlayLegacyPairVerifyProcedure` (§7.6 — legacy AirPlay's pair-verify never produces HAPSession-style transport keys at all; `encryption_keys()` on that class unconditionally raises `NotSupportedError`, `pyatv/protocols/airplay/auth/legacy.py:108-114`). Callers (`verify_connection`, `pyatv/protocols/airplay/auth/__init__.py:100-117`) gate the `encryption_keys()` call on this boolean specifically to avoid calling it on a procedure that would raise.

## 4. Salt/info/key-role table — every call site, verbatim

This supersedes and corrects §3 of the research report, which had the right salts but got the MRP client/server key-role assignment under-specified and mis-stated the AirPlay-only scope of `HAPSession`/`hap_channel`.

### 4.0 Correction: MRP and Companion do NOT use `HAPSession`/`hap_channel`

The research report states `pyatv/auth/hap_session.py` is "used via `AbstractHAPChannel`/`setup_channel` for MRP, AirPlay control, AirPlay events, AirPlay data-stream". **This is wrong for MRP and wrong for Companion.** Verified by grepping every file that imports `hap_session`/`hap_channel`/`HAPSession`/`AbstractHAPChannel`/`setup_channel` across `pyatv/`: the only importers are `pyatv/protocols/raop/protocols/airplayv2.py`, `pyatv/scripts/atvproxy.py`, `pyatv/protocols/airplay/ap2_session.py`, `pyatv/protocols/airplay/auth/__init__.py`, `pyatv/protocols/airplay/channels.py`, plus `hap_session.py`/`hap_channel.py` themselves. **MRP and Companion never import or use `HAPSession` at all.**

- **MRP** (`pyatv/protocols/mrp/connection.py:93-95,114-136,164-167`): `enable_encryption(output_key, input_key)` just stores `self._chacha = chacha20.Chacha20Cipher8byteNonce(output_key, input_key)`. `send()` encrypts the **entire serialized protobuf message** in one `self._chacha.encrypt(serialized)` call (no `aad`, nonce omitted → counter-based, auto-incrementing per §5.2). There is **no 1024-byte frame cap and no 2-byte-length-prefix AAD** — the length prefix that *does* exist on the wire (`write_variant(len(serialized)) + serialized`, `connection.py:123`) is a **protobuf varint framing prefix applied outside/around the ciphertext**, computed over the already-encrypted bytes' length, and is **not passed as AAD to the cipher at all**. This is a materially different framing from `HAPSession` (§5.2 below) despite using the same underlying `Chacha20Cipher8byteNonce` nonce-construction class.
- **Companion** (`pyatv/protocols/companion/connection.py:90-92,98-119,126-154`): also does not use `HAPSession`; `enable_encryption` builds `chacha20.Chacha20Cipher(output_key, input_key, nonce_length=12)` directly (already documented correctly in the research report §5.3) with the 4-byte frame header as AAD, no chunking cap.
- **AirPlay** is the **only** consumer of `HAPSession`/`AbstractHAPChannel`: the RTSP control connection (`verify_connection`, `pyatv/protocols/airplay/auth/__init__.py:100-117`, wraps an existing `HttpConnection`'s `receive_processor`/`send_processor` with `session.decrypt`/`session.encrypt`), and the AirPlay-2-specific event/data-stream channels (`pyatv/protocols/airplay/ap2_session.py`, via `pyatv/auth/hap_channel.py:79-97`'s `setup_channel`, which opens a **new** TCP connection and wraps it in `AbstractHAPChannel`, a subclass of which is `EventChannel`/`DataStreamChannel` from `pyatv/protocols/airplay/channels.py`).

### 4.1 Pair-setup HKDF derivations (protocol-independent, all from `hap_srp.py`/`server_auth.py`)

| Purpose | Salt | Info | IKM | Client site | Server (reference) site |
|---|---|---|---|---|---|
| Controller Ed25519 sign-input ("iOSDeviceX") | `Pair-Setup-Controller-Sign-Salt` | `Pair-Setup-Controller-Sign-Info` | SRP `K` | `hap_srp.py:171-175` | n/a (controller-only derivation) |
| M5/M6 TLV AEAD key | `Pair-Setup-Encrypt-Salt` | `Pair-Setup-Encrypt-Info` | SRP `K` | `hap_srp.py:177-181` | `mrp/server_auth.py:208-212`, `companion/server_auth.py:171-175`, `airplay/server_auth.py:359-363` |
| Accessory Ed25519 sign-input ("AccessoryX") | `Pair-Setup-Accessory-Sign-Salt` | `Pair-Setup-Accessory-Sign-Info` | SRP `K` | n/a (accessory-only, but a Rust hermetic test server needs it) | `mrp/server_auth.py:214-218`, `companion/server_auth.py:177-181`, `airplay/server_auth.py:365-369` |

### 4.2 Pair-verify HKDF derivations

| Purpose | Salt | Info | IKM | Client site | Server (reference) site |
|---|---|---|---|---|---|
| M2/M3 TLV AEAD key | `Pair-Verify-Encrypt-Salt` | `Pair-Verify-Encrypt-Info` | X25519 shared secret | `hap_srp.py:90-92` | `mrp/server_auth.py:140-142`, `companion/server_auth.py:109-111`, `airplay/server_auth.py:276-278` |

### 4.3 Transport session keys — full table with the exact client/server role assignment

Every row: client derives `(output_key, input_key) = (HKDF(salt,output_info,shared), HKDF(salt,input_info,shared))` via `SRPAuthHandler.verify2` (`hap_srp.py:126-136`), then a **protocol-specific `enable_encryption(a, b)` call** decides which derived value actually becomes the local encrypt-key vs decrypt-key. The two are **not always positionally identical** between client and reference-server, because the info-string names are sometimes symmetric-but-mirrored (`Write`/`Read` reused verbatim by both sides) and sometimes asymmetric-by-construction (`Client...`/`Server...`, unambiguous by name). Get the swap wrong in exactly one direction and you decrypt garbage from the peer while your own outgoing traffic is silently accepted as if valid (because AEAD only fails if the *decrypting* side's key is wrong — a wrong *encrypting* key just produces ciphertext the peer can't decrypt, an obvious wrong-key failure, not a byte-level silent corruption).

**MRP** — client: `pyatv/protocols/mrp/protocol.py:26-28,218-219` (`SRP_SALT="MediaRemote-Salt"`, `SRP_OUTPUT_INFO="MediaRemote-Write-Encryption-Key"`, `SRP_INPUT_INFO="MediaRemote-Read-Encryption-Key"`; `MrpConnection.enable_encryption(output_key, input_key)` receives them in that order, `connection.py:93-95`, so **client encrypts with `Write`-derived key, decrypts with `Read`-derived key**). Reference server: `mrp/server_auth.py:162-170` derives `self.output_key = HKDF(salt, "MediaRemote-Write-Encryption-Key", shared)`, `self.input_key = HKDF(salt, "MediaRemote-Read-Encryption-Key", shared)` — **same info-string names as the client**, by construction ambiguous about role — then at `_m3_verify` (`mrp/server_auth.py:173-175`):

```python
def _m3_verify(self, pairing_data):
    self.send_to_client(messages.crypto_pairing({TlvValue.SeqNo: b"\x04"}))
    self.enable_encryption(self.input_key, self.output_key)   # note: swapped vs field names
```

`enable_encryption(output_key_param, input_key_param)`'s abstract signature (`mrp/server_auth.py:245-247`) takes `(output_key, input_key)` positionally — this call passes `(self.input_key, self.output_key)`, i.e. **the server's `Read`-derived value becomes its own encrypt key, and its `Write`-derived value becomes its own decrypt key** — the mirror of the client, so that server-encrypts-with-Read matches client-decrypts-with-Read, and server-decrypts-with-Write matches client-encrypts-with-Write. **The swap happens at this one call site, via positional-argument reordering, not via different salt/info strings.** A Rust hermetic test-server implementation must reproduce this exact swap-at-the-call-site pattern (or equivalently, swap the salts up front — functionally identical, but reading pyatv's own code, the swap is done at the `enable_encryption` call, not at derivation time).

**Companion** — client: `pyatv/protocols/companion/protocol.py:40-42,120-121` (`SRP_SALT=""` literal empty string, `SRP_OUTPUT_INFO="ClientEncrypt-main"`, `SRP_INPUT_INFO="ServerEncrypt-main"`; same `(output_key, input_key)` positional order into `CompanionConnection.enable_encryption`, `connection.py:90-92`). Reference server: `companion/server_auth.py:131-132` — `self.output_key = HKDF("", "ServerEncrypt-main", shared)`, `self.input_key = HKDF("", "ClientEncrypt-main", shared)` — **note the names are already correctly assigned from the server's own perspective** (server's output uses the `Server...` info string, matching what the client expects to decrypt with as its own `input`/`ServerEncrypt-main`). Then `_m3_verify` (`companion/server_auth.py:138-142`): `self.enable_encryption(self.output_key, self.input_key)` — **no positional swap needed here**, because the info-string names themselves already disambiguate role (`Client...` always means "encrypted by the client", `Server...` always means "encrypted by the server", so both sides can derive `output`/`input` directly without a call-site swap). **This is the opposite pattern from MRP** — MRP needed a swap because its two info strings are named from a single shared "Write"/"Read" vocabulary that's ambiguous about *whose* write/read it is; Companion's info strings are named from an unambiguous per-role vocabulary. A Rust port implementing both must not assume one universal "swap" rule; each protocol's swap-or-not is a property of how its own info-string names were chosen by pyatv's authors, and must be encoded per-protocol, not derived generically.

**AirPlay control channel** — client: `pyatv/protocols/airplay/auth/__init__.py:36-38,100-117` (`CONTROL_SALT="Control-Salt"`, `CONTROL_OUTPUT_INFO="Control-Write-Encryption-Key"`, `CONTROL_INPUT_INFO="Control-Read-Encryption-Key"`; fed into `HAPSession.enable(output_key, input_key)`, `hap_session.py:27-29`, i.e. `self.chacha20 = Chacha20Cipher(output_key, input_key)` — output/encrypt = `Write`-derived, input/decrypt = `Read`-derived, same `Write`/`Read` vocabulary ambiguity as MRP). Reference server: `airplay/server_auth.py:296-302` — **already swapped at derivation time**, unlike MRP's swap-at-call-site pattern: `self.input_key = HKDF("Control-Salt", "Control-Write-Encryption-Key", shared)`, `self.output_key = HKDF("Control-Salt", "Control-Read-Encryption-Key", shared)` (note: `input_key` gets the `Write`-info derivation, `output_key` gets the `Read`-info derivation — reversed from how the field names alone would suggest). Then `_m3_verify` (`airplay/server_auth.py:307-309`): `self.enable_encryption(self.output_key, self.input_key)` — **no swap at the call site**, because the swap already happened when the fields were assigned. **Same net effect as MRP's server (server ends up encrypting with the `Read`-info-derived key and decrypting with the `Write`-info-derived key), reached by a different code shape** (assignment-time swap vs call-site swap) — a Rust port should not assume pyatv is internally consistent about *where* it performs this swap, only that the *net effect* (peer symmetry) is what must be replicated; verify against the transport-level KAT (§7), not against "does the Rust code structurally mirror this Python function".

**AirPlay events channel** — `pyatv/protocols/airplay/ap2_session.py:31-33,138-148`: `EVENTS_SALT="Events-Salt"`, `EVENTS_WRITE_INFO="Events-Write-Encryption-Key"`, `EVENTS_READ_INFO="Events-Read-Encryption-Key"`; call site: `setup_channel(EventChannel, self.verifier, address, event_port, EVENTS_SALT, EVENTS_READ_INFO, EVENTS_WRITE_INFO)` — **`output_info` parameter receives `EVENTS_READ_INFO`, `input_info` parameter receives `EVENTS_WRITE_INFO`** — reversed relative to every other channel's `(salt, output_info, input_info)` call shape, with an explicit code comment explaining why (`ap2_session.py:137-139`: "Event channel is not used so we don't care about it (must be set up though). Note: Read/Write info reversed here as connection originates from receiver!"). Confirms the research report's description of this swap; the exact call site and parameter order above pin it precisely (`setup_channel`'s own signature is `(factory, verifier, address, port, salt, output_info, input_info)`, `hap_channel.py:79-87`).

**AirPlay data-stream channel** — `pyatv/protocols/airplay/ap2_session.py:35-37,151-187`: `DATASTREAM_SALT="DataStream-Salt"` (comment: "seed must be appended"), `DATASTREAM_OUTPUT_INFO="DataStream-Output-Encryption-Key"`, `DATASTREAM_INPUT_INFO="DataStream-Input-Encryption-Key"`. `seed = randint(0, 2**64)` (`ap2_session.py:156`, Python's `random.randint`, **not cryptographically secure** — worth noting for a Rust port that might reflexively reach for a CSPRNG here; pyatv itself does not use one for this value, though it has no secrecy requirement, only uniqueness-per-session, since it's transmitted in cleartext in the RTSP `SETUP` body's `seed` integer field, `ap2_session.py:164`, and its only purpose is salt disambiguation). Call site (`ap2_session.py:176-184`): `setup_channel(DataStreamChannel, self.verifier, address, data_port, DATASTREAM_SALT + str(seed), DATASTREAM_OUTPUT_INFO, DATASTREAM_INPUT_INFO)` — **standard unswapped order** (this channel's TCP connection is opened by the controller, matching the "normal" control-channel direction, hence no reversal).

### 4.4 Transient AirPlay pair-verify uses a *different* IKM entirely

`pyatv/protocols/airplay/auth/hap_transient.py:91-99`:

```python
def encryption_keys(self, salt, output_info, input_info):
    shared = binascii.unhexlify(self.srp.shared_key)
    output_key = hkdf_expand(salt, output_info, shared)
    input_key = hkdf_expand(salt, input_info, shared)
    return output_key, input_key
```

`self.srp.shared_key` is `SRPAuthHandler.shared_key` (`hap_srp.py:61-64`, a `@property` returning `self._session.key` — the **SRP session key `K`**, hex-string, unhexlified here), **not** `self._shared` (the X25519 ECDH output that every other HAP-based `encryption_keys()`/`verify2()` call uses). **Transient pairing's transport keys are derived from the SRP premaster-derived session key, because transient pairing skips the X25519-based pair-verify handshake entirely** — it only ever runs HAP pair-setup's M1–M4 (SRP negotiation), never M5/M6 (no persisted-identity signature exchange) and never a separate pair-verify round at all (module docstring, `hap_transient.py:1-7`: "transient pairing only covers the first four states of regular pairing (M1-M4)... implemented as the verification procedure step instead"). This is a **materially different key-derivation IKM** from every other row in this table and is not surfaced as such anywhere in the research report — flag prominently: a Rust port's transient-pairing code path must **not** reuse the same "derive from X25519 shared secret" function signature/assumption the rest of pair-verify uses; it needs `self.srp.shared_key` (SRP `K`) plumbed through instead.

## 5. Symmetric crypto: exact nonce/AAD/framing per consumer

### 5.1 `pyatv/support/chacha20.py` — full file, `Chacha20Cipher`/`Chacha20Cipher8byteNonce`

Already reproduced verbatim in the research report §5.1/§5.2; the arithmetic is correct there. One addition: `NONCE_LENGTH = 12` (`chacha20.py:9`) is the AEAD's required nonce size; `_pad_nonce` (`chacha20.py:49-51`) left-pads with `NONCE_LENGTH - len(nonce)` zero bytes — for the default `nonce_length=8` case (used by `Chacha20Cipher8byteNonce` and by `HAPSession`'s plain `Chacha20Cipher(...)` construction, which also defaults to `nonce_length=8`, `chacha20.py:15`), that's a **4-byte zero prefix**; for Companion's explicit `nonce_length=12`, `_pad_nonce` is never invoked at all (`encrypt`/`decrypt`, `chacha20.py:53-73`, only call it `if nonce is None` and the property getters `out_nonce`/`in_nonce` only call it `if nonce_length != NONCE_LENGTH`) — the 12-byte counter is used raw.

Backing AEAD library: `chacha20poly1305_reuseable.ChaCha20Poly1305Reusable` (`chacha20.py:7`, PyPI package `chacha20poly1305-reuseable`) — a wrapper existing specifically because the stdlib-adjacent `cryptography` package's own `ChaCha20Poly1305` object is documented as single-use-per-instance in some versions; this constraint has no Rust equivalent concern (`chacha20poly1305` crate's `ChaCha20Poly1305` type is safely reusable across many `encrypt`/`decrypt` calls with different nonces from the start), confirmed correct already in the research report §8.

### 5.2 HAPSession framing — AirPlay only (control/events/data-stream channels)

`pyatv/auth/hap_session.py:1-66`, full file reproduced in the research report §5.2 correctly. Confirmed: `FRAME_LENGTH = 1024`, `AUTH_TAG_LENGTH = 16`, 2-byte little-endian plaintext-length prefix, AAD = exactly those 2 bytes, nonce = `Chacha20Cipher`'s default `nonce_length=8` construction (4-zero-byte prefix + 8-byte LE counter), separate `_out_counter`/`_in_counter`. **This framing applies only to the three AirPlay-specific consumers listed in §4.0 — never to MRP or Companion.**

### 5.3 MRP transport framing — no HAPSession, no 1024-byte cap, no AAD

`pyatv/protocols/mrp/connection.py:114-136,164-167` (send/receive), reproduced in full at §4.0 above. Precisely:

- **Send**: `serialized = message.SerializeToString()`; if `self._chacha` is set, `serialized = self._chacha.encrypt(serialized)` (no `nonce=` kwarg → counter-based per-message nonce, auto-increments; no `aad=` kwarg → **AAD is `None`**, i.e. `self._enc_out.encrypt(nonce, data, None)` per `chacha20.py:62`, standard unauthenticated-associated-data AEAD call). Then `data = write_variant(len(serialized)) + serialized` — the length-prefix varint is computed over the **ciphertext's** length (plaintext-length-plus-16-byte-tag, since the whole encrypt output including the Poly1305 tag is what got assigned back to `serialized`), and is **not itself authenticated by the AEAD call** (it's not AAD, it's just a separate framing layer the transport reads before decrypting).
- **Receive**: `_handle_message(data)` — `data` here is already the length-delimited payload (length previously stripped by `read_variant`/buffer bookkeeping, `connection.py:137-163`); `if self._chacha: data = self._chacha.decrypt(data)` (again no explicit nonce/aad — counter-based, `aad=None`), then parsed as a protobuf message directly.
- **No frame-size cap.** A single MRP protobuf message of any size (subject only to whatever `write_variant`'s varint encoding and TCP/asyncio buffering can carry) is encrypted in one AEAD call — there is no 1024-byte chunking anywhere in this path. Large MRP messages (e.g. large `Now Playing` artwork blobs, if ever sent this way — in practice artwork goes over a different path, but nothing in this code enforces a size limit) are single multi-kilobyte-or-larger ChaCha20-Poly1305 operations.
- `write_variant`/`read_variant` (`pyatv/support/variant.py`) implement a standard LEB128-style protobuf varint, not covered further here as it's outside the pairing/crypto scope, but essential context: it is **outside** the AEAD boundary entirely, applied to already-encrypted bytes on send and stripped before decryption on receive.

### 5.4 Companion transport framing

Already correctly documented in the research report §5.3; confirmed verbatim against `pyatv/protocols/companion/connection.py:16-17,90-119,126-154` during this pass: `HEADER_LENGTH = 4` (1-byte `FrameType` + 3-byte big-endian length), `AUTH_TAG_LENGTH = 16` added to the transmitted length field only when encryption is active and payload is non-empty (`connection.py:103-106`: `if self._chacha and payload_length > 0: payload_length += AUTH_TAG_LENGTH` — note **zero-length payloads are never encrypted at all**, even when a chacha session is active: both `send` (`connection.py:115`: `if self._chacha and len(data) > 0`) and the receive path (`connection.py:148`: `if self._chacha and len(payload) > 0`) explicitly skip the AEAD call for empty payloads, sending/parsing the empty body in the clear — this matters because a zero-length `FrameType.NoOp` or similar keepalive frame is never wrapped in ChaCha20-Poly1305 even mid-session, which a Rust port must replicate exactly or it will produce frames the peer can't parse if it forces encryption on all frames indiscriminately). AAD = full 4-byte header (type + length, as already sent — i.e. the length **already includes** the 16-byte tag budget when it's computed, and that post-tag-adjusted header is what's authenticated). Nonce: raw 12-byte little-endian counter, no zero-prefix, separate per-direction counters (inherited from the shared `Chacha20Cipher` counter bookkeeping, §5.1).

### 5.5 Legacy AirPlay device-auth: exact CTR/GCM arithmetic

`pyatv/protocols/airplay/srp.py:25-49,104-194`. Already substantially covered in the research report §5.4; this section adds the two details that report is imprecise or silent about.

**Key/IV derivation is plain SHA-512 concatenation, confirmed exact byte layout:**

```python
def hash_sha512(*indata):
    hasher = hashlib.sha512()
    for data in indata:
        hasher.update(data.encode("utf-8") if isinstance(data, str) else data)
    return hasher.digest()
```

`aes_key = hash_sha512("Pair-Verify-AES-Key", shared)[0:16]` — i.e. `SHA512(ASCII("Pair-Verify-AES-Key") || shared)`, first 16 bytes. `shared` here is the raw X25519 ECDH output (`self._verify_private.exchange(...)`, `srp.py:132`), **not** hex-encoded, **not** passed through HKDF. Same construction for `aes_iv` with label `"Pair-Verify-AES-IV"`, and for pair-setup's `"Pair-Setup-AES-Key"`/`"Pair-Setup-AES-IV"` labels keyed off `sessionKey` (the raw, non-hex-decoded... actually `binascii.unhexlify(self.session.key)`, `srp.py:183`, so it *is* unhexlified first — the SRP session key is stored hex-encoded internally by `srptools`, so every consumer of it must unhexlify before use, unlike the X25519 shared secret which `cryptography`'s `.exchange()` already returns as raw bytes).

**`aes_encrypt`'s multi-argument call silently discards all but the last chunk's ciphertext — a detail the research report elides:**

```python
def aes_encrypt(mode, aes_key, aes_iv, *data):
    encryptor = Cipher(algorithms.AES(aes_key), mode(aes_iv), backend=default_backend()).encryptor()
    result = None
    for value in data:
        result = encryptor.update(value)
    encryptor.finalize()
    return result, None if not hasattr(encryptor, "tag") else encryptor.tag
```

Called at `srp.py:145`: `signature, _ = aes_encrypt(modes.CTR, aes_key, aes_iv, data, signed)` — **two positional `*data` arguments**, `data` (the opaque trailing bytes from the accessory's M2 pair-verify response, past the first 32 bytes) **then** `signed` (the 64-byte Ed25519 signature). The loop calls `encryptor.update(value)` once per argument, **reassigning `result` each iteration** rather than concatenating — so `result` ends up holding **only the CTR-ciphertext of `signed`, the second/last argument**. The CTR keystream **is** advanced through the `data` chunk (that `encryptor.update(data)` call happens and consumes keystream bytes equal to `len(data)`), but **its ciphertext output is computed and then discarded**, never concatenated into what gets returned or transmitted. **Net effect**: pyatv's outgoing pair-verify M3 for legacy AirPlay is `b"\x00\x00\x00\x00" + CTR_encrypt(aes_key, aes_iv, keystream_offset=len(data))(signed)` — i.e. the signature ciphertext as if it were encrypted starting at CTR keystream position `len(data)` bytes in, **not** starting at position 0, and the `data` blob's own ciphertext is never sent anywhere. A Rust port must replicate this **keystream-offset skip**, not attempt to send both ciphertexts concatenated (which would be a different, wire-incompatible byte sequence) and not restart the CTR counter at 0 for the signature (which would also be wire-incompatible). The cleanest Rust translation is: run the CTR keystream generator for `len(data)` bytes and discard that output, then continue the same keystream to encrypt `signed` — exactly mirroring the two sequential `encryptor.update()` calls sharing one internal counter state, just being explicit that only the second output is kept.

**Pair-setup IV increment, confirmed exact:**

```python
aes_key = hash_sha512("Pair-Setup-AES-Key", session_key)[0:16]
tmp = bytearray(hash_sha512("Pair-Setup-AES-IV", session_key)[0:16])
tmp[-1] = tmp[-1] + 1  # Last byte must be increased by 1
aes_iv = bytes(tmp)
```

`srp.py:185-189`. The increment is **unconditional, unchecked-overflow** Python `int + int` on a single byte value extracted from a `bytearray` — if `tmp[-1] == 255`, `tmp[-1] + 1 == 256`, and assigning `256` back into a `bytearray` slot raises `ValueError: byte must be in range(0, 256)` in real Python. **This is a latent crash bug in pyatv itself** for the (astronomically unlikely, 1/256 chance per session, uncontrollable since it depends on the SHA-512 hash output's last byte) case where the derived IV's last byte is already `0xFF`. Not previously flagged anywhere; worth a one-line note in the port ("wrapping add, `.wrapping_add(1)`, is the *safe* choice for a Rust port even though it diverges from pyatv's crash-on-overflow behavior — no real accessory can be interoperated with differently based on this, since a crash means pyatv itself could never complete that pairing attempt against real hardware either; this is pyatv's own bug, not a protocol requirement to replicate faithfully").

## 6. Ed25519/X25519 details — additions to research report §6

Confirmed via `hap_srp.py`/`server_auth.py`/`srp.py` reads above; the research report's §6 is accurate on the signed-payload field orders and the seed-reuse quirk, but (as corrected in §2.6 above) **incorrectly scopes the SRP-ephemeral/Ed25519-seed reuse as legacy-AirPlay-only** — it is present in the **modern HAP profile too** (`hap_srp.py:147-149`, `SRPClientSession(context, binascii.hexlify(self._auth_private).decode())`).

One more addition: the reference **server's** identity key generation (`generate_keys`, present verbatim in all three `server_auth.py` files, e.g. `mrp/server_auth.py:29-45`) derives **both** its Ed25519 signing key **and** its X25519 verify (pair-verify ephemeral) key from the **same fixed 32-byte seed** `PRIVATE_KEY = 32 * b"\xaa"` (`pyatv/auth/server_auth.py:13`):

```python
def generate_keys(seed):
    signing_key = Ed25519PrivateKey.from_private_bytes(seed)
    verify_private = X25519PrivateKey.from_private_bytes(seed)
    return ServerKeys(sign=signing_key, auth=..., auth_pub=..., verify=verify_private, verify_pub=verify_private.public_key())
```

This means the reference server's identity (`auth`/`auth_pub`, used for M5/M6 accessory-signature) and its per-*session* pair-verify ephemeral (`verify`/`verify_pub`) are **the same 32 raw bytes reinterpreted as both an Ed25519 seed and an X25519 scalar** — which is safe/valid because Ed25519 and X25519 seeds are both "any 32 bytes" inputs to their respective clamping/hashing procedures and there's no cross-algorithm key-recovery concern from reusing the raw seed this way, but it does mean the reference server's "ephemeral" X25519 key is **not actually ephemeral at all** — it is the same fixed key on every pair-verify across the process lifetime (there is no per-session regeneration in the server reference code — `self.keys = generate_keys(PRIVATE_KEY)` runs once in `__init__`, `mrp/server_auth.py:78-85`). **A Rust port building the hermetic test-server counterpart described in item 5 of the task should replicate this exactly** (fixed key material makes tests fully deterministic and repeatable), while being aware this would be a real security bug (no forward secrecy) in any actual accessory implementation — pyatv's reference server exists purely for testing, never advertised as production accessory code.

## 7. `pyatv/auth/hap_pairing.py` procedures — see §3.5; transient/PairingType

There is no `PairingType` enum anywhere in pyatv's `auth` package (grepped `pyatv/auth/*.py` and `pyatv/protocols/*/pairing.py`/`auth.py` for `PairingType` — zero hits). The task description's mention of `PairingType` does not correspond to anything in this codebase; the only relevant enum is `AuthenticationType` (§3.4). Treat `PairingType` as **not present in pyatv** — do not port a construct that doesn't exist; a Rust design should use `AuthenticationType` (or a Rust-idiomatic equivalent) for this axis and not invent a parallel `PairingType`.

## 8. `pyatv/auth/server_auth.py` — shared test constants

Full file, 13 lines, reproduced in full (`pyatv/auth/server_auth.py:1-13`):

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

**Independently verified** (not just read — actually recomputed, via `crypto.createPrivateKey`/DER-PKCS8-wrapping the raw seed in a Bun/Node script during this research pass, since no Python interpreter was available in this environment to import `cryptography` directly): `Ed25519PrivateKey.from_private_bytes(32 * b"\xaa").public_key()`'s raw 32 bytes equal `e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58`[:64 hex chars] — **exactly** `CLIENT_CREDENTIALS`'s first (`ltpk`) field. Decoding the third and fourth fields (`atv_id`, `client_id`) as ASCII confirms `atv_id = "5D797FD3-3538-427E-A47B-A32FC6CF3A6A" == SERVER_IDENTIFIER` and `client_id = "4D797FD3-3538-427E-A47B-A32FC6CF3A6A" == CLIENT_IDENTIFIER`. This proves `CLIENT_CREDENTIALS` is exactly what a real client would persist after successfully pairing once against the reference server with seed `PRIVATE_KEY` and identifier `SERVER_IDENTIFIER` — **it is a legitimate, fully-reproducible pair-verify KAT anchor**: any Rust client implementation given `CLIENT_CREDENTIALS` and pointed at a Rust reference server built from `PRIVATE_KEY`/`SERVER_IDENTIFIER`/`PIN_CODE` per §5–§6 above must complete pair-verify successfully and derive the same transport keys pyatv does, and this can be checked without ever touching real hardware. `CLIENT_CREDENTIALS`'s `ltsk` field (`80FD8265...537B1`, 32 bytes) is an arbitrary-but-fixed client-side Ed25519 seed with no particular derivation (just another fixed test constant) — it is the **controller's own** long-term private key, used to sign the controller's M3 pair-verify payload (§2.4 step 6).

The reference server implementations reuse this file's constants as their **default** constructor arguments (`unique_id=SERVER_IDENTIFIER, pin=PIN_CODE` on all three `*ServerAuth.__init__`, e.g. `mrp/server_auth.py:78`) — individual fake-device test fixtures may override the PIN (AirPlay's `tests/fake_device/airplay.py:22`: `DEVICE_PIN = 2271`, not `1111` — confirmed by reading `FakeAirPlayService.__init__`, `tests/fake_device/airplay.py:59-61`: `super().__init__(name=DEVICE_NAME, pin=DEVICE_PIN)`) but keep the same `SERVER_IDENTIFIER`/`PRIVATE_KEY` (MRP and Companion fake devices never override `unique_id`/`pin`, so they use `SERVER_IDENTIFIER`/`PIN_CODE` unmodified — confirmed: `tests/fake_device/mrp.py:382`, `super().__init__(DEVICE_NAME)`, no `unique_id`/`pin` kwargs; same at `tests/fake_device/companion.py:230-231`).

## 9. Per-protocol pairing handlers

### 9.1 MRP — `protocols/mrp/pairing.py` + `protocols/mrp/auth.py`

**Transport framing of pairing messages**: every pair-setup/verify TLV blob is wrapped in a `CryptoPairingMessage` protobuf (`pyatv/protocols/mrp/protobuf/CryptoPairingMessage.proto:9-15`):

```protobuf
message CryptoPairingMessage {
  optional bytes pairingData = 1;
  optional int32 status = 2;
  optional bool isRetrying = 3;
  optional bool isUsingSystemPairing = 4;
  optional int32 state = 5;
}
```

Built by `messages.crypto_pairing(pairing_data, is_pairing=False)` (`pyatv/protocols/mrp/messages.py:68-77`):

```python
def crypto_pairing(pairing_data, is_pairing=False):
    message = create(protobuf.CRYPTO_PAIRING_MESSAGE)
    crypto = protobuf.extract_inner(message)
    crypto.status = 0
    crypto.pairingData = hap_tlv8.write_tlv(pairing_data)
    crypto.isRetrying = False
    crypto.isUsingSystemPairing = False
    crypto.state = 2 if is_pairing else 0
    return message
```

`pairing_data` here is the **Python dict** (tag → bytes), TLV8-encoded internally by this helper — every call site passes the raw dict, not pre-encoded bytes (e.g. `pyatv/protocols/mrp/auth.py:41-44`: `messages.crypto_pairing({TlvValue.Method: b"\x00", TlvValue.SeqNo: b"\x01"}, is_pairing=True)`). `state` is `2` only for the very first pair-setup M1 message (`is_pairing=True`, only set at `auth.py:41-45`'s initial call), `0` for every other message including all of pair-verify — this `state` field is **not** the HAP `SeqNo`/`State` TLV value (that's carried inside `pairingData`); it appears to be an MRP-protocol-level connection-state indicator unrelated to the HAP state machine, and pyatv never reads it back on responses (`_get_pairing_data`, `mrp/auth.py:19-22`, only inspects `pairingData` for a TLV `Error` tag, never touches `resp.state`/`resp.status`). Outer message envelope: `messages.create(protobuf.CRYPTO_PAIRING_MESSAGE)` sets `message.type`, a random `uniqueIdentifier` (UUID4 uppercased), `errorCode=0` (`mrp/messages.py:12-20`).

**begin/finish/pin** (`pyatv/protocols/mrp/pairing.py:18-86`): `begin()` calls `pairing_procedure.start_pairing()` → `srp.initialize()`, connects, sends pair-setup M1 (`Method=PairSetup, SeqNo=M1`), stores `_atv_salt`/`_atv_pub_key` from the M2 response (§9.1's `MrpPairSetupProcedure.start_pairing`, `mrp/auth.py:35-49`). `pin(pin)` stores `str(pin).zfill(4)` (always 4-character decimal string, zero-padded — a PIN like `42` becomes `"0042"`, `mrp/pairing.py:83-85`). `finish()` requires `pin_code` already set (else raises `PairingError("no pin given")`, `mrp/pairing.py:54-55`), then drives `finish_pairing` through SRP M3/M5 (`mrp/auth.py:52-77`: `step1(pin_code)` → send M3 (`SeqNo=3,PublicKey,Proof`) → receive M4 (reads `atv_proof` **but never validates it against anything** — `mrp/auth.py:71-73`, logged only) → `step3()` → send M5 (`SeqNo=5,EncryptedData`) → receive M6 → `step4(encrypted_data)` returns `HapCredentials`). After `finish_pairing` succeeds, `MrpPairingHandler.finish()` **immediately performs a full pair-verify** against the just-obtained credentials (`mrp/pairing.py:69-72`) before considering pairing complete — this is not optional/deferred, it's synchronous within `finish()`, and its failure (e.g. `verify_credentials` raising) propagates as a `PairingError`, meaning **MRP pairing is only reported successful if pair-verify against the fresh credentials also succeeds immediately afterward** — a stronger end-to-end guarantee than "the SRP handshake alone completed". Only after that does `self.service.credentials = credentials` get set and persisted to `self._settings.protocols.mrp.credentials` (`mrp/pairing.py:74-75`).

**What comes out**: `str(HapCredentials(...))`, the 4-field colon-hex string (§3.2), assigned to `service.credentials` and to settings storage.

### 9.2 Companion — `protocols/companion/pairing.py` + `auth.py`

**Transport framing**: Companion frames (§5.4) carry an **OPACK-encoded dict** as payload, not a protobuf. The pairing-specific dict always has key `"_pd"` (constant `PAIRING_DATA_KEY = "_pd"`, `companion/auth.py:19`) holding the **raw TLV8-encoded bytes** (`write_tlv(...)` result, called directly by the pairing procedure, unlike MRP where the protobuf helper does the TLV8 encoding internally) — e.g. `pyatv/protocols/companion/auth.py:54-62`:

```python
resp = await self.protocol.exchange_auth(
    FrameType.PS_Start,
    {PAIRING_DATA_KEY: write_tlv({TlvValue.Method: b"\x00", TlvValue.SeqNo: b"\x01"}), "_pwTy": 1},
)
```

Two extra top-level OPACK keys appear alongside `_pd`, both integer-valued, both undocumented beyond their literal use:

- `"_pwTy": 1` — sent on every pair-setup frame (`PS_Start` and both `PS_Next` calls, `auth.py:57-62,85-93,102-112`), never on pair-verify frames. Read as "password type" by inference from the name; value is always the literal `1`, no other value ever appears anywhere in pyatv.
- `"_auTy": 4` — sent only on the pair-verify `PV_Start` frame (`auth.py:139-144`), never repeated on `PV_Next`. Read as "auth type" by inference; value always literal `4`.

Neither key is read back from any response anywhere in pyatv's client code (grepped `_pwTy`/`_auTy` — only ever written, never inspected on `resp`). A Rust port should send these exact literal integers at the exact frame types above for interop, without over-interpreting their semantics beyond what's observable.

**Frame types used** (`pyatv/protocols/companion/connection.py:21-40`): `PS_Start=3`/`PS_Next=4` for pair-setup, `PV_Start=5`/`PV_Next=6` for pair-verify.

**begin/finish/pin** (`pyatv/protocols/companion/pairing.py:18-78`): structurally identical flow to MRP (`start_pairing`→salt/pubkey capture, `finish_pairing`→step1..step4), same tautological-proof-check gap (`companion/auth.py:96-98`: `atv_proof` read, logged, never checked), same `# TODO: check status code` after pair-verify M3/M4 (`companion/auth.py:162`). `pin(pin)` also zero-pads to 4 digits (`companion/pairing.py:75-78`). **Difference from MRP**: `finish()` does **not** perform an immediate pair-verify after pair-setup succeeds (`companion/pairing.py:52-68` — only `finish_pairing` is called, credentials stored, `_has_paired = True`; no `CompanionPairVerifyProcedure` construction anywhere in this file) — Companion pairing is considered complete on SRP-handshake success alone, unlike MRP's stronger post-hoc verify requirement. `display_name` is passed through as `self._name` (default `"pyatv"`, `companion/pairing.py:24,64`), so Companion pair-setup **always** sends a `Name` TLV (§2.8) unlike MRP which never does.

### 9.3 AirPlay — `protocols/airplay/pairing.py` + `auth/{__init__.py,hap.py,hap_transient.py,legacy.py}`

**Dispatch** (`pyatv/protocols/airplay/auth/__init__.py:58-97`): `pair_setup(auth_type, connection)` — only `Legacy` and `HAP` are valid for **setup** (`Transient`/`Null` both raise `NotSupportedError`, since you can't "set up" a null or ephemeral pairing, only verify one). `pair_verify(credentials, connection)` — `Null`→`NullPairVerifyProcedure`, `Legacy`→`AirPlayLegacyPairVerifyProcedure`, `HAP`→`AirPlayHapPairVerifyProcedure`, and **the fall-through `else` branch** (i.e. `Transient`, since it's the only remaining `AuthenticationType` member) → `AirPlayHapTransientPairVerifyProcedure` — note this is an implicit `else`, not an explicit `credentials.type == AuthenticationType.Transient` check (`auth/__init__.py:93-97`); a Rust port using an exhaustive `match` should make this explicit rather than relying on "not one of the other three" being equivalent to Transient, since that equivalence only holds because `AuthenticationType` currently has exactly four members.

**Which `AuthenticationType` gets used for setup** is chosen entirely by **AirPlay major version**, not by mDNS flags (`pyatv/protocols/airplay/pairing.py:47-57`):

```python
self.pairing_procedure = pair_setup(
    AuthenticationType.HAP if self.airplay_version == AirPlayMajorVersion.AirPlayV2 else AuthenticationType.Legacy,
    self.http,
)
```

Contrast with **verify**'s default-type selection when no stored credentials exist (`extract_credentials`, `auth/__init__.py:120-133`), which **does** consult mDNS `features`/`ft` TXT-record flags: `AirPlayFlags.SupportsSystemPairing` or `AirPlayFlags.SupportsCoreUtilsPairingAndEncryption` present → `TRANSIENT_CREDENTIALS`; otherwise → `NO_CREDENTIALS` (→ `Null` → no auth at all attempted). These are two independent decision axes (setup-type by protocol version, verify-fallback-type by advertised capability) — do not conflate them into one "pick an AuthenticationType" function in the Rust port.

**HTTP framing** (`auth/hap.py:20-25`, `auth/hap_transient.py:23-28`, `auth/legacy.py:19-22`):

| Path | Method/route | Content-Type | Extra headers |
|---|---|---|---|
| `/pair-pin-start` (HAP + transient + legacy, all three send this first) | POST | (none set, empty body) | `User-Agent: AirPlay/320.20`, `Connection: keep-alive`, `X-Apple-HKP: 3` (HAP) or `4` (transient); legacy sends no `X-Apple-HKP` header at all |
| `/pair-setup` (HAP) | POST | `application/octet-stream` | `X-Apple-HKP: 3` |
| `/pair-setup` (transient) | POST | `application/octet-stream` | `X-Apple-HKP: 4` |
| `/pair-setup-pin` (legacy) | POST | `application/x-apple-binary-plist` | none beyond base headers |
| `/pair-verify` (HAP + transient) | POST | `application/octet-stream` | base headers, `Content-Type` re-set explicitly in `_send` (`hap.py:140-145`, `hap_transient.py:84-89`) |
| `/pair-verify` (legacy) | POST | `application/octet-stream` | base headers only, no `X-Apple-HKP` |

The `X-Apple-HKP` header **is the server-side dispatch key** distinguishing HAP (`"3"`) from transient (`"4"`) pair-setup (`airplay/server_auth.py:166-170`: `if auth_version == "3": ...hap; if auth_version == "4": ...transient; else: 501`) and gates whether `/pair-verify` is even handled at all (`airplay/server_auth.py:234-242`: anything other than `"3"` → `501 Not Implemented`, which is exactly the signal `FakeAirPlayService.handle_pair_verify` (`tests/fake_device/airplay.py:193-197`) uses to fall through to the **legacy** pair-verify handler — i.e. legacy pair-verify is detected server-side purely by the **absence** of a recognized `X-Apple-HKP` header value, via a `501` fallback chain, not by a distinct route).

**Transient pairing specifics** (`hap_transient.py:1-99`): fixed PIN `TRANSIENT_PIN = 3939` (`hap_transient.py:30`) — never user-supplied, never prompted; `verify_credentials()` runs the entire M1–M4 SRP exchange inline (there is no separate `start_pairing`/`finish_pairing` split — the docstring explains this is deliberately folded into the verify step, §4.4). Sets the `Flags: TransientPairing(0x10)` TLV on M1 (`hap_transient.py:51-57`) — the **only** place in all of pyatv that TLV is ever set. `encryption_keys()` uses `self.srp.shared_key` (SRP `K`), not X25519 `self._shared` (§4.4) — this is the biggest structural divergence from every other pair-verify path and must not be generalized away in a Rust trait design.

**Legacy pairing specifics** (`legacy.py:1-114`): body format is `plistlib.dumps(..., fmt=FMT_BINARY)` (Apple binary property list, **not** TLV8) for pair-setup (`legacy.py:71-81`), but **is** raw binary (no plist wrapper) for pair-verify (`legacy.py:103-106`, `Content-Type: application/octet-stream`, body = `srp.verify1()`'s raw bytes directly). `finish_pairing` returns `self.srp.credentials` directly (`legacy.py:69`) — **not** a value constructed from decrypted response data the way HAP's `step4` builds a fresh `HapCredentials` from the accessory's M6 payload; legacy AirPlay's "credentials" are simply the **same object passed in at construction** (`new_credentials()`, generated **before** pairing even starts, `pyatv/protocols/airplay/auth/__init__.py:64-67`), since legacy pairing never learns anything new about the *accessory's* identity — it only proves the *controller's* pre-existing identity to the accessory via the PIN-derived SRP session, so there is nothing new to persist from the exchange itself; what gets persisted is exactly the random `(ltsk_seed, client_id)` pair `new_credentials()` generated locally, independent of anything the accessory sent back.

**PIN prompt flow**: identical shape for all three AirPlay sub-flows and for MRP/Companion — `device_provides_pin` is `True` everywhere (never `False` in this codebase; grepped every `PairingHandler` subclass, all return the literal `True`), meaning pyatv always assumes the *accessory* displays the PIN and the *user* types it into the controller (never the reverse "controller displays PIN" flow that HAP also supports in principle) — a Rust port targeting only pyatv-equivalent behavior does not need to implement the display-PIN direction at all.

## 10. Tests worth porting as KATs

### 10.1 `tests/auth/test_hap_tlv8.py` — fully reproduced in §1.8. Port directly; zero external dependencies, pure encode/decode/stringify fixtures.

### 10.2 Legacy AirPlay device-auth — fully deterministic captured-session KAT

`tests/fake_device/airplay.py:19-45`. This is the single most valuable KAT in the whole codebase for legacy AirPlay: real captured request/response byte pairs from an actual working session, made **100% reproducible** because every source of randomness on the client side is pinned by construction:

- Client identity: `DEVICE_IDENTIFIER = "75FBEEC773CFC563"` (`tests/fake_device/airplay.py:20`, 8 bytes hex, used as `client_id`), `DEVICE_AUTH_KEY = "8F06696F2542D70DF59286C761695C485F815BE3D152849E1361282D46AB1493"` (`tests/fake_device/airplay.py:21`) — independently re-counted with `bun` during this pass (`"...".length === 64`): exactly 64 hex characters = 32 bytes, a valid Ed25519/X25519 seed length, consistent with `new_credentials`/`HapCredentials.ltsk`'s expectation (`tests/protocols/airplay/auth/test_airplay_legacy_auth.py:39`: `new_credentials(IDENTIFIER, DEVICE_AUTH_KEY)` unhexlifies it directly as `ltsk`). Copy this exact string into the Rust port's fixtures character-for-character rather than retyping it by hand.
- `DEVICE_PIN = 2271` (`airplay.py:22`).
- `client_id`/`seed` reuse: because `LegacySRPAuthHandler.step1` sets the SRP ephemeral private exponent from `binascii.hexlify(self._auth_private)` where `self._auth_private` is derived from the **fixed** `ltsk` seed above (§2.2 of the research report, confirmed unchanged in this pass), and `verify1`/`verify2` derive the X25519 keypair from the same fixed seed too (`srp.py:106-108`), **every value in the entire exchange is a deterministic function of `(DEVICE_IDENTIFIER, DEVICE_AUTH_KEY, DEVICE_PIN, accessory's fixed salt/pubkey)`** — which is why `tests/fake_device/airplay.py` can get away with a **pure byte-equality replay** server (`handle_pair_setup_pin`, `airplay.py:155-186`: match the incoming request body against one of three fixed hex strings, return the correspondingly fixed canned response; no actual SRP/crypto computation happens server-side for this path at all) rather than a real accessory-side crypto implementation.
- Fixed request/response hex pairs (`tests/fake_device/airplay.py:27-45`, reproduced verbatim — copy these exact strings into the Rust port's test fixtures character-for-character rather than retyping):
  - `_DEVICE_AUTH_STEP1` / `_DEVICE_AUTH_STEP1_RESP` — bplist `{method: "pin", user: <DEVICE_IDENTIFIER>}` request → salt+SRP-B response.
  - `_DEVICE_AUTH_STEP2` / `_DEVICE_AUTH_STEP2_RESP` — bplist `{pk: <A>, proof: <M1>}` request → SRP proof (`M2`) response.
  - `_DEVICE_AUTH_STEP3` / `_DEVICE_AUTH_STEP3_RESP` — bplist `{epk: <encrypted pubkey>, authTag: <GCM tag>}` request → bplist `{epk: <accessory's encrypted LTPK>, authTag: <...>}` response.
  - `_DEVICE_VERIFY_STEP1` / `_DEVICE_VERIFY_STEP1_RESP` — raw (non-plist) pair-verify M1 (`0x01000000 || verify_pub || auth_pub`) → raw accessory response (32-byte accessory X25519 pubkey + opaque trailing blob, §5.5).
  - `_DEVICE_VERIFY_STEP2` / `_DEVICE_VERIFY_STEP2_RESP` — raw M3 (`0x00000000 || CTR-ciphertext`) → **empty response** (`_DEVICE_VERIFY_STEP2_RESP = b""`, comment "Value not used by pyatv" — confirming `AirPlayLegacyPairVerifyProcedure.verify_credentials` never reads the response body from the final POST at all, `legacy.py:100`, only awaits it for the side effect of confirming a `200`-shaped response was returned, implicitly via `HttpConnection.post` not raising).
- Consuming test: `tests/protocols/airplay/auth/test_airplay_legacy_auth.py:1-71`, full file, six test functions (`test_verify_invalid`, `test_verify_authenticated`, `test_verify_has_no_encryption_keys`, `test_pairing_failed`, `test_pairing_successful`) exercising both success and deliberate-failure (`INVALID_AUTH_KEY = 32 * "00"`, an all-zero seed that produces a different, non-matching derived identity — mismatches the fixed captured bytes, so the fake server's byte-equality match fails and it returns `403`) paths.

### 10.3 `tests/protocols/airplay/test_airplay_verify.py` — HAP pair-verify KAT anchored to `CLIENT_CREDENTIALS`

Full file, `tests/protocols/airplay/test_airplay_verify.py:1-42`, parametrized over five credential shapes. Traced the fixture chain (`airplay_conf` → `airplay_device` → `FakeAppleTV.add_service(Protocol.AirPlay)`, `tests/protocols/airplay/conftest.py:14-21,44-51`): this test runs against **the same** `tests/fake_device/airplay.py::FakeAirPlayService` used by the legacy-pairing tests in §10.2 — i.e. `pin=DEVICE_PIN=2271` (`tests/fake_device/airplay.py:59-61`), **not** the bare `PIN_CODE=1111` default `AirPlayServerAuth` would otherwise use. `SERVER_IDENTIFIER`/`PRIVATE_KEY` are left at their `pyatv/auth/server_auth.py` defaults (`FakeAirPlayService.__init__` only overrides `name`/`pin`, `tests/fake_device/airplay.py:59-61`). This matters for reproducing this specific KAT: use PIN `2271`, not `1111`, when building the server side of this exact test.

```python
@pytest.mark.parametrize("credentials, expectation", [
    (parse_credentials(DEVICE_CREDENTIALS), does_not_raise()),
    (parse_credentials(f"{8*'00'}:{32*'11'}"), pytest.raises(AuthenticationError)),
    (parse_credentials(CLIENT_CREDENTIALS), does_not_raise()),
    (parse_credentials(f"{32*'00'}:{32*'11'}:{36*'22'}:{36*'33'}"), pytest.raises(AuthenticationError)),
    (TRANSIENT_CREDENTIALS, does_not_raise()),
])
async def test_verify(airplay_conf, credentials, expectation): ...
```

The `parse_credentials(CLIENT_CREDENTIALS)` case is the **fully independently-verifiable-offline** one (§8): given `CLIENT_CREDENTIALS`'s hard-coded `ltpk`/`ltsk`/`atv_id`/`client_id`, and a server built from `PRIVATE_KEY`/`SERVER_IDENTIFIER`, pair-verify must succeed with no network capture needed to construct the KAT — this is the strongest recommended starting point for a Rust hermetic pair-verify test, since both sides' key material is fully specified in source and independently checkable (as done in §8 of this document).

### 10.4 `tests/protocols/mrp/test_mrp_auth.py` and `tests/protocols/companion/test_companion_auth.py` — full pair-setup+verify round-trip KATs

Both fully reproduced above (§9's context plus the direct reads at the top of this research pass). Key assertions worth porting as behavioral (not byte-exact) KATs:

- `test_pairing_with_device`: fresh pairing → `state.has_paired`/`state.has_authenticated` both become `True` server-side, `service.credentials` becomes non-`None`, and for MRP specifically, storage (`MemoryStorage`) receives the same credentials string (`test_mrp_auth.py:56-58`).
- `test_pairing_with_existing_credentials`: pre-seeding `service.credentials = CLIENT_CREDENTIALS` before pairing still requires `begin()`/`pin()`/`finish()` to succeed (existing credentials do not short-circuit the flow) — worth checking the Rust port doesn't accidentally treat "already have credentials" as "already paired" without actually driving the state machine, since pyatv explicitly re-runs full pair-setup even with credentials present.
- `test_pairing_with_bad_pin` (both protocols): wrong PIN → `PairingError` raised from `finish()`, and critically `state.has_authenticated`/`has_paired` remain `False` and `service.credentials` remains `None` — confirms the **server-side** SRP proof check (`session.verify_proof(...)`, in `_m3_setup`, e.g. `mrp/server_auth.py:188-205`) is what actually enforces correctness end-to-end, since the **client-side** check is the tautology described in §2.7 — the real security property ("wrong PIN is rejected") is provided entirely by the **accessory**, not the controller, in pyatv's design. This is worth stating plainly for the Rust port's threat model: **a pyatv-equivalent client's own code provides no defense against a malicious/buggy accessory silently "succeeding" pair-setup with mismatched keys; correctness of the PIN check is delegated entirely to the accessory being honest.** If the Rust port wants an actual client-side guarantee (e.g. detecting a MITM relay attack during pairing, which SRP is designed to prevent), it must add the verification pyatv omits (§2.7, §2.9) rather than port pyatv's checks as-is.
- `test_authentication` (`test_mrp_auth.py:106-111`): pre-seeded `CLIENT_CREDENTIALS`, plain `pyatv.connect()` (no pairing at all) → `state.has_authenticated` becomes `True` purely from the connect-time pair-verify pyatv always performs when credentials exist (`mrp/protocol.py:206-219`'s `_enable_encryption`, called unconditionally whenever `service.credentials is not None`).

### 10.5 `tests/protocols/airplay/auth/test_auth.py` — dispatch-only, not crypto KATs

`tests/protocols/airplay/auth/test_auth.py:1-79`, full file. Pure `unittest.mock`-based tests of `pair_setup`/`pair_verify`'s type dispatch (§9.3's table) — worth porting as unit tests of whatever dispatch function the Rust port has, but contain no cryptographic assertions at all (SRP handler construction is mocked out entirely via `patch("pyatv.protocols.airplay.auth.LegacySRPAuthHandler")`).

## 11. Divergences & open questions

Ranked roughly by how much they matter for a from-scratch Rust implementation deciding "replicate pyatv exactly" vs. "be more correct than pyatv":

1. **Client-side SRP proof verification is a no-op tautology in both the HAP and legacy profiles** (§2.7; `hap_srp.py:157-158` and the identical pattern at `pyatv/protocols/airplay/srp.py:177-178`). `SRPClientSession.verify_proof(key_proof)` (`srptools/client.py:40-42`) compares `self.key_proof_hash` against itself. **No call site anywhere in pyatv's tree passes the accessory's actual M4/step2-response proof value into this check** — the accessory's real proof (`atv_proof`, read from the M4 TLV response in `mrp/auth.py:71`, `companion/auth.py:97`) is captured into a local variable and only ever logged, in every one of the four call sites (MRP, Companion, AirPlay HAP, AirPlay transient — grepped all `step2(` callers). **This is not a corner case pyatv "hasn't gotten to" — it's structural: `step2`'s function signature has no parameter for it.** A from-scratch Rust port should almost certainly implement real verification (compare the accessory's transmitted `M2`/key-proof-hash TLV value against the locally computed one) since doing so is strictly more correct, costs nothing in interop against honest accessories, and closes an actual MITM/wrong-PIN-detection gap that SRP is specifically designed to provide. Document this as an intentional, security-relevant deviation from pyatv, not an oversight.

2. **`# TODO: verify signature here`** (`hap_srp.py:229`, §2.9) — the accessory's M6 Ed25519 signature is decoded but never checked against its claimed LTPK. Same recommendation as above: verify it in the Rust port.

3. **`# TODO: check status code`** appears after every pair-verify M3/M4 exchange in MRP (`mrp/auth.py:115`), Companion (`companion/auth.py:162`), and AirPlay HAP (`hap.py:136`) — the response to the final pair-verify POST/message is awaited but its `status`/HTTP-code/`Error` TLV is never inspected for success. Combined with finding 1, **pyatv's pair-verify success/failure signal is derived almost entirely from "did decryption/parsing not throw", not from an explicit protocol-level acknowledgement**. A Rust port should decide whether to check status/error codes explicitly (recommended) even though pyatv does not.

4. **Legacy AirPlay pair-verify's opaque trailing `data` blob** (`legacy.py:99`, `# TODO: what is this?`) is CTR-keystream-advanced-but-discarded per §5.5's exact arithmetic, not merely "encrypted alongside the signature" as the research report summarized — replicate the keystream-offset behavior precisely (§5.5), do not attempt to interpret or reconstruct the blob's meaning.

5. **The AES-CTR IV `+1` bump can overflow and crash pyatv itself** (§5.5, `srp.py:188`) — a pure Python `bytearray` assignment overflow, not a protocol requirement; a Rust port should use a wrapping add and not treat pyatv's crash-on-overflow as behavior to replicate.

6. **No unit tests exist for `hap_srp.py` or `hap_pairing.py` in isolation** — `tests/auth/` contains only `test_hap_tlv8.py`. All SRP/HKDF/Ed25519 behavior is only exercised indirectly through the full-stack functional tests in `tests/protocols/{mrp,companion,airplay}/`. This means there is **no pyatv-authored KAT that isolates, e.g., "given this PIN/salt/B, the client's `A`/`M1` must equal this exact hex"** — the closest available is the fully-reproducible legacy-AirPlay capture (§10.2) and the independently-derivable `CLIENT_CREDENTIALS` anchor (§8, §10.3). A Rust port aiming for a true byte-level SRP KAT (not just "the two sides agree with each other") will need to **generate its own** fixed-input KAT by running pyatv itself once with monkey-patched randomness and capturing the output — this document cannot supply one that doesn't already exist in the pyatv tree, and the task's request to "flag any unverified assumptions" applies directly here: **the exact SRP `A`/`M1`/`K` hex values for a given fixed `(a, PIN, salt, B)` were not independently computed in this research pass** (no Python interpreter was available in this sandbox to run `srptools` directly — confirmed by `command -v python3` returning nothing; only `bun`/Node was available, which was used for the Ed25519/DER checks in §8 that don't require `srptools`). If byte-exact SRP arithmetic verification is required before the Rust port ships, run pyatv's actual `srptools`-backed code once with fixed inputs and capture the outputs as a new KAT file — do not trust this document's SRP formulas without that cross-check, even though they were read directly from `srptools` source rather than inferred.

7. **Transient AirPlay pairing has zero test coverage in pyatv** (§6.5/§9.3 — confirmed via `grep -rln "hap_transient\|TransientPairing\|3939" tests/` returning nothing). The only "specification" for this path is the implementation itself plus the server reference's `transient=True` branch (`airplay/server_auth.py:338-352`). A Rust port's transient-pairing implementation cannot be checked against any existing pyatv test; real-device testing or a hand-written KAT (buildable from §4.4 + §6.5, since all the pieces — fixed PIN 3939, SRP-K-derived transport keys, `Flags` TLV — are individually well-specified even without an end-to-end pyatv test) is the only validation path.

8. **Undocumented raw TLV tag `27` (0x1B)** in the Companion server reference's pair-setup M2 (`companion/server_auth.py:150`, `27: b"\x01"`) — not in `TlvValue`, not interpreted by pyatv's own client code (which never reads it back), origin/meaning unknown. Likely an Apple-internal tag pyatv's author captured from a real device trace without identifying it. Port note: if implementing the accessory/server role, replicate its presence for interop with real pyatv-family clients that might expect it (none currently look for it, but a future pyatv version might); if implementing only the controller/client role, this can be ignored entirely (the pyatv client never reads it).

9. **Zero-length-value omission in `write_tlv`** (§1.6) — not a bug pyatv is ever affected by in practice (no call site constructs an intentionally-empty TLV value), but a Rust port's TLV8 encoder should decide explicitly whether to replicate the omission (silently drop empty-valued entries) or diverge (always emit a `tag,0x00` entry) — recommend replicating pyatv's behavior only where wire-compatibility with a real pyatv-family peer is required, and preferring the more-explicit `tag,0x00` form for the port's own accessory/server role if that role is new code with no interop constraint forcing the omission.

10. **`srp` (RustCrypto) 0.7.0 pre-release API risk** — unchanged from the research report §9.6, not re-verified in this pass (out of scope for a source-reading exercise against pyatv; re-check crates.io before implementation as that report already recommends).

## 12. Building the hermetic Rust test harness (recap for item 5)

This section ties §5–§8 together into a concrete recipe for a Rust `pyatv-pairing` test crate that can run full client-vs-server pairing/verify round trips with no real Apple TV, mirroring what `pyatv/auth/server_auth.py` + the three `pyatv/protocols/*/server_auth.py` give pyatv's own test suite.

**Fixed identity material to hard-code** (all from `pyatv/auth/server_auth.py:1-13`, §8):

```
SERVER_PRIVATE_KEY_SEED = [0xAA; 32]     // both Ed25519 seed AND X25519 scalar (§6)
SERVER_IDENTIFIER       = "5D797FD3-3538-427E-A47B-A32FC6CF3A6A"
CLIENT_IDENTIFIER       = "4D797FD3-3538-427E-A47B-A32FC6CF3A6A"
PIN_CODE                = 1111  // MRP / Companion reference server default
CLIENT_CREDENTIALS      = "e734ea6c...6b58:80fd8265...37b1:5D797FD3-...:4D797FD3-..."
                            // (hex-decode the third/fourth fields as ASCII UUID text)
```

**Server role, per protocol** — implement the equivalent of `generate_keys` (§6) once, shared across protocols: derive a signing (Ed25519) and a verify (X25519) keypair from `SERVER_PRIVATE_KEY_SEED`, both from the same 32 bytes, generated once at server construction (not per-session — §6 flags this is intentionally non-forward-secret test-only behavior, replicate it for determinism, not for anything resembling production accessory code). Then implement the five handler methods common to all three `*_server_auth.py` files (`_m1_verify`, `_m3_verify`, `_m1_setup`, `_m3_setup`, `_m5_setup`, §5.1's tables in §4.1/§4.2 for the exact salts each one uses) as one shared "reference accessory" core, with only the outer transport framing (protobuf+varint for MRP, OPACK+4-byte-header for Companion, HTTP+TLV8 for AirPlay) varying per protocol — this mirrors pyatv's own structure (`ABC` base class with `send_to_client`/`enable_encryption` as the only protocol-specific abstract methods, e.g. `mrp/server_auth.py:241-247`).

**Client-side KATs to run against this server, in order of increasing setup cost**:

1. **Pair-verify only**, using `CLIENT_CREDENTIALS` directly (§8, §10.3) — no pair-setup round trip needed at all, exercises M1–M4 of pair-verify plus transport-key derivation (§4.2/§4.3) in isolation. This is the cheapest, most deterministic KAT to get passing first — both sides' long-term keys are fully specified in source, nothing is randomly generated except each side's per-session X25519 ephemeral (which cancels out via ECDH regardless of its random value, so the *test* is deterministic even though the *ephemeral* isn't — only the final derived transport keys need to match between the Rust client and Rust server's independently-computed values, not any fixed expected hex constant).
2. **Full pair-setup with fixed PIN `1111`**, fresh random identity — exercises SRP M1–M6 (§2.6–§2.9) end-to-end; assert the resulting `HapCredentials` successfully pair-verifies against the same server afterward (mirrors `test_pairing_with_device`, §10.4).
3. **Wrong-PIN rejection** — assert `finish_pairing` (or whatever the Rust equivalent is called) surfaces an error when the server's `_m3_setup` returns an `Error` TLV (§9's `test_pairing_with_bad_pin` KAT, §10.4) — this is the test that actually exercises the **server's** SRP proof check, since as documented in §11 finding 1, the client-side check does not.
4. **Legacy AirPlay full replay**, using the fixed hex captures in §10.2 verbatim — this one is special: it is not "run a Rust client against a Rust server", it is "run a Rust client against pyatv's own fixed byte sequences", i.e. a **protocol conformance test independent of any Rust server implementation at all**. Build this by implementing a trivial byte-equality-replay HTTP responder (exactly what `tests/fake_device/airplay.py:155-186` does) fed the five hex pairs from §10.2, and assert the Rust `LegacySRPAuthHandler` equivalent, given `DEVICE_IDENTIFIER`/`DEVICE_AUTH_KEY`/`DEVICE_PIN`, produces byte-identical outbound requests at each step. This is the strongest possible KAT in this entire document because it was captured from **real interoperating software**, not derived from reading pyatv's own source a second time.
5. **Transient AirPlay** (§4.4, §6.5, §11.7) — no pyatv KAT exists; write this test purely from the specification in §4.4/§6.5/§9.3 (fixed PIN `3939`, `Flags=TransientPairing` TLV on M1, SRP-`K`-derived transport keys, no M5/M6) and validate Rust-client-vs-Rust-server self-consistency only; flag in the test's own comments that it has no independent pyatv-derived ground truth to check against, per §11 finding 7.

## Corrections to `crypto-pairing.md`

Consolidated list of every place this deeper read found the existing research report imprecise, incomplete, or wrong. Section numbers below refer to `docs/research/crypto-pairing.md`.

1. **§1 / §3, `HAPSession` scope claim is wrong.** The report lists `pyatv/auth/hap_session.py` as "used via `AbstractHAPChannel`/`setup_channel` for MRP, AirPlay control, AirPlay events, AirPlay data-stream". **MRP does not use `HAPSession` at all** — it uses `Chacha20Cipher8byteNonce` directly on whole protobuf messages with a varint length prefix that is not AAD and no 1024-byte chunking (§4.0, §5.3 of this document). Companion likewise never touches `HAPSession` (correctly described independently in the report's own §5.3, but the §1/§3 file-index entry's blanket claim about `hap_session.py`'s consumers is inconsistent with that). Only the three AirPlay-specific channels (control, events, data-stream) actually use it.

2. **§2.1, the seed-reuse quirk is mis-scoped as legacy-AirPlay-only when it also applies to the modern HAP profile.** The report's §6 states the SRP-ephemeral-equals-Ed25519-seed reuse as a **legacy AirPlay** ("§5.4, §6") quirk to replicate. In fact `hap_srp.py:147-149` does the identical thing for **every** HAP-profile pairing (MRP, Companion, HAP/transient AirPlay) — `SRPClientSession(context, hexlify(self._auth_private))`. This is a correction, not an addition: the report's own §2.1 walkthrough of `step1` quotes this exact line but doesn't flag the reuse, then later (§6) describes the reuse as if it were a legacy-only oddity.

3. **§3's HKDF salt/info table is correct on strings but silent on the client/server key-role-swap mechanics**, which turn out to differ *by protocol* in *how* the swap is implemented (call-site positional swap for MRP, assignment-time swap for AirPlay control, no swap needed for Companion because its info strings are already role-unambiguous). §4.3 of this document supplies the missing mechanics with exact line citations; get this wrong in a hermetic test-server implementation and encryption silently breaks in one direction only.

4. **§3's table omits transient AirPlay's distinct IKM entirely** — it lists `Pair-Verify-Encrypt-Salt`/`-Info` with IKM "X25519 ECDH shared secret" as if that's universal, but transient pairing's `encryption_keys()` uses the **SRP session key `K`**, not any X25519 output at all (§4.4 of this document, `hap_transient.py:91-99`), because transient pairing never performs the X25519-based pair-verify handshake in the first place. This is a materially different, previously-undocumented IKM source.

5. **§4's TLV8 tag table is accurate but incomplete**: missing the undocumented raw tag `27` used server-side by the Companion reference implementation (§1.1, §11.8 of this document), and doesn't note the `write_tlv` zero-length-value omission bug (§1.6, §11.9) or the insertion-order (not tag-order) wire encoding requirement (§1.6).

6. **§9 (Open Questions), first bullet, is answered by this pass and should be closed, not left open**: "Does pyatv's `H(g)` unpadding in M1 apply identically to the legacy 2048-bit/SHA-1 AirPlay profile?" — **Yes, confirmed by direct read of `srptools/context.py:213-232`** (`get_common_session_key_proof`, the single shared method both `SRPContext` and the legacy-profile's `AtvSRPContext` subclass inherit unchanged): `h(self._prime) ^ h(self._gen)` calls `self.hash(self._gen)` with **no padding** — `hash()`'s `conv()` helper (`context.py:84-93`) converts an int argument via `int_to_bytes()`, which is `unhexlify(hex_from(val))`, i.e. the **minimal-length** big-endian encoding, not padded to `len(N)`. Both SRP profiles pyatv uses share this exact code path (`AtvSRPContext` only overrides `get_common_session_key`, not `get_common_session_key_proof` — `pyatv/protocols/airplay/srp.py:59-69`), so **both the 3072-bit/SHA-512 HAP profile and the 2048-bit/SHA-1 legacy-AirPlay profile use unpadded `H(g)` in M1, identically, with no divergence between them.** This can now be stated as verified fact rather than an open question requiring a real-device capture. `u = H(PAD(A) || PAD(B))` (`context.py:120-127`, uses `self.pad(...)` explicitly) and `k = H(N || PAD(g))` (`context.py:42-43`, also explicit `self.pad`) remain padded in both profiles, confirmed unchanged from the report's original claim.

7. **§9's `srp` 0.7.0-rc.3 fit analysis was not re-verified in this pass** (out of scope for a pyatv-source-reading exercise) — still flagged in this document's own §11.10 as needing a pre-implementation re-check, consistent with the original report's own caveat.

8. **General**: the original report's §5.4 description of the legacy-AirPlay opaque `data` blob as "that trailing device-supplied blob is encrypted alongside the signature" is imprecise in a way that would produce wire-incompatible output if implemented literally — "encrypted alongside" reads as "concatenated then encrypted" or "both encrypted and both sent", but the actual behavior (§5.5, §11.4 of this document) is "keystream-advanced through but its ciphertext discarded, never transmitted." This is the correction most likely to cause a subtly-wrong-but-plausible-looking Rust implementation if the original report's wording were followed instead of the exact code.
