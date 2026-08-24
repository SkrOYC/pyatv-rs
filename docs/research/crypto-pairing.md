# Cryptography and pairing stack: primitives and Rust crate mapping

Research date: 2026-08-24. Primary source: [github.com/postlund/pyatv](https://github.com/postlund/pyatv), master branch, shallow-cloned and read directly (files cited by path below). Crate data verified live against the crates.io API (`https://crates.io/api/v1/crates/<name>`) on 2026-08-24; do not trust version numbers from training data — re-verify before pinning if this report is read much later. This document assumes the reader has the pyatv-architecture.md report from this same research batch for wire-protocol context and focuses only on the crypto/pairing layer.

## 1. Where this lives in pyatv

- `pyatv/auth/hap_pairing.py` — `HapCredentials`, `AuthenticationType` enum (`Null`, `Legacy`, `HAP`, `Transient`), credential string parsing.
- `pyatv/auth/hap_srp.py` — the shared HAP/SRP engine (`SRPAuthHandler`) used identically by MRP, Companion, and modern (HAP-based) AirPlay. Contains `hkdf_expand()`.
- `pyatv/auth/hap_tlv8.py` — TLV8 codec + all standardized `TlvValue`/`Method`/`State`/`ErrorCode` constants.
- `pyatv/auth/hap_session.py` — `HAPSession`: the 1024-byte-block ChaCha20-Poly1305 framing used for encrypted transport after pair-verify.
- `pyatv/auth/hap_channel.py` — `AbstractHAPChannel` + `setup_channel()`: generic "connect a TCP socket and immediately wrap it in a HAPSession" helper, reused by AirPlay's event/data-stream channels.
- `pyatv/support/chacha20.py` — thin wrapper around `chacha20poly1305_reuseable` (PyPI) with two nonce-construction modes.
- `pyatv/protocols/airplay/srp.py` — **separate**, non-HAP SRP engine (`LegacySRPAuthHandler`, `AtvSRPContext`) for legacy (pre-HAP) AirPlay device authentication.
- `pyatv/protocols/{mrp,companion,airplay}/auth.py` and `airplay/auth/{hap.py,hap_transient.py,legacy.py,__init__.py}` — per-protocol glue that drives `SRPAuthHandler`/`LegacySRPAuthHandler` over each protocol's transport and defines the transport-key HKDF salt/info strings.
- `pyatv/protocols/{mrp,companion,airplay}/server_auth.py` — a **test/reference server-side implementation** of the same protocols (used by pyatv's own test suite and `atvproxy.py`). Extremely useful because it makes explicit the accessory-side salts pyatv itself never has to compute (e.g. `Pair-Setup-Accessory-Sign-Salt`), letting us cross-check the full salt table.

## 2. SRP6a: two genuinely different profiles

pyatv runs **two unrelated SRP configurations** depending on which pairing generation a device speaks. Do not merge them into one code path.

### 2.1 HAP profile (MRP, Companion, modern/HAP AirPlay, transient AirPlay)

Implemented in `pyatv/auth/hap_srp.py::SRPAuthHandler.step1`:

```python
context = SRPContext("Pair-Setup", str(pin), prime=constants.PRIME_3072, generator=constants.PRIME_3072_GEN, hash_func=hashlib.sha512)
```

- Group: **RFC 5054 3072-bit MODP group, generator `5`** (the same constant hex blob as `srp::groups::G3072` in RustCrypto's `srp` crate — verified byte-for-byte against `srptools/constants.py`'s `PRIME_3072`).
- Hash: **SHA-512** throughout (x, u, k, K, M1, M2 all use SHA-512, not SHA-1).
- "Username" (`I` in RFC 5054 terms) is the **literal ASCII string `"Pair-Setup"`** — not a real per-device identity. Password `P` is the on-screen PIN, stringified.
- `x = H(salt | H(I | ":" | P))` — standard RFC 5054 formula, with the literal username above. This is a case that RustCrypto `srp`'s default (`username_in_x = true`) handles correctly out of the box, no special-casing needed.
- Premaster secret `S` computed the standard way: `S = (B - k·g^x)^(a + u·x) mod N`.
- Session key `K = H(S)` — a single SHA-512 hash of `S`, **not** the interleaved/doubled-hash trick (see §2.2). This matches RustCrypto's default `process_reply()` behavior.
- Proof `M1`: pyatv delegates this to `srptools`' `SRPClientSession`/`SRPContext.get_common_session_key_proof`, whose source (`srptools/context.py`, verified from the PyPI sdist for `srptools==1.0.1`) is:
  ```
  M1 = H(H(N) XOR H(g) | H(I) | s | A | B | K)
  ```
  Critically, **`H(g)` here is UNPADDED** — `srptools` hashes the raw big-endian bytes of `g` (a single byte `0x05` for the 3072-bit group), not `g` zero-padded out to `len(N)` bytes. This is the exact HAP-specific deviation from the "textbook" RFC 5054 M1 formula that most SRP libraries implement with padded `g`. It is the single most important gotcha for interop.
  - `M2 = H(A | M1 | K)` (standard, matches RFC 5054).
  - `u = H(PAD(A) | PAD(B))` — this one **is** padded (standard RFC 5054, matches RustCrypto's `compute_u_padded`).
  - `k = H(N | PAD(g))` — **also padded** (standard RFC 5054 multiplier; only the M1 term differs).
- After SRP completes, pyatv layers **HKDF-SHA512** on top of `K` (not on top of the raw premaster secret `S`) to derive protocol-level Ed25519 signing inputs and the M5/M6 encryption key — see §3.

### 2.2 Legacy AirPlay device-auth profile (`AuthenticationType.Legacy`, pre-HAP AirPlay 1 / early AirPlay 2 "device auth")

Implemented in `pyatv/protocols/airplay/srp.py::LegacySRPAuthHandler` + `AtvSRPContext`:

```python
context = AtvSRPContext(str(username), str(password), prime=constants.PRIME_2048, generator=constants.PRIME_2048_GEN)
```

- Group: **2048-bit MODP group, generator `2`** (RFC 5054 2048-bit group — matches RustCrypto's `srp::groups::G2048`).
- Hash: **no `hash_func` argument is passed**, so `srptools.SRPContext` falls back to its default, which is **SHA-1** (`srptools/constants.py`: `HASH_SHA_1 = hashlib.sha1`). This is confirmed by reading the actual default, not assumed. So x, u, k, and M1 in this profile are all SHA-1-based, standard RFC 5054 shape (this profile does **not** have the unpadded-`g` quirk of §2.1 — that quirk is generic to `srptools`' `get_common_session_key_proof`, which both profiles share, so actually **both profiles use unpadded `H(g)` in M1** — flag this for verification with a captured real packet trace, see Open Questions).
- Username here is the AirPlay client identifier (hex-encoded, uppercased 8-byte random ID from `new_credentials()`), not a literal string.
- **Non-standard session key derivation.** `AtvSRPContext.get_common_session_key` overrides the base class:
  ```python
  def get_common_session_key(self, premaster_secret):
      k_1 = self.hash(premaster_secret, b"\x00\x00\x00\x00", as_bytes=True)
      k_2 = self.hash(premaster_secret, b"\x00\x00\x00\x01", as_bytes=True)
      return k_1 + k_2
  ```
  i.e. `K = SHA1(S || 0x00000000) || SHA1(S || 0x00000001)`, a 40-byte key, **not** the single-hash `K = H(S)` of standard SRP-6a. This is reminiscent of (but not identical to) the classic "interleaved SHA1" trick from the original SRP-6/RFC 2945 draft used to stretch a 160-bit hash output for AES-256 — Apple's variant here is simpler (two whole-value hashes with a 4-byte big-endian counter suffix, not bit-interleaving of even/odd bytes). **No off-the-shelf SRP crate implements this** — it must be built manually on top of the crate's exposed premaster-secret primitive.
- Pair-verify (device verification) for legacy AirPlay does **not** reuse SRP or HKDF at all. It derives AES key material directly from an X25519 shared secret with plain SHA-512, see §5.3.

## 3. HKDF-SHA512: exact salt/info strings

pyatv always uses **HKDF with SHA-512**, 32-byte output, via `pyatv/auth/hap_srp.py::hkdf_expand(salt: str, info: str, shared_secret: bytes)` — salt and info are ASCII strings encoded with `.encode()` (UTF-8, but always plain ASCII in practice), IKM is raw bytes. This one function is reused for every derivation below except the legacy-AirPlay path (§2.2/§5.3), which uses raw SHA-512 concatenation, not HKDF.

Universal, protocol-independent (same string literals regardless of MRP/Companion/AirPlay — defined once in `hap_srp.py` and mirrored in each `server_auth.py`):

| Purpose | Salt | Info | IKM | Consumer |
|---|---|---|---|---|
| Pair-Setup: controller Ed25519 signing input (`iOSDeviceX`) | `Pair-Setup-Controller-Sign-Salt` | `Pair-Setup-Controller-Sign-Info` | SRP session key `K` (hex-decoded `self._session.key`) | `hap_srp.py` step3 |
| Pair-Setup: M5/M6 TLV encryption key | `Pair-Setup-Encrypt-Salt` | `Pair-Setup-Encrypt-Info` | SRP session key `K` | `hap_srp.py` step3/step4 |
| Pair-Setup: accessory Ed25519 signing input (server/device side only) | `Pair-Setup-Accessory-Sign-Salt` | `Pair-Setup-Accessory-Sign-Info` | SRP session key `K` | `*/server_auth.py` (needed if you ever implement the accessory role, e.g. for test tooling) |
| Pair-Verify: M2/M3 TLV encryption key | `Pair-Verify-Encrypt-Salt` | `Pair-Verify-Encrypt-Info` | X25519 ECDH shared secret | `hap_srp.py::verify1` |

Per-protocol **transport session keys** (derived from the X25519 shared secret established during pair-verify, via `SRPAuthHandler.verify2(salt, output_info, input_info)`):

| Protocol / channel | Salt | Output (write) info | Input (read) info | Source |
|---|---|---|---|---|
| MRP main connection | `MediaRemote-Salt` | `MediaRemote-Write-Encryption-Key` | `MediaRemote-Read-Encryption-Key` | `pyatv/protocols/mrp/protocol.py` |
| Companion main connection | `""` (**empty string**) | `ClientEncrypt-main` | `ServerEncrypt-main` | `pyatv/protocols/companion/protocol.py` |
| AirPlay RTSP control connection | `Control-Salt` | `Control-Write-Encryption-Key` | `Control-Read-Encryption-Key` | `pyatv/protocols/airplay/auth/__init__.py::verify_connection` |
| AirPlay event channel | `Events-Salt` | `Events-Write-Encryption-Key` | `Events-Read-Encryption-Key` | `pyatv/protocols/airplay/ap2_session.py` — **note**: because the TCP connection for this channel is opened by the *receiver* (the roles are physically reversed vs. control), pyatv calls `setup_channel(..., EVENTS_SALT, EVENTS_READ_INFO, EVENTS_WRITE_INFO)`, i.e. it swaps which info string is used as "output" vs "input" relative to every other channel. Get this backwards and you'll decrypt garbage in exactly one direction. |
| AirPlay data-stream channel (remote-control tunnel over AirPlay 2) | `DataStream-Salt` **+ decimal string of a random 64-bit `seed`** chosen client-side per session (e.g. `"DataStream-Salt3141592653589793"`) | `DataStream-Output-Encryption-Key` | `DataStream-Input-Encryption-Key` | `pyatv/protocols/airplay/ap2_session.py::_setup_data_channel` — the `seed` is also sent to the device in the RTSP `SETUP` body as an integer field `"seed"`, so both sides can reconstruct the salt string. |

## 4. TLV8 encoding (`pyatv/auth/hap_tlv8.py`)

Trivial, worth hand-rolling rather than pulling a dependency (see §7.6):

- Each entry: `1-byte tag | 1-byte length (0-255) | value bytes`.
- Values longer than 255 bytes are **split into multiple consecutive entries with the same tag**, each ≤255 bytes; the decoder concatenates same-tag runs back together (`read_tlv`'s `_parse` does `result[tag] += value` when the tag repeats). This only works correctly when duplicate-tag chunks are contiguous in the stream, which is what all pyatv writers guarantee — do not assume TLV8 is order-independent in general, only that pyatv's own encoder is well-behaved.
- No nested TLV support (single level only) — matches the module's own docstring caveat.
- Standardized tag values pyatv defines (`TlvValue` IntEnum): `Method=0x00, Identifier=0x01, Salt=0x02, PublicKey=0x03, Proof=0x04, EncryptedData=0x05, SeqNo=0x06, Error=0x07, BackOff=0x08, Certificate=0x09, Signature=0x0A, Permissions=0x0B, FragmentData=0x0C, FragmentLast=0x0D`, plus two Apple-internal-looking extras pyatv also relies on: `Name=0x11, Flags=0x13`.
- `Method`: `PairSetup=0x00, PairSetupWithAuth=0x01, PairVerify=0x02, AddPairing=0x03, RemovePairing=0x04, ListPairing=0x05`.
- `State` (used as the value of `SeqNo`, little-endian-encoded as a 1-byte int in practice): `M1..M6 = 0x01..0x06`.
- `ErrorCode`: `Unknown=0x01, Authentication=0x02, BackOff=0x03, MaxPeers=0x04, MaxTries=0x05, Unavailable=0x06, Busy=0x07`.
- `Flags.TransientPairing = 0x10` — set on the `Flags` TLV entry (1-byte, big-endian per `hap_transient.py`) to request transient (ephemeral, no-persisted-credentials) pairing.
- Multi-byte integer TLV values (`Method`, `SeqNo`, `Error`, `BackOff`) are consistently encoded/decoded as **little-endian** in pyatv (`int.from_bytes(value, byteorder="little")` in `stringify()`), even though they're usually only 1 byte in practice so endianness rarely bites — but get this right for `BackOff` (seconds, can need >1 byte).

## 5. Symmetric crypto: ChaCha20-Poly1305, AES-CTR, AES-GCM

### 5.1 HAP pair-verify TLV encryption (M2→M3, all HAP-based protocols)

`SRPAuthHandler.verify1`/`verify2` (`pyatv/auth/hap_srp.py`) uses `chacha20.Chacha20Cipher8byteNonce(session_key, session_key)` — **same key for both directions** at this stage (there's only one ephemeral key derived from `Pair-Verify-Encrypt-Salt`/`-Info`, used both to decrypt the device's M2 payload and encrypt the controller's M3 payload). Nonces are **fixed ASCII strings, not counters**:

- Decrypt device's M2 encrypted TLV: nonce = `b"PV-Msg02"` (8 ASCII bytes).
- Encrypt controller's M3 encrypted TLV: nonce = `b"PV-Msg03"`.
- The analogous Pair-Setup steps (a separate call path in the same file, §2.1/§3) use the fixed nonces `b"PS-Msg05"` (controller encrypts its M5 TLV) and `b"PS-Msg06"` (controller decrypts the device's M6 TLV) with the Pair-Setup session key instead of the Pair-Verify one.

Nonce construction detail (`pyatv/support/chacha20.py::Chacha20Cipher._pad_nonce`): an 8-byte nonce is **left-padded with 4 zero bytes** to reach ChaCha20-Poly1305's required 12 bytes: `nonce_12 = 0x00000000 || nonce_8`. This is a simple zero-prefix, not the counter-packing scheme described next.

### 5.2 HAP transport encryption (post-pair-verify) — `HAPSession` framing

`pyatv/auth/hap_session.py`, used via `AbstractHAPChannel`/`setup_channel` for MRP, AirPlay control, AirPlay events, AirPlay data-stream:

- **Frame size cap: 1024 bytes of plaintext per AEAD operation** (`FRAME_LENGTH = 1024`, cited as "HAP specification, section 5.2.2"). Larger payloads are chunked by the sender into consecutive 1024-byte (or smaller final) frames.
- Wire format per frame: `2-byte little-endian plaintext-length | ciphertext | 16-byte Poly1305 tag`. AAD for the AEAD call is **exactly those 2 length bytes** (`self.chacha20.decrypt(block, aad=length)` / `encrypt(frame, aad=length)`).
- Nonce: **counter-based**, 12 bytes = `4 zero bytes || 8-byte little-endian counter`, counter starts at 0 and increments once per frame, **separate counters per direction** (`_out_counter`/`_in_counter` on `Chacha20Cipher`). This is produced by the default (non-`8byteNonce`) `Chacha20Cipher` class with `nonce_length=8`, whose `_pad_nonce` prepends zeros — i.e. it converges to the *same* byte layout as `Chacha20Cipher8byteNonce`'s dedicated `_PACK_NONCE_WITH_4_BYTE_PAD` helper (`Struct("<LQ").pack(0, counter)`), they're just two code paths that produce identical bytes for the counter case.
- `AUTH_TAG_LENGTH = 16` (standard Poly1305 tag size, just documented as a named constant for frame-length math).

### 5.3 Companion protocol framing — deliberately different from HAPSession

`pyatv/protocols/companion/connection.py::CompanionConnection`:

- Frame header: **4 bytes = 1-byte `FrameType` | 3-byte big-endian payload length** (`HEADER_LENGTH = 4`). The 3-byte length **includes the 16-byte auth tag** when encryption is active.
- AAD = the full 4-byte header (type byte + length bytes), not just the length.
- Nonce: **plain 12-byte little-endian counter, no 4-byte zero prefix** — `Chacha20Cipher(output_key, input_key, nonce_length=12)` takes the `nonce_length == NONCE_LENGTH` branch in `chacha20.py` and skips `_pad_nonce` entirely. **This is a different nonce layout than HAPSession for the same counter value** — do not reuse one nonce-construction function for both; parameterize it by an explicit "counter byte width + zero-prefix width" pair, or just implement Companion's as a separate straight-12-byte-LE-counter type.
- No 1024-byte chunking cap mentioned/observed for Companion; frames are whatever size the OPACK message serializes to.

### 5.4 Legacy AirPlay device-auth: AES-128-CTR (pair-verify) and AES-128-GCM (pair-setup) — with quirks

`pyatv/protocols/airplay/srp.py`:

- **Pair-verify signature encryption**: after X25519 ECDH (`self._verify_private.exchange(...)`), derive `aes_key = SHA512("Pair-Verify-AES-Key" || shared)[0:16]` and `aes_iv = SHA512("Pair-Verify-AES-IV" || shared)[0:16]` — **plain SHA-512 concatenation, not HKDF**. Then AES-128-CTR-encrypt the Ed25519 signature bytes (`signer.sign(self._public_bytes + atv_public_key)`) using this key/IV pair, no authentication tag at all (raw CTR, no AEAD) — pyatv's own comment flags an unexplained field: the M1 wire message is `0x01000000 || client_verify_pubkey(32) || client_auth_pubkey(32)`, and the M2 response's trailing bytes past the first 32 (the device's public key) are passed through as opaque `data` and concatenated with the signature before CTR-encrypting — i.e. that trailing device-supplied blob is encrypted alongside the signature, not verified or interpreted by pyatv (`# TODO: what is this?` in `legacy.py`).
- **Pair-setup finalization**: `aes_key = SHA512("Pair-Setup-AES-Key" || sessionKey)[0:16]`, `aes_iv = SHA512("Pair-Setup-AES-IV" || sessionKey)[0:16]`, **then the IV's last byte is incremented by 1** before use (`tmp[-1] = tmp[-1] + 1`) — an explicit, deliberate workaround baked into the code with a log line ("Increase last byte from X to Y"), almost certainly compensating for an off-by-one/blank-first-block quirk in Apple's original implementation. **This must be replicated exactly** or legacy-AirPlay pairing will silently fail against real hardware. Then AES-128-**GCM** (not CTR) encrypts the 32-byte Ed25519 auth public key with this key/IV, producing ciphertext + a 16-byte GCM tag, both sent to the device.
- `sessionKey` here is the *raw* premaster secret path through `AtvSRPContext`'s custom `K` (§2.2), not a fresh HKDF output — legacy AirPlay never calls `hkdf_expand`.

### 5.5 FairPlay / RSA audio encryption — explicitly NOT implemented

`pyatv/protocols/raop/parsers.py` recognizes RAOP `ENCRYPTION_TYPES` values for `RSA` (bit 1/legacy AirPlay1 audio), `FairPlay` (bit 3), and `FairPlaySAPv25` (bit 5) purely so it can **parse** an `SDP`/RTSP announce that advertises them — there is no code anywhere in `pyatv/protocols/raop/` that performs FairPlay key unwrapping, RSA-OAEP, or the FairPlay handshake. `AirPlayV1` (`pyatv/protocols/raop/protocols/airplayv1.py`) only calls the shared HAP-style `pair_verify()` for the RTSP control channel and otherwise streams RTP audio; AirPlay 2 audio (`airplayv2.py`) rides entirely on the HAP transport keys already described (§3/§5.2). **Do not implement FairPlay for a pyatv-equivalent Rust client** — it is out of scope for pyatv's supported feature set (no known open-source FairPlay implementation exists publicly either, since it depends on Apple's closed hardware-backed key material).

## 6. Ed25519 / X25519 identity and key-exchange details

- **Ed25519 signing identity ("LTPK"/"LTSK")**: pyatv generates a fresh Ed25519 keypair per pairing attempt via `Ed25519PrivateKey.from_private_bytes(os.urandom(32))` — i.e., the 32-byte raw seed *is* the persisted long-term secret key (`ltsk`), stored and reloaded directly as raw seed bytes (`Ed25519PrivateKey.from_private_bytes(credentials.ltsk)`), never PKCS8/DER-wrapped. `ltpk` is the raw 32-byte public key.
- **X25519 ephemeral keys ("verify" keys)**: fresh `X25519PrivateKey.from_private_bytes(os.urandom(32))` per pair-verify session; used once for ECDH then discarded.
- **Signed payloads** (HAP pair-setup M5/M6, `hap_srp.py` step3/`server_auth.py`):
  - Controller signs `iOSDeviceX || pairingID || auth_public_key` where `iOSDeviceX` = HKDF output described in §3.
  - Accessory (device) signs the analogous `AccessoryX || accessoryPairingID || accessoryLTPK`.
- **Signed payloads** (HAP pair-verify M2/M3):
  - Device signs `session_pub_key || device_identifier || controller_session_pub_key`; controller signs `controller_session_pub_key || controller_pairing_id || session_pub_key` (`info = self._public_bytes + credentials.client_id + session_pub_key` in `verify1`). Get the field order exactly right — Ed25519 signature verification is exact-byte-order-sensitive and there's no framing to catch a mis-ordered concatenation at parse time, only a silent auth failure.
- **Legacy AirPlay** reuses the *same* Ed25519 keypair as both the SRP-6a client private exponent seed **and** the identity signing key — `self._auth_private` (raw Ed25519 seed bytes) is fed directly into `SRPClientSession(context, hexlify(self._auth_private))` as the SRP client's private ephemeral `a`. This conflates two normally-independent secrets (SRP ephemeral vs. long-term Ed25519 identity) — replicate exactly, don't "fix" it by generating a separate SRP ephemeral, or you'll diverge from real devices' expectations of the identity continuity across pairing/verification.

## 7. Persisted credential string format (`pyatv/auth/hap_pairing.py`)

`HapCredentials.__str__`/`parse_credentials` — colon-joined lowercase-hex fields, two shapes:

- **4-field (`AuthenticationType.HAP`)**: `<ltpk_hex>:<ltsk_hex>:<atv_id_hex>:<client_id_hex>` — `ltpk`/`ltsk` are the *device's* long-term Ed25519 public key and the *controller's* long-term Ed25519 private key (naming is from the device's point of view per HAP spec convention: LTPK/LTSK are "long-term public/secret key" but pyatv's field names on `HapCredentials` store the peer's public key and the local private key respectively — read the constructor carefully, it is not "device's LTPK and device's LTSK").
- **2-field (`AuthenticationType.Legacy`)**: `<client_id_hex>:<ltsk_hex>` — reusing the 4-field parser's field names for a different semantic: here `ltsk` holds the legacy AirPlay Ed25519 seed and `client_id` holds the legacy AirPlay 8-byte hex identifier; `ltpk`/`atv_id` are empty.
- **Sentinel values**: `NO_CREDENTIALS = HapCredentials()` (all four fields empty → `AuthenticationType.Null`), `TRANSIENT_CREDENTIALS = HapCredentials(ltpk=b"transient")` — the literal ASCII bytes `"transient"` stored in the `ltpk` slot is the marker for `AuthenticationType.Transient` (ephemeral pairing, nothing to persist). A Rust implementation should model `AuthenticationType`/credential-shape as an enum from the start rather than porting this stringly-typed sentinel scheme verbatim, but the **on-disk/config string format itself should be replicated exactly** for interop with existing pyatv credential exports users may migrate from.

## 8. Rust crate mapping (all versions verified live on crates.io, 2026-08-24)

All of the following share the **same generation of RustCrypto trait crates** — `cipher ^0.5`, `aead ^0.6`, `digest ^0.11` — confirmed by querying each crate's `/dependencies` endpoint on crates.io, so they compose without version-conflict resolution headaches:

| Primitive | Crate | Version (verified) | Notes |
|---|---|---|---|
| SHA-512 / SHA-1 | `sha2` / `sha1` | `sha2 = "0.11.0"` | `sha1` needed only for the legacy-AirPlay profile (§2.2); RustCrypto `sha1` crate, keep on the same `digest ^0.11` generation. |
| HKDF | `hkdf` | `"0.13.0"` | Depends on `hmac ^0.13` (which itself sits on `digest ^0.11`) — consistent generation. Use `Hkdf::<Sha512>::new(Some(salt), ikm)` then `.expand(info, &mut out[..32])`. |
| Ed25519 | `ed25519-dalek` | `"3.0.0"` | Depends on `curve25519-dalek ^5.0.0`. Use `SigningKey::from_bytes(&seed)` for raw-32-byte-seed loading (matches pyatv's `from_private_bytes`), `VerifyingKey::from_bytes`. |
| X25519 | `x25519-dalek` | `"3.0.0"` | Also on `curve25519-dalek ^5.0.0` — consistent with `ed25519-dalek` above (both dalek crates must be pinned to compatible majors; 3.0.0/3.0.0 verified compatible). |
| ChaCha20-Poly1305 | `chacha20poly1305` | `"0.11.0"` | RFC 8439 AEAD, standard 12-byte nonce API (`ChaCha20Poly1305::new(key)`, `.encrypt(nonce, Payload{msg, aad})`). No "reusable" variant needed in Rust — unlike pyatv's Python dependency (`chacha20poly1305_reuseable`, needed only because the stdlib `cryptography` binding's default object was single-use), this crate's `.encrypt`/`.decrypt` already take the nonce per-call with no restriction on reuse across many nonces for one key. |
| AES-128 block cipher | `aes` | `"0.9.2"` | `cipher ^0.5`. |
| AES-CTR mode | `ctr` | `"0.10.1"` | `cipher ^0.5.2`. Use `ctr::Ctr128BE<aes::Aes128>` (full 16-byte IV as the initial 128-bit counter block) to match the common OpenSSL-style AES-CTR semantics `cryptography`'s `Cipher(algorithms.AES(key), modes.CTR(iv))` uses — **verify this against a captured real device exchange before trusting it**, see Open Questions. |
| AES-GCM | `aes-gcm` | `"0.11.1"` | `aead ^0.6`, `cipher ^0.5`. `Aes128Gcm::new(key)`, standard 12-byte-IV / 16-byte-tag GCM — matches pyatv's `modes.GCM(aes_iv)` usage directly (12-byte IV, no custom tag length). |
| SRP6a | `srp` | `"0.7.0-rc.3"` (pre-release; stable is `0.6.0`, last published 2022-01-22) | See §9 for the detailed fit analysis — this is the single biggest risk area in this report. |
| TLV8 | *(none recommended)* | — | See §7.6 below. |
| Big-integer backend (transitive, for `srp`) | `crypto-bigint` | `"0.7.5"` | Pulled in automatically by `srp`; no need to depend on it directly unless you bypass `srp`'s `Client`/`Server` types and want to hand-roll SRP math yourself. |

### 8.1 TLV8: hand-roll it, don't depend on `tlv8`

There is no crate literally named `tlv8` on crates.io as of 2026-08-24 (search returns nothing under that exact name). A search for `hap` turns up `hap-tlv8` (crates.io, v1.0.0) and `hap-controller` (v3.1.0), both published from a GitHub repo `phunapps/hap-rust` that was **created 2026-06-11, has 0 stars, and last pushed 2026-08-07** — i.e. it is a brand-new, unreviewed, single-contributor repo with no community signal. Given the encoding is ~30 lines of Rust (tag/length/value with same-tag chunk splitting for values >255 bytes, per §4), **implement TLV8 directly in this project** rather than taking on an unvetted dependency for something this small. The one established Rust HAP crate with real community traction, `hap` (`ewilken/hap-rs`, 217 GitHub stars, `docs.rs/hap`), is an **accessory/server-side** HAP implementation (build a HomeKit accessory, not a controller pairing with one) and was last pushed 2024-08-05 — worth reading its TLV8 module as a second reference implementation, but not worth depending on for a controller like pyatv's Rust equivalent, and it is not itself actively maintained enough to lean on for currency guarantees.

## 9. Where `srp` (RustCrypto) does — and does not — fit HAP's needs

This is the deep-dive the task specifically flagged as a known pain point. Findings, verified by reading `srp` 0.7.0-rc.3's actual source (`groups.rs`, `utils.rs`, `client.rs`, `lib.rs` — all fetched from `github.com/RustCrypto/PAKEs`, `srp/` subdirectory, `master` branch):

1. **Groups**: `srp::groups::{G2048, G3072}` are predefined with the exact RFC 5054 constants pyatv uses (verified hex-for-hex against `srptools/constants.py`'s `PRIME_2048`/`PRIME_3072`, generators 2 and 5 respectively). No custom group definition needed for either profile.
2. **Apple-compatible `x` computation is now a first-class option.** `Client::new_with_options(username_in_x: bool)` exists specifically, per its own doc comment, "for e.g. compatibility with Apple implementations of SRP." This is not needed for the HAP profile (§2.1, which *does* include a username — the literal string `"Pair-Setup"` — in `x`), but may be relevant if any Apple SRP variant pyatv doesn't use omits `I` from `x` entirely; flag as available if needed.
3. **The critical gap: `Client::process_reply()`'s M1 hardcodes `g_no_pad = false`.** Reading `client.rs` line-by-line: the high-level convenience method calls `compute_m1_rfc5054::<D>(&self.g, false, username, salt, &a_pub_bytes, b_pub_bytes, session_key.as_slice())` — the `false` is a hardcoded literal, not exposed as a parameter of `process_reply`. Since HAP (per `srptools`, verified §2.1) needs the **unpadded** `H(g)` variant (`g_no_pad = true`), the crate's top-level ergonomic API **cannot** be used as-is for HAP pairing. This is the "known pain point" the task asked to check for, confirmed concretely.
4. **The gap is bridgeable without forking, because the building blocks are public.** `srp::utils` is `#[doc(hidden)] pub mod utils;` — hidden from generated docs but genuinely `pub`, and every function needed is `pub fn`: `compute_g_x`/`compute_premaster_secret`/`compute_identity_hash`/`compute_x` on `Client` are all public methods, and `compute_u_padded`, `compute_k`, `compute_hash`, and — crucially — `compute_m1_rfc5054::<D>(g, g_no_pad: bool, ...)` in `srp::utils` are all public free functions that take `g_no_pad` as a caller-supplied argument. **The correct integration strategy is: do not call `Client::process_reply()`; instead call the individual `Client` methods plus `srp::utils::compute_m1_rfc5054(..., true, ...)` and `compute_m2` directly**, replicating the ~15 lines `process_reply()` itself contains but with the one boolean flipped. This gives byte-exact HAP compatibility using the upstream crate's own primitives, no fork or vendoring required.
5. **The legacy-AirPlay session-key derivation (§2.2, doubled-SHA1 `K`) has no crate support and needs equivalent manual composition**: call `Client::compute_premaster_secret(...)` (public) to get `S`, then hash it yourself as `SHA1(S||0x00000000) || SHA1(S||0x00000001)` instead of calling any of the crate's `session_key`/`process_reply*` helpers (which all do single-hash `K = H(S)`). Same pattern as point 4 — use the low-level building blocks, skip the high-level convenience wrapper.
6. **Version risk**: `srp` 0.7.0 has been in pre-release since `0.7.0-pre.0` (2025-12-24) through `0.7.0-rc.3` (2026-04-03, most recent as of this report) — over four months in RC as of 2026-08-24, not yet stabilized. The stable `0.6.0` (2022-01-22, four years old) has a materially different API (`SrpClient`/`SrpServer` structs rather than generic `Client<G, D>`, and — based on `hap-rs`'s successful use of `srp = "0.5"` for its own HAP-3072-SHA512 pairing — the 3072-bit group and generic hash-function support have existed since at least 0.5, so 0.6.0 is a viable fallback if the 0.7 RC's public-API-hidden `utils` module is judged too fragile for production, at the cost of hand-rolling more of the SRP math yourself against `0.6`'s more limited surface). **Recommendation: pin to the specific `0.7.0-rc.N` commit/version you validate against, track the `RustCrypto/PAKEs` repo for the 0.7.0 stable release, and write your own known-answer tests (KATs) against captured real pyatv/Apple-TV pairing traffic before trusting either version blindly** — an RC by definition has not had its API frozen and could still change before 0.7.0 final.

## 10. Summary: crate versions to pin (as verified 2026-08-24)

```toml
[dependencies]
sha2 = "0.11.0"
sha1 = "0.11"            # legacy AirPlay profile only
hkdf = "0.13.0"
ed25519-dalek = "3.0.0"
x25519-dalek = "3.0.0"
chacha20poly1305 = "0.11.0"
aes = "0.9.2"
ctr = "0.10.1"
aes-gcm = "0.11.1"
srp = "0.7.0-rc.3"       # pre-release — see §9.6; re-check for 0.7.0 stable before shipping
# TLV8: hand-rolled, no dependency (see §8.1)
```

## Open questions

- Does pyatv's `H(g)` unpadding in M1 (found in `srptools`, §2.1) apply identically to the legacy 2048-bit/SHA-1 AirPlay profile (§2.2), or does that profile actually use the padded RFC 5054 form? Both profiles share the same `srptools.SRPContext.get_common_session_key_proof` code path in pyatv today, so by direct code inspection they appear identical, but this needs confirmation against a captured real-device pairing trace (e.g. via `pyatv`'s own `atvproxy.py`, which is built exactly for man-in-the-middle capture of these exchanges) since legacy AirPlay is oldest and least-documented.
- Confirm the exact AES-CTR "full 16-byte IV as counter block" semantics (`ctr::Ctr128BE<Aes128>`) against a real captured legacy-AirPlay pair-verify exchange — Python's `cryptography` library's `modes.CTR(iv)` behavior is well-defined or the OpenSSL/RFC-3686-adjacent convention, but this needs a byte-exact KAT rather than assumed equivalence before depending on it.
- pyatv's own code (`legacy.py`, `# TODO: what is this?`) does not fully understand the trailing opaque `data` blob in the legacy AirPlay pair-verify M2 response that gets encrypted alongside the signature — worth treating as "replicate byte-for-byte, do not attempt to interpret" rather than trying to reverse-engineer its semantics further.
- `srp` 0.7.0 stabilization timeline is unknown (still RC as of 2026-08-24, in pre-release since 2025-12-24) — re-check `crates.io/crates/srp` before implementation begins; if stable 0.7.0 has shipped with a different API than `rc.3`, the integration notes in §9 will need re-verification against the final release.
- Whether HAP's M1/M2 (§2.1) is actually *checked* against real devices by pyatv at all is worth double-checking: `pyatv/auth/hap_srp.py::step2` does call `self._session.verify_proof(self._session.key_proof_hash)` (i.e. it does verify the device's proof), so this is exercised in practice, which gives reasonable confidence the described M1 formula (unpadded `H(g)`) is correct and not a latent, never-hit bug in pyatv itself — but a from-scratch Rust implementation should still validate independently rather than trust-by-inheritance.
- No independent, actively-maintained pure-Rust FairPlay implementation exists to reference (§5.5) — if a future scope expansion needs classic (non-AirPlay-2) RAOP audio streaming to a device that requires real FairPlay/RSA encryption rather than the HAP-based AirPlay 2 transport, that is genuinely new research with no pyatv or crates.io precedent to lean on.
- The `hap-controller`/`hap-tlv8` crates from `phunapps/hap-rust` (§8.1) were not deeply audited beyond checking repo provenance (age, star count, push recency) — if a future need arises to reconsider using them, do a full source read and a supply-chain check (crates.io ownership, `cargo vet`/`cargo crev` if available) before adding as a dependency, not just the metadata check performed here.
