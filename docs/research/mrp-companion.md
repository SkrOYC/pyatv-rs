# MRP and Companion protocol internals for a Rust pyatv reimplementation

Research date: 2026-08-24. Grounded against pyatv `master` branch source on GitHub (commit tree fetched live via `raw.githubusercontent.com` and `api.github.com`), pyatv.dev documentation, and crates.io. All code excerpts below are copied verbatim from pyatv source files; file paths are given so engineers can diff against upstream as pyatv evolves. Do not trust memorized values for byte layouts, HKDF salts/infos, or enum numbers in this domain — they are all copied from source, not recalled.

## 0. Scope and primary sources

- pyatv MRP implementation: `pyatv/protocols/mrp/` (`__init__.py`, `auth.py`, `connection.py`, `messages.py`, `player_state.py`, `protocol.py`, `server_auth.py`, `protobuf/*.proto`) — https://github.com/postlund/pyatv/tree/master/pyatv/protocols/mrp
- pyatv Companion implementation: `pyatv/protocols/companion/` (`__init__.py`, `api.py`, `auth.py`, `connection.py`, `keyed_archiver.py`, `pairing.py`, `protocol.py`, `server_auth.py`) — https://github.com/postlund/pyatv/tree/master/pyatv/protocols/companion
- Shared HAP/SRP/crypto plumbing: `pyatv/auth/` (`hap_pairing.py`, `hap_srp.py`, `hap_tlv8.py`, `hap_channel.py`, `hap_session.py`, `server_auth.py`) — https://github.com/postlund/pyatv/tree/master/pyatv/auth
- MRP-over-AirPlay tunnel: `pyatv/protocols/airplay/` (`__init__.py`, `ap2_session.py`, `channels.py`, `mrp_connection.py`, `auth/hap.py`, `auth/__init__.py`) — https://github.com/postlund/pyatv/tree/master/pyatv/protocols/airplay
- Support utilities: `pyatv/support/variant.py`, `pyatv/support/chacha20.py`, `pyatv/support/opack.py`, `pyatv/support/packet.py`, `pyatv/support/rtsp.py` — https://github.com/postlund/pyatv/tree/master/pyatv/support
- pyatv.dev protocol overview page: https://pyatv.dev/documentation/protocols/
- External reverse-engineering reference (linked by pyatv.dev, historical, unmaintained): https://github.com/jeanregisser/mediaremotetv-protocol
- Companion PR that added MRP-over-AirPlay tunneling: https://github.com/postlund/pyatv/pull/1263

pyatv is licensed MIT; the excerpts below are reproduced for engineering reference under that license.

---

## 1. MRP transport (direct connection, tvOS < 15 or HomePod)

### 1.1 Discovery

- Zeroconf/mDNS service type: `_mediaremotetv._tcp.local` (`pyatv/protocols/mrp/__init__.py`, `scan()`).
- Port comes directly from the mDNS SRV record (historically an ephemeral port from 49152 upward; it is not fixed and can change across reboots).
- **Critical: pyatv disables this service entirely when the advertised `SystemBuildVersion` TXT property indicates tvOS ≥ 15.** The check (`pyatv/protocols/mrp/__init__.py`, `mrp_service_handler`):
  ```python
  build = mdns_service.properties.get("SystemBuildVersion", "")
  match = re.match(r"^(\d+)[A-Z]", build)
  if match:
      base = int(match.groups()[0])
      if base >= 19:
          enabled = False   # tvOS 15 corresponds to Darwin-style build major 19
  ```
  Apple's tvOS build-number scheme aligns with the Darwin major version used across iOS/tvOS (tvOS 15.x builds start with `19`), so "build major ≥ 19" means "tvOS ≥ 15". A Rust port must replicate this exact heuristic (regex `^(\d+)[A-Z]` on the `SystemBuildVersion` TXT record, threshold 19) to decide whether to attempt a direct MRP connection at all versus going straight to the AirPlay tunnel path (§3).
- Pairing requirement for direct MRP (`service_info()` in the same file): if the service was disabled by the above check, pairing is reported as `NotNeeded` (there's nothing to pair with — you can't reach it); otherwise MRP pairing is `Optional` if TXT property `allowpairing` is `"yes"` (case-insensitive), else `Disabled`. MRP historically never enforced pairing at all unless "Allow Pairing" is manually toggled on the device.

### 1.2 Wire framing

Direct MRP is length-prefixed protobuf over a plain TCP socket, framed by the same varint used by protobuf itself (base-128, LSB-first, MSB-continuation), **not part of the protobuf message payload** — implemented in `pyatv/support/variant.py`:
```python
def read_variant(variant):
    result = 0
    cnt = 0
    for data in variant:
        result |= (data & 0x7F) << (7 * cnt)
        cnt += 1
        if not data & 0x80:
            return result, variant[cnt:]
    raise ValueError("invalid variant")

def write_variant(number):
    if number < 128:
        return bytes([number])
    return bytes([(number & 0x7F) | 0x80]) + write_variant(number >> 7)
```
Frame on the wire = `write_variant(len(serialized_protobuf_or_ciphertext)) + payload`. This is a per-byte, MSB-continuation-bit varint identical in spirit to protobuf's own varint encoding (`prost`'s internal varint decoder is bit-compatible; you do not need a separate implementation if using `prost` — you can hand-roll a tiny reader using the same algorithm, since it's outside any message and just a raw length prefix).

Before encryption is established (device-info exchange during connect), payload = raw `ProtocolMessage.SerializeToString()` bytes. After pair-verify, payload = ChaCha20-Poly1305 ciphertext (§1.4) of the serialized protobuf; the length prefix covers the **encrypted** length (ciphertext + 16-byte Poly1305 tag), per `pyatv/protocols/mrp/connection.py`:
```python
def send(self, message):
    serialized = message.SerializeToString()
    if self._chacha:
        serialized = self._chacha.encrypt(serialized)
    data = write_variant(len(serialized)) + serialized
    self._transport.write(data)
```
Receive side buffers arbitrarily-split TCP reads, repeatedly attempts `read_variant` + must-have-`length`-bytes-buffered before dispatching (`data_received` in the same file).

### 1.3 Protobuf message catalogue

pyatv vendors and maintains its own `.proto` files (there is no public/official Apple `.proto` source; these were reverse-engineered and are hand-maintained) at `pyatv/protocols/mrp/protobuf/*.proto`. As of the current `master`, that directory contains **77 `.proto` files** (verified via GitHub API directory listing of `pyatv/protocols/mrp/protobuf`), each with a matching generated `_pb2.py`/`_pb2.pyi`. Representative list (alphabetical, all confirmed present): `AudioFadeMessage`, `AudioFadeResponseMessage`, `AudioFormatSettingsMessage`, `ClientUpdatesConfigMessage`, `CommandInfo`, `CommandOptions`, `Common`, `ConfigureConnectionMessage`, `ContentItem`, `ContentItemMetadata`, `CryptoPairingMessage`, `DeviceInfoMessage`, `GenericMessage`, `GetKeyboardSessionMessage`, `GetRemoteTextInputSessionMessage`, `GetVolumeMessage`, `GetVolumeResultMessage`, `KeyboardMessage`, `LanguageOption`, `ModifyOutputContextRequestMessage`, `NotificationMessage`, `NowPlayingClient`, `NowPlayingInfo`, `NowPlayingPlayer`, `Origin`, `OriginClientPropertiesMessage`, `PlaybackQueue`, `PlaybackQueueCapabilities`, `PlaybackQueueContext`, `PlaybackQueueRequestMessage`, `PlayerClientPropertiesMessage`, `PlayerPath`, `ProtocolMessage`, `RegisterForGameControllerEventsMessage`, `RegisterHIDDeviceMessage`, `RegisterHIDDeviceResultMessage`, `RegisterVoiceInputDeviceMessage`, `RegisterVoiceInputDeviceResponseMessage`, `RemoteTextInputMessage`, `RemoveClientMessage`, `RemoveEndpointsMessage`, `RemoveOutputDevicesMessage`, `RemovePlayerMessage`, `SendButtonEventMessage`, `SendCommandMessage`, `SendCommandResultMessage`, `SendHIDEventMessage`, `SendPackedVirtualTouchEventMessage`, `SendVoiceInputMessage`, `SetArtworkMessage`, `SetConnectionStateMessage`, `SetDefaultSupportedCommandsMessage`, `SetDiscoveryModeMessage`, `SetHiliteModeMessage`, `SetNowPlayingClientMessage`, `SetNowPlayingPlayerMessage`, `SetRecordingStateMessage`, `SetStateMessage`, `SetVolumeMessage`, `SupportedCommands`, `TextInputMessage`, `TransactionKey`, `TransactionMessage`, `TransactionPacket`, `TransactionPackets`, `UpdateClientMessage`, `UpdateContentItemArtworkMessage`, `UpdateContentItemMessage`, `UpdateEndPointsMessage`, `UpdateOutputDeviceMessage`, `UpdatePlayerPath`, `VirtualTouchDeviceDescriptorMessage`, `VoiceInputDeviceDescriptorMessage`, `VolumeControlAvailabilityMessage`, `VolumeControlCapabilitiesDidChangeMessage`, `VolumeDidChangeMessage`, `WakeDeviceMessage`.

The envelope type is `ProtocolMessage` (`pyatv/protocols/mrp/protobuf/ProtocolMessage.proto`), `syntax = "proto2"`:
```proto
message ProtocolMessage {
  extensions 6 to 77;
  extensions 79 to 84;
  extensions 86 to max;

  enum Type {
    UNKNOWN_MESSAGE = 0;
    SEND_COMMAND_MESSAGE = 1;
    ...
    CONFIGURE_CONNECTION_MESSAGE = 120;
  }

  optional Type type = 1;
  optional string identifier = 2;
  optional string authenticationToken = 3;
  optional ErrorCode.Enum errorCode = 4;
  optional uint64 timestamp = 5;
  optional string errorDescription = 78;
  optional string uniqueIdentifier = 85;
}
```
The `Type` enum defines **84 distinct message-type constants** (numbered non-contiguously from 0 to 120; the low range 1–77 covers "core" messages, 101–120 a second batch added later — e.g. `SET_DISCOVERY_MODE_MESSAGE = 101` through `CONFIGURE_CONNECTION_MESSAGE = 120`). Each concrete message (e.g. `SendCommandMessage`) is defined as a protobuf **extension** of `ProtocolMessage` at the field number matching its `Type` value (proto2 extension mechanism), i.e. the pattern is: set `type = SEND_COMMAND_MESSAGE`, then populate the extension field `[SendCommandMessage.sendCommandMessage]` (extension field number == enum value). `ErrorCode.Enum` in the same file enumerates ~50 device-side error codes (`NoError=0` ... `OtherUnknownError=299`), useful for a typed Rust error enum.

**Rust implication:** `prost` (proto2 support) with `prost-build` can compile these `.proto` files directly (vendor pyatv's `.proto` sources verbatim, since they're the only accurate spec — there is no other canonical source). `prost` supports proto2 `extensions` via the `extend` construct only partially/awkwardly (prost historically has weaker proto2-extension support than `protobuf`/`rust-protobuf` crate). **Verify before committing**: test-compile `ProtocolMessage.proto` + a representative extension file with `prost-build` to confirm extension fields round-trip; if `prost` cannot express proto2 extensions cleanly, fall back to the `protobuf` crate (rust-protobuf, which has full proto2 extension support) or flatten the extensions into `oneof`-style manual reflection during codegen.

### 1.4 MRP direct-connection pairing (pair-setup) and pair-verify

MRP pair-setup/pair-verify travel as `CryptoPairingMessage` (`ProtocolMessage.Type.CRYPTO_PAIRING_MESSAGE = 34`) whose payload field `pairingData` is raw HAP TLV8 (see §4 for the shared HAP/SRP mechanics — MRP and Companion both call into the identical `pyatv/auth/hap_srp.py` `SRPAuthHandler`). Implementation: `pyatv/protocols/mrp/auth.py`, classes `MrpPairSetupProcedure` / `MrpPairVerifyProcedure`. Pairing state machine (M1–M6 for pair-setup, M1–M4 for pair-verify) is identical to Companion's (§4.2); only the outer transport (protobuf `CryptoPairingMessage` vs. Companion's `PS_Start`/`PS_Next`/`PV_Start`/`PV_Next` frames) differs.

Encryption-key derivation for the **direct MRP connection**, once pair-verify succeeds, uses these exact HKDF-SHA512 salt/info strings (`pyatv/protocols/mrp/__init__.py`):
```python
SRP_SALT = "MediaRemote-Salt"
SRP_OUTPUT_INFO = "MediaRemote-Write-Encryption-Key"
SRP_INPUT_INFO = "MediaRemote-Read-Encryption-Key"
```
called as `pair_verifier.encryption_keys(SRP_SALT, SRP_OUTPUT_INFO, SRP_INPUT_INFO)` → `(output_key, input_key)`, then `MrpConnection.enable_encryption(output_key, input_key)` constructs `Chacha20Cipher8byteNonce(output_key, input_key)` (§1.5). Note this differs from Companion's salt (empty string, §5.3) and from AirPlay's control-channel salt (`"Control-Salt"`, §3.3) — **each protocol/channel uses a distinct salt/info pair fed into the same HKDF-Expand-SHA512 primitive over the same underlying X25519 shared secret model.**

The very first message sent on a freshly-opened MRP TCP connection (before any pairing/verify) must be `DEVICE_INFO_MESSAGE` — the device refuses anything else first (`pyatv/protocols/mrp/protocol.py`, `start()`): a `DeviceInfoMessage` extension populated with fields including `applicationBundleIdentifier = "com.apple.TVRemote"`, `applicationBundleVersion = "344.28"`, `localizedModelName = "iPhone"`, `protocolVersion = 1`, `systemMediaApplication = "com.apple.TVMusic"`, `deviceClass = DeviceClass.iPhone`, `uniqueIdentifier = <pairing_id>` (`pyatv/protocols/mrp/messages.py`, `device_information()`). A Rust client impersonating the "Apple TV Remote" iOS app should send equivalent fields verbatim (these exact strings/versions are what makes real devices accept the connection as a legitimate remote).

### 1.5 ChaCha20-Poly1305 framing (used by both direct MRP and Companion)

`pyatv/support/chacha20.py` wraps the `chacha20poly1305_reuseable` PyPI package (a "reusable-key" ChaCha20-Poly1305 AEAD — this restriction is a PyCryptodome/pynacl API quirk, **not a protocol requirement**; standard RustCrypto `chacha20poly1305` AEAD objects are reusable across many nonces by design, so no special crate feature is needed in Rust).

Two nonce shapes are used depending on channel:
- **8-byte counter, packed into a 12-byte nonce with 4 leading zero bytes** — used for direct MRP (`Chacha20Cipher8byteNonce`, `nonce_length=8`): `nonce = 0x00000000 (4 bytes) || counter (8 bytes, little-endian)`. Struct format: `Struct("<LQ").pack(0, counter)`.
- **Plain 12-byte little-endian counter (RFC 8439 standard nonce size)** — used for Companion (`Chacha20Cipher(..., nonce_length=12)`, §5) and for the HAP-generic 1024-byte-frame channels (`HAPSession`, used for AirPlay control/event/data channels, §3.3): `nonce = counter.to_bytes(12, "little")`.

Counter starts at 0 for both `_out_counter` and `_in_counter` (independent per direction), increments by 1 after every `encrypt`/`decrypt` call that uses the auto-generated (non-explicit) nonce. Explicit nonces (e.g. the literal ASCII strings `b"PS-Msg05"`, `b"PS-Msg06"`, `b"PV-Msg02"`, `b"PV-Msg03"` used only during the pairing handshake itself, padded to 12 bytes with leading zero bytes) bypass the counter entirely — these are the fixed HAP-spec nonces for wrapping the pairing sub-TLV inside pair-setup/pair-verify M5/M6/M2/M3.

Poly1305 authentication tag: 16 bytes, appended after ciphertext (standard AEAD output — `ChaCha20Poly1305Reusable.encrypt(nonce, plaintext, aad)` returns `ciphertext || tag`).

### 1.6 MRP `HAPSession` 1024-byte block chunking (shared with AirPlay, §3.3)

`pyatv/auth/hap_session.py` — **not used for direct MRP** (direct MRP just wraps whole protobuf messages, one ChaCha20-Poly1305 seal per message, framed by the outer variant length prefix, §1.2). It **is** used for AirPlay's control/event/data channels (§3) and is included here because it's part of the shared crypto stack:
```python
FRAME_LENGTH = 1024      # HAP spec section 5.2.2 (Release R1)
AUTH_TAG_LENGTH = 16

def encrypt(self, data: bytes) -> bytes:
    output = b""
    while data:
        frame = data[0:FRAME_LENGTH]
        data = data[FRAME_LENGTH:]
        length = int.to_bytes(len(frame), 2, byteorder="little")
        frame = self.chacha20.encrypt(frame, aad=length)   # AEAD, AAD = the 2-byte length itself
        output += length + frame
    return output
```
Wire layout per HAP block: `length: u16 little-endian (2 bytes) || ciphertext (≤1024 bytes) || poly1305_tag (16 bytes)`, where `length` is both transmitted in the clear as a header **and** used as the AEAD associated data (AAD) for that block. Decrypt buffers partial reads the same way MRP/Companion connections do (block_length = declared length + 16 tag bytes; wait for that many bytes before decrypting).

---

## 2. HAP TLV8, SRP6a, Ed25519/X25519 shared crypto core

This section documents `pyatv/auth/hap_srp.py`, `pyatv/auth/hap_tlv8.py`, `pyatv/auth/hap_pairing.py` — used **identically** by MRP direct pairing, Companion pairing, and AirPlay pairing (only the outer transport framing differs, plus the salt/info strings per §1.4/§3.3/§5.3).

### 2.1 TLV8 (`pyatv/auth/hap_tlv8.py`)

Type-length-value, 1-byte tag + 1-byte length (0–255) + value; values >255 bytes are split into consecutive entries with the same tag (concatenated on decode):
```python
TlvValue.Method = 0x00
TlvValue.Identifier = 0x01
TlvValue.Salt = 0x02
TlvValue.PublicKey = 0x03
TlvValue.Proof = 0x04
TlvValue.EncryptedData = 0x05
TlvValue.SeqNo = 0x06
TlvValue.Error = 0x07
TlvValue.BackOff = 0x08
TlvValue.Certificate = 0x09
TlvValue.Signature = 0x0A
TlvValue.Permissions = 0x0B
TlvValue.FragmentData = 0x0C
TlvValue.FragmentLast = 0x0D
TlvValue.Name = 0x11        # Apple-internal, not in public HAP spec
TlvValue.Flags = 0x13       # Apple-internal
```
`Flags.TransientPairing = 0x10`. `Method`: `PairSetup=0x00, PairSetupWithAuth=0x01, PairVerify=0x02, AddPairing=0x03, RemovePairing=0x04, ListPairing=0x05`. `ErrorCode`: `Unknown=0x01, Authentication=0x02, BackOff=0x03, MaxPeers=0x04, MaxTries=0x05, Unavailable=0x06, Busy=0x07`. `State` (sequence numbers, sent as `SeqNo` value, little-endian encoded integer, 1 byte): `M1..M6 = 0x01..0x06`.

### 2.2 SRP6a parameters (pair-setup only; pair-verify is pure X25519, no SRP)

`pyatv/auth/hap_srp.py` uses the third-party `srptools` PyPI package with:
```python
context = SRPContext(
    "Pair-Setup",           # username is the literal string "Pair-Setup"
    str(pin),                # password = ASCII decimal PIN, e.g. "1234" or "123456"
    prime=constants.PRIME_3072,
    generator=constants.PRIME_3072_GEN,
    hash_func=hashlib.sha512,
)
```
So: **RFC 5054 3072-bit group, SHA-512 hash, fixed username `"Pair-Setup"`.** The Rust `srp` crate (crates.io, verified current, MIT/Apache, built on `crypto-bigint`, description: "Pure Rust implementation of the Secure Remote Password (SRP) password-authenticated key exchange (PAKE) algorithm as described in RFC5054") exposes an `srp::groups` module with pre-defined RFC 5054 groups including `G_3072`; hash function is generic (pick `Sha512` from the `sha2` crate). This is the closest drop-in match — **verify by test-compiling against pyatv's SRP proof output before trusting it**, since HAP's exact `k` derivation, padding of `N`/`g` to fixed width, and username/salt handling must byte-match `srptools`' behavior (SRP has historically had subtle library-to-library incompatibilities around zero-padding of `H(N) XOR H(g)` and the multiplier `k`).

Pair-setup step-by-step (`SRPAuthHandler` in `hap_srp.py`, driven by `MrpPairSetupProcedure`/`CompanionPairSetupProcedure`):
1. `initialize()`: generate fresh Ed25519 signing keypair (`_signing_key`/`_auth_public`, used for the long-term "LTPK/LTSK" identity) **and** a fresh X25519 keypair (`_verify_private`/`_public_bytes`, only used later by pair-verify — pair-setup itself uses SRP, not this X25519 pair, except that the SRP client "private key" seed is `hex(_auth_private)` i.e. the Ed25519 private scalar bytes are reused as the SRP `a` seed via `SRPClientSession(context, hexlify(self._auth_private))`).
2. M1: client sends `Method=0x00, SeqNo=0x01`.
3. M2 (from device): TLV contains `Salt` (`s`) and `PublicKey` (`B`, the server's SRP public value).
4. `step1(pin)`: build the `SRPContext` as above.
5. `step2(atv_pub_key, atv_salt)`: `session.process(B_hex, salt_hex)`, verify `session.verify_proof(session.key_proof_hash)` (this checks the server's proof matches — if it doesn't, `AuthenticationError("proofs do not match")`, i.e. wrong PIN), return `(A, M1_proof)` — client's public value and key proof.
6. M3: client sends `SeqNo=0x03, PublicKey=A, Proof=M1`.
7. M4 (from device): `Proof` (`M2`) — pyatv currently does **not** verify M2 (`log_binary` only, no check — a `# TODO` gap upstream). A correct Rust implementation should still verify M2 per spec even though pyatv's reference client is lax here.
8. `step3(name=None, additional_data=None)`: derive **two more HKDF outputs** from the raw SRP session key `K` (hex-decoded):
   ```python
   ios_device_x   = hkdf_expand("Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info", K)
   session_key    = hkdf_expand("Pair-Setup-Encrypt-Salt",         "Pair-Setup-Encrypt-Info",         K)
   device_info    = ios_device_x + pairing_id + auth_public   # pairing_id = client's UUID (random, generated once, stringified+encoded as bytes)
   device_signature = Ed25519_sign(signing_key, device_info)
   tlv = { Identifier: pairing_id, PublicKey: auth_public (Ed25519 pubkey), Signature: device_signature }
   # optional Name tlv (0x11) is OPACK-packed: opack.pack({"name": name})  -- interesting: TLV value 0x11 (Name) carries an OPACK-encoded dict, not raw UTF-8, when the client wants to send a display name (used by Companion pair-setup for the display name shown on-screen)
   encrypted_data = ChaCha20Poly1305(session_key, session_key).encrypt(write_tlv(tlv), nonce=b"PS-Msg05")
   ```
9. M5: client sends `SeqNo=0x05, EncryptedData=encrypted_data`.
10. M6 (from device): `step4(encrypted_data)`: decrypt with the same `session_key`/nonce `b"PS-Msg06"`, parse inner TLV for device `Identifier`, `Signature` (unverified — another upstream `# TODO`), `PublicKey` (device's Ed25519 LTPK). Result: `HapCredentials(ltpk=atv_pub_key, ltsk=auth_private, atv_id=atv_identifier, client_id=pairing_id)` — this 4-tuple (hex-joined with `:`) is the persisted "pairing record" a Rust client must store long-term (equivalent to iOS's HomeKit pairing keychain entry).

**HKDF parameters throughout are fixed: HKDF-SHA512, 32-byte output length**, via Python's `cryptography` `HKDF(algorithm=SHA512(), length=32, salt=<ascii>.encode(), info=<ascii>.encode())`. Rust: `hkdf::Hkdf::<sha2::Sha512>::new(Some(salt.as_bytes()), shared_secret)`, then `.expand(info.as_bytes(), &mut okm[..32])`.

### 2.3 Pair-verify (X25519 + Ed25519, no SRP) — `SRPAuthHandler.verify1`/`verify2`

Pair-verify is a fresh handshake every connection (does not require re-entering a PIN; uses the long-term Ed25519 keys established during pair-setup):
1. `initialize()` generates a **new** ephemeral X25519 keypair per verify attempt (`_verify_private`/`_public_bytes`).
2. M1: client sends `SeqNo=0x01, PublicKey=<client X25519 pubkey>`.
3. M2 (from device): `PublicKey` (device's ephemeral X25519 pubkey, `session_pub_key`) + `EncryptedData`.
4. `verify1(credentials, session_pub_key, encrypted)`:
   ```python
   shared = X25519_ECDH(client_ephemeral_private, session_pub_key)
   session_key = hkdf_expand("Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", shared)
   decrypted = ChaCha20Poly1305(session_key, session_key).decrypt(encrypted, nonce=b"PV-Msg02")
   # decrypted TLV: Identifier (device's atv_id), Signature
   assert identifier == credentials.atv_id
   info = session_pub_key + identifier + client_ephemeral_pubkey
   Ed25519_verify(credentials.ltpk, signature, info)   # verifies device's identity using the LTPK stored from pair-setup
   device_info = client_ephemeral_pubkey + credentials.client_id + session_pub_key
   device_signature = Ed25519_sign(credentials.ltsk, device_info)   # client proves its own identity using its stored LTSK
   tlv = { Identifier: credentials.client_id, Signature: device_signature }
   return ChaCha20Poly1305(session_key, session_key).encrypt(write_tlv(tlv), nonce=b"PV-Msg03")
   ```
5. M3: client sends `SeqNo=0x03, EncryptedData=<above>`.
6. M4 (from device): status-only ack (pyatv doesn't check it — `# TODO: check status code`).
7. `verify2(salt, output_info, input_info)`: **this is where the actual session traffic keys come from** — `hkdf_expand(salt, output_info, shared)` / `hkdf_expand(salt, input_info, shared)`, where `shared` is the **same X25519 ECDH output computed in step 4** (not re-derived). This is why AirPlay's event/data sub-channels (§3.3) can derive fresh keys with different salt/info **without repeating the TLV8 handshake** — they just call `encryption_keys()` again against the already-computed `_shared` value.

### 2.4 Ed25519/X25519 primitives — Rust crate choices

- Ed25519 signing/verification: `ed25519-dalek` (crates.io, latest stable **3.0.0**, released 2026-07; pure-Rust, `SigningKey`/`VerifyingKey` types operating on raw 32-byte seeds/keys — matches pyatv's raw-bytes usage, `signing_key.sign(message)` / `verifying_key.verify(message, &signature)`). **Verify the 3.0 API surface against your exact usage before committing** — this is a recent major-version bump from the 1.x/2.x lineage many tutorials reference; check `docs.rs/ed25519-dalek/3.0.0` for the current `SigningKey::from_bytes`/`to_bytes` signatures.
- X25519 ECDH: `x25519-dalek` (crates.io, latest stable **3.0.0**, same ecosystem/release wave). Confirm `EphemeralSecret`/`PublicKey`/`StaticSecret` API shape at `docs.rs/x25519-dalek/3.0.0` before use, since 3.0 is also a recent major bump.
- HKDF: `hkdf` crate (crates.io, latest stable **0.13.0**) paired with `sha2` (crates.io, latest stable **0.11.0**) for `Sha512`.
- ChaCha20-Poly1305 AEAD: `chacha20poly1305` crate (crates.io, latest stable **0.11.0**, RustCrypto, pure-Rust with optional hardware acceleration, RFC 8439-compliant). Standard `ChaCha20Poly1305::new(key)` + `.encrypt(nonce, Payload{msg, aad})` is directly reusable across many nonces — no "Reusable"-suffixed variant needed (that was a PyCryptodome-specific naming quirk).

---

## 3. MRP-over-AirPlay tunneling (tvOS 15+, mandatory path for modern Apple TV / HomePod)

### 3.1 Why this exists

As of tvOS 15, Apple removed the standalone `_mediaremotetv._tcp` MRP listener as a directly connectable control surface for third parties (pyatv can still see the mDNS advertisement and extract the device's unique identifier from it, but connecting to that port for control no longer works — confirmed by pyatv's own build-version gate in §1.1, and by pyatv's `PR #1263`, "Add support for MRP over AirPlay": https://github.com/postlund/pyatv/pull/1263). Instead, MRP protobuf traffic is tunneled inside an AirPlay 2 "remote control" data channel that rides on top of the same encrypted connection used for AirPlay media streaming setup.

### 3.2 Discovery and gating logic

- AirPlay service: `_airplay._tcp.local` (`pyatv/protocols/airplay/__init__.py`, `scan()`); port taken from the mDNS SRV record (dynamic; historically 7000 on older firmware, no longer a fixed constant to rely on).
- Whether to attempt the tunnel is controlled by `pyatv.settings.MrpTunnel` (`pyatv/settings.py`): `Auto` (default — attempt if the device advertises remote-control support and usable credentials exist), `Force`, or `Disable`. Gating logic (`pyatv/protocols/airplay/__init__.py`, `setup()`):
  ```python
  mrp_tunnel = core.settings.protocols.airplay.mrp_tunnel
  if mrp_tunnel == MrpTunnel.Disable:
      pass
  elif mrp_tunnel == MrpTunnel.Force:
      yield _create_mrp_tunnel_data(core, credentials)
  elif not is_remote_control_supported(core.service, credentials):
      pass
  elif credentials.type not in [AuthenticationType.HAP, AuthenticationType.Transient]:
      pass
  else:
      yield _create_mrp_tunnel_data(core, credentials)
  ```
  `is_remote_control_supported` inspects the AirPlay TXT `features` bitfield (`pyatv/protocols/airplay/utils.py` — not fetched in full here; consult that file directly for the exact `AirPlayFlags` bit used) to decide if the advertised feature set includes remote-control capability. `AuthenticationType.HAP` = normal persisted pairing; `AuthenticationType.Transient` = ephemeral pairing (used by e.g. HomePod which doesn't require a persisted pairing record for basic control — see `pyatv/protocols/airplay/auth/hap_transient.py`).

### 3.3 Session bring-up sequence (`pyatv/protocols/airplay/ap2_session.py`, class `AP2Session`)

1. **Control connection**: plain HTTP/RTSP-hybrid TCP connect to `(address, control_port)` where `control_port = core.service.port` (the AirPlay service's advertised port) — `pyatv/support/http.py:http_connect`.
2. **Pair-verify on the control connection** (`pyatv/protocols/airplay/auth/__init__.py:verify_connection`): runs the X25519/Ed25519 pair-verify from §2.3 over RTSP-framed HTTP-style requests to path `/pair-verify` (same TLV8 body format, `Content-Type: application/octet-stream`, header `X-Apple-HKP: 3`, `User-Agent: AirPlay/320.20`). If `credentials.type == Null`, a `NullPairVerifyProcedure` short-circuits (no encryption — only relevant for unauthenticated legacy flows, not the modern tunnel path). On success, derives the **control-channel** session keys with:
   ```python
   CONTROL_SALT = "Control-Salt"
   CONTROL_OUTPUT_INFO = "Control-Write-Encryption-Key"
   CONTROL_INPUT_INFO = "Control-Read-Encryption-Key"
   ```
   and wraps the connection's send/receive with `HAPSession` (§1.6, 1024-byte block chunking) — from this point every RTSP request/response on the control connection is ChaCha20-Poly1305 sealed.
3. **RTSP `SETUP` (event channel)**, body is a binary plist (`Content-Type: application/x-apple-binary-plist`) with fields including `isRemoteControlOnly: true`, `osName`, `sourceVersion: "550.10"`, `timingProtocol: "None"`, `model`, `deviceID`, `osVersion`, `osBuildVersion`, `macAddress`, `sessionUUID` (fresh UUID, uppercase string), `name`. Response plist contains `eventPort` (an **independent TCP port** the device will connect *out* to, or the client connects to — check `pyatv/protocols/airplay/channels.py` `EventChannel`; based on the code this is a channel the client opens to the device). The client opens a **new plain TCP connection** to `(address, eventPort)` and immediately layers HAP encryption on it **without re-running the TLV8 pair-verify handshake** — keys are re-derived via HKDF from the **same** X25519 shared secret computed in step 2, using:
   ```python
   EVENTS_SALT = "Events-Salt"
   EVENTS_WRITE_INFO = "Events-Write-Encryption-Key"
   EVENTS_READ_INFO = "Events-Read-Encryption-Key"
   # NOTE: output/input are swapped relative to normal (write/read reversed)
   # because this connection originates *from* the receiver's perspective,
   # per an explicit code comment in ap2_session.py:
   #   "Note: Read/Write info reversed here as connection originates from receiver!"
   setup_channel(EventChannel, verifier, address, event_port,
                 EVENTS_SALT, EVENTS_READ_INFO, EVENTS_WRITE_INFO)
   ```
   The event channel is otherwise unused by pyatv (it just answers RTSP-style requests on that socket with a bare `200 OK` to keep the far end satisfied — no payload is parsed for content).
4. **RTSP `RECORD`** issued on the control connection (`self.rtsp.record()`).
5. **RTSP `SETUP` (data channel)**: body plist:
   ```python
   seed = randint(0, 2**64)   # fresh 64-bit random value per session
   {
     "streams": [{
       "controlType": 2,
       "channelID": <fresh UUID, uppercase>,
       "seed": seed,
       "clientUUID": <fresh UUID, uppercase>,
       "type": 130,
       "wantsDedicatedSocket": True,
       "clientTypeUUID": "1910A70F-DBC0-4242-AF95-115DB30604E1",   # fixed constant — identifies "this is a remote-control data stream" client type to the receiver
     }]
   }
   ```
   Response plist: `streams[0].dataPort`. New TCP connection to `(address, dataPort)`, HAP-encrypted (no re-handshake) with:
   ```python
   DATASTREAM_SALT = "DataStream-Salt" + str(seed)   # NOTE: the random seed from the SETUP body is concatenated onto the salt string itself
   DATASTREAM_OUTPUT_INFO = "DataStream-Output-Encryption-Key"
   DATASTREAM_INPUT_INFO  = "DataStream-Input-Encryption-Key"
   ```
6. **Keepalive**: once the tunnel is up, `AP2Session.start_keep_alive()` sends an RTSP `FEEDBACK` request every **2.0 seconds** (`FEEDBACK_INTERVAL = 2.0`, "This is what iOS uses" per source comment) on the control connection. PR #1263's description notes empirically that the tunnel connection is torn down by the receiver after roughly **30 seconds without a heartbeat** — a Rust implementation must replicate this heartbeat cadence or the tunnel will silently die.

### 3.4 Data-channel frame format (carries MRP protobufs)

`pyatv/protocols/airplay/channels.py`, `DataStreamChannel`. Frame header (`DataHeader = defpacket(size="I", message_type="12s", command="4s", seqno="Q", padding="I")`), packed **big-endian** (`defpacket` in `pyatv/support/packet.py` always prefixes format string with `">"`):

| Field | Type | Size | Notes |
|---|---|---|---|
| `size` | `u32` BE | 4 | total frame size = 32 (header) + `len(payload)` |
| `message_type` | 12 raw bytes | 12 | ASCII tag + zero padding, e.g. `b"sync" + 8*b"\x00"` or `b"rply" + 8*b"\x00"` |
| `command` | 4 raw bytes | 4 | e.g. `b"comm"` for outbound MRP payloads, `4*b"\x00"` for replies |
| `seqno` | `u64` BE | 8 | client→device: random start in `[0x100000000, 0x1FFFFFFFF)`, incremented implicitly per message via caller (pyatv actually reuses a single `send_seqno` set once at channel construction — verify whether it should increment per-message; current pyatv code does not increment it after each send, which may be an upstream simplification worth re-checking against real device behavior) |
| `padding` | `u32` BE | 4 | always `0x00000000` |

Total header length = **32 bytes** (`4+12+4+8+4`). Payload follows the header directly; payload itself is a **binary plist** (`encode_plist_body`/`decode_plist_body`, i.e. Apple bplist00 format — use the `plist` crate, crates.io latest stable **1.10.0**, "a rusty plist parser, supports Serde serialization") wrapping the shape `{"params": {"data": <concatenated framed protobufs>}}`.

Inside `data`, MRP `ProtocolMessage`s are concatenated, each normally **variant-length-prefixed** exactly like direct MRP (§1.2, same `write_variant`/`read_variant`), **except** `ConfigureConnectionMessage` which pyatv special-cases as **not** length-prefixed:
```python
# Protobuf fields are encoded in ascending numerical order and every
# message must include type (field #1), which is encoded with the tag
# 0x08. This is not a valid length since the minimal message length is
# at least 40 (type and uniqueIdentifier). We can use this to detect
# cases where the message is not length prefixed, which is known to
# happen for ConfigureConnectionMessage.
if data[0] == 0x8:
    message, data = data, b""
else:
    length, raw = read_variant(data)
    message, data = raw[:length], raw[length:]
assert message[0] == 0x8
```
i.e. the heuristic is: peek the first byte; `0x08` is the wire-tag for protobuf field #1 varint (`type`), which can never itself be a valid *length* varint value in this context (since minimum real message length is ~40 bytes) — so a leading `0x08` byte means "this is a raw unprefixed message, consume the rest of the buffer as one message" rather than "read a 8-byte-length-prefixed message." **This is a fragile, pyatv-specific heuristic reverse-engineered from observed device behavior — treat it as ground truth to replicate exactly, not as elegant protocol design.**

Reply/ack semantics: any incoming frame whose `message_type` starts with `b"sync"` must be answered with a `b"rply"+8*0x00` frame (same header shape, `command=4*0x00`, same `seqno` echoed back, zero-length payload) to satisfy the receiver — this is a raw ack/keepalive at the data-channel level, distinct from the RTSP-level `FEEDBACK` heartbeat (§3.3 step 6).

`AirPlayMrpConnection` (`pyatv/protocols/airplay/mrp_connection.py`) implements the same `AbstractMrpConnection` trait/ABC as the direct-connection `MrpConnection` (§1.2), so from the perspective of the rest of pyatv's MRP protocol/state-machine code (`pyatv/protocols/mrp/protocol.py`, `player_state.py`, etc.) the tunnel is transparent — **this is a strong signal for the Rust port's architecture: define an `MrpTransport` trait with `send(ProtocolMessage)`/`on_message` and implement it twice (direct-TCP-varint and AirPlay-tunnel-plist-framed), sharing 100% of the higher-level MRP protocol/state logic.**

---

## 4. Companion frame format and OPACK serialization

### 4.1 Discovery

- Zeroconf service type: `_companion-link._tcp.local` (`pyatv/protocols/companion/__init__.py`, `scan()`).
- Port from mDNS SRV record (dynamic).
- Pairing-capability heuristic derived from the `rpfl` TXT property (a bitflags integer, hex string), reverse-engineered by pyatv from observed values (comments preserved verbatim from source since they document real device sampling, not spec):
  ```python
  # Observed values of rpfl (zeroconf):
  # 0x62792 -> All on the same network (Unsupported/Mandatory)
  # 0x627B6 -> Only devices in same home (Disabled)
  # 0xB67A2 -> Same as above
  PAIRING_DISABLED_MASK = 0x04
  PAIRING_WITH_PIN_SUPPORTED_MASK = 0x4000
  ```
  `service_info()`: `Disabled` if `flags & PAIRING_DISABLED_MASK`, else `Mandatory` if `flags & PAIRING_WITH_PIN_SUPPORTED_MASK`, else `Unsupported`.
- `rpmd` TXT property → device model lookup (`DeviceInfo.RAW_MODEL`/`MODEL`).

### 4.2 Frame header

`pyatv/protocols/companion/connection.py`: **1-byte frame type + 3-byte big-endian length**, `HEADER_LENGTH = 4`:
```python
def send(self, frame_type, data):
    payload_length = len(data)
    if self._chacha and payload_length > 0:
        payload_length += AUTH_TAG_LENGTH   # 16
    header = bytes([frame_type.value]) + payload_length.to_bytes(3, byteorder="big")
    if self._chacha and len(data) > 0:
        data = self._chacha.encrypt(data, aad=header)   # header itself is the AEAD AAD
    self.transport.write(header + data)
```
Receive side reads `HEADER_LENGTH` bytes, `payload_length = HEADER_LENGTH + int.from_bytes(buf[1:4], "big")` gives total frame size including header, waits for that many bytes, then decrypts `payload = chacha.decrypt(payload, aad=header)` if encryption is enabled and payload non-empty. **Note the AAD is the 4-byte header itself (frame type + length), not empty** — this binds the ciphertext to its declared type/length, preventing frame-type/length tampering.

Frame type enum (`FrameType`, `pyatv/protocols/companion/connection.py`):
```python
Unknown = 0
NoOp = 1
PS_Start = 3
PS_Next = 4
PV_Start = 5
PV_Next = 6
U_OPACK = 7          # Unencrypted OPACK
E_OPACK = 8          # Encrypted OPACK — the workhorse frame type for all commands/events
P_OPACK = 9          # (purpose not further documented in pyatv source; presumably "plaintext"/pairing-adjacent OPACK)
PA_Req = 10
PA_Rsp = 11
SessionStartRequest = 16
SessionStartResponse = 17
SessionData = 18
FamilyIdentityRequest = 32
FamilyIdentityResponse = 33
FamilyIdentityUpdate = 34
```
(Value `2` is not defined/skipped in pyatv's enum — no explanation in source; likely reserved.)

### 4.3 Companion pairing (PS_*/PV_* frames)

Identical HAP TLV8 + SRP6a/X25519 mechanics as §2, just carried inside OPACK dict `{"_pd": <tlv8 bytes>, "_pwTy": 1}` (pair-setup) sent as `FrameType.PS_Start`/`PS_Next`, or `{"_pd": <tlv8 bytes>, "_auTy": 4}` (pair-verify) as `FrameType.PV_Start`/`PV_Next` (`pyatv/protocols/companion/auth.py`). Response frames are always `PS_Next`/`PV_Next` regardless of which `*_Start` was sent (quirk noted directly in `pyatv/protocols/companion/protocol.py`: "*_Start is only used for first message, then *_Next is used for remaining messages (even response to first message)").

### 4.4 Companion session-key derivation

`pyatv/protocols/companion/protocol.py`:
```python
SRP_SALT = ""
SRP_OUTPUT_INFO = "ClientEncrypt-main"
SRP_INPUT_INFO = "ServerEncrypt-main"
```
i.e. **empty-string salt**, distinct info strings from both MRP-direct (§1.4) and AirPlay (§3.3). Post pair-verify, `CompanionConnection.enable_encryption(output_key, input_key)` constructs `Chacha20Cipher(out, in, nonce_length=12)` — the **plain 12-byte little-endian counter** nonce variant (not the 8-byte-padded variant MRP-direct uses), counters independent per direction, starting at 0.

### 4.5 OPACK serialization — full type-tag table

`pyatv/support/opack.py`. OPACK is an Apple-internal format (CoreUtils framework) resembling a compact bplist/CBOR hybrid with an **object back-reference table** (interning of previously-seen encoded values by their exact serialized-byte representation, referenced by index — a form of structural sharing/dedup baked into the wire format itself). Verified byte-for-byte from pyatv's implementation:

| Tag byte(s) | Meaning |
|---|---|
| `0x01` | `true` |
| `0x02` | `false` |
| `0x04` | `null` |
| `0x05` | UUID, followed by 16 raw bytes |
| `0x06` | Absolute time (pyatv: decode-only, as an 8-byte little-endian int; **encode not implemented upstream** — a Rust port should implement both directions properly) |
| `0x08`–`0x2F` | Small unsigned integer, value = `tag - 8` (range 0–39 inline, no extra bytes) |
| `0x30` | `int8`, 1 byte follows, little-endian |
| `0x31` | `int16`, 2 bytes follow, LE |
| `0x32` | `int32`, 4 bytes follow, LE |
| `0x33` | `int64`, 8 bytes follow, LE |
| `0x35` | `float32`, 4 bytes follow (IEEE754 LE, `struct.pack("<f", ...)`) |
| `0x36` | `float64`, 8 bytes follow (IEEE754 LE, `struct.pack("<d", ...)`) |
| `0x40`–`0x60` | Inline UTF-8 string, length = `tag - 0x40` (0–32 bytes), raw UTF-8 follows |
| `0x61` | UTF-8 string, 1-byte LE length prefix follows, then bytes |
| `0x62` | UTF-8 string, 2-byte LE length prefix |
| `0x63` | UTF-8 string, 3-byte LE length prefix |
| `0x64` | UTF-8 string, 4-byte LE length prefix |
| `0x70`–`0x90` | Inline raw byte-string, length = `tag - 0x70` (0–32 bytes) |
| `0x91` | Raw bytes, 1-byte LE length prefix |
| `0x92` | Raw bytes, 2-byte LE length prefix |
| `0x93` | Raw bytes, 4-byte LE length prefix |
| `0x94` | Raw bytes, 8-byte LE length prefix |
| `0xD0`–`0xDF` | Array, element count = `tag - 0xD0` (0–14 inline); count `0xF` (i.e. tag `0xDF`) = **open-ended array**, terminated by a literal `0x03` sentinel byte after the last element |
| `0xE0`–`0xEF` | Dict/map (key,value pairs interleaved, same count/`0xF`-terminator convention as arrays), tag mask is `0xE0` (top 3 bits `111`) — note the mask check in decode is `(tag & 0xE0) == 0xE0`, so this range slightly overlaps conceptually with `0xD0` range's top bits but is disambiguated by checking `0xD0` mask first |
| `0x03` | Terminator sentinel for open-ended (`0xF`-count) arrays/dicts — not a standalone value type |
| `0xA0`–`0xC0` | Back-reference to previously-encoded object, index = `tag - 0xA0` (0–32 inline) |
| `0xC1` | Back-reference, 1-byte LE index follows |
| `0xC2` | Back-reference, 2-byte LE index follows |
| `0xC3` | Back-reference, 4-byte LE index follows |
| `0xC4` | Back-reference, 8-byte LE index follows |

Object back-reference rules (both pack and unpack maintain an `object_list`, a flat append-only vector, shared across the *entire* top-level `pack()`/`unpack()` call, recursively threaded through nested containers):
- On encode: after producing `packed_bytes` for a value, if that **exact serialized byte sequence** already exists in `object_list`, replace the output with a back-reference tag pointing at its index instead of re-emitting it. Otherwise, if `len(packed_bytes) > 1` (i.e. not a 1-byte-encoded primitive — small ints/bools/null are never interned), append it to `object_list` for future dedup.
- On decode: containers (arrays `0xD0-0xDF`, dicts `0xE0-0xEF`), `true`/`false`/`null` are **not** added to the back-reference table (`add_to_object_list = False` for those paths); nearly everything else (strings, byte-strings, sized ints, UUIDs, floats) **is** added, in encounter order, matching the encoder's bookkeeping.

**This interning/back-reference mechanism is the trickiest part of OPACK to port correctly** — get the "which value types participate in the object table" rules exactly right (cross-reference the table above) or serialization will silently diverge from what real devices expect/produce, since the back-reference index numbering must match exactly between two independent implementations for round-tripping against real hardware (a Rust encoder талking to a real Apple TV must produce back-references the *device* would also produce/expect for identical logical structures, not just be self-consistent).

**Rust implication:** No existing `opack`/OPACK crate was found on crates.io as of this research (searched informally via the crate list fetched; none of the standard serialization crates cover it) — **plan to hand-write an OPACK encoder/decoder crate** (e.g. `serde`-compatible `Serializer`/`Deserializer`, or a standalone `opack::{to_vec, from_slice}` pair) directly against pyatv's `pyatv/support/opack.py` as the reference implementation, mirroring the table above exactly. This is a self-contained, well-specified task — budget real engineering time for it and write extensive round-trip tests (including nested-container, open-ended-array/dict, and back-reference-heavy structures) before trusting it against live devices.

### 4.6 Companion message envelope (E_OPACK payloads)

Every request/response/event carried by `FrameType.E_OPACK` is an OPACK dict with these top-level keys (`pyatv/protocols/companion/protocol.py`):

| Key | Meaning |
|---|---|
| `_i` | Identifier string (command name, e.g. `_systemInfo`, `_launchApp`, `_hidC`, `_sessionStart`) |
| `_t` | Message type: `1` = Event, `2` = Request, `3` = Response (`MessageType` enum) |
| `_c` | Content dict (command-specific arguments / response payload) |
| `_x` | XID (transfer/exchange id) — client-generated `u16`-ish counter (`randint(0, 2**16)` seed, incremented per exchange), echoed back by the device on the matching response so the client can correlate async replies; **not present on Event frames** (events are fire-and-forget in one direction) |
| `_em` | Present only on error responses — error message string; presence of this key is how pyatv detects a failed command (`raise ProtocolError(data["_em"])`) |

Auth frames (`PS_*`/`PV_*`) are dispatched/correlated by `frame_type` alone (only one auth exchange can be in flight at a time); regular `E_OPACK` request/response pairs are correlated by `_x` (XID), allowing multiple concurrent in-flight commands — a Rust client should use a `HashMap<u32, oneshot::Sender<..>>` (or similar) keyed by XID exactly like pyatv's `self._queues` dict.

### 4.7 Session establishment sequence (`pyatv/protocols/companion/api.py`, `CompanionAPI.connect()`)

1. `system_info()` — sends `_systemInfo` request with a "bunch of semi-random values" (source's own comment) including `_bf` (0), `_cf` (512), `_clFl` (128), `_i` (client's `rp_id` or lowercased/colon-stripped device id), `_idsID` (credentials' `client_id`), `_pubID` (device id), `_sf` (256, "Status flags?" per source comment — meaning not fully reverse-engineered), `_sv` ("170.18", "Software Version (I guess?)"), `model`, `name`.
2. `_touch_start()` — `_touchStart` with `{_height: 1000.0, _tFl: 0, _width: 1000.0}` (subscribes to touch-gesture capability; `TOUCHPAD_WIDTH`/`TOUCHPAD_HEIGHT` are both `1000.0` — all touch/HID coordinates in the protocol are normalized to a **0–1000 logical grid**, independent of actual screen resolution).
3. `_session_start()` — `_sessionStart` with `{_srvT: "com.apple.tvremoteservices", _sid: <random u32>}`; response's `_c._sid` is the device-assigned session id; final session id used for `_sessionStop` is `(remote_sid << 32) | local_sid` — a **64-bit composite** built by bit-shifting the device's session id into the high 32 bits and OR-ing the client's original random value into the low 32 bits.
4. `_tv_rc_session_start()` — `TVRCSessionStart` with `{ProtocolVersionKey: "1.2"}`; source comment: "tvOS does not answer `FetchAttentionState` until a TV Remote Client session is registered with the `tvremoted` process." Wrapped in try/except since older devices may not support it.
5. `_text_input_start()` — `_tiStart` (registers a remote-text-input session; response includes a keyed-archiver-encoded `_tiD` blob decoded via `pyatv/protocols/companion/keyed_archiver.py`, an `NSKeyedArchiver`-format plist parser pyatv wrote specifically to extract `sessionUUID` and current on-screen text state — this is Apple's `NSKeyedArchiver` binary plist convention, not OPACK; if implementing text input, budget for a small keyed-archiver decoder too).
6. `subscribe_event("_iMC")` — registers interest in the Media Control capability-flags event via `_interest` `{_regEvents: ["_iMC"]}` (an `E_OPACK` **Event**-type frame, not a Request). `_iMC` event payload's `_mcF` field is a `MediaControlFlags` bitmask (`NoControls=0, Play=0x1, Pause=0x2, NextTrack=0x4, PreviousTrack=0x8, FastForward=0x10, Rewind=0x20, Volume=0x100, SkipForward=0x200, SkipBackward=0x400`) that gates which `FeatureName`s report as `Available`.

### 4.8 Companion services / command surface (`pyatv/protocols/companion/api.py`)

Complete `HidCommand` enum (sent as `_hidC` requests, `{_hBtS: 1|2 (down/up), _hidC: <value>}`):
```
Up=1, Down=2, Left=3, Right=4, Menu=5, Select=6, Home=7, VolumeUp=8, VolumeDown=9,
Siri=10, Screensaver=11, Sleep=12, Wake=13, PlayPause=14, ChannelIncrement=15,
ChannelDecrement=16, Guide=17, PageUp=18, PageDown=19
```
`MediaControlCommand` (sent as `_mcc` requests, `{_mcc: <value>, ...extra_args}`):
```
Play=1, Pause=2, NextTrack=3, PreviousTrack=4, GetVolume=5, SetVolume=6, SkipBy=7,
FastForwardBegin=8, FastForwardEnd=9, RewindBegin=10, RewindEnd=11,
GetCaptionSettings=12, SetCaptionSettings=13
```
`SystemStatus` (from `FetchAttentionState` response `content["state"]`): `Asleep=0x01, Screensaver=0x02, Awake=0x03, Idle=0x04 ("NB: Not verified" per source)`.

Command surface implemented on top of the above:
- **App launch**: `_launchApp` with `{_bundleID: <id>}` or `{_urlS: <url>}` (URL vs. bundle-id key chosen by a URL/scheme sniff helper); `FetchLaunchableApplicationsEvent` (app list) and `SwitchUserAccountEvent`/`FetchUserAccountsEvent` (multi-user Apple TV account switching).
- **Keyboard/text**: `_tiStart`/`_tiStop` (session lifecycle) and `_tiC` **event** frames (`{_tiV: 1, _tiD: <NSKeyedArchiver-encoded payload built by pyatv/protocols/companion/plist_payloads.py helpers get_rti_clear_text_payload/get_rti_input_text_payload>}`) to clear or append text, tracking `sessionUUID` and `current_text` client-side across calls.
- **Touch gestures**: `_hidT` **event** frames (not requests) carrying `{_ns: <elapsed nanoseconds since touch session start>, _tFg: 1, _cx: x, _tPh: <TouchAction value>, _cy: y}`, coordinates clamped to `[0, 1000]`. A synthetic `swipe()` helper interpolates intermediate points every `TOUCHPAD_DELAY_MS = 16` ms between start/end coordinates over a caller-specified duration. `click()` sends two `_hidC` down/up pairs (Select=6) roughly 20ms apart for single tap, or a ~1s hold for the "hold" `InputAction`, always followed by a `_hidT` `Click` touch event.
- **Power**: implemented via `HidCommand.Sleep`/`Wake` plus `SystemStatus` polling/events (`FetchAttentionState`, `_iMC`/media-control-flag-gated `PowerState` feature).
- **Media control**: `_mcc` (`MediaControlCommand`) requests, gated by the `_iMC`-subscribed `MediaControlFlags` bitmask for feature availability reporting.

`SUPPORTED_FEATURES` set in the source enumerates the full `FeatureName` surface Companion claims: app list/launch, account list/switch, power state/turn-on/turn-off, D-pad navigation (up/down/left/right/select/menu/home), volume up/down, play/pause, channel up/down, screensaver, guide, control center, text focus-state/get/clear/append/set, swipe, action, click, plus everything in `MEDIA_CONTROL_MAP` (play/pause/next/previous/volume/skip-forward/skip-backward).

---

## 5. Rust crate landscape — versions verified on crates.io (2026-08-24)

All versions below were fetched live from `https://crates.io/api/v1/crates/<name>` (`max_stable_version` field) — do not treat these as memorized; re-verify at implementation time since this is a fast-moving ecosystem area (`ed25519-dalek`/`x25519-dalek` just had major version bumps).

| Crate | Latest stable | Purpose | Notes |
|---|---|---|---|
| `prost` | 0.14.4 | Protobuf codegen/runtime | Verify proto2 `extend`/extensions support against pyatv's `ProtocolMessage.proto` before committing (§1.3); may need `protobuf` (rust-protobuf) crate instead if extension support is inadequate |
| `prost-build` | 0.14.4 | Build-time `.proto` → Rust codegen | Pair with `prost` |
| `chacha20poly1305` | 0.11.0 | RFC 8439 AEAD | RustCrypto, pure Rust + optional HW accel; standard reusable-key API, no special variant needed |
| `hkdf` | 0.13.0 | HKDF-Extract/Expand | Pair with `sha2::Sha512` for all salt/info derivations in this doc |
| `sha2` | 0.11.0 | SHA-256/384/512 | Needed for HKDF and SRP |
| `ed25519-dalek` | 3.0.0 | Ed25519 sign/verify | Recent major bump (released 2026-07) — verify `SigningKey`/`VerifyingKey` API before use |
| `x25519-dalek` | 3.0.0 | X25519 ECDH | Same release wave as `ed25519-dalek`; verify API |
| `srp` | 0.6.0 | RFC 5054 SRP6a | `crypto-bigint`-backed, exposes `srp::groups::G_3072`; hash function generic — pair with `Sha512`. **High-risk item: byte-for-byte compatibility with `srptools`' padding/derivation conventions must be verified against a real pairing exchange, not assumed** |
| `plist` | 1.10.0 | Apple bplist00 / XML plist | For AirPlay RTSP SETUP bodies (§3.3) and any `NSKeyedArchiver` payloads (Companion keyboard, §4.7) — check whether it covers `NSKeyedArchiver` unarchiving specifically or only flat plists; may need custom logic layered on top |
| `mdns-sd` | 0.21.0 | mDNS/DNS-SD, no async-runtime dependency | Candidate for service discovery (`_mediaremotetv._tcp`, `_companion-link._tcp`, `_airplay._tcp`) |
| `zeroconf` | 0.18.0 | Cross-platform Bonjour/Avahi wrapper | Alternative to `mdns-sd`; binds to system mDNS stack instead of being pure-Rust — evaluate both for TXT-record access needs (this doc's discovery logic depends heavily on reading specific TXT keys like `SystemBuildVersion`, `rpfl`, `rpmd`, `allowpairing`) |
| `tokio` | 1.53.1 | Async runtime | For TCP connections, timers (heartbeats §3.3), channel dispatch |
| `bytes` | 1.12.1 | Buffer management | For frame parsing (variant/length-prefixed buffering, §1.2/§4.2) |
| `thiserror` | 2.0.20 | Error derive | |
| `rand` | 0.10.2 | RNG | For ephemeral keys, XIDs, session/seed values, UUIDs throughout pairing and Companion/AirPlay session setup |

No dedicated **OPACK** crate exists on crates.io as of this research — plan to write one in-house against §4.5 (this is a self-contained, testable subsystem, good candidate for an early milestone with a comprehensive golden-vector test suite derived from pyatv's own `tests/support/test_opack.py`, which was not fetched in this pass but should be pulled directly when writing the Rust OPACK crate's test suite).

---

## Open questions

- Does `prost` (0.14.4) support proto2 `extend`/extensions well enough to compile pyatv's `ProtocolMessage.proto` + all 76 extension `.proto` files directly, or is a fallback to the `protobuf` (rust-protobuf) crate required? This needs a hands-on spike before committing to a protobuf crate choice — it affects the entire MRP message layer.
- Is the `srp` crate (0.6.0, `crypto-bigint`-backed) byte-compatible with `srptools`' exact SRP6a implementation (padding of `N`/`g` in hash inputs, computation of multiplier `k`, proof `M1`/`M2` formulas) well enough to interoperate with real Apple TV / HomePod devices? This is unverifiable from documentation alone and requires either (a) a live device to test against, or (b) capturing/replaying a known-good pyatv pairing transcript as a fixture and asserting the Rust SRP client produces identical intermediate values.
- `ed25519-dalek` 3.0.0 and `x25519-dalek` 3.0.0 are very recent (major-version-bumped in the same 2026-07 release wave) — their exact API surface (key construction, byte (de)serialization, error types) was not independently confirmed beyond a WebFetch summary of `docs.rs`; read the actual rustdoc/changelog before writing code against them, and check for any advisories on `RUSTSEC` given the newness.
- Does the `plist` crate (1.10.0) handle `NSKeyedArchiver`-encoded binary plists (used by Companion's keyboard/`_tiD` payloads, §4.7) directly, or only "flat" plists, requiring hand-rolled `NSKeyedArchiver` unarchiving logic (object graph via `$objects`/`$top`/`$archiver` keys) on top of it? pyatv wrote its own `pyatv/protocols/companion/keyed_archiver.py` for this rather than relying on a generic library, which suggests the latter.
- Exact semantics of Companion's `_srvT`/`_sf`/`_cf`/`_clFl`/`_bf` numeric fields in `_systemInfo` are not fully understood even by pyatv's own maintainers (see verbatim source comments "semi-random values," "Status flags?," "Software Version (I guess?)") — treat these as **cargo-culted magic constants to replicate exactly**, not values to derive from first principles; if a Rust client sends different values and a real device behaves unexpectedly, start by reverting to pyatv's exact literals.
- The AirPlay data-channel `send_seqno` in pyatv (`pyatv/protocols/airplay/channels.py`, `DataStreamChannel.__init__`) is set once from `randrange(0x100000000, 0x1FFFFFFFF)` and, from the code reviewed, does not appear to be incremented on each `send_protobuf` call — confirm against a live capture whether real devices require a monotonically-increasing `seqno` per outbound frame (likely, per general Apple streaming-protocol conventions) or tolerate a fixed value, since replicating a bug vs. replicating intentional behavior matters here.
- `AirPlayFlags`/`is_remote_control_supported` bit-level gating logic (`pyatv/protocols/airplay/utils.py`) was not fetched in this pass — pull that file directly before implementing the "should I attempt the MRP tunnel" decision (§3.2), since getting the feature-bit check wrong will either cause spurious tunnel attempts against devices that don't support it, or skip the tunnel on devices that do.
- pyatv's OPACK implementation has two explicitly-acknowledged gaps (absolute-time encode not implemented; UID/back-reference edge cases possibly incomplete, per its own module docstring: "Pack implementation does not implement UID referencing" and "Likely other cases missing") — a from-scratch Rust implementation should not blindly mirror pyatv's gaps if targeting maximum device compatibility, but should be aware pyatv (the most complete public reference) has never needed to close them, which may mean those code paths are rare in practice for the remote-control use case.
- Companion pair-verify M4/M6 signature checks and MRP pair-setup M4/M6 signature checks are **not actually verified** by pyatv upstream in several spots (explicit `# TODO: check status code` / no-signature-check comments noted inline in §2.2/§2.3/§3.3) — decide deliberately whether the Rust port should be stricter (verify everything per spec, safer) even though this means the reference implementation's exact behavior isn't fully known for the unverified paths.
