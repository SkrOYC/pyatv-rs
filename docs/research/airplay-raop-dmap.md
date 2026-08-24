# AirPlay (1 & 2), RAOP/AirTunes, and DMAP/DAAP Protocol Internals — Research Report

Scope: ground-truth protocol details extracted from the pyatv source tree (branch `master`, version string `0.18.0` as of 2026-08-24) plus the unofficial AirPlay 2 spec and the `airplay2-receiver` reference implementation, aimed at engineers implementing a pure-Rust reimplementation of pyatv. All facts below were verified against source code or live documentation on 2026-08-24; no detail is stated from unverified training-data memory.

Primary sources used (cite these inline throughout):
- pyatv source tree: https://github.com/postlund/pyatv (branch `master`)
- pyatv protocol documentation (single long Markdown page, source of truth for wire examples): https://raw.githubusercontent.com/postlund/pyatv/master/docs/documentation/protocols.md (rendered at https://pyatv.dev/documentation/protocols/)
- Unofficial AirPlay 2 spec: https://emanuelecozzi.net/docs/airplay2/ (status: explicitly marked "incomplete" by its author)
- Unofficial AirPlay spec (feature bits mirror): https://openairplay.github.io/airplay-spec/features.html and https://openairplay.github.io/airplay-spec/status_flags.html
- Reference receiver implementation: https://github.com/openairplay/airplay2-receiver
- crates.io (versions checked live via the crates.io API on 2026-08-24)

---

## 1. High-level protocol map

pyatv treats "AirPlay" as three cooperating layers, implemented in three source directories:
- `pyatv/protocols/airplay/` — the AirPlay-proper layer: mDNS parsing, HAP/legacy authentication, the `/play` (PlayURL) flow, and the AirPlay 2 remote-control tunnel (event + data channels) that MRP rides on top of. Source: https://github.com/postlund/pyatv/tree/master/pyatv/protocols/airplay
- `pyatv/protocols/raop/` — the RAOP/AirTunes audio-streaming layer: RTSP session, UDP audio/control/timing sockets, packet framing, audio source handling. Source: https://github.com/postlund/pyatv/tree/master/pyatv/protocols/raop
- `pyatv/protocols/dmap/` — the legacy DMAP/DAAP/DACP "Home Sharing" remote-control protocol used by original Apple Remote app and iTunes-era Apple TVs. Source: https://github.com/postlund/pyatv/tree/master/pyatv/protocols/dmap

A single mDNS/Bonjour TCP port (from the `_airplay._tcp` or `_raop._tcp` SRV record, commonly but not reliably 7000 or 5000 — pyatv never hardcodes it, always reads it from the SRV record) carries a non-standard "RTSP-flavored HTTP" connection: requests/responses look like HTTP/1.1 but the RTSP verbs (`ANNOUNCE`, `SETUP`, `RECORD`, `SET_PARAMETER`, `FLUSH`, `TEARDOWN`, `GET_PARAMETER`) are sent over it, `Content-Type` is often `application/x-apple-binary-plist` or `application/sdp`, and after AirPlay-2 Pair-Verify the entire connection (not just a sub-channel) is wrapped in HAP's ChaCha20-Poly1305 framing. Source: https://github.com/postlund/pyatv/blob/master/pyatv/support/http.py and https://github.com/postlund/pyatv/blob/master/pyatv/support/rtsp.py

pyatv's own protocol version detection (`AirPlayMajorVersion`) is a heuristic, not a documented field: it looks at the `features`/`ft` TXT bitmask and treats the service as AirPlay 2 if either bit 38 (`SupportsUnifiedMediaControl`) or bit 48 (`SupportsCoreUtilsPairingAndEncryption`) is set, else it falls back to AirPlay 1. Source (with pyatv's own admission this is a guess): https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/utils.py lines 237-259 (`get_protocol_version`).

---

## 2. mDNS service types and TXT record keys

pyatv registers scan handlers per service type; the exact TXT keys it reads are listed below (the "unknown"/best-guess ones are flagged as such — pyatv itself treats them as unverified reverse-engineering).

### 2.1 `_airplay._tcp.local.` (AirPlay control service)

Handler: `airplay_service_handler` in https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/__init__.py (lines 180-223).

| Key | Meaning | Consumed by pyatv how |
|---|---|---|
| `features` (or `ft`) | 64-bit feature bitmask, format `0xLOW` or `0xLOW,0xHIGH` | `parse_features()` — see §3 |
| `flags` (or `sf` on RAOP) | status flags bitmask | `is_password_required`, `get_pairing_requirement` — see §4 |
| `model` | e.g. `AppleTV6,2` | mapped via `lookup_model()` to `DeviceModel`; also matched against `UNSUPPORTED_MODELS = [r"^Mac\d+,\d+$"]` to force `PairingRequirement.Unsupported` |
| `osvers` | OS version string, e.g. `14.5` | stored as `DeviceInfo.VERSION`; major version used by `is_remote_control_supported()` (must be ≥13 for `AppleTV*` models) |
| `deviceid` | MAC address | `DeviceInfo.MAC` |
| `pk` | Ed25519 long-term public key (hex), used for HAP identity | not directly parsed by pyatv scan code, but part of the wire example |
| `psi` | Public (system) pairing identity UUID | `DeviceInfo.OUTPUT_DEVICE_ID` (preferred over `pi`) |
| `pi` | Group/pairing identity UUID | fallback for `DeviceInfo.OUTPUT_DEVICE_ID` if `psi` absent |
| `acl` | Access Control Level; `acl=1` ⇒ pairing forced to `PairingRequirement.Disabled` (e.g. "only devices in this Home") | `update_service_details()` |
| `act` | Access Control Type; `act=2` ("Current User") ⇒ `PairingRequirement.Unsupported` (pyatv doesn't support this scheme) | `get_pairing_requirement()` |
| `gid` | Group UUID (multi-room) | documentation only, not parsed |
| `gcgl` | "Group Contains Group Leader" | documentation only |
| `igl` | "Is Group Leader" | documentation only |
| `pw` | `"true"`/`"false"` — password required | `is_password_required()` |

Full documented example row set, including a few undeciphered keys (`vv`, `fex`, `protovers`, `btaddr`), is in the pyatv docs table: https://github.com/postlund/pyatv/blob/master/docs/documentation/protocols.md lines 1218-1238.

### 2.2 `_raop._tcp.local.` (RAOP/AirTunes audio service)

Handler: `raop_service_handler` in https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/__init__.py (lines 444-467). Service name is `<AAAAAAAAAAAA>@<Friendly Name>._raop._tcp.local`; pyatv strips the `@`-prefixed device id via `raop_name_from_service_name()`.

| Key | Meaning | Consumed by pyatv how |
|---|---|---|
| `et` | Encryption types, comma-separated list of small ints: `0=Unencrypted, 1=RSA, 3=FairPlay, 4=MFiSAP, 5=FairPlaySAPv2.5` | `get_encryption_types()` in https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/parsers.py; pyatv only actively supports `Unencrypted` and `MFiSAP` (`SUPPORTED_ENCRYPTIONS`), and only does the `/auth-setup` MFiSAP dance for `AirPort*` model names (issue-driven workaround) |
| `cn` | Codecs, comma-separated: `0=PCM, 1=ALAC, 2=AAC, 3=AAC-ELD, 4=OPUS` | documented but **not parsed by pyatv** — pyatv always sends raw PCM (see §9) |
| `md` | Metadata types supported, comma-separated: `0=text, 1=artwork, 2=progress` | `get_metadata_types()`, same file; gates whether `SET_PARAMETER` metadata/artwork/progress calls are made |
| `sr` | Sample rate, e.g. `44100` | `get_audio_properties()` |
| `ss` | Sample size in bits, e.g. `16` | `get_audio_properties()` (divided by 8 for bytes) |
| `ch` | Channel count, e.g. `2` | `get_audio_properties()` |
| `am` | Apple device model string, e.g. `AppleTV6,2` | mapped via `lookup_model()`; also gates the MFiSAP `/auth-setup` heuristic (`am` startswith `AirPort`) |
| `ov` | OS version (seen on ATV3) | `DeviceInfo.VERSION` |
| `pw` | password required, `"true"`/`"false"` | reused from AirPlay logic (`is_password_required`) |
| `tp` | Transport protocols, e.g. `TCP,UDP` | documentation only |
| `vs` | Server version | documentation only |
| `vn` | Version number, `uint16.uint16` packed into one uint32 (e.g. `65537` = `1.1`) | documentation only |
| `sv` / `sm` | Software Volume / Software Mute flags | documentation only |
| `da` | Digest Authentication supported | documentation only |
| `pk` | Public key | documentation only |
| `ft` | Features bitmask (same 64-bit format as AirPlay's `features`) | `extract_credentials()`/`get_protocol_version()` reuse this key as fallback |
| `sf` | System/status flags bitmask (same format as AirPlay's `flags`) | `update_service_details()` reuses the shared `_get_flags()` helper which reads `sf` OR `flags` |
| `txtvers` | TXT record schema version, always `"1"` | ignored |

There is also an **`_airport._tcp.local.`** companion service scanned purely for extra `DeviceInfo`, no protocol data: it carries a `wama` key (`macaddress=...,syVs=...`) used to backfill MAC and firmware version for AirPort Express devices. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/__init__.py lines 458-493.

### 2.3 `_touch-able._tcp.local.` (DMAP, no Home Sharing)

Handler: `dmap_service_handler`. Friendly name comes from TXT key `CtlN`. Service credentials are not populated from mDNS for this service type — pairing is mandatory. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/dmap/__init__.py lines 592-627.

### 2.4 `_appletv-v2._tcp.local.` (DMAP Home Sharing)

Handler: `homesharing_service_handler`. Friendly name comes from TXT key `Name`. Credentials are read directly from TXT key `hG` (the Home Sharing GUID) if present — this lets pyatv skip pairing entirely when Home Sharing is already enabled on the device. `service_info()` sets `PairingRequirement.Optional` if a case-insensitive `hg` key is present in the properties dict (the TXT dict is case-insensitive, see §2.6), else `Mandatory`. Source: same file, lines 577-590 and 643-657.

### 2.5 `_hscp._tcp.local.` (Home Sharing Control Protocol, seen on Apple TV "Music"/remote-app-only endpoints)

Handler: `hscp_service_handler`. Friendly name from TXT key `Machine Name`. Also reads `hG` for credentials, same as §2.4. `device_info()` additionally sets `DeviceInfo.MODEL = DeviceModel.Music` for this service type specifically. Source: same file, lines 606-618 and 630-640.

### 2.6 `_touch-remote._tcp.local.` (published BY pyatv itself during DMAP pairing, not scanned)

pyatv's own DMAP pairing handler (`DmapPairingHandler`) publishes this service while waiting for the user to enter the on-device PIN. TXT keys it sets: `DvNm` (device name), `RemV="10000"`, `DvTy="iPod"`, `RemN="Remote"`, `txtvers="1"`, `Pair=<pairing guid hex>`. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/dmap/pairing.py lines 104-124.

### 2.7 TXT record decoding mechanics

pyatv's mDNS core (`pyatv/core/mdns.py`) decodes every TXT record value with `decode_value()` and stores properties in a `CaseInsensitiveDict[str]` (`_decode_properties()`, line 73-76), so all TXT-key lookups throughout the codebase (`"hg"` vs `"hG"`, `"Name"` vs `"name"`) are effectively case-insensitive at the point of consumption. Source: https://github.com/postlund/pyatv/blob/master/pyatv/core/mdns.py

---

## 3. AirPlay feature bitmask (64-bit `features`/`ft`)

### 3.1 Wire format and parsing algorithm

The TXT value is either a single hex literal (`0x12345678`, low 32 bits only, high 32 bits implicitly 0) or a comma-separated pair `0xLOW,0xHIGH` where `HIGH` occupies bits 32-63. pyatv's exact parse regex and reassembly:

```python
match = re.match(r"^0x([0-9A-Fa-f]{1,8})(?:,0x([0-9A-Fa-f]{1,8})|)$", features)
value, upper = match.groups()
if upper is not None:
    value = upper + value          # string concatenation, then int(value, 16)
return AirPlayFlags(int(value, 16))
```

i.e. if a high part is present, its hex digits are **string-prepended** to the low part before parsing as one big hex integer — equivalent to `(high << 32) | low`. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/utils.py lines 104-118 (`parse_features`).

### 3.2 Full bit table (`AirPlayFlags` `IntFlag`, verified against pyatv source and cross-checked against https://emanuelecozzi.net/docs/airplay2/features/, which pyatv itself cites as its source and notes "seems to be some inconsistencies" with https://openairplay.github.io/airplay-spec/features.html)

| Bit | Name | Bit | Name |
|---|---|---|---|
| 0 | SupportsAirPlayVideoV1 | 43 | SupportsSystemPairing |
| 1 | SupportsAirPlayPhoto | 44 | IsAPValeriaScreenSender |
| 5 | SupportsAirPlaySlideShow | 46 | SupportsHKPairingAndAccessControl |
| 7 | SupportsAirPlayScreen | 48 | SupportsCoreUtilsPairingAndEncryption |
| 9 | SupportsAirPlayAudio | 49 | SupportsAirPlayVideoV2 |
| 11 | AudioRedundant | 50 | MetadataFeatures_3 |
| 14 | Authentication_4 (FairPlay auth) | 51 | SupportsUnifiedPairSetupandMFi |
| 15 | MetadataFeatures_0 | 52 | SupportsSetPeersExtendedMessage |
| 16 | MetadataFeatures_1 | 54 | SupportsAPSync |
| 17 | MetadataFeatures_2 | 55 | SupportsWoL |
| 18 | AudioFormats_0 | 56 | SupportsWoL2 |
| 19 | AudioFormats_1 | 58 | SupportsHangdogRemoteControl |
| 20 | AudioFormats_2 | 59 | SupportsAudioStreamConnectionSetup |
| 21 | AudioFormats_3 | 60 | SupportsAudioMetadataControl |
| 23 | Authentication_1 (RSA) | 61 | SupportsRFC2198Redundancy |
| 26 | Authentication_8 (MFi) | | |
| 27 | SupportsLegacyPairing | | |
| 30 | HasUnifiedAdvertiserInfo | | |
| 32 | IsCarPlay (possibly also "SupportsVolume") | | |
| 33 | SupportsAirPlayVideoPlayQueue | | |
| 34 | SupportsAirPlayFromCloud | | |
| 35 | SupportsTLS_PSK | | |
| 38 | SupportsUnifiedMediaControl | | |
| 40 | SupportsBufferedAudio | | |
| 41 | SupportsPTP | | |
| 42 | SupportsScreenMultiCodec | | |

Source (exact enum): https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/utils.py lines 55-98 (`AirPlayFlags`).

Bits not listed are unknown to both pyatv and the emanuelecozzi.net spec as of research date.

### 3.3 How the bitmask drives behavior in pyatv

- `AirPlayMajorVersion` decision: AirPlay 2 iff bit 38 or bit 48 set (§1).
- `HasUnifiedAdvertiserInfo` (bit 30): if set and no separate `_raop._tcp` service was found for a device, pyatv **synthesizes** a RAOP `MutableService` pointing at the same host/port/credentials as the AirPlay service, because AirPlay 2 allows audio-only receivers to skip publishing `_raop._tcp` separately. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/__init__.py lines 338-372.
- `SupportsSystemPairing` (bit 43) or `SupportsCoreUtilsPairingAndEncryption` (bit 48): if either is set **and** no persisted credentials exist yet, pyatv defaults to `TRANSIENT_CREDENTIALS` rather than `NO_CREDENTIALS` when extracting credentials for a connection. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/auth/__init__.py lines 120-134 (`extract_credentials`).
- Remote-control-tunnel eligibility (`is_remote_control_supported`) is **not** bit-based; it is a model/OS heuristic pyatv itself flags as a guess (see §5.4).

---

## 4. AirPlay status flags (`flags`/`sf`) and pairing-requirement logic

Only 3 bits are actually decoded by pyatv (rest are undocumented / delegated to the emanuelecozzi.net "status_flags" reference, which returned HTTP 404 at the specific sub-path checked during this research — only the aggregate examples `flags=0x244`, `flags=0x404`, decoded `statusFlags: 580` are attested in the pyatv docs and openairplay spec index):

```python
PIN_REQUIRED = 0x8
PASSWORD_BIT = 0x80
LEGACY_PAIRING_BIT = 0x200
```
Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/utils.py lines 24-27.

Decision logic (`_get_flags()` reads `sf`, falling back to `flags`, falling back to `"0x0"`):
- `is_password_required(service)`: `True` if TXT `pw == "true"` OR `(flags & PASSWORD_BIT) != 0`.
- `get_pairing_requirement(service)`: `PairingRequirement.Mandatory` if `flags & (LEGACY_PAIRING_BIT | PIN_REQUIRED)` is nonzero; else `PairingRequirement.Unsupported` if TXT `act == "2"` ("Current User" access control, unsupported by pyatv); else `PairingRequirement.NotNeeded`.
- `update_service_details(service)` (the actual entry point called from both AirPlay's and RAOP's `service_info()`): overrides the above to `Disabled` if `acl == "1"`, or to `Unsupported` if the `model` TXT value matches `^Mac\d+,\d+$` (macOS senders publish AirPlay services pyatv doesn't support pairing with), otherwise falls through to `get_pairing_requirement()`.

Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/utils.py lines 121-278.

---

## 5. Authentication flavors

pyatv's `AuthenticationType` enum has exactly four members, discriminated purely by the *shape* of the stored `HapCredentials` tuple `(ltpk, ltsk, atv_id, client_id)` — there is no explicit type tag on the wire or in storage:

| Type | Shape | Meaning |
|---|---|---|
| `Null` | all four fields empty | no credentials at all (`NO_CREDENTIALS` sentinel) |
| `Transient` | `ltpk == b"transient"` (literal sentinel, others empty) | ephemeral HAP "transient pairing" — `TRANSIENT_CREDENTIALS` sentinel, never persisted long-term |
| `Legacy` | `ltpk==b""`, `ltsk!=b""`, `atv_id==b""`, `client_id!=b""` | pre-HAP AirPlay 1 "device auth" (used by AirPort Express, old Apple TVs) |
| `HAP` | all four fields non-empty | full HomeKit Accessory Protocol pairing (long-term Ed25519 keypair + peer identity) |

Source: https://github.com/postlund/pyatv/blob/master/pyatv/auth/hap_pairing.py lines 32-69, 123-124.

Serialized credential string format (what pyatv stores/persists, e.g. in `--airplay-credentials`): `HapCredentials` becomes `hex(ltpk):hex(ltsk):hex(atv_id):hex(client_id)`, and `parse_credentials()` also accepts a legacy 2-part form `hex(client_id):hex(ltsk)` for backward compatibility with old configs. Source: same file, lines 71-147.

### 5.1 Selection logic (`extract_credentials`)

```
if service.credentials is not None:
    return parse_credentials(service.credentials)          # previously-paired
if SupportsSystemPairing or SupportsCoreUtilsPairingAndEncryption in feature-bits:
    return TRANSIENT_CREDENTIALS
return NO_CREDENTIALS
```
Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/auth/__init__.py lines 120-134.

### 5.2 Pair-Setup procedure dispatch (only `Legacy` and `HAP` support Pair-Setup — `Transient` has no separate setup step, `Null` has no setup at all)

```
Legacy -> AirPlayLegacyPairSetupProcedure  (LegacySRPAuthHandler)
HAP    -> AirPlayHapPairSetupProcedure     (SRPAuthHandler, standard HAP)
else   -> NotSupportedError
```
Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/auth/__init__.py lines 58-75.

### 5.3 Pair-Verify procedure dispatch (all four types support verify; `Null` and legacy paths never yield encryption keys)

```
Null      -> NullPairVerifyProcedure          (always returns False, no encryption)
Legacy    -> AirPlayLegacyPairVerifyProcedure  (LegacySRPAuthHandler; verify_credentials always returns False, no encryption)
HAP       -> AirPlayHapPairVerifyProcedure     (SRPAuthHandler + stored credentials; returns True)
Transient -> AirPlayHapTransientPairVerifyProcedure (SRPAuthHandler, PIN=3939; returns True)
```
Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/auth/__init__.py lines 78-97.

`verify_connection()` then checks the boolean: if `True`, it derives `Control-Salt`/`Control-Write-Encryption-Key`/`Control-Read-Encryption-Key` keys via HKDF and wraps the **entire RTSP/HTTP connection** (not a sub-channel) in a `HAPSession` (block-framed ChaCha20-Poly1305, §7.4). This means for AirPlay 1 (`Legacy`/`Null`) the control connection stays in cleartext even after Pair-Verify; for AirPlay 2 (`HAP`/`Transient`) it becomes encrypted. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/auth/__init__.py lines 100-117.

### 5.4 Which flavor a real device needs — pyatv's heuristics (explicitly marked "guesses" in comments)

- Remote-control tunnel eligibility (`is_remote_control_supported`): HomePods (`model` startswith `AudioAccessory`) support it only with `Transient` credentials; `AppleTV*` models support it only if `osvers` major version ≥ 13 **and** credentials type is `HAP`; everything else: unsupported. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/utils.py lines 160-180.
- AirPlay 1 devices needing `/auth-setup` (MFiSAP, Curve25519 dummy handshake, unverified, static public key borrowed from owntone-server) are gated on `EncryptionType.MFiSAP in et` **and** `am` startswith `AirPort` — narrowed specifically because "some receivers won't play audio if setup process isn't finished" per a linked GitHub issue. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/stream_client.py lines 353-363, referencing https://github.com/postlund/pyatv/issues/1134.

### 5.5 HAP Pair-Setup (M1-M6) — cryptographic parameters

SRP context: `Pair-Setup` label, **3072-bit prime group** (`constants.PRIME_3072` / `PRIME_3072_GEN` from `srptools`), hash function **SHA-512**. Source: https://github.com/postlund/pyatv/blob/master/pyatv/auth/hap_srp.py lines 138-146 (`step1`).

Key derivation after SRP session key `K` is established (all via HKDF-SHA512, empty-salt-vs-named-salt as shown):
- `ios_device_x = HKDF(salt="Pair-Setup-Controller-Sign-Salt", info="Pair-Setup-Controller-Sign-Info", ikm=K)`
- `session_key = HKDF(salt="Pair-Setup-Encrypt-Salt", info="Pair-Setup-Encrypt-Info", ikm=K)` — used to ChaCha20-Poly1305-encrypt the M5/M6 TLV8 payloads with fixed nonces `"PS-Msg05"` / `"PS-Msg06"` (8-byte ASCII nonce, left-padded to 12 bytes by the 8-byte-nonce Chacha20 wrapper — see §7.4).
- Client signs `ios_device_x || pairing_id || auth_public(Ed25519)` with its Ed25519 signing key, embeds `{Identifier, PublicKey, Signature}` (+ optional `Name` OPACK-wrapped) as TLV8, encrypts with the session key.
- Device (ATV) response M6 similarly TLV8-encoded, decrypted with the same session key; contains the device's identifier/signature/public key which become `atv_id`/`ltpk` in the resulting `HapCredentials(ltpk=atv_pub_key, ltsk=own_private_key, atv_id=atv_identifier, client_id=own_pairing_id)`.

Source: https://github.com/postlund/pyatv/blob/master/pyatv/auth/hap_srp.py lines 138-233 (`step1`-`step4`), and TLV8 sequence numbers cross-verified against the live pyatv docs wire capture at https://github.com/postlund/pyatv/blob/master/docs/documentation/protocols.md lines 605-714 (this capture is for the Companion protocol, but the M1-M6 TLV8 semantics — `_pd` tag values `Method=0x00/SeqNo=0x06/Salt=0x02/PublicKey=0x03/Proof=0x04/EncryptedData=0x05` — are the same HAP primitives AirPlay's Pair-Setup reuses; AirPlay wraps them directly in HTTP `POST /pair-setup` bodies rather than Companion's OPACK/framed transport).

AirPlay HTTP framing for Pair-Setup: `POST /pair-pin-start` (empty body, triggers on-screen PIN display) then three `POST /pair-setup` calls each carrying a raw TLV8 body (`Content-Type: application/octet-stream`, custom header `X-Apple-HKP: 3`), i.e. M1(seq=1)→M2, M3(seq=3, pubkey+proof)→M4, M5(seq=5, encrypted data)→M6. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/auth/hap.py lines 20-94.

### 5.6 HAP Pair-Verify — cryptographic parameters

X25519 ECDH key exchange (fresh ephemeral keypair each time), session key = HKDF-SHA512 with salt `"Pair-Verify-Encrypt-Salt"` / info `"Pair-Verify-Encrypt-Info"` over the X25519 shared secret. TLV8 payloads for M2/M3 are ChaCha20-Poly1305-encrypted with fixed nonces `"PV-Msg02"` / `"PV-Msg03"`. Device identity is checked by verifying an Ed25519 signature over `session_pub_key || atv_id || client_pub_key` against the stored `ltpk`. HTTP framing: two `POST /pair-verify` calls, `X-Apple-HKP: 3` for standard HAP. Source: https://github.com/postlund/pyatv/blob/master/pyatv/auth/hap_srp.py lines 84-136 and https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/auth/hap.py lines 97-152.

Final derived per-channel keys use HKDF-SHA512 again, this time with the **raw X25519 shared secret** (not the SRP `K`) as IKM, and salts/infos specific to the target channel (`Control-Salt` for the main connection, `Events-Salt` for the event channel, `DataStream-Salt<seed>` for the data channel — see §8).

### 5.7 HAP Transient Pair-Verify (bit 43/48 devices, e.g. many current-generation Apple TVs / HomePods without a persisted pairing)

Folds the first four states of regular Pair-Setup (M1-M4) into the verify step: `POST /pair-pin-start` then `POST /pair-setup` with `Flags = 0x10` (`hap_tlv8.Flags.TransientPairing`) and a **hardcoded PIN of `3939`** (`TRANSIENT_PIN = 3939`), `X-Apple-HKP: 4`. Because it is transient, no signature verification or persisted `ltpk`/`atv_id` is produced — the resulting `HapCredentials` sentinel is the constant `TRANSIENT_CREDENTIALS = HapCredentials(b"transient")` and per-channel keys are derived straight from the SRP shared key via `hkdf_expand`. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/auth/hap_transient.py.

### 5.8 Legacy device auth (AirPlay 1 / AirPort Express / old Apple TVs)

Uses a **different, older SRP flavor**: 2048-bit group (`constants.PRIME_2048`/`PRIME_2048_GEN`), and a nonstandard session-key derivation `K = SHA512(S||0x00000000) || SHA512(S||0x00000001)` (`AtvSRPContext.get_common_session_key`, deliberately overriding the RFC 5054 default). PIN entry flow: `POST /pair-pin-start` then three `POST /pair-setup-pin` calls with plist bodies `{method:"pin", user:<hex client id>}` → `{pk, proof}` → `{epk, authTag}`. Verification flow: `POST /pair-verify` with a raw binary body (no TLV8) — `0x01000000 || X25519_pubkey(32) || Ed25519_pubkey(32)`, response's first 32 bytes are the device's X25519 public key; the client then signs and AES-128-CTR/GCM-encrypts (SHA-512-derived keys, labels `"Pair-Verify-AES-Key"`/`"Pair-Verify-AES-IV"` for verify, `"Pair-Setup-AES-Key"`/`"Pair-Setup-AES-IV"` for setup, the IV's **last byte incremented by 1** for the setup case) and posts back `0x00000000 || signature`. `verify_credentials()` always returns `False` here — legacy verify **never yields encryption keys**, so the RTSP connection stays cleartext even for paired legacy devices. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/srp.py (full file) and https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/auth/legacy.py.

`new_credentials()` for a fresh legacy pairing session synthesizes `HapCredentials(ltpk=b"", ltsk=urandom(32), atv_id=b"", client_id=urandom(8))` — i.e. the "LTSK" slot actually holds an Ed25519 signing seed and "client_id" is just a random 8-byte identifier, deliberately overloading the `HapCredentials` struct.

---

## 6. AirPlay 2 channel encryption (event/data channel and control-connection framing)

All AirPlay-2 channels — the main RTSP control connection (post Pair-Verify), the event channel, and the data channel — use the same block cipher framing, described in the HAP spec §5.2.2 and mirrored by pyatv's `HAPSession`:

```
| Length (2 bytes, little-endian) | Ciphertext (Length bytes) | Poly1305 auth tag (16 bytes) |
```

AAD for each block is the 2-byte length field itself. Encrypt-side splits plaintext into ≤1024-byte frames (`FRAME_LENGTH = 1024`, "as specified by HAP §5.2.2"); decrypt-side has **no hard 1024-byte cap** — it trusts the length prefix (implementers should still bound this for safety in a from-scratch reimplementation). Nonce is a 12-byte little-endian monotonically-incrementing counter, one independent counter per direction, reset per-channel/per-connection (standard `Chacha20Cipher`, 12-byte nonce variant — not the 8-byte-nonce variant used for audio packets, see §9.3). Source: https://github.com/postlund/pyatv/blob/master/pyatv/auth/hap_session.py and https://github.com/postlund/pyatv/blob/master/pyatv/support/chacha20.py.

Per-channel HKDF salt/info labels (all HKDF-SHA512 over the Pair-Verify X25519 shared secret):

| Channel | Output (write) info | Input (read) info | Salt |
|---|---|---|---|
| Main RTSP/control connection | `Control-Write-Encryption-Key` | `Control-Read-Encryption-Key` | `Control-Salt` |
| Event channel | `Events-Write-Encryption-Key` | `Events-Read-Encryption-Key` | `Events-Salt` |
| Data (remote-control/MRP tunnel) channel | `DataStream-Output-Encryption-Key` | `DataStream-Input-Encryption-Key` | `DataStream-Salt<seed>` (seed = 64-bit `seed` field returned in the stream SETUP response, treated as unsigned) |

Sources: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/auth/__init__.py lines 36-38, https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/protocols/airplayv2.py lines 21-23, and https://github.com/postlund/pyatv/blob/master/docs/documentation/protocols.md lines 1758-1816.

Important asymmetry pyatv's docs explicitly call out: for the **event channel**, even though the *sender* opens the TCP connection, key roles are reversed — the sender must use the "Output" key as its *input* (decrypt) key and vice versa, because the channel is conceptually "owned" by the receiver. Source: https://github.com/postlund/pyatv/blob/master/docs/documentation/protocols.md lines 1763-1765.

---

## 7. AirPlay 2 remote-control tunnel setup flow (control + event + data channels)

This is how pyatv rides MRP over AirPlay 2 when a separate MRP mDNS service isn't advertised or isn't wanted. Full sequence (condensed from https://github.com/postlund/pyatv/blob/master/docs/documentation/protocols.md lines 1560-1751, cross-checked against implementation at https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/ap2_session.py):

1. Sender opens the main TCP connection to the AirPlay port, performs Pair-Verify (§5.6/5.7), enabling `HAPSession` block encryption on the connection (§6).
2. Sender sends `SETUP` (binary plist body) with `isRemoteControlOnly: true` plus a bag of client-identification fields (`osName`, `sourceVersion`, `timingProtocol: "None"`, `model`, `deviceID`, `osVersion`, `osBuildVersion`, `macAddress`, `sessionUUID`, `name`).
3. Receiver responds `{ "eventPort": <u16> }`.
4. Sender opens a **new** TCP connection to `eventPort`, does the reversed-key HAP channel setup described in §6 (`EventChannel` in pyatv), and treats subsequent RTSP-shaped messages arriving on it as receiver→sender pushes (see §7.1 for what arrives here — a `POST /command` "system info update").
5. Sender sends `RECORD` on the main connection (no CSeq gap concerns other than iOS optionally probing `/info` first).
6. Receiver sends a `POST /command` with `{type:"updateInfo", value:{...huge device state dict...}}` on the **event channel**; sender must respond `200 OK` within 30s or the channel is closed.
7. Sender sends a second `SETUP` on the main connection with a `streams` array element `{controlType: 2, channelID: <uuid>, seed: <i64>, clientUUID: <uuid>, type: 130, wantsDedicatedSocket: true, clientTypeUUID: <uuid>}` — `type: 130` = remote control stream, `clientTypeUUID = 1910A70F-DBC0-4242-AF95-115DB30604E1` specifically identifies "Media Remote" as the client role (other values exist for other client kinds, undocumented).
8. Receiver responds `{"streams":[{"type":130,"streamID":<u32>,"dataPort":<u16>}]}`.
9. Sender opens a **third** TCP connection to `dataPort`, HAP-channel-encrypts it using the `DataStream-Salt<seed>` keys from §6 — this is `DataStreamChannel` in pyatv, and it carries length-prefixed, varint-length-prefixed protobuf `ProtocolMessage`s identical to the standalone MRP protocol's wire format (see the message-frame layout in §7.2).
10. Sender must POST `/feedback` on the main connection every ~2 seconds indefinitely as a keepalive (`FEEDBACK_INTERVAL = 2.0` in pyatv). Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/protocols/airplayv2.py lines 25 & 167-181.

### 7.1 Event-channel message framing

Plain RTSP-style request/response over the HAP-encrypted event channel (i.e. HAP framing is the outer layer, RTSP/HTTP text framing is the inner layer). pyatv's `EventChannel.handle_received()` just parses whatever request arrives, and replies `200 OK` with `Content-Length: 0`, `Audio-Latency: 0`, echoing `Server`/`CSeq` headers if present — it does not act on the payload content beyond logging. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/channels.py lines 34-98.

### 7.2 Data-channel (`DataStreamChannel`) message frame — exact byte layout

```
| Size (4 bytes, big-endian) | Message Type (12 bytes ASCII, zero-padded) | Command (4 bytes ASCII) | Sequence Number (8 bytes) | Padding (4 bytes, always 0) | Payload (Size-32 bytes) |
```
`Size` includes the 32-byte header itself. `Message Type` is either `"sync"` (request) or `"rply"` (response), remainder zero-padded. `Command` is `"comm"` (sender→receiver, constant sequence-number-upper-32-bits=1 pattern, lower 32 bits random per session) or `"cmnd"` (receiver→sender, each request gets a fresh random sequence number) — `"rply"` messages zero out the `Command` field and echo back the sequence number of the `sync` they answer. Payload (when present) is a binary plist of shape `{"params": {"data": <bytes>}}` where `data` is a concatenation of protobuf messages, each prefixed by its own length as a Protobuf-style base-128 varint (except for `ConfigureConnectionMessage`, which is a known special case sent unprefixed — pyatv detects this because valid protobuf messages always start with byte `0x08` for field #1). Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/channels.py lines 27-32, 100-226 (matches the pyatv docs description at https://github.com/postlund/pyatv/blob/master/docs/documentation/protocols.md lines 1818-1889, which was written for the standalone Companion transport but pyatv's actual `channels.py` code for the AirPlay-2 data channel implements the identical `sync`/`rply`/`comm`/`cmnd` scheme, confirming they share a wire format).

### 7.3 `/feedback` and `/info`

`/feedback` is a plain `POST` with no body on the main connection; used both as AirPlay-2 keepalive (every 2s, indefinite, best-effort — errors are swallowed) and, for AirPlay 1, as an optional one-shot capability probe before starting a periodic 25-second keepalive loop if the receiver answers `200`. `/info` (`GET`) returns a binary plist of device info; pyatv calls it once during RAOP `StreamClient.initialize()`, treats non-200 as "not supported, use empty dict", and among other things looks for an `initialVolume` float key to seed volume state before playback starts. Sources: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/protocols/airplayv1.py lines 87-109, https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/protocols/airplayv2.py lines 167-181, https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/stream_client.py lines 330-331 & 383-391.

---

## 8. `play_url` (PlayURL) flow

Exposed as `Stream.play_url()`. If the given `url` is a local filesystem path, pyatv spins up a throwaway `aiohttp`-based `StaticFileWebServer` bound to the local address that can reach the target device, serving **only that single file** (a middleware 401s any other path), and rewrites `url` to `http://<local-ip>:<ephemeral-port>/<filename>`. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/__init__.py lines 106-146 and https://github.com/postlund/pyatv/blob/master/pyatv/support/http.py lines 608-647.

AirPlay-1 flow (`AirPlayV1.play_url`): Pair-Verify only (no SETUP/RECORD/audio streaming), then `POST /play` with headers `User-Agent: MediaControl/1.0`, `Content-Type: application/x-apple-binary-plist`, body `{"Content-Location": url, "Start-Position": position, "X-Apple-Session-ID": <uuid4>}`. The coroutine does not return until the device finishes playing (the connection is held open for the whole duration) — cancelling it is how `stop()`/`AirPlayRemoteControl.stop()` work (they just close the connection). Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/protocols/airplayv1.py lines 119-137.

AirPlay-2 flow (`AirPlayV2.play_url`): full remote-control-tunnel-style base setup (`_setup_base`, same as §7 steps 1-4 minus the dedicated remote-control stream), starts the 2s feedback loop, sends `RECORD`, then `POST /play` (headers `X-Apple-ProtocolVersion: 1`, `X-Apple-Session-ID: <uuid4>`, `X-Apple-Stream-ID: 1`) with a much larger binary-plist body including timing-telemetry fields pyatv fabricates for compatibility (`secureConnectionMs`, `infoMs`, `connectMs`, `authMs`, `bonjourMs`, `postAuthMs` — all hardcoded small integers, not real measurements) plus `Content-Location`, `Start-Position-Seconds`, `uuid`, `streamType: 1`, `mediaType: "file"`, `playbackRestrictions: 0`, `referenceRestrictions: 3`, `rate: 1.0`. Followed by four more RTSP-verb `PUT`/`POST` calls: `PUT /setProperty?isInterestedInDateRange {value:true}`, `PUT /setProperty?actionAtItemEnd {value:0}`, `POST /rate?value=1.000000` (pyatv's own comment: "most important command ... will start paused otherwise"), and two `PUT /setProperty?forwardEndTime` / `reverseEndTime` calls with a zeroed `{flags,value,epoch,timescale}` struct. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/protocols/airplayv2.py lines 210-273.

---

## 9. RAOP/AirTunes RTSP session — full request sequence

Base RTSP mechanics implemented by pyatv's hand-rolled `RtspSession` (not RFC 7826 compliant — it is the historical Apple "RTSP-over-a-plain-TCP-socket-shared-with-HTTP-framing" variant): every request carries `CSeq` (monotonic per-connection counter starting at 0), `DACP-ID` (random 64-bit hex, fixed per session), `Active-Remote` (random 32-bit decimal, fixed per session), `Client-Instance` (same value as `DACP-ID`), and `User-Agent: AirPlay/550.10` (pyatv's identity string; note the historical example capture in the docs used `AirPlay/540.31`/`AirPlay/320.20` for older code paths — the exact string is not itself meaningful to receivers as far as pyatv's implementation shows). The RTSP "URI" used for all in-session requests is `rtsp://<local-ip>/<session_id>` where `session_id` is a random 32-bit int chosen at `RtspSession.__init__`. Password-protected devices get HTTP Digest auth (`Authorization: Digest ...`) computed from the `WWW-Authenticate` challenge returned on the first `401` to `ANNOUNCE`. Source: https://github.com/postlund/pyatv/blob/master/pyatv/support/rtsp.py (full file) — request builder at lines 254-330.

### 9.1 Verb-by-verb summary (bodies/headers exactly as pyatv sends and as documented with live capture examples)

- **OPTIONS** — sender asks capabilities; receiver echoes `Public: ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER, POST, GET, PUT`. pyatv does not send `OPTIONS` explicitly in its own client code (`RtspSession` has no `options()` method) — this is documented purely from a passive capture; treat as informational for compatibility, not something pyatv itself relies on. Source: https://github.com/postlund/pyatv/blob/master/docs/documentation/protocols.md lines 1249-1271.
- **ANNOUNCE** (AirPlay 1 only) — `Content-Type: application/sdp`, body is a fixed SDP template:
  ```
  v=0
  o=iTunes {session_id} 0 IN IP4 {local_ip}
  s=iTunes
  c=IN IP4 {remote_ip}
  t=0 0
  m=audio 0 RTP/AVP 96
  a=rtpmap:96 L16/44100/2
  a=fmtp:96 352 0 {bits_per_channel} 40 10 14 {channels} 255 0 0 {sample_rate}
  ```
  i.e. pyatv **always announces raw `L16` PCM**, never ALAC, even though the wild-capture example in pyatv's own docs shows a real Apple sender announcing `a=rtpmap:96 AppleLossless` with `a=fmtp:96 352 0 16 40 10 14 2 255 0 0 44100` (ALAC `fmtp` field order: frames-per-packet, ALAC version=0, sample size, history mult, initial history, rice limit, channel count, max run, max coded frame size (0=auto), average bitrate (0=auto), sample rate). This is a deliberate simplification in pyatv — see §9.4. Source: https://github.com/postlund/pyatv/blob/master/pyatv/support/rtsp.py lines 21-49 and https://github.com/postlund/pyatv/blob/master/docs/documentation/protocols.md lines 1273-1312.
- **SETUP** (AirPlay 1) — `Transport: RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port=<local udp port>;timing_port=<local udp port>`. Response `Transport` header echoes back `server_port`, `control_port`, `timing_port` (receiver-chosen UDP ports) and a `Session` id header pyatv must send back on every subsequent verb. `Audio-Jack-Status: connected` may also appear (informational). Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/protocols/airplayv1.py lines 47-79 and docs lines 1314-1345.
- **SETUP** (AirPlay 2, base) — binary-plist body (not SDP), see §7 step 2. A **second** `SETUP` (audio-stream-specific) follows with body:
  ```json
  {"streams":[{
    "audioFormat": 2048,          // 0x800 = PCM/44100/16-bit/2ch, see §9.4
    "audioMode": "default",
    "controlPort": <local udp port>,
    "ct": 1,                      // 1 = "Raw PCM" per pyatv's own comment
    "isMedia": true,
    "latencyMax": 88200,
    "latencyMin": 11025,
    "shk": <32-byte shared secret>,
    "spf": 352,                   // Samples Per Frame == FRAMES_PER_PACKET
    "sr": 44100,
    "type": 96,                   // 0x60
    "supportsDynamicStreamID": false,
    "streamConnectionID": <rtsp session_id, i64>
  }]}
  ```
  Response: `{"streams":[{"controlPort": <u16>, "dataPort": <u16>, ...}]}`. Note pyatv's own comment admits `shk` (shared key) *should* be derived from the Pair-Verify shared secret but pyatv instead derives it from the *event-channel* HKDF output truncated to 32 bytes as a pragmatic substitute, since "it doesn't really matter what the key is ... it's merely a security feature" — this is a known deliberate simplification, flag it if bit-exact behavior vs. real Apple senders matters. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/protocols/airplayv2.py lines 112-156.
- **SETPEERS** — PTP peer list, `Content-Type: /peer-list-changed`, body is a plist array of IPv4/IPv6 address strings. Documented only (pyatv does not implement PTP timing at all — always uses NTP-style timing, see §9.2). Source: docs lines 1347-1359.
- **RECORD** — starts playback; `RTP-Info: seq=<u16>;rtptime=<u32>` header carries the first packet's sequence number and RTP timestamp (both randomized per pyatv's `StreamContext.reset()`). Response may carry `Audio-Latency: <samples>`. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/stream_client.py lines 438-448 and docs lines 1361-1387.
- **FLUSH** — `Range: npt=0-`, `Session`, `RTP-Info` headers; pauses/flushes buffer without tearing the session down. pyatv sends this immediately after `RECORD`, before streaming actual audio, apparently to reset receiver buffer state. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/stream_client.py lines 440-448.
- **TEARDOWN** — `Session` header only; ends the session, called from a `finally` block after streaming completes or errors.
- **SET_PARAMETER** — generic mechanism for `volume`, `progress`, metadata (`application/x-dmap-tagged` DMAP-encoded `mlit` container with `minm`/`asal`/`asar` string tags for title/album/artist), and artwork (`image/jpeg` raw bytes). `Content-Type: text/parameters` with body `<key>: <value>` for volume/progress. Session/RTP-Info headers accompany metadata and artwork calls. Source: https://github.com/postlund/pyatv/blob/master/pyatv/support/rtsp.py lines 194-244 and https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/stream_client.py lines 400-428.

### 9.2 Timing — pyatv uses NTP-style timestamps exclusively (no PTP implementation)

64-bit NTP-format time: seconds since 1900-01-01 in the high 32 bits (`+0x83AA7E80` offset from Unix epoch), fractional seconds in the low 32 bits. Exact conversion code:
```python
def ntp_now() -> int:
    now_us = time_ns() / 1000
    seconds = int(now_us / 1000000)
    frac = int(now_us - seconds * 1000000)
    return (seconds + 0x83AA7E80) << 32 | (int((frac << 32) / 1000000))
```
Plus helpers `ntp2parts` (split into `(sec, frac)` u32 pair), `ntp2ts`/`ts2ntp` (convert between NTP time and RTP-clock "timestamp" units at a given sample rate — right-shift/left-shift by 16 bits around the multiply/divide to preserve precision), `ntp2ms`/`ts2ms`. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/timing.py (full file, 41 lines).

Two dedicated UDP sockets are opened locally per session (ports configurable via `Settings.protocols.raop.control_port`/`timing_port`, default `0` = OS-assigned ephemeral):
- **Timing server** (`TimingServer`): receives a `TimingPacket` request from the receiver and replies with `proto` echoed, type `0x53|0x80 = 0xD3`, seq `7`, its own send/receive NTP timestamps filled in (`req.sendtime_*` echoed back as-is, `recvtime`/`sendtime` in the reply both set to "now"). This is a trivial two-way NTP-like exchange, no external time source involved — it's peer-to-peer wall-clock sync between sender and receiver.
- **Control client** (`ControlClient`): sends a periodic **sync packet** once per second (`asyncio.sleep(1.0)`) to the receiver's advertised `control_port`, and separately listens for **retransmit requests** (packet type `0x55` after masking off the marker bit `0x7F`) and answers by resending buffered audio packets from a 1000-entry `PacketFifo` backlog (oldest-evicted).

Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/stream_client.py lines 64-183 and https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/protocols/__init__.py lines 102-146 (`TimingServer`).

### 9.3 Packet formats (exact field layout, all big-endian per RTP convention; `defpacket` uses Python `struct` format chars where `B`=u8, `H`=u16, `I`=u32)

```
RtpHeader          = { proto: u8, type: u8, seqno: u16 }                                   # 4 bytes, base

TimingPacket        = RtpHeader + { padding: u32, reftime_sec: u32, reftime_frac: u32,
                                     recvtime_sec: u32, recvtime_frac: u32,
                                     sendtime_sec: u32, sendtime_frac: u32 }                 # 32 bytes total

SyncPacket          = RtpHeader + { now_without_latency: u32, last_sync_sec: u32,
                                     last_sync_frac: u32, now: u32 }                         # 20 bytes total
    # sent with proto=0x90 (first packet) or 0x80, type=0xD4, seqno=0x0007 fixed

AudioPacketHeader   = RtpHeader + { timestamp: u32, ssrc: u32 }                              # 12 bytes; audio payload appended by caller
    # sent with proto=0x80, type=0xE0 (first packet of a session) or 0x60 thereafter,
    # ssrc field is populated with the RTSP session_id (reused, not a true random SSRC)

RetransmitRequest   = RtpHeader + { lost_seqno: u16, lost_packets: u16 }                     # 8 bytes
```
Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/packets.py (full file).

`StreamContext` derived values: `frame_size = channels * bytes_per_channel`; `packet_size = FRAMES_PER_PACKET(352) * frame_size`; `latency = 22050 + sample_rate` (i.e. ~1.5s of look-ahead at 44.1kHz, a fixed constant not derived from receiver capabilities); `rtptime = head_ts - (start_ts - latency)` (i.e. RTP timestamp sent on the wire is offset ahead of the raw sample position by the latency amount, matching how `RECORD`'s first packet is expected to be "in the future" relative to `FLUSH`). Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/protocols/__init__.py lines 17-73.

Retransmit response framing (`ControlClient._retransmit_lost_packets`): reply is `0x80 0xD6 <original 2-byte seqno from the cached packet> <full cached packet bytes>` sent back to the sender address that requested it. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/stream_client.py lines 155-170.

### 9.4 Codec: pyatv only ever sends raw PCM, never ALAC, AAC, or OPUS

Despite the `cn` TXT key advertising ALAC/AAC/AAC-ELD/OPUS support on many receivers, and despite AirPlay 1's `ANNOUNCE` SDP historically carrying `AppleLossless`, pyatv's implementation:
- Always announces `L16/44100/2` (16-bit linear PCM, per-channel bit depth substituted from `bytes_per_channel*8`) in the AirPlay-1 `ANNOUNCE` SDP body. Source: https://github.com/postlund/pyatv/blob/master/pyatv/support/rtsp.py lines 25-35.
- Always sets AirPlay-2 stream SETUP `"ct": 1` (raw PCM per pyatv's inline comment) and `"audioFormat": 0x800`. Cross-referenced against the emanuelecozzi.net audio-codec bitmask documentation, `0x800` (bit 11) corresponds exactly to "PCM/44100/16/2" in the AirPlay 2 `audioFormat` bitmask scheme — confirming pyatv's constant is a correct, intentional PCM selection, not a placeholder. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/protocols/airplayv2.py line 134, cross-checked at https://emanuelecozzi.net/docs/airplay2/audio/.
- The audio-source layer (`pyatv/protocols/raop/audio_source.py`) uses the third-party `miniaudio` Python binding purely to **decode** arbitrary input files/streams (MP3, FLAC, etc.) down to raw interleaved PCM samples for framing — there is no ALAC/AAC/OPUS *encoder* anywhere in pyatv. A `_to_audio_samples()` helper explicitly notes "frames are returned in little endian" internally but conditionally byte-swaps to big-endian before sending, matching the RTP `L16` big-endian sample convention. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/audio_source.py lines 1-61.

Implication for a Rust reimplementation: matching pyatv's actual behavior only requires a PCM path (decode arbitrary input → interleaved 16-bit big-endian PCM framed at 352 samples/packet); ALAC/AAC/OPUS encoding is out of scope unless the reimplementation explicitly wants to exceed pyatv's feature set.

### 9.5 Audio packet encryption (AirPlay 2 only)

AAD for AEAD is the RTP header's `timestamp`+`ssrc` fields (bytes 4-12 of the 12-byte `AudioPacketHeader`, i.e. `rtp_header[4:12]`, 8 bytes) — matches the emanuelecozzi.net spec's stated "Timestamp and SSRC are used together as AAD ... 8 bytes" (https://emanuelecozzi.net/docs/airplay2/rtp). Nonce is the **8-byte-counter variant** of the Chacha20 cipher (`Chacha20Cipher8byteNonce`, 4 zero bytes + 8-byte little-endian counter, distinct from the 12-byte counter used for HAP channel framing in §6), keyed with the `shk` shared secret from stream SETUP as **both** the output and input key (self-symmetric, since audio only flows one direction). The wire packet is `rtp_header(12 bytes) || ciphertext || last-8-bytes-of-nonce` — i.e. the trailing 8 raw nonce bytes are appended after the Poly1305-tagged ciphertext (the ciphertext itself already includes the 16-byte auth tag from AEAD), matching the emanuelecozzi.net-documented 24-byte trailer (8-byte nonce + 16-byte tag). Critically, pyatv reads `self._cipher.out_nonce` for the wire trailer *before* calling `encrypt()`, and deliberately does **not** pass that nonce explicitly into `encrypt()` — this makes `encrypt()` use its own internal auto-incrementing counter (consistent with the value just read) rather than a manually threaded nonce, which the pyatv source comments explicitly flag as intentional ("We did that in the past and Apple doesn't seem to care, but other vendors might"). Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/protocols/airplayv2.py lines 183-208 and https://github.com/postlund/pyatv/blob/master/pyatv/support/chacha20.py lines 79-107.

AirPlay 1 audio packets are sent entirely unencrypted (no cipher applied in `AirPlayV1.send_audio_packet`). Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/protocols/airplayv1.py lines 111-117.

### 9.6 Streaming loop pacing

pyatv's send loop (`StreamClient._stream_data`) computes `expected_frame_count` from wall-clock elapsed time vs `sample_rate`, and sleeps the remaining time until the next packet is due; if it falls behind by ≥1 packet's worth of frames it sends up to `MAX_PACKETS_COMPENSATE = 3` extra packets back-to-back to catch up, and logs an escalating warning after `SLOW_WARNING_THRESHOLD = 5` consecutive late packets. After the source is exhausted, it keeps sending zero-filled "padding" packets until `padding_sent >= latency` (i.e. it pads out exactly the fixed latency window before naturally stopping) so the sync-packet clock stays consistent through the tail of playback. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/stream_client.py lines 476-619.

### 9.7 Buffered vs realtime AirPlay 2 audio (bit 40, `SupportsBufferedAudio`)

pyatv's own implementation **does not distinguish buffered vs realtime streaming modes** — it always uses the same immediate RTP push model described above (§9.6) regardless of whether the receiver advertises `SupportsBufferedAudio` (bit 40). This is corroborated by the reference receiver implementation (`airplay2-receiver`) which explicitly lists "Receiving of both REALTIME and BUFFERED Airplay2 audio streams" as a feature it implements independently (https://github.com/openairplay/airplay2-receiver README), implying the mode is a receiver-side distinction primarily signaled through the `type` field in stream SETUP (pyatv hardcodes `"type": 96` / `0x60`) rather than something the sender actively negotiates beyond that constant. Buffered-mode specifics (larger receiver-side jitter buffer, different retransmission/backpressure semantics) are **not implemented or documented by pyatv** — flag as an open question (§13) for a Rust implementation that wants full AirPlay-2 fidelity.

---

## 10. Volume control

pyatv represents volume internally as a percentage (0-100) but AirPlay's wire protocol uses **dBFS** (`-144.0` = muted, `-30.0..0.0` = the linear percentage range, linearly mapped): `pct_to_dbfs()`/`dbfs_to_pct()` do a linear remap between `[0,100]` and `[-30.0,0.0]`, with `0.0%` special-cased to the true-mute sentinel `-144.0` dBFS rather than `-30.0`. `SET_PARAMETER volume: <dbfs float as string>` is the wire call. `INITIAL_VOLUME = 33.0` percent is pyatv's fallback default before any real device value is known; on stream start pyatv also tries to read `initialVolume` from the `/info` binary plist response to seed state, falling back to setting it explicitly if that key is absent. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/utils.py lines 281-302 and https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/__init__.py lines 67, 380-399.

---

## 11. DMAP / DAAP / Home Sharing

### 11.1 Transport and framing

Plain HTTP/1.1 on the SRV-advertised port (commonly 3689 historically, but again always SRV-derived, never hardcoded by pyatv). Requests are GET/POST with special query-string parameters; responses are DMAP binary TLV **except** for a few endpoints returning raw bytes (artwork = PNG) or, for POST bodies pyatv sends, `application/x-www-form-urlencoded`. Source: https://github.com/postlund/pyatv/blob/master/docs/documentation/protocols.md lines 20-32 and https://github.com/postlund/pyatv/blob/master/pyatv/protocols/dmap/daap.py.

### 11.2 DMAP binary tag format

```
| Key (4 bytes ASCII) | Length (4 bytes big-endian u32) | Data (Length bytes) |
```
Nested via "container" tags (their `Data` is itself a sequence of child TLVs) — which tags are containers is a static lookup table (`tag_definitions.py`), not self-describing on the wire; you must already know a tag's type to parse it. Multiple entries with the same key are legal (act like array elements) and are how lists are represented, e.g. multiple `mlit` items inside an `mlcl` container. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/dmap/parser.py (full file, `_parse`/`parse`/`first`/`pprint`) and https://github.com/postlund/pyatv/blob/master/docs/documentation/protocols.md lines 34-119 (worked byte-by-byte decode example).

Tag value type encodings (`tags.py`): `uint8/16/32/64` (fixed-width big-endian), `bool` (1 byte, `0x01`/`0x00`), `string` (raw UTF-8, length = byte length not char count), `bytes` (rendered as `"0x" + hex`), `bplist` (binary property list decoded with `plistlib`), `container` (recursive TLV list), plus an `ignore`/`unknown` fallback that logs and discards for unrecognized tags. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/dmap/tags.py.

Full known-tag table (~90 entries, e.g. `cmst`=container "dmcp.playstatus", `caps`=uint "dacp.playstatus", `cann`=string "daap.nowplayingtrack", `cmpg`=uint64 "dacp.pairingguid") is enumerated at https://github.com/postlund/pyatv/blob/master/pyatv/protocols/dmap/tag_definitions.py lines 24-124 — reproduce this table verbatim in the Rust implementation since it is effectively a fixed protocol dictionary, not something to be inferred.

### 11.3 Required HTTP headers

```
Accept: */*
Accept-Encoding: gzip
Client-DAAP-Version: 3.13
Client-ATV-Sharing-Version: 1.2
Client-iTunes-Sharing-Version: 3.15
User-Agent: Remote/1021
Viewer-Only-Client: 1
```
plus `Content-Type: application/x-www-form-urlencoded` for POSTs. These were captured from the real "Remote" iOS app via Wireshark per pyatv's own docs and are required verbatim for some devices to respond correctly. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/dmap/daap.py lines 17-25 and https://github.com/postlund/pyatv/blob/master/docs/documentation/protocols.md lines 120-140.

### 11.4 Authentication / login and the two credential formats

Login endpoint: `GET login?<auth>&hasFP=1` where `<auth>` is exactly one of:
- `pairing-guid=0xXXXXXXXXXXXXXXXX` (16 hex digits after `0x`) — obtained via the DMAP pairing flow (§11.6).
- `hsgid=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` (UUID form) — Home Sharing GUID, read straight from the `hG`/`hg` mDNS TXT key when Home Sharing is already enabled on the target device, no interactive pairing needed.

pyatv distinguishes the two purely by regex match on the credential string (`^0x[0-9A-Fa-f]{16}$` vs the UUID pattern) — there's no separate stored "type" field. Response is `mlog { mstt: 200, mlid: <session id> }`; `mlid` is echoed as `session-id=<id>` on every subsequent authenticated request. `_do()` auto-retries once with a fresh login if a request fails outside the login call itself (handles session expiry transparently). Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/dmap/daap.py lines 75-176 and https://github.com/postlund/pyatv/blob/master/docs/documentation/protocols.md lines 150-225.

### 11.5 Push updates via long polling

`GET ctrl-int/1/playstatusupdate?session-id=<id>&revision-number=<rev>`. Passing `revision-number=0` returns immediately with current state; passing the `cmsr` (`dmcp.serverrevision`) value from the previous response makes the server **hold the connection open** until state actually changes, then respond with the new state and an incremented `cmsr`. pyatv's `DmapPushUpdater._poller()` loop simply always requests with `use_revision=True` (and `timeout=0`, meaning "no client-side timeout — block indefinitely") after the first call, re-requesting immediately on each response — a textbook long-poll loop, no WebSocket/SSE equivalent exists in DMAP. Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/dmap/__init__.py lines 448-524 and https://github.com/postlund/pyatv/blob/master/docs/documentation/protocols.md lines 227-266.

### 11.6 DMAP pairing flow (device-initiated PIN entry, when Home Sharing is unavailable)

pyatv acts as the *server* here (reversing the usual client role): it starts a small `aiohttp` web server on an ephemeral port exposing `GET /pair`, and publishes an mDNS `_touch-remote._tcp.local.` service so the real Apple TV/iTunes device can discover it and prompt the user to enter a PIN shown by pyatv. It also generates a random 64-bit "pairing GUID" up front (`hex(random.getrandbits(64))`, uppercased, `0x`-prefix stripped and re-added at persistence time). When the device calls back `GET /pair?servicename=<name>&pairingcode=<hex>`, pyatv verifies the code by MD5-hashing `pairing_guid + "P0I1N2\x00..."`-style interleaved PIN digits with null-byte separators (`for char in str(pin).zfill(4): merged.write(char); merged.write("\x00")`), and compares (case-insensitively) against the received hex digest. On success it responds with a DMAP `cmpa` container holding `cmpg` (uint64 pairing guid), `cmnm` (string, pyatv's own display name), `cmty` (string, hardcoded `"iPhone"` device-type spoof). Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/dmap/pairing.py (full file).

### 11.7 Command surface actually implemented by pyatv

- `server-info` (GET, no auth) — capability/version probe.
- `login` (GET) — see §11.4.
- `ctrl-int/1/playstatusupdate` (GET) — see §11.5.
- `ctrl-int/1/nowplayingartwork?mw=<w>&mh=<h>&[AUTH]` (GET) — returns PNG bytes or empty; requested size is a hint the device may ignore.
- `ctrl-int/1/<cmd>?[AUTH]&prompt-id=0` (POST) — `<cmd>` ∈ `{play, pause, playpause, stop, nextitem, previtem, volumeup, volumedown}`.
- `ctrl-int/1/controlpromptentry?[AUTH]&prompt-id=0` (POST) — body is raw DMAP tags `cmbe`(string)+`cmcc`(uint8=0), used for `select`/`menu`/`topmenu` and also for synthesizing swipe-gesture D-pad navigation (`up`/`down`/`left`/`right` are implemented as a **sequence of 7 fake touch-move DMAP commands** simulating a drag gesture across a virtual trackpad, not discrete key presses — see the `_move()` helper coordinates in source).
- `ctrl-int/1/setproperty?<key>=<value>&[AUTH]&prompt-id=0` (POST) — `dacp.playingtime` (ms), `dacp.shufflestate` (bool 0/1), `dacp.repeatstate` (uint 0=Off/1=Track/2=All).

Source: https://github.com/postlund/pyatv/blob/master/pyatv/protocols/dmap/__init__.py lines 228-393 and https://github.com/postlund/pyatv/blob/master/docs/documentation/protocols.md lines 268-327.

---

## 12. Recommended Rust crate stack (versions verified live on crates.io, 2026-08-24)

| Purpose | Crate | Latest stable (as checked) | Notes |
|---|---|---|---|
| SRP-6a (Pair-Setup, RFC 5054-based 3072-bit group for HAP, 2048-bit for legacy AirPlay-1 auth) | `srp` | 0.6.0 | RustCrypto/PAKEs, generic over `Digest` (use `sha2::Sha512`), built on `crypto-bigint`; **explicitly unaudited** — flag as a security risk to accept knowingly (§13) |
| SHA-2 family | `sha2` | 0.11.0 | needed for SHA-512 (HAP/legacy) |
| HKDF | `hkdf` | 0.13.0 | HKDF-SHA512 per §5.5/5.6/6 |
| Ed25519 signing (HAP long-term identity, Pair-Setup signatures) | `ed25519-dalek` | 3.0.0 | |
| X25519 ECDH (Pair-Verify) | `x25519-dalek` | 3.0.0 | |
| Curve25519 primitives (dependency of the above; also used raw for the AirPlay-1 `/auth-setup` dummy MFiSAP handshake) | `curve25519-dalek` | 5.0.0 | |
| ChaCha20-Poly1305 AEAD (HAP channel framing §6, audio packet encryption §9.5, Pair-Setup/Verify TLV8 encryption) | `chacha20poly1305` | 0.11.0 | standard nonce API is sufficient — pyatv's `_reuseable` Python dependency was a Python-specific performance shim, not a different algorithm |
| AES (legacy AirPlay-1 auth, `CTR`/`GCM` modes) | `aes-gcm` (+ a `ctr`-mode AES crate, e.g. `ctr` from RustCrypto) | 0.11.1 | only needed if implementing the legacy (`Legacy`/pre-HAP) auth path, §5.8 |
| Binary property list encode/decode | `plist` | 1.10.0 | supports Serde; needed pervasively (AirPlay 2 SETUP/`/play`/`/info` bodies are all bplist) |
| RTSP/HTTP wire types | *hand-roll* | — | pyatv hand-rolls its own parser (`support/http.py`/`support/rtsp.py`) because the wire format is non-conformant HTTP/RTSP (custom `CSeq`/`DACP-ID` headers layered on RTSP verbs inside HTTP/1.1-shaped framing, interleaved plaintext/binary bodies); the `rtsp-types` crate (0.1.3, RFC 7826-conformant) and generic `httparse` (1.10.1) are candidates for low-level tokenizing but neither will handle the RTSP-verbs-inside-HTTP-shaped-messages quirk out of the box — budget for a custom parser matching pyatv's `_parse_http_message`/`parse_request`/`parse_response` semantics |
| Async runtime | `tokio` | 1.53.1 | matches pyatv's `asyncio` usage pattern (one task per TCP/UDP socket, `create_datagram_endpoint` ≈ `tokio::net::UdpSocket`) |
| UUID generation (session/stream identifiers) | `uuid` | 1.25.0 | |
| Hex encode/decode (credential serialization, TLV8 debug logging) | `hex` | 0.4.3 | |
| Random number generation | `rand` | 0.10.2 | |
| Reference for HAP client-role logic (Pair-Setup/Pair-Verify state machines, TLV8) | `hap-tlv8` (1.0.0) and `hap-controller` (3.1.0, actively updated as of 2026-08-07) | — | `hap-controller` (https://github.com/phunapps/hap-rust) is a full HomeKit-controller-role crate implementing the same SRP/TLV8/Pair-Verify state machine AirPlay 2 reuses; worth evaluating as a dependency or at minimum a design reference even though it targets HomeKit accessories rather than AirPlay's variant framing |
| ALAC (only needed if the Rust implementation chooses to exceed pyatv's PCM-only scope) | `alac` (0.5.0, decoder only, last updated 2018) / `symphonia` (0.6.1, decode-only, has an ALAC codec reader) | — | **no maintained ALAC encoder crate was found on crates.io** as of this research; since pyatv itself never encodes ALAC (§9.4), this is not a blocker for parity but is an open question for anyone wanting to exceed pyatv's feature set |

All version numbers above were fetched live from `https://crates.io/api/v1/crates/<name>` on 2026-08-24; do not treat any version number in this report as durable — re-verify against crates.io at implementation time, since these numbers will drift.

---

## 13. Open questions

- The AirPlay 2 buffered-vs-realtime streaming distinction (bit 40, `SupportsBufferedAudio`) is not implemented anywhere in pyatv and only thinly documented by the unofficial spec and the `airplay2-receiver` project; the exact SETUP-time negotiation and on-wire differences (jitter buffer size hints, different retransmission semantics) need to be reverse-engineered from a real device capture or from the `airplay2-receiver` source directly (https://github.com/openairplay/airplay2-receiver) if the Rust implementation needs to support buffered mode.
- The exact meaning of most AirPlay status-flag bits (`sf`/`flags`, beyond `0x8`/`0x80`/`0x200`) is unknown to pyatv itself and to the cited unofficial specs; the emanuelecozzi.net `status_flags` sub-page returned HTTP 404 at the URL pattern tried during this research (only the parent index and scattered examples like `flags=0x244`/`statusFlags: 580` were recoverable) — a fresh crawl of https://emanuelecozzi.net/docs/airplay2/ or a device-capture-driven approach is needed for full status-flag coverage.
- MFi Authentication (`et=4`/bit 26 `Authentication_8`) is explicitly out of scope for both pyatv (does a no-op dummy Curve25519 handshake, never real MFi crypto, borrowed from owntone-server) and the `airplay2-receiver` reference project ("may never implement: MFi Authentication, requires MFi hardware module") — full MFi support requires an Apple MFi hardware security module and is likely out of scope for any open-source Rust reimplementation too; confirm this is an accepted scope boundary before starting.
- FairPlay authentication/DRM (`et=3`/`et=5`, bit 14 `Authentication_4`) is entirely unimplemented by pyatv; `airplay2-receiver` claims a from-scratch FairPlay v3 implementation exists in their project (credited to a named contributor) which could serve as a reference if FairPlay-protected-source playback (e.g. from Apple Music via AirPlay) is ever required, but this is a substantial additional research task on its own.
- pyatv's `shk` (stream shared key) derivation for AirPlay-2 audio-stream SETUP is a known simplification (derived from the event-channel HKDF output rather than a value cryptographically tied to the Pair-Verify shared secret per spec intent) — confirm whether a from-scratch Rust implementation should replicate this simplification for pyatv-compatibility, or implement the "more correct" derivation and verify it still interoperates with real hardware (pyatv's own comment suggests real receivers don't validate this value strictly, but that should be confirmed empirically, not assumed).
- The `srp` crate (RustCrypto/PAKEs) used for the recommended Rust stack is explicitly marked "has never received an independent third party audit" by its own README (https://github.com/RustCrypto/PAKEs) — decide whether that risk is acceptable for a security-sensitive pairing implementation, or whether a hand-rolled/audited alternative is warranted.
- No maintained ALAC encoder crate exists on crates.io as of this research (§12); if audio quality/bandwidth parity with real Apple senders (which prefer ALAC over raw PCM `cn=1`) is ever a goal beyond matching pyatv's own PCM-only behavior, ALAC encoding will require either porting Apple's reference ALAC encoder algorithm or shelling out to a C library via FFI (e.g. `libalac`), both non-trivial undertakings.
- The Companion-protocol pairing sequence documented at length in pyatv's docs (§5.5's cross-reference) is technically for a *different* protocol (Companion Link, service `_companion-link._tcp.local.`) that shares HAP/TLV8 primitives with AirPlay 2's Pair-Setup/Pair-Verify but uses a distinct OPACK/frame-header transport rather than raw HTTP `POST` bodies — confirm this report's inference (that the TLV8 *content* semantics transfer directly to AirPlay's HTTP-framed Pair-Setup/Verify while the outer transport differs) against a live AirPlay-2 pairing capture, since it was derived by cross-referencing two different pyatv subsystems rather than observed directly in a single AirPlay capture.
- This report did not independently verify wire-format details against a live Apple TV, HomePod, or AirPort Express — every claim traces to pyatv source code, pyatv's own documentation (which itself states several sections are "TBD" or incomplete, e.g. AirPlay 2 Service Discovery at https://github.com/postlund/pyatv/blob/master/docs/documentation/protocols.md line 1535), or third-party reverse-engineering docs that self-describe as incomplete/unverified; treat this report as a strong starting point for implementation, not as a substitute for testing against real hardware during development.
