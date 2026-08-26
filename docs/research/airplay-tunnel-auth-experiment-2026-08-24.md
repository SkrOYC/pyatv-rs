# Authenticating the MRP-over-AirPlay tunnel on tvOS 27: a live experiment

Date: 2026-08-24. Device: Apple TV 4K (3rd gen, `AppleTV14,1`), tvOS 27.0, build `00A0000a`, `AirTunes/980.67.2`, at `10.0.0.5:7000`. mDNS TXT: `features=0x4A7FDFD5,0x3C177FDE`, `flags=0x18644`, no `_mediaremotetv._tcp` advertised.

## Why

`docs/RISKS.md` M7 recorded that AirPlay HAP pair-_setup_ never displays a PIN on this device, which appeared to close off the only path to the HAP credentials that `is_remote_control_supported` (`pyatv/protocols/airplay/utils.py:165-180`) demands before pyatv will even attempt an MRP tunnel to an `AppleTV*` model. Companion pairing, by contrast, works: it does display a PIN and produces HAP credentials, which this workspace already stores. The question this experiment answers is whether those Companion credentials open the _AirPlay_ control connection, and if not, whether transient pairing does.

## Method and safety envelope

Everything below was produced by `crates/pyatv-proto-airplay/examples/airplay_verify_probe.rs`, which is repeatable:

```
PROBE_EXPERIMENTS=hap            cargo run -p pyatv-proto-airplay --example airplay_verify_probe
PROBE_EXPERIMENTS=transient      cargo run -p pyatv-proto-airplay --example airplay_verify_probe
PROBE_EXPERIMENTS=setup-m1       cargo run -p pyatv-proto-airplay --example airplay_verify_probe
PROBE_CONF=/tmp/pyatv-py.conf PROBE_EXPERIMENTS=hap PROBE_SETUP=0 cargo run -p pyatv-proto-airplay --example airplay_verify_probe
```

Request and response heads were captured with `RUST_LOG=pyatv_proto_airplay=trace`, which logs header blocks only — never bodies. Every quoted head below is verbatim from that log with the CRLFs left escaped as the logger writes them.

Constraints observed, because the device owner was away from the TV:

- Only handshakes and reads were sent: `POST /pair-verify`, `POST /pair-setup`, `GET /info`, one `SETUP`. No playback, volume, power, `TEARDOWN` or data-stream `SETUP`.
- **`/pair-pin-start` was never sent**, so nothing could appear on screen even in principle. pyatv posts it before both HAP and transient pair-setup (`auth/hap.py:52`, `auth/hap_transient.py:49`); the probe deliberately diverges, and experiment 2b below establishes that the divergence does not explain experiment 2's result.
- Pair-setup M3 was never sent in experiment 2b, so no PIN was ever guessed and no pairing was created or persisted.
- No key, credential, proof or ciphertext is printed by the probe or reproduced here. TLV values appear as tag name plus length; only the one-byte control tags (`SeqNo`, `Error`, `Method`, `Flags`) are decoded.

## Experiment 1 — Companion HAP credentials on AirPlay `/pair-verify`

Credentials read from `/tmp/pyatv-rs.conf`, `devices[0].protocols.Companion.credentials`, parsed as pyatv's four-field colon hex: `ltpk` 32 B, `ltsk` 32 B, `atv_id` 36 B, `client_id` 36 B, classified `AuthenticationType::Hap`. Driven through the crate's existing `PairVerify` state machine over `HttpConnection`.

**M1 request** (37-byte body, TLV `SeqNo=M1 PublicKey[32B]`):

```
POST /pair-verify HTTP/1.1\r\nContent-Length: 37\r\nUser-Agent: AirPlay/320.20\r\nConnection: keep-alive\r\nX-Apple-HKP: 3\r\nContent-Type: application/octet-stream\r\n\r\n
```

**M2 response** (159-byte body, TLV in wire order `EncryptedData[120B] SeqNo=M2 PublicKey[32B]`):

```
HTTP/1.1 200 OK\r\nDate: Mon, 24 Aug 2026 18:34:58 GMT\r\nContent-Length: 159\r\nContent-Type: application/octet-stream\r\nServer: AirTunes/980.67.2\r\nX-Apple-ProcessingTime: 9\r\nX-Apple-RequestReceivedTimestamp: 26177770\r\n\r\n
```

M2 processing **succeeded in full**, which is the load-bearing result: the X25519 exchange produced a shared secret, the `Pair-Verify-Encrypt` sub-TLV decrypted, the `Identifier` inside it equalled the `atv_id` stored by _Companion_ pairing, and the accessory's Ed25519 signature over `accessoryPK ‖ accessoryID ‖ controllerPK` verified against the `ltpk` stored by _Companion_ pairing. This port checks all three; pyatv checks none of them (`docs/RISKS.md` M6), so a pyatv run could not have distinguished a genuine match from a device that simply answered.

**M3 request** (125-byte body, TLV `SeqNo=M3 EncryptedData[120B]`), same header block as M1 with `Content-Length: 125`.

**M4 response** (3-byte body, TLV `SeqNo=M4`, no `Error` tag):

```
HTTP/1.1 200 OK\r\nDate: Mon, 24 Aug 2026 18:34:58 GMT\r\nContent-Length: 3\r\nContent-Type: application/octet-stream\r\nServer: AirTunes/980.67.2\r\nX-Apple-ProcessingTime: 4\r\nX-Apple-RequestReceivedTimestamp: 26177803\r\n\r\n
```

Transport keys were then derived with `Control-Salt` / `Control-Write-Encryption-Key` / `Control-Read-Encryption-Key` and spliced into the connection as a `HapSession`.

**Proof the channel works.** `GET /info`, the least intrusive request pyatv has (`pyatv/support/rtsp.py:99-108` — a pure read, sent with `allow_error`):

```
GET /info RTSP/1.0\r\nUser-Agent: AirPlay/550.10\r\nCSeq: 0\r\nDACP-ID: 0000000000000001\r\nActive-Remote: 1000000000\r\nClient-Instance: 0000000000000001\r\n\r\n
```

```
RTSP/1.0 200 OK\r\nDate: Mon, 24 Aug 2026 18:34:58 GMT\r\nContent-Length: 1902\r\nContent-Type: application/x-apple-binary-plist\r\nServer: AirTunes/980.67.2\r\nCSeq: 0\r\nX-Apple-ProcessingTime: 1\r\nX-Apple-RequestReceivedTimestamp: 26177815\r\n\r\n
```

Both directions decrypted cleanly through the 1024-byte `HapSession` framing on the first try, which validates the whole `Control-*` salt/info assignment and the ChaCha20 nonce layout against real hardware for the first time. The 1902-byte body decoded as a 27-key `bplist00`: `canRecordScreenStream, deviceID, features, featuresEx, forwardFrameUserData, hasUDPMirroringSupport, initialVolume, keepAliveSendStatsAsBody, macAddress, model, name, osBuildVersion, pi, pk, playbackCapabilities, protocolVersion, psi, receiverHDRCapability, screenDemoMode, senderAddress, sourceVersion, statusFlags, supportedAudioFormatsExtended, supportedFormats, txtAirPlay, volumeControlType, vv`.

Selected values (identifiers and key material deliberately omitted):

| key                        | value                                        |
| -------------------------- | -------------------------------------------- |
| `model`                    | `AppleTV14,1`                                |
| `name`                     | `Living Room`                                |
| `osBuildVersion`           | `00A0000a`                                   |
| `protocolVersion`          | `1.1`                                        |
| `sourceVersion`            | `980.67.2`                                   |
| `features`                 | `4330070159449382869` = `0x3C177FDE4A7FDFD5` |
| `statusFlags`              | `1148484` = `0x118644`                       |
| `keepAliveSendStatsAsBody` | `true`                                       |

Two incidental findings there. `features` matches the mDNS TXT `0x4A7FDFD5,0x3C177FDE` exactly once recombined as `high‖low`, confirming `parse_features`' ordering against a second, independent source. `statusFlags` is `0x118644` where the TXT `flags` is `0x18644` — the `/info` value carries an extra bit `0x100000` that the TXT record does not, so the two are **not** interchangeable inputs to `get_pairing_requirement`.

## Experiment 3 (run as a control even though experiment 1 succeeded) — pyatv's own Companion credentials

Same exchange, `PROBE_CONF=/tmp/pyatv-py.conf`, whose `protocols.companion.credentials` belong to a _different_ controller identity created by upstream pyatv. Byte-identical outcome: `200`/`200`, M2's identifier and signature verified, M4 clean, `GET /info` `200` with the same 27 keys.

So the result is not a property of one credential or of this port's pairing code. **Any HAP controller pairing registered on the device is accepted by the AirPlay endpoint, regardless of which protocol created it.**

## Experiment 2 — transient pairing (`X-Apple-HKP: 4`)

**M1 request** (9-byte body, TLV `Method=0x00 SeqNo=M1 Flags=0x10`, the transient-pairing flag):

```
POST /pair-setup HTTP/1.1\r\nContent-Length: 9\r\nUser-Agent: AirPlay/320.20\r\nConnection: keep-alive\r\nX-Apple-HKP: 4\r\nContent-Type: application/octet-stream\r\n\r\n
```

**Response** — refused outright, with an empty body and therefore no TLV state or error code at all:

```
HTTP/1.1 470 Connection Authorization Required\r\nContent-Length: 0\r\nServer: AirTunes/980.67.2\r\nX-Apple-ProcessingTime: 3\r\nX-Apple-RequestReceivedTimestamp: 26221152\r\n\r\n
```

`470` is the status pyatv maps to `InvalidCredentialsError` in exactly this position (`pyatv/protocols/airplay/__init__.py:277-281`). No keys were derived and no channel test was possible.

## Experiment 2b — the control that makes the `470` interpretable

Because `/pair-pin-start` was withheld, the `470` had two candidate explanations: the device rejects transient pairing, or it rejects any `/pair-setup` that was not preceded by `/pair-pin-start`. One request separates them — HAP pair-setup **M1 only**, `X-Apple-HKP: 3`, also without `/pair-pin-start`, and stopping before M3 so no PIN is guessed and nothing is persisted:

```
-> POST /pair-setup (X-Apple-HKP: 3), 6-byte body, TLV: Method=0x00 SeqNo=M1
<- 200 OK, 409-byte body, TLV: SeqNo=M2 Salt[16B] PublicKey[384B]
```

The device answers a full SRP M2 (16-byte salt, 384-byte 3072-bit group public key) with no `/pair-pin-start` in front of it. **`/pair-pin-start` is not a precondition for `/pair-setup` on this device**, so the `470` in experiment 2 is specific to the `X-Apple-HKP: 4` transient branch. This is consistent with the mDNS `flags=0x18644`: the HomeKit-pairing bit `0x200` is set, which `get_pairing_requirement` reads as `PairingRequirement.Mandatory` — an ephemeral, identity-free session is simply not on offer.

It also independently re-confirms `docs/RISKS.md` M7 from a fresh angle: pair-setup M1 and M2 work perfectly on this device. The pairing flow is not broken; only the PIN display is missing, which is why nobody can ever complete M3.

## Experiment 4 — the event-channel `SETUP`

Sent over the encrypted control connection established in experiment 1, using the complete eleven-key body of `AP2Session._setup_event_channel` (`ap2_session.py:119-135`), with pyatv's default `InfoSettings` and a freshly drawn uppercase UUIDv4 `sessionUUID`.

```
SETUP rtsp://10.0.0.11/3710288703 RTSP/1.0\r\nUser-Agent: AirPlay/550.10\r\nContent-Length: 367\r\nCSeq: 1\r\nDACP-ID: 0000000000000001\r\nActive-Remote: 1000000000\r\nClient-Instance: 0000000000000001\r\nContent-Type: application/x-apple-binary-plist\r\n\r\n
```

```
RTSP/1.0 200 OK\r\nDate: Mon, 24 Aug 2026 18:34:58 GMT\r\nContent-Length: 75\r\nContent-Type: application/x-apple-binary-plist\r\nServer: AirTunes/980.67.2\r\nCSeq: 1\r\nX-Apple-ProcessingTime: 0\r\nX-Apple-RequestReceivedTimestamp: 26177825\r\n\r\n
```

The 75-byte reply plist has exactly two keys:

| key | type | value |
| --- | --- | --- |
| `eventPort` | integer | `49191`, `49192`, `49193`, `49194` on four consecutive runs — allocated fresh per `SETUP`, never reused |
| `skipRecord` | boolean | `true` |

`timingPort` is **absent**, which is coherent with `timingProtocol: "None"` in the request but is worth pinning: a port that assumes the key is present will fail on this device.

`skipRecord: true` is the significant one. **It appears nowhere in pyatv** — not in `ap2_session.py`, not anywhere else in the checkout — yet the receiver is plainly instructing the controller to omit something. The only thing there is to omit at that point in `setup_remote_control()` is the `RECORD` that pyatv sends unconditionally between the event and data `SETUP`s (`ap2_session.py:75-82`). That makes `skipRecord` a live candidate explanation for the tvOS-era tunnel flakiness `docs/RISKS.md` L1/H5 describe: a controller that ignores it sends a `RECORD` the receiver has just said it does not want.

No data-stream `SETUP` was sent, the event port was never dialled, and no MRP message was exchanged, per the brief.

## Conclusion

**The Rust tunnel should authenticate the AirPlay control connection with HAP pair-verify against the credentials from _any_ completed HAP pairing on the device — in practice the Companion one — and must not treat AirPlay pair-setup as a prerequisite.** On this device class (Apple TV 4K, tvOS 27, `flags` bit `0x200` set, `0x8` clear):

1. HAP pair-verify with Companion credentials completes M1–M4 and yields working `Control-*` transport keys. Verified twice, with two independent controller identities.
2. Transient pairing is refused with `470` before any TLV is exchanged, and the refusal is about `X-Apple-HKP: 4`, not about the withheld `/pair-pin-start`.
3. The encrypted control channel then carries `GET /info` and the `isRemoteControlOnly` `SETUP` without incident, so the tunnel's first hop is reachable today.

The practical consequence for the port is that **pyatv's `is_remote_control_supported` heuristic is satisfiable here** — it wants `credentials.type == AuthenticationType::Hap` for an `AppleTV*` model with `osvers >= 13`, and Companion pairing supplies exactly that. What must change relative to a naive reading of pyatv is where the credentials come from: pyatv reaches for `service.credentials` on the _AirPlay_ service (`extract_credentials`, `auth/__init__.py:120-133`), which is empty here because AirPlay pairing cannot be completed. The Rust facade should, when the AirPlay service has no credentials of its own, fall back to the Companion service's HAP credentials before deciding the tunnel is unavailable. That is a deliberate divergence from pyatv and should be written as one, with this document cited.

Do **not** implement transient pairing as a fallback for Apple TV models. It is refused here, and `is_remote_control_supported` would reject its credentials for an `AppleTV*` model even if it were not.

## Open questions, for the next session with the device

Follow-up on 2026-08-25: `docs/research/live-parity-validation-2026-08-25.md` resolves two device-session questions. The Rust client honored `skipRecord=true` and kept the MRP tunnel open for a 60-second observation. After the controller was removed on the Apple TV, the same credential completed M2 device verification and received `Authentication` in M4. Natural credential expiry remains untested.

- **Apple sender handling of `skipRecord`.** The Rust path works when it omits `RECORD`, but an Apple sender capture is still required to confirm Apple's interpretation of the key.
- **Does the event channel actually have to be dialled?** The reply allocates a port per `SETUP`; nothing here shows what happens if the controller never connects to it. `ap2_session.py:137-139`'s comment says the channel is "not used … must be set up though", which is an assertion this experiment did not test.
- **`statusFlags` bit `0x100000`.** Present in `/info`, absent from the mDNS `flags`. Unidentified; decide whether any gating should read it.
- **Credential longevity.** Explicit device-side revocation is verified. Whether tvOS expires a cross-protocol pairing without user action remains unknown.
- **HomePod.** `is_remote_control_supported` allows _only_ transient credentials for `AudioAccessory*`, the exact flavour refused here. This experiment says nothing about that device class; do not generalise the `470`.

## What this experiment added to the crate

- `HttpConnection::send` plus `RequestSpec` (`src/http/request.rs`, split out so the header-order rules keep their own tests), generalising the existing `post` to arbitrary methods, protocols and all three header spellings upstream uses. Unit-tested against each ordering.
- `RtspSession`, previously a `todo!()`: `CSeq`/`DACP-ID`/`Active-Remote`/`Client-Instance` headers, the `rtsp://{local_ip}/{session_id}` URI, `exchange`, `info` and `setup`, plus binary-plist body helpers.
- `ap2::{InfoSettings, remote_control_setup_body, EventChannelSetup, random_uuid}` — pyatv's default controller identity, the eleven-key event-channel `SETUP` body, the reply parser, and the uppercase UUIDv4 generator, all unit-tested.
