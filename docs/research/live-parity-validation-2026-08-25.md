# Live parity validation on tvOS 27

- Date: 2026-08-25
- Rust commit: `572c9b405843`
- Reference: pyatv `0.18.0`, official container image `ghcr.io/postlund/pyatv:0.18.0`
- Device: Apple TV 4K (3rd generation, `AppleTV14,1`), tvOS 27.0, build `24J5315i`

This report records the first human-observed parity pass across the completed workspace. It supplements the earlier wire-format research. It does not replace those point-in-time specifications.

No credential value, account identifier, device address, or media payload is included in this report.

## Scope and method

The pass used one Apple TV and the repository's live probe examples and `atvremote` CLI. A person observed every action that affected the screen, audio, volume, or power state.

The following controls kept comparisons narrow:

- The AirPlay URL test used the same MP4 file from a public HTTPS origin and a local HTTP server with byte-range support.
- The RAOP tests used the same six-second, 44.1 kHz, 16-bit mono WAV at low amplitude.
- The upstream RAOP control used pyatv `0.18.0`, host networking, the same WAV, and the same HomeKit Accessory Protocol (HAP) controller credential.
- Temporary media and the upstream container image were removed after the probes.

## Results

The following table separates implementation coverage from tvOS interoperability.

| Area | Result | Evidence |
| --- | --- | --- |
| Discovery | Pass | Multicast discovery found the device while it was on and off. |
| Companion pairing | Pass | Pairing displayed a PIN, persisted credentials, and passed pair-verify. |
| Credential revocation | Pass | After device-side removal, M2 verified the device identity and M4 returned `Authentication` for the removed controller. Re-pairing then succeeded. |
| Companion state | Pass | Device information, power, app, account, output-device, and keyboard-focus queries returned live values. |
| Companion control | Pass | Home, app launch, touch swipe, touch click, text replacement, text append, text clear, power off, and power on were observed on the device. |
| MRP tunnel | Pass | Metadata, play, pause, relative seek, and absolute seek worked through the AirPlay data-stream tunnel. |
| Tunnel lifetime | Pass within the observation window | The tunnel stayed open for 60 seconds with two-second `POST /feedback` requests. It also showed no closure during a 45-second idle observation without feedback. |
| `skipRecord` | Pass | tvOS returned `skipRecord=true`; the Rust client omitted `RECORD` and completed the MRP tunnel. The same key appeared during the AirPlay 2 `play_url` setup. |
| Volume | Pass when available | Volume was unavailable during an idle session. During active grouped playback, MRP reported absolute volume control and changed the level from 10% to 15%. |
| AirPlay 2 `play_url` | Shared tvOS compatibility failure | tvOS accepted `POST /play` with `200 OK`, then returned `500 Internal Server Error` to the first `GET /playback-info`. The device never fetched the public or local media URL. Upstream reports the same failure on tvOS 26.2 in [pyatv issue 2821](https://github.com/postlund/pyatv/issues/2821). |
| AirPlay 1 `play_url` | Fail on this device | Pair-verify timed out before `POST /play`. This result does not establish behavior on an AirPlay 1 device. |
| AirPlay 2 RAOP | Shared tvOS compatibility failure | The Rust client and pyatv `0.18.0` both completed authentication and the event-channel setup, then timed out waiting for the audio-stream `SETUP` response. Neither implementation reached RTP audio. |
| AirPlay 1 RAOP | Rejected on this device | When forced onto the actual V1 branch, tvOS closed the connection at `ANNOUNCE`. This result does not establish behavior on an AirPlay 1 receiver. |
| Companion `_sessionStop` | Known cleanup failure | tvOS returned `Session not found` on every observed disconnect. The client ignored the error, matching pyatv behavior. |

## Parity conclusion

For the capabilities that this device can exercise, pyatv-rs has practical feature parity with pyatv. The two media-streaming failures do not show that the Rust port is behind the Python reference:

- The `play_url` failure matches upstream pyatv issue 2821.
- The RAOP failure reproduced at the same request in pyatv `0.18.0`.

The evidence establishes parity with an open implementation, not compatibility with Apple's controller behavior. Resolving either media path requires a capture of a successful Apple sender and a comparison of the tvOS 27 setup sequence.

## Unresolved observations

- A normal reconnect after device-side credential removal rewrote the Rust test storage file without its stale credential fields. Reproduce this behavior with controlled copies of both Rust and pyatv storage before classifying it as a divergence.
- `raop_stream_probe` parses `PROBE_VERSION`, but `RaopPlaybackManager` selects the version again from feature bits. The variable changes the displayed version without forcing the manager branch.
- The 45-second no-feedback observation did not exercise a control request after the idle period. It does not prove that feedback is optional.

## Hardware coverage gaps

This pass could not validate the following device classes and configurations:

- Direct-TCP MRP on a pre-tvOS-15 device.
- DMAP and its multicast pairing responder on an Apple TV generation 1-3.
- Legacy AirPlay authentication on an AirPlay 1 receiver.
- HomePod transient pairing.
- Multi-speaker group changes with more than one output target.
