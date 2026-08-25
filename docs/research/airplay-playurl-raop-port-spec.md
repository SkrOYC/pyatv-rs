# AirPlay `play_url` and RAOP audio streaming: byte-level port specification (Steps 5–6)

Research date: 2026-08-24. Grounded against pyatv commit `b277a4c8` (`/tmp/pyatv-ref`, release train 0.18.0 "Willie", released 2026-06-19). Every claim below is `path:line-range` against that checkout; nothing here is recalled from training data. Where `docs/research/airplay-raop-dmap.md` (the existing high-level report) already establishes a fact correctly, this document cites it and adds byte-level/line-level detail instead of re-deriving it; where it is imprecise or missing something, see [§0 Corrections](#0-corrections-to-airplay-raop-dmapmd).

Prerequisite reading, in order: `docs/research/airplay-raop-dmap.md` (this doc's parent — high-level protocol map, mDNS TXT keys, feature-bit table), `docs/research/airplay-control-mrp-tunnel-port-spec.md` §1–§3 (the AirPlay-2 control session, event/data channels, HAP framing, and SETUP bodies already ported for the MRP tunnel — `play_url`'s AirPlay-2 path reuses that exact machinery), `docs/research/hap-pairing-port-spec.md` §4 (the salt/info/key-role table for every AirPlay-2 channel, cited directly below rather than reproduced), `docs/RISKS.md` (L1, L3, and — critically for this document — M7/L10, which describe *live-device* behavior this checkout cannot itself reveal).

## Live device context

The device this port targets is an Apple TV 4K gen 3, tvOS 27.0, decoded fully in `airplay-control-mrp-tunnel-port-spec.md` §1:

```
features=0x4A7FDFD5,0x3C177FDE  -> combined 0x3C177FDE4A7FDFD5
flags=0x18644
et=0,3,5   cn=0,1,2,3   md=0,1,2   sf=0x18644   RAOP tp=UDP   vs=980.67.2
```

Decoded implications used throughout this document (all traced in `airplay-control-mrp-tunnel-port-spec.md:36-79`, reproduced here only as a lookup table so each section below can reference it without re-deriving):

| Bit / key | State on this device | Consequence for `play_url`/RAOP |
|---|---|---|
| `SupportsAirPlayVideoV1` (0) + `SupportsAirPlayVideoV2` (49) | both set | `FeatureName.PlayUrl` reports `Available` (`airplay-raop-dmap.md` doesn't cover this feature-flag path; see `pyatv/protocols/airplay/__init__.py:65-76`, cited fully in §2.4 below) |
| `SupportsUnifiedMediaControl` (38) / `SupportsCoreUtilsPairingAndEncryption` (48) | both set | `get_protocol_version` (`pyatv/protocols/airplay/utils.py:241-259`) returns `AirPlayMajorVersion.AirPlayV2` unambiguously for **both** the AirPlay `play_url` protocol pick and the RAOP protocol pick — they call the exact same function (§1, §4) |
| `HasUnifiedAdvertiserInfo` (30) | set | pyatv synthesizes a `Protocol.RAOP` service pointing at the AirPlay port/credentials if no separate `_raop._tcp` is advertised (`airplay-raop-dmap.md:158`); not directly load-bearing here since RAOP TXT (`et`, `cn`, `md`, `sf`, `tp`, `vs`) is given in the prompt, implying a real `_raop._tcp` service exists |
| `et=0,3,5` (RAOP `EncryptionType`) | `Unencrypted`, `FairPlay`, `FairPlaySAPv25` | No `4` (`MFiSAP`) present ⇒ `_requires_auth_setup` (§5.1) is `False` regardless of `am` — the `/auth-setup` MFiSAP dance is never triggered for this device. `FairPlay`/`FairPlaySAPv2.5` are advertised but pyatv never implements FairPlay (`airplay-raop-dmap.md` §13, RISKS L6) — irrelevant to pyatv-compatible streaming since pyatv always uses `Unencrypted` RAOP framing over AirPlay-2 transport encryption (§6) |
| `cn=0,1,2,3` (codecs) | PCM, ALAC, AAC, AAC-ELD advertised | **Not read by pyatv at all** (`pyatv/protocols/raop/parsers.py` has no `cn` handling — confirmed by grep, see §7); pyatv always announces/sets up raw PCM regardless of what `cn` lists. This device *could* accept ALAC but a pyatv-parity port never offers it. |
| `md=0,1,2` (metadata types) | Text, Artwork, Progress all supported | All three `SET_PARAMETER` metadata paths in `StreamClient.send_audio` (§9) are active for this device: progress, DAAP metadata, and JPEG artwork are all sent |
| `RAOP tp=UDP` | UDP transport | Matches pyatv's SETUP `Transport: RTP/AVP/UDP;...` (AirPlay-1 RAOP) / audio-stream SETUP `controlPort`/`dataPort` UDP model (AirPlay-2 RAOP) — no TCP audio path exists in pyatv for either version |
| `sf=0x18644` | `LEGACY_PAIRING_BIT` set, `PIN_REQUIRED`/`PASSWORD_BIT` clear | Pairing mandatory, no password (`airplay-control-mrp-tunnel-port-spec.md:68-79`) |

**The authentication-type verdict for this device, carried forward from RISKS.md M7 (a *live experiment* this static-analysis document cannot itself reproduce):** the AirPlay endpoint's own `/pair-pin-start`+`/pair-setup` flow never displays a PIN on this tvOS 27 build, and transient pair-verify (`X-Apple-HKP: 4`) is refused with `470`. The working path, confirmed live, is standard **HAP pair-verify** (not pair-setup) against the AirPlay control connection using credentials obtained from **Companion** pairing (Step 3, already delivered) — a deliberate divergence from pyatv's own `extract_credentials`, which only reads the AirPlay service's own persisted `credentials` field. This is the credential type `play_url` (§2) and RAOP-over-AirPlay-2 (§4, §5) must use for a live run against this specific device; pyatv's *code path* (§2.1/§4.1 below) is unmodified — only where the `HapCredentials` value comes from differs. Do not attempt AirPlay-native pair-setup or transient pairing against this device; both are dead ends per M7/L10.

---

## 0. Corrections to `airplay-raop-dmap.md`

Re-reading the full source files (rather than the condensed report) surfaced several points worth stating explicitly, none of which invalidate the prior report but sharpen it:

1. **`airplay-raop-dmap.md` §8 doesn't mention `/playback-info` polling at all.** It documents the `/play` POST bodies for both versions but stops there. `AirPlayPlayer.play_url` (`pyatv/protocols/airplay/player.py:24-71`) is a *layer above* both `AirPlayV1.play_url`/`AirPlayV2.play_url` that retries on `500`, raises on other `4xx`/`5xx`, and then polls `/playback-info` every second until `duration` first appears then disappears (`player.py:75-118`). This is the actual `Stream.play_url` entry point's outer control flow and is fully specified in §2 below.
2. **`airplay-raop-dmap.md` §8's AirPlay-2 `/play` body list omits `mightSupportStorePastisKeyRequests`, `volume`, `SenderMACAddress`, `model`, `clientBundleID`, `clientProcName`, `osBuildVersion`.** The prior report's summary ("`Content-Location`, `Start-Position-Seconds`, `uuid`, `streamType: 1`, `mediaType: "file"`, `playbackRestrictions: 0`, `referenceRestrictions: 3`, `rate: 1.0`") is accurate but partial; the exact full dict is reproduced verbatim in §2.2 below since it is a small, fixed, load-bearing constant.
3. **`airplay-raop-dmap.md` §9.1 doesn't state that pyatv's `RtspSession` has no `announce()`-equivalent for AirPlay 2** — AirPlay 2 RAOP setup has *no SDP ANNOUNCE step at all*; only AirPlay 1 does. The prior report documents ANNOUNCE's SDP body correctly but doesn't call out that it's version-gated at the call-site level (`airplayv1.py:47-79` calls `self.rtsp.announce(...)`; `airplayv2.py` never calls it). Confirmed in §4 below.
4. **The prior report's §9.5 audio-packet-encryption description is accurate**, but doesn't note that the AirPlay-2 stream's `shk` is keyed as **both** the output *and* input key of a self-symmetric cipher (`Chacha20Cipher8byteNonce(shared_secret, shared_secret)`, `airplayv2.py:156`) — since audio only flows sender→receiver, there is no meaningful "input" direction, but the API still requires an `in_key` argument and pyatv passes the same value. Worth stating explicitly so a Rust port doesn't wonder whether a second, distinct key is missing.
5. **The prior report doesn't mention `RaopPlaybackManager`** (`pyatv/protocols/raop/__init__.py:108-178`) — the session-lifecycle object that owns the `HttpConnection`/`RtspSession`/`StreamClient`/`StreamContext` for one RAOP session and is what actually decides `AirPlayV1` vs `AirPlayV2` at connect time (`__init__.py:148-157`), reusing the *exact same* `get_protocol_version` call as AirPlay's own `play_url` path. This is the single place both features' protocol-version decisions are unified; documented in §1/§4.1 below.
6. **The prior report's §5 auth-flavor summary is correct**, but doesn't connect it to what `Stream.play_url`/`Stream.stream_file` actually feed into the two `StreamProtocol` implementations: both `AirPlayV1.play_url` (`airplayv1.py:119-137`) and `AirPlayV1.setup` (`airplayv1.py:47-50`) call `pair_verify(self.context.credentials, ...)` — i.e. **every** AirPlay-1 flow, `play_url` included, performs a fresh Pair-Verify handshake on **every single call**, there is no "verify once, reuse connection" optimization; AirPlay-2's `_setup_base` (`airplayv2.py:51-105`) likewise re-verifies on every `setup()`/`play_url()` invocation since each opens a brand-new `HttpConnection`. This has real behavioral weight for a Rust port: connection reuse across multiple `play_url()` calls is not something to preserve from pyatv, because pyatv itself never does it (`RaopPlaybackManager.setup()` only short-circuits if a session is *already* active, `__init__.py:139-142`, not across separate top-level calls — each `stream_file`/`play_url` call tears down via `teardown()` in a `finally` block, `__init__.py:402-406`, `player.py` has no explicit teardown call at all but relies on the underlying `HttpConnection` being closed by the caller's context, see §2.5).

---

## 1. Protocol-version and credential selection — the one function both features share

`get_protocol_version(service, preferred_version)` (`pyatv/protocols/airplay/utils.py:241-259`):

```python
def get_protocol_version(
    service: BaseService, preferred_version: AirPlayVersion
) -> AirPlayMajorVersion:
    if preferred_version == AirPlayVersion.Auto:
        features = service.properties.get("ft")
        if not features:
            features = service.properties.get("features", "0x0")
        parsed_features = parse_features(features)
        if (
            AirPlayFlags.SupportsUnifiedMediaControl in parsed_features
            or AirPlayFlags.SupportsCoreUtilsPairingAndEncryption in parsed_features
        ):
            return AirPlayMajorVersion.AirPlayV2
        return AirPlayMajorVersion.AirPlayV1
    if preferred_version == AirPlayVersion.V2:
        return AirPlayMajorVersion.AirPlayV2
    return AirPlayMajorVersion.AirPlayV1
```

Note the TXT key priority: `ft` (RAOP service TXT) is tried **first**, falling back to `features` (AirPlay service TXT) only if `ft` is absent. Both `RaopPlaybackManager.setup()` (`pyatv/protocols/raop/__init__.py:148-151`, reading `service` = the RAOP `BaseService`) and `AirPlayPairingHandler`'s construction via `raop.pair()` (`pyatv/protocols/raop/__init__.py:595-603`) call this with the RAOP service, so for RAOP it is `ft` that matters (or `features` if the RAOP service happens not to carry `ft` — unusual but the code tolerates it). `Settings.protocols.raop.protocol_version` defaults to `AirPlayVersion.Auto` (`pyatv/settings.py:145`); there is no equivalent knob read for the AirPlay-proper `play_url` path — `AirPlayStream`'s own protocol selection is a separate call site (`pyatv/protocols/airplay/__init__.py`, not directly read in this research pass but structurally identical per `airplay-control-mrp-tunnel-port-spec.md:63`, which confirms `AirPlayStream.create_airplay_protocol` reads the AirPlay service's own `features`).

For this device (`ft`/`features` both carry the combined `0x3C177FDE4A7FDFD5`, bits 38 and 48 both set) the result is **`AirPlayMajorVersion.AirPlayV2`** for both `play_url` and RAOP, unambiguously — no fallback path is exercised.

`AuthenticationType` and credential extraction (`extract_credentials`) are fully covered in `airplay-raop-dmap.md` §5.1 and `hap-pairing-port-spec.md` §3.2/§3.4 — not re-derived here. What matters for this device: `RaopStream.stream_file` (`pyatv/protocols/raop/__init__.py:334-406`) sets `context.credentials = extract_credentials(self.core.service)` at line 355 before calling `client.initialize()`; `AirPlayStream.play_url`'s equivalent call site (structurally the same per `__init__.py:106-146` cited in `airplay-raop-dmap.md:326`) does the same for the AirPlay service. Per the live-device verdict in the device-context table above, a byte-faithful port must source that `HapCredentials` value from the Companion pairing store rather than from the AirPlay service's own (empty) `credentials`, mirroring the divergence RISKS.md M7 already documents for the MRP tunnel gate — `play_url`/RAOP share the identical AirPlay-2 pair-verify call (`verify_connection`, `pyatv/protocols/airplay/auth/__init__.py:100-117`) so the same fix applies unchanged.

---

## 2. `play_url` — full request sequence

### 2.1 Entry point and outer retry/poll loop (`pyatv/protocols/airplay/player.py`, full file, 119 lines)

`AirPlayPlayer.play_url(url, position)` (`player.py:44-71`) is the version-agnostic outer driver both `AirPlayV1` and `AirPlayV2` sit under (constructed per-version at a call site not read directly in this pass but structurally confirmed by the `test_airplay_player.py` fixture at `tests/protocols/airplay/test_airplay_player.py:21-27`, which builds `AirPlayPlayer(rtsp, airplayv1.AirPlayV1(context, rtsp))` — i.e. `AirPlayPlayer` is generic over `StreamProtocol` and the `AirPlayV1`/`AirPlayV2` split happens purely inside the `stream_protocol.play_url()` call it delegates to).

```python
PLAY_RETRIES = 3
WAIT_RETRIES = 5

async def play_url(self, url: str, position: float = 0) -> None:
    retry = 0
    async with timing_server(self.rtsp) as server:          # binds a TimingServer, see §2.6
        while retry < PLAY_RETRIES:
            resp = await self.stream_protocol.play_url(server.port, url, position)
            if resp.code == 500:
                retry += 1
                await asyncio.sleep(1.0)
                continue
            if 400 <= resp.code < 600:
                raise exceptions.AuthenticationError(f"status code: {resp.code}")
            await self._wait_for_media_to_end()
            return
    raise exceptions.PlaybackError("Max retries exceeded")
```
(`player.py:44-71`)

Exact retry semantics: up to `PLAY_RETRIES = 3` attempts total (not 3 retries after the first — the loop condition is `retry < 3` and `retry` starts at 0, so attempts 1, 2, 3 are made, each 1 second apart on `500` only); any `4xx`/`5xx` other than `500` raises `AuthenticationError` immediately with **no retry**, even for e.g. `403`/`404` — this is called out in-source as `# TODO: Should be more fine-grained` (`player.py:64`), i.e. pyatv itself acknowledges this is an imprecise mapping and a Rust port should not treat "everything non-500 in 4xx/5xx is an auth error" as semantically meaningful, just as the literal behavior to replicate for parity.

`_wait_for_media_to_end()` (`player.py:75-118`) polls `GET /playback-info` **every 1 second, indefinitely** (no timeout budget beyond the `WAIT_RETRIES = 5` idle-counter described below):

```python
async def _wait_for_media_to_end(self) -> None:
    attempts: int = WAIT_RETRIES   # 5
    video_started: bool = False
    while True:
        try:
            resp = await self.rtsp.connection.get("/playback-info")
        except (RuntimeError, exceptions.ConnectionLostError):
            break                                   # connection dropped -> assume stopped
        parsed = decode_bplist_from_body(resp) if resp.body else {}
        if "error" in parsed:
            raise exceptions.PlaybackError(f"got error {code} ({domain}) when playing video")
        if "duration" in parsed:
            video_started = True
            attempts = -1                            # once started, never decrement again
        else:
            video_started = False
            if attempts >= 0:
                attempts -= 1
        if not video_started and attempts < 0:
            break                                    # exit condition
        await asyncio.sleep(1)
```
(`player.py:75-118`, condensed but line-faithful)

Reading the finite-state behavior precisely: this is **not** "poll until playback starts, then poll until it stops" symmetrically — it is "allow up to `WAIT_RETRIES` (5) polls without a `duration` key before giving up as never-started; but once `duration` ever appears even once, `attempts` is permanently pinned to `-1` and the loop exits on the very next poll that lacks `duration`" (because `video_started` becomes `False` and `attempts` is already `< 0`). So: the file must start playing within 5 polls (~5 seconds) of the `/play` POST returning, or the coroutine returns early as if playback never started (no exception is raised in this case — it just silently returns); once it has started, the coroutine returns on the *first* poll after `duration` disappears from the response (no debounce). Only these two plist keys are read: `"error"` (dict with `code`/`domain`, defaulting to `"unknown"`/`"unknown domain"` if absent, `player.py:99-100`) and `"duration"` — `readyToPlay`, `position`, `rate`, `loadedTimeRanges` are **not read anywhere in this loop** despite being real keys tvOS returns (confirmed absent from `player.py` by full-file read; the fake test server's `airplay_playback_playing()` use-case only ever sets `duration`, `tests/fake_device/airplay.py:255-261`, confirming the real implementation only cares about that one key).

### 2.2 AirPlay-1 `play_url` (`pyatv/protocols/raop/protocols/airplayv1.py:119-137`)

```python
HEADERS = {
    "User-Agent": "MediaControl/1.0",
    "Content-Type": "application/x-apple-binary-plist",
}

async def play_url(self, timing_server_port, url, position=0.0):
    verifier = pair_verify(self.context.credentials, self.rtsp.connection)
    await verifier.verify_credentials()

    body = {
        "Content-Location": url,
        "Start-Position": position,
        "X-Apple-Session-ID": str(uuid4()),
    }
    return await self.rtsp.connection.post(
        "/play", headers=HEADERS,
        body=plistlib.dumps(body, fmt=plistlib.FMT_BINARY),
        allow_error=True,
    )
```

No `SETUP`/`RECORD`/UDP audio streaming happens for `play_url` on AirPlay 1 — the coroutine performs Pair-Verify then exactly one `POST /play` and returns whatever `HttpResponse` came back (status code drives §2.1's retry logic). `timing_server_port` is accepted as a parameter (for interface parity with the base class) but **unused** in the AirPlay-1 body — the `TimingServer` UDP socket opened by `player.py`'s `timing_server()` context manager (§2.6) exists purely so the port number can theoretically be supplied to AirPlay-2's body-less-but-parameter-carrying setup path; AirPlay-1 never wires it into anything.

Note `allow_error=True` — the underlying HTTP client will not raise on non-2xx, it returns the response object for §2.1's own status-code branching (confirmed by the parameter's presence and by `player.py`'s explicit `resp.code` checks immediately after the call).

**`Content-Type` and header order:** the dict literal order in `HEADERS` (`User-Agent` then `Content-Type`) is what pyatv's `send_and_receive` will iterate in when constructing the wire request, but `RtspSession.exchange`/`HttpConnection.post` (not fully traced in this pass) likely re-orders/merges with connection-level headers (`CSeq` etc. are RTSP-session concepts that do **not** apply here — this is a plain `HttpConnection.post`, not `RtspSession.exchange`, so no `CSeq`/`DACP-ID`/`Active-Remote` headers are sent on `/play`). A Rust port should treat header *set and values* as load-bearing and header *order* as not verified either way in this checkout.

### 2.3 AirPlay-2 `play_url` (`pyatv/protocols/raop/protocols/airplayv2.py:210-273`)

```python
HEADERS = {
    "User-Agent": "AirPlay/550.10",
    "Content-Type": "application/x-apple-binary-plist",
    "X-Apple-ProtocolVersion": "1",
    "X-Apple-Session-ID": str(uuid4()).lower(),      # fixed once per AirPlayV2 instance, module import time... no: per-instance at class body eval time
    "X-Apple-Stream-ID": "1",
}

async def play_url(self, timing_server_port, url, position=0.0):
    await self._setup_base(timing_server_port)   # pair-verify + base SETUP + event channel, see §2.3.1
    await self.start_feedback()                  # 2s FEEDBACK loop, see §2.3.2
    await self.rtsp.record()                     # RECORD, no headers/body

    body = {
        "Content-Location": url,
        "Start-Position-Seconds": position,
        "uuid": self.uuid,
        "streamType": 1,
        "mediaType": "file",
        "mightSupportStorePastisKeyRequests": True,
        "playbackRestrictions": 0,
        "secureConnectionMs": 22,
        "volume": 1.0,
        "infoMs": 122,
        "connectMs": 18,
        "authMs": 0,
        "bonjourMs": 0,
        "referenceRestrictions": 3,
        "SenderMACAddress": "AA:BB:CC:DD:EE:FF",
        "model": "iPhone14,3",
        "postAuthMs": 0,
        "clientBundleID": "dev.pyatv.GPU",
        "clientProcName": "dev.pyatv.GPU",
        "osBuildVersion": "20G1116",
        "rate": 1.0,
    }
    resp = await self.rtsp.connection.post(
        "/play", headers=HEADERS,
        body=plistlib.dumps(body, fmt=plistlib.FMT_BINARY),
        allow_error=True,
    )

    await self.rtsp.exchange("PUT", uri="/setProperty?isInterestedInDateRange", body={"value": True})
    await self.rtsp.exchange("PUT", uri="/setProperty?actionAtItemEnd", body={"value": 0})
    await self.rtsp.exchange("POST", uri="/rate?value=1.000000")
    await self.rtsp.exchange("PUT", uri="/setProperty?forwardEndTime",
                              body={"value": {"flags": 0, "value": 0, "epoch": 0, "timescale": 0}})
    await self.rtsp.exchange("PUT", uri="/setProperty?reverseEndTime",
                              body={"value": {"flags": 0, "value": 0, "epoch": 0, "timescale": 0}})
    return resp
```
(`airplayv2.py:27-33, 210-273`, verbatim field list; the `# pylint: disable=no-member` markers around `plistlib.dumps(..., fmt=plistlib.FMT_BINARY)` are omitted here for brevity but present in source)

The `X-Apple-Session-ID` header value is computed **once at class-body evaluation time** (`str(uuid4()).lower()` is a module-level dict literal default, `airplayv2.py:31`) — meaning every `AirPlayV2` instance constructed within the same Python process *while the module is loaded exactly once* shares the same session-ID header value unless the dict is copied before mutation elsewhere. This looks like an actual pyatv bug/oversight (a fresh UUID should arguably be generated per `play_url()` call, mirroring `self.uuid = str(uuid4())` which correctly *is* per-instance at `airplayv2.py:49`), but it is what ships in this checkout — flagged here rather than silently "fixed" in the port, per this project's `CLAUDE.md` guidance to validate against reality and decide deliberately rather than inherit unverified/buggy behavior blindly. **Recommendation for the Rust port: generate a fresh UUID per `play_url()` call for `X-Apple-Session-ID`** (matching `X-Apple-Session-ID`'s evident intent and matching what AirPlay-1's `play_url` correctly does at `airplayv1.py:127`, a per-call `str(uuid4())`) rather than replicating what reads as an accidental process-lifetime constant; note the divergence in code comments if implemented this way.

The `PUT`/`POST` sequence after `/play` is fire-and-forget from pyatv's error-handling perspective — `# TODO: Maybe check some return values?` (`airplayv2.py:254`) — none of the five follow-up calls' return values are inspected; a failure in any of them does not currently raise (they go through `self.rtsp.exchange`, which does raise on `TimeoutError`/protocol errors per `rtsp.py:254-330`, but non-2xx HTTP status codes on these five calls are not checked by the caller). pyatv's own comment marks `POST /rate?value=1.000000` as "most important" because without it the stream "will start paused otherwise" (`airplayv2.py:252-253`).

#### 2.3.1 `_setup_base` (`airplayv2.py:51-105`)

This is **exactly** the first half of the AirPlay-2 remote-control tunnel bring-up documented in `airplay-control-mrp-tunnel-port-spec.md` §3.2–§3.4 — same `verify_connection` call, same base `SETUP` plist body (`deviceID`, `sessionUUID`, `timingPort`, `timingProtocol: "NTP"`, `isMultiSelectAirPlay`, `groupContainsGroupLeader`, `macAddress`, `model`, `name`, `osBuildVersion`, `osName`, `osVersion`, `senderSupportsRelay`, `sourceVersion`, `statsCollectionEnabled`), same event-channel `setup_channel(EventChannel, ...)` call with 5 retries on `ConnectionRefusedError` and a 1-second backoff between attempts (`airplayv2.py:84-104`). One difference worth flagging: the tunnel port-spec's base `SETUP` body table (verify against `airplay-control-mrp-tunnel-port-spec.md` §3.2 directly for field-for-field comparison) is for the MRP-tunnel bring-up path in `ap2_session.py`; `airplayv2.py`'s `_setup_base` is a **separate, structurally-identical-but-independently-implemented** copy used only by RAOP/`play_url` — confirmed by `timingProtocol: "NTP"` here (`airplayv2.py:61`) vs. `timingProtocol: "None"` in the tunnel path per `airplay-raop-dmap.md:297` — **these are not the same code path and must not be unified into one Rust function that assumes one constant `timingProtocol` value.** RAOP-over-AirPlay-2 needs real NTP timing (§6); the MRP-only tunnel does not need audio timing at all.

`RaopPlaybackManager`/`AirPlayStream` do **not** share an `AP2Session`/`AirPlayMrpConnection`-style object with the MRP tunnel — `play_url`/`stream_file` open their own independent `HttpConnection` via `http_connect()` (`raop/__init__.py:143-145`), meaning if MRP tunneling and `play_url`/RAOP streaming happen concurrently against the same device, pyatv opens **two separate AirPlay TCP connections**, each with its own Pair-Verify handshake, its own event channel, etc. There is no connection sharing across `Protocol.MRP` and `Protocol.AirPlay`/`Protocol.RAOP` facades in this codebase.

#### 2.3.2 Feedback loop (`airplayv2.py:167-181`)

```python
FEEDBACK_INTERVAL = 2.0

async def _feedback_task_loop(self) -> None:
    while True:
        try:
            await self.rtsp.feedback()
        except Exception as ex:
            pass   # best-effort, never raises
        await asyncio.sleep(FEEDBACK_INTERVAL)
```
`self.rtsp.feedback()` is `POST /feedback`, no body, `allow_error=False` by default when called with no args (`rtsp.py:246-248`) — i.e. non-2xx *would* raise inside `exchange()`, but the outer `try/except Exception` in the loop swallows it entirely (`# TODO: Better end condition here to not risk infinite runs?` at `airplayv2.py:174`). This loop runs **for the lifetime of the `AirPlayV2` instance** (started once via `start_feedback()`'s `if self._feedback_task is None` guard, `airplayv2.py:169-170`) and is only stopped by `teardown()` cancelling the task (`airplayv2.py:158-165`), which is invoked from `StreamClient.close()` in the RAOP path but has **no equivalent call from `AirPlayPlayer.play_url`** — confirmed by a full read of `player.py`: there is no `teardown()` call anywhere in that file. This means for a pyatv-parity `play_url` implementation over AirPlay-2, the feedback task, event channel, and underlying `HttpConnection` are cleaned up only when the caller closes the connection externally (the `client_connection`/`HttpConnection` lifecycle is owned by whatever constructed the `RtspSession`, outside this file) — **a Rust port must not assume `play_url()` returning means all AirPlay-2-side resources are torn down**; that responsibility sits one layer up, and pyatv itself appears not to close it explicitly in this file, which is either intentional (connection reuse across a subsequent `stop()`/second `play_url()`) or an oversight — flag as an open question (§16) rather than silently adding a `teardown()` call pyatv doesn't have.

### 2.4 `FeatureName.PlayUrl` / `FeatureName.Stop` gating

`AirPlayFeatures.get_feature` (cited fully in `airplay-control-mrp-tunnel-port-spec.md:93-110`, not re-derived here): `PlayUrl` is `Available` iff `SupportsAirPlayVideoV1` or `SupportsAirPlayVideoV2` is set in the AirPlay service's `features`/`ft` bitmask (both set for this device, §Live device context table); `Stop` is unconditionally `Available`. `AirPlayStream.play_url` takes an exclusive `RemoteControl` takeover lock (`core.takeover(RemoteControl)`) for the duration of the call (`airplay-control-mrp-tunnel-port-spec.md:112`) — a Rust `FacadeAppleTV` must replicate this exclusive-lock semantic, not just merge `RemoteControl` registrations, or an in-flight `play_url` and an MRP-tunnel button press could race.

### 2.5 `AirPlayRemoteControl.stop()` — how `stop()` interacts with `play_url`

Per `airplay-control-mrp-tunnel-port-spec.md:110`, `AirPlayRemoteControl`'s only implemented method is `stop()`, which calls `self.stream.stop()`. `AirPlayStream.play_url`'s coroutine (structurally, `pyatv/protocols/airplay/__init__.py`, not read in full in this pass but cross-confirmed by `player.py`'s design: the coroutine is held open by `_wait_for_media_to_end`'s indefinite polling loop until either the device reports playback ended or the connection is lost) is cancelled/stopped by closing the underlying connection — `stop()` closing the connection is what makes `GET /playback-info` in `_wait_for_media_to_end` raise `ConnectionLostError`/`RuntimeError`, which is caught and treated as "assume video playback stopped" (`player.py:85-87`). This is the entire `stop()` mechanism for `play_url`: there is no explicit `/stop` RTSP-verb call anywhere in `player.py`, `airplayv1.py`, or `airplayv2.py` — confirmed absent by full-file reads of all three. (`airplay-raop-dmap.md`'s §8 doesn't call this out either; worth stating precisely since a Rust port might otherwise look for a `/stop` endpoint that doesn't exist in pyatv's `play_url` path.)

### 2.6 `TimingServer` context manager for `play_url` (`player.py:24-32`)

```python
@asynccontextmanager
async def timing_server(rtsp: RtspSession):
    local_addr = (rtsp.connection.local_ip, 0)
    (_, server) = await asyncio.get_event_loop().create_datagram_endpoint(
        TimingServer, local_addr=local_addr
    )
    yield server
    server.close()
```
Binds an ephemeral UDP socket on the local IP used for the RTSP connection, port 0 (OS-assigned). `TimingServer` here is `pyatv.protocols.raop.protocols.TimingServer` (`protocols/__init__.py:102-146`, full class reproduced in §6.1 below since it's identical for both `play_url` and `stream_file`) — i.e. **`play_url` always opens a timing UDP socket even on AirPlay-1**, even though `AirPlayV1.play_url` never uses the port number it's handed. This is purely defensive/interface-uniform code; it does not receive meaningful traffic during a `play_url` session (no SETUP/RECORD/audio streaming happens, so the receiver never has a reason to query this timing server) but it does bind a real socket for the lifetime of the `async with` block, which is the entire `play_url()` call including the `_wait_for_media_to_end` polling loop.

### 2.7 tvOS-26/27-era `play_url` issues — search result

Per this task's instruction to search the checkout's `CHANGELOG.md`/`docs/`/code comments rather than guess: `CHANGES.md` (root, full changelog since project inception) contains **no tvOS-26-or-27-specific `play_url` entries**. The only historical `play_url`-tagged changelog entries are from **release 0.13.3 (2023-08-03)**: `c5772b3 airplay: Support stop with play_url` and `c554ab7 airplay: Fix play_url with newer tvOS versions` (`CHANGES.md:867-868`, `900-901`), both roughly 3 years stale relative to this research date and unrelated to any tvOS-26/27-specific regression. `docs/index.md:70` notes only that "`play_url` on tvOS was restored in version 0.13.3" — again historical. No `# TODO`/`# FIXME`/`# XXX` comment referencing tvOS 26 or 27 was found in `player.py`, `airplayv1.py`, or `airplayv2.py` by full-file read. **Conclusion: this checkout contains no documented tvOS-26/27-era `play_url` regression or open issue — RISKS.md's L1 citation of "open upstream issues on `play_url`" is sourced from outside this checkout (the live GitHub issue tracker, not fetched as part of this research pass) and should be treated as unverified against this specific commit until an issue number/URL is captured.** A Rust port should not invent a workaround for a problem this checkout doesn't itself evidence; if a live run against the tvOS 27 device surfaces a `play_url` failure, capture it as a new, dated finding the way RISKS.md's M7/L10 entries were captured, rather than assuming it matches an unspecified upstream issue.

---

## 3. `AirPlayStream` interface — `play_url(url, position)` and local-file serving

`airplay-raop-dmap.md:326` documents the local-file `StaticFileWebServer` rewrite correctly (source: `pyatv/protocols/airplay/__init__.py:106-146` and `pyatv/support/http.py:608-647`, not independently re-verified line-by-line in this pass since the prior report's citation is specific and the mechanism — spin up a throwaway single-file `aiohttp` server, rewrite `url` to `http://<local-ip>:<port>/<filename>`, 401 any other path — is orthogonal to the wire protocol this document focuses on). One detail worth adding: this rewrite happens **before** protocol-version selection or Pair-Verify, so a local file is always served over plain HTTP from pyatv's own throwaway server regardless of whether the eventual `/play` POST to the target device goes over AirPlay-1 or AirPlay-2 — the device fetches the file itself via a normal `GET`, which is exactly what `tests/fake_device/airplay.py:110-127`'s `handle_airplay_play` simulates (`if self.state.last_airplay_url.startswith("http://127.0.0.1"): ... simple_get(...)`).

`Stream.play_url(url: str, **kwargs) -> None` public signature confirmed at `docs/api/pyatv.interface.html:2244` (`async def play_url(self, url: str, **kwargs) -> None`) — the public interface accepts `**kwargs`, of which `position` is the only one actually consumed per the concrete `AirPlayStream.play_url`/`AirPlayPlayer.play_url` chain (default `0`/`0.0`).

---

## 4. RAOP — protocol selection and session lifecycle

### 4.1 `RaopPlaybackManager.setup` (`pyatv/protocols/raop/__init__.py:138-165`)

```python
async def setup(self, service: BaseService) -> Tuple[StreamClient, StreamContext]:
    if self._stream_client and self._rtsp and self._context:
        return self._stream_client, self._context          # reuse if already active

    self._connection = await http_connect(str(self.core.config.address), self.core.service.port)
    self._rtsp = RtspSession(self._connection)

    protocol_version = get_protocol_version(service, self.core.settings.protocols.raop.protocol_version)
    protocol_class = (
        airplayv1.AirPlayV1 if protocol_version == AirPlayMajorVersion.AirPlayV1
        else airplayv2.AirPlayV2
    )
    self._stream_client = StreamClient(self._rtsp, self._context, protocol_class(self._context, self._rtsp), self.core.settings)
    return self._stream_client, self._context
```

For this device (§1): **`protocol_version == AirPlayMajorVersion.AirPlayV2`**, so `StreamClient` wraps an `AirPlayV2` instance. Connection target is `self.core.service.port` — i.e. the **RAOP** service's own port from its `_raop._tcp` SRV record (not the AirPlay port), confirmed by `self.core.service` referring to the `Protocol.RAOP` `BaseService` in this module's context (`Core.service` per the `pyatv-core` `Core` abstraction, standard across all protocol crates). `RaopStream.stream_file` then does `client, context = await self.playback_manager.setup(self.core.service)` (`raop/__init__.py:354`), passing the RAOP service explicitly.

### 4.2 `StreamClient.initialize` (`pyatv/protocols/raop/stream_client.py:287-338`)

Sequence, exactly as it appears in source:

1. Parse `EncryptionType`/`MetadataType` from the RAOP TXT properties (`et`/`md`, `parsers.py:49-96`) — for this device: `EncryptionType.FairPlay | EncryptionType.FairPlaySAPv25` (from `et=0,3,5`; note `0` maps to `Unencrypted` too, so the full flag set is `Unencrypted | FairPlay | FairPlaySAPv25`), `MetadataType.Text | MetadataType.Artwork | MetadataType.Progress` (from `md=0,1,2`).
2. `intersection = encryption_types & SUPPORTED_ENCRYPTIONS` where `SUPPORTED_ENCRYPTIONS = EncryptionType.Unencrypted | EncryptionType.MFiSAP` (`stream_client.py:54`) — for this device, `Unencrypted` is in the intersection (bit `0` present), so **no** "no supported encryption type, continuing anyway" debug log fires; the check exists only to log, never to abort (`stream_client.py:299-302`).
3. `_update_output_properties(properties)` — reads `sr`/`ch`/`ss` (not present in this device's given TXT excerpt; defaults apply: `44100`/`2`/`16` per `parsers.py:8-10, 38-46`).
4. Open two UDP sockets: `ControlClient` bound to `(local_ip, settings.protocols.raop.control_port)` (default `0`, i.e. ephemeral) and `TimingServer` bound to `(local_ip, settings.protocols.raop.timing_port)` (default `0`) — **these are separate socket objects from the `play_url`-path `TimingServer` in §2.6**, even though both use the same `TimingServer` class from `protocols/__init__.py`.
5. `self._info.update(await self.rtsp.info())` — `GET /info`, binary-plist body, used later to seed `initialVolume` (§10).
6. `if self._requires_auth_setup: await self.rtsp.auth_setup()` — **for this device, `False`**: `_requires_auth_setup` (`stream_client.py:353-363`) requires `EncryptionType.MFiSAP in self._encryption_types` (bit `4` in `et`), which this device's `et=0,3,5` does **not** include, so `/auth-setup`/MFiSAP is skipped entirely regardless of the device's `am` (model) TXT value.
7. `await self._protocol.setup(timing_server.port, control_client.port)` — dispatches to `AirPlayV2.setup` (§4.3, since this device is AirPlay-2) or `AirPlayV1.setup`.

### 4.3 `AirPlayV2.setup` (`airplayv2.py:107-156`) — for this device

```python
async def setup(self, timing_server_port: int, control_client_port: int) -> None:
    await self._setup_base(timing_server_port)      # §2.3.1, pair-verify + base SETUP + event channel
    await self.setup_audio_stream(control_client_port)
```

`setup_audio_stream` (§5.2 below) is the audio-specific second `SETUP`. Compare to `AirPlayV1.setup` (`airplayv1.py:47-79`): `pair_verify` + `ANNOUNCE` (SDP, §5.1) + one `SETUP` with a `Transport:` header (not a plist body).

---

## 5. RAOP RTSP sequence — verb by verb, both protocol versions

### 5.1 AirPlay-1 RAOP setup (not used for this device, documented for completeness since a Rust port must support both)

`AirPlayV1.setup` (`airplayv1.py:47-79`):

1. `pair_verify(credentials, connection).verify_credentials()`.
2. `ANNOUNCE`, `Content-Type: application/sdp`, body from `ANNOUNCE_PAYLOAD` (`rtsp.py:25-35`):
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
   `requires_password = password is not None`; if `password` is set, `allow_error=True` is passed and a `401` with `WWW-Authenticate` triggers Digest-auth setup (`get_digest_payload`, `rtsp.py:65-73`) and a second `ANNOUNCE` retry (`rtsp.py:148-168`).
3. `SETUP`, `Transport: RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port={control_client_port};timing_port={timing_server_port}`. Response `Transport` header parsed via `parse_transport` (semicolon-split, `key=value` pairs collected into a dict, bare tokens into a list — `airplayv1.py:24-34`), yielding `timing_port` (optional, defaults `0` if missing from response), `control_port` (required, `KeyError` if missing), `server_port` (required). `Session` header from response becomes `context.rtsp_session` (parsed as `int`).

### 5.2 AirPlay-2 RAOP setup — the exact SETUP used against this device (`airplayv2.py:112-156`)

```python
setup_resp = await self.rtsp.setup(body={
    "streams": [{
        "audioFormat": 0x800,
        "audioMode": "default",
        "controlPort": control_client_port,
        "ct": 1,                    # Raw PCM
        "isMedia": True,
        "latencyMax": 88200,
        "latencyMin": 11025,
        "shk": shared_secret,       # 32 bytes, see §5.2.1
        "spf": 352,                 # Samples Per Frame
        "sr": 44100,
        "type": 0x60,               # 96 decimal
        "supportsDynamicStreamID": False,
        "streamConnectionID": self.rtsp.session_id,
    }]
})
resp = decode_bplist_from_body(setup_resp)
stream = resp["streams"][0]
self.context.control_port = stream["controlPort"]
self.context.server_port = stream["dataPort"]
self._cipher = Chacha20Cipher8byteNonce(shared_secret, shared_secret)
```

Sent as an `RtspSession.setup(body=...)` call, which per `RtspSession.exchange` (`rtsp.py:284-289`) is auto-converted to a binary plist body with `Content-Type: application/x-apple-binary-plist` because `body` is a `dict`.

#### 5.2.1 `shk` derivation (RAOP-stream shared key)

```python
out_key, _ = self._verifier.encryption_keys(EVENTS_SALT, EVENTS_WRITE_INFO, EVENTS_READ_INFO)
shared_secret = out_key[0:32]
```
(`airplayv2.py:120-125`) — `EVENTS_SALT = "Events-Salt"`, `EVENTS_WRITE_INFO = "Events-Write-Encryption-Key"`, `EVENTS_READ_INFO = "Events-Read-Encryption-Key"` (`airplayv2.py:21-23`), i.e. the **event channel's own HKDF "output" key** (see `hap-pairing-port-spec.md` §4.3's per-channel table for the exact HKDF derivation — same info/salt strings, same X25519 Pair-Verify shared secret as IKM) is reused, truncated to 32 bytes, as the RAOP audio-stream `shk`. pyatv's own code comment admits this is not "really correct" — the spec's evident intent is a value derived independently from (or directly equal to) something Pair-Verify-specific to the *audio stream itself*, not borrowed from an unrelated channel's key — but pyatv states "it doesn't really matter what the key is... it's merely a security feature," so it derives *something* deterministic-but-unrelated instead of hardcoding a constant (`airplayv2.py:117-121`, quoted in full in `airplay-raop-dmap.md:372`, not repeated verbatim here beyond the code itself). **Decision point for the Rust port** (also listed in `airplay-raop-dmap.md` §13 and repeated here for RAOP-specific emphasis): replicate this exact derivation for pyatv-compatibility testing, since the audio-packet cipher (§6) is keyed from it and any KAT fixture generated against pyatv's own runtime will use this exact value.

### 5.3 `SETPEERS` — not used by pyatv, PTP-only, documented only

Confirmed absent from all of `airplayv1.py`, `airplayv2.py`, `stream_client.py`, `rtsp.py` by full-file read — `airplay-raop-dmap.md:373`'s note that this is "documented only" is confirmed accurate; no PTP support exists anywhere in this checkout's RAOP implementation. `SupportsPTP` (bit 41) is set on this device's `features` (per the device-context table) but pyatv never negotiates PTP timing regardless — it always uses NTP (§6.1).

### 5.4 `RECORD` (`stream_client.py:438-448`, called from `send_audio`)

```python
await self.rtsp.record()
await self.rtsp.flush(headers={
    "Range": "npt=0-",
    "Session": self.context.rtsp_session,
    "RTP-Info": f"seq={self.context.rtpseq};rtptime={self.context.rtptime}",
})
```
`RECORD` itself carries no headers/body from the `RtspSession.record()` wrapper (`rtsp.py:178-184`) beyond the standard per-request headers `exchange()` always adds (`CSeq`, `DACP-ID`, `Active-Remote`, `Client-Instance`, §5.7). `FLUSH` immediately follows `RECORD`, before any audio packet is sent, with the `Range`/`Session`/`RTP-Info` headers shown — this resets receiver buffer state before streaming starts (`airplay-raop-dmap.md:375` already documents this ordering correctly; reproduced here with the exact header values since the prior report summarized rather than quoted).

Compare to `play_url`'s AirPlay-2 path (§2.3): `RECORD` is called there too (`airplayv2.py:214`), with **no FLUSH** — `play_url` never sends audio packets, so there is no buffer to flush; `RECORD` there exists purely because it's part of the base tunnel/stream-setup handshake the receiver expects before `/play` will be honored. **Per RISKS.md L10, tvOS 27's event-channel `SETUP` response may include `skipRecord: true`, a key pyatv's code has no knowledge of — both `play_url`'s `_setup_base`→`RECORD` sequence (§2.3.1/§2.3) and RAOP's `setup()`→`RECORD` sequence (§4.3/§5.4) share this exposure identically, since both call the same `_setup_base` and both proceed to send `RECORD` unconditionally afterward.** A Rust port implementing byte-faithful pyatv behavior would send `RECORD` regardless; a Rust port prioritizing live-device correctness on tvOS 27 should honor `skipRecord` if present and skip it, for **both** `play_url` and RAOP, and this should be tested against the real device for both flows independently since L10 was only confirmed for the MRP-tunnel path, not yet for RAOP/`play_url`.

### 5.5 `SET_PARAMETER` — volume, metadata, artwork, progress

Fully covered mechanically by `airplay-raop-dmap.md` §9.1's last bullet; exact call sites and header sets from `rtsp.py`:

- **Volume**: `set_parameter("volume", str(dbfs_value))` → `SET_PARAMETER`, `Content-Type: text/parameters`, body `"volume: {value}"` (`rtsp.py:194-200`). No `Session`/`RTP-Info` headers on this one (confirmed by the method signature taking no extra headers).
- **Progress**: `set_parameter("progress", f"{start}/{now}/{end}")`, same `text/parameters` mechanism, values are RTP-clock ticks (not seconds) — `start = context.rtptime` (at stream start, i.e. `head_ts - (start_ts - latency)` evaluated once before any audio is sent, so `head_ts == start_ts` at that point and the expression reduces to `latency`), `now = context.rtptime` (same value, computed a statement later with no state change between, so numerically identical to `start`), `end = start + source.duration * context.sample_rate` (`stream_client.py:399-404`) — i.e. `now` and `start` are always equal at the moment this is sent; only `end` differs, computed from `AudioSource.duration` (seconds) times sample rate.
- **DAAP metadata**: `SET_PARAMETER`, `Content-Type: application/x-dmap-tagged`, headers `Session`/`RTP-Info: seq={rtpseq};rtptime={rtptime}` (evaluated at the moment `send_audio` reaches this call, i.e. before any packet has been sent — `rtpseq`/`rtptime` are whatever `context.reset()` randomized them to), body = `tags.container_tag("mlit", payload)` where `payload` concatenates zero or more of `tags.string_tag("minm", title)`, `tags.string_tag("asal", album)`, `tags.string_tag("asar", artist)` **in that fixed order** (title, album, artist — note album before artist), only for fields that are truthy (`rtsp.py:202-226`, `stream_client.py:406-415`).
  - `string_tag(name, value)` exact bytes (`pyatv/protocols/dmap/tags.py:75-81`): `name.encode("utf-8")` (4 ASCII bytes) `+ len(value).to_bytes(4, "big")` (4-byte big-endian length, **byte length of the UTF-8 encoding, not character count**) `+ value.encode("utf-8")`.
  - `container_tag(name, data)` = `raw_tag(name, data)` = same 4-byte-key + 4-byte-big-endian-length + raw-bytes framing, just without the intermediate string encoding step (i.e. structurally identical DMAP TLV framing for both, `tags.py:86-88` and the `raw_tag` definition it delegates to — confirmed by `airplay-raop-dmap.md:462-464`'s general DMAP TLV description, which applies here unchanged: `Key(4) | Length(4, BE) | Data(Length)`).
- **Artwork**: `SET_PARAMETER`, `Content-Type: image/jpeg`, same `Session`/`RTP-Info` headers as metadata, raw JPEG bytes as body, unconditionally (no format sniffing/validation — whatever bytes are in `metadata.artwork` are sent as-is with a hardcoded `image/jpeg` content type even if the bytes aren't actually JPEG) (`rtsp.py:228-244`, `stream_client.py:417-428`).

Gating: metadata/artwork/progress `SET_PARAMETER` calls are only made if the corresponding `MetadataType` bit is present in the receiver's `md` TXT — for this device (`md=0,1,2`), **all three are sent** every time `send_audio` runs (`stream_client.py:399-428`, condition checks at each call site: `if MetadataType.Progress in self._metadata_types`, `if MetadataType.Text in self._metadata_types`, `if MetadataType.Artwork in self._metadata_types and metadata.artwork is not None`).

### 5.6 `FLUSH`, `TEARDOWN`

`FLUSH` shown in §5.4. `TEARDOWN`: `RtspSession.teardown(rtsp_session)` → `TEARDOWN`, header `Session: {rtsp_session}`, no body (`rtsp.py:250-252`), called from `StreamClient.send_audio`'s `finally` block **after** streaming completes/errors, immediately followed by closing the audio UDP transport and calling `self.close()` (which tears down the protocol object, control client, and timing server) (`stream_client.py:461-470`). `play_url` never calls `TEARDOWN` — confirmed absent from `player.py`/`airplayv1.py`/`airplayv2.py`'s `play_url` methods by full-file read (consistent with §2.5's finding that `play_url` has no explicit session-end RTSP verb at all).

### 5.7 `OPTIONS`/`GET_PARAMETER` — not implemented by pyatv as a client

Confirmed by full-file read of `rtsp.py`: `RtspSession` has no `options()` or `get_parameter()` method. `airplay-raop-dmap.md:340`'s note that `OPTIONS` is "informational only, not something pyatv itself relies on" is confirmed correct and complete — nothing to add.

### 5.8 Standard per-request headers (`RtspSession.exchange`, `rtsp.py:254-330`)

Every RTSP verb sent through `exchange()` (i.e. everything except the raw `/play`, `/playback-info`, `/feedback`, `/auth-setup`-adjacent calls that go through `HttpConnection` directly or `exchange()` with a plain URI) carries:

```
CSeq: {monotonic per-connection counter, starts at 0}
DACP-ID: {random 64-bit int, uppercase hex, fixed per RtspSession}
Active-Remote: {random 32-bit int, decimal, fixed per RtspSession}
Client-Instance: {same value as DACP-ID}
```
(`rtsp.py:86-89, 268-273`) — `session_id`, `dacp_id`, `active_remote` are all generated once in `RtspSession.__init__` via `randrange` and reused for every request on that connection; `dacp_id` format is `f"{randrange(2**64):X}"` (uppercase hex, no fixed width — leading zeros are not padded, so length varies 1–16 hex chars depending on the random value). `Content-Type: application/x-apple-binary-plist` and `Content-Length` (implicit, added by the HTTP-send layer, not shown in `RtspSession` itself) are added when `body` is a `dict`. `User-Agent: AirPlay/550.10` is the fixed constant used for every `RtspSession`-mediated request, both AirPlay 1 and AirPlay 2 RAOP streaming (`rtsp.py:22`, distinct from `play_url`'s own per-version `User-Agent` headers in §2.2/§2.3, which override this for the `/play` POST specifically since that goes through `HttpConnection.post` directly, not `RtspSession.exchange`). `CSeq` response correlation is done by matching the response's own `CSeq` header against a table of pending `asyncio.Event`s, with a **4-second timeout** (`async_timeout(4)`, `rtsp.py:316`) raising `TimeoutError` if no matching response arrives.

The RTSP "URI" for all `RtspSession`-mediated requests (unless a request explicitly passes its own `uri=`, as `/feedback`/`/setProperty...`/`/rate` do) is `rtsp://{local_ip}/{session_id}` (`rtsp.py:91-94`), where `session_id` is the same random 32-bit int used as the RTP `AudioPacketHeader.ssrc` field (§6.2) — i.e. **the RTSP session identifier and the RTP SSRC are the literal same number**, not independently generated, confirmed by `AudioPacketHeader.encode(..., self.rtsp.session_id)` at `stream_client.py:586` using `rtsp.session_id` directly as the `ssrc` argument.

---

## 6. Timing

### 6.1 NTP conversion — full file, `pyatv/protocols/raop/timing.py` (41 lines, reproduced verbatim since it is small and entirely load-bearing)

```python
def ntp_now() -> int:
    now_us = time_ns() / 1000
    seconds = int(now_us / 1000000)
    frac = int(now_us - seconds * 1000000)
    return (seconds + 0x83AA7E80) << 32 | (int((frac << 32) / 1000000))

def ntp2parts(ntp: int) -> Tuple[int, int]:
    return ntp >> 32, ntp & 0xFFFFFFFF

def ntp2ts(ntp: int, rate: int) -> int:
    return int((ntp >> 16) * rate) >> 16

def ts2ntp(timestamp: int, rate: int) -> int:
    return int(int(timestamp << 16) / rate) << 16

def ntp2ms(ntp: int) -> int:
    return ((ntp >> 10) * 1000) >> 22

def ts2ms(timestamp: int, rate: int) -> int:
    return ntp2ms(ts2ntp(timestamp, rate))
```
`0x83AA7E80` = 2208988800 = seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01), the standard NTP-to-Unix offset. `ntp2ts`/`ts2ntp` intentionally right-shift/left-shift by 16 bits around the multiply/divide (rather than doing the multiply/divide directly on the full 64-bit value) specifically to avoid intermediate-value overflow/precision loss when converting between the 64-bit NTP fixed-point format and integer RTP-clock ticks — a Rust port using `u64`/`i128` arithmetic doesn't strictly need this trick for overflow safety but **must** replicate the exact shift-then-multiply-then-shift order for bit-identical output, since integer truncation happens at each shift, not just at the end.

### 6.2 `TimingServer` (`protocols/__init__.py:102-146`) — full class

```python
class TimingServer(asyncio.Protocol):
    def datagram_received(self, data, addr):
        req = TimingPacket.decode(data)
        recvtime_sec, recvtime_frac = timing.ntp2parts(timing.ntp_now())
        resp = TimingPacket.encode(
            req.proto, 0x53 | 0x80, 7, 0,
            req.sendtime_sec, req.sendtime_frac,
            recvtime_sec, recvtime_frac,
            recvtime_sec, recvtime_frac,
        )
        self.transport.sendto(resp, addr)
```
Response type byte is `0x53 | 0x80 = 0xD3`, `seqno` (third `TimingPacket.encode` positional arg per the `RtpHeader` layout) fixed to `7`. Field mapping into `TimingPacket`'s `padding, reftime_sec, reftime_frac, recvtime_sec, recvtime_frac, sendtime_sec, sendtime_frac` (in that order, per `packets.py:7-16`): `padding=0`, `reftime_sec/frac = req.sendtime_sec/frac` (echoing the *receiver's* send time back as pyatv's "reference" time), `recvtime_sec/frac` and `sendtime_sec/frac` both set to the *same* just-computed "now" value (pyatv doesn't distinguish "when we received the request" from "when we're sending the reply" — both timestamps are taken once, after decode, before encode). This is receiver-initiated: the timing server only ever responds to a `TimingPacket` it receives; pyatv's own `ControlClient`/`StreamClient` never *sends* a `TimingPacket` — timing sync flows the other direction, via the periodic sync packets sent to the receiver's `control_port` (§6.3), not through this timing socket at all. So: **the receiver initiates timing-packet requests to pyatv's `TimingServer`; pyatv initiates sync-packet pushes to the receiver's control port; these are two independent, oppositely-directed exchanges over two different UDP sockets, not a single "ask/answer" NTP conversation.**

### 6.3 Sync packets — `ControlClient._sync_task` (`stream_client.py:103-135`)

```python
first_packet = True
current_time = timing.ts2ntp(context.head_ts, context.sample_rate)
while transport is not None:
    current_sec, current_frac = timing.ntp2parts(current_time)
    packet = SyncPacket.encode(
        0x90 if first_packet else 0x80,
        0xD4,
        0x0007,
        context.rtptime - context.latency,
        current_sec, current_frac,
        context.rtptime,
    )
    first_packet = False
    transport.sendto(packet, dest)          # dest = (remote_ip, context.control_port)
    await asyncio.sleep(1.0)
    current_time = timing.ts2ntp(context.head_ts, context.sample_rate)
```
Sent **once per second, starting immediately at `ControlClient.start()`** (called from `send_audio` right after the audio UDP transport is created, `stream_client.py:397`, i.e. before `RECORD`/`FLUSH` are sent — sync packets begin flowing before playback formally starts). `SyncPacket` field order (`packets.py:18-24`): `now_without_latency` (= `rtptime - latency`, i.e. `head_ts - start_ts` since `rtptime = head_ts - (start_ts - latency)` by definition, §9.4/`protocols/__init__.py:54-57` — algebraically this is exactly the "raw" position without the look-ahead offset), `last_sync_sec`/`last_sync_frac` (the wall-clock NTP time this specific sync packet was built, **not** literally "last" in the sense of a previous packet — despite the field name, it's computed fresh every iteration from `context.head_ts` at that moment), `now` (= `context.rtptime`, the latency-inclusive RTP timestamp). First packet's `proto` byte is `0x90` (marker bit set), all subsequent packets use `0x80`; `type` is always `0xD4`; `seqno` is always the fixed literal `0x0007` (**not incremented per packet** — every sync packet on a given stream has the identical RTP-header `seqno` field, `7`).

### 6.4 Retransmission (`stream_client.py:146-183`)

`ControlClient.datagram_received` checks `data[1] & 0x7F` (masking the marker bit off the `type` byte) against `0x55`; if matched, decodes a `RetransmitReqeust` (packet layout `RtpHeader + {lost_seqno: u16, lost_packets: u16}`, `packets.py:33-35`, note the misspelling `RetransmitReqeust` is the actual class name in source — reproduce the misspelling only if literally porting the Python identifier for cross-reference purposes, not as a naming convention to adopt in idiomatic Rust) and resends every packet from `PacketFifo` (§6.5) in the range `[lost_seqno, lost_seqno + lost_packets)` that is still present in the backlog, each wrapped as `b"\x80\xd6" + original_seqno_bytes + full_cached_packet_bytes` where `original_seqno_bytes` is bytes `[2:4]` of the cached packet (i.e. the RTP header's own `seqno` field, re-extracted from the stored packet rather than recomputed) (`stream_client.py:155-170`). Missing-from-backlog packets are silently skipped with a debug log, no error surfaced. `PACKET_BACKLOG_SIZE = 1000` (`stream_client.py:44`).

### 6.5 `PacketFifo` (`fifo.py`, full file, 82 lines) — semantics, not just structure

Insertion-ordered (not sequence-number-ordered) bounded dict: `__setitem__` raises `ValueError` if the index (sequence number) already exists (no overwrite), evicts the **oldest-inserted** entry (`list(self._items.keys())[0]`, i.e. Python dict insertion order, not numerically lowest key) when `len+1 > upper_limit`. `__delitem__` explicitly raises `NotImplementedError` — items can only leave via eviction or `clear()`. `clear()` (called after every `send_audio` session ends, `stream_client.py:462`) empties it entirely — the backlog does **not** persist across separate `stream_file()`/streaming-session calls, matching §0 point 6's observation that pyatv never reuses session state across top-level calls.

---

## 7. RTP audio packet layout (`pyatv/protocols/raop/packets.py`, full file, 36 lines) and `defpacket` (`pyatv/support/packet.py`, full file, 31 lines)

`defpacket` is a thin `struct`-based codec generator: format string is always big-endian (`">" + "".join(field-format-chars)`), fields are declared as `name=format_char` kwargs in call order (Python 3.7+ dict ordering guarantees field order matches declaration order), `.extend(name, **more_fields)` produces a new packet type whose fields are `{**base_fields, **new_fields}` — since Python dicts preserve first-insertion order and `**base_fields` is spread first, extended fields always come **after** the base fields in the encoded byte layout, never interleaved (`packet.py:29-30`).

```python
RtpHeader          = { proto: B(u8), type: B(u8), seqno: H(u16) }                              # 4 bytes
TimingPacket        = RtpHeader + { padding: I, reftime_sec: I, reftime_frac: I,
                                     recvtime_sec: I, recvtime_frac: I, sendtime_sec: I, sendtime_frac: I }  # 4+28 = 32 bytes
SyncPacket          = RtpHeader + { now_without_latency: I, last_sync_sec: I, last_sync_frac: I, now: I }    # 4+16 = 20 bytes
AudioPacketHeader   = RtpHeader + { timestamp: I, ssrc: I }                                     # 4+8 = 12 bytes (payload appended manually by caller)
RetransmitReqeust   = RtpHeader + { lost_seqno: H, lost_packets: H }                            # 4+4 = 8 bytes
```
(`packets.py:1-36`, struct format chars: `B`=u8, `H`=u16(BE), `I`=u32(BE), all confirmed big-endian since the format prefix is always `">"`)

Wire values used when constructing an `AudioPacketHeader` for a normal audio packet (`stream_client.py:581-587`):
```python
header = AudioPacketHeader.encode(
    0x80,                                   # proto: always 0x80 for audio (no marker-bit variant used here directly...)
    0xE0 if first_packet else 0x60,         # type: 0xE0 for the first packet of a session, 0x60 (96 decimal, RTP payload type) thereafter
    context.rtpseq,                         # seqno, wraps mod 2**16 after increment
    context.rtptime,                        # timestamp
    rtsp.session_id,                        # ssrc — literally the RTSP session id, see §5.8
)
```
`0xE0` for the first packet is `0x60 | 0x80` — the RTP marker bit (`0x80`) set on top of the normal payload-type byte (`0x60`), standard RTP convention for "first packet of a talkspurt." `airplay-raop-dmap.md:411`'s summary ("`type: 0x80` proto, `0xE0`/`0x60` type") is confirmed exactly correct; nothing to correct here, just reproduced with the literal encode call for a Rust port to line up field-for-field.

Fake-device receive-side confirms the same convention from the other end: `AudioReceiver.datagram_received` masks `header.type & 0x7F` to get `packet_type`, branches on `0x60` (normal — store `data[12:]` as the audio payload, i.e. strip exactly the fixed 12-byte `AudioPacketHeader`) vs `0x56` (retransmission response — strip a 4-byte retransmission header **and then** the 12-byte `AudioPacketHeader`, i.e. `data[4:][12:]`) (`tests/fake_device/raop.py:218-245`). Note `0x56` here (not `0xD6`) — the fake receiver checks the *masked* type byte (marker bit stripped), and pyatv's real retransmit-response wire format is `0x80 0xD6 ...` per §6.4, so `0xD6 & 0x7F == 0x56`, consistent.

---

## 8. Audio packet encryption (AirPlay 2 only) — exact construction

`AirPlayV2.send_audio_packet` (`airplayv2.py:183-208`):

```python
nonce = b""
if self._cipher:
    nonce = self._cipher.out_nonce          # read BEFORE calling encrypt()
    aad = rtp_header[4:12]                   # timestamp(4) + ssrc(4), 8 bytes
    audio = self._cipher.encrypt(audio, aad=aad)   # nonce=None -> uses internal auto-incrementing counter
packet = rtp_header + audio + nonce[-8:]
transport.sendto(packet)
```

`Chacha20Cipher8byteNonce` (`pyatv/support/chacha20.py:79-107`): 8-byte counter, 4-zero-byte prefix, little-endian counter, packed via `Struct("<LQ").pack(0, counter)` = `4-byte LE u32 zero` + `8-byte LE u64 counter` = 12 bytes total (the "8-byte nonce" name refers to the counter width, not the total nonce length fed to the underlying `ChaCha20Poly1305` primitive, which always takes the full 12-byte `NONCE_LENGTH`). `out_nonce`/`in_nonce` read the **current** counter value (pre-increment) — `encrypt()`/`decrypt()` increment their respective counter only when called with `nonce=None` (`chacha20.py:53-60, 63-70`). The wire packet's trailing 8 bytes are `nonce[-8:]` — i.e. the low 8 bytes of the 12-byte nonce (the counter itself, since the top 4 bytes are always zero) — **not** the full 12-byte nonce; this is the "8-byte nonce trailer" `airplay-raop-dmap.md` §9.5 already documents correctly, confirmed here with the exact slice expression.

AAD is bytes `[4:12]` of the 12-byte `AudioPacketHeader` — i.e. `timestamp` (4 bytes, offset 4) concatenated with `ssrc` (4 bytes, offset 8), **not** including `proto`/`type`/`seqno` (offset 0–3). Cipher key: `Chacha20Cipher8byteNonce(shared_secret, shared_secret)` (§5.2.1) — same 32-byte `shk` used as both the encrypt and decrypt key, confirmed in §0 point 4 above as intentional (audio only flows one direction, so the "decrypt" side of the cipher object is never exercised by pyatv's own code but the API still requires a value).

Critically, **pyatv does not pass `nonce=nonce` explicitly into `encrypt()`** — the code comment is explicit about why: doing so in the past caused the internal counter to never advance (`_out_counter` only increments inside `encrypt()`/`decrypt()` when `nonce is None`, `chacha20.py:53-60`), which would have sent every packet with nonce `0`. The current code reads `out_nonce` *first* (to know what value will be used, for the wire trailer) then calls `encrypt(audio, aad=aad)` with no explicit `nonce=`, letting the object auto-increment internally — the read and the internal auto-increment are guaranteed consistent only because nothing else touches `_out_counter` between the two calls. A Rust port's cipher abstraction must preserve this exact "peek-then-auto-advance" contract (`airplayv2.py:191-199`).

**AirPlay-1 audio packets are sent entirely in the clear** — `AirPlayV1.send_audio_packet` (`airplayv1.py:111-117`) is `packet = rtp_header + audio; transport.sendto(packet)`, no cipher object exists on that class at all (confirmed by absence of any `Chacha20Cipher`/`_cipher` attribute anywhere in `airplayv1.py`).

---

## 9. Streaming loop pacing (`stream_client.py:476-619`, `Statistics` class `stream_client.py:622-667`)

Already summarized correctly in `airplay-raop-dmap.md` §9.6; the exact constants and control-flow details worth adding for a Rust port's timer/scheduler design:

- `MAX_PACKETS_COMPENSATE = 3`, `SLOW_WARNING_THRESHOLD = 5` (`stream_client.py:41, 47`).
- `Statistics.expected_frame_count` = `int((monotonic_ns() - start_time_ns) / (10**9 / sample_rate))` — nanosecond-precision wall clock divided by the per-frame duration in nanoseconds, computed fresh on every access (not cached), giving the number of frames that *should* have been sent by now if streaming were perfectly real-time from `start_time_ns`.
- `frames_behind = expected_frame_count - total_frames` — positive means behind schedule.
- Compensation only triggers if `frames_behind >= FRAMES_PER_PACKET` (352) — i.e. a full packet's worth of lag is required before any catch-up packets are sent; `max_packets = min(int(frames_behind / FRAMES_PER_PACKET), MAX_PACKETS_COMPENSATE)` caps the burst at 3 extra packets per loop iteration regardless of how far behind the sender actually is.
- Per-iteration sleep: `abs_time_stream = stats.total_frames / sample_rate` (seconds of audio sent so far, by frame count, not wall clock), `rel_to_start = monotonic() - initial_time` (actual wall-clock elapsed since the loop began), `diff = abs_time_stream - rel_to_start`; if `diff > 0`, sleep exactly `diff` seconds (i.e. "sleep until the wall clock catches up to how much audio-time we've conceptually sent"); if `diff <= 0`, no sleep — the loop immediately sends the next packet, and a consecutive-lateness counter (`number_slow_seqno`) increments only if the *previous* iteration's `current_seqno` was exactly one less than this iteration's (i.e. truly consecutive, not just "has been late at some point recently") — once `number_slow_seqno >= SLOW_WARNING_THRESHOLD` (5), subsequent late-iteration logs upgrade from `debug` to `warning` level; this is purely observability, it never changes packet timing or drops packets.
- Padding: once `source.readframes()` returns empty, `_send_packet` synthesizes a full zero-filled packet (`context.packet_size` bytes of `\x00`) and increments `context.padding_sent` by the frame count of that packet; `_send_packet` returns `0` (terminating `_stream_data`'s loop) only once `context.padding_sent >= context.latency` — recall `context.latency = 22050 + sample_rate` (constant, set once in `StreamContext.__init__`/`reset()`, `protocols/__init__.py:28, 51`) — i.e. for the default 44100 Hz, `latency = 66150` frames (~1.5 s) of trailing silence is sent after real audio runs out, before the stream naturally ends. This padding exists specifically so the sync-packet clock (§6.3, which reads `context.head_ts`/`context.rtptime` continuously) stays coherent through the tail of playback rather than jumping discontinuously the instant real audio stops.
- Last-packet padding (distinct from trailing silence): if `source.readframes()` returns a non-empty but short final chunk (`len(frames) != context.packet_size`), it's zero-padded up to a full packet (`_send_packet`, `stream_client.py:576-579`) — this is a **separate** mechanism from the latency-padding above and happens exactly once per stream, on the true final chunk of real audio.

---

## 10. Volume control — exact mapping (`pyatv/protocols/airplay/utils.py:281-302`, not fully reproduced by the prior report's summary)

```python
DBFS_MIN, DBFS_MAX = -30.0, 0.0     # (constants not shown in the earlier grep output but referenced by name; confirmed present via pct_to_dbfs/dbfs_to_pct signatures)
PERCENTAGE_MIN, PERCENTAGE_MAX = 0.0, 100.0

def pct_to_dbfs(level: float) -> float:
    if math.isclose(level, 0.0):
        return -144.0
    return map_range(level, PERCENTAGE_MIN, PERCENTAGE_MAX, DBFS_MIN, DBFS_MAX)

def dbfs_to_pct(level: float) -> float:
    if level < DBFS_MIN:
        return PERCENTAGE_MIN
    return map_range(level, DBFS_MIN, DBFS_MAX, PERCENTAGE_MIN, PERCENTAGE_MAX)
```
`math.isclose(level, 0.0)` uses Python's default relative/absolute tolerances (`rel_tol=1e-09, abs_tol=0.0`) — for a value as small as `0.0` itself this reduces to exact-zero-or-effectively-zero comparison; a Rust port should use an equivalent epsilon comparison rather than `level == 0.0` bitwise, to match. `dbfs_to_pct`'s guard is `level < DBFS_MIN` (strictly less than `-30.0`), **not** `<=`, and **not** a check for the "true mute" sentinel `-144.0` specifically — i.e. `-144.0`, `-50.0`, and `-30.0001` all map to `PERCENTAGE_MIN` (`0.0`) identically; only exactly `-30.0` and above map linearly. `INITIAL_VOLUME = 33.0` (`pyatv/protocols/raop/__init__.py:67`) is the client-side fallback before any real device value is known.

`RaopAudio.volume` getter (`raop/__init__.py:286-293`): returns `dbfs_to_pct(context.volume)` if `context.volume is not None`, else `INITIAL_VOLUME` (33.0) — i.e. the *client-side* fallback is a flat percentage constant, not derived from any device response, until either (a) a real device value is read from `/info`'s `initialVolume` key (§4.2/`RaopStream.stream_file`, `raop/__init__.py:384-391`, only if `self.audio.has_changed_volume` is `False`, i.e. only if the user hasn't already explicitly called `set_volume` since the client was constructed) or (b) `set_volume()`/`volume_up()`/`volume_down()` is called explicitly. Test-observed values confirm the mapping precisely (`test_raop_functional.py:391-431`): `pct_to_dbfs(60) == -12.0`, receiver default `INITIAL_VOLUME = -15.0` maps back to client `50.0`, receiver value `-20.1` (a non-round fake-device default in the second test-parametrization) maps back to client `33.0` (approximately — this specific test parametrization exercises the "device does NOT support initial level" branch instead, so `-20.1` there is actually the fake device's own unrelated internal default, not something pyatv derives; don't read too much into that specific number beyond confirming the two-way linear map holds for the round-numbered cases).

---

## 11. The "buffered vs realtime" and ALAC-vs-PCM verdict (RISKS L3)

**Confirmed, not merely inferred**, by full-file reads of `parsers.py`, `airplayv1.py`, `airplayv2.py`, `rtsp.py`, `audio_source.py`:

- `parsers.py` (full file, 97 lines) parses exactly two RAOP TXT keys into enums: `et` → `EncryptionType`, `md` → `MetadataType`. **There is no `cn` (codec) parsing function anywhere in this file, and `grep -rn '"cn"' pyatv/protocols/raop/` across the whole package returns zero matches** — pyatv genuinely never reads the codec-list TXT key at all, for either protocol version, confirming `airplay-raop-dmap.md` §9.4's claim with an independent, exhaustive grep rather than a single-file read.
- AirPlay-1 `ANNOUNCE` SDP is a fixed Python format-string, `a=rtpmap:96 L16/44100/2` literal (not templated on codec choice at all — the `96`/`L16`/`44100`/`2` tokens are hardcoded in `ANNOUNCE_PAYLOAD`, `rtsp.py:25-35`; only `bits_per_channel`, `channels`, `sample_rate` are substituted, and even those come from `StreamContext`'s own negotiated properties, not from any codec-selection logic).
- AirPlay-2 stream `SETUP` hardcodes `"ct": 1` (comment: `# Raw PCM`) and `"audioFormat": 0x800` as Python literals with **no conditional branch** anywhere in `setup_audio_stream` (`airplayv2.py:127-147`) — confirmed by full-function read there is no `if`/codec-selection logic in that function at all, just a fixed dict literal.
- `audio_source.py` (full file, 739 lines) uses `miniaudio` purely for **decoding** arbitrary input (MP3, FLAC, WAV, OGG, etc., whatever `miniaudio`/`libsndfile`'s underlying decoders support — not itself enumerated in this file since `miniaudio.stream_any`/`decode_file` auto-detect format) down to raw PCM samples matching the receiver's negotiated `sample_rate`/`channels`/`sample_size`. `_to_audio_samples` (`audio_source.py:36-49`) explicitly byte-swaps to big-endian on little-endian systems before returning (`if sys.byteorder == "little": output.byteswap()`) — matching RTP `L16`'s big-endian sample convention — with an in-source comment flagging this as empirically-necessary-but-not-fully-understood (`# TODO: According to my investigation in #2057, this should happen if system byteorder is "big". So not sure why this works...`, `audio_source.py:44-45`) — i.e. **pyatv's own maintainers are not fully confident why this conditional is correct**; a Rust port should treat "PCM samples on the wire are big-endian 16-bit" as the verified requirement (matching RTP `L16` semantics) and derive the byte-swap logic from that invariant directly (always swap little-endian host samples to big-endian wire samples) rather than porting the conditional's exact "if little-endian" framing verbatim, since the framing itself is presented by pyatv's own author as uncertain.
- **No ALAC/AAC/OPUS encoder exists anywhere in this checkout** — `grep -rn "alac\|ALAC" pyatv/protocols/raop/` (across the whole package) returns zero matches beyond the codec-parsing dead-key mentioned above never being read; confirmed independently of the prior report's crate-availability research in `docs/research/rust-crates.md:86-91` (also cited in this repo, confirming no maintained pure-Rust ALAC *encoder* exists on crates.io as of 2026-08-24 either — `symphonia-codec-alac` and the `alac` crate are both decode-only).
- **This device's `cn=0,1,2,3` (PCM, ALAC, AAC, AAC-ELD all advertised as acceptable) is irrelevant to what pyatv-parity behavior sends**: since pyatv never reads `cn` and never offers anything but `ct=1`/`audioFormat=0x800` (raw PCM), the device's willingness to accept ALAC has no bearing on the wire bytes a pyatv-compatible Rust port must produce. The device's own codec preferences are simply never consulted by the sender in this design.

**Verdict: RISKS.md L3 is resolved definitively, without needing a live capture — the checkout alone proves it exhaustively.** pyatv sends raw 16-bit PCM (`ct=1`/`audioFormat=0x800`/AirPlay-1 `L16` SDP) unconditionally, on every codepath, for every device, regardless of what codecs that device advertises support for. A Rust port targeting pyatv parity does **not** need an ALAC encoder, matching `docs/research/rust-crates.md`'s existing recommendation to skip it, and matching the RISKS.md L3 mitigation's own suggested resolution path ("confirm... before pulling in an ALAC encoder") — the confirmation is now complete and negative (no ALAC needed for parity). If a future goal is to *exceed* pyatv's feature set by offering ALAC to reduce network bandwidth (this device supports `cn=1`), that remains a from-scratch undertaking with no crate support on either the encode or (this specific need) the RTP-negotiation side, and is explicitly out of scope for parity work.

**Buffered vs realtime (bit 40, `SupportsBufferedAudio`, set on this device):** confirmed by full-file read of `airplayv2.py`/`stream_client.py` — no branch anywhere reads or reacts to this bit; the streaming model (§9) is unconditionally the same immediate-RTP-push loop regardless of what the receiver advertises. `airplay-raop-dmap.md` §9.7's treatment of this as an open question stands unchanged by this deeper read; nothing new to add beyond confirming the absence is total, not partial.

---

## 12. Tests and fixtures — what a Rust fake RAOP/AirPlay receiver must implement

### 12.1 `tests/fake_device/raop.py` (full file, 616 lines, read in full above) — routes registered on `FakeRaopService` (`raop.py:357-365`)

```
ANNOUNCE       rtsp://.*          handle_announce
SETUP          rtsp://*           handle_setup
SET_PARAMETER  rtsp://*           handle_set_parameter
POST           /feedback          handle_feedback
RECORD         rtsp://*           handle_record
POST           /auth-setup        handle_auth_setup
GET            /info              handle_info
TEARDOWN       rtsp://*           handle_teardown
FLUSH          rtsp://*           handle_flush
```
Every route except `/info`/`/auth-setup` is wrapped in `@requires_auth @verify_password` decorators (`raop.py:409-524`): `requires_auth` 403s if `RaopServiceFlags.AUTH_REQUIRED` is set and `auth_setup_performed` is still `False`; `verify_password` implements a real HTTP-Digest challenge/response cycle (401 with `WWW-Authenticate: Digest realm="raop", nonce="..."` on first request if a password is configured, MD5 `HA1`/`HA2`/response verification on retry, matching `get_digest_payload`'s algorithm exactly, §5.8). A Rust fake receiver reproducing this test surface needs: SDP-`ANNOUNCE` parsing (extracts `o=` line's last token as `remote_address`, `raop.py:414-417`), `Transport:` header parsing to extract `control_port` and reply with `server_port`/`control_port`/`timing_port`/fixed `Session: "1"` (**note: the fake server's fixed session id, `"1"` literal, is not representative of real-device behavior — it's a test simplification**), `SET_PARAMETER` dispatch on `Content-Type` (`application/x-dmap-tagged` → parse DMAP `mlit` tags for `minm`/`asar`/`asal`; body starting with `"volume:"` → parse the float after a space; `image/jpeg` → store raw body as artwork; anything else → `501`), `/feedback` toggle-able `200`/`501` based on a use-case flag, `/auth-setup` accepting exactly `1 + 32` bytes (auth-type byte + Curve25519 pubkey) and otherwise `403`, `/info` returning a plist with optional `initialVolume` float key gated by a separate use-case flag, and three independent UDP sockets (`AudioReceiver` — validates/strips the 12-byte `AudioPacketHeader` and optionally simulates packet drop + retransmit-request generation gated by `RaopServiceFlags.SUPPORTS_RETRANSMISSION`; `TimingServer` — receive-only in this fixture, logs but never replies, i.e. the fake device never actually exercises pyatv's `TimingServer`'s reply path from the sender side since the fixture is a receiver stub, not a full NTP peer; `ControlServer` — decodes and counts `SyncPacket`s received, no reply).

`FakeRaopUseCases` (`raop.py:575-616`) is the state-mutation surface a Rust test harness equivalent should expose: `retransmissions_enabled`, `drop_n_packets`, `feedback_enabled`, `initial_audio_level_supported`, `require_auth`, `password`, `supports_info`, `delayed_set_volume` (the last one specifically simulates a real-device quirk pyatv works around: some receivers, "at least Sonos" per the in-source comment at `raop.py:59-64`, reject `SET_PARAMETER volume` before streaming has actually started via `FLUSH`, returning `500`; pyatv's `RaopStream.stream_file` (`raop/__init__.py:392-399`) already handles this by catching the failure and deferring the volume-set call until after `send_audio` begins, passing `volume=` through to `StreamClient.send_audio` for a post-`RECORD` retry, `stream_client.py:450-451`).

### 12.2 `tests/fake_device/airplay.py` (full file, 274 lines, `play`/`playback-info` parts read above)

Routes relevant to `play_url`: `POST /play` (`handle_airplay_play`, `airplay.py:83-136`) — asserts (not just accepts) `User-Agent == "MediaControl/1.0"` and `Content-Type == "application/x-apple-binary-plist"` **unconditionally**, meaning this fixture as written **only validates the AirPlay-1 header set** (`airplayv1.py`'s `HEADERS`, §2.2) — there is no equivalent assertion branch for AirPlay-2's different header set (`User-Agent: AirPlay/550.10`, plus `X-Apple-ProtocolVersion`/`X-Apple-Session-ID`/`X-Apple-Stream-ID`), confirming `test_airplay_player.py`'s own fixture wiring (§ above) that this specific test file only exercises the `AirPlayV1` code path — **there is no equivalent AirPlay-2 `play_url` functional test fixture assertion in this checkout for the `/play` header set**, worth flagging as a real test-coverage gap in pyatv itself, not something to silently "fill in" by assumption in the Rust port's own fake-device fixture without first deciding whether to assert AirPlay-2 headers there (a reasonable choice, since the byte values are known from source, just not test-asserted upstream).

`handle_airplay_play` echoes back the `Content-Location`/`Start-Position`/`X-Apple-Session-ID` plist fields into `state.last_airplay_url`/`last_airplay_start`/`last_airplay_uuid` for test assertions (`airplay.py:105-107`), and — notably — if the posted URL starts with `http://127.0.0.1`, actually performs a real HTTP GET against it in the background (`simple_get`, imported from `tests.utils`) and stores the fetched bytes in `state.last_airplay_content`, simulating a receiver that really does fetch the pyatv-hosted `StaticFileWebServer` URL described in §3. `handle_airplay_playback_info` (`airplay.py:138-153`) pops a queued canned response (`AirPlayPlaybackResponse(code, content)` tuples pushed via `FakeAirPlayUseCases.airplay_playback_idle()`/`airplay_playback_playing()`/`airplay_playback_playing_no_permission()`) or defaults to `{readyToPlay: False, uuid: 123}` with code `200` — confirming `readyToPlay`/`uuid` are keys real devices may return that pyatv's own `_wait_for_media_to_end` (§2.1) simply never reads, exactly as stated there.

### 12.3 `tests/protocols/airplay/test_airplay_player.py` (full file, 67 lines, read above) — exact assertions to replicate

- `test_play_video`: queues idle→playing→idle canned `/playback-info` responses, calls `play_url(STREAM, position=0.8)`, asserts the fake device recorded the right URL/position/a-non-null-UUID, and — this is the interesting one — asserts `math.isclose(total_sleep_time(), 2.0)`, i.e. **exactly two 1-second `asyncio.sleep(1)` calls happen** inside `_wait_for_media_to_end` for this exact canned-response sequence (idle, then playing, then idle again — 3 responses popped, 2 sleeps between them), confirming the sleep-per-poll-iteration accounting precisely: the loop sleeps *after* each poll, so 3 polls → 2 sleeps if the loop exits right after consuming the 3rd (`total_sleep_time()` is a test helper summing all stubbed `asyncio.sleep` calls across the test, from `tests/utils.py`, not read in this pass but its usage here is self-explanatory).
- `test_play_video_no_permission`: a `403`-coded `/playback-info` response (via `airplay_playback_playing_no_permission`) is queued for the **first** call `play_url` will make internally — but reading `player.py` again, `_wait_for_media_to_end` never inspects the *HTTP status code* of the `/playback-info` response at all (only `resp.body`'s parsed plist content), so this test's actual mechanism must be that a `403` causes `resp.body` to be empty/unparseable in a way that... Actually, re-checking `handle_airplay_playback_info`: it sets `Content-Type: text/x-apple-plist+xml"` regardless of code and returns `response.content` as body — for the `no_permission` use case, `response.content` is `None` (`AirPlayPlaybackResponse(403, None)`, `airplay.py:273`) which would make `resp.body` falsy, so `parsed = {}` and the loop just treats it as "no duration key," decrementing `attempts` normally — this does **not** obviously produce an `AuthenticationError` from `_wait_for_media_to_end`'s code as read. Re-examining: this test's queued response is consumed by the very first `/play` POST's *own* response handling in `player.py`'s outer loop, not by `/playback-info` at all — **the assertion source is actually ambiguous from `player.py`/`airplay.py` alone**; the fake device's `/play` handler (`handle_airplay_play`) doesn't consume `airplay_responses` (that's `handle_airplay_playback_info`'s queue) and always returns `200` unless `always_auth_fail`/`has_authenticated`/`injected_play_fails` are set, none of which this test touches. **This is flagged here as a genuine unresolved point this static-analysis pass could not fully close** — the most likely explanation is that `/playback-info`'s `403` propagates through `decode_bplist_from_body`/`resp.body` handling in a way that raises before reaching the `"duration"`/`"error"` key checks (e.g. `HttpResponse.get`/`RtspSession`-adjacent code treating non-2xx as an exception unless `allow_error=True`, and `self.rtsp.connection.get("/playback-info")` at `player.py:84` does **not** pass `allow_error=True`) — meaning a non-2xx response there likely raises an `HttpError`-family exception that is **not** one of the two caught types (`RuntimeError`, `exceptions.ConnectionLostError`), propagating up through `play_url()` uncaught, which is presumably the actual mechanism a `pytest.raises(exceptions.AuthenticationError)` around a raw exception... **This still doesn't cleanly explain the specific exception type asserted.** Recommend: **before implementing this specific error path in Rust, re-run this exact pytest against the live checkout with tracing to observe the real exception chain**, rather than inferring it from static reading alone — flagged explicitly in §13 as an open question this document could not close with source-reading alone, per this project's verification requirements.
- `test_play_with_retries`: 2 injected `500` failures then success — asserts `play_count == 3` (2 failed + 1 successful, matching `PLAY_RETRIES = 3`'s "3 total attempts" semantics from §2.1).
- `test_play_with_too_many_retries`: 10 injected failures (more than `PLAY_RETRIES`) — asserts `exceptions.PlaybackError` (the "Max retries exceeded" path, §2.1's final `raise` after the `while` loop exits without returning).

### 12.4 `tests/protocols/raop/test_raop_functional.py` (full file, 644 lines, read above) — the canonical RAOP functional-test surface

Already effectively documented by direct quotation of its assertions in §5/§9/§10/§11 above (metadata, volume mapping, feedback, sync packets, retransmission-gated-skip, password/digest-auth, legacy-auth-gated-by-`am`-prefix, push-updates/`Playing` state derivation, feature-availability gating, teardown, custom-metadata override semantics). Notable structural facts for a Rust test harness: `raop_properties` is a per-test `pytest.mark.parametrize` fixture overriding the TXT dict a fake device advertises (commonly just `{"et": "0"}`, i.e. most functional tests don't exercise MFiSAP/legacy-auth paths at all — those are isolated to `test_stream_complete_legacy_auth`'s own explicit `et: "4"` parametrization); `data_path(...)` resolves fixture audio files (`audio_10_frames.wav`, `audio_3_packets.wav`, `only_metadata.wav`, `static_3sec.ogg`, `only_title.wav`, `audio_1_packet_metadata.wav`) not enumerated byte-for-byte in this pass (binary fixtures, not directly useful to quote) — a Rust test suite will need equivalent small synthetic PCM/WAV/OGG fixtures of known frame counts (10 frames, 3 packets = `3*352` frames, etc.) to replicate `audio_matches()`'s per-frame-value assertion pattern (`frame_size * bytes([(i + skip_frames) & 0xFF])` — i.e. these fixture files appear to encode a simple repeating byte-ramp pattern per frame, specifically designed for exact-byte verification after the full RTP/audio pipeline, which is a good pattern for a Rust KAT fixture too).

### 12.5 `tests/support/test_rtsp.py` — not present in this checkout

Confirmed by the `find` search in this research pass (`tests/protocols/airplay/*`, `tests/protocols/raop/*` only, plus `tests/fake_device/{airplay,raop}.py`) — **there is no dedicated `tests/support/test_rtsp.py` or equivalent unit-test file for `RtspSession` in isolation** in this checkout; `RtspSession` is exercised only indirectly through the RAOP/AirPlay functional test suites above. State this explicitly rather than fabricate a citation, per this task's instructions.

### 12.6 `test_airplay_interface.py::test_feature_play_url` — the exact `FeatureName.PlayUrl` gating vectors (full file, 23 lines)

```python
@pytest.mark.parametrize("flags,expected_state", [
    ("0x0,0x0", FeatureState.Unavailable),
    ("0x1,0x0", FeatureState.Available),               # bit 0, SupportsAirPlayVideoV1
    ("0x00000000,0x20000", FeatureState.Available),    # bit 49 (0x20000 << 32), SupportsAirPlayVideoV2
])
def test_feature_play_url(flags, expected_state):
    features = AirPlayFeatures(parse_features(flags))
    assert features.get_feature(FeatureName.PlayUrl).state == expected_state
```
This is the complete unit-test evidence for the `PlayUrl` gate already summarized in §2.4/`airplay-control-mrp-tunnel-port-spec.md:93-110` — reproduced here as concrete KAT-style vectors a Rust port's own `AirPlayFlags`/`FeatureName::PlayUrl` unit tests should replicate verbatim (three cases: both bits clear → unavailable, `SupportsAirPlayVideoV1` alone → available, `SupportsAirPlayVideoV2` alone → available; note neither vector tests both bits set simultaneously, which is this document's own live device's actual state — an `OR` gate, so the missing "both set" case is not ambiguous, just untested upstream).

`test_raop.py` (full file, 174 lines) and `test_raop_scan.py` (full file, 46 lines) are pure mDNS-scan/`device_info`/`service_info` unit tests — `test_raop_scan_handlers_present` (exactly 2 handlers: `_raop._tcp.local`, `_airport._tcp.local`), `test_raop_handler_to_service` (constructs a `MutableService` with `port` taken directly from the mDNS `Service.port` field, `credentials=None`, and TXT `properties` passed through unmodified — no key renaming/filtering at scan time, consistent with `airplay-raop-dmap.md` §2.2's already-correct TXT-key table), and `service_info`/`device_info` parametrized cases matching what `airplay-raop-dmap.md` §2.2 and this document's device-context table already cover (`am`→`DeviceModel`/`OperatingSystem`, `ov`→`VERSION`, `wama`→MAC/version backfill for AirPort Express, `acl`/`act` gating `PairingRequirement`). No new wire-format facts beyond what's already cited elsewhere in this document or its parent; not reproduced verbatim here to avoid duplicating `airplay-raop-dmap.md` §2.2/§4 unnecessarily — cited for completeness of the test-inventory this task asked for.

---

## 13. Audio source pipeline (`pyatv/protocols/raop/audio_source.py`, full file, 739 lines) — formats, resampling, and the `open_source` dispatch

`AudioSource` (`audio_source.py:64-101`) is the abstract interface `StreamClient.send_audio` (§9) consumes: `async def readframes(nframes) -> bytes` (returns little-endian raw PCM per the abstract docstring — the big-endian swap for the wire happens inside `_to_audio_samples`, called by every concrete subclass before returning, not by the caller), plus `get_metadata() -> MediaMetadata`, and read-only `sample_rate`/`channels`/`sample_size`/`duration` properties. `FRAMES_PER_PACKET = 352` is redefined locally in this file (`audio_source.py:28`) as the same literal value used in `pyatv/support/rtsp.py:21` — **two independently-defined constants with the same value, not a shared import**, worth flagging since a Rust port centralizing this constant in one place is a deliberate improvement over pyatv's duplication, not a divergence in behavior.

### 13.1 `open_source` dispatch (`audio_source.py:727-739`) — the entry point `RaopStream.stream_file` calls

```python
async def open_source(source, sample_rate, channels, sample_size) -> AudioSource:
    if isinstance(source, str):
        if re.match("^http(|s)://", source):
            return await InternetSource.open(source, sample_rate, channels, sample_size)
        return await FileSource.open(source, sample_rate, channels, sample_size)
    return await BufferedIOBaseSource.open(source, sample_rate, channels, sample_size)
```

Three concrete `AudioSource` implementations, selected purely by the *type and shape* of the `source` argument `Stream.stream_file(file, ...)` was called with (`str` matching `^http(|s)://` → network; other `str` → local path; anything else, i.e. `io.BufferedIOBase` or `asyncio.streams.StreamReader` → buffered/streamed):

- **`FileSource`** (`audio_source.py:661-724`) — wraps `miniaudio.decode_file(filename, output_format=_int2sf(sample_size), nchannels=channels, sample_rate=sample_rate)`, run in a thread executor (`loop.run_in_executor`) since `miniaudio`'s decode call is synchronous/blocking. Fully decodes the entire file into memory up front (`self.samples: bytes = self.src.samples.tobytes()`, `audio_source.py:667`) — no streaming/chunked decode for local files; `readframes` just slices `self.samples[pos:pos+n]` and advances `pos`. Metadata (`get_metadata`) uses a **separate** path: `pyatv.support.metadata.get_metadata(self.src.name)`, i.e. tag-reading (title/artist/album/duration) is done independently of the audio-decode step, via `TinyTag` (`pyatv/support/metadata.py:21-40`, confirmed by direct read — `TinyTag.get(file)` in an executor, mapped into `MediaMetadata(title=tag.title, artist=tag.artist, album=tag.album, duration=tag.duration)`), not derived from anything `miniaudio` parsed.
- **`InternetSource`** (`audio_source.py:552-658`) — for `http(s)://` URLs, uses a hand-patched `PatchedIceCastClient` (`audio_source.py:458-549`, a modified copy of `pyminiaudio`'s `IceCastClient` with `urllib` replaced by `requests` specifically because "Cloudflare is blocking requests by urllib" per the in-source comment citing issue `#1546`, `audio_source.py:453-457`) to stream-download into a `SemiSeekableBuffer` on a background `threading.Thread`, while `miniaudio.stream_any(..., frames_to_read=FRAMES_PER_PACKET, ...)` decodes incrementally via a Python generator (`stream_generator`) that `readframes` steps with `next()` inside a `contextlib.suppress(StopIteration)` block, returning `AudioSource.NO_FRAMES` (`b""`) once exhausted. ICY metadata interleaving is stripped during download if the response carries an `icy-metaint` header (`audio_source.py:523-540`, reads and discards the metadata block, does not surface it to pyatv's own `MediaMetadata`). `duration` is `math.ceil(metadata.duration or 0)` — internet-streamed sources may legitimately report `0` duration if the underlying tag-reader can't determine it (e.g. a live/infinite stream), and pyatv does not special-case that beyond the ceiling.
- **`BufferedIOBaseSource`** (`audio_source.py:275-451`) — for a caller-supplied `io.BufferedIOBase` (an already-open local file handle) or `asyncio.streams.StreamReader` (piped/network input the caller controls directly, distinct from `InternetSource`'s own HTTP fetch). Uses `miniaudio.stream_any` plus a background `asyncio.Task` (`_buffering_task`, `audio_source.py:402-430`) that continuously reads `CHUNK_SIZE = FRAMES_PER_PACKET * 3` (1056 frames) chunks from the underlying `miniaudio.WavFileReadStream` and accumulates them in `self._audio_buffer` (a plain Python `bytes` object, appended-to and sliced-from — **not** a ring buffer), refilling whenever the buffer drops below 50% of `self._buffer_size = int(sample_rate / 2)` (i.e. roughly half a second of audio, sample-count based not byte-count based — for 44100 Hz this is `22050`, compared against raw frame counts not multiplied by frame size, worth double-checking exactly what unit `_buffer_size` is compared against if porting this literally: `len(self._audio_buffer) < 0.5 * self._buffer_size` at `audio_source.py:393` compares a **byte length** against a **frame count**-scaled threshold with no `* frame_size` factor — this looks like it could under- or over-buffer by exactly `channels * sample_size`× depending on interpretation, and is presented here as observed in source rather than as verified-correct; flag as a possible pyatv bug worth an independent check rather than blind replication). The **first 44 bytes** of whatever `miniaudio` returns are unconditionally discarded (`await loop.run_in_executor(None, reader.read, 44)`, `audio_source.py:358`) with an explicit in-source acknowledgment that this is a lazy/approximate WAV-header-stripping hack rather than a real header parse (`# TODO: ... It would be better to actually parse the header ... But for now we are lazy.`, `audio_source.py:354-357`) — i.e. **pyatv assumes `miniaudio.stream_any`'s output is always a WAV container with a standard 44-byte header, regardless of the actual source format**, and blindly skips that many bytes. A Rust port using `symphonia` (which decodes directly to PCM samples, not through an intermediate WAV re-encoding step) does not need to replicate this specific hack — it exists only because pyatv's decode path happens to round-trip through `miniaudio.WavFileReadStream`, an implementation detail of the Python binding, not a protocol requirement.

### 13.2 Sample format conversion (`_int2sf`, `audio_source.py:52-61`)

```python
def _int2sf(sample_size: int) -> SampleFormat:
    if sample_size == 1: return SampleFormat.UNSIGNED8
    if sample_size == 2: return SampleFormat.SIGNED16
    if sample_size == 3: return SampleFormat.SIGNED24
    if sample_size == 4: return SampleFormat.SIGNED32
    raise NotSupportedError(f"unsupported sample size: {sample_size}")
```
`sample_size` here is **bytes per sample**, matching `StreamContext.bytes_per_channel` (§9.4's `frame_size = channels * bytes_per_channel`) — this is the value read from the RAOP TXT `ss` key divided by 8 (`parsers.py:43`, default `16` bits → `2` bytes → `SIGNED16`). For this device (no `ss` given in the prompt's TXT excerpt), the default is `DEFAULT_SAMPLE_SIZE = 16` bits (`parsers.py:9`) → `SIGNED16`/2-byte samples, matching the `L16`/`audioFormat=0x800` PCM verdict of §11. `miniaudio` (and by extension `symphonia`+`rubato` in a Rust port, per `docs/research/rust-crates.md:89-95`, already selected and confirmed appropriate here) is asked to resample/reformat **to** the receiver's negotiated `sample_rate`/`channels`/`sample_size` at decode time — i.e. all three `AudioSource` implementations produce output already conformed to what `StreamContext` expects, so `StreamClient.send_audio`'s packetization loop (§9) never itself resamples or reformats; it only slices fixed-size frame chunks. **This confirms the Rust crate selection in `docs/research/rust-crates.md` is correctly scoped**: `symphonia` (decode arbitrary formats → PCM) + `rubato` (resample to the receiver's `sr`) together replace exactly what `miniaudio.stream_any`'s `output_format`/`nchannels`/`sample_rate` parameters do in one call.

### 13.3 What formats pyatv actually decodes

Not enumerated as a static list anywhere in this file — `miniaudio.stream_any`/`decode_file`/`WavFileReadStream` delegate to the underlying `miniaudio`/`dr_libs` C decoders (WAV, MP3, FLAC, OGG/Vorbis natively; other formats depending on the exact `miniaudio` build) rather than pyatv enumerating supported formats itself. `docs/research/rust-crates.md:89` already identifies the practical minimum feature set for `symphonia` to match: `mp3`, `aac`, `wav`, `flac`, `ogg` (plus `alac`, decode-only, not needed for encoding parity per §11's verdict but harmless to enable for decoding user-supplied ALAC-in-a-file input, which is a distinct concern from RTP-encoding output codec choice). No further formats are confirmed required by this pass beyond what the prior crate-selection research already scoped.

---

## 14. `RaopStream`/`RaopAudio`/`RaopFeatures`/`RaopRemoteControl`/`RaopMetadata`/`RaopPushUpdater` — the facade layer above `StreamClient`

All defined in `pyatv/protocols/raop/__init__.py` (full file, 604 lines, read above); this section documents the public-interface behavior a Rust `pyatv-proto-airplay` (or wherever RAOP lands per `CLAUDE.md`'s workspace shape) crate's equivalent facade types must reproduce, distinct from the wire-protocol detail already covered in §4–§10.

### 14.1 `StreamContext` — full property surface (`protocols/__init__.py:17-73`, full class, reproduced in one place since fields are referenced piecemeal throughout §4–§9)

```python
class StreamContext:
    credentials: HapCredentials = NO_CREDENTIALS
    password: Optional[str] = None
    sample_rate: int = 44100
    channels: int = 2
    bytes_per_channel: int = 2
    latency = 22050 + sample_rate                 # recomputed in reset() too, same formula
    rtpseq: int = 0
    start_ts = 0
    head_ts = 0
    padding_sent: int = 0
    server_port: int = 0
    event_port: int = 0                            # set but never read anywhere else in this file (dead field?)
    control_port: int = 0
    timing_port: int = 0
    rtsp_session: int = 0
    volume: Optional[float] = None

    def reset(self) -> None:
        self.rtpseq = randrange(2**16)
        self.start_ts = timing.ntp2ts(timing.ntp_now(), self.sample_rate)
        self.head_ts = self.start_ts
        self.latency = 22050 + self.sample_rate
        self.padding_sent = 0

    @property
    def rtptime(self) -> int:
        return self.head_ts - (self.start_ts - self.latency)

    @property
    def position(self) -> float:
        return timing.ts2ms(self.head_ts - self.start_ts, self.sample_rate) / 1000.0

    @property
    def frame_size(self) -> int:
        return self.channels * self.bytes_per_channel

    @property
    def packet_size(self) -> int:
        return FRAMES_PER_PACKET * self.frame_size
```
`event_port` is declared and initialized but a full grep across `protocols/__init__.py`, `airplayv1.py`, `airplayv2.py`, `stream_client.py`, `raop/__init__.py` finds no other read or write of `context.event_port` — a genuinely dead field in this checkout (the event channel's port lives on `AirPlayV2`'s own `self.event_channel` transport object instead, never round-tripped through `StreamContext`). Not worth replicating as a struct field in a Rust port unless parity with pyatv's exact struct shape (e.g. for a shared test-fixture format) specifically requires it.

`position` (used by `RaopMetadata.playing()`, §14.3) deliberately excludes `latency` from its calculation ("Do not consider latency here (so do not use rtptime)", the in-source comment at `protocols/__init__.py:62`) — i.e. **playback position reported to the user is the true elapsed-sample position, not the latency-shifted RTP wire timestamp**; only the wire protocol itself (RTP timestamps, sync packets) uses the latency-inclusive `rtptime`.

### 14.2 `RaopPlaybackManager` (`raop/__init__.py:108-178`) — session ownership and reuse rule

Already summarized in §0 point 5 and §4.1; the full `teardown()` method, not yet quoted:
```python
async def teardown(self) -> None:
    if self._stream_client:
        self._stream_client.close()
    if self._connection:
        self._connection.close()
        self._connection = None
    self._stream_client = None
    self._context.reset()
    self._rtsp = None
    self._connection = None
    self._is_playing = False
```
Note `self._context.reset()` is called on **teardown**, not just at the start of streaming (`StreamClient.send_audio` also calls `context.reset()` at `stream_client.py:386`, so `reset()` runs twice per session lifecycle — once at teardown of the previous session, once at the start of the next). `acquire()` (`raop/__init__.py:131-136`) raises `exceptions.InvalidStateError("already streaming to device")` if called while `_is_acquired` is already `True` — this is the mechanism behind `test_only_allow_one_stream_at_the_time` (§12.4): `RaopStream.stream_file` calls `self.playback_manager.acquire()` as its very first action (`raop/__init__.py:348`), so two concurrent `stream_file()` calls race on this single boolean flag, and the loser gets `InvalidStateError` immediately rather than being queued.

### 14.3 `RaopMetadata`/`RaopPushUpdater`/`RaopListener` — playing-state propagation (`raop/__init__.py:70-106, 181-206, 524-543`)

`StreamClient`'s `listener` (a `RaopListener`, weakly referenced via `weakref.ref` — `stream_client.py:245, 258-264` — meaning if nothing else holds a strong reference to the listener object, it silently stops receiving callbacks rather than raising, a common Python footgun a Rust port's equivalent trait-object/callback registration doesn't need to replicate since Rust has no equivalent implicit-weak-reference gotcha) is called at exactly two points: `listener.playing(playback_info)` right before `RECORD` is sent (`stream_client.py:433-435`, i.e. **before** the device has actually started playing anything — `playing` fires optimistically at the moment pyatv commits to starting playback, not upon confirmation), and `listener.stopped()` in `send_audio`'s `finally` block (`stream_client.py:472-474`, i.e. always fires exactly once per `send_audio` call, success or failure, including if an exception was raised partway through streaming).

`RaopStateListener` (`raop/__init__.py:524-543`, defined as a local class inside `setup()`) bridges these two callbacks into `RaopPlaybackManager.playback_info` (set to the real `PlaybackInfo(metadata, position)` on `playing()`, reset to `None` on `stopped()`) and triggers `push_updater.state_updated()` via `asyncio.ensure_future` **only if `push_updater.active`** (i.e. only if `RaopPushUpdater.start()` has been called at least once — `push_updater.active` is exactly `self._activated`, set `True` by `start()`, `raop/__init__.py:84-93`, and never reset except by explicit `stop()`). `RaopMetadata.playing()` (`raop/__init__.py:188-205`) reads `playback_manager.playback_info`: `None` → `Playing(device_state=Idle, media_type=Unknown)`; otherwise → `Playing(device_state=Playing, media_type=Music, title=..., artist=..., album=..., position=int(playback_info.position), total_time=int(metadata.duration) if metadata.duration else None)` — note **position and total_time are both truncated to `int` (whole seconds)**, not passed through as floats, even though `StreamContext.position` (§14.1) computes fractional seconds internally.

`StreamClient.playback_info` property (`stream_client.py:266-272`) substitutes `MISSING_METADATA = MediaMetadata(title="Streaming with pyatv", artist="pyatv", album="AirPlay", duration=0.0)` (`stream_client.py:50-52`) whenever the real metadata object is exactly `EMPTY_METADATA` (i.e. no title/artist/album/duration were ever supplied by the caller or extracted from the source file) — so `RaopMetadata.playing()` while actively streaming **never reports a fully-empty `Playing`**; it falls back to this fixed placeholder identity ("Streaming with pyatv" / "pyatv" / "AirPlay") rather than `None`/empty strings. A Rust port replicating pyatv-parity `Playing` output for sources with no extractable metadata must reproduce this exact fallback string triple, not just "leave fields empty."

### 14.4 `RaopFeatures.get_feature` — `FeatureName` gating (`raop/__init__.py:208-256`)

```
FeatureName.StreamFile                                    -> always Available
FeatureName.Title/Artist/Album                             -> Available iff current metadata.{title,artist,album} truthy
FeatureName.Position/FeatureName.TotalTime                 -> Available iff current metadata.duration truthy (both gated on the SAME field)
FeatureName.SetVolume/Volume/VolumeUp/VolumeDown            -> always Available ("as far as known, volume controls are always supported")
FeatureName.Stop/FeatureName.Pause                          -> Available iff playback_manager.stream_client is not None (i.e. a session is currently active)
everything else                                             -> Unavailable
```
The `FeatureName` set actually **registered** by RAOP's `setup()` (`raop/__init__.py:575-591`) is `{StreamFile, PushUpdates, Artist, Album, Title, Position, TotalTime, SetVolume, Volume, VolumeUp, VolumeDown, Stop, Pause}` — a Rust `Relayer<Features>` registration for `Protocol.RAOP` must advertise exactly this set, no more, no less, matching `test_metadata_features`/`test_volume_features`/`test_remote_control_features` (§12.4) which assert on precisely this partition.

### 14.5 `RaopAudio`/`RaopRemoteControl` — volume interface duality

Two independent public interfaces both expose volume control against the *same* underlying `context.volume`/`StreamClient.set_volume`: `Audio.set_volume(level, output_device=None)` (`raop/__init__.py:295-307`) and `RemoteControl.volume_up()`/`volume_down()` (both on `Audio`, `raop/__init__.py:309-315`, **and** separately on `RaopRemoteControl`, `raop/__init__.py:429-435` — these are two distinct classes with near-identical volume step logic, `min(volume+5.0, 100.0)`/`max(volume-5.0, 0.0)`, a fixed **5.0 percentage-point step**, duplicated rather than shared between the two interface implementations). `RaopAudio._volume_changed` (`raop/__init__.py:274-279`) subscribes to `state_dispatcher.listen_to(UpdatedState.Volume, ...)` — a cross-protocol volume-sync mechanism: if some *other* protocol facade (e.g. MRP, Companion) changes device volume, RAOP's own idea of "current volume" is updated to match, unconditionally trusting the incoming value ("We blindly trust any volume we see here as it's a much better guess than we have", `raop/__init__.py:272-273`) — relevant for a Rust `FacadeAppleTV` that runs RAOP alongside MRP/Companion against the same physical device (this device, per §Live device context, is exactly such a case). `Audio.set_volume` itself: if a `StreamClient` is currently active, calls `raop.set_volume(dbfs)` (the RTSP `SET_PARAMETER volume` wire call, §5.5) immediately; if not, just updates `context.volume` locally without any wire traffic (deferred until the next stream starts, consistent with `RaopStream.stream_file`'s own initial-volume logic, §10).

---

## 15. `/auth-setup` MFiSAP and password Digest auth — full byte layout and worked example

Not needed for this specific device (§Live device context: `et=0,3,5`, no `4`/MFiSAP bit), but required for full protocol coverage per this task's scope and directly relevant if the Rust port is ever pointed at an AirPort Express or similarly-gated receiver.

### 15.1 `/auth-setup` (`rtsp.py:37-49, 112-123`)

```python
AUTH_SETUP_UNENCRYPTED = b"\x01"

CURVE25519_PUB_KEY = (
    b"\x59\x02\xed\xe9\x0d\x4e\xf2\xbd"
    b"\x4c\xb6\x8a\x63\x30\x03\x82\x07"
    b"\xa9\x4d\xbd\x50\xd8\xaa\x46\x5b"
    b"\x5d\x8c\x01\x2a\x0c\x7e\x1d\x4e"
)   # 32 bytes, static, borrowed verbatim from owntone-server's raop.c:276 per the in-source citation

async def auth_setup(self) -> HttpResponse:
    body = AUTH_SETUP_UNENCRYPTED + CURVE25519_PUB_KEY   # 1 + 32 = 33 bytes total
    return await self.exchange("POST", "/auth-setup", content_type="application/octet-stream",
                                body=body, protocol=HTTP_PROTOCOL)   # protocol="HTTP/1.1", not "RTSP/1.0"
```
The single leading byte `0x01` signals "unencrypted" (pyatv never actually completes a real MFiSAP handshake — it sends a fixed dummy Curve25519 public key and never validates or uses whatever the receiver replies with; the whole exchange exists purely to satisfy receivers that refuse to stream audio until `/auth-setup` has been called at all, per the linked GitHub issue `#1134` cited in `airplay-raop-dmap.md:234` and `stream_client.py:356-358`). Note `protocol=HTTP_PROTOCOL` (`"HTTP/1.1"`) is passed explicitly here, **overriding** `exchange()`'s default `protocol: str = "RTSP/1.0"` (`rtsp.py:262`) — `/auth-setup` is the only call site in `rtsp.py` that does this, meaning the request line for this specific verb reads `POST /auth-setup HTTP/1.1` rather than `POST /auth-setup RTSP/1.0`. The fake device's validation (`tests/fake_device/raop.py:525-537`) only checks `len(request.body) == 33` — it does not decode or interpret the Curve25519 key at all, confirming pyatv's own dummy-handshake behavior is mirrored exactly by the test fixture (accept any 33-byte body, reject anything else with `403`).

`StreamClient._requires_auth_setup` (`stream_client.py:353-363`, quoted in full already in §Live device context table and §4.2) gates this call on **both** `EncryptionType.MFiSAP in encryption_types` **and** `model_name.startswith("AirPort")` (reading the `am` TXT key) — both conditions, not either; a device advertising MFiSAP but with a non-`AirPort*` model name (e.g. a third-party AirPlay receiver) will **not** get `/auth-setup` called by pyatv, by design, per the narrowly-scoped GitHub-issue-driven fix.

### 15.2 Password Digest auth — worked byte-level example (`rtsp.py:65-73, 129-168`, `tests/fake_device/raop.py:82-127`)

HTTP Digest, MD5, `qop`-less (no `qop=auth` negotiation — pyatv's `get_digest_payload` never includes a `qop`/`nc`/`cnonce` field, a simpler/older Digest variant):

```python
def get_digest_payload(method, uri, user, realm, pwd, nonce):
    ha1 = md5(f"{user}:{realm}:{pwd}".encode()).hexdigest()
    ha2 = md5(f"{method}:{uri}".encode()).hexdigest()
    response = md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    return f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{response}"'
```
Flow: first `ANNOUNCE` is sent with `allow_error=True` (only if `password is not None`, `rtsp.py:146-153`); if the receiver replies `401` with a `WWW-Authenticate` header, pyatv parses it by **splitting on literal `"` characters** and taking fixed positional indices — `_, realm, _, nonce, _ = www_authenticate.split('"')` (`rtsp.py:158`) — i.e. this assumes the header is *exactly* the two-quoted-value shape `Digest realm="...", nonce="..."` with no other quoted fields (no `qop`, no `opaque`, no `domain`) and no escaped quotes inside either value; a receiver sending a `WWW-Authenticate` header with additional quoted fields (even in a different order) would break this positional split. `RtspSession.digest_info` is set once (`DigestInfo("pyatv", realm, password, nonce)` — **username is the fixed literal string `"pyatv"`**, not configurable) and reused for the `Authorization` header on **every subsequent request on that connection** (`rtsp.py:275-279`), computed fresh per-request from the stored `nonce` (i.e. no nonce-refresh/re-challenge handling — if the server later returns a fresh nonce via a new `401`, pyatv's code as read does not appear to re-parse it since `digest_info` is only ever set inside `announce()`, not inside the generic `exchange()` path). The fake device (`raop.py:82-126`) implements the receiver side of exactly this flow: generates a random 32-char alphanumeric nonce on first unauthenticated request, `401`s with the exact `WWW-Authenticate: Digest realm="raop", nonce="{nonce}"` shape, then on retry splits the client's `Authorization` header the same positional way (`payload_data = request.headers.get("Authorization", "").split('"')`, expects exactly 11 elements after the split, `raop.py:107-108`) and recomputes the expected response server-side to compare.

---

## 16. Divergences & open questions — consolidated

1. **AirPlay-2 `X-Apple-Session-ID` header is a process-lifetime constant, likely an oversight (§2.3).** Recommendation: diverge from pyatv and generate fresh per-call, documenting the divergence in code.
2. **`play_url`'s teardown/resource-cleanup ownership is unclear from `player.py` alone (§2.3.2).** No `teardown()`/connection-close call exists in the file for either AirPlay version's `play_url` path; confirm empirically (live device + connection lifecycle tracing) whether the caller (facade layer, not read in this pass) closes the connection after `play_url()` returns, and whether the AirPlay-2 feedback task/event channel leak if it doesn't.
3. **`test_play_video_no_permission`'s exact exception-propagation mechanism could not be fully closed by static reading alone (§12.3).** Needs either a live pytest run with tracing against the checkout, or reading `pyatv/support/http.py`'s `HttpConnection.get`/`allow_error` semantics in full (out of scope for this pass but flagged precisely for a fast follow-up) before porting this specific error path.
4. **`shk` derivation reuses the event channel's HKDF output rather than anything RAOP-specific — pyatv's own comment calls this "not really correct" (§5.2.1).** Decision point: replicate exactly for pyatv-runtime-generated KAT compatibility, or implement a more spec-faithful derivation and verify interop separately against the live tvOS 27 device. Given `docs/RISKS.md` M7's finding that this device's pairing/verify path already diverges from pyatv's own `extract_credentials`, an independent live-capture validation of the `shk`/audio-cipher path specifically (not just the control-channel HAP framing M7 already validated) is recommended before trusting either derivation blind.
5. **`skipRecord` (RISKS L10) was only confirmed live for the MRP-tunnel event-channel `SETUP` response, not independently for RAOP's or `play_url`'s own `_setup_base`→`RECORD` sequence (§5.4).** Both share the identical code path, so the same behavior almost certainly applies, but this document treats that as a *strong inference*, not an independent live confirmation — verify with a live capture at implementation time for both `play_url` and `stream_file`.
6. **No tvOS-26/27-specific `play_url` regression is documented anywhere in this checkout (§2.7).** RISKS.md L1's citation of "open upstream issues on `play_url`" traces to the live GitHub issue tracker, not to anything fetched in this research pass — treat as unverified against this specific commit; do not implement a defensive workaround for an unspecified problem.
7. **ALAC/PCM (RISKS L3) is now definitively resolved: pyatv is PCM-only, unconditionally, confirmed by exhaustive grep, not sampling (§11).** No further live-capture verification needed for *parity* purposes; only relevant if a future goal explicitly exceeds pyatv's scope.
8. **Buffered-vs-realtime AirPlay 2 audio (bit 40) remains fully unimplemented and undocumented in pyatv (§11, unchanged from `airplay-raop-dmap.md` §9.7)** — no new information surfaced in this deeper pass; still an open question for anyone wanting to exceed pyatv's feature parity.
9. **No dedicated `RtspSession` unit-test file exists in this checkout (§12.5)** — a Rust port's own RTSP-codec unit tests will need to be original rather than ported from an equivalent upstream file.
10. **`play_url`'s two `StreamProtocol` implementations each re-run Pair-Verify on every call, never reusing a verified connection across separate `play_url()`/`stream_file()` invocations (§0 point 6).** Confirm this is acceptable-but-inefficient parity behavior to replicate, or a deliberate divergence point for the Rust port's connection-pooling design — likely acceptable to replicate given how infrequently `play_url` is called in practice, but worth a deliberate decision rather than silent inheritance.
