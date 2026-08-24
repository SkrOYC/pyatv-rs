# AirPlay 2 control connection and the MRP-over-AirPlay tunnel: byte-level port specification

Research date: 2026-08-24. Grounded against pyatv commit `b277a4c8222ecdcbaab8a24e3e713ca44765adb4` (`/tmp/pyatv-ref`, tag/release train 0.18.0-era). Every claim below is `path:line-range` against that checkout; nothing here is recalled from training data. Where the four prerequisite reports (`mrp-companion.md`, `airplay-raop-dmap.md`, `hap-pairing-port-spec.md`, `mrp-protobuf-spike.md`, `companion-port-spec.md`) already establish a fact correctly, this document cites them instead of re-deriving it; where they are wrong or incomplete, see [Corrections](#corrections).

This is the ground truth for **Step 1's** two transports: the AirPlay 2 control connection (pair-verify, event channel, data-stream channel, keepalive) that carries a tunneled MRP session, and the direct-TCP MRP transport used on pre-tvOS-15 devices and HomePod. Read `docs/research/mrp-protobuf-spike.md` first for how `ProtocolMessage` extensions are actually encoded/decoded in Rust — this document assumes that layer exists and only describes what bytes go on the wire above and below it.

## 0. Source file inventory

- `pyatv/protocols/airplay/__init__.py` — `setup()`, `scan()`, `AirPlayFeatures`, `AirPlayRemoteControl`, tunnel gating.
- `pyatv/protocols/airplay/ap2_session.py` — `AP2Session`: control connect, pair-verify, event/data channel SETUP, keepalive, teardown.
- `pyatv/protocols/airplay/channels.py` — `EventChannel`, `DataStreamChannel`, `DataHeader`/`DataStreamMessage`, protobuf-in-plist wrapping.
- `pyatv/protocols/airplay/mrp_connection.py` — `AirPlayMrpConnection`, the `AbstractMrpConnection` implementation that rides the data channel.
- `pyatv/protocols/airplay/auth/__init__.py`, `hap.py`, `hap_transient.py` — pair-verify procedures and control-channel key derivation.
- `pyatv/protocols/airplay/utils.py` — `AirPlayFlags`, `is_remote_control_supported`, `get_protocol_version`, `parse_features`, plist codec helpers.
- `pyatv/auth/hap_channel.py` — `AbstractHAPChannel`, `setup_channel` (the generic "open a socket, HAP-encrypt it" primitive shared by event/data channels).
- `pyatv/auth/hap_session.py` — `HAPSession`, the 1024-byte-block ChaCha20-Poly1305 framing used by all three AirPlay-2 sockets.
- `pyatv/support/rtsp.py` — `RtspSession`: SETUP/RECORD/FLUSH/FEEDBACK/TEARDOWN exchange, CSeq correlation.
- `pyatv/support/http.py` — `HttpConnection`, `http_connect`, `send_and_receive`, `receive_processor`/`send_processor` hook points, `decode_bplist_from_body`.
- `pyatv/support/packet.py` — `defpacket`, the struct-based binary packet helper (always big-endian).
- `pyatv/protocols/mrp/connection.py` — `AbstractMrpConnection` (ABC shared by tunnel and direct), `MrpConnection` (direct-TCP variant framing).
- `pyatv/protocols/mrp/protocol.py` — `MrpProtocol.start()`, encryption enable point, heartbeat, request/response correlation.
- `pyatv/protocols/mrp/messages.py` — every outbound message factory, verbatim field values.
- `pyatv/protocols/mrp/auth.py` — `MrpPairSetupProcedure`/`MrpPairVerifyProcedure` (pair-setup/verify carried inside `CryptoPairingMessage`).
- `pyatv/protocols/mrp/player_state.py` — `PlayerState`, `Client`, `PlayerStateManager`.
- `pyatv/protocols/mrp/__init__.py` — the facade: `MrpRemoteControl`, `MrpMetadata`, `MrpPower`, `MrpAudio`, `MrpPushUpdater`, `MrpFeatures`, `create_with_connection`, `setup`, `scan`, `device_info`, `service_info`.
- `pyatv/settings.py` — `InfoSettings` defaults, `MrpTunnel` enum.
- `pyatv/core/protocol.py` — the generic `heartbeater()` coroutine shared by AirPlay's `FEEDBACK` loop and MRP's heartbeat.
- Tests: `tests/protocols/airplay/*`, `tests/protocols/mrp/*`, `tests/fake_device/airplay.py`, `tests/fake_device/mrp.py`, `tests/protocols/airplay/conftest.py`.

---

## 1. The LAN test device, decoded

Test device: Apple TV 4K (3rd gen), tvOS 27.0, AirPlay TXT `features=0x4A7FDFD5,0x3C177FDE`, `flags=0x18644`, AirPlay port 7000, no `_mediaremotetv._tcp` service advertised. Every gating decision in §2–§3 below depends on these values, so decode them once, up front, and refer back.

### 1.1 `features` → `AirPlayFlags`

`parse_features` (`pyatv/protocols/airplay/utils.py:104-118`) parses `"0x<low>,0x<high>"` as `high‖low` and constructs an `AirPlayFlags` int-flag from the 64-bit result:

```
value="4A7FDFD5", upper="3C177FDE" -> combined = 0x3C177FDE4A7FDFD5
```

Bits set in that combined value, cross-referenced against `AirPlayFlags` (`pyatv/protocols/airplay/utils.py:55-98`):

```
SupportsAirPlayVideoV1 (0), SupportsAirPlayScreen (7), SupportsAirPlayAudio (9),
AudioRedundant (11), Authentication_4 (14), MetadataFeatures_0/1/2 (15,16,17),
AudioFormats_0/1/2/3 (18,19,20,21), SupportsLegacyPairing (27),
HasUnifiedAdvertiserInfo (30), SupportsAirPlayVideoPlayQueue (33),
SupportsAirPlayFromCloud (34), SupportsTLS_PSK (35), SupportsUnifiedMediaControl (38),
SupportsBufferedAudio (40), SupportsPTP (41), SupportsScreenMultiCodec (42),
SupportsSystemPairing (43), IsAPValeriaScreenSender (44),
SupportsHKPairingAndAccessControl (46), SupportsCoreUtilsPairingAndEncryption (48),
SupportsAirPlayVideoV2 (49), MetadataFeatures_3 (50),
SupportsSetPeersExtendedMessage (52), SupportsHangdogRemoteControl (58),
SupportsAudioStreamConnectionSetup (59), SupportsAudioMetadataControl (60),
SupportsRFC2198Redundancy (61)
```

Implications, each traced to the code path that reads the bit:

- **`SupportsUnifiedMediaControl` (38) and `SupportsCoreUtilsPairingAndEncryption` (48) are both set** → `get_protocol_version` (`utils.py:241-259`) returns `AirPlayMajorVersion.AirPlayV2` unambiguously (either bit alone is sufficient; both being set removes any doubt for this device). This is the gate that decides whether `AirPlayStream.create_airplay_protocol` (`__init__.py:148-165`) picks `airplayv2.AirPlayV2` over `airplayv1.AirPlayV1` for `play_url`, and it is a *different* check from the MRP-tunnel gate in §2.3.
- **`HasUnifiedAdvertiserInfo` (30) is set** → `setup()` (`__init__.py:344-372`) will synthesize a `Protocol.RAOP` service pointing at the same AirPlay port/credentials if no dedicated `_raop._tcp` service was found for this device, and re-run `raop_setup` against it. A Rust port must replicate this "one mDNS service, two protocol facades" behavior rather than assuming RAOP always has its own advertised service on modern hardware.
- **`SupportsAirPlayVideoV1` (0) and `SupportsAirPlayVideoV2` (49) both set** → `AirPlayFeatures.get_feature` (`__init__.py:65-76`) reports `FeatureName.PlayUrl` as `Available`.
- No bit here decides MRP-tunnel eligibility directly — that check (§2.3) reads `service.properties["model"]` and `service.properties["osvers"]`, TXT keys not given in the problem statement but implied by "Apple TV 4K gen 3" / "tvOS 27.0": `model` will be an `AppleTV\d+,\d+` string and `osvers` will parse to a major version ≥ 13 (`utils.py:175-180`), so `is_remote_control_supported` returns `True` as long as `credentials.type == AuthenticationType.HAP` — i.e. **only after a persisted HAP pairing has been completed**, not with `NO_CREDENTIALS`.

### 1.2 `flags` (`sf`/`flags` TXT key, distinct from `features`/`ft`) → pairing/password requirement

`_get_flags` (`utils.py:44-47`) reads `sf` first, falling back to `flags`; here that is `0x18644`.

```
0x18644 = 0b1_1000_0110_0100_0100_0
PIN_REQUIRED    (0x8)   -> not set
PASSWORD_BIT    (0x80)  -> not set
LEGACY_PAIRING_BIT (0x200) -> SET
```

`get_pairing_requirement` (`utils.py:139-157`) therefore returns `PairingRequirement.Mandatory` (the `LEGACY_PAIRING_BIT` branch), and `is_password_required` (`utils.py:121-136`) returns `False` (`pw` TXT key absent and `PASSWORD_BIT` clear). Net effect for this device: AirPlay pairing is mandatory, no password gate, no forced PIN-required legacy flow. `update_service_details` (`utils.py:262-278`) writes this into `service.pairing` unless `acl=1` or the model matches `UNSUPPORTED_MODELS` (`^Mac\d+,\d+$`, `utils.py:34`), neither of which applies here.

### 1.3 No `_mediaremotetv._tcp` service

pyatv's own gate for disabling direct MRP is a regex on the `SystemBuildVersion` TXT property of an *advertised* `_mediaremotetv._tcp` service: `^(\d+)[A-Z]` with threshold `base >= 19` (`pyatv/protocols/mrp/__init__.py:1025-1048`, reproduced correctly by `mrp-companion.md:26-35`). This test device goes one step further than that heuristic anticipates: **it does not advertise `_mediaremotetv._tcp` at all**, so pyatv's scan phase never even constructs an MRP `MutableService` for it via mDNS browse — `mrp_service_handler` (`__init__.py:1025-1048`) simply never runs. The only way an MRP `SetupData` gets created for this device is `_create_mrp_tunnel_data` (`pyatv/protocols/airplay/__init__.py:234-300`) synthesizing a `Protocol.MRP` `MutableService` (`__init__.py:241-244`, `mrp_service = MutableService(None, Protocol.MRP, core.service.port, {})`) purely from the AirPlay setup path. This is an important empirical confirmation beyond what pyatv's own gate encodes: real tvOS 15+ firmware appears not to advertise the legacy service at all on some builds/networks, not merely to advertise it in a way pyatv chooses to distrust. A Rust port's discovery layer must not treat "no `_mediaremotetv._tcp` observed" as a scan failure — it is the expected, common case, and MRP reachability must be derived entirely from the AirPlay service's tunnel-eligibility check (§2.3), never from MRP's own mDNS presence.

---

## 2. `pyatv/protocols/airplay/__init__.py` — `setup()`/`scan()` and the tunnel decision

### 2.1 `scan()` and `device_info()`

`scan()` (`__init__.py:193-200`) registers one mDNS handler: `_airplay._tcp.local` → `airplay_service_handler` (`__init__.py:180-190`), which builds a `MutableService` carrying the raw TXT `properties` dict unmodified — no TXT-key normalization happens at scan time, it happens later in `device_info()`/`service_info()`. `device_info()` (`__init__.py:203-222`) reads `model` → `DeviceInfo.RAW_MODEL`/`MODEL` (via `lookup_model`), `osvers` → `DeviceInfo.VERSION`, `deviceid` → `DeviceInfo.MAC`, `psi` (preferred) or `pi` → `DeviceInfo.OUTPUT_DEVICE_ID`.

### 2.2 `AirPlayFeatures` and what `FeatureName`s the AirPlay protocol itself registers

`setup()` (`__init__.py:303-336`) always yields exactly one `SetupData(Protocol.AirPlay, ...)` with:

```python
interfaces = {
    Features: AirPlayFeatures(features),
    RemoteControl: AirPlayRemoteControl(stream),
    Stream: stream,
}
...
yield SetupData(
    Protocol.AirPlay, _connect, _close, _device_info, interfaces,
    set([FeatureName.PlayUrl, FeatureName.Stop]),
)
```

`AirPlayFeatures.get_feature` (`__init__.py:65-76`) only ever answers two feature names itself: `PlayUrl` (available iff `SupportsAirPlayVideoV1` or `SupportsAirPlayVideoV2` is set — both are set for the test device, see §1.1) and `Stop` (always `Available`); everything else falls through to `FeatureState.Unavailable`. `AirPlayRemoteControl` (`__init__.py:168-177`) is a one-method shim: its only implemented `RemoteControl` method is `stop()`, which calls `self.stream.stop()` (closes the play-url HTTP connection) — **the tunnel's `MrpRemoteControl` (§9) is a completely separate `RemoteControl` registration under `Protocol.MRP`, not this one**; the `Relayer<RemoteControl>` priority order (`docs/research/pyatv-architecture.md`) is what decides which implementation actually answers a given call when both `Protocol.MRP` and `Protocol.AirPlay` are present.

`AirPlayStream.play_url` (`__init__.py:106-146`) calls `self.core.takeover(RemoteControl)` (`__init__.py:125`) before opening its own RTSP connection — this is a **takeover of the entire `RemoteControl` capability**, not just of AirPlay's own slot in the relayer, meaning while a `play_url` call is in flight, remote-control button presses routed through the facade (including ones that would otherwise go to the MRP tunnel) are blocked until `takeover_release()` runs in the `finally` block (`__init__.py:138-139`). A Rust `FacadeAppleTV` must replicate this exclusive-lock semantic exactly, not just merge the two `RemoteControl` registrations.

### 2.3 The MRP tunnel gate — confirmed exact, line-for-line

```python
mrp_tunnel = core.settings.protocols.airplay.mrp_tunnel

if mrp_tunnel == MrpTunnel.Disable:
    _LOGGER.debug("Remote control tunnel disabled by setting")
elif mrp_tunnel == MrpTunnel.Force:
    _LOGGER.debug("Remote control channel is supported (forced)")
    yield _create_mrp_tunnel_data(core, credentials)
elif not is_remote_control_supported(core.service, credentials):
    _LOGGER.debug("Remote control not supported by device")
elif credentials.type not in [AuthenticationType.HAP, AuthenticationType.Transient]:
    _LOGGER.debug("%s not supported by remote control channel", credentials.type)
else:
    _LOGGER.debug("Remote control channel is supported")
    yield _create_mrp_tunnel_data(core, credentials)
```

`pyatv/protocols/airplay/__init__.py:374-387`. `MrpTunnel` (`pyatv/settings.py:62-72`) has three values: `Auto` (default; go through the two `elif` checks), `Force` (skip both checks, always tunnel), `Disable` (never tunnel, even direct MRP scan results are irrelevant to this path — direct MRP, if reachable, is set up entirely independently via `pyatv/protocols/mrp/__init__.py:setup()`). `credentials` here is `extract_credentials(core.service)` (`__init__.py:311`, defined `pyatv/protocols/airplay/auth/__init__.py:120-133`): if the service has a persisted `credentials` string, parse it; otherwise, if `SupportsSystemPairing` or `SupportsCoreUtilsPairingAndEncryption` is set in `features` (both would make `TRANSIENT_CREDENTIALS` the answer — note `SupportsCoreUtilsPairingAndEncryption` **is** set for the test device, §1.1, so a fresh/unpaired connection attempt to this device would get `TRANSIENT_CREDENTIALS` rather than `NO_CREDENTIALS`, which then fails the `credentials.type not in [HAP, Transient]` check trivially since `Transient` is allowed — but `is_remote_control_supported` (§1.1) additionally requires `credentials.type == AuthenticationType.HAP` specifically for `AppleTV*` models, only allowing `Transient` for `AudioAccessory*` (HomePod) models (`utils.py:171-180`), so an unpaired attempt against this Apple TV still fails the tunnel gate and only a completed HAP pairing unlocks it).

`is_remote_control_supported` (`utils.py:165-180`, quoted in full because every branch matters):

```python
def is_remote_control_supported(
    service: BaseService, credentials: HapCredentials
) -> bool:
    """Return if device supports remote control tunneling."""
    model = service.properties.get("model", "")

    # HomePod supports remote control but only with transient credentials
    if model.startswith("AudioAccessory"):
        return credentials == TRANSIENT_CREDENTIALS

    if not model.startswith("AppleTV"):
        return False

    # tvOS must be at least version 13 and HAP credentials are required by Apple TV
    version = service.properties.get("osvers", "0.0").split(".", maxsplit=1)[0]
    return float(version) >= 13.0 and credentials.type == AuthenticationType.HAP
```

pyatv's own source-level comment marks this whole function `# TODO: It is not fully understood how to determine if a device supports remote control over AirPlay, so this method makes a pure guess` (`utils.py:160-164`) — this is a heuristic pyatv itself does not trust as spec-accurate, only as empirically-workable; a Rust port inherits the same uncertainty and should treat it as "replicate this exact guess," not as ground truth about the protocol.

### 2.4 `_create_mrp_tunnel_data` — the glue between AirPlay and MRP

`__init__.py:234-300`, reproduced with every step named:

1. Construct `AP2Session(address, core.service.port, credentials, core.settings.info)` (`__init__.py:235-237`) — **the control port is the AirPlay service's own port** (7000 for this device), not a separately-advertised port.
2. Ensure a `Protocol.MRP` service exists in `core.config` (synthesize an empty one if absent, `__init__.py:241-244`, as discussed in §1.3).
3. Call `mrp.create_with_connection(...)` (`__init__.py:246-266`, detailed in §9) with a **fresh `Core`** whose `service` is the synthesized MRP service but whose `state_dispatcher` is `core.state_dispatcher.create_copy(Protocol.MRP)` — state updates from the tunnel are attributed to `Protocol.MRP`, not `Protocol.AirPlay`, even though the transport is an AirPlay socket. Pass `requires_heatbeat=False` (`__init__.py:265`, sic — that is pyatv's actual spelling of the parameter) because the AirPlay control channel's own `FEEDBACK` heartbeat (§3.6) already keeps the underlying TCP connection alive; MRP's own 30-second heartbeat (§8.5) would be redundant and is disabled for the tunnel path specifically.
4. `_connect_rc()` (`__init__.py:268-285`): `await session.connect()` (control connect + pair-verify, §3.2) → `await session.setup_remote_control()` (event + data channel SETUP, §3.3–§3.5) → `session.start_keep_alive(core.device_listener)` (§3.6) → `await mrp_connect()` (the MRP protocol's own `start()`, §8, run **over** the now-open data channel). A `470` HTTP status from any step is translated to `InvalidCredentialsError`; any other exception becomes a generic `ProtocolError("Failed to set up remote control channel")`.
5. `_close_rc()` (`__init__.py:287-291`): closes the MRP protocol first, then stops the `AP2Session` (which cancels the feedback task and closes the control connection plus every channel transport, §3.7).

The returned `SetupData` (`__init__.py:293-300`) still uses `Protocol.MRP` as its protocol tag and forwards `mrp_device_info`/`mrp_interfaces`/`mrp_features` straight through from `create_with_connection` — from the facade's point of view, a tunneled MRP session is indistinguishable from a direct one except in how its `_connect`/`_close` closures are wired.

---

## 3. `AP2Session` (`pyatv/protocols/airplay/ap2_session.py`) — bring-up sequence

### 3.1 Constants

```python
FEEDBACK_INTERVAL = 2.0  # Seconds — "This is what iOS uses"

EVENTS_SALT = "Events-Salt"
EVENTS_WRITE_INFO = "Events-Write-Encryption-Key"
EVENTS_READ_INFO = "Events-Read-Encryption-Key"

DATASTREAM_SALT = "DataStream-Salt"  # seed must be appended
DATASTREAM_OUTPUT_INFO = "DataStream-Output-Encryption-Key"
DATASTREAM_INPUT_INFO = "DataStream-Input-Encryption-Key"
```

`ap2_session.py:28-37`. Control-channel salts (`CONTROL_SALT`/`CONTROL_OUTPUT_INFO`/`CONTROL_INPUT_INFO`) live in `pyatv/protocols/airplay/auth/__init__.py:36-38`, not here — see §3.2.

### 3.2 `connect()` — control connection + pair-verify

```python
async def connect(self) -> None:
    self.connection = await http_connect(self._address, self._control_port)
    self.verifier = await verify_connection(self._credentials, self.connection)
    self.rtsp = RtspSession(self.connection)
```

`ap2_session.py:62-73`. `verify_connection` (`pyatv/protocols/airplay/auth/__init__.py:100-117`):

```python
async def verify_connection(credentials, connection) -> PairVerifyProcedure:
    verifier = pair_verify(credentials, connection)
    has_encryption_keys = await verifier.verify_credentials()
    if has_encryption_keys:
        output_key, input_key = verifier.encryption_keys(
            CONTROL_SALT, CONTROL_OUTPUT_INFO, CONTROL_INPUT_INFO
        )
        session = HAPSession()
        session.enable(output_key, input_key)
        connection.receive_processor = session.decrypt
        connection.send_processor = session.encrypt
    return verifier
```

`pair_verify()` (`auth/__init__.py:78-97`) dispatches on `credentials.type`: `Null` → `NullPairVerifyProcedure` (no encryption, dead path for the modern tunnel), `Legacy` → `AirPlayLegacyPairVerifyProcedure`, `HAP` → `AirPlayHapPairVerifyProcedure`, anything else (`Transient`/default) → `AirPlayHapTransientPairVerifyProcedure`. For this test device (HAP credentials required, §2.3), the `AirPlayHapPairVerifyProcedure` path runs (`auth/hap.py:97-150`):

- **Headers** (`auth/hap.py:20-25`): `User-Agent: AirPlay/320.20`, `Connection: keep-alive`, `X-Apple-HKP: 3`, `Content-Type: application/octet-stream` — note this is a **different** `User-Agent` string from the one used later for RTSP `SETUP`/`RECORD`/`FEEDBACK` exchanges (`AirPlay/550.10`, §3.3/§3.6/`pyatv/support/rtsp.py:22`). The transient variant (`auth/hap_transient.py:23-28`) uses the same `User-Agent`/`Connection`/`Content-Type` but `X-Apple-HKP: 4` instead of `3` — a Rust client must set this header per credential type, not hardcode it.
- **Path**: `POST /pair-verify` on the same TCP connection used for everything else (control connection is multiplexed: pairing, RTSP `SETUP`/`RECORD`, and `FEEDBACK` all share one socket, only encryption state changes mid-stream).
- **Body**: raw HAP TLV8 (`hap_tlv8.write_tlv`), M1 `{SeqNo: 0x01, PublicKey: <client X25519 pubkey>}`, then M3 `{SeqNo: 0x03, EncryptedData: <...>}` — standard HAP pair-verify per `docs/research/hap-pairing-port-spec.md` §2.3/§9.3; do not re-derive here.
- On success, `encryption_keys(CONTROL_SALT, CONTROL_OUTPUT_INFO, CONTROL_INPUT_INFO)` returns `(output_key, input_key)` fed into a fresh `HAPSession`, which is then wired as `connection.receive_processor`/`send_processor` (`http.py:339-350`) — **from this point on, every byte read from or written to the control socket is transparently HAP-block-encrypted** (§4), including the RTSP exchanges that follow. `RtspSession` itself (§3.3) has no awareness of encryption; it operates purely on plaintext request/response objects, with `HttpConnection` doing the encrypt/decrypt via those processor hooks.

### 3.3 `setup_remote_control()` — event channel, RECORD, data channel, in that exact order

```python
async def setup_remote_control(self) -> None:
    if self.connection is None or self.rtsp is None:
        raise exceptions.InvalidStateError("not connected to remote")
    await self._setup_event_channel(self.connection.remote_ip)
    await self.rtsp.record()
    await self._setup_data_channel(self.connection.remote_ip)
```

`ap2_session.py:75-82`. Both `_setup_event_channel` and `_setup_data_channel` issue an RTSP `SETUP` (`self.rtsp.setup(body=...)`, `ap2_session.py:110-113`) on the **already-encrypted control connection**; `RECORD` (`self.rtsp.record()`, no headers/body) is sent once, between the two `SETUP`s, not after both.

`RtspSession.exchange()` (`pyatv/support/rtsp.py:254-330`) is the shared machinery for every RTSP-style verb: it allocates a monotonically increasing `CSeq` (`self.cseq`, starts at 0, `rtsp.py:86`), attaches `DACP-ID`/`Active-Remote`/`Client-Instance` headers derived from per-session random values (`session_id = randrange(2**32)`, `dacp_id = f"{randrange(2**64):X}"`, `active_remote = randrange(2**32)`, `rtsp.py:87-89` — these are AirPlay-1-lineage DACP identifiers, largely irrelevant to the remote-control tunnel itself but sent on every request regardless), serializes a `dict` body as a binary plist automatically (`rtsp.py:284-289`, `Content-Type: application/x-apple-binary-plist`), sends via `HttpConnection.send_and_receive` with `USER_AGENT = "AirPlay/550.10"` and `protocol="RTSP/1.0"`, then correlates the response by matching the returned `CSeq` header against `self.requests` (an `asyncio.Event`-keyed dict) with a **4-second timeout** (`async_timeout(4)`, `rtsp.py:316`) — a Rust port needs the same CSeq-correlation table since responses are not guaranteed to arrive in request order over one socket.

### 3.4 Event channel `SETUP` — exact plist body and the read/write swap

```python
resp = await self._setup(
    {
        "isRemoteControlOnly": True,
        "osName": self._info.os_name,
        "sourceVersion": "550.10",
        "timingProtocol": "None",
        "model": self._info.model,
        "deviceID": self._info.device_id,
        "osVersion": self._info.os_version,
        "osBuildVersion": self._info.os_build,
        "macAddress": self._info.mac,
        "sessionUUID": str(uuid4()).upper(),
        "name": self._info.name,
    }
)
event_port = resp["eventPort"]
```

`ap2_session.py:119-135`. This is the **complete** key set — no other keys are sent in this body. `self._info` is `InfoSettings` (`pyatv/settings.py:78-96`), whose defaults (used unless the application overrides them) are:

```python
DEFAULT_NAME = "pyatv"
DEFUALT_MAC = "02:70:79:61:74:76"        # locally-administered (02) + "pyatv" in hex
DEFAULT_DEVICE_ID = "FF:70:79:61:74:76"  # 0xFF + "pyatv" in hex
DEFAULT_MODEL = "iPhone10,6"
DEFAULT_OS_NAME = "iPhone OS"
DEFAULT_OS_BUILD = "18G82"
DEFAULT_OS_VERSION = "14.7.1"
```

`pyatv/settings.py:36-42,78-88`. `device_id`/`mac` are **static defaults, not per-session-generated** (unlike `sessionUUID`, which is a fresh `uuid4()` uppercased on every `setup_remote_control()` call, `ap2_session.py:130`) — a Rust port should mirror `device_id`/`mac`/`model`/`os_*` as configuration-time constants (with the same defaults, for behavioral parity against devices that might allowlist by MAC/deviceID) and only randomize `sessionUUID` per connection. `sourceVersion` and `timingProtocol` are **hardcoded literals** (`"550.10"`, `"None"`), not derived from `InfoSettings` at all.

Response: `eventPort` (int, TCP port the client dials **out to**, despite the encryption-role naming below implying the opposite direction — see the code comment). Event channel bring-up:

```python
# Event channel is not used so we don't care about it (must be set up though).
#
# Note: Read/Write info reversed here as connection originates from receiver!
transport, _ = await setup_channel(
    EventChannel, self.verifier, address, event_port,
    EVENTS_SALT, EVENTS_READ_INFO, EVENTS_WRITE_INFO,
)
```

`ap2_session.py:137-149`. `setup_channel`'s signature is `(factory, verifier, address, port, salt, output_info, input_info)` (`pyatv/auth/hap_channel.py:79-96`) — this call passes `EVENTS_READ_INFO` where `output_info` is expected and `EVENTS_WRITE_INFO` where `input_info` is expected, i.e. **the two info strings are swapped relative to every other channel's call shape** in this file. `docs/research/hap-pairing-port-spec.md:544` pins this precisely; do not re-derive the swap direction independently, replicate the call site's literal argument order. **The channel itself is functionally a no-op**: `EventChannel.handle_received` (`channels.py:63-97`) parses whatever RTSP-shaped request arrives and answers every single one with a bare `200 OK` (`Content-Length: 0`, `Audio-Latency: 0`, echoing `Server`/`CSeq` headers back if present) — no payload is ever interpreted. A Rust port must still open this socket, complete its HAP framing, and answer requests with `200 OK`, or the device will consider the tunnel misbehaving even though no useful data flows over it.

### 3.5 Data-stream channel `SETUP` — exact plist body, the seed-salted key derivation

```python
seed = randint(0, 2**64)
resp = await self._setup(
    {
        "streams": [
            {
                "controlType": 2,
                "channelID": str(uuid4()).upper(),
                "seed": seed,
                "clientUUID": str(uuid4()).upper(),
                "type": 130,
                "wantsDedicatedSocket": True,
                "clientTypeUUID": "1910A70F-DBC0-4242-AF95-115DB30604E1",
            }
        ]
    }
)
data_port = resp["streams"][0]["dataPort"]
```

`ap2_session.py:151-174`. `seed` is Python's `random.randint` (**not a CSPRNG** — `hap-pairing-port-spec.md:546` flags this explicitly; it has no secrecy requirement, only per-session uniqueness, since it is sent in cleartext as an ordinary plist integer). `channelID` and `clientUUID` are two **independently generated** fresh UUIDs (not the same value, and neither reused from the event channel's `sessionUUID`). `clientTypeUUID` is a **fixed literal constant** — `"1910A70F-DBC0-4242-AF95-115DB30604E1"` — that identifies this stream as "the remote-control data stream" to the receiver; do not treat it as configurable. `controlType: 2` and `type: 130` are likewise fixed literals whose semantics are opaque (never decoded elsewhere in pyatv) but must be sent byte-identical.

Data channel bring-up:

```python
transport, protocol = await setup_channel(
    DataStreamChannel, self.verifier, address, data_port,
    DATASTREAM_SALT + str(seed), DATASTREAM_OUTPUT_INFO, DATASTREAM_INPUT_INFO,
)
```

`ap2_session.py:176-184`. **Unswapped** call order (`output_info`, then `input_info`, matching the control channel's own convention) — this channel's socket is opened by the controller (client dials out), matching the "normal" direction, unlike the event channel. The salt is **not** the bare `"DataStream-Salt"` constant — it is that string concatenated with the decimal string representation of `seed` (Python `str(int)`, e.g. `seed=12345` → salt=`"DataStream-Salt12345"`). Both `output_info`/`input_info` are the fixed strings from §3.1 with no seed appended. `self.data_channel` is set to the resulting `DataStreamChannel` protocol instance (`ap2_session.py:187`) — this is what `AirPlayMrpConnection.connect()` (§7) later grabs and starts forwarding MRP protobufs over.

### 3.6 Keepalive — `FEEDBACK` every 2 seconds

```python
async def _send_feedback(message: Optional[Any]) -> None:
    if self.rtsp:
        await self.rtsp.feedback()

self._feedback_task = asyncio.ensure_future(
    heartbeater(
        name=f"AirPlay:{self._address}",
        sender_func=_send_feedback,
        finish_func=_finish_func,
        failure_func=_failure_func,
        interval=FEEDBACK_INTERVAL,
    )
)
```

`ap2_session.py:84-108`. `RtspSession.feedback()` (`pyatv/support/rtsp.py:246-248`) is `POST /feedback` (no body, no special headers beyond the standard `exchange()` ones) — **not** an RTSP `SET_PARAMETER` verb despite what a superficial reading of "feedback" might suggest, and not the same URI form as `SETUP`/`RECORD` (those go to `self.uri`, an `rtsp://…` URI; `/feedback` is a bare path). `heartbeater()` (`pyatv/core/protocol.py:35-76`) is the shared generic loop: sleep `interval` seconds (2.0 here), call `sender_func`, on any exception increment `attempts` and retry immediately (no sleep) up to `HEARTBEAT_RETRIES=1` extra attempt (i.e. two total tries per period) before calling `failure_func(exc)` and terminating the loop — `failure_func` here is a lambda invoking `device_listener.listener.connection_lost(exc)` (`ap2_session.py:90-91`), tearing down the whole facade connection, not just the AirPlay leg. Losing this heartbeat is fatal to the tunnel: `docs/research/mrp-companion.md:315` cites PR #1263's own description that receivers drop the tunnel after roughly 30 seconds without one — a Rust port must not skip or rate-limit this independently of pyatv's cadence.

### 3.7 Teardown

```python
def stop(self) -> Set[asyncio.Task]:
    tasks = set()
    if self._feedback_task:
        self._feedback_task.cancel()
        tasks.add(self._feedback_task)
        self._feedback_task = None
    if self.connection:
        self.connection.close()
        self.connection = None
    for channel in self._channels:
        channel.close()
    return tasks
```

`ap2_session.py:189-201`. No explicit RTSP `TEARDOWN` is sent for the remote-control tunnel (that verb exists on `RtspSession` — `rtsp.py:250-252` — but is never called from `AP2Session`); the tunnel is torn down purely by closing sockets. Returned cancelled tasks are collected so the caller (`_close_rc`, §2.4) can await them before considering the protocol fully stopped.

---

## 4. HAP framing shared by all three AirPlay-2 sockets

`docs/research/hap-pairing-port-spec.md` §4.0/§5.2 already establishes, correctly and in more depth than needed here, that **`HAPSession`/`AbstractHAPChannel` is exclusively an AirPlay concept** — MRP direct and Companion never use it. Recap only the wire shape, since this document's §3–§7 depend on it directly:

```python
FRAME_LENGTH = 1024      # HAP spec §5.2.2 (Release R1)
AUTH_TAG_LENGTH = 16

def encrypt(self, data: bytes) -> bytes:
    output = b""
    while data:
        frame, data = data[:FRAME_LENGTH], data[FRAME_LENGTH:]
        length = int.to_bytes(len(frame), 2, byteorder="little")
        frame = self.chacha20.encrypt(frame, aad=length)   # AEAD, AAD = the 2 length bytes
        output += length + frame
    return output
```

`pyatv/auth/hap_session.py:53-66`. Wire layout per block: `u16 LE plaintext-length (2 bytes, sent in clear, also = AAD) ‖ ChaCha20-Poly1305(plaintext) (≤1024 bytes) ‖ 16-byte Poly1305 tag`. Decrypt (`hap_session.py:31-51`) buffers partial reads: peek 2 length bytes, wait for `length + 16` more bytes, decrypt, repeat. `self.chacha20` is a `Chacha20Cipher` (`pyatv/support/chacha20.py`) constructed with the **default `nonce_length=8`** (4-zero-byte prefix + 8-byte LE auto-incrementing counter, independent per direction) — same nonce-construction class MRP direct uses (`Chacha20Cipher8byteNonce`), but a materially different frame/AAD contract (§8.2 below spells out MRP's, which has neither the 1024-byte cap nor any AAD at all).

`AbstractHAPChannel` (`pyatv/auth/hap_channel.py:17-76`) is the `asyncio.Protocol` wrapper: `data_received` decrypts through `self.session` and appends to `self.buffer` before calling the subclass's `handle_received()`; `send(data)` encrypts through `self.session` and writes to the transport. `setup_channel` (`hap_channel.py:79-96`) derives `(out_key, in_key)` from the verifier, opens a new `loop.create_connection`, and constructs the channel class with those keys — this is the one function that turns "I have a salt/info pair and an already-completed pair-verify" into "I have a live encrypted socket," and both `EventChannel` and `DataStreamChannel` are built through it identically; only the constructor arguments (salt/info/port/factory) differ per §3.4/§3.5.

---

## 5. `pyatv/protocols/airplay/channels.py` — data-stream framing in full

### 5.1 `DataHeader` — the 32-byte frame header

```python
DataHeader = defpacket(
    "DataFrame", size="I", message_type="12s", command="4s", seqno="Q", padding="I"
)
```

`channels.py:29-31`. `defpacket` (`pyatv/support/packet.py:7-35`) always prefixes the `struct` format string with `">"` — **every field is big-endian**, including `size` and `seqno`. Field-by-field:

| Field | `struct` code | Size | Semantics |
|---|---|---|---|
| `size` | `I` | 4 | Total frame size **including this 32-byte header**: `DataHeader.length + len(payload)` (`channels.py:127-128`) |
| `message_type` | `12s` | 12 | ASCII tag, zero-padded to 12 bytes, e.g. `b"sync" + 8*b"\x00"` or `b"rply" + 8*b"\x00"` |
| `command` | `4s` | 4 | `b"comm"` for outbound MRP payloads (`channels.py:272`), `4*b"\x00"` for replies (`channels.py:158`) |
| `seqno` | `Q` | 8 | Echoed verbatim in a reply to the same value the request carried |
| `padding` | `I` | 4 | Always `DATA_HEADER_PADDING = 0x00000000` (`channels.py:27`) |

`DataHeader.length == struct.calcsize(">I12s4sQI") == 32` bytes. Payload (a binary plist, §5.2) follows the header directly with no gap.

### 5.2 `DataStreamMessage` and the OPACK/plist payload discrimination

There is **no OPACK anywhere in this channel** — the payload framing the task brief flags as "OPACK-vs-protobuf discrimination" does not exist as such; the discrimination is **binary-plist envelope vs. raw protobuf bytes nested inside one plist field**, not a choice between two top-level codecs. `encode_payload`/`decode_payload` (`channels.py:137-140,190-196`) call `encode_plist_body`/`decode_plist_body` (`pyatv/protocols/airplay/utils.py:183-198`), which are thin wrappers over `plistlib.dumps(data, fmt=FMT_BINARY)`/`plistlib.loads(...)` — Apple `bplist00`, the same format used for the RTSP `SETUP` bodies in §3.4/§3.5, not OPACK (OPACK is exclusively a Companion-protocol concept, `docs/research/mrp-companion.md` §4.5; conflating the two would be a real interop bug in a Rust port).

```python
class DataStreamMessage(NamedTuple):
    message_type: bytes
    command: bytes
    seqno: int
    padding: int
    payload: bytes
```

`channels.py:110-117`. `encode_message` (`channels.py:123-135`) packs the header (computing `size` from `DataHeader.length + len(payload)`) then appends `payload` raw.

### 5.3 The MRP-in-data-stream wrapping — exact plist shape

Outbound (`DataStreamChannel.send_protobuf`, `channels.py:266-280`):

```python
def send_protobuf(self, message: protobuf.ProtocolMessage) -> None:
    self.send(
        self.encode_message(
            DataStreamMessage(
                b"sync" + 8 * b"\x00",
                b"comm",
                self.send_seqno,
                DATA_HEADER_PADDING,
                self.encode_payload(
                    {"params": {"data": self.encode_protobufs([message])}}
                ),
            )
        )
    )
```

The plist payload's top-level shape is exactly `{"params": {"data": <bytes>}}` — a two-level dict, `params` → `data`, where `data` is a single binary-plist `<data>` element holding **concatenated, individually variant-length-prefixed serialized `ProtocolMessage`s** (`encode_protobufs`, `channels.py:143-151`):

```python
@staticmethod
def encode_protobufs(protobuf_messages: List[protobuf.ProtocolMessage]) -> bytes:
    serialized_messages = []
    for protobuf_message in protobuf_messages:
        serialized_message = protobuf_message.SerializeToString()
        serialized_length = write_variant(len(serialized_message))
        serialized_messages.append(serialized_length)
        serialized_messages.append(serialized_message)
    return b"".join(serialized_messages)
```

In practice pyatv only ever calls this with a **single-element list** (`send_protobuf` always wraps exactly one message, `channels.py:275-277`) — the multi-message plumbing exists in the encoder but `MrpTransport`-level callers never batch. `message_type` is `b"sync" + 8 zero bytes` and `command` is `b"comm"` for every outbound MRP frame; `seqno` is `self.send_seqno`, set **once** at channel construction from `randrange(0x100000000, 0x1FFFFFFFF)` (`channels.py:235`) and **never incremented** on subsequent sends — every outbound MRP-carrying frame from a given tunnel session uses the identical `seqno` value (this is confirmed pyatv behavior, not a documentation slip; see [Corrections](#corrections) for why the earlier research report's phrasing of this as an open question is now closed).

Inbound (`DataStreamChannel.handle_received`/`_process_payload`, `channels.py:241-264`):

```python
def handle_received(self) -> None:
    while len(self.buffer) >= DataHeader.length:
        message, _, self.buffer = self.decode_message(self.buffer)
        if not message:
            break
        payload = self.decode_payload(message.payload)
        if payload:
            self._process_payload(payload)
        if message.message_type.startswith(b"sync"):
            self.send(self.encode_reply(message.seqno))

def _process_payload(self, message) -> None:
    data = message.get("params", {}).get("data")
    if data is None:
        return
    for pb_msg in self.decode_protobufs(data):
        self.listener.handle_protobuf(pb_msg)
```

Reply/ack rule: **any** incoming frame whose `message_type` starts with `b"sync"` (regardless of whether it decoded to a usable payload) gets an `encode_reply(seqno)` sent back — `channels.py:153-163`:

```python
def encode_reply(self, seqno: int) -> bytes:
    return self.encode_message(
        DataStreamMessage(b"rply" + 8 * b"\x00", 4 * b"\x00", seqno, DATA_HEADER_PADDING, b"")
    )
```

`b"rply" + 8 zero bytes`, `command = 4 zero bytes`, the **same `seqno` the incoming `sync` frame carried** (not the channel's own `send_seqno`), zero-length payload (so `size == 32`, header only). This is the data-channel-level keepalive/ack, distinct from both the AirPlay `FEEDBACK` heartbeat (§3.6, RTSP-level, every 2s) and MRP's own heartbeat (§8.5, only enabled for direct connections). A Rust port's data-channel actor must answer every `sync`-prefixed frame this way regardless of whether it understood the payload, or the receiver will consider the channel unresponsive.

### 5.4 `decode_protobufs` — the `ConfigureConnectionMessage` unprefixed-message heuristic

```python
while data:
    if data[0] == 0x8:
        message, data = data, b""
    else:
        length, raw = read_variant(data)
        if len(raw) < length:
            break
        message, data = raw[:length], raw[length:]
    assert message[0] == 0x8
    pb_msg = protobuf.ProtocolMessage()
    pb_msg.ParseFromString(message)
    pb_messages.append(pb_msg)
```

`channels.py:198-226`, with the source comment reproduced in full because the reasoning matters for anyone re-implementing it: every `ProtocolMessage` must set `type` (field 1), whose wire tag is `0x08` (field number 1, wire type 0/varint); the minimum real message is at least ~40 bytes, so a leading `0x08` byte can never be confused with a valid *length* varint in this position — the heuristic is "if the first byte is exactly `0x08`, treat the rest of the buffer as one unprefixed message; otherwise read a variant length prefix first." pyatv's own comment states this is known to happen specifically for `ConfigureConnectionMessage` (`ProtocolMessage.Type.CONFIGURE_CONNECTION_MESSAGE = 120`, extension field 94 per `mrp-protobuf-spike.md:33`) — no other message type is called out, but the code applies the check to every incoming buffer unconditionally, so a Rust decoder must apply it the same way (per-message, not type-gated) rather than special-casing only `ConfigureConnectionMessage` by type. Both branches assert `message[0] == 0x8` after the fact as a sanity check that would raise (and be swallowed by the enclosing `try/except Exception: _LOGGER.exception(...)`, `channels.py:202,224-225`) on malformed input — a Rust port should surface this as a typed decode error rather than silently dropping the frame, since pyatv's own swallow-and-log behavior here is a debuggability liability worth improving on, not a wire-format requirement to replicate.

### 5.5 Buffering

`BaseDataStreamChannel`/`DataStreamChannel` inherit `AbstractHAPChannel.data_received` (§4) for the encryption boundary; above that, `handle_received` (§5.3) loops `while len(self.buffer) >= DataHeader.length`, decoding one `DataHeader`-plus-payload frame per iteration via `decode_message` (`channels.py:165-188`), which itself re-checks `len(data) < header.size` and returns `(None, b"", data)` if the full frame hasn't arrived yet — standard incremental TCP-stream reassembly, no surprises, but note it operates on **already-HAP-decrypted plaintext** (the 1024-byte HAP block boundary from §4 has no relationship to the `DataHeader` frame boundary; a single `DataHeader`+payload frame can span multiple HAP blocks, and one HAP block's plaintext can contain multiple complete `DataHeader` frames plus a partial one).

---

## 6. `EventChannel` — full behavior (already summarized in §3.4, structural detail here)

`BaseEventChannel` (`channels.py:34-57`) reuses the RTSP/HTTP request/response parser (`pyatv/support/http.py`'s `parse_request`/`format_response` etc.) rather than the `DataHeader` binary framing — the event channel speaks the **same RTSP-over-one-socket text protocol** as the control connection, just HAP-encrypted with its own (swapped, §3.4) key pair, and with the client acting as **server** (answering requests, not sending them) since the receiver is the one issuing requests on this socket. `EventChannel.handle_received` (`channels.py:63-97`) is a `while self.buffer:` loop parsing one request at a time via `parse_request`, breaking out (not erroring) if a request is incomplete (`request is None`), and unconditionally replying `200 OK` with `Content-Length: 0`, `Audio-Latency: 0`, and pass-through `Server`/`CSeq` headers when present in the request. Any exception during a single iteration is caught and logged (`except Exception: _LOGGER.exception(...)`, `channels.py:96-97`) without tearing down the channel — a malformed request from the device is tolerated, not fatal.

---

## 7. `AirPlayMrpConnection` vs `MrpConnection` — the `AbstractMrpConnection` seam

`pyatv/protocols/mrp/connection.py:17-39` defines the shared ABC both transports implement:

```python
class AbstractMrpConnection(asyncio.Protocol, StateProducer):
    async def connect(self) -> None: ...
    def enable_encryption(self, output_key: bytes, input_key: bytes) -> None: ...
    @property
    def connected(self) -> bool: ...
    def close(self) -> None: ...
    def send(self, message: protobuf.ProtocolMessage) -> None: ...
```

`MrpConnection` (direct-TCP, §8.1) implements every method with real socket/encryption logic. `AirPlayMrpConnection` (`pyatv/protocols/airplay/mrp_connection.py:17-76`) implements the same five members almost entirely as **pass-throughs to the already-open `DataStreamChannel`**:

```python
class AirPlayMrpConnection(AbstractMrpConnection, DataStreamListener):
    def __init__(self, session: AP2Session, device_listener=None):
        self.session = session
        self.data_channel: Optional[DataStreamChannel] = None
        self.device_listener = device_listener

    async def connect(self) -> None:
        if self.session.data_channel is None:
            raise exceptions.InvalidStateError("remote control channel not connected")
        self.data_channel = self.session.data_channel
        self.data_channel.listener = self

    def enable_encryption(self, output_key: bytes, input_key: bytes) -> None:
        pass   # already HAP-encrypted at the data-channel level; MRP's own pair-verify is skipped

    @property
    def connected(self) -> bool:
        return True   # always — no notion of "not yet connected" once constructed

    def close(self) -> None:
        if self.data_channel is not None:
            self.data_channel.close()
            self.data_channel = None

    def send(self, message: protobuf.ProtocolMessage) -> None:
        if self.data_channel is not None:
            self.data_channel.send_protobuf(message)

    def handle_protobuf(self, message: protobuf.ProtocolMessage) -> None:
        self.listener.message_received(message, None)

    def handle_connection_lost(self, exc: Optional[Exception]) -> None:
        if self.device_listener:
            if exc is None:
                self.device_listener.listener.connection_closed()
            else:
                self.device_listener.listener.connection_lost(exc)
```

Three facts fall directly out of this that a Rust `MrpTransport` trait design must accommodate:

1. **`connect()` requires the data channel to already be open** — `AirPlayMrpConnection.connect()` is called from `MrpProtocol.start()` (§8.4) *after* `_create_mrp_tunnel_data`'s `_connect_rc()` has already run `session.setup_remote_control()` (§3.3) to completion. The ordering dependency is enforced by the caller (`__init__.py:268-284`, §2.4), not by the connection object itself — `AirPlayMrpConnection.connect()` only raises `InvalidStateError` if that ordering was violated, it does not perform any of the tunnel setup itself.
2. **`enable_encryption` is a documented no-op for the tunnel** — MRP's own pair-verify handshake (`CryptoPairingMessage`, §8.3) still runs its full TLV8 exchange over the tunnel (the device still expects to see it, and `MrpProtocol._enable_encryption` (`protocol.py:207-221`) is unconditional on the credentials being present, transport-agnostic), but the derived keys are simply **discarded** rather than installed, because the transport is already end-to-end encrypted at the AirPlay HAP layer (§4). This means MRP protobuf bytes traveling through the data channel are **never additionally ChaCha20-Poly1305-sealed at the MRP layer** for the tunnel path — only the outer HAP block encryption applies. A Rust port must not attempt to layer MRP-level encryption on top of the tunnel; it must run the pair-verify exchange (for protocol-state-machine parity with the device, which expects to see it) and then explicitly discard the resulting keys, exactly mirroring this no-op.
3. **`connected` is hardcoded `True`** — there is no tunnel-specific notion of a connection being torn down and needing reconnection at this layer; failure is instead signaled asynchronously via `handle_connection_lost`/`connection_lost` callbacks, which the `MrpProtocol`'s listener plumbing (inherited from `StateProducer`) and the outer `device_listener` both observe.

### 7.1 Recommended Rust `MrpTransport` trait shape

Given the above, a Rust port should define a `MrpTransport` trait mirroring `AbstractMrpConnection` at the **message** level (`send(ProtocolMessage)`, an inbound message stream/callback, `close()`), with two implementations:

- `DirectMrpTransport` — owns a raw TCP socket, does its own variant-length framing (§8.1) and its own MRP-level ChaCha20-Poly1305 (§8.2), and actually installs the pair-verify-derived keys.
- `TunnelMrpTransport` — wraps a handle to an already-running AirPlay `DataStreamChannel` actor (itself owned by the `AP2Session`), does no additional framing beyond what `send_protobuf`/`handle_protobuf` already provide (§5.3), and **discards** pair-verify keys rather than installing them.

Everything above this trait — `MrpProtocol`'s `start()` sequence, `send_and_receive` correlation, `PlayerStateManager`, the facade (`MrpRemoteControl`/`MrpMetadata`/`MrpPower`/`MrpAudio`/`MrpPushUpdater`/`MrpFeatures`) — is 100% transport-agnostic in pyatv (`create_with_connection`, §9, is called identically by both `pyatv/protocols/mrp/__init__.py:setup()` for direct connections and `pyatv/protocols/airplay/__init__.py:_create_mrp_tunnel_data` for the tunnel, differing only in which `AbstractMrpConnection` implementation and `requires_heatbeat` value are passed in) and should be ported as a single shared module in Rust as well.

---

## 8. Direct-TCP MRP (`pyatv/protocols/mrp/connection.py`, `protocol.py`)

### 8.1 `MrpConnection` — framing

```python
def send(self, message: protobuf.ProtocolMessage) -> None:
    serialized = message.SerializeToString()
    if self._chacha:
        serialized = self._chacha.encrypt(serialized)
    data = write_variant(len(serialized)) + serialized
    self._transport.write(data)
```

`connection.py:114-125`. Receive (`connection.py:137-173`): buffer arbitrarily-split reads, repeatedly `read_variant(self._buffer)`, wait until `len(raw) >= length`, slice off the frame, decrypt (`self._chacha.decrypt(data)` if enabled — no explicit nonce/AAD kwargs, so counter-based nonce and `aad=None`, per `hap-pairing-port-spec.md:578-580`), `ProtocolMessage().ParseFromString(data)`, dispatch via `self.listener.message_received(parsed, data)`. `write_variant`/`read_variant` (`pyatv/support/variant.py`) are the standard LEB128-style protobuf varint, applied **outside** the AEAD boundary (over already-encrypted bytes on send, stripped before decryption on receive) — this is a length-prefix framing layer, not part of the protobuf wire format itself, and not authenticated by the AEAD call at all. `send_raw(data)` (`connection.py:127-135`) is the same framing for pre-serialized bytes, used only during MRP pairing before a `ProtocolMessage` wrapper is meaningful.

`connection_made` (`connection.py:59-72`) enables TCP keepalive (`tcp_keepalive(sock)`, best-effort — logs a warning and continues if unsupported on the platform) and captures a `srcaddr:srcport<->dstaddr:dstport` string used purely for log-line prefixing.

### 8.2 Encryption enable point and cipher class

```python
def enable_encryption(self, output_key: bytes, input_key: bytes) -> None:
    self._chacha = chacha20.Chacha20Cipher8byteNonce(output_key, input_key)
```

`connection.py:93-95`. `Chacha20Cipher8byteNonce` nonce layout: `0x00000000 (4 zero bytes) ‖ counter (8 bytes, little-endian)`, independent `_out_counter`/`_in_counter` per direction, both starting at 0, auto-incrementing once per `encrypt`/`decrypt` call (`pyatv/support/chacha20.py`, reproduced in full in `mrp-companion.md:120-125` and `hap-pairing-port-spec.md:566`). **No AAD, no 1024-byte chunk cap, no HAPSession** — a whole `ProtocolMessage`, however large, is sealed in one AEAD call (§8's difference from AirPlay framing, §4).

### 8.3 `MrpProtocol.start()` — the exact sequence, confirmed against source

```python
async def start(self, skip_initial_messages: bool = False) -> None:
    await self.connection.connect()
    # credentials override, if service.credentials was set externally
    if self.service.credentials:
        self.srp.pairing_id = parse_credentials(self.service.credentials).client_id

    self.device_info = await self.send_and_receive(
        messages.device_information(self.info, self.srp.pairing_id.decode())
    )
    self.dispatch(protobuf.DEVICE_INFO_MESSAGE, self.device_info)

    if skip_initial_messages:
        return

    await error_handler(self._enable_encryption, exceptions.AuthenticationError)
    await self.send(messages.set_connection_state())
    await self.send_and_receive(messages.client_updates_config())
    await self.send_and_receive(messages.get_keyboard_session())
```

`pyatv/protocols/mrp/protocol.py:123-172`, faithfully condensed (state transitions and exception handling elided but not altered in ordering). **Confirmed exact order**: `DEVICE_INFO_MESSAGE` (request/response, unencrypted, must be the very first thing sent on a fresh socket) → pair-verify (`_enable_encryption`, only if `service.credentials` is set — if there are no persisted credentials, encryption is simply never enabled and everything after this point stays plaintext) → `SET_CONNECTION_STATE_MESSAGE` (fire-and-forget `send`, not `send_and_receive` — this is the **first message sent after encryption turns on**, per an explicit source comment, `protocol.py:159-160`) → `CLIENT_UPDATES_CONFIG_MESSAGE` (request/response) → `GET_KEYBOARD_SESSION_MESSAGE` (request/response). **There is no `REGISTER_HID_DEVICE_MESSAGE` and no `WAKE_DEVICE_MESSAGE` in this sequence** — see [Corrections](#corrections), both were incorrectly assumed present by the task brief.

`skip_initial_messages=True` is used only by `MrpPairSetupProcedure.start_pairing` (`pyatv/protocols/mrp/auth.py:36-40`) to reuse the same `MrpProtocol`/`start()` call for the pairing-only flow (open socket, send `DEVICE_INFO_MESSAGE`, then hand control to the pairing state machine instead of proceeding to encryption/config messages).

### 8.4 `enable_heartbeat()` — direct connections only

```python
def enable_heartbeat(self) -> None:
    async def _sender_func(message):
        if message is not None:
            await self.send_and_receive(message)
    def _failure_func(exc):
        self.connection.close()
    self._heartbeat_task = asyncio.ensure_future(
        heartbeater(
            name=str(self.connection),
            sender_func=_sender_func,
            failure_func=_failure_func,
            message_factory=lambda: messages.create(protobuf.GENERIC_MESSAGE),
        )
    )
```

`protocol.py:188-205`. Called from `create_with_connection`'s `_connect()` (`pyatv/protocols/mrp/__init__.py:1127-1131`) **only if `requires_heatbeat` is `True`** — which it is for direct connections (`setup()`, `pyatv/protocols/mrp/__init__.py:1169-1177`, uses the default `requires_heatbeat=True`) and explicitly is not for the AirPlay tunnel (§2.4). `heartbeater()`'s defaults apply here (not overridden): `interval=HEARTBEAT_INTERVAL=30` seconds, `retries=HEARTBEAT_RETRIES=1` (`pyatv/core/protocol.py:20-21`; `pyatv/protocols/mrp/protocol.py:23-24` also declares its own copy of the same two constants with the same values, unused by the shared `heartbeater()` since it takes them as call-time defaults from its own module, not from `mrp/protocol.py` — the duplication is harmless but worth noting so a Rust port doesn't wire the wrong constant by mistake). Heartbeat message: `messages.create(protobuf.GENERIC_MESSAGE)` — a bare `GENERIC_MESSAGE` (type 42) with no extension payload, sent via `send_and_receive` (so the round trip itself is the liveness check, not a fire-and-forget ping) — timeout comes from `send_and_receive`'s own default (`timeout: float = 5.0`, `protocol.py:237`), separate from the heartbeat interval.

### 8.5 `identifier`/`errorCode` correlation

`send_and_receive` (`protocol.py:233-260`) stamps `message.identifier = str(uuid.uuid4()).upper()` on every request **unless** `generate_identifier=False` is passed — used exclusively by the `CryptoPairingMessage` exchanges (`mrp/auth.py:46,67,77,101,112`), because the device's `CryptoPairingMessage` responses never echo an `identifier` back, and it is only possible to have one crypto-pairing exchange outstanding at a time anyway. When `generate_identifier=False`, the correlation key becomes the synthetic string `"type_" + str(message.type)` (`protocol.py:257`) instead of a UUID; `message_received` (`protocol.py:283-294`) applies the same fallback on the *receiving* side (`identifier = message.identifier or "type_" + str(message.type)`) so unsolicited/keyed-by-type responses still match an outstanding wait. If no outstanding request matches, the message is dispatched to type-based listeners instead (`self.dispatch(message.type, message)`, the `MessageDispatcher` mechanism `PlayerStateManager`/`MrpPower`/`MrpAudio` all register against, §9).

---

## 9. `pyatv/protocols/mrp/messages.py` — every factory, verbatim field-by-field

### 9.1 `create(message_type, error_code=0, identifier=None)`

```python
message = protobuf.ProtocolMessage()
message.type = message_type
message.errorCode = error_code
message.uniqueIdentifier = str(uuid4()).upper()
if identifier:
    message.identifier = identifier
```

`messages.py:13-21`. **Every** outbound message gets a fresh uppercase `uniqueIdentifier` UUID stamped on the envelope (field 85, not to be confused with `identifier`, field 2, which is the request/response correlation key from §8.5 and is left unset by `create()` itself — it is set separately by `send_and_receive`).

### 9.2 `device_information(info_settings, identifier, update=False)`

```python
msg_type = protobuf.DEVICE_INFO_UPDATE_MESSAGE if update else protobuf.DEVICE_INFO_MESSAGE
message = create(msg_type)
info = protobuf.extract_inner(message)
info.allowsPairing = True
info.applicationBundleIdentifier = "com.apple.TVRemote"
info.applicationBundleVersion = "344.28"
info.lastSupportedMessageType = 108
info.localizedModelName = "iPhone"
info.name = info_settings.name
info.protocolVersion = 1
info.sharedQueueVersion = 2
info.supportsACL = True
info.supportsExtendedMotion = True
info.supportsSharedQueue = True
info.supportsSystemPairing = True
info.systemBuildVersion = info_settings.os_build
info.systemMediaApplication = "com.apple.TVMusic"
info.uniqueIdentifier = identifier
info.deviceClass = protobuf.DeviceClass.iPhone
info.logicalDeviceCount = 1
```

`messages.py:24-48`. **This is the complete field set** — every literal is verbatim, no fields are omitted from the excerpt above (unlike `mrp-companion.md:113`'s partial listing, which named only 6 of these 15 fields and omitted `allowsPairing`, `lastSupportedMessageType`, `sharedQueueVersion`, `supportsACL`, `supportsExtendedMotion`, `supportsSharedQueue`, `supportsSystemPairing`, and `logicalDeviceCount` — see [Corrections](#corrections)). `identifier` here is the **pairing identifier** (`self.srp.pairing_id.decode()` at the call site, `protocol.py:145`), written into `DeviceInfoMessage.uniqueIdentifier` (field 1) — a different field from `ProtocolMessage.uniqueIdentifier` set by `create()`. `DeviceClass.Enum` values (`pyatv/protocols/mrp/protobuf/Common.proto:19-33`): `Invalid=0, iPhone=1, iPod=2, iPad=3, AppleTV=4, iFPGA=5, Watch=6, Accessory=7, Bridge=8, Mac=9` — pyatv always impersonates `iPhone` (value `1`), never sends its own device class truthfully, for both `localizedModelName` (`"iPhone"`, hardcoded string) and `deviceClass`. `logicalDeviceCount = 1` on the *client's own* outbound `DeviceInfoMessage` is a fixed literal unrelated to `MrpPower`'s use of the *device's* `logicalDeviceCount` field (received, not sent) to infer `PowerState` (§11).

### 9.3 `wake_device()`, `set_connection_state()`, `get_keyboard_session()`

```python
def wake_device():
    return create(protobuf.ProtocolMessage.WAKE_DEVICE_MESSAGE)

def set_connection_state():
    message = create(protobuf.ProtocolMessage.SET_CONNECTION_STATE_MESSAGE)
    protobuf.extract_inner(message).state = protobuf.SetConnectionStateMessage.Connected
    return message

def get_keyboard_session():
    return create(protobuf.ProtocolMessage.GET_KEYBOARD_SESSION_MESSAGE)
```

`messages.py:51-65`. `SetConnectionStateMessage.ConnectionState` enum (`pyatv/protocols/mrp/protobuf/SetConnectionStateMessage.proto:9-14`): `None=0, Connecting=1, Connected=2, Disconnected=3` — pyatv always sends `Connected` directly, never transitions through `Connecting`. `get_keyboard_session()` carries **no payload at all** — it is a bare envelope with `type=GET_KEYBOARD_SESSION_MESSAGE` and nothing else; see §12 for why this does not actually enable a `Keyboard` interface on MRP.

### 9.4 `crypto_pairing(pairing_data, is_pairing=False)`

```python
message = create(protobuf.CRYPTO_PAIRING_MESSAGE)
crypto = protobuf.extract_inner(message)
crypto.status = 0
crypto.pairingData = hap_tlv8.write_tlv(pairing_data)
crypto.isRetrying = False
crypto.isUsingSystemPairing = False
crypto.state = 2 if is_pairing else 0
```

`messages.py:68-79`, fields per `CryptoPairingMessage.proto:11-16` (`pairingData: bytes`, `status: int32`, `isRetrying: bool`, `isUsingSystemPairing: bool`, `state: int32`). `crypto.state` is `2` only during **pair-setup** (`MrpPairSetupProcedure`, `mrp/auth.py:42-45` passes `is_pairing=True`); pair-verify (`MrpPairVerifyProcedure`, `mrp/auth.py:98-112`) never passes `is_pairing`, so `state` stays `0` for every pair-verify message. The comment `# Hardcoded values for now, might have to be changed` (`messages.py:75`) is pyatv's own acknowledgment that `isRetrying`/`isUsingSystemPairing`/the exact `state` semantics are not fully understood — treat as literals to replicate, not values with independently-derivable meaning.

### 9.5 `client_updates_config(artwork=True, now_playing=False, volume=True, keyboard=True, output_device_updates=True)`

```python
config.artworkUpdates = artwork
config.nowPlayingUpdates = now_playing
config.volumeUpdates = volume
config.keyboardUpdates = keyboard
config.outputDeviceUpdates = output_device_updates
```

`messages.py:82-97`. Called with **no arguments** from `MrpProtocol.start()` (`protocol.py:164`), so the defaults above are what's actually sent: artwork/volume/keyboard/output-device update subscriptions **on**, now-playing-push subscription **off** by default (now-playing updates arrive via `SET_STATE_MESSAGE` regardless, subscribed to elsewhere — see §10).

### 9.6 `playback_queue_request(location, width=-1, height=400)`

Used by artwork fetch (§13.2), not called during `start()`.

### 9.7 `send_hid_event(use_page, usage, down)` — full byte layout

```python
abstime = binascii.unhexlify(b"438922cf08020000")   # fixed literal, not real mach time
data = use_page.to_bytes(2, byteorder="big")
data += usage.to_bytes(2, byteorder="big")
data += (1 if down else 0).to_bytes(2, byteorder="big")
event.hidEventData = (
    abstime
    + binascii.unhexlify(
        b"00000000000000000100000000000000020"
        b"00000200000000300000001000000000000"
    )
    + data
    + binascii.unhexlify(b"0000000000000001000000")
)
```

`messages.py:112-138`, reproduced byte-for-byte because this is exactly the kind of value the parent task flagged as needing exact reproduction. `abstime` is a **hardcoded 8-byte literal** — pyatv's own comment (`messages.py:117-119`) says it "should be generated somehow. I guess it's mach AbsoluteTime which is tricky to generate. The device does not seem to care much about the value though, so hardcode something here." A Rust port should replicate the exact literal rather than attempt to compute a real timestamp, since pyatv's own empirical finding is that the device does not validate it. Full `hidEventData` byte layout, concatenated in order and confirmed by counting the source's own hex literals rather than eyeballing them: `abstime` (8 bytes, fixed, `43 89 22 cf 08 02 00 00`) ‖ a **35-byte** fixed literal blob — the two adjacent Python byte-string literals at `messages.py:130-133` concatenate (Python implicitly joins adjacent string literals) to the 70-hex-digit string `0000000000000000010000000000000002000000200000000300000001000000000000`, which `binascii.unhexlify` turns into exactly 35 bytes — ‖ `data` (6 bytes: 2-byte-BE `use_page`, 2-byte-BE `usage`, 2-byte-BE down-flag) ‖ a fixed **11-byte** trailing literal (`0000000000000001000000`, 22 hex digits = 11 bytes, `messages.py:135`). Total `hidEventData` length: `8 + 35 + 6 + 11 = 60` bytes for every HID event pyatv sends, regardless of which key. Key/usage-page lookup table (`_KEY_LOOKUP`, `pyatv/protocols/mrp/__init__.py:78-96`):

```
up: (1, 0x8C)        down: (1, 0x8D)       left: (1, 0x8B)      right: (1, 0x8A)
stop: (12, 0xB7)      next: (12, 0xB5)      previous: (12, 0xB6)
select: (1, 0x89)     menu: (1, 0x86)       topmenu: (12, 0x60)  home: (12, 0x40)
suspend: (1, 0x82)    wakeup: (1, 0x83)
volume_up: (12, 0xE9) volume_down: (12, 0xEA)
```

(commented-out `'mic': (12, 0x04)` for Siri exists in source but is dead — no caller reaches it). These are literal USB HID usage-page/usage pairs (`docs/research/mrp-companion.md` does not cover this table at all; it is new to this document).

### 9.8 `send_button(usage_page, usage, button_down)` — dead code, confirmed unused

```python
def send_button(usage_page, usage, button_down):
    message = create(protobuf.SEND_BUTTON_EVENT_MESSAGE)
    inner = protobuf.extract_inner(message)
    inner.usagePage = usage_page
    inner.usage = usage
    inner.buttonDown = button_down
    return message
```

`messages.py:141-148`. Grepping every caller of `messages.send_button` across `pyatv/` finds **none** — `SEND_BUTTON_EVENT_MESSAGE` (type 39) is a defined protobuf extension with a working factory function, but nothing in the current codebase ever constructs or sends one; all button presses go through `send_hid_event` (§9.7) instead. A Rust port has no reason to wire up an equivalent code path for parity with current pyatv behavior, though the message type exists in the protobuf corpus if a future need arises.

### 9.9 `command(cmd, **kwargs)`, `repeat`, `shuffle`, `seek_to_position`

```python
def command(cmd, **kwargs):
    message = create(protobuf.SEND_COMMAND_MESSAGE)
    send_command = protobuf.extract_inner(message)
    send_command.command = cmd
    for key, value in kwargs.items():
        setattr(send_command.options, key, value)
    return message
```

`messages.py:151-158`. `SendCommandMessage` (`SendCommandMessage.proto:11-15`): `command: Command`, `options: CommandOptions`, `playerPath: PlayerPath` (the last is never set by this helper — always the zero-value `PlayerPath`, meaning commands are sent against whatever the device considers the currently-active player, not an explicitly-targeted one). `repeat(mode)`/`shuffle(state)` (`messages.py:170-195`) both set `options.sendOptions = 0` before the mode-specific field — an otherwise-undocumented flags field always zeroed by pyatv. `seek_to_position(position)` sets `options.playbackPosition = position` directly, no `sendOptions`.

### 9.10 `command_result`, `set_volume`, `add_output_devices`/`remove_output_devices`/`set_output_devices`

```python
def command_result(identifier, send_error=protobuf.SendError.NoError):
    message = create(protobuf.SEND_COMMAND_RESULT_MESSAGE, identifier=identifier)
    inner = protobuf.extract_inner(message)
    inner.sendError = send_error
    inner.handlerReturnStatus = protobuf.HandlerReturnStatus.Success
```

`messages.py:161-167` — only used by the *fake server* test harness (§14), never by the real client (a client never answers a `SEND_COMMAND_MESSAGE`, it only issues them). `set_volume(device_uid, volume)` (`messages.py:206-212`): `outputDeviceUID = device_uid`, `volume = volume` (a `0.0..1.0` float — the facade-level `Audio.set_volume(level: 0..100)` divides by 100 before calling this, `pyatv/protocols/mrp/__init__.py:875-877,881-883`). The three `*_output_devices` factories (`messages.py:215-245`) all build a single `MODIFY_OUTPUT_CONTEXT_REQUEST_MESSAGE` with `type = SharedAudioPresentation` and populate **two parallel repeated fields** per operation (e.g. `add`: both `addingDevices` and `clusterAwareAddingDevices` get every UID appended) — a Rust port must write to both fields, not just one, or the device will only partially apply the change.

---

## 10. `PlayerStateManager` — merge rules

`pyatv/protocols/mrp/player_state.py:185-327`, `MessageDispatcher`-registered handlers (`_add_listeners`, `player_state.py:197-209`):

```
SET_STATE_MESSAGE                    -> _handle_set_state
UPDATE_CONTENT_ITEM_MESSAGE          -> _handle_content_item_update
SET_NOW_PLAYING_CLIENT_MESSAGE       -> _handle_set_now_playing_client
SET_NOW_PLAYING_PLAYER_MESSAGE       -> _handle_set_now_playing_player
UPDATE_CLIENT_MESSAGE                -> _handle_update_client
REMOVE_CLIENT_MESSAGE                -> _handle_remove_client
REMOVE_PLAYER_MESSAGE                -> _handle_remove_player
SET_DEFAULT_SUPPORTED_COMMANDS_MESSAGE -> _handle_set_default_supported_commands
```

Model: `Client` (keyed by `bundleIdentifier`) owns zero or more `PlayerState` (keyed by player identifier, within that client's `players: Dict[str, PlayerState]`), and `PlayerStateManager` owns zero or more `Client` (keyed by `bundleIdentifier`, in `self._clients`) plus one `_active_client` reference. `PlayerStateManager.playing` (`player_state.py:242-247`) resolves to `self._active_client.active_player` if a client is active, else a **throwaway zero-value `PlayerState`** (`PlayerState(Client(pb.NowPlayingClient()), pb.NowPlayingPlayer())`) — so `psm.playing` is never `None`, callers always get *some* `PlayerState`, just possibly an empty one. `Client.active_player` (`player_state.py:143-150`) similarly falls back to the well-known `DEFAULT_PLAYER_ID = "MediaRemote-DefaultPlayer"` (`player_state.py:14`) player within that client if no explicit active player has been set, before falling back to a fresh empty `PlayerState`.

**`SET_STATE_MESSAGE` merge** (`PlayerState.handle_set_state`, `player_state.py:100-111`): each of `playbackState`, `supportedCommands.supportedCommands`, `playbackQueue` (→ `items`/`location`) is updated **only if `HasField(...)` is true on the incoming message** — absent fields leave the existing value untouched (a partial `SetStateMessage` is a legitimate incremental update, not a full-state replacement). `command_info(command)` (`player_state.py:93-98`) looks in the **player's own** `supported_commands` first, then falls back to the **parent client's** `supported_commands` (set by `SET_DEFAULT_SUPPORTED_COMMANDS_MESSAGE`, §10 below) — this two-level fallback is how `FeatureName` availability (`_FEATURE_COMMAND_MAP`, §11) resolves for commands the current player hasn't explicitly reported but the client has declared as defaults.

**`UPDATE_CONTENT_ITEM_MESSAGE` merge** (`PlayerState.handle_content_item_update`, `player_state.py:113-124`): matches incoming `contentItems` against `self.items` by `identifier`, and for matches calls `existing.metadata.MergeFrom(updated_item.metadata)` — a protobuf `MergeFrom`, which **appends** repeated fields rather than replacing them (source comment, `player_state.py:118-121`, explicitly flags this as a known quirk: "NB: MergeFrom will append repeated fields (which is likely not what is expected)!"). A Rust port reimplementing this merge should decide deliberately whether to replicate the append-not-replace behavior for repeated metadata fields or fix it, since pyatv itself flags it as probably wrong but has shipped it unchanged.

**`SET_DEFAULT_SUPPORTED_COMMANDS_MESSAGE`** (`Client.handle_set_default_supported_commands`, `player_state.py:163-165`): full replacement, not merge — `self.supported_commands = supported_commands.supportedCommands.supportedCommands` (note the double `.supportedCommands` — the outer field on the message wrapper, the inner repeated field on the nested `SupportedCommands` message).

**`_state_updated(client=None, player=None)`** (`player_state.py:320-327`): the listener (`MrpPushUpdater`, only ever one at a time — `psm.listener` is a single slot, not a list, set via a `weakref.ref`, `player_state.py:229-235`) is notified only if the changed `client`/`player` **is** the currently-active one, or if both `client` and `player` are `None` (meaning the caller couldn't scope the change and it should always propagate — used by `_handle_set_now_playing_client` and `_handle_set_default_supported_commands`). Changes to a *non-active* client/player's state are silently absorbed into the model without a push notification — correct, since `Playing`/`Metadata` only ever reflect the active player, but worth being explicit about for a Rust port's own event-dispatch design.

---

## 11. `Metadata`/`Playing` derivation (`build_playing_instance`)

`pyatv/protocols/mrp/__init__.py:158-293`, field-by-field derivation from `PlayerState`:

- `media_type`: `cim.Audio` → `MediaType.Music`, `cim.Video` → `MediaType.Video`, anything else (including no metadata at all) → `MediaType.Unknown`.
- `device_state`: `PlaybackState.Playing→Playing, Paused→Paused, Stopped→Stopped, Interrupted→Loading, Seeking→Seeking, None (or unset)→Idle`, with `PlaybackState.Paused` further re-derived in `PlayerState.playback_state` itself (§10) — the *device_state* mapping consumes the already-adjusted `playback_state` property, not the raw protobuf enum, so the effective mapping folds in the "paused with no metadata means idle, not paused" rule and the playback-rate-based Playing/Paused/Seeking disambiguation (`player_state.py:41-70`) before `build_playing_instance` ever sees it.
- `title`/`artist`/`album`/`genre`/`series_name`/`season_number`/`episode_number`/`content_identifier`/`itunes_store_identifier`: all direct `metadata_field(...)` lookups (`player_state.py:86-91`, `None` if the protobuf field is unset — `HasField` gated, not zero-value-gated).
- `total_time`: `metadata_field("duration")`, `None` if unset or `NaN` (`math.isnan` check, `__init__.py:204-206`).
- `position`: only computable if `elapsedTimeTimestamp` is present; converts that Cocoa-epoch timestamp (`_cocoa_to_timestamp`, `__init__.py:152-155` — 2001-01-01 epoch, standard Apple `NSDate` convention) to a Python `datetime`, then if currently `Playing` **and** `playbackRate` is non-zero, extrapolates position as `elapsedTime + (now - elapsedTimeTimestamp).total_seconds()`; otherwise returns the raw `elapsedTime` unmodified (i.e. **position is only live-extrapolated while genuinely playing at non-zero rate**, not merely while `device_state == Playing`, since a `Playing` state with `playbackRate≈0` still hits the "return int(elapsed_time)" branch).
- `shuffle`/`repeat`: derived from `command_info(ChangeShuffleMode)`/`command_info(ChangeRepeatMode)` — **not** a dedicated shuffle/repeat field, the current mode is read off the `CommandInfo.shuffleMode`/`repeatMode` sub-fields of whichever `CommandInfo` entry matches those command IDs; absent `CommandInfo` → `Off`.
- `hash`: `state.item_identifier` — the current content item's `identifier` field, or `None` if the queue is empty/short.

---

## 12. `RemoteControl` command surface — HID vs `SEND_COMMAND`, and the flush mechanism

`MrpRemoteControl` (`pyatv/protocols/mrp/__init__.py:328-479`) splits every button into two dispatch paths:

- **HID buttons** (`_send_hid_key`, `__init__.py:296-324`): `up`, `down`, `left`, `right`, `select`, `menu`, `volume_up`, `volume_down`, `home`, `home_hold`, `top_menu`, `suspend`, `wakeup` — all go through `send_hid_event` (§9.7). `_send_hid_key` implements `InputAction`: `SingleTap` → one press/release pair, `DoubleTap` → two press/release pairs back-to-back, `Hold` → press, `asyncio.sleep(1)` (hardcoded 1-second hold, `__init__.py:303-304`), release. After every `_do_press` (unless `flush=False`), a `GENERIC_MESSAGE` is sent via `send_and_receive` (`__init__.py:309-310`) purely as "some kind of flush mechanism" (source comment, `__init__.py:308`) — not a real protocol requirement pyatv understands, just an empirically-necessary round trip after HID events. `Audio.volume_up`/`volume_down` (§13) call `_send_hid_key(..., flush=False)` specifically to skip this, since they wait on a different event (`_volume_event`) instead.
- **`SEND_COMMAND_MESSAGE` buttons** (`_send_command`, `__init__.py:342-354`): `play`, `pause`, `stop`, `next`, `previous`, `set_position`, `set_shuffle`, `set_repeat`, `skip_forward`/`skip_backward` (via `_skip_command`, `__init__.py:455-467`, which prefers an explicit `time_interval` argument, falls back to the *first* `preferredIntervals` entry from the matching `CommandInfo` if present, else `_DEFAULT_SKIP_TIME = 15`). `_send_command` raises `exceptions.CommandError` with the device's `SendError`/`HandlerReturnStatus` enum names baked into the message if `inner.sendError != NoError` — this is the one MRP command path with real device-side error reporting (HID presses have no response payload to fail on).
- **`play_pause`** (`__init__.py:376-387`) is neither purely HID nor purely `SEND_COMMAND` — it first checks whether `TogglePlayPause` is `enabled` per the current player's `CommandInfo`; if so, sends that command; if not (app doesn't support the toggle command specifically), falls back to inspecting `playback_state` directly and calling `self.pause()`/`self.play()` accordingly. A comment (`__init__.py:378-379`) explains this exists because "some kind of feature emulation" would otherwise misreport availability — worth preserving the exact fallback logic, not simplifying to "always send TogglePlayPause."

No button in current pyatv master constructs a `RegisterHIDDeviceMessage`, `SendButtonEventMessage` (dead, §9.8), or `SendHIDReportMessage` — see [Corrections](#corrections).

---

## 13. Artwork, volume, power

### 13.1 Artwork

`MrpMetadata.artwork` (`pyatv/protocols/mrp/__init__.py:504-532`) checks a 4-entry LRU `Cache` keyed by `artwork_id` (`__init__.py:600-610`: prefers `metadata.artworkIdentifier`, then `metadata.contentIdentifier`, then falls back to the raw item identifier — only reachable at all if `metadata.artworkAvailable` or `metadata.HasField("artworkURL")`), then tries **two fetch strategies in order**, `_fetch_remote_artwork` before `_fetch_local_artwork` (`__init__.py:534-537`, `or`-chained — first non-`None` wins):

- `_fetch_remote_artwork` (`__init__.py:539-581`): if `metadata.artworkIdentifier` is set, treats it as a `str.format` URL template with keys `w`/`h`/`c`/`f` (`w=999999 if width<1 else width`, same for `h`, `c="bb"`, `f="png"` — the iTunes artwork CDN convention, `999999` as a sentinel meaning "no size constraint, preserve aspect ratio"), and if `metadata.artworkURL` is set, appends that as a fallback fixed-size URL; both are attempted via a plain HTTP GET (`aiohttp.ClientSession`) with only a 200-status check, no auth.
- `_fetch_local_artwork` (`__init__.py:583-598`): only reachable if the remote strategy returned nothing. Sends `messages.playback_queue_request(playing.location, width, height)` (`__init__.py:100-109`: `PLAYBACK_QUEUE_REQUEST_MESSAGE` with `location`, `length=1`, `artworkWidth`, `artworkHeight`, `returnContentItemAssetsInUserCompletion=True`) and pulls `artworkData`/`artworkDataWidth`/`artworkDataHeight` off the matching `contentItems[playing.location]` entry in the response.

There is no `FETCH_ARTWORK_MESSAGE` type or separate artwork-fetch protobuf message — artwork is requested by re-issuing the same `PLAYBACK_QUEUE_REQUEST_MESSAGE` used for general queue introspection, with width/height parameters, and reading the artwork bytes back off the content-item's own fields.

### 13.2 Volume (`MrpAudio`, `pyatv/protocols/mrp/__init__.py:746-948`)

`device_uid` (`__init__.py:764-770`): `inner.clusterID or inner.deviceUID` off the **device's own** `DeviceInfoMessage` (received, cached as `self.protocol.device_info` — updated on both `DEVICE_INFO_MESSAGE` and `DEVICE_INFO_UPDATE_MESSAGE`, §11's power-state listener shares this same field). `is_available` requires both `_volume_controls_available` (from `VOLUME_CONTROL_AVAILABILITY_MESSAGE`/`VOLUME_CONTROL_CAPABILITIES_DID_CHANGE_MESSAGE`, gated on `outputDeviceUID == self.device_uid` for the latter, `__init__.py:806-830`) **and** `device_uid is not None`. `set_volume(level, output_device=None)` (`__init__.py:868-885`) sends `messages.set_volume(uid, level/100.0)` where `uid` is either the explicit `output_device.identifier` or `self.device_uid`, then, only if volume control is absolute (`is_volume_absolute`) and the cached `_volume` doesn't already match, awaits `_volume_event` (a plain `asyncio.Event`, set/cleared on every `VOLUME_DID_CHANGE_MESSAGE`, `__init__.py:832-861`) with a 5-second timeout — **there is no response payload to `SET_VOLUME_MESSAGE` itself**; confirmation is entirely inferred from the next `VOLUME_DID_CHANGE_MESSAGE` push, which is why the wait-on-event pattern exists (source comment, `__init__.py:853-859`, flags the shared-single-`Event` race if multiple callers invoke `volume_up`/`volume_down` concurrently as a known, accepted limitation). `volume_up`/`volume_down` (`__init__.py:887-911`) prefer relative HID stepping (`_send_hid_key(..., flush=False)`) when `is_volume_relative`, only falling back to `set_volume(clamp(volume±5))` when only absolute control is available — and short-circuit entirely at the 0/100 boundary when absolute control is the only mode. `VOLUME_DID_CHANGE_MESSAGE` for a **non**-matching `outputDeviceUID` is dispatched as `UpdatedState.OutputDeviceVolume` instead of the primary `UpdatedState.Volume` (`__init__.py:840-851`) — multi-output-device volume changes are observable but don't affect `Audio.volume`.

### 13.3 Power (`MrpPower`, `pyatv/protocols/mrp/__init__.py:625-695`)

`power_state` is derived entirely from the **device's own** `DeviceInfoMessage.logicalDeviceCount` field (`_get_power_state`, `__init__.py:686-695`): `>=1 → On`, `==0 → Off`, unset → `Unknown`. `MrpPower` listens to both `DEVICE_INFO_MESSAGE` and `DEVICE_INFO_UPDATE_MESSAGE` (`__init__.py:642-645`) and caches the most recent one in `self.device_info`, falling back to `self.protocol.device_info` (the connection-time snapshot from `start()`, §8.3) if no update has arrived yet. `turn_on()` sends `messages.wake_device()` (`WAKE_DEVICE_MESSAGE`, §9.3 — this **is** the one caller of that factory, contrary to the task brief's assumption that it participates in the connection startup sequence; it is purely a `Power.turn_on()` action, never sent during `start()`). `turn_off()` has **no dedicated protobuf message at all** — it is implemented purely as `self.remote.home(InputAction.Hold)` then, after a `DELAY_BETWEEN_COMMANDS = 0.1` second sleep, `self.remote.select()` (`__init__.py:664-669`) — i.e. "hold Home to open the power menu, then press Select to confirm sleep," entirely through the HID button path (§12), not a dedicated power-off command. Both `turn_on`/`turn_off` optionally await a `PowerState`-keyed `asyncio.Event` (`self._waiters`) if `await_new_state=True`, resolved by `_update_power_state` when the next `DeviceInfoMessage`/`DeviceInfoUpdateMessage` reflects the target state.

---

## 14. Keyboard — correction: MRP does not implement it

`pyatv/interface.py:1247-1260` defines a `Keyboard` ABC (`text_focus_state` property plus text-manipulation methods). Grepping every `pyatv/protocols/*/__init__.py` for a class implementing it finds **exactly one**: `pyatv/protocols/companion/__init__.py`. MRP's `create_with_connection` (`pyatv/protocols/mrp/__init__.py:1099-1166`) registers `RemoteControl`, `Metadata`, `Power`, `PushUpdater`, `Features`, `Audio` — **no `Keyboard` entry**. `GET_KEYBOARD_SESSION_MESSAGE` (§9.3) is sent unconditionally during `start()` and `client_updates_config(keyboard=True)` subscribes to keyboard-related update pushes, but nothing in the MRP module ever constructs a `TEXT_INPUT_MESSAGE`, `KEYBOARD_MESSAGE`, `REMOTE_TEXT_INPUT_MESSAGE`, or `GET_REMOTE_TEXT_INPUT_SESSION_MESSAGE` — those four message types exist in the protobuf corpus (`ProtocolMessage.proto:100,102,143` and `GetRemoteTextInputSessionMessage.proto:9`) but have **zero producers** anywhere in `pyatv/protocols/mrp/`. A Rust port that wants keyboard support must implement it against **Companion**'s `_tiStart`/`_tiC`/`_tiStop` surface (`docs/research/companion-port-spec.md` §3.6), not MRP's; the MRP `GET_KEYBOARD_SESSION_MESSAGE` subscription exists only so the client doesn't miss keyboard-*availability* push notifications that might inform `Features`, not so it can drive text entry itself.

---

## 15. Push updates (`MrpPushUpdater`)

`pyatv/protocols/mrp/__init__.py:698-743`. `active` is `self.psm.listener == self` (the single-slot weakref check from §10). `start()` sets `psm.listener = self` and immediately schedules `self.state_updated()` as a task (an initial synthetic push on start, not waiting for the first real device-originated state change) — `initial_delay` is accepted as a parameter (`AbstractPushUpdater` base-class contract) but never actually used in this override, always fires immediately. `state_updated()` calls `self.metadata.playing()` (`build_playing_instance`, §11) and posts it via `self.post_update(playstatus)`; any non-cancellation exception is routed to `self.listener.playstatus_error(self, ex)` on the next event-loop iteration (`loop.call_soon`) rather than raised synchronously.

---

## 16. Tests and fixtures — what exists, and the real gap

### 16.1 What exists

- `tests/protocols/airplay/conftest.py:15-53` — `airplay_device`/`client_connection`/`airplay_usecase`/`airplay_conf` fixtures backed by `tests.fake_device.FakeAppleTV`, wired to a real `AirPlayServerAuth`-based server (`pyatv/protocols/airplay/server_auth.py:414+`) that performs a **genuine** HAP pair-verify handshake (not canned bytes) — used by `test_airplay_verify.py` (§16.2) and the general AirPlay unit tests.
- `tests/protocols/airplay/test_airplay.py` — scan/`device_info`/`service_info` unit tests (parametrized TXT-property → `PairingRequirement`/password-required tables — useful as a cross-check for §1's decoding, though it does not include this exact device's TXT values).
- `tests/protocols/airplay/test_airplay_verify.py:1-38` — parametrized pair-verify functional test against `DEVICE_CREDENTIALS` (HAP), `TRANSIENT_CREDENTIALS`, and two deliberately-wrong credential sets (expecting `AuthenticationError`), run over a real `http_connect` + `pair_verify` round trip against the fake server.
- `tests/fake_device/mrp.py` — a full fake MRP server (`MrpServerAuth`-based) with per-message-type handlers (`handle_device_info`, `handle_set_connection_state`, `handle_client_updates_config`, `handle_get_keyboard_session`, `handle_send_hid_event`, `handle_send_command`, `handle_playback_queue_request`, `handle_wake_device`, `handle_generic`, `handle_set_volume`, `handle_modify_output_context_request` — `mrp.py:471-641`), a `_KEY_LOOKUP`/`_COMMAND_LOOKUP` mirroring the client's own tables for assertion purposes, and `logicalDeviceCount` driven by a `self.state.powered_on` flag (`mrp.py:427`) — this is the harness `tests/protocols/mrp/test_mrp_functional.py` runs the full facade against, over a **direct** `MrpConnection` (real TCP loopback socket, real ChaCha20 encryption, real HAP pair-setup/verify) — the closest thing pyatv has to a byte-level known-answer suite for the direct-MRP path in §8–§13.

### 16.2 The real gap: no tunnel/data-channel fixture exists

Grepping the entire `tests/` tree for `eventPort`, `dataPort`, `isRemoteControlOnly`, `DataStreamChannel`, `EventChannel`, `AP2Session`, or `setup_remote_control` returns **zero matches**. `tests/fake_device/airplay.py` (the only AirPlay fake-device implementation) covers exclusively AirPlay-1-era legacy device-auth and `/play`/`/playback-info` playback — it never handles an RTSP `SETUP` for either the event or data channel, never returns an `eventPort`/`dataPort`, and has no `DataHeader`-framed socket handling at all. There is likewise no fixture anywhere under `tests/support/` exercising `DataHeader`/`defpacket` beyond the unrelated `tests/support/test_packet.py` (generic `defpacket` unit tests, not AirPlay-specific) and RAOP's own unrelated use of `defpacket` in `tests/protocols/raop/test_parsers.py`/`test_raop_functional.py`. **Every byte-level claim in §3–§7 of this document is therefore verified against pyatv's source code, not against pyatv's own test suite** — pyatv itself has no automated coverage proving the tunnel bring-up sequence or data-channel framing actually work end-to-end against anything, real or fake. This is the single largest gap between "what the reference implementation is claimed to do" and "what the reference implementation has been shown to do," and it directly motivates the recommendation in [Divergences](#divergences--open-questions) to build a capture-based (`atvproxy`-MITM) known-answer test for this exact path before trusting a Rust reimplementation against real hardware.

### 16.3 `tests/protocols/mrp/test_mrp_functional.py` — what it does cover, relevant to this document

`test_mrp_functional.py:1-60` sets up `MRPFunctionalTest(common_functional_tests.CommonFunctionalTests)` against the fake MRP server described in §16.1, importing shared constants (`BUILD_NUMBER = "18M60"`, `OS_VERSION = "14.7"`, `DEVICE_MODEL = "AppleTV6,2"`, `DEVICE_UID`, `PLAYER_IDENTIFIER = "com.github.postlund.pyatv"`, `VOLUME_STEP`) — these are the fixture's own device-identity constants, not defaults a Rust client should send (those are `InfoSettings`' defaults, §3.4), but useful as known-good round-trip values for a Rust hermetic MRP test server modeled after this fixture.

---

## 17. `FeatureName` registration and error enums

### 17.1 What `Protocol.MRP` registers, exact set

`create_with_connection`'s tail (`pyatv/protocols/mrp/__init__.py:1151-1166`) builds the `features: Set[FeatureName]` returned in `SetupData` by unioning four sources — reproduced so a Rust `Relayer<Features>` registration can be sized correctly:

```python
features = set([
    FeatureName.Artwork, FeatureName.VolumeDown, FeatureName.VolumeUp,
    FeatureName.SetVolume, FeatureName.Volume, FeatureName.App,
])
features.update(_FEATURES_SUPPORTED)       # Down/Home/HomeHold/Left/Menu/Right/Select/
                                            # TopMenu/Up/TurnOn/TurnOff/PowerState/
                                            # OutputDevices/AddOutputDevices/
                                            # RemoveOutputDevices/SetOutputDevices
features.update(_FEATURE_COMMAND_MAP.keys())  # Next/Pause/Play/PlayPause/Previous/Stop/
                                               # SetPosition/SetRepeat/SetShuffle/Shuffle/
                                               # Repeat/SkipForward/SkipBackward
features.update(_FIELD_FEATURES.keys())    # Title/Artist/Album/Genre/TotalTime/
                                            # SeriesName/Position/SeasonNumber/
                                            # EpisodeNumber/ContentIdentifier/
                                            # iTunesStoreIdentifier
```

`_FEATURES_SUPPORTED` (`__init__.py:99-116`), `_FEATURE_COMMAND_MAP` (`__init__.py:118-132`), `_FIELD_FEATURES` (`__init__.py:135-147`) are the three verbatim tables reproduced in full at those line ranges — a Rust `MrpFeatures::get_feature` implementation should be driven by equivalent static tables, not by an ad hoc match arm per feature, to keep the "which set does this feature name belong to" logic auditable against pyatv's own structure. Note this set is a **declaration of what MRP can answer at all**, separate from the *availability* logic in `MrpFeatures.get_feature` (`__init__.py:960-1022`) that decides `Available`/`Unavailable`/`Unsupported` per call — a feature can be in this registration set and still report `Unavailable` at runtime (e.g. `Volume`/`SetVolume` require `self.audio.is_available and self.audio.is_volume_absolute`, `__init__.py:1014-1020`).

### 17.2 Command-failure error enums

`SendCommandResultMessage.proto:9-23` — `SendError.Enum`, the value read off `inner.sendError` in `MrpRemoteControl._send_command`'s failure path (§12):

```
NoError=0, ApplicationNotFound=1, ConnectionFailed=2, Ignored=3,
CouldNotLaunchApplication=4, TimedOut=5, OriginDoesNotExist=6, InvalidOptions=7,
NoCommandHandlers=8, ApplicationNotInstalled=9, NotSupported=10
```

`SendCommandResultMessage.proto:26-42` — `HandlerReturnStatus.Enum`, the second value baked into the same `CommandError` message (§12):

```
Success=0, NoSuchContent=1, CommandFailed=2, UIKitLegacy=3, NoActionableNowPlayingItem=10,
DeviceNotFound=20, SkipAdProhibited=100, QueueIsUserCurated=101,
UserModifiedQueueDisabled=102, UserQueueModificationNotSupportedForCurrentItem=103,
SubscriptionRequiredForSharedQueue=104, InsertionPositionNotSpecified=105,
InvalidInsertionPosition=106, RequestParametersOutOfBounds=107, SkipLimitReached=108,
AuthenticationFailure=401, MediaServiceUnavailable=501
```

Both are proto2 enums with non-contiguous numbering (note `UIKitLegacy=3` sits between `CommandFailed=2` and `NoActionableNowPlayingItem=10` in declaration order but not in value order) — a Rust `TryFrom<i32>` or equivalent must not assume the enum is dense or that declaration order matches numeric order.

## 18. Recommended Rust `MrpTransport` design (synthesis, not pyatv source)

Everything in this section is a design recommendation the port must make a deliberate decision about, built directly from the seams identified in §7/§8; it is not claiming pyatv itself is structured this way in Rust terms.

```rust
/// Everything above this trait (MrpProtocol::start(), send_and_receive
/// correlation, PlayerStateManager, the facade types) is transport-agnostic
/// and shared, per §7.1 / §8.3-§8.5 / §9-§15.
#[async_trait::async_trait]
pub trait MrpTransport: Send {
    /// Bring the transport up. For the direct transport this dials TCP;
    /// for the tunnel transport this asserts the AirPlay data channel is
    /// already running (§7, point 1) and attaches as its listener.
    async fn connect(&mut self) -> Result<(), Error>;

    /// Install MRP-level transport keys derived from pair-verify. The
    /// direct transport installs a real Chacha20Cipher8byteNonce (§8.2);
    /// the tunnel transport discards the keys (§7, point 2) because the
    /// AirPlay HAP layer already encrypts the socket.
    fn enable_encryption(&mut self, output_key: [u8; 32], input_key: [u8; 32]);

    /// True for the direct transport only after a live socket exists;
    /// unconditionally true for the tunnel transport once constructed
    /// (§7, point 3 — AirPlayMrpConnection.connected is hardcoded True).
    fn connected(&self) -> bool;

    fn close(&mut self);

    /// Direct: write_variant(len) ++ (chacha20-sealed | plain) protobuf (§8.1).
    /// Tunnel: DataHeader-framed bplist {"params":{"data": variant-prefixed
    /// protobuf}} over the already-open DataStreamChannel (§5.3).
    fn send(&mut self, message: &ProtocolMessage) -> Result<(), Error>;

    /// Yields decoded ProtocolMessages as they arrive, regardless of
    /// transport; MrpProtocol::message_received (§8.5) is the only
    /// consumer and does not need to know which transport produced them.
    fn incoming(&mut self) -> &mut (dyn Stream<Item = ProtocolMessage> + Unpin);
}
```

Two implementors, `DirectMrpTransport` (owns the TCP socket + variant framing + real ChaCha20, §8.1-§8.2) and `TunnelMrpTransport` (a thin handle into an `AirPlayDataChannelActor` that itself owns the `DataHeader` framing, the plist encode/decode, and the HAP block encryption, §5). The tunnel implementor's `connect()` must return an error (mirroring `InvalidStateError`, §7 point 1) if constructed before `AP2Session::setup_remote_control()` has completed — encode that as a typed precondition (e.g. take an already-established data-channel handle by value in the constructor, making the invalid state unrepresentable, rather than a runtime check) since Rust's type system can close this gap more tightly than pyatv's own runtime assertion does.

Encryption-key handling deserves its own explicit type rather than a boolean/no-op distinction buried in an `if let Some(...)`: an enum `TransportEncryption { Owned(Chacha20Cipher8byteNonce), DelegatedToTunnel }` makes the "tunnel discards these keys on purpose" fact visible at every call site that would otherwise look like a bug (installing keys and then never using them) rather than a deliberate architectural choice inherited from pyatv (§7, point 2).

---

## Corrections

Corrections to the four prerequisite reports and to assumptions embedded in this task's own brief, each independently verified against `/tmp/pyatv-ref` source rather than asserted.

1. **`mrp-companion.md:113`'s `device_information()` field listing is incomplete.** It names 6 fields (`applicationBundleIdentifier`, `applicationBundleVersion`, `localizedModelName`, `protocolVersion`, `systemMediaApplication`, `deviceClass`, `uniqueIdentifier` — actually 7, but still a partial list) and omits `allowsPairing`, `lastSupportedMessageType=108`, `sharedQueueVersion=2`, `supportsACL`, `supportsExtendedMotion`, `supportsSharedQueue`, `supportsSystemPairing`, and `logicalDeviceCount=1`. §9.2 above gives the complete 15-field set verbatim.

2. **The task brief's assumption that MRP's `start()` sequence includes `REGISTER_HID_DEVICE` is wrong.** `RegisterHIDDeviceMessage`/`RegisterHIDDeviceResultMessage` protobuf types exist in the corpus (`pyatv/protocols/mrp/protobuf/RegisterHIDDeviceMessage.proto`), and `mrp-protobuf-spike.md`'s own known-answer-vector list even names `RegisterHIDDeviceMessage` as one of its eight test vectors — but grepping every `.py` file under `pyatv/` for `RegisterHIDDevice`/`REGISTER_HID` outside the generated `protobuf/` package finds **zero callers**. Nothing in current pyatv master ever constructs or sends this message; all HID input goes through `send_hid_event`/`SEND_HID_EVENT_MESSAGE` directly, with no prior device-registration step. §8.3 and §14 correct this.

3. **The task brief's assumption that `start()` includes `WAKE_DEVICE` is wrong.** `messages.wake_device()` has exactly one caller in the entire codebase: `MrpPower.turn_on()` (`pyatv/protocols/mrp/__init__.py:659`), a user-initiated `Power.turn_on()` action — it is never part of connection bring-up. §8.3/§13.3 correct this.

4. **The task brief's assumption that MRP has a `KEYBOARD_MESSAGE`/`TEXT_INPUT_MESSAGE`-driven keyboard implementation is wrong.** Those message types exist in the protobuf corpus but have no producers anywhere in `pyatv/protocols/mrp/`. Keyboard/text-input is a **Companion-only** feature in current pyatv. §14 above is new content not present in any of the four prerequisite reports.

5. **`mrp-companion.md:551`'s "open question" about the data-channel `seqno` is now closed, not open.** It correctly identified that `send_seqno` is set once and asked whether real devices "require a monotonically-increasing `seqno` per outbound frame ... or tolerate a fixed value" — this document does not have a live-device answer either (§16.2's gap applies equally here), but the **source-level fact** that pyatv sends the identical fixed `seqno` on every outbound frame for the lifetime of a tunnel session (`channels.py:235`, never mutated after `__init__`) is confirmed exact, not merely observed-and-uncertain. Whether real tvOS 27 firmware tolerates this is still unverified and remains a live risk (§16.2), but the Python-source-level ambiguity itself is resolved.

6. **This document's User-Agent strings differ by exact call site, which the prerequisite reports do not distinguish.** `mrp-companion.md:273` states the pair-verify request uses `User-Agent: AirPlay/320.20` — correct for `/pair-verify`/`/pair-setup`/`/pair-pin-start` (`auth/hap.py:21`, `auth/hap_transient.py:24`, `auth/legacy.py:20`), but the RTSP `SETUP`/`RECORD`/`FEEDBACK` exchanges on the same control connection use a **different** `User-Agent: AirPlay/550.10` (`pyatv/support/rtsp.py:22`). Both strings are correct for their respective call sites; a Rust port must not use one uniformly for the whole control-connection session.

7. **`FEEDBACK` is a bare `POST /feedback`, not an RTSP `SET_PARAMETER`-family verb.** `RtspSession.feedback()` (`pyatv/support/rtsp.py:246-248`) issues `POST` to the literal path `/feedback`, not the session's `rtsp://…` URI used by `SETUP`/`RECORD`/`ANNOUNCE`/etc. — worth stating precisely since "FEEDBACK request" in the task brief could plausibly be misread as another RTSP method name.

8. **`send_button`/`SEND_BUTTON_EVENT_MESSAGE` is dead code**, not documented as such anywhere upstream. §9.8 above is new content.

9. **No correction needed, but new content**: `hap-pairing-port-spec.md` §4/§5 already correctly documents that MRP and Companion do not use `HAPSession`, and this document's §4/§7/§8.2 rely on that finding directly rather than re-deriving it — cited here so the two documents are read as consistent rather than duplicative.

---

## Divergences & open questions

- **No known-good byte-level test exists for the AirPlay tunnel bring-up sequence or data-channel framing anywhere in pyatv's own test suite** (§16.2). Every claim in §3–§7 is verified against source code behavior, not against a passing automated test that exercises it end-to-end. **Recommendation**: before trusting a Rust `TunnelMrpTransport` against real hardware, capture a real pairing + tunnel-bringup + button-press session with pyatv's own `atvproxy` MITM tool (`pyatv/scripts/atvproxy.py`, referenced but not read in this pass) against the LAN test device, and build a capture-based known-answer test from it — mirroring the pattern `mrp-protobuf-spike.md` §7 already used for the protobuf-extension layer and `hap-pairing-port-spec.md` §10 used for the crypto layer.
- **`send_seqno` fixed-vs-incrementing is unverified against real hardware** (Correction 5). If tvOS 27 firmware silently drops or resets a tunnel session that reuses a `seqno`, this would be a real interop bug in pyatv itself that a byte-faithful Rust port would inherit; if a Rust port instead "fixes" this by incrementing per-frame, it diverges from the reference implementation in a way that could itself be wrong. Decide deliberately, and verify against a live capture rather than guessing either way.
- **`is_remote_control_supported`'s model/version heuristic is pyatv's own acknowledged guess** (§2.3, `utils.py:160-164`'s `# TODO`), not a documented Apple protocol behavior. A Rust port inherits the same uncertainty; if it diverges from pyatv's exact `AppleTV*`/`AudioAccessory*`/`osvers>=13.0` checks, it risks either attempting doomed tunnel setups or skipping tunnels on devices that would have supported them, with no way to verify correctness short of testing against a range of real hardware/firmware combinations pyatv's own maintainers have not exhaustively enumerated either.
- **`hidEventData`'s fixed literal blob is unexplained and untyped** (§9.7) — pyatv's own source treats it as an opaque byte string the device "does not seem to care much about," with the timestamp field specifically called out as not-really-a-timestamp. A Rust port has no better information available than pyatv does here; replicate the literal exactly and do not attempt to derive semantic meaning for the padding bytes.
- **The `PlayerState.handle_content_item_update` repeated-field `MergeFrom` behavior is pyatv's own flagged-as-likely-wrong quirk** (§10, `player_state.py:118-121`'s own comment). A Rust port must choose explicitly whether to replicate append-semantics for repeated metadata fields (e.g. duplicate accumulation across updates) or implement field-level replacement instead — this is a behavioral decision with observable consequences (duplicate values accumulating over a long-running session), not a wire-format requirement.
- **tvOS-era connectivity fixes, as far as this checkout's own changelog documents them.** `CHANGES.md` (read in full for this pass) does **not** contain any entry naming tvOS 26 or tvOS 27 specifically, nor any entry describing an RTSP heartbeat desync bug by that name — so the task brief's framing of "open, unresolved tvOS-26-era issues" cannot be independently confirmed against this checkout's own release notes and should be treated as external context (upstream GitHub issue tracker, not mined in this pass) rather than something this document re-verifies. What the changelog **does** show, precisely: `CHANGES.md:1-11` — release **0.18.0 "Willie" (2026-06-19)**, the most recent entry in this checkout, is described in its own release notes as carrying "some overdue changes needed for compatibility with newer versions of tvOS," yet its actual commit list (`CHANGES.md:13-47`) contains no AirPlay- or MRP-tunnel-specific commits at all — the tvOS-compatibility claim in the prose is not obviously backed by a corresponding code change in this release, which is itself worth flagging as a gap between pyatv's stated intent and its diff. More concretely actionable: `CHANGES.md:196-197` (release **0.16.1 "Uter" (2025-07-12)**) states its purpose as fixing "Connection issues with tvOS 18.4+" and lists exactly one AirPlay commit as the fix — `e27164ba airplay: Add setting for MRP tunnel` — meaning **the `MrpTunnel` setting itself (`Auto`/`Force`/`Disable`, §2.3) was introduced specifically as a workaround for a tvOS-18.4-era connectivity regression**, not merely as a convenience toggle. A Rust port should treat `MrpTunnel::Force` as a load-bearing escape hatch for exactly this class of future firmware regression, not an obscure option to deprioritize.
- **Whether the AirPlay tunnel's `enable_encryption` no-op (§7, point 2) is the *correct* design or merely what pyatv happens to do** is worth a deliberate Rust-port decision: since MRP's own pair-verify still runs its full TLV8 exchange over the tunnel purely for protocol-state-machine parity with the device (the device apparently still expects to see it even though the resulting keys go unused), a Rust port must implement that exchange too, not skip it as "pointless" — skipping it would likely cause the device to reject the connection at the MRP layer even though the transport itself is already secure.
