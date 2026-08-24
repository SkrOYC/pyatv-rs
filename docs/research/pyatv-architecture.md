# pyatv architecture and public API surface

Research date: 2026-08-24. Sources: [pyatv.dev](https://pyatv.dev/), [github.com/postlund/pyatv](https://github.com/postlund/pyatv) (master branch, commit range current as of pyatv v0.18.0 "Willie", released 2026-06-19), and [pypi.org/project/pyatv](https://pypi.org/project/pyatv/). This document is written for engineers implementing a pure-Rust reimplementation of pyatv and assumes no prior context beyond the target repo.

## 1. What pyatv is, at a glance

pyatv is an asyncio Python library ("a client library for Apple TV and AirPlay devices") that discovers, pairs with, and controls Apple TV and AirPlay-capable devices (Apple TV boxes, HomePod, HomePod mini, AirPort Express) over five wire protocols, and exposes them behind one unified async interface. Current release is **v0.18.0 "Willie"** (2026-06-19); prior recent releases: v0.17.0 "Velma" (2026-01-21), v0.16.1 "Uter" (2025-07-12), v0.16.0 "Troy" (2024-11-04), v0.15.1/v0.15.0 (2024), v0.14.x (2023). Source: [Releases · postlund/pyatv](https://github.com/postlund/pyatv/releases). PyPI metadata: requires Python >=3.9, officially supports 3.9–3.14, MIT licensed. Source: [pypi.org/project/pyatv](https://pypi.org/project/pyatv/).

## 2. Top-level module layout (pyatv/ package)

Confirmed via `gh api repos/postlund/pyatv/contents/...` against master:

- `pyatv/__init__.py` — the three public entry points: `scan()`, `pair()`, `connect()`.
- `pyatv/interface.py` — all abstract public-facing classes (the facade contract described in §4).
- `pyatv/const.py` — every enum used across the public API (Protocol, FeatureName, FeatureState, PowerState, DeviceState, MediaType, RepeatState, ShuffleState, PairingRequirement, InputAction, KeyboardFocusState, TouchAction, OperatingSystem, DeviceModel). See §5.
- `pyatv/conf.py` — concrete `BaseConfig`/`BaseService` implementations (`AppleTV`, `ManualService`, and legacy per-protocol `*Service` classes).
- `pyatv/core/` — internal plumbing shared by all protocols: `facade.py` (FacadeAppleTV + per-interface facades), `relayer.py` (generic `Relayer[T]` priority-selection helper), `scan.py` (mDNS scanning base classes), `mdns.py` (raw mDNS/DNS-SD implementation), `protocol.py` (`MessageDispatcher`, `heartbeater`).
- `pyatv/protocols/` — one subpackage per wire protocol: `airplay/`, `companion/`, `dmap/`, `mrp/`, `raop/`. Each exposes a `setup()` function returning `core.SetupData` plus a `scan()` function registering mDNS handlers.
- `pyatv/auth/hap_srp.py` — shared HAP/SRP pairing and encryption primitives used by MRP, Companion, and AirPlay (see §7).
- `pyatv/support/` — protocol-agnostic helpers: `net.py` (socket helpers), `dns.py`, `http.py`, `rtsp.py`, `opack.py` (OPACK serialization for Companion), `chacha20.py` (ChaCha20 cipher wrapper), `variant.py`, `packet.py`, `state_producer.py` (pub/sub base for listener interfaces), `device_info.py`, `knock.py` (TCP "knock" to wake devices before scanning), `cache.py`, `buffer.py`, `metadata.py`, `collections.py`, `url.py`, `shield.py`, `pydantic_compat.py`.
- `pyatv/storage/` — persistent settings/credentials API (see §8): `__init__.py` (`Storage`, `AbstractStorage`, `StorageModel`), `file_storage.py` (`FileStorage`).
- `pyatv/scripts/` — CLI entry points: `atvremote.py`, `atvscript.py`, `atvproxy.py`, `atvlog.py` (see §10).
- `pyatv/exceptions.py` — exception hierarchy (`NotSupportedError`, `DeviceIdMissingError`, etc.).

## 3. The scan → pair → connect flow

Public entry points, exact signatures from `pyatv/__init__.py` on master:

```python
async def scan(
    loop: asyncio.AbstractEventLoop,
    timeout: int = 5,
    identifier: Optional[Union[str, Set[str]]] = None,
    protocol: Optional[Union[Protocol, Set[Protocol]]] = None,
    hosts: Optional[List[str]] = None,
    aiozc: Optional[AsyncZeroconf] = None,
    storage: Optional[Storage] = None,
) -> List[interface.BaseConfig]: ...

async def connect(
    config: interface.BaseConfig,
    loop: asyncio.AbstractEventLoop,
    protocol: Optional[Protocol] = None,
    session: Optional[aiohttp.ClientSession] = None,
    storage: Optional[Storage] = None,
) -> interface.AppleTV: ...

async def pair(
    config: interface.BaseConfig,
    protocol: Protocol,
    loop: asyncio.AbstractEventLoop,
    session: aiohttp.ClientSession = None,
    storage: Optional[Storage] = None,
    **kwargs,
) -> interface.PairingHandler: ...
```

Source: [pyatv/__init__.py](https://github.com/postlund/pyatv/blob/master/pyatv/__init__.py).

### Discovery (`pyatv/core/scan.py`, `pyatv/core/mdns.py`)

Discovery is built on mDNS/DNS-SD (Bonjour). There are two scanner classes:

- `MulticastMdnsScanner` — broadcasts standard mDNS queries on the LAN via `mdns.multicast()`; can terminate early once a matching `identifier` is seen among responses.
- `UnicastMdnsScanner` — sends unicast mDNS queries directly to specific IPs via `mdns.unicast()` (used for `--scan-hosts`/`hosts=` scanning, and by default on networks where multicast is unreliable, e.g. Docker/VLANs). Before querying, it optionally performs a TCP "knock" (a raw connect-then-close) against a fixed set of ports — **3689, 7000, 49152, 32498** — to nudge sleeping devices into responding to mDNS. Source: `pyatv/support/knock.py`, `pyatv/core/scan.py` (fetched from `raw.githubusercontent.com/postlund/pyatv/master/pyatv/core/scan.py`).

Each protocol registers, per mDNS service type, a `ScanHandler` (`(mdns.Service, mdns.Response) -> Optional[Tuple[name, MutableService]]`) and a `DevInfoExtractor` (`(service_type, properties) -> Mapping[str, Any]`) via `add_service()`. The confirmed mDNS service (`_type._proto.local`) strings, extracted directly from each protocol's `__init__.py` on master via `gh api`:

| Protocol | mDNS service type(s) |
|---|---|
| MRP | `_mediaremotetv._tcp.local` |
| Companion | `_companion-link._tcp.local` |
| AirPlay | `_airplay._tcp.local` |
| RAOP | `_raop._tcp.local`, plus `_airport._tcp.local` (used to enrich AirPort Express device info) |
| DMAP | `_appletv-v2._tcp.local` (home sharing), `_touch-able._tcp.local`, `_hscp._tcp.local` |
| (common) | `_device-info._tcp.local`, `_sleep-proxy._udp.local` (device-info/low-power enrichment, not protocol-specific) |

`BaseScanner.discover()` groups all discovered services by IP, merges per-service `DevInfoExtractor` output into one `DeviceInfo`, and materializes one `conf.AppleTV` (`interface.BaseConfig` implementation) per physical device with all its discovered `BaseService`/`MutableService` entries attached. **Ports are not hardcoded** (except as knock targets above) — each service's real TCP/UDP port is read out of the mDNS SRV record at discovery time (`mdns_service.port`), because Apple TV/AirPlay devices commonly listen on ephemeral high ports (MRP typically ≥49152; Companion similarly high; AirPlay commonly on 7000 but not guaranteed).

### Pairing (`pyatv/interface.py::PairingHandler`, per-protocol `pairing.py`)

`pair()` looks up the protocol's setup module and returns a `PairingHandler` (one concrete subclass per protocol) exposing: `device_provides_pin: bool`, `has_paired: bool`, `pin(pin: int)`, async `begin()`, async `finish()`, async `close()`. Two pairing families exist:

- **HAP/SRP pairing** (MRP, Companion, and AirPlay-with-PIN): a PIN is displayed on the TV/speaker, the client runs the SRP-6a exchange described in §7, and long-term Ed25519 keys + derived credentials are produced and persisted.
- **Legacy DMAP pairing**: HTTP-based, no PIN dialog in the same sense (uses a "pairing code" typed into the client, hashed to authenticate).

Successful pairing writes credentials into the `Storage` (§8) automatically as of v0.14.0; callers no longer need to manually thread credential strings through.

### Connect (`pyatv/__init__.py::connect`, `pyatv/core/facade.py`)

`connect()` iterates the device's enabled services, calls each protocol module's `setup()` to obtain a `core.SetupData` NamedTuple:

```python
SetupData(
    protocol: Protocol,
    connect: Callable[[], Awaitable[bool]],
    close: Callable[[], Set[asyncio.Task]],
    device_info: Callable[[], Dict[str, Any]],
    interfaces: Mapping[Any, Any],
    features: Set[FeatureName],
)
```

Each `SetupData` is registered into a `FacadeAppleTV` via `add_protocol()`; `connect` is invoked for every protocol and, if it returns `True`, that protocol's `interfaces` mapping is registered into the corresponding per-capability `Relayer` (RemoteControl, Metadata, Power, etc.) inside the facade. The fully-assembled `FacadeAppleTV` (an `interface.AppleTV` implementation) is what callers receive — they never see individual protocol clients directly. Source: `pyatv/core/facade.py` (fetched from raw.githubusercontent.com), `pyatv/core/__init__.py`.

## 4. The public interface surface (`pyatv/interface.py`)

All abstractions engineers must reimplement live here as ABCs; `FacadeAppleTV` and its sub-facades implement them by relaying to whichever protocol backs a given call. Key classes and their contracts (method/property names, confirmed against `pyatv/interface.py` on master):

- **`BaseConfig`** — a discovered/constructed device: name, address, identifier, list of `BaseService`, `get_service(protocol)`, `main_service()`.
- **`BaseService`** (ABC) — one protocol's connection info for a device: `identifier`, `protocol: Protocol`, `port: int`, `enabled: bool` (get/set), abstract `requires_password: bool`, abstract `pairing: PairingRequirement`, `properties: Mapping[str, str]`, `merge()`, `settings()`/`apply()` (bridges to storage), abstract `__deepcopy__`. Mutable internal variant is `core.MutableService`.
- **`PairingHandler`** (ABC) — see §3.
- **`AppleTV`** (ABC) — the root facade object exposing: `remote_control: RemoteControl`, `metadata: Metadata`, `push_updater: PushUpdater`, `stream: Stream`, `power: Power`, `apps: Apps`, `audio: Audio`, `keyboard: Keyboard`, `touch_gestures: TouchGestures`, `user_accounts: UserAccounts`, `features: Features`, `device_info: DeviceInfo`, `service: BaseService`, `close()`.
- **`RemoteControl`** — navigation/media transport methods, each decorated `@feature` (ties the method to a `FeatureName` for the `Features` facade): `up/down/left/right(action: InputAction = SingleTap)`, `play()`, `play_pause()`, `pause()`, `stop()`, `next()`, `previous()`, `select()`, `menu()`, `home()`, `home_hold()`, `top_menu()`, `skip_forward(time_interval)`, `skip_backward(time_interval)`, `set_position(pos)`, `set_shuffle(state)`, `set_repeat(state)`, `channel_up()`, `channel_down()`, `screensaver()`, `guide()`, `control_center()`.
- **`Playing`** (ABC) — a snapshot of "what's playing": `media_type`, `device_state`, `title`, `artist`, `album`, `genre`, `total_time`, `position`, `shuffle`, `repeat`, `series_name`, `season_number`, `episode_number`, `content_identifier`, `itunes_store_identifier` (added in v0.16.0, source: [Add iTunesStoreIdentifier](https://github.com/postlund/pyatv/releases/tag/v0.16.0)), `hash`.
- **`Metadata`** — `device_id`, async `artwork(width, height) -> Optional[ArtworkInfo]`, `artwork_id`, async `playing() -> Playing`, `app: Optional[App]`.
- **`PushUpdater`** (ABC, extends `StateProducer`) — `active: bool`, `start(initial_delay=0)`, `stop()`; listeners implement `playstatus_update(updater, playing)`/`playstatus_error(updater, exception)`.
- **`Stream`** — `close()`, async `play_url(url, **kwargs)` (AirPlay video), async `stream_file(file, metadata=None, override_missing_metadata=None, **kwargs)` (RAOP audio; accepts a path, file-like, or `-` for stdin).
- **`Power`** (ABC, extends `StateProducer`) — `power_state: PowerState`, async `turn_on(await_new_state=False)`, async `turn_off(await_new_state=False)`.
- **`Apps`** — async `app_list() -> List[App]`, async `launch_app(bundle_id_or_url)`.
- **`Audio`** — volume get/set, listener-based volume-change notifications, and (since v0.17.0) per-connected-device volume control for AirPlay 2 multi-room groups.
- **`Keyboard`** — text-entry focus state (`KeyboardFocusState`) and text get/set for on-screen keyboard sessions (Companion only).
- **`TouchGestures`** — low-level `TouchAction` (Press/Hold/Release/Click) swipe/click primitives, used for the trackpad-style remote surface.
- **`UserAccounts`** — async `account_list() -> List[UserAccount]`, async `switch_account(account_id)`.
- **`Features`** — `get_feature(FeatureName) -> FeatureInfo`, `all_features()`; backed by `FacadeFeatures.add_mapping()` which unions the `features: Set[FeatureName]` each protocol's `SetupData` declared as supported.
- **`DeviceInfo`** — `operating_system: OperatingSystem`, `version`, `build_number`, `model: DeviceModel`, `mac`.
- **`OutputDevices`**/output-device management — `output_devices`, `add_output_devices()`, `remove_output_devices()`, `set_output_devices()` for AirPlay 2 speaker-group management (multi-room audio).

Source: fetched directly from [pyatv/interface.py](https://github.com/postlund/pyatv/blob/master/pyatv/interface.py) on master, cross-checked against the [atvremote CLI docs](https://pyatv.dev/documentation/atvremote/) which exercise nearly every one of these methods.

## 5. Enums (`pyatv/const.py`)

Confirmed exact values from master:

- **`Protocol`**: `DMAP=1`, `MRP=2`, `AirPlay=3`, `Companion=4`, `RAOP=5`.
- **`MediaType`**: `Unknown=0`, `Video=1`, `Music=2`, `TV=3`.
- **`DeviceState`**: `Idle=0`, `Loading=1`, `Paused=2`, `Playing=3`, `Stopped=4`, `Seeking=5`.
- **`RepeatState`**: `Off=0`, `Track=1`, `All=2`.
- **`ShuffleState`**: `Off=0`, `Albums=1`, `Songs=2`.
- **`PowerState`**: `Unknown=0`, `Off=1`, `On=2`.
- **`KeyboardFocusState`**: `Unknown=0`, `Unfocused=1`, `Focused=2`.
- **`OperatingSystem`**: `Unknown=0`, `Legacy=1`, `TvOS=2`, `AirPortOS=3`, `MacOS=4`.
- **`DeviceModel`**: `Unknown=0`, `Gen2=1`, `Gen3=2`, `Gen4=3`, `Gen4K=4`, `HomePod=5`, `HomePodMini=6`, `AirPortExpress=7`, `AirPortExpressGen2=8`, `Music=10`, `AppleTV4KGen2=9`, `AppleTVGen1=13`, `AppleTV4KGen3=11`, `HomePodGen2=12`.
- **`InputAction`**: `SingleTap=0`, `DoubleTap=1`, `Hold=2`.
- **`PairingRequirement`**: `Unsupported=1`, `Disabled=2`, `NotNeeded=3`, `Optional=4`, `Mandatory=5`.
- **`FeatureState`**: `Unknown=0`, `Unsupported=1`, `Unavailable=2`, `Available=3`.
- **`TouchAction`**: `Press=1`, `Hold=3`, `Release=4`, `Click=5`.
- **`FeatureName`**: a large (50+ entries) enum, one value per `@feature`-decorated method/property across `RemoteControl`, `Playing`/`Metadata`, `Power`, `Apps`, `Audio`, `Keyboard`, `TouchGestures`, `UserAccounts`, e.g. `Up`, `Down`, `Play`, `PlayPause`, `VolumeUp`, `Home`, `SetPosition`, `Title`, `Artwork`, `PowerState`, `TurnOn`, `App`, `SkipForward`, `LaunchApp`, `Volume`, `SetVolume`, `TextGet`, `AccountList`, `Screensaver`, `OutputDevices`, `Swipe`, `Click`, `Guide` (added v0.17.0), `ControlCenter` (added v0.17.0), `ItunesStoreIdentifier` (added v0.16.0). Implementers should treat this enum as authoritative for what the `Features` facade must be able to report per protocol; enumerate the current full list directly from `pyatv/const.py` at implementation time since it grows across releases.

Source: fetched from `raw.githubusercontent.com/postlund/pyatv/master/pyatv/const.py`.

## 6. Protocol relaying: how one facade covers five protocols

This is the architectural core an implementer must replicate.

### `core.relayer.Relayer[T]`

A generic class: `Relayer(base_interface: Type[T], protocol_priority: List[Protocol])`. Internally it holds a `Dict[Protocol, T]` of registered protocol implementations. `relay(target_method_name, priority=None)` walks the priority list (or an override) and returns a bound callable/property from the **first** protocol instance that actually implements `target_method_name`; if none do, it raises `NotSupportedError`. Other members: `get(protocol) -> Optional[T]`, `register(instance, protocol)`, `main_instance` (highest-priority registered instance, raises if none), and a temporary-override pair `takeover(protocol)` / `release()` used e.g. when a specific protocol must be forced to answer a call regardless of normal priority. Source: `pyatv/core/relayer.py`.

### `core.facade.FacadeAppleTV` and friends

`FacadeAppleTV` is the concrete `interface.AppleTV` built by `connect()`. It owns one `Relayer` per capability (`FacadeRemoteControl`, `FacadeMetadata`, `FacadePower`, `FacadeApps`, `FacadeAudio`, `FacadeKeyboard`, `FacadeTouchGestures`, `FacadeUserAccounts`, `FacadeFeatures`, `FacadePushUpdater`, `FacadeStream`), each subclassing `Relayer` with a priority list.

**Default priority order:** `DEFAULT_PRIORITIES = [MRP, DMAP, Companion, AirPlay, RAOP]` — meaning if two protocols both implement a given method, MRP wins by default (it's the richest, tvOS-native remote/metadata protocol). Individual facades override this default when it doesn't make sense: `FacadePower` prefers Companion over MRP (Companion's power semantics are considered more reliable/robust for actual power state on modern tvOS); `FacadeApps` and `FacadeKeyboard` are Companion-only in practice (only Companion implements app listing/launching and keyboard text entry); `FacadeStream` splits by call (AirPlay for `play_url`, RAOP for `stream_file` — these don't overlap so no real "priority" contention exists there).

Individual facade methods are one-liners that call `self.relay("method_name")(...)`, e.g.:

```python
async def up(self, action: InputAction = InputAction.SingleTap) -> None:
    return await self.relay("up")(action=action)
```

`FacadeFeatures.add_mapping()` accumulates, per protocol, the `Set[FeatureName]` each protocol declared in its `SetupData`, so `Features.get_feature()` can answer "available/unavailable/unsupported" per feature by checking which protocol(s), if any, are connected and support it.

`FacadePushUpdater` does **not** relay per-call like the others — because push updates are asynchronous callbacks, not request/response calls. Instead it registers itself as the single listener on every connected protocol's own push-updater, and only forwards the "main instance" protocol's callbacks to the user's registered listener, so a caller never receives duplicate/conflicting updates from two protocols racing each other.

State-change facades (`FacadeAudio`, `FacadeKeyboard`, `FacadePower`) additionally subscribe to a `CoreStateDispatcher`/`ProtocolStateDispatcher` (in `pyatv/core/__init__.py`) which carries `StateMessage(protocol, state: UpdatedState, value)` NamedTuples from protocol internals up to the facade layer, decoupling "a protocol's internal state changed" from "the public listener API fires."

Source: fetched from `raw.githubusercontent.com/postlund/pyatv/master/pyatv/core/facade.py` and `.../pyatv/core/__init__.py`.

### Implication for a Rust port

The Rust equivalent needs, at minimum: (1) a trait per capability (RemoteControl, Metadata, …) mirroring `interface.py`; (2) a generic priority-ordered registry (trait-object map keyed by an enum, analogous to `Relayer<T>`) per capability; (3) one "facade" struct implementing every trait by delegating to the registry; (4) a push/event dedup layer equivalent to `FacadePushUpdater` — since in Rust this is naturally an `mpsc`/broadcast channel fed by whichever protocol is authoritative, rather than a listener-forwarding object.

## 7. Wire protocols

All five protocols and their confirmed characteristics:

### DMAP (Digital Media Access Protocol)
- Legacy protocol for Apple TV (1st–3rd gen) and old iTunes home-sharing, tvOS ≤ 12 era devices/`Legacy` `OperatingSystem`.
- HTTP-based, custom binary TLV ("tag-length-value") response bodies.
- mDNS types: `_appletv-v2._tcp.local` (home sharing), `_touch-able._tcp.local`, `_hscp._tcp.local`.
- Historically fixed at TCP port 3689, but pyatv reads the actual port from mDNS at scan time.
- Considered legacy/frozen by pyatv: `conf.DmapService` is deprecated in favor of `conf.ManualService` since pyatv 0.9.0 (protocol-specific `*Service` constructors are deprecated wrappers, not a sign DMAP itself is being removed). Source: found via code search of `pyatv/exceptions.py`/`pyatv/conf.py` deprecation notices; no GitHub issue was found proposing full DMAP removal as of 2026-08.

### MRP (Media Remote Protocol)
- The modern native remote/now-playing protocol for tvOS 4th-gen-and-later Apple TVs (`_mediaremotetv._tcp.local`). Protobuf-framed messages over a persistent TCP connection (length-prefixed protobuf, not HTTP). `pyatv/protocols/mrp/protobuf/` holds the generated protobuf bindings, regenerated per release (`mypy-protobuf`, `protobuf` python package — pyatv v0.18.0 pins `protobuf` 6.33.x per `requirements/` bumps observed in the changelog).
- Authenticates using the shared HAP/SRP pairing flow (§ below) since it requires a persistent, encrypted, authenticated TCP channel.
- Default facade priority winner for RemoteControl/Metadata/PushUpdater when connected, per `DEFAULT_PRIORITIES`.

### Companion (Companion Link)
- Used for app launch/list, power state (preferred over MRP in the facade), keyboard text entry, and the iOS/Shortcuts-style "Companion" widget in Control Center. mDNS type `_companion-link._tcp.local`.
- Message framing: type + big-endian length + payload; payloads are OPACK-serialized (`pyatv/support/opack.py`) after an initial `PA_Start`/`PA_Next` (pair-setup) and `PV_Start`/`PV_Next` (pair-verify) HAP/SRP handshake identical in cryptographic structure to HomeKit/HAP pairing (see §7.1). Post-verification traffic is encrypted with ChaCha20Poly1305 using per-direction sequence numbers encoded little-endian in an 8-byte nonce field.
- A `PAIRING_WITH_PIN_SUPPORTED_MASK = 0x4000` flag (confirmed in `pyatv/protocols/companion/__init__.py`) is read from the mDNS TXT/flags to detect whether a given Companion service actually needs a PIN dialog (some devices support "transient"/PIN-less pairing).
- One open community observation (issue tracker, unconfirmed by maintainers): some third-party tvOS apps (e.g. Netflix) may report now-playing metadata over Companion rather than MRP — relevant to future feature-coverage/priority decisions. Source: [pyatv#2888](https://github.com/postlund/pyatv/issues/2888).

### AirPlay (v1 legacy + AirPlay 2)
- mDNS type `_airplay._tcp.local`. RTSP is used for session setup/control; actual media flows over a separate UDP/TCP stream depending on codec/mode.
- AirPlay 2 devices additionally expose an MRP-over-AirPlay "event"/"data" channel used for some remote-control relaying, and use HAP-style pairing (`pyatv/protocols/airplay/auth/hap.py`) as well as a **transient pairing** mode (`pyatv/protocols/airplay/auth/hap_transient.py`) — an ephemeral, PIN-less pair-verify used to establish a short-lived encrypted session purely for streaming, without persisting long-term credentials. There is also a `legacy.py` auth path for AirPlay v1 devices that predate HAP (older AirPort Express units).
- `Stream.play_url()` is backed by AirPlay.
- Known regression as of 2026-08: `play_url` failing with HTTP 500 on `/playback-info` against tvOS 26, and AirPlay RTSP `/feedback` heartbeat losing sync on tvOS 26.5 — both open, unresolved upstream issues, signalling that Apple's tvOS 26 AirPlay stack has changed in ways pyatv hasn't fully caught up with yet. Sources: [pyatv#2906](https://github.com/postlund/pyatv/issues/2906), [pyatv#2893](https://github.com/postlund/pyatv/issues/2893).

### RAOP (Remote Audio Output Protocol / AirTunes)
- mDNS type `_raop._tcp.local` (plus `_airport._tcp.local` for AirPort Express device-info enrichment). RTSP-based audio-only streaming protocol (the audio-only ancestor of AirPlay). Backs `Stream.stream_file()` and volume-only `RemoteControl`. Optional password auth via `--raop-password`/`requires_password`.
- Uses `pyatv/support/rtsp.py` for the RTSP layer and `tinytag` (Python dependency, replaced `mediafile` in v0.16.0 because `mediafile` pulled in Python's removed `imghdr` module) for reading source-file metadata to attach to the stream.

### 7.1 Shared HAP/SRP cryptography (`pyatv/auth/hap_srp.py`)

This is the single most implementation-critical piece of crypto shared by MRP, Companion, and AirPlay pairing. Confirmed directly from `pyatv/auth/hap_srp.py` on master:

- **Key exchange**: X25519 (Curve25519 ECDH), via `X25519PrivateKey`/`X25519PublicKey`.
- **Signatures**: Ed25519, via `Ed25519PrivateKey`/`Ed25519PublicKey` (used to sign/verify the exchanged public keys as part of the HAP pair-setup identity proof — standard HomeKit Accessory Protocol pattern).
- **SRP (Secure Remote Password)**: 3072-bit group (`constants.PRIME_3072`, `constants.PRIME_3072_GEN`), hash function SHA-512, used only during pair-setup (PIN-based) to derive a shared secret from which the long-term keys are then bootstrapped — this is the same SRP-6a construction HomeKit pair-setup uses.
- **Key derivation**: HKDF, with exact salt/info string literals (quoted verbatim from source):
  - Pair-Verify session key: salt `"Pair-Verify-Encrypt-Salt"`, info `"Pair-Verify-Encrypt-Info"`.
  - Pair-Setup controller-sign key: salt `"Pair-Setup-Controller-Sign-Salt"`, info `"Pair-Setup-Controller-Sign-Info"`.
  - Pair-Setup session encryption key: salt `"Pair-Setup-Encrypt-Salt"`, info `"Pair-Setup-Encrypt-Info"`.
- **Symmetric cipher**: ChaCha20 (note: HAP historically uses ChaCha20-Poly1305; pyatv's wrapper class is named `Chacha20Cipher8byteNonce`, i.e. an 8-byte-nonce variant, matching HAP's non-standard nonce framing rather than the IETF 12-byte-nonce ChaCha20-Poly1305 variant). Per-message nonces during the handshake are the literal ASCII strings `"PV-Msg02"`, `"PV-Msg03"`, `"PS-Msg05"`, `"PS-Msg06"` (encoded UTF-8, zero-padded to nonce length) — these are HAP-spec-standard nonce labels, not pyatv inventions.
- **Class shape**: `SRPAuthHandler` with `initialize()`, `step1(pin)`, `step2()`, `step3()`, `step4()` (pair-setup state machine) and `verify1()`, `verify2()` (pair-verify state machine); returns/holds a `HapCredentials` dataclass (device identity, long-term public key, session keys) that is what actually gets persisted to `Storage`.
- Companion additionally frames the handshake with explicit message-type bytes `PA_Start`/`PA_Next` (pair-setup) and `PV_Start`/`PV_Next` (pair-verify) around the same underlying SRP/HAP state machine — i.e. Companion and MRP/AirPlay share the crypto core but differ in outer framing.

**Rust implication**: this maps directly onto `x25519-dalek` (X25519), `ed25519-dalek` (Ed25519), an SRP-6a crate or a small hand-rolled implementation against the RFC 5054 3072-bit group, `hkdf` + `sha2`, and `chacha20poly1305` — but implementers must verify byte-for-byte compatibility with the HAP spec's *8-byte nonce* framing (not the standard 12-byte IETF ChaCha20-Poly1305 nonce) since a mismatch there is a classic interop bug. Confirm any chosen crate's nonce-length flexibility against docs.rs before committing, and validate against a real device or against pyatv's own test fixtures.

## 8. Storage / credentials persistence

Introduced as a first-class API in pyatv v0.14.0 ("Lisa", 2023-09-04) — before that, callers had to manually pass credential strings on every `connect()`. Confirmed structure from `pyatv/storage/__init__.py` and `pyatv/storage/file_storage.py` (fetched from master):

- **`Storage`** — presumed minimal abstract protocol (load/save contract); **`AbstractStorage`** implements all storage-agnostic logic (change detection, settings CRUD) and leaves only the actual persistence I/O (`load()`/`save()`) to subclasses.
- **`StorageModel`** — a Pydantic `BaseModel` with `version: int` (currently `MODEL_VERSION = 1`) and `devices: List[Settings]`. Pydantic v2 only as of v0.17.0 (pydantic v1 support was dropped that release).
- Change detection: `AbstractStorage` computes a SHA-256 hash (`_dict_hash`) of the JSON-serialized model on load, and `has_changed()` compares against the current hash so `save()` can be a no-op when nothing changed.
- Per-device settings access: `get_settings(config: BaseConfig) -> Settings` (raises `DeviceIdMissingError` if the config has no identifiers yet — i.e. you generally need to have scanned/discovered a device, not hand-built one, before its settings can be looked up), `remove_settings(settings)`, `update_settings(config)` which pulls protocol-specific fields (AirPlay/DMAP/Companion/MRP/RAOP credentials, passwords, etc.) out of each `BaseService` back into the stored model.
- **`FileStorage(AbstractStorage)`** — concrete on-disk implementation. Default path is **`$HOME/.pyatv.conf`** (Windows: `C:\Users\<user>\.pyatv.conf`), one JSON document per file (not one file per device), written via `run_in_executor` (kept off the event loop) after validating round-trip through `StorageModel.model_validate()`.
- CLI-level operations exposed via `atvremote`: `print_settings`, `change_setting=path,value`, `unset_setting=path`, `remove_settings`, plus `--storage-filename <path>` and `--storage none` (disable persistence entirely) flags.

**Rust implication**: model this as a trait (`Storage`) with `load`/`save`, a default file-backed impl at the same `$HOME/.pyatv.conf`-equivalent-but-Rust-project-specific path (do not literally reuse `.pyatv.conf` unless deliberately aiming for pyatv file-format compatibility — the JSON schema is pyatv/Pydantic-specific and versioned via `MODEL_VERSION`), and a settings-diff/hash mechanism to avoid redundant writes. If cross-compatibility with existing pyatv credential files is a goal, the on-disk JSON shape must be reverse-engineered from `StorageModel`/`Settings` field-by-field — this report did not fully enumerate the `Settings` schema; treat as an open item (see §12).

## 9. Feature-to-protocol coverage matrix

Synthesized from [pyatv.dev/documentation/supported_features](https://pyatv.dev/documentation/supported_features/) and cross-checked against `DEFAULT_PRIORITIES`/facade overrides in §6. Treat exact per-feature granularity as needing re-verification against the live table at implementation time (it changes across releases), but the shape is stable:

| Capability | DMAP | MRP | Companion | AirPlay | RAOP |
|---|---|---|---|---|---|
| RemoteControl (nav/transport) | partial | full | partial (subset) | very limited | volume only |
| Metadata / now playing | yes | yes (richest) | no | no | partial |
| PushUpdater | yes | yes | no | no | yes |
| Stream (`play_url`) | no | no | no | yes | no |
| Stream (`stream_file`) | no | no | no | no | yes |
| Power | no | yes | yes (facade-preferred) | no | no |
| Apps (list/launch) | no | no | yes | no | no |
| Audio (volume) | no | partial | yes (per-device, v0.17+) | no | yes |
| Keyboard | no | no | yes | no | no |
| TouchGestures | no | no | yes | no | no |
| UserAccounts | no | no | yes | no | no |
| DeviceInfo | yes | yes | no | no | no |

Where both DMAP and MRP support a feature, MRP wins by default priority; where both MRP and Companion support Power, Companion wins by facade override.

## 10. CLI tools

- **`atvremote`** — the reference/testing CLI, supports essentially the full public API. Notable subcommands/flags (verified against [pyatv.dev/documentation/atvremote](https://pyatv.dev/documentation/atvremote/)): `wizard` (interactive scan+pair+save-credentials flow, added v0.14.0), `scan` (with `--scan-hosts`, `--scan-protocols`), device selection via `-i/--id`, `-n` (name), `-s` (address), `--manual` (bypass discovery, requires `--address --port --protocol --id`), `pair` (per `--protocol`), remote-control verbs as bare command args (`up`, `down`, `menu`, `play`, …, chainable with `delay=<ms>`), `playing`, `push_updates`, `version`, `device_info`, `features`, `app`, `app_list`, `launch_app=<bundle_id>`, `play_url=<url>`, `stream_file=<path|->` (supports stdin piping), `artwork_save=width,height,filename`, `turn_on`/`turn_off`/`power_state`, `output_devices`/`add_output_devices=`/`remove_output_devices=`/`set_output_devices=` (AirPlay 2 multi-room groups), storage commands (`print_settings`, `change_setting=`, `unset_setting=`, `remove_settings`, `--storage-filename`, `--storage none`), `commands`, `help <command>`, `--verbose`/`--debug`.
- **`atvscript`** — scripting-oriented subset of `atvremote`'s functionality with structured, machine-parseable **JSON** output. Every response is a dict with `result: "success"|"failure"`, `datetime` (ISO8601), and on failure `error` (a stable error-code string, e.g. `device_not_found`, `unsupported_command`) and/or `exception`/`stacktrace`. Supports `scan`, `playing`, remote-control verbs (all `RemoteControl` methods except the `set_*` setters), and `push_updates` (a JSON stream; reports `connection: "closed"`/`"lost"` on disconnect).
- **`atvproxy`** — a MITM/reverse-engineering helper, explicitly documented as unstable ("incubating script and may change behavior with short notice", relies on internal APIs). For AirPlay it publishes a fake mDNS device that a real client pairs with, then relays to the real device using independent encryption keys per hop (since AirPlay traffic is encrypted end-to-end and can't be sniffed passively). For Companion and MRP it fully decrypts and logs plaintext messages to the console since those protocols route entirely through pyatv-controlled endpoints in proxy mode. Uses a hardcoded private key + fixed PIN `1111` to make repeated re-pairing trivial during protocol research. Also offers a generic byte-level relay mode for arbitrary host-pairs. Source: [pyatv.dev/documentation/atvproxy](https://pyatv.dev/documentation/atvproxy/).
- **`atvlog`** — present in `pyatv/scripts/` (log-capture/formatting helper); not deeply documented on pyatv.dev, treat as low-priority for the Rust port (dev-support tool, not core functionality).

## 11. Version/compatibility notes and project direction (as of 2026-08-24)

- Current stable: **v0.18.0** (2026-06-19). Release notes describe it explicitly as bringing "overdue changes needed for compatibility with newer versions of tvOS," and the maintainer (postlund) states reduced personal bandwidth and is soliciting community PRs for bug fixes going forward — a signal that pyatv's own tvOS-26-era compatibility work is not fully caught up and is an active pain point, not a solved problem. Source: [pyatv v0.18.0 release notes](https://github.com/postlund/pyatv/releases/tag/v0.18.0).
- v0.17.0 (2026-01-21): added `Guide`/`ControlCenter` remote buttons, per-connected-device AirPlay 2 volume control, Python 3.14 official support, dropped Pydantic v1 support, modernized packaging.
- v0.16.x (2024): dropped Python 3.8, added Python 3.13, replaced the unmaintained `mediafile` dependency with `tinytag` (Python 3.13 removed the stdlib `imghdr` module that `mediafile` depended on), added `itunes_store_identifier` metadata field, full `InputAction` support in Companion.
- v0.14.0 (2023-09-04): introduced the built-in `Storage`/credential-persistence subsystem and the `atvremote wizard` guided setup — this was a major API/workflow shift (before it, all credentials were manually threaded through connect calls every time).
- **DMAP status**: legacy/frozen but not removed. `conf.DmapService` (and the other protocol-specific `conf.*Service` subclasses) have been deprecated in favor of `conf.ManualService` since pyatv 0.9.0 — this is a config-construction API deprecation, not evidence DMAP wire support itself is being dropped. No open GitHub issue proposing DMAP removal was found as of this research date.
- **Open, unresolved compatibility issues against tvOS 26** (current tvOS major version as of mid-2026), all still open at research time: [`play_url` fails on tvOS 26 with HTTP 500 on `/playback-info`, playback never starts](https://github.com/postlund/pyatv/issues/2906); [AirPlay RTSP session loses synchronization during `/feedback` heartbeat on tvOS 26.5](https://github.com/postlund/pyatv/issues/2893); [`atvremote wizard` error on launch, official Docker image affected, fix pending merge as of Aug 2026](https://github.com/postlund/pyatv/issues/2892); [identifier-based multicast discovery (`-i`) failing while unicast/independent mDNS clients succeed](https://github.com/postlund/pyatv/issues/2904); [Netflix now-playing metadata may route over Companion rather than MRP, breaking assumptions about protocol priority for that app](https://github.com/postlund/pyatv/issues/2888); [paused Netflix playback misreported as `DeviceState.Idle` because the paused state carries no content metadata](https://github.com/postlund/pyatv/issues/2888). A Rust implementation targeting current (2026) tvOS should expect to hit the same class of tvOS-26-era AirPlay/Companion quirks pyatv is currently debugging, and should not assume pyatv's existing protocol behavior is fully correct against the newest tvOS — cross-check against real devices.
- Dependency posture (informative, Python-side, not directly portable but indicates protocol library churn): pyatv v0.18.0 pins `protobuf` ~6.33.x, `cryptography` ~48–49.x, `aiohttp` ~3.13.x, `pydantic` ~2.13.x, `zeroconf` (Python mDNS library) ~0.148.x — these track the underlying Apple wire formats closely enough that protobuf schema bumps and cryptography-library bumps in pyatv's history are a decent proxy for "the protocol itself changed" versus "routine dependency hygiene"; the v0.18.0 changelog's MRP-protobuf-mypy fixes and RAOP `audio_source.py` error-handling fixes suggest ongoing small protocol-edge-case churn rather than a big-bang redesign.

## 12. Open questions

- The exact on-disk JSON schema of `StorageModel`/`Settings` (per-protocol field names, nesting) was not fully enumerated from source in this pass — needed if the Rust port aims for file-compatibility with existing `.pyatv.conf` credential files rather than just an equivalent-but-incompatible format.
- The full, current `FeatureName` enum (50+ values) should be re-extracted verbatim from `pyatv/const.py` at implementation start, not hand-copied from this report, since it grows every release (e.g. `Guide`/`ControlCenter` only added in v0.17.0).
- This report treats `Chacha20Cipher8byteNonce` as HAP's known 8-byte-nonce ChaCha20-Poly1305 variant by naming convention; the exact byte-level nonce construction (zero-padding side, counter placement) should be verified against `pyatv/support/chacha20.py` and, ideally, against the Apple HomeKit Accessory Protocol specification or a packet capture, before implementing — this is the single highest-risk spot for silent interop bugs.
- Whether AirPlay 2's MRP-over-AirPlay "data channel" (mentioned in the protocols doc) is a full second MRP protobuf transport distinct from the standalone MRP protocol's TCP channel, or a thin relay of the same message set, was not fully traced through source in this pass — matters for whether the Rust port can share one MRP-codec implementation across both transports.
- pyatv's precise behavior/fallback when multiple protocols disagree on `Metadata`/`Playing` state (beyond "priority wins") — e.g. whether it ever merges fields from a lower-priority protocol when the highest-priority one returns partial data — was not confirmed from source and should be checked in `FacadeMetadata` directly if exact-parity behavior matters.
- Companion's `PAIRING_WITH_PIN_SUPPORTED_MASK = 0x4000` flag semantics (which mDNS TXT record field it's read from, and what non-PIN "transient" Companion pairing actually requires instead) needs a closer read of `pyatv/protocols/companion/__init__.py` and `pairing.py` before implementation.
- No official public roadmap document was found beyond release notes and the issue tracker; "direction" conclusions in §11 are inferred from the maintainer's release-note commentary and open-issue patterns, not a published plan — worth periodically re-checking [github.com/postlund/pyatv/issues](https://github.com/postlund/pyatv/issues) and [releases](https://github.com/postlund/pyatv/releases) as the Rust project proceeds, since pyatv is still actively evolving against tvOS 26.
