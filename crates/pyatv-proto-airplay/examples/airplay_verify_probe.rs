//! A read-only probe that asks a real Apple TV how its AirPlay control connection can be
//! authenticated.
//!
//! Written for `docs/RISKS.md` M7: AirPlay HAP pair-*setup* never shows a PIN on the LAN tvOS 27
//! test device, so the question is whether the MRP-over-AirPlay tunnel can be reached some other
//! way — by reusing the Companion pairing's HAP credentials, or by transient pairing.
//!
//! # What it does, and what it deliberately does not
//!
//! Every request it sends is a handshake or a read: `POST /pair-verify`, `POST /pair-setup`,
//! `GET /info`, and one `SETUP` carrying `isRemoteControlOnly`. It never plays, seeks, changes
//! volume, powers anything on or off, and it never posts `/pair-pin-start` — so nothing appears on
//! screen. No key, credential, proof or ciphertext is ever printed: TLV values are reported by tag
//! and length, and credentials only by field length.
//!
//! # Running it
//!
//! ```text
//! PROBE_HOST=10.0.0.5 cargo run -p pyatv-proto-airplay --example airplay_verify_probe
//! ```
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `PROBE_HOST` | `10.0.0.5` | Device address. |
//! | `PROBE_PORT` | `7000` | AirPlay control port, from the `_airplay._tcp` SRV record. |
//! | `PROBE_CONF` | `/tmp/pyatv-rs.conf` | Storage file to read Companion credentials from. Both this port's `"Companion"` spelling and pyatv's `"companion"` are accepted. |
//! | `PROBE_EXPERIMENTS` | `hap,transient` | Which experiments to run, comma separated: `hap`, `transient`, `setup-m1`. |
//! | `PROBE_SETUP` | `1` | Send the event-channel `SETUP` after a verify that produced working keys. |
//!
//! Experiment 3 of the task brief — the same HAP verify against pyatv's own credential file — is
//! `PROBE_CONF=/tmp/pyatv-py.conf PROBE_EXPERIMENTS=hap`, not a separate code path.

use std::net::{SocketAddr, ToSocketAddrs as _};

use pyatv_pairing::pairing::TRANSIENT_PIN;
use pyatv_pairing::tlv8::{ErrorCode, Tlv8, TlvValue};
use pyatv_pairing::{
    AuthenticationType, HapCredentials, PairSetup, PairVerify, TransientPairSetup,
};
use pyatv_pairing::{hkdf_derive::transport::AIRPLAY_CONTROL, session::HapSession};
use pyatv_proto_airplay::ap2::{EventChannelSetup, InfoSettings, random_uuid};
use pyatv_proto_airplay::auth::hap_headers;
use pyatv_proto_airplay::auth::{HKP_HAP, HKP_TRANSIENT, PAIR_SETUP_PATH, PAIR_VERIFY_PATH};
use pyatv_proto_airplay::codec::Response;
use pyatv_proto_airplay::http::{HttpConnection, RequestSpec};
use pyatv_proto_airplay::rtsp::RtspSession;

type BoxError = Box<dyn std::error::Error>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    // `RUST_LOG=pyatv_proto_airplay=trace` prints every request and response head, which is how the
    // verbatim exchanges in `docs/research/airplay-tunnel-auth-experiment-2026-08-24.md` were
    // recorded. Bodies are never logged; see `HttpConnection`'s `head_of`.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let host = var("PROBE_HOST", "10.0.0.5");
    let port = var("PROBE_PORT", "7000");
    let conf = var("PROBE_CONF", "/tmp/pyatv-rs.conf");
    let experiments = var("PROBE_EXPERIMENTS", "hap,transient");
    let attempt_setup = var("PROBE_SETUP", "1") != "0";

    let address = resolve(&host, &port)?;
    println!("# AirPlay control-connection auth probe");
    println!("device            {address}");
    println!("credential source {conf}");
    println!("event SETUP       {}", enabled(attempt_setup));

    for experiment in experiments
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        println!();
        println!("## experiment: {experiment}");

        let outcome = match experiment {
            "hap" => hap_experiment(address, &conf, attempt_setup).await,
            "transient" => transient_experiment(address, attempt_setup).await,
            "setup-m1" => setup_m1_control(address).await,
            other => Err(format!("unknown experiment {other:?}").into()),
        };

        match outcome {
            Ok(()) => println!("result            completed"),
            Err(error) => println!("result            FAILED: {error}"),
        }
    }

    Ok(())
}

/// Experiment 1/3: AirPlay HAP `/pair-verify` against Companion credentials.
async fn hap_experiment(
    address: SocketAddr,
    conf: &str,
    attempt_setup: bool,
) -> Result<(), BoxError> {
    let credentials = load_companion_credentials(conf)?;
    println!(
        "credentials       type={:?} ltpk={}B ltsk={}B atv_id={}B client_id={}B",
        credentials.try_authentication_type()?,
        credentials.ltpk.len(),
        credentials.ltsk.len(),
        credentials.atv_id.len(),
        credentials.client_id.len()
    );
    if credentials.try_authentication_type()? != AuthenticationType::Hap {
        return Err("stored Companion credentials are not HAP credentials".into());
    }

    let mut http = HttpConnection::connect(address).await?;
    let headers = hap_headers(HKP_HAP);

    let (mut verify, m1) = PairVerify::start(credentials);
    let m2 = post(&mut http, PAIR_VERIFY_PATH, &headers, &m1, "M1").await?;
    if !m2.is_success() {
        return Err(format!("device refused pair-verify M1: {}", status(&m2)).into());
    }

    let m3 = verify.handle_m2(&m2.body)?;
    println!("M2                accepted: signature and identifier verified");

    let m4 = post(&mut http, PAIR_VERIFY_PATH, &headers, &m3, "M3").await?;
    if !m4.is_success() {
        return Err(format!("device refused pair-verify M3: {}", status(&m4)).into());
    }
    verify.handle_m4(&m4.body)?;
    println!("M4                accepted: pair-verify complete");

    let keys = verify.encryption_keys(
        AIRPLAY_CONTROL.salt,
        AIRPLAY_CONTROL.write_info,
        AIRPLAY_CONTROL.read_info,
    )?;
    http.enable_encryption(HapSession::new(&keys.output_key, &keys.input_key));
    println!("keys              derived from Control-Salt; control channel now encrypted");

    prove_channel(&mut http, attempt_setup).await
}

/// Experiment 2: transient pair-setup M1–M4 with the fixed PIN, then the same channel test.
///
/// pyatv posts `/pair-pin-start` first (`hap_transient.py:49`); this probe skips it, because the
/// brief forbids anything that could put a code on screen and the fixed PIN makes the request
/// pointless anyway. If the device rejects M1 for that reason, that is itself the finding.
async fn transient_experiment(address: SocketAddr, attempt_setup: bool) -> Result<(), BoxError> {
    println!("credentials       none (transient, fixed PIN {TRANSIENT_PIN})");
    println!("divergence        /pair-pin-start deliberately not sent");

    let mut http = HttpConnection::connect(address).await?;
    let headers = hap_headers(HKP_TRANSIENT);

    let (mut setup, m1) = TransientPairSetup::start();
    let m2 = post(&mut http, PAIR_SETUP_PATH, &headers, &m1, "M1").await?;
    if !m2.is_success() {
        return Err(format!("device refused transient M1: {}", status(&m2)).into());
    }

    let m3 = setup.handle_m2(&m2.body)?;
    println!("M2                accepted: salt and accessory public key present");

    let m4 = post(&mut http, PAIR_SETUP_PATH, &headers, &m3, "M3").await?;
    if !m4.is_success() {
        return Err(format!("device refused transient M3: {}", status(&m4)).into());
    }
    setup.handle_m4(&m4.body)?;
    println!("M4                accepted: accessory SRP proof verified");

    let keys = setup.encryption_keys(
        AIRPLAY_CONTROL.salt,
        AIRPLAY_CONTROL.write_info,
        AIRPLAY_CONTROL.read_info,
    )?;
    http.enable_encryption(HapSession::new(&keys.output_key, &keys.input_key));
    println!("keys              derived from SRP K, not an ECDH secret; channel now encrypted");

    prove_channel(&mut http, attempt_setup).await
}

/// The control that makes a `470` on the transient path interpretable.
///
/// Sends HAP pair-setup **M1 only** with `X-Apple-HKP: 3` and, like the transient experiment, no
/// `/pair-pin-start`. If this is answered while the transient M1 is refused, the refusal is about
/// the `X-Apple-HKP: 4` branch rather than about the missing `/pair-pin-start`.
///
/// M3 is never sent, so no PIN is ever guessed, no pairing is created and nothing is persisted.
/// `docs/RISKS.md` M7 already establishes that this exchange puts nothing on screen on this device.
async fn setup_m1_control(address: SocketAddr) -> Result<(), BoxError> {
    println!("purpose           does /pair-setup need /pair-pin-start first?");

    let mut http = HttpConnection::connect(address).await?;
    let headers = hap_headers(HKP_HAP);

    let (_setup, m1) = PairSetup::start(None);
    let m2 = post(&mut http, PAIR_SETUP_PATH, &headers, &m1, "M1").await?;

    if m2.is_success() {
        println!("finding           HKP 3 pair-setup M1 is answered without /pair-pin-start");
    } else {
        println!(
            "finding           HKP 3 pair-setup M1 is refused too: {}",
            status(&m2)
        );
    }
    println!("stopped           M3 deliberately not sent");

    Ok(())
}

/// Prove the encrypted channel works, with the two least intrusive requests there are.
///
/// `GET /info` is a pure read (`pyatv/support/rtsp.py:99-108`). The `SETUP` that follows is the
/// first half of `AP2Session.setup_remote_control` (`ap2_session.py:75-149`) and only negotiates
/// ports; no data channel is opened and no MRP message is sent.
async fn prove_channel(http: &mut HttpConnection, attempt_setup: bool) -> Result<(), BoxError> {
    let mut rtsp = RtspSession::new();

    let info = rtsp.info(http).await?;
    match info.as_dictionary() {
        Some(dictionary) if dictionary.is_empty() => {
            println!("GET /info         non-200: device reports no /info");
        }
        Some(dictionary) => {
            println!(
                "GET /info         200, {} keys, decrypted cleanly",
                dictionary.len()
            );
            let mut keys: Vec<&str> = dictionary.keys().map(String::as_str).collect();
            keys.sort_unstable();
            println!("  keys            {}", keys.join(", "));
            // A deliberately short allowlist. `pk`, `pi`, `psi`, `deviceID` and `macAddress` are
            // the device's own key material and identifiers and are never printed.
            for key in [
                "model",
                "osBuildVersion",
                "name",
                "protocolVersion",
                "sourceVersion",
                "features",
                "statusFlags",
                "keepAliveSendStatsAsBody",
            ] {
                if let Some(value) = dictionary.get(key) {
                    println!("  {key:<24} {}", render(value));
                }
            }
        }
        None => println!("GET /info         200, but the body is not a dictionary"),
    }

    if !attempt_setup {
        return Ok(());
    }

    let session_uuid = random_uuid();
    let body = pyatv_proto_airplay::ap2::remote_control_setup_body(
        &InfoSettings::default(),
        &session_uuid,
    );
    println!("SETUP             isRemoteControlOnly, sessionUUID drawn fresh");

    let reply = rtsp.setup(http, &body).await?;
    if let Some(dictionary) = reply.as_dictionary() {
        let mut entries: Vec<(&String, &plist::Value)> = dictionary.iter().collect();
        entries.sort_by_key(|(key, _)| *key);
        for (key, value) in entries {
            println!("  reply {key:<9} {}", render(value));
        }
    }
    let ports = EventChannelSetup::from_plist(&reply)?;
    println!(
        "  eventPort       {}   timingPort {:?}",
        ports.event_port, ports.timing_port
    );

    Ok(())
}

/// Post one pairing message and report the exchange without leaking its contents.
async fn post(
    http: &mut HttpConnection,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    label: &str,
) -> Result<Response, BoxError> {
    let hkp = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("X-Apple-HKP"))
        .map_or("<none>", |(_, value)| *value);

    println!(
        "-> POST {path} (X-Apple-HKP: {hkp}) {label}, {} bytes",
        body.len()
    );
    println!("   sent           {}", describe(body));

    let response = http
        .send(&RequestSpec {
            uri: path,
            headers,
            body,
            allow_error: true,
            ..RequestSpec::default()
        })
        .await?;

    println!("<- {} {} bytes", status(&response), response.body.len());
    println!("   received       {}", describe(&response.body));

    Ok(response)
}

/// Render a TLV8 body as tag names and lengths, decoding only the one-byte control fields.
///
/// `SeqNo`, `Error`, `Flags`, `Method`, `Permissions` and `BackOff` carry protocol state. Every
/// other tag carries key material, a proof or a ciphertext and is reported by length alone.
fn describe(body: &[u8]) -> String {
    if body.is_empty() {
        return "<empty>".to_owned();
    }
    let Ok(tlv) = Tlv8::decode(body) else {
        return format!("<{} bytes, not TLV8>", body.len());
    };

    let mut parts = Vec::new();
    for tag in tlv.tags() {
        let value = tlv.get_raw(tag).map_or(&[][..], |bytes| &bytes[..]);
        let known = TlvValue::from_tag(tag);
        let name = known.map_or_else(|| format!("0x{tag:02x}"), |tag| format!("{tag:?}"));

        parts.push(match known {
            Some(TlvValue::SeqNo) => {
                format!("SeqNo=M{}", value.first().copied().unwrap_or_default())
            }
            Some(TlvValue::Error) => {
                let code = value.first().copied().unwrap_or_default();
                let named = ErrorCode::from_code(code)
                    .map_or_else(|| format!("0x{code:02x}"), |code| format!("{code:?}"));
                format!("Error={named}")
            }
            Some(
                TlvValue::Method | TlvValue::Flags | TlvValue::Permissions | TlvValue::BackOff,
            ) => format!("{name}=0x{}", hex(value)),
            _ => format!("{name}[{}B]", value.len()),
        });
    }

    parts.join(" ")
}

/// Load the Companion credentials out of a storage file.
///
/// Accepts both this port's `"Companion"` protocol key and pyatv's lowercase `"companion"`; the two
/// files are otherwise the same shape.
fn load_companion_credentials(path: &str) -> Result<HapCredentials, BoxError> {
    let contents = std::fs::read_to_string(path)?;
    let root: serde_json::Value = serde_json::from_str(&contents)?;

    let devices = root
        .get("devices")
        .and_then(serde_json::Value::as_array)
        .ok_or("storage file has no devices array")?;

    for device in devices {
        let Some(protocols) = device
            .get("protocols")
            .and_then(serde_json::Value::as_object)
        else {
            continue;
        };
        for (name, settings) in protocols {
            if !name.eq_ignore_ascii_case("companion") {
                continue;
            }
            if let Some(raw) = settings
                .get("credentials")
                .and_then(serde_json::Value::as_str)
            {
                return Ok(HapCredentials::parse(raw)?);
            }
        }
    }

    Err(format!("no Companion credentials in {path}").into())
}

fn resolve(host: &str, port: &str) -> Result<SocketAddr, BoxError> {
    format!("{host}:{port}")
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| format!("{host}:{port} did not resolve").into())
}

fn var(name: &str, fallback: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fallback.to_owned())
}

fn enabled(flag: bool) -> &'static str {
    if flag { "enabled" } else { "disabled" }
}

/// Render a scalar property-list value for the transcript. Anything else is reported by type.
fn render(value: &plist::Value) -> String {
    if let Some(flag) = value.as_boolean() {
        return format!("bool {flag}");
    }
    if let Some(number) = value.as_unsigned_integer() {
        return format!("uint {number}");
    }
    if let Some(number) = value.as_signed_integer() {
        return format!("int {number}");
    }
    if let Some(text) = value.as_string() {
        return format!("string {text:?}");
    }
    format!("<{value:?}>")
}

fn status(response: &Response) -> String {
    format!("{} {}", response.status, response.reason)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
