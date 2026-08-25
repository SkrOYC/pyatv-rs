//! A read-only probe that brings the whole AirPlay 2 remote-control tunnel up against a real
//! Apple TV and reports what the device answers.
//!
//! The sequel to `airplay_verify_probe`, which stopped at the event-channel `SETUP`. This one goes
//! all the way: pair-verify, the event `SETUP` and its socket, the data-stream `SETUP` and its
//! socket, then it sits and watches whatever the device says unprompted.
//!
//! # What it does, and what it deliberately does not
//!
//! It never sends an MRP message. Nothing it does is visible on screen: `/pair-verify` shows
//! nothing (`docs/research/airplay-tunnel-auth-experiment-2026-08-24.md`), `SETUP` only negotiates
//! ports, and `POST /feedback` is the keepalive an idle pyatv session posts twice a second anyway.
//! No playback, volume, power, `play_url` or `TEARDOWN` request is ever issued. No key, credential
//! or ciphertext is printed: the credentials are reported by field length only.
//!
//! # Running it
//!
//! ```text
//! PROBE_HOST=10.0.0.5 cargo run -p pyatv-proto-airplay --example airplay_tunnel_probe
//! ```
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `PROBE_HOST` | `10.0.0.5` | Device address. |
//! | `PROBE_PORT` | `7000` | AirPlay control port, from the `_airplay._tcp` SRV record. |
//! | `PROBE_CONF` | `/tmp/creds-check.conf` | Storage file to read HAP credentials from. Both this port's `"Companion"` spelling and pyatv's `"companion"` are accepted. |
//! | `PROBE_OBSERVE` | `10` | Seconds to watch the two channels before closing. |
//! | `PROBE_KEEPALIVE` | `1` | Post `/feedback` while observing. `0` disables it. |
//!
//! `RUST_LOG=pyatv_proto_airplay=debug` adds a line per event-channel request and per inbound data
//! frame, including that frame's header fields; `=trace` adds every control-connection header
//! block. Bodies are never logged.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs as _};
use std::time::Duration;

use pyatv_pairing::{AuthenticationType, HapCredentials};
use pyatv_proto_airplay::ap2::{Ap2Session, SeqnoPolicy};
use pyatv_proto_airplay::setup::remote_control_tunnel;
use pyatv_proto_airplay::{InfoSettings, Result};

type BoxError = Box<dyn std::error::Error>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let host = var("PROBE_HOST", "10.0.0.5");
    let port: u16 = var("PROBE_PORT", "7000").parse()?;
    let conf = var("PROBE_CONF", "/tmp/creds-check.conf");
    let observe: u64 = var("PROBE_OBSERVE", "10").parse()?;
    let keepalive = var("PROBE_KEEPALIVE", "1") != "0";

    let address = resolve(&host, port)?;
    println!("# AirPlay 2 remote-control tunnel probe");
    println!("device            {address}");
    println!("credential source {conf}");
    println!("observe           {observe}s, keepalive {}", on(keepalive));
    println!("safety            no MRP message is sent, nothing appears on screen");

    let credentials = load_hap_credentials(&conf)?;
    println!(
        "credentials       type={:?} ltpk={}B ltsk={}B atv_id={}B client_id={}B",
        credentials.authentication_type(),
        credentials.ltpk.len(),
        credentials.ltsk.len(),
        credentials.atv_id.len(),
        credentials.client_id.len()
    );
    if credentials.authentication_type() != AuthenticationType::Hap {
        return Err("the stored credentials are not HAP credentials".into());
    }

    println!();
    println!("## bring-up");
    let (mut session, channel) = remote_control_tunnel(
        address.ip(),
        address.port(),
        &credentials,
        InfoSettings::default(),
        SeqnoPolicy::Fixed,
    )
    .await?;
    println!("pair-verify       M1-M4 accepted, control channel encrypted");

    report_setup(&session);

    let ports = session
        .ports()
        .ok_or("setup completed without recording its ports")?;
    println!(
        "event channel     connected to {}:{}",
        address.ip(),
        ports.event.port
    );
    println!(
        "data channel      connected to {}:{}, seqno {:#x}",
        address.ip(),
        ports.data_port,
        channel.seqno()
    );

    if keepalive {
        session.start_keep_alive(None);
        println!("keepalive         POST /feedback every 2s");
    }

    println!();
    println!("## unprompted traffic ({observe}s)");
    observe_channels(&session, &channel, Duration::from_secs(observe)).await;

    session.close().await?;
    println!();
    println!("closed            control connection and both channels");
    Ok(())
}

/// Print both `SETUP` replies verbatim, key by key.
fn report_setup(session: &Ap2Session) {
    for (name, reply) in [
        ("event SETUP", session.event_setup_reply()),
        ("data SETUP", session.data_setup_reply()),
    ] {
        let Some(reply) = reply else {
            println!("{name:<17} <no reply recorded>");
            continue;
        };
        println!("{name:<17} {}", render(reply));
    }
}

/// Watch both channels, reporting anything the device sends without being asked.
async fn observe_channels(
    session: &Ap2Session,
    channel: &pyatv_proto_airplay::DataStreamChannel,
    window: Duration,
) {
    let deadline = tokio::time::Instant::now() + window;
    let mut events = 0usize;
    let mut messages = 0usize;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        tokio::select! {
            () = tokio::time::sleep(remaining) => break,
            request = async {
                match session.event_channel() {
                    Some(event) => event.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                let Some(request) = request else { break };
                events += 1;
                println!(
                    "event  #{events:<3}       {} {} {}",
                    request.method, request.uri, request.protocol
                );
                for (name, value) in &request.headers {
                    println!("                    {name}: {value}");
                }
                println!("                    body {} bytes", request.body.len());
            }
            message = channel.recv() => {
                let Ok(message) = message else { break };
                messages += 1;
                // The bytes are an MRP `ProtocolMessage` this crate does not decode. The leading
                // bytes carry the type tag and message type, which is the useful part here.
                println!(
                    "data   #{messages:<3}       {} bytes, leading {}",
                    message.len(),
                    hex(&message[..message.len().min(8)])
                );
            }
        }
    }

    println!("totals            {events} event request(s), {messages} data message(s)");
}

/// Render a property list for the transcript, one key per line for a dictionary.
fn render(value: &plist::Value) -> String {
    match value {
        plist::Value::Dictionary(dictionary) => {
            use std::fmt::Write as _;

            let mut out = format!("{} key(s)", dictionary.len());
            for (key, value) in dictionary {
                // Writing into a `String` is infallible; the `Result` exists only for the trait.
                let _ = write!(out, "\n                  {key} = {}", scalar(value));
            }
            out
        }
        other => scalar(other),
    }
}

/// Render one scalar, or name the type of anything more structured.
fn scalar(value: &plist::Value) -> String {
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
    if let Some(items) = value.as_array() {
        return items
            .iter()
            .map(|item| format!("[{}]", render(item)))
            .collect::<Vec<_>>()
            .join(", ");
    }
    if let Some(data) = value.as_data() {
        return format!("data {} bytes", data.len());
    }
    format!("<{value:?}>")
}

/// Load HAP credentials out of a pyatv-format storage file.
///
/// Reads whichever protocol has them, preferring AirPlay's own and falling back to Companion's —
/// the same order [`pyatv_proto_airplay::tunnel_credentials`] applies, spelled out here because an
/// example has no `BaseConfig` to hand.
fn load_hap_credentials(path: &str) -> Result<HapCredentials, BoxError> {
    let contents = std::fs::read_to_string(path)?;
    let root: serde_json::Value = serde_json::from_str(&contents)?;

    let devices = root
        .get("devices")
        .and_then(serde_json::Value::as_array)
        .ok_or("storage file has no devices array")?;

    for wanted in ["airplay", "companion"] {
        for device in devices {
            let Some(protocols) = device
                .get("protocols")
                .and_then(serde_json::Value::as_object)
            else {
                continue;
            };
            for (name, settings) in protocols {
                if !name.eq_ignore_ascii_case(wanted) {
                    continue;
                }
                if let Some(raw) = settings
                    .get("credentials")
                    .and_then(serde_json::Value::as_str)
                    .filter(|it| !it.is_empty())
                {
                    println!("credential slot   protocols.{name}.credentials");
                    return Ok(HapCredentials::parse(raw)?);
                }
            }
        }
    }

    Err(format!("no AirPlay or Companion credentials in {path}").into())
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, BoxError> {
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(address, port));
    }
    format!("{host}:{port}")
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| format!("{host}:{port} did not resolve").into())
}

fn var(name: &str, fallback: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fallback.to_owned())
}

fn on(flag: bool) -> &'static str {
    if flag { "on" } else { "off" }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
