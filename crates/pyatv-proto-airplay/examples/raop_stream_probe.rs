//! Stream one audio file to a real device over RAOP and report what the receiver did.
//!
//! # This one is NOT read-only
//!
//! Unlike `airplay_verify_probe` and `airplay_tunnel_probe`, running this **plays audible sound on
//! the device** and changes its volume. Do not run it against a household TV without knowing
//! someone is there to hear it. It is here so a human can validate the RAOP path against real
//! hardware at a time of their choosing; nothing in CI runs it, and no agent should.
//!
//! To make that hard to do by accident it refuses to start unless `PROBE_CONFIRM=yes` is set.
//!
//! # Running it
//!
//! ```text
//! PROBE_CONFIRM=yes PROBE_HOST=10.0.0.5 PROBE_FILE=/tmp/test.wav \
//!     cargo run -p pyatv-proto-airplay --example raop_stream_probe
//! ```
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `PROBE_CONFIRM` | *(unset)* | Must be `yes`. Nothing runs otherwise. |
//! | `PROBE_HOST` | `10.0.0.5` | Device address. |
//! | `PROBE_PORT` | `7000` | RAOP port, from the `_raop._tcp` SRV record. On tvOS this is usually the same 7000 as AirPlay. |
//! | `PROBE_FILE` | *(required)* | Path or `http://` URL of the audio to stream. |
//! | `PROBE_CONF` | `/tmp/creds-check.conf` | Storage file to read HAP credentials from. |
//! | `PROBE_VOLUME` | *(unset)* | Percentage `0..=100` to set before streaming. Left alone if unset. |
//! | `PROBE_VERSION` | `auto` | `1`, `2`, or `auto` to decide from the feature bits below. |
//! | `PROBE_FEATURES` | `0x4A7FDFD5,0x3C177FDE` | The `ft` TXT value a scan would have found. |
//!
//! `RUST_LOG=pyatv_proto_airplay=debug` reports every RTSP exchange and the pacing loop's
//! per-second interval summary. No key, credential or audio payload is ever printed.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs as _};
use std::sync::Arc;

use pyatv_core::consts::Protocol;
use pyatv_core::models::BaseService;
use pyatv_pairing::HapCredentials;
use pyatv_proto_airplay::audio::Source;
use pyatv_proto_airplay::raop::facade::{RaopPushUpdater, RaopStream};
use pyatv_proto_airplay::raop::manager::RaopPlaybackManager;
use pyatv_proto_airplay::raop::protocol_version;

type BoxError = Box<dyn std::error::Error>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    if var("PROBE_CONFIRM", "") != "yes" {
        eprintln!(
            "This probe plays audible sound on a real device and changes its volume.\n\
             Set PROBE_CONFIRM=yes to run it."
        );
        return Ok(());
    }

    let host = var("PROBE_HOST", "10.0.0.5");
    let port: u16 = var("PROBE_PORT", "7000").parse()?;
    let conf = var("PROBE_CONF", "/tmp/creds-check.conf");
    let features = var("PROBE_FEATURES", "0x4A7FDFD5,0x3C177FDE");
    let file = std::env::var("PROBE_FILE").map_err(|_| "PROBE_FILE is required")?;

    let address = resolve(&host, port)?;
    let credentials = load_hap_credentials(&conf)?;

    let mut service = BaseService::new(Protocol::Raop, address.port());
    service.properties.insert("ft".to_owned(), features.clone());
    let version = match var("PROBE_VERSION", "auto").as_str() {
        "1" => pyatv_core::airplay::AirPlayMajorVersion::V1,
        "2" => pyatv_core::airplay::AirPlayMajorVersion::V2,
        _ => protocol_version(&service),
    };

    println!("# RAOP stream probe");
    println!("device            {address}");
    println!("source            {file}");
    println!("credential source {conf}");
    println!("features          {features}");
    println!("protocol          {version:?}");
    println!("safety            THIS PLAYS AUDIO ON THE DEVICE");

    let manager = Arc::new(RaopPlaybackManager::new(address.ip(), service));
    let push_updater = Arc::new(RaopPushUpdater::new(Arc::clone(&manager)));
    let stream = Arc::new(RaopStream::new(
        Arc::clone(&manager),
        credentials,
        push_updater,
    ));

    if let Ok(level) = var("PROBE_VOLUME", "").parse::<f32>() {
        manager.set_volume(level).await?;
        println!("volume            requested {level}%");
    }

    println!();
    println!("## streaming (Ctrl-C stops)");
    let streaming = stream.stream_source(Source::from_str_source(&file));
    tokio::pin!(streaming);

    tokio::select! {
        outcome = &mut streaming => outcome?,
        result = tokio::signal::ctrl_c() => {
            result?;
            println!("stopping          flushing and tearing the session down");
            manager.stop();
            streaming.await?;
        }
    }

    println!();
    println!("finished          volume now {:.1}%", manager.volume());
    Ok(())
}

/// Load HAP credentials out of a pyatv-format storage file.
///
/// AirPlay's own credentials first, then Companion's — the order
/// [`pyatv_proto_airplay::tunnel_credentials`] applies, spelled out here because an example has no
/// `BaseConfig` to hand.
fn load_hap_credentials(path: &str) -> Result<HapCredentials, BoxError> {
    let contents = std::fs::read_to_string(path)?;
    let root: serde_json::Value = serde_json::from_str(&contents)?;

    let devices = root
        .get("devices")
        .and_then(serde_json::Value::as_array)
        .ok_or("storage file has no devices array")?;

    for wanted in ["raop", "airplay", "companion"] {
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

    Err(format!("no RAOP, AirPlay or Companion credentials in {path}").into())
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
