//! Play a video URL on a real Apple TV and report every step of the sequence.
//!
//! The `play_url` counterpart to `airplay_tunnel_probe`. Unlike that one, **this is not read-only**:
//! it starts playback, so the device switches to the video player and whatever is on screen is
//! replaced. Run it only when someone is expecting that.
//!
//! # Running it
//!
//! ```text
//! PROBE_HOST=10.0.0.5 \
//! PROBE_URL=https://example.invalid/clip.mp4 \
//!   cargo run -p pyatv-proto-airplay --example airplay_play_url_probe
//! ```
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `PROBE_HOST` | `10.0.0.5` | Device address. |
//! | `PROBE_PORT` | `7000` | `AirPlay` control port, from the `_airplay._tcp` SRV record. |
//! | `PROBE_CONF` | `/tmp/creds-check.conf` | Storage file to read HAP credentials from. Both this port's `"AirPlay"`/`"Companion"` spellings and pyatv's lowercase ones are accepted. |
//! | `PROBE_URL` | *(required)* | The video to play. |
//! | `PROBE_POSITION` | `0` | Seconds to start at. |
//! | `PROBE_VERSION` | `2` | `1` or `2`, forcing the protocol version rather than reading the feature bits. |
//! | `PROBE_LIMIT` | `60` | Stop after this many seconds even if the media is longer. `0` waits for the end. |
//!
//! `RUST_LOG=pyatv_proto_airplay=debug` adds a line per request, including the `/playback-info`
//! poll and every keepalive. No key, credential or body is ever logged.
//!
//! # What it establishes
//!
//! Whether the `AirPlay` 2 play sequence in [`pyatv_proto_airplay::stream`] works against tvOS 27
//! at all, which nothing hermetic can answer: `docs/research/airplay-playurl-raop-port-spec.md`
//! §16.5 flags that `skipRecord` was only ever confirmed live for the *tunnel's* `SETUP`, not for
//! this one, and §16.6 records that no tvOS-26/27 `play_url` regression is documented anywhere in
//! the pyatv checkout — so a failure here is a new, dated finding rather than a known one.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs as _};
use std::sync::Arc;
use std::time::Duration;

use pyatv_core::airplay::AirPlayMajorVersion;
use pyatv_pairing::{AuthenticationType, HapCredentials};
use pyatv_proto_airplay::stream::{AirPlayPlayer, PlayOptions};
use tokio::sync::Notify;

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
    let url = std::env::var("PROBE_URL").map_err(|_| "PROBE_URL must name a video to play")?;
    let position: f64 = var("PROBE_POSITION", "0").parse()?;
    let limit: u64 = var("PROBE_LIMIT", "60").parse()?;
    let version = match var("PROBE_VERSION", "2").as_str() {
        "1" => AirPlayMajorVersion::V1,
        "2" => AirPlayMajorVersion::V2,
        other => return Err(format!("PROBE_VERSION must be 1 or 2, not {other:?}").into()),
    };

    let address = resolve(&host, port)?;
    println!("# AirPlay play_url probe");
    println!("device            {address}");
    println!("credential source {conf}");
    println!("url               {url}");
    println!("position          {position}s, protocol AirPlay {version:?}");
    println!(
        "limit             {}",
        if limit == 0 {
            "none, waits for the media to end".to_owned()
        } else {
            format!("{limit}s")
        }
    );
    println!("safety            THIS STARTS PLAYBACK — the device will switch to the video");

    let credentials = load_hap_credentials(&conf)?;
    println!(
        "credentials       type={:?} ltpk={}B ltsk={}B atv_id={}B client_id={}B",
        credentials.authentication_type(),
        credentials.ltpk.len(),
        credentials.ltsk.len(),
        credentials.atv_id.len(),
        credentials.client_id.len()
    );
    if version == AirPlayMajorVersion::V2
        && credentials.authentication_type() != AuthenticationType::Hap
    {
        return Err("AirPlay 2 needs HAP credentials; none were found".into());
    }

    println!();
    println!("## playing");
    let mut player =
        AirPlayPlayer::connect(&PlayOptions::new(address, credentials, version)).await?;
    println!("connected         control connection open");

    let stop = Arc::new(Notify::new());
    if limit > 0 {
        let signal = Arc::clone(&stop);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(limit)).await;
            println!("limit reached     stopping");
            signal.notify_one();
        });
    }
    // Ctrl-C stops the playback rather than killing the process with the connection still open.
    let signal = Arc::clone(&stop);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            println!("interrupted       stopping");
            signal.notify_one();
        }
    });

    let outcome = player.play_url(&url, position, &stop).await;
    player.close().await?;

    match outcome {
        Ok(()) => println!("finished          the device stopped reporting a duration"),
        Err(error) => {
            println!("failed            {error}");
            return Err(error.into());
        }
    }

    Ok(())
}

/// Load HAP credentials out of a pyatv-format storage file.
///
/// AirPlay's own credentials first, then Companion's — the order
/// [`pyatv_proto_airplay::setup::play_credentials`] applies, spelled out here because an example
/// has no `BaseConfig` to hand.
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
