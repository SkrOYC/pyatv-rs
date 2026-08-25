//! Small conveniences that sit on top of [`scan`](crate::scan) and [`connect`](crate::connect).
//!
//! Port of `pyatv/helpers.py`, a public top-level module upstream. Nothing here is required to use
//! the library — every function is a few lines over the three entry points — but they are part of
//! pyatv's public surface, and example code ported from upstream reaches for them.
//!
//! The service-type constants at `helpers.py:10-16` have no equivalent here because
//! [`pyatv_mdns::ServiceType`] already is one, as a closed enum rather than seven loose strings.

use std::sync::Arc;
use std::time::Duration;

use pyatv_core::interface::AppleTV;
use pyatv_core::storage::Storage;
use pyatv_core::{BaseConfig, PairingRequirement, Result};
use pyatv_mdns::ScanOptions;

pub use pyatv_mdns::ServiceType;
pub use pyatv_mdns::scan::handlers::get_unique_id;

/// Whether this library can do anything at all with a discovered device.
///
/// `is_device_supported(conf)` (`helpers.py:105-122`): false when *every* service is either
/// [`PairingRequirement::Unsupported`] or [`PairingRequirement::Disabled`], true otherwise. A true
/// answer does not mean the device is usable right now — pairing, or stored credentials, may still
/// be needed — only that offering to pair it is not pointless.
///
/// A configuration with no services at all is unsupported: upstream's set difference is empty in
/// that case too, and `len(...) > 0` is false.
#[must_use]
pub fn is_device_supported(config: &BaseConfig) -> bool {
    config.services.iter().any(|service| {
        !matches!(
            service.pairing,
            PairingRequirement::Unsupported | PairingRequirement::Disabled
        )
    })
}

/// Whether a file's format can be streamed to a receiver.
///
/// `is_streamable(filename)` (`helpers.py:90-102`). Never fails: a missing file, a permission
/// error or an unrecognised container all answer `false`.
///
/// # Divergence: this decodes, upstream only reads headers
///
/// Upstream calls `miniaudio.get_file_info`, which parses the container header and stops. The
/// closest thing this workspace exposes is `pyatv_proto_airplay::audio::decode_bytes`, which
/// decodes the whole stream, so this reads the file into memory and decodes it on a blocking
/// thread. The answer is the same one `stream_file` would give — which is arguably a *better*
/// predicate, since a file whose header parses but whose codec is unsupported is not in fact
/// streamable — but it costs time and memory proportional to the file. Cache the result rather
/// than calling it per frame of a UI.
pub async fn is_streamable(path: impl AsRef<std::path::Path>) -> bool {
    let path = path.as_ref().to_path_buf();
    let hint = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_owned);

    // Both the read and the decode go to a blocking thread: this is filesystem I/O followed by
    // CPU-bound work, and neither belongs on a runtime worker.
    tokio::task::spawn_blocking(move || {
        let Ok(bytes) = std::fs::read(&path) else {
            return false;
        };
        pyatv_proto_airplay::audio::decode::decode_bytes(bytes, hint.as_deref()).is_ok()
    })
    .await
    .unwrap_or(false)
}

/// Scan, connect to the first device found, hand it to `handler`, then close it.
///
/// `auto_connect(handler, timeout, not_found, loop)` (`helpers.py:19-51`). Upstream's own docstring
/// calls it "very inflexible in many cases, but can be handy sometimes when trying things", and
/// that is exactly what it is for here too.
///
/// Returns `false` when the scan found nothing — upstream calls a `not_found` coroutine instead,
/// which in Rust is an argument a caller would almost always pass `None` for when an `if` says the
/// same thing. The device is closed whether `handler` succeeded or not, as upstream's `finally`
/// does.
///
/// # Errors
///
/// Returns whatever [`crate::scan`], [`crate::connect`] or `handler` reported. A failure inside
/// `handler` is propagated *after* the device has been closed.
///
/// # Examples
///
/// ```no_run
/// # use std::sync::Arc;
/// # async fn example() -> pyatv::Result<()> {
/// let storage = Arc::new(pyatv::MemoryStorage::new());
/// let found = pyatv::helpers::auto_connect(
///     std::time::Duration::from_secs(5),
///     storage,
///     |atv| async move {
///         println!("connected to {:?}", atv.service().protocol);
///         Ok(())
///     },
/// )
/// .await?;
/// # let _ = found;
/// # Ok(())
/// # }
/// ```
pub async fn auto_connect<Handler, Fut>(
    timeout: Duration,
    storage: Arc<dyn Storage>,
    handler: Handler,
) -> Result<bool>
where
    Handler: FnOnce(Arc<dyn AppleTV>) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let devices = crate::scan(ScanOptions {
        timeout,
        ..ScanOptions::default()
    })
    .await?;

    // `if atvs: atv = await pyatv.connect(atvs[0], loop)` (`helpers.py:38-40`).
    let Some(config) = devices.first() else {
        return Ok(false);
    };

    let atv = crate::connect(config, None, storage).await?;
    let outcome = handler(Arc::clone(&atv)).await;

    // `finally: atv.close()` (`helpers.py:44-45`): the close happens even when the handler failed,
    // and its own failure must not mask the handler's.
    if let Err(error) = atv.close().await {
        tracing::debug!(%error, "auto_connect could not close the device cleanly");
    }

    outcome.map(|()| true)
}

#[cfg(test)]
mod tests {
    use super::{get_unique_id, is_device_supported, is_streamable};
    use pyatv_core::{BaseConfig, BaseService, PairingRequirement, Protocol};
    use pyatv_mdns::ServiceType;

    fn config_with(requirements: &[PairingRequirement]) -> BaseConfig {
        let mut config = BaseConfig::new("Living Room", "10.0.0.2".parse().expect("an address"));
        for (index, requirement) in requirements.iter().enumerate() {
            let mut service = BaseService::new(
                Protocol::ALL[index % Protocol::ALL.len()],
                7000 + u16::try_from(index).unwrap_or(0),
            );
            service.pairing = *requirement;
            config.services.push(service);
        }
        config
    }

    /// `is_device_supported` (`helpers.py:105-122`): one usable service is enough.
    #[test]
    fn a_device_is_supported_when_any_service_can_be_paired() {
        assert!(is_device_supported(&config_with(&[
            PairingRequirement::Unsupported,
            PairingRequirement::Mandatory,
        ])));
        assert!(is_device_supported(&config_with(&[
            PairingRequirement::NotNeeded
        ])));
        assert!(is_device_supported(&config_with(&[
            PairingRequirement::Optional
        ])));
    }

    /// All-unsupported and all-disabled are the two cases upstream filters out.
    #[test]
    fn a_device_with_nothing_pairable_is_unsupported() {
        assert!(!is_device_supported(&config_with(&[
            PairingRequirement::Unsupported,
            PairingRequirement::Disabled,
        ])));
        assert!(!is_device_supported(&config_with(&[])));
    }

    /// The re-export is the same function the scanner uses, so its docstring cases hold here.
    #[test]
    fn get_unique_id_is_reachable_from_the_umbrella() {
        let mut properties = pyatv_mdns::dns::Properties::default();
        properties.insert("UniqueIdentifier", "01:23:45".to_owned());

        assert_eq!(
            get_unique_id(ServiceType::MediaRemoteTv, "Living Room", &properties),
            Some("01:23:45".to_owned())
        );
    }

    /// "It will never raise an exception, e.g. because the file is missing" (`helpers.py:93-95`).
    #[tokio::test]
    async fn a_missing_file_is_not_streamable() {
        assert!(!is_streamable("/nonexistent/definitely-not-here.mp3").await);
    }

    /// Nor is a file that exists but is not audio.
    #[tokio::test]
    async fn a_non_audio_file_is_not_streamable() {
        let path = std::env::temp_dir().join("pyatv-rs-not-audio.txt");
        tokio::fs::write(&path, b"this is not a sound").await.ok();
        assert!(!is_streamable(&path).await);
        tokio::fs::remove_file(&path).await.ok();
    }
}
