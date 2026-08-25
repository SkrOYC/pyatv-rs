//! [`Apps`], [`UserAccounts`], [`Power`] and [`Audio`] over Companion.
//!
//! Ports `CompanionApps` (`__init__.py:160-179`), `CompanionUserAccounts` (`:182-201`),
//! `CompanionPower` (`:204-292`) and `CompanionAudio` (`:428-487`).

use std::sync::Arc;
use std::time::Duration;

use pyatv_core::interface::{Apps, Audio, BoxFuture, Power, UserAccounts, not_supported};
use pyatv_core::{App, Error, OutputDevice, PowerState, Result, UserAccount};
use pyatv_opack::Value;

use crate::api::commands::HidCommand;
use crate::api::state::media_control_flags;
use crate::api::{CompanionApi, VOLUME_TIMEOUT};

/// How long [`CompanionPower`] waits for the device to confirm a requested power state.
///
/// **A deliberate extension.** pyatv refuses `await_new_state` outright — `raise
/// NotImplementedError("not supported by Companion yet")` (`__init__.py:280-292`) — but the
/// machinery it would need already exists here, because the background task folds every pushed
/// `SystemStatus`/`TVSystemStatus` into shared state. So this port implements it: send the HID
/// command, then wait for the state to arrive. The timeout matches the audio facade's five
/// seconds, which is upstream's own choice of "long enough for a device to answer".
///
/// A device that never pushes power events (one that also refuses `FetchAttentionState`) reports
/// [`Error::Timeout`] rather than hanging.
pub const POWER_TIMEOUT: Duration = Duration::from_secs(5);

/// App listing and launching.
#[derive(Debug)]
pub struct CompanionApps {
    api: Arc<CompanionApi>,
}

impl CompanionApps {
    /// Wrap a connected session.
    #[must_use]
    pub const fn new(api: Arc<CompanionApi>) -> Self {
        Self { api }
    }
}

impl Apps for CompanionApps {
    /// `FetchLaunchableApplicationsEvent`, whose content is `{bundle_id: display_name}`.
    ///
    /// The key is the identifier and the value is the name — the opposite of the order they appear
    /// in [`App`] (`[App(name, bundle_id) for bundle_id, name in content.items()]`,
    /// `__init__.py:175`), which is exactly the kind of thing a port gets backwards.
    fn app_list(&self) -> BoxFuture<'_, Result<Vec<App>>> {
        Box::pin(async move {
            let response = self.api.app_list().await?;
            Ok(flat_map_entries(&response.content)
                .map(|(identifier, name)| App { name, identifier })
                .collect())
        })
    }

    fn launch_app(&self, bundle_id_or_url: &str) -> BoxFuture<'_, Result<()>> {
        let target = bundle_id_or_url.to_owned();
        Box::pin(async move { self.api.launch_app(&target).await.map_err(Into::into) })
    }
}

/// User account listing and switching.
#[derive(Debug)]
pub struct CompanionUserAccounts {
    api: Arc<CompanionApi>,
}

impl CompanionUserAccounts {
    /// Wrap a connected session.
    #[must_use]
    pub const fn new(api: Arc<CompanionApi>) -> Self {
        Self { api }
    }
}

impl UserAccounts for CompanionUserAccounts {
    /// `FetchUserAccountsEvent`, the same `{id: name}` shape as the app list.
    fn account_list(&self) -> BoxFuture<'_, Result<Vec<UserAccount>>> {
        Box::pin(async move {
            let response = self.api.account_list().await?;
            Ok(flat_map_entries(&response.content)
                .map(|(identifier, name)| UserAccount { name, identifier })
                .collect())
        })
    }

    fn switch_account(&self, account_id: &str) -> BoxFuture<'_, Result<()>> {
        let account_id = account_id.to_owned();
        Box::pin(async move {
            self.api
                .switch_account(&account_id)
                .await
                .map_err(Into::into)
        })
    }
}

/// Read `{identifier: display_name}` out of a response content dict.
///
/// A non-string value is rendered rather than skipped: the device is the authority on what an app
/// is called, and dropping an app because its name came back as something unexpected would hide it
/// from the user entirely.
fn flat_map_entries(content: &Value) -> impl Iterator<Item = (String, String)> + '_ {
    content
        .as_dict()
        .unwrap_or_default()
        .iter()
        .filter_map(|(key, value)| {
            let identifier = key.as_str()?.to_owned();
            let name = value
                .as_str()
                .map_or_else(|| format!("{value:?}"), ToOwned::to_owned);
            Some((identifier, name))
        })
}

/// Power state and sleep/wake.
#[derive(Debug)]
pub struct CompanionPower {
    api: Arc<CompanionApi>,
}

impl CompanionPower {
    /// Wrap a connected session.
    #[must_use]
    pub const fn new(api: Arc<CompanionApi>) -> Self {
        Self { api }
    }

    /// Whether a power state has ever been observed.
    ///
    /// `supports_power_updates` (`__init__.py:214-217`), which is what
    /// [`pyatv_core::FeatureName::PowerState`] resolves through.
    #[must_use]
    pub fn supports_power_updates(&self) -> bool {
        self.api.observed().power_known
    }

    /// Send one power HID command, then optionally wait for the device to confirm.
    ///
    /// The HID command is sent **up only**, with no preceding down — the one button pathway that
    /// does not follow the down/up pairing every other press uses (`__init__.py:280-292`,
    /// `docs/research/companion-port-spec.md` §3.7).
    fn transition(
        &self,
        command: HidCommand,
        target: PowerState,
        await_new_state: bool,
    ) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            // Enqueued *before* the command goes out. `Notify::notified()` alone does not register
            // a waiter — `notify_waiters()` skips a future that has never been polled — so
            // `enable()` is what makes the event the device pushes back impossible to miss in the
            // window between the write and the first `await`.
            let mut notified = std::pin::pin!(self.api.state().power_changed.notified());
            notified.as_mut().enable();

            self.api.hid_command(false, command).await?;

            if !await_new_state {
                return Ok(());
            }

            tokio::time::timeout(POWER_TIMEOUT, async {
                loop {
                    if self.api.observed().power == target {
                        return;
                    }
                    notified.as_mut().await;
                    notified.set(self.api.state().power_changed.notified());
                    notified.as_mut().enable();
                }
            })
            .await
            .map_err(|_| Error::Timeout {
                millis: u64::try_from(POWER_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
            })
        })
    }
}

impl Power for CompanionPower {
    fn power_state(&self) -> PowerState {
        self.api.observed().power
    }

    fn turn_on(&self, await_new_state: bool) -> BoxFuture<'_, Result<()>> {
        self.transition(HidCommand::Wake, PowerState::On, await_new_state)
    }

    fn turn_off(&self, await_new_state: bool) -> BoxFuture<'_, Result<()>> {
        self.transition(HidCommand::Sleep, PowerState::Off, await_new_state)
    }
}

/// Volume control.
///
/// Every mutation is **event-gated**: the command goes out, and the call does not resolve until the
/// device pushes an `_iMC` with the volume bit set and the follow-up `GetVolume` has landed
/// (`__init__.py:461-487`). That is why these are not fire-and-forget even though the underlying
/// `_hidC`/`_mcc` commands are answered immediately.
///
/// The gate cannot tell *which* report it woke on. Nothing in the protocol correlates an `_iMC`
/// push with the command that caused it, so a report already in flight — from a subscription, or
/// from someone changing the volume on another remote — satisfies the wait just as well.
/// Upstream's `asyncio.Event` has exactly the same property, and this port keeps it rather than
/// inventing a correlation the wire does not provide.
#[derive(Debug)]
pub struct CompanionAudio {
    api: Arc<CompanionApi>,
}

impl CompanionAudio {
    /// Wrap a connected session.
    #[must_use]
    pub const fn new(api: Arc<CompanionApi>) -> Self {
        Self { api }
    }

    /// Run `send`, then wait for the device to confirm the new volume.
    fn gated(
        &self,
        send: impl Future<Output = crate::Result<()>> + Send + 'static,
    ) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            // Enqueued *before* the command goes out: `notify_waiters()` skips a `Notified` that
            // has never been polled, so `enable()` is what closes the window between the write and
            // the first `await` on it.
            let mut notified = std::pin::pin!(self.api.state().volume_changed.notified());
            notified.as_mut().enable();

            send.await?;

            tokio::time::timeout(VOLUME_TIMEOUT, notified)
                .await
                .map_err(|_| Error::Timeout {
                    millis: u64::try_from(VOLUME_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
                })
        })
    }
}

impl Audio for CompanionAudio {
    /// The last volume read back, or `0.0` if the device reports no volume control.
    fn volume(&self) -> f32 {
        self.api.observed().volume
    }

    /// `output_device` is ignored: Companion has no way to address one speaker in a group, and
    /// upstream's `CompanionAudio.set_volume` likewise takes the argument and never reads it
    /// (`__init__.py:461-470`).
    fn set_volume(
        &self,
        level: f32,
        _output_device: Option<&OutputDevice>,
    ) -> BoxFuture<'_, Result<()>> {
        let api = Arc::clone(&self.api);
        self.gated(async move { api.set_volume(level).await })
    }

    /// A `VolumeUp` press, then a wait for the device to report the new level.
    fn volume_up(&self) -> BoxFuture<'_, Result<()>> {
        let api = Arc::clone(&self.api);
        self.gated(async move {
            api.hid_command(true, HidCommand::VolumeUp).await?;
            api.hid_command(false, HidCommand::VolumeUp).await
        })
    }

    fn volume_down(&self) -> BoxFuture<'_, Result<()>> {
        let api = Arc::clone(&self.api);
        self.gated(async move {
            api.hid_command(true, HidCommand::VolumeDown).await?;
            api.hid_command(false, HidCommand::VolumeDown).await
        })
    }

    /// Not implemented by Companion: `AirPlay` 2 owns output-device grouping.
    fn output_devices(&self) -> Vec<OutputDevice> {
        Vec::new()
    }

    /// Not implemented by Companion.
    fn add_output_devices(&self, _identifiers: &[String]) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Err(not_supported("output devices over Companion")) })
    }

    /// Not implemented by Companion.
    fn remove_output_devices(&self, _identifiers: &[String]) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Err(not_supported("output devices over Companion")) })
    }

    /// Not implemented by Companion.
    fn set_output_devices(&self, _identifiers: &[String]) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Err(not_supported("output devices over Companion")) })
    }
}

/// Whether the device currently reports volume control at all.
///
/// The `MediaControlFlags.Volume` bit from the last `_iMC` push, which is what gates
/// [`pyatv_core::FeatureName::Volume`] and [`pyatv_core::FeatureName::SetVolume`].
#[must_use]
pub fn has_volume_control(control_flags: u64) -> bool {
    control_flags & media_control_flags::VOLUME != 0
}

#[cfg(test)]
mod tests {
    use super::{flat_map_entries, has_volume_control};
    use pyatv_opack::opack;

    #[test]
    fn an_app_list_maps_keys_to_identifiers_and_values_to_names() {
        let content = opack! {
            "com.apple.TVMusic" => "Music",
            "com.netflix.Netflix" => "Netflix",
        };

        let entries: Vec<(String, String)> = flat_map_entries(&content).collect();
        assert_eq!(
            entries,
            vec![
                ("com.apple.TVMusic".to_owned(), "Music".to_owned()),
                ("com.netflix.Netflix".to_owned(), "Netflix".to_owned()),
            ]
        );
    }

    #[test]
    fn an_empty_or_non_dict_content_yields_nothing() {
        assert_eq!(flat_map_entries(&opack! {}).count(), 0);
        assert_eq!(
            flat_map_entries(&pyatv_opack::Value::from("not a dict")).count(),
            0
        );
    }

    #[test]
    fn the_volume_bit_is_0x0100() {
        assert!(has_volume_control(0x0100));
        assert!(has_volume_control(0x0703));
        assert!(!has_volume_control(0x0003));
        assert!(!has_volume_control(0x0000));
    }
}
