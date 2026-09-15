//! Background worker maintaining connection, metadata polling and discovery for Apple TV.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use pyatv::AppleTV;
use pyatv::{BaseConfig, DeviceState, FileStorage, ScanOptions, Storage};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use super::{BackendEvent, UiAction};
use crate::remote::RemoteCommand;
use crate::state::{DiscoveredDevice, NowPlaying, PlaybackState};

pub(crate) struct BackendWorker {
    event_tx: UnboundedSender<BackendEvent>,
    storage: Arc<dyn Storage>,
    known_configs: Vec<BaseConfig>,
    active_atv: Option<Arc<dyn AppleTV>>,
    active_device_id: Option<String>,
    active_can_navigate: bool,
    user_disconnected: bool,
    active_pairing: Option<Box<dyn pyatv::PairingHandler>>,
}

impl BackendWorker {
    pub(crate) fn new(event_tx: UnboundedSender<BackendEvent>) -> Self {
        let storage: Arc<dyn Storage> = match FileStorage::default_path() {
            Ok(path) => {
                let file_storage = FileStorage::new(path);
                let _ = file_storage.load();
                Arc::new(file_storage)
            }
            Err(_) => Arc::new(pyatv::MemoryStorage::new()),
        };

        Self {
            event_tx,
            storage,
            known_configs: Vec::new(),
            active_atv: None,
            active_device_id: None,
            active_can_navigate: false,
            user_disconnected: false,
            active_pairing: None,
        }
    }

    pub(crate) async fn run(&mut self, mut action_rx: UnboundedReceiver<UiAction>) {
        // Automatically perform a network scan on startup
        self.scan().await;

        let mut poll_interval = tokio::time::interval(Duration::from_secs(3));

        loop {
            tokio::select! {
                Some(action) = action_rx.recv() => {
                    self.handle_action(action).await;
                }
                _ = poll_interval.tick() => {
                    if self.active_atv.is_some() {
                        self.poll_metadata().await;
                    }
                }
                else => break,
            }
        }
    }

    async fn handle_action(&mut self, action: UiAction) {
        match action {
            UiAction::Scan => self.scan().await,
            UiAction::Connect(id) => self.connect(&id).await,
            UiAction::Disconnect => self.disconnect(),
            UiAction::SendCommand(cmd) => self.send_command(cmd).await,
            UiAction::RefreshMetadata => self.poll_metadata().await,
            UiAction::StartPairing(id) => self.start_pairing(&id).await,
            UiAction::SubmitPin(pin) => self.submit_pin(pin).await,
            UiAction::CancelPairing => self.cancel_pairing(),
        }
    }

    async fn scan(&mut self) {
        let _ = self.event_tx.send(BackendEvent::ScanStarted);
        let _ = self.storage.load();

        let candidate_hosts = crate::discovery::discover_candidate_hosts();
        tracing::info!(?candidate_hosts, "scanning with candidate hosts");

        let mcast_options = ScanOptions {
            timeout: Duration::from_secs(3),
            identifiers: HashSet::new(),
            protocols: HashSet::new(),
            hosts: Vec::new(),
        };

        let ucast_options = if candidate_hosts.is_empty() {
            None
        } else {
            Some(ScanOptions {
                timeout: Duration::from_secs(3),
                identifiers: HashSet::new(),
                protocols: HashSet::new(),
                hosts: candidate_hosts,
            })
        };

        let (mcast_res, ucast_res) = tokio::join!(pyatv::scan(mcast_options), async {
            if let Some(opts) = ucast_options {
                pyatv::scan(opts).await
            } else {
                Ok(Vec::new())
            }
        });

        let mut all_configs: Vec<BaseConfig> = Vec::new();
        let mut seen_ids = HashSet::new();

        for configs in [mcast_res, ucast_res].into_iter().flatten() {
            for mut config in configs {
                let id = config.identifier().unwrap_or(&config.name).to_string();
                if seen_ids.insert(id) {
                    if config.ready()
                        && let Ok(settings) = self.storage.get_settings(&config)
                    {
                        config.apply(&settings);
                    }
                    all_configs.push(config);
                }
            }
        }

        let _ = self.storage.save();
        self.known_configs = all_configs;
        let devices = Self::convert_configs(&self.known_configs);
        tracing::info!(
            count = devices.len(),
            ?devices,
            "scan complete, devices discovered"
        );
        let _ = self
            .event_tx
            .send(BackendEvent::DevicesDiscovered(devices.clone()));

        // Auto-connect or auto-reconnect logic
        if let Some(active_id) = &self.active_device_id {
            let is_now_paired = devices
                .iter()
                .any(|d| (d.identifier == *active_id || d.name == *active_id) && d.is_paired);
            if (!self.active_can_navigate && is_now_paired) || self.active_atv.is_none() {
                let id_to_connect = active_id.clone();
                tracing::info!(id = %id_to_connect, "reconnecting device with updated credentials");
                self.connect(&id_to_connect).await;
            }
        } else if !self.user_disconnected {
            let auto_target = devices.iter().find(|d| d.is_paired).or_else(|| {
                if devices.len() == 1 {
                    devices.first()
                } else {
                    None
                }
            });
            if let Some(target) = auto_target {
                let target_id = target.identifier.clone();
                tracing::info!(id = %target_id, name = %target.name, "auto-connecting to device");
                self.connect(&target_id).await;
            }
        }
    }

    pub(crate) async fn connect(&mut self, target_id: &str) {
        let _ = self.storage.load();
        self.active_atv = None;
        self.active_device_id = None;
        self.active_can_navigate = false;
        self.user_disconnected = false;

        let config = self
            .known_configs
            .iter()
            .find(|c| {
                c.identifier().is_some_and(|id| id == target_id)
                    || c.all_identifiers().contains(&target_id)
                    || c.name == target_id
            })
            .cloned();

        let Some(mut config) = config else {
            let _ = self.event_tx.send(BackendEvent::Error(
                "Device not found in scanned list".into(),
            ));
            return;
        };

        if let Ok(settings) = self.storage.get_settings(&config) {
            config.apply(&settings);
        }

        let device_name = config.name.clone();
        let id_string = config.identifier().unwrap_or(target_id).to_string();
        let _ = self
            .event_tx
            .send(BackendEvent::Connecting(device_name.clone()));

        match pyatv::connect(&config, None, self.storage.clone()).await {
            Ok(atv) => {
                let can_navigate = atv.features().get_feature(pyatv::FeatureName::Home).state
                    != pyatv::FeatureState::Unsupported;

                tracing::info!(
                    %device_name,
                    id = %id_string,
                    can_navigate,
                    "connected to device"
                );

                self.active_atv = Some(atv);
                self.active_device_id = Some(id_string.clone());
                self.active_can_navigate = can_navigate;
                let _ = self.event_tx.send(BackendEvent::Connected {
                    name: device_name,
                    id: id_string,
                    can_navigate,
                });
                self.poll_metadata().await;
            }
            Err(err) => {
                tracing::warn!(%device_name, ?err, "failed to connect to device");
                let _ = self
                    .event_tx
                    .send(BackendEvent::Error(format!("Connection failed: {err}")));
            }
        }
    }

    pub(crate) fn disconnect(&mut self) {
        self.active_atv = None;
        self.active_device_id = None;
        self.active_can_navigate = false;
        self.user_disconnected = true;
        let _ = self.event_tx.send(BackendEvent::Disconnected);
    }

    async fn start_pairing(&mut self, target_id: &str) {
        let _ = self.storage.load();
        let config = self
            .known_configs
            .iter()
            .find(|c| {
                c.identifier().is_some_and(|id| id == target_id)
                    || c.all_identifiers().contains(&target_id)
                    || c.name == target_id
            })
            .cloned();

        let Some(config) = config else {
            let _ = self
                .event_tx
                .send(BackendEvent::PairingFailed("Device not found".into()));
            return;
        };

        let device_name = config.name.clone();
        let id_string = config.identifier().unwrap_or(target_id).to_string();

        match pyatv::pair(&config, pyatv::Protocol::Companion, self.storage.clone()).await {
            Ok(handler) => match handler.begin().await {
                Ok(()) => {
                    self.active_pairing = Some(handler);
                    let _ = self.event_tx.send(BackendEvent::PairingStarted {
                        name: device_name,
                        identifier: id_string,
                    });
                }
                Err(err) => {
                    let _ = self.event_tx.send(BackendEvent::PairingFailed(format!(
                        "Failed to begin pairing: {err}"
                    )));
                }
            },
            Err(err) => {
                let _ = self.event_tx.send(BackendEvent::PairingFailed(format!(
                    "Pairing not supported: {err}"
                )));
            }
        }
    }

    async fn submit_pin(&mut self, pin: u32) {
        let Some(handler) = self.active_pairing.take() else {
            let _ = self
                .event_tx
                .send(BackendEvent::PairingFailed("No active pairing".into()));
            return;
        };

        if let Err(err) = handler.pin(pin) {
            let _ = self
                .event_tx
                .send(BackendEvent::PairingFailed(format!("Invalid PIN: {err}")));
            return;
        }

        match handler.finish().await {
            Ok(()) => {
                if handler.has_paired() {
                    let _ = self.storage.save();
                    let _ = self.event_tx.send(BackendEvent::PairingSucceeded);
                    self.user_disconnected = false;
                    self.scan().await;
                } else {
                    let _ = self
                        .event_tx
                        .send(BackendEvent::PairingFailed("Pairing rejected".into()));
                }
            }
            Err(err) => {
                let _ = self.event_tx.send(BackendEvent::PairingFailed(format!(
                    "Pairing failed: {err}"
                )));
            }
        }
    }

    fn cancel_pairing(&mut self) {
        self.active_pairing = None;
    }

    async fn send_command(&mut self, cmd: RemoteCommand) {
        let Some(atv) = &self.active_atv else {
            let _ = self
                .event_tx
                .send(BackendEvent::CommandFailed("No device connected".into()));
            return;
        };

        let label = cmd.label().to_string();
        match cmd.execute(atv).await {
            Ok(()) => {
                let _ = self.event_tx.send(BackendEvent::Toast(label));
                // If it was play/pause or next/prev, poll metadata immediately
                if matches!(
                    cmd,
                    RemoteCommand::PlayPause
                        | RemoteCommand::Play
                        | RemoteCommand::Pause
                        | RemoteCommand::Next
                        | RemoteCommand::Previous
                ) {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    self.poll_metadata().await;
                }
            }
            Err(err) => {
                tracing::warn!(?err, %label, "command execution failed");
                let _ = self
                    .event_tx
                    .send(BackendEvent::CommandFailed(format!("{label}: {err}")));
            }
        }
    }

    async fn poll_metadata(&mut self) {
        let Some(atv) = &self.active_atv else { return };

        if let Some(meta) = atv.metadata()
            && let Ok(playing) = meta.playing().await
        {
            let state = match playing.device_state {
                DeviceState::Playing => PlaybackState::Playing,
                DeviceState::Paused => PlaybackState::Paused,
                DeviceState::Stopped => PlaybackState::Stopped,
                _ => PlaybackState::Idle,
            };

            let now_playing = playing.title.map(|title| NowPlaying {
                title,
                artist: playing.artist,
                album: playing.album,
                state,
            });

            let _ = self
                .event_tx
                .send(BackendEvent::NowPlayingUpdated(now_playing));
        }

        let power_on = atv
            .power()
            .is_some_and(|p| p.power_state() == pyatv::PowerState::On);
        let _ = self
            .event_tx
            .send(BackendEvent::PowerStateUpdated(power_on));
    }

    fn convert_configs(configs: &[BaseConfig]) -> Vec<DiscoveredDevice> {
        configs
            .iter()
            .filter_map(|c| {
                let id = c.identifier()?;
                let is_paired = c
                    .get_service(pyatv::Protocol::Companion)
                    .is_some_and(|s| s.credentials.is_some())
                    || c.get_service(pyatv::Protocol::Mrp)
                        .is_some_and(|s| s.credentials.is_some());
                Some(DiscoveredDevice {
                    name: c.name.clone(),
                    identifier: id.to_string(),
                    address: Some(c.address.to_string()),
                    is_paired,
                })
            })
            .collect()
    }
}
