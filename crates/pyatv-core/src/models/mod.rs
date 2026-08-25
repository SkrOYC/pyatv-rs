//! Device, service and playback data models.
//!
//! Equivalent to pyatv's `interface.BaseConfig`/`interface.BaseService` (plus `conf.AppleTV` and
//! `core.MutableService`), collapsed into plain structs. pyatv needs abstract base classes here
//! because Python has no way to express "a config the scanner mutates while building it, then
//! hands out immutably"; in Rust ownership already expresses that, so [`BaseConfig`] is a concrete
//! struct that the scanner builds and the caller consumes.
//!
//! See `docs/research/pyatv-architecture.md` §4 for the upstream contract these mirror.
//!
//! [`DeviceInfo`] is re-exported from [`crate::device_info`], where it sits next to the model and
//! build-number tables it is derived from.

mod config;
mod media;
mod playing;
mod service;

pub use config::BaseConfig;
pub use media::{MediaMetadata, MediaSource, OutputDevice};
pub use playing::{App, ArtworkInfo, Playing, UserAccount};
pub use service::BaseService;

pub use crate::device_info::DeviceInfo;
