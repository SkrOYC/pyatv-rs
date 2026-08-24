//! Protocol-agnostic core of the pyatv-rs workspace.
//!
//! This crate owns everything that is true about an Apple TV or `AirPlay` device regardless of which wire protocol is used to talk to it: the public capability traits ([`interface`]), the constant enums that appear in the public API ([`consts`], [`features`]), the device/service configuration models ([`models`]), the priority-selection [`relayer::Relayer`], the [`facade::FacadeAppleTV`] that fans a single call out to whichever protocol implements it, the credential/settings [`storage`] abstraction, and the crate-wide [`Error`] type.
//!
//! The layering rule for the whole workspace is enforced here by construction: `pyatv-core` must never depend on a protocol crate. Protocol crates (`pyatv-proto-mrp`, `pyatv-proto-companion`, `pyatv-proto-airplay`, `pyatv-proto-dmap`) depend on this crate and implement its traits; the `pyatv` umbrella crate is the only place that knows about all of them at once.
//!
//! Wire-format and behavioural details behind these types are documented in the research reports under `docs/research/`, primarily `pyatv-architecture.md` (public API surface, the scan/pair/connect flow, the `Relayer`/facade design, the exact enum discriminants reproduced in [`consts`], and the storage model).

pub mod consts;
pub mod error;
pub mod facade;
pub mod features;
pub mod interface;
pub mod models;
pub mod relayer;
pub mod storage;

pub use consts::{
    DeviceModel, DeviceState, InputAction, KeyboardFocusState, MediaType, OperatingSystem,
    PairingRequirement, PowerState, Protocol, RepeatState, ShuffleState, TouchAction,
};
pub use error::{Error, Result};
pub use features::{FeatureInfo, FeatureName, FeatureState};
pub use models::{App, ArtworkInfo, BaseConfig, BaseService, DeviceInfo, UserAccount};
pub use relayer::Relayer;
