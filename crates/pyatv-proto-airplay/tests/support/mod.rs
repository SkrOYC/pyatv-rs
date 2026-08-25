//! Shared test scaffolding.
//!
//! Every integration test binary compiles the whole module, so items only one of them uses would
//! otherwise be reported dead in the others.
#![allow(dead_code)]

pub mod fake_airplay;
pub mod fake_channels;
