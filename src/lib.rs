// src/lib.rs
//
// Thin library crate whose only purpose is to make the modules below
// reachable from tests/*.rs integration tests, which compile as a separate
// crate and can only see items through a `[lib]` target — a bin-only crate
// (the previous shape of this project) is invisible to them. `main.rs` is
// now a binary that depends on this library crate instead of declaring
// these modules itself; nothing about the modules' own code changed.

pub mod advisory;
pub mod audit;
pub mod downstream;
pub mod hasher;
pub mod membrane;
pub mod pin_policy;
pub mod provenance;
pub mod quota;
pub mod registry;
pub mod rules_engine;
pub mod schema_check;
