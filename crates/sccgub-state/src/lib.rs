// Patch-05 §23: iteration-order determinism discipline. Any iteration
// over a HashMap / HashSet in this crate is a compile error. Lookup-only
// uses (`.get()`, `.contains_key()`, `.insert()`) are unaffected. When
// a legitimate use case exists (e.g., serialization via sorted proxy),
// prefer `BTreeMap` / `BTreeSet`; exceptional `HashMap` iterations must
// carry `#[allow(clippy::iter_over_hash_type)]` with a written rationale.
#![deny(clippy::iter_over_hash_type)]

pub mod apply;
pub mod assets;
pub mod balances;
pub mod constitutional_ceilings_state;
pub mod escrow;
pub mod key_rotation_state;
pub mod store;
pub mod tension;
pub mod treasury;
pub mod trie;
pub mod validator_set_state;
pub mod world;
