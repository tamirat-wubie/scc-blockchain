// Patch-04 §15 + §16 discipline: iteration over hash-based containers
// (HashMap/HashSet) in consensus paths produces non-deterministic order,
// which can diverge state roots between honest nodes. Deny the lint so
// any future iteration over an unordered container in this crate is a
// compile error; existing lookup-only uses of `HashMap` are unaffected.
#![deny(clippy::iter_over_hash_type)]

pub mod equivocation;
pub mod finality;
pub mod law_sync;
pub mod partition;
pub mod protocol;
pub mod safety;
pub mod slashing;
pub mod view_change;
