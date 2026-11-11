// Exact NU6.3 transaction-effect openings. Accepted headers provide consensus.
pub mod digest;
pub mod merkle;
pub use digest::{V6Effects, txid_v6, ironwood_digest, verify_nullifier_inclusion};
pub mod nullifier_absence;
pub mod encoding;
pub mod legacy;
pub mod nullifier_absence_state;
pub mod effects;
mod inclusion_tests;
mod legacy_tests;
