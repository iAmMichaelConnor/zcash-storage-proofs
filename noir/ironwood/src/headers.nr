// Zcash NU6.3 history-root openings. The caller authenticates its checkpoint.
// No note-tree or nullifier-set validity is implied by parsing a header alone.
pub mod compact_size;
pub mod history;
mod history_tests;
mod header_tests;
pub mod header;
pub use history::{LatestSnapshot, verify_latest, parse_v3};
pub use header::{header_hash, block_commitments, verify_header_latest};
