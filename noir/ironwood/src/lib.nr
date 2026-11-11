//! Pure Noir relations for Zcash Ironwood V3 notes in V6 transactions under NU6.3:
//! `notes`, `headers`, `transactions`, `creation`, `memo` and the shared
//! `hashes`, `poseidon` and `sinsemilla` arithmetic. No Aztec dependency.
//! The relations open chain data under an application-authenticated checkpoint;
//! transaction effects do not verify transaction proofs, signatures or consensus.
//! Claims, composition rules and consumer obligations: docs/API.md. Arithmetic
//! preconditions (`#[no_predicates]` calls, prechecked BigNum terms): docs/COMPOSITION.md.
pub mod hashes;
pub mod headers;
pub mod notes;
pub mod transactions;
pub mod poseidon;
pub mod sinsemilla;

pub mod creation;
pub mod memo;
mod benchmarks;
pub use bignum::{BigNum, Pallas_Fq, Pallas_Fr};
pub use bigcurve::{BigCurve, Pallas};

// Headline entry points, re-exported so a consumer can `use ironwood::{...}`.
// The absence scans stay under their modules because two share one name:
// transactions::nullifier_absence::from_activation (V5/V6 blocks),
// transactions::legacy::from_activation (blocks with V4 transactions) and
// transactions::nullifier_absence_state::{initialize, advance}.
pub use creation::verify_created_in_block;
pub use headers::{LatestSnapshot, verify_header_latest, verify_latest};
pub use memo::{FullActionCiphertext, verify_memo_created_in_block};
pub use notes::{
    commitment_x, ExpandedReceiver, NoteOpening, verify_contents_membership,
    verify_owned_membership,
};
pub use notes::nullifier::{derive_member, derive_owned, derive_with_commitment};
pub use notes::ownership::{SpendAuthority, ViewingAuthority};
pub use transactions::{V6Effects, verify_nullifier_inclusion};
pub use transactions::effects::{
    ActionEffect, Inclusion, verify_action, verify_output, verify_transaction,
};
