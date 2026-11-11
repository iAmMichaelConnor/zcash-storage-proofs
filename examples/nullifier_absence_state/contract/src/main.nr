pub mod nullifier_absence_note;
mod capsule;
pub mod scan;
mod nullifier_absence_note_tests;
use aztec::macros::aztec;
#[aztec]
pub contract IronwoodNullifierAbsenceState {
    use aztec::{
        macros::{functions::external, storage::storage},
        messages::delivery::MessageDelivery,
        state_vars::{Owned, PrivateSet},
        protocol::address::AztecAddress,
    };
    use crate::nullifier_absence_note::NullifierAbsenceNote;
    #[storage]
    struct Storage<Context> {
        scans: Owned<PrivateSet<NullifierAbsenceNote, Context>, Context>,
    }
    // Only verified initialization and continuation may insert these notes. There
    // is deliberately no function that inserts a caller-provided prior State.
    #[external("private")]
    fn begin(
        queried_nf: [u8; 32],
        expected_tip_hash: [u8; 32],
        expected_tip_height: u32,
        is_testnet: bool,
        count: u32,
    ) {
        crate::scan::begin(
            self.storage.scans.at(self.msg_sender()),
            self.address,
            queried_nf,
            expected_tip_hash,
            expected_tip_height,
            is_testnet,
            count,
        )
            .deliver(MessageDelivery::onchain_unconstrained());
    }
    // Consumes the caller's note for (nf, prior height, prior tip hash, network).
    // The prior tip hash is the parent hash of the first window block, so after a
    // reorg the note of the other lineage at the same height is never selected.
    #[external("private")]
    fn extend(
        queried_nf: [u8; 32],
        prior_height: u32,
        expected_tip_hash: [u8; 32],
        expected_tip_height: u32,
        is_testnet: bool,
        count: u32,
    ) {
        crate::scan::extend(
            self.storage.scans.at(self.msg_sender()),
            self.address,
            queried_nf,
            prior_height,
            expected_tip_hash,
            expected_tip_height,
            is_testnet,
            count,
        )
            .deliver(MessageDelivery::onchain_unconstrained());
    }
    // Reads owner's state note; it does not consume it. Any contract may call this
    // for any owner: a NullifierAbsenceNote is a true historical statement, and the Aztec
    // kernel authenticates that the note was created by begin or extend of THIS
    // contract for that owner (owner, slot and contract are in the note hash).
    // It proves creation, not freshness: a note that extend already consumed is
    // rejected only by an honest PXE lookup. The application must authenticate
    // the expected (tip hash, height, network) through its own chain policy and
    // must call a pinned IronwoodNullifierAbsenceState address or class.
    #[external("private")]
    fn verify(
        owner: AztecAddress,
        queried_nf: [u8; 32],
        expected_tip_hash: [u8; 32],
        expected_tip_height: u32,
        is_testnet: bool,
    ) -> bool {
        crate::scan::verify(
            self.storage.scans.at(owner),
            queried_nf,
            expected_tip_hash,
            expected_tip_height,
            is_testnet,
        )
    }
}
