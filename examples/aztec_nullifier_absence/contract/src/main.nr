//! A nullifier is absent from complete history, from the pinned pre-activation
//! block to an accepted tip, in one Aztec private function. The complete blocks
//! arrive in the slot-63 capsule (claim 0).
//!
//! Capacity: two complete blocks, each at most four V5/V6 transactions, each at
//! most two Ironwood Actions. Other capacities change the generic arguments and
//! the capsule length; blocks with raw V4 transactions use
//! `ironwood::transactions::legacy::from_activation` (slot 66). The tip
//! `(hash, height, network)` is a call argument here; an application must take
//! it from its own authenticated checkpoint. A scan carried across transactions
//! is `examples/nullifier_absence_state`.
mod capsule;
use aztec::{macros::aztec, protocol::address::AztecAddress};

/// The body of `IronwoodNullifierAbsence::verify`: scans the complete blocks in the slot-63
/// capsule of `address` from activation to the tip.
pub fn verify_absence(
    address: AztecAddress,
    queried_nf: [u8; 32],
    expected_tip_hash: [u8; 32],
    expected_tip_height: u32,
    is_testnet: bool,
) {
    // Safety: all capsule values are range checked, all active transactions are
    // opened, all blocks link to the accepted tip, and scan starts at activation.
    let raw = unsafe { crate::capsule::load(address) };
    let mut bytes = [0u8; 6830];
    for i in 0..6830 {
        raw[i].assert_max_bit_size::<8>();
        bytes[i] = raw[i] as u8;
    }
    let blocks = ironwood::transactions::encoding::blocks::<2, 4, 2, 6830>(bytes);
    ironwood::transactions::nullifier_absence::from_activation(
        blocks,
        queried_nf,
        expected_tip_hash,
        expected_tip_height,
        is_testnet,
    );
}

#[aztec]
pub contract IronwoodNullifierAbsence {
    use aztec::macros::functions::external;
    #[external("private")]
    fn verify(
        queried_nf: [u8; 32],
        expected_tip_hash: [u8; 32],
        expected_tip_height: u32,
        is_testnet: bool,
    ) -> bool {
        crate::verify_absence(
            self.address,
            queried_nf,
            expected_tip_hash,
            expected_tip_height,
            is_testnet,
        );
        true
    }
}
