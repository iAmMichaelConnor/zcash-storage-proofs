//! The `aztec_contents` claim with natively computed Sinsemilla hints supplied
//! in capsules (slots 70 to 101 and 102) instead of being computed in Noir. The circuit still checks every
//! hint, so the statement is the same; only the hint transport differs.
//!
//! The caller passes the checkpoint, as in `aztec_contents`; an application
//! must take it from its own authenticated storage.
use aztec::{macros::aztec, protocol::address::AztecAddress};

/// The body of `IronwoodPrivateContentsCapsules::verify`: claim 0 of the capsules of `address`.
pub fn verify_contents_capsules(
    address: AztecAddress,
    expected_hash: [u8; 32],
    header_height: u32,
    is_testnet: bool,
) -> ([u8; 32], u64, [[[u128; 3]; 2]; 2], [u128; 3], u32) {
    ironwood_aztec::verify_contents_capsules(address, 0, expected_hash, header_height, is_testnet)
}

#[aztec]
pub contract IronwoodPrivateContentsCapsules {
    use aztec::macros::functions::external;
    #[external("private")]
    fn verify(
        expected_hash: [u8; 32],
        header_height: u32,
        is_testnet: bool,
    ) -> ([u8; 32], u64, [[[u128; 3]; 2]; 2], [u128; 3], u32) {
        crate::verify_contents_capsules(self.address, expected_hash, header_height, is_testnet)
    }
}
