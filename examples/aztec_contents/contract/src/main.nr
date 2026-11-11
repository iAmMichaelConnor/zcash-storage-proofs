//! Key-free note contents in an Aztec private function, through the
//! `ironwood_aztec` capsule transport (slots 60 and 61, claim 0; one claim per
//! transaction per contract address).
//!
//! `verify` opens a note against the Ironwood root of the header checkpoint
//! `(expected_hash, header_height, is_testnet)` and returns
//! `(cmx, value, receiver, rho, snapshot height)`. The caller passes the
//! checkpoint, so this contract proves nothing about Zcash on its own: an
//! application reads the checkpoint from its own authenticated storage, as
//! `examples/note_value` does. No spending or viewing key is consumed, and no
//! nullifier is emitted.
use aztec::{macros::aztec, protocol::address::AztecAddress};

/// The body of `IronwoodPrivateContents::verify`: claim 0 of the capsules of `address`.
pub fn verify_contents(
    address: AztecAddress,
    expected_hash: [u8; 32],
    header_height: u32,
    is_testnet: bool,
) -> ([u8; 32], u64, [[[u128; 3]; 2]; 2], [u128; 3], u32) {
    ironwood_aztec::verify_contents(address, 0, expected_hash, header_height, is_testnet)
}

#[aztec]
pub contract IronwoodPrivateContents {
    use aztec::macros::functions::external;
    #[external("private")]
    fn verify(
        expected_hash: [u8; 32],
        header_height: u32,
        is_testnet: bool,
    ) -> ([u8; 32], u64, [[[u128; 3]; 2]; 2], [u128; 3], u32) {
        crate::verify_contents(self.address, expected_hash, header_height, is_testnet)
    }
}
