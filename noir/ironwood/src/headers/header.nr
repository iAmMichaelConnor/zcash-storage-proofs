use crate::headers::history::{LatestSnapshot, verify_latest};
// Standard mainnet/testnet Equihash(200,9) header: 140-byte fixed prefix,
// canonical CompactSize(1344) = fd4005, then the 1344-byte solution.
// PoW/chain selection is the accepted checkpoint's responsibility.
pub fn header_hash(bytes: [u8; 1487]) -> [u8; 32] {
    assert(bytes[140] == 253, "Equihash solution size byte 140 is not 0xfd");
    assert(bytes[141] == 64, "Equihash solution size byte 141 is not 0x40");
    assert(bytes[142] == 5, "Equihash solution size byte 142 is not 0x05");
    sha256::digest(sha256::digest(bytes))
}
pub fn block_commitments(bytes: [u8; 1487]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = bytes[68 + i];
    }
    out
}
// Expected hash uses internal bytes, not the reversed human-facing hex form.
// Header height is part of the authenticated (hash,height,network) checkpoint;
// the ordinary header serialization does not contain its own height.
pub fn verify_header_latest(
    bytes: [u8; 1487],
    expected_hash: [u8; 32],
    header_height: u32,
    is_testnet: bool,
    node: [u8; 317],
    auth_root: [u8; 32],
) -> LatestSnapshot {
    assert(header_hash(bytes) == expected_hash, "Header hash mismatch");
    verify_latest(
        node,
        auth_root,
        block_commitments(bytes),
        header_height,
        is_testnet,
    )
}
