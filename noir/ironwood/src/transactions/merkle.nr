// Zcash transaction tree uses SHA256d and duplicate-last padding.
pub fn pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut bytes = [0u8; 64];
    for i in 0..32 {
        bytes[i] = left[i];
        bytes[32 + i] = right[i];
    }
    sha256::digest(sha256::digest(bytes))
}
// tx_count/index describe a path shape, not an independently authenticated block
// transaction count. The only output claim is leaf membership in expected_root.
pub fn verify<let DEPTH: u32>(
    leaf: [u8; 32],
    siblings: [[u8; 32]; DEPTH],
    index: u32,
    count: u32,
    expected_root: [u8; 32],
) {
    assert(DEPTH <= 32);
    assert(count > 0, "Merkle path count is zero");
    assert(index < count, "Merkle leaf index beyond count");
    let mut width = count;
    let mut position = index;
    let mut node = leaf;
    for i in 0..DEPTH {
        if width > 1 {
            let right = (position & 1) == 1;
            if !right & (position + 1 == width) {
                assert(siblings[i] == node, "Wrong duplicate-last sibling");
            }
            let left = if right { siblings[i] } else { node };
            let other = if right { node } else { siblings[i] };
            node = pair(left, other);
            position = position / 2;
            width = width / 2 + width % 2;
        } else {
            assert(siblings[i] == [0u8; 32], "Nonzero unused Merkle sibling");
        }
    }
    assert(width == 1, "Merkle path capacity too small");
    assert(position == 0);
    assert(node == expected_root, "Transaction Merkle root mismatch");
}

// Reconstruct the complete canonical list. Active leaves are all opened txids,
// never caller-supplied opaque hashes. Duplicate leaves are invalid in Zcash.
pub fn complete_root<let MAX_TX: u32>(leaves: [[u8; 32]; MAX_TX], count: u32) -> [u8; 32] {
    assert(MAX_TX > 0);
    assert((MAX_TX & (MAX_TX - 1)) == 0, "Transaction capacity must be a power of two");
    assert(count > 0);
    assert(count <= MAX_TX);
    for i in 0..MAX_TX {
        if i < count {
            for j in 0..MAX_TX {
                if (j < i) & (j < count) {
                    assert(leaves[i] != leaves[j], "Duplicate transaction id");
                }
            }
        } else {
            // Defence in depth only: callers leave inactive leaves as the constant
            // zero, so this enforces nothing about inactive capsule rows.
            assert(leaves[i] == [0u8; 32], "Nonzero unused transaction leaf");
        }
    }
    let mut nodes = leaves;
    let mut width = count;
    for level in 0..32 {
        if (1u64 << (level as u64)) < (MAX_TX as u64) {
            if width > 1 {
                let mut next = [[0u8; 32]; MAX_TX];
                for i in 0..MAX_TX / 2 {
                    if 2 * i < width {
                        let left = nodes[2 * i];
                        let right = if 2 * i + 1 < width {
                            nodes[2 * i + 1]
                        } else {
                            left
                        };
                        if 2 * i + 1 < width {
                            assert(left != right, "Mutated transaction Merkle tree");
                        }
                        next[i] = pair(left, right);
                    }
                }
                nodes = next;
                width = width / 2 + width % 2;
            }
        }
    }
    assert(width == 1);
    nodes[0]
}
