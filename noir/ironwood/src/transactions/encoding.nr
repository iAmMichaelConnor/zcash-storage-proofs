// Canonical byte encoding for private capsule adapters. Generic bounds remain
// compile-time constants; no copy of the digest or completeness relation here.
pub fn u32le<let N: u32>(bytes: [u8; N], offset: u32) -> u32 {
    let mut v = 0u32;
    for i in 0..4 {
        v = v + ((bytes[offset + i] as u32) << ((8 * i) as u32));
    }
    v
}
pub fn row<let A: u32, let N: u32>(
    bytes: [u8; N],
    offset: u32,
) -> crate::transactions::digest::NullifierAbsenceEffects<A> {
    assert(offset + 185 + 148 * A <= N);
    let mut compact = [[0u8; 148]; A];
    for i in 0..A {
        for j in 0..148 {
            compact[i][j] = bytes[offset + 148 * i + j];
        }
    }
    let o = offset + 148 * A;
    let mut memos = [0u8; 32];
    let mut noncompact = [0u8; 32];
    for i in 0..32 {
        memos[i] = bytes[o + i];
        noncompact[i] = bytes[o + 32 + i];
    }
    let mut balance = [0u8; 8];
    for i in 0..8 {
        balance[i] = bytes[o + 65 + i];
    }
    let mut other = [[0u8; 32]; 3];
    for i in 0..3 {
        for j in 0..32 {
            other[i][j] = bytes[o + 73 + 32 * i + j];
        }
    }
    let effects = crate::transactions::digest::V6Effects {
        compact_actions: compact,
        memos_digest: memos,
        noncompact_digest: noncompact,
        flags: bytes[o + 64],
        value_balance: balance,
        transparent_digest: other[0],
        sapling_digest: other[1],
        orchard_digest: other[2],
        lock_time: u32le(bytes, o + 169),
        expiry_height: u32le(bytes, o + 173),
    };
    crate::transactions::digest::NullifierAbsenceEffects {
        effects,
        version: u32le(bytes, o + 177),
        action_count: u32le(bytes, o + 181),
    }
}
pub fn blocks<let B: u32, let TX: u32, let A: u32, let N: u32>(
    bytes: [u8; N],
) -> [crate::transactions::nullifier_absence::BlockEffects<TX, A>; B] {
    assert(B > 0);
    assert(TX > 0);
    assert(N == B * (1491 + TX * (185 + 148 * A)));
    let blank = row::<A, N>(bytes, 1491);
    let mut result = [
        crate::transactions::nullifier_absence::BlockEffects {
            header: [0u8; 1487],
            transactions: [blank; TX],
            transaction_count: 0,
        }; B
    ];
    for b in 0..B {
        let start = b * (1491 + TX * (185 + 148 * A));
        let mut header = [0u8; 1487];
        for i in 0..1487 {
            header[i] = bytes[start + i];
        }
        let mut rows = [blank; TX];
        for i in 0..TX {
            rows[i] = row::<A, N>(bytes, start + 1491 + i * (185 + 148 * A));
        }
        result[b] = crate::transactions::nullifier_absence::BlockEffects {
            header,
            transactions: rows,
            transaction_count: u32le(bytes, start + 1487),
        };
    }
    result
}
pub fn mixed_blocks<let B: u32, let TX: u32, let A: u32, let RAW: u32, let N: u32>(
    bytes: [u8; N],
) -> [crate::transactions::legacy::Block<TX, A, RAW>; B] {
    assert(B > 0);
    assert(TX > 0);
    assert(N == B * (1491 + TX * (189 + 148 * A + RAW)));
    let blank = crate::transactions::legacy::Effects {
        effects: row::<A, N>(bytes, 1491),
        raw_v4: [0u8; RAW],
        raw_length: 0,
    };
    let mut result = [
        crate::transactions::legacy::Block {
            header: [0u8; 1487],
            transactions: [blank; TX],
            transaction_count: 0,
        }; B
    ];
    for b in 0..B {
        let start = b * (1491 + TX * (189 + 148 * A + RAW));
        let mut header = [0u8; 1487];
        for i in 0..1487 {
            header[i] = bytes[start + i];
        }
        let mut rows = [blank; TX];
        for i in 0..TX {
            let off = start + 1491 + i * (189 + 148 * A + RAW);
            let raw_off = off + 185 + 148 * A;
            let mut raw = [0u8; RAW];
            for j in 0..RAW {
                raw[j] = bytes[raw_off + 4 + j];
            }
            rows[i] = crate::transactions::legacy::Effects {
                effects: row::<A, N>(bytes, off),
                raw_v4: raw,
                raw_length: u32le(bytes, raw_off),
            };
        }
        result[b] = crate::transactions::legacy::Block {
            header,
            transactions: rows,
            transaction_count: u32le(bytes, start + 1487),
        };
    }
    result
}
