// Compact action = nf32 || cmx32 || epk32 || enc_ciphertext_prefix52.
// The complete compact sequence is hashed; it is NOT an Action Merkle tree.
pub struct V6Effects<let N: u32> {
    pub compact_actions: [[u8; 148]; N],
    pub memos_digest: [u8; 32],
    pub noncompact_digest: [u8; 32],
    pub flags: u8,
    pub value_balance: [u8; 8],
    pub transparent_digest: [u8; 32],
    pub sapling_digest: [u8; 32],
    pub orchard_digest: [u8; 32],
    pub lock_time: u32,
    pub expiry_height: u32,
}

pub fn header_digest(version: u32, lock_time: u32, expiry_height: u32) -> [u8; 32] {
    assert((version == 5) | (version == 6), "Unsupported effect digest version");
    let group = if version == 6 {
        0xd884b698u32
    } else {
        0x26a7270au32
    };
    let words = [0x80000000u32 | version, group, 0x37a5165bu32, lock_time, expiry_height];
    let mut bytes = [0u8; 20];
    for i in 0..5 {
        for j in 0..4 {
            bytes[i * 4 + j] = (words[i] >> ((8 * j) as u32)) as u8;
        }
    }
    crate::hashes::hash::<20, 32>(bytes, "ZTxIdHeadersHash".as_bytes())
}
pub fn txid_personalization() -> [u8; 16] {
    let mut p = [0u8; 16];
    let text = "ZcashTxHash_".as_bytes();
    for i in 0..12 {
        p[i] = text[i];
    }
    let branch = 0x37a5165bu32;
    for i in 0..4 {
        p[12 + i] = (branch >> ((8 * i) as u32)) as u8;
    }
    p
}
pub fn ironwood_digest<let N: u32>(effects: V6Effects<N>) -> [u8; 32] {
    if N == 0 {
        crate::hashes::hash::<0, 32>([], "ZTxIdIronwd_H_v6".as_bytes())
    } else {
        assert(effects.flags < 8, "Reserved Ironwood flags");
        let mut compact = [0u8; 148 * N];
        for i in 0..N {
            for j in 0..148 {
                compact[148 * i + j] = effects.compact_actions[i][j];
            }
        }
        let c = crate::hashes::hash::<148 * N, 32>(compact, "ZTxIdIrnActCH_v6".as_bytes());
        let mut message = [0u8; 105];
        for i in 0..32 {
            message[i] = c[i];
            message[32 + i] = effects.memos_digest[i];
            message[64 + i] = effects.noncompact_digest[i];
        }
        message[96] = effects.flags;
        for i in 0..8 {
            message[97 + i] = effects.value_balance[i];
        }
        crate::hashes::hash::<105, 32>(message, "ZTxIdIronwd_H_v6".as_bytes())
    }
}
pub fn txid_v6<let N: u32>(effects: V6Effects<N>) -> [u8; 32] {
    let digests = [
        header_digest(6, effects.lock_time, effects.expiry_height),
        effects.transparent_digest,
        effects.sapling_digest,
        effects.orchard_digest,
        ironwood_digest(effects),
    ];
    let mut bytes = [0u8; 160];
    for i in 0..5 {
        for j in 0..32 {
            bytes[32 * i + j] = digests[i][j];
        }
    }
    crate::hashes::hash::<160, 32>(bytes, txid_personalization())
}
// The caller separately links expected_nf to its private note/key if desired.
// This proves nf occurs in the Ironwood component of the block whose SHA256d is
// expected_header_hash. The block's height, network and ancestry are not bound.
pub fn verify_nullifier_inclusion<let N: u32, let DEPTH: u32>(
    witness: crate::transactions::effects::Inclusion<N, DEPTH>,
    expected_nf: [u8; 32],
    expected_header_hash: [u8; 32],
) {
    let (action, _) = crate::transactions::effects::verify_action(witness, expected_header_hash);
    assert(action.nullifier == expected_nf, "Nullifier mismatch");
}

// Ironwood digest of a transaction with exactly action_count Actions, stored in
// a buffer of MAX_ACTIONS slots. Unused slots must be zero (hash_bounded checks
// the padding), so one transaction has one encoding. action_count == 0 is the
// empty bundle; its memo, noncompact, flags and balance fields are not hashed.
pub fn ironwood_digest_bounded<let MAX_ACTIONS: u32>(
    effects: V6Effects<MAX_ACTIONS>,
    action_count: u32,
) -> [u8; 32] {
    assert(action_count <= MAX_ACTIONS, "Action count exceeds capacity");
    let empty = crate::hashes::hash::<0, 32>([], "ZTxIdIronwd_H_v6".as_bytes());
    if action_count == 0 {
        empty
    } else {
        assert(effects.flags < 8, "Reserved Ironwood flags");
        let c = compact_digest_bounded(effects.compact_actions, action_count);
        let mut message = [0u8; 105];
        for i in 0..32 {
            message[i] = c[i];
            message[32 + i] = effects.memos_digest[i];
            message[64 + i] = effects.noncompact_digest[i];
        }
        message[96] = effects.flags;
        for i in 0..8 {
            message[97 + i] = effects.value_balance[i];
        }
        crate::hashes::hash::<105, 32>(message, "ZTxIdIronwd_H_v6".as_bytes())
    }
}
// V6 transaction ID of a transaction with exactly action_count Actions.
pub fn txid_v6_bounded<let MAX_ACTIONS: u32>(
    effects: V6Effects<MAX_ACTIONS>,
    action_count: u32,
) -> [u8; 32] {
    let digests = [
        header_digest(6, effects.lock_time, effects.expiry_height),
        effects.transparent_digest,
        effects.sapling_digest,
        effects.orchard_digest,
        ironwood_digest_bounded(effects, action_count),
    ];
    let mut bytes = [0u8; 160];
    for i in 0..5 {
        for j in 0..32 {
            bytes[32 * i + j] = digests[i][j];
        }
    }
    crate::hashes::hash::<160, 32>(bytes, txid_personalization())
}

// Bounded complete-transaction opening for scanning. Inactive action slots are
// zero and action_count is cryptographically bound by the compact hash length.
pub struct NullifierAbsenceEffects<let MAX_ACTIONS: u32> {
    pub effects: V6Effects<MAX_ACTIONS>,
    pub version: u32,
    pub action_count: u32,
}

pub fn compact_digest_bounded<let MAX_ACTIONS: u32>(
    actions: [[u8; 148]; MAX_ACTIONS],
    count: u32,
) -> [u8; 32] {
    assert(count <= MAX_ACTIONS, "Compact Action count exceeds digest capacity");
    let mut bytes = [0u8; 148 * MAX_ACTIONS];
    for i in 0..MAX_ACTIONS {
        for j in 0..148 {
            bytes[148 * i + j] = actions[i][j];
        }
    }
    crate::hashes::hash_bounded::<148 * MAX_ACTIONS, 32>(
        bytes,
        148 * count,
        "ZTxIdIrnActCH_v6".as_bytes(),
    )
}

pub fn txid_asserting_nullifier_absence<let A: u32>(
    row: NullifierAbsenceEffects<A>,
    queried_nf: [u8; 32],
) -> [u8; 32] {
    assert((row.version == 5) | (row.version == 6), "Scan supports only V5/V6 transactions");
    assert(row.action_count <= A, "Transaction Action count exceeds row capacity");
    if row.version == 5 {
        assert(row.action_count == 0, "V5 cannot contain Ironwood Actions");
    }
    let e = row.effects;
    for i in 0..A {
        if i < row.action_count {
            let mut nf = [0u8; 32];
            for j in 0..32 {
                nf[j] = e.compact_actions[i][j];
            }
            assert(nf != queried_nf, "Queried nullifier occurs in scanned transaction");
        } else {
            assert(e.compact_actions[i] == [0u8; 148], "Nonzero unused Action slot");
        }
    }
    let h = header_digest(row.version, e.lock_time, e.expiry_height);
    let base = [h, e.transparent_digest, e.sapling_digest, e.orchard_digest];
    let mut data = [0u8; 128];
    for i in 0..4 {
        for j in 0..32 {
            data[32 * i + j] = base[i][j];
        }
    }
    if row.version == 5 {
        crate::hashes::hash::<128, 32>(data, txid_personalization())
    } else {
        let component = if row.action_count == 0 {
            crate::hashes::hash::<0, 32>([], "ZTxIdIronwd_H_v6".as_bytes())
        } else {
            assert(e.flags < 8, "Reserved Ironwood flags");
            let c = compact_digest_bounded(e.compact_actions, row.action_count);
            let mut msg = [0u8; 105];
            for i in 0..32 {
                msg[i] = c[i];
                msg[32 + i] = e.memos_digest[i];
                msg[64 + i] = e.noncompact_digest[i];
            }
            msg[96] = e.flags;
            for i in 0..8 {
                msg[97 + i] = e.value_balance[i];
            }
            crate::hashes::hash::<105, 32>(msg, "ZTxIdIronwd_H_v6".as_bytes())
        };
        let mut all = [0u8; 160];
        for i in 0..128 {
            all[i] = data[i];
        }
        for i in 0..32 {
            all[128 + i] = component[i];
        }
        crate::hashes::hash::<160, 32>(all, txid_personalization())
    }
}
