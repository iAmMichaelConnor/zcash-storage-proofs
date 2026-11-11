use aztec::protocol::address::AztecAddress;
use ironwood::memo::FullActionCiphertext;
// Slots 68/69 reuse the Action-inclusion and note-opening layouts of
// crate::creation. N is the Action capacity of the transaction.
// Slot 103 (crate::MEMO_SLOT) = raw receiver43 || memo512 ||
// N*(ciphertext580 || cv32 || rk32 || out80); entries at and after the
// transaction's action count are all zero. `claim` selects the claim's slots
// (crate::claim_slot), so one address can hold several claims.
// All loaded fields are private witnesses; byte checks precede narrowing casts.
// Every value of one claim comes from one load of each capsule. Do not load
// slots 68, 69 or 103 again to get a field of the same claim: a second load is
// a new unconstrained witness that a PXE can answer with another note.
pub struct MemoCreated {
    // The decrypted 512-byte memo of the selected Action.
    pub memo: [u8; 512],
    // Transaction ID (internal byte order). Not unique per Action.
    pub txid: [u8; 32],
    // Output note commitment of the selected Action. Key a per-note
    // application nullifier on it, not on txid or the block.
    pub cmx: [u8; 32],
    // Note value in zatoshi.
    pub value: u64,
    // Raw Ironwood receiver (diversifier11 || pk_d32) that the note pays and
    // that the note encryption uses.
    pub raw_receiver: [u8; 43],
}
// Returning the values does not disclose them: the calling private circuit
// chooses which predicate or commitment to expose. The caller authenticates
// accepted_header_hash and takes the expected receiver, minimum value and memo
// predicate from its own state. The block's height, network and ancestry are
// not bound.
pub fn verify<let N: u32, let DEPTH: u32>(
    address: AztecAddress,
    claim: u32,
    accepted_header_hash: [u8; 32],
) -> MemoCreated {
    // Safety: range and every crypto relation are checked in constrained code.
    let raw = unsafe { load::<555 + 724 * N>(address, crate::claim_slot(crate::MEMO_SLOT, claim)) };
    let mut bytes = [0u8; 555 + 724 * N];
    for i in 0..bytes.len() {
        raw[i].assert_max_bit_size::<8>();
        bytes[i] = raw[i] as u8;
    }
    let mut receiver = [0u8; 43];
    let mut memo = [0u8; 512];
    for i in 0..43 {
        receiver[i] = bytes[i];
    }
    for i in 0..512 {
        memo[i] = bytes[43 + i];
    }
    let empty = FullActionCiphertext {
        encrypted_note: [0u8; 580],
        value_commitment: [0u8; 32],
        randomized_key: [0u8; 32],
        outgoing_ciphertext: [0u8; 80],
    };
    let mut full = [empty; N];
    for a in 0..N {
        let start = 555 + 724 * a;
        for i in 0..580 {
            full[a].encrypted_note[i] = bytes[start + i];
        }
        for i in 0..32 {
            full[a].value_commitment[i] = bytes[start + 580 + i];
            full[a].randomized_key[i] = bytes[start + 612 + i];
        }
        for i in 0..80 {
            full[a].outgoing_ciphertext[i] = bytes[start + 644 + i];
        }
    }
    let note = crate::creation::opening(address, claim);
    let (txid, cmx) = ironwood::memo::verify_memo_created_in_block(
        note,
        receiver,
        memo,
        crate::creation::inclusion::<N, DEPTH>(address, claim),
        full,
        accepted_header_hash,
    );
    MemoCreated { memo, txid, cmx, value: note.value, raw_receiver: receiver }
}
unconstrained fn load<let L: u32>(address: AztecAddress, slot: Field) -> [Field; L] {
    aztec::oracle::capsules::load(address, slot, AztecAddress::zero()).expect(
        f"Missing Ironwood memo capsule",
    )
}
