//! Tests of IronwoodPrivateContentsCapsules' logic in TXE test contexts: `verify_contents_capsules`
//! (the body of `verify`) runs in a private context at a chosen address, with the witnesses of the
//! note_value example's fixture and Sinsemilla hints in that address's capsules. The hints are
//! computed here from the note as a host computes them natively (`hints`), so the fixture holds
//! no hint data. The tests that compute the hints for the whole path take minutes and are in
//! ../slow_tests, which reuses `stage` and `verify`.
use aztec::{
    oracle::capsules, protocol::address::AztecAddress,
    test::helpers::test_environment::TestEnvironment,
};
use aztec_contents_capsules_contract::verify_contents_capsules;
use bignum::{BigNum, Pallas_Fq as Fq};
use ironwood::{
    notes::{commitment_x, encode_nonidentity, NoteOpening, psi},
    sinsemilla::{domain_q, field_bits, hash_to_point},
};
use note_value_test::fixture;

global ADDRESS: AztecAddress = AztecAddress { inner: 0x1234 };
global NOTE_HASH_HINT_SLOT: Field = 102;
global MERKLE_HINT_SLOT: Field = 70;

/// Honest hint records of the Sinsemilla hash of `message` in domain `domain`, and the hash's x
/// coordinate. Each record is (lambda1, xR, lambda2, xFinal, yFinal) of the step
/// acc' = (acc + S) + acc for one 10-bit chunk. The library keeps the generators S private, so
/// S(m) is recovered from its one-chunk hash of m from Q, which is (Q + S(m)) + Q.
unconstrained fn hints<let N: u32>(
    domain: u8,
    message: [bool; N],
) -> ([[[u128; 3]; 5]; (N + 9) / 10], Fq) {
    let q = domain_q(domain);
    // 2Q, to subtract from each one-chunk hash.
    let l = Fq::from(3) * q.x * q.x / (q.y + q.y);
    let q2x = l * l - q.x - q.x;
    let q2y = l * (q.x - q2x) - q.y;
    let (mut x, mut y) = (q.x, q.y);
    let mut records = [[[0; 3]; 5]; (N + 9) / 10];
    for i in 0..(N + 9) / 10 {
        let mut chunk = [false; 10];
        for b in 0..10 {
            if i * 10 + b < N {
                chunk[b] = message[i * 10 + b];
            }
        }
        let h = hash_to_point(q, chunk).point;
        let l = (h.y + q2y) / (h.x - q2x);
        let sx = l * l - h.x - q2x;
        let sy = l * (h.x - sx) - h.y;
        let l1 = (sy - y) / (sx - x);
        let rx = l1 * l1 - x - sx;
        let l2 = Fq::zero() - l1 - (y + y) / (rx - x);
        let fx = l2 * l2 - rx - x;
        let fy = l2 * (x - fx) - y;
        records[i] =
            [l1.get_limbs(), rx.get_limbs(), l2.get_limbs(), fx.get_limbs(), fy.get_limbs()];
        x = fx;
        y = fy;
    }
    (records, x)
}

/// `bytes` as little-endian bits.
fn bits<let N: u32>(bytes: [u8; N]) -> [bool; N * 8] {
    let mut out = [false; N * 8];
    for i in 0..N {
        let b = (bytes[i] as Field).to_le_bits::<8>();
        for j in 0..8 {
            out[8 * i + j] = b[j];
        }
    }
    out
}

/// The NoteCommit message of `note`: g_d, pk_d (encoded), value, rho, psi.
fn note_message(note: NoteOpening) -> [bool; 1086] {
    let gd = bits(encode_nonidentity(note.receiver.g_d));
    let pkd = bits(encode_nonidentity(note.receiver.pk_d));
    let value = (note.value as Field).to_le_bits::<64>();
    let rho = field_bits(note.rho);
    let psi = field_bits(psi(note.rseed, note.rho));
    let mut message = [false; 1086];
    for i in 0..256 {
        message[i] = gd[i];
        message[256 + i] = pkd[i];
    }
    for i in 0..64 {
        message[512 + i] = value[i];
    }
    for i in 0..255 {
        message[576 + i] = rho[i];
        message[831 + i] = psi[i];
    }
    message
}

/// Stores the fixture header and `note` in the claim-0 capsules of ADDRESS with the honest note
/// commitment hints and, for `levels` levels of the path, the honest Merkle hints. Returns the
/// environment.
pub unconstrained fn stage(note: [Field; 145], levels: u32) -> TestEnvironment {
    let env = TestEnvironment::new();
    env.utility_context_at(ADDRESS, |_| {
        capsules::store(ADDRESS, 60, fixture::HEADER, AztecAddress::zero());
        capsules::store(ADDRESS, 61, note, AztecAddress::zero());
        let (opening, position, siblings) = ironwood_aztec::note_opening(ADDRESS, 0);
        let (records, _) = hints(1, note_message(opening));
        capsules::store(ADDRESS, NOTE_HASH_HINT_SLOT, records, AztecAddress::zero());
        let mut node = commitment_x(opening);
        for level in 0..levels {
            let right = ((position >> level) & 1) == 1;
            let (left, right) = if right {
                (siblings[level], node)
            } else {
                (node, siblings[level])
            };
            let mut message = [false; 520];
            let level_bits = (level as Field).to_le_bits::<5>();
            let left = field_bits(left);
            let right = field_bits(right);
            for i in 0..5 {
                message[i] = level_bits[i];
            }
            for i in 0..255 {
                message[10 + i] = left[i];
                message[265 + i] = right[i];
            }
            let (records, x) = hints(0, message);
            capsules::store(
                ADDRESS,
                MERKLE_HINT_SLOT + level as Field,
                records,
                AztecAddress::zero(),
            );
            node = x;
        }
    });
    env
}

/// Runs `verify_contents_capsules` at ADDRESS for the fixture checkpoint.
pub unconstrained fn verify(
    env: TestEnvironment,
) -> ([u8; 32], u64, [[[u128; 3]; 2]; 2], [u128; 3], u32) {
    env.private_context_at(ADDRESS, |_| {
        verify_contents_capsules(ADDRESS, fixture::HASH, fixture::HEIGHT, false)
    })
}

#[test(should_fail_with = "Missing Sinsemilla hint capsule")]
unconstrained fn missing_merkle_hints_rejected() {
    let _ = verify(stage(fixture::NOTE, 0));
}
