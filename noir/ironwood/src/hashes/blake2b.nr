global IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];
global SIGMA: [[u32; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];
unconstrained fn rotate_hint<let N: u32>(x: u64) -> (u64, Field) {
    let y = (x >> (N as u64)) | (x << ((64 - N) as u64));
    let carry = if N <= 32 {
        x & (((1 as u64) << (N as u64)) - 1)
    } else {
        x >> (N as u64)
    };
    (y, carry as Field)
}
fn rotr<let N: u32>(x: u64) -> u64 {
    // Safety: exact bounded integer relation fixes the rotation, including zero and all-ones endpoints.
    let (y, carry) = unsafe { rotate_hint::<N>(x) };
    // Keep this check. Where y feeds a 64-bit XOR the compiler drops it and the
    // backend's XOR operand check bounds y instead (docs/COMPOSITION.md#backend-and-compiler-premises).
    (y as Field).assert_max_bit_size::<64>();
    if N <= 32 {
        carry.assert_max_bit_size::<N>();
        assert(
            (x as Field)
                == (y as Field) * ((1 as u64) << (N as u64)) as Field - carry * 18446744073709551615
                ,
        );
    } else {
        carry.assert_max_bit_size::<64 - N>();
        assert(
            (y as Field)
                == (x as Field) * ((1 as u64) << ((64 - N) as u64)) as Field
                    - carry * 18446744073709551615,
        );
    }
    y
}
unconstrained fn add_hint(a: u64, b: u64, c: u64) -> (u64, Field) {
    let sum = (a as u128) + (b as u128) + (c as u128);
    (sum as u64, (sum >> 64) as Field)
}
fn add<let CARRY_BITS: u32>(a: u64, b: u64, c: u64) -> u64 {
    // Safety: the output and carry are bounded and their reconstruction equals the exact sum.
    let (sum, carry) = unsafe { add_hint(a, b, c) };
    // Keep this check. Where sum feeds a 64-bit XOR the compiler drops it and the
    // backend's XOR operand check bounds sum instead (docs/COMPOSITION.md#backend-and-compiler-premises).
    (sum as Field).assert_max_bit_size::<64>();
    carry.assert_max_bit_size::<CARRY_BITS>();
    assert(
        (a as Field) + (b as Field) + (c as Field) == (sum as Field) + carry * 18446744073709551616,
    );
    sum
}
fn g(v: &mut [u64; 16], a: u32, b: u32, c: u32, d: u32, x: u64, y: u64) {
    v[a] = add::<2>(v[a], v[b], x);
    v[d] = rotr::<32>(v[d] ^ v[a]);
    v[c] = add::<1>(v[c], v[d], 0);
    v[b] = rotr::<24>(v[b] ^ v[c]);
    v[a] = add::<2>(v[a], v[b], y);
    v[d] = rotr::<16>(v[d] ^ v[a]);
    v[c] = add::<1>(v[c], v[d], 0);
    v[b] = rotr::<63>(v[b] ^ v[c]);
}
unconstrained fn pack_hint(bytes: [u8; 8]) -> u64 {
    let mut x: u64 = 0;
    for j in 0..8 {
        x = x | ((bytes[j] as u64) << ((8 * j) as u64));
    }
    x
}
fn pack(bytes: [u8; 8]) -> u64 {
    // Safety: byte ranges make the reconstructed integer less than 2^64.
    let word = unsafe { pack_hint(bytes) };
    (word as Field).assert_max_bit_size::<64>();
    let mut value: Field = 0;
    for j in 0..8 {
        value = value + (bytes[j] as Field) * ((1 as u64) << ((8 * j) as u64)) as Field;
    }
    assert((word as Field) == value);
    word
}
#[no_predicates]
fn compress(h: [u64; 8], block: [u8; 128], count: u64, last: bool) -> [u64; 8] {
    let mut m = [0 as u64; 16];
    for i in 0..16 {
        let mut bytes = [0; 8];
        for j in 0..8 {
            bytes[j] = block[8 * i + j];
        }
        m[i] = pack(bytes);
    }
    let mut v = [0 as u64; 16];
    for i in 0..8 {
        v[i] = h[i];
        v[i + 8] = IV[i];
    }
    v[12] = v[12] ^ count;
    if last {
        v[14] = !v[14];
    }
    for r in 0..12 {
        let s = SIGMA[r];
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    let mut out = [0 as u64; 8];
    for i in 0..8 {
        out[i] = h[i] ^ v[i] ^ v[i + 8];
    }
    out
}
pub struct Blake2b {
    h: [u64; 8],
    block: [u8; 128],
    used: u32,
    count: u64,
}
impl Blake2b {
    // Preserve the exact Halo2 transcript constructor.
    pub fn new() -> Self {
        Self::new_personalized::<64>([
            72, 97, 108, 111, 50, 45, 84, 114, 97, 110, 115, 99, 114, 105, 112, 116,
        ])
    }
    pub fn new_personalized<let OUT: u32>(personalization: [u8; 16]) -> Self {
        assert(OUT > 0);
        assert(OUT <= 64);
        let mut h = IV;
        h[0] = h[0] ^ (0x01010000 | (OUT as u64));
        let mut low = [0u8; 8];
        let mut high = [0u8; 8];
        for i in 0..8 {
            low[i] = personalization[i];
            high[i] = personalization[i + 8];
        }
        h[6] = h[6] ^ pack(low);
        h[7] = h[7] ^ pack(high);
        Self { h, block: [0; 128], used: 0, count: 0 }
    }
    pub fn update<let N: u32>(self: &mut Self, bytes: [u8; N]) {
        for i in 0..N {
            if self.used == 128 {
                self.count += 128;
                self.h = compress(self.h, self.block, self.count, false);
                self.block = [0; 128];
                self.used = 0;
            }
            self.block[self.used] = bytes[i];
            self.used += 1;
        }
    }
    pub fn finalize(self: Self) -> [u8; 64] {
        let h = compress(self.h, self.block, self.count + self.used as u64, true);
        let mut out = [0 as u8; 64];
        for i in 0..8 {
            for j in 0..8 {
                out[8 * i + j] = (h[i] >> ((8 * j) as u64)) as u8;
            }
        }
        out
    }
    // Positions are checked against maintained state, but addresses and compression
    // boundaries are constants before SSA alias and loop passes.
    pub fn update_at<let P: u32, let N: u32>(self: &mut Self, bytes: [u8; N]) {
        assert(self.count + (self.used as u64) == P as u64, "Incorrect transcript position");
        for i in 0..N {
            if (P + i > 0) & ((P + i) % 128 == 0) {
                self.h = compress(self.h, self.block, (P + i) as u64, false);
                self.block = [0; 128];
            }
            self.block[(P + i) % 128] = bytes[i];
        }
        self.count = if P + N > 0 {
            ((P + N - 1) / 128 * 128) as u64
        } else {
            0
        };
        self.used = P + N - (self.count as u32);
    }
    pub fn finalize_at<let P: u32>(self: Self) -> [u8; 64] {
        assert(self.count + (self.used as u64) == P as u64, "Incorrect transcript position");
        let h = compress(self.h, self.block, P as u64, true);
        let mut out = [0 as u8; 64];
        for i in 0..8 {
            for j in 0..8 {
                out[8 * i + j] = (h[i] >> ((8 * j) as u64)) as u8;
            }
        }
        out
    }
    // Variable length only within the already buffered final block. Earlier full
    // blocks remain fixed and authenticated. This is not arbitrary-length streaming.
    pub fn finalize_last_block_at<let P: u32>(self: Self, length: u32) -> [u8; 64] {
        assert(P > 0);
        let prefix = (P - 1) / 128 * 128;
        assert(self.count + (self.used as u64) == P as u64, "Incorrect transcript position");
        assert(length > prefix, "Length changes final block index");
        assert(length <= P, "Length exceeds buffer");
        for i in 0..128 {
            if i >= length - prefix {
                assert(self.block[i] == 0, "Nonzero hash padding");
            }
        }
        let h = compress(self.h, self.block, length as u64, true);
        let mut out = [0u8; 64];
        for i in 0..8 {
            for j in 0..8 {
                out[8 * i + j] = (h[i] >> ((8 * j) as u64)) as u8;
            }
        }
        out
    }
}

// Bounded variable-length message, static compression schedule. One zero-length
// final block is processed for the empty message. All unused bytes are zero.
pub fn hash_bounded<let N: u32, let OUT: u32>(
    message: [u8; N],
    length: u32,
    personalization: [u8; 16],
) -> [u8; OUT] {
    assert(length <= N, "Hash length exceeds capacity");
    for i in 0..N {
        if i >= length {
            assert(message[i] == 0, "Nonzero bounded hash padding");
        }
    }
    let state = Blake2b::new_personalized::<OUT>(personalization);
    let mut h = state.h;
    for block_index in 0..(N + 127) / 128 + (N == 0) as u32 {
        let mut block = [0u8; 128];
        for i in 0..128 {
            if block_index * 128 + i < N {
                block[i] = message[block_index * 128 + i];
            }
        }
        let active = (block_index == 0) | (block_index * 128 < length);
        let last = length <= (block_index + 1) * 128;
        let counter = if last {
            length
        } else {
            (block_index + 1) * 128
        };
        let candidate = compress(h, block, counter as u64, last);
        h = if active { candidate } else { h };
    }
    let mut full = [0u8; 64];
    for i in 0..8 {
        for j in 0..8 {
            full[8 * i + j] = (h[i] >> ((8 * j) as u64)) as u8;
        }
    }
    let mut out = [0u8; OUT];
    for i in 0..OUT {
        out[i] = full[i];
    }
    out
}
