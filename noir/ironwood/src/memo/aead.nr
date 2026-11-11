// RFC 8439 sections 2.3, 2.5, 2.8. Ironwood fixes the 96-bit nonce to zero
// and the associated data to empty (zcash_note_encryption 0.5.1).
// https://www.rfc-editor.org/rfc/rfc8439.html
fn add32(a: u32, b: u32) -> u32 {
    ((a as u64) + (b as u64)) as u32
}
fn rot<let N: u32>(x: u32) -> u32 {
    (x << N) | (x >> (32 - N))
}
fn quarter(s: &mut [u32; 16], a: u32, b: u32, c: u32, d: u32) {
    s[a] = add32(s[a], s[b]);
    s[d] = rot::<16>(s[d] ^ s[a]);
    s[c] = add32(s[c], s[d]);
    s[b] = rot::<12>(s[b] ^ s[c]);
    s[a] = add32(s[a], s[b]);
    s[d] = rot::<8>(s[d] ^ s[a]);
    s[c] = add32(s[c], s[d]);
    s[b] = rot::<7>(s[b] ^ s[c]);
}
pub fn block(key: [u8; 32], counter: u32) -> [u8; 64] {
    let mut s = [0u32; 16];
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;
    for i in 0..8 {
        for j in 0..4 {
            s[4 + i] = s[4 + i] | ((key[4 * i + j] as u32) << (8 * j));
        }
    }
    s[12] = counter;
    let initial = s;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        let w = add32(s[i], initial[i]);
        for j in 0..4 {
            out[4 * i + j] = (w >> (8 * j)) as u8;
        }
    }
    out
}
fn digits(bytes: [u8; 16]) -> [u64; 5] {
    let mut v = [0u64; 5];
    for i in 0..128 {
        v[i / 26] = v[i / 26] | ((((bytes[i / 8] >> (i % 8) as u8) & 1) as u64) << (i % 26) as u64);
    }
    v
}
// Full 16-byte Poly1305 blocks. The AEAD caller pads ciphertext explicitly,
// then appends the two 64-bit lengths. Every block gets the 2^128 high bit.
// Base B=2^26: wrapped convolution uses B^5=5 mod (2^130-5).
// Each product sum is < 50*B^2 <2^58, safely below u64. After carrying,
// represented h <2^130+5*2^32 <2*(2^130-5); one subtraction is sufficient.
// The 131-bit decomposition and canonical 130-bit checks prevent Field aliases.
pub fn poly1305<let BLOCKS: u32>(message: [[u8; 16]; BLOCKS], key: [u8; 32]) -> [u8; 16] {
    let mut rbytes = [0u8; 16];
    for i in 0..16 {
        rbytes[i] = key[i];
    }
    for i in 0..4 {
        rbytes[4 * i + 3] = rbytes[4 * i + 3] & 15;
    }
    for i in 1..4 {
        rbytes[4 * i] = rbytes[4 * i] & 252;
    }
    let r = digits(rbytes);
    let mut h = [0u64; 5];
    let modulus: Field = 1361129467683753853853498429727072845819;
    for n in 0..BLOCKS {
        let m = digits(message[n]);
        for i in 0..5 {
            h[i] = h[i] + m[i];
        }
        h[4] = h[4] + (1u64 << 24);
        let mut d = [0u64; 5];
        for i in 0..5 {
            for j in 0..5 {
                let k = (i + j) % 5;
                let factor = if i + j >= 5 { 5u64 } else { 1u64 };
                d[k] = d[k] + h[i] * r[j] * factor;
            }
        }
        for i in 0..4 {
            d[i + 1] = d[i + 1] + (d[i] >> 26);
            d[i] = d[i] & 67108863;
        }
        let carry = d[4] >> 26;
        d[4] = d[4] & 67108863;
        let mut packed: Field = (d[0] as Field) + 5 * (carry as Field);
        let mut weight: Field = 67108864;
        for i in 1..5 {
            packed = packed + (d[i] as Field) * weight;
            weight = weight * 67108864;
        }
        let bits = packed.to_le_bits::<131>();
        let mut high_ones = true;
        for i in 3..130 {
            high_ones = high_ones & bits[i];
        }
        let low = (bits[0] as u8) + 2 * (bits[1] as u8) + 4 * (bits[2] as u8);
        let subtract = bits[130] | (high_ones & (low >= 3));
        let canonical = packed - (subtract as Field) * modulus;
        canonical.assert_max_bit_size::<130>();
        (canonical + 5).assert_max_bit_size::<130>();
        let reduced = canonical.to_le_bits::<130>();
        h = [0u64; 5];
        for i in 0..130 {
            h[i / 26] = h[i / 26] | ((reduced[i] as u64) << (i % 26) as u64);
        }
    }
    let mut out = [0u8; 16];
    let mut carry = 0u16;
    for i in 0..16 {
        let mut byte = 0u16;
        for j in 0..8 {
            let bit = 8 * i + j;
            byte = byte | ((((h[bit / 26] >> (bit % 26) as u64) & 1) as u16) << (j as u16));
        }
        let sum = byte + (key[16 + i] as u16) + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
    }
    out
}
// Encrypt and authenticate the entire 564-byte Ironwood plaintext. The final
// 16 bytes are the Poly1305 tag, not additional encrypted plaintext.
pub fn encrypt(key: [u8; 32], plaintext: [u8; 564]) -> [u8; 580] {
    let mut ciphertext = [0u8; 580];
    for b in 0..9 {
        let stream = block(key, b + 1);
        for i in 0..64 {
            if b * 64 + i < 564 {
                ciphertext[b * 64 + i] = plaintext[b * 64 + i] ^ stream[i];
            }
        }
    }
    let mut mac = [[0u8; 16]; 37];
    for i in 0..564 {
        mac[i / 16][i % 16] = ciphertext[i];
    }
    // Empty associated data length = 0; ciphertext length = 564, little endian.
    mac[36][8] = 52;
    mac[36][9] = 2;
    let stream0 = block(key, 0);
    let mut polykey = [0u8; 32];
    for i in 0..32 {
        polykey[i] = stream0[i];
    }
    let tag = poly1305(mac, polykey);
    for i in 0..16 {
        ciphertext[564 + i] = tag[i];
    }
    ciphertext
}
