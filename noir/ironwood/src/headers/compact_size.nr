// Canonical Bitcoin/Zcash CompactSize, not LEB128. Caller enforces exact end.
pub fn read<let N: u32>(bytes: [u8; N], offset: u32) -> (u64, u32) {
    assert(offset < N, "CompactSize offset outside input");
    let first = bytes[offset];
    let size: u32 = if first < 253 {
        1
    } else if first == 253 {
        3
    } else if first == 254 {
        5
    } else {
        9
    };
    assert(size <= N - offset, "Truncated CompactSize");
    let mut value: u64 = if first < 253 { first as u64 } else { 0 };
    for i in 0..8 {
        if i + 1 < size {
            value = value + ((bytes[offset + i + 1] as u64) << ((8 * i) as u64));
        }
    }
    if first == 253 {
        assert(value >= 253, "Noncanonical CompactSize u16");
    }
    if first == 254 {
        assert(value >= 65536, "Noncanonical CompactSize u32");
    }
    if first == 255 {
        assert(value >= 4294967296, "Noncanonical CompactSize u64");
    }
    (value, offset + size)
}
