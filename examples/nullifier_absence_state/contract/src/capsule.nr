use aztec::protocol::address::AztecAddress;
unconstrained fn load(address: AztecAddress) -> [Field; 8910] {
    aztec::oracle::capsules::load(address, 67, AztecAddress::zero()).expect(
        f"Missing scan window capsule",
    )
}
pub fn blocks(address: AztecAddress) -> [ironwood::transactions::legacy::Block<4, 2, 256>; 2] {
    // Safety: every byte is range checked; callers constrain complete block scans.
    let raw = unsafe { load(address) };
    let mut data = [0u8; 8910];
    for i in 0..8910 {
        raw[i].assert_max_bit_size::<8>();
        data[i] = raw[i] as u8;
    }
    ironwood::transactions::encoding::mixed_blocks::<2, 4, 2, 256, 8910>(data)
}
