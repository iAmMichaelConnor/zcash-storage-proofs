pub unconstrained fn load(address: aztec::protocol::address::AztecAddress) -> [Field; 6830] {
    aztec::oracle::capsules::load(address, 63, aztec::protocol::address::AztecAddress::zero())
        .expect(f"Missing complete Ironwood scan capsule")
}
