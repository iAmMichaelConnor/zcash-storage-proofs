// Pure checked transitions. A State value is NOT self-authenticating: consumers
// must obtain it from a verified recursive proof or this contract's private note.
// There is no sound global-absence entry accepting arbitrary caller State values.
// initialize binds the start to the pinned pre-activation block; advance trusts
// its prior (tip_hash, height, queried_nf) and must only receive a State that
// initialize or advance produced (IronwoodNullifierAbsenceState pops it from a note).
pub struct State {
    pub queried_nf: [u8; 32],
    pub tip_hash: [u8; 32],
    pub height: u32,
    pub is_testnet: bool,
    pub activation_height: u32,
}
pub fn activation(is_testnet: bool) -> u32 {
    crate::transactions::nullifier_absence::activation(is_testnet)
}
pub fn advance<let B: u32, let TX: u32, let A: u32, let RAW: u32>(
    prior: State,
    blocks: [crate::transactions::legacy::Block<TX, A, RAW>; B],
    count: u32,
    expected_tip_hash: [u8; 32],
    expected_tip_height: u32,
) -> State {
    assert(B > 0);
    assert(count > 0, "Scan window advances zero blocks");
    assert(count <= B, "Scan window count exceeds block capacity");
    assert(
        prior.activation_height == activation(prior.is_testnet),
        "Wrong scan initialization domain",
    );
    assert(prior.height >= prior.activation_height - 1, "Prior scan precedes initialization");
    crate::transactions::nullifier_absence::assert_supported_tip(
        expected_tip_height,
        prior.is_testnet,
    );
    assert(
        (prior.height as u64) + (count as u64) == expected_tip_height as u64,
        "Scan window height discontinuity",
    );
    let mut previous = prior.tip_hash;
    // Blocks i >= count are ignored; their bytes are unconstrained.
    for i in 0..B {
        if i < count {
            for j in 0..32 {
                assert(blocks[i].header[4 + j] == previous[j], "Broken scan window link");
            }
            previous = crate::transactions::legacy::complete_block(blocks[i], prior.queried_nf);
        }
    }
    assert(previous == expected_tip_hash, "Scan window tip mismatch");
    State {
        queried_nf: prior.queried_nf,
        tip_hash: previous,
        height: expected_tip_height,
        is_testnet: prior.is_testnet,
        activation_height: prior.activation_height,
    }
}
pub fn initialize<let B: u32, let TX: u32, let A: u32, let RAW: u32>(
    blocks: [crate::transactions::legacy::Block<TX, A, RAW>; B],
    count: u32,
    queried_nf: [u8; 32],
    expected_tip_hash: [u8; 32],
    expected_tip_height: u32,
    is_testnet: bool,
) -> State {
    assert(B > 0);
    let activation_height = activation(is_testnet);
    assert(count > 0, "Scan initialization covers zero blocks");
    crate::transactions::nullifier_absence::assert_activation_start(
        blocks[0].header,
        queried_nf,
        expected_tip_height,
        is_testnet,
    );
    advance(
        State {
            queried_nf,
            tip_hash: crate::transactions::nullifier_absence::pinned_prev(is_testnet),
            height: activation_height - 1,
            is_testnet,
            activation_height,
        },
        blocks,
        count,
        expected_tip_hash,
        expected_tip_height,
    )
}
