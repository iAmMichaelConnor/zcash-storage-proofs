//! The application policy, the note check of `accept` and the counter update of `record_acceptance`.
use aztec::{
    context::PublicContext,
    protocol::{address::AztecAddress, traits::{Deserialize, Packable, Serialize}},
    state_vars::PublicMutable,
};

#[derive(Deserialize, Packable, Serialize)]
pub struct Policy {
    pub checkpoint_hash: [u8; 32],
    pub checkpoint_height: u32,
    pub is_testnet: bool,
    pub minimum_value: u64,
}

/// Verifies the note in the capsules of `address` under the policy's checkpoint and
/// requires at least the policy's minimum value.
pub fn check_note(address: AztecAddress, policy: Policy) {
    let (_, value, _, _, _) = ironwood_aztec::verify_contents(
        address,
        0,
        policy.checkpoint_hash,
        policy.checkpoint_height,
        policy.is_testnet,
    );
    assert(value >= policy.minimum_value, "Note value is below application minimum");
}

/// The public effect of an accepted note: one more on the counter.
pub fn count_acceptance(accepted: PublicMutable<Field, PublicContext>) {
    accepted.write(accepted.read() + 1);
}
