use aztec::{macros::notes::note, protocol::traits::Packable};
#[derive(Eq, Packable)]
#[note]
pub struct NullifierAbsenceNote {
    pub nf_lo: u128,
    pub nf_hi: u128,
    pub hash_lo: u128,
    pub hash_hi: u128,
    pub height: u32,
    pub is_testnet: bool,
    pub activation_height: u32,
}
pub fn halves(bytes: [u8; 32]) -> [u128; 2] {
    let mut words = [0u128; 2];
    for k in 0..2 {
        for i in 0..16 {
            words[k] = words[k] + ((bytes[k * 16 + i] as u128) << ((8 * i) as u128));
        }
    }
    words
}
fn bytes(words: [u128; 2]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for k in 0..2 {
        for i in 0..16 {
            out[k * 16 + i] = (words[k] >> ((8 * i) as u128)) as u8;
        }
    }
    out
}
impl NullifierAbsenceNote {
    pub fn from_state(state: ironwood::transactions::nullifier_absence_state::State) -> Self {
        let nf = halves(state.queried_nf);
        let hash = halves(state.tip_hash);
        Self {
            nf_lo: nf[0],
            nf_hi: nf[1],
            hash_lo: hash[0],
            hash_hi: hash[1],
            height: state.height,
            is_testnet: state.is_testnet,
            activation_height: state.activation_height,
        }
    }
    pub fn state(self) -> ironwood::transactions::nullifier_absence_state::State {
        ironwood::transactions::nullifier_absence_state::State {
            queried_nf: bytes([self.nf_lo, self.nf_hi]),
            tip_hash: bytes([self.hash_lo, self.hash_hi]),
            height: self.height,
            is_testnet: self.is_testnet,
            activation_height: self.activation_height,
        }
    }
}
