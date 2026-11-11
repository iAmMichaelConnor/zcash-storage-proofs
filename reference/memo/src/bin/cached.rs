//! Full authenticated decryption of the retained public cached transfer.
use orchard::{
    keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey},
    note::{ExtractedNoteCommitment, Nullifier},
    note_encryption::{
        CompactAction, CompactNoteCiphertextBytes, IronwoodDomain, NoteBytesData,
        NoteCiphertextBytes,
    },
};
use serde_json::Value;
use zcash_note_encryption::{EphemeralKeyBytes, ShieldedOutput};
struct Output {
    cm: ExtractedNoteCommitment,
    epk: [u8; 32],
    enc: NoteCiphertextBytes,
}
impl ShieldedOutput<IronwoodDomain> for Output {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.epk)
    }
    fn cmstar(&self) -> &ExtractedNoteCommitment {
        &self.cm
    }
    fn enc_ciphertext(&self) -> Option<&NoteCiphertextBytes> {
        Some(&self.enc)
    }
    fn enc_ciphertext_compact(&self) -> CompactNoteCiphertextBytes {
        NoteBytesData(self.enc.0[..52].try_into().unwrap())
    }
}
fn bytes<const N: usize>(v: &Value) -> [u8; N] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}
fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("retained public bundle JSON");
    let b: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let out = Output {
        cm: ExtractedNoteCommitment::from_bytes(&bytes(&b["cmx"])).unwrap(),
        epk: bytes(&b["epk"]),
        enc: NoteBytesData(bytes(&b["enc_ciphertext"])),
    };
    let compact = CompactAction::from_parts(
        Nullifier::from_bytes(&bytes(&b["nf"])).unwrap(),
        out.cm,
        EphemeralKeyBytes(out.epk),
        out.enc.0[..52].try_into().unwrap(),
    );
    let fvk = FullViewingKey::from(&SpendingKey::from_bytes([2; 32]).unwrap());
    let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
    let domain = IronwoodDomain::for_compact_action(&compact);
    let (note, address, memo) = zcash_note_encryption::try_note_decryption(&domain, &ivk, &out)
        .expect("cached FULL ciphertext and tag decryption");
    let (compact_note, compact_address) =
        zcash_note_encryption::try_compact_note_decryption(&domain, &ivk, &compact).unwrap();
    assert_eq!(note, compact_note);
    assert_eq!(address, compact_address);
    let mut v = ironwood_memo_fixture::vector("cached-native-verified-transfer", note, memo);
    assert_eq!(v["ciphertext"], serde_json::json!(out.enc.0.to_vec()));
    assert_eq!(v["ephemeral_key"], serde_json::json!(out.epk.to_vec()));
    v["full_action"] = serde_json::json!({"encrypted_note":out.enc.0.to_vec(),"value_commitment":bytes::<32>(&b["cv_net"]).to_vec(),"randomized_key":bytes::<32>(&b["rk"]).to_vec(),"outgoing_ciphertext":bytes::<80>(&b["out_ciphertext"]).to_vec()});
    println!("{}", serde_json::to_string_pretty(&v).unwrap());
}
