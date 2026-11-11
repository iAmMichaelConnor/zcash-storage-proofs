//! Public deterministic vectors from the pinned native Ironwood implementation:
//! notes, raw receivers, ephemeral keys and complete memo encryptions. The `cached`
//! binary authenticates and decrypts the retained transfer fixture, checks compact
//! decryption agrees and re-encrypts identically. No proof, spending operation,
//! network connection or wallet material. `scripts/generate_native_fixtures.py`
//! builds both offline (Rust 1.90.0; locked crates fetched beforehand) and compares
//! with fixtures/memo/native-vectors.json (cached vector first).
use ff::PrimeField;
use ironwood_memo_fixture::{point, vector};
use orchard::{
    bundle::BundleVersion,
    keys::{FullViewingKey, Scope, SpendingKey},
    note::{RandomSeed, Rho},
    value::NoteValue,
    Note,
};
use pasta_curves::{arithmetic::CurveExt, pallas};
use serde_json::{json, Value};
fn main() {
    let mut vectors = Vec::new();
    for (name, value, seedbyte) in [
        ("deterministic-seed-seven", 5000u64, 7u8),
        ("zero-value", 0, 8),
        ("maximum-u64", u64::MAX, 9),
    ] {
        let sk = SpendingKey::from_bytes([1; 32]).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let address = fvk.address_at(0u32, Scope::External);
        let rho = Rho::from_bytes(&pallas::Base::from(42).to_repr()).unwrap();
        let seed = RandomSeed::from_bytes([seedbyte; 32], &rho).unwrap();
        let note = Note::from_parts(
            address,
            NoteValue::from_raw(value),
            rho,
            seed,
            BundleVersion::ironwood_v3().note_version(),
        )
        .unwrap();
        let memo: [u8; 512] = std::array::from_fn(|i| (i as u8).wrapping_add(seedbyte));
        vectors.push(vector(name, note, memo));
    }
    let hash = pallas::Point::hash_to_curve("z.cash:Orchard-gd");
    let diversifiers: Vec<Value> = (0..16)
        .map(|i| {
            let d = [i as u8; 11];
            json!({"input":d.to_vec(),"point":point(hash(&d))})
        })
        .collect();
    println!("{}",serde_json::to_string_pretty(&json!({"format":"ironwood-memo-native-v1","profile":"Ironwood V3, transaction V6, NU6.3 pinned source","scope":"Public deterministic test material; no live-chain validity claim.","vectors":vectors,"diversifiers":diversifiers,"empty_hash":point(hash(&[]))})).unwrap());
}
