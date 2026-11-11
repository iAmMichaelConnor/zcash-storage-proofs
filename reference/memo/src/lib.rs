//! Shared deterministic native-vector serialization.
//! No proof, spending operation, network connection or wallet material.
use ff::{FromUniformBytes, PrimeField};
use group::{Curve, GroupEncoding};
use orchard::{
    note::ExtractedNoteCommitment,
    note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
    Note,
};
use pasta_curves::{arithmetic::CurveAffine, pallas};
use serde_json::{json, Value};
use zcash_note_encryption::Domain;
pub fn limbs(bytes: [u8; 32]) -> Vec<String> {
    (0..3)
        .map(|i| {
            let mut v = 0u128;
            for j in 0..15 {
                if i * 15 + j < 32 {
                    v |= (bytes[i * 15 + j] as u128) << (8 * j);
                }
            }
            v.to_string()
        })
        .collect()
}
pub fn point(p: pallas::Point) -> Value {
    let a = p.to_affine();
    let c = a.coordinates().unwrap();
    json!({"x":limbs(c.x().to_repr()),"y":limbs(c.y().to_repr()),"is_infinity":false})
}
pub fn vector(name: &str, note: Note, memo: [u8; 512]) -> Value {
    let raw = note.recipient().to_raw_address_bytes();
    let rho = note.rho();
    let seed = note.rseed();
    let enc = IronwoodNoteEncryption::new(None, note, memo);
    let epk = IronwoodDomain::epk_bytes(enc.epk());
    let secret = IronwoodDomain::ka_agree_enc(enc.esk(), &IronwoodDomain::get_pk_d(&note));
    let key = IronwoodDomain::kdf(secret, &epk);
    let mut input = seed.as_bytes().to_vec();
    input.push(4);
    input.extend_from_slice(&rho.to_bytes());
    let h = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"Zcash_ExpandSeed")
        .hash(&input);
    let esk = pallas::Scalar::from_uniform_bytes(h.as_array());
    let pkd = pallas::Point::from_bytes(&raw[11..].try_into().unwrap()).unwrap();
    let gd = pallas::Point::from_bytes(&note.recipient().g_d().to_bytes()).unwrap();
    let cmx = ExtractedNoteCommitment::from(note.commitment());
    json!({"name":name,"note":{"receiver":{"g_d":point(gd),"pk_d":point(pkd)},"value":note.value().inner().to_string(),"rho":limbs(rho.to_bytes()),"rseed":seed.as_bytes().to_vec()},"raw_receiver":raw.to_vec(),"memo":memo.to_vec(),"ephemeral_key":epk.0.to_vec(),"ciphertext":enc.encrypt_note_plaintext().0.to_vec(),"plaintext":IronwoodDomain::note_plaintext_bytes(&note,&memo).0.to_vec(),"key":key.as_bytes().to_vec(),"esk":limbs(esk.to_repr()),"cmx":cmx.to_bytes().to_vec()})
}
