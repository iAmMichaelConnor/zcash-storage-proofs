//! Deterministic public test-note openings only; never generates proofs or keys.
use ff::{Field,PrimeField};
use group::{Curve,GroupEncoding};
use pasta_curves::{pallas,arithmetic::CurveAffine};
use orchard::{Note,note::{RandomSeed,Rho,ExtractedNoteCommitment},keys::{SpendingKey,FullViewingKey,Scope,SpendAuthorizingKey},bundle::BundleVersion,value::NoteValue,tree::{MerklePath,MerkleHashOrchard}};
use incrementalmerkletree::Hashable;
use serde_json::{json,Value};
fn limbs(bytes:[u8;32])->Vec<String>{
 (0..3).map(|i|{let mut v=0u128;for j in 0..15 {if i*15+j<32{v|=(bytes[i*15+j]as u128)<<(8*j);}}v.to_string()}).collect()
}
fn point(p:pallas::Point)->Value{
 let a=p.to_affine();let c=a.coordinates().unwrap();json!({"x":limbs(c.x().to_repr()),"y":limbs(c.y().to_repr()),"is_infinity":false})
}
fn main(){
 let mut vectors=Vec::new();
 let scope=if std::env::args().any(|a|a=="--internal"){Scope::Internal}else{Scope::External};
 for (label,value,seedbyte) in [("cached-transfer-input",5000u64,7u8),("zero-value",0,8),("maximum-u64",u64::MAX,9)]{
  let sk=SpendingKey::from_bytes([1;32]).unwrap();let fvk=FullViewingKey::from(&sk);let address=fvk.address_at(0u32,scope);
  let rho=Rho::from_bytes(&pallas::Base::from(42).to_repr()).unwrap();let seed=RandomSeed::from_bytes([seedbyte;32],&rho).unwrap();
  let note=Note::from_parts(address,NoteValue::from_raw(value),rho,seed,BundleVersion::ironwood_v3().note_version()).unwrap();
  let gd=address.g_d();let pkd_bytes: [u8;32]=address.to_raw_address_bytes()[11..].try_into().unwrap();
  let gd_point=pallas::Point::from_bytes(&gd.to_bytes()).unwrap();let pkd_point=pallas::Point::from_bytes(&pkd_bytes).unwrap();
  let psi=seed.psi(&rho);let rcm=seed.rcm_v3(&rho,&gd,&orchard::spec::NonIdentityPallasPoint::from_bytes(&pkd_bytes).unwrap(),value,&psi).inner();
  let cm=note.commitment();let cmx=ExtractedNoteCommitment::from(cm.clone());
  let path=MerklePath::from_parts(0,std::array::from_fn(|i|MerkleHashOrchard::empty_root((i as u8).into())));
  let fvk_bytes=fvk.to_bytes();let ask=SpendAuthorizingKey::from(&sk).randomize(&pallas::Scalar::ZERO).to_bytes();
  vectors.push(json!({"name":label,"note":{"receiver":{"g_d":point(gd_point),"pk_d":point(pkd_point)},"value":value.to_string(),"rho":limbs(rho.to_bytes()),"rseed":vec![seedbyte;32]},"expected_nf":limbs(note.nullifier(&fvk).to_bytes()),"ak":point(pallas::Point::from_bytes(&fvk_bytes[..32].try_into().unwrap()).unwrap()),"expected_cmx":limbs(cmx.to_bytes()),"expected_cm":point(cm.inner()),"expected_psi":limbs(psi.to_repr()),"expected_rcm":limbs(rcm.to_repr()),"position":0,"siblings":path.auth_path().map(|x|limbs(x.to_bytes())),"expected_root":limbs(path.root(cmx).to_bytes()),"ownership":{"ask":limbs(ask),"nk":limbs(fvk_bytes[32..64].try_into().unwrap()),"rivk":limbs(fvk.rivk(scope).inner().to_repr())},"raw_address_hex":hex::encode(address.to_raw_address_bytes()),"cmx_hex":hex::encode(cmx.to_bytes()),"root_hex":hex::encode(path.root(cmx).to_bytes())}));
 }
 println!("{}",serde_json::to_string_pretty(&json!({"format":"ironwood-note-openings-v1","scope":"Deterministic public test material. Synthetic single-leaf roots; no chain inclusion or funds claim. No proofs/keys generated.","vectors":vectors})).unwrap());
}
