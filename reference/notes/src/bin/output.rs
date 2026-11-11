//! Decode the cached public test transfer; never create a proof or spend key.
use ff::PrimeField;
use group::{Curve,GroupEncoding};
use pasta_curves::{pallas,arithmetic::CurveAffine};
use orchard::{keys::{SpendingKey,FullViewingKey,Scope,PreparedIncomingViewingKey},note::{Nullifier,ExtractedNoteCommitment},note_encryption::{CompactAction,IronwoodDomain}};
use serde_json::{json,Value};
fn limbs(bytes:[u8;32])->Vec<String>{(0..3).map(|i|{let mut n=0u128;for j in 0..15{if i*15+j<32{n|=(bytes[i*15+j]as u128)<<(8*j);}}n.to_string()}).collect()}
fn point(p:pallas::Point)->Value{let a=p.to_affine();let c=a.coordinates().unwrap();json!({"x":limbs(c.x().to_repr()),"y":limbs(c.y().to_repr()),"is_infinity":false})}
fn bytes<const N:usize>(v:&Value)->[u8;N]{hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()}
fn main(){
 let path=std::env::args().nth(1).expect("cached bundle JSON path");let b:Value=serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
 let enc=hex::decode(b["enc_ciphertext"].as_str().unwrap()).unwrap();
 let action=CompactAction::from_parts(Nullifier::from_bytes(&bytes(&b["nf"])).unwrap(),ExtractedNoteCommitment::from_bytes(&bytes(&b["cmx"])).unwrap(),zcash_note_encryption::EphemeralKeyBytes(bytes(&b["epk"])),enc[..52].try_into().unwrap());
 let fvk=FullViewingKey::from(&SpendingKey::from_bytes([2;32]).unwrap());
 let ivk=PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
 let (note,address)=zcash_note_encryption::try_compact_note_decryption(&IronwoodDomain::for_compact_action(&action),&ivk,&action).expect("cached recipient decryption");
 let cmx=ExtractedNoteCommitment::from(note.commitment());assert_eq!(cmx,action.cmx());assert_eq!(note.rho(),action.rho());
 let raw=address.to_raw_address_bytes();let gd=pallas::Point::from_bytes(&address.g_d().to_bytes()).unwrap();let pkd=pallas::Point::from_bytes(&raw[11..].try_into().unwrap()).unwrap();
 println!("{}",serde_json::to_string_pretty(&json!({"scope":"Cached native-verified synthetic transfer output, decrypted with public deterministic test receiver key. No proof/key generation or chain inclusion.","note":{"receiver":{"g_d":point(gd),"pk_d":point(pkd)},"value":note.value().inner().to_string(),"rho":limbs(note.rho().to_bytes()),"rseed":note.rseed().as_bytes().to_vec()},"cmx_hex":hex::encode(cmx.to_bytes()),"rho_hex":hex::encode(note.rho().to_bytes()),"raw_address_hex":hex::encode(raw)})).unwrap());
}
