use ff::{Field,PrimeField};
use halo2_poseidon::{Spec,P128Pow5T3,Hash,ConstantLength};
use pasta_curves::pallas;
use serde_json::json;
fn limbs(x:pallas::Base)->Vec<String>{let b=x.to_repr();(0..3).map(|i|{let mut n=0u128;for j in 0..15{if i*15+j<32{n|=(b[i*15+j]as u128)<<(8*j);}}n.to_string()}).collect()}
fn main(){
 let(rc,mds,_)=<P128Pow5T3 as Spec<pallas::Base,3,2>>::constants();
 let pairs=[(pallas::Base::ZERO,pallas::Base::ZERO),(pallas::Base::ONE,pallas::Base::from(2)),(-pallas::Base::ONE,-pallas::Base::ONE),(pallas::Base::from(42),-pallas::Base::ONE)];
 let vectors:Vec<_>=pairs.into_iter().map(|(a,b)|json!({"a":limbs(a),"b":limbs(b),"expected":limbs(Hash::<_,P128Pow5T3,ConstantLength<2>,3,2>::init().hash([a,b]))})).collect();
 println!("{}",serde_json::to_string_pretty(&json!({"round_constants":rc.iter().map(|r|r.iter().map(|x|limbs(*x)).collect::<Vec<_>>()).collect::<Vec<_>>(),"mds":mds.iter().map(|r|r.iter().map(|x|limbs(*x)).collect::<Vec<_>>()).collect::<Vec<_>>(),"vectors":vectors})).unwrap());
}
