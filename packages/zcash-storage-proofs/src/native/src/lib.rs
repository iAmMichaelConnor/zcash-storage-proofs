use ff::PrimeField;
use group::Curve;
use pasta_curves::{pallas,arithmetic::CurveAffine};
use orchard::tree::MerkleHashOrchard;
use serde_json::{json,Value};
pub fn limbs(x:pallas::Base)->[String;3]{
 raw_limbs(x.to_repr())
}
pub fn raw_limbs(bytes:[u8;32])->[String;3]{
 let mut out=[0u128;3];
 for bit in 0..255{if (bytes[bit/8]>>(bit%8))&1==1{out[bit/120]|=1u128<<(bit%120);}}
 out.map(|v|v.to_string())
}
pub fn point(p:pallas::Point)->Value{
 let a=p.to_affine();let c=Option::from(a.coordinates());
 match c{Some(c)=>{let c:pasta_curves::arithmetic::Coordinates<pallas::Affine>=c;json!({"x":limbs(*c.x()),"y":limbs(*c.y()),"infinity":false})},None=>json!({"x":["0","0","0"],"y":["0","0","0"],"infinity":true})}
}
pub fn node(x:pallas::Base)->MerkleHashOrchard{MerkleHashOrchard::from_bytes(&x.to_repr()).unwrap()}

pub mod native_hints;
