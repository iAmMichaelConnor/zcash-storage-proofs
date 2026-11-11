//! Native witness provider. The Noir equations, not this code, authenticate hints.
use super::{limbs, point, node};
use ff::{Field, PrimeField};
use group::{Curve,Group};
use incrementalmerkletree::{Hashable,Level};
use orchard::tree::MerkleHashOrchard;
use pasta_curves::{pallas,arithmetic::CurveAffine};
use serde_json::{json,Value};
use sinsemilla::{HashDomain,SINSEMILLA_S};
use std::{fs,time::Instant};
type Record=[[String;3];5];
fn parse_field(v:&Value)->pallas::Base {
 let a=v.as_array().expect("three limbs");assert_eq!(a.len(),3);let mut bytes=[0u8;32];
 for i in 0..3 {let x=a[i].as_str().expect("decimal limb string").parse::<u128>().unwrap();let n=if i==2{15}else{120};assert!(x<(1u128<<n));for b in 0..n{if (x>>b)&1==1{let bit=120*i+b;bytes[bit/8]|=1<<(bit%8);}}}
 Option::from(pallas::Base::from_repr(bytes)).expect("canonical Pallas field")
}
fn parse_point(v:&Value)->pallas::Point {
 let x=parse_field(&v["x"]);let y=parse_field(&v["y"]);
 if v["infinity"].as_bool().unwrap(){pallas::Point::identity()}else{pallas::Point::from(Option::<pallas::Affine>::from(pallas::Affine::from_xy(x,y)).expect("on-curve point"))}
}
fn raw_record(a:[pallas::Base;5])->Record {a.map(limbs)}
fn fused(p:Option<pallas::Point>,s:pallas::Affine)->(Record,Option<pallas::Point>){
 let zero=[pallas::Base::ZERO;5];
 let Some(p)=p else{return(raw_record(zero),None)};
 let a=p.to_affine();let Some(c)=Option::from(a.coordinates())else{return(raw_record(zero),None)};
 let c:pasta_curves::arithmetic::Coordinates<pallas::Affine>=c;
 let sc=s.coordinates().unwrap();let(x,y,u,v)=(*c.x(),*c.y(),*sc.x(),*sc.y());
 if x==u{return(raw_record(zero),None)}
 let l1=(v-y)*(u-x).invert().unwrap();let rx=l1.square()-x-u;
 let middle=p+pallas::Point::from(s);let mc=middle.to_affine().coordinates().unwrap();assert_eq!(rx,*mc.x());
 if rx==x{return(raw_record([l1,rx,pallas::Base::ZERO,pallas::Base::ZERO,pallas::Base::ZERO]),None)}
 let l2=-l1-(y+y)*(rx-x).invert().unwrap();let xf=l2.square()-rx-x;let yf=l2*(x-xf)-y;
 let output=pallas::Point::from(pallas::Affine::from_xy(xf,yf).unwrap());assert_eq!(output,middle+p);
 (raw_record([l1,rx,l2,xf,yf]),Some(output))
}
fn hash(q:pallas::Point,bits:&[bool])->(Vec<Record>,Option<pallas::Point>){
 assert!(bits.len()<=2530);let mut result=Some(q);let mut records=Vec::new();
 for chunk in bits.chunks(10){let index=chunk.iter().enumerate().fold(0usize,|n,(i,b)|n+if *b{1<<i}else{0});let(x,y)=SINSEMILLA_S[index];let s=pallas::Affine::from_xy(x,y).unwrap();let(h,r)=fused(result,s);records.push(h);result=r;}
 let expected=Option::<pallas::Point>::from(HashDomain::from_Q(q).hash_to_point(bits.iter().copied()));assert_eq!(result,expected);
 (records,result)
}
fn field_bits(x:pallas::Base)->Vec<bool>{let b=x.to_repr();(0..255).map(|i|((b[i/8]>>(i%8))&1)==1).collect()}
fn extract(p:Option<pallas::Point>)->pallas::Base{p.and_then(|p|Option::from(p.to_affine().coordinates()).map(|c:pasta_curves::arithmetic::Coordinates<pallas::Affine>|*c.x())).unwrap_or(pallas::Base::ZERO)}
pub fn run(mode:&str,path:&str)->Value{
 let start=Instant::now();let input:Value=serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
 if mode=="--hash-hints"{
  let bits:Vec<bool>=input["message"].as_array().expect("message bits").iter().map(|v|v.as_bool().unwrap()).collect();
  let q=if input.get("q").is_some(){parse_point(&input["q"])}else{let domains=["z.cash:Orchard-MerkleCRH","z.cash:Orchard-NoteCommit-M","z.cash:Orchard-CommitIvk-M"];HashDomain::new(domains[input["domain"].as_u64().unwrap()as usize]).Q()};
  let(records,result)=hash(q,&bits);json!({"mode":"hash","records":records,"message_bits":bits.len(),"point":point(result.unwrap_or(pallas::Point::identity())),"bottom":result.is_none(),"generation_seconds":start.elapsed().as_secs_f64()})
 }else if mode=="--merkle-hints"{
  let mut acc=parse_field(&input["leaf"]);let position=input["position"].as_u64().unwrap();let path=input["siblings"].as_array().unwrap();assert!(path.len()<=32);assert!(position<(1u64<<path.len()));
  let q=HashDomain::new("z.cash:Orchard-MerkleCRH").Q();let mut records=Vec::new();let mut layer_results=Vec::new();
  for (level,s)in path.iter().enumerate(){let sibling=parse_field(s);let(left,right)=if(position>>level)&1==0{(acc,sibling)}else{(sibling,acc)};let mut bits:Vec<bool>=(0..10).map(|b|((level>>b)&1)==1).collect();bits.extend(field_bits(left));bits.extend(field_bits(right));let(h,p)=hash(q,&bits);assert_eq!(h.len(),52);records.extend(h);acc=extract(p);
   let upstream=MerkleHashOrchard::combine(Level::from(level as u8),&node(left),&node(right));assert_eq!(acc.to_repr(),upstream.to_bytes());layer_results.push(limbs(acc));
  }
  if input.get("expected").is_some(){assert_eq!(acc,parse_field(&input["expected"]));}
  json!({"mode":"merkle","depth":path.len(),"records":records,"root":limbs(acc),"layers":layer_results,"generation_seconds":start.elapsed().as_secs_f64()})
 }else{panic!("Expected --hash-hints or --merkle-hints")}
}
