//! The Sinsemilla constants of the Orchard domains (Q of each hash domain, R of each
//! commit domain) and the 1024 generators S, from the sinsemilla crate, as little-endian
//! hex coordinates. scripts/generate_sinsemilla_generators.py turns them into
//! noir/ironwood/src/sinsemilla/generators.nr.
use ff::PrimeField;
use group::Curve;
use pasta_curves::{arithmetic::CurveAffine, pallas};
use serde_json::{json, Value};
use sinsemilla::{CommitDomain, HashDomain, SINSEMILLA_S};

fn base(x: &pallas::Base) -> Value {
    json!(hex::encode(x.to_repr()))
}

fn point(p: pallas::Point) -> Value {
    let affine = p.to_affine();
    let c = affine.coordinates().unwrap();
    json!([base(c.x()), base(c.y())])
}

fn main() {
    let q: Vec<Value> = [
        "z.cash:Orchard-MerkleCRH",
        "z.cash:Orchard-NoteCommit-M",
        "z.cash:Orchard-CommitIvk-M",
    ]
    .iter()
    .map(|name| point(HashDomain::new(name).Q()))
    .collect();
    let r: Vec<Value> = ["z.cash:Orchard-NoteCommit", "z.cash:Orchard-CommitIvk"]
        .iter()
        .map(|name| point(CommitDomain::new(name).R()))
        .collect();
    let s: Vec<Value> = SINSEMILLA_S.iter().map(|(x, y)| json!([base(x), base(y)])).collect();
    println!("{}", serde_json::to_string_pretty(&json!({"q": q, "r": r, "s": s})).unwrap());
}
