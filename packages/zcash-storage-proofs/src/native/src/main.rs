// Explicit native witness preparation; never generates fixture vectors, proofs or keys.
// `ironwood-native-hints --hash-hints INPUT.json` or `--merkle-hints INPUT.json`
// prints affine hint records for a supplied note hash or Merkle witness; the Noir
// equations constrain them as untrusted input. Build with the pinned Rust toolchain
// (rust-toolchain.toml in this directory):
//   cd packages/zcash-storage-proofs/src/native
//   cargo build --release --locked --target-dir /abs/fresh
// and pass /abs/fresh/release/ironwood-native-hints explicitly to the TypeScript
// native provider. Independent vectors come from reference/{notes,memo}.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 3, "Expected --hash-hints or --merkle-hints and an input JSON path");
    println!("{}", serde_json::to_string(&ironwood_native_hints::native_hints::run(&args[1], &args[2])).unwrap());
}
