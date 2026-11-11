#!/usr/bin/env python3
"""Export the Poseidon constants and vectors of the Rust reference; no proofs or keys.

Usage: generate_poseidon.py POSEIDON_BINARY HALO2_POSEIDON_DIR. The binary is the
`poseidon` bin of reference/notes and the directory is the halo2_poseidon crate of the
halo2 commit pinned in reference/notes/Cargo.toml
(scripts/generate_native_fixtures.py builds the one, finds the other and runs this script).
"""

import hashlib, json, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from noir_format import format_file  # noqa: E402

BINARY = Path(sys.argv[1])
HALO2_POSEIDON = Path(sys.argv[2])
HALO2_URL = "https://github.com/zcash/halo2/blob/2d54aaf07c8135d0ce54313048999b4002b4cfbf/"
source = ROOT / "reference/notes/src/bin/poseidon.rs"
data = json.loads(subprocess.check_output([BINARY], text=True))
out = ROOT / "noir/ironwood"
fq = lambda x: "Fq::from_limbs([" + ",".join(x) + "])"
rows = lambda r: "[" + ",".join(fq(x) for x in r) + "]"
text = "use bignum::{BigNum,Pallas_Fq as Fq};\n"
for name, n in [("round_constants", 64), ("mds", 3)]:
    assert len(data[name]) == n
    text += (
        f"pub fn {name}()->[[Fq;3];{n}]{{["
        + ",".join(rows(r) for r in data[name])
        + "]}\n"
    )
# provenance.json records the hash of the committed (formatted) file and,
# separately, of this raw output.
raw_sha256 = hashlib.sha256(text.encode()).hexdigest()
(out / "src/poseidon/constants.nr").write_text(text)
format_file(out / "src/poseidon/constants.nr")
(ROOT / "fixtures/poseidon/native-vectors.json").write_text(
    json.dumps(data["vectors"], indent=2) + "\n"
)
constants = out / "src/poseidon/constants.nr"
files = [
    (str(source.relative_to(ROOT)), source),
    (HALO2_URL + "halo2_poseidon/src/fp.rs", HALO2_POSEIDON / "src/fp.rs"),
    (HALO2_URL + "halo2_poseidon/src/p128pow5t3.rs", HALO2_POSEIDON / "src/p128pow5t3.rs"),
    (str(constants.relative_to(ROOT)), constants),
]
record = {name: hashlib.sha256(p.read_bytes()).hexdigest() for name, p in files}
record["generatorOutputSha256"] = {
    str(constants.relative_to(ROOT)): raw_sha256,
    "note": "Output of scripts/generate_poseidon.py before nargo fmt. The committed file has the same 201 field elements in formatted layout.",
}
(ROOT / "fixtures/poseidon/provenance.json").write_text(
    json.dumps(record, indent=2) + "\n"
)
