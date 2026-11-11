"""Format generated Noir with `nargo fmt` ($NARGO, else `nargo` on PATH) and the
repository's noirfmt.toml, if it has one.

The generators build their Noir in memory and pass it through format_noir
before writing it or, with --check, comparing it; format_file formats a file in
place.
"""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def format_noir(sources):
    """Return each Noir source as `nargo fmt` formats it."""
    sources = list(sources)
    if not sources:
        return []
    with tempfile.TemporaryDirectory(prefix="fmt-") as scratch:
        package = Path(scratch)
        (package / "src").mkdir()
        (package / "Nargo.toml").write_text(
            '[package]\nname = "fmt_scratch"\ntype = "lib"\nauthors = [""]\n'
        )
        if (ROOT / "noirfmt.toml").is_file():
            shutil.copy(ROOT / "noirfmt.toml", package / "noirfmt.toml")
        (package / "src/lib.nr").write_text("")
        for i, source in enumerate(sources):
            (package / f"src/file_{i}.nr").write_text(source)
        result = subprocess.run(
            [os.environ.get("NARGO", "nargo"), "fmt"], cwd=package, capture_output=True, text=True
        )
        # nargo reports waiting for its dependency-cache lock on stderr; that is not a failure.
        errors = [line for line in result.stderr.splitlines() if line.strip() and "Waiting for lock" not in line]
        if result.returncode != 0 or errors:
            raise RuntimeError(f"nargo fmt failed:\n{result.stderr}")
        return [(package / f"src/file_{i}.nr").read_text() for i in range(len(sources))]


def format_file(path):
    """Format the Noir file at `path` in place."""
    path = Path(path)
    (text,) = format_noir([path.read_text()])
    path.write_text(text)
