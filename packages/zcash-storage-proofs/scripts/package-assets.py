"""Stage LICENSE, NOTICE and docs/*.md from the repository root before npm pack.

The staged copies are gitignored in this package. Links in the documents to
files the package ships are rewritten to point inside the package; links to
anything else become explicit repository paths, so that no link in an offline
installation is broken.
"""

from pathlib import Path
import fnmatch
import json
import os
import re
import shutil
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT.parents[1]

for name in ["LICENSE", "NOTICE"]:
    shutil.copy2(REPOSITORY / name, ROOT / name)
# Refresh the staged documents so that a removed document cannot survive in a
# warm npm pack.
if (ROOT / "docs").exists():
    shutil.rmtree(ROOT / "docs")
(ROOT / "docs").mkdir()

package_files = json.loads((ROOT / "package.json").read_text())["files"]


def packaged(path):
    if not path.is_relative_to(ROOT):
        return False
    relative = path.relative_to(ROOT).as_posix()
    return relative in {"README.md", "LICENSE", "NOTICE", "package.json"} or any(
        fnmatch.fnmatchcase(relative, entry)
        or ("*" not in entry and relative.startswith(entry.rstrip("/") + "/"))
        for entry in package_files
    )


def document_link(match, source, destination):
    label, href = match.groups()
    url = urlsplit(href.strip("<>"))
    if url.scheme or url.netloc or not url.path:
        return match.group()
    original = (source.parent / unquote(url.path)).resolve()
    if original.is_relative_to(REPOSITORY / "docs"):
        target = ROOT / "docs" / original.relative_to(REPOSITORY / "docs")
    elif original in {REPOSITORY / "LICENSE", REPOSITORY / "NOTICE"}:
        target = ROOT / original.name
    else:
        target = original
    if packaged(target) and original.exists():
        relative = Path(os.path.relpath(target, destination.parent)).as_posix()
        suffix = ("?" + url.query if url.query else "") + (
            "#" + url.fragment if url.fragment else ""
        )
        return f"[{label}]({relative}{suffix})"
    checkout = Path(os.path.relpath(original, REPOSITORY)).as_posix()
    if url.fragment:
        checkout += "#" + url.fragment
    return f"{label} (repository: `{checkout}`)"


for source in sorted((REPOSITORY / "docs").glob("*.md")):
    destination = ROOT / "docs" / source.name
    text = re.sub(
        r"(?<!!)\[([^\]]+)\]\(([^)\s]+)\)",
        lambda match: document_link(match, source, destination),
        source.read_text(),
    )
    destination.write_text(text)
