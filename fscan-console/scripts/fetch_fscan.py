#!/usr/bin/env python3
"""Download the pinned fscan release into tools/fscan.exe.

The binary is intentionally not committed to this repository. It is verified
against the checksums.txt published in the same GitHub release.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import urllib.request
from pathlib import Path

VERSION = "2.2.2"
ASSET = f"fscan_{VERSION}_windows_x64.exe"
BASE = f"https://github.com/shadow1ng/fscan/releases/download/v{VERSION}"
URL = f"{BASE}/{ASSET}"
CHECKSUMS_URL = f"{BASE}/checksums.txt"
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DEST = ROOT / "tools" / "fscan.exe"


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "fscan-console-fetch/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def expected_sha256() -> str | None:
    try:
        text = fetch(CHECKSUMS_URL).decode("utf-8", "replace")
    except Exception as exc:  # checksum is best-effort; download still useful
        print(f"[warn] cannot download checksums: {exc}", file=sys.stderr)
        return None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*") == ASSET:
            return parts[0].lower()
    print(f"[warn] {ASSET} not found in checksums.txt", file=sys.stderr)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=f"Fetch fscan v{VERSION} for Windows x64")
    parser.add_argument("--dest", default=str(DEFAULT_DEST), help="output path")
    parser.add_argument("--force", action="store_true", help="overwrite an existing file")
    parser.add_argument("--check", action="store_true", help="only verify the existing file")
    args = parser.parse_args()

    dest = Path(args.dest).expanduser()
    dest.parent.mkdir(parents=True, exist_ok=True)
    expected = expected_sha256()

    if args.check:
        if not dest.is_file():
            print(f"[error] {dest} does not exist")
            return 2
        actual = hashlib.sha256(dest.read_bytes()).hexdigest()
        ok = expected is None or actual == expected
        print(f"{dest}\nsha256 {actual}\n{'OK' if ok else 'MISMATCH'}")
        return 0 if ok else 1

    if dest.is_file() and not args.force:
        actual = hashlib.sha256(dest.read_bytes()).hexdigest()
        if expected is None or actual == expected:
            print(f"[ok] {dest} already exists ({dest.stat().st_size} bytes)")
            return 0
        print("[warn] existing file checksum mismatch, re-downloading")

    print(f"[*] downloading {URL}")
    data = fetch(URL)
    actual = hashlib.sha256(data).hexdigest()
    if expected and actual != expected:
        print(f"[error] checksum mismatch\nexpected {expected}\nactual   {actual}")
        return 1

    # Write directly: some Windows AV/sandbox setups deny rename-over-existing
    # executables created from a .part file.
    dest.write_bytes(data)
    try:
        dest.chmod(dest.stat().st_mode | 0o111)
    except OSError:
        pass
    print(f"[ok] {dest} ({len(data)} bytes)\nsha256 {actual}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
