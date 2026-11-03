#!/usr/bin/env python3
"""Package dist/FScanDesk.exe and docs into a GitHub Release zip."""
from __future__ import annotations

import re
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST_EXE = ROOT / "dist" / "FScanDesk.exe"


def version() -> str:
    text = (ROOT / "app" / "paths.py").read_text(encoding="utf-8")
    match = re.search(r'APP_VERSION\s*=\s*"([^"]+)"', text)
    return match.group(1) if match else "0.0.0"


def main() -> int:
    if not DIST_EXE.is_file():
        print(f"[error] {DIST_EXE} not found; run scripts/build.ps1 first", file=sys.stderr)
        return 2

    ver = version()
    name = f"fscan-console-v{ver}-windows-x64"
    release_dir = ROOT / "release"
    staging = release_dir / name
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    shutil.copy2(DIST_EXE, staging / "fscan-console.exe")
    for src, target in (
        (ROOT / "README.md", staging / "README.md"),
        (ROOT / "README_EN.md", staging / "README_EN.md"),
        (ROOT / "LICENSE", staging / "LICENSE"),
        (ROOT / "NOTICE", staging / "NOTICE"),
        (ROOT / "CHANGELOG.md", staging / "CHANGELOG.md"),
        (ROOT / "CONTRIBUTING.md", staging / "CONTRIBUTING.md"),
        (ROOT / "SECURITY.md", staging / "SECURITY.md"),
        (ROOT / "docs" / "USAGE.md", staging / "使用说明.md"),
    ):
        if src.is_file():
            shutil.copy2(src, target)

    for extra in ("docs", "third_party"):
        source_dir = ROOT / extra
        target_dir = staging / extra
        if source_dir.is_dir():
            shutil.copytree(source_dir, target_dir)

    zip_path = release_dir / f"{name}.zip"
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(release_dir))

    print(f"[ok] {zip_path} ({zip_path.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
