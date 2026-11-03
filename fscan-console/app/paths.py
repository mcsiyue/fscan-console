"""路径与应用常量。"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

APP_NAME = "FScanDesk"
APP_TITLE = "FSCAN 内网扫描台"
APP_VERSION = "1.0.0"
APP_ID = "fscan-desk"
APP_AUTHOR = "四月"
APP_AUTHOR_URL = "https://github.com/mcsiyue"
APP_REPO_URL = "https://github.com/mcsiyue/fscan-console"


def is_frozen() -> bool:
    return bool(getattr(sys, "_MEIPASS", None))


def app_dir() -> Path:
    """只读资源根目录（打包后是解包目录）。"""
    if is_frozen():
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent.parent


def exe_dir() -> Path:
    """可执行文件所在目录（开发时是项目根目录）。"""
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return app_dir()


def web_dir() -> Path:
    return app_dir() / "web"


def data_dir() -> Path:
    override = os.environ.get("FSCANDESK_DATA_DIR")
    if override:
        base = Path(override)
    else:
        local = os.environ.get("LOCALAPPDATA") or str(Path.home())
        base = Path(local) / APP_NAME
    base.mkdir(parents=True, exist_ok=True)
    return base


def scans_dir() -> Path:
    d = data_dir() / "scans"
    d.mkdir(parents=True, exist_ok=True)
    return d


def uploads_dir() -> Path:
    d = data_dir() / "uploads"
    d.mkdir(parents=True, exist_ok=True)
    return d


def settings_path() -> Path:
    return data_dir() / "settings.json"


def fscan_candidates() -> list[Path]:
    """按优先级列出可能的 fscan 可执行文件位置。"""
    out: list[Path] = []
    env = os.environ.get("FSCAN_PATH")
    if env:
        out.append(Path(env))
    for base in (exe_dir(), app_dir()):
        out.extend(
            [
                base / "fscan.exe",
                base / "tools" / "fscan.exe",
                base / "fscan",
                base / "tools" / "fscan",
            ]
        )
    seen: set[str] = set()
    uniq: list[Path] = []
    for p in out:
        key = str(p).lower()
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    return uniq


def find_fscan(preferred: str | None = None) -> Path | None:
    if preferred:
        p = Path(preferred)
        if p.is_file():
            return p
    for p in fscan_candidates():
        if p.is_file():
            return p
    return None


def bundled_fscan() -> Path | None:
    p = app_dir() / "fscan.exe"
    return p if p.is_file() else None


def install_bundled_fscan() -> Path | None:
    """把打包进 exe 的 fscan 复制到数据目录，避免每次从临时解包目录运行。"""
    src = bundled_fscan()
    if not src:
        return None
    target = data_dir() / "bin" / "fscan.exe"
    try:
        if src.resolve() == target.resolve():
            return src
    except Exception:
        pass
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.is_file() or target.stat().st_size != src.stat().st_size:
            shutil.copy2(src, target)
        return target
    except Exception:
        return src
