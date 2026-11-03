"""设置与扫描历史的本地持久化。"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any

from . import paths

DEFAULT_SETTINGS: dict[str, Any] = {
    "fscan_path": "",
    "open_mode": "app",  # app | browser
    "last_config": {},
}


def _read_json(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


def _write_json(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    tmp.replace(path)


def load_settings() -> dict[str, Any]:
    data = _read_json(paths.settings_path(), {})
    merged = dict(DEFAULT_SETTINGS)
    if isinstance(data, dict):
        merged.update({k: v for k, v in data.items() if v is not None})
    return merged


def save_settings(patch: dict[str, Any]) -> dict[str, Any]:
    current = load_settings()
    for key, value in patch.items():
        if key in DEFAULT_SETTINGS:
            current[key] = value
    _write_json(paths.settings_path(), current)
    return current


def history_root() -> Path:
    return paths.scans_dir()


def list_history() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    root = history_root()
    if not root.is_dir():
        return items
    for entry in root.iterdir():
        if not entry.is_dir():
            continue
        meta = _read_json(entry / "meta.json", None)
        if not isinstance(meta, dict):
            continue
        meta.setdefault("id", entry.name)
        items.append(meta)
    items.sort(key=lambda m: m.get("started_at") or "", reverse=True)
    return items


def load_history(scan_id: str) -> dict[str, Any] | None:
    safe = "".join(ch for ch in scan_id if ch.isalnum() or ch in "-_")
    if not safe:
        return None
    folder = history_root() / safe
    if not folder.is_dir():
        return None
    meta = _read_json(folder / "meta.json", None)
    result = _read_json(folder / "result.json", {})
    if not isinstance(meta, dict):
        return None
    meta["id"] = safe
    return {"meta": meta, "result": result}


def delete_history(scan_id: str) -> bool:
    safe = "".join(ch for ch in scan_id if ch.isalnum() or ch in "-_")
    if not safe:
        return False
    folder = history_root() / safe
    if not folder.is_dir():
        return False
    shutil.rmtree(folder, ignore_errors=True)
    return True


def save_history(
    scan_id: str,
    meta: dict[str, Any],
    result_json: dict[str, Any],
    console_text: str,
    args_line: str,
) -> None:
    folder = history_root() / scan_id
    folder.mkdir(parents=True, exist_ok=True)
    _write_json(folder / "meta.json", meta)
    _write_json(folder / "result.json", result_json)
    try:
        (folder / "console.log").write_text(console_text, encoding="utf-8")
    except Exception:
        pass
    try:
        (folder / "command.txt").write_text(args_line, encoding="utf-8")
    except Exception:
        pass


def read_history_console(scan_id: str) -> str:
    safe = "".join(ch for ch in scan_id if ch.isalnum() or ch in "-_")
    path = history_root() / safe / "console.log"
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def cleanup_temp(max_age_hours: int = 72) -> None:
    """清理过旧的临时目录（例如异常退出留下的）。"""
    cutoff = time.time() - max_age_hours * 3600
    root = paths.data_dir() / "uploads"
    if not root.is_dir():
        return
    for entry in root.iterdir():
        try:
            if entry.stat().st_mtime < cutoff:
                if entry.is_dir():
                    shutil.rmtree(entry, ignore_errors=True)
                else:
                    entry.unlink(missing_ok=True)
        except Exception:
            pass
