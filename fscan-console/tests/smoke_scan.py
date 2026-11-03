"""后端冒烟：不经过浏览器，直接跑一次真实 fscan 扫描。"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["FSCANDESK_DATA_DIR"] = str(ROOT / "tests" / "tmpdata")

from app import scanner, server  # noqa: E402


def call(base: str, token: str, path: str, body=None, method=None):
    data = None
    headers = {"X-FSCAN-Token": token}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def main() -> int:
    manager = scanner.ScanManager()
    if not manager.fscan_path:
        print("fscan not found. Run: python scripts/fetch_fscan.py")
        return 2
    api = server.Api(manager)
    port = server.pick_port(47400)
    httpd = server.create_server(port, api)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    print("fscan:", manager.fscan_path, manager.fscan_version, "plugins:", len(manager.plugins))
    boot = call(base, api.token, "/api/bootstrap")
    print("bootstrap ok:", boot["ok"], "history:", len(boot["history"]))

    cfg = {
        "target": "127.0.0.1",
        "mode": "all",
        "ports_preset": "custom",
        "ports": "43120,135,445,3389,22",
        "threads": 30,
        "timeout": 1,
        "brute": False,
        "poc": False,
        "redis": False,
    }
    started = call(base, api.token, "/api/scan/start", cfg)
    print("started:", started["id"])
    print("cmd:", started["cmd"])
    log_cursor = 0
    res_cursor = 0
    last = None
    for _ in range(120):
        time.sleep(0.5)
        payload = call(
            base,
            api.token,
            f"/api/scan/poll?id={started['id']}&log={log_cursor}&res={res_cursor}",
        )
        last = payload
        log_cursor = payload["next_log"]
        res_cursor = payload["next_result"]
        if payload["status"] != "running":
            break
    print("status:", last["status"], "elapsed:", last["elapsed"], "stats:", last["stats"])
    print("logs:", len(last.get("logs", [])), "results:", len(last.get("all_results") or []))
    for rec in (last.get("all_results") or [])[:12]:
        print(" ", rec["type"], rec["target"], rec["status"], json.dumps(rec["details"], ensure_ascii=False)[:120])
    print("summary:", last.get("summary"))
    hist = call(base, api.token, "/api/history")
    print("history items:", len(hist["items"]))
    if hist["items"]:
        print("meta:", json.dumps(hist["items"][0], ensure_ascii=False)[:400])
    httpd.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
