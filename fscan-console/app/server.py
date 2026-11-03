"""本地 HTTP 服务与 JSON API。"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import threading
import time
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import paths, scanner, store

MAX_BODY = 32 * 1024 * 1024


class Api:
    def __init__(self, manager: scanner.ScanManager) -> None:
        self.manager = manager
        self.started = time.time()
        self.last_seen = time.time()
        self.token = _make_token()
        self.shutdown_event = threading.Event()
        self.httpd: ThreadingHTTPServer | None = None

    def touch(self) -> None:
        self.last_seen = time.time()


def _make_token() -> str:
    import secrets

    return secrets.token_urlsafe(18)


class Handler(BaseHTTPRequestHandler):
    server_version = "FScanDesk/1.0"
    protocol_version = "HTTP/1.1"
    api: Api

    # ---------- helpers ----------
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        return

    def _send(self, status: int, body: bytes, content_type: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _error(self, message: str, status: int = 400) -> None:
        self._json({"ok": False, "error": message}, status)

    def _read_body(self) -> bytes:
        if getattr(self, "_body_cache", None) is not None:
            return self._body_cache
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            self._body_cache = b""
            return self._body_cache
        if length > MAX_BODY:
            raise ValueError("请求体过大")
        self._body_cache = self.rfile.read(length)
        return self._body_cache

    def _read_json(self) -> dict[str, Any]:
        raw = self._read_body()
        if not raw:
            return {}
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("JSON 结构必须是对象")
        return data

    def _check_token(self) -> bool:
        if self.path.endswith("/api/ping"):
            return True
        token = self.headers.get("X-FSCAN-Token") or ""
        if token != self.api.token:
            self._error("unauthorized", 403)
            return False
        origin = self.headers.get("Origin")
        if origin and not (
            origin.startswith("http://127.0.0.1") or origin.startswith("http://localhost")
        ):
            self._error("bad origin", 403)
            return False
        return True

    def _static_path(self, rel: str) -> Path | None:
        base = paths.web_dir()
        rel = rel.lstrip("/")
        if rel in ("", "/"):
            rel = "index.html"
        target = (base / rel).resolve()
        try:
            target.relative_to(base.resolve())
        except Exception:
            return None
        if not target.is_file():
            return None
        return target

    # ---------- verbs ----------
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        self.api.touch()
        if path == "/api/ping":
            self._json({"app": "FScanDesk", "version": paths.APP_VERSION})
            return
        if path.startswith("/api/"):
            if not self._check_token():
                return
            try:
                self._route_get(path, parse_qs(parsed.query))
            except Exception as exc:
                _log_exc(exc)
                self._error(f"服务器错误: {exc}", 500)
            return
        self._serve_static(path)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        self.api.touch()
        self._body_cache = None
        try:
            # 无论接口是否用到 body，都先完整读掉，避免 keep-alive 连接错位
            self._read_body()
        except ValueError as exc:
            self._error(str(exc), 413)
            return
        if path.startswith("/api/"):
            if not self._check_token():
                return
            try:
                self._route_post(path, parse_qs(parsed.query))
            except Exception as exc:
                _log_exc(exc)
                self._error(f"服务器错误: {exc}", 500)
            return
        self._error("not found", 404)

    # ---------- static ----------
    def _serve_static(self, path: str) -> None:
        if path in ("/", "/index.html"):
            index = paths.web_dir() / "index.html"
            try:
                html = index.read_text(encoding="utf-8")
            except Exception:
                self._error("index.html 缺失", 500)
                return
            html = html.replace("__FSCAN_TOKEN__", self.api.token)
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
            return
        target = self._static_path(path)
        if target is None:
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".svg": "image/svg+xml",
            ".png": "image/png",
            ".ico": "image/x-icon",
            ".json": "application/json; charset=utf-8",
            ".woff2": "font/woff2",
        }.get(target.suffix.lower(), "application/octet-stream")
        try:
            body = target.read_bytes()
        except Exception:
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        self._send(200, body, ctype)

    # ---------- API: GET ----------
    def _route_get(self, path: str, query: dict[str, list[str]]) -> None:
        manager = self.api.manager
        if path == "/api/bootstrap":
            settings = store.load_settings()
            info = manager.info()
            self._json(
                {
                    "ok": True,
                    "app": {
                        "name": paths.APP_TITLE,
                        "version": paths.APP_VERSION,
                        "data_dir": str(paths.data_dir()),
                        "open_mode": settings.get("open_mode", "app"),
                        "author": {"name": paths.APP_AUTHOR, "url": paths.APP_AUTHOR_URL},
                        "repo": paths.APP_REPO_URL,
                    },
                    "fscan": info,
                    "settings": settings,
                    "history": store.list_history()[:60],
                    "presets": {
                        "ports": [
                            {"key": "common", "label": "常用", "hint": "内置 133 个高频端口"},
                            {"key": "web", "label": "Web", "hint": "Web 相关端口组"},
                            {"key": "db", "label": "数据库", "hint": "数据库端口组"},
                            {"key": "service", "label": "服务", "hint": "常见服务端口组"},
                            {"key": "all", "label": "全端口", "hint": "1-65535，耗时长"},
                            {"key": "custom", "label": "自定义", "hint": "手动填写端口"},
                        ],
                        "modes": [
                            {"key": "all", "label": "全量扫描", "hint": "存活 + 端口 + 服务 + 漏洞"},
                            {"key": "alive", "label": "仅存活", "hint": "-ao，快速探活"},
                            {"key": "web", "label": "Web 探测", "hint": "只跑 webtitle / webpoc"},
                            {"key": "plugin", "label": "指定插件", "hint": "手动填写插件名"},
                        ],
                    },
                    "state": manager.current_state(),
                }
            )
            return
        if path == "/api/scan/poll":
            scan_id = _q(query, "id")
            log_cursor = int(_q(query, "log") or 0)
            result_cursor = int(_q(query, "res") or 0)
            payload = manager.poll(scan_id, log_cursor, result_cursor)
            if payload is None:
                self._error("扫描不存在", 404)
                return
            self._json({"ok": True, **payload})
            return
        if path == "/api/scan/result":
            scan_id = _q(query, "id")
            payload = manager.get_result(scan_id)
            if payload is None:
                self._error("扫描不存在", 404)
                return
            self._json({"ok": True, **payload})
            return
        if path == "/api/scan/state":
            self._json({"ok": True, "state": manager.current_state()})
            return
        if path == "/api/history":
            self._json({"ok": True, "items": store.list_history()})
            return
        if path == "/api/history/get":
            scan_id = _q(query, "id")
            stored = store.load_history(scan_id)
            if not stored:
                self._error("记录不存在", 404)
                return
            stored["console"] = store.read_history_console(scan_id)
            self._json({"ok": True, **stored})
            return
        if path == "/api/export":
            self._export(query)
            return
        if path == "/api/heartbeat":
            self._json({"ok": True, "ts": int(time.time())})
            return
        self._error("not found", 404)

    # ---------- API: POST ----------
    def _route_post(self, path: str, query: dict[str, list[str]]) -> None:
        manager = self.api.manager
        if path == "/api/scan/start":
            cfg = self._read_json()
            try:
                result = manager.start(cfg)
            except scanner.ScanBusy as exc:
                self._error(str(exc), 409)
                return
            except ValueError as exc:
                self._error(str(exc), 400)
                return
            self._json({"ok": True, **result})
            return
        if path == "/api/scan/stop":
            stopped = manager.stop()
            self._json({"ok": True, "stopped": stopped})
            return
        if path == "/api/preview":
            cfg = self._read_json()
            try:
                preview = manager.build_preview(cfg)
            except ValueError as exc:
                self._error(str(exc), 400)
                return
            self._json({"ok": True, **preview})
            return
        if path == "/api/upload":
            name = _q(query, "name") or "targets.txt"
            safe = re.sub(r"[^0-9A-Za-z._\-\u4e00-\u9fff]+", "_", os.path.basename(name))[:80]
            folder = paths.uploads_dir() / time.strftime("%Y%m%d-%H%M%S")
            folder.mkdir(parents=True, exist_ok=True)
            target = folder / (safe or "targets.txt")
            data = self._read_body()
            target.write_bytes(data)
            self._json({"ok": True, "path": str(target), "size": len(data), "name": safe})
            return
        if path == "/api/settings":
            body = self._read_json()
            patch: dict[str, Any] = {}
            if body.get("fscan_path") is not None:
                try:
                    info = manager.set_fscan_path(str(body.get("fscan_path") or ""))
                except ValueError as exc:
                    self._error(str(exc), 400)
                    return
                patch["fscan_path"] = info["fscan_path"]
            if body.get("open_mode") in ("app", "browser"):
                patch["open_mode"] = body["open_mode"]
            settings = store.save_settings(patch)
            self._json({"ok": True, "settings": settings, "fscan": manager.info()})
            return
        if path == "/api/history/delete":
            body = self._read_json()
            scan_id = str(body.get("id") or "")
            self._json({"ok": store.delete_history(scan_id)})
            return
        if path == "/api/open":
            body = self._read_json()
            target = str(body.get("path") or paths.data_dir())
            resolved = Path(target).resolve()
            try:
                resolved.relative_to(paths.data_dir().resolve())
            except Exception:
                self._error("只能打开本程序的数据目录", 400)
                return
            try:
                os.startfile(str(resolved))  # type: ignore[attr-defined]
            except Exception as exc:
                self._error(f"打开目录失败: {exc}", 500)
                return
            self._json({"ok": True})
            return
        if path == "/api/quit":
            self._json({"ok": True})
            threading.Timer(0.4, self._quit).start()
            return
        self._error("not found", 404)

    def _quit(self) -> None:
        try:
            self.api.manager.stop()
        except Exception:
            pass
        time.sleep(0.3)
        try:
            (paths.data_dir() / "runtime.json").unlink(missing_ok=True)
        except Exception:
            pass
        os._exit(0)

    # ---------- export ----------
    def _export(self, query: dict[str, list[str]]) -> None:
        scan_id = _q(query, "id")
        kind = (_q(query, "kind") or "csv").lower()
        payload = self.api.manager.get_result(scan_id)
        if payload is None:
            self._error("扫描不存在", 404)
            return
        records = payload.get("results") or []
        safe_id = re.sub(r"[^0-9A-Za-z._\-]+", "_", scan_id)[:40] or "scan"
        if kind == "json":
            data = {
                "id": scan_id,
                "started_at": payload.get("started_at"),
                "ended_at": payload.get("ended_at"),
                "summary": payload.get("summary"),
                "stats": payload.get("stats"),
                "cmd": payload.get("cmd"),
                "results": records,
            }
            body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
            self._send(
                200,
                body,
                "application/json; charset=utf-8",
                {"Content-Disposition": f'attachment; filename="{safe_id}.json"'},
            )
            return
        if kind == "log":
            text = store.read_history_console(scan_id)
            body = text.encode("utf-8")
            self._send(
                200,
                body,
                "text/plain; charset=utf-8",
                {"Content-Disposition": f'attachment; filename="{safe_id}.log.txt"'},
            )
            return
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "类型",
                "目标",
                "状态/漏洞",
                "主机",
                "端口",
                "服务",
                "产品/指纹",
                "标题",
                "URL",
                "用户名",
                "密码",
                "操作系统",
                "Banner",
                "时间",
            ]
        )
        for rec in records:
            details = rec.get("details") or {}
            host = scanner._host_of(rec.get("target", ""))
            writer.writerow(
                [
                    rec.get("type"),
                    rec.get("target"),
                    rec.get("status"),
                    host,
                    details.get("port", ""),
                    details.get("service", ""),
                    details.get("product", ""),
                    details.get("title", ""),
                    details.get("url", ""),
                    details.get("username", ""),
                    details.get("password", ""),
                    details.get("os", ""),
                    str(details.get("banner", ""))[:300],
                    rec.get("time", ""),
                ]
            )
        body = ("\ufeff" + buf.getvalue()).encode("utf-8")
        self._send(
            200,
            body,
            "text/csv; charset=utf-8",
            {"Content-Disposition": f'attachment; filename="{safe_id}.csv"'},
        )


def _q(query: dict[str, list[str]], key: str) -> str:
    values = query.get(key) or []
    return values[0] if values else ""


def _log_exc(exc: BaseException) -> None:
    try:
        log_path = paths.data_dir() / "app.log"
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(time.strftime("%Y-%m-%d %H:%M:%S ") + "ERROR\n")
            fh.write("".join(traceback.format_exception(exc)))
            fh.write("\n")
    except Exception:
        pass


def pick_port(preferred_start: int = 47321, count: int = 12) -> int:
    import socket

    for port in range(preferred_start, preferred_start + count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            sock.close()
    # 让系统分配
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def create_server(port: int, api: Api) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"api": api})
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    httpd.daemon_threads = True
    api.httpd = httpd
    return httpd
