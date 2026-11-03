"""应用入口：启动本地服务并打开界面。"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any

from . import paths, scanner, server, store

LOG_LOCK = threading.Lock()


def log(message: str) -> None:
    try:
        with LOG_LOCK:
            with (paths.data_dir() / "app.log").open("a", encoding="utf-8") as fh:
                fh.write(time.strftime("%Y-%m-%d %H:%M:%S ") + str(message) + "\n")
    except Exception:
        pass


def log_exc(exc: BaseException) -> None:
    log("".join(traceback.format_exception(exc)))


def message_box(text: str, title: str = paths.APP_TITLE) -> None:
    try:
        ctypes.windll.user32.MessageBoxW(0, text, title, 0x40)
    except Exception:
        pass


def set_dpi_awareness() -> None:
    if os.name != "nt":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def runtime_path() -> Path:
    return paths.data_dir() / "runtime.json"


def read_runtime() -> dict[str, Any]:
    try:
        data = json.loads(runtime_path().read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def write_runtime(port: int) -> None:
    try:
        runtime_path().write_text(
            json.dumps({"port": port, "pid": os.getpid(), "started_at": time.time()}),
            encoding="utf-8",
        )
    except Exception:
        pass


def clear_runtime() -> None:
    try:
        runtime_path().unlink(missing_ok=True)
    except Exception:
        pass


def probe_instance(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/ping", timeout=1.2) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
            return bool(data.get("app") == "FScanDesk")
    except Exception:
        return False


def find_browser() -> str | None:
    candidates = [
        os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Microsoft/Edge/Application/msedge.exe"),
        os.path.join(os.environ.get("ProgramFiles", ""), "Microsoft/Edge/Application/msedge.exe"),
        os.path.join(os.environ.get("ProgramFiles", ""), "Google/Chrome/Application/chrome.exe"),
        os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Google/Chrome/Application/chrome.exe"),
        os.path.join(
            os.environ.get("LOCALAPPDATA", ""), "Google/Chrome/Application/chrome.exe"
        ),
    ]
    for path in candidates:
        if path and Path(path).is_file():
            return path
    return None


def open_ui(url: str, mode: str = "app") -> None:
    """优先用 Edge/Chrome 的 --app 模式打开，退回到默认浏览器。"""
    if mode == "app" and os.name == "nt":
        browser = find_browser()
        if browser:
            args = [
                browser,
                f"--app={url}",
                "--window-size=1516,960",
                "--no-first-run",
                "--disable-session-crashed-bubble",
            ]
            if "msedge" in browser.lower():
                # 独立的轻量用户目录，避免和用户日常浏览器会话互相影响
                profile = paths.data_dir() / "webview"
                profile.mkdir(parents=True, exist_ok=True)
                args.insert(1, f"--user-data-dir={profile}")
            try:
                subprocess.Popen(args, close_fds=True, creationflags=0x08000000)
                return
            except Exception as exc:
                log_exc(exc)
    try:
        webbrowser.open(url)
    except Exception as exc:
        log_exc(exc)


def main() -> int:
    parser = argparse.ArgumentParser(description=paths.APP_TITLE)
    parser.add_argument("--no-browser", action="store_true", help="不打开界面（调试用）")
    parser.add_argument("--port", type=int, default=0, help="固定端口（调试用）")
    parser.add_argument("--browser-mode", default="", choices=["", "app", "browser"])
    args = parser.parse_args()

    set_dpi_awareness()
    store.cleanup_temp()
    log(f"start {paths.APP_VERSION}")

    settings = store.load_settings()
    mode = args.browser_mode or str(settings.get("open_mode") or "app")

    # 已经有实例在跑：直接把界面打开到那个实例
    runtime = read_runtime()
    old_port = int(runtime.get("port") or 0)
    if old_port and probe_instance(old_port):
        url = f"http://127.0.0.1:{old_port}/"
        if not args.no_browser:
            open_ui(url, mode)
        return 0

    manager = scanner.ScanManager()
    api = server.Api(manager)
    runtime_lock = threading.Lock()

    port = args.port or server.pick_port()
    if args.port:
        try:
            test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test.bind(("127.0.0.1", port))
            test.close()
        except OSError:
            message_box(f"端口 {port} 已被占用，请换一个端口。")
            return 2
    httpd = server.create_server(port, api)
    write_runtime(port)
    url = f"http://127.0.0.1:{port}/"

    def watchdog() -> None:
        while not api.shutdown_event.is_set():
            time.sleep(10)
            session = manager.session
            if session is not None and session.status == "running":
                continue
            if time.time() - api.last_seen > 180:
                log("idle timeout, shutting down")
                try:
                    httpd.shutdown()
                except Exception:
                    pass
                return

    threading.Thread(target=watchdog, name="idle-watchdog", daemon=True).start()

    try:
        store.save_settings({"open_mode": mode})
    except Exception as exc:
        log_exc(exc)

    if not args.no_browser:
        threading.Timer(0.6, lambda: open_ui(url, mode)).start()

    try:
        httpd.serve_forever(poll_interval=0.4)
    except KeyboardInterrupt:
        pass
    finally:
        api.shutdown_event.set()
        clear_runtime()
        try:
            httpd.server_close()
        except Exception:
            pass
        try:
            manager.stop()
        except Exception:
            pass
        log("bye")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:
        log_exc(exc)
        message_box(f"启动失败：{exc}\n\n详细日志：{paths.data_dir() / 'app.log'}")
        raise SystemExit(1)
