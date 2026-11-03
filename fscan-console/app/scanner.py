"""fscan 子进程管理、输出解析与扫描状态。"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import paths, store

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
VERSION_RE = re.compile(r"Fscan\s+([0-9][0-9A-Za-z.\-_]*)")
PLUGIN_RE = re.compile(r"^([a-z0-9_]+)\s+(service|web|local|udp)\s+(.*)$")

PORT_PRESETS = {
    "common": None,  # 使用 fscan 内置的 133 个常用端口
    "web": "web",
    "db": "db",
    "service": "service",
    "all": "1-65535",
}

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _host_of(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return t
    if "://" in t:
        try:
            return urlparse(t).hostname or t
        except Exception:
            return t
    if t.startswith("[") and "]" in t:
        return t[1 : t.index("]")]
    if t.count(":") == 1:
        head, _, tail = t.rpartition(":")
        if tail.isdigit():
            return head
    return t


def _result_key(typ: str, target: str, status: str, details: dict[str, Any]) -> str:
    if typ == "HOST":
        return f"HOST|{target}"
    if typ == "PORT":
        return f"PORT|{target}:{details.get('port', '')}"
    if typ == "VULN":
        return f"VULN|{target}|{status}"
    return f"SERVICE|{target}"


def _result_id(key: str) -> str:
    return "r" + hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()[:14]


def normalize_result(raw: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    typ = str(raw.get("type") or "").upper()
    target = str(raw.get("target") or "").strip()
    if not typ or not target:
        return None
    details = raw.get("details")
    if not isinstance(details, dict):
        details = {}
    status = raw.get("status")
    status = "" if status is None else str(status)
    key = _result_key(typ, target, status, details)
    return {
        "id": _result_id(key),
        "type": typ,
        "target": target,
        "status": status,
        "details": details,
        "time": raw.get("time") or "",
    }


def compute_stats(results: list[dict[str, Any]]) -> dict[str, int]:
    hosts: set[str] = set()
    alive = ports = services = web = vulns = 0
    for item in results:
        typ = item.get("type")
        if typ == "HOST":
            alive += 1
            hosts.add(_host_of(item.get("target", "")))
        elif typ == "PORT":
            ports += 1
            hosts.add(_host_of(item.get("target", "")))
        elif typ == "SERVICE":
            services += 1
            if item.get("details", {}).get("is_web"):
                web += 1
            hosts.add(_host_of(item.get("target", "")))
        elif typ == "VULN":
            vulns += 1
            hosts.add(_host_of(item.get("target", "")))
    hosts.discard("")
    return {
        "hosts": len(hosts),
        "alive": alive,
        "ports": ports,
        "services": services,
        "web": web,
        "vulns": vulns,
        "total": len(results),
    }


def build_args(cfg: dict[str, Any], fscan: str, result_path: Path) -> list[str]:
    args: list[str] = [fscan]

    target_file = str(cfg.get("target_file") or "").strip()
    raw_target = str(cfg.get("target") or "").strip()
    targets: list[str] = []
    for line in raw_target.splitlines():
        line = line.strip().strip(",")
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    url_target = ""
    if target_file:
        args += ["-hf", target_file]
    elif targets:
        urls = [t for t in targets if t.lower().startswith(("http://", "https://"))]
        if urls:
            if len(targets) > 1:
                raise ValueError("URL 目标请单独填写；批量目标请使用 IP / CIDR / 域名")
            url_target = urls[0]
            args += ["-u", url_target]
        else:
            args += ["-h", ",".join(targets)]
    else:
        raise ValueError("请填写扫描目标")

    exclude_file = str(cfg.get("exclude_file") or "").strip()
    exclude = str(cfg.get("exclude") or "").strip()
    if exclude_file:
        args += ["-ehf", exclude_file]
    elif exclude:
        args += ["-eh", exclude]

    if not url_target:
        mode = str(cfg.get("mode") or "all")
        if mode == "alive":
            args.append("-ao")
        elif mode == "plugin":
            plugins = str(cfg.get("plugins") or "").strip()
            if not plugins:
                raise ValueError("指定插件模式下需要填写插件名，例如 ssh,smb,rdp")
            args += ["-m", plugins]
        elif mode == "web":
            args += ["-m", "webtitle,webpoc"]

        if mode != "alive":
            preset = str(cfg.get("ports_preset") or "common")
            if preset == "custom":
                custom_ports = str(cfg.get("ports") or "").strip()
                if not custom_ports:
                    raise ValueError("自定义端口不能为空")
                args += ["-p", custom_ports]
            else:
                value = PORT_PRESETS.get(preset, None)
                if mode == "web" and preset == "common":
                    value = "web"
                if value:
                    args += ["-p", value]

    if not bool(cfg.get("brute", True)):
        args.append("-nobr")
    if not bool(cfg.get("poc", True)):
        args.append("-nopoc")
    if not bool(cfg.get("redis", True)):
        args.append("-noredis")
    if bool(cfg.get("no_ping", False)):
        args.append("-np")

    threads = int(cfg.get("threads") or 600)
    timeout = int(cfg.get("timeout") or 3)
    args += ["-t", str(max(1, threads)), "-time", str(max(1, timeout))]

    wt = int(cfg.get("wt") or 0)
    if wt > 0:
        args += ["-wt", str(wt)]
    poc_num = int(cfg.get("poc_num") or 0)
    if poc_num > 0:
        args += ["-num", str(poc_num)]
    rate = int(cfg.get("rate") or 0)
    if rate > 0:
        args += ["-rate", str(rate)]
    retry = int(cfg.get("retry") or 0)
    if retry > 0 and retry != 3:
        args += ["-retry", str(retry)]

    for key, flag in (
        ("user", "-user"),
        ("password", "-pwd"),
        ("user_file", "-userf"),
        ("pass_file", "-pwdf"),
        ("hash", "-hash"),
        ("ssh_key", "-sshkey"),
        ("proxy", "-proxy"),
        ("socks5", "-socks5"),
        ("iface", "-iface"),
    ):
        value = str(cfg.get(key) or "").strip()
        if value:
            args += [flag, value]

    custom = str(cfg.get("custom_args") or "").strip()
    if custom:
        try:
            parts = shlex.split(custom, posix=False)
        except ValueError:
            parts = custom.split()
        cleaned = []
        for part in parts:
            if len(part) >= 2 and part[0] == part[-1] and part[0] in ("'", '"'):
                part = part[1:-1]
            cleaned.append(part)
        args += cleaned

    args += [
        "-nocolor",
        "-nopg",
        "-f",
        "json",
        "-o",
        str(result_path),
        "-lang",
        str(cfg.get("lang") or "zh"),
    ]
    return args


def quote_cmd(args: list[str]) -> str:
    out = []
    for a in args:
        if not a or re.search(r'[\s"]', a):
            out.append('"' + a.replace('"', '\\"') + '"')
        else:
            out.append(a)
    return " ".join(out)


class ScanBusy(RuntimeError):
    pass


class ScanSession:
    def __init__(self, scan_id: str, cfg: dict[str, Any], args: list[str], folder: Path):
        self.id = scan_id
        self.cfg = cfg
        self.args = args
        self.folder = folder
        self.result_path = folder / "result.json"
        self.console_path = folder / "console.log"
        self.started_at = now_iso()
        self.started_ts = time.time()
        self.ended_at: str | None = None
        self.duration = 0.0
        self.status = "running"
        self.error = ""
        self.exit_code: int | None = None
        self.proc: subprocess.Popen[bytes] | None = None
        self.stop_requested = False
        self.logs: list[dict[str, Any]] = []
        self.log_seq = 0
        self.results: dict[str, dict[str, Any]] = {}
        self.result_order: list[str] = []
        self.updates: list[dict[str, Any]] = []
        self.update_seq = 0
        self._log_fh: Any = None
        self._readers_stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._final_json: dict[str, Any] | None = None
        self.summary: dict[str, int] = {}

    # ---- logging ----
    def add_log(self, text: str) -> None:
        text = ANSI_RE.sub("", text).rstrip("\r\n")
        if not text.strip():
            return
        self.log_seq += 1
        self.logs.append({"seq": self.log_seq, "t": time.time(), "text": text[:6000]})
        if len(self.logs) > 40000:
            self.logs = self.logs[-25000:]
        if self._log_fh is not None:
            try:
                self._log_fh.write(text + "\n")
                self._log_fh.flush()
            except Exception:
                pass

    # ---- results ----
    def add_result(self, raw: dict[str, Any], source: str = "live") -> None:
        rec = normalize_result(raw)
        if not rec:
            return
        rid = rec["id"]
        existing = self.results.get(rid)
        if existing is None:
            self.results[rid] = rec
            self.result_order.append(rid)
        else:
            details = existing.get("details") or {}
            incoming = rec.get("details") or {}
            changed = False
            for k, v in incoming.items():
                if k not in details or details[k] in (None, "", 0):
                    details[k] = v
                    changed = True
            existing["details"] = details
            if rec.get("status") and not existing.get("status"):
                existing["status"] = rec["status"]
                changed = True
            if rec.get("time"):
                existing["time"] = rec["time"]
            if not changed:
                # 仍然通知前端一次，保证顺序与合并后的信息一致
                pass
            rec = existing
        self.update_seq += 1
        self.updates.append({"seq": self.update_seq, "record": rec, "source": source})
        if len(self.updates) > 8000:
            self.updates = self.updates[-5000:]

    def snapshot_results(self) -> list[dict[str, Any]]:
        return [self.results[rid] for rid in self.result_order if rid in self.results]

    def stats(self) -> dict[str, int]:
        return compute_stats(self.snapshot_results())

    def elapsed(self) -> float:
        if self.status == "running":
            return max(0.0, time.time() - self.started_ts)
        return self.duration

    def as_state(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "elapsed": round(self.elapsed(), 1),
            "stats": self.stats(),
            "summary": self.summary,
            "error": self.error,
            "exit_code": self.exit_code,
            "cmd": quote_cmd(self.args),
            "folder": str(self.folder),
        }


class ScanManager:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.session: ScanSession | None = None
        self.history: dict[str, ScanSession] = {}
        self.settings = store.load_settings()
        self.fscan_path: Path | None = paths.find_fscan(self.settings.get("fscan_path"))
        current = self.fscan_path
        needs_bundled = (
            current is None
            or not current.is_file()
            or (paths.is_frozen() and paths.app_dir() in current.parents)
        )
        if needs_bundled:
            installed = paths.install_bundled_fscan()
            if installed is not None:
                self.fscan_path = installed
        self.fscan_version = ""
        self.plugins: list[dict[str, Any]] = []
        self._probe_fscan()

    # ---- fscan detection ----
    def _probe_fscan(self) -> None:
        path = self.fscan_path
        if not path or not path.is_file():
            self.fscan_version = ""
            self.plugins = []
            return
        try:
            proc = subprocess.run(
                [str(path), "-list-plugins"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=20,
                creationflags=CREATE_NO_WINDOW,
            )
            text = proc.stdout.decode("utf-8", "replace")
            match = VERSION_RE.search(text)
            self.fscan_version = match.group(1) if match else ""
            plugins = []
            for line in text.splitlines():
                m = PLUGIN_RE.match(line.strip())
                if m:
                    plugins.append(
                        {
                            "name": m.group(1),
                            "type": m.group(2),
                            "ports": m.group(3).split()[0] if m.group(3).split() else "",
                        }
                    )
            self.plugins = plugins
        except Exception:
            self.fscan_version = ""
            self.plugins = []

    def set_fscan_path(self, value: str) -> dict[str, Any]:
        candidate = paths.find_fscan(value)
        if not candidate:
            raise ValueError("找不到 fscan 可执行文件：%s" % (value or "(空)"))
        self.fscan_path = candidate
        self.settings = store.save_settings({"fscan_path": str(candidate)})
        self._probe_fscan()
        return {
            "fscan_path": str(candidate),
            "fscan_version": self.fscan_version,
            "plugins": self.plugins,
        }

    def info(self) -> dict[str, Any]:
        return {
            "fscan_path": str(self.fscan_path) if self.fscan_path else "",
            "fscan_ok": bool(self.fscan_path and self.fscan_path.is_file()),
            "fscan_version": self.fscan_version,
            "plugins": self.plugins,
        }

    # ---- scan lifecycle ----
    def build_preview(self, cfg: dict[str, Any]) -> dict[str, Any]:
        if not self.fscan_path or not self.fscan_path.is_file():
            raise ValueError("未找到 fscan.exe，请先在设置里指定路径")
        folder = store.history_root() / "preview"
        args = build_args(cfg, str(self.fscan_path), folder / "result.json")
        return {"cmd": quote_cmd(args), "args": args}

    def start(self, cfg: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            if self.session and self.session.status == "running":
                raise ScanBusy("已有扫描任务正在运行")
            if not self.fscan_path or not self.fscan_path.is_file():
                raise ValueError("未找到 fscan.exe，请先在设置里指定路径")

            scan_id = time.strftime("%Y%m%d-%H%M%S") + "-" + hashlib.sha1(
                str(time.time_ns()).encode()
            ).hexdigest()[:4]
            folder = store.history_root() / scan_id
            folder.mkdir(parents=True, exist_ok=True)
            args = build_args(cfg, str(self.fscan_path), folder / "result.json")
            session = ScanSession(scan_id, cfg, args, folder)
            session._log_fh = open(session.console_path, "w", encoding="utf-8", errors="replace")
            try:
                proc = subprocess.Popen(
                    args,
                    cwd=str(folder),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    creationflags=CREATE_NO_WINDOW,
                )
            except Exception as exc:
                session._log_fh.close()
                session.status = "error"
                session.error = f"启动 fscan 失败: {exc}"
                raise ValueError(session.error)
            session.proc = proc
            self.session = session
            self.history[scan_id] = session

            t_stdout = threading.Thread(
                target=self._read_stdout, args=(session,), name="fscan-stdout", daemon=True
            )
            t_live = threading.Thread(
                target=self._read_realtime, args=(session,), name="fscan-live", daemon=True
            )
            t_wait = threading.Thread(
                target=self._wait_proc, args=(session,), name="fscan-wait", daemon=True
            )
            session._threads = [t_stdout, t_live, t_wait]
            t_stdout.start()
            t_live.start()
            t_wait.start()
            try:
                store.save_settings({"last_config": _public_cfg(cfg)})
            except Exception:
                pass
            return {
                "id": scan_id,
                "cmd": quote_cmd(args),
                "args": args,
                "started_at": session.started_at,
            }

    def _read_stdout(self, session: ScanSession) -> None:
        proc = session.proc
        if not proc or not proc.stdout:
            return
        stream = proc.stdout
        try:
            while True:
                raw = stream.readline()
                if not raw:
                    break
                text = raw.decode("utf-8", "replace")
                with self.lock:
                    session.add_log(text)
        except Exception:
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    def _read_realtime(self, session: ScanSession) -> None:
        path = session.folder / "result.json.realtime.tmp"
        offset = 0
        buf = b""
        while True:
            data = b""
            try:
                if path.exists():
                    with path.open("rb") as fh:
                        fh.seek(offset)
                        data = fh.read()
            except Exception:
                data = b""
            if data:
                offset += len(data)
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw = json.loads(line.decode("utf-8", "replace"))
                    except Exception:
                        continue
                    with self.lock:
                        session.add_result(raw, "live")
            if session._readers_stop.is_set():
                # 最后再读一次，避免漏掉尾部
                try:
                    with path.open("rb") as fh:
                        fh.seek(offset)
                        data = fh.read()
                except Exception:
                    data = b""
                if data:
                    offset += len(data)
                    buf += data
                    for line in buf.split(b"\n"):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            raw = json.loads(line.decode("utf-8", "replace"))
                        except Exception:
                            continue
                        with self.lock:
                            session.add_result(raw, "live")
                break
            time.sleep(0.25)

    def _wait_proc(self, session: ScanSession) -> None:
        proc = session.proc
        code = None
        if proc is not None:
            try:
                code = proc.wait()
            except Exception:
                code = None
        session.exit_code = code
        time.sleep(0.15)
        session._readers_stop.set()
        for thread in session._threads:
            if thread.name != "fscan-wait" and thread.is_alive():
                thread.join(timeout=3)
        with self.lock:
            if session.ended_at is None:
                session.ended_at = now_iso()
                session.duration = round(max(0.0, time.time() - session.started_ts), 1)
            if session.stop_requested:
                session.status = "stopped"
            elif code == 0:
                session.status = "done"
            else:
                session.status = "error"
                session.error = f"fscan 退出码 {code}"
            self._finalize(session)

    def _finalize(self, session: ScanSession) -> None:
        final = None
        try:
            text = session.result_path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(text)
            if isinstance(data, dict):
                final = data
        except Exception:
            final = None

        if final:
            session._final_json = final
            summary = final.get("summary") if isinstance(final.get("summary"), dict) else None
            if summary:
                session.summary = {
                    "total_hosts": int(summary.get("total_hosts") or 0),
                    "total_ports": int(summary.get("total_ports") or 0),
                    "total_services": int(summary.get("total_services") or 0),
                    "total_vulns": int(summary.get("total_vulns") or 0),
                }
            records: list[dict[str, Any]] = []
            for key in ("hosts", "ports", "services", "vulns"):
                for raw in final.get(key) or []:
                    if isinstance(raw, dict):
                        records.append(raw)
            if records:
                session.results = {}
                session.result_order = []
                for raw in records:
                    rec = normalize_result(raw)
                    if not rec:
                        continue
                    session.results[rec["id"]] = rec
                    session.result_order.append(rec["id"])
        stats = session.stats()
        session.summary.setdefault(
            "total_hosts", stats["alive"] if stats["alive"] else stats["hosts"]
        )
        session.summary.setdefault("total_ports", stats["ports"])
        session.summary.setdefault("total_services", stats["services"])
        session.summary.setdefault("total_vulns", stats["vulns"])

        try:
            if session._log_fh is not None:
                session._log_fh.flush()
                session._log_fh.close()
                session._log_fh = None
        except Exception:
            pass

        result_json = session._final_json or {
            "scan_time": session.ended_at,
            "summary": session.summary,
            "hosts": [r for r in session.snapshot_results() if r["type"] == "HOST"],
            "ports": [r for r in session.snapshot_results() if r["type"] == "PORT"],
            "services": [r for r in session.snapshot_results() if r["type"] == "SERVICE"],
            "vulns": [r for r in session.snapshot_results() if r["type"] == "VULN"],
        }

        target_lines = [
            line.strip()
            for line in str(session.cfg.get("target") or "").splitlines()
            if line.strip()
        ]
        target_short = target_lines[0] if target_lines else str(session.cfg.get("target_file") or "")
        if len(target_lines) > 1:
            target_short += f"  +{len(target_lines) - 1}"

        meta = {
            "id": session.id,
            "label": str(session.cfg.get("label") or ""),
            "target": target_short,
            "mode": str(session.cfg.get("mode") or "all"),
            "cfg": _public_cfg(session.cfg),
            "args": quote_cmd(session.args),
            "started_at": session.started_at,
            "ended_at": session.ended_at,
            "duration": session.duration,
            "status": session.status,
            "stats": stats,
            "summary": session.summary,
            "fscan_version": self.fscan_version,
            "exit_code": session.exit_code,
            "error": session.error,
        }
        try:
            console_text = session.console_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            console_text = "\n".join(item["text"] for item in session.logs)
        try:
            store.save_history(
                session.id, meta, result_json, console_text, quote_cmd(session.args)
            )
        except Exception:
            pass

    # ---- querying ----
    def stop(self) -> bool:
        with self.lock:
            session = self.session
            if not session or session.status != "running" or not session.proc:
                return False
            session.stop_requested = True
            try:
                session.proc.terminate()
            except Exception:
                return False
            return True

    def current_state(self) -> dict[str, Any] | None:
        with self.lock:
            if not self.session:
                return None
            state = self.session.as_state()
            state["logs_total"] = self.session.log_seq
            state["results_total"] = len(self.session.results)
            return state

    def poll(self, scan_id: str, log_cursor: int, result_cursor: int) -> dict[str, Any] | None:
        with self.lock:
            session = self.session if self.session and self.session.id == scan_id else None
            if session is None:
                session = self.history.get(scan_id)
            if session is None:
                return None
            logs = [item for item in session.logs if item["seq"] > log_cursor]
            updates = [item for item in session.updates if item["seq"] > result_cursor]
            payload: dict[str, Any] = {
                "id": session.id,
                "status": session.status,
                "started_at": session.started_at,
                "ended_at": session.ended_at,
                "elapsed": round(session.elapsed(), 1),
                "stats": session.stats(),
                "summary": session.summary,
                "error": session.error,
                "logs": logs,
                "next_log": session.log_seq,
                "results": [item["record"] for item in updates],
                "next_result": session.update_seq,
                "final": session.status != "running",
            }
            if session.status != "running":
                payload["all_results"] = session.snapshot_results()
                payload["cmd"] = quote_cmd(session.args)
            return payload

    def get_result(self, scan_id: str) -> dict[str, Any] | None:
        with self.lock:
            session = self.session if self.session and self.session.id == scan_id else None
            if session is None:
                session = self.history.get(scan_id)
            if session is not None:
                return {
                    "id": session.id,
                    "status": session.status,
                    "stats": session.stats(),
                    "summary": session.summary,
                    "results": session.snapshot_results(),
                    "cmd": quote_cmd(session.args),
                    "started_at": session.started_at,
                    "ended_at": session.ended_at,
                    "error": session.error,
                }
        stored = store.load_history(scan_id)
        if not stored:
            return None
        result = stored.get("result") or {}
        records: list[dict[str, Any]] = []
        for key in ("hosts", "ports", "services", "vulns"):
            for raw in result.get(key) or []:
                if isinstance(raw, dict):
                    rec = normalize_result(raw)
                    if rec:
                        records.append(rec)
        meta = stored.get("meta") or {}
        return {
            "id": scan_id,
            "status": meta.get("status", "done"),
            "stats": compute_stats(records),
            "summary": meta.get("summary") or {},
            "results": records,
            "cmd": meta.get("args", ""),
            "started_at": meta.get("started_at"),
            "ended_at": meta.get("ended_at"),
            "error": meta.get("error", ""),
        }


def _public_cfg(cfg: dict[str, Any]) -> dict[str, Any]:
    keys = [
        "target",
        "target_file",
        "exclude",
        "exclude_file",
        "mode",
        "plugins",
        "ports_preset",
        "ports",
        "threads",
        "timeout",
        "wt",
        "poc_num",
        "rate",
        "retry",
        "brute",
        "poc",
        "redis",
        "no_ping",
        "user",
        "password",
        "user_file",
        "pass_file",
        "hash",
        "ssh_key",
        "proxy",
        "socks5",
        "iface",
        "custom_args",
        "lang",
        "label",
    ]
    return {k: cfg.get(k) for k in keys if k in cfg}
