#!/usr/bin/env python3
"""Serve the storage report with a guarded one-click delete API (macOS + Windows).

Starts on 127.0.0.1 + a random port + a random per-session token, serves the
interactive report, and exposes POST /action to move green-tier paths to Trash
or delete them outright. Stop with Ctrl+C.

Usage:
    server.py <analysis.json>

SAFETY MODEL — read before changing:
- Allowlist: only paths listed in this report's green items `trash_paths` are
  accepted. Every request path is realpath-resolved and must be in the allowlist
  AND under $HOME. Anything else is rejected. This is the core guard — the
  endpoint cannot be used to delete arbitrary files.
- One deliberate exception: mode "open" (non-destructive, reveals the folder in
  Finder/Explorer) additionally allows /Applications on macOS and the two
  Program Files roots and local fixed volumes on Windows, because whole-machine
  reports include applications and data outside $HOME.
  The rm/trash allowlists never gain those roots.
- Bound to 127.0.0.1 only; every POST requires the session token; Host header
  must be 127.0.0.1 (blocks DNS-rebinding from a malicious page).
- Two modes: "trash" (Finder -> Trash, reversible) and "rm" (immediate,
  irreversible). The browser confirms each action before sending.
"""
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from report_html import render_report

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "..", "assets", "report_template.html")
HOME = os.path.realpath(os.path.expanduser("~"))
TOKEN = secrets.token_urlsafe(24)

DATA = {}
TPL = ""
DATA_SOURCE = None
DATA_MTIME = None
DATA_DIGEST = ""
RM_ALLOW = set()
TRASH_ALLOW = set()
OPEN_ALLOW = set()
ACTIVE_DELETIONS = set()
DELETION_LOCK = threading.Lock()
STALE_REPORT = "分析文件已更新或无法读取，请重新运行 server.py 打开报告。"


class OperationCancelled(OSError):
    """The OS cancelled an operation; earlier paths may already be processed."""


def expand(p):
    return os.path.realpath(os.path.expanduser(p))


def local_urlopen(url, timeout=2):
    """Never route local heartbeat traffic or its URL through an HTTP proxy."""
    import urllib.parse
    import urllib.request
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'http' or parsed.hostname not in ('127.0.0.1', 'localhost') or parsed.username or parsed.password:
        raise ValueError('Heartbeat URL must be a local HTTP service')
    return urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=timeout)


def read_source(src):
    with open(src, "rb") as f:
        mtime = os.fstat(f.fileno()).st_mtime_ns
        source = f.read()
        if os.fstat(f.fileno()).st_mtime_ns != mtime:
            raise OSError("读取过程中分析文件已更新")
    return source, mtime


def load(src):
    global DATA, TPL, DATA_SOURCE, DATA_MTIME, DATA_DIGEST
    global RM_ALLOW, TRASH_ALLOW, OPEN_ALLOW
    src = os.path.abspath(src)
    source, mtime = read_source(src)
    data = json.loads(source.decode("utf-8"))
    with open(TEMPLATE, encoding="utf-8") as f:
        tpl = f.read()
    # 三套白名单，权限从严到宽：
    #   rm    = 仅绿灯 trash_paths（可直接删的纯缓存）
    #   trash = 绿灯 + 橙灯 trash_paths（橙灯只准移废纸篓，不准直接删）
    #   open  = trash 全集 + 橙灯 path + 红灯 app_paths（仅"在文件管理器打开"，非破坏性）
    rm_allow, trash_allow, open_allow = set(), set(), set()
    for it in data.get("green", []):
        for p in (it.get("trash_paths") or []):
            rp = expand(p)
            rm_allow.add(rp); trash_allow.add(rp); open_allow.add(rp)
    for it in data.get("yellow", []):
        for p in (it.get("trash_paths") or []):
            rp = expand(p)
            trash_allow.add(rp); open_allow.add(rp)
        if it.get("path"):
            rp = expand(it["path"])
            if os.path.exists(rp):
                open_allow.add(rp)
    # 红灯只允许"打开"（应用本体在 /Applications 或 Program Files，
    # 删除让用户在访达/资源管理器里自己走正规卸载）
    for it in data.get("red", []):
        for p in (it.get("app_paths") or []):
            rp = expand(p)
            if os.path.exists(rp):
                open_allow.add(rp)
    DATA, TPL = data, tpl
    RM_ALLOW, TRASH_ALLOW, OPEN_ALLOW = rm_allow, trash_allow, open_allow
    DATA_SOURCE, DATA_MTIME, DATA_DIGEST = src, mtime, hashlib.sha256(source).hexdigest()


def source_matches():
    try:
        source, mtime = read_source(DATA_SOURCE)
    except OSError:
        return False
    return mtime == DATA_MTIME and hashlib.sha256(source).hexdigest() == DATA_DIGEST


def reusable_report(url):
    with local_urlopen(url + "heartbeat", timeout=2) as resp:
        info = json.load(resp)
    return (info.get("ok") and info.get("mtime_ns") == DATA_MTIME
            and info.get("digest") == DATA_DIGEST and source_matches())


def paths_overlap(path, other):
    return (path == other or path.startswith(other.rstrip(os.sep) + os.sep)
            or other.startswith(path.rstrip(os.sep) + os.sep))


def move_to_trash(path):
    if sys.platform == "darwin":
        _trash_macos(path)
    elif sys.platform.startswith("win"):
        _trash_windows(path)
    else:
        raise OSError("移到废纸篓仅支持 macOS / Windows")


def _trash_macos(path):
    # osascript Finder delete -> macOS Trash, recoverable. First run may prompt
    # for Finder automation permission. Never bypass cancellation with a move.
    script = 'tell application "Finder" to delete (POSIX file %s as alias)' % json.dumps(path)
    r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
    if r.returncode != 0:
        if '-128' in r.stderr:
            raise OperationCancelled('废纸篓操作已取消，请检查原路径')
        raise OSError((r.stderr or 'Finder 废纸篓操作失败').strip())


def _trash_windows(path):
    # Send to Recycle Bin via SHFileOperationW with FOF_ALLOWUNDO (stdlib ctypes).
    # Verified on a real Windows 11 machine: both single files and whole
    # directories land in the Recycle Bin and stay restorable.
    import ctypes
    from ctypes import wintypes

    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("wFunc", wintypes.UINT),
            ("pFrom", wintypes.LPCWSTR),
            ("pTo", wintypes.LPCWSTR),
            ("fFlags", ctypes.c_uint16),
            ("fAnyOperationsAborted", wintypes.BOOL),
            ("hNameMappings", ctypes.c_void_p),
            ("lpszProgressTitle", wintypes.LPCWSTR),
        ]

    FO_DELETE = 3
    FOF_ALLOWUNDO = 0x0040
    FOF_NOCONFIRMATION = 0x0010
    FOF_SILENT = 0x0004
    op = SHFILEOPSTRUCTW()
    op.wFunc = FO_DELETE
    op.pFrom = os.path.abspath(path) + "\x00\x00"  # double-null terminated list
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT
    rc = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
    if op.fAnyOperationsAborted:
        raise OperationCancelled("回收站操作已取消或未完成，请检查原路径后重试")
    if rc != 0:
        raise OSError("SHFileOperation failed (code %d)" % rc)


def hard_delete(path):
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    else:
        os.remove(path)


def open_in_file_manager(path):
    # 非破坏性：在访达 / 资源管理器里打开该位置，方便用户自己审查删除
    target = path if os.path.isdir(path) else os.path.dirname(path)
    if sys.platform == "darwin":
        # .app 是 bundle，对它用 open 会"启动应用"而非显示；必须用 open -R 在访达里选中。
        if target.rstrip("/").endswith(".app"):
            r = subprocess.run(["open", "-R", target], capture_output=True, text=True)
            if r.returncode != 0:
                raise OSError((r.stderr or "open -R 失败").strip())
            return
        # 普通文件夹：先试直接打开看内容；沙盒容器（如微信）open 会报 -10814，
        # 退回 open -R 在父目录里选中它。两者都失败才算错。
        r = subprocess.run(["open", target], capture_output=True, text=True)
        if r.returncode != 0:
            r2 = subprocess.run(["open", "-R", target], capture_output=True, text=True)
            if r2.returncode != 0:
                raise OSError((r.stderr or r2.stderr or "open 失败").strip())
    elif sys.platform.startswith("win"):
        subprocess.run(["explorer", target])  # explorer 退出码不可靠，不据此判成败
    else:
        raise OSError("打开文件夹仅支持 macOS / Windows")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        b = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/heartbeat":
            fresh = source_matches()
            self._send(200 if fresh else 409,
                       json.dumps({"ok": fresh, "mtime": DATA_MTIME // 10**9,
                                   "mtime_ns": DATA_MTIME, "digest": DATA_DIGEST}))
        elif self.path in ("/", "/index.html"):
            if not source_matches():
                self._send(409, STALE_REPORT, "text/plain; charset=utf-8")
                return
            html = render_report(TPL, DATA, {"token": TOKEN, "endpoint": "/action"})
            self._send(200, html, "text/html; charset=utf-8")
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        if self.path != "/action":
            self._send(404, json.dumps({"ok": False, "error": "not found"}))
            return
        # DNS-rebinding guard: only accept local Host
        host = (self.headers.get("Host") or "").split(":")[0]
        if host not in ("127.0.0.1", "localhost"):
            self._send(403, json.dumps({"ok": False, "error": "host 不被允许"}))
            return
        try:
            n = int(self.headers.get("Content-Length", 0))
            if not 0 < n <= 1024 * 1024:
                raise ValueError('invalid request size')
        except ValueError:
            self._send(400, json.dumps({"ok": False, "error": "请求长度无效"}))
            return
        try:
            req = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            self._send(400, json.dumps({"ok": False, "error": "请求格式错误"}))
            return
        if not isinstance(req, dict):
            self._send(400, json.dumps({"ok": False, "error": "请求必须是对象"}))
            return
        if req.get("token") != TOKEN:
            self._send(403, json.dumps({"ok": False, "error": "token 校验失败"}))
            return
        mode = req.get("mode")
        allow = {"rm": RM_ALLOW, "trash": TRASH_ALLOW, "open": OPEN_ALLOW}.get(mode)
        if allow is None:
            self._send(400, json.dumps({"ok": False, "error": "未知操作"}))
            return
        paths = req.get("paths")
        if not isinstance(paths, list) or not paths or any(not isinstance(p, str) or not p for p in paths):
            self._send(400, json.dumps({"ok": False, "error": "paths 必须是非空路径数组"}))
            return
        # Validate the ENTIRE batch before changing anything. An invalid second
        # path must not leave the first path deleted behind a 403 response.
        checked = []
        for p in paths:
            rp = expand(p)
            if rp not in allow:
                self._send(403, json.dumps({"ok": False, "error": "路径不在白名单：%s" % p}))
                return
            # 二级护栏：rm/trash 只允许用户目录；"打开"（非破坏性）额外放行应用本体所在目录
            roots = (HOME,)
            if mode == "open":
                roots += ("/Applications",)
                if sys.platform.startswith("win"):
                    # Windows 红灯 app_paths 指向 Program Files（应用本体不在 HOME），
                    # 仅在 open 下放行两个 Program Files，rm/trash 依旧够不到
                    roots += (os.environ.get("ProgramFiles", r"C:\Program Files"),
                              os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
                    # Full-machine reports include data on other fixed volumes.
                    # This extends OPEN only; destructive modes stay HOME-only.
                    from scan_windows_full import fixed_drives
                    roots += tuple(fixed_drives())
            if not any(rp == base or rp.startswith(base.rstrip(os.sep) + os.sep) for base in roots):
                self._send(403, json.dumps({"ok": False, "error": "路径越界：%s" % p}))
                return
            if mode != "open" and rp == HOME:
                self._send(403, json.dumps({"ok": False, "error": "禁止删除用户目录根路径"}))
                return
            checked.append((p, rp))
        # One parent plus its descendant is not two independent operations.
        if mode != 'open':
            for i, (_, rp) in enumerate(checked):
                if any(paths_overlap(rp, other) for _, other in checked[:i]):
                    self._send(400, json.dumps({'ok': False, 'error': '目标路径重复或父子重叠，请分别审查后操作'}))
                    return
        if not source_matches():
            self._send(409, json.dumps({"ok": False, "error": STALE_REPORT}))
            return
        if mode == "open":
            self._apply_actions(checked, mode)
            return
        # Different cards may run concurrently, but an overlapping destructive
        # request must stop before starting any path in its batch.
        targets = {os.path.normcase(rp) for _, rp in checked}
        with DELETION_LOCK:
            conflict = any(paths_overlap(path, active)
                           for path in targets for active in ACTIVE_DELETIONS)
            if not conflict:
                ACTIVE_DELETIONS.update(targets)
        if conflict:
            self._send(409, json.dumps({"ok": False, "error": "有重叠目标正在处理，请先查看当前操作结果。"}))
            return
        try:
            self._apply_actions(checked, mode)
        finally:
            with DELETION_LOCK:
                ACTIVE_DELETIONS.difference_update(targets)

    def _apply_actions(self, checked, mode):
        done, results = [], []
        for index, (p, rp) in enumerate(checked):
            try:
                outcome = 'completed'
                if mode == "open":
                    if not os.path.exists(rp):
                        raise FileNotFoundError('目标路径已不存在：' + p)
                    open_in_file_manager(rp)
                    outcome = 'submitted'
                elif not os.path.exists(rp):
                    outcome = 'already_missing'
                elif mode == "trash":
                    move_to_trash(rp)
                else:
                    hard_delete(rp)
                if mode != 'open' and os.path.lexists(rp):
                    raise OSError('操作返回后目标仍存在，请检查实际内容；目录可能已部分处理')
                done.append(p)
                results.append({'path': p, 'status': outcome})
            except Exception as e:
                status = 'cancelled' if isinstance(e, OperationCancelled) else 'failed'
                results.append({'path': p, 'status': status, 'error': str(e)})
                results.extend({'path': pending, 'status': 'not_attempted'} for pending, _ in checked[index+1:])
                self._send(500, json.dumps({"ok": False, "status": 'partial' if done else status,
                                           "error": str(e), "done": done, "failed": p, "results": results}))
                return
        self._send(200, json.dumps({"ok": True, "done": done, "status": 'submitted' if mode == 'open' else 'completed',
                                   "results": results}))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    load(sys.argv[1])
    # 单实例：同一份分析 JSON 已有存活实例时直接复用，避免多标签页指向死端口
    url_file = os.path.splitext(os.path.abspath(sys.argv[1]))[0] + ".server-url.txt"
    if os.path.exists(url_file):
        try:
            with open(url_file, encoding="utf-8") as f:
                prev = f.read().strip()
            if reusable_report(prev):
                print("已有实例在服务同一份分析：" + prev + "（复用，不再新起）", flush=True)
                webbrowser.open(prev)
                return
        except Exception:
            pass  # 旧地址已死或文件过期 -> 正常起新实例
    if not source_matches():
        load(sys.argv[1])
        if not source_matches():
            sys.exit(STALE_REPORT)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    url = "http://127.0.0.1:%d/" % port
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print("报告服务已启动：" + url, flush=True)
    print("绿灯可删 %d 项 | 橙灯可移废纸篓/打开文件夹 %d 项 | 页面上点" % (len(RM_ALLOW), len(TRASH_ALLOW) - len(RM_ALLOW)), flush=True)
    print("用完按 Ctrl+C 停止服务（服务关掉后按钮即失效）", flush=True)
    # Deterministic URL handoff for detached launches (agent contexts): the
    # report URL lands next to the analysis JSON regardless of stdout buffering.
    try:
        with open(os.path.splitext(os.path.abspath(sys.argv[1]))[0] + ".server-url.txt",
                  "w", encoding="utf-8") as f:
            f.write(url + "\n")
    except OSError:
        pass
    # 线程内未捕获异常落盘（ThreadingHTTPServer 默认只打到 stderr，agent 后台拉起时看不到）
    crash_log = os.path.splitext(os.path.abspath(sys.argv[1]))[0] + ".server-crash.log"
    def _thread_hook(a):
        try:
            with open(crash_log, "a", encoding="utf-8") as f:
                f.write(time.strftime("[%Y-%m-%d %H:%M:%S] ") + repr(a.exc_type) + ": " + str(a.exc_value) + "\n")
        except Exception:
            pass
    threading.excepthook = _thread_hook
    webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止服务。")


if __name__ == "__main__":
    main()
