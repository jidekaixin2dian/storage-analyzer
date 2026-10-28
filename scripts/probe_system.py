#!/usr/bin/env python3
"""Windows system-space probe (read-only) with optional elevated analysis.

Phase 1 (no administrator rights): measures the system-level space that the
regular scan leaves in the blue "system and other" bucket - component store
(WinSxS), Installer cache, DriverStore, recovery partition, hibernation file,
page file, Windows.old leftovers, update caches, crash dumps, logs, Prefetch.

Phase 2 (only when already elevated): runs DISM component-store analysis plus
reagentc / vssadmin / powercfg and returns machine-readable results. It never
cleans anything.

STRICTLY READ-ONLY: file metadata and read-only system queries only. Nothing
here creates, moves or deletes user data.

CLI
    probe_system.py [--json OUT] [--no-driver-usage]
        Phase 1 probe, print (or write) JSON.

    probe_system.py --elevate --json OUT
        Re-launch this script through UAC (Start-Process -Verb RunAs) and wait
        for the elevated child to write OUT. Returns 2 if UAC was cancelled.

    probe_system.py --elevated --json OUT
        Phase 2 analysis; must already be running elevated.

    probe_system.py --merge ANALYSIS_JSON --with ELEVATED_JSON
        Merge the elevated result into an analysis JSON (atomic replace).
"""
import argparse
import json
import locale
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

try:
    from scan_windows_full import api_path
except Exception:  # standalone use from another cwd
    def api_path(path):
        return path

IS_WINDOWS = os.name == "nt"
WINDIR = os.environ.get("SystemRoot", r"C:\Windows")
SYSTEM_DRIVE = (os.path.splitdrive(WINDIR)[0] or "C:") + "\\"
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

OEM_INF = re.compile(r"\boem\d+\.inf\b", re.I)
SIZE_VALUE = re.compile(
    r"([0-9]+(?:[.,][0-9]+)?)\s*(TB|GB|MB|KB|bytes?|字节|B)\b", re.I)


# ----------------------------------------------------------------------
# small helpers
# ----------------------------------------------------------------------
def format_size(num_bytes):
    """Bytes -> '11.98 GB' (1024 based, same units as the report)."""
    n = float(num_bytes or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(n)} B"
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{num_bytes} B"


def _decode(raw):
    """Decode console output. DISM may emit UTF-16; Chinese consoles use GBK."""
    if not raw:
        return ""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace")
    if raw.count(b"\x00") > max(8, len(raw) // 4):
        try:
            return raw.decode("utf-16-le", "replace")
        except UnicodeDecodeError:
            pass
    encodings = ["utf-8", locale.getpreferredencoding(False) or "utf-8", "gb18030"]
    for enc in encodings:
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


def is_elevated():
    if not IS_WINDOWS:
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_detail(args, timeout=300):
    """Run a console tool; return (decoded_text, exit_code) or (None, None)."""
    try:
        proc = subprocess.run(args, capture_output=True, timeout=timeout,
                              creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return None, None
    text = _decode((proc.stdout or b"") + b"\n" + (proc.stderr or b""))
    return text, proc.returncode


def _run(args, timeout=300):
    text, _ = _run_detail(args, timeout=timeout)
    return text


def _stat_path(path):
    """Measure one file or directory without following links. Read-only."""
    try:
        st = os.stat(api_path(path), follow_symlinks=False)
    except OSError:
        return {"present": False, "size_bytes": 0, "files": 0, "denied": 0,
                "skipped_reparse": 0}
    attrs = getattr(st, "st_file_attributes", 0)
    if stat.S_ISLNK(st.st_mode) or attrs & 0x400:
        return {"present": True, "size_bytes": 0, "files": 0, "denied": 0,
                "skipped_reparse": 1}
    if stat.S_ISREG(st.st_mode):
        return {"present": True, "size_bytes": st.st_size, "files": 1,
                "denied": 0, "skipped_reparse": 0}
    if not stat.S_ISDIR(st.st_mode):
        return {"present": True, "size_bytes": 0, "files": 0, "denied": 0,
                "skipped_reparse": 1}

    total = files = denied = skipped = 0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(api_path(current)) as entries:
                for entry in entries:
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        denied += 1
                        continue
                    entry_attrs = getattr(info, "st_file_attributes", 0)
                    if stat.S_ISLNK(info.st_mode) or entry_attrs & 0x400:
                        skipped += 1
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        stack.append(entry.path)
                    elif stat.S_ISREG(info.st_mode):
                        files += 1
                        total += info.st_size
        except OSError:
            denied += 1
    return {"present": True, "size_bytes": total, "files": files,
            "denied": denied, "skipped_reparse": skipped}


def _combine(paths):
    """Measure several paths as one item (missing ones are ignored)."""
    result = {"present": False, "size_bytes": 0, "files": 0, "denied": 0,
              "skipped_reparse": 0, "existing": []}
    for path in paths:
        one = _stat_path(path)
        if one["present"]:
            result["present"] = True
            result["existing"].append(path)
        for key in ("size_bytes", "files", "denied", "skipped_reparse"):
            result[key] += one[key]
    return result


# ----------------------------------------------------------------------
# Phase 1: parsers for the read-only system tools
# ----------------------------------------------------------------------
def parse_pnputil_infs(text):
    """Return the sorted set of oem*.inf names mentioned by pnputil."""
    return sorted({m.group(0).lower() for m in OEM_INF.finditer(text or "")})


def parse_recovery_partitions(text):
    """Parse 'disk|partition|size' lines emitted by our PowerShell snippet."""
    parts = []
    for line in (text or "").splitlines():
        fields = line.strip().split("|")
        if len(fields) != 3:
            continue
        try:
            parts.append({"disk": int(fields[0]), "partition": int(fields[1]),
                          "size_bytes": int(fields[2])})
        except ValueError:
            continue
    return parts


def driver_usage():
    """Count third-party driver packages and which ones match a device."""
    all_text = _run(["pnputil.exe", "/enum-drivers"], timeout=120)
    dev_text = _run(["pnputil.exe", "/enum-devices", "/drivers"], timeout=300)
    if all_text is None:
        return {"available": False, "reason": "pnputil /enum-drivers failed"}
    all_infs = parse_pnputil_infs(all_text)
    used = parse_pnputil_infs(dev_text) if dev_text is not None else None
    if used is None:
        return {"available": True, "partial": True, "oem_total": len(all_infs),
                "reason": "pnputil /enum-devices failed; usage unknown"}
    used_set = set(used) & set(all_infs)
    return {
        "available": True,
        "partial": False,
        "oem_total": len(all_infs),
        "oem_in_use": len(used_set),
        "oem_unmatched": len(set(all_infs) - used_set),
        "unmatched_sample": sorted(set(all_infs) - used_set)[:10],
    }


def recovery_partitions():
    if not IS_WINDOWS:
        return {"available": False, "partitions": []}
    script = (
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
        "Get-Partition -ErrorAction SilentlyContinue | "
        "Where-Object { $_.GptType -eq '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}' } | "
        "ForEach-Object { '{0}|{1}|{2}' -f $_.DiskNumber,$_.PartitionNumber,$_.Size }"
    )
    text = _run(["powershell.exe", "-NoProfile", "-NonInteractive",
                 "-Command", script], timeout=30)
    if text is None:
        return {"available": False, "partitions": []}
    parts = parse_recovery_partitions(text)
    return {"available": True, "partitions": parts,
            "total_bytes": sum(p["size_bytes"] for p in parts)}


# ----------------------------------------------------------------------
# Phase 2 parsers
# ----------------------------------------------------------------------
DISMLABELS = {
    "explorer": ("Windows Explorer Reported Size of Component Store",
                 "Windows 资源管理器报告的组件存储大小",
                 "资源管理器报告的组件存储大小"),
    "actual": ("Actual Size of Component Store", "组件存储的实际大小"),
    "shared": ("Shared with Windows", "与 Windows 共享"),
    "backups": ("Backups and Disabled Features", "备份和禁用的功能",
                "备份和已禁用的功能"),
    "cache": ("Cache and Temporary Data", "缓存和临时数据"),
    "reclaimable": ("Number of Reclaimable Packages", "可回收程序包数",
                    "可回收的程序包数"),
    "recommended": ("Component Store Cleanup Recommended", "建议进行组件存储清理",
                    "建议清理组件存储", "推荐使用组件存储清理"),
}
YES_WORDS = ("yes", "true", "是")
NO_WORDS = ("no", "false", "否")


def _parse_size_token(value):
    match = SIZE_VALUE.search(value or "")
    if not match:
        return None
    number = match.group(1).replace(",", ".")
    unit = match.group(2).upper()
    if unit in ("BYTE", "BYTES", "字节"):
        unit = "B"
    try:
        amount = float(number)
    except ValueError:
        return None
    factor = {"B": 1, "KB": 1024, "MB": 1024 ** 2,
              "GB": 1024 ** 3, "TB": 1024 ** 4}[unit]
    total = int(amount * factor)
    return {"bytes": total, "text": format_size(total)}


def parse_dism_component_store(text):
    """Parse analyzecomponentstore output (zh-CN / en-US labels)."""
    parsed = {key: None for key in DISMLABELS}
    parsed["available"] = False
    for raw_line in (text or "").splitlines():
        line = raw_line.strip().lstrip("-").strip()
        if ":" not in line and "：" not in line:
            continue
        label, value = re.split(r"[:：]", line, maxsplit=1)
        label_low = label.strip().lower()
        for key, names in DISMLABELS.items():
            if parsed[key] is not None:
                continue
            if not any(name.lower() in label_low for name in names):
                continue
            if key == "recommended":
                low = value.strip().lower()
                if any(word in low for word in YES_WORDS):
                    parsed[key] = True
                elif any(word in low for word in NO_WORDS):
                    parsed[key] = False
            elif key == "reclaimable":
                digits = re.search(r"\d+", value or "")
                if digits:
                    parsed[key] = int(digits.group(0))
            else:
                size = _parse_size_token(value)
                if size:
                    parsed[key] = size["text"]
            break
    parsed["available"] = parsed["actual"] is not None
    return parsed


def parse_reagentc(text):
    result = {"available": False, "status": None, "enabled": None,
              "location": None}
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        low = line.lower()
        if "windows re" in low and ("status" in low or "状态" in line):
            value = line.split(":", 1)[-1].split("：", 1)[-1].strip().lower()
            result["status"] = value
            result["enabled"] = ("enabled" in value or "已启用" in value)
            result["available"] = True
        elif "location" in low or "位置" in line:
            value = line.split(":", 1)[-1].split("：", 1)[-1].strip()
            value = line.split(":", 1)[-1].split("：", 1)[-1].strip()
            if value:
                result["location"] = value
                result["available"] = True
    return result


def parse_shadow_storage(text):
    """Keep only the meaningful lines; sizes stay display strings."""
    lines = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("-"):
            continue
        low = line.lower()
        if ("shadow copy storage" in low or "卷影副本存储" in line or
                "最大" in line or "maximum" in low or "已用" in line or "used" in low):
            lines.append(line)
    return {"available": bool(lines), "lines": lines[:12]}


def elevated_analyze():
    """Phase 2. Requires an elevated token; runs read-only queries only."""
    if not IS_WINDOWS:
        return {"elevated": False, "error": "unsupported_platform"}
    if not is_elevated():
        return {"elevated": False, "error": "not_elevated"}
    result = {"elevated": True, "analyzed_at": time.strftime("%Y-%m-%d %H:%M:%S")}

    dism_text, dism_rc = _run_detail(
        [os.path.join(WINDIR, "System32", "Dism.exe"), "/Online",
         "/Cleanup-Image", "/AnalyzeComponentStore"], timeout=900)
    result["dism"] = {
        "exit_code": dism_rc,
        "parsed": parse_dism_component_store(dism_text),
        "raw_tail": (dism_text or "")[-4000:],
    }

    re_text, re_rc = _run_detail(
        [os.path.join(WINDIR, "System32", "reagentc.exe"), "/info"], timeout=60)
    result["reagentc"] = {"exit_code": re_rc, "parsed": parse_reagentc(re_text),
                          "raw_tail": (re_text or "")[-1500:]}

    vss_text, vss_rc = _run_detail(
        [os.path.join(WINDIR, "System32", "vssadmin.exe"), "list",
         "shadowstorage"], timeout=60)
    result["vss"] = {"exit_code": vss_rc,
                     "parsed": parse_shadow_storage(vss_text),
                     "raw_tail": (vss_text or "")[-1500:]}

    pwr_text, pwr_rc = _run_detail(
        [os.path.join(WINDIR, "System32", "powercfg.exe"), "/a"], timeout=60)
    result["powercfg"] = {"exit_code": pwr_rc, "raw_tail": (pwr_text or "")[-1500:]}
    return result


# ----------------------------------------------------------------------
# Phase 1: collect()
# ----------------------------------------------------------------------
RISK_LABELS = {"low": "低风险", "medium": "中风险", "high": "高风险"}


def _item(item_id, name, path, measured, kind, risk, brief, note,
          command=None, admin_required=True, link=None):
    entry = {
        "id": item_id,
        "name": name,
        "path": path,
        "present": bool(measured.get("present")),
        "size_bytes": int(measured.get("size_bytes") or 0),
        "size_h": format_size(measured.get("size_bytes") or 0),
        "files": int(measured.get("files") or 0),
        "kind": kind,
        "risk": risk,
        "risk_label": RISK_LABELS.get(risk, "未知"),
        "brief": brief,
        "note": note,
        "command": command,
        "admin_required": admin_required,
    }
    if measured.get("denied"):
        entry["denied"] = int(measured["denied"])
    if measured.get("skipped_reparse"):
        entry["skipped_reparse"] = int(measured["skipped_reparse"])
    if link:
        entry["link"] = link
    return entry


def collect(include_driver_usage=True):
    """Phase 1 read-only probe. Returns a JSON-serialisable dict."""
    started = time.time()
    if not IS_WINDOWS:
        return {"platform": sys.platform, "elevated": False, "items": [],
                "coverage": {"denied": 0, "skipped_reparse": 0,
                             "warnings": ["system-space probe is Windows-only"]},
                "seconds": 0}

    items = []
    usage = driver_usage() if include_driver_usage else {"available": False,
                                                          "reason": "disabled"}
    partitions = recovery_partitions()

    # 1. component store
    m = _stat_path(os.path.join(WINDIR, "WinSxS"))
    items.append(_item(
        "winsxs", "组件存储（WinSxS）", os.path.join(WINDIR, "WinSxS"), m,
        "system-store", "high",
        "系统更新历史与被取代组件的存放处；这里的大小是组件存储总量，不是可回收量。",
        "清理会移除被取代组件，可能失去卸载已装更新、修复系统组件的能力；"
        "按需运行 DISM 可核对实际大小、可回收包数量和清理建议，不能据此承诺精确可释放字节数。",
        command="dism /online /cleanup-image /analyzecomponentstore"))

    # 2. Installer cache
    m = _stat_path(os.path.join(WINDIR, "Installer"))
    items.append(_item(
        "installer", "Windows Installer 缓存", os.path.join(WINDIR, "Installer"), m,
        "installer-cache", "medium",
        "MSI/MSP 安装与修补缓存；孤立补丁需要专门工具按注册表核对，不能按文件名删。",
        "并非全可删：卸载/修复/更新现有程序仍可能引用这里的文件。"
        "本报告只报总量，不提供删除命令。"))

    # 3. DriverStore
    m = _stat_path(os.path.join(WINDIR, "System32", "DriverStore", "FileRepository"))
    driver_note = ("第三方驱动仓库。未匹配到当前设备的驱动包不等于可以删除："
                   "断开的设备、待安装设备仍可能引用。")
    if usage.get("available") and not usage.get("partial"):
        driver_note += (f" 本机检测到 {usage['oem_total']} 个 oem*.inf，"
                        f"其中 {usage['oem_in_use']} 个匹配当前设备，"
                        f"{usage['oem_unmatched']} 个未匹配。")
    items.append(_item(
        "driverstore", "驱动仓库（DriverStore）",
        os.path.join(WINDIR, "System32", "DriverStore", "FileRepository"), m,
        "driver-store", "medium",
        "已安装的第三方驱动包；旧版本驱动会累积。",
        driver_note,
        command="pnputil /enum-devices /drivers"))

    # 4. recovery partition (WinRE)
    recovery_total = partitions.get("total_bytes") or 0
    m = {"present": bool(partitions.get("partitions")),
         "size_bytes": recovery_total, "files": 0}
    items.append(_item(
        "recovery", "恢复分区（WinRE）", "GPT Recovery partition", m,
        "recovery", "medium",
        "Windows 恢复环境所在分区；用于启动修复、系统还原入口。",
        "禁用或缩小恢复环境会失去启动修复能力；是否可调整取决于分区布局，"
        "必须先运行 reagentc /info 确认。",
        command="reagentc /info"))

    # 5. hibernation
    m = _stat_path(os.path.join(SYSTEM_DRIVE, "hiberfil.sys"))
    items.append(_item(
        "hiberfil", "休眠文件（hiberfil.sys）",
        os.path.join(SYSTEM_DRIVE, "hiberfil.sys"), m,
        "hibernation", "medium",
        "休眠与快速启动使用的内存镜像。",
        ("当前未检测到休眠文件（休眠可能已关闭）。" if not m["present"] else
         "关闭休眠会同时关闭快速启动；笔记本会失去合盖休眠能力。"),
        command="powercfg /h off"))

    # 6. page file
    m = _combine([os.path.join(SYSTEM_DRIVE, "pagefile.sys"),
                  os.path.join(SYSTEM_DRIVE, "swapfile.sys")])
    items.append(_item(
        "pagefile", "页面文件 / 交换文件",
        "C:\\pagefile.sys / swapfile.sys", m,
        "pagefile", "high",
        "系统管理的虚拟内存与交换文件。",
        "不建议删除或手工缩小；大小由系统按内存压力管理，"
        "调整应在「系统属性 > 高级 > 性能」里做。", command=None,
        admin_required=True))

    # 7. Windows.old leftovers
    old_paths = [os.path.join(SYSTEM_DRIVE, "Windows.old"),
                 os.path.join(SYSTEM_DRIVE, "$Windows.~BT"),
                 os.path.join(SYSTEM_DRIVE, "$Windows.~WS")]
    m = _combine(old_paths)
    items.append(_item(
        "windows_old", "旧系统备份（Windows.old）",
        "C:\\Windows.old（及 $Windows.~BT / $Windows.~WS）", m,
        "upgrade-backup", "medium",
        "系统升级/回退留下的旧系统副本，通常 10–30 天自动删除。",
        "删除后无法回退到上一个 Windows 版本；保留期内可用「磁盘清理」"
        "或 设置 > 系统 > 存储 移除。", command="cleanmgr"))

    # 8. update caches
    m = _combine([os.path.join(WINDIR, "SoftwareDistribution", "Download"),
                  os.path.join(WINDIR, "SoftwareDistribution", "DeliveryOptimization")])
    items.append(_item(
        "update_cache", "Windows 更新与传递优化缓存",
        os.path.join(WINDIR, "SoftwareDistribution"), m,
        "update-cache", "medium",
        "更新安装包与 P2P 分发缓存；更新完成后多数可释放。",
        "直接删目录需要先停 wuauserv / DOSvc；更稳妥的是"
        "「磁盘清理」里的 Windows 更新清理。正在更新时不要动。",
        command="cleanmgr /sageset:1"))

    # 9. crash dumps and error reports
    m = _combine([
        os.path.join(WINDIR, "Minidump"),
        os.path.join(WINDIR, "LiveKernelReports"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "CrashDumps"),
        os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                     "Microsoft", "Windows", "WER"),
    ])
    items.append(_item(
        "crash_dumps", "崩溃转储与错误报告", "Minidump / WER / CrashDumps", m,
        "diagnostics", "low",
        "蓝屏转储、内核报告与应用崩溃记录。",
        "删除不影响系统运行；建议保留最近一次转储，排障时有用。",
        command=None))

    # 10. logs
    m = _combine([os.path.join(WINDIR, "Logs"),
                  os.path.join(WINDIR, "Panther")])
    items.append(_item(
        "logs", "系统日志与安装日志", os.path.join(WINDIR, "Logs"), m,
        "logs", "low",
        "CBS、Windows Update、安装程序留下的文本日志。",
        "可清理，但排障时需要它们；建议按时间保留最近一批。", command=None))

    # 11. Prefetch
    m = _stat_path(os.path.join(WINDIR, "Prefetch"))
    items.append(_item(
        "prefetch", "预读取缓存（Prefetch）", os.path.join(WINDIR, "Prefetch"), m,
        "cache", "low",
        "应用启动预读取数据，删除后系统会自动重建。",
        "清理收益通常很小；首次启动会略慢，不建议频繁清。", command=None))

    # 12. system temp
    m = _stat_path(os.path.join(WINDIR, "Temp"))
    items.append(_item(
        "windows_temp", "系统临时目录（Windows\\Temp）",
        os.path.join(WINDIR, "Temp"), m,
        "temp", "low",
        "安装器与服务留下的临时文件；部分文件可能正被占用。",
        "可清理，但正在运行的服务可能锁住文件；失败项保留即可，不要强删。",
        command=None))

    denied = sum(item.get("denied", 0) for item in items)
    skipped = sum(item.get("skipped_reparse", 0) for item in items)
    return {
        "platform": sys.platform,
        "elevated": is_elevated(),
        "probed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "system_drive": SYSTEM_DRIVE,
        "items": items,
        "driver_usage": usage,
        "recovery": partitions,
        "coverage": {"denied": denied, "skipped_reparse": skipped,
                     "warnings": []},
        "elevated_analysis": None,
        "seconds": round(time.time() - started, 1),
    }


# ----------------------------------------------------------------------
# Phase 2: UAC helper + merge
# ----------------------------------------------------------------------
def _ps_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def elevate_self(out_path, wait_seconds=1200):
    """Relaunch with UAC and wait for the elevated child to write out_path."""
    if not IS_WINDOWS:
        return {"ok": False, "error": "unsupported_platform"}
    if is_elevated():
        return {"ok": False, "error": "already_elevated",
                "hint": "run with --elevated instead"}
    out_path = os.path.abspath(out_path)
    if os.path.exists(out_path):
        return {"ok": False, "error": "output_exists",
                "hint": "choose a new --json path"}
    parent = os.path.dirname(out_path) or "."
    os.makedirs(parent, exist_ok=True)

    script_path = os.path.abspath(__file__)
    arg_array = "@(" + ",".join(_ps_quote(v) for v in
                                [script_path, "--elevated", "--json", out_path]) + ")"
    ps = (f"$p = Start-Process -FilePath {_ps_quote(sys.executable)} "
          f"-ArgumentList {arg_array} -Verb RunAs -Wait -PassThru; "
          f"exit $p.ExitCode")
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, timeout=wait_seconds,
            creationflags=CREATE_NO_WINDOW)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout"}
    except OSError as exc:
        return {"ok": False, "error": "launch_failed", "message": str(exc)}

    if not os.path.exists(out_path):
        detail = _decode((proc.stdout or b"") + (proc.stderr or b"")).strip()
        if proc.returncode != 0:
            return {"ok": False, "error": "uac_cancelled_or_failed",
                    "exit_code": proc.returncode,
                    "message": detail[-600:] or "UAC 被取消或提权失败"}
        return {"ok": False, "error": "no_output",
                "message": detail[-600:] or "提权进程未写出结果"}
    try:
        with open(out_path, encoding="utf-8") as stream:
            data = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": "unreadable_output", "message": str(exc)}
    return {"ok": True, "result": data}


def merge_into(analysis_path, elevated_path):
    """Inject the elevated result into system_space and update the WinSxS item."""
    with open(analysis_path, encoding="utf-8") as stream:
        analysis = json.load(stream)
    with open(elevated_path, encoding="utf-8") as stream:
        elevated = json.load(stream)
    if not isinstance(elevated, dict) or not elevated.get("elevated"):
        raise ValueError("elevated result is missing or not elevated")

    space = analysis.get("system_space")
    if not isinstance(space, dict):
        space = {"items": [], "elevated": False}
    space["elevated"] = True
    space["elevated_analysis"] = elevated
    dism = ((elevated.get("dism") or {}).get("parsed") or {})
    for item in space.get("items") or []:
        if item.get("id") != "winsxs":
            continue
        item["reclaim_known"] = bool(dism.get("actual"))
        if dism.get("actual"):
            item["reclaim"] = {
                "actual": dism.get("actual"),
                "shared": dism.get("shared"),
                "backups": dism.get("backups"),
                "cache": dism.get("cache"),
                "reclaimable_packages": dism.get("reclaimable"),
                "cleanup_recommended": dism.get("recommended"),
            }
            if dism.get("reclaimable") is not None:
                item["note"] += (f" DISM 分析：实际大小 {dism.get('actual')}，"
                                 f"可回收程序包 {dism.get('reclaimable')} 个。")
    analysis["system_space"] = space

    target_dir = os.path.dirname(os.path.abspath(analysis_path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".analysis-", suffix=".json",
                                    dir=target_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(analysis, stream, ensure_ascii=False, indent=2)
        os.replace(tmp_path, analysis_path)
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise
    return analysis


def _write_json(path, data):
    if not path:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return
    with open(path, "x", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", help="write result to a NEW UTF-8 JSON file")
    parser.add_argument("--elevated", action="store_true",
                        help="run Phase 2 analysis (must already be elevated)")
    parser.add_argument("--elevate", action="store_true",
                        help="relaunch through UAC and wait for the result")
    parser.add_argument("--no-driver-usage", action="store_true",
                        help="skip pnputil driver enumeration")
    parser.add_argument("--merge", help="analysis JSON to merge into")
    parser.add_argument("--with", dest="with_path",
                        help="elevated probe JSON used by --merge")
    args = parser.parse_args(argv)

    if args.merge:
        if not args.with_path:
            parser.error("--merge requires --with ELEVATED_JSON")
        try:
            merge_into(args.merge, args.with_path)
        except Exception as exc:
            print("merge failed: %s" % exc, file=sys.stderr)
            return 3
        print("merged: %s" % args.merge)
        return 0

    if args.elevate:
        if not args.json:
            parser.error("--elevate requires --json OUT")
        outcome = elevate_self(args.json)
        if outcome.get("ok"):
            print("elevated analysis written: %s" % args.json)
            return 0
        print(json.dumps(outcome, ensure_ascii=False), file=sys.stderr)
        return 2

    if args.elevated:
        result = elevated_analyze()
        if result.get("error") == "not_elevated":
            print(json.dumps(result, ensure_ascii=False), file=sys.stderr)
            return 2
        _write_json(args.json, result)
        return 0

    _write_json(args.json, collect(include_driver_usage=not args.no_driver_usage))
    return 0


if __name__ == "__main__":
    sys.exit(main())
