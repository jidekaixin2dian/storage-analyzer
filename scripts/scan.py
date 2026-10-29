#!/usr/bin/env python3
"""Read-only storage scanner (macOS + Windows).

Collects disk usage, system info, and per-directory size breakdowns for the
hot spots that typically eat disk, and emits one JSON blob to stdout for Claude
to interpret and classify. Auto-detects the OS and scans the right locations.

STRICTLY READ-ONLY: only sizes/lists/reads metadata. Never creates, moves, or
deletes anything.

Output shape (same on both OSes):
{
  "generated_at", "scan_seconds",
  "system": {os, build, arch, user, home, filesystem,
             disk_total, disk_used, disk_free, purgeable,
             disks: [{name, total, used, free}]},   # all volumes/drives
  "groups": { "<group>": [{name, path, size_kb, size_h}], ... },
  "system_space": {items: [...], elevated: bool, ...}   # Windows only, read-only
}
"""
import json
import os
import shutil
import sys
import time
from scan_windows_full import api_path

HOME = os.path.expanduser("~")


def human(kb):
    """KB number -> human string like '12.3 GB'."""
    n = float(kb) * 1024
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit not in ("B", "KB") else f"{int(n)} {unit}"
        n /= 1024


# ======================================================================
# macOS
# ======================================================================
import re
import subprocess


def run(cmd, timeout=180):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def du_children(path, min_kb=51200, limit=40):
    """Size every immediate child of `path` via du, sorted desc. macOS."""
    if not os.path.isdir(path):
        return []
    results = []
    try:
        entries = sorted(os.listdir(path))
    except PermissionError:
        return [{"name": "(permission denied)", "path": path,
                 "size_kb": 0, "size_h": "?", "denied": True}]
    for name in entries:
        if name in (".", ".."):
            continue
        child = os.path.join(path, name)
        if os.path.islink(child):
            continue
        out = run(["du", "-sk", child], timeout=120)
        m = re.match(r"\s*(\d+)", out)
        if not m:
            continue
        kb = int(m.group(1))
        if kb < min_kb:
            continue
        results.append({"name": name, "path": child, "size_kb": kb, "size_h": human(kb)})
    results.sort(key=lambda r: r["size_kb"], reverse=True)
    return results[:limit]


MAC_TARGETS = [
    ("home", HOME, 102400),
    ("library", os.path.join(HOME, "Library"), 51200),
    ("caches", os.path.join(HOME, "Library/Caches"), 51200),
    ("containers", os.path.join(HOME, "Library/Containers"), 51200),
    ("group_containers", os.path.join(HOME, "Library/Group Containers"), 51200),
    ("app_support", os.path.join(HOME, "Library/Application Support"), 51200),
    ("applications", "/Applications", 102400),
    ("downloads", os.path.join(HOME, "Downloads"), 51200),
    ("dev_caches", None, 51200),
]

MAC_DEV_CACHE_PATHS = [
    "~/Library/Caches/pip", "~/Library/Caches/uv", "~/.cache", "~/.cargo",
    "~/.npm", "~/.pnpm-store", "~/.gradle", "~/.m2",
    "~/Library/Developer/Xcode/DerivedData", "~/Library/Developer/CoreSimulator",
    "~/Library/Developer/Xcode/iOS DeviceSupport", "~/Library/pnpm",
    "~/go/pkg", "~/.docker",
]


def dev_caches_macos():
    results = []
    for p in MAC_DEV_CACHE_PATHS:
        path = os.path.expanduser(p)
        if not os.path.isdir(path):
            continue
        out = run(["du", "-sk", path], timeout=180)
        m = re.match(r"\s*(\d+)", out)
        if not m:
            continue
        kb = int(m.group(1))
        if kb < 51200:
            continue
        results.append({"name": os.path.basename(path.rstrip("/")) or path,
                        "path": path, "size_kb": kb, "size_h": human(kb)})
    results.sort(key=lambda r: r["size_kb"], reverse=True)
    return results


def system_info_macos():
    info = {}
    info["os"] = "macOS " + run(["sw_vers", "-productVersion"]).strip()
    info["build"] = run(["sw_vers", "-buildVersion"]).strip()
    arch = run(["uname", "-m"]).strip()
    brand = run(["sysctl", "-n", "machdep.cpu.brand_string"]).strip()
    info["arch"] = (f"Apple Silicon (arm64){' / ' + brand if brand else ''}"
                    if arch == "arm64" else f"{arch}{' / ' + brand if brand else ''}")
    info["user"] = os.environ.get("USER", "") or run(["whoami"]).strip()
    info["home"] = HOME
    total, used, free = "?", "?", "?"
    try:
        t, u, f = shutil.disk_usage("/")
        total, used, free = human(t // 1024), human(u // 1024), human(f // 1024)
    except Exception:
        pass
    info["disk_total"], info["disk_used"], info["disk_free"] = total, used, free
    dinfo = run(["diskutil", "info", "/"])
    fs = re.search(r"File System Personality:\s*(.+)", dinfo)
    info["filesystem"] = fs.group(1).strip() if fs else "APFS"
    pm = re.search(r"Purgeable Space:\s*([\d.,]+ \w+)", dinfo)
    info["purgeable"] = pm.group(1).strip() if pm else ""
    info["disk_name"] = "Macintosh HD"
    info["disks"] = [{"name": "Macintosh HD", "total": total, "used": used, "free": free}]
    return info


def scan_macos():
    system = system_info_macos()
    groups = {}
    for key, path, floor in MAC_TARGETS:
        groups[key] = dev_caches_macos() if key == "dev_caches" else du_children(path, min_kb=floor)
    return system, groups


# ======================================================================
# Windows  (真机实测：Windows 11 + Python 3.12，纯标准库 os / shutil / ctypes)
# ======================================================================
def merge_coverage(target, source):
    """Keep per-target diagnostics; hotspot views overlap and must not be summed."""
    if target is None:
        return
    target.setdefault('size_basis', source['size_basis'])
    for key in ('denied_count', 'skipped_reparse_count'):
        target[key] = target.get(key, 0) + source[key]
    for key, cap in (('denied', 500), ('skipped_reparse', 100)):
        target.setdefault(key, []).extend(source.get(key, [])[:max(0, cap - len(target.get(key, [])))])
    target.setdefault('groups', {}).update(source.get('groups', {}))
    target.setdefault('volumes', []).extend(source.get('volumes', []))
    target['denied_sample_truncated'] = target['denied_count'] > len(target['denied'])
    target['status'] = 'partial' if target['denied_count'] else 'complete_with_exclusions'


def dir_size_bytes(path, coverage=None):
    """Logical bytes, without following links; optionally preserve read failures."""
    from scan_windows_full import scan_roots
    _, diagnostics = scan_roots([path], {})
    merge_coverage(coverage, diagnostics)
    return sum(row['bytes'] for row in diagnostics['volumes'])


def optional_path_present(path):
    """Skip absent optional targets, but let the walker record access failures."""
    try:
        os.stat(api_path(path), follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError:
        pass
    return True


def scandir_children(path, min_kb=51200, limit=40, coverage=None):
    """Size immediate children using the same guarded walker as full scans."""
    if not path:
        return []
    from scan_windows_full import scan_roots
    groups, diagnostics = scan_roots([path], {path: path}, min_kb=min_kb, limit=limit)
    merge_coverage(coverage, diagnostics)
    rows = groups[path]
    if not rows and diagnostics['denied_count']:
        return [{'name': '(unreadable)', 'path': path, 'size_kb': 0,
                 'size_h': '?', 'denied': True, 'partial': True}]
    return rows


def list_drives_windows():
    drives = []
    import string
    for letter in string.ascii_uppercase:
        root = f"{letter}:\\"
        if os.path.exists(root):
            try:
                t, u, f = shutil.disk_usage(root)
                drives.append({"name": root, "total": human(t // 1024),
                               "used": human(u // 1024), "free": human(f // 1024)})
            except Exception:
                continue
    return drives


def recycle_bin_windows(sysdrive, min_kb=51200, coverage=None):
    """回收站占用，聚合成一项（只读）。

    各用户 SID 子目录单独看没有意义，合并成一个「回收站」条目更好分诊：
    它恒为 🟡 —— 清空才真正释放，且里面装的是用户自己删掉的东西。
    """
    base = os.path.join(sysdrive, "$Recycle.Bin")
    if not optional_path_present(base):
        return []
    detail = {}
    kb = dir_size_bytes(base, detail) // 1024
    merge_coverage(coverage, detail)
    if kb < min_kb and not detail.get('denied_count'):
        return []
    return [{"name": "回收站", "path": base, "size_kb": kb, "size_h": human(kb),
             "partial": bool(detail.get('denied_count'))}]


def system_info_windows():
    import platform
    info = {}
    info["os"] = platform.system() + " " + platform.release()
    info["build"] = platform.version()
    info["arch"] = os.environ.get("PROCESSOR_ARCHITECTURE", platform.machine())
    info["user"] = os.environ.get("USERNAME", "")
    info["home"] = os.environ.get("USERPROFILE", HOME)
    sysdrive = os.environ.get("SystemDrive", "C:") + "\\"
    total, used, free = "?", "?", "?"
    try:
        t, u, f = shutil.disk_usage(sysdrive)
        total, used, free = human(t // 1024), human(u // 1024), human(f // 1024)
    except Exception:
        pass
    info["disk_total"], info["disk_used"], info["disk_free"] = total, used, free
    info["filesystem"] = "NTFS"
    info["purgeable"] = ""
    info["disk_name"] = sysdrive
    info["disks"] = list_drives_windows()
    return info


def scan_windows(coverage=None):
    profile = os.environ.get("USERPROFILE", HOME)
    local = os.environ.get("LOCALAPPDATA", os.path.join(profile, "AppData", "Local"))
    roaming = os.environ.get("APPDATA", os.path.join(profile, "AppData", "Roaming"))
    sysdrive = os.environ.get("SystemDrive", "C:") + "\\"
    targets = [
        ("user_profile", profile, 102400),
        ("appdata_local", local, 51200),
        ("appdata_roaming", roaming, 51200),
        ("temp", os.environ.get("TEMP", os.path.join(local, "Temp")), 51200),
        ("downloads", os.path.join(profile, "Downloads"), 51200),
        ("program_files", os.environ.get("ProgramFiles", r"C:\Program Files"), 102400),
        ("program_files_x86", os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), 102400),
    ]
    groups = {}
    for key, path, floor in targets:
        groups[key] = scandir_children(path, min_kb=floor, coverage=coverage)

    dev_paths = [
        os.path.join(profile, ".cache"), os.path.join(profile, ".npm"),
        os.path.join(profile, ".gradle"), os.path.join(profile, ".m2"),
        os.path.join(profile, ".nuget", "packages"), os.path.join(profile, ".cargo"),
        os.path.join(local, "pip", "Cache"), os.path.join(local, "Yarn"),
        os.path.join(local, "uv"), os.path.join(local, "ms-playwright"),
        os.path.join(local, "go-build"),
    ]
    dev = []
    for path in dev_paths:
        if not optional_path_present(path):
            continue
        detail = {}
        kb = dir_size_bytes(path, detail) // 1024
        merge_coverage(coverage, detail)
        if kb < 51200 and not detail.get('denied_count'):
            continue
        dev.append({"name": os.path.basename(path.rstrip("\\/")) or path,
                    "path": path, "size_kb": kb, "size_h": human(kb),
                    "partial": bool(detail.get('denied_count'))})
    dev.sort(key=lambda r: r["size_kb"], reverse=True)
    groups["dev_caches"] = dev
    groups["recycle_bin"] = recycle_bin_windows(sysdrive, coverage=coverage)
    return system_info_windows(), groups


# ======================================================================
def main():
    # Windows shell redirects default to the locale codec (GBK); force UTF-8 so
    # the JSON survives piping and reads back portably.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--all-drives', action='store_true', help='Windows: scan contents of every local fixed volume once')
    parser.add_argument('--progress', action='store_true', help='Write scan progress to stderr; stdout remains JSON')
    parser.add_argument('--output', help='Save UTF-8 JSON to a NEW file instead of shell redirection')
    parser.add_argument('--no-system-probe', action='store_true',
                        help='Windows: skip the read-only system-space probe (WinSxS/DriverStore/update caches)')
    args = parser.parse_args()
    started = time.time()
    diagnostics = None
    if sys.platform == "darwin":
        if args.all_drives:
            parser.error('--all-drives is Windows-only')
        system, groups = scan_macos()
    elif sys.platform.startswith("win"):
        if args.all_drives:
            from scan_windows_full import fixed_drives, watch_paths, scan_roots
            roots = fixed_drives()
            def progress(row):
                print(json.dumps({'scan_progress': row}, ensure_ascii=True), file=sys.stderr, flush=True)
            groups, diagnostics = scan_roots(roots, watch_paths(roots), progress=progress if args.progress else None)
            system = system_info_windows()
        else:
            diagnostics = {}
            system, groups = scan_windows(coverage=diagnostics)
    else:
        print(json.dumps({"error": "unsupported_platform", "platform": sys.platform,
                          "message": "scan.py supports macOS and Windows only."},
                         ensure_ascii=False))
        return
    data = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "system": system,
        "groups": groups,
        "scan_seconds": round(time.time() - started, 1),
    }
    if diagnostics is not None:
        data['coverage'] = diagnostics
        data['scan_scope'] = 'all_local_fixed_volumes' if args.all_drives else 'windows_hotspots'
    # Windows: read-only probe of system-level space that the hot-spot groups
    # cannot see (WinSxS / DriverStore / update caches / recovery / hiberfil...).
    # Failure here must never invalidate the main scan.
    if sys.platform.startswith("win") and not args.no_system_probe:
        try:
            from probe_system import collect as collect_system_space
            data["system_space"] = collect_system_space()
        except Exception as exc:
            data["system_space"] = {"error": "%s: %s" % (type(exc).__name__, exc),
                                    "items": [], "elevated": False}
    if args.output:
        with open(args.output, 'x', encoding='utf-8') as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
    else:
        print(json.dumps(data, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
