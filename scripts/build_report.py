#!/usr/bin/env python3
"""Inject an analysis JSON into the HTML template -> a standalone report.

Usage:
    build_report.py <analysis.json> [output.html]

The analysis JSON is produced by Claude after interpreting scan.py output.
Schema (all sections optional except system):

{
  "generated_at": "2026-05-28 12:00:00",
  "scan_seconds": 42.1,
  "system": {os, build, arch, user, home, filesystem,
             disk_total, disk_used, disk_free, purgeable},
  "top5": [{rank, tier(green|yellow|red), size, type, name, path, note}],
  "green":  [{name, path, size_estimate, evidence?, next_step?, kill_processes:[], trash_paths:[...], commands:[{label,cmd}]}],
  "yellow": [{name, path, size, content_profile, why_manual, disposal, risk, trash_paths:[...]?, open_note?}],
  "red":    [{name, path, size, why_keep, indirect_release, auto_reclaim, app_paths:[...]?}],
  "denied": ["/path/one", ...],
  "scan_scope": "windows_hotspots|all_local_fixed_volumes|...",  # copy from scan
  "coverage": {...},  # copy scan coverage unchanged; never infer full success
  "system_space": {items:[...], elevated:bool, elevated_analysis:{...}?},  # Windows 只读系统空间探测
  "summary": {overview, tier_stats:{green,yellow,red}, priority:[...], long_term:[...]}
}

Each tier item may add `evidence` (a short verified observation tied to its path).
Keep directory size distinct from an estimated reclaim amount. Unknown reclaim
amounts should remain unknown; no estimate is required for yellow/red items.
"""
import json
import os
import sys

from report_html import render_report

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "..", "assets", "report_template.html")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    # Windows 管道/重定向下 stdout 默认走 GBK，中文提示会让调用方解码失败（与 scan.py/server.py 一致）
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    src = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.expanduser(
        "~/Desktop/storage-report.html")

    with open(src, "r", encoding="utf-8") as f:
        data = json.load(f)
    with open(TEMPLATE, "r", encoding="utf-8") as f:
        tpl = f.read()

    # 静态报告不带删除能力（DELETE=null），删除按钮只在 server.py 服务时出现
    html = render_report(tpl, data)

    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"报告已生成: {out}")
    opener = "start" if sys.platform.startswith("win") else "open"
    print(f"打开: {opener} '{out}'")


if __name__ == "__main__":
    main()
