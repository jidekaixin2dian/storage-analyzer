"""Build a synthetic scan -> fixture analysis -> report. No personal scan or DISM.

python scripts/demo_case.py work/demo-new [--serve]
Destination must not exist. --serve simulates recycle outcomes without OS Trash.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch
from http.server import ThreadingHTTPServer

import server
from report_html import render_report
from scan_windows_full import scan_roots, display_path


def build_case(destination):
    dest = Path(destination).resolve()
    dest.mkdir(parents=True, exist_ok=False)
    root = dest/'synthetic-files'
    root.mkdir()
    cache = root/'已核实的合成缓存'
    cache.mkdir()
    for name in ('01 成功 & sample.txt', '02 取消.txt', '03 失败.txt'):
        (cache/name).write_bytes(b'synthetic-regenerable-fixture\n' * 4096)
    docs = root/'中文 空格 & <特殊字符>' if os.name != 'nt' else root/'中文 空格 & 特殊字符'
    docs.mkdir()
    (docs/'example.txt').write_bytes(b'synthetic-user-document\n' * 8192)
    (root/'空目录').mkdir()
    unreadable = root/'模拟访问失败'
    unreadable.mkdir()
    (unreadable/'not-counted.txt').write_bytes(b'known fixture, intentionally not measured')
    actual = os.scandir

    def controlled_scandir(path):
        if Path(display_path(os.fspath(path))) == unreadable:
            raise PermissionError('SIMULATED: fixture access denial (no ACL changed)')
        return actual(path)

    with patch('scan_windows_full.os.scandir', side_effect=controlled_scandir):
        groups, coverage = scan_roots([str(root)], {'demo': str(root)}, min_kb=0)
    scan = {'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'), 'scan_seconds': 0,
            'scan_scope': 'synthetic_fixture', 'coverage': coverage, 'groups': groups,
            'system': {'os': 'Windows (synthetic)' if os.name == 'nt' else 'macOS (synthetic)',
                       'home': str(root), 'user': 'synthetic-demo', 'filesystem': 'fixture',
                       'disk_total': '?', 'disk_used': '?', 'disk_free': '?'}}
    # This is a reviewed fixture interpretation, not an automatic classifier.
    analysis = {k: v for k, v in scan.items() if k != 'groups'}
    analysis['top5'] = [dict(rank=i+1, tier='yellow', size=row['size_h'],
                             type='合成目录', name=row['name'], path=row['path'],
                             note='读取不完整，体量仅为下限' if row.get('partial') else '按逻辑文件长度统计，非可释放量')
                        for i, row in enumerate(groups['demo'])]
    analysis['green'] = [dict(name=path.stem, path=str(path), size_estimate='约 0.11 MB',
                              trash_paths=[str(path)], evidence='由 demo_case.py 明确创建的可丢弃文本样本；不是根据扩展名推断安全。',
                              next_step='演示模式：01 移到本案例的 simulated-trash；02 返回取消；03 返回失败。系统回收站不会被调用。')
                         for path in sorted(cache.iterdir())]
    analysis['yellow'] = [dict(name='合成个人资料目录', path=str(docs), size='约 0.18 MB',
                               content_profile='合成文档，仅用于展示；名称和体量不构成删除依据。',
                               evidence='扫描记录中的精确路径与逻辑大小；内容用途由案例生成记录确定。',
                               why_manual='真实个人资料需要用户自行判断，未设置 trash_paths。',
                               disposal='先在文件管理器查看文件。确认是否仍在使用。需要保留时自行归档；不提供预计可释放量。',
                               risk='删除真实文档可能造成资料丢失。')]
    analysis['summary'] = {'overview': '合成数据演示：存在模拟访问失败，报告保留遗漏；未测量可释放空间。',
                           'priority': ['先看占用排行和扫描覆盖依据，再查看每项判断依据。',
                                        '交互模式可演示成功、取消、失败与批量部分完成；这些不是系统回收站实测。']}
    for name, data in (('scan.json', scan), ('analysis.json', analysis)):
        (dest/name).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    (dest/'report.html').write_text(render_report(Path(server.TEMPLATE).read_text(encoding='utf-8'), analysis), encoding='utf-8')
    return dest


def serve_case(dest):
    server.DATA, server.TPL, server.RM_ALLOW, server.TRASH_ALLOW, server.OPEN_ALLOW = server.load(str(dest/'analysis.json'))
    root = (dest/'synthetic-files').resolve()
    home = Path(server.HOME).resolve()
    if home not in root.parents:
        raise ValueError('--serve requires a destination under HOME; existing server path boundaries are unchanged')
    trash = dest/'simulated-trash'
    trash.mkdir()

    def simulated_trash(path):
        target = Path(path).resolve()
        if root not in target.parents:
            raise ValueError('outside synthetic fixture')
        if target.name.startswith('02'):
            raise server.OperationCancelled('SIMULATED: 用户取消，原路径保留')
        if target.name.startswith('03'):
            raise PermissionError('SIMULATED: 文件被锁定，原路径保留')
        target.rename(trash/target.name)

    def disabled_delete(path):
        raise OSError('演示模式不执行直接删除；请用“移到回收站”测试模拟结果')

    server.move_to_trash = simulated_trash
    server.hard_delete = disabled_delete
    http = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
    url = 'http://127.0.0.1:%d/' % http.server_port
    (dest/'demo-url.txt').write_text(url, encoding='utf-8')
    print('SIMULATED recycle outcomes (no OS Trash): ' + url, flush=True)
    try:
        http.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        http.server_close()


def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination')
    parser.add_argument('--serve', action='store_true')
    args = parser.parse_args()
    dest = build_case(args.destination)
    print(str(dest/'report.html'), flush=True)
    if args.serve:
        serve_case(dest)


if __name__ == '__main__':
    main()
