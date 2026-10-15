"""Read-only, one-pass Windows volume inventory with explicit coverage diagnostics."""
import os
import stat
import time


def api_path(path):
    """Preserve long paths and trailing dots/spaces in Windows native calls."""
    path = os.fspath(path)
    if os.name != 'nt' or path.startswith('\\\\?\\'):
        return path
    if not os.path.isabs(path):
        path = os.path.abspath(path)
    if path.startswith('\\\\'):
        return '\\\\?\\UNC\\' + path[2:]
    return '\\\\?\\' + path


def display_path(path):
    if path.startswith('\\\\?\\UNC\\'):
        return '\\\\' + path[8:]
    return path[4:] if path.startswith('\\\\?\\') else path


def fixed_drives():
    """Only local fixed volumes; never traverse a mapped network drive implicitly."""
    import ctypes
    return [f'{letter}:\\' for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            if ctypes.windll.kernel32.GetDriveTypeW(f'{letter}:\\') == 3]


def watch_paths(roots):
    home = os.environ.get('USERPROFILE', os.path.expanduser('~'))
    local = os.environ.get('LOCALAPPDATA', os.path.join(home, 'AppData', 'Local'))
    roaming = os.environ.get('APPDATA', os.path.join(home, 'AppData', 'Roaming'))
    watches = {f'drive_{root[0].upper()}': root for root in roots}
    watches.update({
        'user_profile': home, 'appdata_local': local, 'appdata_roaming': roaming,
        'temp': os.environ.get('TEMP', os.path.join(local, 'Temp')),
        'downloads': os.path.join(home, 'Downloads'),
        'program_files': os.environ.get('ProgramFiles', 'C:\\Program Files'),
        'program_files_x86': os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'),
        'program_data': os.environ.get('ProgramData', 'C:\\ProgramData'),
        'user_cache': os.path.join(home, '.cache'),
        'local_programs': os.path.join(local, 'Programs'),
        'app_packages': os.path.join(local, 'Packages'),
    })
    return watches


def scan_roots(roots, watches, min_kb=51200, limit=80, progress=None):
    """Walk each volume once. Watches aggregate immediate children in that pass.

    Sizes are logical file lengths; hard links and compression may differ from
    physical disk usage. No file contents are read and no links are followed.
    """
    groups = {key: {} for key in watches}
    by_path = {}
    for key, path in watches.items():
        by_path.setdefault(os.path.normcase(os.path.abspath(path)), []).append(key)
    diagnostics = {'denied_count': 0, 'denied': [], 'skipped_reparse_count': 0,
                   'size_basis': 'logical file bytes; hard links not deduplicated',
                   'volumes': []}
    last_progress = 0

    def failed(path, exc, active):
        diagnostics['denied_count'] += 1
        if len(diagnostics['denied']) < 500:
            diagnostics['denied'].append({'path': path, 'error': str(exc)})
        for row in active:
            row['partial'] = True
            row['denied_count'] = row.get('denied_count', 0) + 1

    for root in roots:
        stats = {'root': root, 'files': 0, 'directories': 0, 'bytes': 0}
        diagnostics['volumes'].append(stats)
        stack = [(os.path.abspath(root), [])]
        while stack:
            path, active = stack.pop()
            try:
                root_stat = os.stat(api_path(path), follow_symlinks=False)
                if stat.S_ISLNK(root_stat.st_mode) or getattr(root_stat, 'st_file_attributes', 0) & 0x400:
                    diagnostics['skipped_reparse_count'] += 1
                    continue
                keys = by_path.get(os.path.normcase(path), [])
                stats['directories'] += 1
                with os.scandir(api_path(path)) as entries:
                    for entry in entries:
                        child_path = display_path(entry.path)
                        child_active = active
                        if keys:
                            child_active = active[:]
                            for key in keys:
                                row = groups[key].setdefault(entry.name, {'name': entry.name, 'path': child_path, 'size_bytes': 0, 'files': 0})
                                child_active.append(row)
                        try:
                            info = entry.stat(follow_symlinks=False)
                            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                                diagnostics['skipped_reparse_count'] += 1
                                for row in child_active:
                                    row['skipped_reparse_count'] = row.get('skipped_reparse_count', 0) + 1
                                continue
                            if stat.S_ISDIR(info.st_mode):
                                stack.append((child_path, child_active))
                            elif stat.S_ISREG(info.st_mode):
                                stats['files'] += 1
                                stats['bytes'] += info.st_size
                                for row in child_active:
                                    row['size_bytes'] += info.st_size
                                    row['files'] += 1
                        except OSError as exc:
                            failed(child_path, exc, child_active)
            except OSError as exc:
                failed(path, exc, active)
            now = time.monotonic()
            if progress and now - last_progress >= 5:
                progress(dict(stats))
                last_progress = now
        if progress:
            progress(dict(stats))

    output = {}
    for key, entries in groups.items():
        rows = []
        for row in entries.values():
            if row['size_bytes'] >= min_kb * 1024 or row.get('partial'):
                row['size_kb'] = row['size_bytes'] // 1024
                value = row['size_bytes'] / 1024**3
                row['size_h'] = f'{value:.2f} GB' if value >= 1 else f'{row["size_bytes"]/1024**2:.1f} MB'
                rows.append(row)
        rows.sort(key=lambda row: row['size_bytes'], reverse=True)
        output[key] = rows[:limit]
    diagnostics['denied_sample_truncated'] = diagnostics['denied_count'] > len(diagnostics['denied'])
    return output, diagnostics
