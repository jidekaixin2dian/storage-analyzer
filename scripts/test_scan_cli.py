"""CLI failure contracts and nonblocking capacity diagnostics; no host scan."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scan


class ScanDiagnosticsTests(unittest.TestCase):
    def test_unsupported_platform_exits_nonzero_without_writing_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'scan.json'
            code = ("import scan; scan.sys.platform='unsupported-test'; "
                    "scan.sys.argv=%r; scan.main()" % ['scan.py', '--output', str(output)])
            result = subprocess.run([sys.executable, '-c', code],
                                    cwd=Path(scan.__file__).parent,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(json.loads(result.stdout)['error'], 'unsupported_platform')
            self.assertFalse(output.exists())

    def test_capacity_failure_retains_unknown_values_and_reports_reason(self):
        for system_info in (scan.system_info_macos, scan.system_info_windows):
            with self.subTest(platform=system_info.__name__), \
                    patch.object(scan, 'run', return_value=''), \
                    patch.object(scan, 'list_drives_windows', return_value=[]), \
                    patch.object(scan.shutil, 'disk_usage', side_effect=OSError('synthetic capacity failure')), \
                    self.assertLogs(level='WARNING') as logs:
                info = system_info()
            self.assertEqual([info[k] for k in ('disk_total', 'disk_used', 'disk_free')], ['?', '?', '?'])
            self.assertIn('synthetic capacity failure', '\n'.join(logs.output))
            self.assertIn('OSError', '\n'.join(logs.output))

    def test_unreadable_drive_does_not_hide_other_drive_capacity(self):
        def capacity(path):
            if path == 'X:\\':
                raise PermissionError('synthetic drive denial')
            return 4096, 1024, 3072

        with patch.object(scan.os.path, 'exists', side_effect=lambda p: p in ('X:\\', 'Y:\\')), \
                patch.object(scan.shutil, 'disk_usage', side_effect=capacity), \
                self.assertLogs(level='WARNING') as logs:
            drives = scan.list_drives_windows()
        self.assertEqual([d['name'] for d in drives], ['Y:\\'])
        self.assertIn('X:\\', '\n'.join(logs.output))
        self.assertIn('synthetic drive denial', '\n'.join(logs.output))


if __name__ == '__main__':
    unittest.main()
