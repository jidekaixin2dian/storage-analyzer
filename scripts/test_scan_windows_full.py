import os
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from scan_windows_full import scan_roots, api_path, display_path
import scan


class VolumeScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.a, self.b = self.base/'first', self.base/'second'
        (self.a/'nested').mkdir(parents=True)
        (self.b/'media').mkdir(parents=True)
        (self.a/'nested'/'data').write_bytes(b'abc')
        (self.b/'media'/'clip').write_bytes(b'0123456')

    def test_all_roots_and_nested_watches_share_one_walk(self):
        actual = os.scandir
        calls = []
        def traced(path):
            calls.append(os.path.normcase(os.path.abspath(path)))
            return actual(path)
        with patch('scan_windows_full.os.scandir', side_effect=traced):
            groups, coverage = scan_roots([str(self.a), str(self.b)], {'a':str(self.a),'b':str(self.b),'nested':str(self.a/'nested')}, min_kb=0)
        self.assertEqual(groups['a'][0]['size_bytes'], 3)
        self.assertEqual(groups['b'][0]['size_bytes'], 7)
        self.assertEqual(groups['nested'][0]['size_bytes'], 3)
        self.assertEqual(len(calls), len(set(calls)))
        self.assertEqual(sum(v['bytes'] for v in coverage['volumes']), 10)

    def test_nested_denied_is_reported_with_partial_size(self):
        actual = os.scandir
        def denied(path):
            if Path(display_path(os.fspath(path))) == self.a/'nested':
                raise PermissionError('synthetic access denial')
            return actual(path)
        with patch('scan_windows_full.os.scandir', side_effect=denied):
            groups, coverage = scan_roots([str(self.a)], {'a':str(self.a)}, min_kb=0)
        self.assertEqual(coverage['denied_count'], 1)
        self.assertTrue(groups['a'][0]['partial'])
        self.assertIn('nested', coverage['denied'][0]['path'])

    def test_root_denied_not_reported_as_empty_success(self):
        with patch('scan_windows_full.os.scandir', side_effect=PermissionError('synthetic')):
            _, coverage = scan_roots([str(self.a)], {'a':str(self.a)}, min_kb=0)
        self.assertEqual(coverage['denied_count'], 1)

    def test_hotspot_nested_failure_survives_threshold(self):
        actual = os.scandir
        def denied(path):
            if Path(display_path(os.fspath(path))) == self.a/'nested':
                raise PermissionError('synthetic access denial')
            return actual(path)
        coverage = {}
        with patch('scan_windows_full.os.scandir', side_effect=denied):
            rows = scan.scandir_children(str(self.a), coverage=coverage)
        self.assertTrue(rows[0]['partial'])
        self.assertEqual(coverage['status'], 'partial')
        self.assertEqual(coverage['denied'][0]['reason'], 'permission_denied')

    def test_hotspot_missing_root_is_not_empty_success(self):
        coverage = {}
        rows = scan.scandir_children(str(self.a/'gone'), coverage=coverage)
        self.assertTrue(rows[0]['partial'])
        self.assertEqual(coverage['denied'][0]['reason'], 'not_found')

    def test_directory_total_preserves_failure_details(self):
        with patch('scan_windows_full.os.scandir', side_effect=PermissionError('synthetic')):
            coverage = {}
            self.assertEqual(scan.dir_size_bytes(str(self.a), coverage), 0)
        self.assertEqual(coverage['status'], 'partial')
        self.assertEqual(coverage['denied_count'], 1)

    def test_optional_recycle_target_denied_is_not_silently_absent(self):
        coverage = {}
        with patch('scan_windows_full.os.stat', side_effect=PermissionError('synthetic access denial')):
            rows = scan.recycle_bin_windows(str(self.a), coverage=coverage)
        self.assertTrue(rows[0]['partial'])
        self.assertEqual(coverage['denied_count'], 1)
        self.assertEqual(coverage['denied'][0]['reason'], 'permission_denied')

    def test_file_disappearing_during_entry_stat_is_recorded(self):
        actual = os.scandir
        class VanishedEntry:
            name = 'data'
            path = str(self.a/'nested'/'data')
            def stat(self, **kwargs):
                raise FileNotFoundError('SIMULATED: disappeared after directory listing')
        class Entries:
            def __enter__(self):
                return iter([VanishedEntry()])
            def __exit__(self, *args):
                return False
        def controlled(path):
            return Entries() if Path(display_path(os.fspath(path))) == self.a/'nested' else actual(path)
        with patch('scan_windows_full.os.scandir', side_effect=controlled):
            groups, coverage = scan_roots([str(self.a)], {'a':str(self.a)}, min_kb=0)
        self.assertEqual(coverage['denied'][0]['reason'], 'not_found')
        self.assertTrue(groups['a'][0]['partial'])

    def test_hotspot_cli_preserves_coverage_and_probe_failure(self):
        def fixture_scan(coverage=None):
            rows = scan.scandir_children(str(self.a), min_kb=0, coverage=coverage)
            return {'os': 'Windows synthetic'}, {'user_profile': rows}
        output = io.StringIO()
        with patch.object(scan.sys, 'platform', 'win32'), \
                patch.object(scan.sys, 'argv', ['scan.py']), \
                patch.object(scan.sys, 'stdout', output), \
                patch.object(scan, 'scan_windows', side_effect=fixture_scan), \
                patch('probe_system.collect', side_effect=OSError('synthetic optional probe failure')):
            scan.main()
        result = json.loads(output.getvalue())
        self.assertEqual(result['scan_scope'], 'windows_hotspots')
        self.assertIn('coverage', result)
        self.assertIn('synthetic optional probe failure', result['system_space']['error'])
        self.assertEqual(result['groups']['user_profile'][0]['size_bytes'], 3)

    def test_filter_limits_and_empty_directory_are_explicit(self):
        (self.a/'empty').mkdir()
        groups, coverage = scan_roots([str(self.a)], {'a':str(self.a)}, min_kb=0, limit=1)
        self.assertEqual(len(groups['a']), 1)
        self.assertEqual(coverage['groups']['a']['omitted_by_limit'], 1)
        groups, coverage = scan_roots([str(self.a)], {'a':str(self.a)}, min_kb=1)
        self.assertEqual(groups['a'], [])
        self.assertEqual(coverage['groups']['a']['below_threshold'], 2)

    def test_symbolic_link_cycle_is_skipped(self):
        try:
            (self.a/'nested'/'cycle').symlink_to(self.a, target_is_directory=True)
        except OSError:
            self.skipTest('symlink creation unavailable without privilege')
        groups, coverage = scan_roots([str(self.a)], {'a':str(self.a)}, min_kb=0)
        self.assertEqual(coverage['volumes'][0]['bytes'], 3)
        self.assertEqual(coverage['skipped_reparse_count'], 1)
        self.assertIn('cycle', coverage['skipped_reparse'][0])

    def test_reparse_directory_is_not_followed(self):
        actual = os.stat
        class LinkStat:
            st_file_attributes = 0x400
            st_mode = 0
        def marked(path, *args, **kwargs):
            if Path(display_path(os.fspath(path))) == self.a:
                return LinkStat()
            return actual(path, *args, **kwargs)
        with patch('scan_windows_full.os.stat', side_effect=marked):
            _, coverage = scan_roots([str(self.a)], {'a':str(self.a)}, min_kb=0)
        self.assertEqual(coverage['skipped_reparse_count'], 1)
        self.assertEqual(coverage['volumes'][0]['files'], 0)

    def test_scan_does_not_modify_inputs(self):
        path = self.a/'nested'/'data'
        before = (path.read_bytes(), path.stat().st_mtime_ns)
        events = []
        scan_roots([str(self.a)], {'a':str(self.a)}, min_kb=0, progress=events.append)
        self.assertEqual(before, (path.read_bytes(), path.stat().st_mtime_ns))
        self.assertTrue(events)

    def test_trailing_space_directory_is_counted(self):
        staged = self.a/'staged '
        os.mkdir(api_path(str(staged)))
        self.addCleanup(lambda: shutil.rmtree(api_path(str(staged))))
        with open(api_path(str(staged/'payload')), 'wb') as stream:
            stream.write(b'12345')
        groups, coverage = scan_roots([str(self.a)], {'a':str(self.a)}, min_kb=0)
        row = next(r for r in groups['a'] if r['name'] == 'staged ')
        self.assertEqual(row['size_bytes'],5)
        self.assertEqual(coverage['denied_count'],0)

    def test_relative_path_remains_usable(self):
        # The legacy hotspot helpers accept relative paths too. Extended paths
        # must be absolute before the Windows native prefix is added.
        # CI may put the checkout on D: and temporary fixtures on C:.
        # Relative paths must be exercised from the fixture's own volume.
        previous = os.getcwd()
        try:
            os.chdir(self.base)
            relative = os.path.relpath(self.a/'nested'/'data')
            with open(api_path(relative), 'rb') as stream:
                self.assertEqual(stream.read(), b'abc')
        finally:
            os.chdir(previous)


if __name__ == '__main__':
    unittest.main(verbosity=2)
