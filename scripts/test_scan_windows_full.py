import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from scan_windows_full import scan_roots, api_path, display_path


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
        relative = os.path.relpath(self.a/'nested'/'data')
        with open(api_path(relative), 'rb') as stream:
            self.assertEqual(stream.read(), b'abc')


if __name__ == '__main__':
    unittest.main(verbosity=2)
