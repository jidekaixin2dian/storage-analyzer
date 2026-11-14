"""Regression tests for the Windows hot-spot helpers added after real cleanups.

Each case reproduces a miss from an earlier round: a full-machine scan that
silently dropped the recycle bin, and IDE index dirs nobody listed.
"""
import os
import tempfile
import unittest
from unittest.mock import patch

import scan


def make_file(path, size_bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as stream:
        stream.write(b"0" * size_bytes)


class RecycleBinTests(unittest.TestCase):
    def test_every_drive_is_listed_with_its_own_label(self):
        with tempfile.TemporaryDirectory() as drive_a, \
                tempfile.TemporaryDirectory() as drive_b:
            make_file(os.path.join(drive_a, "$Recycle.Bin", "S-1-5-21", "old.zip"),
                      3 * 1024 * 1024)
            os.makedirs(os.path.join(drive_b, "$Recycle.Bin"), exist_ok=True)

            rows = scan.recycle_bins_all_drives(
                [drive_a + os.sep, drive_b + os.sep], min_kb=1024)

            self.assertEqual(len(rows), 1, 'an empty bin must not add a row')
            self.assertTrue(rows[0]['name'].startswith('回收站（'))
            self.assertEqual(rows[0]['size_kb'], 3 * 1024)

    def test_rows_are_sorted_by_size(self):
        with tempfile.TemporaryDirectory() as small, \
                tempfile.TemporaryDirectory() as big:
            make_file(os.path.join(small, '$Recycle.Bin', 'a', 'f.bin'),
                      1 * 1024 * 1024)
            make_file(os.path.join(big, '$Recycle.Bin', 'a', 'f.bin'),
                      5 * 1024 * 1024)

            rows = scan.recycle_bins_all_drives(
                [small + os.sep, big + os.sep], min_kb=1024)

            self.assertEqual([row['size_kb'] for row in rows], [5 * 1024, 1024])


class IdeCacheTests(unittest.TestCase):
    def test_jetbrains_index_and_cache_dirs_are_listed_separately(self):
        with tempfile.TemporaryDirectory() as local:
            base = os.path.join(local, 'JetBrains', 'PyCharm2024.3')
            for sub in ('index', 'caches', 'jcef_cache'):
                os.makedirs(os.path.join(base, sub), exist_ok=True)

            def fake_dir_size(path, coverage=None):
                size = {'index': 40, 'caches': 20, 'jcef_cache': 2}.get(
                    os.path.basename(path), 0)
                return size * 1024 * 1024

            with patch.object(scan, 'dir_size_bytes', side_effect=fake_dir_size):
                rows = scan.ide_caches_windows(local)

            names = [row['name'] for row in rows]
            self.assertEqual(names, ['PyCharm2024.3\\index',
                                     'PyCharm2024.3\\caches'],
                             'sub-10 MB caches stay out of the list')

    def test_missing_jetbrains_dir_returns_empty(self):
        with tempfile.TemporaryDirectory() as local:
            self.assertEqual(scan.ide_caches_windows(local), [])


if __name__ == '__main__':
    unittest.main()
