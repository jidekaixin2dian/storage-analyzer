import json
import tempfile
import unittest
from pathlib import Path
from demo_case import build_case


class DemoCaseTests(unittest.TestCase):
    def test_reproducible_scan_analysis_and_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = build_case(Path(tmp)/'new-case')
            scan = json.loads((dest/'scan.json').read_text(encoding='utf-8'))
            analysis = json.loads((dest/'analysis.json').read_text(encoding='utf-8'))
            self.assertEqual(scan['coverage'], analysis['coverage'])
            self.assertEqual(scan['coverage']['denied_count'], 1)
            self.assertEqual(scan['coverage']['volumes'][0]['files'], 4)
            rows = scan['groups']['demo']
            self.assertEqual(sum(r['size_bytes'] for r in rows), 3*4096*len(b'synthetic-regenerable-fixture\n')+8192*len(b'synthetic-user-document\n'))
            self.assertTrue(any(r.get('partial') for r in rows))
            self.assertTrue(any(r['size_bytes']==0 and not r.get('partial') for r in rows))
            self.assertNotIn('trash_paths', analysis['yellow'][0])
            self.assertTrue((dest/'report.html').is_file())
            with self.assertRaises(FileExistsError):
                build_case(dest)
