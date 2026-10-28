import json
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from html.parser import HTMLParser
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import server


class ScriptParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.active = False

    def handle_starttag(self, tag, attrs):
        if tag == 'script':
            self.scripts.append('')
            self.active = True

    def handle_endtag(self, tag):
        if tag == 'script':
            self.active = False

    def handle_data(self, data):
        if self.active:
            self.scripts[-1] += data


class ReportEmbeddingTests(unittest.TestCase):
    def setUp(self):
        self.data = {'system': {}, 'summary': {'overview':
            '</ScRiPt><script id=audit-marker>void 0</script><!--<script>\n'
            '中文 & < > " \\ \u2028 \u2029 __DELETE_CONFIG__ __REPORT_DATA__'}}
        self.template = Path(server.TEMPLATE).read_text(encoding='utf-8')

    def assert_report(self, html, config):
        original, rendered = ScriptParser(), ScriptParser()
        original.feed(self.template)
        rendered.feed(html)
        self.assertEqual(len(rendered.scripts), len(original.scripts))
        script = next(s for s in rendered.scripts if 'const DATA =' in s)
        # Parse data back from the *HTML parser's* script, catching early closure
        # and accidental replacement of marker strings inside report contents.
        data = re.search(r'const DATA = (.*);\n', script).group(1)
        delete = re.search(r'const DELETE = (.*); //', script).group(1)
        self.assertEqual(json.loads(data), self.data)
        self.assertEqual(json.loads(delete), config)

    def test_static_report_cli_preserves_data_without_inserting_scripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, out = Path(tmp)/'analysis.json', Path(tmp)/'report.html'
            src.write_text(json.dumps(self.data), encoding='utf-8')
            subprocess.run([sys.executable, str(Path(__file__).with_name('build_report.py')),
                            str(src), str(out)], check=True, capture_output=True)
            self.assert_report(out.read_text(encoding='utf-8'), None)

    def test_served_report_preserves_data_and_action_config(self):
        with patch.object(server, 'DATA', self.data), \
                patch.object(server, 'TPL', self.template), \
                patch.object(server, 'TOKEN', 'test-token-only'):
            http = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
            thread = threading.Thread(target=http.serve_forever, daemon=True)
            thread.start()
            try:
                with server.local_urlopen('http://127.0.0.1:%s/' % http.server_port) as response:
                    html = response.read().decode('utf-8')
                self.assert_report(html, {'token': 'test-token-only', 'endpoint': '/action'})
            finally:
                http.shutdown()
                http.server_close()
                thread.join()


if __name__ == '__main__':
    unittest.main()
