import json
import ctypes
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
import server


class ActionSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.first, self.second = self.home/'first', self.home/'second'
        self.first.write_text('keep until authorized', encoding='utf-8')
        self.second.write_text('second fixture', encoding='utf-8')
        self.patches = [patch.object(server, 'HOME',str(self.home.resolve())),
                        patch.object(server, 'RM_ALLOW',{str(self.first.resolve()), str(self.second.resolve()), str(self.home.resolve())}),
                        patch.object(server, 'TOKEN','test-only-token')]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.http = ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
        thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.http.server_close)
        self.addCleanup(self.http.shutdown)

    def action(self, paths, token='test-only-token', mode='rm'):
        request = urllib.request.Request(f'http://127.0.0.1:{self.http.server_port}/action', data=json.dumps({'mode':mode,'paths':paths,'token':token}).encode('utf-8'), headers={'Content-Type':'application/json'})
        try:
            response = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=3)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            return response.status, json.load(response)

    def test_invalid_second_path_leaves_first_untouched(self):
        code, _ = self.action([str(self.first),str(self.home/'not-allowlisted')])
        self.assertEqual(code,403)
        self.assertTrue(self.first.is_file())

    def test_home_root_is_never_a_destructive_target(self):
        code, _ = self.action([str(self.home)])
        self.assertEqual(code,403)
        self.assertTrue(self.first.is_file())

    def test_authorized_fixture_is_deleted(self):
        code, result = self.action([str(self.first)])
        self.assertEqual(code,200)
        self.assertEqual(result['done'],[str(self.first)])
        self.assertFalse(self.first.exists())
        self.assertTrue(self.second.exists())

    def test_wrong_token_has_no_side_effect(self):
        code, _ = self.action([str(self.first)],token='wrong')
        self.assertEqual(code,403)
        self.assertTrue(self.first.exists())

    def test_io_failure_reports_completed_paths(self):
        real = server.hard_delete
        def fail_second(path):
            if path == str(self.second.resolve()):
                raise PermissionError('synthetic file lock')
            real(path)
        with patch.object(server,'hard_delete',side_effect=fail_second):
            code, result = self.action([str(self.first),str(self.second)])
        self.assertEqual(code,500)
        self.assertEqual(result['done'],[str(self.first)])
        self.assertTrue(self.second.exists())
        self.assertEqual(result['status'], 'partial')
        self.assertEqual([r['status'] for r in result['results']], ['completed', 'failed'])

    def test_cancelled_batch_preserves_done_and_unattempted_paths(self):
        third = self.home/'third'
        third.write_bytes(b'synthetic')
        with patch.object(server, 'TRASH_ALLOW', {str(p.resolve()) for p in (self.first, self.second, third)}):
            def controlled(path):
                if path == str(self.second.resolve()):
                    raise server.OperationCancelled('synthetic cancellation')
                os.remove(path)
            with patch.object(server, 'move_to_trash', side_effect=controlled):
                code, result = self.action([str(self.first), str(self.second), str(third)], mode='trash')
        self.assertEqual(code, 500)
        self.assertEqual([r['status'] for r in result['results']], ['completed', 'cancelled', 'not_attempted'])
        self.assertTrue(self.second.exists())
        self.assertTrue(third.exists())

    def test_missing_target_is_not_reported_as_deleted(self):
        self.first.unlink()
        code, result = self.action([str(self.first)])
        self.assertEqual(code, 200)
        self.assertEqual(result['results'][0]['status'], 'already_missing')

    def test_successful_return_with_remaining_target_is_failure(self):
        with patch.object(server, 'hard_delete'):
            code, result = self.action([str(self.first)])
        self.assertEqual(code, 500)
        self.assertEqual(result['done'], [])
        self.assertTrue(self.first.exists())

    def test_open_is_only_submitted_and_missing_target_fails(self):
        with patch.object(server, 'OPEN_ALLOW', {str(self.first.resolve())}), patch.object(server, 'open_in_file_manager'):
            code, result = self.action([str(self.first)], mode='open')
            self.assertEqual(code, 200)
            self.assertEqual(result['results'][0]['status'], 'submitted')
            self.first.unlink()
            code, result = self.action([str(self.first)], mode='open')
            self.assertEqual(code, 500)

    def test_overlapping_batch_is_rejected_before_mutation(self):
        parent = self.home/'parent'
        parent.mkdir()
        child = parent/'child'
        child.write_bytes(b'keep')
        with patch.object(server, 'RM_ALLOW', {str(parent.resolve()), str(child.resolve())}):
            code, _ = self.action([str(parent), str(child)])
        self.assertEqual(code, 400)
        self.assertTrue(child.exists())

    def test_paths_string_is_rejected(self):
        code,_ = self.action(str(self.first))
        self.assertEqual(code,400)
        self.assertTrue(self.first.exists())

    @unittest.skipUnless(os.name == 'nt', 'Windows shell cancellation contract')
    def test_cancelled_trash_is_not_reported_as_completed(self):
        def cancelled(operation):
            operation._obj.fAnyOperationsAborted = True
            return 0
        with patch.object(server, 'TRASH_ALLOW', {str(self.first.resolve())}), \
                patch.object(ctypes.windll.shell32, 'SHFileOperationW', side_effect=cancelled):
            code, result = self.action([str(self.first)], mode='trash')
        self.assertEqual(code, 500)
        self.assertFalse(result['ok'])
        self.assertEqual(result['done'], [])
        self.assertEqual(result['failed'], str(self.first))
        self.assertIn('取消', result['error'])
        self.assertTrue(self.first.exists())

    def test_heartbeat_ignores_environment_proxy(self):
        # An unusable proxy must not intercept local health checks.
        with patch.dict('os.environ',{'http_proxy':'http://127.0.0.1:1','HTTP_PROXY':'http://127.0.0.1:1','no_proxy':'','NO_PROXY':''}):
            with server.local_urlopen(f'http://127.0.0.1:{self.http.server_port}/heartbeat') as response:
                self.assertTrue(json.load(response)['ok'])

    def test_heartbeat_never_bypasses_proxy_for_remote_host(self):
        with self.assertRaises(ValueError):
            server.local_urlopen('http://example.com/heartbeat')

    @unittest.skipUnless(os.name == 'nt', 'Windows fixed-volume open support')
    def test_other_local_path_can_be_opened_but_not_deleted(self):
        other = tempfile.TemporaryDirectory()
        self.addCleanup(other.cleanup)
        path = str(Path(other.name).resolve())
        with patch.object(server,'OPEN_ALLOW',{path}), patch.object(server,'open_in_file_manager') as opened:
            code,_ = self.action([path],mode='open')
            self.assertEqual(code,200)
            opened.assert_called_once_with(path)
        with patch.object(server,'RM_ALLOW',{path}):
            code,_ = self.action([path],mode='rm')
            self.assertEqual(code,403)
            self.assertTrue(Path(path).is_dir())


@unittest.skipUnless(os.name == 'nt', 'Windows shell return contract')
class WindowsTrashTests(unittest.TestCase):
    def test_successful_shell_return_is_accepted(self):
        with patch.object(ctypes.windll.shell32, 'SHFileOperationW', return_value=0) as shell:
            server._trash_windows('synthetic-path-not-created')
        shell.assert_called_once()

    def test_shell_error_is_preserved(self):
        with patch.object(ctypes.windll.shell32, 'SHFileOperationW', return_value=5):
            with self.assertRaisesRegex(OSError, 'code 5'):
                server._trash_windows('synthetic-path-not-created')


class MacTrashFailureTests(unittest.TestCase):
    def test_cancel_does_not_fall_back_to_move(self):
        result = type('Result', (), {'returncode': 1, 'stderr': 'User canceled. (-128)'})()
        with patch.object(server.subprocess, 'run', return_value=result), patch.object(server.shutil, 'move') as move:
            with self.assertRaises(server.OperationCancelled):
                server._trash_macos('synthetic-not-created')
        move.assert_not_called()

    def test_finder_error_is_preserved(self):
        result = type('Result', (), {'returncode': 1, 'stderr': 'synthetic Finder error'})()
        with patch.object(server.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(OSError, 'synthetic Finder error'):
                server._trash_macos('synthetic-not-created')


if __name__ == '__main__':
    unittest.main(verbosity=2)
