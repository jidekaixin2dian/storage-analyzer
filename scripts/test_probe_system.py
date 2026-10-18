"""Regression tests for the read-only system-space probe."""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

import probe_system


class FormatTests(unittest.TestCase):
    def test_format_size_units(self):
        self.assertEqual(probe_system.format_size(1024), "1.00 KB")
        self.assertEqual(probe_system.format_size(1024 ** 3), "1.00 GB")
        self.assertEqual(probe_system.format_size(0), "0 B")

    def test_decode_utf16_bom(self):
        self.assertIn("组件", probe_system._decode("组件".encode("utf-16")))


class PnputilParserTests(unittest.TestCase):
    def test_extracts_unique_oem_infs_case_insensitively(self):
        text = (
            "发布名称: oem12.inf\n提供程序名称: Intel\n\n"
            "发布名称: OEM03.INF\n\n"
            "发布名称: oem12.inf\n"
        )
        self.assertEqual(probe_system.parse_pnputil_infs(text),
                         ["oem03.inf", "oem12.inf"])

    def test_ignores_non_oem_lines(self):
        self.assertEqual(
            probe_system.parse_pnputil_infs("Published Name: netwtw08.inf"),
            [])


class PartitionParserTests(unittest.TestCase):
    def test_parses_pipe_lines_and_skips_noise(self):
        text = "0|6|944767488\nnoise\n1|2|abc\n"
        self.assertEqual(
            probe_system.parse_recovery_partitions(text),
            [{"disk": 0, "partition": 6, "size_bytes": 944767488}])


class DismParserTests(unittest.TestCase):
    EN = """Deployment Image Servicing and Management tool
Version: 10.0.26100.1150

Component Store (WinSxS) information:

Windows Explorer Reported Size of Component Store : 12.34 GB
Actual Size of Component Store : 11.98 GB
    Shared with Windows : 7.90 GB
    Backups and Disabled Features : 3.10 GB
    Cache and Temporary Data : 0.98 GB
Number of Reclaimable Packages : 8
Component Store Cleanup Recommended : Yes
"""

    ZH = """部署映像服务和管理工具
版本: 10.0.26100.1150

组件存储(WinSxS)信息：
Windows 资源管理器报告的组件存储大小 : 12.34 GB
组件存储的实际大小 : 11.98 GB
    与 Windows 共享 : 7.90 GB
    备份和禁用的功能 : 3.10 GB
    缓存和临时数据 : 0.98 GB
可回收程序包数 : 8
建议进行组件存储清理 : 是
"""

    def test_english_output(self):
        parsed = probe_system.parse_dism_component_store(self.EN)
        self.assertTrue(parsed["available"])
        self.assertEqual(parsed["actual"], "11.98 GB")
        self.assertEqual(parsed["shared"], "7.90 GB")
        self.assertEqual(parsed["reclaimable"], 8)
        self.assertIs(parsed["recommended"], True)

    def test_chinese_output(self):
        parsed = probe_system.parse_dism_component_store(self.ZH)
        self.assertTrue(parsed["available"])
        self.assertEqual(parsed["actual"], "11.98 GB")
        self.assertEqual(parsed["backups"], "3.10 GB")
        self.assertEqual(parsed["reclaimable"], 8)
        self.assertIs(parsed["recommended"], True)

    def test_unknown_output_is_not_guessed(self):
        parsed = probe_system.parse_dism_component_store("something else\n")
        self.assertFalse(parsed["available"])
        self.assertIsNone(parsed["actual"])
        self.assertIsNone(parsed["recommended"])

    def test_real_win11_zh_labels(self):
        # 真机 Windows 11 26100 实际输出（标签与文档/旧版本不同）
        text = """组件存储(WinSxS)信息:

Windows 资源管理器报告的组件存储大小 : 12.85 GB

组件存储的实际大小 : 12.55 GB

    已与 Windows 共享 : 8.14 GB
    备份和已禁用的功能 : 4.41 GB
    缓存和临时数据 :  0 bytes

可回收的程序包数 : 2
推荐使用组件存储清理 : 是
"""
        parsed = probe_system.parse_dism_component_store(text)
        self.assertTrue(parsed["available"])
        self.assertEqual(parsed["actual"], "12.55 GB")
        self.assertEqual(parsed["shared"], "8.14 GB")
        self.assertEqual(parsed["backups"], "4.41 GB")
        self.assertEqual(parsed["cache"], "0 B")
        self.assertEqual(parsed["reclaimable"], 2)
        self.assertIs(parsed["recommended"], True)


class ReagentcParserTests(unittest.TestCase):
    def test_english(self):
        parsed = probe_system.parse_reagentc(
            "Windows RE status: Enabled\n"
            "Windows RE location: \\\\?\\GLOBALROOT\\device\\harddisk0\\partition6\\Recovery\\WindowsRE\n")
        self.assertTrue(parsed["available"])
        self.assertTrue(parsed["enabled"])
        self.assertIn("partition6", parsed["location"])

    def test_chinese_disabled(self):
        parsed = probe_system.parse_reagentc(
            "Windows 恢复环境(Windows RE)和系统重置配置信息:\n"
            "     Windows RE 状态: 已禁用\n")
        self.assertTrue(parsed["available"])
        self.assertFalse(parsed["enabled"])


class ShadowStorageParserTests(unittest.TestCase):
    def test_keeps_relevant_lines(self):
        parsed = probe_system.parse_shadow_storage(
            "vssadmin 1.1\n"
            "     卷影副本存储卷: (C:)\n"
            "     已用卷影副本存储空间: 1.2 GB (1%)\n"
            "     最大卷影副本存储空间: 12.0 GB (3%)\n")
        self.assertTrue(parsed["available"])
        self.assertTrue(any("已用" in line for line in parsed["lines"]))


class DirMeasureTests(unittest.TestCase):
    def test_measures_nested_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "a", "b"))
            for path, size in (("one.txt", 10), ("a/two.bin", 20),
                               ("a/b/three.bin", 30)):
                with open(os.path.join(tmp, path), "wb") as stream:
                    stream.write(b"x" * size)
            measured = probe_system._stat_path(tmp)
            self.assertTrue(measured["present"])
            self.assertEqual(measured["size_bytes"], 60)
            self.assertEqual(measured["files"], 3)

    def test_missing_path_is_absent_not_zero_size(self):
        measured = probe_system._stat_path(
            os.path.join(tempfile.gettempdir(), "definitely-missing-xyz"))
        self.assertFalse(measured["present"])
        self.assertEqual(measured["size_bytes"], 0)


class MergeTests(unittest.TestCase):
    def _fixture(self, elevated=True):
        analysis = {
            "system": {"os": "Windows 11"},
            "green": [], "yellow": [], "red": [],
            "system_space": {
                "elevated": False,
                "items": [{"id": "winsxs", "name": "组件存储", "note": "base"}],
            },
        }
        elevated_doc = {
            "elevated": elevated,
            "dism": {"exit_code": 0, "parsed": {
                "available": True, "actual": "11.98 GB", "shared": "7.90 GB",
                "backups": "3.10 GB", "cache": "0.98 GB",
                "reclaimable": 8, "recommended": True}},
        }
        return analysis, elevated_doc

    def test_merge_updates_winsxs_and_sets_elevated(self):
        analysis, elevated_doc = self._fixture()
        with tempfile.TemporaryDirectory() as tmp:
            analysis_path = os.path.join(tmp, "analysis.json")
            elevated_path = os.path.join(tmp, "elevated.json")
            with open(analysis_path, "w", encoding="utf-8") as stream:
                json.dump(analysis, stream, ensure_ascii=False)
            with open(elevated_path, "w", encoding="utf-8") as stream:
                json.dump(elevated_doc, stream, ensure_ascii=False)

            probe_system.merge_into(analysis_path, elevated_path)

            with open(analysis_path, encoding="utf-8") as stream:
                merged = json.load(stream)
        space = merged["system_space"]
        self.assertTrue(space["elevated"])
        self.assertEqual(space["elevated_analysis"]["dism"]["parsed"]["actual"],
                         "11.98 GB")
        item = space["items"][0]
        self.assertTrue(item["reclaim_known"])
        self.assertEqual(item["reclaim"]["reclaimable_packages"], 8)
        self.assertIn("DISM 分析", item["note"])
        self.assertIn("11.98 GB", item["note"])

    def test_merge_rejects_non_elevated_result(self):
        analysis, elevated_doc = self._fixture(elevated=False)
        with tempfile.TemporaryDirectory() as tmp:
            analysis_path = os.path.join(tmp, "analysis.json")
            elevated_path = os.path.join(tmp, "elevated.json")
            with open(analysis_path, "w", encoding="utf-8") as stream:
                json.dump(analysis, stream, ensure_ascii=False)
            with open(elevated_path, "w", encoding="utf-8") as stream:
                json.dump(elevated_doc, stream, ensure_ascii=False)
            with self.assertRaises(ValueError):
                probe_system.merge_into(analysis_path, elevated_path)


class CollectShapeTests(unittest.TestCase):
    def test_collect_shape_with_stubbed_measurements(self):
        fake = {"present": True, "size_bytes": 1024 ** 3, "files": 10,
                "denied": 0, "skipped_reparse": 0}
        with patch.object(probe_system, "_stat_path", return_value=fake), \
                patch.object(probe_system, "_combine", return_value=fake), \
                patch.object(probe_system, "driver_usage",
                             return_value={"available": False}), \
                patch.object(probe_system, "recovery_partitions",
                             return_value={"available": False, "partitions": []}), \
                patch.object(probe_system, "is_elevated", return_value=False):
            data = probe_system.collect(include_driver_usage=False)
        self.assertIn("items", data)
        self.assertGreaterEqual(len(data["items"]), 10)
        ids = [item["id"] for item in data["items"]]
        self.assertIn("winsxs", ids)
        self.assertIn("driverstore", ids)
        self.assertIn("update_cache", ids)
        self.assertFalse(data["elevated"])
        self.assertIsNone(data["elevated_analysis"])
        for item in data["items"]:
            self.assertIn("risk", item)
            self.assertNotIn("trash_paths", item)


class TemplateTests(unittest.TestCase):
    def test_template_renders_system_space_without_delete_actions(self):
        here = os.path.dirname(os.path.abspath(__file__))
        template = os.path.join(here, "..", "assets", "report_template.html")
        with open(template, encoding="utf-8") as stream:
            html = stream.read()
        self.assertIn("function renderSystemSpace", html)
        self.assertIn("renderSystemSpace(DATA.system_space)", html)
        self.assertIn("item.blue", html)
        # 系统段只给复制按钮，不能出现删除/移废纸篓动作
        start = html.index("function renderSystemSpace")
        end = html.index("function renderTop5", start)
        section = html[start:end]
        self.assertNotIn("doDelete", section)
        self.assertNotIn("del-btn trash", section)
        self.assertIn("copyBtn", section)


if __name__ == "__main__":
    unittest.main(verbosity=2)
