"""Exercise resource drift, portability, and release archive boundaries."""

import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("plugin", ROOT / "tools/plugin.py")
plugin = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(plugin)


class PluginTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="beacon-plugin-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "checkout with spaces"
        self.root.mkdir()
        for relative in plugin.package_paths(ROOT):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)

    def test_checkout_and_relocated_skill(self):
        plugin.check(self.root)
        skill = Path(self.temp.name) / "different plugin" / plugin.NAME
        shutil.copytree(self.root / plugin.SKILL, skill)
        plugin.check_skill(skill)

    def test_source_drift_requires_sync_without_changing_sources(self):
        header = self.root / "interpreter-includes/beacon.h"
        header.write_bytes(header.read_bytes() + b"\n/* snapshot update */\n")
        before = {path: path.read_bytes() for path in
                  (self.root / "interpreter-includes").glob("*.h")}
        with self.assertRaisesRegex(ValueError, "stale generated"):
            plugin.check(self.root)
        plugin.sync(self.root)
        plugin.check(self.root)
        self.assertTrue(all(path.read_bytes() == data for path, data in before.items()))

    def test_missing_bundle_fails(self):
        (self.root / plugin.SKILL / "references/interpreter-includes/beacon.h").unlink()
        with self.assertRaisesRegex(ValueError, "Missing or stale"):
            plugin.check(self.root)

    def test_manifest_drift_and_version_refresh(self):
        path = self.root / "plugin.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["version"] = "0.2.0"
        path.write_bytes(plugin.json_bytes(manifest))
        with self.assertRaisesRegex(ValueError, "stale generated"):
            plugin.check(self.root)
        plugin.sync(self.root)
        plugin.check(self.root)
        self.assertEqual(plugin.build(self.root).name, f"{plugin.NAME}-0.2.0.zip")

    def test_skill_cannot_depend_on_parent_repository(self):
        path = self.root / plugin.SKILL / "SKILL.md"
        path.write_text(path.read_text(encoding="utf-8") +
                        "\n[external dependency](../../README.md)\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "escapes package"):
            plugin.check(self.root)

    def test_broken_link_fails(self):
        path = self.root / plugin.SKILL / "SKILL.md"
        path.write_text(path.read_text(encoding="utf-8") +
                        "\n[missing](references/missing.md)\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Broken link"):
            plugin.check(self.root)

    def test_reference_must_be_in_release_archive(self):
        skill = self.root / plugin.SKILL
        (skill / "references/new.md").write_text("New reference", encoding="utf-8")
        path = skill / "SKILL.md"
        path.write_text(path.read_text(encoding="utf-8") +
                        "\n[new](references/new.md)\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "missing from archive"):
            plugin.check(self.root)

    def test_absolute_link_is_not_portable(self):
        path = self.root / plugin.SKILL / "SKILL.md"
        absolute = (self.root / plugin.SKILL / "LICENSE").as_posix()
        path.write_text(path.read_text(encoding="utf-8") +
                        f"\n[absolute]({absolute})\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Nonportable link"):
            plugin.check(self.root)

    def test_removed_header_is_reported_without_deletion(self):
        (self.root / "interpreter-includes/file.h").unlink()
        plugin.sync(self.root)
        with self.assertRaisesRegex(ValueError, "Unexpected bundled headers"):
            plugin.check(self.root)
        self.assertTrue((self.root / plugin.SKILL /
                         "references/interpreter-includes/file.h").exists())

    def test_archive_reproducible_complete_and_relocatable(self):
        (self.root / ".env").write_text("not-for-distribution", encoding="utf-8")
        output = plugin.build(self.root)
        first = output.read_bytes()
        self.assertEqual(plugin.build(self.root).read_bytes(), first)
        extracted = Path(self.temp.name) / "extracted"
        with zipfile.ZipFile(output) as archive:
            self.assertFalse(any(name.endswith("/.env") for name in archive.namelist()))
            self.assertIn(f"{plugin.NAME}/.codex-plugin/plugin.json", archive.namelist())
            self.assertIn(f"{plugin.NAME}/.claude-plugin/plugin.json", archive.namelist())
            archive.extractall(extracted)
        plugin.check(extracted / plugin.NAME)

    def test_line_endings_do_not_change_provenance(self):
        header = self.root / "interpreter-includes/beacon.h"
        data = plugin.normalized(header.read_bytes())
        header.write_bytes(data.replace(b"\n", b"\r\n"))
        plugin.check(self.root)
        before = plugin.build(self.root).read_bytes()
        header.write_bytes(data)
        plugin.sync(self.root)
        self.assertEqual(plugin.build(self.root).read_bytes(), before)

    def test_icon_survives_packaging_without_binary_normalization(self):
        relative = "assets/cobalt-strike-beacon-interpreter.png"
        source = (self.root / relative).read_bytes()
        self.assertTrue(source.startswith(b"\x89PNG\r\n\x1a\n"))
        with zipfile.ZipFile(plugin.build(self.root)) as archive:
            self.assertEqual(archive.read(f"{plugin.NAME}/{relative}"), source)
        interface = plugin.read_manifest(self.root)["extensions"]["com.openai"]["interface"]
        self.assertEqual(interface["logo"], f"./{relative}")
        self.assertEqual(interface["composerIcon"], interface["logo"])


if __name__ == "__main__":
    unittest.main()
