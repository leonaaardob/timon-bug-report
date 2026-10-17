"""Offline regression tests. All data is synthetic; no Timon instance is used."""

import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
import zlib


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "package_report.py"
SPEC = importlib.util.spec_from_file_location("package_report", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def fixture_report():
    return {
        "schema_version": 1,
        "title": "A task return stays pending",
        "observed_at": "2000-01-01T12:00:00+00:00",
        "environment": {
            "timon_version": "Unknown", "operating_system": "Unknown",
            "runtime_mode": "Unknown", "llm_provider": "Not applicable",
            "llm_model": "Not applicable",
        },
        "area": "Task returns", "summary": "One existing return is pending.",
        "expected": "The responsible agent receives the return.",
        "actual": "MESSAGE-01 remains pending.",
        "reproduction": {
            "status": "observed-existing", "steps": ["Inspect an existing return."],
            "limitations": ["A fresh reproduction was not run."],
        },
        "evidence": [{"path": "evidence/log.txt", "supports": "Pending return", "locator": "Line 1"}],
        "hypotheses": [], "unknowns": ["Root cause"],
        "privacy": {"manually_reviewed": True, "excluded": ["Identities"], "replacements": ["USER-A"]},
    }


def png(metadata=False):
    def chunk(kind, value):
        return struct.pack(">I", len(value)) + kind + value + struct.pack(">I", zlib.crc32(kind + value) & 0xffffffff)
    data = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    if metadata:
        data += chunk(b"tEXt", b"Author\x00synthetic")
    return data + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + chunk(b"IEND", b"")


class PackageReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="timon-report-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "public"
        (self.source / "evidence").mkdir(parents=True)
        self.report = fixture_report()
        self.save_report()
        (self.source / "BUG-REPORT.md").write_text("# Pending return\nUSER-A did not receive MESSAGE-01.\n", encoding="utf-8")
        self.log("[wake] MESSAGE-01 pending\n")

    def save_report(self):
        (self.source / "report.json").write_text(json.dumps(self.report, ensure_ascii=False), encoding="utf-8")

    def log(self, text):
        (self.source / "evidence/log.txt").write_text(text, encoding="utf-8")

    def run_pack(self, *extra, output=None, expected=0):
        output = output or self.root / "result" / "archive.zip"
        done = subprocess.run(
            [sys.executable, str(SCRIPT), "--source", str(self.source), "--output", str(output), *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
        )
        self.assertEqual(done.returncode, expected, done.stdout + done.stderr)
        self.assertNotIn("Traceback", done.stderr)
        if expected:
            self.assertFalse(output.exists())
        return done, output

    def assert_disclosure_rejected(self, value, rule=None, *extra):
        self.log(value)
        done, _ = self.run_pack(*extra, expected=2)
        if rule:
            self.assertIn(rule, done.stderr)
        self.assertNotIn(value, done.stdout + done.stderr)

    def test_valid_archive_crc_manifest_and_sidecars(self):
        _, output = self.run_pack()
        with zipfile.ZipFile(output) as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(len(archive.namelist()), 4)
            for row in archive.read("timon-bug-report/SHA256SUMS").decode().splitlines():
                digest, name = row.split("  ", 1)
                self.assertEqual(hashlib.sha256(archive.read("timon-bug-report/" + name)).hexdigest(), digest)
        checks = json.loads((output.parent / "package-checks.json").read_text(encoding="utf-8"))
        self.assertEqual(checks["archive_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
        self.assertEqual(checks["checks"]["known_identifier_scan"], "not-configured")

    def test_archive_is_reproducible_without_local_metadata(self):
        _, first = self.run_pack(output=self.root / "first" / "archive.zip")
        _, second = self.run_pack(output=self.root / "second" / "archive.zip")
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_unicode_artifact_directory_and_explicit_utf8(self):
        target = self.root / "préparation 演示"
        self.source.rename(target)
        self.source = target
        self.log("Échec contrôlé — 実行結果\n")
        self.run_pack()

    def test_overwrite_refusal_preserves_original(self):
        _, output = self.run_pack()
        original = output.read_bytes()
        done = subprocess.run([sys.executable, str(SCRIPT), "--source", str(self.source), "--output", str(output)], capture_output=True, encoding="utf-8")
        self.assertEqual(done.returncode, 2)
        self.assertEqual(output.read_bytes(), original)

    def test_empty_markdown_rejected(self):
        (self.source / "BUG-REPORT.md").write_text("", encoding="utf-8")
        self.run_pack(expected=2)

    def test_manual_review_is_required(self):
        self.report["privacy"]["manually_reviewed"] = False
        self.save_report()
        self.run_pack(expected=2)

    def test_timestamp_requires_timezone(self):
        self.report["observed_at"] = "2000-01-01T12:00:00"
        self.save_report()
        self.run_pack(expected=2)

    def test_missing_environment_fields_rejected(self):
        del self.report["environment"]["timon_version"]
        self.save_report()
        self.run_pack(expected=2)

    def test_evidence_path_must_exist(self):
        self.report["evidence"][0]["path"] = "evidence/absent.txt"
        self.save_report()
        self.run_pack(expected=2)

    def test_evidence_path_cannot_escape(self):
        self.report["evidence"][0]["path"] = "../owner-notes.md"
        self.save_report()
        self.run_pack(expected=2)

    def test_null_evidence_path_has_controlled_error(self):
        self.report["evidence"][0]["path"] = None
        self.save_report()
        self.run_pack(expected=2)

    def test_boolean_is_not_schema_version_one(self):
        self.report["schema_version"] = True
        self.save_report()
        self.run_pack(expected=2)

    def test_reproduction_status_type_has_controlled_error(self):
        self.report["reproduction"]["status"] = {"invalid": True}
        self.save_report()
        self.run_pack(expected=2)

    def test_fresh_reproduction_needs_evidence(self):
        self.report["reproduction"]["status"] = "reproduced-fresh"
        self.report["evidence"] = []
        self.save_report()
        self.run_pack(expected=2)

    def test_duplicate_json_keys_are_rejected(self):
        data = (self.source / "report.json").read_text(encoding="utf-8")
        (self.source / "report.json").write_text(data[:-1] + ', "schema_version": 1}', encoding="utf-8")
        self.run_pack(expected=2)

    def test_nonfinite_json_numbers_are_rejected(self):
        self.report["measurement"] = float("nan")
        self.save_report()
        self.run_pack(expected=2)

    def test_private_text_identifiers_are_rejected_without_values(self):
        samples = [
            ("demo" + "@" + "example.invalid", "EMAIL"),
            ("00000000" + "-0000-4000-8000-000000000001", "REAL_UUID"),
            ("/home/" + "demo-user/report", "USER_PATH"),
            ("C:" + "\\Users\\" + "demo-user\\report", "USER_PATH"),
            ("192.0." + "2.10", "NETWORK_ADDRESS"),
            ("2001:" + "db8::10", "NETWORK_ADDRESS"),
        ]
        for value, rule in samples:
            with self.subTest(rule=rule, form=len(value)):
                self.assert_disclosure_rejected(value, rule)

    def test_authentication_values_are_not_echoed(self):
        fixture_value = "synthetic-only-credential"
        samples = [
            ("password" + ": " + fixture_value, "SECRET_ASSIGNMENT"),
            ("Authorization" + ": Bearer " + fixture_value, "AUTHORIZATION_HEADER"),
            ("Authorization" + ": Basic " + fixture_value, "AUTHORIZATION_HEADER"),
            ("Bearer " + fixture_value, "BEARER_TOKEN"),
        ]
        for value, rule in samples:
            with self.subTest(rule=rule):
                done, _ = self._rejected_log(value)
                self.assertIn(rule, done.stderr)
                self.assertNotIn(fixture_value, done.stdout + done.stderr)

    def _rejected_log(self, value):
        self.log(value)
        return self.run_pack(expected=2)

    def test_masked_values_loopback_and_unicode_are_accepted(self):
        self.log(json.dumps({"password": "[REDACTED]", "token": "<TOKEN>", "endpoint": "http://127.0.0.1:3000/", "note": "Échec contrôlé — 実行結果"}, ensure_ascii=False))
        self.run_pack()

    def test_private_terms_are_checked_in_content_and_filenames(self):
        deny = self.root / "private-terms.txt"
        private = "SyntheticPrivateName"
        deny.write_text(private, encoding="utf-8")
        self.log(private)
        done, _ = self.run_pack("--denylist-file", str(deny), expected=2)
        self.assertNotIn(private, done.stderr)
        self.log("safe")
        (self.source / "evidence" / (private + ".txt")).write_text("safe", encoding="utf-8")
        done, _ = self.run_pack("--denylist-file", str(deny), expected=2)
        self.assertNotIn(private, done.stderr)

    def test_denylist_is_never_allowed_inside_public_tree(self):
        deny = self.source / "evidence/terms.txt"
        deny.write_text("SyntheticPrivateName", encoding="utf-8")
        self.run_pack("--denylist-file", str(deny), expected=2)

    def test_hidden_files_and_nested_archives_are_rejected(self):
        for name in [".env", "evidence/extra.zip"]:
            path = self.source / name
            path.write_bytes(b"synthetic")
            self.run_pack(expected=2)
            path.unlink()

    def test_auth_files_are_rejected_even_without_detectable_values(self):
        path = self.source / "evidence/auth.json"
        path.write_text("{}", encoding="utf-8")
        self.run_pack(expected=2)

    def test_non_utf8_and_nul_text_are_rejected(self):
        for data in [b"\xff", b"\x00binary"]:
            (self.source / "evidence/log.txt").write_bytes(data)
            self.run_pack(expected=2)

    def test_symlink_is_not_followed(self):
        link = self.source / "evidence/link.txt"
        try:
            link.symlink_to(self.source / "evidence/log.txt")
        except OSError:
            self.skipTest("Symlink creation is unavailable for this test account")
        self.run_pack(expected=2)

    def test_output_cannot_be_inside_staging(self):
        self.run_pack(output=self.source / "archive.zip", expected=2)

    def test_case_collisions_rejected_where_filesystem_supports_them(self):
        a, b = self.source / "evidence/A.txt", self.source / "evidence/a.txt"
        a.write_text("safe", encoding="utf-8")
        b.write_text("also safe", encoding="utf-8")
        if len([p for p in a.parent.iterdir() if p.name in {"A.txt", "a.txt"}]) < 2:
            self.skipTest("Case-sensitive filenames unavailable")
        self.run_pack(expected=2)

    def test_windows_reserved_and_noncanonical_paths_rejected(self):
        for name in ["evidence/CON.txt", "evidence/aux", "evidence/part.", "evidence//x.txt", "evidence/./x.txt", "evidence/../x.txt"]:
            with self.subTest(name=name), self.assertRaises(MODULE.Rejected):
                MODULE.clean_relative(name)

    def test_png_needs_explicit_review_and_no_metadata(self):
        path = self.source / "evidence/view.png"
        path.write_bytes(png())
        self.run_pack(expected=2)
        path.write_bytes(png(metadata=True))
        self.run_pack("--reviewed-png", "evidence/view.png", expected=2)
        path.write_bytes(png())
        _, output = self.run_pack("--reviewed-png", "evidence/view.png")
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(archive.read("timon-bug-report/evidence/view.png"), png())

    def test_png_crc_and_trailing_payload_rejected(self):
        path = self.source / "evidence/view.png"
        for content in [png() + b"extra", png()[:-1] + b"X"]:
            path.write_bytes(content)
            self.run_pack("--reviewed-png", "evidence/view.png", expected=2)

    def test_individual_size_limit(self):
        (self.source / "evidence/large.txt").write_bytes(b"a" * 10_000_000)
        self.run_pack(expected=2)


if __name__ == "__main__":
    unittest.main()
