from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from repo_public_audit.scanner import audit_repository, should_fail


class ScannerTests(unittest.TestCase):
    def test_flags_secret_like_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_basic_oss_files(root)
            fake_key = "sk-" + "testvalue12345678901234567890"
            (root / "settings.py").write_text(f"API_KEY='{fake_key}'\n", encoding="utf-8")

            result = audit_repository(root)

            self.assertTrue(any(f.rule == "openai-key" for f in result.findings))
            self.assertTrue(should_fail(result, "high"))

    def test_flags_risky_file_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_basic_oss_files(root)
            (root / ".env").write_text("DEBUG=true\n", encoding="utf-8")

            result = audit_repository(root)

            self.assertTrue(any(f.rule == "risky-path" and f.path == ".env" for f in result.findings))

    def test_missing_oss_files_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.py").write_text("print('hello')\n", encoding="utf-8")

            result = audit_repository(root)
            rules = {(f.rule, f.path) for f in result.findings}

            self.assertIn(("missing-file", "readme.md"), rules)
            self.assertIn(("missing-file", "license"), rules)

    def test_clean_basic_repo_has_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_basic_oss_files(root)
            (root / "src").mkdir()
            (root / "src" / "hello.py").write_text("print('hello')\n", encoding="utf-8")

            result = audit_repository(root)

            self.assertEqual((), result.findings)


def write_basic_oss_files(root: Path) -> None:
    (root / "README.md").write_text("# Demo\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (root / "CONTRIBUTING.md").write_text("# Contributing\n", encoding="utf-8")
    (root / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (root / "CODE_OF_CONDUCT.md").write_text("# Code of Conduct\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
